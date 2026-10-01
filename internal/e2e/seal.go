package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
)

// keyLen is the length every raw symmetric key (MK, EK, AK, and keys derived
// from them by this package) must be. A wrong length is refused before it
// ever reaches a cipher, rather than silently truncated or rejected only by
// aes.NewCipher's own error.
const keyLen = 32

func checkKeyLen(key []byte) error {
	if len(key) != keyLen {
		return fmt.Errorf("%w: key length %d, want %d", ErrFormat, len(key), keyLen)
	}
	return nil
}

// epochBytes encodes an epoch as decimal ASCII with no leading zeros.
func epochBytes(epoch uint64) []byte {
	return []byte(strconv.FormatUint(epoch, 10))
}

// Keys derived from MK, EK, and AK. Each requires a 32-byte input key, the
// length every MK, EK, and AK is fixed at; a wrong length is a caller bug,
// not a runtime condition to tolerate.

func MKSealKey(mk []byte) ([]byte, error) {
	if err := checkKeyLen(mk); err != nil {
		return nil, err
	}
	return Derive(mk, nil, LabelMKSeal), nil
}

func IndexKey(mk []byte) ([]byte, error) {
	if err := checkKeyLen(mk); err != nil {
		return nil, err
	}
	return Derive(mk, nil, LabelIndex), nil
}

func EKSealKey(ek []byte) ([]byte, error) {
	if err := checkKeyLen(ek); err != nil {
		return nil, err
	}
	return Derive(ek, nil, LabelEKSeal), nil
}

func LinkToken(ak []byte, artifact string, epoch uint64) ([]byte, error) {
	if err := checkKeyLen(ak); err != nil {
		return nil, err
	}
	return Derive(ak, nil, LabelLinkToken, []byte(artifact), epochBytes(epoch)), nil
}

func FileKey(ak []byte, artifact string, epoch uint64) ([]byte, error) {
	if err := checkKeyLen(ak); err != nil {
		return nil, err
	}
	return Derive(ak, nil, LabelFileKey, []byte(artifact), epochBytes(epoch)), nil
}

// AKCommit is a public commitment to an artifact's AK at a given epoch, so a
// party without AK can confirm two sources agree on it without learning it.
func AKCommit(ak []byte, artifact string, epoch uint64) (string, error) {
	if err := checkKeyLen(ak); err != nil {
		return "", err
	}
	commit := Derive(ak, nil, LabelAKCommit, []byte(artifact), epochBytes(epoch))
	return hex.EncodeToString(commit), nil
}

// LinkTokenHash is what the server stores for a public link's token.
func LinkTokenHash(token []byte) string {
	sum := sha256.Sum256(token)
	return hex.EncodeToString(sum[:])
}

// FileAddress addresses a stored file by its path under fileKey, which must
// be 32 bytes (ErrFormat otherwise).
func FileAddress(fileKey []byte, path string) (string, error) {
	if err := checkKeyLen(fileKey); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, fileKey)
	mac.Write([]byte(path))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// BlindIndex is the lookup hash for a resource value of the given type.
// indexKey must be 32 bytes (ErrFormat otherwise).
func BlindIndex(indexKey []byte, typ, value string) (string, error) {
	if err := checkKeyLen(indexKey); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, indexKey)
	mac.Write(Enc([]byte(LabelBlind), []byte(typ), []byte(value)))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// PreloginSalt is the salt prelogin returns for an address with no verified
// account, so the response looks like a real one and stays stable.
func PreloginSalt(serverSecret []byte, email string) []byte {
	mac := hmac.New(sha256.New, serverSecret)
	mac.Write(Enc([]byte(LabelPrelogin), []byte(NormalizeEmail(email))))
	return mac.Sum(nil)[:16]
}

// Sealed values: a small secret under AES-256-GCM, bound to its field list.
//
//	seal(key, fields, pt) = 0x01 ‖ nonce(12) ‖ AES-GCM(key, nonce, pt, ad)
//	ad = enc("cairn/v1/seal", fields…)

const sealVersion = 0x01
const gcmNonceSize = 12

func sealAD(fields [][]byte) []byte {
	return Enc(append([][]byte{[]byte(LabelSeal)}, fields...)...)
}

// Seal encrypts pt under key, bound to fields, with a fresh random nonce.
func Seal(rnd io.Reader, key []byte, fields [][]byte, pt []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rnd, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, pt, sealAD(fields))
	out := make([]byte, 0, 1+gcmNonceSize+len(ct))
	out = append(out, sealVersion)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts a value sealed with Seal, checking the version byte and
// failing on any authentication error.
func Open(key []byte, fields [][]byte, sealed []byte) ([]byte, error) {
	if len(sealed) < 1+gcmNonceSize || sealed[0] != sealVersion {
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	nonce := sealed[1 : 1+gcmNonceSize]
	ct := sealed[1+gcmNonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, sealAD(fields))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
