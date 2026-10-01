package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strconv"
)

// epochBytes encodes an epoch as decimal ASCII with no leading zeros.
func epochBytes(epoch uint64) []byte {
	return []byte(strconv.FormatUint(epoch, 10))
}

// Keys derived from MK, EK, and AK.

func MKSealKey(mk []byte) []byte { return Derive(mk, nil, LabelMKSeal) }
func IndexKey(mk []byte) []byte  { return Derive(mk, nil, LabelIndex) }
func EKSealKey(ek []byte) []byte { return Derive(ek, nil, LabelEKSeal) }

func LinkToken(ak []byte, artifact string, epoch uint64) []byte {
	return Derive(ak, nil, LabelLinkToken, []byte(artifact), epochBytes(epoch))
}

func FileKey(ak []byte, artifact string, epoch uint64) []byte {
	return Derive(ak, nil, LabelFileKey, []byte(artifact), epochBytes(epoch))
}

// LinkTokenHash is what the server stores for a public link's token.
func LinkTokenHash(token []byte) string {
	sum := sha256.Sum256(token)
	return hex.EncodeToString(sum[:])
}

// FileAddress addresses a stored file by its path under fileKey.
func FileAddress(fileKey []byte, path string) string {
	mac := hmac.New(sha256.New, fileKey)
	mac.Write([]byte(path))
	return hex.EncodeToString(mac.Sum(nil))
}

// BlindIndex is the lookup hash for a resource value of the given type.
func BlindIndex(indexKey []byte, typ, value string) string {
	mac := hmac.New(sha256.New, indexKey)
	mac.Write(Enc([]byte(LabelBlind), []byte(typ), []byte(value)))
	return hex.EncodeToString(mac.Sum(nil))
}

// PreloginSalt is the salt prelogin returns for an address with no verified
// account, so the response looks like a real one and stays stable.
func PreloginSalt(serverSecret []byte, email string) []byte {
	mac := hmac.New(sha256.New, serverSecret)
	mac.Write(Enc([]byte(LabelPrelogin), []byte(email)))
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
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
