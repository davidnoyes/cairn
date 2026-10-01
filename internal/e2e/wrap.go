package e2e

import (
	"bytes"
	"crypto/ecdh"
	"io"

	"golang.org/x/crypto/curve25519"
)

// GenerateX25519 reads a 32-byte seed from rnd and uses it as an X25519
// private scalar. It does not call ecdh's own GenerateKey, which may not
// consume the reader deterministically — that would break seeded vectors.
func GenerateX25519(rnd io.Reader) (priv, pub []byte, err error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, nil, err
	}
	key, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, nil, err
	}
	return key.Bytes(), key.PublicKey().Bytes(), nil
}

// WrapContext binds a wrapped key to its purpose, artifact, epoch,
// recipient, and the keys involved, so it cannot be moved to another
// context.
type WrapContext struct {
	Purpose      string
	Artifact     string
	Epoch        uint64
	RecipientID  string
	RecipientPub []byte
}

const (
	wrapVersion = 0x01
	wrapPubSize = 32
	wrapTagSize = 16
	// wrapSize is the only valid length of a wrapped value: every key this
	// package wraps is 32 bytes, so the ciphertext is always
	// version(1) + ephPub(32) + plaintext(32) + tag(16).
	wrapSize = 1 + wrapPubSize + keyLen + wrapTagSize
)

// x25519Shared is the X25519 scalar multiplication. curve25519.X25519's only
// error condition is a result that would have been all zero, which is
// exactly the low-order-point case the wire format says to refuse: a crafted
// public key can force it, so every caller must check for it.
func x25519Shared(scalar, point []byte) (shared []byte, zero bool) {
	shared, err := curve25519.X25519(scalar, point)
	return shared, err != nil
}

func wrapKey(shared []byte, ctx WrapContext, ephPub []byte) []byte {
	return Derive(shared, nil, LabelWrap,
		[]byte(ctx.Purpose), []byte(ctx.Artifact), epochBytes(ctx.Epoch),
		[]byte(ctx.RecipientID), ctx.RecipientPub, ephPub)
}

// Wrap encrypts key to ctx.RecipientPub with a fresh ephemeral X25519 key
// pair: eph ‖ AES-GCM(wrapKey, zero-nonce, key).
func Wrap(rnd io.Reader, ctx WrapContext, key []byte) ([]byte, error) {
	if len(ctx.RecipientPub) != wrapPubSize {
		return nil, ErrFormat
	}
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}
	ephPriv, ephPub, err := GenerateX25519(rnd)
	if err != nil {
		return nil, err
	}
	// Best-effort zeroing: the ephemeral scalar, the shared secret and the
	// derived wrap key are dead once the AEAD holds its own key schedule.
	shared, sharedIsZero := x25519Shared(ephPriv, ctx.RecipientPub)
	clear(ephPriv)
	defer clear(shared)
	if sharedIsZero {
		return nil, ErrFormat
	}
	k := wrapKey(shared, ctx, ephPub)
	defer clear(k)
	gcm, err := newGCM(k)
	if err != nil {
		return nil, err
	}
	zeroNonce := make([]byte, gcmNonceSize)
	ct := gcm.Seal(nil, zeroNonce, key, nil)
	out := make([]byte, 0, 1+wrapPubSize+len(ct))
	out = append(out, wrapVersion)
	out = append(out, ephPub...)
	out = append(out, ct...)
	return out, nil
}

// Unwrap decrypts a key wrapped with Wrap. The recipient's public key is
// derived from priv rather than trusted from ctx.RecipientPub, so a caller
// who passes a priv/ctx pair that don't match fails closed instead of
// deriving a wrap key under the wrong public key.
func Unwrap(priv []byte, ctx WrapContext, wrapped []byte) ([]byte, error) {
	if len(wrapped) != wrapSize || wrapped[0] != wrapVersion || len(priv) != wrapPubSize {
		return nil, ErrDecrypt
	}
	recipientPub, err := x25519PublicFromPrivate(priv)
	if err != nil || !bytes.Equal(recipientPub, ctx.RecipientPub) {
		return nil, ErrDecrypt
	}
	ephPub := wrapped[1 : 1+wrapPubSize]
	ct := wrapped[1+wrapPubSize:]
	// X25519 masks the high bit and reduces mod p, so a non-canonical
	// spelling of ephPub gives the same shared secret; refuse it, so each
	// wrap has exactly one valid encoding.
	if isNonCanonicalX25519(ephPub) {
		return nil, ErrDecrypt
	}

	shared, zero := x25519Shared(priv, ephPub)
	defer clear(shared) // best-effort zeroing, as in Wrap
	if zero {
		return nil, ErrDecrypt
	}
	// ctx is bound into the derivation here, so a wrap moved to another
	// purpose, artifact, epoch, or recipient fails to decrypt.
	unwrapKey := wrapKey(shared, ctx, ephPub)
	defer clear(unwrapKey)
	gcm, err := newGCM(unwrapKey)
	if err != nil {
		return nil, ErrDecrypt
	}
	zeroNonce := make([]byte, gcmNonceSize)
	pt, err := gcm.Open(nil, zeroNonce, ct, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(pt) != keyLen {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// x25519PublicFromPrivate computes the X25519 public key matching a private
// scalar, the same way GenerateX25519 derives pub from seed.
func x25519PublicFromPrivate(priv []byte) ([]byte, error) {
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}
