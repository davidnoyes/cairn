package e2e

import (
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
	wrapMinSize = 1 + wrapPubSize + wrapTagSize
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
	ephPriv, ephPub, err := GenerateX25519(rnd)
	if err != nil {
		return nil, err
	}
	shared, sharedIsZero := x25519Shared(ephPriv, ctx.RecipientPub)
	if sharedIsZero {
		return nil, ErrFormat
	}
	gcm, err := newGCM(wrapKey(shared, ctx, ephPub))
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

// Unwrap decrypts a key wrapped with Wrap. ctx.RecipientPub must be the
// recipient's own public key, matching priv.
func Unwrap(priv []byte, ctx WrapContext, wrapped []byte) ([]byte, error) {
	if len(wrapped) < wrapMinSize || wrapped[0] != wrapVersion || len(priv) != wrapPubSize {
		return nil, ErrDecrypt
	}
	ephPub := wrapped[1 : 1+wrapPubSize]
	ct := wrapped[1+wrapPubSize:]

	shared, zero := x25519Shared(priv, ephPub)
	if zero {
		return nil, ErrDecrypt
	}
	// ctx is bound into the derivation here, so a wrap moved to another
	// purpose, artifact, epoch, or recipient fails to decrypt.
	unwrapKey := wrapKey(shared, ctx, ephPub)
	gcm, err := newGCM(unwrapKey)
	if err != nil {
		return nil, ErrDecrypt
	}
	zeroNonce := make([]byte, gcmNonceSize)
	pt, err := gcm.Open(nil, zeroNonce, ct, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
