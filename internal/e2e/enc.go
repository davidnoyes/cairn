// Package e2e implements the cryptographic core of Cairn's end-to-end
// encryption: canonical encoding, HKDF-SHA256 labels, Argon2id password
// stretching, sealed values, chunked blob encryption, X25519 key wrapping,
// and Ed25519 signatures. Every byte this package produces or accepts is
// fixed in design/e2e-wire-formats.md, so the browser module agrees with it
// byte for byte.
package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// Sentinel errors. A caller can test for these with errors.Is; the wrapped
// detail is for logs, not for an attacker to distinguish.
var (
	// ErrDecrypt covers every authenticated-decryption failure: a bad key,
	// a bad context, a flipped bit, or truncated or reordered ciphertext.
	ErrDecrypt = errors.New("e2e: decryption failed")
	// ErrFloor means a Params value is below the Argon2id floor.
	ErrFloor = errors.New("e2e: below parameter floor")
	// ErrFormat means an input could not be parsed, independent of any key.
	ErrFormat = errors.New("e2e: malformed input")
)

// b64 is base64.RawURLEncoding.Strict(): the URL-safe alphabet, no padding,
// and — the part plain RawURLEncoding leaves out — a decode error on any
// input whose unused trailing bits in a partial group aren't zero. Without
// Strict, two different strings could decode to the same bytes, which would
// let a value be presented more than one way.
var b64 = base64.RawURLEncoding.Strict()

// B64 encodes b as base64url without padding.
func B64(b []byte) string {
	return b64.EncodeToString(b)
}

// UnB64 decodes a base64url-no-pad string, refusing anything outside the
// URL-safe alphabet, any padding, and non-zero trailing bits. The decoder
// skips CR and LF even in Strict mode, so the result is also re-encoded and
// compared: only the one canonical spelling of a value decodes.
func UnB64(s string) ([]byte, error) {
	b, err := b64.DecodeString(s)
	if err != nil || B64(b) != s {
		return nil, ErrFormat
	}
	return b, nil
}

// Enc is the canonical encoding of a list of byte strings: each field as a
// 4-byte big-endian length followed by its bytes. It is used for every HKDF
// info, every associated-data value, and every signed or hashed input, so no
// two lists of fields can encode to the same bytes.
func Enc(fields ...[]byte) []byte {
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	var lenBuf [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(f)))
		out = append(out, lenBuf[:]...)
		out = append(out, f...)
	}
	return out
}

// sha256Sum is a small helper so callers don't repeat the array-to-slice
// dance.
func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
