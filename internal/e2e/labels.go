package e2e

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// Labels. Every derivation and every domain-separated input starts with one
// of these. No two are equal; TestLabelsDistinct enforces it.
const (
	LabelAuth        = "cairn/v1/auth"
	LabelKEK         = "cairn/v1/kek"
	LabelRecovery    = "cairn/v1/recovery"
	LabelAPIKey      = "cairn/v1/api-key"
	LabelMKSeal      = "cairn/v1/mk-seal"
	LabelIndex       = "cairn/v1/index"
	LabelEKSeal      = "cairn/v1/ek-seal"
	LabelLinkToken   = "cairn/v1/link-token"
	LabelFileKey     = "cairn/v1/file-key"
	LabelBlob        = "cairn/v1/blob"
	LabelWrap        = "cairn/v1/wrap"
	LabelSeal        = "cairn/v1/seal"
	LabelSig         = "cairn/v1/sig"
	LabelFingerprint = "cairn/v1/fingerprint"
	LabelBlind       = "cairn/v1/blind"
	LabelPrelogin    = "cairn/v1/prelogin"
)

// Labels returns every label in the spec's table.
func Labels() []string {
	return []string{
		LabelAuth,
		LabelKEK,
		LabelRecovery,
		LabelAPIKey,
		LabelMKSeal,
		LabelIndex,
		LabelEKSeal,
		LabelLinkToken,
		LabelFileKey,
		LabelBlob,
		LabelWrap,
		LabelSeal,
		LabelSig,
		LabelFingerprint,
		LabelBlind,
		LabelPrelogin,
	}
}

const derivedKeyLen = 32

// Derive is HKDF-SHA256 with input key material ikm, the given salt (empty
// when none is named), and info = Enc(label, fields...), producing 32 bytes.
func Derive(ikm, salt []byte, label string, fields ...[]byte) []byte {
	info := Enc(append([][]byte{[]byte(label)}, fields...)...)
	key, err := hkdf.Key(sha256.New, ikm, salt, string(info), derivedKeyLen)
	if err != nil {
		// Only possible when keyLength is invalid, which derivedKeyLen never
		// is, so this can't happen with the fixed constant above.
		panic(err)
	}
	return key
}
