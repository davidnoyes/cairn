package server

import (
	"encoding/json"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// bundleWire is a key bundle as it travels over the wire: every byte field is
// base64url without padding, per design/e2e-wire-formats.md. store.Bundle
// keeps the same fields as raw []byte (it never needs to look inside them),
// so Go's default JSON encoding of []byte (padded standard base64) would be
// wrong on the wire; bundleWire is the translation between the two.
type bundleWire struct {
	KDF         json.RawMessage `json:"kdf"`
	MKPassword  string          `json:"mkPassword"`
	MKRecovery  string          `json:"mkRecovery"`
	X25519Pub   string          `json:"x25519Pub"`
	X25519Priv  string          `json:"x25519Priv"`
	Ed25519Pub  string          `json:"ed25519Pub"`
	Ed25519Priv string          `json:"ed25519Priv"`
	EK          string          `json:"ek"`
}

// decodeBundle turns a wire bundle into a store.Bundle, decoding every b64
// field. It does not validate lengths or the kdf; call validateBundle after.
func decodeBundle(w bundleWire) (store.Bundle, error) {
	var b store.Bundle
	b.KDF = w.KDF
	dsts := []*[]byte{&b.MKPassword, &b.MKRecovery, &b.X25519Pub, &b.X25519Priv, &b.Ed25519Pub, &b.Ed25519Priv, &b.EK}
	srcs := []string{w.MKPassword, w.MKRecovery, w.X25519Pub, w.X25519Priv, w.Ed25519Pub, w.Ed25519Priv, w.EK}
	for i, src := range srcs {
		raw, err := e2e.UnB64(src)
		if err != nil {
			return store.Bundle{}, errBadBundle
		}
		*dsts[i] = raw
	}
	return b, nil
}

// encodeBundle turns a store.Bundle into its wire form.
func encodeBundle(b store.Bundle) bundleWire {
	return bundleWire{
		KDF:         b.KDF,
		MKPassword:  e2e.B64(b.MKPassword),
		MKRecovery:  e2e.B64(b.MKRecovery),
		X25519Pub:   e2e.B64(b.X25519Pub),
		X25519Priv:  e2e.B64(b.X25519Priv),
		Ed25519Pub:  e2e.B64(b.Ed25519Pub),
		Ed25519Priv: e2e.B64(b.Ed25519Priv),
		EK:          e2e.B64(b.EK),
	}
}
