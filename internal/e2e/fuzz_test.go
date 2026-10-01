package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// Fuzz tests: any input to a parser must return an error or a value, never
// panic.

func FuzzOpen(f *testing.F) {
	key := testKey("fuzz-open-key")
	fields := [][]byte{[]byte("mk")}
	sealed, err := Seal(newDRBG("fuzz-open-nonce"), key, fields, []byte("plaintext"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		Open(key, fields, data)
	})
}

func FuzzOpenBlob(f *testing.F) {
	ak := testKey("fuzz-blob-ak")
	ctx := testBlobCtx()
	blob, err := SealBlob(newDRBG("fuzz-blob-salt"), ak, ctx, fillBytes(200000))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(blob)
	f.Add([]byte{})
	f.Add(blob[:blobHeaderSize])
	f.Fuzz(func(t *testing.T, data []byte) {
		OpenBlob(ak, ctx, data)
	})
}

func FuzzUnwrap(f *testing.F) {
	recipientPriv, recipientPub := func() ([]byte, []byte) {
		priv, pub, err := GenerateX25519(newDRBG("fuzz-wrap-recipient"))
		if err != nil {
			f.Fatal(err)
		}
		return priv, pub
	}()
	ctx := testWrapContext(recipientPub)
	wrapped, err := Wrap(newDRBG("fuzz-wrap-eph"), ctx, testKey("fuzz-wrapped-key"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wrapped)
	f.Add([]byte{})
	f.Add(make([]byte, 81))
	f.Fuzz(func(t *testing.T, data []byte) {
		Unwrap(recipientPriv, ctx, data)
	})
}

func FuzzParseRecoveryCode(f *testing.F) {
	_, display := NewRecoveryCode(newDRBG("fuzz-recovery"))
	f.Add(display)
	f.Add("")
	f.Add(strings.ToLower(display))
	f.Fuzz(func(t *testing.T, s string) {
		ParseRecoveryCode(s)
	})
}

func FuzzParseAPIKey(f *testing.F) {
	full, _, _, _ := NewAPIKey(newDRBG("fuzz-apikey"))
	f.Add(full)
	f.Add("")
	f.Add("cairn_")
	f.Fuzz(func(t *testing.T, s string) {
		ParseAPIKey(s)
	})
}

func FuzzEnvelopeJSON(f *testing.F) {
	seed, _, err := GenerateEd25519(newDRBG("fuzz-envelope"))
	if err != nil {
		f.Fatal(err)
	}
	env := NewEnvelope(seed, "user-1", "manifest", []byte(`{"v":1}`))
	b, err := json.Marshal(env)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(b))
	f.Add("")
	f.Add("{}")
	f.Fuzz(func(t *testing.T, s string) {
		var e Envelope
		json.Unmarshal([]byte(s), &e)
	})
}
