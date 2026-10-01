package server

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

func floorKDF() json.RawMessage {
	b, _ := json.Marshal(e2e.Params{Alg: "argon2id", Memory: 65536, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{1}, 16)})
	return b
}

func validBundle() store.Bundle {
	b, _ := decodeBundle(testBundleWire())
	return b
}

func TestValidateBundleAcceptsFloor(t *testing.T) {
	if err := validateBundle(validBundle()); err != nil {
		t.Fatalf("validateBundle: %v", err)
	}
}

func TestValidateKDFRejectsWrongAlg(t *testing.T) {
	b, _ := json.Marshal(e2e.Params{Alg: "scrypt", Memory: 65536, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{1}, 16)})
	if _, err := validateKDF(b); err == nil {
		t.Error("accepted a non-argon2id alg")
	}
}

func TestValidateKDFRejectsBelowFloor(t *testing.T) {
	b, _ := json.Marshal(e2e.Params{Alg: "argon2id", Memory: 1024, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{1}, 16)})
	if _, err := validateKDF(b); err == nil {
		t.Error("accepted memory below the floor")
	}
}

func TestValidateKDFRejectsAboveCeiling(t *testing.T) {
	b, _ := json.Marshal(e2e.Params{Alg: "argon2id", Memory: ceilingMemory + 1, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{1}, 16)})
	if _, err := validateKDF(b); err == nil {
		t.Error("accepted memory above the ceiling")
	}
	b, _ = json.Marshal(e2e.Params{Alg: "argon2id", Memory: 65536, Time: ceilingTime + 1, Threads: 1, Salt: bytes.Repeat([]byte{1}, 16)})
	if _, err := validateKDF(b); err == nil {
		t.Error("accepted time above the ceiling")
	}
}

func TestValidateKDFRejectsWrongSaltLength(t *testing.T) {
	for _, n := range []int{8, 15, 17, 64} {
		b, _ := json.Marshal(e2e.Params{Alg: "argon2id", Memory: 65536, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{1}, n)})
		if _, err := validateKDF(b); err == nil {
			t.Errorf("accepted a %d-byte salt", n)
		}
	}
}

func TestValidateKDFRejectsMalformedJSON(t *testing.T) {
	if _, err := validateKDF(json.RawMessage(`not json`)); err == nil {
		t.Error("accepted malformed JSON")
	}
	if _, err := validateKDF(nil); err == nil {
		t.Error("accepted a nil kdf")
	}
}

func TestValidateSealedLenRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 32, 60, 62} {
		if err := validateSealedLen(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Errorf("accepted a %d-byte sealed value", n)
		}
	}
	if err := validateSealedLen(bytes.Repeat([]byte{1}, sealedKeyLen)); err != nil {
		t.Errorf("rejected a correctly-sized sealed value: %v", err)
	}
}

func TestValidatePubRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if err := validatePub(bytes.Repeat([]byte{1}, n)); err == nil {
			t.Errorf("accepted a %d-byte public key", n)
		}
	}
}

func TestValidateBundleRejectsEachBadField(t *testing.T) {
	base := validBundle()
	cases := map[string]store.Bundle{
		"bad kdf":          {KDF: json.RawMessage(`{}`), MKPassword: base.MKPassword, MKRecovery: base.MKRecovery, X25519Pub: base.X25519Pub, X25519Priv: base.X25519Priv, Ed25519Pub: base.Ed25519Pub, Ed25519Priv: base.Ed25519Priv, EK: base.EK},
		"short mkPassword": {KDF: floorKDF(), MKPassword: []byte("short"), MKRecovery: base.MKRecovery, X25519Pub: base.X25519Pub, X25519Priv: base.X25519Priv, Ed25519Pub: base.Ed25519Pub, Ed25519Priv: base.Ed25519Priv, EK: base.EK},
		"short x25519Pub":  {KDF: floorKDF(), MKPassword: base.MKPassword, MKRecovery: base.MKRecovery, X25519Pub: []byte("short"), X25519Priv: base.X25519Priv, Ed25519Pub: base.Ed25519Pub, Ed25519Priv: base.Ed25519Priv, EK: base.EK},
	}
	for name, b := range cases {
		if err := validateBundle(b); err == nil {
			t.Errorf("%s: validateBundle accepted it", name)
		}
	}
}

func TestDecodeBundleRoundTrip(t *testing.T) {
	w := testBundleWire()
	b, err := decodeBundle(w)
	if err != nil {
		t.Fatal(err)
	}
	got := encodeBundle(b)
	if !bytes.Equal(got.KDF, w.KDF) {
		t.Errorf("kdf mismatch: got %s, want %s", got.KDF, w.KDF)
	}
	if got.MKPassword != w.MKPassword || got.MKRecovery != w.MKRecovery || got.X25519Pub != w.X25519Pub ||
		got.X25519Priv != w.X25519Priv || got.Ed25519Pub != w.Ed25519Pub || got.Ed25519Priv != w.Ed25519Priv || got.EK != w.EK {
		t.Errorf("round trip mismatch:\ngot  %+v\nwant %+v", got, w)
	}
}

func TestDecodeBundleRejectsBadB64(t *testing.T) {
	w := testBundleWire()
	w.MKPassword = "not base64url!!"
	if _, err := decodeBundle(w); err == nil {
		t.Error("accepted malformed base64")
	}
}

// TestValidateBundleRejectsLowOrderKeys: a low-order public key would let a
// wrap or a signature be forged without the private key, so a bundle that
// carries one is refused at upload.
func TestValidateBundleRejectsLowOrderKeys(t *testing.T) {
	identity := append([]byte{1}, make([]byte, 31)...) // the Ed25519 identity point
	for name, mutate := range map[string]func(*store.Bundle){
		"x25519 zero point":      func(b *store.Bundle) { b.X25519Pub = make([]byte, 32) },
		"ed25519 identity point": func(b *store.Bundle) { b.Ed25519Pub = identity },
	} {
		b := validBundle()
		mutate(&b)
		if err := validateBundle(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
