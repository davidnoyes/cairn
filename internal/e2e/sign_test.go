package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateEd25519Lengths(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("gen-ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 32 || len(pub) != 32 {
		t.Fatalf("len(seed)=%d len(pub)=%d, want 32 and 32", len(seed), len(pub))
	}
}

func TestGenerateEd25519Deterministic(t *testing.T) {
	seed1, pub1, err := GenerateEd25519(newDRBG("gen-ed25519-det"))
	if err != nil {
		t.Fatal(err)
	}
	seed2, pub2, err := GenerateEd25519(newDRBG("gen-ed25519-det"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed1, seed2) || !bytes.Equal(pub1, pub2) {
		t.Fatal("GenerateEd25519 not deterministic for the same reader seed")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("sign-party"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"v":1,"artifact":"a1"}`)
	sig := Sign(seed, "manifest", body)
	if !Verify(pub, "manifest", body, sig) {
		t.Fatal("Verify rejected a genuine signature")
	}
}

func TestVerifyRejectsWrongPurpose(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("sign-purpose"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("body")
	sig := Sign(seed, "manifest", body)
	if Verify(pub, "revision", body, sig) {
		t.Fatal("Verify accepted a signature under the wrong purpose")
	}
}

func TestVerifyRejectsWrongBody(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("sign-body"))
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(seed, "manifest", []byte("original"))
	if Verify(pub, "manifest", []byte("tampered"), sig) {
		t.Fatal("Verify accepted a signature over a different body")
	}
}

func TestVerifyRejectsFlippedSigBit(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("sign-flip"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("body")
	sig := Sign(seed, "manifest", body)
	for i := range sig {
		mutated := append([]byte(nil), sig...)
		mutated[i] ^= 0x01
		if Verify(pub, "manifest", body, mutated) {
			t.Fatalf("flipped sig bit at %d: Verify accepted it", i)
		}
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	seed, _, err := GenerateEd25519(newDRBG("sign-key-a"))
	if err != nil {
		t.Fatal(err)
	}
	_, otherPub, err := GenerateEd25519(newDRBG("sign-key-b"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("body")
	sig := Sign(seed, "manifest", body)
	if Verify(otherPub, "manifest", body, sig) {
		t.Fatal("Verify accepted a signature under another key's public key")
	}
}

func TestVerifyRejectsMalformedSig(t *testing.T) {
	_, pub, err := GenerateEd25519(newDRBG("sign-malformed"))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 32, 63, 65} {
		if Verify(pub, "manifest", []byte("body"), make([]byte, n)) {
			t.Fatalf("len(sig)=%d: Verify accepted a malformed signature", n)
		}
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("envelope"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"v":1,"artifact":"a1"}`)
	env := NewEnvelope(seed, "user-1", "manifest", body)
	if !env.Verify(pub, "manifest") {
		t.Fatal("Envelope.Verify rejected a genuine envelope")
	}
	if env.Signer != "user-1" {
		t.Fatalf("Signer = %q, want user-1", env.Signer)
	}
}

func TestEnvelopeJSONRoundTrip(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("envelope-json"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"v":1,"artifact":"a1"}`)
	env := NewEnvelope(seed, "user-1", "manifest", body)
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var got Envelope
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Body, env.Body) || !bytes.Equal(got.Sig, env.Sig) || got.Signer != env.Signer {
		t.Fatalf("round trip: got %+v, want %+v", got, env)
	}
	if !got.Verify(pub, "manifest") {
		t.Fatal("round-tripped envelope failed to verify")
	}
}

func TestEnvelopeJSONIsBase64(t *testing.T) {
	seed, _, err := GenerateEd25519(newDRBG("envelope-b64"))
	if err != nil {
		t.Fatal(err)
	}
	env := NewEnvelope(seed, "user-1", "manifest", []byte(`{"v":1}`))
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"body", "sig", "signer"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("JSON %s missing key %s", b, key)
		}
	}
	if _, err := UnB64(m["body"].(string)); err != nil {
		t.Fatalf("body is not base64url: %v", err)
	}
}

func TestEnvelopeVerifyRejectsTamperedBody(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("envelope-tamper"))
	if err != nil {
		t.Fatal(err)
	}
	env := NewEnvelope(seed, "user-1", "manifest", []byte("original"))
	env.Body = []byte("tampered")
	if env.Verify(pub, "manifest") {
		t.Fatal("Verify accepted a tampered envelope body")
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	x25519Pub := testKey("fp-x25519")
	ed25519Pub := testKey("fp-ed25519")
	a := Fingerprint(x25519Pub, ed25519Pub)
	b := Fingerprint(x25519Pub, ed25519Pub)
	if !bytes.Equal(a, b) {
		t.Fatal("Fingerprint not deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("len(fingerprint) = %d, want 32", len(a))
	}
}

func TestFingerprintDiffersByEitherKey(t *testing.T) {
	x1, x2 := testKey("fp-x1"), testKey("fp-x2")
	e1, e2 := testKey("fp-e1"), testKey("fp-e2")
	base := Fingerprint(x1, e1)
	if bytes.Equal(base, Fingerprint(x2, e1)) {
		t.Fatal("Fingerprint ignored the x25519 key")
	}
	if bytes.Equal(base, Fingerprint(x1, e2)) {
		t.Fatal("Fingerprint ignored the ed25519 key")
	}
}

func TestFormatFingerprint(t *testing.T) {
	fp := Fingerprint(testKey("ffp-x"), testKey("ffp-e"))
	display := FormatFingerprint(fp)
	parts := strings.Split(display, " ")
	if len(parts) != 10 {
		t.Fatalf("display has %d groups, want 10: %q", len(parts), display)
	}
	for _, p := range parts {
		if len(p) != 4 {
			t.Fatalf("group %q is not 4 characters", p)
		}
	}
	want := hex.EncodeToString(fp[:20])
	if strings.Join(parts, "") != want {
		t.Fatalf("display %q does not match hex(fp[:20]) %q", display, want)
	}
}
