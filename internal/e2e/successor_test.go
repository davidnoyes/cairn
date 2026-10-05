package e2e

import (
	"bytes"
	"errors"
	"testing"
)

func fixedFingerprint() []byte {
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = byte(i)
	}
	return fp
}

// The vector the browser module mirrors: fingerprint bytes 0..31.
func TestSuccessorCodeVector(t *testing.T) {
	const want = "AAAQ-EAYE-AUDA-OCAJ"
	if got := SuccessorCode(fixedFingerprint()); got != want {
		t.Fatalf("SuccessorCode = %q, want %q", got, want)
	}
}

func TestSuccessorCodeRoundTrip(t *testing.T) {
	fp := Fingerprint(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	got, err := ParseSuccessorCode(SuccessorCode(fp))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fp[:10]) {
		t.Fatalf("round trip = %x, want %x", got, fp[:10])
	}
}

func TestSuccessorCodeParseIgnoresCaseSpacesAndHyphens(t *testing.T) {
	want := fixedFingerprint()[:10]
	for _, s := range []string{"aaaq-eaye-auda-ocaj", "AAAQ EAYE AUDA OCAJ", "AAAQEAYEAUDAOCAJ", " aaaq-EAYE auda-OCAJ "} {
		got, err := ParseSuccessorCode(s)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("ParseSuccessorCode(%q) = %x, %v", s, got, err)
		}
	}
}

func TestSuccessorCodeParseRejectsBadInput(t *testing.T) {
	for _, s := range []string{
		"",
		"AAAQ-EAYE-AUDA-OCA",       // 15 characters
		"AAAQ-EAYE-AUDA-OCAJA",     // 17 characters
		"AAAQ-EAYE-AUDA-OCA1",      // outside the alphabet
		"AAAQ-EAYE-AUDA-OCA!",      // outside the character set
		"AAAQ_EAYE_AUDA_OCAJ",      // wrong separator
		"ſAAQ-EAYE-AUDA-OCAJ",      // would fold onto S under some locales
		"AAAQ-EAYE-AUDA-OCAJ\x00",  // control character
		"AAAQ-EAYE-AUDA-OCAJ-AAAA", // a recovery-code-sized tail
	} {
		if _, err := ParseSuccessorCode(s); !errors.Is(err, ErrFormat) {
			t.Errorf("ParseSuccessorCode(%q) = %v, want ErrFormat", s, err)
		}
	}
}

func TestRefusalBodyRoundTrip(t *testing.T) {
	seed, pub, err := GenerateEd25519(newDRBG("refusal"))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"v":1,"user":"u1","requestedAt":"2026-01-02T03:04:05Z"}`)
	env, err := NewEnvelope(seed, "u1", "refusal", body)
	if err != nil {
		t.Fatal(err)
	}
	var got RefusalBody
	if err := OpenEnvelope(env, pub, "refusal", &got); err != nil {
		t.Fatal(err)
	}
	if got.User != "u1" || got.RequestedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("got %+v", got)
	}
}
