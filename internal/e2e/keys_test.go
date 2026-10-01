package e2e

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func floorParams() Params {
	return Params{Alg: "argon2id", Memory: floorMemory, Time: floorTime, Threads: 1, Salt: make([]byte, 16)}
}

func TestParamsCheckFloorAccepts(t *testing.T) {
	if err := floorParams().CheckFloor(); err != nil {
		t.Fatalf("floor params rejected: %v", err)
	}
}

func TestParamsCheckFloorAlg(t *testing.T) {
	p := floorParams()
	p.Alg = "argon2i"
	if err := p.CheckFloor(); !errors.Is(err, ErrFloor) {
		t.Fatalf("CheckFloor(%+v) = %v, want ErrFloor", p, err)
	}
}

func TestParamsCheckFloorMemory(t *testing.T) {
	p := floorParams()
	p.Memory = floorMemory - 1
	if err := p.CheckFloor(); !errors.Is(err, ErrFloor) {
		t.Fatalf("memory one below floor: got %v, want ErrFloor", err)
	}
	p.Memory = floorMemory
	if err := p.CheckFloor(); err != nil {
		t.Fatalf("memory at floor rejected: %v", err)
	}
}

func TestParamsCheckFloorTime(t *testing.T) {
	p := floorParams()
	p.Time = floorTime - 1
	if err := p.CheckFloor(); !errors.Is(err, ErrFloor) {
		t.Fatalf("time one below floor: got %v, want ErrFloor", err)
	}
	p.Time = floorTime
	if err := p.CheckFloor(); err != nil {
		t.Fatalf("time at floor rejected: %v", err)
	}
}

func TestParamsCheckFloorThreads(t *testing.T) {
	for _, p8 := range []uint8{0, 5} {
		p := floorParams()
		p.Threads = p8
		if err := p.CheckFloor(); !errors.Is(err, ErrFloor) {
			t.Fatalf("threads=%d: got %v, want ErrFloor", p8, err)
		}
	}
	for _, p8 := range []uint8{1, 2, 3, 4} {
		p := floorParams()
		p.Threads = p8
		if err := p.CheckFloor(); err != nil {
			t.Fatalf("threads=%d rejected: %v", p8, err)
		}
	}
}

func TestParamsCheckFloorSalt(t *testing.T) {
	for _, n := range []int{0, 15, 65, 100} {
		p := floorParams()
		p.Salt = make([]byte, n)
		if err := p.CheckFloor(); !errors.Is(err, ErrFloor) {
			t.Fatalf("salt len=%d: got %v, want ErrFloor", n, err)
		}
	}
	for _, n := range []int{16, 32, 64} {
		p := floorParams()
		p.Salt = make([]byte, n)
		if err := p.CheckFloor(); err != nil {
			t.Fatalf("salt len=%d rejected: %v", n, err)
		}
	}
}

func TestNewParamsAtFloor(t *testing.T) {
	p := NewParams(newDRBG("params"))
	if err := p.CheckFloor(); err != nil {
		t.Fatalf("NewParams produced params below the floor: %v", err)
	}
	if len(p.Salt) != 16 {
		t.Fatalf("len(Salt) = %d, want 16", len(p.Salt))
	}
}

func TestParamsJSONRoundTrip(t *testing.T) {
	p := NewParams(newDRBG("json"))
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var got Params
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Alg != p.Alg || got.Memory != p.Memory || got.Time != p.Time || got.Threads != p.Threads || !bytes.Equal(got.Salt, p.Salt) {
		t.Fatalf("round trip: got %+v, want %+v", got, p)
	}
}

func TestParamsJSONFieldNames(t *testing.T) {
	p := floorParams()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, key := range []string{`"alg"`, `"m"`, `"t"`, `"p"`, `"salt"`} {
		if !strings.Contains(s, key) {
			t.Fatalf("JSON %s missing key %s", s, key)
		}
	}
	if strings.ContainsAny(s, "+/") {
		t.Fatalf("salt not base64url: %s", s)
	}
}

func TestStretchRejectsBelowFloor(t *testing.T) {
	p := floorParams()
	p.Time = 1
	if _, err := Stretch([]byte("password"), p); !errors.Is(err, ErrFloor) {
		t.Fatalf("Stretch with weak params: got %v, want ErrFloor", err)
	}
}

func TestStretchDeterministic(t *testing.T) {
	p := floorParams()
	a, err := Stretch([]byte("password"), p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Stretch([]byte("password"), p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("Stretch not deterministic for identical inputs")
	}
	if len(a) != 32 {
		t.Fatalf("len(stretched) = %d, want 32", len(a))
	}
}

func TestStretchDiffersByPassword(t *testing.T) {
	p := floorParams()
	a, err := Stretch([]byte("password-1"), p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Stretch([]byte("password-2"), p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("Stretch produced the same output for two different passwords")
	}
}

func TestPasswordKeysDiffer(t *testing.T) {
	stretched := make([]byte, 32)
	authKey, kek := PasswordKeys(stretched)
	if bytes.Equal(authKey, kek) {
		t.Fatal("authKey and kek must differ")
	}
}

func TestRecoveryCodeFormat(t *testing.T) {
	code, display := NewRecoveryCode(newDRBG("recovery"))
	if len(code) != 16 {
		t.Fatalf("len(code) = %d, want 16", len(code))
	}
	parts := strings.Split(display, "-")
	if len(parts) != 7 {
		t.Fatalf("display has %d groups, want 7: %s", len(parts), display)
	}
	for i, part := range parts {
		want := 4
		if i == 6 {
			want = 2
		}
		if len(part) != want {
			t.Fatalf("group %d is %q, want length %d", i, part, want)
		}
	}
}

func TestRecoveryCodeRoundTrip(t *testing.T) {
	code, display := NewRecoveryCode(newDRBG("recovery-2"))
	got, err := ParseRecoveryCode(display)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, code) {
		t.Fatal("round trip did not reproduce the original code")
	}
}

func TestRecoveryCodeParseIgnoresCaseAndSpaces(t *testing.T) {
	code, display := NewRecoveryCode(newDRBG("recovery-3"))
	variant := strings.ToLower(strings.ReplaceAll(display, "-", " "))
	got, err := ParseRecoveryCode(variant)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, code) {
		t.Fatal("lowercase/space variant did not parse to the same code")
	}
}

func TestRecoveryCodeParseRejectsBadInput(t *testing.T) {
	_, display := NewRecoveryCode(newDRBG("recovery-4"))
	cases := []string{
		"",
		"not-a-recovery-code",
		display + "A",            // too long
		display[:len(display)-5], // too short
		strings.Replace(display, display[:1], "!", 1), // invalid character
	}
	for _, c := range cases {
		if _, err := ParseRecoveryCode(c); !errors.Is(err, ErrFormat) {
			t.Errorf("ParseRecoveryCode(%q) = %v, want ErrFormat", c, err)
		}
	}
}

func TestRecoveryKEK(t *testing.T) {
	code, _ := NewRecoveryCode(newDRBG("recovery-5"))
	k1 := RecoveryKEK(code)
	k2 := RecoveryKEK(code)
	if !bytes.Equal(k1, k2) {
		t.Fatal("RecoveryKEK not deterministic")
	}
	if len(k1) != 32 {
		t.Fatalf("len(RecoveryKEK) = %d, want 32", len(k1))
	}
}

func TestAPIKeyRoundTrip(t *testing.T) {
	full, keyID, authSecret, keySecret := NewAPIKey(newDRBG("apikey"))
	parsed, err := ParseAPIKey(full)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeyID != keyID || parsed.AuthSecret != authSecret || !bytes.Equal(parsed.KeySecret, keySecret) {
		t.Fatalf("parsed %+v does not match generated parts", parsed)
	}
	if !strings.HasPrefix(full, "cairn_") {
		t.Fatalf("full key %q missing prefix", full)
	}
}

func TestParseAPIKeyRejectsBadInput(t *testing.T) {
	full, _, _, _ := NewAPIKey(newDRBG("apikey-2"))
	cases := []string{
		"",
		"cairn_",
		strings.Replace(full, "cairn_", "wrong_", 1),
		full[:len(full)-1],                 // truncated
		full + "_extra",                    // an extra part
		strings.Replace(full, "_", "-", 1), // missing a separator
	}
	for _, c := range cases {
		if _, err := ParseAPIKey(c); !errors.Is(err, ErrFormat) {
			t.Errorf("ParseAPIKey(%q) = _, %v, want ErrFormat", c, err)
		}
	}
}

func TestAPIKeyKEK(t *testing.T) {
	_, keyID, _, keySecret := NewAPIKey(newDRBG("apikey-3"))
	k1 := APIKeyKEK(keySecret, keyID)
	k2 := APIKeyKEK(keySecret, keyID)
	if !bytes.Equal(k1, k2) {
		t.Fatal("APIKeyKEK not deterministic")
	}
	other := APIKeyKEK(keySecret, keyID+"x")
	if bytes.Equal(k1, other) {
		t.Fatal("APIKeyKEK ignored keyID")
	}
}

func TestPreloginSalt(t *testing.T) {
	secret := []byte("server-secret")
	a := PreloginSalt(secret, "ada@example.com")
	if len(a) != 16 {
		t.Fatalf("len = %d, want 16", len(a))
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(Enc([]byte(LabelPrelogin), []byte("ada@example.com")))
	if !bytes.Equal(a, mac.Sum(nil)[:16]) {
		t.Fatal("PreloginSalt is not HMAC-SHA256(secret, enc(label, email))[:16]")
	}
	if bytes.Equal(a, PreloginSalt(secret, "bob@example.com")) {
		t.Fatal("two addresses gave the same salt")
	}
	if bytes.Equal(a, PreloginSalt([]byte("other-secret"), "ada@example.com")) {
		t.Fatal("two secrets gave the same salt")
	}
	p := Params{Alg: "argon2id", Memory: floorMemory, Time: floorTime, Threads: 1, Salt: a}
	if err := p.CheckFloor(); err != nil {
		t.Fatalf("fake salt fails the floor: %v", err)
	}
}
