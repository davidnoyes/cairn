package e2e

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
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
	p, err := NewParams(newDRBG("params"))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckFloor(); err != nil {
		t.Fatalf("NewParams produced params below the floor: %v", err)
	}
	if len(p.Salt) != 16 {
		t.Fatalf("len(Salt) = %d, want 16", len(p.Salt))
	}
}

func TestParamsCheckFloorCeiling(t *testing.T) {
	p := floorParams()
	p.Memory = ceilingMemory + 1
	if err := p.CheckFloor(); !errors.Is(err, ErrFloor) {
		t.Fatalf("memory one above ceiling: got %v, want ErrFloor", err)
	}
	p = floorParams()
	p.Memory = ceilingMemory
	if err := p.CheckFloor(); err != nil {
		t.Fatalf("memory at ceiling rejected: %v", err)
	}
	p = floorParams()
	p.Time = ceilingTime + 1
	if err := p.CheckFloor(); !errors.Is(err, ErrFloor) {
		t.Fatalf("time one above ceiling: got %v, want ErrFloor", err)
	}
	p = floorParams()
	p.Time = ceilingTime
	if err := p.CheckFloor(); err != nil {
		t.Fatalf("time at ceiling rejected: %v", err)
	}
}

func TestParamsJSONRoundTrip(t *testing.T) {
	p, err := NewParams(newDRBG("json"))
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := Stretch([]byte("password"), "user@example.com", p); !errors.Is(err, ErrFloor) {
		t.Fatalf("Stretch with weak params: got %v, want ErrFloor", err)
	}
}

func TestStretchDeterministic(t *testing.T) {
	p := floorParams()
	a, err := Stretch([]byte("password"), "user@example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Stretch([]byte("password"), "user@example.com", p)
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
	a, err := Stretch([]byte("password-1"), "user@example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Stretch([]byte("password-2"), "user@example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("Stretch produced the same output for two different passwords")
	}
}

func TestStretchDiffersByEmail(t *testing.T) {
	p := floorParams()
	a, err := Stretch([]byte("password"), "ada@example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Stretch([]byte("password"), "bob@example.com", p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("Stretch produced the same output for two different emails")
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Ada@Example.COM", "ada@example.com"},
		{"  ada@example.com  ", "ada@example.com"},
		{"\t\nada@example.com\r\n", "ada@example.com"},
		{"ada@example.com", "ada@example.com"},
	}
	for _, c := range cases {
		if got := NormalizeEmail(c.in); got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestArgonSaltDeterministicAndEmailBound(t *testing.T) {
	serverSalt := testKey("argon-salt-server")
	a := ArgonSalt("ada@example.com", serverSalt)
	b := ArgonSalt("ada@example.com", serverSalt)
	if !bytes.Equal(a, b) {
		t.Fatal("ArgonSalt not deterministic")
	}
	if len(a) != 32 {
		t.Fatalf("len(ArgonSalt) = %d, want 32", len(a))
	}
	if bytes.Equal(a, ArgonSalt("bob@example.com", serverSalt)) {
		t.Fatal("ArgonSalt ignored the email")
	}
	if bytes.Equal(a, ArgonSalt("ada@example.com", testKey("argon-salt-other"))) {
		t.Fatal("ArgonSalt ignored the server salt")
	}
	// Case and whitespace variants of the same address must land on the same
	// salt, since NormalizeEmail is applied internally.
	if !bytes.Equal(a, ArgonSalt("  Ada@Example.COM ", serverSalt)) {
		t.Fatal("ArgonSalt did not normalize the email")
	}
}

func TestStretchUsesArgonSalt(t *testing.T) {
	p := floorParams()
	got, err := Stretch([]byte("password"), "  Alice@Example.COM ", p)
	if err != nil {
		t.Fatal(err)
	}
	want := argon2.IDKey([]byte("password"), ArgonSalt("  Alice@Example.COM ", p.Salt), p.Time, p.Memory, p.Threads, 32)
	if !bytes.Equal(got, want) {
		t.Fatal("Stretch does not use ArgonSalt(email, params.salt)")
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
	code, display, err := NewRecoveryCode(newDRBG("recovery"))
	if err != nil {
		t.Fatal(err)
	}
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
	code, display, err := NewRecoveryCode(newDRBG("recovery-2"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRecoveryCode(display)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, code) {
		t.Fatal("round trip did not reproduce the original code")
	}
}

func TestRecoveryCodeParseIgnoresCaseAndSpaces(t *testing.T) {
	code, display, err := NewRecoveryCode(newDRBG("recovery-3"))
	if err != nil {
		t.Fatal(err)
	}
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
	_, display, err := NewRecoveryCode(newDRBG("recovery-4"))
	if err != nil {
		t.Fatal(err)
	}
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

func TestRecoveryCodeParseRejectsNonASCIILetters(t *testing.T) {
	_, display, err := NewRecoveryCode(newDRBG("recovery-nonascii"))
	if err != nil {
		t.Fatal(err)
	}
	// Each of these would fold onto an allowed ASCII letter under some
	// locale's case mapping; ParseRecoveryCode must reject them before any
	// folding happens.
	for _, bad := range []string{"ſ", "ı", "ß", "K"} { // long s, dotless i, sharp s, Kelvin sign
		c := bad + display[1:]
		if _, err := ParseRecoveryCode(c); !errors.Is(err, ErrFormat) {
			t.Errorf("ParseRecoveryCode with %q: got %v, want ErrFormat", bad, err)
		}
	}
}

func TestRecoveryCodeParseRejectsNonZeroTrailingBits(t *testing.T) {
	_, display, err := NewRecoveryCode(newDRBG("recovery-trailing"))
	if err != nil {
		t.Fatal(err)
	}
	// Replace the last character with one whose low 2 bits are non-zero.
	bad := nonZeroTrailingBitsChar(display[len(display)-1])
	mutated := display[:len(display)-1] + bad
	if _, err := ParseRecoveryCode(mutated); !errors.Is(err, ErrFormat) {
		t.Fatalf("non-zero trailing bits: got %v, want ErrFormat", err)
	}
}

func TestRecoveryCodeParseRejectsDisallowedDigits(t *testing.T) {
	_, display, err := NewRecoveryCode(newDRBG("recovery-digits"))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []byte{'0', '1', '8'} {
		c := string(bad) + display[1:]
		if _, err := ParseRecoveryCode(c); !errors.Is(err, ErrFormat) {
			t.Errorf("ParseRecoveryCode with %q: got %v, want ErrFormat", bad, err)
		}
	}
}

func TestRecoveryKEK(t *testing.T) {
	code, _, err := NewRecoveryCode(newDRBG("recovery-5"))
	if err != nil {
		t.Fatal(err)
	}
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
	full, keyID, authSecret, keySecret, err := NewAPIKey(newDRBG("apikey"))
	if err != nil {
		t.Fatal(err)
	}
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
	full, _, _, _, err := NewAPIKey(newDRBG("apikey-2"))
	if err != nil {
		t.Fatal(err)
	}
	// The second underscore is the separator between authSecret and
	// keySecret (the first underscore sits inside the "cairn_" prefix), so
	// removing it merges two parts instead of just shortening the prefix.
	secondUnderscore := strings.Index(full, "_") + 1 + strings.Index(full[strings.Index(full, "_")+1:], "_")
	missingSeparator := full[:secondUnderscore] + full[secondUnderscore+1:]
	cases := []string{
		"",
		"cairn_",
		strings.Replace(full, "cairn_", "wrong_", 1),
		full[:len(full)-1], // truncated
		full + "_extra",    // an extra part
		missingSeparator,   // missing a separator between parts
	}
	for _, c := range cases {
		if _, err := ParseAPIKey(c); !errors.Is(err, ErrFormat) {
			t.Errorf("ParseAPIKey(%q) = _, %v, want ErrFormat", c, err)
		}
	}
}

func TestParseAPIKeyRejectsUppercaseHex(t *testing.T) {
	full, _, _, _, err := NewAPIKey(newDRBG("apikey-upper"))
	if err != nil {
		t.Fatal(err)
	}
	upper := strings.ToUpper(full[len("cairn_"):])
	if _, err := ParseAPIKey("cairn_" + upper); !errors.Is(err, ErrFormat) {
		t.Fatalf("uppercase hex: got %v, want ErrFormat", err)
	}
}

func TestAPIKeyStringRedactsKeySecret(t *testing.T) {
	full, keyID, authSecret, keySecret, err := NewAPIKey(newDRBG("apikey-string"))
	if err != nil {
		t.Fatal(err)
	}
	k := APIKey{Full: full, KeyID: keyID, AuthSecret: authSecret, KeySecret: keySecret}
	s := k.String()
	if strings.Contains(s, hex.EncodeToString(keySecret)) {
		t.Fatalf("String() leaked keySecret: %q", s)
	}
	if k.Full != full {
		t.Fatal("Full field no longer holds the complete key")
	}
}

func TestAPIKeyAuthHash(t *testing.T) {
	_, _, authSecret, _, err := NewAPIKey(newDRBG("apikey-authhash"))
	if err != nil {
		t.Fatal(err)
	}
	got := APIKeyAuthHash(authSecret)
	want := sha256.Sum256([]byte(authSecret))
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("APIKeyAuthHash = %q, want hex(SHA-256(authSecret string))", got)
	}
}

func TestAPIKeyKEK(t *testing.T) {
	_, keyID, _, keySecret, err := NewAPIKey(newDRBG("apikey-3"))
	if err != nil {
		t.Fatal(err)
	}
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

func TestPreloginSaltNormalizesEmail(t *testing.T) {
	secret := []byte("server-secret-2")
	if !bytes.Equal(PreloginSalt(secret, "A@B.c "), PreloginSalt(secret, "a@b.c")) {
		t.Fatal("PreloginSalt did not normalize the email")
	}
}
