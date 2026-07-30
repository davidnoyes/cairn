package auth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	hash, err := HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(hash, "s3cret-pass") {
		t.Error("correct password rejected")
	}
	if CheckPassword(hash, "wrong") {
		t.Error("wrong password accepted")
	}
}

func TestSecretPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	s1, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(s1) != string(s2) {
		t.Error("secret not stable across loads")
	}
	if len(s1) < 32 {
		t.Errorf("secret too short: %d", len(s1))
	}
}

func TestJWTRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	claims := Claims{UserID: "u1", IsAdmin: true, TokenVersion: 3, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix()}
	token, err := SignJWT(secret, claims)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyJWT(secret, token)
	if err != nil {
		t.Fatal(err)
	}
	if *got != claims {
		t.Errorf("claims mismatch: %+v != %+v", got, claims)
	}
	if _, err := VerifyJWT([]byte("another-secret-another-secret-32"), token); err == nil {
		t.Error("token verified with wrong secret")
	}
	if _, err := VerifyJWT(secret, token+"x"); err == nil {
		t.Error("tampered token verified")
	}
}

func TestJWTExpiry(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	token, _ := SignJWT(secret, Claims{UserID: "u1", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if _, err := VerifyJWT(secret, token); err == nil {
		t.Error("expired token verified")
	}
}

func TestAPIKeyFormat(t *testing.T) {
	id, token, secretHash, err := NewAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if !IsAPIKey(token) {
		t.Fatalf("token %q not recognized as API key", token)
	}
	gotID, secret, ok := ParseAPIKey(token)
	if !ok || gotID != id {
		t.Fatalf("ParseAPIKey: ok=%v id=%q want %q", ok, gotID, id)
	}
	if HashAPIKeySecret(secret) != secretHash {
		t.Error("secret hash mismatch")
	}
	if _, _, ok := ParseAPIKey("cairn_missingsecret"); ok {
		t.Error("malformed key parsed")
	}
	if IsAPIKey("eyJhbGciOi...") {
		t.Error("JWT recognized as API key")
	}
}
