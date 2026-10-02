package auth

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestUseMinCostForTests(t *testing.T) {
	prev := passwordCost
	t.Cleanup(func() { passwordCost = prev })
	UseMinCostForTests()
	hash, err := HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(hash, "s3cret-pass") || CheckPassword(hash, "wrong") {
		t.Fatal("hash does not verify")
	}
	if cost, err := bcrypt.Cost([]byte(hash)); err != nil || cost != bcrypt.MinCost {
		t.Fatalf("cost %d (%v), want %d", cost, err, bcrypt.MinCost)
	}
}

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

// payload decodes a token's claims without verifying it, to see the wire names.
func payload(t *testing.T, token string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestJWTArtifactClaim(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	exp := time.Now().Add(time.Hour).Unix()
	scoped, _ := SignJWT(secret, Claims{UserID: "u1", Artifact: "a1", ExpiresAt: exp})
	if got := payload(t, scoped)["art"]; got != "a1" {
		t.Errorf("art claim = %v, want a1", got)
	}
	if c, err := VerifyJWT(secret, scoped); err != nil || c.Artifact != "a1" {
		t.Errorf("verified claims: %+v, %v", c, err)
	}
	login, _ := SignJWT(secret, Claims{UserID: "u1", ExpiresAt: exp})
	if _, ok := payload(t, login)["art"]; ok {
		t.Error("a sign-in token carries an art claim")
	}
}

func TestJWTExpiry(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	token, _ := SignJWT(secret, Claims{UserID: "u1", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if _, err := VerifyJWT(secret, token); err == nil {
		t.Error("expired token verified")
	}
}
