// Package auth implements Cairn's credentials: bcrypt passwords and HS256
// JWTs. API keys are in internal/e2e.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Passwords

// passwordCost is the bcrypt cost HashPassword uses.
var passwordCost = bcrypt.DefaultCost

// UseMinCostForTests drops the bcrypt cost to its minimum, so test suites
// that create many users do not pay for a production-cost hash each time:
// under the race detector one takes over half a second. It panics outside a
// test binary.
func UseMinCostForTests() {
	if !testing.Testing() {
		panic("auth: UseMinCostForTests called outside a test binary")
	}
	passwordCost = bcrypt.MinCost
}

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), passwordCost)
	return string(b), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// Signing secret

// LoadOrCreateSecret returns the JWT signing secret, generating a random one
// on first run.
func LoadOrCreateSecret(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) < 32 {
			return nil, fmt.Errorf("secret file %s is too short", path)
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// JWT (HS256, compact serialization)

// Claims is the JWT payload. TokenVersion must match the user row for the
// token to be accepted, which gives instant revocation on password change or
// account disable.
type Claims struct {
	UserID       string `json:"sub"`
	IsAdmin      bool   `json:"adm"`
	TokenVersion int    `json:"tkv"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
	// Artifact, when non-empty, makes the JWT a content-origin token scoped
	// to that artifact. Login never sets it.
	Artifact string `json:"art,omitempty"`
}

var b64 = base64.RawURLEncoding

func SignJWT(secret []byte, c Claims) (string, error) {
	header := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := header + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	return signing + "." + b64.EncodeToString(mac.Sum(nil)), nil
}

var ErrInvalidToken = errors.New("invalid token")

func VerifyJWT(secret []byte, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrInvalidToken
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrInvalidToken
	}
	if c.ExpiresAt < time.Now().Unix() {
		return nil, ErrInvalidToken
	}
	return &c, nil
}
