// Package auth implements Cairn's credentials: bcrypt passwords, HS256 JWTs
// and API keys.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Passwords

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

// API keys, formatted "cairn_<keyid>_<secret>". The key id gives O(1) lookup;
// only SHA-256(secret) is stored.

const apiKeyPrefix = "cairn_"

// NewAPIKey generates a key, returning its id, the full token to show once,
// and the secret hash to store.
func NewAPIKey() (id, token, secretHash string, err error) {
	idB := make([]byte, 8)
	secretB := make([]byte, 24)
	if _, err = rand.Read(idB); err != nil {
		return
	}
	if _, err = rand.Read(secretB); err != nil {
		return
	}
	id = hex.EncodeToString(idB)
	secret := b64.EncodeToString(secretB)
	token = apiKeyPrefix + id + "_" + secret
	secretHash = HashAPIKeySecret(secret)
	return
}

// ParseAPIKey splits a presented token into key id and secret.
func ParseAPIKey(token string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(token, apiKeyPrefix)
	if !found {
		return "", "", false
	}
	id, secret, ok = strings.Cut(rest, "_")
	return id, secret, ok && id != "" && secret != ""
}

func HashAPIKeySecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// IsAPIKey reports whether a bearer credential looks like an API key rather
// than a JWT.
func IsAPIKey(token string) bool {
	return strings.HasPrefix(token, apiKeyPrefix)
}
