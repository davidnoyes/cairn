// Account operations: sign-up, sign-in, password reset, and API keys. Every
// byte sent on the wire is built with internal/e2e, which is the only place
// that touches the cryptographic primitives; this file is wiring and HTTP.
package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// bundleWire mirrors the server's key-bundle JSON (design/e2e-wire-formats.md
// and internal/server/wire.go): every byte field is base64url without
// padding.
type bundleWire struct {
	KDF         json.RawMessage `json:"kdf"`
	MKPassword  string          `json:"mkPassword"`
	MKRecovery  string          `json:"mkRecovery"`
	X25519Pub   string          `json:"x25519Pub"`
	X25519Priv  string          `json:"x25519Priv"`
	Ed25519Pub  string          `json:"ed25519Pub"`
	Ed25519Priv string          `json:"ed25519Priv"`
	EK          string          `json:"ek"`
}

// sealField seals pt under key, bound to the single literal field name field,
// and returns it base64url-encoded for the wire.
func sealField(key []byte, field string, pt []byte) (string, error) {
	sealed, err := e2e.Seal(rand.Reader, key, [][]byte{[]byte(field)}, pt)
	if err != nil {
		return "", err
	}
	return e2e.B64(sealed), nil
}

// generateAccount creates a brand-new key bundle: a fresh MK, X25519 and
// Ed25519 key pairs, EK, and a recovery code, all sealed under a freshly
// stretched password. Signup and a "new"-mode reset both start an account
// over from here.
func generateAccount(email, password string) (authKey []byte, wire bundleWire, recoveryDisplay string, err error) {
	params, err := e2e.NewParams(rand.Reader)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	stretched, err := e2e.Stretch([]byte(password), email, params)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	authKey, kek := e2e.PasswordKeys(stretched)

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		return nil, bundleWire{}, "", err
	}
	ek := make([]byte, 32)
	if _, err := rand.Read(ek); err != nil {
		return nil, bundleWire{}, "", err
	}
	recoveryCode, recoveryDisplay, err := e2e.NewRecoveryCode(rand.Reader)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	x25519Priv, x25519Pub, err := e2e.GenerateX25519(rand.Reader)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	ed25519Seed, ed25519Pub, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	mkSealKey, err := e2e.MKSealKey(mk)
	if err != nil {
		return nil, bundleWire{}, "", err
	}

	mkPassword, err := sealField(kek, "mk", mk)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	mkRecovery, err := sealField(e2e.RecoveryKEK(recoveryCode), "mk", mk)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	x25519PrivSealed, err := sealField(mkSealKey, "x25519", x25519Priv)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	ed25519PrivSealed, err := sealField(mkSealKey, "ed25519", ed25519Seed)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	ekSealed, err := sealField(mkSealKey, "ek", ek)
	if err != nil {
		return nil, bundleWire{}, "", err
	}
	kdfJSON, err := json.Marshal(params)
	if err != nil {
		return nil, bundleWire{}, "", err
	}

	wire = bundleWire{
		KDF:         kdfJSON,
		MKPassword:  mkPassword,
		MKRecovery:  mkRecovery,
		X25519Pub:   e2e.B64(x25519Pub),
		X25519Priv:  x25519PrivSealed,
		Ed25519Pub:  e2e.B64(ed25519Pub),
		Ed25519Priv: ed25519PrivSealed,
		EK:          ekSealed,
	}
	return authKey, wire, recoveryDisplay, nil
}

// Signup generates a fresh key bundle and a recovery code, then signs up.
// Nothing but wrapped material and the authentication key ever leaves this
// function. It returns the recovery code's display form, shown once.
func (c *Client) Signup(email, name, password string) (recoveryDisplay string, err error) {
	email = e2e.NormalizeEmail(email)
	if err := CheckNewPassword(password, email, name); err != nil {
		return "", err
	}
	authKey, wire, recoveryDisplay, err := generateAccount(email, password)
	if err != nil {
		return "", err
	}
	if err := c.doJSON("POST", "/api/auth/signup", map[string]any{
		"email": email, "name": name, "authKey": e2e.B64(authKey), "bundle": wire,
	}, nil); err != nil {
		return "", err
	}
	return recoveryDisplay, nil
}

// LinkHost returns the origin (scheme://host) of an emailed verification or
// reset link, so confirm-email and reset don't need a separate --host flag.
func LinkHost(link string) (string, error) {
	base, _, _ := strings.Cut(link, "#")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q is not a valid link", link)
	}
	return u.Scheme + "://" + u.Host, nil
}

// tokenFromLink pulls the b64 token out of a link's "#token=" fragment, which
// browsers never send to a server.
func tokenFromLink(link string) (string, error) {
	_, token, ok := strings.Cut(link, "#token=")
	if !ok || token == "" {
		return "", fmt.Errorf("%q is not a verification or reset link", link)
	}
	return token, nil
}

// ConfirmEmail follows a verification link of the form
// "<public-url>/verify#token=<b64>".
func (c *Client) ConfirmEmail(link string) error {
	token, err := tokenFromLink(link)
	if err != nil {
		return err
	}
	return c.doJSON("POST", "/api/auth/verify", map[string]string{"token": token}, nil)
}

// Forgot asks the server to email a reset link, if the address has a
// verified account. It always succeeds, so it never reveals which addresses
// do.
func (c *Client) Forgot(email string) error {
	return c.doJSON("POST", "/api/auth/forgot", map[string]string{"email": e2e.NormalizeEmail(email)}, nil)
}

// apiKeyBearer is the bearer credential presented on every later request:
// the key id and auth secret, never keySecret.
func apiKeyBearer(keyID, authSecret string) string {
	return "cairn_" + keyID + "_" + authSecret
}

// LoginResult is what a successful Login returns for the caller to save.
type LoginResult struct {
	APIKey  string // the full four-part key: cairn_<keyid>_<authSecret>_<keySecret>
	Email   string
	Name    string
	IsAdmin bool
}

// Login signs in, then creates a device API key and leaves it set as c.Token
// (as the bearer cairn_<keyid>_<authSecret>) so the client is usable right
// away. The full four-part key, including keySecret, is returned for the
// caller to save; it never touches the wire.
func (c *Client) Login(email, password string) (*LoginResult, error) {
	if password == "" {
		return nil, fmt.Errorf("password must not be empty")
	}
	email = e2e.NormalizeEmail(email)
	var params e2e.Params
	if err := c.doJSON("POST", "/api/auth/prelogin", map[string]string{"email": email}, &params); err != nil {
		return nil, err
	}
	stretched, err := e2e.Stretch([]byte(password), email, params)
	if err != nil {
		return nil, err
	}
	authKey, kek := e2e.PasswordKeys(stretched)

	var loginOut struct {
		User struct {
			Email   string `json:"email"`
			Name    string `json:"name"`
			IsAdmin bool   `json:"isAdmin"`
		} `json:"user"`
		Bundle bundleWire `json:"bundle"`
		Token  string     `json:"token"`
	}
	if err := c.doJSON("POST", "/api/auth/login", map[string]any{
		"email": email, "authKey": e2e.B64(authKey), "client": "cli",
	}, &loginOut); err != nil {
		return nil, err
	}

	mkPassword, err := e2e.UnB64(loginOut.Bundle.MKPassword)
	if err != nil {
		return nil, err
	}
	mk, err := e2e.Open(kek, [][]byte{[]byte("mk")}, mkPassword)
	if err != nil {
		return nil, fmt.Errorf("opening MK: %w", err)
	}

	full, keyID, authSecret, keySecret, err := e2e.NewAPIKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sealedMK, err := e2e.Seal(rand.Reader, e2e.APIKeyKEK(keySecret, keyID), [][]byte{[]byte("mk"), []byte(keyID)}, mk)
	if err != nil {
		return nil, err
	}

	// The device key is created with the session JWT login just returned,
	// never with the API key it's about to make.
	session := &Client{Host: c.Host, Token: loginOut.Token, HTTP: c.HTTP}
	if err := session.doJSON("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(authKey), "name": "device", "device": true,
		"keyId": keyID, "authSecret": authSecret, "mk": e2e.B64(sealedMK),
	}, nil); err != nil {
		return nil, err
	}

	c.Token = apiKeyBearer(keyID, authSecret)
	return &LoginResult{APIKey: full, Email: loginOut.User.Email, Name: loginOut.User.Name, IsAdmin: loginOut.User.IsAdmin}, nil
}

// MeBundleResult is the caller's key bundle as returned by GET
// /api/me/bundle, trimmed to what whoami and a recovery reset need.
type MeBundleResult struct {
	X25519Pub   []byte
	Ed25519Pub  []byte
	Ed25519Priv []byte // sealed under mkSealKey(MK)
	APIKeyID    string // the id of the API key that authenticated this request, if any
	APIKeyMK    []byte // that key's own sealed copy of MK, sealed under APIKeyKEK(keySecret, keyID)
}

func (c *Client) MeBundle() (MeBundleResult, error) {
	var resp struct {
		X25519Pub   string `json:"x25519Pub"`
		Ed25519Pub  string `json:"ed25519Pub"`
		Ed25519Priv string `json:"ed25519Priv"`
		APIKey      *struct {
			ID string `json:"id"`
			MK string `json:"mk"`
		} `json:"apiKey,omitempty"`
	}
	if err := c.doJSON("GET", "/api/me/bundle", nil, &resp); err != nil {
		return MeBundleResult{}, err
	}
	x25519Pub, err := e2e.UnB64(resp.X25519Pub)
	if err != nil {
		return MeBundleResult{}, err
	}
	ed25519Pub, err := e2e.UnB64(resp.Ed25519Pub)
	if err != nil {
		return MeBundleResult{}, err
	}
	ed25519Priv, err := e2e.UnB64(resp.Ed25519Priv)
	if err != nil {
		return MeBundleResult{}, err
	}
	out := MeBundleResult{X25519Pub: x25519Pub, Ed25519Pub: ed25519Pub, Ed25519Priv: ed25519Priv}
	if resp.APIKey != nil {
		mk, err := e2e.UnB64(resp.APIKey.MK)
		if err != nil {
			return MeBundleResult{}, err
		}
		out.APIKeyID = resp.APIKey.ID
		out.APIKeyMK = mk
	}
	return out, nil
}

// Logout revokes an API key — ordinarily the caller's own device key.
func (c *Client) Logout(keyID string) error {
	return c.RevokeKey(keyID)
}

// APIKeyInfo is one of the user's own API keys, as listed by GET /api/keys.
type APIKeyInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Device     bool   `json:"device"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
}

func (c *Client) ListKeys() ([]APIKeyInfo, error) {
	var out []APIKeyInfo
	return out, c.doJSON("GET", "/api/keys", nil, &out)
}

func (c *Client) RevokeKey(id string) error {
	return c.doJSON("DELETE", "/api/keys/"+id, nil, nil)
}

// ResetInfo is what reset/begin exposes about the account a token belongs
// to.
type ResetInfo struct {
	ID          string
	Email       string
	MKRecovery  []byte
	X25519Pub   []byte
	Ed25519Pub  []byte
	Ed25519Priv []byte // sealed under mkSealKey(MK)
}

// resetBegin reads the token out of link and asks the server what completing
// the reset needs, without using the token up.
func (c *Client) resetBegin(link string) (ResetInfo, string, error) {
	token, err := tokenFromLink(link)
	if err != nil {
		return ResetInfo{}, "", err
	}
	var resp struct {
		ID          string `json:"id"`
		Email       string `json:"email"`
		MKRecovery  string `json:"mkRecovery"`
		X25519Pub   string `json:"x25519Pub"`
		Ed25519Pub  string `json:"ed25519Pub"`
		Ed25519Priv string `json:"ed25519Priv"`
	}
	if err := c.doJSON("POST", "/api/auth/reset/begin", map[string]string{"token": token}, &resp); err != nil {
		return ResetInfo{}, "", err
	}
	mkRecovery, err := e2e.UnB64(resp.MKRecovery)
	if err != nil {
		return ResetInfo{}, "", err
	}
	x25519Pub, err := e2e.UnB64(resp.X25519Pub)
	if err != nil {
		return ResetInfo{}, "", err
	}
	ed25519Pub, err := e2e.UnB64(resp.Ed25519Pub)
	if err != nil {
		return ResetInfo{}, "", err
	}
	ed25519Priv, err := e2e.UnB64(resp.Ed25519Priv)
	if err != nil {
		return ResetInfo{}, "", err
	}
	return ResetInfo{ID: resp.ID, Email: resp.Email, MKRecovery: mkRecovery, X25519Pub: x25519Pub, Ed25519Pub: ed25519Pub, Ed25519Priv: ed25519Priv}, token, nil
}

// hashToken returns hex(SHA-256(the raw token)), matching what the server
// stores and what a reset proof binds to, from the token's b64 wire form.
func hashToken(tokenB64 string) (string, error) {
	raw, err := e2e.UnB64(tokenB64)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// resetProofBody mirrors the server's internal/server.resetProofBody
// (design/e2e-wire-formats.md's "reset" purpose): {"v":1,"user","token"}.
type resetProofBody struct {
	V     int    `json:"v"`
	User  string `json:"user"`
	Token string `json:"token"`
}

// ResetRecovery completes a recovery-mode password reset: it opens MK with
// the recovery code and re-wraps it under a freshly stretched new password,
// keeping the account's key pairs. It proves control of MK by opening the
// existing Ed25519 key that reset/begin returns sealed, and signing with it.
func (c *Client) ResetRecovery(link, recoveryCode, newPassword string) error {
	// Checked once before any network call, then again below with the
	// account's email, which only reset/begin reveals.
	if err := CheckNewPassword(newPassword); err != nil {
		return err
	}
	info, token, err := c.resetBegin(link)
	if err != nil {
		return err
	}
	if err := CheckNewPassword(newPassword, info.Email); err != nil {
		return err
	}
	code, err := e2e.ParseRecoveryCode(recoveryCode)
	if err != nil {
		return err
	}
	mk, err := e2e.Open(e2e.RecoveryKEK(code), [][]byte{[]byte("mk")}, info.MKRecovery)
	if err != nil {
		return fmt.Errorf("wrong recovery code")
	}
	mkSealKey, err := e2e.MKSealKey(mk)
	if err != nil {
		return err
	}
	ed25519Seed, err := e2e.Open(mkSealKey, [][]byte{[]byte("ed25519")}, info.Ed25519Priv)
	if err != nil {
		return fmt.Errorf("opening signing key: %w", err)
	}
	tokenHash, err := hashToken(token)
	if err != nil {
		return err
	}
	body, err := json.Marshal(resetProofBody{V: 1, User: info.ID, Token: tokenHash})
	if err != nil {
		return err
	}
	sig, err := e2e.Sign(ed25519Seed, "reset", body)
	if err != nil {
		return err
	}

	newParams, err := e2e.NewParams(rand.Reader)
	if err != nil {
		return err
	}
	newStretched, err := e2e.Stretch([]byte(newPassword), info.Email, newParams)
	if err != nil {
		return err
	}
	newAuthKey, newKek := e2e.PasswordKeys(newStretched)
	newMKPassword, err := sealField(newKek, "mk", mk)
	if err != nil {
		return err
	}
	kdfJSON, err := json.Marshal(newParams)
	if err != nil {
		return err
	}

	return c.doJSON("POST", "/api/auth/reset/complete", map[string]any{
		"token": token, "mode": "recovery", "authKey": e2e.B64(newAuthKey),
		"kdf": json.RawMessage(kdfJSON), "mkPassword": newMKPassword, "proof": e2e.B64(sig),
	}, nil)
}

// ResetNew completes a password reset by discarding the old key material: a
// brand-new MK, key pairs, EK, and recovery code. The account's old private
// work becomes unreadable; others can re-share with the new public keys
// after seeing the key-change warning. Returns the new recovery code's
// display form.
func (c *Client) ResetNew(link, newPassword string) (recoveryDisplay string, err error) {
	// Checked once before any network call, then again below with the
	// account's email, which only reset/begin reveals.
	if err := CheckNewPassword(newPassword); err != nil {
		return "", err
	}
	info, token, err := c.resetBegin(link)
	if err != nil {
		return "", err
	}
	if err := CheckNewPassword(newPassword, info.Email); err != nil {
		return "", err
	}
	authKey, wire, recoveryDisplay, err := generateAccount(info.Email, newPassword)
	if err != nil {
		return "", err
	}
	if err := c.doJSON("POST", "/api/auth/reset/complete", map[string]any{
		"token": token, "mode": "new", "authKey": e2e.B64(authKey), "bundle": wire,
	}, nil); err != nil {
		return "", err
	}
	return recoveryDisplay, nil
}
