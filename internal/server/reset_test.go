package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// signedBundleWire builds a bundle whose Ed25519 key pair is real (so a reset
// proof signed with seed verifies), with everything else a placeholder.
func signedBundleWire(t *testing.T) (w bundleWire, seed, pub []byte) {
	t.Helper()
	seed, pub, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w = testBundleWire()
	w.Ed25519Pub = e2e.B64(pub)
	return w, seed, pub
}

func forgotPassword(t *testing.T, ts string, email string) string {
	t.Helper()
	c := &testClient{t: t, base: ts}
	c.mustDo("POST", "/api/auth/forgot", map[string]string{"email": email}, nil, http.StatusAccepted)
	return email
}

// TestResetRecoveryKeepsKeysAndArchivesNothing covers "a reset with the
// recovery code keeps both public keys", and the server-side half of
// restoring the archived MK: recovery mode must not create an archive.
func TestResetRecoveryKeepsKeys(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.SignupDomains = []string{"example.com"} })
	m := mailer(s)
	w, seed, pub := signedBundleWire(t)
	c := &testClient{t: t, base: ts.URL}
	c.mustDo("POST", "/api/auth/signup", map[string]any{
		"email": "ada@example.com", "name": "Ada", "authKey": e2e.B64(testAuthKey("pw")), "bundle": w,
	}, nil, http.StatusAccepted)
	verifyBody, _ := m.Last("ada@example.com")
	c.mustDo("POST", "/api/auth/verify", map[string]string{"token": extractFragmentToken(t, verifyBody.Body)}, nil, http.StatusOK)

	var loginOut struct {
		User struct{ ID string } `json:"user"`
	}
	c.mustDo("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("pw")), "client": "cli"}, &loginOut, http.StatusOK)
	userID := loginOut.User.ID

	forgotPassword(t, ts.URL, "ada@example.com")
	resetBody, _ := m.Last("ada@example.com")
	rawToken := extractFragmentToken(t, resetBody.Body)
	tokenBytes, err := e2e.UnB64(rawToken)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := hashToken(tokenBytes)

	var begin resetBeginResponse
	c.mustDo("POST", "/api/auth/reset/begin", map[string]string{"token": rawToken}, &begin, http.StatusOK)
	if begin.Ed25519Pub != e2e.B64(pub) {
		t.Errorf("reset/begin Ed25519Pub = %q, want %q", begin.Ed25519Pub, e2e.B64(pub))
	}

	proofBody, err := json.Marshal(resetProofBody{V: 1, User: userID, Token: tokenHash})
	if err != nil {
		t.Fatal(err)
	}
	sig := e2e.Sign(seed, "reset", proofBody)
	newKDF, _ := json.Marshal(e2e.Params{Alg: "argon2id", Memory: 65536, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{0x09}, 16)})
	newMKPassword := e2e.B64(bytes.Repeat([]byte{0x0a}, sealedKeyLen))

	c.mustDo("POST", "/api/auth/reset/complete", map[string]any{
		"token": rawToken, "mode": "recovery",
		"authKey": e2e.B64(testAuthKey("new-pw")),
		"kdf":     json.RawMessage(newKDF), "mkPassword": newMKPassword,
		"proof": e2e.B64(sig),
	}, nil, http.StatusOK)

	// The old password is dead; the new one works, with the SAME public keys.
	resp := c.do("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("pw")), "client": "cli"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password still works: %d", resp.StatusCode)
	}
	var out struct {
		Bundle bundleWire `json:"bundle"`
	}
	c.mustDo("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("new-pw")), "client": "cli"}, &out, http.StatusOK)
	if out.Bundle.Ed25519Pub != e2e.B64(pub) || out.Bundle.X25519Pub != w.X25519Pub {
		t.Errorf("recovery reset changed the public keys: %+v", out.Bundle)
	}

	// No archive was created by a recovery-mode reset.
	archiveClient := &testClient{t: t, base: ts.URL}
	loginAgain(t, archiveClient, "ada@example.com", "new-pw")
	var archives []archiveView
	archiveClient.mustDo("GET", "/api/me/archives", nil, &archives, http.StatusOK)
	if len(archives) != 0 {
		t.Errorf("recovery-mode reset created %d archives, want 0", len(archives))
	}
}

func loginAgain(t *testing.T, c *testClient, email, password string) {
	t.Helper()
	var out struct {
		Token string `json:"token"`
	}
	c.mustDo("POST", "/api/auth/login", map[string]any{"email": email, "authKey": e2e.B64(testAuthKey(password)), "client": "cli"}, &out, http.StatusOK)
	c.token = out.Token
}

// TestResetNewArchivesOldBundleAndKeys covers M1: a reset without the
// recovery code archives the old bundle and every API key's wrapped MK
// intact, revokes those keys, and the archived MK can be restored (verified
// here at the storage level, since opening it is the client's job).
func TestResetNewArchivesOldBundleAndKeys(t *testing.T) {
	s, ts := testServer(t)
	seedAccount(t, s, "ada@example.com", "old-pw", false)
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "ada@example.com", "old-pw")

	oldBundleResp := struct{ bundleWire }{}
	c.mustDo("GET", "/api/me/bundle", nil, &oldBundleResp, http.StatusOK)

	// Create an API key so the archive has something to carry.
	keyMK := e2e.B64(bytes.Repeat([]byte{0x42}, sealedKeyLen))
	var created createKeyResponse
	c.mustDo("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey("old-pw")), "name": "laptop", "device": true,
		"keyId": "0123456789abcdef", "authSecret": "0123456789abcdef0123456789abcdef", "mk": keyMK,
	}, &created, http.StatusCreated)

	forgotPassword(t, ts.URL, "ada@example.com")
	resetMail, ok := mailer(s).Last("ada@example.com")
	if !ok {
		t.Fatal("no reset mail sent")
	}
	rawToken := extractFragmentToken(t, resetMail.Body)

	newBundle := testBundleWire()
	newBundle.X25519Pub = e2e.B64(bytes.Repeat([]byte{0x99}, 32)) // distinguishable from the old one
	c.mustDo("POST", "/api/auth/reset/complete", map[string]any{
		"token": rawToken, "mode": "new",
		"authKey": e2e.B64(testAuthKey("new-pw")), "bundle": newBundle,
	}, nil, http.StatusOK)

	loginAgain(t, c, "ada@example.com", "new-pw")
	var me meView
	c.mustDo("GET", "/api/me", nil, &me, http.StatusOK)
	if me.ResetAt == "" {
		t.Error("resetAt not set after a password-only reset")
	}

	var archives []archiveView
	c.mustDo("GET", "/api/me/archives", nil, &archives, http.StatusOK)
	if len(archives) != 1 {
		t.Fatalf("got %d archives, want 1", len(archives))
	}
	a := archives[0]
	if a.Bundle.X25519Pub != oldBundleResp.X25519Pub || a.Bundle.MKPassword != oldBundleResp.MKPassword {
		t.Errorf("archived bundle doesn't match the pre-reset one:\narchived: %+v\noriginal: %+v", a.Bundle, oldBundleResp.bundleWire)
	}
	if len(a.APIKeys) != 1 || a.APIKeys[0].ID != created.ID || a.APIKeys[0].MK != keyMK {
		t.Errorf("archived API keys = %+v, want the pre-reset key with its MK intact", a.APIKeys)
	}

	// The old API key is revoked.
	var keys []keyView
	c.mustDo("GET", "/api/keys", nil, &keys, http.StatusOK)
	for _, k := range keys {
		if k.ID == created.ID {
			t.Errorf("revoked key %s still listed as live", k.ID)
		}
	}
}
