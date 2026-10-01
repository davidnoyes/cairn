package client

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/server"
)

// newTestServer boots a real server on a temp data dir with a recording
// mailer, allowing sign-up from "example.com".
func newTestServer(t *testing.T) (host string, m *mail.Capture) {
	t.Helper()
	m = &mail.Capture{}
	s, err := server.New(server.Config{
		DataDir:       t.TempDir(),
		SignupDomains: []string{"example.com"},
		AdminEmail:    "admin@example.com",
		Mail:          m,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts.URL, m
}

// verifyLink pulls the "<path>#token=..." link out of the last mail sent to
// email. The test server has no PublicURL configured, so the link has no
// host; tests that need one (LinkHost) prepend it themselves.
func verifyLink(t *testing.T, m *mail.Capture, email string) string {
	t.Helper()
	msg, ok := m.Last(email)
	if !ok {
		t.Fatalf("no mail sent to %s", email)
	}
	i := strings.Index(msg.Body, "#token=")
	if i < 0 {
		t.Fatalf("no link in mail body: %q", msg.Body)
	}
	rest := msg.Body[strings.LastIndexAny(msg.Body[:i], " \n\t")+1:]
	end := strings.IndexAny(rest, " \n\t")
	if end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func signupVerify(t *testing.T, host string, m *mail.Capture, email, password string) {
	t.Helper()
	if _, err := New(host, "").Signup(email, "Ada", password); err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if err := New(host, "").ConfirmEmail(verifyLink(t, m, email)); err != nil {
		t.Fatalf("ConfirmEmail: %v", err)
	}
}

// bearerFor builds a client authenticated with full's public two parts.
func bearerFor(t *testing.T, host, full string) *Client {
	t.Helper()
	key, err := e2e.ParseAPIKey(full)
	if err != nil {
		t.Fatal(err)
	}
	return New(host, apiKeyBearer(key.KeyID, key.AuthSecret))
}

func TestSignupVerifyLogin(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)

	c := New(host, "")
	out, err := c.Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if out.Email != email || out.APIKey == "" {
		t.Fatalf("Login result = %+v", out)
	}
	if c.Token == "" {
		t.Fatal("Login did not leave the client authenticated")
	}
	me, err := c.Me()
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if me.Email != email {
		t.Errorf("Me().Email = %q", me.Email)
	}
}

func TestLoginBeforeVerifyRefused(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	if _, err := New(host, "").Signup(email, "Ada", password); err != nil {
		t.Fatalf("Signup: %v", err)
	}
	_ = m
	if _, err := New(host, "").Login(email, password); err == nil {
		t.Fatal("login before verification succeeded")
	}
}

// TestLoginWrongPassword drives the raw HTTP request the way Login's second
// step does, so it proves the server itself refuses a wrong authKey (401)
// rather than relying on the client failing to decrypt MK with the wrong kek
// — which would pass even if the server's password check were disabled.
func TestLoginWrongPassword(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)

	wrongAuthKey := make([]byte, 32) // all-zero: never matches the real stretched key
	err := New(host, "").doJSON("POST", "/api/auth/login", map[string]any{
		"email": email, "authKey": e2e.B64(wrongAuthKey), "client": "cli",
	}, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Fatalf("login with the wrong authKey = %v, want a 401 APIError", err)
	}
}

// TestAPIKeyMKMatchesPasswordMK covers the device key's own sealed copy of
// MK: opening it with APIKeyKEK must yield the same MK that opening
// mkPassword with kek yields.
func TestAPIKeyMKMatchesPasswordMK(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)

	out, err := New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	full, err := e2e.ParseAPIKey(out.APIKey)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}

	authed := bearerFor(t, host, out.APIKey)
	bundle, err := authed.MeBundle()
	if err != nil {
		t.Fatalf("MeBundle: %v", err)
	}
	if bundle.APIKeyID != full.KeyID || len(bundle.APIKeyMK) == 0 {
		t.Fatalf("MeBundle apiKey = %+v", bundle)
	}
	mkViaKey, err := e2e.Open(e2e.APIKeyKEK(full.KeySecret, full.KeyID), [][]byte{[]byte("mk"), []byte(full.KeyID)}, bundle.APIKeyMK)
	if err != nil {
		t.Fatalf("opening MK via the API key: %v", err)
	}

	// Independently derive MK the way the password path does, straight off
	// the wire, to check both paths agree.
	var params e2e.Params
	if err := New(host, "").doJSON("POST", "/api/auth/prelogin", map[string]string{"email": email}, &params); err != nil {
		t.Fatal(err)
	}
	stretched, err := e2e.Stretch([]byte(password), email, params)
	if err != nil {
		t.Fatal(err)
	}
	authKey, kek := e2e.PasswordKeys(stretched)
	var loginRaw struct {
		Bundle bundleWire `json:"bundle"`
	}
	if err := New(host, "").doJSON("POST", "/api/auth/login", map[string]any{
		"email": email, "authKey": e2e.B64(authKey), "client": "cli",
	}, &loginRaw); err != nil {
		t.Fatal(err)
	}
	mkPasswordSealed, err := e2e.UnB64(loginRaw.Bundle.MKPassword)
	if err != nil {
		t.Fatal(err)
	}
	mkViaPassword, err := e2e.Open(kek, [][]byte{[]byte("mk")}, mkPasswordSealed)
	if err != nil {
		t.Fatalf("opening MK via the password: %v", err)
	}
	if string(mkViaKey) != string(mkViaPassword) {
		t.Error("MK via the API key disagrees with MK via the password")
	}
}

func TestLogoutRevokesTheKey(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)

	c := New(host, "")
	out, err := c.Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	full, err := e2e.ParseAPIKey(out.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(full.KeyID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := c.Me(); err == nil {
		t.Fatal("the revoked key still authenticates")
	}
}

func TestKeysListAndRevoke(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)

	c := New(host, "")
	if _, err := c.Login(email, password); err != nil {
		t.Fatalf("Login: %v", err)
	}
	keys, err := c.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || !keys[0].Device {
		t.Fatalf("ListKeys = %+v, want one device key", keys)
	}
	if err := c.RevokeKey(keys[0].ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := c.Me(); err == nil {
		t.Fatal("the revoked key still authenticates")
	}
}

func TestResetNewChangesPublicKeys(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)

	before, err := New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	beforeBundle, err := bearerFor(t, host, before.APIKey).MeBundle()
	if err != nil {
		t.Fatal(err)
	}

	if err := New(host, "").Forgot(email); err != nil {
		t.Fatalf("Forgot: %v", err)
	}
	link := verifyLink(t, m, email)

	newRecovery, err := New(host, "").ResetNew(link, "a brand new password")
	if err != nil {
		t.Fatalf("ResetNew: %v", err)
	}
	if newRecovery == "" {
		t.Error("ResetNew returned no recovery code")
	}

	if _, err := New(host, "").Login(email, password); err == nil {
		t.Error("old password still works after a new-mode reset")
	}
	after, err := New(host, "").Login(email, "a brand new password")
	if err != nil {
		t.Fatalf("Login with the new password: %v", err)
	}
	afterBundle, err := bearerFor(t, host, after.APIKey).MeBundle()
	if err != nil {
		t.Fatal(err)
	}
	if string(afterBundle.X25519Pub) == string(beforeBundle.X25519Pub) {
		t.Error("a new-mode reset kept the old public keys")
	}
}

// TestResetRecoveryKeepsPublicKeys drives recovery-mode reset the way a new
// device does: it holds only the emailed link and the recovery code, with no
// earlier login to borrow the account id or signing key from.
func TestResetRecoveryKeepsPublicKeys(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"

	recoveryDisplay, err := New(host, "").Signup(email, "Ada", password)
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if err := New(host, "").ConfirmEmail(verifyLink(t, m, email)); err != nil {
		t.Fatalf("ConfirmEmail: %v", err)
	}
	before, err := New(host, "").Login(email, password)
	if err != nil {
		t.Fatal(err)
	}
	beforeBundle, err := bearerFor(t, host, before.APIKey).MeBundle()
	if err != nil {
		t.Fatal(err)
	}

	if err := New(host, "").Forgot(email); err != nil {
		t.Fatalf("Forgot: %v", err)
	}
	link := verifyLink(t, m, email)

	if err := New(host, "").ResetRecovery(link, recoveryDisplay, "a brand new password"); err != nil {
		t.Fatalf("ResetRecovery: %v", err)
	}

	if _, err := New(host, "").Login(email, password); err == nil {
		t.Error("old password still works after a recovery reset")
	}
	out, err := New(host, "").Login(email, "a brand new password")
	if err != nil {
		t.Fatalf("Login with the new password: %v", err)
	}
	afterBundle, err := bearerFor(t, host, out.APIKey).MeBundle()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterBundle.X25519Pub, beforeBundle.X25519Pub) || !bytes.Equal(afterBundle.Ed25519Pub, beforeBundle.Ed25519Pub) {
		t.Error("a recovery reset changed the public keys")
	}
}

func TestResetRecoveryWrongCodeRefused(t *testing.T) {
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	if err := New(host, "").Forgot(email); err != nil {
		t.Fatal(err)
	}
	link := verifyLink(t, m, email)
	err := New(host, "").ResetRecovery(link, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", "a brand new password")
	if err == nil {
		t.Fatal("a wrong recovery code was accepted")
	}
}

// unreachableHost refuses every connection. A network error also satisfies
// err != nil, so tests against it must assert the specific password error
// (errors.Is) to prove the check ran before any network call.
const unreachableHost = "http://127.0.0.1:1"

func TestSignupRejectsEmptyPassword(t *testing.T) {
	if _, err := New(unreachableHost, "").Signup("ada@example.com", "Ada", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Signup with an empty password: err = %v, want ErrEmptyPassword", err)
	}
}

func TestSignupRejectsWeakPassword(t *testing.T) {
	if _, err := New(unreachableHost, "").Signup("ada@example.com", "Ada", "password1"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Signup with a weak password: err = %v, want ErrWeakPassword", err)
	}
}

func TestResetRecoveryRejectsEmptyPassword(t *testing.T) {
	if err := New(unreachableHost, "").ResetRecovery("irrelevant", "AAAA", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("ResetRecovery with an empty password: err = %v, want ErrEmptyPassword", err)
	}
}

func TestResetRecoveryRejectsWeakPassword(t *testing.T) {
	if err := New(unreachableHost, "").ResetRecovery("irrelevant", "AAAA", "password1"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("ResetRecovery with a weak password: err = %v, want ErrWeakPassword", err)
	}
}

func TestResetNewRejectsEmptyPassword(t *testing.T) {
	if _, err := New(unreachableHost, "").ResetNew("irrelevant", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("ResetNew with an empty password: err = %v, want ErrEmptyPassword", err)
	}
}

func TestResetNewRejectsWeakPassword(t *testing.T) {
	if _, err := New(unreachableHost, "").ResetNew("irrelevant", "password1"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("ResetNew with a weak password: err = %v, want ErrWeakPassword", err)
	}
}

func TestLoginRejectsEmptyPassword(t *testing.T) {
	if _, err := New(unreachableHost, "").Login("ada@example.com", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Login with an empty password: err = %v, want ErrEmptyPassword", err)
	}
}

func TestForgotUnknownAddressStillSucceeds(t *testing.T) {
	host, _ := newTestServer(t)
	if err := New(host, "").Forgot("nobody@example.com"); err != nil {
		t.Fatalf("Forgot: %v", err)
	}
}

func TestLinkHost(t *testing.T) {
	cases := []struct {
		link    string
		want    string
		wantErr bool
	}{
		{"http://127.0.0.1:8797/verify#token=abc", "http://127.0.0.1:8797", false},
		{"https://cairn.example.com/reset#token=abc", "https://cairn.example.com", false},
		{"not a link", "", true},
	}
	for _, tc := range cases {
		got, err := LinkHost(tc.link)
		if (err != nil) != tc.wantErr {
			t.Errorf("LinkHost(%q) error = %v, wantErr %v", tc.link, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("LinkHost(%q) = %q, want %q", tc.link, got, tc.want)
		}
	}
}

// TestResetNewWeighsTheAccountEmail sets the new password to the account's own
// email. It scores 3 or more on its own, so only the check reset makes once
// reset/begin has returned the email can refuse it.
func TestResetNewWeighsTheAccountEmail(t *testing.T) {
	host, m := newTestServer(t)
	email := "qzvx.kelmorth@example.com"
	if err := CheckNewPassword(email); err != nil {
		t.Fatalf("precondition: the email alone should pass, got %v", err)
	}
	signupVerify(t, host, m, email, "correct horse battery staple")
	if err := New(host, "").Forgot(email); err != nil {
		t.Fatal(err)
	}
	if _, err := New(host, "").ResetNew(verifyLink(t, m, email), email); err == nil {
		t.Fatal("ResetNew accepted the account's email as its new password")
	}
}

func TestResetRecoveryWeighsTheAccountEmail(t *testing.T) {
	host, m := newTestServer(t)
	email := "qzvx.kelmorth@example.com"
	recovery, err := New(host, "").Signup(email, "Q", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := New(host, "").ConfirmEmail(verifyLink(t, m, email)); err != nil {
		t.Fatal(err)
	}
	if err := New(host, "").Forgot(email); err != nil {
		t.Fatal(err)
	}
	if err := New(host, "").ResetRecovery(verifyLink(t, m, email), recovery, email); err == nil {
		t.Fatal("ResetRecovery accepted the account's email as its new password")
	}
}
