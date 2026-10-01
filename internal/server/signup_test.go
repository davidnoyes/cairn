package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
)

// signupAndCapture signs up email through the HTTP API and returns the
// verification link mailed to it.
func signupAndCapture(t *testing.T, ts string, m *mail.Capture, email, password string) string {
	t.Helper()
	c := &testClient{t: t, base: ts}
	c.mustDo("POST", "/api/auth/signup", map[string]any{
		"email": email, "name": "Test User", "authKey": e2e.B64(testAuthKey(password)), "bundle": testBundleWire(),
	}, nil, http.StatusAccepted)
	msg, ok := m.Last(email)
	if !ok {
		t.Fatalf("no mail sent to %s", email)
	}
	return msg.Body
}

// extractFragmentToken pulls the b64 token out of a link of the form
// ".../verify#token=<b64>" or ".../reset#token=<b64>".
func extractFragmentToken(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, "#token=")
	if i < 0 {
		t.Fatalf("no #token= fragment in mail body: %q", body)
	}
	rest := body[i+len("#token="):]
	end := strings.IndexAny(rest, " \n\t")
	if end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func TestSignupVerifyLogin(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.SignupDomains = []string{"example.com"} })
	body := signupAndCapture(t, ts.URL, mailer(s), "ada@example.com", "pw")

	// Not verified yet: login is refused even with the right key.
	c := &testClient{t: t, base: ts.URL}
	resp := c.do("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("pw")), "client": "cli"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login before verify: %d, want 403", resp.StatusCode)
	}

	token := extractFragmentToken(t, body)
	c.mustDo("POST", "/api/auth/verify", map[string]string{"token": token}, nil, http.StatusOK)

	// A second use of the same link fails.
	resp = c.do("POST", "/api/auth/verify", map[string]string{"token": token}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reused verify token: %d, want 400", resp.StatusCode)
	}

	var out struct {
		Token string `json:"token"`
		User  struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	c.mustDo("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("pw")), "client": "cli"}, &out, http.StatusOK)
	if out.Token == "" || out.User.Email != "ada@example.com" {
		t.Fatalf("login after verify: %+v", out)
	}
}

func TestSignupDisallowedDomainRefused(t *testing.T) {
	_, ts := newTestServer(t, func(c *Config) { c.SignupDomains = []string{"example.com"} })
	c := &testClient{t: t, base: ts.URL}
	resp := c.do("POST", "/api/auth/signup", map[string]any{
		"email": "someone@other.com", "name": "X", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestSignupNoDomainsOnlyAdminEmail covers "without one [--signup-domain],
// only --admin-email can sign up".
func TestSignupNoDomainsOnlyAdminEmail(t *testing.T) {
	_, ts := newTestServer(t, nil) // no SignupDomains at all
	c := &testClient{t: t, base: ts.URL}

	resp := c.do("POST", "/api/auth/signup", map[string]any{
		"email": "anyone@example.com", "name": "X", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin email: status = %d, want 403", resp.StatusCode)
	}

	resp = c.do("POST", "/api/auth/signup", map[string]any{
		"email": "admin@example.com", "name": "Admin", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
	}, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("admin email: status = %d, want 202", resp.StatusCode)
	}
}

// TestSignupVerifiedAccountUnchanged covers the "verified account" branch:
// a repeat sign-up changes nothing and mails the owner instead.
func TestSignupVerifiedAccountUnchanged(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.SignupDomains = []string{"example.com"} })
	u := seedAccount(t, s, "ada@example.com", "original-pw", false)
	c := &testClient{t: t, base: ts.URL}

	c.mustDo("POST", "/api/auth/signup", map[string]any{
		"email": "ada@example.com", "name": "Someone Else", "authKey": e2e.B64(testAuthKey("new-pw")), "bundle": testBundleWire(),
	}, nil, http.StatusAccepted)

	// The account is untouched: the original password still works…
	var out struct {
		User struct{ ID string } `json:"user"`
	}
	c.mustDo("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("original-pw")), "client": "cli"}, &out, http.StatusOK)
	if out.User.ID != u.ID {
		t.Errorf("account replaced: got id %q, want %q", out.User.ID, u.ID)
	}
	// …and the owner was mailed about the attempt.
	if _, ok := mailer(s).Last("ada@example.com"); !ok {
		t.Error("owner was not mailed about the signup attempt")
	}
}

// TestSignupUnverifiedReplaced covers the "unverified account" branch: a
// second sign-up before verification replaces it and mails a new link.
func TestSignupUnverifiedReplaced(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.SignupDomains = []string{"example.com"} })
	m := mailer(s)
	signupAndCapture(t, ts.URL, m, "ada@example.com", "first-pw")
	body2 := signupAndCapture(t, ts.URL, m, "ada@example.com", "second-pw")

	c := &testClient{t: t, base: ts.URL}
	token := extractFragmentToken(t, body2)
	c.mustDo("POST", "/api/auth/verify", map[string]string{"token": token}, nil, http.StatusOK)

	// Only the second password works.
	resp := c.do("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("first-pw")), "client": "cli"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("first password still works: %d", resp.StatusCode)
	}
	c.mustDo("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("second-pw")), "client": "cli"}, nil, http.StatusOK)
}
