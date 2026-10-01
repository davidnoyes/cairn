package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

func wrongLogin(c *testClient, email string) *http.Response {
	return c.do("POST", "/api/auth/login", map[string]any{"email": email, "authKey": e2e.B64(testAuthKey("wrong")), "client": "cli"}, nil)
}

// TestLoginRateLimitPerAccount covers the fifth failed sign-in in a window:
// the sixth attempt is rate limited even with the right key.
func TestLoginRateLimitPerAccount(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.Clock = clock.NewFake(time.Now()) })
	seedAccount(t, s, "ada@example.com", "right-pw", false)
	c := &testClient{t: t, base: ts.URL}

	for i := 0; i < 5; i++ {
		resp := wrongLogin(c, "ada@example.com")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: status = %d, want 401", i+1, resp.StatusCode)
		}
	}
	// The 6th attempt is blocked even with the correct key.
	resp := c.do("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("right-pw")), "client": "cli"}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after 5 failures: status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

// TestLoginRateLimitPerIP covers the 20-per-IP limit: failures against
// different (unknown) accounts from the same client still accumulate.
func TestLoginRateLimitPerIP(t *testing.T) {
	_, ts := newTestServer(t, func(c *Config) { c.Clock = clock.NewFake(time.Now()) })
	c := &testClient{t: t, base: ts.URL}
	for i := 0; i < 20; i++ {
		email := fakeEmail(i)
		resp := wrongLogin(c, email)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: status = %d, want 401", i+1, resp.StatusCode)
		}
	}
	resp := wrongLogin(c, fakeEmail(21))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after 20 failures from one IP: status = %d, want 429", resp.StatusCode)
	}
}

func fakeEmail(i int) string {
	return "user" + string(rune('a'+i%26)) + "@example.com"
}

// TestMePasswordSharesSignInRateLimit covers that a wrong current password at
// /api/me/password is a sign-in failure for the rate limits, and that the
// endpoint itself is blocked once the limit is reached, not just login.
func TestMePasswordSharesSignInRateLimit(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.Clock = clock.NewFake(time.Now()) })
	seedAccount(t, s, "ada@example.com", "right-pw", false)
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "ada@example.com", "right-pw")

	wrongChange := func() *http.Response {
		return c.do("PUT", "/api/me/password", map[string]any{
			"authKey": e2e.B64(testAuthKey("wrong")), "newAuthKey": e2e.B64(testAuthKey("new")),
			"kdf": floorKDF(), "mkPassword": e2e.B64(make([]byte, sealedKeyLen)),
		}, nil)
	}
	for i := 0; i < 5; i++ {
		if resp := wrongChange(); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: status = %d, want 401", i+1, resp.StatusCode)
		}
	}
	// The 6th attempt is rate limited even with the right current password.
	resp := c.do("PUT", "/api/me/password", map[string]any{
		"authKey": e2e.B64(testAuthKey("right-pw")), "newAuthKey": e2e.B64(testAuthKey("new")),
		"kdf": floorKDF(), "mkPassword": e2e.B64(make([]byte, sealedKeyLen)),
	}, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after 5 failures: status = %d, want 429", resp.StatusCode)
	}

	// Login itself is now rate limited too, since the limiter bucket is shared.
	loginResp := c.do("POST", "/api/auth/login", map[string]any{"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("right-pw")), "client": "cli"}, nil)
	if loginResp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("login after /api/me/password failures: status = %d, want 429", loginResp.StatusCode)
	}
}

// TestMailRateLimitAnswersAsSucceeded covers the mail limit: a fourth signup
// to the same address in an hour still answers 202, but no fourth mail goes
// out.
func TestMailRateLimitAnswersAsSucceeded(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) {
		c.SignupDomains = []string{"example.com"}
		c.Clock = clock.NewFake(time.Now())
	})
	c := &testClient{t: t, base: ts.URL}
	signupBody := func() {
		c.mustDo("POST", "/api/auth/signup", map[string]any{
			"email": "ada@example.com", "name": "Ada", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
		}, nil, http.StatusAccepted)
	}
	for i := 0; i < 3; i++ {
		signupBody()
	}
	before := len(mailer(s).All())
	signupBody() // 4th: still 202, but rate limited
	after := len(mailer(s).All())
	if after != before {
		t.Errorf("mail sent past the per-address limit: %d messages before the 4th call, %d after", before, after)
	}
}
