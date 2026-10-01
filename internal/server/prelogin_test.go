package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

type preloginParams struct {
	Alg  string `json:"alg"`
	M    int    `json:"m"`
	T    int    `json:"t"`
	P    int    `json:"p"`
	Salt string `json:"salt"`
}

func prelogin(t *testing.T, base, email string) preloginParams {
	t.Helper()
	c := &testClient{t: t, base: base}
	var out preloginParams
	c.mustDo("POST", "/api/auth/prelogin", map[string]string{"email": email}, &out, http.StatusOK)
	return out
}

// TestPreloginUnknownAccountStableFakeSalt covers M3: an unknown address gets
// the default parameters and a salt that doesn't change between calls.
func TestPreloginUnknownAccountStableFakeSalt(t *testing.T) {
	_, ts := testServer(t)
	a := prelogin(t, ts.URL, "nobody@example.com")
	b := prelogin(t, ts.URL, "nobody@example.com")
	if a != b {
		t.Fatalf("fake salt not stable: %+v vs %+v", a, b)
	}
	if a.Alg != "argon2id" || a.M != 65536 || a.T != 3 || a.P != 1 {
		t.Errorf("fake params: %+v", a)
	}
}

// TestPreloginUnverifiedSameShapeAsUnknown covers M3 fully: for the same
// address, a real but unverified account must look exactly like no account
// at all, before and after the (identical, address-keyed) fake salt is
// computed.
func TestPreloginUnverifiedSameShapeAsUnknown(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.SignupDomains = []string{"example.com"} })
	before := prelogin(t, ts.URL, "ada@example.com")

	m := mailer(s)
	signupAndCapture(t, ts.URL, m, "ada@example.com", "pw")

	after := prelogin(t, ts.URL, "ada@example.com")
	if before != after {
		t.Errorf("unverified account distinguishable from unknown: %+v vs %+v", after, before)
	}
}

// TestPreloginVerifiedAccountReturnsStoredKDF covers the normal path: a
// verified account's own kdf, not the fake one.
func TestPreloginVerifiedAccountReturnsStoredKDF(t *testing.T) {
	s, ts := testServer(t)
	seedAccount(t, s, "ada@example.com", "pw", false)
	got := prelogin(t, ts.URL, "ada@example.com")
	fake := prelogin(t, ts.URL, "nobody@example.com")
	if got.Salt == fake.Salt {
		t.Error("verified account returned the fake salt")
	}

	var want e2e.Params
	b, err := s.store.BundleFor(mustUserID(t, s, "ada@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b.KDF, &want); err != nil {
		t.Fatal(err)
	}
	if got.Salt != e2e.B64(want.Salt) {
		t.Errorf("prelogin salt = %q, want the account's own %q", got.Salt, e2e.B64(want.Salt))
	}
}

func mustUserID(t *testing.T, s *Server, email string) string {
	t.Helper()
	u, err := s.store.UserByEmail(email)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}
