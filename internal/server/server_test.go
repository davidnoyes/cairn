package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/store"
)

// testBundleWire returns a key bundle wire payload with a floor-compliant kdf
// and correctly-sized placeholder keys, for tests that don't care what's
// inside it.
func testBundleWire() bundleWire {
	kdf, _ := json.Marshal(e2e.Params{Alg: "argon2id", Memory: 65536, Time: 3, Threads: 1, Salt: bytes.Repeat([]byte{0x01}, 16)})
	sealed := func(tag byte) string { return e2e.B64(bytes.Repeat([]byte{tag}, sealedKeyLen)) }
	pub := func(tag byte) string { return e2e.B64(bytes.Repeat([]byte{tag}, 32)) }
	// The Ed25519 key must be a real point: validateBundle refuses one with
	// a torsion component, which a repeated byte almost always has.
	_, edPub, _ := e2e.GenerateEd25519(bytes.NewReader(bytes.Repeat([]byte{5}, 32)))
	return bundleWire{
		KDF:         kdf,
		MKPassword:  sealed(1),
		MKRecovery:  sealed(2),
		X25519Pub:   pub(3),
		X25519Priv:  sealed(4),
		Ed25519Pub:  e2e.B64(edPub),
		Ed25519Priv: sealed(6),
		EK:          sealed(7),
	}
}

// testAuthKey deterministically stands in for the client's real Argon2id
// stretch of a test password: the server only ever sees this value.
func testAuthKey(password string) []byte {
	sum := sha256.Sum256([]byte("test-authkey|" + password))
	return sum[:]
}

// seedAccount creates and verifies an account directly through the store, for
// tests that need a working login without exercising sign-up itself.
func seedAccount(t *testing.T, s *Server, email, password string, isAdmin bool) *store.User {
	t.Helper()
	hash, err := auth.HashPassword(string(testAuthKey(password)))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := decodeBundle(testBundleWire())
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.store.CreateAccount(email, "Test User", hash, bundle, isAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.MarkVerified(u.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	u, err = s.store.UserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// testServer boots a full server on a temp data dir with a seeded, verified
// admin account and a recording mailer.
func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, ts := newTestServer(t, nil)
	seedAccount(t, s, "admin@example.com", "admin-password", true)
	return s, ts
}

// newTestServer boots a server with sensible test defaults; cfg may mutate
// the Config before it's used, for tests that need a specific public URL,
// signup domains, or a fake clock. It does not seed any account.
func newTestServer(t *testing.T, cfg func(*Config)) (*Server, *httptest.Server) {
	t.Helper()
	c := Config{
		DataDir:    t.TempDir(),
		AdminEmail: "admin@example.com",
		TokenTTL:   time.Hour,
		Mail:       &mail.Capture{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if cfg != nil {
		cfg(&c)
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ts.Close()
		s.dbs.Close()
		s.store.Close()
	})
	return s, ts
}

// mailer returns the recording mailer newTestServer/testServer installed.
func mailer(s *Server) *mail.Capture {
	return s.mail.(*mail.Capture)
}

type testClient struct {
	t     *testing.T
	base  string
	token string
}

func (c *testClient) do(method, path string, body any, out any) *http.Response {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			c.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp
}

func (c *testClient) mustDo(method, path string, body any, out any, wantStatus int) {
	c.t.Helper()
	resp := c.do(method, path, body, out)
	if resp.StatusCode != wantStatus {
		c.t.Fatalf("%s %s: status %d, want %d", method, path, resp.StatusCode, wantStatus)
	}
}

// login signs in a seeded account by (email, password), as seedAccount
// created it, and returns a client carrying the issued CLI token.
func login(t *testing.T, base, email, password string) *testClient {
	t.Helper()
	c := &testClient{t: t, base: base}
	var out struct {
		Token string `json:"token"`
	}
	c.mustDo("POST", "/api/auth/login", map[string]string{
		"email": email, "authKey": e2e.B64(testAuthKey(password)), "client": "cli",
	}, &out, http.StatusOK)
	if out.Token == "" {
		t.Fatalf("login(%s): no token in response", email)
	}
	c.token = out.Token
	return c
}

func TestBootstrapAndLogin(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	var me struct {
		Email   string `json:"email"`
		IsAdmin bool   `json:"isAdmin"`
	}
	admin.mustDo("GET", "/api/me", nil, &me, http.StatusOK)
	if me.Email != "admin@example.com" || !me.IsAdmin {
		t.Errorf("me: %+v", me)
	}
	// Wrong password
	c := &testClient{t: t, base: ts.URL}
	resp := c.do("POST", "/api/auth/login", map[string]string{"email": "admin@example.com", "authKey": e2e.B64(testAuthKey("nope")), "client": "cli"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}
	// Anonymous /api/me
	resp = c.do("GET", "/api/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous me: %d", resp.StatusCode)
	}
}

func TestNewRequiresMail(t *testing.T) {
	if _, err := New(Config{DataDir: t.TempDir(), AdminEmail: "admin@example.com", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err == nil {
		t.Fatal("server started with no mail sender")
	}
}
