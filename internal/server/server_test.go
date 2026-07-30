package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testServer boots a full server on a temp data dir with a bootstrap admin.
func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Config{
		DataDir:       t.TempDir(),
		AdminEmail:    "admin@example.com",
		AdminPassword: "admin-password",
		TokenTTL:      time.Hour,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
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

func login(t *testing.T, base, email, password string) *testClient {
	t.Helper()
	c := &testClient{t: t, base: base}
	var out struct {
		Token string `json:"token"`
	}
	c.mustDo("POST", "/api/auth/login", map[string]string{"email": email, "password": password}, &out, http.StatusOK)
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
	resp := c.do("POST", "/api/auth/login", map[string]string{"email": "admin@example.com", "password": "nope"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}
	// Anonymous /api/me
	resp = c.do("GET", "/api/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous me: %d", resp.StatusCode)
	}
}

func TestFirstLoginClaim(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	var created struct {
		ID string `json:"id"`
	}
	admin.mustDo("POST", "/api/admin/users", map[string]any{"email": "user@example.com", "name": "User"}, &created, http.StatusCreated)

	anon := &testClient{t: t, base: ts.URL}
	// Missing confirmation
	resp := anon.do("POST", "/api/auth/login", map[string]string{"email": "user@example.com", "password": "password123"}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("claim without confirm: %d", resp.StatusCode)
	}
	// Too short
	resp = anon.do("POST", "/api/auth/login", map[string]string{"email": "user@example.com", "password": "short", "confirm": "short"}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short password: %d", resp.StatusCode)
	}
	// Claim
	var out struct {
		Token      string `json:"token"`
		FirstLogin bool   `json:"firstLogin"`
	}
	anon.mustDo("POST", "/api/auth/login", map[string]string{"email": "user@example.com", "password": "password123", "confirm": "password123"}, &out, http.StatusOK)
	if !out.FirstLogin || out.Token == "" {
		t.Fatalf("claim response: %+v", out)
	}
	// Second login uses the chosen password, no confirm needed
	login(t, ts.URL, "user@example.com", "password123")
	// And the old "any password" hole is closed
	resp = anon.do("POST", "/api/auth/login", map[string]string{"email": "user@example.com", "password": "different123"}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password after claim: %d", resp.StatusCode)
	}
}

func TestUserDirectoryAndAdmin(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	admin.mustDo("POST", "/api/admin/users", map[string]any{"email": "u1@example.com", "name": "U1"}, nil, http.StatusCreated)

	// Non-admin can read the directory but not manage users
	var created struct {
		ID string `json:"id"`
	}
	admin.mustDo("POST", "/api/admin/users", map[string]any{"email": "u2@example.com", "name": "U2"}, &created, http.StatusCreated)
	u2 := &testClient{t: t, base: ts.URL}
	var loginOut struct {
		Token string `json:"token"`
	}
	u2.mustDo("POST", "/api/auth/login", map[string]string{"email": "u2@example.com", "password": "password123", "confirm": "password123"}, &loginOut, http.StatusOK)
	u2.token = loginOut.Token

	var users []map[string]any
	u2.mustDo("GET", "/api/users", nil, &users, http.StatusOK)
	if len(users) != 3 {
		t.Errorf("directory size: %d", len(users))
	}
	for _, u := range users {
		if _, has := u["email"]; !has {
			t.Errorf("directory entry missing email: %v", u)
		}
	}
	resp := u2.do("POST", "/api/admin/users", map[string]any{"email": "x@example.com"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin create user: %d", resp.StatusCode)
	}

	// Disable a user; their token dies immediately
	admin.mustDo("PATCH", fmt.Sprintf("/api/admin/users/%s", created.ID), map[string]any{"disabled": true}, nil, http.StatusOK)
	resp = u2.do("GET", "/api/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("disabled user token still valid: %d", resp.StatusCode)
	}
}

func TestAPIKeyAuth(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	var out struct {
		Key struct {
			ID string `json:"id"`
		} `json:"key"`
		Token string `json:"token"`
	}
	admin.mustDo("POST", "/api/admin/keys", map[string]any{"name": "ci"}, &out, http.StatusCreated)
	if out.Token == "" {
		t.Fatal("no token returned")
	}
	keyClient := &testClient{t: t, base: ts.URL, token: out.Token}
	var me struct {
		Email string `json:"email"`
	}
	keyClient.mustDo("GET", "/api/me", nil, &me, http.StatusOK)
	if me.Email != "admin@example.com" {
		t.Errorf("key acts as %q", me.Email)
	}
	// Revoke, then the key stops working
	admin.mustDo("DELETE", "/api/admin/keys/"+out.Key.ID, nil, nil, http.StatusOK)
	resp := keyClient.do("GET", "/api/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked key still valid: %d", resp.StatusCode)
	}
}
