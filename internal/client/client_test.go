package client

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// authedClient signs up, verifies, and logs in a fresh account, returning a
// client ready to call the artifact, push, db, and files endpoints.
func authedClient(t *testing.T) *Client {
	t.Helper()
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	c, err := New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return keyedFor(t, host, c.APIKey)
}

func TestArtifactLifecycle(t *testing.T) {
	c := authedClient(t)

	a, err := c.CreateArtifact("widget", "a widget")
	if err != nil {
		t.Fatalf("CreateArtifact: %v", err)
	}
	if a.Name != "widget" {
		t.Fatalf("CreateArtifact = %+v", a)
	}

	if err := c.AddResource(a.ID, "claude-session", "sess-1"); err != nil {
		t.Fatalf("AddResource: %v", err)
	}
	byResource, err := c.ResolveArtifact("sess-1")
	if err != nil || byResource.ID != a.ID {
		t.Fatalf("ResolveArtifact(resource) = %+v, %v", byResource, err)
	}
	byName, err := c.ResolveArtifact("widget")
	if err != nil || byName.ID != a.ID {
		t.Fatalf("ResolveArtifact(name) = %+v, %v", byName, err)
	}

	got, err := c.GetArtifact(a.ID)
	if err != nil || got.ID != a.ID {
		t.Fatalf("GetArtifact = %+v, %v", got, err)
	}
	all, err := c.ListArtifacts()
	if err != nil || len(all) != 1 {
		t.Fatalf("ListArtifacts = %+v, %v", all, err)
	}

	if err := c.UpdateArtifact(a.ID, map[string]string{"description": "updated"}); err != nil {
		t.Fatalf("UpdateArtifact: %v", err)
	}
	if got, err := c.GetArtifact(a.ID); err != nil || got.Description != "updated" {
		t.Fatalf("GetArtifact after the update = %+v, %v", got, err)
	}

	if _, err := c.Users(); err != nil {
		t.Fatalf("Users: %v", err)
	}

	if err := c.DeleteArtifact(a.ID); err != nil {
		t.Fatalf("DeleteArtifact: %v", err)
	}
	if _, err := c.GetArtifact(a.ID); err == nil {
		t.Fatal("deleted artifact still found")
	}
}

func TestPush(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "")
	if err != nil {
		t.Fatalf("CreateArtifact: %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>hi</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := c.Push(a.ID, "", dir, "v1", "first")
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	versions, err := c.ListVersions(a.ID)
	if err != nil || len(versions) != 1 || versions[0].ID != v.ID {
		t.Fatalf("ListVersions = %+v, %v", versions, err)
	}

}

func TestResolveArtifactAmbiguousName(t *testing.T) {
	c := authedClient(t)
	if _, err := c.CreateArtifact("dup", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateArtifact("dup", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveArtifact("dup"); err == nil {
		t.Fatal("ambiguous name resolved without error")
	}
}

func TestResolveArtifactNotFound(t *testing.T) {
	c := authedClient(t)
	if _, err := c.ResolveArtifact("nope"); !errors.Is(err, ErrNoArtifact) {
		t.Fatalf("ResolveArtifact(nope) = %v, want ErrNoArtifact", err)
	}
}

// A server from before Google sign-in has no /api/auth/config. Its 404 means
// no Google, so login against it still asks for the password as before; any
// other failure is still an error.
func TestGoogleSignInTreatsAMissingConfigAsOff(t *testing.T) {
	for _, tc := range []struct {
		status  int
		body    string
		want    bool
		wantErr bool
	}{
		{http.StatusNotFound, `404 page not found`, false, false},
		{http.StatusOK, `{"google":true}`, true, false},
		{http.StatusOK, `{"google":false}`, false, false},
		{http.StatusInternalServerError, `{"error":"boom"}`, false, true},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/auth/config" {
				t.Errorf("unexpected request %s", r.URL.Path)
			}
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
		}))
		got, err := New(srv.URL, "").GoogleSignIn()
		srv.Close()
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("status %d: got %v, err %v; want %v, error %v", tc.status, got, err, tc.want, tc.wantErr)
		}
		var apiErr *APIError
		if tc.wantErr && !errors.As(err, &apiErr) {
			t.Errorf("status %d: err %v is not an APIError", tc.status, err)
		}
	}
}

// The proof cairn login receives lasts two minutes. When the server refuses
// it, the error says to run cairn login again, not to "sign in with Google
// first", which the person just did.
func TestLoginWithGoogleExplainsARefusedProof(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/prelogin":
			json.NewEncoder(w).Encode(e2e.Params{Alg: "argon2id", Memory: 65536, Time: 3, Threads: 1, Salt: make([]byte, 16)})
		case "/api/auth/login":
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"error":"sign in with Google first"}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	_, err := New(srv.URL, "").LoginWithGoogle("ada@example.com", "correct horse battery staple", "proof")
	if !errors.Is(err, ErrGoogleSignInExpired) {
		t.Fatalf("err = %v, want ErrGoogleSignInExpired", err)
	}
}
