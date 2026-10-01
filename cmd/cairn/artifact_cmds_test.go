package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

// loggedIn signs up and logs in a fresh account through runLogin, with the
// CLI state in a temp config, and returns a client holding its saved key.
func loggedIn(t *testing.T) *client.Client {
	t.Helper()
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	t.Setenv("CAIRN_HOST", "")
	t.Setenv("CAIRN_API_KEY", "")
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	withStdin(t, password+"\n")
	if err := runLogin([]string{"--host", host, "--email", email, "--password-stdin"}); err != nil {
		t.Fatalf("runLogin: %v", err)
	}
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// runJSON runs a command with --json output and decodes what it prints.
func runJSON[T any](t *testing.T, run func([]string) error, args ...string) T {
	t.Helper()
	done := captureStdout(t)
	err := run(args)
	out := done()
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	var v T
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v printed %q: %v", args, out, err)
	}
	return v
}

// checkOwnedChain asserts that id has a one-record membership chain that the
// caller signed.
func checkOwnedChain(t *testing.T, c *client.Client, id string) {
	t.Helper()
	k, err := c.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.Membership(id)
	if err != nil {
		t.Fatalf("Membership: %v", err)
	}
	if len(m.Records) != 1 || m.Records[0].Signer != k.UserID || !m.Records[0].Verify(k.Ed25519Pub, "membership") {
		t.Errorf("membership of %s = %+v", id, m.Records)
	}
	keys, err := c.Keys(id)
	if err != nil || len(keys.Estate) != 1 {
		t.Errorf("keys of %s = %+v, %v", id, keys, err)
	}
}

func TestApiClientHoldsTheFullKey(t *testing.T) {
	c := loggedIn(t)
	if c.Key == nil || len(c.Key.KeySecret) == 0 {
		t.Fatal("apiClient dropped the keySecret, so it cannot unlock")
	}
	if _, err := c.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

func TestArtifactCreateCommand(t *testing.T) {
	c := loggedIn(t)

	a := runJSON[store.Artifact](t, runArtifact, "create", "notes", "--description", "my notes", "--json")
	if u, err := uuid.Parse(a.ID); err != nil || u.Version() != 4 {
		t.Errorf("id %q is not a random UUID", a.ID)
	}
	if a.Name != "notes" || a.Description != "my notes" || a.Public {
		t.Errorf("created %+v", a)
	}
	checkOwnedChain(t, c, a.ID)

	// --name still names it, for scripts written before the positional form.
	b := runJSON[store.Artifact](t, runArtifact, "create", "--name", "other", "--json")
	if b.Name != "other" {
		t.Errorf("--name created %+v", b)
	}

	// --resource attaches a reference at creation.
	r := runJSON[store.Artifact](t, runArtifact, "create", "with-ref", "--resource", "claude-session=s-1", "--json")
	got, err := c.ResolveArtifact("s-1")
	if err != nil || got.ID != r.ID {
		t.Errorf("resource lookup = %+v, %v", got, err)
	}
}

func TestArtifactCreateNeedsAName(t *testing.T) {
	loggedIn(t)
	if err := runArtifact([]string{"create"}); err == nil {
		t.Error("create with no name succeeded")
	}
	if err := runArtifact([]string{"create", "a", "--name", "b"}); err == nil {
		t.Error("create with two different names succeeded")
	}
}

func TestArtifactUpdateRenames(t *testing.T) {
	c := loggedIn(t)
	a := runJSON[store.Artifact](t, runArtifact, "create", "draft", "--json")
	u := runJSON[store.Artifact](t, runArtifact, "update", a.ID, "--name", "final", "--description", "done", "--json")
	if u.ID != a.ID || u.Name != "final" || u.Description != "done" {
		t.Errorf("update = %+v", u)
	}
	if got, err := c.GetArtifact(a.ID); err != nil || got.Name != "final" {
		t.Errorf("after update: %+v, %v", got, err)
	}
}

func TestPushCreatesThroughTheSignedPath(t *testing.T) {
	c := loggedIn(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>hi</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without --create a missing artifact is an error.
	if err := runPush([]string{dir, "--artifact", "site"}); err == nil {
		t.Fatal("push to a missing artifact without --create succeeded")
	}

	out := runJSON[struct {
		Artifact store.Artifact `json:"artifact"`
		Version  store.Version  `json:"version"`
	}](t, runPush, dir, "--artifact", "site", "--create", "--name", "v1", "--json")
	if out.Artifact.Name != "site" || out.Version.Seq != 1 {
		t.Fatalf("push = %+v", out)
	}
	checkOwnedChain(t, c, out.Artifact.ID)

	// A second push lands on the same artifact.
	again := runJSON[struct {
		Artifact store.Artifact `json:"artifact"`
		Version  store.Version  `json:"version"`
	}](t, runPush, dir, "--artifact", "site", "--create", "--json")
	if again.Artifact.ID != out.Artifact.ID || again.Version.Seq != 2 {
		t.Errorf("second push = %+v", again)
	}
}
