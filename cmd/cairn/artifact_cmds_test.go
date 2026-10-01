package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if err := runArtifact([]string{"create"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("create with no name: %v, want the usage error", err)
	}
	if err := runArtifact([]string{"create", "a", "--name", "b"}); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Errorf("create with two different names: %v, want the disagreement error", err)
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
	if err := runPush([]string{dir, "--artifact", "site"}); err == nil || !strings.Contains(err.Error(), "use --create") {
		t.Fatalf("push to a missing artifact without --create: %v, want the --create hint", err)
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

// runQuiet runs a command with stdout captured and returns what it printed.
func runQuiet(t *testing.T, run func([]string) error, args ...string) (string, error) {
	t.Helper()
	done := captureStdout(t)
	err := run(args)
	return done(), err
}

// siteDir is a directory holding a pushable index.html.
func siteDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>hi</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestArtifactCommandsNeedALogin(t *testing.T) {
	t.Setenv("CAIRN_HOST", "")
	t.Setenv("CAIRN_API_KEY", "")
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	dir := siteDir(t)
	for _, args := range [][]string{{"create", "x"}, {"update", "x", "--name", "y"}} {
		if err := runArtifact(args); err == nil || !strings.Contains(err.Error(), "not logged in") {
			t.Errorf("artifact %v: %v, want the not-logged-in error", args, err)
		}
	}
	if err := runPush([]string{dir, "--artifact", "x"}); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("push: %v, want the not-logged-in error", err)
	}
}

func TestArtifactCreateResourceAndText(t *testing.T) {
	loggedIn(t)
	if _, err := runQuiet(t, runArtifact, "create", "badref", "--resource", "nopair"); err == nil || !strings.Contains(err.Error(), "type=value") {
		t.Errorf("--resource without '=': %v, want the type=value error", err)
	}
	out, err := runQuiet(t, runArtifact, "create", "plain")
	if err != nil || !strings.Contains(out, "created artifact plain (") {
		t.Errorf("text output = %q, %v", out, err)
	}
}

func TestArtifactUpdateRefusalsAndText(t *testing.T) {
	loggedIn(t)
	a := runJSON[store.Artifact](t, runArtifact, "create", "draft", "--json")
	if err := runArtifact([]string{"update"}); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("update with no target: %v, want the usage error", err)
	}
	if err := runArtifact([]string{"update", "missing", "--name", "x"}); err == nil || !strings.Contains(err.Error(), `no artifact with id or name "missing"`) {
		t.Errorf("update of a missing artifact: %v", err)
	}
	out, err := runQuiet(t, runArtifact, "update", a.ID, "--description", "d")
	if err != nil || out != "updated artifact "+a.ID+"\n" {
		t.Errorf("text output = %q, %v", out, err)
	}
}

func TestPushRefusals(t *testing.T) {
	loggedIn(t)
	dir := siteDir(t)
	empty := t.TempDir()
	missing := filepath.Join(empty, "nope")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no artifact", []string{dir}, "usage:"},
		{"no dir", []string{"--artifact", "x"}, "usage:"},
		{"not a directory", []string{missing, "--artifact", "x"}, "is not a directory"},
		{"no index", []string{empty, "--artifact", "x"}, "does not contain an index.html"},
	} {
		if err := runPush(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestPushOverwrite(t *testing.T) {
	loggedIn(t)
	dir := siteDir(t)
	type pushed struct {
		Artifact store.Artifact `json:"artifact"`
		Version  store.Version  `json:"version"`
	}
	empty := runJSON[store.Artifact](t, runArtifact, "create", "site", "--json")

	// Nothing to overwrite yet.
	if err := runPush([]string{dir, "--artifact", "site", "--overwrite", "latest"}); err == nil || !strings.Contains(err.Error(), "no versions yet") {
		t.Errorf("overwrite latest of an empty artifact: %v", err)
	}
	first := runJSON[pushed](t, runPush, dir, "--artifact", "site", "--json")

	// latest replaces the newest version in place; its seq does not move.
	again := runJSON[pushed](t, runPush, dir, "--artifact", "site", "--overwrite", "latest", "--json")
	if again.Artifact.ID != empty.ID || again.Version.ID != first.Version.ID || again.Version.Seq != 1 {
		t.Errorf("overwrite latest = %+v, want version %s at seq 1", again, first.Version.ID)
	}
	// An id the artifact does not have is refused by the server.
	if err := runPush([]string{dir, "--artifact", "site", "--overwrite", uuid.NewString()}); err == nil {
		t.Error("overwrite of an unknown version succeeded")
	}

	// The text form names the version and where to see it.
	out, err := runQuiet(t, runPush, dir, "--artifact", "site")
	if err != nil || !strings.Contains(out, "pushed "+dir+" as version #2") || !strings.Contains(out, "full screen:") {
		t.Errorf("text output = %q, %v", out, err)
	}
}
