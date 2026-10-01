package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrationsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cairn.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path) // reopen re-runs migrate; must be a no-op
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestArtifactsAndVersions(t *testing.T) {
	s := testStore(t)
	a, err := s.CreateArtifact("demo", "a demo", false)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := s.CreateVersion(a.ID, "v1", "initial", "c1")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.CreateVersion(a.ID, "v2", "more", "c2")
	if err != nil {
		t.Fatal(err)
	}
	if v1.Seq != 1 || v2.Seq != 2 {
		t.Errorf("seq: %d %d", v1.Seq, v2.Seq)
	}
	latest, err := s.LatestVersion(a.ID)
	if err != nil || latest.ID != v2.ID {
		t.Fatalf("LatestVersion: %v %+v", err, latest)
	}
	prev, err := s.SwapVersionContent(a.ID, v2.ID, "c3", "v2b", "fixed")
	if err != nil {
		t.Fatal(err)
	}
	if prev != "c2" {
		t.Errorf("prev content dir = %q, want c2", prev)
	}
	got, _ := s.VersionByID(a.ID, v2.ID)
	if got.ContentDir != "c3" || got.Name != "v2b" {
		t.Errorf("after swap: %+v", got)
	}
	// Resources
	r, err := s.AddResource(a.ID, "claude-session", "sess-123")
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := s.ListResources(a.ID)
	if len(rs) != 1 || rs[0].ID != r.ID {
		t.Fatalf("resources: %+v", rs)
	}
	// Cascade delete
	if err := s.DeleteArtifact(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VersionByID(a.ID, v1.ID); !errors.Is(err, ErrNotFound) {
		t.Error("versions not cascaded")
	}
	rs, _ = s.ListResources(a.ID)
	if len(rs) != 0 {
		t.Error("resources not cascaded")
	}
}

// testBundle returns a minimal, distinguishable Bundle for tests that don't
// care about its contents.
func testBundle(tag string) Bundle {
	return Bundle{
		KDF:         []byte(`{"alg":"argon2id","salt":"` + tag + `"}`),
		MKPassword:  []byte("mkpw-" + tag),
		MKRecovery:  []byte("mkrec-" + tag),
		X25519Pub:   []byte("x25519pub-" + tag),
		X25519Priv:  []byte("x25519priv-" + tag),
		Ed25519Pub:  []byte("ed25519pub-" + tag),
		Ed25519Priv: []byte("ed25519priv-" + tag),
		EK:          []byte("ek-" + tag),
	}
}

// testAccount creates a verified account for tests that just need a user to
// hang other rows off.
func testAccount(t *testing.T, s *Store, email string) *User {
	t.Helper()
	u, err := s.CreateAccount(email, "Alice", "authhash", testBundle("a"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkVerified(u.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	u, err = s.UserByID(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
