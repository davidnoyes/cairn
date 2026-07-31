package store

import (
	"errors"
	"path/filepath"
	"testing"
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

func TestUsers(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser("a@b.c", "Alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == "" || u.TokenVersion != 1 {
		t.Fatalf("unexpected user: %+v", u)
	}
	// Case-insensitive unique email
	if _, err := s.CreateUser("A@B.C", "Dup", false); err == nil {
		t.Error("duplicate email accepted")
	}
	got, err := s.UserByEmail("A@b.C")
	if err != nil || got.ID != u.ID {
		t.Fatalf("UserByEmail: %v %+v", err, got)
	}
	if got.PasswordHash != "" {
		t.Error("new user should be unclaimed")
	}
	if err := s.SetPassword(u.ID, "hash1", false); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(u.ID)
	if got.PasswordHash != "hash1" || got.TokenVersion != 1 {
		t.Errorf("SetPassword without bump: %+v", got)
	}
	if err := s.SetPassword(u.ID, "hash2", true); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(u.ID)
	if got.TokenVersion != 2 {
		t.Errorf("token_version not bumped: %+v", got)
	}
	if err := s.ClearPassword(u.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(u.ID)
	if got.PasswordHash != "" || got.TokenVersion != 3 {
		t.Errorf("ClearPassword: %+v", got)
	}
	if err := s.SetUserDisabled(u.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(u.ID)
	if !got.Disabled || got.TokenVersion != 4 {
		t.Errorf("SetUserDisabled: %+v", got)
	}
	if err := s.DeleteUser("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
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

func TestAPIKeys(t *testing.T) {
	s := testStore(t)
	u, _ := s.CreateUser("a@b.c", "Alice", true)
	k, err := s.CreateAPIKey("kid1", u.ID, "ci", "hash")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.APIKeyByID(k.ID)
	if err != nil || got.RevokedAt != "" {
		t.Fatalf("APIKeyByID: %v %+v", err, got)
	}
	if err := s.RevokeAPIKey(k.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.APIKeyByID(k.ID)
	if got.RevokedAt == "" {
		t.Error("not revoked")
	}
	// Revoking twice is a no-op error
	if err := s.RevokeAPIKey(k.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("double revoke: %v", err)
	}
}
