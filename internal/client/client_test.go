package client

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
