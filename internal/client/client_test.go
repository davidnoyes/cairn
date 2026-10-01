package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/versiondb"
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
	return bearerFor(t, host, c.APIKey)
}

func TestArtifactLifecycle(t *testing.T) {
	c := authedClient(t)

	a, err := c.CreateArtifact("widget", "a widget", false)
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

	updated, err := c.UpdateArtifact(a.ID, map[string]any{"description": "updated"})
	if err != nil || updated.Description != "updated" {
		t.Fatalf("UpdateArtifact = %+v, %v", updated, err)
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

func TestPushAndFiles(t *testing.T) {
	c := authedClient(t)
	a, err := c.CreateArtifact("site", "", true)
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

	// Shared database: create a table, insert, and read it back.
	if _, err := c.Query(a.ID, v.ID, "CREATE TABLE t (n INTEGER)", nil); err != nil {
		t.Fatalf("Query create: %v", err)
	}
	batchResults, err := c.Batch(a.ID, v.ID, []versiondb.Statement{
		{SQL: "INSERT INTO t (n) VALUES (?)", Params: []any{1}},
		{SQL: "INSERT INTO t (n) VALUES (?)", Params: []any{2}},
	})
	if err != nil || len(batchResults) != 2 {
		t.Fatalf("Batch = %+v, %v", batchResults, err)
	}
	res, err := c.Query(a.ID, v.ID, "SELECT n FROM t ORDER BY n", nil)
	if err != nil {
		t.Fatalf("Query select: %v", err)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("Query select rows = %+v", res.Rows)
	}

	// File storage.
	if _, err := c.UploadFile(a.ID, v.ID, "notes/hello.txt", strings.NewReader("hello file")); err != nil {
		t.Fatalf("UploadFile: %v", err)
	}
	files, err := c.ListFiles(a.ID, v.ID)
	if err != nil || len(files) != 1 || files[0].Path != "notes/hello.txt" {
		t.Fatalf("ListFiles = %+v, %v", files, err)
	}
	body, err := c.DownloadFile(a.ID, v.ID, "notes/hello.txt")
	if err != nil {
		t.Fatalf("DownloadFile: %v", err)
	}
	defer body.Close()
	data := make([]byte, 32)
	n, _ := body.Read(data)
	if string(data[:n]) != "hello file" {
		t.Fatalf("DownloadFile content = %q", data[:n])
	}
	if err := c.DeleteFile(a.ID, v.ID, "notes/hello.txt"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	files, err = c.ListFiles(a.ID, v.ID)
	if err != nil || len(files) != 0 {
		t.Fatalf("ListFiles after delete = %+v, %v", files, err)
	}
}

func TestResolveArtifactAmbiguousName(t *testing.T) {
	c := authedClient(t)
	if _, err := c.CreateArtifact("dup", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateArtifact("dup", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveArtifact("dup"); err == nil {
		t.Fatal("ambiguous name resolved without error")
	}
}

func TestResolveArtifactNotFound(t *testing.T) {
	c := authedClient(t)
	if _, err := c.ResolveArtifact("nope"); err == nil {
		t.Fatal("missing artifact resolved without error")
	}
}
