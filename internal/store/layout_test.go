package store

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLayout exercises the plain path-joining in layout.go, which predates
// this change and had no coverage.
func TestLayout(t *testing.T) {
	root := t.TempDir()
	l, err := NewLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{l.ContentRoot(), l.DBRoot(), l.FilesRoot(), l.TmpRoot()} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Errorf("NewLayout did not create %q: %v", dir, err)
		}
	}
	if l.MetaDB() != filepath.Join(root, "cairn.db") {
		t.Errorf("MetaDB: %q", l.MetaDB())
	}
	if l.SecretFile() != filepath.Join(root, "secret.key") {
		t.Errorf("SecretFile: %q", l.SecretFile())
	}
	if l.PreloginSecretFile() != filepath.Join(root, "prelogin.key") {
		t.Errorf("PreloginSecretFile: %q", l.PreloginSecretFile())
	}
	if l.ContentDir("a1", "c1") != filepath.Join(root, "content", "a1", "c1") {
		t.Errorf("ContentDir: %q", l.ContentDir("a1", "c1"))
	}
	if l.ArtifactContentRoot("a1") != filepath.Join(root, "content", "a1") {
		t.Errorf("ArtifactContentRoot: %q", l.ArtifactContentRoot("a1"))
	}
	if l.VersionDBDir("a1", "v1") != filepath.Join(root, "dbs", "a1", "v1") {
		t.Errorf("VersionDBDir: %q", l.VersionDBDir("a1", "v1"))
	}
	if l.ArtifactDBRoot("a1") != filepath.Join(root, "dbs", "a1") {
		t.Errorf("ArtifactDBRoot: %q", l.ArtifactDBRoot("a1"))
	}
	if l.VersionFilesDir("a1", "v1") != filepath.Join(root, "files", "a1", "v1") {
		t.Errorf("VersionFilesDir: %q", l.VersionFilesDir("a1", "v1"))
	}
	if l.ArtifactFilesRoot("a1") != filepath.Join(root, "files", "a1") {
		t.Errorf("ArtifactFilesRoot: %q", l.ArtifactFilesRoot("a1"))
	}
}
