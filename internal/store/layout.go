package store

import (
	"os"
	"path/filepath"
)

// Layout resolves paths inside the Cairn data directory:
//
//	data/
//	  cairn.db                                metadata database
//	  secret.key                              JWT signing secret
//	  content/{artifactID}/{contentDir}/...   a pushed version: manifest and blobs/{blobID}, all ciphertext
//	  dbs/{artifactID}/{versionID}/{revision} one encrypted database revision
//	  files/{artifactID}/{versionID}/{address} one encrypted stored file
//	  tmp/                                    upload staging (same volume => atomic rename)
//
// Version databases and file storage live outside the content tree so
// re-uploading a version never touches its data.
type Layout struct {
	Root string
}

func NewLayout(root string) (Layout, error) {
	l := Layout{Root: root}
	for _, dir := range []string{root, l.ContentRoot(), l.DBRoot(), l.FilesRoot(), l.TmpRoot()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Layout{}, err
		}
	}
	return l, nil
}

func (l Layout) MetaDB() string     { return filepath.Join(l.Root, "cairn.db") }
func (l Layout) SecretFile() string { return filepath.Join(l.Root, "secret.key") }

// PreloginSecretFile holds the server secret used to derive the fake salt
// prelogin returns for an address with no verified account (see
// e2e.PreloginSalt). It is persisted the same way as SecretFile so the fake
// salt stays stable across restarts.
func (l Layout) PreloginSecretFile() string { return filepath.Join(l.Root, "prelogin.key") }
func (l Layout) ContentRoot() string        { return filepath.Join(l.Root, "content") }
func (l Layout) DBRoot() string             { return filepath.Join(l.Root, "dbs") }
func (l Layout) TmpRoot() string            { return filepath.Join(l.Root, "tmp") }

func (l Layout) ContentDir(artifactID, contentDir string) string {
	return filepath.Join(l.ContentRoot(), artifactID, contentDir)
}

func (l Layout) ArtifactContentRoot(artifactID string) string {
	return filepath.Join(l.ContentRoot(), artifactID)
}

// VersionDB is the single-file database internal/versiondb still opens, kept
// until that package goes. The server no longer uses it.
func (l Layout) VersionDB(artifactID, versionID string) string {
	return filepath.Join(l.DBRoot(), artifactID, versionID+".db")
}

func (l Layout) VersionDBDir(artifactID, versionID string) string {
	return filepath.Join(l.DBRoot(), artifactID, versionID)
}

func (l Layout) ArtifactDBRoot(artifactID string) string {
	return filepath.Join(l.DBRoot(), artifactID)
}

func (l Layout) FilesRoot() string { return filepath.Join(l.Root, "files") }

func (l Layout) VersionFilesDir(artifactID, versionID string) string {
	return filepath.Join(l.FilesRoot(), artifactID, versionID)
}

func (l Layout) ArtifactFilesRoot(artifactID string) string {
	return filepath.Join(l.FilesRoot(), artifactID)
}
