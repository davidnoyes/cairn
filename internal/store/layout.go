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
//	  content/{artifactID}/{contentDir}/...   extracted version files
//	  dbs/{artifactID}/{versionID}.db         per-version shared databases
//	  tmp/                                    upload staging (same volume => atomic rename)
//
// Version databases live outside the content tree so re-uploading a version
// never touches its data.
type Layout struct {
	Root string
}

func NewLayout(root string) (Layout, error) {
	l := Layout{Root: root}
	for _, dir := range []string{root, l.ContentRoot(), l.DBRoot(), l.TmpRoot()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Layout{}, err
		}
	}
	return l, nil
}

func (l Layout) MetaDB() string      { return filepath.Join(l.Root, "cairn.db") }
func (l Layout) SecretFile() string  { return filepath.Join(l.Root, "secret.key") }
func (l Layout) ContentRoot() string { return filepath.Join(l.Root, "content") }
func (l Layout) DBRoot() string      { return filepath.Join(l.Root, "dbs") }
func (l Layout) TmpRoot() string     { return filepath.Join(l.Root, "tmp") }

func (l Layout) ContentDir(artifactID, contentDir string) string {
	return filepath.Join(l.ContentRoot(), artifactID, contentDir)
}

func (l Layout) ArtifactContentRoot(artifactID string) string {
	return filepath.Join(l.ContentRoot(), artifactID)
}

func (l Layout) VersionDB(artifactID, versionID string) string {
	return filepath.Join(l.DBRoot(), artifactID, versionID+".db")
}

func (l Layout) ArtifactDBRoot(artifactID string) string {
	return filepath.Join(l.DBRoot(), artifactID)
}
