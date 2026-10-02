package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// A version keeps the ID and manifest hash it was pushed under, a re-upload
// replaces the hash, and an ID any version uses, on any artifact, is taken.
func TestVersionIDAndManifestHash(t *testing.T) {
	s := testStore(t)
	a, err := s.CreateArtifact("a", "", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateArtifact("b", "", false)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	v, err := s.CreateVersion(a.ID, id, "v1", "", "c1", "", "aa", 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != id || v.ManifestHash != "aa" {
		t.Errorf("created %q with hash %q, want %q and aa", v.ID, v.ManifestHash, id)
	}
	if _, err := s.CreateVersion(a.ID, id, "again", "", "c2", "", "bb", 0); !errors.Is(err, ErrExists) {
		t.Errorf("reusing an ID: %v, want ErrExists", err)
	}
	if _, err := s.CreateVersion(b.ID, id, "elsewhere", "", "c3", "", "bb", 0); !errors.Is(err, ErrExists) {
		t.Errorf("reusing an ID on another artifact: %v, want ErrExists", err)
	}
	if _, err := s.SwapVersionContent(a.ID, id, "c4", "v1", "", "", "cc", 0); err != nil {
		t.Fatal(err)
	}
	got, err := s.VersionByID(a.ID, id)
	if err != nil || got.ManifestHash != "cc" {
		t.Errorf("after a swap: %+v, %v; want manifest hash cc", got, err)
	}
}

// A version is read through its own artifact only: its ID under another
// artifact is not found.
func TestVersionByIDIsScopedToTheArtifact(t *testing.T) {
	s := testStore(t)
	a, err := s.CreateArtifact("a", "", false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateArtifact("b", "", false)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	if _, err := s.CreateVersion(a.ID, id, "v1", "", "c1", "", "aa", 0); err != nil {
		t.Fatal(err)
	}
	if v, err := s.VersionByID(a.ID, id); err != nil || v.ArtifactID != a.ID {
		t.Errorf("VersionByID on its own artifact = %+v, %v", v, err)
	}
	if v, err := s.VersionByID(b.ID, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("VersionByID on another artifact = %+v, %v, want ErrNotFound", v, err)
	}
}
