package store

import (
	"errors"
	"testing"
)

// TestArtifactLookupsAndListing covers the pre-existing artifacts.go
// accessors that TestArtifactsAndVersions doesn't exercise.
func TestArtifactLookupsAndListing(t *testing.T) {
	s := testStore(t)
	a, err := s.CreateArtifact("demo", "a demo", false)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.CreateVersion(a.ID, "v1", "initial", "c1", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.AddResource(a.ID, "claude-session", "sess-123")
	if err != nil {
		t.Fatal(err)
	}

	byID, err := s.ArtifactByID(a.ID)
	if err != nil || byID.ID != a.ID {
		t.Fatalf("ArtifactByID: %v %+v", err, byID)
	}
	byName, err := s.ArtifactByName("demo")
	if err != nil || byName.ID != a.ID {
		t.Fatalf("ArtifactByName: %v %+v", err, byName)
	}
	byResourceValue, err := s.ArtifactsByResource("sess-123")
	if err != nil || len(byResourceValue) != 1 || byResourceValue[0].ID != a.ID {
		t.Fatalf("ArtifactsByResource(value): %v %+v", err, byResourceValue)
	}
	byResourceID, err := s.ArtifactsByResource(r.ID)
	if err != nil || len(byResourceID) != 1 || byResourceID[0].ID != a.ID {
		t.Fatalf("ArtifactsByResource(id): %v %+v", err, byResourceID)
	}

	all, err := s.ListArtifacts()
	if err != nil || len(all) != 1 {
		t.Fatalf("ListArtifacts: %v %+v", err, all)
	}

	if err := s.UpdateArtifact(a.ID, "renamed", "new desc"); err != nil {
		t.Fatal(err)
	}
	byID, _ = s.ArtifactByID(a.ID)
	if byID.Name != "renamed" || byID.Description != "new desc" || byID.Public {
		t.Errorf("UpdateArtifact: %+v", byID)
	}

	versions, err := s.ListVersions(a.ID)
	if err != nil || len(versions) != 1 || versions[0].ID != v.ID {
		t.Fatalf("ListVersions: %v %+v", err, versions)
	}

	if err := s.UpdateVersionMeta(a.ID, v.ID, "v1 renamed", "edited"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.VersionByID(a.ID, v.ID)
	if got.Name != "v1 renamed" || got.Changelog != "edited" {
		t.Errorf("UpdateVersionMeta: %+v", got)
	}

	if err := s.DeleteResource(a.ID, r.ID); err != nil {
		t.Fatal(err)
	}
	rs, _ := s.ListResources(a.ID)
	if len(rs) != 0 {
		t.Errorf("DeleteResource: %+v", rs)
	}

	if err := s.DeleteVersion(a.ID, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VersionByID(a.ID, v.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteVersion: %v", err)
	}
}
