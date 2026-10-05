package store

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func metaField(aid, vid, field, record string) MetaField {
	return MetaField{ArtifactID: aid, VersionID: vid, Field: field,
		Record: []byte(record), SignerKey: []byte("key"), Blob: []byte("blob-" + record)}
}

func TestMetaFieldsPutReplaceList(t *testing.T) {
	s := testStore(t)
	a, err := s.CreateArtifact(false)
	if err != nil {
		t.Fatal(err)
	}
	vid := uuid.NewString()
	if _, err := s.CreateVersion(a.ID, vid, "c1", "", "", 0); err != nil {
		t.Fatal(err)
	}
	for _, f := range []MetaField{
		metaField(a.ID, "", "name", "one"),
		metaField(a.ID, "", "description", "two"),
		metaField(a.ID, vid, "name", "three"),
		metaField(a.ID, vid, "changelog", "four"),
	} {
		if err := s.PutMetaField(f); err != nil {
			t.Fatalf("put %+v: %v", f, err)
		}
	}
	// A write replaces the field.
	if err := s.PutMetaField(metaField(a.ID, "", "name", "replaced")); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListMetaFields(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("ListMetaFields = %d fields, want 4: %+v", len(got), got)
	}
	by := map[string]MetaField{}
	for _, f := range got {
		by[f.VersionID+"/"+f.Field] = f
	}
	if f := by["/name"]; !bytes.Equal(f.Record, []byte("replaced")) || !bytes.Equal(f.Blob, []byte("blob-replaced")) || !bytes.Equal(f.SignerKey, []byte("key")) {
		t.Errorf("artifact name = %+v, want the replacement", f)
	}
	if by[vid+"/changelog"].Field != "changelog" || by["/description"].Field != "description" {
		t.Errorf("fields = %+v", by)
	}
}

func TestPutMetaFieldRefusesAMissingVersion(t *testing.T) {
	s := testStore(t)
	a, _ := s.CreateArtifact(false)
	b, _ := s.CreateArtifact(false)
	vid := uuid.NewString()
	if _, err := s.CreateVersion(b.ID, vid, "c1", "", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMetaField(metaField(a.ID, uuid.NewString(), "name", "x")); !errors.Is(err, ErrNotFound) {
		t.Errorf("a version that does not exist: %v, want ErrNotFound", err)
	}
	// Another artifact's version is not this artifact's.
	if err := s.PutMetaField(metaField(a.ID, vid, "name", "x")); !errors.Is(err, ErrNotFound) {
		t.Errorf("another artifact's version: %v, want ErrNotFound", err)
	}
	if got, _ := s.ListMetaFields(a.ID); len(got) != 0 {
		t.Errorf("stored %+v", got)
	}
}

func TestMetaFieldsLeaveWithTheirOwner(t *testing.T) {
	s := testStore(t)
	a, _ := s.CreateArtifact(false)
	other, _ := s.CreateArtifact(false)
	vid := uuid.NewString()
	if _, err := s.CreateVersion(a.ID, vid, "c1", "", "", 0); err != nil {
		t.Fatal(err)
	}
	for _, f := range []MetaField{
		metaField(a.ID, "", "name", "a"),
		metaField(a.ID, vid, "name", "v"),
		metaField(other.ID, "", "name", "o"),
	} {
		if err := s.PutMetaField(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteVersion(a.ID, vid); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListMetaFields(a.ID)
	if len(got) != 1 || got[0].VersionID != "" {
		t.Fatalf("after deleting the version: %+v, want only the artifact's field", got)
	}
	if err := s.DeleteArtifact(a.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListMetaFields(a.ID); len(got) != 0 {
		t.Errorf("after deleting the artifact: %+v", got)
	}
	if got, _ := s.ListMetaFields(other.ID); len(got) != 1 {
		t.Errorf("another artifact's field was removed: %+v", got)
	}
}
