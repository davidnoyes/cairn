package store

import (
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func dataVersion(t *testing.T, s *Store) (artifactID, versionID string) {
	t.Helper()
	a, err := s.CreateArtifact(false)
	if err != nil {
		t.Fatal(err)
	}
	vid := uuid.NewString()
	if _, err := s.CreateVersion(a.ID, vid, "c1", "", "aa", 0); err != nil {
		t.Fatal(err)
	}
	return a.ID, vid
}

func revision(aid, vid string, n int) DBRevision {
	return DBRevision{ArtifactID: aid, VersionID: vid, Revision: n, Epoch: 1, Size: 10, Record: []byte("rec"), SignerKey: []byte("key"), WrittenBy: "u"}
}

func noPlace() error { return nil }

func TestAddDBRevisionChecksTheLatest(t *testing.T) {
	s := testStore(t)
	aid, vid := dataVersion(t, s)
	if _, err := s.LatestDBRevision(aid, vid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("latest of none: %v, want ErrNotFound", err)
	}
	if _, _, err := s.AddDBRevision(revision(aid, vid, 1), 0, noPlace); err != nil {
		t.Fatal(err)
	}
	latest, _, err := s.AddDBRevision(revision(aid, vid, 2), 0, noPlace)
	if !errors.Is(err, ErrRevisionMismatch) || latest != 1 {
		t.Errorf("a stale If-Match: latest %d, %v; want 1 and ErrRevisionMismatch", latest, err)
	}
	if _, _, err := s.AddDBRevision(revision(aid, vid, 2), 1, noPlace); err != nil {
		t.Fatal(err)
	}
	got, err := s.LatestDBRevision(aid, vid)
	if err != nil || got.Revision != 2 || string(got.SignerKey) != "key" || got.WrittenBy != "u" || got.CreatedAt == "" {
		t.Errorf("latest: %+v, %v", got, err)
	}
	one, err := s.DBRevisionByNumber(aid, vid, 1)
	if err != nil || one.Revision != 1 {
		t.Errorf("revision 1: %+v, %v", one, err)
	}
	if _, err := s.DBRevisionByNumber(aid, vid, 9); !errors.Is(err, ErrNotFound) {
		t.Errorf("revision 9: %v, want ErrNotFound", err)
	}
	// A revision is read through its own artifact and version only.
	if _, err := s.DBRevisionByNumber(aid, uuid.NewString(), 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("revision 1 of another version: %v, want ErrNotFound", err)
	}
}

func TestAddDBRevisionRollsBackWhenPlacingFails(t *testing.T) {
	s := testStore(t)
	aid, vid := dataVersion(t, s)
	boom := errors.New("rename failed")
	if _, _, err := s.AddDBRevision(revision(aid, vid, 1), 0, func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the placing error", err)
	}
	if revs, err := s.ListDBRevisions(aid, vid); err != nil || len(revs) != 0 {
		t.Errorf("revisions after a failed place: %v, %v; want none", revs, err)
	}
	if _, _, err := s.AddDBRevision(revision(aid, vid, 1), 0, noPlace); err != nil {
		t.Errorf("a retry after a failed place: %v", err)
	}
}

func TestAddDBRevisionKeepsTheNewestTen(t *testing.T) {
	s := testStore(t)
	aid, vid := dataVersion(t, s)
	var allPruned []int
	for n := 1; n <= 12; n++ {
		_, pruned, err := s.AddDBRevision(revision(aid, vid, n), n-1, noPlace)
		if err != nil {
			t.Fatal(err)
		}
		allPruned = append(allPruned, pruned...)
	}
	if len(allPruned) != 2 || allPruned[0] != 1 || allPruned[1] != 2 {
		t.Errorf("pruned %v, want [1 2]", allPruned)
	}
	revs, err := s.ListDBRevisions(aid, vid)
	if err != nil || len(revs) != 10 || revs[0].Revision != 12 || revs[9].Revision != 3 {
		t.Errorf("kept %d revisions, newest %v: %v", len(revs), revs, err)
	}
}

// Two writes naming the same latest revision: one lands, one is refused.
func TestAddDBRevisionConcurrently(t *testing.T) {
	s := testStore(t)
	aid, vid := dataVersion(t, s)
	for round := 0; round < 20; round++ {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, errs[i] = s.AddDBRevision(revision(aid, vid, round+1), round, noPlace)
			}()
		}
		wg.Wait()
		ok, stale := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrRevisionMismatch):
				stale++
			default:
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if ok != 1 || stale != 1 {
			t.Fatalf("round %d: %d landed and %d refused, want 1 and 1", round, ok, stale)
		}
	}
}

func TestStoredFiles(t *testing.T) {
	s := testStore(t)
	aid, vid := dataVersion(t, s)
	put := func(addr, tag string, place func() error) error {
		return s.PutStoredFile(StoredFile{
			ArtifactID: aid, VersionID: vid, Address: addr, Epoch: 1, Size: 3,
			Record: []byte("rec-" + tag), Meta: []byte("meta-" + tag), MetaRecord: []byte("mrec-" + tag), SignerKey: []byte("key"), WrittenBy: "u",
		}, place)
	}
	if err := put("b", "1", noPlace); err != nil {
		t.Fatal(err)
	}
	if err := put("a", "1", noPlace); err != nil {
		t.Fatal(err)
	}
	// A replacement keeps one row per address.
	if err := put("a", "2", noPlace); err != nil {
		t.Fatal(err)
	}
	files, err := s.ListStoredFiles(aid, vid)
	if err != nil || len(files) != 2 || files[0].Address != "a" || files[1].Address != "b" {
		t.Fatalf("list: %v, %v; want a then b", files, err)
	}
	got, err := s.StoredFileByAddress(aid, vid, "a")
	if err != nil || string(got.Record) != "rec-2" || string(got.Meta) != "meta-2" || string(got.MetaRecord) != "mrec-2" || string(got.SignerKey) != "key" || got.UpdatedAt == "" {
		t.Errorf("replaced file: %+v, %v", got, err)
	}
	// A failed place changes nothing.
	boom := errors.New("rename failed")
	if err := put("a", "3", func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the placing error", err)
	}
	if got, _ := s.StoredFileByAddress(aid, vid, "a"); string(got.Record) != "rec-2" {
		t.Errorf("a failed replacement changed the row: %s", got.Record)
	}
	// A failed remove keeps the row, so it never outlives its blob.
	if err := s.DeleteStoredFile(aid, vid, "a", func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the removing error", err)
	}
	if got, _ := s.StoredFileByAddress(aid, vid, "a"); got == nil || string(got.Record) != "rec-2" {
		t.Errorf("a failed delete removed the row: %+v", got)
	}
	if err := s.DeleteStoredFile(aid, vid, "a", noPlace); err != nil {
		t.Fatal(err)
	}
	removed := false
	if err := s.DeleteStoredFile(aid, vid, "a", func() error { removed = true; return nil }); !errors.Is(err, ErrNotFound) || removed {
		t.Errorf("second delete: %v, removed %v; want ErrNotFound and no remove", err, removed)
	}
	if _, err := s.StoredFileByAddress(aid, vid, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete: %v, want ErrNotFound", err)
	}
}

// Rows go with their version, and with their artifact.
func TestClientDataCascades(t *testing.T) {
	s := testStore(t)
	aid, vid := dataVersion(t, s)
	other := uuid.NewString()
	if _, err := s.CreateVersion(aid, other, "c2", "", "bb", 0); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{vid, other} {
		if _, _, err := s.AddDBRevision(revision(aid, v, 1), 0, noPlace); err != nil {
			t.Fatal(err)
		}
		if err := s.PutStoredFile(StoredFile{ArtifactID: aid, VersionID: v, Address: "a", Epoch: 1, Record: []byte("r"), Meta: []byte("m"), MetaRecord: []byte("mr"), SignerKey: []byte("k"), WrittenBy: "u"}, noPlace); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteVersion(aid, vid); err != nil {
		t.Fatal(err)
	}
	if revs, _ := s.ListDBRevisions(aid, vid); len(revs) != 0 {
		t.Errorf("revisions survive their version: %d", len(revs))
	}
	if files, _ := s.ListStoredFiles(aid, vid); len(files) != 0 {
		t.Errorf("files survive their version: %d", len(files))
	}
	if revs, _ := s.ListDBRevisions(aid, other); len(revs) != 1 {
		t.Errorf("the other version's revisions: %d, want 1", len(revs))
	}
	if err := s.DeleteArtifact(aid); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, table := range []string{"db_revisions", "stored_files"} {
		if err := s.DB().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s rows after the artifact is deleted: %d, %v", table, n, err)
		}
	}
}
