package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
)

func hexHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ownedArtifact creates an artifact owned by a fresh account, with no
// membership record yet.
func ownedArtifact(t *testing.T, s *Store, owner *User) *Artifact {
	t.Helper()
	a, err := s.CreateOwnedArtifact("11111111-1111-4111-8111-111111111111", "Poll", "", owner.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func record(seq int, prev string, epoch int, body string) *Record {
	return &Record{
		Seq: seq, Prev: prev, Epoch: epoch, OwnerID: "", OwnerFp: "fp-owner",
		AKCommit: []byte("commit"), Team: "none",
		Envelope: Envelope{Body: []byte(body), Sig: []byte("sig"), Signer: "owner"},
	}
}

func TestMigration003RefusesLegacyArtifacts(t *testing.T) {
	// A data directory holding artifacts from before ownership cannot be
	// migrated: they have no owner.
	path := filepath.Join(t.TempDir(), "cairn.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"migrations/001_init.sql", "migrations/002_accounts.sql"} {
		body, err := migrationsFS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (name, applied_at) VALUES (?, 'x')`, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO artifacts (id, name, created_at, updated_at) VALUES ('a1', 'old', 'x', 'x')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(path); !errors.Is(err, ErrLegacyData) {
		t.Fatalf("expected ErrLegacyData, got %v", err)
	}
}

func TestCreateOwnedArtifactSetsOwner(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, u)
	got, err := s.ArtifactByID(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.OwnerID != u.ID || got.Epoch != 0 || got.Team != "none" || got.PublicWrites {
		t.Fatalf("unexpected artifact: %+v", got)
	}
}

func TestCreateOwnedArtifactDuplicateID(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, u)
	if _, err := s.CreateOwnedArtifact(a.ID, "again", "", u.ID, nil); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
}

func TestCreateOwnedArtifactRollsBackWhenFnFails(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	boom := errors.New("boom")
	_, err := s.CreateOwnedArtifact("22222222-2222-4222-8222-222222222222", "x", "", u.ID,
		func(*ArtifactTx) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if _, err := s.ArtifactByID("22222222-2222-4222-8222-222222222222"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("artifact survived a failed transaction: %v", err)
	}
}

func TestWithArtifactMissingAndRollback(t *testing.T) {
	s := testStore(t)
	if err := s.WithArtifact("nope", func(*ArtifactTx) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	u := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, u)
	boom := errors.New("boom")
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.PutEstate(1, []byte("sealed")); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM artifact_estate_keys`).Scan(&n)
	if n != 0 {
		t.Fatal("write survived a failed transaction")
	}
}

func TestRecordChain(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, u)
	r1 := record(1, "", 1, "body-one")
	r1.Public, r1.PublicWrites, r1.Team = true, true, "viewer"
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if _, err := tx.LatestRecord(); !errors.Is(err, ErrNotFound) {
			t.Errorf("empty chain: %v", err)
		}
		return tx.AppendRecord(r1)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.ArtifactByID(a.ID)
	if got.Epoch != 1 || !got.Public || !got.PublicWrites || got.Team != "viewer" || got.OwnerID != u.ID {
		t.Fatalf("artifact not updated from record: %+v", got)
	}

	// Stale seq, stale prev, and a replay all fail with ErrStale.
	for name, r := range map[string]*Record{
		"replay":     record(1, "", 1, "body-one"),
		"skip":       record(3, hexHash([]byte("body-one")), 1, "x"),
		"wrong prev": record(2, hexHash([]byte("other")), 1, "x"),
		"empty prev": record(2, "", 1, "x"),
	} {
		err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error { return tx.AppendRecord(r) })
		if !errors.Is(err, ErrStale) {
			t.Errorf("%s: expected ErrStale, got %v", name, err)
		}
	}

	r2 := record(2, hexHash([]byte("body-one")), 2, "body-two")
	r2.AKCommit = []byte("commit-2")
	if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error { return tx.AppendRecord(r2) }); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ArtifactByID(a.ID)
	if got.Epoch != 2 || got.Public || got.PublicWrites || got.Team != "none" {
		t.Fatalf("artifact not updated from second record: %+v", got)
	}
	_ = s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		recs, err := tx.Records()
		if err != nil || len(recs) != 2 || recs[0].Seq != 1 || recs[1].Seq != 2 {
			t.Fatalf("Records: %v %+v", err, recs)
		}
		latest, err := tx.LatestRecord()
		if err != nil || latest.Seq != 2 || string(latest.Envelope.Body) != "body-two" ||
			latest.BodyHash != hexHash([]byte("body-two")) || string(latest.AKCommit) != "commit-2" ||
			latest.Envelope.Signer != "owner" || latest.CreatedAt == "" {
			t.Fatalf("LatestRecord: %v %+v", err, latest)
		}
		return nil
	})
}

func TestPrivateRecordClearsPublicToken(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, u)
	r1 := record(1, "", 1, "b1")
	r1.Public = true
	r2 := record(2, hexHash([]byte("b1")), 1, "b2")
	s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.AppendRecord(r1); err != nil {
			t.Fatal(err)
		}
		return tx.SetPublicToken("abc", 1)
	})
	got, _ := s.ArtifactByID(a.ID)
	if got.PublicTokenHash != "abc" || got.PublicEpoch != 1 {
		t.Fatalf("token not stored: %+v", got)
	}
	s.WithArtifact(a.ID, func(tx *ArtifactTx) error { return tx.AppendRecord(r2) })
	got, _ = s.ArtifactByID(a.ID)
	if got.PublicTokenHash != "" || got.PublicEpoch != 0 {
		t.Fatalf("private record left the link live: %+v", got)
	}
}

func TestOwnerChangesWithRecord(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	n := testAccount(t, s, "n@x.y")
	a := ownedArtifact(t, s, o)
	r1 := record(1, "", 1, "b1")
	r2 := record(2, hexHash([]byte("b1")), 1, "b2")
	r2.OwnerID, r2.Transfer = n.ID, "offerhash"
	s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.AppendRecord(r1); err != nil {
			t.Fatal(err)
		}
		return tx.AppendRecord(r2)
	})
	got, _ := s.ArtifactByID(a.ID)
	if got.OwnerID != n.ID {
		t.Fatalf("owner not changed: %+v", got)
	}
}

func TestMembersAndExcludedReplaced(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	m1 := testAccount(t, s, "m1@x.y")
	m2 := testAccount(t, s, "m2@x.y")
	a := ownedArtifact(t, s, o)
	s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.SetMembers([]Member{{UserID: m1.ID, Role: "editor", FP: "f1"}, {UserID: m2.ID, Role: "viewer", FP: "f2"}}); err != nil {
			t.Fatal(err)
		}
		if err := tx.SetExcluded([]Excluded{{UserID: "gone", FP: "fg", Email: "gone@x.y"}}); err != nil {
			t.Fatal(err)
		}
		ms, _ := tx.Members()
		if len(ms) != 2 {
			t.Fatalf("members: %+v", ms)
		}
		// replacing drops the rest
		if err := tx.SetMembers([]Member{{UserID: m2.ID, Role: "editor", FP: "f2b"}}); err != nil {
			t.Fatal(err)
		}
		if err := tx.SetExcluded(nil); err != nil {
			t.Fatal(err)
		}
		ms, _ = tx.Members()
		if len(ms) != 1 || ms[0].Role != "editor" || ms[0].FP != "f2b" {
			t.Fatalf("members after replace: %+v", ms)
		}
		ex, _ := tx.ExcludedEntries()
		if len(ex) != 0 {
			t.Fatalf("excluded after replace: %+v", ex)
		}
		return nil
	})
	// a role outside viewer/editor is refused by the schema
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		return tx.SetMembers([]Member{{UserID: m1.ID, Role: "owner", FP: "f"}})
	})
	if err == nil {
		t.Fatal("bad role accepted")
	}
}

func TestWrapsEstateAndApprovals(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	m := testAccount(t, s, "m@x.y")
	k := testAccount(t, s, "k@x.y")
	a := ownedArtifact(t, s, o)
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		for _, w := range []Wrap{
			{UserID: m.ID, Epoch: 1, Wrapped: []byte("w1"), FP: "fpm"},
			{UserID: m.ID, Epoch: 2, Wrapped: []byte("w2"), FP: "fpm"},
			{UserID: k.ID, Epoch: 2, Wrapped: []byte("w3"), FP: "fpk"},
		} {
			if err := tx.PutWrap(w); err != nil {
				return err
			}
		}
		if err := tx.PutWrap(Wrap{UserID: m.ID, Epoch: 2, Wrapped: []byte("dup"), FP: "fpm"}); !errors.Is(err, ErrExists) {
			t.Errorf("duplicate wrap: %v", err)
		}
		if err := tx.PutEstate(1, []byte("s1")); err != nil {
			return err
		}
		if err := tx.PutEstate(2, []byte("s2")); err != nil {
			return err
		}
		return tx.PutApproval(Approval{UserID: k.ID, FP: "fpk", Epoch: 2, Envelope: Envelope{Body: []byte("ab"), Sig: []byte("as"), Signer: o.ID}})
	})
	if err != nil {
		t.Fatal(err)
	}

	ws, err := s.WrapsFor(a.ID, m.ID)
	if err != nil || len(ws) != 2 || ws[0].Epoch != 1 || ws[1].Epoch != 2 || string(ws[1].Wrapped) != "w2" || ws[1].FP != "fpm" {
		t.Fatalf("WrapsFor: %v %+v", err, ws)
	}
	est, err := s.EstateKeys(a.ID)
	if err != nil || len(est) != 2 || est[0].Epoch != 1 || !bytes.Equal(est[1].Sealed, []byte("s2")) {
		t.Fatalf("EstateKeys: %v %+v", err, est)
	}

	s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		ap, err := tx.Approvals()
		if err != nil || len(ap) != 1 || ap[0].UserID != k.ID || string(ap[0].Envelope.Sig) != "as" {
			t.Fatalf("Approvals: %v %+v", err, ap)
		}
		// next epoch: drop every wrap held by a user the record does not list
		if err := tx.DeleteWrapsExcept([]string{m.ID}); err != nil {
			t.Fatal(err)
		}
		if err := tx.DeleteApprovalsExcept([]string{m.ID}); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if ws, _ := s.WrapsFor(a.ID, k.ID); len(ws) != 0 {
		t.Fatalf("wraps survived: %+v", ws)
	}
	s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if ap, _ := tx.Approvals(); len(ap) != 0 {
			t.Fatalf("approval survived: %+v", ap)
		}
		// removing a member deletes that member's wraps
		if err := tx.DeleteWraps(m.ID); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if ws, _ := s.WrapsFor(a.ID, m.ID); len(ws) != 0 {
		t.Fatalf("wraps survived: %+v", ws)
	}
}

func TestDeletingArtifactRemovesSharingRows(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	m := testAccount(t, s, "m@x.y")
	a := ownedArtifact(t, s, o)
	s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		tx.AppendRecord(record(1, "", 1, "b1"))
		tx.SetMembers([]Member{{UserID: m.ID, Role: "viewer", FP: "f"}})
		tx.PutWrap(Wrap{UserID: m.ID, Epoch: 1, Wrapped: []byte("w"), FP: "f"})
		tx.PutEstate(1, []byte("s"))
		return nil
	})
	if err := s.DeleteArtifact(a.ID); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"artifact_records", "artifact_members", "artifact_keys", "artifact_estate_keys"} {
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM ` + tbl).Scan(&n)
		if n != 0 {
			t.Errorf("%s kept %d rows", tbl, n)
		}
	}
}

func TestOffers(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	e := testAccount(t, s, "e@x.y")
	a := ownedArtifact(t, s, o)
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if _, err := tx.OpenOffer(); !errors.Is(err, ErrNotFound) {
			t.Errorf("no offer: %v", err)
		}
		off := Offer{To: e.ID, By: "owner", Hash: "h1", Envelope: &Envelope{Body: []byte("ob"), Sig: []byte("os"), Signer: o.ID}}
		if err := tx.PutOffer(off); err != nil {
			return err
		}
		// one open offer at a time
		if err := tx.PutOffer(Offer{To: e.ID, By: "admin"}); !errors.Is(err, ErrExists) {
			t.Errorf("second open offer: %v", err)
		}
		got, err := tx.OpenOffer()
		if err != nil || got.To != e.ID || got.By != "owner" || got.Envelope == nil || string(got.Envelope.Body) != "ob" || got.CreatedAt == "" {
			t.Errorf("OpenOffer: %v %+v", err, got)
		}
		if err := tx.SetOfferState("accepted"); err != nil {
			return err
		}
		if _, err := tx.OpenOffer(); !errors.Is(err, ErrNotFound) {
			t.Errorf("accepted offer still open: %v", err)
		}
		// an admin offer carries no envelope and may follow
		if err := tx.PutOffer(Offer{To: e.ID, By: "admin"}); err != nil {
			return err
		}
		got, _ = tx.OpenOffer()
		if got.Envelope != nil || got.By != "admin" {
			t.Errorf("admin offer: %+v", got)
		}
		if err := tx.SetOfferState("closed"); err != nil {
			return err
		}
		accepted, err := tx.AcceptedOffers()
		if err != nil || len(accepted) != 1 || accepted["h1"].To != e.ID {
			t.Errorf("AcceptedOffers: %v %+v", err, accepted)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVersionPusherAndWriteEpochs(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	v, err := s.CreateVersion(a.ID, "v1", "", "c1")
	if err != nil {
		t.Fatal(err)
	}
	if v.PushedBy != "" || v.Epoch != 0 {
		t.Fatalf("defaults: %+v", v)
	}
	err = s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.SetVersionWriter(v.ID, o.ID, 3); err != nil {
			return err
		}
		if err := tx.SetVersionWriter("missing", o.ID, 3); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing version: %v", err)
		}
		if err := tx.RecordWrite(v.ID, "db", "", 3, o.ID); err != nil {
			return err
		}
		if err := tx.RecordWrite(v.ID, "file", "a.txt", 2, o.ID); err != nil {
			return err
		}
		// re-writing replaces the epoch for the same target
		return tx.RecordWrite(v.ID, "file", "a.txt", 3, o.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.VersionByID(a.ID, v.ID)
	if got.PushedBy != o.ID || got.Epoch != 3 {
		t.Fatalf("version writer: %+v", got)
	}
	var n, ep int
	s.db.QueryRow(`SELECT COUNT(*) FROM version_writes WHERE version_id = ?`, v.ID).Scan(&n)
	s.db.QueryRow(`SELECT epoch FROM version_writes WHERE version_id = ? AND kind = 'file'`, v.ID).Scan(&ep)
	if n != 2 || ep != 3 {
		t.Fatalf("version_writes: n=%d epoch=%d", n, ep)
	}
}

func TestAccessState(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	m := testAccount(t, s, "m@x.y")
	a := ownedArtifact(t, s, o)
	s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		tx.AppendRecord(record(1, "", 1, "b1"))
		tx.SetMembers([]Member{{UserID: m.ID, Role: "editor", FP: "fm"}})
		tx.PutWrap(Wrap{UserID: m.ID, Epoch: 1, Wrapped: []byte("w"), FP: "fm"})
		return nil
	})
	st, err := s.AccessState(a.ID, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Artifact.ID != a.ID || st.Member == nil || st.Member.Role != "editor" || st.Member.FP != "fm" ||
		len(st.Wraps) != 1 || st.Wraps[0].Epoch != 1 {
		t.Fatalf("AccessState: %+v", st)
	}
	st, err = s.AccessState(a.ID, o.ID)
	if err != nil || st.Member != nil || len(st.Wraps) != 0 {
		t.Fatalf("owner state: %v %+v", err, st)
	}
	st, err = s.AccessState(a.ID, "")
	if err != nil || st.Member != nil {
		t.Fatalf("anonymous state: %v %+v", err, st)
	}
	if _, err := s.AccessState("nope", m.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing artifact: %v", err)
	}
}

func TestDeleteUserWhoOwnsAnArtifactIsErrOwnsArtifacts(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	ownedArtifact(t, s, o)
	if err := s.DeleteUser(o.ID); !errors.Is(err, ErrOwnsArtifacts) {
		t.Fatalf("DeleteUser(owner) = %v, want ErrOwnsArtifacts", err)
	}
	if _, err := s.UserByID(o.ID); err != nil {
		t.Errorf("owner deleted anyway: %v", err)
	}
}

func TestRecordWriteForAVersionOnAnotherArtifactIsErrNotFound(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.RecordWrite("missing", "db", "", 1, o.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("RecordWrite(missing version) = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
