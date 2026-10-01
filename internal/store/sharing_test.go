package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
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
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.AppendRecord(r1); err != nil {
			t.Fatal(err)
		}
		return tx.SetPublicToken("abc", 1)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.ArtifactByID(a.ID)
	if got.PublicTokenHash != "abc" || got.PublicEpoch != 1 {
		t.Fatalf("token not stored: %+v", got)
	}
	if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error { return tx.AppendRecord(r2) }); err != nil {
		t.Fatal(err)
	}
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
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.AppendRecord(r1); err != nil {
			t.Fatal(err)
		}
		return tx.AppendRecord(r2)
	})
	if err != nil {
		t.Fatal(err)
	}
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
	if err == nil || !strings.Contains(err.Error(), "CHECK constraint failed") {
		t.Fatalf("bad role: got %v, want a CHECK constraint failure", err)
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
		if err != nil || len(ap) != 1 || ap[0].UserID != k.ID || ap[0].FP != "fpk" || ap[0].Epoch != 2 ||
			string(ap[0].Envelope.Body) != "ab" || string(ap[0].Envelope.Sig) != "as" || ap[0].Envelope.Signer != o.ID {
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
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.AppendRecord(record(1, "", 1, "b1")); err != nil {
			return err
		}
		if err := tx.SetMembers([]Member{{UserID: m.ID, Role: "viewer", FP: "f"}}); err != nil {
			return err
		}
		if err := tx.PutWrap(Wrap{UserID: m.ID, Epoch: 1, Wrapped: []byte("w"), FP: "f"}); err != nil {
			return err
		}
		return tx.PutEstate(1, []byte("s"))
	})
	if err != nil {
		t.Fatal(err)
	}
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
	// Store.OpenOffer reads the same row outside a transaction.
	if _, err := s.OpenOffer(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Store.OpenOffer with none open: %v", err)
	}
	err = s.WithArtifact(a.ID, func(tx *ArtifactTx) error { return tx.PutOffer(Offer{To: e.ID, By: "admin"}) })
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.OpenOffer(a.ID)
	if err != nil || got.To != e.ID || got.By != "admin" || got.CreatedAt == "" {
		t.Errorf("Store.OpenOffer: %v %+v", err, got)
	}
}

func TestVersionPusherAndWriteEpochs(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	v, err := s.CreateVersion(a.ID, "v1", "", "c1", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.PushedBy != "" || v.Epoch != 0 {
		t.Fatalf("defaults: %+v", v)
	}
	err = s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
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
	var n, ep int
	s.db.QueryRow(`SELECT COUNT(*) FROM version_writes WHERE version_id = ?`, v.ID).Scan(&n)
	s.db.QueryRow(`SELECT epoch FROM version_writes WHERE version_id = ? AND kind = 'file'`, v.ID).Scan(&ep)
	if n != 2 || ep != 3 {
		t.Fatalf("version_writes: n=%d epoch=%d", n, ep)
	}
}

// A push stamps its pusher and the artifact's epoch in the same statement
// that stores the version, so no epoch change can land between the two.
func TestVersionWritesStampThePusherAndEpoch(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error { return tx.AppendRecord(record(1, "", 2, "b1")) }); err != nil {
		t.Fatal(err)
	}
	v, err := s.CreateVersion(a.ID, "v1", "", "c1", o.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.PushedBy != o.ID || v.Epoch != 2 {
		t.Errorf("created: %+v, want pushedBy %s at epoch 2", v, o.ID)
	}
	if got, _ := s.VersionByID(a.ID, v.ID); got.PushedBy != o.ID || got.Epoch != 2 {
		t.Errorf("stored: %+v", got)
	}

	// A swap by someone else, after the epoch moved, restamps both.
	p := testAccount(t, s, "p@x.y")
	if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		latest, err := tx.LatestRecord()
		if err != nil {
			return err
		}
		return tx.AppendRecord(record(2, latest.BodyHash, 3, "b2"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SwapVersionContent(a.ID, v.ID, "c2", "v1", "", p.ID, 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.VersionByID(a.ID, v.ID); got.PushedBy != p.ID || got.Epoch != 3 {
		t.Errorf("after swap: %+v, want pushedBy %s at epoch 3", got, p.ID)
	}
}

func TestAccessState(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	m := testAccount(t, s, "m@x.y")
	a := ownedArtifact(t, s, o)
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.AppendRecord(record(1, "", 1, "b1")); err != nil {
			return err
		}
		if err := tx.SetMembers([]Member{{UserID: m.ID, Role: "editor", FP: "fm"}}); err != nil {
			return err
		}
		return tx.PutWrap(Wrap{UserID: m.ID, Epoch: 1, Wrapped: []byte("w"), FP: "fm"})
	})
	if err != nil {
		t.Fatal(err)
	}
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

const secondArtifactID = "22222222-2222-4222-8222-222222222222"

func countRows(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDeleteUserCascadesTheirSharingRows(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	m := testAccount(t, s, "m@x.y")
	other := testAccount(t, s, "other@x.y")
	a := ownedArtifact(t, s, o)
	v, err := s.CreateVersion(a.ID, "v1", "", "c1", m.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.SetMembers([]Member{{UserID: m.ID, Role: "viewer", FP: "fm"}, {UserID: other.ID, Role: "viewer", FP: "fo"}}); err != nil {
			return err
		}
		if err := tx.SetExcluded([]Excluded{{UserID: m.ID, FP: "fm", Email: "m@x.y"}}); err != nil {
			return err
		}
		for _, u := range []*User{m, other} {
			if err := tx.PutWrap(Wrap{UserID: u.ID, Epoch: 1, Wrapped: []byte("w"), FP: "f"}); err != nil {
				return err
			}
			if err := tx.PutApproval(Approval{UserID: u.ID, FP: "f", Epoch: 1, Envelope: Envelope{Body: []byte("b"), Sig: []byte("s"), Signer: o.ID}}); err != nil {
				return err
			}
		}
		if err := tx.PutOffer(Offer{To: m.ID, By: "admin"}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(m.ID); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []struct{ name, query string }{
		{"artifact_members", `SELECT COUNT(*) FROM artifact_members WHERE user_id = ?`},
		{"artifact_keys", `SELECT COUNT(*) FROM artifact_keys WHERE user_id = ?`},
		{"team_approvals", `SELECT COUNT(*) FROM team_approvals WHERE user_id = ?`},
		{"artifact_offers", `SELECT COUNT(*) FROM artifact_offers WHERE to_user = ?`},
	} {
		if n := countRows(t, s, tbl.query, m.ID); n != 0 {
			t.Errorf("%s kept %d rows for the deleted user", tbl.name, n)
		}
		// the other user's rows are untouched (the offer was only to m)
		if tbl.name != "artifact_offers" {
			if n := countRows(t, s, tbl.query, other.ID); n != 1 {
				t.Errorf("%s: other user has %d rows, want 1", tbl.name, n)
			}
		}
	}
	got, err := s.VersionByID(a.ID, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PushedBy != "" {
		t.Errorf("pushed_by = %q after the pusher was deleted, want empty", got.PushedBy)
	}
	// artifact_excluded deliberately has no foreign key: the entry survives.
	err = s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		ex, err := tx.ExcludedEntries()
		if err != nil || len(ex) != 1 || ex[0].UserID != m.ID || ex[0].Email != "m@x.y" {
			t.Errorf("excluded entry after delete: %v %+v", err, ex)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSharingWritesStayWithinTheirArtifact(t *testing.T) {
	var m1ID, m2ID string
	seed := func(t *testing.T) (*Store, *Artifact) {
		s := testStore(t)
		o := testAccount(t, s, "o@x.y")
		m1 := testAccount(t, s, "m1@x.y")
		m2 := testAccount(t, s, "m2@x.y")
		m1ID, m2ID = m1.ID, m2.ID
		a := ownedArtifact(t, s, o)
		b, err := s.CreateOwnedArtifact(secondArtifactID, "Other", "", o.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{a.ID, b.ID} {
			err := s.WithArtifact(id, func(tx *ArtifactTx) error {
				if err := tx.SetMembers([]Member{{UserID: m1.ID, Role: "viewer", FP: "f1"}, {UserID: m2.ID, Role: "viewer", FP: "f2"}}); err != nil {
					return err
				}
				if err := tx.SetExcluded([]Excluded{{UserID: "x1", FP: "f", Email: "x1@x.y"}, {UserID: "x2", FP: "f", Email: "x2@x.y"}}); err != nil {
					return err
				}
				for _, u := range []*User{m1, m2} {
					if err := tx.PutWrap(Wrap{UserID: u.ID, Epoch: 1, Wrapped: []byte("w"), FP: "f"}); err != nil {
						return err
					}
					if err := tx.PutApproval(Approval{UserID: u.ID, FP: "f", Epoch: 1, Envelope: Envelope{Body: []byte("b"), Sig: []byte("s"), Signer: o.ID}}); err != nil {
						return err
					}
				}
				if err := tx.PutEstate(1, []byte("s1")); err != nil {
					return err
				}
				return tx.PutEstate(2, []byte("s2"))
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		return s, a
	}
	ops := map[string]func(tx *ArtifactTx) error{
		"DeleteWrapsExcept":     func(tx *ArtifactTx) error { return tx.DeleteWrapsExcept([]string{m1ID}) },
		"DeleteApprovalsExcept": func(tx *ArtifactTx) error { return tx.DeleteApprovalsExcept([]string{m1ID}) },
		"DeleteWraps":           func(tx *ArtifactTx) error { return tx.DeleteWraps(m2ID) },
		"SetMembers":            func(tx *ArtifactTx) error { return tx.SetMembers(nil) },
		"SetExcluded":           func(tx *ArtifactTx) error { return tx.SetExcluded(nil) },
		"DeleteEstates":         func(tx *ArtifactTx) error { return tx.DeleteEstates() },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			s, a := seed(t)
			if err := s.WithArtifact(a.ID, op); err != nil {
				t.Fatal(err)
			}
			for _, tbl := range []string{"artifact_members", "artifact_excluded", "artifact_keys", "team_approvals", "artifact_estate_keys"} {
				if n := countRows(t, s, `SELECT COUNT(*) FROM `+tbl+` WHERE artifact_id = ?`, secondArtifactID); n != 2 {
					t.Errorf("%s on artifact A changed artifact B's %s: %d rows, want 2", name, tbl, n)
				}
			}
		})
	}
}

func TestDeleteWrapsExceptWithNoKeepListDeletesAll(t *testing.T) {
	for name, keep := range map[string][]string{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			o := testAccount(t, s, "o@x.y")
			m := testAccount(t, s, "m@x.y")
			a := ownedArtifact(t, s, o)
			err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
				for _, u := range []string{o.ID, m.ID} {
					if err := tx.PutWrap(Wrap{UserID: u, Epoch: 1, Wrapped: []byte("w"), FP: "f"}); err != nil {
						return err
					}
				}
				return tx.DeleteWrapsExcept(keep)
			})
			if err != nil {
				t.Fatal(err)
			}
			if n := countRows(t, s, `SELECT COUNT(*) FROM artifact_keys WHERE artifact_id = ?`, a.ID); n != 0 {
				t.Fatalf("%d wraps survived an empty keep list", n)
			}
		})
	}
}

func TestVersionWritesRefuseAVersionOnAnotherArtifact(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	b, err := s.CreateOwnedArtifact(secondArtifactID, "Other", "", o.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	vb, err := s.CreateVersion(b.ID, "v1", "", "c1", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.RecordWrite(vb.ID, "db", "", 5, o.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("RecordWrite(other artifact's version) = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.VersionByID(b.ID, vb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PushedBy != "" || got.Epoch != 0 {
		t.Errorf("other artifact's version changed: %+v", got)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM version_writes WHERE version_id = ?`, vb.ID); n != 0 {
		t.Errorf("%d version_writes rows recorded for another artifact's version", n)
	}
}

func TestAcceptedOffersListsOnlyAcceptedOwnerOffers(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	e := testAccount(t, s, "e@x.y")
	a := ownedArtifact(t, s, o)
	owner := func(hash string) Offer {
		return Offer{To: e.ID, By: "owner", Hash: hash, Envelope: &Envelope{Body: []byte("ob"), Sig: []byte("os"), Signer: o.ID}}
	}
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		// an accepted admin offer has an empty hash
		if err := tx.PutOffer(Offer{To: e.ID, By: "admin"}); err != nil {
			return err
		}
		if err := tx.SetOfferState("accepted"); err != nil {
			return err
		}
		// a closed owner offer has a hash but was not accepted
		if err := tx.PutOffer(owner("h-closed")); err != nil {
			return err
		}
		if err := tx.SetOfferState("closed"); err != nil {
			return err
		}
		if err := tx.PutOffer(owner("h-accepted")); err != nil {
			return err
		}
		if err := tx.SetOfferState("accepted"); err != nil {
			return err
		}
		got, err := tx.AcceptedOffers()
		if err != nil {
			return err
		}
		if len(got) != 1 || got["h-accepted"] == nil {
			t.Errorf("AcceptedOffers = %+v, want only h-accepted", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestArtifactsByResourceOrderAndMatching(t *testing.T) {
	s := testStore(t)
	// created in the opposite order to their dates, so a wrong order shows
	newer, err := s.CreateArtifact("newer", "", false)
	if err != nil {
		t.Fatal(err)
	}
	older, err := s.CreateArtifact("older", "", false)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := s.CreateArtifact("unrelated", "", false)
	if err != nil {
		t.Fatal(err)
	}
	for id, at := range map[string]string{older.ID: "2020-01-01T00:00:00Z", newer.ID: "2021-01-01T00:00:00Z", unrelated.ID: "2019-01-01T00:00:00Z"} {
		if _, err := s.db.Exec(`UPDATE artifacts SET created_at = ? WHERE id = ?`, at, id); err != nil {
			t.Fatal(err)
		}
	}
	// two resources on one artifact carry the same value
	for _, add := range []struct{ artifact, value string }{
		{newer.ID, "sess-1"}, {older.ID, "sess-1"}, {older.ID, "sess-1"}, {unrelated.ID, "other"},
	} {
		if _, err := s.AddResource(add.artifact, "claude-session", add.value); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ArtifactsByResource("sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != older.ID || got[1].ID != newer.ID {
		t.Fatalf("ArtifactsByResource = %+v, want [older, newer] with no duplicates", got)
	}
	got, err = s.ArtifactsByResource("no-such-ref")
	if err != nil || len(got) != 0 {
		t.Fatalf("non-matching ref: %v %+v", err, got)
	}
}

func TestSetExcludedNormalizesEmail(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.SetExcluded([]Excluded{{UserID: "u1", FP: "f", Email: "  Gone@X.Y "}}); err != nil {
			return err
		}
		ex, err := tx.ExcludedEntries()
		if err != nil {
			return err
		}
		if len(ex) != 1 || ex[0].Email != "gone@x.y" {
			t.Errorf("excluded email not normalized: %+v", ex)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
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

// keyedAccount creates a verified account whose bundle carries keys tagged
// tag, so two accounts with the same tag share a fingerprint.
func keyedAccount(t *testing.T, s *Store, email, tag string) *User {
	t.Helper()
	u, err := s.CreateAccount(email, "N", "h", testBundle(tag), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkVerified(u.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUserByIDInsideTheTransaction(t *testing.T) {
	s := testStore(t)
	o := keyedAccount(t, s, "o@x.y", "o")
	m := keyedAccount(t, s, "m@x.y", "m")
	if err := s.SetUserDisabled(m.ID, true); err != nil {
		t.Fatal(err)
	}
	pending, err := s.CreateAccount("p@x.y", "P", "h", testBundle("p"), false)
	if err != nil {
		t.Fatal(err)
	}
	a := ownedArtifact(t, s, o)
	err = s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		got, err := tx.UserByID(m.ID)
		if err != nil {
			return err
		}
		b := testBundle("m")
		wantFP := hex.EncodeToString(e2e.Fingerprint(b.X25519Pub, b.Ed25519Pub))
		if got.ID != m.ID || got.Email != "m@x.y" || !bytes.Equal(got.X25519Pub, b.X25519Pub) ||
			!bytes.Equal(got.Ed25519Pub, b.Ed25519Pub) || got.FP != wantFP || !got.Verified || !got.Disabled {
			t.Errorf("UserByID: %+v, want fp %s", got, wantFP)
		}
		if got, err := tx.UserByID(pending.ID); err != nil || got.Verified || got.Disabled {
			t.Errorf("unverified account: %v %+v", err, got)
		}
		if _, err := tx.UserByID("missing"); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing user: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUsersSharingMatchesFingerprintOrEmail(t *testing.T) {
	s := testStore(t)
	o := keyedAccount(t, s, "o@x.y", "o")
	m := keyedAccount(t, s, "m@x.y", "m")
	twin := keyedAccount(t, s, "twin@x.y", "m") // m's public keys under another ID
	other := keyedAccount(t, s, "other@x.y", "other")
	a := ownedArtifact(t, s, o)
	b := testBundle("m")
	fpM := hex.EncodeToString(e2e.Fingerprint(b.X25519Pub, b.Ed25519Pub))
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		got, err := tx.UsersSharing(fpM, "nobody@x.y")
		if err != nil {
			return err
		}
		want := []string{m.ID, twin.ID}
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("by fingerprint: %v, want %v", got, want)
		}
		got, err = tx.UsersSharing(strings.Repeat("0", 64), " Other@X.Y")
		if err != nil {
			return err
		}
		if len(got) != 1 || got[0] != other.ID {
			t.Errorf("by email: %v, want [%s]", got, other.ID)
		}
		got, err = tx.UsersSharing(strings.Repeat("0", 64), "nobody@x.y")
		if err != nil || len(got) != 0 {
			t.Errorf("no match: %v %v", err, got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReplaceWrapOverwritesTheUsersWrapForThatEpoch(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	m := testAccount(t, s, "m@x.y")
	a := ownedArtifact(t, s, o)
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		if err := tx.PutWrap(Wrap{UserID: m.ID, Epoch: 1, Wrapped: []byte("old"), FP: "fp-old"}); err != nil {
			return err
		}
		if err := tx.ReplaceWrap(Wrap{UserID: m.ID, Epoch: 1, Wrapped: []byte("new"), FP: "fp-new"}); err != nil {
			return err
		}
		if err := tx.ReplaceWrap(Wrap{UserID: m.ID, Epoch: 2, Wrapped: []byte("two"), FP: "fp-new"}); err != nil {
			return err
		}
		ws, err := tx.Wraps()
		if err != nil {
			return err
		}
		if len(ws) != 2 || string(ws[0].Wrapped) != "new" || ws[0].FP != "fp-new" || ws[1].Epoch != 2 {
			t.Errorf("wraps after ReplaceWrap: %+v", ws)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A push or re-upload that declares an epoch fails once the artifact's epoch
// has moved on, and writes nothing.
func TestVersionWritesDeclareTheirEpoch(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	setEpoch := func(epoch int) {
		if _, err := s.db.Exec(`UPDATE artifacts SET epoch = ? WHERE id = ?`, epoch, a.ID); err != nil {
			t.Fatal(err)
		}
	}
	setEpoch(1)
	v, err := s.CreateVersion(a.ID, "v1", "", "c1", o.ID, 1)
	if err != nil || v.Epoch != 1 {
		t.Fatalf("push declaring the current epoch: %v %+v", err, v)
	}
	setEpoch(2)
	if _, err := s.CreateVersion(a.ID, "v2", "", "c2", o.ID, 1); !errors.Is(err, ErrEpochMoved) {
		t.Errorf("push declaring epoch 1 at epoch 2: %v, want ErrEpochMoved", err)
	}
	if _, err := s.SwapVersionContent(a.ID, v.ID, "c3", "v1", "", o.ID, 1); !errors.Is(err, ErrEpochMoved) {
		t.Errorf("re-upload declaring epoch 1 at epoch 2: %v, want ErrEpochMoved", err)
	}
	if vs, _ := s.ListVersions(a.ID); len(vs) != 1 || vs[0].ContentDir != "c1" || vs[0].Epoch != 1 {
		t.Errorf("versions after refused writes: %+v, want the original untouched", vs)
	}
	// 0 declares nothing and takes the current epoch.
	v2, err := s.CreateVersion(a.ID, "v2", "", "c2", o.ID, 0)
	if err != nil || v2.Epoch != 2 {
		t.Errorf("push declaring nothing: %v %+v, want epoch 2", err, v2)
	}
	if _, err := s.CreateVersion(a.ID, "v3", "", "c3", o.ID, 2); err != nil {
		t.Errorf("push declaring epoch 2: %v", err)
	}
}

// A vouch is for the content the owner reviewed, so replacing that content
// drops it.
func TestSwapVersionContentDropsTheVouch(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	v, err := s.CreateVersion(a.ID, "v1", "", "c1", o.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	vouches := func() int {
		var n int
		if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
			vs, err := tx.Vouches()
			n = len(vs)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		return tx.PutVouch(v.ID, Envelope{Body: []byte("vb"), Sig: []byte("vs"), Signer: o.ID})
	}); err != nil {
		t.Fatal(err)
	}
	if n := vouches(); n != 1 {
		t.Fatalf("%d vouches before the swap, want 1", n)
	}
	if _, err := s.SwapVersionContent(a.ID, v.ID, "c2", "v1", "", o.ID, 0); err != nil {
		t.Fatal(err)
	}
	if n := vouches(); n != 0 {
		t.Errorf("%d vouches after the swap, want 0", n)
	}
}
