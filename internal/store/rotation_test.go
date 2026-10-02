package store

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func rotationRow(seq int, oldFP, newFP string) Rotation {
	return Rotation{Seq: seq, OldFP: oldFP, NewFP: newFP, Body: []byte("body"), Sig: []byte("sig"), NewSig: []byte("newsig")}
}

func TestRotationsOldestFirst(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	other := testAccount(t, s, "b@b.c")
	if rows, err := s.Rotations(u.ID); err != nil || len(rows) != 0 {
		t.Fatalf("before any rotation: %v %v", rows, err)
	}
	err := s.RotateKeys(u.ID, nil, func(rt *RotateTx) error {
		if seq, err := rt.LastRotationSeq(); err != nil || seq != 0 {
			t.Errorf("last seq before any rotation = %d, %v", seq, err)
		}
		// Added out of order: reads sort by seq.
		if err := rt.AddRotation(rotationRow(2, "b", "c")); err != nil {
			return err
		}
		return rt.AddRotation(rotationRow(1, "a", "b"))
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.Rotations(u.ID)
	if err != nil || len(rows) != 2 || rows[0].Seq != 1 || rows[1].Seq != 2 {
		t.Fatalf("rotations = %+v, %v", rows, err)
	}
	if rows[0].UserID != u.ID || rows[0].OldFP != "a" || rows[0].NewFP != "b" || string(rows[0].Body) != "body" ||
		string(rows[0].Sig) != "sig" || string(rows[0].NewSig) != "newsig" || rows[0].CreatedAt == "" {
		t.Errorf("row not stored whole: %+v", rows[0])
	}
	if rows, _ := s.Rotations(other.ID); len(rows) != 0 {
		t.Errorf("another user's rotations: %+v", rows)
	}
	// The same seq twice is refused.
	err = s.RotateKeys(u.ID, nil, func(rt *RotateTx) error { return rt.AddRotation(rotationRow(2, "x", "y")) })
	if err == nil {
		t.Error("a second row at seq 2 was accepted")
	}
	// The artifact transaction reads them too.
	a := ownedArtifact(t, s, u)
	err = s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		rows, err := tx.Rotations(u.ID)
		if err != nil || len(rows) != 2 || rows[0].Seq != 1 {
			t.Errorf("ArtifactTx.Rotations = %+v, %v", rows, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRotationsCascadeWithTheUser(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if err := s.RotateKeys(u.ID, nil, func(rt *RotateTx) error { return rt.AddRotation(rotationRow(1, "a", "b")) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM user_rotations`).Scan(&n)
	if n != 0 {
		t.Errorf("%d rotation rows outlived the user", n)
	}
}

func TestRotateKeysMissingUser(t *testing.T) {
	s := testStore(t)
	err := s.RotateKeys("nobody", nil, func(*RotateTx) error { t.Error("fn ran"); return nil })
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestRotateKeysRollsBackWhenFnFails(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	member, err := s.CreateAccount("m@b.c", "Mia", "authhash", testBundle("m"), false)
	if err != nil {
		t.Fatal(err)
	}
	a := ownedArtifact(t, s, u)
	other, err := s.CreateOwnedArtifact("33333333-3333-4333-8333-333333333333", "Other", "", member.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	// u owns a, with an estate copy, and holds a wrap and an open offer on other.
	if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error { return tx.PutEstate(1, []byte("estate-old")) }); err != nil {
		t.Fatal(err)
	}
	if err := s.WithArtifact(other.ID, func(tx *ArtifactTx) error {
		if err := tx.PutWrap(Wrap{UserID: u.ID, Epoch: 1, Wrapped: []byte("w-old"), FP: "old"}); err != nil {
			return err
		}
		return tx.PutOffer(Offer{To: u.ID, By: "admin"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPIKey(APIKey{ID: "k1", UserID: u.ID, SecretHash: "h", MK: []byte("mk")}); err != nil {
		t.Fatal(err)
	}
	before, _ := s.UserByID(u.ID)
	boom := errors.New("boom")
	err = s.RotateKeys(u.ID, []string{a.ID}, func(rt *RotateTx) error {
		if err := rt.SetBundle(testBundle("new")); err != nil {
			return err
		}
		if _, err := rt.PutKeyring(1, []byte("ring")); err != nil {
			return err
		}
		if err := rt.ReplaceHeldWrap(other.ID, 1, []byte("w-new"), "new"); err != nil {
			return err
		}
		at := rt.Artifact(a.ID)
		if _, err := at.Artifact(); err != nil {
			return err
		}
		if err := at.DeleteEstates(); err != nil {
			return err
		}
		if err := at.PutEstate(1, []byte("estate-new")); err != nil {
			return err
		}
		if err := at.PutEstate(2, []byte("estate-new-2")); err != nil {
			return err
		}
		if err := rt.CloseOffersToUser(); err != nil {
			return err
		}
		if err := rt.AddRotation(rotationRow(1, "a", "b")); err != nil {
			return err
		}
		if err := rt.RevokeAPIKeys(); err != nil {
			return err
		}
		if err := rt.BumpTokenVersion(); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	b, _ := s.BundleFor(u.ID)
	if string(b.EK) != "ek-a" {
		t.Errorf("bundle survived a rolled-back rotation: %s", b.EK)
	}
	if rev, _, _ := s.Keyring(u.ID); rev != 0 {
		t.Errorf("keyring rev %d survived", rev)
	}
	if rows, _ := s.Rotations(u.ID); len(rows) != 0 {
		t.Errorf("rotation row survived: %+v", rows)
	}
	if w, _ := s.WrapsFor(other.ID, u.ID); len(w) != 1 || string(w[0].Wrapped) != "w-old" || w[0].FP != "old" {
		t.Errorf("wrap changed despite the rollback: %+v", w)
	}
	if es, _ := s.EstateKeys(a.ID); len(es) != 1 || es[0].Epoch != 1 || string(es[0].Sealed) != "estate-old" {
		t.Errorf("estate copies changed despite the rollback: %+v", es)
	}
	if _, err := s.OpenOffer(other.ID); err != nil {
		t.Errorf("offer closed despite the rollback: %v", err)
	}
	if k, _ := s.APIKeyByID("k1"); k.RevokedAt != "" {
		t.Error("API key revoked despite the rollback")
	}
	if after, _ := s.UserByID(u.ID); after.TokenVersion != before.TokenVersion {
		t.Error("token version moved despite the rollback")
	}
	// The artifact lock was released.
	if err := s.WithArtifact(a.ID, func(*ArtifactTx) error { return nil }); err != nil {
		t.Errorf("artifact still locked: %v", err)
	}
}

func TestRotateKeysHoldsTheArtifactLock(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	a := ownedArtifact(t, s, u)
	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error)
	go func() {
		done <- s.RotateKeys(u.ID, []string{a.ID, a.ID}, func(*RotateTx) error { // a duplicate id must not self-deadlock
			close(inside)
			<-release
			return nil
		})
	}()
	<-inside
	under := make(chan error)
	go func() { under <- s.UnderEpoch(a.ID, 0, func() {}) }()
	select {
	case <-under:
		t.Fatal("UnderEpoch ran while RotateKeys held the artifact lock")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-under; err != nil {
		t.Fatal(err)
	}
}

func TestRotateTxReadsAndWrites(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	member, err := s.CreateAccount("m@b.c", "Mia", "authhash", testBundle("m"), false)
	if err != nil {
		t.Fatal(err)
	}
	mb := testBundle("m")
	mfp := hex.EncodeToString(e2e.Fingerprint(mb.X25519Pub, mb.Ed25519Pub))
	a := ownedArtifact(t, s, u)
	other, err := s.CreateOwnedArtifact("33333333-3333-4333-8333-333333333333", "Other", "", member.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	// u owns a (with a record) and holds a wrap on other.
	if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error { return tx.AppendRecord(record(1, "", 1, "r1")) }); err != nil {
		t.Fatal(err)
	}
	if err := s.WithArtifact(other.ID, func(tx *ArtifactTx) error {
		if err := tx.PutWrap(Wrap{UserID: u.ID, Epoch: 1, Wrapped: []byte("w1"), FP: "old"}); err != nil {
			return err
		}
		if err := tx.PutOffer(Offer{To: u.ID, By: "admin"}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPIKey(APIKey{ID: "k1", UserID: u.ID, SecretHash: "h", MK: []byte("mk")}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPIKey(APIKey{ID: "k2", UserID: member.ID, SecretHash: "h2", MK: []byte("mk")}); err != nil {
		t.Fatal(err)
	}
	before, _ := s.UserByID(u.ID)

	owned, err := s.OwnedWithRecords(u.ID)
	if err != nil || len(owned) != 1 || owned[0] != a.ID {
		t.Fatalf("Store.OwnedWithRecords = %v, %v", owned, err)
	}
	err = s.RotateKeys(u.ID, []string{a.ID}, func(rt *RotateTx) error {
		ku, err := rt.User()
		if err != nil || ku.ID != u.ID || ku.FP == "" {
			t.Errorf("User = %+v, %v", ku, err)
		}
		b, err := rt.Bundle()
		if err != nil || string(b.EK) != "ek-a" {
			t.Errorf("Bundle = %+v, %v", b, err)
		}
		if ids, err := rt.OwnedWithRecords(); err != nil || len(ids) != 1 || ids[0] != a.ID {
			t.Errorf("OwnedWithRecords = %v, %v", ids, err)
		}
		held, err := rt.HeldWraps()
		if err != nil || len(held) != 1 || held[0].ArtifactID != other.ID || held[0].FP != "old" || held[0].Epoch != 1 {
			t.Errorf("HeldWraps = %+v, %v", held, err)
		}
		if used, err := rt.OtherUserHasFP(ku.FP); err != nil || used {
			t.Errorf("OtherUserHasFP(own) = %v, %v", used, err)
		}
		if used, err := rt.OtherUserHasFP(mfp); err != nil || !used {
			t.Errorf("OtherUserHasFP(member's) = %v, %v", used, err)
		}
		if err := rt.SetBundle(testBundle("new")); err != nil {
			return err
		}
		if cur, err := rt.PutKeyring(2, []byte("x")); !errors.Is(err, ErrStale) || cur != 0 {
			t.Errorf("keyring rev 2 first: %d %v", cur, err)
		}
		if _, err := rt.PutKeyring(1, []byte("one")); err != nil {
			return err
		}
		if cur, err := rt.PutKeyring(1, []byte("x")); !errors.Is(err, ErrStale) || cur != 1 {
			t.Errorf("keyring rev 1 again: %d %v", cur, err)
		}
		if _, err := rt.PutKeyring(2, []byte("two")); err != nil {
			return err
		}
		if err := rt.ReplaceHeldWrap(other.ID, 1, []byte("w2"), "new"); err != nil {
			return err
		}
		if err := rt.AddRotation(rotationRow(1, ku.FP, "new")); err != nil {
			return err
		}
		if err := rt.RevokeAPIKeys(); err != nil {
			return err
		}
		if err := rt.CloseOffersToUser(); err != nil {
			return err
		}
		if err := rt.BumpTokenVersion(); err != nil {
			return err
		}
		if _, err := rt.Artifact(a.ID).LatestRecord(); err != nil {
			t.Errorf("Artifact(a).LatestRecord: %v", err)
		}
		if used, err := rt.OtherUserHasFP(ku.FP); err != nil || used {
			t.Errorf("OtherUserHasFP after the bundle changed: %v %v", used, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := s.BundleFor(u.ID); string(b.EK) != "ek-new" {
		t.Errorf("bundle not replaced: %s", b.EK)
	}
	if rev, sealed, _ := s.Keyring(u.ID); rev != 2 || string(sealed) != "two" {
		t.Errorf("keyring = %d %q", rev, sealed)
	}
	if w, _ := s.WrapsFor(other.ID, u.ID); len(w) != 1 || string(w[0].Wrapped) != "w2" || w[0].FP != "new" {
		t.Errorf("wrap = %+v", w)
	}
	if k, _ := s.APIKeyByID("k1"); k.RevokedAt == "" {
		t.Error("API key not revoked")
	}
	if k, _ := s.APIKeyByID("k2"); k.RevokedAt != "" {
		t.Error("another user's API key was revoked")
	}
	if _, err := s.OpenOffer(other.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("offer to the user still open: %v", err)
	}
	if after, _ := s.UserByID(u.ID); after.TokenVersion != before.TokenVersion+1 {
		t.Errorf("token version %d -> %d", before.TokenVersion, after.TokenVersion)
	}
}
