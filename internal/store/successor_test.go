package store

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

func rec(body string) Envelope { return Envelope{Body: []byte(body), Sig: []byte("sig"), Signer: "u"} }

func nominate(t *testing.T, s *Store, user, successor *User, seq int) {
	t.Helper()
	if _, _, err := s.Nominate(user.ID, successor.ID, seq, rec("nominate"), []byte("wrapped"), t0); err != nil {
		t.Fatal(err)
	}
}

func TestSuccessorReleaseIsComputed(t *testing.T) {
	sc := &Successor{RequestedAt: formatTime(t0)}
	if sc.ReleaseAt() != t0.Add(14*24*time.Hour) {
		t.Errorf("ReleaseAt = %v", sc.ReleaseAt())
	}
	for _, c := range []struct {
		at   time.Duration
		want bool
	}{
		{0, false}, {14*24*time.Hour - time.Second, false}, {14 * 24 * time.Hour, true}, {15 * 24 * time.Hour, true},
	} {
		if got := sc.Released(t0.Add(c.at)); got != c.want {
			t.Errorf("Released at +%v = %v, want %v", c.at, got, c.want)
		}
	}
	none := &Successor{}
	if none.Released(t0.Add(365*24*time.Hour)) || !none.ReleaseAt().IsZero() {
		t.Error("a nomination with no request is never released")
	}
	// A time that does not parse never releases: release is access, so a
	// fault must deny it.
	bad := &Successor{RequestedAt: "2026-03-01 09:00:00"}
	if bad.Released(t0.Add(365 * 24 * time.Hour)) {
		t.Error("an unparsable requestedAt released the successor")
	}
}

func TestARequestFromAReplacedSuccessorIsRefused(t *testing.T) {
	s := testStore(t)
	a, b, c := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y"), testAccount(t, s, "c@x.y")
	nominate(t, s, a, b, 1)
	// b read the nomination, then a replaced b with c before b's request
	// landed. It must not become c's request.
	if _, _, err := s.Nominate(a.ID, c.ID, 2, rec("nominate c"), []byte("wrapped"), t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestSuccession(a.ID, b.ID, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("request from the replaced successor: %v, want ErrNotFound", err)
	}
	if sc, err := s.SuccessorOf(a.ID); err != nil || sc.SuccessorID != c.ID || sc.Requested() {
		t.Errorf("c's nomination after b's request: %+v, %v", sc, err)
	}
	if err := s.RequestSuccession(a.ID, c.ID, t0); err != nil {
		t.Errorf("c's own request: %v", err)
	}
}

func TestNominateReplaceAndSeq(t *testing.T) {
	s := testStore(t)
	a, b, c := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y"), testAccount(t, s, "c@x.y")
	if _, err := s.SuccessorOf(a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before nominating: %v", err)
	}
	// A seq other than one more than the last is stale, and reports the last.
	if _, last, err := s.Nominate(a.ID, b.ID, 2, rec("x"), []byte("w"), t0); !errors.Is(err, ErrStale) || last != 0 {
		t.Fatalf("seq 2 first: last %d, %v", last, err)
	}
	nominate(t, s, a, b, 1)
	sc, err := s.SuccessorOf(a.ID)
	if err != nil || sc.SuccessorID != b.ID || sc.Seq != 1 || string(sc.Wrapped) != "wrapped" || string(sc.Record.Body) != "nominate" ||
		sc.NominatedAt != formatTime(t0) || sc.Requested() {
		t.Fatalf("nomination = %+v, %v", sc, err)
	}
	if err := s.RequestSuccession(a.ID, b.ID, t0); err != nil {
		t.Fatal(err)
	}
	// Replacing ends the request and reports the old nomination.
	prev, _, err := s.Nominate(a.ID, c.ID, 2, rec("replace"), []byte("w2"), t0.Add(time.Hour))
	if err != nil || prev == nil || prev.SuccessorID != b.ID || !prev.Requested() {
		t.Fatalf("replace: prev %+v, %v", prev, err)
	}
	if sc, _ = s.SuccessorOf(a.ID); sc.SuccessorID != c.ID || sc.Requested() || string(sc.Record.Body) != "replace" {
		t.Errorf("after replacing: %+v", sc)
	}
	if _, last, err := s.Nominate(a.ID, b.ID, 2, rec("x"), []byte("w"), t0); !errors.Is(err, ErrStale) || last != 2 {
		t.Errorf("replayed seq: last %d, %v", last, err)
	}
	if n, _ := s.LastSuccessorSeq(a.ID); n != 2 {
		t.Errorf("last seq = %d", n)
	}
	if got, err := s.SuccessionsTo(b.ID); err != nil || len(got) != 0 {
		t.Errorf("to the old successor: %v, %v", got, err)
	}
	if got, err := s.SuccessionsTo(c.ID); err != nil || len(got) != 1 || got[0].UserID != a.ID {
		t.Errorf("to the new successor: %v, %v", got, err)
	}
}

func TestRemoveKeepsSeqGoing(t *testing.T) {
	s := testStore(t)
	a, b := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y")
	if _, _, err := s.RemoveSuccessor(a.ID, 1, rec("remove"), t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove with none: %v", err)
	}
	nominate(t, s, a, b, 1)
	if _, last, err := s.RemoveSuccessor(a.ID, 3, rec("remove"), t0); !errors.Is(err, ErrStale) || last != 1 {
		t.Fatalf("remove at the wrong seq: last %d, %v", last, err)
	}
	prev, seq, err := s.RemoveSuccessor(a.ID, 2, rec("remove"), t0)
	if err != nil || seq != 2 || prev.SuccessorID != b.ID {
		t.Fatalf("remove: %+v %d %v", prev, seq, err)
	}
	if _, err := s.SuccessorOf(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after removal: %v", err)
	}
	// The next nomination continues the numbering.
	nominate(t, s, a, b, 3)
}

func TestAReleasedNominationCannotBeReplacedOrRemoved(t *testing.T) {
	s := testStore(t)
	a, b, c := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y"), testAccount(t, s, "c@x.y")
	nominate(t, s, a, b, 1)
	if err := s.RequestSuccession(a.ID, b.ID, t0); err != nil {
		t.Fatal(err)
	}
	// One second short of 14 days, both still work.
	if _, _, err := s.Nominate(a.ID, c.ID, 2, rec("replace"), []byte("w"), t0.Add(SuccessionWait-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestSuccession(a.ID, c.ID, t0); err != nil {
		t.Fatal(err)
	}
	released := t0.Add(SuccessionWait)
	if _, _, err := s.Nominate(a.ID, b.ID, 3, rec("replace"), []byte("w"), released); !errors.Is(err, ErrReleased) {
		t.Errorf("replace at release: %v", err)
	}
	if _, _, err := s.RemoveSuccessor(a.ID, 3, rec("remove"), released); !errors.Is(err, ErrReleased) {
		t.Errorf("remove at release: %v", err)
	}
	if sc, err := s.SuccessorOf(a.ID); err != nil || sc.SuccessorID != c.ID {
		t.Errorf("the nomination changed: %+v, %v", sc, err)
	}
}

func TestRequestAndRefuse(t *testing.T) {
	s := testStore(t)
	a, b := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y")
	if err := s.RequestSuccession(a.ID, b.ID, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("request with no nomination: %v", err)
	}
	nominate(t, s, a, b, 1)
	if _, err := s.RefuseSuccession(a.ID, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("refuse with no request: %v", err)
	}
	if err := s.RequestSuccession(a.ID, b.ID, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestSuccession(a.ID, b.ID, t0.Add(time.Hour)); !errors.Is(err, ErrExists) {
		t.Errorf("second request: %v", err)
	}
	if err := s.DeactivateUser(a.ID, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.UserByID(a.ID); !u.Disabled {
		t.Error("DeactivateUser left the account active")
	}
	if err := s.SetUserDisabled(a.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := s.DeactivateUser(a.ID, t0.Add(2*time.Hour)); err != nil { // keeps the first
		t.Fatal(err)
	}
	if sc, _ := s.SuccessorOf(a.ID); sc.DeactivatedAt != formatTime(t0.Add(time.Hour)) {
		t.Errorf("deactivatedAt = %q", sc.DeactivatedAt)
	}
	// 14 days to the second is a release, which cannot be refused.
	if _, err := s.RefuseSuccession(a.ID, t0.Add(SuccessionWait)); !errors.Is(err, ErrReleased) {
		t.Errorf("refuse at release: %v", err)
	}
	prev, err := s.RefuseSuccession(a.ID, t0.Add(SuccessionWait-time.Second))
	if err != nil || prev.RequestedAt != formatTime(t0) || prev.DeactivatedAt == "" {
		t.Fatalf("refuse: %+v, %v", prev, err)
	}
	sc, err := s.SuccessorOf(a.ID)
	if err != nil || sc.Requested() || sc.DeactivatedAt != "" {
		t.Errorf("after refusing the nomination stays and the request goes: %+v, %v", sc, err)
	}
	// A deactivation with nothing pending records nothing.
	if err := s.DeactivateUser(a.ID, t0); err != nil {
		t.Fatal(err)
	}
	if sc, _ := s.SuccessorOf(a.ID); sc.DeactivatedAt != "" {
		t.Errorf("deactivatedAt with no request: %q", sc.DeactivatedAt)
	}
}

func TestTwoRequestsAtOnceRecordOne(t *testing.T) {
	s := testStore(t)
	a, b := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y")
	nominate(t, s, a, b, 1)
	errs := make(chan error, 8)
	for i := 0; i < cap(errs); i++ {
		go func(i int) { errs <- s.RequestSuccession(a.ID, b.ID, t0.Add(time.Duration(i)*time.Second)) }(i)
	}
	var ok, exists int
	for i := 0; i < cap(errs); i++ {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrExists):
			exists++
		default:
			t.Errorf("request: %v", err)
		}
	}
	if ok != 1 || exists != cap(errs)-1 {
		t.Errorf("%d recorded and %d refused, want 1 and %d", ok, exists, cap(errs)-1)
	}
}

func TestDeactivateUnknownUser(t *testing.T) {
	if err := testStore(t).DeactivateUser("nobody", t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeactivateUser(nobody) = %v, want ErrNotFound", err)
	}
}

func TestDeletingEitherUserRemovesTheNomination(t *testing.T) {
	s := testStore(t)
	a, b, c := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y"), testAccount(t, s, "c@x.y")
	nominate(t, s, a, b, 1)
	nominate(t, s, c, b, 1)
	if err := s.DeleteUser(b.ID); err != nil {
		t.Fatal(err)
	}
	for _, u := range []*User{a, c} {
		if _, err := s.SuccessorOf(u.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("nomination of %s survived the successor's deletion: %v", u.Email, err)
		}
	}
	nominate(t, s, a, c, 2) // the nominator's seq goes on
	if err := s.DeleteUser(a.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	for _, table := range []string{"successors", "successor_records"} {
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE user_id = ?`, a.ID).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s rows of a deleted user: %d, %v", table, n, err)
		}
	}
}

func TestResetArchivesTheNomination(t *testing.T) {
	s := testStore(t)
	a, b := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y")
	// A reset with no nomination archives none.
	if err := s.ResetAccount(a.ID, "h", testBundle("n"), t0); err != nil {
		t.Fatal(err)
	}
	if arch, _ := s.Archives(a.ID); len(arch) != 1 || arch[0].Successor != nil {
		t.Fatalf("archive with no nomination: %+v", arch)
	}
	nominate(t, s, a, b, 1)
	if err := s.RequestSuccession(a.ID, b.ID, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetAccount(a.ID, "h", testBundle("m"), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SuccessorOf(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the nomination survived a reset: %v", err)
	}
	arch, err := s.Archives(a.ID)
	if err != nil || len(arch) != 2 {
		t.Fatalf("archives: %+v, %v", arch, err)
	}
	var got *ArchivedSuccessor
	for _, x := range arch {
		if x.Successor != nil {
			got = x.Successor
		}
	}
	if got == nil || got.Successor != b.ID || string(got.Wrapped) != "wrapped" || got.Seq != 1 {
		t.Errorf("archived nomination: %+v", got)
	}
	if n, _ := s.LastSuccessorSeq(a.ID); n != 1 {
		t.Errorf("the record history was lost: last seq %d", n)
	}
}

func TestRotationDeletesTheNomination(t *testing.T) {
	s := testStore(t)
	a, b := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y")
	nominate(t, s, a, b, 1)
	if err := s.RotateKeys(a.ID, nil, func(rt *RotateTx) error { return rt.DeleteSuccessor() }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SuccessorOf(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after rotation: %v", err)
	}
	if n, _ := s.LastSuccessorSeq(a.ID); n != 1 {
		t.Errorf("last seq = %d, want the history kept", n)
	}
}

func TestAccessStateCarriesTheOwnersNomination(t *testing.T) {
	s := testStore(t)
	owner, b, c := testAccount(t, s, "o@x.y"), testAccount(t, s, "b@x.y"), testAccount(t, s, "c@x.y")
	art := ownedArtifact(t, s, owner)
	nominate(t, s, owner, b, 1)
	if st, err := s.AccessState(art.ID, b.ID); err != nil || st.OwnerSuccessor == nil || st.OwnerSuccessor.UserID != owner.ID {
		t.Errorf("the successor's state: %+v, %v", st, err)
	}
	if st, err := s.AccessState(art.ID, c.ID); err != nil || st.OwnerSuccessor != nil {
		t.Errorf("a stranger's state: %+v, %v", st, err)
	}
	// An artifact b owns says nothing about owner's nomination of b.
	other := testAccount(t, s, "d@x.y")
	nominate(t, s, b, other, 1)
	if st, err := s.AccessState(art.ID, other.ID); err != nil || st.OwnerSuccessor != nil {
		t.Errorf("the successor of a member's nomination: %+v, %v", st, err)
	}
}

func TestNoticeEmail(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@x.y")
	if err := s.ConfirmNoticeEmail(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("confirm with nothing pending: %v", err)
	}
	if err := s.SetNoticeEmailPending(a.ID, " Notice@X.Y "); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.UserByID(a.ID); u.NoticeEmail != "" {
		t.Errorf("a pending address is in use: %q", u.NoticeEmail)
	}
	if err := s.ConfirmNoticeEmail(a.ID); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.UserByID(a.ID); u.NoticeEmail != "notice@x.y" {
		t.Errorf("verified address = %q", u.NoticeEmail)
	}
	// A new pending address leaves the verified one in use.
	if err := s.SetNoticeEmailPending(a.ID, "other@x.y"); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.UserByID(a.ID); u.NoticeEmail != "notice@x.y" {
		t.Errorf("verified address after a pending one = %q", u.NoticeEmail)
	}
	if err := s.ClearNoticeEmail(a.ID); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.UserByID(a.ID); u.NoticeEmail != "" {
		t.Errorf("cleared address = %q", u.NoticeEmail)
	}
	if err := s.ConfirmNoticeEmail(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("clearing left a pending address: %v", err)
	}
}

func TestLatestSuccessorRecord(t *testing.T) {
	s := testStore(t)
	a, b := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y")
	art := ownedArtifact(t, s, a)
	read := func() (*Envelope, error) {
		var e *Envelope
		err := s.WithArtifact(art.ID, func(tx *ArtifactTx) (err error) {
			e, err = tx.LatestSuccessorRecord(a.ID)
			return
		})
		return e, err
	}
	if _, err := read(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("before any record: %v", err)
	}
	nominate(t, s, a, b, 1)
	if _, _, err := s.RemoveSuccessor(a.ID, 2, rec("remove"), t0); err != nil {
		t.Fatal(err)
	}
	if e, err := read(); err != nil || string(e.Body) != "remove" {
		t.Errorf("latest record: %+v, %v", e, err)
	}
	err := s.WithArtifact(art.ID, func(tx *ArtifactTx) error {
		if _, err := tx.SuccessorOf(a.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("tx.SuccessorOf after removal: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
