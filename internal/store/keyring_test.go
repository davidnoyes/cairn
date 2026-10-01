package store

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestKeyring(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@b.c")
	b := testAccount(t, s, "b@b.c")

	rev, sealed, err := s.Keyring(a.ID)
	if err != nil || rev != 0 || sealed != nil {
		t.Fatalf("before any write: %d %q %v, want 0, nil, nil", rev, sealed, err)
	}
	// The first write must be rev 1.
	if cur, err := s.PutKeyring(a.ID, 2, []byte("x")); !errors.Is(err, ErrStale) || cur != 0 {
		t.Errorf("first write at rev 2: %d %v, want ErrStale with rev 0", cur, err)
	}
	if _, err := s.PutKeyring(a.ID, 1, []byte("one")); err != nil {
		t.Fatal(err)
	}
	for _, r := range []int{0, 1, 3} {
		if cur, err := s.PutKeyring(a.ID, r, []byte("x")); !errors.Is(err, ErrStale) || cur != 1 {
			t.Errorf("write at rev %d: %d %v, want ErrStale with rev 1", r, cur, err)
		}
	}
	if _, err := s.PutKeyring(a.ID, 2, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if rev, sealed, _ := s.Keyring(a.ID); rev != 2 || string(sealed) != "two" {
		t.Errorf("after two writes: %d %q", rev, sealed)
	}
	// Another user's keyring is untouched.
	if rev, sealed, _ := s.Keyring(b.ID); rev != 0 || sealed != nil {
		t.Errorf("b's keyring: %d %q", rev, sealed)
	}
}

// TestPutKeyringConcurrentSameRev races writers at the same next rev: exactly
// one wins, and every other gets ErrStale.
func TestPutKeyringConcurrentSameRev(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@b.c")
	if _, err := s.PutKeyring(a.ID, 1, []byte("one")); err != nil {
		t.Fatal(err)
	}
	const writers = 16
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.PutKeyring(a.ID, 2, []byte{byte(i)})
		}()
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrStale):
			t.Errorf("a losing writer got %v, want ErrStale", err)
		}
	}
	if won != 1 {
		t.Errorf("%d writers won rev 2, want exactly 1", won)
	}
	if rev, _, _ := s.Keyring(a.ID); rev != 2 {
		t.Errorf("rev = %d, want 2", rev)
	}
}

// TestResetAccountDeletesKeyring: a reset without the recovery code changes
// MK, so the keyring sealed under the old one can never open again. It goes
// with the reset, and another user's stays.
func TestResetAccountDeletesKeyring(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@b.c")
	b := testAccount(t, s, "b@b.c")
	for _, u := range []*User{a, b} {
		if _, err := s.PutKeyring(u.ID, 1, []byte("sealed-"+u.ID)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ResetAccount(a.ID, "resethash", testBundle("reset"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if rev, sealed, err := s.Keyring(a.ID); err != nil || rev != 0 || sealed != nil {
		t.Errorf("a's keyring after a reset: %d %q %v, want 0, nil, nil", rev, sealed, err)
	}
	if _, err := s.PutKeyring(a.ID, 1, []byte("fresh")); err != nil {
		t.Errorf("first write after a reset: %v", err)
	}
	if rev, sealed, _ := s.Keyring(b.ID); rev != 1 || string(sealed) != "sealed-"+b.ID {
		t.Errorf("b's keyring after a's reset: %d %q, want untouched", rev, sealed)
	}
}
