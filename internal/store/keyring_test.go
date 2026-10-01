package store

import (
	"errors"
	"testing"
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
