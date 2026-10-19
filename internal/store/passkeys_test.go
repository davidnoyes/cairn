package store

import (
	"errors"
	"testing"
	"time"
)

func TestPasskeys(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	other := testAccount(t, s, "other@b.c")
	p := Passkey{ID: "cred1", UserID: u.ID, Name: "laptop", PublicKey: []byte("spki"), Alg: -7, MK: []byte("mk")}
	if err := s.CreatePasskey(p); err != nil {
		t.Fatal(err)
	}
	got, err := s.PasskeyByID("cred1")
	if err != nil || got.UserID != u.ID || got.Name != "laptop" || string(got.PublicKey) != "spki" ||
		got.Alg != -7 || got.SignCount != 0 || string(got.MK) != "mk" || got.CreatedAt == "" || got.LastUsedAt != "" {
		t.Fatalf("PasskeyByID: %v %+v", err, got)
	}
	if _, err := s.PasskeyByID("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown id: %v, want ErrNotFound", err)
	}

	// The credential ID is unique across users.
	dup := p
	dup.UserID = other.ID
	if err := s.CreatePasskey(dup); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate id: %v, want ErrExists", err)
	}

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.TouchPasskey("cred1", 7, at); err != nil {
		t.Fatal(err)
	}
	got, _ = s.PasskeyByID("cred1")
	if got.SignCount != 7 || got.LastUsedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("after touch: %+v", got)
	}
	if err := s.TouchPasskey("nope", 1, at); !errors.Is(err, ErrNotFound) {
		t.Errorf("touch of an unknown id: %v, want ErrNotFound", err)
	}

	if list, err := s.ListPasskeys(u.ID); err != nil || len(list) != 1 || list[0].ID != "cred1" {
		t.Errorf("ListPasskeys: %v %+v", err, list)
	}
	if list, err := s.ListPasskeys(other.ID); err != nil || len(list) != 0 {
		t.Errorf("another user's list: %v %+v", err, list)
	}

	if err := s.DeletePasskey(other.ID, "cred1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete by another user: %v, want ErrNotFound", err)
	}
	if err := s.DeletePasskey(u.ID, "cred1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePasskey(u.ID, "cred1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v, want ErrNotFound", err)
	}
}

func TestResetAccountArchivesPasskeys(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	for _, id := range []string{"cred1", "cred2"} {
		if err := s.CreatePasskey(Passkey{ID: id, UserID: u.ID, PublicKey: []byte("spki"), Alg: -7, MK: []byte("mk-" + id)}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := s.BundleFor(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ResetAccount(u.ID, "new-hash", *b, time.Now()); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListPasskeys(u.ID); len(list) != 0 {
		t.Errorf("%d passkeys left after the reset", len(list))
	}
	archives, err := s.Archives(u.ID)
	if err != nil || len(archives) != 1 || len(archives[0].Passkeys) != 2 {
		t.Fatalf("Archives: %v %+v", err, archives)
	}
	got := map[string]string{}
	for _, k := range archives[0].Passkeys {
		got[k.ID] = string(k.MK)
	}
	if got["cred1"] != "mk-cred1" || got["cred2"] != "mk-cred2" {
		t.Errorf("archived passkeys: %v", got)
	}
}
