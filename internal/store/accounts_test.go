package store

import (
	"errors"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func TestCreateAccount(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateAccount(" Ada@Example.com ", "Ada", "authhash", testBundle("a"), true)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == "" || u.Email != "ada@example.com" || u.TokenVersion != 1 || u.VerifiedAt != "" {
		t.Fatalf("unexpected user: %+v", u)
	}

	got, err := s.UserByEmail(" ADA@EXAMPLE.COM ")
	if err != nil || got.ID != u.ID {
		t.Fatalf("UserByEmail: %v %+v", err, got)
	}
	b, err := s.BundleFor(u.ID)
	if err != nil || string(b.MKPassword) != "mkpw-a" {
		t.Fatalf("BundleFor: %v %+v", err, b)
	}
}

func TestCreateAccountReplacesUnverified(t *testing.T) {
	s := testStore(t)
	first, err := s.CreateAccount("a@b.c", "First", "hash1", testBundle("1"), false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateAccount("A@B.C", "Second", "hash2", testBundle("2"), false)
	if err != nil {
		t.Fatalf("replacing unverified account: %v", err)
	}
	if second.ID == first.ID {
		t.Error("expected a fresh id for the replacement account")
	}
	got, err := s.UserByEmail("a@b.c")
	if err != nil || got.ID != second.ID || got.Name != "Second" {
		t.Fatalf("UserByEmail after replace: %v %+v", err, got)
	}
}

// TestCreateAccountFoldsASCIIOnly pins addresses to the wire spec's
// normalize: only ASCII letters fold, so accounts that differ by a Unicode
// case are distinct, as their salts already are.
func TestCreateAccountFoldsASCIIOnly(t *testing.T) {
	s := testStore(t)
	want := e2e.NormalizeEmail("ÉLAN@Example.com") // "Élan@example.com"
	u, err := s.CreateAccount("ÉLAN@Example.com", "Upper", "hash", testBundle("u"), false)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != want {
		t.Errorf("stored email = %q, want %q", u.Email, want)
	}
	got, err := s.UserByEmail("ÉLAN@EXAMPLE.COM")
	if err != nil || got.ID != u.ID || got.Email != want {
		t.Fatalf("UserByEmail(ÉLAN@EXAMPLE.COM) = %v %+v, want %s as %q", err, got, u.ID, want)
	}

	other, err := s.CreateAccount("élan@example.com", "Lower", "hash", testBundle("l"), false)
	if err != nil {
		t.Fatal(err)
	}
	if other.ID == u.ID {
		t.Fatal("élan@example.com reused the ÉLAN@Example.com account")
	}
	if _, err := s.UserByID(u.ID); err != nil {
		t.Errorf("élan@example.com replaced the ÉLAN@Example.com account: %v", err)
	}
	if got, err := s.UserByEmail("élan@example.com"); err != nil || got.ID != other.ID {
		t.Errorf("UserByEmail(élan@example.com) = %v %+v, want %s", err, got, other.ID)
	}
}

func TestCreateAccountVerifiedConflict(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if _, err := s.CreateAccount("A@B.C", "Dup", "hash", testBundle("x"), false); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	// nothing changed
	got, err := s.UserByEmail("a@b.c")
	if err != nil || got.ID != u.ID || got.Name != "Alice" {
		t.Fatalf("account mutated after conflicting signup: %v %+v", err, got)
	}
}

func TestListUsersAndCount(t *testing.T) {
	s := testStore(t)
	testAccount(t, s, "verified@b.c")
	if _, err := s.CreateAccount("unverified@b.c", "Bob", "hash", testBundle("u"), false); err != nil {
		t.Fatal(err)
	}
	n, err := s.CountUsers()
	if err != nil || n != 2 {
		t.Fatalf("CountUsers: %v %d", err, n)
	}
	verified, err := s.ListUsers(false)
	if err != nil || len(verified) != 1 {
		t.Fatalf("ListUsers(false): %v %+v", err, verified)
	}
	all, err := s.ListUsers(true)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListUsers(true): %v %+v", err, all)
	}
}

func TestSetUserAdminDisabledDelete(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if err := s.SetUserAdmin(u.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(u.ID)
	if !got.IsAdmin {
		t.Error("SetUserAdmin did not take effect")
	}
	if err := s.SetUserDisabled(u.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ = s.UserByID(u.ID)
	if !got.Disabled || got.TokenVersion != 2 {
		t.Errorf("SetUserDisabled: %+v", got)
	}

	// Cascade: deleting the user removes its bundle and API keys.
	if err := s.CreateAPIKey(APIKey{ID: "kid1", UserID: u.ID, Name: "k", SecretHash: "h", MK: []byte("mk")}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByID(u.ID); !errors.Is(err, ErrNotFound) {
		t.Error("user not deleted")
	}
	if _, err := s.BundleFor(u.ID); !errors.Is(err, ErrNotFound) {
		t.Error("bundle not cascaded")
	}
	if _, err := s.APIKeyByID("kid1"); !errors.Is(err, ErrNotFound) {
		t.Error("api key not cascaded")
	}

	if err := s.DeleteUser("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMarkVerified(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateAccount("a@b.c", "Alice", "hash", testBundle("a"), false)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.MarkVerified(u.ID, at); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(u.ID)
	if got.VerifiedAt != "2026-01-02T03:04:05Z" {
		t.Errorf("VerifiedAt = %q", got.VerifiedAt)
	}
}
