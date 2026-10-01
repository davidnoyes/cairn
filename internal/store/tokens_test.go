package store

import (
	"errors"
	"testing"
	"time"
)

func TestTokenLifecycle(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(24 * time.Hour)
	if err := s.CreateToken("hash1", u.ID, "verify", expires); err != nil {
		t.Fatal(err)
	}

	peeked, err := s.PeekToken("hash1", "verify", issued)
	if err != nil || peeked.UserID != u.ID {
		t.Fatalf("PeekToken: %v %+v", err, peeked)
	}
	// Peeking does not consume it.
	if _, err := s.PeekToken("hash1", "verify", issued); err != nil {
		t.Fatalf("second PeekToken: %v", err)
	}
	// Wrong kind doesn't match.
	if _, err := s.PeekToken("hash1", "reset", issued); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for wrong kind, got %v", err)
	}

	used, err := s.UseToken("hash1", "verify", issued)
	if err != nil || used.UserID != u.ID {
		t.Fatalf("UseToken: %v %+v", err, used)
	}
	// A second use fails.
	if _, err := s.UseToken("hash1", "verify", issued); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on reuse, got %v", err)
	}
	if _, err := s.PeekToken("hash1", "verify", issued); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound peeking a used token, got %v", err)
	}
}

func TestTokenExpiryBoundary(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	expires := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.CreateToken("hash1", u.ID, "reset", expires); err != nil {
		t.Fatal(err)
	}
	// At the exact expiry instant, expires_at > now is false: already expired.
	if _, err := s.PeekToken("hash1", "reset", expires); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound exactly at expiry, got %v", err)
	}
	if _, err := s.UseToken("hash1", "reset", expires); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound using exactly at expiry, got %v", err)
	}
	// One second before expiry it is still valid.
	beforeExpiry := expires.Add(-time.Second)
	if _, err := s.PeekToken("hash1", "reset", beforeExpiry); err != nil {
		t.Errorf("expected valid token before expiry, got %v", err)
	}
}

func TestDeleteTokens(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	expires := time.Now().Add(time.Hour)
	if err := s.CreateToken("hash1", u.ID, "verify", expires); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken("hash2", u.ID, "reset", expires); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTokens(u.ID, "verify"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeekToken("hash1", "verify", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after DeleteTokens, got %v", err)
	}
	// The other kind is untouched.
	if _, err := s.PeekToken("hash2", "reset", time.Now()); err != nil {
		t.Errorf("unrelated kind should survive DeleteTokens: %v", err)
	}
}
