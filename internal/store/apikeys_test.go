package store

import (
	"errors"
	"testing"
	"time"
)

func TestAPIKeys(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	k := APIKey{ID: "kid1", UserID: u.ID, Name: "ci", Device: true, SecretHash: "hash", MK: []byte("mk")}
	if err := s.CreateAPIKey(k); err != nil {
		t.Fatal(err)
	}
	got, err := s.APIKeyByID("kid1")
	if err != nil || got.RevokedAt != "" || !got.Device || string(got.MK) != "mk" {
		t.Fatalf("APIKeyByID: %v %+v", err, got)
	}

	// Duplicate id, even against a since-revoked key, is ErrExists.
	if err := s.CreateAPIKey(APIKey{ID: "kid1", UserID: u.ID, SecretHash: "h2", MK: []byte("mk2")}); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.RevokeAPIKey(u.ID, "kid1", at); err != nil {
		t.Fatal(err)
	}
	got, _ = s.APIKeyByID("kid1")
	if got.RevokedAt == "" {
		t.Error("not revoked")
	}
	if err := s.CreateAPIKey(APIKey{ID: "kid1", UserID: u.ID, SecretHash: "h2", MK: []byte("mk2")}); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists against a revoked id, got %v", err)
	}

	// Revoking twice is ErrNotFound.
	if err := s.RevokeAPIKey(u.ID, "kid1", at); !errors.Is(err, ErrNotFound) {
		t.Errorf("double revoke: %v", err)
	}
}

func TestRevokeAPIKeyWrongOwner(t *testing.T) {
	s := testStore(t)
	owner := testAccount(t, s, "owner@b.c")
	other := testAccount(t, s, "other@b.c")
	if err := s.CreateAPIKey(APIKey{ID: "kid1", UserID: owner.ID, SecretHash: "h", MK: []byte("mk")}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAPIKey(other.ID, "kid1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound revoking someone else's key, got %v", err)
	}
	got, err := s.APIKeyByID("kid1")
	if err != nil || got.RevokedAt != "" {
		t.Errorf("key should be untouched: %v %+v", err, got)
	}
}

func TestListAPIKeys(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if err := s.CreateAPIKey(APIKey{ID: "kid1", UserID: u.ID, Name: "first", SecretHash: "h", MK: []byte("mk")}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPIKey(APIKey{ID: "kid2", UserID: u.ID, Name: "second", SecretHash: "h", MK: []byte("mk")}); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAPIKey(u.ID, "kid1", time.Now()); err != nil {
		t.Fatal(err)
	}
	keys, err := s.ListAPIKeys(u.ID)
	if err != nil || len(keys) != 1 || keys[0].ID != "kid2" {
		t.Fatalf("ListAPIKeys: %v %+v", err, keys)
	}
}

func TestTouchAPIKey(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if err := s.CreateAPIKey(APIKey{ID: "kid1", UserID: u.ID, SecretHash: "h", MK: []byte("mk")}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	s.TouchAPIKey("kid1", at)
	got, err := s.APIKeyByID("kid1")
	if err != nil || got.LastUsedAt != "2026-05-06T07:08:09Z" {
		t.Fatalf("TouchAPIKey: %v %+v", err, got)
	}
}
