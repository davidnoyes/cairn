package store

import (
	"errors"
	"testing"
	"time"
)

func TestSetPassword(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if err := s.SetPassword(u.ID, "newhash", `{"alg":"argon2id"}`, []byte("newmkpw")); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(u.ID)
	if got.AuthHash != "newhash" || got.TokenVersion != 2 {
		t.Errorf("SetPassword: %+v", got)
	}
	b, err := s.BundleFor(u.ID)
	if err != nil || string(b.MKPassword) != "newmkpw" || string(b.KDF) != `{"alg":"argon2id"}` {
		t.Fatalf("BundleFor after SetPassword: %v %+v", err, b)
	}
	if err := s.SetPassword("nope", "h", "k", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSetRecovery(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if err := s.SetRecovery(u.ID, []byte("newmkrec")); err != nil {
		t.Fatal(err)
	}
	b, err := s.BundleFor(u.ID)
	if err != nil || string(b.MKRecovery) != "newmkrec" {
		t.Fatalf("BundleFor after SetRecovery: %v %+v", err, b)
	}
	got, _ := s.UserByID(u.ID)
	if got.TokenVersion != 1 {
		t.Errorf("SetRecovery should not bump token_version: %+v", got)
	}
}

func TestResetAccount(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if err := s.CreateAPIKey(APIKey{ID: "kid1", UserID: u.ID, Name: "laptop", SecretHash: "h1", MK: []byte("mk1")}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPIKey(APIKey{ID: "kid2", UserID: u.ID, Name: "phone", SecretHash: "h2", MK: []byte("mk2")}); err != nil {
		t.Fatal(err)
	}

	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := s.ResetAccount(u.ID, "resethash", testBundle("reset"), at); err != nil {
		t.Fatal(err)
	}

	got, _ := s.UserByID(u.ID)
	if got.AuthHash != "resethash" || got.ResetAt != "2026-03-04T05:06:07Z" || got.TokenVersion != 2 {
		t.Errorf("ResetAccount user: %+v", got)
	}
	b, err := s.BundleFor(u.ID)
	if err != nil || string(b.MKPassword) != "mkpw-reset" {
		t.Fatalf("BundleFor after reset: %v %+v", err, b)
	}
	k1, err := s.APIKeyByID("kid1")
	if err != nil || k1.RevokedAt == "" {
		t.Errorf("key kid1 not revoked: %v %+v", err, k1)
	}
	keys, err := s.ListAPIKeys(u.ID)
	if err != nil || len(keys) != 0 {
		t.Errorf("ListAPIKeys after reset should be empty: %v %+v", err, keys)
	}

	archives, err := s.Archives(u.ID)
	if err != nil || len(archives) != 1 {
		t.Fatalf("Archives: %v %+v", err, archives)
	}
	a := archives[0]
	if string(a.Bundle.MKPassword) != "mkpw-a" {
		t.Errorf("archived bundle should hold the pre-reset bundle: %+v", a.Bundle)
	}
	if len(a.APIKeys) != 2 {
		t.Fatalf("archived api keys: %+v", a.APIKeys)
	}
	byID := map[string]string{a.APIKeys[0].ID: string(a.APIKeys[0].MK), a.APIKeys[1].ID: string(a.APIKeys[1].MK)}
	if byID["kid1"] != "mk1" || byID["kid2"] != "mk2" {
		t.Errorf("archived api key MKs: %+v", byID)
	}
}

func TestArchivesNewestFirst(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "a@b.c")
	if err := s.ResetAccount(u.ID, "h1", testBundle("r1"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetAccount(u.ID, "h2", testBundle("r2"), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	archives, err := s.Archives(u.ID)
	if err != nil || len(archives) != 2 {
		t.Fatalf("Archives: %v %+v", err, archives)
	}
	if string(archives[0].Bundle.MKPassword) != "mkpw-r1" {
		t.Errorf("expected newest-first order, got %+v", archives[0].Bundle)
	}
}
