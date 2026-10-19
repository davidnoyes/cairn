package store

import (
	"errors"
	"testing"
	"time"
)

func TestGoogleProofLifecycle(t *testing.T) {
	s := testStore(t)
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := s.CreateGoogleProof("h1", "ada@example.com", "Ada", issued.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	p, err := s.PeekGoogleProof("h1", issued)
	if err != nil || p.Email != "ada@example.com" || p.Name != "Ada" {
		t.Fatalf("PeekGoogleProof: %v %+v", err, p)
	}
	if _, err := s.PeekGoogleProof("h1", issued); err != nil {
		t.Fatalf("peeking twice: %v", err)
	}
	if _, err := s.UseGoogleProof("h1", issued); err != nil {
		t.Fatalf("UseGoogleProof: %v", err)
	}
	if _, err := s.UseGoogleProof("h1", issued); !errors.Is(err, ErrNotFound) {
		t.Errorf("second use: %v, want ErrNotFound", err)
	}
	if _, err := s.PeekGoogleProof("h1", issued); !errors.Is(err, ErrNotFound) {
		t.Errorf("peeking a used proof: %v, want ErrNotFound", err)
	}
}

func TestGoogleProofExpiryBoundary(t *testing.T) {
	s := testStore(t)
	expires := time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC)
	if err := s.CreateGoogleProof("h1", "ada@example.com", "", expires); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PeekGoogleProof("h1", expires); !errors.Is(err, ErrNotFound) {
		t.Errorf("peek at expiry: %v, want ErrNotFound", err)
	}
	if _, err := s.UseGoogleProof("h1", expires); !errors.Is(err, ErrNotFound) {
		t.Errorf("use at expiry: %v, want ErrNotFound", err)
	}
	if _, err := s.UseGoogleProof("h1", expires.Add(-time.Second)); err != nil {
		t.Errorf("use a second before expiry: %v", err)
	}
}
