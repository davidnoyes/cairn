package client

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveGroupMatchesAnIDShapedRefByIDOnly(t *testing.T) {
	s := newSharing(t)
	one, err := s.ada.CreateGroup("Reviewers", nil)
	if err != nil {
		t.Fatal(err)
	}
	// A group named after a user's ID never answers to it.
	const victim = "0b3f1a52-7c4e-4d8a-9b61-2f5c8e1d7a90"
	named, err := s.ada.CreateGroup(victim, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.ResolveGroup(victim); !errors.Is(err, ErrNoGroup) {
		t.Errorf("an ID-shaped name: %v, want ErrNoGroup", err)
	}
	if g, err := s.ada.ResolveGroup(named.ID); err != nil || g.ID != named.ID {
		t.Errorf("its own ID = %+v, %v", g, err)
	}
	if g, err := s.ada.ResolveGroup(one.ID); err != nil || g.ID != one.ID {
		t.Errorf("an ID = %+v, %v", g, err)
	}
	if g, err := s.ada.ResolveGroup("Reviewers"); err != nil || g.ID != one.ID {
		t.Errorf("a name = %+v, %v", g, err)
	}
	if IsID("Reviewers") || !IsID(victim) || IsID(strings.ToUpper(victim)) {
		t.Error("IsID misjudges its input")
	}
}

// A user's ID that names a group must still reach the user in Share and
// Unshare: the group commands fail with ErrNoGroup, so the caller falls back.
func TestShareGroupAndUnshareGroupRefuseAUserIDThatOnlyANameMatches(t *testing.T) {
	w := newGroupWorld(t, "cat@example.com")
	dir, err := w.ada.Directory()
	if err != nil {
		t.Fatal(err)
	}
	cat, err := FindUser(dir, "cat@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.CreateGroup(cat.ID, []string{"dan@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.artifact, cat.ID, "viewer", false); !errors.Is(err, ErrNoGroup) {
		t.Errorf("ShareGroup by a user ID a group is named after: %v, want ErrNoGroup", err)
	}
	if _, err := w.ada.UnshareGroup(w.artifact, cat.ID); !errors.Is(err, ErrNoGroup) {
		t.Errorf("UnshareGroup by a user ID a group is named after: %v, want ErrNoGroup", err)
	}
}
