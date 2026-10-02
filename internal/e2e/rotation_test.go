package e2e

import (
	"errors"
	"testing"
)

// The rotation cases in rotation_vectors_test.go are the main tests of
// FollowRotations and RotationLinker; these check what a vector cannot say.

func TestFollowRotationsOfNoRotationHasNoKeys(t *testing.T) {
	r := newRotGens(t)
	got, err := FollowRotations("u-bob", nil, r.pin(r.g[0]))
	if err != nil {
		t.Fatal(err)
	}
	if got != (RotationResult{FP: r.g[0].fp}) {
		t.Errorf("got %+v, want only the pinned fp", got)
	}
}

func TestFollowRotationsForkIsNotAChainError(t *testing.T) {
	r := newRotGens(t)
	recs := []Envelope{r.rec(1, r.g[0], r.g[1])}
	p := r.pinAt(r.g[1], 1, recs[0])
	p.RotHead = hex64("elsewhere")
	_, err := FollowRotations("u-bob", recs, p)
	if !errors.Is(err, ErrRotationFork) || errors.Is(err, ErrChain) {
		t.Errorf("err = %v, want ErrRotationFork and not ErrChain", err)
	}
}

func TestRotationLinkerWithNoRecordsLinksOnlyEqualFPs(t *testing.T) {
	r := newRotGens(t)
	link := RotationLinker(nil)
	if !link("u-bob", r.g[0].fp, r.g[0].fp) {
		t.Error("equal fingerprints must link")
	}
	if link("u-bob", r.g[0].fp, r.g[1].fp) {
		t.Error("different fingerprints must not link without records")
	}
}
