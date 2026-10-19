package client

import (
	"errors"
	"slices"
	"testing"
)

// badWrap is a wrap that does not open.
func badWrap() []byte { return make([]byte, 81) }

// An epoch the owner cannot read cannot be wrapped to a member a record adds:
// a member whose keys changed needs every epoch, and the owner's client says
// which one is unreadable before it writes.
func TestOwnerRelistingAMemberInANewEpochNeedsEveryEpoch(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Unshare(w.artifact, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	// Cat's keys change, so demoting them lists them again under the new
	// keys, in a new epoch that wraps every epoch to them.
	resetUser(t, w, "cat@example.com", &w.cat)
	ada := ownerKeysRewritten(t, w.ada, w.artifact, 2, badWrap)
	memberRows(t, ada, w.artifact)
	before := recordCount(t, w.ada, w.artifact)
	var writes []string
	if _, err := recording(ada, &writes, false).Share(w.artifact, "cat@example.com", "viewer", true); !errors.Is(err, ErrEpochUnreadable) {
		t.Errorf("demoting a member who needs every epoch: %v, want ErrEpochUnreadable", err)
	}
	if after := recordCount(t, w.ada, w.artifact); len(writes) != 0 || after != before {
		t.Errorf("wrote %v, %d records, want none and %d", writes, after, before)
	}
}

// A record that keeps a public artifact public needs the link token of the
// current epoch, which an unreadable epoch cannot give.
func TestOwnerChangeOfAPublicArtifactNeedsTheLinkToken(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Public(w.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	ada := ownerKeysRewritten(t, w.ada, w.artifact, 2, badWrap)
	memberRows(t, ada, w.artifact)
	before := recordCount(t, w.ada, w.artifact)
	var writes []string
	// Lowering the manager to editor needs no wrap and stays in the epoch.
	if _, err := recording(ada, &writes, false).Share(w.artifact, "bob@example.com", "editor", false); !errors.Is(err, ErrEpochUnreadable) {
		t.Errorf("a change to a public artifact under an unreadable epoch: %v, want ErrEpochUnreadable", err)
	}
	if after := recordCount(t, w.ada, w.artifact); len(writes) != 0 || after != before {
		t.Errorf("wrote %v, %d records, want none and %d", writes, after, before)
	}
}

// An owner with two unreadable epochs and a readable one between them: bob
// starts epochs 2 and 4 and the owner's wrap of each is bad, while the owner
// starts epoch 3 by removing dan, which gives it an estate copy of that epoch.
func TestOwnerWithSeveralUnreadableEpochs(t *testing.T) {
	for _, keepEpochs := range []bool{true, false} {
		name := "new epoch"
		if keepEpochs {
			name = "keep epochs"
		}
		t.Run(name, func(t *testing.T) {
			w := managerWorld(t)
			for _, who := range []string{"cat@example.com", "dan@example.com"} {
				if _, err := w.ada.Share(w.artifact, who, "viewer", false); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := w.bob.Unshare(w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			ada := ownerKeysRewrittenAt(t, w.ada, w.artifact, map[int]func() []byte{2: badWrap, 4: badWrap})
			res, err := ada.Unshare(w.artifact, "dan@example.com")
			if err != nil || res.Epoch != 3 || !slices.Equal(res.Unreadable, []int{2}) {
				t.Fatalf("the owner's epoch 3: %+v, %v; want epoch 3 with [2] unreadable", res, err)
			}
			readable := pushOne(t, ada, w.artifact)
			// A later version, which bob's next epoch re-seals into epoch 4
			// and so leaves the first as the only one under epoch 3.
			pushOne(t, w.bob, w.artifact)
			// Bob's second epoch, which a public switch on and off starts.
			if _, err := w.bob.Public(w.artifact, true, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := w.bob.Public(w.artifact, false, nil); err != nil {
				t.Fatal(err)
			}

			k := mustUnlock(t, ada)
			va, err := ada.VerifyArtifact(k, w.artifact, "")
			if err != nil || va.Chain.Latest.Epoch != 4 {
				t.Fatalf("latest epoch, %v: want 4", err)
			}
			aks, err := ada.callerAKs(k, w.artifact, va.Chain)
			if err != nil {
				t.Fatal(err)
			}
			if got := unreadableEpochs(va.Chain, aks); !slices.Equal(got, []int{2, 4}) {
				t.Errorf("unreadable epochs = %v, want [2 4]", got)
			}
			if got, err := ada.VersionFiles(w.artifact, readable); err != nil || string(got["index.html"]) != "<h1>hi</h1>" {
				t.Errorf("the owner reads epoch 3: %v, %v", got, err)
			}

			rot, err := ada.RotateKeys(testPassword, keepEpochs)
			if err != nil {
				t.Fatalf("RotateKeys: %v", err)
			}
			if got := rot.Unreadable[w.artifact]; !slices.Equal(got, []int{2, 4}) || len(rot.Unreadable) != 1 {
				t.Errorf("Unreadable = %v, want epochs 2 and 4 of the artifact", rot.Unreadable)
			}
			wantEstate := []int{1, 3}
			if !keepEpochs {
				wantEstate = []int{1, 3, 5}
			}
			if estate, wraps := keyEpochs(t, ada, w.artifact); !slices.Equal(estate, wantEstate) || !slices.Equal(wraps, []int{2, 4}) {
				t.Errorf("estate %v, wraps %v, want %v and [2 4]", estate, wraps, wantEstate)
			}
			nk := mustUnlock(t, ada)
			keys, err := ada.Keys(w.artifact)
			if err != nil {
				t.Fatal(err)
			}
			for _, kw := range keys.Wraps {
				if kw.FP == nk.FP {
					t.Errorf("the wrap of epoch %d is under the new fingerprint, want the old one", kw.Epoch)
				}
			}
			if got, err := ada.VersionFiles(w.artifact, readable); err != nil || string(got["index.html"]) != "<h1>hi</h1>" {
				t.Errorf("the owner reads epoch 3 after rotating: %v, %v", got, err)
			}
		})
	}
}

// Keeping epochs while rotating keys leaves a public artifact's link hash as
// it is, which the current epoch's AK makes, so an unreadable current epoch
// refuses the rotation with the clear error.
func TestRotateKeepingEpochsOfAPublicArtifactNeedsTheLinkToken(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Public(w.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	ada := ownerKeysRewritten(t, w.ada, w.artifact, 2, badWrap)
	if _, err := ada.RotateKeys(testPassword, true); !errors.Is(err, ErrEpochUnreadable) {
		t.Errorf("RotateKeys keeping epochs under an unreadable current epoch: %v, want ErrEpochUnreadable", err)
	}
}

// A user removed from an artifact stays out of a manager's reach after they
// rotate keys: the record's entry still names them, and the manager's
// re-share is refused without a write.
func TestManagerCannotReShareAnExcludedUserWhoRotatedKeys(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	old := mustUnlock(t, w.cat).FP
	if _, err := w.cat.RotateKeys(testPassword, true); err != nil {
		t.Fatalf("cat rotates keys: %v", err)
	}
	if now := mustUnlock(t, w.cat).FP; now == old {
		t.Fatalf("cat's fingerprint did not change: %s", now)
	}
	memberRows(t, w.bob, w.artifact)
	before := recordCount(t, w.ada, w.artifact)
	var writes []string
	if _, err := recording(w.bob, &writes, false).Share(w.artifact, "cat@example.com", "viewer", true); !errors.Is(err, ErrExcludedOwnerOnly) {
		t.Errorf("a manager re-shares the removed user under new keys: %v, want ErrExcludedOwnerOnly", err)
	}
	if after := recordCount(t, w.ada, w.artifact); len(writes) != 0 || after != before {
		t.Errorf("wrote %v, %d records, want none and %d", writes, after, before)
	}
}
