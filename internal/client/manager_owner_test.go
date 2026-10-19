package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func TestManagerCannotReShareAnExcludedUser(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	// Reading the chain first moves bob's keyring pin, which is not a write
	// the refusal is meant to prevent.
	memberRows(t, w.bob, w.artifact)
	before := recordCount(t, w.ada, w.artifact)
	var writes []string
	if _, err := recording(w.bob, &writes, false).Share(w.artifact, "cat@example.com", "viewer", false); !errors.Is(err, ErrExcludedOwnerOnly) {
		t.Errorf("a manager re-shares the removed user: %v, want ErrExcludedOwnerOnly", err)
	}
	if after := recordCount(t, w.ada, w.artifact); len(writes) != 0 || after != before {
		t.Errorf("wrote %v, %d records, want none and %d", writes, after, before)
	}
	// The owner re-shares them, which drops the entry.
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Errorf("the owner re-shares the removed user: %v", err)
	}
}

// A manager's next epoch carries every excluded entry of the record before.
func TestManagerEpochKeepsTheOwnersExclusions(t *testing.T) {
	w := managerWorld(t)
	for _, who := range []string{"cat@example.com", "dan@example.com"} {
		if _, err := w.ada.Share(w.artifact, who, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.ada.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Unshare(w.artifact, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := excludedEmails(latestRecord(t, w.bob, w.artifact)); !slices.Equal(got, []string{"cat@example.com", "dan@example.com"}) {
		t.Errorf("excluded after the manager's epoch = %v, want cat and dan", got)
	}
}

// ownerKeysRewritten is a copy of c, the owner's client, whose answer for the
// artifact's keys lists epoch's wrap as wrap() returns it, as a server that
// hands the owner a bad wrap would.
func ownerKeysRewritten(t *testing.T, c *Client, artifact string, epoch int, wrap func() []byte) *Client {
	t.Helper()
	return ownerKeysRewrittenAt(t, c, artifact, map[int]func() []byte{epoch: wrap})
}

// ownerKeysRewrittenAt is ownerKeysRewritten for several epochs at once: each
// epoch in wraps has its wrap replaced by what its function returns.
func ownerKeysRewrittenAt(t *testing.T, c *Client, artifact string, wraps map[int]func() []byte) *Client {
	t.Helper()
	return rewriting(c, "/api/artifacts/"+artifact+"/keys", func(body []byte) []byte {
		var keys struct {
			Wraps  []map[string]any `json:"wraps"`
			Estate []map[string]any `json:"estate"`
		}
		if err := json.Unmarshal(body, &keys); err != nil {
			t.Error(err)
			return body
		}
		for _, w := range keys.Wraps {
			if wrap, ok := wraps[int(w["epoch"].(float64))]; ok {
				w["wrapped"] = e2e.B64(wrap())
			}
		}
		out, err := json.Marshal(keys)
		if err != nil {
			t.Error(err)
		}
		return out
	})
}

// A wrap for the owner that does not open, or opens to the wrong AK, leaves
// that epoch unreadable and nothing else: the owner removes the manager who
// sent it and reads the new epoch.
func TestOwnerIsNotLockedOutByABadWrap(t *testing.T) {
	cases := []struct {
		name string
		wrap func(t *testing.T, w *team) func() []byte
	}{
		{"does not open", func(t *testing.T, w *team) func() []byte {
			return func() []byte {
				b := make([]byte, 81)
				if _, err := rand.Read(b); err != nil {
					t.Fatal(err)
				}
				return b
			}
		}},
		{"opens to another AK", func(t *testing.T, w *team) func() []byte {
			k := mustUnlock(t, w.ada)
			return func() []byte {
				ak := make([]byte, 32)
				if _, err := rand.Read(ak); err != nil {
					t.Fatal(err)
				}
				b, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
					Purpose: "ak", Artifact: w.artifact, Epoch: 2, RecipientID: k.UserID, RecipientPub: k.X25519Pub,
				}, ak)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := managerWorld(t)
			if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			putData(t, w.ada, w.artifact)
			if _, err := w.bob.Unshare(w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			ada := ownerKeysRewritten(t, w.ada, w.artifact, 2, tc.wrap(t, w))
			oldVersion := mustLatestVersion(t, w.bob, w.artifact)

			if rows := memberRows(t, ada, w.artifact); rows["bob@example.com"].Role != "manager" {
				t.Errorf("the owner lists members: bob = %+v", rows["bob@example.com"])
			}
			_, err := ada.VersionFiles(w.artifact, oldVersion)
			if !errors.Is(err, ErrEpochUnreadable) || !strings.Contains(err.Error(), "epoch 2") {
				t.Errorf("reading content under the bad epoch: %v, want ErrEpochUnreadable naming epoch 2", err)
			}
			// Wrapping every epoch to a new member needs epoch 2.
			var writes []string
			if _, err := recording(ada, &writes, false).Share(w.artifact, "dan@example.com", "viewer", false); !errors.Is(err, ErrEpochUnreadable) {
				t.Errorf("sharing with a new member: %v, want ErrEpochUnreadable", err)
			}
			if len(writes) != 0 {
				t.Errorf("wrote %v before refusing", writes)
			}
			// Everything sealed under the current epoch, which is the bad one.
			if _, err := ada.Push(w.artifact, "", siteDir(t), "v", ""); !errors.Is(err, ErrEpochUnreadable) {
				t.Errorf("Push under the unreadable epoch: %v, want ErrEpochUnreadable", err)
			}
			if err := ada.UpdateArtifact(w.artifact, map[string]string{"name": "x"}); !errors.Is(err, ErrEpochUnreadable) {
				t.Errorf("UpdateArtifact under the unreadable epoch: %v, want ErrEpochUnreadable", err)
			}
			if _, err := ada.Public(w.artifact, true, nil); !errors.Is(err, ErrEpochUnreadable) {
				t.Errorf("Public under the unreadable epoch: %v, want ErrEpochUnreadable", err)
			}

			res, err := ada.Unshare(w.artifact, "bob@example.com")
			if err != nil {
				t.Fatalf("the owner removes the manager: %v", err)
			}
			if !res.NewEpoch || res.Epoch != 3 || !slices.Equal(res.Unreadable, []int{2}) {
				t.Errorf("Unshare = epoch %d, new %v, unreadable %v; want epoch 3 and [2]", res.Epoch, res.NewEpoch, res.Unreadable)
			}
			if res.ResealErr == nil && (res.Resealed == nil || len(res.Resealed.Skipped) == 0) {
				t.Errorf("the version under epoch 2 was neither re-sealed nor reported: %+v", res.Resealed)
			}
			if got := latestRecord(t, ada, w.artifact); got.Epoch != 3 || got.V != 1 || len(got.Members) != 0 {
				t.Errorf("latest = v%d epoch %d members %v", got.V, got.Epoch, got.Members)
			}

			// The new epoch reads, and the bad one still does not.
			fresh := pushOne(t, ada, w.artifact)
			if got, err := ada.VersionFiles(w.artifact, fresh); err != nil || string(got["index.html"]) != "<h1>hi</h1>" {
				t.Errorf("the owner reads the new epoch: %v, %v", got, err)
			}
			if estate, _ := keyEpochs(t, w.ada, w.artifact); !slices.Equal(estate, []int{1, 3}) {
				t.Errorf("estate copies %v, want [1 3]: none for the unreadable epoch", estate)
			}
			if _, err := ada.VersionFiles(w.artifact, oldVersion); !errors.Is(err, ErrEpochUnreadable) {
				t.Errorf("content under epoch 2 after the removal: %v, want ErrEpochUnreadable", err)
			}
		})
	}
}

// Making a public artifact private starts an epoch, and reports the epoch the
// owner could not read, as an unshare does.
func TestOwnerMakingPrivateReportsAnUnreadableEpoch(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.bob.Public(w.artifact, true, nil); err != nil {
		t.Fatalf("manager makes it public: %v", err)
	}
	if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Unshare(w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	ada := ownerKeysRewritten(t, w.ada, w.artifact, 2, func() []byte { return make([]byte, 81) })
	res, err := ada.Public(w.artifact, false, nil)
	if err != nil {
		t.Fatalf("the owner makes it private: %v", err)
	}
	if !res.NewEpoch || !slices.Equal(res.Unreadable, []int{2}) {
		t.Errorf("Public(false) = new epoch %v, unreadable %v; want true and [2]", res.NewEpoch, res.Unreadable)
	}
}

// Approving a team member wraps every epoch to them, so an epoch the owner
// cannot read refuses the approval before any request writes.
func TestOwnerApprovalNeedsEveryEpoch(t *testing.T) {
	w := managerWorld(t)
	if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Share(w.artifact, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Unshare(w.artifact, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	ada := ownerKeysRewritten(t, w.ada, w.artifact, 2, func() []byte { return make([]byte, 81) })
	memberRows(t, ada, w.artifact)
	var writes []string
	if _, err := recording(ada, &writes, false).Approve(w.artifact, "cat@example.com", false); !errors.Is(err, ErrEpochUnreadable) {
		t.Errorf("Approve with an unreadable epoch: %v, want ErrEpochUnreadable", err)
	}
	if len(writes) != 0 {
		t.Errorf("wrote %v before refusing", writes)
	}
}

// Rotating keys leaves out an epoch the owner cannot read, wrap and estate
// copy both, and names it: the wrap stays under the old keys, the epoch keeps
// no estate copy, and the owner still reads every other epoch, starts a new
// one, and gets the clear error for the unreadable one.
func TestRotateKeysNamesAnUnreadableEpoch(t *testing.T) {
	for _, keepEpochs := range []bool{true, false} {
		name := "new epoch"
		if keepEpochs {
			name = "keep epochs"
		}
		t.Run(name, func(t *testing.T) {
			w := managerWorld(t)
			if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			putData(t, w.ada, w.artifact)
			if _, err := w.bob.Unshare(w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			oldVersion := mustLatestVersion(t, w.bob, w.artifact)
			ada := ownerKeysRewritten(t, w.ada, w.artifact, 2, func() []byte { return make([]byte, 81) })
			res, err := ada.RotateKeys(testPassword, keepEpochs)
			if err != nil {
				t.Fatalf("RotateKeys with an unreadable epoch: %v", err)
			}
			if got := res.Unreadable[w.artifact]; !slices.Equal(got, []int{2}) || len(res.Unreadable) != 1 {
				t.Errorf("Unreadable = %v, want epoch 2 of the artifact", res.Unreadable)
			}
			wantEpoch, wantEstate := 2, []int{1}
			if !keepEpochs {
				wantEpoch, wantEstate = 3, []int{1, 3}
			}
			if res.Epochs[w.artifact] != wantEpoch {
				t.Errorf("epoch = %d, want %d", res.Epochs[w.artifact], wantEpoch)
			}
			k := mustUnlock(t, ada)
			keys, err := ada.Keys(w.artifact)
			if err != nil {
				t.Fatal(err)
			}
			if estate, wraps := keyEpochs(t, ada, w.artifact); !slices.Equal(estate, wantEstate) || !slices.Equal(wraps, []int{2}) {
				t.Errorf("estate %v, wraps %v, want %v and [2]", estate, wraps, wantEstate)
			}
			if len(keys.Wraps) != 1 || keys.Wraps[0].FP == k.FP {
				t.Errorf("wraps %+v, want epoch 2's wrap left under the old fingerprint, not %s", keys.Wraps, k.FP)
			}

			// The owner still reads what it can, and starts a new epoch.
			if _, err := ada.VersionFiles(w.artifact, oldVersion); !errors.Is(err, ErrEpochUnreadable) {
				t.Errorf("content under epoch 2 after rotating: %v, want ErrEpochUnreadable", err)
			}
			unshared, err := ada.Unshare(w.artifact, "bob@example.com")
			if err != nil {
				t.Fatalf("the owner removes the manager after rotating: %v", err)
			}
			if !unshared.NewEpoch || !slices.Equal(unshared.Unreadable, []int{2}) {
				t.Errorf("Unshare = new epoch %v, unreadable %v; want true and [2]", unshared.NewEpoch, unshared.Unreadable)
			}
			fresh := pushOne(t, ada, w.artifact)
			if got, err := ada.VersionFiles(w.artifact, fresh); err != nil || string(got["index.html"]) != "<h1>hi</h1>" {
				t.Errorf("the owner reads the new epoch: %v, %v", got, err)
			}
			if _, err := ada.VersionFiles(w.artifact, oldVersion); !errors.Is(err, ErrEpochUnreadable) {
				t.Errorf("content under epoch 2 after the removal: %v, want ErrEpochUnreadable", err)
			}
		})
	}
}

// The owner may rotate keys after a manager's epoch, before any catch-up
// stored its estate copy: the rotation opens it through the wrap, and every
// epoch reads afterwards.
func TestOwnerRotatesAfterAManagersEpoch(t *testing.T) {
	for _, keepEpochs := range []bool{true, false} {
		name := "new epoch"
		if keepEpochs {
			name = "keep epochs"
		}
		t.Run(name, func(t *testing.T) {
			w := managerWorld(t)
			if _, err := w.bob.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			putData(t, w.ada, w.artifact)
			if _, err := w.bob.Unshare(w.artifact, "cat@example.com"); err != nil {
				t.Fatal(err)
			}
			if estate, wraps := keyEpochs(t, w.ada, w.artifact); !slices.Equal(estate, []int{1}) || !slices.Equal(wraps, []int{2}) {
				t.Fatalf("before rotating: estate %v, wraps %v, want [1] and [2]", estate, wraps)
			}
			rotateOK(t, w.ada, keepEpochs)
			k := mustUnlock(t, w.ada)
			va, err := w.ada.VerifyArtifact(k, w.artifact, "")
			if err != nil {
				t.Fatal(err)
			}
			aks, err := w.ada.callerAKs(k, w.artifact, va.Chain)
			if err != nil || len(aks) != va.Chain.Latest.Epoch {
				t.Fatalf("the owner's AKs after rotating: %d of %d epochs, %v", len(aks), va.Chain.Latest.Epoch, err)
			}
			if got, err := w.ada.VersionFiles(w.artifact, mustLatestVersion(t, w.bob, w.artifact)); err != nil || string(got["index.html"]) != "<html>hi</html>" {
				t.Errorf("the owner reads after rotating: %v, %v", got, err)
			}
		})
	}
}
