// The manager role: who may sign a member list, the changes only the owner
// makes, and the owner's catch-up on estate copies a manager's epoch could not
// carry. See "Managers" in design/e2e-api.md.
package client

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrManagerOwnerOnly means the change adds, removes, or changes a
	// manager, which only the artifact's owner does.
	ErrManagerOwnerOnly = errors.New("only the artifact's owner can add or change a manager")
	// ErrDeleteNotOwner means a manager tried to delete the artifact.
	ErrDeleteNotOwner = errors.New("only the artifact's owner can delete it")
	// ErrExcludedOwnerOnly means a manager tried to share with a user the
	// record excludes, whom only the owner re-shares.
	ErrExcludedOwnerOnly = errors.New("only the artifact's owner can share with a user who was removed from it")
	// ErrEpochUnreadable means the action needs the AK of an epoch the owner
	// cannot read: a manager started it, and the wrap for the owner does not
	// open or does not match the chain.
	ErrEpochUnreadable = errors.New("the key of an epoch is unreadable")
)

// isOwner reports whether the keys in k are the owner's under the record.
func isOwner(latest e2e.MembershipBody, k *UnlockedKeys) bool {
	return latest.Owner == k.UserID && latest.OwnerFP == k.FP
}

// isManager reports whether the record lists the keys in k as a manager.
func isManager(latest e2e.MembershipBody, k *UnlockedKeys) bool {
	return slices.ContainsFunc(latest.Members, func(m e2e.Member) bool {
		return m.User == k.UserID && m.Role == "manager" && m.FP == k.FP
	})
}

// signedByCaller reports whether the record is the owner's, signed under the
// caller's current key, or a manager's naming the caller and that key.
func signedByCaller(latest e2e.MembershipBody, k *UnlockedKeys) bool {
	if latest.V == 2 {
		return latest.Signer == k.UserID && latest.SignerFP == k.FP
	}
	return isOwner(latest, k)
}

// checkSigner refuses, with ErrNotOwner, a caller who may not sign a member
// list: the owner and a listed manager may.
func checkSigner(latest e2e.MembershipBody, k *UnlockedKeys) error {
	if isOwner(latest, k) || isManager(latest, k) {
		return nil
	}
	return ErrNotOwner
}

// listedRole is the role the record lists user under, or "".
func listedRole(latest e2e.MembershipBody, user string) string {
	for _, m := range latest.Members {
		if m.User == user {
			return m.Role
		}
	}
	return ""
}

// checkManagerEntry refuses a manager's change to the entry of user, whom the
// record lists as a manager: a manager changes none, their own included.
func checkManagerEntry(latest e2e.MembershipBody, k *UnlockedKeys, user string) error {
	if !isOwner(latest, k) && listedRole(latest, user) == "manager" {
		return ErrManagerOwnerOnly
	}
	return nil
}

// signedBy marks next, when the caller is not its owner, as the version 2
// record a manager signs, naming them and the key that signs. The owner's
// records are version 1, which signChained sets.
func signedBy(next e2e.MembershipBody, k *UnlockedKeys) e2e.MembershipBody {
	if next.Owner != k.UserID {
		next.V, next.Signer, next.SignerFP = 2, k.UserID, k.FP
	}
	return next
}

// ownerWrap wraps the new epoch's ak to the artifact's owner, under the key
// the directory lists for them. A manager's next-epoch record carries it in
// place of an estate copy, which only the owner can seal. The directory's key
// must be the one the record lists, or one a rotation chain links to it.
func ownerWrap(artifactID string, va *VerifiedArtifact, dir []DirectoryUser, epoch int, ak []byte) (map[string]any, error) {
	latest := va.Chain.Latest
	i := slices.IndexFunc(dir, func(u DirectoryUser) bool { return u.ID == latest.Owner })
	if i < 0 {
		return nil, fmt.Errorf("the directory does not list the owner %s, so the new key cannot be wrapped to them", latest.Owner)
	}
	owner := dir[i]
	if owner.FP != latest.OwnerFP && !e2e.RotationLinker(va.Membership.Rotations)(owner.ID, latest.OwnerFP, owner.FP) {
		return nil, errors.New("the owner's keys in the directory do not follow from the fingerprint the latest record lists for them")
	}
	w, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
		Purpose: "ak", Artifact: artifactID, Epoch: uint64(epoch), RecipientID: owner.ID, RecipientPub: owner.X25519Pub,
	}, ak)
	if err != nil {
		return nil, err
	}
	return map[string]any{"user": owner.ID, "epoch": epoch, "wrapped": e2e.B64(w)}, nil
}

// openWrap opens the caller's wrap w of an epoch's AK, and checks it against
// the akCommit the chain lists for that epoch.
func openWrap(k *UnlockedKeys, artifactID string, commits map[int]string, w KeyWrap) ([]byte, error) {
	ak, err := e2e.Unwrap(k.X25519Priv, e2e.WrapContext{
		Purpose: "ak", Artifact: artifactID, Epoch: uint64(w.Epoch), RecipientID: k.UserID, RecipientPub: k.X25519Pub,
	}, w.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("opening your wrap of epoch %d: %w", w.Epoch, err)
	}
	commit, err := e2e.AKCommit(ak, artifactID, uint64(w.Epoch))
	if err != nil {
		return nil, err
	}
	if want, ok := commits[w.Epoch]; !ok || commit != want {
		return nil, fmt.Errorf("%w: your wrap of epoch %d does not match the chain's akCommit", e2e.ErrChain, w.Epoch)
	}
	return ak, nil
}

// epochKey is the AK of epoch in aks, or ErrEpochUnreadable when the owner's
// client left the epoch out because its wrap did not open.
func epochKey(aks map[int][]byte, epoch int) ([]byte, error) {
	if ak := aks[epoch]; ak != nil {
		return ak, nil
	}
	return nil, fmt.Errorf("%w: epoch %d", ErrEpochUnreadable, epoch)
}

// unreadableEpochs lists the epochs up to the chain's latest that aks leaves
// out.
func unreadableEpochs(chain *e2e.Chain, aks map[int][]byte) []int {
	var out []int
	for epoch := 1; epoch <= chain.Latest.Epoch; epoch++ {
		if aks[epoch] == nil {
			out = append(out, epoch)
		}
	}
	return out
}

// catchUpEstate fills, in aks, each epoch up to the chain's latest that has no
// estate copy, from the owner's own wrap of it, which a manager's next-epoch
// record carries, and stores the estate copy for it. The owner reads through
// the wrap either way: a copy that fails to store is left for the next time,
// and the client has no place to report it. A wrap that does not open, or
// whose AK does not match the chain, is skipped, so one bad wrap does not
// lock the owner out: it returns those epochs, which aks leaves out.
func (c *Client) catchUpEstate(k *UnlockedKeys, artifactID string, chain *e2e.Chain, keys *ArtifactKeys, aks map[int][]byte) ([]int, error) {
	commits := epochCommits(chain)
	ekKey, err := e2e.EKSealKey(k.EK)
	if err != nil {
		return nil, err
	}
	var unreadable []int
	for epoch := 1; epoch <= chain.Latest.Epoch; epoch++ {
		if aks[epoch] != nil {
			continue
		}
		i := slices.IndexFunc(keys.Wraps, func(w KeyWrap) bool { return w.Epoch == epoch })
		if i < 0 {
			continue
		}
		ak, err := openWrap(k, artifactID, commits, keys.Wraps[i])
		if err != nil {
			unreadable = append(unreadable, epoch)
			continue
		}
		aks[epoch] = ak
		sealed, err := e2e.Seal(rand.Reader, ekKey, estateFields(artifactID, epoch), ak)
		if err != nil {
			return nil, err
		}
		// A failure, or a copy another device stored first, changes nothing
		// about what this command reads.
		_ = c.doJSON(http.MethodPut, "/api/artifacts/"+artifactID+"/estate/"+strconv.Itoa(epoch), map[string]any{"sealed": e2e.B64(sealed)}, nil)
	}
	return unreadable, nil
}
