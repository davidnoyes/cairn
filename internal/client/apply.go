// Applying: bringing the items the caller owns or manages in step with their
// folders, which other people changed. Whoever shares a folder signs only the
// records they can; every other item inside it stays pending until its owner
// or a manager applies the share here. See "Folders with other people's
// items" in design/e2e-api.md.
package client

import (
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// ApplyApproval is what Apply did about the members of the groups an item
// lists: the ones it approved, and the ones it left waiting with the reason.
type ApplyApproval struct {
	ID       string
	Kind     string
	Approved []DirectoryUser
	Pending  []UnlistedUser
}

// ApplyResult is what Apply did. FanOut holds every pending item the caller
// could sign, with what happened to it: updated, at a new epoch, failed, or
// needing a move. Waiting holds the pending items
// that only someone else can sign. Approvals are the group members approved
// on items the caller can approve.
type ApplyResult struct {
	FanOut    FanOutResult
	Waiting   []FanOutItem
	Approvals []ApplyApproval
}

// Apply signs every pending record the caller can. For each item the caller
// owns or manages whose artifact view says inherit is pending, it adds the
// entries the folder lists, with wraps of every epoch's key, or starts the
// next epoch where an entry no longer holds, as FanOut does for a folder it
// changed; parents come before the items inside them, and an item is also
// visited when a folder above it changed during the run, because its own
// folder's record then says more. An item whose record names the folder the
// server lists it in is brought up to date. An item the server lists at the top
// level whose record names a folder is written as naming none: the server
// moved it there when the folder was deleted or an editor removed it, and
// its owner signs the record. An item the server lists at the top level
// with no hiddenParent is taken on its word: it controls the tree anyway, and
// the change only lowers what the folder's members hold. An item that sits in
// a folder the caller cannot read (hiddenParent) is not at the top level, so
// nothing is signed for it and it needs a move. Any other mismatch between the record and the
// server's tree is left, as needing a move, because only the owner knows
// where the item belongs; a manager's record keeps the folder, so an item
// that needs one waits on its owner. Apply then approves the waiting members
// of every group an item the caller can approve lists, as sharing with a group
// does. A pending item the caller cannot sign is reported as waiting. Running
// it again finds nothing more to do. Items that fail are skipped, with the
// reason in the result, and ErrFanOutIncomplete is returned at the end.
func (c *Client) Apply() (*ApplyResult, error) { return c.apply(true) }

// ApplyInherited is Apply without the approvals: it signs the pending records
// the caller can and reports the ones that wait, and approves no group
// newcomer, which stays an explicit decision. It is what runs on its own, as
// the caller's client starts. With no item pending that the caller can sign it
// lists the artifacts and does nothing more. An item the server lists at the
// top level whose record names a folder is signed out of it on the server's
// word, as Apply does: see topWhenOrphaned.
func (c *Client) ApplyInherited() (*ApplyResult, error) { return c.apply(false) }

func (c *Client) apply(approve bool) (*ApplyResult, error) {
	all, err := c.listWithStubs()
	if err != nil {
		return nil, err
	}
	if !approve && !slices.ContainsFunc(all, func(a *Artifact) bool { return a.Inherit == "pending" && canSign(a) }) {
		return &ApplyResult{}, nil
	}
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	f := &fanOut{c: c, k: k, dir: dir, parents: map[string]*e2e.MembershipBody{}, verified: map[string]*VerifiedArtifact{}, topWhenOrphaned: true}
	res := &ApplyResult{}
	changed := map[string]bool{}
	for _, a := range inDepthOrder(all) {
		if !canSign(a) {
			if a.Inherit == "pending" {
				res.Waiting = append(res.Waiting, waitingItem(a, dir))
			}
			continue
		}
		if a.Inherit != "pending" && !aboveChanged(all, a, changed) {
			continue
		}
		if a.ParentID == "" && a.HiddenParent {
			res.FanOut.Items = append(res.FanOut.Items, hiddenParentItem(a))
			continue
		}
		item := f.item(a, nil)
		if errors.Is(item.Err, ErrManagerOwnerOnly) || errors.Is(item.Err, ErrExcludedOwnerOnly) {
			res.Waiting = append(res.Waiting, waitingItem(a, dir))
			continue
		}
		if errors.Is(item.Err, ErrPlacement) {
			item.State = FanOutNeedsMove
		}
		if fatalFetch(item.Err) {
			return res, item.Err
		}
		if item.State == FanOutUpdated || item.State == FanOutNewEpoch {
			changed[a.ID] = true
		}
		res.FanOut.Items = append(res.FanOut.Items, item)
	}
	for _, a := range all {
		if !approve || !slices.Contains([]string{"owner", "manager", "editor"}, a.Access) {
			continue
		}
		ap, err := c.applyApprovals(k, a)
		if err != nil {
			return res, err
		}
		if ap != nil {
			res.Approvals = append(res.Approvals, *ap)
		}
	}
	if n := res.FanOut.Count(FanOutFailed); n > 0 {
		return res, fmt.Errorf("%w: %d of %d", ErrFanOutIncomplete, n, len(res.FanOut.Items))
	}
	return res, nil
}

// hiddenParentItem is the FanOutNeedsMove entry for a, an item that sits in a
// folder the caller can no longer read. The server does not name the folder,
// so Apply cannot tell whether the item's record still matches it, and signs
// nothing; the owner takes the item out of the folder, which needs no read
// access to it.
func hiddenParentItem(a *Artifact) FanOutItem {
	return FanOutItem{ID: a.ID, Kind: a.Kind, State: FanOutNeedsMove,
		Err: fmt.Errorf("it sits in a folder you can no longer read; take it out with: cairn move %s --top", a.ID)}
}

// inDepthOrder returns the artifacts of all with each folder before the items
// inside it, as the server lists the tree, and otherwise by ID.
func inDepthOrder(all []*Artifact) []*Artifact {
	depth := map[string]int{}
	for _, a := range all {
		n := 0
		for p := a; p != nil && p.ParentID != "" && n < 4*len(all); p = byID(all, p.ParentID) {
			n++
		}
		depth[a.ID] = n
	}
	out := slices.Clone(all)
	sort.SliceStable(out, func(i, j int) bool {
		if depth[out[i].ID] != depth[out[j].ID] {
			return depth[out[i].ID] < depth[out[j].ID]
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// aboveChanged reports whether a folder above a, as the server lists the
// tree, was written during this run.
func aboveChanged(all []*Artifact, a *Artifact, changed map[string]bool) bool {
	for p, n := byID(all, a.ParentID), 0; p != nil && n < len(all); p, n = byID(all, p.ParentID), n+1 {
		if changed[p.ID] {
			return true
		}
	}
	return false
}

// applyApprovals approves the waiting members of each group a's latest record
// lists, for an item the caller can approve on, as the server's access level
// says: an approval that a check refuses is left waiting, with the reason. It
// returns nil when nothing was approved and nothing is left waiting. An item whose chain does not verify,
// or a group that does not, is skipped: whoever can fix them runs the command
// that says why.
func (c *Client) applyApprovals(k *UnlockedKeys, a *Artifact) (*ApplyApproval, error) {
	va, err := c.VerifyArtifact(k, a.ID, "")
	if err != nil {
		if fatalFetch(err) {
			return nil, err
		}
		return nil, nil
	}
	res := &ShareGroupResult{}
	for _, g := range va.Chain.Latest.Groups {
		vg, err := c.VerifyGroup(k, g.Group, false)
		if err != nil {
			if fatalFetch(err) {
				return nil, err
			}
			continue
		}
		if err := c.approveGroupMembers(k, a.ID, vg.Chain, false, res); err != nil {
			return nil, err
		}
	}
	if len(res.Approved) == 0 && len(res.Pending) == 0 {
		return nil, nil
	}
	return &ApplyApproval{ID: a.ID, Kind: a.Kind, Approved: res.Approved, Pending: res.Pending}, nil
}
