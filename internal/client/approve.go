// Team shares: the pending list, approving a team member, and the owner's
// client listing approved members. As elsewhere in this package, every byte
// of cryptography is built with internal/e2e.
package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrNotApprover means the caller is neither the owner nor a listed
	// editor, so their client never wraps keys.
	ErrNotApprover = errors.New("only the owner or an editor can approve team members")
	// ErrNoTeam means the latest record's team is none, so there is no team
	// to approve into.
	ErrNoTeam = errors.New("the artifact is not shared with the team; the owner sets it with cairn team")
	// ErrAlreadyListed means the latest record lists the user. Only the owner
	// shares again, through a membership record.
	ErrAlreadyListed = errors.New("the user is already a member of the artifact")
	// ErrAlreadyApproved means the user already holds a wrap through an
	// approval, and waits for the owner to list them. The owner cannot check
	// a wrap's contents; only the recipient can, and a bad wrap is repaired
	// by a new epoch.
	ErrAlreadyApproved = errors.New("the user is already approved; the owner lists them in the next record")
	// ErrChangedKey means the user holds a wrap, or is listed, under keys
	// that are no longer theirs. A changed key is never a new member.
	ErrChangedKey = errors.New("the user's keys changed after they were wrapped to or listed; the owner shares again with cairn share")
	// ErrNotWaiting means the server lists the user as none of new, approved,
	// or keyChanged.
	ErrNotWaiting = errors.New("the user is not waiting for approval on this artifact")
	// ErrApprovalUnverified means the owner's client does not list a user the
	// server reports as approved, because the approval does not check out.
	// Only a new epoch repairs it: cairn unshare starts one and excludes them.
	ErrApprovalUnverified = errors.New("the approval does not check out, so cairn will not share with the user; cairn unshare starts a new epoch that excludes them")
	// ErrPendingKeysDiffer means the server serves a user's keys one way in
	// the directory and another in the pending list.
	ErrPendingKeysDiffer = errors.New("the server serves different keys for the user in the directory and in the pending list")
)

// States of a pending entry, as GET /pending names them.
const (
	PendingNew        = "new"
	PendingApproved   = "approved"
	PendingKeyChanged = "keyChanged"
)

// PendingUser is one entry of GET /api/artifacts/{id}/pending: a user with
// the keys the server serves for them now, and why the caller's client
// should ask about them. Approval is the stored approval of an approved
// user, shown to the owner only.
type PendingUser struct {
	User     DirectoryUser
	State    string
	Approval *e2e.Envelope
}

type pendingWire struct {
	directoryWire
	State    string        `json:"state"`
	Approval *e2e.Envelope `json:"approval"`
}

// Pending lists the users the caller, an owner or an editor, should be
// asked about.
func (c *Client) Pending(artifactID string) ([]PendingUser, error) {
	var resp []pendingWire
	if err := c.doJSON("GET", "/api/artifacts/"+artifactID+"/pending", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]PendingUser, 0, len(resp))
	for _, w := range resp {
		u, err := w.user()
		if err != nil {
			return nil, err
		}
		out = append(out, PendingUser{User: u, State: w.State, Approval: w.Approval})
	}
	return out, nil
}

// ApproveResult is what Approve did.
type ApproveResult struct {
	User  DirectoryUser
	Prior string // the pin state before: new, unverified, verified, or changed
	Epoch int
}

// Approve approves who, a team member waiting for access, at the
// artifact's current epoch: it wraps the AK of every epoch to them and
// signs an approval of their name and fingerprint. The caller must be the
// owner or a listed editor. It refuses, before asking the server, a user
// the chain excludes, a directory in which two user IDs share an email or a
// fingerprint, a user who is listed, already approved, or whose key changed
// after they were wrapped to, and a user whose pinned key changed, unless
// acceptNewKey. The pin is stored once the server accepts the approval.
func (c *Client) Approve(artifactID, who string, acceptNewKey bool) (*ApproveResult, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	latest := va.Chain.Latest
	if !approverOf(latest, k) {
		return nil, ErrNotApprover
	}
	if latest.Team == "none" {
		return nil, ErrNoTeam
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	u, err := FindUser(dir, who)
	if err != nil {
		return nil, err
	}
	if e := ExcludedMatch(latest.Excluded, u); e != nil {
		return nil, fmt.Errorf("%w: %s matches the excluded entry for %s (%s)", ErrExcluded, u.Email, e.Email, e.User)
	}
	pending, err := c.Pending(artifactID)
	if err != nil {
		return nil, err
	}
	p := slices.IndexFunc(pending, func(p PendingUser) bool { return p.User.ID == u.ID })
	// A listed member whose key changed is pending as keyChanged, so this
	// check comes before ErrAlreadyListed.
	if p >= 0 && pending[p].State == PendingKeyChanged {
		return nil, fmt.Errorf("%w: %s", ErrChangedKey, u.Email)
	}
	if u.ID == latest.Owner || slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == u.ID }) {
		return nil, fmt.Errorf("%w: %s", ErrAlreadyListed, u.Email)
	}
	switch {
	case p < 0:
		return nil, fmt.Errorf("%w: %s", ErrNotWaiting, u.Email)
	case pending[p].State == PendingApproved:
		return nil, fmt.Errorf("%w: %s", ErrAlreadyApproved, u.Email)
	case pending[p].User.FP != u.FP:
		return nil, fmt.Errorf("%w: %s", ErrPendingKeysDiffer, u.Email)
	}
	prior, pin, err := checkPin(va.Keyring, u, acceptNewKey)
	if err != nil {
		return nil, err
	}
	// Defense in depth behind VerifyChain's epoch pin, which already refuses a
	// stale epoch.
	if err := e2e.CheckEncryptEpoch(va.Keyring.EpochPin(artifactID), latest.Epoch); err != nil {
		return nil, err
	}
	aks, err := c.callerAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	var wraps []map[string]any
	for epoch := 1; epoch <= latest.Epoch; epoch++ {
		w, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
			Purpose: "ak", Artifact: artifactID, Epoch: uint64(epoch),
			RecipientID: u.ID, RecipientPub: u.X25519Pub,
		}, aks[epoch])
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, map[string]any{"epoch": epoch, "wrapped": e2e.B64(w)})
	}
	body, err := json.Marshal(e2e.ApprovalBody{V: 1, Artifact: artifactID, Epoch: latest.Epoch, User: u.ID, FP: u.FP})
	if err != nil {
		return nil, err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "approval", body)
	if err != nil {
		return nil, err
	}
	basedOn := va.Keyring.Pins[u.ID].FP
	if err := c.doJSON("POST", "/api/artifacts/"+artifactID+"/keys", map[string]any{
		"user": u.ID, "fp": u.FP, "approval": env, "wraps": wraps,
	}, nil); err != nil {
		return nil, err
	}
	if pin != nil {
		if err := c.storePin(k, u.ID, *pin, basedOn); err != nil {
			return nil, fmt.Errorf("the server accepted the approval, but pinning %s failed: %w", u.Email, err)
		}
	}
	return &ApproveResult{User: u, Prior: prior, Epoch: latest.Epoch}, nil
}

// approverOf reports whether the keys in k may approve under the record:
// they are the owner's, or the listed editor's.
func approverOf(latest e2e.MembershipBody, k *UnlockedKeys) bool {
	if latest.Owner == k.UserID {
		return latest.OwnerFP == k.FP
	}
	return slices.ContainsFunc(latest.Members, func(m e2e.Member) bool {
		return m.User == k.UserID && m.Role == "editor" && m.FP == k.FP
	})
}

// callerAKs returns the AK of every epoch up to the chain's latest, for the
// owner from the estate copies, for an editor by opening the caller's own
// wraps. Each is checked against the akCommit the verified chain lists.
func (c *Client) callerAKs(k *UnlockedKeys, artifactID string, chain *e2e.Chain) (map[int][]byte, error) {
	if chain.Latest.Owner == k.UserID {
		return c.epochAKs(k, artifactID, chain)
	}
	commits := epochCommits(chain)
	keys, err := c.Keys(artifactID)
	if err != nil {
		return nil, err
	}
	aks := map[int][]byte{}
	for _, w := range keys.Wraps {
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
		aks[w.Epoch] = ak
	}
	for epoch := 1; epoch <= chain.Latest.Epoch; epoch++ {
		if aks[epoch] == nil {
			return nil, fmt.Errorf("the server holds no wrap of epoch %d for you", epoch)
		}
	}
	return aks, nil
}

// UnlistedUser is an approved team member the owner's client did not list,
// because their approval failed a check (Err says which, by errors.Is), and
// who the owner must be asked about by name and fingerprint.
type UnlistedUser struct {
	User DirectoryUser
	Err  error
}

// approvalUser is u in the form CheckApproval takes.
func approvalUser(u DirectoryUser) e2e.ApprovalUser {
	return e2e.ApprovalUser{ID: u.ID, Email: u.Email,
		Keys: e2e.KeyPair{X25519: e2e.B64(u.X25519Pub), Ed25519: e2e.B64(u.Ed25519Pub)}}
}

// approvedListing is what the owner's client adds to its next record.
type approvedListing struct {
	members  []e2e.Member
	listed   []DirectoryUser
	unlisted []UnlistedUser
	// pins are the pins to store once the server accepts the record, keyed
	// by user, with the fingerprint each was decided against.
	pins map[string]pinDecision
}

type pinDecision struct {
	pin     e2e.Pin
	basedOn string
}

// checkApproved runs the four checks of e2e.CheckApproval on the approval
// in the pending entry p, and requires the directory to list the same keys
// for the user as the pending entry does, so the approval's fingerprint is
// the directory's. rotations are the rotation records the membership GET
// served, which let a signer's approval pass across a rotation. It does not
// look at the owner's pin.
func checkApproved(k *UnlockedKeys, latest e2e.MembershipBody, rotations map[string][]e2e.Envelope, dir []DirectoryUser, p PendingUser) error {
	keysOf := func(id string) (e2e.KeyPair, bool) {
		if id == k.UserID {
			return keyPairOf(k), true
		}
		for _, d := range dir {
			if d.ID == id {
				return approvalUser(d).Keys, true
			}
		}
		return e2e.KeyPair{}, false
	}
	if d, ok := keysOf(p.User.ID); ok && d != approvalUser(p.User).Keys {
		return fmt.Errorf("%w: %s", ErrPendingKeysDiffer, p.User.Email)
	}
	in := e2e.ApprovalInput{Artifact: latest.Artifact, Latest: &latest, Approval: p.Approval, User: approvalUser(p.User), Rotations: rotations}
	for _, d := range dir {
		in.Directory = append(in.Directory, approvalUser(d))
	}
	if p.Approval != nil {
		var ok bool
		if in.SignerKeys, ok = keysOf(p.Approval.Signer); !ok {
			return fmt.Errorf("%w: the directory does not list the signer %s", e2e.ErrApprovalSigner, p.Approval.Signer)
		}
	}
	return e2e.CheckApproval(in)
}

// listApproved decides, for each approved user the server reports, whether
// the owner's client may list them as role without asking: only when the
// approval passes all four checks of e2e.CheckApproval, the directory lists
// the keys the pending entry does, and the keys do not contradict the
// owner's pin. A user failing a check is reported, never listed. skip names
// users already in the record being built.
func (c *Client) listApproved(k *UnlockedKeys, va *VerifiedArtifact, dir []DirectoryUser, pending []PendingUser, role string, skip func(id string) bool) approvedListing {
	out := approvedListing{pins: map[string]pinDecision{}}
	for _, p := range pending {
		if p.State != PendingApproved || skip(p.User.ID) {
			continue
		}
		err := checkApproved(k, va.Chain.Latest, va.Membership.Rotations, dir, p)
		var pin *e2e.Pin
		if err == nil {
			_, pin, err = checkPin(va.Keyring, p.User, false)
		}
		if err != nil {
			out.unlisted = append(out.unlisted, UnlistedUser{User: p.User, Err: err})
			continue
		}
		out.members = append(out.members, e2e.Member{User: p.User.ID, Role: role, FP: p.User.FP})
		out.listed = append(out.listed, p.User)
		if pin != nil {
			out.pins[p.User.ID] = pinDecision{*pin, va.Keyring.Pins[p.User.ID].FP}
		}
	}
	return out
}

// teamNoneNextEpoch is Team none while a team member holds a wrap: a next-epoch
// record that excludes each of them.
func (c *Client) teamNoneNextEpoch(k *UnlockedKeys, artifactID string, va *VerifiedArtifact, pending []PendingUser, res *TeamResult) (*TeamResult, error) {
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	next := va.Chain.Latest
	next.Team = "none"
	change, _, err := c.putNextEpoch(k, artifactID, va, dir, pending, nextEpochRecord{next: next})
	if err != nil {
		return nil, err
	}
	if err := c.readBack(k, artifactID, change.Link); err != nil {
		return nil, err
	}
	res.EpochChange, res.Epoch = *change, va.Chain.Latest.Epoch+1
	return res, nil
}

// Team

// TeamResult is what Team did.
type TeamResult struct {
	Team      string
	Epoch     int
	Unchanged bool // the record already had this team and no approved member to list
	// Listed are approved team members the record lists, with the role the
	// team grants; Unlisted are those whose approval failed a check.
	Listed   []DirectoryUser
	Unlisted []UnlistedUser
	EpochChange
}

// CheckTeam refuses a team value other than none, viewer, or editor, so a
// caller can do it before any request.
func CheckTeam(team string) error {
	if team != "none" && team != "viewer" && team != "editor" {
		return fmt.Errorf("team must be none, viewer, or editor, not %q", team)
	}
	return nil
}

// Team sets whom the artifact is shared with as a team (none, viewer, or
// editor) in a same-epoch record, and lists each approved team member whose
// approval passes the four checks, under the role the team grants. Setting
// none while a team member holds a wrap starts a new epoch, which excludes
// every such member.
func (c *Client) Team(artifactID, team string) (*TeamResult, error) {
	if err := CheckTeam(team); err != nil {
		return nil, err
	}
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	latest := va.Chain.Latest
	if latest.Owner != k.UserID || latest.OwnerFP != k.FP {
		return nil, ErrNotOwner
	}
	pending, err := c.Pending(artifactID)
	if err != nil {
		return nil, err
	}
	res := &TeamResult{Team: team, Epoch: latest.Epoch}
	listed := func(id string) bool {
		return slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == id })
	}
	if team == "none" {
		// A team member holds a wrap while they are approved, or while a
		// wrap they hold is for keys that are no longer theirs.
		if slices.ContainsFunc(pending, func(p PendingUser) bool {
			return p.State == PendingApproved || p.State == PendingKeyChanged && !listed(p.User.ID)
		}) {
			return c.teamNoneNextEpoch(k, artifactID, va, pending, res)
		}
	}
	var lst approvedListing
	if team != "none" {
		dir, err := c.Directory()
		if err != nil {
			return nil, err
		}
		lst = c.listApproved(k, va, dir, pending, team, listed)
	}
	res.Listed, res.Unlisted = lst.listed, lst.unlisted
	if latest.Team == team && len(lst.members) == 0 {
		res.Unchanged = true
		return res, nil
	}

	next := latest
	next.Team = team
	next.Members = append(slices.Clone(latest.Members), lst.members...)
	slices.SortFunc(next.Members, func(a, b e2e.Member) int { return strings.Compare(a.User, b.User) })
	if err := c.putRecord(k, artifactID, va, next, nil, nil, ""); err != nil {
		return nil, err
	}
	for id, d := range lst.pins {
		if err := c.storePin(k, id, d.pin, d.basedOn); err != nil {
			return nil, fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", id, err)
		}
	}
	if err := c.readBack(k, artifactID, ""); err != nil {
		return nil, err
	}
	return res, nil
}
