// Next-epoch records: the owner's client starts a new epoch when a change
// removes a member, demotes an editor, makes a public artifact private, or
// ends a team share while a team member holds a wrap. As elsewhere in this
// package, every byte of cryptography is built with internal/e2e.
package client

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrNotMember means the user is neither listed nor holding a wrap, so
	// there is nothing to remove.
	ErrNotMember = errors.New("the user is not a member of the artifact")
	// ErrMemberKeyChanged means a member the record lists has keys other than
	// the ones it lists them under. A next-epoch record lists every member
	// under their current fingerprint, so the owner decides about them first.
	ErrMemberKeyChanged = errors.New("a member's keys changed since the record listed them")
	// ErrUnshareOwner means the owner tried to remove themselves.
	ErrUnshareOwner = errors.New("the owner cannot be removed from the artifact")
)

// newAK makes the AK of a new epoch. Tests replace it.
var newAK = func() ([]byte, error) {
	ak := make([]byte, 32)
	_, err := rand.Read(ak)
	return ak, err
}

// ExcludedUser is a user a next-epoch record excluded, and why.
type ExcludedUser struct {
	User   DirectoryUser
	Reason string
}

// EpochChange is what a command that started a new epoch reports. Link is
// the artifact's new public link when it stays public: the old one stops
// working. Resealed is what re-sealing the artifact's data under the new
// epoch did, and ResealErr why it stopped short: cairn reseal runs it again.
type EpochChange struct {
	NewEpoch  bool
	Excluded  []ExcludedUser
	Link      string
	Resealed  *ResealResult
	ResealErr error
}

// nextEpochRecord is what putNextEpoch needs to know about the change.
type nextEpochRecord struct {
	// next is the record to write, with the members, team, and public
	// switches the change wants. putNextEpoch fills in the epoch, akCommit,
	// excluded, and the team members it lists.
	next e2e.MembershipBody
	// decided is a member whose pin the caller already decided, or "".
	decided string
	// exclude is a user the caller removes, listed or holding a wrap, or "".
	exclude string
	// newOwner is the listed member who takes ownership in this record, or
	// "". They leave the members list without being removed.
	newOwner string
	// prevOwner is the owner who gives up ownership in this record and is
	// excluded from it, or "".
	prevOwner string
}

// nextEpochBuild is a next-epoch record built from a nextEpochRecord, and
// not yet sent.
type nextEpochBuild struct {
	// next is the record, before its chain fields are set (signNext).
	next e2e.MembershipBody
	// wraps and estate are the new epoch's wraps and estate copy; estate is
	// sealed under k.EK.
	wraps, estate []map[string]any
	linkHash      string
	// aks holds the AK of every epoch, the new one included.
	aks    map[int][]byte
	change *EpochChange
	lst    approvedListing
}

// putNextEpoch signs and PUTs a next-epoch record built from r, as
// buildNextEpoch makes it, then stores the pins the build decided.
func (c *Client) putNextEpoch(k *UnlockedKeys, artifactID string, va *VerifiedArtifact, dir []DirectoryUser, pending []PendingUser, r nextEpochRecord) (*EpochChange, []DirectoryUser, error) {
	b, err := c.buildNextEpoch(k, artifactID, va, dir, pending, r)
	if err != nil {
		return nil, nil, err
	}
	if err := c.putRecord(k, artifactID, va, b.next, b.wraps, b.estate, b.linkHash); err != nil {
		return nil, nil, err
	}
	for id, d := range b.lst.pins {
		if err := c.storePin(k, id, d.pin, d.basedOn); err != nil {
			return nil, nil, fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", id, err)
		}
	}
	return b.change, b.lst.listed, nil
}

// linkTokenHash is the hash of the link token an epoch's AK makes, which the
// server stores for a public record.
func linkTokenHash(ak []byte, artifactID string, epoch int) (string, error) {
	token, err := e2e.LinkToken(ak, artifactID, uint64(epoch))
	if err != nil {
		return "", err
	}
	return e2e.LinkTokenHash(token), nil
}

// errRotationsUnreadable is the refusal for a user the server calls rotated
// and whose rotation records could not be read: without them cairn cannot
// tell which keys their wraps were made for, or whether they changed keys.
func errRotationsUnreadable(p PendingUser) error {
	return fmt.Errorf("cannot read the rotation records of %s (%s): %w; without them cairn cannot tell which keys their wraps were made for. Retry when the records can be read", p.User.Email, p.User.ID, p.RotationsErr)
}

// buildNextEpoch builds a next-epoch record from r, and sends nothing. It
// makes the new AK, wraps it to every listed member, seals the estate copy,
// and excludes every user the record removes or drops, and every team member
// who holds a wrap and cannot be listed. The server refuses a record that
// leaves any of them out of both lists, and the CLI is not interactive, so a
// team member whose approval fails a check is excluded: the owner lists them
// again by name with Share.
func (c *Client) buildNextEpoch(k *UnlockedKeys, artifactID string, va *VerifiedArtifact, dir []DirectoryUser, pending []PendingUser, r nextEpochRecord) (*nextEpochBuild, error) {
	latest := va.Chain.Latest
	epoch := latest.Epoch + 1
	// Defense in depth behind VerifyChain's epoch pin, which already refuses a
	// stale epoch.
	if err := e2e.CheckEncryptEpoch(va.Keyring.EpochPin(artifactID), epoch); err != nil {
		return nil, err
	}
	next := r.next
	byID := map[string]DirectoryUser{}
	for _, u := range dir {
		byID[u.ID] = u
	}
	inMembers := func(id string) bool {
		return slices.ContainsFunc(next.Members, func(m e2e.Member) bool { return m.User == id })
	}

	// Team members who hold a wrap are listed or excluded.
	lst := approvedListing{pins: map[string]pinDecision{}}
	if next.Team != "none" {
		var err error
		if lst, err = c.listApproved(k, va, dir, pending, next.Team, func(id string) bool { return inMembers(id) || id == r.exclude }); err != nil {
			return nil, err
		}
	}
	next.Members = append(slices.Clone(next.Members), lst.members...)
	slices.SortFunc(next.Members, func(a, b e2e.Member) int { return strings.Compare(a.User, b.User) })

	// A listed member whose rotation chain verified is listed under their
	// current keys, and holds wraps under them already. rotated means listed
	// and rotated: the guard on latest.Members keeps out an unlisted holder
	// who rotated, whom the loop below excludes.
	rotated := map[string]bool{}
	for _, p := range pending {
		if u, ok := byID[p.User.ID]; ok && p.State == PendingRotated &&
			slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == p.User.ID }) {
			rotated[u.ID] = true
		}
	}
	for i, m := range next.Members {
		if rotated[m.User] {
			next.Members[i].FP = byID[m.User].FP
		}
	}

	change := &EpochChange{NewEpoch: true}
	exclude := map[string]e2e.ExcludedEntry{}
	exclude1 := func(u DirectoryUser, fp, reason string) {
		email := e2e.NormalizeEmail(u.Email)
		if email == "" {
			// A deleted account has no email to give. The server takes any
			// for a user it no longer has; the ID and fingerprint still match.
			email = u.ID
		}
		exclude[u.ID] = e2e.ExcludedEntry{User: u.ID, FP: fp, Email: email}
		change.Excluded = append(change.Excluded, ExcludedUser{User: u, Reason: reason})
	}
	// Removed members, under the fingerprint the previous record lists them.
	for _, m := range latest.Members {
		if inMembers(m.User) || m.User == r.newOwner {
			continue
		}
		u, ok := byID[m.User]
		if !ok {
			exclude1(DirectoryUser{ID: m.User, FP: m.FP}, m.FP, "removed; their account was deleted")
			continue
		}
		exclude1(u, m.FP, "removed")
	}
	if r.prevOwner != "" {
		// The directory does not list a deactivated owner; the server takes
		// any email for one.
		u, ok := byID[r.prevOwner]
		if !ok {
			u = DirectoryUser{ID: r.prevOwner, FP: latest.OwnerFP}
		}
		exclude1(u, latest.OwnerFP, "the previous owner, who was not kept")
	}
	for _, p := range pending {
		if exclude[p.User.ID].User != "" || inMembers(p.User.ID) {
			continue
		}
		switch {
		case p.State == PendingKeyChanged && p.RotationsErr != nil:
			// The server says they rotated, and without their records no pin
			// says which key their wraps were made for.
			return nil, errRotationsUnreadable(p)
		case p.State == PendingKeyChanged:
			// Not listed, so a wrap they hold was made for a key other than
			// their current one. The server accepts only a fingerprint it can
			// account for, which the owner's client knows from its pin.
			pin, ok := va.Keyring.Pins[p.User.ID]
			if !ok || pin.FP == p.User.FP {
				return nil, fmt.Errorf("%s holds a wrap made for a key that is no longer theirs, and cairn does not know which; share with them again with cairn share --accept-new-key, then unshare them", p.User.Email)
			}
			reason := "their keys changed after they were wrapped to"
			if p.User.ID == r.exclude {
				reason = "removed"
			}
			exclude1(p.User, pin.FP, reason)
		case p.User.ID == r.exclude:
			exclude1(p.User, p.User.FP, "removed")
		case p.State == PendingApproved || p.State == PendingRotated:
			// A rotated user who is not listed holds wraps under their new keys
			// and an approval for their old ones, which no record can list.
			reason := "team sharing ended while they held a wrap"
			if p.State == PendingRotated {
				reason = "their keys rotated after they were approved, so the approval no longer checks out"
			}
			if i := slices.IndexFunc(lst.unlisted, func(u UnlistedUser) bool { return u.User.ID == p.User.ID }); i >= 0 {
				reason = fmt.Sprintf("their approval does not check out: %v", lst.unlisted[i].Err)
			}
			exclude1(p.User, p.User.FP, reason)
		}
	}

	// Every member is listed under their current keys, and a pinned key that
	// differs from them is the owner's to decide about.
	for _, m := range next.Members {
		u, ok := byID[m.User]
		if !ok {
			return nil, fmt.Errorf("the account of member %s was deleted, so no new key can be wrapped to them; remove them first with cairn unshare %s %s", m.User, artifactID, m.User)
		}
		if m.FP != u.FP {
			// A member who rotated, whose records cannot be read, is not
			// known to have changed keys the owner is to decide about.
			if i := slices.IndexFunc(pending, func(p PendingUser) bool { return p.User.ID == m.User && p.RotationsErr != nil }); i >= 0 {
				return nil, errRotationsUnreadable(pending[i])
			}
			return nil, fmt.Errorf("%w: %s (%s); share with them again with cairn share --accept-new-key, or remove them with cairn unshare", ErrMemberKeyChanged, u.Email, u.ID)
		}
		if m.User == r.decided {
			continue
		}
		state, pin, err := c.checkPin(va.Keyring, u, false, va.Membership.Rotations)
		if err != nil {
			return nil, fmt.Errorf("member %s: %w", u.Email, err)
		}
		// A member the owner holds no pin for is pinned too when their chain
		// verified: it is anchored on the fingerprint the owner's record listed.
		if pin != nil && (state == e2e.PinRotated || rotated[m.User]) {
			lst.pins[m.User] = pinDecision{*pin, va.Keyring.Pins[m.User].FP}
		}
	}

	// An entry stays until a listed member matches it. A user listed again by
	// name drops theirs.
	for _, x := range latest.Excluded {
		matched := slices.ContainsFunc(next.Members, func(m e2e.Member) bool {
			return x.User == m.User || x.FP == m.FP || e2e.NormalizeEmail(x.Email) == e2e.NormalizeEmail(byID[m.User].Email)
		})
		if _, again := exclude[x.User]; !matched && !again {
			exclude[x.User] = x
		}
	}
	next.Excluded = make([]e2e.ExcludedEntry, 0, len(exclude))
	for _, x := range exclude {
		next.Excluded = append(next.Excluded, x)
	}
	slices.SortFunc(next.Excluded, func(a, b e2e.ExcludedEntry) int { return strings.Compare(a.User, b.User) })

	// The new epoch's key, which no earlier epoch used. The caller is the
	// owner, or the editor about to become one.
	aks, err := c.callerAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	ak, err := newAK()
	if err != nil {
		return nil, err
	}
	var earlier [][]byte
	for _, old := range aks {
		earlier = append(earlier, old)
	}
	if err := e2e.CheckNewAK(ak, earlier); err != nil {
		return nil, err
	}
	commit, err := e2e.AKCommit(ak, artifactID, uint64(epoch))
	if err != nil {
		return nil, err
	}
	next.Epoch, next.AKCommit = epoch, commit
	aks[epoch] = ak

	// The new epoch for every listed member, and every earlier epoch for one
	// the record adds: not listed under this fingerprint before, and holding
	// no wrap through an approval.
	var wraps []map[string]any
	for _, m := range next.Members {
		u := byID[m.User]
		epochs := []int{epoch}
		held := rotated[m.User] || slices.ContainsFunc(latest.Members, func(l e2e.Member) bool { return l.User == m.User && l.FP == m.FP }) ||
			slices.ContainsFunc(pending, func(p PendingUser) bool {
				return p.User.ID == m.User && p.State == PendingApproved && p.User.FP == m.FP
			})
		if !held {
			epochs = nil
			for e := 1; e <= epoch; e++ {
				epochs = append(epochs, e)
			}
		}
		for _, e := range epochs {
			w, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
				Purpose: "ak", Artifact: artifactID, Epoch: uint64(e), RecipientID: u.ID, RecipientPub: u.X25519Pub,
			}, aks[e])
			if err != nil {
				return nil, err
			}
			wraps = append(wraps, map[string]any{"user": u.ID, "epoch": e, "wrapped": e2e.B64(w)})
		}
	}
	ekKey, err := e2e.EKSealKey(k.EK)
	if err != nil {
		return nil, err
	}
	sealed, err := e2e.Seal(rand.Reader, ekKey, estateFields(artifactID, epoch), ak)
	if err != nil {
		return nil, err
	}
	estate := []map[string]any{{"epoch": epoch, "sealed": e2e.B64(sealed)}}

	// Build the link first: a host the link format refuses must fail before
	// any record is written.
	var linkHash string
	if next.Public {
		if change.Link, err = e2e.PublicLink(c.Host, artifactID, ak, epoch, va.Chain.Bodies[0].OwnerFP); err != nil {
			return nil, fmt.Errorf("cannot make a link for host %s: %w", c.Host, err)
		}
		if linkHash, err = linkTokenHash(ak, artifactID, epoch); err != nil {
			return nil, err
		}
	}
	return &nextEpochBuild{next: next, wraps: wraps, estate: estate, linkHash: linkHash, aks: aks, change: change, lst: lst}, nil
}

// readBack verifies the artifact after the server accepted a record. A
// failure still names link, the new public link, when there is one: the old
// link already stopped working.
func (c *Client) readBack(k *UnlockedKeys, artifactID, link string) error {
	if _, err := c.VerifyArtifact(k, artifactID, k.FP); err != nil {
		if link != "" {
			return fmt.Errorf("the server accepted the new membership record, but reading it back failed: %w; the new public link is %s", err, link)
		}
		return fmt.Errorf("the server accepted the new membership record, but reading it back failed: %w", err)
	}
	return nil
}

// UnshareResult is what Unshare did.
type UnshareResult struct {
	EpochChange
	User  DirectoryUser
	Epoch int
	// Listed are approved team members the new record lists, with the role
	// the team grants.
	Listed []DirectoryUser
}

// Unshare removes who from an artifact in a next-epoch record: the new epoch's
// AK is wrapped to every member who stays, and who is excluded is listed in
// the result. who is a member, or a team member who holds a wrap and is not
// listed. The caller must be the owner.
func (c *Client) Unshare(artifactID, who string) (*UnshareResult, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	if err := c.checkHandover(k, artifactID, va); err != nil {
		return nil, err
	}
	latest := va.Chain.Latest
	if latest.Owner != k.UserID || latest.OwnerFP != k.FP {
		return nil, ErrNotOwner
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	u, err := FindUser(dir, who)
	if i := slices.IndexFunc(latest.Members, func(m e2e.Member) bool { return m.User == who }); errors.Is(err, ErrUnknownUser) && i >= 0 {
		// A listed member whose account was deleted, named by user ID.
		u, err = DirectoryUser{ID: who, FP: latest.Members[i].FP}, nil
	}
	if err != nil {
		return nil, err
	}
	if u.ID == k.UserID {
		return nil, ErrUnshareOwner
	}
	pending, err := c.pendingFor(k, artifactID, va)
	if err != nil {
		return nil, err
	}
	next := latest
	next.Members = slices.DeleteFunc(slices.Clone(latest.Members), func(m e2e.Member) bool { return m.User == u.ID })
	if len(next.Members) == len(latest.Members) && !slices.ContainsFunc(pending, func(p PendingUser) bool {
		return p.User.ID == u.ID && (p.State == PendingApproved || p.State == PendingKeyChanged || p.State == PendingRotated)
	}) {
		return nil, fmt.Errorf("%w: %s", ErrNotMember, u.Email)
	}
	// Excluded whether listed or not, so a server that still reports a listed
	// user approved cannot get them listed again by the team.
	change, listed, err := c.putNextEpoch(k, artifactID, va, dir, pending, nextEpochRecord{next: next, exclude: u.ID})
	if err != nil {
		return nil, err
	}
	if err := c.readBack(k, artifactID, change.Link); err != nil {
		return nil, err
	}
	c.resealInto(k, artifactID, change)
	return &UnshareResult{EpochChange: *change, User: u, Epoch: latest.Epoch + 1, Listed: listed}, nil
}
