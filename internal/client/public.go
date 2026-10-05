// Public links: the owner turns one on, and a visitor opens one. As elsewhere
// in this package, every byte of cryptography is built with internal/e2e.
package client

import (
	"errors"
	"fmt"
	"slices"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrPublicWritesWithOff means --writes was given with off, which has no
	// switch to set.
	ErrPublicWritesWithOff = errors.New("--writes sets who can write through a public link, so it goes with on, not off")
)

// PublicResult is what Public did. Link is the public link, empty while the
// artifact is private.
type PublicResult struct {
	Public       bool
	PublicWrites bool
	Epoch        int
	Link         string
	Unchanged    bool // the artifact already had this setting, so no record was written
	// NewEpoch is set when making the artifact private started a new epoch,
	// because anyone holding the link already has the old epoch's key.
	// Excluded are the team members who held a wrap, and are excluded.
	// Listed are approved team members the new record lists.
	NewEpoch bool
	Excluded []ExcludedUser
	Listed   []DirectoryUser
	// Resealed and ResealErr are as in EpochChange.
	Resealed  *ResealResult
	ResealErr error
}

// Public makes the artifact public, or sets whether a signed-in link holder
// may write, in a same-epoch record that carries the link token hash the
// server needs. writes is nil to leave the switch as it is, which for an
// artifact going public is off. The caller must be the owner. Off on a
// public artifact starts a new epoch, so the old link stops working, and off
// on a private one writes nothing. The link is built from the epoch's AK, opened from the
// owner's estate copy, before any record is written, so a host the link
// format refuses is an error with the artifact unchanged.
func (c *Client) Public(artifactID string, on bool, writes *bool) (*PublicResult, error) {
	if !on && writes != nil {
		return nil, ErrPublicWritesWithOff
	}
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
	if !on {
		if latest.Public {
			return c.publicOffNextEpoch(k, artifactID, va)
		}
		return &PublicResult{Epoch: latest.Epoch, Unchanged: true}, nil
	}
	next := latest
	next.Public = true
	if writes != nil {
		next.PublicWrites = *writes
	}
	res := &PublicResult{Public: true, PublicWrites: next.PublicWrites, Epoch: latest.Epoch}
	// Build the link first: a host the link format refuses must fail before
	// any record is written, or the artifact is public with no link.
	aks, err := c.epochAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	res.Link, err = e2e.PublicLink(c.Host, artifactID, aks[latest.Epoch], latest.Epoch, va.Chain.Bodies[0].OwnerFP)
	if err != nil {
		return nil, fmt.Errorf("cannot make a link for host %s: %w", c.Host, err)
	}
	// A member who rotated is listed under their new keys in any record the
	// owner writes, and a public artifact already set so is Unchanged only if
	// none waits.
	pending, err := c.pendingFor(k, artifactID, va)
	if err != nil {
		return nil, err
	}
	next.Members = slices.Clone(latest.Members)
	pins := map[string]pinDecision{}
	relisted, err := c.relistRotated(va, pending, next.Members, pins)
	if err != nil {
		return nil, err
	}
	if latest.Public && next.PublicWrites == latest.PublicWrites && !relisted {
		res.Unchanged = true
		return res, nil
	}
	if err := c.putRecord(k, artifactID, va, next, nil, nil, ""); err != nil {
		return nil, err
	}
	for id, d := range pins {
		if err := c.storePin(k, id, d.pin, d.basedOn); err != nil {
			return nil, fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", id, err)
		}
	}
	if err := c.readBack(k, artifactID, ""); err != nil {
		return nil, err
	}
	return res, nil
}

// publicOffNextEpoch makes a public artifact private in a next-epoch record.
func (c *Client) publicOffNextEpoch(k *UnlockedKeys, artifactID string, va *VerifiedArtifact) (*PublicResult, error) {
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	pending, err := c.pendingFor(k, artifactID, va)
	if err != nil {
		return nil, err
	}
	next := va.Chain.Latest
	next.Public, next.PublicWrites = false, false
	change, listed, err := c.putNextEpoch(k, artifactID, va, dir, pending, nextEpochRecord{next: next})
	if err != nil {
		return nil, err
	}
	if err := c.readBack(k, artifactID, ""); err != nil {
		return nil, err
	}
	c.resealInto(k, artifactID, change)
	return &PublicResult{Epoch: va.Chain.Latest.Epoch + 1, NewEpoch: true, Excluded: change.Excluded, Listed: listed,
		Resealed: change.Resealed, ResealErr: change.ResealErr}, nil
}

// linkTokenHashFor is the hash of the epoch's link token the server stores
// for a public record, from the owner's estate copy of the epoch's AK.
func (c *Client) linkTokenHashFor(k *UnlockedKeys, artifactID string, chain *e2e.Chain, epoch int) (string, error) {
	aks, err := c.epochAKs(k, artifactID, chain)
	if err != nil {
		return "", err
	}
	return linkTokenHash(aks[epoch], artifactID, epoch)
}

// OpenedLink is what OpenLink verified: the link, the chain it opens, and the
// editors whose served keys verified, by user ID. Editors are the writers the
// visitor trusts; an editor missing from it has no keys served or changed
// them. Handover is the latest administrator's handover in the chain, or nil;
// a visitor has no keyring to acknowledge it, so it is never Acked.
type OpenedLink struct {
	Link     *e2e.Link
	Chain    *e2e.Chain
	Editors  map[string]e2e.KeyPair
	Handover *HandoverNotice
}

// OpenLink opens a public link as a visitor, with no account: it reads the
// artifact's membership with the link's token and verifies the chain as
// e2e.VerifyLinkChain does. It writes no keyring.
func OpenLink(link string) (*OpenedLink, error) {
	l, err := e2e.ParseLink(link)
	if err != nil {
		return nil, err
	}
	return New(l.Host, "").OpenLink(l)
}

// OpenLink reads the membership of the link's artifact from c, with the
// link's token on the request, and verifies it against the link. Any caller
// may use it; a signed-in non-member reads at the same level as a visitor.
func (c *Client) OpenLink(l *e2e.Link) (*OpenedLink, error) {
	token, err := e2e.LinkToken(l.AK, l.Artifact, uint64(l.Epoch))
	if err != nil {
		return nil, err
	}
	lc := *c
	lc.LinkToken = e2e.B64(token)
	m, err := lc.Membership(l.Artifact)
	if err != nil {
		return nil, err
	}
	verified, err := e2e.VerifyLinkChain(e2e.LinkChainInput{
		Link: *l, Records: m.Records, Owners: m.Owners, Offers: m.Offers, Keys: m.Keys, Rotations: m.Rotations, Successors: m.Successors,
	})
	if err != nil {
		return nil, fmt.Errorf("the link's artifact %s does not verify: %w", l.Artifact, err)
	}
	out := &OpenedLink{Link: l, Chain: verified.Chain, Editors: verified.Editors, Handover: handoverOf(verified.Chain, m, 0)}
	if out.Handover != nil && c.OnHandover != nil {
		c.OnHandover(l.Artifact, *out.Handover)
	}
	return out, nil
}
