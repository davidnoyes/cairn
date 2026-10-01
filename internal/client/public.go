// Public links: the owner turns one on, and a visitor opens one. As elsewhere
// in this package, every byte of cryptography is built with internal/e2e.
package client

import (
	"errors"
	"fmt"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrPublicOffNeedsNextEpoch means making a public artifact private needs
	// a new epoch, because anyone holding the link already has the epoch's
	// key.
	ErrPublicOffNeedsNextEpoch = errors.New("making a public artifact private needs a new epoch, which this version of cairn cannot create yet")
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
}

// Public makes the artifact public, or sets whether a signed-in link holder
// may write, in a same-epoch record that carries the link token hash the
// server needs. writes is nil to leave the switch as it is, which for an
// artifact going public is off. The caller must be the owner. Off on a
// public artifact is ErrPublicOffNeedsNextEpoch, and off on a private one
// writes nothing. The link is built from the epoch's AK, opened from the
// owner's estate copy.
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
	latest := va.Chain.Latest
	if latest.Owner != k.UserID || latest.OwnerFP != k.FP {
		return nil, ErrNotOwner
	}
	if !on {
		if latest.Public {
			return nil, ErrPublicOffNeedsNextEpoch
		}
		return &PublicResult{Epoch: latest.Epoch, Unchanged: true}, nil
	}
	next := latest
	next.Public = true
	if writes != nil {
		next.PublicWrites = *writes
	}
	res := &PublicResult{Public: true, PublicWrites: next.PublicWrites, Epoch: latest.Epoch}
	if latest.Public && next.PublicWrites == latest.PublicWrites {
		res.Unchanged = true
	} else if err := c.putRecord(k, artifactID, va, next, nil); err != nil {
		return nil, err
	} else if _, err := c.VerifyArtifact(k, artifactID, k.FP); err != nil {
		return nil, fmt.Errorf("the server accepted the new membership record, but reading it back failed: %w", err)
	}
	aks, err := c.epochAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	res.Link, err = e2e.PublicLink(c.Host, artifactID, aks[latest.Epoch], latest.Epoch, va.Chain.Bodies[0].OwnerFP)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// linkTokenHashFor is the hash of the epoch's link token the server stores
// for a public record, from the owner's estate copy of the epoch's AK.
func (c *Client) linkTokenHashFor(k *UnlockedKeys, artifactID string, chain *e2e.Chain, epoch int) (string, error) {
	aks, err := c.epochAKs(k, artifactID, chain)
	if err != nil {
		return "", err
	}
	token, err := e2e.LinkToken(aks[epoch], artifactID, uint64(epoch))
	if err != nil {
		return "", err
	}
	return e2e.LinkTokenHash(token), nil
}

// OpenedLink is what OpenLink verified: the link and the chain it opens.
type OpenedLink struct {
	Link  *e2e.Link
	Chain *e2e.Chain
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
	chain, err := e2e.VerifyLinkChain(e2e.LinkChainInput{
		Link: *l, Records: m.Records, Owners: m.Owners, Offers: m.Offers, Keys: m.Keys,
	})
	if err != nil {
		return nil, fmt.Errorf("the link's artifact %s does not verify: %w", l.Artifact, err)
	}
	return &OpenedLink{Link: l, Chain: chain}, nil
}
