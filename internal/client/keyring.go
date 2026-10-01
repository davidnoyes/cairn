// The user's keyring: reading it against the anchor, writing it with a
// merge on conflict, and the verified membership chain that records its
// epochs entry there.
package client

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// AnchorStore keeps the keyring anchor for each account this client signs
// in to. It holds nothing secret, and signing out must not clear it. Load
// returns nil, nil when no anchor is stored, and an error, never nil, when
// a stored one cannot be read.
type AnchorStore interface {
	LoadAnchor(userID string) (*e2e.KeyringAnchor, error)
	SaveAnchor(userID string, a e2e.KeyringAnchor) error
}

// keyringRetries bounds how many times UpdateKeyring reads again and
// re-applies its change after another device wrote first.
const keyringRetries = 5

// ErrKeyringBusy means every attempt UpdateKeyring made lost to a write by
// another device.
var ErrKeyringBusy = errors.New("the keyring kept changing on the server while this client tried to update it; try again")

type keyringWire struct {
	Rev     int    `json:"rev"`
	Keyring string `json:"keyring"`
}

func (c *Client) anchors() (AnchorStore, error) {
	if c.Anchors == nil {
		return nil, errors.New("this client has no keyring anchor store")
	}
	return c.Anchors, nil
}

// ReadKeyring fetches the keyring, opens it against the stored anchor, and
// stores the new anchor. A keyring that fails to open or parse, or that the
// anchor refuses, is an error.
func (c *Client) ReadKeyring(k *UnlockedKeys) (*e2e.Keyring, error) {
	kr, _, err := c.readKeyring(k)
	return kr, err
}

func (c *Client) readKeyring(k *UnlockedKeys) (*e2e.Keyring, e2e.KeyringAnchor, error) {
	store, err := c.anchors()
	if err != nil {
		return nil, e2e.KeyringAnchor{}, err
	}
	anchor, err := store.LoadAnchor(k.UserID)
	if err != nil {
		return nil, e2e.KeyringAnchor{}, fmt.Errorf("reading the keyring anchor: %w", err)
	}
	var resp keyringWire
	if err := c.doJSON("GET", "/api/me/keyring", nil, &resp); err != nil {
		return nil, e2e.KeyringAnchor{}, err
	}
	sealed, err := e2e.UnB64(resp.Keyring)
	if err != nil {
		return nil, e2e.KeyringAnchor{}, fmt.Errorf("the keyring is not base64: %w", err)
	}
	kr, next, err := e2e.OpenKeyring(k.MKSealKey, resp.Rev, sealed, anchor)
	if err != nil {
		return nil, e2e.KeyringAnchor{}, fmt.Errorf("refusing the server's keyring: %w", err)
	}
	if err := store.SaveAnchor(k.UserID, next); err != nil {
		return nil, e2e.KeyringAnchor{}, fmt.Errorf("saving the keyring anchor: %w", err)
	}
	return kr, next, nil
}

// UpdateKeyring reads the keyring, applies change to a copy, and writes it
// at the next rev. When another device wrote first, the server answers 409;
// UpdateKeyring then reads again, checks it against the anchor, and applies
// change to the fresh copy, so both devices' changes land. change must
// therefore be safe to call more than once. It returns the keyring written.
func (c *Client) UpdateKeyring(k *UnlockedKeys, change func(kr *e2e.Keyring) error) (*e2e.Keyring, error) {
	store, err := c.anchors()
	if err != nil {
		return nil, err
	}
	for range keyringRetries {
		cur, _, err := c.readKeyring(k)
		if err != nil {
			return nil, err
		}
		next := cur.Clone()
		if err := change(next); err != nil {
			return nil, err
		}
		next.Rev = cur.Rev + 1
		sealed, err := e2e.SealKeyring(rand.Reader, k.MKSealKey, next)
		if err != nil {
			return nil, err
		}
		err = c.doJSON("PUT", "/api/me/keyring", keyringWire{Rev: next.Rev, Keyring: e2e.B64(sealed)}, nil)
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := store.SaveAnchor(k.UserID, e2e.KeyringAnchorOf(next.Rev, sealed)); err != nil {
			return nil, fmt.Errorf("the keyring was written, but saving its anchor failed: %w", err)
		}
		return next, nil
	}
	return nil, ErrKeyringBusy
}

// VerifiedArtifact is an artifact's membership chain after the client
// verified it against the keyring.
type VerifiedArtifact struct {
	Chain      *e2e.Chain
	Membership *Membership
	Keyring    *e2e.Keyring
}

// VerifyArtifact reads an artifact's membership chain and verifies it. The
// first record is anchored at the creator's pinned fingerprint, the
// caller's own when the caller created it, or on first sight the
// directory's, which is then pinned unverified. The keyring's epochs entry
// is the pin, so a chain shorter than the stored seq, or forked at it, is
// refused. currentOwnerFP, when set, is the fingerprint the latest record
// must be signed under. After success, the keyring stores the chain's
// epoch, seq, and head.
func (c *Client) VerifyArtifact(k *UnlockedKeys, artifactID, currentOwnerFP string) (*VerifiedArtifact, error) {
	kr, err := c.ReadKeyring(k)
	if err != nil {
		return nil, err
	}
	m, err := c.Membership(artifactID)
	if err != nil {
		return nil, err
	}
	if len(m.Records) == 0 {
		return nil, fmt.Errorf("artifact %s: %w: no records", artifactID, e2e.ErrChain)
	}
	creator := m.Records[0].Signer
	anchor, newPin := k.FP, (*e2e.Pin)(nil)
	if creator != k.UserID {
		if p, ok := kr.Pins[creator]; ok {
			anchor = p.FP
		} else {
			u, err := c.DirectoryUser(creator)
			if err != nil {
				return nil, fmt.Errorf("looking up the creator of artifact %s: %w", artifactID, err)
			}
			_, anchor = e2e.PinState(nil, u.X25519Pub, u.Ed25519Pub)
			newPin = &e2e.Pin{FP: anchor, State: e2e.PinUnverified}
		}
	}
	chain, err := e2e.VerifyChain(e2e.ChainInput{
		Artifact: artifactID, Records: m.Records, Owners: m.Owners, Offers: m.Offers,
		Anchor: anchor, CurrentOwnerFP: currentOwnerFP, Pin: kr.EpochPin(artifactID),
	})
	if err != nil {
		return nil, fmt.Errorf("the membership of artifact %s does not verify: %w", artifactID, err)
	}
	kr, err = c.recordChain(k, kr, artifactID, chain, creator, newPin)
	if err != nil {
		return nil, err
	}
	return &VerifiedArtifact{Chain: chain, Membership: m, Keyring: kr}, nil
}

// recordChain stores a verified chain as artifactID's epochs entry, and a
// first-sight pin for its creator, unless the keyring already holds both.
// On a merge it keeps whichever entry has the higher seq, so a later chain
// another device stored is not replaced by this one.
func (c *Client) recordChain(k *UnlockedKeys, kr *e2e.Keyring, artifactID string, chain *e2e.Chain, creator string, pin *e2e.Pin) (*e2e.Keyring, error) {
	want := e2e.KeyringEpoch{Epoch: chain.Latest.Epoch, Seq: chain.Latest.Seq, Head: chain.Head, Ack: kr.Epochs[artifactID].Ack}
	if kr.Epochs[artifactID] == want && pin == nil {
		return kr, nil
	}
	return c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		if cur, ok := kr.Epochs[artifactID]; !ok || cur.Seq < chain.Latest.Seq {
			kr.SetEpoch(artifactID, chain)
		}
		if _, ok := kr.Pins[creator]; pin != nil && !ok {
			kr.Pins[creator] = *pin
		}
		return nil
	})
}
