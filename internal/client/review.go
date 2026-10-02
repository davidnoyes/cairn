// Reviewing a removed editor's versions: the owner's review list and
// vouches. As elsewhere in this package, every byte of cryptography is built
// with internal/e2e.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrReviewInconsistent means the server lists a version for review
	// whose pusher the verified chain says is the owner or a listed editor.
	ErrReviewInconsistent = errors.New("the server's review list contradicts the verified membership chain")
	// ErrVouchNotOwner means the caller is not the owner the verified chain
	// names, under their current keys, so their client does not vouch.
	ErrVouchNotOwner = errors.New("only the artifact's owner can vouch for a version")
)

// ReviewVersion is one entry of GET /api/artifacts/{id}/review: a version
// whose pusher is not the owner or a listed editor and that has no vouch.
// PushedBy is empty for a version whose pusher's account is gone.
type ReviewVersion struct {
	ID        string
	Seq       int
	PushedBy  string
	CreatedAt string
}

type reviewWire struct {
	ID        string  `json:"id"`
	Seq       int     `json:"seq"`
	PushedBy  *string `json:"pushedBy"`
	CreatedAt string  `json:"createdAt"`
}

// Review lists the versions the owner should review. It verifies the
// artifact's chain and checks each entry the server lists against the
// latest verified record: an entry pushed by the owner or a listed editor is
// ErrReviewInconsistent, and nothing is dropped.
func (c *Client) Review(artifactID string) ([]ReviewVersion, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	var resp []reviewWire
	if err := c.doJSON("GET", "/api/artifacts/"+artifactID+"/review", nil, &resp); err != nil {
		return nil, err
	}
	latest := va.Chain.Latest
	out := make([]ReviewVersion, 0, len(resp))
	for _, w := range resp {
		v := ReviewVersion{ID: w.ID, Seq: w.Seq, CreatedAt: w.CreatedAt}
		if w.PushedBy != nil {
			v.PushedBy = *w.PushedBy
		}
		switch {
		case v.PushedBy != "" && v.PushedBy == latest.Owner:
			return nil, fmt.Errorf("%w: version %s was pushed by the owner", ErrReviewInconsistent, v.ID)
		case v.PushedBy != "" && slices.ContainsFunc(latest.Members, func(m e2e.Member) bool {
			return m.User == v.PushedBy && m.Role == "editor"
		}):
			return nil, fmt.Errorf("%w: version %s was pushed by %s, a listed editor", ErrReviewInconsistent, v.ID, v.PushedBy)
		}
		out = append(out, v)
	}
	return out, nil
}

// Vouch signs the owner's vouch for versionID, with an empty manifest until
// milestone 4 adds signed manifests, and stores it. It refuses, before asking
// the server, a caller who is not the owner the verified chain names under
// the caller's current fingerprint.
func (c *Client) Vouch(artifactID, versionID string) error {
	k, err := c.Unlock()
	if err != nil {
		return err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return err
	}
	if err := c.checkHandover(k, artifactID, va); err != nil {
		return err
	}
	if latest := va.Chain.Latest; latest.Owner != k.UserID || latest.OwnerFP != k.FP {
		return ErrVouchNotOwner
	}
	body, err := json.Marshal(e2e.VouchBody{V: 1, Artifact: artifactID, Version: versionID})
	if err != nil {
		return err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "vouch", body)
	if err != nil {
		return err
	}
	return c.doJSON("PUT", "/api/artifacts/"+artifactID+"/versions/"+versionID+"/vouch", map[string]any{"vouch": env}, nil)
}
