// Reviewing a removed editor's versions: the owner's review list and
// vouches. As elsewhere in this package, every byte of cryptography is built
// with internal/e2e.
package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
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

// ErrVouchManifest means the manifest the server serves for a version is not
// the one its listed manifestHash names, or does not verify.
var ErrVouchManifest = errors.New("the version's manifest does not match its manifestHash")

// ErrVouchSignerGone means the version's manifest was signed by an account
// that is disabled or deleted, so the directory no longer publishes its keys
// and the signature cannot be checked.
var ErrVouchSignerGone = errors.New("the account that pushed this version is disabled or deleted, so its keys can no longer be checked: an admin can re-enable the account, or you can delete the version (in the admin page, or with DELETE /api/artifacts/{id}/versions/{vid})")

// maxManifestBytes caps the sealed manifest the client reads; the server
// refuses to store a larger one.
const maxManifestBytes = e2e.MaxManifestBytes

// checkManifest fetches v's manifest, opens it under the owner's AK for v's
// epoch, and verifies it: the envelope's signature must verify under a key
// of its signer, who must be a user the verified chain has ever listed (the
// owner or an editor, possibly since removed, which is why a version needs a
// vouch). A key counts when its fingerprint is one the chain lists for the
// signer, whether it is their current key or one an earlier rotation left
// behind (see manifestSignerKeys). The body must name this artifact,
// version, and epoch, and hash to v's manifestHash.
func (c *Client) checkManifest(k *UnlockedKeys, chain *e2e.Chain, artifactID string, v *store.Version) error {
	_, _, err := c.verifyManifest(k, chain, artifactID, v)
	return err
}

// verifyManifest is checkManifest, and returns the signer and the body it
// verified.
func (c *Client) verifyManifest(k *UnlockedKeys, chain *e2e.Chain, artifactID string, v *store.Version) (string, e2e.ManifestBody, error) {
	aks, err := c.callerAKs(k, artifactID, chain)
	if err != nil {
		return "", e2e.ManifestBody{}, err
	}
	ak := aks[v.Epoch]
	if ak == nil {
		return "", e2e.ManifestBody{}, fmt.Errorf("%w: no key for epoch %d", ErrVouchManifest, v.Epoch)
	}
	sealed, err := c.getBytes("/api/artifacts/" + artifactID + "/versions/" + v.ID + "/manifest")
	if err != nil {
		return "", e2e.ManifestBody{}, err
	}
	envJSON, err := e2e.OpenBlob(ak, e2e.BlobContext{Artifact: artifactID, Version: v.ID, Kind: "manifest"}, sealed)
	if err != nil {
		return "", e2e.ManifestBody{}, fmt.Errorf("%w: %v", ErrVouchManifest, err)
	}
	var env e2e.Envelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return "", e2e.ManifestBody{}, fmt.Errorf("%w: %v", ErrVouchManifest, err)
	}
	keys, err := c.manifestSignerKeys(k, chain, env.Signer)
	if err != nil {
		return "", e2e.ManifestBody{}, err
	}
	var body e2e.ManifestBody
	verified := false
	var openErr error
	for _, pub := range keys {
		body = e2e.ManifestBody{}
		if openErr = e2e.OpenEnvelope(env, pub, "manifest", &body); openErr == nil {
			verified = true
			break
		}
	}
	if !verified {
		return "", e2e.ManifestBody{}, fmt.Errorf("%w: the signature does not verify under any key the chain lists for %q: %v", ErrVouchManifest, env.Signer, openErr)
	}
	if body.Artifact != artifactID || body.Version != v.ID || body.Epoch != v.Epoch {
		return "", e2e.ManifestBody{}, fmt.Errorf("%w: it names another artifact, version, or epoch", ErrVouchManifest)
	}
	if e2e.BodyHash(env.Body) != v.ManifestHash {
		return "", e2e.ManifestBody{}, ErrVouchManifest
	}
	return env.Signer, body, nil
}

// signerKeys is a pair of public keys: X25519 for wrapping, Ed25519 for
// signing.
type signerKeys struct{ x25519, ed25519 []byte }

// manifestSignerKeys returns the Ed25519 keys of signer, a user some record
// of the verified chain lists as owner or member, that a manifest may be
// signed under. A key pair counts when its fingerprint is one the chain
// lists for them. The fingerprint is a hash of the keys, so the keys may
// come from anywhere: the caller's own keys for the caller, else the
// directory's current ones, and the old and new keys of the signer's
// rotation records, which is how an editor who has rotated since pushing
// still has their version vouched.
//
// A disabled or deleted account is not in the directory, and its rotation
// records are not served either, so when no key matches and the directory
// answered 404 for the signer, the error is ErrVouchSignerGone. A 404 from
// the rotations route alone is not that: the account is published.
func (c *Client) manifestSignerKeys(k *UnlockedKeys, chain *e2e.Chain, signer string) ([][]byte, error) {
	listed := map[string]bool{}
	for _, b := range chain.Bodies {
		if b.Owner == signer {
			listed[b.OwnerFP] = true
		}
		for _, m := range b.Members {
			if m.User == signer {
				listed[m.FP] = true
			}
		}
	}
	if len(listed) == 0 {
		return nil, fmt.Errorf("%w: the manifest is signed by %q, whom the membership chain never lists", ErrVouchManifest, signer)
	}
	var pairs []signerKeys
	unpublished := false
	if signer == k.UserID {
		pairs = append(pairs, signerKeys{k.X25519Pub, k.Ed25519Pub})
	} else {
		u, err := c.DirectoryUser(signer)
		switch {
		case isNotFound(err):
			unpublished = true
		case err != nil:
			return nil, err
		default:
			pairs = append(pairs, signerKeys{u.X25519Pub, u.Ed25519Pub})
		}
	}
	records, err := c.Rotations(signer)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	for _, env := range records {
		var b e2e.RotationBody
		// A record that fails to decode, or a malformed key, is skipped on
		// purpose: skipping can only shrink the candidate set.
		if e2e.DecodeStrict(env.Body, &b) != nil {
			continue
		}
		for _, kp := range []e2e.KeyPair{b.Old, b.New} {
			x, errX := e2e.UnB64(kp.X25519)
			ed, errEd := e2e.UnB64(kp.Ed25519)
			if errX == nil && errEd == nil && len(x) == 32 && len(ed) == 32 {
				pairs = append(pairs, signerKeys{x, ed})
			}
		}
	}
	var keys [][]byte
	for _, kp := range pairs {
		if listed[hex.EncodeToString(e2e.Fingerprint(kp.x25519, kp.ed25519))] {
			keys = append(keys, kp.ed25519)
		}
	}
	if len(keys) == 0 {
		if unpublished {
			return nil, fmt.Errorf("%w; the signer is %s", ErrVouchSignerGone, signerLabel(chain, signer))
		}
		return nil, fmt.Errorf("%w: the keys published for %q are not the ones the chain lists", ErrVouchManifest, signer)
	}
	return keys, nil
}

// signerLabel names a signer by email when the chain gives one, which it does
// for a user the owner removed (the excluded entries), else by user ID.
func signerLabel(chain *e2e.Chain, signer string) string {
	for _, b := range chain.Bodies {
		for _, e := range b.Excluded {
			if e.User == signer && e.Email != "" {
				return e.Email
			}
		}
	}
	return signer
}

// isNotFound reports whether err is the server's 404.
func isNotFound(err error) bool {
	var api *APIError
	return errors.As(err, &api) && api.Status == http.StatusNotFound
}

// getBytes reads the body of a GET that answers with raw bytes, up to
// maxManifestBytes.
func (c *Client) getBytes(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", c.Host+path, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.roundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, errorFromResponse("GET", path, resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("%w: the manifest is larger than %d MiB", ErrVouchManifest, maxManifestBytes>>20)
	}
	return data, nil
}

// VersionFiles returns the files of versionID, a map of slash path to content.
// It verifies the artifact's chain and the version's manifest first, then
// checks each blob's hash against the manifest and opens it under the
// version's epoch, so the caller reads what was pushed or an error.
func (c *Client) VersionFiles(artifactID, versionID string) (map[string][]byte, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	versions, err := c.storeVersions(artifactID)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(versions, func(v *store.Version) bool { return v.ID == versionID })
	if i < 0 {
		return nil, fmt.Errorf("version %s not found in artifact %s", versionID, artifactID)
	}
	v := versions[i]
	_, manifest, err := c.verifyManifest(k, va.Chain, artifactID, v)
	if err != nil {
		return nil, fmt.Errorf("version %s: %w", v.ID, err)
	}
	aks, err := c.callerAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	ak := aks[v.Epoch]
	if ak == nil {
		return nil, fmt.Errorf("version %s: no key for epoch %d", v.ID, v.Epoch)
	}
	return c.openBlobs(artifactID, v, ak, manifest)
}

// Vouch signs the owner's vouch for versionID, naming the manifestHash the
// version was pushed with, and stores it. It refuses, before asking the
// server, a caller who is not the owner the verified chain names under the
// caller's current fingerprint, and a version whose manifest does not
// verify to the listed manifestHash.
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
	versions, err := c.storeVersions(artifactID)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(versions, func(v *store.Version) bool { return v.ID == versionID })
	if i < 0 {
		return fmt.Errorf("version %s not found in artifact %s", versionID, artifactID)
	}
	// The listed hash is the server's word. Sign it only once the manifest
	// the server serves, opened and verified here, has that body hash.
	if err := c.checkManifest(k, va.Chain, artifactID, versions[i]); err != nil {
		return err
	}
	body, err := json.Marshal(e2e.VouchBody{V: 1, Artifact: artifactID, Version: versionID, Manifest: versions[i].ManifestHash})
	if err != nil {
		return err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "vouch", body)
	if err != nil {
		return err
	}
	return c.doJSON("PUT", "/api/artifacts/"+artifactID+"/versions/"+versionID+"/vouch", map[string]any{"vouch": env}, nil)
}
