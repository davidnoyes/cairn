// Encrypted metadata. An artifact's name and description and a version's name
// and changelog are sealed fields: the server holds a blob and a signed
// record for each, and no plaintext. This file writes them, reads them back
// as "Encrypted metadata and the app UI" in design/e2e-api.md says, and
// resolves an artifact by its name or by a resource reference. As elsewhere in
// this package, every byte of cryptography is built with internal/e2e.
package client

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// ErrCannotRename means the verified chain lists the caller as neither the
// owner nor an editor, under their current keys.
var ErrCannotRename = errors.New("only the artifact's owner or an editor can change its name or description")

// ErrNoArtifact means a reference matched no artifact the caller can see, by
// ID, name, or resource. It is not the answer when names could not be read
// to look for a match.
var ErrNoArtifact = errors.New("no artifact")

// MetaItem is one encrypted field as the server returns it.
type MetaItem struct {
	Record    e2e.Envelope `json:"record"`
	SignerKey string       `json:"signerKey"`
	Blob      string       `json:"blob"`
}

// Artifact is an artifact as the server returns it, with the fields the client
// has opened. Name and Description are empty when nobody wrote them, and when
// a field failed a check: the artifact then displays under its ID. Opening
// them costs a verification of the artifact's chain, so only the functions
// that return an Artifact for display do it.
type Artifact struct {
	store.Artifact
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Meta        map[string]MetaItem `json:"-"`
	// Access is the level the server gave the caller, such as "owner" or
	// "successor".
	Access string `json:"-"`
}

// Title is the name the artifact displays under: its name, or its ID when it
// has none that could be read.
func (a *Artifact) Title() string {
	if a.Name == "" {
		return a.ID
	}
	return a.Name
}

// Version is a version as the server returns it, with its fields opened, as
// for Artifact.
type Version struct {
	store.Version
	Name      string              `json:"name"`
	Changelog string              `json:"changelog"`
	Meta      map[string]MetaItem `json:"-"`
}

// artifactWire and versionWire are the views the server sends: the store's
// own fields, and the sealed fields beside them.
type artifactWire struct {
	store.Artifact
	Access string              `json:"access"`
	Meta   map[string]MetaItem `json:"meta"`
}

type versionWire struct {
	store.Version
	Meta map[string]MetaItem `json:"meta"`
}

func (w artifactWire) artifact() *Artifact {
	return &Artifact{Artifact: w.Artifact, Meta: w.Meta, Access: w.Access}
}
func (w versionWire) version() *Version { return &Version{Version: w.Version, Meta: w.Meta} }

// listArtifacts reads the artifacts the caller can see, with no field opened.
func (c *Client) listArtifacts() ([]*Artifact, error) {
	var wire []artifactWire
	if err := c.doJSON("GET", "/api/artifacts", nil, &wire); err != nil {
		return nil, err
	}
	out := make([]*Artifact, len(wire))
	for i, w := range wire {
		out[i] = w.artifact()
	}
	return out, nil
}

func (c *Client) getArtifact(id string) (*Artifact, error) {
	var wire artifactWire
	if err := c.doJSON("GET", "/api/artifacts/"+id, nil, &wire); err != nil {
		return nil, err
	}
	return wire.artifact(), nil
}

func (c *Client) listVersions(artifactID string) ([]*Version, error) {
	var wire []versionWire
	if err := c.doJSON("GET", "/api/artifacts/"+artifactID+"/versions", nil, &wire); err != nil {
		return nil, err
	}
	out := make([]*Version, len(wire))
	for i, w := range wire {
		out[i] = w.version()
	}
	return out, nil
}

// storeVersions is listVersions for a caller that needs only what the server
// stores about each version.
func (c *Client) storeVersions(artifactID string) ([]*store.Version, error) {
	vs, err := c.listVersions(artifactID)
	if err != nil {
		return nil, err
	}
	out := make([]*store.Version, len(vs))
	for i, v := range vs {
		out[i] = &v.Version
	}
	return out, nil
}

// ListArtifacts lists the artifacts the caller can see, with their names and
// descriptions opened.
func (c *Client) ListArtifacts() ([]*Artifact, error) {
	as, err := c.listArtifacts()
	if err != nil {
		return nil, err
	}
	c.OpenNames(as...) // an artifact whose chain fails shows under its ID
	return as, nil
}

// GetArtifact reads one artifact by its ID, with its name and description
// opened.
func (c *Client) GetArtifact(id string) (*Artifact, error) {
	a, err := c.getArtifact(id)
	if err != nil {
		return nil, err
	}
	c.OpenNames(a) // an artifact whose chain fails shows under its ID
	return a, nil
}

// ListVersions lists an artifact's versions, newest first, with their names
// and changelogs opened.
func (c *Client) ListVersions(artifactID string) ([]*Version, error) {
	vs, err := c.listVersions(artifactID)
	if err != nil {
		return nil, err
	}
	c.openVersionNames(artifactID, vs)
	return vs, nil
}

// metaChecker holds what reading an artifact's fields is checked against: the
// record that lists its writers now, and every AK the caller holds. A field
// is checked as a stored file's record is, except that publicWrites does not
// widen it: only the owner and the editors write metadata.
func (c *Client) metaChecker(k *UnlockedKeys, artifactID string) (*dataChecker, error) {
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	return c.metaCheckerFor(k, va, artifactID)
}

func (c *Client) metaCheckerFor(k *UnlockedKeys, va *VerifiedArtifact, artifactID string) (*dataChecker, error) {
	aks, err := c.callerAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	writers, err := c.writerKeys(k, va.Membership, va.Chain.Latest)
	if err != nil {
		return nil, err
	}
	return &dataChecker{artifact: artifactID, aks: aks, writers: writers}, nil
}

// openMeta checks and opens one field of the artifact, or of version vid when
// it is not empty, and returns its text and the epoch it was sealed under. A
// field that fails a check is an error wrapping ErrUnverified.
func openMeta(chk *dataChecker, vid, field string, item MetaItem) (string, int, error) {
	var body e2e.RecordBody
	if err := e2e.DecodeStrict(item.Record.Body, &body); err != nil {
		return "", 0, unverified("the record does not decode: %v", err)
	}
	blob, err := e2e.UnB64(item.Blob)
	if err != nil {
		return "", 0, unverified("the blob is not base64url")
	}
	// checkBlob skips a nil blob, which means one the caller does not hold.
	if len(blob) == 0 {
		return "", 0, unverified("the blob is empty")
	}
	scoped := *chk
	scoped.version = vid
	ak, err := scoped.checkRecord(item.Record, item.SignerKey, body.Epoch, "meta", field, blob)
	if err != nil {
		return "", 0, err
	}
	plain, err := e2e.OpenBlob(ak, e2e.BlobContext{Artifact: chk.artifact, Version: vid, Kind: "meta", Name: field}, blob)
	if err != nil {
		return "", 0, unverified("the blob does not open: %v", err)
	}
	if len(plain) > e2e.MaxMetaPlaintext {
		return "", 0, unverified("the field is over %d bytes", e2e.MaxMetaPlaintext)
	}
	if !utf8.Valid(plain) {
		return "", 0, unverified("the field is not valid UTF-8")
	}
	return string(plain), body.Epoch, nil
}

// readMeta opens field of items, or reports "" for a field nobody wrote or one
// that failed a check.
func readMeta(chk *dataChecker, vid, field string, items map[string]MetaItem) string {
	item, ok := items[field]
	if !ok {
		return ""
	}
	plain, _, err := openMeta(chk, vid, field, item)
	if err != nil {
		return ""
	}
	return plain
}

// OpenNames opens the name and description of each artifact, which one
// verification of the artifact's chain makes possible. A field that cannot be
// opened is left empty, and the artifact displays under its ID. It returns the
// first reason the chain of an artifact could not be verified, or the keys
// could not be unlocked, for a caller that would otherwise report "not found"
// without saying why; the others are still opened.
func (c *Client) OpenNames(as ...*Artifact) error {
	var k *UnlockedKeys
	var first error
	for _, a := range as {
		if len(a.Meta) == 0 {
			continue
		}
		if k == nil {
			var err error
			if k, err = c.Unlock(); err != nil {
				return err
			}
		}
		chk, err := c.metaChecker(k, a.ID)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		a.Name = readMeta(chk, "", "name", a.Meta)
		a.Description = readMeta(chk, "", "description", a.Meta)
	}
	return first
}

// openVersionNames opens the name and changelog of each of an artifact's
// versions, as OpenNames does for an artifact.
func (c *Client) openVersionNames(artifactID string, vs []*Version) {
	if !slices.ContainsFunc(vs, func(v *Version) bool { return len(v.Meta) > 0 }) {
		return
	}
	k, err := c.Unlock()
	if err != nil {
		return
	}
	chk, err := c.metaChecker(k, artifactID)
	if err != nil {
		return
	}
	for _, v := range vs {
		v.Name = readMeta(chk, v.ID, "name", v.Meta)
		v.Changelog = readMeta(chk, v.ID, "changelog", v.Meta)
	}
}

// putMeta seals text as a field under ak, the AK of epoch, signs the record
// that covers it with k's key, and stores it. vid is empty for a field of the
// artifact. The server refuses it if the epoch has moved since.
func (c *Client) putMeta(k *UnlockedKeys, artifactID, vid, field string, epoch int, ak []byte, text string) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("the %s is not valid UTF-8", field)
	}
	if len(text) > e2e.MaxMetaPlaintext {
		return fmt.Errorf("the %s is over %d bytes", field, e2e.MaxMetaPlaintext)
	}
	blob, err := e2e.SealBlob(rand.Reader, ak, e2e.BlobContext{Artifact: artifactID, Version: vid, Kind: "meta", Name: field}, []byte(text))
	if err != nil {
		return err
	}
	body, err := json.Marshal(e2e.RecordBody{V: 1, Artifact: artifactID, Version: vid, Kind: "meta", Name: field, Epoch: epoch, SHA256: e2e.BodyHash(blob)})
	if err != nil {
		return err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "record", body)
	if err != nil {
		return err
	}
	path := "/api/artifacts/" + artifactID
	if vid != "" {
		path += "/versions/" + vid
	}
	err = c.doJSON("PUT", path+"/meta/"+field, map[string]any{"record": env, "blob": e2e.B64(blob)}, nil)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
		return fmt.Errorf("%w: %w", ErrEpochMoved, apiErr)
	}
	return err
}

// UpdateArtifact writes the artifact's name or description, whichever fields
// holds ("name", "description"). It verifies the artifact's chain first and
// refuses a caller the chain does not list as owner or editor.
func (c *Client) UpdateArtifact(id string, fields map[string]string) error {
	k, err := c.Unlock()
	if err != nil {
		return err
	}
	va, err := c.VerifyArtifact(k, id, "")
	if err != nil {
		return err
	}
	if err := c.checkHandover(k, id, va); err != nil {
		return err
	}
	if !approverOf(va.Chain.Latest, k) {
		return ErrCannotRename
	}
	// VerifyArtifact has already refused a chain below the keyring's pin.
	epoch := va.Chain.Latest.Epoch
	aks, err := c.callerAKs(k, id, va.Chain)
	if err != nil {
		return err
	}
	for _, field := range []string{"name", "description"} {
		text, ok := fields[field]
		if !ok {
			continue
		}
		if err := c.putMeta(k, id, "", field, epoch, aks[epoch], text); err != nil {
			return err
		}
	}
	return nil
}

// AddResource associates a reference with the artifact. The server keeps its
// blind index under the caller's index key, never the reference.
func (c *Client) AddResource(artifactID, typ, value string) error {
	k, err := c.Unlock()
	if err != nil {
		return err
	}
	index, err := e2e.BlindIndex(k.IndexKey, typ, value)
	if err != nil {
		return err
	}
	return c.doJSON("POST", "/api/artifacts/"+artifactID+"/resources", map[string]string{"type": typ, "value": index}, nil)
}

// ResolveArtifact accepts an artifact ID, else the exact name of one of the
// caller's artifacts, else a resource reference the caller added, such as a
// Claude session ID, and returns the artifact with its name and description
// opened. A name or a reference that several artifacts share is an error
// naming their IDs.
func (c *Client) ResolveArtifact(ref string) (*Artifact, error) {
	a, err := c.GetArtifact(ref)
	if err == nil {
		return a, nil
	}
	var apiErr *APIError
	// Fall through to the name and reference lookups only on plain not-found;
	// any other failure surfaces as is.
	if !errors.As(err, &apiErr) || apiErr.Status != 404 {
		return nil, err
	}
	all, err := c.listArtifacts()
	if err != nil {
		return nil, err
	}
	openErr := c.OpenNames(all...)
	var matches []*Artifact
	for _, a := range all {
		if a.Name == ref {
			matches = append(matches, a)
		}
	}
	if len(matches) == 0 {
		if matches, err = c.byReference(all, ref); err != nil {
			return nil, err
		}
	}
	switch len(matches) {
	case 0:
		if openErr != nil {
			return nil, fmt.Errorf("no artifact with id or name %q, and the names of some artifacts could not be read: %w", ref, openErr)
		}
		return nil, fmt.Errorf("%w with id or name %q", ErrNoArtifact, ref)
	case 1:
		return matches[0], nil
	}
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.ID
	}
	return nil, fmt.Errorf("%d artifacts match %q (%s); use the id", len(matches), ref, strings.Join(ids, ", "))
}

// byReference returns the artifacts among all that carry ref as a resource,
// by computing its blind index under each type the artifacts' resources carry.
// A caller who cannot unlock their keys, or whose artifacts carry no resource,
// finds none.
func (c *Client) byReference(all []*Artifact, ref string) ([]*Artifact, error) {
	var types []string
	for _, a := range all {
		for _, r := range a.Resources {
			if !slices.Contains(types, r.Type) {
				types = append(types, r.Type)
			}
		}
	}
	if len(types) == 0 {
		return nil, nil
	}
	k, err := c.Unlock()
	if err != nil {
		return nil, nil
	}
	index := map[string]string{}
	for _, typ := range types {
		if index[typ], err = e2e.BlindIndex(k.IndexKey, typ, ref); err != nil {
			return nil, err
		}
	}
	var out []*Artifact
	for _, a := range all {
		if slices.ContainsFunc(a.Resources, func(r *store.Resource) bool { return r.Value == index[r.Type] }) {
			out = append(out, a)
		}
	}
	return out, nil
}
