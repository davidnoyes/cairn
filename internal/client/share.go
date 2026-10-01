// The user directory, pins, and same-epoch sharing. As elsewhere in this
// package, every byte of cryptography is built with internal/e2e.
package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrUnknownUser means the directory lists no user with that email or id.
	ErrUnknownUser = errors.New("no user with that email or id in the directory")
	// ErrDirectoryDuplicate means two user IDs in the directory share an
	// email or a fingerprint, so a name cannot be trusted to mean one person.
	ErrDirectoryDuplicate = errors.New("the directory lists two users with the same email or fingerprint")
	// ErrExcluded means the user matches an entry the owner excluded.
	ErrExcluded = errors.New("the user was removed from this artifact and is excluded from it")
	// ErrNeedsNextEpoch means the change removes or demotes someone, which
	// only a new epoch can do.
	ErrNeedsNextEpoch = errors.New("demoting a member needs a new epoch, which this version of cairn cannot create yet")
	// ErrNotOwner means only the artifact's owner can make the change.
	ErrNotOwner = errors.New("only the artifact's owner can change its members")
	// ErrShareSelf means the owner tried to share with themselves.
	ErrShareSelf = errors.New("the owner already has access to the artifact")
)

// KeyChangedError means a user's current keys differ from the ones pinned
// for them. ResetAt is when the server says they last reset their account
// without the recovery code, if it says so.
type KeyChangedError struct {
	User      string
	Email     string
	PinnedFP  string
	CurrentFP string
	ResetAt   string
}

func (e *KeyChangedError) Error() string {
	msg := fmt.Sprintf("the keys of %s (%s) changed: pinned %s, now %s", e.Email, e.User,
		formatHexFP(e.PinnedFP), formatHexFP(e.CurrentFP))
	if e.ResetAt != "" {
		msg += "; the account was reset at " + e.ResetAt
	}
	return msg + ". Confirm the new fingerprint with them, then pass --accept-new-key"
}

// formatHexFP groups a hex fingerprint for reading aloud, or returns it as
// it is when it is not hex.
func formatHexFP(fp string) string {
	b, err := hex.DecodeString(fp)
	if err != nil {
		return fp
	}
	return e2e.FormatFingerprint(b)
}

// DirectoryUser is a user as GET /api/users lists them, with the
// fingerprint of their current keys.
type DirectoryUser struct {
	ID         string
	Name       string
	Email      string
	X25519Pub  []byte
	Ed25519Pub []byte
	ResetAt    string
	FP         string // hex
}

type directoryWire struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	X25519Pub  string `json:"x25519Pub"`
	Ed25519Pub string `json:"ed25519Pub"`
	ResetAt    string `json:"resetAt"`
}

func (w directoryWire) user() (DirectoryUser, error) {
	x, err := e2e.UnB64(w.X25519Pub)
	if err != nil || len(x) != 32 {
		return DirectoryUser{}, fmt.Errorf("the directory's X25519 key for %s is not 32 bytes of base64", w.ID)
	}
	ed, err := e2e.UnB64(w.Ed25519Pub)
	if err != nil || len(ed) != 32 {
		return DirectoryUser{}, fmt.Errorf("the directory's Ed25519 key for %s is not 32 bytes of base64", w.ID)
	}
	_, fp := e2e.PinState(nil, x, ed)
	return DirectoryUser{ID: w.ID, Name: w.Name, Email: w.Email, X25519Pub: x, Ed25519Pub: ed, ResetAt: w.ResetAt, FP: fp}, nil
}

// Directory lists every user the server's directory holds.
func (c *Client) Directory() ([]DirectoryUser, error) {
	var resp []directoryWire
	if err := c.doJSON("GET", "/api/users", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]DirectoryUser, 0, len(resp))
	for _, w := range resp {
		u, err := w.user()
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// DirectoryUser looks one user up by id.
func (c *Client) DirectoryUser(id string) (*DirectoryUser, error) {
	var w directoryWire
	if err := c.doJSON("GET", "/api/users/"+id, nil, &w); err != nil {
		return nil, err
	}
	u, err := w.user()
	return &u, err
}

// CheckDirectory refuses a directory in which two user IDs share a
// normalized email or a fingerprint.
func CheckDirectory(dir []DirectoryUser) error {
	emails, fps := map[string]string{}, map[string]string{}
	for _, u := range dir {
		email := e2e.NormalizeEmail(u.Email)
		if other, ok := emails[email]; ok && other != u.ID {
			return fmt.Errorf("%w: %s and %s share the email %s", ErrDirectoryDuplicate, other, u.ID, email)
		}
		if other, ok := fps[u.FP]; ok && other != u.ID {
			return fmt.Errorf("%w: %s and %s share the fingerprint %s", ErrDirectoryDuplicate, other, u.ID, formatHexFP(u.FP))
		}
		emails[email], fps[u.FP] = u.ID, u.ID
	}
	return nil
}

// FindUser finds who, an email (compared normalized) or a user id, in the
// directory. It refuses a directory CheckDirectory refuses.
func FindUser(dir []DirectoryUser, who string) (DirectoryUser, error) {
	if err := CheckDirectory(dir); err != nil {
		return DirectoryUser{}, err
	}
	email := e2e.NormalizeEmail(who)
	for _, u := range dir {
		if u.ID == who || e2e.NormalizeEmail(u.Email) == email {
			return u, nil
		}
	}
	return DirectoryUser{}, fmt.Errorf("%w: %s", ErrUnknownUser, who)
}

// ExcludedMatch reports the excluded entry u matches, by user id,
// fingerprint, or normalized email, or nil.
func ExcludedMatch(excluded []e2e.ExcludedEntry, u DirectoryUser) *e2e.ExcludedEntry {
	email := e2e.NormalizeEmail(u.Email)
	for i, e := range excluded {
		if e.User == u.ID || e.FP == u.FP || e2e.NormalizeEmail(e.Email) == email {
			return &excluded[i]
		}
	}
	return nil
}

// checkPin compares u's current keys with the keyring's pin. A changed key
// is a *KeyChangedError unless acceptNewKey. It returns the state before
// any change, and the pin to store, or nil when the stored one stands.
func checkPin(kr *e2e.Keyring, u DirectoryUser, acceptNewKey bool) (string, *e2e.Pin, error) {
	var pin *e2e.Pin
	if p, ok := kr.Pins[u.ID]; ok {
		pin = &p
	}
	state, fp := e2e.PinState(pin, u.X25519Pub, u.Ed25519Pub)
	switch state {
	case e2e.PinNew:
		return state, &e2e.Pin{FP: fp, State: e2e.PinUnverified}, nil
	case e2e.PinChanged:
		if !acceptNewKey {
			return state, nil, &KeyChangedError{User: u.ID, Email: u.Email, PinnedFP: pin.FP, CurrentFP: fp, ResetAt: u.ResetAt}
		}
		return state, &e2e.Pin{FP: fp, State: e2e.PinUnverified}, nil
	}
	return state, nil, nil
}

// storePin writes a pin for user, replacing any other.
func (c *Client) storePin(k *UnlockedKeys, user string, pin e2e.Pin) error {
	_, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Pins[user] = pin
		return nil
	})
	return err
}

// PinResult is what Pin did.
type PinResult struct {
	User  DirectoryUser
	Prior string // the state before: new, unverified, verified, or changed
	State string // the state stored
}

// Pin records who's current fingerprint in the keyring, unverified, or
// verified when the caller has compared it with them. A changed key is a
// *KeyChangedError unless acceptNewKey.
func (c *Client) Pin(who string, verified, acceptNewKey bool) (*PinResult, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	u, err := FindUser(dir, who)
	if err != nil {
		return nil, err
	}
	kr, err := c.ReadKeyring(k)
	if err != nil {
		return nil, err
	}
	prior, pin, err := checkPin(kr, u, acceptNewKey)
	if err != nil {
		return nil, err
	}
	if pin == nil {
		p := kr.Pins[u.ID]
		pin = &p
	}
	if verified {
		pin.State = e2e.PinVerified
	}
	if kr.Pins[u.ID] != *pin {
		if err := c.storePin(k, u.ID, *pin); err != nil {
			return nil, err
		}
	}
	return &PinResult{User: u, Prior: prior, State: pin.State}, nil
}

// MemberView is one row of Members: the owner or a member, with the pin
// state of their current keys. State is "self" for the caller, and "-" for
// a user the directory no longer lists.
type MemberView struct {
	User  string
	Name  string
	Email string
	Role  string // owner, editor, or viewer
	FP    string // hex, as the latest verified record lists it
	State string
}

// Members verifies an artifact's chain and lists its owner and members.
func (c *Client) Members(artifactID string) (*VerifiedArtifact, []MemberView, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, nil, err
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, nil, err
	}
	byID := map[string]DirectoryUser{}
	for _, u := range dir {
		byID[u.ID] = u
	}
	latest := va.Chain.Latest
	rows := []MemberView{{User: latest.Owner, Role: "owner", FP: latest.OwnerFP}}
	for _, m := range latest.Members {
		rows = append(rows, MemberView{User: m.User, Role: m.Role, FP: m.FP})
	}
	for i := range rows {
		r := &rows[i]
		u, ok := byID[r.User]
		switch {
		case r.User == k.UserID:
			r.State = "self"
		case !ok:
			r.State = "-"
		default:
			var pin *e2e.Pin
			if p, ok := va.Keyring.Pins[r.User]; ok {
				pin = &p
			}
			r.State, _ = e2e.PinState(pin, u.X25519Pub, u.Ed25519Pub)
		}
		if ok {
			r.Name, r.Email = u.Name, u.Email
		}
	}
	return va, rows, nil
}

// ShareResult is what Share did.
type ShareResult struct {
	User      DirectoryUser
	Prior     string // the pin state before
	Role      string
	Promoted  bool // an existing viewer became an editor
	Unchanged bool // the user already held this role under these keys
	Epoch     int
}

// Share adds who to an artifact at its current epoch, or promotes a viewer
// to editor. It refuses a demotion, which needs a new epoch; a user an
// owner excluded; a directory with duplicate emails or fingerprints; and a
// user whose keys changed since they were pinned, unless acceptNewKey. A
// user seen for the first time is pinned unverified. The new member gets a
// wrap of every epoch's AK, opened from the owner's estate copies and
// checked against the chain's akCommit.
func (c *Client) Share(artifactID, who, role string, acceptNewKey bool) (*ShareResult, error) {
	if role != "viewer" && role != "editor" {
		return nil, fmt.Errorf("role must be viewer or editor, not %q", role)
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
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	u, err := FindUser(dir, who)
	if err != nil {
		return nil, err
	}
	if u.ID == k.UserID {
		return nil, ErrShareSelf
	}
	if e := ExcludedMatch(latest.Excluded, u); e != nil {
		return nil, fmt.Errorf("%w: %s matches the excluded entry for %s (%s)", ErrExcluded, u.Email, e.Email, e.User)
	}
	prior, pin, err := checkPin(va.Keyring, u, acceptNewKey)
	if err != nil {
		return nil, err
	}
	res := &ShareResult{User: u, Prior: prior, Role: role, Epoch: latest.Epoch}

	members := slices.Clone(latest.Members)
	i := slices.IndexFunc(members, func(m e2e.Member) bool { return m.User == u.ID })
	needsWraps := true
	switch {
	case i < 0:
		members = append(members, e2e.Member{User: u.ID, Role: role, FP: u.FP})
	case members[i].Role == "editor" && role == "viewer":
		return nil, ErrNeedsNextEpoch
	default:
		res.Promoted = members[i].Role != role
		needsWraps = members[i].FP != u.FP
		res.Unchanged = !res.Promoted && !needsWraps
		members[i] = e2e.Member{User: u.ID, Role: role, FP: u.FP}
	}
	if pin != nil {
		if err := c.storePin(k, u.ID, *pin); err != nil {
			return nil, err
		}
	}
	if res.Unchanged {
		return res, nil
	}
	slices.SortFunc(members, func(a, b e2e.Member) int { return strings.Compare(a.User, b.User) })

	var wraps []map[string]any
	if needsWraps {
		if err := e2e.CheckEncryptEpoch(va.Keyring.EpochPin(artifactID), latest.Epoch); err != nil {
			return nil, err
		}
		aks, err := c.epochAKs(k, artifactID, va.Chain)
		if err != nil {
			return nil, err
		}
		for epoch := 1; epoch <= latest.Epoch; epoch++ {
			w, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
				Purpose: "ak", Artifact: artifactID, Epoch: uint64(epoch),
				RecipientID: u.ID, RecipientPub: u.X25519Pub,
			}, aks[epoch])
			if err != nil {
				return nil, err
			}
			wraps = append(wraps, map[string]any{"user": u.ID, "epoch": epoch, "wrapped": e2e.B64(w)})
		}
	}

	next := latest
	next.Seq, next.Prev, next.Transfer, next.Handover = latest.Seq+1, va.Chain.Head, "", ""
	next.Members = members
	if next.Excluded == nil {
		next.Excluded = []e2e.ExcludedEntry{}
	}
	body, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "membership", body)
	if err != nil {
		return nil, err
	}
	if wraps == nil {
		wraps = []map[string]any{}
	}
	if err := c.doJSON("PUT", "/api/artifacts/"+artifactID+"/membership", map[string]any{
		"membership": env, "wraps": wraps, "estate": []any{}, "linkTokenHash": "",
	}, nil); err != nil {
		return nil, err
	}
	if _, err := c.VerifyArtifact(k, artifactID, k.FP); err != nil {
		return nil, fmt.Errorf("the server accepted the new membership record, but reading it back failed: %w", err)
	}
	return res, nil
}

// epochAKs opens the owner's estate copy of each epoch's AK and checks it
// against the akCommit the verified chain lists for that epoch.
func (c *Client) epochAKs(k *UnlockedKeys, artifactID string, chain *e2e.Chain) (map[int][]byte, error) {
	commits := map[int]string{}
	for _, b := range chain.Bodies {
		if _, ok := commits[b.Epoch]; !ok {
			commits[b.Epoch] = b.AKCommit
		}
	}
	keys, err := c.Keys(artifactID)
	if err != nil {
		return nil, err
	}
	ekKey, err := e2e.EKSealKey(k.EK)
	if err != nil {
		return nil, err
	}
	aks := map[int][]byte{}
	for _, e := range keys.Estate {
		ak, err := e2e.Open(ekKey, estateFields(artifactID, e.Epoch), e.Sealed)
		if err != nil {
			return nil, fmt.Errorf("opening the estate copy of epoch %d: %w", e.Epoch, err)
		}
		commit, err := e2e.AKCommit(ak, artifactID, uint64(e.Epoch))
		if err != nil {
			return nil, err
		}
		if want, ok := commits[e.Epoch]; !ok || commit != want {
			return nil, fmt.Errorf("%w: the estate copy of epoch %d does not match the chain's akCommit", e2e.ErrChain, e.Epoch)
		}
		aks[e.Epoch] = ak
	}
	for epoch := 1; epoch <= chain.Latest.Epoch; epoch++ {
		if aks[epoch] == nil {
			return nil, fmt.Errorf("the server holds no estate copy of epoch %d", epoch)
		}
	}
	return aks, nil
}
