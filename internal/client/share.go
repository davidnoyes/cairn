// The user directory, pins, and same-epoch sharing. As elsewhere in this
// package, every byte of cryptography is built with internal/e2e.
package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
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
	// ErrNotOwner means only the artifact's owner can make the change.
	ErrNotOwner = errors.New("only the artifact's owner can change its members")
	// ErrShareSelf means the owner tried to share with themselves.
	ErrShareSelf = errors.New("the owner already has access to the artifact")
	// ErrPinConflict means another device pinned the user at a different
	// fingerprint than the one this command decided on, between its read of
	// the keyring and its write.
	ErrPinConflict = errors.New("another device pinned this user at a different fingerprint; run the command again")
)

// KeyChangedError means a user's current keys differ from the ones pinned
// for them, and no rotation chain explains it. ResetAt is when the server
// says they last reset their account without the recovery code, if it says
// so. Fork is set when the user's rotation records conflict with the pin
// (e2e.ErrRotationFork or e2e.ErrRollback), which may be an attack. FetchErr
// is set when the records could not be read, so nothing says whether the
// keys rotated or were replaced: the command is to be tried again.
type KeyChangedError struct {
	User      string
	Email     string
	PinnedFP  string
	CurrentFP string
	ResetAt   string
	Fork      error
	FetchErr  error
}

// Error states the facts only; what to do about a fork or a rollback is the
// command's advice, given once.
func (e *KeyChangedError) Error() string {
	switch {
	case errors.Is(e.Fork, e2e.ErrRollback):
		return fmt.Sprintf("WARNING: the server served fewer rotation records than you pinned for %s (%s), and this may be an attack: pinned %s, now %s (%v)",
			e.Email, e.User, formatHexFP(e.PinnedFP), formatHexFP(e.CurrentFP), e.Fork)
	case e.Fork != nil:
		return fmt.Sprintf("WARNING: the rotation records of %s (%s) conflict with each other or with the record you pinned, and this may be an attack: pinned %s, now %s (%v)",
			e.Email, e.User, formatHexFP(e.PinnedFP), formatHexFP(e.CurrentFP), e.Fork)
	case e.FetchErr != nil:
		return fmt.Sprintf("cairn could not read the rotation records of %s (%s), so it cannot tell whether their keys rotated: pinned %s, now %s (%v); retry before considering --accept-new-key",
			e.Email, e.User, formatHexFP(e.PinnedFP), formatHexFP(e.CurrentFP), e.FetchErr)
	}
	msg := fmt.Sprintf("the keys of %s (%s) changed: pinned %s, now %s", e.Email, e.User,
		formatHexFP(e.PinnedFP), formatHexFP(e.CurrentFP))
	if e.ResetAt != "" {
		msg += "; the account was reset at " + e.ResetAt
	}
	return msg + ". Confirm the new fingerprint with them, then pass --accept-new-key"
}

func (e *KeyChangedError) Unwrap() error { return e.Fork }

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
	return e2e.ExcludedMatch(excluded, u.ID, u.FP, u.Email)
}

// rotationsOf returns user's rotation records: those in known, which the
// caller read with the membership, or else the server's.
func (c *Client) rotationsOf(userID string, known map[string][]e2e.Envelope) ([]e2e.Envelope, error) {
	if recs, ok := known[userID]; ok {
		return recs, nil
	}
	return c.Rotations(userID)
}

// followPin is e2e.FollowPin for u against the keyring's pin. A pin on u's
// current keys reads no rotation records. A first pin reads them, so that it
// records the seq of the record that made the keys, and so does a pin on other
// keys, which a chain may explain. They come from known, the records the
// caller has by user ID, or else the server. fork is FollowPin's error for
// records that conflict with the pin. Records the server fails to serve are no
// records: a first pin is taken at seq 0, and a pin on other keys is a plain
// change, which only --accept-new-key stores, never a fork. fetchErr is why
// the records could not be read, set for a pin on other keys, which the
// caller must not take for a change of keys, and for any failure that
// fatalFetch says to stop on, which the caller returns.
func (c *Client) followPin(kr *e2e.Keyring, u DirectoryUser, known map[string][]e2e.Envelope) (state string, next e2e.Pin, fork, fetchErr error) {
	var pin *e2e.Pin
	if p, ok := kr.Pins[u.ID]; ok {
		pin = &p
	}
	var records []e2e.Envelope
	if pin == nil || pin.FP != u.FP {
		var err error
		if records, err = c.rotationsOf(u.ID, known); err != nil && (pin != nil || fatalFetch(err)) {
			return e2e.PinChanged, e2e.Pin{FP: u.FP, State: e2e.PinUnverified}, nil, err
		}
	}
	state, next, fork = e2e.FollowPin(u.ID, pin, records, u.X25519Pub, u.Ed25519Pub)
	return state, next, fork, nil
}

// fatalFetch reports whether err, from a fetch of rotation records, ends the
// command rather than degrading it: the caller cancelled it, or the server
// refused its credentials. Anything else may be a fault that passes.
func fatalFetch(err error) bool {
	var api *APIError
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.As(err, &api) && api.Status == http.StatusUnauthorized
}

// checkPin compares u's current keys with the keyring's pin, following the
// user's rotation records as followPin does; known holds the ones the caller
// has. A changed key is a *KeyChangedError unless acceptNewKey, and one that
// a rotation chain explains is not a change: the state is e2e.PinRotated,
// and the pin to store is unverified. It returns the state before any
// change, and the pin to store, or nil when the stored one stands.
func (c *Client) checkPin(kr *e2e.Keyring, u DirectoryUser, acceptNewKey bool, known map[string][]e2e.Envelope) (string, *e2e.Pin, error) {
	state, next, fork, fetchErr := c.followPin(kr, u, known)
	if fatalFetch(fetchErr) {
		return "", nil, fetchErr
	}
	switch state {
	case e2e.PinNew, e2e.PinRotated:
		return state, &next, nil
	case e2e.PinChanged:
		if !acceptNewKey {
			return state, nil, &KeyChangedError{User: u.ID, Email: u.Email, PinnedFP: kr.Pins[u.ID].FP, CurrentFP: u.FP, ResetAt: u.ResetAt, Fork: fork, FetchErr: fetchErr}
		}
		return state, &next, nil
	}
	return state, nil, nil
}

// wasVerified reports whether prior is a rotation that dropped a verified
// pin to unverified, so the person is told to compare the keys again.
func wasVerified(kr *e2e.Keyring, user, prior string) bool {
	return prior == e2e.PinRotated && kr.Pins[user].State == e2e.PinVerified
}

// storePin writes a pin for user. basedOn is the fingerprint the keyring
// pinned for user when the caller decided on pin, or "" if it pinned none.
// Against the keyring as it is when written, which another device may have
// changed since: a pin at the same fingerprint is never downgraded from
// verified, and a pin at a fingerprint other than basedOn is ErrPinConflict.
func (c *Client) storePin(k *UnlockedKeys, user string, pin e2e.Pin, basedOn string) error {
	_, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		if cur, ok := kr.Pins[user]; ok {
			switch {
			case cur.FP == pin.FP && cur.State == e2e.PinVerified:
				return nil
			case cur.FP != pin.FP && cur.FP != basedOn:
				return fmt.Errorf("%w: %s", ErrPinConflict, user)
			}
		}
		kr.Pins[user] = pin
		return nil
	})
	return err
}

// PinResult is what Pin did.
type PinResult struct {
	User  DirectoryUser
	Prior string // the state before: new, unverified, verified, rotated, or changed
	State string // the state stored
	// WasVerified is set when Prior is rotated and the pin was verified: it
	// is unverified now.
	WasVerified bool
}

// Pin records the current fingerprint of who in the keyring, unverified, or
// verified when the caller has compared it with them. A changed key is a
// *KeyChangedError unless acceptNewKey; one a rotation chain explains is not.
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
	prior, pin, err := c.checkPin(kr, u, acceptNewKey, nil)
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
		if err := c.storePin(k, u.ID, *pin, kr.Pins[u.ID].FP); err != nil {
			return nil, err
		}
	}
	return &PinResult{User: u, Prior: prior, State: pin.State, WasVerified: wasVerified(kr, u.ID, prior)}, nil
}

// MemberConflict is the state of a Members row whose rotation records
// conflict with the pin: a fork or a rollback, which may be an attack.
const MemberConflict = "conflict"

// MemberView is one row of Members: the owner or a member, with the pin
// state of their current keys. State is "self" for the caller, and "-" for
// a user the directory no longer lists. It is "rotated" when a rotation
// chain leads from the pin to their current keys; WasVerified then says
// whether the pin was verified, which a rotation drops. It is MemberConflict
// when the rotation records fork or roll back.
type MemberView struct {
	User        string
	Name        string
	Email       string
	Role        string // owner, editor, or viewer
	FP          string // hex, as the latest verified record lists it
	State       string
	WasVerified bool
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
			state, _, fork, fetchErr := c.followPin(va.Keyring, u, va.Membership.Rotations)
			if fatalFetch(fetchErr) {
				return nil, nil, fetchErr
			}
			if fork != nil {
				state = MemberConflict
			}
			r.State, r.WasVerified = state, wasVerified(va.Keyring, r.User, state)
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
	Demoted   bool // an existing editor became a viewer, in a new epoch
	Unchanged bool // the user already held this role under these keys
	Epoch     int
	TeamRole  string // the latest record's team: none, viewer, or editor
	// Dropped are the excluded entries the share removed, because the user
	// is listed again by name.
	Dropped []e2e.ExcludedEntry
	EpochChange
	// Listed are approved team members the record also lists, with the role
	// the team grants; Unlisted are those whose approval failed a check, who
	// the owner is asked about.
	Listed   []DirectoryUser
	Unlisted []UnlistedUser

	// WasVerified is set when Prior is rotated and the pin was verified.
	WasVerified bool
}

// Share adds who to an artifact at its current epoch, or promotes a viewer
// to editor. Demoting an editor starts a new epoch. Sharing by name with a
// user the owner excluded lists them again, and drops the entries they match.
// It refuses a directory with duplicate emails or fingerprints, and a user
// whose keys changed since they were pinned, unless acceptNewKey. A user
// seen for the first time is pinned unverified. The new member gets a
// wrap of every epoch's AK, opened from the owner's estate copies and
// checked against the chain's akCommit. A user an editor approved already
// holds those wraps, so they get none. The record also lists each approved
// team member whose approval passes the four checks.
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
	if err != nil {
		return nil, err
	}
	if u.ID == k.UserID {
		return nil, ErrShareSelf
	}
	prior, pin, err := c.checkPin(va.Keyring, u, acceptNewKey, va.Membership.Rotations)
	if err != nil {
		return nil, err
	}
	res := &ShareResult{User: u, Prior: prior, WasVerified: wasVerified(va.Keyring, u.ID, prior), Role: role, Epoch: latest.Epoch, TeamRole: latest.Team}
	pending, err := c.pendingFor(k, artifactID, va)
	if err != nil {
		return nil, err
	}
	// A user the pending list reports rotated, and whose chain pendingFor
	// verified, holds wraps under their new keys already: they re-made their
	// own when they rotated.
	rotated := slices.ContainsFunc(pending, func(p PendingUser) bool { return p.User.ID == u.ID && p.State == PendingRotated })
	// An approved user holds their wraps already, so the owner's client takes
	// the server's word for it only after the checks listApproved makes.
	approved := false
	if p := slices.IndexFunc(pending, func(p PendingUser) bool { return p.User.ID == u.ID && p.State == PendingApproved }); p >= 0 {
		approved = true
		if err := checkApproved(k, latest, va.Membership.Rotations, dir, pending[p]); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrApprovalUnverified, u.Email, err)
		}
	}

	members := slices.Clone(latest.Members)
	i := slices.IndexFunc(members, func(m e2e.Member) bool { return m.User == u.ID })
	needsWraps := true
	demote := false
	switch {
	case i < 0:
		members = append(members, e2e.Member{User: u.ID, Role: role, FP: u.FP})
		needsWraps = !approved && !rotated
	default:
		demote = members[i].Role == "editor" && role == "viewer"
		res.Promoted = members[i].Role != role && !demote
		res.Demoted = demote
		relist := members[i].FP != u.FP
		needsWraps = relist && !rotated
		res.Unchanged = !res.Promoted && !demote && !relist
		members[i] = e2e.Member{User: u.ID, Role: role, FP: u.FP}
	}
	basedOn := va.Keyring.Pins[u.ID].FP
	if demote {
		return c.shareNextEpoch(k, artifactID, va, dir, pending, members, u, pin, basedOn, res)
	}
	// A member who rotated is listed under their new keys in any record this
	// writes, so the user's own entry unchanged is not Unchanged while one waits.
	pins := map[string]pinDecision{}
	relisted, err := c.relistRotated(va, pending, members, pins)
	if err != nil {
		return nil, err
	}
	if res.Unchanged && !relisted {
		if pin != nil {
			if err := c.storePin(k, u.ID, *pin, basedOn); err != nil {
				return nil, err
			}
		}
		return res, nil
	}
	res.Unchanged = false
	lst := approvedListing{pins: pins}
	if latest.Team != "none" {
		if lst, err = c.listApproved(k, va, dir, pending, latest.Team, func(id string) bool {
			return slices.ContainsFunc(members, func(m e2e.Member) bool { return m.User == id })
		}); err != nil {
			return nil, err
		}
		maps.Copy(lst.pins, pins)
	}
	members = append(members, lst.members...)
	res.Listed, res.Unlisted = lst.listed, lst.unlisted
	slices.SortFunc(members, func(a, b e2e.Member) int { return strings.Compare(a.User, b.User) })

	var wraps []map[string]any
	if needsWraps {
		// Defense in depth behind VerifyChain's epoch pin, which already
		// refuses a stale epoch.
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
	next.Members = members
	next.Excluded, res.Dropped = dropExcluded(latest.Excluded, members, dir)
	if err := c.putRecord(k, artifactID, va, next, wraps, nil, ""); err != nil {
		// A member who rotated needs no wrap, which cairn could not know
		// while their records were out of reach: the server refuses it as a
		// bad request.
		var api *APIError
		if i := slices.IndexFunc(pending, func(p PendingUser) bool { return p.User.ID == u.ID && p.RotationsErr != nil }); i >= 0 && wraps != nil && errors.As(err, &api) && api.Status == http.StatusBadRequest {
			return nil, fmt.Errorf("the rotation records of %s could not be read (%v), so cairn may have sent a wrap the server did not need; retry when the records can be read: %w", u.Email, pending[i].RotationsErr, err)
		}
		return nil, err
	}
	for id, d := range lst.pins {
		if err := c.storePin(k, id, d.pin, d.basedOn); err != nil {
			return nil, fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", id, err)
		}
	}
	if pin != nil {
		if err := c.storePin(k, u.ID, *pin, basedOn); err != nil {
			return nil, fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", u.Email, err)
		}
	}
	if err := c.readBack(k, artifactID, ""); err != nil {
		return nil, err
	}
	return res, nil
}

// shareNextEpoch is Share when the change demotes an editor: the demoted
// user stays listed as a viewer and the record starts a new epoch.
func (c *Client) shareNextEpoch(k *UnlockedKeys, artifactID string, va *VerifiedArtifact, dir []DirectoryUser,
	pending []PendingUser, members []e2e.Member, u DirectoryUser, pin *e2e.Pin, basedOn string, res *ShareResult) (*ShareResult, error) {
	next := va.Chain.Latest
	next.Members = members
	change, listed, err := c.putNextEpoch(k, artifactID, va, dir, pending, nextEpochRecord{next: next, decided: u.ID})
	if err != nil {
		return nil, err
	}
	res.EpochChange, res.Listed, res.Unlisted, res.Epoch = *change, listed, nil, va.Chain.Latest.Epoch+1
	if pin != nil {
		if err := c.storePin(k, u.ID, *pin, basedOn); err != nil {
			return nil, fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", u.Email, err)
		}
	}
	if err := c.readBack(k, artifactID, change.Link); err != nil {
		return nil, err
	}
	return res, nil
}

// dropExcluded returns the entries no listed member matches, by user ID,
// fingerprint, or normalized email, and those a member matches, which a record
// that lists the member must drop.
func dropExcluded(excluded []e2e.ExcludedEntry, members []e2e.Member, dir []DirectoryUser) (kept, dropped []e2e.ExcludedEntry) {
	email := map[string]string{}
	for _, d := range dir {
		email[d.ID] = e2e.NormalizeEmail(d.Email)
	}
	for _, x := range excluded {
		if slices.ContainsFunc(members, func(m e2e.Member) bool {
			return x.User == m.User || x.FP == m.FP || e2e.NormalizeEmail(x.Email) == email[m.User]
		}) {
			dropped = append(dropped, x)
		} else {
			kept = append(kept, x)
		}
	}
	return kept, dropped
}

// signNext makes next the record after the verified chain's latest, and
// signs it as signer with seed. It returns the record as signed.
func signNext(seed []byte, signer string, va *VerifiedArtifact, next e2e.MembershipBody) (e2e.MembershipBody, e2e.Envelope, error) {
	next.Transfer, next.Handover = "", ""
	return signChained(seed, signer, va, next)
}

// signChained is signNext for a record that may set transfer or handover, as
// the one that accepts ownership does.
func signChained(seed []byte, signer string, va *VerifiedArtifact, next e2e.MembershipBody) (e2e.MembershipBody, e2e.Envelope, error) {
	next.Seq, next.Prev = va.Chain.Latest.Seq+1, va.Chain.Head
	if next.Excluded == nil {
		next.Excluded = []e2e.ExcludedEntry{}
	}
	body, err := json.Marshal(next)
	if err != nil {
		return next, e2e.Envelope{}, err
	}
	env, err := e2e.NewEnvelope(seed, signer, "membership", body)
	return next, env, err
}

// putRecord signs next as the record after the verified chain's latest and
// PUTs it with wraps and, for a next epoch, the estate copy of its AK. A
// public record carries the hash of the epoch's link token, which the server
// requires of every public record: linkHash for a next epoch, whose estate
// copy the server does not hold yet, or empty to take it from the epoch's own.
func (c *Client) putRecord(k *UnlockedKeys, artifactID string, va *VerifiedArtifact, next e2e.MembershipBody, wraps, estate []map[string]any, linkHash string) error {
	next, env, err := signNext(k.Ed25519Seed, k.UserID, va, next)
	if err != nil {
		return err
	}
	if wraps == nil {
		wraps = []map[string]any{}
	}
	if estate == nil {
		estate = []map[string]any{}
	}
	if next.Public && linkHash == "" {
		if linkHash, err = c.linkTokenHashFor(k, artifactID, va.Chain, next.Epoch); err != nil {
			return err
		}
	}
	return c.doJSON("PUT", "/api/artifacts/"+artifactID+"/membership", map[string]any{
		"membership": env, "wraps": wraps, "estate": estate, "linkTokenHash": linkHash,
	}, nil)
}

// epochCommits maps each epoch to the akCommit the verified chain lists for it.
func epochCommits(chain *e2e.Chain) map[int]string {
	commits := map[int]string{}
	for _, b := range chain.Bodies {
		if _, ok := commits[b.Epoch]; !ok {
			commits[b.Epoch] = b.AKCommit
		}
	}
	return commits
}

// epochAKs opens the owner's estate copy of each epoch's AK and checks it
// against the akCommit the verified chain lists for that epoch.
func (c *Client) epochAKs(k *UnlockedKeys, artifactID string, chain *e2e.Chain) (map[int][]byte, error) {
	commits := epochCommits(chain)
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
