// Groups: a named set of users, kept as a signed chain of group records. The
// client verifies the chain against the keyring's groups entry before it
// shows a member or signs a record. See "Groups" in design/e2e-api.md.
package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

var (
	// ErrNoGroup means no group has that ID or name.
	ErrNoGroup = errors.New("no group")
	// ErrAmbiguousGroup means two or more groups share the name.
	ErrAmbiguousGroup = errors.New("more than one group has that name")
	// ErrNotGroupManager means only a manager of the group can change it.
	ErrNotGroupManager = errors.New("only a manager of the group can change it")
	// ErrNotGroupMember means the group does not list the user.
	ErrNotGroupMember = errors.New("the group does not list that user")
	// ErrLastManager means the change leaves the group with no manager.
	ErrLastManager = errors.New("the group would have no manager; make another user a manager first, or delete the group")
	// ErrGroupMoved means another device stored a newer head of the group in
	// the keyring while this client was reading it, twice running.
	ErrGroupMoved = errors.New("another device stored a newer head of the group while it was read; run the command again")
)

// GroupSummary is one row of Groups, as the server lists it. The name and the
// count are the server's word: Group verifies the chain before it shows
// members.
type GroupSummary struct {
	ID      string
	Name    string
	Seq     int
	Members int
	Role    string // the caller's role: manager, member, or empty
}

type groupWire struct {
	ID      string                     `json:"id"`
	Name    string                     `json:"name"`
	Seq     int                        `json:"seq"`
	Members int                        `json:"members"`
	Role    string                     `json:"role"`
	Records []e2e.Envelope             `json:"records"`
	Signers map[string]groupSignerWire `json:"signers"`
}

// groupSignerWire is the keys the server serves for a signer of a record:
// their current public keys and their rotation records, oldest first.
type groupSignerWire struct {
	X25519    string         `json:"x25519"`
	Ed25519   string         `json:"ed25519"`
	Rotations []e2e.Envelope `json:"rotations"`
}

func (w groupWire) summary() GroupSummary {
	return GroupSummary{ID: w.ID, Name: w.Name, Seq: w.Seq, Members: w.Members, Role: w.Role}
}

// Groups lists every group the server holds.
func (c *Client) Groups() ([]GroupSummary, error) {
	var resp []groupWire
	if err := c.doJSON("GET", "/api/groups", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]GroupSummary, 0, len(resp))
	for _, w := range resp {
		out = append(out, w.summary())
	}
	return out, nil
}

// ResolveGroup finds the group ref names: a group ID, else an exact name. A
// name two groups share is ErrAmbiguousGroup, and none is ErrNoGroup.
func (c *Client) ResolveGroup(ref string) (*GroupSummary, error) {
	all, err := c.Groups()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == ref {
			return &all[i], nil
		}
	}
	var matches []GroupSummary
	for _, g := range all {
		if g.Name == ref {
			matches = append(matches, g)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("%w with id or name %q", ErrNoGroup, ref)
	case 1:
		return &matches[0], nil
	}
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.ID
	}
	return nil, fmt.Errorf("%w: %d groups are named %q (%s); use the id", ErrAmbiguousGroup, len(matches), ref, strings.Join(ids, ", "))
}

// VerifiedGroup is a group's chain after the client verified it against the
// keyring.
type VerifiedGroup struct {
	ID      string
	Chain   *e2e.GroupChain
	Keyring *e2e.Keyring
	// Rotations are the rotation records of every user who signed a record,
	// by user ID.
	Rotations map[string][]e2e.Envelope
}

// groupSigners is what anchorSigners makes of the keys a group's answer
// serves for the users who signed its records.
type groupSigners struct {
	// keys holds, by fingerprint, the keys that may have signed a record, with
	// the user each belongs to: a signer's current key, and any earlier one
	// their rotation records link to it.
	keys map[string]e2e.GroupKey
	// rotations are each signer's rotation records, by user ID.
	rotations map[string][]e2e.Envelope
	// pins are the pins to store for signers once the chain verifies.
	pins map[string]e2e.Pin
}

// anchorSigners anchors each signer's key as a share anchors a member's: the
// current key the answer serves for them must be the keyring's pin or follow
// from it by their rotation records, else it is a *KeyChangedError unless
// acceptNewKey, and a signer not pinned yet is pinned unverified. The caller's
// own key is k's. A signer the directory still lists must have the same
// current key there as the answer serves, else it is e2e.ErrChain: a server
// cannot plant a key of its own for a real user. A record may be signed by that
// current key or by an earlier one their rotation records link to it, and by
// no other: a key the server serves that nothing anchors is not one, and
// VerifyGroupChain refuses a record whose key belongs to another user.
func (c *Client) anchorSigners(k *UnlockedKeys, kr *e2e.Keyring, w groupWire, acceptNewKey bool) (*groupSigners, error) {
	out := &groupSigners{
		keys:      map[string]e2e.GroupKey{},
		rotations: map[string][]e2e.Envelope{}, pins: map[string]e2e.Pin{},
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	for _, env := range w.Records {
		id := env.Signer
		if _, ok := out.rotations[id]; ok {
			continue
		}
		served, ok := w.Signers[id]
		if !ok {
			return nil, fmt.Errorf("the server did not serve the keys of %s, who signed a record of group %s", id, w.ID)
		}
		out.rotations[id] = served.Rotations
		cur := e2e.KeyPair{X25519: served.X25519, Ed25519: served.Ed25519}
		if id == k.UserID {
			cur = e2e.KeyPair{X25519: e2e.B64(k.X25519Pub), Ed25519: e2e.B64(k.Ed25519Pub)}
		}
		x, errX := e2e.UnB64(cur.X25519)
		ed, errEd := e2e.UnB64(cur.Ed25519)
		if errX != nil || errEd != nil || len(x) != 32 || len(ed) != 32 {
			return nil, fmt.Errorf("the keys the server served for %s are not 32 bytes of base64 each", id)
		}
		curFP := hex.EncodeToString(e2e.Fingerprint(x, ed))
		if id != k.UserID {
			u := DirectoryUser{ID: id, X25519Pub: x, Ed25519Pub: ed, FP: curFP}
			_, pin, err := c.checkPin(kr, u, acceptNewKey, out.rotations)
			if err != nil {
				var changed *KeyChangedError
				if errors.As(err, &changed) {
					changed.Email = id
					if d, derr := c.DirectoryUser(id); derr == nil {
						changed.Email = d.Email
					}
				}
				return nil, err
			}
			if pin != nil {
				out.pins[id] = *pin
			}
			if i := slices.IndexFunc(dir, func(d DirectoryUser) bool { return d.ID == id }); i >= 0 && dir[i].FP != curFP {
				return nil, fmt.Errorf("%w: the keys the server served for %s, who signed a record of group %s, are not the ones the directory lists for them", e2e.ErrChain, dir[i].Email, w.ID)
			}
		}
		linked := e2e.RotationLinker(out.rotations)
		out.keys[curFP] = e2e.GroupKey{User: id, KeyPair: cur}
		for _, r := range served.Rotations {
			var b e2e.RotationBody
			if json.Unmarshal(r.Body, &b) != nil {
				continue
			}
			for _, kp := range []e2e.KeyPair{b.Old, b.New} {
				x, errX := e2e.UnB64(kp.X25519)
				ed, errEd := e2e.UnB64(kp.Ed25519)
				if errX != nil || errEd != nil {
					continue
				}
				fp := hex.EncodeToString(e2e.Fingerprint(x, ed))
				if linked(id, fp, curFP) {
					out.keys[fp] = e2e.GroupKey{User: id, KeyPair: kp}
				}
			}
		}
	}
	return out, nil
}

// VerifyGroup reads a group's chain and verifies it. Each signer's keys come
// with the group and are anchored at the keyring's pin for them, as
// anchorSigners describes. The keyring's groups entry is the pin, so a chain
// shorter than the stored seq, or forked at it, is refused. After success the
// keyring stores the chain's seq and head, and the pins of signers seen for
// the first time or whose keys rotated.
//
// If another device stored a newer head in the keyring while the group was
// read, the group is read again, so the chain shown is checked against it.
func (c *Client) VerifyGroup(k *UnlockedKeys, groupID string, acceptNewKey bool) (*VerifiedGroup, error) {
	vg, err := c.verifyGroup(k, groupID, acceptNewKey)
	if errors.Is(err, ErrGroupMoved) {
		return c.verifyGroup(k, groupID, acceptNewKey)
	}
	return vg, err
}

func (c *Client) verifyGroup(k *UnlockedKeys, groupID string, acceptNewKey bool) (*VerifiedGroup, error) {
	kr, err := c.ReadKeyring(k)
	if err != nil {
		return nil, err
	}
	var w groupWire
	if err := c.doJSON("GET", "/api/groups/"+groupID, nil, &w); err != nil {
		return nil, err
	}
	signers, err := c.anchorSigners(k, kr, w, acceptNewKey)
	if err != nil {
		return nil, err
	}
	chain, err := e2e.VerifyGroupChain(e2e.GroupInput{
		Group: groupID, Records: w.Records, Keys: signers.keys, Pin: kr.GroupPin(groupID),
		Linked: e2e.RotationLinker(signers.rotations),
	})
	if err != nil {
		return nil, fmt.Errorf("the records of group %s do not verify: %w", groupID, err)
	}
	for id, pin := range signers.pins {
		if err := c.storePin(k, id, pin, kr.Pins[id].FP); err != nil {
			return nil, fmt.Errorf("pinning the signer %s of group %s failed: %w", id, groupID, err)
		}
	}
	kr, err = c.recordGroup(k, kr, groupID, chain)
	if err != nil {
		return nil, err
	}
	return &VerifiedGroup{ID: groupID, Chain: chain, Keyring: kr, Rotations: signers.rotations}, nil
}

// recordGroup stores a verified chain as groupID's groups entry, unless the
// keyring already holds it. The entry never goes back: when the keyring now
// holds a higher seq than the chain, another device stored a newer head after
// this chain was checked, and recordGroup is ErrGroupMoved so the caller reads
// the group again. The same seq at another head is e2e.ErrFork.
func (c *Client) recordGroup(k *UnlockedKeys, kr *e2e.Keyring, groupID string, chain *e2e.GroupChain) (*e2e.Keyring, error) {
	want := e2e.GroupPin{Seq: chain.Latest.Seq, Head: chain.Head}
	if p := kr.GroupPin(groupID); p != nil && *p == want {
		// Nothing to write, but another device may have stored a newer head
		// since kr was read.
		now, err := c.ReadKeyring(k)
		if err != nil {
			return nil, err
		}
		if cur := now.GroupPin(groupID); cur != nil && cur.Seq > want.Seq {
			return nil, ErrGroupMoved
		}
		return now, nil
	}
	return c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		cur := kr.GroupPin(groupID)
		if cur != nil && cur.Seq == want.Seq && cur.Head != want.Head {
			return fmt.Errorf("%w: record %d of group %s", e2e.ErrFork, cur.Seq, groupID)
		}
		if cur != nil && cur.Seq > want.Seq {
			return ErrGroupMoved
		}
		if cur == nil || cur.Seq < want.Seq {
			kr.SetGroup(groupID, chain)
		}
		return nil
	})
}

// GroupMemberView is one row of ShowGroup: a listed member, with the pin
// state of their current keys. State is "self" for the caller and "-" for a
// user the directory no longer lists, as for MemberView.
type GroupMemberView struct {
	User        string
	Name        string
	Email       string
	Role        string // manager or member
	FP          string // hex, as the latest verified record lists it
	State       string
	WasVerified bool
}

// GroupView is a verified group: its name and seq from the chain, the
// caller's role in it, and its members.
type GroupView struct {
	ID      string
	Name    string
	Seq     int
	Role    string
	Members []GroupMemberView
}

// ShowGroup verifies a group's chain and lists its members, each with the
// pin state of their current keys. acceptNewKey accepts a signer's changed
// key, as VerifyGroup does.
func (c *Client) ShowGroup(groupID string, acceptNewKey bool) (*GroupView, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	vg, err := c.VerifyGroup(k, groupID, acceptNewKey)
	if err != nil {
		return nil, err
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	byID := map[string]DirectoryUser{}
	for _, u := range dir {
		byID[u.ID] = u
	}
	latest := vg.Chain.Latest
	v := &GroupView{ID: groupID, Name: latest.Name, Seq: latest.Seq}
	for _, m := range latest.Members {
		row := GroupMemberView{User: m.User, Role: m.Role, FP: m.FP}
		u, ok := byID[m.User]
		switch {
		case m.User == k.UserID:
			row.State = "self"
			v.Role = m.Role
		case !ok:
			row.State = "-"
		default:
			state, _, fork, fetchErr := c.followPin(vg.Keyring, u, vg.Rotations)
			if fatalFetch(fetchErr) {
				return nil, fetchErr
			}
			if fork != nil {
				state = MemberConflict
			}
			row.State, row.WasVerified = state, wasVerified(vg.Keyring, m.User, state)
		}
		if ok {
			row.Name, row.Email = u.Name, u.Email
		}
		v.Members = append(v.Members, row)
	}
	return v, nil
}

// signGroup signs next as the record after the verified chain's latest, as
// the caller, and returns it as signed.
func signGroup(k *UnlockedKeys, vg *VerifiedGroup, next e2e.GroupBody) (e2e.GroupBody, e2e.Envelope, error) {
	next.V, next.Group = 1, vg.ID
	next.Seq, next.Prev = vg.Chain.Latest.Seq+1, vg.Chain.Head
	next.Signer, next.SignerFP = k.UserID, k.FP
	slices.SortFunc(next.Members, func(a, b e2e.GroupMember) int { return strings.Compare(a.User, b.User) })
	body, err := json.Marshal(next)
	if err != nil {
		return next, e2e.Envelope{}, err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "group", body)
	return next, env, err
}

// putGroupRecord signs next after vg's chain and PUTs it, then reads the
// group back, which verifies the chain with the new record and stores its
// head in the keyring.
func (c *Client) putGroupRecord(k *UnlockedKeys, vg *VerifiedGroup, next e2e.GroupBody) error {
	_, env, err := signGroup(k, vg, next)
	if err != nil {
		return err
	}
	if err := c.doJSON("PUT", "/api/groups/"+vg.ID, map[string]any{"record": env}, nil); err != nil {
		return err
	}
	if _, err := c.VerifyGroup(k, vg.ID, false); err != nil {
		return fmt.Errorf("the server accepted the new group record, but reading it back failed: %w", err)
	}
	return nil
}

// managerOf verifies group groupID, as VerifyGroup does with acceptNewKey, and
// returns it with the caller's keys, or ErrNotGroupManager when the latest
// record does not list the caller as a manager.
func (c *Client) managerOf(groupID string, acceptNewKey bool) (*UnlockedKeys, *VerifiedGroup, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, nil, err
	}
	vg, err := c.VerifyGroup(k, groupID, acceptNewKey)
	if err != nil {
		return nil, nil, err
	}
	if !slices.ContainsFunc(vg.Chain.Latest.Members, func(m e2e.GroupMember) bool {
		return m.User == k.UserID && m.Role == "manager"
	}) {
		return nil, nil, ErrNotGroupManager
	}
	return k, vg, nil
}

// pinnedMember is a member a command adds, with the pin to store for them.
type pinnedMember struct {
	user DirectoryUser
	pin  *e2e.Pin
}

// CreateGroup creates a group named name, with the caller as its manager and
// each of members, an email or user ID from the directory, as a member. A
// member whose keys changed since they were pinned is refused. The group ID
// is a random UUID. Once the server accepts the first record, the chain is
// read back and verified, which stores its head in the keyring.
func (c *Client) CreateGroup(name string, members []string) (*GroupView, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	kr, err := c.ReadKeyring(k)
	if err != nil {
		return nil, err
	}
	entries := []e2e.GroupMember{{User: k.UserID, FP: k.FP, Role: "manager"}}
	var pins []pinnedMember
	if len(members) > 0 {
		dir, err := c.Directory()
		if err != nil {
			return nil, err
		}
		for _, who := range members {
			u, err := FindUser(dir, who)
			if err != nil {
				return nil, err
			}
			if slices.ContainsFunc(entries, func(m e2e.GroupMember) bool { return m.User == u.ID }) {
				continue
			}
			_, pin, err := c.checkPin(kr, u, false, nil)
			if err != nil {
				return nil, err
			}
			entries = append(entries, e2e.GroupMember{User: u.ID, FP: u.FP, Role: "member"})
			pins = append(pins, pinnedMember{u, pin})
		}
	}
	first := e2e.GroupBody{V: 1, Group: uuid.NewString(), Seq: 1, Name: name, Members: entries, Signer: k.UserID, SignerFP: k.FP}
	slices.SortFunc(first.Members, func(a, b e2e.GroupMember) int { return strings.Compare(a.User, b.User) })
	if err := e2e.CheckGroupBody(first); err != nil {
		return nil, err
	}
	body, err := json.Marshal(first)
	if err != nil {
		return nil, err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "group", body)
	if err != nil {
		return nil, err
	}
	if err := c.doJSON("POST", "/api/groups", map[string]any{"record": env}, nil); err != nil {
		return nil, err
	}
	for _, p := range pins {
		if p.pin == nil {
			continue
		}
		if err := c.storePin(k, p.user.ID, *p.pin, kr.Pins[p.user.ID].FP); err != nil {
			return nil, fmt.Errorf("the server accepted the group, but pinning %s failed: %w", p.user.Email, err)
		}
	}
	return c.ShowGroup(first.Group, false)
}

// GroupAddResult is what AddGroupMember did.
type GroupAddResult struct {
	User  DirectoryUser
	Prior string // the pin state before
	Role  string
	// Unchanged is set when the group already listed the user under these
	// keys and this role: nothing was signed.
	Unchanged bool
	// WasVerified is set when Prior is rotated and the pin was verified.
	WasVerified bool
}

// AddGroupMember adds who to a group as a member, or as a manager, or
// changes the role of one it lists. Only a manager signs it. The user's
// fingerprint comes from the directory and is checked against the caller's
// pin as Share does: a user whose keys changed since they were pinned is
// refused unless acceptNewKey, and one seen for the first time is pinned
// unverified. A viewer account is never made a manager.
func (c *Client) AddGroupMember(groupID, who string, manager, acceptNewKey bool) (*GroupAddResult, error) {
	k, vg, err := c.managerOf(groupID, acceptNewKey)
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
	role := "member"
	if manager {
		role = "manager"
	}
	if role == "manager" && u.Role == store.RoleViewer {
		return nil, fmt.Errorf("%s is a viewer account and cannot be a manager of a group", u.Email)
	}
	prior, pin, err := c.checkPin(vg.Keyring, u, acceptNewKey, vg.Rotations)
	if err != nil {
		return nil, err
	}
	res := &GroupAddResult{User: u, Prior: prior, Role: role, WasVerified: wasVerified(vg.Keyring, u.ID, prior)}
	basedOn := vg.Keyring.Pins[u.ID].FP

	next := vg.Chain.Latest
	next.Members = slices.Clone(next.Members)
	entry := e2e.GroupMember{User: u.ID, FP: u.FP, Role: role}
	if i := slices.IndexFunc(next.Members, func(m e2e.GroupMember) bool { return m.User == u.ID }); i < 0 {
		next.Members = append(next.Members, entry)
	} else if next.Members[i] == entry {
		res.Unchanged = true
	} else {
		next.Members[i] = entry
	}
	if !res.Unchanged {
		if err := c.putGroupRecord(k, vg, next); err != nil {
			return nil, err
		}
	}
	if pin != nil {
		if err := c.storePin(k, u.ID, *pin, basedOn); err != nil {
			return nil, fmt.Errorf("the server accepted the new group record, but pinning %s failed: %w", u.Email, err)
		}
	}
	return res, nil
}

// RemoveGroupMember removes who, a user ID or an email, from a group. Only a
// manager signs it, and a manager may remove themselves while another
// remains. It returns the user ID removed.
func (c *Client) RemoveGroupMember(groupID, who string, acceptNewKey bool) (string, error) {
	k, vg, err := c.managerOf(groupID, acceptNewKey)
	if err != nil {
		return "", err
	}
	id := who
	if !slices.ContainsFunc(vg.Chain.Latest.Members, func(m e2e.GroupMember) bool { return m.User == id }) {
		dir, err := c.Directory()
		if err != nil {
			return "", err
		}
		u, err := FindUser(dir, who)
		if err != nil {
			return "", err
		}
		id = u.ID
	}
	next := vg.Chain.Latest
	next.Members = slices.DeleteFunc(slices.Clone(next.Members), func(m e2e.GroupMember) bool { return m.User == id })
	if len(next.Members) == len(vg.Chain.Latest.Members) {
		return "", fmt.Errorf("%w: %s", ErrNotGroupMember, who)
	}
	if !slices.ContainsFunc(next.Members, func(m e2e.GroupMember) bool { return m.Role == "manager" }) {
		return "", ErrLastManager
	}
	if err := c.putGroupRecord(k, vg, next); err != nil {
		return "", err
	}
	return id, nil
}

// RenameGroup gives a group a new name. Only a manager signs it.
func (c *Client) RenameGroup(groupID, name string, acceptNewKey bool) error {
	k, vg, err := c.managerOf(groupID, acceptNewKey)
	if err != nil {
		return err
	}
	next := vg.Chain.Latest
	next.Name = name
	if err := e2e.CheckGroupBody(next); err != nil {
		return err
	}
	return c.putGroupRecord(k, vg, next)
}

// DeleteGroup deletes a group. The server allows a manager of the group, or
// an administrator, so the client reads no chain first. Once the server
// confirms, the group's entry leaves the keyring; nothing else removes one.
func (c *Client) DeleteGroup(groupID string) error {
	k, err := c.Unlock()
	if err != nil {
		return err
	}
	if err := c.doJSON("DELETE", "/api/groups/"+groupID, nil, nil); err != nil {
		return err
	}
	_, err = c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		delete(kr.Groups, groupID)
		return nil
	})
	return err
}
