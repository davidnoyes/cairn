// Sharing with groups: listing a group in an artifact's member list, approving
// its members, and dropping it again. A group, like the team share, grants
// nothing by itself: its members read once an approver wraps the key to them.
// See "Sharing with groups" in design/e2e-api.md.
package client

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrNotInGroup means the server holds a user under a listed group whose
	// verified chain does not list them, so the client neither approves nor
	// lists them.
	ErrNotInGroup = errors.New("the verified record of the group does not list the user")
	// ErrGroupKeyChanged means the group's record lists the user under keys
	// other than the ones the directory serves for them now.
	ErrGroupKeyChanged = errors.New("the group's record lists the user under another fingerprint than the directory does")
	// ErrNotSharedWithGroup means the artifact's latest record does not list
	// the group.
	ErrNotSharedWithGroup = errors.New("the artifact is not shared with the group")
)

// GroupKeyChangedError is ErrGroupKeyChanged with the two fingerprints, for a
// key-change warning: a manager of the group saw GroupFP for the user, and the
// directory serves FP now.
type GroupKeyChangedError struct {
	User    DirectoryUser
	Group   string
	GroupFP string
}

func (e *GroupKeyChangedError) Error() string {
	return fmt.Sprintf("%s: the record of group %s lists %s under fingerprint %s, but the directory serves %s now; compare the fingerprint with them, then run the command again with --accept-new-key",
		ErrGroupKeyChanged, e.Group, e.User.Email, e.GroupFP, e.User.FP)
}

func (e *GroupKeyChangedError) Unwrap() error { return ErrGroupKeyChanged }

// groupSet holds the verified chains of groups, by ID. A nil entry is a
// group that no longer exists.
type groupSet map[string]*e2e.GroupChain

// groupChains verifies the chain of each group in ids that have lacks, and
// adds it. A group the server no longer holds (404) is added as nil. Verifying
// a group may pin its signers, so va's keyring is read again afterwards: a
// pin decided later is then based on what is stored.
func (c *Client) groupChains(k *UnlockedKeys, va *VerifiedArtifact, ids []string, have groupSet) error {
	verified := false
	for _, id := range ids {
		if _, ok := have[id]; ok {
			continue
		}
		vg, err := c.VerifyGroup(k, id, false)
		var api *APIError
		switch {
		case errors.As(err, &api) && api.Status == http.StatusNotFound:
			have[id] = nil
		case err != nil:
			return fmt.Errorf("group %s: %w", id, err)
		default:
			have[id], verified = vg.Chain, true
		}
	}
	if !verified {
		return nil
	}
	kr, err := c.ReadKeyring(k)
	if err != nil {
		return err
	}
	va.Keyring = kr
	return nil
}

// listsUser returns the entry the chain's latest record has for user.
func listsUser(ch *e2e.GroupChain, user string) (e2e.GroupMember, bool) {
	if ch == nil {
		return e2e.GroupMember{}, false
	}
	i := slices.IndexFunc(ch.Latest.Members, func(m e2e.GroupMember) bool { return m.User == user })
	if i < 0 {
		return e2e.GroupMember{}, false
	}
	return ch.Latest.Members[i], true
}

// holdingGroups returns the groups of rec that the server says hold p.
func holdingGroups(rec e2e.MembershipBody, p PendingUser) []string {
	var ids []string
	for _, g := range rec.Groups {
		if slices.Contains(p.Groups, g.Group) {
			ids = append(ids, g.Group)
		}
	}
	return ids
}

// covers reports whether the record gives the user in p a reason to read: the
// team share is on, or a group it lists holds them, on the server's word.
func covers(rec e2e.MembershipBody, p PendingUser) bool {
	return rec.Team != "none" || len(holdingGroups(rec, p)) > 0
}

// holdersLose reports whether next, a record after latest, leaves an unlisted
// holder in pending without a reason to read, so the server refuses it at the
// same epoch. An approved user loses it when next covers them no more. A user
// whose wrap is for old keys has no group the server names, so they lose it
// unless the record lists them: erring that way costs only an epoch.
func holdersLose(pending []PendingUser, latest, next e2e.MembershipBody) bool {
	return slices.ContainsFunc(pending, func(p PendingUser) bool {
		switch p.State {
		case PendingApproved:
			return !covers(next, p)
		case PendingKeyChanged, PendingRotated:
			return !slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == p.User.ID })
		}
		return false
	})
}

// grantedRole is the role the record gives the approved user p: the highest
// of the team share's role and the roles of the listed groups whose verified
// chains list them. It is "" when the record covers them no more, and
// ErrNotInGroup when a group the server names holds them in no verified chain
// and nothing else covers them.
func (c *Client) grantedRole(k *UnlockedKeys, va *VerifiedArtifact, rec e2e.MembershipBody, p PendingUser, chains groupSet) (string, error) {
	role := ""
	if rec.Team != "none" {
		role = rec.Team
	}
	ids := holdingGroups(rec, p)
	if err := c.groupChains(k, va, ids, chains); err != nil {
		return "", err
	}
	for _, g := range rec.Groups {
		if _, ok := listsUser(chains[g.Group], p.User.ID); ok && (role == "" || roleRank(g.Role) > roleRank(role)) {
			role = g.Role
		}
	}
	if role == "" && len(ids) > 0 {
		return "", fmt.Errorf("%w: %s", ErrNotInGroup, p.User.Email)
	}
	return role, nil
}

// checkGroupCover is the group check of an approval. When the team share is
// off, the newcomer must be listed by a verified chain of a listed group that
// holds them, under the fingerprint the directory serves for them: a
// difference is a *GroupKeyChangedError, which acceptNewKey overrides, and no
// chain listing them is ErrNotInGroup. While the team share is on, it covers
// them whatever the groups say.
func (c *Client) checkGroupCover(k *UnlockedKeys, va *VerifiedArtifact, latest e2e.MembershipBody, p PendingUser, u DirectoryUser, acceptNewKey bool) error {
	if latest.Team != "none" {
		return nil
	}
	ids := holdingGroups(latest, p)
	chains := groupSet{}
	if err := c.groupChains(k, va, ids, chains); err != nil {
		return err
	}
	var differs *GroupKeyChangedError
	for _, id := range ids {
		m, ok := listsUser(chains[id], u.ID)
		switch {
		case !ok:
		case m.FP == u.FP:
			return nil
		case differs == nil:
			differs = &GroupKeyChangedError{User: u, Group: id, GroupFP: m.FP}
		}
	}
	switch {
	case differs == nil:
		return fmt.Errorf("%w: %s", ErrNotInGroup, u.Email)
	case !acceptNewKey:
		return differs
	}
	return nil
}

// liveGroups returns gs without the groups that no longer exist, and the IDs
// it dropped. A client builds every record this way: a deleted group grants
// nothing, and the record that keeps listing it only clutters the list. Nothing
// is asked when gs is empty.
func (c *Client) liveGroups(gs []e2e.GroupShare) (kept []e2e.GroupShare, dropped []string, err error) {
	if len(gs) == 0 {
		return gs, nil, nil
	}
	all, err := c.Groups()
	if err != nil {
		return nil, nil, err
	}
	for _, g := range gs {
		if slices.ContainsFunc(all, func(s GroupSummary) bool { return s.ID == g.Group }) {
			kept = append(kept, g)
		} else {
			dropped = append(dropped, g.Group)
		}
	}
	return kept, dropped, nil
}

// GroupRef names a group: its ID, and its name when the server still holds
// the group.
type GroupRef struct {
	ID   string
	Name string
}

// ShareGroupResult is what ShareGroup did.
type ShareGroupResult struct {
	Group GroupRef
	Role  string
	Epoch int
	// Unchanged is set when the record already lists the group under this
	// role and nothing else needed listing: no record was signed.
	Unchanged bool
	// Approved are the group's members the command approved. Pending are the
	// ones it left waiting, with the reason: their directory key differs from
	// the group record's, a pin check refused them, or an approval check did.
	Approved []DirectoryUser
	Pending  []UnlistedUser
	// Listed are approved team or group members the record also lists, with
	// the role they are granted; Unlisted are those whose approval failed a
	// check.
	Listed   []DirectoryUser
	Unlisted []UnlistedUser
	// DroppedGroups are the groups the record dropped because they no longer
	// exist.
	DroppedGroups []string
}

// ShareGroup lists the group groupRef names, an ID or an exact name, in the
// artifact's member list with role, viewer or editor, in a same-epoch record,
// or changes the role it is listed under. It then approves each current
// member of the group's verified chain who is waiting: the keys the directory
// serves for them must be the ones the group record lists, and the pin checks
// of Approve must pass. The others stay pending, with a reason. The record
// also lists each approved member whose approval passes the four checks. The
// caller must be the owner or a manager.
func (c *Client) ShareGroup(artifactID, groupRef, role string, acceptNewKey bool) (*ShareGroupResult, error) {
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
	if err := checkSigner(latest, k); err != nil {
		return nil, err
	}
	g, err := c.ResolveGroup(groupRef)
	if err != nil {
		return nil, err
	}
	if role != "viewer" && role != "editor" {
		return nil, fmt.Errorf("a group is shared as viewer or editor, not %q", role)
	}
	vg, err := c.VerifyGroup(k, g.ID, acceptNewKey)
	if err != nil {
		return nil, err
	}
	if va.Keyring, err = c.ReadKeyring(k); err != nil {
		return nil, err
	}
	res := &ShareGroupResult{Group: GroupRef{ID: g.ID, Name: vg.Chain.Latest.Name}, Role: role, Epoch: latest.Epoch}
	pending, err := c.pendingFor(k, artifactID, va)
	if err != nil {
		return nil, err
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	next := latest
	next.Groups = slices.Clone(latest.Groups)
	if i := slices.IndexFunc(next.Groups, func(s e2e.GroupShare) bool { return s.Group == g.ID }); i >= 0 {
		next.Groups[i].Role = role
	} else {
		next.Groups = append(next.Groups, e2e.GroupShare{Group: g.ID, Role: role})
		slices.SortFunc(next.Groups, func(a, b e2e.GroupShare) int { return strings.Compare(a.Group, b.Group) })
	}
	next.Members = slices.Clone(latest.Members)
	pins := map[string]pinDecision{}
	relisted, err := c.relistRotated(va, pending, next.Members, pins)
	if err != nil {
		return nil, err
	}
	lst, err := c.listApproved(k, va, dir, pending, next, func(id string) bool {
		return slices.ContainsFunc(next.Members, func(m e2e.Member) bool { return m.User == id })
	})
	if err != nil {
		return nil, err
	}
	maps.Copy(lst.pins, pins)
	res.Listed, res.Unlisted = lst.listed, lst.unlisted
	if slices.Equal(latest.Groups, next.Groups) && len(lst.members) == 0 && !relisted {
		res.Unchanged = true
	} else {
		next.Members = append(next.Members, lst.members...)
		slices.SortFunc(next.Members, func(a, b e2e.Member) int { return strings.Compare(a.User, b.User) })
		if res.DroppedGroups, err = c.putRecord(k, artifactID, va, next, nil, nil, ""); err != nil {
			return nil, err
		}
		for id, d := range lst.pins {
			if err := c.storePin(k, id, d.pin, d.basedOn); err != nil {
				return nil, fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", id, err)
			}
		}
		if err := c.readBack(k, artifactID, ""); err != nil {
			return nil, err
		}
	}
	if err := c.approveGroupMembers(k, artifactID, vg.Chain, acceptNewKey, res); err != nil {
		return nil, err
	}
	return res, nil
}

// approveGroupMembers approves each member of chain who waits as new, and
// records the outcome in res: Approved, or Pending with the reason. A member
// whose directory key differs from the chain's is left pending without a
// request, as is any whose approval fails a check; only a failure that ends
// the command, as fatalFetch says, is an error. The artifact is verified
// again first: the record that lists the group has landed.
func (c *Client) approveGroupMembers(k *UnlockedKeys, artifactID string, chain *e2e.GroupChain, acceptNewKey bool, res *ShareGroupResult) error {
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return err
	}
	pending, err := c.pendingFor(k, artifactID, va)
	if err != nil {
		return err
	}
	for _, m := range chain.Latest.Members {
		i := slices.IndexFunc(pending, func(p PendingUser) bool { return p.User.ID == m.User && p.State == PendingNew })
		if i < 0 {
			continue
		}
		u := pending[i].User
		if u.FP != m.FP {
			res.Pending = append(res.Pending, UnlistedUser{User: u, Err: &GroupKeyChangedError{User: u, Group: chain.Latest.Group, GroupFP: m.FP}})
			continue
		}
		if _, err := c.approveWith(k, artifactID, u.ID, acceptNewKey); err != nil {
			if fatalFetch(err) {
				return err
			}
			res.Pending = append(res.Pending, UnlistedUser{User: u, Err: err})
			continue
		}
		res.Approved = append(res.Approved, u)
	}
	return nil
}

// UnshareGroupResult is what UnshareGroup did. EpochChange says whether the
// record started a new epoch, and who it excluded, and names any groups the
// record dropped because they no longer exist.
type UnshareGroupResult struct {
	EpochChange
	Group GroupRef
	Epoch int
	// Listed are approved members the new epoch's record lists, with the
	// role the team share or their other groups grant.
	Listed []DirectoryUser
}

// UnshareGroup drops the group groupRef names from the artifact's member
// list. groupRef is the ID of a listed group, which may be deleted, or an
// exact name. When someone read the artifact only through that group, a
// next-epoch record drops it and excludes them. Otherwise a same-epoch record
// does. The caller must be the owner or a manager.
func (c *Client) UnshareGroup(artifactID, groupRef string) (*UnshareGroupResult, error) {
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
	if err := checkSigner(latest, k); err != nil {
		return nil, err
	}
	id, name := groupRef, ""
	if !slices.ContainsFunc(latest.Groups, func(g e2e.GroupShare) bool { return g.Group == id }) {
		g, err := c.ResolveGroup(groupRef)
		if err != nil {
			return nil, err
		}
		id, name = g.ID, g.Name
	} else if all, err := c.Groups(); err == nil {
		if i := slices.IndexFunc(all, func(s GroupSummary) bool { return s.ID == id }); i >= 0 {
			name = all[i].Name
		}
	}
	if !slices.ContainsFunc(latest.Groups, func(g e2e.GroupShare) bool { return g.Group == id }) {
		return nil, fmt.Errorf("%w: %s", ErrNotSharedWithGroup, groupRef)
	}
	pending, err := c.pendingFor(k, artifactID, va)
	if err != nil {
		return nil, err
	}
	next := latest
	next.Groups = slices.DeleteFunc(slices.Clone(latest.Groups), func(g e2e.GroupShare) bool { return g.Group == id })
	res := &UnshareGroupResult{Group: GroupRef{ID: id, Name: name}, Epoch: latest.Epoch}
	if holdersLose(pending, latest, next) {
		change, listed, err := c.coverEndsNextEpoch(k, artifactID, va, pending, next)
		if err != nil {
			return nil, err
		}
		res.EpochChange, res.Epoch, res.Listed = *change, latest.Epoch+1, listed
		return res, nil
	}
	next.Members = slices.Clone(latest.Members)
	pins := map[string]pinDecision{}
	if _, err := c.relistRotated(va, pending, next.Members, pins); err != nil {
		return nil, err
	}
	if res.DroppedGroups, err = c.putRecord(k, artifactID, va, next, nil, nil, ""); err != nil {
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

// ListedGroup is a group the artifact's latest record lists, with the role it
// grants. Name is the server's word, and empty, with Deleted set, when the
// server no longer holds the group.
type ListedGroup struct {
	ID      string
	Name    string
	Role    string
	Deleted bool
}

// ListedGroups returns the groups va's latest record lists, in the record's
// order, with the names the server holds for them.
func (c *Client) ListedGroups(va *VerifiedArtifact) ([]ListedGroup, error) {
	gs := va.Chain.Latest.Groups
	if len(gs) == 0 {
		return nil, nil
	}
	all, err := c.Groups()
	if err != nil {
		return nil, err
	}
	out := make([]ListedGroup, 0, len(gs))
	for _, g := range gs {
		row := ListedGroup{ID: g.Group, Role: g.Role, Deleted: true}
		if i := slices.IndexFunc(all, func(s GroupSummary) bool { return s.ID == g.Group }); i >= 0 {
			row.Name, row.Deleted = all[i].Name, false
		}
		out = append(out, row)
	}
	return out, nil
}
