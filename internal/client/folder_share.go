// Shared folders: bringing the records of the items inside a folder in step
// with the folder's, after the folder is shared or unshared or an item moves.
// A folder's record lists users and groups like any record, and each item
// inside it lists them too, marked with the folder they come from. The server
// checks the marks and refuses an item's record that leaves out an entry its
// folder lists, so the client that changes a folder writes one record for
// each item as well. See "Shared folders" in design/e2e-api.md.
package client

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// ErrFanOutIncomplete means some items could not be brought up to date with
// their folder. Each is named in the result, and running the same command
// again works through the ones still pending.
var ErrFanOutIncomplete = errors.New("some items are not up to date with their folder yet")

// The states of an item after FanOut.
const (
	// FanOutCurrent: the item's record already matched its folder's.
	FanOutCurrent = "current"
	// FanOutUpdated: a same-epoch record added entries.
	FanOutUpdated = "updated"
	// FanOutNewEpoch: a next-epoch record removed an entry or lowered a role.
	FanOutNewEpoch = "newEpoch"
	// FanOutFailed: the item is still pending, and Err says why.
	FanOutFailed = "failed"
)

// FanOutItem is what FanOut did for one item. Excluded are the users a
// next-epoch record excluded, and Resealed and ResealErr what sealing the
// item's data again under the new epoch did. Approved and Pending are the
// members of a group the record added whom the client approved, or left
// waiting. SkippedUsers and SkippedGroups are the entries the folder lists
// that the record did not add, because the account is deactivated or not
// verified, or the group was deleted: a record may not add them, and the
// folder's rule does not ask for them.
type FanOutItem struct {
	ID            string
	Kind          string
	State         string
	Err           error
	Excluded      []ExcludedUser
	Resealed      *ResealResult
	ResealErr     error
	Approved      []DirectoryUser
	Pending       []UnlistedUser
	SkippedUsers  []string
	SkippedGroups []string
}

// FanOutResult is what FanOut did to the items inside a folder, in the order
// it visited them.
type FanOutResult struct {
	Items []FanOutItem
}

// Count is how many items ended in state.
func (r *FanOutResult) Count(state string) int {
	n := 0
	for _, it := range r.Items {
		if it.State == state {
			n++
		}
	}
	return n
}

// Placing says the client itself put the root of a fan-out in a folder, by
// moving it, so its user chose the folder: Parent is the folder's ID, empty
// for the top level. The root's record then names Parent, whatever it named
// before, and the entries Parent lists are copied into it. Everything else
// that decides whose keys an item is sealed to comes from signed records.
type Placing struct{ Parent string }

// ErrPlacement means an item's latest verified record does not name the
// folder the server lists the item in, so no entry of that folder is copied
// into it: the server's tree is unsigned, and a hostile server could use it
// to have an item's key sealed to the members of a folder it chose.
var ErrPlacement = errors.New("the item's signed record does not name the folder the server lists it in")

// FanOut brings every item in the subtree of the folder rootID up to date
// with its own folder, parents before the items inside them: for each item
// whose artifact view says inherit is pending, it writes the record that adds
// the entries the folder lists, marked with the folder they come from, and
// when an entry no longer holds, because its folder stopped listing the user
// or the item left it, a next-epoch record that excludes the users who held
// the item only through it, and seals its data again. The walk goes into an
// item only when its latest verified record names the folder it was found
// in; any other item the server lists there as pending is refused, by ID,
// and never sealed to. placing, when not nil, also visits the folder itself,
// as a move does for the item it moved, and writes its record naming
// placing.Parent. It calls progress, when not nil, after each item with how
// many are done of how many the run visits; an item already current counts
// as done. An item that fails is skipped, with the reason in the result, so
// that one item does not hold the rest back, and ErrFanOutIncomplete is
// returned at the end; running the same command again resumes with the items
// still pending.
func (c *Client) FanOut(rootID string, placing *Placing, progress func(done, total int)) (*FanOutResult, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	all, err := c.listArtifacts()
	if err != nil {
		return nil, err
	}
	if byID(all, rootID) == nil {
		return nil, fmt.Errorf("%w: no artifact has the id %s", ErrNoArtifact, rootID)
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	f := &fanOut{c: c, k: k, dir: dir, parents: map[string]*e2e.MembershipBody{}, verified: map[string]*VerifiedArtifact{}}
	order := subtreeOrder(all, rootID, placing != nil, f.folderNamed)
	res := &FanOutResult{}
	for i, s := range order {
		var item FanOutItem
		switch {
		case s.refused != nil:
			item = FanOutItem{ID: s.a.ID, Kind: s.a.Kind, State: FanOutFailed, Err: s.refused}
		case placing != nil && s.a.ID == rootID:
			item = f.item(s.a, placing)
		default:
			item = f.item(s.a, nil)
		}
		res.Items = append(res.Items, item)
		if fatalFetch(item.Err) {
			return res, item.Err
		}
		if progress != nil {
			progress(i+1, len(order))
		}
	}
	if n := res.Count(FanOutFailed); n > 0 {
		return res, fmt.Errorf("%w: %d of %d", ErrFanOutIncomplete, n, len(order))
	}
	return res, nil
}

// subtreeItem is an item the walk visits. refused, when set, says why the
// walk will not touch it: its signed record does not name the folder it was
// found in, or its record cannot be verified.
type subtreeItem struct {
	a       *Artifact
	refused error
}

// placeName is a folder ID as an error message says it.
func placeName(id string) string {
	if id == "" {
		return "no folder (the top level)"
	}
	return "folder " + id
}

// placementError is ErrPlacement for the item id the server lists in listed
// while its record names named. A move another client made looks the same, so
// the message says how the owner places the item: by moving it there.
func placementError(id, listed, named string) error {
	move := "cairn move " + id + " --top"
	if listed != "" {
		move = "cairn move " + id + " --to " + listed
	}
	return fmt.Errorf("%w: it is listed in %s, and its record names %s; its owner places it with: %s (a move made by another client looks the same until then)", ErrPlacement, placeName(listed), placeName(named), move)
}

// subtreeOrder lists the items the server lists inside the folder root, depth
// first, each folder before the items inside it, folders before artifacts and
// each by ID. includeRoot puts the root itself first. The server's tree is
// unsigned, so folderNamed reads the folder an item's latest verified record
// names, and an item found in a folder that its record does not name is
// refused, and the walk does not go into it. A folder is always checked, and
// so is an artifact the server lists as pending; one it calls current is
// visited without being read, because nothing is copied into it.
func subtreeOrder(all []*Artifact, root string, includeRoot bool, folderNamed func(*Artifact) (string, error)) []subtreeItem {
	var out []subtreeItem
	if includeRoot {
		out = append(out, subtreeItem{a: byID(all, root)})
	}
	var walk func(parent string, depth int)
	walk = func(parent string, depth int) {
		var kids []*Artifact
		for _, a := range all {
			if a.ParentID == parent {
				kids = append(kids, a)
			}
		}
		sort.SliceStable(kids, func(i, j int) bool {
			if fi, fj := kids[i].Kind == store.KindFolder, kids[j].Kind == store.KindFolder; fi != fj {
				return fi
			}
			return kids[i].ID < kids[j].ID
		})
		for _, a := range kids {
			item := subtreeItem{a: a}
			if a.Kind == store.KindFolder || a.Inherit == "pending" {
				named, err := folderNamed(a)
				switch {
				case err != nil:
					item.refused = err
				case named != parent:
					item.refused = placementError(a.ID, parent, named)
				}
			}
			out = append(out, item)
			if item.refused == nil && a.Kind == store.KindFolder && depth < store.MaxFolderDepth {
				walk(a.ID, depth+1)
			}
		}
	}
	walk(root, 1)
	return out
}

// fanOut is one FanOut run: the caller's keys, the directory, the latest
// record of each folder the run has read, and the chain the walk verified
// for each item it checked, which sync uses once, before it writes the item.
// A folder is visited before the items inside it, so a record read for an
// item is never one the run is yet to change.
type fanOut struct {
	c        *Client
	k        *UnlockedKeys
	dir      []DirectoryUser
	parents  map[string]*e2e.MembershipBody
	verified map[string]*VerifiedArtifact
}

// folderNamed verifies the item a and returns the folder its latest record
// names, empty at the top level.
func (f *fanOut) folderNamed(a *Artifact) (string, error) {
	va, err := f.c.VerifyArtifact(f.k, a.ID, "")
	if err != nil {
		return "", err
	}
	f.verified[a.ID] = va
	return va.Chain.Latest.Folder, nil
}

// item brings one item up to date. placing is set for the root of a move.
func (f *fanOut) item(a *Artifact, placing *Placing) FanOutItem {
	out := FanOutItem{ID: a.ID, Kind: a.Kind, State: FanOutCurrent}
	if err := f.sync(a.ID, placing, &out); err != nil {
		out.State, out.Err = FanOutFailed, err
	}
	return out
}

// usable reports whether the directory holds the user, which it does for an
// active, verified account only: a record may add no other.
func (f *fanOut) usable(user string) bool {
	return slices.ContainsFunc(f.dir, func(u DirectoryUser) bool { return u.ID == user })
}

// parentRecord is the latest verified record of the folder id.
func (f *fanOut) parentRecord(id string) (*e2e.MembershipBody, error) {
	if b, ok := f.parents[id]; ok {
		return b, nil
	}
	va, err := f.c.VerifyArtifact(f.k, id, "")
	if err != nil {
		return nil, fmt.Errorf("the folder %s: %w", id, err)
	}
	b := va.Chain.Latest
	f.parents[id] = &b
	return &b, nil
}

// sync writes the record that brings item id up to date, if it is pending,
// and notes in out what it did. The folder whose entries it copies in is the
// one the item's latest verified record names, or placing.Parent when the
// client put the item there itself; the server's own word for where the item
// sits must agree, or nothing is written.
func (f *fanOut) sync(id string, placing *Placing, out *FanOutItem) error {
	c, k := f.c, f.k
	view, err := c.getArtifact(id)
	if err != nil {
		return err
	}
	if view.Inherit != "pending" {
		return nil
	}
	va := f.verified[id]
	delete(f.verified, id)
	if va == nil {
		if va, err = c.VerifyArtifact(k, id, ""); err != nil {
			return err
		}
	}
	latest := va.Chain.Latest
	folder := latest.Folder
	if placing != nil {
		folder = placing.Parent
	}
	if view.ParentID != folder {
		return placementError(id, view.ParentID, folder)
	}
	var parent *e2e.MembershipBody
	live := func(string) bool { return false }
	if folder != "" {
		if parent, err = f.parentRecord(folder); err != nil {
			return err
		}
		kept, _, err := c.liveGroups(parent.Groups)
		if err != nil {
			return err
		}
		live = func(g string) bool {
			return slices.ContainsFunc(kept, func(s e2e.GroupShare) bool { return s.Group == g })
		}
	}
	plan := planInherit(latest, parent, folder, f.usable, live)
	out.SkippedUsers, out.SkippedGroups = plan.skippedUsers, plan.skippedGroups
	if slices.Equal(plan.members, latest.Members) && slices.Equal(plan.groups, latest.Groups) && folder == latest.Folder {
		return nil
	}
	if err := c.checkHandover(k, id, va); err != nil {
		return err
	}
	if err := checkSigner(latest, k); err != nil {
		return err
	}
	next := latest
	next.Members, next.Groups, next.Folder = plan.members, plan.groups, folder
	// Moving is the owner's, so a manager's record keeps the folder.
	if !isOwner(latest, k) && (!slices.Equal(managersOf(latest.Members), managersOf(next.Members)) || folder != latest.Folder) {
		return ErrManagerOwnerOnly
	}
	byID := map[string]DirectoryUser{}
	for _, u := range f.dir {
		byID[u.ID] = u
	}
	// A user the item lists anew is listed under the keys the directory serves
	// now, which must be the ones the folder lists them under.
	for _, uid := range plan.added {
		i := slices.IndexFunc(next.Members, func(m e2e.Member) bool { return m.User == uid })
		if u := byID[uid]; u.FP != next.Members[i].FP {
			return fmt.Errorf("%w: %s (%s) was listed by the folder under another fingerprint than the directory serves now; share the folder with them again with cairn share --accept-new-key", ErrMemberKeyChanged, u.Email, u.ID)
		}
	}
	pending, err := c.pendingFor(k, view.ID, va)
	if err != nil {
		return err
	}
	if plan.epoch {
		return f.writeNextEpoch(view, va, next, pending, out)
	}
	return f.writeSameEpoch(view, va, next, plan, pending, out)
}

// writeNextEpoch writes next as a next-epoch record, which excludes the
// users it drops, and seals the item's data again.
func (f *fanOut) writeNextEpoch(a *Artifact, va *VerifiedArtifact, next e2e.MembershipBody, pending []PendingUser, out *FanOutItem) error {
	c, k := f.c, f.k
	change, _, err := c.putNextEpoch(k, a.ID, va, f.dir, pending, nextEpochRecord{next: next})
	if err != nil {
		return err
	}
	if err := c.readBack(k, a.ID, change.Link); err != nil {
		return err
	}
	c.resealInto(k, a.ID, change)
	out.State, out.Excluded, out.Resealed, out.ResealErr = FanOutNewEpoch, change.Excluded, change.Resealed, change.ResealErr
	return nil
}

// writeSameEpoch writes next as a same-epoch record that adds entries, seals
// every epoch's key to each user it adds, and approves the members of each
// group it adds.
func (f *fanOut) writeSameEpoch(a *Artifact, va *VerifiedArtifact, next e2e.MembershipBody, plan inheritPlan, pending []PendingUser, out *FanOutItem) error {
	c, k := f.c, f.k
	latest := va.Chain.Latest
	byID := map[string]DirectoryUser{}
	for _, u := range f.dir {
		byID[u.ID] = u
	}
	var wraps []map[string]any
	pins := map[string]pinDecision{}
	for _, id := range plan.added {
		u := byID[id]
		_, pin, err := c.checkPin(va.Keyring, u, false, va.Membership.Rotations)
		if err != nil {
			return fmt.Errorf("%s: %w", u.Email, err)
		}
		if pin != nil {
			pins[id] = pinDecision{*pin, va.Keyring.Pins[id].FP}
		}
		// A user who holds wraps already, because an editor approved them or
		// they rotated, needs none; the server asks for exactly the ones missing.
		if slices.ContainsFunc(pending, func(p PendingUser) bool {
			return p.User.ID == id && (p.State == PendingApproved || p.State == PendingLeft || p.State == PendingRotated)
		}) {
			continue
		}
		w, err := c.wrapEveryEpoch(k, a.ID, va, u)
		if err != nil {
			return err
		}
		wraps = append(wraps, w...)
	}
	var dropped []e2e.ExcludedEntry
	next.Excluded, dropped = dropExcluded(latest.Excluded, next.Members, f.dir)
	if len(dropped) > 0 && !isOwner(latest, k) {
		return ErrExcludedOwnerOnly
	}
	if _, err := c.putRecord(k, a.ID, va, next, wraps, nil, ""); err != nil {
		return err
	}
	for id, d := range pins {
		if err := c.storePin(k, id, d.pin, d.basedOn); err != nil {
			return fmt.Errorf("the server accepted the new membership record, but pinning %s failed: %w", id, err)
		}
	}
	if err := c.readBack(k, a.ID, ""); err != nil {
		return err
	}
	out.State = FanOutUpdated
	for _, g := range plan.addedGroups {
		vg, err := c.VerifyGroup(k, g, false)
		if err != nil {
			out.Pending = append(out.Pending, UnlistedUser{Err: fmt.Errorf("group %s: %w", g, err)})
			continue
		}
		res := &ShareGroupResult{}
		if err := c.approveGroupMembers(k, a.ID, vg.Chain, false, res); err != nil {
			return err
		}
		out.Approved, out.Pending = append(out.Approved, res.Approved...), append(out.Pending, res.Pending...)
	}
	return nil
}

// wrapEveryEpoch wraps the AK of every epoch up to the chain's latest to u,
// opening them with the caller's own keys and checking each against the
// chain's akCommit.
func (c *Client) wrapEveryEpoch(k *UnlockedKeys, artifactID string, va *VerifiedArtifact, u DirectoryUser) ([]map[string]any, error) {
	latest := va.Chain.Latest
	// Defense in depth behind VerifyChain's epoch pin, which already refuses a
	// stale epoch.
	if err := e2e.CheckEncryptEpoch(va.Keyring.EpochPin(artifactID), latest.Epoch); err != nil {
		return nil, err
	}
	aks, err := c.callerAKs(k, artifactID, va.Chain)
	if err != nil {
		return nil, err
	}
	return wrapsTo(artifactID, aks, latest.Epoch, u)
}

// wrapsTo wraps the AK of each epoch 1 to last in aks to u.
func wrapsTo(artifactID string, aks map[int][]byte, last int, u DirectoryUser) ([]map[string]any, error) {
	var wraps []map[string]any
	for epoch := 1; epoch <= last; epoch++ {
		ak, err := epochKey(aks, epoch)
		if err != nil {
			return nil, err
		}
		w, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
			Purpose: "ak", Artifact: artifactID, Epoch: uint64(epoch),
			RecipientID: u.ID, RecipientPub: u.X25519Pub,
		}, ak)
		if err != nil {
			return nil, err
		}
		wraps = append(wraps, map[string]any{"user": u.ID, "epoch": epoch, "wrapped": e2e.B64(w)})
	}
	return wraps, nil
}

// inheritPlan is the member and group lists an item's next record holds to
// follow its folder.
type inheritPlan struct {
	members []e2e.Member
	groups  []e2e.GroupShare
	// added and addedGroups are the IDs the plan lists that the item's record
	// did not, and epoch is set when an entry leaves or a role drops, which a
	// same-epoch record cannot do.
	added, addedGroups []string
	epoch              bool
	// skippedUsers and skippedGroups are the users and groups the folder lists
	// that the plan does not add: a deactivated or unverified account and a
	// deleted group, which a record may not add and the folder's rule does not
	// require.
	skippedUsers, skippedGroups []string
}

// nearestVia is the folder an entry that parent lists comes from: the folder
// that lists the user or group itself, not by inheritance. An entry the
// parent holds by inheritance already names it, so a folder further up that
// stops listing them takes the entry from every item below at once.
func nearestVia(via, parentID string) string {
	if via != "" {
		return via
	}
	return parentID
}

// planInherit works out the lists of the record that follows item, an item
// in the folder parentID whose latest record is parent (nil for an item at
// the top level). An entry with no via is a direct grant: it stays, at the
// higher of its role and the folder's. An entry with a via exists only
// because of a folder: it follows the folder's role and mark while the folder
// lists it, and leaves when the folder does not, which takes a next epoch. A
// user or group the folder lists and the item does not is added, marked with
// its nearest folder, unless usable says the user's account is deactivated or
// not verified, or live says the group was deleted: those are skipped, and
// kept if the item already lists them. The item's owner is never listed.
func planInherit(item e2e.MembershipBody, parent *e2e.MembershipBody, parentID string, usable func(user string) bool, live func(group string) bool) inheritPlan {
	p := inheritPlan{members: []e2e.Member{}}
	wantMembers := map[string]e2e.Member{}
	wantGroups := map[string]e2e.GroupShare{}
	if parent != nil {
		for _, m := range parent.Members {
			if m.User != item.Owner {
				wantMembers[m.User] = e2e.Member{User: m.User, Role: m.Role, FP: m.FP, Via: nearestVia(m.Via, parentID)}
			}
		}
		for _, g := range parent.Groups {
			wantGroups[g.Group] = e2e.GroupShare{Group: g.Group, Role: g.Role, Via: nearestVia(g.Via, parentID)}
		}
	}
	for _, m := range item.Members {
		w, listed := wantMembers[m.User]
		delete(wantMembers, m.User)
		switch {
		case m.Via == "":
			if listed && roleRank(w.Role) > roleRank(m.Role) {
				m.Role = w.Role
			}
		case listed:
			p.epoch = p.epoch || roleRank(w.Role) < roleRank(m.Role)
			m.Role, m.Via = w.Role, w.Via
		default:
			p.epoch = true // a member the folder no longer lists leaves
			continue
		}
		p.members = append(p.members, m)
	}
	for _, w := range wantMembers {
		if !usable(w.User) {
			p.skippedUsers = append(p.skippedUsers, w.User)
			continue
		}
		p.members = append(p.members, w)
		p.added = append(p.added, w.User)
	}
	for _, g := range item.Groups {
		w, listed := wantGroups[g.Group]
		delete(wantGroups, g.Group)
		switch {
		case g.Via == "":
			if listed && roleRank(w.Role) > roleRank(g.Role) {
				g.Role = w.Role
			}
		case listed:
			p.epoch = p.epoch || roleRank(w.Role) < roleRank(g.Role)
			g.Role, g.Via = w.Role, w.Via
		default:
			p.epoch = true // a group the folder no longer lists leaves
			continue
		}
		p.groups = append(p.groups, g)
	}
	for _, w := range wantGroups {
		if !live(w.Group) {
			p.skippedGroups = append(p.skippedGroups, w.Group)
			continue
		}
		p.groups = append(p.groups, w)
		p.addedGroups = append(p.addedGroups, w.Group)
	}
	slices.SortFunc(p.members, func(a, b e2e.Member) int { return strings.Compare(a.User, b.User) })
	slices.SortFunc(p.groups, func(a, b e2e.GroupShare) int { return strings.Compare(a.Group, b.Group) })
	slices.Sort(p.added)
	slices.Sort(p.addedGroups)
	slices.Sort(p.skippedUsers)
	slices.Sort(p.skippedGroups)
	return p
}

// managersOf is the entries of ms with role manager.
func managersOf(ms []e2e.Member) []e2e.Member {
	return slices.DeleteFunc(slices.Clone(ms), func(m e2e.Member) bool { return m.Role != "manager" })
}
