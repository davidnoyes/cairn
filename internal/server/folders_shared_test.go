package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Shared folders: a folder's record lists users and groups, an item's record
// carries them as inherited entries, and access follows the folder. See
// "Shared folders" in design/e2e-api.md.

// inheritView is the part of an artifact view that shared folders add.
type inheritView struct {
	ID      string `json:"id"`
	Access  string `json:"access"`
	Inherit string `json:"inherit"`
}

func inheritOf(t *testing.T, c *testClient, id string) string {
	t.Helper()
	var v inheritView
	c.mustDo("GET", "/api/artifacts/"+id, nil, &v, http.StatusOK)
	return v.Inherit
}

func wantInherit(t *testing.T, c *testClient, id, want string) {
	t.Helper()
	if got := inheritOf(t, c, id); got != want {
		t.Errorf("inherit of %s = %q, want %q", id, got, want)
	}
}

// viaMember lists u as role through folder.
func viaMember(u actor, role, folder string) e2e.Member {
	return e2e.Member{User: u.id, Role: role, FP: u.keys.fp(), Via: folder}
}

// shareVia lists users through folder in a same-epoch record, at role, or
// raises their role to it when the record already lists them.
func (o *owned) shareVia(folder *owned, role string, users ...actor) {
	o.t.Helper()
	b := o.next()
	for _, u := range users {
		b.Members = append(b.Members, viaMember(u, role, folder.id))
	}
	b.Folder = folder.id
	sortMembers(b.Members)
	o.apply(b)
}

// unshareNow writes the next-epoch record that removes users and excludes
// them.
func (o *owned) unshareNow(users ...actor) {
	o.t.Helper()
	b := o.nextEpoch()
	for _, u := range users {
		b.Members = removeMember(b.Members, u.id)
		b.Excluded = append(b.Excluded, e2e.ExcludedEntry{User: u.id, FP: u.keys.fp(), Email: u.email})
	}
	sortExcluded(b.Excluded)
	o.apply(b)
}

func removeMember(ms []e2e.Member, id string) []e2e.Member {
	out := []e2e.Member{}
	for _, m := range ms {
		if m.User != id {
			out = append(out, m)
		}
	}
	return out
}

// putRecord PUTs b for o and returns the status and error text. It does not
// move o's latest record.
func (o *owned) putRecord(b e2e.MembershipBody) (int, string) {
	o.t.Helper()
	return status(o.owner.testClient, "PUT", "/api/artifacts/"+o.id+"/membership", o.change(b))
}

type sharedFolderWorld struct {
	*groupWorld
	folder, item *owned
}

// newSharedFolderWorld is a folder with an item in it, both private, as
// alice owns them.
func newSharedFolderWorld(t *testing.T) *sharedFolderWorld {
	t.Helper()
	w := &sharedFolderWorld{groupWorld: newGroupWorld(t)}
	w.folder = newItem(t, w.alice, "folder", "")
	w.item = newItem(t, w.alice, "", w.folder.id)
	return w
}

func TestFolderRecordListsMembersAndGroups(t *testing.T) {
	w := newSharedFolderWorld(t)
	g := newGroup(t, w.alice, "team", gm(w.alice, "manager"), gm(w.carol, "member"))
	w.folder.share("editor", w.bob)
	b := w.folder.next()
	b.Groups = []e2e.GroupShare{{Group: g.id, Role: "viewer"}}
	w.folder.apply(b)
	// A listed member reads the folder.
	var bob inheritView
	w.bob.mustDo("GET", "/api/artifacts/"+w.folder.id, nil, &bob, http.StatusOK)
	if bob.Access != "editor" {
		t.Errorf("bob's access to the folder: %q", bob.Access)
	}
}

func TestFolderRecordRefusesTeamAndPublic(t *testing.T) {
	w := newSharedFolderWorld(t)
	for name, edit := range map[string]func(*e2e.MembershipBody){
		"a team":              func(m *e2e.MembershipBody) { m.Team = "viewer" },
		"public":              func(m *e2e.MembershipBody) { m.Public = true },
		"public writes":       func(m *e2e.MembershipBody) { m.Public, m.PublicWrites = true, true },
		"public writes alone": func(m *e2e.MembershipBody) { m.PublicWrites = true },
	} {
		b := w.folder.next()
		edit(&b)
		got, msg := w.folder.putRecord(b)
		if got != http.StatusConflict || !strings.Contains(msg, "folder") {
			t.Errorf("%s: %d %q, want 409", name, got, msg)
		}
	}
	// A record that changes nothing is fine.
	if got, msg := w.folder.putRecord(w.folder.next()); got != http.StatusOK {
		t.Errorf("an unchanged record: %d %q", got, msg)
	}
}

func TestItemRecordMustHoldTheFoldersEntries(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.folder.share("editor", w.bob)
	w.folder.share("viewer", w.carol)

	// Missing the entries the folder lists: the refusal names the first by user ID.
	first := min(w.bob.id, w.carol.id)
	b := w.item.next()
	got, msg := w.item.putRecord(b)
	if got != http.StatusConflict || !strings.Contains(msg, "member "+first+" is missing") {
		t.Errorf("a record without bob and carol: %d %q", got, msg)
	}

	// An entry below the folder's role.
	b = w.item.next()
	b.Members = []e2e.Member{viaMember(w.bob, "viewer", w.folder.id), viaMember(w.carol, "viewer", w.folder.id)}
	sortMembers(b.Members)
	got, msg = w.item.putRecord(b)
	if got != http.StatusConflict || !strings.Contains(msg, "member "+w.bob.id+" is viewer") {
		t.Errorf("bob below the folder's role: %d %q", got, msg)
	}

	// An entry the folder does not list, marked as from it.
	b = w.item.next()
	b.Members = []e2e.Member{viaMember(w.bob, "editor", w.folder.id), viaMember(w.carol, "viewer", w.folder.id), viaMember(w.dave, "viewer", w.folder.id)}
	sortMembers(b.Members)
	got, msg = w.item.putRecord(b)
	if got != http.StatusConflict || !strings.Contains(msg, "member "+w.dave.id+" via "+w.folder.id) {
		t.Errorf("a false via: %d %q", got, msg)
	}

	// A via that names a folder that does not contain the item.
	other := newItem(t, w.alice, "folder", "")
	other.share("viewer", w.dave)
	b = w.item.next()
	b.Members = []e2e.Member{viaMember(w.bob, "editor", w.folder.id), viaMember(w.carol, "viewer", w.folder.id), viaMember(w.dave, "viewer", other.id)}
	sortMembers(b.Members)
	got, msg = w.item.putRecord(b)
	if got != http.StatusConflict || !strings.Contains(msg, "via "+other.id) {
		t.Errorf("a via that names another folder: %d %q", got, msg)
	}

	// A record with every entry lands, and a role above the folder's too.
	b = w.item.next()
	b.Members = []e2e.Member{viaMember(w.bob, "editor", w.folder.id), {User: w.carol.id, Role: "editor", FP: w.carol.keys.fp()}}
	sortMembers(b.Members)
	w.item.apply(b)
}

func TestViaOnAnItemInNoFolderIsRefused(t *testing.T) {
	w := newSharedFolderWorld(t)
	top := newArtifact(t, w.alice, "top")
	b := top.next()
	b.Members = []e2e.Member{viaMember(w.bob, "viewer", w.folder.id)}
	got, msg := top.putRecord(b)
	if got != http.StatusConflict || !strings.Contains(msg, "via") {
		t.Errorf("via on a top-level item: %d %q", got, msg)
	}
}

func TestCreatingAnItemInASharedFolderNeedsTheFoldersEntries(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.folder.share("viewer", w.bob)
	if got, msg := tryItem(t, w.alice, "", w.folder.id); got != http.StatusConflict || !strings.Contains(msg, "member "+w.bob.id+" is missing") {
		t.Fatalf("a create without the entries: %d %q", got, msg)
	}
	id, req := itemRequest(t, w.alice, "", w.folder.id)
	b := firstRecord(t, w.alice, id)
	b.Folder = w.folder.id
	b.Members = []e2e.Member{viaMember(w.bob, "viewer", w.folder.id)}
	req["membership"] = signRecord(t, w.alice, b)
	req["wraps"] = []any{map[string]any{"user": w.bob.id, "epoch": 1, "wrapped": e2e.B64(fakeWrap)}}
	w.alice.mustDo("POST", "/api/artifacts", req, nil, http.StatusCreated)
	var v inheritView
	w.bob.mustDo("GET", "/api/artifacts/"+id, nil, &v, http.StatusOK)
	if v.Access != "viewer" || v.Inherit != "ok" {
		t.Errorf("bob's view of the new item: %+v", v)
	}
}

func TestInheritPendingAndOk(t *testing.T) {
	w := newSharedFolderWorld(t)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")
	wantInherit(t, w.alice.testClient, w.folder.id, "ok")

	// The folder lists bob; the item's record does not yet.
	w.folder.share("viewer", w.bob)
	wantInherit(t, w.alice.testClient, w.item.id, "pending")
	wantInherit(t, w.alice.testClient, w.folder.id, "ok")
	// Bob cannot read the item yet.
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusNotFound)

	w.item.shareVia(w.folder, "viewer", w.bob)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")

	// Raising bob in the folder leaves the item below it, so it is pending.
	b := w.folder.next()
	b.Members[0].Role = "editor"
	w.folder.apply(b)
	wantInherit(t, w.alice.testClient, w.item.id, "pending")
	b = w.item.next()
	b.Members[0].Role = "editor"
	w.item.apply(b)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")
}

func TestAMemberViaTheFolderReads(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.folder.share("viewer", w.bob)
	w.item.shareVia(w.folder, "viewer", w.bob)
	var v inheritView
	w.bob.mustDo("GET", "/api/artifacts/"+w.item.id, nil, &v, http.StatusOK)
	if v.Access != "viewer" {
		t.Errorf("bob's access via the folder: %q", v.Access)
	}
	if _, ok := listIDs(t, w.bob.testClient)[w.item.id]; !ok {
		t.Error("the item is not in bob's list")
	}
	w.bob.mustDo("GET", "/api/artifacts/"+w.item.id+"/keys", nil, nil, http.StatusOK)
}

// pendingStates returns the pending list's state for each user, as the
// owner sees it.
func pendingStates(t *testing.T, c *testClient, id string) map[string]string {
	t.Helper()
	var list []struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	c.mustDo("GET", "/api/artifacts/"+id+"/pending", nil, &list, http.StatusOK)
	out := map[string]string{}
	for _, p := range list {
		out[p.ID] = p.State
	}
	return out
}

func TestUnsharingTheFolderStopsAccessAtOnce(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.folder.share("viewer", w.bob, w.carol)
	w.item.shareVia(w.folder, "viewer", w.bob, w.carol)
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusOK)

	// The folder drops bob, at the next epoch.
	w.folder.unshareNow(w.bob)
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusNotFound)
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+w.item.id+"/keys", nil, http.StatusNotFound)
	if _, ok := listIDs(t, w.bob.testClient)[w.item.id]; ok {
		t.Error("the item is still in bob's list")
	}
	// Carol, still listed by the folder, reads on.
	wantStatus(t, w.carol.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusOK)

	// The item still lists bob, who still holds its key: pending shows him as
	// one who has left, and the item is pending.
	states := pendingStates(t, w.alice.testClient, w.item.id)
	if states[w.bob.id] != "left" || states[w.carol.id] != "" {
		t.Errorf("pending states: %v", states)
	}
	wantInherit(t, w.alice.testClient, w.item.id, "pending")

	// The item's next epoch excludes bob, and the item is current again.
	w.item.unshareNow(w.bob)
	if _, ok := pendingStates(t, w.alice.testClient, w.item.id)[w.bob.id]; ok {
		t.Error("bob is still pending after the next epoch")
	}
	wantInherit(t, w.alice.testClient, w.item.id, "ok")
}

func TestMovingAnItemOutStopsAccessAtOnce(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.folder.share("viewer", w.bob, w.carol)
	// Carol also holds a direct entry, so she keeps reading.
	b := w.item.next()
	b.Members = []e2e.Member{viaMember(w.bob, "viewer", w.folder.id), {User: w.carol.id, Role: "viewer", FP: w.carol.keys.fp()}}
	sortMembers(b.Members)
	w.item.apply(b)

	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusOK)
	if got, msg := move(w.alice.testClient, w.item.id, nil); got != http.StatusOK {
		t.Fatalf("move out: %d %q", got, msg)
	}
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusNotFound)
	wantStatus(t, w.carol.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusOK)
	if got := pendingStates(t, w.alice.testClient, w.item.id)[w.bob.id]; got != "left" {
		t.Errorf("bob's pending state after the move: %q", got)
	}
	wantInherit(t, w.alice.testClient, w.item.id, "pending")

	// Moving back restores the entry with no new record.
	if got, msg := move(w.alice.testClient, w.item.id, w.folder.id); got != http.StatusOK {
		t.Fatalf("move in: %d %q", got, msg)
	}
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusOK)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")
}

func TestMovingAnItemIntoASharedFolderLeavesItPending(t *testing.T) {
	w := newSharedFolderWorld(t)
	top := newArtifact(t, w.alice, "top")
	w.folder.share("viewer", w.bob)
	wantInherit(t, w.alice.testClient, top.id, "ok")
	if got, msg := move(w.alice.testClient, top.id, w.folder.id); got != http.StatusOK {
		t.Fatalf("move: %d %q", got, msg)
	}
	wantInherit(t, w.alice.testClient, top.id, "pending")
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+top.id, nil, http.StatusNotFound)
	top.shareVia(w.folder, "viewer", w.bob)
	wantInherit(t, w.alice.testClient, top.id, "ok")
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+top.id, nil, http.StatusOK)
}

func TestADirectEntrySurvivesTheFolderUnsharing(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.folder.share("viewer", w.bob)
	b := w.item.next()
	b.Members = []e2e.Member{{User: w.bob.id, Role: "viewer", FP: w.bob.keys.fp()}}
	w.item.apply(b)
	w.folder.unshareNow(w.bob)
	wantStatus(t, w.bob.testClient, "GET", "/api/artifacts/"+w.item.id, nil, http.StatusOK)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")
}

func TestAGroupViaTheFolderReadsOnlyWhileTheFolderListsIt(t *testing.T) {
	w := newSharedFolderWorld(t)
	g := newGroup(t, w.alice, "readers", gm(w.alice, "manager"), gm(w.carol, "member"))
	b := w.folder.next()
	b.Groups = []e2e.GroupShare{{Group: g.id, Role: "viewer"}}
	w.folder.apply(b)
	wantInherit(t, w.alice.testClient, w.item.id, "pending")
	b = w.item.next()
	b.Groups = []e2e.GroupShare{{Group: g.id, Role: "viewer", Via: w.folder.id}}
	w.item.apply(b)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")

	// Carol, a member of the group, waits for approval while the item lists it.
	if got := pendingStates(t, w.alice.testClient, w.item.id)[w.carol.id]; got != "new" {
		t.Errorf("carol's pending state while the group counts: %q", got)
	}

	// The folder drops the group: the item's entry lapses, carol waits for
	// nothing, and the item is pending again.
	b = w.folder.next()
	b.Groups = nil
	w.folder.apply(b)
	wantInherit(t, w.alice.testClient, w.item.id, "pending")
	if got, ok := pendingStates(t, w.alice.testClient, w.item.id)[w.carol.id]; ok {
		t.Errorf("carol's pending state after the group lapsed: %q", got)
	}
	// An entry that names a folder that no longer lists the group is false.
	b = w.item.next()
	b.Groups = []e2e.GroupShare{{Group: g.id, Role: "viewer", Via: w.folder.id}}
	got, msg := w.item.putRecord(b)
	if got != http.StatusConflict || !strings.Contains(msg, "group "+g.id+" via") {
		t.Errorf("a group via a folder that no longer lists it: %d %q", got, msg)
	}
}

func TestLoweringTheFoldersRoleCapsTheItemAtOnce(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.folder.share("editor", w.bob)
	w.item.shareVia(w.folder, "editor", w.bob)
	var v inheritView
	w.bob.mustDo("GET", "/api/artifacts/"+w.item.id, nil, &v, http.StatusOK)
	if v.Access != "editor" || v.Inherit != "ok" {
		t.Fatalf("before: %+v", v)
	}
	b := w.folder.nextEpoch()
	b.Members[0].Role = "viewer"
	w.folder.apply(b)
	w.bob.mustDo("GET", "/api/artifacts/"+w.item.id, nil, &v, http.StatusOK)
	if v.Access != "viewer" || v.Inherit != "pending" {
		t.Errorf("after the folder lowered bob: %+v", v)
	}
	// The item's next epoch lowers the entry, and it is current again.
	b = w.item.nextEpoch()
	b.Members[0].Role = "viewer"
	w.item.apply(b)
	w.bob.mustDo("GET", "/api/artifacts/"+w.item.id, nil, &v, http.StatusOK)
	if v.Access != "viewer" || v.Inherit != "ok" {
		t.Errorf("after the item's record: %+v", v)
	}
}
