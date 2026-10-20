package client

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// folderTree is a folder with a nested folder and two items, owned by ada,
// beside the team world's users: bob, cat, and dan.
//
//	F
//	  item1
//	  G
//	    item2
type folderTree struct {
	*team
	f, g, item1, item2 string
}

func newFolderTree(t *testing.T) *folderTree {
	t.Helper()
	w := &folderTree{team: newTeam(t)}
	f, err := w.ada.CreateFolder("Work", "")
	if err != nil {
		t.Fatal(err)
	}
	g, err := w.ada.CreateFolder("Plans", f.ID)
	if err != nil {
		t.Fatal(err)
	}
	w.f, w.g = f.ID, g.ID
	w.item1 = mustCreate(t, w.ada, "one", InFolder(w.f)).ID
	w.item2 = mustCreate(t, w.ada, "two", InFolder(w.g)).ID
	putData(t, w.ada, w.item2)
	return w
}

// entry is what the artifact's latest record lists for the user with email,
// as c reads it, or nil.
func entry(t *testing.T, w *folderTree, c *Client, artifact, email string) *e2e.Member {
	t.Helper()
	dir, err := c.Directory()
	if err != nil {
		t.Fatal(err)
	}
	u, err := FindUser(dir, email)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range latestBody(t, c, artifact).Members {
		if m.User == u.ID {
			return &m
		}
	}
	return nil
}

// wantEntry fails unless the artifact lists email with this role and via.
func wantEntry(t *testing.T, w *folderTree, artifact, email, role, via string) {
	t.Helper()
	m := entry(t, w, w.ada, artifact, email)
	if m == nil || m.Role != role || m.Via != via {
		t.Errorf("%s lists %s as %+v, want %s via %q", artifact, email, m, role, via)
	}
}

func wantInherit(t *testing.T, c *Client, artifact, want string) {
	t.Helper()
	a, err := c.GetArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if a.Inherit != want {
		t.Errorf("inherit of %s = %q, want %q", artifact, a.Inherit, want)
	}
}

func wantStatus(t *testing.T, c *Client, artifact string, want int) {
	t.Helper()
	if got := status(t, c, artifact); got != want {
		t.Errorf("status of %s = %d, want %d", artifact, got, want)
	}
}

// fanOutOK runs FanOut and fails on an error, returning the result.
func fanOutOK(t *testing.T, c *Client, root string, includeRoot bool) *FanOutResult {
	t.Helper()
	res, err := c.FanOut(root, includeRoot, nil)
	if err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	return res
}

func stateOf(res *FanOutResult, id string) string {
	for _, it := range res.Items {
		if it.ID == id {
			return it.State
		}
	}
	return ""
}

func TestSharingAFolderFansOutToEveryItem(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	// Only the items in the folder itself lack its entries yet: the items in
	// the nested folder follow that folder's record, which is not updated.
	for _, id := range []string{w.g, w.item1} {
		wantInherit(t, w.ada, id, "pending")
	}
	wantInherit(t, w.ada, w.item2, "ok")
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantStatus(t, w.bob, id, http.StatusNotFound)
	}
	var done, total []int
	res, err := w.ada.FanOut(w.f, false, func(d, n int) { done, total = append(done, d), append(total, n) })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(done, []int{1, 2, 3}) || !slices.Equal(total, []int{3, 3, 3}) {
		t.Errorf("progress: done %v of %v", done, total)
	}
	if got := res.Count(FanOutUpdated); got != 3 || len(res.Items) != 3 {
		t.Errorf("result: %+v", res.Items)
	}
	// Folders come before the items inside them.
	if res.Items[0].ID != w.g || res.Items[1].ID != w.item2 || res.Items[2].ID != w.item1 {
		t.Errorf("order: %v %v %v", res.Items[0].ID, res.Items[1].ID, res.Items[2].ID)
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantEntry(t, w, id, "bob@example.com", "viewer", w.f)
		wantInherit(t, w.ada, id, "ok")
		wantStatus(t, w.bob, id, http.StatusOK)
		if got := wrapEpochs(t, w.bob, id); !slices.Equal(got, []int{1}) {
			t.Errorf("bob's wraps of %s: %v", id, got)
		}
	}
	d, err := w.bob.OpenData(w.item2, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if plain, _, err := d.Latest(); err != nil || string(plain) != "db" {
		t.Errorf("bob reads %q, %v", plain, err)
	}
}

func TestFanOutIsIdempotentAndResumes(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	// A run that stopped after the first item.
	res := fanOutOK(t, w.ada, w.item1, true)
	if stateOf(res, w.item1) != FanOutUpdated {
		t.Fatalf("item1: %+v", res.Items)
	}
	wantInherit(t, w.ada, w.item1, "ok")
	wantInherit(t, w.ada, w.g, "pending")
	seq := latestBody(t, w.ada, w.item1).Seq

	// Running it again finishes the rest and leaves the finished alone.
	res = fanOutOK(t, w.ada, w.f, false)
	if stateOf(res, w.g) != FanOutUpdated || stateOf(res, w.item2) != FanOutUpdated || stateOf(res, w.item1) != FanOutCurrent {
		t.Errorf("resumed: %+v", res.Items)
	}
	if got := latestBody(t, w.ada, w.item1).Seq; got != seq {
		t.Errorf("a finished item got another record: seq %d, was %d", got, seq)
	}
	res = fanOutOK(t, w.ada, w.f, false)
	if res.Count(FanOutCurrent) != 3 {
		t.Errorf("a third run: %+v", res.Items)
	}
	// Sharing again changes nothing and the fan-out has nothing left.
	if r, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil || !r.Unchanged {
		t.Errorf("Share again = %+v, %v", r, err)
	}
}

func TestUnsharingAFolderStartsAnEpochForEachItem(t *testing.T) {
	w := newFolderTree(t)
	for _, who := range []string{"bob@example.com", "cat@example.com"} {
		if _, err := w.ada.Share(w.f, who, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	fanOutOK(t, w.ada, w.f, false)
	wantStatus(t, w.bob, w.item2, http.StatusOK)

	if _, err := w.ada.Unshare(w.f, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	// The server stops serving bob at once, though the items still list him.
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantStatus(t, w.bob, id, http.StatusNotFound)
		wantStatus(t, w.cat, id, http.StatusOK)
		wantInherit(t, w.ada, id, "pending")
		wantStates(t, pendingStates(t, w.ada, id), map[string]string{"bob@example.com": PendingLeft})
	}

	res := fanOutOK(t, w.ada, w.f, false)
	if res.Count(FanOutNewEpoch) != 3 {
		t.Fatalf("result: %+v", res.Items)
	}
	for _, it := range res.Items {
		if len(it.Excluded) != 1 || it.Excluded[0].User.Email != "bob@example.com" {
			t.Errorf("%s excluded %+v", it.ID, it.Excluded)
		}
	}
	// The item's data is sealed again under the new epoch.
	for _, it := range res.Items {
		if it.ID == w.item2 && (it.ResealErr != nil || it.Resealed == nil || it.Resealed.Databases != 1 || it.Resealed.Files != 1) {
			t.Errorf("item2 resealed %+v, %v", it.Resealed, it.ResealErr)
		}
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		b := latestBody(t, w.ada, id)
		if b.Epoch != 2 || entry(t, w, w.ada, id, "bob@example.com") != nil {
			t.Errorf("%s: epoch %d, bob %+v", id, b.Epoch, entry(t, w, w.ada, id, "bob@example.com"))
		}
		if !slices.ContainsFunc(b.Excluded, func(x e2e.ExcludedEntry) bool { return x.Email == "bob@example.com" }) {
			t.Errorf("%s does not exclude bob: %+v", id, b.Excluded)
		}
		wantEntry(t, w, id, "cat@example.com", "viewer", w.f)
		wantInherit(t, w.ada, id, "ok")
		wantStatus(t, w.bob, id, http.StatusNotFound)
		if got := wrapEpochs(t, w.cat, id); !slices.Equal(got, []int{1, 2}) {
			t.Errorf("cat's wraps of %s: %v", id, got)
		}
	}
	d, err := w.cat.OpenData(w.item2, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if plain, _, err := d.Latest(); err != nil || string(plain) != "db" {
		t.Errorf("cat reads %q, %v", plain, err)
	}
	// Unsharing again finds the folder done and works through nothing.
	if _, err := w.ada.Unshare(w.f, "bob@example.com"); !errors.Is(err, ErrNotMember) {
		t.Errorf("Unshare again: %v, want ErrNotMember", err)
	}
	if res := fanOutOK(t, w.ada, w.f, false); res.Count(FanOutCurrent) != 3 {
		t.Errorf("a second fan-out: %+v", res.Items)
	}
}

func TestMovingAnItemIntoAndOutOfASharedFolder(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	loose := mustCreate(t, w.ada, "loose").ID
	wantStatus(t, w.bob, loose, http.StatusNotFound)

	if _, err := w.ada.Move(loose, w.g); err != nil {
		t.Fatal(err)
	}
	wantInherit(t, w.ada, loose, "pending")
	res := fanOutOK(t, w.ada, loose, true)
	if stateOf(res, loose) != FanOutUpdated {
		t.Fatalf("into: %+v", res.Items)
	}
	// The mark names the folder that lists bob, two levels up.
	wantEntry(t, w, loose, "bob@example.com", "editor", w.f)
	wantStatus(t, w.bob, loose, http.StatusOK)

	if _, err := w.ada.Move(loose, ""); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, w.bob, loose, http.StatusNotFound)
	wantInherit(t, w.ada, loose, "pending")
	res = fanOutOK(t, w.ada, loose, true)
	if stateOf(res, loose) != FanOutNewEpoch || len(res.Items[0].Excluded) != 1 {
		t.Fatalf("out: %+v", res.Items)
	}
	if b := latestBody(t, w.ada, loose); b.Epoch != 2 || len(b.Members) != 0 {
		t.Errorf("after moving out: epoch %d, members %+v", b.Epoch, b.Members)
	}
	wantInherit(t, w.ada, loose, "ok")
	wantStatus(t, w.bob, loose, http.StatusNotFound)
}

func TestDirectAndInheritedRolesMerge(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.item1, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.item2, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.f, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	// A direct viewer is raised to the folder's role, and stays direct. A
	// direct editor stays an editor. The folder with none is marked.
	wantEntry(t, w, w.item1, "bob@example.com", "editor", "")
	wantEntry(t, w, w.item2, "bob@example.com", "editor", "")
	wantEntry(t, w, w.g, "bob@example.com", "editor", w.f)

	// Unsharing the folder takes the inherited entry only: the direct ones stay.
	if _, err := w.ada.Unshare(w.f, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.ada, w.f, false)
	if stateOf(res, w.g) != FanOutNewEpoch || stateOf(res, w.item1) != FanOutCurrent && stateOf(res, w.item1) != FanOutUpdated {
		t.Errorf("unshare: %+v", res.Items)
	}
	wantStatus(t, w.bob, w.item1, http.StatusOK)
	wantStatus(t, w.bob, w.item2, http.StatusOK)
	wantStatus(t, w.bob, w.g, http.StatusNotFound)
	if b := latestBody(t, w.ada, w.item1); b.Epoch != 1 {
		t.Errorf("a direct entry started epoch %d", b.Epoch)
	}
}

func TestLoweringAFolderRoleStartsAnEpochForItsItems(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.ada, w.f, false)
	if res.Count(FanOutNewEpoch) != 3 {
		t.Fatalf("result: %+v", res.Items)
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantEntry(t, w, id, "bob@example.com", "viewer", w.f)
		if b := latestBody(t, w.ada, id); b.Epoch != 2 {
			t.Errorf("%s epoch %d", id, b.Epoch)
		}
	}
}

func TestAnItemCreatedInASharedFolderListsItsEntries(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	// Two levels down: the entry is marked with the folder that lists bob.
	n := mustCreate(t, w.ada, "new", InFolder(w.g)).ID
	wantEntry(t, w, n, "bob@example.com", "editor", w.f)
	wantInherit(t, w.ada, n, "ok")
	wantStatus(t, w.bob, n, http.StatusOK)
	if got := wrapEpochs(t, w.bob, n); !slices.Equal(got, []int{1}) {
		t.Errorf("bob's wraps: %v", got)
	}
	nf, err := w.ada.CreateFolder("More", w.f)
	if err != nil {
		t.Fatal(err)
	}
	wantEntry(t, w, nf.ID, "bob@example.com", "editor", w.f)
	wantStatus(t, w.bob, nf.ID, http.StatusOK)
}

func TestMembersNameTheFolderAnEntryComesFrom(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.item2, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	rows := func(c *Client) map[string]MemberView {
		_, rs, err := c.Members(w.item2)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]MemberView{}
		for _, r := range rs {
			out[r.Email] = r
		}
		return out
	}
	got := rows(w.ada)
	if r := got["bob@example.com"]; r.Via != w.f || r.ViaName != "Work" {
		t.Errorf("bob's row: %+v", r)
	}
	if r := got["cat@example.com"]; r.Via != "" || r.ViaName != "" {
		t.Errorf("cat's row: %+v", r)
	}
	// Cat cannot read the folder, so its ID stands for its name.
	if r := rows(w.cat)["bob@example.com"]; r.Via != w.f || r.ViaName != w.f {
		t.Errorf("bob's row as cat reads it: %+v", r)
	}
}

func TestSharingAFolderWithAGroupApprovesItsMembersOnEveryItem(t *testing.T) {
	w := newFolderTree(t)
	v, err := w.ada.CreateGroup("Reviewers", []string{"cat@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.f, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.ada, w.f, false)
	for _, it := range res.Items {
		if it.State != FanOutUpdated || len(it.Approved) != 1 || it.Approved[0].Email != "cat@example.com" {
			t.Errorf("%s: %+v", it.ID, it)
		}
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		b := latestBody(t, w.ada, id)
		if len(b.Groups) != 1 || b.Groups[0].Group != v.ID || b.Groups[0].Via != w.f {
			t.Errorf("%s groups: %+v", id, b.Groups)
		}
		wantStatus(t, w.cat, id, http.StatusOK)
	}
	// An item created in the folder lists the group and approves its members.
	late := mustCreate(t, w.ada, "late", InFolder(w.f)).ID
	wantStatus(t, w.cat, late, http.StatusOK)
	// Dropping the group from the folder stops cat at once, and the items'
	// next epoch excludes them.
	if _, err := w.ada.UnshareGroup(w.f, "Reviewers"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, w.cat, w.item1, http.StatusNotFound)
	wantInherit(t, w.ada, w.item1, "pending")
	res = fanOutOK(t, w.ada, w.f, false)
	if res.Count(FanOutNewEpoch) != 4 {
		t.Fatalf("result: %+v", res.Items)
	}
	for _, id := range []string{w.g, w.item1, w.item2, late} {
		if b := latestBody(t, w.ada, id); b.Epoch != 2 || len(b.Groups) != 0 {
			t.Errorf("%s: epoch %d groups %+v", id, b.Epoch, b.Groups)
		}
		wantInherit(t, w.ada, id, "ok")
	}
}

func TestAManagerOfAFolderFansOutToItsItems(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	// Bob manages the items through the folder, so his records for them are
	// valid, and he shares the folder with cat.
	if _, err := w.bob.Share(w.f, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.bob, w.f, false)
	if res.Count(FanOutUpdated) != 3 {
		t.Fatalf("bob's fan-out: %+v", res.Items)
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantEntry(t, w, id, "cat@example.com", "viewer", w.f)
		wantStatus(t, w.cat, id, http.StatusOK)
		if b := latestBody(t, w.ada, id); b.V != 2 || b.Signer == "" {
			t.Errorf("%s: record %+v is not bob's", id, b)
		}
	}
}

func TestAFanOutThatCannotSignLeavesItemsPending(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	// Bob is an editor, who cannot share, so the share itself is refused.
	if _, err := w.bob.Share(w.f, "cat@example.com", "viewer", false); err == nil {
		t.Fatal("an editor shared the folder")
	}
	// A fan-out by someone who signs none of the records fails on each item,
	// names it, and leaves it pending.
	if _, err := w.ada.Share(w.f, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res, err := w.bob.FanOut(w.f, false, nil)
	if !errors.Is(err, ErrFanOutIncomplete) || res.Count(FanOutFailed) != 2 {
		t.Fatalf("FanOut = %+v, %v", res, err)
	}
	for _, it := range res.Items {
		// The items in the nested folder wait for that folder's record.
		if it.ID == w.item2 && it.State != FanOutCurrent || it.ID != w.item2 && !errors.Is(it.Err, ErrNotOwner) {
			t.Errorf("%s: %+v", it.ID, it)
		}
	}
	wantInherit(t, w.ada, w.item1, "pending")
}

func TestPlanInherit(t *testing.T) {
	const f, up = "ffffffff-ffff-4fff-8fff-ffffffffffff", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	m := func(user, role, via string) e2e.Member {
		return e2e.Member{User: user, Role: role, FP: "fp-" + user, Via: via}
	}
	g := func(group, role, via string) e2e.GroupShare {
		return e2e.GroupShare{Group: group, Role: role, Via: via}
	}
	parent := &e2e.MembershipBody{Members: []e2e.Member{m("a", "editor", ""), m("b", "viewer", up), m("owner", "viewer", "")}}
	cases := []struct {
		name    string
		item    e2e.MembershipBody
		parent  *e2e.MembershipBody
		groups  []e2e.GroupShare
		members []e2e.Member
		out     []e2e.GroupShare
		added   []string
		epoch   bool
	}{
		{name: "everything is added, marked with its nearest folder, never the owner", item: e2e.MembershipBody{Owner: "owner"}, parent: parent,
			members: []e2e.Member{m("a", "editor", f), m("b", "viewer", up)}, added: []string{"a", "b"}},
		{name: "a direct grant stays direct and takes the higher role", item: e2e.MembershipBody{Owner: "owner", Members: []e2e.Member{m("a", "viewer", ""), m("b", "editor", "")}}, parent: parent,
			members: []e2e.Member{m("a", "editor", ""), m("b", "editor", "")}},
		{name: "an entry that follows the folder takes its role and mark", item: e2e.MembershipBody{Owner: "owner", Members: []e2e.Member{m("a", "viewer", up), m("b", "viewer", f)}}, parent: parent,
			members: []e2e.Member{m("a", "editor", f), m("b", "viewer", up)}},
		{name: "a lower role takes an epoch", item: e2e.MembershipBody{Owner: "owner", Members: []e2e.Member{m("a", "manager", f), m("b", "viewer", up)}}, parent: parent,
			members: []e2e.Member{m("a", "editor", f), m("b", "viewer", up)}, epoch: true},
		{name: "an entry the folder no longer lists leaves, with an epoch", item: e2e.MembershipBody{Owner: "owner", Members: []e2e.Member{m("a", "editor", f), m("c", "viewer", f), m("d", "viewer", "")}}, parent: parent,
			members: []e2e.Member{m("a", "editor", f), m("b", "viewer", up), m("d", "viewer", "")}, added: []string{"b"}, epoch: true},
		{name: "an item at the top level drops every inherited entry", item: e2e.MembershipBody{Owner: "owner", Members: []e2e.Member{m("a", "editor", f), m("d", "viewer", "")}},
			members: []e2e.Member{m("d", "viewer", "")}, epoch: true},
		{name: "a group's lower role takes an epoch", item: e2e.MembershipBody{Owner: "owner", Groups: []e2e.GroupShare{g("g2", "editor", f)}},
			parent: &e2e.MembershipBody{}, groups: []e2e.GroupShare{g("g2", "viewer", "")},
			members: []e2e.Member{}, out: []e2e.GroupShare{g("g2", "viewer", f)}, epoch: true},
		{name: "groups follow the same rules", item: e2e.MembershipBody{Owner: "owner", Groups: []e2e.GroupShare{g("g1", "viewer", ""), g("g2", "editor", f), g("g9", "viewer", f)}},
			parent: &e2e.MembershipBody{}, groups: []e2e.GroupShare{g("g1", "editor", ""), g("g2", "viewer", up), g("g3", "viewer", "")},
			members: []e2e.Member{}, out: []e2e.GroupShare{g("g1", "editor", ""), g("g2", "viewer", up), g("g3", "viewer", f)}, epoch: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := planInherit(c.item, c.parent, f, c.groups)
			if !slices.Equal(p.members, c.members) || !slices.Equal(p.groups, c.out) || !slices.Equal(p.added, c.added) || p.epoch != c.epoch {
				t.Errorf("plan = %+v\nwant members %v groups %v added %v epoch %v", p, c.members, c.out, c.added, c.epoch)
			}
		})
	}
}

func TestResharingAFolderAfterUnsharingListsTheUserAgainAtTheNewEpoch(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	res, err := w.ada.Unshare(w.f, "bob@example.com")
	if err != nil || res.ResealErr != nil {
		t.Fatalf("Unshare = %+v, %v: a folder holds no versions to seal again", res, err)
	}
	fanOutOK(t, w.ada, w.f, false)
	wantStatus(t, w.bob, w.item2, http.StatusNotFound)

	// The owner lists bob again by name, which drops the exclusions, in the
	// folder and then in each item, now at epoch 2.
	if r, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil || len(r.Dropped) != 1 {
		t.Fatalf("Share again = %+v, %v", r, err)
	}
	res2 := fanOutOK(t, w.ada, w.f, false)
	if res2.Count(FanOutUpdated) != 3 {
		t.Fatalf("result: %+v", res2.Items)
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		b := latestBody(t, w.ada, id)
		if b.Epoch != 2 || len(b.Excluded) != 0 {
			t.Errorf("%s: epoch %d excluded %+v", id, b.Epoch, b.Excluded)
		}
		wantEntry(t, w, id, "bob@example.com", "viewer", w.f)
		wantStatus(t, w.bob, id, http.StatusOK)
		if got := wrapEpochs(t, w.bob, id); !slices.Equal(got, []int{1, 2}) {
			t.Errorf("bob's wraps of %s: %v", id, got)
		}
	}
	d, err := w.bob.OpenData(w.item2, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if plain, _, err := d.Latest(); err != nil || string(plain) != "db" {
		t.Errorf("bob reads %q, %v", plain, err)
	}
}

func TestAManagerCannotAddAManagerOrListAnExcludedUserThroughAFanOut(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)

	// The owner makes cat a manager of the folder: only the owner lists a manager
	// in the items, so bob's fan-out leaves them pending.
	if _, err := w.ada.Share(w.f, "cat@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	res, err := w.bob.FanOut(w.f, false, nil)
	if !errors.Is(err, ErrFanOutIncomplete) {
		t.Fatalf("FanOut = %+v, %v", res, err)
	}
	for _, it := range res.Items {
		if it.State == FanOutFailed && !errors.Is(it.Err, ErrManagerOwnerOnly) {
			t.Errorf("%s: %v", it.ID, it.Err)
		}
	}
	if res.Count(FanOutFailed) != 2 {
		t.Errorf("failed: %+v", res.Items)
	}
	if res := fanOutOK(t, w.ada, w.f, false); res.Count(FanOutUpdated) != 3 {
		t.Fatalf("the owner's fan-out: %+v", res.Items)
	}

	// An item that excludes cat: the owner lists them again in the folder, and a
	// manager's record cannot drop the exclusion.
	if _, err := w.ada.Unshare(w.f, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	if _, err := w.ada.Share(w.f, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res, err = w.bob.FanOut(w.f, false, nil)
	if !errors.Is(err, ErrFanOutIncomplete) {
		t.Fatalf("FanOut = %+v, %v", res, err)
	}
	for _, it := range res.Items {
		if it.State == FanOutFailed && !errors.Is(it.Err, ErrExcludedOwnerOnly) {
			t.Errorf("%s: %v", it.ID, it.Err)
		}
	}
	if res := fanOutOK(t, w.ada, w.f, false); res.Count(FanOutUpdated) != 3 {
		t.Fatalf("the owner's fan-out: %+v", res.Items)
	}
}

func TestAFolderEntryUnderChangedKeysIsNotInherited(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	// Bob's keys change before the items list him, so the folder's entry is
	// for keys that are no longer his.
	w.resetBob(t)
	res, err := w.ada.FanOut(w.f, false, nil)
	if !errors.Is(err, ErrFanOutIncomplete) {
		t.Fatalf("FanOut = %+v, %v", res, err)
	}
	for _, it := range res.Items {
		if it.State == FanOutFailed && !errors.Is(it.Err, ErrMemberKeyChanged) {
			t.Errorf("%s: %v", it.ID, it.Err)
		}
	}
	if res.Count(FanOutFailed) == 0 {
		t.Errorf("nothing failed: %+v", res.Items)
	}
	// A new item in the folder is refused for the same reason.
	if _, err := w.ada.CreateArtifact("late", "", InFolder(w.f)); !errors.Is(err, ErrMemberKeyChanged) {
		t.Errorf("CreateArtifact in the folder = %v, want ErrMemberKeyChanged", err)
	}
}

func TestAUserApprovedThroughAGroupIsListedByTheFolderWithoutNewWraps(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.CreateGroup("Reviewers", []string{"cat@example.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.f, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, false)
	// Cat holds the wraps already, as an approved member of the group, so the
	// folder's entry for them by name needs none.
	if _, err := w.ada.Share(w.f, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.ada, w.f, false)
	if res.Count(FanOutUpdated) != 3 {
		t.Fatalf("result: %+v", res.Items)
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantEntry(t, w, id, "cat@example.com", "editor", w.f)
		wantStatus(t, w.cat, id, http.StatusOK)
	}
	// An item created in the folder lists the group, and approves its members.
	n := mustCreate(t, w.ada, "late", InFolder(w.g)).ID
	wantStatus(t, w.cat, n, http.StatusOK)
}

func TestAFanOutOfAnUnknownRootIsRefused(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.FanOut("00000000-0000-4000-8000-000000000000", false, nil); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("FanOut of a missing folder = %v", err)
	}
}
