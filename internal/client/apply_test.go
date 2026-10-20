package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Other people's items in a folder: whoever shares the folder signs only the
// records they can, and the owner of every other item applies the share. See
// "Folders with other people's items" in design/e2e-api.md.

// othersTree is ada's folder Work, which bob edits, holding ada's item and
// two of bob's: an item, and a folder with an item in it.
//
//	Work (ada; bob edits)
//	  mine (ada)
//	  theirs (bob)
//	  theirFolder (bob)
//	    inside (bob)
type othersTree struct {
	*team
	work, mine, theirs, theirFolder, inside string
}

func newOthersTree(t *testing.T) *othersTree {
	t.Helper()
	w := &othersTree{team: newTeam(t)}
	w.work = mustFolder(t, w.ada, "Work", "")
	if _, err := w.ada.Share(w.work, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	w.mine = mustCreate(t, w.ada, "mine", InFolder(w.work)).ID
	w.theirs = mustCreate(t, w.bob, "theirs", InFolder(w.work)).ID
	w.theirFolder = mustFolder(t, w.bob, "theirFolder", w.work)
	w.inside = mustCreate(t, w.bob, "inside", InFolder(w.theirFolder)).ID
	return w
}

func mustFolder(t *testing.T, c *Client, name, parent string) string {
	t.Helper()
	f, err := c.CreateFolder(name, parent)
	if err != nil {
		t.Fatalf("CreateFolder(%s): %v", name, err)
	}
	return f.ID
}

// applyOK runs Apply and fails on an error.
func applyOK(t *testing.T, c *Client) *ApplyResult {
	t.Helper()
	res, err := c.Apply()
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return res
}

func TestAnEditorCreatesAndMovesItemsInSomeoneElsesFolder(t *testing.T) {
	w := newOthersTree(t)
	// The records name the folder, and bob's items are current.
	for _, id := range []string{w.theirs, w.theirFolder, w.inside} {
		wantInherit(t, w.bob, id, "ok")
	}
	if b := latestBody(t, w.bob, w.theirs); b.Folder != w.work {
		t.Errorf("the record of bob's item names %q, want the folder", b.Folder)
	}
	// Moving an item bob owns into the folder, and fanning out as he places it.
	moved := mustCreate(t, w.bob, "moved").ID
	if _, err := w.bob.Move(moved, w.work); err != nil {
		t.Fatalf("Move: %v", err)
	}
	wantInherit(t, w.bob, moved, "pending")
	fanOutOK(t, w.bob, moved, &Placing{Parent: w.work})
	wantInherit(t, w.bob, moved, "ok")
	if b := latestBody(t, w.bob, moved); b.Folder != w.work {
		t.Errorf("the record of the moved item names %q", b.Folder)
	}
	// Cat, a viewer of the folder, cannot place an item in it.
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.cat.CreateArtifact("nope", "", InFolder(w.work)); err == nil {
		t.Error("a viewer created an item in the folder")
	}
}

func TestAFanOutLeavesOtherPeoplesItemsWaitingOnTheirOwners(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.FanOut(w.work, nil, nil)
	if err != nil {
		t.Fatalf("FanOut: %v", err)
	}
	if got := stateOf(res, w.mine); got != FanOutUpdated {
		t.Errorf("ada's item: %q, want updated", got)
	}
	for _, id := range []string{w.theirs, w.theirFolder} {
		it := itemResult(res, id)
		if it == nil || it.State != FanOutWaits || it.Err != nil || it.OwnerEmail != "bob@example.com" {
			t.Errorf("%s: %+v, want waits on bob", id, it)
		}
		wantInherit(t, w.bob, id, "pending")
	}
	// The walk does not go into a folder that waits.
	if it := itemResult(res, w.inside); it != nil {
		t.Errorf("the item inside the waiting folder was visited: %+v", it)
	}
	wantStatus(t, w.cat, w.mine, http.StatusOK)
	wantStatus(t, w.cat, w.theirs, http.StatusNotFound)
}

func TestAMemberSeesAnItemTheyCannotReadAsAStub(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	tree, err := w.cat.Tree(w.work)
	if err != nil {
		t.Fatal(err)
	}
	stubs := map[string]*TreeNode{}
	for _, n := range tree {
		if n.Stub {
			stubs[n.ID] = n
		}
	}
	if len(tree) != 3 || len(stubs) != 2 || stubs[w.theirs] == nil || stubs[w.theirFolder] == nil {
		t.Fatalf("cat's tree: %d nodes, stubs %v", len(tree), stubs)
	}
	s := stubs[w.theirs]
	if s.Name != "" || s.Description != "" || len(s.Meta) != 0 || s.Access != "none" || s.Inherit != "pending" || s.OwnerID == "" || s.Kind != "artifact" || s.ParentID != w.work {
		t.Errorf("stub = %+v", s.Artifact)
	}
	if len(stubs[w.theirFolder].Children) != 0 {
		t.Errorf("a stub folder lists what is inside it: %v", stubs[w.theirFolder].Children)
	}
	// The ordinary list holds only what cat reads.
	all, err := w.cat.ListArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.ID == w.theirs || a.ID == w.theirFolder {
			t.Errorf("ListArtifacts holds the stub %s", a.ID)
		}
	}
	// The top of cat's own tree is empty: a stub belongs to the folder, and
	// an artifact shared with cat is not hers.
	if _, err := w.ada.Share(w.artifact, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if top, err := w.cat.Tree(""); err != nil || len(top) != 0 {
		t.Errorf("cat's own tree: %v, %v", top, err)
	}
	// A stub is not a folder she can open or delete.
	if _, err := w.cat.Tree(w.theirFolder); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("Tree of a stub folder: %v, want ErrNoArtifact", err)
	}
	if _, err := w.cat.FolderContents(w.theirFolder); !errors.Is(err, ErrNoArtifact) {
		t.Errorf("FolderContents of a stub folder: %v, want ErrNoArtifact", err)
	}
}

func TestApplyBringsTheItemsOfItsOwnerInStep(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)

	// Ada owns none of what is pending, so her apply only reports it.
	res := applyOK(t, w.ada)
	if len(res.FanOut.Items) != 0 || len(res.Waiting) != 2 {
		t.Fatalf("ada's apply: %+v, waiting %+v", res.FanOut.Items, res.Waiting)
	}
	for _, it := range res.Waiting {
		if it.State != FanOutWaits || it.OwnerEmail != "bob@example.com" {
			t.Errorf("waiting: %+v", it)
		}
	}
	// Bob's apply signs the item and the folder, then the item inside the
	// folder, which follows the folder's new record.
	res = applyOK(t, w.bob)
	if len(res.Waiting) != 0 || res.FanOut.Count(FanOutUpdated) != 3 || len(res.FanOut.Items) != 3 {
		t.Fatalf("bob's apply: %+v, waiting %+v", res.FanOut.Items, res.Waiting)
	}
	if res.FanOut.Items[len(res.FanOut.Items)-1].ID != w.inside && res.FanOut.Items[0].ID != w.theirs && res.FanOut.Items[0].ID != w.theirFolder {
		t.Errorf("order: %+v", res.FanOut.Items)
	}
	for _, id := range []string{w.theirs, w.theirFolder, w.inside} {
		wantInherit(t, w.bob, id, "ok")
		wantStatus(t, w.cat, id, http.StatusOK)
		if keys := wrapEpochs(t, w.cat, id); !slices.Equal(keys, []int{1}) {
			t.Errorf("cat holds wraps of epochs %v on %s", keys, id)
		}
	}
	// Idempotent: a second run finds nothing to do.
	res = applyOK(t, w.bob)
	if len(res.FanOut.Items) != 0 || len(res.Waiting) != 0 || len(res.Approvals) != 0 {
		t.Errorf("the second apply: %+v", res)
	}
	// Cat sees the real items now, and no stub.
	tree, err := w.cat.Tree(w.work)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range tree {
		if n.Stub {
			t.Errorf("%s is still a stub", n.ID)
		}
	}
}

func TestUnsharingTakesAnotherOwnersItemAtOnceAndApplyExcludesIt(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	applyOK(t, w.bob)
	wantStatus(t, w.cat, w.theirs, http.StatusOK)

	if _, err := w.ada.Unshare(w.work, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	fan := fanOutOK(t, w.ada, w.work, nil)
	// Cat loses bob's items before anyone applies: removal is immediate.
	for _, id := range []string{w.theirs, w.theirFolder, w.inside} {
		wantStatus(t, w.cat, id, http.StatusNotFound)
	}
	if got := stateOf(fan, w.mine); got != FanOutNewEpoch {
		t.Errorf("ada's item: %q, want newEpoch", got)
	}
	if got := stateOf(fan, w.theirs); got != FanOutWaits {
		t.Errorf("bob's item in ada's fan-out: %q, want waits", got)
	}
	wantInherit(t, w.bob, w.theirs, "pending")
	// Bob's apply starts the next epoch without cat.
	res := applyOK(t, w.bob)
	adaID := latestBody(t, w.ada, w.work).Owner
	if res.FanOut.Count(FanOutNewEpoch) != 3 {
		t.Fatalf("bob's apply: %+v", res.FanOut.Items)
	}
	for _, id := range []string{w.theirs, w.theirFolder, w.inside} {
		b := latestBody(t, w.bob, id)
		// Only ada, the folder's owner, stays: she reads what is in it.
		if b.Epoch != 2 || slices.ContainsFunc(b.Members, func(m e2e.Member) bool { return m.Via != "" && m.User != adaID }) {
			t.Errorf("%s: epoch %d, members %+v", id, b.Epoch, b.Members)
		}
		wantInherit(t, w.bob, id, "ok")
	}
}

func TestApplyAfterTheFolderIsDeletedNamesNoFolder(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	applyOK(t, w.bob)

	// Ada sees what the delete does before it runs: her own item goes, bob's
	// item and folder stay, and she reads them as their folder's owner.
	contents, err := w.ada.FolderContents(w.work)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents.Artifacts) != 1 || contents.Artifacts[0].ID != w.mine || len(contents.Folders) != 1 || len(contents.Moved) != 2 {
		t.Fatalf("contents: %+v", contents)
	}
	for _, m := range contents.Moved {
		if m.Access != "editor" || m.OwnerID == "" {
			t.Errorf("moved %+v", m)
		}
	}
	counts, err := w.ada.DeleteFolder(w.work, nil)
	if err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if counts != (DeleteCounts{Folders: 1, Artifacts: 1, Moved: 2}) {
		t.Errorf("counts = %+v", counts)
	}
	// Bob's items are at his top level and pending, and cat lost them at once.
	for _, id := range []string{w.theirs, w.theirFolder} {
		a, err := w.bob.GetArtifact(id)
		if err != nil || a.ParentID != "" || a.Inherit != "pending" {
			t.Errorf("%s after the delete: %+v, %v", id, a, err)
		}
		wantStatus(t, w.cat, id, http.StatusNotFound)
	}
	if a, err := w.bob.GetArtifact(w.inside); err != nil || a.ParentID != w.theirFolder {
		t.Errorf("the item inside bob's folder: %+v, %v", a, err)
	}
	// Bob's apply writes records that name no folder, then settles.
	res := applyOK(t, w.bob)
	if res.FanOut.Count(FanOutNewEpoch) != 3 {
		t.Fatalf("bob's apply: %+v", res.FanOut.Items)
	}
	for _, id := range []string{w.theirs, w.theirFolder, w.inside} {
		if b := latestBody(t, w.bob, id); b.Folder != "" && id != w.inside {
			t.Errorf("%s names the folder %q", id, b.Folder)
		}
		wantInherit(t, w.bob, id, "ok")
	}
	if res = applyOK(t, w.bob); len(res.FanOut.Items) != 0 {
		t.Errorf("the second apply: %+v", res.FanOut.Items)
	}
}

func TestOnlyTheOwnerDeletesAFolder(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.bob.FolderContents(w.work); !errors.Is(err, ErrNotFolderOwner) {
		t.Errorf("FolderContents by an editor: %v, want ErrNotFolderOwner", err)
	}
	if _, err := w.bob.DeleteFolder(w.work, nil); !errors.Is(err, ErrNotFolderOwner) {
		t.Errorf("DeleteFolder by an editor: %v, want ErrNotFolderOwner", err)
	}
	wantStatus(t, w.ada, w.work, http.StatusOK)
	// The server refuses to delete a folder that still holds the owner's item.
	if err := w.ada.DeleteArtifact(w.work); err == nil {
		t.Error("the server deleted a folder holding the owner's item")
	}
}

func TestApplyLeavesAMovedItemToItsOwner(t *testing.T) {
	w := newOthersTree(t)
	other := mustFolder(t, w.bob, "Other", "")
	// Another client moved the item, so its record names Work while the
	// server lists it in Other.
	if _, err := w.bob.Move(w.theirs, other); err != nil {
		t.Fatal(err)
	}
	res := applyOK(t, w.bob)
	it := itemResult(&res.FanOut, w.theirs)
	if it == nil || it.State != FanOutNeedsMove || !errors.Is(it.Err, ErrPlacement) || !strings.Contains(it.Err.Error(), "its record names folder "+w.work) {
		t.Fatalf("the moved item: %+v", it)
	}
	wantInherit(t, w.bob, w.theirs, "pending")
	// Placing it, as cairn move does, settles it.
	fanOutOK(t, w.bob, w.theirs, &Placing{Parent: other})
	wantInherit(t, w.bob, w.theirs, "ok")
}

func TestAManagerCannotConfirmAnotherOwnersOrphan(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.bob.Share(w.theirs, "cat@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	// An editor removes the item from the folder: it is bob's, at his top
	// level, and pending.
	if _, err := w.bob.Move(w.theirs, ""); err != nil {
		t.Fatal(err)
	}
	// Cat manages it, but moving is the owner's, so it waits on bob.
	res := applyOK(t, w.cat)
	if len(res.Waiting) != 1 || res.Waiting[0].ID != w.theirs || res.Waiting[0].OwnerEmail != "bob@example.com" {
		t.Fatalf("cat's apply: %+v, waiting %+v", res.FanOut.Items, res.Waiting)
	}
	if res = applyOK(t, w.bob); res.FanOut.Count(FanOutNewEpoch)+res.FanOut.Count(FanOutUpdated) != 1 {
		t.Fatalf("bob's apply: %+v", res.FanOut.Items)
	}
	wantInherit(t, w.bob, w.theirs, "ok")
}

func TestApplyReportsAnItemItCannotWrite(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	// The server refuses the write of one item's record.
	failing := NewWithKey(w.bob.Host, *w.bob.Key)
	failing.Anchors = w.bob.Anchors
	failing.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "PUT" && r.URL.Path == "/api/artifacts/"+w.theirs+"/membership" {
			return &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":"boom"}`))}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	res, err := failing.Apply()
	if !errors.Is(err, ErrFanOutIncomplete) || res.FanOut.Count(FanOutFailed) != 1 || res.FanOut.Count(FanOutUpdated) != 2 {
		t.Fatalf("Apply = %+v, %v", res.FanOut.Items, err)
	}
	if it := itemResult(&res.FanOut, w.theirs); it == nil || it.State != FanOutFailed {
		t.Errorf("the item: %+v", it)
	}
	// Running it again, with the server answering, finishes the rest.
	if res = applyOK(t, w.bob); res.FanOut.Count(FanOutUpdated) != 1 {
		t.Errorf("the second run: %+v", res.FanOut.Items)
	}
}

// Only Apply confirms a move to the top level: a fan-out of a folder never
// does, because there the server lists the item inside the folder, and an item
// that turns out to sit at the top level is refused, not rewritten.
func TestFanOutDoesNotConfirmAMoveToTheTopLevel(t *testing.T) {
	w := newOthersTree(t)
	// An editor of Work removed bob's item, so it sits at his top level and
	// its record still names Work.
	if _, err := w.bob.Move(w.theirs, ""); err != nil {
		t.Fatal(err)
	}
	// Ada's list is stale: it still shows the item inside Work.
	stale := NewWithKey(w.bob.Host, *w.bob.Key)
	stale.Anchors = w.bob.Anchors
	var sent []string
	stale.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "PUT" || r.Method == "POST" {
			sent = append(sent, r.Method+" "+r.URL.Path)
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil || r.Method != "GET" || r.URL.Path != "/api/artifacts" {
			return resp, err
		}
		var list []map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			return nil, err
		}
		resp.Body.Close()
		for _, m := range list {
			if m["id"] == w.theirs {
				m["parent"], m["inherit"] = w.work, "pending"
			}
		}
		data, err := json.Marshal(list)
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		resp.ContentLength = int64(len(data))
		return resp, nil
	})}
	res, err := stale.FanOut(w.work, nil, nil)
	if !errors.Is(err, ErrFanOutIncomplete) {
		t.Fatalf("FanOut: %+v, %v", res, err)
	}
	if it := itemResult(res, w.theirs); it == nil || it.State != FanOutFailed || !errors.Is(it.Err, ErrPlacement) {
		t.Errorf("the item: %+v", it)
	}
	if writesTo(sent, w.theirs) {
		t.Errorf("a record was written for the item: %v", sent)
	}
}

func TestApplyApprovesGroupNewcomers(t *testing.T) {
	w := &othersTree{team: newTeam(t)}
	w.work = mustFolder(t, w.ada, "Work", "")
	if _, err := w.ada.Share(w.work, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	w.theirs = mustCreate(t, w.bob, "theirs", InFolder(w.work)).ID
	g, err := w.ada.CreateGroup("Reviewers", []string{"cat@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.work, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	// Bob's apply lists the group and approves cat, who is in it now.
	res := applyOK(t, w.bob)
	if len(res.FanOut.Items) != 1 || !slices.Contains(emails(res.FanOut.Items[0].Approved), "cat@example.com") {
		t.Fatalf("bob's apply: %+v", res.FanOut.Items)
	}
	wantStatus(t, w.cat, w.theirs, http.StatusOK)
	// A newcomer to the group waits for an approver of the item, and bob's
	// next apply approves them.
	if _, err := w.ada.AddGroupMember(g.ID, "dan@example.com", false, false); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, w.dan, w.theirs, http.StatusNotFound)
	// Cat only reads the item, so her apply approves no one.
	if res = applyOK(t, w.cat); len(res.Approvals) != 0 {
		t.Errorf("a viewer's apply approved: %+v", res.Approvals)
	}
	res = applyOK(t, w.bob)
	// He is an editor of the folder too, so he approves dan there as well.
	approved := map[string][]string{}
	for _, a := range res.Approvals {
		approved[a.ID] = emails(a.Approved)
	}
	if len(res.FanOut.Items) != 0 || len(approved) != 2 || !slices.Equal(approved[w.theirs], []string{"dan@example.com"}) || !slices.Equal(approved[w.work], []string{"dan@example.com"}) {
		t.Fatalf("bob's second apply: %+v, approvals %+v", res.FanOut.Items, res.Approvals)
	}
	wantStatus(t, w.dan, w.theirs, http.StatusOK)
	if res = applyOK(t, w.bob); len(res.Approvals) != 0 {
		t.Errorf("the third apply approved again: %+v", res.Approvals)
	}
}

func TestApplyLeavesAnItemInAFolderItsOwnerCannotRead(t *testing.T) {
	w := newOthersTree(t)
	// Ada takes the folder away from bob, and later lists cat on it: bob's
	// items in it are pending, and he reads the folder no more.
	if _, err := w.ada.Unshare(w.work, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	wantInherit(t, w.bob, w.theirs, "pending")
	view, err := w.bob.getArtifact(w.theirs)
	if err != nil || view.ParentID != "" || !view.HiddenParent {
		t.Fatalf("bob's view of the item: %+v, %v", view, err)
	}
	before := latestBody(t, w.bob, w.theirs)

	res := applyOK(t, w.bob)
	it := itemResult(&res.FanOut, w.theirs)
	if it == nil || it.State != FanOutNeedsMove || it.Err == nil || !strings.Contains(it.Err.Error(), "can no longer read") || !strings.Contains(it.Err.Error(), "cairn move "+w.theirs+" --top") {
		t.Fatalf("the item in the unreadable folder: %+v", it)
	}
	if after := latestBody(t, w.bob, w.theirs); after.Seq != before.Seq || after.Folder != w.work {
		t.Errorf("apply wrote a record: seq %d to %d, folder %q", before.Seq, after.Seq, after.Folder)
	}
	wantInherit(t, w.bob, w.theirs, "pending")
}

func TestDeletingAFolderLeavesItsOwnersItemInsideAnotherOwnersFolder(t *testing.T) {
	w := newOthersTree(t)
	// Ada's folder Work holds bob's folder, which holds an item of ada's.
	m := mustCreate(t, w.ada, "m", InFolder(w.theirFolder)).ID
	contents, err := w.ada.FolderContents(w.work)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents.Artifacts) != 1 || contents.Artifacts[0].ID != w.mine || len(contents.Folders) != 1 || len(contents.Moved) != 2 {
		t.Fatalf("contents: artifacts %d, folders %d, moved %d; M is inside bob's folder, so it does not count", len(contents.Artifacts), len(contents.Folders), len(contents.Moved))
	}
	counts, err := w.ada.DeleteFolder(w.work, nil)
	if err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if counts != (DeleteCounts{Folders: 1, Artifacts: 1, Moved: 2}) {
		t.Errorf("counts = %+v", counts)
	}
	// Bob's folder is at bob's top level, with M still inside it.
	if a, err := w.bob.GetArtifact(w.theirFolder); err != nil || a.ParentID != "" {
		t.Errorf("bob's folder after the delete: %+v, %v", a, err)
	}
	wantStatus(t, w.ada, m, http.StatusOK)
	all, err := w.bob.listWithStubs()
	if err != nil {
		t.Fatal(err)
	}
	if a := byID(all, m); a == nil || a.ParentID != w.theirFolder {
		t.Errorf("M after the delete: %+v, want it inside bob's folder", a)
	}
}
