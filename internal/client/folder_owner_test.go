package client

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// The folder's owner manages what is in it: an item someone else owns lists
// the owner of its folder as a manager via that folder. See "Placing an item
// in someone else's folder" in design/e2e-api.md. The server tests hold the
// table of records this plans.

func memberOf(b e2e.MembershipBody, user string) *e2e.Member {
	i := slices.IndexFunc(b.Members, func(m e2e.Member) bool { return m.User == user })
	if i < 0 {
		return nil
	}
	return &b.Members[i]
}

func TestTheFoldersOwnerManagesAnItemAnEditorPlacedInIt(t *testing.T) {
	w := newOthersTree(t)
	ada := latestBody(t, w.ada, w.work).Owner

	// Bob created the item in ada's folder, so its record lists ada.
	m := memberOf(latestBody(t, w.bob, w.theirs), ada)
	if m == nil || m.Role != "manager" || m.Via != w.work {
		t.Fatalf("bob's item lists ada as %+v, want a manager via the folder", m)
	}
	a, err := w.ada.GetArtifact(w.theirs)
	if err != nil || a.Access != "manager" {
		t.Fatalf("ada's view of bob's item: %+v, %v", a, err)
	}
	// She may edit it: the first record sealed the key to her.
	if _, err := w.ada.Push(w.theirs, "", siteDir(t), "v1", ""); err != nil {
		t.Fatalf("ada pushes to bob's item: %v", err)
	}
	// An item placed by a move lists her once its owner fans out. That adds a
	// manager, which only the owner does, and the owner signs the placement.
	moved := mustCreate(t, w.bob, "moved").ID
	if _, err := w.bob.Move(moved, w.work); err != nil {
		t.Fatal(err)
	}
	if got := managersOf(latestBody(t, w.bob, moved).Members); len(got) != 0 {
		t.Fatalf("the item lists managers %+v before it is placed", got)
	}
	fanOutOK(t, w.bob, moved, &Placing{Parent: w.work})
	if m := memberOf(latestBody(t, w.bob, moved), ada); m == nil || m.Role != "manager" || m.Via != w.work {
		t.Errorf("the moved item lists ada as %+v", m)
	}
	wantStatus(t, w.ada, moved, http.StatusOK)
	// Ada's own items list no one on account of her folder.
	if m := memberOf(latestBody(t, w.ada, w.mine), ada); m != nil {
		t.Errorf("ada's own item lists her as %+v", m)
	}
}

func TestTheFoldersOwnerLosesTheItemWhenItLeavesTheFolder(t *testing.T) {
	w := newOthersTree(t)
	ada := latestBody(t, w.ada, w.work).Owner
	wantStatus(t, w.ada, w.theirs, http.StatusOK)
	if a, err := w.ada.GetArtifact(w.theirs); err != nil || a.Access != "manager" {
		t.Fatalf("ada's view of bob's item: %+v, %v", a, err)
	}

	if _, err := w.bob.Move(w.theirs, ""); err != nil {
		t.Fatal(err)
	}
	// Ada loses it at once, before anyone signs anything.
	wantStatus(t, w.ada, w.theirs, http.StatusNotFound)
	// Bob's next epoch excludes her.
	applyOK(t, w.bob)
	b := latestBody(t, w.bob, w.theirs)
	if b.Epoch != 2 || memberOf(b, ada) != nil || !slices.ContainsFunc(b.Excluded, func(e e2e.ExcludedEntry) bool { return e.User == ada }) {
		t.Errorf("bob's item after the move: epoch %d members %+v excluded %+v", b.Epoch, b.Members, b.Excluded)
	}
	wantInherit(t, w.bob, w.theirs, "ok")
}

func TestAFolderInsideAFolderListsBothOwners(t *testing.T) {
	w := newOthersTree(t)
	ada := latestBody(t, w.ada, w.work).Owner
	// Cat edits ada's folder and owns a folder inside it, where bob puts an
	// item: ada owns the folder above, cat the one it is in.
	if _, err := w.ada.Share(w.work, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	catFolder := mustFolder(t, w.cat, "Cat's", w.work)
	item := mustCreate(t, w.bob, "deep", InFolder(catFolder)).ID
	cat := latestBody(t, w.cat, catFolder).Owner

	b := latestBody(t, w.bob, item)
	if m := memberOf(b, ada); m == nil || m.Role != "manager" || m.Via != w.work {
		t.Errorf("ada is %+v, want a manager via her folder", m)
	}
	if m := memberOf(b, cat); m == nil || m.Role != "manager" || m.Via != catFolder {
		t.Errorf("cat is %+v, want a manager via her folder", m)
	}
	wantStatus(t, w.ada, item, http.StatusOK)
	wantStatus(t, w.cat, item, http.StatusOK)
	wantInherit(t, w.bob, item, "ok")
}

// Ada shares her folder with cat as a viewer. She manages bob's items, so she
// signs them herself, with cat added via the folder, and none is left waiting
// on bob.
func TestTheFoldersOwnerSharesTheFolderAndSignsOthersItems(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.ada, w.work, nil)
	if res.Count(FanOutUpdated) != 4 || res.Count(FanOutWaits) != 0 || res.Count(FanOutFailed) != 0 {
		t.Fatalf("ada's fan-out: %+v", res.Items)
	}
	for _, id := range []string{w.theirs, w.theirFolder, w.inside} {
		wantInherit(t, w.bob, id, "ok")
		wantStatus(t, w.cat, id, http.StatusOK)
	}
	if m := memberOf(latestBody(t, w.bob, w.theirs), userID(t, w.cat)); m == nil || m.Role != "viewer" || m.Via != w.work {
		t.Errorf("bob's item lists cat as %+v, want a viewer via the folder", m)
	}
	if res := applyOK(t, w.ada); len(res.Waiting) != 0 || len(res.FanOut.Items) != 0 {
		t.Errorf("ada's apply: %+v, waiting %+v", res.FanOut.Items, res.Waiting)
	}
	if res := applyOK(t, w.bob); len(res.Waiting) != 0 || len(res.FanOut.Items) != 0 {
		t.Errorf("bob's apply: %+v, waiting %+v", res.FanOut.Items, res.Waiting)
	}
}

// Ada lists cat on her folder as a manager. That adds a manager to bob's
// items, which only their owner signs, so they wait on bob.
func TestTheFoldersOwnerSharingAManagerWaitsOnTheItemsOwner(t *testing.T) {
	w := newOthersTree(t)
	res := shareManagerLeavingPending(t, w)
	for _, id := range []string{w.theirs, w.theirFolder} {
		if it := itemResult(res, id); it == nil || it.State != FanOutFailed || !errors.Is(it.Err, ErrManagerOwnerOnly) {
			t.Errorf("%s: %+v, want failed with ErrManagerOwnerOnly", id, it)
		}
		wantInherit(t, w.bob, id, "pending")
		wantStatus(t, w.cat, id, http.StatusNotFound)
	}
	// Apply reports them as waiting on bob.
	ap := applyOK(t, w.ada)
	if len(ap.Waiting) != 2 || ap.Waiting[0].OwnerEmail != "bob@example.com" {
		t.Errorf("ada's apply: waiting %+v", ap.Waiting)
	}
	// Bob signs them.
	applyOK(t, w.bob)
	for _, id := range []string{w.theirs, w.theirFolder, w.inside} {
		wantInherit(t, w.bob, id, "ok")
		wantStatus(t, w.cat, id, http.StatusOK)
	}
}
