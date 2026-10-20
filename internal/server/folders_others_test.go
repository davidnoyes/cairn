package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Folders with other people's items: who may place an item in a folder, take
// it out, delete the folder, and what a member sees of an item they cannot
// read yet. See "Folders with other people's items" in design/e2e-api.md.

// othersWorld is four accounts and a folder alice owns, listing bob as an
// editor. Carol and dave are not on it yet.
type othersWorld struct {
	alice, bob, carol, dave actor
	folder                  *owned
}

func newOthersWorld(t *testing.T) *othersWorld {
	t.Helper()
	s, ts := testServer(t)
	w := &othersWorld{
		alice: seedKeyedAccount(t, s, ts.URL, "alice@example.com"),
		bob:   seedKeyedAccount(t, s, ts.URL, "bob@example.com"),
		carol: seedKeyedAccount(t, s, ts.URL, "carol@example.com"),
		dave:  seedKeyedAccount(t, s, ts.URL, "dave@example.com"),
	}
	w.folder = newItem(t, w.alice, "folder", "")
	w.folder.share("editor", w.bob)
	return w
}

// remove is a PUT to the parent route with a null parent: the removal a
// folder's editor makes.
func remove(c *testClient, id string) (int, string) { return move(c, id, nil) }

func TestAnEditorPlacesTheirOwnItemsInSomeoneElsesFolder(t *testing.T) {
	w := newOthersWorld(t)
	// Creating: the folder lists bob, so a record naming it is bob's to sign.
	made := itemIn(t, w.bob, "", w.folder)
	madeFolder := itemIn(t, w.bob, "folder", w.folder)
	if v := parentOf(t, w.bob.testClient, made.id); v == nil || *v != w.folder.id {
		t.Errorf("created item sits in %v, want the folder", v)
	}
	// The folder bob created inside belongs to bob.
	var fv folderView
	w.bob.mustDo("GET", "/api/artifacts/"+madeFolder.id, nil, &fv, http.StatusOK)
	if fv.Access != "owner" {
		t.Errorf("a folder an editor created: access %q, want owner", fv.Access)
	}
	// Moving: an item bob owns at the top level goes in.
	mine := newArtifact(t, w.bob, "mine")
	w.bob.mustDo("PUT", "/api/artifacts/"+mine.id+"/parent", map[string]any{"parent": w.folder.id}, nil, http.StatusOK)
	wantParent(t, w.bob.testClient, mine.id, w.folder.id)
	// The item's record names no folder yet, so it is pending until bob's
	// client writes one that does.
	wantInherit(t, w.bob.testClient, mine.id, "pending")
	// A folder bob owns can go in too.
	w.bob.mustDo("PUT", "/api/artifacts/"+newItem(t, w.bob, "folder", "").id+"/parent", map[string]any{"parent": w.folder.id}, nil, http.StatusOK)
}

func TestOnlyAnEditorMayPlaceAnItemInAFolder(t *testing.T) {
	w := newOthersWorld(t)
	w.folder.share("viewer", w.carol)
	mine := newArtifact(t, w.carol, "mine")
	// A viewer of the folder is refused, on create and on move.
	if got, msg := tryItem(t, w.carol, "", w.folder.id); got != http.StatusForbidden {
		t.Errorf("a viewer creates in the folder: %d %q, want 403", got, msg)
	}
	if got, msg := move(w.carol.testClient, mine.id, w.folder.id); got != http.StatusForbidden {
		t.Errorf("a viewer moves into the folder: %d %q, want 403", got, msg)
	}
	// A stranger cannot see the folder at all.
	if got, msg := tryItem(t, w.dave, "", w.folder.id); got != http.StatusNotFound {
		t.Errorf("a stranger creates in the folder: %d %q, want 404", got, msg)
	}
	wantParent(t, w.carol.testClient, mine.id, "")
}

func TestPlacingAnItemNeedsToOwnOrManageIt(t *testing.T) {
	w := newOthersWorld(t)
	theirs := newArtifact(t, w.alice, "alices")
	theirs.share("editor", w.bob)
	// Bob edits the folder and the item, but he does not manage the item.
	if got, msg := move(w.bob.testClient, theirs.id, w.folder.id); got != http.StatusForbidden {
		t.Errorf("an editor of both places the item: %d %q, want 403", got, msg)
	}
	// An item bob cannot read at all is not found.
	hidden := newArtifact(t, w.carol, "carols")
	if got, msg := move(w.bob.testClient, hidden.id, w.folder.id); got != http.StatusNotFound {
		t.Errorf("a stranger to the item places it: %d %q, want 404", got, msg)
	}
	// A manager of the item places it.
	theirs.share("manager", w.carol)
	w.folder.share("editor", w.carol)
	w.carol.mustDo("PUT", "/api/artifacts/"+theirs.id+"/parent", map[string]any{"parent": w.folder.id}, nil, http.StatusOK)
	wantParent(t, w.alice.testClient, theirs.id, w.folder.id)
	// The item's record names no folder yet, so it is pending.
	wantInherit(t, w.alice.testClient, theirs.id, "pending")
}

func TestRemovingAnItemFromAFolderYouEdit(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)
	again := itemIn(t, w.bob, "", w.folder)

	// A stranger to the folder is told nothing of the item.
	if got, msg := remove(w.dave.testClient, item.id); got != http.StatusNotFound {
		t.Errorf("a stranger removes the item: %d %q, want 404", got, msg)
	}
	w.folder.share("editor", w.carol)
	w.folder.share("viewer", w.dave)
	// A viewer cannot remove it, and learns nothing more than the stub says.
	if got, msg := remove(w.dave.testClient, item.id); got != http.StatusForbidden {
		t.Errorf("a viewer removes the item: %d %q, want 403", got, msg)
	}
	wantParent(t, w.bob.testClient, item.id, w.folder.id)
	// A folder's editor who cannot read the item removes it, and gets the
	// stub of it back.
	var out map[string]any
	w.carol.mustDo("PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{"parent": nil}, &out, http.StatusOK)
	if out["access"] != "none" || out["id"] != item.id || out["parent"] != nil {
		t.Errorf("the removal answered %v", out)
	}
	if _, ok := out["meta"]; ok {
		t.Errorf("the removal answered with meta: %v", out)
	}
	// The item is at its owner's top level, and its record still names the
	// folder, so it is pending until bob writes one that does not.
	wantParent(t, w.bob.testClient, item.id, "")
	wantInherit(t, w.bob.testClient, item.id, "pending")
	// Editing the folder does not let carol move the item anywhere else.
	other := newItem(t, w.alice, "folder", "")
	other.share("editor", w.carol)
	if got, msg := move(w.carol.testClient, again.id, other.id); got != http.StatusForbidden {
		t.Errorf("a folder editor moves the item into another folder: %d %q, want 403", got, msg)
	}
	// A stranger to both is told nothing.
	lone := newArtifact(t, w.bob, "lone")
	if got, msg := remove(w.dave.testClient, lone.id); got != http.StatusNotFound {
		t.Errorf("removing an item at the top level of someone else: %d %q, want 404", got, msg)
	}
}

func TestAnOwnerTakesTheirItemOutOfAFolderTheyOnlyView(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)
	// Alice lowers bob to a viewer, so he cannot edit the folder any more.
	b := w.folder.nextEpoch()
	b.Members[0].Role = "viewer"
	w.folder.apply(b)
	w.bob.mustDo("PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{"parent": nil}, nil, http.StatusOK)
	wantParent(t, w.bob.testClient, item.id, "")
}

func TestAnOwnerTakesTheirItemOutOfAFolderTheyCannotRead(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)
	// Alice takes bob off the folder altogether: he cannot read it, not even
	// as a viewer, and the item stays in it.
	w.folder.unshareNow(w.bob)
	w.bob.mustDo("GET", "/api/artifacts/"+w.folder.id, nil, nil, http.StatusNotFound)
	if got, msg := remove(w.carol.testClient, item.id); got != http.StatusNotFound {
		t.Errorf("a stranger removes the item: %d %q, want 404", got, msg)
	}
	w.bob.mustDo("PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{"parent": nil}, nil, http.StatusOK)
	wantParent(t, w.bob.testClient, item.id, "")
	var v map[string]any
	w.bob.mustDo("GET", "/api/artifacts/"+item.id, nil, &v, http.StatusOK)
	if _, ok := v["hiddenParent"]; ok {
		t.Errorf("the item is at the top level, yet the view says %v", v)
	}
}

func TestMovingBetweenFoldersNeedsBoth(t *testing.T) {
	w := newOthersWorld(t)
	second := newItem(t, w.alice, "folder", "")
	second.share("viewer", w.bob)
	item := itemIn(t, w.bob, "", w.folder)
	if got, msg := move(w.bob.testClient, item.id, second.id); got != http.StatusForbidden {
		t.Errorf("into a folder bob only views: %d %q, want 403", got, msg)
	}
	wantParent(t, w.bob.testClient, item.id, w.folder.id)
	b := second.nextEpoch()
	b.Members[0].Role = "editor"
	second.apply(b)
	w.bob.mustDo("PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{"parent": second.id}, nil, http.StatusOK)
	wantParent(t, w.bob.testClient, item.id, second.id)
	// The depth and cycle checks hold for a folder someone else owns.
	if got, msg := move(w.alice.testClient, second.id, second.id); got != http.StatusConflict {
		t.Errorf("a folder into itself: %d %q, want 409", got, msg)
	}
}

// stubOfItem reads the list c gets and returns the entry for id, as raw JSON.
func stubOfItem(t *testing.T, c *testClient, id string) map[string]any {
	t.Helper()
	var list []map[string]any
	c.mustDo("GET", "/api/artifacts", nil, &list, http.StatusOK)
	for _, e := range list {
		if e["id"] == id {
			return e
		}
	}
	return nil
}

func TestAnItemYouCannotReadIsListedAsAStub(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)
	inner := itemIn(t, w.bob, "folder", w.folder)
	deep := itemIn(t, w.bob, "", inner)
	w.folder.share("viewer", w.carol)

	stub := stubOfItem(t, w.carol.testClient, item.id)
	if stub == nil {
		t.Fatal("carol's list has no stub for bob's item")
	}
	want := map[string]any{"id": item.id, "kind": "artifact", "owner": w.bob.id, "parent": w.folder.id, "inherit": "pending", "access": "none"}
	if len(stub) != len(want) {
		t.Errorf("the stub is %v, want exactly the keys of %v", stub, want)
	}
	for k, v := range want {
		if stub[k] != v {
			t.Errorf("stub %s = %v, want %v", k, stub[k], v)
		}
	}
	if s := stubOfItem(t, w.carol.testClient, inner.id); s == nil || s["kind"] != "folder" {
		t.Errorf("the folder inside is not a stub: %v", s)
	}
	// Inside a folder carol cannot read, nothing is listed.
	if s := stubOfItem(t, w.carol.testClient, deep.id); s != nil {
		t.Errorf("an item in an unreadable folder is listed: %v", s)
	}
	// A stranger to the folder sees none of it.
	for _, id := range []string{item.id, inner.id, deep.id} {
		if s := stubOfItem(t, w.dave.testClient, id); s != nil {
			t.Errorf("dave's list holds %s: %v", id, s)
		}
	}
	// The stub opens nothing.
	wantStatus(t, w.carol.testClient, "GET", "/api/artifacts/"+item.id, nil, http.StatusNotFound)
	// Once the owner lists carol, the entry is the whole view.
	item.shareVia(w.folder, "viewer", w.carol)
	if e := stubOfItem(t, w.carol.testClient, item.id); e == nil || e["access"] != "viewer" || e["meta"] == nil && e["team"] == nil {
		t.Errorf("after bob's record the entry is %v, want the full view", e)
	}
	// The folder's owner reads what is in it, as an editor.
	if s := stubOfItem(t, w.alice.testClient, item.id); s == nil || s["access"] != "editor" {
		t.Errorf("alice's entry for bob's item: %v", s)
	}
}

func TestUnsharingTheFolderTakesAnotherOwnersItemAtOnce(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)
	w.folder.share("viewer", w.carol)
	item.shareVia(w.folder, "viewer", w.carol)
	wantStatus(t, w.carol.testClient, "GET", "/api/artifacts/"+item.id, nil, http.StatusOK)
	w.folder.unshareNow(w.carol)
	wantStatus(t, w.carol.testClient, "GET", "/api/artifacts/"+item.id, nil, http.StatusNotFound)
	wantInherit(t, w.bob.testClient, item.id, "pending")
	if s := stubOfItem(t, w.carol.testClient, item.id); s != nil {
		t.Errorf("carol still lists the item: %v", s)
	}
}

func TestDeletingAFolderWithOtherPeoplesItems(t *testing.T) {
	w := newOthersWorld(t)
	theirs := itemIn(t, w.bob, "", w.folder)
	theirFolder := itemIn(t, w.bob, "folder", w.folder)
	inside := itemIn(t, w.bob, "", theirFolder)
	mine := newArtifact(t, w.alice, "mine")
	w.alice.mustDo("PUT", "/api/artifacts/"+mine.id+"/parent", map[string]any{"parent": w.folder.id}, nil, http.StatusOK)
	w.folder.share("viewer", w.carol)
	theirs.shareVia(w.folder, "viewer", w.carol)
	path := "/api/artifacts/" + w.folder.id

	// Only the owner deletes it, an editor never.
	if got, msg := status(w.bob.testClient, "DELETE", path, nil); got != http.StatusForbidden {
		t.Errorf("an editor deletes the folder: %d %q, want 403", got, msg)
	}
	// An item the owner owns stops the delete.
	if got, msg := status(w.alice.testClient, "DELETE", path, nil); got != http.StatusConflict || msg != "the folder is not empty" {
		t.Errorf("deleting with the owner's own item inside: %d %q, want 409", got, msg)
	}
	w.alice.mustDo("DELETE", "/api/artifacts/"+mine.id, nil, nil, http.StatusOK)
	w.alice.mustDo("DELETE", path, nil, nil, http.StatusOK)

	// Bob's items are at his top level, with what was inside them, and
	// pending, because their records still name the folder.
	for _, a := range []*owned{theirs, theirFolder} {
		wantParent(t, w.bob.testClient, a.id, "")
		wantInherit(t, w.bob.testClient, a.id, "pending")
	}
	wantParent(t, w.bob.testClient, inside.id, theirFolder.id)
	// Carol had the item only through the folder: she loses it at once.
	wantStatus(t, w.carol.testClient, "GET", "/api/artifacts/"+theirs.id, nil, http.StatusNotFound)
	if got, msg := tryItem(t, w.bob, "", uuid.NewString()); got != http.StatusNotFound {
		t.Errorf("creating in the deleted folder: %d %q, want 404", got, msg)
	}
}

func TestAServerRefusesAPlacementWhoseRecordNamesAnotherFolder(t *testing.T) {
	w := newOthersWorld(t)
	_, req := itemRequest(t, w.bob, "", w.folder.id)
	delete(req, "parent")
	if got, msg := status(w.bob.testClient, "POST", "/api/artifacts", req); got != http.StatusConflict || !strings.Contains(msg, "folder") {
		t.Errorf("a record naming a folder the item is not placed in: %d %q, want 409", got, msg)
	}
}

// TestAnItemInAFolderItsOwnerCannotReadSaysSo checks the artifact view of an
// item in a folder the caller cannot read: the owner and a manager are told,
// without the folder's ID, so a client does not take the item for one at the
// top level; a reader is not told.
func TestAnItemInAFolderItsOwnerCannotReadSaysSo(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)
	item.share("manager", w.carol)
	item.share("viewer", w.dave)
	// Alice takes the folder away from bob; the item stays in it.
	w.folder.unshareNow(w.bob)
	wantParent(t, w.bob.testClient, item.id, "")

	hidden := func(v map[string]any) bool { h, _ := v["hiddenParent"].(bool); return h }
	cases := map[string]struct {
		c    *testClient
		want bool
	}{"owner": {w.bob.testClient, true}, "manager": {w.carol.testClient, true}, "viewer": {w.dave.testClient, false}}
	for name, tc := range cases {
		var got map[string]any
		tc.c.mustDo("GET", "/api/artifacts/"+item.id, nil, &got, http.StatusOK)
		if hidden(got) != tc.want || got["parent"] != nil {
			t.Errorf("%s GET: hiddenParent %v, parent %v; want hiddenParent %v, parent null", name, got["hiddenParent"], got["parent"], tc.want)
		}
		if !tc.want {
			if _, ok := got["hiddenParent"]; ok {
				t.Errorf("%s GET carries hiddenParent: %v", name, got)
			}
		}
		if e := stubOfItem(t, tc.c, item.id); e == nil || hidden(e) != tc.want || e["parent"] != nil {
			t.Errorf("%s list entry: %v, want hiddenParent %v", name, e, tc.want)
		}
	}
	// Placing the item where it already sits answers the same.
	var moved map[string]any
	w.bob.mustDo("PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{"parent": w.folder.id}, &moved, http.StatusOK)
	if !hidden(moved) || moved["parent"] != nil {
		t.Errorf("the move answered %v, want hiddenParent true and parent null", moved)
	}
	// An item at the top level, or in a folder the caller reads, has none.
	top := newArtifact(t, w.bob, "top")
	var v map[string]any
	w.bob.mustDo("GET", "/api/artifacts/"+top.id, nil, &v, http.StatusOK)
	if _, ok := v["hiddenParent"]; ok {
		t.Errorf("an item at the top level carries hiddenParent: %v", v)
	}
}
