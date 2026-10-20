package client

import (
	"net/http"
	"slices"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Edges of the folder owner's inherited manager entry: nesting, a folder
// manager who is not the owner, and ownership transfer. See "Folders with
// other people's items" in design/e2e-api.md.

// Three owners down a chain: ada owns FA, cat owns FC inside it, and bob owns
// an item inside FC. Ada shares FA and fans out through cat's folder to bob's
// item, signing every record as a manager.
func TestAFanOutThroughANestedFolderReachesAThirdOwnersItem(t *testing.T) {
	w := newFolderTree(t)
	fa := mustFolder(t, w.ada, "FA", "")
	if _, err := w.ada.Share(fa, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, fa, nil)
	fc := mustFolder(t, w.cat, "FC", fa)
	if _, err := w.cat.Share(fc, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.cat, fc, nil)
	x := mustCreate(t, w.bob, "x", InFolder(fc)).ID
	ada, cat, dan := userID(t, w.ada), userID(t, w.cat), userID(t, w.dan)

	// FC lists ada via FA, and the item lists both owners.
	if m := memberOf(latestBody(t, w.cat, fc), ada); m == nil || m.Role != "manager" || m.Via != fa {
		t.Errorf("FC lists ada as %+v, want a manager via FA", m)
	}
	if m := memberOf(latestBody(t, w.bob, x), cat); m == nil || m.Role != "manager" || m.Via != fc {
		t.Errorf("the item lists cat as %+v, want a manager via FC", m)
	}

	if _, err := w.ada.Share(fa, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.ada, fa, nil)
	if res.Count(FanOutWaits) != 0 || res.Count(FanOutFailed) != 0 || stateOf(res, x) != FanOutUpdated || stateOf(res, fc) != FanOutUpdated {
		t.Fatalf("ada's fan-out: %+v", res.Items)
	}
	b := latestBody(t, w.bob, x)
	for _, want := range []struct{ user, role, via string }{{dan, "viewer", fa}, {ada, "manager", fa}, {cat, "manager", fc}} {
		if m := memberOf(b, want.user); m == nil || m.Role != want.role || m.Via != want.via {
			t.Errorf("the item lists %s as %+v, want %s via %s", want.user, m, want.role, want.via)
		}
	}
	if b.Signer != ada {
		t.Errorf("the item's record was signed by %q, want ada", b.Signer)
	}
	wantStatus(t, w.dan, x, http.StatusOK)
	if a, err := w.dan.GetArtifact(x); err != nil || a.Access != "viewer" {
		t.Errorf("dan's view of the item: %+v, %v", a, err)
	}
	wantInherit(t, w.bob, x, "ok")
	wantInherit(t, w.cat, fc, "ok")
}

// Cat manages ada's folder, and bob owns an item in it. Cat manages the item
// only if it lists her, and only bob adds a manager to it.
func TestAFolderManagerSignsAThirdPartysItemOnlyOnceItListsThem(t *testing.T) {
	setup := func(t *testing.T) (w *folderTree, fa, y string) {
		w = newFolderTree(t)
		fa = mustFolder(t, w.ada, "FA", "")
		if _, err := w.ada.Share(fa, "bob@example.com", "editor", false); err != nil {
			t.Fatal(err)
		}
		fanOutOK(t, w.ada, fa, nil)
		y = mustCreate(t, w.bob, "y", InFolder(fa)).ID
		// Ada makes cat a manager. That adds a manager to bob's item, which only
		// bob signs, so it waits on him.
		if _, err := w.ada.Share(fa, "cat@example.com", "manager", false); err != nil {
			t.Fatal(err)
		}
		res := fanOutOK(t, w.ada, fa, nil)
		if it := itemResult(res, y); it == nil || it.State != FanOutWaits || it.OwnerEmail != "bob@example.com" {
			t.Fatalf("ada's fan-out: %+v, want the item waiting on bob", res.Items)
		}
		if memberOf(latestBody(t, w.bob, y), userID(t, w.cat)) != nil {
			t.Fatal("the item lists cat before bob applied")
		}
		return w, fa, y
	}

	t.Run("bob applied first", func(t *testing.T) {
		w, fa, y := setup(t)
		applyOK(t, w.bob)
		cat := userID(t, w.cat)
		if m := memberOf(latestBody(t, w.bob, y), cat); m == nil || m.Role != "manager" || m.Via != fa {
			t.Fatalf("the item lists cat as %+v, want a manager via FA", m)
		}
		if _, err := w.cat.Share(fa, "dan@example.com", "viewer", false); err != nil {
			t.Fatal(err)
		}
		res, err := w.cat.FanOut(fa, nil, nil)
		if err != nil {
			t.Fatalf("cat's fan-out: %v", err)
		}
		if it := itemResult(res, y); it == nil || it.State != FanOutUpdated || res.Count(FanOutWaits) != 0 || res.Count(FanOutFailed) != 0 {
			t.Fatalf("cat's fan-out: %+v, want the item updated", res.Items)
		}
		dan := memberOf(latestBody(t, w.bob, y), userID(t, w.dan))
		if b := latestBody(t, w.bob, y); b.Signer != cat || dan == nil || dan.Via != fa {
			t.Errorf("the item's record: signer %q, dan %+v; want cat's, listing dan via FA", b.Signer, dan)
		}
		wantStatus(t, w.dan, y, http.StatusOK)
		wantInherit(t, w.bob, y, "ok")
	})

	t.Run("bob has not applied", func(t *testing.T) {
		w, fa, y := setup(t)
		if _, err := w.cat.Share(fa, "dan@example.com", "viewer", false); err != nil {
			t.Fatal(err)
		}
		res, err := w.cat.FanOut(fa, nil, nil)
		if err != nil {
			t.Fatalf("cat's fan-out: %v", err)
		}
		if it := itemResult(res, y); it == nil || it.State != FanOutWaits || it.Err != nil || it.OwnerEmail != "bob@example.com" || res.Count(FanOutFailed) != 0 {
			t.Fatalf("cat's fan-out: %+v, want the item waiting on bob", res.Items)
		}
		wantStatus(t, w.dan, y, http.StatusNotFound)
		wantInherit(t, w.bob, y, "pending")

		// Bob applies once, which adds cat and dan, and dan reads it.
		applyOK(t, w.bob)
		wantStatus(t, w.dan, y, http.StatusOK)
		wantInherit(t, w.bob, y, "ok")
		if m := memberOf(latestBody(t, w.bob, y), userID(t, w.cat)); m == nil || m.Role != "manager" || m.Via != fa {
			t.Errorf("the item lists cat as %+v after bob applied", m)
		}
	})
}

// A folder cannot be offered, so it keeps its owner, and bob's item in it keeps
// requiring ada.
func TestAFolderCannotBeTransferred(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	_, err := w.ada.OfferTransfer(w.work, "cat@example.com", false)
	if got := statusOf(err); got != http.StatusConflict {
		t.Fatalf("OfferTransfer of a folder: %v, want a 409", err)
	}
	if o, err := w.cat.OpenTransfer(w.work); err != nil || o != nil {
		t.Errorf("an offer is open for the folder: %+v, %v", o, err)
	}
	if b := latestBody(t, w.ada, w.work); b.Owner != userID(t, w.ada) {
		t.Errorf("the folder's owner is %s", b.Owner)
	}
	ada := userID(t, w.ada)
	if m := memberOf(latestBody(t, w.bob, w.theirs), ada); m == nil || m.Role != "manager" || m.Via != w.work {
		t.Errorf("bob's item lists ada as %+v, want a manager via the folder", m)
	}
}

// transferItem has owner offer the item to to, who accepts, keeping the
// previous owner.
func transferItem(t *testing.T, id string, owner, to *Client, toEmail string) {
	t.Helper()
	if _, err := owner.OfferTransfer(id, toEmail, false); err != nil {
		t.Fatalf("OfferTransfer: %v", err)
	}
	if _, err := to.AcceptTransfer(id, AcceptTransferOptions{}); err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
}

// Bob gives ada, who owns the folder, his item in it. She is listed as a
// manager of it, which makes her a listed manager the offer may go to, and the
// record that accepts it must not list her as a member of her own item.
func TestAnItemTransferredToTheFoldersOwnerIsNotRefusedForTheOldEntry(t *testing.T) {
	w := newOthersTree(t)
	// Cat is listed on the item via the folder too, so the accepted record
	// carries an entry whose folder no longer holds the item.
	if _, err := w.ada.Share(w.work, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	wantStatus(t, w.cat, w.theirs, http.StatusOK)
	ada, bob, cat := userID(t, w.ada), userID(t, w.bob), userID(t, w.cat)

	transferItem(t, w.theirs, w.bob, w.ada, "ada@example.com")

	b := latestBody(t, w.ada, w.theirs)
	if b.Owner != ada || memberOf(b, ada) != nil {
		t.Errorf("owner %s, ada listed as %+v; want her owner and unlisted", b.Owner, memberOf(b, ada))
	}
	if m := memberOf(b, bob); m == nil || m.Role != "editor" || m.Via != "" {
		t.Errorf("bob is %+v, want a direct editor", m)
	}
	// Accepting takes an item out of its folder, so the entry for cat lapses.
	if a, err := w.ada.GetArtifact(w.theirs); err != nil || a.ParentID != "" || a.Access != "owner" {
		t.Errorf("ada's view: %+v, %v; want her item at the top level", a, err)
	}
	wantStatus(t, w.cat, w.theirs, http.StatusNotFound)
	wantInherit(t, w.ada, w.theirs, "pending")
	// Ada applies it: a next epoch drops cat, and nothing waits.
	res := applyOK(t, w.ada)
	if len(res.Waiting) != 0 || res.FanOut.Count(FanOutFailed) != 0 || stateOf(&res.FanOut, w.theirs) != FanOutNewEpoch {
		t.Fatalf("ada's apply: %+v, waiting %+v", res.FanOut.Items, res.Waiting)
	}
	b = latestBody(t, w.ada, w.theirs)
	if memberOf(b, cat) != nil || !slices.ContainsFunc(b.Excluded, func(e e2e.ExcludedEntry) bool { return e.User == cat }) {
		t.Errorf("after applying: members %+v excluded %+v", b.Members, b.Excluded)
	}
	wantInherit(t, w.ada, w.theirs, "ok")
	for _, c := range []*Client{w.ada, w.bob} {
		if res := applyOK(t, c); len(res.Waiting) != 0 || len(res.FanOut.Items) != 0 {
			t.Errorf("a later apply: %+v, waiting %+v", res.FanOut.Items, res.Waiting)
		}
	}
}

// Bob gives a third user, who edits the folder, his item in it. Accepting
// takes an item to the new owner's top level (the server cannot know they read
// the folder), so the folder's owner loses it with the folder.
func TestAnItemTransferredToAThirdUserLeavesTheFolder(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.bob.Share(w.theirs, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	ada, cat := userID(t, w.ada), userID(t, w.cat)
	// Sharing the item keeps the folder's owner in its record.
	if m := memberOf(latestBody(t, w.bob, w.theirs), ada); m == nil || m.Role != "manager" || m.Via != w.work {
		t.Fatalf("bob's item lists ada as %+v before the transfer", m)
	}

	transferItem(t, w.theirs, w.bob, w.cat, "cat@example.com")

	b := latestBody(t, w.cat, w.theirs)
	if b.Owner != cat || b.Folder != "" {
		t.Errorf("owner %s folder %q, want cat's and the top level", b.Owner, b.Folder)
	}
	if a, err := w.cat.GetArtifact(w.theirs); err != nil || a.ParentID != "" || a.Access != "owner" {
		t.Errorf("cat's view: %+v, %v", a, err)
	}
	// The entry survives in the record without a folder to stand on, so ada
	// loses the item at once and cat's next record sheds her.
	wantStatus(t, w.ada, w.theirs, http.StatusNotFound)
	wantInherit(t, w.cat, w.theirs, "pending")
	applyOK(t, w.cat)
	b = latestBody(t, w.cat, w.theirs)
	if memberOf(b, ada) != nil || !slices.ContainsFunc(b.Excluded, func(e e2e.ExcludedEntry) bool { return e.User == ada }) {
		t.Errorf("after applying: members %+v excluded %+v", b.Members, b.Excluded)
	}
	wantInherit(t, w.cat, w.theirs, "ok")
}
