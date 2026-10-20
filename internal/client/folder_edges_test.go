package client

import (
	"net/http"
	"testing"
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
// record that accepts it must not list her as a member of her own item. The
// item stays in her folder, and cat, whom the folder lists, still reads it.
func TestAnItemTransferredToTheFoldersOwnerStaysInTheFolder(t *testing.T) {
	w := newOthersTree(t)
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
	if b.Folder != w.work {
		t.Errorf("the accepting record names folder %q, want %q", b.Folder, w.work)
	}
	if m := memberOf(b, bob); m == nil || m.Role != "editor" || m.Via != "" {
		t.Errorf("bob is %+v, want a direct editor", m)
	}
	if m := memberOf(b, cat); m == nil || m.Role != "viewer" || m.Via != w.work {
		t.Errorf("cat is %+v, want a viewer via the folder", m)
	}
	if a, err := w.ada.GetArtifact(w.theirs); err != nil || a.ParentID != w.work || a.Access != "owner" {
		t.Errorf("ada's view: %+v, %v; want her item in her folder", a, err)
	}
	wantStatus(t, w.cat, w.theirs, http.StatusOK)
	wantInherit(t, w.ada, w.theirs, "ok")
	for _, c := range []*Client{w.ada, w.bob} {
		if res := applyOK(t, c); len(res.Waiting) != 0 || stateOf(&res.FanOut, w.theirs) != "" {
			t.Errorf("a later apply: %+v, waiting %+v", res.FanOut.Items, res.Waiting)
		}
	}
}

// Bob gives cat, who edits the folder, his item in it. The item stays in the
// folder and still lists ada, the folder's owner, as its manager, and the
// folder's members keep reading it.
func TestAnItemTransferredToAThirdUserStaysInTheFolder(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.ada.Share(w.work, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.work, nil)
	ada, bob, cat := userID(t, w.ada), userID(t, w.bob), userID(t, w.cat)
	if m := memberOf(latestBody(t, w.bob, w.theirs), ada); m == nil || m.Role != "manager" || m.Via != w.work {
		t.Fatalf("bob's item lists ada as %+v before the transfer", m)
	}

	transferItem(t, w.theirs, w.bob, w.cat, "cat@example.com")

	b := latestBody(t, w.cat, w.theirs)
	if b.Owner != cat || b.Folder != w.work {
		t.Errorf("owner %s folder %q, want cat's and the folder", b.Owner, b.Folder)
	}
	if m := memberOf(b, ada); m == nil || m.Role != "manager" || m.Via != w.work {
		t.Errorf("the item lists ada as %+v, want a manager via the folder", m)
	}
	if memberOf(b, cat) != nil {
		t.Errorf("the item lists its owner as %+v", memberOf(b, cat))
	}
	if m := memberOf(b, bob); m == nil || m.Role != "editor" {
		t.Errorf("bob is %+v, want an editor", m)
	}
	if a, err := w.cat.GetArtifact(w.theirs); err != nil || a.ParentID != w.work || a.Access != "owner" {
		t.Errorf("cat's view: %+v, %v", a, err)
	}
	for _, c := range []*Client{w.ada, w.bob} {
		wantStatus(t, c, w.theirs, http.StatusOK)
	}
	wantInherit(t, w.cat, w.theirs, "ok")
}

// The new owner is a direct editor of the item and not a member of the folder,
// so they cannot read it. They accept anyway: the item stays in the folder,
// their view says it sits in one they cannot read, and the folder's members
// keep access.
func TestAnItemTransferredToAUserWhoCannotReadTheFolderStaysInIt(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.bob.Share(w.theirs, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	ada, cat := userID(t, w.ada), userID(t, w.cat)
	wantStatus(t, w.cat, w.work, http.StatusNotFound)

	transferItem(t, w.theirs, w.bob, w.cat, "cat@example.com")

	b := latestBody(t, w.cat, w.theirs)
	if b.Owner != cat || b.Folder != w.work {
		t.Errorf("owner %s folder %q, want cat's and the folder", b.Owner, b.Folder)
	}
	a, err := w.cat.GetArtifact(w.theirs)
	if err != nil || a.ParentID != "" || !a.HiddenParent || a.Access != "owner" {
		t.Errorf("cat's view: %+v, %v; want hiddenParent", a, err)
	}
	if m := memberOf(b, ada); m == nil || m.Role != "manager" || m.Via != w.work {
		t.Errorf("the item lists ada as %+v, want a manager via the folder", m)
	}
	for _, c := range []*Client{w.ada, w.bob} {
		wantStatus(t, c, w.theirs, http.StatusOK)
	}
	if a, err := w.ada.GetArtifact(w.theirs); err != nil || a.ParentID != w.work {
		t.Errorf("ada's view: %+v, %v", a, err)
	}
	wantInherit(t, w.cat, w.theirs, "ok")
}

// The folder lists dan, whom the item's record lacks, so the item is pending.
// A new owner who cannot read the folder accepts it with the entries it has,
// and it stays pending until ada, the folder's owner and its manager, applies.
func TestTransferOfAPendingItemLandsAndStaysPending(t *testing.T) {
	w := newOthersTree(t)
	if _, err := w.bob.Share(w.theirs, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.work, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	dan := userID(t, w.dan)
	wantInherit(t, w.bob, w.theirs, "pending")

	transferItem(t, w.theirs, w.bob, w.cat, "cat@example.com")

	b := latestBody(t, w.cat, w.theirs)
	if b.Owner != userID(t, w.cat) || b.Folder != w.work || memberOf(b, dan) != nil {
		t.Errorf("the accepting record: owner %s folder %q, dan %+v", b.Owner, b.Folder, memberOf(b, dan))
	}
	wantInherit(t, w.cat, w.theirs, "pending")
	wantStatus(t, w.dan, w.theirs, http.StatusNotFound)

	applyOK(t, w.ada)
	wantInherit(t, w.cat, w.theirs, "ok")
	wantStatus(t, w.dan, w.theirs, http.StatusOK)
	if m := memberOf(latestBody(t, w.cat, w.theirs), dan); m == nil || m.Role != "viewer" || m.Via != w.work {
		t.Errorf("after ada applied, dan is %+v", m)
	}
}

// An administrator hands over an item in a folder while its owner is
// deactivated. The record keeps the folder, and the item stays in it.
func TestAnAdministratorsHandoverKeepsTheItemInItsFolder(t *testing.T) {
	x := newXfer(t, nil)
	f, err := x.ada.CreateFolder("Work", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.ada.Move(x.artifact, f.ID); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, x.ada, x.artifact, &Placing{Parent: f.ID})
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	// Ada owns the folder, and an administrator's handover drops her anyway:
	// she is deactivated, so the folder cannot require her.
	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true}); err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	latest := x.verify(x.dan).Chain.Latest
	if latest.Owner != x.id(x.bob) || latest.Folder != f.ID {
		t.Errorf("latest record: owner %s folder %q, want bob's and %q", latest.Owner, latest.Folder, f.ID)
	}
	a, err := x.bob.GetArtifact(x.artifact)
	if err != nil || a.ParentID != "" || !a.HiddenParent || a.Access != "owner" {
		t.Errorf("bob's view: %+v, %v; want an item in a folder he cannot read", a, err)
	}
	wantStatus(t, x.cat, x.artifact, http.StatusOK)
}
