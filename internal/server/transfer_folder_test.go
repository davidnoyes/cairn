package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Accepting an offer keeps the item in its folder, as transferring a file in
// Google Drive does. The accepting record is held to the folder's rules, but
// it need not catch up with a folder record newer than the item's.

// folderItemWorld is newTransferWorld with the item in a folder that the
// owner owns and that lists out as a viewer, so the item lists out via the
// folder.
func folderItemWorld(t *testing.T) (*transferWorld, *owned) {
	t.Helper()
	w := newTransferWorld(t)
	folder := newItem(t, w.owner, "folder", "")
	folder.share("viewer", w.out)
	w.o = itemIn(t, w.owner, "", folder)
	w.o.share("editor", w.ed, w.ed2)
	return w, folder
}

// asManager lists prev, who owns the folder, as its manager through it: the
// entry the folder requires of an item she no longer owns.
func asManager(b e2e.MembershipBody, prev actor, folder string) e2e.MembershipBody {
	b.Members = append(removeMember(b.Members, prev.id), viaMember(prev, "manager", folder))
	sortMembers(b.Members)
	return b
}

// accept signs b as newOwner, sends req with it, and returns the status and
// error text.
func accept(w *transferWorld, newOwner actor, b e2e.MembershipBody, req map[string]any) (int, string) {
	req["membership"] = signRecord(w.t, newOwner, b)
	return status(newOwner.testClient, "POST", w.transferPath("/accept"), req)
}

func TestAcceptKeepsTheItemInItsFolder(t *testing.T) {
	w, folder := folderItemWorld(t)
	offer := w.offer(w.ed)
	b, req := w.acceptOwnerOffer(w.ed, offer, false)

	// The record must still name the folder the item sits in.
	top := asManager(b, w.owner, folder.id)
	top.Folder = ""
	if got, msg := accept(w, w.ed, top, req); got != http.StatusConflict || !strings.Contains(msg, "folder") {
		t.Errorf("a record at the top level: %d %q, want 409", got, msg)
	}
	// The previous owner owns the folder, so the record lists her as its
	// manager: as an editor, or not at all, it is refused.
	if got, msg := accept(w, w.ed, b, req); got != http.StatusConflict || !strings.Contains(msg, w.owner.id) {
		t.Errorf("the folder's owner as an editor: %d %q, want 409 naming her", got, msg)
	}
	omitted := b
	omitted.Members = removeMember(b.Members, w.owner.id)
	if got, msg := accept(w, w.ed, omitted, req); got != http.StatusConflict || !strings.Contains(msg, w.owner.id) {
		t.Errorf("the folder's owner omitted: %d %q, want 409 naming her", got, msg)
	}
	if got, msg := accept(w, w.ed, asManager(b, w.owner, folder.id), req); got != http.StatusOK {
		t.Fatalf("accept: %d %q", got, msg)
	}
	wantInherit(t, w.ed.testClient, w.o.id, "ok")
	item, err := w.s.store.ArtifactByID(w.o.id)
	if err != nil {
		t.Fatal(err)
	}
	if item.ParentID != folder.id || item.OwnerID != w.ed.id {
		t.Errorf("the accepted item: owner %q parent %q, want %q in %q", item.OwnerID, item.ParentID, w.ed.id, folder.id)
	}
	// The new owner cannot read the folder, and the folder's owner keeps the item.
	wantParent(t, w.owner.testClient, w.o.id, folder.id)
	wantParent(t, w.ed.testClient, w.o.id, "")
	var list []folderView
	w.ed.mustDo("GET", "/api/artifacts", nil, &list, http.StatusOK)
	for _, v := range list {
		if v.ID == folder.id {
			t.Errorf("the new owner lists the previous owner's folder")
		}
	}
}

// A handover from an administrator keeps the item in the folder. The
// deactivated owner is not required to be listed, and is excluded.
func TestAnAdministratorsHandoverKeepsTheItemInItsFolder(t *testing.T) {
	w, folder := folderItemWorld(t)
	w.deactivate(w.owner)
	w.admin.mustDo("POST", "/api/admin/artifacts/"+w.o.id+"/transfer", map[string]any{"to": w.ed.id}, nil, http.StatusOK)
	b, req := w.accepting(w.ed, "", "admin", true)
	if got, msg := accept(w, w.ed, b, req); got != http.StatusOK {
		t.Fatalf("accept: %d %q", got, msg)
	}
	item, err := w.s.store.ArtifactByID(w.o.id)
	if err != nil || item.OwnerID != w.ed.id || item.ParentID != folder.id {
		t.Errorf("the handed-over item: %+v, %v; want ed's, in the folder", item, err)
	}
}

// The new owner may be the folder's owner: the record does not list her as a
// member of her own item, and the item stays in her folder.
func TestAcceptByTheFoldersOwnerKeepsTheItemAndUnlistsHer(t *testing.T) {
	w := newTransferWorld(t)
	folder := newItem(t, w.ed, "folder", "")
	folder.share("editor", w.owner)
	w.o = itemIn(t, w.owner, "", folder)
	w.o.share("editor", w.ed2)
	offer := w.offer(w.ed)
	b, req := w.acceptOwnerOffer(w.ed, offer, false)
	if got, msg := accept(w, w.ed, b, req); got != http.StatusOK {
		t.Fatalf("accept: %d %q", got, msg)
	}
	wantParent(t, w.ed.testClient, w.o.id, folder.id)
	wantInherit(t, w.ed.testClient, w.o.id, "ok")
}

// An item whose folder record is newer than its own is pending. The record
// that accepts it carries the entries the item has and no more, so it lands
// and the item stays pending; one that drops an entry the item has is refused.
func TestAcceptOfAPendingItemLandsAndStaysPending(t *testing.T) {
	w, folder := folderItemWorld(t)
	folder.share("viewer", w.v)
	wantInherit(t, w.owner.testClient, w.o.id, "pending")
	offer := w.offer(w.ed)
	b, req := w.acceptOwnerOffer(w.ed, offer, false)
	b = asManager(b, w.owner, folder.id)

	dropped := b
	dropped.Members = removeMember(b.Members, w.out.id)
	if got, msg := accept(w, w.ed, dropped, req); got != http.StatusConflict || !strings.Contains(msg, w.out.id) {
		t.Errorf("a record that drops an entry the item has: %d %q, want 409 naming it", got, msg)
	}
	if got, msg := accept(w, w.ed, b, req); got != http.StatusOK {
		t.Fatalf("accept: %d %q", got, msg)
	}
	wantInherit(t, w.ed.testClient, w.o.id, "pending")
	wantParent(t, w.owner.testClient, w.o.id, folder.id)
}

// An entry whose folder stopped listing the user is carried over as it is,
// but a via the item never had is refused.
func TestAcceptCarriesAStaleViaButNotAForgedOne(t *testing.T) {
	w, folder := folderItemWorld(t)
	folder.unshareNow(w.out)
	wantInherit(t, w.owner.testClient, w.o.id, "pending")
	offer := w.offer(w.ed)
	b, req := w.acceptOwnerOffer(w.ed, offer, false)
	b = asManager(b, w.owner, folder.id)

	forged := b
	forged.Members = append(append([]e2e.Member{}, b.Members...), viaMember(w.v, "viewer", folder.id))
	sortMembers(forged.Members)
	if got, msg := accept(w, w.ed, forged, req); got != http.StatusConflict || !strings.Contains(msg, "via") {
		t.Errorf("a forged via: %d %q, want 409", got, msg)
	}
	if got, msg := accept(w, w.ed, b, req); got != http.StatusOK {
		t.Fatalf("accept with the stale via: %d %q", got, msg)
	}
}

// A folder owned by a third party: the accepting record keeps listing them as
// the folder's manager, whoever else changes. As an editor or omitted, it is
// refused.
func TestAcceptRequiresAThirdPartyFolderOwnerAsManager(t *testing.T) {
	w := newTransferWorld(t)
	folder := newItem(t, w.ed2, "folder", "")
	folder.share("editor", w.owner)
	w.o = itemIn(t, w.owner, "", folder)
	w.o.share("editor", w.ed)
	offer := w.offer(w.ed)
	b, req := w.acceptOwnerOffer(w.ed, offer, false)

	asEditor := b
	asEditor.Members = append(removeMember(b.Members, w.ed2.id), e2e.Member{User: w.ed2.id, Role: "editor", FP: w.ed2.keys.fp(), Via: folder.id})
	sortMembers(asEditor.Members)
	if got, msg := accept(w, w.ed, asEditor, req); got != http.StatusConflict || !strings.Contains(msg, w.ed2.id) {
		t.Errorf("the folder's owner as an editor: %d %q, want 409 naming them", got, msg)
	}
	omitted := b
	omitted.Members = removeMember(b.Members, w.ed2.id)
	if got, msg := accept(w, w.ed, omitted, req); got != http.StatusConflict || !strings.Contains(msg, w.ed2.id) {
		t.Errorf("the folder's owner omitted: %d %q, want 409 naming them", got, msg)
	}
	if got, msg := accept(w, w.ed, b, req); got != http.StatusOK {
		t.Fatalf("accept: %d %q", got, msg)
	}
}

// The artifact view names the folder's owner for the item's owner, its
// managers, and the user an open offer names, and for no one else.
func TestTheViewNamesTheFoldersOwnerOnlyToThoseWhoNeedIt(t *testing.T) {
	w := newTransferWorld(t)
	folder := newItem(t, w.owner, "folder", "")
	w.o = itemIn(t, w.owner, "", folder)
	w.o.share("editor", w.ed, w.out)
	w.o.share("manager", w.ed2)
	w.o.share("viewer", w.v)
	top := newItem(t, w.owner, "", "")
	ownerOf := func(c *testClient, id string) string {
		t.Helper()
		var v struct {
			FolderOwner string `json:"folderOwner"`
		}
		c.mustDo("GET", "/api/artifacts/"+id, nil, &v, http.StatusOK)
		return v.FolderOwner
	}
	for name, c := range map[string]*testClient{"the owner": w.owner.testClient, "a manager": w.ed2.testClient} {
		if got := ownerOf(c, w.o.id); got != w.owner.id {
			t.Errorf("%s sees folderOwner %q, want %q", name, got, w.owner.id)
		}
	}
	for name, c := range map[string]*testClient{"an editor": w.ed.testClient, "a viewer": w.v.testClient} {
		if got := ownerOf(c, w.o.id); got != "" {
			t.Errorf("%s sees folderOwner %q, want none", name, got)
		}
	}
	w.offer(w.ed)
	if got := ownerOf(w.ed.testClient, w.o.id); got != w.owner.id {
		t.Errorf("the offered user sees folderOwner %q, want %q", got, w.owner.id)
	}
	if got := ownerOf(w.out.testClient, w.o.id); got != "" {
		t.Errorf("another editor sees folderOwner %q, want none", got)
	}
	if got := ownerOf(w.owner.testClient, top.id); got != "" {
		t.Errorf("an item at the top level shows folderOwner %q", got)
	}
}
