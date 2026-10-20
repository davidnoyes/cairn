package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// Placement is signed: a membership record names the folder its item sits
// in, and the server refuses one that names another. See "Placement is
// signed" in design/e2e-api.md.

func wantPlacementRefusal(t *testing.T, got int, msg string) {
	t.Helper()
	if got != http.StatusConflict || !strings.Contains(msg, "placement") {
		t.Errorf("got %d %q, want 409 placement", got, msg)
	}
}

func TestRecordMustNameTheFolderTheItemSitsIn(t *testing.T) {
	cases := []struct {
		name   string
		pick   func(w *sharedFolderWorld, top, other *owned) (o *owned, folder string)
		wantOK bool
	}{
		{"an item in a folder names it", func(w *sharedFolderWorld, _, _ *owned) (*owned, string) { return w.item, w.folder.id }, true},
		{"an item in a folder names none", func(w *sharedFolderWorld, _, _ *owned) (*owned, string) { return w.item, "" }, false},
		{"an item in a folder names another", func(w *sharedFolderWorld, _, other *owned) (*owned, string) { return w.item, other.id }, false},
		{"a top-level item names none", func(_ *sharedFolderWorld, top, _ *owned) (*owned, string) { return top, "" }, true},
		{"a top-level item names a folder", func(w *sharedFolderWorld, top, _ *owned) (*owned, string) { return top, w.folder.id }, false},
		{"a top-level folder names another", func(w *sharedFolderWorld, _, other *owned) (*owned, string) { return w.folder, other.id }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newSharedFolderWorld(t)
			top := newArtifact(t, w.alice, "top")
			other := newItem(t, w.alice, "folder", "")
			o, folder := c.pick(w, top, other)
			b := o.next()
			b.Folder = folder
			got, msg := o.putRecord(b)
			if c.wantOK {
				if got != http.StatusOK {
					t.Fatalf("%d %q", got, msg)
				}
				return
			}
			wantPlacementRefusal(t, got, msg)
		})
	}
}

func TestACreateMustNameTheFolderItIsPlacedIn(t *testing.T) {
	w := newSharedFolderWorld(t)
	for _, c := range []struct{ name, parent, folder string }{
		{"in a folder, names none", w.folder.id, ""},
		{"in a folder, names another", w.folder.id, w.item.id},
		{"at the top level, names a folder", "", w.folder.id},
	} {
		id, req := itemRequest(t, w.alice, "", c.parent)
		first := firstRecord(t, w.alice, id)
		first.Folder = c.folder
		req["membership"] = signRecord(t, w.alice, first)
		got, msg := status(w.alice.testClient, "POST", "/api/artifacts", req)
		if got != http.StatusConflict || !strings.Contains(msg, "placement") {
			t.Errorf("%s: %d %q, want 409 placement", c.name, got, msg)
		}
	}
}

// A move leaves the item's latest record naming the old folder, so the item
// is pending even when no entry is missing, and a record naming the old
// folder is refused, until the owner writes one that names the new folder.
func TestAMovePendsTheItemUntilARecordNamesTheNewFolder(t *testing.T) {
	w := newSharedFolderWorld(t)
	other := newItem(t, w.alice, "folder", "")
	wantInherit(t, w.alice.testClient, w.item.id, "ok")

	if got, msg := move(w.alice.testClient, w.item.id, other.id); got != http.StatusOK {
		t.Fatalf("move: %d %q", got, msg)
	}
	wantInherit(t, w.alice.testClient, w.item.id, "pending")
	got, msg := w.item.putRecord(w.item.next())
	wantPlacementRefusal(t, got, msg)
	b := w.item.next()
	b.Folder = other.id
	w.item.apply(b)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")

	// Out to the top level, and back in.
	if got, msg := move(w.alice.testClient, w.item.id, nil); got != http.StatusOK {
		t.Fatalf("move out: %d %q", got, msg)
	}
	wantInherit(t, w.alice.testClient, w.item.id, "pending")
	b = w.item.next()
	b.Folder = ""
	w.item.apply(b)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")
}

// Moving is the owner's: after a move a manager cannot write a record that
// names the new folder, nor one that still names the old.
func TestAManagerCannotChangeTheFolder(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.item.share("manager", w.bob)
	// A manager's record that keeps the folder lands.
	w.item.applyByManager(w.bob, w.item.next())

	if got, msg := move(w.alice.testClient, w.item.id, nil); got != http.StatusOK {
		t.Fatalf("move: %d %q", got, msg)
	}
	got, msg := status(w.bob.testClient, "PUT", "/api/artifacts/"+w.item.id+"/membership", w.item.byManager(w.bob, w.item.next()))
	wantPlacementRefusal(t, got, msg)
	b := w.item.next()
	b.Folder = ""
	got, msg = status(w.bob.testClient, "PUT", "/api/artifacts/"+w.item.id+"/membership", w.item.byManager(w.bob, b))
	if got != http.StatusBadRequest || !strings.Contains(msg, "only the owner moves an item") {
		t.Errorf("a manager names the new folder: %d %q", got, msg)
	}
	w.item.apply(b)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")
}

// An accepting record is held to the via checks, so the new owner cannot list
// a user through a folder that does not contain the item.
func TestAnAcceptRecordWithAForgedViaIsRefused(t *testing.T) {
	w := newTransferWorld(t)
	folder := newItem(t, w.owner, "folder", "")
	folder.share("viewer", w.out)
	offer := w.offer(w.ed)

	b, req := w.acceptOwnerOffer(w.ed, offer, false)
	b.Members = append(b.Members, viaMember(w.out, "viewer", folder.id))
	sortMembers(b.Members)
	req["membership"] = signRecord(t, w.ed, b)
	req["wraps"] = append(req["wraps"].([]any), map[string]any{"user": w.out.id, "epoch": 1, "wrapped": e2e.B64(fakeWrap)})
	wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusConflict)
}

// A user disabled after the folder shared them is not required of an item,
// so the item does not stay pending.
func TestADisabledUserDoesNotLeaveItemsPending(t *testing.T) {
	w := newSharedFolderWorld(t)
	w.folder.share("viewer", w.bob)
	wantInherit(t, w.alice.testClient, w.item.id, "pending")
	w.admin.mustDo("PATCH", "/api/admin/users/"+w.bob.id, map[string]any{"disabled": true}, nil, http.StatusOK)
	wantInherit(t, w.alice.testClient, w.item.id, "ok")
	// A record that does not list them lands.
	w.item.apply(w.item.next())
	w.admin.mustDo("PATCH", "/api/admin/users/"+w.bob.id, map[string]any{"disabled": false}, nil, http.StatusOK)
	wantInherit(t, w.alice.testClient, w.item.id, "pending")
}
