package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// The folder's owner manages what is in it: an item someone else owns lists
// the owner of its folder as an inherited manager, via that folder. See
// "Placing an item in someone else's folder" in design/e2e-api.md.
//
// Expected records, written by hand as a cross-check for the other
// implementations (the browser's sharing.mjs, the Go client). A owns folder
// FA, B owns the item, C owns folder FC, and FC sits in FA. Every entry is
// listed as "user role via".
//
//	state                                   FA lists   FC record lists          the item's record lists
//	1. B's item in FA                       nobody     -                        A manager FA
//	2. B's item in FA                       D viewer   -                        A manager FA, D viewer FA
//	3. B's item in FC (C owns FC, in FA)    nobody     A manager FA (inherited) A manager FA, C manager FC
//
// The folder's owner is listed by that folder, so its via is the folder
// itself: C is via FC, not FA. A's entry in state 3 comes from FC's record,
// where it is via FA. When the folder's owner owns the item, nothing is added.

func TestTheFoldersOwnerManagesAnItemSomeoneElsePlacedInIt(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)

	// The record lists alice as a manager via the folder, so the entry
	// grants alice the role.
	var view struct {
		Access  string `json:"access"`
		Inherit string `json:"inherit"`
	}
	w.alice.mustDo("GET", "/api/artifacts/"+item.id, nil, &view, http.StatusOK)
	if view.Access != "manager" || view.Inherit != "ok" {
		t.Errorf("alice's view of bob's item: %+v, want manager and ok", view)
	}
	if got := item.latest.Members; len(got) != 1 || got[0] != viaMember(w.alice, "manager", w.folder.id) {
		t.Errorf("the record lists %+v, want alice as a manager via the folder", got)
	}
}

func TestOwnerEntryEndsWhenTheItemLeavesTheFolder(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)
	wantStatus(t, w.alice.testClient, "GET", "/api/artifacts/"+item.id, nil, http.StatusOK)

	// Bob takes his item out. Alice, who did nothing, loses it at once.
	w.bob.mustDo("PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{"parent": nil}, nil, http.StatusOK)
	wantStatus(t, w.alice.testClient, "GET", "/api/artifacts/"+item.id, nil, http.StatusNotFound)
	wantInherit(t, w.bob.testClient, item.id, "pending")

	// Bob's next epoch, at the top level, excludes alice.
	b := item.nextEpoch()
	b.Folder = ""
	b.Members = removeMember(b.Members, w.alice.id)
	b.Excluded = append(b.Excluded, e2e.ExcludedEntry{User: w.alice.id, FP: w.alice.keys.fp(), Email: w.alice.email})
	sortExcluded(b.Excluded)
	item.apply(b)
	wantInherit(t, w.bob.testClient, item.id, "ok")
	wantStatus(t, w.alice.testClient, "GET", "/api/artifacts/"+item.id, nil, http.StatusNotFound)
}

func TestARecordOmittingTheFoldersOwnerIsRefused(t *testing.T) {
	w := newOthersWorld(t)
	item := itemIn(t, w.bob, "", w.folder)

	b := item.next()
	b.Members = removeMember(b.Members, w.alice.id)
	if got, msg := item.putRecord(b); got != http.StatusConflict || !strings.Contains(msg, "inherit") && !strings.Contains(msg, w.alice.id) {
		t.Errorf("a record without the folder's owner: %d %q, want 409 naming alice", got, msg)
	}
	// Listing her as a viewer is not enough either, nor as an editor.
	b = item.next()
	b.Members[0].Role, b.Members[0].Via = "viewer", ""
	if got, msg := item.putRecord(b); got != http.StatusConflict {
		t.Errorf("a record listing the folder's owner as a viewer: %d %q, want 409", got, msg)
	}
	b = item.next()
	b.Members[0].Role = "editor"
	if got, msg := item.putRecord(b); got != http.StatusConflict || !strings.Contains(msg, "inherit") || !strings.Contains(msg, "lists them as manager") {
		t.Errorf("a record listing the folder's owner as an editor: %d %q, want 409 inherit, listing them as manager", got, msg)
	}
	// A creation that omits her is refused too.
	_, req, _ := itemRequestIn(t, w.bob, "", w.folder.id, nil)
	if got, msg := status(w.bob.testClient, "POST", "/api/artifacts", req); got != http.StatusConflict || !strings.Contains(msg, w.alice.id) {
		t.Errorf("creating without the folder's owner: %d %q, want 409 naming alice", got, msg)
	}
	// A via that claims a folder alice does not own is refused: a member
	// via a folder must be listed by it, or own it.
	b = item.next()
	b.Members = append(b.Members, viaMember(w.carol, "manager", w.folder.id))
	sortMembers(b.Members)
	if got, msg := item.putRecord(b); got != http.StatusConflict || !strings.Contains(msg, "via") {
		t.Errorf("a via naming a folder that neither lists nor is owned by them: %d %q, want 409 via", got, msg)
	}
}

func TestTheOwnerOfAFolderInsideAFolderManagesItsItems(t *testing.T) {
	w := newOthersWorld(t)
	// Carol owns a folder inside alice's, and bob an item inside carol's.
	w.folder.share("editor", w.carol)
	inner := itemIn(t, w.carol, "folder", w.folder)
	item := itemIn(t, w.bob, "", inner)

	want := []e2e.Member{viaMember(w.alice, "manager", w.folder.id), viaMember(w.carol, "manager", inner.id)}
	sortMembers(want)
	if len(item.latest.Members) != 2 || item.latest.Members[0] != want[0] || item.latest.Members[1] != want[1] {
		t.Fatalf("the record lists %+v, want %+v", item.latest.Members, want)
	}
	for _, c := range []actor{w.alice, w.carol} {
		var view struct {
			Access string `json:"access"`
		}
		c.mustDo("GET", "/api/artifacts/"+item.id, nil, &view, http.StatusOK)
		if view.Access != "manager" {
			t.Errorf("%s reads bob's item as %q, want manager", c.email, view.Access)
		}
	}
	wantInherit(t, w.bob.testClient, item.id, "ok")

	// A record that leaves out alice, whose folder holds carol's, is refused.
	b := item.next()
	b.Members = removeMember(b.Members, w.alice.id)
	if got, msg := item.putRecord(b); got != http.StatusConflict {
		t.Errorf("a record omitting the owner of a folder further up: %d %q, want 409", got, msg)
	}
}

func TestADeactivatedFolderOwnerIsNotRequired(t *testing.T) {
	s, ts := testServer(t)
	alice := seedKeyedAccount(t, s, ts.URL, "alice@example.com")
	bob := seedKeyedAccount(t, s, ts.URL, "bob@example.com")
	folder := newItem(t, alice, "folder", "")
	folder.share("editor", bob)
	item := itemIn(t, bob, "", folder)
	wantInherit(t, bob.testClient, item.id, "ok")

	if err := s.store.SetUserDisabled(alice.id, true); err != nil {
		t.Fatal(err)
	}
	// Nothing waits on a user who cannot read it.
	wantInherit(t, bob.testClient, item.id, "ok")
	// A next-epoch record without her lands, because a record may not add
	// her.
	b := item.nextEpoch()
	b.Members = removeMember(b.Members, alice.id)
	b.Excluded = append(b.Excluded, e2e.ExcludedEntry{User: alice.id, FP: alice.keys.fp(), Email: alice.email})
	sortExcluded(b.Excluded)
	if got, msg := item.putRecord(b); got != http.StatusOK {
		t.Errorf("a record without a deactivated folder owner: %d %q, want 200", got, msg)
	}
}

func TestAnItemPendingWithoutTheFoldersOwner(t *testing.T) {
	w := newOthersWorld(t)
	// A move into the folder leaves the item's record naming no folder, so
	// it is pending, and bob's record is what lists alice.
	mine := newArtifact(t, w.bob, "mine")
	w.bob.mustDo("PUT", "/api/artifacts/"+mine.id+"/parent", map[string]any{"parent": w.folder.id}, nil, http.StatusOK)
	wantInherit(t, w.bob.testClient, mine.id, "pending")
	wantStatus(t, w.alice.testClient, "GET", "/api/artifacts/"+mine.id, nil, http.StatusNotFound)

	b := mine.next()
	b.Folder = w.folder.id
	b.Members = append(b.Members, viaMember(w.alice, "manager", w.folder.id))
	sortMembers(b.Members)
	// The record adds a manager, which only the owner signs, and bob does.
	mine.apply(b)
	wantInherit(t, w.bob.testClient, mine.id, "ok")
	wantStatus(t, w.alice.testClient, "GET", "/api/artifacts/"+mine.id, nil, http.StatusOK)
}
