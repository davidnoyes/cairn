package store

import (
	"testing"
)

// inheritWorld is a folder with an item in it, a member of a group, and a
// stranger. Groups are listed on the folder and the item by the tests.
type inheritWorld struct {
	s                *Store
	owner, bob, carl *User
	folder, item     string
	nested           string
}

// listIn writes members and groups as the latest record's entries of id.
func (w *inheritWorld) listIn(t *testing.T, id string, members []Member, groups []ArtifactGroup) {
	t.Helper()
	err := w.s.WithArtifact(id, func(tx *ArtifactTx) error {
		if err := tx.SetMembers(members); err != nil {
			return err
		}
		return tx.SetGroups(groups)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func newInheritWorld(t *testing.T) *inheritWorld {
	t.Helper()
	s := testStore(t)
	w := &inheritWorld{s: s, owner: testAccount(t, s, "o@x.y"), bob: testAccount(t, s, "b@x.y"), carl: testAccount(t, s, "c@x.y")}
	w.folder, w.nested, w.item = folderA, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", itemC
	for _, c := range []struct{ id, kind, parent string }{
		{w.folder, KindFolder, ""}, {w.nested, KindFolder, w.folder}, {w.item, KindArtifact, w.nested},
	} {
		if _, err := s.CreateOwnedItem(c.id, w.owner.ID, c.kind, c.parent, nil); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

func TestAccessCountsAViaMemberOnlyWhileTheFolderListsThemAndContainsTheItem(t *testing.T) {
	w := newInheritWorld(t)
	viaFolder := []Member{{UserID: w.bob.ID, Role: "viewer", FP: "fb", Via: w.folder}}
	w.listIn(t, w.folder, []Member{{UserID: w.bob.ID, Role: "viewer", FP: "fb"}}, nil)
	w.listIn(t, w.item, viaFolder, nil)

	member := func() *Member {
		st, err := w.s.AccessState(w.item, w.bob.ID)
		if err != nil {
			t.Fatal(err)
		}
		return st.Member
	}
	if m := member(); m == nil || m.Via != w.folder {
		t.Fatalf("a via member two levels down: %+v", m)
	}
	// The folder stops listing bob.
	w.listIn(t, w.folder, nil, nil)
	if m := member(); m != nil {
		t.Errorf("after the folder dropped bob: %+v", m)
	}
	// Listed again, but the item moves out of the folder.
	w.listIn(t, w.folder, []Member{{UserID: w.bob.ID, Role: "viewer", FP: "fb"}}, nil)
	if m := member(); m == nil {
		t.Fatal("after the folder listed bob again")
	}
	if err := w.s.MoveItem(w.item, ""); err != nil {
		t.Fatal(err)
	}
	if m := member(); m != nil {
		t.Errorf("after the item left the folder: %+v", m)
	}
	// A direct grant counts wherever the item sits.
	w.listIn(t, w.item, []Member{{UserID: w.bob.ID, Role: "viewer", FP: "fb"}}, nil)
	if m := member(); m == nil {
		t.Error("a direct grant")
	}
}

func TestAccessCountsAViaGroupOnlyWhileTheFolderListsIt(t *testing.T) {
	w := newInheritWorld(t)
	members := []GroupMember{{w.owner.ID, "manager", "fo"}, {w.bob.ID, "member", "fb"}}
	if _, err := w.s.AddGroupRecord(testGroup, 1, rec("one"), members, t0); err != nil {
		t.Fatal(err)
	}
	w.listIn(t, w.folder, nil, []ArtifactGroup{{GroupID: testGroup, Role: "viewer"}})
	w.listIn(t, w.item, nil, []ArtifactGroup{{GroupID: testGroup, Role: "viewer", Via: w.folder}})
	state := func() *AccessState {
		st, err := w.s.AccessState(w.item, w.bob.ID)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := state(); !st.InGroup || !st.HasGroups {
		t.Fatalf("a group via the folder: %+v", st)
	}
	w.listIn(t, w.folder, nil, nil)
	if st := state(); st.InGroup || st.HasGroups {
		t.Errorf("after the folder dropped the group: %+v", st)
	}
	users, groups, err := lapsedOf(w, w.item)
	if err != nil || len(users) != 0 || !groups[testGroup] {
		t.Errorf("lapsed groups: %v %v %v", users, groups, err)
	}
}

// inheritPending is InheritPending for the artifact id.
func inheritPending(w *inheritWorld, id string) (bool, error) {
	a, err := w.s.ArtifactByID(id)
	if err != nil {
		return false, err
	}
	return w.s.InheritPending(a)
}

// lapsedOf reads LapsedVia for id.
func lapsedOf(w *inheritWorld, id string) (users, groups map[string]bool, err error) {
	err = w.s.WithArtifact(id, func(tx *ArtifactTx) (err error) { users, groups, err = tx.LapsedVia(); return })
	return
}

func TestInheritPending(t *testing.T) {
	w := newInheritWorld(t)
	if _, err := w.s.AddGroupRecord(testGroup, 1, rec("one"), []GroupMember{{w.owner.ID, "manager", "fo"}}, t0); err != nil {
		t.Fatal(err)
	}
	pending := func(id string, want bool, why string) {
		t.Helper()
		p, err := inheritPending(w, id)
		if err != nil {
			t.Fatal(err)
		}
		if p != want {
			t.Errorf("%s: pending of %s = %v, want %v", why, id, p, want)
		}
	}
	bob := func(role, via string) []Member {
		return []Member{{UserID: w.bob.ID, Role: role, FP: "fb", Via: via}}
	}
	group := func(role, via string) []ArtifactGroup {
		return []ArtifactGroup{{GroupID: testGroup, Role: role, Via: via}}
	}
	pending(w.item, false, "nothing shared")
	pending(w.folder, false, "nothing shared")

	// The folder lists the item's owner, whom the item's own record never lists.
	w.listIn(t, w.folder, []Member{{UserID: w.owner.ID, Role: "viewer", FP: "fo"}}, nil)
	pending(w.nested, false, "the folder lists the owner")
	w.listIn(t, w.folder, nil, nil)

	// The folder lists bob and the group, and the nested folder under it
	// lists neither.
	w.listIn(t, w.folder, bob("editor", ""), group("editor", ""))
	pending(w.nested, true, "the folder lists bob and the group")
	pending(w.item, false, "the item's own folder lists nobody")
	pending(w.folder, false, "a top-level folder")

	// Bob below the folder's role, then at it; then the group the same way.
	w.listIn(t, w.nested, bob("viewer", w.folder), nil)
	pending(w.nested, true, "bob a viewer where the folder lists an editor")
	w.listIn(t, w.nested, bob("editor", w.folder), nil)
	pending(w.nested, true, "the group is missing")
	w.listIn(t, w.nested, bob("editor", w.folder), group("viewer", w.folder))
	pending(w.nested, true, "the group is a viewer where the folder lists an editor")
	w.listIn(t, w.nested, bob("manager", w.folder), group("editor", w.folder))
	pending(w.nested, true, "bob a manager where the folder lists an editor: the mark is no longer true")
	w.listIn(t, w.nested, bob("editor", w.folder), group("editor", w.folder))
	pending(w.nested, false, "every entry at the folder's role")

	// The item must hold what the nested folder lists.
	pending(w.item, true, "the nested folder now lists bob and the group")
	w.listIn(t, w.item, bob("editor", w.folder), group("editor", w.folder))
	pending(w.item, false, "the item holds them via the folder")
	// A direct grant above the folder's role is the higher-role rule.
	w.listIn(t, w.item, bob("manager", ""), group("editor", w.folder))
	pending(w.item, false, "a direct manager")
	w.listIn(t, w.item, bob("editor", w.folder), group("editor", w.folder))

	// The folder stops listing bob: the item's entry no longer holds, and so
	// does the nested folder's.
	w.listIn(t, w.folder, nil, group("editor", ""))
	pending(w.item, true, "bob's via no longer holds")
	pending(w.nested, true, "bob's via no longer holds")
	w.listIn(t, w.nested, nil, group("editor", w.folder))
	pending(w.nested, false, "the nested folder dropped bob")
	w.listIn(t, w.item, nil, group("editor", w.folder))
	pending(w.item, false, "the item dropped bob")

	// A group that was deleted is not required.
	w.listIn(t, w.nested, nil, nil)
	pending(w.nested, true, "the folder lists the group")
	if err := w.s.DeleteGroup(testGroup); err != nil {
		t.Fatal(err)
	}
	pending(w.nested, false, "the group was deleted")
}

func TestAccessCapsAViaMemberAtTheFoldersRole(t *testing.T) {
	w := newInheritWorld(t)
	role := func() string {
		st, err := w.s.AccessState(w.item, w.bob.ID)
		if err != nil || st.Member == nil {
			t.Fatalf("AccessState: %+v, %v", st, err)
		}
		return st.Member.Role
	}
	w.listIn(t, w.folder, []Member{{UserID: w.bob.ID, Role: "editor", FP: "fb"}}, nil)
	w.listIn(t, w.item, []Member{{UserID: w.bob.ID, Role: "editor", FP: "fb", Via: w.folder}}, nil)
	if got := role(); got != "editor" {
		t.Errorf("an entry at the folder's role: %s", got)
	}
	pending, err := inheritPending(w, w.item)
	if err != nil || pending {
		t.Errorf("pending at the folder's role: %v, %v", pending, err)
	}
	// The folder lowers bob to a viewer: the entry grants no more at once, and
	// the item is pending until a record lowers it.
	w.listIn(t, w.folder, []Member{{UserID: w.bob.ID, Role: "viewer", FP: "fb"}}, nil)
	if got := role(); got != "viewer" {
		t.Errorf("after the folder lowered bob: %s", got)
	}
	if pending, err := inheritPending(w, w.item); err != nil || !pending {
		t.Errorf("pending after the folder lowered bob: %v, %v", pending, err)
	}
	// A direct grant is not capped.
	w.listIn(t, w.item, []Member{{UserID: w.bob.ID, Role: "editor", FP: "fb"}}, nil)
	if got := role(); got != "editor" {
		t.Errorf("a direct editor: %s", got)
	}
}

// A move leaves the item's latest record naming the old folder, so the item is
// pending until a record names the new one.
func TestInheritPendingWhenTheRecordNamesAnotherFolder(t *testing.T) {
	w := newInheritWorld(t)
	appendRecord := func(seq int, prev, body string) string {
		t.Helper()
		r := record(seq, prev, 1, body)
		if err := w.s.WithArtifact(w.item, func(tx *ArtifactTx) error { return tx.AppendRecord(r) }); err != nil {
			t.Fatal(err)
		}
		return r.BodyHash
	}
	pending := func(want bool, why string) {
		t.Helper()
		if p, err := inheritPending(w, w.item); err != nil || p != want {
			t.Errorf("%s: pending = %v, %v; want %v", why, p, err, want)
		}
	}
	pending(false, "no record yet")
	h := appendRecord(1, "", `{"folder":"`+w.nested+`"}`)
	pending(false, "the record names the folder the item sits in")
	if err := w.s.MoveItem(w.item, w.folder); err != nil {
		t.Fatal(err)
	}
	pending(true, "moved to another folder")
	h = appendRecord(2, h, `{"folder":"`+w.folder+`"}`)
	pending(false, "a record names the new folder")
	if err := w.s.MoveItem(w.item, ""); err != nil {
		t.Fatal(err)
	}
	pending(true, "moved to the top level")
	appendRecord(3, h, `{}`)
	pending(false, "a record names no folder")
}

// A deactivated or unverified account is not required of an item, because a
// record may not add one; one the item already lists is not affected.
func TestInheritPendingDoesNotRequireAnInactiveAccount(t *testing.T) {
	w := newInheritWorld(t)
	w.listIn(t, w.folder, []Member{{UserID: w.bob.ID, Role: "viewer", FP: "fb"}, {UserID: w.carl.ID, Role: "viewer", FP: "fc"}}, nil)
	pending := func(want bool, why string) {
		t.Helper()
		if p, err := inheritPending(w, w.item); err != nil || p != want {
			t.Errorf("%s: pending = %v, %v; want %v", why, p, err, want)
		}
	}
	// The nested folder lists both users, and the item neither.
	w.listIn(t, w.nested, []Member{{UserID: w.bob.ID, Role: "viewer", FP: "fb", Via: w.folder}, {UserID: w.carl.ID, Role: "viewer", FP: "fc", Via: w.folder}}, nil)
	pending(true, "the nested folder lists two active users")
	if err := w.s.SetUserDisabled(w.bob.ID, true); err != nil {
		t.Fatal(err)
	}
	pending(true, "carl is still required")
	if _, err := w.s.db.Exec(`UPDATE users SET verified_at = NULL WHERE id = ?`, w.carl.ID); err != nil {
		t.Fatal(err)
	}
	pending(false, "bob is deactivated and carl is not verified")
	if err := w.s.SetUserDisabled(w.bob.ID, false); err != nil {
		t.Fatal(err)
	}
	pending(true, "bob is active again")
}
