package store

import "testing"

// shareWith lists the groups on artifact id.
func shareWith(t *testing.T, s *Store, id string, groups ...ArtifactGroup) {
	t.Helper()
	if err := s.WithArtifact(id, func(tx *ArtifactTx) error { return tx.SetGroups(groups) }); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactGroupsAreReplacedWholesale(t *testing.T) {
	s := testStore(t)
	o := testAccount(t, s, "o@x.y")
	a := ownedArtifact(t, s, o)
	other := "7f1d2c3a-0b4e-4c5d-8e7f-0123456789ab"
	shareWith(t, s, a.ID, ArtifactGroup{GroupID: testGroup, Role: "viewer"}, ArtifactGroup{GroupID: other, Role: "editor"})
	list := func() []ArtifactGroup {
		var got []ArtifactGroup
		if err := s.WithArtifact(a.ID, func(tx *ArtifactTx) (err error) { got, err = tx.Groups(); return }); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := list(); len(got) != 2 || got[0].GroupID != testGroup || got[0].Role != "viewer" || got[1].GroupID != other || got[1].Role != "editor" {
		t.Fatalf("groups = %+v", got)
	}
	shareWith(t, s, a.ID, ArtifactGroup{GroupID: other, Role: "viewer"})
	if got := list(); len(got) != 1 || got[0].GroupID != other || got[0].Role != "viewer" {
		t.Errorf("groups after the replacement = %+v", got)
	}
	shareWith(t, s, a.ID)
	if got := list(); len(got) != 0 {
		t.Errorf("groups after clearing = %+v", got)
	}
}

func TestAccessStateSaysWhetherTheCallerIsInAListedGroup(t *testing.T) {
	s := testStore(t)
	o, m, x := testAccount(t, s, "o@x.y"), testAccount(t, s, "m@x.y"), testAccount(t, s, "x@x.y")
	a := ownedArtifact(t, s, o)
	members := []GroupMember{{o.ID, "manager", "fo"}, {m.ID, "member", "fm"}}
	if _, err := s.AddGroupRecord(testGroup, 1, rec("one"), members, t0); err != nil {
		t.Fatal(err)
	}
	// x belongs to a group the artifact never lists.
	if _, err := s.AddGroupRecord("7f1d2c3a-0b4e-4c5d-8e7f-0123456789ab", 1, rec("one"), []GroupMember{{x.ID, "manager", "fx"}}, t0); err != nil {
		t.Fatal(err)
	}
	state := func(user string) *AccessState {
		st, err := s.AccessState(a.ID, user)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	// The group is not listed yet.
	if st := state(m.ID); st.InGroup || st.HasGroups {
		t.Errorf("before listing: %+v", st)
	}
	shareWith(t, s, a.ID, ArtifactGroup{GroupID: testGroup, Role: "viewer"})
	if st := state(m.ID); !st.InGroup || !st.HasGroups {
		t.Errorf("a member: %+v", st)
	}
	if st := state(x.ID); st.InGroup || !st.HasGroups {
		t.Errorf("a stranger: %+v", st)
	}
	if st := state(""); st.InGroup || !st.HasGroups {
		t.Errorf("anonymous: %+v", st)
	}
	// Leaving the group takes effect at once, and a deleted group has no
	// members, though the record keeps listing it.
	if _, err := s.AddGroupRecord(testGroup, 2, rec("two"), members[:1], t0); err != nil {
		t.Fatal(err)
	}
	if st := state(m.ID); st.InGroup {
		t.Errorf("after leaving: %+v", st)
	}
	if st := state(o.ID); !st.InGroup {
		t.Errorf("the remaining member: %+v", st)
	}
	if err := s.DeleteGroup(testGroup); err != nil {
		t.Fatal(err)
	}
	if st := state(o.ID); st.InGroup || !st.HasGroups {
		t.Errorf("after the group was deleted: %+v", st)
	}
}

func TestTheTransactionKnowsWhichGroupsExistAndWhoIsInThem(t *testing.T) {
	s := testStore(t)
	o, m := testAccount(t, s, "o@x.y"), testAccount(t, s, "m@x.y")
	a := ownedArtifact(t, s, o)
	if _, err := s.AddGroupRecord(testGroup, 1, rec("one"), []GroupMember{{o.ID, "manager", "fo"}}, t0); err != nil {
		t.Fatal(err)
	}
	err := s.WithArtifact(a.ID, func(tx *ArtifactTx) error {
		for _, tc := range []struct {
			group, user string
			exists, in  bool
		}{
			{testGroup, o.ID, true, true},
			{testGroup, m.ID, true, false},
			{"no-such-group", o.ID, false, false},
		} {
			if ok, err := tx.GroupExists(tc.group); err != nil || ok != tc.exists {
				t.Errorf("GroupExists(%s) = %v, %v", tc.group, ok, err)
			}
			if ok, err := tx.IsGroupMember(tc.group, tc.user); err != nil || ok != tc.in {
				t.Errorf("IsGroupMember(%s, %s) = %v, %v", tc.group, tc.user, ok, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
