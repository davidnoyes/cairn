package store

import (
	"errors"
	"testing"
)

const testGroup = "6f1d2c3a-0b4e-4c5d-8e7f-0123456789ab"

func TestGroupRecordsAreStoredInOrderWithTheirMembers(t *testing.T) {
	s := testStore(t)
	a, b := testAccount(t, s, "a@x.y"), testAccount(t, s, "b@x.y")
	if _, err := s.GroupRecords(testGroup); !errors.Is(err, ErrNotFound) {
		t.Fatalf("records of a missing group: %v, want ErrNotFound", err)
	}
	first := Envelope{Body: []byte("one"), Sig: []byte("s1"), Signer: a.ID}
	if last, err := s.AddGroupRecord(testGroup, 1, first, []GroupMember{{a.ID, "manager", "fp-a"}}, t0); err != nil || last != 1 {
		t.Fatalf("first record: %d, %v", last, err)
	}
	second := Envelope{Body: []byte("two"), Sig: []byte("s2"), Signer: a.ID}
	members := []GroupMember{{a.ID, "manager", "fp-a"}, {b.ID, "member", "fp-b"}}
	if _, err := s.AddGroupRecord(testGroup, 2, second, members, t0); err != nil {
		t.Fatal(err)
	}
	recs, err := s.GroupRecords(testGroup)
	if err != nil || len(recs) != 2 || string(recs[0].Body) != "one" || string(recs[1].Body) != "two" || recs[1].Signer != a.ID || string(recs[1].Sig) != "s2" {
		t.Fatalf("records = %+v, %v", recs, err)
	}
	got, err := s.GroupMembers(testGroup)
	if err != nil || len(got) != 2 {
		t.Fatalf("members = %+v, %v", got, err)
	}
	want := map[string]GroupMember{a.ID: members[0], b.ID: members[1]}
	for _, m := range got {
		if want[m.UserID] != m {
			t.Errorf("member %+v, want %+v", m, want[m.UserID])
		}
	}
	// A later record replaces the members: b leaves.
	if _, err := s.AddGroupRecord(testGroup, 3, rec("three"), members[:1], t0); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GroupMembers(testGroup); len(got) != 1 || got[0].UserID != a.ID {
		t.Errorf("members after b left = %+v", got)
	}
}

func TestAGroupRecordMustFollowTheLast(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@x.y")
	m := []GroupMember{{a.ID, "manager", "fp-a"}}
	if last, err := s.AddGroupRecord(testGroup, 2, rec("two"), m, t0); !errors.Is(err, ErrStale) || last != 0 {
		t.Errorf("a second record with no first: %d, %v, want ErrStale at 0", last, err)
	}
	if _, err := s.AddGroupRecord(testGroup, 1, rec("one"), m, t0); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []int{1, 3} {
		if last, err := s.AddGroupRecord(testGroup, seq, rec("x"), m, t0); !errors.Is(err, ErrStale) || last != 1 {
			t.Errorf("seq %d after 1: %d, %v, want ErrStale at 1", seq, last, err)
		}
	}
	if recs, _ := s.GroupRecords(testGroup); len(recs) != 1 {
		t.Errorf("%d records after the refused ones, want 1", len(recs))
	}
}

func TestGroupsListsTheLatestRecordOfEachGroup(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@x.y")
	m := []GroupMember{{a.ID, "manager", "fp-a"}}
	other := "7f1d2c3a-0b4e-4c5d-8e7f-0123456789ab"
	for _, step := range []struct {
		id   string
		seq  int
		body string
	}{{testGroup, 1, "g1-1"}, {other, 1, "g2-1"}, {testGroup, 2, "g1-2"}} {
		if _, err := s.AddGroupRecord(step.id, step.seq, rec(step.body), m, t0); err != nil {
			t.Fatal(err)
		}
	}
	heads, err := s.Groups()
	if err != nil || len(heads) != 2 {
		t.Fatalf("Groups = %+v, %v", heads, err)
	}
	got := map[string]GroupHead{heads[0].ID: heads[0], heads[1].ID: heads[1]}
	if g := got[testGroup]; g.Seq != 2 || string(g.Record.Body) != "g1-2" {
		t.Errorf("group 1 head = %+v", g)
	}
	if g := got[other]; g.Seq != 1 || string(g.Record.Body) != "g2-1" {
		t.Errorf("group 2 head = %+v", g)
	}
}

func TestDeleteGroupRemovesRecordsAndMembers(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@x.y")
	if _, err := s.AddGroupRecord(testGroup, 1, rec("one"), []GroupMember{{a.ID, "manager", "fp-a"}}, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(testGroup); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GroupRecords(testGroup); !errors.Is(err, ErrNotFound) {
		t.Errorf("records after delete: %v, want ErrNotFound", err)
	}
	if ms, _ := s.GroupMembers(testGroup); len(ms) != 0 {
		t.Errorf("members after delete = %+v", ms)
	}
	if err := s.DeleteGroup(testGroup); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second delete: %v, want ErrNotFound", err)
	}
}

// A member whose account is gone is carried over by a later record, which
// the signed record still lists; the store keeps no row for them.
func TestAGroupRecordMayListAnAccountThatIsGone(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@x.y")
	m := []GroupMember{{a.ID, "manager", "fp-a"}, {"u-gone", "member", "fp-gone"}}
	if _, err := s.AddGroupRecord(testGroup, 1, rec("one"), m, t0); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GroupMembers(testGroup); len(got) != 1 || got[0].UserID != a.ID {
		t.Errorf("members = %+v, want only the account that exists", got)
	}
}

func TestKeyedUserByID(t *testing.T) {
	s := testStore(t)
	a := testAccount(t, s, "a@x.y")
	u, err := s.KeyedUserByID(a.ID)
	if err != nil || u.ID != a.ID || u.FP == "" || !u.Verified || u.Role != RoleMember {
		t.Errorf("KeyedUserByID = %+v, %v", u, err)
	}
	if _, err := s.KeyedUserByID("nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a missing user: %v, want ErrNotFound", err)
	}
}
