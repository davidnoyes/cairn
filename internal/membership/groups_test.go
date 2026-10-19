package membership

import (
	"fmt"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

const (
	groupA = "11111111-1111-4111-8111-111111111111"
	groupB = "22222222-2222-4222-8222-222222222222"
	groupX = "99999999-9999-4999-8999-999999999999" // never created
)

// groupDir is a Directory that has groups: each key is a group that exists,
// and its value is the users its latest record lists.
type groupDir struct {
	fakeDir
	groups map[string]map[string]bool
}

func (d groupDir) GroupExists(id string) (bool, error) {
	_, ok := d.groups[id]
	return ok, nil
}

func (d groupDir) GroupMember(group, user string) (bool, error) { return d.groups[group][user], nil }

// groupsOf makes a groupDir for f whose groups A and B list the given users.
func (f *fixture) groupsOf(a, b []*tUser) groupDir {
	set := func(us []*tUser) map[string]bool {
		out := map[string]bool{}
		for _, u := range us {
			out[u.ID] = true
		}
		return out
	}
	return groupDir{f.dir, map[string]map[string]bool{groupA: set(a), groupB: set(b)}}
}

// latestWith makes the latest record list team and groups, as one a same-epoch
// change follows.
func (f *fixture) latestWith(team string, groups ...e2e.GroupShare) {
	l := *f.cur.Latest
	l.Team, l.Groups = team, groups
	f.setLatest(&l)
}

func share(group, role string) e2e.GroupShare { return e2e.GroupShare{Group: group, Role: role} }

func TestCheckAcceptsGroups(t *testing.T) {
	f := newFixture(t)
	dir := f.groupsOf(nil, nil)
	b := f.next()
	b.Groups = []e2e.GroupShare{share(groupA, "viewer"), share(groupB, "editor")}
	res, err := Check(f.cur, dir, f.change(t, b, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := []store.ArtifactGroup{{GroupID: groupA, Role: "viewer"}, {GroupID: groupB, Role: "editor"}}
	if fmt.Sprint(res.Groups) != fmt.Sprint(want) {
		t.Errorf("groups to store = %v, want %v", res.Groups, want)
	}
}

func TestCheckRefusesBadGroups(t *testing.T) {
	many := make([]e2e.GroupShare, 101)
	for i := range many {
		many[i] = share(fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1), "viewer")
	}
	for name, groups := range map[string][]e2e.GroupShare{
		"unsorted":   {share(groupB, "viewer"), share(groupA, "viewer")},
		"duplicate":  {share(groupA, "viewer"), share(groupA, "editor")},
		"a manager":  {share(groupA, "manager")},
		"no role":    {share(groupA, "")},
		"not a UUID": {share("ABCDEF", "viewer")},
		"uppercase":  {share("11111111-1111-4111-8111-11111111111A", "viewer")},
		"101":        many,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			b := f.next()
			b.Groups = groups
			_, err := Check(f.cur, f.groupsOf(nil, nil), f.change(t, b, nil, nil))
			refused(t, err, 400, RuleGroups, "")
		})
	}
}

func TestCheckRefusesAGroupThatDoesNotExist(t *testing.T) {
	f := newFixture(t)
	b := f.next()
	b.Groups = []e2e.GroupShare{share(groupA, "viewer"), share(groupX, "viewer")}
	_, err := Check(f.cur, f.groupsOf(nil, nil), f.change(t, b, nil, nil))
	refused(t, err, 400, RuleNewGroup, groupX)
}

// A record may keep listing a group that was deleted since, and change what it
// lists for it, but not add one.
func TestCheckKeepsAGroupThatWasDeleted(t *testing.T) {
	f := newFixture(t)
	f.latestWith("viewer", share(groupX, "viewer"))
	b := f.next()
	b.Groups[0].Role = "editor"
	b.Public = false
	if _, err := Check(f.cur, f.groupsOf(nil, nil), f.change(t, b, nil, nil)); err != nil {
		t.Errorf("keeping a deleted group: %v", err)
	}
	// Dropping it needs nothing: it holds nobody.
	b = f.next()
	b.Groups = nil
	if _, err := Check(f.cur, f.groupsOf(nil, nil), f.change(t, b, nil, nil)); err != nil {
		t.Errorf("dropping a deleted group: %v", err)
	}
}

func TestCheckGroupsAreNotForAFolder(t *testing.T) {
	f := newFixture(t)
	f.creation()
	f.cur.Kind = store.KindFolder
	b, _, _ := f.first()
	b.Members = []e2e.Member{}
	b.Groups = []e2e.GroupShare{share(groupA, "viewer")}
	_, err := Check(f.cur, f.groupsOf(nil, nil), f.change(t, b, nil, nil))
	refused(t, err, 409, RuleFolder, "")
}

// tm holds wraps and is unlisted. A same-epoch record may not leave tm with no
// reason to read when they had one before it.
func TestCheckSameEpochCannotLeaveAHolderUncovered(t *testing.T) {
	cases := []struct {
		name      string
		team      string
		before    []e2e.GroupShare
		after     []e2e.GroupShare
		afterTeam string
		inA, inB  bool
		list      bool // the record lists tm
		refused   bool
	}{
		{"drops the only group holding them", "none", []e2e.GroupShare{share(groupA, "viewer")}, nil, "none", true, false, false, true},
		{"drops a group they already left", "none", []e2e.GroupShare{share(groupA, "viewer")}, nil, "none", false, false, false, false},
		{"drops one group while another holds them", "none", []e2e.GroupShare{share(groupA, "viewer"), share(groupB, "viewer")},
			[]e2e.GroupShare{share(groupB, "viewer")}, "none", true, true, false, false},
		{"drops the group that holds them, and the other does not", "none", []e2e.GroupShare{share(groupA, "viewer"), share(groupB, "viewer")},
			[]e2e.GroupShare{share(groupB, "viewer")}, "none", true, false, false, true},
		{"drops the group but lists them", "none", []e2e.GroupShare{share(groupA, "viewer")}, nil, "none", true, false, true, false},
		{"lowers the team to none while a group holds them", "viewer", nil, []e2e.GroupShare{share(groupA, "viewer")}, "none", true, false, false, false},
		{"lowers the team to none and no group holds them", "viewer", nil, []e2e.GroupShare{share(groupA, "viewer")}, "none", false, false, false, true},
		{"keeps the team on while dropping the group", "viewer", []e2e.GroupShare{share(groupA, "viewer")}, nil, "viewer", true, false, false, false},
		{"drops the group of a holder the team never covered", "none", []e2e.GroupShare{share(groupA, "viewer")}, nil, "none", false, true, false, false},
		{"changes a group's role", "none", []e2e.GroupShare{share(groupA, "viewer")}, []e2e.GroupShare{share(groupA, "editor")}, "none", true, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.latestWith(tc.team, tc.before...)
			var a, b []*tUser
			if tc.inA {
				a = append(a, f.tm)
			}
			if tc.inB {
				b = append(b, f.tm)
			}
			rec := f.next()
			rec.Team, rec.Groups = tc.afterTeam, tc.after
			if tc.list {
				rec.Members = append(rec.Members, member(f.tm, "viewer"))
			}
			_, err := Check(f.cur, f.groupsOf(a, b), f.change(t, rec, nil, nil))
			if tc.refused {
				refused(t, err, 400, RuleSameEpoch, "u-t")
			} else if err != nil {
				t.Errorf("Check: %v", err)
			}
		})
	}
}

// A next-epoch record lists or excludes every unlisted holder, a group or not.
func TestCheckNextEpochCoversAHolderWhoLeftAGroup(t *testing.T) {
	f := newFixture(t)
	f.latestWith("none", share(groupA, "viewer"))
	rec, w, e := f.nextEpoch()
	rec.Excluded = rec.Excluded[1:] // tm is neither listed nor excluded
	_, err := Check(f.cur, f.groupsOf(nil, nil), f.change(t, rec, w, e))
	refused(t, err, 400, RuleNextEpoch, "u-t")

	rec, w, e = f.nextEpoch()
	if _, err := Check(f.cur, f.groupsOf(nil, nil), f.change(t, rec, w, e)); err != nil {
		t.Errorf("excluding the user who left: %v", err)
	}
}

func TestCheckApprovalIntoAGroup(t *testing.T) {
	f := newFixture(t)
	f.latestWith("none", share(groupA, "viewer"))
	dir := f.groupsOf([]*tUser{f.c}, nil)

	// c is in the listed group: the owner's approval lands.
	if _, err := CheckApproval(f.cur, dir, f.approval(t, f.o, f.c)); err != nil {
		t.Errorf("approving a member of a listed group: %v", err)
	}
	// c is in a group the record does not list.
	other := f.groupsOf(nil, []*tUser{f.c})
	_, err := CheckApproval(f.cur, other, f.approval(t, f.o, f.c))
	refused(t, err, 409, RuleTeamNone, "none of its groups")
	// c is in no group at all.
	_, err = CheckApproval(f.cur, f.groupsOf(nil, nil), f.approval(t, f.o, f.c))
	refused(t, err, 409, RuleTeamNone, "none of its groups")

	// A record with no team and no group has no one to approve into.
	f.latestWith("none")
	_, err = CheckApproval(f.cur, dir, f.approval(t, f.o, f.c))
	refused(t, err, 409, RuleTeamNone, "no group")

	// The team share covers anyone, with or without a group.
	f.latestWith("viewer")
	if _, err := CheckApproval(f.cur, f.groupsOf(nil, nil), f.approval(t, f.o, f.c)); err != nil {
		t.Errorf("approving into the team: %v", err)
	}
}
