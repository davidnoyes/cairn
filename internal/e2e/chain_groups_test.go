package e2e

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Group IDs the group cases list, in sorted order.
const (
	chainGroupA = "11111111-1111-4111-8111-111111111111"
	chainGroupB = "22222222-2222-4222-8222-222222222222"
)

// groupIDs returns n distinct lowercase UUIDs in sorted order.
func groupIDs(n int) []GroupShare {
	out := make([]GroupShare, n)
	for i := range out {
		out[i] = GroupShare{Group: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1), Role: "viewer"}
	}
	return out
}

// groupChainCases are the chain section's groups cases: records that list
// groups, and each rule that refuses a list. Each refusal breaks exactly one
// rule.
func groupChainCases() []chainCase {
	base := func(t testing.TB, u chainUsers) *chainFixture {
		return newChain(t, u.alice, []Member{manager(u.bob), viewer(u.carol)}, nil)
	}
	listed := func(edit func(b *MembershipBody)) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			return base(t, u).add(u.alice, edit).input()
		}
	}
	groups := func(gs ...GroupShare) func(b *MembershipBody) {
		return func(b *MembershipBody) { b.Groups = gs }
	}
	// rawGroups is alice's second record with "groups": value spelled out.
	rawGroups := func(value string) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			f := base(t, u)
			b := f.last()
			b.Seq++
			b.Prev = f.head(1)
			body, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			return f.addRaw(u.alice, append(body[:len(body)-1], []byte(`,"groups":`+value+`}`)...)).input()
		}
	}
	return []chainCase{
		{name: "groups-listed", why: "alice lists two groups, sorted by group ID, in her second record", seq: 2, epoch: 1,
			build: listed(groups(GroupShare{chainGroupA, "viewer"}, GroupShare{chainGroupB, "editor"}))},
		{name: "groups-first-record", why: "alice's first record lists a group", seq: 1, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return newChain(t, u.alice, []Member{}, groups(GroupShare{chainGroupA, "editor"})).input()
			}},
		{name: "groups-limit", why: "a record that lists 100 groups, the most it may", seq: 2, epoch: 1,
			build: listed(func(b *MembershipBody) { b.Groups = groupIDs(100) })},
		{name: "groups-manager-changes", why: "bob, a manager, lists a group, then changes its role in a second version 2 record", seq: 3, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).
					addByManager(u.bob, groups(GroupShare{chainGroupA, "viewer"})).
					addByManager(u.bob, groups(GroupShare{chainGroupA, "editor"})).input()
			}},
		{name: "groups-unsorted", why: "groups out of group ID order", err: ErrChain,
			build: listed(groups(GroupShare{chainGroupB, "viewer"}, GroupShare{chainGroupA, "viewer"}))},
		{name: "groups-duplicate", why: "the same group listed twice", err: ErrChain,
			build: listed(groups(GroupShare{chainGroupA, "viewer"}, GroupShare{chainGroupA, "viewer"}))},
		{name: "groups-empty-explicit", why: "a record with an explicit empty groups list, which the format leaves out", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := base(t, u)
				b := f.last()
				b.Seq++
				b.Prev = f.head(1)
				body, err := json.Marshal(b)
				if err != nil {
					t.Fatal(err)
				}
				return f.addRaw(u.alice, append(body[:len(body)-1], []byte(`,"groups":[]}`)...)).input()
			}},
		{name: "groups-null", why: "a record whose groups is null, which the format leaves out", err: ErrFormat,
			build: rawGroups(`null`)},
		{name: "groups-not-array", why: "a record whose groups is an object, not an array", err: ErrFormat,
			build: rawGroups(`{}`)},
		{name: "groups-role-manager", why: "a group listed with role manager", err: ErrChain,
			build: listed(groups(GroupShare{chainGroupA, "manager"}))},
		{name: "groups-id-not-uuid", why: "a group ID in uppercase, which is not a lowercase UUID", err: ErrChain,
			build: listed(groups(GroupShare{"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "viewer"}))},
		{name: "groups-too-many", why: "a record that lists 101 groups", err: ErrChain,
			build: listed(func(b *MembershipBody) { b.Groups = groupIDs(101) })},
	}
}
