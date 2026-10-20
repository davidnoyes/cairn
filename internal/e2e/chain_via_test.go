package e2e

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The folder IDs the via cases name.
const (
	chainFolder    = "33333333-3333-4333-8333-333333333333"
	chainFolderBad = "33333333-3333-4333-8333-33333333333G"
)

// viaChainCases are the chain section's via cases: records whose member and
// groups entries come from a folder, and each rule that refuses a via. Each
// refusal breaks exactly one rule.
func viaChainCases() []chainCase {
	base := func(t testing.TB, u chainUsers) *chainFixture {
		return newChain(t, u.alice, []Member{manager(u.bob)}, nil)
	}
	// viaMember lists carol as a viewer with the given via.
	viaMember := func(via string) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			return base(t, u).add(u.alice, func(b *MembershipBody) {
				c := viewer(u.carol)
				c.Via = via
				b.Members = append(b.Members, c)
			}).input()
		}
	}
	viaGroup := func(via string) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			return base(t, u).add(u.alice, func(b *MembershipBody) {
				b.Groups = []GroupShare{{Group: chainGroupA, Role: "viewer", Via: via}}
			}).input()
		}
	}
	return []chainCase{
		{name: "via-member", why: "alice lists carol as a viewer through a folder", seq: 2, epoch: 1,
			build: viaMember(chainFolder)},
		{name: "via-group", why: "alice lists a group as a viewer through a folder", seq: 2, epoch: 1,
			build: viaGroup(chainFolder)},
		{name: "via-by-manager", why: "bob, a manager, lists carol and a group through a folder in a version 2 record", seq: 2, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).addByManager(u.bob, func(b *MembershipBody) {
					c := viewer(u.carol)
					c.Via = chainFolder
					b.Members = append(b.Members, c)
					b.Groups = []GroupShare{{Group: chainGroupA, Role: "editor", Via: chainFolder}}
				}).input()
			}},
		{name: "via-manager-entry-changed", why: "bob, a manager, drops the via of carol's manager entry, which only the owner changes", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				carol := manager(u.carol)
				carol.Via = chainFolder
				return newChain(t, u.alice, []Member{manager(u.bob), carol}, nil).
					addByManager(u.bob, func(b *MembershipBody) {
						for i := range b.Members {
							if b.Members[i].User == u.carol.id {
								b.Members[i].Via = ""
							}
						}
					}).input()
			}},
		{name: "via-member-uppercase", why: "a member's via in uppercase, which is not a lowercase UUID", err: ErrChain,
			build: viaMember("33333333-3333-4333-8333-AAAAAAAAAAAA")},
		{name: "via-member-not-uuid", why: "a member's via that is not a UUID", err: ErrChain,
			build: viaMember(chainFolderBad)},
		{name: "via-group-uppercase", why: "a group's via in uppercase, which is not a lowercase UUID", err: ErrChain,
			build: viaGroup("33333333-3333-4333-8333-AAAAAAAAAAAA")},
		{name: "via-group-not-uuid", why: "a group's via that is not a UUID", err: ErrChain,
			build: viaGroup("folder")},
		{name: "via-member-empty", why: "a member with an explicit empty via, which the format leaves out", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := base(t, u)
				b := f.last()
				b.Seq++
				b.Prev = f.head(1)
				b.Members = append(b.Members[:len(b.Members):len(b.Members)], viewer(u.carol))
				body, err := json.Marshal(b)
				if err != nil {
					t.Fatal(err)
				}
				from := []byte(`"fp":"` + u.carol.fp + `"}`)
				to := []byte(`"fp":"` + u.carol.fp + `","via":""}`)
				return f.addRaw(u.alice, bytes.Replace(body, from, to, 1)).input()
			}},
	}
}
