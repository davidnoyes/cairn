package membership

import (
	"slices"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

const (
	folderF = "f0f0f0f0-f0f0-40f0-80f0-f0f0f0f0f0f0"
	folderG = "a1a1a1a1-a1a1-41a1-81a1-a1a1a1a1a1a1"
)

// folderRecord is a folder's latest record: it lists members and groups.
func folderRecord(id string, members []e2e.Member, groups []e2e.GroupShare) *e2e.MembershipBody {
	if members == nil {
		members = []e2e.Member{}
	}
	return &e2e.MembershipBody{V: 1, Artifact: id, Epoch: 1, Seq: 1, Members: members, Excluded: []e2e.ExcludedEntry{}, Team: "none", Groups: groups}
}

// inFolder puts f's artifact in folder F, whose latest record lists members
// and groups, and whose item's latest record names it.
func (f *fixture) inFolder(members []e2e.Member, groups ...e2e.GroupShare) {
	f.cur.Parent = folderF
	named := *f.cur.Latest
	named.Folder = folderF
	f.setLatest(&named)
	f.cur.Folders = map[string]*e2e.MembershipBody{folderF: folderRecord(folderF, members, groups)}
}

// withVia returns g marked as coming from folder.
func withVia(g e2e.GroupShare, folder string) e2e.GroupShare {
	g.Via = folder
	return g
}

// The item in the fixture lists a as an editor and b as a viewer. These
// cases change its record while it sits in folder F.
func TestCheckInheritedEntries(t *testing.T) {
	cases := []struct {
		name   string
		folder []e2e.Member
		groups []e2e.GroupShare
		edit   func(f *fixture, b *e2e.MembershipBody)
		status int // 0 for accepted
		rule   Rule
		msg    string
	}{
		{name: "the folder's entries are all there", folder: []e2e.Member{{User: "u-a", Role: "viewer"}}},
		{name: "a higher role than the folder's", folder: []e2e.Member{{User: "u-b", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) { b.Members[1].Role = "editor" }},
		{name: "an entry marked as from the folder", folder: []e2e.Member{{User: "u-a", Role: "editor"}, {User: "u-b", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Members[0].Via, b.Members[1].Via = folderF, folderF
			}},
		{name: "the folder lists a user the record lacks", folder: []e2e.Member{{User: "u-c", Role: "viewer"}},
			status: 409, rule: RuleInherit, msg: "member u-c is missing"},
		{name: "the folder lists a user at a higher role", folder: []e2e.Member{{User: "u-b", Role: "editor"}},
			status: 409, rule: RuleInherit, msg: "member u-b is viewer"},
		{name: "the folder lists a manager the record lists as an editor", folder: []e2e.Member{{User: "u-a", Role: "manager"}},
			status: 409, rule: RuleInherit, msg: "member u-a is editor"},
		{name: "the record drops an inherited entry", folder: []e2e.Member{{User: "u-b", Role: "viewer"}},
			edit:   func(f *fixture, b *e2e.MembershipBody) { b.Members = b.Members[:1] },
			status: 409, rule: RuleInherit, msg: "member u-b is missing"},
		{name: "the folder lists the owner", folder: []e2e.Member{{User: "u-o", Role: "manager"}}},
		{name: "the folder lists a deactivated user", folder: []e2e.Member{{User: "u-c", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) { f.dir["u-c"].Active = false }},
		{name: "the folder lists a user who is not verified", folder: []e2e.Member{{User: "u-c", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) { f.dir["u-c"].Verified = false }},
		{name: "the folder lists a user whose account is gone", folder: []e2e.Member{{User: "u-c", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) { delete(f.dir, "u-c") }},
		{name: "the folder lists a group the record lacks", groups: []e2e.GroupShare{share(groupA, "viewer")},
			status: 409, rule: RuleInherit, msg: "group " + groupA + " is missing"},
		{name: "the folder lists a group at a higher role", groups: []e2e.GroupShare{share(groupA, "editor")},
			edit:   func(f *fixture, b *e2e.MembershipBody) { b.Groups = []e2e.GroupShare{share(groupA, "viewer")} },
			status: 409, rule: RuleInherit, msg: "group " + groupA + " is viewer"},
		{name: "the record lists the folder's group at its role", groups: []e2e.GroupShare{share(groupA, "viewer")},
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Groups = []e2e.GroupShare{withVia(share(groupA, "editor"), folderF)}
			}},
		{name: "the folder lists a group that was deleted", groups: []e2e.GroupShare{share(groupX, "viewer")}},
		{name: "a member via a folder that does not list them", folder: []e2e.Member{{User: "u-a", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Members[1].Via = folderF
			}, status: 409, rule: RuleVia, msg: "member u-b via " + folderF},
		{name: "a member via a folder that does not contain the item", folder: []e2e.Member{{User: "u-a", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Members[1].Via = folderG
			}, status: 409, rule: RuleVia, msg: "member u-b via " + folderG},
		{name: "a member via a folder further up that lists them", folder: []e2e.Member{{User: "u-a", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) {
				f.cur.Folders[folderG] = folderRecord(folderG, []e2e.Member{{User: "u-b", Role: "viewer"}}, nil)
				b.Members[1].Via = folderG
			}},
		{name: "a group via a folder that does not contain the item", folder: []e2e.Member{{User: "u-a", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Groups = []e2e.GroupShare{withVia(share(groupA, "viewer"), folderG)}
			}, status: 409, rule: RuleVia, msg: "group " + groupA + " via " + folderG},
		{name: "a group via a folder that does not list it", folder: []e2e.Member{{User: "u-a", Role: "viewer"}},
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Groups = []e2e.GroupShare{withVia(share(groupA, "viewer"), folderF)}
			}, status: 409, rule: RuleVia, msg: "group " + groupA + " via " + folderF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			for i := range c.folder {
				u := f.dir[c.folder[i].User]
				c.folder[i].FP = u.FP
			}
			f.inFolder(c.folder, c.groups...)
			b := f.next()
			// A same-epoch record that lists a as an editor and b as a
			// viewer and shares nothing else keeps the fixture valid.
			if c.edit != nil {
				c.edit(f, b)
			}
			_, err := Check(f.cur, f.groupsOf(nil, nil), f.change(t, b, nil, nil))
			if c.status == 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			refused(t, err, c.status, c.rule, c.msg)
		})
	}
}

// An item that sits in no folder may not carry a via: it names no folder
// that contains the item.
func TestCheckViaOnAnItemInNoFolder(t *testing.T) {
	f := newFixture(t)
	b := f.next()
	b.Members[1].Via = folderF
	_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
	refused(t, err, 409, RuleVia, "member u-b via "+folderF)
	b = f.next()
	if _, err := Check(f.cur, f.dir, f.change(t, b, nil, nil)); err != nil {
		t.Fatalf("a direct grant: %v", err)
	}
}

// A record that accepts an ownership offer leaves the item in its folder: it
// names the folder, and it is held to the folder's entries, though it need not
// catch up with entries the item's record lacks. The item in the fixture is
// owned by u-o and lists u-a (who accepts) and u-b; folder F is owned by u-c,
// whom the item lists as a manager via F.
func TestCheckAcceptKeepsTheItemInItsFolder(t *testing.T) {
	cFolder := func(f *fixture) e2e.Member {
		return e2e.Member{User: f.c.ID, Role: "manager", FP: f.c.FP, Via: folderF}
	}
	tmVia := func(f *fixture, role string) e2e.Member {
		return e2e.Member{User: f.tm.ID, Role: role, FP: f.tm.FP, Via: folderF}
	}
	cases := []struct {
		name string
		// setup shapes the folder and the item's latest record; accepted
		// shapes the accepting record built from takeOver.
		setup    func(f *fixture)
		accepted func(f *fixture, b *e2e.MembershipBody)
		status   int // 0 for accepted
		rule     Rule
		msg      string
	}{
		{name: "the folder's owner stays listed via the folder",
			accepted: func(f *fixture, b *e2e.MembershipBody) { b.Members = append(b.Members, cFolder(f)) }},
		{name: "the folder's owner is missing",
			status: 409, rule: RuleInherit, msg: "member u-c is missing"},
		{name: "the folder's owner is an editor",
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				m := cFolder(f)
				m.Role = "editor"
				b.Members = append(b.Members, m)
			},
			status: 409, rule: RuleInherit, msg: "member u-c is editor"},
		{name: "the new owner owns the folder, so the folder's owner entry goes",
			setup: func(f *fixture) {
				f.ownedBy(f.a)
				f.dropFromLatest(f.c)
			}},
		{name: "the previous owner owns the folder and is listed as an editor",
			setup: func(f *fixture) {
				f.ownedBy(f.o)
				f.dropFromLatest(f.c)
			},
			status: 409, rule: RuleInherit, msg: "member u-o is editor: folder " + folderF + " lists them as manager"},
		{name: "the previous owner owns the folder and is omitted",
			setup: func(f *fixture) {
				f.ownedBy(f.o)
				f.dropFromLatest(f.c)
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = []e2e.Member{member(f.b, "viewer")}
			},
			status: 409, rule: RuleInherit, msg: "member u-o is missing"},
		{name: "the folder's owner is not in the latest record and the record omits them",
			setup:  func(f *fixture) { f.dropFromLatest(f.c) },
			status: 409, rule: RuleInherit, msg: "member u-c is missing"},
		{name: "the previous owner owns the folder and is listed as its manager",
			setup: func(f *fixture) {
				f.ownedBy(f.o)
				f.dropFromLatest(f.c)
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members[1].Role, b.Members[1].Via = "manager", folderF
			}},
		{name: "the record names no folder",
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, cFolder(f))
				b.Folder = ""
			},
			status: 409, rule: RulePlacement, msg: "folder"},
		{name: "the folder lists a user the item does not, so the item is pending",
			setup: func(f *fixture) {
				f.cur.Folders[folderF].Members = []e2e.Member{{User: f.tm.ID, Role: "viewer", FP: f.tm.FP}}
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) { b.Members = append(b.Members, cFolder(f)) }},
		{name: "the folder lists a user at a higher role than the item does",
			setup: func(f *fixture) {
				f.cur.Folders[folderF].Members = []e2e.Member{{User: f.b.ID, Role: "editor", FP: f.b.FP}}
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) { b.Members = append(b.Members, cFolder(f)) }},
		{name: "the record drops a user the folder lists and the item has",
			setup: func(f *fixture) {
				f.cur.Folders[folderF].Members = []e2e.Member{{User: f.b.ID, Role: "viewer", FP: f.b.FP}}
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = []e2e.Member{member(f.o, "editor"), cFolder(f)}
			},
			status: 409, rule: RuleInherit, msg: "member u-b is missing"},
		{name: "the record lowers a user the folder lists and the item has",
			setup: func(f *fixture) {
				f.cur.Folders[folderF].Members = []e2e.Member{{User: f.b.ID, Role: "viewer", FP: f.b.FP}}
				f.setRoleInLatest(f.b, "editor")
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) { b.Members = append(b.Members, cFolder(f)) },
			status:   409, rule: RuleInherit, msg: "member u-b is viewer"},
		{name: "the folder lists a group the item lacks",
			setup: func(f *fixture) {
				f.cur.Folders[folderF].Groups = []e2e.GroupShare{share(groupA, "viewer")}
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) { b.Members = append(b.Members, cFolder(f)) }},
		{name: "the record drops a group the folder lists and the item has",
			setup: func(f *fixture) {
				f.cur.Folders[folderF].Groups = []e2e.GroupShare{share(groupA, "viewer")}
				f.latestWith("viewer", withVia(share(groupA, "viewer"), folderF))
				f.listInLatest(cFolder(f))
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, cFolder(f))
				b.Groups = nil
			},
			status: 409, rule: RuleInherit, msg: "group " + groupA + " is missing"},
		{name: "the folder lists a group at a higher role than the item does",
			setup: func(f *fixture) {
				f.cur.Folders[folderF].Groups = []e2e.GroupShare{share(groupA, "editor")}
				f.latestWith("viewer", withVia(share(groupA, "viewer"), folderF))
				f.listInLatest(cFolder(f))
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) { b.Members = append(b.Members, cFolder(f)) }},
		{name: "a group via a folder that stopped listing it is carried over",
			setup: func(f *fixture) {
				f.latestWith("viewer", withVia(share(groupA, "viewer"), folderF))
				f.listInLatest(cFolder(f))
			},
			accepted: func(f *fixture, b *e2e.MembershipBody) { b.Members = append(b.Members, cFolder(f)) }},
		{name: "a group via a folder that never listed it",
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, cFolder(f))
				b.Groups = []e2e.GroupShare{withVia(share(groupA, "viewer"), folderF)}
			},
			status: 409, rule: RuleVia, msg: "group " + groupA + " via " + folderF},
		{name: "an entry via a folder that stopped listing the user is carried over",
			setup: func(f *fixture) { f.listInLatest(tmVia(f, "viewer")) },
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, cFolder(f), tmVia(f, "viewer"))
			}},
		{name: "an entry via a folder the item never had it from",
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, cFolder(f))
				b.Members[0].Via = folderF
			},
			status: 409, rule: RuleVia, msg: "member u-b via " + folderF},
		{name: "an entry that changed its role under a via the folder does not honor",
			setup: func(f *fixture) { f.listInLatest(tmVia(f, "viewer")) },
			accepted: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, cFolder(f), tmVia(f, "editor"))
			},
			status: 409, rule: RuleVia, msg: "member u-t via " + folderF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.inFolder(nil)
			f.ownedBy(f.c)
			f.listInLatest(cFolder(f))
			for e := 1; e <= 2; e++ {
				f.cur.Wraps = append(f.cur.Wraps, store.Wrap{UserID: f.c.ID, Epoch: e, Wrapped: make([]byte, 81), FP: f.c.FP})
			}
			if c.setup != nil {
				c.setup(f)
			}
			b := f.takeOver()
			if c.accepted != nil {
				c.accepted(f, b)
			}
			slices.SortFunc(b.Members, func(x, y e2e.Member) int { return strings.Compare(x.User, y.User) })
			_, err := Check(f.cur, f.groupsOf(nil, nil), f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2)))
			if c.status == 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			refused(t, err, c.status, c.rule, c.msg)
		})
	}
}

// listInLatest adds m to the members the item's latest record lists.
func (f *fixture) listInLatest(m ...e2e.Member) {
	b := *f.cur.Latest
	b.Members = append(slices.Clone(b.Members), m...)
	slices.SortFunc(b.Members, func(x, y e2e.Member) int { return strings.Compare(x.User, y.User) })
	f.setLatest(&b)
}

// dropFromLatest removes u from the members the item's latest record lists.
func (f *fixture) dropFromLatest(u *tUser) {
	b := *f.cur.Latest
	b.Members = slices.DeleteFunc(slices.Clone(b.Members), func(m e2e.Member) bool { return m.User == u.ID })
	f.setLatest(&b)
}

// setRoleInLatest changes u's role in the item's latest record.
func (f *fixture) setRoleInLatest(u *tUser, role string) {
	b := *f.cur.Latest
	b.Members = slices.Clone(b.Members)
	for i := range b.Members {
		if b.Members[i].User == u.ID {
			b.Members[i].Role = role
		}
	}
	f.setLatest(&b)
}

// A folder's own record is held to its parent's entries, and may list its
// own members and groups.
func TestCheckAFolderInAFolder(t *testing.T) {
	f := newFixture(t)
	f.cur.Kind = "folder"
	f.latestWith("none")
	f.inFolder([]e2e.Member{{User: f.c.ID, Role: "viewer", FP: f.c.FP}})
	b := f.next()
	_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
	refused(t, err, 409, RuleInherit, "member u-c is missing")
}

// ownedBy makes u the owner of the folder f's artifact sits in, as the
// folder's latest record lists it.
func (f *fixture) ownedBy(u *tUser) {
	fr := f.cur.Folders[folderF]
	fr.Owner, fr.OwnerFP = u.ID, u.FP
}

// The folder's owner manages what is in it: an item someone else owns lists
// the owner of its folder as a manager via that folder. The item in the
// fixture is owned by u-o, and folder F by u-c.
func TestCheckTheFoldersOwnerReadsWhatIsInIt(t *testing.T) {
	ownerEntry := func(f *fixture, role, via string) e2e.Member {
		return e2e.Member{User: f.c.ID, Role: role, FP: f.c.FP, Via: via}
	}
	cases := []struct {
		name   string
		edit   func(f *fixture, b *e2e.MembershipBody)
		status int // 0 for accepted
		rule   Rule
		msg    string
	}{
		{name: "the record lists the owner as a manager via the folder",
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, ownerEntry(f, "manager", folderF))
			}},
		{name: "a direct grant at manager keeps no via",
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, ownerEntry(f, "manager", ""))
			}},
		{name: "the record omits the folder's owner",
			status: 409, rule: RuleInherit, msg: "member u-c is missing"},
		{name: "the record lists the folder's owner as an editor",
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, ownerEntry(f, "editor", folderF))
			},
			status: 409, rule: RuleInherit, msg: "member u-c is editor: folder " + folderF + " lists them as manager"},
		{name: "the record lists the folder's owner as a viewer",
			edit: func(f *fixture, b *e2e.MembershipBody) {
				b.Members = append(b.Members, ownerEntry(f, "viewer", ""))
			},
			status: 409, rule: RuleInherit, msg: "member u-c is viewer"},
		{name: "the folder's owner is deactivated",
			edit: func(f *fixture, b *e2e.MembershipBody) { f.dir["u-c"].Active = false }},
		{name: "the folder's owner is not verified",
			edit: func(f *fixture, b *e2e.MembershipBody) { f.dir["u-c"].Verified = false }},
		{name: "the folder is owned by the item's owner",
			edit: func(f *fixture, b *e2e.MembershipBody) { f.ownedBy(f.o) }},
		{name: "a via naming a folder that someone else owns",
			edit: func(f *fixture, b *e2e.MembershipBody) {
				f.ownedBy(f.a)
				b.Members = append(b.Members, ownerEntry(f, "manager", folderF))
			},
			status: 409, rule: RuleVia, msg: "member u-c via " + folderF},
		{name: "a folder further up, whose owner its record lists via itself",
			edit: func(f *fixture, b *e2e.MembershipBody) {
				f.cur.Folders[folderG] = folderRecord(folderG, nil, nil)
				f.cur.Folders[folderG].Owner = f.a.ID
				f.cur.Folders[folderF].Members = []e2e.Member{{User: f.a.ID, Role: "manager", FP: f.a.FP, Via: folderG}}
				b.Members = append(b.Members, ownerEntry(f, "manager", folderF))
				b.Members[0].Role, b.Members[0].Via = "manager", folderG
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.inFolder(nil)
			f.ownedBy(f.c)
			b := f.next()
			if c.edit != nil {
				c.edit(f, b)
			}
			slices.SortFunc(b.Members, func(x, y e2e.Member) int { return strings.Compare(x.User, y.User) })
			var wraps []WrapIn
			if slices.ContainsFunc(b.Members, func(m e2e.Member) bool { return m.User == f.c.ID }) {
				wraps = wrapsFor(f.c, 1, 2)
			}
			_, err := Check(f.cur, f.dir, f.change(t, b, wraps, nil))
			if c.status == 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			refused(t, err, c.status, c.rule, c.msg)
		})
	}
}
