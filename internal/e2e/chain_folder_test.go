package e2e

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The folder IDs the folder cases name.
const (
	chainFolderA = "44444444-4444-4444-8444-444444444444"
	chainFolderB = "55555555-5555-4555-8555-555555555555"
)

// folderChainCases are the chain section's folder cases: records that name
// the folder their item sits in, and each rule that refuses a folder. Each
// refusal breaks exactly one rule.
func folderChainCases() []chainCase {
	// inFolder is a chain whose owner's second record names chainFolderA.
	inFolder := func(t testing.TB, u chainUsers) *chainFixture {
		f := newChain(t, u.alice, []Member{manager(u.bob)}, nil)
		return f.add(u.alice, func(b *MembershipBody) { b.Folder = chainFolderA })
	}
	// folderRecord is a second record the owner signs naming folder.
	folderRecord := func(folder string) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			f := newChain(t, u.alice, []Member{manager(u.bob)}, nil)
			b := f.last()
			b.Seq++
			b.Prev = f.head(1)
			b.Folder = folder
			body, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			return f.addRaw(u.alice, body).input()
		}
	}
	return []chainCase{
		{name: "folder-owner", why: "alice's second record names the folder the item sits in", seq: 2, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput { return inFolder(t, u).input() }},
		{name: "folder-manager-keeps", why: "bob, a manager, signs a record that keeps the folder alice named", seq: 3, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return inFolder(t, u).addByManager(u.bob, func(b *MembershipBody) { b.Team = "viewer" }).input()
			}},
		{name: "folder-owner-moves", why: "alice's next record names another folder, and then none, which only the owner does", seq: 4, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return inFolder(t, u).add(u.alice, func(b *MembershipBody) { b.Folder = chainFolderB }).
					add(u.alice, func(b *MembershipBody) { b.Folder = "" }).input()
			}},
		{name: "folder-manager-changes", why: "bob, a manager, names another folder than alice's record did", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return inFolder(t, u).addByManager(u.bob, func(b *MembershipBody) { b.Folder = chainFolderB }).input()
			}},
		{name: "folder-manager-drops", why: "bob, a manager, leaves out the folder alice's record named", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return inFolder(t, u).addByManager(u.bob, func(b *MembershipBody) { b.Folder = "" }).input()
			}},
		{name: "folder-manager-adds", why: "bob, a manager, names a folder where alice's record named none", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return newChain(t, u.alice, []Member{manager(u.bob)}, nil).
					addByManager(u.bob, func(b *MembershipBody) { b.Folder = chainFolderA }).input()
			}},
		{name: "folder-uppercase", why: "a folder in uppercase, which is not a lowercase UUID", err: ErrChain,
			build: folderRecord("44444444-4444-4444-8444-AAAAAAAAAAAA")},
		{name: "folder-not-uuid", why: "a folder that is not a UUID", err: ErrChain,
			build: folderRecord("top")},
		{name: "folder-empty", why: "an explicit empty folder, which the format leaves out", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := newChain(t, u.alice, []Member{manager(u.bob)}, nil)
				b := f.last()
				b.Seq++
				b.Prev = f.head(1)
				body, err := json.Marshal(b)
				if err != nil {
					t.Fatal(err)
				}
				body = bytes.Replace(body, []byte(`,"public":`), []byte(`,"folder":"","public":`), 1)
				return f.addRaw(u.alice, body).input()
			}},
	}
}
