package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The group section of vectors.json: signed group records that
// VerifyGroupChain and the browser's verifyGroupChain must both accept, with
// the result in Want, or both refuse with the error kind in Error. Records
// and Keys are in the wire form the group endpoint serves.

// groupID is the group every case is about, a lowercase UUID.
const groupID = "6f1d2c3a-0b4e-4c5d-8e7f-0123456789ab"

// otherGroupID is another lowercase UUID, for the cases that change the ID.
const otherGroupID = "7f1d2c3a-0b4e-4c5d-8e7f-0123456789ab"

func gmanager(u chainUser) GroupMember { return GroupMember{User: u.id, FP: u.fp, Role: "manager"} }
func gmember(u chainUser) GroupMember  { return GroupMember{User: u.id, FP: u.fp, Role: "member"} }

// groupFixture accumulates the records and signing keys of one group chain.
type groupFixture struct {
	t       testing.TB
	records []Envelope
	keys    map[string]GroupKey
}

// newGroup starts a chain with creator's first record, after edit.
func newGroup(t testing.TB, creator chainUser, name string, members []GroupMember, edit func(*GroupBody)) *groupFixture {
	t.Helper()
	f := &groupFixture{t: t, keys: map[string]GroupKey{}}
	b := GroupBody{V: 1, Group: groupID, Seq: 1, Name: name, Members: members, Signer: creator.id, SignerFP: creator.fp}
	if edit != nil {
		edit(&b)
	}
	f.sign(creator, b)
	return f
}

// last decodes the latest record's body.
func (f *groupFixture) last() GroupBody {
	f.t.Helper()
	var b GroupBody
	if err := json.Unmarshal(f.records[len(f.records)-1].Body, &b); err != nil {
		f.t.Fatal(err)
	}
	return b
}

// add appends the record that follows the latest one, signed by signer
// after edit.
func (f *groupFixture) add(signer chainUser, edit func(*GroupBody)) *groupFixture {
	f.t.Helper()
	b := f.last()
	b.Seq++
	b.Prev = f.head(len(f.records))
	b.Signer, b.SignerFP = signer.id, signer.fp
	b.Members = slices.Clone(b.Members)
	if edit != nil {
		edit(&b)
	}
	f.sign(signer, b)
	return f
}

func (f *groupFixture) sign(signer chainUser, b GroupBody) {
	f.t.Helper()
	body, err := json.Marshal(b)
	if err != nil {
		f.t.Fatal(err)
	}
	f.addRaw(signer, signer.id, body)
}

// addRaw appends a record with exactly body, signed with signer's seed under
// the envelope signer id. The signer's keys join keys.
func (f *groupFixture) addRaw(signer chainUser, id string, body []byte) *groupFixture {
	f.t.Helper()
	env, err := NewEnvelope(signer.seed, id, "group", body)
	if err != nil {
		f.t.Fatal(err)
	}
	f.records = append(f.records, env)
	f.keys[signer.fp] = GroupKey{User: signer.id, KeyPair: signer.keys}
	return f
}

// head is the body hash of record seq.
func (f *groupFixture) head(seq int) string { return BodyHash(f.records[seq-1].Body) }

func (f *groupFixture) input() GroupInput {
	return GroupInput{Group: groupID, Records: f.records, Keys: f.keys}
}

// withPin is input with the keyring's entry for the group.
func (f *groupFixture) withPin(seq int, head string) GroupInput {
	in := f.input()
	in.Pin = &GroupPin{Seq: seq, Head: head}
	return in
}

// groupCase is one chain and what VerifyGroupChain must make of it: a
// refusal with err, or a valid chain.
type groupCase struct {
	name, why string
	build     func(t testing.TB, u chainUsers) GroupInput
	err       error
	// rule is the rule a refusal names, which the verifier's error must carry.
	rule      string
	rotations func(t testing.TB, u chainUsers) map[string][]Envelope
}

// rawGroup appends to a one-record chain by alice, who lists bob as a
// manager and carol as a member, a record whose body is the next record
// after edit, rewritten by rewrite, signed with signer's seed under the
// envelope signer envSigner, or signer's own ID when that is empty.
func rawGroup(signer func(u chainUsers) chainUser, envSigner string, edit func(u chainUsers, b *GroupBody), rewrite func(body []byte) []byte) func(t testing.TB, u chainUsers) GroupInput {
	return func(t testing.TB, u chainUsers) GroupInput {
		f := newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice), gmanager(u.bob), gmember(u.carol)}, nil)
		b := f.last()
		b.Seq, b.Prev = 2, f.head(1)
		b.Signer, b.SignerFP = u.alice.id, u.alice.fp
		if edit != nil {
			edit(u, &b)
		}
		body, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if rewrite != nil {
			body = rewrite(body)
		}
		if envSigner == "" {
			envSigner = signer(u).id
		}
		return f.addRaw(signer(u), envSigner, body).input()
	}
}

// signerFpKey matches the signerFp member of a group body.
var signerFpKey = regexp.MustCompile(`,"signerFp":"[0-9a-f]*"`)

func aliceSigns(u chainUsers) chainUser { return u.alice }

// threeRecords is alice's chain: she creates it alone, adds bob as a manager
// and carol and dave as members, then renames it.
func threeRecords(t testing.TB, u chainUsers) *groupFixture {
	return newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice)}, nil).
		add(u.alice, func(b *GroupBody) {
			b.Members = []GroupMember{gmanager(u.alice), gmanager(u.bob), gmember(u.carol), gmember(u.dave)}
		}).
		add(u.alice, func(b *GroupBody) { b.Name = "Release reviewers" })
}

// manyMembers is alice and n more members, sorted by user ID.
func manyMembers(u chainUsers, n int) []GroupMember {
	ms := []GroupMember{gmanager(u.alice)}
	for i := 0; i < n; i++ {
		ms = append(ms, GroupMember{User: fmt.Sprintf("u-m%04d", i), FP: u.bob.fp, Role: "member"})
	}
	return ms
}

func groupCases() []groupCase {
	// bobRotated is bob's second key pair, under his own user ID.
	bobRotated := func(t testing.TB, u chainUsers) chainUser { return newChainUser(t, u.bob.id, "-rotated") }
	// named builds a one-record chain whose group name is name.
	named := func(name string) func(t testing.TB, u chainUsers) GroupInput {
		return func(t testing.TB, u chainUsers) GroupInput {
			return newGroup(t, u.alice, name, []GroupMember{gmanager(u.alice)}, nil).input()
		}
	}
	// first builds a one-record chain whose body is edited by edit.
	first := func(edit func(u chainUsers, b *GroupBody)) func(t testing.TB, u chainUsers) GroupInput {
		return func(t testing.TB, u chainUsers) GroupInput {
			return newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice)}, func(b *GroupBody) { edit(u, b) }).input()
		}
	}
	// twoManagers is alice's one-record chain with bob as a second manager
	// and carol as a member.
	twoManagers := func(t testing.TB, u chainUsers) *groupFixture {
		return newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice), gmanager(u.bob), gmember(u.carol)}, nil)
	}
	return []groupCase{
		// Valid chains.
		{name: "single-record", why: "alice creates the group and lists herself as its manager",
			build: func(t testing.TB, u chainUsers) GroupInput {
				return newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice)}, nil).input()
			}},
		{name: "three-records", why: "alice creates a group, adds bob as a manager and carol and dave as members, then renames it",
			build: func(t testing.TB, u chainUsers) GroupInput { return threeRecords(t, u).input() }},
		{name: "manager-added-then-signs", why: "alice adds bob as a manager, and bob signs the next record, adding carol",
			build: func(t testing.TB, u chainUsers) GroupInput {
				return newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice)}, nil).
					add(u.alice, func(b *GroupBody) { b.Members = []GroupMember{gmanager(u.alice), gmanager(u.bob)} }).
					add(u.bob, func(b *GroupBody) {
						b.Members = []GroupMember{gmanager(u.alice), gmanager(u.bob), gmember(u.carol)}
					}).input()
			}},
		{name: "manager-key-rotated", why: "bob signs under a new key, and the previous record lists his old fp: his rotation record links the two",
			build: func(t testing.TB, u chainUsers) GroupInput {
				return twoManagers(t, u).add(bobRotated(t, u), func(b *GroupBody) { b.Name = "Release reviewers" }).input()
			},
			rotations: func(t testing.TB, u chainUsers) map[string][]Envelope {
				return bobRotation(t, u.bob, bobRotated(t, u))
			}},
		{name: "manager-removes-themselves", why: "alice removes herself while bob remains a manager",
			build: func(t testing.TB, u chainUsers) GroupInput {
				return twoManagers(t, u).add(u.alice, func(b *GroupBody) { b.Members = []GroupMember{gmanager(u.bob), gmember(u.carol)} }).input()
			}},
		{name: "manager-demotes-manager", why: "alice makes bob a member, and carol a manager",
			build: func(t testing.TB, u chainUsers) GroupInput {
				return twoManagers(t, u).add(u.alice, func(b *GroupBody) {
					b.Members = []GroupMember{gmanager(u.alice), gmember(u.bob), gmanager(u.carol)}
				}).input()
			}},
		{name: "name-100-astral-code-points", why: "a name of 100 code points, each two UTF-16 units, is the longest allowed",
			build: named(strings.Repeat("\U0001F600", 100))},
		{name: "name-one-code-point", why: "a one-character name is the shortest allowed",
			build: named("x")},
		{name: "members-1000", why: "a group of 1000 members is the largest allowed",
			build: func(t testing.TB, u chainUsers) GroupInput {
				return newGroup(t, u.alice, "Everyone", manyMembers(u, 999), nil).input()
			}},
		{name: "pin-at-the-head", why: "the keyring's pin is the latest record",
			build: func(t testing.TB, u chainUsers) GroupInput {
				f := threeRecords(t, u)
				return f.withPin(3, f.head(3))
			}},
		{name: "pin-behind-the-head", why: "the keyring's pin is the second of three records, which the chain still holds",
			build: func(t testing.TB, u chainUsers) GroupInput {
				f := threeRecords(t, u)
				return f.withPin(2, f.head(2))
			}},

		// The first record.
		{name: "no-records", why: "the server served no records", rule: "no-records", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				return GroupInput{Group: groupID, Keys: map[string]GroupKey{}}
			}},
		{name: "first-signer-is-member", why: "alice signs the first record and lists herself as a member, with bob as the manager", rule: "first-signer-not-manager", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				return newGroup(t, u.alice, "Reviewers", []GroupMember{gmember(u.alice), gmanager(u.bob)}, nil).input()
			}},
		{name: "first-signer-not-listed", why: "alice signs the first record and does not list herself", rule: "first-signer-not-manager", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				return newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.bob)}, nil).input()
			}},
		{name: "first-signer-fp-differs", why: "the first record lists alice under another fingerprint than the key that signed it", rule: "first-signer-fp-differs", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				return newGroup(t, u.alice, "Reviewers", []GroupMember{{User: u.alice.id, FP: u.carol.fp, Role: "manager"}}, nil).input()
			}},
		{name: "first-record-seq-2", why: "the first record has seq 2", rule: "first-seq", err: ErrChain,
			build: first(func(u chainUsers, b *GroupBody) { b.Seq = 2 })},
		{name: "first-record-has-prev", why: "the first record names a prev", rule: "first-prev", err: ErrChain,
			build: first(func(u chainUsers, b *GroupBody) { b.Prev = strings.Repeat("0", 64) })},
		{name: "group-id-not-a-uuid", why: "the group ID is not a lowercase UUID", rule: "group-id-not-uuid", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				in := newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice)}, func(b *GroupBody) { b.Group = "reviewers" }).input()
				in.Group = "reviewers"
				return in
			}},
		{name: "group-id-asked-for-differs", why: "the records are for another group than the one asked for", rule: "group-id-differs", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				in := newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice)}, nil).input()
				in.Group = otherGroupID
				return in
			}},

		// Who signs a later record.
		{name: "signer-not-listed", why: "mallory, whom the previous record does not list, signs the next record", rule: "signer-not-manager", err: ErrChain,
			build: rawGroup(func(u chainUsers) chainUser { return u.mallory }, "", func(u chainUsers, b *GroupBody) {
				b.Signer, b.SignerFP = u.mallory.id, u.mallory.fp
			}, nil)},
		{name: "signer-is-member", why: "carol, listed as a member, signs the next record", rule: "signer-not-manager", err: ErrChain,
			build: rawGroup(func(u chainUsers) chainUser { return u.carol }, "", func(u chainUsers, b *GroupBody) {
				b.Signer, b.SignerFP = u.carol.id, u.carol.fp
			}, nil)},
		{name: "signer-key-not-linked", why: "bob signs under a new key, and no rotation chain links it to the fp the previous record lists", rule: "signer-key-not-linked", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				return twoManagers(t, u).add(bobRotated(t, u), nil).input()
			}},
		{name: "signer-key-missing", why: "keys has no key for the signerFp", rule: "signer-key-missing", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				in := twoManagers(t, u).add(u.bob, nil).input()
				in.Keys = map[string]GroupKey{u.alice.fp: {User: u.alice.id, KeyPair: u.alice.keys}}
				return in
			}},
		{name: "signer-key-of-another-user", why: "bob signs a record that names alice as its signer, under bob's fingerprint, and bob's key is served as bob's", rule: "signer-key-of-another-user", err: ErrChain,
			build: rawGroup(func(u chainUsers) chainUser { return u.bob }, "u-alice", func(u chainUsers, b *GroupBody) {
				b.Signer, b.SignerFP = u.alice.id, u.bob.fp
			}, nil)},
		{name: "forged-signature", why: "mallory signs a record that names bob as its signer, under bob's fingerprint", rule: "signature", err: ErrDecrypt,
			build: func(t testing.TB, u chainUsers) GroupInput {
				in := rawGroup(func(u chainUsers) chainUser { return u.mallory }, "u-bob", func(u chainUsers, b *GroupBody) {
					b.Signer, b.SignerFP = u.bob.id, u.bob.fp
				}, nil)(t, u)
				// bob's real keys are served for his fingerprint, as the directory would.
				in.Keys[u.bob.fp] = GroupKey{User: u.bob.id, KeyPair: u.bob.keys}
				delete(in.Keys, u.mallory.fp)
				return in
			}},
		{name: "signer-differs-from-envelope-signer", why: "the body's signer is alice, and the envelope names carol as the signer", rule: "envelope-signer-differs", err: ErrChain,
			build: rawGroup(aliceSigns, "u-carol", nil, nil)},

		// seq and prev.
		{name: "skipped-seq", why: "the second record has seq 3", rule: "seq-skipped", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) { b.Seq = 3 }, nil)},
		{name: "repeated-seq", why: "the second record has seq 1", rule: "seq-skipped", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) { b.Seq = 1 }, nil)},
		{name: "wrong-prev", why: "the second record's prev is not the first record's hash", rule: "prev-wrong", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) { b.Prev = strings.Repeat("0", 64) }, nil)},
		{name: "group-id-changes", why: "the second record is for another group", rule: "group-id-differs", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) { b.Group = otherGroupID }, nil)},

		// The members.
		{name: "members-unsorted", why: "the members are not sorted by user ID", rule: "members-unsorted", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) {
				b.Members = []GroupMember{gmanager(u.alice), gmember(u.carol), gmanager(u.bob)}
			}, nil)},
		{name: "duplicate-user", why: "carol is listed twice", rule: "member-duplicate", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) {
				b.Members = []GroupMember{gmanager(u.alice), gmember(u.carol), gmember(u.carol)}
			}, nil)},
		{name: "no-manager-left", why: "alice removes herself and bob, leaving only a member", rule: "no-manager", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) { b.Members = []GroupMember{gmember(u.carol)} }, nil)},
		{name: "bad-role", why: "carol's role is owner", rule: "member-role-invalid", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) {
				b.Members = []GroupMember{gmanager(u.alice), {User: u.carol.id, FP: u.carol.fp, Role: "owner"}}
			}, nil)},
		{name: "member-fp-malformed", why: "carol's fp is not 64 lowercase hex digits", rule: "member-fp-malformed", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) {
				b.Members = []GroupMember{gmanager(u.alice), {User: u.carol.id, FP: strings.ToUpper(u.carol.fp), Role: "member"}}
			}, nil)},
		{name: "no-members", why: "the members list is empty", rule: "members-none", err: ErrChain,
			build: rawGroup(aliceSigns, "", func(u chainUsers, b *GroupBody) { b.Members = []GroupMember{} }, nil)},
		{name: "members-1001", why: "the group lists 1001 members", rule: "members-too-many", err: ErrChain,
			build: func(t testing.TB, u chainUsers) GroupInput {
				return newGroup(t, u.alice, "Everyone", manyMembers(u, 1000), nil).input()
			}},

		// The name.
		{name: "name-empty", why: "the name is empty", rule: "name-empty", err: ErrChain, build: named("")},
		{name: "name-101-code-points", why: "the name is 101 code points", rule: "name-too-long", err: ErrChain, build: named(strings.Repeat("a", 101))},
		{name: "name-newline", why: "the name holds a line feed, a C0 control character", rule: "name-control-character", err: ErrChain, build: named("Review\ners")},
		{name: "name-c1-control", why: "the name holds U+0085, a C1 control character", rule: "name-control-character", err: ErrChain, build: named("Review\u0085ers")},
		{name: "name-delete", why: "the name holds U+007F", rule: "name-control-character", err: ErrChain, build: named("Review\u007fers")},

		// The body.
		{name: "unknown-body-key", why: "the body has a key the format does not", rule: "body-format", err: ErrFormat,
			build: rawGroup(aliceSigns, "", nil, func(body []byte) []byte {
				return []byte(strings.Replace(string(body), `"name":`, `"extra":1,"name":`, 1))
			})},
		{name: "body-version-2", why: "the body's v is 2", rule: "body-version", err: ErrFormat,
			build: rawGroup(aliceSigns, "", nil, func(body []byte) []byte {
				return []byte(strings.Replace(string(body), `"v":1`, `"v":2`, 1))
			})},
		{name: "signer-fp-missing", why: "the body has no signerFp", rule: "body-format", err: ErrFormat,
			build: rawGroup(aliceSigns, "", nil, func(body []byte) []byte {
				return signerFpKey.ReplaceAll(body, nil)
			})},

		// The keyring's pin.
		{name: "rollback", why: "the keyring pins seq 4 and the chain has three records", rule: "pin-rolled-back", err: ErrRollback,
			build: func(t testing.TB, u chainUsers) GroupInput {
				f := threeRecords(t, u)
				return f.withPin(4, f.head(3))
			}},
		{name: "fork", why: "the record at the pinned seq 2 hashes to another head", rule: "pin-forked", err: ErrFork,
			build: func(t testing.TB, u chainUsers) GroupInput {
				f := threeRecords(t, u)
				return f.withPin(2, f.head(3))
			}},
		{name: "pin-seq-zero", why: "the keyring pins seq 0", rule: "pin-seq-invalid", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) GroupInput {
				f := threeRecords(t, u)
				return f.withPin(0, f.head(1))
			}},
	}
}

type groupWantVec struct {
	Seq     int           `json:"seq"`
	Head    string        `json:"head"`
	Name    string        `json:"name"`
	Members []GroupMember `json:"members"`
}

type groupVec struct {
	Name      string                `json:"name"`
	Why       string                `json:"why"`
	Group     string                `json:"group"`
	Records   []Envelope            `json:"records"`
	Keys      map[string]GroupKey   `json:"keys"`
	Rotations map[string][]Envelope `json:"rotations"`
	Pin       *GroupPin             `json:"pin"`
	Want      *groupWantVec         `json:"want,omitempty"`
	Error     string                `json:"error,omitempty"`
	Rule      string                `json:"rule,omitempty"`
}

// groupVectors builds the group section from groupCases. Want comes from the
// last record's own body, never from VerifyGroupChain.
func groupVectors(t testing.TB) []groupVec {
	t.Helper()
	u := newChainUsers(t)
	var vs []groupVec
	for _, c := range groupCases() {
		in := c.build(t, u)
		v := groupVec{Name: c.name, Why: c.why, Group: in.Group, Records: in.Records, Keys: in.Keys, Rotations: map[string][]Envelope{}, Pin: in.Pin}
		if v.Records == nil {
			v.Records = []Envelope{}
		}
		if c.rotations != nil {
			v.Rotations = c.rotations(t, u)
		}
		if c.err != nil {
			v.Error, v.Rule = chainErrorKind(t, c.err), c.rule
		} else {
			last := in.Records[len(in.Records)-1].Body
			var b GroupBody
			if err := json.Unmarshal(last, &b); err != nil {
				t.Fatal(err)
			}
			v.Want = &groupWantVec{Seq: b.Seq, Head: BodyHash(last), Name: b.Name, Members: b.Members}
		}
		vs = append(vs, v)
	}
	return vs
}

// checkGroupVectors runs every group entry, as read back from JSON, through
// VerifyGroupChain.
func checkGroupVectors(t *testing.T, vs []groupVec) {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []groupVec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, v := range parsed {
		got, err := VerifyGroupChain(GroupInput{Group: v.Group, Records: v.Records, Keys: v.Keys, Linked: RotationLinker(v.Rotations), Pin: v.Pin})
		if v.Error != "" {
			if !errors.Is(err, chainErrorKinds[v.Error]) {
				t.Errorf("%s (%s): got %v, want %s", v.Name, v.Why, err, v.Error)
			}
			if got := GroupRule(err); got != v.Rule || v.Rule == "" {
				t.Errorf("%s (%s): refused under rule %q, want %q", v.Name, v.Why, got, v.Rule)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s (%s): %v", v.Name, v.Why, err)
			continue
		}
		w := v.Want
		if got.Head != w.Head || got.Latest.Seq != w.Seq || got.Latest.Name != w.Name || !slices.Equal(got.Latest.Members, w.Members) {
			t.Errorf("%s: got head %s, seq %d, name %q, %d members; want %+v", v.Name, got.Head, got.Latest.Seq, got.Latest.Name, len(got.Latest.Members), *w)
		}
	}
}
