package e2e

import (
	"encoding/json"
	"errors"
	"testing"
)

func manager(u chainUser) Member { return Member{User: u.id, Role: "manager", FP: u.fp} }

// bobRotation is u-bob's one rotation record, from bob's keys to bob2's.
func bobRotation(t testing.TB, bob, bob2 chainUser) map[string][]Envelope {
	t.Helper()
	body, err := json.Marshal(RotationBody{V: 1, User: bob.id, Seq: 1, Old: bob.keys, New: bob2.keys})
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignRotation(bob.seed, bob2.seed, body, bob.id)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]Envelope{bob.id: {env}}
}

// managerChainCases are the chain section's manager cases: version 2 records
// that bob, a listed manager, signs in alice's chain, and each rule that
// refuses one. Each refusal breaks exactly one rule.
func managerChainCases() []chainCase {
	// base lists bob as a manager, carol as an editor, and dave as a viewer.
	base := func(t testing.TB, u chainUsers) *chainFixture {
		return newChain(t, u.alice, []Member{manager(u.bob), editor(u.carol), viewer(u.dave)}, nil)
	}
	// twoManagers lists bob and carol as managers.
	twoManagers := func(t testing.TB, u chainUsers) *chainFixture {
		return newChain(t, u.alice, []Member{manager(u.bob), manager(u.carol), viewer(u.dave)}, nil)
	}
	byBob := func(edit func(t testing.TB, u chainUsers, b *MembershipBody)) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			return base(t, u).addByManager(u.bob, func(b *MembershipBody) { edit(t, u, b) }).input()
		}
	}
	// raw appends to base a record whose body is the version 2 record bob
	// would sign, after edit, then rewritten by rewrite, signed by signer.
	raw := func(signer func(u chainUsers) chainUser, edit func(u chainUsers, b *MembershipBody), rewrite func(body []byte) []byte) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			f := base(t, u)
			b := f.last()
			b.Seq++
			b.Prev = f.head(1)
			b.V, b.Signer, b.SignerFP = 2, u.bob.id, u.bob.fp
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
			return f.addRaw(signer(u), body).input()
		}
	}
	bob := func(u chainUsers) chainUser { return u.bob }
	// asBob is mallory's seed and keys under bob's user ID.
	asBob := func(u chainUsers) chainUser {
		return chainUser{id: u.bob.id, seed: u.mallory.seed, keys: u.mallory.keys, fp: u.mallory.fp}
	}

	return []chainCase{
		// Valid chains.
		{name: "manager-listed", why: "alice's first record lists bob as a manager", seq: 1, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput { return base(t, u).input() }},
		{name: "manager-same-epoch", why: "bob, a listed manager, adds mallory as a viewer at the same epoch", seq: 2, epoch: 1,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Members = append(b.Members, viewer(u.mallory)) })},
		{name: "manager-promotes-viewer", why: "bob promotes dave from viewer to editor at the same epoch", seq: 2, epoch: 1,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Members[2] = editor(u.dave) })},
		{name: "manager-sets-team", why: "bob opens the artifact to the team as viewers", seq: 2, epoch: 1,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Team = "viewer" })},
		{name: "manager-next-epoch", why: "bob removes carol at the next epoch, with a new akCommit", seq: 2, epoch: 2,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) {
				bump(t)(b)
				b.Members = []Member{manager(u.bob), viewer(u.dave)}
				b.Excluded = []ExcludedEntry{{User: u.carol.id, FP: u.carol.fp, Email: "carol@example.com"}}
			})},
		{name: "manager-then-owner", why: "an owner's record, signed by alice, follows bob's", seq: 3, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).addByManager(u.bob, func(b *MembershipBody) { b.Team = "viewer" }).
					add(u.alice, func(b *MembershipBody) { b.Team = "none" }).input()
			}},
		{name: "manager-key-rotated", why: "bob signs under a new key, and the first record lists his old fp: his rotation record links the two", seq: 2, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				bob2 := newChainUser(t, u.bob.id, "-rotated")
				return base(t, u).addByManager(bob2, func(b *MembershipBody) { b.Team = "viewer" }).input()
			},
			rotations: func(t testing.TB, u chainUsers) map[string][]Envelope {
				return bobRotation(t, u.bob, newChainUser(t, u.bob.id, "-rotated"))
			}},
		{name: "transfer-to-manager", why: "alice offers ownership to bob, a listed manager, who accepts", seq: 2, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := base(t, u)
				h := f.offer(u.alice, u.bob, nil)
				return f.add(u.bob, newOwner(u.alice, u.bob, setTransfer(h))).input()
			}},

		// Who signs.
		{name: "manager-signer-not-listed", why: "mallory, whom the previous record does not list, signs a version 2 record", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).addByManager(u.mallory, nil).input()
			}},
		{name: "manager-signer-is-editor", why: "carol, listed as an editor, signs a version 2 record", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).addByManager(u.carol, nil).input()
			}},
		{name: "manager-signer-is-viewer", why: "dave, listed as a viewer, signs a version 2 record", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).addByManager(u.dave, nil).input()
			}},
		{name: "manager-fp-unlinked", why: "bob signs under a new key, and no rotation chain links it to the fp the previous record lists", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				bob2 := newChainUser(t, u.bob.id, "-rotated")
				return base(t, u).addByManager(bob2, nil).input()
			}},
		{name: "manager-key-missing", why: "owners has no key for the signerFp", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				in := base(t, u).addByManager(u.bob, nil).input()
				delete(in.Owners, u.bob.fp)
				return in
			}},
		{name: "manager-key-substituted", why: "owners serves mallory's keys under bob's fingerprint, and mallory signed", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				in := base(t, u).addByManager(asBob(u), func(b *MembershipBody) { b.SignerFP = u.bob.fp }).input()
				in.Owners[u.bob.fp] = u.mallory.keys
				return in
			}},
		{name: "manager-signed-by-another-key", why: "a record naming bob's signerFp, signed by mallory, with bob's keys served", err: ErrDecrypt,
			build: func(t testing.TB, u chainUsers) ChainInput {
				in := base(t, u).addByManager(asBob(u), func(b *MembershipBody) { b.SignerFP = u.bob.fp }).input()
				in.Owners[u.bob.fp] = u.bob.keys
				return in
			}},
		{name: "manager-envelope-signer", why: "the envelope names carol as signer, and the body names bob", err: ErrChain,
			build: raw(func(u chainUsers) chainUser {
				return chainUser{id: u.carol.id, seed: u.bob.seed, keys: u.bob.keys, fp: u.bob.fp}
			}, nil, nil)},

		// What a version 2 record may not change.
		{name: "manager-changes-owner", why: "bob's record names mallory, not listed, as owner, under alice's ownerFp", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Owner = u.mallory.id })},
		{name: "manager-changes-owner-fp", why: "bob's record keeps alice as owner under another fp, with no rotation chain", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.OwnerFP = u.mallory.fp })},
		{name: "manager-sets-transfer", why: "bob's record sets transfer", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Transfer = BodyHash([]byte("x")) })},
		{name: "manager-sets-handover", why: "bob's record sets handover", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Handover = "admin" })},
		{name: "manager-adds-manager", why: "bob promotes dave to manager", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Members[2] = manager(u.dave) })},
		{name: "manager-adds-new-manager", why: "bob lists mallory, not listed before, as a manager", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Members = append(b.Members, manager(u.mallory)) })},
		{name: "manager-removes-manager", why: "bob removes carol, another manager, at the next epoch", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return twoManagers(t, u).addByManager(u.bob, func(b *MembershipBody) {
					bump(t)(b)
					b.Members = []Member{manager(u.bob), viewer(u.dave)}
					b.Excluded = []ExcludedEntry{{User: u.carol.id, FP: u.carol.fp, Email: "carol@example.com"}}
				}).input()
			}},
		{name: "manager-removes-self", why: "bob removes his own entry at the next epoch", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) {
				bump(t)(b)
				b.Members = []Member{editor(u.carol), viewer(u.dave)}
				b.Excluded = []ExcludedEntry{{User: u.bob.id, FP: u.bob.fp, Email: "bob@example.com"}}
			})},
		{name: "manager-changes-manager-role", why: "bob demotes carol from manager to editor", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return twoManagers(t, u).addByManager(u.bob, func(b *MembershipBody) { b.Members[1] = editor(u.carol) }).input()
			}},
		{name: "manager-changes-manager-fp", why: "bob lists carol, a manager, under another fp", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return twoManagers(t, u).addByManager(u.bob, func(b *MembershipBody) { b.Members[1].FP = BodyHash([]byte("other key")) }).input()
			}},
		{name: "manager-changes-own-role", why: "bob demotes himself to editor", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Members[0] = editor(u.bob) })},
		{name: "manager-changes-own-fp", why: "bob lists himself under another fp", err: ErrChain,
			build: byBob(func(t testing.TB, u chainUsers, b *MembershipBody) { b.Members[0].FP = BodyHash([]byte("other key")) })},

		// The version rule.
		{name: "manager-first-record", why: "a first record that bob signs as version 2", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := &chainFixture{t: t, owners: map[string]KeyPair{}, offers: map[string]Envelope{}, anchor: u.alice.fp}
				body, err := json.Marshal(MembershipBody{V: 2, Artifact: chainArtifact, Epoch: 1, Seq: 1, Owner: u.alice.id, OwnerFP: u.alice.fp,
					AKCommit: chainAKCommit(t, 1), Members: []Member{manager(u.bob)}, Excluded: []ExcludedEntry{}, Team: "none",
					Signer: u.bob.id, SignerFP: u.bob.fp})
				if err != nil {
					t.Fatal(err)
				}
				return f.addRaw(u.bob, body).input()
			}},
		{name: "v1-with-signer", why: "alice signs a version 1 record that has signer and signerFp", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).add(u.alice, func(b *MembershipBody) { b.Signer, b.SignerFP = u.bob.id, u.bob.fp }).input()
			}},
		{name: "v1-with-signer-only", why: "alice signs a version 1 record that has signer and no signerFp", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).add(u.alice, func(b *MembershipBody) { b.Signer = u.bob.id }).input()
			}},
		{name: "v2-without-signer", why: "bob signs a version 2 record with neither signer nor signerFp", err: ErrFormat,
			build: raw(bob, func(u chainUsers, b *MembershipBody) { b.Signer, b.SignerFP = "", "" }, nil)},
		{name: "v2-without-signer-fp", why: "bob signs a version 2 record with signer and no signerFp", err: ErrFormat,
			build: raw(bob, func(u chainUsers, b *MembershipBody) { b.SignerFP = "" }, nil)},
		{name: "v2-empty-signer", why: "a version 2 record with an explicit empty signer and signerFp", err: ErrFormat,
			build: raw(bob, func(u chainUsers, b *MembershipBody) { b.Signer, b.SignerFP = "", "" }, func(body []byte) []byte {
				return append(body[:len(body)-1], []byte(`,"signer":"","signerFp":""}`)...)
			})},
		{name: "v2-signer-is-owner", why: "alice signs a version 2 record naming herself as signer", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return base(t, u).addByManager(u.alice, nil).input()
			}},
		{name: "v-unknown", why: "bob signs a record with v 3 and both signer fields", err: ErrFormat,
			build: raw(bob, func(u chainUsers, b *MembershipBody) { b.V = 3 }, nil)},
	}
}

// TestManagerRecordRules shows that every rule of a version 2 record
// refuses with the error class the spec's chain section names, on the cases
// above, and that the explicit-empty signer is refused by DecodeStrict
// itself.
func TestManagerRecordRules(t *testing.T) {
	for _, body := range []string{
		`{"signer":""}`,
		`{"signerFp":""}`,
	} {
		var b MembershipBody
		if err := DecodeStrict([]byte(body), &b); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: got %v, want ErrFormat", body, err)
		}
	}
	good := MembershipBody{V: 2, Owner: "u-alice", Signer: "u-bob", SignerFP: "ab"}
	for name, edit := range map[string]func(*MembershipBody){
		"v1 with signer":     func(b *MembershipBody) { b.V = 1 },
		"v2 no signer":       func(b *MembershipBody) { b.Signer = "" },
		"v2 no signerFp":     func(b *MembershipBody) { b.SignerFP = "" },
		"v2 signer is owner": func(b *MembershipBody) { b.Signer = b.Owner },
		"v0":                 func(b *MembershipBody) { b.V = 0 },
		"v3":                 func(b *MembershipBody) { b.V = 3 },
	} {
		b := good
		edit(&b)
		if err := b.checkVersion(); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: got %v, want ErrFormat", name, err)
		}
	}
	if err := good.checkVersion(); err != nil {
		t.Errorf("a version 2 body with both fields: %v", err)
	}
	v1 := MembershipBody{V: 1, Owner: "u-alice"}
	if err := v1.checkVersion(); err != nil {
		t.Errorf("a version 1 body with neither field: %v", err)
	}
}
