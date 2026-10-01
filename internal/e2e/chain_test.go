package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The chain cases below build real membership chains: real keys, real
// signatures, and bodies marshaled from MembershipBody. TestVerifyChain runs
// each one, and chainVectors turns the same cases into the chain section of
// vectors.json, so the Go and JavaScript verifiers refuse the same chains.

const chainArtifact = "artifact-chain"

// chainUser is a test identity. Two chainUsers may share an id and differ in
// keys, which is how a test stands in for a key rotation.
type chainUser struct {
	id   string
	seed []byte
	keys KeyPair
	fp   string
}

func newChainUser(t testing.TB, id, label string) chainUser {
	t.Helper()
	seed, edPub, err := GenerateEd25519(newDRBG("chain-ed25519-" + id + label))
	if err != nil {
		t.Fatal(err)
	}
	_, xPub, err := GenerateX25519(newDRBG("chain-x25519-" + id + label))
	if err != nil {
		t.Fatal(err)
	}
	return chainUser{id: id, seed: seed, keys: KeyPair{X25519: B64(xPub), Ed25519: B64(edPub)}, fp: hex.EncodeToString(Fingerprint(xPub, edPub))}
}

// chainUsers are the people every case draws on. Their IDs sort in the
// order listed.
type chainUsers struct{ alice, bob, carol, dave, mallory chainUser }

func newChainUsers(t testing.TB) chainUsers {
	return chainUsers{
		alice:   newChainUser(t, "u-alice", ""),
		bob:     newChainUser(t, "u-bob", ""),
		carol:   newChainUser(t, "u-carol", ""),
		dave:    newChainUser(t, "u-dave", ""),
		mallory: newChainUser(t, "u-mallory", ""),
	}
}

func editor(u chainUser) Member { return Member{User: u.id, Role: "editor", FP: u.fp} }
func viewer(u chainUser) Member { return Member{User: u.id, Role: "viewer", FP: u.fp} }

func chainAKCommit(t testing.TB, epoch int) string {
	t.Helper()
	c, err := AKCommit(testKey(fmt.Sprintf("chain-ak-%d", epoch)), chainArtifact, uint64(epoch))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// bump moves a body to the next epoch, with that epoch's commitment.
func bump(t testing.TB) func(*MembershipBody) {
	return func(b *MembershipBody) {
		b.Epoch++
		b.AKCommit = chainAKCommit(t, b.Epoch)
	}
}

// chainFixture accumulates the records, owner keys, and offers of one
// chain, as GET /api/artifacts/{id}/membership would serve them.
type chainFixture struct {
	t       testing.TB
	records []Envelope
	owners  map[string]KeyPair
	offers  map[string]Envelope
	anchor  string
}

// newChain starts a chain with owner's first record, after edit.
func newChain(t testing.TB, owner chainUser, members []Member, edit func(*MembershipBody)) *chainFixture {
	t.Helper()
	f := &chainFixture{t: t, owners: map[string]KeyPair{}, offers: map[string]Envelope{}, anchor: owner.fp}
	b := MembershipBody{
		V: 1, Artifact: chainArtifact, Epoch: 1, Seq: 1, Owner: owner.id, OwnerFP: owner.fp,
		AKCommit: chainAKCommit(t, 1), Members: members, Excluded: []ExcludedEntry{}, Team: "none",
	}
	if edit != nil {
		edit(&b)
	}
	f.sign(owner, b)
	return f
}

// last decodes the latest record's body.
func (f *chainFixture) last() MembershipBody {
	f.t.Helper()
	var b MembershipBody
	if err := json.Unmarshal(f.records[len(f.records)-1].Body, &b); err != nil {
		f.t.Fatal(err)
	}
	return b
}

// add appends the record that follows the latest one, at the same epoch and
// with the same owner, after edit; signer signs it.
func (f *chainFixture) add(signer chainUser, edit func(*MembershipBody)) *chainFixture {
	f.t.Helper()
	b := f.last()
	b.Seq++
	b.Prev = BodyHash(f.records[len(f.records)-1].Body)
	b.Transfer, b.Handover = "", ""
	b.Members = slices.Clone(b.Members)
	b.Excluded = slices.Clone(b.Excluded)
	if edit != nil {
		edit(&b)
	}
	f.sign(signer, b)
	return f
}

func (f *chainFixture) sign(signer chainUser, b MembershipBody) {
	f.t.Helper()
	body, err := json.Marshal(b)
	if err != nil {
		f.t.Fatal(err)
	}
	f.addRaw(signer, body)
}

// addRaw appends a record with exactly body, signed by signer. The signer's
// keys join owners, as the server would serve them for its ownerFp.
func (f *chainFixture) addRaw(signer chainUser, body []byte) *chainFixture {
	f.t.Helper()
	env, err := NewEnvelope(signer.seed, signer.id, "membership", body)
	if err != nil {
		f.t.Fatal(err)
	}
	f.records = append(f.records, env)
	f.owners[signer.fp] = signer.keys
	return f
}

// offer signs, with signer, a transfer offer from the latest record's owner
// to the user to, after edit, and returns its body hash.
func (f *chainFixture) offer(signer, to chainUser, edit func(*TransferBody)) string {
	f.t.Helper()
	last := f.last()
	tb := TransferBody{V: 1, Artifact: chainArtifact, From: last.Owner, To: to.id, ToFP: to.fp, Prev: BodyHash(f.records[len(f.records)-1].Body)}
	for _, m := range last.Members {
		if m.User == to.id {
			tb.ToFP = m.FP
		}
	}
	if edit != nil {
		edit(&tb)
	}
	body, err := json.Marshal(tb)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.offerRaw(signer, body)
}

func (f *chainFixture) offerRaw(signer chainUser, body []byte) string {
	f.t.Helper()
	env, err := NewEnvelope(signer.seed, signer.id, "transfer", body)
	if err != nil {
		f.t.Fatal(err)
	}
	h := BodyHash(body)
	f.offers[h] = env
	return h
}

func (f *chainFixture) input() ChainInput {
	return ChainInput{Artifact: chainArtifact, Records: f.records, Owners: f.owners, Offers: f.offers, Anchor: f.anchor}
}

// head is the body hash of record seq.
func (f *chainFixture) head(seq int) string { return BodyHash(f.records[seq-1].Body) }

// newOwner returns an edit that makes to the owner, in place of the
// latest record's owner from, whom it keeps as an editor.
func newOwner(from, to chainUser, edit func(*MembershipBody)) func(*MembershipBody) {
	return func(b *MembershipBody) {
		b.Owner, b.OwnerFP = to.id, to.fp
		members := []Member{editor(from)}
		for _, m := range b.Members {
			if m.User != to.id {
				members = append(members, m)
			}
		}
		sort.Slice(members, func(i, j int) bool { return members[i].User < members[j].User })
		b.Members = members
		if edit != nil {
			edit(b)
		}
	}
}

func setTransfer(h string) func(*MembershipBody) {
	return func(b *MembershipBody) { b.Transfer = h }
}

func setHandover(v string) func(*MembershipBody) {
	return func(b *MembershipBody) { b.Handover = v }
}

// transferChain is alice's chain with bob as an editor and carol as a
// viewer, and the offer to bob. The case finishes it with bob's record.
func transferChain(t testing.TB, u chainUsers, offerEdit func(*TransferBody)) (*chainFixture, string) {
	f := newChain(t, u.alice, []Member{editor(u.bob), viewer(u.carol)}, nil)
	return f, f.offer(u.alice, u.bob, offerEdit)
}

// transferredTo finishes a transferChain with bob's accepting record.
func transferredTo(t testing.TB, u chainUsers, offerEdit func(*TransferBody)) ChainInput {
	f, h := transferChain(t, u, offerEdit)
	return f.add(u.bob, newOwner(u.alice, u.bob, setTransfer(h))).input()
}

// chainCase is one chain and what VerifyChain must make of it: a refusal
// with err, or for a valid chain, the latest record's seq and epoch and the
// handovers.
type chainCase struct {
	name, why string
	build     func(t testing.TB, u chainUsers) ChainInput
	err       error
	seq       int
	epoch     int
	handovers []int
}

func chainCases() []chainCase {
	plain := func(t testing.TB, u chainUsers) *chainFixture {
		return newChain(t, u.alice, []Member{editor(u.bob)}, nil)
	}
	three := func(t testing.TB, u chainUsers) *chainFixture {
		return plain(t, u).add(u.alice, func(b *MembershipBody) { b.Members = append(b.Members, viewer(u.carol)) }).add(u.alice, func(b *MembershipBody) { b.Team = "viewer" })
	}
	pinned := func(epoch, seq int, head func(*chainFixture) string) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			f := three(t, u)
			in := f.input()
			in.Pin = &EpochPin{Epoch: epoch, Seq: seq, Head: head(f)}
			return in
		}
	}
	member := func(edit func(*MembershipBody)) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			return newChain(t, u.alice, []Member{editor(u.bob), viewer(u.carol)}, edit).input()
		}
	}
	second := func(edit func(*MembershipBody)) func(t testing.TB, u chainUsers) ChainInput {
		return func(t testing.TB, u chainUsers) ChainInput {
			return plain(t, u).add(u.alice, edit).input()
		}
	}
	return []chainCase{
		// Valid chains.
		{name: "single-record", why: "one record, anchored at the creator", seq: 1, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput { return plain(t, u).input() }},
		{name: "same-epoch-append", why: "a record that adds a viewer at the same epoch", seq: 2, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return plain(t, u).add(u.alice, func(b *MembershipBody) { b.Members = append(b.Members, viewer(u.carol)) }).input()
			}},
		{name: "team-editor", why: "a record that opens the artifact to the team as editors", seq: 2, epoch: 1,
			build: second(func(b *MembershipBody) { b.Team = "editor" })},
		{name: "epoch-bump", why: "a record that removes bob at the next epoch, with a new akCommit", seq: 2, epoch: 2,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return plain(t, u).add(u.alice, func(b *MembershipBody) {
					bump(t)(b)
					b.Members = []Member{}
					b.Excluded = []ExcludedEntry{{User: u.bob.id, FP: u.bob.fp, Email: "bob@example.com"}}
				}).input()
			}},
		{name: "transfer", why: "alice transfers to bob through an offer; the latest record is bob's", seq: 2, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				in := transferredTo(t, u, nil)
				in.CurrentOwnerFP = u.bob.fp
				return in
			}},
		{name: "admin-handover", why: "an administrator hands alice's artifact to carol, a listed editor", seq: 2, epoch: 1, handovers: []int{2},
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := newChain(t, u.alice, []Member{editor(u.bob), editor(u.carol)}, nil)
				return f.add(u.carol, newOwner(u.alice, u.carol, setHandover("admin"))).input()
			}},
		{name: "transfer-then-handover", why: "alice to bob by offer, a record of bob's, then a handover to carol", seq: 4, epoch: 2, handovers: []int{4},
			build: func(t testing.TB, u chainUsers) ChainInput {
				f, h := transferChain(t, u, nil)
				f.add(u.bob, newOwner(u.alice, u.bob, setTransfer(h)))
				f.add(u.bob, func(b *MembershipBody) {
					bump(t)(b)
					b.Members = []Member{editor(u.alice), editor(u.carol)}
				})
				return f.add(u.carol, newOwner(u.bob, u.carol, setHandover("admin"))).input()
			}},
		{name: "members-code-point-order", why: "U+FFFD sorts before U+1F600 by UTF-8 bytes, though not by UTF-16 code units", seq: 1, epoch: 1,
			build: func(t testing.TB, u chainUsers) ChainInput {
				members := []Member{{User: "u-\uFFFD", Role: "editor", FP: u.carol.fp}, {User: "u-\U0001F600", Role: "viewer", FP: u.dave.fp}}
				return newChain(t, u.alice, members, nil).input()
			}},
		{name: "pin-matches", why: "the keyring pins seq 2, and the chain extends it", seq: 3, epoch: 1,
			build: pinned(1, 2, func(f *chainFixture) string { return f.head(2) })},
		{name: "pin-at-latest", why: "the keyring pins the latest record", seq: 3, epoch: 1,
			build: pinned(1, 3, func(f *chainFixture) string { return f.head(3) })},

		// Every record.
		{name: "no-records", why: "the chain is empty", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return ChainInput{Artifact: chainArtifact, Anchor: u.alice.fp}
			}},
		{name: "owner-key-missing", why: "owners has no key for the record's ownerFp", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				in := plain(t, u).input()
				delete(in.Owners, u.alice.fp)
				return in
			}},
		{name: "owner-key-substituted", why: "owners serves mallory's keys under alice's fingerprint, and mallory signed", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := &chainFixture{t: t, owners: map[string]KeyPair{}, offers: map[string]Envelope{}, anchor: u.alice.fp}
				body, err := json.Marshal(MembershipBody{V: 1, Artifact: chainArtifact, Epoch: 1, Seq: 1, Owner: u.alice.id, OwnerFP: u.alice.fp,
					AKCommit: chainAKCommit(t, 1), Members: []Member{}, Excluded: []ExcludedEntry{}, Team: "none"})
				if err != nil {
					t.Fatal(err)
				}
				f.addRaw(u.mallory, body)
				f.owners[u.alice.fp] = u.mallory.keys
				return f.input()
			}},
		{name: "bad-signature", why: "a record naming alice's ownerFp, signed by mallory", err: ErrDecrypt,
			build: func(t testing.TB, u chainUsers) ChainInput { return plain(t, u).add(u.mallory, nil).input() }},
		{name: "body-not-strict", why: "a record body with a key the format does not declare", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := plain(t, u)
				body := bytes.TrimSuffix(f.records[0].Body, []byte("}"))
				f.records = nil
				return f.addRaw(u.alice, append(body, []byte(`,"extra":1}`)...)).input()
			}},
		{name: "body-version", why: "a record body with v 2", err: ErrFormat,
			build: member(func(b *MembershipBody) { b.V = 2 })},
		{name: "wrong-artifact", why: "a record for another artifact", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Artifact = "artifact-other" })},
		{name: "members-null", why: "members is null, not an array", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Members = nil })},
		{name: "excluded-null", why: "excluded is null, not an array", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Excluded = nil })},
		{name: "members-unsorted", why: "members out of user ID order", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Members[0], b.Members[1] = b.Members[1], b.Members[0] })},
		{name: "members-duplicate", why: "bob listed twice", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Members[1] = b.Members[0] })},
		{name: "excluded-unsorted", why: "excluded out of user ID order", err: ErrChain,
			build: member(func(b *MembershipBody) {
				b.Excluded = []ExcludedEntry{{User: "u-zed", FP: "aa", Email: "z@example.com"}, {User: "u-yan", FP: "bb", Email: "y@example.com"}}
			})},
		{name: "excluded-duplicate", why: "the same user excluded twice", err: ErrChain,
			build: member(func(b *MembershipBody) {
				b.Excluded = []ExcludedEntry{{User: "u-zed", FP: "aa", Email: "z@example.com"}, {User: "u-zed", FP: "aa", Email: "z@example.com"}}
			})},
		{name: "owner-is-member", why: "alice lists herself as a member", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return newChain(t, u.alice, []Member{editor(u.alice), editor(u.bob)}, nil).input()
			}},
		{name: "excluded-matches-member-id", why: "an excluded entry with a member's user ID", err: ErrChain,
			build: member(func(b *MembershipBody) {
				b.Excluded = []ExcludedEntry{{User: b.Members[0].User, FP: "aa", Email: "b@example.com"}}
			})},
		{name: "excluded-matches-member-fp", why: "an excluded entry with a member's fingerprint", err: ErrChain,
			build: member(func(b *MembershipBody) {
				b.Excluded = []ExcludedEntry{{User: "u-zed", FP: b.Members[0].FP, Email: "z@example.com"}}
			})},
		{name: "excluded-names-owner", why: "an excluded entry with the owner's user ID", err: ErrChain,
			build: member(func(b *MembershipBody) {
				b.Excluded = []ExcludedEntry{{User: b.Owner, FP: BodyHash([]byte("old key")), Email: "a@example.com"}}
			})},
		{name: "member-role-unknown", why: "a member listed with role admin", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Members[0].Role = "admin" })},
		{name: "member-role-case", why: "a member listed with role Editor, not editor", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Members[0].Role = "Editor" })},
		{name: "member-fp-uppercase", why: "a member fp in uppercase hex", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Members[0].FP = strings.ToUpper(b.Members[0].FP) })},
		{name: "member-fp-short", why: "a member fp of 62 hex digits", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Members[0].FP = b.Members[0].FP[:62] })},
		{name: "team-unknown", why: "team is admin", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Team = "admin" })},
		{name: "akcommit-uppercase", why: "akCommit in uppercase hex", err: ErrChain,
			build: member(func(b *MembershipBody) { b.AKCommit = strings.ToUpper(b.AKCommit) })},
		{name: "akcommit-short", why: "akCommit of 62 hex digits", err: ErrChain,
			build: member(func(b *MembershipBody) { b.AKCommit = b.AKCommit[:62] })},

		// The first record.
		{name: "first-seq", why: "the first record has seq 2", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Seq = 2 })},
		{name: "first-prev", why: "the first record has a prev", err: ErrChain,
			build: member(func(b *MembershipBody) { b.Prev = BodyHash([]byte("x")) })},
		{name: "first-epoch", why: "the first record is at epoch 2", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return newChain(t, u.alice, []Member{}, bump(t)).input()
			}},
		{name: "first-transfer", why: "the first record sets transfer", err: ErrChain,
			build: member(setTransfer(BodyHash([]byte("x"))))},
		{name: "first-handover", why: "the first record sets handover", err: ErrChain,
			build: member(setHandover("admin"))},
		{name: "anchor-mismatch", why: "the anchor is bob's fingerprint, and alice signed the first record", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				in := plain(t, u).input()
				in.Anchor = u.bob.fp
				return in
			}},

		// Each later record.
		{name: "seq-skip", why: "the second record has seq 3", err: ErrChain,
			build: second(func(b *MembershipBody) { b.Seq++ })},
		{name: "prev-wrong", why: "the second record's prev is not the first record's hash", err: ErrChain,
			build: second(func(b *MembershipBody) { b.Prev = BodyHash([]byte("x")) })},
		{name: "epoch-skip", why: "the second record jumps from epoch 1 to 3", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return plain(t, u).add(u.alice, func(b *MembershipBody) { bump(t)(b); bump(t)(b) }).input()
			}},
		{name: "epoch-decrease", why: "the third record goes back from epoch 2 to 1", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return plain(t, u).add(u.alice, bump(t)).add(u.alice, func(b *MembershipBody) {
					b.Epoch = 1
					b.AKCommit = chainAKCommit(t, 1)
				}).input()
			}},
		{name: "akcommit-changed", why: "akCommit changes within epoch 1", err: ErrChain,
			build: second(func(b *MembershipBody) { b.AKCommit = BodyHash([]byte("other")) })},
		{name: "akcommit-kept", why: "epoch 2 keeps epoch 1's akCommit", err: ErrChain,
			build: second(func(b *MembershipBody) { b.Epoch++ })},
		{name: "same-owner-transfer", why: "a record that keeps its owner sets transfer", err: ErrChain,
			build: second(setTransfer(BodyHash([]byte("x"))))},
		{name: "same-owner-handover", why: "a record that keeps its owner sets handover", err: ErrChain,
			build: second(setHandover("admin"))},
		{name: "owner-fp-changed", why: "alice's second record is signed by a new key, with no rotation chain", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				alice2 := newChainUser(t, u.alice.id, "-rotated")
				return plain(t, u).add(alice2, func(b *MembershipBody) { b.OwnerFP = alice2.fp }).input()
			}},
		{name: "owner-change-unexplained", why: "bob takes over with neither transfer nor handover", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return plain(t, u).add(u.bob, newOwner(u.alice, u.bob, nil)).input()
			}},
		{name: "owner-change-both", why: "bob's record sets both transfer and handover", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f, h := transferChain(t, u, nil)
				return f.add(u.bob, newOwner(u.alice, u.bob, func(b *MembershipBody) {
					b.Transfer, b.Handover = h, "admin"
				})).input()
			}},
		{name: "transfer-to-unlisted", why: "an offer to dave, whom the previous record does not list", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f, _ := transferChain(t, u, nil)
				h := f.offer(u.alice, u.dave, nil)
				return f.add(u.dave, newOwner(u.alice, u.dave, setTransfer(h))).input()
			}},
		{name: "transfer-to-viewer", why: "an offer to carol, a listed viewer", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f, _ := transferChain(t, u, nil)
				h := f.offer(u.alice, u.carol, nil)
				return f.add(u.carol, newOwner(u.alice, u.carol, setTransfer(h))).input()
			}},
		{name: "transfer-fp-mismatch", why: "the previous record lists another key for bob than the one that signs", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				bob2 := newChainUser(t, u.bob.id, "-other")
				f := newChain(t, u.alice, []Member{editor(bob2), viewer(u.carol)}, nil)
				h := f.offer(u.alice, u.bob, nil)
				return f.add(u.bob, newOwner(u.alice, u.bob, setTransfer(h))).input()
			}},
		{name: "offer-missing", why: "offers has no entry for the transfer hash", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				in := transferredTo(t, u, nil)
				clear(in.Offers)
				return in
			}},
		{name: "offer-missing-empty-hash", why: "transfer is the hash of an empty body, and offers has no entry for it", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f, _ := transferChain(t, u, nil)
				return f.add(u.bob, newOwner(u.alice, u.bob, setTransfer(BodyHash(nil)))).input()
			}},
		{name: "offer-hash-mismatch", why: "offers serves, under the transfer hash, the same offer with its keys reordered, so only its hash is wrong", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f, h := transferChain(t, u, nil)
				var tb TransferBody
				if err := json.Unmarshal(f.offers[h].Body, &tb); err != nil {
					t.Fatal(err)
				}
				body := fmt.Sprintf(`{"artifact":%q,"v":1,"from":%q,"to":%q,"toFp":%q,"prev":%q}`, tb.Artifact, tb.From, tb.To, tb.ToFP, tb.Prev)
				other := f.offerRaw(u.alice, []byte(body))
				f.offers[h] = f.offers[other]
				delete(f.offers, other)
				return f.add(u.bob, newOwner(u.alice, u.bob, setTransfer(h))).input()
			}},
		{name: "offer-proto-key", why: "transfer names __proto__, which offers does not hold as its own key", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f, _ := transferChain(t, u, nil)
				return f.add(u.bob, newOwner(u.alice, u.bob, setTransfer("__proto__"))).input()
			}},
		{name: "offer-bad-signature", why: "the offer is signed by mallory, not the previous owner", err: ErrDecrypt,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := newChain(t, u.alice, []Member{editor(u.bob), viewer(u.carol)}, nil)
				h := f.offer(u.mallory, u.bob, nil)
				return f.add(u.bob, newOwner(u.alice, u.bob, setTransfer(h))).input()
			}},
		{name: "offer-not-strict", why: "the offer body has a key the format does not declare", err: ErrFormat,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := newChain(t, u.alice, []Member{editor(u.bob), viewer(u.carol)}, nil)
				body := fmt.Sprintf(`{"v":1,"artifact":%q,"from":%q,"to":%q,"toFp":%q,"prev":%q,"extra":1}`,
					chainArtifact, u.alice.id, u.bob.id, u.bob.fp, f.head(1))
				h := f.offerRaw(u.alice, []byte(body))
				return f.add(u.bob, newOwner(u.alice, u.bob, setTransfer(h))).input()
			}},
		{name: "offer-wrong-artifact", why: "the offer names another artifact", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return transferredTo(t, u, func(tb *TransferBody) { tb.Artifact = "artifact-other" })
			}},
		{name: "offer-wrong-from", why: "the offer names carol as from", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return transferredTo(t, u, func(tb *TransferBody) { tb.From = u.carol.id })
			}},
		{name: "offer-wrong-to", why: "the offer names carol as to, and bob accepts it", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return transferredTo(t, u, func(tb *TransferBody) { tb.To = u.carol.id })
			}},
		{name: "offer-wrong-toFp", why: "the offer's toFp is not the fp listed for bob", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return transferredTo(t, u, func(tb *TransferBody) { tb.ToFP = u.carol.fp })
			}},
		{name: "offer-stale-prev", why: "the offer's prev is not the hash of the record before bob's", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return transferredTo(t, u, func(tb *TransferBody) { tb.Prev = BodyHash([]byte("x")) })
			}},
		{name: "handover-to-unlisted", why: "an administrator hands over to dave, whom the previous record does not list", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return plain(t, u).add(u.dave, newOwner(u.alice, u.dave, setHandover("admin"))).input()
			}},
		{name: "handover-to-viewer", why: "an administrator hands over to carol, a listed viewer", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				f := newChain(t, u.alice, []Member{editor(u.bob), viewer(u.carol)}, nil)
				return f.add(u.carol, newOwner(u.alice, u.carol, setHandover("admin"))).input()
			}},
		{name: "handover-unknown", why: `handover is "owner", not "admin"`, err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				return plain(t, u).add(u.bob, newOwner(u.alice, u.bob, setHandover("owner"))).input()
			}},

		// The chain as a whole.
		{name: "current-owner-mismatch", why: "the latest record's ownerFp is not the current owner's", err: ErrChain,
			build: func(t testing.TB, u chainUsers) ChainInput {
				in := transferredTo(t, u, nil)
				in.CurrentOwnerFP = u.alice.fp
				return in
			}},
		{name: "rollback", why: "the keyring pins seq 4, and the chain has 3 records", err: ErrRollback,
			build: pinned(1, 4, func(f *chainFixture) string { return f.head(3) })},
		{name: "fork", why: "the record at the pinned seq hashes to another head", err: ErrFork,
			build: pinned(1, 2, func(f *chainFixture) string { return f.head(3) })},
		{name: "pin-stale-epoch", why: "the keyring pins epoch 2, and the latest record is at epoch 1", err: ErrStaleEpoch,
			build: pinned(2, 3, func(f *chainFixture) string { return f.head(3) })},
		{name: "pin-seq-zero", why: "a pin with seq 0", err: ErrFormat,
			build: pinned(1, 0, func(f *chainFixture) string { return "" })},
	}
}

func TestVerifyChain(t *testing.T) {
	u := newChainUsers(t)
	for _, c := range chainCases() {
		t.Run(c.name, func(t *testing.T) {
			in := c.build(t, u)
			got, err := VerifyChain(in)
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("%s: got %v, want %v", c.why, err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: %v", c.why, err)
			}
			last := in.Records[len(in.Records)-1].Body
			if got.Head != BodyHash(last) || got.Latest.Seq != c.seq || got.Latest.Epoch != c.epoch || len(got.Bodies) != len(in.Records) {
				t.Errorf("got head %s, seq %d, epoch %d, %d bodies; want %s, %d, %d, %d",
					got.Head, got.Latest.Seq, got.Latest.Epoch, len(got.Bodies), BodyHash(last), c.seq, c.epoch, len(in.Records))
			}
			if !slices.Equal(got.Handovers, c.handovers) {
				t.Errorf("handovers %v, want %v", got.Handovers, c.handovers)
			}
		})
	}
}

// TestVerifyChainUnlistedHandover shows that an administrator's handover to
// an unlisted user names the successor record it needs, rather than reading
// like any other unlisted new owner.
func TestVerifyChainUnlistedHandover(t *testing.T) {
	u := newChainUsers(t)
	for _, c := range chainCases() {
		if c.name != "handover-to-unlisted" {
			continue
		}
		_, err := VerifyChain(c.build(t, u))
		if !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "successor record") {
			t.Fatalf("got %v, want ErrChain naming the successor record", err)
		}
		return
	}
	t.Fatal("no handover-to-unlisted case")
}

// TestVerifyChainLinked shows that a rotation chain hook stands in for
// fingerprint equality at the anchor and at each record, and that the
// default refuses what the hook accepts.
func TestVerifyChainLinked(t *testing.T) {
	u := newChainUsers(t)
	alice2 := newChainUser(t, u.alice.id, "-rotated")
	in := newChain(t, u.alice, []Member{editor(u.bob)}, nil).
		add(alice2, func(b *MembershipBody) { b.OwnerFP = alice2.fp }).input()
	in.Anchor = "anchor-fp"
	if _, err := VerifyChain(in); !errors.Is(err, ErrChain) {
		t.Fatalf("without a hook: got %v, want ErrChain", err)
	}
	var calls [][3]string
	in.Linked = func(user, from, to string) bool {
		calls = append(calls, [3]string{user, from, to})
		return true
	}
	if _, err := VerifyChain(in); err != nil {
		t.Fatalf("with a hook: %v", err)
	}
	want := [][3]string{{u.alice.id, "anchor-fp", u.alice.fp}, {u.alice.id, u.alice.fp, alice2.fp}}
	if !slices.Equal(calls, want) {
		t.Errorf("hook calls %v, want %v", calls, want)
	}
}

func TestCheckEncryptEpoch(t *testing.T) {
	pin := &EpochPin{Epoch: 3, Seq: 5, Head: "h"}
	for _, epoch := range []int{3, 4} {
		if err := CheckEncryptEpoch(pin, epoch); err != nil {
			t.Errorf("epoch %d: %v", epoch, err)
		}
	}
	if err := CheckEncryptEpoch(pin, 2); !errors.Is(err, ErrStaleEpoch) {
		t.Errorf("epoch 2 under a pin at 3: got %v, want ErrStaleEpoch", err)
	}
	if err := CheckEncryptEpoch(nil, 1); err != nil {
		t.Errorf("no pin: %v", err)
	}
}

func TestCheckNewAK(t *testing.T) {
	earlier := [][]byte{testKey("ak-1"), testKey("ak-2")}
	if err := CheckNewAK(testKey("ak-3"), earlier); err != nil {
		t.Errorf("a fresh AK: %v", err)
	}
	if err := CheckNewAK(testKey("ak-3"), nil); err != nil {
		t.Errorf("the first epoch: %v", err)
	}
	for i, ak := range earlier {
		if err := CheckNewAK(bytes.Clone(ak), earlier); !errors.Is(err, ErrReusedAK) {
			t.Errorf("epoch %d's AK again: got %v, want ErrReusedAK", i+1, err)
		}
	}
	if err := CheckNewAK(make([]byte, 16), earlier); !errors.Is(err, ErrFormat) {
		t.Errorf("a 16-byte AK: got %v, want ErrFormat", err)
	}
}
