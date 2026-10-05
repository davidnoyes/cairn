package e2e

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

// succRecord signs a successor record of alice's, naming carol, with signer's
// key, after edit.
func succRecord(t testing.TB, signer chainUser, edit func(*SuccessorBody)) Envelope {
	t.Helper()
	u := newChainUsers(t)
	b := SuccessorBody{V: 1, User: u.alice.id, Seq: 1, Successor: u.carol.id, SuccessorFP: u.carol.fp, Action: "nominate"}
	if edit != nil {
		edit(&b)
	}
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := NewEnvelope(signer.seed, signer.id, "successor", body)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// handoverInput is alice's chain, handed by an administrator to carol in
// record 2, with rec served as the successor record for it, or none when rec
// is nil. The first record lists carol as an editor only when listed is set.
func handoverInput(t testing.TB, listed bool, rec *Envelope) ChainInput {
	u := newChainUsers(t)
	members := []Member{editor(u.bob)}
	if listed {
		members = append(members, editor(u.carol))
	}
	in := newChain(t, u.alice, members, nil).add(u.carol, newOwner(u.alice, u.carol, setHandover("admin"))).input()
	if rec != nil {
		in.Successors = map[string]Envelope{"2": *rec}
	}
	return in
}

// successorChainCases are the chain section's successor record cases: an
// administrator's handover from alice to carol in record 2, with each record
// served for it, once with carol listed as an editor and once not. A valid
// record makes the handover silent, and lets an unlisted carol in; any other
// leaves the notice, and refuses an unlisted carol.
func successorChainCases() []chainCase {
	type rec struct {
		name, why string
		signer    func(u chainUsers) chainUser
		edit      func(u chainUsers, b *SuccessorBody)
		silent    bool
	}
	alice := func(u chainUsers) chainUser { return u.alice }
	recs := []rec{
		{"valid", "alice's record nominates carol", alice, nil, true},
		{"none", "no record is served", nil, nil, false},
		{"remove", "alice's record removes the nomination", alice, func(_ chainUsers, b *SuccessorBody) { b.Action = "remove"; b.SuccessorFP = "" }, false},
		{"remove-keeping-fp", "alice's record removes the nomination and keeps carol's fp", alice, func(_ chainUsers, b *SuccessorBody) { b.Action = "remove" }, false},
		{"wrong-signer", "mallory signs the record", func(u chainUsers) chainUser { return u.mallory }, nil, false},
		{"wrong-successor-fp", "the record's successorFp is dave's", alice, func(u chainUsers, b *SuccessorBody) { b.SuccessorFP = u.dave.fp }, false},
		{"wrong-successor", "the record nominates dave", alice, func(u chainUsers, b *SuccessorBody) { b.Successor = u.dave.id }, false},
		{"wrong-user", "the record is bob's", alice, func(u chainUsers, b *SuccessorBody) { b.User = u.bob.id }, false},
	}
	var cases []chainCase
	for _, r := range recs {
		for _, listed := range []bool{true, false} {
			c := chainCase{seq: 2, epoch: 1}
			build := func(t testing.TB, u chainUsers) ChainInput {
				var env *Envelope
				if r.signer != nil {
					e := succRecord(t, r.signer(u), func(b *SuccessorBody) {
						if r.edit != nil {
							r.edit(u, b)
						}
					})
					env = &e
				}
				return handoverInput(t, listed, env)
			}
			c.build = build
			if listed {
				c.name, c.why = "successor-listed-"+r.name, "carol is a listed editor; "+r.why
				if !r.silent {
					c.handovers = []int{2}
				}
			} else {
				c.name, c.why = "successor-unlisted-"+r.name, "carol is not listed; "+r.why
				if !r.silent {
					c.err = ErrChain
				}
			}
			cases = append(cases, c)
		}
	}
	return cases
}

// The record is looked up by the accepting record's seq, so one served under
// another seq does not count.
func TestVerifyChainSuccessorRecordWrongSeq(t *testing.T) {
	u := newChainUsers(t)
	in := handoverInput(t, true, nil)
	in.Successors = map[string]Envelope{"1": succRecord(t, u.alice, nil)}
	got, err := VerifyChain(in)
	if err != nil || !slices.Equal(got.Handovers, []int{2}) {
		t.Fatalf("got %v, %v", got, err)
	}
}

// A transfer is not a handover, so a successor record plays no part in it.
func TestVerifyChainSuccessorRecordIgnoredForTransfer(t *testing.T) {
	u := newChainUsers(t)
	in := transferredTo(t, u, nil)
	in.Successors = map[string]Envelope{"2": succRecord(t, u.alice, nil)}
	got, err := VerifyChain(in)
	if err != nil || len(got.Handovers) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

// The previous owner's key is the one the preceding record's ownerFp names,
// reached through their rotation chain as for an offer.
func TestVerifyChainSuccessorRecordUnderRotatedKey(t *testing.T) {
	u := newChainUsers(t)
	alice2 := newChainUser(t, u.alice.id, "-rotated")
	build := func(signer chainUser) ChainInput {
		f := newChain(t, u.alice, []Member{editor(u.bob)}, nil).
			add(alice2, func(b *MembershipBody) { b.OwnerFP = alice2.fp }).
			add(u.carol, newOwner(u.alice, u.carol, setHandover("admin")))
		in := f.input()
		in.Linked = func(user, from, to string) bool {
			return from == to || user == u.alice.id && from == u.alice.fp && to == alice2.fp
		}
		in.Successors = map[string]Envelope{"3": succRecord(t, signer, nil)}
		return in
	}
	if got, err := VerifyChain(build(alice2)); err != nil || len(got.Handovers) != 0 {
		t.Fatalf("signed under the current key: %v, %v", got, err)
	}
	if _, err := VerifyChain(build(u.alice)); !errors.Is(err, ErrChain) {
		t.Fatalf("signed under the key before the rotation: got %v, want ErrChain", err)
	}
}
