package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

// rotationChainVec is one user's rotation records and the pin held for them,
// which FollowRotations and followRotations must both accept, with the
// result in Want, or both refuse with the error kind in Error. Records are
// in the wire form the server serves, oldest first.
type rotationChainVec struct {
	Name    string           `json:"name"`
	Why     string           `json:"why"`
	User    string           `json:"user"`
	Records []Envelope       `json:"records"`
	Pin     Pin              `json:"pin"`
	Want    *rotationWantVec `json:"want,omitempty"`
	Error   string           `json:"error,omitempty"`
}

type rotationWantVec struct {
	FP   string  `json:"fp"`
	Seq  int     `json:"seq"`
	Head string  `json:"head"`
	Keys KeyPair `json:"keys"`
}

// rotationLinkVec is one question for RotationLinker and rotationLinker:
// does the user's rotation chain lead from From to To, in either direction.
type rotationLinkVec struct {
	Name      string                `json:"name"`
	Why       string                `json:"why"`
	Rotations map[string][]Envelope `json:"rotations"`
	User      string                `json:"user"`
	From      string                `json:"from"`
	To        string                `json:"to"`
	Want      bool                  `json:"want"`
}

// rotationErrorKinds names each sentinel FollowRotations returns, as the
// rotationChain section spells it.
var rotationErrorKinds = map[string]error{
	"chain":        ErrChain,
	"rotationFork": ErrRotationFork,
	"format":       ErrFormat,
	"decrypt":      ErrDecrypt,
	"rollback":     ErrRollback,
}

func rotationErrorKind(t testing.TB, err error) string {
	t.Helper()
	for kind, sentinel := range rotationErrorKinds {
		if sentinel == err {
			return kind
		}
	}
	t.Fatalf("no error kind for %v", err)
	return ""
}

// rotGens are the key generations of u-bob, and one stranger's keys.
type rotGens struct {
	t testing.TB
	g [6]chainUser
	m chainUser
}

func newRotGens(t testing.TB) rotGens {
	r := rotGens{t: t, m: newChainUser(t, "u-mallory", "")}
	for i := range r.g {
		r.g[i] = newChainUser(t, "u-bob", fmt.Sprintf("-gen%d", i))
	}
	return r
}

// body is the rotation body for seq, from old to new.
func (r rotGens) body(user string, seq int, old, new chainUser) RotationBody {
	return RotationBody{V: 1, User: user, Seq: seq, Old: old.keys, New: new.keys}
}

// sign signs b with oldSeed and newSeed, as SignRotation does.
func (r rotGens) sign(b RotationBody, oldSeed, newSeed []byte) Envelope {
	r.t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		r.t.Fatal(err)
	}
	env, err := SignRotation(oldSeed, newSeed, raw, b.User)
	if err != nil {
		r.t.Fatal(err)
	}
	return env
}

// rec is a correct rotation of u-bob from old to new.
func (r rotGens) rec(seq int, old, new chainUser) Envelope {
	r.t.Helper()
	return r.sign(r.body("u-bob", seq, old, new), old.seed, new.seed)
}

// pin is the pin for a user who has not rotated since it was taken.
func (r rotGens) pin(c chainUser) Pin { return Pin{FP: c.fp, State: PinUnverified} }

// pinAt is the pin after accepting env as rotation seq, which ended at c.
func (r rotGens) pinAt(c chainUser, seq int, env Envelope) Pin {
	return Pin{FP: c.fp, State: PinVerified, RotSeq: seq, RotHead: BodyHash(env.Body)}
}

type rotationCase struct {
	name, why string
	build     func(r rotGens) ([]Envelope, Pin)
	err       error
	// ends is the index of the last record followed, or -1 when none
	// applies; fp is the key generation the chain ends at.
	ends int
	fp   int
	// seq is the seq of that record, when it is not ends+1.
	seq int
}

func rotationCases() []rotationCase {
	chain3 := func(r rotGens) []Envelope {
		return []Envelope{r.rec(1, r.g[0], r.g[1]), r.rec(2, r.g[1], r.g[2]), r.rec(3, r.g[2], r.g[3])}
	}
	return []rotationCase{
		{name: "no-rotation", why: "no records: the pin stands, and nothing applies", ends: -1,
			build: func(r rotGens) ([]Envelope, Pin) { return nil, r.pin(r.g[0]) }},
		{name: "one", why: "one rotation from the pinned key", ends: 0, fp: 1,
			build: func(r rotGens) ([]Envelope, Pin) { return chain3(r)[:1], r.pin(r.g[0]) }},
		{name: "three-in-a-row", why: "three rotations from the pinned key, followed to the end", ends: 2, fp: 3,
			build: func(r rotGens) ([]Envelope, Pin) { return chain3(r), r.pin(r.g[0]) }},
		{name: "pin-taken-mid-chain", why: "the pin was taken at gen 2 with rotSeq 0; the first two records predate it and are skipped", ends: 2, fp: 3,
			build: func(r rotGens) ([]Envelope, Pin) { return chain3(r), r.pin(r.g[2]) }},
		{name: "only-older-rotations", why: "every record predates the pin, so none applies", ends: -1,
			build: func(r rotGens) ([]Envelope, Pin) { return chain3(r), r.pin(r.g[3]) }},
		{name: "accepted-records-skipped", why: "rotSeq 1 with the matching head: record 1 was accepted and is skipped, 2 and 3 are followed", ends: 2, fp: 3,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				return recs, r.pinAt(r.g[1], 1, recs[0])
			}},
		{name: "all-accepted", why: "rotSeq 3 with the matching head: the replay of every record is skipped and none applies", ends: -1,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				return recs, r.pinAt(r.g[3], 3, recs[2])
			}},
		{name: "identical-duplicate-skipped", why: "a record served twice, both already accepted, is no fork", ends: -1,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				return []Envelope{recs[0], recs[0]}, r.pinAt(r.g[1], 1, recs[0])
			}},

		{name: "unsorted-records-skipped", why: "records served newest first: record 2 does not rotate from the pin's key, so it is skipped as before the chain, and record 1 starts the chain and ends it", ends: 1, fp: 1, seq: 1,
			build: func(r rotGens) ([]Envelope, Pin) {
				return []Envelope{r.rec(2, r.g[1], r.g[2]), r.rec(1, r.g[0], r.g[1])}, r.pin(r.g[0])
			}},

		{name: "fork-against-empty-rotHead", why: "rotSeq 1 with an empty rotHead: no record hashes to it", err: ErrRotationFork,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				p := r.pinAt(r.g[1], 1, recs[0])
				p.RotHead = ""
				return recs[:1], p
			}},
		{name: "fork-above-rotSeq", why: "rotSeq is 1, and the user signed two different records 2", err: ErrRotationFork,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				return []Envelope{recs[0], recs[1], r.rec(2, r.g[1], r.g[4])}, r.pinAt(r.g[1], 1, recs[0])
			}},
		{name: "fork-below-rotSeq", why: "rotSeq is 2, and two different records 1 stand below it", err: ErrRotationFork,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				return []Envelope{recs[0], r.rec(1, r.g[0], r.g[4]), recs[1]}, r.pinAt(r.g[2], 2, recs[1])
			}},
		{name: "rollback-no-records", why: "rotSeq is 1 and the server serves no records: the pinned record is withheld", err: ErrRollback,
			build: func(r rotGens) ([]Envelope, Pin) {
				return nil, r.pinAt(r.g[1], 1, r.rec(1, r.g[0], r.g[1]))
			}},
		{name: "rollback-pinned-record-omitted", why: "rotSeq is 1 and the records skip it and start at 2", err: ErrRollback,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				return recs[1:], r.pinAt(r.g[1], 1, recs[0])
			}},
		{name: "old-keys-do-not-decode", why: "record 2, inside a started chain, has old keys that are not base64", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				first := r.rec(1, r.g[0], r.g[1])
				b := r.body("u-bob", 2, r.g[1], r.g[2])
				b.Old = KeyPair{X25519: "!!!", Ed25519: "!!!"}
				return []Envelope{first, r.sign(b, r.g[1].seed, r.g[2].seed)}, r.pin(r.g[0])
			}},

		{name: "fork-against-rotHead", why: "the record at rotSeq hashes to something other than rotHead", err: ErrRotationFork,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				p := r.pinAt(r.g[1], 1, recs[0])
				p.RotHead = hex64("another head")
				return recs, p
			}},
		{name: "fork-by-another-record-at-rotSeq", why: "the user signed a second record 2 with other new keys; the pin holds the first", err: ErrRotationFork,
			build: func(r rotGens) ([]Envelope, Pin) {
				recs := chain3(r)
				other := r.rec(2, r.g[1], r.g[4])
				return []Envelope{recs[0], other}, r.pinAt(r.g[2], 2, recs[1])
			}},
		{name: "duplicate-seq", why: "two records with seq 1 and different bodies", err: ErrRotationFork,
			build: func(r rotGens) ([]Envelope, Pin) {
				return []Envelope{r.rec(1, r.g[0], r.g[1]), r.rec(1, r.g[0], r.g[4])}, r.pin(r.g[0])
			}},
		{name: "skipped-seq", why: "seq 3 follows seq 1", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				return []Envelope{r.rec(1, r.g[0], r.g[1]), r.rec(3, r.g[1], r.g[2])}, r.pin(r.g[0])
			}},
		{name: "first-record-skips-past-rotSeq", why: "rotSeq is 1, and the first record followed has seq 3", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				first := r.rec(1, r.g[0], r.g[1])
				return []Envelope{first, r.rec(3, r.g[1], r.g[2])}, r.pinAt(r.g[1], 1, first)
			}},
		{name: "seq-goes-down", why: "seq 1 follows seq 2", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				return []Envelope{r.rec(2, r.g[0], r.g[1]), r.rec(1, r.g[1], r.g[2])}, r.pin(r.g[0])
			}},
		{name: "seq-zero", why: "a first record with seq 0", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				return []Envelope{r.rec(0, r.g[0], r.g[1])}, r.pin(r.g[0])
			}},
		{name: "record-repeated-in-chain", why: "the first record served again where the second belongs", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				first := r.rec(1, r.g[0], r.g[1])
				return []Envelope{first, first}, r.pin(r.g[0])
			}},
		{name: "old-does-not-match", why: "record 2 rotates from keys that are not where record 1 ended", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				return []Envelope{r.rec(1, r.g[0], r.g[1]), r.rec(2, r.g[4], r.g[2])}, r.pin(r.g[0])
			}},
		{name: "bad-sig", why: "record 2 is signed by keys other than its old keys", err: ErrDecrypt,
			build: func(r rotGens) ([]Envelope, Pin) {
				bad := r.sign(r.body("u-bob", 2, r.g[1], r.g[2]), r.m.seed, r.g[2].seed)
				return []Envelope{r.rec(1, r.g[0], r.g[1]), bad}, r.pin(r.g[0])
			}},
		{name: "bad-newSig", why: "record 1 is not signed by its new keys", err: ErrDecrypt,
			build: func(r rotGens) ([]Envelope, Pin) {
				bad := r.sign(r.body("u-bob", 1, r.g[0], r.g[1]), r.g[0].seed, r.m.seed)
				return []Envelope{bad}, r.pin(r.g[0])
			}},
		{name: "missing-newSig", why: "record 1 has no newSig", err: ErrFormat,
			build: func(r rotGens) ([]Envelope, Pin) {
				bad := r.rec(1, r.g[0], r.g[1])
				bad.NewSig = nil
				return []Envelope{bad}, r.pin(r.g[0])
			}},
		{name: "wrong-user-in-chain", why: "record 2 is for another user, signed by the right keys", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				other := r.sign(r.body("u-carol", 2, r.g[1], r.g[2]), r.g[1].seed, r.g[2].seed)
				return []Envelope{r.rec(1, r.g[0], r.g[1]), other}, r.pin(r.g[0])
			}},
		{name: "wrong-user-before-chain", why: "a record for another user ahead of the chain, which would otherwise be skipped", err: ErrChain,
			build: func(r rotGens) ([]Envelope, Pin) {
				other := r.sign(r.body("u-carol", 1, r.m, r.g[4]), r.m.seed, r.g[4].seed)
				return []Envelope{other, r.rec(1, r.g[0], r.g[1])}, r.pin(r.g[0])
			}},
		{name: "unknown-body-field", why: "a body with a field the format does not declare", err: ErrFormat,
			build: func(r rotGens) ([]Envelope, Pin) {
				raw, err := json.Marshal(r.body("u-bob", 1, r.g[0], r.g[1]))
				if err != nil {
					r.t.Fatal(err)
				}
				raw = append(raw[:len(raw)-1], []byte(`,"extra":1}`)...)
				env, err := SignRotation(r.g[0].seed, r.g[1].seed, raw, "u-bob")
				if err != nil {
					r.t.Fatal(err)
				}
				return []Envelope{env}, r.pin(r.g[0])
			}},
	}
}

func rotationChainVectors(t testing.TB) []rotationChainVec {
	t.Helper()
	r := newRotGens(t)
	var vs []rotationChainVec
	for _, c := range rotationCases() {
		recs, pin := c.build(r)
		if recs == nil {
			recs = []Envelope{}
		}
		v := rotationChainVec{Name: c.name, Why: c.why, User: "u-bob", Records: recs, Pin: pin}
		switch {
		case c.err != nil:
			v.Error = rotationErrorKind(t, c.err)
		case c.ends < 0:
			v.Want = &rotationWantVec{FP: pin.FP, Seq: pin.RotSeq, Head: pin.RotHead}
		default:
			// Want comes from the case and the records, never from
			// FollowRotations.
			end := r.g[c.fp]
			seq := c.ends + 1
			if c.seq > 0 {
				seq = c.seq
			}
			v.Want = &rotationWantVec{FP: end.fp, Seq: seq, Head: BodyHash(recs[c.ends].Body), Keys: end.keys}
		}
		vs = append(vs, v)
	}
	return vs
}

func checkRotationChainVectors(t *testing.T, vs []rotationChainVec) {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []rotationChainVec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, v := range parsed {
		got, err := FollowRotations(v.User, v.Records, v.Pin)
		if v.Error != "" {
			if want, ok := rotationErrorKinds[v.Error]; !ok || !errors.Is(err, want) {
				t.Errorf("%s (%s): got %v, want %s", v.Name, v.Why, err, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s (%s): %v", v.Name, v.Why, err)
			continue
		}
		if got.FP != v.Want.FP || got.Seq != v.Want.Seq || got.Head != v.Want.Head || got.Keys != v.Want.Keys {
			t.Errorf("%s (%s): got %+v, want %+v", v.Name, v.Why, got, *v.Want)
		}
	}
}

func rotationLinkVectors(t testing.TB) []rotationLinkVec {
	t.Helper()
	r := newRotGens(t)
	good := []Envelope{r.rec(1, r.g[0], r.g[1]), r.rec(2, r.g[1], r.g[2]), r.rec(3, r.g[2], r.g[3])}
	badSig := r.sign(r.body("u-bob", 3, r.g[2], r.g[3]), r.m.seed, r.g[3].seed)
	skip := []Envelope{good[0], r.rec(3, r.g[1], r.g[2])}
	other := r.sign(r.body("u-carol", 2, r.g[1], r.g[2]), r.g[1].seed, r.g[2].seed)
	bob := func(recs []Envelope) map[string][]Envelope { return map[string][]Envelope{"u-bob": recs} }
	vec := func(name, why string, rot map[string][]Envelope, user string, from, to chainUser, want bool) rotationLinkVec {
		return rotationLinkVec{Name: name, Why: why, Rotations: rot, User: user, From: from.fp, To: to.fp, Want: want}
	}
	return []rotationLinkVec{
		vec("same-fp", "equal fingerprints link with no rotations at all", map[string][]Envelope{}, "u-bob", r.g[0], r.g[0], true),
		vec("forward", "the chain leads from gen 0 to gen 3", bob(good), "u-bob", r.g[0], r.g[3], true),
		vec("forward-one-step", "the chain leads from gen 0 to gen 1", bob(good), "u-bob", r.g[0], r.g[1], true),
		vec("forward-from-the-middle", "following from gen 1 skips record 1 and reaches gen 3", bob(good), "u-bob", r.g[1], r.g[3], true),
		vec("reverse", "either direction: gen 3 is linked to gen 0, which its chain leads back to", bob(good), "u-bob", r.g[3], r.g[0], true),
		vec("reverse-one-step", "either direction: gen 2 is linked to gen 1", bob(good), "u-bob", r.g[2], r.g[1], true),
		vec("unrelated-fp", "a fingerprint no record names", bob(good), "u-bob", r.g[0], r.m, false),
		vec("not-on-the-chain", "gen 4 appears in no record", bob(good), "u-bob", r.g[4], r.g[0], false),
		vec("other-user", "the records belong to u-bob, and the question is about u-carol", bob(good), "u-carol", r.g[0], r.g[3], false),
		vec("broken-chain-after-the-target", "toFP is reached at record 1, but record 2 breaks the chain, so no link", bob(skip), "u-bob", r.g[0], r.g[1], false),
		vec("bad-signature-after-the-target", "toFP is reached at record 2, but record 3 is badly signed, so no link", bob([]Envelope{good[0], good[1], badSig}), "u-bob", r.g[0], r.g[2], false),
		vec("reverse-across-a-broken-chain", "gen 2 to gen 0 with record 2 skipped past: record 3 does not follow, so no link", bob(skip), "u-bob", r.g[2], r.g[0], false),
		vec("wrong-user-record-in-the-list", "a record for u-carol among u-bob's records refuses the whole list", bob([]Envelope{good[0], other, good[2]}), "u-bob", r.g[0], r.g[1], false),
		vec("fork-in-the-list", "two different records with seq 1 refuse the list, even though gen 1 is reached", bob([]Envelope{good[0], r.rec(1, r.g[0], r.g[4])}), "u-bob", r.g[0], r.g[1], false),
		vec("no-records", "different fingerprints and no records", map[string][]Envelope{}, "u-bob", r.g[0], r.g[1], false),
	}
}

func checkRotationLinkVectors(t *testing.T, vs []rotationLinkVec) {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []rotationLinkVec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, v := range parsed {
		if got := RotationLinker(v.Rotations)(v.User, v.From, v.To); got != v.Want {
			t.Errorf("%s (%s): linked = %v, want %v", v.Name, v.Why, got, v.Want)
		}
	}
}
