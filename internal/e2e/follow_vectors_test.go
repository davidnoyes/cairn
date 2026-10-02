package e2e

import (
	"encoding/json"
	"errors"
	"testing"
)

// followPinVec is one user's current keys, the pin held for them (nil on
// first sight), and their rotation records, which FollowPin and followPin
// must both answer with the state and next pin in Want. When Want.Error is
// set, both also refuse with that error kind, and still report Want.State
// and Want.Next.
type followPinVec struct {
	Name    string          `json:"name"`
	Why     string          `json:"why"`
	User    string          `json:"user"`
	Pin     *Pin            `json:"pin"`
	Records []Envelope      `json:"records"`
	Keys    KeyPair         `json:"keys"`
	Want    followPinWanted `json:"want"`
}

type followPinWanted struct {
	State string `json:"state"`
	Next  Pin    `json:"next"`
	Error string `json:"error,omitempty"`
}

type followPinCase struct {
	name, why string
	// build returns the pin, the records, the user's current keys, and the
	// answer. The answer is written out from the case, never taken from
	// FollowPin.
	build func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted)
	err   error
}

// pinFor is the pin FollowPin stores for a new or changed key: unverified,
// at the record whose new keys are the current ones, if it verifies.
func pinFor(c chainUser, seq int, env Envelope) Pin {
	return Pin{FP: c.fp, State: PinUnverified, RotSeq: seq, RotHead: BodyHash(env.Body)}
}

func followPinCases() []followPinCase {
	chain3 := func(r rotGens) []Envelope {
		return []Envelope{r.rec(1, r.g[0], r.g[1]), r.rec(2, r.g[1], r.g[2]), r.rec(3, r.g[2], r.g[3])}
	}
	plain := func(c chainUser) Pin { return Pin{FP: c.fp, State: PinUnverified} }
	return []followPinCase{
		{name: "new-no-rotations", why: "no pin and no records: the pin starts at rotSeq 0",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				return nil, nil, r.g[0], followPinWanted{State: PinNew, Next: plain(r.g[0])}
			}},
		{name: "new-latest-record-matches", why: "no pin, and the latest record's new keys are the current ones: the pin starts at that record",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				recs := chain3(r)
				return nil, recs, r.g[3], followPinWanted{State: PinNew, Next: pinFor(r.g[3], 3, recs[2])}
			}},
		{name: "new-earlier-record-matches", why: "no pin, and the current keys are the ones record 2 made: the pin starts at record 2",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				recs := chain3(r)
				return nil, recs, r.g[2], followPinWanted{State: PinNew, Next: pinFor(r.g[2], 2, recs[1])}
			}},
		{name: "new-no-record-matches", why: "no pin, and no record's new keys are the current ones: rotSeq 0",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				return nil, chain3(r), r.g[4], followPinWanted{State: PinNew, Next: plain(r.g[4])}
			}},
		{name: "new-record-bad-newSig", why: "no pin, and the matching record is not signed by its new keys: rotSeq 0",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				bad := r.sign(r.body("u-bob", 1, r.g[0], r.g[1]), r.g[0].seed, r.m.seed)
				return nil, []Envelope{bad}, r.g[1], followPinWanted{State: PinNew, Next: plain(r.g[1])}
			}},
		{name: "new-record-bad-sig", why: "no pin, and the matching record is not signed by its old keys: rotSeq 0",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				bad := r.sign(r.body("u-bob", 1, r.g[0], r.g[1]), r.m.seed, r.g[1].seed)
				return nil, []Envelope{bad}, r.g[1], followPinWanted{State: PinNew, Next: plain(r.g[1])}
			}},
		{name: "new-record-of-another-user", why: "no pin, and the matching record is u-carol's: it explains nothing for u-bob",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				other := r.sign(r.body("u-carol", 1, r.g[0], r.g[1]), r.g[0].seed, r.g[1].seed)
				return nil, []Envelope{other}, r.g[1], followPinWanted{State: PinNew, Next: plain(r.g[1])}
			}},
		{name: "new-record-seq-zero", why: "no pin, and the matching record has seq 0, which the format never allows: rotSeq 0",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				return nil, []Envelope{r.rec(0, r.g[0], r.g[1])}, r.g[1], followPinWanted{State: PinNew, Next: plain(r.g[1])}
			}},
		{name: "matching-unverified", why: "the pin is the current key: its state stands, and the records are not read",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				p := plain(r.g[0])
				return &p, nil, r.g[0], followPinWanted{State: PinUnverified, Next: p}
			}},
		{name: "matching-verified", why: "a verified pin on the current key stays verified, with its rotSeq and rotHead, and bad records are not read",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				rec := r.rec(1, r.g[0], r.g[1])
				p := r.pinAt(r.g[1], 1, rec)
				return &p, []Envelope{r.sign(r.body("u-bob", 1, r.g[0], r.g[2]), r.m.seed, r.m.seed)}, r.g[1], followPinWanted{State: PinVerified, Next: p}
			}},
		{name: "rotated-one-step", why: "an unverified pin and one rotation to the current key: rotated, recorded at that record",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				recs := chain3(r)[:1]
				p := plain(r.g[0])
				return &p, recs, r.g[1], followPinWanted{State: PinRotated, Next: pinFor(r.g[1], 1, recs[0])}
			}},
		{name: "rotated-verified-drops", why: "a verified pin followed through three rotations becomes unverified, at the last record",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				recs := chain3(r)
				p := Pin{FP: r.g[0].fp, State: PinVerified}
				return &p, recs, r.g[3], followPinWanted{State: PinRotated, Next: pinFor(r.g[3], 3, recs[2])}
			}},
		{name: "rotated-from-rotSeq", why: "a pin accepted at record 1 follows records 2 and 3, and records the third",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				recs := chain3(r)
				p := r.pinAt(r.g[1], 1, recs[0])
				return &p, recs, r.g[3], followPinWanted{State: PinRotated, Next: pinFor(r.g[3], 3, recs[2])}
			}},
		{name: "fork", why: "the record at rotSeq hashes to another head: changed, and the fork is reported", err: ErrRotationFork,
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				recs := chain3(r)
				p := r.pinAt(r.g[1], 1, recs[0])
				p.RotHead = hex64("another head")
				return &p, recs, r.g[3], followPinWanted{State: PinChanged, Next: pinFor(r.g[3], 3, recs[2])}
			}},
		{name: "fork-two-records-at-a-seq", why: "the user signed two different records 2: changed, and the fork is reported", err: ErrRotationFork,
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				recs := chain3(r)
				p := r.pinAt(r.g[1], 1, recs[0])
				return &p, []Envelope{recs[0], recs[1], r.rec(2, r.g[1], r.g[4])}, r.g[2], followPinWanted{State: PinChanged, Next: pinFor(r.g[2], 2, recs[1])}
			}},
		{name: "rollback", why: "the records omit the one at rotSeq: changed, and the rollback is reported", err: ErrRollback,
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				recs := chain3(r)
				p := r.pinAt(r.g[1], 1, recs[0])
				return &p, recs[1:], r.g[3], followPinWanted{State: PinChanged, Next: pinFor(r.g[3], 3, recs[2])}
			}},
		{name: "rollback-no-records", why: "rotSeq is 1 and no records are served: changed, and the rollback is reported; the next pin has rotSeq 0", err: ErrRollback,
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				p := r.pinAt(r.g[1], 1, r.rec(1, r.g[0], r.g[1]))
				return &p, nil, r.g[2], followPinWanted{State: PinChanged, Next: plain(r.g[2])}
			}},
		{name: "broken-chain", why: "record 2 is skipped past, so the chain breaks: no error, but the chain explains nothing and the key is changed",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				skip := r.rec(3, r.g[1], r.g[2])
				p := plain(r.g[0])
				return &p, []Envelope{r.rec(1, r.g[0], r.g[1]), skip}, r.g[2], followPinWanted{State: PinChanged, Next: pinFor(r.g[2], 3, skip)}
			}},
		{name: "bad-signature-in-chain", why: "record 2 is signed by other keys: changed with no error, and the next pin is at rotSeq 0 because its record does not verify",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				bad := r.sign(r.body("u-bob", 2, r.g[1], r.g[2]), r.m.seed, r.g[2].seed)
				p := plain(r.g[0])
				return &p, []Envelope{r.rec(1, r.g[0], r.g[1]), bad}, r.g[2], followPinWanted{State: PinChanged, Next: plain(r.g[2])}
			}},
		{name: "chain-ends-elsewhere", why: "the chain ends at gen 2 and the current keys are gen 4, as after a password-only reset: changed",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				p := plain(r.g[0])
				return &p, chain3(r)[:2], r.g[4], followPinWanted{State: PinChanged, Next: plain(r.g[4])}
			}},
		{name: "chain-older-than-the-pin", why: "every record predates the pin, and the current key is none of them: changed",
			build: func(r rotGens) (*Pin, []Envelope, chainUser, followPinWanted) {
				p := plain(r.g[3])
				return &p, chain3(r), r.g[4], followPinWanted{State: PinChanged, Next: plain(r.g[4])}
			}},
	}
}

func followPinVectors(t testing.TB) []followPinVec {
	t.Helper()
	r := newRotGens(t)
	var vs []followPinVec
	for _, c := range followPinCases() {
		pin, recs, cur, want := c.build(r)
		if recs == nil {
			recs = []Envelope{}
		}
		if c.err != nil {
			want.Error = rotationErrorKind(t, c.err)
		}
		vs = append(vs, followPinVec{Name: c.name, Why: c.why, User: "u-bob", Pin: pin, Records: recs, Keys: cur.keys, Want: want})
	}
	return vs
}

func checkFollowPinVectors(t *testing.T, vs []followPinVec) {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []followPinVec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, v := range parsed {
		x, errX := UnB64(v.Keys.X25519)
		ed, errEd := UnB64(v.Keys.Ed25519)
		if errX != nil || errEd != nil {
			t.Fatalf("%s: keys do not decode", v.Name)
		}
		state, next, err := FollowPin(v.User, v.Pin, v.Records, x, ed)
		if state != v.Want.State || next != v.Want.Next {
			t.Errorf("%s (%s): got %s %+v, want %s %+v", v.Name, v.Why, state, next, v.Want.State, v.Want.Next)
		}
		if v.Want.Error != "" {
			if want, ok := rotationErrorKinds[v.Want.Error]; !ok || !errors.Is(err, want) {
				t.Errorf("%s (%s): err = %v, want %s", v.Name, v.Why, err, v.Want.Error)
			}
		} else if err != nil {
			t.Errorf("%s (%s): err = %v", v.Name, v.Why, err)
		}
	}
}

// A fork is not a chain error, so a caller that tells the two apart raises
// the hard warning for it alone.
func TestFollowPinForkIsNotAChainError(t *testing.T) {
	for _, c := range followPinCases() {
		if c.err == nil {
			continue
		}
		r := newRotGens(t)
		pin, recs, cur, _ := c.build(r)
		x, _ := UnB64(cur.keys.X25519)
		ed, _ := UnB64(cur.keys.Ed25519)
		_, _, err := FollowPin("u-bob", pin, recs, x, ed)
		if !errors.Is(err, c.err) || errors.Is(err, ErrChain) {
			t.Errorf("%s: err = %v, want %v and not ErrChain", c.name, err, c.err)
		}
	}
}

// FollowPin never edits the pin it is given.
func TestFollowPinLeavesThePinAlone(t *testing.T) {
	r := newRotGens(t)
	recs := []Envelope{r.rec(1, r.g[0], r.g[1])}
	p := Pin{FP: r.g[0].fp, State: PinVerified}
	x, _ := UnB64(r.g[1].keys.X25519)
	ed, _ := UnB64(r.g[1].keys.Ed25519)
	if _, _, err := FollowPin("u-bob", &p, recs, x, ed); err != nil {
		t.Fatal(err)
	}
	if p != (Pin{FP: r.g[0].fp, State: PinVerified}) {
		t.Errorf("pin = %+v", p)
	}
}
