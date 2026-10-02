package e2e

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// ErrRotationFork means a rotation record at the seq the keyring pins hashes
// to another head, or two records share a seq and differ. A record that
// fails to parse is ErrFormat, and one whose signature fails is ErrDecrypt,
// as from OpenRotation; every other broken rule is ErrChain.
var ErrRotationFork = errors.New("e2e: rotation chain forked")

// RotationResult is where a rotation chain ends. FP, Seq, and Head are the
// fingerprint, seq, and body hash of the last record followed, for the
// keyring's pin; Keys are the public keys the chain ends at. When no record
// applies, FP, Seq, and Head are the pin's own (RotSeq and RotHead), so a
// caller that writes the result back into the pin changes nothing, and Keys
// is empty.
type RotationResult struct {
	FP   string
	Seq  int
	Head string
	Keys KeyPair
}

// keyPairFP returns the fingerprint of a key pair, or false when a key does
// not decode.
func keyPairFP(kp KeyPair) (string, bool) {
	x, errX := UnB64(kp.X25519)
	ed, errEd := UnB64(kp.Ed25519)
	if errX != nil || errEd != nil {
		return "", false
	}
	return hex.EncodeToString(Fingerprint(x, ed)), true
}

// FollowRotations follows user's rotation records, oldest first, from the
// key the pin names to the key the chain ends at, as design/e2e-wire-formats.md
// ("The keyring") requires. Records at or below pin.RotSeq were accepted
// already and are skipped, but the one at RotSeq must hash to RotHead
// (ErrRotationFork), and a list that omits it is ErrRollback: the server
// withheld a record the keyring pins. The chain starts at the first record
// whose old keys hash to the pin's fp; the records before it predate the
// pin. From there each record must be the user's, one seq above the last,
// rotate from the fp the last reached, and verify under both keys. A record
// for any other user is refused wherever it stands. Mirrors followRotations
// in internal/server/web/e2e.mjs.
func FollowRotations(user string, records []Envelope, pin Pin) (RotationResult, error) {
	res, _, err := followRotations(user, records, pin)
	return res, err
}

// followRotations is FollowRotations, and also returns each fingerprint the
// chain reached after the first, which RotationLinker reads.
func followRotations(user string, records []Envelope, pin Pin) (RotationResult, []string, error) {
	res := RotationResult{FP: pin.FP, Seq: pin.RotSeq, Head: pin.RotHead}
	var reached []string
	heads := map[int]string{}
	started := false
	for i, env := range records {
		var b RotationBody
		if err := DecodeStrict(env.Body, &b); err != nil {
			return RotationResult{}, nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		if b.User != user {
			return RotationResult{}, nil, fmt.Errorf("record %d: %w: rotation for user %q, not %q", i+1, ErrChain, b.User, user)
		}
		head := BodyHash(env.Body)
		if prior, ok := heads[b.Seq]; ok && prior != head {
			return RotationResult{}, nil, fmt.Errorf("record %d: %w: two records with seq %d", i+1, ErrRotationFork, b.Seq)
		}
		heads[b.Seq] = head
		if pin.RotSeq > 0 && b.Seq <= pin.RotSeq {
			if b.Seq == pin.RotSeq && head != pin.RotHead {
				return RotationResult{}, nil, fmt.Errorf("record %d: %w: seq %d is not the pinned record", i+1, ErrRotationFork, b.Seq)
			}
			continue
		}
		oldFP, ok := keyPairFP(b.Old)
		if !started && (!ok || oldFP != res.FP) {
			continue
		}
		started = true
		switch {
		case !ok || oldFP != res.FP:
			return RotationResult{}, nil, fmt.Errorf("record %d: %w: old keys are not the keys the chain reached", i+1, ErrChain)
		// With pin.RotSeq 0 the chain may start at any seq of 1 or more
		// whose old fp is the pin's, and this is deliberate. A pin first
		// taken after the user already rotated has rotSeq 0 (until step 7d
		// records the current rotSeq when pinning), and RotationLinker asks
		// from any point in the chain. The record is still signed by the
		// pinned key, and continuity is enforced from there.
		case res.Seq > 0 && b.Seq != res.Seq+1:
			return RotationResult{}, nil, fmt.Errorf("record %d: %w: seq %d does not follow the last accepted", i+1, ErrChain, b.Seq)
		case b.Seq < 1:
			return RotationResult{}, nil, fmt.Errorf("record %d: %w: seq %d", i+1, ErrChain, b.Seq)
		}
		oldPub, err := UnB64(b.Old.Ed25519)
		if err != nil {
			return RotationResult{}, nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		var opened RotationBody
		if err := OpenRotation(env, oldPub, &opened); err != nil {
			return RotationResult{}, nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		newFP, ok := keyPairFP(opened.New)
		if !ok {
			return RotationResult{}, nil, fmt.Errorf("record %d: %w: new keys do not decode", i+1, ErrFormat)
		}
		res = RotationResult{FP: newFP, Seq: opened.Seq, Head: head, Keys: opened.New}
		reached = append(reached, newFP)
	}
	if _, ok := heads[pin.RotSeq]; pin.RotSeq > 0 && !ok {
		return RotationResult{}, nil, fmt.Errorf("%w: the rotation record the keyring pins, seq %d, is missing", ErrRollback, pin.RotSeq)
	}
	return res, reached, nil
}

// RotationLinker returns the Linked hook of ChainInput: it reports whether
// user's rotation chain leads from fromFP to toFP, or from toFP to fromFP,
// as design/e2e-wire-formats.md allows "in either direction". Equal
// fingerprints are always linked. Only the records from fromFP onward are
// verified (the earlier ones are skipped unchecked), and a break or a bad
// record on that stretch links nothing, even a fingerprint reached before it.
func RotationLinker(rotations map[string][]Envelope) func(user, fromFP, toFP string) bool {
	leads := func(user, fromFP, toFP string) bool {
		_, reached, err := followRotations(user, rotations[user], Pin{FP: fromFP})
		if err != nil {
			return false
		}
		for _, fp := range reached {
			if fp == toFP {
				return true
			}
		}
		return false
	}
	return func(user, fromFP, toFP string) bool {
		return fromFP == toFP || leads(user, fromFP, toFP) || leads(user, toFP, fromFP)
	}
}
