package e2e

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// Sentinel errors for a membership chain the client refuses. A record that
// fails to parse is ErrFormat, and one whose signature fails is ErrDecrypt,
// as from OpenEnvelope; every other broken rule is ErrChain.
var (
	// ErrChain means a record breaks a chain rule: seq, prev, epoch,
	// akCommit, the member lists, the anchor, or a change of owner.
	ErrChain = errors.New("e2e: membership chain refused")
	// ErrRollback means the chain is shorter than the seq the keyring pins.
	ErrRollback = errors.New("e2e: membership chain rolled back")
	// ErrFork means the record at the pinned seq hashes to another head.
	ErrFork = errors.New("e2e: membership chain forked")
	// ErrStaleEpoch means an epoch below the highest one the keyring pins.
	ErrStaleEpoch = errors.New("e2e: epoch older than the pinned epoch")
	// ErrReusedAK means a new epoch's AK equals an earlier epoch's.
	ErrReusedAK = errors.New("e2e: AK reused from an earlier epoch")
)

// EpochPin is the keyring's epochs entry for one artifact: the highest
// epoch seen, and the seq and body hash of the latest record accepted.
type EpochPin struct {
	Epoch, Seq int
	Head       string
}

// ChainInput is what VerifyChain checks: the response of
// GET /api/artifacts/{id}/membership, and what the client already trusts.
type ChainInput struct {
	Artifact string
	// Records are the membership envelopes, oldest first.
	Records []Envelope
	// Owners maps a fingerprint to an owner's public keys. A pair that does
	// not hash to its fingerprint is ignored.
	Owners map[string]KeyPair
	// Offers maps a transfer body hash to the offer envelope.
	Offers map[string]Envelope
	// Successors maps the seq of an accepting record, as a string, to the
	// previous owner's latest successor record.
	Successors map[string]Envelope
	// Anchor is the fingerprint the first record's ownerFp must reach: the
	// client's pin for the creator, or a public link's o.
	Anchor string
	// CurrentOwnerFP, when set, is the fingerprint the latest record's
	// ownerFp must equal.
	CurrentOwnerFP string
	// Pin is the keyring's entry for the artifact, or nil on first sight.
	Pin *EpochPin
	// Linked reports whether user's rotation chain leads from fromFP to
	// toFP. Nil means the two must be equal.
	Linked func(user, fromFP, toFP string) bool
}

// Chain is a verified membership chain.
type Chain struct {
	Bodies []MembershipBody
	Latest MembershipBody
	// Head is the body hash of the latest record, for the keyring.
	Head string
	// Handovers are the seqs of the records that accept an administrator's
	// handover to anyone but the previous owner's nominated successor, for
	// the notice.
	Handovers []int
}

// VerifyChain checks every record of a membership chain, as the client
// rules in design/e2e-api.md ("Membership records" and "Ownership
// transfer") require, and refuses the whole chain when any check fails.
func VerifyChain(in ChainInput) (*Chain, error) {
	if len(in.Records) == 0 {
		return nil, fmt.Errorf("%w: no records", ErrChain)
	}
	linked := in.Linked
	if linked == nil {
		linked = func(_, fromFP, toFP string) bool { return fromFP == toFP }
	}
	owners := ownerKeys(in.Owners)
	c := &Chain{}
	for i, env := range in.Records {
		b, err := openRecord(env, in.Artifact, owners)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		if i == 0 {
			err = checkFirstRecord(b, in.Anchor, linked)
		} else {
			err = checkNextRecord(c, in, owners, linked, in.Records[i-1].Body, b)
		}
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		c.Bodies = append(c.Bodies, b)
	}
	c.Latest = c.Bodies[len(c.Bodies)-1]
	c.Head = BodyHash(in.Records[len(in.Records)-1].Body)
	if in.CurrentOwnerFP != "" && c.Latest.OwnerFP != in.CurrentOwnerFP {
		return nil, fmt.Errorf("%w: the latest record is not signed by the current owner's key", ErrChain)
	}
	if p := in.Pin; p != nil {
		if p.Seq < 1 {
			return nil, fmt.Errorf("%w: pinned seq %d", ErrFormat, p.Seq)
		}
		if len(in.Records) < p.Seq {
			return nil, fmt.Errorf("%w: %d records, pinned seq %d", ErrRollback, len(in.Records), p.Seq)
		}
		if BodyHash(in.Records[p.Seq-1].Body) != p.Head {
			return nil, fmt.Errorf("%w: record %d", ErrFork, p.Seq)
		}
		if c.Latest.Epoch < p.Epoch {
			return nil, fmt.Errorf("%w: latest epoch %d, pinned %d", ErrStaleEpoch, c.Latest.Epoch, p.Epoch)
		}
	}
	return c, nil
}

// ownerKeys keeps the Ed25519 key of each pair that hashes to its
// fingerprint, and drops the rest.
func ownerKeys(pairs map[string]KeyPair) map[string][]byte {
	keys := map[string][]byte{}
	for fp, kp := range pairs {
		x, errX := UnB64(kp.X25519)
		ed, errEd := UnB64(kp.Ed25519)
		if errX == nil && errEd == nil && hex.EncodeToString(Fingerprint(x, ed)) == fp {
			keys[fp] = ed
		}
	}
	return keys
}

// openRecord verifies one record under the key its ownerFp names, and
// checks the fields that do not depend on the record before it. The body is
// decoded strictly before the signature is checked, only to read ownerFp;
// OpenEnvelope then decodes the same bytes the same way, so the ownerFp it
// returns is the one whose key verified the record.
func openRecord(env Envelope, artifact string, owners map[string][]byte) (MembershipBody, error) {
	var b MembershipBody
	if err := DecodeStrict(env.Body, &b); err != nil {
		return b, err
	}
	pub, ok := owners[b.OwnerFP]
	if !ok {
		return b, fmt.Errorf("%w: no owner key for ownerFp %s", ErrChain, b.OwnerFP)
	}
	b = MembershipBody{}
	if err := OpenEnvelope(env, pub, "membership", &b); err != nil {
		return b, err
	}
	if b.Artifact != artifact {
		return b, fmt.Errorf("%w: record for artifact %q", ErrChain, b.Artifact)
	}
	if b.Members == nil || b.Excluded == nil {
		return b, fmt.Errorf("%w: members and excluded must be arrays", ErrChain)
	}
	if b.Team != "none" && b.Team != "viewer" && b.Team != "editor" {
		return b, fmt.Errorf("%w: team %q", ErrChain, b.Team)
	}
	if !isHex64(b.AKCommit) {
		return b, fmt.Errorf("%w: akCommit is not 64 lowercase hex digits", ErrChain)
	}
	for i := 1; i < len(b.Members); i++ {
		if b.Members[i-1].User >= b.Members[i].User {
			return b, fmt.Errorf("%w: members not sorted by user ID, or duplicated", ErrChain)
		}
	}
	for i := 1; i < len(b.Excluded); i++ {
		if b.Excluded[i-1].User >= b.Excluded[i].User {
			return b, fmt.Errorf("%w: excluded not sorted by user ID, or duplicated", ErrChain)
		}
	}
	for _, m := range b.Members {
		if m.User == b.Owner {
			return b, fmt.Errorf("%w: the owner is listed as a member", ErrChain)
		}
		if m.Role != "viewer" && m.Role != "editor" {
			return b, fmt.Errorf("%w: member %q has role %q", ErrChain, m.User, m.Role)
		}
		if !isHex64(m.FP) {
			return b, fmt.Errorf("%w: member %q fp is not 64 lowercase hex digits", ErrChain, m.User)
		}
		for _, e := range b.Excluded {
			if e.User == m.User || e.FP == m.FP {
				return b, fmt.Errorf("%w: excluded entry %q matches member %q", ErrChain, e.User, m.User)
			}
		}
	}
	for _, e := range b.Excluded {
		if e.User == b.Owner {
			return b, fmt.Errorf("%w: the owner is excluded", ErrChain)
		}
	}
	return b, nil
}

// isHex64 reports whether s is 64 lowercase hex digits: a SHA-256 hash or
// fingerprint in its one canonical form.
func isHex64(s string) bool {
	return len(s) == 64 && isLowerHex(s)
}

func checkFirstRecord(b MembershipBody, anchor string, linked func(user, fromFP, toFP string) bool) error {
	switch {
	case b.Seq != 1:
		return fmt.Errorf("%w: first record has seq %d", ErrChain, b.Seq)
	case b.Prev != "":
		return fmt.Errorf("%w: first record has a prev", ErrChain)
	case b.Epoch != 1:
		return fmt.Errorf("%w: first record has epoch %d", ErrChain, b.Epoch)
	case b.Transfer != "" || b.Handover != "":
		return fmt.Errorf("%w: first record sets transfer or handover", ErrChain)
	case !linked(b.Owner, anchor, b.OwnerFP):
		return fmt.Errorf("%w: first record's ownerFp does not reach the anchor", ErrChain)
	}
	return nil
}

// checkNextRecord checks b against the record before it, whose body bytes
// are prevBody, and notes an administrator's handover in c.
func checkNextRecord(c *Chain, in ChainInput, owners map[string][]byte, linked func(user, fromFP, toFP string) bool, prevBody []byte, b MembershipBody) error {
	prev := c.Bodies[len(c.Bodies)-1]
	prevHash := BodyHash(prevBody)
	if b.Seq != prev.Seq+1 {
		return fmt.Errorf("%w: seq %d follows %d", ErrChain, b.Seq, prev.Seq)
	}
	if b.Prev != prevHash {
		return fmt.Errorf("%w: prev is not the previous record's hash", ErrChain)
	}
	switch b.Epoch {
	case prev.Epoch:
		if b.AKCommit != prev.AKCommit {
			return fmt.Errorf("%w: akCommit changed within epoch %d", ErrChain, b.Epoch)
		}
	case prev.Epoch + 1:
		if b.AKCommit == prev.AKCommit {
			return fmt.Errorf("%w: epoch %d keeps the previous akCommit", ErrChain, b.Epoch)
		}
	default:
		return fmt.Errorf("%w: epoch %d follows %d", ErrChain, b.Epoch, prev.Epoch)
	}

	if b.Owner == prev.Owner {
		if b.Transfer != "" || b.Handover != "" {
			return fmt.Errorf("%w: transfer or handover set without a change of owner", ErrChain)
		}
		if !linked(b.Owner, prev.OwnerFP, b.OwnerFP) {
			return fmt.Errorf("%w: ownerFp does not follow from the previous record's", ErrChain)
		}
		return nil
	}

	if (b.Transfer == "") == (b.Handover == "") {
		return fmt.Errorf("%w: a change of owner sets exactly one of transfer and handover", ErrChain)
	}
	if b.Handover != "" && b.Handover != "admin" {
		return fmt.Errorf("%w: handover %q", ErrChain, b.Handover)
	}
	var listed *Member
	for i := range prev.Members {
		if prev.Members[i].User == b.Owner {
			listed = &prev.Members[i]
		}
	}
	if listed == nil {
		if b.Handover == "" {
			return fmt.Errorf("%w: the new owner is not listed in the previous record", ErrChain)
		}
		if err := checkSuccessor(in, owners, prev, b); err != nil {
			return fmt.Errorf("%w: a handover to a user the previous record does not list needs the previous owner's successor record: %v", ErrChain, err)
		}
		return nil
	}
	if listed.Role != "editor" {
		return fmt.Errorf("%w: the new owner is listed as %q, not editor", ErrChain, listed.Role)
	}
	if !linked(b.Owner, listed.FP, b.OwnerFP) {
		return fmt.Errorf("%w: ownerFp does not follow from the fp the previous record lists for the new owner", ErrChain)
	}
	if b.Handover != "" {
		if checkSuccessor(in, owners, prev, b) != nil {
			c.Handovers = append(c.Handovers, b.Seq)
		}
		return nil
	}

	offer, ok := in.Offers[b.Transfer]
	if !ok || BodyHash(offer.Body) != b.Transfer {
		return fmt.Errorf("%w: no offer hashes to transfer %s", ErrChain, b.Transfer)
	}
	var t TransferBody
	if err := OpenEnvelope(offer, owners[prev.OwnerFP], "transfer", &t); err != nil {
		return fmt.Errorf("offer: %w", err)
	}
	switch {
	case t.Artifact != in.Artifact:
		return fmt.Errorf("%w: offer for artifact %q", ErrChain, t.Artifact)
	case t.From != prev.Owner:
		return fmt.Errorf("%w: offer from %q, not the previous owner", ErrChain, t.From)
	case t.To != b.Owner:
		return fmt.Errorf("%w: offer to %q, not the new owner", ErrChain, t.To)
	case t.ToFP != listed.FP:
		return fmt.Errorf("%w: offer's toFp is not the fp listed for the new owner", ErrChain)
	case t.Prev != prevHash:
		return fmt.Errorf("%w: offer's prev is not the previous record's hash", ErrChain)
	}
	return nil
}

// checkSuccessor checks the successor record served for the handover b: it
// verifies under the previous owner's key, the one prev's ownerFp names, and
// nominates b's owner, under the fingerprint b lists for them.
func checkSuccessor(in ChainInput, owners map[string][]byte, prev, b MembershipBody) error {
	env, ok := in.Successors[strconv.Itoa(b.Seq)]
	if !ok {
		return errors.New("no successor record")
	}
	pub, ok := owners[prev.OwnerFP]
	if !ok {
		return errors.New("no key for the previous owner")
	}
	var s SuccessorBody
	if err := OpenEnvelope(env, pub, "successor", &s); err != nil {
		return fmt.Errorf("successor record: %w", err)
	}
	switch {
	case s.User != prev.Owner:
		return fmt.Errorf("successor record for %q, not the previous owner", s.User)
	case s.Successor != b.Owner:
		return fmt.Errorf("successor record names %q, not the new owner", s.Successor)
	case s.SuccessorFP != b.OwnerFP:
		return errors.New("successor record's successorFp is not the new owner's fingerprint")
	case s.Action != "nominate":
		return fmt.Errorf("successor record's action is %q", s.Action)
	}
	return nil
}

// CheckEncryptEpoch refuses to encrypt under an epoch older than the
// highest one the keyring pins. A nil pin allows any epoch.
func CheckEncryptEpoch(pin *EpochPin, epoch int) error {
	if pin != nil && epoch < pin.Epoch {
		return fmt.Errorf("%w: epoch %d, pinned %d", ErrStaleEpoch, epoch, pin.Epoch)
	}
	return nil
}

// CheckNewAK refuses a new epoch's AK that equals the AK of any earlier
// epoch. The akCommit check cannot show this, because the commitment
// includes the epoch.
func CheckNewAK(ak []byte, earlier [][]byte) error {
	if err := checkKeyLen(ak); err != nil {
		return err
	}
	for _, e := range earlier {
		if subtle.ConstantTimeCompare(ak, e) == 1 {
			return ErrReusedAK
		}
	}
	return nil
}
