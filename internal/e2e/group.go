package e2e

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Limits of a group record, from design/e2e-wire-formats.md ("Signatures").
const (
	maxGroupMembers  = 1000
	maxGroupNameLen  = 100 // code points
	groupRoleManager = "manager"
	groupRoleMember  = "member"
)

// GroupMember is one entry of a group record: the user, the fingerprint the
// signer saw for them, and their role, manager or member.
type GroupMember struct {
	User string `json:"user"`
	FP   string `json:"fp"`
	Role string `json:"role"`
}

// GroupBody is signed by a manager of the group: the creator for the first
// record, and for each later one a manager the record before lists. Signer
// and SignerFP name that manager and the key that signed.
type GroupBody struct {
	V        int           `json:"v"`
	Group    string        `json:"group"`
	Seq      int           `json:"seq"`
	Prev     string        `json:"prev"`
	Name     string        `json:"name"`
	Members  []GroupMember `json:"members"`
	Signer   string        `json:"signer"`
	SignerFP string        `json:"signerFp"`
}

// GroupKey is the public keys of a user who may have signed a group record.
// User is the account they belong to: a record is accepted under a key only
// when its signer is that user.
type GroupKey struct {
	User string `json:"user"`
	KeyPair
}

// GroupRuleError is a refusal of VerifyGroupChain that names the rule it
// broke, a short stable key the vectors carry. It wraps the error kind
// (ErrChain, ErrFormat, and so on), so errors.Is still answers for the kind.
type GroupRuleError struct {
	Rule string
	Err  error
}

func (e *GroupRuleError) Error() string { return e.Err.Error() }
func (e *GroupRuleError) Unwrap() error { return e.Err }

// GroupRule returns the rule err names, or "" when it names none.
func GroupRule(err error) string {
	var re *GroupRuleError
	if errors.As(err, &re) {
		return re.Rule
	}
	return ""
}

// ruled wraps err, a failure of rule, as a *GroupRuleError.
func ruled(rule string, err error) error { return &GroupRuleError{Rule: rule, Err: err} }

// GroupPin is the keyring's groups entry for one group: the seq of the
// latest record accepted, and the hash of its body.
type GroupPin struct {
	Seq  int    `json:"seq"`
	Head string `json:"head"`
}

// GroupInput is what VerifyGroupChain checks: the answer of
// GET /api/groups/{id}, and what the client already trusts.
type GroupInput struct {
	// Group is the group ID the client asked for, which every record names.
	Group string
	// Records are the group envelopes, oldest first.
	Records []Envelope
	// Keys maps a fingerprint to the public keys of a manager who signed a
	// record, and the user they belong to. A pair that does not hash to its
	// fingerprint is ignored.
	Keys map[string]GroupKey
	// Pin is the keyring's entry for the group, or nil on first sight.
	Pin *GroupPin
	// Linked reports whether user's rotation chain leads from fromFP to
	// toFP. Nil means the two must be equal.
	Linked func(user, fromFP, toFP string) bool
}

// GroupChain is a verified group chain.
type GroupChain struct {
	Bodies []GroupBody
	Latest GroupBody
	// Head is the body hash of the latest record, for the keyring.
	Head string
}

// VerifyGroupChain checks every record of a group's chain, as the client
// rules in design/e2e-api.md ("Group records") require, and refuses the
// whole chain when any check fails. The first record is signed by a manager
// it lists, under the fingerprint it lists. Each later record is signed by a
// manager the record before lists, under that fingerprint or one their
// rotation chain links to it. The chain must then reach the keyring's pin:
// a shorter chain is ErrRollback, and one whose record at the pinned seq
// hashes to another head is ErrFork. A record is accepted only under a key
// whose user is its signer. Every refusal is a *GroupRuleError.
func VerifyGroupChain(in GroupInput) (*GroupChain, error) {
	if len(in.Records) == 0 {
		return nil, ruled("no-records", fmt.Errorf("%w: no group records", ErrChain))
	}
	linked := in.Linked
	if linked == nil {
		linked = func(_, fromFP, toFP string) bool { return fromFP == toFP }
	}
	keys := groupOwnerKeys(in.Keys)
	c := &GroupChain{}
	for i, env := range in.Records {
		b, err := openGroupRecord(env, in.Group, keys)
		if err != nil {
			return nil, fmt.Errorf("group record %d: %w", i+1, err)
		}
		if i == 0 {
			err = checkFirstGroupRecord(b)
		} else {
			err = checkNextGroupRecord(c.Bodies[i-1], BodyHash(in.Records[i-1].Body), b, linked)
		}
		if err != nil {
			return nil, fmt.Errorf("group record %d: %w", i+1, err)
		}
		c.Bodies = append(c.Bodies, b)
	}
	c.Latest = c.Bodies[len(c.Bodies)-1]
	c.Head = BodyHash(in.Records[len(in.Records)-1].Body)
	if p := in.Pin; p != nil {
		if p.Seq < 1 {
			return nil, ruled("pin-seq-invalid", fmt.Errorf("%w: pinned seq %d", ErrFormat, p.Seq))
		}
		if len(in.Records) < p.Seq {
			return nil, ruled("pin-rolled-back", fmt.Errorf("%w: %d group records, pinned seq %d", ErrRollback, len(in.Records), p.Seq))
		}
		if BodyHash(in.Records[p.Seq-1].Body) != p.Head {
			return nil, ruled("pin-forked", fmt.Errorf("%w: group record %d", ErrFork, p.Seq))
		}
	}
	return c, nil
}

// groupSignerKey is a key a group record may be signed under, with its owner.
type groupSignerKey struct {
	user string
	ed   []byte
}

// groupOwnerKeys keeps the Ed25519 key of each pair that hashes to its
// fingerprint, with its user, and drops the rest.
func groupOwnerKeys(in map[string]GroupKey) map[string]groupSignerKey {
	pairs := make(map[string]KeyPair, len(in))
	for fp, k := range in {
		pairs[fp] = k.KeyPair
	}
	keys := map[string]groupSignerKey{}
	for fp, ed := range ownerKeys(pairs) {
		keys[fp] = groupSignerKey{user: in[fp].User, ed: ed}
	}
	return keys
}

// openGroupRecord verifies one record under the key its signerFp names, which
// must belong to the record's signer, and checks the fields that do not
// depend on the record before it. The body is decoded strictly before the
// signature is checked, only to read the fingerprint; OpenEnvelope then
// decodes the same bytes the same way.
func openGroupRecord(env Envelope, group string, keys map[string]groupSignerKey) (GroupBody, error) {
	var b GroupBody
	if err := DecodeStrict(env.Body, &b); err != nil {
		return b, ruled("body-format", err)
	}
	key, ok := keys[b.SignerFP]
	if !ok {
		return b, ruled("signer-key-missing", fmt.Errorf("%w: no signer key for fingerprint %s", ErrChain, b.SignerFP))
	}
	if key.user != b.Signer {
		return b, ruled("signer-key-of-another-user", fmt.Errorf("%w: the key for fingerprint %s belongs to %q, not the record's signer %q", ErrChain, b.SignerFP, key.user, b.Signer))
	}
	b = GroupBody{}
	if err := OpenEnvelope(env, key.ed, "group", &b); err != nil {
		if errors.Is(err, ErrDecrypt) {
			return b, ruled("signature", err)
		}
		return b, ruled("body-version", err)
	}
	switch {
	case env.Signer != b.Signer:
		return b, ruled("envelope-signer-differs", fmt.Errorf("%w: the envelope's signer %q is not the body's signer %q", ErrChain, env.Signer, b.Signer))
	case !isUUID(b.Group):
		return b, ruled("group-id-not-uuid", fmt.Errorf("%w: group %q is not a lowercase UUID", ErrChain, b.Group))
	case b.Group != group:
		return b, ruled("group-id-differs", fmt.Errorf("%w: record for group %q, not %q", ErrChain, b.Group, group))
	}
	return b, CheckGroupBody(b)
}

// CheckGroupBody refuses a body whose name or member list breaks the rules
// in design/e2e-wire-formats.md ("Signatures"). It checks nothing that
// depends on another record: the server runs it on the record it is sent.
func CheckGroupBody(b GroupBody) error {
	if err := checkGroupName(b.Name); err != nil {
		return err
	}
	return checkGroupMembers(b.Members)
}

// checkGroupName refuses a name that is not 1 to 100 code points, or holds a
// control character: the C0 characters, U+007F, and the C1 characters.
func checkGroupName(name string) error {
	switch n := utf8.RuneCountInString(name); {
	case n < 1:
		return ruled("name-empty", fmt.Errorf("%w: group name is %d code points, want 1 to %d", ErrChain, n, maxGroupNameLen))
	case n > maxGroupNameLen:
		return ruled("name-too-long", fmt.Errorf("%w: group name is %d code points, want 1 to %d", ErrChain, n, maxGroupNameLen))
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return ruled("name-control-character", fmt.Errorf("%w: group name holds the control character U+%04X", ErrChain, r))
		}
	}
	return nil
}

// checkGroupMembers refuses a member list that is not 1 to 1000 entries,
// sorted by user ID with no repeat, each with the role manager or member and
// a fingerprint, and at least one manager.
func checkGroupMembers(members []GroupMember) error {
	switch n := len(members); {
	case n == 0:
		return ruled("members-none", fmt.Errorf("%w: group has %d members, want 1 to %d", ErrChain, n, maxGroupMembers))
	case n > maxGroupMembers:
		return ruled("members-too-many", fmt.Errorf("%w: group has %d members, want 1 to %d", ErrChain, n, maxGroupMembers))
	}
	managers := 0
	for i, m := range members {
		switch {
		case i > 0 && members[i-1].User == m.User:
			return ruled("member-duplicate", fmt.Errorf("%w: group lists user %q twice", ErrChain, m.User))
		case i > 0 && members[i-1].User > m.User:
			return ruled("members-unsorted", fmt.Errorf("%w: group members not sorted by user ID", ErrChain))
		case m.Role != groupRoleManager && m.Role != groupRoleMember:
			return ruled("member-role-invalid", fmt.Errorf("%w: group member %q has role %q", ErrChain, m.User, m.Role))
		case !isHex64(m.FP):
			return ruled("member-fp-malformed", fmt.Errorf("%w: group member %q fp is not 64 lowercase hex digits", ErrChain, m.User))
		}
		if m.Role == groupRoleManager {
			managers++
		}
	}
	if managers == 0 {
		return ruled("no-manager", fmt.Errorf("%w: group lists no manager", ErrChain))
	}
	return nil
}

// groupManager returns the entry of members that lists user as a manager.
func groupManager(members []GroupMember, user string) (GroupMember, bool) {
	for _, m := range members {
		if m.User == user && m.Role == groupRoleManager {
			return m, true
		}
	}
	return GroupMember{}, false
}

// checkFirstGroupRecord checks the creator's record: seq 1, no prev, and the
// signer listed as a manager under the key that signed.
func checkFirstGroupRecord(b GroupBody) error {
	if b.Seq != 1 {
		return ruled("first-seq", fmt.Errorf("%w: first record has seq %d", ErrChain, b.Seq))
	}
	if b.Prev != "" {
		return ruled("first-prev", fmt.Errorf("%w: first record has a prev", ErrChain))
	}
	m, ok := groupManager(b.Members, b.Signer)
	if !ok {
		return ruled("first-signer-not-manager", fmt.Errorf("%w: the first record does not list its signer %q as a manager", ErrChain, b.Signer))
	}
	if m.FP != b.SignerFP {
		return ruled("first-signer-fp-differs", fmt.Errorf("%w: the first record lists its signer %q under another fp than signerFp", ErrChain, b.Signer))
	}
	return nil
}

// checkNextGroupRecord checks b against the record before it, prev, whose
// body hashes to prevHash. The signer is a manager prev lists, and the key
// that signed is the fp prev lists for them or one their rotation chain
// links to it.
func checkNextGroupRecord(prev GroupBody, prevHash string, b GroupBody, linked func(user, fromFP, toFP string) bool) error {
	if b.Seq != prev.Seq+1 {
		return ruled("seq-skipped", fmt.Errorf("%w: seq %d follows %d", ErrChain, b.Seq, prev.Seq))
	}
	if b.Prev != prevHash {
		return ruled("prev-wrong", fmt.Errorf("%w: prev is not the previous record's hash", ErrChain))
	}
	listed, ok := groupManager(prev.Members, b.Signer)
	if !ok {
		return ruled("signer-not-manager", fmt.Errorf("%w: the previous record does not list %q as a manager", ErrChain, b.Signer))
	}
	if !linked(b.Signer, listed.FP, b.SignerFP) {
		return ruled("signer-key-not-linked", fmt.Errorf("%w: signerFp does not follow from the fp the previous record lists for the manager", ErrChain))
	}
	return nil
}
