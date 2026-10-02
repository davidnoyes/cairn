// Package membership decides whether the server accepts a membership record
// (an artifact's first, or a change through PUT .../membership), following
// "Membership records" in design/e2e-api.md, and writes what an accepted one
// changes.
package membership

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Rule names the acceptance rule a refused record broke.
type Rule string

const (
	RuleSigner        Rule = "signer"         // the envelope's signer is the owner
	RuleSignature     Rule = "signature"      // verifies under the owner's current key and parses strictly
	RuleArtifact      Rule = "artifact"       // names this artifact
	RuleOwner         Rule = "owner"          // names the artifact's owner
	RuleOwnerFP       Rule = "ownerFp"        // the owner's current fingerprint
	RuleSeq           Rule = "seq"            // one more than the latest (409)
	RulePrev          Rule = "prev"           // the latest record's body hash (409)
	RuleTransfer      Rule = "transfer"       // transfer and handover are empty
	RuleMembers       Rule = "members"        // shape, order, roles, fingerprints
	RuleExcluded      Rule = "excluded"       // shape and order
	RuleTeam          Rule = "team"           // none, viewer or editor
	RuleAKCommit      Rule = "akCommit"       // format, and changes exactly with the epoch
	RuleEpoch         Rule = "epoch"          // the current epoch or the next
	RuleNewMember     Rule = "new member"     // a new or changed member is the user's current, unique key
	RuleExcludedMatch Rule = "excluded match" // no entry matches the owner or a member
	RuleSameEpoch     Rule = "same epoch"     // what a same-epoch record cannot do
	RuleNextEpoch     Rule = "next epoch"     // everyone removed or dropped is excluded
	RuleExcludedDrop  Rule = "excluded drop"  // an entry leaves only when its user is listed
	RuleExcludedEntry Rule = "excluded entry" // carried entries unchanged, new ones true
	RuleWraps         Rule = "wraps"          // exactly the wraps the change needs
	RuleStaleFP       Rule = "stale fp"       // a next epoch lists every member under their current fp
	RuleEstate        Rule = "estate"         // the new epoch's estate copy
	RuleLinkToken     Rule = "linkTokenHash"  // with a public record, and only then
)

// Error is a refused record: the HTTP status to answer with, and the rule.
type Error struct {
	Status int
	Rule   Rule
	Msg    string
}

func (e *Error) Error() string { return "membership: " + string(e.Rule) + ": " + e.Msg }

func refuse(rule Rule, format string, args ...any) *Error {
	return &Error{Status: http.StatusBadRequest, Rule: rule, Msg: fmt.Sprintf(format, args...)}
}

func conflict(rule Rule, format string, args ...any) *Error {
	return &Error{Status: http.StatusConflict, Rule: rule, Msg: fmt.Sprintf(format, args...)}
}

// User is a user as the checks see them: their current keys, and FP, the
// hex fingerprint of those keys. Email is normalized.
type User struct {
	ID         string
	Email      string
	X25519Pub  []byte
	Ed25519Pub []byte
	FP         string
	Verified   bool
	Active     bool
}

// Directory looks users up.
type Directory interface {
	// User returns the user, or nil, nil when there is none.
	User(id string) (*User, error)
	// Sharing returns the IDs of every user whose current fingerprint is fp
	// or whose normalized email is email.
	Sharing(fp, email string) ([]string, error)
}

// WrapIn is a wrap a change carries.
type WrapIn struct {
	User    string
	Epoch   int
	Wrapped []byte
}

// EstateIn is the owner's sealed copy of a new epoch's AK.
type EstateIn struct {
	Epoch  int
	Sealed []byte
}

// Acceptance is an open offer the record accepts. NewOwner is the offered
// user, who signs the record.
type Acceptance struct {
	NewOwner  *User
	OfferHash string // the owner's offer body hash; empty for an administrator's offer
}

// Change is a membership record and everything sent with it. Accept is set
// for a record that accepts an ownership offer, and only for one.
type Change struct {
	Envelope      e2e.Envelope
	Wraps         []WrapIn
	Estate        []EstateIn
	LinkTokenHash string
	Accept        *Acceptance
}

// Current is the artifact a change applies to. Latest is nil before the
// first record. Wraps is every wrap on the artifact.
type Current struct {
	ArtifactID string
	Owner      *User
	Latest     *e2e.MembershipBody
	LatestHash string
	Wraps      []store.Wrap
}

// Result is what an accepted change writes.
type Result struct {
	Body     *e2e.MembershipBody
	Record   *store.Record
	Members  []store.Member
	Excluded []store.Excluded
	// Wraps carry the recipient's current fingerprint.
	Wraps  []store.Wrap
	Estate []store.Estate
	// NewEpoch is true for the first record and for a next-epoch record:
	// Apply then deletes every wrap held by a user the record does not list.
	// That includes every removed member, because only a next-epoch record
	// can remove one.
	NewEpoch bool
	// PublicTokenHash and PublicEpoch replace the link's token hash, or
	// clear it when empty.
	PublicTokenHash string
	PublicEpoch     int
	// Accepted is true for a record that accepts an ownership offer: Apply
	// then changes the owner and replaces the estate copies.
	Accepted bool
}

// Sizes of a wrap and of an estate copy, from design/e2e-wire-formats.md.
const (
	wrapSize   = 1 + 32 + 32 + 16 // version, ephemeral key, AK, tag
	estateSize = 1 + 12 + 32 + 16 // version, nonce, AK, tag
)

type wrapKey struct {
	user  string
	epoch int
}

// CheckNewOwner refuses u as the artifact's next owner unless u is an active,
// verified user whom the latest record lists as an editor under their current
// key. Check applies it to an acceptance; the server also applies it to an
// offer.
func CheckNewOwner(cur Current, u *User) error {
	var listed *e2e.Member
	if cur.Latest != nil {
		for i := range cur.Latest.Members {
			if cur.Latest.Members[i].User == u.ID {
				listed = &cur.Latest.Members[i]
			}
		}
	}
	switch {
	case listed == nil || listed.Role != access.RoleEditor:
		return conflict(RuleOwner, "only a listed editor can take ownership")
	case !u.Active || !u.Verified:
		return conflict(RuleOwner, "the user is not an active, verified user")
	case listed.FP != u.FP:
		return conflict(RuleOwner, "the user's key is not the one the latest record lists")
	}
	return nil
}

// Check decides whether the server accepts ch on cur. A refusal is an
// *Error; any other error is a directory failure.
//
// A record with ch.Accept set is checked under the new owner's key and
// names them as owner. The previous owner is then a member of the artifact
// like any other: listed, or removed.
func Check(cur Current, dir Directory, ch Change) (*Result, error) {
	prevOwner := cur.Owner
	if prevOwner == nil {
		return nil, errors.New("membership: the artifact has no owner")
	}
	owner := prevOwner
	if ch.Accept != nil {
		owner = ch.Accept.NewOwner
		if err := CheckNewOwner(cur, owner); err != nil {
			return nil, err
		}
	}

	// Rules 1 and 2: who signed, under which key, for what.
	if ch.Envelope.Signer != owner.ID {
		return nil, refuse(RuleSigner, "signer %q is not the owner", ch.Envelope.Signer)
	}
	var body e2e.MembershipBody
	if err := e2e.OpenEnvelope(ch.Envelope, owner.Ed25519Pub, "membership", &body); err != nil {
		if errors.Is(err, e2e.ErrDecrypt) {
			return nil, refuse(RuleSignature, "the record does not verify under the owner's current key")
		}
		return nil, refuse(RuleSignature, "the body does not parse: %v", err)
	}
	if body.Artifact != cur.ArtifactID {
		return nil, refuse(RuleArtifact, "artifact %q is not this artifact", body.Artifact)
	}
	if body.Owner != owner.ID {
		return nil, refuse(RuleOwner, "owner %q is not the artifact's owner", body.Owner)
	}
	if body.OwnerFP != owner.FP {
		return nil, refuse(RuleOwnerFP, "ownerFp is not the owner's current fingerprint")
	}

	// Rule 3: the chain moves on from the latest record.
	prev := cur.Latest
	epoch, wantSeq, wantPrev := 0, 1, ""
	if prev != nil {
		epoch, wantSeq, wantPrev = prev.Epoch, prev.Seq+1, cur.LatestHash
	}
	if body.Seq != wantSeq {
		return nil, conflict(RuleSeq, "seq %d, want %d", body.Seq, wantSeq)
	}
	if body.Prev != wantPrev {
		return nil, conflict(RulePrev, "prev is not the latest record's hash")
	}

	// Rule 8.
	switch {
	case ch.Accept == nil && body.Transfer != "":
		return nil, refuse(RuleTransfer, "transfer must be empty")
	case ch.Accept == nil && body.Handover != "":
		return nil, refuse(RuleTransfer, "handover must be empty")
	case ch.Accept != nil && ch.Accept.OfferHash != "" && (body.Transfer != ch.Accept.OfferHash || body.Handover != ""):
		return nil, refuse(RuleTransfer, "transfer must be the offer's hash, and handover empty")
	case ch.Accept != nil && ch.Accept.OfferHash == "" && (body.Handover != "admin" || body.Transfer != ""):
		return nil, refuse(RuleTransfer, "an administrator's offer needs handover admin, and transfer empty")
	}

	// Rule 4: shapes.
	if err := checkShape(&body, owner.ID); err != nil {
		return nil, err
	}

	// Rule 7.
	newEpoch := body.Epoch == epoch+1
	switch {
	case prev == nil && body.Epoch != 1:
		return nil, refuse(RuleEpoch, "epoch %d, want 1", body.Epoch)
	case prev != nil && body.Epoch != epoch && !newEpoch:
		return nil, refuse(RuleEpoch, "epoch %d, want %d or %d", body.Epoch, epoch, epoch+1)
	case prev != nil && !newEpoch && body.AKCommit != prev.AKCommit:
		return nil, refuse(RuleAKCommit, "a same-epoch record keeps akCommit")
	case prev != nil && newEpoch && body.AKCommit == prev.AKCommit:
		return nil, refuse(RuleAKCommit, "a next-epoch record needs a new akCommit")
	}

	prevMembers := map[string]e2e.Member{}
	prevExcluded := map[string]e2e.ExcludedEntry{}
	if prev != nil {
		for _, m := range prev.Members {
			prevMembers[m.User] = m
		}
		for _, x := range prev.Excluded {
			prevExcluded[x.User] = x
		}
	}
	listed := map[string]e2e.Member{}
	users := map[string]*User{}
	for _, m := range body.Members {
		listed[m.User] = m
		u, err := dir.User(m.User)
		if err != nil {
			return nil, err
		}
		if u != nil {
			users[m.User] = u
		}
	}

	// Rule 6: a member the previous record does not list, or lists under
	// another fp, is the user's current key and theirs alone.
	for _, m := range body.Members {
		if pm, ok := prevMembers[m.User]; ok && pm.FP == m.FP {
			continue
		}
		u := users[m.User]
		switch {
		case u == nil:
			return nil, refuse(RuleNewMember, "member %s is not a user", m.User)
		case m.FP != u.FP:
			return nil, refuse(RuleNewMember, "member %s fp is not their current fingerprint", m.User)
		case !u.Verified:
			return nil, refuse(RuleNewMember, "member %s is not verified", m.User)
		case !u.Active:
			return nil, refuse(RuleNewMember, "member %s is not active", m.User)
		}
		ids, err := dir.Sharing(u.FP, u.Email)
		if err != nil {
			return nil, err
		}
		if len(ids) != 1 || ids[0] != u.ID {
			return nil, refuse(RuleNewMember, "member %s shares a fingerprint or email with another user", m.User)
		}
	}

	// Rule 5.
	for _, x := range body.Excluded {
		if x.User == owner.ID {
			return nil, refuse(RuleExcludedMatch, "excluded %s is the owner", x.User)
		}
		for _, m := range body.Members {
			if matches(x, m, users[m.User]) {
				return nil, refuse(RuleExcludedMatch, "excluded %s matches member %s", x.User, m.User)
			}
		}
	}

	// Rules 9 and 10. A team member holding a wrap is an unlisted user,
	// other than the owner, with a wrap for the current epoch.
	var removed []string
	if prev != nil {
		for _, m := range prev.Members {
			if _, ok := listed[m.User]; !ok && m.User != owner.ID {
				removed = append(removed, m.User)
			}
		}
		if _, ok := listed[prevOwner.ID]; ch.Accept != nil && !ok {
			removed = append(removed, prevOwner.ID)
		}
	}
	var holders []string
	seen := map[string]bool{}
	for _, w := range cur.Wraps {
		if _, ok := prevMembers[w.UserID]; w.Epoch == epoch && !ok && w.UserID != owner.ID && !seen[w.UserID] {
			seen[w.UserID] = true
			holders = append(holders, w.UserID)
		}
	}
	sort.Strings(holders)
	inExcluded := map[string]bool{}
	for _, x := range body.Excluded {
		inExcluded[x.User] = true
	}
	if prev != nil && !newEpoch {
		if len(removed) > 0 {
			return nil, refuse(RuleSameEpoch, "a same-epoch record removes %s", removed[0])
		}
		for _, m := range body.Members {
			if prevMembers[m.User].Role == access.RoleEditor && m.Role == access.RoleViewer {
				return nil, refuse(RuleSameEpoch, "a same-epoch record demotes %s", m.User)
			}
		}
		if prev.Public && !body.Public {
			return nil, refuse(RuleSameEpoch, "a same-epoch record cannot make a public artifact private")
		}
		for _, x := range body.Excluded {
			if _, ok := prevExcluded[x.User]; !ok {
				return nil, refuse(RuleSameEpoch, "a same-epoch record excludes %s", x.User)
			}
		}
		if body.Team == access.TeamNone && prev.Team != access.TeamNone {
			for _, h := range holders {
				if _, ok := listed[h]; !ok {
					return nil, refuse(RuleSameEpoch, "a same-epoch record sets team none while team member %s holds a wrap", h)
				}
			}
		}
	}
	if prev != nil && newEpoch {
		for _, r := range removed {
			if !inExcluded[r] {
				return nil, refuse(RuleNextEpoch, "removed member %s is neither listed nor excluded", r)
			}
		}
		for _, h := range holders {
			if _, ok := listed[h]; !ok && !inExcluded[h] {
				return nil, refuse(RuleNextEpoch, "team member %s holds a wrap and is neither listed nor excluded", h)
			}
		}
	}

	// Rule 11.
	if err := checkExcluded(&body, cur, dir, prevMembers, prevExcluded, users, ch.Accept != nil); err != nil {
		return nil, err
	}

	// Rule 12. A listed member is added for an epoch when they hold no wrap
	// for it under their current fingerprint. Only a member listed under
	// their current fingerprint can be added: one a same-epoch record leaves
	// under an old fp is not wrapped to again until the owner updates it. A
	// next epoch cannot leave one: they could not open a wrap to their old
	// key, and a wrap to their new one would share with a key the owner has
	// not approved.
	held := map[wrapKey]bool{}
	for _, w := range cur.Wraps {
		if u := users[w.UserID]; u != nil && w.FP == u.FP {
			held[wrapKey{w.UserID, w.Epoch}] = true
		}
	}
	need := map[wrapKey]bool{}
	for _, m := range body.Members {
		u := users[m.User]
		if u == nil {
			if newEpoch {
				return nil, refuse(RuleWraps, "member %s has no account to wrap the new epoch to", m.User)
			}
			continue
		}
		if newEpoch && m.FP != u.FP {
			return nil, refuse(RuleStaleFP, "next epoch lists %s under a fingerprint that is no longer theirs", m.User)
		}
		if m.FP == u.FP {
			for e := 1; e <= epoch; e++ {
				if !held[wrapKey{m.User, e}] {
					need[wrapKey{m.User, e}] = true
				}
			}
		}
		if newEpoch {
			need[wrapKey{m.User, body.Epoch}] = true
		}
	}
	res := &Result{Body: &body, NewEpoch: newEpoch}
	got := map[wrapKey]bool{}
	for _, w := range ch.Wraps {
		k := wrapKey{w.User, w.Epoch}
		switch {
		case len(w.Wrapped) != wrapSize:
			return nil, refuse(RuleWraps, "the wrap for %s at epoch %d is not %d bytes", w.User, w.Epoch, wrapSize)
		case got[k]:
			return nil, refuse(RuleWraps, "the wrap for %s at epoch %d is given twice", w.User, w.Epoch)
		case listed[w.User].User == "":
			return nil, refuse(RuleWraps, "a wrap for %s, who is not a listed member", w.User)
		case !need[k]:
			return nil, refuse(RuleWraps, "the wrap for %s at epoch %d is not needed", w.User, w.Epoch)
		}
		got[k] = true
		res.Wraps = append(res.Wraps, store.Wrap{UserID: w.User, Epoch: w.Epoch, Wrapped: w.Wrapped, FP: users[w.User].FP})
	}
	if len(got) != len(need) {
		var missing []wrapKey
		for k := range need {
			if !got[k] {
				missing = append(missing, k)
			}
		}
		sort.Slice(missing, func(i, j int) bool {
			if missing[i].user != missing[j].user {
				return missing[i].user < missing[j].user
			}
			return missing[i].epoch < missing[j].epoch
		})
		return nil, refuse(RuleWraps, "missing the wrap for %s at epoch %d", missing[0].user, missing[0].epoch)
	}

	// Rule 13.
	if ch.Accept != nil {
		if len(ch.Estate) != body.Epoch {
			return nil, refuse(RuleEstate, "an accepting record needs exactly one estate copy for every epoch, 1 to %d", body.Epoch)
		}
		have := map[int]bool{}
		for _, e := range ch.Estate {
			switch {
			case e.Epoch < 1 || e.Epoch > body.Epoch || have[e.Epoch]:
				return nil, refuse(RuleEstate, "an accepting record needs exactly one estate copy for every epoch, 1 to %d", body.Epoch)
			case len(e.Sealed) != estateSize:
				return nil, refuse(RuleEstate, "the estate copy for epoch %d is not %d bytes", e.Epoch, estateSize)
			}
			have[e.Epoch] = true
			res.Estate = append(res.Estate, store.Estate{Epoch: e.Epoch, Sealed: e.Sealed})
		}
		res.Accepted = true
	} else if newEpoch {
		if len(ch.Estate) != 1 || ch.Estate[0].Epoch != body.Epoch {
			return nil, refuse(RuleEstate, "a new epoch needs exactly one estate copy, for epoch %d", body.Epoch)
		}
		if len(ch.Estate[0].Sealed) != estateSize {
			return nil, refuse(RuleEstate, "the estate copy is not %d bytes", estateSize)
		}
		res.Estate = []store.Estate{{Epoch: body.Epoch, Sealed: ch.Estate[0].Sealed}}
	} else if len(ch.Estate) > 0 {
		return nil, refuse(RuleEstate, "a same-epoch record takes none")
	}

	// Rule 14.
	switch {
	case body.Public && ch.LinkTokenHash == "":
		return nil, refuse(RuleLinkToken, "linkTokenHash is required for a public record")
	case body.Public && !isHex64(ch.LinkTokenHash):
		return nil, refuse(RuleLinkToken, "linkTokenHash is not 64 lowercase hex")
	case !body.Public && ch.LinkTokenHash != "":
		return nil, refuse(RuleLinkToken, "linkTokenHash is refused for a private record")
	case body.Public:
		res.PublicTokenHash, res.PublicEpoch = ch.LinkTokenHash, body.Epoch
	}

	commit, _ := hex.DecodeString(body.AKCommit) // checked by checkShape
	res.Record = &store.Record{
		Seq: body.Seq, Prev: body.Prev, Epoch: body.Epoch, OwnerID: body.Owner, OwnerFp: body.OwnerFP,
		AKCommit: commit, Team: body.Team, Public: body.Public, PublicWrites: body.PublicWrites,
		Transfer: body.Transfer, Handover: body.Handover,
		Envelope: store.Envelope{Body: ch.Envelope.Body, Sig: ch.Envelope.Sig, Signer: ch.Envelope.Signer},
	}
	for _, m := range body.Members {
		res.Members = append(res.Members, store.Member{UserID: m.User, Role: m.Role, FP: m.FP})
	}
	for _, x := range body.Excluded {
		res.Excluded = append(res.Excluded, store.Excluded{UserID: x.User, FP: x.FP, Email: x.Email})
	}
	return res, nil
}

// checkShape is rule 4: members and excluded are arrays sorted by user ID
// with no duplicates, and every enumerated or hex field is well formed.
func checkShape(b *e2e.MembershipBody, ownerID string) error {
	if b.Members == nil {
		return refuse(RuleMembers, "members is null, want an array")
	}
	if b.Excluded == nil {
		return refuse(RuleExcluded, "excluded is null, want an array")
	}
	for i, m := range b.Members {
		switch {
		case i > 0 && m.User <= b.Members[i-1].User:
			return refuse(RuleMembers, "members are not sorted by user ID without duplicates")
		case m.User == ownerID:
			return refuse(RuleMembers, "members list the owner")
		case m.Role != access.RoleViewer && m.Role != access.RoleEditor:
			return refuse(RuleMembers, "member %s has role %q, want viewer or editor", m.User, m.Role)
		case !isHex64(m.FP):
			return refuse(RuleMembers, "member %s fp is not 64 lowercase hex", m.User)
		}
	}
	if b.Team != access.TeamNone && b.Team != access.TeamViewer && b.Team != access.TeamEditor {
		return refuse(RuleTeam, "team %q is not none, viewer or editor", b.Team)
	}
	if !isHex64(b.AKCommit) {
		return refuse(RuleAKCommit, "akCommit is not 64 lowercase hex")
	}
	for i, x := range b.Excluded {
		switch {
		case i > 0 && x.User <= b.Excluded[i-1].User:
			return refuse(RuleExcluded, "excluded is not sorted by user ID without duplicates")
		case !isHex64(x.FP):
			return refuse(RuleExcluded, "excluded %s fp is not 64 lowercase hex", x.User)
		case x.Email == "":
			return refuse(RuleExcluded, "excluded %s has no email", x.User)
		}
	}
	return nil
}

// matches reports whether excluded entry x matches member m by user ID,
// fingerprint, or normalized email. u is m's account, or nil when it is
// gone and there is no email to compare.
func matches(x e2e.ExcludedEntry, m e2e.Member, u *User) bool {
	return x.User == m.User || x.FP == m.FP || (u != nil && e2e.NormalizeEmail(x.Email) == u.Email)
}

// checkExcluded is rule 11. An entry leaves only when a listed member
// matches it; one carried over is unchanged; a new one has the user's
// current email and a fingerprint the server can account for: the one the
// previous record listed for them, or the one a wrap they hold was made for.
// When accepting is true the previous owner is accountable under the
// fingerprint the previous record names as ownerFp.
func checkExcluded(b *e2e.MembershipBody, cur Current, dir Directory, prevMembers map[string]e2e.Member,
	prevExcluded map[string]e2e.ExcludedEntry, users map[string]*User, accepting bool) error {
	if cur.Latest == nil {
		if len(b.Excluded) > 0 {
			return refuse(RuleExcludedEntry, "the first record must have an empty excluded")
		}
		return nil
	}
	kept := map[string]e2e.ExcludedEntry{}
	for _, x := range b.Excluded {
		kept[x.User] = x
	}
	for _, p := range cur.Latest.Excluded {
		if x, ok := kept[p.User]; ok {
			if x != p {
				return refuse(RuleExcludedEntry, "the excluded entry for %s changes", p.User)
			}
			continue
		}
		dropped := true
		for _, m := range b.Members {
			if matches(p, m, users[m.User]) {
				dropped = false
				break
			}
		}
		if dropped {
			return refuse(RuleExcludedDrop, "the record drops excluded %s without listing them", p.User)
		}
	}
	for _, x := range b.Excluded {
		if _, ok := prevExcluded[x.User]; ok {
			continue
		}
		u, err := dir.User(x.User)
		if err != nil {
			return err
		}
		// A deactivated user is not in the directory a client reads, so for one
		// the client writes the user ID as the email.
		if u != nil && x.Email != u.Email && (u.Active || x.Email != x.User) {
			return refuse(RuleExcludedEntry, "excluded %s email is not their current email", x.User)
		}
		fps := map[string]bool{}
		if m, ok := prevMembers[x.User]; ok {
			fps[m.FP] = true
		}
		for _, w := range cur.Wraps {
			if w.UserID == x.User {
				fps[w.FP] = true
			}
		}
		if accepting && x.User == cur.Owner.ID {
			fps[cur.Latest.OwnerFP] = true
		}
		if len(fps) == 0 {
			return refuse(RuleExcludedEntry, "excluded %s was not listed and holds no wrap", x.User)
		}
		if !fps[x.FP] {
			return refuse(RuleExcludedEntry, "excluded %s fp is neither the one the previous record listed nor one a wrap they hold was made for", x.User)
		}
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// Apply writes an accepted change. It must run in the artifact's
// transaction, on the same Current that Check saw.
func Apply(tx *store.ArtifactTx, res *Result) error {
	if err := tx.AppendRecord(res.Record); err != nil {
		return err
	}
	if res.Accepted {
		// The new owner holds estate copies, not wraps, and theirs replace
		// the previous owner's.
		if err := tx.SetOwner(res.Body.Owner); err != nil {
			return err
		}
		if err := tx.DeleteEstates(); err != nil {
			return err
		}
		if err := tx.DeleteWraps(res.Body.Owner); err != nil {
			return err
		}
	}
	if err := tx.SetMembers(res.Members); err != nil {
		return err
	}
	if err := tx.SetExcluded(res.Excluded); err != nil {
		return err
	}
	if res.NewEpoch {
		keep := make([]string, len(res.Members))
		for i, m := range res.Members {
			keep[i] = m.UserID
		}
		if err := tx.DeleteWrapsExcept(keep); err != nil {
			return err
		}
		if err := tx.DeleteApprovalsExcept(keep); err != nil {
			return err
		}
	}
	// A member re-listed under a reset key already holds rows for the
	// epochs they are wrapped to again.
	for _, w := range res.Wraps {
		if err := tx.ReplaceWrap(w); err != nil {
			return err
		}
	}
	for _, e := range res.Estate {
		if err := tx.PutEstate(e.Epoch, e.Sealed); err != nil {
			return err
		}
	}
	if err := tx.SetPublicToken(res.PublicTokenHash, res.PublicEpoch); err != nil {
		return err
	}
	// Any record moves prev, so an open offer can no longer be accepted; the
	// record that accepts it keeps it, for the membership view to serve.
	state := "closed"
	if res.Accepted {
		state = "accepted"
	}
	if err := tx.SetOfferState(state); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// Load reads the Current that Check needs from the artifact's transaction.
func Load(tx *store.ArtifactTx, dir Directory) (Current, error) {
	a, err := tx.Artifact()
	if err != nil {
		return Current{}, err
	}
	owner, err := dir.User(a.OwnerID)
	if err != nil {
		return Current{}, err
	}
	cur := Current{ArtifactID: tx.ArtifactID(), Owner: owner}
	rec, err := tx.LatestRecord()
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return Current{}, err
	default:
		var b e2e.MembershipBody
		if err := e2e.DecodeStrict(rec.Envelope.Body, &b); err != nil {
			return Current{}, err
		}
		cur.Latest, cur.LatestHash = &b, rec.BodyHash
	}
	if cur.Wraps, err = tx.Wraps(); err != nil {
		return Current{}, err
	}
	return cur, nil
}

// TxDirectory is a Directory that reads inside the artifact's transaction.
func TxDirectory(tx *store.ArtifactTx) Directory { return txDirectory{tx} }

type txDirectory struct{ tx *store.ArtifactTx }

func (d txDirectory) User(id string) (*User, error) {
	k, err := d.tx.UserByID(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &User{ID: k.ID, Email: k.Email, X25519Pub: k.X25519Pub, Ed25519Pub: k.Ed25519Pub,
		FP: k.FP, Verified: k.Verified, Active: !k.Disabled}, nil
}

func (d txDirectory) Sharing(fp, email string) ([]string, error) { return d.tx.UsersSharing(fp, email) }
