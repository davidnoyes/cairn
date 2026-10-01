package membership

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// The rules a refused approval broke, following "Team approval" in
// design/e2e-api.md.
const (
	RuleApprover         Rule = "approver"          // the caller is the owner or a listed editor (403)
	RuleApprovalUser     Rule = "approval user"     // the user is a verified, active account (404)
	RuleTeamNone         Rule = "team none"         // the record shares with a team (409)
	RuleHolds            Rule = "holds"             // the user holds no wrap and is not listed (409)
	RuleApprovalExcluded Rule = "approval excluded" // the user matches no excluded entry (409)
	RuleApprovalShared   Rule = "approval shared"   // no other user shares their fingerprint or email (409)
	RuleApprovalFP       Rule = "approval fp"       // the request's fp is their current one (409)
	RuleApproval         Rule = "approval"          // the envelope verifies and names this request (400)
	RuleApprovalWraps    Rule = "approval wraps"    // one wrap for every epoch (400)
)

// ApprovalWrap is a wrap an approval carries. It is for the approved user.
type ApprovalWrap struct {
	Epoch   int
	Wrapped []byte
}

// ApprovalChange is an approval request and the authenticated caller who
// made it.
type ApprovalChange struct {
	Caller   string
	User     string
	FP       string
	Approval e2e.Envelope
	Wraps    []ApprovalWrap
}

// ApprovalResult is what an accepted approval writes.
type ApprovalResult struct {
	// Wraps carry the approved user's current fingerprint.
	Wraps    []store.Wrap
	Approval store.Approval
}

func statusError(status int, rule Rule, format string, args ...any) *Error {
	return &Error{Status: status, Rule: rule, Msg: fmt.Sprintf(format, args...)}
}

// CheckApproval decides whether the server accepts ch on cur. A refusal is
// an *Error; any other error is a directory failure. The checks run in the
// order the status codes are listed in the design: who may approve, the
// artifact's state, the user, then the approval and the wraps.
func CheckApproval(cur Current, dir Directory, ch ApprovalChange) (*ApprovalResult, error) {
	latest := cur.Latest
	if latest == nil || cur.Owner == nil {
		return nil, errors.New("membership: the artifact has no record")
	}

	// 403: the caller is the owner, or an editor listed under their
	// current fingerprint, as access.Check decided before the lock was held.
	caller, err := dir.User(ch.Caller)
	if err != nil {
		return nil, err
	}
	allowed := false
	switch {
	case caller == nil:
	case caller.ID == cur.Owner.ID:
		allowed = true
	default:
		for _, m := range latest.Members {
			if m.User == caller.ID && m.Role == access.RoleEditor {
				if m.FP != caller.FP {
					return nil, statusError(http.StatusForbidden, RuleApprover, "your keys differ from the listed fingerprint")
				}
				allowed = true
			}
		}
	}
	if !allowed {
		return nil, statusError(http.StatusForbidden, RuleApprover, "you are not the owner or a listed editor")
	}

	// 409: the record shares with a team.
	if latest.Team != access.TeamViewer && latest.Team != access.TeamEditor {
		return nil, conflict(RuleTeamNone, "the record's team is %q, so there is no team to approve into", latest.Team)
	}

	u, err := dir.User(ch.User)
	if err != nil {
		return nil, err
	}
	if u == nil || !u.Verified || !u.Active {
		return nil, statusError(http.StatusNotFound, RuleApprovalUser, "%s is not a user to approve", ch.User)
	}
	if u.ID == cur.Owner.ID {
		return nil, conflict(RuleHolds, "%s is the owner and needs no wrap", u.ID)
	}
	for _, m := range latest.Members {
		if m.User == u.ID {
			return nil, conflict(RuleHolds, "%s is listed; a changed key is shared again through a membership record", u.ID)
		}
	}
	for _, w := range cur.Wraps {
		if w.UserID == u.ID {
			return nil, conflict(RuleHolds, "%s holds a wrap; a changed key is shared again through a membership record", u.ID)
		}
	}
	if x := e2e.ExcludedMatch(latest.Excluded, u.ID, u.FP, u.Email); x != nil {
		return nil, conflict(RuleApprovalExcluded, "%s matches the excluded entry for %s", u.ID, x.User)
	}
	ids, err := dir.Sharing(u.FP, u.Email)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if id != u.ID {
			return nil, conflict(RuleApprovalShared, "%s shares a fingerprint or email with %s", u.ID, id)
		}
	}
	if ch.FP != u.FP {
		return nil, conflict(RuleApprovalFP, "fp is not %s's current fingerprint", u.ID)
	}

	// 400: the approval is the caller's, and names this request.
	if ch.Approval.Signer != caller.ID {
		return nil, refuse(RuleApproval, "the approval is not signed by the caller")
	}
	var body e2e.ApprovalBody
	if err := e2e.OpenEnvelope(ch.Approval, caller.Ed25519Pub, "approval", &body); err != nil {
		if errors.Is(err, e2e.ErrDecrypt) {
			return nil, refuse(RuleApproval, "the approval does not verify under the caller's current key")
		}
		return nil, refuse(RuleApproval, "the body does not parse: %v", err)
	}
	switch {
	case body.Artifact != cur.ArtifactID:
		return nil, refuse(RuleApproval, "artifact %q is not this artifact", body.Artifact)
	case body.Epoch != latest.Epoch:
		return nil, refuse(RuleApproval, "epoch %d is not the current epoch %d", body.Epoch, latest.Epoch)
	case body.User != u.ID:
		return nil, refuse(RuleApproval, "user %q is not the requested user", body.User)
	case body.FP != ch.FP:
		return nil, refuse(RuleApproval, "fp is not the requested fp")
	}

	// 400: a wrap for every epoch, and no other.
	res := &ApprovalResult{Approval: store.Approval{
		UserID: u.ID, FP: u.FP, Epoch: latest.Epoch,
		Envelope: store.Envelope{Body: ch.Approval.Body, Sig: ch.Approval.Sig, Signer: ch.Approval.Signer},
	}}
	got := map[int]bool{}
	for _, w := range ch.Wraps {
		switch {
		case len(w.Wrapped) != wrapSize:
			return nil, refuse(RuleApprovalWraps, "the wrap for epoch %d is not %d bytes", w.Epoch, wrapSize)
		case w.Epoch < 1 || w.Epoch > latest.Epoch:
			return nil, refuse(RuleApprovalWraps, "a wrap for epoch %d, which is not an epoch from 1 to %d", w.Epoch, latest.Epoch)
		case got[w.Epoch]:
			return nil, refuse(RuleApprovalWraps, "the wrap for epoch %d is given twice", w.Epoch)
		}
		got[w.Epoch] = true
		res.Wraps = append(res.Wraps, store.Wrap{UserID: u.ID, Epoch: w.Epoch, Wrapped: w.Wrapped, FP: u.FP})
	}
	for e := 1; e <= latest.Epoch; e++ {
		if !got[e] {
			return nil, refuse(RuleApprovalWraps, "missing the wrap for epoch %d", e)
		}
	}
	return res, nil
}

// ApplyApproval writes an accepted approval. It must run in the artifact's
// transaction, on the same Current that CheckApproval saw.
func ApplyApproval(tx *store.ArtifactTx, res *ApprovalResult) error {
	for _, w := range res.Wraps {
		if err := tx.PutWrap(w); err != nil {
			return err
		}
	}
	return tx.PutApproval(res.Approval)
}
