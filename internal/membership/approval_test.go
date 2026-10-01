package membership

import (
	"encoding/json"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// approval builds the request signer would send to approve target, with the
// approval body and wraps the rules need, for the fixture's current epoch.
func (f *fixture) approval(t *testing.T, signer, target *tUser) ApprovalChange {
	t.Helper()
	return ApprovalChange{
		Caller: signer.ID, User: target.ID, FP: target.FP,
		Approval: f.approvalEnv(t, signer, e2e.ApprovalBody{V: 1, Artifact: artID, Epoch: 2, User: target.ID, FP: target.FP}),
		Wraps:    []ApprovalWrap{{Epoch: 1, Wrapped: make([]byte, 81)}, {Epoch: 2, Wrapped: make([]byte, 81)}},
	}
}

func (f *fixture) approvalEnv(t *testing.T, signer *tUser, b e2e.ApprovalBody) e2e.Envelope {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return f.approvalRaw(t, signer, raw)
}

func (f *fixture) approvalRaw(t *testing.T, signer *tUser, raw []byte) e2e.Envelope {
	t.Helper()
	env, err := e2e.NewEnvelope(signer.seed, signer.ID, "approval", raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestCheckApprovalAccepts(t *testing.T) {
	for _, name := range []string{"owner", "editor"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			signer := f.o
			if name == "editor" {
				signer = f.a
			}
			res, err := CheckApproval(f.cur, f.dir, f.approval(t, signer, f.c))
			if err != nil {
				t.Fatal(err)
			}
			if got := wrapKeys(res.Wraps); got != "u-c@1,u-c@2" {
				t.Errorf("wraps %s, want u-c@1,u-c@2", got)
			}
			for _, w := range res.Wraps {
				if w.FP != f.c.FP {
					t.Errorf("wrap for epoch %d stored under fp %s, want the user's current %s", w.Epoch, w.FP, f.c.FP)
				}
			}
			if a := res.Approval; a.UserID != f.c.ID || a.FP != f.c.FP || a.Epoch != 2 || a.Envelope.Signer != signer.ID {
				t.Errorf("approval to store: %+v", a)
			}
		})
	}
}

func TestCheckApprovalRefusals(t *testing.T) {
	cases := []struct {
		name   string
		build  func(t *testing.T, f *fixture) ApprovalChange
		status int
		rule   Rule
		msg    string
	}{
		// 403: who may approve
		{"a viewer", func(t *testing.T, f *fixture) ApprovalChange {
			return f.approval(t, f.b, f.c)
		}, 403, RuleApprover, "not the owner or a listed editor"},
		{"a team member", func(t *testing.T, f *fixture) ApprovalChange {
			return f.approval(t, f.tm, f.c)
		}, 403, RuleApprover, "not the owner or a listed editor"},
		{"a user with no access", func(t *testing.T, f *fixture) ApprovalChange {
			return f.approval(t, f.x, f.c)
		}, 403, RuleApprover, "not the owner or a listed editor"},
		{"an editor whose keys changed", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.a, f.c)
			rekey(t, f.a)
			return ch
		}, 403, RuleApprover, "listed fingerprint"},
		{"a caller who is not a user", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Caller = "u-ghost"
			return ch
		}, 403, RuleApprover, "not the owner or a listed editor"},

		// 409: the artifact's state
		{"team none", func(t *testing.T, f *fixture) ApprovalChange {
			b := *f.cur.Latest
			b.Team = "none"
			f.setLatest(&b)
			return f.approval(t, f.o, f.c)
		}, 409, RuleTeamNone, "team"},
		{"a user who holds a wrap", func(t *testing.T, f *fixture) ApprovalChange {
			return f.approval(t, f.o, f.tm)
		}, 409, RuleHolds, "holds a wrap"},
		{"a user the record lists", func(t *testing.T, f *fixture) ApprovalChange {
			f.cur.Wraps = nil
			return f.approval(t, f.o, f.b)
		}, 409, RuleHolds, "listed"},
		{"a listed user whose key changed", func(t *testing.T, f *fixture) ApprovalChange {
			f.cur.Wraps = nil
			rekey(t, f.b)
			return f.approval(t, f.o, f.b)
		}, 409, RuleHolds, "listed"},
		{"a user whose wraps are for an old key", func(t *testing.T, f *fixture) ApprovalChange {
			rekey(t, f.tm)
			return f.approval(t, f.o, f.tm)
		}, 409, RuleHolds, "holds a wrap"},
		{"the owner", func(t *testing.T, f *fixture) ApprovalChange {
			return f.approval(t, f.o, f.o)
		}, 409, RuleHolds, "owner"},
		{"an excluded user ID", func(t *testing.T, f *fixture) ApprovalChange {
			return f.approval(t, f.o, f.x)
		}, 409, RuleApprovalExcluded, "excluded"},
		{"a user with an excluded fingerprint", func(t *testing.T, f *fixture) ApprovalChange {
			f.c.FP = f.x.FP
			return f.approval(t, f.o, f.c)
		}, 409, RuleApprovalExcluded, "excluded"},
		{"a user with an excluded email", func(t *testing.T, f *fixture) ApprovalChange {
			f.c.Email = f.x.Email
			return f.approval(t, f.o, f.c)
		}, 409, RuleApprovalExcluded, "excluded"},
		{"a fingerprint another user shares", func(t *testing.T, f *fixture) ApprovalChange {
			d := f.add(t, "u-d", "d@x.y")
			d.FP = f.c.FP
			return f.approval(t, f.o, f.c)
		}, 409, RuleApprovalShared, "shares"},
		{"an email another user shares", func(t *testing.T, f *fixture) ApprovalChange {
			d := f.add(t, "u-d", "d@x.y")
			d.Email = f.c.Email
			return f.approval(t, f.o, f.c)
		}, 409, RuleApprovalShared, "shares"},
		{"a fingerprint that is not current", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.FP = f.b.FP
			ch.Approval = f.approvalEnv(t, f.o, e2e.ApprovalBody{V: 1, Artifact: artID, Epoch: 2, User: f.c.ID, FP: f.b.FP})
			return ch
		}, 409, RuleApprovalFP, "current fingerprint"},

		// 404: the user is not someone to approve
		{"a user who does not exist", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.User = "u-ghost"
			return ch
		}, 404, RuleApprovalUser, "not a user"},
		{"an unverified user", func(t *testing.T, f *fixture) ApprovalChange {
			f.c.Verified = false
			return f.approval(t, f.o, f.c)
		}, 404, RuleApprovalUser, "not a user"},
		{"a deactivated user", func(t *testing.T, f *fixture) ApprovalChange {
			f.c.Active = false
			return f.approval(t, f.o, f.c)
		}, 404, RuleApprovalUser, "not a user"},

		// 400: the approval
		{"an approval signed by another key", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Approval = f.approvalEnv(t, f.b, e2e.ApprovalBody{V: 1, Artifact: artID, Epoch: 2, User: f.c.ID, FP: f.c.FP})
			ch.Approval.Signer = f.o.ID
			return ch
		}, 400, RuleApproval, "verify"},
		{"an approval signed by someone else", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Caller = f.a.ID
			return ch
		}, 400, RuleApproval, "caller"},
		{"an approval whose signer is not the caller", func(t *testing.T, f *fixture) ApprovalChange {
			// The signature verifies under the caller's key, but the envelope
			// names someone else: a client would look up the wrong key.
			ch := f.approval(t, f.o, f.c)
			ch.Approval.Signer = f.a.ID
			return ch
		}, 400, RuleApproval, "not signed by the caller"},
		{"an approval for another purpose", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			raw, _ := json.Marshal(e2e.ApprovalBody{V: 1, Artifact: artID, Epoch: 2, User: f.c.ID, FP: f.c.FP})
			env, _ := e2e.NewEnvelope(f.o.seed, f.o.ID, "vouch", raw)
			ch.Approval = env
			return ch
		}, 400, RuleApproval, "verify"},
		{"an approval body with an unknown field", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			raw := []byte(`{"v":1,"artifact":"` + artID + `","epoch":2,"user":"` + f.c.ID + `","fp":"` + f.c.FP + `","role":"editor"}`)
			ch.Approval = f.approvalRaw(t, f.o, raw)
			return ch
		}, 400, RuleApproval, "unknown field"},
		{"an approval with v not 1", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Approval = f.approvalEnv(t, f.o, e2e.ApprovalBody{V: 2, Artifact: artID, Epoch: 2, User: f.c.ID, FP: f.c.FP})
			return ch
		}, 400, RuleApproval, "version"},
		{"an approval for another artifact", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Approval = f.approvalEnv(t, f.o, e2e.ApprovalBody{V: 1, Artifact: "22222222-2222-4222-8222-222222222222", Epoch: 2, User: f.c.ID, FP: f.c.FP})
			return ch
		}, 400, RuleApproval, "artifact"},
		{"an approval for an old epoch", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Approval = f.approvalEnv(t, f.o, e2e.ApprovalBody{V: 1, Artifact: artID, Epoch: 1, User: f.c.ID, FP: f.c.FP})
			return ch
		}, 400, RuleApproval, "epoch"},
		{"an approval for another user", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Approval = f.approvalEnv(t, f.o, e2e.ApprovalBody{V: 1, Artifact: artID, Epoch: 2, User: f.b.ID, FP: f.c.FP})
			return ch
		}, 400, RuleApproval, "user"},
		{"an approval for another fingerprint", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Approval = f.approvalEnv(t, f.o, e2e.ApprovalBody{V: 1, Artifact: artID, Epoch: 2, User: f.c.ID, FP: f.b.FP})
			return ch
		}, 400, RuleApproval, "fp"},

		// 400: the wraps
		{"no wraps", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Wraps = nil
			return ch
		}, 400, RuleApprovalWraps, "epoch 1"},
		{"a wrap missing for the current epoch", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Wraps = ch.Wraps[:1]
			return ch
		}, 400, RuleApprovalWraps, "epoch 2"},
		{"a wrap missing for an earlier epoch", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Wraps = ch.Wraps[1:]
			return ch
		}, 400, RuleApprovalWraps, "epoch 1"},
		{"a wrap for a future epoch", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Wraps = append(ch.Wraps, ApprovalWrap{Epoch: 3, Wrapped: make([]byte, 81)})
			return ch
		}, 400, RuleApprovalWraps, "epoch 3"},
		{"a wrap given twice", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Wraps = append(ch.Wraps, ch.Wraps[0])
			return ch
		}, 400, RuleApprovalWraps, "twice"},
		{"a wrap of the wrong size", func(t *testing.T, f *fixture) ApprovalChange {
			ch := f.approval(t, f.o, f.c)
			ch.Wraps[1].Wrapped = make([]byte, 80)
			return ch
		}, 400, RuleApprovalWraps, "81 bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			ch := c.build(t, f)
			_, err := CheckApproval(f.cur, f.dir, ch)
			refused(t, err, c.status, c.rule, c.msg)
		})
	}
}

// An approval the record's owner signs while the record is at team none is
// refused for the state, ahead of every check about the user.
func TestCheckApprovalTeamNoneComesBeforeTheUser(t *testing.T) {
	f := newFixture(t)
	b := *f.cur.Latest
	b.Team = "none"
	f.setLatest(&b)
	_, err := CheckApproval(f.cur, f.dir, f.approval(t, f.o, f.x))
	refused(t, err, 409, RuleTeamNone, "team")
}
