package membership

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// managerFixture is the fixture with m, a manager, listed after the editor a
// and the viewer b, holding wraps for epochs 1 and 2.
func managerFixture(t *testing.T) (*fixture, *tUser) {
	t.Helper()
	f := newFixture(t)
	m := f.add(t, "u-m", "m@x.y")
	b := *f.cur.Latest
	b.Members = append(append([]e2e.Member{}, b.Members...), member(m, "manager"))
	f.setLatest(&b)
	for e := 1; e <= 2; e++ {
		f.cur.Wraps = append(f.cur.Wraps, store.Wrap{UserID: m.ID, Epoch: e, Wrapped: make([]byte, 81), FP: m.FP})
	}
	return f, m
}

// addMember lists u in b under role, keeping members sorted by user ID.
func addMember(b *e2e.MembershipBody, u *tUser, role string) {
	b.Members = append(b.Members, member(u, role))
	sort.Slice(b.Members, func(i, j int) bool { return b.Members[i].User < b.Members[j].User })
}

// asManager turns b into the version 2 record m signs.
func asManager(b *e2e.MembershipBody, m *tUser) *e2e.MembershipBody {
	b.V, b.Signer, b.SignerFP = 2, m.ID, m.FP
	return b
}

// byManager signs b, as a version 2 record, with m's key and ID.
func (f *fixture) byManager(t *testing.T, m *tUser, b *e2e.MembershipBody, wraps []WrapIn, est []EstateIn) Change {
	t.Helper()
	raw, err := json.Marshal(asManager(b, m))
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(m.seed, m.ID, "membership", raw)
	if err != nil {
		t.Fatal(err)
	}
	return Change{Envelope: env, Wraps: wraps, Estate: est}
}

// managerNextEpoch is the next-epoch change a manager starts: everyone
// stays and tm is excluded, with every listed member's wrap of epoch 3 and
// the owner's. The record is not yet version 2.
func managerNextEpoch(f *fixture, m *tUser) (*e2e.MembershipBody, []WrapIn) {
	b := f.next()
	b.Epoch, b.AKCommit = 3, commit(3)
	b.Excluded = []e2e.ExcludedEntry{excluded(f.tm), b.Excluded[0]}
	wraps := append(wrapsFor(f.a, 3), wrapsFor(f.b, 3)...)
	wraps = append(wraps, wrapsFor(m, 3)...)
	return b, append(wraps, wrapsFor(f.o, 3)...)
}

func TestManagerAcceptance(t *testing.T) {
	t.Run("same epoch: add a member", func(t *testing.T) {
		f, m := managerFixture(t)
		b := f.next()
		addMember(b, f.c, "viewer")
		res := check(t, f, f.byManager(t, m, b, wrapsFor(f.c, 1, 2), nil))
		r := res.Record
		if r.Envelope.Signer != m.ID || r.OwnerID != f.o.ID || res.Body.Signer != m.ID || res.Body.SignerFP != m.FP {
			t.Errorf("record %+v, body %+v", r, res.Body)
		}
		if len(res.Estate) != 0 || res.NewEpoch {
			t.Errorf("estate %v, new epoch %v", res.Estate, res.NewEpoch)
		}
	})
	t.Run("same epoch: team, public writes, promote a viewer", func(t *testing.T) {
		f, m := managerFixture(t)
		b := f.next()
		b.Team, b.PublicWrites = "editor", true
		b.Members[1].Role = "editor"
		check(t, f, f.byManager(t, m, b, nil, nil))
	})
	t.Run("same epoch: make public", func(t *testing.T) {
		f, m := managerFixture(t)
		b := f.next()
		b.Public = true
		ch := f.byManager(t, m, b, nil, nil)
		ch.LinkTokenHash = linkHash()
		res := check(t, f, ch)
		if res.PublicTokenHash != linkHash() {
			t.Errorf("public token hash %q", res.PublicTokenHash)
		}
	})
	t.Run("next epoch with the owner's wrap", func(t *testing.T) {
		f, m := managerFixture(t)
		b, wraps := managerNextEpoch(f, m)
		res := check(t, f, f.byManager(t, m, b, wraps, nil))
		if !res.NewEpoch || len(res.Estate) != 0 {
			t.Errorf("new epoch %v, estate %v", res.NewEpoch, res.Estate)
		}
		var owner *store.Wrap
		for i, w := range res.Wraps {
			if w.UserID == f.o.ID {
				owner = &res.Wraps[i]
			}
		}
		if owner == nil || owner.Epoch != 3 || owner.FP != f.o.FP {
			t.Errorf("the owner's wrap: %+v in %s", owner, wrapKeys(res.Wraps))
		}
	})
	t.Run("next epoch demotes an editor", func(t *testing.T) {
		f, m := managerFixture(t)
		b, wraps := managerNextEpoch(f, m)
		b.Members[0].Role = "viewer"
		check(t, f, f.byManager(t, m, b, wraps, nil))
	})
	t.Run("next epoch removes a member", func(t *testing.T) {
		f, m := managerFixture(t)
		b := f.next()
		b.Epoch, b.AKCommit = 3, commit(3)
		b.Members = []e2e.Member{member(f.a, "editor"), member(m, "manager")}
		b.Excluded = []e2e.ExcludedEntry{excluded(f.b), excluded(f.tm), b.Excluded[0]}
		wraps := append(wrapsFor(f.a, 3), wrapsFor(m, 3)...)
		check(t, f, f.byManager(t, m, b, append(wraps, wrapsFor(f.o, 3)...), nil))
	})
	t.Run("a manager's key is the current one", func(t *testing.T) {
		f, m := managerFixture(t)
		old := rekey(t, m)
		b := f.next()
		b.PublicWrites = true
		// The listed fp is the old one, and the manager signs with the new.
		check(t, f, f.byManager(t, m, b, nil, nil))
		if f.cur.Latest.Members[2].FP != old {
			t.Fatalf("the latest record lists %s, want the old fp %s", f.cur.Latest.Members[2].FP, old)
		}
	})
}

func TestManagerRefusals(t *testing.T) {
	cases := []struct {
		name   string
		build  func(t *testing.T, f *fixture, m *tUser) Change
		status int
		rule   Rule
		msg    string
	}{
		{"signer not listed", func(t *testing.T, f *fixture, m *tUser) Change {
			return f.byManager(t, f.c, f.next(), nil, nil)
		}, 400, RuleSignerRole, "does not list them as a manager"},
		{"signer listed as editor", func(t *testing.T, f *fixture, m *tUser) Change {
			return f.byManager(t, f.a, f.next(), nil, nil)
		}, 400, RuleSignerRole, "does not list them as a manager"},
		{"signer listed as viewer", func(t *testing.T, f *fixture, m *tUser) Change {
			return f.byManager(t, f.b, f.next(), nil, nil)
		}, 400, RuleSignerRole, "does not list them as a manager"},
		{"signer is not a user", func(t *testing.T, f *fixture, m *tUser) Change {
			ch := f.byManager(t, m, f.next(), nil, nil)
			delete(f.dir, m.ID)
			return ch
		}, 400, RuleSigner, "not a user"},
		{"first record signed by a manager", func(t *testing.T, f *fixture, m *tUser) Change {
			b, w, e := f.first()
			ch := f.byManager(t, f.a, b, w, e)
			f.creation()
			return ch
		}, 400, RuleSigner, "not the owner"},
		{"accepting record signed by a manager", func(t *testing.T, f *fixture, m *tUser) Change {
			ch := f.byManager(t, m, f.next(), nil, nil)
			ch.Accept = &Acceptance{NewOwner: f.a.User, OfferHash: commit(7)}
			return ch
		}, 400, RuleSigner, "not the owner"},
		{"manager signs version 1", func(t *testing.T, f *fixture, m *tUser) Change {
			raw, _ := json.Marshal(f.next())
			env, _ := e2e.NewEnvelope(m.seed, m.ID, "membership", raw)
			return Change{Envelope: env}
		}, 400, RuleVersion, "a manager signs a version 2 record"},
		{"owner signs version 2", func(t *testing.T, f *fixture, m *tUser) Change {
			return f.change(t, asManager(f.next(), m), nil, nil)
		}, 400, RuleVersion, "the owner signs a version 1 record"},
		{"body signer is another user", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			ch := f.byManager(t, m, b, nil, nil)
			b.Signer, b.SignerFP = f.a.ID, f.a.FP
			raw, _ := json.Marshal(b)
			ch.Envelope, _ = e2e.NewEnvelope(m.seed, m.ID, "membership", raw)
			return ch
		}, 400, RuleSigner, "body's signer"},
		{"signerFp is not current", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			ch := f.byManager(t, m, b, nil, nil)
			b.SignerFP = commit(5)
			raw, _ := json.Marshal(b)
			ch.Envelope, _ = e2e.NewEnvelope(m.seed, m.ID, "membership", raw)
			return ch
		}, 400, RuleSignerFP, "current fingerprint"},
		{"signed under the manager's old key", func(t *testing.T, f *fixture, m *tUser) Change {
			ch := f.byManager(t, m, f.next(), nil, nil)
			rekey(t, m)
			return ch
		}, 400, RuleSignature, "verify"},
		{"signed by another key", func(t *testing.T, f *fixture, m *tUser) Change {
			raw, _ := json.Marshal(asManager(f.next(), m))
			env, _ := e2e.NewEnvelope(f.a.seed, m.ID, "membership", raw)
			return Change{Envelope: env}
		}, 400, RuleSignature, "verify"},
		{"manager changes the owner", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Owner = f.a.ID
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleOwner, "owner"},
		{"manager changes ownerFp", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.OwnerFP = f.a.FP
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleOwnerFP, "ownerFp"},
		{"manager sets transfer", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Transfer = commit(7)
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleTransfer, "transfer must be empty"},
		{"manager sets handover", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Handover = "admin"
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleTransfer, "handover must be empty"},
		{"manager adds a manager", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Members[1].Role = "manager"
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleManagerChange, "u-b"},
		{"manager lists a new manager", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			addMember(b, f.c, "manager")
			return f.byManager(t, m, b, wrapsFor(f.c, 1, 2), nil)
		}, 400, RuleManagerChange, "u-c"},
		{"manager removes a manager", func(t *testing.T, f *fixture, m *tUser) Change {
			b, wraps := managerNextEpoch(f, m)
			b.Members = b.Members[:2]
			b.Excluded = []e2e.ExcludedEntry{excluded(m), excluded(f.tm), b.Excluded[1]}
			return f.byManager(t, m, b, append(wraps[:2:2], wrapsFor(f.o, 3)...), nil)
		}, 400, RuleManagerChange, "u-m"},
		{"manager demotes a manager", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Members[2].Role = "editor"
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleManagerChange, "u-m"},
		{"manager changes a manager's fp", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Members[2].FP = commit(9)
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleManagerChange, "u-m"},
		{"manager lists an excluded user again", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			addMember(b, f.x, "viewer")
			b.Excluded = []e2e.ExcludedEntry{}
			return f.byManager(t, m, b, wrapsFor(f.x, 1, 2), nil)
		}, 400, RuleKeepExcluded, "u-x"},
		{"manager drops an excluded entry without listing the user", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Excluded = []e2e.ExcludedEntry{}
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleKeepExcluded, "u-x"},
		{"manager's next epoch without the owner's wrap", func(t *testing.T, f *fixture, m *tUser) Change {
			b, wraps := managerNextEpoch(f, m)
			return f.byManager(t, m, b, wraps[:3], nil)
		}, 400, RuleWraps, "missing the wrap for u-o at epoch 3"},
		{"manager's same epoch with the owner's wrap", func(t *testing.T, f *fixture, m *tUser) Change {
			return f.byManager(t, m, f.next(), wrapsFor(f.o, 2), nil)
		}, 400, RuleWraps, "u-o, who is not a listed member"},
		{"manager's next epoch with the owner's wrap of an earlier epoch", func(t *testing.T, f *fixture, m *tUser) Change {
			b, wraps := managerNextEpoch(f, m)
			return f.byManager(t, m, b, append(wraps, wrapsFor(f.o, 2)...), nil)
		}, 400, RuleWraps, "not needed"},
		{"manager's next epoch with an estate copy", func(t *testing.T, f *fixture, m *tUser) Change {
			b, wraps := managerNextEpoch(f, m)
			return f.byManager(t, m, b, wraps, estate(3))
		}, 400, RuleEstate, "takes no estate copy"},
		{"manager's same epoch with an estate copy", func(t *testing.T, f *fixture, m *tUser) Change {
			return f.byManager(t, m, f.next(), nil, estate(2))
		}, 400, RuleEstate, "takes no estate copy"},
		{"manager's same epoch removal", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Members = b.Members[1:]
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleSameEpoch, "removes u-a"},
		{"manager's same epoch demotion", func(t *testing.T, f *fixture, m *tUser) Change {
			b := f.next()
			b.Members[0].Role = "viewer"
			return f.byManager(t, m, b, nil, nil)
		}, 400, RuleSameEpoch, "demotes u-a"},
		{"viewer account as a new editor by a manager", func(t *testing.T, f *fixture, m *tUser) Change {
			f.c.Role = store.RoleViewer
			b := f.next()
			addMember(b, f.c, "editor")
			return f.byManager(t, m, b, wrapsFor(f.c, 1, 2), nil)
		}, 400, RuleViewerAccount, "u-c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, m := managerFixture(t)
			ch := tc.build(t, f, m)
			res, err := Check(f.cur, f.dir, ch)
			if res != nil {
				t.Errorf("refusal returned a result: %+v", res)
			}
			refused(t, err, tc.status, tc.rule, tc.msg)
		})
	}
}

// TestOwnerChangesManagers checks the owner's record adds, removes, and
// demotes managers under the epoch rules.
func TestOwnerChangesManagers(t *testing.T) {
	t.Run("promotes an editor to manager in the same epoch", func(t *testing.T) {
		f, _ := managerFixture(t)
		b := f.next()
		b.Members[0].Role = "manager"
		check(t, f, f.change(t, b, nil, nil))
	})
	t.Run("lists a new manager in the same epoch", func(t *testing.T) {
		f, _ := managerFixture(t)
		b := f.next()
		addMember(b, f.c, "manager")
		check(t, f, f.change(t, b, wrapsFor(f.c, 1, 2), nil))
	})
	t.Run("demotes a manager to editor in the same epoch", func(t *testing.T) {
		f, _ := managerFixture(t)
		b := f.next()
		b.Members[2].Role = "editor"
		check(t, f, f.change(t, b, nil, nil))
	})
	t.Run("a same-epoch removal is refused", func(t *testing.T) {
		f, _ := managerFixture(t)
		b := f.next()
		b.Members = b.Members[:2]
		_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
		refused(t, err, 400, RuleSameEpoch, "removes u-m")
	})
	t.Run("a same-epoch demotion to viewer is refused", func(t *testing.T) {
		f, _ := managerFixture(t)
		b := f.next()
		b.Members[2].Role = "viewer"
		_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
		refused(t, err, 400, RuleSameEpoch, "demotes u-m")
	})
	t.Run("a next-epoch removal and demotion pass", func(t *testing.T) {
		f, m := managerFixture(t)
		b, wraps := managerNextEpoch(f, m)
		b.Members[2].Role = "viewer"
		// The owner signs: no owner's wrap, but an estate copy.
		if _, err := Check(f.cur, f.dir, f.change(t, b, wraps[:3], estate(3))); err != nil {
			t.Fatalf("demoted to viewer at the next epoch: %v", err)
		}
		b2, _ := managerNextEpoch(f, m)
		b2.Members = b2.Members[:2]
		b2.Excluded = []e2e.ExcludedEntry{excluded(m), excluded(f.tm), b2.Excluded[1]}
		if _, err := Check(f.cur, f.dir, f.change(t, b2, wraps[:2], estate(3))); err != nil {
			t.Fatalf("removed at the next epoch: %v", err)
		}
	})
	t.Run("the owner's next epoch takes no owner's wrap", func(t *testing.T) {
		f, m := managerFixture(t)
		b, wraps := managerNextEpoch(f, m)
		_, err := Check(f.cur, f.dir, f.change(t, b, wraps, estate(3)))
		refused(t, err, 400, RuleWraps, "u-o, who is not a listed member")
	})
}

// TestViewerAccountIsNotANewManager checks the viewer-account rule for the
// manager role, and its exception for an entry the previous record has.
func TestViewerAccountIsNotANewManager(t *testing.T) {
	t.Run("a new manager", func(t *testing.T) {
		f, _ := managerFixture(t)
		f.c.Role = store.RoleViewer
		b := f.next()
		addMember(b, f.c, "manager")
		_, err := Check(f.cur, f.dir, f.change(t, b, wrapsFor(f.c, 1, 2), nil))
		refused(t, err, 400, RuleViewerAccount, "member u-c "+viewerMsg)
	})
	t.Run("a listed viewer promoted to manager", func(t *testing.T) {
		f, _ := managerFixture(t)
		f.b.Role = store.RoleViewer
		b := f.next()
		b.Members[1].Role = "manager"
		_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
		refused(t, err, 400, RuleViewerAccount, "member u-b "+viewerMsg)
	})
	t.Run("a listed editor promoted to manager", func(t *testing.T) {
		f, _ := managerFixture(t)
		f.a.Role = store.RoleViewer
		b := f.next()
		b.Members[0].Role = "manager"
		_, err := Check(f.cur, f.dir, f.change(t, b, nil, nil))
		refused(t, err, 400, RuleViewerAccount, "member u-a "+viewerMsg)
	})
	t.Run("a listed manager stays, and may become an editor", func(t *testing.T) {
		f, m := managerFixture(t)
		m.Role = store.RoleViewer
		check(t, f, f.change(t, f.next(), nil, nil))
		b := f.next()
		b.Members[2].Role = "editor"
		check(t, f, f.change(t, b, nil, nil))
	})
}

// TestCheckNewOwnerAllowsAManager checks an ownership offer may go to a
// listed manager, and not to a listed viewer.
func TestCheckNewOwnerAllowsAManager(t *testing.T) {
	f, m := managerFixture(t)
	if err := CheckNewOwner(f.cur, m.User); err != nil {
		t.Errorf("a manager: %v", err)
	}
	if err := CheckNewOwner(f.cur, f.a.User); err != nil {
		t.Errorf("an editor: %v", err)
	}
	err := CheckNewOwner(f.cur, f.b.User)
	refused(t, err, 409, RuleOwner, "editor or manager")
	if !strings.Contains(err.Error(), "manager") {
		t.Errorf("message %q", err)
	}
}

// TestManagerApproves checks a listed manager approves a team member as an
// editor does, and one whose keys changed is refused.
func TestManagerApproves(t *testing.T) {
	f, m := managerFixture(t)
	res, err := CheckApproval(f.cur, f.dir, f.approval(t, m, f.c))
	if err != nil {
		t.Fatal(err)
	}
	if got := wrapKeys(res.Wraps); got != "u-c@1,u-c@2" || res.Approval.Envelope.Signer != m.ID {
		t.Errorf("wraps %s, approval %+v", got, res.Approval)
	}

	f, m = managerFixture(t)
	ch := f.approval(t, m, f.c)
	rekey(t, m)
	_, err = CheckApproval(f.cur, f.dir, ch)
	refused(t, err, 403, RuleApprover, "differ from the listed fingerprint")
}
