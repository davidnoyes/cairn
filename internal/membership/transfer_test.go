package membership

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

func offerHash() string { return commit(60) }

// takeOver returns a same-epoch record in which a, the editor, becomes the
// owner under an owner's offer, and o stays as an editor.
func (f *fixture) takeOver() *e2e.MembershipBody {
	b := f.next()
	b.Owner, b.OwnerFP, b.Transfer = f.a.ID, f.a.FP, offerHash()
	b.Members = []e2e.Member{member(f.b, "viewer"), member(f.o, "editor")}
	return b
}

// takeOverExcluding returns the next-epoch version: o is excluded, along
// with tm, who holds a wrap.
func (f *fixture) takeOverExcluding() *e2e.MembershipBody {
	b := f.takeOver()
	b.Epoch, b.AKCommit = 3, commit(3)
	b.Members = []e2e.Member{member(f.b, "viewer")}
	b.Excluded = []e2e.ExcludedEntry{excluded(f.o), excluded(f.tm), excluded(f.x)}
	return b
}

func estates(n int) []EstateIn {
	var out []EstateIn
	for e := 1; e <= n; e++ {
		out = append(out, EstateIn{Epoch: e, Sealed: make([]byte, 61)})
	}
	return out
}

// accepting signs b as a, the new owner, and marks it as accepting an
// owner's offer.
func (f *fixture) accepting(t *testing.T, b *e2e.MembershipBody, wraps []WrapIn, est []EstateIn) Change {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(f.a.seed, f.a.ID, "membership", raw)
	if err != nil {
		t.Fatal(err)
	}
	return Change{Envelope: env, Wraps: wraps, Estate: est, Accept: &Acceptance{NewOwner: f.a.User, OfferHash: offerHash()}}
}

func TestCheckAcceptKeepsThePreviousOwnerAsEditor(t *testing.T) {
	f := newFixture(t)
	res, err := Check(f.cur, f.dir, f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2)))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted || res.NewEpoch {
		t.Errorf("Accepted %v NewEpoch %v, want true and false", res.Accepted, res.NewEpoch)
	}
	if res.Record.OwnerID != f.a.ID || res.Record.Transfer != offerHash() || res.Record.Handover != "" {
		t.Errorf("record %+v does not keep the owner and transfer", res.Record)
	}
	if len(res.Estate) != 2 || len(res.Wraps) != 2 {
		t.Errorf("%d estate copies and %d wraps, want 2 and 2", len(res.Estate), len(res.Wraps))
	}
}

func TestCheckAcceptExcludesThePreviousOwnerAtTheNextEpoch(t *testing.T) {
	f := newFixture(t)
	res, err := Check(f.cur, f.dir, f.accepting(t, f.takeOverExcluding(), wrapsFor(f.b, 3), estates(3)))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted || !res.NewEpoch || len(res.Estate) != 3 {
		t.Errorf("Accepted %v NewEpoch %v estate %d", res.Accepted, res.NewEpoch, len(res.Estate))
	}
}

func TestCheckAcceptAdminHandover(t *testing.T) {
	f := newFixture(t)
	f.o.Active = false
	b := f.takeOverExcluding()
	b.Transfer, b.Handover = "", "admin"
	ch := f.accepting(t, b, wrapsFor(f.b, 3), estates(3))
	ch.Accept.OfferHash = ""
	res, err := Check(f.cur, f.dir, ch)
	if err != nil {
		t.Fatal(err)
	}
	if res.Record.Handover != "admin" || res.Record.Transfer != "" {
		t.Errorf("record %+v does not keep the handover", res.Record)
	}

	// A deactivated owner cannot be kept.
	b = f.takeOver()
	b.Transfer, b.Handover = "", "admin"
	ch = f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
	ch.Accept.OfferHash = ""
	_, err = Check(f.cur, f.dir, ch)
	refused(t, err, 400, RuleNewMember, "not active")
}

// A deactivated user is missing from the directory a client reads, so the
// client writes their user ID as the email of their excluded entry; any other
// email must be theirs.
func TestCheckExcludedEmailOfADeactivatedUser(t *testing.T) {
	for _, c := range []struct {
		name  string
		email string
		want  bool
	}{
		{"the user ID, as the client writes for a user the directory lacks", "u-o", true},
		{"their email", "o@x.y", true},
		{"another email", "other@x.y", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.o.Active = false
			b := f.takeOverExcluding()
			b.Transfer, b.Handover = "", "admin"
			b.Excluded[0].Email = c.email
			ch := f.accepting(t, b, wrapsFor(f.b, 3), estates(3))
			ch.Accept.OfferHash = ""
			_, err := Check(f.cur, f.dir, ch)
			if c.want {
				if err != nil {
					t.Fatalf("Check: %v", err)
				}
				return
			}
			refused(t, err, 400, RuleExcludedEntry, "email")
		})
	}
}

func TestCheckAcceptRefusals(t *testing.T) {
	cases := []struct {
		name   string
		build  func(t *testing.T, f *fixture) Change
		status int
		rule   Rule
		msg    string
	}{
		{"signed by someone other than the new owner", func(t *testing.T, f *fixture) Change {
			ch := f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2))
			ch.Envelope.Signer = f.o.ID
			return ch
		}, 400, RuleSigner, "not the owner"},
		{"signed under another key", func(t *testing.T, f *fixture) Change {
			ch := f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2))
			raw, _ := json.Marshal(f.takeOver())
			ch.Envelope, _ = e2e.NewEnvelope(f.o.seed, f.a.ID, "membership", raw)
			return ch
		}, 400, RuleSignature, "verify"},
		{"owner is still the previous owner", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Owner = f.o.ID
			return f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
		}, 400, RuleOwner, "owner"},
		{"ownerFp is not the new owner's", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.OwnerFP = f.o.FP
			return f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
		}, 400, RuleOwnerFP, "ownerFp"},
		{"transfer is not the offer's hash", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Transfer = commit(61)
			return f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
		}, 400, RuleTransfer, "transfer"},
		{"transfer is empty for an owner's offer", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Transfer = ""
			return f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
		}, 400, RuleTransfer, "transfer"},
		{"handover on an owner's offer", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Handover = "admin"
			return f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
		}, 400, RuleTransfer, "handover"},
		{"an administrator's offer without handover", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Transfer = ""
			ch := f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
			ch.Accept.OfferHash = ""
			return ch
		}, 400, RuleTransfer, "handover"},
		{"an administrator's offer with a transfer", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Handover = "admin"
			ch := f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
			ch.Accept.OfferHash = ""
			return ch
		}, 400, RuleTransfer, "transfer"},
		{"an ordinary record sets transfer", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Transfer = offerHash()
			return f.change(t, b, nil, nil)
		}, 400, RuleTransfer, "transfer"},
		{"an ordinary record sets handover", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Handover = "admin"
			return f.change(t, b, nil, nil)
		}, 400, RuleTransfer, "handover"},
		{"the new owner is a viewer", func(t *testing.T, f *fixture) Change {
			ch := f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2))
			ch.Accept.NewOwner = f.b.User
			return ch
		}, 409, RuleOwner, "listed editor"},
		{"the new owner is not listed", func(t *testing.T, f *fixture) Change {
			ch := f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2))
			ch.Accept.NewOwner = f.c.User
			return ch
		}, 409, RuleOwner, "listed editor"},
		{"the new owner is inactive", func(t *testing.T, f *fixture) Change {
			ch := f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2))
			u := *f.a.User
			u.Active = false
			ch.Accept.NewOwner = &u
			return ch
		}, 409, RuleOwner, "active, verified"},
		{"the new owner is unverified", func(t *testing.T, f *fixture) Change {
			ch := f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2))
			u := *f.a.User
			u.Verified = false
			ch.Accept.NewOwner = &u
			return ch
		}, 409, RuleOwner, "active, verified"},
		{"the new owner's key is not the listed one", func(t *testing.T, f *fixture) Change {
			ch := f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2))
			u := *f.a.User
			u.FP = f.c.FP
			ch.Accept.NewOwner = &u
			return ch
		}, 409, RuleOwner, "key"},
		{"the new owner is listed", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Members = []e2e.Member{member(f.a, "editor"), member(f.b, "viewer"), member(f.o, "editor")}
			return f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
		}, 400, RuleMembers, "owner"},
		{"the new owner is excluded", func(t *testing.T, f *fixture) Change {
			b := f.takeOverExcluding()
			b.Excluded = []e2e.ExcludedEntry{excluded(f.a), excluded(f.o), excluded(f.tm), excluded(f.x)}
			return f.accepting(t, b, wrapsFor(f.b, 3), estates(3))
		}, 400, RuleExcludedMatch, "owner"},
		{"the previous owner needs a wrap of every epoch", func(t *testing.T, f *fixture) Change {
			return f.accepting(t, f.takeOver(), wrapsFor(f.o, 2), estates(2))
		}, 400, RuleWraps, "missing the wrap for u-o at epoch 1"},
		{"the previous owner dropped in a same-epoch record", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Members = []e2e.Member{member(f.b, "viewer")}
			return f.accepting(t, b, nil, estates(2))
		}, 400, RuleSameEpoch, "removes u-o"},
		{"the previous owner dropped without being excluded", func(t *testing.T, f *fixture) Change {
			b := f.takeOverExcluding()
			b.Excluded = []e2e.ExcludedEntry{excluded(f.tm), excluded(f.x)}
			return f.accepting(t, b, wrapsFor(f.b, 3), estates(3))
		}, 400, RuleNextEpoch, "u-o"},
		{"the previous owner excluded under the wrong fp", func(t *testing.T, f *fixture) Change {
			b := f.takeOverExcluding()
			b.Excluded[0].FP = f.a.FP
			return f.accepting(t, b, wrapsFor(f.b, 3), estates(3))
		}, 400, RuleExcludedEntry, "fp"},
		{"an estate copy is missing an epoch", func(t *testing.T, f *fixture) Change {
			return f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), estates(2)[1:])
		}, 400, RuleEstate, "every epoch"},
		{"an estate copy is given twice", func(t *testing.T, f *fixture) Change {
			est := estates(2)
			est[1].Epoch = 1
			return f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), est)
		}, 400, RuleEstate, "every epoch"},
		{"an estate copy is the wrong size", func(t *testing.T, f *fixture) Change {
			est := estates(2)
			est[0].Sealed = make([]byte, 60)
			return f.accepting(t, f.takeOver(), wrapsFor(f.o, 1, 2), est)
		}, 400, RuleEstate, "bytes"},
		{"a stale prev", func(t *testing.T, f *fixture) Change {
			b := f.takeOver()
			b.Prev = commit(7)
			return f.accepting(t, b, wrapsFor(f.o, 1, 2), estates(2))
		}, 409, RulePrev, "prev"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			ch := c.build(t, f)
			_, err := Check(f.cur, f.dir, ch)
			refused(t, err, c.status, c.rule, c.msg)
		})
	}
}

func TestApplyAcceptanceThroughTheStore(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	o := account(t, s, "o@x.y")
	a := account(t, s, "a@x.y")
	first := &e2e.MembershipBody{
		V: 1, Artifact: artID, Epoch: 1, Seq: 1, Owner: o.ID, OwnerFP: o.FP, AKCommit: commit(1),
		Members: []e2e.Member{member(a, "editor")}, Excluded: []e2e.ExcludedEntry{}, Team: "none",
	}
	_, err = s.CreateOwnedArtifact(artID, o.ID, func(tx *store.ArtifactTx) error {
		dir := TxDirectory(tx)
		cur, err := Load(tx, dir)
		if err != nil {
			return err
		}
		res, err := Check(cur, dir, Change{Envelope: signedBy(t, o, first), Wraps: wrapsFor(a, 1), Estate: estate(1)})
		if err != nil {
			return err
		}
		return Apply(tx, res)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.WithArtifact(artID, func(tx *store.ArtifactTx) error {
		return tx.PutOffer(store.Offer{To: a.ID, By: "owner", Hash: offerHash(),
			Envelope: &store.Envelope{Body: []byte("{}"), Sig: []byte("s"), Signer: o.ID}})
	})
	if err != nil {
		t.Fatal(err)
	}

	second := &e2e.MembershipBody{
		V: 1, Artifact: artID, Epoch: 1, Seq: 2, Prev: e2e.BodyHash(signedBy(t, o, first).Body), Owner: a.ID, OwnerFP: a.FP,
		AKCommit: commit(1), Members: []e2e.Member{member(o, "editor")}, Excluded: []e2e.ExcludedEntry{}, Team: "none",
		Transfer: offerHash(),
	}
	err = land(t, s, Change{Envelope: signedBy(t, a, second), Wraps: wrapsFor(o, 1), Estate: estate(1),
		Accept: &Acceptance{NewOwner: a.User, OfferHash: offerHash()}})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.ArtifactByID(artID)
	if err != nil || got.OwnerID != a.ID {
		t.Fatalf("owner %q (%v), want %q", got.OwnerID, err, a.ID)
	}
	err = s.WithArtifact(artID, func(tx *store.ArtifactTx) error {
		wraps, err := tx.Wraps()
		if err != nil {
			return err
		}
		if len(wraps) != 1 || wraps[0].UserID != o.ID {
			t.Errorf("wraps %+v, want only the previous owner's", wraps)
		}
		estates, err := tx.Estates()
		if err != nil {
			return err
		}
		if len(estates) != 1 {
			t.Errorf("%d estate copies, want 1", len(estates))
		}
		accepted, err := tx.AcceptedOffers()
		if err != nil {
			return err
		}
		if accepted[offerHash()] == nil {
			t.Errorf("the offer is not accepted: %+v", accepted)
		}
		rec, err := tx.LatestRecord()
		if err != nil {
			return err
		}
		if rec.Transfer != offerHash() {
			t.Errorf("record transfer %q", rec.Transfer)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
