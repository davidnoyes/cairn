package membership

import (
	"encoding/json"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// handoverToSuccessor is a next-epoch record in which c, whom the latest
// record does not list, takes over from the deactivated owner o under an
// administrator's offer. a and b stay as members; o, the team member, and x
// are excluded. successor is what the server says about c.
func (f *fixture) handoverToSuccessor(t *testing.T, successor bool) Change {
	t.Helper()
	b := f.next()
	b.Owner, b.OwnerFP, b.Handover = f.c.ID, f.c.FP, "admin"
	b.Epoch, b.AKCommit = 3, commit(3)
	b.Excluded = []e2e.ExcludedEntry{excluded(f.o), excluded(f.tm), excluded(f.x)}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(f.c.seed, f.c.ID, "membership", raw)
	if err != nil {
		t.Fatal(err)
	}
	wraps := append(wrapsFor(f.a, 3), wrapsFor(f.b, 3)...)
	return Change{Envelope: env, Wraps: wraps, Estate: estates(3), Accept: &Acceptance{NewOwner: f.c.User, Successor: successor}}
}

func TestCheckAcceptByTheOwnersSuccessorWhoIsNotAMember(t *testing.T) {
	f := newFixture(t)
	f.o.Active = false
	// Without the server's word that c is the released successor, only a
	// listed editor takes ownership.
	_, err := Check(f.cur, f.dir, f.handoverToSuccessor(t, false))
	refused(t, err, 409, RuleOwner, "only a listed editor")
	res, err := Check(f.cur, f.dir, f.handoverToSuccessor(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted || res.Record.OwnerID != f.c.ID || res.Record.Handover != "admin" {
		t.Errorf("record %+v", res.Record)
	}
}

func TestCheckAcceptBySuccessorNeedsAnActiveVerifiedUser(t *testing.T) {
	for name, mutate := range map[string]func(*fixture){
		"inactive":   func(f *fixture) { f.c.Active = false },
		"unverified": func(f *fixture) { f.c.Verified = false },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.o.Active = false
			mutate(f)
			_, err := Check(f.cur, f.dir, f.handoverToSuccessor(t, true))
			refused(t, err, 409, RuleOwner, "not an active, verified user")
		})
	}
}
