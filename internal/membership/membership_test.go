package membership

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

const artID = "11111111-1111-4111-8111-111111111111"

// tUser is a directory user plus the Ed25519 seed that signs for them.
type tUser struct {
	*User
	seed []byte
}

func genKeys(t *testing.T) (xpub, seed, epub []byte) {
	t.Helper()
	_, xpub, err := e2e.GenerateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed, epub, err = e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return xpub, seed, epub
}

func fingerprint(xpub, epub []byte) string {
	return hex.EncodeToString(e2e.Fingerprint(xpub, epub))
}

func newUser(t *testing.T, id, email string) *tUser {
	t.Helper()
	xpub, seed, epub := genKeys(t)
	return &tUser{
		User: &User{ID: id, Email: email, X25519Pub: xpub, Ed25519Pub: epub, FP: fingerprint(xpub, epub), Verified: true, Active: true},
		seed: seed,
	}
}

// rekey gives u new keys in place, as a reset or a rotation does, and
// returns the fingerprint u had before.
func rekey(t *testing.T, u *tUser) string {
	t.Helper()
	old := u.FP
	xpub, seed, epub := genKeys(t)
	u.X25519Pub, u.Ed25519Pub, u.FP, u.seed = xpub, epub, fingerprint(xpub, epub), seed
	return old
}

type fakeDir map[string]*User

func (d fakeDir) User(id string) (*User, error) { return d[id], nil }

func (d fakeDir) Sharing(fp, email string) ([]string, error) {
	var ids []string
	for id, u := range d {
		if u.FP == fp || u.Email == email {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// fixture is an artifact at epoch 2, seq 3, owned by o: a is an editor, b a
// viewer, x excluded, team viewer, and tm a team member holding wraps for
// epochs 1 and 2. c is a verified user with no access.
type fixture struct {
	dir               fakeDir
	o, a, b, c, tm, x *tUser
	cur               Current
}

func (f *fixture) add(t *testing.T, id, email string) *tUser {
	u := newUser(t, id, email)
	f.dir[id] = u.User
	return u
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: fakeDir{}}
	f.o = f.add(t, "u-o", "o@x.y")
	f.a = f.add(t, "u-a", "a@x.y")
	f.b = f.add(t, "u-b", "b@x.y")
	f.c = f.add(t, "u-c", "c@x.y")
	f.tm = f.add(t, "u-t", "t@x.y")
	f.x = f.add(t, "u-x", "x@x.y")
	f.setLatest(&e2e.MembershipBody{
		V: 1, Artifact: artID, Epoch: 2, Seq: 3, Owner: f.o.ID, OwnerFP: f.o.FP, AKCommit: commit(2),
		Members:  []e2e.Member{{User: f.a.ID, Role: "editor", FP: f.a.FP}, {User: f.b.ID, Role: "viewer", FP: f.b.FP}},
		Excluded: []e2e.ExcludedEntry{{User: f.x.ID, FP: f.x.FP, Email: f.x.Email}},
		Team:     "viewer", Prev: commit(99),
	})
	f.cur.ArtifactID, f.cur.Owner = artID, f.o.User
	for _, u := range []*tUser{f.a, f.b, f.tm} {
		for e := 1; e <= 2; e++ {
			f.cur.Wraps = append(f.cur.Wraps, store.Wrap{UserID: u.ID, Epoch: e, Wrapped: make([]byte, 81), FP: u.FP})
		}
	}
	return f
}

func (f *fixture) setLatest(b *e2e.MembershipBody) {
	raw, err := json.Marshal(b)
	if err != nil {
		panic(err)
	}
	f.cur.Latest, f.cur.LatestHash = b, e2e.BodyHash(raw)
}

// creation turns f into an artifact with no record yet.
func (f *fixture) creation() {
	f.cur.Latest, f.cur.LatestHash, f.cur.Wraps = nil, "", nil
}

func commit(n int) string {
	sum := sha256.Sum256([]byte{byte(n)})
	return hex.EncodeToString(sum[:])
}

// next returns a no-op same-epoch record following the latest, with its own
// copies of the lists.
func (f *fixture) next() *e2e.MembershipBody {
	b := *f.cur.Latest
	b.Seq++
	b.Prev = f.cur.LatestHash
	b.Members = append([]e2e.Member{}, b.Members...)
	b.Excluded = append([]e2e.ExcludedEntry{}, b.Excluded...)
	return &b
}

// nextEpoch returns the simplest valid next-epoch change: everyone stays,
// and tm, the team member holding a wrap, is excluded.
func (f *fixture) nextEpoch() (*e2e.MembershipBody, []WrapIn, []EstateIn) {
	b := f.next()
	b.Epoch, b.AKCommit = 3, commit(3)
	b.Excluded = []e2e.ExcludedEntry{{User: f.tm.ID, FP: f.tm.FP, Email: f.tm.Email}, b.Excluded[0]}
	return b, append(wrapsFor(f.a, 3), wrapsFor(f.b, 3)...), estate(3)
}

// first returns a valid first record listing a as an editor.
func (f *fixture) first() (*e2e.MembershipBody, []WrapIn, []EstateIn) {
	b := &e2e.MembershipBody{
		V: 1, Artifact: artID, Epoch: 1, Seq: 1, Owner: f.o.ID, OwnerFP: f.o.FP, AKCommit: commit(1),
		Members:  []e2e.Member{{User: f.a.ID, Role: "editor", FP: f.a.FP}},
		Excluded: []e2e.ExcludedEntry{}, Team: "none",
	}
	return b, wrapsFor(f.a, 1), estate(1)
}

func (f *fixture) change(t *testing.T, b *e2e.MembershipBody, wraps []WrapIn, est []EstateIn) Change {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return f.signed(t, raw, wraps, est)
}

func (f *fixture) signed(t *testing.T, raw []byte, wraps []WrapIn, est []EstateIn) Change {
	t.Helper()
	env, err := e2e.NewEnvelope(f.o.seed, f.o.ID, "membership", raw)
	if err != nil {
		t.Fatal(err)
	}
	return Change{Envelope: env, Wraps: wraps, Estate: est}
}

func wrapsFor(u *tUser, epochs ...int) []WrapIn {
	var out []WrapIn
	for _, e := range epochs {
		out = append(out, WrapIn{User: u.ID, Epoch: e, Wrapped: make([]byte, 81)})
	}
	return out
}

func estate(epoch int) []EstateIn {
	return []EstateIn{{Epoch: epoch, Sealed: make([]byte, 61)}}
}

func linkHash() string { return commit(42) }

func member(u *tUser, role string) e2e.Member { return e2e.Member{User: u.ID, Role: role, FP: u.FP} }

func excluded(u *tUser) e2e.ExcludedEntry {
	return e2e.ExcludedEntry{User: u.ID, FP: u.FP, Email: u.Email}
}

func refused(t *testing.T, err error, status int, rule Rule, msg string) {
	t.Helper()
	var me *Error
	if !errors.As(err, &me) {
		t.Fatalf("got %v, want a %d refusal under %s", err, status, rule)
	}
	if me.Status != status || me.Rule != rule {
		t.Fatalf("got %d %s (%v), want %d %s", me.Status, me.Rule, me, status, rule)
	}
	if !strings.Contains(me.Error(), msg) {
		t.Fatalf("message %q does not say %q", me.Error(), msg)
	}
}

func TestCheckRefusals(t *testing.T) {
	cases := []struct {
		name   string
		build  func(t *testing.T, f *fixture) Change
		status int
		rule   Rule
		msg    string
	}{
		// 1. the owner's current key, and the owner as signer
		{"signer is not the owner", func(t *testing.T, f *fixture) Change {
			ch := f.change(t, f.next(), nil, nil)
			ch.Envelope.Signer = f.a.ID
			return ch
		}, 400, RuleSigner, "not the owner"},
		{"signed by another key", func(t *testing.T, f *fixture) Change {
			raw, _ := json.Marshal(f.next())
			env, _ := e2e.NewEnvelope(f.a.seed, f.o.ID, "membership", raw)
			return Change{Envelope: env}
		}, 400, RuleSignature, "verify"},
		{"signed under the owner's old key", func(t *testing.T, f *fixture) Change {
			ch := f.change(t, f.next(), nil, nil)
			rekey(t, f.o)
			return ch
		}, 400, RuleSignature, "verify"},
		{"signed for another purpose", func(t *testing.T, f *fixture) Change {
			raw, _ := json.Marshal(f.next())
			env, _ := e2e.NewEnvelope(f.o.seed, f.o.ID, "approval", raw)
			return Change{Envelope: env}
		}, 400, RuleSignature, "verify"},
		{"body with an unknown field", func(t *testing.T, f *fixture) Change {
			raw, _ := json.Marshal(f.next())
			raw = append(raw[:len(raw)-1], []byte(`,"extra":1}`)...)
			return f.signed(t, raw, nil, nil)
		}, 400, RuleSignature, "unknown field"},
		{"v is not 1", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.V = 2
			return f.change(t, b, nil, nil)
		}, 400, RuleSignature, "version"},

		// 2. artifact, owner, ownerFp
		{"another artifact", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Artifact = "22222222-2222-4222-8222-222222222222"
			return f.change(t, b, nil, nil)
		}, 400, RuleArtifact, "artifact"},
		{"another owner", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Owner = f.a.ID
			return f.change(t, b, nil, nil)
		}, 400, RuleOwner, "owner"},
		{"ownerFp is not the owner's current fingerprint", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.OwnerFP = f.a.FP
			return f.change(t, b, nil, nil)
		}, 400, RuleOwnerFP, "ownerFp"},

		// 3. seq and prev
		{"seq repeats the latest", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Seq = 3
			return f.change(t, b, nil, nil)
		}, 409, RuleSeq, "seq 3, want 4"},
		{"seq skips", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Seq = 5
			return f.change(t, b, nil, nil)
		}, 409, RuleSeq, "seq 5, want 4"},
		{"stale prev", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Prev = commit(7)
			return f.change(t, b, nil, nil)
		}, 409, RulePrev, "prev"},
		{"first record with seq 2", func(t *testing.T, f *fixture) Change {
			f.creation()
			b, w, e := f.first()
			b.Seq = 2
			return f.change(t, b, w, e)
		}, 409, RuleSeq, "want 1"},
		{"first record with a prev", func(t *testing.T, f *fixture) Change {
			f.creation()
			b, w, e := f.first()
			b.Prev = commit(7)
			return f.change(t, b, w, e)
		}, 409, RulePrev, "prev"},

		// 4. list shapes, roles, team, hex
		{"members is null", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members = nil
			return f.change(t, b, nil, nil)
		}, 400, RuleMembers, "null"},
		{"excluded is null", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Excluded = nil
			return f.change(t, b, nil, nil)
		}, 400, RuleExcluded, "null"},
		{"members out of order", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members[0], b.Members[1] = b.Members[1], b.Members[0]
			return f.change(t, b, nil, nil)
		}, 400, RuleMembers, "sorted"},
		{"member listed twice", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members[1] = b.Members[0]
			return f.change(t, b, nil, nil)
		}, 400, RuleMembers, "sorted"},
		{"members list the owner", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members = append(b.Members, member(f.o, "editor"))
			return f.change(t, b, nil, nil)
		}, 400, RuleMembers, "owner"},
		{"unknown role", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members[1].Role = "admin"
			return f.change(t, b, nil, nil)
		}, 400, RuleMembers, "role"},
		{"member fp in upper case", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members[1].FP = strings.ToUpper(b.Members[1].FP)
			return f.change(t, b, nil, nil)
		}, 400, RuleMembers, "fp"},
		{"unknown team", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Team = "everyone"
			return f.change(t, b, nil, nil)
		}, 400, RuleTeam, "team"},
		{"akCommit is not hex", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.AKCommit = "zz" + b.AKCommit[2:]
			return f.change(t, b, w, e)
		}, 400, RuleAKCommit, "64 lowercase hex"},
		{"excluded out of order", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded[0], b.Excluded[1] = b.Excluded[1], b.Excluded[0]
			return f.change(t, b, w, e)
		}, 400, RuleExcluded, "sorted"},
		{"excluded entry twice", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded[0] = b.Excluded[1]
			return f.change(t, b, w, e)
		}, 400, RuleExcluded, "sorted"},
		{"excluded fp is not hex", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded[0].FP = "abc"
			return f.change(t, b, w, e)
		}, 400, RuleExcluded, "fp"},
		{"excluded entry without an email", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded[0].Email = ""
			return f.change(t, b, w, e)
		}, 400, RuleExcluded, "no email"},

		// 5. excluded matches nobody listed, nor the owner
		{"excluded names the owner", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded = append([]e2e.ExcludedEntry{excluded(f.o)}, b.Excluded...)
			return f.change(t, b, w, e)
		}, 400, RuleExcludedMatch, "owner"},
		{"excluded user is also listed", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members = append(b.Members, member(f.x, "viewer"))
			return f.change(t, b, wrapsFor(f.x, 1, 2), nil)
		}, 400, RuleExcludedMatch, "u-x"},
		{"excluded fp matches a member", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded[0].FP = f.a.FP
			return f.change(t, b, w, e)
		}, 400, RuleExcludedMatch, "u-a"},
		{"excluded email matches a member", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded[0].Email = f.b.Email
			return f.change(t, b, w, e)
		}, 400, RuleExcludedMatch, "u-b"},

		// 6. a new or changed member is the current, unique, verified, active user
		{"new member is not a user", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members = append(b.Members, e2e.Member{User: "u-z", Role: "viewer", FP: commit(5)})
			return f.change(t, b, nil, nil)
		}, 400, RuleNewMember, "not a user"},
		{"new member is unverified", func(t *testing.T, f *fixture) Change {
			f.c.Verified = false
			b := f.next()
			b.Members = append(b.Members, member(f.c, "viewer"))
			return f.change(t, b, wrapsFor(f.c, 1, 2), nil)
		}, 400, RuleNewMember, "verified"},
		{"new member is deactivated", func(t *testing.T, f *fixture) Change {
			f.c.Active = false
			b := f.next()
			b.Members = append(b.Members, member(f.c, "viewer"))
			return f.change(t, b, wrapsFor(f.c, 1, 2), nil)
		}, 400, RuleNewMember, "active"},
		{"new member under an old fp", func(t *testing.T, f *fixture) Change {
			b := f.next()
			m := member(f.c, "viewer")
			b.Members = append(b.Members, m)
			rekey(t, f.c)
			return f.change(t, b, wrapsFor(f.c, 1, 2), nil)
		}, 400, RuleNewMember, "current"},
		{"new member shares a fingerprint", func(t *testing.T, f *fixture) Change {
			twin := *f.c.User
			twin.ID, twin.Email = "u-d", "d@x.y"
			f.dir[twin.ID] = &twin
			b := f.next()
			b.Members = append(b.Members, member(f.c, "viewer"))
			return f.change(t, b, wrapsFor(f.c, 1, 2), nil)
		}, 400, RuleNewMember, "shares"},
		{"new member shares an email", func(t *testing.T, f *fixture) Change {
			f.add(t, "u-d", f.c.Email)
			b := f.next()
			b.Members = append(b.Members, member(f.c, "viewer"))
			return f.change(t, b, wrapsFor(f.c, 1, 2), nil)
		}, 400, RuleNewMember, "shares"},
		{"member's fp changed to one not theirs", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members[1].FP = commit(6)
			return f.change(t, b, nil, nil)
		}, 400, RuleNewMember, "current"},

		// 7. epoch and akCommit
		{"epoch skips", func(t *testing.T, f *fixture) Change {
			b, w, _ := f.nextEpoch()
			b.Epoch = 4
			return f.change(t, b, w, estate(4))
		}, 400, RuleEpoch, "epoch 4"},
		{"epoch goes back", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Epoch = 1
			return f.change(t, b, nil, nil)
		}, 400, RuleEpoch, "epoch 1"},
		{"first record not at epoch 1", func(t *testing.T, f *fixture) Change {
			f.creation()
			b, _, _ := f.first()
			b.Epoch = 2
			return f.change(t, b, wrapsFor(f.a, 2), estate(2))
		}, 400, RuleEpoch, "want 1"},
		{"same epoch with a new akCommit", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.AKCommit = commit(3)
			return f.change(t, b, nil, nil)
		}, 400, RuleAKCommit, "keeps akCommit"},
		{"next epoch with the same akCommit", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.AKCommit = commit(2)
			return f.change(t, b, w, e)
		}, 400, RuleAKCommit, "new akCommit"},

		// 8. transfer and handover
		{"transfer set", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Transfer = commit(8)
			return f.change(t, b, nil, nil)
		}, 400, RuleTransfer, "transfer"},
		{"handover set", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Handover = "admin"
			return f.change(t, b, nil, nil)
		}, 400, RuleTransfer, "handover"},

		// 9. what a same-epoch record cannot do
		{"same epoch removes a member", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members = b.Members[:1]
			return f.change(t, b, nil, nil)
		}, 400, RuleSameEpoch, "removes u-b"},
		{"same epoch demotes an editor", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members[0].Role = "viewer"
			return f.change(t, b, nil, nil)
		}, 400, RuleSameEpoch, "demotes u-a"},
		{"same epoch makes a public artifact private", func(t *testing.T, f *fixture) Change {
			l := *f.cur.Latest
			l.Public = true
			f.setLatest(&l)
			b := f.next()
			b.Public = false
			return f.change(t, b, nil, nil)
		}, 400, RuleSameEpoch, "private"},
		{"same epoch excludes a user", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Excluded = append([]e2e.ExcludedEntry{excluded(f.tm)}, b.Excluded...)
			return f.change(t, b, nil, nil)
		}, 400, RuleSameEpoch, "excludes u-t"},
		{"same epoch sets team none while a team member holds a wrap", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Team = "none"
			return f.change(t, b, nil, nil)
		}, 400, RuleSameEpoch, "u-t"},

		// 10. a next-epoch record accounts for everyone it removes or drops
		{"next epoch removes a member without excluding them", func(t *testing.T, f *fixture) Change {
			b, _, e := f.nextEpoch()
			b.Members = b.Members[:1]
			return f.change(t, b, wrapsFor(f.a, 3), e)
		}, 400, RuleNextEpoch, "u-b"},
		{"next epoch neither lists nor excludes a team member", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded = b.Excluded[1:]
			return f.change(t, b, w, e)
		}, 400, RuleNextEpoch, "u-t"},

		// 11. how excluded changes
		{"drops an entry without listing the user", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Excluded = []e2e.ExcludedEntry{}
			return f.change(t, b, nil, nil)
		}, 400, RuleExcludedDrop, "u-x"},
		{"carried entry changes", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Excluded[0].Email = "other@x.y"
			return f.change(t, b, nil, nil)
		}, 400, RuleExcludedEntry, "changes"},
		{"new entry with another email", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded[0].Email = "t2@x.y"
			return f.change(t, b, w, e)
		}, 400, RuleExcludedEntry, "email"},
		{"new entry with another fp", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded[0].FP = commit(9)
			return f.change(t, b, w, e)
		}, 400, RuleExcludedEntry, "fp"},
		{"new entry under the team member's current fp, not the wrap's", func(t *testing.T, f *fixture) Change {
			rekey(t, f.tm)
			b, w, e := f.nextEpoch() // excludes tm under the new fp
			return f.change(t, b, w, e)
		}, 400, RuleExcludedEntry, "fp"},
		{"new entry for a user who was never listed and holds no wrap", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			b.Excluded = []e2e.ExcludedEntry{excluded(f.c), b.Excluded[0], b.Excluded[1]}
			return f.change(t, b, w, e)
		}, 400, RuleExcludedEntry, "u-c was not listed and holds no wrap"},
		{"first record excludes someone", func(t *testing.T, f *fixture) Change {
			f.creation()
			b, w, e := f.first()
			b.Excluded = []e2e.ExcludedEntry{excluded(f.x)}
			return f.change(t, b, w, e)
		}, 400, RuleExcludedEntry, "first record"},

		// 12. wraps match exactly
		{"same epoch add without every epoch", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members = append(b.Members, member(f.c, "viewer"))
			return f.change(t, b, wrapsFor(f.c, 2), nil)
		}, 400, RuleWraps, "missing"},
		{"wrap for a member who already holds it", func(t *testing.T, f *fixture) Change {
			return f.change(t, f.next(), wrapsFor(f.a, 1), nil)
		}, 400, RuleWraps, "not needed"},
		{"wrap given twice", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members = append(b.Members, member(f.c, "viewer"))
			return f.change(t, b, wrapsFor(f.c, 1, 2, 2), nil)
		}, 400, RuleWraps, "twice"},
		{"wrap of the wrong size", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Members = append(b.Members, member(f.c, "viewer"))
			w := wrapsFor(f.c, 1, 2)
			w[1].Wrapped = make([]byte, 80)
			return f.change(t, b, w, nil)
		}, 400, RuleWraps, "81 bytes"},
		{"wrap for someone not listed", func(t *testing.T, f *fixture) Change {
			return f.change(t, f.next(), wrapsFor(f.c, 1, 2), nil)
		}, 400, RuleWraps, "not a listed member"},
		{"wrap for the owner", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			return f.change(t, b, append(w, wrapsFor(f.o, 3)...), e)
		}, 400, RuleWraps, "not a listed member"},
		{"next epoch without a member's new-epoch wrap", func(t *testing.T, f *fixture) Change {
			b, _, e := f.nextEpoch()
			return f.change(t, b, wrapsFor(f.a, 3), e)
		}, 400, RuleWraps, "u-b at epoch 3"},
		{"next epoch with a wrap for a later epoch", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			return f.change(t, b, append(w, wrapsFor(f.a, 4)...), e)
		}, 400, RuleWraps, "not needed"},
		{"first record without a member's wrap", func(t *testing.T, f *fixture) Change {
			f.creation()
			b, _, e := f.first()
			return f.change(t, b, nil, e)
		}, 400, RuleWraps, "missing"},
		{"member re-listed under a reset key without wraps", func(t *testing.T, f *fixture) Change {
			rekey(t, f.b)
			b := f.next()
			b.Members[1].FP = f.b.FP
			return f.change(t, b, nil, nil)
		}, 400, RuleWraps, "missing"},
		{"next epoch lists a member with no account", func(t *testing.T, f *fixture) Change {
			delete(f.dir, f.b.ID)
			b, w, e := f.nextEpoch()
			return f.change(t, b, w, e)
		}, 400, RuleWraps, "no account"},
		{"next epoch keeps a reset member under their old fp", func(t *testing.T, f *fixture) Change {
			rekey(t, f.b)
			b, w, e := f.nextEpoch()
			return f.change(t, b, w, e)
		}, 400, RuleStaleFP, "next epoch lists u-b under a fingerprint that is no longer theirs"},

		// 13. estate
		{"same epoch with an estate copy", func(t *testing.T, f *fixture) Change {
			return f.change(t, f.next(), nil, estate(2))
		}, 400, RuleEstate, "none"},
		{"next epoch without an estate copy", func(t *testing.T, f *fixture) Change {
			b, w, _ := f.nextEpoch()
			return f.change(t, b, w, nil)
		}, 400, RuleEstate, "exactly one"},
		{"estate copy for the wrong epoch", func(t *testing.T, f *fixture) Change {
			b, w, _ := f.nextEpoch()
			return f.change(t, b, w, estate(2))
		}, 400, RuleEstate, "exactly one"},
		{"estate copy of the wrong size", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			e[0].Sealed = make([]byte, 60)
			return f.change(t, b, w, e)
		}, 400, RuleEstate, "61 bytes"},
		{"two estate copies", func(t *testing.T, f *fixture) Change {
			b, w, e := f.nextEpoch()
			return f.change(t, b, w, append(e, e...))
		}, 400, RuleEstate, "exactly one"},
		{"first record without an estate copy", func(t *testing.T, f *fixture) Change {
			f.creation()
			b, w, _ := f.first()
			return f.change(t, b, w, nil)
		}, 400, RuleEstate, "exactly one"},

		// 14. linkTokenHash
		{"public without a link token hash", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Public = true
			return f.change(t, b, nil, nil)
		}, 400, RuleLinkToken, "required"},
		{"public with a malformed link token hash", func(t *testing.T, f *fixture) Change {
			b := f.next()
			b.Public = true
			ch := f.change(t, b, nil, nil)
			ch.LinkTokenHash = strings.ToUpper(linkHash())
			return ch
		}, 400, RuleLinkToken, "64 lowercase hex"},
		{"private with a link token hash", func(t *testing.T, f *fixture) Change {
			ch := f.change(t, f.next(), nil, nil)
			ch.LinkTokenHash = linkHash()
			return ch
		}, 400, RuleLinkToken, "private"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ch := tc.build(t, f)
			res, err := Check(f.cur, f.dir, ch)
			if res != nil {
				t.Errorf("refusal returned a result: %+v", res)
			}
			refused(t, err, tc.status, tc.rule, tc.msg)
		})
	}
}

func check(t *testing.T, f *fixture, ch Change) *Result {
	t.Helper()
	res, err := Check(f.cur, f.dir, ch)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return res
}

func wrapKeys(ws []store.Wrap) string {
	var out []string
	for _, w := range ws {
		out = append(out, w.UserID+"@"+string(rune('0'+w.Epoch)))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestCheckFirstRecordWithMembers(t *testing.T) {
	f := newFixture(t)
	f.creation()
	b, _, e := f.first()
	b.Members = append(b.Members, member(f.b, "viewer"))
	b.Team = "editor"
	res := check(t, f, f.change(t, b, append(wrapsFor(f.a, 1), wrapsFor(f.b, 1)...), e))
	r := res.Record
	if r.Seq != 1 || r.Prev != "" || r.Epoch != 1 || r.OwnerID != f.o.ID || r.OwnerFp != f.o.FP || r.Team != "editor" ||
		hex.EncodeToString(r.AKCommit) != commit(1) || r.Envelope.Signer != f.o.ID {
		t.Errorf("record: %+v", r)
	}
	if len(res.Members) != 2 || res.Members[0] != (store.Member{UserID: f.a.ID, Role: "editor", FP: f.a.FP}) {
		t.Errorf("members: %+v", res.Members)
	}
	if wrapKeys(res.Wraps) != "u-a@1,u-b@1" || res.Wraps[0].FP != f.a.FP || len(res.Excluded) != 0 {
		t.Errorf("wraps: %+v", res.Wraps)
	}
	if !res.NewEpoch || len(res.Estate) != 1 || res.Estate[0].Epoch != 1 || len(res.Estate[0].Sealed) != 61 {
		t.Errorf("estate: %+v new epoch %v", res.Estate, res.NewEpoch)
	}
	if res.PublicTokenHash != "" || res.PublicEpoch != 0 {
		t.Errorf("a private record set a link: %+v", res)
	}
}

func TestCheckSameEpochAddsAMember(t *testing.T) {
	f := newFixture(t)
	b := f.next()
	b.Members = append(b.Members, member(f.c, "viewer"))
	res := check(t, f, f.change(t, b, wrapsFor(f.c, 1, 2), nil))
	if wrapKeys(res.Wraps) != "u-c@1,u-c@2" || res.Wraps[0].FP != f.c.FP || res.NewEpoch || len(res.Estate) != 0 {
		t.Errorf("result: %+v", res)
	}
	if len(res.Members) != 3 || res.Members[2].UserID != f.c.ID || len(res.Excluded) != 1 {
		t.Errorf("lists: %+v %+v", res.Members, res.Excluded)
	}
}

func TestCheckSameEpochPromotesAViewer(t *testing.T) {
	f := newFixture(t)
	b := f.next()
	b.Members[1].Role = "editor"
	res := check(t, f, f.change(t, b, nil, nil))
	if res.Members[1].Role != "editor" || len(res.Wraps) != 0 {
		t.Errorf("result: %+v", res)
	}
}

func TestCheckSameEpochChangesTeam(t *testing.T) {
	f := newFixture(t)
	b := f.next()
	b.Team, b.PublicWrites = "editor", true
	res := check(t, f, f.change(t, b, nil, nil))
	if res.Record.Team != "editor" || !res.Record.PublicWrites {
		t.Errorf("record: %+v", res.Record)
	}
	// team none is fine at the same epoch once the team member is listed:
	// they already hold every epoch under their current key, so no wraps.
	b = f.next()
	b.Team = "none"
	b.Members = append(b.Members, member(f.tm, "viewer"))
	res = check(t, f, f.change(t, b, nil, nil))
	if res.Record.Team != "none" || len(res.Wraps) != 0 {
		t.Errorf("listing the team member: %+v", res)
	}
}

func TestCheckSameEpochMakesPublic(t *testing.T) {
	f := newFixture(t)
	b := f.next()
	b.Public = true
	ch := f.change(t, b, nil, nil)
	ch.LinkTokenHash = linkHash()
	res := check(t, f, ch)
	if !res.Record.Public || res.PublicTokenHash != linkHash() || res.PublicEpoch != 2 {
		t.Errorf("result: %+v", res)
	}
}

func TestCheckNextEpochRemovesWithExclusion(t *testing.T) {
	f := newFixture(t)
	b, _, e := f.nextEpoch()
	b.Members = b.Members[:1]
	b.Excluded = []e2e.ExcludedEntry{excluded(f.b), excluded(f.tm), excluded(f.x)}
	res := check(t, f, f.change(t, b, wrapsFor(f.a, 3), e))
	if !res.NewEpoch || res.Record.Epoch != 3 || wrapKeys(res.Wraps) != "u-a@3" || res.Estate[0].Epoch != 3 {
		t.Errorf("result: %+v", res)
	}
	if len(res.Members) != 1 || len(res.Excluded) != 3 || res.Excluded[0] != (store.Excluded{UserID: f.b.ID, FP: f.b.FP, Email: f.b.Email}) {
		t.Errorf("lists: %+v %+v", res.Members, res.Excluded)
	}
}

func TestCheckNextEpochListsTheTeamMember(t *testing.T) {
	f := newFixture(t)
	b, _, e := f.nextEpoch()
	b.Excluded = b.Excluded[1:]
	b.Members = append(b.Members, member(f.tm, "viewer"))
	res := check(t, f, f.change(t, b, append(wrapsFor(f.a, 3), append(wrapsFor(f.b, 3), wrapsFor(f.tm, 3)...)...), e))
	if wrapKeys(res.Wraps) != "u-a@3,u-b@3,u-t@3" {
		t.Errorf("wraps: %s", wrapKeys(res.Wraps))
	}
}

func TestCheckNextEpochKeepsPublicUnderANewLink(t *testing.T) {
	f := newFixture(t)
	l := *f.cur.Latest
	l.Public = true
	f.setLatest(&l)
	b, w, e := f.nextEpoch()
	ch := f.change(t, b, w, e)
	ch.LinkTokenHash = commit(43)
	res := check(t, f, ch)
	if res.PublicTokenHash != commit(43) || res.PublicEpoch != 3 {
		t.Errorf("link: %+v", res)
	}
	// and making it private at the next epoch clears the link
	b, w, e = f.nextEpoch()
	b.Public = false
	res = check(t, f, f.change(t, b, w, e))
	if res.PublicTokenHash != "" || res.PublicEpoch != 0 {
		t.Errorf("private: %+v", res)
	}
}

func TestCheckRelistingAnExcludedUserDropsTheEntry(t *testing.T) {
	f := newFixture(t)
	b := f.next()
	b.Members = append(b.Members, member(f.x, "viewer"))
	b.Excluded = []e2e.ExcludedEntry{}
	res := check(t, f, f.change(t, b, wrapsFor(f.x, 1, 2), nil))
	if len(res.Excluded) != 0 || wrapKeys(res.Wraps) != "u-x@1,u-x@2" {
		t.Errorf("result: %+v", res)
	}
}

func TestCheckListingAUserWhoMatchesAnEntryByEmailDropsIt(t *testing.T) {
	// x's account is gone, and a new account took x's email. The owner
	// shares with it by name, which drops x's entry.
	f := newFixture(t)
	delete(f.dir, f.x.ID)
	y := f.add(t, "u-y", f.x.Email)
	b := f.next()
	b.Members = append(b.Members, member(y, "viewer"))
	b.Excluded = []e2e.ExcludedEntry{}
	res := check(t, f, f.change(t, b, wrapsFor(y, 1, 2), nil))
	if len(res.Excluded) != 0 {
		t.Errorf("entry kept: %+v", res.Excluded)
	}
}

func TestCheckMemberKeyChanges(t *testing.T) {
	t.Run("rotated member re-wrapped for themselves needs no new wrap", func(t *testing.T) {
		f := newFixture(t)
		rekey(t, f.b)
		for i, w := range f.cur.Wraps {
			if w.UserID == f.b.ID {
				f.cur.Wraps[i].FP = f.b.FP
			}
		}
		b := f.next()
		b.Members[1].FP = f.b.FP
		res := check(t, f, f.change(t, b, nil, nil))
		if len(res.Wraps) != 0 || res.Members[1].FP != f.b.FP {
			t.Errorf("result: %+v", res)
		}
	})
	t.Run("reset member re-listed needs every epoch", func(t *testing.T) {
		f := newFixture(t)
		rekey(t, f.b)
		b := f.next()
		b.Members[1].FP = f.b.FP
		res := check(t, f, f.change(t, b, wrapsFor(f.b, 1, 2), nil))
		if wrapKeys(res.Wraps) != "u-b@1,u-b@2" || res.Wraps[0].FP != f.b.FP {
			t.Errorf("wraps: %+v", res.Wraps)
		}
	})
	t.Run("reset member re-listed at the next epoch needs every epoch", func(t *testing.T) {
		f := newFixture(t)
		rekey(t, f.b)
		b, _, e := f.nextEpoch()
		b.Members[1].FP = f.b.FP
		res := check(t, f, f.change(t, b, append(wrapsFor(f.a, 3), wrapsFor(f.b, 1, 2, 3)...), e))
		if wrapKeys(res.Wraps) != "u-a@3,u-b@1,u-b@2,u-b@3" {
			t.Errorf("wraps: %s", wrapKeys(res.Wraps))
		}
	})
	t.Run("member left under an old fp is not re-checked and gets no wrap", func(t *testing.T) {
		f := newFixture(t)
		rekey(t, f.b)
		f.b.Verified = false // not checked: the record does not change b
		check(t, f, f.change(t, f.next(), nil, nil))
		// a wrap to b's new key would share with a key the record does not list
		_, err := Check(f.cur, f.dir, f.change(t, f.next(), wrapsFor(f.b, 1), nil))
		refused(t, err, 400, RuleWraps, "not needed")
	})
	t.Run("removed member is excluded under the fp the record listed", func(t *testing.T) {
		// b rotated and re-made their wraps, so only the record has the old fp.
		f := newFixture(t)
		old := rekey(t, f.b)
		for i, w := range f.cur.Wraps {
			if w.UserID == f.b.ID {
				f.cur.Wraps[i].FP = f.b.FP
			}
		}
		b, _, e := f.nextEpoch()
		b.Members = b.Members[:1]
		b.Excluded = []e2e.ExcludedEntry{{User: f.b.ID, FP: old, Email: f.b.Email}, excluded(f.tm), excluded(f.x)}
		check(t, f, f.change(t, b, wrapsFor(f.a, 3), e))
	})
	t.Run("team member is excluded under the fp of their wrap", func(t *testing.T) {
		f := newFixture(t)
		old := rekey(t, f.tm)
		b, w, e := f.nextEpoch()
		b.Excluded[0].FP = old
		check(t, f, f.change(t, b, w, e))
	})
}

func TestCheckExcludedMatchesAMemberByUserIDAlone(t *testing.T) {
	// x reset and changed email since being excluded, so only the user ID
	// still matches.
	f := newFixture(t)
	rekey(t, f.x)
	f.x.Email = "x2@x.y"
	b := f.next()
	b.Members = append(b.Members, member(f.x, "viewer"))
	_, err := Check(f.cur, f.dir, f.change(t, b, wrapsFor(f.x, 1, 2), nil))
	refused(t, err, 400, RuleExcludedMatch, "excluded u-x matches member u-x")
}

func TestCheckAWrapForAnEarlierEpochIsNotATeamMember(t *testing.T) {
	// c holds a wrap for epoch 1 only, so is not a team member holding a
	// wrap: a next epoch need not exclude them, and team none is allowed.
	f := newFixture(t)
	f.cur.Wraps = append(f.cur.Wraps, store.Wrap{UserID: f.c.ID, Epoch: 1, Wrapped: make([]byte, 81), FP: f.c.FP})
	b, w, e := f.nextEpoch()
	check(t, f, f.change(t, b, w, e))
	b = f.next()
	b.Team = "none"
	b.Members = append(b.Members, member(f.tm, "viewer"))
	check(t, f, f.change(t, b, nil, nil))
}

func TestCheckMemberWhoseAccountIsGone(t *testing.T) {
	// A carried member with no account blocks nothing at the same epoch, and
	// a next epoch can remove and exclude them with the email it knows.
	f := newFixture(t)
	delete(f.dir, f.b.ID)
	check(t, f, f.change(t, f.next(), nil, nil))
	b, _, e := f.nextEpoch()
	b.Members = b.Members[:1]
	b.Excluded = []e2e.ExcludedEntry{excluded(f.b), excluded(f.tm), excluded(f.x)}
	check(t, f, f.change(t, b, wrapsFor(f.a, 3), e))
}

func TestCheckNeedsAnOwner(t *testing.T) {
	f := newFixture(t)
	ch := f.change(t, f.next(), nil, nil)
	f.cur.Owner = nil
	if _, err := Check(f.cur, f.dir, ch); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("got %v", err)
	}
	var me *Error
	if _, err := Check(f.cur, f.dir, ch); errors.As(err, &me) {
		t.Fatalf("a missing owner is the caller's bug, not a refusal: %v", err)
	}
}
