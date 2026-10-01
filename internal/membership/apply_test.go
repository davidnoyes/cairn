package membership

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// account creates a verified account in s with fresh keys, and returns it as
// a test user so records can be signed for it.
func account(t *testing.T, s *store.Store, email string) *tUser {
	t.Helper()
	xpub, seed, epub := genKeys(t)
	u, err := s.CreateAccount(email, "N", "h", store.Bundle{
		KDF: []byte(`{}`), MKPassword: []byte("p"), MKRecovery: []byte("r"),
		X25519Pub: xpub, X25519Priv: []byte("x"), Ed25519Pub: epub, Ed25519Priv: []byte("e"), EK: []byte("k"),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkVerified(u.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	return &tUser{User: &User{ID: u.ID, Email: email, X25519Pub: xpub, Ed25519Pub: epub, FP: fingerprint(xpub, epub),
		Verified: true, Active: true}, seed: seed}
}

func signedBy(t *testing.T, o *tUser, b *e2e.MembershipBody) e2e.Envelope {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(o.seed, o.ID, "membership", raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// land loads the artifact, checks ch, and applies it, all in one
// transaction, as the endpoints will.
func land(t *testing.T, s *store.Store, ch Change) error {
	t.Helper()
	return s.WithArtifact(artID, func(tx *store.ArtifactTx) error {
		dir := TxDirectory(tx)
		cur, err := Load(tx, dir)
		if err != nil {
			return err
		}
		res, err := Check(cur, dir, ch)
		if err != nil {
			return err
		}
		return Apply(tx, res)
	})
}

func TestApplyThroughTheStore(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	o := account(t, s, "o@x.y")
	a := account(t, s, "a@x.y")
	b := account(t, s, "b@x.y")
	tm := account(t, s, "t@x.y")

	// The first record, in the transaction that creates the artifact.
	first := &e2e.MembershipBody{
		V: 1, Artifact: artID, Epoch: 1, Seq: 1, Owner: o.ID, OwnerFP: o.FP, AKCommit: commit(1),
		Members:  []e2e.Member{member(a, "editor"), member(b, "viewer")},
		Excluded: []e2e.ExcludedEntry{}, Team: "viewer",
	}
	sortMembers(first.Members)
	_, err = s.CreateOwnedArtifact(artID, "N", "", o.ID, func(tx *store.ArtifactTx) error {
		dir := TxDirectory(tx)
		cur, err := Load(tx, dir)
		if err != nil {
			return err
		}
		if cur.Latest != nil || cur.Owner == nil || cur.Owner.FP != o.FP || cur.Owner.Email != "o@x.y" {
			t.Errorf("loaded before the first record: %+v", cur)
		}
		res, err := Check(cur, dir, Change{Envelope: signedBy(t, o, first),
			Wraps: append(wrapsFor(a, 1), wrapsFor(b, 1)...), Estate: estate(1)})
		if err != nil {
			return err
		}
		return Apply(tx, res)
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	firstHash := e2e.BodyHash(signedBy(t, o, first).Body)

	// A team member approved by an editor, with an approval and wraps.
	err = s.WithArtifact(artID, func(tx *store.ArtifactTx) error {
		if err := tx.PutWrap(store.Wrap{UserID: tm.ID, Epoch: 1, Wrapped: make([]byte, 81), FP: tm.FP}); err != nil {
			return err
		}
		return tx.PutApproval(store.Approval{UserID: tm.ID, FP: tm.FP, Epoch: 1,
			Envelope: store.Envelope{Body: []byte("{}"), Sig: []byte("s"), Signer: a.ID}})
	})
	if err != nil {
		t.Fatal(err)
	}

	// Same epoch: make it public.
	pub := *first
	pub.Seq, pub.Prev, pub.Public = 2, firstHash, true
	pubEnv := signedBy(t, o, &pub)
	if err := land(t, s, Change{Envelope: pubEnv, LinkTokenHash: linkHash()}); err != nil {
		t.Fatalf("public: %v", err)
	}
	art, err := s.ArtifactByID(artID)
	if err != nil {
		t.Fatal(err)
	}
	if !art.Public || art.PublicTokenHash != linkHash() || art.PublicEpoch != 1 || art.Epoch != 1 || art.Team != "viewer" {
		t.Errorf("after public: %+v", art)
	}

	// A stale prev now loses with 409.
	stale := pub
	stale.Seq = 3
	err = land(t, s, Change{Envelope: signedBy(t, o, &stale), LinkTokenHash: linkHash()})
	refused(t, err, 409, RulePrev, "prev")

	// An open offer, which the next record closes.
	err = s.WithArtifact(artID, func(tx *store.ArtifactTx) error {
		return tx.PutOffer(store.Offer{To: a.ID, By: "owner", Hash: commit(50), Envelope: &store.Envelope{Body: []byte("{}"), Sig: []byte("s"), Signer: o.ID}})
	})
	if err != nil {
		t.Fatal(err)
	}

	// Next epoch: remove b, exclude b and the team member, new link.
	next := pub
	next.Seq, next.Prev, next.Epoch, next.AKCommit = 3, e2e.BodyHash(pubEnv.Body), 2, commit(2)
	next.Members = []e2e.Member{member(a, "editor")}
	next.Excluded = []e2e.ExcludedEntry{excluded(b), excluded(tm)}
	sortExcluded(next.Excluded)
	if err := land(t, s, Change{Envelope: signedBy(t, o, &next), Wraps: wrapsFor(a, 2), Estate: estate(2),
		LinkTokenHash: commit(43)}); err != nil {
		t.Fatalf("next epoch: %v", err)
	}

	err = s.WithArtifact(artID, func(tx *store.ArtifactTx) error {
		art, err := tx.Artifact()
		if err != nil {
			return err
		}
		if art.Epoch != 2 || art.PublicTokenHash != commit(43) || art.PublicEpoch != 2 {
			t.Errorf("artifact: %+v", art)
		}
		recs, err := tx.Records()
		if err != nil {
			return err
		}
		if len(recs) != 3 || hex.EncodeToString(recs[2].AKCommit) != commit(2) || recs[2].OwnerFp != o.FP || recs[2].Envelope.Signer != o.ID {
			t.Errorf("records: %d, last %+v", len(recs), recs[len(recs)-1])
		}
		members, err := tx.Members()
		if err != nil {
			return err
		}
		if len(members) != 1 || members[0] != (store.Member{UserID: a.ID, Role: "editor", FP: a.FP}) {
			t.Errorf("members: %+v", members)
		}
		ex, err := tx.ExcludedEntries()
		if err != nil {
			return err
		}
		if len(ex) != 2 {
			t.Errorf("excluded: %+v", ex)
		}
		wraps, err := tx.Wraps()
		if err != nil {
			return err
		}
		if len(wraps) != 2 || wraps[0].UserID != a.ID || wraps[1].UserID != a.ID || wraps[1].Epoch != 2 || wraps[1].FP != a.FP {
			t.Errorf("wraps: %+v", wraps)
		}
		approvals, err := tx.Approvals()
		if err != nil {
			return err
		}
		if len(approvals) != 0 {
			t.Errorf("the team member's approval survived: %+v", approvals)
		}
		estates, err := tx.Estates()
		if err != nil {
			return err
		}
		if len(estates) != 2 || estates[1].Epoch != 2 {
			t.Errorf("estates: %+v", estates)
		}
		if _, err := tx.OpenOffer(); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("open offer after a record: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Private again, at the next epoch: the link goes.
	priv := next
	priv.Seq, priv.Prev, priv.Epoch, priv.AKCommit, priv.Public = 4, e2e.BodyHash(signedBy(t, o, &next).Body), 3, commit(3), false
	if err := land(t, s, Change{Envelope: signedBy(t, o, &priv), Wraps: wrapsFor(a, 3), Estate: estate(3)}); err != nil {
		t.Fatalf("private: %v", err)
	}
	art, err = s.ArtifactByID(artID)
	if err != nil {
		t.Fatal(err)
	}
	if art.Public || art.PublicTokenHash != "" || art.PublicEpoch != 0 {
		t.Errorf("after private: %+v", art)
	}
}

func TestApplyReplacesTheWrapsOfAResetMember(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	o := account(t, s, "o@x.y")
	a := account(t, s, "a@x.y")
	first := &e2e.MembershipBody{
		V: 1, Artifact: artID, Epoch: 1, Seq: 1, Owner: o.ID, OwnerFP: o.FP, AKCommit: commit(1),
		Members: []e2e.Member{member(a, "viewer")}, Excluded: []e2e.ExcludedEntry{}, Team: "none",
	}
	env := signedBy(t, o, first)
	_, err = s.CreateOwnedArtifact(artID, "N", "", o.ID, func(tx *store.ArtifactTx) error {
		dir := TxDirectory(tx)
		cur, err := Load(tx, dir)
		if err != nil {
			return err
		}
		res, err := Check(cur, dir, Change{Envelope: env, Wraps: wrapsFor(a, 1), Estate: estate(1)})
		if err != nil {
			return err
		}
		return Apply(tx, res)
	})
	if err != nil {
		t.Fatal(err)
	}

	// a resets: new keys in their bundle.
	xpub, seed, epub := genKeys(t)
	if err := s.ResetAccount(a.ID, "h2", store.Bundle{KDF: []byte(`{}`), MKPassword: []byte("p"), MKRecovery: []byte("r"),
		X25519Pub: xpub, X25519Priv: []byte("x"), Ed25519Pub: epub, Ed25519Priv: []byte("e"), EK: []byte("k")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	a.X25519Pub, a.Ed25519Pub, a.FP, a.seed = xpub, epub, fingerprint(xpub, epub), seed

	again := *first
	again.Seq, again.Prev, again.Members = 2, e2e.BodyHash(env.Body), []e2e.Member{member(a, "viewer")}
	w := wrapsFor(a, 1)
	w[0].Wrapped[0] = 7
	if err := land(t, s, Change{Envelope: signedBy(t, o, &again), Wraps: w}); err != nil {
		t.Fatalf("re-list: %v", err)
	}
	wraps, err := s.WrapsFor(artID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(wraps) != 1 || wraps[0].FP != a.FP || wraps[0].Wrapped[0] != 7 {
		t.Errorf("wraps: %+v", wraps)
	}
}

func TestTxDirectory(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	o := account(t, s, "O@X.y")
	d := account(t, s, "d@x.y")
	if err := s.SetUserDisabled(d.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOwnedArtifact(artID, "N", "", o.ID, nil); err != nil {
		t.Fatal(err)
	}
	err = s.WithArtifact(artID, func(tx *store.ArtifactTx) error {
		dir := TxDirectory(tx)
		u, err := dir.User(o.ID)
		if err != nil {
			return err
		}
		if u == nil || u.Email != "o@x.y" || u.FP != o.FP || !u.Verified || !u.Active {
			t.Errorf("owner: %+v", u)
		}
		if u, err := dir.User(d.ID); err != nil || u == nil || u.Active {
			t.Errorf("disabled user: %+v %v", u, err)
		}
		if u, err := dir.User("nobody"); u != nil || err != nil {
			t.Errorf("missing user: %+v %v", u, err)
		}
		ids, err := dir.Sharing(o.FP, "d@x.y")
		if err != nil {
			return err
		}
		if len(ids) != 2 {
			t.Errorf("sharing: %v", ids)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func sortMembers(ms []e2e.Member) {
	sort.Slice(ms, func(i, j int) bool { return ms[i].User < ms[j].User })
}

func sortExcluded(xs []e2e.ExcludedEntry) {
	sort.Slice(xs, func(i, j int) bool { return xs[i].User < xs[j].User })
}
