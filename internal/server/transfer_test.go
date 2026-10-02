package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// transferWorld is an artifact owned by owner, with ed and ed2 as editors and
// v as a viewer, and admin and out (a user it does not list) alongside.
type transferWorld struct {
	t     *testing.T
	s     *Server
	base  string
	admin *testClient
	o     *owned
	owner actor
	ed    actor
	ed2   actor
	v     actor
	out   actor
}

func newTransferWorld(t *testing.T) *transferWorld {
	t.Helper()
	s, ts := testServer(t)
	w := &transferWorld{t: t, s: s, base: ts.URL, admin: login(t, ts.URL, "admin@example.com", "admin-password")}
	w.owner = seedKeyedAccount(t, s, ts.URL, "owner@example.com")
	w.ed = seedKeyedAccount(t, s, ts.URL, "ed@example.com")
	w.ed2 = seedKeyedAccount(t, s, ts.URL, "ed2@example.com")
	w.v = seedKeyedAccount(t, s, ts.URL, "v@example.com")
	w.out = seedKeyedAccount(t, s, ts.URL, "out@example.com")
	w.o = newArtifact(t, w.owner, "doc")
	w.o.share("editor", w.ed, w.ed2)
	w.o.share("viewer", w.v)
	return w
}

func signOffer(t *testing.T, signer actor, b e2e.TransferBody) e2e.Envelope {
	t.Helper()
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(signer.keys.seed, signer.id, "transfer", body)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// offerFor is the owner's offer of the artifact to to, naming the latest record.
func (w *transferWorld) offerFor(to actor) e2e.TransferBody {
	return e2e.TransferBody{V: 1, Artifact: w.o.id, From: w.owner.id, To: to.id, ToFP: to.keys.fp(), Prev: w.o.hash}
}

func (w *transferWorld) offerReq(to actor, b e2e.TransferBody) map[string]any {
	return map[string]any{"to": to.id, "offer": signOffer(w.t, w.owner, b)}
}

// offer makes the owner's offer to to and returns its envelope.
func (w *transferWorld) offer(to actor) e2e.Envelope {
	w.t.Helper()
	req := w.offerReq(to, w.offerFor(to))
	var out struct {
		Transfer struct{ To, By, At string }
	}
	w.owner.mustDo("POST", "/api/artifacts/"+w.o.id+"/transfer", req, &out, http.StatusOK)
	if out.Transfer.To != to.id || out.Transfer.By != "owner" || out.Transfer.At == "" {
		w.t.Fatalf("offer answered %+v", out)
	}
	return req["offer"].(e2e.Envelope)
}

// closingRecord is a same-epoch record from the owner that changes nothing.
func (w *transferWorld) closingRecord() e2e.MembershipBody { return w.o.next() }

// accepting builds the accept request in which newOwner takes over from the
// owner. transfer and handover go into the record as given. With exclude the
// record is a next-epoch one that excludes the previous owner; otherwise it
// keeps them as an editor.
func (w *transferWorld) accepting(newOwner actor, transfer, handover string, exclude bool) (e2e.MembershipBody, map[string]any) {
	w.t.Helper()
	b := w.o.next()
	b.Owner, b.OwnerFP, b.Transfer, b.Handover = newOwner.id, newOwner.keys.fp(), transfer, handover
	b.Members = nil
	for _, m := range w.o.latest.Members {
		if m.User != newOwner.id {
			b.Members = append(b.Members, m)
		}
	}
	wraps := []any{}
	wrap := func(user string, from int) {
		for e := from; e <= b.Epoch; e++ {
			wraps = append(wraps, map[string]any{"user": user, "epoch": e, "wrapped": e2e.B64(fakeWrap)})
		}
	}
	if exclude {
		b.Epoch++
		b.AKCommit = testCommit(w.t, w.o.id, b.Epoch)
		b.Excluded = append(b.Excluded, e2e.ExcludedEntry{User: w.owner.id, FP: w.owner.keys.fp(), Email: w.owner.email})
		sortExcluded(b.Excluded)
		for _, m := range b.Members {
			wrap(m.User, b.Epoch)
		}
	} else {
		b.Members = append(b.Members, e2e.Member{User: w.owner.id, Role: "editor", FP: w.owner.keys.fp()})
		sortMembers(b.Members)
		wrap(w.owner.id, 1)
	}
	estate := []any{}
	for e := 1; e <= b.Epoch; e++ {
		estate = append(estate, testEstate(w.t, w.o.id, e))
	}
	return b, map[string]any{"membership": signRecord(w.t, newOwner, b), "wraps": wraps, "estate": estate}
}

func sortExcluded(xs []e2e.ExcludedEntry) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j].User < xs[j-1].User; j-- {
			xs[j], xs[j-1] = xs[j-1], xs[j]
		}
	}
}

// acceptOwnerOffer builds the request in which newOwner accepts offer.
func (w *transferWorld) acceptOwnerOffer(newOwner actor, offer e2e.Envelope, exclude bool) (e2e.MembershipBody, map[string]any) {
	return w.accepting(newOwner, e2e.BodyHash(offer.Body), "", exclude)
}

func (w *transferWorld) transferPath(suffix string) string {
	return "/api/artifacts/" + w.o.id + "/transfer" + suffix
}

func (w *transferWorld) viewOf(c *testClient) gotArtifact {
	w.t.Helper()
	var a gotArtifact
	c.mustDo("GET", "/api/artifacts/"+w.o.id, nil, &a, http.StatusOK)
	return a
}

// rekey resets u's account to fresh keys, as a reset without the recovery
// code does, and signs them in again.
func (w *transferWorld) rekey(u *actor) {
	w.t.Helper()
	fresh := newUserKeys(w.t)
	hash, err := auth.HashPassword(string(testAuthKey(u.email + "-password")))
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.s.store.ResetAccount(u.id, hash, bundleFor(w.t, fresh), time.Now()); err != nil {
		w.t.Fatal(err)
	}
	u.testClient = login(w.t, w.base, u.email, u.email+"-password")
	u.keys = fresh
}

func (w *transferWorld) deactivate(u actor) {
	w.t.Helper()
	w.admin.mustDo("PATCH", "/api/admin/users/"+u.id, map[string]any{"disabled": true}, nil, http.StatusOK)
}

func TestTransferKeepingThePreviousOwner(t *testing.T) {
	w := newTransferWorld(t)
	offer := w.offer(w.ed)
	if got := w.viewOf(w.v.testClient); got.Transfer == nil || got.Transfer.To != w.ed.id || got.Transfer.By != "owner" {
		t.Errorf("transfer in the artifact view: %+v", got.Transfer)
	}

	b, req := w.acceptOwnerOffer(w.ed, offer, false)
	var out struct {
		Epoch int `json:"epoch"`
	}
	w.ed.mustDo("POST", w.transferPath("/accept"), req, &out, http.StatusOK)
	if out.Epoch != 1 {
		t.Errorf("epoch %d, want 1", out.Epoch)
	}

	if got := w.viewOf(w.ed.testClient); got.Owner != w.ed.id || got.Access != "owner" || got.Transfer != nil {
		t.Errorf("new owner's view: %+v", got)
	}
	if got := w.viewOf(w.owner.testClient); got.Owner != w.ed.id || got.Access != "editor" {
		t.Errorf("previous owner's view: %+v", got)
	}

	var served struct {
		Records []e2e.Envelope          `json:"records"`
		Offers  map[string]e2e.Envelope `json:"offers"`
		Owners  map[string]e2e.KeyPair  `json:"owners"`
	}
	w.v.mustDo("GET", "/api/artifacts/"+w.o.id+"/membership", nil, &served, http.StatusOK)
	hash := e2e.BodyHash(offer.Body)
	if o, ok := served.Offers[hash]; !ok || e2e.BodyHash(o.Body) != hash {
		t.Errorf("offers: %+v", served.Offers)
	}
	chain, err := e2e.VerifyChain(e2e.ChainInput{Artifact: w.o.id, Records: served.Records, Owners: served.Owners,
		Offers: served.Offers, Anchor: w.owner.keys.fp(), CurrentOwnerFP: w.ed.keys.fp()})
	if err != nil {
		t.Fatalf("served chain does not verify: %v", err)
	}
	if last := chain.Bodies[len(chain.Bodies)-1]; last.Owner != w.ed.id || last.Transfer != hash {
		t.Errorf("latest record: %+v", last)
	}

	if m, ok := mailer(w.s).Last(w.owner.email); !ok || !strings.Contains(m.Body, w.o.id) || !strings.Contains(m.Body, w.ed.email) {
		t.Errorf("previous owner's mail: %+v, %v", m, ok)
	}

	// The new owner holds estate copies and no wraps; the previous owner the reverse.
	var keys struct {
		Wraps  []any `json:"wraps"`
		Estate []any `json:"estate"`
	}
	w.ed.mustDo("GET", "/api/artifacts/"+w.o.id+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Estate) != 1 || len(keys.Wraps) != 0 {
		t.Errorf("new owner's keys: %+v", keys)
	}
	w.owner.mustDo("GET", "/api/artifacts/"+w.o.id+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Estate) != 0 || len(keys.Wraps) != 1 {
		t.Errorf("previous owner's keys: %+v", keys)
	}

	// The previous owner is an editor now, and cannot share.
	w.o.latest, w.o.hash = b, e2e.BodyHash(req["membership"].(e2e.Envelope).Body)
	w.o.owner = w.owner
	wantStatus(t, w.owner.testClient, "PUT", "/api/artifacts/"+w.o.id+"/membership", w.o.change(w.o.next()), http.StatusForbidden)
	// The new owner can.
	w.o.owner = w.ed
	b = w.o.next()
	b.Transfer = ""
	w.o.apply(b)
}

func TestTransferExcludingThePreviousOwner(t *testing.T) {
	w := newTransferWorld(t)
	offer := w.offer(w.ed)
	_, req := w.acceptOwnerOffer(w.ed, offer, true)
	var out struct {
		Epoch int `json:"epoch"`
	}
	w.ed.mustDo("POST", w.transferPath("/accept"), req, &out, http.StatusOK)
	if out.Epoch != 2 {
		t.Errorf("epoch %d, want 2", out.Epoch)
	}
	wantStatus(t, w.owner.testClient, "GET", "/api/artifacts/"+w.o.id, nil, http.StatusNotFound)
	if got := w.viewOf(w.ed.testClient); got.Owner != w.ed.id || got.Access != "owner" || got.Epoch != 2 {
		t.Errorf("new owner's view: %+v", got)
	}
	if got := w.viewOf(w.ed2.testClient); got.Access != "editor" {
		t.Errorf("another editor's view: %+v", got)
	}
}

func TestOfferRefusals(t *testing.T) {
	cases := []struct {
		name  string
		build func(w *transferWorld) (actor, map[string]any)
		want  int
	}{
		{"to the owner", func(w *transferWorld) (actor, map[string]any) {
			return w.owner, w.offerReq(w.owner, w.offerFor(w.owner))
		}, http.StatusConflict},
		{"to a viewer", func(w *transferWorld) (actor, map[string]any) {
			return w.owner, w.offerReq(w.v, w.offerFor(w.v))
		}, http.StatusConflict},
		{"to a user the record does not list", func(w *transferWorld) (actor, map[string]any) {
			return w.owner, w.offerReq(w.out, w.offerFor(w.out))
		}, http.StatusConflict},
		{"to a user with no account", func(w *transferWorld) (actor, map[string]any) {
			b := w.offerFor(w.ed)
			b.To = "no-such-user"
			return w.owner, map[string]any{"to": b.To, "offer": signOffer(w.t, w.owner, b)}
		}, http.StatusConflict},
		{"with a toFp that is not the listed fp", func(w *transferWorld) (actor, map[string]any) {
			b := w.offerFor(w.ed)
			b.ToFP = w.out.keys.fp()
			return w.owner, w.offerReq(w.ed, b)
		}, http.StatusConflict},
		{"with a stale prev", func(w *transferWorld) (actor, map[string]any) {
			b := w.offerFor(w.ed)
			b.Prev = testCommit(w.t, w.o.id, 7)
			return w.owner, w.offerReq(w.ed, b)
		}, http.StatusBadRequest},
		{"signed by someone else", func(w *transferWorld) (actor, map[string]any) {
			return w.owner, map[string]any{"to": w.ed.id, "offer": signOffer(w.t, w.ed2, w.offerFor(w.ed))}
		}, http.StatusBadRequest},
		{"signed by someone else under the owner's name", func(w *transferWorld) (actor, map[string]any) {
			env := signOffer(w.t, w.ed2, w.offerFor(w.ed))
			env.Signer = w.owner.id
			return w.owner, map[string]any{"to": w.ed.id, "offer": env}
		}, http.StatusBadRequest},
		{"signed by the owner but naming another signer", func(w *transferWorld) (actor, map[string]any) {
			env := signOffer(w.t, w.owner, w.offerFor(w.ed))
			env.Signer = w.ed2.id
			return w.owner, map[string]any{"to": w.ed.id, "offer": env}
		}, http.StatusBadRequest},
		{"to an editor whose key changed since the record", func(w *transferWorld) (actor, map[string]any) {
			w.rekey(&w.ed)
			return w.owner, w.offerReq(w.ed, w.offerFor(w.ed))
		}, http.StatusConflict},
		{"for another artifact", func(w *transferWorld) (actor, map[string]any) {
			b := w.offerFor(w.ed)
			b.Artifact = testCommit(w.t, w.o.id, 7)
			return w.owner, w.offerReq(w.ed, b)
		}, http.StatusBadRequest},
		{"from another user", func(w *transferWorld) (actor, map[string]any) {
			b := w.offerFor(w.ed)
			b.From = w.ed2.id
			return w.owner, w.offerReq(w.ed, b)
		}, http.StatusBadRequest},
		{"to a user other than the body's", func(w *transferWorld) (actor, map[string]any) {
			return w.owner, w.offerReq(w.ed, w.offerFor(w.ed2))
		}, http.StatusBadRequest},
		{"by an editor", func(w *transferWorld) (actor, map[string]any) {
			b := w.offerFor(w.ed)
			b.From = w.ed.id
			return w.ed, map[string]any{"to": w.ed.id, "offer": signOffer(w.t, w.ed, b)}
		}, http.StatusForbidden},
		{"to a deactivated user", func(w *transferWorld) (actor, map[string]any) {
			w.deactivate(w.ed)
			return w.owner, w.offerReq(w.ed, w.offerFor(w.ed))
		}, http.StatusConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newTransferWorld(t)
			caller, req := c.build(w)
			wantStatus(t, caller.testClient, "POST", w.transferPath(""), req, c.want)
			if _, err := w.s.store.OpenOffer(w.o.id); err == nil {
				t.Errorf("a refused offer is open")
			}
		})
	}
}

func TestSecondOffer(t *testing.T) {
	w := newTransferWorld(t)

	// A closing record with no offer open is refused, and not applied.
	before := len(getMembership(t, w.owner.testClient, w.o.id).Records)
	stray := w.offerReq(w.ed, w.offerFor(w.ed))
	stray["membership"] = signRecord(t, w.owner, w.closingRecord())
	wantStatus(t, w.owner.testClient, "POST", w.transferPath(""), stray, http.StatusConflict)
	if got := len(getMembership(t, w.owner.testClient, w.o.id).Records); got != before {
		t.Fatalf("records after a stray closing record: %d, want %d", got, before)
	}

	first := w.offer(w.ed)

	// Without a record that closes the first, the answer is 409.
	wantStatus(t, w.owner.testClient, "POST", w.transferPath(""), w.offerReq(w.ed2, w.offerFor(w.ed2)), http.StatusConflict)

	// With one, the first closes and the second opens, in one request.
	rec := w.closingRecord()
	recEnv := signRecord(t, w.owner, rec)
	w.o.latest, w.o.hash = rec, e2e.BodyHash(recEnv.Body)
	req := w.offerReq(w.ed2, w.offerFor(w.ed2))
	req["membership"] = recEnv
	w.owner.mustDo("POST", w.transferPath(""), req, nil, http.StatusOK)
	if got := w.viewOf(w.v.testClient); got.Transfer == nil || got.Transfer.To != w.ed2.id {
		t.Errorf("transfer after the second offer: %+v", got.Transfer)
	}

	// The first offer is dead: not to ed any more, and stale besides.
	_, accept := w.acceptOwnerOffer(w.ed, first, false)
	wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), accept, http.StatusConflict)

	// A second offer whose closing record is refused leaves the first open.
	bad := w.o.next()
	bad.Owner = w.ed.id
	badReq := w.offerReq(w.ed, w.offerFor(w.ed))
	badReq["membership"] = signRecord(t, w.owner, bad)
	wantStatus(t, w.owner.testClient, "POST", w.transferPath(""), badReq, http.StatusBadRequest)
	if o, err := w.s.store.OpenOffer(w.o.id); err != nil || o.To != w.ed2.id {
		t.Errorf("open offer after a refused record: %+v, %v", o, err)
	}
}

func TestWithdrawAndDecline(t *testing.T) {
	t.Run("the owner withdraws with a record", func(t *testing.T) {
		w := newTransferWorld(t)
		offer := w.offer(w.ed)
		_, accept := w.acceptOwnerOffer(w.ed, offer, false)
		rec := w.closingRecord()
		w.owner.mustDo("DELETE", w.transferPath(""), map[string]any{"membership": signRecord(t, w.owner, rec)}, nil, http.StatusOK)
		if got := w.viewOf(w.v.testClient); got.Transfer != nil {
			t.Errorf("transfer after withdrawing: %+v", got.Transfer)
		}
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), accept, http.StatusConflict)
	})
	t.Run("the owner withdraws without a record", func(t *testing.T) {
		w := newTransferWorld(t)
		w.offer(w.ed)
		wantStatus(t, w.owner.testClient, "DELETE", w.transferPath(""), nil, http.StatusBadRequest)
		if _, err := w.s.store.OpenOffer(w.o.id); err != nil {
			t.Errorf("the offer closed without a record: %v", err)
		}
	})
	t.Run("the owner withdraws with a record that changes the owner", func(t *testing.T) {
		w := newTransferWorld(t)
		w.offer(w.ed)
		bad := w.o.next()
		bad.Owner = w.ed.id
		wantStatus(t, w.owner.testClient, "DELETE", w.transferPath(""), map[string]any{"membership": signRecord(t, w.owner, bad)}, http.StatusBadRequest)
	})
	t.Run("the offered user declines", func(t *testing.T) {
		w := newTransferWorld(t)
		offer := w.offer(w.ed)
		wantStatus(t, w.ed.testClient, "DELETE", w.transferPath(""), nil, http.StatusOK)
		if got := w.viewOf(w.v.testClient); got.Transfer != nil {
			t.Errorf("transfer after declining: %+v", got.Transfer)
		}
		_, accept := w.acceptOwnerOffer(w.ed, offer, false)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), accept, http.StatusConflict)
	})
	t.Run("the offered user declines an administrator's offer", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		w.admin.mustDo("POST", "/api/admin/artifacts/"+w.o.id+"/transfer", map[string]any{"to": w.ed.id}, nil, http.StatusOK)
		wantStatus(t, w.ed.testClient, "DELETE", w.transferPath(""), nil, http.StatusOK)
		_, accept := w.accepting(w.ed, "", "admin", true)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), accept, http.StatusConflict)
	})
	t.Run("another editor cannot close it", func(t *testing.T) {
		w := newTransferWorld(t)
		w.offer(w.ed)
		wantStatus(t, w.ed2.testClient, "DELETE", w.transferPath(""), nil, http.StatusForbidden)
		wantStatus(t, w.v.testClient, "DELETE", w.transferPath(""), nil, http.StatusForbidden)
		if _, err := w.s.store.OpenOffer(w.o.id); err != nil {
			t.Errorf("the offer closed: %v", err)
		}
	})
	t.Run("with no offer open", func(t *testing.T) {
		w := newTransferWorld(t)
		rec := map[string]any{"membership": signRecord(t, w.owner, w.closingRecord())}
		wantStatus(t, w.owner.testClient, "DELETE", w.transferPath(""), rec, http.StatusConflict)
		wantStatus(t, w.ed.testClient, "DELETE", w.transferPath(""), nil, http.StatusConflict)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), map[string]any{}, http.StatusConflict)
	})
}

func TestAcceptRefusals(t *testing.T) {
	t.Run("by someone other than the offered user", func(t *testing.T) {
		w := newTransferWorld(t)
		offer := w.offer(w.ed)
		_, req := w.acceptOwnerOffer(w.ed2, offer, false)
		wantStatus(t, w.ed2.testClient, "POST", w.transferPath("/accept"), req, http.StatusConflict)
	})
	t.Run("by someone who cannot read the artifact", func(t *testing.T) {
		w := newTransferWorld(t)
		offer := w.offer(w.ed)
		_, req := w.acceptOwnerOffer(w.ed, offer, false)
		wantStatus(t, w.out.testClient, "POST", w.transferPath("/accept"), req, http.StatusNotFound)
	})
	t.Run("after the editor's key changed", func(t *testing.T) {
		w := newTransferWorld(t)
		offer := w.offer(w.ed)
		_, req := w.acceptOwnerOffer(w.ed, offer, false)
		w.rekey(&w.ed)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusConflict)
		_, req = w.acceptOwnerOffer(w.ed, offer, false)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusConflict)
	})
	// No request can store an offer like these, because the offer handler
	// checks them and any record closes the offer, so the test stores them.
	for name, edit := range map[string]func(b *e2e.TransferBody, w *transferWorld){
		"a stored offer whose prev is stale":      func(b *e2e.TransferBody, w *transferWorld) { b.Prev = testCommit(t, w.o.id, 7) },
		"a stored offer whose toFp is not theirs": func(b *e2e.TransferBody, w *transferWorld) { b.ToFP = w.out.keys.fp() },
	} {
		t.Run(name, func(t *testing.T) {
			w := newTransferWorld(t)
			b := w.offerFor(w.ed)
			edit(&b, w)
			offer := signOffer(t, w.owner, b)
			err := w.s.store.WithArtifact(w.o.id, func(tx *store.ArtifactTx) error {
				return tx.PutOffer(store.Offer{To: w.ed.id, By: "owner", Hash: e2e.BodyHash(offer.Body),
					Envelope: &store.Envelope{Body: offer.Body, Sig: offer.Sig, Signer: offer.Signer}})
			})
			if err != nil {
				t.Fatal(err)
			}
			_, req := w.acceptOwnerOffer(w.ed, offer, false)
			wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusConflict)
		})
	}
	t.Run("a record that sets handover for an owner's offer", func(t *testing.T) {
		w := newTransferWorld(t)
		w.offer(w.ed)
		_, req := w.accepting(w.ed, "", "admin", false)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusBadRequest)
	})
	t.Run("a record whose transfer is another hash", func(t *testing.T) {
		w := newTransferWorld(t)
		w.offer(w.ed)
		_, req := w.accepting(w.ed, e2e.BodyHash([]byte("another offer")), "", false)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusBadRequest)
		if m, ok := mailer(w.s).Last(w.owner.email); ok {
			t.Errorf("a refused acceptance mailed the owner: %+v", m)
		}
	})
	t.Run("a record that sets no transfer", func(t *testing.T) {
		w := newTransferWorld(t)
		w.offer(w.ed)
		_, req := w.accepting(w.ed, "", "", false)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusBadRequest)
	})
	t.Run("a record signed by the previous owner", func(t *testing.T) {
		w := newTransferWorld(t)
		offer := w.offer(w.ed)
		b, req := w.acceptOwnerOffer(w.ed, offer, false)
		req["membership"] = signRecord(t, w.owner, b)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusBadRequest)
	})
	t.Run("a record that lists the new owner", func(t *testing.T) {
		w := newTransferWorld(t)
		offer := w.offer(w.ed)
		b, req := w.acceptOwnerOffer(w.ed, offer, false)
		b.Members = append(b.Members, e2e.Member{User: w.ed.id, Role: "editor", FP: w.ed.keys.fp()})
		sortMembers(b.Members)
		req["membership"] = signRecord(t, w.ed, b)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusBadRequest)
	})
	t.Run("an ordinary membership record that sets transfer", func(t *testing.T) {
		w := newTransferWorld(t)
		b := w.o.next()
		b.Transfer = testCommit(t, w.o.id, 7)
		wantStatus(t, w.owner.testClient, "PUT", "/api/artifacts/"+w.o.id+"/membership", w.o.change(b), http.StatusBadRequest)
		b = w.o.next()
		b.Handover = "admin"
		wantStatus(t, w.owner.testClient, "PUT", "/api/artifacts/"+w.o.id+"/membership", w.o.change(b), http.StatusBadRequest)
	})
	t.Run("a record missing an estate epoch", func(t *testing.T) {
		w := newTransferWorld(t)
		w.o.apply(w.o.nextEpoch())
		offer := w.offer(w.ed)
		_, req := w.acceptOwnerOffer(w.ed, offer, false)
		req["estate"] = req["estate"].([]any)[1:]
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusBadRequest)
		_, req = w.acceptOwnerOffer(w.ed, offer, false)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusOK)
	})
	t.Run("a record missing a wrap for the kept previous owner", func(t *testing.T) {
		w := newTransferWorld(t)
		w.o.apply(w.o.nextEpoch())
		offer := w.offer(w.ed)
		_, req := w.acceptOwnerOffer(w.ed, offer, false)
		req["wraps"] = req["wraps"].([]any)[1:]
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusBadRequest)
		if got := w.viewOf(w.owner.testClient); got.Owner != w.owner.id {
			t.Errorf("a refused acceptance changed the owner: %+v", got)
		}
	})
}

func TestAdminTransfer(t *testing.T) {
	adminOffer := func(w *transferWorld, to actor, want int) {
		w.t.Helper()
		wantStatus(w.t, w.admin, "POST", "/api/admin/artifacts/"+w.o.id+"/transfer", map[string]any{"to": to.id}, want)
	}

	t.Run("an active owner must agree", func(t *testing.T) {
		w := newTransferWorld(t)
		adminOffer(w, w.ed, http.StatusConflict)
		if _, err := w.s.store.OpenOffer(w.o.id); err == nil {
			t.Errorf("an offer is open")
		}
	})
	t.Run("offer, accept, and the notice", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		var out struct {
			Transfer struct{ To, By, At string }
		}
		w.admin.mustDo("POST", "/api/admin/artifacts/"+w.o.id+"/transfer", map[string]any{"to": w.ed.id}, &out, http.StatusOK)
		if out.Transfer.To != w.ed.id || out.Transfer.By != "admin" {
			t.Errorf("offer answered %+v", out)
		}
		if m, ok := mailer(w.s).Last(w.owner.email); !ok || !strings.Contains(m.Body, w.ed.email) || !strings.Contains(m.Body, w.o.id) {
			t.Errorf("owner's mail: %+v, %v", m, ok)
		}
		if got := w.viewOf(w.v.testClient); got.Transfer == nil || got.Transfer.By != "admin" {
			t.Errorf("transfer in the artifact view: %+v", got.Transfer)
		}

		// A deactivated owner cannot be kept, so the record excludes them.
		_, req := w.accepting(w.ed, "", "admin", true)
		w.ed.mustDo("POST", w.transferPath("/accept"), req, nil, http.StatusOK)
		a, err := w.s.store.ArtifactByID(w.o.id)
		if err != nil || a.OwnerID != w.ed.id || a.Epoch != 2 {
			t.Errorf("artifact after the handover: %+v, %v", a, err)
		}
		var served struct {
			Records []e2e.Envelope         `json:"records"`
			Owners  map[string]e2e.KeyPair `json:"owners"`
		}
		w.v.mustDo("GET", "/api/artifacts/"+w.o.id+"/membership", nil, &served, http.StatusOK)
		chain, err := e2e.VerifyChain(e2e.ChainInput{Artifact: w.o.id, Records: served.Records, Owners: served.Owners, Anchor: w.owner.keys.fp()})
		if err != nil || len(chain.Handovers) != 1 {
			t.Errorf("served chain: %+v, %v", chain, err)
		}
	})
	t.Run("a deactivated owner cannot be kept", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		adminOffer(w, w.ed, http.StatusOK)
		_, req := w.accepting(w.ed, "", "admin", false)
		if code, msg := status(w.ed.testClient, "POST", w.transferPath("/accept"), req); code != http.StatusBadRequest || !strings.Contains(msg, "not active") {
			t.Errorf("keeping a deactivated owner: %d %q, want 400 not active", code, msg)
		}
		if a, err := w.s.store.ArtifactByID(w.o.id); err != nil || a.OwnerID != w.owner.id {
			t.Errorf("artifact after a refused handover: %+v, %v", a, err)
		}
	})
	t.Run("an administrator's offer is for the offered user only", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		adminOffer(w, w.ed, http.StatusOK)
		_, req := w.accepting(w.ed2, "", "admin", true)
		wantStatus(t, w.ed2.testClient, "POST", w.transferPath("/accept"), req, http.StatusConflict)
	})
	t.Run("an owner who is active again", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		adminOffer(w, w.ed, http.StatusOK)
		w.admin.mustDo("PATCH", "/api/admin/users/"+w.owner.id, map[string]any{"disabled": false}, nil, http.StatusOK)
		_, req := w.accepting(w.ed, "", "admin", false)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusConflict)
	})
	t.Run("only a listed editor", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		adminOffer(w, w.v, http.StatusConflict)
		adminOffer(w, w.out, http.StatusConflict)
		adminOffer(w, w.owner, http.StatusConflict)
		w.deactivate(w.ed)
		adminOffer(w, w.ed, http.StatusConflict)
	})
	t.Run("an offer replaces an open one", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		adminOffer(w, w.ed, http.StatusOK)
		adminOffer(w, w.ed2, http.StatusOK)
		if o, err := w.s.store.OpenOffer(w.o.id); err != nil || o.To != w.ed2.id {
			t.Errorf("open offer: %+v, %v", o, err)
		}
	})
	t.Run("a record that sets transfer for an administrator's offer", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		adminOffer(w, w.ed, http.StatusOK)
		_, req := w.accepting(w.ed, testCommit(t, w.o.id, 7), "", true)
		wantStatus(t, w.ed.testClient, "POST", w.transferPath("/accept"), req, http.StatusBadRequest)
	})
	t.Run("a missing artifact", func(t *testing.T) {
		w := newTransferWorld(t)
		wantStatus(t, w.admin, "POST", "/api/admin/artifacts/nope/transfer", map[string]any{"to": w.ed.id}, http.StatusNotFound)
		wantStatus(t, w.admin, "DELETE", "/api/admin/artifacts/nope", nil, http.StatusNotFound)
	})
	t.Run("not an administrator", func(t *testing.T) {
		w := newTransferWorld(t)
		w.deactivate(w.owner)
		wantStatus(t, w.ed.testClient, "POST", "/api/admin/artifacts/"+w.o.id+"/transfer", map[string]any{"to": w.ed.id}, http.StatusForbidden)
		wantStatus(t, w.ed.testClient, "DELETE", "/api/admin/artifacts/"+w.o.id, nil, http.StatusForbidden)
		wantStatus(t, w.ed.testClient, "GET", "/api/admin/users/"+w.owner.id+"/artifacts", nil, http.StatusForbidden)
	})
}

func TestAdminUserArtifacts(t *testing.T) {
	w := newTransferWorld(t)
	other := newArtifact(t, w.owner, "second")
	var got []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Editors []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"editors"`
	}
	w.admin.mustDo("GET", "/api/admin/users/"+w.owner.id+"/artifacts", nil, &got, http.StatusOK)
	if len(got) != 2 {
		t.Fatalf("artifacts: %+v", got)
	}
	for _, a := range got {
		switch a.ID {
		case w.o.id:
			ids := map[string]bool{}
			for _, e := range a.Editors {
				ids[e.ID] = true
				if e.Name == "" {
					t.Errorf("an editor has no name: %+v", e)
				}
			}
			if len(a.Editors) != 2 || !ids[w.ed.id] || !ids[w.ed2.id] {
				t.Errorf("editors: %+v", a.Editors)
			}
		case other.id:
			if a.Editors == nil || len(a.Editors) != 0 {
				t.Errorf("editors of the second artifact: %#v", a.Editors)
			}
		default:
			t.Errorf("unexpected artifact %s", a.ID)
		}
		if a.Name != "" {
			t.Errorf("artifact %s is named", a.ID)
		}
	}

	// A user who owns nothing gets an empty array, not null.
	var raw json.RawMessage
	w.admin.mustDo("GET", "/api/admin/users/"+w.v.id+"/artifacts", nil, &raw, http.StatusOK)
	if string(raw) != "[]" {
		t.Errorf("a user who owns nothing: %s", raw)
	}
	wantStatus(t, w.admin, "GET", "/api/admin/users/nope/artifacts", nil, http.StatusNotFound)
}

func TestAdminDeleteArtifact(t *testing.T) {
	w := newTransferWorld(t)
	pushVersion(t, w.owner.testClient, w.o.id)
	wantStatus(t, w.admin, "DELETE", "/api/admin/artifacts/"+w.o.id, nil, http.StatusConflict)
	if _, err := w.s.store.ArtifactByID(w.o.id); err != nil {
		t.Fatalf("an active owner's artifact was deleted: %v", err)
	}
	w.deactivate(w.owner)
	wantStatus(t, w.admin, "DELETE", "/api/admin/artifacts/"+w.o.id, nil, http.StatusOK)
	if _, err := w.s.store.ArtifactByID(w.o.id); err == nil {
		t.Errorf("the artifact is still there")
	}
	wantStatus(t, w.ed.testClient, "GET", "/api/artifacts/"+w.o.id, nil, http.StatusNotFound)
}

// The store's offer state is what the membership view serves, so an
// acceptance must leave the offer accepted and nothing open.
func TestAcceptanceLeavesTheOfferAccepted(t *testing.T) {
	w := newTransferWorld(t)
	offer := w.offer(w.ed)
	_, req := w.acceptOwnerOffer(w.ed, offer, false)
	w.ed.mustDo("POST", w.transferPath("/accept"), req, nil, http.StatusOK)
	if _, err := w.s.store.OpenOffer(w.o.id); err == nil {
		t.Errorf("an offer is still open")
	}
	err := w.s.store.WithArtifact(w.o.id, func(tx *store.ArtifactTx) error {
		accepted, err := tx.AcceptedOffers()
		if err != nil {
			return err
		}
		if accepted[e2e.BodyHash(offer.Body)] == nil {
			t.Errorf("accepted offers: %+v", accepted)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Only the owner and listed members are party to an offer: a link holder is
// refused and an outsider sees no artifact, whether or not an offer is open,
// so neither can tell.
func TestAnsweringAnOfferNeedsAListedMember(t *testing.T) {
	w := newTransferWorld(t)
	anon := anonWithLink(t, w.base, w.o.makePublic())
	check := func() {
		t.Helper()
		for who, status := range map[*testClient]int{anon: http.StatusForbidden, w.out.testClient: http.StatusNotFound} {
			wantStatus(t, who, "POST", w.transferPath("/accept"), map[string]any{}, status)
			wantStatus(t, who, "DELETE", w.transferPath(""), nil, status)
		}
	}
	check()
	w.offer(w.ed)
	check()
}
