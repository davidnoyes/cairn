package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/server"
)

// xfer is a server with an artifact owned by ada, bob and cat as editors, dan
// as a viewer, and eve, who was a viewer and is excluded. The artifact is at
// epoch 2, so a transfer has more than one epoch to carry. An administrator
// is signed in alongside.
type xfer struct {
	t                       *testing.T
	host                    string
	m                       *mail.Capture
	admin                   *Client
	ada, bob, cat, dan, eve *Client
	artifact                string
}

func newXfer(t *testing.T, cfg func(*server.Config)) *xfer {
	t.Helper()
	host, m := newTestServerWith(t, cfg)
	x := &xfer{t: t, host: host, m: m}
	for _, acct := range []struct {
		email string
		c     **Client
	}{{"ada@example.com", &x.ada}, {"bob@example.com", &x.bob}, {"cat@example.com", &x.cat},
		{"dan@example.com", &x.dan}, {"eve@example.com", &x.eve}} {
		signupVerify(t, host, m, acct.email, testPassword)
		out, err := New(host, "").Login(acct.email, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		*acct.c = keyedFor(t, host, out.APIKey)
	}
	signupVerify(t, host, m, "admin@example.com", testPassword)
	ps, err := New(host, "").passwordSignIn("admin@example.com", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	x.admin = &Client{Host: host, Token: ps.Token, HTTP: http.DefaultClient}

	a, err := x.ada.CreateArtifact("shared", "")
	if err != nil {
		t.Fatal(err)
	}
	x.artifact = a.ID
	for _, s := range []struct{ who, role string }{{"bob", "editor"}, {"cat", "editor"}, {"dan", "viewer"}, {"eve", "viewer"}} {
		if _, err := x.ada.Share(x.artifact, s.who+"@example.com", s.role, false); err != nil {
			t.Fatalf("Share %s: %v", s.who, err)
		}
	}
	if _, err := x.ada.Unshare(x.artifact, "eve@example.com"); err != nil {
		t.Fatal(err)
	}
	// Each member has opened it, so each has the owner pinned: a client that
	// sees an artifact for the first time anchors it at the creator's
	// directory entry, which a deactivated creator no longer has.
	for _, c := range []*Client{x.bob, x.cat, x.dan} {
		x.verify(c)
	}
	return x
}

func (x *xfer) id(c *Client) string {
	x.t.Helper()
	me, err := c.Me()
	if err != nil {
		x.t.Fatal(err)
	}
	return me.ID
}

func (x *xfer) offer(owner *Client, to string) {
	x.t.Helper()
	if _, err := owner.OfferTransfer(x.artifact, to+"@example.com", false); err != nil {
		x.t.Fatalf("OfferTransfer to %s: %v", to, err)
	}
}

// deactivate has the administrator deactivate u.
func (x *xfer) deactivate(u *Client) {
	x.t.Helper()
	if err := x.admin.doJSON("PATCH", "/api/admin/users/"+x.id(u), map[string]any{"disabled": true}, nil); err != nil {
		x.t.Fatal(err)
	}
}

// adminOffer has the administrator offer the artifact to to.
func (x *xfer) adminOffer(to *Client) {
	x.t.Helper()
	if err := x.admin.doJSON("POST", "/api/admin/artifacts/"+x.artifact+"/transfer", map[string]any{"to": x.id(to)}, nil); err != nil {
		x.t.Fatal(err)
	}
}

func (x *xfer) verify(c *Client) *VerifiedArtifact {
	x.t.Helper()
	va, err := c.VerifyArtifact(mustUnlock(x.t, c), x.artifact, "")
	if err != nil {
		x.t.Fatalf("VerifyArtifact: %v", err)
	}
	return va
}

// wrapEpochs opens every AK wrap c holds, checking each against the akCommit
// the chain lists for its epoch, and returns the epochs.
func (x *xfer) wrapEpochs(c *Client) []int {
	x.t.Helper()
	k := mustUnlock(x.t, c)
	va := x.verify(c)
	keys, err := c.Keys(x.artifact)
	if err != nil {
		x.t.Fatal(err)
	}
	var epochs []int
	for _, w := range keys.Wraps {
		ak, err := e2e.Unwrap(k.X25519Priv, e2e.WrapContext{
			Purpose: "ak", Artifact: x.artifact, Epoch: uint64(w.Epoch), RecipientID: k.UserID, RecipientPub: k.X25519Pub,
		}, w.Wrapped)
		if err != nil {
			x.t.Fatalf("Unwrap epoch %d: %v", w.Epoch, err)
		}
		if commit, _ := e2e.AKCommit(ak, x.artifact, uint64(w.Epoch)); commit != epochCommits(va.Chain)[w.Epoch] {
			x.t.Errorf("the AK wrapped for epoch %d does not match the chain's akCommit", w.Epoch)
		}
		epochs = append(epochs, w.Epoch)
	}
	return epochs
}

func today() string { return time.Now().UTC().Format("2006-01-02") }

func TestTransferKeepingThePreviousOwner(t *testing.T) {
	x := newXfer(t, nil)
	x.offer(x.ada, "bob")
	open, err := x.bob.OpenTransfer(x.artifact)
	if err != nil || open == nil || open.To != x.id(x.bob) || open.By != "owner" || open.Offer == nil {
		t.Fatalf("the open offer: %+v, %v", open, err)
	}
	res, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{})
	if err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	if res.Epoch != 2 || !res.Kept || res.PreviousOwner.Email != "ada@example.com" || res.Handover || res.NewEpoch {
		t.Errorf("result: %+v", res)
	}

	// A third member verifies the chain: bob owns it, ada is an editor, and
	// nothing is a handover.
	va := x.verify(x.dan)
	latest := va.Chain.Latest
	if latest.Owner != x.id(x.bob) || latest.Transfer != e2e.BodyHash(open.Offer.Body) || latest.Handover != "" || va.Handover != nil {
		t.Errorf("latest record %+v, handover %+v", latest, va.Handover)
	}
	if i := slices.IndexFunc(latest.Members, func(m e2e.Member) bool { return m.User == x.id(x.ada) && m.Role == "editor" }); i < 0 {
		t.Errorf("ada is not listed as an editor: %+v", latest.Members)
	}
	if slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == x.id(x.bob) }) {
		t.Errorf("the new owner is listed as a member: %+v", latest.Members)
	}

	// Ada holds a wrap of every epoch, and bob an estate copy of every epoch.
	if got := x.wrapEpochs(x.ada); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("ada's wraps: %v, want epochs 1 and 2", got)
	}
	if got := x.wrapEpochs(x.cat); !slices.Equal(got, []int{1, 2}) {
		t.Errorf("cat's wraps: %v", got)
	}
	if aks, err := x.bob.epochAKs(mustUnlock(t, x.bob), x.artifact, va.Chain); err != nil || len(aks) != 2 {
		t.Errorf("bob's estate copies: %d, %v", len(aks), err)
	}
	if got := x.wrapEpochs(x.bob); len(got) != 0 {
		t.Errorf("the new owner still holds wraps %v", got)
	}

	// Bob owns it now, and ada cannot change its members.
	if _, err := x.bob.Share(x.artifact, "eve@example.com", "viewer", false); err != nil {
		t.Errorf("the new owner's Share: %v", err)
	}
	if _, err := x.ada.Share(x.artifact, "eve@example.com", "viewer", false); !errors.Is(err, ErrNotOwner) {
		t.Errorf("the previous owner's Share: %v, want ErrNotOwner", err)
	}
	if open, err := x.dan.OpenTransfer(x.artifact); err != nil || open != nil {
		t.Errorf("an offer is still open: %+v, %v", open, err)
	}
}

func TestTransferDroppingThePreviousOwner(t *testing.T) {
	x := newXfer(t, nil)
	x.offer(x.ada, "bob")
	res, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true})
	if err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	if res.Epoch != 3 || res.Kept || !res.NewEpoch || len(res.Excluded) != 1 || res.Excluded[0].User.Email != "ada@example.com" {
		t.Errorf("result: %+v", res)
	}
	va := x.verify(x.dan)
	latest := va.Chain.Latest
	if latest.Epoch != 3 || latest.Owner != x.id(x.bob) {
		t.Errorf("latest record: %+v", latest)
	}
	if i := slices.IndexFunc(latest.Excluded, func(e e2e.ExcludedEntry) bool { return e.User == x.id(x.ada) && e.FP == mustUnlock(t, x.ada).FP }); i < 0 {
		t.Errorf("ada is not excluded under her fingerprint: %+v", latest.Excluded)
	}
	if slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == x.id(x.ada) || m.User == x.id(x.bob) }) {
		t.Errorf("members: %+v", latest.Members)
	}
	// Ada cannot open the new epoch's key, or anything of the artifact.
	if _, err := x.ada.Keys(x.artifact); statusOf(err) != http.StatusNotFound {
		t.Errorf("the excluded previous owner's Keys: %v, want 404", err)
	}
	// The others hold wraps of the new epoch, and bob holds estate copies of all three.
	if got := x.wrapEpochs(x.cat); !slices.Equal(got, []int{1, 2, 3}) {
		t.Errorf("cat's wraps: %v", got)
	}
	if got := x.wrapEpochs(x.dan); !slices.Equal(got, []int{1, 2, 3}) {
		t.Errorf("dan's wraps: %v", got)
	}
	if aks, err := x.bob.epochAKs(mustUnlock(t, x.bob), x.artifact, va.Chain); err != nil || len(aks) != 3 {
		t.Errorf("bob's estate copies: %d, %v", len(aks), err)
	}
	if _, err := x.bob.Unshare(x.artifact, "cat@example.com"); err != nil {
		t.Errorf("the new owner's Unshare: %v", err)
	}
}

func TestSecondOfferClosesTheFirst(t *testing.T) {
	x := newXfer(t, nil)
	x.offer(x.ada, "bob")
	res, err := x.ada.OfferTransfer(x.artifact, "cat@example.com", false)
	if err != nil || !res.Replaced {
		t.Fatalf("the second offer: %+v, %v", res, err)
	}
	if open, err := x.dan.OpenTransfer(x.artifact); err != nil || open == nil || open.To != x.id(x.cat) {
		t.Fatalf("the open offer: %+v, %v", open, err)
	}
	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); !errors.Is(err, ErrNoOfferToYou) {
		t.Errorf("accepting the closed first offer: %v, want ErrNoOfferToYou", err)
	}
	if err := x.bob.DeclineTransfer(x.artifact); !errors.Is(err, ErrNoOfferToYou) {
		t.Errorf("declining the closed first offer: %v, want ErrNoOfferToYou", err)
	}
	// The second offer names the closing record, so it is accepted as it is.
	if _, err := x.cat.AcceptTransfer(x.artifact, AcceptTransferOptions{}); err != nil {
		t.Fatalf("accepting the second offer: %v", err)
	}
	if got := x.verify(x.dan).Chain.Latest.Owner; got != x.id(x.cat) {
		t.Errorf("owner %s, want cat", got)
	}
}

func TestWithdrawAndDecline(t *testing.T) {
	t.Run("withdraw", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		before := len(x.verify(x.dan).Chain.Bodies)
		if err := x.ada.WithdrawTransfer(x.artifact); err != nil {
			t.Fatalf("WithdrawTransfer: %v", err)
		}
		if got := len(x.verify(x.dan).Chain.Bodies); got != before+1 {
			t.Errorf("records %d, want %d: a withdrawal is a new record", got, before+1)
		}
		if open, err := x.dan.OpenTransfer(x.artifact); err != nil || open != nil {
			t.Errorf("the offer is still open: %+v, %v", open, err)
		}
		if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); !errors.Is(err, ErrNoOfferToYou) {
			t.Errorf("accepting a withdrawn offer: %v, want ErrNoOfferToYou", err)
		}
		if err := x.ada.WithdrawTransfer(x.artifact); !errors.Is(err, ErrNoOffer) {
			t.Errorf("withdrawing with none open: %v, want ErrNoOffer", err)
		}
		// The old offer cannot come back: a new one works.
		x.offer(x.ada, "bob")
	})
	t.Run("only the owner withdraws", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		if err := x.bob.WithdrawTransfer(x.artifact); !errors.Is(err, ErrTransferNotOwner) {
			t.Errorf("the offered user's WithdrawTransfer: %v, want ErrTransferNotOwner", err)
		}
	})
	t.Run("decline", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		before := len(x.verify(x.dan).Chain.Bodies)
		if err := x.cat.DeclineTransfer(x.artifact); !errors.Is(err, ErrNoOfferToYou) {
			t.Errorf("another editor's DeclineTransfer: %v, want ErrNoOfferToYou", err)
		}
		if err := x.bob.DeclineTransfer(x.artifact); err != nil {
			t.Fatalf("DeclineTransfer: %v", err)
		}
		if open, err := x.dan.OpenTransfer(x.artifact); err != nil || open != nil {
			t.Errorf("the offer is still open: %+v, %v", open, err)
		}
		if got := len(x.verify(x.dan).Chain.Bodies); got != before {
			t.Errorf("records %d, want %d: a decline writes none", got, before)
		}
		if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); !errors.Is(err, ErrNoOfferToYou) {
			t.Errorf("accepting a declined offer: %v", err)
		}
	})
	t.Run("a public artifact", func(t *testing.T) {
		x := newXfer(t, nil)
		if _, err := x.ada.Public(x.artifact, true, nil); err != nil {
			t.Fatal(err)
		}
		x.offer(x.ada, "bob")
		if err := x.ada.WithdrawTransfer(x.artifact); err != nil {
			t.Fatalf("WithdrawTransfer: %v", err)
		}
		x.offer(x.ada, "bob")
		// A second offer closes the first with a record that carries the link hash.
		if res, err := x.ada.OfferTransfer(x.artifact, "cat@example.com", false); err != nil || !res.Replaced {
			t.Fatalf("the second offer: %+v, %v", res, err)
		}
		if _, err := x.cat.AcceptTransfer(x.artifact, AcceptTransferOptions{}); err != nil {
			t.Fatalf("accepting on a public artifact: %v", err)
		}
		if got := x.verify(x.dan).Chain.Latest; !got.Public || got.Owner != x.id(x.cat) {
			t.Errorf("latest record: %+v", got)
		}
	})
}

func TestTransferOnAPublicArtifactKeepsAndDrops(t *testing.T) {
	for _, drop := range []bool{false, true} {
		x := newXfer(t, nil)
		if _, err := x.ada.Public(x.artifact, true, nil); err != nil {
			t.Fatal(err)
		}
		x.offer(x.ada, "bob")
		res, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: drop})
		if err != nil {
			t.Fatalf("AcceptTransfer(drop=%v): %v", drop, err)
		}
		if drop != (res.Link != "") {
			t.Errorf("drop=%v: link %q, want one only for a new epoch", drop, res.Link)
		}
		if !x.verify(x.dan).Chain.Latest.Public {
			t.Errorf("drop=%v: the artifact is not public", drop)
		}
	}
}

// forgeOffer returns a proxy that serves bob the open offer with edit
// applied, signed by signer's seed, so only the check of that one field can
// refuse it.
func (x *xfer) forgeOffer(edit func(b *e2e.TransferBody), signer *Client) *Client {
	x.t.Helper()
	open, err := x.bob.OpenTransfer(x.artifact)
	if err != nil || open == nil || open.Offer == nil {
		x.t.Fatalf("no offer to forge: %+v, %v", open, err)
	}
	var body e2e.TransferBody
	if err := json.Unmarshal(open.Offer.Body, &body); err != nil {
		x.t.Fatal(err)
	}
	edit(&body)
	raw, err := json.Marshal(body)
	if err != nil {
		x.t.Fatal(err)
	}
	k := mustUnlock(x.t, signer)
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "transfer", raw)
	if err != nil {
		x.t.Fatal(err)
	}
	return x.serveOffer(env)
}

// serveOffer is bob's client behind a proxy that replaces the offer in the
// artifact view with env.
func (x *xfer) serveOffer(env e2e.Envelope) *Client {
	proxy := tamperingProxy(x.t, x.host, "/api/artifacts/"+x.artifact, func(m map[string]json.RawMessage) {
		var tr map[string]json.RawMessage
		if json.Unmarshal(m["transfer"], &tr) != nil {
			return
		}
		tr["offer"] = mustJSON(x.t, env)
		m["transfer"] = mustJSON(x.t, tr)
	})
	return viaProxy(proxy, x.bob)
}

func TestAcceptRefusesATamperedOffer(t *testing.T) {
	cases := []struct {
		name   string
		field  string
		edit   func(x *xfer, b *e2e.TransferBody)
		signer func(x *xfer) *Client
	}{
		{"artifact", "artifact", func(x *xfer, b *e2e.TransferBody) { b.Artifact = "another-artifact" }, nil},
		{"from", "from", func(x *xfer, b *e2e.TransferBody) { b.From = x.id(x.cat) }, nil},
		{"to", "to", func(x *xfer, b *e2e.TransferBody) { b.To = x.id(x.cat) }, nil},
		{"toFp", "toFp", func(x *xfer, b *e2e.TransferBody) { b.ToFP = strings.Repeat("a", 64) }, nil},
		{"prev", "prev", func(x *xfer, b *e2e.TransferBody) { b.Prev = strings.Repeat("b", 64) }, nil},
		{"signed by someone else", "signature", func(x *xfer, b *e2e.TransferBody) {}, func(x *xfer) *Client { return x.cat }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newXfer(t, nil)
			x.offer(x.ada, "bob")
			signer := x.ada
			if c.signer != nil {
				signer = c.signer(x)
			}
			bob := x.forgeOffer(func(b *e2e.TransferBody) { c.edit(x, b) }, signer)
			before := len(x.verify(x.dan).Chain.Bodies)
			_, err := bob.AcceptTransfer(x.artifact, AcceptTransferOptions{})
			if !errors.Is(err, ErrOfferRefused) || !strings.Contains(err.Error(), c.field) {
				t.Fatalf("AcceptTransfer: %v, want ErrOfferRefused naming %s", err, c.field)
			}
			if got := len(x.verify(x.dan).Chain.Bodies); got != before {
				t.Errorf("a refused offer was accepted anyway: %d records, want %d", got, before)
			}
		})
	}

	t.Run("a flipped signature byte", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		open, err := x.bob.OpenTransfer(x.artifact)
		if err != nil {
			t.Fatal(err)
		}
		env := *open.Offer
		env.Sig = slices.Clone(env.Sig)
		env.Sig[0] ^= 1
		_, err = x.serveOffer(env).AcceptTransfer(x.artifact, AcceptTransferOptions{})
		if !errors.Is(err, ErrOfferRefused) || !strings.Contains(err.Error(), "signature") {
			t.Errorf("AcceptTransfer: %v, want ErrOfferRefused naming the signature", err)
		}
	})
	t.Run("a body changed after signing", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		open, err := x.bob.OpenTransfer(x.artifact)
		if err != nil {
			t.Fatal(err)
		}
		env := *open.Offer
		env.Body = []byte(strings.Replace(string(env.Body), `"v":1`, `"v": 1`, 1))
		_, err = x.serveOffer(env).AcceptTransfer(x.artifact, AcceptTransferOptions{})
		if !errors.Is(err, ErrOfferRefused) {
			t.Errorf("AcceptTransfer: %v, want ErrOfferRefused", err)
		}
	})
	t.Run("owner keys the server swapped", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		_, pair, _ := strangerKeys(t)
		proxy := tamperingProxy(t, x.host, "/membership", func(m map[string]json.RawMessage) {
			var owners map[string]e2e.KeyPair
			json.Unmarshal(m["owners"], &owners)
			for fp := range owners {
				owners[fp] = pair
			}
			m["owners"] = mustJSON(t, owners)
		})
		if _, err := viaProxy(proxy, x.bob).AcceptTransfer(x.artifact, AcceptTransferOptions{}); err == nil {
			t.Error("AcceptTransfer accepted a chain with swapped owner keys")
		}
	})
	t.Run("no offer", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		proxy := tamperingProxy(t, x.host, "/api/artifacts/"+x.artifact, func(m map[string]json.RawMessage) {
			var tr map[string]json.RawMessage
			json.Unmarshal(m["transfer"], &tr)
			tr["offer"] = json.RawMessage("null")
			m["transfer"] = mustJSON(t, tr)
		})
		if _, err := viaProxy(proxy, x.bob).AcceptTransfer(x.artifact, AcceptTransferOptions{}); !errors.Is(err, ErrOfferRefused) {
			t.Errorf("AcceptTransfer: %v, want ErrOfferRefused", err)
		}
	})
	t.Run("an offer by someone the client does not know", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		proxy := tamperingProxy(t, x.host, "/api/artifacts/"+x.artifact, func(m map[string]json.RawMessage) {
			var tr map[string]json.RawMessage
			json.Unmarshal(m["transfer"], &tr)
			tr["by"] = json.RawMessage(`"a stranger"`)
			m["transfer"] = mustJSON(t, tr)
		})
		if _, err := viaProxy(proxy, x.bob).AcceptTransfer(x.artifact, AcceptTransferOptions{}); err == nil || !strings.Contains(err.Error(), "a stranger") {
			t.Errorf("AcceptTransfer: %v", err)
		}
	})
}

func TestOfferRefusals(t *testing.T) {
	x := newXfer(t, nil)
	for _, c := range []struct {
		name string
		by   *Client
		to   string
		want error
	}{
		{"to a viewer", x.ada, "dan@example.com", ErrTransferNotEditor},
		{"to a user who is not a member", x.ada, "admin@example.com", ErrTransferNotEditor},
		{"to an excluded user", x.ada, "eve@example.com", ErrTransferNotEditor},
		{"to oneself", x.ada, "ada@example.com", ErrTransferNotEditor},
		{"to nobody", x.ada, "nobody@example.com", ErrUnknownUser},
		{"by an editor", x.bob, "cat@example.com", ErrTransferNotOwner},
		{"by a viewer", x.dan, "bob@example.com", ErrTransferNotOwner},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.by.OfferTransfer(x.artifact, c.to, false); !errors.Is(err, c.want) {
				t.Errorf("OfferTransfer: %v, want %v", err, c.want)
			}
			if open, err := x.dan.OpenTransfer(x.artifact); err != nil || open != nil {
				t.Errorf("a refused offer is open: %+v, %v", open, err)
			}
		})
	}
	t.Run("accepting with no offer", func(t *testing.T) {
		if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); !errors.Is(err, ErrNoOfferToYou) {
			t.Errorf("AcceptTransfer: %v", err)
		}
	})
	t.Run("accepting when the offer is to another", func(t *testing.T) {
		x := newXfer(t, nil)
		x.offer(x.ada, "bob")
		if _, err := x.cat.AcceptTransfer(x.artifact, AcceptTransferOptions{}); !errors.Is(err, ErrNoOfferToYou) {
			t.Errorf("AcceptTransfer: %v", err)
		}
	})
}

func TestOfferChecksTheEditorsKey(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	s.resetBob(t)
	_, err := s.ada.OfferTransfer(s.artifact, "bob@example.com", false)
	var changed *KeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("OfferTransfer after bob reset: %v, want *KeyChangedError", err)
	}
	// With the flag the key is accepted, but the record still lists the old
	// one, so the owner shares again first.
	if _, err := s.ada.OfferTransfer(s.artifact, "bob@example.com", true); !errors.Is(err, ErrMemberKeyChanged) {
		t.Fatalf("OfferTransfer --accept-new-key: %v, want ErrMemberKeyChanged", err)
	}
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.OfferTransfer(s.artifact, "bob@example.com", false); err != nil {
		t.Errorf("OfferTransfer after sharing again: %v", err)
	}
}

func TestOfferPinsAFirstSeenEditor(t *testing.T) {
	x := newXfer(t, nil)
	k := mustUnlock(t, x.ada)
	kr, err := x.ada.ReadKeyring(k)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := kr.Pins[x.id(x.bob)]; !ok {
		t.Fatal("bob is not pinned after Share")
	}
	res, err := x.ada.OfferTransfer(x.artifact, "bob@example.com", false)
	if err != nil || res.Prior != e2e.PinUnverified || res.Replaced {
		t.Errorf("OfferTransfer: %+v, %v", res, err)
	}
}

func TestAcceptNeedsTheKeptPreviousOwnerInTheDirectory(t *testing.T) {
	x := newXfer(t, nil)
	x.offer(x.ada, "bob")
	x.deactivate(x.ada)
	// A deactivated owner is not in the directory, so they cannot be kept.
	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); !errors.Is(err, ErrPreviousOwnerGone) {
		t.Fatalf("AcceptTransfer: %v, want ErrPreviousOwnerGone", err)
	}
	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true}); err != nil {
		t.Fatalf("AcceptTransfer dropping them: %v", err)
	}
}

func TestAcceptingAnAdministratorsOfferDropsThePreviousOwnerByDefault(t *testing.T) {
	x := newXfer(t, nil)
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	res, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{})
	if err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	if !res.Handover || res.Kept || !res.NewEpoch || res.Epoch != 3 {
		t.Errorf("result: %+v", res)
	}
	if latest := x.verify(x.dan).Chain.Latest; latest.Epoch != 3 || latest.Owner != x.id(x.bob) {
		t.Errorf("latest record: %+v", latest)
	}
}

func TestAcceptRefusesAnAdministratorsOfferWhileTheOwnerIsActive(t *testing.T) {
	x := newXfer(t, nil)
	x.offer(x.ada, "bob")
	// The server says an administrator made the owner's offer.
	proxy := tamperingProxy(t, x.host, "/api/artifacts/"+x.artifact, func(m map[string]json.RawMessage) {
		var tr map[string]json.RawMessage
		json.Unmarshal(m["transfer"], &tr)
		tr["by"] = json.RawMessage(`"admin"`)
		tr["offer"] = json.RawMessage("null")
		m["transfer"] = mustJSON(t, tr)
	})
	before := len(x.verify(x.dan).Chain.Bodies)
	_, err := viaProxy(proxy, x.bob).AcceptTransfer(x.artifact, AcceptTransferOptions{})
	if !errors.Is(err, ErrOfferRefused) || !strings.Contains(err.Error(), "still active") {
		t.Fatalf("AcceptTransfer: %v, want ErrOfferRefused saying the owner is still active", err)
	}
	if got := len(x.verify(x.dan).Chain.Bodies); got != before {
		t.Errorf("a refused offer was accepted anyway: %d records, want %d", got, before)
	}
}

func TestDeclineNeedsNoHandoverAcknowledgement(t *testing.T) {
	x := newXfer(t, nil)
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); err != nil {
		t.Fatal(err)
	}
	x.offer(x.bob, "cat")
	// Cat never acknowledged the handover, and may still decline.
	var refused *HandoverNotAckedError
	if _, err := x.cat.AcceptTransfer(x.artifact, AcceptTransferOptions{}); !errors.As(err, &refused) {
		t.Fatalf("AcceptTransfer: %v, want *HandoverNotAckedError", err)
	}
	if err := x.cat.DeclineTransfer(x.artifact); err != nil {
		t.Fatalf("DeclineTransfer: %v", err)
	}
	if open, err := x.dan.OpenTransfer(x.artifact); err != nil || open != nil {
		t.Errorf("the offer is still open: %+v, %v", open, err)
	}
}

func TestAdministratorHandover(t *testing.T) {
	x := newXfer(t, nil)
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	open, err := x.bob.OpenTransfer(x.artifact)
	if err != nil || open == nil || open.By != "admin" || open.Offer != nil {
		t.Fatalf("the open offer: %+v, %v", open, err)
	}
	res, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true})
	if err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	if !res.Handover || res.Epoch != 3 || res.Kept {
		t.Errorf("result: %+v", res)
	}
	seq := len(x.verify(x.dan).Chain.Bodies)

	// The accepting user sees the notice, already acknowledged, and is never refused.
	if h := x.verify(x.bob).Handover; h == nil || !h.Acked || h.Seq != seq || h.Date != today() {
		t.Errorf("the new owner's notice: %+v", h)
	}
	if _, err := x.bob.Share(x.artifact, "eve@example.com", "viewer", false); err != nil {
		t.Errorf("the new owner's Share: %v", err)
	}

	// A third member sees the notice with the date, unacknowledged.
	h := x.verify(x.cat).Handover
	if h == nil || h.Acked || h.Seq != seq || h.Date != today() {
		t.Fatalf("the third member's notice: %+v, want unacknowledged, seq %d, %s", h, seq, today())
	}
	// A viewer sees it too, and reading never refuses.
	if h := x.verify(x.dan).Handover; h == nil || h.Acked {
		t.Errorf("the viewer's notice: %+v", h)
	}
	if _, _, err := x.cat.Members(x.artifact); err != nil {
		t.Errorf("Members: %v", err)
	}
	if _, err := x.cat.Pending(x.artifact); err != nil {
		t.Errorf("Pending: %v", err)
	}
	// The owner reads it too, and the owner's Review is not a write.
	if _, err := x.bob.Review(x.artifact); err != nil {
		t.Errorf("Review: %v", err)
	}
}

func TestEveryWriteRefusesAnUnacknowledgedHandover(t *testing.T) {
	x := newXfer(t, nil)
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true}); err != nil {
		t.Fatal(err)
	}
	seq := len(x.verify(x.dan).Chain.Bodies)
	site := siteDir(t)
	writes := []struct {
		name string
		c    *Client
		do   func(c *Client) error
	}{
		{"Share", x.cat, func(c *Client) error { _, err := c.Share(x.artifact, "eve@example.com", "viewer", false); return err }},
		{"Unshare", x.cat, func(c *Client) error { _, err := c.Unshare(x.artifact, "dan@example.com"); return err }},
		{"Team", x.cat, func(c *Client) error { _, err := c.Team(x.artifact, "viewer"); return err }},
		{"Approve", x.cat, func(c *Client) error { _, err := c.Approve(x.artifact, "eve@example.com", false); return err }},
		{"Public", x.cat, func(c *Client) error { _, err := c.Public(x.artifact, true, nil); return err }},
		{"Vouch", x.cat, func(c *Client) error { return c.Vouch(x.artifact, "no-such-version") }},
		{"Push", x.cat, func(c *Client) error { _, err := c.Push(x.artifact, "", site, "v1", ""); return err }},
		{"OfferTransfer", x.cat, func(c *Client) error { _, err := c.OfferTransfer(x.artifact, "bob@example.com", false); return err }},
		{"WithdrawTransfer", x.cat, func(c *Client) error { return c.WithdrawTransfer(x.artifact) }},
		{"AcceptTransfer", x.cat, func(c *Client) error {
			_, err := c.AcceptTransfer(x.artifact, AcceptTransferOptions{})
			return err
		}},
	}
	for _, w := range writes {
		t.Run(w.name, func(t *testing.T) {
			var refused *HandoverNotAckedError
			if err := w.do(w.c); !errors.As(err, &refused) || refused.Seq != seq || refused.Date != today() {
				t.Fatalf("%s: %v, want *HandoverNotAckedError for seq %d on %s", w.name, err, seq, today())
			}
		})
	}
	if got := len(x.verify(x.dan).Chain.Bodies); got != seq {
		t.Errorf("a refused write landed: %d records, want %d", got, seq)
	}

	// Told to accept, a write records the acknowledgement and goes ahead; the
	// notice still shows afterwards, and the next write needs no flag.
	x.cat.AcceptNewOwner = true
	if _, err := x.cat.Push(x.artifact, "", site, "v1", ""); err != nil {
		t.Fatalf("Push with AcceptNewOwner: %v", err)
	}
	x.cat.AcceptNewOwner = false
	kr, err := x.cat.ReadKeyring(mustUnlock(t, x.cat))
	if err != nil || kr.Epochs[x.artifact].Ack != seq {
		t.Errorf("the keyring's ack: %+v, %v, want %d", kr.Epochs[x.artifact], err, seq)
	}
	if h := x.verify(x.cat).Handover; h == nil || !h.Acked || h.Date != today() {
		t.Errorf("the notice after acknowledging: %+v", h)
	}
	if _, err := x.cat.Push(x.artifact, "", site, "v2", ""); err != nil {
		t.Errorf("Push after acknowledging: %v", err)
	}
	// Another viewer's acknowledgement is their own.
	var refused *HandoverNotAckedError
	if _, err := x.dan.Push(x.artifact, "", site, "v3", ""); !errors.As(err, &refused) {
		t.Errorf("a member who did not acknowledge: %v", err)
	}
}

func TestAcknowledgementSurvivesALaterRecord(t *testing.T) {
	x := newXfer(t, nil)
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true}); err != nil {
		t.Fatal(err)
	}
	x.cat.AcceptNewOwner = true
	if _, err := x.cat.Push(x.artifact, "", siteDir(t), "v1", ""); err != nil {
		t.Fatal(err)
	}
	// A later record does not undo it: the chain moves on, the ack stays.
	if _, err := x.bob.Share(x.artifact, "eve@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	x.cat.AcceptNewOwner = false
	if h := x.verify(x.cat).Handover; h == nil || !h.Acked {
		t.Errorf("the notice after a later record: %+v", h)
	}
}

func TestHandoverNoticeWords(t *testing.T) {
	if got := (&HandoverNotice{Date: "2026-10-02"}).String(); got != "ownership was handed over by an administrator on 2026-10-02" {
		t.Errorf("notice: %q", got)
	}
	if got := (&HandoverNotice{}).String(); got != "ownership was handed over by an administrator" {
		t.Errorf("notice without a date: %q", got)
	}
	err := &HandoverNotAckedError{Date: "2026-10-02", Seq: 4}
	if !strings.Contains(err.Error(), "on 2026-10-02") || !strings.Contains(err.Error(), "not acknowledged") {
		t.Errorf("error: %q", err)
	}
}

func TestHandoverNoticeWithoutADate(t *testing.T) {
	x := newXfer(t, nil)
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true}); err != nil {
		t.Fatal(err)
	}
	proxy := tamperingProxy(t, x.host, "/membership", func(m map[string]json.RawMessage) { delete(m, "ownerChanges") })
	h := x.verify(viaProxy(proxy, x.cat)).Handover
	if h == nil || h.Date != "" || h.Acked {
		t.Errorf("notice without ownerChanges: %+v", h)
	}
}

func TestRotateWarnsAboutRecentTransfers(t *testing.T) {
	for days, want := range map[int]int{29: 1, 31: 0} {
		clk := clock.NewFake(time.Now())
		x := newXfer(t, func(c *server.Config) { c.Clock = clk })
		x.offer(x.ada, "bob")
		if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); err != nil {
			t.Fatal(err)
		}
		clk.Advance(time.Duration(days) * 24 * time.Hour)
		res := rotateOK(t, x.ada, false)
		if len(res.Warnings) != want {
			t.Fatalf("after %d days the previous owner got warnings %q, want %d", days, res.Warnings, want)
		}
		if want == 0 {
			continue
		}
		w := res.Warnings[0]
		if !strings.Contains(w, x.artifact) || !strings.Contains(w, "bob@example.com") || !strings.Contains(w, "handed ownership") {
			t.Errorf("the previous owner's warning: %q", w)
		}
		res = rotateOK(t, x.bob, false)
		if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "ada@example.com") || !strings.Contains(res.Warnings[0], "took ownership") ||
			!strings.Contains(res.Warnings[0], x.artifact) {
			t.Errorf("the new owner's warnings: %q", res.Warnings)
		}
		if res = rotateOK(t, x.cat, false); len(res.Warnings) != 0 {
			t.Errorf("another member's warnings: %q", res.Warnings)
		}
	}
}

func TestOwnerKeyNeedsThePairToHashToTheFingerprint(t *testing.T) {
	_, pair, fp := strangerKeys(t)
	if _, err := ownerKey(map[string]e2e.KeyPair{fp: pair}, fp); err != nil {
		t.Errorf("a pair that hashes to its fingerprint: %v", err)
	}
	_, other, _ := strangerKeys(t)
	if _, err := ownerKey(map[string]e2e.KeyPair{fp: other}, fp); err == nil {
		t.Error("a pair that does not hash to the fingerprint was taken")
	}
	if _, err := ownerKey(map[string]e2e.KeyPair{fp: {X25519: "!", Ed25519: "!"}}, fp); err == nil {
		t.Error("a pair that is not base64 was taken")
	}
	if _, err := ownerKey(map[string]e2e.KeyPair{}, fp); err == nil {
		t.Error("a missing pair was taken")
	}
}

// An editor whose keys changed after the owner offered cannot take it: the
// record lists their old keys.
func TestAcceptAfterTheEditorsOwnKeysChanged(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.OfferTransfer(s.artifact, "bob@example.com", false); err != nil {
		t.Fatal(err)
	}
	s.resetBob(t)
	if _, err := s.bob.AcceptTransfer(s.artifact, AcceptTransferOptions{}); !errors.Is(err, ErrMemberKeyChanged) {
		t.Errorf("AcceptTransfer after a reset: %v, want ErrMemberKeyChanged", err)
	}
}

func TestTransferWarningsNameUnknownUsersByID(t *testing.T) {
	ts := []rotateTransfer{{Artifact: "a1", From: "me", To: "u9", At: "2026-10-01"}, {Artifact: "a2", From: "u8", To: "me", At: "2026-10-02"}}
	got := transferWarnings(ts, "me", map[string]string{"u8": "u8@example.com"})
	if len(got) != 2 || !strings.Contains(got[0], "to u9 on 2026-10-01") || !strings.Contains(got[1], "from u8@example.com on 2026-10-02") {
		t.Errorf("warnings: %q", got)
	}
	if got := transferWarnings(nil, "me", nil); len(got) != 0 {
		t.Errorf("warnings for nothing: %q", got)
	}
}
