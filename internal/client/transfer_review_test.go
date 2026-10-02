package client

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// newMember signs up name and shares the artifact with it as a viewer. It
// has never opened the artifact, so it has no pin for the creator.
func (x *xfer) newMember(name string) *Client {
	x.t.Helper()
	email := name + "@example.com"
	signupVerify(x.t, x.host, x.m, email, testPassword)
	out, err := New(x.host, "").Login(email, testPassword)
	if err != nil {
		x.t.Fatal(err)
	}
	c := keyedFor(x.t, x.host, out.APIKey)
	if _, err := x.ada.Share(x.artifact, email, "viewer", false); err != nil {
		x.t.Fatalf("Share %s: %v", name, err)
	}
	return c
}

// failingProxy answers a request whose path ends with suffix with status, and
// forwards every other.
func failingProxy(t *testing.T, host, suffix string, status int) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, suffix) {
			http.Error(w, `{"error":"boom"}`, status)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFirstSightVerifiesWhenTheCreatorIsDeactivated(t *testing.T) {
	t.Run("an administrator's handover", func(t *testing.T) {
		x := newXfer(t, nil)
		fay := x.newMember("fay")
		adaID, adaFP := x.id(x.ada), mustUnlock(t, x.ada).FP
		x.deactivate(x.ada)
		x.adminOffer(x.bob)
		if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true}); err != nil {
			t.Fatal(err)
		}
		if got := x.wrapEpochs(fay); !slices.Equal(got, []int{1, 2, 3}) {
			t.Errorf("fay's wraps: %v", got)
		}
		kr, err := fay.ReadKeyring(mustUnlock(t, fay))
		if err != nil {
			t.Fatal(err)
		}
		if p, ok := kr.Pins[adaID]; !ok || p.State != e2e.PinUnverified || p.FP != adaFP {
			t.Errorf("the creator's pin: %+v, %v", p, ok)
		}
	})
	t.Run("an owner's transfer keeping the previous owner", func(t *testing.T) {
		x := newXfer(t, nil)
		fay := x.newMember("fay")
		x.offer(x.ada, "bob")
		if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); err != nil {
			t.Fatal(err)
		}
		x.deactivate(x.ada)
		if got := x.wrapEpochs(fay); !slices.Equal(got, []int{1, 2}) {
			t.Errorf("fay's wraps: %v", got)
		}
	})
	t.Run("served owner keys that do not match record 0", func(t *testing.T) {
		x := newXfer(t, nil)
		fay := x.newMember("fay")
		adaID, _ := x.id(x.ada), mustUnlock(t, x.ada).FP
		x.deactivate(x.ada)
		_, pair, _ := strangerKeys(t)
		proxy := tamperingProxy(t, x.host, "/membership", func(m map[string]json.RawMessage) {
			var owners map[string]e2e.KeyPair
			json.Unmarshal(m["owners"], &owners)
			for fp := range owners {
				owners[fp] = pair
			}
			m["owners"] = mustJSON(t, owners)
		})
		_, err := viaProxy(proxy, fay).VerifyArtifact(mustUnlock(t, fay), x.artifact, "")
		if !errors.Is(err, e2e.ErrChain) {
			t.Errorf("VerifyArtifact: %v, want e2e.ErrChain", err)
		}
		kr, _ := fay.ReadKeyring(mustUnlock(t, fay))
		if _, ok := kr.Pins[adaID]; ok {
			t.Error("a refused chain left a pin")
		}
	})
	t.Run("another lookup error still fails", func(t *testing.T) {
		x := newXfer(t, nil)
		fay := x.newMember("fay")
		adaID, _ := x.id(x.ada), mustUnlock(t, x.ada).FP
		x.deactivate(x.ada)
		proxy := failingProxy(t, x.host, "/api/users/"+adaID, http.StatusInternalServerError)
		if _, err := viaProxy(proxy, fay).VerifyArtifact(mustUnlock(t, fay), x.artifact, ""); statusOf(err) != http.StatusInternalServerError {
			t.Errorf("VerifyArtifact: %v, want the 500", err)
		}
	})
}

func TestLinkVisitorSeesTheHandoverNotice(t *testing.T) {
	x := newXfer(t, nil)
	pub, err := x.ada.Public(x.artifact, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Before any handover a visitor has no notice.
	opened, err := OpenLink(pub.Link)
	if err != nil || opened.Handover != nil {
		t.Fatalf("OpenLink before a handover: %+v, %v", opened, err)
	}
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	res, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{DropPreviousOwner: true})
	if err != nil || res.Link == "" {
		t.Fatalf("AcceptTransfer: %+v, %v", res, err)
	}
	var called []HandoverNotice
	c := New(x.host, "")
	c.OnHandover = func(id string, n HandoverNotice) {
		if id != x.artifact {
			t.Errorf("notice for %s", id)
		}
		called = append(called, n)
	}
	opened, err = c.OpenLink(mustParseLink(t, res.Link))
	if err != nil {
		t.Fatalf("OpenLink: %v", err)
	}
	h := opened.Handover
	if h == nil || h.Acked || h.Seq != len(opened.Chain.Bodies) || h.Date != today() {
		t.Fatalf("the visitor's notice: %+v, want unacknowledged, seq %d, %s", h, len(opened.Chain.Bodies), today())
	}
	if len(called) != 1 || called[0] != *h {
		t.Errorf("OnHandover calls: %+v", called)
	}
	if opened, err := OpenLink(res.Link); err != nil || opened.Handover == nil {
		t.Errorf("the package-level OpenLink: %+v, %v", opened, err)
	}
}
