package client

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/google/uuid"
)

// keyedFor builds a client that holds the whole of full, so it can unlock
// the account's keys as well as authenticate.
func keyedFor(t *testing.T, host, full string) *Client {
	t.Helper()
	key, err := e2e.ParseAPIKey(full)
	if err != nil {
		t.Fatal(err)
	}
	return NewWithKey(host, key)
}

// keyedLogin signs up and logs in a fresh account on host and returns its
// full API key.
func keyedLogin(t *testing.T) (host, full string) {
	t.Helper()
	host, m := newTestServer(t)
	email, password := "ada@example.com", "correct horse battery staple"
	signupVerify(t, host, m, email, password)
	out, err := New(host, "").Login(email, password)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return host, out.APIKey
}

func TestUnlock(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)

	k, err := c.Unlock()
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	me, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := c.MeBundle()
	if err != nil {
		t.Fatal(err)
	}
	if k.UserID != me.ID {
		t.Errorf("UserID = %q, want %q", k.UserID, me.ID)
	}
	if !bytes.Equal(k.X25519Pub, bundle.X25519Pub) || !bytes.Equal(k.Ed25519Pub, bundle.Ed25519Pub) {
		t.Error("unlocked public keys differ from the bundle's")
	}
	if want := hex.EncodeToString(e2e.Fingerprint(bundle.X25519Pub, bundle.Ed25519Pub)); k.FP != want {
		t.Errorf("FP = %q, want %q", k.FP, want)
	}
	// The private halves really are the bundle's.
	_, xPub, _ := e2e.GenerateX25519(bytes.NewReader(k.X25519Priv))
	_, edPub, _ := e2e.GenerateEd25519(bytes.NewReader(k.Ed25519Seed))
	if !bytes.Equal(xPub, bundle.X25519Pub) || !bytes.Equal(edPub, bundle.Ed25519Pub) {
		t.Error("unlocked private keys do not derive the bundle's public keys")
	}
	if len(k.EK) != 32 {
		t.Errorf("EK length %d", len(k.EK))
	}
}

func TestUnlockRefusals(t *testing.T) {
	host, full := keyedLogin(t)

	// A bearer-only client has no keySecret to open MK with.
	if _, err := bearerFor(t, host, full).Unlock(); err == nil {
		t.Error("bearer-only client unlocked")
	}

	// A wrong keySecret cannot open the device key's MK.
	key, err := e2e.ParseAPIKey(full)
	if err != nil {
		t.Fatal(err)
	}
	key.KeySecret = bytes.Repeat([]byte{7}, len(key.KeySecret))
	if _, err := NewWithKey(host, key).Unlock(); err == nil {
		t.Error("wrong keySecret unlocked")
	}
}

func TestCreateArtifact(t *testing.T) {
	host, full := keyedLogin(t)
	c := keyedFor(t, host, full)
	k, err := c.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	a, err := c.CreateArtifact("widget", "a widget")
	if err != nil {
		t.Fatalf("CreateArtifact: %v", err)
	}
	if u, err := uuid.Parse(a.ID); err != nil || u.Version() != 4 || u.String() != a.ID {
		t.Errorf("id %q is not a random UUID", a.ID)
	}
	if a.Name != "widget" || a.Description != "a widget" || a.OwnerID != k.UserID || a.Public || a.Epoch != 1 {
		t.Errorf("artifact = %+v", a)
	}

	m, err := c.Membership(a.ID)
	if err != nil {
		t.Fatalf("Membership: %v", err)
	}
	if len(m.Records) != 1 {
		t.Fatalf("%d records", len(m.Records))
	}
	rec := m.Records[0]
	if rec.Signer != k.UserID || !rec.Verify(k.Ed25519Pub, "membership") {
		t.Error("the first record is not signed by the creator")
	}
	// The empty lists are sent as lists, not null.
	for _, want := range []string{`"members":[]`, `"excluded":[]`, `"prev":""`} {
		if !strings.Contains(string(rec.Body), want) {
			t.Errorf("record body lacks %s: %s", want, rec.Body)
		}
	}
	var b e2e.MembershipBody
	if err := json.Unmarshal(rec.Body, &b); err != nil {
		t.Fatal(err)
	}
	if b.V != 1 || b.Artifact != a.ID || b.Epoch != 1 || b.Seq != 1 || b.Owner != k.UserID || b.OwnerFP != k.FP ||
		b.Team != "none" || b.Public || b.PublicWrites || b.Transfer != "" || b.Handover != "" {
		t.Errorf("first record = %+v", b)
	}
	if _, ok := m.Owners[k.FP]; !ok {
		t.Errorf("owners lacks the creator: %+v", m.Owners)
	}

	keys, err := c.Keys(a.ID)
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys.Wraps) != 0 || len(keys.Estate) != 1 || keys.Estate[0].Epoch != 1 {
		t.Fatalf("keys = %+v", keys)
	}
	// The estate copy opens under EK to the AK the record commits to.
	ekKey, err := e2e.EKSealKey(k.EK)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := e2e.Open(ekKey, [][]byte{[]byte("estate"), []byte(a.ID), []byte("1")}, keys.Estate[0].Sealed)
	if err != nil {
		t.Fatalf("estate copy does not open under EK: %v", err)
	}
	if commit, _ := e2e.AKCommit(ak, a.ID, 1); commit != b.AKCommit {
		t.Error("the estate copy's AK does not match the record's akCommit")
	}

	// Two artifacts never share an id or an AK.
	a2, err := c.CreateArtifact("widget", "")
	if err != nil {
		t.Fatal(err)
	}
	if a2.ID == a.ID {
		t.Error("two artifacts share an id")
	}
}

// tamperingProxy forwards to host, letting rewrite change the body of every
// successful GET whose path ends in suffix.
func tamperingProxy(t *testing.T, host, suffix string, rewrite func(m map[string]json.RawMessage)) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		r := resp.Request
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, suffix) || resp.StatusCode != 200 {
			return nil
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(data, &m); err != nil {
			return err
		}
		rewrite(m)
		data, err = json.Marshal(m)
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts.URL
}

// strangerKeys is a key pair the client has never seen.
func strangerKeys(t *testing.T) (seed []byte, pair e2e.KeyPair, fp string) {
	t.Helper()
	_, xPub, err := e2e.GenerateX25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed, edPub, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return seed, e2e.KeyPair{X25519: e2e.B64(xPub), Ed25519: e2e.B64(edPub)}, hex.EncodeToString(e2e.Fingerprint(xPub, edPub))
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCreateArtifactVerifiesTheChain covers the read-back: a server that
// hands back a chain the creator did not sign is refused.
func TestCreateArtifactVerifiesTheChain(t *testing.T) {
	host, full := keyedLogin(t)

	t.Run("owner keys swapped", func(t *testing.T) {
		_, pair, _ := strangerKeys(t)
		proxy := tamperingProxy(t, host, "/membership", func(m map[string]json.RawMessage) {
			var owners map[string]e2e.KeyPair
			json.Unmarshal(m["owners"], &owners)
			for fp := range owners {
				owners[fp] = pair
			}
			m["owners"] = mustJSON(t, owners)
		})
		if _, err := keyedFor(t, proxy, full).CreateArtifact("swapped", ""); err == nil {
			t.Error("a chain whose owner keys were swapped was accepted")
		}
	})

	t.Run("signed by someone else", func(t *testing.T) {
		seed, pair, fp := strangerKeys(t)
		proxy := tamperingProxy(t, host, "/membership", func(m map[string]json.RawMessage) {
			var recs []e2e.Envelope
			json.Unmarshal(m["records"], &recs)
			var b e2e.MembershipBody
			json.Unmarshal(recs[0].Body, &b)
			b.OwnerFP = fp
			body, _ := json.Marshal(b)
			env, err := e2e.NewEnvelope(seed, b.Owner, "membership", body)
			if err != nil {
				t.Error(err)
				return
			}
			m["records"] = mustJSON(t, []e2e.Envelope{env})
			m["owners"] = mustJSON(t, map[string]e2e.KeyPair{fp: pair})
		})
		if _, err := keyedFor(t, proxy, full).CreateArtifact("forged", ""); err == nil {
			t.Error("a chain anchored at another key was accepted")
		}
	})
}

// TestUnlockRefusesMismatchedPublicKeys covers a server that publishes
// public keys the account's private keys do not derive.
func TestUnlockRefusesMismatchedPublicKeys(t *testing.T) {
	host, full := keyedLogin(t)
	for _, field := range []string{"x25519Pub", "ed25519Pub"} {
		t.Run(field, func(t *testing.T) {
			_, pair, _ := strangerKeys(t)
			pub := pair.X25519
			if field == "ed25519Pub" {
				pub = pair.Ed25519
			}
			proxy := tamperingProxy(t, host, "/api/me/bundle", func(m map[string]json.RawMessage) {
				m[field] = mustJSON(t, pub)
			})
			if _, err := keyedFor(t, proxy, full).Unlock(); err == nil {
				t.Errorf("a bundle with a foreign %s unlocked", field)
			}
		})
	}
}
