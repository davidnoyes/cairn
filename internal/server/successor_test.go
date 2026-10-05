package server

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
)

// The successor. See "Successor" in design/e2e-api.md.

const day = 24 * time.Hour

// succWorld is a user u who owns an artifact, a user sc to nominate, a third
// user, and an artifact the third user owns and shares with u. The server runs
// on a fake clock, so a test crosses the 14 days without waiting.
type succWorld struct {
	t            *testing.T
	s            *Server
	base         string
	clk          *clock.Fake
	admin        *testClient
	u, sc, other actor
	art, shared  *owned
	seq          int // the last successor record u signed
}

func newSuccWorld(t *testing.T) *succWorld {
	t.Helper()
	w := &succWorld{t: t}
	s, ts := newTestServer(t, func(c *Config) {
		w.clk = clock.NewFake(time.Now())
		c.Clock = w.clk
		c.PublicURL, c.ContentDomain = "https://cairn.example.com", "cairn-content.example.net"
	})
	seedAccount(t, s, "admin@example.com", "admin-password", true)
	w.s, w.base = s, ts.URL
	w.admin = login(t, ts.URL, "admin@example.com", "admin-password")
	w.u = seedKeyedAccount(t, s, ts.URL, "u@example.com")
	w.sc = seedKeyedAccount(t, s, ts.URL, "sc@example.com")
	w.other = seedKeyedAccount(t, s, ts.URL, "other@example.com")
	w.art = newArtifact(t, w.u, "doc")
	w.shared = newArtifact(t, w.other, "theirs")
	w.shared.share("viewer", w.u)
	return w
}

func signSuccessor(t *testing.T, who actor, b e2e.SuccessorBody) e2e.Envelope {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(who.keys.seed, who.id, "successor", raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func signRefusal(t *testing.T, who actor, requestedAt string) e2e.Envelope {
	t.Helper()
	raw, err := json.Marshal(e2e.RefusalBody{V: 1, User: who.id, RequestedAt: requestedAt})
	if err != nil {
		t.Fatal(err)
	}
	env, err := e2e.NewEnvelope(who.keys.seed, who.id, "refusal", raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func authKeyOf(a actor) string { return e2e.B64(testAuthKey(a.email + "-password")) }

// nominateBody is the valid PUT /api/me/successor body for who nominating to
// at seq.
func nominateBody(t *testing.T, who, to actor, seq int) map[string]any {
	t.Helper()
	rec := signSuccessor(t, who, e2e.SuccessorBody{V: 1, User: who.id, Seq: seq, Successor: to.id, SuccessorFP: to.keys.fp(), Action: "nominate"})
	return map[string]any{"authKey": authKeyOf(who), "successor": to.id, "record": rec, "wrapped": e2e.B64(fakeWrap)}
}

func removeBody(t *testing.T, who actor, current actor, seq int) map[string]any {
	t.Helper()
	return map[string]any{"record": signSuccessor(t, who, e2e.SuccessorBody{V: 1, User: who.id, Seq: seq, Successor: current.id, Action: "remove"})}
}

// nominate has w.u nominate to, as the next record.
func (w *succWorld) nominate(to actor) {
	w.t.Helper()
	w.seq++
	var out struct {
		Seq int `json:"seq"`
	}
	w.u.mustDo("PUT", "/api/me/successor", nominateBody(w.t, w.u, to, w.seq), &out, http.StatusOK)
	if out.Seq != w.seq {
		w.t.Fatalf("PUT answered seq %d, want %d", out.Seq, w.seq)
	}
}

type requestAnswer struct {
	RequestedAt string `json:"requestedAt"`
	ReleaseAt   string `json:"releaseAt"`
}

// request has w.sc ask for access to w.u's artifacts.
func (w *succWorld) request() requestAnswer {
	w.t.Helper()
	var out requestAnswer
	w.sc.mustDo("POST", "/api/successions/"+w.u.id+"/request", nil, &out, http.StatusOK)
	return out
}

type gotSuccession struct {
	User struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"user"`
	Record      e2e.Envelope `json:"record"`
	NominatedAt string       `json:"nominatedAt"`
	RequestedAt string       `json:"requestedAt"`
	ReleaseAt   string       `json:"releaseAt"`
	Released    bool         `json:"released"`
	Wrapped     string       `json:"wrapped"`
}

func successions(t *testing.T, c *testClient) []gotSuccession {
	t.Helper()
	var out []gotSuccession
	c.mustDo("GET", "/api/successions", nil, &out, http.StatusOK)
	return out
}

type gotMySuccessor struct {
	Successor *struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Email      string `json:"email"`
		X25519Pub  string `json:"x25519Pub"`
		Ed25519Pub string `json:"ed25519Pub"`
	} `json:"successor"`
	Record      *e2e.Envelope `json:"record"`
	NominatedAt string        `json:"nominatedAt"`
	Seq         int           `json:"seq"`
	Request     *struct {
		RequestedAt   string `json:"requestedAt"`
		ReleaseAt     string `json:"releaseAt"`
		Released      bool   `json:"released"`
		DeactivatedAt string `json:"deactivatedAt"`
	} `json:"request"`
}

func mySuccessor(t *testing.T, c *testClient) gotMySuccessor {
	t.Helper()
	var out gotMySuccessor
	c.mustDo("GET", "/api/me/successor", nil, &out, http.StatusOK)
	return out
}

type gotMe struct {
	MustRotate bool `json:"mustRotate"`
	Succession *struct {
		Successor struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"successor"`
		RequestedAt   string `json:"requestedAt"`
		ReleaseAt     string `json:"releaseAt"`
		Released      bool   `json:"released"`
		DeactivatedAt string `json:"deactivatedAt"`
	} `json:"succession"`
}

func me(t *testing.T, c *testClient) (gotMe, *http.Response) {
	t.Helper()
	var out gotMe
	resp := c.do("GET", "/api/me", nil, &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me: %d", resp.StatusCode)
	}
	return out, resp
}

// body decodes a response's JSON error and any other fields.
func jsonOf(c *testClient, method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var out map[string]any
	resp := c.do(method, path, body, &out)
	return resp.StatusCode, out
}

func mailsTo(s *Server, addr string) []mail.Message {
	var out []mail.Message
	for _, m := range mailer(s).All() {
		if m.To == addr {
			out = append(out, m)
		}
	}
	return out
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Nominating

func TestNominate(t *testing.T) {
	w := newSuccWorld(t)
	put := func(body map[string]any, want int) map[string]any {
		t.Helper()
		code, out := jsonOf(w.u.testClient, "PUT", "/api/me/successor", body)
		if code != want {
			t.Fatalf("PUT /api/me/successor: %d %v, want %d", code, out, want)
		}
		return out
	}
	good := func() map[string]any { return nominateBody(t, w.u, w.sc, 1) }
	record := func(mutate func(*e2e.SuccessorBody)) map[string]any {
		b := e2e.SuccessorBody{V: 1, User: w.u.id, Seq: 1, Successor: w.sc.id, SuccessorFP: w.sc.keys.fp(), Action: "nominate"}
		mutate(&b)
		body := good()
		body["record"] = signSuccessor(t, w.u, b)
		return body
	}

	t.Run("nothing nominated", func(t *testing.T) {
		got := mySuccessor(t, w.u.testClient)
		if got.Successor != nil || got.Record != nil || got.Request != nil || got.Seq != 0 {
			t.Errorf("before nominating: %+v", got)
		}
		if got := successions(t, w.sc.testClient); len(got) != 0 {
			t.Errorf("successions before nominating: %+v", got)
		}
	})
	t.Run("refusals leave nothing behind", func(t *testing.T) {
		wrongKey := good()
		wrongKey["authKey"] = e2e.B64(testAuthKey("wrong"))
		put(wrongKey, http.StatusUnauthorized)
		put(record(func(b *e2e.SuccessorBody) { b.SuccessorFP = w.other.keys.fp() }), http.StatusBadRequest)
		put(record(func(b *e2e.SuccessorBody) { b.SuccessorFP = "" }), http.StatusBadRequest)
		put(record(func(b *e2e.SuccessorBody) { b.Action = "remove" }), http.StatusBadRequest)
		put(record(func(b *e2e.SuccessorBody) { b.User = w.other.id }), http.StatusBadRequest)
		put(record(func(b *e2e.SuccessorBody) { b.Successor = w.other.id }), http.StatusBadRequest)
		badSig := good()
		badSig["record"] = signSuccessor(t, w.other, e2e.SuccessorBody{V: 1, User: w.u.id, Seq: 1, Successor: w.sc.id, SuccessorFP: w.sc.keys.fp(), Action: "nominate"})
		put(badSig, http.StatusBadRequest)
		wrongPurpose := good()
		raw, _ := json.Marshal(e2e.SuccessorBody{V: 1, User: w.u.id, Seq: 1, Successor: w.sc.id, SuccessorFP: w.sc.keys.fp(), Action: "nominate"})
		wrongPurpose["record"], _ = e2e.NewEnvelope(w.u.keys.seed, w.u.id, "reset", raw)
		put(wrongPurpose, http.StatusBadRequest)
		wrongSigner := good()
		wrongSigner["record"] = e2e.Envelope{Body: raw, Sig: wrongSigner["record"].(e2e.Envelope).Sig, Signer: w.other.id}
		put(wrongSigner, http.StatusBadRequest)
		for _, wrapLen := range []int{0, 80, 82, 61} {
			short := good()
			short["wrapped"] = e2e.B64(make([]byte, wrapLen))
			put(short, http.StatusBadRequest)
		}
		notB64 := good()
		notB64["wrapped"] = "!!"
		put(notB64, http.StatusBadRequest)
		if got := mySuccessor(t, w.u.testClient); got.Successor != nil || got.Seq != 0 {
			t.Errorf("a refused nomination changed something: %+v", got)
		}
	})
	t.Run("the successor must be another verified, active user", func(t *testing.T) {
		self := nominateBody(t, w.u, w.u, 1)
		put(self, http.StatusBadRequest)
		unknown := good()
		unknown["successor"] = "00000000-0000-4000-8000-000000000000"
		put(unknown, http.StatusBadRequest)
		keys := newUserKeys(t)
		unverified, err := w.s.store.CreateAccount("pending@example.com", "P", "hash", bundleFor(t, keys), false)
		if err != nil {
			t.Fatal(err)
		}
		put(nominateBody(t, w.u, actor{id: unverified.ID, keys: keys}, 1), http.StatusBadRequest)
		w.admin.mustDo("PATCH", "/api/admin/users/"+w.other.id, map[string]any{"disabled": true}, nil, http.StatusOK)
		put(nominateBody(t, w.u, w.other, 1), http.StatusBadRequest)
		w.admin.mustDo("PATCH", "/api/admin/users/"+w.other.id, map[string]any{"disabled": false}, nil, http.StatusOK)
	})
	t.Run("a wrong seq is a 409 that names the last", func(t *testing.T) {
		body := nominateBody(t, w.u, w.sc, 5)
		out := put(body, http.StatusConflict)
		if out["seq"] != float64(0) || out["error"] == nil {
			t.Errorf("409 body %v, want the error and seq 0", out)
		}
	})
	t.Run("success", func(t *testing.T) {
		w.nominate(w.sc)
		got := mySuccessor(t, w.u.testClient)
		if got.Successor == nil || got.Successor.ID != w.sc.id || got.Successor.Email != w.sc.email ||
			got.Successor.X25519Pub != e2e.B64(w.sc.keys.xpub) || got.Successor.Ed25519Pub != e2e.B64(w.sc.keys.epub) {
			t.Fatalf("successor = %+v", got.Successor)
		}
		if got.Seq != 1 || got.Request != nil || got.NominatedAt == "" || got.Record == nil || got.Record.Signer != w.u.id {
			t.Errorf("nomination = %+v", got)
		}
		var body e2e.SuccessorBody
		if err := e2e.OpenEnvelope(*got.Record, w.u.keys.epub, "successor", &body); err != nil || body.Successor != w.sc.id {
			t.Errorf("served record: %+v, %v", body, err)
		}
		list := successions(t, w.sc.testClient)
		if len(list) != 1 || list[0].User.ID != w.u.id || list[0].User.Email != w.u.email || list[0].Released || list[0].Wrapped != "" ||
			list[0].RequestedAt != "" || list[0].ReleaseAt != "" || list[0].NominatedAt == "" {
			t.Fatalf("successions = %+v", list)
		}
		if err := e2e.OpenEnvelope(list[0].Record, w.u.keys.epub, "successor", &body); err != nil {
			t.Errorf("record in successions: %v", err)
		}
		// A replay of the same seq is refused.
		out := put(nominateBody(t, w.u, w.sc, 1), http.StatusConflict)
		if out["seq"] != float64(1) {
			t.Errorf("409 body %v, want seq 1", out)
		}
	})
	t.Run("an API key cannot nominate", func(t *testing.T) {
		w.u.mustDo("POST", "/api/keys", map[string]any{
			"authKey": authKeyOf(w.u), "name": "k", "keyId": "00112233445566aa", "authSecret": "00112233445566778899aabbccddeeff",
			"mk": e2e.B64(make([]byte, sealedKeyLen)),
		}, nil, http.StatusCreated)
		key := &testClient{t: t, base: w.base, token: "cairn_00112233445566aa_00112233445566778899aabbccddeeff"}
		wantStatus(t, key, "PUT", "/api/me/successor", nominateBody(t, w.u, w.sc, 2), http.StatusUnauthorized)
		key.mustDo("GET", "/api/me/successor", nil, nil, http.StatusOK)
	})
}

func TestNominateReplaceEndsAPendingRequestAndMailsTheOldSuccessor(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)
	// Replacing with no request pending says nothing to the old successor.
	w.nominate(w.other)
	if got := mailsTo(w.s, w.sc.email); len(got) != 0 {
		t.Fatalf("mail to the old successor with nothing pending: %+v", got)
	}
	if got := mySuccessor(t, w.u.testClient); got.Successor.ID != w.other.id || got.Seq != 2 {
		t.Errorf("after replacing: %+v", got)
	}
	// With one pending it ends, and the old successor is told.
	w.sc.mustDo("POST", "/api/successions/"+w.u.id+"/request", nil, nil, http.StatusNotFound)
	w.other.mustDo("POST", "/api/successions/"+w.u.id+"/request", nil, nil, http.StatusOK)
	w.nominate(w.sc)
	if got := mySuccessor(t, w.u.testClient); got.Successor.ID != w.sc.id || got.Request != nil {
		t.Errorf("a replacement kept the request: %+v", got)
	}
	got := mailsTo(w.s, w.other.email)
	if len(got) != 1 || !strings.Contains(got[0].Body, w.u.email) {
		t.Fatalf("mail to the replaced successor: %+v", got)
	}
	if list := successions(t, w.other.testClient); len(list) != 0 {
		t.Errorf("the replaced successor still lists it: %+v", list)
	}
	// And the old successor can no longer ask.
	w.other.mustDo("POST", "/api/successions/"+w.u.id+"/request", nil, nil, http.StatusNotFound)
}

// Removing

func TestRemoveSuccessor(t *testing.T) {
	w := newSuccWorld(t)
	del := func(body any, want int) map[string]any {
		t.Helper()
		code, out := jsonOf(w.u.testClient, "DELETE", "/api/me/successor", body)
		if code != want {
			t.Fatalf("DELETE /api/me/successor: %d %v, want %d", code, out, want)
		}
		return out
	}
	del(removeBody(t, w.u, w.sc, 1), http.StatusConflict) // no successor
	w.nominate(w.sc)

	t.Run("refused", func(t *testing.T) {
		del(map[string]any{}, http.StatusBadRequest)
		unsigned := removeBody(t, w.u, w.sc, 2)
		unsigned["record"] = e2e.Envelope{Body: unsigned["record"].(e2e.Envelope).Body, Sig: make([]byte, 64), Signer: w.u.id}
		del(unsigned, http.StatusBadRequest)
		del(removeBody(t, w.other, w.sc, 2), http.StatusBadRequest) // signed under another key
		del(map[string]any{"record": signSuccessor(t, w.u, e2e.SuccessorBody{V: 1, User: w.u.id, Seq: 2, Successor: w.sc.id, SuccessorFP: w.sc.keys.fp(), Action: "nominate"})}, http.StatusBadRequest)
		del(map[string]any{"record": signSuccessor(t, w.u, e2e.SuccessorBody{V: 1, User: w.u.id, Seq: 2, Successor: w.sc.id, SuccessorFP: w.sc.keys.fp(), Action: "remove"})}, http.StatusBadRequest)
		del(removeBody(t, w.u, w.other, 2), http.StatusBadRequest) // names someone else
		del(map[string]any{"record": signSuccessor(t, w.u, e2e.SuccessorBody{V: 1, User: w.other.id, Seq: 2, Successor: w.sc.id, Action: "remove"})}, http.StatusBadRequest)
		out := del(removeBody(t, w.u, w.sc, 7), http.StatusConflict)
		if out["seq"] != float64(1) {
			t.Errorf("409 body %v, want seq 1", out)
		}
		if got := mySuccessor(t, w.u.testClient); got.Successor == nil || got.Seq != 1 {
			t.Errorf("a refused removal changed something: %+v", got)
		}
	})
	t.Run("a signed removal ends the nomination and a pending request", func(t *testing.T) {
		w.request()
		var out struct {
			Seq int `json:"seq"`
		}
		w.u.mustDo("DELETE", "/api/me/successor", removeBody(t, w.u, w.sc, 2), &out, http.StatusOK)
		if out.Seq != 2 {
			t.Errorf("seq = %d", out.Seq)
		}
		got := mySuccessor(t, w.u.testClient)
		if got.Successor != nil || got.Request != nil || got.Seq != 2 {
			t.Errorf("after removal: %+v", got)
		}
		if list := successions(t, w.sc.testClient); len(list) != 0 {
			t.Errorf("the removed successor still lists it: %+v", list)
		}
		if m := mailsTo(w.s, w.sc.email); len(m) != 1 || !strings.Contains(m[0].Body, w.u.email) {
			t.Errorf("mail to the removed successor: %+v", m)
		}
		del(removeBody(t, w.u, w.sc, 3), http.StatusConflict) // none left
		w.seq = 2
		w.nominate(w.sc) // the numbering goes on
	})
}

// Asking for access

func TestRequestSuccession(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)
	if m, resp := me(t, w.u.testClient); m.Succession != nil || m.MustRotate || resp.Header.Get("Cairn-Notice") != "" {
		t.Fatalf("before a request: %+v, notice %q", m, resp.Header.Get("Cairn-Notice"))
	}
	w.other.mustDo("POST", "/api/successions/"+w.u.id+"/request", nil, nil, http.StatusNotFound)
	w.sc.mustDo("POST", "/api/successions/"+w.other.id+"/request", nil, nil, http.StatusNotFound)
	w.sc.mustDo("POST", "/api/successions/nobody/request", nil, nil, http.StatusNotFound)

	at := w.clk.Now()
	got := w.request()
	if got.RequestedAt != rfc3339(at) || got.ReleaseAt != rfc3339(at.Add(14*day)) {
		t.Errorf("answered %+v, want %s and %s", got, rfc3339(at), rfc3339(at.Add(14*day)))
	}
	w.sc.mustDo("POST", "/api/successions/"+w.u.id+"/request", nil, nil, http.StatusConflict)

	list := successions(t, w.sc.testClient)
	if len(list) != 1 || list[0].RequestedAt != got.RequestedAt || list[0].ReleaseAt != got.ReleaseAt || list[0].Released || list[0].Wrapped != "" {
		t.Errorf("successions = %+v", list)
	}
	m, resp := me(t, w.u.testClient)
	if m.Succession == nil || m.Succession.Successor.ID != w.sc.id || m.Succession.Successor.Email != w.sc.email ||
		m.Succession.RequestedAt != got.RequestedAt || m.Succession.ReleaseAt != got.ReleaseAt || m.Succession.Released ||
		m.Succession.DeactivatedAt != "" || m.MustRotate {
		t.Errorf("GET /api/me: %+v", m.Succession)
	}
	if resp.Header.Get("Cairn-Notice") != "succession-requested" {
		t.Errorf("Cairn-Notice = %q", resp.Header.Get("Cairn-Notice"))
	}
	if r := w.u.do("GET", "/api/keys", nil, nil); r.Header.Get("Cairn-Notice") != "succession-requested" {
		t.Errorf("Cairn-Notice on another route = %q", r.Header.Get("Cairn-Notice"))
	}
	if r := w.u.do("GET", "/api/artifacts/"+w.art.id, nil, nil); r.Header.Get("Cairn-Notice") != "succession-requested" {
		t.Errorf("Cairn-Notice on an artifact route = %q", r.Header.Get("Cairn-Notice"))
	}
	if _, resp := me(t, w.sc.testClient); resp.Header.Get("Cairn-Notice") != "" {
		t.Errorf("the successor sees Cairn-Notice %q", resp.Header.Get("Cairn-Notice"))
	}
	if g := mySuccessor(t, w.u.testClient); g.Request == nil || g.Request.Released || g.Request.RequestedAt != got.RequestedAt {
		t.Errorf("GET /api/me/successor request: %+v", g.Request)
	}
	// While pending, writes still work.
	w.u.mustDo("PUT", "/api/me/keyring", map[string]any{"rev": 1, "keyring": e2e.B64([]byte("sealed"))}, nil, http.StatusOK)
}

func TestRequestMailGoesToTheAccountAndTheVerifiedNoticeAddress(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)

	// Before the address is verified, only the account address is told.
	w.u.mustDo("PUT", "/api/me/notice-email", map[string]string{"email": " Notice@Example.com "}, nil, http.StatusAccepted)
	link := mailsTo(w.s, "notice@example.com")
	if len(link) != 1 || !strings.Contains(link[0].Body, "https://cairn.example.com/verify#token=") {
		t.Fatalf("verification mail to the notice address: %+v", link)
	}
	w.request()
	if got := mailsTo(w.s, "notice@example.com"); len(got) != 1 {
		t.Fatalf("an unverified notice address got the request mail: %+v", got)
	}
	got := mailsTo(w.s, w.u.email)
	if len(got) != 1 {
		t.Fatalf("mail to the account address: %+v", got)
	}
	releaseDate := w.clk.Now().Add(14 * day).UTC().Format("2006-01-02")
	for _, want := range []string{w.sc.email, releaseDate, "https://cairn.example.com/refuse"} {
		if !strings.Contains(got[0].Body, want) {
			t.Errorf("request mail does not say %q:\n%s", want, got[0].Body)
		}
	}

	// Verify the address through the usual page's endpoint, then ask again.
	token := extractFragmentToken(t, link[0].Body)
	anon := &testClient{t: t, base: w.base}
	anon.mustDo("POST", "/api/auth/verify", map[string]string{"token": token}, nil, http.StatusOK)
	anon.mustDo("POST", "/api/auth/verify", map[string]string{"token": token}, nil, http.StatusBadRequest) // once
	w.u.mustDo("DELETE", "/api/me/successor/request", nil, nil, http.StatusOK)
	w.request()
	if got := mailsTo(w.s, "notice@example.com"); len(got) != 2 || !strings.Contains(got[1].Body, w.sc.email) {
		t.Errorf("mail to the verified notice address: %+v", got)
	}
	if got := mailsTo(w.s, w.u.email); len(got) != 2 {
		t.Errorf("mail to the account address: %d messages, want 2", len(got))
	}

	// Clearing it stops the mail.
	w.u.mustDo("PUT", "/api/me/notice-email", map[string]string{"email": ""}, nil, http.StatusOK)
	w.u.mustDo("DELETE", "/api/me/successor/request", nil, nil, http.StatusOK)
	w.request()
	if got := mailsTo(w.s, "notice@example.com"); len(got) != 2 {
		t.Errorf("a cleared address got mail: %d messages", len(got))
	}
}

func TestNoticeEmailTokens(t *testing.T) {
	w := newSuccWorld(t)
	anon := &testClient{t: t, base: w.base}
	for _, bad := range []string{"not an address", "a@b@c", "x@y.z\r\nBcc: v@w.x", "Name <a@b.c>", strings.Repeat("a", 300) + "@example.com"} {
		wantStatus(t, w.u.testClient, "PUT", "/api/me/notice-email", map[string]string{"email": bad}, http.StatusBadRequest)
	}
	wantStatus(t, w.u.testClient, "PUT", "/api/me/notice-email", map[string]any{"email": "a@b.c", "extra": 1}, http.StatusBadRequest)

	// A newer address replaces a pending one: the older link does nothing.
	w.u.mustDo("PUT", "/api/me/notice-email", map[string]string{"email": "first@example.com"}, nil, http.StatusAccepted)
	first := extractFragmentToken(t, mailsTo(w.s, "first@example.com")[0].Body)
	w.u.mustDo("PUT", "/api/me/notice-email", map[string]string{"email": "second@example.com"}, nil, http.StatusAccepted)
	anon.mustDo("POST", "/api/auth/verify", map[string]string{"token": first}, nil, http.StatusBadRequest)
	second := extractFragmentToken(t, mailsTo(w.s, "second@example.com")[0].Body)

	// A notice token is not a reset token, and a reset token is not a notice token.
	anon.mustDo("POST", "/api/auth/reset/begin", map[string]string{"token": second}, nil, http.StatusBadRequest)
	forgotPassword(t, w.base, w.u.email)
	reset := extractFragmentToken(t, mailsTo(w.s, w.u.email)[0].Body)
	anon.mustDo("POST", "/api/auth/verify", map[string]string{"token": reset}, nil, http.StatusBadRequest)
	anon.mustDo("POST", "/api/auth/verify", map[string]string{"token": second}, nil, http.StatusOK)
	// The reset token still works: the failed verify did not use it.
	anon.mustDo("POST", "/api/auth/reset/begin", map[string]string{"token": reset}, nil, http.StatusOK)

	// Only a session sets it.
	w.u.mustDo("POST", "/api/keys", map[string]any{
		"authKey": authKeyOf(w.u), "name": "k", "keyId": "00112233445566bb", "authSecret": "00112233445566778899aabbccddeeff",
		"mk": e2e.B64(make([]byte, sealedKeyLen)),
	}, nil, http.StatusCreated)
	key := &testClient{t: t, base: w.base, token: "cairn_00112233445566bb_00112233445566778899aabbccddeeff"}
	wantStatus(t, key, "PUT", "/api/me/notice-email", map[string]string{"email": "k@example.com"}, http.StatusUnauthorized)
}

// The 14 days

func TestRefusalBeforeReleaseBlocksIt(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)
	w.request()
	w.clk.Advance(13 * day)
	w.u.mustDo("DELETE", "/api/me/successor/request", nil, nil, http.StatusOK)
	if m := mailsTo(w.s, w.sc.email); len(m) != 1 || !strings.Contains(m[0].Body, w.u.email) {
		t.Errorf("mail to the successor: %+v", m)
	}
	w.clk.Advance(30 * day)
	list := successions(t, w.sc.testClient)
	if len(list) != 1 || list[0].Released || list[0].Wrapped != "" || list[0].RequestedAt != "" {
		t.Fatalf("after the refusal: %+v", list)
	}
	wantStatus(t, w.sc.testClient, "GET", "/api/artifacts/"+w.art.id, nil, http.StatusNotFound)
	wantStatus(t, w.sc.testClient, "GET", "/api/artifacts/"+w.art.id+"/keys", nil, http.StatusNotFound)
	if m, resp := me(t, w.u.testClient); m.MustRotate || m.Succession != nil || resp.Header.Get("Cairn-Notice") != "" {
		t.Errorf("a refused request still shows: %+v, %q", m, resp.Header.Get("Cairn-Notice"))
	}
	w.u.mustDo("DELETE", "/api/me/successor/request", nil, nil, http.StatusConflict) // none pending
	if g := mySuccessor(t, w.u.testClient); g.Successor == nil || g.Request != nil {
		t.Errorf("the nomination stays: %+v", g)
	}
	w.request() // and the successor may ask again
}

func TestReleaseAfterFourteenDays(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)
	vid := pushVersion(t, w.u.testClient, w.art.id)
	w.request()

	w.clk.Advance(14*day - time.Second)
	list := successions(t, w.sc.testClient)
	if len(list) != 1 || list[0].Released || list[0].Wrapped != "" {
		t.Fatalf("one second early: %+v", list)
	}
	wantStatus(t, w.sc.testClient, "GET", "/api/artifacts/"+w.art.id, nil, http.StatusNotFound)
	if m, _ := me(t, w.u.testClient); m.MustRotate || m.Succession == nil || m.Succession.Released {
		t.Errorf("one second early: /api/me %+v", m)
	}

	w.clk.Advance(time.Second)
	list = successions(t, w.sc.testClient)
	if len(list) != 1 || !list[0].Released || list[0].Wrapped != e2e.B64(fakeWrap) || list[0].RequestedAt == "" {
		t.Fatalf("at 14 days: %+v", list)
	}
	base := "/api/artifacts/" + w.art.id

	// The successor reads what u owns.
	var view gotArtifact
	w.sc.mustDo("GET", base, nil, &view, http.StatusOK)
	if view.Access != "successor" || view.Owner != w.u.id {
		t.Errorf("artifact view: %+v", view)
	}
	if got := listIDs(t, w.sc.testClient); got[w.art.id].Access != "successor" {
		t.Errorf("listing: %+v", got[w.art.id])
	} else if _, ok := got[w.shared.id]; ok {
		t.Error("the successor lists an artifact only shared with the user")
	}
	var keys struct {
		Wraps  []any `json:"wraps"`
		Estate []struct {
			Epoch  int    `json:"epoch"`
			Sealed string `json:"sealed"`
		} `json:"estate"`
	}
	w.sc.mustDo("GET", base+"/keys", nil, &keys, http.StatusOK)
	if keys.Wraps == nil || len(keys.Wraps) != 0 || len(keys.Estate) != 1 || keys.Estate[0].Epoch != 1 {
		t.Errorf("keys = %+v, want the estate copy and no wraps", keys)
	}
	var mem membershipGot
	w.sc.mustDo("GET", base+"/membership", nil, &mem, http.StatusOK)
	if len(mem.Records) != 1 {
		t.Errorf("membership records: %d", len(mem.Records))
	}
	w.sc.mustDo("GET", base+"/versions", nil, nil, http.StatusOK)
	w.sc.mustDo("GET", base+"/versions/"+vid, nil, nil, http.StatusOK)
	w.sc.mustDo("GET", base+"/versions/"+vid+"/files", nil, nil, http.StatusOK)
	var tok struct {
		Token string `json:"token"`
	}
	w.sc.mustDo("POST", base+"/content-token", nil, &tok, http.StatusOK)
	(&testClient{t: t, base: w.base, token: tok.Token}).mustDo("GET", base+"/membership", nil, nil, http.StatusOK)

	// And nothing more.
	for _, req := range []struct{ method, path string }{
		{"PUT", base + "/membership"}, {"DELETE", base}, {"POST", base + "/versions"}, {"POST", base + "/transfer"},
		{"GET", base + "/pending"}, {"GET", base + "/review"}, {"POST", base + "/keys"},
		{"PUT", base + "/versions/" + vid + "/db"}, {"PUT", base + "/versions/" + vid + "/files/abc"},
		{"POST", base + "/resources"},
	} {
		wantStatus(t, w.sc.testClient, req.method, req.path, map[string]any{}, http.StatusForbidden)
	}

	// An artifact only shared with the user stays out of reach.
	for _, path := range []string{"/api/artifacts/" + w.shared.id, "/api/artifacts/" + w.shared.id + "/keys", "/api/artifacts/" + w.shared.id + "/membership"} {
		wantStatus(t, w.sc.testClient, "GET", path, nil, http.StatusNotFound)
	}
	// Nor can a stranger read it.
	wantStatus(t, w.other.testClient, "GET", base, nil, http.StatusNotFound)

	// The user is told to rotate.
	m, resp := me(t, w.u.testClient)
	if !m.MustRotate || m.Succession == nil || !m.Succession.Released {
		t.Errorf("GET /api/me after release: %+v", m)
	}
	if resp.Header.Get("Cairn-Notice") != "rotate-keys" {
		t.Errorf("Cairn-Notice = %q", resp.Header.Get("Cairn-Notice"))
	}
	for _, req := range []struct {
		method, path string
		body         any
	}{
		{"PUT", "/api/me/keyring", map[string]any{"rev": 1, "keyring": "AA"}},
		{"PUT", "/api/me/notice-email", map[string]string{"email": "n@example.com"}},
		{"PUT", "/api/me/recovery", map[string]any{"authKey": authKeyOf(w.u), "mkRecovery": e2e.B64(make([]byte, sealedKeyLen))}},
		{"POST", "/api/artifacts", map[string]any{}},
		{"PUT", base + "/membership", map[string]any{}},
		{"DELETE", base, nil},
		{"PUT", base + "/versions/" + vid + "/db", map[string]any{}},
		{"POST", base + "/versions", map[string]any{}},
		{"DELETE", "/api/me/successor", removeBody(t, w.u, w.sc, 2)},
		{"PUT", "/api/me/successor", nominateBody(t, w.u, w.other, 2)},
		{"DELETE", "/api/me/successor/request", nil},
	} {
		code, out := jsonOf(w.u.testClient, req.method, req.path, req.body)
		msg, _ := out["error"].(string)
		if code != http.StatusConflict || !strings.HasPrefix(msg, "rotate your keys first") {
			t.Errorf("%s %s: %d %q, want 409 rotate your keys first", req.method, req.path, code, msg)
		}
	}
	if resp := w.u.do("PUT", "/api/me/keyring", map[string]any{"rev": 1, "keyring": "AA"}, nil); resp.Header.Get("Cairn-Notice") != "rotate-keys" {
		t.Errorf("Cairn-Notice on a refused write = %q", resp.Header.Get("Cairn-Notice"))
	}
	w.u.mustDo("GET", base, nil, nil, http.StatusOK)
	w.u.mustDo("GET", "/api/me/keyring", nil, nil, http.StatusOK)

	// A release cannot be refused, signed in or on the page.
	w.u.mustDo("DELETE", "/api/me/successor/request", nil, nil, http.StatusConflict)
	anon := &testClient{t: t, base: w.base}
	wantStatus(t, anon, "POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "authKey": authKeyOf(w.u)}, http.StatusConflict)

	// Only four writes are open to the user: rotating, signing out, and API
	// keys. Asking for a content token is open too.
	w.u.mustDo("POST", "/api/keys", map[string]any{
		"authKey": authKeyOf(w.u), "name": "k", "keyId": "00112233445566cc", "authSecret": "00112233445566778899aabbccddeeff",
		"mk": e2e.B64(make([]byte, sealedKeyLen)),
	}, nil, http.StatusCreated)
	w.u.mustDo("DELETE", "/api/keys/00112233445566cc", nil, nil, http.StatusOK)
	// A content token is a POST, but it only reads, so the user can still
	// open what they own in the browser.
	w.u.mustDo("POST", base+"/content-token", nil, nil, http.StatusOK)

	// Rotating ends it all.
	rot := newRotation(t, w.s, w.base, w.u, w.art)
	if code, msg, _ := rot.post(w.u.testClient, rot.request()); code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, msg)
	}
	u2 := rot.asNew()
	if m, resp := me(t, u2.testClient); m.MustRotate || m.Succession != nil || resp.Header.Get("Cairn-Notice") != "" {
		t.Errorf("after rotating: %+v, %q", m, resp.Header.Get("Cairn-Notice"))
	}
	var ring keyringBody
	u2.mustDo("GET", "/api/me/keyring", nil, &ring, http.StatusOK)
	u2.mustDo("PUT", "/api/me/keyring", map[string]any{"rev": ring.Rev + 1, "keyring": e2e.B64([]byte("sealed"))}, nil, http.StatusOK)
	if g := mySuccessor(t, u2.testClient); g.Successor != nil || g.Seq != 1 {
		t.Errorf("after rotating: %+v", g)
	}
	if list := successions(t, w.sc.testClient); len(list) != 0 {
		t.Errorf("after rotating the successor still lists it: %+v", list)
	}
	wantStatus(t, w.sc.testClient, "GET", base, nil, http.StatusNotFound)
	wantStatus(t, w.sc.testClient, "GET", base+"/keys", nil, http.StatusNotFound)
	w.sc.mustDo("POST", "/api/successions/"+w.u.id+"/request", nil, nil, http.StatusNotFound)
}

func TestReleasedSuccessorOfAnOwnerWhoSharedWithThem(t *testing.T) {
	// A successor who is also a viewer keeps the viewer level, and the estate
	// copy is still theirs to read.
	w := newSuccWorld(t)
	w.art.share("viewer", w.sc)
	w.nominate(w.sc)
	w.request()
	w.clk.Advance(14 * day)
	var view gotArtifact
	w.sc.mustDo("GET", "/api/artifacts/"+w.art.id, nil, &view, http.StatusOK)
	if view.Access != "viewer" {
		t.Errorf("access = %q, want viewer first", view.Access)
	}
	var keys struct {
		Wraps  []any `json:"wraps"`
		Estate []any `json:"estate"`
	}
	w.sc.mustDo("GET", "/api/artifacts/"+w.art.id+"/keys", nil, &keys, http.StatusOK)
	if len(keys.Wraps) == 0 || len(keys.Estate) != 1 {
		t.Errorf("keys = %+v, want the wraps and the estate copy", keys)
	}
}

// Refusing from the page

func TestRefuseFromThePage(t *testing.T) {
	type refused struct {
		Refused     bool `json:"refused"`
		Successor   struct{ Name, Email string }
		RequestedAt string `json:"requestedAt"`
		// DeactivatedAt is the time an administrator deactivated the account.
		DeactivatedAt string `json:"deactivatedAt"`
	}
	anon := func(w *succWorld) *testClient { return &testClient{t: t, base: w.base} }
	deactivated := func(w *succWorld) string {
		w.admin.mustDo("PATCH", "/api/admin/users/"+w.u.id, map[string]any{"disabled": true}, nil, http.StatusOK)
		return rfc3339(w.clk.Now())
	}
	pending := func() *succWorld {
		w := newSuccWorld(t)
		w.nominate(w.sc)
		w.request()
		return w
	}

	t.Run("with the key, on a deactivated account", func(t *testing.T) {
		w := pending()
		w.clk.Advance(2 * day)
		at := deactivated(w)
		wantStatus(t, w.u.testClient, "GET", "/api/me", nil, http.StatusUnauthorized) // cannot sign in
		w.clk.Advance(day)
		var out refused
		anon(w).mustDo("POST", "/api/auth/refuse", map[string]any{"email": " U@example.com ", "authKey": authKeyOf(w.u)}, &out, http.StatusOK)
		if !out.Refused || out.Successor.Email != w.sc.email || out.Successor.Name != "Test User" ||
			out.RequestedAt == "" || out.DeactivatedAt != at {
			t.Errorf("answered %+v, want deactivatedAt %s", out, at)
		}
		if m := mailsTo(w.s, w.sc.email); len(m) != 1 || !strings.Contains(m[0].Body, w.u.email) {
			t.Errorf("mail to the successor: %+v", m)
		}
		w.clk.Advance(20 * day)
		if list := successions(t, w.sc.testClient); len(list) != 1 || list[0].Released || list[0].Wrapped != "" {
			t.Errorf("successions after the refusal: %+v", list)
		}
		wantStatus(t, w.sc.testClient, "GET", "/api/artifacts/"+w.art.id, nil, http.StatusNotFound)
		wantStatus(t, anon(w), "POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "authKey": authKeyOf(w.u)}, http.StatusConflict)
	})
	t.Run("with the recovery code's proof, on a deactivated account", func(t *testing.T) {
		w := pending()
		deactivated(w)
		var begin struct {
			ID          string `json:"id"`
			MKRecovery  string `json:"mkRecovery"`
			Ed25519Priv string `json:"ed25519Priv"`
			RequestedAt string `json:"requestedAt"`
		}
		anon(w).mustDo("POST", "/api/auth/refuse/begin", map[string]string{"email": w.u.email}, &begin, http.StatusOK)
		b, err := w.s.store.BundleFor(w.u.id)
		if err != nil {
			t.Fatal(err)
		}
		if begin.ID != w.u.id || begin.MKRecovery != e2e.B64(b.MKRecovery) || begin.Ed25519Priv != e2e.B64(b.Ed25519Priv) {
			t.Errorf("begin answered %+v", begin)
		}
		sc, err := w.s.store.SuccessorOf(w.u.id)
		if err != nil {
			t.Fatal(err)
		}
		if begin.RequestedAt != sc.RequestedAt {
			t.Errorf("begin answered requestedAt %q, want %q", begin.RequestedAt, sc.RequestedAt)
		}
		// The page signs what begin returned; it has nothing else to go on.
		var out refused
		anon(w).mustDo("POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "proof": signRefusal(t, w.u, begin.RequestedAt)}, &out, http.StatusOK)
		if !out.Refused || out.DeactivatedAt == "" || out.RequestedAt != sc.RequestedAt {
			t.Errorf("answered %+v", out)
		}
		if g, err := w.s.store.SuccessorOf(w.u.id); err != nil || g.Requested() {
			t.Errorf("after the refusal: %+v, %v", g, err)
		}
	})
	t.Run("an active account, without a deactivation", func(t *testing.T) {
		w := pending()
		var out refused
		anon(w).mustDo("POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "authKey": authKeyOf(w.u)}, &out, http.StatusOK)
		if !out.Refused || out.DeactivatedAt != "" {
			t.Errorf("answered %+v", out)
		}
	})
	t.Run("a deactivation is recorded only while a request is pending", func(t *testing.T) {
		w := newSuccWorld(t)
		w.nominate(w.sc)
		deactivated(w)
		if sc, _ := w.s.store.SuccessorOf(w.u.id); sc.DeactivatedAt != "" {
			t.Errorf("deactivatedAt with no request: %q", sc.DeactivatedAt)
		}
	})
	t.Run("wrong keys are 401 and count for the rate limits", func(t *testing.T) {
		w := pending()
		bad := []map[string]any{
			{"email": w.u.email, "authKey": e2e.B64(testAuthKey("wrong"))},
			{"email": w.u.email, "proof": signRefusal(t, w.other, rfc3339(w.clk.Now()))},                               // another key
			{"email": w.u.email, "proof": signRefusal(t, w.u, rfc3339(w.clk.Now().Add(-time.Hour)))},                   // another request
			{"email": w.u.email, "proof": signRefusal(t, actor{id: w.other.id, keys: w.u.keys}, rfc3339(w.clk.Now()))}, // another user
			{"email": "nobody@example.com", "authKey": authKeyOf(w.u)},
		}
		for i, body := range bad {
			code, out := jsonOf(anon(w), "POST", "/api/auth/refuse", body)
			if code != http.StatusUnauthorized || out["error"] != "invalid email or password" {
				t.Errorf("bad request %d: %d %v", i, code, out)
			}
		}
		// Four of those failed against u's address, one against an unknown
		// address: one more fails, and the sixth attempt is limited even with
		// the right key.
		wantStatus(t, anon(w), "POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "authKey": e2e.B64(testAuthKey("wrong"))}, http.StatusUnauthorized)
		resp := anon(w).do("POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "authKey": authKeyOf(w.u)}, nil)
		if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
			t.Errorf("after five failures: %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
		}
		if sc, _ := w.s.store.SuccessorOf(w.u.id); !sc.Requested() {
			t.Error("a refused refusal ended the request")
		}
		// The same limit counts sign-in failures, so login is limited too.
		resp = anon(w).do("POST", "/api/auth/login", map[string]any{"email": w.u.email, "authKey": authKeyOf(w.u)}, nil)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("login after refuse failures: %d", resp.StatusCode)
		}
		w.clk.Advance(16 * time.Minute)
		anon(w).mustDo("POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "authKey": authKeyOf(w.u)}, nil, http.StatusOK)
	})
	t.Run("a failed proof counts per address", func(t *testing.T) {
		w := pending()
		sc, _ := w.s.store.SuccessorOf(w.u.id)
		for i := 0; i < 5; i++ {
			wantStatus(t, anon(w), "POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "proof": signRefusal(t, w.other, sc.RequestedAt)}, http.StatusUnauthorized)
		}
		wantStatus(t, anon(w), "POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "proof": signRefusal(t, w.u, sc.RequestedAt)}, http.StatusTooManyRequests)
	})
	t.Run("a proof from an earlier request is refused", func(t *testing.T) {
		w := pending()
		old, _ := w.s.store.SuccessorOf(w.u.id)
		w.u.mustDo("DELETE", "/api/me/successor/request", nil, nil, http.StatusOK)
		w.clk.Advance(time.Hour)
		w.request()
		code, out := jsonOf(anon(w), "POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "proof": signRefusal(t, w.u, old.RequestedAt)})
		if code != http.StatusUnauthorized {
			t.Errorf("replayed proof: %d %v", code, out)
		}
		now, _ := w.s.store.SuccessorOf(w.u.id)
		anon(w).mustDo("POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "proof": signRefusal(t, w.u, now.RequestedAt)}, nil, http.StatusOK)
	})
	t.Run("a malformed request", func(t *testing.T) {
		w := pending()
		for _, body := range []map[string]any{
			{"email": w.u.email},
			{"email": w.u.email, "authKey": authKeyOf(w.u), "proof": signRefusal(t, w.u, "x")},
			{"email": w.u.email, "authKey": "!!"},
			{"authKey": authKeyOf(w.u)},
		} {
			if code, _ := jsonOf(anon(w), "POST", "/api/auth/refuse", body); code != http.StatusBadRequest && code != http.StatusUnauthorized {
				t.Errorf("%v: %d, want 400 or 401", body, code)
			}
		}
		if sc, _ := w.s.store.SuccessorOf(w.u.id); !sc.Requested() {
			t.Error("a malformed refusal ended the request")
		}
	})
	t.Run("nothing pending is 409 after a correct key", func(t *testing.T) {
		w := newSuccWorld(t)
		w.nominate(w.sc)
		wantStatus(t, anon(w), "POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "authKey": authKeyOf(w.u)}, http.StatusConflict)
		wantStatus(t, anon(w), "POST", "/api/auth/refuse", map[string]any{"email": w.u.email, "proof": signRefusal(t, w.u, "")}, http.StatusConflict)
		w.other.mustDo("POST", "/api/auth/refuse", map[string]any{"email": w.other.email, "authKey": authKeyOf(w.other)}, nil, http.StatusConflict)
	})
}

func TestRefuseBegin(t *testing.T) {
	w := newSuccWorld(t)
	anon := &testClient{t: t, base: w.base}
	type beginAnswer struct {
		ID          string `json:"id"`
		MKRecovery  string `json:"mkRecovery"`
		Ed25519Priv string `json:"ed25519Priv"`
		RequestedAt string `json:"requestedAt"`
	}
	begin := func(email string) beginAnswer {
		t.Helper()
		var out beginAnswer
		anon.mustDo("POST", "/api/auth/refuse/begin", map[string]string{"email": email}, &out, http.StatusOK)
		return out
	}
	real := func(u actor) beginAnswer {
		b, err := w.s.store.BundleFor(u.id)
		if err != nil {
			t.Fatal(err)
		}
		requestedAt := ""
		if sc, err := w.s.store.SuccessorOf(u.id); err == nil {
			requestedAt = sc.RequestedAt
		}
		return beginAnswer{ID: u.id, MKRecovery: e2e.B64(b.MKRecovery), Ed25519Priv: e2e.B64(b.Ed25519Priv), RequestedAt: requestedAt}
	}
	uuidShape := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sameShape := func(label string, got beginAnswer) {
		t.Helper()
		if !uuidShape.MatchString(got.ID) {
			t.Errorf("%s: id %q is not shaped like a user ID", label, got.ID)
		}
		// A fake requestedAt is a whole second inside the last 14 days, like a
		// pending request's.
		at, err := time.Parse(time.RFC3339, got.RequestedAt)
		if err != nil || rfc3339(at) != got.RequestedAt || !at.After(w.clk.Now().Add(-14*day)) || at.After(w.clk.Now()) {
			t.Errorf("%s: requestedAt %q is not a pending request's time at %s", label, got.RequestedAt, rfc3339(w.clk.Now()))
		}
		for _, v := range []string{got.MKRecovery, got.Ed25519Priv} {
			raw, err := e2e.UnB64(v)
			if err != nil || len(raw) != sealedKeyLen || raw[0] != 0x01 {
				t.Errorf("%s: %q is not shaped like a sealed key", label, v)
			}
		}
	}

	unknown := begin("nobody@example.com")
	sameShape("unknown", unknown)
	if again := begin("nobody@example.com"); again != unknown {
		t.Errorf("unstable fake: %+v then %+v", unknown, again)
	}
	if again := begin("  NOBODY@example.com"); again != unknown {
		t.Error("the fake changes with the case of the address")
	}
	if begin("somebody@example.com") == unknown {
		t.Error("two addresses share a fake")
	}

	// The fake requestedAt holds until it would be released, then moves on,
	// as a real request would give way to the fake.
	first, _ := time.Parse(time.RFC3339, unknown.RequestedAt)
	w.clk.Advance(first.Add(14*day - time.Second).Sub(w.clk.Now()))
	if again := begin("nobody@example.com"); again.RequestedAt != unknown.RequestedAt {
		t.Errorf("the fake requestedAt moved early: %q then %q", unknown.RequestedAt, again.RequestedAt)
	}
	w.clk.Advance(time.Second)
	if again := begin("nobody@example.com"); again.RequestedAt == unknown.RequestedAt {
		t.Error("the fake requestedAt outlived a release")
	} else {
		sameShape("unknown, later", again)
	}

	// An account with nothing pending, with no nomination, or with a nomination
	// and no request, gets a fake that is not its real value.
	for _, label := range []string{"no nomination", "nominated"} {
		got := begin(w.u.email)
		sameShape(label, got)
		if got == real(w.u) || got.ID == w.u.id {
			t.Errorf("%s: begin returned the real values", label)
		}
		if again := begin(w.u.email); again != got {
			t.Errorf("%s: unstable fake", label)
		}
		w.nominate(w.sc)
	}

	w.request()
	if got := begin(w.u.email); got != real(w.u) {
		t.Errorf("pending: %+v, want %+v", got, real(w.u))
	}
	w.clk.Advance(14*day - time.Second)
	if got := begin(w.u.email); got != real(w.u) {
		t.Errorf("a second before release: %+v", got)
	}
	w.clk.Advance(time.Second)
	if got := begin(w.u.email); got == real(w.u) {
		t.Errorf("after release begin still returns the real values")
	}
	// Deactivation does not stop it.
	w2 := newSuccWorld(t)
	w2.nominate(w2.sc)
	w2.request()
	w2.admin.mustDo("PATCH", "/api/admin/users/"+w2.u.id, map[string]any{"disabled": true}, nil, http.StatusOK)
	var got beginAnswer
	(&testClient{t: t, base: w2.base}).mustDo("POST", "/api/auth/refuse/begin", map[string]string{"email": w2.u.email}, &got, http.StatusOK)
	if got.ID != w2.u.id {
		t.Errorf("deactivated account: begin answered %+v", got)
	}
}

// Administrator handover

func TestAdminHandoverToAReleasedSuccessor(t *testing.T) {
	newWorld := func() (*transferWorld, *clock.Fake) {
		var clk *clock.Fake
		w := newTransferWorldWith(t, func(c *Config) {
			clk = clock.NewFake(time.Now())
			c.Clock = clk
		})
		return w, clk
	}
	nominateOut := func(w *transferWorld) {
		w.owner.mustDo("PUT", "/api/me/successor", nominateBody(t, w.owner, w.out, 1), nil, http.StatusOK)
	}
	adminOffer := func(w *transferWorld, to actor, want int) {
		t.Helper()
		wantStatus(t, w.admin, "POST", "/api/admin/artifacts/"+w.o.id+"/transfer", map[string]any{"to": to.id}, want)
	}
	release := func(w *transferWorld, clk *clock.Fake) {
		w.out.mustDo("POST", "/api/successions/"+w.owner.id+"/request", nil, nil, http.StatusOK)
		clk.Advance(14 * day)
	}

	t.Run("offer, accept, and a silent chain", func(t *testing.T) {
		w, clk := newWorld()
		nominateOut(w)
		w.out.mustDo("POST", "/api/successions/"+w.owner.id+"/request", nil, nil, http.StatusOK)
		w.deactivate(w.owner)
		if sc, _ := w.s.store.SuccessorOf(w.owner.id); sc.DeactivatedAt == "" {
			t.Error("the deactivation during the request was not recorded")
		}
		// Not released yet: a non-member successor is refused.
		adminOffer(w, w.out, http.StatusConflict)
		clk.Advance(14*day - time.Second)
		adminOffer(w, w.out, http.StatusConflict)
		clk.Advance(time.Second)
		adminOffer(w, w.out, http.StatusOK)
		if m, ok := mailer(w.s).Last(w.owner.email); !ok || !strings.Contains(m.Body, w.out.email) {
			t.Errorf("owner's mail: %+v, %v", m, ok)
		}
		// Anyone else who is not a member is still refused.
		adminOffer(w, w.v, http.StatusConflict)
		w.admin.mustDo("POST", "/api/admin/artifacts/"+w.o.id+"/transfer", map[string]any{"to": w.out.id}, nil, http.StatusOK)

		var view gotArtifact
		w.out.mustDo("GET", "/api/artifacts/"+w.o.id, nil, &view, http.StatusOK)
		if view.Access != "successor" || view.Transfer == nil || view.Transfer.To != w.out.id || view.Transfer.By != "admin" {
			t.Errorf("the successor's view: %+v", view)
		}
		b, req := w.accepting(w.out, "", "admin", true)
		w.out.mustDo("POST", w.transferPath("/accept"), req, nil, http.StatusOK)
		if a, err := w.s.store.ArtifactByID(w.o.id); err != nil || a.OwnerID != w.out.id {
			t.Fatalf("artifact after the handover: %+v, %v", a, err)
		}
		var served struct {
			Records    []e2e.Envelope          `json:"records"`
			Owners     map[string]e2e.KeyPair  `json:"owners"`
			Successors map[string]e2e.Envelope `json:"successors"`
		}
		w.v.mustDo("GET", "/api/artifacts/"+w.o.id+"/membership", nil, &served, http.StatusOK)
		rec, ok := served.Successors[strconv.Itoa(b.Seq)]
		if len(served.Successors) != 1 || !ok {
			t.Fatalf("successors = %v, want one entry at seq %d", served.Successors, b.Seq)
		}
		var body e2e.SuccessorBody
		if err := e2e.OpenEnvelope(rec, w.owner.keys.epub, "successor", &body); err != nil ||
			body.User != w.owner.id || body.Successor != w.out.id || body.SuccessorFP != w.out.keys.fp() || body.Action != "nominate" {
			t.Errorf("the served successor record: %+v, %v", body, err)
		}
	})
	t.Run("the offer is refused when the successor's key changed", func(t *testing.T) {
		w, clk := newWorld()
		nominateOut(w)
		release(w, clk)
		w.deactivate(w.owner)
		w.rekey(&w.out)
		adminOffer(w, w.out, http.StatusConflict)
	})
	t.Run("accept checks the successor again", func(t *testing.T) {
		w, clk := newWorld()
		nominateOut(w)
		release(w, clk)
		w.deactivate(w.owner)
		adminOffer(w, w.out, http.StatusOK)
		if _, err := w.s.store.DB().Exec(`UPDATE successors SET requested_at = NULL`); err != nil {
			t.Fatal(err)
		}
		// Without its release the successor has no access to the artifact.
		_, req := w.accepting(w.out, "", "admin", true)
		wantStatus(t, w.out.testClient, "POST", w.transferPath("/accept"), req, http.StatusNotFound)
		if a, _ := w.s.store.ArtifactByID(w.o.id); a.OwnerID != w.owner.id {
			t.Error("a handover to a successor who is no longer released landed")
		}
		// Back in release, it lands.
		if _, err := w.s.store.DB().Exec(`UPDATE successors SET requested_at = ?`, rfc3339(clk.Now().Add(-14*day))); err != nil {
			t.Fatal(err)
		}
		w.out.mustDo("POST", w.transferPath("/accept"), req, nil, http.StatusOK)
	})
	t.Run("an active owner must still agree", func(t *testing.T) {
		w, clk := newWorld()
		nominateOut(w)
		release(w, clk)
		adminOffer(w, w.out, http.StatusConflict)
	})
	t.Run("the successor may decline", func(t *testing.T) {
		w, clk := newWorld()
		nominateOut(w)
		release(w, clk)
		w.deactivate(w.owner)
		adminOffer(w, w.out, http.StatusOK)
		w.out.mustDo("DELETE", w.transferPath(""), nil, nil, http.StatusOK)
		if _, err := w.s.store.OpenOffer(w.o.id); err == nil {
			t.Error("the offer is still open")
		}
	})
	t.Run("an offer replaced by another cannot be accepted", func(t *testing.T) {
		w, clk := newWorld()
		nominateOut(w)
		release(w, clk)
		w.deactivate(w.owner)
		adminOffer(w, w.out, http.StatusOK)
		// out is the successor of the owner only; w.ed2 is a listed editor,
		// so an offer replaces and ed2 accepts as an editor does.
		adminOffer(w, w.ed2, http.StatusOK)
		_, req := w.accepting(w.out, "", "admin", true)
		wantStatus(t, w.out.testClient, "POST", w.transferPath("/accept"), req, http.StatusConflict)
	})
}

func TestMembershipSuccessorsIsEmptyWithoutAHandover(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)
	var served struct {
		Successors map[string]e2e.Envelope `json:"successors"`
	}
	w.u.mustDo("GET", "/api/artifacts/"+w.art.id+"/membership", nil, &served, http.StatusOK)
	if served.Successors == nil || len(served.Successors) != 0 {
		t.Errorf("successors = %v, want {}", served.Successors)
	}
}

// Reset

func TestResetWithoutTheRecoveryCodeArchivesTheNomination(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)
	w.request()
	forgotPassword(t, w.base, w.u.email)
	token := extractFragmentToken(t, mailsTo(w.s, w.u.email)[1].Body) // the request mail came first
	anon := &testClient{t: t, base: w.base}
	anon.mustDo("POST", "/api/auth/reset/complete", map[string]any{
		"token": token, "mode": "new", "authKey": e2e.B64(testAuthKey("new-pw")), "bundle": testBundleWire(),
	}, nil, http.StatusOK)

	if _, err := w.s.store.SuccessorOf(w.u.id); err == nil {
		t.Error("the nomination survived a reset without the recovery code")
	}
	archives, err := w.s.store.Archives(w.u.id)
	if err != nil || len(archives) != 1 || archives[0].Successor == nil ||
		archives[0].Successor.Successor != w.sc.id || len(archives[0].Successor.Wrapped) != 81 {
		t.Fatalf("archives: %+v, %v", archives, err)
	}
	// An archived copy is never released.
	w.clk.Advance(30 * day)
	if list := successions(t, w.sc.testClient); len(list) != 0 {
		t.Errorf("successions after the reset: %+v", list)
	}
	wantStatus(t, w.sc.testClient, "GET", "/api/artifacts/"+w.art.id, nil, http.StatusNotFound)
	w.sc.mustDo("POST", "/api/successions/"+w.u.id+"/request", nil, nil, http.StatusNotFound)
	// The archive listing does not carry it.
	u2 := login(t, w.base, w.u.email, "new-pw")
	var raw json.RawMessage
	u2.mustDo("GET", "/api/me/archives", nil, &raw, http.StatusOK)
	if strings.Contains(string(raw), "successor") {
		t.Errorf("GET /api/me/archives exposes the nomination: %s", raw)
	}
	// seq goes on past the reset.
	if g := mySuccessor(t, u2); g.Seq != 1 || g.Successor != nil {
		t.Errorf("after the reset: %+v", g)
	}
}

func TestResetWithTheRecoveryCodeKeepsTheNomination(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)
	w.request()
	forgotPassword(t, w.base, w.u.email)
	token := extractFragmentToken(t, mailsTo(w.s, w.u.email)[1].Body)
	raw, _ := json.Marshal(resetProofBody{V: 1, User: w.u.id, Token: hashToken(mustUnB64(t, token))})
	proof, err := e2e.Sign(w.u.keys.seed, "reset", raw)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := w.s.store.BundleFor(w.u.id)
	anon := &testClient{t: t, base: w.base}
	anon.mustDo("POST", "/api/auth/reset/complete", map[string]any{
		"token": token, "mode": "recovery", "authKey": e2e.B64(testAuthKey("new-pw")), "kdf": json.RawMessage(b.KDF),
		"mkPassword": e2e.B64(make([]byte, sealedKeyLen)), "proof": e2e.B64(proof),
	}, nil, http.StatusOK)
	if sc, err := w.s.store.SuccessorOf(w.u.id); err != nil || !sc.Requested() {
		t.Errorf("the nomination after a reset with the recovery code: %+v, %v", sc, err)
	}
}

func mustUnB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := e2e.UnB64(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Deleting a user

func TestDeletingAUserEndsTheNomination(t *testing.T) {
	w := newSuccWorld(t)
	spare := seedKeyedAccount(t, w.s, w.base, "spare@example.com")
	spareSC := seedKeyedAccount(t, w.s, w.base, "sparesc@example.com")
	spare.mustDo("PUT", "/api/me/successor", nominateBody(t, spare, spareSC, 1), nil, http.StatusOK)
	w.nominate(w.sc)

	w.admin.mustDo("DELETE", "/api/admin/users/"+w.sc.id, nil, nil, http.StatusOK)
	if g := mySuccessor(t, w.u.testClient); g.Successor != nil || g.Seq != 1 {
		t.Errorf("after the successor was deleted: %+v", g)
	}
	w.admin.mustDo("DELETE", "/api/admin/users/"+spare.id, nil, nil, http.StatusOK)
	if list := successions(t, spareSC.testClient); len(list) != 0 {
		t.Errorf("after the nominating user was deleted: %+v", list)
	}
}

// A request on a server with a wall clock still releases on the stored time.
func TestSuccessionTimeIsTheServersClock(t *testing.T) {
	w := newSuccWorld(t)
	w.nominate(w.sc)
	start := w.clk.Now()
	w.request()
	sc, err := w.s.store.SuccessorOf(w.u.id)
	if err != nil || sc.RequestedAt != rfc3339(start) {
		t.Fatalf("requestedAt = %q, want the fake clock's %s", sc.RequestedAt, rfc3339(start))
	}
}
