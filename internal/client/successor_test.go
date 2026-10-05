package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/server"
)

// succ is a server on a fake clock with ada, who owns an artifact; bob and
// cat, whom she can nominate; and the full API key of each, so a test can
// reach the server through a proxy of its own.
type succ struct {
	t             *testing.T
	host          string
	clk           *clock.Fake
	keys          map[string]string
	ada, bob, cat *Client
	artifact      string
}

func newSucc(t *testing.T) *succ {
	t.Helper()
	clk := clock.NewFake(time.Now())
	host, m := newTestServer(t, func(c *server.Config) { c.Clock = clk })
	s := &succ{t: t, host: host, clk: clk, keys: map[string]string{}}
	for _, acct := range []struct {
		who string
		c   **Client
	}{{"ada", &s.ada}, {"bob", &s.bob}, {"cat", &s.cat}} {
		email := acct.who + "@example.com"
		signupVerify(t, host, m, email, testPassword)
		out, err := New(host, "").Login(email, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		s.keys[acct.who] = out.APIKey
		*acct.c = keyedFor(t, host, out.APIKey)
	}
	a, err := s.ada.CreateArtifact("estate", "")
	if err != nil {
		t.Fatal(err)
	}
	s.artifact = a.ID
	return s
}

func (s *succ) id(c *Client) string {
	s.t.Helper()
	me, err := c.Me()
	if err != nil {
		s.t.Fatal(err)
	}
	return me.ID
}

// nominate has ada nominate who, given by email.
func (s *succ) nominate(who *Client, email string) {
	s.t.Helper()
	code, err := who.SuccessorCode()
	if err != nil {
		s.t.Fatal(err)
	}
	u, err := s.ada.CheckSuccessorCode(email, code)
	if err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.ada.NominateSuccessor(*u, testPassword); err != nil {
		s.t.Fatal(err)
	}
}

// release has ada nominate bob and bob ask, and lets the 14 days pass.
func (s *succ) release() {
	s.t.Helper()
	s.nominate(s.bob, "bob@example.com")
	if _, err := s.bob.RequestSuccession("ada@example.com"); err != nil {
		s.t.Fatal(err)
	}
	s.clk.Advance(14*24*time.Hour + time.Hour)
}

// bodyProxy forwards to host, letting rewrite change the body of every
// successful response; it gets the request's method and path.
func bodyProxy(t *testing.T, host string, rewrite func(method, path string, body []byte) []byte) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode != 200 {
			return nil
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		data = rewrite(resp.Request.Method, resp.Request.URL.Path, data)
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestSuccessorReadsTheEstateAfterTheRelease(t *testing.T) {
	s := newSucc(t)
	if a, err := s.bob.ResolveArtifact(s.artifact); err == nil {
		t.Errorf("bob read %+v before any nomination", a)
	}
	s.release()
	a, err := s.bob.ResolveArtifact(s.artifact)
	if err != nil || a.Name != "estate" || a.Access != "successor" {
		t.Fatalf("bob read %+v, %v; want the name and successor access", a, err)
	}
	if err := s.bob.UpdateArtifact(s.artifact, map[string]string{"name": "mine"}); err == nil || !errors.Is(err, ErrCannotRename) {
		t.Errorf("a successor's rename: %v, want ErrCannotRename", err)
	}
}

func TestSuccessorEKBeforeTheRelease(t *testing.T) {
	s := newSucc(t)
	k, err := s.bob.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	adaID := s.id(s.ada)
	if _, err := s.bob.successorEK(k, adaID); !errors.Is(err, ErrNotSuccessor) {
		t.Errorf("before a nomination: %v, want ErrNotSuccessor", err)
	}
	s.nominate(s.bob, "bob@example.com")
	if _, err := s.bob.successorEK(k, adaID); err == nil || !strings.Contains(err.Error(), "not released") {
		t.Errorf("before a request: %v, want not released", err)
	}
	if _, err := s.bob.RequestSuccession("ada@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bob.successorEK(k, adaID); err == nil || !strings.Contains(err.Error(), "not released") {
		t.Errorf("before the release: %v, want not released", err)
	}
	s.clk.Advance(15 * 24 * time.Hour)
	ek, err := s.bob.successorEK(k, adaID)
	if err != nil {
		t.Fatal(err)
	}
	ada, err := s.ada.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ek, ada.EK) {
		t.Error("the successor's EK is not ada's")
	}
	if _, err := s.cat.successorEK(k, adaID); err == nil {
		t.Error("cat unwrapped ada's EK with bob's keys")
	}
}

// The wrapped EK is not used unless the nomination record verifies under the
// nominating user's key and names the caller, with the caller's fingerprint.
func TestSuccessorEKRefusesATamperedRecord(t *testing.T) {
	s := newSucc(t)
	s.release()
	adaID, bobID, catID := s.id(s.ada), s.id(s.bob), s.id(s.cat)
	adaKeys, err := s.ada.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	bobKeys, err := s.bob.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	catKeys, err := s.cat.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	record := func(signer *UnlockedKeys, b e2e.SuccessorBody) e2e.Envelope {
		body, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		env, err := e2e.NewEnvelope(signer.Ed25519Seed, signer.UserID, "successor", body)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	good := e2e.SuccessorBody{V: 1, User: adaID, Seq: 1, Successor: bobID, SuccessorFP: bobKeys.FP, Action: "nominate"}
	with := func(edit func(*e2e.SuccessorBody)) e2e.SuccessorBody { b := good; edit(&b); return b }

	// The honest record passes through the proxy untouched.
	var swap *e2e.Envelope
	proxy := bodyProxy(t, s.host, func(method, path string, body []byte) []byte {
		if swap == nil || method != "GET" || path != "/api/successions" {
			return body
		}
		var list []map[string]json.RawMessage
		if err := json.Unmarshal(body, &list); err != nil {
			t.Fatal(err)
		}
		list[0]["record"], _ = json.Marshal(swap)
		body, _ = json.Marshal(list)
		return body
	})
	bob := keyedFor(t, proxy, s.keys["bob"])
	if _, err := bob.successorEK(bobKeys, adaID); err != nil {
		t.Fatalf("the untouched record: %v", err)
	}

	forged := record(adaKeys, good)
	forged.Body = []byte(strings.Replace(string(forged.Body), `"seq":1`, `"seq":9`, 1))
	for _, tc := range []struct {
		name string
		env  e2e.Envelope
	}{
		{"signature of another body", forged},
		{"signed by the successor", record(bobKeys, good)},
		{"signed by a third user", record(catKeys, good)},
		{"another user", record(adaKeys, with(func(b *e2e.SuccessorBody) { b.User = catID }))},
		{"another successor", record(adaKeys, with(func(b *e2e.SuccessorBody) { b.Successor = catID }))},
		{"another fingerprint", record(adaKeys, with(func(b *e2e.SuccessorBody) { b.SuccessorFP = catKeys.FP }))},
		{"a removal", record(adaKeys, with(func(b *e2e.SuccessorBody) { b.Action = "remove" }))},
	} {
		swap = &tc.env
		if _, err := bob.successorEK(bobKeys, adaID); err == nil {
			t.Errorf("%s: the record was accepted", tc.name)
		}
	}
	swap = nil
}

func TestSuccessionsListsTheRequest(t *testing.T) {
	s := newSucc(t)
	s.nominate(s.bob, "bob@example.com")
	if _, err := s.bob.RequestSuccession("ada@example.com"); err != nil {
		t.Fatal(err)
	}
	list, err := s.bob.Successions()
	if err != nil || len(list) != 1 || list[0].User.ID != s.id(s.ada) || list[0].RequestedAt == "" || list[0].Released || len(list[0].Wrapped) != 0 {
		t.Fatalf("Successions = %+v, %v", list, err)
	}
}

func TestSuccessorSeqGoesStale(t *testing.T) {
	s := newSucc(t)
	s.nominate(s.bob, "bob@example.com")
	// A second device signed a record this one has not seen: the seq it
	// reads is the old one.
	proxy := bodyProxy(t, s.host, func(method, path string, body []byte) []byte {
		if method == "GET" && path == "/api/me/successor" {
			return bytes.Replace(body, []byte(`"seq":1`), []byte(`"seq":0`), 1)
		}
		return body
	})
	ada := keyedFor(t, proxy, s.keys["ada"])
	code, err := s.cat.SuccessorCode()
	if err != nil {
		t.Fatal(err)
	}
	u, err := ada.CheckSuccessorCode("cat@example.com", code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.NominateSuccessor(*u, testPassword); !errors.Is(err, ErrSuccessorStale) {
		t.Errorf("a stale nomination: %v, want ErrSuccessorStale", err)
	}
	if _, err := ada.RemoveSuccessor(); !errors.Is(err, ErrSuccessorStale) {
		t.Errorf("a stale removal: %v, want ErrSuccessorStale", err)
	}
	// Nothing changed.
	if st, err := s.ada.MySuccessor(); err != nil || st.Successor == nil || st.Successor.Email != "bob@example.com" || st.Seq != 1 {
		t.Errorf("MySuccessor = %+v, %v", st, err)
	}
}

func TestStaleSeqPassesOtherErrorsOn(t *testing.T) {
	other := &APIError{Status: http.StatusConflict, Message: "your successor was released; rotate your keys to end it"}
	if got := staleSeq(other); got != error(other) {
		t.Errorf("staleSeq(released) = %v", got)
	}
	if got := staleSeq(&APIError{Status: http.StatusBadRequest, Message: "seq must be one more"}); errors.Is(got, ErrSuccessorStale) {
		t.Error("a 400 was taken for a stale seq")
	}
	if got := staleSeq(nil); got != nil {
		t.Errorf("staleSeq(nil) = %v", got)
	}
}

// spyProxy forwards to host, recording "METHOD path" of every request, and
// lets modify change each response.
func spyProxy(t *testing.T, host string, modify func(*http.Response)) (string, func() []string) {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		if modify != nil {
			modify(resp)
		}
		return nil
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		p.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

func TestNominateRefusesYourself(t *testing.T) {
	s := newSucc(t)
	proxy, seen := spyProxy(t, s.host, nil)
	ada := keyedFor(t, proxy, s.keys["ada"])
	code, err := ada.SuccessorCode()
	if err != nil {
		t.Fatal(err)
	}
	u, err := ada.CheckSuccessorCode("ada@example.com", code)
	if err != nil {
		t.Fatal(err)
	}
	before := len(seen())
	if _, err := ada.NominateSuccessor(*u, testPassword); err == nil || err.Error() != "you cannot be your own successor" {
		t.Errorf("nominating yourself: %v", err)
	}
	for _, r := range seen()[before:] {
		if strings.HasPrefix(r, "PUT ") || strings.HasPrefix(r, "POST /api/auth") {
			t.Errorf("nominating yourself sent %s, want no sign-in and no nomination", r)
		}
	}

	// A wrong password is refused by the sign-in, before any PUT.
	bobCode, err := s.bob.SuccessorCode()
	if err != nil {
		t.Fatal(err)
	}
	bu, err := ada.CheckSuccessorCode("bob@example.com", bobCode)
	if err != nil {
		t.Fatal(err)
	}
	var apiErr *APIError
	if _, err := ada.NominateSuccessor(*bu, "wrong password for this account"); !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		t.Errorf("a wrong password: %v, want a 401", err)
	}
	if slices.Contains(seen(), "PUT /api/me/successor") {
		t.Error("a nomination was sent after a refused sign-in")
	}
	if st, err := s.ada.MySuccessor(); err != nil || st.Successor != nil {
		t.Errorf("MySuccessor = %+v, %v; want none", st, err)
	}
}

func TestSessionRequestsOfNominateReportTheNotice(t *testing.T) {
	s := newSucc(t)
	proxy, seen := spyProxy(t, s.host, func(resp *http.Response) {
		if strings.HasPrefix(resp.Request.URL.Path, "/api/me/successor") {
			resp.Header.Set(NoticeHeader, "succession-requested")
		}
	})
	ada := keyedFor(t, proxy, s.keys["ada"])
	var got []string
	ada.OnNotice = func(n string) { got = append(got, n) }
	code, err := s.bob.SuccessorCode()
	if err != nil {
		t.Fatal(err)
	}
	u, err := ada.CheckSuccessorCode("bob@example.com", code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.NominateSuccessor(*u, testPassword); err != nil {
		t.Fatal(err)
	}
	// The GET and the PUT of the session client both carry it.
	if want := []string{"succession-requested", "succession-requested"}; !slices.Equal(got, want) {
		t.Errorf("notices %v after %v, want %v", got, seen(), want)
	}
}

// An unlisted caller cannot take an offer: an administrator's only if they
// are the owner's released successor, an owner's never. The cause stays
// readable, and nothing is written. The offer is the server's real one to bob,
// rewritten to name dan, a viewer who reads the chain but is not listed.
func TestSuccessorAdminHandoverNeedsAReleasedSuccessor(t *testing.T) {
	for _, tc := range []struct {
		by        string
		wantCause bool
	}{{"admin", true}, {"owner", false}} {
		t.Run(tc.by, func(t *testing.T) {
			x := newXfer(t, nil)
			x.offer(x.ada, "bob")
			danID := x.id(x.dan)
			proxy := tamperingProxy(t, x.host, "/api/artifacts/"+x.artifact, func(m map[string]json.RawMessage) {
				var tr map[string]json.RawMessage
				json.Unmarshal(m["transfer"], &tr)
				tr["to"], tr["by"] = mustJSON(t, danID), mustJSON(t, tc.by)
				tr["offer"] = json.RawMessage("null")
				m["transfer"] = mustJSON(t, tr)
			})
			before := x.verify(x.cat).Chain.Latest.Seq
			_, err := viaProxy(proxy, x.dan).AcceptTransfer(x.artifact, AcceptTransferOptions{})
			if !errors.Is(err, ErrNotListedEditor) {
				t.Fatalf("AcceptTransfer: %v, want ErrNotListedEditor", err)
			}
			if got := errors.Is(err, ErrNotSuccessor); got != tc.wantCause {
				t.Errorf("errors.Is(err, ErrNotSuccessor) = %v, want %v: %v", got, tc.wantCause, err)
			}
			if got := x.verify(x.cat).Chain.Latest.Seq; got != before {
				t.Errorf("the refused accept wrote a record: seq %d, want %d", got, before)
			}
		})
	}
}

func TestNoticeHeaderReachesEveryRequestPath(t *testing.T) {
	var path string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set(NoticeHeader, "rotate-keys")
		if strings.HasSuffix(r.URL.Path, "/fail") {
			http.Error(w, `{"error":"rotate your keys first"}`, http.StatusConflict)
			return
		}
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(ts.Close)
	var got []string
	c := New(ts.URL, "token")
	c.OnNotice = func(n string) { got = append(got, n) }

	_ = c.doJSON("GET", "/api/ok", nil, nil)
	_ = c.doJSON("POST", "/api/fail", nil, nil)
	if resp, err := c.send("GET", "/api/send", nil, "", nil); err == nil {
		resp.Body.Close()
	}
	_, _ = c.getBytes("/api/bytes")
	if want := []string{"rotate-keys", "rotate-keys", "rotate-keys", "rotate-keys"}; strings.Join(got, ",") != strings.Join(want, ",") || path != "/api/bytes" {
		t.Errorf("notices %v after %s, want one for each of the four requests", got, path)
	}
	// No hook, no panic; no header, no call.
	c.OnNotice = nil
	if err := c.doJSON("GET", "/api/ok", nil, nil); err != nil {
		t.Fatal(err)
	}
	c.OnNotice = func(string) { t.Error("called with no header") }
	quiet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	t.Cleanup(quiet.Close)
	c.Host = quiet.URL
	if err := c.doJSON("GET", "/api/ok", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSuccessorNoticeFromTheServer(t *testing.T) {
	s := newSucc(t)
	var got []string
	s.ada.OnNotice = func(n string) { got = append(got, n) }
	s.nominate(s.bob, "bob@example.com")
	if _, err := s.ada.Me(); err != nil || len(got) != 0 {
		t.Fatalf("before a request: %v, notices %v", err, got)
	}
	if _, err := s.bob.RequestSuccession("ada@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ada.Me(); err != nil || len(got) != 1 || got[0] != "succession-requested" {
		t.Fatalf("after a request: %v, notices %v", err, got)
	}
	s.clk.Advance(15 * 24 * time.Hour)
	got = nil
	_, err := s.ada.CreateArtifact("again", "")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || !strings.Contains(got[len(got)-1], "rotate-keys") {
		t.Errorf("a write after the release: %v, notices %v", err, got)
	}
	// RotateKeys keeps the hook on the session client it makes.
	got = nil
	if _, err := s.ada.RotateKeys(testPassword, false); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Error("rotating keys reported no notice")
	}
}

func TestRemoveAndRefuseAndNoticeEmail(t *testing.T) {
	s := newSucc(t)
	if err := s.ada.RefuseSuccession(); err == nil {
		t.Error("refused with no request")
	}
	if _, err := s.ada.RemoveSuccessor(); !errors.Is(err, ErrNoSuccessor) {
		t.Errorf("remove with none: %v", err)
	}
	s.nominate(s.bob, "bob@example.com")
	if _, err := s.bob.RequestSuccession("nobody@example.com"); !errors.Is(err, ErrNotSuccessor) {
		t.Errorf("request of a stranger: %v", err)
	}
	if _, err := s.bob.RequestSuccession(s.id(s.ada)); err != nil {
		t.Fatal(err)
	}
	if err := s.ada.RefuseSuccession(); err != nil {
		t.Fatal(err)
	}
	if u, err := s.ada.RemoveSuccessor(); err != nil || u.Email != "bob@example.com" {
		t.Errorf("RemoveSuccessor = %v, %v", u, err)
	}
	if pending, err := s.ada.SetNoticeEmail("home@example.org", testPassword); err != nil || !pending {
		t.Errorf("SetNoticeEmail = %v, %v", pending, err)
	}
	if pending, err := s.ada.SetNoticeEmail("", testPassword); err != nil || pending {
		t.Errorf("clearing = %v, %v", pending, err)
	}
	if _, err := s.ada.SetNoticeEmail("x@example.org", "wrong password for this account"); err == nil {
		t.Error("a wrong password was accepted")
	}
}
