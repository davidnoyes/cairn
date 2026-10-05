package release_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/release"
	"github.com/aloisdeniel/cairn/internal/server"
)

// tamper changes one response: the one for path on the app origin, or on a
// content host when content is set. A path ending in / matches every path
// under it. It appends a comment, as an attacker's edit would, or answers
// 404 when missing is set, or redirects when redirect is set.
type tamper struct {
	content bool
	path    string
	missing bool // answer 404 instead
	// redirect, when set, answers 302 to this path on the same host instead.
	redirect string
}

// startServer runs a real server on a loopback port with a localhost content
// domain, optionally changing one response on the way out.
func startServer(t *testing.T, change *tamper) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	s, err := server.New(server.Config{
		DataDir:    t.TempDir(),
		PublicURL:  origin,
		AdminEmail: "admin@example.com",
		TokenTTL:   time.Hour,
		Mail:       &mail.Capture{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	if change != nil {
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			onContent := strings.HasSuffix(strings.Split(r.Host, ":")[0], ".localhost")
			matches := r.URL.Path == change.path || strings.HasSuffix(change.path, "/") && strings.HasPrefix(r.URL.Path, change.path)
			if onContent != change.content || !matches {
				inner.ServeHTTP(w, r)
				return
			}
			if change.missing {
				http.NotFound(w, r)
				return
			}
			if change.redirect != "" {
				http.Redirect(w, r, change.redirect, http.StatusFound)
				return
			}
			rec := httptest.NewRecorder()
			inner.ServeHTTP(rec, r)
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.Header().Del("Content-Length")
			w.WriteHeader(rec.Code)
			w.Write(append(rec.Body.Bytes(), []byte("\n/* changed */\n")...))
		})
	}
	ts := httptest.NewUnstartedServer(h)
	ts.Listener.Close()
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)
	return origin
}

func signedManifest(t *testing.T) (*release.Manifest, []byte, []byte) {
	t.Helper()
	seed, pub, err := e2e.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := server.ReleaseManifest("v0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := release.Sign(seed, m)
	if err != nil {
		t.Fatal(err)
	}
	return &m, signed, pub
}

func target(t *testing.T, origin string) release.Target {
	t.Helper()
	client := release.NewClient()
	doc, err := release.Discover(context.Background(), client, origin)
	if err != nil {
		t.Fatal(err)
	}
	return release.Target{AppOrigin: doc.AppOrigin, ContentOrigin: doc.ContentOrigin, Client: client}
}

// byStatus groups the results' URLs by status.
func byStatus(results []release.Result) map[string][]string {
	out := map[string][]string{}
	for _, r := range results {
		out[r.Status] = append(out[r.Status], r.URL)
	}
	return out
}

func TestCheckPassesAgainstAnUnchangedServer(t *testing.T) {
	origin := startServer(t, nil)
	m, _, _ := signedManifest(t)
	results := release.Check(context.Background(), target(t, origin), m)
	got := byStatus(results)
	if len(got[release.StatusChanged]) > 0 || len(got[release.StatusFailed]) > 0 {
		for _, r := range results {
			if r.Status != release.StatusOK {
				t.Errorf("%s %s: %s", r.Status, r.URL, r.Detail)
			}
		}
	}
	// Every asset, the six account pages, both shell modes and the boot page.
	if want := len(m.Assets) + 6 + 2 + 1; len(got[release.StatusOK]) != want {
		t.Errorf("%d checks passed, want %d: %v", len(got[release.StatusOK]), want, got)
	}
	if skipped := got[release.StatusSkipped]; len(skipped) != 1 || !strings.HasSuffix(skipped[0], "/app") {
		t.Errorf("skipped = %v, want only /app with no API key", skipped)
	}
}

func TestCheckFindsOneChangedFile(t *testing.T) {
	cases := []struct {
		name   string
		change tamper
		want   string // the suffix of the one URL that must fail
	}{
		{"app asset", tamper{path: "/login.js"}, "/login.js"},
		{"vendored wasm", tamper{path: "/argon2.wasm"}, "/argon2.wasm"},
		{"content asset", tamper{content: true, path: "/_cairn/frame.js"}, "/_cairn/frame.js"},
		{"service worker", tamper{content: true, path: "/_cairn/sw.js"}, "/_cairn/sw.js"},
		{"sign-in page", tamper{path: "/login"}, "/login"},
		{"static page", tamper{path: "/refuse"}, "/refuse"},
		{"shell page", tamper{path: "/full/"}, ""},
		{"boot page", tamper{content: true, path: "/_cairn/boot"}, "/_cairn/boot"},
	}
	m, _, _ := signedManifest(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			origin := startServer(t, &c.change)
			results := release.Check(context.Background(), target(t, origin), m)
			changed := byStatus(results)[release.StatusChanged]
			if len(changed) != 1 {
				t.Fatalf("changed = %v, want exactly one", changed)
			}
			if c.want != "" && !strings.HasSuffix(strings.Split(changed[0], "?")[0], c.want) {
				t.Errorf("changed = %s, want ...%s", changed[0], c.want)
			}
			if c.want == "" && !strings.Contains(changed[0], "/full/") {
				t.Errorf("changed = %s, want the full shell page", changed[0])
			}
			if c.change.content && !strings.Contains(changed[0], ".localhost:") {
				t.Errorf("changed = %s, want a content-origin URL", changed[0])
			}
		})
	}
}

func TestCheckFailsAFileTheServerDoesNotServe(t *testing.T) {
	origin := startServer(t, &tamper{path: "/login.js", missing: true})
	m, _, _ := signedManifest(t)
	got := byStatus(release.Check(context.Background(), target(t, origin), m))
	if failed := got[release.StatusFailed]; len(failed) != 1 || !strings.HasSuffix(failed[0], "/login.js") {
		t.Errorf("failed = %v, want only /login.js", failed)
	}
	if changed := got[release.StatusChanged]; len(changed) != 0 {
		t.Errorf("changed = %v, want none: a missing file is a failure", changed)
	}
}

func TestCheckFailsATemplateTheManifestLacks(t *testing.T) {
	origin := startServer(t, nil)
	m, _, _ := signedManifest(t)
	var kept []release.Template
	for _, tm := range m.Templates {
		if tm.Name != "login.html" {
			kept = append(kept, tm)
		}
	}
	m.Templates = kept
	failed := byStatus(release.Check(context.Background(), target(t, origin), m))[release.StatusFailed]
	if len(failed) != 1 || !strings.HasSuffix(failed[0], "/login") {
		t.Errorf("failed = %v, want only /login", failed)
	}
}

func TestDiscoverReadsTheServersDocument(t *testing.T) {
	origin := startServer(t, nil)
	doc, err := release.Discover(context.Background(), release.NewClient(), origin+"/")
	if err != nil {
		t.Fatal(err)
	}
	if doc.AppOrigin != origin || !strings.HasPrefix(doc.ContentOrigin, "http://*.localhost:") {
		t.Errorf("doc = %+v", doc)
	}
	if !bytes.Equal(doc.Manifest, nil) {
		t.Errorf("manifest = %s, want none from a build without one", doc.Manifest)
	}
}

// stubDocument serves a release document with the given origins.
func stubDocument(t *testing.T, appOrigin, contentOrigin string) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if appOrigin == "" {
			appOrigin = "http://" + r.Host
		}
		w.Header().Set("Content-Type", "application/json")
		// :PORT stands for the stub's own port, so a content origin can
		// differ from the app origin in the host alone.
		content := strings.Replace(contentOrigin, ":PORT", ":"+strings.Split(r.Host, ":")[1], 1)
		io.WriteString(w, `{"manifest":null,"appOrigin":"`+appOrigin+`","contentOrigin":"`+content+`"}`)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestDiscoverRefusesAnotherAppOrigin(t *testing.T) {
	u := stubDocument(t, "https://cairn.example", "https://*.content.example")
	if _, err := release.Discover(context.Background(), release.NewClient(), u); !errors.Is(err, release.ErrOriginMismatch) {
		t.Errorf("Discover: %v, want ErrOriginMismatch", err)
	}
}

func TestDiscoverRefusesAContentOriginWithoutAWildcard(t *testing.T) {
	u := stubDocument(t, "", "http://content.example:PORT")
	if _, err := release.Discover(context.Background(), release.NewClient(), u); err == nil {
		t.Error("Discover accepted a content origin with no * label")
	}
}

func TestCheckRefusesToFollowARedirect(t *testing.T) {
	// /login.js redirects to another genuine asset: following it would pass
	// on that asset's bytes, so the redirect itself must fail the file.
	origin := startServer(t, &tamper{path: "/login.js", redirect: "/argon2.wasm"})
	m, _, _ := signedManifest(t)
	results := release.Check(context.Background(), target(t, origin), m)
	got := byStatus(results)
	if failed := got[release.StatusFailed]; len(failed) != 1 || !strings.HasSuffix(failed[0], "/login.js") {
		t.Fatalf("failed = %v, want only /login.js", failed)
	}
	for _, r := range results {
		if r.Status == release.StatusFailed && !strings.Contains(r.Detail, "HTTP 302") {
			t.Errorf("detail = %q, want HTTP 302", r.Detail)
		}
	}
	if changed := got[release.StatusChanged]; len(changed) != 0 {
		t.Errorf("changed = %v, want none", changed)
	}
}

func TestDiscoverAcceptsTheSameOriginSpelledDifferently(t *testing.T) {
	// The document names the server's own origin in another case, with a
	// trailing slash. Check builds URLs on the app origin, so Discover hands
	// back the origin alone.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToUpper(r.Host)
		io.WriteString(w, `{"manifest":null,"appOrigin":"HTTP://`+host+`/","contentOrigin":"http://*.localhost:`+strings.Split(r.Host, ":")[1]+`"}`)
	}))
	t.Cleanup(ts.Close)
	for _, server := range []string{ts.URL, ts.URL + "/", "HTTP" + strings.TrimPrefix(ts.URL, "http")} {
		doc, err := release.Discover(context.Background(), release.NewClient(), server)
		if err != nil {
			t.Errorf("Discover(%q): %v", server, err)
			continue
		}
		if doc.AppOrigin != ts.URL {
			t.Errorf("Discover(%q).AppOrigin = %q, want %q", server, doc.AppOrigin, ts.URL)
		}
	}
}

func TestDiscoverRefusesAGenuinelyDifferentOrigin(t *testing.T) {
	u := stubDocument(t, "http://other.localhost:1", "http://*.localhost:1")
	_, err := release.Discover(context.Background(), release.NewClient(), u)
	if !errors.Is(err, release.ErrOriginMismatch) || !strings.Contains(err.Error(), "CAIRN_PUBLIC_URL") {
		t.Errorf("Discover: %v, want ErrOriginMismatch naming CAIRN_PUBLIC_URL", err)
	}
}

func portOf(t *testing.T, u string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(u, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestDiscoverChecksTheContentOriginAgainstTheApp(t *testing.T) {
	// Every content origin is served from a stub whose app origin is its own
	// address, so only the content origin varies.
	cases := []struct {
		name    string
		content func(port string) string
		ok      bool
	}{
		{"same scheme and port", func(p string) string { return "http://*.localhost:" + p }, true},
		{"another scheme", func(p string) string { return "https://*.localhost:" + p }, false},
		{"another port", func(p string) string { return "http://*.localhost:1" }, false},
		{"no port where the app has one", func(p string) string { return "http://*.localhost" }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var content string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"manifest":null,"appOrigin":"http://`+r.Host+`","contentOrigin":"`+content+`"}`)
			}))
			t.Cleanup(ts.Close)
			content = c.content(portOf(t, ts.URL))
			_, err := release.Discover(context.Background(), release.NewClient(), ts.URL)
			if (err == nil) != c.ok {
				t.Errorf("Discover with content origin %q: %v, want ok = %v", content, err, c.ok)
			}
		})
	}
}

func TestDiscoverTreatsTheDefaultPortAsStated(t *testing.T) {
	// The client dials every address at the stub, so the server can be named
	// without a port, as a real https deployment is.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"manifest":null,"appOrigin":"`+r.URL.Query().Get("app")+`","contentOrigin":"`+r.URL.Query().Get("content")+`"}`)
	}))
	t.Cleanup(ts.Close)
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
		},
	}}
	stub := func(app, content string) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			r.URL.RawQuery = url.Values{"app": {app}, "content": {content}}.Encode()
			return client.Transport.RoundTrip(r)
		})
	}
	cases := []struct{ server, app, content string }{
		{"http://cairn.localhost", "http://cairn.localhost", "http://*.cairn.localhost:80"},
		{"http://cairn.localhost:80", "http://cairn.localhost:80", "http://*.cairn.localhost"},
		{"http://cairn.localhost", "http://cairn.localhost:80", "http://*.cairn.localhost"},
	}
	for _, c := range cases {
		hc := &http.Client{Transport: stub(c.app, c.content)}
		doc, err := release.Discover(context.Background(), hc, c.server)
		if err != nil {
			t.Errorf("Discover(%q) with app %q, content %q: %v", c.server, c.app, c.content, err)
			continue
		}
		if doc.AppOrigin != "http://cairn.localhost" {
			t.Errorf("Discover(%q).AppOrigin = %q, want http://cairn.localhost", c.server, doc.AppOrigin)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
