package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hostKind is where a Host header routes.
type hostKind int

const (
	hostApp     hostKind = iota // the app's routes
	hostContent                 // the content origin
	hostRefused                 // inside the content domain but no artifact's host: 404
)

// hostGetter answers GET path on host, whatever carries the request.
type hostGetter func(host, path string, hdr map[string]string) (int, string, http.Header)

func TestContentHostMatching(t *testing.T) {
	w := newHostWorld(t)
	id := w.art.id
	tests := []struct {
		name string
		host string
		want hostKind
	}{
		{"exact", id + ".localhost:" + w.port, hostContent},
		{"upper case", strings.ToUpper(id + ".localhost:" + w.port), hostContent},
		{"another artifact's UUID", "0a1b2c3d-0000-4000-8000-000000000000.localhost:" + w.port, hostContent},
		// Only the host name routes; a browser omits a default port.
		{"no port", id + ".localhost", hostContent},
		{"wrong port", id + ".localhost:1", hostContent},
		{"trailing dot", id + ".localhost.:" + w.port, hostRefused},
		{"trailing dot, no port", id + ".localhost.", hostRefused},
		{"nested label", "x." + id + ".localhost:" + w.port, hostRefused},
		{"bare content domain", "localhost:" + w.port, hostRefused},
		{"bare content domain with a dot", "localhost.:" + w.port, hostRefused},
		{"36 characters that are not a UUID", "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz.localhost:" + w.port, hostRefused},
		{"not a UUID", "notes.localhost:" + w.port, hostRefused},
		{"another label", "evil.localhost:" + w.port, hostRefused},
		{"UUID without hyphens", strings.ReplaceAll(id, "-", "") + ".localhost:" + w.port, hostRefused},
		{"UUID alone", id, hostApp},
		{"another domain", id + ".example.com:" + w.port, hostApp},
		{"look-alike suffix", id + ".notlocalhost:" + w.port, hostApp},
		{"the public host", "127.0.0.1:" + w.port, hostApp},
		{"IPv6 literal with a port", "[::1]:" + w.port, hostApp},
		{"IPv6 literal", "[::1]", hostApp},
		{"bare IPv6", "::1", hostApp},
		{"unclosed IPv6 bracket", "[::1", hostApp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkHostKind(t, tt.host, tt.want, func(host, path string, hdr map[string]string) (int, string, http.Header) {
				resp := w.viaHost(t, host, "GET", path, hdr, nil)
				return resp.StatusCode, resp.body, resp.Header
			})
		})
	}
}

// checkHostKind asserts where host routes, by what GET /_cairn/boot, /healthz,
// /login and /api/auth/me answer there.
func checkHostKind(t *testing.T, host string, want hostKind, get hostGetter) {
	t.Helper()
	code, body, _ := get(host, "/_cairn/boot", nil)
	isBoot := code == http.StatusOK && strings.Contains(body, "cairn-app-origin")
	hcode, _, _ := get(host, "/healthz", nil)
	switch want {
	case hostContent:
		if !isBoot {
			t.Errorf("Host %q: /_cairn/boot gave %d, want the boot page", host, code)
		}
		if hcode != http.StatusNotFound {
			t.Errorf("Host %q: /healthz gave %d, want 404 (a content host)", host, hcode)
		}
	case hostRefused:
		for _, p := range []string{"/_cairn/boot", "/healthz", "/login", "/api/auth/me", "/api/me", "/"} {
			c, _, h := get(host, p, map[string]string{"Accept": "text/html"})
			if c != http.StatusNotFound {
				t.Errorf("Host %q: GET %s gave %d, want 404", host, p, c)
			}
			if h.Get("Cache-Control") != "no-store" {
				t.Errorf("Host %q: GET %s Cache-Control = %q, want no-store", host, p, h.Get("Cache-Control"))
			}
		}
	case hostApp:
		if isBoot {
			t.Errorf("Host %q: served the boot page, want the app", host)
		}
		if hcode != http.StatusOK {
			t.Errorf("Host %q: /healthz gave %d, want 200 (the app)", host, hcode)
		}
	}
}

// handlerGet sends GET path to s's handler as Host host, with no listener.
func handlerGet(s *Server, host, path string, hdr map[string]string) (int, string, http.Header) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	s.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec.Header()
}

// Routing compares the host name only, so it holds for a public URL with a
// default port, for no public URL, and for a localhost content domain beside a
// localhost public URL.
func TestContentHostRoutingByConfig(t *testing.T) {
	id := "0a1b2c3d-0000-4000-8000-000000000000"
	for _, tt := range []struct {
		name      string
		publicURL string
		domain    string
		addr      string
		hosts     map[string]hostKind
		frameSrc  string
	}{
		{"https default port", "https://cairn.example.com:443", "cairn-content.net", "", map[string]hostKind{
			id + ".cairn-content.net":        hostContent,
			id + ".cairn-content.net:443":    hostContent,
			"x." + id + ".cairn-content.net": hostRefused,
			"cairn-content.net":              hostRefused,
			"{" + id + "}.cairn-content.net": hostRefused, // not sent by Go's client, which drops it
			"cairn.example.com":              hostApp,
			"cairn.example.com:443":          hostApp,
		}, "https://*.cairn-content.net"},
		{"http default port", "http://cairn.example.com:80", "cairn-content.net", "", map[string]hostKind{
			id + ".cairn-content.net": hostContent,
			"cairn.example.com":       hostApp,
		}, "http://*.cairn-content.net"},
		{"https with a port", "https://cairn.example.com:8443", "cairn-content.net", "", map[string]hostKind{
			id + ".cairn-content.net:8443": hostContent,
			id + ".cairn-content.net":      hostContent,
			id + ".cairn-content.net.":     hostRefused,
		}, "https://*.cairn-content.net:8443"},
		{"no public URL", "", "", ":8787", map[string]hostKind{
			id + ".localhost:8787": hostContent,
			id + ".localhost":      hostContent,
			"evil.localhost:8787":  hostRefused,
			"localhost:8787":       hostApp,
			"127.0.0.1:8787":       hostApp,
		}, "http://*.localhost:8787"},
		{"no public URL, port 80", "", "", ":80", map[string]hostKind{
			id + ".localhost": hostContent,
		}, "http://*.localhost"},
		{"no public URL, host and port", "", "", "127.0.0.1:9000", map[string]hostKind{
			id + ".localhost:9000": hostContent,
		}, "http://*.localhost:9000"},
		{"no public URL, unparsable address", "", "", "bogus", map[string]hostKind{
			id + ".localhost": hostContent,
		}, "http://*.localhost"},
		{"localhost beside localhost", "http://localhost:8787", "localhost", "", map[string]hostKind{
			"localhost:8787":        hostApp,
			"localhost":             hostApp,
			id + ".localhost:8787":  hostContent,
			"evil.localhost:8787":   hostRefused,
			id + ".localhost.:8787": hostRefused,
		}, "http://*.localhost:8787"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := newTestServer(t, func(c *Config) {
				c.PublicURL, c.ContentDomain = tt.publicURL, tt.domain
				if tt.addr != "" {
					c.Addr = tt.addr
				}
			})
			for host, want := range tt.hosts {
				checkHostKind(t, host, want, func(h, p string, hdr map[string]string) (int, string, http.Header) {
					return handlerGet(s, h, p, hdr)
				})
			}
			if got, want := s.shellCSP(), appCSP+"; frame-src "+tt.frameSrc; got != want {
				t.Errorf("shellCSP = %q, want %q", got, want)
			}
		})
	}
}

// A request with no Host reaches the app, as it does for any host that is not
// the content domain's.
func TestContentHostMissingHostReachesTheApp(t *testing.T) {
	s, _ := newTestServer(t, nil)
	if code, _, _ := handlerGet(s, "", "/healthz", nil); code != http.StatusOK {
		t.Errorf("GET /healthz with no Host: %d, want 200", code)
	}
}

// A content token that has not expired stops working on the content origin
// the moment its user's token version moves, the user is disabled, or the user
// is deleted.
func TestContentOriginTokenRevocation(t *testing.T) {
	w := newHostWorld(t)
	for _, tt := range []struct {
		name   string
		user   actor
		revoke func(id string) error
	}{
		{"token version bump", w.editor, func(id string) error { return w.s.store.SetUserDisabled(id, false) }},
		{"user disabled", w.viewer, func(id string) error { return w.s.store.SetUserDisabled(id, true) }},
		{"user deleted", w.outside, func(id string) error { return w.s.store.DeleteUser(id) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tok := mintContentToken(t, w.s, tt.user.id, w.art.id)
			paths := []string{"/api/me", w.vbase}
			for _, p := range paths {
				if tt.user.id == w.outside.id && p == w.vbase {
					continue // a user with no access gets a 404, not a 200
				}
				if resp := w.onContent(t, "GET", p, bearer(tok), nil); resp.StatusCode != http.StatusOK {
					t.Fatalf("before: GET %s: %d %s, want 200", p, resp.StatusCode, resp.body)
				}
			}
			if err := tt.revoke(tt.user.id); err != nil {
				t.Fatal(err)
			}
			for _, p := range paths {
				if resp := w.onContent(t, "GET", p, bearer(tok), nil); resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("after: GET %s: %d %s, want 401", p, resp.StatusCode, resp.body)
				}
			}
		})
	}
}

// HEAD is answered like GET, minus the body; any other method on the boot
// route is a 404.
func TestContentOriginHead(t *testing.T) {
	w := newHostWorld(t)
	get := w.onContent(t, "GET", "/_cairn/boot", nil, nil)
	for _, path := range []string{"/_cairn/boot", "/_cairn/boot.js"} {
		head := w.onContent(t, "HEAD", path, nil, nil)
		if head.StatusCode != http.StatusOK {
			t.Errorf("HEAD %s: %d, want 200", path, head.StatusCode)
		}
		if head.body != "" {
			t.Errorf("HEAD %s: a body of %d bytes", path, len(head.body))
		}
		if head.Header.Get("Content-Type") == "" {
			t.Errorf("HEAD %s: no Content-Type", path)
		}
	}
	head := w.onContent(t, "HEAD", "/_cairn/boot", nil, nil)
	if got, want := head.Header.Get("Content-Security-Policy"), get.Header.Get("Content-Security-Policy"); got != want || got == "" {
		t.Errorf("HEAD boot CSP %q, GET %q", got, want)
	}
	if resp := w.onContent(t, "OPTIONS", "/_cairn/boot", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("OPTIONS /_cairn/boot: %d, want 404", resp.StatusCode)
	}
}
