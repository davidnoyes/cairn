package release

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The statuses a check ends in.
const (
	StatusOK      = "ok"
	StatusChanged = "changed"
	StatusSkipped = "skipped"
	StatusFailed  = "failed"
)

// ErrOriginMismatch means the server names a different app origin from the
// one asked: its pages would render differently, so the check would fail on
// every page for a reason that is not a change.
var ErrOriginMismatch = errors.New("release: the server's public URL differs from the address given")

// maxBody caps one response. The largest asset, the Mermaid bundle, is a few
// megabytes.
const maxBody = 64 << 20

// Document is what GET /.well-known/cairn-release returns. Only Manifest is
// signed.
type Document struct {
	Manifest      json.RawMessage `json:"manifest"`
	AppOrigin     string          `json:"appOrigin"`
	ContentOrigin string          `json:"contentOrigin"`
}

// Target is the server a check runs against.
type Target struct {
	AppOrigin string
	// ContentOrigin is the content origin with * where the artifact ID goes.
	ContentOrigin string
	Client        *http.Client
	// Bearer, when set, is sent for the signed-in home page alone.
	Bearer string
}

// Result is the outcome of checking one URL.
type Result struct {
	URL    string
	Status string
	Detail string
}

// NewClient returns the HTTP client a check uses. It follows no redirects,
// so a page that sends the checker elsewhere fails rather than passing on
// another page's bytes, and it dials any *.localhost name at the loopback
// address (RFC 6761), as browsers do, so a local server's content hosts
// resolve.
func NewClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil && isLocalhostName(host) {
			addr = net.JoinHostPort("localhost", port)
		}
		return dialer.DialContext(ctx, network, addr)
	}
	proxy := tr.Proxy
	tr.Proxy = func(r *http.Request) (*url.URL, error) {
		if isLocalhostName(r.URL.Hostname()) {
			return nil, nil
		}
		return proxy(r)
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func isLocalhostName(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// defaultPorts are the ports a URL without one uses.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// splitOrigin parses raw as a URL and returns its scheme and host in
// lowercase, and its effective port: the one given, else the scheme's
// default, else "". The host may carry a * label, which url.Parse accepts.
func splitOrigin(raw string) (scheme, host, port string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", "", "", fmt.Errorf("release: %q is not a server URL", raw)
	}
	scheme, host, port = strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	if port == "" {
		port = defaultPorts[scheme]
	}
	return scheme, host, port, nil
}

// Origin returns raw's origin as scheme://host in lowercase, with the port
// only when it is not the scheme's default (:443 for https, :80 for http).
func Origin(raw string) (string, error) {
	scheme, host, port, err := splitOrigin(raw)
	if err != nil {
		return "", err
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" && port != defaultPorts[scheme] {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// Discover fetches the server's release document. It refuses one whose app
// origin is not the origin of server, or whose content origin has no *
// label for the artifact ID or is on another scheme or port than the app
// origin.
func Discover(ctx context.Context, client *http.Client, server string) (*Document, error) {
	origin, err := Origin(server)
	if err != nil {
		return nil, err
	}
	body, status, err := get(ctx, client, origin+"/.well-known/cairn-release", "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("release: %s/.well-known/cairn-release: HTTP %d; the server may predate release manifests", origin, status)
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("release: the server's release document: %v", err)
	}
	if string(doc.Manifest) == "null" {
		doc.Manifest = nil
	}
	if docOrigin, err := Origin(doc.AppOrigin); err != nil || docOrigin != origin {
		return nil, fmt.Errorf("%w: it says %q, not %q; the server's CAIRN_PUBLIC_URL must match the address given", ErrOriginMismatch, doc.AppOrigin, origin)
	}
	// Check builds URLs on the app origin, so it gets the origin alone.
	doc.AppOrigin = origin
	if !strings.Contains(doc.ContentOrigin, "://*.") {
		return nil, fmt.Errorf("release: the server's content origin %q has no * label for the artifact ID", doc.ContentOrigin)
	}
	appScheme, _, appPort, _ := splitOrigin(origin)
	scheme, _, port, err := splitOrigin(doc.ContentOrigin)
	if err != nil {
		return nil, err
	}
	if scheme != appScheme || port != appPort {
		return nil, fmt.Errorf("release: the server's content origin %q is on another scheme or port than its app origin %q", doc.ContentOrigin, doc.AppOrigin)
	}
	return &doc, nil
}

// page is an HTML page the server renders from a template, with the data
// the server renders it with for the request the check makes.
type page struct {
	origin, path, template string
	data                   any
	signedIn               bool
}

// Check fetches every asset in m and every page the server renders, and
// compares each with the manifest: an asset by its SHA-256, a page with the
// manifest's template rendered here. It never stops early, so one run lists
// every difference. The home page needs a session, so it is skipped unless
// t.Bearer is set.
func Check(ctx context.Context, t Target, m *Manifest) []Result {
	id := randomUUID()
	contentOrigin := strings.Replace(t.ContentOrigin, "*", id, 1)
	originURL := func(origin string) string {
		if origin == OriginContent {
			return contentOrigin
		}
		return t.AppOrigin
	}
	var results []Result
	for _, a := range m.Assets {
		u := originURL(a.Origin) + a.Path
		if a.Origin == OriginContent && a.Path == "/_cairn/sw.js" {
			// The server serves its worker only for its own app origin.
			u += "?app=" + url.QueryEscape(t.AppOrigin)
		}
		results = append(results, checkBytes(ctx, t.Client, u, "", a.SHA256))
	}

	set := template.New("")
	for _, tm := range m.Templates {
		if _, err := set.New(tm.Name).Parse(tm.Source); err != nil {
			results = append(results, Result{URL: tm.Name, Status: StatusFailed, Detail: "the manifest's template does not parse: " + err.Error()})
		}
	}
	shell := func(mode string) map[string]any {
		return map[string]any{"ID": id, "Version": "", "Path": "/", "Mode": mode, "ContentOrigin": contentOrigin, "User": nil}
	}
	pages := []page{
		{OriginApp, "/login", "login.html", map[string]any{"Next": "/"}, false},
		{OriginApp, "/signup", "signup.html", nil, false},
		{OriginApp, "/verify", "verify.html", nil, false},
		{OriginApp, "/forgot", "forgot.html", nil, false},
		{OriginApp, "/reset", "reset.html", nil, false},
		{OriginApp, "/refuse", "refuse.html", nil, false},
		{OriginApp, "/app", "app.html", nil, true},
		{OriginApp, "/shared/" + id, "shell.html", shell("shared"), false},
		{OriginApp, "/full/" + id, "shell.html", shell("full"), false},
		{OriginContent, "/_cairn/boot", "boot.html", map[string]string{"AppOrigin": t.AppOrigin}, false},
	}
	for _, p := range pages {
		u := originURL(p.origin) + p.path
		if p.signedIn && t.Bearer == "" {
			results = append(results, Result{URL: u, Status: StatusSkipped, Detail: "needs a session; sign in with cairn login to check it"})
			continue
		}
		tmpl := set.Lookup(p.template)
		if tmpl == nil {
			results = append(results, Result{URL: u, Status: StatusFailed, Detail: p.template + " is not in the manifest"})
			continue
		}
		var want bytes.Buffer
		if err := tmpl.Execute(&want, p.data); err != nil {
			results = append(results, Result{URL: u, Status: StatusFailed, Detail: "rendering " + p.template + ": " + err.Error()})
			continue
		}
		bearer := ""
		if p.signedIn {
			bearer = t.Bearer
		}
		results = append(results, checkBytes(ctx, t.Client, u, bearer, sum(want.Bytes())))
	}
	return results
}

// checkBytes fetches u and compares the SHA-256 of its body with want.
func checkBytes(ctx context.Context, client *http.Client, u, bearer, want string) Result {
	body, status, err := get(ctx, client, u, bearer)
	switch {
	case err != nil:
		return Result{URL: u, Status: StatusFailed, Detail: err.Error()}
	case status != http.StatusOK:
		return Result{URL: u, Status: StatusFailed, Detail: fmt.Sprintf("HTTP %d", status)}
	}
	if got := sum(body); got != want {
		return Result{URL: u, Status: StatusChanged, Detail: fmt.Sprintf("served sha256 %s, release %s", got, want)}
	}
	return Result{URL: u, Status: StatusOK}
}

func get(ctx context.Context, client *http.Client, u, bearer string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxBody {
		return nil, 0, fmt.Errorf("%s: response larger than %d bytes", u, maxBody)
	}
	return body, resp.StatusCode, nil
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// randomUUID returns a fresh lowercase version 4 UUID, for an artifact ID no
// server has: the pages and assets a check fetches are the same for any ID.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
