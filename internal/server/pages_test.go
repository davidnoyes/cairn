package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/server/web"
)

// Every page that carries the app CSP: the signed-out pages need no session,
// and /admin needs an administrator.
var accountPages = []string{"/signup", "/verify", "/login", "/forgot", "/reset", "/admin"}

// pageTemplates are the template files behind accountPages.
var pageTemplates = []string{"signup.html", "verify.html", "login.html", "forgot.html", "reset.html", "admin.html"}

var (
	scriptSrcRe = regexp.MustCompile(`<script[^>]*\ssrc="([^"]+)"`)
	linkHrefRe  = regexp.MustCompile(`<link[^>]*\shref="(/[^"]+)"`)
	importRe    = regexp.MustCompile(`from '\./([^']+)'`)
)

func pageBody(t *testing.T, base, path string) (*http.Response, string) {
	t.Helper()
	token := ""
	if path == "/admin" {
		token = login(t, base, "admin@example.com", "admin-password").token
	}
	resp := get(t, base+path, token, "text/html")
	return resp, body(t, resp)
}

func TestAccountPagesSendTheAppCSP(t *testing.T) {
	_, ts := testServer(t)
	for _, path := range accountPages {
		resp, _ := pageBody(t, ts.URL, path)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Security-Policy"); got != appCSP {
			t.Errorf("%s: CSP %q, want %q", path, got, appCSP)
		}
	}
}

// TestAccountPageAssetsAreServed follows every script and stylesheet a page
// names, and every module those import, and checks each is served with the
// right content type. A page whose script is missing shows a dead form.
func TestAccountPageAssetsAreServed(t *testing.T) {
	_, ts := testServer(t)
	seen := map[string]bool{}
	var fetch func(path string)
	fetch = func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		resp := get(t, ts.URL+path, "", "")
		text := body(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, resp.StatusCode)
			return
		}
		got := resp.Header.Get("Content-Type")
		switch {
		case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".mjs"):
			if !strings.HasPrefix(got, "text/javascript") {
				t.Errorf("%s: Content-Type %q, want text/javascript", path, got)
			}
			for _, m := range importRe.FindAllStringSubmatch(text, -1) {
				fetch("/" + m[1])
			}
		case strings.HasSuffix(path, ".css"):
			if !strings.HasPrefix(got, "text/css") {
				t.Errorf("%s: Content-Type %q, want text/css", path, got)
			}
		}
	}
	for _, path := range accountPages {
		_, html := pageBody(t, ts.URL, path)
		scripts := scriptSrcRe.FindAllStringSubmatch(html, -1)
		if len(scripts) == 0 {
			t.Errorf("%s names no script file", path)
		}
		for _, m := range scripts {
			fetch(m[1])
		}
		for _, m := range linkHrefRe.FindAllStringSubmatch(html, -1) {
			fetch(m[1])
		}
	}
	// What the worker loads is not named by any page or import.
	for _, path := range []string{"/argon2-worker.js", "/wasm_exec.js", "/argon2.wasm"} {
		fetch(path)
	}
	for _, want := range []string{"/e2e.mjs", "/account.mjs", "/zxcvbn.js", "/signup.js", "/reset.js", "/admin.js", "/app.css"} {
		if !seen[want] {
			t.Errorf("%s was never reached from a page", want)
		}
	}
}

var (
	inlineScriptRe = regexp.MustCompile(`(?is)<script(?:\s[^>]*)?>(.*?)</script>`)
	handlerAttrRe  = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	styleAttrRe    = regexp.MustCompile(`(?i)\sstyle\s*=`)
)

// TestPageTemplatesCarryNoInlineCode checks the source of each template, since
// the CSP only fails at run time in a browser: an inline script body, an
// on* handler, a style element or attribute, or a javascript: URL.
func TestPageTemplatesCarryNoInlineCode(t *testing.T) {
	for _, name := range pageTemplates {
		src, err := web.Templates.ReadFile(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		html := string(src)
		for _, m := range inlineScriptRe.FindAllStringSubmatch(html, -1) {
			if strings.TrimSpace(m[1]) != "" {
				t.Errorf("%s: inline script body %.60q", name, m[1])
			}
		}
		if !scriptSrcRe.MatchString(html) {
			t.Errorf("%s: no script file", name)
		}
		if handlerAttrRe.MatchString(html) {
			t.Errorf("%s: inline event handler attribute", name)
		}
		if styleAttrRe.MatchString(html) {
			t.Errorf("%s: inline style attribute", name)
		}
		for _, bad := range []string{"<style", "javascript:", "fonts.googleapis.com"} {
			if strings.Contains(strings.ToLower(html), bad) {
				t.Errorf("%s: contains %q, which the CSP blocks", name, bad)
			}
		}
	}
}

// A form that falls back to its default submit would send the password in the
// URL (GET) or to the server in plain text (POST) whenever the page script
// fails to load. method="dialog" outside a dialog element does nothing.
func TestPageFormsDoNothingWithoutTheScript(t *testing.T) {
	formRe := regexp.MustCompile(`(?i)<form\b[^>]*>`)
	for _, name := range pageTemplates {
		src, err := web.Templates.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, tag := range formRe.FindAllString(string(src), -1) {
			if !strings.Contains(tag, `method="dialog"`) {
				t.Errorf("%s: %s lacks method=\"dialog\"", name, tag)
			}
		}
	}
}

// The strength estimator is 800 KB, so only the pages that set a password
// load it.
func TestStrengthEstimatorOnlyOnPasswordPages(t *testing.T) {
	_, ts := testServer(t)
	for _, path := range accountPages {
		_, html := pageBody(t, ts.URL, path)
		has := strings.Contains(html, `src="/zxcvbn.js"`)
		want := path == "/signup" || path == "/reset"
		if has != want {
			t.Errorf("%s loads zxcvbn.js = %v, want %v", path, has, want)
		}
	}
}

// The login page hands ?next= to its script in a data attribute, after the
// same safe-next rule that guards the redirect for a signed-in user.
func TestLoginPageCarriesOnlyASafeNext(t *testing.T) {
	_, ts := testServer(t)
	cases := []struct{ next, want string }{
		{"/shared/abc/def/", "/shared/abc/def/"},
		{"/admin", "/admin"},
		{"", "/"},
		{"https://evil.example", "/"},
		{"//evil.example", "/"},
		{`/\evil.example`, "/"},
	}
	for _, c := range cases {
		resp := get(t, ts.URL+"/login?next="+url.QueryEscape(c.next), "", "text/html")
		html := body(t, resp)
		if want := `data-next="` + c.want + `"`; !strings.Contains(html, want) {
			t.Errorf("next %q: login page lacks %s", c.next, want)
		}
		if resp.Header.Get("Content-Security-Policy") != appCSP {
			t.Errorf("next %q: login page lacks the app CSP", c.next)
		}
	}
}

// The old sign-in page asked a new user to type the password twice. That flow
// is gone: sign-up is its own page.
func TestLoginPageHasNoClaimFlow(t *testing.T) {
	_, ts := testServer(t)
	_, html := pageBody(t, ts.URL, "/login")
	for _, gone := range []string{`name="confirm"`, "First sign-in", "claim"} {
		if strings.Contains(html, gone) {
			t.Errorf("login page still contains %q", gone)
		}
	}
	for _, want := range []string{`href="/signup"`, `href="/forgot"`} {
		if !strings.Contains(html, want) {
			t.Errorf("login page lacks %s", want)
		}
	}
}
