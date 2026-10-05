package server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSafeNext(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"/shared/abc/def/", "/shared/abc/def/"},
		{"/admin?tab=users", "/admin?tab=users"},
		{"https://evil.com", "/"},
		{"evil.com", "/"},
		{"//evil.com", "/"},
		// Browsers read a backslash in a URL as a slash, so these are
		// protocol-relative URLs to another host.
		{`/\evil.com`, "/"},
		{`\\evil.com`, "/"},
		{`/\/evil.com`, "/"},
		{`/shared/\evil`, "/"},
		// Browsers strip tabs and newlines before parsing.
		{"/\t/evil.com", "/"},
		{"/\n/evil.com", "/"},
	}
	for _, c := range cases {
		if got := safeNext(c.in); got != c.want {
			t.Errorf("safeNext(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestLoginNextRejectsBackslash covers the data attribute the page script
// navigates to, for a visitor and for a signed-in user alike: the page no
// longer redirects either of them itself.
func TestLoginNextRejectsBackslash(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	next := "/login?next=" + url.QueryEscape(`/\evil.com`)
	for _, token := range []string{"", admin.token} {
		req, _ := http.NewRequest("GET", ts.URL+next, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `data-next="/"`) {
			t.Errorf("signed in %v: status %d, page does not fall back to /:\n%s", token != "", resp.StatusCode, body)
		}
	}
}
