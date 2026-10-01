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

// TestLoginNextRejectsBackslash covers both places the target is used: the
// redirect for a signed-in user, and the data attribute the page script
// navigates to after sign-in.
func TestLoginNextRejectsBackslash(t *testing.T) {
	_, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	next := "/login?next=" + url.QueryEscape(`/\evil.com`)

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest("GET", ts.URL+next, nil)
	req.Header.Set("Authorization", "Bearer "+admin.token)
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Errorf("signed in: status %d, Location %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, err = http.Get(ts.URL + next)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `data-next="/"`) {
		t.Errorf("login page does not fall back to /:\n%s", body)
	}
}
