package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// reviewProxy forwards to host and answers GET /api/artifacts/{id}/review
// with entries: nobody can be made a removed editor through the CLI yet.
// With failDirectory, the user directory answers 500.
func reviewProxy(t *testing.T, host string, entries []map[string]any, failDirectory ...bool) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		if len(failDirectory) > 0 && failDirectory[0] && resp.Request.Method == "GET" && resp.Request.URL.Path == "/api/users" {
			resp.StatusCode = http.StatusInternalServerError
			return nil
		}
		if resp.Request.Method != "GET" || !strings.HasSuffix(resp.Request.URL.Path, "/review") {
			return nil
		}
		data, err := json.Marshal(entries)
		if err != nil {
			return err
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestReviewCommand(t *testing.T) {
	host, _, artifact := shareSetup(t)
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	bob := membersByEmail(t, artifact)["bob@example.com"].User

	out, err := runQuiet(t, runReview, artifact)
	if err != nil || !strings.Contains(out, "no versions on shared need review") {
		t.Errorf("cairn review with nothing to review printed %q, %v", out, err)
	}
	none := runJSON[struct {
		Artifact string           `json:"artifact"`
		Versions []map[string]any `json:"versions"`
	}](t, runReview, artifact, "--json")
	if none.Artifact != artifact || none.Versions == nil || len(none.Versions) != 0 {
		t.Errorf("cairn review --json with nothing = %+v, want an empty list", none)
	}

	entries := []map[string]any{
		{"id": "v-bob", "seq": 3, "pushedBy": bob, "createdAt": "2026-03-04T05:06:07Z"},
		{"id": "v-gone", "seq": 5, "pushedBy": nil, "createdAt": "2026-03-06T00:00:00Z"},
	}
	proxy := reviewProxy(t, host, entries)
	cliLogin(t, proxy, "ada@example.com", sharePassword)

	out, err = runQuiet(t, runReview, artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 versions on shared need review", "v-bob", "bob@example.com", "2026-03-04", "v-gone", "cairn vouch " + artifact + " VERSION"} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn review printed %q, missing %q", out, want)
		}
	}

	got := runJSON[struct {
		Artifact string `json:"artifact"`
		Versions []struct {
			ID        string  `json:"id"`
			Seq       int     `json:"seq"`
			PushedBy  *string `json:"pushedBy"`
			Email     string  `json:"email"`
			CreatedAt string  `json:"createdAt"`
		} `json:"versions"`
	}](t, runReview, artifact, "--json")
	if len(got.Versions) != 2 {
		t.Fatalf("cairn review --json = %+v", got)
	}
	if v := got.Versions[0]; v.ID != "v-bob" || v.Seq != 3 || v.PushedBy == nil || *v.PushedBy != bob || v.Email != "bob@example.com" || v.CreatedAt != "2026-03-04T05:06:07Z" {
		t.Errorf("first entry = %+v", v)
	}
	if v := got.Versions[1]; v.ID != "v-gone" || v.PushedBy != nil || v.Email != "" {
		t.Errorf("second entry = %+v", v)
	}
}

func TestReviewAndVouchUsage(t *testing.T) {
	if _, err := runQuiet(t, runReview); err == nil || !strings.Contains(err.Error(), "usage: cairn review ARTIFACT [--json]") {
		t.Errorf("review with no artifact: %v", err)
	}
	if _, err := runQuiet(t, runVouch, "only-one"); err == nil || !strings.Contains(err.Error(), "usage: cairn vouch ARTIFACT VERSION [--json]") {
		t.Errorf("vouch with no version: %v", err)
	}
}

func TestVouchCommand(t *testing.T) {
	_, _, artifact := shareSetup(t)
	pushed := runJSON[struct {
		Version struct {
			ID string `json:"id"`
		} `json:"version"`
	}](t, runPush, siteDir(t), "--artifact", artifact, "--json")
	vid := pushed.Version.ID

	out, err := runQuiet(t, runVouch, artifact, vid)
	if err != nil || !strings.Contains(out, "vouched for version "+vid+" of shared") {
		t.Errorf("cairn vouch printed %q, %v", out, err)
	}
	res := runJSON[map[string]any](t, runVouch, artifact, vid, "--json")
	if res["artifact"] != artifact || res["version"] != vid || res["vouched"] != true {
		t.Errorf("cairn vouch --json = %v", res)
	}
	if _, err := runQuiet(t, runVouch, artifact, "no-such-version"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("vouch for a missing version: %v, want not found", err)
	}
}

// One entry reads in the singular, and an unreachable directory shows user
// IDs rather than failing the list.
func TestReviewCommandOneEntryWithoutTheDirectory(t *testing.T) {
	host, _, artifact := shareSetup(t)
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	bob := membersByEmail(t, artifact)["bob@example.com"].User
	proxy := reviewProxy(t, host, []map[string]any{
		{"id": "v-bob", "seq": 3, "pushedBy": bob, "createdAt": "2026-03-04T05:06:07Z"},
	}, true)
	cliLogin(t, proxy, "ada@example.com", sharePassword)

	out, err := runQuiet(t, runReview, artifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"1 version on shared needs review: its pusher is no longer an editor", "v-bob", bob} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn review printed %q, missing %q", out, want)
		}
	}
}
