package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

// badWrapProxy forwards to host and, in each answer to GET
// /api/artifacts/{id}/keys, replaces the wrap of epoch with bytes that do not
// open, as a server handing the owner a bad wrap would.
func badWrapProxy(t *testing.T, host string, epoch int) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		path := resp.Request.URL.Path
		if resp.Request.Method != "GET" || resp.StatusCode != 200 || !strings.HasPrefix(path, "/api/artifacts/") || !strings.HasSuffix(path, "/keys") {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		var keys map[string]any
		if err := json.Unmarshal(body, &keys); err != nil {
			return err
		}
		wraps, _ := keys["wraps"].([]any)
		for _, w := range wraps {
			if m, _ := w.(map[string]any); m != nil && int(m["epoch"].(float64)) == epoch {
				m["wrapped"] = e2e.B64(make([]byte, 81))
			}
		}
		if body, err = json.Marshal(keys); err != nil {
			return err
		}
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts.URL
}

// The owner's unshare, run through a server that hands them a bad wrap of a
// manager's epoch, names the epoch in the warning and in the JSON.
func TestUnshareReportsAnEpochTheOwnerCannotRead(t *testing.T) {
	w := managerWorld(t)
	for _, who := range []string{"cat@example.com", "dan@example.com"} {
		if _, err := runQuiet(t, runShare, w.artifact, who); err != nil {
			t.Fatal(err)
		}
	}
	// The manager's unshare starts epoch 2, with a wrap for the owner.
	w.as(t, "bob")
	if _, err := runQuiet(t, runUnshare, w.artifact, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	// The owner again, on a config that signs in through the proxy.
	w.configs["adaProxy"] = filepath.Join(t.TempDir(), "adaProxy.json")
	w.as(t, "adaProxy")
	cliLogin(t, badWrapProxy(t, w.host, 2), "ada@example.com", sharePassword)

	res := runJSON[map[string]any](t, runUnshare, w.artifact, "dan@example.com", "--json")
	if got := res["unreadableEpochs"]; !reflect.DeepEqual(got, []any{float64(2)}) || res["epoch"] != float64(3) || res["newEpoch"] != true {
		t.Errorf("cairn unshare --json = %v, want epoch 3 with unreadableEpochs [2]", res)
	}
	out, err := runQuiet(t, runUnshare, w.artifact, "bob@example.com")
	if err != nil {
		t.Fatalf("the owner removes the manager: %v", err)
	}
	if !strings.Contains(out, "warning: epoch 2 is unreadable to you") {
		t.Errorf("cairn unshare printed %q, want the warning naming epoch 2", out)
	}
}

// A change that starts no epoch still has unreadableEpochs, empty, as the
// JSON of one that does.
func TestEpochChangeJSONAlwaysHasUnreadableEpochs(t *testing.T) {
	for _, ch := range []client.EpochChange{{}, {NewEpoch: true}} {
		got := map[string]any{}
		epochChangeJSON(got, ch)
		out, err := json.Marshal(got)
		if err != nil || !strings.Contains(string(out), `"unreadableEpochs":[]`) {
			t.Errorf("epochChangeJSON(%+v) = %s, %v, want an empty unreadableEpochs", ch, out, err)
		}
	}
}
