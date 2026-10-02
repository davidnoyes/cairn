package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

func TestRotateKeysCommand(t *testing.T) {
	host, m := newTestServer(t)
	signupVerify(t, host, m, "ada@example.com", sharePassword)
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cliLogin(t, host, "ada@example.com", sharePassword)
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	private, err := c.CreateArtifact("private", "")
	if err != nil {
		t.Fatal(err)
	}
	public, err := c.CreateArtifact("public", "")
	if err != nil {
		t.Fatal(err)
	}
	oldLink, err := c.Public(public.ID, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := loadConfig().APIKey

	withStdin(t, sharePassword+"\n")
	out, err := runQuiet(t, runRotateKeys, "--password-stdin")
	if err != nil {
		t.Fatalf("cairn rotate-keys: %v", err)
	}
	var link, code string
	for _, field := range strings.Fields(out) {
		if strings.Contains(field, "/shared/") {
			link = field
		}
		if _, err := e2e.ParseRecoveryCode(field); err == nil && strings.Contains(field, "-") {
			code = field
		}
	}
	if code == "" {
		t.Errorf("cairn rotate-keys printed no recovery code: %q", out)
	}
	if l, perr := e2e.ParseLink(link); perr != nil || l.Artifact != public.ID || l.Epoch != 2 || link == oldLink.Link {
		t.Errorf("cairn rotate-keys printed the link %q (%v), want a new one at epoch 2", link, perr)
	}
	for _, want := range []string{
		"Save this recovery code. Nobody, including an administrator, can recover your account without your password or this code.",
		"rotation 1",
		"artifact " + private.ID + ": epoch 2",
		"artifact " + public.ID + ": epoch 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn rotate-keys printed %q, want it to say %q", out, want)
		}
	}
	if _, err := client.OpenLink(link); err != nil {
		t.Errorf("OpenLink of the new link: %v", err)
	}
	if _, err := client.OpenLink(oldLink.Link); err == nil {
		t.Error("the old link still opens")
	}

	// The saved device key is the new one; the old one is dead.
	cfg := loadConfig()
	if cfg.APIKey == "" || cfg.APIKey == oldKey || cfg.Host != host || cfg.Email != "ada@example.com" {
		t.Errorf("config after rotation = %+v, want the new key", cfg)
	}
	key, err := e2e.ParseAPIKey(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	var api *client.APIError
	if _, err := client.New(host, bearerOf(key)).Me(); !errors.As(err, &api) || api.Status != http.StatusUnauthorized {
		t.Errorf("the old key after rotation: %v, want 401", err)
	}
	if _, err := runQuiet(t, runWhoami); err != nil {
		t.Errorf("cairn whoami with the saved key: %v", err)
	}
	// The keyring anchor for the new keys is saved in the config file.
	c, err = apiClient()
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f, err := readConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if a := f.Anchors[configAnchors{host: host}.key(k.UserID, k.FP)]; a.Rev < 1 {
		t.Errorf("anchor for the new keys = %+v, want one saved", a)
	}
	if _, rows, err := c.Members(private.ID); err != nil || len(rows) != 1 {
		t.Errorf("Members after rotation = %v, %v", rows, err)
	}

	// A second rotation, keeping epochs, with JSON output.
	withStdin(t, sharePassword+"\n")
	res := runJSON[map[string]any](t, runRotateKeys, "--keep-epochs", "--json", "--password-stdin")
	epochs, _ := res["epochs"].(map[string]any)
	if res["seq"] != float64(2) || epochs[private.ID] != float64(2) || epochs[public.ID] != float64(2) || len(epochs) != 2 ||
		res["recoveryCode"] == "" || res["recoveryCode"] == code ||
		len(res["links"].(map[string]any)) != 0 || len(res["warnings"].([]any)) != 0 || res["unconfirmed"] != false || len(res) != 6 {
		t.Errorf("cairn rotate-keys --keep-epochs --json = %v", res)
	}
}

func TestRotateKeysCommandRefusals(t *testing.T) {
	host, m := newTestServer(t)
	signupVerify(t, host, m, "ada@example.com", sharePassword)
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cliLogin(t, host, "ada@example.com", sharePassword)
	before := loadConfig()

	if _, err := runQuiet(t, runRotateKeys, "extra"); err == nil || !strings.Contains(err.Error(), "usage: cairn rotate-keys") {
		t.Errorf("an extra argument: %v, want the usage error", err)
	}
	withStdin(t, "not the password\n")
	var api *client.APIError
	if _, err := runQuiet(t, runRotateKeys, "--password-stdin"); !errors.As(err, &api) || api.Status != http.StatusUnauthorized {
		t.Errorf("a wrong password: %v, want 401", err)
	}
	if got := loadConfig(); got != before {
		t.Errorf("a refused rotation changed the config: %+v, was %+v", got, before)
	}
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Me(); err != nil {
		t.Errorf("the saved key after a refused rotation: %v", err)
	}
}

// failAfterRotateProxy forwards to host and, once a POST /api/me/rotate has
// been forwarded, answers 503 to every request fail accepts.
func failAfterRotateProxy(t *testing.T, host string, fail func(r *http.Request) bool) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	forward := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		pr.Out.Host = pr.In.Host
	}}
	var rotated atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rotated.Load() && fail(r) {
			http.Error(w, "injected failure", http.StatusServiceUnavailable)
			return
		}
		forward.ServeHTTP(w, r)
		if r.Method == "POST" && r.URL.Path == "/api/me/rotate" {
			rotated.Store(true)
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// rotateLogin signs ada up on a fresh server and logs the CLI in through a
// proxy that fails what fail accepts after the rotation. It returns the
// proxy's address and the config then.
func rotateLogin(t *testing.T, fail func(r *http.Request) bool) (host string, before cliConfig) {
	t.Helper()
	server, m := newTestServer(t)
	signupVerify(t, server, m, "ada@example.com", sharePassword)
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	host = failAfterRotateProxy(t, server, fail)
	cliLogin(t, host, "ada@example.com", sharePassword)
	return host, loadConfig()
}

// recoveryCodeIn is the recovery code printed in out, or "".
func recoveryCodeIn(out string) string {
	for _, field := range strings.Fields(out) {
		if _, err := e2e.ParseRecoveryCode(field); err == nil && strings.Contains(field, "-") {
			return field
		}
	}
	return ""
}

func TestRotateKeysCommandRefusesHeadlessCredentials(t *testing.T) {
	for _, env := range []string{"CAIRN_API_KEY", "CAIRN_HOST"} {
		t.Run(env, func(t *testing.T) {
			host, m := newTestServer(t)
			signupVerify(t, host, m, "ada@example.com", sharePassword)
			t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
			t.Setenv("CAIRN_HOST", "")
			t.Setenv("CAIRN_API_KEY", "")
			cliLogin(t, host, "ada@example.com", sharePassword)
			before := loadConfig()
			c, err := apiClient()
			if err != nil {
				t.Fatal(err)
			}
			k, err := c.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(env, map[string]string{"CAIRN_API_KEY": before.APIKey, "CAIRN_HOST": host}[env])

			withStdin(t, sharePassword+"\n")
			out, err := runQuiet(t, runRotateKeys, "--password-stdin")
			if err == nil || !strings.Contains(err.Error(), "revokes every API key, CAIRN_API_KEY included") || !strings.Contains(err.Error(), "unset CAIRN_HOST and CAIRN_API_KEY") {
				t.Fatalf("cairn rotate-keys = %q, %v, want the refusal", out, err)
			}
			if out != "" {
				t.Errorf("a refusal printed %q", out)
			}
			if got := loadConfig(); got != before {
				t.Errorf("a refusal changed the config: %+v, was %+v", got, before)
			}
			if recs, err := c.Rotations(k.UserID); err != nil || len(recs) != 0 {
				t.Errorf("Rotations = %v, %v, want none", recs, err)
			}
		})
	}
}

func TestRotateKeysCommandAFailureAfterTheRotationStillShowsTheCode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fail      func(r *http.Request) bool
		wantSaved bool
	}{
		{"signing in again fails", func(r *http.Request) bool { return r.URL.Path == "/api/auth/login" }, false},
		{"the read-back fails", func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "/membership") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, before := rotateLogin(t, tc.fail)
			c, err := apiClient()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.CreateArtifact("private", ""); err != nil {
				t.Fatal(err)
			}
			withStdin(t, sharePassword+"\n")
			out, err := runQuiet(t, runRotateKeys, "--password-stdin")
			if err == nil {
				t.Fatalf("cairn rotate-keys succeeded: %q", out)
			}
			if recoveryCodeIn(out) == "" {
				t.Errorf("cairn rotate-keys printed no recovery code with the error %v: %q", err, out)
			}
			saved := loadConfig().APIKey != before.APIKey
			if saved != tc.wantSaved || loadConfig().Host != host {
				t.Errorf("config after = %+v, want a new key saved: %v", loadConfig(), tc.wantSaved)
			}
			if got := strings.Contains(out, "has a new one, saved"); got != tc.wantSaved {
				t.Errorf("output says the key was saved = %v, want %v: %q", got, tc.wantSaved, out)
			}
			if !tc.wantSaved && !strings.Contains(out, "run cairn login") {
				t.Errorf("output with no key to save does not say to run cairn login: %q", out)
			}
		})
	}
}

func TestRotateKeysCommandSaveFailureStillShowsTheCode(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop root")
	}
	_, before := rotateLogin(t, func(*http.Request) bool { return false })
	dir := filepath.Dir(os.Getenv("CAIRN_CONFIG"))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	withStdin(t, sharePassword+"\n")
	out, err := runQuiet(t, runRotateKeys, "--password-stdin")
	if err == nil || !strings.Contains(err.Error(), "saving the new device key failed") || !strings.Contains(err.Error(), "run cairn login") {
		t.Fatalf("cairn rotate-keys error = %v, want the failed save, and to run cairn login", err)
	}
	if recoveryCodeIn(out) == "" || strings.Contains(out, "has a new one, saved") || !strings.Contains(out, "run cairn login") {
		t.Errorf("output = %q, want the code and no claim that the key was saved", out)
	}
	if got := loadConfig(); got != before {
		t.Errorf("config = %+v, want it unchanged: %+v", got, before)
	}
}

func TestRotateKeysCommandKeptAndMovedEpochs(t *testing.T) {
	rotateLogin(t, func(*http.Request) bool { return false })
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.CreateArtifact("private", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--keep-epochs", "--password-stdin"}, "artifact " + a.ID + ": epoch 1 (kept)"},
		{[]string{"--password-stdin"}, "artifact " + a.ID + ": epoch 2 (moved)"},
	} {
		withStdin(t, sharePassword+"\n")
		out, err := runQuiet(t, runRotateKeys, tc.args...)
		if err != nil || !strings.Contains(out, tc.want) || !strings.Contains(out, "has a new one, saved") {
			t.Errorf("cairn rotate-keys %v = %q, %v, want %q and the key saved", tc.args, out, err, tc.want)
		}
	}
}

// TestPrintRotationShowsWarnings: RotateKeys has no warning to give yet, so
// the output for one is checked on a result made by hand.
func TestPrintRotationShowsWarnings(t *testing.T) {
	done := captureStdout(t)
	printRotation(&client.RotateResult{RecoveryCode: "code", Seq: 3, Warnings: []string{"artifact x changed hands"}}, false, true)
	if out := done(); !strings.Contains(out, "warning: artifact x changed hands") {
		t.Errorf("printRotation = %q, want the warning", out)
	}
}

// TestPrintRotationUnconfirmed: when the server's answer was lost and could
// not be settled, the output must not claim the keys were rotated.
func TestPrintRotationUnconfirmed(t *testing.T) {
	done := captureStdout(t)
	printRotation(&client.RotateResult{RecoveryCode: "code", Seq: 3, Unconfirmed: true}, false, false)
	out := done()
	if strings.Contains(out, "Keys rotated") || strings.Contains(out, "was revoked") {
		t.Errorf("printRotation = %q, want no claim that the keys were rotated", out)
	}
	if !strings.Contains(out, "may have rotated") || !strings.Contains(out, "code") || !strings.Contains(out, "cairn rotate-keys again") {
		t.Errorf("printRotation = %q, want the code, the doubt, and the advice", out)
	}
}

func TestRotateKeysCommandJSON(t *testing.T) {
	rotateLogin(t, func(*http.Request) bool { return false })
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	public, err := c.CreateArtifact("public", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Public(public.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	withStdin(t, sharePassword+"\n")
	res := runJSON[map[string]any](t, runRotateKeys, "--json", "--password-stdin")
	links, _ := res["links"].(map[string]any)
	link, _ := links[public.ID].(string)
	if l, err := e2e.ParseLink(link); err != nil || l.Artifact != public.ID || l.Epoch != 2 || len(links) != 1 {
		t.Errorf("cairn rotate-keys --json links = %v, want the public artifact's new link at epoch 2", res["links"])
	}
}

func TestRotateKeysCommandJSONWithAnErrorAfterTheRotation(t *testing.T) {
	rotateLogin(t, func(r *http.Request) bool { return r.URL.Path == "/api/auth/login" })
	withStdin(t, sharePassword+"\n")
	out, err := runQuiet(t, runRotateKeys, "--json", "--password-stdin")
	if err == nil {
		t.Fatalf("cairn rotate-keys succeeded: %q", out)
	}
	var res map[string]any
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil {
		t.Fatalf("stdout %q is not JSON: %v", out, jerr)
	}
	if code, _ := res["recoveryCode"].(string); recoveryCodeIn(code) == "" || res["seq"] != float64(1) {
		t.Errorf("cairn rotate-keys --json = %v, want the recovery code and seq 1", res)
	}
}

func TestRotateKeysCommandReadsThePasswordFromStdin(t *testing.T) {
	for _, tc := range []struct {
		name, stdin string
		args        []string
		wantErr     string
	}{
		{"without the flag", sharePassword + "\n", nil, ""},
		{"no trailing newline", sharePassword, []string{"--password-stdin"}, ""},
		{"empty stdin", "", []string{"--password-stdin"}, "password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, m := newTestServer(t)
			signupVerify(t, host, m, "ada@example.com", sharePassword)
			t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
			cliLogin(t, host, "ada@example.com", sharePassword)
			before := loadConfig()
			withStdin(t, tc.stdin)
			out, err := runQuiet(t, runRotateKeys, tc.args...)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("cairn rotate-keys = %q, %v, want an error naming the %s", out, err, tc.wantErr)
				}
				if got := loadConfig(); got != before {
					t.Errorf("an empty password changed the config: %+v", got)
				}
				return
			}
			if err != nil || recoveryCodeIn(out) == "" || loadConfig().APIKey == before.APIKey {
				t.Errorf("cairn rotate-keys = %q, %v, want a rotation", out, err)
			}
		})
	}
}
