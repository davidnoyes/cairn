package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/mail"
)

const sharePassword = "correct horse battery staple"

// cliLogin signs email in through runLogin, against host, with the config
// at the current CAIRN_CONFIG.
func cliLogin(t *testing.T, host, email, password string) {
	t.Helper()
	withStdin(t, password+"\n")
	if _, err := runQuiet(t, runLogin, "--host", host, "--email", email, "--password-stdin"); err != nil {
		t.Fatalf("runLogin %s: %v", email, err)
	}
}

// keyringProxy forwards to host and, while override is set, answers GET
// /api/me/keyring with it instead.
func keyringProxy(t *testing.T, host string, override *atomic.Pointer[string]) string {
	t.Helper()
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		body := override.Load()
		if body == nil || resp.Request.Method != "GET" || resp.Request.URL.Path != "/api/me/keyring" {
			return nil
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(strings.NewReader(*body))
		resp.ContentLength = int64(len(*body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(*body)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestKeyringAnchorSurvivesLogoutAndLogin writes the keyring once, logs out
// and in again, then has the server serve the keyring wiped: the anchor
// kept in the config file must refuse it.
func TestKeyringAnchorSurvivesLogoutAndLogin(t *testing.T) {
	host, m := newTestServer(t)
	signupVerify(t, host, m, "ada@example.com", sharePassword)
	var override atomic.Pointer[string]
	proxy := keyringProxy(t, host, &override)
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cliLogin(t, proxy, "ada@example.com", sharePassword)

	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateKeyring(k, func(kr *e2e.Keyring) error {
		kr.Pins["someone"] = e2e.Pin{FP: strings.Repeat("a", 64), State: e2e.PinUnverified}
		return nil
	}); err != nil {
		t.Fatalf("UpdateKeyring: %v", err)
	}

	if _, err := runQuiet(t, runLogout); err != nil {
		t.Fatalf("runLogout: %v", err)
	}
	f, err := readConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if f.cliConfig != (cliConfig{}) {
		t.Errorf("login after logout = %+v, want cleared", f.cliConfig)
	}
	if a := f.Anchors[proxy+" "+k.UserID+" "+k.FP]; a.Rev != 1 {
		t.Errorf("anchor after logout = %+v, want rev 1 kept", a)
	}

	cliLogin(t, proxy, "ada@example.com", sharePassword)
	wiped := `{"rev":0,"keyring":""}`
	override.Store(&wiped)
	c, err = apiClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadKeyring(k); !errors.Is(err, e2e.ErrKeyringRollback) {
		t.Errorf("ReadKeyring of a wiped keyring after signing in again: %v, want ErrKeyringRollback", err)
	}
	if _, err := runQuiet(t, runPin, "ada@example.com"); !errors.Is(err, e2e.ErrKeyringRollback) {
		t.Errorf("cairn pin on a wiped keyring: %v, want ErrKeyringRollback", err)
	}
}

func TestConfigRefusesACorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("CAIRN_CONFIG", path)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(cliConfig{Host: "http://example.test"}); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("saveConfig over a corrupt file: %v, want a refusal", err)
	}
	store := configAnchors{host: "http://example.test"}
	if _, err := store.LoadAnchor("u1", "fp1"); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("LoadAnchor from a corrupt file: %v, want a refusal", err)
	}
	if err := store.SaveAnchor("u1", "fp1", e2e.KeyringAnchor{Rev: 1, Hash: strings.Repeat("a", 64)}); err == nil {
		t.Error("SaveAnchor wrote over a corrupt file")
	}
}

func TestConfigAnchorsAreKeyedByHostUserAndFingerprint(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	want := cliConfig{Host: "http://a.test", Email: "ada@example.com", APIKey: "cairn_x_y_z"}
	if err := saveConfig(want); err != nil {
		t.Fatal(err)
	}
	a, b := configAnchors{host: "http://a.test"}, configAnchors{host: "http://b.test"}
	anchor := e2e.KeyringAnchor{Rev: 3, Hash: strings.Repeat("c", 64)}
	if err := a.SaveAnchor("u1", "fp1", anchor); err != nil {
		t.Fatal(err)
	}
	if got, err := a.LoadAnchor("u1", "fp1"); err != nil || got == nil || *got != anchor {
		t.Errorf("LoadAnchor = %v, %v, want %+v", got, err, anchor)
	}
	for _, tc := range []struct {
		store    configAnchors
		user, fp string
	}{{b, "u1", "fp1"}, {a, "u2", "fp1"}, {a, "u1", "fp2"}} {
		if got, err := tc.store.LoadAnchor(tc.user, tc.fp); err != nil || got != nil {
			t.Errorf("LoadAnchor(%s, %s, %s) = %v, %v, want none", tc.store.host, tc.user, tc.fp, got, err)
		}
	}
	if got := loadConfig(); got != want {
		t.Errorf("saving an anchor changed the login to %+v", got)
	}
}

// shareSetup is a server with ada and bob, ada logged in through the CLI
// and owning an artifact.
func shareSetup(t *testing.T) (host string, m *mail.Capture, artifact string) {
	t.Helper()
	host, m = newTestServer(t)
	signupVerify(t, host, m, "ada@example.com", sharePassword)
	signupVerify(t, host, m, "bob@example.com", sharePassword)
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cliLogin(t, host, "ada@example.com", sharePassword)
	a := runJSON[map[string]any](t, artifactCreate, "shared", "--json")
	return host, m, a["id"].(string)
}

type memberRow struct {
	User, Email, Role, FP, State string
}

func membersByEmail(t *testing.T, artifact string) map[string]memberRow {
	t.Helper()
	out := runJSON[struct {
		Members []memberRow `json:"members"`
	}](t, runMembers, artifact, "--json")
	rows := map[string]memberRow{}
	for _, r := range out.Members {
		rows[r.Email] = r
	}
	return rows
}

func TestShareMembersAndPinCommands(t *testing.T) {
	_, _, artifact := shareSetup(t)

	out, err := runQuiet(t, runShare, artifact, "bob@example.com")
	if err != nil {
		t.Fatalf("cairn share: %v", err)
	}
	for _, want := range []string{"bob@example.com", "new; pinned unverified", "added as viewer of shared", "cairn pin bob@example.com --verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("cairn share printed %q, want %q", out, want)
		}
	}

	rows := membersByEmail(t, artifact)
	if r := rows["ada@example.com"]; r.Role != "owner" || r.State != "self" {
		t.Errorf("ada's row = %+v, want owner, self", r)
	}
	bob := rows["bob@example.com"]
	if bob.Role != "viewer" || bob.State != e2e.PinUnverified {
		t.Errorf("bob's row = %+v, want viewer, unverified", bob)
	}
	if !strings.Contains(out, showFP(bob.FP)) {
		t.Errorf("cairn share printed %q, want bob's fingerprint %s", out, showFP(bob.FP))
	}
	text, err := runQuiet(t, runMembers, artifact)
	if err != nil || !strings.Contains(text, "viewer  bob@example.com") || !strings.Contains(text, "unverified") {
		t.Errorf("cairn members printed %q, %v", text, err)
	}

	pin := runJSON[map[string]string](t, runPin, "bob@example.com", "--verified", "--json")
	if pin["prior"] != e2e.PinUnverified || pin["state"] != e2e.PinVerified {
		t.Errorf("cairn pin --verified = %v", pin)
	}
	if r := membersByEmail(t, artifact)["bob@example.com"]; r.State != e2e.PinVerified {
		t.Errorf("bob's row after pinning = %+v, want verified", r)
	}

	promoted := runJSON[map[string]any](t, runShare, artifact, "bob@example.com", "--role", "editor", "--json")
	if promoted["promoted"] != true || promoted["prior"] != e2e.PinVerified {
		t.Errorf("promotion = %v", promoted)
	}
}

func TestShareCommandRefusals(t *testing.T) {
	host, m, artifact := shareSetup(t)
	if _, err := runQuiet(t, runShare, artifact); err == nil || !strings.Contains(err.Error(), "usage: cairn share ARTIFACT USER") {
		t.Errorf("share with no user: %v", err)
	}
	if _, err := runQuiet(t, runMembers); err == nil || !strings.Contains(err.Error(), "usage: cairn members ARTIFACT") {
		t.Errorf("members with no artifact: %v", err)
	}
	if _, err := runQuiet(t, runPin); err == nil || !strings.Contains(err.Error(), "usage: cairn pin USER") {
		t.Errorf("pin with no user: %v", err)
	}
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com", "--role", "owner"); err == nil || !strings.Contains(err.Error(), "role must be viewer or editor") {
		t.Errorf("share --role owner: %v", err)
	}
	if _, err := runQuiet(t, runShare, artifact, "nobody@example.com"); !errors.Is(err, client.ErrUnknownUser) {
		t.Errorf("share with an unknown user: %v, want ErrUnknownUser", err)
	}

	// Bob resets without his recovery code, so his keys change.
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	pinned := membersByEmail(t, artifact)["bob@example.com"].FP
	if err := client.New(host, "").Forgot("bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.New(host, "").ResetNew(verifyLink(t, m, "bob@example.com"), "a brand new password"); err != nil {
		t.Fatal(err)
	}
	if r := membersByEmail(t, artifact)["bob@example.com"]; r.State != e2e.PinChanged {
		t.Errorf("bob's row after his reset = %+v, want changed", r)
	}
	_, err := runQuiet(t, runShare, artifact, "bob@example.com", "--role", "editor")
	var changed *client.KeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("share with a changed key: %v, want a KeyChangedError", err)
	}
	for _, want := range []string{showFP(pinned), showFP(changed.CurrentFP), "reset at", "--accept-new-key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err, want)
		}
	}
	res := runJSON[map[string]any](t, runShare, artifact, "bob@example.com", "--role", "editor", "--accept-new-key", "--json")
	if res["prior"] != e2e.PinChanged || res["fp"] != changed.CurrentFP {
		t.Errorf("share --accept-new-key = %v", res)
	}
}

// resetBob resets bob's account without his recovery code, so his keys change.
func resetBob(t *testing.T, host string, m *mail.Capture) {
	t.Helper()
	if err := client.New(host, "").Forgot("bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.New(host, "").ResetNew(verifyLink(t, m, "bob@example.com"), "a brand new password"); err != nil {
		t.Fatal(err)
	}
}

func TestPinCommand(t *testing.T) {
	host, m, artifact := shareSetup(t)
	if _, err := runQuiet(t, runPin, "nobody@example.com"); !errors.Is(err, client.ErrUnknownUser) {
		t.Errorf("pin an unknown user: %v, want ErrUnknownUser", err)
	}
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if pin := runJSON[map[string]string](t, runPin, "bob@example.com", "--verified", "--json"); pin["state"] != e2e.PinVerified {
		t.Fatalf("pin --verified = %v", pin)
	}
	// Pinning again without --verified must not take the verification back.
	again := runJSON[map[string]string](t, runPin, "bob@example.com", "--json")
	if again["prior"] != e2e.PinVerified || again["state"] != e2e.PinVerified {
		t.Errorf("pin without --verified = %v, want verified kept", again)
	}
	if r := membersByEmail(t, artifact)["bob@example.com"]; r.State != e2e.PinVerified {
		t.Errorf("bob's row = %+v, want verified", r)
	}

	resetBob(t, host, m)
	_, err := runQuiet(t, runPin, "bob@example.com")
	var changed *client.KeyChangedError
	if !errors.As(err, &changed) || !strings.Contains(err.Error(), "--accept-new-key") {
		t.Fatalf("pin a changed key: %v, want a KeyChangedError naming --accept-new-key", err)
	}
	if r := membersByEmail(t, artifact)["bob@example.com"]; r.State != e2e.PinChanged {
		t.Errorf("bob's row after the refusal = %+v, want still changed", r)
	}
	res := runJSON[map[string]string](t, runPin, "bob@example.com", "--verified", "--accept-new-key", "--json")
	if res["prior"] != e2e.PinChanged || res["state"] != e2e.PinVerified || res["fp"] != changed.CurrentFP {
		t.Errorf("pin --verified --accept-new-key = %v", res)
	}
	if r := membersByEmail(t, artifact)["bob@example.com"]; r.State != e2e.PinVerified || r.FP == "" {
		t.Errorf("bob's row after accepting = %+v, want verified", r)
	}
}

func TestShareAlreadyAMemberAndNotOwner(t *testing.T) {
	host, _, artifact := shareSetup(t)
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	out, err := runQuiet(t, runShare, artifact, "bob@example.com")
	if err != nil || !strings.Contains(out, "already a viewer of shared; nothing changed") {
		t.Errorf("sharing again printed %q, %v, want %q", out, err, "already a viewer of shared; nothing changed")
	}
	if res := runJSON[map[string]any](t, runShare, artifact, "bob@example.com", "--json"); res["unchanged"] != true {
		t.Errorf("sharing again --json = %v, want unchanged", res)
	}

	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "bob.json"))
	cliLogin(t, host, "bob@example.com", sharePassword)
	if _, err := runQuiet(t, runShare, artifact, "ada@example.com"); !errors.Is(err, client.ErrNotOwner) {
		t.Errorf("share by a member who is not the owner: %v, want ErrNotOwner", err)
	}
}

// TestMembersListsAMemberMissingFromTheDirectory drops bob from the
// directory the server lists: his row stays, with no email and state "-".
func TestMembersListsAMemberMissingFromTheDirectory(t *testing.T) {
	host, _, artifact := shareSetup(t)
	if _, err := runQuiet(t, runShare, artifact, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		if resp.Request.URL.Path != "/api/users" {
			return nil
		}
		var users []map[string]any
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err := json.Unmarshal(data, &users); err != nil {
			return err
		}
		kept := users[:0]
		for _, u := range users {
			if u["email"] != "bob@example.com" {
				kept = append(kept, u)
			}
		}
		data, _ = json.Marshal(kept)
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return nil
	}
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	cliLogin(t, ts.URL, "ada@example.com", sharePassword)

	var bob memberRow
	for _, r := range runJSON[struct {
		Members []memberRow `json:"members"`
	}](t, runMembers, artifact, "--json").Members {
		if r.Role == "viewer" {
			bob = r
		}
	}
	if bob.User == "" || bob.Email != "" || bob.State != "-" {
		t.Errorf("bob's row = %+v, want a viewer with no email and state -", bob)
	}
	text, err := runQuiet(t, runMembers, artifact)
	if err != nil || !strings.Contains(text, "viewer  "+bob.User) {
		t.Errorf("cairn members printed %q, %v, want bob listed by id", text, err)
	}
}

// TestAPIClientFromEnvironmentKeepsAnchorsInTheConfig logs in through the
// environment only, with CAIRN_CONFIG at a file that holds no login: the
// anchor lands in that file.
func TestAPIClientFromEnvironmentKeepsAnchorsInTheConfig(t *testing.T) {
	host, _, artifact := shareSetup(t)
	login := loadConfig()
	path := filepath.Join(t.TempDir(), "agent.json")
	t.Setenv("CAIRN_CONFIG", path)
	t.Setenv("CAIRN_HOST", host)
	t.Setenv("CAIRN_API_KEY", login.APIKey)

	if out := runJSON[map[string]any](t, runMembers, artifact, "--json"); out["artifact"] != artifact {
		t.Fatalf("members through the environment = %v", out)
	}
	f, err := readConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if f.cliConfig != (cliConfig{}) {
		t.Errorf("login in the agent's config = %+v, want none written", f.cliConfig)
	}
	if len(f.Anchors) != 1 {
		t.Fatalf("anchors = %v, want one", f.Anchors)
	}
	for key, a := range f.Anchors {
		if !strings.HasPrefix(key, host+" ") || a.Rev < 1 {
			t.Errorf("anchor %q = %+v, want one for %s at rev 1 or more", key, a, host)
		}
	}
}

// TestRefusedKeyringTellsTheUserHowToRecover serves each keyring command a
// wiped keyring and checks the error names the cause and the anchors entry
// to remove, with the config file's real path.
func TestRefusedKeyringTellsTheUserHowToRecover(t *testing.T) {
	host, _, artifact := shareSetup(t)
	var override atomic.Pointer[string]
	proxy := keyringProxy(t, host, &override)
	cliLogin(t, proxy, "ada@example.com", sharePassword)
	runJSON[map[string]any](t, runMembers, artifact, "--json") // records the anchor
	c, err := apiClient()
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	path, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	wiped := `{"rev":0,"keyring":""}`
	override.Store(&wiped)

	key := proxy + " " + k.UserID + " " + k.FP
	for name, run := range map[string]func() error{
		"pin":     func() error { _, err := runQuiet(t, runPin, "bob@example.com"); return err },
		"members": func() error { _, err := runQuiet(t, runMembers, artifact); return err },
		"share":   func() error { _, err := runQuiet(t, runShare, artifact, "bob@example.com"); return err },
	} {
		err := run()
		if !errors.Is(err, e2e.ErrKeyringRollback) {
			t.Errorf("%s: %v, want ErrKeyringRollback kept in the chain", name, err)
			continue
		}
		for _, want := range []string{
			"older or altered keyring", "restore from backup", "tampering", "confirm with your admin",
			`remove the "anchors" entry "` + key + `" from ` + path,
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: message %q lacks %q", name, err, want)
			}
		}
	}
	// A failure that is not a refusal gets no recovery advice.
	override.Store(nil)
	if _, err := runQuiet(t, runPin, "nobody@example.com"); err == nil || strings.Contains(err.Error(), "anchors") {
		t.Errorf("pin an unknown user: %v, want an error with no anchor advice", err)
	}
}
