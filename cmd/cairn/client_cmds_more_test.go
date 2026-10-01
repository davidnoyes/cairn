package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/aloisdeniel/cairn/internal/versiondb"
)

// pushedSite logs in, creates an artifact called "site" and pushes one
// version to it.
func pushedSite(t *testing.T) (c *client.Client, a store.Artifact, v store.Version) {
	t.Helper()
	c = loggedIn(t)
	type pushed struct {
		Artifact store.Artifact `json:"artifact"`
		Version  store.Version  `json:"version"`
	}
	p := runJSON[pushed](t, runPush, siteDir(t), "--artifact", "site", "--create", "--name", "v1", "--changelog", "first", "--json")
	return c, p.Artifact, p.Version
}

func TestArtifactDispatchErrors(t *testing.T) {
	if err := runArtifact(nil); err == nil || !strings.Contains(err.Error(), "usage: cairn artifact <list|create|show|update|delete>") {
		t.Errorf("artifact with no subcommand: %v", err)
	}
	if err := runArtifact([]string{"frobnicate"}); err == nil || !strings.Contains(err.Error(), `unknown artifact subcommand "frobnicate"`) {
		t.Errorf("artifact frobnicate: %v", err)
	}
	if err := runFiles(nil); err == nil || !strings.Contains(err.Error(), "usage: cairn files <list|put|get|delete>") {
		t.Errorf("files with no subcommand: %v", err)
	}
	if err := runFiles([]string{"frobnicate"}); err == nil || !strings.Contains(err.Error(), `unknown files subcommand "frobnicate"`) {
		t.Errorf("files frobnicate: %v", err)
	}
}

func TestArtifactListTextAndJSON(t *testing.T) {
	loggedIn(t)
	out, err := runQuiet(t, runArtifact, "list")
	if err != nil || out != "" {
		t.Errorf("list with no artifacts = %q, %v", out, err)
	}
	a := runJSON[store.Artifact](t, runArtifact, "create", "notes", "--description", "my notes", "--json")
	out, err = runQuiet(t, runArtifact, "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, a.ID+"  notes ") || !strings.Contains(out, "  private  my notes\n") {
		t.Errorf("list text = %q", out)
	}
	list := runJSON[[]store.Artifact](t, runArtifact, "list", "--json")
	if len(list) != 1 || list[0].ID != a.ID || list[0].Name != "notes" {
		t.Errorf("list json = %+v", list)
	}
}

func TestArtifactShow(t *testing.T) {
	_, a, v := pushedSite(t)
	if _, err := runQuiet(t, runArtifact, "update", a.ID, "--description", "the site"); err != nil {
		t.Fatal(err)
	}
	out, err := runQuiet(t, runArtifact, "show", "site")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"site (" + a.ID + ", private)\nthe site\n", "versions (1):\n", "#1  " + v.ID, "v1", "first"} {
		if !strings.Contains(out, want) {
			t.Errorf("show output missing %q:\n%s", want, out)
		}
	}
	got := runJSON[struct {
		Artifact store.Artifact  `json:"artifact"`
		Versions []store.Version `json:"versions"`
	}](t, runArtifact, "show", a.ID, "--json")
	if got.Artifact.ID != a.ID || len(got.Versions) != 1 || got.Versions[0].ID != v.ID {
		t.Errorf("show json = %+v", got)
	}
	if err := runArtifact([]string{"show"}); err == nil || !strings.Contains(err.Error(), "usage: cairn artifact show") {
		t.Errorf("show with no target: %v", err)
	}
	if err := runArtifact([]string{"show", "ghost"}); err == nil || !strings.Contains(err.Error(), `no artifact with id or name "ghost"`) {
		t.Errorf("show of a missing artifact: %v", err)
	}
}

func TestArtifactDelete(t *testing.T) {
	c, a, _ := pushedSite(t)
	if err := runArtifact([]string{"delete"}); err == nil || !strings.Contains(err.Error(), "usage: cairn artifact delete") {
		t.Errorf("delete with no target: %v", err)
	}
	if err := runArtifact([]string{"delete", "ghost"}); err == nil || !strings.Contains(err.Error(), `no artifact with id or name "ghost"`) {
		t.Errorf("delete of a missing artifact: %v", err)
	}
	out, err := runQuiet(t, runArtifact, "delete", "site")
	if err != nil || out != "deleted artifact site ("+a.ID+")\n" {
		t.Errorf("delete output = %q, %v", out, err)
	}
	left, err := c.ListArtifacts()
	if err != nil || len(left) != 0 {
		t.Errorf("artifacts after delete = %+v, %v", left, err)
	}
}

func TestPushWithoutCreateNamesTheFlag(t *testing.T) {
	loggedIn(t)
	err := runPush([]string{siteDir(t), "--artifact", "ghost"})
	if err == nil || !strings.Contains(err.Error(), `no artifact with id or name "ghost"`) || !strings.Contains(err.Error(), "use --create to create it") {
		t.Errorf("push to a missing artifact: %v", err)
	}
}

func TestPushRecordsNameChangelogAndURL(t *testing.T) {
	c, a, v := pushedSite(t)
	if v.Name != "v1" || v.Changelog != "first" || v.Seq != 1 {
		t.Errorf("version = %+v", v)
	}
	url := runJSON[struct {
		URL string `json:"url"`
	}](t, runPush, siteDir(t), "--artifact", a.ID, "--json")
	if !strings.HasPrefix(url.URL, c.Host+"/artifacts/"+a.ID+"/") || !strings.HasSuffix(url.URL, "/") {
		t.Errorf("push url = %q", url.URL)
	}
}

func TestDBQuery(t *testing.T) {
	_, a, v := pushedSite(t)
	if _, err := runQuiet(t, runDB, "query", "--artifact", "site", "CREATE TABLE t (id INTEGER, name TEXT)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	out, err := runQuiet(t, runDB, "query", "--artifact", "site", "--params", `[1, "ada"]`, "INSERT INTO t VALUES (?, ?)")
	if err != nil || out != "1 row(s) affected\n" {
		t.Errorf("insert output = %q, %v", out, err)
	}
	if _, err := runQuiet(t, runDB, "query", "--artifact", a.ID, "--version", v.ID, "INSERT INTO t VALUES (2, NULL)"); err != nil {
		t.Fatal(err)
	}
	out, err = runQuiet(t, runDB, "query", "--artifact", "site", "SELECT id, name FROM t ORDER BY id")
	if err != nil || out != "id\tname\n1\tada\n2\tNULL\n" {
		t.Errorf("select output = %q, %v", out, err)
	}
	res := runJSON[versiondb.Result](t, runDB, "query", "--artifact", "site", "--json", "SELECT count(*) AS n FROM t")
	if len(res.Rows) != 1 || res.Columns[0] != "n" || res.Rows[0][0] != float64(2) {
		t.Errorf("json result = %+v", res)
	}
}

func TestDBQueryRefusals(t *testing.T) {
	loggedIn(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", nil, "usage: cairn db query"},
		{"wrong subcommand", []string{"exec"}, "usage: cairn db query"},
		{"no sql", []string{"query", "--artifact", "x"}, "usage: cairn db query"},
		{"no artifact", []string{"query", "SELECT 1"}, "usage: cairn db query"},
		{"bad params", []string{"query", "--artifact", "x", "--params", "{", "SELECT 1"}, "--params must be a JSON array"},
		{"missing artifact", []string{"query", "--artifact", "ghost", "SELECT 1"}, `no artifact with id or name "ghost"`},
	} {
		if err := runDB(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	runJSON[store.Artifact](t, runArtifact, "create", "bare", "--json")
	if err := runDB([]string{"query", "--artifact", "bare", "SELECT 1"}); err == nil || !strings.Contains(err.Error(), "artifact has no versions yet") {
		t.Errorf("query of an artifact with no versions: %v", err)
	}
}

func TestFilesRoundTrip(t *testing.T) {
	_, _, _ = pushedSite(t)
	local := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(local, []byte("remember the milk"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runQuiet(t, runFiles, "put", local, "--artifact", "site")
	if err != nil || out != "uploaded notes.txt (17 bytes)\n" {
		t.Errorf("put output = %q, %v", out, err)
	}
	info := runJSON[client.FileInfo](t, runFiles, "put", local, "--artifact", "site", "--path", "docs/n.txt", "--json")
	if info.Path != "docs/n.txt" || info.Size != 17 {
		t.Errorf("put json = %+v", info)
	}

	out, err = runQuiet(t, runFiles, "list", "--artifact", "site")
	if err != nil || !strings.Contains(out, "notes.txt\n") || !strings.Contains(out, "docs/n.txt\n") || !strings.Contains(out, "        17  ") {
		t.Errorf("list output = %q, %v", out, err)
	}
	files := runJSON[[]client.FileInfo](t, runFiles, "list", "--artifact", "site", "--json")
	if len(files) != 2 {
		t.Errorf("list json = %+v", files)
	}

	out, err = runQuiet(t, runFiles, "get", "docs/n.txt", "--artifact", "site")
	if err != nil || out != "remember the milk" {
		t.Errorf("get to stdout = %q, %v", out, err)
	}
	dst := filepath.Join(t.TempDir(), "got.txt")
	if _, err := runQuiet(t, runFiles, "get", "notes.txt", "--artifact", "site", "--out", dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "remember the milk" {
		t.Errorf("get --out wrote %q, %v", b, err)
	}

	out, err = runQuiet(t, runFiles, "delete", "docs/n.txt", "--artifact", "site")
	if err != nil || out != "deleted docs/n.txt\n" {
		t.Errorf("delete output = %q, %v", out, err)
	}
	files = runJSON[[]client.FileInfo](t, runFiles, "list", "--artifact", "site", "--json")
	if len(files) != 1 || files[0].Path != "notes.txt" {
		t.Errorf("files after delete = %+v", files)
	}
	if err := runFiles([]string{"get", "docs/n.txt", "--artifact", "site"}); err == nil {
		t.Error("get of a deleted file succeeded")
	}
}

func TestFilesRefusals(t *testing.T) {
	loggedIn(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"list without artifact", []string{"list"}, "--artifact is required"},
		{"put without file", []string{"put", "--artifact", "x"}, "usage: cairn files put"},
		{"get without name", []string{"get", "--artifact", "x"}, "usage: cairn files get"},
		{"delete without name", []string{"delete", "--artifact", "x"}, "usage: cairn files delete"},
		{"missing artifact", []string{"list", "--artifact", "ghost"}, `no artifact with id or name "ghost"`},
		{"put of a missing file", []string{"put", filepath.Join(t.TempDir(), "nope"), "--artifact", "x"}, "no such file or directory"},
	} {
		if err := runFiles(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	runJSON[store.Artifact](t, runArtifact, "create", "bare", "--json")
	if err := runFiles([]string{"list", "--artifact", "bare"}); err == nil || !strings.Contains(err.Error(), "artifact has no versions yet") {
		t.Errorf("list of an artifact with no versions: %v", err)
	}
}

func TestOpenPrintsTheURL(t *testing.T) {
	c, a, v := pushedSite(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"site"}, c.Host + "/artifacts/" + a.ID},
		{[]string{"site", "--version", v.ID}, c.Host + "/artifacts/" + a.ID + "/" + v.ID + "/"},
		{[]string{a.ID, "--shared"}, c.Host + "/shared/" + a.ID},
		{[]string{"site", "--shared", "--version", v.ID}, c.Host + "/shared/" + a.ID + "/" + v.ID},
	} {
		out, err := runQuiet(t, runOpen, tc.args...)
		if err != nil || out != tc.want+"\n" {
			t.Errorf("open %v = %q, %v; want %q", tc.args, out, err, tc.want)
		}
	}
	if err := runOpen(nil); err == nil || !strings.Contains(err.Error(), "usage: cairn open") {
		t.Errorf("open with no target: %v", err)
	}
	if err := runOpen([]string{"ghost"}); err == nil || !strings.Contains(err.Error(), `no artifact with id or name "ghost"`) {
		t.Errorf("open of a missing artifact: %v", err)
	}
}

func TestWhoamiNeedsALogin(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := runWhoami(nil); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("whoami with no login: %v", err)
	}
}

func TestUsageTextListsEveryDispatchedCommand(t *testing.T) {
	for _, cmd := range []string{"serve", "backup", "signup", "login", "logout", "whoami", "keys", "artifact", "push", "db", "files", "open", "members", "share", "pin"} {
		if !strings.Contains(usage, "  cairn "+cmd+" ") {
			t.Errorf("usage does not list %q", cmd)
		}
	}
}
