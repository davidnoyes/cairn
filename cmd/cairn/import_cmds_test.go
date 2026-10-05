package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/store"
	_ "modernc.org/sqlite"
)

// The fake backups here are laid out as `cairn backup` on a server from before
// encryption wrote them: a cairn.db with the old schema, and content, dbs, and
// files trees beside it.

const oldSchema = `
CREATE TABLE artifacts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    public      INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE artifact_resources (
    id          TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL
);
CREATE TABLE versions (
    id          TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    name        TEXT NOT NULL DEFAULT '',
    changelog   TEXT NOT NULL DEFAULT '',
    seq         INTEGER NOT NULL,
    content_dir TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX versions_artifact_seq ON versions(artifact_id, seq);
`

type fakeVersion struct {
	id, name, changelog string
	content             map[string]string // slash path -> content
	dbRows              []string          // rows of a table t; nil for no database
	stored              map[string]string // slash path -> content
}

type fakeArtifact struct {
	id, name, description string
	public                bool
	created               string
	resources             map[string]string
	versions              []fakeVersion // in ascending seq
}

// writeFile writes content at the slash path under root.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeOldBackup builds a backup of arts in a temp dir and returns it.
func writeOldBackup(t *testing.T, arts []fakeArtifact) string {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	// The old server ran in WAL mode, and the header says so in its backup:
	// opening it without immutable would create a -wal and -shm file.
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	for _, a := range arts {
		public := 0
		if a.public {
			public = 1
		}
		if _, err := db.Exec(`INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?)`, a.id, a.name, a.description, public, a.created, a.created); err != nil {
			t.Fatal(err)
		}
		for typ, val := range a.resources {
			if _, err := db.Exec(`INSERT INTO artifact_resources VALUES (?, ?, ?, ?)`, a.id+typ, a.id, typ, val); err != nil {
				t.Fatal(err)
			}
		}
		for i, v := range a.versions {
			contentDir := "cd-" + v.id
			if _, err := db.Exec(`INSERT INTO versions VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, v.id, a.id, v.name, v.changelog, i+1, contentDir, a.created, a.created); err != nil {
				t.Fatal(err)
			}
			for rel, c := range v.content {
				writeFile(t, dir, "content/"+a.id+"/"+contentDir+"/"+rel, c)
			}
			if v.dbRows != nil {
				vdb, err := sql.Open("sqlite", filepath.Join(dir, "scratch.db"))
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range append([]string{`CREATE TABLE t (s TEXT)`}, v.dbRows...) {
					if _, err := vdb.Exec(s); err != nil {
						t.Fatal(err)
					}
				}
				vdb.Close()
				data, err := os.ReadFile(filepath.Join(dir, "scratch.db"))
				if err != nil {
					t.Fatal(err)
				}
				os.Remove(filepath.Join(dir, "scratch.db"))
				writeFile(t, dir, "dbs/"+a.id+"/"+v.id+".db", string(data))
			}
			for rel, c := range v.stored {
				writeFile(t, dir, "files/"+a.id+"/"+v.id+"/"+rel, c)
			}
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// hashTree maps the slash path of every file under dir to its SHA-256, and of
// every symbolic link to its target.
func hashTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = "-> " + target
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		rel, _ := filepath.Rel(dir, p)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// sampleBackup is two artifacts, the first public, with every kind of part:
// versions with neither a database nor stored files, with both, with stored
// files alone, and with a database alone.
func sampleBackup(t *testing.T) (string, []fakeArtifact) {
	arts := []fakeArtifact{
		{
			id: "old-a", name: "Guestbook", description: "marker-desc-A", public: true, created: "2026-01-01T00:00:00Z",
			resources: map[string]string{"claude-session": "old-sess-1"},
			versions: []fakeVersion{
				{id: "va1", name: "first", changelog: "marker-log-1", content: map[string]string{"index.html": "<h1>one</h1>"}},
				{
					id: "va2", name: "second", changelog: "marker-log-2",
					content: map[string]string{"index.html": "<h1>two</h1>", "assets/app.js": "console.log(2)"},
					dbRows:  []string{`INSERT INTO t VALUES ('marker-row-1')`, `INSERT INTO t VALUES ('marker-row-2')`},
					stored:  map[string]string{"notes.txt": "marker-file", "dir/deep/blob.bin": "\x00\x01\x02"},
				},
			},
		},
		{
			id: "old-b", name: "Poll", description: "", created: "2026-01-02T00:00:00Z",
			versions: []fakeVersion{
				{id: "vb1", content: map[string]string{"index.html": "<h1>poll</h1>"}, stored: map[string]string{"only.txt": "marker-files-only"}},
				{id: "vb2", content: map[string]string{"index.html": "<h1>poll 2</h1>"}, dbRows: []string{`INSERT INTO t VALUES ('marker-db-only')`}},
			},
		},
	}
	return writeOldBackup(t, arts), arts
}

// editOld runs stmts on the cairn.db of the backup in dir.
func editOld(t *testing.T, dir string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
}

// replaceWithLink moves the file or directory at the slash path rel under dir
// out of the backup, and leaves a symbolic link to it in its place.
func replaceWithLink(t *testing.T, dir, rel string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	outside := filepath.Join(t.TempDir(), filepath.Base(p))
	if err := os.Rename(p, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}
}

func listArtifactsByName(t *testing.T, c *client.Client) map[string]*client.Artifact {
	t.Helper()
	list, err := c.ListArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*client.Artifact{}
	for _, a := range list {
		out[a.Name] = a
	}
	return out
}

func TestImportCopiesEverything(t *testing.T) {
	c := loggedIn(t)
	dir, arts := sampleBackup(t)
	before := hashTree(t, dir)

	var out, progress bytes.Buffer
	done, err := importBackup(context.Background(), c, dir, &out, &progress)
	if err != nil {
		t.Fatalf("importBackup: %v", err)
	}
	if len(done) != 2 || done[0].OldID != "old-a" || done[1].OldID != "old-b" || !done[0].Public || done[1].Public {
		t.Fatalf("imported = %+v, want old-a then old-b, only the first public", done)
	}
	wantOut := "imported old-a as " + done[0].NewID + ": Guestbook (2 versions)\nimported old-b as " + done[1].NewID + ": Poll (2 versions)\n"
	if out.String() != wantOut {
		t.Errorf("stdout = %q, want %q", out.String(), wantOut)
	}
	if !strings.Contains(progress.String(), `importing "Guestbook": version 2 of 2`) || !strings.Contains(progress.String(), `importing "Poll": version 2 of 2`) {
		t.Errorf("progress = %q", progress.String())
	}

	byName := listArtifactsByName(t, c)
	if len(byName) != 2 {
		t.Fatalf("the new server holds %d artifacts, want 2", len(byName))
	}
	for i, a := range arts {
		got := byName[a.name]
		if got == nil || got.ID != done[i].NewID || got.Description != a.description || got.Public {
			t.Fatalf("artifact %s = %+v, want it private and described %q", a.name, got, a.description)
		}
		vs, err := c.ListVersions(got.ID) // newest first
		if err != nil || len(vs) != len(a.versions) {
			t.Fatalf("ListVersions(%s) = %d, %v", a.name, len(vs), err)
		}
		for j, ov := range a.versions {
			nv := vs[len(vs)-1-j]
			if nv.Name != ov.name || nv.Changelog != ov.changelog || nv.Seq != j+1 {
				t.Errorf("%s version %d = %q %q seq %d, want %q %q", a.name, j+1, nv.Name, nv.Changelog, nv.Seq, ov.name, ov.changelog)
			}
			files, err := c.VersionFiles(got.ID, nv.ID)
			if err != nil || len(files) != len(ov.content) {
				t.Fatalf("VersionFiles = %d files, %v, want %d", len(files), err, len(ov.content))
			}
			for rel, want := range ov.content {
				if string(files[rel]) != want {
					t.Errorf("%s %s = %q, want %q", a.name, rel, files[rel], want)
				}
			}
			d, err := c.OpenData(got.ID, nv.ID, false)
			if err != nil {
				t.Fatal(err)
			}
			plain, rev, err := d.Latest()
			if ov.dbRows == nil {
				if err != client.ErrNoDatabase {
					t.Errorf("a version with no database: Latest = %v", err)
				}
			} else {
				src, rerr := os.ReadFile(filepath.Join(dir, "dbs", a.id, ov.id+".db"))
				if rerr != nil || err != nil || rev != 1 || !bytes.Equal(plain, src) {
					t.Errorf("database of %s: revision %d, %v, equal=%v", ov.id, rev, err, bytes.Equal(plain, src))
				}
			}
			listed, err := d.ListFiles()
			if err != nil || len(listed) != len(ov.stored) {
				t.Fatalf("ListFiles = %+v, %v, want %d", listed, err, len(ov.stored))
			}
			for rel, want := range ov.stored {
				if got, err := d.GetFile(rel); err != nil || string(got) != want {
					t.Errorf("stored file %s = %q, %v, want %q", rel, got, err, want)
				}
			}
		}
	}
	if r, err := c.ResolveArtifact("old-sess-1"); err != nil || r.ID != done[0].NewID {
		t.Errorf("ResolveArtifact(old-sess-1) = %v, %v, want %s", r, err, done[0].NewID)
	}
	if !reflect.DeepEqual(hashTree(t, dir), before) {
		t.Error("the import changed the backup")
	}
}

func TestImportCommandListsPublicArtifacts(t *testing.T) {
	c := loggedIn(t)
	dir, _ := sampleBackup(t)
	done := captureStdout(t)
	err := runImport([]string{dir})
	out := done()
	if err != nil {
		t.Fatal(err)
	}
	byName := listArtifactsByName(t, c)
	if !strings.Contains(out, "These artifacts were public on the old server") ||
		!strings.Contains(out, byName["Guestbook"].ID+"  Guestbook\n") ||
		strings.Contains(out, byName["Poll"].ID+"  Poll\n") ||
		!strings.Contains(out, "cairn public <id> on") {
		t.Errorf("stdout = %q, want only Guestbook in the public list", out)
	}
}

func TestImportCommandJSON(t *testing.T) {
	c := loggedIn(t)
	dir, _ := sampleBackup(t)
	got := runJSON[struct {
		Artifacts []importedArtifact `json:"artifacts"`
	}](t, runImport, "--json", dir)
	byName := listArtifactsByName(t, c)
	want := []importedArtifact{
		{OldID: "old-a", NewID: byName["Guestbook"].ID, Name: "Guestbook", Versions: 2, Public: true},
		{OldID: "old-b", NewID: byName["Poll"].ID, Name: "Poll", Versions: 2},
	}
	if !reflect.DeepEqual(got.Artifacts, want) {
		t.Errorf("--json = %+v, want %+v", got.Artifacts, want)
	}
	raw, _ := json.Marshal(want[0])
	for _, k := range []string{`"oldId"`, `"newId"`, `"name"`, `"versions"`, `"public"`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("JSON key %s missing from %s", k, raw)
		}
	}
}

func TestImportNeedsOneArgumentAndALogin(t *testing.T) {
	loggedIn(t)
	if err := runImport(nil); err == nil || !strings.Contains(err.Error(), "usage: cairn import") {
		t.Errorf("no argument: %v", err)
	}
	t.Setenv("CAIRN_HOST", "")
	t.Setenv("CAIRN_API_KEY", "")
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := runImport([]string{t.TempDir()}); err == nil || !strings.Contains(err.Error(), "not logged in") {
		t.Errorf("not signed in: %v", err)
	}
}

func TestImportRefusesABadBackupBeforeUploading(t *testing.T) {
	good := func(t *testing.T) string {
		dir, _ := sampleBackup(t)
		return dir
	}
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) string
		want  string
	}{
		{"no cairn.db", func(t *testing.T) string {
			dir := good(t)
			os.Remove(filepath.Join(dir, "cairn.db"))
			return dir
		}, "no cairn.db"},
		{"a WAL file beside cairn.db", func(t *testing.T) string {
			dir := good(t)
			writeFile(t, dir, "cairn.db-wal", "x")
			return dir
		}, "live data directory"},
		{"a WAL file beside a version database", func(t *testing.T) string {
			dir := good(t)
			writeFile(t, dir, "dbs/old-a/va2.db-wal", "x")
			return dir
		}, "live data directory"},
		{"an artifact ID that climbs out", func(t *testing.T) string {
			dir := good(t)
			editOld(t, dir, `UPDATE artifacts SET id = '../escape' WHERE id = 'old-b'`, `UPDATE versions SET artifact_id = '../escape' WHERE artifact_id = 'old-b'`)
			return dir
		}, `artifact ID "../escape" is not a plain name`},
		{"an artifact ID with a separator", func(t *testing.T) string {
			dir := good(t)
			editOld(t, dir, `UPDATE artifacts SET id = 'old-b/cd-vb1' WHERE id = 'old-b'`)
			return dir
		}, "is not a plain name"},
		{"a version ID that climbs out", func(t *testing.T) string {
			dir := good(t)
			editOld(t, dir, `UPDATE versions SET id = '../../escape' WHERE id = 'vb1'`)
			return dir
		}, "a directory name in cairn.db is not a plain name"},
		{"a content dir that climbs out", func(t *testing.T) string {
			dir := good(t)
			editOld(t, dir, `UPDATE versions SET content_dir = '../old-a/cd-va1' WHERE id = 'vb1'`)
			return dir
		}, "a directory name in cairn.db is not a plain name"},
		{"an empty content dir", func(t *testing.T) string {
			dir := good(t)
			editOld(t, dir, `UPDATE versions SET content_dir = '' WHERE id = 'vb1'`)
			return dir
		}, "a directory name in cairn.db is not a plain name"},
		{"a content dir of dot", func(t *testing.T) string {
			dir := good(t)
			editOld(t, dir, `UPDATE versions SET content_dir = '.' WHERE id = 'vb1'`)
			return dir
		}, "a directory name in cairn.db is not a plain name"},
		{"a content dir of dot-dot", func(t *testing.T) string {
			dir := good(t)
			editOld(t, dir, `UPDATE versions SET content_dir = '..' WHERE id = 'vb1'`)
			return dir
		}, "a directory name in cairn.db is not a plain name"},
		{"a symbolic link for a database", func(t *testing.T) string {
			dir := good(t)
			replaceWithLink(t, dir, "dbs/old-a/va2.db")
			return dir
		}, "va2.db is a symbolic link"},
		{"a directory for a database", func(t *testing.T) string {
			dir := good(t)
			os.Remove(filepath.Join(dir, "dbs", "old-a", "va2.db"))
			writeFile(t, dir, "dbs/old-a/va2.db/inside", "x")
			return dir
		}, "its database is not a regular file"},
		{"a symbolic link for an artifact's databases", func(t *testing.T) string {
			dir := good(t)
			replaceWithLink(t, dir, "dbs/old-a")
			return dir
		}, "old-a is a symbolic link"},
		{"a symbolic link for an artifact's content", func(t *testing.T) string {
			dir := good(t)
			replaceWithLink(t, dir, "content/old-b")
			return dir
		}, "old-b is a symbolic link"},
		{"a symbolic link for an artifact's stored files", func(t *testing.T) string {
			dir := good(t)
			replaceWithLink(t, dir, "files/old-b")
			return dir
		}, "old-b is a symbolic link"},
		{"a symbolic link among the stored files", func(t *testing.T) string {
			dir := good(t)
			replaceWithLink(t, dir, "files/old-b/vb1/only.txt")
			return dir
		}, "only.txt\" is not a regular file"},
		{"the new schema", func(t *testing.T) string {
			dir := t.TempDir()
			s, err := store.Open(filepath.Join(dir, "cairn.db"))
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			os.Remove(filepath.Join(dir, "cairn.db-wal"))
			os.Remove(filepath.Join(dir, "cairn.db-shm"))
			return dir
		}, "not a backup of a Cairn server from before encryption"},
		{"not a database", func(t *testing.T) string {
			dir := t.TempDir()
			writeFile(t, dir, "cairn.db", "this is not SQLite, and is long enough to read as a bad header")
			return dir
		}, "Cairn database"},
		{"a version with no index.html", func(t *testing.T) string {
			dir := good(t)
			os.Remove(filepath.Join(dir, "content", "old-b", "cd-vb1", "index.html"))
			writeFile(t, dir, "content/old-b/cd-vb1/other.html", "x")
			return dir
		}, "index.html"},
		{"a missing content dir", func(t *testing.T) string {
			dir := good(t)
			os.RemoveAll(filepath.Join(dir, "content", "old-b"))
			return dir
		}, "Poll"},
		{"a stored file path the new server refuses", func(t *testing.T) string {
			dir := good(t)
			writeFile(t, dir, "files/old-b/vb1/back\\slash.txt", "x")
			return dir
		}, "back"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := loggedIn(t)
			dir := tc.build(t)
			before := hashTree(t, dir)
			done, err := importBackup(context.Background(), c, dir, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("importBackup = %v, want an error containing %q", err, tc.want)
			}
			if len(done) != 0 {
				t.Errorf("imported %+v", done)
			}
			if got := listArtifactsByName(t, c); len(got) != 0 {
				t.Errorf("the refused backup left %d artifact(s) on the server", len(got))
			}
			if !reflect.DeepEqual(hashTree(t, dir), before) {
				t.Error("the check changed the backup")
			}
		})
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestImportInterruptDeletesThePartialArtifact(t *testing.T) {
	c := loggedIn(t)
	arts := []fakeArtifact{
		{id: "old-a", name: "first", public: true, created: "2026-01-01T00:00:00Z", versions: []fakeVersion{
			{id: "va1", content: map[string]string{"index.html": "a"}},
		}},
		{id: "old-b", name: "many", created: "2026-01-02T00:00:00Z", versions: []fakeVersion{
			{id: "vb1", content: map[string]string{"index.html": "1"}},
			{id: "vb2", content: map[string]string{"index.html": "2"}},
			{id: "vb3", content: map[string]string{"index.html": "3"}},
		}},
	}
	dir := writeOldBackup(t, arts)
	before := hashTree(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	progress := writerFunc(func(p []byte) (int, error) {
		if strings.Contains(string(p), `"many": version 2 of`) {
			cancel()
		}
		return len(p), nil
	})
	done, err := importBackup(ctx, c, dir, io.Discard, progress)
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("importBackup = %v, want interrupted", err)
	}
	if len(done) != 1 || done[0].OldID != "old-a" {
		t.Fatalf("done = %+v, want only old-a", done)
	}
	// The person may keep what finished, so the list must say what was public:
	// only a run that completes prints the public list.
	for _, want := range []string{"old-a -> " + done[0].NewID + "  first  (public on the old server)", "running the import again imports every artifact again", "artifact delete"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	got := listArtifactsByName(t, c)
	if len(got) != 1 || got["first"] == nil {
		names := []string{}
		for n := range got {
			names = append(names, n)
		}
		t.Errorf("the server holds %v, want only the finished artifact", names)
	}
	if after := hashTree(t, dir); !reflect.DeepEqual(after, before) {
		t.Errorf("the backup changed:\nbefore %v\nafter  %v", before, after)
	}
}

func TestImportDeletesThePartialArtifactOnAFailure(t *testing.T) {
	c := loggedIn(t)
	arts := []fakeArtifact{{id: "old-a", name: "doomed", created: "2026-01-01T00:00:00Z", versions: []fakeVersion{
		{id: "va1", content: map[string]string{"index.html": "1"}},
		{id: "va2", content: map[string]string{"index.html": "2"}},
	}}}
	dir := writeOldBackup(t, arts)
	// The second version's tree turns bad after the check passed.
	hookRoundTrips(c, func(r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/versions") {
			os.Remove(filepath.Join(dir, "content", "old-a", "cd-va2", "index.html"))
		}
	}, nil)
	_, err := importBackup(context.Background(), c, dir, io.Discard, io.Discard)
	if err == nil || strings.Contains(err.Error(), "interrupted") || !strings.Contains(err.Error(), "index.html") {
		t.Fatalf("importBackup = %v, want the push failure", err)
	}
	if got := listArtifactsByName(t, c); len(got) != 0 {
		t.Errorf("the failed import left %d artifact(s)", len(got))
	}
}

// hookRoundTrips makes c call before ahead of each request, and rewrite on the
// body of each successful response, when they are not nil.
func hookRoundTrips(c *client.Client, before func(*http.Request), rewrite func(*http.Request, []byte) []byte) {
	base := http.DefaultTransport
	c.HTTP = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		if before != nil {
			before(r)
		}
		resp, err := base.RoundTrip(r)
		if err != nil || rewrite == nil || resp.StatusCode != http.StatusOK {
			return resp, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		data = rewrite(r, data)
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Del("Content-Length")
		return resp, nil
	})}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestImportReadBackCatchesADifference changes the backup after its parts are
// uploaded and before they are read back, which is the only way a run can see
// the server and the backup disagree: each case must be an error, not a pass.
func TestImportReadBackCatchesADifference(t *testing.T) {
	stored := map[string]string{"a.txt": "stored-a", "b.txt": "stored-b"}
	for _, tc := range []struct {
		name string
		// when says which request is the moment to act: the first one for
		// which it is true after seenPut did.
		seenPut string // a PUT path substring that must have happened first, or ""
		at      func(*http.Request) bool
		act     func(t *testing.T, dir string)
		rewrite func(*http.Request, []byte) []byte
		want    string
	}{
		{
			name: "content differs",
			at:   func(r *http.Request) bool { return r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/manifest") },
			act: func(t *testing.T, dir string) {
				writeFile(t, dir, "content/old-a/cd-va1/index.html", "<h1>changed</h1>")
			},
			want: "content file index.html differs",
		},
		{
			name: "content gained a file",
			at:   func(r *http.Request) bool { return r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/manifest") },
			act: func(t *testing.T, dir string) {
				writeFile(t, dir, "content/old-a/cd-va1/new.html", "new")
			},
			want: "content file new.html differs",
		},
		{
			name: "content lost a file",
			at:   func(r *http.Request) bool { return r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/manifest") },
			act: func(t *testing.T, dir string) {
				os.Remove(filepath.Join(dir, "content", "old-a", "cd-va1", "extra.css"))
			},
			want: "1 content file(s) the backup does not",
		},
		{
			name:    "database differs",
			seenPut: "/db",
			at:      func(r *http.Request) bool { return r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/db") },
			act: func(t *testing.T, dir string) {
				p := filepath.Join(dir, "dbs", "old-a", "va1.db")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, append(data, 0), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "the database differs",
		},
		{
			name:    "a stored file differs",
			seenPut: "/files/",
			at:      func(r *http.Request) bool { return r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/files") },
			act: func(t *testing.T, dir string) {
				writeFile(t, dir, "files/old-a/va1/b.txt", "stored-CHANGED")
			},
			want: "stored file b.txt differs",
		},
		{
			name:    "the server forgets a stored file",
			seenPut: "/files/",
			at:      func(r *http.Request) bool { return false },
			rewrite: func(r *http.Request, data []byte) []byte {
				if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/files") {
					return data
				}
				var items []json.RawMessage
				if err := json.Unmarshal(data, &items); err != nil || len(items) < 2 {
					return data
				}
				out, _ := json.Marshal(items[1:])
				return out
			},
			want: "the server lists stored files",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := loggedIn(t)
			dir := writeOldBackup(t, []fakeArtifact{{id: "old-a", name: "A", created: "2026-01-01T00:00:00Z", versions: []fakeVersion{{
				id:      "va1",
				content: map[string]string{"index.html": "<h1>hi</h1>", "extra.css": "body{}"},
				dbRows:  []string{`INSERT INTO t VALUES ('row')`},
				stored:  stored,
			}}}})
			seen := tc.seenPut == ""
			fired := false
			hookRoundTrips(c, func(r *http.Request) {
				if r.Method == "PUT" && tc.seenPut != "" && strings.Contains(r.URL.Path, tc.seenPut) {
					seen = true
				}
				if seen && !fired && tc.at(r) {
					fired = true
					tc.act(t, dir)
				}
			}, tc.rewrite)
			_, err := importBackup(context.Background(), c, dir, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("importBackup = %v, want an error containing %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "differs") && !strings.Contains(err.Error(), "does not") && !strings.Contains(err.Error(), "lists stored files") {
				t.Errorf("the error does not say it is a comparison failure: %v", err)
			}
			if got := listArtifactsByName(t, c); len(got) != 0 {
				t.Errorf("a failed read-back left %d artifact(s)", len(got))
			}
		})
	}
}

// TestImportReadsABackupItCannotWriteTo imports from a backup made read-only,
// as one on read-only media would be: the metadata database is in WAL mode,
// which SQLite can only read without creating -wal and -shm files when it is
// opened immutable.
func TestImportReadsABackupItCannotWriteTo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	c := loggedIn(t)
	dir, _ := sampleBackup(t)
	var dirs []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			dirs = append(dirs, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	before := hashTree(t, dir)
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i], 0o555); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, d := range dirs {
			os.Chmod(d, 0o755)
		}
	})
	done, err := importBackup(context.Background(), c, dir, io.Discard, io.Discard)
	if err != nil || len(done) != 2 {
		t.Fatalf("importBackup from a read-only backup = %+v, %v", done, err)
	}
	if !reflect.DeepEqual(hashTree(t, dir), before) {
		t.Error("the import changed the backup")
	}
}

// TestImportTakesWALNamesOutsideTheDatabases imports a backup whose content
// and stored files carry names ending in .db-wal: only a WAL file beside a
// database means a live data directory.
func TestImportTakesWALNamesOutsideTheDatabases(t *testing.T) {
	c := loggedIn(t)
	dir, _ := sampleBackup(t)
	writeFile(t, dir, "content/old-b/cd-vb1/notes.db-wal", "content")
	writeFile(t, dir, "files/old-b/vb1/kept.db-wal", "stored")
	done, err := importBackup(context.Background(), c, dir, io.Discard, io.Discard)
	if err != nil || len(done) != 2 {
		t.Fatalf("importBackup = %+v, %v", done, err)
	}
	vs, err := c.ListVersions(done[1].NewID) // newest first
	if err != nil {
		t.Fatal(err)
	}
	files, err := c.VersionFiles(done[1].NewID, vs[1].ID)
	if err != nil || string(files["notes.db-wal"]) != "content" {
		t.Errorf("content notes.db-wal = %q, %v", files["notes.db-wal"], err)
	}
	d, err := c.OpenData(done[1].NewID, vs[1].ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := d.GetFile("kept.db-wal"); err != nil || string(got) != "stored" {
		t.Errorf("stored kept.db-wal = %q, %v", got, err)
	}
}

func TestImportSaysWhenTheBackupIsEmpty(t *testing.T) {
	c := loggedIn(t)
	dir := writeOldBackup(t, nil)
	var out bytes.Buffer
	done, err := importBackup(context.Background(), c, dir, &out, io.Discard)
	if err != nil || len(done) != 0 {
		t.Fatalf("importBackup = %+v, %v", done, err)
	}
	if !strings.Contains(out.String(), "nothing to import") {
		t.Errorf("stdout = %q, want it to say there is nothing to import", out.String())
	}
}
