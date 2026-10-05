package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/sqlrun"
)

func TestDBBatch(t *testing.T) {
	pushedSite(t)
	file := filepath.Join(t.TempDir(), "batch.json")
	script := `[
		{"sql": "CREATE TABLE t (n INTEGER)"},
		{"sql": "INSERT INTO t VALUES (?)", "params": [1]},
		{"sql": "INSERT INTO t VALUES (?)", "params": [2]},
		{"sql": "SELECT n FROM t ORDER BY n"}
	]`
	if err := os.WriteFile(file, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	res := runJSON[[]sqlrun.Result](t, runDB, "batch", "--artifact", "site", "--file", file, "--json")
	if len(res) != 4 || res[1].RowsAffected != 1 || len(res[3].Rows) != 2 || res[3].Rows[1][0] != float64(2) {
		t.Fatalf("batch results = %+v, want one per statement", res)
	}
	// From standard input, as text.
	withStdin(t, `[{"sql": "SELECT count(*) AS n FROM t"}, {"sql": "SELECT 7 AS seven"}]`)
	out, err := runQuiet(t, runDB, "batch", "--artifact", "site")
	if err != nil || out != "-- statement 1\nn\n2\n-- statement 2\nseven\n7\n" {
		t.Errorf("batch output = %q, %v", out, err)
	}
	// One transaction: a failing statement leaves nothing of the others.
	withStdin(t, `[{"sql": "INSERT INTO t VALUES (3)"}, {"sql": "INSERT INTO nowhere VALUES (1)"}]`)
	if _, err := runQuiet(t, runDB, "batch", "--artifact", "site"); err == nil || !strings.Contains(err.Error(), "statement 2") {
		t.Fatalf("a failing batch: %v", err)
	}
	q := runJSON[sqlrun.Result](t, runDB, "query", "--artifact", "site", "--json", "SELECT count(*) AS n FROM t")
	if q.Rows[0][0] != float64(2) {
		t.Errorf("rows after the failed batch = %v, want 2", q.Rows[0][0])
	}
}

func TestDBBatchRefusals(t *testing.T) {
	pushedSite(t)
	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"not JSON", "nope", nil, "the batch must be a JSON array"},
		{"empty", "[]", nil, "no statements"},
		{"no artifact", "[]", []string{"--file", "x"}, ""},
		{"missing file", "", []string{"--file", filepath.Join(t.TempDir(), "nope")}, "no such file"},
		{"extra argument", "[]", []string{"extra"}, "usage: cairn db batch"},
		{"two statements in one", `[{"sql": "SELECT 1; SELECT 2"}]`, nil, "only one SQL statement per call"},
	} {
		withStdin(t, tc.stdin)
		args := append([]string{"batch"}, tc.args...)
		if tc.name != "no artifact" {
			args = append(args, "--artifact", "site")
		}
		err := runDB(args)
		if tc.name == "no artifact" {
			if err == nil || !strings.Contains(err.Error(), "usage: cairn db batch") {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestDBRevisionsRestoreAndDownload(t *testing.T) {
	pushedSite(t)
	for _, sql := range []string{"CREATE TABLE t (n INTEGER)", "INSERT INTO t VALUES (1)", "INSERT INTO t VALUES (2)"} {
		if _, err := runQuiet(t, runDB, "query", "--artifact", "site", sql); err != nil {
			t.Fatal(err)
		}
	}
	revs := runJSON[[]client.Revision](t, runDB, "revisions", "--artifact", "site", "--json")
	if len(revs) != 3 || revs[0].Revision != 3 || revs[2].Revision != 1 || revs[0].Epoch != 1 {
		t.Fatalf("revisions = %+v", revs)
	}
	out, err := runQuiet(t, runDB, "revisions", "--artifact", "site")
	if err != nil || strings.Count(out, "\n") != 3 || !strings.Contains(out, "epoch 1") {
		t.Errorf("revisions output = %q, %v", out, err)
	}

	res := runJSON[map[string]any](t, runDB, "restore", "--artifact", "site", "--revision", "2", "--json")
	if res["restored"] != float64(2) || res["revision"] != float64(4) {
		t.Fatalf("restore --json = %v, want revision 2 restored as 4", res)
	}
	out, err = runQuiet(t, runDB, "restore", "--artifact", "site", "--revision", "1")
	if err != nil || out != "restored revision 1 as revision 5\n" {
		t.Errorf("restore output = %q, %v", out, err)
	}
	// Revision 1 holds the empty table: nothing in it.
	q := runJSON[sqlrun.Result](t, runDB, "query", "--artifact", "site", "--json", "SELECT count(*) AS n FROM t")
	if q.Rows[0][0] != float64(0) {
		t.Errorf("rows after restoring revision 1 = %v, want 0", q.Rows[0][0])
	}

	dst := filepath.Join(t.TempDir(), "copy.db")
	out, err = runQuiet(t, runDB, "download", "--artifact", "site", "--out", dst)
	if err != nil || !strings.HasPrefix(out, "wrote revision 5 to "+dst) {
		t.Errorf("download output = %q, %v", out, err)
	}
	if b, err := os.ReadFile(dst); err != nil || !strings.HasPrefix(string(b), "SQLite format 3\x00") {
		t.Errorf("the download is not a SQLite file: %q, %v", b[:min(len(b), 16)], err)
	}
	// The default name.
	t.Chdir(t.TempDir())
	if _, err := runQuiet(t, runDB, "download", "--artifact", "site"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("database.db"); err != nil {
		t.Errorf("no database.db: %v", err)
	}
}

func TestDBDataCommandRefusals(t *testing.T) {
	_, a, _ := pushedSite(t)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"restore without a revision", []string{"restore", "--artifact", "site"}, "usage: cairn db restore"},
		{"revisions without an artifact", []string{"revisions"}, "usage: cairn db revisions"},
		{"download without an artifact", []string{"download"}, "usage: cairn db download"},
		{"download of no database", []string{"download", "--artifact", "site"}, "no database yet"},
		{"restore of a revision never kept", []string{"restore", "--artifact", a.ID, "--revision", "9"}, "not found"},
		{"unknown version", []string{"revisions", "--artifact", "site", "--version", "00000000-0000-4000-8000-000000000000"}, "not found"},
	} {
		if err := runDB(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestUnshareReseals(t *testing.T) {
	w := newTeamWorld(t)
	w.as(t, "ada")
	if _, err := runQuiet(t, runTeam, w.artifact, "none"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runShare, w.artifact, "dan@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runPush, siteDir(t), "--artifact", w.artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runDB, "query", "--artifact", w.artifact, "CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(t.TempDir(), "f.txt")
	os.WriteFile(local, []byte("keep me"), 0o600)
	if _, err := runQuiet(t, runFiles, "put", local, "--artifact", w.artifact); err != nil {
		t.Fatal(err)
	}
	out, err := runQuiet(t, runUnshare, w.artifact, "dan@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "sealed 1 database(s) and 1 file(s) again under the new epoch") {
		t.Errorf("cairn unshare printed %q, want the re-seal reported", out)
	}
	if got, err := runQuiet(t, runFiles, "get", "f.txt", "--artifact", w.artifact); err != nil || got != "keep me" {
		t.Errorf("the file after the re-seal = %q, %v", got, err)
	}
	// Nothing left to do: reseal says so, in text and JSON.
	out, err = runQuiet(t, runReseal, w.artifact)
	if err != nil || out != "nothing to seal again: the data is under the current epoch\n" {
		t.Errorf("cairn reseal printed %q, %v", out, err)
	}
	res := runJSON[map[string]any](t, runReseal, w.artifact, "--json")
	r, _ := res["resealed"].(map[string]any)
	if res["artifact"] != w.artifact || r["databases"] != float64(0) || r["files"] != float64(0) || r["error"] != "" {
		t.Errorf("cairn reseal --json = %v", res)
	}
	// A second unshare reports the re-seal in JSON.
	j := runJSON[map[string]any](t, runUnshare, w.artifact, "bob@example.com", "--json")
	if r, _ := j["resealed"].(map[string]any); r["databases"] != float64(1) || r["files"] != float64(1) {
		t.Errorf("cairn unshare --json resealed = %v", j["resealed"])
	}
	if _, err := runQuiet(t, runReseal); err == nil || !strings.Contains(err.Error(), "usage: cairn reseal ARTIFACT") {
		t.Errorf("reseal with no artifact: %v", err)
	}
}

func TestPrintResealReportsAFailure(t *testing.T) {
	done := captureStdout(t)
	printReseal("art1", &client.ResealResult{Databases: 1, Skipped: []string{"a file: may not write"}}, errors.New("disk on fire"))
	out := done()
	for _, want := range []string{"sealed 1 database(s) and 0 file(s)", "may not write", "disk on fire", "run: cairn reseal art1"} {
		if !strings.Contains(out, want) {
			t.Errorf("printReseal printed %q, want %q", out, want)
		}
	}
	j := resealJSON(nil, errors.New("boom"))
	if j["error"] != "boom" || j["databases"] != 0 {
		t.Errorf("resealJSON = %v", j)
	}
}
