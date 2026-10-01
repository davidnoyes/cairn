package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedDB creates a SQLite database at path with one row in table t.
func seedDB(t *testing.T, path, value string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t VALUES (?)`, value); err != nil {
		t.Fatal(err)
	}
}

func readValue(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT v FROM t`).Scan(&v); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return v
}

func TestBackupCopiesDatabasesAndFiles(t *testing.T) {
	src := t.TempDir()
	seedDB(t, filepath.Join(src, "cairn.db"), "meta")
	if err := os.MkdirAll(filepath.Join(src, "dbs", "a1"), 0o755); err != nil {
		t.Fatal(err)
	}
	seedDB(t, filepath.Join(src, "dbs", "a1", "v1.db"), "shared")
	if err := os.MkdirAll(filepath.Join(src, "content", "a1", "c1"), 0o755); err != nil {
		t.Fatal(err)
	}
	page := filepath.Join(src, "content", "a1", "c1", "index.html")
	if err := os.WriteFile(page, []byte("<h1>hi</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	// WAL side files are consolidated by VACUUM INTO, never copied.
	for _, n := range []string{"cairn.db-wal", "cairn.db-shm"} {
		if err := os.WriteFile(filepath.Join(src, n), []byte("junk"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Symlinks are skipped, not followed.
	if err := os.Symlink(page, filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "bk")
	stdout, err := runQuiet(t, runBackup, "--data-dir", src, "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	if want := "backed up 2 database(s) and 1 file(s) to " + out + "\n"; stdout != want {
		t.Errorf("output = %q, want %q", stdout, want)
	}
	if got := readValue(t, filepath.Join(out, "cairn.db")); got != "meta" {
		t.Errorf("backup cairn.db = %q", got)
	}
	if got := readValue(t, filepath.Join(out, "dbs", "a1", "v1.db")); got != "shared" {
		t.Errorf("backup v1.db = %q", got)
	}
	copied := filepath.Join(out, "content", "a1", "c1", "index.html")
	b, err := os.ReadFile(copied)
	if err != nil || string(b) != "<h1>hi</h1>" {
		t.Errorf("backup index.html = %q, %v", b, err)
	}
	st, err := os.Stat(copied)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("copied file mode = %v, %v; want 0600 preserved", st.Mode().Perm(), err)
	}
	for _, n := range []string{"cairn.db-wal", "cairn.db-shm", "link"} {
		if _, err := os.Lstat(filepath.Join(out, n)); !os.IsNotExist(err) {
			t.Errorf("%s was backed up (err=%v)", n, err)
		}
	}
}

func TestBackupOverwritesAnExistingBackup(t *testing.T) {
	src := t.TempDir()
	seedDB(t, filepath.Join(src, "cairn.db"), "first")
	out := filepath.Join(t.TempDir(), "bk")
	if _, err := runQuiet(t, runBackup, "--data-dir", src, "--out", out); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(src, "cairn.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`UPDATE t SET v = 'second'`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runQuiet(t, runBackup, "--data-dir", src, "--out", out); err != nil {
		t.Fatalf("second backup into the same dir: %v", err)
	}
	if got := readValue(t, filepath.Join(out, "cairn.db")); got != "second" {
		t.Errorf("second backup holds %q, want the newer value", got)
	}
}

func TestBackupRefusesANonCairnDirectory(t *testing.T) {
	src := t.TempDir()
	out := filepath.Join(t.TempDir(), "bk")
	err := runBackup([]string{"--data-dir", src, "--out", out})
	if err == nil || !strings.Contains(err.Error(), src+" does not look like a Cairn data directory (no cairn.db)") {
		t.Errorf("backup of an empty dir: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("the destination was created anyway (err=%v)", err)
	}
}

func TestBackupDefaultsTheDestinationToATimestampedDir(t *testing.T) {
	src := t.TempDir()
	seedDB(t, filepath.Join(src, "cairn.db"), "meta")
	cwd := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	if _, err := runQuiet(t, runBackup, "--data-dir", src); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(cwd, "cairn-backup-*", "cairn.db"))
	if len(matches) != 1 {
		t.Errorf("default backup dir not found, got %v", matches)
	}
}

func TestBackupReportsAnUnwritableDestination(t *testing.T) {
	src := t.TempDir()
	seedDB(t, filepath.Join(src, "cairn.db"), "meta")
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := runBackup([]string{"--data-dir", src, "--out", filepath.Join(blocker, "bk")})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("backup under a regular file: %v", err)
	}
}

func TestBackupReportsACorruptDatabase(t *testing.T) {
	src := t.TempDir()
	seedDB(t, filepath.Join(src, "cairn.db"), "meta")
	bad := filepath.Join(src, "bad.db")
	if err := os.WriteFile(bad, []byte(strings.Repeat("not sqlite ", 100)), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runBackup([]string{"--data-dir", src, "--out", filepath.Join(t.TempDir(), "bk")})
	if err == nil || !strings.Contains(err.Error(), "backup "+bad+":") {
		t.Errorf("backup with a corrupt db: %v", err)
	}
}
