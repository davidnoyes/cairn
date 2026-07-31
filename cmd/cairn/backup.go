package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// runBackup produces a consistent point-in-time copy of a Cairn data
// directory. SQLite databases (which may be live, in WAL mode) are copied with
// VACUUM INTO; everything else is a plain file copy.
func runBackup(args []string) error {
	fs_ := flag.NewFlagSet("backup", flag.ExitOnError)
	dataDir := fs_.String("data-dir", envOr("CAIRN_DATA_DIR", "data"), "data directory to back up")
	out := fs_.String("out", "", "destination directory (default: cairn-backup-<timestamp>)")
	if err := fs_.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		*out = "cairn-backup-" + time.Now().UTC().Format("20060102-150405")
	}
	if _, err := os.Stat(filepath.Join(*dataDir, "cairn.db")); err != nil {
		return fmt.Errorf("%s does not look like a Cairn data directory (no cairn.db)", *dataDir)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	databases, files := 0, 0
	err := filepath.WalkDir(*dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(*dataDir, path)
		if err != nil {
			return err
		}
		target := filepath.Join(*out, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch {
		case strings.HasSuffix(path, ".db-wal"), strings.HasSuffix(path, ".db-shm"):
			return nil // consolidated into the vacuumed copy
		case strings.HasSuffix(path, ".db"):
			databases++
			return vacuumInto(path, target)
		default:
			files++
			return copyFile(path, target)
		}
	})
	if err != nil {
		return err
	}
	fmt.Printf("backed up %d database(s) and %d file(s) to %s\n", databases, files, *out)
	return nil
}

// vacuumInto writes a consistent snapshot of a (possibly live) SQLite
// database.
func vacuumInto(src, dst string) error {
	os.Remove(dst) // VACUUM INTO refuses to overwrite
	db, err := sql.Open("sqlite", "file:"+src+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`VACUUM INTO ?`, dst); err != nil {
		return fmt.Errorf("backup %s: %w", src, err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
