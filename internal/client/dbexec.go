// Running SQL on a version's database: the client downloads the latest
// revision, runs the statements on its own copy, and uploads a new revision
// when they wrote.
package client

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aloisdeniel/cairn/internal/sqlrun"
	_ "modernc.org/sqlite"
)

// maxExecTries bounds how often Exec runs the statements again after a 412.
const maxExecTries = 5

// ErrDatabaseBusy means other writers kept landing revisions first, so the
// statements never ran against the latest one.
var ErrDatabaseBusy = fmt.Errorf("the database kept changing under other writers; gave up after %d tries", maxExecTries)

// writeSignals are the three counters whose change says a transaction wrote:
// SQL is never parsed to decide it.
type writeSignals struct{ totalChanges, schemaVersion, userVersion int64 }

func readSignals(ctx context.Context, tx *sql.Tx) (writeSignals, error) {
	var s writeSignals
	for _, q := range []struct {
		sql string
		out *int64
	}{
		{"SELECT total_changes()", &s.totalChanges},
		{"PRAGMA schema_version", &s.schemaVersion},
		{"PRAGMA user_version", &s.userVersion},
	} {
		if err := tx.QueryRowContext(ctx, q.sql).Scan(q.out); err != nil {
			return s, err
		}
	}
	return s, nil
}

// Exec runs stmts in one transaction on a private copy of the version's latest
// database, and returns one result per statement. When the statements wrote, it
// uploads the copy as a new revision with If-Match; on a 412 it reloads the
// latest revision and runs the statements again, up to five times. A version
// with no database yet starts from an empty one.
func (d *Data) Exec(stmts []sqlrun.Statement) ([]*sqlrun.Result, error) {
	for range maxExecTries {
		results, err := d.execOnce(stmts)
		var conflict *ConflictError
		if !errors.As(err, &conflict) {
			return results, err
		}
	}
	return nil, ErrDatabaseBusy
}

func (d *Data) execOnce(stmts []sqlrun.Statement) ([]*sqlrun.Result, error) {
	plain, base, err := d.Latest()
	if err != nil && !errors.Is(err, ErrNoDatabase) {
		return nil, err
	}
	// MkdirTemp makes the directory with mode 0700.
	dir, err := os.MkdirTemp("", "cairn-db-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "database.db")
	if plain != nil {
		if err := os.WriteFile(path, plain, 0o600); err != nil {
			return nil, err
		}
	}
	results, wrote, err := runInTransaction(path, stmts)
	if err != nil || !wrote {
		return results, err
	}
	out, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, err := d.PutRevision(out, base); err != nil {
		return nil, err
	}
	return results, nil
}

// runInTransaction runs stmts in one transaction on the database file at path,
// over a single connection, and reports whether they wrote. The database is
// closed, and holds the committed changes, when it returns.
func runInTransaction(path string, stmts []sqlrun.Statement) (results []*sqlrun.Result, wrote bool, err error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, false, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	before, err := readSignals(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	for i, stmt := range stmts {
		res, err := sqlrun.Run(ctx, tx, stmt)
		if err != nil {
			if len(stmts) > 1 {
				err = fmt.Errorf("statement %d: %w", i+1, err)
			}
			return nil, false, err
		}
		results = append(results, res)
	}
	after, err := readSignals(ctx, tx)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, err
	}
	if err := db.Close(); err != nil {
		return nil, false, err
	}
	return results, before != after, nil
}
