// Package store persists Cairn's metadata (users, API keys, artifacts,
// versions) in a single SQLite database.
package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store wraps the metadata database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the metadata database at path and applies
// pending migrations.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite handles one writer at a time; a single connection avoids
	// SQLITE_BUSY churn on the small metadata DB.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying handle (used by backup).
func (s *Store) DB() *sql.DB { return s.db }

// accountsMigration drops and recreates the account tables; applying it to a
// data directory that already holds accounts would discard them.
const accountsMigration = "migrations/002_accounts.sql"

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)
	for _, name := range entries {
		var applied int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		if name == accountsMigration {
			var n int
			if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return ErrLegacyData
			}
		}
		body, err := migrationsFS.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("%s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)`, name, now()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = sql.ErrNoRows

// ErrExists is returned when a create would collide with an existing row.
var ErrExists = errors.New("already exists")

// ErrLegacyData is returned by Open when the data directory holds accounts
// from a Cairn version that predates this schema. Those accounts cannot be
// migrated automatically: start the server with a fresh data directory, or
// run `cairn import` to bring the old accounts across.
var ErrLegacyData = errors.New("this data directory holds accounts from an earlier version of Cairn; start with a fresh data directory, or run `cairn import`")

// isUniqueViolation reports whether err is a SQLite uniqueness failure (a
// duplicate email, or a reused API key id — a client-chosen primary key).
func isUniqueViolation(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	switch sqliteErr.Code() {
	case 2067, 1555: // SQLITE_CONSTRAINT_UNIQUE, SQLITE_CONSTRAINT_PRIMARYKEY
		return true
	default:
		return false
	}
}
