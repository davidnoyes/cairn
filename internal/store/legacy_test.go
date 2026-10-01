package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// applyOnly001 opens a raw sqlite DB (bypassing Store.migrate) and applies
// only 001_init.sql, recording it in schema_migrations, so the DB looks the
// way a pre-002 server left it.
func applyOnly001(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	body, err := migrationsFS.ReadFile("migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (name, applied_at) VALUES ('migrations/001_init.sql', '2020-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyDataRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cairn.db")
	applyOnly001(t, path)

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, name, created_at) VALUES ('u1', 'a@b.c', 'Alice', '2020-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = Open(path)
	if !errors.Is(err, ErrLegacyData) {
		t.Fatalf("expected ErrLegacyData, got %v", err)
	}
}

func TestEmptyLegacyUsersMigratesNormally(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cairn.db")
	applyOnly001(t, path)
	// users table exists from 001 but holds no rows.

	s, err := Open(path)
	if err != nil {
		t.Fatalf("expected a clean migration, got %v", err)
	}
	s.Close()
}
