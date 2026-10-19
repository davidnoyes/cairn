package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestMigration014ManagerRole applies migrations 001 to 013 with a listed
// editor and viewer, and checks that opening the store keeps those rows and
// the cascade and index, accepts the manager role, and still refuses any
// other.
func TestMigration014ManagerRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cairn.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"001_init", "002_accounts", "003_sharing", "004_keyring", "005_vouches", "006_rotation",
		"007_encrypted_content", "008_client_data", "009_meta_fields", "010_successor", "011_google_proofs", "012_passkeys",
		"013_roles",
	} {
		file := "migrations/" + name + ".sql"
		body, err := migrationsFS.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (name, applied_at) VALUES (?, 'x')`, file); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"ed", "vw", "mg"} {
		if _, err := db.Exec(`INSERT INTO users (id, email, name, auth_hash, token_version, created_at) VALUES (?, ?, 'N', 'h', 1, 'x')`, id, id+"@x.y"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO artifacts (id, created_at, updated_at) VALUES ('a1', 'x', 'x')`); err != nil {
		t.Fatal(err)
	}
	for _, m := range [][2]string{{"ed", "editor"}, {"vw", "viewer"}} {
		if _, err := db.Exec(`INSERT INTO artifact_members (artifact_id, user_id, role, fp) VALUES ('a1', ?, ?, 'fp')`, m[0], m[1]); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rows, err := s.db.Query(`SELECT user_id, role FROM artifact_members WHERE artifact_id = 'a1' ORDER BY user_id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var u, r string
		if err := rows.Scan(&u, &r); err != nil {
			t.Fatal(err)
		}
		got = append(got, u+"="+r)
	}
	rows.Close()
	if len(got) != 2 || got[0] != "ed=editor" || got[1] != "vw=viewer" {
		t.Errorf("members after the migration: %v", got)
	}
	if _, err := s.db.Exec(`INSERT INTO artifact_members (artifact_id, user_id, role, fp) VALUES ('a1', 'mg', 'manager', 'fp')`); err != nil {
		t.Errorf("a manager: %v", err)
	}
	if _, err := s.db.Exec(`DELETE FROM users WHERE id = 'ed'`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM artifact_members WHERE user_id = 'ed'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("a deleted user's membership: %d, %v", n, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'artifact_members_user'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("artifact_members_user index: %d, %v", n, err)
	}
	if _, err := s.db.Exec(`UPDATE artifact_members SET role = 'owner' WHERE user_id = 'mg'`); err == nil {
		t.Error("an unknown role was accepted")
	}
}
