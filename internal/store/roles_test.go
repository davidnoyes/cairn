package store

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// TestMigration013RolesFromAdminFlag applies migrations 001 to 012, adds an
// administrator and a member, and checks that opening the store maps the flag
// onto users.role and drops the column.
func TestMigration013RolesFromAdminFlag(t *testing.T) {
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
	for _, u := range []struct {
		id    string
		admin int
	}{{"adm", 1}, {"mem", 0}} {
		if _, err := db.Exec(`INSERT INTO users (id, email, name, auth_hash, is_admin, token_version, created_at) VALUES (?, ?, 'N', 'h', ?, 1, 'x')`,
			u.id, u.id+"@x.y", u.admin); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	adm, err := s.UserByID("adm")
	if err != nil {
		t.Fatal(err)
	}
	mem, err := s.UserByID("mem")
	if err != nil {
		t.Fatal(err)
	}
	if adm.Role != "admin" || !adm.IsAdmin {
		t.Errorf("administrator became role %q, IsAdmin %v", adm.Role, adm.IsAdmin)
	}
	if mem.Role != "member" || mem.IsAdmin {
		t.Errorf("member became role %q, IsAdmin %v", mem.Role, mem.IsAdmin)
	}
	if _, err := s.db.Exec(`SELECT is_admin FROM users`); err == nil || !strings.Contains(err.Error(), "no such column") {
		t.Errorf("is_admin should be dropped, got %v", err)
	}
}

// TestSetUserRole checks every role is accepted, an unknown one is refused
// and leaves the account as it was, and an unknown user is ErrNotFound.
func TestSetUserRole(t *testing.T) {
	s := testStore(t)
	u := testAccount(t, s, "r@x.y")
	for _, role := range []string{"admin", "viewer", "member"} {
		if err := s.SetUserRole(u.ID, role); err != nil {
			t.Fatalf("SetUserRole(%q): %v", role, err)
		}
		got, _ := s.UserByID(u.ID)
		if got.Role != role || got.IsAdmin != (role == "admin") {
			t.Errorf("after %q: role %q, IsAdmin %v", role, got.Role, got.IsAdmin)
		}
	}
	err := s.SetUserRole(u.ID, "owner")
	if err == nil || err.Error() != `unknown role "owner"` {
		t.Fatalf("unknown role: got %v", err)
	}
	if got, _ := s.UserByID(u.ID); got.Role != "member" {
		t.Errorf("a refused role changed the account to %q", got.Role)
	}
	if err := s.SetUserRole("nobody", "viewer"); err != ErrNotFound {
		t.Errorf("unknown user: got %v", err)
	}
}

// TestCreateAccountRole checks CreateAccount stores the role it is given and
// refuses an unknown one.
func TestCreateAccountRole(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateAccount("v@x.y", "V", "h", testBundle("v"), "viewer")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(u.ID)
	if u.Role != "viewer" || got.Role != "viewer" || got.IsAdmin {
		t.Errorf("created %q, read back %q, IsAdmin %v", u.Role, got.Role, got.IsAdmin)
	}
	if _, err := s.CreateAccount("w@x.y", "W", "h", testBundle("w"), "root"); err == nil {
		t.Error("an unknown role created an account")
	}
}
