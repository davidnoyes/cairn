package store

import (
	"database/sql"

	"github.com/google/uuid"
)

// User is an account on the server. PasswordHash is empty until the user
// claims the account at first login.
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	PasswordHash string `json:"-"`
	IsAdmin      bool   `json:"isAdmin"`
	TokenVersion int    `json:"-"`
	Disabled     bool   `json:"disabled"`
	CreatedAt    string `json:"createdAt"`
}

const userCols = `id, email, name, COALESCE(password_hash, ''), is_admin, token_version, disabled, created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsAdmin, &u.TokenVersion, &u.Disabled, &u.CreatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) CreateUser(email, name string, isAdmin bool) (*User, error) {
	u := &User{
		ID:           uuid.NewString(),
		Email:        email,
		Name:         name,
		IsAdmin:      isAdmin,
		TokenVersion: 1,
		CreatedAt:    now(),
	}
	_, err := s.db.Exec(`INSERT INTO users (id, email, name, is_admin, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Name, u.IsAdmin, u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) UserByEmail(email string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE email = ?`, email))
}

func (s *Store) UserByID(id string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY created_at, email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// SetPassword stores a new password hash. When bumpToken is true, existing
// JWTs for the user are invalidated.
func (s *Store) SetPassword(userID, hash string, bumpToken bool) error {
	bump := 0
	if bumpToken {
		bump = 1
	}
	return s.exec1(`UPDATE users SET password_hash = ?, token_version = token_version + ? WHERE id = ?`, hash, bump, userID)
}

// ClearPassword resets the account to the unclaimed state so the user picks a
// new password at next login. Existing tokens are invalidated.
func (s *Store) ClearPassword(userID string) error {
	return s.exec1(`UPDATE users SET password_hash = NULL, token_version = token_version + 1 WHERE id = ?`, userID)
}

func (s *Store) SetUserDisabled(userID string, disabled bool) error {
	return s.exec1(`UPDATE users SET disabled = ?, token_version = token_version + 1 WHERE id = ?`, disabled, userID)
}

func (s *Store) UpdateUser(userID, name string, isAdmin bool) error {
	return s.exec1(`UPDATE users SET name = ?, is_admin = ? WHERE id = ?`, name, isAdmin, userID)
}

func (s *Store) DeleteUser(userID string) error {
	return s.exec1(`DELETE FROM users WHERE id = ?`, userID)
}

// exec1 runs a statement that must affect exactly one row, mapping "no rows"
// to ErrNotFound.
func (s *Store) exec1(query string, args ...any) error {
	res, err := s.db.Exec(query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
