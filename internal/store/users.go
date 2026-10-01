package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// User is an account on the server. AuthHash is bcrypt of the client-derived
// authKey; the store never sees a plaintext password.
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	AuthHash     string `json:"-"`
	IsAdmin      bool   `json:"isAdmin"`
	TokenVersion int    `json:"-"`
	Disabled     bool   `json:"disabled"`
	VerifiedAt   string `json:"verifiedAt,omitempty"`
	ResetAt      string `json:"resetAt,omitempty"`
	CreatedAt    string `json:"createdAt"`
}

const userCols = `id, email, name, auth_hash, is_admin, token_version, disabled, COALESCE(verified_at, ''), COALESCE(reset_at, ''), created_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.AuthHash, &u.IsAdmin, &u.TokenVersion, &u.Disabled, &u.VerifiedAt, &u.ResetAt, &u.CreatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

// normalizeEmail lowercases and trims an address the way every lookup and
// comparison expects it.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// CreateAccount creates a new unverified account and its key bundle in one
// transaction. A VERIFIED account already at this email is ErrExists and
// nothing changes; an unverified one is replaced (its bundle and API keys
// cascade away with it).
func (s *Store) CreateAccount(email, name, authHash string, b Bundle, isAdmin bool) (*User, error) {
	email = normalizeEmail(email)
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var existingID string
	var verifiedAt sql.NullString
	err = tx.QueryRow(`SELECT id, verified_at FROM users WHERE email = ?`, email).Scan(&existingID, &verifiedAt)
	switch {
	case err == nil:
		if verifiedAt.Valid {
			return nil, ErrExists
		}
		if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, existingID); err != nil {
			return nil, err
		}
	case errors.Is(err, sql.ErrNoRows):
		// no existing account at this address
	default:
		return nil, err
	}

	u := &User{ID: uuid.NewString(), Email: email, Name: name, AuthHash: authHash, IsAdmin: isAdmin, TokenVersion: 1, CreatedAt: now()}
	if _, err := tx.Exec(`INSERT INTO users (id, email, name, auth_hash, is_admin, token_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Name, u.AuthHash, u.IsAdmin, u.TokenVersion, u.CreatedAt); err != nil {
		return nil, err
	}
	if err := insertBundle(tx, u.ID, b); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) UserByEmail(email string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE email = ?`, normalizeEmail(email)))
}

func (s *Store) UserByID(id string) (*User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// ListUsers returns verified users ordered by creation; set includeUnverified
// to also list accounts still awaiting a verification link.
func (s *Store) ListUsers(includeUnverified bool) ([]*User, error) {
	q := `SELECT ` + userCols + ` FROM users`
	if !includeUnverified {
		q += ` WHERE verified_at IS NOT NULL`
	}
	q += ` ORDER BY created_at, email`
	rows, err := s.db.Query(q)
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

func (s *Store) MarkVerified(userID string, at time.Time) error {
	return s.exec1(`UPDATE users SET verified_at = ? WHERE id = ?`, formatTime(at), userID)
}

func (s *Store) SetUserAdmin(userID string, isAdmin bool) error {
	return s.exec1(`UPDATE users SET is_admin = ? WHERE id = ?`, isAdmin, userID)
}

// SetUserDisabled toggles an account; disabling bumps token_version so every
// existing session and API key stops working immediately.
func (s *Store) SetUserDisabled(userID string, disabled bool) error {
	return s.exec1(`UPDATE users SET disabled = ?, token_version = token_version + 1 WHERE id = ?`, disabled, userID)
}

// DeleteUser deletes an account. A user who owns artifacts is
// ErrOwnsArtifacts: disable the account instead, so an administrator can hand
// the artifacts over.
func (s *Store) DeleteUser(userID string) error {
	var owns bool
	if err := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM artifacts WHERE owner_id = ?)`, userID).Scan(&owns); err != nil {
		return err
	}
	if owns {
		return ErrOwnsArtifacts
	}
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
