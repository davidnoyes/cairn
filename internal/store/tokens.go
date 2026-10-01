package store

import "time"

// Token is a single-use random token behind a verification or reset link.
// The store holds only its SHA-256 hash; the client holds the token itself.
type Token struct {
	Hash      string `json:"-"`
	UserID    string `json:"userId"`
	Kind      string `json:"kind"`
	ExpiresAt string `json:"expiresAt"`
	UsedAt    string `json:"usedAt,omitempty"`
}

const tokenCols = `hash, user_id, kind, expires_at, COALESCE(used_at, '')`

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	if err := row.Scan(&t.Hash, &t.UserID, &t.Kind, &t.ExpiresAt, &t.UsedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateToken stores a token's hash. Callers should DeleteTokens(userID,
// kind) first so only the most recently issued link of a kind is valid.
func (s *Store) CreateToken(hash, userID, kind string, expiresAt time.Time) error {
	_, err := s.db.Exec(`INSERT INTO tokens (hash, user_id, kind, expires_at) VALUES (?, ?, ?, ?)`,
		hash, userID, kind, formatTime(expiresAt))
	return err
}

// PeekToken returns the token if it is unused and unexpired, without
// consuming it (reset/begin reads the token but must not burn the link).
func (s *Store) PeekToken(hash, kind string, now time.Time) (*Token, error) {
	return scanToken(s.db.QueryRow(`SELECT `+tokenCols+` FROM tokens WHERE hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?`,
		hash, kind, formatTime(now)))
}

// UseToken atomically marks a token used and returns it, or ErrNotFound if
// it is unknown, already used, or expired — so a second call always fails.
func (s *Store) UseToken(hash, kind string, now time.Time) (*Token, error) {
	t := formatTime(now)
	res, err := s.db.Exec(`UPDATE tokens SET used_at = ? WHERE hash = ? AND kind = ? AND used_at IS NULL AND expires_at > ?`,
		t, hash, kind, t)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrNotFound
	}
	return scanToken(s.db.QueryRow(`SELECT `+tokenCols+` FROM tokens WHERE hash = ? AND kind = ?`, hash, kind))
}

// DeleteTokens removes outstanding tokens of one kind for a user, so issuing
// a new verification or reset link invalidates any older one.
func (s *Store) DeleteTokens(userID, kind string) error {
	_, err := s.db.Exec(`DELETE FROM tokens WHERE user_id = ? AND kind = ?`, userID, kind)
	return err
}
