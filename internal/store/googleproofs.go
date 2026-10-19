package store

import "time"

// GoogleProof is a single-use record that a browser completed Google sign-in
// for Email. The store holds only the SHA-256 hash of its token.
type GoogleProof struct {
	Hash      string `json:"-"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expiresAt"`
}

const googleProofCols = `hash, email, name, expires_at`

func scanGoogleProof(row interface{ Scan(...any) error }) (*GoogleProof, error) {
	var p GoogleProof
	if err := row.Scan(&p.Hash, &p.Email, &p.Name, &p.ExpiresAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateGoogleProof stores a proof's hash for a normalized address and the
// Google display name.
func (s *Store) CreateGoogleProof(hash, email, name string, expiresAt time.Time) error {
	_, err := s.db.Exec(`INSERT INTO google_proofs (hash, email, name, expires_at) VALUES (?, ?, ?, ?)`,
		hash, email, name, formatTime(expiresAt))
	return err
}

// PeekGoogleProof returns the proof if it is unused and unexpired, without
// consuming it, or ErrNotFound.
func (s *Store) PeekGoogleProof(hash string, now time.Time) (*GoogleProof, error) {
	return scanGoogleProof(s.db.QueryRow(`SELECT `+googleProofCols+` FROM google_proofs WHERE hash = ? AND used_at IS NULL AND expires_at > ?`,
		hash, formatTime(now)))
}

// UseGoogleProof atomically marks a proof used and returns it, or
// ErrNotFound if it is unknown, already used, or expired, so a second call
// always fails.
func (s *Store) UseGoogleProof(hash string, now time.Time) (*GoogleProof, error) {
	t := formatTime(now)
	res, err := s.db.Exec(`UPDATE google_proofs SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ?`,
		t, hash, t)
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
	return scanGoogleProof(s.db.QueryRow(`SELECT `+googleProofCols+` FROM google_proofs WHERE hash = ?`, hash))
}
