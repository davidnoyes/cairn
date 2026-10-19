package store

import "time"

// Passkey is a credential that signs its user in. MK is that credential's
// own sealed copy of the account's MK; the server cannot open it.
type Passkey struct {
	ID         string // the credential ID, base64url
	UserID     string
	Name       string
	PublicKey  []byte // SPKI
	Alg        int    // COSE algorithm
	SignCount  uint32
	MK         []byte
	CreatedAt  string
	LastUsedAt string // empty when never used
}

const passkeyCols = `id, user_id, name, public_key, alg, sign_count, mk, created_at, COALESCE(last_used_at, '')`

func scanPasskey(row interface{ Scan(...any) error }) (*Passkey, error) {
	var p Passkey
	if err := row.Scan(&p.ID, &p.UserID, &p.Name, &p.PublicKey, &p.Alg, &p.SignCount, &p.MK, &p.CreatedAt, &p.LastUsedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreatePasskey stores a new passkey; the caller supplies everything but
// CreatedAt. ErrExists when the credential ID is already enrolled, by any
// user.
func (s *Store) CreatePasskey(p Passkey) error {
	p.CreatedAt = now()
	_, err := s.db.Exec(`INSERT INTO passkeys (id, user_id, name, public_key, alg, sign_count, mk, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.UserID, p.Name, p.PublicKey, p.Alg, p.SignCount, p.MK, p.CreatedAt)
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

// PasskeyByID returns the passkey with this credential ID, or ErrNotFound.
func (s *Store) PasskeyByID(id string) (*Passkey, error) {
	return scanPasskey(s.db.QueryRow(`SELECT `+passkeyCols+` FROM passkeys WHERE id = ?`, id))
}

// ListPasskeys returns a user's passkeys, newest first.
func (s *Store) ListPasskeys(userID string) ([]*Passkey, error) {
	rows, err := s.db.Query(`SELECT `+passkeyCols+` FROM passkeys WHERE user_id = ? ORDER BY created_at DESC, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePasskey removes id only if it belongs to userID; otherwise
// ErrNotFound, so one user can never remove another's passkey.
func (s *Store) DeletePasskey(userID, id string) error {
	return s.exec1(`DELETE FROM passkeys WHERE id = ? AND user_id = ?`, id, userID)
}

// TouchPasskey records a successful sign-in: the authenticator's new counter
// and the time.
func (s *Store) TouchPasskey(id string, signCount uint32, at time.Time) error {
	return s.exec1(`UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?`, signCount, formatTime(at), id)
}
