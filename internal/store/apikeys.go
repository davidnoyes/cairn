package store

import "time"

// APIKey authenticates as its owning user. Only the SHA-256 of the secret is
// stored; the full bearer token is shown once at creation time. MK is that
// key's own sealed copy of the account's MK.
type APIKey struct {
	ID         string `json:"id"`
	UserID     string `json:"userId"`
	Name       string `json:"name"`
	Device     bool   `json:"device"`
	SecretHash string `json:"-"`
	MK         []byte `json:"-"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
	RevokedAt  string `json:"revokedAt,omitempty"`
}

const apiKeyCols = `id, user_id, name, device, secret_hash, mk, created_at, COALESCE(last_used_at, ''), COALESCE(revoked_at, '')`

func scanAPIKey(row interface{ Scan(...any) error }) (*APIKey, error) {
	var k APIKey
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Device, &k.SecretHash, &k.MK, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
		return nil, err
	}
	return &k, nil
}

// CreateAPIKey stores a new key; the caller supplies everything but
// CreatedAt. ErrExists when the id is already used, even by a revoked key,
// since keyId is client-chosen and must stay globally unique.
func (s *Store) CreateAPIKey(k APIKey) error {
	k.CreatedAt = now()
	_, err := s.db.Exec(`INSERT INTO api_keys (id, user_id, name, device, secret_hash, mk, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.UserID, k.Name, k.Device, k.SecretHash, k.MK, k.CreatedAt)
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

func (s *Store) APIKeyByID(id string) (*APIKey, error) {
	return scanAPIKey(s.db.QueryRow(`SELECT `+apiKeyCols+` FROM api_keys WHERE id = ?`, id))
}

// ListAPIKeys returns a user's non-revoked keys, newest first.
func (s *Store) ListAPIKeys(userID string) ([]*APIKey, error) {
	rows, err := s.db.Query(`SELECT `+apiKeyCols+` FROM api_keys WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// RevokeAPIKey revokes id only if it belongs to userID and is still live;
// otherwise ErrNotFound, so one user can never revoke another's key.
func (s *Store) RevokeAPIKey(userID, id string, at time.Time) error {
	return s.exec1(`UPDATE api_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, formatTime(at), id, userID)
}

// TouchAPIKey records last use; best-effort, like touchArtifact.
func (s *Store) TouchAPIKey(id string, at time.Time) {
	s.db.Exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, formatTime(at), id)
}
