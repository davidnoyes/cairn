package store

// APIKey authenticates as its owning user. Only the SHA-256 of the secret is
// stored; the full token is shown once at creation time.
type APIKey struct {
	ID         string `json:"id"`
	UserID     string `json:"userId"`
	Name       string `json:"name"`
	SecretHash string `json:"-"`
	CreatedAt  string `json:"createdAt"`
	RevokedAt  string `json:"revokedAt,omitempty"`
}

const apiKeyCols = `id, user_id, name, secret_hash, created_at, COALESCE(revoked_at, '')`

func scanAPIKey(row interface{ Scan(...any) error }) (*APIKey, error) {
	var k APIKey
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.SecretHash, &k.CreatedAt, &k.RevokedAt); err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *Store) CreateAPIKey(id, userID, name, secretHash string) (*APIKey, error) {
	k := &APIKey{ID: id, UserID: userID, Name: name, SecretHash: secretHash, CreatedAt: now()}
	_, err := s.db.Exec(`INSERT INTO api_keys (id, user_id, name, secret_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		k.ID, k.UserID, k.Name, k.SecretHash, k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Store) APIKeyByID(id string) (*APIKey, error) {
	return scanAPIKey(s.db.QueryRow(`SELECT `+apiKeyCols+` FROM api_keys WHERE id = ?`, id))
}

func (s *Store) ListAPIKeys() ([]*APIKey, error) {
	rows, err := s.db.Query(`SELECT ` + apiKeyCols + ` FROM api_keys ORDER BY created_at`)
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

func (s *Store) RevokeAPIKey(id string) error {
	return s.exec1(`UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now(), id)
}
