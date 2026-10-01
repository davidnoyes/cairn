package store

import (
	"database/sql"
	"encoding/json"
)

// Bundle is a user's wrapped key material. The store checks nothing about
// its contents (lengths and floors are the HTTP layer's job); KDF is kept as
// raw JSON since the store never needs to look inside it, only pass it
// through to the client and persist it as TEXT.
type Bundle struct {
	KDF         json.RawMessage `json:"kdf"`
	MKPassword  []byte          `json:"mkPassword"`
	MKRecovery  []byte          `json:"mkRecovery"`
	X25519Pub   []byte          `json:"x25519Pub"`
	X25519Priv  []byte          `json:"x25519Priv"`
	Ed25519Pub  []byte          `json:"ed25519Pub"`
	Ed25519Priv []byte          `json:"ed25519Priv"`
	EK          []byte          `json:"ek"`
}

const bundleCols = `kdf, mk_password, mk_recovery, x25519_pub, x25519_priv, ed25519_pub, ed25519_priv, ek`

func scanBundle(row interface{ Scan(...any) error }) (*Bundle, error) {
	var b Bundle
	var kdf string
	if err := row.Scan(&kdf, &b.MKPassword, &b.MKRecovery, &b.X25519Pub, &b.X25519Priv, &b.Ed25519Pub, &b.Ed25519Priv, &b.EK); err != nil {
		return nil, err
	}
	b.KDF = json.RawMessage(kdf)
	return &b, nil
}

func insertBundle(tx *sql.Tx, userID string, b Bundle) error {
	_, err := tx.Exec(`INSERT INTO key_bundles (user_id, `+bundleCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, string(b.KDF), []byte(b.MKPassword), []byte(b.MKRecovery), []byte(b.X25519Pub), []byte(b.X25519Priv), []byte(b.Ed25519Pub), []byte(b.Ed25519Priv), []byte(b.EK))
	return err
}

func (s *Store) BundleFor(userID string) (*Bundle, error) {
	return scanBundle(s.db.QueryRow(`SELECT `+bundleCols+` FROM key_bundles WHERE user_id = ?`, userID))
}

// SetPassword replaces the password-derived wrapping (authHash, kdf,
// mkPassword) and bumps token_version, signing out every other session.
func (s *Store) SetPassword(userID, authHash, kdf string, mkPassword []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := requireUser(tx, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET auth_hash = ?, token_version = token_version + 1 WHERE id = ?`, authHash, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE key_bundles SET kdf = ?, mk_password = ? WHERE user_id = ?`, kdf, mkPassword, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// SetRecovery replaces the recovery wrap only; it does not touch the
// password or token_version.
func (s *Store) SetRecovery(userID string, mkRecovery []byte) error {
	return s.exec1(`UPDATE key_bundles SET mk_recovery = ? WHERE user_id = ?`, mkRecovery, userID)
}

// requireUser confirms userID exists, inside tx, mapping "no rows" to
// ErrNotFound so callers get a clear error before further writes.
func requireUser(tx *sql.Tx, userID string) error {
	var id string
	return tx.QueryRow(`SELECT id FROM users WHERE id = ?`, userID).Scan(&id)
}
