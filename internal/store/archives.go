package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Archive is a bundle_archives row: the bundle and API keys as they stood
// immediately before a password-only reset discarded them.
type Archive struct {
	ID         string        `json:"id"`
	ArchivedAt string        `json:"archivedAt"`
	Bundle     Bundle        `json:"bundle"`
	APIKeys    []ArchivedKey `json:"apiKeys"`
}

// ArchivedKey is one API key's wrapped MK as it stood at the time of an
// archive.
type ArchivedKey struct {
	ID string `json:"id"`
	MK []byte `json:"mk"`
}

// ResetAccount is the "reset without the recovery code" path: it archives
// the current bundle and every live API key's wrapped MK, revokes those
// keys, replaces the bundle and auth hash, deletes the keyring, and bumps
// token_version — all in one transaction.
func (s *Store) ResetAccount(userID, authHash string, b Bundle, at time.Time) error {
	t := formatTime(at)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	current, err := scanBundle(tx.QueryRow(`SELECT `+bundleCols+` FROM key_bundles WHERE user_id = ?`, userID))
	if err != nil {
		return err
	}
	bundleJSON, err := json.Marshal(current)
	if err != nil {
		return err
	}

	rows, err := tx.Query(`SELECT id, mk FROM api_keys WHERE user_id = ? AND revoked_at IS NULL`, userID)
	if err != nil {
		return err
	}
	var liveKeys []ArchivedKey
	for rows.Next() {
		var k ArchivedKey
		if err := rows.Scan(&k.ID, &k.MK); err != nil {
			rows.Close()
			return err
		}
		liveKeys = append(liveKeys, k)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	keysJSON, err := json.Marshal(liveKeys)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT INTO bundle_archives (id, user_id, archived_at, bundle, api_keys) VALUES (?, ?, ?, ?, ?)`,
		uuid.NewString(), userID, t, string(bundleJSON), string(keysJSON)); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE api_keys SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, t, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE key_bundles SET kdf = ?, mk_password = ?, mk_recovery = ?, x25519_pub = ?, x25519_priv = ?, ed25519_pub = ?, ed25519_priv = ?, ek = ? WHERE user_id = ?`,
		string(b.KDF), []byte(b.MKPassword), []byte(b.MKRecovery), []byte(b.X25519Pub), []byte(b.X25519Priv), []byte(b.Ed25519Pub), []byte(b.Ed25519Priv), []byte(b.EK), userID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE users SET auth_hash = ?, reset_at = ?, token_version = token_version + 1 WHERE id = ?`, authHash, t, userID); err != nil {
		return err
	}
	// The keyring is sealed under the old MK and can never open again.
	if _, err := tx.Exec(`DELETE FROM user_keyrings WHERE user_id = ?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// Archives returns bundles archived by a reset, newest first.
func (s *Store) Archives(userID string) ([]*Archive, error) {
	rows, err := s.db.Query(`SELECT id, archived_at, bundle, api_keys FROM bundle_archives WHERE user_id = ? ORDER BY archived_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Archive
	for rows.Next() {
		var a Archive
		var bundleJSON, keysJSON string
		if err := rows.Scan(&a.ID, &a.ArchivedAt, &bundleJSON, &keysJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(bundleJSON), &a.Bundle); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(keysJSON), &a.APIKeys); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}
