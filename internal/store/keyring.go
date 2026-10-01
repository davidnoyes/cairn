package store

import (
	"database/sql"
	"errors"
)

// Keyring returns a user's sealed keyring and its rev, or rev 0 and nil
// before the first write. The store never looks inside it.
func (s *Store) Keyring(userID string) (rev int, sealed []byte, err error) {
	err = s.db.QueryRow(`SELECT rev, keyring FROM user_keyrings WHERE user_id = ?`, userID).Scan(&rev, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, nil
	}
	return rev, sealed, err
}

// PutKeyring stores a user's sealed keyring at rev, which must be one more
// than the stored rev. Otherwise it returns ErrStale and the stored rev, so
// a second device reads again and merges instead of overwriting. Each branch
// is one statement, so two writers cannot both succeed at the same rev.
func (s *Store) PutKeyring(userID string, rev int, sealed []byte) (current int, err error) {
	var res sql.Result
	if rev == 1 {
		res, err = s.db.Exec(`INSERT INTO user_keyrings (user_id, rev, keyring, updated_at) VALUES (?, 1, ?, ?) ON CONFLICT (user_id) DO NOTHING`, userID, sealed, now())
	} else {
		res, err = s.db.Exec(`UPDATE user_keyrings SET rev = ?, keyring = ?, updated_at = ? WHERE user_id = ? AND rev = ?`, rev, sealed, now(), userID, rev-1)
	}
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		return rev, nil
	}
	if current, _, err = s.Keyring(userID); err != nil {
		return 0, err
	}
	return current, ErrStale
}
