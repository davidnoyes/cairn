package store

import (
	"database/sql"
	"errors"
	"sort"
)

// Rotation is one key rotation record as the client sent it. OldFP and NewFP
// are copies of what the keys in Body hash to; the store checks nothing.
// CreatedAt is set by the store.
type Rotation struct {
	UserID    string
	Seq       int
	OldFP     string
	NewFP     string
	Body      []byte
	Sig       []byte
	NewSig    []byte
	CreatedAt string
}

const rotationCols = `user_id, seq, old_fp, new_fp, body, sig, new_sig, created_at`

func queryRotations(q querier, userID string) ([]Rotation, error) {
	rows, err := q.Query(`SELECT `+rotationCols+` FROM user_rotations WHERE user_id = ? ORDER BY seq`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rotation
	for rows.Next() {
		var r Rotation
		if err := rows.Scan(&r.UserID, &r.Seq, &r.OldFP, &r.NewFP, &r.Body, &r.Sig, &r.NewSig, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Rotations returns a user's rotation records, oldest first.
func (s *Store) Rotations(userID string) ([]Rotation, error) {
	return queryRotations(s.db, userID)
}

// Rotations returns a user's rotation records inside the transaction, oldest
// first.
func (t *ArtifactTx) Rotations(userID string) ([]Rotation, error) {
	return queryRotations(t.tx, userID)
}

func queryOwnedWithRecords(q querier, userID string) ([]string, error) {
	rows, err := q.Query(`SELECT a.id FROM artifacts a WHERE a.owner_id = ?
		AND EXISTS (SELECT 1 FROM artifact_records r WHERE r.artifact_id = a.id) ORDER BY a.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// OwnedWithRecords returns the IDs, sorted, of the artifacts userID owns that
// have at least one membership record.
func (s *Store) OwnedWithRecords(userID string) ([]string, error) {
	return queryOwnedWithRecords(s.db, userID)
}

// OwnerChange is a record that moved an artifact from one owner to another.
type OwnerChange struct {
	ArtifactID string
	From, To   string
	At         string
}

// OwnerChanges returns every record stored at or after since (RFC 3339) whose
// owner differs from the previous record's and is userID on either side,
// oldest first.
func (s *Store) OwnerChanges(userID, since string) ([]OwnerChange, error) {
	rows, err := s.db.Query(`SELECT r.artifact_id, p.owner_id, r.owner_id, r.created_at
		FROM artifact_records r JOIN artifact_records p ON p.artifact_id = r.artifact_id AND p.seq = r.seq - 1
		WHERE r.owner_id != p.owner_id AND (r.owner_id = ? OR p.owner_id = ?) AND r.created_at >= ?
		ORDER BY r.created_at, r.artifact_id, r.seq`, userID, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OwnerChange
	for rows.Next() {
		var c OwnerChange
		if err := rows.Scan(&c.ArtifactID, &c.From, &c.To, &c.At); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RotateTx is the transaction RotateKeys runs: the user's row and every
// artifact RotateKeys locked, and nothing else.
type RotateTx struct {
	tx     *sql.Tx
	userID string
}

// HeldWrap is a wrap a user holds, with the artifact it is on.
type HeldWrap struct {
	ArtifactID string
	Wrap
}

// RotateKeys runs fn in one transaction that locks every artifact in owned
// and the user's row, committing if fn returns nil. A missing user is
// ErrNotFound. It follows the same rules as WithArtifact: fn must use only
// the RotateTx, never the Store, and stay short.
//
// The locks are taken in sorted order, so two rotations or a rotation and a
// membership change cannot wait on each other. RotateTx.Artifact is for the
// artifacts in owned only.
func (s *Store) RotateKeys(userID string, owned []string, fn func(*RotateTx) error) error {
	ids := append([]string{}, owned...)
	sort.Strings(ids)
	for i, id := range ids {
		if i > 0 && id == ids[i-1] {
			continue
		}
		l := s.artifactLock(id)
		l.Lock()
		defer l.Unlock()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A no-op write takes SQLite's write lock now, and doubles as the
	// existence check.
	res, err := tx.Exec(`UPDATE users SET id = id WHERE id = ?`, userID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	if err := fn(&RotateTx{tx: tx, userID: userID}); err != nil {
		return err
	}
	return tx.Commit()
}

// User reads the user and their current keys.
func (t *RotateTx) User() (*KeyedUser, error) {
	return scanKeyedUser(t.tx.QueryRow(`SELECT `+keyedUserCols+` FROM users u JOIN key_bundles b ON b.user_id = u.id WHERE u.id = ?`, t.userID))
}

// Bundle reads the user's current bundle.
func (t *RotateTx) Bundle() (*Bundle, error) {
	return scanBundle(t.tx.QueryRow(`SELECT `+bundleCols+` FROM key_bundles WHERE user_id = ?`, t.userID))
}

// LastRotationSeq is the seq of the user's latest rotation record, 0 when
// there is none.
func (t *RotateTx) LastRotationSeq() (int, error) {
	var seq int
	err := t.tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM user_rotations WHERE user_id = ?`, t.userID).Scan(&seq)
	return seq, err
}

// OwnedWithRecords returns the IDs, sorted, of the artifacts the user owns
// that have at least one membership record.
func (t *RotateTx) OwnedWithRecords() ([]string, error) {
	return queryOwnedWithRecords(t.tx, t.userID)
}

// HeldWraps returns every wrap the user holds on any artifact, ordered by
// artifact then epoch.
func (t *RotateTx) HeldWraps() ([]HeldWrap, error) {
	rows, err := t.tx.Query(`SELECT artifact_id, user_id, epoch, wrapped, fp FROM artifact_keys WHERE user_id = ? ORDER BY artifact_id, epoch`, t.userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HeldWrap
	for rows.Next() {
		var h HeldWrap
		if err := rows.Scan(&h.ArtifactID, &h.UserID, &h.Epoch, &h.Wrapped, &h.FP); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetBundle replaces every column of the user's bundle. The auth hash is not
// part of it.
func (t *RotateTx) SetBundle(b Bundle) error {
	_, err := t.tx.Exec(`UPDATE key_bundles SET kdf = ?, mk_password = ?, mk_recovery = ?, x25519_pub = ?, x25519_priv = ?, ed25519_pub = ?, ed25519_priv = ?, ek = ? WHERE user_id = ?`,
		string(b.KDF), b.MKPassword, b.MKRecovery, b.X25519Pub, b.X25519Priv, b.Ed25519Pub, b.Ed25519Priv, b.EK, t.userID)
	return err
}

// PutKeyring stores the user's sealed keyring at rev, with the rule of
// Store.PutKeyring: rev must be one more than the stored rev, and 1 when none
// is stored. Otherwise it returns ErrStale and the stored rev.
func (t *RotateTx) PutKeyring(rev int, sealed []byte) (current int, err error) {
	err = t.tx.QueryRow(`SELECT rev FROM user_keyrings WHERE user_id = ?`, t.userID).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if rev != current+1 {
		return current, ErrStale
	}
	_, err = t.tx.Exec(`INSERT OR REPLACE INTO user_keyrings (user_id, rev, keyring, updated_at) VALUES (?, ?, ?, ?)`, t.userID, rev, sealed, now())
	return rev, err
}

// ReplaceHeldWrap replaces the user's wrap on an artifact at an epoch, and the
// fingerprint it was made to.
func (t *RotateTx) ReplaceHeldWrap(artifactID string, epoch int, wrapped []byte, fp string) error {
	_, err := t.tx.Exec(`UPDATE artifact_keys SET wrapped = ?, fp = ? WHERE artifact_id = ? AND epoch = ? AND user_id = ?`,
		wrapped, fp, artifactID, epoch, t.userID)
	return err
}

// Artifact returns the transaction of an artifact RotateKeys locked.
func (t *RotateTx) Artifact(id string) *ArtifactTx { return &ArtifactTx{tx: t.tx, id: id} }

// OtherUserHasFP reports whether a user other than this one has fp as their
// current fingerprint. Fingerprints are not stored, so each is computed.
func (t *RotateTx) OtherUserHasFP(fp string) (bool, error) {
	rows, err := t.tx.Query(`SELECT `+keyedUserCols+` FROM users u JOIN key_bundles b ON b.user_id = u.id WHERE u.id != ?`, t.userID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		u, err := scanKeyedUser(rows)
		if err != nil {
			return false, err
		}
		if u.FP == fp {
			return true, nil
		}
	}
	return false, rows.Err()
}

// AddRotation stores a rotation record. A seq already stored is an error.
func (t *RotateTx) AddRotation(r Rotation) error {
	_, err := t.tx.Exec(`INSERT INTO user_rotations (`+rotationCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.userID, r.Seq, r.OldFP, r.NewFP, r.Body, r.Sig, r.NewSig, now())
	return err
}

// RevokeAPIKeys revokes every live API key the user has.
func (t *RotateTx) RevokeAPIKeys() error {
	_, err := t.tx.Exec(`UPDATE api_keys SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now(), t.userID)
	return err
}

// CloseOffersToUser closes every open ownership offer made to the user.
func (t *RotateTx) CloseOffersToUser() error {
	_, err := t.tx.Exec(`UPDATE artifact_offers SET state = 'closed' WHERE to_user = ? AND state = 'open'`, t.userID)
	return err
}

// BumpTokenVersion signs out every session of the user.
func (t *RotateTx) BumpTokenVersion() error {
	_, err := t.tx.Exec(`UPDATE users SET token_version = token_version + 1 WHERE id = ?`, t.userID)
	return err
}
