package store

import (
	"database/sql"
	"errors"
	"time"
)

// SuccessionWait is how long a request waits before the successor is
// released: 14 days by the server's clock.
const SuccessionWait = 14 * 24 * time.Hour

// ErrReleased is returned when a refusal comes after the release: a release
// cannot be refused.
var ErrReleased = errors.New("the successor was already released")

// Successor is a user's current nomination. Record is the signed `successor`
// record that made it, stored verbatim; Seq is that record's seq. RequestedAt
// is empty until the successor asks, DeactivatedAt empty unless an
// administrator deactivated the user during the request.
type Successor struct {
	UserID        string
	SuccessorID   string
	Seq           int
	Record        Envelope
	Wrapped       []byte
	NominatedAt   string
	RequestedAt   string
	DeactivatedAt string
}

// Requested reports whether the successor has asked.
func (sc *Successor) Requested() bool { return sc.RequestedAt != "" }

// ReleaseAt is when the request releases the successor: the request's time
// plus SuccessionWait. It is the zero time when there is no request, or when
// the stored time does not parse, which Released treats as never.
func (sc *Successor) ReleaseAt() time.Time {
	t, err := time.Parse(time.RFC3339, sc.RequestedAt)
	if err != nil {
		return time.Time{}
	}
	return t.Add(SuccessionWait)
}

// Released reports whether the request is at or past its release at now.
// Nothing is stored at that moment: every read compares the time.
func (sc *Successor) Released(now time.Time) bool {
	at := sc.ReleaseAt()
	return !at.IsZero() && !now.Before(at)
}

const successorCols = `s.user_id, s.successor_id, s.record_seq, r.body, r.sig, r.signer, s.wrapped, s.nominated_at, COALESCE(s.requested_at, ''), COALESCE(s.deactivated_at, '')`

const successorFrom = ` FROM successors s JOIN successor_records r ON r.user_id = s.user_id AND r.seq = s.record_seq `

func scanSuccessor(row interface{ Scan(...any) error }) (*Successor, error) {
	var sc Successor
	if err := row.Scan(&sc.UserID, &sc.SuccessorID, &sc.Seq, &sc.Record.Body, &sc.Record.Sig, &sc.Record.Signer,
		&sc.Wrapped, &sc.NominatedAt, &sc.RequestedAt, &sc.DeactivatedAt); err != nil {
		return nil, err
	}
	return &sc, nil
}

func querySuccessor(q interface {
	QueryRow(query string, args ...any) *sql.Row
}, userID string) (*Successor, error) {
	return scanSuccessor(q.QueryRow(`SELECT `+successorCols+successorFrom+`WHERE s.user_id = ?`, userID))
}

// SuccessorOf returns the user's current nomination, or ErrNotFound.
func (s *Store) SuccessorOf(userID string) (*Successor, error) {
	return querySuccessor(s.db, userID)
}

// SuccessorOf returns the user's current nomination inside the transaction,
// or ErrNotFound.
func (t *ArtifactTx) SuccessorOf(userID string) (*Successor, error) {
	return querySuccessor(t.tx, userID)
}

// LatestSuccessorRecord returns the user's latest successor record, a
// nomination or a removal, or ErrNotFound when they never signed one.
func (t *ArtifactTx) LatestSuccessorRecord(userID string) (*Envelope, error) {
	var e Envelope
	err := t.tx.QueryRow(`SELECT body, sig, signer FROM successor_records WHERE user_id = ? ORDER BY seq DESC LIMIT 1`, userID).
		Scan(&e.Body, &e.Sig, &e.Signer)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func lastSuccessorSeq(q interface {
	QueryRow(query string, args ...any) *sql.Row
}, userID string) (int, error) {
	var seq int
	err := q.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM successor_records WHERE user_id = ?`, userID).Scan(&seq)
	return seq, err
}

// LastSuccessorSeq is the seq of the last successor record the user signed, 0
// when there is none.
func (s *Store) LastSuccessorSeq(userID string) (int, error) {
	return lastSuccessorSeq(s.db, userID)
}

// SuccessionsTo returns every nomination that names successorID, oldest
// first.
func (s *Store) SuccessionsTo(successorID string) ([]*Successor, error) {
	rows, err := s.db.Query(`SELECT `+successorCols+successorFrom+`WHERE s.successor_id = ? ORDER BY s.nominated_at, s.user_id`, successorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Successor
	for rows.Next() {
		sc, err := scanSuccessor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// Nominate stores a `successor` record at seq and makes it the user's
// nomination of successorID with the wrapped EK, in one transaction. An
// earlier nomination, and any request on it, goes: prev is that nomination,
// nil when there was none. A nomination already released at the time at is
// ErrReleased: it can be neither replaced nor removed. A seq that is not one
// more than the last is ErrStale, with that last seq in last.
func (s *Store) Nominate(userID, successorID string, seq int, rec Envelope, wrapped []byte, at time.Time) (prev *Successor, last int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	prev, err = querySuccessor(tx, userID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, 0, err
	}
	if prev != nil && prev.Released(at) {
		return nil, 0, ErrReleased
	}
	if last, err = lastSuccessorSeq(tx, userID); err != nil {
		return nil, 0, err
	}
	if seq != last+1 {
		return nil, last, ErrStale
	}
	if err := putSuccessorRecord(tx, userID, seq, rec, at); err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(`DELETE FROM successors WHERE user_id = ?`, userID); err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(`INSERT INTO successors (user_id, successor_id, record_seq, wrapped, nominated_at) VALUES (?, ?, ?, ?, ?)`,
		userID, successorID, seq, wrapped, formatTime(at)); err != nil {
		return nil, 0, err
	}
	return prev, seq, tx.Commit()
}

// RemoveSuccessor stores a `successor` record at seq and deletes the user's
// nomination, its wrapped copy, and any request, in one transaction. prev is
// the nomination that went. No nomination is ErrNotFound; one already
// released at the time at is ErrReleased; a seq that is not one more than the
// last is ErrStale, with that last seq in last.
func (s *Store) RemoveSuccessor(userID string, seq int, rec Envelope, at time.Time) (prev *Successor, last int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	if prev, err = querySuccessor(tx, userID); err != nil {
		return nil, 0, err
	}
	if prev.Released(at) {
		return nil, 0, ErrReleased
	}
	if last, err = lastSuccessorSeq(tx, userID); err != nil {
		return nil, 0, err
	}
	if seq != last+1 {
		return nil, last, ErrStale
	}
	if err := putSuccessorRecord(tx, userID, seq, rec, at); err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(`DELETE FROM successors WHERE user_id = ?`, userID); err != nil {
		return nil, 0, err
	}
	return prev, seq, tx.Commit()
}

func putSuccessorRecord(tx *sql.Tx, userID string, seq int, rec Envelope, at time.Time) error {
	_, err := tx.Exec(`INSERT INTO successor_records (user_id, seq, body, sig, signer, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		userID, seq, rec.Body, rec.Sig, rec.Signer, formatTime(at))
	return err
}

// RequestSuccession records the time successorID asked. The check that
// successorID is still the nominee and the write are one transaction, so a
// request from a successor the user has just replaced never lands on the new
// nomination. No nomination, or one naming someone else, is ErrNotFound; a
// request already made, pending or released, is ErrExists.
func (s *Store) RequestSuccession(userID, successorID string, at time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	sc, err := querySuccessor(tx, userID)
	if err != nil {
		return err
	}
	switch {
	case sc.SuccessorID != successorID:
		return ErrNotFound
	case sc.Requested():
		return ErrExists
	}
	if _, err := tx.Exec(`UPDATE successors SET requested_at = ? WHERE user_id = ?`, formatTime(at), userID); err != nil {
		return err
	}
	return tx.Commit()
}

// RefuseSuccession ends the user's pending request and keeps the nomination.
// prev is the nomination as it stood, with the request's time and any
// deactivation. No request is ErrNotFound; one at or past its release at now
// is ErrReleased.
func (s *Store) RefuseSuccession(userID string, now time.Time) (prev *Successor, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if prev, err = querySuccessor(tx, userID); err != nil {
		return nil, err
	}
	switch {
	case !prev.Requested():
		return nil, ErrNotFound
	case prev.Released(now):
		return nil, ErrReleased
	}
	if _, err := tx.Exec(`UPDATE successors SET requested_at = NULL, deactivated_at = NULL WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	return prev, tx.Commit()
}

// DeactivateUser disables an account, as SetUserDisabled does, and in the
// same transaction records the time on a pending request, so an
// administrator cannot deactivate the user without it showing on the refusal
// page. A time already recorded stays. No user is ErrNotFound.
func (s *Store) DeactivateUser(userID string, at time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE users SET disabled = 1, token_version = token_version + 1 WHERE id = ?`, userID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE successors SET deactivated_at = ? WHERE user_id = ? AND requested_at IS NOT NULL AND deactivated_at IS NULL`,
		formatTime(at), userID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteSuccessor deletes the user's nomination, its wrapped copy, and any
// request. The records stay, so seq keeps going up.
func (t *RotateTx) DeleteSuccessor() error {
	_, err := t.tx.Exec(`DELETE FROM successors WHERE user_id = ?`, t.userID)
	return err
}

// Notice address

// SetNoticeEmailPending stores an address that waits for its verification
// link. The verified address, if any, stays in use until it is confirmed.
func (s *Store) SetNoticeEmailPending(userID, email string) error {
	return s.exec1(`UPDATE users SET notice_email_pending = ? WHERE id = ?`, normalizeEmail(email), userID)
}

// ClearNoticeEmail removes the verified address and any pending one.
func (s *Store) ClearNoticeEmail(userID string) error {
	return s.exec1(`UPDATE users SET notice_email = NULL, notice_email_pending = NULL WHERE id = ?`, userID)
}

// ConfirmNoticeEmail makes the pending address the verified one. No pending
// address is ErrNotFound.
func (s *Store) ConfirmNoticeEmail(userID string) error {
	return s.exec1(`UPDATE users SET notice_email = notice_email_pending, notice_email_pending = NULL WHERE id = ? AND notice_email_pending IS NOT NULL`, userID)
}
