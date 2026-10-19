package store

import "time"

// GroupMember is a member the latest group record lists, a copy of what its
// body says, parsed and checked by the caller. Role is member or manager.
type GroupMember struct {
	UserID string
	Role   string
	FP     string
}

// GroupHead is a group and its latest record, stored verbatim.
type GroupHead struct {
	ID     string
	Seq    int
	Record Envelope
}

// GroupRecords returns a group's records, oldest first, or ErrNotFound when
// there is no such group.
func (s *Store) GroupRecords(id string) ([]Envelope, error) {
	rows, err := s.db.Query(`SELECT body, sig, signer FROM group_records WHERE group_id = ? ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Envelope
	for rows.Next() {
		var e Envelope
		if err := rows.Scan(&e.Body, &e.Sig, &e.Signer); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// Groups returns every group with its latest record, oldest group first.
func (s *Store) Groups() ([]GroupHead, error) {
	rows, err := s.db.Query(`SELECT g.id, r.seq, r.body, r.sig, r.signer FROM groups g
		JOIN group_records r ON r.group_id = g.id AND r.seq = (SELECT MAX(seq) FROM group_records WHERE group_id = g.id)
		ORDER BY g.created_at, g.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupHead
	for rows.Next() {
		var h GroupHead
		if err := rows.Scan(&h.ID, &h.Seq, &h.Record.Body, &h.Record.Sig, &h.Record.Signer); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// GroupMembers returns the members the group's latest record lists, ordered
// by user ID.
func (s *Store) GroupMembers(id string) ([]GroupMember, error) {
	rows, err := s.db.Query(`SELECT user_id, role, fp FROM group_members WHERE group_id = ? ORDER BY user_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupMember
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Role, &m.FP); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddGroupRecord stores a `group` record at seq and replaces the group's
// members with those the record lists, in one transaction. Seq 1 creates the
// group. A seq that is not one more than the last, which includes a first
// record for a group that exists, is ErrStale, with that last seq in last.
// A member whose account is gone is left out of group_members: the record
// carries such an entry over unchanged, and the signed record still lists it.
func (s *Store) AddGroupRecord(id string, seq int, rec Envelope, members []GroupMember, at time.Time) (last int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM group_records WHERE group_id = ?`, id).Scan(&last); err != nil {
		return 0, err
	}
	if seq != last+1 {
		return last, ErrStale
	}
	if seq == 1 {
		if _, err := tx.Exec(`INSERT INTO groups (id, created_at) VALUES (?, ?)`, id, formatTime(at)); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`INSERT INTO group_records (group_id, seq, body, sig, signer) VALUES (?, ?, ?, ?, ?)`,
		id, seq, rec.Body, rec.Sig, rec.Signer); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM group_members WHERE group_id = ?`, id); err != nil {
		return 0, err
	}
	for _, m := range members {
		if _, err := tx.Exec(`INSERT INTO group_members (group_id, user_id, role, fp)
			SELECT ?, id, ?, ? FROM users WHERE id = ?`, id, m.Role, m.FP, m.UserID); err != nil {
			return 0, err
		}
	}
	return seq, tx.Commit()
}

// DeleteGroup deletes a group with its records and members, or returns
// ErrNotFound.
func (s *Store) DeleteGroup(id string) error {
	res, err := s.db.Exec(`DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// KeyedUserByID reads a user and their current keys. A missing user is
// ErrNotFound.
func (s *Store) KeyedUserByID(id string) (*KeyedUser, error) {
	return scanKeyedUser(s.db.QueryRow(`SELECT `+keyedUserCols+` FROM users u JOIN key_bundles b ON b.user_id = u.id WHERE u.id = ?`, id))
}
