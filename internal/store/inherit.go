package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
)

// rowQuerier is what the inheritance reads run through: a transaction, or
// the database.
type rowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

// maxAncestors bounds the walk up a folder chain, so a loop in the data
// cannot hang a request. The depth rule keeps real chains well inside it.
const maxAncestors = 4 * MaxFolderDepth

// ancestorIDs returns the IDs of the folders above artifact id, nearest
// first. A missing artifact has none.
func ancestorIDs(q rowQuerier, id string) ([]string, error) {
	var out []string
	for len(out) < maxAncestors {
		var parent string
		err := q.QueryRow(`SELECT COALESCE(parent_id, '') FROM artifacts WHERE id = ?`, id).Scan(&parent)
		if errors.Is(err, sql.ErrNoRows) || err == nil && parent == "" {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, parent)
		id = parent
	}
	return out, nil
}

// viaCheck decides whether an entry's via still holds for one artifact: the
// folder it names contains the artifact, and that folder's latest record
// still lists the user or group. It looks the artifact's ancestors up the
// first time an entry has a via, so a direct grant costs nothing.
type viaCheck struct {
	q         rowQuerier
	id        string
	ancestors []string
	loaded    bool
}

// holds reports whether the entry for who, a group ID when group is true and
// a user ID otherwise, still counts under via, and the role via's latest
// record lists them under, which is manager for the folder's owner. An empty
// via is a direct grant, which always counts and has no folder's role to
// report.
func (v *viaCheck) holds(via string, group bool, who string) (ok bool, role string, err error) {
	if via == "" {
		return true, "", nil
	}
	if !v.loaded {
		anc, err := ancestorIDs(v.q, v.id)
		if err != nil {
			return false, "", err
		}
		v.ancestors, v.loaded = anc, true
	}
	if !slices.Contains(v.ancestors, via) {
		return false, "", nil
	}
	query := `SELECT role FROM artifact_members WHERE artifact_id = ? AND user_id = ?`
	if group {
		query = `SELECT role FROM artifact_groups WHERE artifact_id = ? AND group_id = ?`
	}
	err = v.q.QueryRow(query, via, who).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) && !group {
		// A folder lists its owner as its owner, not as a member, and the
		// owner manages what is in it.
		err = v.q.QueryRow(`SELECT 'manager' FROM artifacts WHERE id = ? AND owner_id = ?`, via, who).Scan(&role)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	return err == nil, role, err
}

// roleRank orders the roles an entry grants: viewer, editor, manager.
func roleRank(role string) int {
	switch role {
	case "manager":
		return 3
	case "editor":
		return 2
	}
	return 1
}

// viaEntry is a member or group entry that carries a via, with its role.
type viaEntry struct {
	who, via, role string
	group          bool
}

// viaEntries lists the entries of artifact id's latest record that carry a
// via, members first.
func viaEntries(q rowQuerier, id string) ([]viaEntry, error) {
	var out []viaEntry
	for _, group := range []bool{false, true} {
		query := `SELECT user_id, via, role FROM artifact_members WHERE artifact_id = ? AND via != '' ORDER BY user_id`
		if group {
			query = `SELECT group_id, via, role FROM artifact_groups WHERE artifact_id = ? AND via != '' ORDER BY group_id`
		}
		rows, err := q.Query(query, id)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			e := viaEntry{group: group}
			if err := rows.Scan(&e.who, &e.via, &e.role); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// viaState reads artifact id's entries that carry a via: the user IDs and
// the group IDs whose via no longer holds, and whether any that does hold
// carries a higher role than its folder lists now.
func viaState(q rowQuerier, id string) (users, groups map[string]bool, lowered bool, err error) {
	entries, err := viaEntries(q, id)
	if err != nil {
		return nil, nil, false, err
	}
	users, groups = map[string]bool{}, map[string]bool{}
	check := &viaCheck{q: q, id: id}
	for _, e := range entries {
		ok, role, err := check.holds(e.via, e.group, e.who)
		if err != nil {
			return nil, nil, false, err
		}
		switch {
		case ok:
			lowered = lowered || roleRank(e.role) > roleRank(role)
		case e.group:
			groups[e.who] = true
		default:
			users[e.who] = true
		}
	}
	return users, groups, lowered, nil
}

// LapsedVia returns the IDs of the users and of the groups whose entries in
// the artifact's latest record carry a via that no longer holds: the folder
// no longer contains the artifact, or no longer lists them. They grant
// nothing, and the next epoch drops them.
func (t *ArtifactTx) LapsedVia() (users, groups map[string]bool, err error) {
	users, groups, _, err = viaState(t.tx, t.id)
	return users, groups, err
}

// Ancestors returns the IDs of the folders above the artifact, nearest
// first.
func (t *ArtifactTx) Ancestors() ([]string, error) { return ancestorIDs(t.tx, t.id) }

// LatestRecordOf returns the newest membership record of artifact id, or
// ErrNotFound when it has none.
func (t *ArtifactTx) LatestRecordOf(id string) (*Record, error) {
	r, err := scanRecord(t.tx.QueryRow(`SELECT `+recordCols+` FROM artifact_records WHERE artifact_id = ? ORDER BY seq DESC LIMIT 1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// recordNamesOtherFolder reports whether artifact a's latest record names a
// folder other than the one the server's tree puts a in, which is so after a
// move until the owner writes a record that names the new folder. An artifact
// with no record yet names none.
func recordNamesOtherFolder(q rowQuerier, a *Artifact) (bool, error) {
	var body []byte
	err := q.QueryRow(`SELECT body FROM artifact_records WHERE artifact_id = ? ORDER BY seq DESC LIMIT 1`, a.ID).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var b struct {
		Folder string `json:"folder"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return false, err
	}
	return b.Folder != a.ParentID, nil
}

// InheritPending reports whether artifact a's latest record is out of step
// with its folder: it names another folder than a sits in, or lacks a user or
// group the folder lists, or lists one at a lower role, or holds an entry
// whose via no longer holds, or whose role is above what its folder lists
// them as now, or lacks the owner of its folder as a manager. A group that
// was deleted is not required, because it grants nothing, and neither is a user
// whose account is deactivated or not verified, because a record may not add
// one, nor the item's own owner.
func (s *Store) InheritPending(a *Artifact) (bool, error) {
	id := a.ID
	if moved, err := recordNamesOtherFolder(s.db, a); err != nil || moved {
		return moved, err
	}
	users, groups, lowered, err := viaState(s.db, id)
	if err != nil {
		return false, err
	}
	if len(users) > 0 || len(groups) > 0 || lowered {
		return true, nil
	}
	if a.ParentID == "" {
		return false, nil
	}
	var missing bool
	err = s.db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM artifact_members p
			LEFT JOIN artifact_members m ON m.artifact_id = ? AND m.user_id = p.user_id
			WHERE p.artifact_id = ? AND p.user_id != ?
			AND p.user_id IN (SELECT id FROM users WHERE disabled = 0 AND verified_at IS NOT NULL)
			AND (m.user_id IS NULL OR (CASE m.role WHEN 'manager' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END)
				< (CASE p.role WHEN 'manager' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END))
		) OR EXISTS (
			SELECT 1 FROM artifact_groups p
			LEFT JOIN artifact_groups m ON m.artifact_id = ? AND m.group_id = p.group_id
			WHERE p.artifact_id = ? AND p.group_id IN (SELECT id FROM groups)
			AND (m.group_id IS NULL OR (CASE m.role WHEN 'editor' THEN 2 ELSE 1 END)
				< (CASE p.role WHEN 'editor' THEN 2 ELSE 1 END))
		) OR EXISTS (
			-- the folder's owner: the 6th, 7th and 8th ?, the item's ID, its
			-- folder's ID and its owner's ID
			SELECT 1 FROM artifacts f
			LEFT JOIN artifact_members m ON m.artifact_id = ? AND m.user_id = f.owner_id
			WHERE f.id = ? AND f.owner_id != ?
			AND f.owner_id IN (SELECT id FROM users WHERE verified_at IS NOT NULL AND disabled = 0)
			AND (m.role IS NULL OR m.role != 'manager')
		)`, id, a.ParentID, a.OwnerID, id, a.ParentID, id, a.ParentID, a.OwnerID).Scan(&missing)
	return missing, err
}
