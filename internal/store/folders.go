package store

import (
	"database/sql"
	"errors"
)

// The kinds of artifact row. A folder is an artifact with no content: no
// versions, database, or files.
const (
	KindArtifact = "artifact"
	KindFolder   = "folder"
)

// MaxFolderDepth is the most folders a chain may hold, from the top level
// down to an item's parent.
const MaxFolderDepth = 16

// ErrNotFolder is returned when an item's parent is missing, is not a folder,
// or belongs to someone other than the item's owner.
var ErrNotFolder = errors.New("the parent is not a folder of the item's owner")

// ErrCycle is returned when a folder would move into itself or into a folder
// inside it.
var ErrCycle = errors.New("a folder cannot move into itself or a folder inside it")

// ErrTooDeep is returned when a create or move would put a folder deeper than
// MaxFolderDepth.
var ErrTooDeep = errors.New("folders are nested too deeply")

// ErrFolderNotEmpty is returned when a folder with items in it is deleted.
var ErrFolderNotEmpty = errors.New("the folder is not empty")

// queryRower is what the placement checks read through: a transaction.
type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

// checkParent refuses parent as the place for an item owned by owner whose
// own subtree holds height levels of folders (0 for an artifact, 1 for an
// empty folder), unless parent is a folder of the same owner and the result
// stays within MaxFolderDepth. An empty parent is the top level, always
// allowed. movingID is the folder being moved, or empty for a create; parent
// may not be it or inside it.
func checkParent(q queryRower, movingID, owner, parent string, height int) error {
	if parent == "" {
		return nil
	}
	var kind, parentOwner string
	err := q.QueryRow(`SELECT kind, COALESCE(owner_id, '') FROM artifacts WHERE id = ?`, parent).Scan(&kind, &parentOwner)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (kind != KindFolder || parentOwner != owner) {
		return ErrNotFolder
	}
	if err != nil {
		return err
	}
	// Walk up from the parent: the chain's length is its depth, and meeting
	// the moving folder means the parent sits inside it.
	var depth, cyclic int
	err = q.QueryRow(`WITH RECURSIVE up(id, parent_id, n) AS (
			SELECT id, parent_id, 1 FROM artifacts WHERE id = ?
			UNION ALL
			SELECT a.id, a.parent_id, up.n + 1 FROM artifacts a JOIN up ON a.id = up.parent_id)
		SELECT COALESCE(MAX(n), 0), COALESCE(MAX(id = ?), 0) FROM up`, parent, movingID).Scan(&depth, &cyclic)
	if err != nil {
		return err
	}
	if movingID != "" && cyclic == 1 {
		return ErrCycle
	}
	if depth+height > MaxFolderDepth {
		return ErrTooDeep
	}
	return nil
}

// CreateOwnedItem is CreateOwnedArtifact for either kind, placed in the
// folder parent (empty for the top level). The parent must be a folder the
// owner owns, within the depth limit, or the answer is ErrNotFolder or
// ErrTooDeep and nothing is written.
func (s *Store) CreateOwnedItem(id, ownerID, kind, parentID string, fn func(*ArtifactTx) error) (*Artifact, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	height := 0
	if kind == KindFolder {
		height = 1
	}
	if err := checkParent(tx, "", ownerID, parentID, height); err != nil {
		return nil, err
	}
	t := now()
	if _, err := tx.Exec(`INSERT INTO artifacts (id, owner_id, kind, parent_id, created_at, updated_at) VALUES (?, ?, ?, NULLIF(?, ''), ?, ?)`,
		id, ownerID, kind, parentID, t, t); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrExists
		}
		return nil, err
	}
	if fn != nil {
		if err := fn(&ArtifactTx{tx: tx, id: id}); err != nil {
			return nil, err
		}
	}
	a, err := scanArtifact(tx.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return a, nil
}

// MoveItem puts the item in the folder parent, or at the top level when
// parent is empty. The parent must be a folder of the item's owner; a folder
// may not move into itself or a folder inside it (ErrCycle), and the deepest
// folder of a moved subtree must stay within MaxFolderDepth (ErrTooDeep). A
// missing item is ErrNotFound. The checks and the write share one
// transaction.
func (s *Store) MoveItem(id, parent string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A no-op write takes SQLite's write lock now, so no other move lands
	// between the checks and the update.
	res, err := tx.Exec(`UPDATE artifacts SET id = id WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	var kind, owner string
	if err := tx.QueryRow(`SELECT kind, COALESCE(owner_id, '') FROM artifacts WHERE id = ?`, id).Scan(&kind, &owner); err != nil {
		return err
	}
	height := 0
	if kind == KindFolder {
		// The levels of folders under id, itself included.
		if err := tx.QueryRow(`WITH RECURSIVE down(id, n) AS (
				SELECT id, 1 FROM artifacts WHERE id = ?
				UNION ALL
				SELECT a.id, down.n + 1 FROM artifacts a JOIN down ON a.parent_id = down.id WHERE a.kind = 'folder')
			SELECT COALESCE(MAX(n), 0) FROM down`, id).Scan(&height); err != nil {
			return err
		}
	}
	if err := checkParent(tx, id, owner, parent, height); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE artifacts SET parent_id = NULLIF(?, '') WHERE id = ?`, parent, id); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteFolderIfEmpty deletes the folder id unless an item sits in it
// (ErrFolderNotEmpty), checking and deleting under one write lock so an item
// created or moved in meanwhile is not orphaned. It is ErrNotFound if there
// is no such artifact.
func (s *Store) DeleteFolderIfEmpty(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A no-op write takes SQLite's write lock now, before the count.
	if _, err := tx.Exec(`UPDATE artifacts SET id = id WHERE id = ?`, id); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM artifacts WHERE parent_id = ?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrFolderNotEmpty
	}
	res, err := tx.Exec(`DELETE FROM artifacts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}
