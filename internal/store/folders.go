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

// ErrNotFolder is returned when an item's parent is missing or is not a
// folder.
var ErrNotFolder = errors.New("the parent is not a folder")

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

// checkParent refuses parent as the place for an item whose own subtree
// holds height levels of folders (0 for an artifact, 1 for an empty folder),
// unless parent is a folder and the result stays within MaxFolderDepth. Whose
// folder it is, and whether the caller may place the item there, is the
// server's to decide. An empty parent is the top level, always allowed.
// movingID is the folder being moved, or empty for a create; parent may not
// be it or inside it.
func checkParent(q queryRower, movingID, parent string, height int) error {
	if parent == "" {
		return nil
	}
	var kind string
	err := q.QueryRow(`SELECT kind FROM artifacts WHERE id = ?`, parent).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) || err == nil && kind != KindFolder {
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
// folder parent (empty for the top level), which may belong to someone else.
// The parent must be a folder, within the depth limit, or the answer is
// ErrNotFolder or ErrTooDeep and nothing is written.
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
	if err := checkParent(tx, "", parentID, height); err != nil {
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
// parent is empty. The parent must be a folder, whoever owns it; a folder
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
	var kind string
	if err := tx.QueryRow(`SELECT kind FROM artifacts WHERE id = ?`, id).Scan(&kind); err != nil {
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
	if err := checkParent(tx, id, parent, height); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE artifacts SET parent_id = NULLIF(?, '') WHERE id = ?`, parent, id); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteFolderIfNoneOwned deletes the folder id unless an item its owner owns
// sits in it (ErrFolderNotEmpty). An item someone else owns does not stop it:
// the foreign key moves it to the top level, which is its owner's. The check
// and the delete share one write lock so an item created or moved in
// meanwhile is not orphaned. It is ErrNotFound if there is no such artifact.
func (s *Store) DeleteFolderIfNoneOwned(id string) error {
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
	if err := tx.QueryRow(`SELECT COUNT(*) FROM artifacts c JOIN artifacts f ON f.id = c.parent_id
		WHERE c.parent_id = ? AND c.owner_id = f.owner_id`, id).Scan(&n); err != nil {
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
