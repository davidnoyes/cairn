package store

import (
	"database/sql"
	"errors"
)

// DBRevisionsKept is how many database revisions a version keeps; adding one
// beyond that deletes the oldest.
const DBRevisionsKept = 10

// ErrRevisionMismatch is returned by AddDBRevision when the latest revision
// is not the one the write named.
var ErrRevisionMismatch = errors.New("the latest revision is not the one named")

// DBRevision is one stored database revision. The sealed bytes are a file
// under the layout's dbs tree; Record is the signed revision envelope as JSON.
type DBRevision struct {
	ArtifactID string `json:"-"`
	VersionID  string `json:"-"`
	Revision   int    `json:"revision"`
	Epoch      int    `json:"epoch"`
	Size       int64  `json:"size"`
	Record     []byte `json:"-"`
	SignerKey  []byte `json:"-"`
	WrittenBy  string `json:"writtenBy"`
	CreatedAt  string `json:"createdAt"`
}

const dbRevisionCols = `artifact_id, version_id, revision, epoch, size, record, signer_key, written_by, created_at`

func scanDBRevision(row interface{ Scan(...any) error }) (*DBRevision, error) {
	var r DBRevision
	if err := row.Scan(&r.ArtifactID, &r.VersionID, &r.Revision, &r.Epoch, &r.Size, &r.Record, &r.SignerKey, &r.WrittenBy, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// LatestDBRevision is the version's highest revision, or ErrNotFound.
func (s *Store) LatestDBRevision(artifactID, versionID string) (*DBRevision, error) {
	return scanDBRevision(s.db.QueryRow(`SELECT `+dbRevisionCols+` FROM db_revisions
		WHERE artifact_id = ? AND version_id = ? ORDER BY revision DESC LIMIT 1`, artifactID, versionID))
}

// DBRevisionByNumber is one revision, or ErrNotFound.
func (s *Store) DBRevisionByNumber(artifactID, versionID string, revision int) (*DBRevision, error) {
	return scanDBRevision(s.db.QueryRow(`SELECT `+dbRevisionCols+` FROM db_revisions
		WHERE artifact_id = ? AND version_id = ? AND revision = ?`, artifactID, versionID, revision))
}

// ListDBRevisions returns the revisions kept, newest first.
func (s *Store) ListDBRevisions(artifactID, versionID string) ([]*DBRevision, error) {
	rows, err := s.db.Query(`SELECT `+dbRevisionCols+` FROM db_revisions
		WHERE artifact_id = ? AND version_id = ? ORDER BY revision DESC`, artifactID, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DBRevision{}
	for rows.Next() {
		r, err := scanDBRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddDBRevision stores r as the version's next revision, provided the latest
// revision is ifMatch (0 for none). The comparison and the insert are one
// transaction, so two writes naming the same latest revision cannot both
// land: the other gets ErrRevisionMismatch with the latest revision's number.
// place runs after the insert and before the commit, to move the blob into
// place; if it fails nothing is stored. The revisions beyond DBRevisionsKept
// are deleted, and their numbers returned for the caller to delete the files.
func (s *Store) AddDBRevision(r DBRevision, ifMatch int, place func() error) (latest int, pruned []int, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	err = tx.QueryRow(`SELECT COALESCE(MAX(revision), 0) FROM db_revisions WHERE version_id = ?`, r.VersionID).Scan(&latest)
	if err != nil {
		return 0, nil, err
	}
	if latest != ifMatch {
		return latest, nil, ErrRevisionMismatch
	}
	if _, err := tx.Exec(`INSERT INTO db_revisions (`+dbRevisionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ArtifactID, r.VersionID, r.Revision, r.Epoch, r.Size, r.Record, r.SignerKey, r.WrittenBy, now()); err != nil {
		return 0, nil, err
	}
	rows, err := tx.Query(`SELECT revision FROM db_revisions WHERE version_id = ? AND revision <= ?`, r.VersionID, r.Revision-DBRevisionsKept)
	if err != nil {
		return 0, nil, err
	}
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return 0, nil, err
		}
		pruned = append(pruned, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	if _, err := tx.Exec(`DELETE FROM db_revisions WHERE version_id = ? AND revision <= ?`, r.VersionID, r.Revision-DBRevisionsKept); err != nil {
		return 0, nil, err
	}
	if err := place(); err != nil {
		return 0, nil, err
	}
	if err := tx.Commit(); err != nil {
		return 0, nil, err
	}
	return r.Revision, pruned, nil
}

// StoredFile is one stored file's rows. The server holds no path: Address is
// the only name, and the path is inside the sealed Meta blob.
type StoredFile struct {
	ArtifactID string
	VersionID  string
	Address    string
	Epoch      int
	Size       int64
	Record     []byte
	Meta       []byte
	MetaRecord []byte
	SignerKey  []byte
	WrittenBy  string
	UpdatedAt  string
}

const storedFileCols = `artifact_id, version_id, address, epoch, size, record, meta, meta_record, signer_key, written_by, updated_at`

func scanStoredFile(row interface{ Scan(...any) error }) (*StoredFile, error) {
	var f StoredFile
	if err := row.Scan(&f.ArtifactID, &f.VersionID, &f.Address, &f.Epoch, &f.Size, &f.Record, &f.Meta, &f.MetaRecord, &f.SignerKey, &f.WrittenBy, &f.UpdatedAt); err != nil {
		return nil, err
	}
	return &f, nil
}

// ListStoredFiles returns the version's stored files, by address.
func (s *Store) ListStoredFiles(artifactID, versionID string) ([]*StoredFile, error) {
	rows, err := s.db.Query(`SELECT `+storedFileCols+` FROM stored_files
		WHERE artifact_id = ? AND version_id = ? ORDER BY address`, artifactID, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*StoredFile{}
	for rows.Next() {
		f, err := scanStoredFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// StoredFileByAddress is one stored file, or ErrNotFound.
func (s *Store) StoredFileByAddress(artifactID, versionID, address string) (*StoredFile, error) {
	return scanStoredFile(s.db.QueryRow(`SELECT `+storedFileCols+` FROM stored_files
		WHERE artifact_id = ? AND version_id = ? AND address = ?`, artifactID, versionID, address))
}

// PutStoredFile stores f, replacing any file at its address. place runs after
// the write and before the commit, to move the blob into place; if it fails
// nothing is stored.
func (s *Store) PutStoredFile(f StoredFile, place func() error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR REPLACE INTO stored_files (`+storedFileCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ArtifactID, f.VersionID, f.Address, f.Epoch, f.Size, f.Record, f.Meta, f.MetaRecord, f.SignerKey, f.WrittenBy, now()); err != nil {
		return err
	}
	if err := place(); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteStoredFile removes the row at address, or returns ErrNotFound.
func (s *Store) DeleteStoredFile(artifactID, versionID, address string) error {
	return s.exec1(`DELETE FROM stored_files WHERE artifact_id = ? AND version_id = ? AND address = ?`, artifactID, versionID, address)
}

var _ = sql.ErrNoRows
