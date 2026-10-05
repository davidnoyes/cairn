package store

import (
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

// Artifact is a collection of versions. Its name and description are
// client-encrypted fields (see MetaField); the server holds no plaintext of
// either.
type Artifact struct {
	ID        string      `json:"id"`
	Public    bool        `json:"public"`
	CreatedAt string      `json:"createdAt"`
	UpdatedAt string      `json:"updatedAt"`
	Resources []*Resource `json:"resources,omitempty"`

	// Sharing state, set from the latest membership record. OwnerID is
	// empty for an artifact created without one; Epoch is 0 until the first
	// record lands. PublicTokenHash and PublicEpoch are set only while public.
	OwnerID         string `json:"owner,omitempty"`
	Epoch           int    `json:"epoch"`
	Team            string `json:"team"`
	PublicWrites    bool   `json:"publicWrites"`
	PublicTokenHash string `json:"-"`
	PublicEpoch     int    `json:"-"`
}

// Resource associates an external reference (e.g. a Claude session ID) with an
// artifact. Value is a blind index, never the reference itself.
type Resource struct {
	ID         string `json:"id"`
	ArtifactID string `json:"-"`
	Type       string `json:"type"`
	Value      string `json:"value"`
}

// Version is one uploaded revision of an artifact. ContentDir is the name of
// the extracted directory under content/{artifactID}/; it changes on every
// (re-)upload so replacement is an atomic pointer swap.
type Version struct {
	ID         string `json:"id"`
	ArtifactID string `json:"artifactId"`
	Seq        int    `json:"seq"`
	ContentDir string `json:"-"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`

	// PushedBy is the user who pushed the version, empty if unrecorded.
	// Epoch is the epoch it was written under.
	PushedBy string `json:"pushedBy,omitempty"`
	Epoch    int    `json:"epoch"`
	// ManifestHash is hex(SHA-256) of the manifest envelope's body, as the
	// pusher declared it.
	ManifestHash string `json:"manifestHash"`
}

const artifactCols = `id, public, created_at, updated_at,
	COALESCE(owner_id, ''), epoch, team, public_writes, COALESCE(public_token_hash, ''), COALESCE(public_epoch, 0)`

func scanArtifact(row interface{ Scan(...any) error }) (*Artifact, error) {
	var a Artifact
	if err := row.Scan(&a.ID, &a.Public, &a.CreatedAt, &a.UpdatedAt,
		&a.OwnerID, &a.Epoch, &a.Team, &a.PublicWrites, &a.PublicTokenHash, &a.PublicEpoch); err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) CreateArtifact(public bool) (*Artifact, error) {
	t := now()
	a := &Artifact{ID: uuid.NewString(), Public: public, CreatedAt: t, UpdatedAt: t}
	_, err := s.db.Exec(`INSERT INTO artifacts (id, public, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		a.ID, a.Public, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) ArtifactByID(id string) (*Artifact, error) {
	return scanArtifact(s.db.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE id = ?`, id))
}

// ArtifactsByResource returns the artifacts associated with a resource,
// matched by resource value (a blind index) or resource row id.
func (s *Store) ArtifactsByResource(ref string) ([]*Artifact, error) {
	rows, err := s.db.Query(`SELECT `+artifactCols+` FROM artifacts
		WHERE id IN (SELECT artifact_id FROM artifact_resources WHERE value = ? OR id = ?)
		ORDER BY created_at`, ref, ref)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Artifact
	for rows.Next() {
		a, err := scanArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ListArtifacts() ([]*Artifact, error) {
	rows, err := s.db.Query(`SELECT ` + artifactCols + ` FROM artifacts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Artifact
	for rows.Next() {
		a, err := scanArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) DeleteArtifact(id string) error {
	return s.exec1(`DELETE FROM artifacts WHERE id = ?`, id)
}

// DeleteArtifactOfDisabledOwner deletes an artifact only if its owner's
// account is disabled, in one statement, so an artifact handed to an active
// owner after the caller looked is not deleted. It is ErrOwnerActive if the
// owner is active, and ErrNotFound if there is no such artifact.
func (s *Store) DeleteArtifactOfDisabledOwner(id string) error {
	err := s.exec1(`DELETE FROM artifacts WHERE id = ?
		AND owner_id IN (SELECT id FROM users WHERE disabled)`, id)
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	if _, err := s.ArtifactByID(id); err != nil {
		return err
	}
	return ErrOwnerActive
}

func (s *Store) touchArtifact(id string) {
	s.db.Exec(`UPDATE artifacts SET updated_at = ? WHERE id = ?`, now(), id)
}

// Resources

func (s *Store) AddResource(artifactID, typ, value string) (*Resource, error) {
	r := &Resource{ID: uuid.NewString(), ArtifactID: artifactID, Type: typ, Value: value}
	_, err := s.db.Exec(`INSERT INTO artifact_resources (id, artifact_id, type, value) VALUES (?, ?, ?, ?)`,
		r.ID, r.ArtifactID, r.Type, r.Value)
	if err != nil {
		return nil, err
	}
	s.touchArtifact(artifactID)
	return r, nil
}

func (s *Store) ListResources(artifactID string) ([]*Resource, error) {
	rows, err := s.db.Query(`SELECT id, artifact_id, type, value FROM artifact_resources WHERE artifact_id = ?`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Resource
	for rows.Next() {
		var r Resource
		if err := rows.Scan(&r.ID, &r.ArtifactID, &r.Type, &r.Value); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteResource(artifactID, resourceID string) error {
	return s.exec1(`DELETE FROM artifact_resources WHERE id = ? AND artifact_id = ?`, resourceID, artifactID)
}

// Versions

const versionCols = `id, artifact_id, seq, content_dir, created_at, updated_at, COALESCE(pushed_by, ''), epoch, manifest_hash`

func scanVersion(row interface{ Scan(...any) error }) (*Version, error) {
	var v Version
	if err := row.Scan(&v.ID, &v.ArtifactID, &v.Seq, &v.ContentDir, &v.CreatedAt, &v.UpdatedAt, &v.PushedBy, &v.Epoch, &v.ManifestHash); err != nil {
		return nil, err
	}
	return &v, nil
}

// CreateVersion inserts the next version under the ID the client chose,
// stamped with its pusher, its manifest hash, and the artifact's epoch. An ID
// any version already uses is ErrExists. The INSERT reads the epoch itself, so no epoch change can
// land between the read and the write. A declaredEpoch other than 0 must be
// the artifact's current epoch, checked by the same statement; otherwise
// nothing is written and the answer is ErrEpochMoved.
func (s *Store) CreateVersion(artifactID, versionID, contentDir, pushedBy, manifestHash string, declaredEpoch int) (*Version, error) {
	t := now()
	v := &Version{ID: versionID, ArtifactID: artifactID, ContentDir: contentDir, CreatedAt: t, UpdatedAt: t, PushedBy: pushedBy, ManifestHash: manifestHash}
	err := s.db.QueryRow(`INSERT INTO versions (id, artifact_id, seq, content_dir, created_at, updated_at, pushed_by, epoch, manifest_hash)
		SELECT ?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM versions WHERE artifact_id = ?), ?, ?, ?, NULLIF(?, ''), epoch, ?
		FROM artifacts WHERE id = ? AND (? = 0 OR epoch = ?)
		RETURNING seq, epoch`,
		v.ID, v.ArtifactID, artifactID, v.ContentDir, v.CreatedAt, v.UpdatedAt, pushedBy, manifestHash, artifactID,
		declaredEpoch, declaredEpoch).Scan(&v.Seq, &v.Epoch)
	if isUniqueViolation(err) {
		// The version ID is unique across every artifact, so a clash can be
		// another artifact's version.
		return nil, ErrExists
	}
	if errors.Is(err, sql.ErrNoRows) {
		// No row means no such artifact, or an epoch other than the declared one.
		var exists bool
		if aerr := s.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM artifacts WHERE id = ?)`, artifactID).Scan(&exists); aerr != nil {
			return nil, aerr
		}
		if !exists {
			return nil, ErrNotFound
		}
		return nil, ErrEpochMoved
	}
	if err != nil {
		return nil, err
	}
	s.touchArtifact(artifactID)
	return v, nil
}

func (s *Store) VersionByID(artifactID, versionID string) (*Version, error) {
	return scanVersion(s.db.QueryRow(`SELECT `+versionCols+` FROM versions WHERE id = ? AND artifact_id = ?`, versionID, artifactID))
}

func (s *Store) LatestVersion(artifactID string) (*Version, error) {
	return scanVersion(s.db.QueryRow(`SELECT `+versionCols+` FROM versions WHERE artifact_id = ? ORDER BY seq DESC LIMIT 1`, artifactID))
}

func (s *Store) ListVersions(artifactID string) ([]*Version, error) {
	rows, err := s.db.Query(`SELECT `+versionCols+` FROM versions WHERE artifact_id = ? ORDER BY seq DESC`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SwapVersionContent atomically points a version at a freshly extracted
// content dir (re-upload), restamping its pusher, manifest hash, and the
// artifact's epoch in the same transaction. Returns the previous content dir for cleanup. A
// declaredEpoch other than 0 must be the artifact's current epoch, checked by
// the UPDATE itself; otherwise nothing changes and the answer is
// ErrEpochMoved.
func (s *Store) SwapVersionContent(artifactID, versionID, contentDir, pushedBy, manifestHash string, declaredEpoch int) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var prev string
	if err := tx.QueryRow(`SELECT content_dir FROM versions WHERE id = ? AND artifact_id = ?`, versionID, artifactID).Scan(&prev); err != nil {
		return "", err
	}
	res, err := tx.Exec(`UPDATE versions SET content_dir = ?, updated_at = ?, pushed_by = NULLIF(?, ''),
		manifest_hash = ?, epoch = (SELECT epoch FROM artifacts WHERE id = ?) WHERE id = ?
		AND (? = 0 OR (SELECT epoch FROM artifacts WHERE id = ?) = ?)`,
		contentDir, now(), pushedBy, manifestHash, artifactID, versionID, declaredEpoch, artifactID, declaredEpoch)
	if err != nil {
		return "", err
	}
	if n, err := res.RowsAffected(); err != nil {
		return "", err
	} else if n == 0 {
		return "", ErrEpochMoved
	}
	// A vouch covers the content the owner reviewed, not its replacement.
	if _, err := tx.Exec(`DELETE FROM version_vouches WHERE version_id = ?`, versionID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	s.touchArtifact(artifactID)
	return prev, nil
}

func (s *Store) DeleteVersion(artifactID, versionID string) error {
	return s.exec1(`DELETE FROM versions WHERE id = ? AND artifact_id = ?`, versionID, artifactID)
}

// MetaField is one encrypted metadata field: the sealed blob, the signed
// record that covers it, and the Ed25519 key the record verified under when it
// was written. VersionID is empty for an artifact's own fields.
type MetaField struct {
	ArtifactID string
	VersionID  string
	Field      string
	Record     []byte
	SignerKey  []byte
	Blob       []byte
}

// PutMetaField stores f, replacing the field's earlier write. A field of a
// version that does not exist, or was deleted since the caller looked, is
// ErrNotFound.
func (s *Store) PutMetaField(f MetaField) error {
	res, err := s.db.Exec(`INSERT INTO meta_fields (artifact_id, version_id, field, record, signer_key, blob)
		SELECT ?, ?, ?, ?, ?, ?
		WHERE ? = '' OR EXISTS (SELECT 1 FROM versions WHERE id = ? AND artifact_id = ?)
		ON CONFLICT (artifact_id, version_id, field) DO UPDATE SET record = excluded.record, signer_key = excluded.signer_key, blob = excluded.blob`,
		f.ArtifactID, f.VersionID, f.Field, f.Record, f.SignerKey, f.Blob,
		f.VersionID, f.VersionID, f.ArtifactID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	s.touchArtifact(f.ArtifactID)
	return nil
}

// ListMetaFields returns every field of the artifact and of its versions.
func (s *Store) ListMetaFields(artifactID string) ([]MetaField, error) {
	rows, err := s.db.Query(`SELECT artifact_id, version_id, field, record, signer_key, blob FROM meta_fields
		WHERE artifact_id = ? ORDER BY version_id, field`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetaField
	for rows.Next() {
		var f MetaField
		if err := rows.Scan(&f.ArtifactID, &f.VersionID, &f.Field, &f.Record, &f.SignerKey, &f.Blob); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
