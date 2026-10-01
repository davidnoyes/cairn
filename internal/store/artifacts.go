package store

import (
	"github.com/google/uuid"
)

// Artifact is a named collection of versions.
type Artifact struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Public      bool        `json:"public"`
	CreatedAt   string      `json:"createdAt"`
	UpdatedAt   string      `json:"updatedAt"`
	Resources   []*Resource `json:"resources,omitempty"`

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

// Resource associates external references (e.g. a Claude session ID) with an
// artifact.
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
	Name       string `json:"name"`
	Changelog  string `json:"changelog"`
	Seq        int    `json:"seq"`
	ContentDir string `json:"-"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`

	// PushedBy is the user who pushed the version, empty if unrecorded.
	// Epoch is the epoch it was written under.
	PushedBy string `json:"pushedBy,omitempty"`
	Epoch    int    `json:"epoch"`
}

const artifactCols = `id, name, description, public, created_at, updated_at,
	COALESCE(owner_id, ''), epoch, team, public_writes, COALESCE(public_token_hash, ''), COALESCE(public_epoch, 0)`

func scanArtifact(row interface{ Scan(...any) error }) (*Artifact, error) {
	var a Artifact
	if err := row.Scan(&a.ID, &a.Name, &a.Description, &a.Public, &a.CreatedAt, &a.UpdatedAt,
		&a.OwnerID, &a.Epoch, &a.Team, &a.PublicWrites, &a.PublicTokenHash, &a.PublicEpoch); err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) CreateArtifact(name, description string, public bool) (*Artifact, error) {
	t := now()
	a := &Artifact{ID: uuid.NewString(), Name: name, Description: description, Public: public, CreatedAt: t, UpdatedAt: t}
	_, err := s.db.Exec(`INSERT INTO artifacts (id, name, description, public, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.Description, a.Public, a.CreatedAt, a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) ArtifactByID(id string) (*Artifact, error) {
	return scanArtifact(s.db.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE id = ?`, id))
}

// ArtifactByName returns the artifact with the given exact name. Names are not
// unique; the oldest match wins (used by the CLI for convenience).
func (s *Store) ArtifactByName(name string) (*Artifact, error) {
	return scanArtifact(s.db.QueryRow(`SELECT `+artifactCols+` FROM artifacts WHERE name = ? ORDER BY created_at LIMIT 1`, name))
}

// ArtifactsByResource returns the artifacts associated with a resource,
// matched by resource value (e.g. a Claude session id) or resource row id.
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

// UpdateArtifact renames an artifact. Its sharing state changes only through
// a membership record.
func (s *Store) UpdateArtifact(id, name, description string) error {
	return s.exec1(`UPDATE artifacts SET name = ?, description = ?, updated_at = ? WHERE id = ?`,
		name, description, now(), id)
}

func (s *Store) DeleteArtifact(id string) error {
	return s.exec1(`DELETE FROM artifacts WHERE id = ?`, id)
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

const versionCols = `id, artifact_id, name, changelog, seq, content_dir, created_at, updated_at, COALESCE(pushed_by, ''), epoch`

func scanVersion(row interface{ Scan(...any) error }) (*Version, error) {
	var v Version
	if err := row.Scan(&v.ID, &v.ArtifactID, &v.Name, &v.Changelog, &v.Seq, &v.ContentDir, &v.CreatedAt, &v.UpdatedAt, &v.PushedBy, &v.Epoch); err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Store) CreateVersion(artifactID, name, changelog, contentDir string) (*Version, error) {
	t := now()
	v := &Version{ID: uuid.NewString(), ArtifactID: artifactID, Name: name, Changelog: changelog, ContentDir: contentDir, CreatedAt: t, UpdatedAt: t}
	err := s.db.QueryRow(`INSERT INTO versions (id, artifact_id, name, changelog, seq, content_dir, created_at, updated_at)
		VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM versions WHERE artifact_id = ?), ?, ?, ?)
		RETURNING seq`,
		v.ID, v.ArtifactID, v.Name, v.Changelog, artifactID, v.ContentDir, v.CreatedAt, v.UpdatedAt).Scan(&v.Seq)
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
// content dir (re-upload). Returns the previous content dir for cleanup.
func (s *Store) SwapVersionContent(artifactID, versionID, contentDir, name, changelog string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var prev string
	if err := tx.QueryRow(`SELECT content_dir FROM versions WHERE id = ? AND artifact_id = ?`, versionID, artifactID).Scan(&prev); err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE versions SET content_dir = ?, name = ?, changelog = ?, updated_at = ? WHERE id = ?`,
		contentDir, name, changelog, now(), versionID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	s.touchArtifact(artifactID)
	return prev, nil
}

func (s *Store) UpdateVersionMeta(artifactID, versionID, name, changelog string) error {
	return s.exec1(`UPDATE versions SET name = ?, changelog = ?, updated_at = ? WHERE id = ? AND artifact_id = ?`,
		name, changelog, now(), versionID, artifactID)
}

func (s *Store) DeleteVersion(artifactID, versionID string) error {
	return s.exec1(`DELETE FROM versions WHERE id = ? AND artifact_id = ?`, versionID, artifactID)
}
