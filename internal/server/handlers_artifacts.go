package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/store"
)

// errAmbiguousResource is returned when a resource reference matches several
// artifacts the caller can read.
type errAmbiguousResource struct {
	ref   string
	count int
}

func (e errAmbiguousResource) Error() string {
	return fmt.Sprintf("resource %q is associated with %d artifacts; use the artifact id", e.ref, e.count)
}

// requestArtifact returns the artifact attached by artifactRoute (never nil
// inside wrapped handlers).
func requestArtifact(r *http.Request) *store.Artifact {
	a, _ := r.Context().Value(artifactCtxKey).(*store.Artifact)
	return a
}

// Artifact CRUD. Creating one lives in sharing.go, with the membership
// endpoints whose first record it writes.

// handleListArtifacts lists the artifacts the caller can read without a
// link token.
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	as, err := s.store.ListArtifacts()
	if err != nil {
		s.writeStoreError(w, err, "artifacts")
		return
	}
	c, err := s.callerFor(requestUser(r), requestAPIKey(r))
	if err != nil {
		s.writeStoreError(w, err, "user")
		return
	}
	// Name-based lookup convenience for the CLI: ?name= filters exactly.
	name := r.URL.Query().Get("name")
	out := []*artifactView{}
	for _, a := range as {
		if name != "" && a.Name != name {
			continue
		}
		a, req, err := s.accessRequest(c, a.ID, nil)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			s.writeStoreError(w, err, "artifacts")
			return
		}
		level := access.LevelOf(req)
		if level == access.LevelNone {
			continue
		}
		v, err := s.viewOf(a, level)
		if err != nil {
			s.writeStoreError(w, err, "artifacts")
			return
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, paginate(r, out))
}

func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	v, err := s.viewOf(requestArtifact(r), access.LevelOf(requestAccess(r)))
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// renameRequest is the PATCH body: an artifact's sharing state changes only
// through PUT /membership, so a public field is refused as unknown.
type renameRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleUpdateArtifact(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	var req renameRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		req.Name = a.Name
	}
	if req.Description == "" {
		req.Description = a.Description
	}
	if err := s.store.UpdateArtifact(a.ID, req.Name, req.Description); err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	a, err := s.store.ArtifactByID(a.ID)
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	v, err := s.viewOf(a, access.LevelOf(requestAccess(r)))
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteArtifact(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	versions, err := s.store.ListVersions(a.ID)
	if err != nil {
		s.writeStoreError(w, err, "versions")
		return
	}
	if err := s.store.DeleteArtifact(a.ID); err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	for _, v := range versions {
		s.dbs.Invalidate(a.ID, v.ID)
	}
	os.RemoveAll(s.layout.ArtifactContentRoot(a.ID))
	os.RemoveAll(s.layout.ArtifactDBRoot(a.ID))
	os.RemoveAll(s.layout.ArtifactFilesRoot(a.ID))
	s.log.Info("artifact deleted", "id", a.ID, "by", requestUser(r).Email)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Resources

type resourceRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (s *Server) handleAddResource(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	var req resourceRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Type == "" || req.Value == "" {
		writeError(w, http.StatusBadRequest, "type and value are required")
		return
	}
	res, err := s.store.AddResource(a.ID, req.Type, req.Value)
	if err != nil {
		s.writeStoreError(w, err, "resource")
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (s *Server) handleDeleteResource(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteResource(requestArtifact(r).ID, r.PathValue("rid")); err != nil {
		s.writeStoreError(w, err, "resource")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// Versions (metadata; uploads live in upload.go)

func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	vs, err := s.store.ListVersions(requestArtifact(r).ID)
	if err != nil {
		s.writeStoreError(w, err, "versions")
		return
	}
	if vs == nil {
		vs = []*store.Version{}
	}
	writeJSON(w, http.StatusOK, vs)
}

func (s *Server) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.VersionByID(requestArtifact(r).ID, r.PathValue("vid"))
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type versionMetaRequest struct {
	Name      *string `json:"name"`
	Changelog *string `json:"changelog"`
}

func (s *Server) handleUpdateVersionMeta(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.VersionByID(requestArtifact(r).ID, r.PathValue("vid"))
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	var req versionMetaRequest
	if !readJSON(w, r, &req) {
		return
	}
	name, changelog := v.Name, v.Changelog
	if req.Name != nil {
		name = *req.Name
	}
	if req.Changelog != nil {
		changelog = *req.Changelog
	}
	if err := s.store.UpdateVersionMeta(v.ArtifactID, v.ID, name, changelog); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	v, _ = s.store.VersionByID(v.ArtifactID, v.ID)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteVersion(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.VersionByID(requestArtifact(r).ID, r.PathValue("vid"))
	if err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	if err := s.store.DeleteVersion(v.ArtifactID, v.ID); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	if err := s.dbs.DeleteDatabase(v.ArtifactID, v.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("delete version db", "err", err)
	}
	os.RemoveAll(s.layout.ContentDir(v.ArtifactID, v.ContentDir))
	os.RemoveAll(s.layout.VersionFilesDir(v.ArtifactID, v.ID))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
