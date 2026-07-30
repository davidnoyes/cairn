package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/aloisdeniel/artifacts/internal/store"
)

// errAmbiguousResource is returned when a resource reference matches several
// artifacts.
type errAmbiguousResource struct {
	ref   string
	count int
}

func (e errAmbiguousResource) Error() string {
	return fmt.Sprintf("resource %q is associated with %d artifacts; use the artifact id", e.ref, e.count)
}

// resolveArtifactRef resolves the {id} path segment of artifact-scoped
// routes: an artifact id first, else a resource reference (resource value
// such as a Claude session id, or resource row id). A resource matching more
// than one artifact is an error.
func (s *Server) resolveArtifactRef(ref string) (*store.Artifact, error) {
	a, err := s.store.ArtifactByID(ref)
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	matches, err := s.store.ArtifactsByResource(ref)
	if err != nil {
		return nil, err
	}
	switch len(matches) {
	case 0:
		return nil, store.ErrNotFound
	case 1:
		return matches[0], nil
	default:
		return nil, errAmbiguousResource{ref: ref, count: len(matches)}
	}
}

const artifactCtxKey ctxKey = 100

// withArtifact resolves the {id} segment (artifact id or resource reference)
// once and attaches the artifact to the request context.
func (s *Server) withArtifact(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, err := s.resolveArtifactRef(r.PathValue("id"))
		if err != nil {
			var ambiguous errAmbiguousResource
			if errors.As(err, &ambiguous) {
				writeError(w, http.StatusConflict, ambiguous.Error())
				return
			}
			s.writeStoreError(w, err, "artifact")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), artifactCtxKey, a)))
	}
}

// requestArtifact returns the artifact attached by withArtifact (never nil
// inside wrapped handlers).
func requestArtifact(r *http.Request) *store.Artifact {
	a, _ := r.Context().Value(artifactCtxKey).(*store.Artifact)
	return a
}

// canRead applies the public/private rule: public artifacts are readable by
// anyone, private ones by any authenticated user.
func (s *Server) canRead(r *http.Request, a *store.Artifact) bool {
	if a.Public {
		return true
	}
	u, err := s.currentUser(r)
	return err == nil && u != nil
}

// publicAware wraps read handlers of artifact-scoped routes: resolves the
// artifact reference and enforces the public/private rule.
func (s *Server) publicAware(next http.HandlerFunc) http.HandlerFunc {
	return s.withArtifact(func(w http.ResponseWriter, r *http.Request) {
		if !s.canRead(r, requestArtifact(r)) {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r)
	})
}

func (s *Server) withResources(a *store.Artifact) *store.Artifact {
	if rs, err := s.store.ListResources(a.ID); err == nil {
		a.Resources = rs
	}
	return a
}

// Artifact CRUD

type artifactRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Public      *bool  `json:"public"`
}

func (s *Server) handleCreateArtifact(w http.ResponseWriter, r *http.Request) {
	var req artifactRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	public := req.Public != nil && *req.Public
	a, err := s.store.CreateArtifact(req.Name, req.Description, public)
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	s.log.Info("artifact created", "id", a.ID, "name", a.Name, "by", requestUser(r).Email)
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	as, err := s.store.ListArtifacts()
	if err != nil {
		s.writeStoreError(w, err, "artifacts")
		return
	}
	// Name-based lookup convenience for the CLI: ?name= filters exactly.
	if name := r.URL.Query().Get("name"); name != "" {
		filtered := as[:0]
		for _, a := range as {
			if a.Name == name {
				filtered = append(filtered, a)
			}
		}
		as = filtered
	}
	if as == nil {
		as = []*store.Artifact{}
	}
	writeJSON(w, http.StatusOK, paginate(r, as))
}

func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.withResources(requestArtifact(r)))
}

func (s *Server) handleUpdateArtifact(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	var req artifactRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		req.Name = a.Name
	}
	if req.Description == "" {
		req.Description = a.Description
	}
	public := a.Public
	if req.Public != nil {
		public = *req.Public
	}
	if err := s.store.UpdateArtifact(a.ID, req.Name, req.Description, public); err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	a, err := s.store.ArtifactByID(a.ID)
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	writeJSON(w, http.StatusOK, s.withResources(a))
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
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
