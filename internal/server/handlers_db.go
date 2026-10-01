package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/versiondb"
)

// resolveVersion validates the version exists before touching its database
// and returns the resolved artifact id.
func (s *Server) resolveVersion(w http.ResponseWriter, r *http.Request) (string, bool) {
	aid := requestArtifact(r).ID
	if _, err := s.store.VersionByID(aid, r.PathValue("vid")); err != nil {
		s.writeStoreError(w, err, "version")
		return "", false
	}
	return aid, true
}

// handleDBQuery runs one SQL statement against a version's shared database.
// Callers who may write data get the read-write pool; every other reader
// the query_only pool — enforcement is at the connection level.
func (s *Server) handleDBQuery(w http.ResponseWriter, r *http.Request) {
	aid, ok := s.resolveVersion(w, r)
	if !ok {
		return
	}
	var stmt versiondb.Statement
	if !readJSON(w, r, &stmt) {
		return
	}
	if strings.TrimSpace(stmt.SQL) == "" {
		writeError(w, http.StatusBadRequest, "sql is required")
		return
	}
	writable := access.Check(requestAccess(r), access.WriteData) == access.Allow
	res, err := s.dbs.Exec(r.Context(), aid, r.PathValue("vid"), writable, stmt)
	if err != nil {
		s.writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type batchRequest struct {
	Statements []versiondb.Statement `json:"statements"`
}

// handleDBBatch runs statements atomically in one transaction (client-driven
// migrations rely on this).
func (s *Server) handleDBBatch(w http.ResponseWriter, r *http.Request) {
	aid, ok := s.resolveVersion(w, r)
	if !ok {
		return
	}
	var req batchRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Statements) == 0 {
		writeError(w, http.StatusBadRequest, "statements are required")
		return
	}
	results, err := s.dbs.Batch(r.Context(), aid, r.PathValue("vid"), req.Statements)
	if err != nil {
		s.writeDBError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, results)
}

// handleDBDownload streams the raw SQLite file (checkpointed first).
func (s *Server) handleDBDownload(w http.ResponseWriter, r *http.Request) {
	aid, ok := s.resolveVersion(w, r)
	if !ok {
		return
	}
	path, err := s.dbs.PreparedPath(r.Context(), aid, r.PathValue("vid"))
	if err != nil {
		if errors.Is(err, versiondb.ErrNoDatabase) {
			writeError(w, http.StatusNotFound, "this version has no shared database yet")
			return
		}
		s.writeDBError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="database.db"`)
	http.ServeFile(w, r, path)
}

func (s *Server) writeDBError(w http.ResponseWriter, err error) {
	if errors.Is(err, versiondb.ErrMultiStatement) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	msg := err.Error()
	// SQLite errors (bad SQL, constraint violations, readonly rejections) are
	// client errors in a raw-SQL API; the message is the useful payload.
	if strings.Contains(msg, "SQLITE_") || strings.Contains(msg, "syntax error") ||
		strings.Contains(msg, "constraint") || strings.Contains(msg, "no such") ||
		strings.Contains(msg, "readonly") || strings.Contains(msg, "query_only") {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	s.log.Error("db query", "err", err)
	writeError(w, http.StatusInternalServerError, "database error")
}
