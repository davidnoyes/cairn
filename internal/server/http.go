package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/aloisdeniel/cairn/internal/store"
)

// paginate applies optional ?limit= and ?offset= query parameters to a list
// response.
func paginate[T any](r *http.Request, items []T) []T {
	q := r.URL.Query()
	if off, err := strconv.Atoi(q.Get("offset")); err == nil && off > 0 {
		if off >= len(items) {
			return items[:0]
		}
		items = items[off:]
	}
	if lim, err := strconv.Atoi(q.Get("limit")); err == nil && lim >= 0 && lim < len(items) {
		items = items[:lim]
	}
	return items
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

// writeStoreError maps store errors to HTTP statuses.
func (s *Server) writeStoreError(w http.ResponseWriter, err error, what string) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, what+" not found")
		return
	}
	if errors.Is(err, store.ErrEpochMoved) {
		writeError(w, http.StatusConflict, err.Error()+"; run the command again")
		return
	}
	s.log.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// readJSON decodes a request body strictly: an unknown field, or anything
// after the closing brace, is a 400 rather than being silently ignored.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON body: trailing data")
		return false
	}
	return true
}
