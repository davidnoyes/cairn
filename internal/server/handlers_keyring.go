package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// maxKeyringBytes caps the sealed keyring. The request body carries it in
// b64, a third larger, so the body limit is set above it.
const (
	maxKeyringBytes     = 1 << 20
	maxKeyringBodyBytes = 2 << 20
)

// keyringBody is both the GET answer and the PUT request. The server never
// opens or parses the keyring: it holds the sealed bytes and checks rev.
type keyringBody struct {
	Rev     int    `json:"rev"`
	Keyring string `json:"keyring"`
}

func (s *Server) handleGetKeyring(w http.ResponseWriter, r *http.Request) {
	rev, sealed, err := s.store.Keyring(requestUser(r).ID)
	if err != nil {
		s.writeStoreError(w, err, "keyring")
		return
	}
	writeJSON(w, http.StatusOK, keyringBody{Rev: rev, Keyring: e2e.B64(sealed)})
}

func (s *Server) handlePutKeyring(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxKeyringBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req keyringBody
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "keyring exceeds 1 MiB")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON body: trailing data")
		return
	}
	sealed, err := e2e.UnB64(req.Keyring)
	if err != nil {
		writeError(w, http.StatusBadRequest, "keyring is not base64")
		return
	}
	if len(sealed) == 0 {
		writeError(w, http.StatusBadRequest, "keyring is required")
		return
	}
	if len(sealed) > maxKeyringBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "keyring exceeds 1 MiB")
		return
	}
	current, err := s.store.PutKeyring(requestUser(r).ID, req.Rev, sealed)
	if errors.Is(err, store.ErrStale) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "rev must be one more than the stored rev; read the keyring again and merge",
			"rev":   current,
		})
		return
	}
	if err != nil {
		s.writeStoreError(w, err, "keyring")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"rev": req.Rev})
}
