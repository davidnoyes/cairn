package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

type createKeyRequest struct {
	AuthKey    string `json:"authKey"`
	Name       string `json:"name"`
	Device     bool   `json:"device"`
	KeyID      string `json:"keyId"`
	AuthSecret string `json:"authSecret"`
	MK         string `json:"mk"`
}

type createKeyResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Device    bool   `json:"device"`
	CreatedAt string `json:"createdAt"`
}

// handleCreateKey stores a client-generated API key: the client picks keyId
// and authSecret and keeps keySecret to itself, sending only the bearer's two
// public parts and its own sealed copy of MK.
func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	var req createKeyRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireFreshAuthKey(w, r, req.AuthKey) {
		return
	}
	if len(req.KeyID) != 16 || !isLowerHex(req.KeyID) || len(req.AuthSecret) != 32 || !isLowerHex(req.AuthSecret) {
		writeError(w, http.StatusBadRequest, "malformed key id or auth secret")
		return
	}
	mk, err := e2e.UnB64(req.MK)
	if err != nil || validateSealedLen(mk) != nil {
		writeError(w, http.StatusBadRequest, "malformed key")
		return
	}
	// The stored hash covers the auth secret's hex string, not the bytes it
	// decodes to, matching what a bearer credential presents byte for byte.
	sum := sha256.Sum256([]byte(req.AuthSecret))
	key := store.APIKey{
		ID:         req.KeyID,
		UserID:     u.ID,
		Name:       req.Name,
		Device:     req.Device,
		SecretHash: hex.EncodeToString(sum[:]),
		MK:         mk,
	}
	if err := s.store.CreateAPIKey(key); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeError(w, http.StatusConflict, "key id already in use")
			return
		}
		s.writeStoreError(w, err, "key")
		return
	}
	created, err := s.store.APIKeyByID(req.KeyID)
	if err != nil {
		s.writeStoreError(w, err, "key")
		return
	}
	writeJSON(w, http.StatusCreated, createKeyResponse{ID: created.ID, Name: created.Name, Device: created.Device, CreatedAt: created.CreatedAt})
}

// keyView is one of the user's own keys, as listed by GET /api/keys.
type keyView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Device     bool   `json:"device"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	keys, err := s.store.ListAPIKeys(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "keys")
		return
	}
	out := make([]keyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyView{ID: k.ID, Name: k.Name, Device: k.Device, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevokeKey revokes id only if it belongs to the caller; store.
// RevokeAPIKey maps anything else to ErrNotFound, so one user can never
// revoke another's key.
func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	if err := s.store.RevokeAPIKey(u.ID, r.PathValue("id"), s.clk.Now()); err != nil {
		s.writeStoreError(w, err, "key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
