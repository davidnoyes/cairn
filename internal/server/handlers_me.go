package server

import (
	"encoding/json"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, toMeView(requestUser(r)))
}

// apiKeyMK is an API key's own sealed copy of MK, as returned alongside a
// bundle (GET /api/me/bundle) or an archive (GET /api/me/archives).
type apiKeyMK struct {
	ID string `json:"id"`
	MK string `json:"mk"`
}

// meBundleResponse embeds bundleWire so its fields sit at the top level,
// alongside apiKey when the request authenticated with an API key.
type meBundleResponse struct {
	bundleWire
	APIKey *apiKeyMK `json:"apiKey,omitempty"`
}

func (s *Server) handleMeBundle(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	b, err := s.store.BundleFor(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return
	}
	resp := meBundleResponse{bundleWire: encodeBundle(*b)}
	if key := requestAPIKey(r); key != nil {
		resp.APIKey = &apiKeyMK{ID: key.ID, MK: e2e.B64(key.MK)}
	}
	writeJSON(w, http.StatusOK, resp)
}

// requireFreshAuthKey verifies the password the caller claims to hold right
// now, as /api/me/password, /api/me/recovery, and POST /api/keys all require,
// and writes the response itself on failure. It shares the sign-in rate
// limit with login: the same account or IP that has already failed five (or
// twenty) times in the last 15 minutes is refused here too, and a wrong key
// here counts as a failure there.
func (s *Server) requireFreshAuthKey(w http.ResponseWriter, r *http.Request, authKeyB64 string) bool {
	u := requestUser(r)
	ip := clientIP(r)
	if retryAfter, blocked := s.checkSignInLimits(u.Email, ip); blocked {
		writeRateLimited(w, retryAfter)
		return false
	}
	authKey, err := e2e.UnB64(authKeyB64)
	if err != nil || !auth.CheckPassword(u.AuthHash, string(authKey)) {
		s.recordSignInFailure(u.Email, ip)
		writeError(w, http.StatusUnauthorized, "invalid password")
		return false
	}
	return true
}

type changePasswordRequest struct {
	AuthKey    string          `json:"authKey"`
	NewAuthKey string          `json:"newAuthKey"`
	KDF        json.RawMessage `json:"kdf"`
	MKPassword string          `json:"mkPassword"`
}

// handleMePassword changes the password-derived wrapping. The token version
// goes up, which signs out every other session, so this request gets a fresh
// cookie of its own.
func (s *Server) handleMePassword(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	var req changePasswordRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireFreshAuthKey(w, r, req.AuthKey) {
		return
	}
	if _, err := validateKDF(req.KDF); err != nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return
	}
	mkPassword, err := e2e.UnB64(req.MKPassword)
	if err != nil || validateSealedLen(mkPassword) != nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return
	}
	newAuthKey, err := e2e.UnB64(req.NewAuthKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed authKey")
		return
	}
	newHash, err := auth.HashPassword(string(newAuthKey))
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	if err := s.store.SetPassword(u.ID, newHash, string(req.KDF), mkPassword); err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	u, err = s.store.UserByID(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	token, err := s.issueToken(u)
	if err != nil {
		s.writeStoreError(w, err, "token")
		return
	}
	s.setSessionCookie(w, token, s.cfg.TokenTTL)
	writeJSON(w, http.StatusOK, toMeView(u))
}

type changeRecoveryRequest struct {
	AuthKey    string `json:"authKey"`
	MKRecovery string `json:"mkRecovery"`
}

func (s *Server) handleMeRecovery(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	var req changeRecoveryRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireFreshAuthKey(w, r, req.AuthKey) {
		return
	}
	mkRecovery, err := e2e.UnB64(req.MKRecovery)
	if err != nil || validateSealedLen(mkRecovery) != nil {
		writeError(w, http.StatusBadRequest, "malformed key bundle")
		return
	}
	if err := s.store.SetRecovery(u.ID, mkRecovery); err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// archiveView is one bundle_archives row as returned by GET /api/me/archives.
type archiveView struct {
	ID         string     `json:"id"`
	ArchivedAt string     `json:"archivedAt"`
	Bundle     bundleWire `json:"bundle"`
	APIKeys    []apiKeyMK `json:"apiKeys"`
}

func (s *Server) handleMeArchives(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	archives, err := s.store.Archives(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "archives")
		return
	}
	out := make([]archiveView, 0, len(archives))
	for _, a := range archives {
		keys := make([]apiKeyMK, 0, len(a.APIKeys))
		for _, k := range a.APIKeys {
			keys = append(keys, apiKeyMK{ID: k.ID, MK: e2e.B64(k.MK)})
		}
		out = append(out, archiveView{ID: a.ID, ArchivedAt: a.ArchivedAt, Bundle: encodeBundle(a.Bundle), APIKeys: keys})
	}
	writeJSON(w, http.StatusOK, out)
}
