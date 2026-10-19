package server

import (
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// The command-line tool's Google login: the tool listens on a loopback port,
// and /auth/cli hands it a short-lived Google proof there. The tool still
// asks for the passphrase; see design/google-signin.md.

const (
	cliProofTTL = 2 * time.Minute

	minCLIPort, maxCLIPort   = 1024, 65535
	minCLIState, maxCLIState = 16, 128
)

// validCLIPort reports whether port is one the command-line tool could have
// bound: unprivileged.
func validCLIPort(port int) bool { return port >= minCLIPort && port <= maxCLIPort }

// validCLIState reports whether state is 16 to 128 characters of base64url.
func validCLIState(state string) bool {
	if len(state) < minCLIState || len(state) > maxCLIState {
		return false
	}
	for _, c := range state {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// handleCLIPage serves the page that asks a signed-in person to confirm the
// command-line tool. Its body carries the port and state as data attributes,
// which its script reads: the page loads no inline script.
func (s *Server) handleCLIPage(w http.ResponseWriter, r *http.Request) {
	if !s.googleEnabled() {
		http.NotFound(w, r)
		return
	}
	port, err := strconv.Atoi(r.URL.Query().Get("port"))
	state := r.URL.Query().Get("state")
	if err != nil || !validCLIPort(port) || !validCLIState(state) {
		http.Error(w, "bad port or state", http.StatusBadRequest)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := s.templates().ExecuteTemplate(w, "cli.html", map[string]any{"Port": port, "State": state}); err != nil {
		s.log.Error("render page", "page", "cli.html", "err", err)
	}
}

// handleCLIProof swaps the browser's proof for one the command-line tool can
// carry: the cookie's proof is used up, and a new proof for the same address,
// good for two minutes, goes to the tool's loopback address in the redirect
// the page follows.
func (s *Server) handleCLIProof(w http.ResponseWriter, r *http.Request) {
	if !s.googleEnabled() {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Port  int    `json:"port"`
		State string `json:"state"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !validCLIPort(req.Port) || !validCLIState(req.State) {
		writeError(w, http.StatusBadRequest, "bad port or state")
		return
	}
	token := s.proofCookieToken(r)
	p, err := s.peekProof(token)
	if err != nil {
		s.writeStoreError(w, err, "google proof")
		return
	}
	if p == nil {
		writeError(w, http.StatusForbidden, errNeedGoogle)
		return
	}
	if !s.useProof(w, token) {
		return
	}
	s.clearProofCookie(w)
	proof, err := s.newGoogleProof(p.Email, p.Name, cliProofTTL)
	if err != nil {
		s.writeStoreError(w, err, "google proof")
		return
	}
	q := url.Values{"state": {req.State}, "email": {p.Email}, "proof": {proof}}
	writeJSON(w, http.StatusOK, map[string]string{
		"redirect": "http://127.0.0.1:" + strconv.Itoa(req.Port) + "/callback?" + q.Encode(),
	})
}
