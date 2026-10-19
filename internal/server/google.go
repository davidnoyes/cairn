package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Google sign-in adds a second step to sign-up, sign-in, and forgot: a
// Google proof for the address. Google never replaces the passphrase, which
// still unlocks the keys; see design/google-signin.md.

const (
	googleAuthEndpoint  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenEndpoint = "https://oauth2.googleapis.com/token"
	googleTimeout       = 10 * time.Second

	// The oauth cookie carries state and the PKCE verifier from the redirect
	// to Google to the callback. It is Lax because Google sends the browser
	// back with a cross-site navigation.
	secureOAuthCookie   = "__Secure-cairn_oauth"
	insecureOAuthCookie = "cairn_oauth"
	oauthCookieTTL      = 10 * time.Minute

	// The proof cookie holds a proof's token. As with the session cookie, the
	// __Host- prefix rules out a subdomain planting it.
	secureProofCookie   = "__Host-cairn_google"
	insecureProofCookie = "cairn_google"
	googleProofTTL      = 10 * time.Minute

	errNeedGoogle = "sign in with Google first"
)

// checkGoogleConfig refuses a client ID the server cannot use: Google needs
// the client secret to exchange a code, and the public URL to name where the
// browser comes back to.
func checkGoogleConfig(cfg Config) error {
	if cfg.GoogleClientID == "" {
		return nil
	}
	if cfg.GoogleClientSecret == "" {
		return errors.New("--google-client-id needs --google-client-secret: Google sign-in cannot exchange a code without the client secret")
	}
	if cfg.PublicURL == "" {
		return errors.New("--google-client-id needs --public-url: Google redirects the browser to <public URL>/auth/google/callback")
	}
	return nil
}

func (s *Server) googleEnabled() bool { return s.cfg.GoogleClientID != "" }

func (s *Server) googleRedirectURI() string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/auth/google/callback"
}

func (s *Server) oauthCookieName() string {
	if s.secure {
		return secureOAuthCookie
	}
	return insecureOAuthCookie
}

func (s *Server) proofCookieName() string {
	if s.secure {
		return secureProofCookie
	}
	return insecureProofCookie
}

// randomString returns 32 random bytes as base64url, 43 characters, which is
// also a valid PKCE verifier.
func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return e2e.B64(b), nil
}

// oauthState is what the oauth cookie holds between the redirect to Google
// and the callback.
type oauthState struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Next     string `json:"n"`
}

func (s *Server) oauthCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     s.oauthCookieName(),
		Value:    value,
		Path:     "/auth/google",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// handleGoogleStart sends the browser to Google's consent page with a state
// value and a PKCE challenge, and keeps the state, the verifier, and where to
// go afterwards in the oauth cookie.
func (s *Server) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	if !s.googleEnabled() {
		http.NotFound(w, r)
		return
	}
	state, err1 := randomString()
	verifier, err2 := randomString()
	if err := errors.Join(err1, err2); err != nil {
		s.writeStoreError(w, err, "oauth state")
		return
	}
	st := oauthState{State: state, Verifier: verifier, Next: safeNext(r.URL.Query().Get("next"))}
	raw, err := json.Marshal(st)
	if err != nil {
		s.writeStoreError(w, err, "oauth state")
		return
	}
	http.SetCookie(w, s.oauthCookie(e2e.B64(raw), int(oauthCookieTTL.Seconds())))
	challenge := sha256.Sum256([]byte(st.Verifier))
	q := url.Values{
		"client_id":             {s.cfg.GoogleClientID},
		"redirect_uri":          {s.googleRedirectURI()},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {st.State},
		"code_challenge":        {e2e.B64(challenge[:])},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	http.Redirect(w, r, s.googleAuthURL+"?"+q.Encode(), http.StatusFound)
}

// readOAuthState reads the oauth cookie. A missing or malformed cookie is an
// error.
func (s *Server) readOAuthState(r *http.Request) (oauthState, error) {
	var st oauthState
	c, err := r.Cookie(s.oauthCookieName())
	if err != nil {
		return st, err
	}
	raw, err := e2e.UnB64(c.Value)
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(raw, &st)
}

// handleGoogleCallback finishes the round trip: it checks state, trades the
// code for an ID token, checks the token's claims, and makes a proof. A
// failure makes no proof and shows the sign-in page with the reason.
func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if !s.googleEnabled() {
		http.NotFound(w, r)
		return
	}
	st, err := s.readOAuthState(r)
	http.SetCookie(w, s.oauthCookie("", -1))
	q := r.URL.Query()
	if err != nil || st.State == "" || subtle.ConstantTimeCompare([]byte(st.State), []byte(q.Get("state"))) != 1 {
		s.renderLogin(w, http.StatusBadRequest, st.Next, "Sign-in expired or was started elsewhere. Try again.")
		return
	}
	// Google's error code is logged, not shown: the page must not display text
	// that anyone can put in a link.
	if e := q.Get("error"); e != "" {
		s.log.Info("google sign-in cancelled", "error", e)
		s.renderLogin(w, http.StatusUnauthorized, st.Next, "Google sign-in was cancelled.")
		return
	}
	email, name, err := s.exchangeGoogleCode(r, q.Get("code"), st.Verifier)
	if err != nil {
		s.log.Warn("google sign-in refused", "err", err)
		s.renderLogin(w, http.StatusUnauthorized, st.Next, "Google sign-in failed.")
		return
	}
	token, err := s.newGoogleProof(email, name, googleProofTTL)
	if err != nil {
		s.writeStoreError(w, err, "google proof")
		return
	}
	s.setProofCookie(w, token)
	// The oauth cookie is unsigned, so next goes through the safe-next rule
	// again rather than being trusted as handleGoogleStart wrote it.
	http.Redirect(w, r, safeNext(st.Next), http.StatusFound)
}

// googleClaims are the ID token claims the server checks.
type googleClaims struct {
	Iss           string `json:"iss"`
	Aud           string `json:"aud"`
	Exp           int64  `json:"exp"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	HD            string `json:"hd"`
	Name          string `json:"name"`
}

// exchangeGoogleCode trades the authorization code for an ID token and
// returns the normalized address and display name it vouches for. The ID
// token comes straight from Google's token endpoint over TLS, authenticated
// with the client secret, so its signature need not be checked (OpenID
// Connect Core 3.1.3.7); its claims still are.
func (s *Server) exchangeGoogleCode(r *http.Request, code, verifier string) (email, name string, err error) {
	if code == "" {
		return "", "", errors.New("missing code")
	}
	form := url.Values{
		"code":          {code},
		"client_id":     {s.cfg.GoogleClientID},
		"client_secret": {s.cfg.GoogleClientSecret},
		"redirect_uri":  {s.googleRedirectURI()},
		"grant_type":    {"authorization_code"},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.googleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", "", fmt.Errorf("token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || tok.IDToken == "" {
		return "", "", fmt.Errorf("token endpoint: status %d, error %q", resp.StatusCode, tok.Error)
	}
	claims, err := parseIDToken(tok.IDToken)
	if err != nil {
		return "", "", err
	}
	email, err = s.checkGoogleClaims(claims)
	return email, claims.Name, err
}

// parseIDToken reads the claims of a JWT without checking its signature.
func parseIDToken(idToken string) (googleClaims, error) {
	var claims googleClaims
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return claims, errors.New("malformed id_token")
	}
	payload, err := e2e.UnB64(parts[1])
	if err != nil {
		return claims, fmt.Errorf("id_token payload: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("id_token claims: %w", err)
	}
	return claims, nil
}

// checkGoogleClaims applies every check the design lists, and returns the
// normalized address. For an address in a signup domain, hd must name that
// domain, which refuses a personal Google Account created with a company
// address. The administrator's address needs no hd when its domain is not a
// signup domain, because the rule then never applies to it.
func (s *Server) checkGoogleClaims(c googleClaims) (string, error) {
	email := normalizeEmail(c.Email)
	domain := email[strings.LastIndex(email, "@")+1:]
	switch {
	case c.Iss != "https://accounts.google.com" && c.Iss != "accounts.google.com":
		return "", fmt.Errorf("unexpected issuer %q", c.Iss)
	case c.Aud != s.cfg.GoogleClientID:
		return "", errors.New("id_token audience mismatch")
	case s.clk.Now().Unix() >= c.Exp:
		return "", errors.New("id_token expired")
	case email == "" || !c.EmailVerified:
		return "", errors.New("email missing or not verified by Google")
	case slices.Contains(s.cfg.SignupDomains, domain) && normalizeEmail(c.HD) != domain:
		return "", fmt.Errorf("hd %q is not %q", c.HD, domain)
	}
	return email, nil
}

// Proofs

// newGoogleProof stores a proof for email that lasts ttl, and returns its
// token, base64url, which is shown only to the browser or the tool.
func (s *Server) newGoogleProof(email, name string, ttl time.Duration) (string, error) {
	raw, hash, err := newLinkToken()
	if err != nil {
		return "", err
	}
	if err := s.store.CreateGoogleProof(hash, email, name, s.clk.Now().Add(ttl)); err != nil {
		return "", err
	}
	return e2e.B64(raw), nil
}

func (s *Server) setProofCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, s.proofCookie(token, int(googleProofTTL.Seconds())))
}

func (s *Server) clearProofCookie(w http.ResponseWriter) {
	http.SetCookie(w, s.proofCookie("", -1))
}

func (s *Server) proofCookie(token string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     s.proofCookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// proofCookieToken is the token in the request's proof cookie, or "".
func (s *Server) proofCookieToken(r *http.Request) string {
	if c, err := r.Cookie(s.proofCookieName()); err == nil {
		return c.Value
	}
	return ""
}

// proofHash is the store key for a base64url proof token, or "" if it is not
// a token at all.
func proofHash(token string) string {
	raw, err := e2e.UnB64(token)
	if err != nil {
		return ""
	}
	return hashToken(raw)
}

// peekProof returns the unused, unexpired proof a token names, or nil when
// there is none.
func (s *Server) peekProof(token string) (*store.GoogleProof, error) {
	hash := proofHash(token)
	if hash == "" {
		return nil, nil
	}
	p, err := s.store.PeekGoogleProof(hash, s.clk.Now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return p, err
}

// requireProof answers 403 unless token names a live proof for email, and
// reports whether the request may go on. It does not use the proof.
func (s *Server) requireProof(w http.ResponseWriter, token, email string) bool {
	p, err := s.peekProof(token)
	if err != nil {
		s.writeStoreError(w, err, "google proof")
		return false
	}
	if p == nil || p.Email != email {
		writeError(w, http.StatusForbidden, errNeedGoogle)
		return false
	}
	return true
}

// useProof spends the proof a token names. It answers 403 if another request
// spent it first, and reports whether the request may go on.
func (s *Server) useProof(w http.ResponseWriter, token string) bool {
	if _, err := s.store.UseGoogleProof(proofHash(token), s.clk.Now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusForbidden, errNeedGoogle)
		} else {
			s.writeStoreError(w, err, "google proof")
		}
		return false
	}
	return true
}

// handleAuthConfig tells clients, the command-line tool among them, whether
// the server asks for Google sign-in, and whether passkeys work here and
// under which relying party ID, so a page never enrolls a passkey that could
// not sign in.
func (s *Server) handleAuthConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"google": s.googleEnabled(), "passkeys": s.passkeysEnabled()}
	if s.passkeysEnabled() {
		out["rpId"] = s.appHost
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGoogleProof tells a page whose address and name the proof cookie
// holds, so it can show them. It does not use the proof.
func (s *Server) handleGoogleProof(w http.ResponseWriter, r *http.Request) {
	if !s.googleEnabled() {
		http.NotFound(w, r)
		return
	}
	p, err := s.peekProof(s.proofCookieToken(r))
	if err != nil {
		s.writeStoreError(w, err, "google proof")
		return
	}
	if p == nil {
		writeError(w, http.StatusUnauthorized, errNeedGoogle)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": p.Email, "name": p.Name})
}
