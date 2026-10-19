package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/aloisdeniel/cairn/internal/webauthn"
)

// Passkey unlock: a passkey signs a user in and opens its own sealed copy of
// MK. See "Passkey unlock" in design/google-signin.md.

const (
	// challengeTTL is how long an issued challenge may be answered.
	challengeTTL = 2 * time.Minute
	// maxChallenges bounds the challenges held in memory, since begin is
	// open to anyone.
	maxChallenges = 10000
	// maxChallengesPerIP bounds one address's share of them, so a single
	// client cannot fill the store and lock every other sign-in out.
	maxChallengesPerIP = 10

	// A credential ID is 16 to 1023 bytes: the WebAuthn ceiling, with a floor
	// that keeps an ID from being guessed.
	minCredentialIDLen = 16
	maxCredentialIDLen = 1023

	defaultPasskeyName = "passkey"
	errPasskeyFailed   = "passkey sign-in failed"
	// errPasskeyOtherAccount answers a passkey whose owner is not the address
	// the browser's Google proof names.
	errPasskeyOtherAccount = "this passkey belongs to another account than the Google Account you signed in with"
)

// challenges holds the challenges passkey/begin issued, each until it is
// spent or expires. It lives in memory: a restart only makes a page ask again.
type challenges struct {
	clk   clock.Clock
	mu    sync.Mutex
	m     map[string]challenge // keyed by the challenge, base64url
	perIP map[string]int       // outstanding challenges for each address
}

// challenge is one issued challenge: when it expires, and the address that
// asked for it.
type challenge struct {
	exp time.Time
	ip  string
}

func newChallenges(clk clock.Clock) *challenges {
	return &challenges{clk: clk, m: make(map[string]challenge), perIP: make(map[string]int)}
}

// errTooManyFromIP is issue's refusal of an address that already holds
// maxChallengesPerIP challenges.
var errTooManyFromIP = errors.New("too many passkey sign-ins in progress from this address")

// issue returns a new challenge for ip, base64url. It refuses with
// errTooManyFromIP when ip holds maxChallengesPerIP, and with false when
// maxChallenges are outstanding, in each case after expired ones are dropped.
func (c *challenges) issue(ip string) (string, bool, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", false, err
	}
	token := e2e.B64(raw)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clk.Now()
	if len(c.m) >= maxChallenges || c.perIP[ip] >= maxChallengesPerIP {
		c.sweep(now)
	}
	if c.perIP[ip] >= maxChallengesPerIP {
		return "", false, errTooManyFromIP
	}
	if len(c.m) >= maxChallenges {
		return "", false, nil
	}
	c.m[token] = challenge{exp: now.Add(challengeTTL), ip: ip}
	c.perIP[ip]++
	return token, true, nil
}

// sweep drops expired challenges. The caller holds c.mu.
func (c *challenges) sweep(now time.Time) {
	for k, ch := range c.m {
		if !now.Before(ch.exp) {
			c.remove(k, ch)
		}
	}
}

// remove forgets one challenge and frees its address's slot. The caller
// holds c.mu.
func (c *challenges) remove(token string, ch challenge) {
	delete(c.m, token)
	if c.perIP[ch.ip]--; c.perIP[ch.ip] <= 0 {
		delete(c.perIP, ch.ip)
	}
}

// consume spends a challenge, whether or not it has expired, and reports
// whether it was issued, unspent, and unexpired.
func (c *challenges) consume(token string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.m[token]
	if ok {
		c.remove(token, ch) // spent, whatever the outcome
	}
	return ok && c.clk.Now().Before(ch.exp)
}

// passkeysEnabled reports whether passkeys can work: the relying party ID and
// origin come from --public-url. Without one the routes answer 404.
func (s *Server) passkeysEnabled() bool {
	return s.appHost != "" && s.appOrigin != ""
}

type createPasskeyRequest struct {
	AuthKey   string `json:"authKey"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
	Alg       int    `json:"alg"`
	MK        string `json:"mk"`
}

type createPasskeyResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

// handleCreatePasskey stores a passkey the browser just made. Like an API
// key it needs a fresh authKey, since it adds a way to sign in. Registration
// verifies no attestation and uses no challenge; the session and the authKey
// are the proof. The public key must fit its algorithm, so a passkey that
// could never sign in is refused here.
func (s *Server) handleCreatePasskey(w http.ResponseWriter, r *http.Request) {
	if !s.passkeysEnabled() {
		http.NotFound(w, r)
		return
	}
	u := requestUser(r)
	var req createPasskeyRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireFreshAuthKey(w, r, req.AuthKey) {
		return
	}
	id, err := e2e.UnB64(req.ID)
	if err != nil || len(id) < minCredentialIDLen || len(id) > maxCredentialIDLen {
		writeError(w, http.StatusBadRequest, "malformed credential id")
		return
	}
	spki, err := e2e.UnB64(req.PublicKey)
	if err != nil || webauthn.CheckPublicKey(spki, req.Alg) != nil {
		writeError(w, http.StatusBadRequest, "malformed public key")
		return
	}
	mk, err := e2e.UnB64(req.MK)
	if err != nil || validateSealedLen(mk) != nil {
		writeError(w, http.StatusBadRequest, "malformed key")
		return
	}
	name := strings.TrimSpace(req.Name)
	if len(name) > maxNameLen {
		writeError(w, http.StatusBadRequest, "name too long")
		return
	}
	if name == "" {
		name = defaultPasskeyName
	}
	p := store.Passkey{ID: req.ID, UserID: u.ID, Name: name, PublicKey: spki, Alg: req.Alg, MK: mk}
	if err := s.store.CreatePasskey(p); err != nil {
		if errors.Is(err, store.ErrExists) {
			writeError(w, http.StatusConflict, "passkey already enrolled")
			return
		}
		s.writeStoreError(w, err, "passkey")
		return
	}
	created, err := s.store.PasskeyByID(req.ID)
	if err != nil {
		s.writeStoreError(w, err, "passkey")
		return
	}
	writeJSON(w, http.StatusCreated, createPasskeyResponse{ID: created.ID, Name: created.Name, CreatedAt: created.CreatedAt})
}

// passkeyView is one of the user's own passkeys, as listed by GET
// /api/me/passkeys.
type passkeyView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
}

func (s *Server) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	passkeys, err := s.store.ListPasskeys(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "passkeys")
		return
	}
	out := make([]passkeyView, 0, len(passkeys))
	for _, p := range passkeys {
		out = append(out, passkeyView{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeletePasskey removes id only if it belongs to the caller; store.
// DeletePasskey maps anything else to ErrNotFound, so one user can never
// remove another's passkey.
func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	u := requestUser(r)
	if err := s.store.DeletePasskey(u.ID, r.PathValue("id")); err != nil {
		s.writeStoreError(w, err, "passkey")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handlePasskeyBegin issues a challenge for one sign-in with a passkey, and
// names the relying party ID the browser must use.
func (s *Server) handlePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	if !s.passkeysEnabled() {
		http.NotFound(w, r)
		return
	}
	var req struct{}
	if !readJSON(w, r, &req) {
		return
	}
	challenge, ok, err := s.passkeyChallenges.issue(clientIP(r))
	if errors.Is(err, errTooManyFromIP) {
		writeRateLimited(w, challengeTTL)
		return
	}
	if err != nil {
		s.writeStoreError(w, err, "challenge")
		return
	}
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "too many sign-ins in progress; try again shortly")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"challenge": challenge, "rpId": s.appHost})
}

type passkeyFinishRequest struct {
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

// passkeyLoginResponse is a sign-in's answer: like a password sign-in's, plus
// the passkey's own sealed copy of MK.
type passkeyLoginResponse struct {
	User      meView     `json:"user"`
	Bundle    bundleWire `json:"bundle"`
	PasskeyMK string     `json:"passkeyMk"`
}

// handlePasskeyFinish checks an assertion and starts a session. Every
// refusal after the rate-limit check counts against the client's address, and
// the challenge is spent before anything else is checked, so a refused
// assertion cannot be tried again. On a Google server the owner's proof is
// required, and checked before any signature work; it is used only on
// success, as for a password sign-in.
func (s *Server) handlePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if !s.passkeysEnabled() {
		http.NotFound(w, r)
		return
	}
	ip := clientIP(r)
	if retryAfter, blocked := s.signIn.ip.blocked(ip); blocked {
		writeRateLimited(w, retryAfter)
		return
	}
	refuse := func(status int, msg string) {
		s.signIn.ip.record(ip)
		writeError(w, status, msg)
	}
	var req passkeyFinishRequest
	if !readJSON(w, r, &req) {
		s.signIn.ip.record(ip)
		return
	}
	clientData, err1 := e2e.UnB64(req.ClientDataJSON)
	authData, err2 := e2e.UnB64(req.AuthenticatorData)
	sig, err3 := e2e.UnB64(req.Signature)
	userHandle, err4 := e2e.UnB64(req.UserHandle)
	if errors.Join(err1, err2, err3, err4) != nil {
		refuse(http.StatusBadRequest, "malformed assertion")
		return
	}

	// The challenge is read from the client data only to find the one the
	// server issued; Verify checks it against the client data again.
	var cd struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(clientData, &cd); err != nil {
		refuse(http.StatusUnauthorized, errPasskeyFailed)
		return
	}
	challenge, err := e2e.UnB64(cd.Challenge)
	if err != nil || !s.passkeyChallenges.consume(cd.Challenge) {
		refuse(http.StatusUnauthorized, errPasskeyFailed)
		return
	}

	pk, err := s.store.PasskeyByID(req.CredentialID)
	if errors.Is(err, store.ErrNotFound) {
		refuse(http.StatusUnauthorized, errPasskeyFailed)
		return
	}
	if err != nil {
		s.writeStoreError(w, err, "passkey")
		return
	}
	if len(userHandle) > 0 && !bytes.Equal(userHandle, []byte(pk.UserID)) {
		refuse(http.StatusUnauthorized, errPasskeyFailed)
		return
	}
	u, err := s.store.UserByID(pk.UserID)
	if err != nil {
		s.writeStoreError(w, err, "account")
		return
	}
	if u.VerifiedAt == "" {
		refuse(http.StatusForbidden, "verify your email first")
		return
	}
	if u.Disabled {
		refuse(http.StatusForbidden, "account deactivated")
		return
	}
	proofToken := s.proofCookieToken(r)
	if s.googleEnabled() {
		proof, err := s.peekProof(proofToken)
		if err != nil {
			s.writeStoreError(w, err, "google proof")
			return
		}
		if proof == nil {
			refuse(http.StatusForbidden, errNeedGoogle)
			return
		}
		if proof.Email != u.Email {
			refuse(http.StatusForbidden, errPasskeyOtherAccount)
			return
		}
	}

	signCount, err := webauthn.Verify(
		webauthn.Assertion{ClientDataJSON: clientData, AuthenticatorData: authData, Signature: sig},
		webauthn.Credential{PublicKey: pk.PublicKey, Alg: pk.Alg, SignCount: pk.SignCount},
		webauthn.Expect{RPID: s.appHost, Origin: s.appOrigin, Challenge: challenge})
	if err != nil {
		s.log.Warn("passkey sign-in refused", "err", err)
		refuse(http.StatusUnauthorized, errPasskeyFailed)
		return
	}
	if err := s.store.TouchPasskey(pk.ID, signCount, s.clk.Now()); err != nil {
		s.writeStoreError(w, err, "passkey")
		return
	}
	bundle, err := s.store.BundleFor(u.ID)
	if err != nil {
		s.writeStoreError(w, err, "bundle")
		return
	}
	token, err := s.issueToken(u)
	if err != nil {
		s.writeStoreError(w, err, "token")
		return
	}
	if s.googleEnabled() {
		if !s.useProof(w, proofToken) {
			return
		}
		s.clearProofCookie(w)
	}
	s.setSessionCookie(w, token, s.cfg.TokenTTL)
	writeJSON(w, http.StatusOK, passkeyLoginResponse{User: toMeView(u), Bundle: encodeBundle(*bundle), PasskeyMK: e2e.B64(pk.MK)})
}
