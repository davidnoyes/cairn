package server

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"

	"github.com/aloisdeniel/cairn/internal/access"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/membership"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

// Access control for artifact routes. Every route under /api/artifacts/{id}
// and every artifact page builds an access.Request from the caller and the
// artifact's latest membership record, and asks access.Check. A request with
// no access gets 404, administrators included. See design/e2e-api.md
// (Access).

// errBadCredentials marks credentials that are present but invalid.
var errBadCredentials = errors.New("invalid credentials")

// requestAccess returns the access.Request attached by artifactRoute.
func requestAccess(r *http.Request) access.Request {
	req, _ := r.Context().Value(accessCtxKey).(access.Request)
	return req
}

// callerFor describes a resolved user, or an anonymous caller when u is nil.
// key is the API key that authenticated the request, nil for a session.
func (s *Server) callerFor(u *store.User, key *store.APIKey) (access.Caller, error) {
	if u == nil {
		return access.Caller{Kind: access.Anonymous}, nil
	}
	c := access.Caller{UserID: u.ID, Kind: access.Session, IsAdmin: u.IsAdmin}
	if key != nil {
		c.Kind = access.APIKey
	}
	b, err := s.store.BundleFor(u.ID)
	if err != nil {
		return access.Caller{}, err
	}
	c.Fingerprint = hex.EncodeToString(e2e.Fingerprint(b.X25519Pub, b.Ed25519Pub))
	return c, nil
}

// callerOf resolves the request's credentials. Invalid credentials are
// errBadCredentials.
func (s *Server) callerOf(r *http.Request) (access.Caller, *store.User, *store.APIKey, error) {
	u, key, err := s.resolveAny(r)
	if err != nil {
		return access.Caller{}, nil, nil, errBadCredentials
	}
	c, err := s.callerFor(u, key)
	return c, u, key, err
}

// linkToken returns the X-Cairn-Link-Token header's bytes, or nil when it is
// missing or not base64.
func linkToken(r *http.Request) []byte {
	h := r.Header.Get("X-Cairn-Link-Token")
	if h == "" {
		return nil
	}
	tok, err := e2e.UnB64(h)
	if err != nil {
		return nil
	}
	return tok
}

// linkMatches reports whether token opens a's public link: the artifact is
// public and the token's hash equals the stored hash, compared in constant
// time.
func linkMatches(a *store.Artifact, token []byte) bool {
	if !a.Public || token == nil || a.PublicTokenHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(e2e.LinkTokenHash(token)), []byte(a.PublicTokenHash)) == 1
}

// accessRequest reads what access.Check needs about c and artifact id. A
// missing artifact is store.ErrNotFound.
func (s *Server) accessRequest(c access.Caller, id string, token []byte) (*store.Artifact, access.Request, error) {
	st, err := s.store.AccessState(id, c.UserID)
	if err != nil {
		return nil, access.Request{}, err
	}
	a := st.Artifact
	c.Wraps = nil
	for _, w := range st.Wraps {
		c.Wraps = append(c.Wraps, access.Wrap{Epoch: w.Epoch})
	}
	req := access.Request{
		Caller: c,
		Artifact: access.Artifact{ID: a.ID, OwnerID: a.OwnerID, Epoch: a.Epoch, Team: a.Team,
			Public: a.Public, PublicWrites: a.PublicWrites},
		LinkToken: linkMatches(a, token),
	}
	if st.Member != nil {
		req.Member = &access.Member{Role: st.Member.Role, FP: st.Member.FP}
	}
	return a, req, nil
}

// resolveReadable resolves the {id} segment among the artifacts c can read:
// an artifact ID first, else a resource reference. An unreadable artifact is
// store.ErrNotFound, so a reference cannot reveal one through a 409.
func (s *Server) resolveReadable(c access.Caller, ref string, token []byte) (*store.Artifact, access.Request, error) {
	a, req, err := s.accessRequest(c, ref, token)
	switch {
	case err == nil:
		if access.LevelOf(req) != access.LevelNone {
			return a, req, nil
		}
	case !errors.Is(err, store.ErrNotFound):
		return nil, access.Request{}, err
	}
	matches, err := s.store.ArtifactsByResource(ref)
	if err != nil {
		return nil, access.Request{}, err
	}
	var found []*store.Artifact
	var foundReq access.Request
	for _, m := range matches {
		a, req, err := s.accessRequest(c, m.ID, token)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, access.Request{}, err
		}
		if access.LevelOf(req) != access.LevelNone {
			found, foundReq = append(found, a), req
		}
	}
	switch len(found) {
	case 0:
		return nil, access.Request{}, store.ErrNotFound
	case 1:
		return found[0], foundReq, nil
	default:
		return nil, access.Request{}, errAmbiguousResource{ref: ref, count: len(found)}
	}
}

// decisionMessage is the error text for a refused decision.
func decisionMessage(d access.Decision) string {
	switch d {
	case access.Forbidden:
		return "your access does not allow this"
	case access.Conflict:
		return "the artifact's state refuses this"
	default:
		return "artifact not found"
	}
}

// artifactRoute resolves the {id} segment among the artifacts the caller can
// read, checks act, and attaches the artifact, the access.Request, and the
// caller to the request.
func (s *Server) artifactRoute(act access.Action, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, u, key, err := s.callerOf(r)
		if errors.Is(err, errBadCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if err != nil {
			s.writeStoreError(w, err, "user")
			return
		}
		a, req, err := s.resolveReadable(c, r.PathValue("id"), linkToken(r))
		if err != nil {
			var ambiguous errAmbiguousResource
			if errors.As(err, &ambiguous) {
				writeError(w, http.StatusConflict, ambiguous.Error())
				return
			}
			s.writeStoreError(w, err, "artifact")
			return
		}
		if d := access.Check(req, act); d != access.Allow {
			writeError(w, d.Status(), decisionMessage(d))
			return
		}
		ctx := context.WithValue(r.Context(), artifactCtxKey, a)
		r = r.WithContext(context.WithValue(ctx, accessCtxKey, req))
		if u != nil {
			r = withUser(r, u)
		}
		if key != nil {
			r = withAPIKey(r, key)
		}
		next(w, r)
	}
}

// pageArtifact is artifactRoute for the artifact pages, with plain-text
// errors. A caller without access who is not signed in goes to the login
// page; a signed-in one gets 404. It returns nil when it has answered.
func (s *Server) pageArtifact(w http.ResponseWriter, r *http.Request) *store.Artifact {
	toLogin := func() {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	}
	c, _, _, err := s.callerOf(r)
	if errors.Is(err, errBadCredentials) {
		toLogin()
		return nil
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil
	}
	a, req, err := s.resolveReadable(c, r.PathValue("id"), linkToken(r))
	if err == nil && access.Check(req, access.ReadContent) != access.Allow {
		err = store.ErrNotFound
	}
	if err != nil {
		var ambiguous errAmbiguousResource
		switch {
		case errors.As(err, &ambiguous):
			http.Error(w, ambiguous.Error(), http.StatusConflict)
		case !errors.Is(err, store.ErrNotFound):
			http.Error(w, "internal error", http.StatusInternalServerError)
		case c.Kind == access.Anonymous:
			toLogin()
		default:
			http.NotFound(w, r)
		}
		return nil
	}
	return a
}

// Artifact JSON

type transferView struct {
	To string `json:"to"`
	By string `json:"by"`
	At string `json:"at"`
}

// artifactView is an artifact as GET /api/artifacts/{id} and each entry of
// GET /api/artifacts return it. Resources are kept from milestone 2.
type artifactView struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Owner        string            `json:"owner"`
	Access       access.Level      `json:"access"`
	Epoch        int               `json:"epoch"`
	Team         string            `json:"team"`
	Public       bool              `json:"public"`
	PublicWrites bool              `json:"publicWrites"`
	Transfer     *transferView     `json:"transfer"`
	CreatedAt    string            `json:"createdAt"`
	UpdatedAt    string            `json:"updatedAt"`
	Resources    []*store.Resource `json:"resources,omitempty"`
}

func (s *Server) viewOf(a *store.Artifact, level access.Level) (*artifactView, error) {
	v := &artifactView{ID: a.ID, Name: a.Name, Description: a.Description, Owner: a.OwnerID, Access: level,
		Epoch: a.Epoch, Team: a.Team, Public: a.Public, PublicWrites: a.PublicWrites,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
	o, err := s.store.OpenOffer(a.ID)
	switch {
	case err == nil:
		v.Transfer = &transferView{To: o.To, By: o.By, At: o.CreatedAt}
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	if v.Resources, err = s.store.ListResources(a.ID); err != nil {
		return nil, err
	}
	return v, nil
}

// Wire shapes shared by create and PUT membership

type wrapWire struct {
	User    string `json:"user"`
	Epoch   int    `json:"epoch"`
	Wrapped string `json:"wrapped"`
}

type estateWire struct {
	Epoch  int    `json:"epoch"`
	Sealed string `json:"sealed"`
}

// changeOf decodes the base64 in a change's wraps and estate copies.
func changeOf(env e2e.Envelope, wraps []wrapWire, estate []estateWire, linkHash string) (membership.Change, error) {
	ch := membership.Change{Envelope: env, LinkTokenHash: linkHash}
	for _, w := range wraps {
		b, err := e2e.UnB64(w.Wrapped)
		if err != nil {
			return ch, errors.New("wraps: wrapped is not base64")
		}
		ch.Wraps = append(ch.Wraps, membership.WrapIn{User: w.User, Epoch: w.Epoch, Wrapped: b})
	}
	for _, e := range estate {
		b, err := e2e.UnB64(e.Sealed)
		if err != nil {
			return ch, errors.New("estate: sealed is not base64")
		}
		ch.Estate = append(ch.Estate, membership.EstateIn{Epoch: e.Epoch, Sealed: b})
	}
	return ch, nil
}

// applyChange loads the artifact's current state, checks ch against it, and
// writes it, all in tx.
func applyChange(tx *store.ArtifactTx, ch membership.Change) (*membership.Result, error) {
	dir := membership.TxDirectory(tx)
	cur, err := membership.Load(tx, dir)
	if err != nil {
		return nil, err
	}
	res, err := membership.Check(cur, dir, ch)
	if err != nil {
		return nil, err
	}
	return res, membership.Apply(tx, res)
}

// writeChangeError answers a refused or failed change.
func (s *Server) writeChangeError(w http.ResponseWriter, err error) {
	var refused *membership.Error
	switch {
	case errors.As(err, &refused):
		writeError(w, refused.Status, refused.Error())
	case errors.Is(err, store.ErrStale):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.writeStoreError(w, err, "artifact")
	}
}

// Creating an artifact

type createArtifactRequest struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Membership  e2e.Envelope `json:"membership"`
	Wraps       []wrapWire   `json:"wraps"`
	Estate      []estateWire `json:"estate"`
}

// isRandomUUID reports whether id is a version 4, RFC 4122 UUID in its
// canonical lowercase form.
func isRandomUUID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u.Version() == 4 && u.Variant() == uuid.RFC4122 && u.String() == id
}

func (s *Server) handleCreateArtifact(w http.ResponseWriter, r *http.Request) {
	var req createArtifactRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !isRandomUUID(req.ID) {
		writeError(w, http.StatusBadRequest, "id must be a random (version 4) UUID")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	ch, err := changeOf(req.Membership, req.Wraps, req.Estate, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u := requestUser(r)
	a, err := s.store.CreateOwnedArtifact(req.ID, req.Name, req.Description, u.ID, func(tx *store.ArtifactTx) error {
		_, err := applyChange(tx, ch)
		return err
	})
	if errors.Is(err, store.ErrExists) {
		writeError(w, http.StatusConflict, "artifact id already in use")
		return
	}
	if err != nil {
		s.writeChangeError(w, err)
		return
	}
	v, err := s.viewOf(a, access.LevelOwner)
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	s.log.Info("artifact created", "id", a.ID, "name", a.Name, "by", u.Email)
	writeJSON(w, http.StatusCreated, v)
}

// Membership

type membershipRequest struct {
	Membership    e2e.Envelope `json:"membership"`
	Wraps         []wrapWire   `json:"wraps"`
	Estate        []estateWire `json:"estate"`
	LinkTokenHash string       `json:"linkTokenHash"`
}

func (s *Server) handlePutMembership(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	var req membershipRequest
	if !readJSON(w, r, &req) {
		return
	}
	ch, err := changeOf(req.Membership, req.Wraps, req.Estate, req.LinkTokenHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var epoch int
	err = s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		res, err := applyChange(tx, ch)
		if err != nil {
			return err
		}
		epoch = res.Body.Epoch
		return nil
	})
	if err != nil {
		s.writeChangeError(w, err)
		return
	}
	s.log.Info("membership changed", "artifact", a.ID, "epoch", epoch, "by", requestUser(r).Email)
	writeJSON(w, http.StatusOK, map[string]int{"epoch": epoch})
}

type membershipView struct {
	Records []e2e.Envelope          `json:"records"`
	Offers  map[string]e2e.Envelope `json:"offers"`
	Owners  map[string]e2e.KeyPair  `json:"owners"`
	// Rotations and Successors stay empty until step 7 adds key rotation
	// and successors.
	Rotations  map[string][]e2e.Envelope `json:"rotations"`
	Successors map[string]e2e.Envelope   `json:"successors"`
	// Keys is set for link scope only: every listed editor's keys.
	Keys map[string]e2e.KeyPair `json:"keys,omitempty"`
}

func keyPairOf(u *store.KeyedUser) e2e.KeyPair {
	return e2e.KeyPair{X25519: e2e.B64(u.X25519Pub), Ed25519: e2e.B64(u.Ed25519Pub)}
}

func envelopeOf(e store.Envelope) e2e.Envelope {
	return e2e.Envelope{Body: e.Body, Sig: e.Sig, Signer: e.Signer}
}

func (s *Server) handleGetMembership(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	linkScope := access.LevelOf(requestAccess(r)) == access.LevelLink
	v := membershipView{
		Records: []e2e.Envelope{}, Offers: map[string]e2e.Envelope{}, Owners: map[string]e2e.KeyPair{},
		Rotations: map[string][]e2e.Envelope{}, Successors: map[string]e2e.Envelope{},
	}
	err := s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		records, err := tx.Records()
		if err != nil {
			return err
		}
		accepted, err := tx.AcceptedOffers()
		if err != nil {
			return err
		}
		for _, rec := range records {
			v.Records = append(v.Records, envelopeOf(rec.Envelope))
			if o := accepted[rec.Transfer]; rec.Transfer != "" && o != nil && o.Envelope != nil {
				v.Offers[rec.Transfer] = envelopeOf(*o.Envelope)
			}
			if _, done := v.Owners[rec.OwnerFp]; done {
				continue
			}
			// Only the owner's current keys are known until step 7 keeps
			// rotation records; the client ignores a pair that does not
			// hash to its key.
			u, err := tx.UserByID(rec.OwnerID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if u.FP == rec.OwnerFp {
				v.Owners[rec.OwnerFp] = keyPairOf(u)
			}
		}
		if !linkScope {
			return nil
		}
		members, err := tx.Members()
		if err != nil {
			return err
		}
		v.Keys = map[string]e2e.KeyPair{}
		for _, m := range members {
			if m.Role != access.RoleEditor {
				continue
			}
			u, err := tx.UserByID(m.UserID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			v.Keys[m.UserID] = keyPairOf(u)
		}
		return nil
	})
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// Keys

type keyWrapView struct {
	Epoch   int    `json:"epoch"`
	Wrapped string `json:"wrapped"`
	FP      string `json:"fp"`
}

type estateView struct {
	Epoch  int    `json:"epoch"`
	Sealed string `json:"sealed"`
}

type keysView struct {
	Wraps  []keyWrapView `json:"wraps"`
	Estate []estateView  `json:"estate"`
}

// handleGetKeys returns the caller's own wraps, or for the owner the estate
// copies with an empty wraps.
func (s *Server) handleGetKeys(w http.ResponseWriter, r *http.Request) {
	a, req := requestArtifact(r), requestAccess(r)
	v := keysView{Wraps: []keyWrapView{}, Estate: []estateView{}}
	if access.LevelOf(req) == access.LevelOwner {
		estate, err := s.store.EstateKeys(a.ID)
		if err != nil {
			s.writeStoreError(w, err, "keys")
			return
		}
		for _, e := range estate {
			v.Estate = append(v.Estate, estateView{Epoch: e.Epoch, Sealed: e2e.B64(e.Sealed)})
		}
	} else {
		wraps, err := s.store.WrapsFor(a.ID, req.Caller.UserID)
		if err != nil {
			s.writeStoreError(w, err, "keys")
			return
		}
		for _, k := range wraps {
			v.Wraps = append(v.Wraps, keyWrapView{Epoch: k.Epoch, Wrapped: e2e.B64(k.Wrapped), FP: k.FP})
		}
	}
	writeJSON(w, http.StatusOK, v)
}
