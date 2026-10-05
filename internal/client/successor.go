// The successor: nominating one, asking for access as one, and reading as a
// released one. As elsewhere in this package, every byte of cryptography is
// built with internal/e2e; see "Successor" in design/e2e-api.md.
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

var (
	// ErrSuccessorCode means the code the user gave is not the one the
	// directory's keys for the successor produce.
	ErrSuccessorCode = errors.New("the code does not match the keys the server lists for that user")
	// ErrSuccessorStale means another device signed a successor record since
	// this one read the seq.
	ErrSuccessorStale = errors.New("the successor record went stale: another device changed your successor since it was read; run the command again")
	// ErrNoSuccessor means there is nothing to remove.
	ErrNoSuccessor = errors.New("you have no successor")
	// ErrNotSuccessor means the caller is not the nominated successor of the
	// user whose artifact they read.
	ErrNotSuccessor = errors.New("you are not that user's successor")
)

// SuccessionRequest is a successor's request for access, as the nominating
// user and the successor see it.
type SuccessionRequest struct {
	RequestedAt   string `json:"requestedAt"`
	ReleaseAt     string `json:"releaseAt"`
	Released      bool   `json:"released"`
	DeactivatedAt string `json:"deactivatedAt"`
}

// SuccessorStatus is the caller's successor and any request, as
// GET /api/me/successor returns them. Successor, Record, and Request are nil
// when there is none. Seq is the last successor record the caller signed.
type SuccessorStatus struct {
	Successor   *DirectoryUser
	Record      *e2e.Envelope
	NominatedAt string
	Seq         int
	Request     *SuccessionRequest
}

// MySuccessor reads the caller's successor.
func (c *Client) MySuccessor() (*SuccessorStatus, error) {
	var resp struct {
		Successor   *directoryWire     `json:"successor"`
		Record      *e2e.Envelope      `json:"record"`
		NominatedAt string             `json:"nominatedAt"`
		Seq         int                `json:"seq"`
		Request     *SuccessionRequest `json:"request"`
	}
	if err := c.doJSON("GET", "/api/me/successor", nil, &resp); err != nil {
		return nil, err
	}
	st := &SuccessorStatus{Record: resp.Record, NominatedAt: resp.NominatedAt, Seq: resp.Seq, Request: resp.Request}
	if resp.Successor != nil {
		u, err := resp.Successor.user()
		if err != nil {
			return nil, err
		}
		st.Successor = &u
	}
	return st, nil
}

// SuccessorCode is the caller's own successor code, computed from the keys
// in their bundle, never from the directory.
func (c *Client) SuccessorCode() (string, error) {
	k, err := c.Unlock()
	if err != nil {
		return "", err
	}
	fp, err := hex.DecodeString(k.FP)
	if err != nil {
		return "", err
	}
	return e2e.SuccessorCode(fp), nil
}

// CheckSuccessorCode finds who in the directory and refuses, with
// ErrSuccessorCode, a code that the keys the directory serves for them do not
// produce. It sends nothing.
func (c *Client) CheckSuccessorCode(who, code string) (*DirectoryUser, error) {
	want, err := e2e.ParseSuccessorCode(code)
	if err != nil {
		return nil, err
	}
	dir, err := c.Directory()
	if err != nil {
		return nil, err
	}
	u, err := FindUser(dir, who)
	if err != nil {
		return nil, err
	}
	fp, err := hex.DecodeString(u.FP)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want, fp[:len(want)]) {
		return nil, fmt.Errorf("%w: %s", ErrSuccessorCode, u.Email)
	}
	return &u, nil
}

// sessionClient signs in with the password, for the endpoints that need a
// session, and returns a client on the session with the account's keys.
func (c *Client) sessionClient(password string) (*Client, *passwordSession, error) {
	me, err := c.Me()
	if err != nil {
		return nil, nil, err
	}
	ps, err := c.passwordSignIn(me.Email, password)
	if err != nil {
		return nil, nil, err
	}
	return &Client{Host: c.Host, Token: ps.Token, HTTP: c.HTTP, OnNotice: c.OnNotice}, ps, nil
}

// staleSeq maps the server's 409 for a successor record whose seq is not one
// more than the last to ErrSuccessorStale, and passes any other error on.
func staleSeq(err error) error {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict && strings.HasPrefix(apiErr.Message, "seq must be") {
		return ErrSuccessorStale
	}
	return err
}

// signSuccessor signs a successor record of k's.
func signSuccessor(k *UnlockedKeys, b e2e.SuccessorBody) (e2e.Envelope, error) {
	b.V, b.User = 1, k.UserID
	body, err := json.Marshal(b)
	if err != nil {
		return e2e.Envelope{}, err
	}
	return e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "successor", body)
}

// NominateSuccessor makes u the caller's successor, replacing any earlier
// one, after CheckSuccessorCode checked the keys it is given. It signs in with
// the password, signs a nominate record naming u and the fingerprint of u's
// keys, wraps EK to u's X25519 key, and sends both. It returns the record's
// seq.
func (c *Client) NominateSuccessor(u DirectoryUser, password string) (int, error) {
	k, err := c.Unlock()
	if err != nil {
		return 0, err
	}
	if u.ID == k.UserID {
		return 0, errors.New("you cannot be your own successor")
	}
	s, ps, err := c.sessionClient(password)
	if err != nil {
		return 0, err
	}
	st, err := s.MySuccessor()
	if err != nil {
		return 0, err
	}
	env, err := signSuccessor(k, e2e.SuccessorBody{Seq: st.Seq + 1, Successor: u.ID, SuccessorFP: u.FP, Action: "nominate"})
	if err != nil {
		return 0, err
	}
	wrapped, err := e2e.Wrap(rand.Reader, e2e.WrapContext{
		Purpose: "ek", Artifact: k.UserID, Epoch: 0, RecipientID: u.ID, RecipientPub: u.X25519Pub,
	}, k.EK)
	if err != nil {
		return 0, err
	}
	var out struct {
		Seq int `json:"seq"`
	}
	err = s.doJSON("PUT", "/api/me/successor", map[string]any{
		"authKey": e2e.B64(ps.AuthKey), "successor": u.ID, "record": env, "wrapped": e2e.B64(wrapped),
	}, &out)
	return out.Seq, staleSeq(err)
}

// RemoveSuccessor signs a remove record for the current successor and sends
// it. It returns the successor it removed.
func (c *Client) RemoveSuccessor() (*DirectoryUser, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	st, err := c.MySuccessor()
	if err != nil {
		return nil, err
	}
	if st.Successor == nil {
		return nil, ErrNoSuccessor
	}
	env, err := signSuccessor(k, e2e.SuccessorBody{Seq: st.Seq + 1, Successor: st.Successor.ID, Action: "remove"})
	if err != nil {
		return nil, err
	}
	err = c.doJSON("DELETE", "/api/me/successor", map[string]any{"record": env}, nil)
	return st.Successor, staleSeq(err)
}

// RefuseSuccession refuses a pending request for access to the caller's
// artifacts. The nomination stays.
func (c *Client) RefuseSuccession() error {
	return c.doJSON("DELETE", "/api/me/successor/request", nil, nil)
}

// SetNoticeEmail sets a personal address for notices, or clears it when
// address is empty. It needs a session, so it signs in with the password.
// pending is whether the server still has to verify the address.
func (c *Client) SetNoticeEmail(address, password string) (pending bool, err error) {
	s, _, err := c.sessionClient(password)
	if err != nil {
		return false, err
	}
	var out struct {
		Status string `json:"status"`
	}
	err = s.doJSON("PUT", "/api/me/notice-email", map[string]string{"email": address}, &out)
	return out.Status == "check-email", err
}

// Succession is a user whose nomination names the caller.
type Succession struct {
	User        DirectoryUser
	Record      e2e.Envelope
	NominatedAt string
	RequestedAt string
	ReleaseAt   string
	Released    bool
	// Wrapped is the user's EK wrapped to the caller, set once released.
	Wrapped []byte
}

// Successions lists the users whose nomination names the caller.
func (c *Client) Successions() ([]Succession, error) {
	var resp []struct {
		User        directoryWire `json:"user"`
		Record      e2e.Envelope  `json:"record"`
		NominatedAt string        `json:"nominatedAt"`
		RequestedAt string        `json:"requestedAt"`
		ReleaseAt   string        `json:"releaseAt"`
		Released    bool          `json:"released"`
		Wrapped     string        `json:"wrapped"`
	}
	if err := c.doJSON("GET", "/api/successions", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]Succession, 0, len(resp))
	for _, r := range resp {
		u, err := r.User.user()
		if err != nil {
			return nil, err
		}
		s := Succession{User: u, Record: r.Record, NominatedAt: r.NominatedAt, RequestedAt: r.RequestedAt, ReleaseAt: r.ReleaseAt, Released: r.Released}
		if s.Wrapped, err = e2e.UnB64(r.Wrapped); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// RequestSuccession asks for access to the artifacts of who, an email or user
// ID among the users who nominated the caller, and returns that user and the
// release date.
func (c *Client) RequestSuccession(who string) (*Succession, error) {
	list, err := c.Successions()
	if err != nil {
		return nil, err
	}
	email := e2e.NormalizeEmail(who)
	for _, s := range list {
		if s.User.ID != who && e2e.NormalizeEmail(s.User.Email) != email {
			continue
		}
		var out struct {
			RequestedAt string `json:"requestedAt"`
			ReleaseAt   string `json:"releaseAt"`
		}
		if err := c.doJSON("POST", "/api/successions/"+s.User.ID+"/request", nil, &out); err != nil {
			return nil, err
		}
		s.RequestedAt, s.ReleaseAt = out.RequestedAt, out.ReleaseAt
		return &s, nil
	}
	return nil, fmt.Errorf("%w: %s has not nominated you", ErrNotSuccessor, who)
}

// checkSuccession refuses a nomination record the nominating user's key does
// not verify, or that is not a nomination of the caller under the caller's own
// fingerprint. The server's wrapped EK is not used before it passes.
func checkSuccession(k *UnlockedKeys, s Succession, ed25519Pub []byte) error {
	var b e2e.SuccessorBody
	if err := e2e.OpenEnvelope(s.Record, ed25519Pub, "successor", &b); err != nil {
		return fmt.Errorf("the nomination record of %s does not verify: %w", s.User.Email, err)
	}
	switch {
	case b.User != s.User.ID:
		return fmt.Errorf("the nomination record is for %q, not %s", b.User, s.User.Email)
	case b.Successor != k.UserID:
		return fmt.Errorf("the nomination record of %s names %q, not you", s.User.Email, b.Successor)
	case b.SuccessorFP != k.FP:
		return fmt.Errorf("the nomination record of %s names another fingerprint than your own", s.User.Email)
	case b.Action != "nominate":
		return fmt.Errorf("the nomination record of %s has the action %q", s.User.Email, b.Action)
	}
	return nil
}

// successorEK opens the EK of ownerID, whose released nomination names the
// caller. It reads the nominating user's signing key from the directory, or,
// for a deactivated user whom the directory no longer lists, from the
// succession list: both are served by the server.
func (c *Client) successorEK(k *UnlockedKeys, ownerID string) ([]byte, error) {
	list, err := c.Successions()
	if err != nil {
		return nil, err
	}
	for _, s := range list {
		if s.User.ID != ownerID {
			continue
		}
		if !s.Released || len(s.Wrapped) == 0 {
			return nil, fmt.Errorf("%s's artifacts are not released to you yet", s.User.Email)
		}
		pub := s.User.Ed25519Pub
		if d, err := c.DirectoryUser(ownerID); err == nil {
			pub = d.Ed25519Pub
		} else if !isNotFound(err) {
			return nil, err
		}
		if err := checkSuccession(k, s, pub); err != nil {
			return nil, err
		}
		ek, err := e2e.Unwrap(k.X25519Priv, e2e.WrapContext{
			Purpose: "ek", Artifact: ownerID, Epoch: 0, RecipientID: k.UserID, RecipientPub: k.X25519Pub,
		}, s.Wrapped)
		if err != nil {
			return nil, fmt.Errorf("opening the EK of %s: %w", s.User.Email, err)
		}
		return ek, nil
	}
	return nil, fmt.Errorf("%w: %s has not nominated you", ErrNotSuccessor, ownerID)
}

// successorAKs opens the AK of every epoch up to the chain's latest from the
// estate copies the server serves a released successor, under the EK of the
// artifact's owner.
func (c *Client) successorAKs(k *UnlockedKeys, artifactID string, chain *e2e.Chain, keys *ArtifactKeys) (map[int][]byte, error) {
	ek, err := c.successorEK(k, chain.Latest.Owner)
	if err != nil {
		return nil, err
	}
	return estateAKs(ek, artifactID, chain, keys)
}
