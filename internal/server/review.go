package server

import (
	"errors"
	"net/http"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
)

// Reviewing a removed editor's versions. See design/e2e-api.md.

// versionView is a version as GET /api/artifacts/{id}/versions and
// GET /api/artifacts/{id}/versions/{vid} return it. PushedBy is null for a
// version with no recorded pusher; Vouch is null until the owner vouches.
type versionView struct {
	*store.Version
	PushedBy *string       `json:"pushedBy"`
	Vouch    *e2e.Envelope `json:"vouch"`
}

func viewVersions(vs []*store.Version, vouches map[string]store.Envelope) []*versionView {
	out := make([]*versionView, 0, len(vs))
	for _, v := range vs {
		view := &versionView{Version: v}
		if v.PushedBy != "" {
			view.PushedBy = &v.PushedBy
		}
		if e, ok := vouches[v.ID]; ok {
			env := envelopeOf(e)
			view.Vouch = &env
		}
		out = append(out, view)
	}
	return out
}

type reviewEntryView struct {
	ID        string  `json:"id"`
	Seq       int     `json:"seq"`
	PushedBy  *string `json:"pushedBy"`
	CreatedAt string  `json:"createdAt"`
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	out := []reviewEntryView{}
	err := s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		vs, err := tx.ReviewVersions()
		if err != nil {
			return err
		}
		for _, v := range viewVersions(vs, nil) {
			out = append(out, reviewEntryView{ID: v.ID, Seq: v.Seq, PushedBy: v.PushedBy, CreatedAt: v.CreatedAt})
		}
		return nil
	})
	if err != nil {
		s.writeStoreError(w, err, "artifact")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type vouchRequest struct {
	Vouch e2e.Envelope `json:"vouch"`
}

// handleVouch stores the owner's vouch for a version. The envelope must be
// the artifact owner's, under their current signing key, and name this
// artifact and version. The manifest is empty until milestone 4 adds signed
// manifests; the server has nothing to compare it with.
func (s *Server) handleVouch(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	vid := r.PathValue("vid")
	var req vouchRequest
	if !readJSON(w, r, &req) {
		return
	}
	if _, err := s.store.VersionByID(a.ID, vid); err != nil {
		s.writeStoreError(w, err, "version")
		return
	}
	var refused string
	err := s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		cur, err := tx.Artifact()
		if err != nil {
			return err
		}
		owner, err := tx.UserByID(cur.OwnerID)
		if err != nil {
			return err
		}
		if refused = checkVouch(req.Vouch, owner, a.ID, vid); refused != "" {
			return nil
		}
		return tx.PutVouch(vid, store.Envelope{Body: req.Vouch.Body, Sig: req.Vouch.Sig, Signer: req.Vouch.Signer})
	})
	switch {
	case err != nil:
		s.writeStoreError(w, err, "version")
	case refused != "":
		writeError(w, http.StatusBadRequest, refused)
	default:
		s.log.Info("version vouched", "artifact", a.ID, "version", vid, "by", requestUser(r).Email)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

// checkVouch returns why env is not the owner's vouch for version of
// artifact, or "" when it is. The signature is checked under the owner's
// current key, so a vouch signed with an earlier key is refused.
func checkVouch(env e2e.Envelope, owner *store.KeyedUser, artifact, version string) string {
	if env.Signer != owner.ID {
		return "the vouch is not signed by the owner"
	}
	var body e2e.VouchBody
	if err := e2e.OpenEnvelope(env, owner.Ed25519Pub, "vouch", &body); err != nil {
		if errors.Is(err, e2e.ErrDecrypt) {
			return "the vouch does not verify under the owner's current key"
		}
		return "the vouch body is invalid: " + err.Error()
	}
	switch {
	case body.Artifact != artifact:
		return "the vouch is for another artifact"
	case body.Version != version:
		return "the vouch is for another version"
	case body.Manifest != "":
		return "the manifest must be empty until signed manifests exist"
	}
	return ""
}
