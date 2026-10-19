package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/membership"
	"github.com/aloisdeniel/cairn/internal/store"
)

// errEstateExists is the 409 answer to an estate copy for an epoch that has
// one.
var errEstateExists = errors.New("that epoch already has an estate copy")

type putEstateRequest struct {
	Sealed string `json:"sealed"`
}

// handlePutEstate stores the owner's estate copy of an epoch that has none:
// the copy a manager's next-epoch record could not carry, because only the
// owner seals one. The epoch must exist, and a copy already stored is never
// replaced, so the owner's client sends it once. The check and the write run
// in one transaction that holds the artifact row lock.
func (s *Server) handlePutEstate(w http.ResponseWriter, r *http.Request) {
	a := requestArtifact(r)
	epoch, err := strconv.Atoi(r.PathValue("epoch"))
	if err != nil || epoch < 1 {
		writeError(w, http.StatusNotFound, "epoch not found")
		return
	}
	var req putEstateRequest
	if !readJSON(w, r, &req) {
		return
	}
	sealed, err := e2e.UnB64(req.Sealed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "sealed is not base64")
		return
	}
	if len(sealed) != membership.EstateSize {
		writeError(w, http.StatusBadRequest, "sealed is not "+strconv.Itoa(membership.EstateSize)+" bytes")
		return
	}
	err = s.store.WithArtifact(a.ID, func(tx *store.ArtifactTx) error {
		cur, err := tx.Artifact()
		if err != nil {
			return err
		}
		if epoch > cur.Epoch {
			return store.ErrNotFound
		}
		have, err := tx.Estates()
		if err != nil {
			return err
		}
		for _, e := range have {
			if e.Epoch == epoch {
				return errEstateExists
			}
		}
		return tx.PutEstate(epoch, sealed)
	})
	switch {
	case errors.Is(err, errEstateExists):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.writeStoreError(w, err, "epoch")
		return
	}
	s.log.Info("estate copy added", "artifact", a.ID, "epoch", epoch, "by", requestUser(r).Email)
	writeJSON(w, http.StatusOK, map[string]int{"epoch": epoch})
}
