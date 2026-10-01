package server

import (
	"net/http"
	"strconv"
)

// epochHeader is how a write declares the epoch it was made under.
const epochHeader = "X-Cairn-Epoch"

// declaredEpoch reads the epoch a write declares. It returns 0 when the
// header is absent, which is allowed while content is not encrypted. A value
// that is not a positive decimal without leading zeros is a 400.
func declaredEpoch(w http.ResponseWriter, r *http.Request) (int, bool) {
	vals := r.Header.Values(epochHeader)
	if len(vals) == 0 {
		return 0, true
	}
	v := vals[0]
	n, err := strconv.ParseUint(v, 10, 31)
	if len(vals) > 1 || err != nil || n == 0 || v[0] == '0' {
		writeError(w, http.StatusBadRequest, epochHeader+" must be a positive decimal number without leading zeros")
		return 0, false
	}
	return int(n), true
}

// underEpoch runs write unless the artifact has moved past the declared
// epoch, and keeps the epoch from changing until write returns (see
// store.UnderEpoch). With no declared epoch (0) it just runs write. write must
// not write to the client.
func (s *Server) underEpoch(artifactID string, declared int, write func()) error {
	if declared == 0 {
		write()
		return nil
	}
	return s.store.UnderEpoch(artifactID, declared, write)
}
