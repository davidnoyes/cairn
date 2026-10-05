package server

import (
	"net/http"
	"testing"
	"time"
)

// A released successor reads the pending list of an artifact they reach as
// successor, approved users included, so their accept can carry the team
// over. Nothing else changes for them.
func TestSuccessorReadsThePendingList(t *testing.T) {
	w := newSuccWorld(t)
	w.art.setTeam("viewer")
	w.art.approve(w.u, w.other) // other holds a wrap but is not listed
	path := "/api/artifacts/" + w.art.id + "/pending"
	approve := func() int {
		code, _ := status(w.sc.testClient, "POST", w.art.approvePath(), approveReq(t, w.art, w.sc, w.other))
		return code
	}

	// A nominee who has not asked, and one still inside the 14 days, reach
	// nothing.
	wantStatus(t, w.sc.testClient, "GET", path, nil, http.StatusNotFound)
	w.nominate(w.sc)
	w.request()
	w.clk.Advance(14*day - time.Second)
	wantStatus(t, w.sc.testClient, "GET", path, nil, http.StatusNotFound)

	w.clk.Advance(time.Second)
	got := pendingOf(t, w.sc.testClient, w.art)
	if e, ok := got[w.other.id]; !ok || e.State != "approved" || e.Approval == nil {
		t.Errorf("the released successor's pending list: %+v, want other approved with the approval", got)
	}
	// Reading the list is all they gain.
	if code := approve(); code != http.StatusForbidden {
		t.Errorf("a successor's approval: %d, want 403", code)
	}

	// Anyone else is where they were.
	wantStatus(t, w.other.testClient, "GET", path, nil, http.StatusForbidden) // a team member
	anon := &testClient{t: t, base: w.base}
	wantStatus(t, anon, "GET", path, nil, http.StatusNotFound)
}
