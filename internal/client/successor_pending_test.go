package client

import (
	"slices"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/server"
)

// newUser signs up email and returns a keyed client for it.
func (x *xfer) newUser(email string) *Client {
	x.t.Helper()
	signupVerify(x.t, x.host, x.m, email, testPassword)
	out, err := New(x.host, "").Login(email, testPassword)
	if err != nil {
		x.t.Fatal(err)
	}
	return keyedFor(x.t, x.host, out.APIKey)
}

// A team member whom an editor approved holds a wrap but is not listed. The
// released successor, who is not a member, takes the artifact by an
// administrator's offer, and carries that member into the new epoch, as an
// editor's accept would.
func TestSuccessorAcceptCarriesApprovedTeamMembers(t *testing.T) {
	clk := clock.NewFake(time.Now())
	x := newXfer(t, func(c *server.Config) { c.Clock = clk })
	fay, gus := x.newUser("fay@example.com"), x.newUser("gus@example.com")
	if _, err := x.ada.Team(x.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.cat.Approve(x.artifact, "fay@example.com", false); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// Ada nominates gus, who asks, and 14 days pass.
	code, err := gus.SuccessorCode()
	if err != nil {
		t.Fatal(err)
	}
	u, err := x.ada.CheckSuccessorCode("gus@example.com", code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.ada.NominateSuccessor(*u, testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := gus.RequestSuccession("ada@example.com"); err != nil {
		t.Fatal(err)
	}
	clk.Advance(14*24*time.Hour + time.Hour)
	x.deactivate(x.ada)
	x.adminOffer(gus)

	if _, err := gus.AcceptTransfer(x.artifact, AcceptTransferOptions{}); err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	latest := x.verify(fay).Chain.Latest
	if latest.Owner != x.id(gus) || latest.OwnerFP != mustUnlock(t, gus).FP || latest.Epoch != 3 {
		t.Errorf("latest record: owner %s, epoch %d", latest.Owner, latest.Epoch)
	}
	if got := x.wrapEpochs(fay); !slices.Equal(got, []int{1, 2, 3}) {
		t.Errorf("fay holds wraps for epochs %v, want 1, 2, 3", got)
	}
	if !slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == x.id(fay) }) {
		t.Errorf("the new record does not list fay: %+v", latest.Members)
	}
}

// A listed editor offered the artifact by an administrator carries an approved
// team member over too: the open offer, not the caller's level, decides who
// sees approved members.
func TestAdminOfferToAnEditorCarriesApprovedTeamMembers(t *testing.T) {
	x := newXfer(t, nil)
	fay := x.newUser("fay@example.com")
	if _, err := x.ada.Team(x.artifact, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.cat.Approve(x.artifact, "fay@example.com", false); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	x.deactivate(x.ada)
	x.adminOffer(x.bob)
	// Only the editor the offer names sees the approval; cat, another editor,
	// does not.
	approved := func(c *Client) bool {
		t.Helper()
		pending, err := c.Pending(x.artifact)
		if err != nil {
			t.Fatalf("Pending: %v", err)
		}
		return slices.ContainsFunc(pending, func(p PendingUser) bool { return p.User.ID == x.id(fay) && p.State == "approved" })
	}
	if !approved(x.bob) || approved(x.cat) {
		t.Errorf("fay approved: to bob %v, to cat %v; want bob only", approved(x.bob), approved(x.cat))
	}

	if _, err := x.bob.AcceptTransfer(x.artifact, AcceptTransferOptions{}); err != nil {
		t.Fatalf("AcceptTransfer: %v", err)
	}
	latest := x.verify(fay).Chain.Latest
	if latest.Owner != x.id(x.bob) {
		t.Errorf("latest record owner %s, want bob", latest.Owner)
	}
	if got := x.wrapEpochs(fay); !slices.Contains(got, latest.Epoch) {
		t.Errorf("fay holds wraps for epochs %v, not the new epoch %d", got, latest.Epoch)
	}
	if !slices.ContainsFunc(latest.Members, func(m e2e.Member) bool { return m.User == x.id(fay) }) {
		t.Errorf("the new record does not list fay: %+v", latest.Members)
	}
}
