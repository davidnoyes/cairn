package access

import "testing"

// readOnly marks the caller as a viewer account.
func readOnly(r Request) Request { r.Caller.ReadOnly = true; return r }

var readOnlyWrites = []Action{WriteData, PushVersion, Share, Delete, Rename, ApproveMember, ReviewVersions, Transfer, Estate}

// TestReadOnlyCallerNeverWrites checks every write action at every level for
// a viewer account: Forbidden whatever the level, owner and public writes
// included, while the reads and AnswerTransfer stay as the table decides.
func TestReadOnlyCallerNeverWrites(t *testing.T) {
	levels := []struct {
		name string
		req  Request
	}{
		{"owner", asUser(base(), owner)},
		{"editor", asUser(base(), editor)},
		{"viewer", asUser(base(), viewer)},
		{"team viewer", withWrap(team(asUser(base(), teamer), TeamViewer), 2)},
		{"team editor", withWrap(team(asUser(base(), teamer), TeamEditor), 2)},
		{"successor", asSuccessor(base())},
		{"link signed in, writes off", asUser(withLink(public(base(), false)), someone)},
		{"link signed in, writes on", asUser(withLink(public(base(), true)), someone)},
		{"owner, team share", team(asUser(base(), owner), TeamEditor)},
	}
	isWrite := map[Action]bool{}
	for _, a := range readOnlyWrites {
		isWrite[a] = true
	}
	for _, l := range levels {
		for _, a := range allActions {
			plain := Check(l.req, a)
			got := Check(readOnly(l.req), a)
			want := plain
			if isWrite[a] {
				want = Forbidden
			}
			if got != want {
				t.Errorf("%s / %s: got %v, want %v (without ReadOnly %v)", l.name, a, got, want, plain)
			}
			if isWrite[a] && got.Status() != 403 {
				t.Errorf("%s / %s: status %d, want 403", l.name, a, got.Status())
			}
		}
	}
}

// TestReadOnlyFilterSitsAfterNotFound checks the ReadOnly filter comes after
// the no-access and content-token checks: a viewer account with no access
// still gets 404, and a content token still answers 404 for an action it may
// not take, instead of 403.
func TestReadOnlyFilterSitsAfterNotFound(t *testing.T) {
	for _, a := range allActions {
		if got := Check(readOnly(asUser(base(), someone)), a); got != NotFound {
			t.Errorf("stranger / %s: got %v, want NotFound", a, got)
		}
	}
	tok := readOnly(viaContentToken(asUser(base(), editor), aid))
	want := map[Action]Decision{
		ReadContent: Allow, ReadMembership: Allow, WriteData: Forbidden,
		Share: NotFound, PushVersion: NotFound, Delete: NotFound, Transfer: NotFound,
	}
	for a, w := range want {
		if got := Check(tok, a); got != w {
			t.Errorf("content token / %s: got %v, want %v", a, got, w)
		}
	}
}
