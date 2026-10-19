package access

import "testing"

const manager = "manager"

// asManager is a signed-in manager listed under fp, whose current keys hash
// to fresh.
func asManager(r Request, listed, current string) Request {
	r.Caller.UserID = manager
	r.Caller.Fingerprint = current
	r.Member = &Member{Role: RoleManager, FP: listed}
	return r
}

// TestManagerByAction checks every action for a listed manager whose
// fingerprint is current, whose fingerprint is stale, and who is a viewer
// account: a manager has every editor action plus Share, and not Delete,
// Transfer, ReviewVersions, or Estate.
func TestManagerByAction(t *testing.T) {
	fresh := asManager(base(), "fp-m", "fp-m")
	stale := asManager(base(), "fp-m", "fp-other")
	// The team share lets ApproveMember through to Allow.
	fresh, stale = team(fresh, TeamViewer), team(stale, TeamViewer)
	want := map[Action][3]Decision{
		// fresh, stale, viewer account
		ReadContent:    {Allow, Allow, Allow},
		WriteData:      {Allow, Forbidden, Forbidden},
		PushVersion:    {Allow, Forbidden, Forbidden},
		Share:          {Allow, Forbidden, Forbidden},
		Delete:         {Forbidden, Forbidden, Forbidden},
		Rename:         {Allow, Forbidden, Forbidden},
		ReadMembership: {Allow, Allow, Allow},
		ReadKeys:       {Allow, Allow, Allow},
		ListPending:    {Allow, Forbidden, Allow},
		ApproveMember:  {Allow, Forbidden, Forbidden},
		ReviewVersions: {Forbidden, Forbidden, Forbidden},
		Transfer:       {Forbidden, Forbidden, Forbidden},
		AnswerTransfer: {Allow, Allow, Allow},
		Estate:         {Forbidden, Forbidden, Forbidden},
	}
	for _, a := range allActions {
		w, ok := want[a]
		if !ok {
			t.Fatalf("no expectation for %s", a)
		}
		for i, r := range []Request{fresh, stale, readOnly(fresh)} {
			if got := Check(r, a); got != w[i] {
				t.Errorf("%s / case %d: got %v, want %v", a, i, got, w[i])
			}
		}
	}
}

// TestManagerLevel checks LevelOf names a listed manager LevelManager, fresh
// or stale, and that a manager is matched before an editor would be.
func TestManagerLevel(t *testing.T) {
	for _, current := range []string{"fp-m", "fp-other"} {
		if got := LevelOf(asManager(base(), "fp-m", current)); got != LevelManager {
			t.Errorf("manager under %s: level %v", current, got)
		}
	}
	// The owner, listed as nothing, still outranks.
	r := asManager(base(), "fp-m", "fp-m")
	r.Caller.UserID = owner
	if got := LevelOf(r); got != LevelOwner {
		t.Errorf("owner: level %v", got)
	}
	// An editor is still an editor, with no Share.
	if got := Check(asUser(base(), editor), Share); got != Forbidden {
		t.Errorf("editor Share: %v", got)
	}
}

// TestManagerContentToken checks a content token gives a manager only what
// it gives an editor.
func TestManagerContentToken(t *testing.T) {
	r := viaContentToken(asManager(base(), "fp-m", "fp-m"), aid)
	for a, w := range map[Action]Decision{
		ReadContent: Allow, ReadMembership: Allow, WriteData: Allow,
		Share: NotFound, Estate: NotFound, PushVersion: NotFound, Delete: NotFound,
	} {
		if got := Check(r, a); got != w {
			t.Errorf("content token / %s: got %v, want %v", a, got, w)
		}
	}
}

// TestEstateIsOwnerOnly checks the estate action: the owner alone, at any
// credential kind but a content token, and no one else at any level.
func TestEstateIsOwnerOnly(t *testing.T) {
	for _, k := range []Kind{Session, APIKey} {
		r := asUser(base(), owner)
		r.Caller.Kind = k
		if got := Check(r, Estate); got != Allow {
			t.Errorf("owner, kind %d: %v", k, got)
		}
	}
	if got := Check(viaContentToken(asUser(base(), owner), aid), Estate); got != NotFound {
		t.Errorf("owner's content token: %v", got)
	}
	for name, r := range map[string]Request{
		"editor": asUser(base(), editor), "viewer": asUser(base(), viewer),
		"team":      withWrap(team(asUser(base(), teamer), TeamEditor), 2),
		"successor": asSuccessor(base()),
	} {
		if got := Check(r, Estate); got != Forbidden {
			t.Errorf("%s: %v, want Forbidden", name, got)
		}
	}
}
