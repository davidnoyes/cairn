package access

import "testing"

// inGroup is r with the caller a member of a group the record lists.
func inGroup(r Request) Request {
	r.InGroup = true
	r.Artifact.HasGroups = true
	return r
}

// A member of a listed group who holds a wrap at the current epoch reads, at
// the team level, with the team share off.
func TestAGroupMemberHoldingAWrapReads(t *testing.T) {
	r := withWrap(asUser(inGroup(base()), teamer), 2)
	if got := LevelOf(r); got != LevelTeam {
		t.Fatalf("level = %s, want team", got)
	}
	for _, act := range []Action{ReadContent, ReadMembership, ReadKeys} {
		if got := Check(r, act); got != Allow {
			t.Errorf("%s: %s, want Allow", act, got)
		}
	}
	for _, act := range []Action{WriteData, PushVersion, Share, Delete, Rename, ApproveMember, ListPending, ReviewVersions, Transfer, Estate, Move} {
		if got := Check(r, act); got != Forbidden {
			t.Errorf("%s: %s, want Forbidden", act, got)
		}
	}
}

func TestAGroupMemberReadsNothingWithoutAWrapAtTheCurrentEpoch(t *testing.T) {
	for name, r := range map[string]Request{
		"no wrap":                 asUser(inGroup(base()), teamer),
		"a wrap of an old epoch":  withWrap(asUser(inGroup(base()), teamer), 1),
		"a wrap of a later epoch": withWrap(asUser(inGroup(base()), teamer), 3),
	} {
		if got := Check(r, ReadContent); got != NotFound {
			t.Errorf("%s: %s, want NotFound", name, got)
		}
	}
}

// Leaving every listed group, with the team share off, ends access at once:
// the server finds the caller in no group, and answers 404 to a holder.
func TestSomeoneWhoLeftEveryListedGroupGetsNotFound(t *testing.T) {
	r := withWrap(asUser(base(), teamer), 2)
	r.Artifact.HasGroups = true
	for _, act := range []Action{ReadContent, ReadMembership, ReadKeys} {
		if got := Check(r, act); got != NotFound {
			t.Errorf("%s: %s, want NotFound", act, got)
		}
	}
	if got := LevelOf(r); got != LevelNone {
		t.Errorf("level = %s, want none", got)
	}
	// The team share still covers them.
	if got := Check(team(r, TeamViewer), ReadContent); got != Allow {
		t.Errorf("with the team share on: %s, want Allow", got)
	}
}

func TestAGroupGrantsNothingToAnAnonymousCallerOrALinkOnlyToken(t *testing.T) {
	r := inGroup(base())
	r.Caller.Wraps = []Wrap{{Epoch: 2}}
	if got := Check(anon(r), ReadContent); got != NotFound {
		t.Errorf("anonymous: %s", got)
	}
	r = asUser(r, teamer)
	r.Caller.LinkOnly = true
	if got := Check(r, ReadContent); got != NotFound {
		t.Errorf("a link-only token: %s", got)
	}
}

func TestAViewerAccountInAGroupNeverWrites(t *testing.T) {
	r := withWrap(asUser(inGroup(base()), teamer), 2)
	r.Caller.ReadOnly = true
	if got := Check(r, ReadContent); got != Allow {
		t.Errorf("read: %s", got)
	}
	if got := Check(r, WriteData); got != Forbidden {
		t.Errorf("write: %s", got)
	}
}

// An approval needs a team share or a listed group to approve into.
func TestApprovingNeedsTheTeamShareOrAListedGroup(t *testing.T) {
	r := asUser(base(), editor)
	if got := Check(r, ApproveMember); got != Conflict {
		t.Errorf("neither: %s, want Conflict", got)
	}
	if got := Check(team(r, TeamViewer), ApproveMember); got != Allow {
		t.Errorf("team: %s, want Allow", got)
	}
	r.Artifact.HasGroups = true
	if got := Check(r, ApproveMember); got != Allow {
		t.Errorf("a listed group: %s, want Allow", got)
	}
}
