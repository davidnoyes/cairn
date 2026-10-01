package access

import "testing"

const (
	aid     = "artifact-1"
	owner   = "owner"
	editor  = "editor"
	viewer  = "viewer"
	teamer  = "teamer"
	someone = "stranger"
)

// base builds a private artifact owned by `owner`, listing an editor and a
// viewer under the fingerprints "fp-editor" and "fp-viewer", at epoch 2.
func base() Request {
	return Request{
		Caller:   Caller{Kind: Session},
		Artifact: Artifact{ID: aid, OwnerID: owner, Epoch: 2, Team: TeamNone},
	}
}

func asUser(r Request, id string) Request {
	r.Caller.UserID = id
	r.Caller.Fingerprint = "fp-" + id
	switch id {
	case editor:
		r.Member = &Member{Role: RoleEditor, FP: "fp-editor"}
	case viewer:
		r.Member = &Member{Role: RoleViewer, FP: "fp-viewer"}
	}
	return r
}

func anon(r Request) Request {
	r.Caller = Caller{Kind: Anonymous}
	return r
}

func public(r Request, writes bool) Request {
	r.Artifact.Public, r.Artifact.PublicWrites = true, writes
	return r
}

func withLink(r Request) Request { r.LinkToken = true; return r }

func team(r Request, mode string) Request { r.Artifact.Team = mode; return r }

func withWrap(r Request, epoch int) Request {
	r.Caller.Wraps = append(r.Caller.Wraps, Wrap{Epoch: epoch})
	return r
}

func viaContentToken(r Request, artifact string) Request {
	r.Caller.Kind = ContentToken
	r.Caller.TokenArtifactID = artifact
	return r
}

func TestPermissionTableRowByRow(t *testing.T) {
	// The trust model's permission table, one case per cell. Columns are the
	// owner, an editor, a viewer, and a public link holder (anonymous, then
	// signed in), with public writes off and on where the table says "if".
	pubOff := func(r Request) Request { return withLink(public(r, false)) }
	pubOn := func(r Request) Request { return withLink(public(r, true)) }
	cols := []struct {
		name string
		req  Request
	}{
		{"owner", asUser(base(), owner)},
		{"editor", asUser(base(), editor)},
		{"viewer", asUser(base(), viewer)},
		{"link anonymous, writes off", anon(pubOff(base()))},
		{"link anonymous, writes on", anon(pubOn(base()))},
		{"link signed in, writes off", asUser(pubOff(base()), someone)},
		{"link signed in, writes on", asUser(pubOn(base()), someone)},
	}
	rows := []struct {
		action Action
		want   [7]Decision
	}{
		{ReadContent, [7]Decision{Allow, Allow, Allow, Allow, Allow, Allow, Allow}},
		{WriteData, [7]Decision{Allow, Allow, Forbidden, Forbidden, Forbidden, Forbidden, Allow}},
		{PushVersion, [7]Decision{Allow, Allow, Forbidden, Forbidden, Forbidden, Forbidden, Forbidden}},
		{Share, [7]Decision{Allow, Forbidden, Forbidden, Forbidden, Forbidden, Forbidden, Forbidden}},
		{Delete, [7]Decision{Allow, Forbidden, Forbidden, Forbidden, Forbidden, Forbidden, Forbidden}},
	}
	for _, row := range rows {
		for i, col := range cols {
			if got := Check(col.req, row.action); got != row.want[i] {
				t.Errorf("%s / %s: got %v, want %v", row.action, col.name, got, row.want[i])
			}
		}
	}
}

func TestEndpointActionsByLevel(t *testing.T) {
	// The remaining endpoints of "Endpoints for sharing", by access level.
	team1 := func(r Request) Request { return withWrap(team(r, TeamViewer), 2) }
	cols := []struct {
		name string
		req  Request
	}{
		{"owner", asUser(base(), owner)},
		{"editor", asUser(base(), editor)},
		{"viewer", asUser(base(), viewer)},
		{"team member", asUser(team1(base()), teamer)},
		{"link", anon(withLink(public(base(), false)))},
	}
	rows := []struct {
		action Action
		want   [5]Decision
	}{
		{Rename, [5]Decision{Allow, Allow, Forbidden, Forbidden, Forbidden}},
		{ReadMembership, [5]Decision{Allow, Allow, Allow, Allow, Allow}},
		{ReadKeys, [5]Decision{Allow, Allow, Allow, Allow, Forbidden}},
		{ListPending, [5]Decision{Allow, Allow, Forbidden, Forbidden, Forbidden}},
		{ReviewVersions, [5]Decision{Allow, Forbidden, Forbidden, Forbidden, Forbidden}},
		{Transfer, [5]Decision{Allow, Forbidden, Forbidden, Forbidden, Forbidden}},
		// team is none in these artifacts, so approval is 409 for those who
		// may approve, and 403 for those who may not.
		{ApproveMember, [5]Decision{Conflict, Conflict, Forbidden, Forbidden, Forbidden}},
	}
	for _, row := range rows {
		for i, col := range cols {
			if got := Check(col.req, row.action); got != row.want[i] {
				t.Errorf("%s / %s: got %v, want %v", row.action, col.name, got, row.want[i])
			}
		}
	}
}

func TestApprovalRefusedWhileTeamIsNone(t *testing.T) {
	for _, mode := range []string{TeamNone, ""} {
		for _, who := range []string{owner, editor} {
			r := team(asUser(base(), who), mode)
			if got := Check(r, ApproveMember); got != Conflict {
				t.Errorf("team %q, %s: got %v, want Conflict", mode, who, got)
			}
		}
	}
	for _, mode := range []string{TeamViewer, TeamEditor} {
		for _, who := range []string{owner, editor} {
			r := team(asUser(base(), who), mode)
			if got := Check(r, ApproveMember); got != Allow {
				t.Errorf("team %q, %s: got %v, want Allow", mode, who, got)
			}
		}
		// a viewer is refused before the team check
		if got := Check(team(asUser(base(), viewer), mode), ApproveMember); got != Forbidden {
			t.Errorf("team %q, viewer: got %v, want Forbidden", mode, got)
		}
	}
	// the team mode never turns a viewer's refusal into a conflict
	if got := Check(asUser(base(), viewer), ApproveMember); got != Forbidden {
		t.Errorf("viewer, team none: got %v, want Forbidden", got)
	}
}

func TestChangedFingerprintReadsButCannotWrite(t *testing.T) {
	r := asUser(base(), editor)
	r.Caller.Fingerprint = "fp-editor-after-reset"
	if got := LevelOf(r); got != LevelEditor {
		t.Errorf("level: got %v, want editor", got)
	}
	want := map[Action]Decision{
		ReadContent: Allow, ReadMembership: Allow, ReadKeys: Allow,
		WriteData: Forbidden, PushVersion: Forbidden, Rename: Forbidden,
		ApproveMember: Forbidden, ListPending: Forbidden, Share: Forbidden, Delete: Forbidden,
	}
	for a, d := range want {
		if got := Check(r, a); got != d {
			t.Errorf("%s: got %v, want %v", a, got, d)
		}
	}
	// The same editor with an unchanged fingerprint writes.
	if got := Check(asUser(base(), editor), WriteData); got != Allow {
		t.Errorf("unchanged fingerprint: got %v", got)
	}
	// A listed viewer with a changed fingerprint still reads.
	v := asUser(base(), viewer)
	v.Caller.Fingerprint = "other"
	if got := Check(v, ReadContent); got != Allow {
		t.Errorf("viewer read: got %v", got)
	}
	// A changed fingerprint does not stop a signed-in link holder writing.
	e := public(withLink(r), true)
	if got := Check(e, WriteData); got != Allow {
		t.Errorf("link write by changed-key editor: got %v", got)
	}
}

func TestTeamMember(t *testing.T) {
	cases := []struct {
		name  string
		req   Request
		level Level
		read  Decision
		write Decision
	}{
		{"viewer team, wrap for current epoch", withWrap(team(asUser(base(), teamer), TeamViewer), 2), LevelTeam, Allow, Forbidden},
		{"editor team is still viewer access", withWrap(team(asUser(base(), teamer), TeamEditor), 2), LevelTeam, Allow, Forbidden},
		{"no wrap at all", team(asUser(base(), teamer), TeamViewer), LevelNone, NotFound, NotFound},
		{"wrap for an old epoch only", withWrap(team(asUser(base(), teamer), TeamViewer), 1), LevelNone, NotFound, NotFound},
		{"wrap for a future epoch only", withWrap(team(asUser(base(), teamer), TeamViewer), 3), LevelNone, NotFound, NotFound},
		{"wrap but team is none", withWrap(team(asUser(base(), teamer), TeamNone), 2), LevelNone, NotFound, NotFound},
		{"wrap but team is unset", withWrap(team(asUser(base(), teamer), ""), 2), LevelNone, NotFound, NotFound},
		{"wrap but team is unknown", withWrap(team(asUser(base(), teamer), "everyone"), 2), LevelNone, NotFound, NotFound},
		{"old and current wraps", withWrap(withWrap(team(asUser(base(), teamer), TeamViewer), 1), 2), LevelTeam, Allow, Forbidden},
	}
	for _, c := range cases {
		if got := LevelOf(c.req); got != c.level {
			t.Errorf("%s: level %v, want %v", c.name, got, c.level)
		}
		if got := Check(c.req, ReadContent); got != c.read {
			t.Errorf("%s: read %v, want %v", c.name, got, c.read)
		}
		if got := Check(c.req, WriteData); got != c.write {
			t.Errorf("%s: write %v, want %v", c.name, got, c.write)
		}
	}
}

func TestSignedInViewerWithLinkTokenMayWriteWhilePublicWritesOn(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want Decision
	}{
		{"writes on, token matches", withLink(public(asUser(base(), viewer), true)), Allow},
		{"writes off", withLink(public(asUser(base(), viewer), false)), Forbidden},
		{"no token", public(asUser(base(), viewer), true), Forbidden},
		{"token matches but artifact is private", withLink(asUser(base(), viewer)), Forbidden},
		{"team viewer, writes on, token", withLink(public(withWrap(team(asUser(base(), teamer), TeamViewer), 2), true)), Allow},
	}
	for _, c := range cases {
		if got := Check(c.req, WriteData); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	// The viewer's level stays viewer: first match wins.
	if got := LevelOf(withLink(public(asUser(base(), viewer), true))); got != LevelViewer {
		t.Errorf("level: got %v, want viewer", got)
	}
	// A link never lets anyone push or share.
	r := withLink(public(asUser(base(), viewer), true))
	for _, a := range []Action{PushVersion, Share, Delete, Rename} {
		if got := Check(r, a); got != Forbidden {
			t.Errorf("%s: got %v, want Forbidden", a, got)
		}
	}
}

func TestLinkHolder(t *testing.T) {
	cases := []struct {
		name  string
		req   Request
		level Level
	}{
		{"public, token matches", anon(withLink(public(base(), false))), LevelLink},
		{"public, no token", anon(public(base(), false)), LevelNone},
		{"private, token matches", anon(withLink(base())), LevelNone},
		{"signed-in stranger, public, token", asUser(withLink(public(base(), false)), someone), LevelLink},
		{"signed-in stranger, public, no token", asUser(public(base(), false), someone), LevelNone},
	}
	for _, c := range cases {
		if got := LevelOf(c.req); got != c.level {
			t.Errorf("%s: level %v, want %v", c.name, got, c.level)
		}
	}
}

func TestLevelOrderFirstMatchWins(t *testing.T) {
	// owner beats member, member beats team, team beats link
	r := withLink(public(withWrap(team(asUser(base(), owner), TeamViewer), 2), true))
	r.Member = &Member{Role: RoleViewer, FP: "fp-owner"}
	if got := LevelOf(r); got != LevelOwner {
		t.Errorf("owner: got %v", got)
	}
	r = withLink(public(withWrap(team(asUser(base(), viewer), TeamEditor), 2), true))
	if got := LevelOf(r); got != LevelViewer {
		t.Errorf("member: got %v", got)
	}
	r = withLink(public(withWrap(team(asUser(base(), teamer), TeamViewer), 2), true))
	if got := LevelOf(r); got != LevelTeam {
		t.Errorf("team: got %v", got)
	}
	r = withLink(public(asUser(base(), someone), true))
	if got := LevelOf(r); got != LevelLink {
		t.Errorf("link: got %v", got)
	}
}

func TestNoAccessIsAlwaysNotFound(t *testing.T) {
	admin := asUser(base(), someone)
	admin.Caller.IsAdmin = true
	cases := map[string]Request{
		"stranger":                   asUser(base(), someone),
		"administrator stranger":     admin,
		"anonymous":                  anon(base()),
		"anonymous, public, no link": anon(public(base(), true)),
		"team member without wrap":   team(asUser(base(), teamer), TeamViewer),
		"link token on private":      withLink(asUser(base(), someone)),
		"empty artifact owner":       {Caller: Caller{Kind: Anonymous}, Artifact: Artifact{ID: aid}},
		"anonymous naming the owner": {Caller: Caller{Kind: Anonymous, UserID: owner}, Artifact: Artifact{ID: aid, OwnerID: owner}},
	}
	for name, r := range cases {
		if got := LevelOf(r); got != LevelNone {
			t.Errorf("%s: level %v, want none", name, got)
		}
		for _, a := range allActions {
			got := Check(r, a)
			if got != NotFound {
				t.Errorf("%s / %s: got %v, want NotFound", name, a, got)
			}
			if got.Status() != 404 {
				t.Errorf("%s / %s: status %d, want 404", name, a, got.Status())
			}
		}
	}
}

func TestAdministratorHasNoSpecialAccess(t *testing.T) {
	// An administrator who is the owner is the owner; one who is a viewer is
	// a viewer; the flag changes nothing.
	for _, who := range []string{owner, editor, viewer} {
		plain := asUser(base(), who)
		adm := plain
		adm.Caller.IsAdmin = true
		for _, a := range allActions {
			if Check(plain, a) != Check(adm, a) {
				t.Errorf("%s / %s: administrator flag changed the answer", who, a)
			}
		}
	}
}

func TestContentOriginToken(t *testing.T) {
	tok := func(r Request) Request { return viaContentToken(r, aid) }
	cases := []struct {
		name   string
		req    Request
		action Action
		want   Decision
	}{
		{"owner reads", tok(asUser(base(), owner)), ReadContent, Allow},
		{"owner writes data", tok(asUser(base(), owner)), WriteData, Allow},
		{"editor writes data", tok(asUser(base(), editor)), WriteData, Allow},
		{"viewer cannot write data", tok(asUser(base(), viewer)), WriteData, Forbidden},
		{"reads membership", tok(asUser(base(), viewer)), ReadMembership, Allow},
		{"owner cannot share", tok(asUser(base(), owner)), Share, NotFound},
		{"owner cannot delete", tok(asUser(base(), owner)), Delete, NotFound},
		{"owner cannot push", tok(asUser(base(), owner)), PushVersion, NotFound},
		{"owner cannot transfer", tok(asUser(base(), owner)), Transfer, NotFound},
		{"owner cannot rename", tok(asUser(base(), owner)), Rename, NotFound},
		{"editor cannot approve", tok(asUser(team(base(), TeamViewer), editor)), ApproveMember, NotFound},
		{"owner cannot read keys", tok(asUser(base(), owner)), ReadKeys, NotFound},
		{"owner cannot list pending", tok(asUser(base(), owner)), ListPending, NotFound},
		{"owner cannot review", tok(asUser(base(), owner)), ReviewVersions, NotFound},
		{"token for another artifact reads nothing", viaContentToken(asUser(base(), owner), "other"), ReadContent, NotFound},
		{"token for another artifact writes nothing", viaContentToken(asUser(base(), owner), "other"), WriteData, NotFound},
		{"token with no artifact", viaContentToken(asUser(base(), owner), ""), ReadContent, NotFound},
	}
	for _, c := range cases {
		if got := Check(c.req, c.action); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if got := LevelOf(viaContentToken(asUser(base(), owner), "other")); got != LevelNone {
		t.Errorf("foreign token level: got %v", got)
	}
}

func TestSessionAndAPIKeyAreEquivalent(t *testing.T) {
	for _, k := range []Kind{Session, APIKey} {
		r := asUser(base(), owner)
		r.Caller.Kind = k
		for _, a := range allActions {
			if got := Check(r, a); got != Allow && !(a == ApproveMember && got == Conflict) {
				t.Errorf("kind %d / %s: got %v", k, a, got)
			}
		}
	}
}

func TestStatus(t *testing.T) {
	for d, s := range map[Decision]int{Allow: 200, NotFound: 404, Forbidden: 403, Conflict: 409} {
		if d.Status() != s {
			t.Errorf("%v: got %d, want %d", d, d.Status(), s)
		}
	}
}

func TestUnknownActionIsRefused(t *testing.T) {
	if got := Check(asUser(base(), owner), Action("explode")); got != Forbidden {
		t.Errorf("owner, unknown action: got %v", got)
	}
}

var allActions = []Action{
	ReadContent, WriteData, PushVersion, Share, Delete, Rename, ReadMembership,
	ReadKeys, ListPending, ApproveMember, ReviewVersions, Transfer,
}
