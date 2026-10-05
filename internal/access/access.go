// Package access is the artifact permission table as one pure function.
//
// Check answers "may this caller do this action to this artifact" from state
// the caller has already read: who is asking, how they authenticated, how the
// artifact's latest membership record lists them, which wraps they hold, and
// whether the request carried a matching link token. It reads nothing and
// writes nothing, so every cell of the table in the trust model can be tested
// directly. See design/e2e-trust-model.md (Ownership, sharing, and epochs)
// and design/e2e-api.md (Access).
package access

import "net/http"

// Level is the first access level that matches a request.
type Level string

const (
	LevelOwner  Level = "owner"
	LevelEditor Level = "editor"
	LevelViewer Level = "viewer"
	LevelTeam   Level = "team"
	LevelLink   Level = "link"
	LevelNone   Level = "none"

	// LevelSuccessor is a released successor of the artifact's owner. It sits
	// between team and link in match order.
	LevelSuccessor Level = "successor"
)

// Roles a membership record gives a listed member.
const (
	RoleViewer = "viewer"
	RoleEditor = "editor"
)

// Values of a membership record's team field.
const (
	TeamNone   = "none"
	TeamViewer = "viewer"
	TeamEditor = "editor"
)

// Kind is how the caller authenticated.
type Kind int

const (
	Anonymous    Kind = iota // no credentials
	Session                  // app-origin session cookie
	APIKey                   // API key or device key
	ContentToken             // token handed to one artifact's content origin
)

// Action is something a caller may try to do to an artifact.
type Action string

const (
	ReadContent    Action = "read"       // content, database, files
	WriteData      Action = "write"      // database and files
	PushVersion    Action = "push"       // push a version
	Share          Action = "share"      // share, unshare, make public or private
	Delete         Action = "delete"     // delete the artifact
	Rename         Action = "rename"     // write metadata fields, add resources
	ReadMembership Action = "membership" // GET membership records
	ReadKeys       Action = "keys"       // GET the caller's wraps
	ListPending    Action = "pending"    // GET team members waiting
	ApproveMember  Action = "approve"    // POST keys: approve a team member
	ReviewVersions Action = "review"     // list and vouch for versions
	Transfer       Action = "transfer"   // offer ownership
	AnswerTransfer Action = "answer"     // accept, decline, or withdraw an offer
)

// Decision is the outcome of a check.
type Decision int

const (
	Allow     Decision = iota
	NotFound           // no access at all: never 401 or 403, administrators included
	Forbidden          // has access, but the level does not allow the action
	Conflict           // allowed in principle, but the artifact's state refuses it
)

// Status is the HTTP status for the decision.
func (d Decision) Status() int {
	switch d {
	case Allow:
		return http.StatusOK
	case Forbidden:
		return http.StatusForbidden
	case Conflict:
		return http.StatusConflict
	default:
		return http.StatusNotFound
	}
}

func (d Decision) String() string {
	switch d {
	case Allow:
		return "Allow"
	case NotFound:
		return "NotFound"
	case Forbidden:
		return "Forbidden"
	case Conflict:
		return "Conflict"
	default:
		return "Decision(?)"
	}
}

// Caller is who is asking.
type Caller struct {
	UserID string // empty when anonymous
	Kind   Kind
	// IsAdmin is carried for completeness. It grants nothing: an
	// administrator with no access gets the same 404 as anyone.
	IsAdmin bool
	// Fingerprint is the fingerprint of the caller's current keys.
	Fingerprint string
	// Wraps is every wrap the caller holds on this artifact.
	Wraps []Wrap
	// TokenArtifactID is the one artifact a ContentToken is scoped to.
	TokenArtifactID string
	// LinkOnly limits a ContentToken to what the public link gives: the
	// caller's ownership, listing, and team wraps match nothing.
	LinkOnly bool
}

// Wrap is a wrap the caller holds. Only its epoch matters here.
type Wrap struct {
	Epoch int
}

// Artifact is the artifact's state from its latest membership record.
type Artifact struct {
	ID           string
	OwnerID      string
	Epoch        int
	Team         string
	Public       bool
	PublicWrites bool
}

// Member is the caller's entry in the latest record: their role, and the
// fingerprint the owner listed them under.
type Member struct {
	Role string
	FP   string
}

// Request is everything Check needs.
type Request struct {
	Caller   Caller
	Artifact Artifact
	// Member is the caller's entry in the latest record, nil if not listed.
	Member *Member
	// LinkToken is true when the request carried X-Cairn-Link-Token and its
	// hash matched the artifact's public token hash.
	LinkToken bool
	// Successor is true when the caller is the released successor of the
	// artifact's owner. The caller of Check works that out; an artifact only
	// shared with the nominating user never sets it.
	Successor bool
}

// matches records which access levels match a request.
type matches struct {
	owner, member, team, successor, link bool
	signedIn                             bool
	editorPower                          bool
}

func match(r Request) matches {
	c, a := r.Caller, r.Artifact
	if c.Kind == ContentToken && c.TokenArtifactID != a.ID {
		return matches{}
	}
	m := matches{signedIn: c.Kind != Anonymous && c.UserID != ""}
	m.owner = m.signedIn && c.UserID == a.OwnerID
	m.member = m.signedIn && r.Member != nil
	// A team member the record also lists matches as a member first, so the
	// "record does not list them" condition needs no check here.
	m.team = m.signedIn && (a.Team == TeamViewer || a.Team == TeamEditor) && holdsWrap(c.Wraps, a.Epoch)
	m.successor = m.signedIn && r.Successor
	m.link = a.Public && r.LinkToken
	if c.LinkOnly {
		m.owner, m.member, m.team, m.successor = false, false, false, false
	}
	// A listed editor whose current keys differ from the listed fingerprint
	// can read but not write, until the owner lists the new fingerprint.
	m.editorPower = m.member && r.Member.Role == RoleEditor && r.Member.FP == c.Fingerprint
	return m
}

// holdsWrap ignores the fingerprint a wrap was made for: the design grants
// team access for any wrap at the current epoch, and a wrap for keys the
// caller no longer has opens nothing.
func holdsWrap(wraps []Wrap, epoch int) bool {
	for _, w := range wraps {
		if w.Epoch == epoch {
			return true
		}
	}
	return false
}

// LevelOf returns the first level that matches the request: owner, then the
// listed member's role, then team, then successor, then link, else none.
func LevelOf(r Request) Level {
	m := match(r)
	switch {
	case m.owner:
		return LevelOwner
	case m.member && r.Member.Role == RoleEditor:
		return LevelEditor
	case m.member && r.Member.Role == RoleViewer:
		return LevelViewer
	case m.team:
		return LevelTeam
	case m.successor:
		return LevelSuccessor
	case m.link:
		return LevelLink
	}
	return LevelNone
}

// contentTokenAllows is the allowlist of a content-origin token for actions
// on its own artifact. Every other action is answered as if the route did
// not exist. GET /api/me and GET /api/users/{id} are not artifact actions;
// the router's allowlist (contentTokenRoutes in internal/server) adds them.
func contentTokenAllows(act Action) bool {
	switch act {
	case ReadContent, WriteData, ReadMembership:
		return true
	}
	return false
}

// Check decides whether the caller may do act. A request with no matching
// level is NotFound whatever the action. A request that matches may do
// whatever any matching level allows, so a signed-in viewer who also holds a
// matching link token writes while public writes are on.
func Check(r Request, act Action) Decision {
	m := match(r)
	if !(m.owner || m.member || m.team || m.successor || m.link) {
		return NotFound
	}
	if r.Caller.Kind == ContentToken && !contentTokenAllows(act) {
		return NotFound
	}
	if !allowed(m, r.Artifact, act) {
		return Forbidden
	}
	// An approval needs a team share to approve into.
	if act == ApproveMember && r.Artifact.Team != TeamViewer && r.Artifact.Team != TeamEditor {
		return Conflict
	}
	return Allow
}

func allowed(m matches, a Artifact, act Action) bool {
	if m.owner {
		switch act {
		case ReadContent, WriteData, PushVersion, Share, Delete, Rename, ReadMembership,
			ReadKeys, ListPending, ApproveMember, ReviewVersions, Transfer, AnswerTransfer:
			return true
		}
		return false
	}
	// A listed member of either role, a team member, and a link holder read.
	if m.member || m.team || m.link {
		if act == ReadContent || act == ReadMembership {
			return true
		}
	}
	// A released successor reads, and may accept an administrator's offer.
	if m.successor {
		switch act {
		case ReadContent, ReadMembership, ReadKeys, AnswerTransfer:
			return true
		}
	}
	// An offer is made to a listed member, so only they can answer one.
	if m.member && act == AnswerTransfer {
		return true
	}
	// Wraps are held by members and team members, not link holders.
	if (m.member || m.team) && act == ReadKeys {
		return true
	}
	if m.editorPower {
		switch act {
		case WriteData, PushVersion, Rename, ListPending, ApproveMember:
			return true
		}
	}
	// A signed-in link holder writes while public writes are on.
	return m.link && m.signedIn && a.PublicWrites && act == WriteData
}
