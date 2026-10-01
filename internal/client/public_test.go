package client

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func boolp(b bool) *bool { return &b }

// publicChain reads the artifact's chain as its owner verifies it.
func publicChain(t *testing.T, c *Client, artifact string) *e2e.Chain {
	t.Helper()
	va, err := c.VerifyArtifact(mustUnlock(t, c), artifact, "")
	if err != nil {
		t.Fatalf("VerifyArtifact: %v", err)
	}
	return va.Chain
}

func mustParseLink(t *testing.T, link string) *e2e.Link {
	t.Helper()
	l, err := e2e.ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink(%q): %v", link, err)
	}
	return l
}

func TestPublicOnMakesALinkAnAnonymousVisitorOpens(t *testing.T) {
	s := newSharing(t)
	res, err := s.ada.Public(s.artifact, true, nil)
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if !res.Public || res.PublicWrites || res.Unchanged || res.Epoch != 1 {
		t.Errorf("Public result = %+v, want public, writes off, changed, epoch 1", res)
	}
	l := mustParseLink(t, res.Link)
	chain := publicChain(t, s.ada, s.artifact)
	if l.Host != s.host || l.Artifact != s.artifact || l.Epoch != 1 || l.Owner != chain.Bodies[0].OwnerFP {
		t.Errorf("link = %+v, want host %s, artifact %s, epoch 1, o the first record's ownerFp", l, s.host, s.artifact)
	}
	if !chain.Latest.Public || chain.Latest.PublicWrites {
		t.Errorf("latest record = public %v, writes %v", chain.Latest.Public, chain.Latest.PublicWrites)
	}
	opened, err := OpenLink(res.Link)
	if err != nil {
		t.Fatalf("OpenLink: %v", err)
	}
	if opened.Chain.Head != chain.Head || opened.Link.Artifact != s.artifact {
		t.Errorf("OpenLink = head %s, want %s", opened.Chain.Head, chain.Head)
	}
}

func TestPublicIsIdempotentAndTogglesWrites(t *testing.T) {
	s := newSharing(t)
	first, err := s.ada.Public(s.artifact, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	seq := publicChain(t, s.ada, s.artifact).Latest.Seq
	again, err := s.ada.Public(s.artifact, true, nil)
	if err != nil || !again.Unchanged || again.Link != first.Link {
		t.Fatalf("Public again = %+v, %v; want unchanged with the same link", again, err)
	}
	if got := publicChain(t, s.ada, s.artifact).Latest.Seq; got != seq {
		t.Errorf("an unchanged Public wrote a record: seq %d, was %d", got, seq)
	}
	for _, want := range []bool{true, false} {
		res, err := s.ada.Public(s.artifact, true, boolp(want))
		if err != nil || res.Unchanged || res.PublicWrites != want || res.Link != first.Link {
			t.Fatalf("Public --writes %v = %+v, %v", want, res, err)
		}
		if got := publicChain(t, s.ada, s.artifact).Latest; !got.Public || got.PublicWrites != want {
			t.Errorf("latest = public %v, writes %v, want public, writes %v", got.Public, got.PublicWrites, want)
		}
		if _, err := OpenLink(first.Link); err != nil {
			t.Errorf("OpenLink after --writes %v: %v", want, err)
		}
	}
	// Already at that setting.
	res, err := s.ada.Public(s.artifact, true, boolp(false))
	if err != nil || !res.Unchanged {
		t.Errorf("Public --writes off again = %+v, %v; want unchanged", res, err)
	}
	// Left alone, the switch keeps its setting.
	if _, err := s.ada.Public(s.artifact, true, boolp(true)); err != nil {
		t.Fatal(err)
	}
	res, err = s.ada.Public(s.artifact, true, nil)
	if err != nil || !res.Unchanged || !res.PublicWrites {
		t.Errorf("Public with no --writes after writes on = %+v, %v; want unchanged, writes on", res, err)
	}
}

func TestPublicOnWithWritesOnAPrivateArtifact(t *testing.T) {
	s := newSharing(t)
	res, err := s.ada.Public(s.artifact, true, boolp(true))
	if err != nil || !res.Public || !res.PublicWrites || res.Unchanged {
		t.Fatalf("Public on --writes on = %+v, %v", res, err)
	}
	if got := publicChain(t, s.ada, s.artifact); got.Latest.Seq != 2 {
		t.Errorf("seq = %d, want a single record", got.Latest.Seq)
	}
}

func TestPublicOff(t *testing.T) {
	s := newSharing(t)
	// Private already: nothing to do, nothing written.
	res, err := s.ada.Public(s.artifact, false, nil)
	if err != nil || res.Public || !res.Unchanged || res.Link != "" {
		t.Errorf("Public off on a private artifact = %+v, %v; want unchanged, no link", res, err)
	}
	if got := publicChain(t, s.ada, s.artifact).Latest.Seq; got != 1 {
		t.Errorf("an unchanged Public wrote a record: seq %d", got)
	}
	// --writes means nothing with off.
	if _, err := s.ada.Public(s.artifact, false, boolp(true)); !errors.Is(err, ErrPublicWritesWithOff) {
		t.Errorf("Public off --writes on = %v, want ErrPublicWritesWithOff", err)
	}
	// Public: off needs the next epoch.
	if _, err := s.ada.Public(s.artifact, true, nil); err != nil {
		t.Fatal(err)
	}
	seq := publicChain(t, s.ada, s.artifact).Latest.Seq
	if _, err := s.ada.Public(s.artifact, false, nil); !errors.Is(err, ErrPublicOffNeedsNextEpoch) {
		t.Errorf("Public off on a public artifact = %v, want ErrPublicOffNeedsNextEpoch", err)
	}
	if got := publicChain(t, s.ada, s.artifact); got.Latest.Seq != seq || !got.Latest.Public {
		t.Errorf("a refused off changed the chain: seq %d, public %v", got.Latest.Seq, got.Latest.Public)
	}
}

func TestPublicIsForTheOwner(t *testing.T) {
	s := newSharing(t)
	if _, err := s.ada.Share(s.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.bob.Public(s.artifact, true, nil); !errors.Is(err, ErrNotOwner) {
		t.Errorf("an editor's Public = %v, want ErrNotOwner", err)
	}
	if got := publicChain(t, s.ada, s.artifact).Latest; got.Public {
		t.Error("an editor made the artifact public")
	}
}

// TestSharingRecordsKeepAPublicArtifactPublic proves every record writer
// sends the link token hash a public record needs, so share and team still
// work once the artifact is public, and the link still opens after them.
func TestSharingRecordsKeepAPublicArtifactPublic(t *testing.T) {
	w := newTeam(t)
	res, err := w.ada.Public(w.artifact, true, boolp(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatalf("Share on a public artifact: %v", err)
	}
	if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
		t.Fatalf("Team on a public artifact: %v", err)
	}
	if got := publicChain(t, w.ada, w.artifact).Latest; !got.Public || !got.PublicWrites || got.Team != "viewer" || len(got.Members) != 1 {
		t.Errorf("latest = %+v, want public with writes, team viewer, bob listed", got)
	}
	// Bob is an editor now, so the link's chain lists his keys, which the
	// link scope serves.
	if _, err := OpenLink(res.Link); err != nil {
		t.Errorf("OpenLink after share and team: %v", err)
	}
	// A listing of approved team members writes a record too.
	if _, err := w.bob.Approve(w.artifact, "cat@example.com", false); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if _, err := w.ada.Team(w.artifact, "viewer"); err != nil {
		t.Fatalf("Team listing an approved member on a public artifact: %v", err)
	}
	if got := publicChain(t, w.ada, w.artifact).Latest; !got.Public || len(got.Members) != 2 {
		t.Errorf("latest = %+v, want public and cat listed", got)
	}
	if _, err := OpenLink(res.Link); err != nil {
		t.Errorf("OpenLink after listing: %v", err)
	}
}

func TestOpenLinkRefusals(t *testing.T) {
	w := newTeam(t)
	if _, err := w.ada.Share(w.artifact, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	res, err := w.ada.Public(w.artifact, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	good := mustParseLink(t, res.Link)
	if _, err := OpenLink(res.Link); err != nil {
		t.Fatalf("OpenLink: %v", err)
	}
	other := make([]byte, 32)
	for name, mutate := range map[string]func(l *e2e.Link){
		"a wrong o":  func(l *e2e.Link) { l.Owner = e2e.LinkTokenHash([]byte("not the owner")) },
		"a wrong AK": func(l *e2e.Link) { l.AK = other },
	} {
		l := *good
		mutate(&l)
		link, err := e2e.PublicLink(l.Host, l.Artifact, l.AK, l.Epoch, l.Owner)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenLink(link); err == nil {
			t.Errorf("OpenLink with %s succeeded", name)
		}
	}
	// A wrong o with the right token is the chain's refusal, not the
	// server's.
	l := *good
	l.Owner = e2e.LinkTokenHash([]byte("not the owner"))
	link, _ := e2e.PublicLink(l.Host, l.Artifact, l.AK, l.Epoch, l.Owner)
	if _, err := OpenLink(link); !errors.Is(err, e2e.ErrChain) {
		t.Errorf("OpenLink with a wrong o = %v, want ErrChain", err)
	}
	if _, err := OpenLink("not a link"); !errors.Is(err, e2e.ErrFormat) {
		t.Errorf("OpenLink(not a link) = %v, want ErrFormat", err)
	}

	// The server serves another's keys for the editor: a signed-in
	// non-member reads at link scope, and a mismatch is refused.
	path := "/api/artifacts/" + w.artifact + "/membership"
	ada, err := w.cat.DirectoryUser(w.userID(t, w.ada))
	if err != nil {
		t.Fatal(err)
	}
	bobID := w.userID(t, w.bob)
	forged := rewriting(w.cat, path, func(body []byte) []byte {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Error(err)
			return body
		}
		m["keys"] = map[string]any{bobID: map[string]string{"x25519": e2e.B64(ada.X25519Pub), "ed25519": e2e.B64(ada.Ed25519Pub)}}
		out, _ := json.Marshal(m)
		return out
	})
	opened, err := forged.OpenLink(good)
	if err != nil {
		t.Fatalf("OpenLink with substituted editor keys: %v", err)
	}
	if _, trusted := opened.Editors[bobID]; trusted {
		t.Error("an editor whose served keys do not hash to the record's fp is a trusted writer")
	}
	opened, err = w.cat.OpenLink(good)
	if err != nil {
		t.Errorf("OpenLink as a signed-in non-member: %v", err)
	} else if _, trusted := opened.Editors[bobID]; !trusted {
		t.Error("an editor whose keys verify is not a trusted writer")
	}
}

// TestPublicRefusesAHostTheLinkCannotNameBeforeWriting proves Public builds the
// link before it writes a record: a host the link format refuses leaves the
// artifact private, so the owner is never stuck with a public artifact and no
// link.
func TestPublicRefusesAHostTheLinkCannotNameBeforeWriting(t *testing.T) {
	s := newSharing(t)
	before := publicChain(t, s.ada, s.artifact).Latest.Seq
	bad := *s.ada
	bad.Host = "HTTP" + s.host[len("http"):] // reaches the server, but the link grammar wants a lowercase scheme
	_, err := bad.Public(s.artifact, true, nil)
	if !errors.Is(err, e2e.ErrFormat) || !strings.Contains(err.Error(), bad.Host) {
		t.Fatalf("Public = %v, want ErrFormat naming the host %s", err, bad.Host)
	}
	latest := publicChain(t, s.ada, s.artifact).Latest
	if latest.Seq != before || latest.Public {
		t.Errorf("after the refusal: seq %d (was %d), public %v; want no new record", latest.Seq, before, latest.Public)
	}
}
