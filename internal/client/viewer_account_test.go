package client

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aloisdeniel/cairn/internal/server"
)

// TestViewerAccountThroughTheClient signs up a viewer account through a
// viewer domain and checks what the client sees: its role from Me and the
// directory, a refused share as editor that writes and pins nothing, a share
// as viewer that works, and a refused artifact create.
func TestViewerAccountThroughTheClient(t *testing.T) {
	host, m := newTestServerWith(t, func(c *server.Config) {
		c.SignupDomains = []string{"example.com"}
		c.ViewerDomains = []string{"viewers.test"}
	})
	clients := map[string]*Client{}
	for _, email := range []string{"ada@example.com", "carol@viewers.test"} {
		signupVerify(t, host, m, email, testPassword)
		out, err := New(host, "").Login(email, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		clients[email] = keyedFor(t, host, out.APIKey)
	}
	ada, carol := clients["ada@example.com"], clients["carol@viewers.test"]

	for who, want := range map[*Client]string{ada: "member", carol: "viewer"} {
		me, err := who.Me()
		if err != nil || me.Role != want {
			t.Errorf("Me: role %q (%v), want %q", me.Role, err, want)
		}
	}
	dir, err := ada.Directory()
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{}
	for _, u := range dir {
		roles[u.Email] = u.Role
	}
	if roles["ada@example.com"] != "member" || roles["carol@viewers.test"] != "viewer" {
		t.Errorf("directory roles = %v", roles)
	}

	a, err := ada.CreateArtifact("shared", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ada.Share(a.ID, "carol@viewers.test", "editor", false)
	if !errors.Is(err, ErrViewerAccount) || err.Error() != "carol@viewers.test is a viewer account and can only be a viewer" {
		t.Fatalf("share as editor: %v", err)
	}
	// Nothing was signed, written, or pinned.
	kr, err := ada.ReadKeyring(mustUnlock(t, ada))
	if err != nil {
		t.Fatal(err)
	}
	if e := kr.Epochs[a.ID]; e.Epoch != 1 || e.Seq != 1 {
		t.Errorf("ada's epochs entry = %+v, want epoch 1 seq 1 after the refused share", e)
	}
	if len(kr.Pins) != 0 {
		t.Errorf("ada has pins %v after the refused share", kr.Pins)
	}
	if _, ok := memberRows(t, ada, a.ID)["carol@viewers.test"]; ok {
		t.Error("carol is listed after the refused share")
	}

	if _, err := ada.Share(a.ID, "carol@viewers.test", "viewer", false); err != nil {
		t.Fatalf("share as viewer: %v", err)
	}
	if r := memberRows(t, carol, a.ID)["ada@example.com"]; r.Role != "owner" {
		t.Errorf("ada's row as carol sees it = %+v, want owner", r)
	}

	var apiErr *APIError
	if _, err := carol.CreateArtifact("mine", ""); !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden || apiErr.Message != "a viewer account cannot change anything" {
		t.Errorf("a viewer account creating: %v, want 403 and the viewer-account message", err)
	}
}

// An editor whose account an administrator made a viewer account stays listed
// as editor until the owner changes the entry, as the server's membership
// check allows. Re-sharing them as editor keeps the entry, rather than
// refusing; making them a viewer still works.
func TestShareKeepsADemotedEditorListed(t *testing.T) {
	host, m := newTestServer(t)
	clients := map[string]*Client{}
	for _, email := range []string{"admin@example.com", "ada@example.com", "bob@example.com"} {
		signupVerify(t, host, m, email, testPassword)
		out, err := New(host, "").Login(email, testPassword)
		if err != nil {
			t.Fatal(err)
		}
		clients[email] = keyedFor(t, host, out.APIKey)
	}
	admin, ada := clients["admin@example.com"], clients["ada@example.com"]
	a, err := ada.CreateArtifact("shared", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ada.Share(a.ID, "bob@example.com", "editor", false); err != nil {
		t.Fatalf("share as editor: %v", err)
	}
	bob := memberRows(t, ada, a.ID)["bob@example.com"]
	if err := admin.doJSON("PATCH", "/api/admin/users/"+bob.User, map[string]string{"role": "viewer"}, nil); err != nil {
		t.Fatalf("demote: %v", err)
	}

	res, err := ada.Share(a.ID, "bob@example.com", "editor", false)
	if err != nil || !res.Unchanged {
		t.Fatalf("re-share a demoted editor as editor: %+v, %v; want unchanged", res, err)
	}
	if _, err := ada.Share(a.ID, "bob@example.com", "viewer", false); err != nil {
		t.Fatalf("make the demoted editor a viewer: %v", err)
	}
	if _, err := ada.Share(a.ID, "bob@example.com", "editor", false); !errors.Is(err, ErrViewerAccount) {
		t.Fatalf("promote the viewer account back to editor: %v, want ErrViewerAccount", err)
	}
}
