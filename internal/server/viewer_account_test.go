package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

// setRole changes a user's server role through the store, as an
// administrator's PATCH does, without touching their sessions or keys.
func setRole(t *testing.T, s *Server, userID, role string) {
	t.Helper()
	if err := s.store.SetUserRole(userID, role); err != nil {
		t.Fatal(err)
	}
}

// apiKeyFor makes an API key for the user c is signed in as, and returns its
// bearer.
func apiKeyFor(t *testing.T, c *testClient, password, keyID string) string {
	t.Helper()
	secret := "00112233445566778899aabbccddeeff"
	c.mustDo("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey(password)), "name": "agent", "device": true,
		"keyId": keyID, "authSecret": secret,
		"mk": e2e.B64(bytes.Repeat([]byte{0x11}, sealedKeyLen)),
	}, nil, http.StatusCreated)
	return "cairn_" + keyID + "_" + secret
}

// wantForbidden checks a write was refused with 403, for being a viewer
// account rather than for any other reason.
func wantForbidden(t *testing.T, what string, resp *http.Response) {
	t.Helper()
	defer resp.Body.Close()
	var out struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusForbidden || out.Error != errViewerAccount {
		t.Errorf("%s: %d %q, want 403 %q", what, resp.StatusCode, out.Error, errViewerAccount)
	}
}

// wantViewerRefusal sends a metadata write and checks it was refused with
// 403 for being a viewer account. jsonOf keeps the body that do drains.
func wantViewerRefusal(t *testing.T, who actor, what string, m *metaRequest) {
	t.Helper()
	code, out := jsonOf(who.testClient, "PUT", m.path(), m.request(t))
	if msg, _ := out["error"].(string); code != http.StatusForbidden || msg != errViewerAccount {
		t.Errorf("%s: %d %q, want 403 %q", what, code, msg, errViewerAccount)
	}
}

// refusedEveryWrite checks who may read the artifact in w and is refused
// every write to it, whatever way they sign in.
func refusedEveryWrite(t *testing.T, w *contentWorld, who actor) {
	t.Helper()
	aid, vid := w.art.id, w.vid
	base := "/api/artifacts/" + aid
	vbase := base + "/versions/" + vid

	who.mustDo("GET", base, nil, nil, http.StatusOK)
	who.mustDo("GET", base+"/versions", nil, nil, http.StatusOK)
	who.mustDo("GET", base+"/membership", nil, nil, http.StatusOK)
	who.mustDo("GET", base+"/keys", nil, nil, http.StatusOK)
	who.mustDo("GET", vbase+"/db", nil, nil, http.StatusOK)
	who.mustDo("GET", vbase+"/db/revisions", nil, nil, http.StatusOK)
	wantCode(t, who.testClient, "GET", vbase+"/files/"+w.addr, http.StatusOK)

	wantForbidden(t, "write db", who.writeDB(t, aid, vid))
	wantForbidden(t, "put file", who.writeFile(t, aid, vid, "x.txt", "x"))
	wantStatus(t, who.testClient, "DELETE", vbase+"/files/"+w.addr, nil, http.StatusForbidden)
	wantForbidden(t, "push", who.upload("POST", base+"/versions", map[string]string{"index.html": "v2"}))
	wantForbidden(t, "replace", who.upload("PUT", vbase, map[string]string{"index.html": "v2"}))
	wantViewerRefusal(t, who, "artifact meta", newMeta(t, who, aid, "", "name", 1, "x"))
	wantViewerRefusal(t, who, "version meta", newMeta(t, who, aid, vid, "name", 1, "x"))
	wantStatus(t, who.testClient, "POST", base+"/resources", map[string]any{"type": "t", "value": refOf("v")}, http.StatusForbidden)
	wantStatus(t, who.testClient, "GET", base+"/review", nil, http.StatusForbidden)
	wantStatus(t, who.testClient, "PUT", base+"/membership", w.art.change(w.art.next()), http.StatusForbidden)
	wantStatus(t, who.testClient, "POST", base+"/transfer", map[string]any{"to": w.outside.id}, http.StatusForbidden)
	wantStatus(t, who.testClient, "DELETE", vbase, nil, http.StatusForbidden)
	wantStatus(t, who.testClient, "DELETE", base, nil, http.StatusForbidden)
}

// TestViewerAccountReadsAndNeverWrites demotes a listed editor to a viewer
// account: the member list still names them editor, yet every write is
// refused (session, API key, and content token) while every read works.
func TestViewerAccountReadsAndNeverWrites(t *testing.T) {
	w := newContentWorld(t)
	ed := w.editor
	edTok := actor{testClient: w.token(t, ed.id), id: ed.id, keys: ed.keys}

	// Control: as a member, the same editor writes by session and by token,
	// so the refusals below are the role's doing.
	ed.mustWriteDB(t, w.art.id, w.vid)
	edTok.mustWriteDB(t, w.art.id, w.vid)

	setRole(t, w.s, ed.id, store.RoleViewer)

	t.Run("session", func(t *testing.T) { refusedEveryWrite(t, w, ed) })

	t.Run("API key", func(t *testing.T) {
		key := actor{testClient: &testClient{t: t, base: w.base, token: apiKeyFor(t, ed.testClient, "editor@example.com-password", "00112233445566a1")}, id: ed.id, keys: ed.keys}
		refusedEveryWrite(t, w, key)
	})

	t.Run("content token", func(t *testing.T) {
		wantCode(t, edTok.testClient, "HEAD", w.vbase+"/files/"+w.addr, http.StatusOK)
		edTok.mustDo("GET", w.vbase+"/db", nil, nil, http.StatusOK)
		edTok.mustDo("GET", "/api/artifacts/"+w.art.id+"/membership", nil, nil, http.StatusOK)
		wantForbidden(t, "token write db", edTok.writeDB(t, w.art.id, w.vid))
		wantForbidden(t, "token put file", edTok.writeFile(t, w.art.id, w.vid, "x.txt", "x"))
		wantStatus(t, edTok.testClient, "DELETE", w.vbase+"/files/"+w.addr, nil, http.StatusForbidden)
	})

	t.Run("listed viewer who is a viewer account", func(t *testing.T) {
		setRole(t, w.s, w.viewer.id, store.RoleViewer)
		refusedEveryWrite(t, w, w.viewer)
	})

	// The owner and an editor who is still a member are not affected.
	w.owner.mustWriteDB(t, w.art.id, w.vid)
}

// TestViewerAccountOwnerCannotChangeAnything demotes an artifact's owner:
// they keep reading what they own and change none of it.
func TestViewerAccountOwnerCannotChangeAnything(t *testing.T) {
	w := newContentWorld(t)
	setRole(t, w.s, w.owner.id, store.RoleViewer)
	refusedEveryWrite(t, w, w.owner)
	// The viewer account that owns it still lists it.
	if _, ok := listIDs(t, w.owner.testClient)[w.art.id]; !ok {
		t.Error("the owner no longer lists their artifact")
	}
}

// TestViewerAccountCannotUsePublicWrites checks public writes, which let a
// signed-in link holder write, do not reach a viewer account.
func TestViewerAccountCannotUsePublicWrites(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	b := seedKeyedAccount(t, s, ts.URL, "b@example.com")
	o := newArtifact(t, a, "guestbook")
	vid := pushVersion(t, a.testClient, o.id)
	a.mustWriteDB(t, o.id, vid)
	link := o.makePublic()
	next := o.next()
	next.PublicWrites = true
	o.apply(next)

	b.link = link
	b.mustWriteDB(t, o.id, vid) // control: a member writes through the switch
	setRole(t, s, b.id, store.RoleViewer)
	wantForbidden(t, "public db write", b.writeDB(t, o.id, vid))
	wantForbidden(t, "public file write", b.writeFile(t, o.id, vid, "note.txt", "hi"))
	b.mustDo("GET", "/api/artifacts/"+o.id+"/versions/"+vid+"/db", nil, nil, http.StatusOK)
}

// TestViewerAccountCannotCreateArtifacts checks POST /api/artifacts answers a
// viewer account 403 with the viewer-account message, by session and API key,
// and that the same request from a member lands.
func TestViewerAccountCannotCreateArtifacts(t *testing.T) {
	s, ts := testServer(t)
	member := seedKeyedAccount(t, s, ts.URL, "m@example.com")
	viewer := seedKeyedAccount(t, s, ts.URL, "v@example.com")
	setRole(t, s, viewer.id, store.RoleViewer)
	key := &testClient{t: t, base: ts.URL, token: apiKeyFor(t, viewer.testClient, "v@example.com-password", "00112233445566b1")}

	create := func(c *testClient, as actor) (int, string) {
		id := uuid.NewString()
		return status(c, "POST", "/api/artifacts", map[string]any{
			"id": id, "membership": signRecord(t, as, firstRecord(t, as, id)),
			"wraps": []any{}, "estate": []any{testEstate(t, id, 1)},
		})
	}
	if code, msg := create(member.testClient, member); code != http.StatusCreated {
		t.Fatalf("a member creating: %d %q, want 201", code, msg)
	}
	for name, c := range map[string]*testClient{"session": viewer.testClient, "API key": key} {
		if code, msg := create(c, viewer); code != http.StatusForbidden || msg != "a viewer account cannot change anything" {
			t.Errorf("%s: %d %q, want 403 and the viewer-account message", name, code, msg)
		}
	}
	if got := listIDs(t, viewer.testClient); len(got) != 0 {
		t.Errorf("the viewer account lists %d artifacts after refused creates", len(got))
	}
}

// TestViewerAccountCannotAcceptOwnership checks accepting an offer is refused
// with the viewer-account message and changes nothing, while declining it is
// allowed.
func TestViewerAccountCannotAcceptOwnership(t *testing.T) {
	w := newTransferWorld(t)
	offer := w.offer(w.ed)
	setRole(t, w.s, w.ed.id, store.RoleViewer)

	_, req := w.acceptOwnerOffer(w.ed, offer, false)
	if code, msg := status(w.ed.testClient, "POST", w.transferPath("/accept"), req); code != http.StatusForbidden || msg != "a viewer account cannot change anything" {
		t.Fatalf("accept: %d %q, want 403 and the viewer-account message", code, msg)
	}
	if got := w.viewOf(w.owner.testClient); got.Owner != w.owner.id || got.Transfer == nil || got.Transfer.To != w.ed.id {
		t.Errorf("after the refused accept: %+v, want the owner unchanged and the offer open", got)
	}

	// Declining is allowed.
	w.ed.mustDo("DELETE", w.transferPath(""), nil, nil, http.StatusOK)
	if got := w.viewOf(w.owner.testClient); got.Transfer != nil {
		t.Errorf("the offer is still open after the viewer account declined: %+v", got.Transfer)
	}
}

// TestViewerAccountKeepsAccountMaintenance checks a viewer account still
// manages its own account: keys, notice email, recovery code, keyring, and
// password.
func TestViewerAccountKeepsAccountMaintenance(t *testing.T) {
	s, ts := testServer(t)
	v := seedKeyedAccount(t, s, ts.URL, "v@example.com")
	setRole(t, s, v.id, store.RoleViewer)
	pw := "v@example.com-password"

	key := apiKeyFor(t, v.testClient, pw, "00112233445566c1")
	keyClient := &testClient{t: t, base: ts.URL, token: key}
	var keys []keyView
	keyClient.mustDo("GET", "/api/keys", nil, &keys, http.StatusOK)
	if len(keys) != 1 {
		t.Fatalf("keys: %+v", keys)
	}
	keyClient.mustDo("GET", "/api/me/keyring", nil, nil, http.StatusOK)
	v.mustDo("PUT", "/api/me/notice-email", map[string]string{"email": "notice@example.com"}, nil, http.StatusAccepted)
	wire := testBundleWire()
	v.mustDo("PUT", "/api/me/recovery", map[string]any{"authKey": e2e.B64(testAuthKey(pw)), "mkRecovery": wire.MKRecovery}, nil, http.StatusOK)
	v.mustDo("DELETE", "/api/keys/"+keys[0].ID, nil, nil, http.StatusOK)
	keyClient.mustDo("GET", "/api/me", nil, nil, http.StatusUnauthorized)
	v.mustDo("PUT", "/api/me/password", map[string]any{
		"authKey": e2e.B64(testAuthKey(pw)), "newAuthKey": e2e.B64(testAuthKey("new-pw")),
		"kdf": wire.KDF, "mkPassword": wire.MKPassword,
	}, nil, http.StatusOK)
	login(t, ts.URL, "v@example.com", "new-pw").mustDo("GET", "/api/me", nil, nil, http.StatusOK)
}

// TestRoleInViews checks "role" sits next to "isAdmin" in every view of a
// user: the login response, /api/me, the directory, and the administrator's
// list.
func TestRoleInViews(t *testing.T) {
	s, ts := testServer(t)
	v := seedKeyedAccount(t, s, ts.URL, "v@example.com")
	setRole(t, s, v.id, store.RoleViewer)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")

	check := func(what string, got map[string]any, role string, isAdmin bool) {
		t.Helper()
		if flag, ok := got["isAdmin"]; got["role"] != role || (ok && flag != isAdmin) {
			t.Errorf("%s: role %v isAdmin %v, want %s %v", what, got["role"], got["isAdmin"], role, isAdmin)
		}
	}
	var login struct {
		User map[string]any `json:"user"`
	}
	(&testClient{t: t, base: ts.URL}).mustDo("POST", "/api/auth/login", map[string]string{
		"email": "v@example.com", "authKey": e2e.B64(testAuthKey("v@example.com-password")), "client": "cli",
	}, &login, http.StatusOK)
	check("login", login.User, "viewer", false)

	var me map[string]any
	v.mustDo("GET", "/api/me", nil, &me, http.StatusOK)
	check("/api/me", me, "viewer", false)

	var one map[string]any
	admin.mustDo("GET", "/api/users/"+v.id, nil, &one, http.StatusOK)
	check("/api/users/{id}", one, "viewer", false)

	var dir []map[string]any
	admin.mustDo("GET", "/api/users", nil, &dir, http.StatusOK)
	var adminAdmin []map[string]any
	admin.mustDo("GET", "/api/admin/users", nil, &adminAdmin, http.StatusOK)
	for _, tc := range []struct {
		what string
		list []map[string]any
	}{{"/api/users", dir}, {"/api/admin/users", adminAdmin}} {
		seen := map[string]bool{}
		for _, u := range tc.list {
			switch u["email"] {
			case "v@example.com":
				check(tc.what+" viewer", u, "viewer", false)
				seen["v"] = true
			case "admin@example.com":
				check(tc.what+" admin", u, "admin", true)
				seen["a"] = true
			}
		}
		if len(seen) != 2 {
			t.Errorf("%s did not list both users: %v", tc.what, seen)
		}
	}
}

// TestAdminSetsRole checks PATCH /api/admin/users/{id} with role, with the
// legacy isAdmin, with both, with a bad role, and the protection on an
// administrator's own role.
func TestAdminSetsRole(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	adminUser, _ := s.store.UserByEmail("admin@example.com")
	u := seedAccount(t, s, "x@example.com", "x-pw", false)
	path := "/api/admin/users/" + u.ID
	roleOf := func() string {
		t.Helper()
		got, err := s.store.UserByID(u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.Role
	}

	for _, role := range []string{"viewer", "admin", "member"} {
		var out map[string]any
		admin.mustDo("PATCH", path, map[string]any{"role": role}, &out, http.StatusOK)
		if out["role"] != role || out["isAdmin"] != (role == "admin") || roleOf() != role {
			t.Errorf("role %s: view %v, stored %s", role, out, roleOf())
		}
	}

	// Legacy isAdmin: true is admin, false is member, and false on a viewer
	// account leaves it a viewer account.
	admin.mustDo("PATCH", path, map[string]any{"isAdmin": true}, nil, http.StatusOK)
	if roleOf() != "admin" {
		t.Errorf("isAdmin true: %s", roleOf())
	}
	admin.mustDo("PATCH", path, map[string]any{"isAdmin": false}, nil, http.StatusOK)
	if roleOf() != "member" {
		t.Errorf("isAdmin false: %s", roleOf())
	}
	setRole(t, s, u.ID, store.RoleViewer)
	admin.mustDo("PATCH", path, map[string]any{"isAdmin": false}, nil, http.StatusOK)
	if roleOf() != "viewer" {
		t.Errorf("isAdmin false on a viewer account: %s", roleOf())
	}

	// Bad input changes nothing.
	for name, body := range map[string]map[string]any{
		"unknown role": {"role": "owner"},
		"empty role":   {"role": ""},
		"both":         {"role": "admin", "isAdmin": true},
		"both, equal":  {"role": "viewer", "isAdmin": false},
	} {
		code, msg := status(admin, "PATCH", path, body)
		want := "role must be admin, member, or viewer"
		if name == "both" || name == "both, equal" {
			want = "send role or isAdmin, not both"
		}
		if code != http.StatusBadRequest || msg != want {
			t.Errorf("%s: %d %q, want 400 %q", name, code, msg, want)
		}
		if roleOf() != "viewer" {
			t.Errorf("%s changed the role to %s", name, roleOf())
		}
	}

	// An administrator keeps their own role, as the last one; another
	// administrator may change it.
	for name, body := range map[string]map[string]any{
		"role member":   {"role": "member"},
		"role viewer":   {"role": "viewer"},
		"isAdmin false": {"isAdmin": false},
	} {
		code, msg := status(admin, "PATCH", "/api/admin/users/"+adminUser.ID, body)
		if code != http.StatusBadRequest || msg != "cannot remove your own administrator role" {
			t.Errorf("own %s: %d %q, want 400 and the own-role message", name, code, msg)
		}
	}
	admin.mustDo("PATCH", "/api/admin/users/"+adminUser.ID, map[string]any{"role": "admin"}, nil, http.StatusOK)
	if got, _ := s.store.UserByID(adminUser.ID); got.Role != "admin" {
		t.Errorf("the administrator is now %s", got.Role)
	}
	admin.mustDo("PATCH", path, map[string]any{"role": "admin"}, nil, http.StatusOK)
	second := login(t, ts.URL, "x@example.com", "x-pw")
	second.mustDo("PATCH", "/api/admin/users/"+adminUser.ID, map[string]any{"role": "viewer"}, nil, http.StatusOK)
	if got, _ := s.store.UserByID(adminUser.ID); got.Role != "viewer" {
		t.Errorf("the first administrator is %s after the second demoted them", got.Role)
	}

	// The first administrator is a viewer account now, so cannot set a role.
	wantStatus(t, admin, "PATCH", path, map[string]any{"role": "viewer"}, http.StatusForbidden)
}

// TestSignupRoles checks the role a new account gets: the administrator's
// address, a signup domain, a viewer domain, one in both lists, and one in
// neither, through the mailed sign-up.
func TestSignupRoles(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) {
		c.SignupDomains = []string{"members.test", "both.test"}
		c.ViewerDomains = []string{"Viewers.Test", "both.test", "example.com"}
	})
	c := &testClient{t: t, base: ts.URL}
	signup := func(email string) (int, string) {
		return status(c, "POST", "/api/auth/signup", map[string]any{
			"email": email, "name": "X", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
		})
	}
	for email, role := range map[string]string{
		"admin@example.com": "admin", // in a viewer domain too: the address wins
		"a@members.test":    "member",
		"v@viewers.test":    "viewer",
		"V@VIEWERS.TEST":    "viewer",
		"b@both.test":       "member",
	} {
		if code, msg := signup(email); code != http.StatusAccepted {
			t.Fatalf("%s: %d %q, want 202", email, code, msg)
		}
		u, err := s.store.UserByEmail(email)
		if err != nil || u.Role != role {
			t.Errorf("%s: role %v (%v), want %s", email, u, err, role)
		}
	}
	if code, msg := signup("n@other.test"); code != http.StatusForbidden || msg != "this email domain may not sign up" {
		t.Errorf("neither list: %d %q, want 403", code, msg)
	}
	if _, err := s.store.UserByEmail("n@other.test"); err == nil {
		t.Error("an account was created for a domain in neither list")
	}
}

// TestGoogleSignupRoles is TestSignupRoles through Google sign-up, where the
// hd rule still applies to signup domains only.
func TestGoogleSignupRoles(t *testing.T) {
	w := newGoogleWorld(t, func(c *Config) {
		c.SignupDomains = []string{"members.test", "both.test"}
		c.ViewerDomains = []string{"viewers.test", "both.test"}
	})
	for email, role := range map[string]string{
		"admin@example.com": "admin",
		"a@members.test":    "member",
		"v@viewers.test":    "viewer",
		"b@both.test":       "member",
	} {
		b := w.browser()
		b.mustSignIn(email)
		rec := b.do("POST", "/api/auth/signup", map[string]any{
			"email": email, "name": "X", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s: %d %s, want 201", email, rec.Code, rec.Body)
		}
		u, err := w.s.store.UserByEmail(email)
		if err != nil || u.Role != role {
			t.Errorf("%s: role %v (%v), want %s", email, u, err, role)
		}
	}
	b := w.browser()
	b.mustSignIn("n@other.test")
	wantError(t, b.do("POST", "/api/auth/signup", map[string]any{
		"email": "n@other.test", "name": "X", "authKey": e2e.B64(testAuthKey("pw")), "bundle": testBundleWire(),
	}), http.StatusForbidden, "this email domain may not sign up")
}
