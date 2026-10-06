package server

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// TestAPIKeyLifecycle covers creating, using, listing, and revoking an API
// key, and the new bearer format cairn_<keyid>_<authSecret>.
func TestAPIKeyLifecycle(t *testing.T) {
	s, ts := testServer(t)
	seedAccount(t, s, "ada@example.com", "pw", false)
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "ada@example.com", "pw")

	mk := e2e.B64(bytes.Repeat([]byte{0x11}, sealedKeyLen))
	var created createKeyResponse
	c.mustDo("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey("pw")), "name": "laptop", "device": true,
		"keyId": "00112233445566ff", "authSecret": "00112233445566778899aabbccddeeff", "mk": mk,
	}, &created, http.StatusCreated)
	if created.Name != "laptop" || !created.Device {
		t.Fatalf("created key: %+v", created)
	}

	bearer := "cairn_00112233445566ff_00112233445566778899aabbccddeeff"
	keyClient := &testClient{t: t, base: ts.URL, token: bearer}
	var me meView
	keyClient.mustDo("GET", "/api/me", nil, &me, http.StatusOK)
	if me.Email != "ada@example.com" {
		t.Errorf("key authenticates as %q", me.Email)
	}

	var bundleResp meBundleResponse
	keyClient.mustDo("GET", "/api/me/bundle", nil, &bundleResp, http.StatusOK)
	if bundleResp.APIKey == nil || bundleResp.APIKey.ID != created.ID || bundleResp.APIKey.MK != mk {
		t.Errorf("bundle apiKey = %+v, want id %q mk %q", bundleResp.APIKey, created.ID, mk)
	}

	// POST /api/keys needs a session, not an API key.
	resp := keyClient.do("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey("pw")), "name": "x",
		"keyId": "1111111111111111", "authSecret": "11111111111111111111111111111111", "mk": mk,
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /api/keys with an API key: %d, want 401", resp.StatusCode)
	}

	var list []keyView
	keyClient.mustDo("GET", "/api/keys", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("list keys: %+v", list)
	}

	c.mustDo("DELETE", "/api/keys/"+created.ID, nil, nil, http.StatusOK)
	resp = keyClient.do("GET", "/api/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked key still works: %d", resp.StatusCode)
	}
}

// TestAPIKeyFromDisabledUserRefused covers "an API key from a disabled user
// is refused".
func TestAPIKeyFromDisabledUserRefused(t *testing.T) {
	s, ts := testServer(t)
	u := seedAccount(t, s, "ada@example.com", "pw", false)
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "ada@example.com", "pw")

	mk := e2e.B64(bytes.Repeat([]byte{0x22}, sealedKeyLen))
	var created createKeyResponse
	c.mustDo("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey("pw")), "name": "k",
		"keyId": "aabbccddeeff0011", "authSecret": "aabbccddeeff00112233445566778899", "mk": mk,
	}, &created, http.StatusCreated)
	bearer := "cairn_aabbccddeeff0011_aabbccddeeff00112233445566778899"
	keyClient := &testClient{t: t, base: ts.URL, token: bearer}

	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	admin.mustDo("PATCH", "/api/admin/users/"+u.ID, map[string]any{"disabled": true}, nil, http.StatusOK)

	resp := keyClient.do("GET", "/api/me", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("disabled user's API key still works: %d", resp.StatusCode)
	}
}

// TestNoAdminEndpointCreatesAccountsOrKeysOrSetsPasswords covers the removed
// admin endpoints: none of them exist any more.
func TestNoAdminEndpointCreatesAccountsOrKeysOrSetsPasswords(t *testing.T) {
	s, ts := testServer(t)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	for _, call := range []struct{ method, path string }{
		{"POST", "/api/admin/users"},
		{"POST", "/api/admin/keys"},
		{"POST", "/api/admin/users/x/reset-password"},
	} {
		resp := admin.do(call.method, call.path, map[string]any{"email": "x@example.com"}, nil)
		// The mux answers 405 when the path is registered for another method
		// (GET /api/admin/users exists) and 404 when it matches no pattern at
		// all; either way, there is no endpoint that will act on this call.
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, want 404 or 405 (endpoint must not exist)", call.method, call.path, resp.StatusCode)
		}
	}

	// PATCH only ever reads isAdmin/disabled; anything else sent alongside
	// them (such as a password) is simply not a field the request type has,
	// so it's ignored rather than honored.
	u := seedAccount(t, s, "x@example.com", "x-pw", false)
	admin.mustDo("PATCH", "/api/admin/users/"+u.ID, map[string]any{"isAdmin": true}, nil, http.StatusOK)
	// The account's password is untouched: the original one still signs in.
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "x@example.com", "x-pw")
}

// TestAdminRoutesRefuseEveryoneElse sends each administrator route a request
// from a signed-in user who is not an administrator, and one from a visitor:
// each is refused, and the account the requests name is unchanged.
func TestAdminRoutesRefuseEveryoneElse(t *testing.T) {
	s, ts := testServer(t)
	u := seedAccount(t, s, "user@example.com", "user-pw", false)
	user := login(t, ts.URL, "user@example.com", "user-pw")
	visitor := &testClient{t: t, base: ts.URL}
	for _, call := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/admin/users", nil},
		{"PATCH", "/api/admin/users/" + u.ID, map[string]any{"isAdmin": true}},
		{"DELETE", "/api/admin/users/" + u.ID, nil},
		{"GET", "/api/admin/users/" + u.ID + "/artifacts", nil},
		{"POST", "/api/admin/artifacts/x/transfer", map[string]any{"to": u.ID}},
		{"DELETE", "/api/admin/artifacts/x", nil},
	} {
		wantStatus(t, user, call.method, call.path, call.body, http.StatusForbidden)
		wantStatus(t, visitor, call.method, call.path, call.body, http.StatusUnauthorized)
	}
	got, err := s.store.UserByEmail("user@example.com")
	if err != nil {
		t.Fatalf("the account is gone: %v", err)
	}
	if got.IsAdmin {
		t.Error("the account became an administrator")
	}
}

func TestDirectoryExcludesDisabledAndUnverified(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.SignupDomains = []string{"example.com"} })
	seedAccount(t, s, "admin@example.com", "admin-password", true)
	seedAccount(t, s, "verified@example.com", "pw", false)
	disabled := seedAccount(t, s, "disabled@example.com", "pw", false)
	if err := s.store.SetUserDisabled(disabled.ID, true); err != nil {
		t.Fatal(err)
	}
	signupAndCapture(t, ts.URL, mailer(s), "unverified@example.com", "pw")

	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "verified@example.com", "pw")
	var dir []directoryUser
	c.mustDo("GET", "/api/users", nil, &dir, http.StatusOK)
	emails := map[string]bool{}
	for _, d := range dir {
		emails[d.Email] = true
	}
	if !emails["verified@example.com"] {
		t.Error("directory missing the verified account")
	}
	if emails["disabled@example.com"] {
		t.Error("directory includes a disabled account")
	}
	if emails["unverified@example.com"] {
		t.Error("directory includes an unverified account")
	}

	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	var adminDir []adminDirectoryUser
	admin.mustDo("GET", "/api/admin/users", nil, &adminDir, http.StatusOK)
	adminEmails := map[string]bool{}
	for _, d := range adminDir {
		adminEmails[d.Email] = true
	}
	if !adminEmails["disabled@example.com"] || !adminEmails["unverified@example.com"] {
		t.Errorf("admin directory missing disabled/unverified accounts: %+v", adminDir)
	}
}

// TestAPIKeyWrongSecretRefused: a real key id with the wrong secret is
// refused, so the key id alone is not a credential.
func TestAPIKeyWrongSecretRefused(t *testing.T) {
	s, ts := testServer(t)
	seedAccount(t, s, "ada@example.com", "pw", false)
	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "ada@example.com", "pw")
	c.mustDo("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey("pw")), "name": "k",
		"keyId": "0011223344556677", "authSecret": "00112233445566778899aabbccddeeff",
		"mk": e2e.B64(bytes.Repeat([]byte{0x33}, sealedKeyLen)),
	}, nil, http.StatusCreated)

	wrong := &testClient{t: t, base: ts.URL, token: "cairn_0011223344556677_ffeeddccbbaa99887766554433221100"}
	if resp := wrong.do("GET", "/api/me", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong secret for a real key id: status %d, want 401", resp.StatusCode)
	}
}

// TestRevokeOtherUsersKeyNotFound: DELETE /api/keys/{id} only reaches the
// caller's own keys; another user's key is a 404 and keeps working.
func TestRevokeOtherUsersKeyNotFound(t *testing.T) {
	s, ts := testServer(t)
	seedAccount(t, s, "ada@example.com", "pw", false)
	seedAccount(t, s, "bob@example.com", "pw", false)
	ada := &testClient{t: t, base: ts.URL}
	loginAgain(t, ada, "ada@example.com", "pw")
	var created createKeyResponse
	ada.mustDo("POST", "/api/keys", map[string]any{
		"authKey": e2e.B64(testAuthKey("pw")), "name": "k",
		"keyId": "8899aabbccddeeff", "authSecret": "8899aabbccddeeff0011223344556677",
		"mk": e2e.B64(bytes.Repeat([]byte{0x44}, sealedKeyLen)),
	}, &created, http.StatusCreated)

	bob := &testClient{t: t, base: ts.URL}
	loginAgain(t, bob, "bob@example.com", "pw")
	bob.mustDo("DELETE", "/api/keys/"+created.ID, nil, nil, http.StatusNotFound)

	key := &testClient{t: t, base: ts.URL, token: "cairn_8899aabbccddeeff_8899aabbccddeeff0011223344556677"}
	key.mustDo("GET", "/api/me", nil, nil, http.StatusOK)
}

// TestUserByIDHidesDisabledAndUnverified: GET /api/users/{id} shows the
// same accounts the directory lists, and no others.
func TestUserByIDHidesDisabledAndUnverified(t *testing.T) {
	s, ts := newTestServer(t, func(c *Config) { c.SignupDomains = []string{"example.com"} })
	seedAccount(t, s, "admin@example.com", "admin-password", true)
	verified := seedAccount(t, s, "verified@example.com", "pw", false)
	disabled := seedAccount(t, s, "disabled@example.com", "pw", false)
	if err := s.store.SetUserDisabled(disabled.ID, true); err != nil {
		t.Fatal(err)
	}
	signupAndCapture(t, ts.URL, mailer(s), "unverified@example.com", "pw")
	unverified := mustUserID(t, s, "unverified@example.com")

	c := &testClient{t: t, base: ts.URL}
	loginAgain(t, c, "verified@example.com", "pw")
	c.mustDo("GET", "/api/users/"+verified.ID, nil, nil, http.StatusOK)
	c.mustDo("GET", "/api/users/"+disabled.ID, nil, nil, http.StatusNotFound)
	c.mustDo("GET", "/api/users/"+unverified, nil, nil, http.StatusNotFound)
}

// TestLoginDisabledAccountRefused: the right key for a deactivated account
// gets 403, not a session.
func TestLoginDisabledAccountRefused(t *testing.T) {
	s, ts := testServer(t)
	u := seedAccount(t, s, "ada@example.com", "pw", false)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	admin.mustDo("PATCH", "/api/admin/users/"+u.ID, map[string]any{"disabled": true}, nil, http.StatusOK)

	c := &testClient{t: t, base: ts.URL}
	c.mustDo("POST", "/api/auth/login", map[string]any{
		"email": "ada@example.com", "authKey": e2e.B64(testAuthKey("pw")), "client": "cli",
	}, nil, http.StatusForbidden)
}

// TestPasswordChangeEndsOldSessions: changing the password bumps the token
// version, so a token issued before it stops working at once, while the one
// the change hands back works.
func TestPasswordChangeEndsOldSessions(t *testing.T) {
	s, ts := testServer(t)
	seedAccount(t, s, "ada@example.com", "pw", false)
	old := &testClient{t: t, base: ts.URL}
	loginAgain(t, old, "ada@example.com", "pw")
	current := &testClient{t: t, base: ts.URL}
	loginAgain(t, current, "ada@example.com", "pw")

	w := testBundleWire()
	current.mustDo("PUT", "/api/me/password", map[string]any{
		"authKey": e2e.B64(testAuthKey("pw")), "newAuthKey": e2e.B64(testAuthKey("new-pw")),
		"kdf": w.KDF, "mkPassword": w.MKPassword,
	}, nil, http.StatusOK)

	old.mustDo("GET", "/api/me", nil, nil, http.StatusUnauthorized)
	fresh := &testClient{t: t, base: ts.URL}
	loginAgain(t, fresh, "ada@example.com", "new-pw")
	fresh.mustDo("GET", "/api/me", nil, nil, http.StatusOK)
}

// TestAdminCannotDeleteAnArtifactOwner: deleting an owner would orphan the
// artifacts other members rely on, so it is a 409, not a 500.
func TestAdminCannotDeleteAnArtifactOwner(t *testing.T) {
	s, ts := testServer(t)
	u := seedAccount(t, s, "ada@example.com", "pw", false)
	if _, err := s.store.CreateOwnedArtifact("11111111-1111-4111-8111-111111111111", u.ID, nil); err != nil {
		t.Fatal(err)
	}
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	resp := admin.do("DELETE", "/api/admin/users/"+u.ID, nil, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("deleting an owner: status %d, want 409", resp.StatusCode)
	}
	if _, err := s.store.UserByID(u.ID); err != nil {
		t.Errorf("owner deleted anyway: %v", err)
	}
}
