package server

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/google/uuid"
)

// folderView is the part of an artifact view that folders add.
type folderView struct {
	ID     string  `json:"id"`
	Kind   string  `json:"kind"`
	Parent *string `json:"parent"`
	Access string  `json:"access"`
}

// itemRequest is the POST /api/artifacts body for a new item of kind in
// parent, owned by owner, and its ID.
func itemRequest(t *testing.T, owner actor, kind, parent string) (string, map[string]any) {
	t.Helper()
	id := uuid.NewString()
	req := map[string]any{
		"id": id, "membership": signRecord(t, owner, firstRecord(t, owner, id)),
		"wraps": []any{}, "estate": []any{testEstate(t, id, 1)},
	}
	if kind != "" {
		req["kind"] = kind
	}
	if parent != "" {
		req["parent"] = parent
	}
	return id, req
}

// newItem creates an item of kind in parent and expects it to land.
func newItem(t *testing.T, owner actor, kind, parent string) *owned {
	t.Helper()
	id, req := itemRequest(t, owner, kind, parent)
	var v folderView
	owner.mustDo("POST", "/api/artifacts", req, &v, http.StatusCreated)
	wantKind := kind
	if wantKind == "" {
		wantKind = "artifact"
	}
	if v.ID != id || v.Kind != wantKind || (parent == "") != (v.Parent == nil) || parent != "" && *v.Parent != parent {
		t.Fatalf("created %s in %q answered %+v", kind, parent, v)
	}
	b := firstRecord(t, owner, id)
	return &owned{t: t, owner: owner, id: id, latest: b, hash: e2e.BodyHash(req["membership"].(e2e.Envelope).Body)}
}

// tryItem creates an item and returns the status and error text.
func tryItem(t *testing.T, owner actor, kind, parent string) (int, string) {
	t.Helper()
	_, req := itemRequest(t, owner, kind, parent)
	return status(owner.testClient, "POST", "/api/artifacts", req)
}

func parentOf(t *testing.T, c *testClient, id string) *string {
	t.Helper()
	var v folderView
	c.mustDo("GET", "/api/artifacts/"+id, nil, &v, http.StatusOK)
	return v.Parent
}

func wantParent(t *testing.T, c *testClient, id, want string) {
	t.Helper()
	got := parentOf(t, c, id)
	if (want == "") != (got == nil) || got != nil && *got != want {
		t.Errorf("parent of %s: %v, want %q", id, got, want)
	}
}

func move(c *testClient, id string, parent any) (int, string) {
	return status(c, "PUT", "/api/artifacts/"+id+"/parent", map[string]any{"parent": parent})
}

func folderWorld(t *testing.T) (a, b actor) {
	t.Helper()
	s, ts := testServer(t)
	return seedKeyedAccount(t, s, ts.URL, "a@example.com"), seedKeyedAccount(t, s, ts.URL, "b@example.com")
}

func TestCreateFoldersAndItemsInThem(t *testing.T) {
	a, _ := folderWorld(t)
	top := newItem(t, a, "folder", "")
	inner := newItem(t, a, "folder", top.id)
	item := newItem(t, a, "", inner.id)
	newItem(t, a, "artifact", top.id)

	listed := listIDs(t, a.testClient)
	if len(listed) != 4 {
		t.Fatalf("listed %d items, want 4", len(listed))
	}
	var views []folderView
	a.mustDo("GET", "/api/artifacts", nil, &views, http.StatusOK)
	byID := map[string]folderView{}
	for _, v := range views {
		byID[v.ID] = v
	}
	if v := byID[top.id]; v.Kind != "folder" || v.Parent != nil || v.Access != "owner" {
		t.Errorf("top folder in the list: %+v", v)
	}
	if v := byID[inner.id]; v.Kind != "folder" || v.Parent == nil || *v.Parent != top.id {
		t.Errorf("nested folder in the list: %+v", v)
	}
	if v := byID[item.id]; v.Kind != "artifact" || v.Parent == nil || *v.Parent != inner.id {
		t.Errorf("item in the list: %+v", v)
	}
	wantParent(t, a.testClient, item.id, inner.id)
	wantParent(t, a.testClient, top.id, "")
}

func TestCreateRefusals(t *testing.T) {
	a, b := folderWorld(t)
	plain := newArtifact(t, a, "plain")
	theirFolder := newItem(t, b, "folder", "")
	shared := newArtifact(t, b, "shared")
	shared.share("editor", a)

	for _, c := range []struct {
		name, kind, parent string
		want               int
	}{
		{"unknown kind", "drawer", "", http.StatusBadRequest},
		{"parent is an artifact", "", plain.id, http.StatusConflict},
		{"parent does not exist", "", uuid.NewString(), http.StatusNotFound},
		{"parent is another user's unreadable folder", "", theirFolder.id, http.StatusNotFound},
		{"parent is readable but not owned", "", shared.id, http.StatusForbidden},
	} {
		if got, msg := tryItem(t, a, c.kind, c.parent); got != c.want {
			t.Errorf("%s: %d %q, want %d", c.name, got, msg, c.want)
		}
	}
	if len(listIDs(t, a.testClient)) != 2 { // plain, and shared with a
		t.Errorf("a refused create left an item behind")
	}
}

func TestDepthLimitOnCreate(t *testing.T) {
	a, _ := folderWorld(t)
	parent := ""
	var last *owned
	for i := 0; i < 16; i++ {
		last = newItem(t, a, "folder", parent)
		parent = last.id
	}
	if got, msg := tryItem(t, a, "folder", last.id); got != http.StatusConflict {
		t.Errorf("a 17th folder: %d %q, want 409", got, msg)
	}
	newItem(t, a, "artifact", last.id)
}

func TestMove(t *testing.T) {
	a, b := folderWorld(t)
	f1 := newItem(t, a, "folder", "")
	f2 := newItem(t, a, "folder", f1.id)
	item := newArtifact(t, a, "item")
	theirs := newItem(t, b, "folder", "")

	var v folderView
	a.mustDo("PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{"parent": f2.id}, &v, http.StatusOK)
	if v.ID != item.id || v.Parent == nil || *v.Parent != f2.id || v.Kind != "artifact" {
		t.Errorf("move answered %+v", v)
	}
	wantParent(t, a.testClient, item.id, f2.id)
	a.mustDo("PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{"parent": nil}, &v, http.StatusOK)
	if v.Parent != nil {
		t.Errorf("move to the top answered %+v", v)
	}
	wantParent(t, a.testClient, item.id, "")

	checks := []struct {
		name string
		got  func() (int, string)
		want int
	}{
		{"folder into itself", func() (int, string) { return move(a.testClient, f1.id, f1.id) }, http.StatusConflict},
		{"folder into a descendant", func() (int, string) { return move(a.testClient, f1.id, f2.id) }, http.StatusConflict},
		{"into an artifact", func() (int, string) { return move(a.testClient, f1.id, item.id) }, http.StatusConflict},
		{"into someone else's folder", func() (int, string) { return move(a.testClient, item.id, theirs.id) }, http.StatusNotFound},
		{"into a missing folder", func() (int, string) { return move(a.testClient, item.id, uuid.NewString()) }, http.StatusNotFound},
		{"a stranger moves it", func() (int, string) { return move(b.testClient, item.id, nil) }, http.StatusNotFound},
		{"parent is not a string", func() (int, string) { return move(a.testClient, item.id, 7) }, http.StatusBadRequest},
		{"parent is empty", func() (int, string) { return move(a.testClient, item.id, "") }, http.StatusBadRequest},
		{"no parent key", func() (int, string) {
			return status(a.testClient, "PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{})
		}, http.StatusBadRequest},
	}
	for _, c := range checks {
		if got, msg := c.got(); got != c.want {
			t.Errorf("%s: %d %q, want %d", c.name, got, msg, c.want)
		}
	}

	if got, msg := status(a.testClient, "PUT", "/api/artifacts/"+item.id+"/parent", map[string]any{}); got != http.StatusBadRequest || !strings.Contains(msg, "parent is required") {
		t.Errorf("no parent key: %d %q, want 400 parent is required", got, msg)
	}
	// A listed editor reads the item but may not move it.
	item.share("editor", b)
	if got, msg := move(b.testClient, item.id, nil); got != http.StatusForbidden {
		t.Errorf("an editor moves the item: %d %q, want 403", got, msg)
	}
	wantParent(t, a.testClient, f2.id, f1.id)
}

func TestDepthLimitOnMove(t *testing.T) {
	a, _ := folderWorld(t)
	var chain []*owned
	parent := ""
	for i := 0; i < 10; i++ {
		f := newItem(t, a, "folder", parent)
		chain = append(chain, f)
		parent = f.id
	}
	var sub []*owned
	parent = ""
	for i := 0; i < 7; i++ {
		f := newItem(t, a, "folder", parent)
		sub = append(sub, f)
		parent = f.id
	}
	// Seven folders under ten make seventeen, though the folder moved sits
	// only one deep: the deepest folder of the subtree counts.
	if got, msg := move(a.testClient, sub[0].id, chain[9].id); got != http.StatusConflict {
		t.Errorf("a subtree past the limit: %d %q, want 409", got, msg)
	}
	if got, msg := move(a.testClient, sub[0].id, chain[8].id); got != http.StatusOK {
		t.Errorf("a subtree to exactly 16: %d %q, want 200", got, msg)
	}
	art := newArtifact(t, a, "leaf")
	if got, msg := move(a.testClient, art.id, sub[6].id); got != http.StatusOK {
		t.Errorf("an artifact into the 16th folder: %d %q, want 200", got, msg)
	}
}

// folderRoutes are the /api/artifacts/{id} routes a folder legitimately
// uses: its view, name, place, owner-only membership, keys, and deletion.
// Every other route under {id} is content and must refuse a folder. A new
// route belongs here only if a folder really has the thing it serves.
var folderRoutes = map[string]bool{
	"GET /api/artifacts/{id}":                  true,
	"DELETE /api/artifacts/{id}":               true,
	"PUT /api/artifacts/{id}/meta/{field}":     true,
	"PUT /api/artifacts/{id}/parent":           true,
	"GET /api/artifacts/{id}/membership":       true,
	"PUT /api/artifacts/{id}/membership":       true,
	"POST /api/artifacts/{id}/transfer":        true,
	"DELETE /api/artifacts/{id}/transfer":      true,
	"POST /api/artifacts/{id}/transfer/accept": true,
	"PUT /api/artifacts/{id}/estate/{epoch}":   true,
	"GET /api/artifacts/{id}/keys":             true,
	"POST /api/artifacts/{id}/keys":            true,
	"GET /api/artifacts/{id}/pending":          true,
}

// pathParams fills a route's {name} segments with values that pass the
// handlers' own shape checks.
var pathParams = map[string]string{
	"blob": strings.Repeat("a", 64), "address": strings.Repeat("a", 64), "rev": "1", "field": "title", "epoch": "1",
}

func TestFolderRefusesEveryContentRoute(t *testing.T) {
	s, ts := testServer(t)
	a, b := seedKeyedAccount(t, s, ts.URL, "a@example.com"), seedKeyedAccount(t, s, ts.URL, "b@example.com")
	f := newItem(t, a, "folder", "")
	registered := map[string]bool{}
	checked := 0
	for _, pattern := range s.patterns {
		registered[pattern] = true
		method, path, _ := strings.Cut(pattern, " ")
		if path != "/api/artifacts/{id}" && !strings.HasPrefix(path, "/api/artifacts/{id}/") || folderRoutes[pattern] {
			continue
		}
		checked++
		path = strings.ReplaceAll(path, "{id}", f.id)
		for _, seg := range strings.Split(path, "/") {
			if name, ok := strings.CutPrefix(seg, "{"); ok {
				name = strings.TrimSuffix(name, "}")
				v, ok := pathParams[name]
				if !ok {
					v = uuid.NewString()
				}
				path = strings.Replace(path, seg, v, 1)
			}
		}
		got, msg := status(a.testClient, method, path, nil)
		if got != http.StatusConflict || msg != "a folder holds no content" {
			t.Errorf("%s: %d %q, want 409 a folder holds no content (add refuseFolder, or list it in folderRoutes)", pattern, got, msg)
		}
		// Someone with no access learns nothing, not even that it is a folder.
		if got, _ := status(b.testClient, method, path, nil); got != http.StatusNotFound {
			t.Errorf("%s as a stranger: %d, want 404", pattern, got)
		}
	}
	if checked < 20 {
		t.Errorf("checked only %d content routes", checked)
	}
	for p := range folderRoutes {
		if !registered[p] {
			t.Errorf("folderRoutes lists %q, which no route registers", p)
		}
	}
	// What a folder does carry still works: its view, its name.
	a.mustDo("GET", "/api/artifacts/"+f.id, nil, nil, http.StatusOK)
	newMeta(t, a, f.id, "", "name", 1, "Work").send(t)
	if r := newMeta(t, a, f.id, "", "name", 1, "Work again").send(t); r.StatusCode != http.StatusOK {
		t.Errorf("renaming a folder: %d", r.StatusCode)
	}
}

func TestFolderTakesNoResources(t *testing.T) {
	a, _ := folderWorld(t)
	f := newItem(t, a, "folder", "")
	base := "/api/artifacts/" + f.id + "/resources"
	got, msg := status(a.testClient, "POST", base, map[string]string{"type": "claude-session", "value": refOf("s")})
	if got != http.StatusConflict || msg != "a folder holds no content" {
		t.Errorf("adding a resource to a folder: %d %q, want 409 a folder holds no content", got, msg)
	}
	got, msg = status(a.testClient, "DELETE", base+"/"+uuid.NewString(), nil)
	if got != http.StatusConflict || msg != "a folder holds no content" {
		t.Errorf("removing a resource from a folder: %d %q, want 409 a folder holds no content", got, msg)
	}
}

func TestFolderIsPrivateInF1(t *testing.T) {
	a, b := folderWorld(t)
	f := newItem(t, a, "folder", "")
	put := func(edit func(*e2e.MembershipBody)) (int, string) {
		body := f.next()
		edit(&body)
		return status(a.testClient, "PUT", "/api/artifacts/"+f.id+"/membership", f.change(body))
	}
	for name, edit := range map[string]func(*e2e.MembershipBody){
		"a member": func(m *e2e.MembershipBody) {
			m.Members = []e2e.Member{{User: b.id, Role: "viewer", FP: b.keys.fp()}}
		},
		"a team": func(m *e2e.MembershipBody) { m.Team = "viewer" },
		"public": func(m *e2e.MembershipBody) { m.Public = true },
		"public writes": func(m *e2e.MembershipBody) {
			m.Public, m.PublicWrites = true, true
		},
		"public writes alone": func(m *e2e.MembershipBody) { m.PublicWrites = true },
	} {
		got, msg := put(edit)
		if got != http.StatusConflict || !strings.Contains(msg, "folders cannot be shared yet") {
			t.Errorf("%s: %d %q, want 409 folders cannot be shared yet", name, got, msg)
		}
	}
	// A record that changes nothing is fine, and so is a next epoch.
	if got, msg := put(func(*e2e.MembershipBody) {}); got != http.StatusOK {
		t.Errorf("an unchanged record: %d %q", got, msg)
	}
	// Artifacts are unaffected.
	art := newArtifact(t, a, "plain")
	art.share("viewer", b)
}

func TestFolderCannotBeOffered(t *testing.T) {
	w := newTransferWorld(t)
	f := newItem(t, w.owner, "folder", "")
	body := e2e.TransferBody{V: 1, Artifact: f.id, From: w.owner.id, To: w.ed.id, ToFP: w.ed.keys.fp(), Prev: f.hash}
	req := map[string]any{"to": w.ed.id, "offer": signOffer(t, w.owner, body)}
	got, msg := status(w.owner.testClient, "POST", "/api/artifacts/"+f.id+"/transfer", req)
	if got != http.StatusConflict || !strings.Contains(msg, "folders cannot be shared yet") {
		t.Errorf("offer of a folder: %d %q", got, msg)
	}
	w.deactivate(w.owner)
	got, msg = status(w.admin, "POST", "/api/admin/artifacts/"+f.id+"/transfer", map[string]any{"to": w.ed.id})
	if got != http.StatusConflict || !strings.Contains(msg, "folders cannot be shared yet") {
		t.Errorf("administrator's offer of a folder: %d %q", got, msg)
	}
}

func TestAcceptingAnItemInTheOwnersFolderMovesItToTheTop(t *testing.T) {
	w := newTransferWorld(t)
	f := newItem(t, w.owner, "folder", "")
	if got, msg := move(w.owner.testClient, w.o.id, f.id); got != http.StatusOK {
		t.Fatalf("move: %d %q", got, msg)
	}
	wantParent(t, w.owner.testClient, w.o.id, f.id)

	offer := w.offer(w.ed)
	_, req := w.acceptOwnerOffer(w.ed, offer, false)
	w.ed.mustDo("POST", w.transferPath("/accept"), req, nil, http.StatusOK)

	for _, c := range []*testClient{w.ed.testClient, w.owner.testClient} {
		wantParent(t, c, w.o.id, "")
	}
	var list []folderView
	w.ed.mustDo("GET", "/api/artifacts", nil, &list, http.StatusOK)
	for _, v := range list {
		if v.ID == f.id {
			t.Errorf("the new owner lists the previous owner's folder")
		}
	}
}

func TestDeletingAFolder(t *testing.T) {
	a, b := folderWorld(t)
	f := newItem(t, a, "folder", "")
	child := newItem(t, a, "", f.id)
	path := "/api/artifacts/" + f.id

	if got, msg := status(b.testClient, "DELETE", path, nil); got != http.StatusNotFound {
		t.Errorf("a stranger deletes the folder: %d %q", got, msg)
	}
	if got, msg := status(a.testClient, "DELETE", path, nil); got != http.StatusConflict || msg != "the folder is not empty" {
		t.Errorf("deleting a non-empty folder: %d %q, want 409 the folder is not empty", got, msg)
	}
	a.mustDo("GET", path, nil, nil, http.StatusOK)
	a.mustDo("DELETE", "/api/artifacts/"+child.id, nil, nil, http.StatusOK)
	a.mustDo("DELETE", path, nil, nil, http.StatusOK)
	wantStatus(t, a.testClient, "GET", path, nil, http.StatusNotFound)
}

func TestParentIsHiddenFromAReaderWhoCannotReadTheFolder(t *testing.T) {
	a, b := folderWorld(t)
	f := newItem(t, a, "folder", "")
	item := newItem(t, a, "", f.id)
	item.share("viewer", b)

	wantParent(t, a.testClient, item.id, f.id)
	wantParent(t, b.testClient, item.id, "")
	if got := listIDs(t, b.testClient); len(got) != 1 {
		t.Fatalf("b lists %d items, want 1 (the folder is private)", len(got))
	}
	var list []folderView
	b.mustDo("GET", "/api/artifacts", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].ID != item.id || list[0].Parent != nil || list[0].Kind != "artifact" {
		t.Errorf("b's list: %+v", list)
	}
	// The folder itself is a 404 for b.
	wantStatus(t, b.testClient, "GET", "/api/artifacts/"+f.id, nil, http.StatusNotFound)
}

func TestFolderNamesAreCiphertextOnDisk(t *testing.T) {
	dir := t.TempDir()
	s, ts := newTestServer(t, func(c *Config) { c.DataDir = dir })
	seedAccount(t, s, "admin@example.com", "admin-password", true)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	f := newItem(t, a, "folder", "")
	const name = "Zebra-Quartz-Ledger-7731"
	if r := newMeta(t, a, f.id, "", "name", 1, name).send(t); r.StatusCode != http.StatusOK {
		t.Fatalf("naming the folder: %d", r.StatusCode)
	}
	seen := false
	for _, file := range []string{"cairn.db", "cairn.db-wal"} {
		raw, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			continue
		}
		if bytes.Contains(raw, []byte(name)) {
			t.Errorf("%s holds the folder's name in the clear", file)
		}
		seen = seen || bytes.Contains(raw, []byte(f.id))
	}
	if !seen {
		t.Error("neither database file holds the folder's ID: the scan read nothing")
	}
}
