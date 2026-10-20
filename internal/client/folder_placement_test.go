package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Placement is signed: a fan-out copies a folder's entries into an item only
// when the item's own verified record names the folder, never on the word of
// the server's unsigned tree. See "Placement is signed" in design/e2e-api.md.

// claiming is a copy of c that answers GET for the list of artifacts, and for
// each artifact in claims, as a hostile server could: the item sits in the
// folder claims names, and is pending. It records every PUT and POST it
// sends, so a test can show that nothing was written for an item.
func claiming(c *Client, claims map[string]string) (*Client, *[]string) {
	out := NewWithKey(c.Host, *c.Key)
	out.Anchors = c.Anchors
	var sent []string
	claim := func(m map[string]any) {
		if folder, ok := claims[m["id"].(string)]; ok {
			m["parent"], m["inherit"] = folder, "pending"
		}
	}
	out.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "PUT" || r.Method == "POST" {
			sent = append(sent, r.Method+" "+r.URL.Path)
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		_, one := claims[strings.TrimPrefix(r.URL.Path, "/api/artifacts/")]
		if err != nil || r.Method != "GET" || resp.StatusCode != 200 || r.URL.Path != "/api/artifacts" && !one {
			return resp, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if r.URL.Path == "/api/artifacts" {
			var list []map[string]any
			if err := json.Unmarshal(data, &list); err != nil {
				return nil, err
			}
			for _, m := range list {
				claim(m)
			}
			data, err = json.Marshal(list)
		} else {
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				return nil, err
			}
			claim(m)
			data, err = json.Marshal(m)
		}
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return resp, nil
	})}
	return out, &sent
}

// writesTo reports whether sent holds a PUT or POST to a path under artifact.
func writesTo(sent []string, artifact string) bool {
	return slices.ContainsFunc(sent, func(s string) bool { return strings.Contains(s, "/api/artifacts/"+artifact+"/") })
}

func itemResult(res *FanOutResult, id string) *FanOutItem {
	for i := range res.Items {
		if res.Items[i].ID == id {
			return &res.Items[i]
		}
	}
	return nil
}

// A server that lists another of the caller's items under a folder, as
// pending, does not get that item's key sealed to the folder's members.
func TestAHostileServerCannotListAForeignItemUnderAFolder(t *testing.T) {
	w := newFolderTree(t)
	foreign := mustCreate(t, w.ada, "foreign").ID
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	before := latestBody(t, w.ada, foreign)

	hostile, sent := claiming(w.ada, map[string]string{foreign: w.f})
	res, err := hostile.FanOut(w.f, nil, nil)
	if !errors.Is(err, ErrFanOutIncomplete) {
		t.Fatalf("FanOut = %v, want ErrFanOutIncomplete", err)
	}
	it := itemResult(res, foreign)
	if it == nil || it.State != FanOutFailed || !errors.Is(it.Err, ErrPlacement) {
		t.Fatalf("the foreign item: %+v", it)
	}
	if res.Count(FanOutFailed) != 1 || res.Count(FanOutUpdated) != 3 {
		t.Errorf("the others are still brought up to date: %+v", res.Items)
	}
	if writesTo(*sent, foreign) {
		t.Errorf("a write was sent for the foreign item: %v", *sent)
	}
	if after := latestBody(t, w.ada, foreign); after.Seq != before.Seq || len(after.Members) != 0 {
		t.Errorf("the foreign item's record changed: %+v", after)
	}
	wantStatus(t, w.bob, foreign, http.StatusNotFound)
	wantStatus(t, w.bob, w.item1, http.StatusOK)
}

// A folder the server lists under another folder is refused the same way, and
// the walk does not go into it.
func TestAHostileServerCannotListAForeignFolderUnderAFolder(t *testing.T) {
	w := newFolderTree(t)
	other, err := w.ada.CreateFolder("Other", "")
	if err != nil {
		t.Fatal(err)
	}
	inside := mustCreate(t, w.ada, "inside", InFolder(other.ID)).ID
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	hostile, sent := claiming(w.ada, map[string]string{other.ID: w.f, inside: other.ID})
	res, err := hostile.FanOut(w.f, nil, nil)
	if !errors.Is(err, ErrFanOutIncomplete) {
		t.Fatalf("FanOut = %v", err)
	}
	if it := itemResult(res, other.ID); it == nil || !errors.Is(it.Err, ErrPlacement) {
		t.Fatalf("the foreign folder: %+v", it)
	}
	if itemResult(res, inside) != nil || writesTo(*sent, other.ID) || writesTo(*sent, inside) {
		t.Errorf("the walk went into the foreign folder: %+v, %v", res.Items, *sent)
	}
	wantStatus(t, w.bob, other.ID, http.StatusNotFound)
}

// A server that rewrites the parent in an item's own view, to another folder
// of the caller's that lists someone else, does not get the item sealed to
// that folder's members either.
func TestAHostileServerCannotRewriteAnItemsParent(t *testing.T) {
	w := newFolderTree(t)
	h, err := w.ada.CreateFolder("Hostile", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(h.ID, "cat@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	before := latestBody(t, w.ada, w.item1)

	// The list still says item1 sits in the folder, as the walk reads it; the
	// item's own view says another.
	hostile, sent := claiming(w.ada, map[string]string{})
	hostile.HTTP.Transport = viewClaiming(hostile.HTTP.Transport, w.item1, h.ID)
	res, err := hostile.FanOut(w.f, nil, nil)
	if !errors.Is(err, ErrFanOutIncomplete) {
		t.Fatalf("FanOut = %v", err)
	}
	if it := itemResult(res, w.item1); it == nil || it.State != FanOutFailed || !errors.Is(it.Err, ErrPlacement) {
		t.Fatalf("item1: %+v", it)
	}
	if want := "cairn move " + w.item1 + " --to " + h.ID; !strings.Contains(itemResult(res, w.item1).Err.Error(), want) {
		t.Errorf("the message %q does not give the remedy %q", itemResult(res, w.item1).Err, want)
	}
	if writesTo(*sent, w.item1) {
		t.Errorf("a write was sent for item1: %v", *sent)
	}
	if after := latestBody(t, w.ada, w.item1); after.Seq != before.Seq {
		t.Errorf("item1's record changed: %+v", after)
	}
	wantStatus(t, w.cat, w.item1, http.StatusNotFound)
	wantStatus(t, w.bob, w.item1, http.StatusNotFound)
}

// viewClaiming wraps next so that GET of one artifact's own view says it sits
// in folder.
func viewClaiming(next http.RoundTripper, artifact, folder string) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := next.RoundTrip(r)
		if err != nil || r.Method != "GET" || r.URL.Path != "/api/artifacts/"+artifact || resp.StatusCode != 200 {
			return resp, err
		}
		var m map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			return nil, err
		}
		resp.Body.Close()
		m["parent"], m["inherit"] = folder, "pending"
		data, err := json.Marshal(m)
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		return resp, nil
	})
}

// Creating an item in a folder, and moving one into a folder, write the
// folder into the record; every record the client writes after that keeps it,
// whether the owner's or a manager's, and one that moves the item names the
// new folder.
func TestCreateAndMoveWriteTheFolderAndEveryRecordKeepsIt(t *testing.T) {
	w := newFolderTree(t)
	for id, want := range map[string]string{w.g: w.f, w.item1: w.f, w.item2: w.g, w.f: ""} {
		if got := latestBody(t, w.ada, id).Folder; got != want {
			t.Errorf("the first record of %s names %q, want %q", id, got, want)
		}
	}
	if got := latestBody(t, w.ada, mustCreate(t, w.ada, "top").ID).Folder; got != "" {
		t.Errorf("a top-level item names %q", got)
	}

	// Sharing a user, a next-epoch removal, a team share, and a manager's
	// record all keep the folder.
	if _, err := w.ada.Share(w.item1, "bob@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.Share(w.item1, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if b := latestBody(t, w.ada, w.item1); b.V != 2 || b.Folder != w.f {
		t.Errorf("a manager's record: v%d names %q", b.V, b.Folder)
	}
	if _, err := w.ada.Team(w.item1, "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Unshare(w.item1, "cat@example.com"); err != nil {
		t.Fatal(err)
	}
	if b := latestBody(t, w.ada, w.item1); b.Epoch != 2 || b.Folder != w.f {
		t.Errorf("a next-epoch record: epoch %d names %q", b.Epoch, b.Folder)
	}

	// A move, followed by its fan-out, names the new folder, then the top level.
	loose := mustCreate(t, w.ada, "loose").ID
	for _, to := range []string{w.g, w.f, ""} {
		if _, err := w.ada.Move(loose, to); err != nil {
			t.Fatal(err)
		}
		wantInherit(t, w.ada, loose, "pending")
		fanOutOK(t, w.ada, loose, &Placing{Parent: to})
		if got := latestBody(t, w.ada, loose).Folder; got != to {
			t.Errorf("after moving to %q the record names %q", to, got)
		}
		wantInherit(t, w.ada, loose, "ok")
	}
}

// After a move another client made, the item's record still names the old
// folder: a fan-out of the new folder refuses it, by ID, and writes nothing.
func TestAFanOutRefusesAnItemMovedByAnotherClientUntilItIsPlaced(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, nil)
	loose := mustCreate(t, w.ada, "loose").ID
	if _, err := w.ada.Move(loose, w.f); err != nil {
		t.Fatal(err)
	}
	before := latestBody(t, w.ada, loose)
	res, err := w.ada.FanOut(w.f, nil, nil)
	if !errors.Is(err, ErrFanOutIncomplete) {
		t.Fatalf("FanOut = %v", err)
	}
	if it := itemResult(res, loose); it == nil || !errors.Is(it.Err, ErrPlacement) {
		t.Fatalf("the moved item: %+v", it)
	}
	// The message says how its owner places it: a move by another client looks the same.
	if want := "cairn move " + loose + " --to " + w.f; !strings.Contains(itemResult(res, loose).Err.Error(), want) {
		t.Errorf("the message %q does not give the remedy %q", itemResult(res, loose).Err, want)
	}
	if after := latestBody(t, w.ada, loose); after.Seq != before.Seq {
		t.Errorf("a record was written: %+v", after)
	}
	wantStatus(t, w.bob, loose, http.StatusNotFound)
	// The client that moved it places it.
	fanOutOK(t, w.ada, loose, &Placing{Parent: w.f})
	wantEntry(t, w, loose, "bob@example.com", "viewer", w.f)
	wantStatus(t, w.bob, loose, http.StatusOK)
}

// An item moved while a fan-out is under way is never sealed to the folder it
// left: whether the move lands before the client reads the item or between the
// read and the write, which the server's own rule catches, nothing is written,
// and placing the item in its new folder afterwards works.
func TestAnItemMovedDuringAFanOutNeverGetsTheOldFoldersEntries(t *testing.T) {
	for _, trigger := range []struct {
		name   string
		method string
		path   func(w *folderTree) string
	}{
		{"before the client reads the item", "GET", func(w *folderTree) string { return "/api/artifacts/" + w.item1 }},
		{"between the read and the write", "PUT", func(w *folderTree) string { return "/api/artifacts/" + w.item1 + "/membership" }},
	} {
		t.Run(trigger.name, func(t *testing.T) {
			w := newFolderTree(t)
			h, err := w.ada.CreateFolder("Elsewhere", "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.ada.Share(w.f, "bob@example.com", "viewer", false); err != nil {
				t.Fatal(err)
			}
			racing := NewWithKey(w.ada.Host, *w.ada.Key)
			racing.Anchors = w.ada.Anchors
			moved := false
			racing.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if !moved && r.Method == trigger.method && r.URL.Path == trigger.path(w) {
					moved = true
					if _, err := w.ada.Move(w.item1, h.ID); err != nil {
						t.Error(err)
					}
				}
				return http.DefaultTransport.RoundTrip(r)
			})}
			res, err := racing.FanOut(w.f, nil, nil)
			if !errors.Is(err, ErrFanOutIncomplete) || !moved {
				t.Fatalf("FanOut = %v (moved %v)", err, moved)
			}
			if it := itemResult(res, w.item1); it == nil || it.State != FanOutFailed {
				t.Fatalf("item1: %+v", it)
			}
			if b := latestBody(t, w.ada, w.item1); b.Folder != w.f || len(b.Members) != 0 || b.Seq != 1 {
				t.Errorf("item1's record: %+v", b)
			}
			wantStatus(t, w.bob, w.item1, http.StatusNotFound)
			// The rest were brought up to date, and the moved item is placed.
			wantInherit(t, w.ada, w.item2, "ok")
			fanOutOK(t, w.ada, w.item1, &Placing{Parent: h.ID})
			if b := latestBody(t, w.ada, w.item1); b.Folder != h.ID || len(b.Members) != 0 {
				t.Errorf("item1 after it is placed: %+v", b)
			}
			wantInherit(t, w.ada, w.item1, "ok")
		})
	}
}

// Two managers fan out the same folder at once: the one that loses the race
// for an item gets the server's refusal for that item alone, and running the
// fan-out again leaves every record as the winner wrote it.
func TestTwoManagersFanningOutAtOnce(t *testing.T) {
	w := newFolderTree(t)
	for _, who := range []string{"bob@example.com", "cat@example.com"} {
		if _, err := w.ada.Share(w.f, who, "manager", false); err != nil {
			t.Fatal(err)
		}
	}
	fanOutOK(t, w.ada, w.f, nil)
	if _, err := w.ada.Share(w.f, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	before := map[string]int{}
	for _, id := range []string{w.g, w.item1, w.item2} {
		before[id] = latestBody(t, w.ada, id).Seq
	}

	// Cat's whole fan-out lands between bob's read of the folder G and his write.
	racing := NewWithKey(w.bob.Host, *w.bob.Key)
	racing.Anchors = w.bob.Anchors
	raced := false
	racing.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !raced && r.Method == "PUT" && r.URL.Path == "/api/artifacts/"+w.g+"/membership" {
			raced = true
			if _, err := w.cat.FanOut(w.f, nil, nil); err != nil {
				t.Error(err)
			}
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	res, err := racing.FanOut(w.f, nil, nil)
	if !errors.Is(err, ErrFanOutIncomplete) || !raced {
		t.Fatalf("bob's FanOut = %v (raced %v)", err, raced)
	}
	var api *APIError
	if it := itemResult(res, w.g); it == nil || it.State != FanOutFailed || !errors.As(it.Err, &api) || api.Status != http.StatusConflict {
		t.Fatalf("G: %+v", it)
	}
	if res.Count(FanOutFailed) != 1 {
		t.Errorf("only the item that lost fails: %+v", res.Items)
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		if b := latestBody(t, w.ada, id); b.Seq != before[id]+1 {
			t.Errorf("%s: seq %d, want %d: one record, cat's", id, b.Seq, before[id]+1)
		}
	}
	// Bob runs it again: nothing is left to write.
	again := fanOutOK(t, w.bob, w.f, nil)
	if again.Count(FanOutCurrent) != 3 {
		t.Errorf("the second run: %+v", again.Items)
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		b := latestBody(t, w.ada, id)
		if b.Seq != before[id]+1 || b.Signer != mustUserID(t, w.cat) {
			t.Errorf("%s: seq %d signer %s", id, b.Seq, b.Signer)
		}
		wantEntry(t, w, id, "dan@example.com", "viewer", w.f)
	}
}

func mustUserID(t *testing.T, c *Client) string {
	t.Helper()
	me, err := c.Me()
	if err != nil {
		t.Fatal(err)
	}
	return me.ID
}

// A three-level tree in which the middle folder lists the user directly too:
// when the top folder unshares them, the items under the middle folder keep
// them, and the folder's own direct entry is the one they name.
func TestAMiddleFolderThatListsTheUserDirectlyKeepsThemWhenTheTopUnshares(t *testing.T) {
	w := newFolderTree(t)
	top, err := w.ada.CreateFolder("Top", "")
	if err != nil {
		t.Fatal(err)
	}
	mid, err := w.ada.CreateFolder("Mid", top.ID)
	if err != nil {
		t.Fatal(err)
	}
	under := mustCreate(t, w.ada, "under", InFolder(mid.ID)).ID
	beside := mustCreate(t, w.ada, "beside", InFolder(top.ID)).ID

	// The middle folder lists bob directly, as a viewer, and the top lists him
	// as an editor.
	if _, err := w.ada.Share(mid.ID, "bob@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, mid.ID, nil)
	if _, err := w.ada.Share(top.ID, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.ada, top.ID, nil)
	if stateOf(res, mid.ID) != FanOutUpdated || stateOf(res, under) != FanOutUpdated || stateOf(res, beside) != FanOutUpdated {
		t.Fatalf("the top's fan-out: %+v", res.Items)
	}
	// The middle folder's entry stays direct, at the higher role. The item
	// under it names the middle folder, the nearest that lists bob itself.
	wantEntry(t, w, mid.ID, "bob@example.com", "editor", "")
	wantEntry(t, w, under, "bob@example.com", "editor", mid.ID)
	wantEntry(t, w, beside, "bob@example.com", "editor", top.ID)

	// The top folder unshares bob.
	if _, err := w.ada.Unshare(top.ID, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	res = fanOutOK(t, w.ada, top.ID, nil)
	want := map[string]string{mid.ID: FanOutCurrent, under: FanOutCurrent, beside: FanOutNewEpoch}
	for id, state := range want {
		if got := stateOf(res, id); got != state {
			t.Errorf("%s: %q, want %q", id, got, state)
		}
	}
	wantEntry(t, w, mid.ID, "bob@example.com", "editor", "")
	wantEntry(t, w, under, "bob@example.com", "editor", mid.ID)
	if entry(t, w, w.ada, beside, "bob@example.com") != nil {
		t.Errorf("the item beside the middle folder still lists bob")
	}
	for id, epoch := range map[string]int{mid.ID: 1, under: 1, beside: 2, top.ID: 2} {
		if b := latestBody(t, w.ada, id); b.Epoch != epoch {
			t.Errorf("%s is at epoch %d, want %d", id, b.Epoch, epoch)
		}
	}
	wantStatus(t, w.bob, mid.ID, http.StatusOK)
	wantStatus(t, w.bob, under, http.StatusOK)
	wantStatus(t, w.bob, beside, http.StatusNotFound)
	wantInherit(t, w.ada, under, "ok")

	// Then the middle folder unshares them, and the item under it follows.
	if _, err := w.ada.Unshare(mid.ID, "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, mid.ID, nil)
	wantStatus(t, w.bob, under, http.StatusNotFound)
	if b := latestBody(t, w.ada, under); b.Epoch != 2 || len(b.Members) != 0 {
		t.Errorf("under after the middle folder unshared: %+v", b)
	}
}

func disable(t *testing.T, w *folderTree, c *Client) {
	t.Helper()
	signupVerify(t, w.host, w.m, "admin@example.com", testPassword)
	admin := New(w.host, "")
	if _, err := admin.Login("admin@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	if err := admin.doJSON("PATCH", "/api/admin/users/"+mustUserID(t, c), map[string]any{"disabled": true}, nil); err != nil {
		t.Fatal(err)
	}
}

// A user disabled after the folder shared them is not required of an item:
// the items do not stay pending, a fan-out skips them and says so, and a new
// item in the folder is created without them.
func TestADisabledUserIsSkippedAndItemsDoNotStayPending(t *testing.T) {
	w := newFolderTree(t)
	for _, who := range []string{"dan@example.com", "cat@example.com"} {
		if _, err := w.ada.Share(w.f, who, "viewer", false); err != nil {
			t.Fatal(err)
		}
	}
	danID := mustUserID(t, w.dan)
	disable(t, w, w.dan)
	res := fanOutOK(t, w.ada, w.f, nil)
	if res.Count(FanOutUpdated) != 3 {
		t.Fatalf("result: %+v", res.Items)
	}
	// The folder's own items skip them; the item inside G follows G's record,
	// which does not list them.
	for _, it := range res.Items {
		want := []string{danID}
		if it.ID == w.item2 {
			want = nil
		}
		if !slices.Equal(it.SkippedUsers, want) || len(it.SkippedGroups) != 0 {
			t.Errorf("%s skipped %v %v, want %v", it.ID, it.SkippedUsers, it.SkippedGroups, want)
		}
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantEntry(t, w, id, "cat@example.com", "viewer", w.f)
		if m := entry(t, w, w.cat, id, "cat@example.com"); m == nil {
			t.Errorf("%s does not list cat", id)
		}
		for _, m := range latestBody(t, w.ada, id).Members {
			if m.User == danID {
				t.Errorf("%s lists the disabled user", id)
			}
		}
		wantInherit(t, w.ada, id, "ok")
	}
	// A new item skips them too, and the server accepts it.
	late := mustCreate(t, w.ada, "late", InFolder(w.f)).ID
	wantInherit(t, w.ada, late, "ok")
	wantEntry(t, w, late, "cat@example.com", "viewer", w.f)
}

// A user the folder shared who is disabled before any item lists them leaves
// nothing pending at all.
func TestADisabledUserLeavesNoItemPending(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	wantInherit(t, w.ada, w.item1, "pending")
	disable(t, w, w.dan)
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantInherit(t, w.ada, id, "ok")
	}
	res := fanOutOK(t, w.ada, w.f, nil)
	if res.Count(FanOutCurrent) != 3 {
		t.Errorf("result: %+v", res.Items)
	}
}

// A deleted group that a folder lists is not required of an item: an item that
// already lists it keeps it, with no new epoch, a new item is created without
// it, and the members view shows the entry as deleted, through the folder.
func TestADeletedGroupTheFolderListsIsNotRequiredAndShownAsDeleted(t *testing.T) {
	w := newFolderTree(t)
	v, err := w.ada.CreateGroup("Reviewers", []string{"cat@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.f, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, nil)
	if err := w.ada.DeleteGroup(v.ID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		wantInherit(t, w.ada, id, "ok")
	}
	res := fanOutOK(t, w.ada, w.f, nil)
	if res.Count(FanOutCurrent) != 3 {
		t.Errorf("a fan-out after the group was deleted: %+v", res.Items)
	}
	late := mustCreate(t, w.ada, "late", InFolder(w.f)).ID
	if b := latestBody(t, w.ada, late); len(b.Groups) != 0 || b.Folder != w.f {
		t.Errorf("an item created after the group was deleted: %+v", b)
	}
	wantInherit(t, w.ada, late, "ok")

	k := mustUnlock(t, w.ada)
	for _, id := range []string{w.f, w.item1} {
		va, err := w.ada.VerifyArtifact(k, id, "")
		if err != nil {
			t.Fatal(err)
		}
		groups, err := w.ada.ListedGroups(va)
		if err != nil || len(groups) != 1 || !groups[0].Deleted || groups[0].ID != v.ID {
			t.Fatalf("ListedGroups of %s = %+v, %v", id, groups, err)
		}
		if via := map[string]string{w.f: "", w.item1: w.f}[id]; groups[0].Via != via {
			t.Errorf("%s lists the deleted group via %q, want %q", id, groups[0].Via, via)
		}
	}
	if b := latestBody(t, w.ada, w.item1); b.Epoch != 1 || len(b.Groups) != 1 {
		t.Errorf("item1: epoch %d groups %+v", b.Epoch, b.Groups)
	}
}

// A fan-out that has another entry to add skips a deleted group the folder
// lists, and names it in the result.
func TestAFanOutSkipsADeletedGroupAndReportsIt(t *testing.T) {
	w := newFolderTree(t)
	v, err := w.ada.CreateGroup("Reviewers", []string{"cat@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.ShareGroup(w.f, "Reviewers", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Share(w.f, "dan@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if err := w.ada.DeleteGroup(v.ID); err != nil {
		t.Fatal(err)
	}
	res := fanOutOK(t, w.ada, w.f, nil)
	if res.Count(FanOutUpdated) != 3 {
		t.Fatalf("result: %+v", res.Items)
	}
	for _, it := range res.Items {
		want := []string{v.ID}
		if it.ID == w.item2 {
			want = nil // it follows G's record, which does not list the group
		}
		if !slices.Equal(it.SkippedGroups, want) || len(it.SkippedUsers) != 0 {
			t.Errorf("%s skipped %v %v, want groups %v", it.ID, it.SkippedUsers, it.SkippedGroups, want)
		}
	}
	for _, id := range []string{w.g, w.item1, w.item2} {
		if b := latestBody(t, w.ada, id); len(b.Groups) != 0 {
			t.Errorf("%s lists %+v", id, b.Groups)
		}
		wantEntry(t, w, id, "dan@example.com", "viewer", w.f)
		wantInherit(t, w.ada, id, "ok")
	}
}

// Moving is the owner's, so a manager's fan-out cannot place an item: the
// record would change the folder, which the chain rule refuses.
func TestAManagerCannotPlaceAnItem(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.item1, "bob@example.com", "manager", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.Move(w.item1, ""); err != nil {
		t.Fatal(err)
	}
	before := latestBody(t, w.ada, w.item1)
	res, err := w.bob.FanOut(w.item1, &Placing{}, nil)
	if err != nil {
		t.Fatalf("FanOut = %v", err)
	}
	if it := itemResult(res, w.item1); it == nil || it.State != FanOutWaits || it.OwnerEmail != "ada@example.com" || res.Count(FanOutFailed) != 0 {
		t.Fatalf("item1: %+v", it)
	}
	if after := latestBody(t, w.ada, w.item1); after.Seq != before.Seq {
		t.Errorf("a record was written: %+v", after)
	}
	fanOutOK(t, w.ada, w.item1, &Placing{})
	wantInherit(t, w.ada, w.item1, "ok")
}

// Accepting ownership keeps the item in its folder: the accepting record names
// it. Bob cannot read the folder, so his view says the item sits in one he
// cannot read. Ada owns the folder and gave the item away, so she is listed as
// its manager via the folder, nothing is pending, and she can still manage it.
func TestAcceptingKeepsAnItemInItsFolder(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.item1, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.OfferTransfer(w.item1, "bob@example.com", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.bob.AcceptTransfer(w.item1, AcceptTransferOptions{}); err != nil {
		t.Fatal(err)
	}
	b := latestBody(t, w.bob, w.item1)
	if b.Folder != w.f || b.Owner == "" {
		t.Errorf("the accepting record: %+v", b)
	}
	if m := memberOf(b, userID(t, w.ada)); m == nil || m.Role != "manager" || m.Via != w.f {
		t.Errorf("ada is %+v, want a manager via the folder", m)
	}
	got, err := w.bob.GetArtifact(w.item1)
	if err != nil || got.ParentID != "" || !got.HiddenParent || got.Inherit != "ok" {
		t.Errorf("the item after it was accepted: %+v, %v", got, err)
	}
	if got, err := w.ada.GetArtifact(w.item1); err != nil || got.ParentID != w.f {
		t.Errorf("ada's view: %+v, %v", got, err)
	}
	// She manages it still: a manager shares it.
	if _, err := w.ada.Share(w.item1, "cat@example.com", "viewer", false); err != nil {
		t.Errorf("ada shares the item: %v", err)
	}
}

// Dropping the previous owner is refused while they own the folder the item is
// in, before anything is written, and the offer stays open.
func TestDroppingTheFoldersOwnerOnAcceptIsRefused(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.item1, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ada.OfferTransfer(w.item1, "bob@example.com", false); err != nil {
		t.Fatal(err)
	}
	before := latestBody(t, w.bob, w.item1)
	_, err := w.bob.AcceptTransfer(w.item1, AcceptTransferOptions{DropPreviousOwner: true})
	if !errors.Is(err, ErrDropFolderOwner) || !strings.Contains(err.Error(), "move the item out of the folder first") {
		t.Fatalf("AcceptTransfer dropping the folder's owner: %v", err)
	}
	if after := latestBody(t, w.bob, w.item1); after.Seq != before.Seq {
		t.Errorf("a record was written: %+v", after)
	}
	if o, err := w.bob.OpenTransfer(w.item1); err != nil || o == nil {
		t.Errorf("the offer after the refusal: %+v, %v", o, err)
	}
}

// The remedy names the item and the folder it is listed in, or --top.
func TestPlacementErrorGivesTheMoveCommand(t *testing.T) {
	for _, c := range []struct{ listed, want string }{
		{"fold", "cairn move item --to fold"},
		{"", "cairn move item --top"},
	} {
		err := placementError("item", c.listed, "other")
		if !errors.Is(err, ErrPlacement) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("placementError(listed %q) = %v, want %q", c.listed, err, c.want)
		}
	}
}
