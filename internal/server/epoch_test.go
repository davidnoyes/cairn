package server

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// epochReq sends a request that declares an epoch in X-Cairn-Epoch (nothing
// is sent when declared is nil) and returns the status and body.
func epochReq(t *testing.T, c *testClient, method, path, ctype string, body []byte, declared *string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if declared != nil {
		req.Header.Set("X-Cairn-Epoch", *declared)
	}
	c.setHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func str(s string) *string { return &s }

// epochWrites maps each write route that declares an epoch in X-Cairn-Epoch
// to a function that issues one such write on version vid of artifact aid. A
// push or re-upload declares its epoch in its version part instead: see
// TestPushEpoch in upload_test.go.
func epochWrites(t *testing.T, c *testClient, aid, vid string) map[string]func(declared *string) (int, string) {
	vbase := "/api/artifacts/" + aid + "/versions"
	return map[string]func(*string) (int, string){
		"db exec": func(d *string) (int, string) {
			return epochReq(t, c, "POST", vbase+"/"+vid+"/db/query", "application/json",
				[]byte(`{"sql":"CREATE TABLE IF NOT EXISTS t (n INTEGER)"}`), d)
		},
		"db batch": func(d *string) (int, string) {
			return epochReq(t, c, "POST", vbase+"/"+vid+"/db/batch", "application/json",
				[]byte(`{"statements":[{"sql":"CREATE TABLE IF NOT EXISTS t (n INTEGER)"}]}`), d)
		},
		"file upload": func(d *string) (int, string) {
			return epochReq(t, c, "PUT", vbase+"/"+vid+"/files/a.txt", "", []byte("hi"), d)
		},
		"file delete": func(d *string) (int, string) {
			c.doRaw("PUT", vbase+"/"+vid+"/files/del.txt", []byte("x")).Body.Close()
			return epochReq(t, c, "DELETE", vbase+"/"+vid+"/files/del.txt", "", nil, d)
		},
	}
}

func TestDeclaredEpoch(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "epochs")
	o.apply(o.nextEpoch()) // epoch 2
	vid := pushVersion(t, a.testClient, o.id)

	for name, write := range epochWrites(t, a.testClient, o.id, vid) {
		t.Run(name, func(t *testing.T) {
			for _, ok := range []*string{nil, str("2")} {
				if code, body := write(ok); code >= 300 {
					t.Errorf("declared %v: %d %s, want success", ok, code, body)
				}
			}
			for _, stale := range []string{"1", "3"} {
				code, body := write(str(stale))
				if code != http.StatusConflict || !strings.Contains(body, "new epoch") {
					t.Errorf("declared %s: %d %s, want 409 naming a new epoch", stale, code, body)
				}
			}
			for _, bad := range []string{"0", "01", "-1", "x", "", "+2", "1.0", "2147483648", "99999999999999999999"} {
				if code, body := write(str(bad)); code != http.StatusBadRequest {
					t.Errorf("declared %q: %d %s, want 400", bad, code, body)
				}
			}
		})
	}
}

// A refused write leaves nothing behind: a push declaring epoch 1 fails once
// the artifact is at epoch 2, and no version, file, or table appears.
func TestStaleDeclaredEpochWritesNothing(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "epochs")
	vid := pushVersion(t, a.testClient, o.id)
	o.apply(o.nextEpoch()) // epoch 2; a writer still at 1 is stale
	w := epochWrites(t, a.testClient, o.id, vid)

	for _, name := range []string{"file upload", "db exec", "db batch"} {
		if code, _ := w[name](str("1")); code != http.StatusConflict {
			t.Fatalf("%s: %d, want 409", name, code)
		}
	}
	var versions []struct {
		Epoch int `json:"epoch"`
	}
	a.mustDo("GET", "/api/artifacts/"+o.id+"/versions", nil, &versions, http.StatusOK)
	if len(versions) != 1 || versions[0].Epoch != 1 {
		t.Errorf("versions after refused writes: %+v, want the one at epoch 1", versions)
	}
	var files []fileInfo
	a.mustDo("GET", fmt.Sprintf("/api/artifacts/%s/versions/%s/files", o.id, vid), nil, &files, http.StatusOK)
	if len(files) != 0 {
		t.Errorf("files after a refused upload: %+v", files)
	}
	code, body := epochReq(t, a.testClient, "POST", fmt.Sprintf("/api/artifacts/%s/versions/%s/db/query", o.id, vid),
		"application/json", []byte(`{"sql":"SELECT name FROM sqlite_master"}`), nil)
	if code != http.StatusOK || strings.Contains(body, `"t"`) {
		t.Errorf("database after refused writes: %d %s, want no table t", code, body)
	}
}

func TestDeclaredEpochTwiceIs400(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	o := newArtifact(t, a, "epochs")
	vid := pushVersion(t, a.testClient, o.id)
	req, err := http.NewRequest("POST", ts.URL+"/api/artifacts/"+o.id+"/versions/"+vid+"/db/query",
		strings.NewReader(`{"sql":"CREATE TABLE t (n INTEGER)"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("X-Cairn-Epoch", "1")
	req.Header.Add("X-Cairn-Epoch", "1")
	a.setHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("two epoch headers: %d, want 400", resp.StatusCode)
	}
}

// A query is not classified as a read or a write, so a caller who may not
// write is not held to the epoch they declare, and one who may write is.
func TestStaleEpochOnAQueryHoldsOnlyWriters(t *testing.T) {
	s, ts := testServer(t)
	a := seedKeyedAccount(t, s, ts.URL, "a@example.com")
	b := seedKeyedAccount(t, s, ts.URL, "b@example.com")
	o := newArtifact(t, a, "epochs")
	o.share("viewer", b)
	o.apply(o.nextEpoch())
	anon := anonWithLink(t, ts.URL, o.makePublic())
	vid := pushVersion(t, a.testClient, o.id)
	stale := str(fmt.Sprint(o.latest.Epoch - 1))
	path := "/api/artifacts/" + o.id + "/versions/" + vid + "/db/query"
	query := []byte(`{"sql":"SELECT 1"}`)
	for name, c := range map[string]*testClient{"viewer": b.testClient, "link holder": anon} {
		if code, body := epochReq(t, c, "POST", path, "application/json", query, stale); code != http.StatusOK {
			t.Errorf("%s with a stale epoch: %d %s, want 200", name, code, body)
		}
	}
	if code, body := epochReq(t, a.testClient, "POST", path, "application/json", query, stale); code != http.StatusConflict {
		t.Errorf("owner with a stale epoch: %d %s, want 409", code, body)
	}
}
