package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

// dataWorld is an owner with an artifact and one version that has no database
// and no files, on a server with small size caps.
type dataWorld struct {
	s     *Server
	base  string
	owner actor
	art   *owned
	vid   string
	vpath string // /api/artifacts/{id}/versions/{vid}
}

func newDataWorld(t *testing.T) *dataWorld {
	t.Helper()
	s, ts := newTestServer(t, func(c *Config) { c.MaxDBMB, c.MaxUploadMB = 1, 1 })
	w := &dataWorld{s: s, base: ts.URL}
	w.owner = seedKeyedAccount(t, s, ts.URL, "owner@example.com")
	w.art = newArtifact(t, w.owner, "data")
	w.vid = pushVersion(t, w.owner.testClient, w.art.id)
	w.vpath = "/api/artifacts/" + w.art.id + "/versions/" + w.vid
	return w
}

func (w *dataWorld) dbDir() string { return filepath.Join(w.s.cfg.DataDir, "dbs", w.art.id, w.vid) }
func (w *dataWorld) filesDir() string {
	return filepath.Join(w.s.cfg.DataDir, "files", w.art.id, w.vid)
}

// entries lists the names in dir, or nothing when it does not exist.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func status0(t *testing.T, resp *http.Response) int {
	t.Helper()
	resp.Body.Close()
	return resp.StatusCode
}

func TestDBRevisionRoundTrip(t *testing.T) {
	w := newDataWorld(t)
	dbPath := w.vpath + "/db"
	if got := status0(t, w.owner.doRaw("GET", dbPath, nil)); got != http.StatusNotFound {
		t.Fatalf("GET db with no database: %d, want 404", got)
	}
	q := newRevision(t, w.owner, w.art.id, w.vid, 1, 1, "first")
	resp := q.send(t)
	var out struct {
		Revision int `json:"revision"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || out.Revision != 1 || resp.Header.Get("ETag") != `"1"` {
		t.Fatalf("PUT db: %d %+v ETag %q", resp.StatusCode, out, resp.Header.Get("ETag"))
	}

	got := w.owner.doRaw("GET", dbPath, nil)
	body := readBody(t, got)
	if got.StatusCode != http.StatusOK || !bytes.Equal(body, q.blob) {
		t.Fatalf("GET db: %d, bytes equal %v", got.StatusCode, bytes.Equal(body, q.blob))
	}
	for k, want := range map[string]string{
		"ETag": `"1"`, "X-Cairn-Revision": "1", "X-Cairn-Epoch": "1",
		"Content-Type": "application/octet-stream", "Cache-Control": "no-store",
		"X-Cairn-Signer-Key": e2e.B64(w.owner.keys.epub), "X-Cairn-Record": e2e.B64(q.record(t)),
	} {
		if got.Header.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, got.Header.Get(k), want)
		}
	}

	req, _ := http.NewRequest("GET", w.base+dbPath, nil)
	req.Header.Set("If-None-Match", `"1"`)
	w.owner.setHeaders(req)
	cached, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := status0(t, cached); got != http.StatusNotModified {
		t.Errorf("If-None-Match naming the latest: %d, want 304", got)
	}

	one := w.owner.doRaw("GET", dbPath+"/revisions/1", nil)
	if b := readBody(t, one); one.StatusCode != http.StatusOK || !bytes.Equal(b, q.blob) {
		t.Errorf("GET revisions/1: %d", one.StatusCode)
	}
	for _, bad := range []string{"0", "2", "x", "-1", "01x"} {
		if got := status0(t, w.owner.doRaw("GET", dbPath+"/revisions/"+bad, nil)); got != http.StatusNotFound {
			t.Errorf("GET revisions/%s: %d, want 404", bad, got)
		}
	}
	var list []struct {
		Revision  int    `json:"revision"`
		Epoch     int    `json:"epoch"`
		Size      int    `json:"size"`
		WrittenBy string `json:"writtenBy"`
		CreatedAt string `json:"createdAt"`
	}
	w.owner.mustDo("GET", dbPath+"/revisions", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].Revision != 1 || list[0].Epoch != 1 || list[0].Size != len(q.blob) || list[0].WrittenBy != w.owner.id {
		t.Errorf("revisions: %+v", list)
	}
	if _, err := time.Parse(time.RFC3339, list[0].CreatedAt); err != nil {
		t.Errorf("createdAt %q: %v", list[0].CreatedAt, err)
	}
}

func TestDBPutPreconditions(t *testing.T) {
	w := newDataWorld(t)
	put := func(ifMatch string, rev int) *http.Response {
		q := newRevision(t, w.owner, w.art.id, w.vid, 1, rev, "r"+strconv.Itoa(rev))
		q.ifMatch = ifMatch
		return q.send(t)
	}
	for _, bad := range []string{"", "0", `W/"0"`, `"x"`, `"01"`, `"-1"`, `"0", "1"`, `""`, `"99999999999"`} {
		if got := status0(t, put(bad, 1)); got != http.StatusPreconditionRequired {
			t.Errorf("If-Match %q: %d, want 428", bad, got)
		}
	}
	// The version has no database, so "1" is stale.
	resp := put(`"1"`, 2)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed || resp.Header.Get("ETag") != `"0"` {
		t.Errorf("stale If-Match on an empty database: %d ETag %q, want 412 and \"0\"", resp.StatusCode, resp.Header.Get("ETag"))
	}
	if got := status0(t, put(`"0"`, 1)); got != http.StatusOK {
		t.Fatalf("first revision: %d", got)
	}
	// Revision 1 is the latest now: "0" is stale, and the 412 names it.
	resp = put(`"0"`, 1)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed || resp.Header.Get("ETag") != `"1"` {
		t.Errorf("stale If-Match: %d ETag %q, want 412 and \"1\"", resp.StatusCode, resp.Header.Get("ETag"))
	}
	resp = put(`"7"`, 8)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed || resp.Header.Get("ETag") != `"1"` {
		t.Errorf("If-Match ahead of the latest: %d ETag %q, want 412 and \"1\"", resp.StatusCode, resp.Header.Get("ETag"))
	}
	if got := w.owner.latestRevision(t, w.art.id, w.vid); got != 1 {
		t.Errorf("latest revision after the refusals: %d, want 1", got)
	}
}

// Two writes naming the same latest revision cannot both land.
func TestDBConcurrentPutsHaveOneWinner(t *testing.T) {
	w := newDataWorld(t)
	for round := 0; round < 8; round++ {
		var wg sync.WaitGroup
		codes := make([]int, 2)
		reqs := []*revisionRequest{
			newRevision(t, w.owner, w.art.id, w.vid, 1, round+1, "a"),
			newRevision(t, w.owner, w.art.id, w.vid, 1, round+1, "b"),
		}
		for i := range reqs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp := reqs[i].send(t)
				resp.Body.Close()
				codes[i] = resp.StatusCode
			}()
		}
		wg.Wait()
		sort.Ints(codes)
		if codes[0] != http.StatusOK || codes[1] != http.StatusPreconditionFailed {
			t.Fatalf("round %d: statuses %v, want one 200 and one 412", round, codes)
		}
		// The stored blob is one of the two, whole.
		got := readBody(t, w.owner.doRaw("GET", w.vpath+"/db", nil))
		if !bytes.Equal(got, reqs[0].blob) && !bytes.Equal(got, reqs[1].blob) {
			t.Fatalf("round %d: the stored revision is neither write", round)
		}
	}
	if names := entries(t, w.dbDir()); len(names) != 8 {
		t.Errorf("revision files after 8 rounds: %v, want 8 and no temp files", names)
	}
}

func TestDBPutRefusals(t *testing.T) {
	w := newDataWorld(t)
	other := seedKeyedAccount(t, w.s, w.base, "other@example.com")
	notBlob := bytes.Repeat([]byte{1}, 200)
	wrongPurpose := func(t *testing.T, q *revisionRequest) {
		q.recordPart = signedBody(t, q.a.keys.seed, q.a.id, "record", q.body)
	}
	unknownField := func(t *testing.T, q *revisionRequest) {
		q.recordPart = signedBody(t, q.a.keys.seed, q.a.id, "revision", map[string]any{
			"v": 1, "artifact": q.aid, "version": q.vid, "revision": 1, "epoch": 1, "sha256": q.body.SHA256, "extra": 1,
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, q *revisionRequest)
		want   int
	}{
		{"signer is not the caller", func(t *testing.T, q *revisionRequest) { q.signer = other.id }, http.StatusForbidden},
		{"signed under another key", func(t *testing.T, q *revisionRequest) { q.seed = other.keys.seed }, http.StatusForbidden},
		{"signed for another purpose", wrongPurpose, http.StatusForbidden},
		{"epoch is not current", func(t *testing.T, q *revisionRequest) { q.body.Epoch = 2 }, http.StatusConflict},
		{"epoch zero", func(t *testing.T, q *revisionRequest) { q.body.Epoch = 0 }, http.StatusConflict},
		{"another artifact", func(t *testing.T, q *revisionRequest) { q.body.Artifact = other.id }, http.StatusBadRequest},
		{"another version", func(t *testing.T, q *revisionRequest) { q.body.Version = other.id }, http.StatusBadRequest},
		{"revision is not latest plus one", func(t *testing.T, q *revisionRequest) { q.body.Revision = 2 }, http.StatusBadRequest},
		{"revision zero", func(t *testing.T, q *revisionRequest) { q.body.Revision = 0 }, http.StatusBadRequest},
		{"sha256 is not the blob's", func(t *testing.T, q *revisionRequest) { q.body.SHA256 = e2e.BodyHash([]byte("x")) }, http.StatusBadRequest},
		{"no blob header", func(t *testing.T, q *revisionRequest) { q.blob = notBlob; q.body.SHA256 = e2e.BodyHash(q.blob) }, http.StatusBadRequest},
		{"blob shorter than a blob", func(t *testing.T, q *revisionRequest) {
			q.blob = []byte("CRNB\x01")
			q.body.SHA256 = e2e.BodyHash(q.blob)
		}, http.StatusBadRequest},
		{"empty blob", func(t *testing.T, q *revisionRequest) { q.blob = nil }, http.StatusBadRequest},
		{"unknown field in the body", unknownField, http.StatusBadRequest},
		{"record is not JSON", func(t *testing.T, q *revisionRequest) { q.recordPart = []byte("nope") }, http.StatusBadRequest},
		{"record is empty", func(t *testing.T, q *revisionRequest) { q.recordPart = []byte{} }, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newRevision(t, w.owner, w.art.id, w.vid, 1, 1, "x")
			tc.mutate(t, q)
			resp := q.send(t)
			body := readBody(t, resp)
			if resp.StatusCode != tc.want {
				t.Errorf("status %d %s, want %d", resp.StatusCode, body, tc.want)
			}
		})
	}
	if got := w.owner.latestRevision(t, w.art.id, w.vid); got != 0 {
		t.Errorf("latest revision after the refusals: %d, want none", got)
	}
	if names := entries(t, w.dbDir()); len(names) != 0 {
		t.Errorf("dbs dir after the refusals: %v, want empty", names)
	}
}

func TestDBPutPartShape(t *testing.T) {
	w := newDataWorld(t)
	q := newRevision(t, w.owner, w.art.id, w.vid, 1, 1, "x")
	rec, blob := namedPart{"record", q.record(t)}, namedPart{"blob", q.blob}
	hdr := map[string]string{"If-Match": `"0"`}
	for name, parts := range map[string][]namedPart{
		"no parts":         {},
		"record only":      {rec},
		"blob only":        {blob},
		"blob first":       {blob, rec},
		"a third part":     {rec, blob, {"extra", []byte("x")}},
		"record twice":     {rec, rec, blob},
		"a misnamed part":  {rec, {"file", q.blob}},
		"a misnamed first": {{"version", q.record(t)}, blob},
	} {
		if got := status0(t, w.owner.sendParts("PUT", w.vpath+"/db", hdr, parts...)); got != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, got)
		}
	}
	// Not multipart at all.
	req, _ := http.NewRequest("PUT", w.base+w.vpath+"/db", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", `"0"`)
	w.owner.setHeaders(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if got := status0(t, resp); got != http.StatusBadRequest {
		t.Errorf("a JSON body: %d, want 400", got)
	}
	if got := w.owner.latestRevision(t, w.art.id, w.vid); got != 0 {
		t.Errorf("latest revision after the refusals: %d, want none", got)
	}
	if names := entries(t, w.dbDir()); len(names) != 0 {
		t.Errorf("dbs dir after the refusals: %v, want empty", names)
	}
}

// A blob over --max-db-mb is 413, and one at the cap is stored.
func TestDBPutSizeCap(t *testing.T) {
	w := newDataWorld(t) // MaxDBMB is 1
	// A sealed blob is 37 bytes of header, the plaintext, and 16 per chunk:
	// this plaintext seals to exactly 1 MiB.
	const atCap = 1<<20 - 37 - 16*16
	over := newRevision(t, w.owner, w.art.id, w.vid, 1, 1, strings.Repeat("x", atCap+1))
	if len(over.blob) != 1<<20+1 {
		t.Fatalf("test setup: blob is %d bytes", len(over.blob))
	}
	resp := over.send(t)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("a blob one byte over the cap: %d %s, want 413", resp.StatusCode, body)
	}
	if names := entries(t, w.dbDir()); len(names) != 0 {
		t.Errorf("dbs dir after a refused write: %v, want empty", names)
	}
	exact := newRevision(t, w.owner, w.art.id, w.vid, 1, 1, strings.Repeat("x", atCap))
	if len(exact.blob) != 1<<20 {
		t.Fatalf("test setup: blob is %d bytes", len(exact.blob))
	}
	if got := status0(t, exact.send(t)); got != http.StatusOK {
		t.Errorf("a blob at the cap: %d, want 200", got)
	}
	// A record over 64 KiB is 413 too.
	big := newRevision(t, w.owner, w.art.id, w.vid, 1, 2, "x")
	big.recordPart = bytes.Repeat([]byte{' '}, maxRecordBytes+1)
	if got := status0(t, big.send(t)); got != http.StatusRequestEntityTooLarge {
		t.Errorf("a record over 64 KiB: %d, want 413", got)
	}
}

func TestDBRetention(t *testing.T) {
	w := newDataWorld(t)
	var blobs [][]byte
	for rev := 1; rev <= 12; rev++ {
		q := newRevision(t, w.owner, w.art.id, w.vid, 1, rev, "rev "+strconv.Itoa(rev))
		blobs = append(blobs, q.blob)
		if got := status0(t, q.send(t)); got != http.StatusOK {
			t.Fatalf("revision %d: %d", rev, got)
		}
	}
	var list []struct {
		Revision int `json:"revision"`
	}
	w.owner.mustDo("GET", w.vpath+"/db/revisions", nil, &list, http.StatusOK)
	var got []int
	for _, r := range list {
		got = append(got, r.Revision)
	}
	want := []int{12, 11, 10, 9, 8, 7, 6, 5, 4, 3}
	if !equalInts(got, want) {
		t.Errorf("revisions kept: %v, want %v newest first", got, want)
	}
	if names := entries(t, w.dbDir()); !equalStrings(names, []string{"10", "11", "12", "3", "4", "5", "6", "7", "8", "9"}) {
		t.Errorf("revision files on disk: %v, want 3 to 12 only", names)
	}
	for _, rev := range []int{1, 2} {
		if got := status0(t, w.owner.doRaw("GET", w.vpath+"/db/revisions/"+strconv.Itoa(rev), nil)); got != http.StatusNotFound {
			t.Errorf("GET revisions/%d: %d, want 404", rev, got)
		}
	}
	three := w.owner.doRaw("GET", w.vpath+"/db/revisions/3", nil)
	if b := readBody(t, three); three.StatusCode != http.StatusOK || !bytes.Equal(b, blobs[2]) {
		t.Errorf("GET revisions/3: %d", three.StatusCode)
	}
	if latest := readBody(t, w.owner.doRaw("GET", w.vpath+"/db", nil)); !bytes.Equal(latest, blobs[11]) {
		t.Error("the latest revision is not revision 12")
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A key a user replaced no longer signs for them.
func TestDBPutSignedByAnOldKey(t *testing.T) {
	w := newDataWorld(t)
	hash, err := auth.HashPassword(string(testAuthKey("owner@example.com-password")))
	if err != nil {
		t.Fatal(err)
	}
	newKeys := newUserKeys(t)
	if err := w.s.store.ResetAccount(w.owner.id, hash, bundleFor(t, newKeys), time.Now()); err != nil {
		t.Fatal(err)
	}
	relogged := actor{testClient: login(t, w.base, "owner@example.com", "owner@example.com-password"), id: w.owner.id, email: w.owner.email, keys: newKeys}
	old := newRevision(t, w.owner, w.art.id, w.vid, 1, 1, "old key") // signed by the old seed, sent as the owner
	old.a = relogged
	old.seed = w.owner.keys.seed
	if got := status0(t, old.send(t)); got != http.StatusForbidden {
		t.Errorf("a revision signed by the old key: %d, want 403", got)
	}
	fresh := newRevision(t, relogged, w.art.id, w.vid, 1, 1, "new key")
	if got := status0(t, fresh.send(t)); got != http.StatusOK {
		t.Errorf("a revision signed by the new key: %d, want 200", got)
	}
	got := relogged.doRaw("GET", w.vpath+"/db", nil)
	got.Body.Close()
	if got.Header.Get("X-Cairn-Signer-Key") != e2e.B64(newKeys.epub) {
		t.Error("X-Cairn-Signer-Key is not the key the server verified under")
	}
}

func TestDataWriteAccess(t *testing.T) {
	w := newDataWorld(t)
	viewer := seedKeyedAccount(t, w.s, w.base, "viewer@example.com")
	editor := seedKeyedAccount(t, w.s, w.base, "editor@example.com")
	w.art.share("viewer", viewer)
	w.art.share("editor", editor)
	w.owner.mustWriteDB(t, w.art.id, w.vid)
	addr := w.owner.mustWriteFile(t, w.art.id, w.vid, "a.txt", "hi")

	// A viewer reads and cannot write or delete.
	viewer.mustDo("GET", w.vpath+"/db", nil, nil, http.StatusOK)
	viewer.mustDo("GET", w.vpath+"/db/revisions", nil, nil, http.StatusOK)
	viewer.mustDo("GET", w.vpath+"/files", nil, nil, http.StatusOK)
	if got := status0(t, viewer.doRaw("GET", w.vpath+"/files/"+addr, nil)); got != http.StatusOK {
		t.Errorf("viewer file read: %d", got)
	}
	if got := status0(t, viewer.writeDB(t, w.art.id, w.vid)); got != http.StatusForbidden {
		t.Errorf("viewer db write: %d, want 403", got)
	}
	if got := status0(t, viewer.writeFile(t, w.art.id, w.vid, "v.txt", "x")); got != http.StatusForbidden {
		t.Errorf("viewer file write: %d, want 403", got)
	}
	if got := status0(t, viewer.doRaw("DELETE", w.vpath+"/files/"+addr, nil)); got != http.StatusForbidden {
		t.Errorf("viewer file delete: %d, want 403", got)
	}

	// An editor writes.
	editor.mustWriteDB(t, w.art.id, w.vid)
	editor.mustWriteFile(t, w.art.id, w.vid, "e.txt", "x")

	// Removed by a record at the next epoch, they find nothing.
	next := w.art.nextEpoch()
	next.Members = nil
	for _, m := range w.art.latest.Members {
		if m.User != editor.id {
			next.Members = append(next.Members, m)
		}
	}
	next.Excluded = []e2e.ExcludedEntry{{User: editor.id, FP: editor.keys.fp(), Email: e2e.NormalizeEmail(editor.email)}}
	w.art.apply(next)
	q := newRevision(t, editor, w.art.id, w.vid, 2, 3, "after removal")
	if got := status0(t, q.send(t)); got != http.StatusNotFound {
		t.Errorf("removed editor db write: %d, want 404", got)
	}
	f := newFile(t, editor, w.art.id, w.vid, 2, "late.txt", "x")
	if got := status0(t, f.send(t)); got != http.StatusNotFound {
		t.Errorf("removed editor file write: %d, want 404", got)
	}
	if got := status0(t, editor.doRaw("GET", w.vpath+"/db", nil)); got != http.StatusNotFound {
		t.Errorf("removed editor db read: %d, want 404", got)
	}
	if got := w.owner.latestRevision(t, w.art.id, w.vid); got != 2 {
		t.Errorf("latest revision after the removed editor's attempts: %d, want 2", got)
	}
}

func TestPublicLinkReadsDataButCannotWrite(t *testing.T) {
	w := newDataWorld(t)
	w.owner.mustWriteDB(t, w.art.id, w.vid)
	addr := w.owner.mustWriteFile(t, w.art.id, w.vid, "a.txt", "hi")
	anon := anonWithLink(t, w.base, w.art.makePublic())
	for _, p := range []string{"/db", "/db/revisions", "/db/revisions/1", "/files", "/files/" + addr} {
		if got := status0(t, anon.doRaw("GET", w.vpath+p, nil)); got != http.StatusOK {
			t.Errorf("anonymous GET %s: %d, want 200", p, got)
		}
	}
	// A body type the CSRF check lets through, so the refusal is the access check's.
	for method, p := range map[string]string{"PUT": "/db", "DELETE": "/files/" + addr} {
		req, _ := http.NewRequest(method, w.base+w.vpath+p, strings.NewReader("x"))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("If-Match", `"1"`)
		anon.setHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if got := status0(t, resp); got != http.StatusForbidden {
			t.Errorf("anonymous %s %s: %d, want 403", method, p, got)
		}
	}
	if got := w.owner.latestRevision(t, w.art.id, w.vid); got != 1 {
		t.Errorf("latest revision: %d, want 1", got)
	}
}

// A write sealed under a past epoch leaves nothing behind.
func TestStaleEpochWritesNothing(t *testing.T) {
	w := newDataWorld(t)
	w.art.apply(w.art.nextEpoch()) // epoch 2
	stale := newRevision(t, w.owner, w.art.id, w.vid, 1, 1, "stale")
	if got := status0(t, stale.send(t)); got != http.StatusConflict {
		t.Errorf("revision at a past epoch: %d, want 409", got)
	}
	staleFile := newFile(t, w.owner, w.art.id, w.vid, 1, "a.txt", "stale")
	if got := status0(t, staleFile.send(t)); got != http.StatusConflict {
		t.Errorf("file at a past epoch: %d, want 409", got)
	}
	if got := w.owner.latestRevision(t, w.art.id, w.vid); got != 0 {
		t.Errorf("latest revision: %d, want none", got)
	}
	var files []json.RawMessage
	w.owner.mustDo("GET", w.vpath+"/files", nil, &files, http.StatusOK)
	if len(files) != 0 {
		t.Errorf("files after a refused write: %d, want none", len(files))
	}
	if len(entries(t, w.dbDir()))+len(entries(t, w.filesDir())) != 0 {
		t.Error("a refused write left files on disk")
	}
	if got := status0(t, newRevision(t, w.owner, w.art.id, w.vid, 2, 1, "current").send(t)); got != http.StatusOK {
		t.Errorf("revision at the current epoch: %d, want 200", got)
	}
}

func TestUnknownVersionAndArtifact(t *testing.T) {
	w := newDataWorld(t)
	ghost := "/api/artifacts/" + w.art.id + "/versions/00000000-0000-0000-0000-000000000000"
	q := newRevision(t, w.owner, w.art.id, w.vid, 1, 1, "x")
	for method, p := range map[string]string{"GET": "/db", "PUT": "/db"} {
		resp := w.owner.sendParts(method, ghost+p, map[string]string{"If-Match": `"0"`}, namedPart{"record", q.record(t)}, namedPart{"blob", q.blob})
		if got := status0(t, resp); got != http.StatusNotFound {
			t.Errorf("%s db of an unknown version: %d, want 404", method, got)
		}
	}
	for _, p := range []string{"/db/revisions", "/files", "/files/" + strings.Repeat("a", 64)} {
		if got := status0(t, w.owner.doRaw("GET", ghost+p, nil)); got != http.StatusNotFound {
			t.Errorf("GET %s of an unknown version: %d, want 404", p, got)
		}
	}
}

// Files

func TestStoredFileRoundTrip(t *testing.T) {
	w := newDataWorld(t)
	var list []struct {
		Address    string          `json:"address"`
		Epoch      int             `json:"epoch"`
		Size       int             `json:"size"`
		UpdatedAt  string          `json:"updatedAt"`
		Record     json.RawMessage `json:"record"`
		Meta       string          `json:"meta"`
		MetaRecord json.RawMessage `json:"metaRecord"`
		SignerKey  string          `json:"signerKey"`
	}
	w.owner.mustDo("GET", w.vpath+"/files", nil, &list, http.StatusOK)
	if list == nil || len(list) != 0 {
		t.Fatalf("a version with no files lists %v, want []", list)
	}

	q := newFile(t, w.owner, w.art.id, w.vid, 1, "notes/hello.txt", "hello file")
	resp := q.send(t)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT file: %d", resp.StatusCode)
	}
	w.owner.mustDo("GET", w.vpath+"/files", nil, &list, http.StatusOK)
	if len(list) != 1 {
		t.Fatalf("files: %+v", list)
	}
	rec, metaRec := q.records(t)
	var gotRec, wantRec, gotMeta, wantMeta e2e.Envelope
	for _, c := range []struct {
		raw  []byte
		into *e2e.Envelope
	}{{list[0].Record, &gotRec}, {rec, &wantRec}, {list[0].MetaRecord, &gotMeta}, {metaRec, &wantMeta}} {
		if err := json.Unmarshal(c.raw, c.into); err != nil {
			t.Fatal(err)
		}
	}
	meta, err := e2e.UnB64(list[0].Meta)
	if err != nil {
		t.Fatal(err)
	}
	f := list[0]
	if f.Address != q.address || f.Epoch != 1 || f.Size != len(q.blob) || !bytes.Equal(meta, q.metaBl) ||
		f.SignerKey != e2e.B64(w.owner.keys.epub) || !bytes.Equal(gotRec.Body, wantRec.Body) || !bytes.Equal(gotMeta.Body, wantMeta.Body) ||
		gotRec.Signer != w.owner.id || !gotRec.Verify(w.owner.keys.epub, "record") || !gotMeta.Verify(w.owner.keys.epub, "record") {
		t.Errorf("listing %+v does not match what was stored", f)
	}
	if _, err := time.Parse(time.RFC3339, f.UpdatedAt); err != nil {
		t.Errorf("updatedAt %q: %v", f.UpdatedAt, err)
	}

	got := w.owner.doRaw("GET", w.vpath+"/files/"+q.address, nil)
	body := readBody(t, got)
	if got.StatusCode != http.StatusOK || !bytes.Equal(body, q.blob) {
		t.Fatalf("GET file: %d, bytes equal %v", got.StatusCode, bytes.Equal(body, q.blob))
	}
	for k, want := range map[string]string{
		"Content-Type": "application/octet-stream", "Cache-Control": "no-store", "X-Cairn-Epoch": "1",
		"X-Cairn-Signer-Key": e2e.B64(w.owner.keys.epub), "X-Cairn-Record": e2e.B64(rec),
	} {
		if got.Header.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, got.Header.Get(k), want)
		}
	}

	// A replacement swaps the file in whole.
	again := newFile(t, w.owner, w.art.id, w.vid, 1, "notes/hello.txt", "a longer replacement")
	if got := status0(t, again.send(t)); got != http.StatusOK {
		t.Fatalf("replacement: %d", got)
	}
	if body := readBody(t, w.owner.doRaw("GET", w.vpath+"/files/"+q.address, nil)); !bytes.Equal(body, again.blob) {
		t.Error("GET after a replacement does not return the new file")
	}
	w.owner.mustDo("GET", w.vpath+"/files", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].Size != len(again.blob) {
		t.Errorf("listing after a replacement: %+v", list)
	}
	if names := entries(t, w.filesDir()); !equalStrings(names, []string{q.address}) {
		t.Errorf("files on disk after a replacement: %v, want the one file and no temp files", names)
	}

	// Delete.
	if got := status0(t, w.owner.doRaw("DELETE", w.vpath+"/files/"+q.address, nil)); got != http.StatusNoContent {
		t.Errorf("DELETE: %d, want 204", got)
	}
	if got := status0(t, w.owner.doRaw("GET", w.vpath+"/files/"+q.address, nil)); got != http.StatusNotFound {
		t.Errorf("GET after delete: %d, want 404", got)
	}
	if got := status0(t, w.owner.doRaw("DELETE", w.vpath+"/files/"+q.address, nil)); got != http.StatusNotFound {
		t.Errorf("second DELETE: %d, want 404", got)
	}
	if names := entries(t, w.filesDir()); len(names) != 0 {
		t.Errorf("files on disk after delete: %v, want none", names)
	}
	w.owner.mustDo("GET", w.vpath+"/files", nil, &list, http.StatusOK)
	if len(list) != 0 {
		t.Errorf("listing after delete: %+v", list)
	}
}

func TestStoredFileAddressMustBeLowercaseHex(t *testing.T) {
	w := newDataWorld(t)
	good := w.owner.mustWriteFile(t, w.art.id, w.vid, "a.txt", "hi")
	for name, addr := range map[string]string{
		"uppercase": strings.ToUpper(good),
		"short":     good[:63],
		"long":      good + "0",
		"not hex":   strings.Repeat("g", 64),
		"one char":  "x",
	} {
		for _, method := range []string{"GET", "DELETE"} {
			if got := status0(t, w.owner.doRaw(method, w.vpath+"/files/"+addr, nil)); got != http.StatusNotFound {
				t.Errorf("%s %s address: %d, want 404", method, name, got)
			}
		}
		q := newFile(t, w.owner, w.art.id, w.vid, 1, "a.txt", "hi")
		q.address = addr
		if got := status0(t, q.send(t)); got != http.StatusNotFound {
			t.Errorf("PUT %s address: %d, want 404", name, got)
		}
	}
	if names := entries(t, w.filesDir()); !equalStrings(names, []string{good}) {
		t.Errorf("files on disk: %v, want only %s", names, good)
	}
}

func TestStoredFilePutRefusals(t *testing.T) {
	w := newDataWorld(t)
	other := seedKeyedAccount(t, w.s, w.base, "other@example.com")
	notBlob := bytes.Repeat([]byte{1}, 200)
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, q *fileRequest)
		want   int
	}{
		{"record signer is not the caller", func(t *testing.T, q *fileRequest) { q.signer = other.id }, http.StatusForbidden},
		{"records signed under another key", func(t *testing.T, q *fileRequest) { q.seed = other.keys.seed }, http.StatusForbidden},
		{"metaRecord signed under another key", func(t *testing.T, q *fileRequest) {
			q.metaRecordPart = signedBody(t, other.keys.seed, w.owner.id, "record", q.meta)
		}, http.StatusForbidden},
		{"metaRecord signer is not the caller", func(t *testing.T, q *fileRequest) {
			q.metaRecordPart = signedBody(t, w.owner.keys.seed, other.id, "record", q.meta)
		}, http.StatusForbidden},
		{"record signed for another purpose", func(t *testing.T, q *fileRequest) {
			q.recordPart = signedBody(t, w.owner.keys.seed, w.owner.id, "revision", q.body)
		}, http.StatusForbidden},
		{"record epoch is not current", func(t *testing.T, q *fileRequest) { q.body.Epoch = 2 }, http.StatusConflict},
		{"both epochs are not current", func(t *testing.T, q *fileRequest) { q.body.Epoch, q.meta.Epoch = 2, 2 }, http.StatusConflict},
		{"metaRecord epoch is not current", func(t *testing.T, q *fileRequest) { q.meta.Epoch = 2 }, http.StatusConflict},
		{"record names another artifact", func(t *testing.T, q *fileRequest) { q.body.Artifact = other.id }, http.StatusBadRequest},
		{"metaRecord names another artifact", func(t *testing.T, q *fileRequest) { q.meta.Artifact = other.id }, http.StatusBadRequest},
		{"record names another version", func(t *testing.T, q *fileRequest) { q.body.Version = other.id }, http.StatusBadRequest},
		{"metaRecord names another version", func(t *testing.T, q *fileRequest) { q.meta.Version = other.id }, http.StatusBadRequest},
		{"record kind is not file", func(t *testing.T, q *fileRequest) { q.body.Kind = "file-meta" }, http.StatusBadRequest},
		{"record kind is content", func(t *testing.T, q *fileRequest) { q.body.Kind = "content" }, http.StatusBadRequest},
		{"metaRecord kind is not file-meta", func(t *testing.T, q *fileRequest) { q.meta.Kind = "file" }, http.StatusBadRequest},
		{"record name is not the address", func(t *testing.T, q *fileRequest) { q.body.Name = strings.Repeat("0", 64) }, http.StatusBadRequest},
		{"metaRecord name is not the address", func(t *testing.T, q *fileRequest) { q.meta.Name = strings.Repeat("0", 64) }, http.StatusBadRequest},
		{"record sha256 is not the blob's", func(t *testing.T, q *fileRequest) { q.body.SHA256 = e2e.BodyHash([]byte("x")) }, http.StatusBadRequest},
		{"metaRecord sha256 is not the meta's", func(t *testing.T, q *fileRequest) { q.meta.SHA256 = e2e.BodyHash([]byte("x")) }, http.StatusBadRequest},
		{"metaRecord sha256 is the file's", func(t *testing.T, q *fileRequest) { q.meta.SHA256 = q.body.SHA256 }, http.StatusBadRequest},
		{"blob has no header", func(t *testing.T, q *fileRequest) { q.blob = notBlob; q.body.SHA256 = e2e.BodyHash(q.blob) }, http.StatusBadRequest},
		{"blob is shorter than a blob", func(t *testing.T, q *fileRequest) { q.blob = []byte("CRNB\x01"); q.body.SHA256 = e2e.BodyHash(q.blob) }, http.StatusBadRequest},
		{"meta has no header", func(t *testing.T, q *fileRequest) { q.metaBl = notBlob; q.meta.SHA256 = e2e.BodyHash(q.metaBl) }, http.StatusBadRequest},
		{"meta is shorter than a blob", func(t *testing.T, q *fileRequest) {
			q.metaBl = []byte("CRNB\x01")
			q.meta.SHA256 = e2e.BodyHash(q.metaBl)
		}, http.StatusBadRequest},
		{"meta is over 4 KiB", func(t *testing.T, q *fileRequest) {
			q.metaBl = sealFor(t, q.aid, q.vid, "file-meta", q.address, 1, bytes.Repeat([]byte{'m'}, maxMetaBytes))
			q.meta.SHA256 = e2e.BodyHash(q.metaBl)
		}, http.StatusRequestEntityTooLarge},
		{"record is not JSON", func(t *testing.T, q *fileRequest) { q.recordPart = []byte("nope") }, http.StatusBadRequest},
		{"metaRecord is not JSON", func(t *testing.T, q *fileRequest) { q.metaRecordPart = []byte("nope") }, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newFile(t, w.owner, w.art.id, w.vid, 1, "a.txt", "hi")
			tc.mutate(t, q)
			resp := q.send(t)
			body := readBody(t, resp)
			if resp.StatusCode != tc.want {
				t.Errorf("status %d %s, want %d", resp.StatusCode, body, tc.want)
			}
		})
	}
	var list []json.RawMessage
	w.owner.mustDo("GET", w.vpath+"/files", nil, &list, http.StatusOK)
	if len(list) != 0 {
		t.Errorf("files after the refusals: %d, want none", len(list))
	}
	if names := entries(t, w.filesDir()); len(names) != 0 {
		t.Errorf("files dir after the refusals: %v, want empty", names)
	}
}

// A refused replacement leaves the old file alone.
func TestRefusedReplacementKeepsTheFile(t *testing.T) {
	w := newDataWorld(t)
	first := newFile(t, w.owner, w.art.id, w.vid, 1, "a.txt", "keep me")
	if got := status0(t, first.send(t)); got != http.StatusOK {
		t.Fatalf("PUT: %d", got)
	}
	bad := newFile(t, w.owner, w.art.id, w.vid, 1, "a.txt", "replacement")
	bad.body.SHA256 = e2e.BodyHash([]byte("x"))
	if got := status0(t, bad.send(t)); got != http.StatusBadRequest {
		t.Fatalf("refused replacement: %d, want 400", got)
	}
	if body := readBody(t, w.owner.doRaw("GET", w.vpath+"/files/"+first.address, nil)); !bytes.Equal(body, first.blob) {
		t.Error("the file changed after a refused replacement")
	}
	if names := entries(t, w.filesDir()); !equalStrings(names, []string{first.address}) {
		t.Errorf("files dir: %v", names)
	}
}

func TestStoredFilePutPartShapeAndSize(t *testing.T) {
	w := newDataWorld(t) // MaxUploadMB is 1
	q := newFile(t, w.owner, w.art.id, w.vid, 1, "a.txt", "hi")
	rec, metaRec := q.records(t)
	r, b, mr, m := namedPart{"record", rec}, namedPart{"blob", q.blob}, namedPart{"metaRecord", metaRec}, namedPart{"meta", q.metaBl}
	for name, parts := range map[string][]namedPart{
		"no parts":               {},
		"record and blob only":   {r, b},
		"missing meta":           {r, b, mr},
		"out of order":           {r, mr, b, m},
		"meta before metaRecord": {r, b, m, mr},
		"a fifth part":           {r, b, mr, m, {"extra", []byte("x")}},
	} {
		if got := status0(t, w.owner.sendParts("PUT", q.path(), nil, parts...)); got != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, got)
		}
	}
	// 1 MiB is the cap: this plaintext seals to one byte over it.
	const atCap = 1<<20 - 37 - 16*16
	over := newFile(t, w.owner, w.art.id, w.vid, 1, "big.bin", strings.Repeat("x", atCap+1))
	if got := status0(t, over.send(t)); got != http.StatusRequestEntityTooLarge {
		t.Errorf("a file blob one byte over the cap: %d, want 413", got)
	}
	exact := newFile(t, w.owner, w.art.id, w.vid, 1, "big.bin", strings.Repeat("x", atCap))
	if got := status0(t, exact.send(t)); got != http.StatusOK {
		t.Errorf("a file blob at the cap: %d, want 200", got)
	}
	big := newFile(t, w.owner, w.art.id, w.vid, 1, "rec.bin", "x")
	big.recordPart = bytes.Repeat([]byte{' '}, maxRecordBytes+1)
	if got := status0(t, big.send(t)); got != http.StatusRequestEntityTooLarge {
		t.Errorf("a record over 64 KiB: %d, want 413", got)
	}
	big = newFile(t, w.owner, w.art.id, w.vid, 1, "rec2.bin", "x")
	big.metaRecordPart = bytes.Repeat([]byte{' '}, maxRecordBytes+1)
	if got := status0(t, big.send(t)); got != http.StatusRequestEntityTooLarge {
		t.Errorf("a metaRecord over 64 KiB: %d, want 413", got)
	}
	if names := entries(t, w.filesDir()); len(names) != 1 {
		t.Errorf("files dir: %v, want only the one file at the cap", names)
	}
}

// The server never receives a path in the clear, so none may appear anywhere
// under the data directory, not in the metadata database either.
func TestNoFilePathIsStored(t *testing.T) {
	w := newDataWorld(t)
	const path = "private/folder/very-secret-name.txt"
	addr := w.owner.mustWriteFile(t, w.art.id, w.vid, path, "contents")
	w.owner.mustWriteDB(t, w.art.id, w.vid)
	if err := w.s.store.DB().QueryRow(`PRAGMA wal_checkpoint(PASSIVE)`).Scan(new(int), new(int), new(int)); err != nil {
		t.Fatal(err)
	}
	foundAddress, scanned := false, 0
	err := filepath.WalkDir(w.s.cfg.DataDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.Contains(p, "very-secret") || strings.Contains(p, "private") {
			t.Errorf("a file name holds the path: %s", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		scanned++
		for _, needle := range []string{path, "very-secret-name", "private/folder"} {
			if bytes.Contains(b, []byte(needle)) {
				t.Errorf("%s holds the path %q", p, needle)
			}
		}
		if filepath.Base(p) == "cairn.db" && bytes.Contains(b, []byte(addr)) {
			foundAddress = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !foundAddress {
		t.Error("the scan did not find the file's address in cairn.db, so it is not reading what the server stores")
	}
	if scanned < 4 {
		t.Errorf("scanned only %d files", scanned)
	}
}

func TestDeletingAVersionRemovesItsData(t *testing.T) {
	w := newDataWorld(t)
	other := pushVersion(t, w.owner.testClient, w.art.id)
	w.owner.mustWriteDB(t, w.art.id, w.vid)
	w.owner.mustWriteDB(t, w.art.id, w.vid)
	w.owner.mustWriteFile(t, w.art.id, w.vid, "a.txt", "hi")
	w.owner.mustWriteDB(t, w.art.id, other)
	w.owner.mustWriteFile(t, w.art.id, other, "a.txt", "hi")
	if len(entries(t, w.dbDir())) != 2 || len(entries(t, w.filesDir())) != 1 {
		t.Fatal("test setup: the data is not on disk")
	}
	for _, v := range []string{w.vid, other} {
		if files, _ := w.s.store.ListStoredFiles(w.art.id, v); len(files) != 1 {
			t.Fatalf("test setup: version %s has %d file rows, want 1", v, len(files))
		}
	}

	w.owner.mustDo("DELETE", w.vpath, nil, nil, http.StatusOK)
	if _, err := os.Stat(w.dbDir()); !os.IsNotExist(err) {
		t.Errorf("the version's db dir survives: %v", err)
	}
	if _, err := os.Stat(w.filesDir()); !os.IsNotExist(err) {
		t.Errorf("the version's files dir survives: %v", err)
	}
	if revs, _ := w.s.store.ListDBRevisions(w.art.id, w.vid); len(revs) != 0 {
		t.Errorf("revision rows survive: %d", len(revs))
	}
	if files, _ := w.s.store.ListStoredFiles(w.art.id, w.vid); len(files) != 0 {
		t.Errorf("file rows survive: %d", len(files))
	}
	// The other version's data is untouched.
	otherDB := filepath.Join(w.s.cfg.DataDir, "dbs", w.art.id, other)
	otherFiles := filepath.Join(w.s.cfg.DataDir, "files", w.art.id, other)
	if len(entries(t, otherDB)) != 1 || len(entries(t, otherFiles)) != 1 {
		t.Error("deleting a version removed another version's data")
	}
	if revs, _ := w.s.store.ListDBRevisions(w.art.id, other); len(revs) != 1 {
		t.Errorf("the other version's revision rows: %d, want 1", len(revs))
	}

	w.owner.mustDo("DELETE", "/api/artifacts/"+w.art.id, nil, nil, http.StatusOK)
	for _, dir := range []string{
		filepath.Join(w.s.cfg.DataDir, "dbs", w.art.id), filepath.Join(w.s.cfg.DataDir, "files", w.art.id),
	} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s survives the artifact: %v", dir, err)
		}
	}
	var n int
	for _, table := range []string{"db_revisions", "stored_files"} {
		if err := w.s.store.DB().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s rows after the artifact is deleted: %d, %v", table, n, err)
		}
	}
}

func TestContentTokenAllowsTheDataRoutesAndNotTheOldOnes(t *testing.T) {
	for _, p := range []string{
		"GET /api/artifacts/{id}/versions/{vid}/db",
		"PUT /api/artifacts/{id}/versions/{vid}/db",
		"GET /api/artifacts/{id}/versions/{vid}/db/revisions",
		"GET /api/artifacts/{id}/versions/{vid}/db/revisions/{rev}",
		"GET /api/artifacts/{id}/versions/{vid}/files",
		"GET /api/artifacts/{id}/versions/{vid}/files/{address}",
		"PUT /api/artifacts/{id}/versions/{vid}/files/{address}",
		"DELETE /api/artifacts/{id}/versions/{vid}/files/{address}",
	} {
		if !contentTokenRoutes[p] {
			t.Errorf("contentTokenRoutes lacks %q", p)
		}
	}
	for _, p := range []string{
		"POST /api/artifacts/{id}/versions/{vid}/db/query",
		"POST /api/artifacts/{id}/versions/{vid}/db/batch",
		"GET /api/artifacts/{id}/versions/{vid}/db/download",
		"GET /api/artifacts/{id}/versions/{vid}/files/{path...}",
		"PUT /api/artifacts/{id}/versions/{vid}/files/{path...}",
		"DELETE /api/artifacts/{id}/versions/{vid}/files/{path...}",
	} {
		if contentTokenRoutes[p] {
			t.Errorf("contentTokenRoutes still lists %q", p)
		}
	}
	if len(contentTokenRoutes) != 15 {
		t.Errorf("contentTokenRoutes has %d entries, want 15", len(contentTokenRoutes))
	}
}
