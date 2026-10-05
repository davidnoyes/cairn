package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// metaFieldsUnchanged reports whether both scopes' fields still read as before.
func metaFieldsUnchanged(t *testing.T, w *metaWorld, beforeA, beforeV map[string]metaItem) bool {
	t.Helper()
	return sameMeta(beforeA, artifactMeta(t, w.owner.testClient, w.o.id)) &&
		sameMeta(beforeV, versionMeta(t, w.owner.testClient, w.o.id, w.vid))
}

func TestMetaWriteByADemotedEditor(t *testing.T) {
	w := newMetaWorld(t)
	aid, vid := w.o.id, w.vid
	mustMeta(t, newMeta(t, w.owner, aid, "", "name", 1, "seeded"))
	mustMeta(t, newMeta(t, w.owner, aid, vid, "name", 1, "seeded"))

	// Demoted to viewer: still a member, no longer allowed to write.
	b := w.o.nextEpoch()
	for i := range b.Members {
		if b.Members[i].User == w.editor.id {
			b.Members[i].Role = "viewer"
		}
	}
	w.o.apply(b)
	beforeA := artifactMeta(t, w.owner.testClient, aid)
	beforeV := versionMeta(t, w.owner.testClient, aid, vid)
	for _, c := range []struct{ name, vid string }{{"artifact", ""}, {"version", vid}} {
		q := newMeta(t, w.editor, aid, c.vid, "name", 2, "demoted")
		if got := status0(t, q.send(t)); got != http.StatusForbidden {
			t.Errorf("demoted editor, %s: %d, want 403", c.name, got)
		}
	}
	if !metaFieldsUnchanged(t, w, beforeA, beforeV) {
		t.Error("a demoted editor changed a stored field")
	}
}

func TestMetaWriteByARemovedEditor(t *testing.T) {
	w := newMetaWorld(t)
	aid, vid := w.o.id, w.vid
	mustMeta(t, newMeta(t, w.owner, aid, "", "name", 1, "seeded"))
	mustMeta(t, newMeta(t, w.owner, aid, vid, "name", 1, "seeded"))

	w.o.removeAndExclude(w.editor)
	beforeA := artifactMeta(t, w.owner.testClient, aid)
	beforeV := versionMeta(t, w.owner.testClient, aid, vid)
	// A non-member is told nothing exists (withArtifact answers 404).
	for _, c := range []struct{ name, vid string }{{"artifact", ""}, {"version", vid}} {
		q := newMeta(t, w.editor, aid, c.vid, "name", 2, "removed")
		if got := status0(t, q.send(t)); got != http.StatusNotFound {
			t.Errorf("removed editor, %s: %d, want 404", c.name, got)
		}
	}
	if !metaFieldsUnchanged(t, w, beforeA, beforeV) {
		t.Error("a removed editor changed a stored field")
	}
}

func TestMetaEditorWritesVersionField(t *testing.T) {
	w := newMetaWorld(t)
	q := newMeta(t, w.editor, w.o.id, w.vid, "name", 1, "by the editor")
	mustMeta(t, q)
	vm := versionMeta(t, w.owner.testClient, w.o.id, w.vid)
	if vm["name"].Blob != e2e.B64(q.blob) || vm["name"].SignerKey != e2e.B64(w.editor.keys.epub) {
		t.Errorf("version meta = %+v, want the editor's write", vm)
	}
}

func TestMetaWriteBodyLimits(t *testing.T) {
	w := newMetaWorld(t)
	aid, vid := w.o.id, w.vid
	mustMeta(t, newMeta(t, w.owner, aid, "", "name", 1, "seeded"))
	before := artifactMeta(t, w.owner.testClient, aid)

	t.Run("trailing data after the body", func(t *testing.T) {
		q := newMeta(t, w.owner, aid, "", "name", 1, "trailing")
		body, err := json.Marshal(q.request(t))
		if err != nil {
			t.Fatal(err)
		}
		resp := w.owner.doRaw("PUT", q.path(), append(body, []byte("{}")...))
		if got := status0(t, resp); got != http.StatusBadRequest {
			t.Errorf("status %d, want 400", got)
		}
		if !sameMeta(before, artifactMeta(t, w.owner.testClient, aid)) {
			t.Error("a refused write changed a stored field")
		}
	})

	t.Run("a request over the reader limit", func(t *testing.T) {
		// The unknown field would be a 400 once decoded; only the reader's
		// limit, hit while the decoder is still reading the value, gives 413.
		q := newMeta(t, w.owner, aid, "", "name", 1, "oversize")
		req := q.request(t)
		req["pad"] = strings.Repeat("x", 2*maxMetaBlob+maxRecordBytes)
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if got := status0(t, w.owner.doRaw("PUT", q.path(), body)); got != http.StatusRequestEntityTooLarge {
			t.Errorf("status %d, want 413", got)
		}
		if !sameMeta(before, artifactMeta(t, w.owner.testClient, aid)) {
			t.Error("a refused write changed a stored field")
		}
	})

	// A blob the server never opens: its header, then filler, at an exact size.
	blobOf := func(n int) []byte {
		return append([]byte("CRNB\x01"), bytes.Repeat([]byte{7}, n-5)...)
	}
	for _, c := range []struct {
		name   string
		size   int
		status int
	}{
		{"a blob of exactly the maximum is stored", maxMetaBlob, http.StatusOK},
		{"a blob one over the maximum is refused", maxMetaBlob + 1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := newMeta(t, w.owner, aid, vid, "changelog", 1, "x")
			q.blob = blobOf(c.size)
			q.body.SHA256 = e2e.BodyHash(q.blob)
			if got := status0(t, q.send(t)); got != c.status {
				t.Errorf("status %d, want %d", got, c.status)
			}
			stored := versionMeta(t, w.owner.testClient, aid, vid)["changelog"].Blob
			if c.status == http.StatusOK && stored != e2e.B64(q.blob) {
				t.Error("the maximum-size blob was not stored")
			}
			if c.status != http.StatusOK && stored != "" && stored != e2e.B64(blobOf(maxMetaBlob)) {
				t.Error("a refused write changed a stored field")
			}
		})
	}
}

func TestListArtifactsIgnoresANameFilter(t *testing.T) {
	w := newMetaWorld(t)
	mustMeta(t, newMeta(t, w.owner, w.o.id, "", "name", 1, "x"))
	newArtifact(t, w.owner, "second")

	get := func(path string) string {
		t.Helper()
		resp := w.owner.doRaw("GET", path, nil)
		defer resp.Body.Close()
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d", path, resp.StatusCode)
		}
		return buf.String()
	}
	all := get("/api/artifacts")
	if !strings.Contains(all, w.o.id) {
		t.Fatalf("the list does not hold the artifact: %s", all)
	}
	if got := get("/api/artifacts?name=x"); got != all {
		t.Errorf("GET /api/artifacts?name=x = %s, want the whole list %s", got, all)
	}
}
