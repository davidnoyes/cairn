package server

import (
	"net/http"
	"testing"
)

// Artifact-scoped APIs accept a resource reference (e.g. a Claude session id)
// wherever an artifact id is expected — unless it matches several artifacts.
func TestResourceReferenceResolution(t *testing.T) {
	_, ts := testServer(t)
	admin, aid, vid, _ := setupArtifact(t, ts.URL, true)
	admin.mustDo("POST", "/api/artifacts/"+aid+"/resources",
		map[string]string{"type": "claude-session", "value": "sess-123"}, nil, http.StatusCreated)

	// API lookup by resource value resolves to the artifact
	var a struct {
		ID        string `json:"id"`
		Resources []struct {
			ID string `json:"id"`
		} `json:"resources"`
	}
	admin.mustDo("GET", "/api/artifacts/sess-123", nil, &a, http.StatusOK)
	if a.ID != aid {
		t.Fatalf("resolved %q, want %q", a.ID, aid)
	}

	// ...and by resource row id
	var byRowID struct {
		ID string `json:"id"`
	}
	admin.mustDo("GET", "/api/artifacts/"+a.Resources[0].ID, nil, &byRowID, http.StatusOK)
	if byRowID.ID != aid {
		t.Errorf("resource row id resolved %q", byRowID.ID)
	}

	// Version + database APIs work through the reference
	var versions []struct {
		ID string `json:"id"`
	}
	admin.mustDo("GET", "/api/artifacts/sess-123/versions", nil, &versions, http.StatusOK)
	if len(versions) != 1 || versions[0].ID != vid {
		t.Fatalf("versions via reference: %+v", versions)
	}
	admin.mustDo("POST", "/api/artifacts/sess-123/versions/"+vid+"/db/query",
		map[string]any{"sql": "CREATE TABLE t (n INTEGER)"}, nil, http.StatusOK)

	// Upload through the reference lands on the right artifact
	resp := admin.upload("POST", "/api/artifacts/sess-123/versions",
		zipFrom(t, map[string]string{"index.html": "v2"}), nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload via reference: %d", resp.StatusCode)
	}
	uploaded := decode[struct {
		ArtifactID string `json:"artifactId"`
	}](t, resp)
	if uploaded.ArtifactID != aid {
		t.Errorf("upload landed on %q", uploaded.ArtifactID)
	}

	// The old page URL passes the reference on to the shared page, which resolves it
	pr := get(t, ts.URL+"/artifacts/sess-123", admin.token, "text/html")
	if pr.StatusCode != http.StatusFound || pr.Header.Get("Location") != "/shared/sess-123" {
		t.Errorf("page redirect: %d %s", pr.StatusCode, pr.Header.Get("Location"))
	}
	pr.Body.Close()

	// A second artifact sharing the resource value makes the reference
	// ambiguous → 409, while artifact ids keep working.
	bid := createArtifact(t, admin, "other")
	admin.mustDo("POST", "/api/artifacts/"+bid+"/resources",
		map[string]string{"type": "claude-session", "value": "sess-123"}, nil, http.StatusCreated)
	r := admin.do("GET", "/api/artifacts/sess-123", nil, nil)
	if r.StatusCode != http.StatusConflict {
		t.Errorf("ambiguous reference: %d, want 409", r.StatusCode)
	}
	admin.mustDo("GET", "/api/artifacts/"+aid, nil, nil, http.StatusOK)

	// Unknown references still 404
	r = admin.do("GET", "/api/artifacts/does-not-exist", nil, nil)
	if r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown reference: %d", r.StatusCode)
	}
}
