package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func protectedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func protectReq(t *testing.T, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	protectMutations("https://cairn.example", protectedHandler()).ServeHTTP(rec, req)
	return rec
}

func TestProtectMutationsForgedCrossSitePOSTRefused(t *testing.T) {
	rec := protectReq(t, "POST", "/api/widgets", map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "cross-site",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestProtectMutationsSameSiteRefused(t *testing.T) {
	// Only "same-origin" is accepted; a sibling subdomain ("same-site") is
	// still a different origin and must be refused.
	rec := protectReq(t, "POST", "/api/widgets", map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "same-site",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestProtectMutationsFormEncodedBodyRefused(t *testing.T) {
	rec := protectReq(t, "POST", "/api/widgets", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", rec.Code)
	}
}

func TestProtectMutationsMissingContentTypeRefused(t *testing.T) {
	rec := protectReq(t, "DELETE", "/api/widgets/1", nil)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", rec.Code)
	}
}

func TestProtectMutationsContentTypeWithCharsetAllowed(t *testing.T) {
	rec := protectReq(t, "POST", "/api/widgets", map[string]string{
		"Content-Type": "application/json; charset=utf-8",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestProtectMutationsOriginMismatchRefused(t *testing.T) {
	rec := protectReq(t, "POST", "/api/widgets", map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://evil.example",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestProtectMutationsCorrectOriginAllowed(t *testing.T) {
	rec := protectReq(t, "POST", "/api/widgets", map[string]string{
		"Content-Type": "application/json",
		"Origin":       "https://cairn.example",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestProtectMutationsSameOriginSecFetchSiteAllowed(t *testing.T) {
	rec := protectReq(t, "PATCH", "/api/widgets/1", map[string]string{
		"Content-Type":   "application/json",
		"Sec-Fetch-Site": "same-origin",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestProtectMutationsNeitherHeaderAllowed(t *testing.T) {
	rec := protectReq(t, "PUT", "/api/widgets/1", map[string]string{
		"Content-Type": "application/json",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestProtectMutationsAuthorizationBypassesChecks(t *testing.T) {
	rec := protectReq(t, "POST", "/api/widgets", map[string]string{
		"Content-Type":   "text/plain",
		"Sec-Fetch-Site": "cross-site",
		"Authorization":  "Bearer cairn_abc_def",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestProtectMutationsGETUntouched(t *testing.T) {
	rec := protectReq(t, "GET", "/api/widgets", map[string]string{
		"Sec-Fetch-Site": "cross-site",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestProtectMutationsNonAPIPathUntouched(t *testing.T) {
	rec := protectReq(t, "POST", "/healthz", map[string]string{
		"Sec-Fetch-Site": "cross-site",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestProtectMutationsNoPublicOriginSkipsOriginCheck covers a server with no
// --base-url configured: there is nothing to compare Origin against, so only
// Sec-Fetch-Site and the content type are enforced.
func TestProtectMutationsNoPublicOriginSkipsOriginCheck(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/widgets", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://anything.example")
	rec := httptest.NewRecorder()
	protectMutations("", protectedHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestOriginOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"https://cairn.example", "https://cairn.example"},
		{"https://cairn.example:8443/path", "https://cairn.example:8443"},
		{"not a url", ""},
	}
	for _, c := range cases {
		if got := originOf(c.in); got != c.want {
			t.Errorf("originOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func protectBodyless(t *testing.T, method string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/widgets/1", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	protectMutations("https://cairn.example", protectedHandler()).ServeHTTP(rec, req)
	return rec
}

func TestProtectMutationsOctetStreamAllowed(t *testing.T) {
	rec := protectReq(t, "PUT", "/api/widgets/1", map[string]string{
		"Content-Type":   "application/octet-stream",
		"Sec-Fetch-Site": "same-origin",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestProtectMutationsSafelistedTypesRefused(t *testing.T) {
	// These are the types a cross-site form or a no-preflight fetch can send.
	for _, ct := range []string{"text/plain", "multipart/form-data; boundary=x", "image/png"} {
		rec := protectReq(t, "POST", "/api/widgets", map[string]string{"Content-Type": ct})
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s: status = %d, want 415", ct, rec.Code)
		}
	}
}

func TestProtectMutationsBodylessDeleteSkipsContentType(t *testing.T) {
	rec := protectBodyless(t, "DELETE", map[string]string{"Sec-Fetch-Site": "same-origin"})
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestProtectMutationsBodylessDeleteStillChecksOrigin(t *testing.T) {
	rec := protectBodyless(t, "DELETE", map[string]string{"Sec-Fetch-Site": "cross-site"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestProtectMutationsBodylessPOSTNeedsContentType(t *testing.T) {
	// A cross-site form with no fields has an empty body; only DELETE is exempt.
	rec := protectBodyless(t, "POST", nil)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", rec.Code)
	}
}
