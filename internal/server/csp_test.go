package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithAppCSP(t *testing.T) {
	h := withAppCSP(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest("GET", "/signup", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != appCSP {
		t.Errorf("CSP = %q, want %q", got, appCSP)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
