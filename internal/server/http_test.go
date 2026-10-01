package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type readJSONTarget struct {
	A string `json:"a"`
}

func TestReadJSONRejectsUnknownFields(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"a":"x","b":"surprise"}`))
	var out readJSONTarget
	if readJSON(rec, req, &out) {
		t.Fatal("accepted a body with an unknown field")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestReadJSONRejectsTrailingData(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"a":"x"}{"a":"y"}`))
	var out readJSONTarget
	if readJSON(rec, req, &out) {
		t.Fatal("accepted a body with trailing data")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestReadJSONAcceptsWellFormedBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"a":"x"}`))
	var out readJSONTarget
	if !readJSON(rec, req, &out) {
		t.Fatalf("rejected a well-formed body: %d", rec.Code)
	}
	if out.A != "x" {
		t.Errorf("A = %q, want %q", out.A, "x")
	}
}
