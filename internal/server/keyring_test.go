package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

type keyringWire struct {
	Rev     int    `json:"rev"`
	Keyring string `json:"keyring"`
}

type keyringConflict struct {
	Error string `json:"error"`
	Rev   *int   `json:"rev"`
}

func TestKeyringStartsEmpty(t *testing.T) {
	_, ts := testServer(t)
	c := login(t, ts.URL, "admin@example.com", "admin-password")
	var raw map[string]json.RawMessage
	c.mustDo("GET", "/api/me/keyring", nil, &raw, http.StatusOK)
	if string(raw["rev"]) != "0" || string(raw["keyring"]) != `""` || len(raw) != 2 {
		t.Errorf("first GET = %v, want exactly {rev:0, keyring:\"\"}", raw)
	}
}

func TestKeyringPutAndRev(t *testing.T) {
	_, ts := testServer(t)
	c := login(t, ts.URL, "admin@example.com", "admin-password")

	first := []byte("sealed keyring one")
	c.mustDo("PUT", "/api/me/keyring", keyringWire{Rev: 1, Keyring: e2e.B64(first)}, nil, http.StatusOK)
	var got keyringWire
	c.mustDo("GET", "/api/me/keyring", nil, &got, http.StatusOK)
	if got.Rev != 1 || got.Keyring != e2e.B64(first) {
		t.Fatalf("after the first PUT: %+v", got)
	}

	// A stale rev, a repeated rev, a skipped rev, and rev 0 are all refused
	// with the stored rev, and leave the stored keyring alone.
	for _, rev := range []int{0, 1, 3} {
		var conflict keyringConflict
		resp := c.do("PUT", "/api/me/keyring", keyringWire{Rev: rev, Keyring: e2e.B64([]byte("other"))}, &conflict)
		if resp.StatusCode != http.StatusConflict || conflict.Rev == nil || *conflict.Rev != 1 || !strings.Contains(conflict.Error, "rev") {
			t.Errorf("PUT rev %d: status %d, %+v; want 409 with rev 1", rev, resp.StatusCode, conflict)
		}
	}
	c.mustDo("GET", "/api/me/keyring", nil, &got, http.StatusOK)
	if got.Rev != 1 || got.Keyring != e2e.B64(first) {
		t.Fatalf("a refused PUT changed the keyring: %+v", got)
	}

	second := []byte("sealed keyring two")
	c.mustDo("PUT", "/api/me/keyring", keyringWire{Rev: 2, Keyring: e2e.B64(second)}, nil, http.StatusOK)
	c.mustDo("GET", "/api/me/keyring", nil, &got, http.StatusOK)
	if got.Rev != 2 || got.Keyring != e2e.B64(second) {
		t.Fatalf("after the second PUT: %+v", got)
	}

	// The first PUT on a fresh account must be rev 1, not any rev.
	_, ts2 := testServer(t)
	c2 := login(t, ts2.URL, "admin@example.com", "admin-password")
	var conflict keyringConflict
	resp := c2.do("PUT", "/api/me/keyring", keyringWire{Rev: 2, Keyring: e2e.B64(first)}, &conflict)
	if resp.StatusCode != http.StatusConflict || conflict.Rev == nil || *conflict.Rev != 0 {
		t.Errorf("first PUT at rev 2: status %d, %+v; want 409 with rev 0", resp.StatusCode, conflict)
	}
}

func TestKeyringSizeAndShape(t *testing.T) {
	_, ts := testServer(t)
	c := login(t, ts.URL, "admin@example.com", "admin-password")

	// Exactly 1 MiB of sealed bytes is accepted; one byte more is not.
	c.mustDo("PUT", "/api/me/keyring", keyringWire{Rev: 1, Keyring: e2e.B64(bytes.Repeat([]byte{7}, 1<<20))}, nil, http.StatusOK)
	var e apiError
	resp := c.do("PUT", "/api/me/keyring", keyringWire{Rev: 2, Keyring: e2e.B64(bytes.Repeat([]byte{7}, 1<<20+1))}, &e)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(e.Error, "1 MiB") {
		t.Errorf("1 MiB + 1: status %d, %q; want 413", resp.StatusCode, e.Error)
	}
	// A body far past the limit is refused before it is decoded.
	huge := []byte(`{"rev":2,"keyring":"` + strings.Repeat("A", 3<<20) + `"}`)
	if resp := c.doRaw("PUT", "/api/me/keyring", huge); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("3 MiB body: status %d, want 413", resp.StatusCode)
	}

	for name, body := range map[string]string{
		"empty keyring": `{"rev":2,"keyring":""}`,
		"not base64":    `{"rev":2,"keyring":"a+b/"}`,
		"unknown field": `{"rev":2,"keyring":"AAAA","extra":1}`,
		"no keyring":    `{"rev":2}`,
	} {
		if resp := c.doRaw("PUT", "/api/me/keyring", []byte(body)); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, resp.StatusCode)
		}
	}
	var got keyringWire
	c.mustDo("GET", "/api/me/keyring", nil, &got, http.StatusOK)
	if got.Rev != 1 {
		t.Errorf("a refused PUT moved rev to %d", got.Rev)
	}
}

func TestKeyringNeedsAuthAndIsPerUser(t *testing.T) {
	s, ts := testServer(t)
	anon := &testClient{t: t, base: ts.URL}
	for _, m := range []string{"GET", "PUT"} {
		var body any
		if m == "PUT" {
			body = keyringWire{Rev: 1, Keyring: "AAAA"}
		}
		if resp := anon.do(m, "/api/me/keyring", body, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous %s: status %d, want 401", m, resp.StatusCode)
		}
	}

	seedAccount(t, s, "bob@example.com", "bob-password", false)
	admin := login(t, ts.URL, "admin@example.com", "admin-password")
	bob := login(t, ts.URL, "bob@example.com", "bob-password")
	admin.mustDo("PUT", "/api/me/keyring", keyringWire{Rev: 1, Keyring: e2e.B64([]byte("admin's"))}, nil, http.StatusOK)

	// Bob sees his own empty keyring, not the admin's, and his first write
	// is rev 1 of his own.
	var got keyringWire
	bob.mustDo("GET", "/api/me/keyring", nil, &got, http.StatusOK)
	if got.Rev != 0 || got.Keyring != "" {
		t.Errorf("bob read %+v, want his own empty keyring", got)
	}
	bob.mustDo("PUT", "/api/me/keyring", keyringWire{Rev: 1, Keyring: e2e.B64([]byte("bob's"))}, nil, http.StatusOK)
	admin.mustDo("GET", "/api/me/keyring", nil, &got, http.StatusOK)
	if got.Rev != 1 || got.Keyring != e2e.B64([]byte("admin's")) {
		t.Errorf("bob's write reached the admin's keyring: %+v", got)
	}
}
