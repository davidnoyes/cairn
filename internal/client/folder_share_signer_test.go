package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"testing"
)

// A fan-out signs only what the verified record lets the caller sign. The
// access level the server gives is a hint for which items to leave alone; a
// server that calls an editor the owner gets a refusal for each item, and no
// record.
func TestFanOutChecksTheSignerWhateverTheServerSays(t *testing.T) {
	w := newFolderTree(t)
	if _, err := w.ada.Share(w.f, "bob@example.com", "editor", false); err != nil {
		t.Fatal(err)
	}
	fanOutOK(t, w.ada, w.f, nil)
	if _, err := w.ada.Share(w.f, "cat@example.com", "viewer", false); err != nil {
		t.Fatal(err)
	}
	liar := NewWithKey(w.bob.Host, *w.bob.Key)
	liar.Anchors = w.bob.Anchors
	var sent []string
	liar.HTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "PUT" || r.Method == "POST" {
			sent = append(sent, r.Method+" "+r.URL.Path)
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil || r.Method != "GET" || r.URL.Path != "/api/artifacts" {
			return resp, err
		}
		var list []map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			return nil, err
		}
		resp.Body.Close()
		for _, m := range list {
			m["access"] = "owner"
		}
		data, err := json.Marshal(list)
		if err != nil {
			return nil, err
		}
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.Header.Set("Content-Length", strconv.Itoa(len(data)))
		resp.ContentLength = int64(len(data))
		return resp, nil
	})}
	res, err := liar.FanOut(w.f, nil, nil)
	if !errors.Is(err, ErrFanOutIncomplete) || res.Count(FanOutFailed) != 2 {
		t.Fatalf("FanOut = %+v, %v", res, err)
	}
	for _, it := range res.Items {
		// The items in the nested folder wait for that folder's record.
		if it.ID == w.item2 && it.State != FanOutCurrent || it.ID != w.item2 && !errors.Is(it.Err, ErrNotOwner) {
			t.Errorf("%s: %+v", it.ID, it)
		}
	}
	if writesTo(sent, w.item1) || writesTo(sent, w.g) {
		t.Errorf("a record was written: %v", sent)
	}
	wantInherit(t, w.ada, w.item1, "pending")
}
