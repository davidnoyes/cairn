//go:build !e2egoogle

package main

import "testing"

func TestServeGoogleURLsAreGoogles(t *testing.T) {
	auth, token, err := serveGoogleURLs()
	if auth != "" || token != "" || err != nil {
		t.Errorf("serveGoogleURLs() = %q, %q, %v; want no override", auth, token, err)
	}
}
