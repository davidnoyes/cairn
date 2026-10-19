//go:build e2egoogle

package main

import (
	"os"
	"testing"
)

// init lets the package's other tests serve under this build too.
func init() {
	os.Setenv(testGoogleEnv, "http://127.0.0.1:1")
}

func TestE2EGoogleReadsTheFakeURL(t *testing.T) {
	t.Setenv(testGoogleEnv, "http://127.0.0.1:9999/")
	auth, token, err := serveGoogleURLs()
	if err != nil || auth != "http://127.0.0.1:9999/authorize" || token != "http://127.0.0.1:9999/token" {
		t.Errorf("serveGoogleURLs() = %q, %q, %v", auth, token, err)
	}
}

func TestE2EGoogleNeedsTheEnv(t *testing.T) {
	t.Setenv(testGoogleEnv, "")
	if _, _, err := serveGoogleURLs(); err == nil {
		t.Error("an e2egoogle build started without " + testGoogleEnv)
	}
}
