//go:build e2egoogle

package main

import (
	"errors"
	"os"
	"strings"
)

// testGoogleEnv names the base URL of the fake Google.
const testGoogleEnv = "CAIRN_TEST_GOOGLE_URL"

// serveGoogleURLs, in a build for the browser tests only, points Google
// sign-in at the fake Google whose base URL testGoogleEnv names, so a test can
// sign in without Google. A release build never contains it.
func serveGoogleURLs() (authURL, tokenURL string, err error) {
	base := strings.TrimRight(os.Getenv(testGoogleEnv), "/")
	if base == "" {
		return "", "", errors.New("this is a test build: set " + testGoogleEnv)
	}
	return base + "/authorize", base + "/token", nil
}
