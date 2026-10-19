//go:build !e2egoogle

package main

// serveGoogleURLs returns no endpoints, so the server talks to Google's own.
// The browser tests build with the e2egoogle tag instead; see google_e2e.go.
func serveGoogleURLs() (authURL, tokenURL string, err error) { return "", "", nil }
