package server

import (
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// mutatingMethods are the methods a cross-site form or script can trigger a
// browser into sending with cookies attached, so they're the ones that need
// the extra checks below.
var mutatingMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// protectMutations guards /api/ writes against cross-site request forgery.
// It only applies to requests that carry no Authorization header: a bearer
// credential has to be read out of a JSON response and copied into a header
// by something that can read the response, which a forged cross-site request
// (a submitted form, an <img>, a fetch with credentials) cannot do, so those
// requests are already safe. Cookie-authenticated requests are not, because
// browsers attach cookies to a cross-site request automatically.
//
// Two independent checks apply:
//   - The body must be declared application/json or application/octet-stream.
//     A browser can send neither to another site without a preflight, which
//     rules out a plain HTML form post. A DELETE with no body is exempt,
//     because a cross-site DELETE needs a preflight too. multipart/form-data
//     is also accepted when Sec-Fetch-Site is same-origin: the app's own
//     uploads use it, and a forged form post cannot claim that header.
//   - Sec-Fetch-Site, when the browser sends it, must say the request
//     originated from the same origin; failing that, an explicit Origin
//     header must match the server's own public origin.
//
// When publicOrigin is empty (no --public-url configured) there's nothing to
// compare Origin against, so only the Sec-Fetch-Site rule and the content
// type are enforced.
func protectMutations(publicOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mutatingMethods[r.Method] || !strings.HasPrefix(r.URL.Path, "/api/") || r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodDelete || r.ContentLength != 0 {
			mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			sameOriginForm := mediaType == "multipart/form-data" && r.Header.Get("Sec-Fetch-Site") == "same-origin"
			if err != nil || (mediaType != "application/json" && mediaType != "application/octet-stream" && !sameOriginForm) {
				writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json or application/octet-stream")
				return
			}
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
			if site != "same-origin" {
				writeError(w, http.StatusForbidden, "cross-site request refused")
				return
			}
		} else if origin := r.Header.Get("Origin"); origin != "" && publicOrigin != "" && origin != publicOrigin {
			writeError(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originOf returns the scheme://host[:port] of rawURL, or "" when rawURL is
// empty or not a usable absolute URL.
func originOf(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
