package server

import "net/http"

// appCSP is the Content Security Policy for the account pages (signup,
// verify, login, forgot, reset, admin): scripts load only from files, never
// inline or from a CDN.
const appCSP = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; require-trusted-types-for 'script'"

// withAppCSP sets the account-pages Content Security Policy on h's response.
func withAppCSP(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", appCSP)
		h(w, r)
	}
}
