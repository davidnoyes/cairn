package main

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// googleLoginTimeout is how long cairn login waits for the browser to hand
// over a Google proof.
const googleLoginTimeout = 5 * time.Minute

// openBrowser opens url in the user's browser. A variable, so a test can play
// the browser. Failure is ignored by the caller: the address is printed too.
var openBrowser = func(url string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	return exec.Command(name, url).Start()
}

// googleHandover is what the browser gives the tool: the address Google
// vouched for, and a short-lived proof of it.
type googleHandover struct{ Email, Proof string }

// awaitGoogleProof runs the tool's half of the Google sign-in: it listens on
// a loopback port, opens the server's /auth/cli page with that port and a
// random state, and waits for the browser to arrive at /callback with the
// same state, an address, and a proof. A request with another state is
// refused and the wait goes on.
func awaitGoogleProof(host string) (googleHandover, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return googleHandover{}, err
	}
	defer ln.Close()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return googleHandover{}, err
	}
	state := e2e.B64(b)

	got := make(chan googleHandover, 1)
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if r.URL.Path != "/callback" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 ||
				q.Get("email") == "" || q.Get("proof") == "" {
				http.Error(w, "unexpected request", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>Cairn</title><p>Signed in as %s. You can close this tab and go back to the terminal.</p>", html.EscapeString(q.Get("email")))
			select {
			case got <- googleHandover{Email: q.Get("email"), Proof: q.Get("proof")}:
			default:
			}
		}),
	}
	go srv.Serve(ln)
	defer srv.Close()

	url := host + "/auth/cli?port=" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "&state=" + state
	fmt.Printf("Sign in with Google in your browser. If it does not open, visit:\n  %s\n", url)
	_ = openBrowser(url)

	select {
	case h := <-got:
		return h, nil
	case <-time.After(googleLoginTimeout):
		return googleHandover{}, errors.New("timed out waiting for the browser sign-in")
	}
}
