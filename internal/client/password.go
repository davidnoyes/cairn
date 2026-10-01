package client

import (
	"errors"

	"github.com/trustelem/zxcvbn"
)

// ErrEmptyPassword and ErrWeakPassword are what CheckNewPassword (and Login,
// for the empty case) return, so callers and tests can tell a rejected
// password from a network failure.
var (
	ErrEmptyPassword = errors.New("password must not be empty")
	ErrWeakPassword  = errors.New("password is too weak: use a longer, less predictable passphrase, and don't include your name or email")
)

// CheckNewPassword enforces password strength on every path that sets a
// *new* password (signup and both reset modes), per design/e2e-trust-model.md:
// the server never sees the plaintext, so the client is the only place that
// can judge it. userInputs are extra dictionary context — typically the
// account's email and name — that zxcvbn weighs against the password.
// Login is deliberately exempt: it authenticates an existing password, which
// this check cannot retroactively improve.
func CheckNewPassword(password string, userInputs ...string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	if zxcvbn.PasswordStrength(password, userInputs).Score < 3 {
		return ErrWeakPassword
	}
	return nil
}
