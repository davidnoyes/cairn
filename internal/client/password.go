package client

import (
	"fmt"

	"github.com/trustelem/zxcvbn"
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
		return fmt.Errorf("password must not be empty")
	}
	if score := zxcvbn.PasswordStrength(password, userInputs).Score; score < 3 {
		return fmt.Errorf("password is too weak (score %d/4); choose a longer or less predictable passphrase", score)
	}
	return nil
}
