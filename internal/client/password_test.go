package client

import "testing"

func TestCheckNewPasswordEmpty(t *testing.T) {
	err := CheckNewPassword("")
	if err == nil {
		t.Fatal("an empty password was accepted")
	}
	if err.Error() != "password must not be empty" {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCheckNewPasswordWeak(t *testing.T) {
	if err := CheckNewPassword("password1"); err == nil {
		t.Fatal("a weak password was accepted")
	}
}

func TestCheckNewPasswordRejectsUserInputs(t *testing.T) {
	if err := CheckNewPassword("ada@example.com", "ada@example.com", "Ada"); err == nil {
		t.Fatal("a password equal to the account's own email was accepted")
	}
}

func TestCheckNewPasswordStrong(t *testing.T) {
	if err := CheckNewPassword("correct horse battery staple"); err != nil {
		t.Errorf("a strong passphrase was rejected: %v", err)
	}
}
