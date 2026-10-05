package e2e

import (
	"bytes"
	"regexp"
	"testing"
	"time"
)

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestRefuseFakeShape(t *testing.T) {
	id, mk, priv := RefuseFake([]byte("secret"), "ada@example.com")
	if !uuidV4.MatchString(id) {
		t.Errorf("id %q is not a version 4 UUID", id)
	}
	// A sealed 32-byte key is 61 bytes and starts with the version byte.
	for name, v := range map[string][]byte{"mkRecovery": mk, "ed25519Priv": priv} {
		if len(v) != 61 || v[0] != 0x01 {
			t.Errorf("%s is %d bytes starting %#x, want 61 starting 0x01", name, len(v), v[0])
		}
	}
	if bytes.Equal(mk, priv) {
		t.Error("the two blobs are equal")
	}
}

func TestRefuseFakeIsStableAndSeparated(t *testing.T) {
	secret := []byte("secret")
	id, mk, priv := RefuseFake(secret, "ada@example.com")
	id2, mk2, priv2 := RefuseFake(secret, "  ADA@example.com ")
	if id != id2 || !bytes.Equal(mk, mk2) || !bytes.Equal(priv, priv2) {
		t.Error("the same address, normalized, gave a different answer")
	}
	id3, mk3, _ := RefuseFake(secret, "bob@example.com")
	if id3 == id || bytes.Equal(mk3, mk) {
		t.Error("two addresses gave the same answer")
	}
	id4, mk4, _ := RefuseFake([]byte("other"), "ada@example.com")
	if id4 == id || bytes.Equal(mk4, mk) {
		t.Error("two secrets gave the same answer")
	}
}

func TestRefuseFakeRequestedAt(t *testing.T) {
	const wait = 14 * 24 * time.Hour
	secret := []byte("secret")
	now := time.Date(2026, 10, 5, 12, 30, 15, 500, time.UTC)
	at := RefuseFakeRequestedAt(secret, "ada@example.com", now, wait)
	if !at.After(now.Add(-wait)) || at.After(now) || at.Nanosecond() != 0 || at.Location() != time.UTC {
		t.Fatalf("%s is not a whole UTC second in the %s before %s", at, wait, now)
	}
	// It stays put until a request made then would be released, then moves on
	// by exactly the wait.
	for _, later := range []time.Time{at, at.Add(wait - time.Second)} {
		if got := RefuseFakeRequestedAt(secret, "  ADA@example.com", later, wait); !got.Equal(at) {
			t.Errorf("at %s: %s, want %s", later, got, at)
		}
	}
	if got := RefuseFakeRequestedAt(secret, "ada@example.com", at.Add(wait), wait); !got.Equal(at.Add(wait)) {
		t.Errorf("at release: %s, want %s", got, at.Add(wait))
	}
	if RefuseFakeRequestedAt(secret, "bob@example.com", now, wait).Equal(at) &&
		RefuseFakeRequestedAt(secret, "carol@example.com", now, wait).Equal(at) {
		t.Error("the offset does not depend on the address")
	}
	if RefuseFakeRequestedAt([]byte("other"), "ada@example.com", now, wait).Equal(at) &&
		RefuseFakeRequestedAt([]byte("third"), "ada@example.com", now, wait).Equal(at) {
		t.Error("the offset does not depend on the secret")
	}
}
