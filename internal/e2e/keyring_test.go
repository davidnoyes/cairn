package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func testKeyringKey(t *testing.T, b byte) []byte {
	t.Helper()
	key, err := MKSealKey(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func sampleKeyring(rev int) *Keyring {
	k := NewKeyring()
	k.Rev = rev
	k.Pins["u-bob"] = Pin{FP: hex64("bob"), State: PinUnverified}
	k.Pins["u-carol"] = Pin{FP: hex64("carol"), State: PinVerified, RotSeq: 2, RotHead: hex64("carol-rot")}
	k.Epochs["a-1"] = KeyringEpoch{Epoch: 2, Seq: 5, Head: hex64("a-1-head"), Ack: 0}
	return k
}

func hex64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestKeyringRoundTrip(t *testing.T) {
	key := testKeyringKey(t, 1)
	want := sampleKeyring(3)
	sealed, err := SealKeyring(rand.Reader, key, want)
	if err != nil {
		t.Fatal(err)
	}
	got, anchor, err := OpenKeyring(key, 3, sealed, nil)
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
	sum := sha256.Sum256(sealed)
	if anchor != (KeyringAnchor{Rev: 3, Hash: hex.EncodeToString(sum[:])}) || anchor != KeyringAnchorOf(3, sealed) {
		t.Errorf("anchor = %+v", anchor)
	}
	// Sealed under the keyring field only: Open with other fields fails.
	if _, err := Open(key, [][]byte{[]byte("mk")}, sealed); !errors.Is(err, ErrDecrypt) {
		t.Errorf("opened under the wrong fields: %v", err)
	}
	if _, err := Open(key, [][]byte{[]byte("keyring")}, sealed); err != nil {
		t.Errorf("Open under [keyring]: %v", err)
	}
}

func TestOpenKeyringAnchor(t *testing.T) {
	key := testKeyringKey(t, 1)
	sealed3, _ := SealKeyring(rand.Reader, key, sampleKeyring(3))
	sealed3b, _ := SealKeyring(rand.Reader, key, sampleKeyring(3))
	at3 := KeyringAnchorOf(3, sealed3)

	cases := []struct {
		name   string
		rev    int
		sealed []byte
		anchor *KeyringAnchor
		want   error
	}{
		{"no anchor", 3, sealed3, nil, nil},
		{"same rev, same hash", 3, sealed3, &at3, nil},
		{"older anchor", 3, sealed3, &KeyringAnchor{Rev: 2, Hash: hex64("x")}, nil},
		{"inner and outer rev differ", 4, sealed3, nil, ErrKeyringRev},
		{"outer below inner", 2, sealed3, nil, ErrKeyringRev},
		{"below the anchor", 3, sealed3, &KeyringAnchor{Rev: 4, Hash: hex64("x")}, ErrKeyringRollback},
		{"same rev, another hash", 3, sealed3b, &at3, ErrKeyringFork},
		{"server wiped it", 0, nil, &at3, ErrKeyringRollback},
		{"empty at a nonzero rev", 3, nil, nil, ErrFormat},
		{"bad anchor hash", 3, sealed3, &KeyringAnchor{Rev: 1, Hash: "XYZ"}, ErrFormat},
		{"negative anchor rev", 3, sealed3, &KeyringAnchor{Rev: -1, Hash: hex64("x")}, ErrFormat},
	}
	for _, c := range cases {
		_, _, err := OpenKeyring(key, c.rev, c.sealed, c.anchor)
		if c.want == nil && err != nil || c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	// The anchor errors are distinct from each other.
	for _, pair := range [][2]error{{ErrKeyringRev, ErrKeyringRollback}, {ErrKeyringRollback, ErrKeyringFork}, {ErrKeyringRev, ErrKeyringFork}} {
		if errors.Is(pair[0], pair[1]) {
			t.Errorf("%v is %v", pair[0], pair[1])
		}
	}
}

func TestOpenKeyringEmpty(t *testing.T) {
	key := testKeyringKey(t, 1)
	got, anchor, err := OpenKeyring(key, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, NewKeyring()) || got.Pins == nil || got.Epochs == nil {
		t.Errorf("empty keyring = %+v", got)
	}
	if anchor != KeyringAnchorOf(0, nil) {
		t.Errorf("anchor = %+v", anchor)
	}
	// Re-reading the empty keyring against its own anchor is fine.
	if _, _, err := OpenKeyring(key, 0, nil, &anchor); err != nil {
		t.Errorf("empty against its own anchor: %v", err)
	}
}

// A keyring that does not open is an error, never an empty keyring.
func TestOpenKeyringFailureIsAnError(t *testing.T) {
	key := testKeyringKey(t, 1)
	sealed, _ := SealKeyring(rand.Reader, key, sampleKeyring(1))
	got, _, err := OpenKeyring(testKeyringKey(t, 2), 1, sealed, nil)
	if !errors.Is(err, ErrDecrypt) || got != nil {
		t.Errorf("wrong key: %+v, %v; want nil and ErrDecrypt", got, err)
	}
	sealed[len(sealed)-1] ^= 1
	if got, _, err := OpenKeyring(key, 1, sealed, nil); !errors.Is(err, ErrDecrypt) || got != nil {
		t.Errorf("tampered: %+v, %v; want nil and ErrDecrypt", got, err)
	}
}

func TestKeyringCheck(t *testing.T) {
	if err := sampleKeyring(1).Check(); err != nil {
		t.Fatalf("valid keyring: %v", err)
	}
	for name, mutate := range map[string]func(k *Keyring){
		"v 2":               func(k *Keyring) { k.V = 2 },
		"negative rev":      func(k *Keyring) { k.Rev = -1 },
		"nil pins":          func(k *Keyring) { k.Pins = nil },
		"nil epochs":        func(k *Keyring) { k.Epochs = nil },
		"state trusted":     func(k *Keyring) { p := k.Pins["u-bob"]; p.State = "trusted"; k.Pins["u-bob"] = p },
		"state new":         func(k *Keyring) { p := k.Pins["u-bob"]; p.State = PinNew; k.Pins["u-bob"] = p },
		"fp uppercase":      func(k *Keyring) { p := k.Pins["u-bob"]; p.FP = "AB" + p.FP[2:]; k.Pins["u-bob"] = p },
		"fp short":          func(k *Keyring) { p := k.Pins["u-bob"]; p.FP = p.FP[:62]; k.Pins["u-bob"] = p },
		"rotHead no rotSeq": func(k *Keyring) { p := k.Pins["u-bob"]; p.RotHead = hex64("r"); k.Pins["u-bob"] = p },
		"rotSeq no rotHead": func(k *Keyring) { p := k.Pins["u-bob"]; p.RotSeq = 1; k.Pins["u-bob"] = p },
		"rotHead not hex":   func(k *Keyring) { p := k.Pins["u-carol"]; p.RotHead = "zz"; k.Pins["u-carol"] = p },
		"negative rotSeq":   func(k *Keyring) { p := k.Pins["u-carol"]; p.RotSeq = -1; k.Pins["u-carol"] = p },
		"epoch zero":        func(k *Keyring) { e := k.Epochs["a-1"]; e.Epoch = 0; k.Epochs["a-1"] = e },
		"seq zero":          func(k *Keyring) { e := k.Epochs["a-1"]; e.Seq = 0; k.Epochs["a-1"] = e },
		"head not hex":      func(k *Keyring) { e := k.Epochs["a-1"]; e.Head = "nope"; k.Epochs["a-1"] = e },
		"negative ack":      func(k *Keyring) { e := k.Epochs["a-1"]; e.Ack = -1; k.Epochs["a-1"] = e },
	} {
		k := sampleKeyring(1)
		mutate(k)
		if err := k.Check(); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v, want ErrFormat", name, err)
		}
		// Nothing invalid is ever sealed.
		if _, err := SealKeyring(rand.Reader, testKeyringKey(t, 1), k); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: SealKeyring %v, want ErrFormat", name, err)
		}
	}
}

func TestKeyringClone(t *testing.T) {
	k := sampleKeyring(1)
	c := k.Clone()
	if !reflect.DeepEqual(k, c) {
		t.Fatal("clone differs")
	}
	c.Pins["u-dave"] = Pin{FP: hex64("dave"), State: PinUnverified}
	c.Epochs["a-2"] = KeyringEpoch{Epoch: 1, Seq: 1, Head: hex64("h")}
	if _, ok := k.Pins["u-dave"]; ok {
		t.Error("a clone's pin reached the original")
	}
	if _, ok := k.Epochs["a-2"]; ok {
		t.Error("a clone's epoch reached the original")
	}
}

func TestKeyringEpochPin(t *testing.T) {
	k := sampleKeyring(1)
	if p := k.EpochPin("a-1"); p == nil || *p != (EpochPin{Epoch: 2, Seq: 5, Head: hex64("a-1-head")}) {
		t.Errorf("EpochPin(a-1) = %+v", p)
	}
	if p := k.EpochPin("a-unknown"); p != nil {
		t.Errorf("EpochPin of an unknown artifact = %+v, want nil", p)
	}
	k.Epochs["a-1"] = KeyringEpoch{Epoch: 2, Seq: 5, Head: hex64("a-1-head"), Ack: 4}
	k.SetEpoch("a-1", &Chain{Latest: MembershipBody{Epoch: 3, Seq: 7}, Head: hex64("new")})
	if got := k.Epochs["a-1"]; got != (KeyringEpoch{Epoch: 3, Seq: 7, Head: hex64("new"), Ack: 4}) {
		t.Errorf("SetEpoch kept %+v; want the new chain's epoch, seq and head, and the old ack", got)
	}
}

func TestPinState(t *testing.T) {
	x := bytes.Repeat([]byte{1}, 32)
	ed := bytes.Repeat([]byte{2}, 32)
	fp := hex.EncodeToString(Fingerprint(x, ed))
	other := hex64("other")
	cases := []struct {
		pin  *Pin
		want string
	}{
		{nil, PinNew},
		{&Pin{FP: fp, State: PinUnverified}, PinUnverified},
		{&Pin{FP: fp, State: PinVerified}, PinVerified},
		{&Pin{FP: other, State: PinVerified}, PinChanged},
		{&Pin{FP: other, State: PinUnverified}, PinChanged},
	}
	for _, c := range cases {
		state, got := PinState(c.pin, x, ed)
		if state != c.want || got != fp {
			t.Errorf("PinState(%+v) = %s, %s; want %s, %s", c.pin, state, got, c.want, fp)
		}
	}
}
