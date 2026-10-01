package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// keyringVec is one GET /api/me/keyring answer that OpenKeyring and
// openKeyring must both accept, with the result in Want, or both refuse with
// the error kind in Error. Key is the mkSealKey, Rev the outer rev, Sealed
// the sealed keyring, and Anchor the client's anchor or null. PT is the
// plaintext Sealed holds, for reference only.
type keyringVec struct {
	Name   string          `json:"name"`
	Why    string          `json:"why"`
	Key    string          `json:"key"`
	Rev    int             `json:"rev"`
	PT     string          `json:"pt"`
	Sealed string          `json:"sealed"`
	Anchor *KeyringAnchor  `json:"anchor"`
	Want   *keyringWantVec `json:"want,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type keyringWantVec struct {
	Keyring *Keyring      `json:"keyring"`
	Anchor  KeyringAnchor `json:"anchor"`
}

// keyringErrorKinds names each error OpenKeyring returns, as the keyring
// section spells it.
var keyringErrorKinds = map[string]error{
	"rev":      ErrKeyringRev,
	"rollback": ErrKeyringRollback,
	"fork":     ErrKeyringFork,
	"format":   ErrFormat,
	"decrypt":  ErrDecrypt,
}

// keyringPT is a valid keyring plaintext at rev, with two pins (one after a
// rotation) and one epochs entry.
func keyringPT(rev string) string {
	return `{"v":1,"rev":` + rev + `,"pins":{` +
		`"u-bob":{"fp":"` + hex64("bob") + `","state":"unverified","rotSeq":0,"rotHead":""},` +
		`"u-carol":{"fp":"` + hex64("carol") + `","state":"verified","rotSeq":2,"rotHead":"` + hex64("carol-rot") + `"}},` +
		`"epochs":{"a-1":{"epoch":2,"seq":5,"head":"` + hex64("a-1-head") + `","ack":1}}}`
}

// edit replaces exactly one occurrence of old in s, so a case that no
// longer applies fails the generator instead of silently testing nothing.
func edit(t testing.TB, s, old, new string) string {
	t.Helper()
	if strings.Count(s, old) != 1 {
		t.Fatalf("edit: %q occurs %d times in %s", old, strings.Count(s, old), s)
	}
	return strings.Replace(s, old, new, 1)
}

func keyringVectors(t testing.TB) []keyringVec {
	t.Helper()
	key, err := MKSealKey(bytes.Repeat([]byte{0x4b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := MKSealKey(bytes.Repeat([]byte{0x4c}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keyringFields := [][]byte{[]byte("keyring")}
	seal := func(name string, k []byte, fields [][]byte, pt string) []byte {
		if pt == "" {
			return nil
		}
		sealed, err := Seal(newDRBG("vector-keyring-"+name), k, fields, []byte(pt))
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	valid3 := keyringPT("3")
	sealed3 := seal("valid-3", key, keyringFields, valid3)
	anchorAt := func(rev int, sealed []byte) *KeyringAnchor {
		a := KeyringAnchorOf(rev, sealed)
		return &a
	}
	other := &KeyringAnchor{Rev: 4, Hash: hex64("some other keyring")}
	older := &KeyringAnchor{Rev: 2, Hash: hex64("an older keyring")}

	type kcase struct {
		name, why string
		rev       int
		pt        string
		sealed    []byte // when set, used instead of sealing pt
		anchor    *KeyringAnchor
		err       error
	}
	cases := []kcase{
		{name: "empty", why: "the server's answer before the first write, on a new device", rev: 0},
		{name: "empty-own-anchor", why: "still empty, read again against the anchor it left", rev: 0, anchor: anchorAt(0, nil)},
		{name: "first-read", why: "a new device has no anchor and accepts the keyring", rev: 3, pt: valid3, sealed: sealed3},
		{name: "anchor-same", why: "the rev and hash the anchor holds", rev: 3, pt: valid3, sealed: sealed3, anchor: anchorAt(3, sealed3)},
		{name: "anchor-older", why: "a newer keyring than the anchor", rev: 3, pt: valid3, sealed: sealed3, anchor: older},
		{name: "no-entries", why: "empty pins and epochs", rev: 1, pt: `{"v":1,"rev":1,"pins":{},"epochs":{}}`},
		{name: "proto-key", why: "a user ID of __proto__ is an ordinary key", rev: 1,
			pt: `{"v":1,"rev":1,"pins":{"__proto__":{"fp":"` + hex64("p") + `","state":"verified","rotSeq":0,"rotHead":""}},"epochs":{}}`},

		{name: "rev-higher-outside", why: "the outer rev is above the sealed one", rev: 4, pt: valid3, sealed: sealed3, err: ErrKeyringRev},
		{name: "rev-lower-outside", why: "the outer rev is below the sealed one", rev: 2, pt: valid3, sealed: sealed3, err: ErrKeyringRev},
		{name: "below-anchor", why: "an older keyring than the anchor", rev: 3, pt: valid3, sealed: sealed3, anchor: other, err: ErrKeyringRollback},
		{name: "wiped", why: "the server answers empty after a write the anchor saw", rev: 0, anchor: anchorAt(3, sealed3), err: ErrKeyringRollback},
		{name: "fork", why: "the anchor's rev with different sealed bytes", rev: 3, pt: valid3, sealed: seal("valid-3-again", key, keyringFields, valid3), anchor: anchorAt(3, sealed3), err: ErrKeyringFork},
		{name: "empty-nonzero-rev", why: "no keyring, but a rev above zero", rev: 3, err: ErrFormat},
		{name: "wrong-key", why: "sealed under another MK", rev: 3, pt: valid3, sealed: seal("wrong-key", otherKey, keyringFields, valid3), err: ErrDecrypt},
		{name: "wrong-fields", why: "sealed under the mk field, not keyring", rev: 3, pt: valid3, sealed: seal("wrong-fields", key, [][]byte{[]byte("mk")}, valid3), err: ErrDecrypt},
		{name: "truncated", why: "the last byte of the tag is missing", rev: 3, pt: valid3, sealed: sealed3[:len(sealed3)-1], err: ErrDecrypt},
	}
	// Each refusal below is a plaintext that opens but must not parse.
	for _, f := range []struct{ name, why, pt string }{
		{"unknown-field", "a field the keyring does not have", edit(t, valid3, `"v":1,`, `"v":1,"extra":0,`)},
		{"unknown-pin-field", "a field a pin does not have", edit(t, valid3, `"state":"unverified",`, `"state":"unverified","note":"",`)},
		{"unknown-epoch-field", "a field an epochs entry does not have", edit(t, valid3, `"ack":1`, `"ack":1,"x":1`)},
		{"case-variant", "Pins for pins", edit(t, valid3, `"pins"`, `"Pins"`)},
		{"case-variant-pin", "FP for fp", edit(t, valid3, `{"fp":"`+hex64("bob"), `{"FP":"`+hex64("bob"))},
		{"duplicate-key", "rev twice", edit(t, valid3, `"rev":3,`, `"rev":3,"rev":3,`)},
		{"duplicate-user", "one user pinned twice", edit(t, valid3, `"u-carol"`, `"u-bob"`)},
		{"v-2", "a version this client does not know", edit(t, valid3, `"v":1`, `"v":2`)},
		{"v-missing", "no version", edit(t, valid3, `"v":1,`, ``)},
		{"epochs-missing", "no epochs", edit(t, valid3, `,"epochs":{"a-1":{"epoch":2,"seq":5,"head":"`+hex64("a-1-head")+`","ack":1}}`, ``)},
		{"pins-null", "pins is null, not an object", `{"v":1,"rev":3,"pins":null,"epochs":{}}`},
		{"pins-array", "pins is a list", `{"v":1,"rev":3,"pins":[],"epochs":{}}`},
		{"pin-null", "a pin that is null", `{"v":1,"rev":3,"pins":{"u-bob":null},"epochs":{}}`},
		{"state-trusted", "a state other than unverified or verified", edit(t, valid3, `"state":"verified"`, `"state":"trusted"`)},
		{"state-new", "new is a pin state shown, never stored", edit(t, valid3, `"state":"verified"`, `"state":"new"`)},
		{"state-case", "Verified for verified", edit(t, valid3, `"state":"verified"`, `"state":"Verified"`)},
		{"state-empty", "an empty state", edit(t, valid3, `"state":"verified"`, `"state":""`)},
		{"negative-rev", "a negative rev", edit(t, valid3, `"rev":3`, `"rev":-3`)},
		{"negative-rotseq", "a negative rotSeq", edit(t, valid3, `"rotSeq":2`, `"rotSeq":-2`)},
		{"negative-seq", "a negative seq", edit(t, valid3, `"seq":5`, `"seq":-5`)},
		{"negative-ack", "a negative ack", edit(t, valid3, `"ack":1`, `"ack":-1`)},
		{"fraction", "a seq that is not an integer", edit(t, valid3, `"seq":5`, `"seq":5.5`)},
		{"exponent", "an epoch written with an exponent", edit(t, valid3, `"epoch":2`, `"epoch":2e0`)},
		{"too-large", "a seq above 2^53 - 1", edit(t, valid3, `"seq":5`, `"seq":9007199254740992`)},
		{"string-rev", "a rev in quotes", edit(t, valid3, `"rev":3`, `"rev":"3"`)},
		{"fp-uppercase", "an fp in uppercase hex", edit(t, valid3, hex64("bob"), strings.ToUpper(hex64("bob")))},
		{"fp-short", "an fp of 63 hex digits", edit(t, valid3, hex64("bob"), hex64("bob")[:63])},
		{"fp-not-hex", "an fp that is not hex", edit(t, valid3, hex64("bob"), "g"+hex64("bob")[1:])},
		{"head-not-hex", "a head that is not hex", edit(t, valid3, hex64("a-1-head"), "zz")},
		{"rothead-not-hex", "a rotHead that is not hex", edit(t, valid3, hex64("carol-rot"), "zz")},
		{"rothead-without-rotseq", "a rotHead with rotSeq 0", edit(t, valid3, `"rotSeq":2`, `"rotSeq":0`)},
		{"rotseq-without-rothead", "a rotSeq with no rotHead", edit(t, valid3, `"rotSeq":0,"rotHead":""`, `"rotSeq":1,"rotHead":""`)},
		{"epoch-zero", "an epochs entry at epoch 0", edit(t, valid3, `"epoch":2`, `"epoch":0`)},
		{"seq-zero", "an epochs entry at seq 0", edit(t, valid3, `"seq":5`, `"seq":0`)},
		{"trailing-data", "a second value after the keyring", valid3 + ` {}`},
		{"not-an-object", "a list, not an object", `[]`},
		{"not-json", "not JSON at all", `keyring`},
	} {
		cases = append(cases, kcase{name: f.name, why: f.why, rev: 3, pt: f.pt, err: ErrFormat})
	}

	var vs []keyringVec
	for _, c := range cases {
		sealed := c.sealed
		if sealed == nil {
			sealed = seal(c.name, key, keyringFields, c.pt)
		}
		v := keyringVec{Name: c.name, Why: c.why, Key: hexEnc(key), Rev: c.rev, PT: hexEnc([]byte(c.pt)), Sealed: hexEnc(sealed), Anchor: c.anchor}
		if c.err != nil {
			for kind, sentinel := range keyringErrorKinds {
				if sentinel == c.err {
					v.Error = kind
				}
			}
		} else {
			// Want is the plaintext itself, decoded leniently; the checker
			// requires OpenKeyring to give the same keyring.
			want := NewKeyring()
			if c.pt != "" {
				if err := json.Unmarshal([]byte(c.pt), want); err != nil {
					t.Fatalf("%s: %v", c.name, err)
				}
			}
			v.Want = &keyringWantVec{Keyring: want, Anchor: KeyringAnchorOf(c.rev, sealed)}
		}
		vs = append(vs, v)
	}
	return vs
}

// checkKeyringVectors runs every keyring entry, as read back from JSON,
// through OpenKeyring.
func checkKeyringVectors(t *testing.T, vs []keyringVec) {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []keyringVec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, v := range parsed {
		sealed, err := hex.DecodeString(v.Sealed)
		if err != nil {
			t.Fatal(err)
		}
		got, anchor, err := OpenKeyring(hexDec(t, v.Key), v.Rev, sealed, v.Anchor)
		if v.Error != "" {
			if !errors.Is(err, keyringErrorKinds[v.Error]) || got != nil {
				t.Errorf("%s (%s): got %+v, %v; want %s", v.Name, v.Why, got, err, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s (%s): %v", v.Name, v.Why, err)
			continue
		}
		if !reflect.DeepEqual(got, v.Want.Keyring) || anchor != v.Want.Anchor {
			t.Errorf("%s: got %+v and anchor %+v; want %+v", v.Name, got, anchor, *v.Want)
		}
	}
}
