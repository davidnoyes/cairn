package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// linkVec is one public link PublicLink must build, and ParseLink must read
// back, with the link in Want. Negative inputs must be refused with
// ErrFormat. Bytes are hex; the link itself is text.
type linkVec struct {
	Name     string       `json:"name"`
	Host     string       `json:"host"`
	Artifact string       `json:"artifact"`
	AK       string       `json:"ak"`
	Epoch    int          `json:"epoch"`
	O        string       `json:"o"`
	Want     string       `json:"want"`
	Negative []linkNegVec `json:"negative"`
}

type linkNegVec struct {
	Why   string `json:"why"`
	Input string `json:"input"`
}

// linkChainVec is one answer of GET /api/artifacts/{id}/membership read
// through a link, which VerifyLinkChain and verifyLinkChain must both
// accept, with the result in Want, or both refuse with the error kind in
// Error. Keys is the link scope's editor keys.
type linkChainVec struct {
	Name     string              `json:"name"`
	Why      string              `json:"why"`
	Artifact string              `json:"artifact"`
	AK       string              `json:"ak"`
	Epoch    int                 `json:"epoch"`
	O        string              `json:"o"`
	Records  []Envelope          `json:"records"`
	Owners   map[string]KeyPair  `json:"owners"`
	Offers   map[string]Envelope `json:"offers"`
	Keys     map[string]KeyPair  `json:"keys"`
	Want     *chainWantVec       `json:"want,omitempty"`
	Error    string              `json:"error,omitempty"`
}

const linkVectorArtifact = "0b7e3f0a-6c1d-4f5e-9a2b-3c4d5e6f7a8b"

func linkVectors() []linkVec {
	ak := testKey("vector-link-ak")
	o := hex64("link-owner")
	enc := B64(ak)
	good := "https://cairn.example/shared/" + linkVectorArtifact + "#k=" + enc + "&e=3&o=" + o
	neg := func(why, in string) linkNegVec { return linkNegVec{Why: why, Input: in} }
	other := strings.Replace(linkVectorArtifact, "0b7e", "0B7E", 1)
	short := B64(ak[:31])
	long := B64(append(append([]byte{}, ak...), 0))
	frag := func(f string) string { return "https://cairn.example/shared/" + linkVectorArtifact + "#" + f }
	return []linkVec{{
		Name: "https", Host: "https://cairn.example", Artifact: linkVectorArtifact, AK: hexEnc(ak), Epoch: 3, O: o, Want: good,
		Negative: []linkNegVec{
			neg("no fragment", "https://cairn.example/shared/"+linkVectorArtifact),
			neg("empty fragment", frag("")),
			neg("two fragments", good+"#x"),
			neg("key missing", frag("e=3&o="+o)),
			neg("epoch missing", frag("k="+enc+"&o="+o)),
			neg("o missing", frag("k="+enc+"&e=3")),
			neg("keys out of order", frag("e=3&k="+enc+"&o="+o)),
			neg("extra key", good+"&x=1"),
			neg("duplicate key", good+"&k="+enc),
			neg("unknown key name", frag("k="+enc+"&e=3&p="+o)),
			neg("a query string", "https://cairn.example/shared/"+linkVectorArtifact+"?x=1#k="+enc+"&e=3&o="+o),
			neg("key not canonical base64", frag("k="+enc+"=&e=3&o="+o)),
			neg("key uses the standard alphabet", frag("k="+strings.Replace(enc, "_", "/", 1)+"&e=3&o="+o)),
			neg("key is 31 bytes", frag("k="+short+"&e=3&o="+o)),
			neg("key is 33 bytes", frag("k="+long+"&e=3&o="+o)),
			neg("epoch zero", frag("k="+enc+"&e=0&o="+o)),
			neg("epoch negative", frag("k="+enc+"&e=-1&o="+o)),
			neg("epoch with a plus sign", frag("k="+enc+"&e=%2B3&o="+o)),
			neg("epoch with a leading zero", frag("k="+enc+"&e=03&o="+o)),
			neg("epoch not a number", frag("k="+enc+"&e=three&o="+o)),
			neg("epoch beyond 2^53", frag("k="+enc+"&e=9007199254740993&o="+o)),
			neg("epoch empty", frag("k="+enc+"&e=&o="+o)),
			neg("o is uppercase", frag("k="+enc+"&e=3&o="+strings.ToUpper(o))),
			neg("o is 63 digits", frag("k="+enc+"&e=3&o="+o[1:])),
			neg("o is not hex", frag("k="+enc+"&e=3&o=g"+o[1:])),
			neg("artifact is not a UUID", "https://cairn.example/shared/artifact-1#k="+enc+"&e=3&o="+o),
			neg("artifact is uppercase", "https://cairn.example/shared/"+other+"#k="+enc+"&e=3&o="+o),
			neg("artifact is braced", "https://cairn.example/shared/{"+linkVectorArtifact+"}#k="+enc+"&e=3&o="+o),
			neg("artifact is empty", "https://cairn.example/shared/#k="+enc+"&e=3&o="+o),
			neg("trailing slash", "https://cairn.example/shared/"+linkVectorArtifact+"/#k="+enc+"&e=3&o="+o),
			neg("wrong path", "https://cairn.example/artifacts/"+linkVectorArtifact+"#k="+enc+"&e=3&o="+o),
			neg("no host", "/shared/"+linkVectorArtifact+"#k="+enc+"&e=3&o="+o),
			neg("not http", "ftp://cairn.example/shared/"+linkVectorArtifact+"#k="+enc+"&e=3&o="+o),
			neg("user info in the host", "https://u@cairn.example/shared/"+linkVectorArtifact+"#k="+enc+"&e=3&o="+o),
			neg("leading space", " "+good),
			neg("trailing line feed", good+"\n"),
			neg("empty", ""),
		},
	}, {
		Name: "http-with-port", Host: "http://localhost:8787", Artifact: linkVectorArtifact, AK: hexEnc(ak), Epoch: 1, O: o,
		Want: "http://localhost:8787/shared/" + linkVectorArtifact + "#k=" + enc + "&e=1&o=" + o,
	}}
}

func checkLinkVectors(t *testing.T, vs []linkVec) {
	t.Helper()
	for _, v := range vs {
		got, err := PublicLink(v.Host, v.Artifact, hexDec(t, v.AK), v.Epoch, v.O)
		if err != nil || got != v.Want {
			t.Errorf("%s: PublicLink = %q, %v; want %q", v.Name, got, err, v.Want)
		}
		l, err := ParseLink(v.Want)
		if err != nil {
			t.Errorf("%s: ParseLink: %v", v.Name, err)
		} else if l.Host != v.Host || l.Artifact != v.Artifact || !bytes.Equal(l.AK, hexDec(t, v.AK)) || l.Epoch != v.Epoch || l.Owner != v.O {
			t.Errorf("%s: ParseLink = %+v", v.Name, l)
		}
		for _, n := range v.Negative {
			if _, err := ParseLink(n.Input); !errors.Is(err, ErrFormat) {
				t.Errorf("%s: ParseLink(%q) (%s) = %v, want ErrFormat", v.Name, n.Input, n.Why, err)
			}
		}
	}
}

// linkChainErrorKinds adds the link's own refusal to the chain's.
func linkChainErrorKind(t testing.TB, err error) string {
	t.Helper()
	if err == ErrStaleLink {
		return "staleLink"
	}
	return chainErrorKind(t, err)
}

type linkChainCase struct {
	name, why string
	epoch     int // the link's e; 0 means the chain's latest epoch
	build     func(t testing.TB, u chainUsers) (f *chainFixture, ak []byte, o string, keys map[string]KeyPair)
	err       error
	seq       int
	headEpoch int
}

func linkChainCases() []linkChainCase {
	ak := func(epoch int) []byte { return testKey("chain-ak-" + string(rune('0'+epoch))) }
	public := func(t testing.TB, u chainUsers) *chainFixture {
		return newChain(t, u.alice, []Member{editor(u.bob), viewer(u.carol)}, nil).
			add(u.alice, func(b *MembershipBody) { b.Public = true })
	}
	std := func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
		return public(t, u), ak(1), u.alice.fp, map[string]KeyPair{u.bob.id: u.bob.keys}
	}
	with := func(edit func(u chainUsers, f *chainFixture, a *[]byte, o *string, keys map[string]KeyPair) *chainFixture) func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
		return func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
			f, a, o, keys := std(t, u)
			f = edit(u, f, &a, &o, keys)
			return f, a, o, keys
		}
	}
	return []linkChainCase{
		{name: "public", why: "a public chain anchored at o, with the right AK and the editor's keys", seq: 2, headEpoch: 1, build: std},
		{name: "public-writes", why: "public writes on is no obstacle", seq: 3, headEpoch: 1,
			build: with(func(u chainUsers, f *chainFixture, _ *[]byte, _ *string, _ map[string]KeyPair) *chainFixture {
				return f.add(u.alice, func(b *MembershipBody) { b.PublicWrites = true })
			})},
		{name: "public-after-epoch-bump", why: "a link for epoch 2 on a chain that bumped to it", seq: 3, headEpoch: 2,
			build: func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
				f := public(t, u).add(u.alice, func(b *MembershipBody) { bump(t)(b) })
				return f, ak(2), u.alice.fp, map[string]KeyPair{u.bob.id: u.bob.keys}
			}},
		{name: "viewer-keys-unchecked", why: "only editors' keys are checked; a viewer's keys may be absent or wrong", seq: 2, headEpoch: 1,
			build: with(func(u chainUsers, f *chainFixture, _ *[]byte, _ *string, keys map[string]KeyPair) *chainFixture {
				keys[u.carol.id] = u.mallory.keys
				return f
			})},
		{name: "o-is-not-the-first-owner", why: "o names another fingerprint than the first record's ownerFp", err: ErrChain,
			build: with(func(u chainUsers, f *chainFixture, _ *[]byte, o *string, _ map[string]KeyPair) *chainFixture {
				*o = u.mallory.fp
				return f
			})},
		{name: "chain-of-another-owner", why: "the server serves a whole chain signed by mallory, whose keys it also serves, against alice's o", err: ErrChain,
			build: func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
				f := newChain(t, u.mallory, []Member{editor(u.bob)}, nil).add(u.mallory, func(b *MembershipBody) { b.Public = true })
				return f, ak(1), u.alice.fp, map[string]KeyPair{u.bob.id: u.bob.keys}
			}},
		{name: "substituted-owner-keys", why: "the server serves mallory's keys under alice's fingerprint", err: ErrChain,
			build: with(func(u chainUsers, f *chainFixture, _ *[]byte, _ *string, _ map[string]KeyPair) *chainFixture {
				f.owners[u.alice.fp] = u.mallory.keys
				return f
			})},
		{name: "editor-keys-substituted", why: "the keys served for an editor hash to another fingerprint than the record lists", err: ErrChain,
			build: with(func(u chainUsers, f *chainFixture, _ *[]byte, _ *string, keys map[string]KeyPair) *chainFixture {
				keys[u.bob.id] = u.mallory.keys
				return f
			})},
		{name: "editor-keys-missing", why: "the server serves no keys for a listed editor", err: ErrChain,
			build: with(func(u chainUsers, f *chainFixture, _ *[]byte, _ *string, keys map[string]KeyPair) *chainFixture {
				delete(keys, u.bob.id)
				return f
			})},
		{name: "wrong-ak", why: "the link's AK does not match the chain's akCommit", err: ErrChain,
			build: with(func(u chainUsers, f *chainFixture, a *[]byte, _ *string, _ map[string]KeyPair) *chainFixture {
				*a = testKey("another-ak")
				return f
			})},
		{name: "stale-link", why: "the link is for epoch 1, and the chain is at epoch 2", epoch: 1, err: ErrStaleLink,
			build: func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
				f := public(t, u).add(u.alice, func(b *MembershipBody) { bump(t)(b) })
				return f, ak(1), u.alice.fp, map[string]KeyPair{u.bob.id: u.bob.keys}
			}},
		{name: "link-ahead-of-the-chain", why: "the link is for epoch 2, and the chain stops at epoch 1", epoch: 2, err: ErrChain,
			build: func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
				return public(t, u), ak(2), u.alice.fp, map[string]KeyPair{u.bob.id: u.bob.keys}
			}},
		{name: "private-latest", why: "the latest record is private", err: ErrChain,
			build: func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
				f := newChain(t, u.alice, []Member{editor(u.bob)}, nil)
				return f, ak(1), u.alice.fp, map[string]KeyPair{u.bob.id: u.bob.keys}
			}},
		{name: "made-private-again", why: "an earlier record was public, and the latest is not", err: ErrChain,
			build: func(t testing.TB, u chainUsers) (*chainFixture, []byte, string, map[string]KeyPair) {
				f := public(t, u).add(u.alice, func(b *MembershipBody) { b.Public = false })
				return f, ak(1), u.alice.fp, map[string]KeyPair{u.bob.id: u.bob.keys}
			}},
		{name: "broken-chain", why: "chain rules still apply: the second record's prev is wrong", err: ErrChain,
			build: with(func(u chainUsers, f *chainFixture, _ *[]byte, _ *string, _ map[string]KeyPair) *chainFixture {
				return newChain(f.t, u.alice, []Member{editor(u.bob), viewer(u.carol)}, nil).
					add(u.alice, func(b *MembershipBody) { b.Public = true; b.Prev = hex64("wrong") })
			})},
	}
}

func linkChainVectors(t testing.TB) []linkChainVec {
	t.Helper()
	u := newChainUsers(t)
	var vs []linkChainVec
	for _, c := range linkChainCases() {
		f, ak, o, keys := c.build(t, u)
		epoch := c.epoch
		if epoch == 0 {
			epoch = max(c.headEpoch, 1)
		}
		v := linkChainVec{
			Name: c.name, Why: c.why, Artifact: chainArtifact, AK: hexEnc(ak), Epoch: epoch, O: o,
			Records: f.records, Owners: f.owners, Offers: f.offers, Keys: keys,
		}
		if c.err != nil {
			v.Error = linkChainErrorKind(t, c.err)
		} else {
			v.Want = &chainWantVec{Head: f.head(len(f.records)), Seq: c.seq, Epoch: c.headEpoch, Handovers: []int{}}
		}
		vs = append(vs, v)
	}
	return vs
}

func checkLinkChainVectors(t *testing.T, vs []linkChainVec) {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []linkChainVec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, v := range parsed {
		got, err := VerifyLinkChain(LinkChainInput{
			Link:    Link{Artifact: v.Artifact, AK: hexDec(t, v.AK), Epoch: v.Epoch, Owner: v.O},
			Records: v.Records, Owners: v.Owners, Offers: v.Offers, Keys: v.Keys,
		})
		if v.Error != "" {
			want := chainErrorKinds[v.Error]
			if v.Error == "staleLink" {
				want = ErrStaleLink
			}
			if !errors.Is(err, want) {
				t.Errorf("%s (%s): got %v, want %s", v.Name, v.Why, err, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s (%s): %v", v.Name, v.Why, err)
			continue
		}
		if got.Head != v.Want.Head || got.Latest.Seq != v.Want.Seq || got.Latest.Epoch != v.Want.Epoch {
			t.Errorf("%s: got head %s, seq %d, epoch %d; want %+v", v.Name, got.Head, got.Latest.Seq, got.Latest.Epoch, *v.Want)
		}
	}
}

func TestPublicLinkRefusesBadInputs(t *testing.T) {
	ak := testKey("link-ak")
	o := hex64("o")
	for name, f := range map[string]func() (string, error){
		"short AK":       func() (string, error) { return PublicLink("https://h", linkVectorArtifact, ak[:31], 1, o) },
		"epoch zero":     func() (string, error) { return PublicLink("https://h", linkVectorArtifact, ak, 0, o) },
		"bad artifact":   func() (string, error) { return PublicLink("https://h", "nope", ak, 1, o) },
		"bad owner":      func() (string, error) { return PublicLink("https://h", linkVectorArtifact, ak, 1, "AB") },
		"host with path": func() (string, error) { return PublicLink("https://h/x", linkVectorArtifact, ak, 1, o) },
	} {
		if _, err := f(); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v, want ErrFormat", name, err)
		}
	}
	// A trailing slash on the host is dropped, as the client does.
	got, err := PublicLink("https://h/", linkVectorArtifact, ak, 1, o)
	if err != nil || !strings.HasPrefix(got, "https://h/shared/") {
		t.Errorf("PublicLink with a trailing slash = %q, %v", got, err)
	}
}
