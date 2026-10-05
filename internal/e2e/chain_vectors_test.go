package e2e

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

// chainVec is one membership chain that VerifyChain and verifyChain must
// both accept, with the result in Want, or both refuse with the error kind
// in Error. Records, Owners, Offers, and Successors are in the wire form the
// membership endpoint serves, not hex.
type chainVec struct {
	Name           string              `json:"name"`
	Why            string              `json:"why"`
	Artifact       string              `json:"artifact"`
	Records        []Envelope          `json:"records"`
	Owners         map[string]KeyPair  `json:"owners"`
	Offers         map[string]Envelope `json:"offers"`
	Successors     map[string]Envelope `json:"successors"`
	Anchor         string              `json:"anchor"`
	CurrentOwnerFP string              `json:"currentOwnerFp"`
	Pin            *chainPinVec        `json:"pin"`
	Want           *chainWantVec       `json:"want,omitempty"`
	Error          string              `json:"error,omitempty"`
}

type chainPinVec struct {
	Epoch int    `json:"epoch"`
	Seq   int    `json:"seq"`
	Head  string `json:"head"`
}

type chainWantVec struct {
	Head      string `json:"head"`
	Seq       int    `json:"seq"`
	Epoch     int    `json:"epoch"`
	Handovers []int  `json:"handovers"`
}

// chainErrorKinds names each sentinel VerifyChain returns, as the chain
// section spells it.
var chainErrorKinds = map[string]error{
	"chain":      ErrChain,
	"rollback":   ErrRollback,
	"fork":       ErrFork,
	"staleEpoch": ErrStaleEpoch,
	"format":     ErrFormat,
	"decrypt":    ErrDecrypt,
}

func chainErrorKind(t testing.TB, err error) string {
	t.Helper()
	for kind, sentinel := range chainErrorKinds {
		if sentinel == err {
			return kind
		}
	}
	t.Fatalf("no error kind for %v", err)
	return ""
}

// chainVectors builds the chain section from chainCases. Want comes from
// the case and the records themselves, never from VerifyChain.
func chainVectors(t testing.TB) []chainVec {
	t.Helper()
	u := newChainUsers(t)
	var vs []chainVec
	for _, c := range chainCases() {
		in := c.build(t, u)
		v := chainVec{
			Name: c.name, Why: c.why, Artifact: in.Artifact, Records: in.Records,
			Owners: in.Owners, Offers: in.Offers, Successors: in.Successors, Anchor: in.Anchor, CurrentOwnerFP: in.CurrentOwnerFP,
		}
		if v.Records == nil {
			v.Records = []Envelope{}
		}
		if v.Owners == nil {
			v.Owners = map[string]KeyPair{}
		}
		if v.Offers == nil {
			v.Offers = map[string]Envelope{}
		}
		if v.Successors == nil {
			v.Successors = map[string]Envelope{}
		}
		if in.Pin != nil {
			v.Pin = &chainPinVec{Epoch: in.Pin.Epoch, Seq: in.Pin.Seq, Head: in.Pin.Head}
		}
		if c.err != nil {
			v.Error = chainErrorKind(t, c.err)
		} else {
			last := in.Records[len(in.Records)-1].Body
			v.Want = &chainWantVec{Head: BodyHash(last), Seq: c.seq, Epoch: c.epoch, Handovers: append([]int{}, c.handovers...)}
		}
		vs = append(vs, v)
	}
	return vs
}

// checkChainVectors runs every chain entry, as read back from JSON, through
// VerifyChain.
func checkChainVectors(t *testing.T, vs []chainVec) {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []chainVec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, v := range parsed {
		in := ChainInput{
			Artifact: v.Artifact, Records: v.Records, Owners: v.Owners, Offers: v.Offers, Successors: v.Successors,
			Anchor: v.Anchor, CurrentOwnerFP: v.CurrentOwnerFP,
		}
		if v.Pin != nil {
			in.Pin = &EpochPin{Epoch: v.Pin.Epoch, Seq: v.Pin.Seq, Head: v.Pin.Head}
		}
		got, err := VerifyChain(in)
		if v.Error != "" {
			if !errors.Is(err, chainErrorKinds[v.Error]) {
				t.Errorf("%s (%s): got %v, want %s", v.Name, v.Why, err, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s (%s): %v", v.Name, v.Why, err)
			continue
		}
		w := v.Want
		if got.Head != w.Head || got.Latest.Seq != w.Seq || got.Latest.Epoch != w.Epoch || !slices.Equal(got.Handovers, w.Handovers) {
			t.Errorf("%s: got head %s, seq %d, epoch %d, handovers %v; want %+v", v.Name, got.Head, got.Latest.Seq, got.Latest.Epoch, got.Handovers, *w)
		}
	}
}
