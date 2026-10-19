package e2e

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestGroupCasesFailForTheirOwnReason runs every group vector and requires a
// refusal to name the rule the case breaks, so a case cannot pass by
// tripping another check.
func TestGroupCasesFailForTheirOwnReason(t *testing.T) {
	reasons := map[string]string{
		"no-records":                          "no group records",
		"first-signer-is-member":              "does not list its signer",
		"first-signer-not-listed":             "does not list its signer",
		"first-signer-fp-differs":             "under another fp than signerFp",
		"signer-key-of-another-user":          "belongs to \"u-bob\"",
		"first-record-seq-2":                  "first record has seq 2",
		"first-record-has-prev":               "first record has a prev",
		"group-id-not-a-uuid":                 "not a lowercase UUID",
		"group-id-asked-for-differs":          "record for group",
		"signer-not-listed":                   "does not list \"u-mallory\" as a manager",
		"signer-is-member":                    "does not list \"u-carol\" as a manager",
		"signer-key-not-linked":               "signerFp does not follow",
		"signer-key-missing":                  "no signer key",
		"forged-signature":                    "decrypt",
		"signer-differs-from-envelope-signer": "the envelope's signer",
		"skipped-seq":                         "seq 3 follows 1",
		"repeated-seq":                        "seq 1 follows 1",
		"wrong-prev":                          "prev is not the previous record's hash",
		"group-id-changes":                    "record for group",
		"members-unsorted":                    "not sorted by user ID",
		"duplicate-user":                      "lists user \"u-carol\" twice",
		"no-manager-left":                     "lists no manager",
		"bad-role":                            "has role \"owner\"",
		"member-fp-malformed":                 "fp is not 64 lowercase hex digits",
		"no-members":                          "has 0 members",
		"members-1001":                        "has 1001 members",
		"name-empty":                          "is 0 code points",
		"name-101-code-points":                "is 101 code points",
		"name-newline":                        "U+000A",
		"name-c1-control":                     "U+0085",
		"name-delete":                         "U+007F",
		"unknown-body-key":                    "unknown field",
		"body-version-2":                      "body version 2",
		"signer-fp-missing":                   "round-trip",
		"rollback":                            "rolled back",
		"fork":                                "forked",
		"pin-seq-zero":                        "pinned seq 0",
	}
	u := newChainUsers(t)
	for _, c := range groupCases() {
		in := c.build(t, u)
		if c.rotations != nil {
			in.Linked = RotationLinker(c.rotations(t, u))
		}
		_, err := VerifyGroupChain(in)
		if c.err == nil {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			if _, ok := reasons[c.name]; ok {
				t.Errorf("%s is valid but has a refusal reason", c.name)
			}
			continue
		}
		if !errors.Is(err, c.err) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.err)
			continue
		}
		if got := GroupRule(err); got != c.rule || c.rule == "" {
			t.Errorf("%s: refused under rule %q, want %q", c.name, got, c.rule)
		}
		want, ok := reasons[c.name]
		if !ok {
			t.Errorf("%s: no reason listed", c.name)
			continue
		}
		msg := err.Error()
		if c.err == ErrDecrypt {
			msg = "decrypt"
		}
		if !strings.Contains(msg, want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, want)
		}
	}
}

// A chain verifies to the records' own contents: every body, the latest, and
// the head the keyring stores.
func TestVerifyGroupChainResult(t *testing.T) {
	u := newChainUsers(t)
	f := threeRecords(t, u)
	c, err := VerifyGroupChain(f.input())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Bodies) != 3 || c.Latest.Seq != 3 || c.Latest.Name != "Release reviewers" || len(c.Latest.Members) != 4 {
		t.Errorf("chain = %d bodies, latest %+v", len(c.Bodies), c.Latest)
	}
	if c.Head != f.head(3) {
		t.Errorf("Head = %s, want %s", c.Head, f.head(3))
	}
	if c.Bodies[0].Name != "Reviewers" || len(c.Bodies[0].Members) != 1 {
		t.Errorf("first body = %+v", c.Bodies[0])
	}
}

// The keyring's groups entry is left out while empty, parsed when present,
// copied by Clone, set by SetGroup, and checked by Check.
func TestKeyringGroups(t *testing.T) {
	k := NewKeyring()
	out, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "groups") {
		t.Errorf("an empty keyring marshals as %s, want no groups key", out)
	}
	if err := DecodeStrict(out, &Keyring{}); err != nil {
		t.Errorf("a keyring without groups: %v", err)
	}

	u := newChainUsers(t)
	f := threeRecords(t, u)
	chain, err := VerifyGroupChain(f.input())
	if err != nil {
		t.Fatal(err)
	}
	k.SetGroup(groupID, chain)
	if p := k.GroupPin(groupID); p == nil || *p != (GroupPin{Seq: 3, Head: f.head(3)}) {
		t.Errorf("GroupPin = %+v", p)
	}
	if k.GroupPin(otherGroupID) != nil {
		t.Error("GroupPin for another group is not nil")
	}
	clone := k.Clone()
	clone.Groups[otherGroupID] = GroupPin{Seq: 1, Head: f.head(1)}
	if len(k.Groups) != 1 {
		t.Error("Clone shares the groups map")
	}
	out, err = json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var back Keyring
	if err := DecodeStrict(out, &back); err != nil {
		t.Fatalf("a keyring with groups: %v", err)
	}
	if back.Groups[groupID] != k.Groups[groupID] {
		t.Errorf("round trip = %+v", back.Groups)
	}
	if err := back.Check(); err != nil {
		t.Errorf("Check: %v", err)
	}
	for name, p := range map[string]GroupPin{"seq 0": {Seq: 0, Head: f.head(1)}, "short head": {Seq: 1, Head: "abc"}} {
		bad := k.Clone()
		bad.Groups[groupID] = p
		if err := bad.Check(); !errors.Is(err, ErrFormat) {
			t.Errorf("Check with %s: %v, want ErrFormat", name, err)
		}
	}
}

// A body that names its signer as a different user than the envelope does is
// refused even when the signature verifies, which TestGroupCasesFailForTheirOwnReason
// shows; here the same body under the right envelope signer is accepted.
func TestGroupEnvelopeSignerMatches(t *testing.T) {
	u := newChainUsers(t)
	in := newGroup(t, u.alice, "Reviewers", []GroupMember{gmanager(u.alice)}, nil).input()
	if _, err := VerifyGroupChain(in); err != nil {
		t.Fatal(err)
	}
	in.Records[0].Signer = "u-bob"
	if _, err := VerifyGroupChain(in); !errors.Is(err, ErrChain) {
		t.Errorf("a changed envelope signer: %v, want ErrChain", err)
	}
}
