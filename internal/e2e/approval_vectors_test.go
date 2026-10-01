package e2e

import (
	"encoding/json"
	"errors"
	"testing"
)

// approvalVec is one stored approval that CheckApproval and checkApproval
// must both accept (Error empty) or both refuse with the error kind in
// Error. Latest is the verified current membership record; keys are in the
// wire form the server serves them, so each side computes fingerprints
// itself.
type approvalVec struct {
	Name       string         `json:"name"`
	Why        string         `json:"why"`
	Artifact   string         `json:"artifact"`
	Latest     MembershipBody `json:"latest"`
	Approval   *Envelope      `json:"approval"`
	SignerKeys KeyPair        `json:"signerKeys"`
	User       ApprovalUser   `json:"user"`
	Directory  []ApprovalUser `json:"directory"`
	Error      string         `json:"error,omitempty"`
}

// approvalErrorKinds names each error CheckApproval returns, as the
// approval section spells it.
var approvalErrorKinds = map[string]error{
	"missing":   ErrApprovalMissing,
	"signer":    ErrApprovalSigner,
	"decrypt":   ErrDecrypt,
	"format":    ErrFormat,
	"mismatch":  ErrApprovalMismatch,
	"excluded":  ErrApprovalExcluded,
	"duplicate": ErrApprovalDuplicate,
}

func approvalErrorKind(t testing.TB, err error) string {
	t.Helper()
	for kind, sentinel := range approvalErrorKinds {
		if sentinel == err {
			return kind
		}
	}
	t.Fatalf("no error kind for %v", err)
	return ""
}

type approvalCase struct {
	name, why string
	err       error // nil when the approval passes all four checks
	build     func(t testing.TB, u approvalUsers) approvalVec
}

// approvalUsers are the people every approval case draws on: alice owns the
// artifact, bob is an editor, carol a viewer, dave is the team member being
// approved, and mallory is nobody.
type approvalUsers struct {
	alice, bob, carol, dave, mallory chainUser
	emails                           map[string]string
}

func newApprovalUsers(t testing.TB) approvalUsers {
	u := newChainUsers(t)
	return approvalUsers{alice: u.alice, bob: u.bob, carol: u.carol, dave: u.dave, mallory: u.mallory,
		emails: map[string]string{"u-alice": "alice@example.com", "u-bob": "bob@example.com",
			"u-carol": "carol@example.com", "u-dave": "dave@example.com", "u-mallory": "mallory@example.com"}}
}

func (u approvalUsers) apUser(c chainUser) ApprovalUser {
	return ApprovalUser{ID: c.id, Email: u.emails[c.id], Keys: c.keys}
}

func (u approvalUsers) directory() []ApprovalUser {
	var dir []ApprovalUser
	for _, c := range []chainUser{u.alice, u.bob, u.carol, u.dave, u.mallory} {
		dir = append(dir, u.apUser(c))
	}
	return dir
}

// baseApproval is alice's artifact at epoch 2, shared with the team as
// viewers, with bob an editor and carol a viewer, and dave approved by
// signer.
func (u approvalUsers) baseApproval(t testing.TB, signer chainUser) approvalVec {
	latest := MembershipBody{V: 1, Artifact: chainArtifact, Epoch: 2, Seq: 3, Owner: u.alice.id, OwnerFP: u.alice.fp,
		AKCommit: chainAKCommit(t, 2), Members: []Member{editor(u.bob), viewer(u.carol)}, Excluded: []ExcludedEntry{}, Team: "viewer"}
	v := approvalVec{Artifact: chainArtifact, Latest: latest, SignerKeys: signer.keys, User: u.apUser(u.dave), Directory: u.directory()}
	v.Approval = u.sign(t, signer, ApprovalBody{V: 1, Artifact: chainArtifact, Epoch: 2, User: u.dave.id, FP: u.dave.fp})
	return v
}

func (u approvalUsers) sign(t testing.TB, signer chainUser, b ApprovalBody) *Envelope {
	body, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return u.signRaw(t, signer, body)
}

func (u approvalUsers) signRaw(t testing.TB, signer chainUser, body []byte) *Envelope {
	env, err := NewEnvelope(signer.seed, signer.id, "approval", body)
	if err != nil {
		t.Fatal(err)
	}
	return &env
}

func approvalCases() []approvalCase {
	withExcluded := func(v approvalVec, x ExcludedEntry) approvalVec {
		v.Latest.Excluded = []ExcludedEntry{x}
		return v
	}
	return []approvalCase{
		{"owner-signed", "the owner's approval passes", nil, func(t testing.TB, u approvalUsers) approvalVec {
			return u.baseApproval(t, u.alice)
		}},
		{"editor-signed", "a listed editor's approval passes", nil, func(t testing.TB, u approvalUsers) approvalVec {
			return u.baseApproval(t, u.bob)
		}},
		{"approval-missing", "a server that serves no approval gets the user asked about", ErrApprovalMissing, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.Approval = nil
			return v
		}},
		{"signer-viewer", "a listed viewer cannot approve", ErrApprovalSigner, func(t testing.TB, u approvalUsers) approvalVec {
			return u.baseApproval(t, u.carol)
		}},
		{"signer-unlisted", "a user the record does not list cannot approve", ErrApprovalSigner, func(t testing.TB, u approvalUsers) approvalVec {
			return u.baseApproval(t, u.mallory)
		}},
		{"signer-key-not-listed-fp", "an editor's key that does not hash to the listed fp cannot approve", ErrApprovalSigner, func(t testing.TB, u approvalUsers) approvalVec {
			return u.baseApproval(t, newChainUser(t, "u-bob", "rotated"))
		}},
		{"signature-forged", "an approval signed by another key does not verify under the signer's", ErrDecrypt, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			forged := u.baseApproval(t, u.mallory).Approval
			forged.Signer = u.alice.id
			v.Approval = forged
			return v
		}},
		{"body-unknown-field", "a signed body with a field the format does not declare is refused", ErrFormat, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.Approval = u.signRaw(t, u.alice, []byte(`{"v":1,"artifact":"`+chainArtifact+`","epoch":2,"user":"`+u.dave.id+`","fp":"`+u.dave.fp+`","role":"editor"}`))
			return v
		}},
		{"other-artifact", "an approval for another artifact is not this one's", ErrApprovalMismatch, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.Approval = u.sign(t, u.alice, ApprovalBody{V: 1, Artifact: "artifact-other", Epoch: 2, User: u.dave.id, FP: u.dave.fp})
			return v
		}},
		{"old-epoch", "an approval for an earlier epoch is refused", ErrApprovalMismatch, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.Approval = u.sign(t, u.alice, ApprovalBody{V: 1, Artifact: chainArtifact, Epoch: 1, User: u.dave.id, FP: u.dave.fp})
			return v
		}},
		{"other-user", "an approval for another user is not this user's", ErrApprovalMismatch, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.Approval = u.sign(t, u.alice, ApprovalBody{V: 1, Artifact: chainArtifact, Epoch: 2, User: u.mallory.id, FP: u.dave.fp})
			return v
		}},
		{"other-fp", "an approval for another fingerprint is refused", ErrApprovalMismatch, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.Approval = u.sign(t, u.alice, ApprovalBody{V: 1, Artifact: chainArtifact, Epoch: 2, User: u.dave.id, FP: u.mallory.fp})
			return v
		}},
		{"served-keys-changed", "an approval of keys the server no longer serves for the user is refused", ErrApprovalMismatch, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.User.Keys = newChainUser(t, "u-dave", "reset").keys
			return v
		}},
		{"excluded-by-id", "an excluded entry for the user's ID blocks listing", ErrApprovalExcluded, func(t testing.TB, u approvalUsers) approvalVec {
			return withExcluded(u.baseApproval(t, u.alice), ExcludedEntry{User: u.dave.id, FP: u.mallory.fp, Email: "other@example.com"})
		}},
		{"excluded-by-fp", "an excluded entry for the user's fingerprint blocks listing", ErrApprovalExcluded, func(t testing.TB, u approvalUsers) approvalVec {
			return withExcluded(u.baseApproval(t, u.alice), ExcludedEntry{User: "u-zed", FP: u.dave.fp, Email: "zed@example.com"})
		}},
		{"excluded-by-email", "an excluded entry for the user's normalized email blocks listing", ErrApprovalExcluded, func(t testing.TB, u approvalUsers) approvalVec {
			return withExcluded(u.baseApproval(t, u.alice), ExcludedEntry{User: "u-zed", FP: u.mallory.fp, Email: "dave@example.com"})
		}},
		{"excluded-by-email-case", "the email match is on the normalized form", ErrApprovalExcluded, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.User.Email = " Dave@Example.COM "
			return withExcluded(v, ExcludedEntry{User: "u-zed", FP: u.mallory.fp, Email: "dave@example.com"})
		}},
		{"excluded-unrelated", "an excluded entry that matches nothing about the user does not block", nil, func(t testing.TB, u approvalUsers) approvalVec {
			return withExcluded(u.baseApproval(t, u.alice), ExcludedEntry{User: "u-zed", FP: u.mallory.fp, Email: "zed@example.com"})
		}},
		{"directory-shares-email", "another user ID with the same normalized email blocks listing", ErrApprovalDuplicate, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.Directory = append(v.Directory, ApprovalUser{ID: "u-dave2", Email: "DAVE@example.com", Keys: newChainUser(t, "u-dave2", "").keys})
			return v
		}},
		{"directory-shares-fp", "another user ID with the same fingerprint blocks listing", ErrApprovalDuplicate, func(t testing.TB, u approvalUsers) approvalVec {
			v := u.baseApproval(t, u.alice)
			v.Directory = append(v.Directory, ApprovalUser{ID: "u-dave2", Email: "dave2@example.com", Keys: u.dave.keys})
			return v
		}},
	}
}

func approvalVectors(t testing.TB) []approvalVec {
	t.Helper()
	u := newApprovalUsers(t)
	var vs []approvalVec
	for _, c := range approvalCases() {
		v := c.build(t, u)
		v.Name, v.Why = c.name, c.why
		if c.err != nil {
			v.Error = approvalErrorKind(t, c.err)
		}
		vs = append(vs, v)
	}
	return vs
}

func (v approvalVec) input() ApprovalInput {
	return ApprovalInput{Artifact: v.Artifact, Latest: &v.Latest, Approval: v.Approval, SignerKeys: v.SignerKeys, User: v.User, Directory: v.Directory}
}

// checkApprovalVectors runs every approval entry, as read back from JSON,
// through CheckApproval.
func checkApprovalVectors(t *testing.T, vs []approvalVec) {
	t.Helper()
	raw, err := json.Marshal(vs)
	if err != nil {
		t.Fatal(err)
	}
	var parsed []approvalVec
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, v := range parsed {
		err := CheckApproval(v.input())
		if v.Error != "" {
			if !errors.Is(err, approvalErrorKinds[v.Error]) {
				t.Errorf("%s (%s): got %v, want %s", v.Name, v.Why, err, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s (%s): %v", v.Name, v.Why, err)
		}
	}
}

func TestCheckApproval(t *testing.T) {
	u := newApprovalUsers(t)
	for _, c := range approvalCases() {
		t.Run(c.name, func(t *testing.T) {
			err := CheckApproval(c.build(t, u).input())
			if c.err == nil {
				if err != nil {
					t.Fatalf("%s: %v", c.why, err)
				}
				return
			}
			if !errors.Is(err, c.err) {
				t.Fatalf("%s: got %v, want %v", c.why, err, c.err)
			}
		})
	}
}

func TestExcludedMatch(t *testing.T) {
	x := []ExcludedEntry{{User: "u-1", FP: "aa", Email: "a@example.com"}}
	for _, c := range []struct {
		name         string
		id, fp, mail string
		want         bool
	}{
		{"by id", "u-1", "bb", "b@example.com", true},
		{"by fp", "u-2", "aa", "b@example.com", true},
		{"by normalized email", "u-2", "bb", " A@Example.com", true},
		{"no match", "u-2", "bb", "b@example.com", false},
	} {
		if got := ExcludedMatch(x, c.id, c.fp, c.mail) != nil; got != c.want {
			t.Errorf("%s: match = %v, want %v", c.name, got, c.want)
		}
	}
	// A signed record may carry the email as the directory spelled it, so the
	// stored side is normalized too.
	stored := []ExcludedEntry{{User: "u-1", FP: "aa", Email: " A@Example.COM"}}
	if ExcludedMatch(stored, "u-2", "bb", "a@example.com") == nil {
		t.Error("an excluded entry with an unnormalized email did not match")
	}
}
