package e2e

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

// Purpose bodies. Every field a verifier doesn't recognize, every duplicate
// key, and every field missing from the JSON the struct declares is a
// rejection: see DecodeStrict. None of these structs use `omitempty`,
// because a zero-valued field that round-trips back into the JSON is exactly
// how a missing field is caught.

type KeyPair struct {
	X25519  string `json:"x25519"`
	Ed25519 string `json:"ed25519"`
}

type Member struct {
	User string `json:"user"`
	Role string `json:"role"`
	FP   string `json:"fp"`
}

// MembershipBody is signed by the owner.
type MembershipBody struct {
	V            int      `json:"v"`
	Artifact     string   `json:"artifact"`
	Epoch        int      `json:"epoch"`
	Owner        string   `json:"owner"`
	AKCommit     string   `json:"akCommit"`
	Members      []Member `json:"members"`
	Team         string   `json:"team"`
	Public       bool     `json:"public"`
	PublicWrites bool     `json:"publicWrites"`
	Prev         string   `json:"prev"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	Blob   string `json:"blob"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ManifestBody is signed by whoever pushed.
type ManifestBody struct {
	V        int            `json:"v"`
	Artifact string         `json:"artifact"`
	Version  string         `json:"version"`
	Epoch    int            `json:"epoch"`
	Files    []ManifestFile `json:"files"`
}

// RevisionBody is signed by whoever wrote the database.
type RevisionBody struct {
	V        int    `json:"v"`
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
	Revision int    `json:"revision"`
	Epoch    int    `json:"epoch"`
	SHA256   string `json:"sha256"`
}

// VouchBody is signed by the owner.
type VouchBody struct {
	V        int    `json:"v"`
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
	Manifest string `json:"manifest"`
}

// RotationBody is signed by the old signing key, and again (as Envelope's
// NewSig) by the new one: see SignRotation and OpenRotation.
type RotationBody struct {
	V    int     `json:"v"`
	User string  `json:"user"`
	Seq  int     `json:"seq"`
	Old  KeyPair `json:"old"`
	New  KeyPair `json:"new"`
}

// SuccessorBody is signed by the user.
type SuccessorBody struct {
	V         int    `json:"v"`
	User      string `json:"user"`
	Seq       int    `json:"seq"`
	Successor string `json:"successor"`
	Action    string `json:"action"`
}

// ResetBody is signed by the user, with their existing key.
type ResetBody struct {
	V     int    `json:"v"`
	User  string `json:"user"`
	Token string `json:"token"`
}

// RecordBody covers a stored file, a file-meta record, or a meta blob.
type RecordBody struct {
	V        int    `json:"v"`
	Artifact string `json:"artifact"`
	Version  string `json:"version"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Epoch    int    `json:"epoch"`
	SHA256   string `json:"sha256"`
}

// bodyVersion is read out of a decoded body to check it against the "v":1
// rule, without requiring every body struct to implement an interface.
type bodyVersion struct {
	V int `json:"v"`
}

// DecodeStrict decodes data into out, refusing anything json.Unmarshal would
// silently accept: a duplicate key at any depth, a field out does not
// declare, trailing data after the JSON value, and — the one none of the
// above catches — a key that differs from a declared field only in case
// (such as "Files" next to "files"). Go's own decoder resolves that
// case-insensitively onto the same field, so DisallowUnknownFields alone
// does not see it as unknown. It's caught here by re-marshaling out and
// comparing it, as a generic JSON value, against the original: a case
// variant (or any other field) decoded away by one side and not thrown away
// by the other makes the two values differ.
func DecodeStrict(data []byte, out any) error {
	if err := checkNoDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after JSON value", ErrFormat)
	}
	again, err := json.Marshal(out)
	if err != nil {
		return err
	}
	var original, roundTripped any
	if err := json.Unmarshal(data, &original); err != nil {
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if err := json.Unmarshal(again, &roundTripped); err != nil {
		return err
	}
	if !reflect.DeepEqual(original, roundTripped) {
		return fmt.Errorf("%w: decoded value does not round-trip (case-variant or extra field)", ErrFormat)
	}
	return nil
}

// checkNoDuplicateKeys walks data token by token and fails if any JSON
// object, at any depth, repeats a key.
func checkNoDuplicateKeys(data []byte) error {
	type frame struct {
		isObject  bool
		expectKey bool
		seen      map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*frame
	closeContainer := func() {
		stack = stack[:len(stack)-1]
		if len(stack) > 0 && stack[len(stack)-1].isObject {
			stack[len(stack)-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrFormat, err)
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, &frame{isObject: true, expectKey: true, seen: map[string]bool{}})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				closeContainer()
			}
			continue
		}
		if len(stack) == 0 {
			continue // a bare top-level scalar
		}
		top := stack[len(stack)-1]
		if top.isObject && top.expectKey {
			key := tok.(string)
			if top.seen[key] {
				return fmt.Errorf("%w: duplicate key %q", ErrFormat, key)
			}
			top.seen[key] = true
			top.expectKey = false
		} else if top.isObject {
			top.expectKey = true
		}
	}
	return nil
}

// OpenEnvelope verifies env's signature against pub for purpose, strictly
// decodes its body into out, and requires the body's "v" field to be 1.
func OpenEnvelope(env Envelope, pub ed25519.PublicKey, purpose string, out any) error {
	if !Verify(pub, purpose, env.Body, env.Sig) {
		return ErrDecrypt
	}
	if err := DecodeStrict(env.Body, out); err != nil {
		return err
	}
	var v bodyVersion
	if err := json.Unmarshal(env.Body, &v); err != nil {
		return err
	}
	if v.V != 1 {
		return fmt.Errorf("%w: body version %d, want 1", ErrFormat, v.V)
	}
	return nil
}

// SignRotation signs a rotation body with the old signing key, and again
// with the new one, producing the envelope and NewSig the wire format
// requires.
func SignRotation(oldSeed, newSeed, body []byte, signer string) (Envelope, error) {
	env, err := NewEnvelope(oldSeed, signer, "rotation", body)
	if err != nil {
		return Envelope{}, err
	}
	newSig, err := Sign(newSeed, "rotation", body)
	if err != nil {
		return Envelope{}, err
	}
	env.NewSig = newSig
	return env, nil
}

// OpenRotation verifies both of a rotation envelope's signatures: env.Sig
// against oldPub, and env.NewSig against the new Ed25519 key named inside
// the body itself, so a rotation can't be accepted without proof of control
// over both the key it moves from and the key it moves to.
func OpenRotation(env Envelope, oldPub ed25519.PublicKey, out *RotationBody) error {
	if err := OpenEnvelope(env, oldPub, "rotation", out); err != nil {
		return err
	}
	if len(env.NewSig) == 0 {
		return fmt.Errorf("%w: rotation envelope missing newSig", ErrFormat)
	}
	newPub, err := UnB64(out.New.Ed25519)
	if err != nil {
		return err
	}
	if !Verify(newPub, "rotation", env.Body, env.NewSig) {
		return ErrDecrypt
	}
	return nil
}
