package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"unicode/utf8"
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

// ExcludedEntry is a user an owner removed, listed in the membership record
// so the same user can't be added back under another ID, key, or email.
type ExcludedEntry struct {
	User  string `json:"user"`
	FP    string `json:"fp"`
	Email string `json:"email"`
}

// MembershipBody is signed by the owner.
type MembershipBody struct {
	V            int             `json:"v"`
	Artifact     string          `json:"artifact"`
	Epoch        int             `json:"epoch"`
	Seq          int             `json:"seq"`
	Owner        string          `json:"owner"`
	OwnerFP      string          `json:"ownerFp"`
	AKCommit     string          `json:"akCommit"`
	Members      []Member        `json:"members"`
	Excluded     []ExcludedEntry `json:"excluded"`
	Team         string          `json:"team"`
	Public       bool            `json:"public"`
	PublicWrites bool            `json:"publicWrites"`
	Prev         string          `json:"prev"`
	Transfer     string          `json:"transfer"`
	Handover     string          `json:"handover"`
}

// TransferBody is signed by the current owner.
type TransferBody struct {
	V        int    `json:"v"`
	Artifact string `json:"artifact"`
	From     string `json:"from"`
	To       string `json:"to"`
	ToFP     string `json:"toFp"`
	Prev     string `json:"prev"`
}

// ApprovalBody is signed by the approving owner or editor.
type ApprovalBody struct {
	V        int    `json:"v"`
	Artifact string `json:"artifact"`
	Epoch    int    `json:"epoch"`
	User     string `json:"user"`
	FP       string `json:"fp"`
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
	V           int    `json:"v"`
	User        string `json:"user"`
	Seq         int    `json:"seq"`
	Successor   string `json:"successor"`
	SuccessorFP string `json:"successorFp"`
	Action      string `json:"action"`
}

// ResetBody is signed by the user, with their existing key.
type ResetBody struct {
	V     int    `json:"v"`
	User  string `json:"user"`
	Token string `json:"token"`
}

// RefusalBody is signed by the user, with their existing key. RequestedAt is
// the pending request's time exactly as the server sent it.
type RefusalBody struct {
	V           int    `json:"v"`
	User        string `json:"user"`
	RequestedAt string `json:"requestedAt"`
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

// BodyHash returns the lowercase hex SHA-256 of a signed body, the form the
// spec's prev, transfer, and manifest fields take.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
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
	if err := checkStrictBytes(data); err != nil {
		return err
	}
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
// object, at any depth, repeats a key, or if any JSON number in data isn't a
// non-negative integer lexeme at most 2^53-1 (see checkStrictNumber) — every
// number this package's wire format carries is a count, a revision, an
// epoch, or a size, never a fraction or anything requiring more precision
// than JavaScript's Number can hold exactly.
func checkNoDuplicateKeys(data []byte) error {
	type frame struct {
		isObject  bool
		expectKey bool
		seen      map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
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
		if num, ok := tok.(json.Number); ok {
			if err := checkStrictNumber(string(num)); err != nil {
				return err
			}
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

// strictNumberRe matches the only JSON number lexemes this package accepts:
// zero, or a non-zero digit followed by more digits. No sign, no fraction,
// and no exponent — those are all syntactically valid JSON numbers, so
// json.Decoder itself doesn't reject them, but none of this package's wire
// format ever needs one.
var strictNumberRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// maxSafeInteger is 2^53-1, the largest integer a float64 (and so a
// JavaScript Number) represents exactly. A wire format number above it could
// round-trip differently between Go and the browser.
const maxSafeInteger = (uint64(1) << 53) - 1

func checkStrictNumber(lexeme string) error {
	if !strictNumberRe.MatchString(lexeme) {
		return fmt.Errorf("%w: number %q is not a non-negative integer literal", ErrFormat, lexeme)
	}
	n, err := strconv.ParseUint(lexeme, 10, 64)
	if err != nil || n > maxSafeInteger {
		return fmt.Errorf("%w: number %q exceeds 2^53-1", ErrFormat, lexeme)
	}
	return nil
}

// checkStrictBytes refuses a leading UTF-8 BOM, invalid UTF-8, and an
// unpaired UTF-16 surrogate escape — none of which json.Unmarshal itself
// rejects: a BOM is a valid-but-unexpected character, invalid UTF-8 inside a
// string is silently accepted by Go's decoder, and an unpaired \uD800-\uDFFF
// escape is silently replaced with U+FFFD rather than rejected, any of which
// would let two different inputs decode to the same value.
func checkStrictBytes(data []byte) error {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return fmt.Errorf("%w: UTF-8 BOM", ErrFormat)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8", ErrFormat)
	}
	return checkNoLoneSurrogates(data)
}

// checkNoLoneSurrogates scans data for \uXXXX escapes inside JSON string
// literals and refuses a high surrogate (D800-DBFF) not immediately followed
// by a low surrogate (DC00-DFFF) escape, or a low surrogate not immediately
// preceded by one.
func checkNoLoneSurrogates(data []byte) error {
	inString := false
	n := len(data)
	for i := 0; i < n; {
		c := data[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			i++
			continue
		}
		switch c {
		case '"':
			inString = false
			i++
		case '\\':
			if i+1 >= n {
				return fmt.Errorf("%w: truncated escape", ErrFormat)
			}
			if data[i+1] != 'u' {
				i += 2
				continue
			}
			if i+6 > n {
				return fmt.Errorf("%w: truncated unicode escape", ErrFormat)
			}
			hi, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 32)
			if err != nil {
				return fmt.Errorf("%w: bad unicode escape", ErrFormat)
			}
			i += 6
			switch {
			case hi >= 0xD800 && hi <= 0xDBFF:
				if i+6 <= n && data[i] == '\\' && data[i+1] == 'u' {
					if lo, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 32); err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
						i += 6
						continue
					}
				}
				return fmt.Errorf("%w: unpaired high surrogate", ErrFormat)
			case hi >= 0xDC00 && hi <= 0xDFFF:
				return fmt.Errorf("%w: unpaired low surrogate", ErrFormat)
			}
		default:
			i++
		}
	}
	return nil
}

// OpenEnvelope and OpenRotation verify a signature and decode a body; that is
// all they do. Neither binds Signer to pub, binds a membership record's
// owner to the signer, binds a rotation's user/old to the key being rotated
// away from, or enforces a monotonic seq. The caller must do all of that —
// Signer is untrusted wire data, never a key lookup by itself — and must run
// CheckPublicKeys on any wrap recipient before trusting it. OpenRotation
// itself runs CheckPublicKeys on the new key pair, so a rotation to a
// malformed or low-order key is refused as ErrFormat even when both
// signatures verify.

// OpenEnvelope verifies env's signature against pub for purpose, strictly
// decodes its body into out, and requires the body's "v" field to be 1. It
// refuses purpose "rotation" with ErrFormat: a rotation also needs newSig,
// which only OpenRotation checks.
func OpenEnvelope(env Envelope, pub ed25519.PublicKey, purpose string, out any) error {
	if purpose == "rotation" {
		return fmt.Errorf("%w: open a rotation envelope with OpenRotation", ErrFormat)
	}
	return openEnvelope(env, pub, purpose, out)
}

func openEnvelope(env Envelope, pub ed25519.PublicKey, purpose string, out any) error {
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
	if err := openEnvelope(env, oldPub, "rotation", out); err != nil {
		return err
	}
	if len(env.NewSig) == 0 {
		return fmt.Errorf("%w: rotation envelope missing newSig", ErrFormat)
	}
	newX25519, err := UnB64(out.New.X25519)
	if err != nil {
		return err
	}
	newPub, err := UnB64(out.New.Ed25519)
	if err != nil {
		return err
	}
	if err := CheckPublicKeys(newX25519, newPub); err != nil {
		return err
	}
	if !Verify(newPub, "rotation", env.Body, env.NewSig) {
		return ErrDecrypt
	}
	return nil
}
