package e2e

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Argon2id floor and ceiling. Clients refuse parameters below the floor, so
// the server can raise them later without breaking existing accounts, but
// never lower them. The ceiling catches a server (malicious or broken) trying
// to force a client into a denial-of-service-sized Argon2id run.
const (
	floorMemory   = 65536 // KiB
	floorTime     = 3
	floorSaltMin  = 16
	floorSaltMax  = 64
	ceilingMemory = 1048576 // KiB
	ceilingTime   = 10
)

// Params are the Argon2id parameters the server stores per user and returns
// from prelogin.
type Params struct {
	Alg     string
	Memory  uint32
	Time    uint32
	Threads uint8
	Salt    []byte
}

type paramsJSON struct {
	Alg     string `json:"alg"`
	Memory  uint32 `json:"m"`
	Time    uint32 `json:"t"`
	Threads uint8  `json:"p"`
	Salt    string `json:"salt"`
}

// MarshalJSON encodes Salt as base64url without padding, matching the
// prelogin JSON in the wire-format spec.
func (p Params) MarshalJSON() ([]byte, error) {
	return json.Marshal(paramsJSON{p.Alg, p.Memory, p.Time, p.Threads, B64(p.Salt)})
}

func (p *Params) UnmarshalJSON(data []byte) error {
	var aux paramsJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	salt, err := UnB64(aux.Salt)
	if err != nil {
		return err
	}
	*p = Params{aux.Alg, aux.Memory, aux.Time, aux.Threads, salt}
	return nil
}

// CheckFloor refuses alg other than argon2id, m below 65536 or above
// 1048576, t below 3 or above 10, p outside 1 to 4, or a salt shorter than 16
// bytes or longer than 64.
func (p Params) CheckFloor() error {
	if p.Alg != "argon2id" {
		return fmt.Errorf("%w: alg %q", ErrFloor, p.Alg)
	}
	if p.Memory < floorMemory {
		return fmt.Errorf("%w: memory %d below floor", ErrFloor, p.Memory)
	}
	if p.Memory > ceilingMemory {
		return fmt.Errorf("%w: memory %d above ceiling", ErrFloor, p.Memory)
	}
	if p.Time < floorTime {
		return fmt.Errorf("%w: time %d below floor", ErrFloor, p.Time)
	}
	if p.Time > ceilingTime {
		return fmt.Errorf("%w: time %d above ceiling", ErrFloor, p.Time)
	}
	if p.Threads < 1 || p.Threads > 4 {
		return fmt.Errorf("%w: threads %d out of range", ErrFloor, p.Threads)
	}
	if len(p.Salt) < floorSaltMin || len(p.Salt) > floorSaltMax {
		return fmt.Errorf("%w: salt length %d out of range", ErrFloor, len(p.Salt))
	}
	return nil
}

// NewParams returns floor Argon2id parameters with a fresh 16-byte salt.
func NewParams(rnd io.Reader) (Params, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return Params{}, err
	}
	return Params{Alg: "argon2id", Memory: floorMemory, Time: floorTime, Threads: 1, Salt: salt}, nil
}

// NormalizeEmail trims ASCII whitespace and lowercases ASCII letters only. It
// deliberately does not use strings.ToLower: Unicode case mapping can map
// different source bytes to the same lowercase form in ways that diverge
// between Go and the browser's JavaScript, which would let two different
// addresses collide on one salt. Only plain ASCII folding is guaranteed to
// agree on both sides.
func NormalizeEmail(s string) string {
	s = strings.Trim(s, " \t\n\r\f\v")
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// ArgonSalt derives the Argon2id salt actually used to stretch a password,
// binding it to the account's normalized email as well as the server-issued
// serverSalt. This stops a server from handing two different users the same
// salt, which would let it test one user's password against another's hash.
func ArgonSalt(email string, serverSalt []byte) []byte {
	sum := sha256.Sum256(Enc([]byte(LabelSalt), []byte(NormalizeEmail(email)), serverSalt))
	return sum[:]
}

// Stretch runs Argon2id over the password, after checking p against the
// floor and ceiling, using the identity-bound salt derived from email and
// p.Salt, producing 32 bytes.
func Stretch(password []byte, email string, p Params) ([]byte, error) {
	if err := p.CheckFloor(); err != nil {
		return nil, err
	}
	salt := ArgonSalt(email, p.Salt)
	return argon2Key(password, salt, p.Time, p.Memory, p.Threads, 32), nil
}

// argon2Key is the Argon2id call Stretch makes; UseFastKDFForTests swaps it.
var argon2Key = argon2.IDKey

// UseFastKDFForTests replaces Argon2id in Stretch with a cheap deterministic
// stand-in, so test suites that sign up many users do not pay for a
// floor-parameter run each time: under the race detector one takes over a
// second. It never weakens the floor check, which Stretch runs before the
// call. The stand-in depends on every input but is not a password hash, so it
// panics outside a test binary.
func UseFastKDFForTests() {
	if !testing.Testing() {
		panic("e2e: UseFastKDFForTests called outside a test binary")
	}
	argon2Key = fastKDF
}

// fastKDF is SHA-256 over the length-prefixed inputs, counter-expanded or
// truncated to keyLen.
func fastKDF(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], time)
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], memory)
	var k [4]byte
	binary.BigEndian.PutUint32(k[:], keyLen)
	in := Enc(password, salt, n[:], m[:], []byte{threads}, k[:])
	out := make([]byte, 0, keyLen+sha256.Size)
	for ctr := byte(0); uint32(len(out)) < keyLen; ctr++ {
		out = append(out, sha256Sum(append([]byte{ctr}, in...))...)
	}
	return out[:keyLen]
}

// PasswordKeys derives authKey, sent to the server, and kek, which never
// leaves the client, from the stretched password.
func PasswordKeys(stretched []byte) (authKey, kek []byte) {
	authKey = Derive(stretched, nil, LabelAuth)
	kek = Derive(stretched, nil, LabelKEK)
	return
}

// Recovery codes: 16 random bytes shown as base32 groups.

const recoveryCodeBytes = 16

// NewRecoveryCode generates a recovery code and its display form.
func NewRecoveryCode(rnd io.Reader) (code []byte, display string, err error) {
	code = make([]byte, recoveryCodeBytes)
	if _, err := io.ReadFull(rnd, code); err != nil {
		return nil, "", err
	}
	return code, FormatRecoveryCode(code), nil
}

// FormatRecoveryCode renders a recovery code as uppercase base32 in groups
// of four separated by hyphens.
func FormatRecoveryCode(code []byte) string {
	enc := base32Encoding.EncodeToString(code)
	var groups []string
	for i := 0; i < len(enc); i += 4 {
		end := min(i+4, len(enc))
		groups = append(groups, enc[i:end])
	}
	return strings.Join(groups, "-")
}

// isRecoveryCodeByte reports whether b is a byte ParseRecoveryCode accepts:
// ASCII letters, the digits 2-7, a space, or a hyphen. Checking this before
// any case folding means a non-ASCII letter that some locale's uppercasing
// would otherwise fold onto an allowed letter (the long s "ſ", Turkish
// dotless "ı", German "ß", or the Kelvin sign "K") is rejected outright
// instead of silently accepted.
func isRecoveryCodeByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '2' && b <= '7') || b == '-' || b == ' '
}

// base32Value returns the 5-bit value of a base32 alphabet character.
func base32Value(c byte) (int, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A'), true
	case c >= '2' && c <= '7':
		return int(c-'2') + 26, true
	}
	return 0, false
}

// ParseRecoveryCode parses a displayed recovery code, ignoring case, spaces,
// and hyphens, and failing on anything else. It also rejects an encoding
// whose unused trailing bits are not zero: 16 bytes is 128 bits, which
// base32 spreads over 26 characters (130 bits), so the last character's low
// 2 bits carry no data and a non-zero value there is not a code this package
// ever produced.
func ParseRecoveryCode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if !isRecoveryCodeByte(s[i]) {
			return nil, ErrFormat
		}
	}
	s = strings.ToUpper(s)
	s = strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, s)
	wantLen := base32Encoding.EncodedLen(recoveryCodeBytes)
	if len(s) != wantLen {
		return nil, ErrFormat
	}
	last, ok := base32Value(s[len(s)-1])
	if !ok || last&0x03 != 0 {
		return nil, ErrFormat
	}
	b, err := base32Encoding.DecodeString(s)
	if err != nil || len(b) != recoveryCodeBytes {
		return nil, ErrFormat
	}
	return b, nil
}

// Successor codes: the first 10 bytes of a fingerprint, shown as four groups
// of four base32 characters. 80 bits leave no unused trailing bits, so unlike
// a recovery code there is no trailing-bit check.

const successorCodeBytes = 10

// SuccessorCode renders the first 10 bytes of a fingerprint as a successor
// code, in the shape XXXX-XXXX-XXXX-XXXX.
func SuccessorCode(fp []byte) string {
	return FormatRecoveryCode(fp[:successorCodeBytes])
}

// ParseSuccessorCode parses a displayed successor code by the recovery
// code's character rules and returns the 10 bytes it names. Anything but 16
// characters after the spaces and hyphens are dropped is refused.
func ParseSuccessorCode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if !isRecoveryCodeByte(s[i]) {
			return nil, ErrFormat
		}
	}
	s = strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToUpper(s))
	if len(s) != base32Encoding.EncodedLen(successorCodeBytes) {
		return nil, ErrFormat
	}
	b, err := base32Encoding.DecodeString(s)
	if err != nil || len(b) != successorCodeBytes {
		return nil, ErrFormat
	}
	return b, nil
}

// RecoveryKEK derives the key that seals MK under the recovery code.
func RecoveryKEK(code []byte) []byte {
	return Derive(code, nil, LabelRecovery)
}

// API keys: cairn_<keyid>_<authSecret>_<keySecret>, each part in hex, so the
// underscore separator never appears inside a part.

const apiKeyPrefix = "cairn_"

const (
	apiKeyIDBytes   = 8
	apiKeyAuthBytes = 16
	apiKeySecBytes  = 32
)

// APIKey holds a parsed or generated API key's parts.
type APIKey struct {
	Full       string
	KeyID      string
	AuthSecret string
	KeySecret  []byte
}

// String redacts keySecret, so an APIKey never leaks its full secret through
// a log line or an error message formatted with %v or %s. The Full field
// holds the complete presentable key, including keySecret, for when it's
// genuinely needed; its name says so explicitly.
func (k APIKey) String() string {
	return apiKeyPrefix + k.KeyID + "_" + k.AuthSecret + "_…"
}

// NewAPIKey generates a fresh API key.
func NewAPIKey(rnd io.Reader) (full, keyID, authSecret string, keySecret []byte, err error) {
	idB := make([]byte, apiKeyIDBytes)
	authB := make([]byte, apiKeyAuthBytes)
	keyB := make([]byte, apiKeySecBytes)
	for _, b := range [][]byte{idB, authB, keyB} {
		if _, err := io.ReadFull(rnd, b); err != nil {
			return "", "", "", nil, err
		}
	}
	keyID = hex.EncodeToString(idB)
	authSecret = hex.EncodeToString(authB)
	keySecret = keyB
	full = apiKeyPrefix + keyID + "_" + authSecret + "_" + hex.EncodeToString(keyB)
	return full, keyID, authSecret, keySecret, nil
}

// isLowerHex reports whether s is non-empty and every byte is a lowercase
// hex digit. hex.DecodeString accepts uppercase too, which would let two
// different-looking strings decode to the same bytes; API keys must have one
// canonical form.
func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ParseAPIKey splits a presented full API key into its parts.
func ParseAPIKey(full string) (APIKey, error) {
	rest, ok := strings.CutPrefix(full, apiKeyPrefix)
	if !ok {
		return APIKey{}, ErrFormat
	}
	parts := strings.Split(rest, "_")
	if len(parts) != 3 {
		return APIKey{}, ErrFormat
	}
	keyID, authSecret, keySecretHex := parts[0], parts[1], parts[2]
	if len(keyID) != 2*apiKeyIDBytes || len(authSecret) != 2*apiKeyAuthBytes || len(keySecretHex) != 2*apiKeySecBytes {
		return APIKey{}, ErrFormat
	}
	if !isLowerHex(keyID) || !isLowerHex(authSecret) || !isLowerHex(keySecretHex) {
		return APIKey{}, ErrFormat
	}
	keySecret, err := hex.DecodeString(keySecretHex)
	if err != nil {
		return APIKey{}, ErrFormat
	}
	return APIKey{full, keyID, authSecret, keySecret}, nil
}

// APIKeyKEK derives the key that seals the API key's copy of MK.
func APIKeyKEK(keySecret []byte, keyID string) []byte {
	return Derive(keySecret, nil, LabelAPIKey, []byte(keyID))
}

// APIKeyAuthHash is what the server stores for authSecret: the hash of the
// hex string itself, not of the bytes it decodes to, matching the wire
// format.
func APIKeyAuthHash(authSecretHex string) string {
	sum := sha256.Sum256([]byte(authSecretHex))
	return hex.EncodeToString(sum[:])
}
