package e2e

import (
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Argon2id floor. Clients refuse parameters below this, so the server can
// raise them later without breaking existing accounts, but never lower them.
const (
	floorMemory  = 65536 // KiB
	floorTime    = 3
	floorSaltMin = 16
	floorSaltMax = 64
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

// CheckFloor refuses alg other than argon2id, m below 65536, t below 3, p
// outside 1 to 4, or a salt shorter than 16 bytes or longer than 64.
func (p Params) CheckFloor() error {
	if p.Alg != "argon2id" {
		return fmt.Errorf("%w: alg %q", ErrFloor, p.Alg)
	}
	if p.Memory < floorMemory {
		return fmt.Errorf("%w: memory %d below floor", ErrFloor, p.Memory)
	}
	if p.Time < floorTime {
		return fmt.Errorf("%w: time %d below floor", ErrFloor, p.Time)
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
func NewParams(rnd io.Reader) Params {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		panic(err)
	}
	return Params{Alg: "argon2id", Memory: floorMemory, Time: floorTime, Threads: 1, Salt: salt}
}

// Stretch runs Argon2id over the password, after checking p against the
// floor, producing 32 bytes.
func Stretch(password []byte, p Params) ([]byte, error) {
	if err := p.CheckFloor(); err != nil {
		return nil, err
	}
	return argon2.IDKey(password, p.Salt, p.Time, p.Memory, p.Threads, 32), nil
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
func NewRecoveryCode(rnd io.Reader) (code []byte, display string) {
	code = make([]byte, recoveryCodeBytes)
	if _, err := io.ReadFull(rnd, code); err != nil {
		panic(err)
	}
	return code, FormatRecoveryCode(code)
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

// ParseRecoveryCode parses a displayed recovery code, ignoring case, spaces,
// and hyphens, and failing on anything else.
func ParseRecoveryCode(s string) ([]byte, error) {
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
	b, err := base32Encoding.DecodeString(s)
	if err != nil || len(b) != recoveryCodeBytes {
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

// NewAPIKey generates a fresh API key.
func NewAPIKey(rnd io.Reader) (full, keyID, authSecret string, keySecret []byte) {
	idB := make([]byte, apiKeyIDBytes)
	authB := make([]byte, apiKeyAuthBytes)
	keyB := make([]byte, apiKeySecBytes)
	for _, b := range [][]byte{idB, authB, keyB} {
		if _, err := io.ReadFull(rnd, b); err != nil {
			panic(err)
		}
	}
	keyID = hex.EncodeToString(idB)
	authSecret = hex.EncodeToString(authB)
	keySecret = keyB
	full = apiKeyPrefix + keyID + "_" + authSecret + "_" + hex.EncodeToString(keyB)
	return
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
	if _, err := hex.DecodeString(keyID); err != nil {
		return APIKey{}, ErrFormat
	}
	if _, err := hex.DecodeString(authSecret); err != nil {
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
