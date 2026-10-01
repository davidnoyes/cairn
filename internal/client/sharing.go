// Artifact creation and the membership and key reads. As in account.go,
// every byte of cryptography is built with internal/e2e; this file is wiring
// and HTTP.
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/google/uuid"
)

// UnlockedKeys is the caller's own key material, opened from the device API
// key. It never leaves the process.
type UnlockedKeys struct {
	UserID      string
	FP          string // hex fingerprint of the two public keys
	X25519Pub   []byte
	X25519Priv  []byte
	Ed25519Pub  []byte
	Ed25519Seed []byte
	EK          []byte
	// MKSealKey seals and opens the keyring.
	MKSealKey []byte
}

// Unlock opens the caller's keys: MK from the device key's own sealed copy,
// then the X25519 and Ed25519 private keys and EK under MK. The public keys
// are derived from the private ones, and a bundle whose published public
// keys differ is refused.
func (c *Client) Unlock() (*UnlockedKeys, error) {
	if c.Key == nil {
		return nil, errors.New("unlocking keys needs the full API key; this client holds only its bearer")
	}
	me, err := c.Me()
	if err != nil {
		return nil, err
	}
	var resp struct {
		bundleWire
		APIKey *struct {
			ID string `json:"id"`
			MK string `json:"mk"`
		} `json:"apiKey"`
	}
	if err := c.doJSON("GET", "/api/me/bundle", nil, &resp); err != nil {
		return nil, err
	}
	if resp.APIKey == nil {
		return nil, errors.New("the server returned no sealed MK for this API key")
	}
	sealedMK, err := e2e.UnB64(resp.APIKey.MK)
	if err != nil {
		return nil, err
	}
	mk, err := e2e.Open(e2e.APIKeyKEK(c.Key.KeySecret, c.Key.KeyID), [][]byte{[]byte("mk"), []byte(c.Key.KeyID)}, sealedMK)
	if err != nil {
		return nil, fmt.Errorf("opening MK with the API key: %w", err)
	}
	mkKey, err := e2e.MKSealKey(mk)
	if err != nil {
		return nil, err
	}
	k := &UnlockedKeys{UserID: me.ID, MKSealKey: mkKey}
	for _, f := range []struct {
		name   string
		sealed string
		out    *[]byte
	}{
		{"x25519", resp.X25519Priv, &k.X25519Priv},
		{"ed25519", resp.Ed25519Priv, &k.Ed25519Seed},
		{"ek", resp.EK, &k.EK},
	} {
		sealed, err := e2e.UnB64(f.sealed)
		if err != nil {
			return nil, err
		}
		if *f.out, err = e2e.Open(mkKey, [][]byte{[]byte(f.name)}, sealed); err != nil {
			return nil, fmt.Errorf("opening the %s key: %w", f.name, err)
		}
	}
	if _, k.X25519Pub, err = e2e.GenerateX25519(bytes.NewReader(k.X25519Priv)); err != nil {
		return nil, err
	}
	if _, k.Ed25519Pub, err = e2e.GenerateEd25519(bytes.NewReader(k.Ed25519Seed)); err != nil {
		return nil, err
	}
	if resp.X25519Pub != e2e.B64(k.X25519Pub) || resp.Ed25519Pub != e2e.B64(k.Ed25519Pub) {
		return nil, errors.New("the server's published public keys do not match this account's private keys")
	}
	k.FP = hex.EncodeToString(e2e.Fingerprint(k.X25519Pub, k.Ed25519Pub))
	return k, nil
}

// estateFields binds an estate copy of an AK to its artifact and epoch.
func estateFields(artifact string, epoch int) [][]byte {
	return [][]byte{[]byte("estate"), []byte(artifact), []byte(strconv.Itoa(epoch))}
}

// CreateArtifact creates a private artifact with no members, owned by the
// caller. It picks the id and the first AK itself, signs the first
// membership record, seals the estate copy of the AK under EK, and once the
// server accepts it reads the chain back and verifies it, anchored at the
// caller's own fingerprint.
func (c *Client) CreateArtifact(name, description string) (*store.Artifact, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	id := uuid.NewString()
	ak := make([]byte, 32)
	if _, err := rand.Read(ak); err != nil {
		return nil, err
	}
	commit, err := e2e.AKCommit(ak, id, 1)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(e2e.MembershipBody{
		V: 1, Artifact: id, Epoch: 1, Seq: 1, Owner: k.UserID, OwnerFP: k.FP, AKCommit: commit,
		Members: []e2e.Member{}, Excluded: []e2e.ExcludedEntry{}, Team: "none",
	})
	if err != nil {
		return nil, err
	}
	env, err := e2e.NewEnvelope(k.Ed25519Seed, k.UserID, "membership", body)
	if err != nil {
		return nil, err
	}
	ekKey, err := e2e.EKSealKey(k.EK)
	if err != nil {
		return nil, err
	}
	sealed, err := e2e.Seal(rand.Reader, ekKey, estateFields(id, 1), ak)
	if err != nil {
		return nil, err
	}
	var out store.Artifact
	if err := c.doJSON("POST", "/api/artifacts", map[string]any{
		"id": id, "name": name, "description": description, "membership": env,
		"wraps":  []any{},
		"estate": []map[string]any{{"epoch": 1, "sealed": e2e.B64(sealed)}},
	}, &out); err != nil {
		return nil, err
	}

	if _, err := c.VerifyArtifact(k, id, k.FP); err != nil {
		return nil, fmt.Errorf("artifact %s was created, but reading its membership back failed: %w", id, err)
	}
	return &out, nil
}

// Membership is an artifact's membership chain and the keys needed to check
// it, as GET /api/artifacts/{id}/membership returns them.
type Membership struct {
	Records    []e2e.Envelope            `json:"records"`
	Offers     map[string]e2e.Envelope   `json:"offers"`
	Owners     map[string]e2e.KeyPair    `json:"owners"`
	Rotations  map[string][]e2e.Envelope `json:"rotations"`
	Successors map[string]e2e.Envelope   `json:"successors"`
	// Keys is set only for a link holder: every listed editor's keys.
	Keys map[string]e2e.KeyPair `json:"keys,omitempty"`
}

func (c *Client) Membership(artifactID string) (*Membership, error) {
	var out Membership
	return &out, c.doJSON("GET", "/api/artifacts/"+artifactID+"/membership", nil, &out)
}

// KeyWrap is one of the caller's wrapped AKs.
type KeyWrap struct {
	Epoch   int
	Wrapped []byte
	FP      string // the fingerprint of the key it was wrapped to
}

// EstateCopy is an AK sealed under the owner's EK.
type EstateCopy struct {
	Epoch  int
	Sealed []byte
}

// ArtifactKeys is the caller's key material for one artifact: its own wraps,
// or for the owner the estate copies.
type ArtifactKeys struct {
	Wraps  []KeyWrap
	Estate []EstateCopy
}

func (c *Client) Keys(artifactID string) (*ArtifactKeys, error) {
	var resp struct {
		Wraps []struct {
			Epoch   int    `json:"epoch"`
			Wrapped string `json:"wrapped"`
			FP      string `json:"fp"`
		} `json:"wraps"`
		Estate []struct {
			Epoch  int    `json:"epoch"`
			Sealed string `json:"sealed"`
		} `json:"estate"`
	}
	if err := c.doJSON("GET", "/api/artifacts/"+artifactID+"/keys", nil, &resp); err != nil {
		return nil, err
	}
	out := &ArtifactKeys{}
	for _, w := range resp.Wraps {
		b, err := e2e.UnB64(w.Wrapped)
		if err != nil {
			return nil, err
		}
		out.Wraps = append(out.Wraps, KeyWrap{Epoch: w.Epoch, Wrapped: b, FP: w.FP})
	}
	for _, e := range resp.Estate {
		b, err := e2e.UnB64(e.Sealed)
		if err != nil {
			return nil, err
		}
		out.Estate = append(out.Estate, EstateCopy{Epoch: e.Epoch, Sealed: b})
	}
	return out, nil
}
