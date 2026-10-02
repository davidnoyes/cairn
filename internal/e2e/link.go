package e2e

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ErrStaleLink means the link is for an epoch older than the artifact's
// latest. The owner shares a new link.
var ErrStaleLink = errors.New("e2e: the link is for an older epoch than the artifact's current one")

// maxLinkEpoch is the largest epoch a link carries: the largest integer a
// JavaScript number holds exactly.
const maxLinkEpoch = 1<<53 - 1

// Link is a public link's parts: the host it points at, the artifact, the
// artifact key of the epoch, the epoch, and the fingerprint of the owner of
// the artifact's first membership record.
type Link struct {
	Host     string
	Artifact string
	AK       []byte
	Epoch    int
	Owner    string // hex
}

// PublicLink builds <host>/shared/<artifact>#k=<b64(ak)>&e=<epoch>&o=<owner>.
// The key is in the fragment, which a browser never sends to the server. A
// trailing slash on host is dropped. It refuses, with ErrFormat, a part
// ParseLink would refuse.
func PublicLink(host, artifact string, ak []byte, epoch int, owner string) (string, error) {
	host = strings.TrimSuffix(host, "/")
	l := Link{Host: host, Artifact: artifact, AK: ak, Epoch: epoch, Owner: owner}
	if err := l.check(); err != nil {
		return "", err
	}
	return host + "/shared/" + artifact + "#k=" + B64(ak) + "&e=" + strconv.Itoa(epoch) + "&o=" + owner, nil
}

func (l Link) check() error {
	switch {
	case !isLinkHost(l.Host):
		return fmt.Errorf("%w: link host %q", ErrFormat, l.Host)
	case !isUUID(l.Artifact):
		return fmt.Errorf("%w: link artifact %q is not a lowercase UUID", ErrFormat, l.Artifact)
	case len(l.AK) != 32:
		return fmt.Errorf("%w: link key is %d bytes, not 32", ErrFormat, len(l.AK))
	case l.Epoch < 1 || l.Epoch > maxLinkEpoch:
		return fmt.Errorf("%w: link epoch %d", ErrFormat, l.Epoch)
	case !isHex64(l.Owner):
		return fmt.Errorf("%w: link o is not 64 lowercase hex digits", ErrFormat)
	}
	return nil
}

// isLinkHost reports whether s is exactly scheme://host[:port], with an
// http or https scheme and nothing else. The host is DNS-style labels (1 to
// 63 of letters, digits, hyphens, and underscores, none starting or ending
// with a hyphen, joined by single dots) or an IPv6 address in brackets,
// checked only as hex digits and colons. The port is 1 to 65535 with no
// leading zero. No user info.
func isLinkHost(s string) bool {
	m := linkHostRE.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	if m[2] == "" {
		return true
	}
	port, _ := strconv.Atoi(m[2])
	return port <= 65535
}

// linkHostRE is the same pattern the JavaScript parseLink uses, so the two
// agree on every host. Group 2 is the port; its range is checked apart.
var linkHostRE = regexp.MustCompile(`^https?://((?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*|\[[0-9a-fA-F:]+\])(?::([1-9][0-9]{0,4}))?$`)

// isUUID reports whether s is a UUID in its one canonical form: lowercase
// hex in 8-4-4-4-12 groups.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
			continue
		}
		if !isLowerHex(s[i : i+1]) {
			return false
		}
	}
	return true
}

// ParseLink reads a public link as strictly as PublicLink writes one: one
// fragment holding exactly k, e, and o in that order, a key of 32 bytes in
// canonical base64, a decimal epoch from 1 with no sign or leading zero, a
// 64-digit lowercase hex o, a lowercase UUID, and a bare scheme://host
// before /shared/. Anything else is ErrFormat.
func ParseLink(s string) (*Link, error) {
	base, frag, ok := strings.Cut(s, "#")
	if !ok || strings.Contains(frag, "#") {
		return nil, fmt.Errorf("%w: a link has exactly one fragment", ErrFormat)
	}
	i := strings.LastIndex(base, "/shared/")
	if i < 0 {
		return nil, fmt.Errorf("%w: a link's path is /shared/<artifact>", ErrFormat)
	}
	parts := strings.Split(frag, "&")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: a link's fragment is k, e, and o", ErrFormat)
	}
	var vals [3]string
	for n, key := range []string{"k=", "e=", "o="} {
		v, ok := strings.CutPrefix(parts[n], key)
		if !ok {
			return nil, fmt.Errorf("%w: a link's fragment is k, e, and o, in that order", ErrFormat)
		}
		vals[n] = v
	}
	l := Link{Host: base[:i], Artifact: base[i+len("/shared/"):], Owner: vals[2]}
	var err error
	if l.AK, err = UnB64(vals[0]); err != nil {
		return nil, fmt.Errorf("%w: link key is not canonical base64", ErrFormat)
	}
	e := vals[1]
	if e == "" || e[0] == '0' || len(e) > 16 || strings.Trim(e, "0123456789") != "" {
		return nil, fmt.Errorf("%w: link epoch %q", ErrFormat, e)
	}
	n, _ := strconv.ParseUint(e, 10, 64)
	if n > maxLinkEpoch {
		return nil, fmt.Errorf("%w: link epoch %q", ErrFormat, e)
	}
	l.Epoch = int(n)
	if err := l.check(); err != nil {
		return nil, err
	}
	return &l, nil
}

// LinkChainInput is the answer of GET /api/artifacts/{id}/membership read
// with a link's token, and the link it was read for. Keys is the link
// scope's editor keys. Rotations are the rotation records the server serves,
// by user ID.
type LinkChainInput struct {
	Link      Link
	Records   []Envelope
	Owners    map[string]KeyPair
	Offers    map[string]Envelope
	Keys      map[string]KeyPair
	Rotations map[string][]Envelope
}

// LinkChain is what VerifyLinkChain verified: the chain, and Editors, the
// keys of each editor the latest record lists whose served keys hash to the
// fp it lists, by user ID. These are the writers a visitor trusts.
type LinkChain struct {
	Chain   *Chain
	Editors map[string]KeyPair
}

// VerifyLinkChain checks a membership chain a visitor read through a public
// link, which the server answers and so cannot be trusted. The chain must
// verify with its first record anchored at the link's o, so only keys that
// hash to o, or that a rotation chain in Rotations links to it, sign it. The
// chain follows an owner who rotated after the link was made. Its latest
// record must be public, at the link's epoch, with the akCommit the link's
// key makes. A link for an older epoch is ErrStaleLink. A reader needs only
// the link's key and the chain, so an editor whose keys are not served, or do
// not hash to the fp the record lists, does not fail the open, even if a
// rotation chain would link them. That editor is left out of Editors, the
// writers the visitor trusts.
// Mirrors verifyLinkChain in internal/server/web/e2e.mjs.
func VerifyLinkChain(in LinkChainInput) (*LinkChain, error) {
	c, err := VerifyChain(ChainInput{Artifact: in.Link.Artifact, Records: in.Records, Owners: in.Owners, Offers: in.Offers, Anchor: in.Link.Owner, Linked: RotationLinker(in.Rotations)})
	if err != nil {
		return nil, err
	}
	b := c.Latest
	switch {
	case !b.Public:
		return nil, fmt.Errorf("%w: the latest record is not public", ErrChain)
	case in.Link.Epoch < b.Epoch:
		return nil, fmt.Errorf("%w: link epoch %d, artifact epoch %d", ErrStaleLink, in.Link.Epoch, b.Epoch)
	case in.Link.Epoch > b.Epoch:
		return nil, fmt.Errorf("%w: link epoch %d is ahead of the artifact's epoch %d", ErrChain, in.Link.Epoch, b.Epoch)
	}
	commit, err := AKCommit(in.Link.AK, in.Link.Artifact, uint64(in.Link.Epoch))
	if err != nil {
		return nil, err
	}
	if commit != b.AKCommit {
		return nil, fmt.Errorf("%w: the link's key does not match the chain's akCommit", ErrChain)
	}
	editors := map[string]KeyPair{}
	for _, m := range b.Members {
		if m.Role != "editor" {
			continue
		}
		kp, ok := in.Keys[m.User]
		if !ok {
			continue
		}
		x, errX := UnB64(kp.X25519)
		ed, errEd := UnB64(kp.Ed25519)
		if errX == nil && errEd == nil && hex.EncodeToString(Fingerprint(x, ed)) == m.FP {
			editors[m.User] = kp
		}
	}
	return &LinkChain{Chain: c, Editors: editors}, nil
}
