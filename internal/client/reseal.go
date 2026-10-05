// Re-sealing data after an epoch change. A record that starts a new epoch makes
// the new epoch's AK the only one a public link opens, so the person who made
// it seals the data again under that AK: the latest revision of every
// version's database, and every stored file at its new address. See "Epoch
// changes" in design/e2e-api.md.
package client

import (
	"errors"
	"fmt"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

// ErrCannotReseal means the verified chain lists the caller as neither the
// owner nor an editor, under their current keys.
var ErrCannotReseal = errors.New("only the artifact's owner or an editor can re-seal its data")

// ResealResult is what a re-seal did. Skipped says what it left alone, and why.
type ResealResult struct {
	Databases int
	Files     int
	Skipped   []string
}

// Reseal seals the artifact's data under its current epoch again, signed by
// the caller. It is safe to run at any time: what is already under the current
// epoch is left as it is.
func (c *Client) Reseal(artifactID string) (*ResealResult, error) {
	k, err := c.Unlock()
	if err != nil {
		return nil, err
	}
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err != nil {
		return nil, err
	}
	if err := c.checkHandover(k, artifactID, va); err != nil {
		return nil, err
	}
	if !approverOf(va.Chain.Latest, k) {
		return nil, ErrCannotReseal
	}
	if err := e2e.CheckEncryptEpoch(va.Keyring.EpochPin(artifactID), va.Chain.Latest.Epoch); err != nil {
		return nil, err
	}
	return c.reseal(k, va, artifactID)
}

// resealInto re-seals after the record that started a new epoch, and notes
// the outcome in change, which a command reports.
func (c *Client) resealInto(k *UnlockedKeys, artifactID string, change *EpochChange) {
	va, err := c.VerifyArtifact(k, artifactID, "")
	if err == nil {
		change.Resealed, err = c.reseal(k, va, artifactID)
	}
	change.ResealErr = err
}

// bodyBefore is the last record before the chain's current epoch began, the
// record whose writers made what is to be re-sealed. It is false when the
// chain is still in its first epoch.
func bodyBefore(chain *e2e.Chain) (e2e.MembershipBody, bool) {
	for i := len(chain.Bodies) - 1; i >= 0; i-- {
		if chain.Bodies[i].Epoch < chain.Latest.Epoch {
			return chain.Bodies[i], true
		}
	}
	return e2e.MembershipBody{}, false
}

// reseal re-seals every version's data that verifies under the record before
// the current epoch began. What fails a check, such as a revision signed by
// someone the change removed, is left as it is and noted in Skipped. On an
// error it returns what it had done.
func (c *Client) reseal(k *UnlockedKeys, va *VerifiedArtifact, artifactID string) (*ResealResult, error) {
	res := &ResealResult{}
	before, ok := bodyBefore(va.Chain)
	if !ok {
		return res, nil
	}
	aks, err := c.callerAKs(k, artifactID, va.Chain)
	if err != nil {
		return res, err
	}
	now, err := c.writerKeys(k, va.Membership, va.Chain.Latest)
	if err != nil {
		return res, err
	}
	old, err := c.writerKeys(k, va.Membership, before)
	if err != nil {
		return res, err
	}
	versions, err := c.ListVersions(artifactID)
	if err != nil {
		return res, err
	}
	for _, v := range versions {
		d := newData(k, va, artifactID, v, aks, c, now)
		chk := *d.now
		chk.writers, chk.anyWriter = old, before.PublicWrites
		if err := d.resealDatabase(&chk, res); err != nil {
			return res, fmt.Errorf("version %s: %w", v.ID, err)
		}
		if err := d.resealFiles(&chk, res); err != nil {
			return res, fmt.Errorf("version %s: %w", v.ID, err)
		}
	}
	return res, nil
}

// resealDatabase writes the latest revision again under the current epoch,
// when it was sealed under an earlier one and chk accepts it.
func (d *Data) resealDatabase(chk *dataChecker, res *ResealResult) error {
	f, err := d.fetchRevision(0)
	if errors.Is(err, ErrNoDatabase) {
		return nil
	}
	if err != nil {
		return err
	}
	if f.epoch >= d.va.Chain.Latest.Epoch {
		return nil
	}
	plain, err := d.openRevision(f, chk)
	if err != nil {
		res.Skipped = append(res.Skipped, fmt.Sprintf("the database of version %s, revision %d: %v", d.version.ID, f.revision, err))
		return nil
	}
	if err := d.noteLatest(f.revision); err != nil {
		return err
	}
	if _, err := d.PutRevision(plain, f.revision); err != nil {
		return err
	}
	res.Databases++
	return nil
}

// resealFiles stores each file sealed under an earlier epoch and accepted by
// chk at its address under the current one, then deletes the old address. A
// path already stored under the current epoch keeps that copy.
func (d *Data) resealFiles(chk *dataChecker, res *ResealResult) error {
	items, err := d.entries()
	if err != nil {
		return err
	}
	current := d.va.Chain.Latest.Epoch
	have := map[string]bool{}
	for _, item := range items {
		have[item.Address] = true
	}
	for _, item := range items {
		if item.Epoch >= current {
			continue
		}
		m, err := d.openEntry(chk, item)
		var plain []byte
		if err == nil {
			var found bool
			if plain, found, err = d.readFile(chk, item.Epoch, item.Address); err == nil && !found {
				err = errors.New("the server no longer has the file")
			}
		}
		if err != nil {
			res.Skipped = append(res.Skipped, fmt.Sprintf("a stored file of version %s: %v", d.version.ID, err))
			continue
		}
		address, err := d.addressAt(current, m.Path)
		if err != nil {
			return err
		}
		if !have[address] {
			if _, err := d.putAt(m.Path, plain, m.ModifiedAt); err != nil {
				return err
			}
			have[address] = true
		}
		if _, err := d.deleteAddress(item.Address); err != nil {
			return err
		}
		res.Files++
	}
	return nil
}
