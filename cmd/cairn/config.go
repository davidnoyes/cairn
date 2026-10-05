package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aloisdeniel/cairn/internal/client"
	"github.com/aloisdeniel/cairn/internal/e2e"
)

// cliConfig is stored at ~/.config/cairn/config.json after `cairn login`.
// APIKey is the full four-part key (cairn_<keyid>_<authSecret>_<keySecret>);
// only the two-part bearer `cairn_<keyId>_<authSecret>` ever goes on the
// wire; the keySecret never leaves this machine.
type cliConfig struct {
	Host   string `json:"host"`
	Email  string `json:"email"`
	APIKey string `json:"apiKey"`
}

func configPath() (string, error) {
	if p := os.Getenv("CAIRN_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cairn", "config.json"), nil
}

// configFile is the file on disk: the login, and the keyring anchor for
// each account this machine has read the keyring of, keyed by host and user
// id. Logging out clears the login and keeps the anchors, so a server that
// rolls a keyring back is still caught after signing in again.
type configFile struct {
	cliConfig
	Anchors map[string]e2e.KeyringAnchor `json:"anchors,omitempty"`
}

// readConfigFile reads the config file. A missing file is an empty one; a
// file that cannot be read or parsed is an error.
func readConfigFile() (configFile, error) {
	var f configFile
	path, err := configPath()
	if err != nil {
		return f, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return configFile{}, fmt.Errorf("the config file %s is not valid JSON: %w", path, err)
	}
	return f, nil
}

// syncFile flushes a file to disk. It is a variable so tests can fail it.
var syncFile = func(f *os.File) error { return f.Sync() }

// writeConfigFile replaces the config file atomically: it writes a 0600
// temp file in the same directory, syncs it, and renames it over the old
// one, so a failure leaves the previous file intact.
func writeConfigFile(f configFile) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	data, _ := json.MarshalIndent(f, "", "  ")
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after a successful rename
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := syncFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// updateConfigFile reads the config file, applies change, and writes it
// back, all under the config lock, so concurrent cairn processes do not
// lose each other's changes. A change that fails writes nothing.
func updateConfigFile(change func(f *configFile) error) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := lockConfig(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	f, err := readConfigFile()
	if err != nil {
		return err
	}
	if err := change(&f); err != nil {
		return err
	}
	return writeConfigFile(f)
}

func loadConfig() cliConfig {
	f, _ := readConfigFile()
	return f.cliConfig
}

// saveConfig replaces the login and keeps the anchors. It refuses to
// overwrite a config file it cannot parse, which would lose them.
func saveConfig(cfg cliConfig) error {
	return updateConfigFile(func(f *configFile) error {
		f.cliConfig = cfg
		return nil
	})
}

// configAnchors keeps keyring anchors in the config file, for one host.
type configAnchors struct{ host string }

// key scopes an anchor to the user's own fingerprint as well as the user ID.
// A reset without the recovery code changes the user's keys, so the device
// starts with no anchor and accepts the empty keyring the reset leaves. A
// server cannot use this to roll a keyring back, because it cannot make the
// user's keys change.
// The scheme and host are compared in lowercase, as URLs do.
func (a configAnchors) key(userID, fp string) string {
	host := a.host
	if u, err := url.Parse(host); err == nil && u.Scheme != "" && u.Host != "" {
		u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
		host = u.String()
	}
	return host + " " + userID + " " + fp
}

func (a configAnchors) LoadAnchor(userID, fp string) (*e2e.KeyringAnchor, error) {
	f, err := readConfigFile()
	if err != nil {
		return nil, err
	}
	anchor, ok := f.Anchors[a.key(userID, fp)]
	if !ok {
		return nil, nil
	}
	return &anchor, nil
}

// SaveAnchor never lowers an anchor's rev, and never replaces the hash at
// the same rev: the stored anchor stays and the error says so.
func (a configAnchors) SaveAnchor(userID, fp string, anchor e2e.KeyringAnchor) error {
	key := a.key(userID, fp)
	return updateConfigFile(func(f *configFile) error {
		if cur, ok := f.Anchors[key]; ok {
			if anchor.Rev < cur.Rev {
				return fmt.Errorf("%w: refusing to lower the stored anchor from rev %d to %d", e2e.ErrKeyringRollback, cur.Rev, anchor.Rev)
			}
			if anchor.Rev == cur.Rev && anchor.Hash != cur.Hash {
				return fmt.Errorf("%w: refusing to replace the stored anchor at rev %d", e2e.ErrKeyringFork, cur.Rev)
			}
		}
		if f.Anchors == nil {
			f.Anchors = map[string]e2e.KeyringAnchor{}
		}
		f.Anchors[key] = anchor
		return nil
	})
}

// apiClient builds a client from, in priority order: CAIRN_HOST/CAIRN_API_KEY
// environment (headless agents), then the stored login. CAIRN_API_KEY and the
// config file both hold the full four-part key; only its bearer (the first
// two parts) ever goes on the wire, and the client keeps the whole key to
// unlock the account's keys locally. Keyring anchors always live in the
// config file, even when the login comes from the environment.
func apiClient() (*client.Client, error) {
	host := os.Getenv("CAIRN_HOST")
	fullKey := os.Getenv("CAIRN_API_KEY")
	cfg := loadConfig()
	if host == "" {
		host = cfg.Host
	}
	if fullKey == "" {
		fullKey = cfg.APIKey
	}
	if host == "" {
		return nil, errors.New("not logged in: run 'cairn login --host <url>' or set CAIRN_HOST and CAIRN_API_KEY")
	}
	if fullKey == "" {
		return nil, fmt.Errorf("no credentials for %s: run 'cairn login' or set CAIRN_API_KEY", host)
	}
	key, err := e2e.ParseAPIKey(fullKey)
	if err != nil {
		return nil, fmt.Errorf("malformed API key: %w", err)
	}
	c := client.NewWithKey(host, key)
	c.Anchors = configAnchors{host: c.Host}
	watchHandovers(c)
	watchNotices(c)
	return c, nil
}

// bearerOf is the on-the-wire credential for a parsed key.
func bearerOf(k e2e.APIKey) string {
	return "cairn_" + k.KeyID + "_" + k.AuthSecret
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
