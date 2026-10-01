package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

func writeConfigFile(f configFile) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(f, "", "  ")
	return os.WriteFile(path, data, 0o600)
}

func loadConfig() cliConfig {
	f, _ := readConfigFile()
	return f.cliConfig
}

// saveConfig replaces the login and keeps the anchors. It refuses to
// overwrite a config file it cannot parse, which would lose them.
func saveConfig(cfg cliConfig) error {
	f, err := readConfigFile()
	if err != nil {
		return err
	}
	f.cliConfig = cfg
	return writeConfigFile(f)
}

// configAnchors keeps keyring anchors in the config file, for one host.
type configAnchors struct{ host string }

func (a configAnchors) key(userID string) string { return a.host + " " + userID }

func (a configAnchors) LoadAnchor(userID string) (*e2e.KeyringAnchor, error) {
	f, err := readConfigFile()
	if err != nil {
		return nil, err
	}
	anchor, ok := f.Anchors[a.key(userID)]
	if !ok {
		return nil, nil
	}
	return &anchor, nil
}

func (a configAnchors) SaveAnchor(userID string, anchor e2e.KeyringAnchor) error {
	f, err := readConfigFile()
	if err != nil {
		return err
	}
	if f.Anchors == nil {
		f.Anchors = map[string]e2e.KeyringAnchor{}
	}
	f.Anchors[a.key(userID)] = anchor
	return writeConfigFile(f)
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
