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

func loadConfig() cliConfig {
	var cfg cliConfig
	path, err := configPath()
	if err != nil {
		return cfg
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	json.Unmarshal(data, &cfg)
	return cfg
}

func saveConfig(cfg cliConfig) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(path, data, 0o600)
}

// apiClient builds a client from, in priority order: CAIRN_HOST/CAIRN_API_KEY
// environment (headless agents), then the stored login. CAIRN_API_KEY and the
// config file both hold the full four-part key; only its bearer (the first
// two parts) ever goes on the wire.
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
	bearer, err := apiKeyBearer(fullKey)
	if err != nil {
		return nil, err
	}
	return client.New(host, bearer), nil
}

// apiKeyBearer extracts the bearer credential (cairn_<keyid>_<authSecret>)
// from a presented full four-part API key; the key's keySecret never goes on
// the wire.
func apiKeyBearer(full string) (string, error) {
	key, err := e2e.ParseAPIKey(full)
	if err != nil {
		return "", fmt.Errorf("malformed API key: %w", err)
	}
	return "cairn_" + key.KeyID + "_" + key.AuthSecret, nil
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
