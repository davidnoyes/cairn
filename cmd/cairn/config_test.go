package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/aloisdeniel/cairn/internal/e2e"
)

func testAnchor(rev int, c byte) e2e.KeyringAnchor {
	return e2e.KeyringAnchor{Rev: rev, Hash: strings.Repeat(string(c), 64)}
}

func TestSaveAnchorIsMonotonic(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	store := configAnchors{host: "http://a.test"}
	if err := store.SaveAnchor("u1", "fp1", testAnchor(3, 'a')); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAnchor("u1", "fp1", testAnchor(3, 'a')); err != nil {
		t.Errorf("saving the same anchor again: %v, want it accepted", err)
	}
	if err := store.SaveAnchor("u1", "fp1", testAnchor(2, 'b')); !errors.Is(err, e2e.ErrKeyringRollback) {
		t.Errorf("SaveAnchor at a lower rev: %v, want ErrKeyringRollback", err)
	}
	if err := store.SaveAnchor("u1", "fp1", testAnchor(3, 'b')); !errors.Is(err, e2e.ErrKeyringFork) {
		t.Errorf("SaveAnchor at the same rev with another hash: %v, want ErrKeyringFork", err)
	}
	if got, err := store.LoadAnchor("u1", "fp1"); err != nil || got == nil || *got != testAnchor(3, 'a') {
		t.Errorf("anchor after two refusals = %v, %v, want rev 3 kept", got, err)
	}
	if err := store.SaveAnchor("u1", "fp1", testAnchor(4, 'c')); err != nil {
		t.Errorf("SaveAnchor at a higher rev: %v", err)
	}
}

func TestSaveAnchorConcurrentWritersEndAtTheMax(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	if err := saveConfig(cliConfig{Host: "http://a.test", Email: "ada@example.com"}); err != nil {
		t.Fatal(err)
	}
	store := configAnchors{host: "http://a.test"}
	const writers = 40
	var wg sync.WaitGroup
	for rev := 1; rev <= writers; rev++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := store.SaveAnchor("u1", "fp1", testAnchor(rev, 'a'+byte(rev%6))); err != nil && !errors.Is(err, e2e.ErrKeyringRollback) {
				t.Errorf("SaveAnchor rev %d: %v", rev, err)
			}
			if err := saveConfig(cliConfig{Host: "http://a.test", Email: "ada@example.com"}); err != nil {
				t.Errorf("saveConfig: %v", err)
			}
		}()
	}
	wg.Wait()
	got, err := store.LoadAnchor("u1", "fp1")
	if err != nil || got == nil || got.Rev != writers {
		t.Errorf("anchor after %d concurrent writers = %v, %v, want rev %d", writers, got, err, writers)
	}
	if cfg := loadConfig(); cfg.Email != "ada@example.com" {
		t.Errorf("login = %+v, want it kept", cfg)
	}
}

func TestConfigWriteFailureKeepsThePreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("CAIRN_CONFIG", path)
	if err := saveConfig(cliConfig{Host: "http://a.test", Email: "ada@example.com"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	boom := errors.New("disk full")
	old := syncFile
	syncFile = func(*os.File) error { return boom }
	t.Cleanup(func() { syncFile = old })
	if err := saveConfig(cliConfig{Host: "http://b.test"}); !errors.Is(err, boom) {
		t.Errorf("saveConfig with a failing sync: %v, want the sync error", err)
	}
	if err := (configAnchors{host: "http://a.test"}).SaveAnchor("u1", "fp1", testAnchor(1, 'a')); !errors.Is(err, boom) {
		t.Errorf("SaveAnchor with a failing sync: %v, want the sync error", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Errorf("config after failed writes = %q, %v, want %q", after, err, before)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "config.json" && e.Name() != "config.json.lock" {
			t.Errorf("a failed write left %s behind", e.Name())
		}
	}
}

func TestConfigFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not POSIX here")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("CAIRN_CONFIG", path)
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(cliConfig{Host: "http://a.test"}); err != nil {
		t.Fatal(err)
	}
	if err := (configAnchors{host: "http://a.test"}).SaveAnchor("u1", "fp1", testAnchor(1, 'a')); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v, %v, want 0600", fi.Mode().Perm(), err)
	}
}

func TestConfigAnchorKeyNormalizesTheHost(t *testing.T) {
	t.Setenv("CAIRN_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	upper, lower := configAnchors{host: "HTTP://Cairn.Example.COM:8080"}, configAnchors{host: "http://cairn.example.com:8080"}
	if err := upper.SaveAnchor("u1", "fp1", testAnchor(2, 'a')); err != nil {
		t.Fatal(err)
	}
	if got, err := lower.LoadAnchor("u1", "fp1"); err != nil || got == nil || *got != testAnchor(2, 'a') {
		t.Errorf("anchor under the lowercase host = %v, %v, want the one saved under the uppercase host", got, err)
	}
	if err := lower.SaveAnchor("u1", "fp1", testAnchor(1, 'a')); !errors.Is(err, e2e.ErrKeyringRollback) {
		t.Errorf("a lower rev under the other spelling: %v, want ErrKeyringRollback", err)
	}
	if k := (configAnchors{host: "http://h.test/Base"}).key("u", "f"); k != "http://h.test/Base u f" {
		t.Errorf("key = %q, want the path's case kept", k)
	}
}
