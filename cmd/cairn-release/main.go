// Command cairn-release makes Cairn's release key and signs the release
// manifest with it. The release workflow signs before it builds, so the
// binary embeds the manifest; see deploy/gcp/README.md.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/release"
	"github.com/aloisdeniel/cairn/internal/server"
)

const usage = `usage:
  cairn-release keygen                       Print a new release key: the secret, and its public key
  cairn-release public                       Print the public key of CAIRN_RELEASE_KEY
  cairn-release sign -version V [-out FILE]  Sign this tree's manifest with CAIRN_RELEASE_KEY`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "cairn-release:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, getenv func(string) string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "keygen":
		seed, pub, err := e2e.GenerateEd25519(rand.Reader)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "CAIRN_RELEASE_KEY=%s\npublic key: %s\n", e2e.B64(seed), e2e.B64(pub))
		return nil
	case "public":
		seed, err := releaseSeed(getenv)
		if err != nil {
			return err
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		fmt.Fprintln(out, e2e.B64(pub))
		return nil
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ContinueOnError)
		fs.SetOutput(out)
		version := fs.String("version", "", "release version, such as the tag")
		path := fs.String("out", "internal/release/manifest.json", "where to write the signed manifest")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *version == "" {
			return errors.New("sign: -version is required")
		}
		seed, err := releaseSeed(getenv)
		if err != nil {
			return err
		}
		m, err := server.ReleaseManifest(*version)
		if err != nil {
			return err
		}
		signed, err := release.Sign(seed, m)
		if err != nil {
			return err
		}
		return os.WriteFile(*path, signed, 0o644)
	}
	return fmt.Errorf("unknown command %q\n%s", args[0], usage)
}

// releaseSeed reads the release key's seed from CAIRN_RELEASE_KEY.
func releaseSeed(getenv func(string) string) ([]byte, error) {
	v := getenv("CAIRN_RELEASE_KEY")
	if v == "" {
		return nil, errors.New("CAIRN_RELEASE_KEY is not set; run cairn-release keygen to make one")
	}
	seed, err := e2e.UnB64(v)
	if err == nil && len(seed) != ed25519.SeedSize {
		err = e2e.ErrFormat
	}
	if err != nil {
		return nil, fmt.Errorf("CAIRN_RELEASE_KEY is not a base64url Ed25519 seed: %w", err)
	}
	return seed, nil
}
