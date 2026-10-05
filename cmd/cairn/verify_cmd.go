package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/aloisdeniel/cairn/internal/e2e"
	"github.com/aloisdeniel/cairn/internal/release"
)

// keyFlags collects repeated --key values.
type keyFlags []string

func (k *keyFlags) String() string     { return strings.Join(*k, ",") }
func (k *keyFlags) Set(v string) error { *k = append(*k, v); return nil }

// runVerify checks that a server serves exactly the files and pages of a
// signed release. See design/e2e-api.md "Release manifest".
func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "signed manifest file (default: the one the server serves)")
	var extra keyFlags
	fs.Var(&extra, "key", "release public key to trust, base64url (repeatable; added to the compiled-in keys)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: cairn verify [--manifest FILE] [--key KEY]... [URL]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	loginHost, fullKey := os.Getenv("CAIRN_HOST"), os.Getenv("CAIRN_API_KEY")
	cfg := loadConfig()
	if loginHost == "" {
		loginHost = cfg.Host
	}
	if fullKey == "" {
		fullKey = cfg.APIKey
	}
	server := fs.Arg(0)
	if server == "" {
		server = loginHost
	}
	if server == "" || fs.NArg() > 1 {
		return errors.New("usage: cairn verify [--manifest FILE] [--key KEY]... [URL]")
	}

	keys, err := release.TrustedKeys()
	if err != nil {
		return err
	}
	more, err := release.ParseKeys(extra)
	if err != nil {
		return err
	}
	keys = append(keys, more...)
	if len(keys) == 0 {
		return fmt.Errorf("%w: this build trusts none; pass the release's public key with --key", release.ErrNoKeys)
	}

	ctx := context.Background()
	client := release.NewClient()
	doc, err := release.Discover(ctx, client, server)
	if err != nil {
		return err
	}
	signed := []byte(doc.Manifest)
	if *manifestPath != "" {
		if signed, err = os.ReadFile(*manifestPath); err != nil {
			return err
		}
	}
	if len(signed) == 0 {
		return errors.New("the server serves no signed manifest (a build without a release key); pass one with --manifest")
	}
	m, err := release.Open(signed, keys)
	if err != nil {
		return err
	}

	t := release.Target{AppOrigin: doc.AppOrigin, ContentOrigin: doc.ContentOrigin, Client: client}
	// The login's key goes only to the server it was made for.
	if sameOrigin(loginHost, doc.AppOrigin) && fullKey != "" {
		if k, err := e2e.ParseAPIKey(fullKey); err == nil {
			t.Bearer = bearerOf(k)
		}
	}
	fmt.Printf("release %s, checked against %s\n", m.Version, doc.AppOrigin)
	counts := map[string]int{}
	for _, r := range release.Check(ctx, t, m) {
		counts[r.Status]++
		if r.Status != release.StatusOK {
			fmt.Printf("%-8s %s: %s\n", r.Status, r.URL, r.Detail)
		}
	}
	fmt.Printf("%d ok, %d changed, %d failed, %d skipped\n",
		counts[release.StatusOK], counts[release.StatusChanged], counts[release.StatusFailed], counts[release.StatusSkipped])
	if counts[release.StatusChanged] > 0 || counts[release.StatusFailed] > 0 {
		return fmt.Errorf("%s does not serve release %s as signed: %d changed, %d failed",
			doc.AppOrigin, m.Version, counts[release.StatusChanged], counts[release.StatusFailed])
	}
	return nil
}

// sameOrigin compares two URLs' scheme and host, in lowercase.
func sameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return ua.Host != "" && strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}
