package server

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// normalizeHost lowercases a host name and drops one trailing dot.
func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// isLocalHost reports whether h is a loopback name a developer runs Cairn on.
func isLocalHost(h string) bool {
	return h == "" || h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// validDomainName reports whether d is dot-separated labels of letters,
// digits, and hyphens, none empty or starting or ending with a hyphen.
func validDomainName(d string) bool {
	if d == "" {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// resolveContentDomain returns the domain under which each artifact gets its
// own host, from the --content-domain value and the public URL. An empty flag
// defaults to localhost when the public URL's host is a loopback name, and is
// otherwise an error. It refuses a public URL that is not http or https with a
// host, and a domain that is an IP address, that is not a domain name (or has a
// label over 63 characters, or is over 253 in all), that equals the public URL's host (other than localhost, whose
// subdomains are sites of their own), that is a parent or child of it, or that
// shares a registrable domain with it by the Public Suffix List. The result
// is lowercase with no trailing dot.
func resolveContentDomain(publicURL, flag string) (string, error) {
	host := ""
	if publicURL != "" {
		u, err := url.Parse(publicURL)
		if err != nil {
			return "", fmt.Errorf("--public-url: %w", err)
		}
		if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return "", fmt.Errorf("--public-url %q must be an http or https URL with a host, such as https://cairn.example.com", publicURL)
		}
		host = normalizeHost(u.Hostname())
	}
	cd := normalizeHost(strings.TrimSpace(flag))
	if cd == "" {
		if !isLocalHost(host) {
			return "", fmt.Errorf("--content-domain (or CAIRN_CONTENT_DOMAIN) is required when the public URL host is %q: it names the domain each artifact is served under, and must not share a registrable domain with the public URL", host)
		}
		return "localhost", nil
	}
	if _, err := netip.ParseAddr(strings.Trim(cd, "[]")); err == nil {
		return "", fmt.Errorf("--content-domain %q is an IP address; it must be a domain name, because each artifact needs its own host name", flag)
	}
	if !validDomainName(cd) {
		return "", fmt.Errorf("--content-domain %q is not a domain name: give a bare host name, with no scheme, port, or path", flag)
	}
	if len(cd) > 253 {
		return "", fmt.Errorf("--content-domain %q is over 253 characters, the longest a domain name can be", flag)
	}
	for _, label := range strings.Split(cd, ".") {
		if len(label) > 63 {
			return "", fmt.Errorf("--content-domain %q has a label over 63 characters, the longest a domain label can be", flag)
		}
	}
	if host == "" {
		return cd, nil
	}
	// Every subdomain of localhost is a site of its own, so the default
	// pairing is safe. Any other relation to the public URL's host is not.
	if cd == "localhost" && host == "localhost" {
		return cd, nil
	}
	if cd == host || strings.HasSuffix(cd, "."+host) || strings.HasSuffix(host, "."+cd) {
		return "", fmt.Errorf("--content-domain %q must not equal the public URL's host %q or be its parent or child: an artifact would share a site with the app", cd, host)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		a, aerr := publicsuffix.EffectiveTLDPlusOne(host)
		c, cerr := publicsuffix.EffectiveTLDPlusOne(cd)
		if aerr == nil && cerr == nil && a == c {
			return "", fmt.Errorf("--content-domain %q shares the registrable domain %q with the public URL's host %q: an artifact would be same-site with the app", cd, a, host)
		}
	}
	return cd, nil
}
