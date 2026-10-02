package server

import (
	"strings"
	"testing"

	"github.com/aloisdeniel/cairn/internal/mail"
)

func TestResolveContentDomain(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		flag      string
		want      string // the resolved domain, or "" when refused
		errHas    string // text the refusal names
	}{
		{name: "default for localhost", publicURL: "http://localhost:8787", want: "localhost"},
		{name: "default for 127.0.0.1", publicURL: "http://127.0.0.1:8787", want: "localhost"},
		{name: "default for ::1", publicURL: "http://[::1]:8787", want: "localhost"},
		{name: "default with no public URL", publicURL: "", want: "localhost"},
		{name: "default for LOCALHOST", publicURL: "http://LOCALHOST:8787", want: "localhost"},
		{name: "localhost beside localhost", publicURL: "http://localhost:8787", flag: "localhost", want: "localhost"},
		{name: "localhost beside app.localhost is its parent", publicURL: "http://app.localhost:8787", flag: "localhost", errHas: "must not equal"},
		{name: "localhost beside 127.0.0.1", publicURL: "http://127.0.0.1:8787", flag: "localhost", want: "localhost"},
		{name: "localhost beside another host", publicURL: "https://cairn.example.com", flag: "localhost", want: "localhost"},
		{name: "required off localhost", publicURL: "https://cairn.example.com", errHas: "--content-domain"},
		{name: "separate registrable domain", publicURL: "https://cairn.example.com", flag: "cairn-content.net", want: "cairn-content.net"},
		{name: "mixed case is folded", publicURL: "https://Cairn.Example.com", flag: "Cairn-Content.NET", want: "cairn-content.net"},
		{name: "trailing dot is dropped", publicURL: "https://cairn.example.com.", flag: "cairn-content.net.", want: "cairn-content.net"},
		{name: "sibling private suffix", publicURL: "https://a.github.io", flag: "b.github.io", want: "b.github.io"},
		{name: "IPv4", publicURL: "https://cairn.example.com", flag: "192.0.2.7", errHas: "IP address"},
		{name: "IPv6", publicURL: "https://cairn.example.com", flag: "2001:db8::1", errHas: "IP address"},
		{name: "bracketed IPv6", publicURL: "https://cairn.example.com", flag: "[::1]", errHas: "IP address"},
		{name: "equal host", publicURL: "https://cairn.example.com", flag: "cairn.example.com", errHas: "must not equal"},
		{name: "equal host by case and dot", publicURL: "https://cairn.example.com", flag: "CAIRN.example.com.", errHas: "must not equal"},
		{name: "localhost by case and dot", publicURL: "http://localhost:8787", flag: "LocalHost.", want: "localhost"},
		{name: "parent of the host", publicURL: "https://cairn.example.com", flag: "example.com", errHas: "must not equal"},
		{name: "child of the host", publicURL: "https://cairn.example.com", flag: "content.cairn.example.com", errHas: "must not equal"},
		{name: "child of localhost", publicURL: "http://localhost:8787", flag: "content.localhost", errHas: "must not equal"},
		{name: "sibling under one registrable domain", publicURL: "https://cairn.example.com", flag: "content.example.com", errHas: "registrable domain"},
		{name: "sibling under a multi-label suffix", publicURL: "https://cairn.example.co.uk", flag: "content.example.co.uk", errHas: "registrable domain"},
		{name: "same registrable domain, mixed case", publicURL: "https://cairn.example.com", flag: "Content.EXAMPLE.com.", errHas: "registrable domain"},
		{name: "not a domain name", publicURL: "https://cairn.example.com", flag: "content.net:8443", errHas: "domain name"},
		{name: "empty label", publicURL: "https://cairn.example.com", flag: "content..net", errHas: "domain name"},
		{name: "a path", publicURL: "https://cairn.example.com", flag: "content.net/x", errHas: "domain name"},
		{name: "public URL without a scheme", publicURL: "cairn.example.com", flag: "content.net", errHas: "--public-url"},
		{name: "public URL with host and port only", publicURL: "cairn.example.com:8443", flag: "content.net", errHas: "--public-url"},
		{name: "public URL with another scheme", publicURL: "ftp://cairn.example.com", flag: "content.net", errHas: "--public-url"},
		{name: "public URL with no host", publicURL: "https://", flag: "content.net", errHas: "--public-url"},
		{name: "public URL with no host or flag", publicURL: "http:///x", errHas: "--public-url"},
		{name: "label of 63 characters", publicURL: "https://cairn.example.com", flag: strings.Repeat("a", 63) + ".net", want: strings.Repeat("a", 63) + ".net"},
		{name: "label over 63 characters", publicURL: "https://cairn.example.com", flag: strings.Repeat("a", 64) + ".net", errHas: "63 characters"},
		{name: "name over 253 characters", publicURL: "https://cairn.example.com", flag: strings.Repeat(strings.Repeat("a", 60)+".", 5) + "net", errHas: "253 characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveContentDomain(tt.publicURL, tt.flag)
			if tt.errHas != "" {
				if err == nil {
					t.Fatalf("resolveContentDomain(%q, %q) = %q, want a refusal", tt.publicURL, tt.flag, got)
				}
				if !strings.Contains(err.Error(), tt.errHas) {
					t.Errorf("error %q does not name %q", err, tt.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveContentDomain(%q, %q): %v", tt.publicURL, tt.flag, err)
			}
			if got != tt.want {
				t.Errorf("resolveContentDomain(%q, %q) = %q, want %q", tt.publicURL, tt.flag, got, tt.want)
			}
		})
	}
}

func TestNewRefusesABadContentDomain(t *testing.T) {
	_, err := New(Config{DataDir: t.TempDir(), PublicURL: "https://cairn.example.com", Mail: &mail.Capture{}})
	if err == nil || !strings.Contains(err.Error(), "--content-domain") {
		t.Fatalf("New with no content domain off localhost: %v, want a refusal naming --content-domain", err)
	}
}
