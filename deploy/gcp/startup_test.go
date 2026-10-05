// Package gcp holds the Compute Engine deployment files. Its test runs
// startup.sh with fake docker, cosign, and curl commands on PATH.
package gcp

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	amd64Hash = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
	arm64Hash = "c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a"
)

const digestRef = "ghcr.io/davidnoyes/cairn@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakes writes the fake commands. Each appends its arguments to calls.log;
// docker answers inspect with the digest in DIGEST_REF, cosign exits with
// COSIGN_EXIT, mountpoint exits with MOUNTPOINT_EXIT, and uname -m prints
// UNAME_M.
func fakes(t *testing.T) (bin, log string) {
	t.Helper()
	bin = t.TempDir()
	log = filepath.Join(t.TempDir(), "calls.log")
	scripts := map[string]string{
		"docker": `echo "docker $*" >> "$CALLS"
if [ "$1 $2" = "image inspect" ]; then echo "$DIGEST_REF"; fi`,
		"cosign": `echo "cosign $*" >> "$CALLS"
exit "${COSIGN_EXIT:-0}"`,
		"mountpoint": `exit "${MOUNTPOINT_EXIT:-0}"`,
		"uname":      `echo "${UNAME_M:-x86_64}"`,
		"curl": `echo "curl $*" >> "$CALLS"
while [ $# -gt 0 ]; do if [ "$1" = -o ]; then echo "not cosign" > "$2"; fi; shift; done`,
	}
	if _, err := exec.LookPath("sha256sum"); err != nil {
		scripts["sha256sum"] = `shasum -a 256 "$@"`
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return bin, log
}

// runStartup runs startup.sh with the fakes first on PATH and an installed
// cosign unless install is set, and returns its output and the calls made.
func runStartup(t *testing.T, install bool, env ...string) (string, []string, error) {
	t.Helper()
	bin, log := fakes(t)
	cosign := filepath.Join(bin, "cosign")
	if install {
		cosign = filepath.Join(t.TempDir(), "cosign")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cairn.env"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "startup.sh")
	cmd.Env = append([]string{
		"PATH=" + bin + ":" + os.Getenv("PATH"),
		"CALLS=" + log,
		"TMPDIR=" + t.TempDir(),
		"COSIGN=" + cosign,
		"CAIRN_DATA=" + dir,
		"CAIRN_IMAGE=ghcr.io/davidnoyes/cairn:v1.2.3",
		"DIGEST_REF=" + digestRef,
	}, env...)
	out, err := cmd.CombinedOutput()
	data, _ := os.ReadFile(log)
	return string(out), strings.Split(strings.TrimSpace(string(data)), "\n"), err
}

func called(calls []string, prefix string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func TestStartupRunsAVerifiedImageByDigest(t *testing.T) {
	out, calls, err := runStartup(t, false)
	if err != nil {
		t.Fatalf("startup.sh: %v\n%s", err, out)
	}
	verify := called(calls, "cosign verify ")
	if len(verify) != 1 || !strings.HasSuffix(verify[0], " "+digestRef) {
		t.Fatalf("cosign calls = %v, want one verify of the digest", called(calls, "cosign"))
	}
	if !strings.Contains(verify[0], "--certificate-oidc-issuer https://token.actions.githubusercontent.com ") {
		t.Errorf("verify does not pin the GitHub Actions issuer: %s", verify[0])
	}
	run := called(calls, "docker run ")
	if len(run) != 1 || !strings.Contains(run[0], " "+digestRef+" serve") {
		t.Errorf("docker run calls = %v, want one run of the verified digest", run)
	}
}

func TestStartupRefusesAnImageThatDoesNotVerify(t *testing.T) {
	out, calls, err := runStartup(t, false, "COSIGN_EXIT=1")
	if err == nil {
		t.Fatalf("startup.sh succeeded with an unsigned image:\n%s", out)
	}
	if c := append(called(calls, "docker run"), called(calls, "docker rm")...); len(c) > 0 {
		t.Errorf("a refused image still touched the container: %v", c)
	}
	if !strings.Contains(out, "refusing to start") || !strings.Contains(out, "not signed") {
		t.Errorf("output does not say why:\n%s", out)
	}
}

func TestStartupRefusesAnImageWithNoDigest(t *testing.T) {
	out, calls, err := runStartup(t, false, "DIGEST_REF=ghcr.io/davidnoyes/cairn:v1.2.3")
	if err == nil {
		t.Fatalf("startup.sh succeeded without a digest:\n%s", out)
	}
	if c := append(called(calls, "cosign"), called(calls, "docker run")...); len(c) > 0 {
		t.Errorf("calls after a missing digest: %v", c)
	}
}

func TestStartupRefusesACosignDownloadThatDoesNotMatch(t *testing.T) {
	out, calls, err := runStartup(t, true)
	if err == nil {
		t.Fatalf("startup.sh installed a cosign with the wrong checksum:\n%s", out)
	}
	if len(called(calls, "curl -sfL -o ")) != 1 {
		t.Errorf("calls = %v, want one cosign download", calls)
	}
	if c := called(calls, "docker"); len(c) > 0 {
		t.Errorf("docker ran after a bad cosign download: %v", c)
	}
	if !strings.Contains(out, "cosign download has sha256") {
		t.Errorf("output does not name the checksum:\n%s", out)
	}
}

// TestStartupRefusesWithNoSha256sum: without sha256sum the checksum cannot be
// checked, so it must say so before downloading anything. PATH holds only the
// fakes, which is all the script reaches before that check.
func TestStartupRefusesWithNoSha256sum(t *testing.T) {
	bin, log := fakes(t)
	os.Remove(filepath.Join(bin, "sha256sum"))
	cmd := exec.Command("bash", "startup.sh")
	cmd.Env = []string{
		"PATH=" + bin,
		"CALLS=" + log,
		"TMPDIR=" + t.TempDir(),
		"COSIGN=" + filepath.Join(t.TempDir(), "cosign"),
		"CAIRN_DATA=" + t.TempDir(),
		"CAIRN_IMAGE=ghcr.io/davidnoyes/cairn:v1.2.3",
	}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "sha256sum") {
		t.Fatalf("startup.sh with no sha256sum: %v\n%s", err, out)
	}
	if data, _ := os.ReadFile(log); strings.Contains(string(data), "curl") {
		t.Errorf("downloaded cosign with no sha256sum:\n%s", data)
	}
}

// TestStartupPicksCosignByArchitecture: each architecture downloads its own
// asset and is held to its own pinned hash, which the mismatch message prints
// because the fake curl serves neither.
func TestStartupPicksCosignByArchitecture(t *testing.T) {
	for _, tc := range []struct{ uname, asset, hash, other string }{
		{"x86_64", "cosign-linux-amd64", amd64Hash, arm64Hash},
		{"aarch64", "cosign-linux-arm64", arm64Hash, amd64Hash},
		{"arm64", "cosign-linux-arm64", arm64Hash, amd64Hash},
	} {
		out, calls, err := runStartup(t, true, "UNAME_M="+tc.uname)
		if err == nil {
			t.Fatalf("%s: startup.sh installed a bad cosign:\n%s", tc.uname, out)
		}
		dl := called(calls, "curl -sfL -o ")
		if len(dl) != 1 || !strings.HasSuffix(dl[0], "/"+tc.asset) {
			t.Errorf("%s: downloads = %v, want one of %s", tc.uname, dl, tc.asset)
		}
		if !strings.Contains(out, "not "+tc.hash) || strings.Contains(out, tc.other) {
			t.Errorf("%s: output does not expect %s:\n%s", tc.uname, tc.hash, out)
		}
	}
}

func TestStartupRefusesAnUnsupportedArchitecture(t *testing.T) {
	out, calls, err := runStartup(t, true, "UNAME_M=riscv64")
	if err == nil || !strings.Contains(out, "no cosign build for riscv64") {
		t.Fatalf("startup.sh on riscv64: %v\n%s", err, out)
	}
	if c := called(calls, "curl"); len(c) > 0 {
		t.Errorf("downloaded cosign for an unsupported architecture: %v", c)
	}
}

// TestStartupKeepsTheContainerWhenTheDataIsNotThere: the data disk is mounted
// nofail, and docker run would create the directory on the boot disk and
// start on empty state. A missing cairn.env would fail the run after the old
// container was removed. Either leaves the old container alone.
func TestStartupKeepsTheContainerWhenTheDataIsNotThere(t *testing.T) {
	for name, tc := range map[string]struct {
		env  []string
		want string
	}{
		"not mounted": {[]string{"MOUNTPOINT_EXIT=1"}, "is not mounted"},
		"no env file": {[]string{"CAIRN_DATA=" + t.TempDir()}, "cairn.env"},
	} {
		t.Run(name, func(t *testing.T) {
			out, calls, err := runStartup(t, false, tc.env...)
			if err == nil {
				t.Fatalf("startup.sh replaced the container:\n%s", out)
			}
			if c := append(called(calls, "docker run"), called(calls, "docker rm")...); len(c) > 0 {
				t.Errorf("touched the container: %v", c)
			}
			if !strings.Contains(out, "refusing to start") || !strings.Contains(out, tc.want) {
				t.Errorf("output does not say why:\n%s", out)
			}
		})
	}
}

func TestStartupRefusesWithNoImage(t *testing.T) {
	// The metadata server is the fake curl, which prints nothing.
	out, calls, err := runStartup(t, false, "CAIRN_IMAGE=")
	if err == nil || !strings.Contains(out, "no cairn-image") {
		t.Fatalf("startup.sh with no image: %v\n%s", err, out)
	}
	if c := called(calls, "docker"); len(c) > 0 {
		t.Errorf("docker ran with no image: %v", c)
	}
}

// TestStartupIdentityPattern: the pattern startup.sh passes cosign, read
// from the call, accepts the docker workflow from a v* tag or main, and
// nothing else. cosign matches with Go's regexp package, as this test does.
func TestStartupIdentityPattern(t *testing.T) {
	_, calls, err := runStartup(t, false)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`--certificate-identity-regexp (\S+) `).FindStringSubmatch(strings.Join(called(calls, "cosign verify"), ""))
	if m == nil {
		t.Fatalf("no identity pattern in %v", calls)
	}
	re := regexp.MustCompile(m[1])
	const base = "https://github.com/davidnoyes/cairn/.github/workflows/"
	for id, want := range map[string]bool{
		base + "docker.yml@refs/tags/v1.2.3":                                                 true,
		base + "docker.yml@refs/heads/main":                                                  true,
		base + "docker.yml@refs/heads/feature":                                               false,
		base + "docker.yml@refs/heads/main-old":                                              false,
		base + "docker.yml@refs/tags/release-1":                                              false,
		base + "docker.yml@refs/pull/7/merge":                                                false,
		base + "test.yml@refs/heads/main":                                                    false,
		base + "dockerxyml@refs/heads/main":                                                  false,
		"https://github.com/davidnoyes/cairnx/.github/workflows/docker.yml@refs/heads/main":  false,
		"https://github.com/someone/cairn/.github/workflows/docker.yml@refs/heads/main":      false,
		"https://github.com/davidnoyes/cairn/.github/workflows/docker.yml@refs/heads/main/x": false,
		"https://githubxcom/davidnoyes/cairn/.github/workflows/docker.yml@refs/heads/main":   false,
	} {
		if got := re.MatchString(id); got != want {
			t.Errorf("pattern %s on %s = %v, want %v", m[1], id, got, want)
		}
	}
}
