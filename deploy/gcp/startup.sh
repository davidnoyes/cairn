#!/usr/bin/env bash
# Compute Engine startup script for Cairn. It runs the image named in the
# instance metadata only if this repository's docker workflow signed it, in
# a GitHub Actions run from a v* tag or from main. Any other image is refused
# and nothing new runs. See deploy/gcp/README.md.
#
# Instance metadata it reads:
#   cairn-image  the image to run, such as ghcr.io/davidnoyes/cairn:v1.2.3
#
# The data disk is mounted at /mnt/disks/cairn, and holds the server's data
# directory and cairn.env, the server's settings as CAIRN_* variables.
set -euo pipefail

# The repository whose docker workflow builds and signs your images.
REPOSITORY="davidnoyes/cairn"

COSIGN_VERSION=v3.1.3
COSIGN_SHA256_amd64=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
COSIGN_SHA256_arm64=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a
ISSUER=https://token.actions.githubusercontent.com

# Paths, overridable so the test can run this script without root.
COSIGN="${COSIGN:-/usr/local/bin/cosign}"
DATA="${CAIRN_DATA:-/mnt/disks/cairn}"

refuse() {
  echo "cairn: refusing to start: $*" >&2
  exit 1
}

metadata() {
  curl -sf -H 'Metadata-Flavor: Google' \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"
}

IMAGE="${CAIRN_IMAGE:-$(metadata cairn-image || true)}"
[[ -n "$IMAGE" ]] || refuse "no cairn-image in the instance metadata"
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || refuse "REPOSITORY $REPOSITORY is not owner/name"
# The Fulcio certificate of a GitHub Actions run names the workflow file and
# the ref it ran from. Dots are escaped so the pattern matches them alone.
IDENTITY="^https://github\\.com/${REPOSITORY//./\\.}/\\.github/workflows/docker\\.yml@refs/(tags/v[^/]+|heads/main)\$"

command -v docker >/dev/null || { apt-get update -q && apt-get install -qy docker.io; }

if [[ ! -x "$COSIGN" ]]; then
  case "$(uname -m)" in
    x86_64) arch=amd64 want=$COSIGN_SHA256_amd64 ;;
    aarch64 | arm64) arch=arm64 want=$COSIGN_SHA256_arm64 ;;
    *) refuse "no cosign build for $(uname -m)" ;;
  esac
  tmp="$(mktemp "${TMPDIR:-/tmp}/cosign.XXXXXX")"
  curl -sfL -o "$tmp" "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-$arch" \
    || refuse "could not download cosign"
  got="$(sha256sum "$tmp" | cut -d' ' -f1)"
  if [[ "$got" != "$want" ]]; then
    rm -f "$tmp"
    refuse "the cosign download has sha256 $got, not $want"
  fi
  install -m 0755 "$tmp" "$COSIGN"
  rm -f "$tmp"
fi

# Verify and run the same bytes: resolve the image to its digest first.
docker pull -q "$IMAGE" >/dev/null || refuse "could not pull $IMAGE"
ref="$(docker image inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)"
[[ "$ref" =~ @sha256:[0-9a-f]{64}$ ]] || refuse "$IMAGE has no registry digest"
"$COSIGN" verify --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$ref" >/dev/null \
  || refuse "$ref is not signed by the docker workflow of $REPOSITORY"

docker rm -f cairn >/dev/null 2>&1 || true
docker run -d --name cairn --restart unless-stopped -p 8787:8787 \
  -v "$DATA/data:/data" --env-file "$DATA/cairn.env" "$ref" serve
echo "cairn: running $ref" >&2
