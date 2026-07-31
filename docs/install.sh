#!/bin/sh
# Cairn installer — downloads the latest release binary from GitHub.
#
#   curl -fsSL https://aloisdeniel.github.io/cairn/install.sh | sh
#
# Options (environment variables):
#   CAIRN_VERSION      install a specific tag (default: latest release)
#   CAIRN_INSTALL_DIR  target directory (default: /usr/local/bin)
set -eu

REPO="aloisdeniel/cairn"
INSTALL_DIR="${CAIRN_INSTALL_DIR:-/usr/local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux | darwin) ;;
  *)
    echo "cairn: unsupported OS '$os'." >&2
    echo "Build from source instead: go install github.com/$REPO/cmd/cairn@latest" >&2
    exit 1
    ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *)
    echo "cairn: unsupported architecture '$arch'." >&2
    exit 1
    ;;
esac

if [ -n "${CAIRN_VERSION:-}" ]; then
  url="https://github.com/$REPO/releases/download/$CAIRN_VERSION/cairn-$os-$arch.tar.gz"
else
  url="https://github.com/$REPO/releases/latest/download/cairn-$os-$arch.tar.gz"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $url"
curl -fsSL "$url" -o "$tmp/cairn.tar.gz"
tar -xzf "$tmp/cairn.tar.gz" -C "$tmp"

if [ -w "$INSTALL_DIR" ]; then
  install -m 0755 "$tmp/cairn" "$INSTALL_DIR/cairn"
else
  echo "Installing into $INSTALL_DIR (needs sudo)"
  sudo install -m 0755 "$tmp/cairn" "$INSTALL_DIR/cairn"
fi

echo "Installed cairn to $INSTALL_DIR/cairn"
echo "Get started:  cairn serve --data-dir data --admin-email you@example.com --admin-password '...'"
