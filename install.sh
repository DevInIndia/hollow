#!/bin/sh
#
# Install a hollow binary. No Go toolchain, no compiler, no package manager.
#
#   curl -fsSL https://raw.githubusercontent.com/DevInIndia/hollow/main/install.sh | sh
#
# Or, if you would rather read a script before running it, which is a reasonable
# thing to want from a script you found on the internet:
#
#   curl -fsSL https://raw.githubusercontent.com/DevInIndia/hollow/main/install.sh -o install.sh
#   less install.sh
#   sh install.sh
#
# Environment:
#   HOLLOW_VERSION       release tag to install, or "latest" (the default)
#   HOLLOW_INSTALL_DIR   where the binary goes (default $HOME/.local/bin)
#
# The binary is checked against the SHA256SUMS published with the same release
# before it is installed, and a mismatch installs nothing. Nothing is written
# outside the install directory, and nothing is run as root.

set -eu

REPO=DevInIndia/hollow
VERSION=${HOLLOW_VERSION:-latest}
INSTALL_DIR=${HOLLOW_INSTALL_DIR:-${HOME}/.local/bin}

die() {
	echo "install.sh: $*" >&2
	exit 1
}

# Which binary is this machine's.
os=$(uname -s)
arch=$(uname -m)

case $os in
Linux) os=linux ;;
Darwin) os=darwin ;;
MINGW* | MSYS* | CYGWIN*)
	die "this is a POSIX shell script and Windows needs the PowerShell one:
  irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex"
	;;
*) die "unrecognised operating system: $os" ;;
esac

case $arch in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unrecognised architecture: $arch" ;;
esac

# Checked against the published list by name rather than assumed from the
# detection above, because the two are not the same set. darwin/amd64 is the
# case that matters: an Intel Mac detects perfectly well and there is no asset
# for it, so without this the script would download GitHub's 404 page, find no
# checksum line for it, and at best fail with something that reads like a
# network problem. This says the real thing instead.
case $os/$arch in
linux/amd64 | linux/arm64 | darwin/arm64) ;;
*)
	die "no published binary for $os/$arch.
  Published: linux/amd64, linux/arm64, darwin/arm64, windows/amd64.
  For $os/$arch, build from source with a Go toolchain:
    git clone https://github.com/$REPO.git && cd hollow && go build ./cmd/hollow"
	;;
esac

asset=hollow-$os-$arch

# "latest" is a permanent GitHub redirect to the newest release, so the common
# path never names a version and never goes stale.
if [ "$VERSION" = latest ]; then
	base=https://github.com/$REPO/releases/latest/download
else
	base=https://github.com/$REPO/releases/download/$VERSION
fi

# -f is the flag that matters: without it curl writes a 404 body to the output
# file and exits 0, and the script would carry on with an HTML error page.
if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q "$1" -O "$2"; }
else
	die "need curl or wget on PATH to download anything"
fi

# sha256sum is coreutils and so is missing on macOS, where shasum ships with the
# system perl. openssl is the last resort. Refusing outright is deliberate: an
# unverified install is the thing this script exists to avoid.
if command -v sha256sum >/dev/null 2>&1; then
	sum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
	sum() { openssl dgst -sha256 "$1" | tr ' ' '\n' | tail -n 1; }
else
	die "need sha256sum, shasum or openssl to verify the download"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "hollow: fetching $asset ($VERSION)"
fetch "$base/$asset" "$tmp/$asset" || die "could not download $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download $base/SHA256SUMS"

# The sums file carries bare filenames, so the asset name anchored to the end of
# the line identifies its row. The leading space is part of the match and not
# decoration: it is what stops a shorter name matching a longer one's line.
want=$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1) || true
[ -n "${want:-}" ] || die "SHA256SUMS from $VERSION has no entry for $asset"

got=$(sum "$tmp/$asset")
if [ "$want" != "$got" ]; then
	die "checksum mismatch for $asset. Nothing was installed.
  expected $want
  actual   $got"
fi
echo "hollow: sha256 verified"

# $HOME/.local/bin rather than /usr/local/bin, so that a script piped into a
# shell never asks for root. The cost is that the directory may not be on PATH,
# which is why the end of this script checks.
mkdir -p "$INSTALL_DIR" || die "could not create $INSTALL_DIR"
chmod 755 "$tmp/$asset"
mv "$tmp/$asset" "$INSTALL_DIR/hollow" || die "could not write to $INSTALL_DIR"

echo "hollow: installed $INSTALL_DIR/hollow"
echo

case ":$PATH:" in
*:"$INSTALL_DIR":*)
	echo "Try:  hollow resolve example.com"
	;;
*)
	echo "$INSTALL_DIR is not on your PATH. Add it:"
	echo
	echo "  export PATH=\"\$PATH:$INSTALL_DIR\""
	echo
	echo "Then try:  hollow resolve example.com"
	;;
esac
