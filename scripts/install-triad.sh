#!/usr/bin/env bash
# Sync / install TRIAD Soccer onto this Pi from Glyph Grid downloads.
# Usage: ./scripts/install-triad.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${TRIAD_HOME:-$HOME/triad-soccer}"
BASE="${TRIAD_CDN:-https://glyphgrid.online}"
ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) ZIP="triad-soccer-linux-arm64.zip" ;;
  armv7l|armv6l|armhf) ZIP="triad-soccer-linux-armhf.zip" ;;
  x86_64|amd64) ZIP="triad-soccer-linux-x64.zip" ;;
  *) ZIP="triad-soccer-linux-arm64.zip" ;;
esac
URL="$BASE/downloads/triad/$ZIP"
TMP="$(mktemp -d)"

echo "Manticore Net → TRIAD Soccer install"
echo "  arch=$ARCH  →  $URL"

curl -fsSL "$URL" -o "$TMP/triad.zip"
unzip -qo "$TMP/triad.zip" -d "$TMP/out"
SRC="$(find "$TMP/out" -maxdepth 3 -name index.html | head -1 | xargs dirname)"
mkdir -p "$PREFIX"
rsync -a --delete "$SRC/" "$PREFIX/"
chmod +x "$PREFIX/scripts/"*.sh 2>/dev/null || true
rm -rf "$TMP"

# Link from manticore-net for convenience
ln -sfn "$PREFIX" "$ROOT/triad-soccer" 2>/dev/null || true

echo "✓ TRIAD Soccer ready at $PREFIX"
echo "  Run: $PREFIX/scripts/run.sh"
echo "  Or:  $PREFIX/scripts/install-pi.sh  (full desktop entry + systemd)"
