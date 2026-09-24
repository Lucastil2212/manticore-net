#!/usr/bin/env bash
# Install TRIAD Soccer local client on Linux (any distro), macOS, or WSL.
# Windows: use scripts/install-triad.ps1 (or Git Bash / WSL with this script).
# Usage: ./scripts/install-triad.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${TRIAD_HOME:-$HOME/triad-soccer}"
BASE="${TRIAD_CDN:-https://glyphgrid.online}"
MANIFEST_URL="${TRIAD_MANIFEST:-$BASE/downloads/triad/latest.json}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

die() {
  echo "error: $*" >&2
  exit 1
}

# --- OS / arch ---------------------------------------------------------------
OS_RAW="$(uname -s 2>/dev/null || echo unknown)"
ARCH_RAW="$(uname -m 2>/dev/null || echo unknown)"
OS="$(printf '%s' "$OS_RAW" | tr '[:upper:]' '[:lower:]')"
ARCH="$(printf '%s' "$ARCH_RAW" | tr '[:upper:]' '[:lower:]')"

# Git Bash / MSYS / Cygwin on Windows → treat as Windows
case "$OS" in
  mingw*|msys*|cygwin*) OS="windows" ;;
  linux*) OS="linux" ;;
  darwin*) OS="macos" ;;
  freebsd*|openbsd*|netbsd*) OS="bsd" ;;
esac

# WSL reports Linux; keep linux package (Chromium works under WSL2+WSLg)
if [[ "$OS" == "linux" ]] && grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
  echo "Detected WSL — installing Linux client"
fi

case "$ARCH" in
  aarch64|arm64) ARCH_KEY="arm64" ;;
  armv7l|armv6l|armhf|armv7|armv6) ARCH_KEY="armhf" ;;
  x86_64|amd64) ARCH_KEY="x64" ;;
  i386|i686|x86) ARCH_KEY="x86" ;;
  *) ARCH_KEY="$ARCH" ;;
esac

pick_zip() {
  case "$OS" in
    linux)
      case "$ARCH_KEY" in
        arm64) echo "triad-soccer-linux-arm64.zip" ;;
        armhf) echo "triad-soccer-linux-armhf.zip" ;;
        x64)   echo "triad-soccer-linux-x64.zip" ;;
        *)
          echo "Unsupported Linux arch: $ARCH_RAW (need x64, arm64, or armhf)" >&2
          return 1
          ;;
      esac
      ;;
    macos)
      # Universal web client package (Apple Silicon + Intel)
      echo "triad-soccer-macos.zip"
      ;;
    windows)
      case "$ARCH_KEY" in
        x64|arm64) echo "triad-soccer-win-x64.zip" ;;
        *)
          echo "Unsupported Windows arch: $ARCH_RAW (need x64)" >&2
          return 1
          ;;
      esac
      ;;
    bsd)
      # Same static client as Linux x64 / arm64
      case "$ARCH_KEY" in
        arm64) echo "triad-soccer-linux-arm64.zip" ;;
        x64)   echo "triad-soccer-linux-x64.zip" ;;
        *)
          echo "Unsupported BSD arch: $ARCH_RAW" >&2
          return 1
          ;;
      esac
      ;;
    *)
      echo "Unsupported OS: $OS_RAW" >&2
      echo "  Supported: Linux (Debian, Ubuntu, Fedora, Arch, Raspberry Pi OS, …)," >&2
      echo "             macOS, Windows (use install-triad.ps1), WSL, FreeBSD." >&2
      return 1
      ;;
  esac
}

ZIP="$(pick_zip)" || exit 1
URL="$BASE/downloads/triad/$ZIP"

# Prefer manifest key when available (non-fatal)
if need_cmd curl || need_cmd wget; then
  MANIFEST_TMP="$(mktemp 2>/dev/null || echo /tmp/triad-manifest.$$)"
  if need_cmd curl; then
    curl -fsSL "$MANIFEST_URL" -o "$MANIFEST_TMP" 2>/dev/null || true
  else
    wget -qO "$MANIFEST_TMP" "$MANIFEST_URL" 2>/dev/null || true
  fi
  if [[ -s "$MANIFEST_TMP" ]] && need_cmd python3; then
    KEY=""
    case "$OS-$ARCH_KEY" in
      linux-arm64) KEY="linux-arm64" ;;
      linux-armhf) KEY="linux-armhf" ;;
      linux-x64)   KEY="linux-x64" ;;
      macos-*)     KEY="macos" ;;
      windows-*)   KEY="win-x64" ;;
      bsd-arm64)   KEY="linux-arm64" ;;
      bsd-x64)     KEY="linux-x64" ;;
    esac
    if [[ -n "$KEY" ]]; then
      REL="$(python3 -c "
import json,sys
try:
  d=json.load(open(sys.argv[1]))
  print(d.get('downloads',{}).get(sys.argv[2],''))
except Exception:
  pass
" "$MANIFEST_TMP" "$KEY" 2>/dev/null || true)"
      if [[ -n "${REL:-}" ]]; then
        case "$REL" in
          http*) URL="$REL" ;;
          /*)    URL="$BASE$REL" ;;
          *)     URL="$BASE/downloads/triad/$REL" ;;
        esac
      fi
    fi
  fi
  rm -f "$MANIFEST_TMP" 2>/dev/null || true
fi

echo "TRIAD Soccer · local install"
echo "  os=$OS  arch=$ARCH_RAW  →  $URL"
echo "  dest=$PREFIX"

TMP="$(mktemp -d 2>/dev/null || mktemp -d -t triad)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

download() {
  local dest="$1"
  if need_cmd curl; then
    curl -fsSL "$URL" -o "$dest"
  elif need_cmd wget; then
    wget -qO "$dest" "$URL"
  else
    die "need curl or wget to download TRIAD"
  fi
}

extract_zip() {
  local zip="$1" out="$2"
  mkdir -p "$out"
  if need_cmd unzip; then
    unzip -qo "$zip" -d "$out"
  elif need_cmd python3; then
    python3 - "$zip" "$out" <<'PY'
import sys, zipfile
zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])
PY
  else
    die "need unzip or python3 to extract the package"
  fi
}

sync_tree() {
  local src="$1" dest="$2"
  mkdir -p "$dest"
  if need_cmd rsync; then
    rsync -a --delete "$src/" "$dest/"
  else
    # Portable fallback (no rsync on minimal macOS / some distros)
    find "$dest" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
    if need_cmd cp && cp -a "$src"/. "$dest"/ 2>/dev/null; then
      :
    else
      tar -C "$src" -cf - . | tar -C "$dest" -xf -
    fi
  fi
}

download "$TMP/triad.zip"
extract_zip "$TMP/triad.zip" "$TMP/out"

# Zip root is triad-soccer-*-vX.Y.Z/ — find the app root by index.html
INDEX_HTML="$(find "$TMP/out" -maxdepth 3 -name index.html 2>/dev/null | head -1 || true)"
[[ -n "$INDEX_HTML" ]] || die "downloaded zip has no index.html (bad package?)"
SRC="$(dirname "$INDEX_HTML")"
[[ -f "$SRC/index.html" ]] || die "downloaded zip has no index.html (bad package?)"

sync_tree "$SRC" "$PREFIX"
chmod +x "$PREFIX/scripts/"*.sh 2>/dev/null || true

# Convenience link from this repo
ln -sfn "$PREFIX" "$ROOT/triad-soccer" 2>/dev/null || true

echo "✓ TRIAD Soccer ready at $PREFIX"
case "$OS" in
  macos)
    echo "  Run:  $PREFIX/scripts/run-macos.sh"
    echo "   or:  $PREFIX/scripts/run.sh"
    ;;
  windows)
    echo "  Run:  $PREFIX/scripts/run-windows.bat"
    ;;
  *)
    echo "  Run:  $PREFIX/scripts/run.sh"
    if [[ -f /etc/rpi-issue ]] || grep -qi raspberry /proc/device-tree/model 2>/dev/null; then
      echo "  Pi desktop entry + autostart:  $PREFIX/scripts/install-pi.sh"
    fi
    ;;
esac
echo "  Online host: glyphgrid.online  ·  Browser play: https://glyphgrid.online/apps/triad/"
echo "  Downloads:   https://glyphgrid.online/downloads/"
