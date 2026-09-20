#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
IFACE="${1:-eth0}"
export MANTICORE_HOME="${MANTICORE_HOME:-$HOME/manticore-net-data}"
cd "$ROOT"
exec sudo -E env MANTICORE_HOME="$MANTICORE_HOME" "$ROOT/.venv/bin/python" -m manticore_net.app -i "$IFACE"
