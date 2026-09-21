#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export MANTICORE_HOME="${MANTICORE_HOME:-$HOME/manticore-net-data}"
cd "$ROOT"
if [[ "${1:-}" == "--map-controller" ]]; then
  exec sudo -E "$ROOT/.venv/bin/python" -m manticore_net.controller --watch
fi
IFACE="${1:-eth0}"
exec sudo -E env MANTICORE_HOME="$MANTICORE_HOME" "$ROOT/.venv/bin/python" -m manticore_net -i "$IFACE"
