#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "[1/4] Installing OS packages..."
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump tshark sqlite3 libpcap-dev
cd "$ROOT"
echo "[2/4] Creating virtual environment..."
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
echo "[3/4] Creating data directories..."
mkdir -p "$HOME/manticore-net-data"/{data,captures,exports,logs}
echo "[4/4] Done."
echo "Run: cd '$ROOT' && sudo -E env MANTICORE_HOME='$HOME/manticore-net-data' .venv/bin/python -m manticore_net.app -i eth0"
