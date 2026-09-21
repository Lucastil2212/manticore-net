#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "[1/5] Installing OS packages..."
sudo apt update
sudo apt install -y python3 python3-venv python3-pip tcpdump tshark sqlite3 libpcap-dev
cd "$ROOT"
echo "[2/5] Creating virtual environment..."
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
echo "[3/5] Creating data directories..."
mkdir -p "$HOME/manticore-net-data"/{data,captures,exports,logs}
echo "[4/5] Allowing gamepad access via input group..."
sudo usermod -aG input "${SUDO_USER:-$USER}" || true
echo "[5/5] Done."
echo "Run: cd '$ROOT' && ./run.sh eth0"
echo "Map pad: ./run.sh --map-controller"
echo "If the controller is not visible until reboot, log out or run: newgrp input"
