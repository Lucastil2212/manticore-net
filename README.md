# Manticore Network Intelligence

Local packet sensor and terminal dashboard for networks you **own** or are **authorized** to monitor. Built for Raspberry Pi (Debian/Ubuntu) and other Linux hosts.

It captures traffic you can already see on a chosen interface, stores rotating PCAP files plus structured metadata in SQLite, and presents a live Textual TUI. Flow-level JSONL can be exported for local analysis. Packet payloads are **not** copied into the AI export.

## Features

- Live capture with Scapy / libpcap
- Rotating raw PCAP evidence (128 MB default)
- SQLite WAL database with FTS5 search
- TCP / UDP / ICMP metadata, DNS queries, ports, and TCP flags
- Flow aggregation
- Live Textual terminal UI
- Automatic iNNEXT / generic Linux gamepad detection via evdev
- Flow-level JSONL export for local experiments
- Runtime data stored **outside** the source tree

## Requirements

- Linux with `libpcap` (Raspberry Pi OS, Debian, or Ubuntu)
- Python 3.11+ recommended
- Root (or `cap_net_raw`) to sniff
- Optional: a Linux-visible gamepad (`/dev/input/event*`)

Python packages are listed in `requirements.txt`: `scapy`, `textual`, `evdev`, `psutil`.

## Install (Raspberry Pi / Debian)

```bash
git clone git@github.com:Lucastil2212/manticore-net.git
cd manticore-net
chmod +x scripts/install.sh run.sh
./scripts/install.sh
```

The installer creates a `.venv`, installs OS packages (`tcpdump`, `tshark`, `sqlite3`, `libpcap-dev`, …), and creates `~/manticore-net-data/`.

## Run

List interfaces, then start capture on the one you intend to monitor:

```bash
ip route
ip -br link
./run.sh eth0    # wired
./run.sh wlan0   # Wi-Fi
```

`run.sh` wraps the app with `sudo -E` so the virtualenv Python keeps `MANTICORE_HOME`.

Direct invocation:

```bash
sudo -E env MANTICORE_HOME="$HOME/manticore-net-data" \
  .venv/bin/python -m manticore_net.app -i eth0 --rotate-mb 128
```

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `MANTICORE_HOME` | `~/manticore-net-data` | Root directory for the database, PCAP files, exports, and logs |

There are **no API keys, tokens, or cloud credentials**. This project is fully local.

## Data layout

```
~/manticore-net-data/
  captures/          raw rotating PCAP
  data/network.db    packet metadata, flows, FTS index
  exports/           flow-level JSONL for local AI / analysis
  logs/              reserved for service logs
```

Override the location with `MANTICORE_HOME`. Those paths are gitignored. Never commit PCAPs, SQLite databases, or flow exports — they can contain addresses, DNS names, and other traffic from your network.

## Keyboard

| Key | Action |
| --- | --- |
| Arrow keys | Navigate |
| Enter | Select |
| `/` | Focus search |
| `s` | Start / stop capture |
| `r` | Refresh |
| `e` | Export flow-level JSONL |
| `q` | Quit |

## Controller

The program searches evdev for a device whose name contains `innext`, `gamepad`, `controller`, or `joystick`. Typical Linux mappings:

| Control | Action |
| --- | --- |
| D-pad | Navigate |
| A / South | Select |
| B / East | Back |
| X / North | Search |
| Start | Home |
| Select | Start / stop capture |

Mappings vary by pad. If yours differs, run `python -m evdev.evtest`, note the event codes, and adjust `Controller.run()` in `manticore_net/app.py`.

## Architecture

```
interface (eth0 / wlan0)
        │
        ▼
  Scapy AsyncSniffer ──► rotating PCAP (captures/)
        │
        ▼
  metadata + DNS QNAME ──► SQLite WAL (data/network.db)
        │                       │
        │                       ├── packets
        │                       ├── flows
        │                       └── FTS5 packet_search
        ▼
  Textual TUI (LIVE / FLOWS / DNS / HOSTS / SEARCH / AI DATA)
        │
        └── E key ──► JSONL export (exports/)  [no payload bytes]
```

## Capture scope

Capturing `eth0` records traffic **visible to that interface**. A normal switched LAN does not send other clients' unicast packets to the Pi. Network-wide visibility needs an authorized path: router/AP capture, switch mirror / SPAN, a tap, or the Pi sitting in the traffic path.

Unauthorized interception of network traffic is illegal in many jurisdictions. Use this only on networks you own or have explicit permission to monitor.

## Storage

PCAP files rotate at `--rotate-mb` (default 128). Rotation is not deletion: archive or remove old captures so the disk (especially an SD card) cannot fill.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m manticore_net.app -i eth0
```

Version is defined in `manticore_net/__init__.py`.

## License

MIT. See [LICENSE](LICENSE).
