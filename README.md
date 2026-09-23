# Manticore Network Intelligence

Local packet sensor and terminal dashboard for networks you **own** or are **authorized** to monitor. Built for Raspberry Pi (Debian/Ubuntu) and other Linux hosts.

It captures traffic you can already see on a chosen interface, stores rotating PCAP files plus structured metadata in SQLite, and presents a live Textual TUI driven by keyboard or an **iNNEXT SNES USB pad**. Flow-level JSONL can be exported for local analysis. Packet payloads are **not** copied into the AI export.

## Features

- **HOME** overview: rate, protocol mix, storage, top talkers
- Live capture with Scapy / libpcap (capture path never waits on SQLite)
- In-memory ring buffer for the UI (real-time first)
- Batched WAL SQLite writer for history
- Rotating unsynced PCAP evidence (128 MB default)
- Packet DETAIL (flags, endpoints, flow and host totals)
- Token search: `tcp`, `host:10.0.0.5`, `port:443`, `dns:example`, `:22`
- DISCOVER tab: new hosts, new DNS names, top talkers, protocol mix
- iNNEXT mapped from the real DragonRise `0079:0011` evdev codes

## TRIAD Soccer (local client)

Install the lightweight TRIAD client (same Glyph Grid Render host for online):

```bash
./scripts/install-triad.sh
~/triad-soccer/scripts/run.sh
```

Downloads: https://glyphgrid.online/downloads/

## Requirements

- Linux with `libpcap` (Raspberry Pi OS, Debian, or Ubuntu)
- Python 3.11+ recommended
- Root (or `cap_net_raw`) to sniff
- Optional: iNNEXT USB gamepad (`/dev/input/event*`, group `input`)

Python packages are listed in `requirements.txt`: `scapy`, `textual`, `evdev`, `psutil`.

## Install (Raspberry Pi / Debian)

```bash
git clone git@github.com:Lucastil2212/manticore-net.git
cd manticore-net
chmod +x scripts/install.sh run.sh
./scripts/install.sh
```

The installer creates a `.venv`, installs OS packages, creates `~/manticore-net-data/`, and adds your user to the `input` group so the pad can be read.

## Run

```bash
ip route
ip -br link
./run.sh eth0    # wired
./run.sh wlan0   # Wi-Fi
```

`run.sh` wraps the app with `sudo -E` so the virtualenv Python keeps `MANTICORE_HOME`.

Confirm the iNNEXT mapping (press buttons; Ctrl+C to stop):

```bash
./run.sh --map-controller
```

You should see `USB Gamepad` / `innext` and actions like `up`, `inspect`, `tab_next`.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `MANTICORE_HOME` | `~/manticore-net-data` | Root directory for the database, PCAP files, exports, and logs |

There are **no API keys, tokens, or cloud credentials**. This project is fully local.

## Data layout

```
~/manticore-net-data/
  captures/          raw rotating PCAP
  data/network.db    packet metadata and flows
  exports/           flow-level JSONL for local AI / analysis
  logs/              reserved for service logs
```

Override the location with `MANTICORE_HOME`. Those paths are gitignored. Never commit PCAPs, SQLite databases, or flow exports.

## Keyboard

| Key | Action |
| --- | --- |
| Arrow up/down | Move in the list |
| PageUp / PageDown | Page the list |
| `[` / `]` | Previous / next view |
| Enter / `d` | Packet or row detail |
| Esc | Back (close detail, resume follow) |
| `/` | Find related, or open SEARCH |
| `y` | Cycle traffic filter |
| `s` | Start / stop capture |
| `h` | HOME |
| `e` | Export flow-level JSONL |
| `q` | Quit |

The app opens on **HOME**. Start / `h` always returns there. Full controls: in-app HELP tab and [docs/MANUAL.md](docs/MANUAL.md).

## iNNEXT controller

Linux exposes the wired iNNEXT as **DragonRise Inc. Gamepad** (`0079:0011`, name `USB Gamepad`).

| Physical | Action |
| --- | --- |
| D-pad up/down | Move in the current list |
| D-pad left/right | Page the list |
| L / R | Previous / next view |
| A | Packet / row detail |
| B | Back |
| X | Find related host or DNS |
| Y | Cycle filter |
| Select | Toggle capture |
| Start | HOME overview |

The green flash bar confirms each button. Generic pads that speak `BTN_SOUTH` / hat switches still work as a fallback.

## Search and discovery

Type in SEARCH; results update from the live buffer as you type. Enter also scans SQLite history.

| Query | Meaning |
| --- | --- |
| `tcp` `udp` `icmp` `dns` | Protocol / DNS-only |
| `port:443` or `:443` or `443` | Source or destination port |
| `host:8.8.8.8` `ip:10.0` | Substring on src/dst IP |
| `dns:google` | DNS QNAME substring |
| `tcp host:1.2.3.4 port:443` | Combined (AND) |

A / Enter opens DETAIL for that row. X searches the host or DNS name.

DISCOVER lists new hosts, new DNS names, top talkers, and protocol counts from the in-memory index. The status bar shows pps, throughput, CPU, RAM, queue depth, PCAP/DB size, and disk free.

## Architecture

```
interface
    │
    ▼
Scapy AsyncSniffer ──► unsynced rotating PCAP
    │
    ├── cheap parse (no pkt.summary(), raw DNS QNAME)
    ├── in-memory ring / flows / hosts   ◄── TUI reads this only
    └── queue (drop-oldest if backed up)
            │
            ▼
      batched SQLite WAL writer (256 rows / 50 ms)
```

The sniffer thread never commits SQLite. The TUI never walks the full database except on Enter in SEARCH. Only the visible tab is rebuilt, and LIVE skips redraws while you have follow paused.

## Capture scope

Capturing `eth0` records traffic **visible to that interface**. A normal switched LAN does not send other clients' unicast packets to the Pi. Network-wide visibility needs an authorized path: router/AP capture, switch mirror / SPAN, a tap, or the Pi sitting in the traffic path.

Unauthorized interception of network traffic is illegal in many jurisdictions. Use this only on networks you own or have explicit permission to monitor.

## Storage

PCAP files rotate at `--rotate-mb` (default 128). Rotation is not deletion: archive or remove old captures so the disk (especially an SD card) cannot fill.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m manticore_net -i eth0
.venv/bin/python -m manticore_net.controller --watch
```

Version is defined in `manticore_net/__init__.py`.

## License

MIT. See [LICENSE](LICENSE).
