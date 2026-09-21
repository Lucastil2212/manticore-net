# Manticore Network Intelligence — Manual

Local packet sensor and terminal dashboard for **networks you own or are authorized to monitor**.

Version is in `manticore_net/__init__.py`.

## 1. What you are looking at

The app opens on **HOME**, a quiet overview for at-a-glance monitoring:

- capture state, packets/s, throughput, CPU, RAM
- protocol mix (bar graph)
- top talkers and newest DNS names
- selectable watch list (A opens detail, X finds that host/name)

Other views:

| View | Purpose |
| --- | --- |
| HOME | Landing / health |
| LIVE | Recent packets (auto-follow newest) |
| FLOWS | Conversations |
| DNS | Queries |
| HOSTS | Addresses by volume |
| DISCOVER | First-seen hosts and names |
| SEARCH | Live filter + disk history |
| DETAIL | One packet, host, or DNS name |
| HELP | In-app controls |

The strip under the table is a **preview** of the highlighted row. A / Enter opens the full DETAIL page.

## 2. Controller (iNNEXT)

Linux names the pad `USB Gamepad` (DragonRise `0079:0011`).

| Control | Action |
| --- | --- |
| D-pad up/down | Move in the list |
| D-pad left/right | Page the list |
| L / R | Previous / next view |
| A | Detail. On HOME with no row selected, opens LIVE |
| B | Back. Closes DETAIL, resumes follow, or returns HOME |
| X | Find this host or DNS name in SEARCH |
| Y | Cycle traffic filter |
| Select | Start / stop capture |
| Start | HOME |

The green bar flashes the button you pressed. D-pad paging does not flash, so holding a direction stays smooth.

Confirm mapping:

```bash
./run.sh --map-controller
```

## 3. Keyboard

| Key | Action |
| --- | --- |
| Arrows | Move |
| PageUp / PageDown | Page |
| `[` `]` | Views |
| Enter / `d` | Detail |
| Esc | Back |
| `/` | Find / SEARCH |
| `y` | Filter |
| `s` | Capture |
| `h` | HOME |
| `e` | Export JSONL |
| `q` | Quit |

On LIVE, moving off the newest row **pauses follow** so the row does not jump away. B or Start resumes a stable view.

## 4. Search

Type in SEARCH; the live buffer filters as you type. Enter also reads SQLite history.

| Query | Meaning |
| --- | --- |
| `tcp` `udp` `icmp` `dns` | Protocol / DNS-only |
| `port:443` `:443` `443` | Source or destination port |
| `host:10.0.0.5` `ip:10.0` | IP substring |
| `dns:google` | DNS name substring |
| `tcp host:1.2.3.4 port:443` | Combined (AND) |

Y cycles a global filter applied on LIVE and SEARCH: ALL, TCP, UDP, DNS, ICMP, HTTPS, HTTP, SSH, DNS-53.

## 5. Data and storage

Default root: `~/manticore-net-data` (`MANTICORE_HOME`).

```
captures/   rotating PCAP (not deleted on rotate — archive them)
data/       SQLite packet metadata and flows
exports/    flow-level JSONL (no payload bytes)
```

The status bar shows disk free, PCAP bytes, database size, current file vs rotate limit, queue depth, and drops.

The sniffer never waits on SQLite. The UI reads an in-memory ring. Only SEARCH Enter walks the database.

## 6. Capture scope and law

Traffic is only what this interface can see. A switched LAN does not copy other hosts’ unicast to the Pi unless you use a tap, SPAN/mirror, or the Pi is in the path.

Unauthorized interception is illegal in many places. Use this only with authorization.

## 7. Install and run

```bash
git clone git@github.com:Lucastil2212/manticore-net.git
cd manticore-net
./scripts/install.sh
./run.sh eth0          # or wlan0
./run.sh --map-controller
```

Needs Python 3.11+, libpcap, and usually root (or `cap_net_raw`). The installer adds your user to group `input` for the gamepad.
