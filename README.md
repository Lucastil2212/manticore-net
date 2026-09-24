# TRIAD Soccer

Local street soccer client by **Manticore Technologies Studio**. Gameplay and graphics run on your machine; online seats use the same Glyph Grid Render host (`glyphgrid.online`).

**Modes:** 3v3 Solo vs AI · 1v1 Goalie Shootouts · Local 2-player · Online  
**Input:** Xbox · PlayStation · iNNEXT / DragonRise · keyboard · mouse (remappable)

Play in the browser anytime: https://glyphgrid.online/apps/triad/

---

## Install (Linux · macOS · Windows)

### Linux (Debian, Ubuntu, Fedora, Arch, Raspberry Pi OS, …) and macOS

```bash
git clone git@github.com:Lucastil2212/manticore-net.git
cd manticore-net
chmod +x scripts/install-triad.sh
./scripts/install-triad.sh
```

Then launch:

| OS | Command |
| --- | --- |
| Linux / Raspberry Pi | `~/triad-soccer/scripts/run.sh` |
| macOS | `~/triad-soccer/scripts/run-macos.sh` |
| Raspberry Pi desktop entry | `~/triad-soccer/scripts/install-pi.sh` |

Needs `curl` or `wget`, plus `unzip` or `python3`. Optional: `rsync`.

### Windows

In PowerShell from the repo:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install-triad.ps1
```

Then double-click `%USERPROFILE%\triad-soccer\scripts\run-windows.bat`  
(requires Python 3, or open `index.html` in Chrome).

### Manual downloads

| Platform | Package |
| --- | --- |
| Linux x64 | [triad-soccer-linux-x64.zip](https://glyphgrid.online/downloads/triad/triad-soccer-linux-x64.zip) |
| Linux arm64 (Pi 4/5, Apple-class ARM boards) | [triad-soccer-linux-arm64.zip](https://glyphgrid.online/downloads/triad/triad-soccer-linux-arm64.zip) |
| Linux armhf (Pi 3 / 32-bit) | [triad-soccer-linux-armhf.zip](https://glyphgrid.online/downloads/triad/triad-soccer-linux-armhf.zip) |
| macOS (Intel + Apple Silicon) | [triad-soccer-macos.zip](https://glyphgrid.online/downloads/triad/triad-soccer-macos.zip) |
| Windows x64 | [triad-soccer-win-x64.zip](https://glyphgrid.online/downloads/triad/triad-soccer-win-x64.zip) |

Catalog: https://glyphgrid.online/downloads/ · Manifest: https://glyphgrid.online/downloads/triad/latest.json

### Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `TRIAD_HOME` | `~/triad-soccer` | Install directory |
| `TRIAD_CDN` | `https://glyphgrid.online` | Download host |
| `TRIAD_PORT` | `8765` | Local HTTP port used by `run.sh` |
| `TRIAD_BROWSER` | (auto) | Override browser binary on Linux |

---

## How to play

- **Solo** — you + bots, first to 5 (or most goals at 2:00)
- **Shootout** — 1v1 goalie duel
- **Local 2P** — two pads / keyboard split on one machine
- **Online** — connects to `wss://glyphgrid.online` (same sim as the arena)

Chip over the tackle. Don't fly the bar. Controllers remap under **Controls**.

---

## Network sensor (optional)

This repo also ships **Manticore Network Intelligence** — a local packet sensor / Textual TUI for networks you own or are authorized to monitor (Raspberry Pi / Linux).

```bash
chmod +x scripts/install.sh run.sh
./scripts/install.sh
./run.sh eth0
```

See [docs/MANUAL.md](docs/MANUAL.md) for the full sensor manual.

## License

MIT. See [LICENSE](LICENSE).
