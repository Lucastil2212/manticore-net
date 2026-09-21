#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import time
from datetime import datetime
from pathlib import Path

import psutil
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import DataTable, Footer, Header, Input, Static, TabbedContent, TabPane

from manticore_net.capture import Sensor
from manticore_net.controller import PadThread, watch as watch_pad
from manticore_net.packet import (
    Rec,
    endpoint,
    format_rec,
    human_bytes,
    human_rate,
    preview_rec,
    ts_ms,
)
from manticore_net.search import Query, parse_query
from manticore_net.store import DbWriter, LiveStore

BASE = Path(os.environ.get("MANTICORE_HOME", str(Path.home() / "manticore-net-data")))
DB_PATH = BASE / "data" / "network.db"
CAP_DIR = BASE / "captures"
EXPORT_DIR = BASE / "exports"
for _p in (DB_PATH.parent, CAP_DIR, EXPORT_DIR, BASE / "logs"):
    _p.mkdir(parents=True, exist_ok=True)

TABS = ("home", "live", "flows", "dns", "hosts", "discover", "search", "detail", "help")
TABLE_FOR_TAB = {
    "home": "watch",
    "live": "packets",
    "flows": "flows",
    "dns": "dns",
    "hosts": "hosts",
    "discover": "discover",
    "search": "results",
}
FILTERS = (
    "ALL",
    "TCP",
    "UDP",
    "DNS",
    "ICMP",
    "HTTPS",
    "HTTP",
    "SSH",
    "DNS-53",
)
FILTER_QUERY = {
    "ALL": "",
    "TCP": "tcp",
    "UDP": "udp",
    "DNS": "dns",
    "ICMP": "icmp",
    "HTTPS": "port:443",
    "HTTP": "port:80",
    "SSH": "port:22",
    "DNS-53": "port:53",
}
CONTROLS = (
    "A/Enter detail   B/Esc back   X find   Y filter   "
    "L/R views   D-pad move/page   Select capture   Start home"
)
HELP_TEXT = """MANTICORE  —  views, pad, search

HOME     landing page: rate, protocol mix, storage, top talkers
LIVE     scrolling packets (follow newest, or pause with D-pad)
FLOWS    conversations by endpoints
DNS      recent queries
HOSTS    addresses by volume
DISCOVER new hosts / new DNS / talkers
SEARCH   type to filter; Enter also searches disk history
DETAIL   one packet, host, or DNS name
HELP     this page

iNNEXT pad
  D-pad U/D     move list          D-pad L/R   page list
  L / R         previous / next view
  A             detail (HOME with no row → LIVE)
  B             back; resume follow; HOME
  X             find related host or DNS
  Y             filter  ALL → TCP → UDP → DNS → ICMP → HTTPS → HTTP → SSH
  Select        start / stop capture
  Start         HOME overview

Keyboard
  arrows / PgUp PgDn    [ ] views    Enter detail    Esc back
  / find    y filter    s capture    h home    e export    q quit

Search examples
  tcp     host:10.0.0.5     port:443     :22     dns:google
  tcp host:1.2.3.4 port:443

Storage lives in MANTICORE_HOME (default ~/manticore-net-data):
  captures/*.pcap    data/network.db    exports/*.jsonl
Capture only networks you own or are authorized to monitor.

Full manual: docs/MANUAL.md
"""


def _hhmmss(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def _merge_query(search_text: str, filter_name: str) -> Query:
    q = parse_query(search_text)
    f = parse_query(FILTER_QUERY[filter_name])
    if f.empty():
        return q
    q.protocols |= f.protocols
    q.dns_only = q.dns_only or f.dns_only
    q.ports |= f.ports
    q.ips.extend(f.ips)
    q.dns.extend(f.dns)
    q.terms.extend(f.terms)
    return q


def _sum_dir(path: Path) -> tuple[int, int]:
    files = 0
    nbytes = 0
    try:
        for item in path.iterdir():
            if item.is_file():
                files += 1
                nbytes += item.stat().st_size
    except OSError:
        pass
    return files, nbytes


class NetApp(App):
    TITLE = "Manticore Network Intelligence"
    CSS = """
    Screen { background: #050505; }
    #status { height: 5; border: solid #1f7a1f; padding: 0 1; color: #ccffcc; }
    #feedback { height: 1; color: #99cc99; padding: 0 1; }
    #feedback.hit { color: #050505; background: #66ff66; }
    #preview { height: 6; border: solid #2a8a2a; padding: 0 1; color: #cceecc; }
    DataTable { height: 1fr; }
    #search { margin: 0 1 1 1; }
    #search-help { color: #88aa88; padding: 0 1; height: 2; }
    .panel { border: solid #1f7a1f; padding: 1; color: #ccffcc; }
    #detail-body { height: 1fr; padding: 1; color: #ccffcc; }
    #overview-board { height: 12; border: solid #1f7a1f; padding: 0 1; color: #cceecc; }
    #help-body { height: 1fr; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("s", "toggle", "Capture"),
        Binding("slash", "find", "Find"),
        Binding("e", "export", "Export"),
        Binding("y", "cycle_filter", "Filter"),
        Binding("left_square_bracket", "tab_prev", "Prev"),
        Binding("right_square_bracket", "tab_next", "Next"),
        Binding("enter", "inspect", "Detail"),
        Binding("d", "inspect", "Detail", show=False),
        Binding("escape", "back", "Back"),
        Binding("h", "home", "Home"),
        Binding("r", "refresh_now", "Refresh", show=False),
        Binding("pageup", "page_up", "Page", show=False),
        Binding("pagedown", "page_down", "Page", show=False),
    ]

    def __init__(self, iface: str, rotate_mb: int):
        super().__init__()
        self.store = LiveStore()
        self.db = DbWriter(DB_PATH, self.store)
        self.sensor = Sensor(iface, CAP_DIR, self.store, self.db, rotate_mb)
        self.pad: PadThread | None = None
        self.controller = "not detected"
        self.filter_idx = 0
        self.follow = True
        self.search_text = ""
        self._meta: dict[str, list] = {}
        self._cpu = 0.0
        self._ram = 0.0
        self._disk_free = 0
        self._disk_total = 1
        self._pcap_files = 0
        self._pcap_bytes = 0
        self._db_bytes = 0
        self._export_bytes = 0
        self._search_timer = None
        self._flash_timer = None
        self._last_sig: dict[str, object] = {}
        self._detail_target = None
        self._prev_tab = "home"
        self._last_feedback = CONTROLS
        self._last_status = ""
        self._last_preview = ""
        self._last_board = ""
        self._draw_t: dict[str, float] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Starting…", id="status")
        yield Static(CONTROLS, id="feedback")
        with TabbedContent(id="tabs"):
            with TabPane("HOME", id="tab-home"):
                with Vertical():
                    yield Static("Waiting for packets…", id="overview-board")
                    yield DataTable(id="watch", cursor_type="row", zebra_stripes=True)
            with TabPane("LIVE", id="tab-live"):
                yield DataTable(id="packets", cursor_type="row", zebra_stripes=True)
            with TabPane("FLOWS", id="tab-flows"):
                yield DataTable(id="flows", cursor_type="row", zebra_stripes=True)
            with TabPane("DNS", id="tab-dns"):
                yield DataTable(id="dns", cursor_type="row", zebra_stripes=True)
            with TabPane("HOSTS", id="tab-hosts"):
                yield DataTable(id="hosts", cursor_type="row", zebra_stripes=True)
            with TabPane("DISCOVER", id="tab-discover"):
                yield DataTable(id="discover", cursor_type="row", zebra_stripes=True)
            with TabPane("SEARCH", id="tab-search"):
                with Vertical():
                    yield Input(
                        placeholder="tcp host:1.2.3.4 port:443 dns:example  |  type live, Enter for disk",
                        id="search",
                    )
                    yield Static(
                        "tcp  |  udp port:53  |  host:192.168  |  dns:google  |  :443  |  ssh",
                        id="search-help",
                    )
                    yield DataTable(id="results", cursor_type="row", zebra_stripes=True)
            with TabPane("DETAIL", id="tab-detail"):
                yield Static("Highlight a packet, then press A / Enter.", id="detail-body", classes="panel")
            with TabPane("HELP", id="tab-help"):
                yield Static(HELP_TEXT, classes="panel", id="help-body")
        yield Static("Move onto a row to inspect it.", id="preview")
        yield Footer()

    def on_mount(self) -> None:
        self.db.start()
        cols = {
            "packets": ("Time", "Proto", "Source", "Destination", "Bytes", "DNS"),
            "watch": ("Kind", "What", "Detail"),
            "flows": ("Source", "Destination", "Proto", "Pkts", "Bytes", "Age"),
            "dns": ("Time", "Client", "Query"),
            "hosts": ("Host", "Packets", "Bytes", "Last"),
            "discover": ("Kind", "When", "What", "Detail"),
            "results": ("Time", "Proto", "Source", "Destination", "Bytes", "DNS"),
        }
        for ident, names in cols.items():
            self.query_one("#" + ident, DataTable).add_columns(*names)
        try:
            self.sensor.start()
        except Exception as e:
            self.notify(f"Capture failed: {e}", severity="error")
        self.pad = PadThread(emit=self._pad_emit, on_name=self._pad_name)
        self.pad.start()
        self.set_interval(0.35, self.refresh_visible)
        self.set_interval(2.0, self._sample_sys)
        self._sample_sys()
        self._show_tab("home")

    def _sample_sys(self) -> None:
        self._cpu = psutil.cpu_percent(interval=None)
        self._ram = psutil.virtual_memory().percent
        try:
            usage = shutil.disk_usage(BASE)
            self._disk_total = usage.total
            self._disk_free = usage.free
        except OSError:
            pass
        self._pcap_files, self._pcap_bytes = _sum_dir(CAP_DIR)
        _, self._export_bytes = _sum_dir(EXPORT_DIR)
        try:
            self._db_bytes = sum(
                p.stat().st_size for p in DB_PATH.parent.glob("network.db*") if p.is_file()
            )
        except OSError:
            self._db_bytes = 0

    def set_controller_name(self, name: str) -> None:
        self.controller = name
        self._flash("PAD", name)

    def _pad_emit(self, action: str) -> None:
        try:
            self.call_from_thread(self.handle_pad, action)
        except Exception:
            pass

    def _pad_name(self, name: str) -> None:
        try:
            self.call_from_thread(self.set_controller_name, name)
        except Exception:
            pass

    def _flash(self, button: str, message: str) -> None:
        text = f"{button}  {message}"
        self._last_feedback = text
        fb = self.query_one("#feedback", Static)
        fb.update(text)
        fb.add_class("hit")
        if self._flash_timer is not None:
            self._flash_timer.stop()
        self._flash_timer = self.set_timer(0.35, self._unflash)

    def _unflash(self) -> None:
        fb = self.query_one("#feedback", Static)
        fb.remove_class("hit")
        fb.update(CONTROLS)
        self._last_feedback = CONTROLS

    def _due(self, key: str, min_s: float) -> bool:
        now = time.monotonic()
        if now - self._draw_t.get(key, 0.0) < min_s:
            return False
        self._draw_t[key] = now
        return True

    def _set_static(self, ident: str, text: str, cache_attr: str) -> None:
        if getattr(self, cache_attr) == text:
            return
        setattr(self, cache_attr, text)
        self.query_one("#" + ident, Static).update(text)

    def _bar(self, frac: float, width: int = 18) -> str:
        frac = max(0.0, min(1.0, frac))
        filled = int(round(frac * width))
        return "█" * filled + "░" * (width - filled)

    def _tab(self) -> str:
        active = self.query_one("#tabs", TabbedContent).active or "tab-home"
        return active.removeprefix("tab-")

    def _show_tab(self, name: str) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-" + name

    def _search_focused(self) -> bool:
        try:
            return self.query_one("#search", Input).has_focus
        except Exception:
            return False

    def _active_table(self) -> DataTable | None:
        ident = TABLE_FOR_TAB.get(self._tab())
        if not ident:
            return None
        try:
            return self.query_one("#" + ident, DataTable)
        except Exception:
            return None

    def _selected_target(self):
        tab = self._tab()
        ident = TABLE_FOR_TAB.get(tab)
        if not ident:
            return self._detail_target
        table = self.query_one("#" + ident, DataTable)
        row = table.cursor_row
        meta = self._meta.get(ident, [])
        if row is None or row < 0 or row >= len(meta):
            return None
        return meta[row]

    def handle_pad(self, action: str) -> None:
        if not self.is_running:
            return
        searching = self._search_focused()
        if searching:
            results = self.query_one("#results", DataTable)
            if action == "up":
                results.action_cursor_up()
                self._sync_preview()
                return
            if action == "down":
                results.action_cursor_down()
                self._sync_preview()
                return
            if action in ("left", "right"):
                self.simulate_key(action)
                return
            if action == "inspect":
                self.action_inspect()
                return
            if action == "back":
                self.action_back()
                return
        dispatch = {
            "up": self.action_cursor_up,
            "down": self.action_cursor_down,
            "left": self.action_page_up,
            "right": self.action_page_down,
            "inspect": self.action_inspect,
            "back": self.action_back,
            "search": self.action_find,
            "filter": self.action_cycle_filter,
            "tab_prev": self.action_tab_prev,
            "tab_next": self.action_tab_next,
            "capture": self.action_toggle,
            "home": self.action_home,
            "page_up": self.action_page_up,
            "page_down": self.action_page_down,
        }
        fn = dispatch.get(action)
        if fn:
            fn()
        if action in ("up", "down"):
            return
        if action in ("tab_prev", "tab_next"):
            self._flash("L" if action == "tab_prev" else "R", self._tab().upper())
        elif action == "filter":
            self._flash("Y", f"filter {FILTERS[self.filter_idx]}")
        elif action == "capture":
            self._flash("Select", "CAPTURING" if self.sensor.running else "STOPPED")
        elif action == "home":
            self._flash("Start", "HOME")
        elif action in ("page_up", "page_down", "left", "right"):
            return

    def action_cursor_up(self) -> None:
        t = self._active_table()
        if t is None:
            return
        t.action_cursor_up()
        if self._tab() == "live" and t.cursor_row not in (0, None):
            self.follow = False
        self._sync_preview()

    def action_cursor_down(self) -> None:
        t = self._active_table()
        if t is None:
            return
        t.action_cursor_down()
        if self._tab() == "live" and t.cursor_row not in (0, None):
            self.follow = False
        self._sync_preview()

    def action_page_up(self) -> None:
        t = self._active_table()
        if t is None:
            return
        self.follow = False
        if hasattr(t, "action_page_up"):
            t.action_page_up()
        else:
            for _ in range(12):
                t.action_cursor_up()
        self._sync_preview()

    def action_page_down(self) -> None:
        t = self._active_table()
        if t is None:
            return
        self.follow = False
        if hasattr(t, "action_page_down"):
            t.action_page_down()
        else:
            for _ in range(12):
                t.action_cursor_down()
        self._sync_preview()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._sync_preview()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_inspect()

    def action_tab_next(self) -> None:
        self._shift_tab(1)

    def action_tab_prev(self) -> None:
        self._shift_tab(-1)

    def _shift_tab(self, delta: int) -> None:
        tabs = self.query_one("#tabs", TabbedContent)
        cur = self._tab()
        idx = TABS.index(cur) if cur in TABS else 0
        nxt = TABS[(idx + delta) % len(TABS)]
        self._prev_tab = cur
        tabs.active = "tab-" + nxt
        self._focus_tab_body()
        self._sync_preview()

    def _focus_tab_body(self) -> None:
        tab = self._tab()
        if tab == "search":
            self.query_one("#search", Input).focus()
            return
        if tab in ("detail", "help"):
            return
        t = self._active_table()
        if t is not None:
            t.focus()

    def action_home(self) -> None:
        self.follow = True
        self._show_tab("home")
        try:
            self.query_one("#watch", DataTable).focus()
        except Exception:
            pass
        self._sync_preview()

    def action_back(self) -> None:
        if self._tab() == "detail":
            back = self._prev_tab if self._prev_tab not in ("detail",) else "home"
            self._show_tab(back)
            self._focus_tab_body()
            self._sync_preview()
            return
        if self._search_focused():
            t = self.query_one("#results", DataTable)
            t.focus()
            return
        if not self.follow:
            self.follow = True
            self._flash("B", "follow newest")
            return
        self.action_home()

    def action_find(self) -> None:
        target = self._selected_target()
        text = self._query_for_target(target) if target is not None else ""
        if text:
            self.query_one("#search", Input).value = text
            self.search_text = text
            self._show_tab("search")
            self.action_run_search()
            self._flash("X", text)
            return
        self._show_tab("search")
        self.query_one("#search", Input).focus()

    def action_cycle_filter(self) -> None:
        self.filter_idx = (self.filter_idx + 1) % len(FILTERS)
        self.follow = True
        self._last_sig.clear()
        self.refresh_visible()

    def action_toggle(self) -> None:
        if self.sensor.running:
            self.sensor.stop()
        else:
            try:
                self.sensor.start()
            except Exception as e:
                self.notify(f"Capture failed: {e}", severity="error")

    def action_export(self) -> None:
        path = self._export_jsonl()
        self._flash("E", f"exported {path.name}")
        self.notify(f"Exported {path}")

    def _export_jsonl(self) -> Path:
        import json

        EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        path = EXPORT_DIR / f"ai_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        flows = self.store.snapshot_flows(10_000)
        with path.open("w") as f:
            for fl in flows:
                d = {
                    "first_seen": fl["first"],
                    "last_seen": fl["last"],
                    "src_ip": fl["src_ip"],
                    "dst_ip": fl["dst_ip"],
                    "src_port": fl["src_port"],
                    "dst_port": fl["dst_port"],
                    "protocol": fl["protocol"],
                    "packets": fl["packets"],
                    "bytes": fl["bytes"],
                    "duration_s": max(0.0, fl["last"] - fl["first"]),
                }
                f.write(json.dumps(d, separators=(",", ":")) + "\n")
        return path

    def action_inspect(self) -> None:
        if self._search_focused():
            self.action_run_search()
            return
        target = self._selected_target()
        if target is None:
            if self._tab() == "home":
                self.follow = True
                self._show_tab("live")
                self.query_one("#packets", DataTable).focus()
                self._flash("A", "LIVE")
                return
            self._flash("A", "nothing selected")
            return
        if isinstance(target, tuple) and target[0] == "proto":
            name = str(target[1]).upper()
            if name in FILTERS:
                self.filter_idx = FILTERS.index(name)
                self._last_sig.clear()
                self._flash("A", f"filter {name}")
                self._show_tab("live")
                self.refresh_visible()
            return
        self._prev_tab = self._tab()
        self._detail_target = target
        self._render_detail()
        self._show_tab("detail")
        self._flash("A", "packet detail")

    def _query_for_target(self, target) -> str:
        if isinstance(target, Rec):
            if target.dns_query:
                return f"dns:{target.dns_query}"
            if target.dst_ip:
                return f"host:{target.dst_ip}"
            if target.src_ip:
                return f"host:{target.src_ip}"
            return ""
        if isinstance(target, tuple):
            kind, value = target[0], target[1]
            if kind == "dns":
                return f"dns:{value}"
            if kind == "proto":
                return str(value).lower()
            return f"host:{value}"
        if isinstance(target, str):
            return f"host:{target}"
        return ""

    def _render_detail(self) -> None:
        body = self.query_one("#detail-body", Static)
        target = self._detail_target
        if isinstance(target, Rec):
            body.update(
                format_rec(
                    target,
                    flow=self.store.flow_for(target),
                    src_host=self.store.host_for(target.src_ip),
                    dst_host=self.store.host_for(target.dst_ip),
                )
            )
            return
        if isinstance(target, tuple) and target[0] == "dns":
            name = target[1]
            recs = [r for r in self.store.snapshot_dns(200) if r.dns_query == name]
            lines = [f"DNS  {name}", f"Seen in buffer  {len(recs)}", ""]
            for r in recs[:12]:
                lines.append(f"  {ts_ms(r.ts)}  {r.src_ip or ''}")
            body.update("\n".join(lines) or "No DNS rows")
            return
        ip = target if isinstance(target, str) else target[1] if isinstance(target, tuple) else ""
        host = self.store.host_for(ip)
        lines = [f"HOST  {ip}"]
        if host:
            lines.append(
                f"Packets {host['packets']:,}   {human_bytes(host['bytes'])}   "
                f"first {ts_ms(host['first'])}   last {ts_ms(host['last'])}"
            )
        lines.append("")
        lines.append("Recent flows")
        for f in self.store.flows_for_ip(ip, 12):
            lines.append(
                f"  {endpoint(f['src_ip'], f['src_port'])} → {endpoint(f['dst_ip'], f['dst_port'])}  "
                f"{f['protocol']}  {f['packets']} pkts  {human_bytes(f['bytes'])}"
            )
        body.update("\n".join(lines))

    def _sync_preview(self) -> None:
        target = self._selected_target()
        text = "HOME  A LIVE    X search    Y filter    Select capture    L/R views"
        if self._tab() == "home" and target is None:
            self._set_static("preview", text, "_last_preview")
            return
        if isinstance(target, Rec):
            flow = self.store.flow_for(target)
            extra = ""
            if flow:
                extra = (
                    f"flow {flow['packets']:,} pkts  {human_bytes(flow['bytes'])}  "
                    f"{max(0.0, flow['last'] - flow['first']):.2f}s"
                )
            self._set_static("preview", preview_rec(target, extra), "_last_preview")
            return
        if isinstance(target, tuple) and target[0] == "dns":
            self._set_static(
                "preview",
                f"DNS  {target[1]}\nA / Enter  full detail    X  find this name",
                "_last_preview",
            )
            return
        if isinstance(target, tuple) and target[0] == "proto":
            self._set_static(
                "preview",
                f"Protocol {target[1]}\nA  filter LIVE to this protocol",
                "_last_preview",
            )
            return
        if isinstance(target, (str, tuple)):
            ip = target if isinstance(target, str) else target[1]
            host = self.store.host_for(str(ip))
            if host:
                self._set_static(
                    "preview",
                    f"HOST  {host['ip']}  {host['packets']:,} pkts  {human_bytes(host['bytes'])}\n"
                    f"A  host detail    X  find this address",
                    "_last_preview",
                )
                return
        self._set_static(
            "preview",
            "Move onto a row, then A / Enter for full packet detail.",
            "_last_preview",
        )

    def action_run_search(self) -> None:
        inp = self.query_one("#search", Input)
        self.search_text = inp.value.strip()
        q = _merge_query(self.search_text, FILTERS[self.filter_idx])
        live = list(reversed(self.store.snapshot_packets(400, q)))
        disk: list[Rec] = []
        if self.search_text:
            rows = self.db.search(q, 200)
            for ts, proto, sip, sp, dip, dp, length, dns in rows:
                try:
                    tsf = datetime.fromisoformat(ts).timestamp() if ts else 0.0
                except ValueError:
                    tsf = 0.0
                disk.append(
                    Rec(
                        ts=tsf,
                        iface="",
                        src_ip=sip,
                        dst_ip=dip,
                        src_port=sp,
                        dst_port=dp,
                        protocol=proto or "OTHER",
                        length=length or 0,
                        tcp_flags=None,
                        dns_query=dns,
                    )
                )
        seen: set[tuple] = set()
        merged: list[Rec] = []
        for r in live + disk:
            key = (round(r.ts, 4), r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.protocol, r.length, r.dns_query)
            if key in seen:
                continue
            seen.add(key)
            merged.append(r)
        merged.sort(key=lambda r: r.ts, reverse=True)
        self._fill_recs("results", merged[:250])
        self.query_one("#results", DataTable).focus()
        self._sync_preview()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "search":
            return
        self.search_text = event.value.strip()
        if self._search_timer is not None:
            self._search_timer.stop()
        self._search_timer = self.set_timer(0.08, self._live_search)

    def _live_search(self) -> None:
        q = _merge_query(self.search_text, FILTERS[self.filter_idx])
        recs = list(reversed(self.store.snapshot_packets(200, q)))
        self._fill_recs("results", recs)
        self._sync_preview()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search":
            self.action_run_search()

    def action_refresh_now(self) -> None:
        self._last_sig.clear()
        self.refresh_visible()

    def refresh_visible(self) -> None:
        n, nbytes, pps, bps, qdrop = self.store.stats()
        qdepth = self.db.q.qsize()
        filt = FILTERS[self.filter_idx]
        cap = "CAPTURING" if self.sensor.running else "STOPPED"
        follow = "FOLLOW" if self.follow else "PAUSED"
        disk_used_pct = 100.0 * (1.0 - (self._disk_free / self._disk_total)) if self._disk_total else 0.0
        cur_pcap = self.sensor.current_bytes
        rotate = self.sensor.rotate_bytes
        pcap_name = self.sensor.pcap_path.name if self.sensor.pcap_path else "-"
        status = (
            f"{cap}  {self.sensor.iface}  {self.controller}  {filt}  {follow}  {self._tab().upper()}\n"
            f"{n:,} pkts  {human_bytes(nbytes)}  {pps:,.0f} pps  {human_rate(bps)}  "
            f"q {qdepth} drop {qdrop}  CPU {self._cpu:.0f}%  RAM {self._ram:.0f}%\n"
            f"disk {human_bytes(self._disk_free)} free / {human_bytes(self._disk_total)} "
            f"({disk_used_pct:.0f}% used)  pcap {human_bytes(self._pcap_bytes)} ({self._pcap_files})  "
            f"db {human_bytes(self._db_bytes)}  exp {human_bytes(self._export_bytes)}\n"
            f"current {pcap_name}  {human_bytes(cur_pcap)} / {human_bytes(rotate)}"
        )
        self._set_static("status", status, "_last_status")
        tab = self._tab()
        if tab == "home":
            if self._due("home", 0.5):
                self._refresh_home(n, nbytes, pps, bps)
        elif tab == "live":
            if self.follow and self._due("live", 0.45):
                q = _merge_query("", filt)
                recs = list(reversed(self.store.snapshot_packets(80, q)))
                sig = (filt, recs[0].ts if recs else 0, len(recs))
                if self._last_sig.get("live") != sig:
                    self._fill_recs("packets", recs)
                    self._last_sig["live"] = sig
                    t = self.query_one("#packets", DataTable)
                    if t.row_count:
                        t.move_cursor(row=0)
                    self._sync_preview()
        elif tab == "flows":
            if self._due("flows", 0.7):
                flows = self.store.snapshot_flows(80)
                sig = (len(flows), flows[0]["last"] if flows else 0, flows[0]["packets"] if flows else 0)
                if self._last_sig.get("flows") != sig:
                    self._fill_flows(flows)
                    self._last_sig["flows"] = sig
        elif tab == "dns":
            if self._due("dns", 0.6):
                dns = list(reversed(self.store.snapshot_dns(80)))
                sig = (len(dns), dns[0].ts if dns else 0)
                if self._last_sig.get("dns") != sig:
                    self._fill_dns(dns)
                    self._last_sig["dns"] = sig
        elif tab == "hosts":
            if self._due("hosts", 0.8):
                hosts = self.store.snapshot_hosts(50)
                sig = (len(hosts), hosts[0]["bytes"] if hosts else 0)
                if self._last_sig.get("hosts") != sig:
                    self._fill_hosts(hosts)
                    self._last_sig["hosts"] = sig
        elif tab == "discover":
            if self._due("discover", 0.7):
                d = self.store.snapshot_discover()
                sig = (
                    d["unique_hosts"],
                    d["unique_dns"],
                    d["flows"],
                    d["talkers"][0]["bytes"] if d["talkers"] else 0,
                )
                if self._last_sig.get("discover") != sig:
                    self._fill_discover(d)
                    self._last_sig["discover"] = sig
        elif tab == "search" and not self._search_focused() and self._due("search", 0.45):
            self._live_search()

    def _refresh_home(self, n: int, nbytes: int, pps: float, bps: float) -> None:
        d = self.store.snapshot_discover()
        total_p = sum(c for _, c in d["protocols"]) or 1
        proto_lines = []
        for proto, count in d["protocols"][:6]:
            proto_lines.append(f"  {proto:<6} {self._bar(count / total_p)}  {count / total_p:5.0%}  {count:,}")
        if not proto_lines:
            proto_lines = ["  (no traffic yet)"]
        talk = d["talkers"][:5]
        talk_lines = [
            f"  {h['ip']:<40} {human_bytes(h['bytes']):>8}  {h['packets']:,} pkts" for h in talk
        ] or ["  (none)"]
        dns_lines = [f"  {name}" for _, name, _ in list(reversed(d["new_dns"]))[:4]] or ["  (none)"]
        cap = "CAPTURING" if self.sensor.running else "STOPPED"
        board = "\n".join(
            [
                f"{cap}  {self.sensor.iface}  {pps:,.0f} pps  {human_rate(bps)}  {n:,} pkts  {human_bytes(nbytes)}",
                f"CPU {self._cpu:.0f}%   RAM {self._ram:.0f}%   hosts {d['unique_hosts']}   dns {d['unique_dns']}   flows {d['flows']}",
                f"disk {human_bytes(self._disk_free)} free   pcap {human_bytes(self._pcap_bytes)}   db {human_bytes(self._db_bytes)}",
                "",
                "Protocols",
                *proto_lines,
                "Top talkers",
                *talk_lines,
                "New DNS",
                *dns_lines,
            ]
        )
        self._set_static("overview-board", board, "_last_board")
        sig = (
            d["unique_hosts"],
            d["unique_dns"],
            talk[0]["bytes"] if talk else 0,
            d["new_hosts"][-1][1] if d["new_hosts"] else "",
        )
        if self._last_sig.get("home") != sig:
            self._fill_watch(d)
            self._last_sig["home"] = sig
            self._sync_preview()

    def _fill_watch(self, d: dict) -> None:
        rows = []
        meta = []
        for h in d["talkers"][:8]:
            rows.append(("talker", h["ip"], f"{human_bytes(h['bytes'])}  {h['packets']:,} pkts"))
            meta.append(("host", h["ip"]))
        for ts, ip in list(reversed(d["new_hosts"]))[:6]:
            rows.append(("new-host", ip, _hhmmss(ts)))
            meta.append(("host", ip))
        for ts, name, client in list(reversed(d["new_dns"]))[:6]:
            rows.append(("new-dns", name, client or _hhmmss(ts)))
            meta.append(("dns", name))
        self._set_rows("watch", rows, meta)

    def _fill_recs(self, ident: str, recs: list[Rec]) -> None:
        rows = [
            (
                _hhmmss(r.ts),
                r.protocol,
                endpoint(r.src_ip, r.src_port),
                endpoint(r.dst_ip, r.dst_port),
                r.length,
                r.dns_query or "",
            )
            for r in recs
        ]
        self._set_rows(ident, rows, recs)

    def _fill_flows(self, flows: list[dict]) -> None:
        now = time.time()
        rows = []
        meta = []
        for f in flows:
            rows.append(
                (
                    endpoint(f["src_ip"], f["src_port"]),
                    endpoint(f["dst_ip"], f["dst_port"]),
                    f["protocol"],
                    f["packets"],
                    f["bytes"],
                    f"{max(0.0, now - f['last']):.0f}s",
                )
            )
            meta.append(
                Rec(
                    ts=f["last"],
                    iface="",
                    src_ip=f["src_ip"],
                    dst_ip=f["dst_ip"],
                    src_port=f["src_port"],
                    dst_port=f["dst_port"],
                    protocol=f["protocol"],
                    length=f["bytes"],
                    tcp_flags=None,
                    dns_query=None,
                )
            )
        self._set_rows("flows", rows, meta)

    def _fill_dns(self, recs: list[Rec]) -> None:
        rows = [(_hhmmss(r.ts), r.src_ip or "", r.dns_query or "") for r in recs]
        self._set_rows("dns", rows, recs)

    def _fill_hosts(self, hosts: list[dict]) -> None:
        rows = [
            (h["ip"], h["packets"], h["bytes"], _hhmmss(h["last"]))
            for h in hosts
        ]
        self._set_rows("hosts", rows, [h["ip"] for h in hosts])

    def _fill_discover(self, d: dict) -> None:
        rows = []
        meta = []
        for proto, count in d["protocols"]:
            rows.append(("proto", "", proto, f"{count:,} packets"))
            meta.append(("proto", proto))
        for ts, ip in reversed(d["new_hosts"]):
            rows.append(("new-host", _hhmmss(ts), ip, "first seen"))
            meta.append(("host", ip))
        for ts, name, client in reversed(d["new_dns"]):
            rows.append(("new-dns", _hhmmss(ts), name, client or ""))
            meta.append(("dns", name))
        for h in d["talkers"]:
            rows.append(("talker", _hhmmss(h["last"]), h["ip"], f"{h['bytes']:,} B / {h['packets']:,} pkts"))
            meta.append(("host", h["ip"]))
        self._set_rows("discover", rows, meta)

    def _set_rows(self, ident: str, rows: list, meta: list) -> None:
        t = self.query_one("#" + ident, DataTable)
        cur = t.cursor_row
        t.clear()
        if rows:
            t.add_rows(rows)
            if cur is not None and t.row_count and ident != "packets":
                t.move_cursor(row=min(cur, t.row_count - 1))
        self._meta[ident] = meta

    def on_unmount(self) -> None:
        if self.pad is not None:
            self.pad.stop()
        try:
            self.sensor.stop()
        except Exception:
            pass
        try:
            self.db.stop()
            if self.db.is_alive():
                self.db.join(timeout=2.0)
        except RuntimeError:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description="Manticore Network Intelligence")
    ap.add_argument("-i", "--interface", default="eth0")
    ap.add_argument("--rotate-mb", type=int, default=128)
    ap.add_argument(
        "--map-controller",
        action="store_true",
        help="watch iNNEXT events (sudo if /dev/input is restricted)",
    )
    args = ap.parse_args()
    if args.map_controller:
        raise SystemExit(watch_pad())
    NetApp(args.interface, args.rotate_mb).run()


if __name__ == "__main__":
    main()
