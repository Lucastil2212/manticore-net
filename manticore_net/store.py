"""In-memory live store (UI source of truth) + batched SQLite writer."""
from __future__ import annotations

import sqlite3
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Full, Queue

from manticore_net.packet import Rec, summary
from manticore_net.search import Query, like_sql, matches

LIVE_CAP = 8000
DNS_CAP = 1500
NEW_CAP = 120
FLOW_SOFT_MAX = 20000
QUEUE_MAX = 8192
BATCH = 256
FLUSH_S = 0.05
FLOW_FLUSH_S = 1.0


class LiveStore:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.packets: deque[Rec] = deque(maxlen=LIVE_CAP)
        self.flows: dict[str, dict] = {}
        self.hosts: dict[str, dict] = {}
        self.dns: deque[Rec] = deque(maxlen=DNS_CAP)
        self.new_hosts: deque[tuple[float, str]] = deque(maxlen=NEW_CAP)
        self.new_dns: deque[tuple[float, str, str | None]] = deque(maxlen=NEW_CAP)
        self.dns_first: dict[str, float] = {}
        self.protocols = Counter()
        self.n = 0
        self.nbytes = 0
        self.qdrop = 0
        self._tick_n = 0
        self._tick_b = 0
        self._tick_t = time.monotonic()
        self.pps = 0.0
        self.bps = 0.0

    def ingest(self, r: Rec) -> None:
        with self.lock:
            self.packets.append(r)
            self.n += 1
            self.nbytes += r.length
            self.protocols[r.protocol] += 1
            key = f"{r.src_ip}:{r.src_port}->{r.dst_ip}:{r.dst_port}/{r.protocol}"
            fl = self.flows.get(key)
            if fl is None:
                self.flows[key] = {
                    "first": r.ts,
                    "last": r.ts,
                    "src_ip": r.src_ip,
                    "dst_ip": r.dst_ip,
                    "src_port": r.src_port,
                    "dst_port": r.dst_port,
                    "protocol": r.protocol,
                    "packets": 1,
                    "bytes": r.length,
                    "dirty": True,
                }
            else:
                fl["last"] = r.ts
                fl["packets"] += 1
                fl["bytes"] += r.length
                fl["dirty"] = True
            for ip in (r.src_ip, r.dst_ip):
                if not ip:
                    continue
                h = self.hosts.get(ip)
                if h is None:
                    self.hosts[ip] = {
                        "ip": ip,
                        "packets": 1,
                        "bytes": r.length,
                        "first": r.ts,
                        "last": r.ts,
                    }
                    self.new_hosts.append((r.ts, ip))
                else:
                    h["packets"] += 1
                    h["bytes"] += r.length
                    h["last"] = r.ts
            if r.dns_query:
                self.dns.append(r)
                first = self.dns_first.get(r.dns_query)
                if first is None:
                    self.dns_first[r.dns_query] = r.ts
                    self.new_dns.append((r.ts, r.dns_query, r.src_ip))
            if len(self.flows) > FLOW_SOFT_MAX:
                self._evict_flows()
            now = time.monotonic()
            dt = now - self._tick_t
            if dt >= 0.5:
                self.pps = (self.n - self._tick_n) / dt
                self.bps = (self.nbytes - self._tick_b) / dt
                self._tick_n = self.n
                self._tick_b = self.nbytes
                self._tick_t = now

    def _evict_flows(self) -> None:
        items = sorted(self.flows.items(), key=lambda kv: kv[1]["last"])
        for key, _ in items[: len(items) // 5]:
            self.flows.pop(key, None)

    def snapshot_packets(self, n: int, q: Query | None = None) -> list[Rec]:
        with self.lock:
            data = list(self.packets)
        if q is None or q.empty():
            if n < len(data):
                return data[-n:]
            return data
        out: list[Rec] = []
        for r in reversed(data):
            if matches(r, q):
                out.append(r)
                if len(out) >= n:
                    break
        out.reverse()
        return out

    def snapshot_flows(self, n: int = 100) -> list[dict]:
        with self.lock:
            items = sorted(self.flows.values(), key=lambda f: f["last"], reverse=True)
            return [dict(x) for x in items[:n]]

    def snapshot_dns(self, n: int = 120) -> list[Rec]:
        with self.lock:
            data = list(self.dns)
        return data[-n:]

    def snapshot_hosts(self, n: int = 60) -> list[dict]:
        with self.lock:
            items = sorted(self.hosts.values(), key=lambda h: h["bytes"], reverse=True)
            return [dict(x) for x in items[:n]]

    def snapshot_discover(self) -> dict:
        with self.lock:
            proto = self.protocols.most_common()
            new_h = list(self.new_hosts)[-40:]
            new_d = list(self.new_dns)[-40:]
            talkers = sorted(self.hosts.values(), key=lambda h: h["bytes"], reverse=True)[:15]
            return {
                "protocols": proto,
                "new_hosts": new_h,
                "new_dns": new_d,
                "talkers": [dict(x) for x in talkers],
                "unique_hosts": len(self.hosts),
                "unique_dns": len(self.dns_first),
                "flows": len(self.flows),
            }

    def dirty_flows(self) -> list[dict]:
        with self.lock:
            out = [dict(f) for f in self.flows.values() if f.get("dirty")]
            for f in self.flows.values():
                f["dirty"] = False
        return out

    def flow_for(self, r: Rec) -> dict | None:
        key = f"{r.src_ip}:{r.src_port}->{r.dst_ip}:{r.dst_port}/{r.protocol}"
        with self.lock:
            fl = self.flows.get(key)
            return dict(fl) if fl else None

    def host_for(self, ip: str | None) -> dict | None:
        if not ip:
            return None
        with self.lock:
            h = self.hosts.get(ip)
            return dict(h) if h else None

    def flows_for_ip(self, ip: str, n: int = 10) -> list[dict]:
        with self.lock:
            hits = [f for f in self.flows.values() if f["src_ip"] == ip or f["dst_ip"] == ip]
            hits.sort(key=lambda f: f["last"], reverse=True)
            return [dict(x) for x in hits[:n]]

    def stats(self) -> tuple[int, int, float, float, int]:
        with self.lock:
            return self.n, self.nbytes, self.pps, self.bps, self.qdrop


class DbWriter(threading.Thread):
    def __init__(self, path: Path, store: LiveStore):
        super().__init__(daemon=True, name="db-writer")
        self.path = path
        self.store = store
        self.q: Queue[Rec] = Queue(maxsize=QUEUE_MAX)
        self.stop_flag = threading.Event()
        self.conn: sqlite3.Connection | None = None

    def put(self, r: Rec) -> None:
        try:
            self.q.put_nowait(r)
            return
        except Full:
            pass
        try:
            self.q.get_nowait()
        except Empty:
            pass
        try:
            self.q.put_nowait(r)
        except Full:
            self.store.qdrop += 1

    def run(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, check_same_thread=True)
        self.conn = conn
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA cache_size=-8000")
        conn.execute("PRAGMA mmap_size=67108864")
        conn.executescript(
            """
CREATE TABLE IF NOT EXISTS packets(
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  timestamp TEXT NOT NULL,
  interface TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  protocol TEXT,
  length INTEGER,
  tcp_flags TEXT,
  dns_query TEXT,
  summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_packets_dport ON packets(dst_port);
CREATE INDEX IF NOT EXISTS idx_packets_dns ON packets(dns_query);
CREATE TABLE IF NOT EXISTS flows(
  flow_key TEXT PRIMARY KEY,
  first_seen REAL,
  last_seen REAL,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  protocol TEXT,
  packets INTEGER,
  bytes INTEGER
);
"""
        )
        conn.commit()
        buf: list[Rec] = []
        last_flow = time.monotonic()
        while not self.stop_flag.is_set() or not self.q.empty() or buf:
            try:
                item = self.q.get(timeout=FLUSH_S)
                buf.append(item)
                if len(buf) >= BATCH:
                    self._flush_packets(conn, buf)
                    buf.clear()
            except Empty:
                if buf:
                    self._flush_packets(conn, buf)
                    buf.clear()
            now = time.monotonic()
            if now - last_flow >= FLOW_FLUSH_S:
                self._flush_flows(conn)
                last_flow = now
        if buf:
            self._flush_packets(conn, buf)
        self._flush_flows(conn)
        conn.close()

    def _flush_packets(self, conn: sqlite3.Connection, buf: list[Rec]) -> None:
        rows = []
        for r in buf:
            ts_iso = datetime.fromtimestamp(r.ts, timezone.utc).isoformat()
            rows.append(
                (
                    r.ts,
                    ts_iso,
                    r.iface,
                    r.src_ip,
                    r.dst_ip,
                    r.src_port,
                    r.dst_port,
                    r.protocol,
                    r.length,
                    r.tcp_flags,
                    r.dns_query,
                    summary(r),
                )
            )
        conn.executemany(
            """INSERT INTO packets(ts,timestamp,interface,src_ip,dst_ip,src_port,dst_port,protocol,length,tcp_flags,dns_query,summary)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        conn.commit()

    def _flush_flows(self, conn: sqlite3.Connection) -> None:
        dirty = self.store.dirty_flows()
        if not dirty:
            return
        conn.executemany(
            """INSERT INTO flows(flow_key,first_seen,last_seen,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(flow_key) DO UPDATE SET
                 last_seen=excluded.last_seen,
                 packets=excluded.packets,
                 bytes=excluded.bytes""",
            [
                (
                    f"{f['src_ip']}:{f['src_port']}->{f['dst_ip']}:{f['dst_port']}/{f['protocol']}",
                    f["first"],
                    f["last"],
                    f["src_ip"],
                    f["dst_ip"],
                    f["src_port"],
                    f["dst_port"],
                    f["protocol"],
                    f["packets"],
                    f["bytes"],
                )
                for f in dirty
            ],
        )
        conn.commit()

    def search(self, q: Query, n: int = 200) -> list[tuple]:
        if self.conn is None:
            return []
        where, args = like_sql(q)
        sql = (
            "SELECT timestamp,protocol,src_ip,src_port,dst_ip,dst_port,length,dns_query "
            f"FROM packets WHERE {where} ORDER BY id DESC LIMIT ?"
        )
        args.append(n)
        try:
            ro = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, check_same_thread=False)
            try:
                return ro.execute(sql, args).fetchall()
            finally:
                ro.close()
        except sqlite3.Error:
            return []

    def stop(self) -> None:
        self.stop_flag.set()
