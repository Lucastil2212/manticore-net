"""Intuitive search: tokens, filters, and in-memory matching. No FTS syntax required."""
from __future__ import annotations

from dataclasses import dataclass, field

from manticore_net.packet import Rec

_PROTO = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "other": "OTHER"}


@dataclass(slots=True)
class Query:
    raw: str
    protocols: set[str] = field(default_factory=set)
    dns_only: bool = False
    ports: set[int] = field(default_factory=set)
    ips: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    terms: list[str] = field(default_factory=list)

    def empty(self) -> bool:
        return not (
            self.protocols
            or self.dns_only
            or self.ports
            or self.ips
            or self.dns
            or self.terms
        )


def parse_query(text: str) -> Query:
    q = Query(raw=text.strip())
    if not q.raw:
        return q
    for tok in q.raw.split():
        low = tok.lower()
        if low in _PROTO:
            q.protocols.add(_PROTO[low])
            continue
        if low == "dns":
            q.dns_only = True
            continue
        key, sep, val = tok.partition(":")
        k = key.lower()
        if sep and val:
            if k in {"port", "dport", "sport"}:
                try:
                    q.ports.add(int(val))
                except ValueError:
                    q.terms.append(low)
                continue
            if k in {"ip", "src", "dst", "host"}:
                q.ips.append(val.lower())
                continue
            if k in {"dns", "name", "qname"}:
                q.dns.append(val.lower())
                continue
            if k == "proto":
                mapped = _PROTO.get(val.lower())
                if mapped:
                    q.protocols.add(mapped)
                    continue
        if tok.startswith(":") and tok[1:].isdigit():
            q.ports.add(int(tok[1:]))
            continue
        if tok.isdigit():
            q.ports.add(int(tok))
            continue
        q.terms.append(low)
    return q


def _blob(r: Rec) -> str:
    parts = (
        r.src_ip or "",
        r.dst_ip or "",
        r.protocol,
        r.dns_query or "",
        str(r.src_port or ""),
        str(r.dst_port or ""),
        r.tcp_flags or "",
    )
    return " ".join(parts).lower()


def matches(r: Rec, q: Query) -> bool:
    if q.empty():
        return True
    if q.dns_only and not r.dns_query:
        return False
    if q.protocols and r.protocol not in q.protocols:
        return False
    if q.ports:
        if r.src_port not in q.ports and r.dst_port not in q.ports:
            return False
    if q.ips:
        src = (r.src_ip or "").lower()
        dst = (r.dst_ip or "").lower()
        if not any(ip in src or ip in dst for ip in q.ips):
            return False
    if q.dns:
        name = (r.dns_query or "").lower()
        if not any(d in name for d in q.dns):
            return False
    if q.terms:
        blob = _blob(r)
        if not all(t in blob for t in q.terms):
            return False
    return True


def like_sql(q: Query) -> tuple[str, list]:
    """Historical SQLite filter. Uses LIKE + indexed columns, not FTS MATCH."""
    where: list[str] = []
    args: list = []
    if q.dns_only:
        where.append("dns_query IS NOT NULL")
    if q.protocols:
        where.append(f"protocol IN ({','.join('?' * len(q.protocols))})")
        args.extend(q.protocols)
    if q.ports:
        where.append(
            "("
            + " OR ".join(["src_port=? OR dst_port=?"] * len(q.ports))
            + ")"
        )
        for p in q.ports:
            args.extend((p, p))
    for ip in q.ips:
        where.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
        pat = f"%{ip}%"
        args.extend((pat, pat))
    for d in q.dns:
        where.append("dns_query LIKE ?")
        args.append(f"%{d}%")
    for t in q.terms:
        where.append(
            "(src_ip LIKE ? OR dst_ip LIKE ? OR dns_query LIKE ? OR protocol LIKE ? OR summary LIKE ?)"
        )
        pat = f"%{t}%"
        args.extend((pat, pat, pat, pat, pat))
    sql = " AND ".join(where) if where else "1"
    return sql, args
