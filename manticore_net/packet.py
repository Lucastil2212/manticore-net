"""Hot-path packet parse. No Scapy summary(), no DNS layer dissect."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
except Exception:  # pragma: no cover
    ICMP = IP = TCP = UDP = IPv6 = None  # type: ignore

PROTO_TCP = "TCP"
PROTO_UDP = "UDP"
PROTO_ICMP = "ICMP"
PROTO_OTHER = "OTHER"

PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    137: "netbios",
    138: "netbios",
    139: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    500: "ike",
    587: "submission",
    853: "dot",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1900: "ssdp",
    3306: "mysql",
    3389: "rdp",
    3516: "6lowpan",
    5353: "mdns",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    6443: "k8s",
    8080: "http-alt",
    8443: "https-alt",
}


@dataclass(slots=True, frozen=True)
class Rec:
    ts: float
    iface: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    tcp_flags: str | None
    dns_query: str | None


def port_label(port: int | None) -> str:
    if port is None:
        return ""
    name = PORTS.get(port)
    return f"{port}/{name}" if name else str(port)


def endpoint(ip: str | None, port: int | None) -> str:
    if not ip:
        return ""
    if port is None:
        return ip
    name = PORTS.get(port)
    return f"{ip}:{port}/{name}" if name else f"{ip}:{port}"


_FLAG_NAMES = (
    ("F", "FIN"),
    ("S", "SYN"),
    ("R", "RST"),
    ("P", "PSH"),
    ("A", "ACK"),
    ("U", "URG"),
    ("E", "ECE"),
    ("C", "CWR"),
)


def tcp_flag_names(flags: str | None) -> str:
    if not flags:
        return ""
    names = [name for ch, name in _FLAG_NAMES if ch in flags]
    return " ".join(names) if names else str(flags)


def human_bytes(n: int | float) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(value)}B"
            return f"{value:.1f}{unit}"
        value /= 1024.0
    return f"{n}B"


def human_rate(n: float) -> str:
    return f"{human_bytes(n)}/s"


def ts_full(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def ts_ms(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]


def summary(r: Rec) -> str:
    if r.dns_query:
        return f"DNS {r.src_ip or ''} {r.dns_query}"
    left = endpoint(r.src_ip, r.src_port)
    right = endpoint(r.dst_ip, r.dst_port)
    flags = f" {r.tcp_flags}" if r.tcp_flags else ""
    return f"{r.protocol} {left} > {right}{flags}".strip()


def preview_rec(r: Rec, extra: str = "") -> str:
    flags = tcp_flag_names(r.tcp_flags)
    proto = f"{r.protocol} {flags}".strip()
    line1 = f"{ts_ms(r.ts)}  {proto}  {human_bytes(r.length)}  {r.iface or '-'}"
    line2 = f"{endpoint(r.src_ip, r.src_port)}  →  {endpoint(r.dst_ip, r.dst_port)}"
    line3 = f"DNS {r.dns_query}" if r.dns_query else "A / Enter  full packet detail    X  find related"
    if extra:
        return f"{line1}\n{line2}\n{extra}\n{line3}"
    return f"{line1}\n{line2}\n{line3}"


def format_rec(r: Rec, flow: dict | None = None, src_host: dict | None = None, dst_host: dict | None = None) -> str:
    flags = tcp_flag_names(r.tcp_flags)
    lines = [
        f"PACKET  {r.protocol}  {human_bytes(r.length)}",
        f"Time     {ts_full(r.ts)}",
        f"Iface    {r.iface or '-'}",
        f"Source   {endpoint(r.src_ip, r.src_port)}",
        f"Dest     {endpoint(r.dst_ip, r.dst_port)}",
    ]
    if flags or r.tcp_flags:
        lines.append(f"TCP      {flags or ''}  ({r.tcp_flags})")
    if r.dns_query:
        lines.append(f"DNS      {r.dns_query}")
    lines.append(f"Summary  {summary(r)}")
    if flow:
        dur = max(0.0, flow["last"] - flow["first"])
        lines.append("")
        lines.append(
            f"FLOW     {flow['packets']:,} packets  {human_bytes(flow['bytes'])}  "
            f"{dur:.2f}s  last {ts_ms(flow['last'])}"
        )
    if src_host:
        lines.append(
            f"SRC host {src_host['ip']}  {src_host['packets']:,} pkts  {human_bytes(src_host['bytes'])}"
        )
    if dst_host:
        lines.append(
            f"DST host {dst_host['ip']}  {dst_host['packets']:,} pkts  {human_bytes(dst_host['bytes'])}"
        )
    lines.append("")
    lines.append("B back   X find this host/DNS   Y filter")
    return "\n".join(lines)


def dns_qname(payload: bytes) -> str | None:
    if len(payload) < 13:
        return None

    def read_name(start: int) -> str | None:
        labels: list[str] = []
        off = start
        jumped = False
        hops = 0
        while hops < 12 and off < len(payload):
            length = payload[off]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                if off + 1 >= len(payload):
                    return None
                off = ((length & 0x3F) << 8) | payload[off + 1]
                jumped = True
                hops += 1
                continue
            if length & 0xC0:
                return None
            off += 1
            end = off + length
            if end > len(payload):
                return None
            label = payload[off:end]
            try:
                labels.append(label.decode("ascii"))
            except UnicodeDecodeError:
                labels.append(label.decode("latin-1", "replace"))
            off = end
            hops += 1
            if jumped and hops > 8:
                break
        if not labels:
            return None
        return ".".join(labels).rstrip(".")

    return read_name(12)


def parse_packet(pkt, iface: str) -> Rec:
    ts = float(pkt.time)
    length = int(getattr(pkt, "wirelen", None) or len(pkt))
    src_ip = dst_ip = None
    src_port = dst_port = None
    protocol = PROTO_OTHER
    tcp_flags = None
    dns = None

    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is not None:
        src_ip = ip.src
        dst_ip = ip.dst

    tcp = pkt.getlayer(TCP)
    if tcp is not None:
        protocol = PROTO_TCP
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        tcp_flags = str(tcp.flags)
    else:
        udp = pkt.getlayer(UDP)
        if udp is not None:
            protocol = PROTO_UDP
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            if src_port in (53, 5353) or dst_port in (53, 5353):
                raw = bytes(udp)
                if len(raw) > 8:
                    dns = dns_qname(raw[8:])
        elif pkt.getlayer(ICMP) is not None:
            protocol = PROTO_ICMP

    return Rec(
        ts=ts,
        iface=iface,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        tcp_flags=tcp_flags,
        dns_query=dns,
    )
