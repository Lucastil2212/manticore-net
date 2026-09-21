"""Capture thread: cheap parse, unsynced PCAP, never waits on SQLite."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from scapy.config import conf
from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapWriter

from manticore_net.packet import parse_packet
from manticore_net.store import DbWriter, LiveStore

conf.verb = 0


class Sensor:
    def __init__(self, iface: str, cap_dir: Path, store: LiveStore, db: DbWriter, rotate_mb: int = 128):
        self.iface = iface
        self.cap_dir = cap_dir
        self.store = store
        self.db = db
        self.rotate_bytes = rotate_mb * 1024 * 1024
        self.running = False
        self.writer: PcapWriter | None = None
        self.sniffer: AsyncSniffer | None = None
        self.current_bytes = 0
        self.pcap_path: Path | None = None

    def _new_writer(self) -> None:
        if self.writer is not None:
            try:
                self.writer.close()
            except Exception:
                pass
        self.cap_dir.mkdir(parents=True, exist_ok=True)
        self.pcap_path = self.cap_dir / f"{self.iface}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        self.writer = PcapWriter(str(self.pcap_path), append=False, sync=False)
        self.current_bytes = 0

    def start(self) -> None:
        if self.running:
            return
        self._new_writer()
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self.handle, store=False)
        self.sniffer.start()
        self.running = True

    def stop(self) -> None:
        if not self.running:
            return
        try:
            if self.sniffer is not None:
                self.sniffer.stop()
        except Exception:
            pass
        try:
            if self.writer is not None:
                self.writer.close()
        except Exception:
            pass
        self.writer = None
        self.sniffer = None
        self.running = False

    def handle(self, pkt) -> None:
        try:
            rec = parse_packet(pkt, self.iface)
            w = self.writer
            if w is not None:
                if self.current_bytes >= self.rotate_bytes:
                    self._new_writer()
                    w = self.writer
                w.write(pkt)
                self.current_bytes += rec.length
            self.store.ingest(rec)
            self.db.put(rec)
        except Exception:
            pass
