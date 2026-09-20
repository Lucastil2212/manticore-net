#!/usr/bin/env python3
import argparse, csv, json, os, sqlite3, threading, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import psutil
from scapy.all import AsyncSniffer, PcapWriter, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Header, Footer, Static, DataTable, Input, TabbedContent, TabPane

try:
    from evdev import InputDevice, list_devices, ecodes
except Exception:
    InputDevice = None

BASE = Path(os.environ.get("MANTICORE_HOME", str(Path.home()/"manticore-net-data")))
DB_PATH = BASE/"data"/"network.db"
CAP_DIR = BASE/"captures"
EXPORT_DIR = BASE/"exports"
for p in (DB_PATH.parent, CAP_DIR, EXPORT_DIR, BASE/"logs"): p.mkdir(parents=True, exist_ok=True)

class Database:
    def __init__(self):
        self.lock=threading.RLock(); self.conn=sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL"); self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript('''
CREATE TABLE IF NOT EXISTS packets(id INTEGER PRIMARY KEY,ts REAL NOT NULL,timestamp TEXT NOT NULL,interface TEXT,src_ip TEXT,dst_ip TEXT,src_port INTEGER,dst_port INTEGER,protocol TEXT,length INTEGER,tcp_flags TEXT,dns_query TEXT,summary TEXT);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts); CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip); CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip); CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(protocol);
CREATE TABLE IF NOT EXISTS flows(flow_key TEXT PRIMARY KEY,first_seen REAL,last_seen REAL,src_ip TEXT,dst_ip TEXT,src_port INTEGER,dst_port INTEGER,protocol TEXT,packets INTEGER,bytes INTEGER);
CREATE VIRTUAL TABLE IF NOT EXISTS packet_search USING fts5(summary,src_ip,dst_ip,protocol,dns_query);
'''); self.conn.commit()
    def insert(self,r):
        with self.lock:
            c=self.conn.execute('''INSERT INTO packets(ts,timestamp,interface,src_ip,dst_ip,src_port,dst_port,protocol,length,tcp_flags,dns_query,summary) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',tuple(r[k] for k in ('ts','timestamp','interface','src_ip','dst_ip','src_port','dst_port','protocol','length','tcp_flags','dns_query','summary')))
            i=c.lastrowid
            self.conn.execute("INSERT INTO packet_search(rowid,summary,src_ip,dst_ip,protocol,dns_query) VALUES(?,?,?,?,?,?)",(i,r['summary'],r['src_ip'] or '',r['dst_ip'] or '',r['protocol'],r['dns_query'] or ''))
            key=f"{r['src_ip']}:{r['src_port']}->{r['dst_ip']}:{r['dst_port']}/{r['protocol']}"
            self.conn.execute('''INSERT INTO flows VALUES(?,?,?,?,?,?,?,?,1,?) ON CONFLICT(flow_key) DO UPDATE SET last_seen=excluded.last_seen,packets=flows.packets+1,bytes=flows.bytes+excluded.bytes''',(key,r['ts'],r['ts'],r['src_ip'],r['dst_ip'],r['src_port'],r['dst_port'],r['protocol'],r['length']))
            self.conn.commit()
    def q(self,sql,args=()):
        with self.lock: return self.conn.execute(sql,args).fetchall()
    def recent(self,n=150): return self.q("SELECT id,timestamp,protocol,src_ip,src_port,dst_ip,dst_port,length,dns_query FROM packets ORDER BY id DESC LIMIT ?",(n,))
    def dns(self,n=100): return self.q("SELECT timestamp,src_ip,dns_query FROM packets WHERE dns_query IS NOT NULL ORDER BY id DESC LIMIT ?",(n,))
    def flows(self,n=100): return self.q("SELECT src_ip,src_port,dst_ip,dst_port,protocol,packets,bytes FROM flows ORDER BY last_seen DESC LIMIT ?",(n,))
    def hosts(self,n=50): return self.q("SELECT dst_ip,COUNT(*),SUM(length) FROM packets WHERE dst_ip IS NOT NULL GROUP BY dst_ip ORDER BY SUM(length) DESC LIMIT ?",(n,))
    def stats(self): return self.q("SELECT COUNT(*),COALESCE(SUM(length),0) FROM packets")[0]
    def search(self,s,n=100): return self.q("SELECT p.id,p.timestamp,p.protocol,p.src_ip,p.dst_ip,p.length,p.dns_query FROM packet_search s JOIN packets p ON p.id=s.rowid WHERE packet_search MATCH ? ORDER BY p.id DESC LIMIT ?",(s,n))
    def export_jsonl(self):
        path=EXPORT_DIR/f"ai_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        rows=self.q("SELECT first_seen,last_seen,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes FROM flows ORDER BY last_seen")
        with path.open('w') as f:
            for x in rows:
                d=dict(zip(('first_seen','last_seen','src_ip','dst_ip','src_port','dst_port','protocol','packets','bytes'),x)); d['duration_s']=max(0,d['last_seen']-d['first_seen']); f.write(json.dumps(d,separators=(',',':'))+'\n')
        return path
DB=Database()

def record(pkt,iface):
    ts=float(pkt.time); r={'ts':ts,'timestamp':datetime.fromtimestamp(ts,timezone.utc).isoformat(),'interface':iface,'src_ip':None,'dst_ip':None,'src_port':None,'dst_port':None,'protocol':'OTHER','length':len(pkt),'tcp_flags':None,'dns_query':None,'summary':pkt.summary()}
    if IP in pkt: r['src_ip'],r['dst_ip']=pkt[IP].src,pkt[IP].dst
    elif IPv6 in pkt: r['src_ip'],r['dst_ip']=pkt[IPv6].src,pkt[IPv6].dst
    if TCP in pkt: r['protocol']='TCP'; r['src_port'],r['dst_port']=int(pkt[TCP].sport),int(pkt[TCP].dport); r['tcp_flags']=str(pkt[TCP].flags)
    elif UDP in pkt: r['protocol']='UDP'; r['src_port'],r['dst_port']=int(pkt[UDP].sport),int(pkt[UDP].dport)
    elif ICMP in pkt: r['protocol']='ICMP'
    if DNS in pkt and DNSQR in pkt:
        try: r['dns_query']=pkt[DNSQR].qname.decode(errors='replace').rstrip('.')
        except Exception: pass
    return r

class Sensor:
    def __init__(self,iface,rotate_mb=128): self.iface=iface; self.rotate_bytes=rotate_mb*1024*1024; self.running=False; self.writer=None; self.sniffer=None; self.current_bytes=0; self.protocols=Counter(); self.lock=threading.Lock()
    def _new_writer(self):
        if self.writer:
            try:self.writer.close()
            except:pass
        path=CAP_DIR/f"{self.iface}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"; self.writer=PcapWriter(str(path),append=False,sync=True); self.current_bytes=0
    def start(self):
        if self.running:return
        self._new_writer(); self.sniffer=AsyncSniffer(iface=self.iface,prn=self.handle,store=False); self.sniffer.start(); self.running=True
    def stop(self):
        if not self.running:return
        try:self.sniffer.stop()
        except:pass
        try:self.writer.close()
        except:pass
        self.running=False
    def handle(self,pkt):
        try:
            if self.current_bytes>=self.rotate_bytes:self._new_writer()
            self.writer.write(pkt); self.current_bytes+=len(pkt); r=record(pkt,self.iface); DB.insert(r)
            with self.lock:self.protocols[r['protocol']]+=1
        except Exception: pass

class Controller(threading.Thread):
    def __init__(self,app): super().__init__(daemon=True); self.app=app; self.dev=None
    def run(self):
        if InputDevice is None:return
        devices=[]
        for p in list_devices():
            try:
                d=InputDevice(p); name=(d.name or '').lower()
                if any(x in name for x in ('innext','gamepad','controller','joystick')): devices.append(d)
            except: pass
        if not devices:return
        self.dev=devices[0]; self.app.call_from_thread(self.app.set_controller_name,self.dev.name)
        for e in self.dev.read_loop():
            if e.type==ecodes.EV_KEY and e.value==1:
                m={ecodes.BTN_SOUTH:'enter',ecodes.BTN_EAST:'escape',ecodes.BTN_NORTH:'slash',ecodes.BTN_START:'home',ecodes.BTN_SELECT:'s'}
                if e.code in m:self.app.call_from_thread(self.app.press_key,m[e.code])
            elif e.type==ecodes.EV_ABS:
                if e.code==ecodes.ABS_HAT0Y and e.value:self.app.call_from_thread(self.app.press_key,'down' if e.value>0 else 'up')
                elif e.code==ecodes.ABS_HAT0X and e.value:self.app.call_from_thread(self.app.press_key,'right' if e.value>0 else 'left')

class NetApp(App):
    TITLE='Manticore Network Intelligence'
    CSS='''Screen{background:#050505} #status{height:6;border:solid green;padding:1} DataTable{height:1fr} #search{margin:1}.panel{border:solid green;padding:1}'''
    BINDINGS=[Binding('q','quit','Quit'),Binding('s','toggle','Capture'),Binding('r','refresh_now','Refresh'),Binding('/','find','Search'),Binding('e','export','Export AI')]
    def __init__(self,iface,rotate_mb): super().__init__(); self.sensor=Sensor(iface,rotate_mb); self.controller='not detected'
    def compose(self)->ComposeResult:
        yield Header(); yield Static('Starting...',id='status')
        with TabbedContent():
            with TabPane('LIVE'): yield DataTable(id='packets')
            with TabPane('FLOWS'): yield DataTable(id='flows')
            with TabPane('DNS'): yield DataTable(id='dns')
            with TabPane('HOSTS'): yield DataTable(id='hosts')
            with TabPane('SEARCH'): yield Input(placeholder='FTS query: IP, protocol, DNS name',id='search'); yield DataTable(id='results')
            with TabPane('AI DATA'): yield Static('E = export flow-level JSONL\nRaw PCAP is retained separately. Payload bytes are not copied into the AI dataset.\n\nController: D-pad navigate | A select | B back | X search | Start home | Select capture',classes='panel')
        yield Footer()
    def on_mount(self):
        for ident,cols in {'packets':('ID','Time','Proto','Source','Destination','Bytes','DNS'),'flows':('Source','SPort','Destination','DPort','Proto','Packets','Bytes'),'dns':('Time','Source','Query'),'hosts':('Host','Packets','Bytes'),'results':('ID','Time','Proto','Source','Destination','Bytes','DNS')}.items(): self.query_one('#'+ident,DataTable).add_columns(*cols)
        try:self.sensor.start()
        except Exception as e:self.notify(f'Capture failed: {e}',severity='error')
        Controller(self).start(); self.set_interval(1.0,self.refresh_all)
    def set_controller_name(self,n): self.controller=n
    def press_key(self,k): self.simulate_key(k)
    def rows(self,ident,rows):
        t=self.query_one('#'+ident,DataTable); t.clear()
        for r in rows:t.add_row(*['' if x is None else str(x) for x in r])
    def refresh_all(self):
        n,b=DB.stats(); self.query_one('#status',Static).update(f"MANTICORE NETWORK INTELLIGENCE\nSensor: {'CAPTURING' if self.sensor.running else 'STOPPED'} | Interface: {self.sensor.iface} | Controller: {self.controller}\nPackets: {n:,} | Bytes: {b:,} | CPU: {psutil.cpu_percent():.1f}% | RAM: {psutil.virtual_memory().percent:.1f}%")
        rr=[]
        for i,t,p,si,sp,di,dp,l,d in DB.recent(): rr.append((i,t[11:19],p,f'{si}:{sp}' if sp else si,f'{di}:{dp}' if dp else di,l,d or ''))
        self.rows('packets',rr); self.rows('flows',DB.flows()); self.rows('dns',[(t[11:19],s,q) for t,s,q in DB.dns()]); self.rows('hosts',DB.hosts())
    def action_toggle(self): self.sensor.stop() if self.sensor.running else self.sensor.start()
    def action_refresh_now(self): self.refresh_all()
    def action_find(self): self.query_one('#search',Input).focus()
    def action_export(self):
        p=DB.export_jsonl(); self.notify(f'Exported {p}')
    def on_input_submitted(self,e:Input.Submitted):
        q=e.value.strip()
        if not q:return
        try:self.rows('results',[(i,t[11:19],p,s,d,l,dns or '') for i,t,p,s,d,l,dns in DB.search(q)])
        except Exception as x:self.notify(f'Search error: {x}',severity='error')
    def on_unmount(self): self.sensor.stop()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('-i','--interface',default='eth0'); ap.add_argument('--rotate-mb',type=int,default=128); a=ap.parse_args(); NetApp(a.interface,a.rotate_mb).run()
if __name__=='__main__': main()
