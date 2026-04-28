"""
NetSentinel — Network Packet Analyzer & IDS Engine
Backend: FastAPI + Scapy + WebSocket streaming
Author: NetSentinel v3.0
"""

import asyncio
import json
import time
import hashlib
import logging
import os
import sys
import signal
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, asdict, field
from typing import Optional
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ─── Optional Scapy import (graceful fallback to simulation) ─────────────────
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw,
        Ether, get_if_list, conf as scapy_conf
    )
    SCAPY_AVAILABLE = True
    scapy_conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not installed — running in simulation mode")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("netsentinel")


# ══════════════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PacketRecord:
    no:        int
    timestamp: float
    time_str:  str
    src_ip:    str
    src_port:  Optional[int]
    dst_ip:    str
    dst_port:  Optional[int]
    protocol:  str
    length:    int
    ttl:       Optional[int]
    flags:     Optional[str]
    info:      str
    payload_preview: str
    hex_dump:  list[dict]
    alert:     bool = False
    alert_type: str = ""
    checksum:  str = ""

    def to_dict(self):
        d = asdict(self)
        d["timestamp"] = round(d["timestamp"], 6)
        return d


@dataclass
class ThreatAlert:
    alert_id:    str
    alert_type:  str
    severity:    str          # LOW | MEDIUM | HIGH | CRITICAL
    src_ip:      str
    dst_ip:      str
    description: str
    timestamp:   float
    packet_no:   int

    def to_dict(self):
        return asdict(self)


@dataclass
class SessionStats:
    total_packets:  int = 0
    total_bytes:    int = 0
    tcp_count:      int = 0
    udp_count:      int = 0
    icmp_count:     int = 0
    dns_count:      int = 0
    arp_count:      int = 0
    http_count:     int = 0
    https_count:    int = 0
    other_count:    int = 0
    alerts_total:   int = 0
    alerts_critical: int = 0
    rx_bytes_sec:   float = 0.0
    tx_bytes_sec:   float = 0.0
    uptime_sec:     int = 0
    unique_ips:     int = 0
    top_talkers:    list = field(default_factory=list)
    proto_dist:     dict = field(default_factory=dict)


# ══════════════════════════════════════════════════════════════════════════════
#  IDS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class IDSEngine:
    """Intrusion Detection System — stateful rule-based engine."""

    RULES = [
        {
            "name":    "SYN Flood",
            "severity":"CRITICAL",
            "desc":    "SYN flood detected: >100 SYN packets from same IP in 10s",
        },
        {
            "name":    "Port Scan",
            "severity":"HIGH",
            "desc":    "Port scan detected: >20 unique destination ports in 5s",
        },
        {
            "name":    "DNS Amplification",
            "severity":"HIGH",
            "desc":    "DNS amplification attack: large DNS response to small query",
        },
        {
            "name":    "ICMP Flood",
            "severity":"MEDIUM",
            "desc":    "ICMP flood: >50 ICMP packets from same IP in 10s",
        },
        {
            "name":    "Brute Force SSH",
            "severity":"HIGH",
            "desc":    "Possible SSH brute force: repeated connections to port 22",
        },
        {
            "name":    "ARP Spoofing",
            "severity":"CRITICAL",
            "desc":    "ARP cache poisoning attempt detected",
        },
        {
            "name":    "Large Payload",
            "severity":"LOW",
            "desc":    "Anomalous packet size >1400 bytes (possible fragmentation attack)",
        },
    ]

    def __init__(self):
        self.syn_tracker:  defaultdict[str, deque] = defaultdict(deque)
        self.port_tracker: defaultdict[str, dict]  = defaultdict(lambda: {"ports": set(), "ts": time.time()})
        self.icmp_tracker: defaultdict[str, deque] = defaultdict(deque)
        self.ssh_tracker:  defaultdict[str, deque] = defaultdict(deque)
        self.arp_table:    dict[str, str]           = {}  # ip → mac
        self.alert_count:  int = 0

    def _window(self, dq: deque, window_sec: float) -> int:
        now = time.time()
        while dq and now - dq[0] > window_sec:
            dq.popleft()
        return len(dq)

    def inspect(self, pkt_rec: PacketRecord) -> Optional[ThreatAlert]:
        src = pkt_rec.src_ip
        now = time.time()

        # SYN Flood
        if pkt_rec.protocol == "TCP" and pkt_rec.flags and "S" in pkt_rec.flags and "A" not in pkt_rec.flags:
            self.syn_tracker[src].append(now)
            if self._window(self.syn_tracker[src], 10) > 100:
                return self._mk_alert("SYN Flood", "CRITICAL", pkt_rec)

        # Port Scan
        if pkt_rec.protocol in ("TCP", "UDP") and pkt_rec.dst_port:
            pt = self.port_tracker[src]
            if now - pt["ts"] > 5:
                pt["ports"] = set()
                pt["ts"] = now
            pt["ports"].add(pkt_rec.dst_port)
            if len(pt["ports"]) > 20:
                pt["ports"] = set()
                return self._mk_alert("Port Scan", "HIGH", pkt_rec)

        # ICMP Flood
        if pkt_rec.protocol == "ICMP":
            self.icmp_tracker[src].append(now)
            if self._window(self.icmp_tracker[src], 10) > 50:
                return self._mk_alert("ICMP Flood", "MEDIUM", pkt_rec)

        # SSH Brute Force
        if pkt_rec.protocol == "TCP" and pkt_rec.dst_port == 22:
            self.ssh_tracker[src].append(now)
            if self._window(self.ssh_tracker[src], 30) > 15:
                return self._mk_alert("Brute Force SSH", "HIGH", pkt_rec)

        # Large Payload
        if pkt_rec.length > 1400:
            return self._mk_alert("Large Payload", "LOW", pkt_rec)

        return None

    def _mk_alert(self, rule_name: str, severity: str, p: PacketRecord) -> ThreatAlert:
        rule = next((r for r in self.RULES if r["name"] == rule_name), self.RULES[0])
        self.alert_count += 1
        aid = hashlib.md5(f"{rule_name}{p.src_ip}{p.timestamp}".encode()).hexdigest()[:8].upper()
        return ThreatAlert(
            alert_id=f"ALERT-{aid}",
            alert_type=rule_name,
            severity=severity,
            src_ip=p.src_ip,
            dst_ip=p.dst_ip,
            description=rule["desc"],
            timestamp=p.timestamp,
            packet_no=p.no,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  PACKET PROCESSOR
# ══════════════════════════════════════════════════════════════════════════════

class PacketProcessor:
    def __init__(self):
        self.pkt_no    = 0
        self.ids       = IDSEngine()
        self.stats     = SessionStats()
        self.start_ts  = time.time()
        self.ip_counter: defaultdict[str, int] = defaultdict(int)
        self._rx_window: deque = deque()
        self._tx_window: deque = deque()

    # ── Scapy packet → PacketRecord ──────────────────────────────────────────
    def from_scapy(self, pkt) -> PacketRecord:
        self.pkt_no += 1
        ts  = float(pkt.time) if hasattr(pkt, "time") else time.time()
        ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
        proto = "OTHER"; src_ip = "0.0.0.0"; dst_ip = "0.0.0.0"
        src_port = dst_port = ttl = flags_str = None
        info = ""

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ttl    = pkt[IP].ttl
            if TCP in pkt:
                proto     = "TCP"
                src_port  = pkt[TCP].sport
                dst_port  = pkt[TCP].dport
                flags_str = str(pkt[TCP].flags)
                if dst_port == 80:  proto = "HTTP"
                if dst_port == 443: proto = "HTTPS"
                if dst_port == 22:  proto = "SSH"
                info = f"[{flags_str}] {src_ip}:{src_port} → {dst_ip}:{dst_port}"
            elif UDP in pkt:
                proto    = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                if DNS in pkt:
                    proto = "DNS"
                    qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else "?"
                    info  = f"{'Query' if pkt[DNS].qr==0 else 'Response'}: {qname}"
                else:
                    info = f"UDP {src_port} → {dst_port}"
            elif ICMP in pkt:
                proto = "ICMP"
                info  = f"ICMP type={pkt[ICMP].type} code={pkt[ICMP].code}"
        elif ARP in pkt:
            proto  = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            info   = f"{'Who has' if pkt[ARP].op==1 else 'Reply:'} {dst_ip} → {src_ip}"

        raw_bytes = bytes(pkt)
        return PacketRecord(
            no=self.pkt_no, timestamp=ts, time_str=ts_str,
            src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
            protocol=proto, length=len(raw_bytes), ttl=ttl, flags=flags_str,
            info=info or proto,
            payload_preview=raw_bytes[:32].hex(),
            hex_dump=self._hex_dump(raw_bytes),
            checksum=hashlib.md5(raw_bytes).hexdigest()[:16],
        )

    # ── Simulation mode ───────────────────────────────────────────────────────
    def simulate(self) -> PacketRecord:
        import random, struct
        self.pkt_no += 1
        ts     = time.time()
        ts_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

        POOL_SRC = ["192.168.1.10","10.0.0.23","172.16.5.88","192.168.0.55",
                    "8.8.8.8","1.1.1.1","10.10.1.200","172.31.0.4"]
        POOL_DST = ["192.168.1.1","10.0.0.1","172.16.0.1","8.8.8.8",
                    "192.168.1.105","1.1.1.1","224.0.0.1","255.255.255.255"]
        PROTOS   = ["TCP"]*5+["UDP"]*3+["HTTP","HTTPS","DNS","ICMP","ARP"]

        proto    = random.choice(PROTOS)
        src_ip   = random.choice(POOL_SRC)
        dst_ip   = random.choice(POOL_DST)
        src_port = random.randint(1024, 65535)
        dst_port_map = {"HTTP":80,"HTTPS":443,"DNS":53,"SSH":22,"TCP":random.randint(1,65535),"UDP":random.randint(1,65535)}
        dst_port = dst_port_map.get(proto, random.randint(1, 65535))
        length   = random.randint(40, 1500)
        ttl      = random.choice([64,128,255,32])
        flags_str= random.choice(["S","SA","A","PA","FA","R"]) if proto in ("TCP","HTTP","HTTPS") else None

        INFOS = {
            "TCP":   [f"[{flags_str}] Seq={random.randint(0,4294967295)} Win=65535"],
            "HTTP":  [f"GET /api/v{random.randint(1,3)}/data HTTP/1.1",f"POST /login HTTP/1.1","HTTP/1.1 200 OK"],
            "HTTPS": ["TLSv1.3 Application Data","Client Hello","Server Hello"],
            "DNS":   [f"Query: A example{random.randint(1,99)}.com",f"Response: {random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"],
            "UDP":   [f"Src:{src_port} Dst:{dst_port}","DHCP Discover","mDNS Query"],
            "ICMP":  ["Echo request","Echo reply","Dest unreachable","TTL exceeded"],
            "ARP":   [f"Who has {dst_ip}? Tell {src_ip}",f"{dst_ip} is at {'%02x:%02x:%02x:%02x:%02x:%02x'%tuple(random.randint(0,255) for _ in range(6))}"],
        }
        info = random.choice(INFOS.get(proto, ["Packet"]))
        raw  = bytes([random.randint(0,255) for _ in range(min(length,128))])

        return PacketRecord(
            no=self.pkt_no, timestamp=ts, time_str=ts_str,
            src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
            protocol=proto, length=length, ttl=ttl, flags=flags_str,
            info=info, payload_preview=raw[:32].hex(),
            hex_dump=self._hex_dump(raw),
            checksum=hashlib.md5(raw).hexdigest()[:16],
        )

    def update_stats(self, p: PacketRecord, alert: Optional[ThreatAlert]):
        s = self.stats
        s.total_packets += 1
        s.total_bytes   += p.length
        s.uptime_sec     = int(time.time() - self.start_ts)
        self.ip_counter[p.src_ip] += 1

        pm = {"TCP":"tcp","UDP":"udp","HTTP":"http","HTTPS":"https",
              "DNS":"dns","ICMP":"icmp","ARP":"arp"}
        attr = pm.get(p.protocol, "other")
        setattr(s, f"{attr}_count", getattr(s, f"{attr}_count", 0)+1)

        now = time.time()
        self._rx_window.append((now, p.length))
        while self._rx_window and now - self._rx_window[0][0] > 1:
            self._rx_window.popleft()
        s.rx_bytes_sec = round(sum(x[1] for x in self._rx_window) / 1024, 2)

        if alert:
            s.alerts_total += 1
            if alert.severity == "CRITICAL":
                s.alerts_critical += 1

        s.unique_ips  = len(self.ip_counter)
        s.top_talkers = sorted(self.ip_counter.items(), key=lambda x: -x[1])[:5]
        s.proto_dist  = {
            "TCP":   s.tcp_count,   "UDP":  s.udp_count,
            "HTTP":  s.http_count,  "HTTPS":s.https_count,
            "DNS":   s.dns_count,   "ICMP": s.icmp_count,
            "ARP":   s.arp_count,   "Other":s.other_count,
        }

    @staticmethod
    def _hex_dump(raw: bytes, rows: int = 8) -> list[dict]:
        result = []
        for i in range(0, min(len(raw), rows*16), 16):
            chunk = raw[i:i+16]
            result.append({
                "offset": f"{i:04x}",
                "hex":    " ".join(f"{b:02x}" for b in chunk),
                "ascii":  "".join(chr(b) if 32 <= b < 127 else "." for b in chunk),
            })
        return result


# ══════════════════════════════════════════════════════════════════════════════
#  CONNECTION MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class ConnectionManager:
    def __init__(self):
        self.clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.clients.append(ws)
        log.info(f"Client connected — total: {len(self.clients)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.clients:
            self.clients.remove(ws)
        log.info(f"Client disconnected — total: {len(self.clients)}")

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self.clients:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


# ══════════════════════════════════════════════════════════════════════════════
#  APP BOOTSTRAP
# ══════════════════════════════════════════════════════════════════════════════

manager   = ConnectionManager()
processor = PacketProcessor()
capturing = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("NetSentinel backend starting…")
    yield
    log.info("NetSentinel backend stopped.")

app = FastAPI(title="NetSentinel API", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Simulation loop ───────────────────────────────────────────────────────────
async def simulation_loop():
    global capturing
    import random
    while True:
        if capturing and manager.clients:
            count = random.choices([1, 2, 3], weights=[6, 3, 1])[0]
            for _ in range(count):
                p     = processor.simulate()
                alert = processor.ids.inspect(p)
                if alert:
                    p.alert      = True
                    p.alert_type = alert.alert_type
                processor.update_stats(p, alert)

                msg: dict = {"type": "packet", "data": p.to_dict()}
                if alert:
                    msg["alert"] = alert.to_dict()
                await manager.broadcast(msg)

            # Stats every 10 packets
            if processor.stats.total_packets % 10 == 0:
                await manager.broadcast({
                    "type":  "stats",
                    "data":  asdict(processor.stats),
                })

        await asyncio.sleep(0.25)


# ── Scapy capture loop ────────────────────────────────────────────────────────
def scapy_capture_loop(iface: str = "eth0"):
    global capturing

    def handle(pkt):
        if not capturing:
            return
        try:
            p     = processor.from_scapy(pkt)
            alert = processor.ids.inspect(p)
            if alert:
                p.alert      = True
                p.alert_type = alert.alert_type
            processor.update_stats(p, alert)
            msg: dict = {"type": "packet", "data": p.to_dict()}
            if alert:
                msg["alert"] = alert.to_dict()
            asyncio.run_coroutine_threadsafe(manager.broadcast(msg), asyncio.get_event_loop())
        except Exception as e:
            log.error(f"Packet handling error: {e}")

    sniff(iface=iface, prn=handle, store=False, stop_filter=lambda _: not capturing)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    asyncio.create_task(simulation_loop())

@app.get("/")
async def root():
    return {"service": "NetSentinel", "version": "3.0.0", "scapy": SCAPY_AVAILABLE}

@app.get("/interfaces")
async def list_interfaces():
    if SCAPY_AVAILABLE:
        return {"interfaces": get_if_list()}
    return {"interfaces": ["eth0", "eth1", "wlan0", "lo", "any"]}

@app.get("/stats")
async def get_stats():
    return asdict(processor.stats)

@app.post("/capture/start")
async def start_capture(iface: str = "eth0"):
    global capturing
    if capturing:
        return {"status": "already_capturing"}
    capturing = True
    log.info(f"Capture started on {iface}")
    if SCAPY_AVAILABLE:
        import threading
        t = threading.Thread(target=scapy_capture_loop, args=(iface,), daemon=True)
        t.start()
    return {"status": "capturing", "iface": iface, "scapy": SCAPY_AVAILABLE}

@app.post("/capture/stop")
async def stop_capture():
    global capturing
    capturing = False
    return {"status": "stopped"}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            msg  = json.loads(data)
            if msg.get("cmd") == "start":
                global capturing
                capturing = True
            elif msg.get("cmd") == "stop":
                capturing = False
    except WebSocketDisconnect:
        manager.disconnect(ws)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8765, reload=False, log_level="info")
