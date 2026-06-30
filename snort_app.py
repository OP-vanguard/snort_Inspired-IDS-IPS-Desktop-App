#!/usr/bin/env python3
"""
Snort IDS/IPS Dashboard
A beginner-friendly network intrusion detection & prevention system GUI.
Requires: pip install pyqt5 scapy pyqtgraph
"""

import sys
import json
import time
import random
import struct
from datetime import datetime
from collections import defaultdict
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem, QFileDialog,
    QStackedWidget, QFrame, QTextEdit, QLineEdit, QComboBox,
    QHeaderView, QSplitter, QCheckBox, QSpinBox, QMessageBox,
    QProgressBar, QScrollArea, QGroupBox, QFormLayout, QTabWidget,
    QListWidget, QListWidgetItem, QAbstractItemView, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QFont, QPalette, QBrush

try:
    import pyqtgraph as pg
    HAS_PYQTGRAPH = True
except ImportError:
    HAS_PYQTGRAPH = False

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw, DNS, ARP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ─── COLOUR PALETTE ───────────────────────────────────
COLORS = {
    "bg_primary":    "#0d1117",
    "bg_secondary":  "#161b22",
    "bg_tertiary":   "#1c2128",
    "bg_card":       "#21262d",
    "accent_blue":   "#58a6ff",
    "accent_green":  "#3fb950",
    "accent_red":    "#f85149",
    "accent_orange": "#d29922",
    "accent_purple": "#bc8cff",
    "accent_cyan":   "#39d353",
    "text_primary":  "#e6edf3",
    "text_secondary":"#8b949e",
    "text_muted":    "#484f58",
    "border":        "#30363d",
    "sidebar_active":"#1d4ed8",
    "sidebar_hover": "#1f2937",
    "high_sev":      "#f85149",
    "med_sev":       "#d29922",
    "low_sev":       "#3fb950",
    "blocked_bg":    "#3d1a1a",
    "allowed_bg":    "#0d2616",
}

GLOBAL_STYLE = f"""
QMainWindow, QWidget {{
    background-color: {COLORS['bg_primary']};
    color: {COLORS['text_primary']};
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
}}
QScrollBar:vertical {{
    background: {COLORS['bg_secondary']}; width: 8px; border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {COLORS['border']}; border-radius: 4px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {COLORS['text_secondary']}; }}
QScrollBar:horizontal {{
    background: {COLORS['bg_secondary']}; height: 8px; border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: {COLORS['border']}; border-radius: 4px;
}}
QTableWidget {{
    background-color: {COLORS['bg_secondary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    gridline-color: {COLORS['bg_tertiary']};
    selection-background-color: {COLORS['sidebar_active']};
}}
QTableWidget::item {{ padding: 6px 10px; border-bottom: 1px solid {COLORS['bg_tertiary']}; }}
QHeaderView::section {{
    background-color: {COLORS['bg_card']};
    color: {COLORS['text_secondary']};
    padding: 8px 10px;
    border: none;
    border-bottom: 1px solid {COLORS['border']};
    font-weight: bold;
    font-size: 11px;
}}
QLineEdit, QTextEdit, QComboBox, QSpinBox {{
    background-color: {COLORS['bg_tertiary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    color: {COLORS['text_primary']};
    padding: 6px 10px;
}}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{
    border: 1px solid {COLORS['accent_blue']};
}}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    selection-background-color: {COLORS['sidebar_active']};
}}
QPushButton {{
    background-color: {COLORS['bg_card']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
    color: {COLORS['text_primary']};
    padding: 8px 16px;
    font-weight: bold;
}}
QPushButton:hover {{
    background-color: {COLORS['sidebar_hover']};
    border-color: {COLORS['accent_blue']};
    color: {COLORS['accent_blue']};
}}
QPushButton:pressed {{ background-color: {COLORS['sidebar_active']}; }}
QGroupBox {{
    border: 1px solid {COLORS['border']};
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 10px;
    color: {COLORS['text_secondary']};
    font-size: 11px;
    font-weight: bold;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: {COLORS['accent_blue']};
}}
QCheckBox {{ color: {COLORS['text_primary']}; spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {COLORS['border']};
    border-radius: 3px;
    background: {COLORS['bg_tertiary']};
}}
QCheckBox::indicator:checked {{
    background: {COLORS['accent_blue']}; border-color: {COLORS['accent_blue']};
}}
QProgressBar {{
    background: {COLORS['bg_tertiary']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    text-align: center;
    color: {COLORS['text_primary']};
    height: 18px;
}}
QProgressBar::chunk {{ background: {COLORS['accent_blue']}; border-radius: 4px; }}
QSplitter::handle {{ background: {COLORS['border']}; width: 2px; }}
QStatusBar {{
    background: {COLORS['bg_secondary']};
    border-top: 1px solid {COLORS['border']};
    color: {COLORS['text_secondary']};
    font-size: 11px;
}}
QListWidget {{
    background: {COLORS['bg_secondary']};
    border: 1px solid {COLORS['border']};
    border-radius: 6px;
}}
QListWidget::item {{
    padding: 6px 10px; border-radius: 4px; margin: 1px 4px;
}}
QListWidget::item:selected {{ background: {COLORS['sidebar_active']}; }}
QListWidget::item:hover {{ background: {COLORS['sidebar_hover']}; }}
"""

# ─── DETECTION RULES ──────────────────────────────────
BUILTIN_RULES = [
    {"id":"SCAN-001","name":"SYN Scan (Stealth Scan)","category":"Port Scan","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"TCP SYN-only packet to ports 1-1024 with no payload — classic nmap stealth scan.","mitre":"T1046",
     "conditions":{"proto":"TCP","scan_type":"syn"}},
    {"id":"SCAN-002","name":"NULL Scan","category":"Port Scan","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"TCP packet with zero flags — evades stateless firewalls.","mitre":"T1046",
     "conditions":{"proto":"TCP","scan_type":"null"}},
    {"id":"SCAN-003","name":"FIN Scan","category":"Port Scan","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"TCP FIN-only flag — bypasses non-stateful packet filters.","mitre":"T1046",
     "conditions":{"proto":"TCP","scan_type":"fin"}},
    {"id":"SCAN-004","name":"XMAS Scan","category":"Port Scan","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"FIN+PSH+URG flags set simultaneously — the 'Christmas tree' scan.","mitre":"T1046",
     "conditions":{"proto":"TCP","scan_type":"xmas"}},
    {"id":"SCAN-005","name":"ICMP Ping Sweep","category":"Port Scan","severity":"MEDIUM","confidence":"HIGH","enabled":True,
     "description":"ICMP echo-request used for host discovery.","mitre":"T1018",
     "conditions":{"proto":"ICMP","icmp_type":8}},
    {"id":"BRUTE-001","name":"SSH Brute Force","category":"Brute Force","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"5+ SYN packets to port 22 from same source within 10 seconds.","mitre":"T1110",
     "conditions":{"proto":"TCP","dport":22,"threshold":{"count":5,"window":10}}},
    {"id":"BRUTE-002","name":"FTP Brute Force","category":"Brute Force","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"Rapid repeated connection attempts to FTP port 21.","mitre":"T1110",
     "conditions":{"proto":"TCP","dport":21,"threshold":{"count":5,"window":10}}},
    {"id":"BRUTE-003","name":"RDP Brute Force","category":"Brute Force","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"Repeated SYN packets to RDP port 3389.","mitre":"T1110",
     "conditions":{"proto":"TCP","dport":3389,"threshold":{"count":4,"window":10}}},
    {"id":"WEB-001","name":"SQL Injection Attempt","category":"Web Attack","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"HTTP payload contains known SQL injection patterns.","mitre":"T1190",
     "conditions":{"proto":"TCP","dport_range":[80,8080],"payload_keywords":["union select","' or '1'='1","'; drop table","1=1--","sleep(","benchmark(","xp_cmdshell","' or 1=1"]}},
    {"id":"WEB-002","name":"XSS Attempt","category":"Web Attack","severity":"MEDIUM","confidence":"HIGH","enabled":True,
     "description":"HTTP payload contains cross-site scripting patterns.","mitre":"T1059.007",
     "conditions":{"proto":"TCP","dport_range":[80,8080],"payload_keywords":["<script>","javascript:","onerror=","onload=","alert(","document.cookie","<img src=x"]}},
    {"id":"WEB-003","name":"Directory Traversal","category":"Web Attack","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"Path traversal sequences attempting to read system files.","mitre":"T1083",
     "conditions":{"proto":"TCP","dport_range":[80,8080],"payload_keywords":["../../../","..\\\\..\\\\","/etc/passwd","/etc/shadow","boot.ini","win.ini"]}},
    {"id":"WEB-004","name":"Command Injection","category":"Web Attack","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"OS command injection patterns in HTTP payload.","mitre":"T1059",
     "conditions":{"proto":"TCP","dport_range":[80,8080],"payload_keywords":["; ls","; cat ","| whoami","& net user","; id;","$(id)","`id`","; wget "]}},
    {"id":"MALW-001","name":"Suspicious DNS Query (DGA)","category":"Malware","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"DNS query for a high-entropy domain — characteristic of DGA malware C2.","mitre":"T1568.002",
     "conditions":{"proto":"UDP","dport":53,"dns_high_entropy":True,"min_entropy":3.8}},
    {"id":"MALW-002","name":"Suspicious Outbound Port","category":"Malware","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"Outbound SYN to port commonly used by RATs and reverse shells.","mitre":"T1571",
     "conditions":{"proto":"TCP","dport_list":[4444,1234,31337,8888,9999,6666,5555,1337,12345,54321]}},
    {"id":"MALW-003","name":"ICMP Tunnel (Large Payload)","category":"Malware","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"ICMP packet with >100 byte payload — sign of data exfiltration or tunneling.","mitre":"T1095",
     "conditions":{"proto":"ICMP","min_payload_size":100}},
    {"id":"ANOM-001","name":"Malformed TCP (SYN+FIN)","category":"Anomaly","severity":"MEDIUM","confidence":"HIGH","enabled":True,
     "description":"SYN and FIN simultaneously set — invalid TCP state, often a probe or evasion.","mitre":"T1499",
     "conditions":{"proto":"TCP","scan_type":"synfin"}},
    {"id":"ANOM-002","name":"ARP Spoofing","category":"Anomaly","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"Unsolicited ARP reply — classic man-in-the-middle indicator.","mitre":"T1557.002",
     "conditions":{"proto":"ARP","arp_op":2}},
    {"id":"EXPL-001","name":"EternalBlue (SMB)","category":"Exploit","severity":"HIGH","confidence":"HIGH","enabled":True,
     "description":"Large payload on SMB port 445 — possible MS17-010 exploit (WannaCry).","mitre":"T1210",
     "conditions":{"proto":"TCP","dport":445,"min_payload_size":200}},
    {"id":"EXPL-002","name":"Telnet Access Attempt","category":"Exploit","severity":"MEDIUM","confidence":"HIGH","enabled":True,
     "description":"SYN to Telnet port 23 — unencrypted, frequently targeted.","mitre":"T1021",
     "conditions":{"proto":"TCP","dport":23,"syn_only":True}},
]

WHITELIST_DPORTS = {53, 67, 68, 123, 443, 5353}


def shannon_entropy(s):
    if not s:
        return 0.0
    import math
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((f/n)*math.log2(f/n) for f in freq.values())


# ─── DETECTION ENGINE ─────────────────────────────────
class DetectionEngine:
    def __init__(self, rules):
        self.rules = [r for r in rules if r["enabled"]]
        self._counters = defaultdict(lambda: defaultdict(list))

    def _flags(self, pkt):
        if not (HAS_SCAPY and pkt.haslayer(TCP)):
            return {}
        f = pkt[TCP].flags
        return {
            "SYN": bool(f & 0x02), "ACK": bool(f & 0x10), "FIN": bool(f & 0x01),
            "RST": bool(f & 0x04), "PSH": bool(f & 0x08), "URG": bool(f & 0x20),
        }

    def _payload(self, pkt):
        if HAS_SCAPY and pkt.haslayer(Raw):
            return bytes(pkt[Raw].load)
        return b""

    def _threshold_ok(self, src, rule_id, window, max_count, ts):
        hits = self._counters[src][rule_id]
        hits.append(ts)
        cutoff = ts - window
        self._counters[src][rule_id] = [t for t in hits if t >= cutoff]
        return len(self._counters[src][rule_id]) >= max_count

    def analyze(self, pkt, idx, ts):
        if not HAS_SCAPY:
            return self._demo_analyze(idx, ts)
        alerts = []
        src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
        payload = self._payload(pkt)
        payload_lower = payload.decode("utf-8", errors="ignore").lower()
        flags = self._flags(pkt)
        dport = None
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
        if dport in WHITELIST_DPORTS:
            return []

        for rule in self.rules:
            cond = rule["conditions"]
            proto = cond.get("proto", "ANY")
            matched = False
            rid = rule["id"]

            if proto == "TCP" and not pkt.haslayer(TCP): continue
            if proto == "UDP" and not pkt.haslayer(UDP): continue
            if proto == "ICMP" and not pkt.haslayer(ICMP): continue
            if proto == "ARP" and not pkt.haslayer(ARP): continue

            if rid == "SCAN-001":
                if pkt.haslayer(TCP) and flags.get("SYN") and not flags.get("ACK") and not flags.get("FIN"):
                    if 1 <= pkt[TCP].dport <= 1024 and not payload:
                        matched = True
            elif rid == "SCAN-002":
                if pkt.haslayer(TCP) and int(pkt[TCP].flags) == 0:
                    matched = True
            elif rid == "SCAN-003":
                if pkt.haslayer(TCP) and flags.get("FIN") and not flags.get("SYN") and not flags.get("ACK") and not flags.get("RST"):
                    matched = True
            elif rid == "SCAN-004":
                if pkt.haslayer(TCP) and flags.get("FIN") and flags.get("PSH") and flags.get("URG"):
                    matched = True
            elif rid == "SCAN-005":
                if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                    matched = True
            elif rid in ("BRUTE-001","BRUTE-002","BRUTE-003"):
                tp = cond["dport"]
                th = cond["threshold"]
                if pkt.haslayer(TCP) and pkt[TCP].dport == tp and flags.get("SYN") and not flags.get("ACK"):
                    if self._threshold_ok(src, rid, th["window"], th["count"], ts):
                        matched = True
            elif rid in ("WEB-001","WEB-002","WEB-003","WEB-004"):
                dr = cond.get("dport_range",[80,8080])
                kws = cond.get("payload_keywords",[])
                if pkt.haslayer(TCP) and dr[0] <= pkt[TCP].dport <= dr[1] and payload_lower:
                    if any(k in payload_lower for k in kws):
                        matched = True
            elif rid == "MALW-001":
                if pkt.haslayer(UDP) and pkt[UDP].dport == 53 and pkt.haslayer(DNS):
                    try:
                        qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                        domain = qname.split(".")[0]
                        if len(domain) > 8 and shannon_entropy(domain) >= cond["min_entropy"]:
                            matched = True
                    except Exception:
                        pass
            elif rid == "MALW-002":
                if pkt.haslayer(TCP) and pkt[TCP].dport in cond["dport_list"]:
                    if flags.get("SYN") and not flags.get("ACK"):
                        matched = True
            elif rid == "MALW-003":
                if pkt.haslayer(ICMP) and len(payload) >= cond["min_payload_size"]:
                    matched = True
            elif rid == "ANOM-001":
                if pkt.haslayer(TCP) and flags.get("SYN") and flags.get("FIN"):
                    matched = True
            elif rid == "ANOM-002":
                if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                    matched = True
            elif rid == "EXPL-001":
                if pkt.haslayer(TCP) and pkt[TCP].dport == 445 and len(payload) >= 200:
                    matched = True
            elif rid == "EXPL-002":
                if pkt.haslayer(TCP) and pkt[TCP].dport == 23 and flags.get("SYN") and not flags.get("ACK"):
                    matched = True

            if matched:
                alerts.append({
                    "pkt_index":idx,"timestamp":datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
                    "src_ip":src,"dst_ip":dst,"rule_id":rule["id"],"rule_name":rule["name"],
                    "category":rule["category"],"severity":rule["severity"],
                    "mitre":rule.get("mitre",""),"description":rule["description"],
                    "proto":proto,"dport":dport or 0,
                })
        return alerts

    def _demo_analyze(self, idx, ts):
        alerts = []
        tstr = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
        scenarios = [
            (0.06, "SCAN-001","SYN Scan (Stealth Scan)","Port Scan","HIGH","T1046","192.168.1.105","10.0.0.1","TCP",random.randint(1,1024)),
            (0.04, "WEB-001","SQL Injection Attempt","Web Attack","HIGH","T1190","203.0.113.42","192.168.1.10","TCP",80),
            (0.03, "BRUTE-001","SSH Brute Force","Brute Force","HIGH","T1110","198.51.100.7","192.168.1.20","TCP",22),
            (0.02, "MALW-001","Suspicious DNS Query (DGA)","Malware","HIGH","T1568.002","10.0.0.55","8.8.8.8","UDP",53),
            (0.015,"SCAN-004","XMAS Scan","Port Scan","HIGH","T1046","192.168.1.77","172.16.0.1","TCP",random.randint(1,1024)),
            (0.01, "EXPL-001","EternalBlue (SMB)","Exploit","HIGH","T1210","10.10.10.99","192.168.1.5","TCP",445),
        ]
        for prob, rid, rname, cat, sev, mitre, src, dst, proto, dp in scenarios:
            if random.random() < prob:
                alerts.append({
                    "pkt_index":idx,"timestamp":tstr,"src_ip":src,"dst_ip":dst,
                    "rule_id":rid,"rule_name":rname,"category":cat,"severity":sev,
                    "mitre":mitre,"description":next(r["description"] for r in BUILTIN_RULES if r["id"]==rid),
                    "proto":proto,"dport":dp,
                })
        return alerts


# ─── PCAP WORKER ──────────────────────────────────────
class PcapWorker(QThread):
    packet_processed = pyqtSignal(dict)
    alert_generated  = pyqtSignal(dict)
    finished_signal  = pyqtSignal(int, int)

    def __init__(self, filepath, rules, mode="IDS"):
        super().__init__()
        self.filepath = filepath
        self.engine = DetectionEngine(rules)
        self.mode = mode
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        total_pkts = 0
        total_alerts = 0
        try:
            if HAS_SCAPY and self.filepath:
                packets = rdpcap(self.filepath)
                for i, pkt in enumerate(packets):
                    if self._stop: break
                    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
                    proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else "OTHER"
                    src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                    dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                    dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport if pkt.haslayer(UDP) else 0
                    size = len(pkt)
                    alerts = self.engine.analyze(pkt, i, ts)
                    is_blocked = self.mode == "IPS" and len(alerts) > 0
                    self.packet_processed.emit({"index":i,"timestamp":datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
                        "src":src,"dst":dst,"proto":proto,"dport":dport,"size":size,
                        "alerts":alerts,"blocked":is_blocked,"raw":bytes(pkt).hex()[:120]})
                    for alert in alerts:
                        alert["blocked"] = is_blocked
                        self.alert_generated.emit(alert)
                        total_alerts += 1
                    total_pkts += 1
                    self.msleep(2)
            else:
                src_pool = [f"192.168.1.{i}" for i in range(100,115)]
                dst_pool = [f"10.0.0.{i}" for i in range(1,20)]
                protos = ["TCP"]*6+["UDP"]*2+["ICMP"]+["OTHER"]
                for i in range(500):
                    if self._stop: break
                    ts = time.time()
                    proto = random.choice(protos)
                    src = random.choice(src_pool)
                    dst = random.choice(dst_pool)
                    dport = random.choice([80,443,22,53,445,3389,21,23,8080,4444,random.randint(1024,65535)])
                    size = random.randint(40,1500)
                    alerts = self.engine._demo_analyze(i, ts)
                    is_blocked = self.mode == "IPS" and len(alerts) > 0
                    self.packet_processed.emit({"index":i,"timestamp":datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
                        "src":src,"dst":dst,"proto":proto,"dport":dport,"size":size,
                        "alerts":alerts,"blocked":is_blocked,
                        "raw":"4500002800010000401100000a000001c0a80164"+"00"*8})
                    for alert in alerts:
                        alert["blocked"] = is_blocked
                        self.alert_generated.emit(alert)
                        total_alerts += 1
                    total_pkts += 1
                    self.msleep(20)
        except Exception as e:
            print(f"[Worker error] {e}")
        self.finished_signal.emit(total_pkts, total_alerts)


# ─── HELPERS ──────────────────────────────────────────
def make_badge(text, color):
    lbl = QLabel(text)
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setFixedHeight(22)
    lbl.setStyleSheet(f"QLabel{{background:{color}22;color:{color};border:1px solid {color}55;border-radius:4px;padding:0 8px;font-size:11px;font-weight:bold;}}")
    return lbl

def stat_card(title, init_val, accent):
    card = QFrame()
    card.setStyleSheet(f"QFrame{{background:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:10px;}}")
    lay = QVBoxLayout(card)
    lay.setContentsMargins(16,14,16,14)
    lay.setSpacing(4)
    t = QLabel(title.upper())
    t.setStyleSheet(f"color:{COLORS['text_muted']};font-size:10px;letter-spacing:1.5px;font-weight:bold;")
    v = QLabel(init_val)
    v.setStyleSheet(f"color:{accent};font-size:28px;font-weight:bold;")
    lay.addWidget(t); lay.addWidget(v)
    return card, v

class SidebarButton(QPushButton):
    def __init__(self, label, icon=""):
        super().__init__(f"  {icon}  {label}" if icon else f"    {label}")
        self.setCheckable(True)
        self.setFixedHeight(44)
        self.setStyleSheet(f"""
            QPushButton{{background:transparent;border:none;border-radius:6px;
                color:{COLORS['text_secondary']};text-align:left;padding-left:12px;font-size:13px;margin:2px 8px;}}
            QPushButton:hover{{background:{COLORS['sidebar_hover']};color:{COLORS['text_primary']};}}
            QPushButton:checked{{background:{COLORS['sidebar_active']}33;color:{COLORS['accent_blue']};
                border-left:3px solid {COLORS['accent_blue']};font-weight:bold;}}
        """)


# ─── OVERVIEW PAGE ────────────────────────────────────
class OverviewPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setSpacing(16); lay.setContentsMargins(24,20,24,20)

        hdr = QLabel("NETWORK OVERVIEW")
        hdr.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:11px;letter-spacing:2px;font-weight:bold;")
        lay.addWidget(hdr)

        mode_row = QHBoxLayout()
        self.mode_badge = make_badge("IDS  —  MONITOR ONLY", COLORS["accent_green"])
        self.mode_badge.setFixedWidth(210)
        self.status_badge = make_badge("IDLE", COLORS["text_secondary"])
        self.status_badge.setFixedWidth(140)
        mode_row.addWidget(QLabel("MODE:"))
        mode_row.addWidget(self.mode_badge)
        mode_row.addStretch()
        mode_row.addWidget(self.status_badge)
        lay.addLayout(mode_row)

        cards = QHBoxLayout(); cards.setSpacing(12)
        self.card_pkts, self.val_pkts = stat_card("Packets Analyzed","0",COLORS["accent_blue"])
        self.card_alerts, self.val_alerts = stat_card("Alerts Fired","0",COLORS["accent_red"])
        self.card_blocked, self.val_blocked = stat_card("Packets Blocked","0",COLORS["accent_orange"])
        self.card_clean, self.val_clean = stat_card("Clean Packets","0",COLORS["accent_green"])
        for c in [self.card_pkts,self.card_alerts,self.card_blocked,self.card_clean]:
            cards.addWidget(c)
        lay.addLayout(cards)

        acc_grp = QGroupBox("DETECTION ACCURACY")
        acc_lay = QVBoxLayout(acc_grp)
        self.acc_bar = QProgressBar()
        self.acc_bar.setValue(0)
        self.acc_bar.setFormat("%p%  accurate")
        self.acc_bar.setStyleSheet(f"""
            QProgressBar{{background:{COLORS['bg_tertiary']};border:1px solid {COLORS['border']};border-radius:6px;height:22px;font-size:12px;color:{COLORS['text_primary']};text-align:center;}}
            QProgressBar::chunk{{background:{COLORS['accent_blue']};border-radius:6px;}}
        """)
        self.acc_label = QLabel("Load a PCAP file or use Demo Mode to begin analysis.")
        self.acc_label.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:12px;")
        acc_lay.addWidget(self.acc_bar); acc_lay.addWidget(self.acc_label)
        lay.addWidget(acc_grp)

        feed_grp = QGroupBox("LIVE ALERT FEED")
        feed_lay = QVBoxLayout(feed_grp)
        self.feed_list = QListWidget()
        self.feed_list.setMaximumHeight(220)
        feed_lay.addWidget(self.feed_list)
        lay.addWidget(feed_grp)
        lay.addStretch()

    def add_alert(self, alert):
        sev = alert.get("severity","LOW")
        color = COLORS["high_sev"] if sev=="HIGH" else COLORS["med_sev"] if sev=="MEDIUM" else COLORS["low_sev"]
        ts = alert.get("timestamp","")
        item = QListWidgetItem(f"  [{ts}]  {alert['rule_name']}  —  {alert['src_ip']} → {alert['dst_ip']}")
        item.setForeground(QColor(color))
        self.feed_list.insertItem(0, item)
        if self.feed_list.count() > 60:
            self.feed_list.takeItem(self.feed_list.count()-1)

    def update_stats(self, total_pkts, total_alerts, total_blocked):
        clean = max(0, total_pkts - total_alerts)
        self.val_pkts.setText(str(total_pkts))
        self.val_alerts.setText(str(total_alerts))
        self.val_blocked.setText(str(total_blocked))
        self.val_clean.setText(str(clean))
        if total_pkts > 0:
            acc = int((clean / total_pkts)*100)
            self.acc_bar.setValue(acc)
            self.acc_label.setText(f"{clean} clean  ·  {total_alerts} threats detected" +
                (f"  ·  {total_blocked} blocked (IPS)" if total_blocked else ""))

    def set_mode(self, mode):
        if mode == "IPS":
            self.mode_badge.setText("IPS  —  BLOCKING ACTIVE")
            self.mode_badge.setStyleSheet(f"QLabel{{background:{COLORS['accent_red']}22;color:{COLORS['accent_red']};border:1px solid {COLORS['accent_red']}55;border-radius:4px;padding:0 8px;font-size:11px;font-weight:bold;}}")
        else:
            self.mode_badge.setText("IDS  —  MONITOR ONLY")
            self.mode_badge.setStyleSheet(f"QLabel{{background:{COLORS['accent_green']}22;color:{COLORS['accent_green']};border:1px solid {COLORS['accent_green']}55;border-radius:4px;padding:0 8px;font-size:11px;font-weight:bold;}}")

    def set_status(self, status):
        m = {"idle":("IDLE",COLORS["text_secondary"]),"running":("ANALYZING",COLORS["accent_green"]),"done":("COMPLETE",COLORS["accent_blue"])}
        txt, col = m.get(status, ("IDLE",COLORS["text_secondary"]))
        self.status_badge.setText(txt)
        self.status_badge.setStyleSheet(f"QLabel{{background:{col}22;color:{col};border:1px solid {col}55;border-radius:4px;padding:0 8px;font-size:11px;font-weight:bold;}}")


# ─── ALERTS PAGE ──────────────────────────────────────
class AlertsPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self); lay.setSpacing(10); lay.setContentsMargins(24,20,24,20)
        hdr = QLabel("ALERT LOG")
        hdr.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:11px;letter-spacing:2px;font-weight:bold;")
        lay.addWidget(hdr)

        fr = QHBoxLayout()
        self.sev_filter = QComboBox(); self.sev_filter.addItems(["All Severities","HIGH","MEDIUM","LOW"])
        self.cat_filter = QComboBox(); self.cat_filter.addItems(["All Categories","Port Scan","Brute Force","Web Attack","Malware","Anomaly","Exploit","Custom"])
        self.search_box = QLineEdit(); self.search_box.setPlaceholderText("Search rule, IP, or ID...")
        clear_btn = QPushButton("Clear"); clear_btn.setFixedWidth(70)
        self.sev_filter.currentIndexChanged.connect(self._filter)
        self.cat_filter.currentIndexChanged.connect(self._filter)
        self.search_box.textChanged.connect(self._filter)
        clear_btn.clicked.connect(self.clear_alerts)
        fr.addWidget(QLabel("Severity:")); fr.addWidget(self.sev_filter)
        fr.addWidget(QLabel("Category:")); fr.addWidget(self.cat_filter)
        fr.addWidget(self.search_box,1); fr.addWidget(clear_btn)
        lay.addLayout(fr)

        cols = ["#","Time","Src IP","Dst IP","Rule ID","Rule Name","Category","Severity","MITRE","Action"]
        self.table = QTableWidget(0, len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        lay.addWidget(self.table)
        self._all = []

    def add_alert(self, alert):
        self._all.append(alert)
        self._filter()

    def _filter(self):
        sev = self.sev_filter.currentText()
        cat = self.cat_filter.currentText()
        q = self.search_box.text().lower()
        filtered = [a for a in self._all
            if (sev=="All Severities" or a["severity"]==sev)
            and (cat=="All Categories" or a["category"]==cat)
            and (not q or q in a["rule_name"].lower() or q in a["src_ip"].lower() or q in a["rule_id"].lower())]
        self.table.setRowCount(len(filtered))
        sc = {"HIGH":COLORS["high_sev"],"MEDIUM":COLORS["med_sev"],"LOW":COLORS["low_sev"]}
        for row, a in enumerate(reversed(filtered)):
            blocked = a.get("blocked",False)
            cells = [str(row+1), a.get("timestamp",""), a.get("src_ip",""), a.get("dst_ip",""),
                     a.get("rule_id",""), a.get("rule_name",""), a.get("category",""),
                     a.get("severity",""), a.get("mitre",""), "BLOCKED" if blocked else "LOGGED"]
            for col, txt in enumerate(cells):
                itm = QTableWidgetItem(txt)
                itm.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                if blocked:
                    itm.setBackground(QColor(COLORS["blocked_bg"]))
                if col==7:
                    itm.setForeground(QColor(sc.get(txt, COLORS["text_secondary"])))
                    itm.setFont(QFont("Consolas",11,QFont.Bold))
                if col==9:
                    itm.setForeground(QColor(COLORS["accent_red"] if blocked else COLORS["accent_green"]))
                    itm.setFont(QFont("Consolas",11,QFont.Bold))
                if col==8:
                    itm.setForeground(QColor(COLORS["accent_purple"]))
                self.table.setItem(row, col, itm)

    def clear_alerts(self):
        self._all.clear(); self.table.setRowCount(0)


# ─── PACKET INSPECTOR ─────────────────────────────────
class PacketInspectorPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self); lay.setSpacing(10); lay.setContentsMargins(24,20,24,20)
        hdr = QLabel("PACKET INSPECTOR")
        hdr.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:11px;letter-spacing:2px;font-weight:bold;")
        lay.addWidget(hdr)
        splitter = QSplitter(Qt.Horizontal)

        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0,0,0,0)
        self.pkt_list = QTableWidget(0,5)
        self.pkt_list.setHorizontalHeaderLabels(["#","Time","Src","Dst","Proto"])
        self.pkt_list.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.pkt_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.pkt_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.pkt_list.verticalHeader().setVisible(False)
        self.pkt_list.cellClicked.connect(self._on_select)
        ll.addWidget(self.pkt_list)
        splitter.addWidget(left)

        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0,0,0,0)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane{{border:1px solid {COLORS['border']};border-radius:6px;}}
            QTabBar::tab{{background:{COLORS['bg_card']};color:{COLORS['text_secondary']};padding:6px 14px;border-radius:4px 4px 0 0;font-size:12px;}}
            QTabBar::tab:selected{{background:{COLORS['bg_tertiary']};color:{COLORS['accent_blue']};}}
        """)
        base_style = f"background:{COLORS['bg_secondary']};border:none;color:{COLORS['text_primary']};"
        self.summary_tab = QTextEdit(); self.summary_tab.setReadOnly(True)
        self.summary_tab.setStyleSheet(base_style + "font-size:13px;")
        self.hex_tab = QTextEdit(); self.hex_tab.setReadOnly(True)
        self.hex_tab.setStyleSheet(base_style + f"font-family:'Consolas',monospace;font-size:12px;color:{COLORS['accent_green']};")
        self.rules_tab = QTextEdit(); self.rules_tab.setReadOnly(True)
        self.rules_tab.setStyleSheet(base_style + "font-size:13px;")
        self.tabs.addTab(self.summary_tab,"Summary")
        self.tabs.addTab(self.hex_tab,"Hex View")
        self.tabs.addTab(self.rules_tab,"Matched Rules")
        rl.addWidget(self.tabs)
        splitter.addWidget(right)
        splitter.setSizes([340,500])
        lay.addWidget(splitter)
        self._packets = []

    def add_packet(self, p):
        if len(self._packets) > 2000: return
        self._packets.append(p)
        row = self.pkt_list.rowCount()
        self.pkt_list.insertRow(row)
        has_alert = len(p.get("alerts",[])) > 0
        color = COLORS["high_sev"] if has_alert else COLORS["text_secondary"]
        for col, txt in enumerate([str(p["index"]),p["timestamp"],p["src"],p["dst"],p["proto"]]):
            itm = QTableWidgetItem(txt)
            itm.setForeground(QColor(color))
            self.pkt_list.setItem(row, col, itm)

    def _on_select(self, row, _):
        if row >= len(self._packets): return
        p = self._packets[row]
        self.summary_tab.setPlainText(
            f"Packet #{p['index']}\n{'─'*38}\n"
            f"Timestamp : {p['timestamp']}\nProtocol  : {p['proto']}\n"
            f"Source    : {p['src']}\nDestination: {p['dst']}\n"
            f"Dst Port  : {p.get('dport','N/A')}\nSize      : {p.get('size','N/A')} bytes\n"
            f"Blocked   : {'YES' if p.get('blocked') else 'NO'}\nAlerts    : {len(p.get('alerts',[]))}\n")
        raw = p.get("raw","")
        lines = []
        for i in range(0,len(raw),32):
            chunk=raw[i:i+32]; pairs=[chunk[j:j+2] for j in range(0,len(chunk),2)]
            lines.append(f"{i//2:04x}  {' '.join(pairs):<48}")
        self.hex_tab.setPlainText("\n".join(lines) or "(no payload)")
        alerts = p.get("alerts",[])
        if alerts:
            txt = ""
            for a in alerts:
                txt += f"RULE   : {a['rule_id']}  —  {a['rule_name']}\n"
                txt += f"Category: {a['category']}   Severity: {a['severity']}\n"
                txt += f"MITRE  : {a.get('mitre','N/A')}\n"
                txt += f"Detail : {a['description']}\n\n"
            self.rules_tab.setPlainText(txt)
        else:
            self.rules_tab.setPlainText("No rules matched — packet is clean.")

    def clear(self):
        self._packets.clear(); self.pkt_list.setRowCount(0)
        self.summary_tab.clear(); self.hex_tab.clear(); self.rules_tab.clear()


# ─── RULE MANAGER ─────────────────────────────────────
class RuleManagerPage(QWidget):
    rules_changed = pyqtSignal(list)

    def __init__(self, rules):
        super().__init__()
        self.rules = [dict(r) for r in rules]
        lay = QVBoxLayout(self); lay.setSpacing(10); lay.setContentsMargins(24,20,24,20)
        hdr = QLabel("RULE MANAGER")
        hdr.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:11px;letter-spacing:2px;font-weight:bold;")
        lay.addWidget(hdr)
        splitter = QSplitter(Qt.Horizontal)

        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0,0,0,0)
        cats = ["All"] + sorted(set(r["category"] for r in self.rules))
        self._cat_btns = []
        for cat in cats:
            btn = QPushButton(cat); btn.setCheckable(True); btn.setFixedHeight(32)
            btn.setChecked(cat=="All")
            btn.clicked.connect(lambda _,c=cat: self._filter(c))
            btn.setStyleSheet(f"""
                QPushButton{{background:{COLORS['bg_card']};border:1px solid {COLORS['border']};border-radius:5px;
                    color:{COLORS['text_secondary']};text-align:left;padding-left:10px;font-size:12px;margin-bottom:3px;}}
                QPushButton:checked{{border-color:{COLORS['accent_blue']};color:{COLORS['accent_blue']};background:{COLORS['sidebar_active']}22;}}
            """)
            ll.addWidget(btn); self._cat_btns.append((cat,btn))
        ll.addSpacing(8)
        self.rule_list = QTableWidget(0,3)
        self.rule_list.setHorizontalHeaderLabels(["ID","Rule Name","On"])
        self.rule_list.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.rule_list.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeToContents)
        self.rule_list.horizontalHeader().setSectionResizeMode(2,QHeaderView.ResizeToContents)
        self.rule_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rule_list.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rule_list.verticalHeader().setVisible(False)
        self.rule_list.cellClicked.connect(self._on_select)
        ll.addWidget(self.rule_list)
        splitter.addWidget(left)

        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0,0,0,0)
        self.detail = QTextEdit(); self.detail.setReadOnly(True); self.detail.setMaximumHeight(190)
        self.detail.setStyleSheet(f"background:{COLORS['bg_secondary']};border:1px solid {COLORS['border']};border-radius:6px;padding:10px;")
        self.detail.setPlaceholderText("Select a rule to view its details...")
        rl.addWidget(QLabel("Rule Details")); rl.addWidget(self.detail)

        cg = QGroupBox("ADD CUSTOM RULE")
        cl = QFormLayout(cg); cl.setSpacing(8)
        self.cr_id   = QLineEdit(); self.cr_id.setPlaceholderText("CUSTOM-001")
        self.cr_name = QLineEdit(); self.cr_name.setPlaceholderText("Rule name")
        self.cr_cat  = QComboBox(); self.cr_cat.addItems(["Port Scan","Brute Force","Web Attack","Malware","Anomaly","Exploit","Custom"])
        self.cr_sev  = QComboBox(); self.cr_sev.addItems(["HIGH","MEDIUM","LOW"])
        self.cr_proto= QComboBox(); self.cr_proto.addItems(["TCP","UDP","ICMP","ANY"])
        self.cr_port = QLineEdit(); self.cr_port.setPlaceholderText("e.g. 4444 (leave blank = any)")
        self.cr_kw   = QLineEdit(); self.cr_kw.setPlaceholderText("e.g. /bin/sh, cmd.exe")
        self.cr_desc = QLineEdit(); self.cr_desc.setPlaceholderText("Short description")
        add_btn = QPushButton("+ Add Rule")
        add_btn.setStyleSheet(f"background:{COLORS['accent_blue']}22;border-color:{COLORS['accent_blue']};color:{COLORS['accent_blue']};font-weight:bold;")
        add_btn.clicked.connect(self._add_custom)
        cl.addRow("Rule ID:", self.cr_id)
        cl.addRow("Name:", self.cr_name)
        cl.addRow("Category:", self.cr_cat)
        cl.addRow("Severity:", self.cr_sev)
        cl.addRow("Protocol:", self.cr_proto)
        cl.addRow("Dst Port:", self.cr_port)
        cl.addRow("Keywords:", self.cr_kw)
        cl.addRow("Description:", self.cr_desc)
        cl.addRow("", add_btn)
        rl.addWidget(cg); rl.addStretch()
        splitter.addWidget(right); splitter.setSizes([380,460])
        lay.addWidget(splitter)
        self._current_cat = "All"
        self._filter("All")

    def _filter(self, cat):
        self._current_cat = cat
        for c,btn in self._cat_btns: btn.setChecked(c==cat)
        filtered = self.rules if cat=="All" else [r for r in self.rules if r["category"]==cat]
        self.rule_list.setRowCount(len(filtered))
        sc = {"HIGH":COLORS["high_sev"],"MEDIUM":COLORS["med_sev"],"LOW":COLORS["low_sev"]}
        for row, rule in enumerate(filtered):
            self.rule_list.setItem(row,0,QTableWidgetItem(rule["id"]))
            itm = QTableWidgetItem(rule["name"])
            itm.setForeground(QColor(sc.get(rule["severity"],COLORS["text_secondary"])))
            self.rule_list.setItem(row,1,itm)
            cb = QCheckBox(); cb.setChecked(rule["enabled"]); cb.setStyleSheet("margin-left:10px;")
            cb.stateChanged.connect(lambda s,rid=rule["id"]: self._toggle(rid,s))
            self.rule_list.setCellWidget(row,2,cb)

    def _on_select(self, row, _):
        cat = self._current_cat
        filtered = self.rules if cat=="All" else [r for r in self.rules if r["category"]==cat]
        if row >= len(filtered): return
        r = filtered[row]
        self.detail.setPlainText(
            f"ID         : {r['id']}\nName       : {r['name']}\nCategory   : {r['category']}\n"
            f"Severity   : {r['severity']}\nConfidence : {r.get('confidence','HIGH')}\n"
            f"MITRE      : {r.get('mitre','N/A')}\n\nDescription:\n{r['description']}")

    def _toggle(self, rid, state):
        for r in self.rules:
            if r["id"] == rid: r["enabled"] = (state == Qt.Checked)
        self.rules_changed.emit(self.rules)

    def _add_custom(self):
        rid = self.cr_id.text().strip(); name = self.cr_name.text().strip()
        if not rid or not name:
            QMessageBox.warning(self,"Missing Fields","Rule ID and Name are required."); return
        keywords = [k.strip() for k in self.cr_kw.text().split(",") if k.strip()]
        pt = self.cr_port.text().strip()
        try: port = int(pt) if pt else None
        except ValueError: QMessageBox.warning(self,"Invalid Port","Port must be a number."); return
        cond = {"proto": self.cr_proto.currentText()}
        if port: cond["dport"] = port
        if keywords: cond["payload_keywords"] = keywords
        self.rules.append({"id":rid,"name":name,"category":self.cr_cat.currentText(),
            "severity":self.cr_sev.currentText(),"confidence":"HIGH","enabled":True,
            "description":self.cr_desc.text().strip() or "Custom rule.","mitre":"Custom","conditions":cond})
        self._filter(self._current_cat)
        self.rules_changed.emit(self.rules)
        for w in [self.cr_id,self.cr_name,self.cr_port,self.cr_kw,self.cr_desc]: w.clear()
        QMessageBox.information(self,"Rule Added",f"Rule '{name}' added.")


# ─── STATISTICS PAGE ──────────────────────────────────
class StatisticsPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self); lay.setSpacing(16); lay.setContentsMargins(24,20,24,20)
        hdr = QLabel("STATISTICS")
        hdr.setStyleSheet(f"color:{COLORS['text_secondary']};font-size:11px;letter-spacing:2px;font-weight:bold;")
        lay.addWidget(hdr)
        self._proto_counts = defaultdict(int)
        self._cat_counts = defaultdict(int)
        self._sev_counts = defaultdict(int)
        self._src_alerts = defaultdict(list)

        if HAS_PYQTGRAPH:
            pg.setConfigOptions(antialias=True, background=COLORS["bg_secondary"], foreground=COLORS["text_secondary"])
            cr = QHBoxLayout()
            pg1 = QGroupBox("PROTOCOL BREAKDOWN"); pl1 = QVBoxLayout(pg1)
            self.proto_chart = pg.PlotWidget(); self.proto_chart.setMaximumHeight(200)
            pl1.addWidget(self.proto_chart); cr.addWidget(pg1)
            pg2 = QGroupBox("ALERTS BY CATEGORY"); pl2 = QVBoxLayout(pg2)
            self.cat_chart = pg.PlotWidget(); self.cat_chart.setMaximumHeight(200)
            pl2.addWidget(self.cat_chart); cr.addWidget(pg2)
            lay.addLayout(cr)
        else:
            lbl = QLabel("Install pyqtgraph for charts:\n  pip install pyqtgraph")
            lbl.setStyleSheet(f"color:{COLORS['text_muted']};font-size:13px;padding:20px;"); lay.addWidget(lbl)

        sg = QGroupBox("SEVERITY BREAKDOWN"); sl = QVBoxLayout(sg)
        self.sev_table = QTableWidget(3,3)
        self.sev_table.setHorizontalHeaderLabels(["Severity","Count","% of Alerts"])
        self.sev_table.verticalHeader().setVisible(False)
        self.sev_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.sev_table.setMaximumHeight(140); self.sev_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        for row,(sev,col) in enumerate([("HIGH",COLORS["high_sev"]),("MEDIUM",COLORS["med_sev"]),("LOW",COLORS["low_sev"])]):
            itm = QTableWidgetItem(sev); itm.setForeground(QColor(col)); itm.setFont(QFont("Consolas",11,QFont.Bold))
            self.sev_table.setItem(row,0,itm); self.sev_table.setItem(row,1,QTableWidgetItem("0")); self.sev_table.setItem(row,2,QTableWidgetItem("0%"))
        sl.addWidget(self.sev_table); lay.addWidget(sg)

        srcg = QGroupBox("TOP ALERT SOURCES"); srcl = QVBoxLayout(srcg)
        self.src_table = QTableWidget(0,3)
        self.src_table.setHorizontalHeaderLabels(["Source IP","Alerts","Top Rule"])
        self.src_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.src_table.verticalHeader().setVisible(False)
        self.src_table.setEditTriggers(QAbstractItemView.NoEditTriggers); self.src_table.setMaximumHeight(160)
        srcl.addWidget(self.src_table); lay.addWidget(srcg); lay.addStretch()

    def add_packet(self, p): self._proto_counts[p["proto"]] += 1

    def add_alert(self, a):
        self._cat_counts[a["category"]] += 1
        self._sev_counts[a["severity"]] += 1
        self._src_alerts[a.get("src_ip","?")].append(a["rule_name"])
        self._refresh()

    def _refresh(self):
        total = sum(self._sev_counts.values())
        for row, sev in enumerate(["HIGH","MEDIUM","LOW"]):
            cnt = self._sev_counts[sev]
            pct = f"{int(cnt/total*100)}%" if total else "0%"
            self.sev_table.item(row,1).setText(str(cnt))
            self.sev_table.item(row,2).setText(pct)
        srcs = sorted(self._src_alerts.items(), key=lambda x:len(x[1]),reverse=True)[:10]
        self.src_table.setRowCount(len(srcs))
        for row,(src,rl) in enumerate(srcs):
            top = max(set(rl),key=rl.count)
            self.src_table.setItem(row,0,QTableWidgetItem(src))
            ci = QTableWidgetItem(str(len(rl))); ci.setForeground(QColor(COLORS["accent_red"]))
            self.src_table.setItem(row,1,ci); self.src_table.setItem(row,2,QTableWidgetItem(top))
        if not HAS_PYQTGRAPH: return
        self.proto_chart.clear()
        ps = list(self._proto_counts.keys()); pc = [self._proto_counts[p] for p in ps]
        if ps:
            cols = [QColor(COLORS["accent_blue"]),QColor(COLORS["accent_green"]),QColor(COLORS["accent_orange"]),QColor(COLORS["accent_purple"])]
            self.proto_chart.addItem(pg.BarGraphItem(x=list(range(len(ps))),height=pc,width=0.6,brushes=[cols[i%len(cols)] for i in range(len(ps))]))
            self.proto_chart.getAxis("bottom").setTicks([[(i,p) for i,p in enumerate(ps)]]); self.proto_chart.showAxis("bottom")
        self.cat_chart.clear()
        cs = list(self._cat_counts.keys()); cc = [self._cat_counts[c] for c in cs]
        if cs:
            cols2 = [QColor(COLORS["accent_red"]),QColor(COLORS["accent_orange"]),QColor(COLORS["accent_purple"]),QColor(COLORS["accent_blue"]),QColor(COLORS["accent_cyan"])]
            self.cat_chart.addItem(pg.BarGraphItem(x=list(range(len(cs))),height=cc,width=0.6,brushes=[cols2[i%len(cols2)] for i in range(len(cs))]))
            self.cat_chart.getAxis("bottom").setTicks([[(i,c[:8]) for i,c in enumerate(cs)]]); self.cat_chart.showAxis("bottom")


# ─── MAIN WINDOW ──────────────────────────────────────
class SnortDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Snort IDS/IPS Dashboard  —  OP-vanguard")
        self.setMinimumSize(1200,750)
        self.rules = [dict(r) for r in BUILTIN_RULES]
        self._worker = None
        self._total_pkts = 0; self._total_alerts = 0; self._total_blocked = 0
        self._mode = "IDS"; self._current_pcap = None
        self._apply_theme(); self._build_ui()

    def _apply_theme(self):
        self.setStyleSheet(GLOBAL_STYLE)
        pal = QPalette()
        pal.setColor(QPalette.Window,      QColor(COLORS["bg_primary"]))
        pal.setColor(QPalette.WindowText,  QColor(COLORS["text_primary"]))
        pal.setColor(QPalette.Base,        QColor(COLORS["bg_secondary"]))
        pal.setColor(QPalette.Text,        QColor(COLORS["text_primary"]))
        pal.setColor(QPalette.Button,      QColor(COLORS["bg_card"]))
        pal.setColor(QPalette.ButtonText,  QColor(COLORS["text_primary"]))
        self.setPalette(pal)

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        ml = QHBoxLayout(central); ml.setSpacing(0); ml.setContentsMargins(0,0,0,0)

        # Sidebar
        sb = QFrame(); sb.setFixedWidth(220)
        sb.setStyleSheet(f"background:{COLORS['bg_secondary']};border-right:1px solid {COLORS['border']};")
        sbl = QVBoxLayout(sb); sbl.setSpacing(0); sbl.setContentsMargins(0,16,0,16)

        logo = QLabel("SNORT")
        logo.setStyleSheet(f"color:{COLORS['accent_blue']};font-size:22px;font-weight:bold;letter-spacing:4px;padding:8px 20px 4px;")
        sub = QLabel("IDS / IPS Dashboard")
        sub.setStyleSheet(f"color:{COLORS['text_muted']};font-size:10px;letter-spacing:1px;padding:0 20px 16px;")
        sbl.addWidget(logo); sbl.addWidget(sub)
        line = QFrame(); line.setFrameShape(QFrame.HLine)
        line.setStyleSheet(f"color:{COLORS['border']};margin:4px 12px;"); sbl.addWidget(line)

        self._nav_btns = []
        for label, icon in [("Overview","◉"),("Alerts","⚠"),("Packet Inspector","🔍"),("Rule Manager","📋"),("Statistics","📊")]:
            btn = SidebarButton(label, icon)
            btn.clicked.connect(lambda _,l=label: self._switch_page(l))
            sbl.addWidget(btn); self._nav_btns.append((label,btn))
        self._nav_btns[0][1].setChecked(True)
        sbl.addStretch()

        # Mode
        mg = QGroupBox("MODE"); mg.setStyleSheet(f"QGroupBox{{margin:8px;padding:10px 8px;}}QGroupBox::title{{color:{COLORS['text_muted']};}}")
        ml2 = QVBoxLayout(mg)
        self.ids_btn = QPushButton("IDS  (Monitor)"); self.ids_btn.setCheckable(True); self.ids_btn.setChecked(True); self.ids_btn.setFixedHeight(34)
        self.ips_btn = QPushButton("IPS  (Block)");   self.ips_btn.setCheckable(True); self.ips_btn.setFixedHeight(34)
        self.ids_btn.setStyleSheet(self.ids_btn.styleSheet()+f"QPushButton:checked{{background:{COLORS['accent_green']}22;border-color:{COLORS['accent_green']};color:{COLORS['accent_green']};}}")
        self.ips_btn.setStyleSheet(self.ips_btn.styleSheet()+f"QPushButton:checked{{background:{COLORS['accent_red']}22;border-color:{COLORS['accent_red']};color:{COLORS['accent_red']};}}")
        self.ids_btn.clicked.connect(lambda: self._set_mode("IDS"))
        self.ips_btn.clicked.connect(lambda: self._set_mode("IPS"))
        ml2.addWidget(self.ids_btn); ml2.addWidget(self.ips_btn)
        sbl.addWidget(mg)

        # Controls
        cg2 = QGroupBox("ANALYSIS"); cg2.setStyleSheet(f"QGroupBox{{margin:8px;padding:10px 8px;}}QGroupBox::title{{color:{COLORS['text_muted']};}}")
        cl2 = QVBoxLayout(cg2)
        self.load_btn = QPushButton("📂  Load PCAP")
        self.run_btn  = QPushButton("▶  Run Analysis")
        self.stop_btn = QPushButton("■  Stop"); self.stop_btn.setEnabled(False)
        demo_btn = QPushButton("🎮  Demo Mode")
        self.load_btn.setStyleSheet(self.load_btn.styleSheet()+f"QPushButton{{color:{COLORS['accent_blue']};}}")
        self.run_btn.setStyleSheet(self.run_btn.styleSheet()+f"QPushButton{{color:{COLORS['accent_green']};}}")
        demo_btn.setStyleSheet(demo_btn.styleSheet()+f"QPushButton{{color:{COLORS['accent_purple']};}}")
        self.load_btn.clicked.connect(self._load_pcap)
        self.run_btn.clicked.connect(self._run_analysis)
        self.stop_btn.clicked.connect(self._stop_analysis)
        demo_btn.clicked.connect(self._run_demo)
        for w in [self.load_btn,self.run_btn,self.stop_btn,demo_btn]: cl2.addWidget(w)
        sbl.addWidget(cg2)

        # Content
        content = QWidget(); content.setStyleSheet(f"background:{COLORS['bg_primary']};")
        cl3 = QVBoxLayout(content); cl3.setContentsMargins(0,0,0,0); cl3.setSpacing(0)

        topbar = QFrame(); topbar.setFixedHeight(48)
        topbar.setStyleSheet(f"background:{COLORS['bg_secondary']};border-bottom:1px solid {COLORS['border']};")
        tbl = QHBoxLayout(topbar); tbl.setContentsMargins(20,0,20,0)
        self.page_title = QLabel("Overview")
        self.page_title.setStyleSheet(f"color:{COLORS['text_primary']};font-size:15px;font-weight:bold;")
        self.pcap_label = QLabel("No file loaded")
        self.pcap_label.setStyleSheet(f"color:{COLORS['text_muted']};font-size:11px;")
        tbl.addWidget(self.page_title); tbl.addStretch(); tbl.addWidget(self.pcap_label)
        cl3.addWidget(topbar)

        self.stack = QStackedWidget()
        self.overview_page  = OverviewPage()
        self.alerts_page    = AlertsPage()
        self.inspector_page = PacketInspectorPage()
        self.rules_page     = RuleManagerPage(self.rules)
        self.stats_page     = StatisticsPage()
        self.rules_page.rules_changed.connect(self._on_rules_changed)
        for page in [self.overview_page,self.alerts_page,self.inspector_page,self.rules_page,self.stats_page]:
            self.stack.addWidget(page)
        cl3.addWidget(self.stack)
        ml.addWidget(sb); ml.addWidget(content,1)

        self.status_bar = QStatusBar(); self.setStatusBar(self.status_bar)
        if not HAS_SCAPY:
            self.status_bar.showMessage("Scapy not installed — running in Demo Mode.  Install: pip install scapy")
        else:
            self.status_bar.showMessage("Ready  —  Load a PCAP file or use Demo Mode.")

    def _switch_page(self, label):
        idx = {"Overview":0,"Alerts":1,"Packet Inspector":2,"Rule Manager":3,"Statistics":4}
        self.stack.setCurrentIndex(idx.get(label,0))
        self.page_title.setText(label)
        for lbl,btn in self._nav_btns: btn.setChecked(lbl==label)

    def _set_mode(self, mode):
        self._mode = mode
        self.ids_btn.setChecked(mode=="IDS"); self.ips_btn.setChecked(mode=="IPS")
        self.overview_page.set_mode(mode)
        self.status_bar.showMessage(f"Mode: {mode}")

    def _load_pcap(self):
        path,_ = QFileDialog.getOpenFileName(self,"Open PCAP File","","PCAP Files (*.pcap *.pcapng *.cap)")
        if path:
            self._current_pcap = path
            self.pcap_label.setText(f"📂  {path.split('/')[-1]}")
            self.status_bar.showMessage(f"Loaded: {path}")

    def _run_analysis(self):
        if not self._current_pcap and HAS_SCAPY:
            QMessageBox.warning(self,"No File","Load a PCAP file first, or use Demo Mode."); return
        self._start_worker(self._current_pcap or "")

    def _run_demo(self):
        self._current_pcap = None; self.pcap_label.setText("🎮  Demo Mode"); self._start_worker("")

    def _start_worker(self, path):
        if self._worker and self._worker.isRunning():
            self._worker.stop(); self._worker.wait()
        self._reset_state()
        self._worker = PcapWorker(path, self.rules, self._mode)
        self._worker.packet_processed.connect(self._on_packet)
        self._worker.alert_generated.connect(self._on_alert)
        self._worker.finished_signal.connect(self._on_done)
        self._worker.start()
        self.run_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        self.overview_page.set_status("running")
        self.status_bar.showMessage(f"Analyzing  —  Mode: {self._mode}")

    def _stop_analysis(self):
        if self._worker: self._worker.stop()
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.overview_page.set_status("idle")
        self.status_bar.showMessage("Stopped.")

    def _reset_state(self):
        self._total_pkts=0; self._total_alerts=0; self._total_blocked=0
        self.alerts_page.clear_alerts(); self.inspector_page.clear()

    def _on_packet(self, p):
        self._total_pkts += 1
        self.inspector_page.add_packet(p); self.stats_page.add_packet(p)
        if self._total_pkts % 10 == 0:
            self.overview_page.update_stats(self._total_pkts,self._total_alerts,self._total_blocked)

    def _on_alert(self, a):
        self._total_alerts += 1
        if a.get("blocked"): self._total_blocked += 1
        self.overview_page.add_alert(a); self.alerts_page.add_alert(a); self.stats_page.add_alert(a)
        self.overview_page.update_stats(self._total_pkts,self._total_alerts,self._total_blocked)

    def _on_done(self, total_pkts, total_alerts):
        self.run_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        self.overview_page.set_status("done")
        self.overview_page.update_stats(self._total_pkts,self._total_alerts,self._total_blocked)
        self.status_bar.showMessage(f"Done  —  {self._total_pkts} packets  ·  {self._total_alerts} alerts  ·  {self._total_blocked} blocked")

    def _on_rules_changed(self, new_rules): self.rules = new_rules

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.stop(); self._worker.wait()
        event.accept()


# ─── ENTRY POINT ──────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Snort IDS/IPS Dashboard")
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window,          QColor(COLORS["bg_primary"]))
    pal.setColor(QPalette.WindowText,      QColor(COLORS["text_primary"]))
    pal.setColor(QPalette.Base,            QColor(COLORS["bg_secondary"]))
    pal.setColor(QPalette.AlternateBase,   QColor(COLORS["bg_tertiary"]))
    pal.setColor(QPalette.Text,            QColor(COLORS["text_primary"]))
    pal.setColor(QPalette.Button,          QColor(COLORS["bg_card"]))
    pal.setColor(QPalette.ButtonText,      QColor(COLORS["text_primary"]))
    pal.setColor(QPalette.Highlight,       QColor(COLORS["sidebar_active"]))
    pal.setColor(QPalette.HighlightedText, QColor(COLORS["text_primary"]))
    app.setPalette(pal)
    win = SnortDashboard(); win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
