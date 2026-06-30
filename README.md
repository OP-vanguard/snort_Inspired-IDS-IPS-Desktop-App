# Snort-Inspired IDS/IPS Desktop App

A desktop Intrusion Detection / Prevention System built with Python and PyQt5, inspired by Snort's rule-based detection model. It analyzes PCAP files (or live demo traffic) against a custom rule engine, classifies threats by severity, and maps every detection to the MITRE ATT&CK framework — all through a dark-themed, real-time dashboard.

![Status](https://img.shields.io/badge/status-active-brightgreen) ![Python](https://img.shields.io/badge/python-3.x-blue) ![PyQt5](https://img.shields.io/badge/GUI-PyQt5-orange)

---

## Overview

This project recreates the core detection logic of an IDS/IPS like Snort in a self-contained desktop application. It supports two operating modes — **IDS (Monitor)**, which logs and alerts only, and **IPS (Block)**, which actively blocks matched traffic — and gives full visibility into network activity through a live dashboard.

It was built as a hands-on complement to the TryHackMe SOC Level 1 path, focused on understanding signature-based detection from the ground up rather than just using an existing tool.

## Features

- **Dual operating modes** — switch between IDS (monitor-only) and IPS (active blocking)
- **PCAP analysis** — load and analyze `.pcap` files, or run a built-in Demo Mode with synthetic traffic
- **Real-time dashboard** — live packet counters, detection accuracy gauge, and a scrolling live alert feed
- **19 high-confidence detection rules** covering port scans, web attacks, and protocol anomalies
- **MITRE ATT&CK mapping** — every alert is tagged with its corresponding technique ID
- **Alert log with filtering** — filter by severity and category, search by rule, IP, or alert ID
- **Packet Inspector & Statistics views** for deeper traffic analysis
- **Custom Rule Manager** — define new detection rules without touching code


## Architecture

```
snort-ids-ips-desktop/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── src/
│   ├── main.py                 # Entry point
│   ├── gui/
│   │   ├── main_window.py      # Main window, navigation, mode switch
│   │   ├── dashboard.py        # Overview, Alerts, Packet Inspector, Statistics views
│   │   └── charts.py           # Real-time chart rendering
│   ├── detection/
│   │   ├── engine.py           # Core detection/rule-matching engine
│   │   ├── rules.py            # Rule definitions and loader
│   │   └── mitre_mapping.py    # Rule ID → MITRE ATT&CK technique mapping
│   └── core/
│       ├── packet_capture.py   # PCAP loading / packet parsing
│       └── alert_manager.py    # Alert generation, logging, filtering
├── rules/
│   └── detection_rules.yaml    # Editable rule definitions
├── docs/
│   ├── architecture.md
│   └── screenshots/
└── tests/
```

## Detection Rules

The engine ships with 19 rules across three categories: port/recon scans, web application attacks, and protocol anomalies.

| Rule ID | Rule Name | Category | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| SCAN-001 | TCP Connect Scan | Port Scan | Medium | T1046 |
| SCAN-002 | NULL Scan | Port Scan | High | T1046 |
| SCAN-003 | FIN Scan | Port Scan | High | T1046 |
| SCAN-004 | XMAS Scan | Port Scan | High | T1046 |
| SCAN-005 | ICMP Ping Sweep | Port Scan | Medium | T1018 |
| SCAN-006 | SYN Scan (Stealth Scan) | Port Scan | High | T1046 |
| SCAN-007 | UDP Scan | Port Scan | Medium | T1046 |
| SCAN-008 | Port Sweep (Multi-host) | Port Scan | Medium | T1046 |
| WEB-001 | SQL Injection Attempt | Web Attack | High | T1190 |
| WEB-002 | Cross-Site Scripting (XSS) | Web Attack | High | T1190 |
| WEB-003 | Directory Traversal | Web Attack | High | T1083 |
| WEB-004 | Command Injection Attempt | Web Attack | High | T1190 |
| WEB-005 | Suspicious User-Agent String | Web Attack | Low | T1071 |
| ANOM-001 | Malformed TCP Flags (SYN+FIN) | Anomaly | Medium | T1499 |
| ANOM-002 | Oversized Packet | Anomaly | Low | T1499 |
| ANOM-003 | Fragmented Packet Flood | Anomaly | Medium | T1499 |
| ANOM-004 | TTL Anomaly (Possible Spoofing) | Anomaly | Medium | T1499 |
| ANOM-005 | Repeated Failed Connections | Anomaly | Medium | T1110 |
| ANOM-006 | Beaconing Pattern (Periodic Traffic) | Anomaly | High | T1071 |

> Edit `rules/detection_rules.yaml` to match the exact rule list and IDs in your build — adjust the table above accordingly before publishing.

### How rules work

Each rule defines a packet-level pattern (flags, ports, payload signatures, or timing behavior) the engine checks against every packet. A match generates an alert containing the source/destination IP, severity, category, and mapped MITRE technique. In IPS mode, a match additionally triggers the block action.

### Writing your own rules

New rules can be added in `rules/detection_rules.yaml` (or via the in-app Rule Manager) without modifying the detection engine. A rule definition follows this structure:

```yaml
- id: CUSTOM-001
  name: "Suspicious FTP Brute Force"
  category: "Anomaly"
  severity: "Medium"
  mitre: "T1110"
  match:
    protocol: "tcp"
    dst_port: 21
    condition: "failed_attempts > 5 within 10s"
  action: "alert"   # or "block" in IPS mode
```

Guidelines for writing effective rules:

1. **Pick a unique ID** following the existing prefix convention (`SCAN-`, `WEB-`, `ANOM-`, or your own category prefix).
2. **Keep conditions specific** — overly broad conditions cause false positives and noisy alert feeds.
3. **Always map to MITRE ATT&CK** so the alert has investigative context, not just a name.
4. **Set severity deliberately** — reserve High for confirmed malicious patterns (e.g. SQLi payloads, stealth scans), Medium for suspicious-but-ambiguous behavior, Low for informational signals.
5. **Test against both clean and malicious traffic** before enabling a rule in IPS mode, since a false positive there means a legitimate connection gets blocked.

## Installation

```bash
git clone https://github.com/OP-vanguard/snort_Inspired-IDS-IPS-Desktop-App.git
cd snort_Inspired-IDS-IPS-Desktop-App
pip install -r requirements.txt
python src/main.py
```

## Usage

1. Launch the app — it opens on the **Overview** tab in IDS (Monitor) mode.
2. Click **Load PCAP** to select a `.pcap` file, or use **Demo Mode** to generate synthetic traffic.
3. Click **Run Analysis** to begin processing. Live stats (packets analyzed, alerts fired, detection accuracy) update in real time.
4. Switch to **IPS (Block)** mode to actively block traffic matching a rule, instead of only logging it.
5. Use the **Alerts** tab to filter by severity/category or search by rule, IP, or alert ID.
6. Use **Packet Inspector** and **Statistics** for deeper traffic breakdowns.
7. Use **Rule Manager** to view, edit, or add detection rules.

## Lessons Learned

- Building the rule engine from scratch made signature-based detection logic (the kind Snort uses) far more concrete than just reading about it.
- Balancing detection coverage against false positives is the central tradeoff in any IDS — especially once a rule is allowed to trigger blocking in IPS mode.
- Mapping every alert to MITRE ATT&CK turned a simple alert log into something that reads like an actual SOC analyst tool, with context an analyst could act on.

## Related Projects

- [Wireshark NSM/SIEM Dashboard](#) — network traffic analysis and custom GUI SIEM detecting 8 attack vectors
- [Phishing Attacker/Defender Simulation](#) — phishing simulation with MITRE ATT&CK mapping

