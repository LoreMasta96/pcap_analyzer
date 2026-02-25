# PCAP Forensic & Behavioral Analyzer

A command-line Python tool for advanced forensic and behavioral analysis of PCAP files.

This project performs deep inspection of network traffic to extract host identity, protocol behavior, suspicious activity patterns, and enrichment through optional VirusTotal and tshark integration.

---

## 🚀 Features

### 📊 Network Overview
- Protocol distribution (packets and bytes)
- Top source/destination IPs
- Top source/destination ports
- JA3 fingerprint statistics

### 🖥 Host Inventory & Identity Correlation
- DHCP client identity extraction
- NetBIOS / NBNS parsing
- LLMNR / mDNS hostname extraction
- Kerberos principal detection
- NTLM username extraction
- Server role detection (HTTP, TLS, DNS indicators)
- OS hint from TTL analysis

### 🌐 DNS Analysis
- Base domain extraction
- High-entropy domain detection (DGA/tunneling heuristics)
- Suspicious vs known-good classification

### 📁 HTTP File Analysis
- File extension tracking
- Suspicious download detection
- Large file detection
- Content-Type ↔ extension mismatch detection

### 🔐 TLS & JA3 Analysis
- JA3 fingerprint extraction
- SNI extraction
- UA ↔ JA3 mismatch heuristics

### 🎯 Focus Host Mode
Deep behavioral analysis of a single host:
- Timeline of DNS, HTTP, TLS events
- Client vs server role distinction
- Suspicious downloads per host
- Per-host JA3 activity
- Optional VirusTotal enrichment

### 🛡 VirusTotal Integration (Optional)
- IP reputation lookup
- Exported HTTP object hashing
- File reputation lookup
- Local caching support

### 🧰 tshark Enrichment (Optional)
- Enhanced Kerberos extraction
- HTTP object export
- Improved TLS server role detection

---

## 🛠 Requirements

Python 3.9+

### Python Dependencies

scapy==2.5.0
cryptography==42.0.5

Install them with:

```bash
pip install -r requirements.txt

### Optional Dependencies (Not Installed via pip)

- tshark (Wireshark CLI tool)

Required for advanced enrichment features such as:

- HTTP object export

- Enhanced Kerberos extraction

- Improved TLS server role detection

- VirusTotal API key

Required for:

- IP reputation lookups

- Exported file hash reputation checks

You can pass your API key via CLI:

python main.py sample.pcap --vt --vt-key YOUR_API_KEY


Or set it as an environment variable:

export VT_API_KEY=YOUR_API_KEY      # macOS / Linux
set VT_API_KEY YOUR_API_KEY        # Windows

---

## Focus Mode

python main.py sample.pcap --focus 192.168.1.10

## Enable VirusTotal

python main.py sample.pcap --vt --vt-key YOUR_API_KEY

## Enable tshark Enrichment

python main.py sample.pcap --use-tshark

---

## 🧠 Detection Philosophy

This tool is not just a PCAP parser.
It applies correlation logic and behavioral heuristics to identify:

- Suspicious DNS entropy patterns

- Potential DGA domains

- Risky HTTP file downloads

- UA/JA3 inconsistencies

- Host role anomalies

- Identity correlations across protocols

The goal is to simulate real-world SOC investigation workflow in an automated CLI environment.

---

## 📁 Project Structure

pcap-analyzer/
├── main.py
├── requirements.txt
└── pcap_analyzer/
    ├── __init__.py
    ├── cli.py
    ├── constants.py
    ├── models.py
    ├── pcap.io
    ├── proto_stats.py
    ├── utils.py
    ├── host_inventory.py
    ├── dns_analysis.py
    ├── http_analysis.py
    ├── tls_analysis.py
    ├── focus.py
    ├── vt_enrichment.py
    ├── tshark_enrichment.py
    └── reporting.py

---

## ⚠ Limitations

- Passive analysis only (no active scanning)

- JA3 extraction depends on TLS visibility

- Encrypted traffic limits deep inspection

- VirusTotal queries may be rate-limited

---

## 🎯 Intended Use

- SOC Analyst portfolio project

- Blue Team training

- PCAP forensic analysis practice

- Threat hunting experimentation


## 👤 Author

Lorenzo Mastandrea


