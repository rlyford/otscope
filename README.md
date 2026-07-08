# OTscope

**Interactive multi-pcap OT/ICS traffic analysis with session persistence, role inference, attack-chain correlation, MITRE ATT&CK for ICS mapping, and Wireshark investigation guidance.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![tshark 4.6.4+](https://img.shields.io/badge/tshark-4.6.4+-green.svg)](https://www.wireshark.org/)
[![Status](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

OTscope is a single-file Python program that ingests one or many OT/ICS packet captures, builds a unified device and flow inventory, runs a comprehensive battery of vulnerability and intrusion-detection checks, and produces a Word report alongside JSON, CSV, and SVG artifacts.

It is designed for the case where you receive a pile of pcap files from a site you don't fully know and need to answer: **what's on this network, is anything obviously misconfigured, and is anyone attacking it?**

---

## Why OTscope

| | |
|---|---|
| **Scope** | Vulnerability detection AND active-intrusion detection. Both run on every analysis. |
| **Input** | Multiple `.pcap` / `.pcapng` files merged into one unified session. Incremental — add new files later without re-analyzing the old ones. |
| **Output** | Word report, JSON report, two CSVs, and Purdue-Model SVG diagrams. |
| **Safety** | `--offline` hard-lock means the tool never leaks DNS / HTTPS for unknown-source pcaps. tshark always invoked with `-n`. |
| **Performance** | Single combined tshark pass per file across all protocol checks (N protocols × M files becomes 1 × M). Calibrated per-step ETAs. Atomic session checkpointing — resume from any boundary. |
| **Scale** | Handles flood-scale captures with 1M+ spoofed source IPs via per-finding emission caps + rollup findings. |
| **Form** | Single Python file. No Flask, no Django, no databases. Run with `python3 otscope.py`. |

---

## Quick Start

> **Field deployment:** `otscope.py` is fully self-provisioning — drop the single file (plus your capture files) into any folder and run it. It creates `pcaps\`, `output\`, `requirements.txt`, and a `README_FIRST.txt` quick-start on first run, and moves any loose `.pcap` / `.pcapng` files sitting next to the script into `pcaps\` automatically.

```bash
# Install Python dependencies (all platforms)
pip install -r requirements.txt

# tshark is a separate system install:
winget install WiresharkFoundation.Wireshark   # Windows (winget)
                                               # or download from wireshark.org/download.html
sudo apt install tshark                        # Debian / Ubuntu / Kali
brew install wireshark                         # macOS
```

> **Windows note:** Use `python` in place of `python3` in all commands below.
> On Linux/macOS, `python` may point to Python 2 — use `python3` to be safe.

```bash
# Non-interactive: scan a folder of pcaps, no prompts, auto-generate Word report
python3 otscope.py --scan /path/to/pcaps/

# Non-interactive with metadata and both report formats
python3 otscope.py --scan /path/to/pcaps/ --assessor "Ryan" --site "Plant-A" --format both

# Run interactively (prompts for folder, name, discovery questions)
python3 otscope.py

# Start interactive session with a specific pcap (pre-loads folder, still asks questions)
python3 otscope.py --pcap /path/to/capture.pcap

# Resume a saved session
python3 otscope.py --session captures/<site>.otpa_session

# Generate a report from an existing session, no re-analysis
python3 otscope.py --report-only captures/<site>.otpa_session

# Hard-lock outbound network (recommended for unknown-source pcaps)
python3 otscope.py --offline
```

On startup in interactive mode, OTscope prints a banner, the network-safety status, and prompts for: NEW session, RESUME, or ADD pcaps to an existing session. Use `--scan` to skip all prompts entirely.

---

## Detection Coverage

OT/ICS protocols, attack patterns, and hygiene anomalies are detected in a single combined streaming pass.

### OT/ICS Protocols

- **Modbus TCP** — writes, register scanning, exception bursts, polling-burst timing anomalies, Unit ID 0, identical-response replay timing, single-register repetitive polling, **register value anomaly** (sudden large jumps indicating spoofed/injected responses).
- **DNP3** — Direct Operate, Freeze, Disable Spontaneous, Cold/Warm Restart, broadcast, traffic without Secure Authentication.
- **BACnet/IP** — WriteProperty, BBMD/forwarded NPDU, broadcast storms.
- **IEC 61850 / GOOSE / MMS** — control operations, GOOSE state-number anomalies, MMS without TLS.
- **IEC 60870-5-104** — cleartext substation control.
- **MQTT** — anonymous CONNECT, control-keyword topics, wildcard SUBSCRIBE, retained-control messages.
- **OPC-UA** — SecurityMode None, Browse/Read enumeration, Write service calls.
- **EtherNet/IP / CIP** — write services, reset, PCCC, Write Tag Fragmented.
- **Siemens S7 / PROFINET** — PLC Stop/Start, Write Variable, block download/upload, DCP-Set.
- **Omron FINS (TCP/UDP 9600)** — presence, cleartext/no-auth, write/control command indicators.
- **GE SRTP (TCP 18245)** — presence, cleartext/no-auth, write indicators (GE PACSystems RX3i / 90-30).
- **Schneider UMAS (TCP 1024)** — presence, cleartext/no-auth, write/stop/download indicators (Modicon M340/Premium).
- **Mitsubishi MELSEC SLMP (TCP 5007)** — presence, cleartext/no-auth, remote run/stop/write indicators.
- **OSIsoft PI Server (TCP 9001)** — historian traffic presence, potential data exfiltration.
- **Ignition Gateway (TCP 4592)** — OPC-UA without TLS indicators.
- **Node-RED (TCP 1880)** — unauthenticated dashboard access and flow deployment events.
- **Physical Security** — RTSP/ONVIF cleartext, ONVIF discovery storms.
- **IoT wireless** — Zigbee / IEEE 802.15.4 (presence, unencrypted frames, ZCL write/control), CoAP (cleartext presence, DTLS, PUT/POST/DELETE writes), Z-Wave (presence).
- **Audio/Video streaming** — RTP flows classified audio vs. video (payload type + bitrate), SIP/VoIP call signaling, active RTSP stream requests, MPEG-TS distribution (IPTV/CCTV multicast), RTMP, sustained multicast UDP, unsignaled media-like UDP heuristic, GigE Vision machine-vision cameras (UDP 3956), CCTV DVR/NVR vendor ports (Hikvision 8000 / Dahua 37777).

### Attack and Anomaly Patterns

- **Adversary-in-the-Middle (ARP MITM)** — multi-MAC-per-IP, eth/ARP MAC mismatch, gratuitous-ARP burst. Combined-signal MITM correlation escalates to INTRUSION when subsequent OT writes appear in the same subnet.
- **Beaconing / C2** — low-jitter periodic flows.
- **DNS abuse** — DGA-like NXDOMAIN bursts, long names, large TXT, multi-resolver.
- **TLS weakness** — SSLv2/3, TLS 1.0/1.1, RC4/3DES/DES/NULL/MD5/EXPORT ciphers, self-signed, expired.
- **SNMP** — walks (≥50 GETNEXT), SET ops, plaintext communities.
- **Reconnaissance** — ICMP sweeps, port-scan unreachable bursts, register scanning, suspicious tool User-Agents (Mimikatz, Cobalt Strike, sqlmap, masscan, nmap), recon-then-write correlation.
- **Suppression attacks** — DNP3 disable-spontaneous, cold/warm restart, alarm silencing.
- **Brute-force** — auth-failure bursts on FTP/Telnet/SSH/HTTP.
- **Boundary violations** — IT/OT crossings, dual-zone bridging, public-IP exposure of OT devices.
- **IT-noise on OT segments** — mDNS, LLMNR, NBNS, SSDP from OT subnets.
- **DHCP rogue server** detection.
- **Capture integrity** — large inter-packet gaps, no-NTP networks, multi-resolver NTP.
- **EOL services** — IIS 5/6, Apache 1.x/2.0, OpenSSL 0.x, Boa, GoAhead, etc.
- **Cleartext credential extraction** — FTP, Telnet, HTTP Basic, HTTP Form, SNMP, MQTT, POP3, IMAP.
- **Baseline diff** — new device, new flow, new protocol, new port relative to a known-good snapshot.

Every finding auto-attaches MITRE ATT&CK for ICS technique IDs and CISA / NIST / IEC / vendor advisory references.

---

## Output Artifacts

Each session writes up to six artifacts alongside the pcap files:

| Artifact | Filename Pattern | Purpose |
|---|---|---|
| Word report | `OT_PCAP_Analysis_<site>_<YYYYMMDD>.docx` | Human-readable deliverable. TOC, Executive Summary, findings grouped by category, Timeline / Attack Chain, MITRE coverage, Top Riskiest Devices, Device Inventory, Wireshark Investigation Appendix. |
| JSON report | `OT_PCAP_Analysis_<site>_<YYYYMMDD>.json` | SIEM / ticketing / scripting input. |
| Device Inventory CSV | `OT_Device_Inventory_<site>_<YYYYMMDD>.csv` | Full device list (Word table is capped at top 200 by traffic). |
| Flow Allowlist CSV | `OT_Flow_Allowlist_<site>_<YYYYMMDD>.csv` | Observed (src, dst, dport, proto) tuples for asset-owner segmentation review. |
| Purdue Summary SVG | `OTscope_Purdue_Summary_<site>_<YYYYMMDD>.svg` | Visual layered architecture diagram (always written; readable at any network size). |
| Purdue Detail SVG | `OTscope_Purdue_Detail_<site>_<YYYYMMDD>.svg` | Per-device visual diagram with inter-device flow arrows (only for ≤50 devices). |

Findings include `@<epoch>` jump tags so you can paste any evidence line's timestamp into Wireshark as `frame.time_epoch == <value>` and land on the exact frame.

---

## Network Safety

OTscope is **read-only on pcap data** and never connects to any IP address found inside a capture. The only outbound calls are optional public-IP enrichment (PTR + RDAP) for non-RFC1918 destinations talked-to by OT-classed devices.

For unknown-source pcaps:

- Pass `--offline` — hard lock that suppresses **all** PTR/RDAP/DNS calls regardless of how the discovery questionnaire is answered.
- Or answer "yes" to the air-gapped question in the discovery questionnaire.

tshark is invoked with `-n` on every call, so it never resolves any IP, MAC, or port through your local DNS / OUI / services files. The startup banner prints the current safety state.

---

## Documentation

The complete operator manual is **[OTscope_User_Guide.md](./otscope/docs/OTscope_User_Guide.md)**. It covers:

- Installation, dependencies, first-run walkthrough
- All operating modes and CLI flags
- Network-safety contract
- The 6-question discovery questionnaire
- Five-phase analysis pipeline (calibration, streaming, per-category, correlation, scoring)
- Word report structure and severity color coding
- Purdue-Model SVG diagrams (Summary always, Detail for ≤50 devices)
- Wireshark investigation workflow with `@<epoch>` tags and Observation Windows
- Baseline diff (save / compare known-good snapshot)
- Performance and scale features (per-step ETA, atomic checkpointing, flood-scale emission caps, subprocess hygiene)
- Triage order for reading reports
- Known limitations
- **Version History** — running changelog, newest at top

---

## Project Structure

```
otscope/                            # repo root
├── README.md                       # this file
├── CLAUDE.md                       # Claude Code agent guide
├── AGENTS.md                       # Codex agent guide
├── .gitignore
└── otscope/                        # tool directory
    ├── src/
    │   └── otscope.py              # the tool (single-file Python program)
    ├── docs/
    │   └── OTscope_User_Guide.md   # complete operator manual
    ├── requirements.txt
    ├── LICENSE.txt
    ├── README.md                   # mirrored quick-start (same as repo root)
    ├── pcaps/                      # gitignored — put your pcap subfolders here
    │   └── <site-name>/
    │       └── *.pcap / *.pcapng
    └── output/                     # gitignored — generated artifacts land here
        ├── <session>.otpa_session
        ├── OT_PCAP_Analysis_*.docx
        ├── OT_PCAP_Analysis_*.json
        ├── OT_Device_Inventory_*.csv
        ├── OT_Flow_Allowlist_*.csv
        ├── OTscope_Purdue_Summary_*.svg
        └── OTscope_Purdue_Detail_*.svg
```

---

## Requirements

- **Python 3.8+** — type hints, walrus operator, dataclasses, `from __future__ import annotations`.
- **tshark 4.6.4+** — uses display-filter set-membership syntax (`tcp.port in {…}`).
- **python-docx** — installed via `requirements.txt`.

That's the entire dependency surface. SVG diagrams use only the standard library.

---

## License and Authorship

© 2026 Ryan Lyford. All rights reserved.

OTscope is **source-available** under a proprietary license. You may run it for OT/ICS security-assessment work within your own organization (including for paid client engagements where you are the assessor) and share the resulting reports / CSVs / SVG diagrams with your engagement clients. Public redistribution, forking, SaaS hosting, and modification for redistribution require prior written permission. Authorship attribution must be preserved in all copies.

See **[LICENSE.txt](./LICENSE.txt)** for the complete terms.

For commercial licensing (redistribution, hosting, OEM, white-label), contact Ryan Lyford with "OTscope licensing" in the subject line.

---

## Contributing / Issues

For issues, suggestions, or feature requests, open a GitHub issue with:

- OTscope version (`python3 otscope.py --version`)
- tshark version (`tshark -v | head -1`)
- Python version (`python3 --version`)
- Operating system
- Brief description, ideally with a representative pcap snippet (or anonymized excerpt) if relevant

Pull requests are welcome. Please ensure new detection logic includes:

- A dedicated finding title that doesn't collide with existing ones.
- An entry in the relevant `MITRE_ICS_MAP` and `ADVISORY_MAP` tables.
- A Wireshark Investigation guide entry for the new finding category in `_WIRESHARK_GUIDE`.
- An update to the Version History in `OTscope_User_Guide.md`.
