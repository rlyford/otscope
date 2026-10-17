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
| **Input** | Multiple `.pcap` / `.pcapng` / `.cap` files (gzip-compressed is fine) merged into one unified session. Incremental — add new files later without re-analyzing the old ones. |
| **Output** | Word report, JSON report, two CSVs, and Purdue-Model SVG diagrams. |
| **Safety** | `--offline` hard-lock means the tool never leaks DNS / HTTPS for unknown-source pcaps. tshark always invoked with `-n`. |
| **Performance** | Single combined tshark pass per file across all protocol checks (N protocols × M files becomes 1 × M). Calibrated per-step ETAs. Atomic session checkpointing — resume from any boundary. |
| **Scale** | Handles flood-scale captures with 1M+ spoofed source IPs via per-finding emission caps + rollup findings. |
| **Form** | Single Python file. No Flask, no Django, no databases. Run with `python3 otscope.py`. |

---

## Quick Start

> **Field deployment:** `otscope.py` is fully self-provisioning — drop the single file (plus your capture files) into any folder and run it. It creates `pcaps\`, `output\`, `requirements.txt`, and a `README_FIRST.txt` quick-start on first run, and moves any loose capture files sitting next to the script into `pcaps\` automatically.

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
python3 otscope.py --session output/<site>_<YYYYMMDD>.otpa_session

# Generate a report from an existing session, no re-analysis
python3 otscope.py --report-only output/<site>_<YYYYMMDD>.otpa_session

# Hard-lock outbound network (recommended for unknown-source pcaps)
python3 otscope.py --offline
```

On startup in interactive mode, OTscope prints a banner, the network-safety status, and prompts for: NEW session, RESUME, or ADD pcaps to an existing session. Use `--scan` to skip all prompts entirely.

---

## Detection Coverage

OT/ICS protocols, attack patterns, and hygiene anomalies are detected in a single combined streaming pass. Every flow is oriented client → server from the TCP handshake (or well-known service ports), detectors read structured tshark fields rather than the Info column, and write/control detectors fire only on requests.

### OT/ICS Protocols

- **Modbus TCP** — write requests by function code, Unit ID 0 broadcast writes, register-map sweeps, exception bursts, polling-burst anomalies, hammer-rate polling, **duplicate or unsolicited responses** (replay/injection, matched by transaction ID), **register value anomaly** (sudden large jumps indicating spoofed/injected values), Read Device ID.
- **DNP3** — Direct Operate, Freeze, Disable Spontaneous, Cold/Warm Restart, broadcast addresses, traffic without Secure Authentication.
- **BACnet/IP** — WriteProperty, BBMD/forwarded NPDU, broadcast storms.
- **IEC 61850 / GOOSE / MMS** — control operations, GOOSE state-number anomalies, MMS without TLS.
- **IEC 60870-5-104** — cleartext sessions, control ASDUs, general interrogation.
- **MQTT** — CONNECT without credentials, cleartext brokers, readable traffic on 8883, control-keyword topics, wildcard SUBSCRIBE, retained-control messages, reconnect loops per client ID.
- **OPC-UA** — SecureChannels with SecurityPolicy None or Sign-only mode, Browse enumeration, Write requests.
- **EtherNet/IP / CIP** — List Identity discovery, Forward Open, write services, reset, logic transfer, PCCC.
- **Siemens S7 / PROFINET** — PLC Stop/Start, Write Variable, block download/upload, Read SZL, DCP Identify All / Set.
- **Omron FINS (TCP/UDP 9600)** — presence, cleartext/no-auth, write/control command indicators.
- **GE SRTP (TCP 18245)** — presence, cleartext/no-auth, write indicators (GE PACSystems RX3i / 90-30).
- **Schneider UMAS (Modbus function code 90)** — engineering sessions to Modicon M340/M580/Premium/Quantum PLCs.
- **Mitsubishi MELSEC SLMP (TCP 5007)** — presence, cleartext/no-auth, remote run/stop/write indicators.
- **AVEVA / OSIsoft PI (TCP 5450 / 5457)** — historian traffic presence.
- **Ignition Gateway (TCP 62541 / 8060)** — presence, gateway-network traffic without TLS.
- **Node-RED (TCP 1880)** — editor/admin API reachable without authentication, flow deployment events.
- **Physical Security** — RTSP streams served without an authentication challenge, OSDP without Secure Channel.
- **IoT wireless** — Zigbee / IEEE 802.15.4 (presence, unencrypted frames, ZCL write/control), CoAP (cleartext presence, DTLS, PUT/POST/DELETE writes), Z-Wave (presence).
- **Audio/Video streaming** — RTP flows classified audio vs. video (payload type + bitrate), SIP/VoIP call signaling, active RTSP stream requests, MPEG-TS distribution (IPTV/CCTV multicast), RTMP, sustained multicast UDP, unsignaled media-like UDP heuristic, GigE Vision machine-vision cameras (UDP 3956), CCTV DVR/NVR vendor ports (Hikvision 8000 / Dahua 37777).

### Attack and Anomaly Patterns

- **Adversary-in-the-Middle (ARP MITM)** — for every IP claimed by more than one MAC, decides which MAC is the owner and which is the impostor, then reports the impostor's MAC and own IP, the impersonated host, the poisoned hosts, the attack window, and how much of the victim's traffic passed through it. INTRUSION when interception is confirmed.
- **Beaconing / C2** — low-jitter periodic client → server exchanges (OT polling, DNS, NTP, SNMP, syslog, and discovery traffic excluded).
- **DNS abuse** — DGA-like NXDOMAIN bursts, long and high-entropy names, large TXT, multi-resolver.
- **TLS weakness** — the version and cipher suite each server actually selected (SSLv2/3, TLS 1.0/1.1; NULL/anon/EXPORT/RC4/DES/3DES/MD5 suites), certificates rejected by the peer, expired certificates, JA3 fingerprints of known offensive tools.
- **SNMP** — walks (≥50 GetNext/GetBulk), SET ops, SNMPv1/v2c community strings.
- **Reconnaissance** — broad-and-shallow OT port scans, ICMP sweeps, port-scan unreachable bursts, register-map sweeps, SNMP walks, suspicious tool User-Agents (Mimikatz, Cobalt Strike, sqlmap, masscan, nmap), recon-then-write correlation. Routine engineering discovery (IEC 104 interrogation, CIP List Identity, S7 Read SZL) is reported but not treated as reconnaissance.
- **Denial of service** — correlation of unanswered SYNs, aborted connections, and hammer-rate requests between one client and one server.
- **Suppression attacks** — DNP3 disable-spontaneous, cold/warm restart, alarm silencing.
- **Brute-force** — authentication-failure bursts read from server replies (FTP 530, HTTP 401, Telnet login failures).
- **Boundary violations** — IT/OT crossings, dual-zone bridging, public-IP exposure of OT devices.
- **IT-noise on OT segments** — mDNS, LLMNR, NetBIOS, SSDP, WS-Discovery from subnets that hold OT devices.
- **DHCP rogue server** detection.
- **Capture integrity** — large inter-packet gaps, no-NTP networks, multi-resolver NTP, truncated captures (analyzed and flagged).
- **EOL services** — IIS 5/6, Apache 1.x/2.0, OpenSSL 0.x, Boa, GoAhead, etc.
- **Cleartext credential extraction** — FTP, Telnet, HTTP Basic, HTTP Form, SNMP, MQTT, POP3, IMAP.
- **Baseline diff** — new device, new flow, new protocol, new port relative to a known-good snapshot.

Every finding auto-attaches MITRE ATT&CK for ICS technique IDs and CISA / NIST / IEC / vendor advisory references.

---

## Output Artifacts

Each session writes up to six artifacts to `output\` next to `otscope.py` (or the pcap folder if `output\` cannot be written):

| Artifact | Filename Pattern | Purpose |
|---|---|---|
| Word report | `OT_PCAP_Analysis_<site>_<YYYYMMDD>.docx` | Human-readable deliverable. Executive Summary, Priority Findings by category, Suggested Controls, Network Interpretation, MITRE coverage, Device Inventory and Flow Allowlist summaries, Wireshark guides (Appendix A); timeline and full evidence with `--technical-appendix` (Appendix B). |
| JSON report | `OT_PCAP_Analysis_<site>_<YYYYMMDD>.json` | SIEM / ticketing / scripting input. |
| Device Inventory CSV | `OT_Device_Inventory_<site>_<YYYYMMDD>.csv` | Full host list with MACs, roles, services used and answered, folded IPv6 addresses, and observations such as "impersonated by MAC …" (the Word report shows the top 15 by traffic). |
| Flow Allowlist CSV | `OT_Flow_Allowlist_<site>_<YYYYMMDD>.csv` | Observed (client, server, service port, protocol) tuples for asset-owner segmentation review. |
| Purdue Summary SVG | `OTscope_Purdue_Summary_<site>_<YYYYMMDD>.svg` | Visual layered architecture diagram (always written; readable at any network size). |
| Purdue Detail SVG | `OTscope_Purdue_Detail_<site>_<YYYYMMDD>.svg` | Per-device visual diagram with a top-connections panel (only for ≤50 devices). |

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

The complete operator manual is **[OTscope_User_Guide.md](/otscope/docs/OTscope_User_Guide.md)**. It covers:

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
├── build_release.py                # packages dist/OTscope_v<VERSION>.zip
├── .gitignore
├── tests/                          # detection regression suite (stdlib only)
│   ├── pcapgen.py                  # synthetic pcap writer
│   ├── scenarios.py                # benign and attack scenarios
│   └── run_regression.py           # runs otscope --scan on each and checks the output
└── otscope/                        # tool directory
    ├── src/
    │   ├── otscope.py              # the tool (single-file Python program)
    │   ├── README.txt              # field quick-start shipped in the release zip
    │   ├── pcaps/                  # contents gitignored — drop captures (or site subfolders) here
    │   └── output/                 # contents gitignored — generated artifacts land here
    │       ├── <site>_<date>.otpa_session
    │       ├── OT_PCAP_Analysis_*.docx / *.json
    │       ├── OT_Device_Inventory_*.csv
    │       ├── OT_Flow_Allowlist_*.csv
    │       └── OTscope_Purdue_Summary_*.svg / OTscope_Purdue_Detail_*.svg
    ├── docs/
    │   └── OTscope_User_Guide.md   # complete operator manual
    ├── requirements.txt
    ├── LICENSE.txt
    └── README.md                   # mirrored quick-start (same as repo root)
```

---

## Requirements

- **Python 3.8+** — tested with Python 3.14.
- **tshark 4.6.4+** — also supplies the offline vendor (OUI) and TLS cipher-name tables.
- **python-docx** — installed via `requirements.txt`.

That's the entire dependency surface. SVG diagrams use only the standard library.

---

## License and Authorship

© 2026 Ryan Lyford. All rights reserved.

OTscope is **source-available** under a proprietary license. You may run it for OT/ICS security-assessment work within your own organization (including for paid client engagements where you are the assessor) and share the resulting reports / CSVs / SVG diagrams with your engagement clients. Public redistribution, forking, SaaS hosting, and modification for redistribution require prior written permission. Authorship attribution must be preserved in all copies.

See **[LICENSE.txt](/otscope/LICENSE.txt)** for the complete terms.

For commercial licensing (redistribution, hosting, OEM, white-label), contact Ryan Lyford with "OTscope licensing" in the subject line.

---

## Contributing / Issues

For issues, suggestions, or feature requests, open a GitHub issue with:

- OTscope version (`python3 otscope.py --version`)
- tshark version (`tshark -v | head -1`)
- Python version (`python3 --version`)
- Operating system
- Brief description, ideally with a representative pcap snippet (or anonymized excerpt) if relevant

Pull requests are welcome. Run the regression suite before submitting:

```bash
python tests/run_regression.py
```

Please ensure new detection logic includes:

- A dedicated finding title that doesn't collide with existing ones.
- A scenario in `tests/scenarios.py` with a check in `tests/run_regression.py` (benign traffic that must stay quiet, and the behavior that must fire).
- An entry in the relevant `MITRE_ICS_MAP` and `ADVISORY_MAP` tables.
- A Wireshark Investigation guide entry for the new finding category in `_WIRESHARK_GUIDE`.
- An update to the Version History in `OTscope_User_Guide.md`.
