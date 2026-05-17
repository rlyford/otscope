# OTscope

**User Guide**

Interactive multi-pcap OT/ICS traffic analysis with session persistence, role inference, attack-chain correlation, MITRE ATT&CK for ICS mapping, Wireshark investigation guidance, Purdue-Model architecture diagrams, and machine-readable artifacts.

> **Version 2.6.0**  ·  May 2026
> Authored by Ryan Lyford  ·  © 2026 Ryan Lyford. All rights reserved.

---

## Table of Contents

1. [What OTscope Is](#1-what-otscope-is)
2. [Installation and Dependencies](#2-installation-and-dependencies)
3. [Operating Modes and CLI](#3-operating-modes-and-cli)
4. [Network Safety (Important for Unknown-Source Pcaps)](#4-network-safety-important-for-unknown-source-pcaps)
5. [Environment Discovery Questions](#5-environment-discovery-questions)
6. [Analysis Pipeline](#6-analysis-pipeline)
7. [Reports and Artifacts](#7-reports-and-artifacts)
8. [Wireshark Investigation Workflow](#8-wireshark-investigation-workflow)
9. [Baseline Diff (Known-Good Snapshot)](#9-baseline-diff-known-good-snapshot)
10. [Performance and Scale](#10-performance-and-scale)
11. [Files OTscope Creates](#11-files-otscope-creates)
12. [Reading the Report — Triage Order](#12-reading-the-report--triage-order)
13. [Known Limitations](#13-known-limitations)
14. [Version History](#14-version-history)

---

## 1. What OTscope Is

OTscope is a single-file Python program for offline analysis of OT/ICS packet captures (`.pcap` / `.pcapng`). It reads pcaps with tshark, builds a unified device and flow inventory across one or many capture files, runs a battery of vulnerability and intrusion-detection checks, and produces a Word report plus several machine-readable artifacts (JSON, two CSVs, and Purdue-Model SVG diagrams).

It is designed for the case where you receive a pile of pcap files from a site you don't fully know and need to answer: *what's on this network, is anything obviously misconfigured, and is anyone attacking it?*

### 1.1 Two Primary Goals

- **Vulnerability detection** — unauthenticated protocols, cleartext communications, insecure configurations, exposed management interfaces, IT/OT boundary violations, weak TLS, EOL services, segmentation gaps.
- **Intrusion detection** — reconnaissance, unauthorized writes, polling-burst anomalies, lateral movement, beaconing/C2, DNS abuse, ARP spoofing / Adversary-in-the-Middle, brute-force, replay attacks, attacker tool User-Agents, suppression-attack signatures (DNP3 disable spontaneous, cold/warm restart), and recon-then-write sequences.

---

## 2. Installation and Dependencies

| Component | Notes |
| --- | --- |
| Python 3.8+ | Standard on Kali / most Linux distros and macOS. Windows: download from python.org — check "Add Python to PATH" during install. |
| tshark 4.6.4+ | Installed as part of Wireshark. See install commands below. |
| python-docx | `pip install python-docx` — Word report writer. |

`scapy` and `capinfos` are optional. SVG diagrams require no additional dependencies — pure stdlib.

**Install dependencies:**

```bash
# Python packages (all platforms)
pip install -r requirements.txt

# tshark — installed separately as a system package:
winget install WiresharkFoundation.Wireshark   # Windows (winget)
                                               # or download from wireshark.org/download.html
sudo apt install tshark                        # Debian / Ubuntu / Kali
brew install wireshark                         # macOS
```

> **Windows note:** The standard Wireshark installer for Windows includes tshark. During installation, ensure the "TShark" component is selected (it is included by default). After install, you may need to add the Wireshark folder (e.g. `C:\Program Files\Wireshark`) to your system PATH, or restart your terminal.

> **tshark build note:** The standard Wireshark installer includes dissectors for all supported protocols. Z-Wave detection specifically requires a tshark build that includes the `zwave` dissector — if it is absent, OTscope prints an informational message and skips Z-Wave detection gracefully. All other protocols (including Zigbee/IEEE 802.15.4 and CoAP) work with any standard tshark 4.6.4+ install.

### 2.1 Field Deployment (Standalone)

When distributing OTscope as a standalone file (without the full repository), the recommended layout is:

```
OTscope\
    otscope.py
    requirements.txt
    README.txt          ← plain-text quick-start
    pcaps\              ← drop capture files here
    output\             ← reports appear here
```

On first run, OTscope automatically creates `pcaps\` and `output\` next to the script if they do not exist. If `pcaps\` is empty, the startup message will prompt you to drop capture files there before proceeding.

Use `build_release.py` (at the repo root) to package this layout into a zip:

```bash
python build_release.py           # writes dist/OTscope_v<VERSION>.zip
python build_release.py --dry-run # preview file list without writing
```

### 2.2 First Run

```bash
# Windows (PowerShell or Command Prompt)
python otscope.py

# Linux / macOS
python3 otscope.py
```

> **Note — `python` vs `python3`:** On Windows, the Python launcher is typically on the PATH as `python`. On Linux and macOS, `python` may point to Python 2, so `python3` is the safe default. All examples below use `python3`; substitute `python` when running in PowerShell or Command Prompt.

On startup OTscope prints a banner, the network-safety status (see §4), and prompts for: NEW session, RESUME existing session, or ADD pcaps to an existing session `[N/R/A]`.

---

## 3. Operating Modes and CLI

| Mode | Invocation |
| --- | --- |
| Interactive (default) | `python3 otscope.py` |
| Start with a specific pcap | `python3 otscope.py --pcap /path/file.pcap` |
| **Non-interactive scan (folder)** | `python3 otscope.py --scan /path/to/pcaps/` |
| **Non-interactive scan (single file)** | `python3 otscope.py --scan /path/file.pcap` |
| Resume a saved session | `python3 otscope.py --session /path/session.otpa_session` |
| Generate a report from a saved session, no analysis | `python3 otscope.py --report-only /path/session.otpa_session` |
| Save current session as a baseline | `python3 otscope.py --session <file> --save-baseline /path/baseline.otpa_baseline` |
| Compare current session to a baseline | `python3 otscope.py --session <file> --compare-baseline /path/baseline.otpa_baseline` |
| Hard-lock all outbound network calls | `python3 otscope.py --offline` |
| Print version | `python3 otscope.py --version` |

### 3.2 Non-Interactive Scan Mode (`--scan`)

`--scan <path>` accepts either a single pcap file or a folder (searched recursively). It skips all prompts — discovery questions use empty/unknown defaults — runs the full analysis pipeline, auto-generates a report, and exits. No keyboard input required at any point.

Optional flags that combine with `--scan`:

| Flag | Purpose | Default when omitted |
| --- | --- | --- |
| `--assessor <name>` | Assessor name embedded in the report | `OTscope` |
| `--site <name>` | Site name used in the report and filename slug | Folder name |
| `--env <type>` | Environment type hint (e.g. `manufacturing`, `power`, `water`, `building-automation`, `scada`) | *(empty)* |
| `--format word\|json\|both` | Report format(s) to generate | `word` |
| `--technical-appendix` | Append Appendix B (raw evidence lines + per-pcap breakdown) to the Word report | *(omitted — concise report only)* |
| `--offline` | Hard-lock all outbound network calls | *(unlocked)* |

Examples:

```bash
# Minimal — scan all pcaps in a folder, default everything, Word report
python3 otscope.py --scan /captures/site-a/

# Single pcap with metadata
python3 otscope.py --scan /captures/site-a/capture.pcap --assessor "Ryan" --site "Plant-A"

# Folder scan, both Word and JSON, offline, environment hint (Linux/macOS — backslash continuation)
python3 otscope.py --scan /captures/site-a/ --assessor "Ryan" --site "Plant-A" \
    --env manufacturing --format both --offline

# Same command on Windows PowerShell (backtick continuation, forward slashes or backslashes both work)
python otscope.py --scan C:\captures\site-a\ --assessor "Ryan" --site "Plant-A" `
    --env manufacturing --format both --offline
```

`--assessor` and `--site` also work in interactive mode (`--pcap` or no-arg) to pre-fill those prompts without skipping the rest of the questionnaire. `--env` pre-fills the environment-type discovery question in interactive mode.

### 3.1 Session Lifecycle

| Phase | What Happens |
| --- | --- |
| New | Pick a folder of pcaps, name the session, answer environment-discovery questions, run analysis. |
| Active | Streaming + per-protocol passes generate findings; per-step ETAs print as you go. |
| Resume | Reload an `.otpa_session` file, see findings counts, choose: Re-run / Add / Generate report / Review / Exit. |
| Add | Process only NEW pcaps; cross-file correlation re-runs across the full set. |
| Report | Word + JSON + CSV addenda + Purdue SVG diagrams regenerated from current session state. |

---

## 4. Network Safety (Important for Unknown-Source Pcaps)

OTscope is read-only on pcap data — it never connects to any IP address found inside a capture. It does, however, optionally enrich public IPs with PTR + RDAP lookups. When you receive a pcap from an untrusted source, those lookups can leave a small DNS / HTTPS footprint that could be attributed to your machine. There are two ways to suppress this:

- Answer 'yes' to the air-gapped question in the discovery questionnaire.
- Pass `--offline` on the command line — a hard lock that overrides the questionnaire.

tshark itself is invoked with `-n` on every call so it never resolves any IP, MAC, or port through your DNS / OUI / services files. The startup banner shows current state (LOCKED or unlocked). When LOCKED, no PTR, RDAP, or hostname resolution can occur regardless of how the discovery questionnaire is answered.

### 4.1 What OTscope Does NOT Do

- Connect to any IP found in the pcap (Modbus, OPC-UA, web servers, anything).
- Send any probe packets of any kind to any host.
- Upload the pcap, the session, or the report anywhere.
- Resolve hostnames mentioned inside the capture's payload.
- Phone home to the author or any telemetry service.

---

## 5. Environment Discovery Questions

Asked once at session start. All are optional — press Enter to skip a question, or type `S` once to skip the rest.

| Question | Effect on analysis |
| --- | --- |
| **Environment type** | Calibrates severity for environment-specific protocols. `power` / `electrical` / `substation` escalates DNP3 no-Secure-Auth to CRITICAL and adds absence checks for IEC 61850 and IEC 104. `physical` / `camera` adds absence checks for RTSP/ONVIF/OSDP. |
| **Expected OT protocols** | Enables absence-of-expected-traffic findings for any protocol you list. If a declared protocol has no traffic in the captures, OTscope adds a MEDIUM finding. See keyword list below. |
| **Known HMI / EWS IPs** | Any IP listed here is pinned to role "HMI / Engineering Workstation" during device-role inference, overriding the heuristic classifier. |
| **Air-gapped (yes/no)** | Suppresses all outbound PTR and RDAP lookups (equivalent to `--offline`). Also escalates new-device baseline-diff findings to CRITICAL. |
| **Baseline file** | Path to a `.otpa_baseline` file — enables diff detection (new device, new flow, new protocol, new port). |
| **Save as baseline** | After analysis, save this session's device/flow set as a new known-good baseline. |

### 5.1 Expected Protocols — Keyword Reference

Type any of these keywords (comma-separated) to enable absence detection for that protocol:

| Keyword(s) | Protocol |
| --- | --- |
| `modbus` | Modbus TCP (TCP 502) |
| `bacnet` | BACnet/IP (UDP 47808) |
| `dnp3` | DNP3 (TCP/UDP 20000) |
| `iec61850`, `goose`, `mms` | IEC 61850 / GOOSE / MMS |
| `iec104`, `iec60870` | IEC 60870-5-104 (TCP 2404) |
| `mqtt` | MQTT (TCP 1883 / 8883) |
| `opcua`, `opc-ua`, `opc` | OPC-UA (TCP 4840 / 4843) |
| `enip`, `cip`, `ethernet/ip` | EtherNet/IP / CIP (TCP 44818) |
| `s7`, `profinet`, `siemens` | Siemens S7 / PROFINET |
| `omron`, `fins` | Omron FINS (TCP/UDP 9600) |
| `srtp`, `ge` | GE SRTP (TCP 18245) |
| `umas`, `schneider`, `modicon` | Schneider UMAS (TCP 1024) |
| `melsec`, `mitsubishi`, `slmp` | Mitsubishi MELSEC SLMP (TCP 5007) |
| `historian`, `osisoft` | OSIsoft PI Server (TCP 9001) |
| `ignition` | Ignition Gateway (TCP 4592) |
| `nodered`, `node-red` | Node-RED (TCP 1880) |
| `physical`, `rtsp`, `osdp`, `onvif`, `camera` | Physical Security (RTSP / ONVIF / OSDP) |
| `zigbee`, `zbee`, `ieee 802.15.4` | Zigbee / IEEE 802.15.4 wireless |
| `coap` | CoAP (UDP 5683 cleartext / 5684 DTLS) |
| `zwave`, `z-wave` | Z-Wave wireless |

Example entry: `modbus, dnp3, historian, ignition`

---

## 6. Analysis Pipeline

After the questionnaire, OTscope runs a calibrated pipeline. The first pass measures bytes-per-second on YOUR machine; every subsequent step prints an ETA based on that measurement so a long run is predictable.

### 6.1 Phase 1 — Capture Inventory

Always runs. One full tshark pass per pcap that builds the unified device and flow inventory. Outputs total packets, duplicate count, time range, unified device count (after low-confidence pruning), top talker pairs, and per-machine bytes-per-second calibration for ETAs.

### 6.2 Phase 2 — Streaming Protocol Pass

ONE combined tshark read per pcap with a single display filter that covers all protocols and hygiene signals. Per-protocol accumulators are fed in parallel, then findings are emitted post-loop. This is the single biggest performance win — N protocols × M files becomes 1 × M.

- Modbus TCP — writes, scans, exceptions, timing burst, unit-id-0, replay, repetitive single-register polling, register value anomaly (sudden large jumps indicating spoofed/injected responses).
- BACnet/IP — Who-Is/I-Am, WriteProperty, BBMD/forwarded NPDU.
- DNP3 — Direct Operate, Freeze, Disable Spontaneous, Cold/Warm Restart, broadcast, no-Secure-Authentication.
- IEC 61850 / GOOSE / MMS — control operations, GOOSE state-number anomalies, MMS without TLS.
- IEC 60870-5-104 — cleartext substation control protocol.
- MQTT — anonymous CONNECT, control-keyword topics, wildcard SUBSCRIBE, retained-control messages.
- OPC-UA — SecurityMode None, Browse/Read enumeration, Write service calls.
- EtherNet/IP / CIP — write services, reset, PCCC, Write Tag Fragmented.
- Siemens S7 / PROFINET — PLC Stop/Start, Write Variable, block download/upload, DCP-Set.
- Omron FINS (TCP/UDP 9600) — presence, cleartext/no-auth, write/control command indicators.
- GE SRTP (TCP 18245) — presence, cleartext/no-auth, write/control indicators (GE PACSystems).
- Schneider UMAS (TCP 1024) — presence, cleartext/no-auth, write/stop/download indicators (Modicon M340/Premium).
- Mitsubishi MELSEC SLMP (TCP 5007) — presence, cleartext/no-auth, remote run/stop/write indicators.
- OSIsoft PI Server (TCP 9001) — historian traffic presence, potential data exfiltration.
- Ignition Gateway (TCP 4592) — OPC-UA without TLS indicators.
- Node-RED (TCP 1880) — unauthenticated dashboard access, flow deployment events.
- Zigbee / IEEE 802.15.4 — wireless presence, unencrypted frames (no zbee_nwk security header), ZCL write/control commands.
- CoAP (UDP 5683/5684) — cleartext CoAP presence (5683), DTLS-protected traffic (5684), PUT/POST/DELETE write operations.
- Z-Wave — wireless presence detection.
- Physical Security — RTSP/ONVIF cleartext, ONVIF discovery storms.
- Beaconing / C2 — low-jitter periodic flows.
- DNS anomalies — DGA-like NXDOMAIN bursts, long names, large TXT, multi-resolver.
- SNMP — walks, SETs, plaintext communities.
- TLS inspection — old versions (SSLv2/3, TLS 1.0/1.1), weak ciphers (RC4/3DES/DES/NULL/MD5/EXPORT), self-signed, expired.
- NTP / capture integrity — large inter-packet gaps, no-NTP, multi-resolver NTP.
- IT noise on OT — mDNS / LLMNR / NBNS / SSDP from OT subnets.
- DHCP rogue server detection.
- ICMP sweep / unreachable burst.
- TCP RST / SYN-no-ACK storm counters.
- ARP — gratuitous-burst, multi-IP-per-MAC, multi-MAC-per-IP, eth/ARP MAC mismatch, unsolicited replies.

### 6.3 Phase 3 — Per-Category Passes

Phase 2 covers the majority of detection. Three checks need their own pass: Cleartext / Legacy / Credential extraction (PAYLOAD fields are expensive), Artifact extraction (model names / firmware / project files), and Network Hygiene + Intrusion / Unknown (consume already-built session state, no tshark re-read).

### 6.4 Phase 4 — Correlations

- Recon-then-write — reconnaissance tags + write tags on the same source IP → CORRELATION finding.
- ARP-based Adversary-in-the-Middle — multi-MAC-per-IP + eth/ARP mismatch on the same IP, escalates to INTRUSION when subsequent OT writes are seen in the same subnet.
- Combined-signal anomalies — anonymous MQTT + control-keyword topic, lateral movement + write protocol, etc. (~20 patterns).

### 6.5 Phase 5 — Risk Scoring

```text
Score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (LOW × 1)
      + (CORRELATION × 15) + (INTRUSION × 20)
```

| Score Range | Risk Band |
| --- | --- |
| 0 – 15 | LOW RISK |
| 16 – 40 | MODERATE RISK |
| 41 – 80 | HIGH RISK |
| 81 – 150 | CRITICAL RISK |
| 151+ | SEVERE / ACTIVE COMPROMISE SUSPECTED |

---

## 7. Reports and Artifacts

OTscope writes up to six artifacts alongside any session, named with the site slug + date:

| Artifact | Filename Pattern / Purpose |
| --- | --- |
| Word report | `OT_PCAP_Analysis_<site>_<YYYYMMDD>.docx` — the human-readable deliverable. |
| JSON report | `OT_PCAP_Analysis_<site>_<YYYYMMDD>.json` — machine-readable findings + devices + risk for SIEM/ticketing. |
| Device Inventory CSV | `OT_Device_Inventory_<site>_<YYYYMMDD>.csv` — full device list with per-device traffic, role, vendor, OS, VLAN, source pcaps, `is_critical_in_findings` flag. |
| Flow Allowlist CSV | `OT_Flow_Allowlist_<site>_<YYYYMMDD>.csv` — observed (src, dst, dport, proto) tuples sorted by frequency, with a default ALLOW action column for asset-owner review. |
| Purdue Summary SVG | `OTscope_Purdue_Summary_<site>_<YYYYMMDD>.svg` — visual layered diagram (always written). |
| Purdue Detail SVG | `OTscope_Purdue_Detail_<site>_<YYYYMMDD>.svg` — per-device visual diagram (only for ≤50 devices). |

### 7.1 Word Report Structure

The Word report is designed as an **auditor workpaper** for IT-oriented cybersecurity auditors who may be unfamiliar with OT/ICS protocols. It follows a progressive-disclosure model: the Word document is concise and narrative-focused; raw technical evidence lives in the JSON export; device and flow details are in the CSVs.

**Sections:**

1. **Cover Page** — Site, Assessor, Session name, generated date/time, OTscope version.
2. **Document Purpose and Scope** — what this report is, what pcap files it covers, what it does not cover.
3. **How to Use This Report** — reading order guidance, cross-reference map (Word → JSON → CSVs), `--technical-appendix` note.
4. **Executive Summary** — overall risk band, finding counts by severity, key narrative observations, top affected hosts, recommended immediate actions.
5. **Network Interpretation Summary** — narrative paragraphs describing the observed network architecture and behavior in plain language for audit readers.
6. **Risk Summary** — color-coded table (Severity · Count · Score Contribution); each row shaded in its severity color.
7. **Findings** (grouped by category, severity-sorted within each category). Each finding includes:
   - Auto-sequential finding ID (e.g. `MODBUS-001`, `DNP3-002`) for cross-referencing
   - Severity and category
   - **Detection confidence** (High / Medium / Low) — how certain OTscope is that this event was correctly detected
   - **Maliciousness confidence** (High / Medium / Low, with "may be authorized maintenance" qualifier where applicable) — how likely the activity represents a threat vs. legitimate operation
   - **OT Significance** — one-paragraph explanation of why this matters specifically in an OT/ICS context, written for IT audit readers
   - Description and evidence summary
   - **Auditor Action** — 3–5 specific verification and follow-up steps
   - **Benign Explanation** — one sentence describing the most likely legitimate cause, for auditors to ask the asset owner about
   - Compact metadata: affected endpoints, source pcaps, MITRE IDs, advisory references, Wireshark pointer
8. **Timeline / Attack-Chain Summary** — chronological table of MEDIUM+ findings (capped at 80), highlighting correlated attack sequences.
9. **MITRE ATT&CK for ICS Coverage** — table of technique IDs and names observed across all findings.
10. **Top Riskiest Devices** — top 15 devices by severity-weighted score.
11. **Device Inventory** — top 200 devices by traffic volume; full list in the Device Inventory CSV.
12. **Appendix A: Wireshark Investigation Guide** — per-category filter recipes and investigation steps (see §8).

**Appendix B (optional — `--technical-appendix`):** Raw evidence lines and per-pcap breakdown for each finding category. Not included by default to keep the document readable for non-technical reviewers. Pass `--technical-appendix` on the command line to include it. The same detail is always available in the JSON export.

All tables use a consistent dark-blue header row (white bold text, full grid borders). Right-click the Table of Contents and select *Update Field* after opening the document to populate page numbers.

### 7.2 Severity Color Coding

| Severity | Use |
| --- | --- |
| INTRUSION | Behavioral indicator of active or past attack. |
| CRITICAL | Immediate action required. |
| CORRELATION | Cross-finding elevated risk (recon-then-write, MITM-with-writes, etc.). |
| HIGH | Action required at next opportunity. |
| MEDIUM | Review and document. |
| LOW | Note and monitor. |
| INFO / NOTE | Informational. |
| ABSENCE | Expected protocol not found. |

### 7.3 Purdue-Model Architecture Diagrams (SVG)

OTscope writes one or two visual Purdue-Model architecture diagrams alongside every report. SVG was chosen so the output is vector (zoomable without quality loss), opens in any browser / image viewer / Word, and adds no dependencies. Color coded by highest severity in each layer — a glance shows you which layers have problems.

#### 7.3.1 Summary Diagram (always written)

One color-coded box per Purdue layer with device count, top protocols, and severity tally. Inter-layer arrows scaled by packet volume. Readable at any network size — even on flood-scale captures with millions of devices, this aggregated view stays legible.

- External / Public
- Purdue L4/L5 — IT / Corporate
- Purdue L3/L3.5 — DMZ / Boundary
- Purdue L2/L3 — Supervisory / HMI
- Purdue L1/L2 — Controllers / PLC / RTU
- Physical Security / OT Edge
- Unclassified (only if any device couldn't be placed)

Empty layers are skipped automatically.

#### 7.3.2 Detail Diagram (only for ≤50 devices)

Same Purdue stack, but each device is its own labeled box (IP + role + vendor). Top 30 inter-device flows drawn as bezier curves. CRITICAL/INTRUSION-touched devices and flows are highlighted red so they pop out of the diagram.

Above 50 devices the Detail diagram is automatically skipped with a log message — drawing every device on a flood-scale capture would produce an unreadable spaghetti picture. The Summary diagram and the Device Inventory CSV cover that case.

#### 7.3.3 Color Legend

| Layer top severity | Box color |
| --- | --- |
| INTRUSION | Light red fill, dark red border. |
| CRITICAL | Red fill, dark red border. |
| CORRELATION | Blue fill, dark blue border. |
| HIGH | Orange fill, dark orange border. |
| MEDIUM | Yellow fill, gold border. |
| LOW | Light gray fill, gray border. |
| No findings | Off-white fill, light gray border. |

#### 7.3.4 Opening the Diagrams

- Double-click the `.svg` in any file manager — opens in your default browser.
- In Word: Insert → Pictures → This Device → select the `.svg`. The image embeds and prints natively in Word 2016+.
- On macOS: Quick Look (spacebar) renders SVG natively.
- On Linux: most image viewers (Eye of GNOME, Gwenview, Inkscape) render SVG.

---

## 8. Wireshark Investigation Workflow

Every finding in the report is paired with a per-category guide in Appendix A and one of two ways to jump from the report directly to the exact frame(s) in Wireshark.

### 8.1 Per-Row Findings — `@<epoch>` Jump Tags

Findings emitted from per-row signals (Modbus writes, replays, scans, DNP3 control commands, MITM correlation signals, beaconing, DNS anomalies, IT noise, ICMP sweeps, etc.) include `@<epoch>` at the end of every evidence line:

```text
eth2dump-mitm-15m_1.pcap: 172.27.224.250 -> 172.27.224.251 |
  Response: Trans: 1; Unit: 1, Func: 6: Write Single Register @1745801234.567
```

In Wireshark, paste the epoch into the display filter as:

```text
frame.time_epoch == 1745801234.567
```

…and you land on the exact frame.

### 8.2 Session-Aggregated Findings — Observation Window

Findings built from session-level state (ARP spoof, multi-subnet, public-IP, VLAN crossings) include an "Observation window" evidence line with two epochs to bracket the activity:

```text
Observation window: first seen @1745801234.567890, last seen @1745801999.123456
(Wireshark: `frame.time_epoch >= 1745801234.567890 &&
             frame.time_epoch <= 1745801999.123456`)
```

### 8.3 Appendix A — Per-Category Guides

Each category that fired at least one finding gets a guide entry in Appendix A of the Word report, with a recommended display filter and 4-5 concrete steps (column suggestions, Follow Stream targets, Statistics menu paths). Categories covered include ARP/MITM, Modbus, DNP3, BACnet, IEC 104 / IEC 61850 / GOOSE / MMS, OPC-UA, EtherNet/IP/CIP, Siemens S7, PROFINET, cleartext/legacy/credentials, TLS weakness, beaconing/C2, DNS anomalies, SNMP, ARP/RST/SYN/ICMP scans, mDNS/LLMNR/NBNS/SSDP, DHCP rogue, suspicious UA / EOL banners, auth-failure bursts, public IP exposure, baseline drift, and capture-integrity / no-NTP.

---

## 9. Baseline Diff (Known-Good Snapshot)

The baseline mechanism is the highest-signal detection mechanism for OT environments because deviation from normal is almost always interesting.

### 9.1 Save a Baseline

```bash
$ python3 otscope.py
  ... [discovery question 'Save current run as baseline? y']
  → captures/<site>_baseline.otpa_baseline

# Or after the fact:
$ python3 otscope.py --session captures/known_good.otpa_session \
    --save-baseline captures/<site>_baseline.otpa_baseline
```

- Captures: device set, flow tuples, per-device protocol/port sets.
- Small on purpose — meant to be committed to version control by the asset owner.

### 9.2 Compare Against a Baseline

```bash
$ python3 otscope.py
  ... [discovery question 'Baseline file: captures/<site>_baseline.otpa_baseline']

# Or via CLI:
$ python3 otscope.py --session captures/this_run.otpa_session \
    --compare-baseline captures/<site>_baseline.otpa_baseline
```

Emits findings for each deviation:

- New device since baseline — CRITICAL on air-gapped networks, HIGH otherwise.
- New flow since baseline (≥50 from one source = scanner signature → CRITICAL).
- New protocol per device.
- New destination port per device.

---

## 10. Performance and Scale

### 10.1 Per-Step ETA

After the inventory pass, OTscope knows your machine's effective tshark throughput (bytes/sec) on the actual files. Every later step prints both an ETA (before it runs) and the elapsed time (after it finishes), with wall-clock timestamps on each progress line.

### 10.2 Atomic Session Checkpointing

After every pcap is fully processed (in both inventory and streaming passes), the session JSON is written via atomic `.tmp → rename`. A kill / crash / power loss leaves the session at the last completed file, never half-written. Re-run resumes cleanly.

### 10.3 Flood-Scale Captures

On flood-scale captures (e.g. ping-flood or Modbus query-flood test pcaps with 1M+ spoofed source IPs), per-finding emission caps engage automatically:

- Network hygiene findings cap at 200 per type (25 in fast-path mode); excess collapses to one rollup finding per type.
- Device Inventory table caps at top 200 by traffic — full list in CSV.
- Network Map caps at 30 devices per Purdue zone (text view).
- Purdue Detail diagram is skipped above 50 devices; Summary always renders.
- Affected Endpoints lines cap at 30, Source Pcaps at 8 per finding.
- Source Pcaps line collapses to "(all N session pcaps)" when finding spans the full set.

Net result: a 1.4M-device flood capture renders as a ~50-page Word report with the full data exported to the Device Inventory CSV and a readable Purdue Summary diagram.

### 10.4 Subprocess Hygiene

- tshark is invoked with `-n` (no name resolution, no DNS leak).
- tshark stderr is redirected to a spooled temp file so the OS pipe never fills.
- Generator try/finally guarantees tshark is reaped within ~7 seconds even on early-exit / exception paths (terminate → wait 5s, kill if needed).
- Ctrl+C offers to save partial state then exits cleanly. Avoid SIGKILL — it can orphan tshark.

---

## 11. Files OTscope Creates

| Path | Purpose |
| --- | --- |
| `~/.ot_pcap_analyzer.conf` | Last folder, last assessor, last site, configurable thresholds. |
| `<session_folder>/<session>.otpa_session` | Session state JSON — devices, connections, findings, environment answers, processed pcaps. |
| `<session_folder>/<site>_baseline.otpa_baseline` | Optional: known-good snapshot for diffing. |
| `<session_folder>/OT_PCAP_Analysis_<site>_<YYYYMMDD>.docx` | Word report. |
| `<session_folder>/OT_PCAP_Analysis_<site>_<YYYYMMDD>.json` | JSON report (auto-generated alongside every Word report). |
| `<session_folder>/OT_Device_Inventory_<site>_<YYYYMMDD>.csv` | Full device inventory. |
| `<session_folder>/OT_Flow_Allowlist_<site>_<YYYYMMDD>.csv` | Observed flows for segmentation policy. |
| `<session_folder>/OTscope_Purdue_Summary_<session>.svg` | Visual Purdue diagram (always). |
| `<session_folder>/OTscope_Purdue_Detail_<session>.svg` | Visual per-device diagram (≤50 devices only). |

> **Field deployment note:** When running from the standard field layout, `pcaps\` is the default pcap drop folder and `output\` is the default session folder — both are siblings of `otscope.py` and are auto-created on first run.

---

## 12. Reading the Report — Triage Order

When the Word report opens, work top-down for fastest triage:

1. Open the Purdue Summary SVG first — visual confirmation of which Purdue layers have findings, before reading any text.
2. Executive Summary on page 2 — read the Key Attack Chain Narratives bullets first. If any ⚠ ACTIVE ATTACK CHAIN line appears, that is the headline finding.
3. Top Riskiest Devices — these are the IPs that show up across the most severity-weighted findings.
4. Findings → INTRUSION-class items first (deep red), then CRITICAL (dark red), then CORRELATION (dark blue), then HIGH.
5. Timeline / Attack Chain — confirm the sequence: was there reconnaissance before the writes? Did beaconing precede a control action?
6. Use Appendix A guides + the `@<epoch>` tags in the evidence to drop into Wireshark on any finding that needs deeper confirmation.
7. Hand the Device Inventory CSV and Flow Allowlist CSV to the asset owner for segmentation-policy review.

---

## 13. Known Limitations

- Single-threaded tshark per file. Parallel reads are deferred until profiling justifies the refactor risk.
- Some payload-level CIP services (symbolic-name extraction for service `0x4e`, multi-service-packet frame counts) are not parsed. Use Wireshark for those forensic drills.
- Baseline behavior is not auto-learned — you must capture a known-good run with `--save-baseline`.
- OUI table (~140 entries) covers major industrial + IT vendors but is not the full IEEE registry.
- Passive OS fingerprinting is heuristic (TCP SYN TTL + window) — accurate for Windows / Linux / BSD / IoT-class but not deterministic.
- Public-IP RDAP/PTR enrichment is best-effort and skipped entirely under `--offline`. Reports under offline mode omit the "owner / network / country" fields on public IP findings.
- Purdue Detail SVG is only emitted for ≤50 devices. Above that threshold the Summary SVG plus the Device Inventory CSV cover the picture.
- Z-Wave detection requires the `zwave` tshark dissector, which is not included in all tshark builds. If unavailable, OTscope skips Z-Wave detection and prints an informational message — no other functionality is affected. Z-Wave is rare in industrial OT environments; upgrade to the latest full Wireshark install if Z-Wave capture analysis is needed.
- Zigbee (IEEE 802.15.4) and Z-Wave dissectors conflict at the tshark filter level and cannot share a single analysis pass. OTscope runs Z-Wave as a separate dedicated tshark pass to avoid this — adding latency only on pcaps that are large enough for it to matter.

---

## 14. Version History

Running log of capabilities added in each release. Newest at the top.

### Version 2.6.0 · May 2026 (patch 5)

IoT wireless protocol detection and output directory fix.

- **Output directory fix** — reports, session files, and companion artifacts (JSON, SVGs) are now always written to `output\` (sibling of `otscope.py`) instead of the pcap source folder. Falls back to the pcap folder if `output\` is not accessible (e.g. read-only USB).
- **Zigbee / IEEE 802.15.4 detection** — presence, unencrypted frames (`zbee_nwk.security == 0`), and ZCL write/control commands. Absence finding when declared via `expected_protocols`. Wireshark investigation guide added.
- **CoAP detection** — cleartext CoAP (UDP/5683) vs. DTLS-protected (UDP/5684), PUT/POST/DELETE write operations. Absence finding when declared.
- **Z-Wave detection** — presence detection with absence support when declared.
- **`expected_protocols` prompt** updated with an `IoT:` section listing `zigbee`, `coap`, and `zwave` keywords.

### Version 2.6.0 · May 2026 (patch 4)

Field deployment, discovery question overhaul, and complete expected-protocol absence coverage.

- **4 documentation-only discovery questions removed** (`expected_vendors`, `known_it_services`, `capture_context`, `maintenance_window`) — none drove analysis logic.
- **`expected_protocols` question rewritten** with an inline keyword cheat-sheet. Users can now type any recognized keyword to enable absence detection for that protocol.
- **Absence-of-expected-traffic detection completed** across all 17 supported protocols. Three previously env_type-only checks (IEC 61850, IEC 60870-5-104, Physical Security) now also trigger from `expected_protocols`. Seven vendor protocols added in v2.5.0 (Omron FINS, GE SRTP, Schneider UMAS, Mitsubishi MELSEC, OSIsoft PI, Ignition, Node-RED) now have absence findings when declared but not observed.
- **JSON and Purdue SVG files are now always auto-generated** alongside every successful Word report — no `--format both` required.
- **Field deployment packaging** — `pcaps\` and `output\` are auto-created as siblings of `otscope.py` on first run. If `pcaps\` is empty, a startup hint directs the user to drop captures there. `README.txt` added alongside the script with a plain-text 10-step quick-start.
- **`build_release.py`** at the repo root packages the field distribution zip (`dist/OTscope_v<VERSION>.zip`) on demand. Supports `--dry-run`.
- **Script-relative path anchor** — all workspace paths now use `_SCRIPT_DIR = Path(__file__).resolve().parent` so `pcaps\` and `output\` always resolve correctly regardless of where `otscope.py` is placed.
- **Windows-friendly dependency error** — `ensure_runtime_dependencies()` now leads with `pip install -r requirements.txt` and includes tshark download links for Windows and macOS.
- **Advisory references updated** — Dragos references now cite the specific "Dragos OT Cybersecurity Year in Review 2025 (dragos.com/year-in-review)" rather than a generic title.
- **"Key OT Concepts for IT Auditors" section removed** from the Word report — report stays focused on the pcap under analysis.
- **MITRE ATT&CK technique IDs** in the Word report's ATT&CK coverage table are now hyperlinked to `attack.mitre.org`.

### Version 2.6.0 · May 2026

Auditor-focused report overhaul and `--technical-appendix` flag.

- **Complete DOCX report redesign** for IT-oriented cybersecurity auditors unfamiliar with OT/ICS.  The report follows a progressive-disclosure model: the main Word document is a concise workpaper; the JSON export carries complete machine-readable detail; CSVs carry device and flow inventories.
- New 12-section report structure: Cover Page → Document Purpose and Scope → How to Use This Report → Executive Summary → Network Interpretation Summary → Risk Summary → Findings (grouped by category) → Timeline / Attack-Chain Summary → MITRE ATT&CK for ICS Coverage → Top Riskiest Devices → Device Inventory → Appendix A: Wireshark Investigation Guide.
- **New per-finding fields** — detection confidence, maliciousness confidence (with "may be authorized maintenance" qualifier where appropriate), OT significance narrative for IT auditors, auditor action bullets, and benign-case explanation.
- **Auto-sequential finding IDs** (`MODBUS-001`, `DNP3-001`, etc.) assigned at report generation time; `dedupe_key` preserved in the JSON export for correlation.
- **`--technical-appendix` CLI flag** — when passed, appends Appendix B (Detailed Technical Evidence) to the Word report, including raw evidence lines and per-pcap breakdown.  Absent the flag, technical detail remains in the JSON export only, keeping the Word document readable by non-technical audit reviewers.
- New module-level helper functions: `detection_confidence_for_finding`, `maliciousness_confidence_for_finding`, `ot_significance_for_finding`, `auditor_guidance_for_finding`, `benign_explanation_for_finding`, `build_network_interpretation_summary`.
- `technical_appendix` parameter threaded through `generate_report`, `prompt_report_generation`, and all top-level flow functions (`new_session_flow`, `resume_flow`, `add_pcaps_flow`, `report_only_flow`, `scan_flow`).

### Version 2.5.0 · May 2026

Expanded OT protocol coverage and Modbus register value anomaly detection.

- **7 new OT vendor protocol detectors** added to the single-pass streaming check:
  - Omron FINS (TCP/UDP 9600) — presence, cleartext/no-auth, write/control command indicators.
  - GE SRTP (TCP 18245) — presence, cleartext/no-auth, write indicators (GE PACSystems RX3i / 90-30).
  - Schneider UMAS (TCP 1024) — presence, cleartext/no-auth, write/stop/download indicators (Modicon M340/Premium).
  - Mitsubishi MELSEC SLMP (TCP 5007) — presence, cleartext/no-auth, remote run/stop/write indicators.
  - OSIsoft PI Server (TCP 9001) — historian traffic presence and potential data exfiltration signal.
  - Ignition Gateway (TCP 4592) — OPC-UA without TLS.
  - Node-RED (TCP 1880) — unauthenticated dashboard access and flow deployment events.
- **Modbus register value anomaly detection** — extracts `modbus.regval_uint16` and `modbus.reference_num` per response frame; flags registers with sudden jumps ≥50% of observed range and ≥500 raw units. Catches spoofed/injected Modbus responses that substitute false process values.
- MITRE ATT&CK for ICS, advisory references, and Wireshark investigation guides added for all new protocols and the register value anomaly finding.
- `modbus.reference_num` and `modbus.regval_uint16` added to `BASE_PACKET_FIELDS` (zero overhead on non-Modbus frames).

### Version 2.4.0 · May 2026

Visualization, non-interactive scan mode, and report layout release.

- Purdue-Model SVG architecture diagrams — Summary (always) and Detail (≤50 devices). Color-coded by per-layer top severity. Pure stdlib, no new dependencies.
- Pointer in the Word report's Network Map section to the standalone SVG file(s).
- Network Map ASCII view notes the device count per zone explicitly.
- **Non-interactive scan mode** (`--scan <path>`) — accepts a pcap file or folder; skips all prompts, runs the full analysis pipeline, auto-generates a report, and exits. Combine with `--assessor`, `--site`, `--env`, `--format`, and `--offline` for fully scripted / pipeline runs. `--assessor`, `--site`, and `--env` also pre-fill prompts in interactive mode.
- **Word report layout overhaul** — all tables now use a consistent dark-blue header row with white bold text and full grid borders. Title metadata block converted to a 2-col table. Risk Summary converted to a color-coded 3-col table (each severity row shaded in its own color). Environment Discovery converted to a 2-col table. Per-finding metadata (endpoints, pcaps, MITRE, advisory refs, related findings, Wireshark pointer) consolidated into a compact 2-col mini-table per finding.
- User Guide expanded with §3.2 covering the non-interactive scan mode, §7.1 updated to reflect the new table-based report layout, and this Version History entry.
- User Guide now distributed as both `.docx` (for offline reading) and `.md` (for GitHub-tracked changes).

### Version 2.3.0 · April 2026

Brand rename, deep detection coverage, and report-readability overhaul.

- Brand rename: tool is now **OTscope** (was *OT PCAP Analyzer*). `TOOL_NAME` constant and docstring header updated; `otscope.py` is the active filename.
- Beaconing / C2 detection — jitter-ratio test (`stdev/mean < 0.15`) over ≥10 intervals; CRITICAL when destination is public.
- DNS anomaly suite — DGA-like NXDOMAIN bursts, long names, large TXT, multi-resolver per source.
- TLS / certificate inspection — old versions (SSLv2/3, TLS 1.0/1.1), weak ciphers (RC4/3DES/DES/NULL/anon/MD5/EXPORT), self-signed, expired.
- SNMP depth — walks (≥50 GETNEXT), SET ops, plaintext communities.
- OUI vendor table (~140 entries) and `DeviceRecord.vendors` auto-population.
- Passive OS fingerprinting via TCP SYN TTL + window heuristic.
- NTP / capture integrity — large inter-packet gaps, no-NTP-at-all, multi-resolver NTP.
- Timeline / Attack Chain table — chronological MEDIUM+ findings with `first_seen` ordering.
- Flow Allowlist CSV addendum — observed (src, dst, dport, proto) tuples for segmentation policy.
- Device Inventory CSV addendum — full device list (Word table is capped at top 200).
- CVE / advisory mapping — `Finding.advisory_refs` auto-populated from category and tags. References include CISA ICS-CERT, NIST SP 800-82r3, IEC 62351, ISA/IEC 62443, vendor PSIRTs, and Dragos Year-in-Review.
- Atomic session checkpointing — `.tmp → rename` after every pcap in both passes; resume from kill at any boundary.
- Tier-1 detection bundle: suspicious User-Agent / EOL Server-banner (Mimikatz, Cobalt Strike, sqlmap, masscan, nmap, IIS 5/6, OpenSSL 0.x, etc.), IT-noise-on-OT (mDNS/LLMNR/NBNS/SSDP) with subnet aggregation, DHCP rogue-server, ICMP sweep + unreachable burst, auth-failure bursts (FTP/Telnet/SSH/HTTP).
- Tier-1 forensic bundle: Modbus identical-response replay-timing detection, Modbus single-register repetitive-polling, DNP3 disable-spontaneous + cold/warm restart detectors.
- Combined-signal MITM correlation — multi-MAC-per-IP + eth/ARP MAC mismatch on same IP escalates to INTRUSION when subsequent OT writes appear in the same subnet.
- OUI-annotated MAC evidence on every ARP / MITM finding (`(VMware)` etc.).
- Per-IP and per-MAC first/last-seen Observation Window evidence on session-aggregated findings.
- `@<epoch>` jump tags on per-row finding evidence — paste into Wireshark `frame.time_epoch == X` for instant frame jump.
- Wireshark Investigation Guides — per-finding pointer in body, full per-category guides consolidated into Appendix A.
- Findings grouped by category with H2 headings; auto Table of Contents; Executive Summary section on page 2.
- Source Pcaps line collapses to "(all N session pcaps)" when a finding spans the full session.
- Per-finding emission caps + rollup findings for flood-scale captures (1M+ source IPs); fast-path mode triggers above 50,000 devices/connections.
- Per-step timestamps and ETA estimates calibrated to your machine's measured tshark throughput.
- Network safety: `--offline` hard-lock CLI flag, tshark `-n` flag, network-safety startup banner stating exactly what (if anything) the tool will reach out to.
- Subprocess hygiene: stderr to spooled temp file (no pipe-fill deadlock), generator try/finally guarantees tshark reaping within ~7s on early-exit paths.
- DeprecationWarning fix: replaced `datetime.utcfromtimestamp()` with timezone-aware `fromtimestamp()`.

### Version 2.2.0 · April 2026

First-pass detection expansion.

- ARP fields added to `BASE_PACKET_FIELDS` (`arp.opcode`, `arp.src.hw_mac`, `arp.src.proto_ipv4`, `arp.dst.hw_mac`, `arp.dst.proto_ipv4`) — empty on non-ARP frames so cost is negligible.
- ARP spoofing detection: gratuitous-ARP burst (≥10), MAC claiming ≥3 IPs, IP claimed by ≥2 MACs, Ethernet/ARP MAC mismatch, unsolicited ARP replies.
- MITRE ATT&CK for ICS mapping (~70 keyword → technique-ID entries) auto-attached to every finding via `add_finding()`; MITRE coverage table in the report.
- Per-device risk scoring (severity-weighted aggregation) and Top Riskiest Devices table.
- Low-confidence device pruning post-inventory (drops <2-packet broadcast/multicast and destination-only IPs, keeps active multicast).
- Streaming protocol pass extended: S7 download/upload (function codes 0x1a–0x1f), CIP logic transfer (services 0x4B + 0x53), TFTP RRQ/WRQ with firmware-name severity escalation, Modbus MEI.
- `check_legacy`: ports 110/143/1883 added; per-protocol credential extraction for FTP/Telnet/HTTP-Basic/HTTP-Form/SNMP/MQTT/POP3/IMAP. Passwords stored and rendered in cleartext per assessor request — report header notes sensitivity.
- Baseline diff mechanism — `save_baseline()` + `compare_to_baseline()` emit findings for new devices, new flows, new protocols, new ports. Air-gapped escalates new-device to CRITICAL.
- `--save-baseline` / `--compare-baseline` CLI flags; `baseline_file` and `save_as_baseline` discovery questions.
- Baseline Deviation report category.
- Per-file progress output `[N/M] filename (size) — streaming protocol pass …` and `→ X matching rows` summary.

### Version 2.1.0 · April 2026

Stabilization and protocol-coverage round-out.

- `is_public_ip()` refined to exclude loopback, link-local, CGNAT, multicast.
- `dataclass_from_dict()` forward-compatibility — unknown keys ignored on session reload so future schema additions don't break old sessions.
- `BASE_PACKET_FIELDS` / `PAYLOAD_PACKET_FIELDS` split — payload bytes only requested on checks that need them (legacy + artifact extraction).
- Millisecond-precision packet fingerprint (was whole-second; caused false dedup on fast polling).
- `vlan.id` added to `BASE_PACKET_FIELDS`; `DeviceRecord.vlans` field; VLAN crossing detection in `check_network_hygiene`.
- Air-gapped discovery question; RDAP / PTR lookups skipped when air-gapped.
- IEC 60870-5-104 (`check_iec104`) protocol check.
- DNP3 filter includes `dnp3` dissector match (in addition to TCP/UDP 20000); OPC-UA filter adds port 4843 (TLS).
- S7 stop/start false-positive fix (now requires `s7comm` in `frame.protocols`).
- `generate_json_report()` added; report-format prompt now offers Word / JSON / Both.
- Removed dead `skip_remaining_checks` field.

### Version 2.0 · April 2026

Initial public specification.

- Single-file Python program; no web framework, no external database.
- Multi-pcap session model with unified device registry, deduplication, and incremental analysis.
- Device role and zone inference engine (Purdue-aware).
- Protocol coverage for Modbus, BACnet, DNP3, IEC 61850/GOOSE/MMS, MQTT, OPC-UA, EtherNet/IP, S7/PROFINET, RTSP/ONVIF.
- Cleartext / legacy protocol detection for Telnet, FTP, TFTP, HTTP, SNMP, RDP, VNC, SMB, NetBIOS, NTP, rsh/rexec.
- Cross-file correlation engine — single-file dangerous-combination findings + cross-file pivot/recon-then-attack patterns.
- Risk scoring with banded output and ASCII risk-banner.
- Word report (python-docx) with severity color coding and OTSO Next Step language.
- Session JSON state file with file-hash change-detection.
- Configuration file at `~/.ot_pcap_analyzer.conf` for last folder / assessor / site.
- Interactive terminal UX with ANSI colors, section headers, mini-summary boxes after each check.
- CLI arguments: `--pcap`, `--session`, `--report-only`, `--version`.

---

---

*End of OTscope User Guide  ·  © 2026 Ryan Lyford. All rights reserved.*
