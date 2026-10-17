# OTscope

**User Guide**

Interactive multi-pcap OT/ICS traffic analysis with session persistence, role inference, attack-chain correlation, MITRE ATT&CK for ICS mapping, Wireshark investigation guidance, Purdue-Model architecture diagrams, and machine-readable artifacts.

> **Version 2.8.1**  ·  October 2026
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

OTscope is a single-file Python program for offline analysis of OT/ICS packet captures (`.pcap`, `.pcapng`, or `.cap`, optionally gzip-compressed). It reads pcaps with tshark, builds a unified device and flow inventory across one or many capture files, runs a battery of vulnerability and intrusion-detection checks, and produces a Word report plus several machine-readable artifacts (JSON, two CSVs, and Purdue-Model SVG diagrams).

It is designed for the case where you receive a pile of pcap files from a site you don't fully know and need to answer: *what's on this network, is anything obviously misconfigured, and is anyone attacking it?*

### 1.1 Two Primary Goals

- **Vulnerability detection** — unauthenticated protocols, cleartext communications, insecure configurations, exposed management interfaces, IT/OT boundary violations, weak TLS, EOL services, segmentation gaps.
- **Intrusion detection** — reconnaissance (port scans, host sweeps, register-map sweeps, SNMP walks), unauthorized writes, polling-burst anomalies, beaconing/C2, DNS abuse, ARP spoofing / Adversary-in-the-Middle, brute-force, replayed or injected Modbus responses, attacker tool User-Agents, suppression-attack signatures (DNP3 disable spontaneous, cold/warm restart), and recon-then-write sequences.

---

## 2. Installation and Dependencies

| Component | Notes |
| --- | --- |
| Python 3.8+ | Tested with Python 3.14. Standard on Kali / most Linux distros and macOS. Windows: download from python.org — check "Add Python to PATH" during install. |
| tshark 4.6.4+ | Installed as part of Wireshark. See install commands below. |
| python-docx | `pip install python-docx` — Word report writer. |

No other Python packages are needed: SVG diagrams are pure stdlib, and device vendor names come from the manufacturer database that ships with Wireshark (read offline with `tshark -G manuf`).

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

> **Linux note:** distribution repositories can lag behind the required tshark 4.6.4. On Ubuntu, the Wireshark team's stable PPA tracks current releases: `sudo add-apt-repository ppa:wireshark-dev/stable && sudo apt install tshark`. Check with `tshark --version`.

> **Windows note:** The standard Wireshark installer for Windows includes tshark. During installation, ensure the "TShark" component is selected (it is included by default). After install, you may need to add the Wireshark folder (e.g. `C:\Program Files\Wireshark`) to your system PATH, or restart your terminal.

> **tshark build note:** The standard Wireshark installer includes dissectors for all supported protocols. Z-Wave detection specifically requires a tshark build that includes the `zwave` dissector — if it is absent, OTscope prints an informational message and skips Z-Wave detection gracefully. All other protocols (including Zigbee/IEEE 802.15.4 and CoAP) work with any standard tshark 4.6.4+ install.

### 2.1 Field Deployment (Standalone)

OTscope is fully self-provisioning: drop `otscope.py` — and optionally your capture files — into any folder (e.g. `Building 1\`) and run it. On first run it creates everything else it needs next to itself:

```
Building 1\
    otscope.py          ← the only file you need to copy
    site_capture.pcap   ← optional: loose captures are moved into pcaps\ automatically
    requirements.txt    ← auto-generated (pip dependency list; refreshed if it is an older OTscope-generated copy)
    README_FIRST.txt    ← auto-generated plain-text quick-start (kept current with the OTscope version)
    pcaps\              ← auto-created; capture files live here
    output\             ← auto-created; reports appear here
```

Any capture files sitting loose next to `otscope.py` (`.pcap`, `.pcapng`, `.cap`, or the same names ending in `.gz`) are moved into `pcaps\` at startup (with a `[i] Moved capture into workspace: …` notice; name collisions get a `_v2` suffix rather than overwriting). The same run then finds them in the default location — so "one folder with the script and the captures" is a complete deployment.

If `pcaps\` is empty when you start an interactive new session, the startup message prompts you to drop capture files there before proceeding. If Python packages are missing, the startup dependency check prints the exact `pip install -r requirements.txt` command pointing at the generated file.

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

### 3.1 Session Lifecycle

| Phase | What Happens |
| --- | --- |
| New | Pick a folder of pcaps, name the session, answer environment-discovery questions, run analysis. |
| Active | Streaming + per-protocol passes generate findings; per-step ETAs print as you go. |
| Resume | Reload an `.otpa_session` file, see findings counts, choose: Re-run / Add / Generate report / Review / Exit. |
| Add | Process only NEW pcaps; cross-file correlation re-runs across the full set. |
| Report | Word + JSON + CSV addenda + Purdue SVG diagrams regenerated from current session state. |

### 3.2 Non-Interactive Scan Mode (`--scan`)

`--scan <path>` accepts either a single pcap file or a folder (searched recursively). It skips all prompts — discovery questions use empty/unknown defaults — runs the full analysis pipeline, auto-generates a report, and exits. No keyboard input required at any point.

Optional flags that combine with `--scan`:

| Flag | Purpose | Default when omitted |
| --- | --- | --- |
| `--assessor <name>` | Assessor name embedded in the report | `OTscope` |
| `--site <name>` | Site name used in the report and filename slug | Folder name (the workspace folder's name when scanning the `pcaps\` drop folder itself) |
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
| **Environment type** | Calibrates severity for environment-specific protocols. `power` / `electrical` / `substation` escalates DNP3 no-Secure-Auth to CRITICAL and adds absence checks for IEC 61850 and IEC 104. `physical` / `camera` adds absence checks for RTSP/OSDP. |
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
| `umas` | Schneider UMAS (Modbus function code 90 on TCP 502; appears only during engineering sessions) |
| `melsec`, `mitsubishi`, `slmp` | Mitsubishi MELSEC SLMP (TCP 5007) |
| `historian`, `osisoft`, `pi server` | AVEVA / OSIsoft PI (TCP 5450 Data Archive, TCP 5457 Asset Framework) |
| `ignition` | Ignition Gateway (TCP 62541 OPC UA server, TCP 8060 gateway network) |
| `nodered`, `node-red` | Node-RED (TCP 1880) |
| `physical`, `rtsp`, `osdp`, `onvif`, `camera` | Physical Security (RTSP / OSDP) |
| `zigbee`, `zbee`, `ieee 802.15.4` | Zigbee / IEEE 802.15.4 wireless |
| `coap` | CoAP (UDP 5683 cleartext / 5684 DTLS) |
| `zwave`, `z-wave` | Z-Wave wireless |
| `voip`, `video`, `audio`, `cctv`, `sip`, `camera`, `rtsp` | Audio/Video streaming (SIP/RTP, RTSP, MPEG-TS, CCTV) |

Example entry: `modbus, dnp3, historian, ignition`

---

## 6. Analysis Pipeline

After the questionnaire, OTscope runs a calibrated pipeline. The first pass measures bytes-per-second on YOUR machine; every subsequent step prints an ETA based on that measurement so a long run is predictable.

### 6.1 Phase 1 — Capture Inventory

Always runs. One full tshark pass per pcap that builds the unified device and flow inventory. Outputs total packets, duplicate count, time range, unified device count (after low-confidence pruning), top talker pairs, and per-machine bytes-per-second calibration for ETAs.

- **Flow direction.** Every flow is oriented client → server. The server side comes from the TCP handshake (SYN / SYN-ACK) when the capture contains it; otherwise from well-known service ports. A flow is recorded once as *client → server : service port* — the client's ephemeral port never becomes a "destination port", and a device's **ports** are the services it actually answered on (its **client ports** are the services it used).
- **Truncated captures.** A capture that ends mid-packet or has a damaged record (common when a capture is stopped abruptly or copied while still being written) is analyzed up to the damage, flagged `truncated` in the JSON report, and noted on the console — it is not dropped.
- **Hosts only.** Broadcast and multicast destinations (`x.x.x.255`, `255.255.255.255`, `224.0.0.0/4`, `ff00::/8`) are not devices; they are counted separately and listed in the report's Network Interpretation Summary. Hosts seen only in ARP — quiet devices, or an attacker poisoning caches from its own address — are added from their ARP frames. An IPv6 link-local address is folded into the IPv4 host that uses the same MAC, so one machine appears once.

### 6.2 Phase 2 — Streaming Protocol Pass

ONE combined tshark read per pcap with a single display filter that covers all protocols and hygiene signals. Per-protocol accumulators are fed in parallel, then findings are emitted post-loop. This is the single biggest performance win — N protocols × M files becomes 1 × M.

Detectors read structured tshark fields — function codes, transaction IDs, TLS handshake fields, SNMP community and PDU type, MQTT flags — rather than parsing the Info column. Fields an older tshark does not know are simply read as empty. Checks keyed on a port need application data: a refused connection (SYN answered by RST), a bare ACK, or an ICMP error quoting a probe does not count as that protocol's traffic. Command and write detectors only fire on requests travelling client → server, never on the device's reply.

- Modbus TCP — write requests (by function code), Unit ID 0 broadcast writes, register-map sweeps (many start addresses read once or twice each), exceptions per server, polling bursts (one-second request rate far above the pair's own baseline), hammer-rate single-address polling (≥1,000 reads at ≥20/s), duplicate or unsolicited responses (answers are matched to each connection's queue of outstanding requests; segments that carry several requests, TCP retransmissions, and request bytes tshark could not decode are all accounted for), register value anomaly, writes confirmed from the server's answer when a client's requests are split into segments too small for tshark to decode, Schneider UMAS engineering traffic (function code 90), and Read Device Identification (MEI).
- BACnet/IP — Who-Is/I-Am, WriteProperty requests, BBMD/forwarded NPDU.
- DNP3 — Direct Operate, Freeze, Disable Spontaneous, Cold/Warm Restart, broadcast (link-layer destination 0xFFFD–0xFFFF), no-Secure-Authentication (no SA function codes 32/33/131 seen).
- IEC 61850 / GOOSE / MMS — control operations, GOOSE state-number anomalies, MMS without TLS. Requires the MMS dissector, so S7comm on TCP/102 is not mistaken for MMS.
- IEC 60870-5-104 — cleartext sessions per server, control ASDUs, general interrogation (INFO).
- MQTT — CONNECT without a username, cleartext MQTT per broker, readable MQTT on 8883 (the TLS port), control-keyword topics, wildcard SUBSCRIBE, retained control messages, rapid reconnects per client ID.
- OPC-UA — SecureChannels using SecurityPolicy None or Sign-only mode, Browse enumeration, Write requests.
- EtherNet/IP / CIP — List Identity (device discovery), Forward Open, write services, reset, logic transfer, PCCC.
- Siemens S7 / PROFINET — PLC Stop/Start, Write Variable, block download/upload, Read SZL, DCP Identify All / Set.
- Omron FINS (TCP/UDP 9600), GE SRTP (TCP 18245), Mitsubishi MELSEC SLMP (TCP 5007) — presence (cleartext, no authentication) and write/control requests.
- AVEVA / OSIsoft PI (TCP 5450 / 5457) — historian traffic presence.
- Ignition Gateway (TCP 62541 / 8060) — presence; gateway-network traffic without TLS.
- Node-RED (TCP 1880) — admin API reachable without authentication (requests to `/flows`, `/nodes`, `/settings`… with no Authorization header and no 401 reply), flow deployment events.
- Zigbee / IEEE 802.15.4 — wireless presence, unencrypted frames (no zbee_nwk security header), ZCL write/control commands.
- CoAP (UDP 5683/5684) — cleartext CoAP presence (5683), DTLS-protected traffic (5684), PUT/POST/DELETE write operations.
- Z-Wave — wireless presence detection.
- Physical Security — RTSP streams served without an authentication challenge (per camera), OSDP without Secure Channel.
- Audio/Video streaming — signaled RTP flows classified audio vs. video (payload type + bitrate), SIP/VoIP call signaling, active RTSP stream requests, MPEG-TS distribution (IPTV/CCTV multicast), RTMP, sustained multicast UDP, unsignaled media-like UDP heuristic, GigE Vision machine-vision cameras, CCTV DVR/NVR vendor ports (Hikvision 8000 / Dahua 37777).
- Beaconing / C2 — low-jitter periodic client → server exchanges (mean interval 5 s – 1 day). OT protocol ports, DNS, NTP, SNMP, syslog, discovery protocols, multicast, and broadcast are excluded. MEDIUM for internal destinations, HIGH for public ones.
- DNS anomalies — DGA-like NXDOMAIN bursts, long names, high-entropy names, large TXT, multi-resolver.
- SNMP — walks (≥50 GetNext/GetBulk), SETs, SNMPv1/v2c community strings.
- TLS inspection — version and cipher suite the server selected in its ServerHello (SSLv2/3, TLS 1.0/1.1; NULL, anonymous, EXPORT, RC4, DES/3DES, MD5 suites, named from Wireshark's cipher table), certificates rejected by the peer (unknown CA / bad certificate alerts), expired certificates (certificate_expired alerts), and JA3 fingerprints of known offensive tools.
- NTP / capture integrity — large inter-packet gaps, very short captures, no NTP at all (only reported for captures of 30 minutes or longer), hosts querying many NTP servers.
- IT noise on OT — mDNS / LLMNR / NetBIOS / SSDP / WS-Discovery from subnets that hold OT devices.
- DHCP rogue server detection.
- ICMP sweep / unreachable burst.
- TCP RST bursts (aborted connections only — RSTs that follow a normal FIN close are routine teardown) and repeated unanswered SYNs (SYN-ACK counts separate answered from unanswered).
- ARP — for every IP claimed by more than one MAC, the analysis decides which MAC owns it and which is impersonating it (see §6.4); gratuitous-ARP bursts, one MAC claiming many IPs, frames sent on another host's behalf, and unsolicited replies are reported separately only when no impostor explains them.

### 6.3 Phase 3 — Per-Category Passes

Phase 2 covers the majority of detection. Three checks need their own pass: Cleartext / Legacy / Credential extraction (PAYLOAD fields are expensive), Artifact extraction (model names / firmware / project files), and Network Hygiene + Intrusion / Unknown (consume already-built session state, no tshark re-read).

- **Cleartext / legacy** inventories legacy services by the port the server answered on, extracts credentials (FTP, Telnet logins reassembled across packets, HTTP Basic, HTTP form posts, SNMPv1/v2c communities, MQTT, POP3/IMAP), and reports authentication-failure bursts from the server's replies (FTP 530, HTTP 401, Telnet login failures).
- **Unknown traffic** reports unclassified service ports on OT-adjacent devices; dynamic-range ports (≥49152) are never treated as services.

### 6.4 Phase 4 — Correlations

- Recon-then-write — strong reconnaissance and write/control commands from the same source IP → CORRELATION finding. Only scans, sweeps, SNMP walks, and scanner tooling count as reconnaissance; routine discovery that engineering tools perform (IEC 104 general interrogation, CIP List Identity, S7 Read SZL, Modbus Read Device ID, OPC UA browsing, PROFINET Identify All) is tagged *discovery* and does not trigger it.
- Possible OT protocol scanning — one source touching ≥3 OT protocol ports on ≥5 endpoints, at least half of them with ≤4 packets (broad and shallow, unlike a SCADA master's long-lived sessions) → INTRUSION.
- Write/control commands sent to many devices — one source writing to at least `write_burst_count` devices (known HMIs exempt) → HIGH.
- ARP-based Adversary-in-the-Middle — for each IP claimed by two or more MACs, every claimant is checked for spoofing signals: unsolicited ARP replies, claims sent from a different Ethernet source, ARP frames sent on behalf of another host (the "restore" step of MITM tools), and using a different address as its own. The MAC without signals is the owner; a MAC with them is the impostor. One finding per impostor names its MAC and own IP, the impersonated host, the hosts whose caches were poisoned, the attack window, and how much of the victim's traffic passed through the impostor:
  - **INTRUSION — traffic intercepted** when the victim's packets were carried by the impostor's MAC.
  - **INTRUSION — OT writes during poisoning** when write/control commands crossed the poisoned path during the window, even if this capture point did not see them pass through the impostor.
  - **CRITICAL** when the poisoning is clear but no intercepted traffic is visible from this capture point.
  - An IP claimed by two MACs with no spoofing signals (VRRP/HSRP failover, NIC teaming, a duplicate address) stays a HIGH "IP address claimed by multiple MACs in ARP" finding.
- Possible denial-of-service — two or more different availability indicators (unanswered SYNs, aborted connections, hammer-rate or bursting requests) between the same client and server → CORRELATION.
- Anonymous MQTT plus control topics from the same source → CRITICAL.

### 6.5 Phase 5 — Risk Scoring

Findings are grouped by category and title. Each group contributes the weights of its three most severe findings, so a detector that fires once per host cannot dominate the score:

```text
Weights:  INTRUSION 20 · CORRELATION 15 · CRITICAL 10 · HIGH 5 · MEDIUM 2 · LOW 1
Score  =  Σ over distinct (category, title)  of  the weights of its 3 heaviest findings
```

INFO findings, Suggested Controls, and Assessor Notes score zero. A confirmed intrusion is never reported as low risk: any INTRUSION finding raises the band to at least HIGH, and any CRITICAL or CORRELATION finding to at least MODERATE. The report states when a band was raised and why.

| Score Range | Risk Band |
| --- | --- |
| 0 – 9 | MINIMAL |
| 10 – 34 | LOW |
| 35 – 74 | MODERATE |
| 75 – 119 | HIGH |
| 120+ | SEVERE |

---

## 7. Reports and Artifacts

OTscope writes up to six report artifacts alongside the session file, named with the site slug + date:

| Artifact | Filename Pattern / Purpose |
| --- | --- |
| Word report | `OT_PCAP_Analysis_<site>_<YYYYMMDD>.docx` — the human-readable deliverable. |
| JSON report | `OT_PCAP_Analysis_<site>_<YYYYMMDD>.json` — machine-readable findings + devices + risk for SIEM/ticketing. |
| Device Inventory CSV | `OT_Device_Inventory_<site>_<YYYYMMDD>.csv` — full device list with per-device traffic, role, vendor, OS, VLAN, source pcaps, `is_critical_in_findings` flag, plus `client_ports` (services the device used), `ipv6_link_local` (folded IPv6 addresses), and `observations` (e.g. "impersonated by MAC …", "ARP cache poisoned by …"). |
| Flow Allowlist CSV | `OT_Flow_Allowlist_<site>_<YYYYMMDD>.csv` — observed (client, server, service port, protocol) tuples sorted by frequency, with a default ALLOW action column for asset-owner review. |
| Purdue Summary SVG | `OTscope_Purdue_Summary_<site>_<YYYYMMDD>.svg` — visual layered diagram (always written). |
| Purdue Detail SVG | `OTscope_Purdue_Detail_<site>_<YYYYMMDD>.svg` — per-device visual diagram (only for ≤50 devices). |

### 7.1 Word Report Structure

The Word report is designed as an **auditor workpaper** for IT-oriented cybersecurity auditors who may be unfamiliar with OT/ICS protocols. It follows a progressive-disclosure model: the Word document is concise and narrative-focused; raw technical evidence lives in the JSON export; device and flow details are in the CSVs.

**Sections:**

1. **Cover Page** — site, assessor, session name, generation time, risk score, and tool credit.
2. **Table of Contents** — right-click → *Update Field* after opening to populate it.
3. **Executive Summary** — risk score and band (with the reason when a confirmed intrusion raised it), finding breakdown by severity, top affected assets, the highest-severity finding with its narrative, attack-chain indicators, up to three distinct immediate actions, and the companion artifacts.
4. **Environment Discovery and Context** — the questionnaire answers the analysis used.
5. **Priority Findings** — every category that produced a scoring finding, ordered by its top severity. HIGH and above (plus the first finding of each category) get full detail:
   - Auto-sequential finding ID (e.g. `MODBUS-001`, `DNP3-002`) for cross-referencing
   - Affected assets, inferred OT roles, category, MITRE ATT&CK for ICS techniques, advisory and standards references
   - **Detection confidence** (High / Medium / Low) — how certain OTscope is that this event was correctly detected
   - **Maliciousness confidence** (High / Medium / Low, with "may be authorized maintenance" qualifier where applicable) — how likely the activity represents a threat vs. legitimate operation
   - **What Was Observed**, **OT Significance** (why it matters in an OT/ICS context, written for IT audit readers), and **Key Evidence**
   - **Auditor Guidance** — 3–5 specific verification and follow-up steps
   - **What Would Make This Benign** and **Recommended Action**
   - Pointers to the JSON finding, Appendix A, and (when included) Appendix B

   Lower-severity findings get a compact summary: assets, MITRE IDs, description, evidence, and action.
6. **Suggested Controls** — defensive measures suggested by what the capture contained (for example, IDS signatures for exposed credentials). Recommendations, not findings; not scored.
7. **Assessor Notes** — free-text notes recorded during the session.
8. **Network Interpretation Summary** — plain-language paragraphs describing the observed architecture: likely initiators and controllers, host observations (impersonated, impostor, poisoned), IPv6 addresses matched to their IPv4 hosts, broadcast and multicast destinations, IT discovery protocols on OT subnets, services on dynamic ports.
9. **MITRE ATT&CK for ICS Coverage** — technique IDs (hyperlinked to attack.mitre.org), names, and finding counts.
10. **Device Inventory Summary** — top 15 devices by traffic with MAC and vendor (⚠ marks an IP seen with more than one MAC), role, zone, protocols, and risk score, followed by any per-device observations; the full list is in the Device Inventory CSV.
11. **Flow Allowlist Summary** — how to use the Flow Allowlist CSV for segmentation review.
12. **Limitations of Analysis** — disclosures to carry into a formal audit.
13. **Appendix A: Wireshark Investigation Guide** — the investigation guides that match the reported findings, grouped by category (see §8).

**Appendix B (optional — `--technical-appendix`):** B.1 Timeline / Attack Chain (chronological MEDIUM+ findings), B.2 Full Evidence by Finding, B.3 Inferred Network Map, B.4 Top Riskiest Devices (top 15 by severity-weighted score), B.5 Full Device Inventory (top 200 by traffic). Not included by default to keep the document readable for non-technical reviewers. Pass `--technical-appendix` on the command line to include it. The same detail is always available in the JSON export.

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

One color-coded box per Purdue layer with its device count and top protocols, stacked in Purdue order. Readable at any network size — even on flood-scale captures with millions of devices, this aggregated view stays legible.

- External / Public
- Purdue L4/L5 — IT / Corporate
- Purdue L3/L3.5 — DMZ / Boundary
- Purdue L2/L3 — Supervisory / HMI
- Purdue L1/L2 — Controllers / PLC / RTU
- Physical Security / OT Edge
- Unclassified (only if any device couldn't be placed)

Empty layers are skipped automatically.

#### 7.3.2 Detail Diagram (only for ≤50 devices)

Same Purdue stack, but each device is its own labeled box (IP, inferred role, primary protocol), colored by the most severe finding that touches it; CRITICAL/INTRUSION devices get a heavy red border. A panel on the right lists the top connections (client → server, protocol:port, packet count, and the Purdue layers at each end).

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

Findings built from session-level state (ARP conflicts, public-IP, VLAN crossings) include an "Observation window" evidence line with two epochs to bracket the activity. The Adversary-in-the-Middle finding gives an "Attack window" line instead — the impostor's own activity, in UTC and as a Wireshark filter — and sets the finding's first/last-seen times to it:

```text
Observation window: first seen @1745801234.567890, last seen @1745801999.123456
(Wireshark: `frame.time_epoch >= 1745801234.567890 &&
             frame.time_epoch <= 1745801999.123456`)
```

### 8.3 Appendix A — Per-Category Guides

Each category that fired at least one finding gets the guides matching its findings in Appendix A of the Word report — a category with several finding types can show several guides — each with a display filter and 3-5 concrete steps (column suggestions, Follow Stream targets, Statistics menu paths). Findings without a specific guide point to a General Investigation Steps section. Every display filter is valid tshark/Wireshark 4.x syntax (set members are comma-separated, e.g. `tcp.port in {512, 513}`); a few contain `<src>`-style placeholders to fill in. Categories covered include ARP/MITM, Modbus, DNP3, BACnet, IEC 104 / IEC 61850 / GOOSE / MMS, OPC-UA, EtherNet/IP/CIP, Siemens S7, PROFINET, cleartext/legacy/credentials, TLS weakness, beaconing/C2, DNS anomalies, SNMP, ARP/RST/SYN/ICMP scans, mDNS/LLMNR/NBNS/SSDP, DHCP rogue, suspicious UA / EOL banners, auth-failure bursts, public IP exposure, baseline drift, audio/video streaming (RTP/SIP/RTSP/MPEG-TS), and capture-integrity / no-NTP.

---

## 9. Baseline Diff (Known-Good Snapshot)

The baseline mechanism is the highest-signal detection mechanism for OT environments because deviation from normal is almost always interesting.

### 9.1 Save a Baseline

```bash
$ python3 otscope.py
  ... [discovery question 'Save current run as baseline? y']
  → output/<site>_baseline.otpa_baseline   (the session folder; _v2, _v3 … if one exists)

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
- Repeated detections merge into one finding that keeps at most 50 evidence lines and 1,000 IPs per side, with an `occurrences` count in the JSON.
- Device Inventory Summary shows the top 15 devices; Appendix B.5 the top 200 by traffic — full list in CSV.
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
| `<session_folder>/OTscope_Purdue_Summary_<site>_<YYYYMMDD>.svg` | Visual Purdue diagram (always). |
| `<session_folder>/OTscope_Purdue_Detail_<site>_<YYYYMMDD>.svg` | Visual per-device diagram (≤50 devices only). |

> **Field deployment note:** `<session_folder>` is `output\` next to `otscope.py` (or the pcap folder if `output\` cannot be written). When running from the standard field layout, `pcaps\` is the default pcap drop folder and `output\` is the default session folder — both are siblings of `otscope.py` and are auto-created on first run, along with `requirements.txt` and `README_FIRST.txt` (see §2.1). Loose capture files next to `otscope.py` are moved into `pcaps\` at startup. Existing files are never overwritten.

---

## 12. Reading the Report — Triage Order

When the Word report opens, work top-down for fastest triage:

1. Open the Purdue Summary SVG first — visual confirmation of which Purdue layers have findings, before reading any text.
2. Executive Summary on page 2 — read the Attack Chain Indicators first. If any ⚠ line appears, that is the headline finding.
3. Riskiest devices — the console prints the top 5 at the end of the run, the Device Inventory Summary carries a risk score per device, and Appendix B.4 (with `--technical-appendix`) lists the top 15.
4. Priority Findings → INTRUSION-class items first (deep red), then CRITICAL (dark red), then CORRELATION (dark blue), then HIGH.
5. Timeline / Attack Chain (Appendix B.1, with `--technical-appendix`) — confirm the sequence: was there reconnaissance before the writes? Did beaconing precede a control action?
6. Use Appendix A guides + the `@<epoch>` tags in the evidence to drop into Wireshark on any finding that needs deeper confirmation.
7. Hand the Device Inventory CSV and Flow Allowlist CSV to the asset owner for segmentation-policy review.

---

## 13. Known Limitations

- Single-threaded tshark per file. Parallel reads are deferred until profiling justifies the refactor risk.
- Some payload-level CIP services (symbolic-name extraction for service `0x4e`, multi-service-packet frame counts) are not parsed. Use Wireshark for those forensic drills.
- Baseline behavior is not auto-learned — you must capture a known-good run with `--save-baseline`.
- Vendor names come from Wireshark's manufacturer database (`tshark -G manuf`, read offline, including /28 and /36 assignments). If that lookup fails, a small built-in table of industrial and IT vendors is the fallback.
- Flow direction comes from the TCP handshake. For connections already open when the capture started (and for UDP), OTscope uses well-known service ports; when neither port is recognized the lower port is taken as the service.
- Replay detection matches each Modbus answer to its connection's outstanding requests. A verbatim copy of an old frame (same TCP sequence number) is indistinguishable from a TCP retransmission and is not counted, and answers to requests the capture lost entirely can look unsolicited.
- Interception is only visible on the part of the path the capture sees. A SPAN of the controller's switch port shows the impostor's frames to and from the controller, but not the attacker's leg to the HMI, so altered values on that leg cannot be compared with the originals.
- Passive OS fingerprinting is heuristic (TCP SYN TTL + window) — accurate for Windows / Linux / BSD / IoT-class but not deterministic.
- Public-IP RDAP/PTR enrichment is best-effort and skipped entirely under `--offline`. Reports under offline mode omit the "owner / network / country" fields on public IP findings.
- Purdue Detail SVG is only emitted for ≤50 devices. Above that threshold the Summary SVG plus the Device Inventory CSV cover the picture.
- Z-Wave detection requires the `zwave` tshark dissector, which is not included in all tshark builds. If unavailable, OTscope skips Z-Wave detection and prints an informational message — no other functionality is affected. Z-Wave is rare in industrial OT environments; upgrade to the latest full Wireshark install if Z-Wave capture analysis is needed.
- Zigbee (IEEE 802.15.4) and Z-Wave dissectors conflict at the tshark filter level and cannot share a single analysis pass. OTscope runs Z-Wave as a separate dedicated tshark pass to avoid this — adding latency only on pcaps that are large enough for it to matter.

---

## 14. Version History

Running log of capabilities added in each release. Newest at the top.

### Version 2.8.1 · October 2026

Report accuracy release, driven by a review of the reports for a real one-minute ARP MITM capture (a one-hour Modbus capture taken at the PLC's switch port) and a Modbus flooding capture.

- **Adversary-in-the-Middle findings name the attacker.** The ARP analysis now decides, for every IP claimed by more than one MAC, which MAC owns it and which is impersonating it, and emits one consolidated finding per impostor under Intrusion Indicators. It gives the impostor's MAC and own IP, the impersonated host, the poisoned hosts, the attack window (UTC and Wireshark filter), how much of the victim's traffic passed through the impostor, and any restore frames. Before, the finding listed the victim as the source, used a one-hour window, and claimed "subsequent OT writes" from unrelated Modbus findings. The separate "claimed by multiple MACs", "multiple MAC addresses", "ARP sender MAC differs", and "unsolicited ARP replies" findings are folded into it. It no longer requires an Ethernet/ARP mismatch to fire.
- **False positives removed** (found on the real captures):
  - "Duplicate or unsolicited Modbus responses" for clients that pack several requests into one TCP segment or reuse transaction ID 0, for clients whose requests are split one byte per segment, and for requests lost by the capture and then retransmitted.
  - "TCP reset storm" for RSTs that follow a normal FIN close.
  - "Unknown OT-adjacent traffic" for the Sentinel license manager (UDP 1947).
- **Writes no longer missed** when a client's requests are too fragmented for tshark's Modbus dissector — the server's answer confirms them.
- **Denial-of-service correlation** — two or more availability indicators between one client and one server produce a CORRELATION "Possible denial-of-service against an OT device" finding.
- **Device inventory holds hosts only.** Broadcast and multicast destinations are listed in the Network Interpretation Summary instead of as devices; hosts seen only in ARP (such as an attacker's own address) are added; IPv6 link-local addresses fold into the IPv4 host with the same MAC. The Device Inventory CSV gains `client_ports`, `ipv6_link_local`, and `observations` columns; IPv6 subnets are written as valid prefixes; DHCPv6 flows are oriented correctly.
- **Report text matches each finding.** Explanatory text (why it matters, OT significance, auditor guidance, benign explanation, recommended action) now comes from one classifier keyed on finding titles and tags. Since the 2.8.0 category rename it had matched "segmentation" in the category name, giving ARP, IPv6, and ICMP findings firewall/DMZ advice. Evidence lines keep the order detectors write them in instead of being sorted alphabetically.
- **Risk band floors** — any INTRUSION finding sets the band to at least HIGH; CRITICAL or CORRELATION to at least MODERATE; the report says when and why.
- **Executive summary** leads with the highest-severity finding's narrative; immediate next steps list distinct actions. The Device Inventory Summary shows MACs and vendors with a conflict marker and per-device observations. The Purdue Detail diagram lists host-to-host flows first. IPv6 findings are LOW when only link-local traffic is seen and name the IPv4 host behind each address.
- **Regression suite** — 14 scenarios: new `attack_mitm_intercept` (modeled on the real capture) and the ARP MITM check updated for the consolidated finding; the DNP3 sample is found in `otscope/src/pcaps/`.

### Version 2.8.0 · October 2026

Detection-accuracy release. Most changes remove false positives on normal OT traffic and make detectors fire on the traffic they describe; a stdlib-only regression suite now guards the behavior.

- **Client/server flow orientation** — every flow is oriented from the TCP handshake (or well-known service ports when the handshake wasn't captured) and recorded once as client → server : service port. Ephemeral ports no longer appear as device ports, "unknown traffic", legacy services, or Flow Allowlist rows; a device's `ports` are the services it answered on, and the new `client_ports` lists the services it used. Write and control detectors fire only on requests, never on the device's echo.
- **Structured fields instead of Info-column parsing** — TLS version and cipher (from the ServerHello, named via Wireshark's cipher table), TLS alerts, SNMP community and PDU type, MQTT flags/topic/client ID, Modbus function code / transaction ID / unit ID / exception, DNP3 destination and function code, BACnet PDU type, OPC UA security policy and mode, RTSP and HTTP status codes, and HTTP Authorization headers are read as tshark fields. Detectors for weak TLS, SNMP communities, anonymous MQTT, Telnet logins, and HTTP Basic credentials now work (several never fired before). Fields an older tshark lacks read as empty.
- **Fixed tshark filter syntax** — the Cleartext/Legacy check and several Appendix A guide filters used space-separated sets (`{21 23}`), which tshark 4.x rejects; that check had silently produced no findings. All filters are now validated against tshark.
- **Modbus** — register scanning now means many start addresses each read once or twice (an HMI's repeated scan list no longer qualifies); replay detection replaced by duplicate/unsolicited responses matched by transaction ID with TCP retransmissions excluded; polling bursts measured as one-second request rates; hammer polling requires ≥20 reads/s; Unit ID 0 broadcast writes; register value anomaly now actually collects values (it never fired before).
- **Schneider UMAS** is detected as Modbus function code 90 (TCP 502) instead of TCP 1024; **AVEVA PI** uses TCP 5450/5457 instead of 9001; **Ignition** uses TCP 62541/8060 instead of 4592.
- **Fewer false positives** — routine discovery (IEC 104 general interrogation, CIP List Identity, S7 Read SZL, Modbus Read Device ID, OPC UA browsing, PROFINET Identify All) no longer counts as reconnaissance for the recon-then-write correlation; "OT protocol scanning" requires broad, shallow probing instead of any multi-protocol master; the lateral-movement and multi-subnet checks were removed; beaconing ignores OT polling, DNS, NTP, SNMP, syslog, discovery, multicast, and broadcast, collapses each exchange into one sample, and rates internal beacons MEDIUM; refused connections and ICMP errors no longer count as protocol traffic; DNS/ICMP/IPv6 hygiene findings are aggregated; "No NTP" needs a capture of at least 30 minutes; S7comm on TCP/102 is no longer reported as IEC 61850 MMS; WS-Discovery is treated as IT noise rather than ONVIF.
- **New and reworked findings** — OPC UA SecurityPolicy None / Sign-only per SecureChannel; cleartext MQTT per broker and readable MQTT on 8883; MQTT reconnects per client ID; Node-RED editor reachable without authentication (admin API with no Authorization header and no 401); RTSP streams served without an authentication challenge (per camera); TLS certificates rejected by the peer; authentication-failure bursts read from server replies (FTP 530, HTTP 401, Telnet failures); "Write/control commands sent to many devices"; "Repeated unanswered SYNs".
- **Risk score** — each distinct finding title contributes its three heaviest findings; INFO findings, Suggested Controls, and Assessor Notes do not score. Bands are unchanged.
- **Word report** — every scoring category is reported (A/V Streaming, IEC 60870-5-104, and Network Hygiene and Segmentation findings were previously left out); new Suggested Controls and Assessor Notes sections; Appendix A lists every guide matching a category's findings instead of overwriting one guide with another or with the generic steps.
- **Purdue SVGs** — site names and labels are XML-escaped, so names containing `&` or `<` no longer produce invalid SVG files.
- **Truncated captures** — captures that end mid-packet are analyzed up to the damage and flagged `truncated` instead of being dropped from the inventory.
- **Vendor lookup** — OUI vendors come from Wireshark's manufacturer database (`tshark -G manuf`, offline, including /28 and /36 blocks); 42 incorrect entries were removed from the built-in fallback table and seven relabeled.
- **References** — MITRE ATT&CK for ICS mappings corrected (e.g. discovery → T0846, cleartext → T0842, GOOSE spoofing → T0856) and the advisory map rewritten to cite verifiable standards (IEC 62351, IEEE 1815, ODVA CIP Security, RFC 8996, NIST SP 800-82r3 and others), CISA advisories, and vendor PSIRTs.
- **Inputs and outputs** — `.cap` and gzip-compressed captures (`.pcap.gz`, `.pcapng.gz`, `.cap.gz`) are accepted everywhere; `--scan` of the `pcaps\` drop folder names the site after the workspace folder; repeated merges of one finding are bounded (50 evidence lines, 1,000 IPs per side) with an `occurrences` counter; the packet-dedup fingerprint now includes MACs, ports, and IP ID so distinct frames in the same millisecond are kept.
- **Dependencies** — `scapy` removed (it was never used); `python-docx` is the only Python package. Stale generated `requirements.txt` / `README_FIRST.txt` files in a workspace are refreshed.
- **Regression suite** — `tests/` holds a pure-stdlib pcap generator and thirteen scenarios (benign HMI polling, SCADA master, office LAN, dual-zone HMI, credential brute force, Modbus recon and injection, ARP MITM, camera/VoIP, S7 engineering, same-millisecond ARP, Modbus register spike, truncated capture, and a DNP3 sample capture when `otscope/pcaps/dnp3_challenge.pcap` is present). Run `python tests/run_regression.py`.
- **Release package** — `build_release.py` now includes `LICENSE.txt` and builds on Python versions before 3.11.

### Version 2.7.0 · July 2026

- **Audio/Video streaming detection** — new `Audio/Video Streaming` category (`AVMEDIA-###` finding IDs) answering "is there video or audio running on this network?": signaled RTP flows classified audio vs. video from payload type and bitrate; SIP/VoIP call signaling (INVITE / 200 OK with SDP); active RTSP `SETUP`/`PLAY` stream requests; MPEG Transport Stream distribution (IPTV/CCTV multicast); RTMP; sustained multicast UDP streams; unsignaled media-like UDP heuristic; GigE Vision machine-vision camera control (GVCP, UDP 3956); CCTV DVR/NVR vendor-port traffic (Hikvision TCP 8000, Dahua TCP 37777). Absence detection via `voip` / `video` / `audio` / `cctv` keywords in the expected-protocols question. Global RTP heuristics are deliberately left OFF in tshark so media decoding can never hijack OT UDP dissection.
- **Drop-in self-provisioning** — a bare `otscope.py` in an empty folder now creates its full workspace on first run: `pcaps\`, `output\`, `requirements.txt`, and `README_FIRST.txt`. Capture files dropped loose next to the script are moved into `pcaps\` automatically at startup (collision-safe `_v2` suffixing), so "one folder with the script and the pcaps" is a complete deployment. Nothing to pre-create, nothing overwritten if already present; read-only media never blocks startup.
- **UTF-8 console output** — stdout/stderr are reconfigured to UTF-8 with replacement at startup, fixing a crash (`UnicodeEncodeError: 'charmap' codec…`) when output was piped or redirected on Windows (legacy cp1252 code page).
- **Dead code removal** — the ten legacy per-protocol `check_*` methods superseded by the streaming combined pass (Modbus, BACnet, DNP3, IEC 61850, IEC 104, MQTT, OPC-UA, EtherNet/IP, Siemens, Physical Security) were removed (~500 lines); all detection logic lives in the streaming pass only, eliminating drift risk between two implementations.
- **Slimmed `requirements.txt`** — trimmed from a 17-package pip-freeze to the two real dependencies (`python-docx`, `scapy`); release packages and the first-run bootstrap now agree.
- Finding-ID prefixes registered for Zigbee (`ZIGBEE-###`), CoAP (`COAP-###`), and Z-Wave (`ZWAVE-###`) categories, which previously fell back to the generic `FIND-###`.

### Version 2.6.0 · May 2026 (patch 7)

Code quality and correctness fixes. No user-facing behavior changes.

- **CSV output correctness** — `export_flow_allowlist` and `export_device_inventory_csv` now use Python's `csv.writer` module instead of hand-built CSV strings. Fixes malformed output when device role or vendor fields contain double-quotes, commas, or newlines.
- **Purdue Detail SVG** — replaced overlapping bezier flow-arrow curves with a clean right-side panel listing the top connections in a readable striped table (Source IP → Dest IP, protocol, port, packet count, layer labels). SVG canvas width extended to 1330 px to accommodate the panel.
- **Documentation** — Purdue SVG filename tokens corrected in the output-files reference table (§10); tshark and Python installation instructions updated with Windows-specific steps in the User Guide and README.

### Version 2.6.0 · May 2026 (patch 6)

Purdue Detail SVG connection diagram redesigned.

- **Purdue Detail SVG flow arrows replaced** — the previous design drew up to 30 individual bezier curves between device centres, which overlapped into an unreadable tangle when many devices were present. The new design adds a 230 px right panel (separated by a vertical rule) listing the top connections in a striped table: Source IP → Dest IP, Protocol:Port, packet count, and source/destination layer labels. Scales to available diagram height (up to 16 rows).

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
