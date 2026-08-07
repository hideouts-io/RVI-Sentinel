# RVI-Sentinel

**Persistent iOS Network Forensics and Packet Baseline Analysis for macOS**

RVI-Sentinel is a defensive network-analysis toolkit for inspecting packet captures over time, with first-class support for captures from a personally owned or authorized iPhone or iPad through Apple's Remote Virtual Interface (`rvictl`). It is intentionally split into two independent layers: **capture** and **analysis**. The analyzer works with ordinary `.pcap` or `.pcapng` files and does not require an iPhone, `rvictl`, or an active `rvi0` interface.

The guiding idea is simple:

> A packet capture shows what happened during one session. A persistent baseline shows what changed.

RVI-Sentinel records previously observed endpoints and hostnames so later captures can highlight infrastructure that is new to your local investigation history.

---

## Highlights

- Optional Apple `rvictl` workflow for USB-connected iPhone/iPad traffic capture.
- Analysis of existing PCAP/PCAPNG files from any authorized source.
- IPv4 and IPv6 endpoint inventory.
- TCP and UDP port frequency analysis.
- DNS query extraction.
- TLS Server Name Indication (SNI) extraction when visible.
- QUIC/HTTP/3-style traffic heuristics, including UDP/443 activity.
- DNS-label Shannon entropy heuristic for generated or encoded-looking names.
- Persistent first-seen / last-seen observations across captures.
- New-vs-known endpoint, DNS, and TLS-hostname detection.
- JSON investigation reports.
- CSV endpoint, DNS, and TLS-SNI exports.
- No TLS interception, certificate installation, or payload decryption required.
- A deterministic integration test that validates the analyzer without `rvictl` or `rvi0`.

---

## Architecture

```text
                           CAPTURE SOURCES

       ordinary PCAP      tcpdump/Wireshark       iPhone / iPad
             |                   |                     |
             |                   |                  USB trust
             |                   |                     |
             |                   |                  rvictl
             |                   |                     |
             |                   |                    rvi0
             +-------------------+---------------------+
                                 |
                                 v
                           PCAP / PCAPNG
                                 |
                                 v
                              tshark
                                 |
                  +--------------+--------------+
                  |              |              |
                  v              v              v
             IP / ports         DNS          TLS / QUIC
                  |              |              |
                  +--------------+--------------+
                                 |
                                 v
                            analyze.py
                                 |
                   +-------------+-------------+
                   |                           |
                   v                           v
              Current report             Persistent state
               JSON + CSV              findings_master.json
```

The key design rule is:

```text
CAPTURE LAYER != ANALYSIS LAYER
```

`rvictl` is one packet-acquisition method. It is **not** a dependency of the analysis engine.

---

## Requirements

### Python

Python 3.9+ is recommended. RVI-Sentinel currently uses only Python's standard library.

```bash
python3 --version
```

### tshark

Packet decoding is performed by `tshark`, the command-line component of Wireshark.

Check for it:

```bash
command -v tshark
tshark --version
```

On macOS, Wireshark can be installed with Homebrew:

```bash
brew install --cask wireshark
```

### Optional RVI tooling

Only the iPhone/iPad capture workflow requires Apple's RVI tooling.

Check:

```bash
command -v rvictl
xcrun xctrace list devices
```

`tcpdump` is included with macOS:

```bash
command -v tcpdump
```

---

## Installation

Clone the current repository into a local folder named `RVI-Sentinel`:

```bash
git clone https://github.com/hideouts-io/iOS-rvi_capture_analyzer.git RVI-Sentinel
cd RVI-Sentinel
```

Ensure the entry points are executable:

```bash
chmod +x analyze.py capture_rvi.sh tests/test_analyzer.py
```

Check the CLI:

```bash
python3 analyze.py --help
```

---

## Analyze a PCAP without RVI

You do not need an iPhone to use RVI-Sentinel.

Given an existing capture:

```text
capture.pcapng
```

run:

```bash
python3 analyze.py capture.pcapng
```

RVI-Sentinel writes a persistent baseline and investigation outputs:

```text
data/
└── findings_master.json

exports/
├── capture_report.json
├── capture_endpoints.csv
├── capture_dns.csv
└── capture_tls_sni.csv
```

Increase terminal output:

```bash
python3 analyze.py capture.pcapng --top 50
```

Use a separate baseline for a particular device, experiment, or investigation:

```bash
python3 analyze.py capture.pcapng \
  --baseline data/iphone_baseline.json \
  --export-dir exports/iphone
```

Compatible input files can come from Wireshark, `tcpdump`, `dumpcap`, an RVI session, a VM lab, or another authorized capture source supported by `tshark`.

---

## iPhone/iPad capture with Apple RVI

### 1. Connect the device

Connect your personally owned or otherwise authorized iPhone/iPad to the Mac over USB and accept the trust prompt if necessary.

### 2. Find the UDID

```bash
xcrun xctrace list devices
```

### 3. Start RVI

Using the helper:

```bash
./capture_rvi.sh start <UDID>
```

Or directly:

```bash
rvictl -s <UDID>
```

A virtual interface such as `rvi0` should appear:

```bash
ifconfig rvi0
```

### 4. Capture traffic

Using RVI-Sentinel:

```bash
./capture_rvi.sh capture captures/ios_capture.pcapng
```

Equivalent manual capture:

```bash
sudo tcpdump -i rvi0 -n -s 0 -U \
  -w captures/ios_capture.pcapng
```

Use the device normally while the capture is active. Press `Ctrl-C` when finished.

### 5. Analyze

```bash
python3 analyze.py captures/ios_capture.pcapng
```

### 6. Stop RVI

```bash
./capture_rvi.sh stop <UDID>
```

or:

```bash
rvictl -x <UDID>
```

---

## Persistent baselining

The default state database is JSON:

```text
data/findings_master.json
```

For each observed endpoint, DNS name, or visible TLS SNI value, RVI-Sentinel records data such as:

- first seen
- last seen
- observation count
- captures in which the item appeared
- most recent capture counts

Suppose capture one contains:

```text
17.57.144.10
1.1.1.1
gateway.icloud.com
```

After that baseline exists, a later capture containing:

```text
17.57.144.10
1.1.1.1
34.120.55.20
gateway.icloud.com
new.example.net
```

can surface:

```text
NEW ENDPOINT
34.120.55.20

NEW DNS NAME
new.example.net
```

This does not imply maliciousness. It tells the analyst where the capture differs from previous observations.

---

## Current analysis fields

RVI-Sentinel asks `tshark` for fields including:

```text
frame.time_epoch
ip.src
ip.dst
ipv6.src
ipv6.dst
tcp.srcport
tcp.dstport
udp.srcport
udp.dstport
dns.qry.name
tls.handshake.extensions_server_name
_ws.col.Protocol
```

These fields are then converted into summary statistics, persistent observations, and export files.

---

## QUIC detection

Modern iOS applications frequently use QUIC and HTTP/3. RVI-Sentinel currently uses a deliberately simple heuristic: packets are treated as QUIC-like when Wireshark classifies them as QUIC or when they use UDP port 443.

That is useful for traffic summarization, but it should not be treated as a definitive application classification.

---

## DNS entropy heuristic

RVI-Sentinel calculates Shannon entropy for the longest label in each observed DNS query. Long labels with relatively high entropy are added to the report as investigation leads.

Examples of things that may legitimately produce high-entropy labels include CDNs, telemetry services, anti-abuse systems, cloud-generated identifiers, tracking systems, and signed or tokenized URLs.

High entropy is therefore **not proof of DNS tunneling or compromise**. It is a prioritization signal for manual review.

---

## Encryption limitations

RVI packet visibility does not defeat modern transport or application encryption.

An analyst may still observe metadata such as source/destination addresses, ports, packet size, packet timing, connection frequency, unencrypted DNS, visible TLS SNI, and protocol classification while encrypted application content remains unavailable.

Visibility can also be reduced by technologies including TLS 1.3, Encrypted Client Hello (ECH), encrypted DNS, QUIC, VPNs, iCloud Private Relay, and application-specific encryption.

RVI-Sentinel intentionally does not attempt to bypass TLS, device security controls, or application encryption.

---

## Testing without `rvi0`

The repository includes a deterministic integration-style test:

```text
tests/test_analyzer.py
```

Run it with:

```bash
python3 tests/test_analyzer.py
```

The test does **not** connect to an iPhone, invoke `rvictl`, create `rvi0`, or capture live network traffic. Instead it creates a controlled fake `tshark` executable that supplies known packet-field output. That isolates and validates the analysis layer.

The test checks packet-field parsing, IPv4 endpoint tracking, DNS extraction, TLS SNI extraction, QUIC-like classification, DNS entropy heuristics, JSON/CSV exports, persistent baseline creation, and second-run known/new differentiation.

Expected completion:

```text
PASS: analyzer works without rvictl/rvi0
```

---

## Repository structure

```text
RVI-Sentinel/
├── analyze.py
├── capture_rvi.sh
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
├── tests/
│   └── test_analyzer.py
├── captures/
│   └── .gitkeep
├── data/
│   └── .gitkeep
└── exports/
    └── .gitkeep
```

---

## Privacy and evidence handling

PCAP files can contain sensitive network metadata even when payloads are encrypted. Captures may reveal hostnames, IP addresses, local addressing, connection timing, traffic volume, and service usage.

The default `.gitignore` excludes real captures, generated exports, and local baseline state. Do not commit real captures to a public repository unless you have intentionally reviewed and sanitized them.

---

## Troubleshooting

### `tshark was not found`

Install Wireshark and check:

```bash
command -v tshark
```

### `rvictl: command not found`

RVI availability depends on the Apple development/device tooling installed on the Mac. RVI is optional when analyzing an existing capture.

### No `rvi0` interface

Check device visibility:

```bash
xcrun xctrace list devices
```

Confirm the device is connected, trusted, and recognized before running `rvictl -s <UDID>`.

### DNS report is empty

Possible explanations include cached resolution, encrypted DNS, VPN use, Private Relay, direct-IP communication, or a capture that did not contain DNS requests.

### TLS SNI is missing

Modern TLS privacy features, particularly ECH, can reduce exposed hostname information.

---

## Roadmap

Potential future development areas include SQLite-backed persistent state, capture-to-capture diff reports, ASN/GeoIP enrichment, Apple infrastructure classification, iCloud Private Relay indicators, richer QUIC analysis, connection-flow reconstruction, HTML reports, dashboard mode, Wireshark display-filter helpers, synthetic PCAP fixtures for CI, GitHub Actions tests, and optional Zeek integration.

---

## Responsible use

Use RVI-Sentinel only with devices, networks, and packet captures you own or are explicitly authorized to inspect. Appropriate uses include personal iPhone/iPad diagnostics, defensive security testing, application troubleshooting, protocol research, lab exercises, incident investigation on authorized systems, and packet-analysis education.

---

## License

MIT. See [`LICENSE`](LICENSE).
