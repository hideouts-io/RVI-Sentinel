# RVI-Sentinel

### Cross-platform iPhone/iPad packet capture and persistent network-baseline analysis

<p align="center">
  <img src="assets/rvi-sentinel-logo.png" width="220" alt="RVI-Sentinel iOS packet-capture logo">
</p>

![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-000000?logo=apple&logoColor=white)
![Capture](https://img.shields.io/badge/capture-PCAP%20%7C%20PCAPNG-0969da)
![Analysis](https://img.shields.io/badge/analysis-tshark%20%2B%20persistent%20baseline-8250df)
![Test](https://img.shields.io/badge/analyzer-test%20passing-1a7f37)
![License](https://img.shields.io/badge/license-MIT-2da44e)

> **Scope:** RVI-Sentinel is a defensive, cross-platform toolkit for authorized iPhone/iPad packet capture and persistent network-baseline analysis. It combines Apple's native Remote Virtual Interface workflow on macOS with the upstream `gh2o/rvi_capture` backend on Linux and Windows, while keeping capture and analysis independent.

---

## Table of Contents

- [Overview](#overview)
- [Executive Summary](#executive-summary)
- [Overall Architecture](#overall-architecture)
- [Verified Analyzer Screenshot](#verified-analyzer-screenshot)
- [Installation](#installation)
- [Desktop GUI](#desktop-gui)
- [Analyze an Existing Capture](#analyze-an-existing-capture)
- [macOS Capture with Apple RVI](#macos-capture-with-apple-rvi)
- [Linux and Windows Capture](#linux-and-windows-capture)
- [Persistent Baselining](#persistent-baselining)
- [Current Analysis Fields](#current-analysis-fields)
- [Encryption Limitations](#encryption-limitations)
- [Testing Without Live Capture](#testing-without-live-capture)
- [Repository Structure](#repository-structure)
- [Privacy and Responsible Use](#privacy-and-responsible-use)
- [Evidence and Provenance](#evidence-and-provenance)
- [Conclusions](#conclusions)
- [Upstream Source](#upstream-source)
- [Community Standards](#community-standards)
- [License](#license)

---

## Overview

RVI-Sentinel is a defensive network-analysis toolkit for inspecting packet captures over time. It supports Apple's native Remote Virtual Interface (`rvictl`) workflow on macOS and integrates the upstream [`gh2o/rvi_capture`](https://github.com/gh2o/rvi_capture) project for iPhone/iPad packet capture on Linux and Windows.

The project deliberately separates **capture** from **analysis**:

> A packet capture shows what happened during one session. A persistent baseline shows what changed.

The analyzer works with ordinary `.pcap` and `.pcapng` files from any authorized source. An iPhone, `rvictl`, or `rvi0` is not required to use the analysis engine.

---

## Executive Summary

- macOS iPhone/iPad capture with Apple `rvictl` + `rvi0` + `tcpdump`.
- Linux and Windows iPhone/iPad capture through [`gh2o/rvi_capture`](https://github.com/gh2o/rvi_capture).
- PCAP and PCAPNG analysis through `tshark`.
- IPv4 and IPv6 endpoint inventory.
- TCP and UDP port-frequency analysis.
- DNS query extraction.
- TLS Server Name Indication (SNI) extraction when visible.
- QUIC/HTTP/3-style traffic heuristics, including UDP/443 activity.
- DNS-label Shannon entropy heuristic for generated or encoded-looking names.
- Persistent first-seen / last-seen observations across captures.
- New-vs-known endpoint, DNS, and TLS-hostname detection.
- JSON investigation reports and CSV exports.
- Deterministic integration test that validates analysis without live capture.

### Direct capability vs. interpretation

| Type | Finding |
|---|---|
| **Direct capability** | `capture_rvi.sh` drives Apple's `rvictl` / `rvi0` / `tcpdump` workflow on macOS. |
| **Direct capability** | `capture_mobile.py` integrates the separately fetched `gh2o/rvi_capture` backend for Linux and Windows. |
| **Direct capability** | `analyze.py` accepts authorized PCAP or PCAPNG input and produces persistent JSON plus CSV findings. |
| **Direct verification** | The deterministic analyzer integration test passes without an iPhone, `rvictl`, or `rvi0`. |
| **Interpretation boundary** | A newly observed endpoint or hostname is a baseline change, not proof of malicious activity. |
| **Visibility boundary** | Packet metadata does not defeat TLS, QUIC, VPNs, Private Relay, encrypted DNS, ECH, or application-layer encryption. |

---

## Overall Architecture

```mermaid
flowchart TB
    Device[iPhone / iPad]

    subgraph Hosts[Authorized capture host]
        Mac[macOS<br/>rvictl + rvi0 + tcpdump]
        Cross[Linux / Windows<br/>gh2o/rvi_capture]
    end

    Capture[PCAP / PCAPNG evidence]
    Tshark[tshark field extraction]
    GUI[PySide6 capture + analysis GUI]
    Analyzer[analyze.py CLI engine]
    Metadata[IP / ports / DNS / TLS SNI / QUIC heuristics]
    Report[Current JSON + CSV reports]
    Baseline[Persistent findings_master.json baseline]

    Device -->|USB| Mac
    Device -->|USB| Cross
    GUI -->|orchestrates| Mac
    GUI -->|orchestrates| Cross
    Mac --> Capture
    Cross --> Capture
    Capture --> GUI --> Analyzer
    Capture --> Analyzer
    Analyzer --> Tshark --> Metadata
    Metadata --> Report
    Metadata --> Baseline
```

The two capture paths converge on the same host-independent analysis pipeline.

<details>
<summary>Text-only architecture</summary>

```text
                              iPhone / iPad
                                   |
                                   | USB
                    +--------------+--------------+
                    |                             |
                  macOS                    Linux / Windows
                    |                             |
                 rvictl                    gh2o/rvi_capture
                    |                             |
                  rvi0                            |
                    |                             |
                 tcpdump                          |
                    +--------------+--------------+
                                   |
                                   v
                              PCAP / PCAPNG
                                   |
                                   v
                                tshark
                                   |
                      +------------+------------+
                      |            |            |
                      v            v            v
                 IP / ports       DNS       TLS / QUIC
                      |            |            |
                      +------------+------------+
                                   |
                                   v
                              analyze.py
                                   |
                      +------------+------------+
                      |                         |
                      v                         v
                 Current report            Persistent state
                  JSON + CSV              findings_master.json
```

</details>

The key design rule is:

```text
CAPTURE LAYER != ANALYSIS LAYER
```

---

## Verified Analyzer Screenshot

![RVI-Sentinel deterministic analyzer test](evidence/rvi-sentinel-analyzer-test.png)

The screenshot records the repository's deterministic analyzer integration test. It verifies packet-field parsing, IPv4 endpoint tracking, DNS and TLS SNI extraction, QUIC-like classification, DNS entropy handling, JSON/CSV exports, persistent baselining, and known/new differentiation without requiring live device capture.

---

## Installation

Clone RVI-Sentinel:

```bash
git clone https://github.com/hideouts-io/RVI-Sentinel.git
cd RVI-Sentinel
```

Check the analyzer:

```bash
python3 analyze.py --help
```

The CLI analyzer uses Python's standard library. Packet decoding requires `tshark`, the command-line component of Wireshark. The optional desktop GUI uses PySide6.

---

## Desktop GUI

The desktop GUI presents capture and analysis as two separate workspaces. It supports:

- recognizing physical iPhone/iPad devices and showing connected-versus-offline state;
- selecting a connected device in a guided capture dialog;
- choosing a bounded capture duration from 5 seconds to 60 minutes;
- choosing PCAPNG or PCAP and a local output path without overwriting existing evidence;
- macOS readiness checks through Apple `devicectl`, followed by `rvictl`, a temporary RVI interface, and `tcpdump`;
- Linux/Windows capture through the separately installed `gh2o/rvi_capture` backend;
- live progress, activity output, cancellation, and platform-specific errors;
- optional automatic handoff from a completed capture into analysis;

- selecting or dropping an authorized PCAP, PCAPNG, or CAP file;
- choosing a persistent baseline and export directory;
- configuring the DNS entropy threshold and console result count;
- displaying the exact `analyze.py` command before execution;
- live analyzer output and actionable process errors;
- summary, endpoint, DNS, TLS SNI, protocol, port, and entropy-heuristic views;
- PTR reverse-DNS names and address-scope labels for every endpoint;
- optional local MaxMind-compatible GeoIP city/country lookup without a web API;
- TCP/UDP-aware service labels and plain-language port explanations;
- a report-specific Interpretation view that explains scope, caveats, and next steps;
- explicit new-versus-known baseline labels;
- opening the generated export directory.

Create a project-local environment and install the optional GUI dependency:

```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements-gui.txt
```

Use the non-hidden `venv/` directory shown above. In macOS File Provider-managed folders, a dot-prefixed environment such as `.venv/` can propagate the hidden file flag to Qt plugins and prevent the Cocoa platform plugin from being discovered.

Launch the GUI:

```bash
./scripts/run_gui.sh
```

On macOS, the launcher builds and ad-hoc signs a lightweight runtime app wrapper in the system temporary directory, outside a File Provider-managed Documents checkout. It starts with the project icon so RVI-Sentinel has its own Dock identity while all source, captures, baselines, and exports remain at their selected project paths. The generated wrapper stays outside version control and is recreated by `scripts/run_gui.sh`.

The app opens on **Capture iPhone/iPad**. Connect the device by USB, unlock it, trust the host if prompted, and choose **Refresh Devices**. **New Capture…** opens a dialog for the device, duration, format, output path, and automatic-analysis choice. Offline devices are recognized but cannot be selected until connected.

On macOS, the timed capture requires a physical, booted, paired iPhone/iPad connected over USB. It then uses a narrow native administrator authorization prompt for `tcpdump`; RVI-Sentinel never asks for, reads, stores, or transmits the Mac password. The countdown stays stopped while authorization is pending and during a five-second live-packet preflight. Completed captures are closed, checked for the requested PCAP/PCAPNG header, and required to contain at least one readable packet before automatic analysis begins. The temporary RVI interface is removed after success, failure, or cancellation.

On Linux and Windows, choose **Install Capture Support** once to clone the canonical `gh2o/rvi_capture` source into the ignored local `tools/` directory. Linux still requires `libimobiledevice` and `usbmuxd`; Windows still requires iTunes or Apple Mobile Device Support and its running service.

Optionally open an existing capture immediately:

```bash
./scripts/run_gui.sh captures/authorized-capture.pcapng
```

Analysis requires the same `tshark` runtime dependency as the CLI analyzer. Live capture follows the platform-specific prerequisites below and never bypasses device trust, host authorization, or encryption.

### Local GeoIP setup

Geolocation is deliberately local-only: RVI-Sentinel never sends captured endpoint IP addresses to a geolocation web API. To add approximate locations, download a current MaxMind-compatible City or Country `.mmdb` database, keep it outside version control (the repository's `data/` contents are ignored), and choose it in **Local GeoIP database** before analysis. MaxMind provides [GeoLite downloadable databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) after account and license-key setup.

IP geolocation is approximate. It often represents a network or nearby population center and must not be interpreted as the exact location of a device, person, or household. PTR hostnames are also attribution hints rather than proof: they may be absent, generic, stale, shared, or controlled by a hosting provider. Reverse-DNS resolution sends PTR queries for the observed addresses to the Mac's configured DNS resolver.

### GUI screenshots

These screenshots use a deterministic synthetic report and documentation-only sample values. No private capture, endpoint list, baseline, or generated report is included.

#### Endpoint names, scope, and approximate location

![RVI-Sentinel endpoint enrichment view](evidence/rvi-sentinel-gui-endpoints.png)

The Endpoints view keeps packet counts and baseline status alongside PTR hostname hints, address scope, and optional local-only GeoIP results.

#### Transport-aware port labels

![RVI-Sentinel transport-aware ports view](evidence/rvi-sentinel-gui-ports.png)

TCP and UDP observations remain distinct so the GUI can explain common uses such as TCP/443 HTTPS, UDP/443 QUIC/HTTP/3, UDP/53 DNS, TCP/5223 Apple Push Service, and TCP/62078 iOS lockdown. A conventional port label is context, not proof that a particular process or server was present.

#### Plain-language findings interpretation

![RVI-Sentinel findings interpretation view](evidence/rvi-sentinel-gui-interpretation.png)

The Interpretation view explains the report-specific counts, new-versus-known baseline changes, endpoint-attribution limits, port observations, encrypted traffic, and entropy findings without turning a heuristic or newly observed value into a malicious verdict.

---

## Analyze an Existing Capture

Given:

```text
capture.pcapng
```

run:

```bash
python3 analyze.py capture.pcapng
```

Outputs are written to:

```text
data/findings_master.json

exports/
├── capture_report.json
├── capture_endpoints.csv
├── capture_dns.csv
└── capture_tls_sni.csv
```

Use a dedicated baseline for one device or investigation:

```bash
python3 analyze.py capture.pcapng \
  --baseline data/iphone_baseline.json \
  --export-dir exports/iphone
```

---

## macOS Capture with Apple RVI

Connect and trust the iPhone/iPad over USB.

Find its UDID:

```bash
xcrun xctrace list devices
```

Start RVI:

```bash
./capture_rvi.sh start <UDID>
```

or directly:

```bash
rvictl -s <UDID>
```

A virtual interface such as `rvi0` should appear:

```bash
ifconfig rvi0
```

Capture:

```bash
./capture_rvi.sh capture captures/ios_capture.pcapng
```

Equivalent manual command:

```bash
sudo tcpdump -i rvi0 -n -s 0 -U --apple-pcapng -Z "$USER" \
  -w captures/ios_capture.pcapng
```

Analyze:

```bash
python3 analyze.py captures/ios_capture.pcapng
```

Stop RVI:

```bash
./capture_rvi.sh stop <UDID>
```

---

## Linux and Windows Capture

### Capture with `gh2o/rvi_capture`

RVI-Sentinel integrates the open-source project:

**https://github.com/gh2o/rvi_capture**

The upstream project describes itself as **`rvictl for Linux and Windows`** and creates packet-capture dumps from connected iOS devices. It supports both PCAP and PCAPNG, optional UDID selection, file/FIFO output, stdout streaming, and direct Wireshark streaming.

RVI-Sentinel does **not** copy the upstream Python implementation into this repository. Instead, the setup helper clones the canonical source directly so provenance remains clear.

Install the upstream capture backend locally:

```bash
python3 scripts/setup_rvi_capture.py
```

It is placed at:

```text
tools/rvi_capture/
```

That directory is intentionally ignored by Git.

Update the upstream checkout later with:

```bash
python3 scripts/setup_rvi_capture.py --update
```

The setup helper prints the exact upstream commit SHA so you can record which capture implementation produced a packet trace.

See [`SOURCES.md`](SOURCES.md) for attribution and provenance details.

---

## Linux prerequisites

Upstream documents the following requirements:

- Python 3
- `libimobiledevice`
- `usbmuxd` running

On Debian/Ubuntu-derived systems, a typical starting point is:

```bash
sudo apt update
sudo apt install python3 libimobiledevice-utils usbmuxd
```

Confirm that the connected device is visible:

```bash
idevice_id -l
```

Install the upstream backend:

```bash
python3 scripts/setup_rvi_capture.py
```

Capture an iPhone/iPad to PCAPNG:

```bash
python3 capture_mobile.py \
  captures/iphone_linux.pcapng
```

Select a particular device:

```bash
python3 capture_mobile.py \
  --udid <IPHONE_UDID> \
  captures/iphone_linux.pcapng
```

Capture and immediately analyze:

```bash
python3 capture_mobile.py \
  --analyze \
  captures/iphone_linux.pcapng
```

---

## Windows prerequisites

Upstream documents the following requirements:

- Python 3
- iTunes / Apple mobile-device components
- `AppleMobileDeviceService.exe` running

The upstream project states that its required `libimobiledevice` components are downloaded as needed on Windows.

From PowerShell:

```powershell
python scripts\setup_rvi_capture.py
```

Capture:

```powershell
python capture_mobile.py `
  captures\iphone_windows.pcapng
```

Specify the UDID:

```powershell
python capture_mobile.py `
  --udid <IPHONE_UDID> `
  captures\iphone_windows.pcapng
```

Capture and analyze in one workflow:

```powershell
python capture_mobile.py `
  --analyze `
  captures\iphone_windows.pcapng
```

---

## Direct upstream usage

After running the setup helper, you can invoke upstream `rvi_capture.py` directly.

Linux:

```bash
python3 tools/rvi_capture/rvi_capture.py \
  --format pcapng \
  --udid <IPHONE_UDID> \
  captures/iphone.pcapng
```

Windows PowerShell:

```powershell
python tools\rvi_capture\rvi_capture.py `
  --format pcapng `
  --udid <IPHONE_UDID> `
  captures\iphone.pcapng
```

If `--udid` is omitted, upstream selects the first device it finds.

Then analyze normally:

```bash
python3 analyze.py captures/iphone.pcapng
```

---

## Stream directly into Wireshark

The upstream project can write capture data to stdout:

```bash
./tools/rvi_capture/rvi_capture.py - | wireshark -k -i -
```

For RVI-Sentinel investigations, saving a PCAPNG first is often preferable because it creates a repeatable evidence artifact that can be re-analyzed later.

---

## iOS interface metadata

PCAPNG can retain interface metadata. The upstream `rvi_capture` documentation discusses iOS interfaces such as:

```text
en0       Wi-Fi
pdp_ip0   cellular
ipsec1    IPSec outer transport observed for VoLTE
ipsec3    IPSec inner transport observed for VoLTE
```

In Wireshark, inspect:

```text
frame.interface_name
```

This can help distinguish traffic paths when the capture includes the relevant metadata.

---

## Cross-platform capture matrix

| Host OS | iPhone/iPad capture backend | Output | RVI-Sentinel analysis |
|---|---|---|---|
| macOS | Apple `rvictl` + `tcpdump` | PCAP/PCAPNG | Yes |
| Linux | `gh2o/rvi_capture` + `libimobiledevice`/`usbmuxd` | PCAP/PCAPNG | Yes |
| Windows | `gh2o/rvi_capture` + Apple mobile-device services | PCAP/PCAPNG | Yes |
| Any analysis host | Existing authorized PCAP/PCAPNG | PCAP/PCAPNG | Yes |

---

## Persistent Baselining

The default state database is:

```text
data/findings_master.json
```

For observed endpoints, DNS names, and visible TLS SNI values, RVI-Sentinel records historical context including first seen, last seen, observation counts, capture membership, and recent capture counts.

This allows a later capture to distinguish previously observed infrastructure from newly observed infrastructure.

A new endpoint or hostname is **not automatically suspicious**. It is simply a change worth contextualizing.

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

---

## Encryption limitations

RVI packet visibility does not defeat TLS, QUIC, VPN encryption, iCloud Private Relay, encrypted DNS, ECH, or application-layer encryption.

You may still observe useful metadata such as source/destination addresses, ports, timing, traffic volume, unencrypted DNS, visible TLS SNI, and protocol classifications.

RVI-Sentinel does not attempt to bypass device security controls or decrypt protected application content.

---

## Testing without live capture

Run:

```bash
python3 tests/test_analyzer.py
python3 -m tests.test_capture_models
python3 -m tests.test_gui_models
python3 -m tests.test_finding_enrichment
QT_QPA_PLATFORM=offscreen venv/bin/python -m tests.test_gui_integration
```

The automated tests do not connect to an iPhone, invoke `rvictl`, create `rvi0`, request administrator authorization, or capture live traffic. They validate physical-device readiness parsing, bounded capture requests, Apple PCAP/PCAPNG mode selection, clean termination, post-capture header checks, countdown/finalization state, deterministic `tshark` field output, and the analysis layer independently. Live validation remains an explicit local action because it requires a connected trusted device and native authorization.

The GUI integration test uses the same deterministic field stream to exercise Qt process execution, report loading, and results presentation without displaying a window or requiring live capture.

Expected completion includes:

```text
PASS: analyzer works without rvictl/rvi0
```

---

## Repository structure

```text
RVI-Sentinel/
├── analyze.py
├── capture_models.py          # typed device and bounded capture contracts
├── capture_devices.py         # macOS/Linux/Windows device discovery
├── capture_session.py         # timed platform-aware capture runner
├── enrich_endpoints.py        # bounded PTR and local GeoIP enrichment process
├── finding_enrichment.py      # address, location, and port explanations
├── gui.py                     # PySide6 capture and analysis desktop UI
├── gui_models.py              # typed request/report validation
├── capture_rvi.sh             # macOS rvictl/rvi0 capture
├── capture_mobile.py          # Linux/Windows frontend
├── scripts/
│   ├── run_gui.sh             # launch GUI from project environment
│   └── setup_rvi_capture.py   # fetch canonical gh2o/rvi_capture source
├── evidence/
│   └── rvi-sentinel-analyzer-test.png
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── feature_request.yml
│   │   └── config.yml
│   └── pull_request_template.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── SECURITY.md
├── SOURCES.md                 # upstream provenance/attribution
├── README.md
├── requirements.txt
├── requirements-gui.txt
├── LICENSE
├── .gitignore
├── tests/
│   ├── test_analyzer.py
│   ├── test_capture_models.py
│   ├── test_finding_enrichment.py
│   ├── test_gui_integration.py
│   └── test_gui_models.py
├── captures/
├── data/
├── exports/
└── tools/
    └── rvi_capture/           # local upstream clone; intentionally ignored
```

---

## Privacy and responsible use

Packet captures and device identifiers can reveal sensitive metadata even when payloads are encrypted. The repository ignores PCAP files, generated reports, local baselines, and the local upstream checkout by default. The GUI keeps capture files and device identifiers local and does not upload them.

Endpoint geolocation uses only the local `.mmdb` file selected by the user. RVI-Sentinel does not send captures, reports, DNS names, SNI values, or endpoint lists to a geolocation web API. PTR hostname resolution does query the Mac's configured DNS resolver for each observed endpoint.

Use RVI-Sentinel only with devices, networks, and packet captures you own or are explicitly authorized to inspect.

---

## Evidence and Provenance

This repository keeps capture provenance, analysis output, and interpretation separate:

| Layer | Evidence or record |
|---|---|
| **Capture implementation** | macOS uses Apple `rvictl` and `tcpdump`; Linux and Windows use a separately cloned canonical `gh2o/rvi_capture` checkout. |
| **Backend provenance** | `scripts/setup_rvi_capture.py` prints the exact upstream commit SHA after installation. |
| **Packet evidence** | PCAP or PCAPNG files remain independent inputs that can be retained and re-analyzed. |
| **Current findings** | JSON and CSV exports describe the supplied capture. |
| **Historical context** | The persistent baseline records first seen, last seen, counts, and capture membership. |
| **Verification evidence** | `tests/test_capture_models.py` validates discovery/capture contracts without a device; `tests/test_analyzer.py` validates analysis deterministically; the screenshot above records a passing analyzer run. |

Live device capture depends on the host OS, USB trust state, and the platform-specific prerequisites documented above. The deterministic test verifies the analysis pipeline, not a live macOS, Linux, or Windows device session.

For third-party attribution and redistribution boundaries, see [`SOURCES.md`](SOURCES.md).

---

## Conclusions

RVI-Sentinel provides three host capture paths with one common analysis model:

- macOS capture through Apple's native RVI tooling.
- Linux capture through `gh2o/rvi_capture`, `libimobiledevice`, and `usbmuxd`.
- Windows capture through `gh2o/rvi_capture` and Apple mobile-device services.
- Host-independent analysis of existing authorized PCAP and PCAPNG evidence.
- Persistent comparison of endpoints, DNS names, and visible TLS SNI across captures.
- Explicit limits: baseline changes require context, and encrypted content remains protected.

The central design principle is that capture produces evidence, while analysis and persistent baselining explain how that evidence differs from earlier observations.

---

## Upstream Source

Linux/Windows iOS capture functionality is provided by the separately maintained upstream project:

https://github.com/gh2o/rvi_capture

RVI-Sentinel's integration code does not claim authorship of that implementation. See [`SOURCES.md`](SOURCES.md).

---

## Community Standards

- Read the [Code of Conduct](CODE_OF_CONDUCT.md) before participating.
- Follow the [Contributing Guidelines](CONTRIBUTING.md) for setup, validation, privacy, and pull-request expectations.
- Report vulnerabilities privately through the [Security Policy](SECURITY.md).
- Use the structured GitHub issue forms for bugs and feature requests.

Never publish private captures, generated reports, baseline data, endpoint inventories, device identifiers, credentials, or unsanitized investigation logs in an issue or pull request.

---

## License

RVI-Sentinel's own project code is MIT licensed. See [`LICENSE`](LICENSE). Upstream dependencies retain their own copyright and licensing status.
