# Upstream Sources

RVI-Sentinel uses external capture tooling without silently absorbing its source code.

## gh2o/rvi_capture

Canonical source:

https://github.com/gh2o/rvi_capture

Purpose:

- iPhone/iPad packet capture on Linux
- iPhone/iPad packet capture on Windows
- PCAP and PCAPNG output
- device selection by UDID
- streaming to files, FIFOs, stdout, or Wireshark

The upstream project describes itself as `rvictl for Linux and Windows` and documents the following host requirements:

### Linux

- Python 3
- `libimobiledevice`
- `usbmuxd` running

### Windows

- Python 3
- iTunes / Apple mobile-device components
- `AppleMobileDeviceService.exe` running

RVI-Sentinel does not vendor the upstream `rvi_capture.py` file in this repository. As of August 7, 2026, the upstream GitHub repository does not expose a separate LICENSE file in its top-level file listing. To avoid misrepresenting redistribution rights, RVI-Sentinel's setup helper clones the canonical repository directly into a local ignored dependency directory.

Install locally with:

```bash
python3 scripts/setup_rvi_capture.py
```

Update later with:

```bash
python3 scripts/setup_rvi_capture.py --update
```

The setup helper prints the exact upstream commit SHA after cloning so an investigation can record which capture implementation produced a PCAP.

## Data flow

```text
Linux / Windows
      |
      v
gh2o/rvi_capture
      |
      v
PCAP / PCAPNG
      |
      v
RVI-Sentinel analyze.py
      |
      +--> endpoint inventory
      +--> DNS observations
      +--> TLS SNI observations
      +--> QUIC-like traffic
      +--> persistent baseline
      +--> JSON/CSV reports
```

## Attribution

All upstream `rvi_capture` implementation credit belongs to its original author/contributors. RVI-Sentinel's `capture_mobile.py` and setup helper are integration code written for this project; they do not claim authorship of the upstream capture implementation.
