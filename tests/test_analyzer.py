#!/usr/bin/env python3
"""
Integration-style analyzer test that does not require rvictl, rvi0, or real packet capture.

It creates:
  - a dummy PCAP path (analyze.py only needs the file to exist before tshark reads it)
  - a fake tshark executable that emits deterministic tab-separated field output
  - isolated baseline/export directories

It then runs analyze.py twice and verifies persistent-newness behavior.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ANALYZER = REPO / "analyze.py"

FAKE_TSHARK = r'''#!/usr/bin/env python3
rows = [
    ["1720000000.000000", "10.0.0.2", "17.57.144.10", "", "", "53111", "443", "", "", "", "example.apple.com", "TLS"],
    ["1720000000.100000", "17.57.144.10", "10.0.0.2", "", "", "443", "53111", "", "", "", "", "TLS"],
    ["1720000000.200000", "10.0.0.2", "1.1.1.1", "", "", "", "", "5353", "53", "www.example.com", "", "DNS"],
    ["1720000000.300000", "1.1.1.1", "10.0.0.2", "", "", "", "", "53", "5353", "", "", "DNS"],
    ["1720000000.400000", "10.0.0.2", "203.0.113.40", "", "", "", "", "51000", "443", "", "api.example.net", "QUIC"],
    ["1720000000.500000", "203.0.113.40", "10.0.0.2", "", "", "", "", "443", "51000", "", "", "QUIC"],
    ["1720000000.600000", "10.0.0.2", "8.8.8.8", "", "", "", "", "53000", "53", "ajd83jf92ksla7d.example.org", "", "DNS"],
]
for row in rows:
    print("\t".join(row))
'''

def run_analyzer(env, pcap, baseline, exports):
    return subprocess.run(
        [
            "python3",
            str(ANALYZER),
            str(pcap),
            "--baseline",
            str(baseline),
            "--export-dir",
            str(exports),
            "--top",
            "0",
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

def main():
    with tempfile.TemporaryDirectory(prefix="rvi-sentinel-test-") as tmp:
        tmp = Path(tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()

        fake_tshark = bin_dir / "tshark"
        fake_tshark.write_text(FAKE_TSHARK, encoding="utf-8")
        fake_tshark.chmod(0o755)

        pcap = tmp / "synthetic.pcapng"
        pcap.write_bytes(b"synthetic fixture; fake tshark supplies decoded fields\n")

        baseline = tmp / "data" / "findings_master.json"
        exports = tmp / "exports"

        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

        first = run_analyzer(env, pcap, baseline, exports)
        assert first.returncode == 0, first.stderr or first.stdout

        report_path = exports / "synthetic_report.json"
        assert report_path.exists(), "JSON report was not created"
        assert baseline.exists(), "Persistent baseline was not created"
        assert (exports / "synthetic_endpoints.csv").exists()
        assert (exports / "synthetic_dns.csv").exists()
        assert (exports / "synthetic_tls_sni.csv").exists()

        report1 = json.loads(report_path.read_text(encoding="utf-8"))
        summary1 = report1["summary"]

        assert report1["capture"]["packet_count"] == 7
        assert summary1["unique_endpoints"] == 5
        assert summary1["unique_dns_queries"] == 2
        assert summary1["unique_tls_sni"] == 2
        assert summary1["quic_like_packets"] == 2
        assert "17.57.144.10" in summary1["new_endpoints"]
        assert "www.example.com" in summary1["new_domains"]
        assert "example.apple.com" in summary1["new_tls_sni"]
        assert "ajd83jf92ksla7d.example.org" in report1["dns_entropy_findings"]

        second = run_analyzer(env, pcap, baseline, exports)
        assert second.returncode == 0, second.stderr or second.stdout

        report2 = json.loads(report_path.read_text(encoding="utf-8"))
        summary2 = report2["summary"]

        assert summary2["new_endpoints"] == []
        assert summary2["new_domains"] == []
        assert summary2["new_tls_sni"] == []

        baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
        assert baseline_data["captures_analyzed"] == 2
        assert baseline_data["endpoints"]["17.57.144.10"]["observations"] == 2

        print("PASS: analyzer works without rvictl/rvi0")
        print("PASS: packet-field parsing")
        print("PASS: IPv4 endpoint tracking")
        print("PASS: DNS extraction")
        print("PASS: TLS SNI extraction")
        print("PASS: QUIC-like classification")
        print("PASS: DNS entropy heuristic")
        print("PASS: JSON/CSV exports")
        print("PASS: persistent baseline")
        print("PASS: second-run known/new differentiation")

if __name__ == "__main__":
    main()
