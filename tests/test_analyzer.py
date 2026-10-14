#!/usr/bin/env python3
"""
Deterministic process-contract test, separate from real-TShark integration.

It creates:
  - a format-generated saved PCAP path
  - a fake tshark executable that emits deterministic tab-separated field output
  - isolated baseline/export directories

It then runs analyze.py twice and verifies persistent-newness behavior.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from tests.saved_capture_fixture import classic_capture

ANALYZER = REPO / "analyze.py"

FAKE_TSHARK = r'''#!/usr/bin/env python3
import csv
import json
import os
import sys
import time
from pathlib import Path

arguments = sys.argv[1:]
mode = os.environ.get("RVI_TEST_TSHARK_MODE", "normal")
log_path = os.environ.get("RVI_TEST_TSHARK_LOG")
if log_path:
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(arguments) + "\n")
if "--version" in arguments:
    print("TShark (Wireshark) deterministic test connector 1.0")
    raise SystemExit(0)
fields = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len",
    "frame.protocols", "_ws.col.Protocol", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "dns.qry.name",
    "tls.handshake.extensions_server_name", "frame.darwin.process_info.pid",
    "frame.darwin.process_info.pname", "frame.interface_name", "frame.packet_flags_direction",
    "tcp.stream", "udp.stream", "tcp.seq_raw", "tcp.ack_raw",
)
if "-G" in arguments:
    for field in fields:
        if mode == "missing_required" and field == "frame.time_epoch":
            continue
        if mode == "missing_optional" and field == "frame.darwin.process_info.pname":
            continue
        print("F\tTest field\t" + field + "\tFT_STRING\tframe\t\t0x0\t")
    raise SystemExit(0)
if "-n" not in arguments:
    print("The test decoder forbids name resolution.", file=sys.stderr)
    raise SystemExit(90)
if mode in {"timeout", "cancel"}:
    time.sleep(30)
if mode in {"grow_source", "change_source"}:
    path = Path(os.environ["RVI_TEST_TSHARK_SOURCE"])
    content = path.read_bytes()
    path.write_bytes(content + b"x" if mode == "grow_source" else bytes([content[0] ^ 1]) + content[1:])
if mode == "stderr_limit":
    os.write(2, b"diagnostic " * 10000)
if mode == "both_pipes":
    os.write(2, b"test diagnostic\n" * 1000)
if mode == "malformed_utf8":
    os.write(1, b"\xff\n")
    raise SystemExit(0)
rows = [
    ["1720000000.000000001", "192.0.2.2", "198.51.100.10", "", "", "53111", "443", "", "", "", "handshake.test", "TLS"],
    ["1720000000.100000002", "198.51.100.10", "192.0.2.2", "", "", "443", "53111", "", "", "", "", "TLS"],
    ["1720000000.200000003", "192.0.2.2", "192.0.2.53", "", "", "", "", "5353", "53", "www.test", "", "DNS"],
    ["1720000000.300000004", "192.0.2.53", "192.0.2.2", "", "", "", "", "53", "5353", "", "", "DNS"],
    ["1720000000.400000005", "192.0.2.2", "203.0.113.40", "", "", "", "", "51000", "443", "", "api.test", "QUIC"],
    ["1720000000.500000006", "203.0.113.40", "192.0.2.2", "", "", "", "", "443", "51000", "", "", "QUIC"],
    ["1720000000.600000007", "192.0.2.2", "198.51.100.53", "", "", "", "", "53000", "53", "ajd83jf92ksla7d.test", "", "DNS"],
]
legacy_fields = ("frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "dns.qry.name", "tls.handshake.extensions_server_name", "_ws.col.Protocol")
output_rows = rows * 100 if mode == "both_pipes" else rows
if "json" in arguments:
    packets = []
    for index, row in enumerate(output_rows, 1):
        if row[-1] != "DNS":
            continue
        response = row[8] != "53"
        question = {"dns.qry.name": row[9], "dns.qry.type": "1", "dns.qry.class": "0x0001"}
        protocol = "ip:udp:dns" if mode != "conflict_ambiguous" else "ip:ip:udp:dns"
        message = {"dns.id": "0x0007", "dns.flags": "0x8180" if response else "0x0100",
                   "dns.flags_tree": {"dns.flags.response": "1" if response else "0", "dns.flags.truncated": "0", "dns.flags.opcode": "0"},
                   "dns.count.queries": "1" if row[9] else "0", "dns.count.answers": "0", "dns.count.add_rr": "0"}
        if row[9]:
            message["Queries"] = {row[9]: question}
        if response:
            message["dns.response_to"] = str(index - 1)
        packets.append({"_source": {"layers": {
            "frame": {"frame.number": str(index), "frame.time_epoch": row[0], "frame.len": "60", "frame.protocols": protocol},
            "dns": message}}})
    print(json.dumps(packets))
    raise SystemExit(0)
selected = [arguments[index + 1] for index, value in enumerate(arguments[:-1]) if value == "-e"]
writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL)
for index, row in enumerate(output_rows, 1):
    record = dict(zip(legacy_fields, row))
    record.update({"frame.number": str(index), "frame.len": "60", "frame.cap_len": "60", "frame.protocols": "ip:tcp:tls" if row[-1] == "TLS" else "ip:udp:" + row[-1].lower(), "frame.darwin.process_info.pid": "343", "frame.darwin.process_info.pname": "fixture-maild", "frame.interface_name": "fixture0", "frame.packet_flags_direction": "0x00000002", "tcp.stream": "0" if row[-1] == "TLS" else "", "udp.stream": "1" if row[-1] == "DNS" else "2"})
    if mode == "invalid_pid":
        record["frame.darwin.process_info.pid"] = "-1"
    if mode == "invalid_port":
        record["tcp.srcport"] = "70000"
    if mode == "invalid_timestamp":
        record["frame.time_epoch"] = "1720000000.1234567890"
    if mode == "duplicate_frame":
        record["frame.number"] = "1"
    if mode == "frame_gap" and index == 2:
        record["frame.number"] = "3"
    if mode == "conflict_ambiguous":
        record["frame.darwin.process_info.pid"] = "343\x1e344"
        record["frame.darwin.process_info.pname"] = "fixture-maild\x1eother-label"
        record["ip.src"] += "\x1e192.0.2.3"
        record["frame.protocols"] = "ip:" + record["frame.protocols"]
    values = [record.get(field, "") for field in selected]
    writer.writerow(values[:-1] if mode == "wrong_columns" else values)
'''

def run_analyzer(env: Mapping[str, str], pcap: Path, baseline: Path, exports: Path) -> subprocess.CompletedProcess[str]:
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
        timeout=20,
    )

def main() -> None:
    with tempfile.TemporaryDirectory(prefix="rvi-sentinel-test-") as tmp:
        tmp = Path(tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()

        fake_tshark = bin_dir / "tshark"
        fake_tshark.write_text(FAKE_TSHARK, encoding="utf-8")
        fake_tshark.chmod(0o755)

        pcap = tmp / "synthetic.pcap"
        pcap.write_bytes(classic_capture(7))

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
        assert "198.51.100.10" in summary1["new_endpoints"]
        assert "www.test" in summary1["new_domains"]
        assert "handshake.test" in summary1["new_tls_sni"]
        assert "ajd83jf92ksla7d.test" in report1["dns_entropy_findings"]
        assert ["tcp", "443", 2] in report1["top_transport_ports"]
        assert ["udp", "53", 3] in report1["top_transport_ports"]

        second = run_analyzer(env, pcap, baseline, exports)
        assert second.returncode == 0, second.stderr or second.stdout

        report2 = json.loads(report_path.read_text(encoding="utf-8"))
        summary2 = report2["summary"]

        assert summary2["new_endpoints"] == []
        assert summary2["new_domains"] == []
        assert summary2["new_tls_sni"] == []

        baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
        assert baseline_data["captures_analyzed"] == 2
        assert baseline_data["endpoints"]["198.51.100.10"]["observations"] == 2

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
