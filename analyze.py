#!/usr/bin/env python3
"""Passive saved-file summaries and traceable records; baseline writes are explicit."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import os
import signal
import sys
import threading
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import FrameType
from typing import Iterable, TypedDict

from analysis_baseline import (
    MAXIMUM_BASELINE_BYTES,
    BaselineDocument,
    BaselineValidationError,
    load_baseline as read_baseline,
    updated_domains,
    updated_endpoints,
    updated_tls_sni,
)
from packet_models import PacketDocument, PacketTimestamp, packet_document, packet_values
from captured_dns import DnsEvidenceDocument, dns_evidence_document
from saved_capture import SAVED_ANALYSIS_LIMITS, SavedAnalysisLimits, SavedCaptureError, read_saved_capture


class CaptureDocument(TypedDict):
    path: str
    size_bytes: int
    capture_id: str
    sha256: str
    integrity: str
    origin: str
    analyzed_at: str
    packet_count: int
    first_packet: str
    last_packet: str
    first_packet_epoch: str
    last_packet_epoch: str
    duration_seconds: float


class DecoderDocument(TypedDict):
    tshark_version: str
    supported_fields: list[str]
    unsupported_fields: list[str]
    active_resolution_enabled: bool
    container_fields: list[str]


class SummaryDocument(TypedDict):
    unique_endpoints: int
    unique_dns_queries: int
    unique_tls_sni: int
    quic_like_packets: int
    new_endpoints: list[str]
    new_domains: list[str]
    new_tls_sni: list[str]


class EntropyDocument(TypedDict):
    max_label: str
    entropy: float
    note: str


class ReportDocument(TypedDict):
    schema_version: int
    capture: CaptureDocument
    decoder: DecoderDocument
    packets: list[PacketDocument]
    dns_evidence: DnsEvidenceDocument
    summary: SummaryDocument
    top_endpoints: list[tuple[str, int]]
    top_domains: list[tuple[str, int]]
    top_tls_sni: list[tuple[str, int]]
    top_protocols: list[tuple[str, int]]
    top_ports: list[tuple[str, int]]
    top_transport_ports: list[tuple[str, str, int]]
    dns_entropy_findings: dict[str, EntropyDocument]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Counter[str] = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def dns_entropy(name: str) -> tuple[float, str]:
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        return 0.0, ""
    label = max(labels, key=len)
    return entropy(label), label


def load_baseline(path: Path) -> BaselineDocument:
    return read_baseline(path, utc_now())


def epoch_iso(timestamp: PacketTimestamp) -> str:
    """Keep existing microsecond display precision; exact decoded epochs are separate."""
    try:
        value = datetime.fromtimestamp(timestamp.seconds, tz=timezone.utc)
        return (value + timedelta(microseconds=timestamp.nanoseconds // 1000)).isoformat()
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError("Decoded packet epoch is outside the supported calendar range.") from error


def analyze_capture(pcap: Path, baseline: BaselineDocument, entropy_threshold: float,
                    limits: SavedAnalysisLimits, cancellation: threading.Event) -> ReportDocument:
    """Read a stable original and return complete evidence without changing baseline."""
    if not math.isfinite(entropy_threshold) or not 0.0 <= entropy_threshold <= 8.0:
        raise ValueError("Entropy threshold must be a finite number between 0.0 and 8.0.")
    decoded = read_saved_capture(pcap, limits, cancellation)
    endpoints: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    sni: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    transport_ports: Counter[tuple[str, str]] = Counter()
    suspicious_dns: dict[str, EntropyDocument] = {}
    quic_like = 0
    for record in decoded.packets:
        if cancellation.is_set():
            raise SavedCaptureError("cancelled", "Saved-file analysis was cancelled; no completed report or baseline update was produced.")
        for field in ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst"):
            endpoints.update(str(ipaddress.ip_address(value)) for value in packet_values(record, field))
        protocol_values = packet_values(record, "_ws.col.Protocol")
        protocol = protocol_values[0]
        protocols[protocol] += 1
        for transport, fields in (("tcp", ("tcp.srcport", "tcp.dstport")), ("udp", ("udp.srcport", "udp.dstport"))):
            for field in fields:
                for value in packet_values(record, field):
                    port = str(int(value))
                    ports[port] += 1
                    transport_ports[(transport, port)] += 1
        udp_ports = packet_values(record, "udp.srcport") + packet_values(record, "udp.dstport")
        if "443" in udp_ports or "QUIC" in protocol.upper():
            quic_like += 1
        for value in packet_values(record, "dns.qry.name"):
            domain = value.strip().lower().rstrip(".")
            if domain:
                domains[domain] += 1
                score, label = dns_entropy(domain)
                if score >= entropy_threshold and len(label) >= 12:
                    suspicious_dns[domain] = {
                        "max_label": label,
                        "entropy": round(score, 3),
                        "note": "Heuristic only; legitimate generated/CDN names can score highly.",
                    }
        for value in packet_values(record, "tls.handshake.extensions_server_name"):
            host = value.strip().lower().rstrip(".")
            if host:
                sni[host] += 1
    first = min((packet.timestamp for packet in decoded.packets), key=lambda epoch: (epoch.seconds, epoch.nanoseconds))
    last = max((packet.timestamp for packet in decoded.packets), key=lambda epoch: (epoch.seconds, epoch.nanoseconds))
    duration_nanoseconds = (last.seconds - first.seconds) * 1_000_000_000 + last.nanoseconds - first.nanoseconds
    return {
        "schema_version": 2,
        "capture": {
            "path": str(pcap),
            "size_bytes": decoded.size_bytes,
            "capture_id": "sha256:" + decoded.sha256,
            "sha256": decoded.sha256,
            "integrity": "verified",
            "origin": "imported_unknown",
            "analyzed_at": utc_now(),
            "packet_count": len(decoded.packets),
            "first_packet": epoch_iso(first),
            "last_packet": epoch_iso(last),
            "first_packet_epoch": first.epoch,
            "last_packet_epoch": last.epoch,
            "duration_seconds": round(duration_nanoseconds / 1_000_000_000, 3),
        },
        "decoder": {
            "tshark_version": decoded.tshark_version,
            "supported_fields": list(decoded.supported_fields),
            "unsupported_fields": list(decoded.unsupported_fields),
            "active_resolution_enabled": False,
            "container_fields": list(decoded.container_fields),
        },
        "packets": [packet_document(packet) for packet in decoded.packets],
        "dns_evidence": dns_evidence_document(decoded.dns_evidence),
        "summary": {
            "unique_endpoints": len(endpoints),
            "unique_dns_queries": len(domains),
            "unique_tls_sni": len(sni),
            "quic_like_packets": quic_like,
            "new_endpoints": sorted(set(endpoints) - set(baseline["endpoints"])),
            "new_domains": sorted(set(domains) - set(baseline["domains"])),
            "new_tls_sni": sorted(set(sni) - set(baseline["tls_sni"])),
        },
        "top_endpoints": endpoints.most_common(),
        "top_domains": domains.most_common(),
        "top_tls_sni": sni.most_common(),
        "top_protocols": protocols.most_common(),
        "top_ports": ports.most_common(),
        "top_transport_ports": [(transport, port, count) for (transport, port), count in transport_ports.most_common()],
        "dns_entropy_findings": suspicious_dns,
    }


def analyze(pcap: Path, baseline: BaselineDocument, entropy_threshold: float) -> ReportDocument:
    """Preserve the aggregate call contract while keeping the input baseline immutable."""
    return analyze_capture(pcap, baseline, entropy_threshold, SAVED_ANALYSIS_LIMITS, threading.Event())


def updated_baseline(baseline: BaselineDocument, report: ReportDocument) -> BaselineDocument:
    """Count reviewed analyses as before; new capture references identify exact bytes."""
    timestamp = report["capture"]["analyzed_at"]
    capture_id = report["capture"]["capture_id"]
    return {
        "schema_version": baseline["schema_version"],
        "created_at": baseline["created_at"],
        "updated_at": timestamp,
        "captures_analyzed": baseline["captures_analyzed"] + 1,
        "endpoints": updated_endpoints(baseline["endpoints"], dict(report["top_endpoints"]), timestamp, capture_id),
        "domains": updated_domains(baseline["domains"], dict(report["top_domains"]), timestamp, capture_id),
        "tls_sni": updated_tls_sni(baseline["tls_sni"], dict(report["top_tls_sni"]), timestamp, capture_id),
    }


def write_csv(path: Path, header: list[str], rows: Iterable[tuple[str, int]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)


def write_report(report: ReportDocument, pcap: Path, export_dir: Path) -> Path:
    """Write local outputs without following output links or replacing the original."""
    return save_report(report, pcap, export_dir, (pcap,), threading.Event())


def report_destinations(pcap: Path, export_dir: Path) -> tuple[Path, ...]:
    stem = pcap.stem
    return tuple(export_dir / f"{stem}_{suffix}" for suffix in ("report.json", "endpoints.csv", "dns.csv", "tls_sni.csv"))


def paths_alias(first: Path, second: Path) -> bool:
    if first.resolve() == second.resolve():
        return True
    return first.exists() and second.exists() and first.samefile(second)


def validate_destinations(destinations: tuple[Path, ...], protected: tuple[Path, ...]) -> None:
    """Refuse links, input aliases and overlapping report destinations before writes."""
    for index, destination in enumerate(destinations):
        if destination.is_symlink() or destination.exists() and not destination.is_file():
            raise SavedCaptureError("unsafe_destination", "An output destination is a link or nonregular file. Choose a separate regular output path.")
        if any(paths_alias(destination, source) for source in protected):
            raise SavedCaptureError("input_output_alias", "An output would replace the capture or selected baseline. Choose a separate export directory and baseline path.")
        if any(paths_alias(destination, other) for other in destinations[:index]):
            raise SavedCaptureError("output_alias", "Report output paths identify the same file. Choose an export directory without aliased outputs.")


def validate_preview_destinations(pcap: Path, baseline: Path, export_dir: Path) -> None:
    if paths_alias(pcap, baseline):
        raise SavedCaptureError("input_output_alias", "Capture and baseline must identify different files.")
    validate_destinations(report_destinations(pcap, export_dir), (pcap, baseline))


def validate_update_destinations(pcap: Path, baseline: Path, export_dir: Path) -> None:
    validate_preview_destinations(pcap, baseline, export_dir)
    validate_destinations((baseline,), (pcap,) + report_destinations(pcap, export_dir))


def check_save_cancellation(cancellation: threading.Event) -> None:
    if cancellation.is_set():
        raise SavedCaptureError("cancelled", "Analysis was cancelled before output publication; no baseline update was performed.")


def prepare_json(path: Path, document: ReportDocument | BaselineDocument, cancellation: threading.Event) -> None:
    """Write a task-owned staging file with explicit bytes and cancellation checks."""
    encoder = json.JSONEncoder(indent=2, sort_keys=True, allow_nan=False)
    byte_count = 0
    with path.open("w", encoding="utf-8") as stream:
        for chunk in encoder.iterencode(document):
            check_save_cancellation(cancellation)
            byte_count += len(chunk.encode("utf-8"))
            if byte_count > 536_870_912:
                raise SavedCaptureError("report_limit", "The serialized report exceeds its 512 MiB output limit. Choose a smaller capture.")
            stream.write(chunk)
        stream.flush()


def save_report(report: ReportDocument, pcap: Path, export_dir: Path, protected: tuple[Path, ...], cancellation: threading.Event) -> Path:
    destinations = report_destinations(pcap, export_dir)
    validate_destinations(destinations, protected)
    export_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rvi-sentinel-report-", dir=export_dir) as temporary:
        staged = tuple(Path(temporary) / destination.name for destination in destinations)
        prepare_json(staged[0], report, cancellation)
        write_csv(staged[1], ["endpoint", "packets"], report["top_endpoints"])
        write_csv(staged[2], ["domain", "queries"], report["top_domains"])
        write_csv(staged[3], ["hostname", "observations"], report["top_tls_sni"])
        check_save_cancellation(cancellation)
        validate_destinations(destinations, protected)
        # The complete JSON report is published last; an individual file is never truncated.
        for index in (1, 2, 3, 0):
            check_save_cancellation(cancellation)
            os.replace(staged[index], destinations[index])
    return destinations[0]


def save_baseline(path: Path, document: BaselineDocument, protected: tuple[Path, ...], cancellation: threading.Event) -> None:
    """Publish a complete baseline only while it remains within its read limit."""
    validate_destinations((path,), protected)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rvi-sentinel-baseline-", dir=path.parent) as temporary:
        staged = Path(temporary) / "baseline.json"
        prepare_json(staged, document, cancellation)
        if staged.stat().st_size > MAXIMUM_BASELINE_BYTES:
            raise BaselineValidationError("The updated baseline exceeds its 64 MiB input limit and was not published. Select a separate baseline for additional reviewed captures.")
        check_save_cancellation(cancellation)
        validate_destinations((path,), protected)
        os.replace(staged, path)


def print_summary(report: ReportDocument, report_path: Path, baseline_path: Path, top: int) -> None:
    summary = report["summary"]
    capture = report["capture"]
    print(f"Capture: {capture['path']}")
    print(f"Packets: {capture['packet_count']}")
    print(f"Duration: {capture['duration_seconds']} seconds")
    print(f"Original SHA-256: {capture['sha256']}")
    print(f"Decoder: {report['decoder']['tshark_version']} (passive; no PTR lookup)")
    print(f"Unique endpoints: {summary['unique_endpoints']} ({len(summary['new_endpoints'])} new)")
    print(f"Unique DNS names: {summary['unique_dns_queries']} ({len(summary['new_domains'])} new)")
    print(f"Unique TLS SNI: {summary['unique_tls_sni']} ({len(summary['new_tls_sni'])} new)")
    print(f"QUIC-like packets: {summary['quic_like_packets']}")
    print(f"Report: {report_path}")
    print(f"Baseline: {baseline_path}")
    if top > 0:
        print("\nTop endpoints:")
        for key, count in report["top_endpoints"][:top]:
            marker = " NEW" if key in summary["new_endpoints"] else ""
            print(f"  {count:>8}  {key}{marker}")
        print("\nTop DNS:")
        for key, count in report["top_domains"][:top]:
            marker = " NEW" if key in summary["new_domains"] else ""
            print(f"  {count:>8}  {key}{marker}")


def install_analysis_cancellation(cancellation: threading.Event) -> None:
    """CLI termination requests cooperative decoder cleanup instead of abandoning a child."""
    def cancel(_number: int, _frame: FrameType | None) -> None:
        cancellation.set()
    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGTERM, cancel)


def main() -> None:
    parser = argparse.ArgumentParser(description="RVI-Sentinel passive saved-file analysis with explicit baseline update.")
    parser.add_argument("pcap", type=Path, help="Saved PCAP, PCAPNG or CAP file")
    parser.add_argument("--baseline", type=Path, default=Path("data/findings_master.json"))
    parser.add_argument("--export-dir", type=Path, default=Path("exports"))
    parser.add_argument("--entropy-threshold", type=float, default=3.5)
    parser.add_argument("--top", type=int, default=20, help="Number of rows shown in console summaries")
    args = parser.parse_args()
    cancellation = threading.Event()
    install_analysis_cancellation(cancellation)
    try:
        validate_update_destinations(args.pcap, args.baseline, args.export_dir)
        baseline = load_baseline(args.baseline)
        report = analyze_capture(args.pcap, baseline, args.entropy_threshold, SAVED_ANALYSIS_LIMITS, cancellation)
        if cancellation.is_set():
            raise SavedCaptureError("cancelled", "Analysis was cancelled before saving; baseline unchanged.")
        report_path = save_report(report, args.pcap, args.export_dir, (args.pcap, args.baseline), cancellation)
        reviewed_baseline = updated_baseline(baseline, report)
        save_baseline(args.baseline, reviewed_baseline, (args.pcap,) + report_destinations(args.pcap, args.export_dir), cancellation)
        print_summary(report, report_path, args.baseline, args.top)
    except (SavedCaptureError, BaselineValidationError, OSError, ValueError) as error:
        print(f"Saved-file analysis failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
