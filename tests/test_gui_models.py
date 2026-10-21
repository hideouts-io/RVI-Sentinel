#!/usr/bin/env python3
"""Integration-style tests for GUI request and report contracts."""

from __future__ import annotations

import copy
import json
import shutil
import struct
import tempfile
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Mapping
from unittest.mock import patch

import analysis_observations
from analysis_observations import PacketObservationCancelled, PacketObservations, summarize_packet_observations
from analyze import ReportDocument, analyze, load_baseline
from gui_models import (
    AnalysisRequest,
    ReportLoadCancelled,
    ReportValidationError,
    analyzer_arguments,
    load_report,
    load_report_cancellable,
    report_path_for,
    validate_request,
)
from packet_models import PacketRecord, decode_packet_fields, packet_values
from tests.dns_fixture import classic_dns_capture, dns_message, dns_transport
from tests.saved_capture_fixture import classic_capture, metadata_capture
from tests.session_fixture import transport_packet

REPO = Path(__file__).resolve().parents[1]


def sample_report(capture_path: Path) -> dict[str, object]:
    return {
        "capture": {
            "path": str(capture_path),
            "size_bytes": 128,
            "packet_count": 7,
            "first_packet": "2024-07-03T09:46:40+00:00",
            "last_packet": "2024-07-03T09:46:40.600000+00:00",
            "duration_seconds": 0.6,
        },
        "summary": {
            "unique_endpoints": 5,
            "unique_dns_queries": 2,
            "unique_tls_sni": 2,
            "quic_like_packets": 2,
            "new_endpoints": ["17.57.144.10"],
            "new_domains": ["www.example.com"],
            "new_tls_sni": ["example.apple.com"],
        },
        "top_endpoints": [["17.57.144.10", 2], ["10.0.0.2", 7]],
        "top_domains": [["www.example.com", 1]],
        "top_tls_sni": [["example.apple.com", 1]],
        "top_protocols": [["TLS", 2], ["DNS", 2]],
        "top_ports": [["443", 4], ["53", 2]],
        "top_transport_ports": [["tcp", "443", 4], ["udp", "53", 2]],
        "dns_entropy_findings": {
            "ajd83jf92ksla7d.example.org": {
                "max_label": "ajd83jf92ksla7d",
                "entropy": 3.75,
                "note": "Heuristic only; legitimate generated/CDN names can score highly.",
            }
        },
    }


def tls_client_hello(host: str) -> bytes:
    """Encode a minimal real TLS ClientHello with a recorded server name."""
    name = host.encode("ascii")
    names = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extension = struct.pack("!HH", 0, len(names)) + names
    body = b"\x03\x03" + bytes(range(32)) + b"\x00\x00\x02\x13\x01\x01\x00"
    body += struct.pack("!H", len(extension)) + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def observation_capture() -> bytes:
    """Build actual offline DNS, IPv6, TLS and UDP/443 traffic with existing helpers."""
    questions = (("Ajd83jf92ksla7d.Example.TEST", 1, 1), ("Second.TEST", 1, 1))
    query = dns_message(7, 0x0100, questions, (), (), ())
    response = dns_message(7, 0x8180, questions, (), (), ())
    ipv6 = dns_message(8, 0x0100, (("IPv6.TEST", 28, 1),), (), (), ())
    packets = (
        dns_transport("192.0.2.2", "192.0.2.53", 53000, 53, "udp", query, 0, 0),
        dns_transport("192.0.2.53", "192.0.2.2", 53, 53000, "udp", response, 0, 0),
        dns_transport("2001:db8::2", "2001:db8::53", 53001, 53, "udp", ipv6, 0, 0),
        transport_packet("192.0.2.2", "198.51.100.20", 54000, 443, "tcp", 100, 0, 24,
                         tls_client_hello("MiXeD.Example.TEST.")),
        transport_packet("192.0.2.2", "198.51.100.20", 54001, 443, "tcp", 200, 0, 24,
                         tls_client_hello("mixed.example.test")),
        transport_packet("192.0.2.2", "198.51.100.20", 54002, 443, "udp", 0, 0, 0, b"fixture"),
        transport_packet("198.51.100.20", "192.0.2.2", 443, 54002, "udp", 0, 0, 0, b"fixture"),
    )
    return classic_dns_capture(tuple((packet, index) for index, packet in enumerate(packets)))


def reject_report(path: Path, payload: Mapping[str, object], field: str) -> None:
    path.write_text(json.dumps(dict(payload)), encoding="utf-8")
    before = path.read_bytes()
    try:
        load_report(path)
    except ReportValidationError as error:
        assert not isinstance(error, ReportLoadCancelled)
        assert field in str(error), (field, str(error))
    else:
        raise AssertionError(f"Inconsistent {field} unexpectedly passed report validation.")
    assert path.read_bytes() == before


def check_reducer_occurrences() -> None:
    """Exercise layered/repeated fields that ordinary single-flow captures do not cover."""
    fields: dict[str, tuple[str, ...]] = {
        "frame.number": ("1",), "frame.time_epoch": ("1",), "frame.len": ("96",),
        "frame.protocols": ("ip:ipv6:tcp:udp",), "_ws.col.Protocol": ("custom-quic",),
        "ip.src": ("192.0.2.2", "192.0.2.2"), "ip.dst": ("192.0.2.53",),
        "ipv6.src": ("2001:0DB8:0:0:0:0:0:2",), "ipv6.dst": ("2001:db8::53",),
        "tcp.srcport": ("00443", "00443"), "tcp.dstport": ("53",),
        "udp.srcport": ("443",), "udp.dstport": ("443",),
        "dns.qry.name": (" Mixed.Test... ", "mixed.test", "."),
        "tls.handshake.extensions_server_name": (" MiXeD.Test. ", "mixed.test", "."),
    }
    packet = decode_packet_fields(fields, tuple(fields))
    before = copy.deepcopy(packet)
    result = summarize_packet_observations((packet,), threading.Event())
    assert packet == before
    assert result.endpoints == (("192.0.2.2", 2), ("192.0.2.53", 1), ("2001:db8::2", 1), ("2001:db8::53", 1))
    assert result.domains == (("mixed.test", 2),)
    assert result.tls_sni == (("mixed.test", 2),)
    assert result.protocols == (("custom-quic", 1),)
    assert result.ports == (("443", 4), ("53", 1))
    assert result.transport_ports == (("tcp", "443", 2), ("udp", "443", 2), ("tcp", "53", 1))
    assert result.quic_like_packets == 1
    for protocol, udp_port, expected in (("UDP", "00443", 0), ("UDP", "443", 1), ("custom-QUIC", "123", 1)):
        variant = fields | {"_ws.col.Protocol": (protocol,), "udp.srcport": (udp_port,), "udp.dstport": ("123",)}
        record = decode_packet_fields(variant, tuple(variant))
        assert summarize_packet_observations((record,), threading.Event()).quic_like_packets == expected
    assert summarize_packet_observations((), threading.Event()) == PacketObservations((), (), (), (), (), (), 0)
    try:
        setattr(result, "quic_like_packets", 0)
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("Packet observations must remain immutable.")
    cancelled = threading.Event()
    cancelled.set()
    try:
        summarize_packet_observations((), cancelled)
    except PacketObservationCancelled:
        pass
    else:
        raise AssertionError("Even an empty reduction must honor cancellation.")
    cancellation = threading.Event()
    visited_frames: list[int] = []

    def cancel_during_reduction(record: PacketRecord, field: str) -> tuple[str, ...]:
        visited_frames.append(record.frame_number)
        cancellation.set()
        return packet_values(record, field)

    with patch.object(analysis_observations, "packet_values", cancel_during_reduction):
        second_fields = fields | {"frame.number": ("2",)}
        second = decode_packet_fields(second_fields, tuple(second_fields))
        try:
            summarize_packet_observations((packet, second) * 500, cancellation)
        except PacketObservationCancelled:
            assert set(visited_frames) == {1}, "Cancellation must stop before the second bounded packet."
        else:
            raise AssertionError("In-progress packet reduction ignored cancellation.")


def check_saved_report_consistency(directory: Path) -> None:
    if shutil.which("tshark") is None:
        raise RuntimeError("GUI report evidence integration requires real TShark on PATH.")
    baseline = load_baseline(directory / "unwritten-baseline.json")
    original_baseline = copy.deepcopy(baseline)
    rich_document: ReportDocument | None = None
    for name, content in (("classic.pcap", classic_capture(3)), ("metadata.pcapng", metadata_capture()),
                          ("observations.pcap", observation_capture())):
        capture = directory / name
        capture.write_bytes(content)
        document = analyze(capture, baseline, 0.0)
        report_path = directory / (capture.stem + "-roundtrip.json")
        report_path.write_text(json.dumps(document), encoding="utf-8")
        serialized = report_path.read_bytes()
        report = load_report(report_path)
        assert report.evidence is not None
        assert report.evidence.packet_record_count == len(report.packets)
        observations = summarize_packet_observations(report.packets, threading.Event())
        assert observations.endpoints == tuple(document["top_endpoints"])
        assert observations.domains == tuple(document["top_domains"])
        assert observations.tls_sni == tuple(document["top_tls_sni"])
        assert observations.protocols == tuple(document["top_protocols"])
        assert observations.ports == tuple(document["top_ports"])
        assert observations.transport_ports == tuple(document["top_transport_ports"])
        assert observations.quic_like_packets == document["summary"]["quic_like_packets"]
        assert capture.read_bytes() == content
        assert report_path.read_bytes() == serialized
        if name == "observations.pcap":
            rich_document = document
            assert observations.domains == (("ajd83jf92ksla7d.example.test", 2), ("second.test", 2), ("ipv6.test", 1))
            assert observations.tls_sni == (("mixed.example.test", 2),)
            assert observations.quic_like_packets == 2
            assert report.entropy_findings[0].domain == "ajd83jf92ksla7d.example.test"
    assert baseline == original_baseline
    assert not (directory / "unwritten-baseline.json").exists()
    assert rich_document is not None
    check_inconsistent_reports(directory, rich_document)


def check_inconsistent_reports(directory: Path, document: ReportDocument) -> None:
    path = directory / "mutated-report.json"
    rejected = 0
    for field in ("unique_endpoints", "unique_dns_queries", "unique_tls_sni", "quic_like_packets"):
        summary: dict[str, object] = dict(document["summary"])
        original = summary[field]
        assert isinstance(original, int)
        summary[field] = original + 1
        reject_report(path, {**document, "summary": summary}, "summary." + field)
        rejected += 1
    for field, rows in (("top_endpoints", document["top_endpoints"]), ("top_domains", document["top_domains"]),
                        ("top_tls_sni", document["top_tls_sni"]), ("top_protocols", document["top_protocols"]),
                        ("top_ports", document["top_ports"])):
        first_value, first_count = rows[0]
        unobserved = "203.0.113.222" if field == "top_endpoints" else "unobserved.test"
        if field == "top_ports":
            unobserved = "65535"
        for replacement in (
            [(unobserved, first_count), *rows[1:]], [(first_value, first_count + 1), *rows[1:]],
            [(first_value, 0), *rows[1:]], [rows[0], *rows], rows[1:],
        ):
            reject_report(path, {**document, field: replacement}, field)
            rejected += 1
        if len(rows) > 1:
            reject_report(path, {**document, field: [rows[0], rows[0], *rows[2:]]}, field)
            reject_report(path, {**document, field: list(reversed(rows))}, field)
            rejected += 2
    transport_rows = document["top_transport_ports"]
    transport, port, count = transport_rows[0]
    for replacement_ports in (
        [(transport, port, count + 1), *transport_rows[1:]],
        [(transport, "65535", count), *transport_rows[1:]],
        [("tcp" if transport == "udp" else "udp", port, count), *transport_rows[1:]],
        [transport_rows[0], *transport_rows], transport_rows[1:],
        [transport_rows[0], transport_rows[0], *transport_rows[2:]], list(reversed(transport_rows)),
    ):
        reject_report(path, {**document, "top_transport_ports": replacement_ports}, "top_transport_ports")
        rejected += 1
    missing_transport: dict[str, object] = dict(document)
    del missing_transport["top_transport_ports"]
    reject_report(path, missing_transport, "top_transport_ports")
    rejected += 1
    for field, values, unobserved in (
        ("new_endpoints", document["summary"]["new_endpoints"], "203.0.113.222"),
        ("new_domains", document["summary"]["new_domains"], "unobserved.test"),
        ("new_tls_sni", document["summary"]["new_tls_sni"], "unobserved.test"),
    ):
        for replacement_values in ([*values, unobserved], [*values, values[0]]):
            reject_report(path, {**document, "summary": {**document["summary"], field: replacement_values}}, "summary." + field)
            rejected += 1
    for address in ("invalid-address", "999.1.2.3", "2001:db8::2%fixture", ""):
        reject_report(path, {**document, "top_endpoints": [(address, 1)]}, "top_endpoints")
        reject_report(path, {**document, "summary": {**document["summary"], "new_endpoints": [address]}}, "summary.new_endpoints")
        rejected += 2
    entropy = document["dns_entropy_findings"]
    reject_report(path, {**document, "dns_entropy_findings": {"unobserved.test": next(iter(entropy.values()))}}, "dns_entropy_findings")
    rejected += 1
    subset_summary = {**document["summary"], "new_endpoints": [], "new_domains": document["summary"]["new_domains"][:1], "new_tls_sni": []}
    path.write_text(json.dumps({**document, "summary": subset_summary}), encoding="utf-8")
    subset = load_report(path)
    assert not subset.summary.new_endpoints and not subset.summary.new_tls_sni
    assert len(subset.summary.new_domains) == 1
    path.write_text(json.dumps(document), encoding="utf-8")
    cancelled = threading.Event()
    cancelled.set()
    try:
        load_report_cancellable(path, cancelled)
    except ReportLoadCancelled:
        pass
    else:
        raise AssertionError("Cancelled report loading unexpectedly succeeded.")

    def cancel_observations(packets: tuple[PacketRecord, ...], cancellation: threading.Event) -> PacketObservations:
        cancellation.set()
        return summarize_packet_observations(packets, cancellation)

    with patch("gui_models.summarize_packet_observations", cancel_observations):
        try:
            load_report_cancellable(path, threading.Event())
        except ReportLoadCancelled as error:
            assert isinstance(error.__cause__, PacketObservationCancelled)
        else:
            raise AssertionError("Packet observation cancellation lost its report-load exception type.")
    print(f"PASS: {rejected} inconsistent saved v2 aggregates rejected")
    print("PASS: complete real-TShark PCAP/PCAPNG report roundtrips and observed new subsets")
    print("PASS: report observation cancellation retains ReportLoadCancelled and its cause")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="rvi-sentinel-gui-models-") as temp_directory:
        temporary_root = Path(temp_directory)
        capture = temporary_root / "authorized.pcapng"
        capture.write_bytes(b"synthetic GUI contract fixture\n")
        request = AnalysisRequest(
            capture_path=capture,
            baseline_path=temporary_root / "data" / "baseline.json",
            export_directory=temporary_root / "exports",
            entropy_threshold=3.5,
            top_count=20,
        )

        validate_request(request)
        arguments = analyzer_arguments(request, REPO / "analyze.py")
        assert arguments[0] == str(REPO / "analyze.py")
        assert arguments[1] == str(capture)
        assert arguments[-2:] == ["--top", "20"]

        report_path = report_path_for(request)
        report_path.parent.mkdir(parents=True)
        report_path.write_text(json.dumps(sample_report(capture)), encoding="utf-8")
        report = load_report(report_path)

        assert report.capture.packet_count == 7
        assert report.capture.duration_seconds == 0.6
        assert report.summary.unique_endpoints == 5
        assert report.endpoints[0].is_new is True
        assert report.endpoints[1].is_new is False
        assert report.domains[0].value == "www.example.com"
        assert report.tls_sni[0].is_new is True
        assert report.ports[0].transport == "TCP"
        assert report.ports[0].port == 443
        assert report.entropy_findings[0].entropy == 3.75

        invalid_report = temporary_root / "invalid.json"
        invalid_report.write_text('{"capture": {}}', encoding="utf-8")
        try:
            load_report(invalid_report)
        except ReportValidationError as error:
            assert "missing required field" in str(error)
        else:
            raise AssertionError("Invalid report unexpectedly passed validation.")

        invalid_report.write_bytes(b"\xff\xfe invalid UTF-8 report")
        try:
            load_report(invalid_report)
        except ReportValidationError as error:
            assert isinstance(error.__cause__, UnicodeDecodeError)
        else:
            raise AssertionError("Non-UTF-8 report unexpectedly passed validation.")

        for address in ("invalid-address", "999.1.2.3", "2001:db8::2%fixture", ""):
            legacy = sample_report(capture)
            reject_report(invalid_report, {**legacy, "top_endpoints": [[address, 1]]}, "top_endpoints")
            legacy_summary: dict[str, object] = {
                "unique_endpoints": 5, "unique_dns_queries": 2, "unique_tls_sni": 2, "quic_like_packets": 2,
                "new_endpoints": [address], "new_domains": [], "new_tls_sni": [],
            }
            reject_report(invalid_report, {**legacy, "summary": legacy_summary}, "summary.new_endpoints")
        check_reducer_occurrences()
        check_saved_report_consistency(temporary_root)

        print("PASS: GUI request validation")
        print("PASS: exact analyzer argument construction")
        print("PASS: report path derivation")
        print("PASS: typed report parsing")
        print("PASS: new-versus-known presentation data")
        print("PASS: invalid report rejection")
        print("PASS: invalid UTF-8 report returns a typed validation failure")
        print("PASS: legacy endpoint addresses fail during report validation")
        print("PASS: immutable occurrence reducer preserves canonical values, tie ordering and bounded cancellation")


if __name__ == "__main__":
    main()
