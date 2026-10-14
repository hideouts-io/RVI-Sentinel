#!/usr/bin/env python3
"""Typed GUI request and report models for RVI-Sentinel."""

from __future__ import annotations

import json
import math
import re
import threading
import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, cast

from analyze import epoch_iso
from packet_models import PCAPNG_PROCESS_FIELDS, PacketRecord, PacketTimestamp, PacketValidationError, estimated_packet_bytes, validate_packet_document
from captured_dns import CapturedDnsEvidence, CapturedDnsValidationError, CapturedDnsCancelled, validate_dns_evidence_document
from saved_capture import OPTIONAL_FIELDS, PROTOCOL_FIELDS, REQUIRED_FIELDS

CAPTURE_SUFFIXES = frozenset({".cap", ".pcap", ".pcapng"})


class RequestValidationError(ValueError):
    """Raised when GUI analysis inputs are invalid."""


class ReportValidationError(ValueError):
    """Raised when an analyzer report does not match the required schema."""


@dataclass(frozen=True)
class AnalysisRequest:
    capture_path: Path
    baseline_path: Path
    export_directory: Path
    entropy_threshold: float
    top_count: int


@dataclass(frozen=True)
class RankedFinding:
    value: str
    count: int
    is_new: bool


@dataclass(frozen=True)
class PortFinding:
    transport: str
    port: int
    count: int


@dataclass(frozen=True)
class EntropyFinding:
    domain: str
    max_label: str
    entropy: float
    note: str


@dataclass(frozen=True)
class CaptureDetails:
    path: str
    size_bytes: int
    packet_count: int
    first_packet: str | None
    last_packet: str | None
    duration_seconds: float | None


@dataclass(frozen=True)
class AnalysisSummary:
    unique_endpoints: int
    unique_dns_queries: int
    unique_tls_sni: int
    quic_like_packets: int
    new_endpoints: frozenset[str]
    new_domains: frozenset[str]
    new_tls_sni: frozenset[str]


@dataclass(frozen=True)
class AnalysisEvidence:
    sha256: str
    tshark_version: str
    supported_field_count: int
    supported_fields: tuple[str, ...]
    unsupported_fields: tuple[str, ...]
    packet_record_count: int
    origin: str
    integrity: str


@dataclass(frozen=True)
class AnalysisReport:
    capture: CaptureDetails
    summary: AnalysisSummary
    endpoints: tuple[RankedFinding, ...]
    domains: tuple[RankedFinding, ...]
    tls_sni: tuple[RankedFinding, ...]
    protocols: tuple[RankedFinding, ...]
    ports: tuple[PortFinding, ...]
    entropy_findings: tuple[EntropyFinding, ...]
    evidence: AnalysisEvidence | None
    packets: tuple[PacketRecord, ...]
    dns_evidence: CapturedDnsEvidence | None


def validate_request(request: AnalysisRequest) -> None:
    if not request.capture_path.is_file():
        raise RequestValidationError(f"Capture file not found: {request.capture_path}")
    if request.capture_path.suffix.lower() not in CAPTURE_SUFFIXES:
        supported = ", ".join(sorted(CAPTURE_SUFFIXES))
        raise RequestValidationError(
            f"Unsupported capture extension: {request.capture_path.suffix or '(none)'}. "
            f"Expected one of: {supported}"
        )
    if request.baseline_path.exists() and not request.baseline_path.is_file():
        raise RequestValidationError(f"Baseline path is not a file: {request.baseline_path}")
    if request.export_directory.exists() and not request.export_directory.is_dir():
        raise RequestValidationError(
            f"Export directory path is not a directory: {request.export_directory}"
        )
    if not math.isfinite(request.entropy_threshold) or request.entropy_threshold < 0.0 or request.entropy_threshold > 8.0:
        raise RequestValidationError("Entropy threshold must be between 0.0 and 8.0.")
    if request.top_count < 0 or request.top_count > 500:
        raise RequestValidationError("Top result count must be between 0 and 500.")


def analyzer_arguments(request: AnalysisRequest, analyzer_path: Path) -> list[str]:
    validate_request(request)
    return [
        str(analyzer_path),
        str(request.capture_path),
        "--baseline",
        str(request.baseline_path),
        "--export-dir",
        str(request.export_directory),
        "--entropy-threshold",
        str(request.entropy_threshold),
        "--top",
        str(request.top_count),
    ]


def report_path_for(request: AnalysisRequest) -> Path:
    return request.export_directory / f"{request.capture_path.stem}_report.json"


class ReportLoadCancelled(ReportValidationError):
    """The caller cancelled loading before a completed report was returned."""


def check_report_cancellation(cancellation: threading.Event) -> None:
    if cancellation.is_set():
        raise ReportLoadCancelled("Report loading was cancelled; no completed report was returned.")


def report_file_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def unique_report_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReportValidationError("Analyzer report contains a duplicate JSON property.")
        result[key] = value
    return result


def load_report(path: Path) -> AnalysisReport:
    """Load a validated report synchronously for CLI and non-UI callers."""
    return load_report_cancellable(path, threading.Event())


def load_report_cancellable(path: Path, cancellation: threading.Event) -> AnalysisReport:
    """Read a stable bounded report and retain its validated immutable packet evidence.

    GUI callers run this connector in an owned worker. JSON decoding itself is a
    bounded library operation; cancellation is checked around it and throughout
    packet validation. No capture, baseline or export is modified.
    """
    check_report_cancellation(cancellation)
    try:
        expected = path.lstat()
        if not stat.S_ISREG(expected.st_mode) or not 0 < expected.st_size <= 536_870_912:
            raise ReportValidationError("Analyzer report must be a nonempty regular file within the 512 MiB report limit; links and special files are not accepted.")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        with ExitStack() as cleanup:
            descriptor = os.open(path, flags)
            cleanup.callback(os.close, descriptor)
            stream = cleanup.enter_context(os.fdopen(descriptor, "rb", closefd=False))
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or report_file_identity(before) != report_file_identity(expected):
                raise ReportValidationError("Analyzer report changed while opening. Run analysis again before reviewing it.")
            content = bytearray()
            while True:
                check_report_cancellation(cancellation)
                chunk = stream.read(1_048_576)
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > 536_870_912:
                    raise ReportValidationError("Analyzer report exceeded the 512 MiB report limit while reading.")
            after = os.fstat(stream.fileno())
            current = path.lstat()
            if not stat.S_ISREG(current.st_mode) or report_file_identity(before) != report_file_identity(after) or report_file_identity(before) != report_file_identity(current):
                raise ReportValidationError("Analyzer report changed while reading. Run analysis again before reviewing it.")
        check_report_cancellation(cancellation)

        def checked_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            check_report_cancellation(cancellation)
            return unique_report_object(pairs)

        payload: object = json.loads(content.decode("utf-8"), object_pairs_hook=checked_object)
        del content
        check_report_cancellation(cancellation)
    except FileNotFoundError as error:
        raise ReportValidationError(f"Analyzer report not found: {path}") from error
    except UnicodeDecodeError as error:
        raise ReportValidationError(f"Analyzer report is not valid UTF-8: {path}") from error
    except ReportValidationError:
        raise
    except (ValueError, RecursionError) as error:
        raise ReportValidationError("Analyzer report is not valid bounded JSON.") from error
    except OSError as error:
        raise ReportValidationError(f"Could not read analyzer report: {path}: {error}") from error

    root = require_mapping(payload, "report")
    capture_data = require_mapping(require_field(root, "capture", "report"), "capture")
    summary_data = require_mapping(require_field(root, "summary", "report"), "summary")

    new_endpoints = require_string_set(
        require_field(summary_data, "new_endpoints", "summary"), "summary.new_endpoints"
    )
    new_domains = require_string_set(
        require_field(summary_data, "new_domains", "summary"), "summary.new_domains"
    )
    new_tls_sni = require_string_set(
        require_field(summary_data, "new_tls_sni", "summary"), "summary.new_tls_sni"
    )

    capture = CaptureDetails(
        path=require_string(require_field(capture_data, "path", "capture"), "capture.path"),
        size_bytes=require_integer(
            require_field(capture_data, "size_bytes", "capture"), "capture.size_bytes"
        ),
        packet_count=require_integer(
            require_field(capture_data, "packet_count", "capture"), "capture.packet_count"
        ),
        first_packet=require_optional_string(
            require_field(capture_data, "first_packet", "capture"), "capture.first_packet"
        ),
        last_packet=require_optional_string(
            require_field(capture_data, "last_packet", "capture"), "capture.last_packet"
        ),
        duration_seconds=require_optional_number(
            require_field(capture_data, "duration_seconds", "capture"),
            "capture.duration_seconds",
        ),
    )

    summary = AnalysisSummary(
        unique_endpoints=require_integer(
            require_field(summary_data, "unique_endpoints", "summary"),
            "summary.unique_endpoints",
        ),
        unique_dns_queries=require_integer(
            require_field(summary_data, "unique_dns_queries", "summary"),
            "summary.unique_dns_queries",
        ),
        unique_tls_sni=require_integer(
            require_field(summary_data, "unique_tls_sni", "summary"),
            "summary.unique_tls_sni",
        ),
        quic_like_packets=require_integer(
            require_field(summary_data, "quic_like_packets", "summary"),
            "summary.quic_like_packets",
        ),
        new_endpoints=new_endpoints,
        new_domains=new_domains,
        new_tls_sni=new_tls_sni,
    )

    evidence, packets = parse_packet_evidence(root, capture_data, capture.packet_count, cancellation)
    dns_evidence: CapturedDnsEvidence | None = None
    if "dns_evidence" in root:
        if evidence is None:
            raise ReportValidationError("Structured DNS evidence requires capture-bound packet records.")
        try:
            dns_evidence = validate_dns_evidence_document(root["dns_evidence"], evidence.sha256, packets, cancellation)
        except CapturedDnsCancelled as error:
            raise ReportLoadCancelled("Report DNS validation was cancelled.") from error
        except CapturedDnsValidationError as error:
            raise ReportValidationError(f"Structured DNS report evidence is invalid: {error}") from error
    check_report_cancellation(cancellation)
    return AnalysisReport(
        capture=capture,
        summary=summary,
        endpoints=parse_ranked_findings(
            require_field(root, "top_endpoints", "report"), "top_endpoints", new_endpoints
        ),
        domains=parse_ranked_findings(
            require_field(root, "top_domains", "report"), "top_domains", new_domains
        ),
        tls_sni=parse_ranked_findings(
            require_field(root, "top_tls_sni", "report"), "top_tls_sni", new_tls_sni
        ),
        protocols=parse_ranked_findings(
            require_field(root, "top_protocols", "report"),
            "top_protocols",
            frozenset(),
        ),
        ports=parse_port_findings(root),
        entropy_findings=parse_entropy_findings(
            require_field(root, "dns_entropy_findings", "report")
        ),
        evidence=evidence,
        packets=packets,
        dns_evidence=dns_evidence,
    )


def require_mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ReportValidationError(f"{field} must be a JSON object.")
    mapping = cast(dict[object, object], value)
    for key in mapping:
        if not isinstance(key, str):
            raise ReportValidationError(f"{field} contains a non-string key.")
    return cast(dict[str, object], value)


def require_nonnegative_integer(value: object, field: str) -> int:
    number = require_integer(value, field)
    if number < 0:
        raise ReportValidationError(f"{field} must be nonnegative.")
    return number


def evidence_texts(value: object, field: str) -> tuple[str, ...]:
    rows = require_list(value, field)
    if len(rows) > 128:
        raise ReportValidationError(f"{field} exceeds the 128-field coverage limit.")
    texts = tuple(require_string(row, field) for row in rows)
    if any(not text or len(text) > 256 or any(ord(character) < 32 for character in text) for text in texts):
        raise ReportValidationError(f"{field} contains invalid field text.")
    if len(set(texts)) != len(texts):
        raise ReportValidationError(f"{field} contains duplicate fields.")
    return texts


def parse_analysis_evidence(root: Mapping[str, object], capture: Mapping[str, object], packet_count: int) -> AnalysisEvidence | None:
    """Preserve the evidence-only API while validated GUI reports retain packets."""
    evidence, _packets = parse_packet_evidence(root, capture, packet_count, threading.Event())
    return evidence


def parse_packet_evidence(root: Mapping[str, object], capture: Mapping[str, object], packet_count: int,
                          cancellation: threading.Event) -> tuple[AnalysisEvidence | None, tuple[PacketRecord, ...]]:
    """Legacy summaries have no packet records; v2 retains complete typed evidence."""
    if "schema_version" not in root:
        return None, ()
    version = require_integer(root["schema_version"], "schema_version")
    if version != 2:
        raise ReportValidationError(f"Unsupported report schema version: {version}.")
    sha256 = require_string(require_field(capture, "sha256", "capture"), "capture.sha256")
    if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise ReportValidationError("capture.sha256 must be a lowercase SHA-256 digest.")
    capture_id = require_string(require_field(capture, "capture_id", "capture"), "capture.capture_id")
    if capture_id != "sha256:" + sha256:
        raise ReportValidationError("Capture identity does not match its digest.")
    integrity = require_string(require_field(capture, "integrity", "capture"), "capture.integrity")
    origin = require_string(require_field(capture, "origin", "capture"), "capture.origin")
    if integrity != "verified" or origin != "imported_unknown":
        raise ReportValidationError("Saved-file reports must retain verified bytes and unknown imported origin.")
    decoder = require_mapping(require_field(root, "decoder", "report"), "decoder")
    if require_field(decoder, "active_resolution_enabled", "decoder") is not False:
        raise ReportValidationError("Saved-file analysis must not enable active resolution.")
    tshark_version = require_string(require_field(decoder, "tshark_version", "decoder"), "decoder.tshark_version")
    if not tshark_version or len(tshark_version) > 512 or any(ord(character) < 32 for character in tshark_version):
        raise ReportValidationError("decoder.tshark_version contains invalid text.")
    supported = evidence_texts(require_field(decoder, "supported_fields", "decoder"), "decoder.supported_fields")
    unsupported = evidence_texts(require_field(decoder, "unsupported_fields", "decoder"), "decoder.unsupported_fields")
    container_fields = evidence_texts(decoder["container_fields"], "decoder.container_fields") if "container_fields" in decoder else ()
    if container_fields not in ((), PCAPNG_PROCESS_FIELDS):
        raise ReportValidationError("Container coverage must be absent or the complete Apple PCAPNG process field schema.")
    if set(supported) & set(unsupported):
        raise ReportValidationError("Decoder fields cannot be both supported and unsupported.")
    if not set(REQUIRED_FIELDS).issubset(supported) or len(set(PROTOCOL_FIELDS).intersection(supported)) != 1:
        raise ReportValidationError("Decoder coverage is missing required packet identity fields.")
    if not set(OPTIONAL_FIELDS).issubset(set(supported) | set(unsupported)) or not set(unsupported).issubset(OPTIONAL_FIELDS):
        raise ReportValidationError("Decoder coverage must account for every requested optional field.")
    if not set(supported).issubset(set(REQUIRED_FIELDS) | set(PROTOCOL_FIELDS) | set(OPTIONAL_FIELDS)):
        raise ReportValidationError("Decoder coverage contains fields outside this report's requested schema.")
    records = require_list(require_field(root, "packets", "report"), "packets")
    if not 0 < len(records) <= 200_000 or len(records) != packet_count:
        raise ReportValidationError("Packet record count must match the complete capture count and stay within the index limit.")
    frames: set[int] = set()
    timestamps: list[PacketTimestamp] = []
    packets: list[PacketRecord] = []
    retained_bytes = 0
    for index, value in enumerate(records):
        check_report_cancellation(cancellation)
        try:
            packet = validate_packet_document(value)
        except PacketValidationError as error:
            raise ReportValidationError(f"packets[{index}] is not valid traceable packet evidence: {error}") from error
        retained_bytes += estimated_packet_bytes(packet)
        if retained_bytes > 268_435_456:
            raise ReportValidationError("Packet evidence exceeds the 256 MiB retained-value limit.")
        packets.append(packet)
        frame = packet.frame_number
        if frame == 0 or frame in frames:
            raise ReportValidationError("Packet frame identities must be positive and unique within the original.")
        frames.add(frame)
        timestamps.append(packet.timestamp)
        if any(field.name not in supported + container_fields for field in packet.fields):
            raise ReportValidationError("Packet fields must be present in decoder or independently declared container coverage.")
    if frames != set(range(1, len(records) + 1)):
        raise ReportValidationError("Complete saved-file reports must retain every contiguous frame identity.")
    first = min(timestamps, key=lambda epoch: (epoch.seconds, epoch.nanoseconds))
    last = max(timestamps, key=lambda epoch: (epoch.seconds, epoch.nanoseconds))
    expected_duration = round(((last.seconds - first.seconds) * 1_000_000_000 + last.nanoseconds - first.nanoseconds) / 1_000_000_000, 3)
    if require_field(capture, "first_packet_epoch", "capture") != first.epoch or require_field(capture, "last_packet_epoch", "capture") != last.epoch:
        raise ReportValidationError("Capture epoch bounds do not match the retained packet records.")
    try:
        first_display = epoch_iso(first)
        last_display = epoch_iso(last)
    except ValueError as error:
        raise ReportValidationError("Packet epoch cannot be represented as the report's display time.") from error
    if capture.get("first_packet") != first_display or capture.get("last_packet") != last_display or capture.get("duration_seconds") != expected_duration:
        raise ReportValidationError("Capture display times or duration do not match the retained packet records.")
    evidence = AnalysisEvidence(
        sha256=sha256,
        tshark_version=tshark_version,
        supported_field_count=len(supported),
        supported_fields=supported,
        unsupported_fields=unsupported,
        packet_record_count=len(records),
        origin=origin,
        integrity=integrity,
    )
    check_report_cancellation(cancellation)
    return evidence, tuple(packets)


def require_field(mapping: Mapping[str, object], key: str, field: str) -> object:
    if key not in mapping:
        raise ReportValidationError(f"{field} is missing required field: {key}")
    return mapping[key]


def require_list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise ReportValidationError(f"{field} must be a JSON array.")
    return cast(list[object], value)


def require_string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ReportValidationError(f"{field} must be a string.")
    return value


def require_optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    return require_string(value, field)


def require_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReportValidationError(f"{field} must be an integer.")
    if value < 0:
        raise ReportValidationError(f"{field} must be nonnegative.")
    return value


def require_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportValidationError(f"{field} must be a number.")
    converted = float(value)
    if not math.isfinite(converted):
        raise ReportValidationError(f"{field} must be finite.")
    if converted < 0:
        raise ReportValidationError(f"{field} must be nonnegative.")
    return converted


def require_optional_number(value: object, field: str) -> float | None:
    if value is None:
        return None
    return require_number(value, field)


def require_string_set(value: object, field: str) -> frozenset[str]:
    items = require_list(value, field)
    return frozenset(require_string(item, f"{field}[]") for item in items)


def parse_ranked_findings(
    value: object, field: str, new_values: frozenset[str]
) -> tuple[RankedFinding, ...]:
    rows = require_list(value, field)
    findings: list[RankedFinding] = []
    for index, row_value in enumerate(rows):
        row = require_list(row_value, f"{field}[{index}]")
        if len(row) != 2:
            raise ReportValidationError(f"{field}[{index}] must contain exactly two values.")
        finding_value = require_string(row[0], f"{field}[{index}][0]")
        count = require_integer(row[1], f"{field}[{index}][1]")
        findings.append(
            RankedFinding(
                value=finding_value,
                count=count,
                is_new=finding_value in new_values,
            )
        )
    return tuple(findings)


def parse_port_findings(root: Mapping[str, object]) -> tuple[PortFinding, ...]:
    if "top_transport_ports" not in root:
        legacy_rows = parse_ranked_findings(
            require_field(root, "top_ports", "report"), "top_ports", frozenset()
        )
        return tuple(
            PortFinding(transport="TCP/UDP", port=parse_port(row.value), count=row.count)
            for row in legacy_rows
        )

    rows = require_list(root["top_transport_ports"], "top_transport_ports")
    findings: list[PortFinding] = []
    for index, row_value in enumerate(rows):
        row = require_list(row_value, f"top_transport_ports[{index}]")
        if len(row) != 3:
            raise ReportValidationError(
                f"top_transport_ports[{index}] must contain exactly three values."
            )
        transport = require_string(row[0], f"top_transport_ports[{index}][0]").upper()
        if transport not in {"TCP", "UDP"}:
            raise ReportValidationError(
                f"top_transport_ports[{index}][0] must be TCP or UDP."
            )
        port = parse_port(require_string(row[1], f"top_transport_ports[{index}][1]"))
        count = require_integer(row[2], f"top_transport_ports[{index}][2]")
        findings.append(PortFinding(transport=transport, port=port, count=count))
    return tuple(findings)


def parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise ReportValidationError(f"Port must be a decimal integer: {value}") from error
    if port < 0 or port > 65535:
        raise ReportValidationError(f"Port must be between 0 and 65535: {value}")
    return port


def parse_entropy_findings(value: object) -> tuple[EntropyFinding, ...]:
    mapping = require_mapping(value, "dns_entropy_findings")
    findings: list[EntropyFinding] = []
    for domain in sorted(mapping):
        details = require_mapping(mapping[domain], f"dns_entropy_findings.{domain}")
        findings.append(
            EntropyFinding(
                domain=domain,
                max_label=require_string(
                    require_field(details, "max_label", domain), f"{domain}.max_label"
                ),
                entropy=require_number(
                    require_field(details, "entropy", domain), f"{domain}.entropy"
                ),
                note=require_string(require_field(details, "note", domain), f"{domain}.note"),
            )
        )
    return tuple(findings)
