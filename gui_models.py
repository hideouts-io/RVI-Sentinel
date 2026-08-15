#!/usr/bin/env python3
"""Typed GUI request and report models for RVI-Sentinel."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, cast

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
class AnalysisReport:
    capture: CaptureDetails
    summary: AnalysisSummary
    endpoints: tuple[RankedFinding, ...]
    domains: tuple[RankedFinding, ...]
    tls_sni: tuple[RankedFinding, ...]
    protocols: tuple[RankedFinding, ...]
    ports: tuple[PortFinding, ...]
    entropy_findings: tuple[EntropyFinding, ...]


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
    if request.entropy_threshold < 0.0 or request.entropy_threshold > 8.0:
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


def load_report(path: Path) -> AnalysisReport:
    try:
        payload: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ReportValidationError(f"Analyzer report not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ReportValidationError(
            f"Analyzer report is not valid JSON: {path}: {error}"
        ) from error
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
    )


def require_mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ReportValidationError(f"{field} must be a JSON object.")
    mapping = cast(dict[object, object], value)
    for key in mapping:
        if not isinstance(key, str):
            raise ReportValidationError(f"{field} contains a non-string key.")
    return cast(dict[str, object], value)


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
    return value


def require_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportValidationError(f"{field} must be a number.")
    return float(value)


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
