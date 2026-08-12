#!/usr/bin/env python3
"""Integration-style tests for GUI request and report contracts."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from gui_models import (
    AnalysisRequest,
    ReportValidationError,
    analyzer_arguments,
    load_report,
    report_path_for,
    validate_request,
)

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
        "dns_entropy_findings": {
            "ajd83jf92ksla7d.example.org": {
                "max_label": "ajd83jf92ksla7d",
                "entropy": 3.75,
                "note": "Heuristic only; legitimate generated/CDN names can score highly.",
            }
        },
    }


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
        assert report.entropy_findings[0].entropy == 3.75

        invalid_report = temporary_root / "invalid.json"
        invalid_report.write_text('{"capture": {}}', encoding="utf-8")
        try:
            load_report(invalid_report)
        except ReportValidationError as error:
            assert "missing required field" in str(error)
        else:
            raise AssertionError("Invalid report unexpectedly passed validation.")

        print("PASS: GUI request validation")
        print("PASS: exact analyzer argument construction")
        print("PASS: report path derivation")
        print("PASS: typed report parsing")
        print("PASS: new-versus-known presentation data")
        print("PASS: invalid report rejection")


if __name__ == "__main__":
    main()
