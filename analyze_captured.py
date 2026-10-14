#!/usr/bin/env python3
"""Preview only the original bytes identified by a verified capture receipt."""

from __future__ import annotations

import argparse
import re
import sys
import threading
from pathlib import Path

from analysis_baseline import BaselineValidationError
from analyze import (
    analyze_capture, install_analysis_cancellation, load_baseline,
    print_summary, save_report, validate_preview_destinations,
)
from saved_capture import SAVED_ANALYSIS_LIMITS, SavedCaptureError


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Passively preview capture-receipt bytes without updating a baseline.")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--export-dir", required=True, type=Path)
    parser.add_argument("--entropy-threshold", required=True, type=float)
    parser.add_argument("--top", required=True, type=int)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(arguments)
    cancellation = threading.Event()
    install_analysis_cancellation(cancellation)
    try:
        if re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256) is None:
            raise ValueError("Capture receipt SHA-256 must be a lowercase 64-digit digest.")
        validate_preview_destinations(args.pcap, args.baseline, args.export_dir)
        baseline = load_baseline(args.baseline)
        report = analyze_capture(args.pcap, baseline, args.entropy_threshold, SAVED_ANALYSIS_LIMITS, cancellation)
        if report["capture"]["sha256"] != args.expected_sha256:
            raise SavedCaptureError("captured_artifact_changed", "Capture bytes no longer match the final receipt. Reopen and review the file as a new saved artifact before exporting findings.")
        report_path = save_report(report, args.pcap, args.export_dir, (args.pcap, args.baseline), cancellation)
        print("Read-only analysis of receipt-verified bytes: baseline unchanged; no active PTR lookup.")
        print_summary(report, report_path, args.baseline, args.top)
    except (SavedCaptureError, BaselineValidationError, OSError, ValueError) as error:
        print(f"Capture receipt preview failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
