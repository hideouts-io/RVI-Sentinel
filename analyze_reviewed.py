#!/usr/bin/env python3
"""Update a baseline only from the exact capture bytes reviewed in a preview."""

from __future__ import annotations

import argparse
import re
import sys
import threading
from pathlib import Path

from analysis_baseline import BaselineValidationError
from analyze import (
    analyze_capture,
    install_analysis_cancellation,
    load_baseline,
    print_summary,
    report_destinations,
    save_baseline,
    save_report,
    updated_baseline,
    validate_update_destinations,
)
from saved_capture import SAVED_ANALYSIS_LIMITS, SavedCaptureError


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Add reviewed saved-file findings only when the original SHA-256 still matches.")
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
            raise ValueError("Reviewed capture SHA-256 must be a lowercase 64-digit digest.")
        validate_update_destinations(args.pcap, args.baseline, args.export_dir)
        baseline = load_baseline(args.baseline)
        report = analyze_capture(args.pcap, baseline, args.entropy_threshold, SAVED_ANALYSIS_LIMITS, cancellation)
        if report["capture"]["sha256"] != args.expected_sha256:
            raise SavedCaptureError("reviewed_capture_changed", "Capture bytes changed after preview. Analyze the saved file again and review its findings before adding them to the baseline.")
        report_path = save_report(report, args.pcap, args.export_dir, (args.pcap, args.baseline), cancellation)
        save_baseline(args.baseline, updated_baseline(baseline, report), (args.pcap,) + report_destinations(args.pcap, args.export_dir), cancellation)
        print_summary(report, report_path, args.baseline, args.top)
    except (SavedCaptureError, BaselineValidationError, OSError, ValueError) as error:
        print(f"Reviewed baseline update failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
