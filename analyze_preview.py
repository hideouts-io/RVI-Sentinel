#!/usr/bin/env python3
"""Analyze a capture against a baseline without changing that baseline."""

from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path

from analysis_baseline import BaselineValidationError
from analyze import analyze_capture, install_analysis_cancellation, load_baseline, print_summary, save_report, validate_preview_destinations
from saved_capture import SAVED_ANALYSIS_LIMITS, SavedCaptureError


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview RVI-Sentinel findings without updating the baseline.")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--export-dir", required=True, type=Path)
    parser.add_argument("--entropy-threshold", required=True, type=float)
    parser.add_argument("--top", required=True, type=int)
    args = parser.parse_args()
    cancellation = threading.Event()
    install_analysis_cancellation(cancellation)
    try:
        validate_preview_destinations(args.pcap, args.baseline, args.export_dir)
        baseline = load_baseline(args.baseline)
        report = analyze_capture(args.pcap, baseline, args.entropy_threshold, SAVED_ANALYSIS_LIMITS, cancellation)
        if cancellation.is_set():
            raise SavedCaptureError("cancelled", "Analysis was cancelled before saving; baseline unchanged.")
        report_path = save_report(report, args.pcap, args.export_dir, (args.pcap, args.baseline), cancellation)
        print("Read-only analysis: baseline was not changed. No active PTR lookup was performed.")
        print_summary(report, report_path, args.baseline, args.top)
    except (SavedCaptureError, BaselineValidationError, OSError, ValueError) as error:
        print(f"Saved-file preview failed: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
