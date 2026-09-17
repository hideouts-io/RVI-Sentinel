#!/usr/bin/env python3
"""Analyze a capture against a baseline without changing that baseline."""

from __future__ import annotations

import argparse
from pathlib import Path

from analyze import analyze, load_baseline, print_summary, write_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Preview RVI-Sentinel findings without updating the baseline.")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--export-dir", required=True, type=Path)
    parser.add_argument("--entropy-threshold", required=True, type=float)
    parser.add_argument("--top", required=True, type=int)
    args = parser.parse_args()
    if not args.pcap.is_file():
        raise SystemExit(f"Capture not found: {args.pcap}")
    baseline = load_baseline(args.baseline)
    report = analyze(args.pcap, baseline, args.entropy_threshold)
    report_path = write_report(report, args.pcap, args.export_dir)
    print("Read-only analysis: baseline was not changed.")
    print_summary(report, report_path, args.baseline, args.top)


if __name__ == "__main__":
    main()
