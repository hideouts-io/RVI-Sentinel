#!/usr/bin/env python3
"""Count packets in a completed capture without loading packet data into memory."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def capture_statistics(path: Path) -> tuple[int, float | None]:
    process = subprocess.Popen(
        [
            "tshark", "-n", "-r", str(path), "-T", "fields",
            "-E", "separator=\t", "-e", "frame.number", "-e", "frame.time_epoch",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("tshark output streams were not available.")
    count = 0
    first_epoch: float | None = None
    last_epoch: float | None = None
    for line in process.stdout:
        if not line.strip():
            continue
        count += 1
        columns = line.rstrip("\n").split("\t")
        if len(columns) < 2 or not columns[1]:
            continue
        try:
            epoch = float(columns[1])
        except ValueError:
            continue
        first_epoch = epoch if first_epoch is None else min(first_epoch, epoch)
        last_epoch = epoch if last_epoch is None else max(last_epoch, epoch)
    detail = process.stderr.read().strip()
    status = process.wait()
    if status != 0:
        raise RuntimeError(f"tshark could not inspect the completed capture (exit {status}): {detail}")
    duration = last_epoch - first_epoch if first_epoch is not None and last_epoch is not None else None
    return count, duration


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Read the size and packet count of one capture.")
    parser.add_argument("capture", type=Path)
    args = parser.parse_args(arguments)
    if not args.capture.is_file():
        raise FileNotFoundError(f"Completed capture not found: {args.capture}")
    count, duration = capture_statistics(args.capture)
    print(json.dumps({"packet_count": count, "size_bytes": args.capture.stat().st_size, "duration_seconds": duration}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
