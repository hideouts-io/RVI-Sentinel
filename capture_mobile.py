#!/usr/bin/env python3
"""Cross-platform iPhone/iPad capture frontend for RVI-Sentinel.

On Linux and Windows this invokes the canonical gh2o/rvi_capture source cloned
by scripts/setup_rvi_capture.py. The resulting PCAP/PCAPNG can optionally be
analyzed immediately by RVI-Sentinel.
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_UPSTREAM = ROOT / "tools" / "rvi_capture" / "rvi_capture.py"
ANALYZER = ROOT / "analyze.py"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture iPhone/iPad traffic on Linux/Windows via gh2o/rvi_capture."
    )
    parser.add_argument("outfile", type=Path, help="Output .pcap or .pcapng")
    parser.add_argument("--udid", help="Specific iOS device UDID; upstream selects the first device if omitted")
    parser.add_argument("--format", choices=("pcap", "pcapng"), default="pcapng")
    parser.add_argument("--upstream", type=Path, default=DEFAULT_UPSTREAM,
                        help="Path to upstream rvi_capture.py")
    parser.add_argument("--analyze", action="store_true",
                        help="Run RVI-Sentinel analyze.py after capture exits successfully")
    parser.add_argument("--top", type=int, default=20,
                        help="Top rows shown when --analyze is used")
    args = parser.parse_args()

    host = platform.system()
    if host not in {"Linux", "Windows"}:
        print(
            f"capture_mobile.py is intended for Linux/Windows (detected {host}).\n"
            "On macOS use capture_rvi.sh with Apple's rvictl/rvi0.",
            file=sys.stderr,
        )
        return 2

    upstream = args.upstream.resolve()
    if not upstream.is_file():
        print(f"Upstream capture backend not found: {upstream}", file=sys.stderr)
        print("Install it with:", file=sys.stderr)
        print("  python3 scripts/setup_rvi_capture.py", file=sys.stderr)
        return 2

    args.outfile.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(upstream), "--format", args.format]
    if args.udid:
        cmd += ["--udid", args.udid]
    cmd.append(str(args.outfile))

    print(f"Host OS: {host}")
    print("Capture backend: https://github.com/gh2o/rvi_capture")
    print("+", " ".join(cmd))
    result = subprocess.run(cmd)
    if result.returncode != 0:
        return result.returncode

    if args.analyze:
        analyze_cmd = [
            sys.executable,
            str(ANALYZER),
            str(args.outfile),
            "--top",
            str(args.top),
        ]
        print("\nCapture complete; starting RVI-Sentinel analysis")
        print("+", " ".join(analyze_cmd))
        return subprocess.run(analyze_cmd).returncode

    print(f"\nCapture complete: {args.outfile}")
    print("Analyze with:")
    print(f"  python3 analyze.py {args.outfile}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
