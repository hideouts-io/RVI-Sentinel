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

from capture_models import MAXIMUM_CAPTURE_SECONDS, MINIMUM_CAPTURE_SECONDS
from capture_session import CaptureProcessController, CaptureSessionError

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
    parser.add_argument(
        "--duration",
        type=int,
        help="Stop cleanly after this many seconds; omit for an open-ended CLI capture",
    )
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
    if args.duration is not None and not (
        MINIMUM_CAPTURE_SECONDS <= args.duration <= MAXIMUM_CAPTURE_SECONDS
    ):
        print(
            f"Capture duration must be between {MINIMUM_CAPTURE_SECONDS} and "
            f"{MAXIMUM_CAPTURE_SECONDS} seconds.",
            file=sys.stderr,
        )
        return 2

    args.outfile.parent.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(upstream), "--format", args.format]
    if args.udid:
        cmd += ["--udid", args.udid]
    cmd.append(str(args.outfile))

    print(f"Host OS: {host}")
    print("Capture backend: https://github.com/gh2o/rvi_capture")
    print("+", " ".join(cmd))
    controller = CaptureProcessController()
    controller.install_signal_handlers()
    creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if host == "Windows" else 0
    try:
        if args.duration is None:
            return_code = controller.run_until_exit(cmd, creation_flags)
        else:
            return_code = controller.run_for_duration(
                cmd, args.duration, creation_flags
            )
    except CaptureSessionError as error:
        print(str(error), file=sys.stderr)
        return 2
    if return_code != 0:
        return return_code

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
