#!/usr/bin/env python3
"""Install/update the upstream gh2o/rvi_capture helper locally.

RVI-Sentinel does not vendor gh2o/rvi_capture source because the upstream
repository currently exposes no explicit license file. This script clones the
canonical repository into tools/rvi_capture so users run the upstream source
unchanged and can inspect exactly where it came from.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

UPSTREAM = "https://github.com/gh2o/rvi_capture.git"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEST = ROOT / "tools" / "rvi_capture"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Clone or update gh2o/rvi_capture for Linux/Windows iOS capture."
    )
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    parser.add_argument("--update", action="store_true", help="Pull latest upstream changes if already cloned")
    args = parser.parse_args()

    if shutil.which("git") is None:
        print("git is required but was not found in PATH", file=sys.stderr)
        return 2

    dest = args.dest.resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    if (dest / ".git").is_dir():
        print(f"Upstream already present: {dest}")
        if args.update:
            run(["git", "pull", "--ff-only"], cwd=dest)
    elif dest.exists():
        print(f"Destination exists but is not a git checkout: {dest}", file=sys.stderr)
        return 2
    else:
        run(["git", "clone", UPSTREAM, str(dest)])

    capture = dest / "rvi_capture.py"
    if not capture.is_file():
        print(f"Expected upstream script not found: {capture}", file=sys.stderr)
        return 3

    try:
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=dest, text=True
        ).strip()
    except subprocess.SubprocessError:
        head = "unknown"

    print("\nInstalled upstream iOS capture backend")
    print(f"Source: {UPSTREAM}")
    print(f"Path:   {dest}")
    print(f"Commit: {head}")
    print("\nNext:")
    print("  python3 capture_mobile.py captures/iphone.pcapng")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
