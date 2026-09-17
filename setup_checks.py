#!/usr/bin/env python3
"""Report local capture prerequisites without changing device or capture state."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from capture_devices import DeviceDiscoveryError, discover_devices
from capture_models import CaptureValidationError, DeviceInfo

ROOT = Path(__file__).resolve().parent
MINIMUM_FREE_BYTES = 100 * 1024 * 1024
APPLE_RPMUXD_SERVICE = "system/com.apple.rpmuxd"
APPLE_RPMUXD_PLISTS = (
    Path("/Library/Apple/System/Library/LaunchDaemons/com.apple.rpmuxd.plist"),
    Path("/System/Library/LaunchDaemons/com.apple.rpmuxd.plist"),
)


@dataclass(frozen=True)
class SetupCheck:
    name: str
    passed: bool
    detail: str
    fix: str


def selected_device(devices: tuple[DeviceInfo, ...], udid: str | None) -> DeviceInfo | None:
    if udid is not None:
        return next((device for device in devices if device.udid == udid), None)
    return next(iter(devices), None)


def check_devices(host: str, udid: str | None) -> tuple[SetupCheck, SetupCheck]:
    usb_fix = (
        "Connect the unlocked phone by USB. On a Chromebook, open Settings > Developers > "
        "Linux > USB preferences and share this phone with Linux, then rerun checks."
        if host == "Linux"
        else "Connect the unlocked phone by USB, then refresh devices."
    )
    trust_fix = "Unlock the phone, accept Trust This Computer, then rerun checks."
    try:
        devices = discover_devices(host)
    except (CaptureValidationError, DeviceDiscoveryError, OSError, ImportError) as error:
        return (
            SetupCheck("USB access", False, f"Device discovery failed: {error}", usb_fix),
            SetupCheck("Device trust", False, "Trust could not be verified while discovery is unavailable.", trust_fix),
        )
    device = selected_device(devices, udid)
    if device is None:
        return (
            SetupCheck("USB access", False, "No selected iPhone or iPad is visible to this host.", usb_fix),
            SetupCheck("Device trust", False, "No device is available for a trust check.", trust_fix),
        )
    if host == "Darwin":
        usb_ok = "not connected by USB" not in device.status
        trust_ok = "not paired" not in device.status
        return (
            SetupCheck("USB access", usb_ok, "USB connection detected." if usb_ok else "The phone is not connected over USB.", usb_fix),
            SetupCheck("Device trust", trust_ok, "The phone is paired with this Mac." if trust_ok else "The phone is not paired with this Mac.", trust_fix),
        )
    idevice_id = shutil.which("idevice_id")
    if idevice_id is None:
        return (
            SetupCheck("USB access", False, "idevice_id is unavailable, so USB transport cannot be verified.", "Install libimobiledevice tools in the host/Linux environment, then rerun checks."),
            SetupCheck("Device trust", False, "Trust cannot be verified without libimobiledevice tools.", "Install idevicepair, unlock the phone, and accept Trust This Computer."),
        )
    usb_result = subprocess.run([idevice_id, "-l"], capture_output=True, text=True, check=False, timeout=10)
    usb_ok = usb_result.returncode == 0 and device.udid in usb_result.stdout.splitlines()
    usb_check = SetupCheck("USB access", usb_ok, "USB transport is visible to Linux/Windows." if usb_ok else "Selected device is not visible over USB.", usb_fix)
    idevicepair = shutil.which("idevicepair")
    if idevicepair is None:
        trust_check = SetupCheck("Device trust", False, "idevicepair is unavailable, so pairing cannot be verified.", "Install libimobiledevice tools, then unlock and trust the phone.")
    elif not usb_ok:
        trust_check = SetupCheck("Device trust", False, "Trust cannot be verified until USB access works.", trust_fix)
    else:
        pair_result = subprocess.run([idevicepair, "-u", device.udid, "validate"], capture_output=True, text=True, check=False, timeout=10)
        trust_ok = pair_result.returncode == 0
        trust_check = SetupCheck("Device trust", trust_ok, "Pairing validated." if trust_ok else "Pairing validation failed.", trust_fix)
    return usb_check, trust_check


def check_backend(host: str) -> SetupCheck:
    if host == "Darwin":
        rvictl = Path("/Library/Apple/usr/bin/rvictl")
        has_rvictl = (rvictl.is_file() and os.access(rvictl, os.X_OK)) or shutil.which("rvictl") is not None
        launchctl = shutil.which("launchctl")
        missing = [name for name, present in (("rvictl", has_rvictl), ("tcpdump", shutil.which("tcpdump") is not None), ("ifconfig", shutil.which("ifconfig") is not None), ("osascript", shutil.which("osascript") is not None), ("launchctl", launchctl is not None)) if not present]
        if missing:
            return SetupCheck("Capture backend", False, "Missing: " + ", ".join(missing), "Install or repair full Xcode and Apple device support, then confirm rvictl and tcpdump are available on PATH.")
        assert launchctl is not None
        relay = subprocess.run(
            [launchctl, "print", APPLE_RPMUXD_SERVICE],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if relay.returncode == 0:
            return SetupCheck("Capture backend", True, "Apple RVI, rpmuxd, and tcpdump are ready.", "")
        installed_plist = next((path for path in APPLE_RPMUXD_PLISTS if path.is_file()), None)
        if installed_plist is None:
            return SetupCheck(
                "Capture backend",
                False,
                "Apple's com.apple.rpmuxd RVI relay daemon is not installed.",
                "Open Xcode and install all requested device-support components, then rerun checks.",
            )
        return SetupCheck(
            "Capture backend",
            False,
            "Apple's com.apple.rpmuxd RVI relay daemon is installed but not loaded; rvictl will fail with bootstrap error 1102.",
            f"Open Xcode and install requested components. If it still fails, run in Terminal: sudo launchctl load -w {installed_plist}",
        )
    if host in {"Linux", "Windows"}:
        available = (ROOT / "tools" / "rvi_capture" / "rvi_capture.py").is_file()
        return SetupCheck("Capture backend", available, "Local RVI capture backend is installed." if available else "The local RVI capture backend is missing.", "Choose Install Capture Support in the Capture tab, then rerun checks.")
    return SetupCheck("Capture backend", False, f"Capture is unsupported on {host}.", "Use a supported macOS, Linux, or Windows host.")


def check_tshark() -> SetupCheck:
    found = shutil.which("tshark") is not None
    return SetupCheck("tshark", found, "tshark is on PATH." if found else "tshark is not on PATH.", "Install Wireshark/tshark in this environment and restart RVI-Sentinel.")


def existing_directory(path: Path) -> Path:
    parent = path
    while not parent.exists():
        if parent == parent.parent:
            raise FileNotFoundError(f"No existing parent for output folder: {path}")
        parent = parent.parent
    if not parent.is_dir():
        raise NotADirectoryError(f"Output folder parent is not a directory: {parent}")
    return parent


def check_output(path: Path) -> SetupCheck:
    try:
        directory = existing_directory(path)
        with tempfile.NamedTemporaryFile(prefix=".rvi-setup-", dir=directory) as handle:
            handle.write(b"RVI setup write check")
            handle.flush()
        return SetupCheck("Output-folder permissions", True, "A temporary file could be written in the output folder or its nearest existing parent.", "")
    except (OSError, ValueError) as error:
        return SetupCheck("Output-folder permissions", False, f"Output folder is not writable: {error}", "Choose a writable local output folder and rerun checks.")


def check_disk(path: Path) -> SetupCheck:
    try:
        available = shutil.disk_usage(existing_directory(path)).free
    except OSError as error:
        return SetupCheck("Available disk space", False, f"Free space could not be read: {error}", "Choose an accessible local output folder and rerun checks.")
    enough = available >= MINIMUM_FREE_BYTES
    mib = available // (1024 * 1024)
    return SetupCheck("Available disk space", enough, f"{mib:,} MiB free on the output volume (minimum check: 100 MiB).", "Free space or choose another volume; longer captures may need substantially more than 100 MiB.")


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Check RVI-Sentinel capture setup without starting a capture.")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--udid")
    args = parser.parse_args(arguments)
    host = platform.system()
    usb, trust = check_devices(host, args.udid)
    checks = (trust, usb, check_backend(host), check_tshark(), check_output(args.output_dir), check_disk(args.output_dir))
    print(json.dumps({"checks": [asdict(check) for check in checks]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
