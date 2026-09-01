#!/usr/bin/env python3
"""Discover physical iPhone/iPad devices for the RVI-Sentinel GUI."""

from __future__ import annotations

import ctypes
import importlib.util
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

from capture_models import DeviceInfo, devices_to_json, parse_devicectl_devices

ROOT = Path(__file__).resolve().parent
UPSTREAM_CAPTURE = ROOT / "tools" / "rvi_capture" / "rvi_capture.py"


class DeviceDiscoveryError(RuntimeError):
    """Raised when the platform device provider cannot enumerate iOS hardware."""


def discover_macos_devices() -> tuple[DeviceInfo, ...]:
    xcrun = shutil.which("xcrun")
    if xcrun is None:
        raise DeviceDiscoveryError(
            "xcrun was not found. Install Xcode or the Xcode Command Line Tools."
        )
    with tempfile.TemporaryDirectory(prefix="rvi-sentinel-devicectl-") as directory:
        json_path = Path(directory) / "devices.json"
        result = subprocess.run(
            [
                xcrun,
                "devicectl",
                "list",
                "devices",
                "--json-output",
                str(json_path),
                "--quiet",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        if result.returncode != 0:
            raise DeviceDiscoveryError(
                f"devicectl device discovery failed with exit code {result.returncode}:\n"
                f"{output.strip()}"
            )
        if not json_path.is_file():
            raise DeviceDiscoveryError(
                "devicectl exited successfully but did not create its required JSON output."
            )
        return parse_devicectl_devices(json_path.read_text(encoding="utf-8"))


def discover_libimobiledevice_devices() -> tuple[DeviceInfo, ...]:
    idevice_id = shutil.which("idevice_id")
    if idevice_id is not None:
        return discover_with_idevice_id(idevice_id)
    if not UPSTREAM_CAPTURE.is_file():
        raise DeviceDiscoveryError(
            "The Linux/Windows capture backend is not installed. Choose Install Capture Support "
            "in RVI-Sentinel, or run: python3 scripts/setup_rvi_capture.py"
        )
    return discover_with_upstream_library(UPSTREAM_CAPTURE)


def discover_with_idevice_id(executable: str) -> tuple[DeviceInfo, ...]:
    result = subprocess.run(
        [executable, "-l"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise DeviceDiscoveryError(
            f"idevice_id failed with exit code {result.returncode}: {detail}"
        )
    udids = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    return tuple(device_details_from_ideviceinfo(udid) for udid in udids)


def device_details_from_ideviceinfo(udid: str) -> DeviceInfo:
    ideviceinfo = shutil.which("ideviceinfo")
    if ideviceinfo is None:
        return generic_connected_device(udid, "Connected; ideviceinfo is not installed")
    name = read_idevice_property(ideviceinfo, udid, "DeviceName")
    product_type = read_idevice_property(ideviceinfo, udid, "ProductType")
    version = read_idevice_property(ideviceinfo, udid, "ProductVersion")
    if name is None:
        return generic_connected_device(udid, "Connected; device details unavailable")
    operating_system = " ".join(
        value for value in (product_type or "iOS/iPadOS", version or "") if value
    )
    return DeviceInfo(
        name=name,
        udid=udid,
        operating_system=operating_system,
        status="Connected",
        connected=True,
    )


def read_idevice_property(executable: str, udid: str, key: str) -> str | None:
    result = subprocess.run(
        [executable, "-u", udid, "-k", key],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def discover_with_upstream_library(upstream_path: Path) -> tuple[DeviceInfo, ...]:
    module = load_upstream_module(upstream_path)
    library_value = module.__dict__.get("cdll")
    if not isinstance(library_value, ctypes.CDLL):
        raise DeviceDiscoveryError(
            f"Upstream backend did not expose a loaded libimobiledevice library: {upstream_path}"
        )
    library = library_value
    device_list = ctypes.POINTER(ctypes.c_char_p)()
    device_count = ctypes.c_int(0)
    get_device_list = library.idevice_get_device_list
    get_device_list.argtypes = [
        ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p)),
        ctypes.POINTER(ctypes.c_int),
    ]
    get_device_list.restype = ctypes.c_int
    free_device_list = library.idevice_device_list_free
    free_device_list.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
    free_device_list.restype = ctypes.c_int

    result = get_device_list(ctypes.byref(device_list), ctypes.byref(device_count))
    if result != 0:
        raise DeviceDiscoveryError(
            f"libimobiledevice enumeration failed with error code {result}."
        )
    try:
        udids = tuple(
            device_list[index].decode("utf-8") for index in range(device_count.value)
        )
    finally:
        free_result = free_device_list(device_list)
        if free_result != 0:
            raise DeviceDiscoveryError(
                f"libimobiledevice could not release its device list: error {free_result}."
            )
    return tuple(
        generic_connected_device(udid, "Connected through libimobiledevice")
        for udid in udids
    )


def load_upstream_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("rvi_sentinel_upstream_capture", path)
    if spec is None or spec.loader is None:
        raise DeviceDiscoveryError(f"Could not load upstream capture backend: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generic_connected_device(udid: str, status: str) -> DeviceInfo:
    suffix = udid[-8:] if len(udid) >= 8 else udid
    return DeviceInfo(
        name=f"Connected iOS device • {suffix}",
        udid=udid,
        operating_system="iOS/iPadOS",
        status=status,
        connected=True,
    )


def discover_devices(host_system: str) -> tuple[DeviceInfo, ...]:
    if host_system == "Darwin":
        return discover_macos_devices()
    if host_system in {"Linux", "Windows"}:
        return discover_libimobiledevice_devices()
    raise DeviceDiscoveryError(
        f"RVI-Sentinel capture is not supported on this operating system: {host_system}"
    )


def main() -> int:
    try:
        devices = discover_devices(platform.system())
    except (DeviceDiscoveryError, OSError, ImportError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(devices_to_json(devices))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
