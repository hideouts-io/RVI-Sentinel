#!/usr/bin/env python3
"""Typed device-discovery and capture-request contracts for RVI-Sentinel."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping, cast

CAPTURE_FORMATS = frozenset({"pcap", "pcapng"})
MINIMUM_CAPTURE_SECONDS = 5
MAXIMUM_CAPTURE_SECONDS = 3_600
CAPTURE_AUTHORIZATION_EVENT = "RVI_SENTINEL_EVENT authorization_requested"
CAPTURE_PREFLIGHT_EVENT = "RVI_SENTINEL_EVENT preflight_started"
CAPTURE_STARTED_EVENT = "RVI_SENTINEL_EVENT capture_started"
CAPTURE_VALIDATED_EVENT = "RVI_SENTINEL_EVENT capture_validated"
IOS_DEVICE_NAME = re.compile(r"\b(iPhone|iPad|iPod)\b", re.IGNORECASE)
DEVICE_LINE = re.compile(
    r"^(?P<name>.+?) \((?P<version>[^()]*)\)(?: - (?P<state>[^()]+))? "
    r"\((?P<udid>(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}))\)$"
)


class CaptureValidationError(ValueError):
    """Raised when device discovery or capture configuration is invalid."""


@dataclass(frozen=True)
class DeviceInfo:
    name: str
    udid: str
    operating_system: str
    status: str
    connected: bool


@dataclass(frozen=True)
class CaptureRequest:
    device: DeviceInfo
    output_path: Path
    duration_seconds: int
    capture_format: str
    analyze_after_capture: bool


def parse_xctrace_devices(output: str) -> tuple[DeviceInfo, ...]:
    """Parse physical iPhone/iPad devices from ``xctrace list devices`` output."""
    section = ""
    devices: list[DeviceInfo] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("==") and line.endswith("=="):
            section = line.strip("= ")
            continue
        if not line or section == "Simulators" or IOS_DEVICE_NAME.search(line) is None:
            continue
        match = DEVICE_LINE.fullmatch(line)
        if match is None:
            continue
        state = (match.group("state") or "").strip()
        connected = section == "Devices" and state.lower() != "connecting"
        version = match.group("version") or "iOS/iPadOS version unavailable"
        devices.append(
            DeviceInfo(
                name=match.group("name"),
                udid=match.group("udid"),
                operating_system=version,
                status="Connected" if connected else state or "Offline",
                connected=connected,
            )
        )
    return tuple(devices)


def parse_devicectl_devices(payload: str) -> tuple[DeviceInfo, ...]:
    """Parse Apple's supported devicectl JSON into capture-ready physical devices."""
    try:
        decoded: object = json.loads(payload)
    except json.JSONDecodeError as error:
        raise CaptureValidationError(
            f"devicectl returned invalid JSON: {error}"
        ) from error
    root = require_mapping(decoded, "devicectl output")
    info = require_mapping(root.get("info"), "devicectl output.info")
    outcome = require_string(info, "outcome", "devicectl output.info")
    if outcome != "success":
        raise CaptureValidationError(
            f"devicectl reported an unsuccessful outcome: {outcome}"
        )
    result = require_mapping(root.get("result"), "devicectl output.result")
    device_values = result.get("devices")
    if not isinstance(device_values, list):
        raise CaptureValidationError("devicectl output.result.devices must be an array.")

    devices: list[DeviceInfo] = []
    for index, value in enumerate(cast(list[object], device_values)):
        context = f"devicectl output.result.devices[{index}]"
        row = require_mapping(value, context)
        hardware = require_mapping(row.get("hardwareProperties"), f"{context}.hardwareProperties")
        if require_string(hardware, "reality", f"{context}.hardwareProperties") != "physical":
            continue
        if require_string(hardware, "platform", f"{context}.hardwareProperties") != "iOS":
            continue
        properties = require_mapping(row.get("deviceProperties"), f"{context}.deviceProperties")
        connection = require_mapping(
            row.get("connectionProperties"), f"{context}.connectionProperties"
        )
        name = require_string(properties, "name", f"{context}.deviceProperties")
        os_version = require_string(
            properties, "osVersionNumber", f"{context}.deviceProperties"
        )
        boot_state = require_string(properties, "bootState", f"{context}.deviceProperties")
        udid = require_string(hardware, "udid", f"{context}.hardwareProperties")
        model = require_string(
            hardware, "marketingName", f"{context}.hardwareProperties"
        )
        product_type = require_string(
            hardware, "productType", f"{context}.hardwareProperties"
        )
        pairing_state = require_string(
            connection, "pairingState", f"{context}.connectionProperties"
        )
        transport = require_string(
            connection, "transportType", f"{context}.connectionProperties"
        )
        visibility = require_string(row, "visibilityClass", context)
        ready = (
            boot_state == "booted"
            and pairing_state == "paired"
            and transport == "wired"
            and visibility == "default"
        )
        status = macos_device_status(
            boot_state, pairing_state, transport, visibility, ready
        )
        devices.append(
            DeviceInfo(
                name=name,
                udid=udid,
                operating_system=f"{model} • iOS {os_version} ({product_type})",
                status=status,
                connected=ready,
            )
        )
    return tuple(devices)


def require_mapping(value: object, context: str) -> Mapping[object, object]:
    if not isinstance(value, dict):
        raise CaptureValidationError(f"{context} must be an object.")
    return cast(Mapping[object, object], value)


def require_string(
    mapping: Mapping[object, object], key: str, context: str
) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CaptureValidationError(f"{context}.{key} must be a non-empty string.")
    return value.strip()


def macos_device_status(
    boot_state: str,
    pairing_state: str,
    transport: str,
    visibility: str,
    ready: bool,
) -> str:
    if ready:
        return "Ready — paired over USB"
    reasons: list[str] = []
    if pairing_state != "paired":
        reasons.append("not paired")
    if transport != "wired":
        reasons.append("not connected by USB")
    if boot_state != "booted":
        reasons.append("not booted")
    if visibility != "default":
        reasons.append("not currently available")
    return "Not ready — " + ", ".join(reasons)


def devices_to_json(devices: tuple[DeviceInfo, ...]) -> str:
    payload = [
        {
            "name": device.name,
            "udid": device.udid,
            "operating_system": device.operating_system,
            "status": device.status,
            "connected": device.connected,
        }
        for device in devices
    ]
    return json.dumps(payload, indent=2)


def devices_from_json(payload: str) -> tuple[DeviceInfo, ...]:
    try:
        value: object = json.loads(payload)
    except json.JSONDecodeError as error:
        raise CaptureValidationError(f"Device discovery returned invalid JSON: {error}") from error
    if not isinstance(value, list):
        raise CaptureValidationError("Device discovery JSON must be an array.")
    rows = cast(list[object], value)
    return tuple(parse_device_mapping(row, index) for index, row in enumerate(rows))


def parse_device_mapping(value: object, index: int) -> DeviceInfo:
    if not isinstance(value, dict):
        raise CaptureValidationError(f"Device entry {index} must be an object.")
    mapping = cast(Mapping[object, object], value)
    name = require_device_string(mapping, "name", index)
    udid = require_device_string(mapping, "udid", index)
    operating_system = require_device_string(mapping, "operating_system", index)
    status = require_device_string(mapping, "status", index)
    connected = mapping.get("connected")
    if not isinstance(connected, bool):
        raise CaptureValidationError(f"Device entry {index}.connected must be a boolean.")
    return DeviceInfo(
        name=name,
        udid=udid,
        operating_system=operating_system,
        status=status,
        connected=connected,
    )


def require_device_string(
    mapping: Mapping[object, object], key: str, index: int
) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CaptureValidationError(f"Device entry {index}.{key} must be a non-empty string.")
    return value


def validate_capture_request(request: CaptureRequest) -> None:
    if not request.device.connected:
        raise CaptureValidationError(
            f"Selected device is not connected: {request.device.name}"
        )
    if not request.device.udid.strip():
        raise CaptureValidationError("Selected device does not have a usable UDID.")
    if request.capture_format not in CAPTURE_FORMATS:
        supported = ", ".join(sorted(CAPTURE_FORMATS))
        raise CaptureValidationError(
            f"Unsupported capture format: {request.capture_format}. Expected: {supported}"
        )
    expected_suffix = f".{request.capture_format}"
    if request.output_path.suffix.lower() != expected_suffix:
        raise CaptureValidationError(
            f"Capture output must end in {expected_suffix}: {request.output_path}"
        )
    if request.output_path.exists():
        raise CaptureValidationError(
            f"Capture output already exists; choose a new file to avoid overwriting evidence: "
            f"{request.output_path}"
        )
    if request.output_path.parent.exists() and not request.output_path.parent.is_dir():
        raise CaptureValidationError(
            f"Capture output parent is not a directory: {request.output_path.parent}"
        )
    if not MINIMUM_CAPTURE_SECONDS <= request.duration_seconds <= MAXIMUM_CAPTURE_SECONDS:
        raise CaptureValidationError(
            f"Capture duration must be between {MINIMUM_CAPTURE_SECONDS} and "
            f"{MAXIMUM_CAPTURE_SECONDS} seconds."
        )


def capture_session_arguments(request: CaptureRequest, session_script: Path) -> list[str]:
    validate_capture_request(request)
    return [
        str(session_script),
        str(request.output_path),
        "--udid",
        request.device.udid,
        "--duration",
        str(request.duration_seconds),
        "--format",
        request.capture_format,
    ]


def default_capture_path(
    capture_directory: Path, device_name: str, captured_at: datetime, capture_format: str
) -> Path:
    if capture_format not in CAPTURE_FORMATS:
        raise CaptureValidationError(f"Unsupported capture format: {capture_format}")
    normalized_name = re.sub(r"[^A-Za-z0-9]+", "-", device_name).strip("-").lower()
    if not normalized_name:
        normalized_name = "ios-device"
    timestamp = captured_at.strftime("%Y%m%d-%H%M%S")
    return capture_directory / f"{normalized_name}-{timestamp}.{capture_format}"
