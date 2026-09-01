#!/usr/bin/env python3
"""Integration-style contracts for guided device discovery and timed capture setup."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path

from capture_models import (
    CaptureRequest,
    CaptureValidationError,
    capture_session_arguments,
    default_capture_path,
    devices_from_json,
    devices_to_json,
    parse_devicectl_devices,
    parse_xctrace_devices,
    validate_capture_request,
)
from capture_session import (
    CaptureSessionError,
    native_authorized_tcpdump_command,
    parse_rvi_interfaces,
    parse_tcpdump_interfaces,
    select_created_interface,
    validate_macos_capture_output,
)

XCTRACE_OUTPUT = """== Devices ==
Research iPhone (26.1) (00008150-000000000000001C)
Connecting iPhone (26.3.1) - Connecting (00008150-000000000000003F)
Julian's Mac (11111111-2222-3333-4444-555555555555)

== Devices Offline ==
Lab iPad (18.6) (00008120-000000000000002E)

== Simulators ==
iPhone 17 Simulator (26.1) (AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE)
"""

DEVICECTL_OUTPUT = json.dumps(
    {
        "info": {"outcome": "success"},
        "result": {
            "devices": [
                {
                    "visibilityClass": "default",
                    "deviceProperties": {
                        "name": "Research iPhone",
                        "osVersionNumber": "26.3.1",
                        "bootState": "booted",
                    },
                    "hardwareProperties": {
                        "reality": "physical",
                        "platform": "iOS",
                        "udid": "00008150-000000000000001C",
                        "marketingName": "iPhone 17 Pro",
                        "productType": "iPhone18,1",
                    },
                    "connectionProperties": {
                        "pairingState": "paired",
                        "transportType": "wired",
                    },
                },
                {
                    "visibilityClass": "default",
                    "deviceProperties": {
                        "name": "Known iPad",
                        "osVersionNumber": "26.3.1",
                        "bootState": "booted",
                    },
                    "hardwareProperties": {
                        "reality": "physical",
                        "platform": "iOS",
                        "udid": "00008120-000000000000002E",
                        "marketingName": "iPad Pro",
                        "productType": "iPad16,3",
                    },
                    "connectionProperties": {
                        "pairingState": "paired",
                        "transportType": "network",
                    },
                },
            ]
        },
    }
)


def main() -> None:
    devices = parse_xctrace_devices(XCTRACE_OUTPUT)
    assert len(devices) == 3
    assert devices[0].name == "Research iPhone"
    assert devices[0].connected is True
    assert devices[0].operating_system == "26.1"
    assert devices[1].name == "Connecting iPhone"
    assert devices[1].connected is False
    assert devices[1].status == "Connecting"
    assert devices[2].name == "Lab iPad"
    assert devices[2].connected is False
    assert devices[2].status == "Offline"

    core_devices = parse_devicectl_devices(DEVICECTL_OUTPUT)
    assert len(core_devices) == 2
    assert core_devices[0].name == "Research iPhone"
    assert core_devices[0].connected is True
    assert core_devices[0].status == "Ready — paired over USB"
    assert core_devices[1].connected is False
    assert core_devices[1].status == "Not ready — not connected by USB"

    round_trip = devices_from_json(devices_to_json(devices))
    assert round_trip == devices

    with tempfile.TemporaryDirectory(prefix="rvi-sentinel-capture-models-") as directory:
        capture_directory = Path(directory) / "captures"
        output = default_capture_path(
            capture_directory,
            devices[0].name,
            datetime(2026, 8, 31, 12, 34, 56),
            "pcapng",
        )
        assert output.name == "research-iphone-20260831-123456.pcapng"
        request = CaptureRequest(
            device=devices[0],
            output_path=output,
            duration_seconds=60,
            capture_format="pcapng",
            analyze_after_capture=True,
        )
        validate_capture_request(request)
        arguments = capture_session_arguments(request, Path("/repo/capture_session.py"))
        assert arguments == [
            "/repo/capture_session.py",
            str(output),
            "--udid",
            devices[0].udid,
            "--duration",
            "60",
            "--format",
            "pcapng",
        ]

        invalid_request = CaptureRequest(
            device=devices[1],
            output_path=output,
            duration_seconds=60,
            capture_format="pcapng",
            analyze_after_capture=False,
        )
        try:
            validate_capture_request(invalid_request)
        except CaptureValidationError as error:
            assert "not connected" in str(error)
        else:
            raise AssertionError("Offline device unexpectedly passed capture validation.")

    interface = select_created_interface(
        frozenset(), frozenset({"rvi0"}), "Starting device"
    )
    assert interface == "rvi0"
    rvi_interfaces = parse_rvi_interfaces("lo0 en0 awdl0 rvi0 rvi12")
    assert rvi_interfaces == frozenset({"rvi0", "rvi12"})
    tcpdump_interfaces = parse_tcpdump_interfaces(
        "1.en0 [Up, Running]\n17.rvi0 [Up, Running]\n"
    )
    assert tcpdump_interfaces == frozenset({"en0", "rvi0"})
    command = native_authorized_tcpdump_command(
        "/usr/sbin/tcpdump",
        "rvi0",
        Path("/tmp/Authorized Capture.pcapng"),
        Path("/tmp/rvi-sentinel-preflight/preflight.pcap"),
        Path("/tmp/rvi-sentinel-preflight/authorized"),
        Path("/tmp/rvi-sentinel-preflight/ready"),
        Path("/tmp/rvi-sentinel-preflight/failure"),
        Path("/tmp/rvi-sentinel-preflight/cancel"),
        "pcapng",
        "researcher",
        30,
    )
    assert "'/tmp/Authorized Capture.pcapng'" in command
    assert '"$capture_elapsed" -lt 30' in command
    assert 'for preflight_second in 1 2 3 4 5' in command
    assert "-c 1" in command
    assert "-P -Z researcher" in command
    assert "/bin/kill -TERM" in command
    assert "/bin/kill -INT" not in command
    assert "administrator" not in command

    pcap_command = native_authorized_tcpdump_command(
        "/usr/sbin/tcpdump",
        "rvi0",
        Path("/tmp/Authorized Capture.pcap"),
        Path("/tmp/rvi-sentinel-preflight/preflight.pcapng"),
        Path("/tmp/rvi-sentinel-preflight/authorized"),
        Path("/tmp/rvi-sentinel-preflight/ready"),
        Path("/tmp/rvi-sentinel-preflight/failure"),
        Path("/tmp/rvi-sentinel-preflight/cancel"),
        "pcap",
        "researcher",
        30,
    )
    assert "-y RAW -Z researcher" in pcap_command

    with tempfile.TemporaryDirectory(prefix="rvi-sentinel-invalid-capture-") as directory:
        invalid_capture = Path(directory) / "invalid.pcapng"
        invalid_capture.write_bytes(b"not a packet capture")
        try:
            validate_macos_capture_output(
                "/usr/sbin/tcpdump", invalid_capture, "pcapng"
            )
        except CaptureSessionError as error:
            assert "requested pcapng header" in str(error)
        else:
            raise AssertionError("Invalid capture unexpectedly passed format validation.")

    print("PASS: physical-device discovery parsing")
    print("PASS: macOS CoreDevice readiness parsing")
    print("PASS: typed device JSON contract")
    print("PASS: bounded capture request validation")
    print("PASS: exact timed capture argument construction")
    print("PASS: macOS RVI interface and authorized tcpdump command construction")
    print("PASS: macOS format selection, termination, and output-header validation")
    print("PASS: tcpdump interface-readiness parsing")


if __name__ == "__main__":
    main()
