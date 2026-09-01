#!/usr/bin/env python3
"""Run one timed, platform-aware iPhone/iPad capture for RVI-Sentinel."""

from __future__ import annotations

import argparse
import getpass
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import cast

from capture_devices import DeviceDiscoveryError, discover_macos_devices
from capture_models import (
    CAPTURE_AUTHORIZATION_EVENT,
    CAPTURE_PREFLIGHT_EVENT,
    CAPTURE_STARTED_EVENT,
    CAPTURE_VALIDATED_EVENT,
    CaptureRequest,
    DeviceInfo,
    validate_capture_request,
)

ROOT = Path(__file__).resolve().parent
UPSTREAM_CAPTURE = ROOT / "tools" / "rvi_capture" / "rvi_capture.py"
RVI_INTERFACE = re.compile(r"^rvi[0-9]+$")
APPLE_RVICTL = Path("/Library/Apple/usr/bin/rvictl")


class CaptureSessionError(RuntimeError):
    """Raised when a capture provider cannot complete a requested session."""


class CaptureCancelled(CaptureSessionError):
    """Raised when the user cancels an active capture."""


class CaptureProcessController:
    """Own the external capture process so cancellation never leaves it orphaned."""

    def __init__(self) -> None:
        self.active_process: subprocess.Popen[str] | None = None
        self.cancellation_marker: Path | None = None
        self.cancelled = False

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, self.cancel)
        signal.signal(signal.SIGINT, self.cancel)

    def cancel(self, signal_number: int, _frame: object) -> None:
        self.cancelled = True
        cancellation_marker = self.cancellation_marker
        if cancellation_marker is not None:
            cancellation_marker.touch()
            return
        process = self.active_process
        if process is not None and process.poll() is None:
            stop_capture_process(process)
        raise CaptureCancelled(f"Capture cancelled by signal {signal_number}.")

    def run_until_exit(self, arguments: list[str], creation_flags: int) -> int:
        process = subprocess.Popen(
            arguments,
            text=True,
            creationflags=creation_flags,
        )
        self.active_process = process
        try:
            return process.wait()
        finally:
            self.active_process = None

    def run_for_duration(
        self, arguments: list[str], duration_seconds: int, creation_flags: int
    ) -> int:
        process = subprocess.Popen(
            arguments,
            text=True,
            creationflags=creation_flags,
        )
        self.active_process = process
        try:
            try:
                return process.wait(timeout=duration_seconds)
            except subprocess.TimeoutExpired:
                print(f"Capture duration reached ({duration_seconds} seconds); stopping cleanly.")
                stop_capture_process(process)
                try:
                    return process.wait(timeout=15)
                except subprocess.TimeoutExpired as error:
                    process.kill()
                    process.wait()
                    raise CaptureSessionError(
                        "Capture backend did not stop within 15 seconds after an interrupt."
                    ) from error
        finally:
            self.active_process = None


def stop_capture_process(process: subprocess.Popen[str]) -> None:
    if platform.system() == "Windows":
        process.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        process.send_signal(signal.SIGTERM)


def available_rvi_interfaces(ifconfig: str) -> frozenset[str]:
    result = subprocess.run(
        [ifconfig, "-l"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CaptureSessionError(
            f"ifconfig failed with exit code {result.returncode}: {detail}"
        )
    return parse_rvi_interfaces(result.stdout)


def parse_rvi_interfaces(output: str) -> frozenset[str]:
    return frozenset(
        interface
        for interface in output.split()
        if RVI_INTERFACE.fullmatch(interface) is not None
    )


def parse_tcpdump_interfaces(output: str) -> frozenset[str]:
    interfaces: set[str] = set()
    for line in output.splitlines():
        match = re.match(r"^[0-9]+\.([^\s]+)", line.strip())
        if match is not None:
            interfaces.add(match.group(1))
    return frozenset(interfaces)


def available_tcpdump_interfaces(tcpdump: str) -> frozenset[str]:
    result = subprocess.run(
        [tcpdump, "-D"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CaptureSessionError(
            f"tcpdump interface discovery failed with exit code {result.returncode}: {detail}"
        )
    return parse_tcpdump_interfaces(result.stdout)


def select_created_interface(
    before: frozenset[str], after: frozenset[str], rvictl_output: str
) -> str:
    created = sorted(after - before)
    if len(created) == 1:
        return created[0]
    mentioned = sorted(
        {
            candidate
            for candidate in re.findall(r"\brvi[0-9]+\b", rvictl_output)
            if candidate in after
        }
    )
    if len(mentioned) == 1:
        return mentioned[0]
    if not before and len(after) == 1:
        return next(iter(after))
    raise CaptureSessionError(
        "rvictl completed, but RVI-Sentinel could not identify a unique RVI interface. "
        f"Before: {sorted(before)}; after: {sorted(after)}; output: {rvictl_output.strip()}"
    )


def wait_for_created_rvi_interface(
    before: frozenset[str],
    ifconfig: str,
    tcpdump: str,
    rvictl_output: str,
    timeout_seconds: float,
) -> str:
    deadline = time.monotonic() + timeout_seconds
    last_interfaces = before
    last_error = "RVI interface has not appeared yet."
    while time.monotonic() < deadline:
        last_interfaces = available_rvi_interfaces(ifconfig)
        try:
            interface = select_created_interface(before, last_interfaces, rvictl_output)
        except CaptureSessionError as error:
            last_error = str(error)
            time.sleep(0.25)
            continue
        readiness = subprocess.run(
            [ifconfig, interface], capture_output=True, text=True, check=False
        )
        if readiness.returncode == 0:
            capture_interfaces = available_tcpdump_interfaces(tcpdump)
            if interface in capture_interfaces:
                time.sleep(1.0)
            if (
                interface in available_rvi_interfaces(ifconfig)
                and interface in available_tcpdump_interfaces(tcpdump)
            ):
                return interface
            last_error = (
                f"{interface} exists in ifconfig but is not yet stable in tcpdump -D. "
                f"tcpdump interfaces: {sorted(capture_interfaces)}"
            )
        else:
            detail = readiness.stderr.strip() or readiness.stdout.strip()
            last_error = (
                f"ifconfig could not read {interface} (exit {readiness.returncode}): {detail}"
            )
        time.sleep(0.25)
    raise CaptureSessionError(
        f"RVI interface was not stable within {timeout_seconds:.1f} seconds. "
        f"Last interfaces: {sorted(last_interfaces)}. Last result: {last_error}"
    )


def native_authorized_tcpdump_command(
    tcpdump: str,
    interface: str,
    output_path: Path,
    preflight_path: Path,
    authorization_marker: Path,
    ready_marker: Path,
    failure_marker: Path,
    cancellation_marker: Path,
    capture_format: str,
    capture_user: str,
    duration_seconds: int,
) -> str:
    if RVI_INTERFACE.fullmatch(interface) is None:
        raise CaptureSessionError(f"Invalid RVI interface name: {interface}")
    if capture_format not in {"pcap", "pcapng"}:
        raise CaptureSessionError(f"Unsupported macOS capture format: {capture_format}")
    if not capture_user:
        raise CaptureSessionError("Could not identify the user who owns the capture output.")
    preflight_command = shlex.join(
        [
            tcpdump,
            "-i",
            interface,
            "-s",
            "0",
            "-U",
            "-n",
            "-c",
            "1",
            "-P",
            "-Z",
            capture_user,
            "-w",
            str(preflight_path),
        ]
    )
    format_arguments = ["-P"] if capture_format == "pcapng" else ["-y", "RAW"]
    capture_command = shlex.join(
        [
            tcpdump,
            "-i",
            interface,
            "-s",
            "0",
            "-U",
            "-n",
            *format_arguments,
            "-Z",
            capture_user,
            "-w",
            str(output_path),
        ]
    )
    preflight = shlex.quote(str(preflight_path))
    authorization = shlex.quote(str(authorization_marker))
    ready = shlex.quote(str(ready_marker))
    failure = shlex.quote(str(failure_marker))
    cancellation = shlex.quote(str(cancellation_marker))
    no_packet_message = shlex.quote(
        "No packets arrived from the iPhone/iPad during the five-second RVI preflight. "
        "Keep the device connected by USB, unlocked, and generate some network activity."
    )
    preflight_failed_message = shlex.quote(
        "tcpdump failed during the five-second RVI packet preflight."
    )
    capture_failed_message = shlex.quote(
        "tcpdump could not remain running for the requested capture."
    )
    return (
        "set -eu; "
        "capture_pid=''; "
        "cleanup_capture() { "
        "if [ -n \"$capture_pid\" ] && /bin/kill -0 \"$capture_pid\" 2>/dev/null; then "
        "/bin/kill -TERM \"$capture_pid\"; "
        "if ! wait \"$capture_pid\" 2>/dev/null; then cleanup_wait_failed=1; fi; fi; "
        f"/bin/rm -f {preflight} {authorization} {ready} {cancellation}; "
        "}; "
        "trap cleanup_capture HUP INT TERM EXIT; "
        f"/usr/bin/touch {authorization}; "
        f"{preflight_command} & capture_pid=$!; "
        "for preflight_second in 1 2 3 4 5; do "
        f"if [ -e {cancellation} ]; then break; fi; "
        "if ! /bin/kill -0 \"$capture_pid\" 2>/dev/null; then break; fi; "
        "/bin/sleep 1; "
        "done; "
        f"if [ -e {cancellation} ]; then "
        "/bin/kill -TERM \"$capture_pid\"; "
        "cancel_status=0; wait \"$capture_pid\" || cancel_status=$?; "
        "capture_pid=''; exit 44; "
        "fi; "
        "if /bin/kill -0 \"$capture_pid\" 2>/dev/null; then "
        "/bin/kill -TERM \"$capture_pid\"; "
        "preflight_status=0; wait \"$capture_pid\" || preflight_status=$?; "
        "capture_pid=''; "
        f"/usr/bin/printf '%s\\n' {no_packet_message} > {failure}; "
        "exit 42; "
        "fi; "
        "preflight_status=0; wait \"$capture_pid\" || preflight_status=$?; "
        "capture_pid=''; "
        "if [ \"$preflight_status\" -ne 0 ]; then "
        f"/usr/bin/printf '%s\\n' {preflight_failed_message} > {failure}; "
        "exit \"$preflight_status\"; "
        "fi; "
        f"if [ ! -s {preflight} ]; then "
        f"/usr/bin/printf '%s\\n' {preflight_failed_message} > {failure}; "
        "exit 43; "
        "fi; "
        f"/bin/rm -f {preflight}; "
        f"{capture_command} & capture_pid=$!; "
        "/bin/sleep 1; "
        "if ! /bin/kill -0 \"$capture_pid\" 2>/dev/null; then "
        "capture_status=0; wait \"$capture_pid\" || capture_status=$?; "
        "capture_pid=''; "
        f"/usr/bin/printf '%s\\n' {capture_failed_message} > {failure}; "
        "exit \"$capture_status\"; "
        "fi; "
        f"/usr/bin/touch {ready}; "
        "capture_elapsed=0; "
        f"while [ \"$capture_elapsed\" -lt {duration_seconds} ] && [ ! -e {cancellation} ]; do "
        "/bin/sleep 1; capture_elapsed=$((capture_elapsed + 1)); "
        "done; "
        "/bin/kill -TERM \"$capture_pid\"; "
        "capture_status=0; wait \"$capture_pid\" || capture_status=$?; "
        "capture_pid=''; "
        f"if [ -e {cancellation} ]; then exit 44; fi; "
        "if [ \"$capture_status\" -ne 0 ]; then "
        f"/usr/bin/printf '%s\\n' {capture_failed_message} > {failure}; "
        "exit \"$capture_status\"; "
        "fi; "
        f"/bin/rm -f {authorization} {ready} {cancellation}; "
        "trap - EXIT"
    )


def validate_macos_capture_output(
    tcpdump: str, output_path: Path, capture_format: str
) -> int:
    with output_path.open("rb") as capture_file:
        header = capture_file.read(4)
    pcapng_magic = bytes.fromhex("0a0d0d0a")
    pcap_magics = {
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("4d3cb2a1"),
        bytes.fromhex("a1b23c4d"),
    }
    magic_matches = (
        header == pcapng_magic if capture_format == "pcapng" else header in pcap_magics
    )
    if not magic_matches:
        raise CaptureSessionError(
            f"Capture file does not contain the requested {capture_format} header: {output_path}"
        )
    result = subprocess.run(
        [tcpdump, "-n", "-c", "1", "-r", str(output_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise CaptureSessionError(
            f"tcpdump could not read the completed capture (exit {result.returncode}): {detail}"
        )
    if not result.stdout.strip():
        raise CaptureSessionError(
            "The completed capture is readable but contains no packets. Generate network "
            "activity on the iPhone/iPad and capture again."
        )
    return output_path.stat().st_size


def ensure_macos_device_ready(udid: str) -> DeviceInfo:
    try:
        devices = discover_macos_devices()
    except DeviceDiscoveryError as error:
        raise CaptureSessionError(
            f"Could not verify the selected iPhone/iPad before starting rvictl: {error}"
        ) from error
    matches = tuple(device for device in devices if device.udid == udid)
    if not matches:
        raise CaptureSessionError(
            "The selected iPhone/iPad is no longer available. Reconnect it by USB, unlock it, "
            "confirm Trust if prompted, and refresh the device list."
        )
    device = matches[0]
    if not device.connected:
        raise CaptureSessionError(
            f"The selected iPhone/iPad is not capture-ready: {device.status}. Reconnect it by "
            "USB, unlock it, confirm Trust if prompted, and refresh the device list."
        )
    return device


def process_diagnostic(process: subprocess.Popen[str]) -> str:
    standard_output, standard_error = process.communicate()
    return "\n".join(
        part.strip() for part in (standard_output, standard_error) if part.strip()
    )


def run_authorized_macos_capture(
    arguments: list[str],
    controller: CaptureProcessController,
    authorization_marker: Path,
    ready_marker: Path,
    failure_marker: Path,
    authorization_timeout_seconds: float,
    completion_timeout_seconds: float,
) -> None:
    process = subprocess.Popen(
        arguments,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    controller.active_process = process
    authorization_reported = False
    deadline = time.monotonic() + authorization_timeout_seconds
    try:
        while ready_marker.exists() is False:
            if authorization_marker.exists() and not authorization_reported:
                print(CAPTURE_PREFLIGHT_EVENT, flush=True)
                authorization_reported = True
            if failure_marker.exists():
                failure = failure_marker.read_text(encoding="utf-8").strip()
                process.wait(timeout=10)
                diagnostic = process_diagnostic(process)
                detail = failure or diagnostic or "The authorized capture preflight failed."
                raise CaptureSessionError(detail)
            return_code = process.poll()
            if return_code is not None:
                diagnostic = process_diagnostic(process)
                if controller.cancelled:
                    raise CaptureCancelled("Capture cancelled by the user.")
                detail = diagnostic or "The native authorization prompt was cancelled."
                raise CaptureSessionError(
                    "The authorized macOS capture command exited before packet capture started "
                    f"(osascript exit {return_code}): {detail}"
                )
            if time.monotonic() >= deadline:
                stop_capture_process(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                raise CaptureSessionError(
                    "Timed out waiting for the native macOS tcpdump authorization prompt. "
                    "Start the capture again and approve or cancel the prompt."
                )
            time.sleep(0.1)

        if not authorization_reported:
            print(CAPTURE_PREFLIGHT_EVENT, flush=True)
        print(CAPTURE_STARTED_EVENT, flush=True)
        try:
            return_code = process.wait(timeout=completion_timeout_seconds)
        except subprocess.TimeoutExpired as error:
            cancellation_marker = controller.cancellation_marker
            if cancellation_marker is None:
                raise CaptureSessionError(
                    "The macOS capture exceeded its completion deadline and no cancellation "
                    "channel was available."
                ) from error
            cancellation_marker.touch()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise CaptureSessionError(
                "tcpdump did not close within 15 seconds after the requested duration. "
                "RVI-Sentinel requested cleanup and stopped waiting."
            ) from error
        diagnostic = process_diagnostic(process)
        if diagnostic:
            print(diagnostic)
        if controller.cancelled:
            raise CaptureCancelled("Capture cancelled by the user.")
        if return_code != 0:
            failure = (
                failure_marker.read_text(encoding="utf-8").strip()
                if failure_marker.exists()
                else ""
            )
            detail = failure or diagnostic or "No diagnostic output was returned."
            raise CaptureSessionError(
                "The authorized macOS tcpdump command failed "
                f"(osascript exit {return_code}): {detail}"
            )
    finally:
        controller.active_process = None


def run_macos_capture(
    request: CaptureRequest, controller: CaptureProcessController
) -> None:
    ready_device = ensure_macos_device_ready(request.device.udid)
    rvictl = (
        str(APPLE_RVICTL)
        if APPLE_RVICTL.is_file() and os.access(APPLE_RVICTL, os.X_OK)
        else shutil.which("rvictl")
    )
    tcpdump = shutil.which("tcpdump")
    ifconfig = shutil.which("ifconfig")
    osascript = shutil.which("osascript")
    missing = [
        name
        for name, path in (
            ("rvictl", rvictl),
            ("tcpdump", tcpdump),
            ("ifconfig", ifconfig),
            ("osascript", osascript),
        )
        if path is None
    ]
    if missing:
        raise CaptureSessionError(
            "Required macOS capture commands were not found: " + ", ".join(missing)
        )
    rvictl_path = cast(str, rvictl)
    tcpdump_path = cast(str, tcpdump)
    ifconfig_path = cast(str, ifconfig)
    osascript_path = cast(str, osascript)

    print(
        f"Device ready: {ready_device.name} — {ready_device.status}",
        flush=True,
    )
    print(f"Apple RVI command: {rvictl_path}", flush=True)
    before = available_rvi_interfaces(ifconfig_path)
    start = subprocess.run(
        [rvictl_path, "-s", request.device.udid],
        capture_output=True,
        text=True,
        check=False,
    )
    start_output = "\n".join(part for part in (start.stdout, start.stderr) if part)
    if start.returncode != 0:
        raise CaptureSessionError(
            f"rvictl could not start the selected device (exit {start.returncode}):\n"
            f"{start_output.strip()}"
        )
    capture_error: CaptureSessionError | None = None
    try:
        interface = wait_for_created_rvi_interface(
            before,
            ifconfig_path,
            tcpdump_path,
            start_output,
            8.0,
        )
        print(f"RVI ready: {interface}", flush=True)
        print(CAPTURE_AUTHORIZATION_EVENT, flush=True)
        print(
            "macOS will now request administrator authorization for tcpdump. "
            "The capture countdown starts only after a packet passes the five-second preflight.",
            flush=True,
        )
        with tempfile.TemporaryDirectory(prefix="rvi-sentinel-preflight-") as directory:
            temporary_directory = Path(directory)
            preflight_path = temporary_directory / "preflight.pcapng"
            authorization_marker = temporary_directory / "authorized"
            ready_marker = temporary_directory / "capture-ready"
            failure_marker = temporary_directory / "capture-failed.txt"
            cancellation_marker = temporary_directory / "cancel-requested"
            controller.cancellation_marker = cancellation_marker
            shell_command = native_authorized_tcpdump_command(
                tcpdump_path,
                interface,
                request.output_path,
                preflight_path,
                authorization_marker,
                ready_marker,
                failure_marker,
                cancellation_marker,
                request.capture_format,
                getpass.getuser(),
                request.duration_seconds,
            )
            apple_script_arguments = [
                osascript_path,
                "-e",
                "on run argv",
                "-e",
                "do shell script (item 1 of argv) with administrator privileges",
                "-e",
                "end run",
                "--",
                shell_command,
            ]
            run_authorized_macos_capture(
                apple_script_arguments,
                controller,
                authorization_marker,
                ready_marker,
                failure_marker,
                300.0,
                request.duration_seconds + 15.0,
            )
            controller.cancellation_marker = None
        capture_size = validate_macos_capture_output(
            tcpdump_path, request.output_path, request.capture_format
        )
        print(
            f"Capture validated: {capture_size} bytes and at least one readable packet.",
            flush=True,
        )
        print(CAPTURE_VALIDATED_EVENT, flush=True)
    except CaptureSessionError as error:
        capture_error = error
    finally:
        controller.cancellation_marker = None
        stop = subprocess.run(
            [rvictl_path, "-x", request.device.udid],
            capture_output=True,
            text=True,
            check=False,
        )
        if stop.returncode != 0:
            detail = "\n".join(part for part in (stop.stdout, stop.stderr) if part).strip()
            cleanup_error = CaptureSessionError(
                f"Capture ended, but rvictl could not remove the device interface "
                f"(exit {stop.returncode}): {detail}"
            )
            if capture_error is not None:
                raise CaptureSessionError(f"{capture_error}\n{cleanup_error}")
            raise cleanup_error
    if capture_error is not None:
        raise capture_error


def run_mobile_capture(
    request: CaptureRequest, controller: CaptureProcessController
) -> None:
    if not UPSTREAM_CAPTURE.is_file():
        raise CaptureSessionError(
            "The Linux/Windows capture backend is not installed. Use Install Capture Support "
            "in the GUI, or run: python3 scripts/setup_rvi_capture.py"
        )
    arguments = [
        sys.executable,
        str(UPSTREAM_CAPTURE),
        "--format",
        request.capture_format,
        "--udid",
        request.device.udid,
        str(request.output_path),
    ]
    creation_flags = (
        subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0
    )
    print(CAPTURE_STARTED_EVENT, flush=True)
    return_code = controller.run_for_duration(
        arguments, request.duration_seconds, creation_flags
    )
    if return_code != 0:
        raise CaptureSessionError(
            f"The Linux/Windows capture backend exited with code {return_code}."
        )


def run_capture(request: CaptureRequest) -> None:
    validate_capture_request(request)
    request.output_path.parent.mkdir(parents=True, exist_ok=True)
    controller = CaptureProcessController()
    controller.install_signal_handlers()
    host_system = platform.system()
    if host_system == "Darwin":
        run_macos_capture(request, controller)
    elif host_system in {"Linux", "Windows"}:
        run_mobile_capture(request, controller)
    else:
        raise CaptureSessionError(
            f"RVI-Sentinel capture is not supported on this operating system: {host_system}"
        )
    if not request.output_path.is_file():
        raise CaptureSessionError(
            f"Capture backend exited successfully but did not create: {request.output_path}"
        )
    print(f"Capture complete: {request.output_path}")


def parse_arguments(arguments: list[str]) -> CaptureRequest:
    parser = argparse.ArgumentParser(
        description="Run a timed iPhone/iPad packet capture for RVI-Sentinel."
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--duration", required=True, type=int)
    parser.add_argument("--format", required=True, choices=("pcap", "pcapng"))
    values = parser.parse_args(arguments)
    device = DeviceInfo(
        name="Selected iOS device",
        udid=values.udid,
        operating_system="iOS/iPadOS",
        status="Connected",
        connected=True,
    )
    return CaptureRequest(
        device=device,
        output_path=values.output.expanduser().resolve(),
        duration_seconds=values.duration,
        capture_format=values.format,
        analyze_after_capture=False,
    )


def main(arguments: list[str]) -> int:
    try:
        request = parse_arguments(arguments)
        run_capture(request)
    except (CaptureSessionError, CaptureCancelled, ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
