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
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from capture_devices import DeviceDiscoveryError, discover_macos_devices
from capture_models import (
    CAPTURE_AUTHORIZATION_EVENT,
    CAPTURE_PREFLIGHT_EVENT,
    CAPTURE_STARTED_EVENT,
    CAPTURE_VALIDATED_EVENT,
    CAPTURE_NO_TRAFFIC_EVENT,
    CaptureRequest,
    DeviceInfo,
    validate_capture_request,
)
from capture_receipt import (
    CaptureCleanup, CaptureFailure, CaptureReceipt, receipt_event, receipt_is_success,
)
from capture_stats import validate_capture_artifact
from saved_capture import SavedCaptureError

ROOT = Path(__file__).resolve().parent
UPSTREAM_CAPTURE = ROOT / "tools" / "rvi_capture" / "rvi_capture.py"
RVI_INTERFACE = re.compile(r"^rvi[0-9]+$")
APPLE_RVICTL = Path("/Library/Apple/usr/bin/rvictl")
APPLE_RPMUXD_SERVICE = "system/com.apple.rpmuxd"
APPLE_RPMUXD_PLISTS = (
    Path("/Library/Apple/System/Library/LaunchDaemons/com.apple.rpmuxd.plist"),
    Path("/System/Library/LaunchDaemons/com.apple.rpmuxd.plist"),
)


class CaptureSessionError(RuntimeError):
    """Raised when a capture provider cannot complete a requested session."""

    code = "capture_backend_failed"


class CaptureCancelled(CaptureSessionError):
    """Raised when the user cancels an active capture."""

    code = "capture_cancelled"


class CaptureInterfaceOwnershipError(CaptureSessionError):
    """An interface cannot safely be attributed to this capture session."""

    code = "interface_ownership_unverified"


class CaptureCommandTimeout(CaptureSessionError):
    """A capture control command exceeded its bounded deadline."""

    code = "capture_command_timeout"


class CaptureEarlyExit(CaptureSessionError):
    """The recording provider exited before the requested interval ended."""

    code = "capture_early_exit"


class CaptureCleanupIncomplete(CaptureSessionError):
    """The session-owned interface remains after its removal command."""

    code = "interface_cleanup_incomplete"


class CaptureBackendExit(CaptureSessionError):
    """A provider exited unsuccessfully, retaining its safe numeric exit status."""

    code = "capture_backend_exit"


class CaptureShutdownUnverified(CaptureSessionError):
    """A privileged wrapper exited without a recording-child acknowledgement."""

    code = "recording_shutdown_unverified"


class CaptureNoTraffic(CaptureSessionError):
    """The authorized preflight ended without observed device traffic."""

    code = "preflight_no_traffic"


class CaptureInterfaceInspectionError(CaptureSessionError):
    """Interface state cannot be verified from a failed inventory operation."""

    code = "interface_inspection_failed"


@dataclass(frozen=True, slots=True)
class BackendCaptureResult:
    """Recording and cleanup evidence, independent of saved-file validation."""

    capture_outcome: Literal["completed", "cancelled", "failed"]
    recording_lifetime_nanoseconds: int | None
    cleanup: CaptureCleanup
    failures: tuple[CaptureFailure, ...]


class CaptureProcessController:
    """Track owned child shutdown separately from a cancellation request."""

    def __init__(self) -> None:
        self.active_process: subprocess.Popen[str] | None = None
        self.cancellation_marker: Path | None = None
        self.cancelled = False
        self.validation_cancellation: threading.Event | None = None
        self.recording_process_stopped: bool | None = True
        self.provider_lifetime_nanoseconds: int | None = None
        self.duration_reached = False

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGTERM, self.cancel)
        signal.signal(signal.SIGINT, self.cancel)

    def cancel(self, signal_number: int, _frame: object) -> None:
        self.cancelled = True
        validation_cancellation = self.validation_cancellation
        if validation_cancellation is not None:
            validation_cancellation.set()
            return
        cancellation_marker = self.cancellation_marker
        if cancellation_marker is not None:
            cancellation_marker.touch()
            return
        process = self.active_process
        if process is not None and process.poll() is None:
            stop_capture_process(process)

    def run_until_exit(self, arguments: list[str], creation_flags: int) -> int:
        process = subprocess.Popen(
            arguments,
            text=True,
            creationflags=creation_flags,
        )
        self.active_process = process
        self.recording_process_stopped = False
        started = time.monotonic_ns()
        try:
            while process.poll() is None:
                if self.cancelled:
                    stop_and_reap_capture_process(process)
                    raise CaptureCancelled("Capture cancelled by the user.")
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
            return process.wait(timeout=1)
        finally:
            if process.poll() is None:
                stop_and_reap_capture_process(process)
            self.recording_process_stopped = process.poll() is not None
            self.provider_lifetime_nanoseconds = time.monotonic_ns() - started
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
        self.recording_process_stopped = False
        self.duration_reached = False
        started = time.monotonic_ns()
        deadline = time.monotonic() + duration_seconds
        try:
            while process.poll() is None:
                if self.cancelled:
                    stop_and_reap_capture_process(process)
                    raise CaptureCancelled("Capture cancelled by the user.")
                if time.monotonic() >= deadline:
                    self.duration_reached = True
                    print(f"Capture duration reached ({duration_seconds} seconds); stopping cleanly.")
                    return stop_and_reap_capture_process(process)
                try:
                    process.wait(timeout=min(0.1, max(0.001, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    continue
            return process.wait(timeout=1)
        finally:
            if process.poll() is None:
                stop_and_reap_capture_process(process)
            self.recording_process_stopped = process.poll() is not None
            self.provider_lifetime_nanoseconds = time.monotonic_ns() - started
            self.active_process = None


def stop_and_reap_capture_process(process: subprocess.Popen[str]) -> int:
    """Bound shutdown of the directly owned child; wrappers prove only their exit."""
    if process.poll() is None:
        stop_capture_process(process)
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired as kill_error:
                raise CaptureCommandTimeout("The owned capture child could not be reaped after forced termination.") from kill_error
            raise CaptureCommandTimeout("The owned capture child required forced termination; a clean recording shutdown was not verified.") from error
    return process.wait(timeout=1)


def run_capture_command(arguments: list[str], timeout_seconds: float) -> subprocess.CompletedProcess[str]:
    """Bound control-command lifetime and output while avoiding pipe deadlocks."""
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stdout, tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, text=True)
        deadline = time.monotonic() + timeout_seconds
        try:
            while process.poll() is None:
                if os.fstat(stdout.fileno()).st_size > 65_536 or os.fstat(stderr.fileno()).st_size > 65_536:
                    raise CaptureSessionError("Capture control-command output exceeded its 64 KiB diagnostic limit.")
                if time.monotonic() >= deadline:
                    raise CaptureCommandTimeout("A capture control command exceeded its deadline. Check device readiness and inspect the session cleanup outcome.")
                try:
                    process.wait(timeout=0.05)
                except subprocess.TimeoutExpired:
                    continue
            stdout.seek(0)
            stderr.seek(0)
            output = stdout.read(65_537)
            diagnostic = stderr.read(65_537)
            if len(output.encode("utf-8")) > 65_536 or len(diagnostic.encode("utf-8")) > 65_536:
                raise CaptureSessionError("Capture control-command output exceeded its 64 KiB diagnostic limit.")
            return subprocess.CompletedProcess(arguments, process.wait(timeout=1), output, diagnostic)
        finally:
            if process.poll() is None:
                stop_and_reap_capture_process(process)


def ensure_macos_rvi_relay_ready(launchctl: str) -> None:
    result = run_capture_command([launchctl, "print", APPLE_RPMUXD_SERVICE], 5.0)
    if result.returncode == 0:
        return
    installed_plist = next((path for path in APPLE_RPMUXD_PLISTS if path.is_file()), None)
    if installed_plist is None:
        raise CaptureSessionError(
            "Apple RVI support is incomplete: the com.apple.rpmuxd launch daemon is not "
            "installed. Open Xcode and install its requested device-support components, then "
            "run Check setup again."
        )
    raise CaptureSessionError(
        "Apple RVI support is installed, but com.apple.rpmuxd is not loaded. This causes "
        "rvictl to fail with bootstrap error 1102. Open Check setup for the exact repair "
        "command, then retry the capture."
    )


def stop_capture_process(process: subprocess.Popen[str]) -> None:
    try:
        if platform.system() == "Windows":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        if process.poll() is None:
            raise


def available_rvi_interfaces(ifconfig: str) -> frozenset[str]:
    result = run_capture_command([ifconfig, "-l"], 3.0)
    if result.returncode != 0:
        raise CaptureInterfaceInspectionError(
            f"Interface inventory could not be read (ifconfig exit {result.returncode}). Inspect active interfaces before retrying cleanup."
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
    result = run_capture_command([tcpdump, "-D"], 3.0)
    if result.returncode != 0:
        raise CaptureInterfaceInspectionError(
            f"Capture interface inventory could not be read (tcpdump exit {result.returncode}). Check capture support before retrying."
        )
    return parse_tcpdump_interfaces(result.stdout)


def select_created_interface(
    before: frozenset[str], after: frozenset[str], rvictl_output: str
) -> str:
    mentioned = sorted(
        {
            candidate
            for candidate in re.findall(r"\brvi[0-9]+\b", rvictl_output)
        }
    )
    if len(mentioned) == 1 and mentioned[0] in after - before:
        return mentioned[0]
    raise CaptureInterfaceOwnershipError(
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
        readiness = run_capture_command([ifconfig, interface], 3.0)
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
    stopped = shlex.quote(str(ready_marker.with_name("capture-stopped")))
    return (
        "set -eu; "
        "capture_pid=''; capture_stop_status=0; "
        "stop_owned_capture() { "
        "capture_stop_status=0; "
        "if [ -n \"$capture_pid\" ]; then "
        "if /bin/kill -0 \"$capture_pid\" 2>/dev/null; then "
        "/bin/kill -INT \"$capture_pid\" 2>/dev/null || :; "
        "for stop_second in 1 2 3 4 5; do "
        "if ! /bin/kill -0 \"$capture_pid\" 2>/dev/null; then break; fi; /bin/sleep 1; done; "
        "if /bin/kill -0 \"$capture_pid\" 2>/dev/null; then "
        "/bin/kill -TERM \"$capture_pid\" 2>/dev/null || :; "
        "for stop_second in 1 2; do "
        "if ! /bin/kill -0 \"$capture_pid\" 2>/dev/null; then break; fi; /bin/sleep 1; done; fi; "
        "if /bin/kill -0 \"$capture_pid\" 2>/dev/null; then /bin/kill -KILL \"$capture_pid\"; fi; fi; "
        "wait \"$capture_pid\" || capture_stop_status=$?; capture_pid=''; "
        f"/usr/bin/touch {stopped}; fi; "
        "}; "
        "cleanup_capture() { stop_owned_capture; "
        f"/bin/rm -f {preflight} {authorization} {ready} {cancellation}; "
        "}; "
        "trap 'cleanup_capture; exit 44' HUP INT TERM; trap cleanup_capture EXIT; "
        f"/usr/bin/touch {authorization}; /bin/rm -f {stopped}; "
        f"{preflight_command} & capture_pid=$!; "
        "for preflight_second in 1 2 3 4 5; do "
        f"if [ -e {cancellation} ]; then break; fi; "
        "if ! /bin/kill -0 \"$capture_pid\" 2>/dev/null; then break; fi; /bin/sleep 1; done; "
        f"if [ -e {cancellation} ]; then stop_owned_capture; exit 44; fi; "
        "if /bin/kill -0 \"$capture_pid\" 2>/dev/null; then stop_owned_capture; "
        f"/usr/bin/printf '%s\\n' {no_packet_message} > {failure}; exit 42; fi; "
        "stop_owned_capture; "
        "if [ \"$capture_stop_status\" -ne 0 ]; then "
        f"/usr/bin/printf '%s\\n' {preflight_failed_message} > {failure}; exit \"$capture_stop_status\"; fi; "
        f"if [ ! -s {preflight} ]; then /usr/bin/printf '%s\\n' {preflight_failed_message} > {failure}; exit 43; fi; "
        f"/bin/rm -f {preflight} {stopped}; "
        f"{capture_command} & capture_pid=$!; /bin/sleep 1; "
        "if ! /bin/kill -0 \"$capture_pid\" 2>/dev/null; then stop_owned_capture; "
        f"/usr/bin/printf '%s\\n' {capture_failed_message} > {failure}; exit 43; fi; "
        f"/usr/bin/touch {ready}; capture_remaining={duration_seconds}; "
        "while [ \"$capture_remaining\" -gt 0 ] && /bin/kill -0 \"$capture_pid\" 2>/dev/null "
        f"&& [ ! -e {cancellation} ]; do /bin/sleep 1; capture_remaining=$((capture_remaining - 1)); done; "
        f"if [ -e {cancellation} ]; then stop_owned_capture; exit 44; fi; "
        "stop_owned_capture; "
        "if [ \"$capture_stop_status\" -ne 0 ] || [ \"$capture_remaining\" -gt 0 ]; then "
        f"/usr/bin/printf '%s\\n' {capture_failed_message} > {failure}; exit 43; fi; "
        f"/bin/rm -f {authorization} {ready} {cancellation}; trap - EXIT HUP INT TERM"
    )



def validate_macos_capture_output(
    tcpdump: str, output_path: Path, capture_format: str
) -> int:
    """Compatibility entrypoint: verify the entire stable requested-format file."""
    try:
        artifact = validate_capture_artifact(output_path, capture_format, threading.Event())
    except SavedCaptureError as error:
        raise CaptureSessionError(f"Completed capture validation failed ({error.code}): {error}") from error
    if artifact.positive_packet_count == 0:
        raise CaptureSessionError("The completed capture has no positive captured packet data. Generate device traffic and capture again.")
    return artifact.size_bytes


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


def remove_macos_rvi_interface(
    rvictl: str,
    ifconfig: str,
    udid: str,
    interface: str | None,
    interfaces_before_capture: frozenset[str],
) -> None:
    if interface is None or interface in interfaces_before_capture:
        raise CaptureInterfaceOwnershipError(
            "RVI cleanup was not attempted because the interface is not uniquely owned by this session. Inspect active interfaces before removing anything manually."
        )
    if interface not in available_rvi_interfaces(ifconfig):
        return
    stop = run_capture_command([rvictl, "-x", udid], 5.0)
    interfaces_after_stop = available_rvi_interfaces(ifconfig)
    if interface not in interfaces_after_stop:
        return
    raise CaptureCleanupIncomplete(
        f"The session-owned RVI interface remained active after cleanup (rvictl exit {stop.returncode}). Inspect the interface and retry cleanup explicitly."
    )


def process_diagnostic(process: subprocess.Popen[str]) -> str:
    """Read legacy process diagnostics with a finite communicate deadline."""
    standard_output, standard_error = process.communicate(timeout=2)
    if len(standard_output) + len(standard_error) > 65_536:
        raise CaptureSessionError("Capture diagnostics exceeded their 64 KiB limit.")
    return "\n".join(part.strip() for part in (standard_output, standard_error) if part.strip())


def run_authorized_macos_capture(
    arguments: list[str],
    controller: CaptureProcessController,
    authorization_marker: Path,
    ready_marker: Path,
    failure_marker: Path,
    authorization_timeout_seconds: float,
    completion_timeout_seconds: float,
) -> None:
    """Monitor a privileged wrapper; only its child-stop marker proves recording exit.

    The parent does not observe tcpdump's full lifetime across authorization and
    startup, so it leaves recording lifetime unavailable rather than including
    authorization, validation or cleanup in an invented measurement.
    """
    stopped_marker = ready_marker.with_name("capture-stopped")
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stdout, tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, text=True, stdout=stdout, stderr=stderr)
        controller.active_process = process
        controller.recording_process_stopped = None
        controller.provider_lifetime_nanoseconds = None
        authorization_reported = False
        recording_reported = False
        deadline = time.monotonic() + authorization_timeout_seconds
        try:
            while process.poll() is None:
                if os.fstat(stdout.fileno()).st_size > 65_536 or os.fstat(stderr.fileno()).st_size > 65_536:
                    raise CaptureSessionError("Authorized capture diagnostics exceeded the 64 KiB limit.")
                if controller.cancelled and not authorization_marker.exists() and not recording_reported:
                    stop_and_reap_capture_process(process)
                    raise CaptureCancelled("Capture cancelled before recording was observed.")
                if authorization_marker.exists() and not authorization_reported:
                    print(CAPTURE_PREFLIGHT_EVENT, flush=True)
                    authorization_reported = True
                if ready_marker.exists() and not recording_reported:
                    recording_reported = True
                    print(CAPTURE_STARTED_EVENT, flush=True)
                    deadline = time.monotonic() + completion_timeout_seconds
                if time.monotonic() >= deadline:
                    marker = controller.cancellation_marker
                    if marker is not None:
                        marker.touch()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        stop_and_reap_capture_process(process)
                    raise CaptureCommandTimeout("The native capture helper exceeded its authorization or completion deadline. Recording shutdown must be checked separately.")
                try:
                    process.wait(timeout=0.1)
                except subprocess.TimeoutExpired:
                    continue
            return_code = process.wait(timeout=1)
            if failure_marker.exists():
                if failure_marker.stat().st_size > 4096:
                    raise CaptureSessionError("The native capture failure marker exceeded its 4 KiB limit.")
                failure = failure_marker.read_text(encoding="utf-8")
                if failure.startswith("No packets arrived"):
                    print(CAPTURE_NO_TRAFFIC_EVENT, flush=True)
                    raise CaptureNoTraffic("No device traffic was observed during the five-second preflight. Generate device network activity and retry the traffic check.")
            if controller.cancelled:
                raise CaptureCancelled("Capture cancelled by the user.")
            if return_code != 0:
                raise CaptureBackendExit(f"The authorized capture helper failed (exit {return_code}). Check device readiness and the independent cleanup outcome.")
            if not recording_reported:
                raise CaptureEarlyExit("The authorized helper exited without an observed recording start.")
            if not stopped_marker.is_file():
                raise CaptureShutdownUnverified("The recording helper exited without its child-stop acknowledgement. Inspect the session before another capture.")
        finally:
            try:
                if process.poll() is None:
                    stop_and_reap_capture_process(process)
            finally:
                controller.recording_process_stopped = True if stopped_marker.is_file() else None
                controller.active_process = None


def capture_failure(stage: Literal["capture", "validation", "cleanup"], error: CaptureSessionError | SavedCaptureError | OSError | ValueError) -> CaptureFailure:
    """Preserve a distinct boundary code without serializing provider payloads."""
    if isinstance(error, SavedCaptureError):
        return CaptureFailure(stage, error.code, str(error))
    if isinstance(error, CaptureCancelled):
        return CaptureFailure(stage, error.code, "Capture was cancelled. Review saved-file validation and both cleanup outcomes separately.")
    if isinstance(error, CaptureInterfaceOwnershipError):
        return CaptureFailure(stage, error.code, "Interface ownership could not be established; existing interfaces were preserved. Inspect active interfaces before manual cleanup.")
    if isinstance(error, CaptureCommandTimeout):
        return CaptureFailure(stage, error.code, "A capture operation exceeded its deadline. Check device readiness and independently verify recording and interface cleanup.")
    if isinstance(error, CaptureEarlyExit):
        return CaptureFailure(stage, error.code, "The recording backend exited before the requested interval completed. Review any validated partial file and retry after checking device readiness.")
    if isinstance(error, (CaptureCleanupIncomplete, CaptureBackendExit, CaptureShutdownUnverified, CaptureNoTraffic, CaptureInterfaceInspectionError)):
        return CaptureFailure(stage, error.code, str(error))
    if isinstance(error, OSError):
        return CaptureFailure(stage, "capture_io_failed", "A capture command or local file operation failed. Check tool availability, output permissions, and the independent cleanup outcome.")
    if isinstance(error, ValueError):
        return CaptureFailure(stage, "capture_invalid_input", "Capture settings or a control response were invalid. Check device, format, duration, and the selected output destination.")
    return CaptureFailure(stage, error.code, "The capture backend operation failed. Check device readiness, installed tools, and the independent cleanup outcome before retrying.")


def run_macos_capture(
    request: CaptureRequest, controller: CaptureProcessController
) -> BackendCaptureResult:
    """Record one session and report owned process/interface cleanup independently."""
    failures: list[CaptureFailure] = []
    outcome: Literal["completed", "cancelled", "failed"] = "completed"
    interface_status: Literal["verified_complete", "failed", "unverified", "not_applicable"] = "not_applicable"
    interface: str | None = None
    before: frozenset[str] = frozenset()
    start_attempted = False
    rvictl_path: str | None = None
    ifconfig_path: str | None = None
    try:
        ready_device = ensure_macos_device_ready(request.device.udid)
        rvictl_path = str(APPLE_RVICTL) if APPLE_RVICTL.is_file() and os.access(APPLE_RVICTL, os.X_OK) else shutil.which("rvictl")
        tcpdump_path = shutil.which("tcpdump")
        ifconfig_path = shutil.which("ifconfig")
        osascript_path = shutil.which("osascript")
        launchctl_path = shutil.which("launchctl")
        if rvictl_path is None or tcpdump_path is None or ifconfig_path is None or osascript_path is None or launchctl_path is None:
            raise CaptureSessionError("Required macOS capture commands are unavailable. Run Check setup before retrying.")
        ensure_macos_rvi_relay_ready(launchctl_path)
        if controller.cancelled:
            raise CaptureCancelled("Capture cancelled before interface creation.")
        print(f"Device ready: {ready_device.name} — {ready_device.status}", flush=True)
        before = available_rvi_interfaces(ifconfig_path)
        start_attempted = True
        interface_status = "unverified"
        start = run_capture_command([rvictl_path, "-s", request.device.udid], 5.0)
        start_output = "\n".join(part for part in (start.stdout, start.stderr) if part)
        if start.returncode != 0 or "bootstrap_look_up(): 1102" in start_output or "[FAILED]" in start_output:
            raise CaptureSessionError("Apple RVI could not start the selected device. Run Check setup and inspect active interfaces before retrying.")
        interface = wait_for_created_rvi_interface(before, ifconfig_path, tcpdump_path, start_output, 8.0)
        if controller.cancelled:
            raise CaptureCancelled("Capture cancelled after interface creation.")
        print(f"RVI ready: {interface}", flush=True)
        print(CAPTURE_AUTHORIZATION_EVENT, flush=True)
        with tempfile.TemporaryDirectory(prefix="rvi-sentinel-preflight-") as directory:
            temporary_directory = Path(directory)
            preflight_path = temporary_directory / "preflight.pcapng"
            authorization_marker = temporary_directory / "authorized"
            ready_marker = temporary_directory / "capture-ready"
            failure_marker = temporary_directory / "capture-failed.txt"
            cancellation_marker = temporary_directory / "cancel-requested"
            controller.cancellation_marker = cancellation_marker
            shell_command = native_authorized_tcpdump_command(
                tcpdump_path, interface, request.output_path, preflight_path,
                authorization_marker, ready_marker, failure_marker, cancellation_marker,
                request.capture_format, getpass.getuser(), request.duration_seconds,
            )
            apple_script_arguments = [
                osascript_path, "-e", "on run argv", "-e",
                "do shell script (item 1 of argv) with administrator privileges",
                "-e", "end run", "--", shell_command,
            ]
            run_authorized_macos_capture(
                apple_script_arguments, controller, authorization_marker, ready_marker,
                failure_marker, 300.0, request.duration_seconds + 20.0,
            )
    except (CaptureSessionError, OSError, ValueError) as error:
        outcome = "cancelled" if controller.cancelled or isinstance(error, CaptureCancelled) else "failed"
        failures.append(capture_failure("capture", error))
    finally:
        controller.cancellation_marker = None
        if start_attempted and rvictl_path is not None and ifconfig_path is not None:
            if interface is None:
                failures.append(CaptureFailure("cleanup", "interface_ownership_unverified", "The interface could not be uniquely attributed to this session. No interface was removed; inspect active interfaces before manual cleanup."))
            else:
                try:
                    remove_macos_rvi_interface(rvictl_path, ifconfig_path, request.device.udid, interface, before)
                    interface_status = "verified_complete"
                except (CaptureSessionError, OSError, ValueError) as cleanup_error:
                    interface_status = "failed" if isinstance(cleanup_error, CaptureCleanupIncomplete) else "unverified"
                    failures.append(capture_failure("cleanup", cleanup_error))
    if controller.recording_process_stopped is not True:
        failures.append(CaptureFailure("cleanup", "recording_shutdown_unverified", "The recording process has no verified stop acknowledgement. Inspect the session before starting another capture."))
    return BackendCaptureResult(outcome, None,
        CaptureCleanup(controller.recording_process_stopped, interface_status), tuple(failures))


def run_mobile_capture(
    request: CaptureRequest, controller: CaptureProcessController
) -> BackendCaptureResult:
    """Preserve the upstream adapter while measuring only its owned child lifetime."""
    failures: list[CaptureFailure] = []
    outcome: Literal["completed", "cancelled", "failed"] = "completed"
    try:
        if not UPSTREAM_CAPTURE.is_file():
            raise CaptureSessionError("The Linux/Windows capture backend is not installed. Use Install Capture Support before retrying.")
        if controller.cancelled:
            raise CaptureCancelled("Capture cancelled before recording started.")
        arguments = [sys.executable, str(UPSTREAM_CAPTURE), "--format", request.capture_format, "--udid", request.device.udid, str(request.output_path)]
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0
        print(CAPTURE_STARTED_EVENT, flush=True)
        return_code = controller.run_for_duration(arguments, request.duration_seconds, creation_flags)
        if return_code != 0:
            raise CaptureBackendExit(f"The Linux/Windows capture backend failed (exit {return_code}).")
        if not controller.duration_reached:
            raise CaptureEarlyExit("The upstream capture backend exited before the requested interval.")
    except (CaptureSessionError, OSError, ValueError) as error:
        outcome = "cancelled" if controller.cancelled or isinstance(error, CaptureCancelled) else "failed"
        failures.append(capture_failure("capture", error))
    if controller.recording_process_stopped is not True:
        failures.append(CaptureFailure("cleanup", "recording_shutdown_unverified", "The owned capture child could not be confirmed stopped. Inspect the session before another capture."))
    # Provider startup/connection/shutdown are not observed recording boundaries.
    return BackendCaptureResult(outcome, None,
        CaptureCleanup(controller.recording_process_stopped, "not_applicable"), tuple(failures))


def assemble_capture_receipt(
    request: CaptureRequest, request_id: str, result: BackendCaptureResult,
    validation_cancellation: threading.Event,
) -> CaptureReceipt:
    """Validate saved bytes after cleanup, preserving every independent outcome."""
    failures = result.failures
    try:
        artifact = validate_capture_artifact(request.output_path, request.capture_format, validation_cancellation)
    except SavedCaptureError as error:
        return CaptureReceipt(request_id, request.output_path, request.capture_format,
            request.duration_seconds, result.recording_lifetime_nanoseconds,
            result.capture_outcome, "failed", None, result.cleanup,
            failures + (capture_failure("validation", error),))
    if artifact.positive_packet_count == 0:
        failures += (CaptureFailure("validation", "no_positive_data", "The file is fully readable but contains no positive captured packet data. Generate device traffic before retrying."),)
    return CaptureReceipt(request_id, request.output_path, request.capture_format,
        request.duration_seconds, result.recording_lifetime_nanoseconds,
        result.capture_outcome, "verified", artifact, result.cleanup, failures)


def run_capture(request: CaptureRequest, request_id: str) -> CaptureReceipt:
    """Return a final receipt only after recording, cleanup and full verification."""
    validate_capture_request(request)
    if re.fullmatch(r"[0-9a-f]{32}", request_id) is None:
        raise ValueError("Capture request identity must contain 32 lowercase hexadecimal characters.")
    request.output_path.parent.mkdir(parents=True, exist_ok=True)
    controller = CaptureProcessController()
    previous_interrupt = signal.getsignal(signal.SIGINT)
    previous_terminate = signal.getsignal(signal.SIGTERM)
    controller.install_signal_handlers()
    try:
        host_system = platform.system()
        if host_system == "Darwin":
            result = run_macos_capture(request, controller)
        elif host_system in {"Linux", "Windows"}:
            result = run_mobile_capture(request, controller)
        else:
            error = CaptureSessionError("Capture is unsupported on this operating system.")
            result = BackendCaptureResult("failed", None, CaptureCleanup(True, "not_applicable"), (capture_failure("capture", error),))
        validation_cancellation = threading.Event()
        controller.validation_cancellation = validation_cancellation
        validation_deadline = threading.Timer(10.0, validation_cancellation.set)
        if controller.cancelled:
            validation_deadline.start()
        try:
            receipt = assemble_capture_receipt(request, request_id, result, validation_cancellation)
        finally:
            validation_deadline.cancel()
            if validation_deadline.ident is not None:
                validation_deadline.join(timeout=1)
            controller.validation_cancellation = None
        if receipt.validation_status == "verified":
            print(CAPTURE_VALIDATED_EVENT, flush=True)
        return receipt

    finally:
        signal.signal(signal.SIGINT, previous_interrupt)
        signal.signal(signal.SIGTERM, previous_terminate)


def parse_capture_command(arguments: list[str]) -> tuple[CaptureRequest, str]:
    parser = argparse.ArgumentParser(
        description="Run a timed iPhone/iPad packet capture for RVI-Sentinel."
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--duration", required=True, type=int)
    parser.add_argument("--format", required=True, choices=("pcap", "pcapng"))
    parser.add_argument("--request-id", help="32 lowercase hexadecimal characters binding a GUI request to its final receipt")
    values = parser.parse_args(arguments)
    request_id = values.request_id if values.request_id is not None else uuid.uuid4().hex
    if re.fullmatch(r"[0-9a-f]{32}", request_id) is None:
        raise ValueError("Capture request identity must contain 32 lowercase hexadecimal characters.")
    device = DeviceInfo(
        name="Selected iOS device",
        udid=values.udid,
        operating_system="iOS/iPadOS",
        status="Connected",
        connected=True,
    )
    request = CaptureRequest(
        device=device,
        output_path=values.output.expanduser().absolute(),
        duration_seconds=values.duration,
        capture_format=values.format,
        analyze_after_capture=False,
    )
    return request, request_id


def parse_arguments(arguments: list[str]) -> CaptureRequest:
    """Keep the existing request-parser API while the CLI also carries a nonce."""
    request, _request_id = parse_capture_command(arguments)
    return request


def main(arguments: list[str]) -> int:
    try:
        request, request_id = parse_capture_command(arguments)
        receipt = run_capture(request, request_id)
        print(receipt_event(receipt), flush=True)
    except (CaptureSessionError, CaptureCancelled, ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    if not receipt_is_success(receipt):
        for failure in receipt.failures:
            print(f"{failure.stage}: {failure.code}: {failure.message}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
