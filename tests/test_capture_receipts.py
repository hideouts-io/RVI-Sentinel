"""Validate saved artifacts and capture receipts without device or privileged operations.

Real TShark reads generated packet containers. Controlled backend results exercise
the unavailable device boundary; they do not establish physical RVI teardown.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from analyze import load_baseline, report_destinations
from capture_models import CaptureRequest, DeviceInfo
from capture_receipt import (
    CAPTURE_RECEIPT_EVENT,
    CaptureCleanup,
    CaptureFailure,
    CaptureReceipt,
    parse_capture_receipt,
    receipt_document,
    receipt_event,
    receipt_is_success,
    validate_receipt_binding,
)
from capture_session import (
    BackendCaptureResult,
    CaptureCancelled,
    CaptureCommandTimeout,
    CaptureBackendExit,
    CaptureCleanupIncomplete,
    CaptureInterfaceInspectionError,
    CaptureShutdownUnverified,
    CaptureProcessController,
    CaptureSessionError,
    run_capture,
    run_macos_capture,
    run_mobile_capture,
    run_authorized_macos_capture,
    native_authorized_tcpdump_command,
    select_created_interface,
    remove_macos_rvi_interface,
    stop_and_reap_capture_process,
    validate_macos_capture_output,
)
from capture_stats import CaptureArtifact, validate_capture_artifact
from saved_capture import SavedCaptureCancelled
from tests.saved_capture_fixture import classic_capture, metadata_capture

REQUEST_ID = "0123456789abcdef0123456789abcdef"
DEVICE = DeviceInfo("Fixture iPhone", "00008150-000000000000001C", "Fixture iOS", "Connected", True)


def capture_request(path: Path, capture_format: str) -> CaptureRequest:
    return CaptureRequest(DEVICE, path, 5, capture_format, False)


def artifact_receipt(artifact: CaptureArtifact, path: Path) -> CaptureReceipt:
    return CaptureReceipt(
        REQUEST_ID,
        path,
        artifact.capture_format,
        5,
        5_200_000_000,
        "completed",
        "verified",
        artifact,
        CaptureCleanup(True, "verified_complete"),
        (),
    )


class CaptureReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("Capture receipt integration requires real TShark on PATH.")

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-sentinel-receipt-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def saved_capture(self, content: bytes, capture_format: str) -> Path:
        capture = self.directory / ("generated." + capture_format)
        capture.write_bytes(content)
        return capture

    def capture_with_result(self, request: CaptureRequest, result: BackendCaptureResult) -> CaptureReceipt:
        content = request.output_path.read_bytes() if request.output_path.is_file() else None
        if content is not None:
            self.assertEqual(request.output_path.parent, self.directory)
            request.output_path.unlink()

        def recording_backend(_request: CaptureRequest, _controller: CaptureProcessController) -> BackendCaptureResult:
            if content is not None:
                _request.output_path.write_bytes(content)
            if result.capture_outcome == "cancelled":
                _controller.cancelled = True
            return result

        with (
            patch("capture_session.platform.system", return_value="Darwin"),
            patch.object(CaptureProcessController, "install_signal_handlers"),
            patch("capture_session.run_macos_capture", side_effect=recording_backend) as backend,
        ):
            receipt = run_capture(request, REQUEST_ID)
        backend.assert_called_once()
        return receipt

    def test_complete_saved_files_produce_traceable_receipts_with_exact_packet_span(self) -> None:
        cases = (("pcap", classic_capture(3)), ("pcapng", metadata_capture()))
        for capture_format, content in cases:
            with self.subTest(capture_format=capture_format):
                capture = self.saved_capture(content, capture_format)
                result = BackendCaptureResult("completed", 5_200_000_000, CaptureCleanup(True, "verified_complete"), ())
                receipt = self.capture_with_result(capture_request(capture, capture_format), result)
                self.assertTrue(receipt_is_success(receipt))
                self.assertEqual(receipt.capture_outcome, "completed")
                self.assertEqual(receipt.validation_status, "verified")
                self.assertEqual(receipt.requested_duration_seconds, 5)
                self.assertEqual(receipt.recording_lifetime_nanoseconds, 5_200_000_000)
                self.assertIsNotNone(receipt.artifact)
                artifact = receipt.artifact
                assert artifact is not None
                self.assertEqual(artifact.capture_format, capture_format)
                self.assertEqual(artifact.packet_count, 3)
                self.assertEqual(artifact.positive_packet_count, 3)
                self.assertEqual(artifact.sha256, hashlib.sha256(content).hexdigest())
                self.assertEqual(artifact.size_bytes, len(content))
                self.assertEqual(artifact.first_packet_epoch, "1791428448.590385001")
                self.assertEqual(artifact.last_packet_epoch, "1791428448.590385003")
                self.assertEqual(artifact.packet_span_nanoseconds, 2)
                self.assertEqual(capture.read_bytes(), content)

    def test_one_packet_span_does_not_replace_recording_lifetime(self) -> None:
        capture = self.saved_capture(classic_capture(1), "pcap")
        result = BackendCaptureResult("completed", 5_000_000_000, CaptureCleanup(True, "not_applicable"), ())
        receipt = self.capture_with_result(capture_request(capture, "pcap"), result)
        self.assertIsNotNone(receipt.artifact)
        assert receipt.artifact is not None
        self.assertEqual(receipt.artifact.packet_span_nanoseconds, 0)
        self.assertEqual(receipt.recording_lifetime_nanoseconds, 5_000_000_000)

    def test_valid_artifact_survives_cleanup_failure_with_distinct_failure(self) -> None:
        content = metadata_capture()
        capture = self.saved_capture(content, "pcapng")
        failure = CaptureFailure("cleanup", "rvi_cleanup_failed", "The owned interface remained active after removal.")
        result = BackendCaptureResult("completed", None, CaptureCleanup(True, "failed"), (failure,))
        receipt = self.capture_with_result(capture_request(capture, "pcapng"), result)
        self.assertFalse(receipt_is_success(receipt))
        self.assertEqual(receipt.capture_outcome, "completed")
        self.assertEqual(receipt.validation_status, "verified")
        self.assertEqual(receipt.cleanup.interface_status, "failed")
        self.assertEqual(receipt.failures, (failure,))
        self.assertIsNotNone(receipt.artifact)
        assert receipt.artifact is not None
        self.assertEqual(receipt.artifact.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(capture.read_bytes(), content)

    def test_capture_and_cleanup_failures_remain_separate_from_valid_saved_evidence(self) -> None:
        content = classic_capture(1)
        capture = self.saved_capture(content, "pcap")
        capture_failure = CaptureFailure("capture", "backend_failed", "The recording backend exited before its requested duration.")
        cleanup_failure = CaptureFailure("cleanup", "process_stop_unverified", "The privileged recording process could not be independently verified stopped.")
        result = BackendCaptureResult("failed", None, CaptureCleanup(None, "unverified"), (capture_failure, cleanup_failure))
        receipt = self.capture_with_result(capture_request(capture, "pcap"), result)
        self.assertFalse(receipt_is_success(receipt))
        self.assertEqual(receipt.capture_outcome, "failed")
        self.assertEqual(receipt.validation_status, "verified")
        self.assertEqual(receipt.failures, (capture_failure, cleanup_failure))
        self.assertIsNotNone(receipt.artifact)
        self.assertEqual(capture.read_bytes(), content)

    def test_cancelled_partial_capture_reports_verified_and_unverified_cleanup_independently(self) -> None:
        content = classic_capture(1)
        capture = self.saved_capture(content, "pcap")
        cases = (
            (CaptureCleanup(True, "verified_complete"), ()),
            (CaptureCleanup(None, "unverified"), (CaptureFailure("cleanup", "process_stop_unverified", "No durable stop confirmation was received."),)),
        )
        for cleanup, failures in cases:
            with self.subTest(cleanup=cleanup):
                result = BackendCaptureResult("cancelled", 1_200_000_000, cleanup, failures)
                receipt = self.capture_with_result(capture_request(capture, "pcap"), result)
                self.assertEqual(receipt.capture_outcome, "cancelled")
                self.assertFalse(receipt_is_success(receipt))
                self.assertEqual(receipt.cleanup, cleanup)
                self.assertEqual(receipt.validation_status, "verified")
                self.assertIsNotNone(receipt.artifact)
                self.assertEqual(capture.read_bytes(), content)

    def test_zero_length_only_frames_are_preserved_without_positive_capture_claim(self) -> None:
        content = classic_capture(0) + bytes(16)
        capture = self.saved_capture(content, "pcap")
        result = BackendCaptureResult("completed", 5_000_000_000, CaptureCleanup(True, "verified_complete"), ())
        receipt = self.capture_with_result(capture_request(capture, "pcap"), result)
        self.assertFalse(receipt_is_success(receipt))
        self.assertEqual(receipt.validation_status, "verified")
        self.assertIsNotNone(receipt.artifact)
        assert receipt.artifact is not None
        self.assertEqual(receipt.artifact.packet_count, 1)
        self.assertEqual(receipt.artifact.positive_packet_count, 0)
        self.assertTrue(any(failure.stage == "validation" and failure.code == "no_positive_data" for failure in receipt.failures))
        self.assertEqual(capture.read_bytes(), content)

    def test_wrong_format_and_corruption_after_readable_packet_are_not_success(self) -> None:
        cases = (
            (metadata_capture(), "pcap"),
            (classic_capture(3)[:-9], "pcap"),
            (classic_capture(0), "pcap"),
            (b"", "pcap"),
        )
        for content, requested_format in cases:
            with self.subTest(size=len(content), requested_format=requested_format):
                capture = self.saved_capture(content, requested_format)
                result = BackendCaptureResult("completed", 5_000_000_000, CaptureCleanup(True, "verified_complete"), ())
                receipt = self.capture_with_result(capture_request(capture, requested_format), result)
                self.assertFalse(receipt_is_success(receipt))
                self.assertEqual(receipt.validation_status, "failed")
                self.assertIsNone(receipt.artifact)
                self.assertTrue(any(failure.stage == "validation" for failure in receipt.failures))
                self.assertEqual(capture.read_bytes(), content)

    def test_missing_output_does_not_override_backend_and_cleanup_failures(self) -> None:
        capture = self.directory / "missing.pcap"
        failures = (
            CaptureFailure("capture", "backend_failed", "The recording backend failed."),
            CaptureFailure("cleanup", "rvi_cleanup_failed", "The owned interface remained active."),
        )
        result = BackendCaptureResult("failed", None, CaptureCleanup(False, "failed"), failures)
        receipt = self.capture_with_result(capture_request(capture, "pcap"), result)
        self.assertFalse(receipt_is_success(receipt))
        self.assertIsNone(receipt.artifact)
        self.assertEqual(receipt.failures[:2], failures)
        self.assertIn(receipt.validation_status, ("failed", "not_attempted"))

    def test_receipt_event_roundtrip_and_binding_rejects_stale_request(self) -> None:
        capture = self.saved_capture(metadata_capture(), "pcapng")
        artifact = validate_capture_artifact(capture, "pcapng", threading.Event())
        receipt = artifact_receipt(artifact, capture)
        event = receipt_event(receipt)
        self.assertTrue(event.startswith(CAPTURE_RECEIPT_EVENT))
        payload = event[len(CAPTURE_RECEIPT_EVENT):].strip()
        parsed = parse_capture_receipt(payload)
        self.assertEqual(parsed, receipt)
        validate_receipt_binding(parsed, REQUEST_ID, capture, "pcapng", 5)
        bindings = (
            ("other-request", capture, "pcapng", 5),
            (REQUEST_ID, self.directory / "other.pcapng", "pcapng", 5),
            (REQUEST_ID, capture, "pcap", 5),
            (REQUEST_ID, capture, "pcapng", 6),
        )
        for request_id, output, capture_format, duration in bindings:
            with self.subTest(request_id=request_id, output=output, capture_format=capture_format, duration=duration):
                with self.assertRaises(ValueError):
                    validate_receipt_binding(parsed, request_id, output, capture_format, duration)

    def test_receipt_parser_rejects_nonfinite_and_boolean_numeric_fields(self) -> None:
        capture = self.saved_capture(classic_capture(1), "pcap")
        artifact = validate_capture_artifact(capture, "pcap", threading.Event())
        document = receipt_document(artifact_receipt(artifact, capture))
        for key, value in (("requested_duration_seconds", True), ("recording_lifetime_nanoseconds", True), ("recording_lifetime_nanoseconds", float("nan"))):
            with self.subTest(key=key, value=value):
                invalid = dict(document)
                invalid[key] = value
                with self.assertRaises(ValueError):
                    parse_capture_receipt(json.dumps(invalid))

    def test_receipt_parser_rejects_conflicting_evidence_and_duplicate_keys(self) -> None:
        capture = self.saved_capture(classic_capture(1), "pcap")
        artifact = validate_capture_artifact(capture, "pcap", threading.Event())
        receipt = artifact_receipt(artifact, capture)
        invalid_receipts = (
            replace(receipt, validation_status="failed"),
            replace(receipt, artifact=None),
            replace(receipt, capture_outcome="failed"),
            replace(receipt, failures=(CaptureFailure("capture", "backend_failed", "The backend failed."),)),
            replace(receipt, cleanup=CaptureCleanup(False, "failed")),
            replace(receipt, failures=(CaptureFailure("validation", "decoder_failed", "The decoder failed."),)),
            replace(receipt, artifact=replace(artifact, packet_span_nanoseconds=1)),
            replace(receipt, artifact=replace(artifact, positive_packet_count=2)),
            replace(receipt, artifact=replace(artifact, capture_format="pcapng")),
        )
        for invalid in invalid_receipts:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    parse_capture_receipt(json.dumps(receipt_document(invalid)))
        payload = json.dumps(receipt_document(receipt))
        duplicate = payload.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1', 1)
        with self.assertRaises(ValueError):
            parse_capture_receipt(duplicate)

    def test_receipt_success_requires_verified_positive_artifact_and_cleanup(self) -> None:
        capture = self.saved_capture(classic_capture(1), "pcap")
        artifact = validate_capture_artifact(capture, "pcap", threading.Event())
        receipt = artifact_receipt(artifact, capture)
        self.assertTrue(receipt_is_success(receipt))
        self.assertFalse(receipt_is_success(replace(receipt, cleanup=CaptureCleanup(None, "unverified"))))
        self.assertFalse(receipt_is_success(replace(receipt, cleanup=CaptureCleanup(False, "failed"))))
        self.assertFalse(receipt_is_success(replace(receipt, capture_outcome="cancelled")))
        self.assertFalse(receipt_is_success(replace(receipt, validation_status="failed", artifact=None)))

    def test_macos_compatibility_validator_requires_complete_readability(self) -> None:
        capture = self.saved_capture(classic_capture(3), "pcap")
        self.assertEqual(validate_macos_capture_output("unused-tcpdump", capture, "pcap"), capture.stat().st_size)
        capture.write_bytes(classic_capture(3)[:-9])
        with self.assertRaises(CaptureSessionError):
            validate_macos_capture_output("unused-tcpdump", capture, "pcap")

    def test_preexisting_interface_cannot_be_selected_as_owned(self) -> None:
        before = frozenset({"rvi0", "rvi7"})
        with self.assertRaises(CaptureSessionError):
            select_created_interface(before, before, "Starting device succeeded with interface rvi0")
        with self.assertRaises(CaptureSessionError):
            select_created_interface(before, before | {"rvi9"}, "Starting device succeeded with interface rvi0")
        self.assertEqual(select_created_interface(before, before | {"rvi9"}, "Starting device succeeded with interface rvi9"), "rvi9")
        with self.assertRaises(CaptureSessionError):
            select_created_interface(before, before | {"rvi9"}, "Starting device without an interface acknowledgement")
        with self.assertRaises(CaptureSessionError):
            select_created_interface(before, before | {"rvi9"}, "Starting device succeeded with interfaces rvi0 rvi9")
        with self.assertRaises(CaptureSessionError):
            select_created_interface(before, before | {"rvi9", "rvi10"}, "Starting device succeeded with interface rvi0")

    def controlled_macos_backend(
        self,
        recording_failure: CaptureSessionError | None,
        cleanup_failure: CaptureSessionError | None,
        stopped: bool | None,
    ) -> tuple[BackendCaptureResult, tuple[str, ...]]:
        capture = self.directory / "backend.pcap"
        controller = CaptureProcessController()
        stages: list[str] = []

        def recorded(*_arguments: object) -> None:
            stages.append("recording")
            capture.write_bytes(classic_capture(1))
            controller.recording_process_stopped = stopped
            if recording_failure is not None:
                raise recording_failure

        def cleanup(_rvictl: str, _ifconfig: str, _udid: str, interface: str | None, before: frozenset[str]) -> None:
            self.assertEqual(interface, "rvi9")
            self.assertEqual(before, frozenset({"rvi77"}))
            self.assertEqual(capture.read_bytes(), classic_capture(1))
            stages.append("cleanup")
            if cleanup_failure is not None:
                raise cleanup_failure

        with (
            patch("capture_session.ensure_macos_device_ready", return_value=DEVICE),
            patch("capture_session.shutil.which", return_value="/synthetic/capture-tool"),
            patch("capture_session.ensure_macos_rvi_relay_ready"),
            patch("capture_session.available_rvi_interfaces", return_value=frozenset({"rvi77"})),
            patch("capture_session.run_capture_command", return_value=subprocess.CompletedProcess([], 0, "Starting device with interface rvi9", "")),
            patch("capture_session.wait_for_created_rvi_interface", return_value="rvi9"),
            patch("capture_session.run_authorized_macos_capture", side_effect=recorded),
            patch("capture_session.remove_macos_rvi_interface", side_effect=cleanup),
        ):
            result = run_macos_capture(capture_request(capture, "pcap"), controller)
        self.assertEqual(capture.read_bytes(), classic_capture(1))
        return result, tuple(stages)

    def test_backend_returns_only_after_cleanup_and_keeps_cleanup_failure_distinct(self) -> None:
        result, stages = self.controlled_macos_backend(None, CaptureCleanupIncomplete("Fixture owned interface remained active (rvictl exit 7)."), True)
        self.assertEqual(stages, ("recording", "cleanup"))
        self.assertEqual(result.capture_outcome, "completed")
        self.assertEqual(result.cleanup, CaptureCleanup(True, "failed"))
        self.assertEqual(tuple(failure.stage for failure in result.failures), ("cleanup",))

    def test_backend_preserves_capture_failure_then_cleanup_failure(self) -> None:
        result, stages = self.controlled_macos_backend(CaptureSessionError("Fixture recording failed."), CaptureCleanupIncomplete("Fixture owned interface remained active (rvictl exit 7)."), True)
        self.assertEqual(stages, ("recording", "cleanup"))
        self.assertEqual(result.capture_outcome, "failed")
        self.assertEqual(result.cleanup, CaptureCleanup(True, "failed"))
        self.assertEqual(tuple(failure.stage for failure in result.failures), ("capture", "cleanup"))

    def test_failed_interface_inspection_reports_unverified_removal_with_specific_cause(self) -> None:
        failure = CaptureInterfaceInspectionError("Interface inspection failed (ifconfig exit 8).")
        result, stages = self.controlled_macos_backend(None, failure, True)
        self.assertEqual(stages, ("recording", "cleanup"))
        self.assertEqual(result.capture_outcome, "completed")
        self.assertEqual(result.cleanup, CaptureCleanup(True, "unverified"))
        self.assertEqual(tuple(item.stage for item in result.failures), ("cleanup",))
        self.assertEqual(result.failures[0].code, failure.code)
        self.assertIn("exit 8", result.failures[0].message)

    def test_backend_cancellation_keeps_unverified_recording_stop_independent_of_removed_interface(self) -> None:
        result, stages = self.controlled_macos_backend(CaptureCancelled("Fixture cancellation requested."), None, None)
        self.assertEqual(stages, ("recording", "cleanup"))
        self.assertEqual(result.capture_outcome, "cancelled")
        self.assertEqual(result.cleanup, CaptureCleanup(None, "verified_complete"))
        self.assertEqual(tuple(failure.stage for failure in result.failures), ("capture", "cleanup"))
        self.assertEqual(result.failures[-1].code, "recording_shutdown_unverified")

    def test_cleanup_refuses_unowned_interface_without_invoking_device_command(self) -> None:
        for interface in (None, "rvi77"):
            with self.subTest(interface=interface):
                with patch("capture_session.run_capture_command") as command:
                    with self.assertRaises(CaptureSessionError):
                        remove_macos_rvi_interface("fixture-rvictl", "fixture-ifconfig", DEVICE.udid, interface, frozenset({"rvi77"}))
                    command.assert_not_called()

    def test_verified_owned_interface_removal_preserves_preexisting_interfaces(self) -> None:
        before = frozenset({"rvi77", "rvi78"})
        with (
            patch("capture_session.run_capture_command", return_value=subprocess.CompletedProcess([], 0, "", "")) as command,
            patch("capture_session.available_rvi_interfaces", side_effect=(before | {"rvi9"}, before)),
        ):
            remove_macos_rvi_interface("fixture-rvictl", "fixture-ifconfig", DEVICE.udid, "rvi9", before)
        command.assert_called_once_with(["fixture-rvictl", "-x", DEVICE.udid], 5.0)

    def test_already_absent_owned_interface_does_not_run_device_removal(self) -> None:
        before = frozenset({"rvi77"})
        with (
            patch("capture_session.run_capture_command") as command,
            patch("capture_session.available_rvi_interfaces", return_value=before),
        ):
            remove_macos_rvi_interface("fixture-rvictl", "fixture-ifconfig", DEVICE.udid, "rvi9", before)
        command.assert_not_called()

    def test_incomplete_interface_cleanup_preserves_a_specific_code_and_safe_exit_status(self) -> None:
        before = frozenset({"rvi77"})
        after = before | {"rvi9"}
        with (
            patch("capture_session.run_capture_command", return_value=subprocess.CompletedProcess([], 7, "", "")),
            patch("capture_session.available_rvi_interfaces", return_value=after),
        ):
            with self.assertRaises(CaptureCleanupIncomplete) as failure:
                remove_macos_rvi_interface("fixture-rvictl", "fixture-ifconfig", DEVICE.udid, "rvi9", before)
        self.assertEqual(failure.exception.code, "interface_cleanup_incomplete")
        self.assertIn("exit 7", str(failure.exception))

    def test_invalid_request_nonce_is_rejected_before_process_or_output_creation(self) -> None:
        output = self.directory / "new-directory" / "capture.pcap"
        with (
            patch("capture_session.run_macos_capture") as backend,
            patch.object(CaptureProcessController, "install_signal_handlers") as signals,
        ):
            with self.assertRaises(ValueError):
                run_capture(capture_request(output, "pcap"), "invalid-nonce")
        self.assertFalse(output.parent.exists())
        backend.assert_not_called()
        signals.assert_not_called()

    def test_cancelled_partial_validation_has_a_deadline_without_claiming_completed_artifact(self) -> None:
        content = classic_capture(1)
        output = self.directory / "cancelled.pcap"

        def backend(request: CaptureRequest, controller: CaptureProcessController) -> BackendCaptureResult:
            request.output_path.write_bytes(content)
            controller.cancelled = True
            return BackendCaptureResult("cancelled", None, CaptureCleanup(True, "verified_complete"), ())

        def blocked_validation(_path: Path, _format: str, cancellation: threading.Event) -> CaptureArtifact:
            if not cancellation.wait(timeout=12):
                raise AssertionError("Cancelled partial-file verification had no cooperative deadline.")
            raise SavedCaptureCancelled()

        started = time.monotonic()
        with (
            patch("capture_session.platform.system", return_value="Darwin"),
            patch.object(CaptureProcessController, "install_signal_handlers"),
            patch("capture_session.run_macos_capture", side_effect=backend),
            patch("capture_session.validate_capture_artifact", side_effect=blocked_validation),
        ):
            receipt = run_capture(capture_request(output, "pcap"), REQUEST_ID)
        self.assertLess(time.monotonic() - started, 13)
        self.assertEqual(receipt.capture_outcome, "cancelled")
        self.assertEqual(receipt.validation_status, "failed")
        self.assertIsNone(receipt.artifact)
        self.assertEqual(receipt.cleanup, CaptureCleanup(True, "verified_complete"))
        self.assertEqual(receipt.failures[-1].stage, "validation")
        self.assertEqual(receipt.failures[-1].code, "cancelled")
        self.assertEqual(output.read_bytes(), content)

    def test_signal_handlers_are_restored_after_success_and_validation_failure(self) -> None:
        previous_interrupt = signal.getsignal(signal.SIGINT)
        previous_terminate = signal.getsignal(signal.SIGTERM)
        cases = (("valid.pcap", classic_capture(1), "verified"), ("corrupt.pcap", classic_capture(3)[:-9], "failed"))
        try:
            for filename, content, validation_status in cases:
                with self.subTest(filename=filename):
                    output = self.directory / filename

                    def backend(request: CaptureRequest, _controller: CaptureProcessController) -> BackendCaptureResult:
                        request.output_path.write_bytes(content)
                        return BackendCaptureResult("completed", None, CaptureCleanup(True, "verified_complete"), ())

                    with (
                        patch("capture_session.platform.system", return_value="Darwin"),
                        patch("capture_session.run_macos_capture", side_effect=backend),
                    ):
                        receipt = run_capture(capture_request(output, "pcap"), REQUEST_ID)
                    self.assertEqual(receipt.validation_status, validation_status)
                    self.assertEqual(signal.getsignal(signal.SIGINT), previous_interrupt)
                    self.assertEqual(signal.getsignal(signal.SIGTERM), previous_terminate)
        finally:
            signal.signal(signal.SIGINT, previous_interrupt)
            signal.signal(signal.SIGTERM, previous_terminate)

    def captured_preview(self, capture: Path, baseline: Path, exports: Path, digest: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "analyze_captured.py", str(capture), "--baseline", str(baseline),
             "--export-dir", str(exports), "--entropy-threshold", "3.5", "--top", "0", "--expected-sha256", digest],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False, timeout=30,
        )

    def preview_baseline(self) -> tuple[Path, bytes]:
        baseline = self.directory / "baseline.json"
        baseline.write_text(json.dumps(load_baseline(baseline), sort_keys=True), encoding="utf-8")
        return baseline, baseline.read_bytes()

    def test_capture_bound_preview_cli_exports_matching_bytes_without_updating_baseline(self) -> None:
        content = metadata_capture()
        capture = self.saved_capture(content, "pcapng")
        baseline, baseline_bytes = self.preview_baseline()
        exports = self.directory / "exports"
        digest = hashlib.sha256(content).hexdigest()
        result = self.captured_preview(capture, baseline, exports, digest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(baseline.read_bytes(), baseline_bytes)
        self.assertEqual(capture.read_bytes(), content)
        destinations = report_destinations(capture, exports)
        self.assertTrue(all(path.is_file() for path in destinations))
        report = json.loads(destinations[0].read_text(encoding="utf-8"))
        self.assertEqual(report["capture"]["sha256"], digest)
        self.assertEqual(report["capture"]["capture_id"], "sha256:" + digest)

    def test_capture_bound_preview_cli_denies_changed_digest_before_any_publication(self) -> None:
        content = classic_capture(3)
        capture = self.saved_capture(content, "pcap")
        baseline, baseline_bytes = self.preview_baseline()
        exports = self.directory / "exports"
        digest = hashlib.sha256(content).hexdigest()
        completed = self.captured_preview(capture, baseline, exports, digest)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        existing = {path: path.read_bytes() for path in report_destinations(capture, exports)}
        changed = classic_capture(1)
        capture.write_bytes(changed)
        failed = self.captured_preview(capture, baseline, exports, digest)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("no longer match the final receipt", failed.stderr)
        self.assertEqual({path: path.read_bytes() for path in existing}, existing)
        self.assertEqual(baseline.read_bytes(), baseline_bytes)
        self.assertEqual(capture.read_bytes(), changed)

        fresh_exports = self.directory / "fresh-exports"
        failed = self.captured_preview(capture, baseline, fresh_exports, digest)
        self.assertEqual(failed.returncode, 2)
        self.assertFalse(fresh_exports.exists())
        self.assertEqual(baseline.read_bytes(), baseline_bytes)


class OwnedCaptureProcessTests(unittest.TestCase):
    """Check real task-owned child termination; no privileged wrapper is involved."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-sentinel-owned-child-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def await_ready(self, ready: Path, process: subprocess.Popen[str]) -> None:
        deadline = time.monotonic() + 3
        while not ready.exists():
            if process.poll() is not None:
                self.fail("The owned fixture process exited before readiness.")
            if time.monotonic() >= deadline:
                self.fail("The owned fixture process did not signal readiness.")
            threading.Event().wait(0.01)

    def terminate_fixture(self, process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)

    @unittest.skipUnless(os.name == "posix", "Owned-child signal checks require POSIX processes.")
    def test_forced_shutdown_is_bounded_and_reports_failed_clean_stop(self) -> None:
        ready = self.directory / "ready"
        script = "import signal,time; from pathlib import Path; import sys; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path(sys.argv[1]).touch(); time.sleep(60)"
        process = subprocess.Popen([sys.executable, "-c", script, str(ready)], text=True)
        self.addCleanup(self.terminate_fixture, process)
        self.await_ready(ready, process)
        started = time.monotonic()
        with self.assertRaises(CaptureCommandTimeout):
            stop_and_reap_capture_process(process)
        self.assertLess(time.monotonic() - started, 9)
        self.assertIsNotNone(process.poll())
        if os.name == "posix":
            with self.assertRaises(ProcessLookupError):
                os.kill(process.pid, 0)

    @unittest.skipUnless(os.name == "posix", "Owned-child signal checks require POSIX processes.")
    def test_cancellation_reaps_owned_child_and_preserves_an_unrelated_process(self) -> None:
        ready = self.directory / "ready"
        script = "import time; from pathlib import Path; import sys; Path(sys.argv[1]).touch(); time.sleep(60)"
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], text=True)
        self.addCleanup(self.terminate_fixture, other)
        controller = CaptureProcessController()
        errors: list[BaseException] = []

        def record() -> None:
            try:
                controller.run_for_duration([sys.executable, "-c", script, str(ready)], 30, 0)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=record)
        worker.start()
        deadline = time.monotonic() + 3
        while not ready.exists():
            if not worker.is_alive():
                self.fail("The capture fixture stopped before readiness.")
            if time.monotonic() >= deadline:
                controller.cancel(signal.SIGTERM, None)
                worker.join(timeout=9)
                self.fail("The capture fixture did not signal readiness.")
            threading.Event().wait(0.01)
        process = controller.active_process
        self.assertIsNotNone(process)
        assert process is not None
        controller.cancel(signal.SIGTERM, None)
        worker.join(timeout=9)
        self.assertFalse(worker.is_alive())
        self.assertTrue(all(isinstance(error, CaptureCancelled) for error in errors))
        self.assertTrue(controller.cancelled)
        self.assertTrue(controller.recording_process_stopped)
        self.assertIsNone(controller.active_process)
        self.assertIsNotNone(controller.provider_lifetime_nanoseconds)
        self.assertIsNotNone(process.poll())
        self.assertIsNone(other.poll())

    def test_requesting_marker_cancellation_does_not_claim_privileged_child_stop(self) -> None:
        marker = self.directory / "cancel-requested"
        controller = CaptureProcessController()
        controller.cancellation_marker = marker
        controller.recording_process_stopped = None
        controller.cancel(signal.SIGTERM, None)
        self.assertTrue(controller.cancelled)
        self.assertTrue(marker.exists())
        self.assertIsNone(controller.recording_process_stopped)

    @unittest.skipUnless(os.name == "posix", "Synthetic upstream provider checks require POSIX signals.")
    def test_upstream_provider_lifetime_is_not_claimed_as_recording_lifetime(self) -> None:
        provider = self.directory / "synthetic_upstream.py"
        source = (
            "import signal, sys, time\n"
            "from pathlib import Path\n"
            f"Path(sys.argv[-1]).write_bytes(bytes.fromhex('{classic_capture(1).hex()}'))\n"
            "def stop(_number, _frame): raise SystemExit(0)\n"
            "signal.signal(signal.SIGTERM, stop)\n"
            "time.sleep(60)\n"
        )
        provider.write_text(source, encoding="utf-8")
        controller = CaptureProcessController()
        output = self.directory / "recorded.pcap"
        with (
            patch("capture_session.UPSTREAM_CAPTURE", provider),
            patch("capture_session.platform.system", return_value="Linux"),
        ):
            result = run_mobile_capture(capture_request(output, "pcap"), controller)
        self.assertEqual(result.capture_outcome, "completed")
        self.assertTrue(result.cleanup.recording_process_stopped)
        self.assertIsNone(result.recording_lifetime_nanoseconds)
        self.assertIsNotNone(controller.provider_lifetime_nanoseconds)
        self.assertEqual(output.read_bytes(), classic_capture(1))
        self.assertIsNone(controller.active_process)


class NativeCaptureShellTests(unittest.TestCase):
    """Execute the generated shell against a synthetic nonprivileged recorder."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-sentinel-native-shell-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.output = self.directory / "generated capture.pcap"
        self.authorization = self.directory / "authorized"
        self.ready = self.directory / "capture-ready"
        self.failure = self.directory / "capture-failed.txt"
        self.cancellation = self.directory / "cancel-requested"
        self.controller = CaptureProcessController()
        self.controller.cancellation_marker = self.cancellation

    def fixture_arguments(self, mode: str, duration: int) -> list[str]:
        executable = self.directory / "synthetic-recorder"
        source = (
            f"#!{sys.executable}\n"
            "import os, signal, sys, time\n"
            "from pathlib import Path\n"
            "output = Path(sys.argv[sys.argv.index('-w') + 1])\n"
            f"output.write_bytes(bytes.fromhex('{classic_capture(1).hex()}'))\n"
            "if '-c' in sys.argv: raise SystemExit(0)\n"
            "output.with_suffix('.pid').write_text(str(os.getpid()))\n"
            f"mode = {mode!r}\n"
            "if mode == 'early': raise SystemExit(0)\n"
            "def stopped(_number, _frame): raise SystemExit(0)\n"
            "signal.signal(signal.SIGINT, signal.SIG_IGN if mode == 'ignore' else stopped)\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN if mode == 'ignore' else stopped)\n"
            "time.sleep(60)\n"
        )
        executable.write_text(source, encoding="utf-8")
        executable.chmod(0o700)
        command = native_authorized_tcpdump_command(
            str(executable), "rvi999", self.output, self.directory / "preflight.pcapng",
            self.authorization, self.ready, self.failure, self.cancellation,
            "pcap", "fixture-user", duration,
        )
        return ["/bin/sh", "-c", command]

    def run_fixture(self, arguments: list[str]) -> None:
        run_authorized_macos_capture(
            arguments, self.controller, self.authorization, self.ready, self.failure, 10.0, 15.0,
        )

    def assert_recording_stopped(self) -> None:
        self.assertTrue(self.ready.with_name("capture-stopped").exists())
        self.assertTrue(self.controller.recording_process_stopped)
        self.assertIsNone(self.controller.active_process)
        self.assertEqual(self.output.read_bytes(), classic_capture(1))
        pid = int(self.output.with_suffix(".pid").read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    @unittest.skipUnless(os.name == "posix", "Native shell checks require POSIX processes.")
    def test_native_shell_confirms_owned_recorder_stop_after_success(self) -> None:
        self.run_fixture(self.fixture_arguments("normal", 1))
        self.assert_recording_stopped()
        self.assertIsNone(self.controller.provider_lifetime_nanoseconds)

    @unittest.skipUnless(os.name == "posix", "Native shell checks require POSIX processes.")
    def test_native_shell_rejects_early_exit_even_with_readable_saved_file(self) -> None:
        with self.assertRaises(CaptureBackendExit) as failure:
            self.run_fixture(self.fixture_arguments("early", 1))
        self.assertEqual(failure.exception.code, "capture_backend_exit")
        self.assertIn("exit 43", str(failure.exception))
        self.assert_recording_stopped()

    @unittest.skipUnless(os.name == "posix", "Native shell checks require POSIX processes.")
    def test_native_shell_cancellation_verifies_stop_before_returning(self) -> None:
        arguments = self.fixture_arguments("normal", 30)
        failures: list[Exception] = []

        def cancel_when_recording() -> None:
            deadline = time.monotonic() + 5
            while not self.ready.exists():
                if time.monotonic() >= deadline:
                    failures.append(RuntimeError("The synthetic recorder never entered recording."))
                    self.controller.cancel(signal.SIGTERM, None)
                    return
                threading.Event().wait(0.01)
            self.controller.cancel(signal.SIGTERM, None)

        worker = threading.Thread(target=cancel_when_recording)
        worker.start()
        try:
            with self.assertRaises(CaptureCancelled):
                self.run_fixture(arguments)
        finally:
            worker.join(timeout=6)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assert_recording_stopped()

    @unittest.skipUnless(os.name == "posix", "Native shell checks require POSIX processes.")
    def test_native_shell_forced_stop_is_bounded_and_never_clean_success(self) -> None:
        started = time.monotonic()
        with self.assertRaises(CaptureBackendExit) as failure:
            self.run_fixture(self.fixture_arguments("ignore", 1))
        self.assertEqual(failure.exception.code, "capture_backend_exit")
        self.assertLess(time.monotonic() - started, 14)
        self.assert_recording_stopped()

    def test_wrapper_exit_without_child_stop_acknowledgement_remains_unverified(self) -> None:
        script = (
            "import sys,time; from pathlib import Path; "
            "Path(sys.argv[1]).touch(); Path(sys.argv[2]).touch(); time.sleep(0.3)"
        )
        with self.assertRaises(CaptureShutdownUnverified) as failure:
            self.run_fixture([sys.executable, "-c", script, str(self.authorization), str(self.ready)])
        self.assertEqual(failure.exception.code, "recording_shutdown_unverified")
        self.assertIsNone(self.controller.recording_process_stopped)
        self.assertIsNone(self.controller.active_process)
        self.assertFalse(self.ready.with_name("capture-stopped").exists())


if __name__ == "__main__":
    unittest.main()
