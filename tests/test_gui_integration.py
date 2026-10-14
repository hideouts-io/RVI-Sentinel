#!/usr/bin/env python3
"""Headless GUI integration test using deterministic tshark field output."""

from __future__ import annotations

import os
import hashlib
import json
import time
import tempfile
from dataclasses import replace
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QEventLoop, QProcess, QTimer
from PySide6.QtTest import QTest
from typing import Callable
from PySide6.QtWidgets import QApplication, QLabel

from capture_models import (
    CAPTURE_AUTHORIZATION_EVENT,
    CAPTURE_PREFLIGHT_EVENT,
    CAPTURE_STARTED_EVENT,
    CAPTURE_VALIDATED_EVENT,
    CaptureRequest,
    DeviceInfo,
)
from gui import (
    APP_ICON,
    GuiInstanceAlreadyRunningError,
    RviSentinelWindow,
    acquire_gui_instance_lock,
    populate_device_table,
)
from gui_models import RankedFinding, report_path_for
from capture_receipt import CAPTURE_RECEIPT_EVENT, CaptureCleanup, CaptureFailure, CaptureReceipt, receipt_document, receipt_event
from capture_stats import CaptureArtifact
from macos_application import set_macos_application_icon
from analyze import load_baseline
from tests.saved_capture_fixture import FIXTURE_EPOCH_SECONDS, FIXTURE_NANOSECONDS, classic_capture
from tests.test_analyzer import FAKE_TSHARK


def wait_for_process(process: QProcess, timeout_milliseconds: int) -> None:
    """Wait for task-owned process completion while allowing GUI result slots to run."""
    if process.state() == QProcess.ProcessState.NotRunning:
        return
    loop = QEventLoop()
    timer = QTimer()
    timer.setSingleShot(True)
    timed_out = False

    def timeout() -> None:
        nonlocal timed_out
        timed_out = True
        loop.quit()

    timer.timeout.connect(timeout)
    process.finished.connect(loop.quit)
    timer.start(timeout_milliseconds)
    loop.exec()
    timer.stop()
    process.finished.disconnect(loop.quit)
    assert not timed_out, f"Task-owned GUI process exceeded {timeout_milliseconds} milliseconds"


def wait_for_condition(condition: Callable[[], bool], timeout_milliseconds: int) -> None:
    """Wait for a stated GUI postcondition while processing queued worker results."""
    deadline = time.monotonic() + timeout_milliseconds / 1000
    while not condition() and time.monotonic() < deadline:
        QTest.qWait(10)
    assert condition(), f"GUI postcondition exceeded {timeout_milliseconds} milliseconds"


def wait_for_report(window: RviSentinelWindow) -> None:
    wait_for_condition(lambda: not window.report_loading and window.report_worker is None, 10_000)


def main() -> None:
    application = QApplication(["test_gui_integration"])
    set_macos_application_icon(APP_ICON)

    with tempfile.TemporaryDirectory(prefix="rvi-sentinel-gui-integration-") as temp_directory:
        temporary_root = Path(temp_directory).resolve()
        binary_directory = temporary_root / "bin"
        binary_directory.mkdir()
        fake_tshark = binary_directory / "tshark"
        fake_tshark.write_text(FAKE_TSHARK, encoding="utf-8")
        fake_tshark.chmod(0o755)

        capture = temporary_root / "authorized.pcap"
        capture_content = classic_capture(7)
        capture.write_bytes(capture_content)
        baseline = temporary_root / "data" / "findings_master.json"
        exports = temporary_root / "exports"

        original_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{binary_directory}:{original_path}"
        try:
            instance_lock_path = temporary_root / "gui-instance.lock"
            first_lock = acquire_gui_instance_lock(instance_lock_path)
            try:
                try:
                    acquire_gui_instance_lock(instance_lock_path)
                except GuiInstanceAlreadyRunningError:
                    pass
                else:
                    raise AssertionError("A duplicate GUI instance acquired the same lock.")
            finally:
                first_lock.unlock()
            window = RviSentinelWindow()
            assert window.windowIcon().isNull() is False
            assert window.workspace_tabs.count() == 3
            assert window.workspace_tabs.tabText(0) == "Capture iPhone/iPad"
            assert window.workspace_tabs.tabText(1) == "Analyze Capture"
            assert window.workspace_tabs.tabText(2) == "Check setup"
            assert window.device_table.columnCount() == 4
            assert window.device_table.isColumnHidden(2)
            assert window.capture_console.isVisible() is False
            assert window.new_capture_button.objectName() == "newCaptureButton"
            logo = window.findChild(QLabel, "applicationLogo")
            assert logo is not None
            assert logo.pixmap().isNull() is False
            capture_request = CaptureRequest(
                device=DeviceInfo(
                    name="Research iPhone",
                    udid="00008150-000000000000001C",
                    operating_system="iPhone 17 Pro • iOS 26.3.1 (iPhone18,1)",
                    status="Ready — paired over USB",
                    connected=True,
                ),
                output_path=temporary_root / "countdown-test.pcap",
                duration_seconds=30,
                capture_format="pcap",
                analyze_after_capture=False,
            )
            devices = (capture_request.device,)
            window.discovered_devices = devices
            populate_device_table(window.device_table, devices)
            assert window.device_table.item(0, 2).text() == "Hidden"
            name_item = window.device_table.item(0, 0)
            name_item.setData(257, "preserved")
            populate_device_table(window.device_table, devices)
            assert window.device_table.item(0, 0) is name_item
            assert window.device_table.item(0, 0).data(257) == "preserved"
            window.set_advanced_details_visible(True)
            assert window.device_table.item(0, 2).text() == capture_request.device.udid
            window.set_advanced_details_visible(False)
            assert window.device_table.item(0, 2).text() == "Hidden"
            window.active_capture_request = capture_request
            window.handle_capture_event(CAPTURE_AUTHORIZATION_EVENT)
            assert window.capture_timer.isActive() is False
            assert window.capture_progress.maximum() == 0
            window.handle_capture_event(CAPTURE_PREFLIGHT_EVENT)
            assert window.capture_timer.isActive() is False
            assert "five seconds" in window.capture_status_label.text()
            window.handle_capture_event(CAPTURE_STARTED_EVENT)
            assert window.capture_timer.isActive() is True
            assert window.capture_progress.maximum() == 30
            assert "Recording started" in window.capture_status_label.text()
            window.capture_elapsed_seconds = 29
            window.advance_capture_progress()
            assert window.capture_timer.isActive() is False
            assert "Finalizing" in window.capture_progress.text()
            window.handle_capture_event(CAPTURE_VALIDATED_EVENT)
            assert window.capture_progress.text() == "Awaiting final capture receipt"
            assert "final cleanup outcome" in window.capture_status_label.text()
            window.capture_timer.stop()
            window.active_capture_request = None
            window.capture_countdown_started = False
            window.capture_field.setText(str(capture))
            window.baseline_field.setText(str(baseline))
            window.export_field.setText(str(exports))
            window.top_field.setValue(0)

            event_loop = QEventLoop()
            timed_out = False

            def handle_timeout() -> None:
                nonlocal timed_out
                timed_out = True
                event_loop.quit()

            timer = QTimer()
            timer.setSingleShot(True)
            timer.timeout.connect(handle_timeout)
            window.process.finished.connect(event_loop.quit)

            window.start_analysis()
            timer.start(10_000)
            event_loop.exec()
            timer.stop()

            assert timed_out is False, "GUI analyzer process timed out"
            assert window.process.exitCode() == 0

            wait_for_report(window)
            wait_for_process(window.enrichment_process, 10_000)

            assert window.summary_labels["packet_count"].text() == "7"
            assert window.summary_labels["endpoints"].text() == "5 (5 new)"
            assert window.endpoints_table.rowCount() == 5
            assert window.endpoints_table.columnCount() == 6
            assert all(
                window.endpoints_table.item(row, 1).text() == "Not requested"
                for row in range(window.endpoints_table.rowCount())
            )
            assert window.resolve_ptr_button.objectName() == "resolvePtrButton"
            assert window.cancel_enrichment_button.objectName() == "cancelEnrichmentButton"
            assert window.cancel_analysis_button.objectName() == "cancelAnalysisButton"
            assert window.ptr_resolver_notice.objectName() == "ptrResolverNotice"
            assert "Local endpoint enrichment complete. PTR not requested." in window.status_label.text()
            assert window.endpoint_enrichment_result is not None
            assert window.endpoint_enrichment_result.evidence_source == "local"
            assert window.endpoint_enrichment_result.completed_at >= window.endpoint_enrichment_result.requested_at
            assert all(
                window.endpoints_table.item(row, 2).text()
                for row in range(window.endpoints_table.rowCount())
            )
            assert all(
                window.endpoints_table.item(row, 3).text()
                for row in range(window.endpoints_table.rowCount())
            )
            assert window.domains_table.rowCount() == 2
            assert window.tls_table.rowCount() == 2
            assert window.ports_table.columnCount() == 5
            assert window.ports_table.item(0, 2).text()
            assert window.entropy_table.rowCount() == 1
            assert "NEW means newly observed" in window.interpretation.toPlainText()
            assert "Analysis complete." in window.status_label.text()
            assert (exports / "authorized_report.json").is_file()
            assert baseline.exists() is False, "Read-only analysis must not create a baseline"
            assert window.add_to_baseline_button.isEnabled()
            assert capture.read_bytes() == capture_content
            digest_label = window.findChild(QLabel, "captureDigest")
            assert digest_label is not None
            assert hashlib.sha256(capture_content).hexdigest() in digest_label.text()
            assert window.findChild(QLabel, "decoderCoverage") is not None
            assert window.findChild(QLabel, "packetRecordCount") is not None
            assert window.findChild(QLabel, "captureIntegrity") is not None

            baseline.parent.mkdir(parents=True)
            baseline.write_text(json.dumps(load_baseline(baseline), sort_keys=True), encoding="utf-8")
            original_baseline_bytes = baseline.read_bytes()
            window.start_analysis()
            timed_out = False
            timer.start(10_000)
            event_loop.exec()
            timer.stop()
            assert timed_out is False, "Second GUI passive analysis timed out"
            assert window.process.exitCode() == 0
            wait_for_report(window)
            wait_for_process(window.enrichment_process, 10_000)
            assert baseline.read_bytes() == original_baseline_bytes, "Passive GUI analysis must preserve an existing baseline byte for byte"
            assert all(window.endpoints_table.item(row, 1).text() == "Not requested" for row in range(window.endpoints_table.rowCount()))
            assert window.preview_sha256 == hashlib.sha256(capture_content).hexdigest()

            report_path = exports / "authorized_report.json"
            report_bytes = report_path.read_bytes()
            captured_dns_rows = window.domains_table.rowCount()
            captured_sni_rows = window.tls_table.rowCount()
            loopback_findings = (RankedFinding(value="127.0.0.1", count=1, is_new=True),)
            window.start_endpoint_enrichment(loopback_findings)
            wait_for_report(window)
            wait_for_process(window.enrichment_process, 10_000)
            window.resolve_ptr_button.click()
            assert window.enrichment_process.arguments()[-1] == "127.0.0.1"
            assert len(window.enrichment_process.arguments()) == 2, "Explicit GUI lookup must target only the test-owned loopback address"
            wait_for_report(window)
            wait_for_process(window.enrichment_process, 10_000)
            assert window.endpoint_enrichment_result is not None
            assert window.endpoint_enrichment_result.evidence_source == "ptr"
            assert window.endpoint_enrichment_result.completed_at >= window.endpoint_enrichment_result.requested_at
            assert "Current PTR resolution complete." in window.status_label.text()
            assert window.domains_table.rowCount() == captured_dns_rows
            assert window.tls_table.rowCount() == captured_sni_rows
            assert report_path.read_bytes() == report_bytes
            assert baseline.read_bytes() == original_baseline_bytes

            completed_lookup = window.endpoint_enrichment_result
            window.resolve_ptr_button.click()
            assert window.cancel_enrichment_button.isEnabled()
            window.cancel_enrichment_button.click()
            wait_for_report(window)
            wait_for_process(window.enrichment_process, 10_000)
            assert window.endpoint_enrichment_result == completed_lookup
            assert report_path.read_bytes() == report_bytes
            assert baseline.read_bytes() == original_baseline_bytes

            os.environ["RVI_TEST_TSHARK_MODE"] = "cancel"
            try:
                window.start_analysis()
                assert window.cancel_analysis_button.isEnabled()
                window.cancel_analysis_button.click()
                wait_for_process(window.process, 10_000)
                assert "cancel" in window.status_label.text().lower()
                assert window.preview_sha256 is None, "Cancelled or cleared previews cannot authorize a reviewed update"
                assert baseline.read_bytes() == original_baseline_bytes
                assert report_path.read_bytes() == report_bytes
            finally:
                os.environ.pop("RVI_TEST_TSHARK_MODE", None)

            capture_request.output_path.write_bytes(classic_capture(7))
            window.active_capture_request = capture_request
            window.capture_request_id = "1" * 32
            artifact = CaptureArtifact(
                "pcap", hashlib.sha256(capture_request.output_path.read_bytes()).hexdigest(),
                capture_request.output_path.stat().st_size, 7, 7,
                f"{FIXTURE_EPOCH_SECONDS}.{FIXTURE_NANOSECONDS:09d}",
                f"{FIXTURE_EPOCH_SECONDS}.{FIXTURE_NANOSECONDS + 6:09d}",
                6, "TShark fixture decoder",
            )
            receipt = CaptureReceipt(
                "1" * 32, capture_request.output_path, "pcap", 30, 30_250_000_000,
                "completed", "verified", artifact, CaptureCleanup(True, "verified_complete"), (),
            )
            event = receipt_event(receipt)
            window.consume_capture_events(event[:31])
            assert window.capture_receipt is None, "Partial helper rows cannot finalize a capture"
            window.consume_capture_events(event[31:] + "\n")
            assert window.capture_receipt == receipt
            window.workspace_tabs.setCurrentIndex(0)
            window.capture_finished(0, QProcess.ExitStatus.NormalExit)
            assert window.workspace_tabs.currentIndex() == 0
            assert window.completion_group.isHidden() is False
            assert str(capture_request.output_path) in window.completion_summary.text()
            assert "Observed recording lifetime: 30.250 seconds" in window.completion_summary.text()
            assert "Packet timestamp span: 6 nanoseconds" in window.completion_summary.text()
            assert artifact.sha256 in window.completion_summary.text()
            assert "verified stopped" in window.capture_status_label.text()
            assert window.findChild(QLabel, "captureCompletionSummary") is not None
            assert window.completion_analyze_button.objectName() == "analyzeSavedCaptureButton"
            assert not hasattr(window, "stats_process"), "Guided receipts must not launch a redundant statistics decoder"
            assert window.baseline_field.text() != str(baseline)

            def activate_receipt_request() -> None:
                window.active_capture_request = capture_request
                window.capture_request_id = "1" * 32
                window.capture_receipt = None
                window.capture_receipt_error = None
                window.completed_capture_path = None
                window.completed_capture_receipt = None
                window.completion_group.setVisible(False)

            activate_receipt_request()
            window.handle_capture_event(receipt_event(replace(receipt, request_id="2" * 32)))
            window.capture_finished(0, QProcess.ExitStatus.NormalExit)
            assert window.capture_receipt is None
            assert "does not match" in window.capture_status_label.text()
            assert window.completed_capture_path is None
            assert window.completion_group.isHidden()

            activate_receipt_request()
            window.handle_capture_event(receipt_event(replace(receipt, output_path=temporary_root / "other.pcap")))
            window.capture_finished(0, QProcess.ExitStatus.NormalExit)
            assert window.completed_capture_path is None
            assert "does not match" in window.capture_status_label.text()

            activate_receipt_request()
            window.handle_capture_event(event)
            window.handle_capture_event(event)
            window.capture_finished(0, QProcess.ExitStatus.NormalExit)
            assert "more than one" in window.capture_status_label.text()
            assert window.completed_capture_path is None

            activate_receipt_request()
            partial_receipt = replace(
                receipt, recording_lifetime_nanoseconds=None, capture_outcome="cancelled",
                cleanup=CaptureCleanup(None, "verified_complete"),
                failures=(CaptureFailure("cleanup", "process_shutdown_unverified",
                                         "The owned recording process could not be verified stopped."),),
            )
            window.handle_capture_event(receipt_event(partial_receipt))
            window.capture_cancel_requested = True
            window.capture_finished(130, QProcess.ExitStatus.NormalExit)
            assert window.completed_capture_path == capture_request.output_path
            assert window.completion_group.isHidden() is False
            assert "Recording process: unverified" in window.capture_status_label.text()
            assert "Interface cleanup: verified complete" in window.capture_status_label.text()
            assert "Unavailable (not observed)" in window.completion_summary.text()
            assert "Actual capture time" not in window.completion_summary.text()

            activate_receipt_request()
            window.capture_cancel_requested = True
            window.capture_finished(9, QProcess.ExitStatus.CrashExit)
            assert "Cancellation was requested" in window.capture_status_label.text()
            assert "cleanup are unverified" in window.capture_status_label.text()
            assert "interface was removed" not in window.capture_status_label.text()
            assert window.completed_capture_path is None
            assert window.completion_group.isHidden()

            activate_receipt_request()
            failure_receipt = replace(
                receipt, capture_outcome="failed", cleanup=CaptureCleanup(True, "failed"),
                failures=(CaptureFailure("capture", "capture_failed", "The recording process exited unsuccessfully."),
                          CaptureFailure("cleanup", "interface_cleanup_failed", "The owned interface remains present.")),
            )
            window.handle_capture_event(receipt_event(failure_receipt))
            window.capture_finished(2, QProcess.ExitStatus.NormalExit)
            assert window.completed_capture_path == capture_request.output_path
            assert "capture_failed" in window.capture_status_label.text()
            assert "interface_cleanup_failed" in window.capture_status_label.text()
            assert "Saved-artifact validation: verified readable" in window.capture_status_label.text()
            assert window.process.state() == QProcess.ProcessState.NotRunning, "Failure evidence must not trigger automatic analysis"
            window.copy_diagnostics()
            diagnostics = application.clipboard().text()
            assert "Recording outcome: failed" in diagnostics
            assert "Interface cleanup: failed" in diagnostics
            assert "capture/capture_failed" in diagnostics
            assert str(capture_request.output_path) not in diagnostics
            assert capture_request.device.udid not in diagnostics

            error_dialogs: list[tuple[str, str]] = []
            window.show_error = lambda title, detail: error_dialogs.append((title, detail))
            capture_request.output_path.write_bytes(classic_capture(8))
            window.export_field.setText(str(exports))
            window.baseline_field.setText(str(baseline))
            window.analyze_completed_capture()
            assert window.active_analysis_capture_sha256 == artifact.sha256
            assert window.process.arguments()[0].endswith("analyze_captured.py")
            assert window.process.arguments()[-2:] == ["--expected-sha256", artifact.sha256]
            changed_capture_report = report_path_for(window.active_request)
            wait_for_process(window.process, 10_000)
            assert window.preview_sha256 is None, (window.preview_sha256, window.status_label.text(), error_dialogs)
            assert window.active_report_path is None
            assert window.process.exitCode() == 2
            assert not changed_capture_report.exists(), "Changed guided bytes must be rejected before any report publication"
            assert error_dialogs and error_dialogs[-1][0] == "Analysis failed"
            assert "no longer match the final receipt" in window.console.toPlainText().lower()
            assert baseline.read_bytes() == original_baseline_bytes

            window.select_imported_capture(capture_request.output_path)
            assert window.completed_capture_receipt is None
            assert window.completed_capture_path is None
            assert window.completion_group.isHidden()
            assert window.capture_receipt == failure_receipt, "Explicit import must preserve the last recording and cleanup diagnostics"
            window.start_analysis()
            assert window.process.arguments()[0].endswith("analyze_preview.py")
            assert "--expected-sha256" not in window.process.arguments()
            wait_for_process(window.process, 10_000)
            wait_for_report(window)
            wait_for_process(window.enrichment_process, 10_000)
            assert window.preview_sha256 == hashlib.sha256(classic_capture(8)).hexdigest()
            assert baseline.read_bytes() == original_baseline_bytes

            process_request = replace(capture_request, output_path=temporary_root / "process-receipt.pcap")
            process_receipt = replace(receipt, output_path=process_request.output_path)
            receipt_script = temporary_root / "synthetic_receipt_helper.py"
            receipt_script.write_text(
                "import json, pathlib, sys\n"
                f"document = json.loads({json.dumps(json.dumps(receipt_document(process_receipt)))})\n"
                "document['request_id'] = sys.argv[sys.argv.index('--request-id') + 1]\n"
                f"pathlib.Path(document['output_path']).write_bytes(bytes.fromhex({classic_capture(7).hex()!r}))\n"
                f"print({CAPTURE_RECEIPT_EVENT!r} + json.dumps(document), flush=True)\n",
                encoding="utf-8",
            )
            window.start_capture(process_request, [str(receipt_script)])
            process_nonce = window.capture_request_id
            assert process_nonce is not None and len(process_nonce) == 32
            assert window.capture_process.arguments()[-2:] == ["--request-id", process_nonce]
            window.force_kill_capture()
            wait_for_process(window.capture_process, 10_000)
            assert window.completed_capture_receipt is not None
            assert window.completed_capture_receipt.request_id == process_nonce
            assert window.completed_capture_path == process_request.output_path
            assert window.capture_progress.text() == "Capture complete"
            assert not window.capture_cancel_timer.isActive(), "A previous shutdown timer cannot affect a later capture"
            assert baseline.read_bytes() == original_baseline_bytes

            activate_receipt_request()
            window.cancel_capture_button.setEnabled(True)
            startup_loop = QEventLoop()
            startup_timer = QTimer()
            startup_timer.setSingleShot(True)
            startup_timer.timeout.connect(startup_loop.quit)
            window.capture_process.errorOccurred.connect(startup_loop.quit)
            window.capture_process.setProgram(str(temporary_root / "absent-owned-helper"))
            window.capture_process.setArguments([])
            window.capture_process.start()
            startup_timer.start(10_000)
            startup_loop.exec()
            startup_timer.stop()
            window.capture_process.errorOccurred.disconnect(startup_loop.quit)
            assert window.capture_process.error() == QProcess.ProcessError.FailedToStart
            assert window.active_capture_request is None
            assert window.capture_request_id is None
            assert not window.cancel_capture_button.isEnabled()
            assert window.refresh_devices_button.isEnabled()
            assert "cleanup are unverified" in window.capture_status_label.text()
            window.close()
            wait_for_condition(lambda: window.report_worker is None and not window.packet_timeline.is_busy and not window.session_timeline.is_busy, 10_000)
        finally:
            os.environ["PATH"] = original_path

    application.quit()
    print("PASS: headless GUI startup")
    print("PASS: application icon and visible logo")
    print("PASS: duplicate GUI instance prevention")
    print("PASS: separate guided capture, analysis, and setup workspaces")
    print("PASS: countdown begins only after authorization and live-packet preflight")
    print("PASS: GUI-to-analyzer process execution")
    print("PASS: generated report loading")
    print("PASS: summary and findings table population")
    print("PASS: explanatory port and endpoint presentation")
    print("PASS: automatic local enrichment without PTR resolution")
    print("PASS: explicit loopback PTR provenance and cancellation without changing captured evidence")
    print("PASS: cancelled passive analysis preserves report and baseline bytes")
    print("PASS: read-only analysis and visible capture completion card")
    print("PASS: typed receipt binding, exact duration semantics, and independent cleanup presentation")
    print("PASS: missing/stale/duplicate receipts cannot claim completion or cancellation cleanup")
    print("PASS: saved evidence survives capture/cleanup failure and changed bytes lose guided attribution")
    print("PASS: task-owned Qt helper process receives a nonce and delivers a final typed receipt")
    print("PASS: explicit import establishes fresh passive evidence while preserving prior capture diagnostics")
    print("PASS: actual helper startup failure clears the operation and preserves unverified outcomes")


if __name__ == "__main__":
    main()
