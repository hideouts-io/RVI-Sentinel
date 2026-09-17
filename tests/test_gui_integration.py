#!/usr/bin/env python3
"""Headless GUI integration test using deterministic tshark field output."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QEventLoop, QProcess, QTimer
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
    GuiInstanceAlreadyRunningError,
    RviSentinelWindow,
    acquire_gui_instance_lock,
    populate_device_table,
)
from tests.test_analyzer import FAKE_TSHARK


def main() -> None:
    application = QApplication(["test_gui_integration"])

    with tempfile.TemporaryDirectory(prefix="rvi-sentinel-gui-integration-") as temp_directory:
        temporary_root = Path(temp_directory)
        binary_directory = temporary_root / "bin"
        binary_directory.mkdir()
        fake_tshark = binary_directory / "tshark"
        fake_tshark.write_text(FAKE_TSHARK, encoding="utf-8")
        fake_tshark.chmod(0o755)

        capture = temporary_root / "authorized.pcapng"
        capture.write_bytes(b"synthetic GUI integration fixture\n")
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
            assert "Live packets verified" in window.capture_status_label.text()
            window.capture_elapsed_seconds = 29
            window.advance_capture_progress()
            assert window.capture_timer.isActive() is False
            assert "Finalizing" in window.capture_progress.text()
            window.handle_capture_event(CAPTURE_VALIDATED_EVENT)
            assert window.capture_progress.text() == "Capture validated"
            assert "readable packets" in window.capture_status_label.text()
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

            if window.enrichment_process.state() != QProcess.ProcessState.NotRunning:
                enrichment_loop = QEventLoop()
                enrichment_timed_out = False

                def handle_enrichment_timeout() -> None:
                    nonlocal enrichment_timed_out
                    enrichment_timed_out = True
                    enrichment_loop.quit()

                enrichment_timer = QTimer()
                enrichment_timer.setSingleShot(True)
                enrichment_timer.timeout.connect(handle_enrichment_timeout)
                window.enrichment_process.finished.connect(enrichment_loop.quit)
                enrichment_timer.start(35_000)
                enrichment_loop.exec()
                enrichment_timer.stop()
                assert enrichment_timed_out is False, "GUI endpoint enrichment timed out"

            assert window.summary_labels["packet_count"].text() == "7"
            assert window.summary_labels["endpoints"].text() == "5 (5 new)"
            assert window.endpoints_table.rowCount() == 5
            assert window.endpoints_table.columnCount() == 6
            assert all(
                window.endpoints_table.item(row, 1).text() != "Resolving…"
                for row in range(window.endpoints_table.rowCount())
            )
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

            capture_request.output_path.write_bytes(b"synthetic completed capture\n")
            window.active_capture_request = capture_request
            window.capture_actual_seconds = 30.25
            window.workspace_tabs.setCurrentIndex(0)
            window.capture_finished(0, QProcess.ExitStatus.NormalExit)
            assert window.workspace_tabs.currentIndex() == 0
            assert window.completion_group.isHidden() is False
            assert str(capture_request.output_path) in window.completion_summary.text()
            assert "Actual capture time: 30.250 seconds" in window.completion_summary.text()
            assert window.baseline_field.text() != str(baseline)
            window.close()
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
    print("PASS: read-only analysis and visible capture completion card")


if __name__ == "__main__":
    main()
