#!/usr/bin/env python3
"""Headless GUI integration test using deterministic tshark field output."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from gui import RviSentinelWindow
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
            window = RviSentinelWindow()
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
            assert window.summary_labels["packet_count"].text() == "7"
            assert window.summary_labels["endpoints"].text() == "5 (5 new)"
            assert window.endpoints_table.rowCount() == 5
            assert window.domains_table.rowCount() == 2
            assert window.tls_table.rowCount() == 2
            assert window.entropy_table.rowCount() == 1
            assert "Analysis complete." in window.status_label.text()
            assert (exports / "authorized_report.json").is_file()
            assert baseline.is_file()
            window.close()
        finally:
            os.environ["PATH"] = original_path

    application.quit()
    print("PASS: headless GUI startup")
    print("PASS: GUI-to-analyzer process execution")
    print("PASS: generated report loading")
    print("PASS: summary and findings table population")


if __name__ == "__main__":
    main()
