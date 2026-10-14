"""Real saved-file and Qt timeline interactions; no packets or resolver queries are sent."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from pathlib import Path
from threading import Event
from typing import TypeVar
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QModelIndex, QObject, QProcess, QTimer
from PySide6.QtWidgets import QApplication, QComboBox, QLineEdit, QPushButton

from analyze import analyze, load_baseline, write_report
from gui import RviSentinelWindow
from gui_models import AnalysisReport, AnalysisRequest, ReportLoadCancelled, ReportValidationError, load_report, load_report_cancellable
from packet_models import PacketRecord
from packet_timeline import PacketIndex, build_packet_index
from packet_view import PacketTimelineWidget
from tests.packet_timeline_fixture import timeline_records, timeline_report
from tests.saved_capture_fixture import classic_capture, metadata_capture

QtObject = TypeVar("QtObject", bound=QObject)


def child(widget: QObject, kind: type[QtObject], identity: str) -> QtObject:
    """Locate one required control by its stable ID and validated widget type."""
    control = widget.findChild(kind, identity)
    if not isinstance(control, kind):
        raise AssertionError(f"Required Qt control {identity!r} was not found with type {kind.__name__}.")
    return control


def wait_until(condition: Callable[[], bool], timeout_milliseconds: int, operation: str) -> None:
    """Process real Qt events until an observable condition or explicit deadline."""
    if condition():
        return
    loop = QEventLoop()
    condition_timer = QTimer()
    deadline = QTimer()
    deadline.setSingleShot(True)
    expired = False

    def inspect() -> None:
        if condition():
            loop.quit()

    def timeout() -> None:
        nonlocal expired
        expired = True
        loop.quit()

    condition_timer.timeout.connect(inspect)
    deadline.timeout.connect(timeout)
    condition_timer.start(10)
    deadline.start(timeout_milliseconds)
    loop.exec()
    condition_timer.stop()
    deadline.stop()
    if expired or not condition():
        raise AssertionError(f"{operation} did not complete within {timeout_milliseconds} milliseconds.")


def choose(widget: QObject, identity: str, value: str | int) -> None:
    combo = child(widget, QComboBox, identity)
    index = combo.findData(value)
    if index < 0:
        raise AssertionError(f"Required Qt choice {value!r} is unavailable in {identity!r}.")
    combo.setCurrentIndex(index)


def apply_filters(widget: PacketTimelineWidget) -> None:
    child(widget, QPushButton, "packetApplyFilters").click()
    wait_until(lambda: not widget.is_busy and widget.completed_page is not None, 20_000, "Packet query")


def clear_filters(widget: PacketTimelineWidget) -> None:
    child(widget, QPushButton, "packetClearFilters").click()
    wait_until(lambda: not widget.is_busy and widget.completed_page is not None, 20_000, "Clear packet filters")


def maximum_rss_mebibytes() -> float | None:
    """Report process cumulative high-water RSS where the host provides rusage."""
    if platform.system() == "Windows":
        return None
    import resource

    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    divisor = 1_048_576 if platform.system() == "Darwin" else 1_024
    return round(usage / divisor, 3)


class PacketGuiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("Packet GUI integration requires the real Wireshark/TShark decoder on PATH.")
        application = QApplication.instance()
        cls.application = application if isinstance(application, QApplication) else QApplication(["test_packet_gui_integration"])

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-sentinel-packet-gui-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.baseline = self.directory / "baseline.json"
        self.baseline.write_text(json.dumps(load_baseline(self.baseline), sort_keys=True), encoding="utf-8")
        self.exports = self.directory / "exports"

    def saved_report(self, filename: str, content: bytes) -> AnalysisReport:
        capture = self.directory / filename
        capture.write_bytes(content)
        report = analyze(capture, load_baseline(self.baseline), 3.8)
        path = write_report(report, capture, self.exports)
        return load_report(path)

    def make_widget(self, report: AnalysisReport) -> PacketTimelineWidget:
        widget = PacketTimelineWidget(None)
        self.addCleanup(self.close_widget, widget)
        widget.set_report(report)
        wait_until(lambda: not widget.is_busy and widget.completed_page is not None, 30_000, "Packet index and first page")
        return widget

    def close_widget(self, widget: PacketTimelineWidget) -> None:
        widget.shutdown()
        wait_until(lambda: not widget.is_busy, 10_000, "Packet worker shutdown")
        widget.close()

    def assert_matches(self, widget: PacketTimelineWidget, count: int) -> None:
        page = widget.completed_page
        self.assertIsNotNone(page)
        if page is None:
            raise AssertionError("A completed packet page was not published.")
        self.assertEqual(page.matching_count, count)
        self.assertEqual(widget.model.rowCount(QModelIndex()), min(count, page.page_size))

    def test_real_generated_captures_load_async_and_inspect_without_mutating_evidence(self) -> None:
        window = RviSentinelWindow()
        self.addCleanup(window.close)
        failures: list[tuple[str, str]] = []
        window.show_error = lambda title, detail: failures.append((title, detail))
        window.baseline_field.setText(str(self.baseline))
        window.export_field.setText(str(self.exports))
        original_baseline = self.baseline.read_bytes()
        prior_identity = None
        with patch("socket.gethostbyaddr", side_effect=AssertionError("Timeline queries must not resolve PTR")), patch(
            "socket.getaddrinfo", side_effect=AssertionError("Timeline queries must not resolve names")
        ):
            for filename, content, process_state in (
                ("classic.pcap", classic_capture(3), "unknown"),
                ("metadata.pcapng", metadata_capture(), "recorded"),
            ):
                with self.subTest(filename=filename):
                    capture = self.directory / filename
                    capture.write_bytes(content)
                    window.capture_field.setText(str(capture))
                    window.start_analysis()
                    wait_until(
                        lambda: window.process.state() == QProcess.ProcessState.NotRunning and
                        not window.report_loading and not window.packet_timeline.is_busy and
                        window.packet_timeline.completed_page is not None,
                        30_000, "Real analyzer, report loading, and packet indexing",
                    )
                    wait_until(lambda: window.enrichment_process.state() == QProcess.ProcessState.NotRunning,
                               10_000, "Passive local endpoint context")
                    self.assertEqual(failures, [])
                    self.assertEqual(window.process.exitCode(), 0)
                    self.assertEqual(window.packet_timeline.objectName(), "packetTimeline")
                    widget = window.packet_timeline
                    self.assert_matches(widget, 3)
                    self.assertIsNone(widget.selected_identity, "A changed artifact must invalidate the old frame selection.")
                    self.assertEqual(window.endpoint_enrichment_result.evidence_source, "local")
                    report_path = self.exports / f"{capture.stem}_report.json"
                    report_bytes = report_path.read_bytes()
                    all_exports = {path.name: path.read_bytes() for path in self.exports.iterdir() if path.is_file()}

                    choose(widget, "packetProcessStateFilter", process_state)
                    apply_filters(widget)
                    self.assert_matches(widget, 3)
                    clear_filters(widget)
                    child(widget, QLineEdit, "packetEndpointFilter").setText("192.0.2.53")
                    apply_filters(widget)
                    self.assert_matches(widget, 2)
                    clear_filters(widget)
                    child(widget, QLineEdit, "packetEndpointFilter").setText("2001:db8::2")
                    apply_filters(widget)
                    self.assert_matches(widget, 1)
                    clear_filters(widget)
                    child(widget, QLineEdit, "packetPortFilter").setText("53001")
                    apply_filters(widget)
                    self.assert_matches(widget, 1)
                    clear_filters(widget)
                    child(widget, QLineEdit, "packetSearch").setText("second.test")
                    apply_filters(widget)
                    self.assert_matches(widget, 1)
                    widget.table.selectRow(0)
                    self.assertIsNotNone(widget.selected_identity)
                    identity = widget.selected_identity
                    self.assertNotEqual(identity, prior_identity)
                    prior_identity = identity
                    inspector = widget.inspector.toPlainText()
                    self.assertIn(hashlib.sha256(content).hexdigest(), inspector)
                    self.assertIn("1791428448.590385001", inspector)
                    self.assertIn("first.test", inspector)
                    self.assertIn("second.test", inspector)
                    self.assertIn("dns.qry.name", inspector)
                    self.assertIn("imported_unknown", inspector)
                    if process_state == "recorded":
                        self.assertIn("fixture-maild", inspector)
                        self.assertIn("apple_pcapng", inspector)
                        self.assertIn("fixture0", inspector)

                    child(widget, QLineEdit, "packetSearch").setText("ipv6.test")
                    apply_filters(widget)
                    self.assertEqual(widget.selected_identity, identity, "Filtering must preserve artifact/frame selection.")
                    self.assertIn("second.test", widget.inspector.toPlainText())
                    self.assertIn("outside", widget.selection_notice.text().lower())
                    clear_filters(widget)
                    self.assertEqual(widget.selected_identity, identity)
                    self.assertEqual(widget.table.selectionModel().selectedRows()[0].row(), 0)
                    self.assertEqual(capture.read_bytes(), content)
                    self.assertEqual(self.baseline.read_bytes(), original_baseline)
                    self.assertEqual(report_path.read_bytes(), report_bytes)
                    self.assertEqual({path.name: path.read_bytes() for path in self.exports.iterdir() if path.is_file()}, all_exports)

    def test_synthetic_metadata_conflicts_repeated_layers_and_stable_selection(self) -> None:
        template = self.saved_report("template.pcapng", metadata_capture())
        records = timeline_records(12)
        digest = hashlib.sha256(b"synthetic timeline model; no original capture claim").hexdigest()
        widget = self.make_widget(timeline_report(template, records, digest))
        self.assert_matches(widget, 12)
        frames = tuple(packet.frame_number for packet in widget.completed_page.packets)
        self.assertEqual(frames, tuple(range(1, 13)), "Tied exact timestamps must use frame identity ordering.")
        widget.table.selectRow(3)
        selected = widget.selected_identity
        inspector = widget.inspector.toPlainText()
        self.assertIn("conflict", inspector.lower())
        self.assertIn("fixture-other", inspector)
        self.assertIn("pktap", inspector)
        self.assertIn("ambiguous_network_layers", inspector)
        self.assertIn("203.0.113.7", inspector)
        self.assertIn("fixture-agent", inspector)
        for identity, value, count in (
            ("packetProcessStateFilter", "unknown", 3),
            ("packetProcessStateFilter", "recorded", 6),
            ("packetProcessStateFilter", "conflict", 3),
            ("packetInterfaceStateFilter", "unknown", 3),
            ("packetInterfaceStateFilter", "conflict", 3),
            ("packetDirectionFilter", "unknown", 3),
            ("packetDirectionFilter", "inbound", 3),
            ("packetDirectionFilter", "conflict", 3),
        ):
            with self.subTest(identity=identity, value=value):
                clear_filters(widget)
                choose(widget, identity, value)
                apply_filters(widget)
                self.assert_matches(widget, count)
                self.assertEqual(widget.selected_identity, selected)
        for identity, value, count in (
            ("packetEndpointFilter", "203.0.113.7", 3),
            ("packetEndpointFilter", "192.0.2.2", 9),
            ("packetPortFilter", "53000", 9),
            ("packetProcessFilter", "fixture-agent", 6),
            ("packetProcessFilter", "901", 3),
            ("packetInterfaceFilter", "fixture1", 6),
            ("packetSearch", "authority.test", 9),
        ):
            with self.subTest(identity=identity, value=value):
                clear_filters(widget)
                child(widget, QLineEdit, identity).setText(value)
                apply_filters(widget)
                self.assert_matches(widget, count)
                self.assertEqual(widget.selected_identity, selected)
        clear_filters(widget)
        replacement_digest = hashlib.sha256(b"replacement synthetic model").hexdigest()
        widget.set_report(timeline_report(template, records, replacement_digest))
        wait_until(lambda: not widget.is_busy and widget.completed_page is not None, 20_000, "Replacement artifact index")
        self.assertIsNone(widget.selected_identity)
        self.assertNotIn(digest, widget.inspector.toPlainText())
        legacy = timeline_report(template, records, replacement_digest)
        from dataclasses import replace

        widget.set_report(replace(legacy, evidence=None, packets=()))
        wait_until(lambda: not widget.is_busy, 10_000, "Legacy summary replacement")
        self.assertEqual(widget.model.rowCount(QModelIndex()), 0)
        self.assertIsNone(widget.selected_identity)
        self.assertIsNone(widget.completed_page)
        self.assertFalse(child(widget, QPushButton, "packetApplyFilters").isEnabled())

    def test_report_loader_rejects_fifo_links_open_races_duplicate_json_and_cancellation(self) -> None:
        if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK") or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("Task-owned FIFO and no-follow descriptor regression requires a POSIX filesystem.")
        self.saved_report("loader-template.pcap", classic_capture(3))
        report_path = self.exports / "loader-template_report.json"
        original_bytes = report_path.read_bytes()
        fifo = self.directory / "blocked.json"
        os.mkfifo(fifo)
        started = time.monotonic()
        with self.assertRaises(ReportValidationError):
            load_report(fifo)
        self.assertLess(time.monotonic() - started, 1.0, "A report FIFO must fail before blocking at open.")
        link = self.directory / "report-link.json"
        link.symlink_to(report_path)
        with self.assertRaises(ReportValidationError):
            load_report(link)
        real_open = os.open
        for replacement in ("fifo", "symlink"):
            with self.subTest(replacement=replacement):
                race = self.directory / f"open-race-{replacement}.json"
                race.write_bytes(original_bytes)
                attempts: list[int] = []

                def replace_before_open(path: str | bytes | os.PathLike[str], flags: int) -> int:
                    attempts.append(flags)
                    self.assertTrue(flags & os.O_NONBLOCK, "Report open must not block after a FIFO replacement race.")
                    self.assertTrue(flags & os.O_NOFOLLOW, "Report open must reject a link replacement race.")
                    race.unlink()
                    if replacement == "fifo":
                        os.mkfifo(race)
                    else:
                        race.symlink_to(report_path)
                    return real_open(path, flags)

                with patch("gui_models.os.open", replace_before_open), self.assertRaises(ReportValidationError):
                    load_report(race)
                self.assertEqual(len(attempts), 1)
        duplicate = self.directory / "duplicate.json"
        duplicate.write_text('{"schema_version":2,"schema_version":2}', encoding="utf-8")
        with self.assertRaisesRegex(ReportValidationError, "duplicate"):
            load_report(duplicate)
        cancellation = Event()
        cancellation.set()
        with self.assertRaises(ReportLoadCancelled):
            load_report_cancellable(report_path, cancellation)
        self.assertEqual(report_path.read_bytes(), original_bytes)

    def test_real_report_worker_clear_replace_cancel_and_close_never_publish_stale_packets(self) -> None:
        large_capture = self.directory / "large-loader.pcap"
        large_capture.write_bytes(classic_capture(10_000))
        large_document = analyze(large_capture, load_baseline(self.baseline), 3.8)
        large_path = write_report(large_document, large_capture, self.exports)
        small_capture = self.directory / "small-loader.pcapng"
        small_content = metadata_capture()
        small_capture.write_bytes(small_content)
        small_document = analyze(small_capture, load_baseline(self.baseline), 3.8)
        small_path = write_report(small_document, small_capture, self.exports)
        large_request = AnalysisRequest(large_capture, self.baseline, self.exports, 3.8, 0)
        small_request = AnalysisRequest(small_capture, self.baseline, self.exports, 3.8, 0)
        baseline_bytes = self.baseline.read_bytes()
        report_bytes = {path.name: path.read_bytes() for path in self.exports.iterdir() if path.is_file()}
        window = RviSentinelWindow()
        self.addCleanup(window.close)
        failures: list[tuple[str, str]] = []
        window.show_error = lambda title, detail: failures.append((title, detail))
        window.capture_field.setText(str(large_capture))
        window.baseline_field.setText(str(self.baseline))
        window.export_field.setText(str(self.exports))
        heartbeat = QTimer()
        heartbeats: list[float] = [time.monotonic()]
        heartbeat.timeout.connect(lambda: heartbeats.append(time.monotonic()))
        heartbeat.start(10)
        report_finished_at: list[float] = []
        window.report_load_finished.connect(lambda: report_finished_at.append(time.monotonic()))
        started = time.monotonic()
        window.begin_report_load(large_request, large_path, None, False)
        wait_until(lambda: window.report_worker is None and not window.report_loading and
                   not window.packet_timeline.is_busy and window.packet_timeline.completed_page is not None,
                   20_000, "Complete real 10,000-frame report loading and indexing")
        heartbeat.stop()
        heartbeats.append(time.monotonic())
        self.assertEqual(len(report_finished_at), 1)
        maximum_event_gap = max(after - before for before, after in zip(heartbeats, heartbeats[1:]))
        self.assertLess(maximum_event_gap, 2.0, "Real report parsing blocked Qt events for at least two seconds.")
        print("REPORT_LOADING_BENCHMARK " + json.dumps({
            "qt_platform": os.environ.get("QT_QPA_PLATFORM", "default"), "records": 10_000,
            "report_file_mib": round(large_path.stat().st_size / 1_048_576, 3),
            "report_load_and_summary_seconds": round(report_finished_at[0] - started, 4),
            "report_load_and_packet_page_seconds": round(time.monotonic() - started, 4),
            "maximum_event_gap_seconds": round(maximum_event_gap, 4),
            "event_heartbeats": len(heartbeats), "process_high_water_rss_mib": maximum_rss_mebibytes(),
        }, sort_keys=True), flush=True)
        wait_until(lambda: window.enrichment_process.state() == QProcess.ProcessState.NotRunning,
                   10_000, "Passive context after large report")
        window.clear_results()
        window.begin_report_load(large_request, large_path, None, False)
        window.clear_results()
        wait_until(lambda: window.report_worker is None and not window.packet_timeline.is_busy and not window.session_timeline.is_busy,
                   20_000, "Clear during real report loading")
        self.assertFalse(window.report_loading)
        self.assertIsNone(window.packet_timeline.completed_page)
        self.assertIsNone(window.preview_sha256)
        self.assertEqual(window.summary_labels["packet_count"].text(), "—")

        window.begin_report_load(large_request, large_path, None, False)
        window.capture_field.setText(str(small_capture))
        window.begin_report_load(small_request, small_path, None, False)
        wait_until(lambda: window.report_worker is None and not window.report_loading and
                   not window.packet_timeline.is_busy and window.packet_timeline.completed_page is not None,
                   20_000, "Newest real report generation replacing old load")
        self.assertEqual(window.active_report_path, small_path)
        self.assertEqual(window.summary_labels["packet_count"].text(), "3")
        self.assertEqual(window.packet_timeline.completed_page.capture_sha256, hashlib.sha256(small_content).hexdigest())
        wait_until(lambda: window.enrichment_process.state() == QProcess.ProcessState.NotRunning,
                   10_000, "Local enrichment after replacement")

        window.clear_results()
        window.capture_field.setText(str(large_capture))
        window.begin_report_load(large_request, large_path, None, False)
        window.cancel_analysis()
        wait_until(lambda: window.report_worker is None and not window.packet_timeline.is_busy and not window.session_timeline.is_busy,
                   20_000, "Cancellation during real report loading")
        self.assertIsNone(window.packet_timeline.completed_page)
        self.assertIsNone(window.preview_sha256)
        self.assertFalse(window.report_loading)

        window.show()
        window.begin_report_load(large_request, large_path, None, False)
        window.close()
        wait_until(lambda: window.report_worker is None and not window.packet_timeline.is_busy and not window.session_timeline.is_busy and
                   not window.isVisible(), 20_000, "Window close during real report loading")
        self.assertTrue(window.closing_requested)
        self.assertEqual(failures, [])
        self.assertEqual(self.baseline.read_bytes(), baseline_bytes)
        self.assertEqual({path.name: path.read_bytes() for path in self.exports.iterdir() if path.is_file()}, report_bytes)

    def test_application_quit_waits_for_actual_workers_in_owned_process(self) -> None:
        capture = self.directory / "quit-loader.pcap"
        capture.write_bytes(classic_capture(10_000))
        document = analyze(capture, load_baseline(self.baseline), 3.8)
        report_path = write_report(document, capture, self.exports)
        script = """
from pathlib import Path
import sys
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from gui import RviSentinelWindow, WindowQuitFilter
from gui_models import AnalysisRequest, load_report
from tests.packet_timeline_fixture import timeline_records, timeline_report

application = QApplication(['test_owned_application_quit'])
window = RviSentinelWindow()
quit_filter = WindowQuitFilter(window)
application.installEventFilter(quit_filter)
capture, baseline, exports, report_path = (Path(value) for value in sys.argv[1:5])
mode = sys.argv[5]
window.capture_field.setText(str(capture))
window.baseline_field.setText(str(baseline))
window.export_field.setText(str(exports))
window.show()
if mode == 'report':
    window.begin_report_load(AnalysisRequest(capture, baseline, exports, 3.8, 0), report_path, None, False)
else:
    template = load_report(report_path)
    assert template.evidence is not None
    records = timeline_records(100_000)
    window.packet_timeline.set_report(timeline_report(template, records, template.evidence.sha256))

def quit_while_loading():
    active = (window.report_loading and window.report_worker is not None) if mode == 'report' else window.packet_timeline.is_busy
    if not active:
        print(f'Expected an actual active {mode} worker before application quit.', flush=True)
        application.exit(4)
        return
    application.quit()

deadline = QTimer()
deadline.setSingleShot(True)
deadline.timeout.connect(lambda: application.exit(3))
deadline.start(10_000)
QTimer.singleShot(0, quit_while_loading)
result = application.exec()
deadline.stop()
assert result == 0, f'Application quit exceeded its deadline or missed worker activity: {result}'
assert window.closing_requested and window.quit_requested
assert window.report_worker is None or not window.report_worker.isRunning()
assert not window.packet_timeline.is_busy
assert not window.session_timeline.is_busy
assert not window.isVisible()
print('PASS actual application quit completed owned worker shutdown', flush=True)
"""
        for mode in ("report", "packet"):
            with self.subTest(worker=mode):
                result = subprocess.run(
                    [sys.executable, "-c", script, str(capture), str(self.baseline), str(self.exports), str(report_path), mode],
                    cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=20, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("PASS actual application quit", result.stdout)
                self.assertNotIn("Destroyed while thread is still running", result.stderr)
                self.assertNotIn("Destroyed while process", result.stderr)

    def test_large_native_qt_worker_queries_have_bounded_pages_and_event_heartbeats(self) -> None:
        template = self.saved_report("benchmark-template.pcapng", metadata_capture())
        records = timeline_records(100_000)
        measurements: list[dict[str, str | float | int | None]] = []
        for count in (50_000, 100_000):
            with self.subTest(record_count=count):
                digest = hashlib.sha256(f"timeline benchmark {count}".encode("ascii")).hexdigest()
                report = timeline_report(template, records[:count], digest)
                widget = PacketTimelineWidget(None)
                self.addCleanup(self.close_widget, widget)
                widget.resize(1_400, 850)
                widget.show()
                heartbeat = QTimer()
                heartbeats: list[float] = [time.monotonic()]
                heartbeat.timeout.connect(lambda: heartbeats.append(time.monotonic()))
                heartbeat.start(10)
                started = time.monotonic()
                index_timings: list[float] = []

                def timed_index(capture_sha256: str, packets: tuple[PacketRecord, ...], cancellation: Event) -> PacketIndex:
                    index_started = time.monotonic()
                    result = build_packet_index(capture_sha256, packets, cancellation)
                    index_timings.append(time.monotonic() - index_started)
                    return result

                with patch("packet_view.build_packet_index", timed_index):
                    widget.set_report(report)
                    wait_until(lambda: not widget.is_busy and widget.completed_page is not None, 30_000, "Large timeline index and first presentation")
                index_and_page_seconds = time.monotonic() - started
                self.assertEqual(len(index_timings), 1, "The first page should build one owned packet index.")
                self.assert_matches(widget, count)
                self.assertEqual(widget.model.rowCount(QModelIndex()), 100)
                self.assertEqual(widget.completed_page.total_count, count)
                self.assertEqual(widget.completed_page.page_count, count // 100)
                widget.table.selectRow(3)
                selected = widget.selected_identity
                previous_page = widget.completed_page
                child(widget, QLineEdit, "packetSearch").setText("cancelled-filter.test")
                child(widget, QPushButton, "packetApplyFilters").click()
                child(widget, QPushButton, "packetCancelQuery").click()
                wait_until(lambda: not widget.is_busy, 20_000, "Cancelled large packet query shutdown")
                self.assertEqual(widget.completed_page, previous_page)
                self.assertEqual(widget.selected_identity, selected)
                child(widget, QLineEdit, "packetSearch").setText("fixture-other")
                choose(widget, "packetProcessStateFilter", "conflict")
                choose(widget, "packetInterfaceStateFilter", "conflict")
                choose(widget, "packetDirectionFilter", "conflict")
                child(widget, QLineEdit, "packetProtocolFilter").setText("tls")
                choose(widget, "packetPageSize", 250)
                started = time.monotonic()
                apply_filters(widget)
                query_and_page_seconds = time.monotonic() - started
                self.assert_matches(widget, count // 4)
                self.assertEqual(widget.model.rowCount(QModelIndex()), 250)
                self.assertEqual(widget.completed_page.page_count, count // 1_000)
                self.assertEqual(widget.selected_identity, selected)
                child(widget, QPushButton, "packetNextPage").click()
                wait_until(lambda: not widget.is_busy and widget.completed_page.page_number == 2, 20_000, "Second large filtered page")
                self.assertEqual(widget.model.rowCount(QModelIndex()), 250)
                self.assertEqual(widget.selected_identity, selected)
                self.assertIn("outside", widget.selection_notice.text().lower())
                clear_filters(widget)
                choose(widget, "packetPageSize", 500)
                apply_filters(widget)
                self.assertEqual(widget.model.rowCount(QModelIndex()), 500)
                self.assertEqual(widget.completed_page.matching_count, count)
                self.assertEqual(widget.selected_identity, selected)
                started = time.monotonic()
                rendered_viewport = widget.table.viewport().grab()
                viewport_render_seconds = time.monotonic() - started
                self.assertFalse(rendered_viewport.isNull(), "The native Qt viewport must render a real bounded packet page.")
                heartbeat.stop()
                heartbeats.append(time.monotonic())
                maximum_event_gap = max(after - before for before, after in zip(heartbeats, heartbeats[1:]))
                self.assertGreater(len(heartbeats), 2, "Qt events must run while large worker work is pending.")
                self.assertLess(maximum_event_gap, 2.0, "Timeline work blocked Qt events for at least two seconds.")
                measurements.append({
                    "qt_platform": os.environ.get("QT_QPA_PLATFORM", "default"),
                    "records": count, "index_and_first_page_seconds": round(index_and_page_seconds, 4),
                    "worker_index_seconds": round(index_timings[0], 4),
                    "filtered_query_and_page_seconds": round(query_and_page_seconds, 4),
                    "viewport_render_seconds": round(viewport_render_seconds, 4),
                    "maximum_event_gap_seconds": round(maximum_event_gap, 4),
                    "event_heartbeats": len(heartbeats), "maximum_page_rows": 500,
                    "process_high_water_rss_mib": maximum_rss_mebibytes(),
                })
                self.close_widget(widget)
        print("TIMELINE_BENCHMARK " + json.dumps(measurements, sort_keys=True), flush=True)


if __name__ == "__main__":
    unittest.main()
