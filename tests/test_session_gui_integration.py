"""Real offline transport evidence, scoped session navigation, and Qt responsiveness."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Literal
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QModelIndex, QTimer
from PySide6.QtWidgets import QApplication, QGroupBox, QLabel, QLineEdit, QPushButton

from analyze import analyze, load_baseline, write_report
from gui import RviSentinelWindow
from gui_models import AnalysisReport, load_report
from packet_timeline import PacketIdentity
from packet_sessions import members_for_session, session_for_packet
from tests.packet_timeline_fixture import timeline_report
from tests.test_packet_gui_integration import child, choose, maximum_rss_mebibytes, wait_until
from tests.session_fixture import diverse_session_records, session_capture, ungrouped_session_records


class SessionGuiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("Session GUI integration requires the real Wireshark/TShark decoder on PATH.")
        application = QApplication.instance()
        cls.application = application if isinstance(application, QApplication) else QApplication(["test_session_gui_integration"])

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-sentinel-session-gui-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.baseline = self.directory / "baseline.json"
        self.baseline.write_text(json.dumps(load_baseline(self.baseline), sort_keys=True), encoding="utf-8")
        self.exports = self.directory / "exports"

    def saved_report(self, container: Literal["pcap", "pcapng"]) -> tuple[AnalysisReport, Path, bytes]:
        capture = self.directory / f"scoped-session-{container}.{container}"
        content = session_capture(container)
        capture.write_bytes(content)
        document = analyze(capture, load_baseline(self.baseline), 3.8)
        report_path = write_report(document, capture, self.exports)
        return load_report(report_path), capture, content

    def window(self, report: AnalysisReport) -> RviSentinelWindow:
        window = RviSentinelWindow()
        self.addCleanup(self.close_window, window)
        window.baseline_field.setText(str(self.baseline))
        window.export_field.setText(str(self.exports))
        window.populate_report(report)
        self.wait_views(window)
        return window

    def close_window(self, window: RviSentinelWindow) -> None:
        window.close()
        wait_until(lambda: not window.packet_timeline.is_busy and not window.session_timeline.is_busy,
                   20_000, "Owned packet and session workers shut down")

    def wait_views(self, window: RviSentinelWindow) -> None:
        wait_until(lambda: not window.packet_timeline.is_busy and not window.session_timeline.is_busy and
                   window.packet_timeline.completed_page is not None and
                   window.session_timeline.completed_page is not None,
                   30_000, "Packet and session indexes and completed pages")

    def apply_sessions(self, window: RviSentinelWindow) -> None:
        child(window.session_timeline, QPushButton, "sessionApplyFilters").click()
        wait_until(lambda: not window.session_timeline.is_busy and window.session_timeline.completed_page is not None,
                   30_000, "Scoped session query")

    def apply_packets(self, window: RviSentinelWindow) -> None:
        child(window.packet_timeline, QPushButton, "packetApplyFilters").click()
        wait_until(lambda: not window.packet_timeline.is_busy and window.packet_timeline.completed_page is not None,
                   30_000, "Scoped member packet query")

    def test_real_decoded_scope_partition_navigation_and_saved_bytes(self) -> None:
        original_baseline = self.baseline.read_bytes()
        with patch("socket.gethostbyaddr", side_effect=AssertionError("Session navigation must not resolve PTR")), patch(
            "socket.getaddrinfo", side_effect=AssertionError("Session navigation must not resolve names")
        ):
            for container, expected in (
                ("pcap", ((1, 3, 5, 6, 7, 8, 9, 14), (2, 4), (10, 11), (12, 13))),
                ("pcapng", ((1, 3, 5), (2, 4), (6, 7), (8, 9), (10, 11), (12, 13), (14,))),
            ):
                with self.subTest(container=container):
                    report, capture, content = self.saved_report(container)
                    exports_before = {path.name: path.read_bytes() for path in self.exports.iterdir() if path.is_file()}
                    window = self.window(report)
                    sessions = window.session_timeline
                    packets = window.packet_timeline
                    index = sessions.session_index
                    self.assertIsNotNone(index)
                    if index is None:
                        raise AssertionError("The actual session worker did not publish an index.")
                    self.assertEqual(tuple(sorted(session.member_frames for session in index.sessions)), tuple(sorted(expected)))
                    self.assertEqual(index.eligible_packet_count, 14)
                    self.assertEqual(index.ungrouped, ())
                    self.assertEqual(sum(session.packet_count for session in index.sessions), 14)
                    self.assertEqual(sum(session.wire_bytes for session in index.sessions), sum(packet.wire_length for packet in report.packets))
                    self.assertEqual(len({frame for session in index.sessions for frame in session.member_frames}), 14)
                    self.assertEqual({session.scope.transport for session in index.sessions}, {"tcp", "udp"})
                    self.assertEqual(index.capture_sha256, hashlib.sha256(content).hexdigest())
                    originals = {packet.frame_number: packet for packet in report.packets}
                    for session in index.sessions:
                        self.assertTrue(all(packet is originals[packet.frame_number]
                                            for packet in members_for_session(index, session.identity)),
                                        "Session membership must retain original immutable evidence objects.")
                    if container == "pcapng":
                        self.assertEqual({session.scope.interface.labels[0].name for session in index.sessions}, {"fixture0", "fixture1"})
                        self.assertIn("unknown", {session.scope.process.state for session in index.sessions})
                        child(sessions, QLineEdit, "sessionProcessFilter").setText("fixture-maild")
                        self.apply_sessions(window)
                        self.assertEqual(sessions.completed_page.matching_count, 3)
                    else:
                        self.assertEqual({session.scope.process.state for session in index.sessions}, {"unknown"})
                        choose(sessions, "sessionProcessStateFilter", "unknown")
                        self.apply_sessions(window)
                        self.assertEqual(sessions.completed_page.matching_count, 4)
                    sessions.table.selectRow(0)
                    selected_session = sessions.selected_identity
                    self.assertIsNotNone(selected_session)
                    session_context = sessions.capture_navigation()
                    session_inspector = sessions.inspector.toPlainText()
                    self.assertIn(hashlib.sha256(content).hexdigest(), session_inspector)
                    self.assertIn("1791428448.590385001", session_inspector)
                    child(packets, QLineEdit, "packetProtocolFilter").setText("udp")
                    self.apply_packets(window)
                    packets.table.selectRow(0)
                    prior_packet_context = packets.capture_navigation()
                    prior_packet_inspector = packets.inspector.toPlainText()

                    child(sessions, QPushButton, "sessionOpenPackets").click()
                    self.wait_views(window)
                    selected_record = next(session for session in index.sessions if session.identity == selected_session)
                    self.assertEqual(tuple(packet.frame_number for packet in packets.completed_page.packets), selected_record.member_frames)
                    self.assertEqual(packets.completed_page.matching_count, selected_record.packet_count)
                    self.assertEqual(window.results_tabs.currentWidget(), packets)
                    packets.table.selectRow(0)
                    selected_packet = packets.selected_identity
                    self.assertIsNotNone(selected_packet)
                    self.assertIn(f"frame:{selected_record.member_frames[0]}", packets.inspector.toPlainText())
                    member_packet_context = packets.capture_navigation()
                    member_packet_inspector = packets.inspector.toPlainText()
                    child(packets, QPushButton, "packetShowOwningSession").click()
                    self.wait_views(window)
                    self.assertEqual(sessions.selected_identity, selected_session)
                    self.assertEqual(window.results_tabs.currentWidget(), sessions)
                    child(sessions, QPushButton, "sessionReturnToPackets").click()
                    self.wait_views(window)
                    self.assertEqual(window.results_tabs.currentWidget(), packets)
                    self.assertEqual(packets.capture_navigation(), member_packet_context)
                    self.assertEqual(packets.inspector.toPlainText(), member_packet_inspector)

                    child(packets, QPushButton, "packetBackToSessions").click()
                    self.wait_views(window)
                    self.assertEqual(sessions.capture_navigation(), session_context)
                    self.assertEqual(sessions.inspector.toPlainText(), session_inspector)
                    child(packets, QPushButton, "packetRestoreTimeline").click()
                    self.wait_views(window)
                    self.assertEqual(packets.capture_navigation(), prior_packet_context)
                    self.assertEqual(packets.inspector.toPlainText(), prior_packet_inspector)
                    self.assertEqual(capture.read_bytes(), content)
                    self.assertEqual(self.baseline.read_bytes(), original_baseline)
                    self.assertEqual({path.name: path.read_bytes() for path in self.exports.iterdir() if path.is_file()}, exports_before)
                    self.close_window(window)

    def test_ungrouped_evidence_is_inspectable_and_never_guessed_into_a_session(self) -> None:
        template, _, _ = self.saved_report("pcapng")
        records = ungrouped_session_records()
        digest = hashlib.sha256(b"typed ungrouped evidence fixture").hexdigest()
        window = self.window(timeline_report(template, records, digest))
        sessions = window.session_timeline
        index = sessions.session_index
        self.assertIsNotNone(index)
        if index is None:
            raise AssertionError("The session index is unavailable.")
        self.assertEqual(len(index.sessions), 1)
        self.assertEqual(index.sessions[0].member_frames, (1, 2))
        self.assertEqual(tuple(packet.frame_number for packet in index.ungrouped), (3, 4, 5, 6, 7, 8))
        self.assertEqual(index.eligible_packet_count + len(index.ungrouped), len(records))
        self.assertTrue(all(packet.reasons for packet in index.ungrouped))
        self.assertIn("6", child(sessions, QLabel, "sessionUngroupedStatus").text())
        child(sessions, QPushButton, "sessionOpenUngroupedPackets").click()
        self.wait_views(window)
        packets = window.packet_timeline
        self.assertEqual(tuple(packet.frame_number for packet in packets.completed_page.packets), (3, 4, 5, 6, 7, 8))
        for row, evidence in enumerate(index.ungrouped):
            packets.table.selectRow(row)
            self.assertEqual(packets.selected_identity, PacketIdentity(digest, evidence.frame_number))
            self.assertIn(digest, packets.inspector.toPlainText())
            self.assertIsNone(session_for_packet(index, packets.selected_identity))
            self.assertFalse(child(packets, QPushButton, "packetShowOwningSession").isEnabled())
            self.assertTrue(any(reason.replace("_", " ") in packets.inspector.toPlainText().lower() or
                                reason in packets.inspector.toPlainText() for reason in evidence.reasons),
                            "An ungrouped member inspector must preserve an accessible explanation.")

    def test_many_session_pages_navigation_cancellation_and_qt_heartbeats(self) -> None:
        template, _, _ = self.saved_report("pcapng")
        records = diverse_session_records(100_000)
        measurements: list[dict[str, str | int | float | None]] = []
        for count in (50_000, 100_000):
            with self.subTest(frame_count=count):
                digest = hashlib.sha256(f"diverse scoped session benchmark {count}".encode("ascii")).hexdigest()
                report = timeline_report(template, records[:count], digest)
                window = RviSentinelWindow()
                self.addCleanup(self.close_window, window)
                window.resize(1400, 1000)
                window.show()
                window.workspace_tabs.setCurrentIndex(1)
                heartbeat = QTimer()
                heartbeats: list[float] = [time.monotonic()]
                heartbeat.timeout.connect(lambda: heartbeats.append(time.monotonic()))
                heartbeat.start(10)
                started = time.monotonic()
                window.populate_report(report)
                self.wait_views(window)
                index_and_page_seconds = time.monotonic() - started
                sessions = window.session_timeline
                packets = window.packet_timeline
                index = sessions.session_index
                self.assertIsNotNone(index)
                if index is None:
                    raise AssertionError("The many-session index is unavailable.")
                self.assertEqual(len(index.sessions), count // 2)
                self.assertEqual(index.eligible_packet_count, count)
                self.assertEqual(index.ungrouped, ())
                self.assertEqual(len(index.member_frames), count)
                self.assertEqual(len(set(index.member_frames)), count)
                self.assertEqual(sessions.model.rowCount(QModelIndex()), 100)
                self.assertEqual(sessions.completed_page.matching_count, count // 2)
                window.results_tabs.setCurrentWidget(sessions)
                configuration = child(window, QGroupBox, "analysisConfiguration")
                toggle = child(window, QPushButton, "analysisConfigurationToggle")
                self.assertTrue(configuration.isHidden(), "Packet and session workspaces must reserve visible evidence space.")
                toggle.click()
                self.assertFalse(configuration.isHidden(), "Analysis settings must remain available through the explicit toggle.")
                toggle.click()
                self.assertTrue(configuration.isHidden())
                wait_until(lambda: sessions.table.viewport().height() > 0 and
                           sessions.table.viewport().width() > 0 and
                           sessions.inspector.viewport().height() > 0 and
                           sessions.inspector.viewport().width() > 0,
                           5_000, "Usable native session table and inspector viewports")
                child(sessions, QLineEdit, "sessionInterfaceFilter").setText("fixture1")
                choose(sessions, "sessionTransportFilter", "tcp")
                choose(sessions, "sessionPageSize", 250)
                started = time.monotonic()
                self.apply_sessions(window)
                query_seconds = time.monotonic() - started
                expected_matches = sum(group % 2 == 0 and group % 13 in (1, 10, 11, 12)
                                       for group in range(count // 2))
                self.assertEqual(sessions.completed_page.matching_count, expected_matches)
                self.assertGreater(expected_matches, 500)
                self.assertEqual(sessions.model.rowCount(QModelIndex()), 250)
                child(sessions, QPushButton, "sessionNextPage").click()
                wait_until(lambda: not sessions.is_busy and sessions.completed_page.page_number == 2,
                           30_000, "Many-session second filtered page")
                sessions.table.selectRow(20)
                sessions.table.verticalScrollBar().setValue(120)
                selected = sessions.selected_identity
                context = sessions.capture_navigation()
                inspector = sessions.inspector.toPlainText()
                prior_page = sessions.completed_page
                child(sessions, QLineEdit, "sessionSearch").setText("cancelled-query-that-must-not-replace-the-page")
                child(sessions, QPushButton, "sessionApplyFilters").click()
                child(sessions, QPushButton, "sessionCancelQuery").click()
                wait_until(lambda: not sessions.is_busy, 30_000, "Cancelled many-session query")
                self.assertEqual(sessions.completed_page, prior_page)
                self.assertEqual(sessions.selected_identity, selected)
                self.assertEqual(sessions.inspector.toPlainText(), inspector)
                sessions.restore_navigation(context)
                self.wait_views(window)
                started = time.monotonic()
                child(sessions, QPushButton, "sessionOpenPackets").click()
                self.wait_views(window)
                self.assertEqual(packets.completed_page.matching_count, 2)
                wait_until(lambda: packets.table.viewport().height() > 0 and
                           packets.table.viewport().width() > 0 and
                           packets.inspector.viewport().height() > 0 and
                           packets.inspector.viewport().width() > 0,
                           5_000, "Usable native member table and packet inspector viewports")
                packets.table.selectRow(1)
                packet_identity = packets.selected_identity
                self.assertIsNotNone(packet_identity)
                child(packets, QPushButton, "packetShowOwningSession").click()
                self.wait_views(window)
                self.assertEqual(sessions.selected_identity, selected)
                child(packets, QPushButton, "packetBackToSessions").click()
                self.wait_views(window)
                self.assertEqual(sessions.capture_navigation(), context)
                self.assertEqual(sessions.inspector.toPlainText(), inspector)
                navigation_seconds = time.monotonic() - started
                rendered = sessions.table.viewport().grab()
                self.assertFalse(rendered.isNull())
                heartbeat.stop()
                heartbeats.append(time.monotonic())
                maximum_gap = max(after - before for before, after in zip(heartbeats, heartbeats[1:]))
                self.assertGreater(len(heartbeats), 2)
                self.assertLess(maximum_gap, 2.0, "Session work blocked the Qt event loop for at least two seconds.")
                measurements.append({
                    "qt_platform": os.environ.get("QT_QPA_PLATFORM", "default"),
                    "frames": count, "sessions": count // 2, "shared_stream_scope_groups": 8,
                    "regular_process_labels": 103, "effective_process_labels": 113, "interfaces": 13,
                    "index_and_first_pages_seconds": round(index_and_page_seconds, 4),
                    "filtered_query_and_page_seconds": round(query_seconds, 4),
                    "member_owner_back_navigation_seconds": round(navigation_seconds, 4),
                    "maximum_event_gap_seconds": round(maximum_gap, 4), "event_heartbeats": len(heartbeats),
                    "maximum_session_page_rows": 250, "process_high_water_rss_mib": maximum_rss_mebibytes(),
                })
                self.close_window(window)
        print("SESSION_GUI_BENCHMARK " + json.dumps(measurements, sort_keys=True), flush=True)

    def test_capture_replacement_invalidates_pending_sessions_selection_and_navigation(self) -> None:
        template, _, _ = self.saved_report("pcapng")
        records = diverse_session_records(2000)
        old_digest = hashlib.sha256(b"old artifact scoped sessions").hexdigest()
        new_digest = hashlib.sha256(b"new artifact scoped sessions").hexdigest()
        window = self.window(timeline_report(template, records, old_digest))
        sessions = window.session_timeline
        packets = window.packet_timeline
        sessions.table.selectRow(0)
        context = sessions.capture_navigation()
        packet_context = packets.capture_navigation()
        child(sessions, QPushButton, "sessionOpenPackets").click()
        self.wait_views(window)
        packets.table.selectRow(0)
        child(sessions, QLineEdit, "sessionSearch").setText("fixture-process")
        child(sessions, QPushButton, "sessionApplyFilters").click()
        window.populate_report(timeline_report(template, records[:20], new_digest))
        self.wait_views(window)
        self.assertEqual(sessions.completed_page.capture_sha256, new_digest)
        self.assertEqual(packets.completed_page.capture_sha256, new_digest)
        self.assertEqual(len(sessions.session_index.sessions), 10)
        self.assertIsNone(sessions.selected_identity)
        self.assertIsNone(packets.selected_identity)
        self.assertFalse(sessions.restore_navigation(context))
        self.assertFalse(packets.restore_navigation(packet_context))
        self.assertFalse(child(packets, QPushButton, "packetBackToSessions").isEnabled())
        self.assertFalse(child(packets, QPushButton, "packetRestoreTimeline").isEnabled())
        self.assertNotIn(old_digest, sessions.inspector.toPlainText())
        self.assertNotIn(old_digest, packets.inspector.toPlainText())
        legacy = replace(timeline_report(template, records[:20], new_digest), evidence=None, packets=())
        window.populate_report(legacy)
        wait_until(lambda: not sessions.is_busy and not packets.is_busy, 20_000, "Legacy report invalidation")
        self.assertIsNone(sessions.completed_page)
        self.assertIsNone(sessions.session_index)
        self.assertIsNone(packets.completed_page)
        self.assertFalse(child(sessions, QPushButton, "sessionApplyFilters").isEnabled())
        self.assertFalse(child(sessions, QPushButton, "sessionOpenPackets").isEnabled())

    def test_application_quit_finishes_actual_owned_session_and_packet_workers(self) -> None:
        self.saved_report("pcapng")
        report_path = self.exports / "scoped-session-pcapng_report.json"
        script = """
from pathlib import Path
import hashlib
import sys
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from gui import RviSentinelWindow, WindowQuitFilter
from gui_models import load_report
from tests.packet_timeline_fixture import timeline_report
from tests.session_fixture import diverse_session_records

application = QApplication(['test_owned_session_quit'])
window = RviSentinelWindow()
quit_filter = WindowQuitFilter(window)
application.installEventFilter(quit_filter)
template = load_report(Path(sys.argv[1]))
records = diverse_session_records(100_000)
report = timeline_report(template, records, hashlib.sha256(b'owned session quit corpus').hexdigest())
window.show()

def quit_with_actual_workers():
    window.populate_report(report)
    if not window.session_timeline.is_busy or not window.packet_timeline.is_busy:
        print('Expected both actual session and packet workers before quit.', flush=True)
        application.exit(4)
        return
    application.quit()

deadline = QTimer()
deadline.setSingleShot(True)
deadline.timeout.connect(lambda: application.exit(3))
deadline.start(15_000)
QTimer.singleShot(0, quit_with_actual_workers)
result = application.exec()
deadline.stop()
assert result == 0, f'Actual session/packet shutdown failed: {result}'
assert window.closing_requested and window.quit_requested
assert not window.session_timeline.is_busy
assert not window.packet_timeline.is_busy
assert not window.isVisible()
print('PASS actual session and packet workers completed owned application quit', flush=True)
"""
        result = subprocess.run([sys.executable, "-X", "faulthandler", "-c", script, str(report_path)],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True,
                                text=True, timeout=40, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS actual session and packet workers", result.stdout)
        self.assertNotIn("Destroyed while thread is still running", result.stderr)
        self.assertNotIn("Destroyed while process", result.stderr)


if __name__ == "__main__":
    unittest.main()
