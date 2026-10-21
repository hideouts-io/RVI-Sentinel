"""Qt scoped-session selection, bounded pages, return context and owned workers."""

from __future__ import annotations

import os
import unittest
from dataclasses import replace
from threading import Event

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QModelIndex, QTimer, Qt
from PySide6.QtGui import QTextDocument
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QComboBox, QLineEdit, QPushButton, QWidget

import session_view
from gui_models import AnalysisEvidence, AnalysisReport, AnalysisSummary, CaptureDetails
from packet_models import PacketRecord, decode_packet_fields
from packet_sessions import SessionCancelled, SessionIdentity, SessionIndex, SessionPage, SessionQuery
from session_view import SessionTimelineWidget
from tests.test_packet_view import wait_until


def fixture_packet(frame: int, stream: int, transport: str, reverse: bool) -> PacketRecord:
    source, destination = ("192.0.2.1", "198.51.100.2")
    source_port, destination_port = (51000, 443) if transport == "tcp" else (53000, 53)
    if reverse:
        source, destination = destination, source
        source_port, destination_port = destination_port, source_port
    values: dict[str, tuple[str, ...]] = {
        "frame.number": (str(frame),), "frame.time_epoch": (f"1700000000.{frame:09d}",),
        "frame.len": ("64",), "frame.cap_len": ("64",), "frame.protocols": (f"ip:{transport}",),
        "_ws.col.protocol": (transport.upper(),), "ip.src": (source,), "ip.dst": (destination,),
        f"{transport}.srcport": (str(source_port),), f"{transport}.dstport": (str(destination_port),),
        f"{transport}.stream": (str(stream),),
        "frame.darwin.process_info.pname": (("<b>literal<script>.test" if stream == 0 else f"process-{stream}.test"),),
        "frame.darwin.process_info.pid": (str(1000 + stream),),
        "frame.interface_name": ("fixture0",),
    }
    return decode_packet_fields(values, tuple(values))


def fixture_report(count: int, digest: str) -> AnalysisReport:
    packets = tuple(fixture_packet(frame, (frame - 1) // 2, "tcp" if ((frame - 1) // 2) % 2 == 0 else "udp", frame % 2 == 0) for frame in range(1, count * 2 + 1))
    missing_stream = {field.name: field.values for field in packets[0].fields}
    missing_stream.pop("tcp.stream")
    missing_stream["frame.number"] = (str(count * 2 + 1),)
    missing_stream["frame.time_epoch"] = (f"1700000000.{count * 2 + 1:09d}",)
    ungrouped = decode_packet_fields(missing_stream, tuple(missing_stream))
    packets += (ungrouped,)
    supported = tuple(dict.fromkeys(field.name for packet in packets for field in packet.fields))
    evidence = AnalysisEvidence(digest, "synthetic session decoder", len(supported), supported, (), len(packets), "imported_unknown", "verified")
    return AnalysisReport(
        CaptureDetails("synthetic.pcap", len(packets) * 64, len(packets), None, None, None),
        AnalysisSummary(2, 0, 0, 0, frozenset(), frozenset(), frozenset()),
        (), (), (), (), (), (), evidence, packets, None,
    )


class SessionViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication(["test_session_view"])

    def setUp(self) -> None:
        self.parent = QWidget()
        self.widget = SessionTimelineWidget(self.parent)
        self.widget.resize(1200, 850)
        self.widget.show()
        self.report = fixture_report(301, "a" * 64)

    def tearDown(self) -> None:
        self.widget.shutdown()
        wait_until(lambda: not self.widget.is_busy, 5000)
        self.parent.close()
        self.parent.deleteLater()
        self.application.processEvents()

    def load(self) -> None:
        self.widget.set_report(self.report)
        wait_until(lambda: not self.widget.is_busy and self.widget.page is not None, 5000)

    def ready(self) -> None:
        wait_until(lambda: not self.widget.is_busy, 5000)

    def click(self, name: str) -> None:
        control = self.widget.findChild(QPushButton, name)
        self.assertIsNotNone(control, name)
        QTest.mouseClick(control, Qt.MouseButton.LeftButton)

    def edit(self, name: str, value: str) -> None:
        control = self.widget.findChild(QLineEdit, name)
        self.assertIsNotNone(control, name)
        control.setText(value)

    def choice(self, name: str, value: str) -> None:
        control = self.widget.findChild(QComboBox, name)
        self.assertIsNotNone(control, name)
        position = control.findData(value)
        self.assertGreaterEqual(position, 0)
        control.setCurrentIndex(position)

    def test_bounded_pages_show_counts_and_exact_ungrouped_reason(self) -> None:
        self.load()
        self.assertEqual(self.widget.model.rowCount(QModelIndex()), 100)
        self.assertEqual(self.widget.page.total_count, 301)
        self.assertEqual(self.widget.page.page_count, 4)
        self.assertIn("602 eligible / 603 total packets", self.widget.status_label.text())
        self.assertIn("1 ungrouped", self.widget.status_label.text())
        self.assertIn("missing_stream: 1", self.widget.ungrouped_label.text())
        self.click("sessionNextPage")
        self.ready()
        self.assertEqual(self.widget.page.page_number, 2)
        self.assertEqual(self.widget.model.sessions[0].member_frames, (201, 202))
        self.widget.page_size.setCurrentIndex(2)
        self.ready()
        self.assertEqual(self.widget.page.page_size, 500)
        self.assertEqual(self.widget.model.rowCount(QModelIndex()), 301)

    def test_plain_scope_inspector_survives_filter_hiding_selection(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        cell = self.widget.model.index(0, 4)
        display = self.widget.model.data(cell, Qt.ItemDataRole.DisplayRole)
        tooltip = self.widget.model.data(cell, Qt.ItemDataRole.ToolTipRole)
        if not isinstance(display, str) or not isinstance(tooltip, str):
            raise AssertionError("The recorded session process must expose display and tooltip evidence.")
        document = QTextDocument()
        document.setHtml(tooltip)
        self.assertEqual(document.toPlainText(), display)
        identity = self.widget.selected_identity
        text = self.widget.inspector.toPlainText()
        self.assertIn("<b>literal<script>.test", text)
        self.assertIn("1700000000.000000001", text)
        self.assertIn("1700000000.000000002", text)
        self.assertIn("0.000000001 s", text)
        self.assertIn("do not establish the process owning a connection", text)
        self.edit("sessionSearch", "process-1.test")
        self.click("sessionApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.matching_count, 1)
        self.assertEqual(self.widget.selected_identity, identity)
        self.assertEqual(self.widget.inspector.toPlainText(), text)
        self.assertIn("outside the current filter", self.widget.selection_notice.text())
        self.assertEqual(self.widget.table.selectionModel().selectedRows(), [])
        self.click("sessionClearFilters")
        self.ready()
        self.assertEqual(self.widget.table.selectionModel().selectedRows()[0].row(), 0)

    def test_search_transport_endpoint_port_and_metadata_filters_combine(self) -> None:
        self.load()
        self.edit("sessionSearch", "PROCESS-1.TEST")
        self.edit("sessionEndpointFilter", "198.51.100.2")
        self.edit("sessionPortFilter", "53")
        self.choice("sessionTransportFilter", "udp")
        self.choice("sessionProcessStateFilter", "recorded")
        self.choice("sessionEffectiveProcessStateFilter", "unknown")
        self.edit("sessionInterfaceFilter", "FIXTURE0")
        self.click("sessionApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.matching_count, 1)
        self.assertEqual(self.widget.page.sessions[0].member_frames, (3, 4))
        self.edit("sessionPortFilter", "443")
        self.click("sessionApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.matching_count, 0)
        self.assertEqual(self.widget.model.rowCount(QModelIndex()), 0)

    def test_invalid_filters_preserve_completed_page_and_cause(self) -> None:
        self.load()
        page = self.widget.page
        self.edit("sessionPortFilter", "not a port")
        self.click("sessionApplyFilters")
        self.ready()
        self.assertIs(self.widget.page, page)
        self.assertIn("decimal integer", self.widget.status_label.text())
        self.edit("sessionPortFilter", "")
        self.edit("sessionEndpointFilter", "198.51")
        self.click("sessionApplyFilters")
        self.ready()
        self.assertIs(self.widget.page, page)
        self.assertIn("complete IPv4 or IPv6", self.widget.status_label.text())

    def test_navigation_restores_query_page_identity_and_scroll(self) -> None:
        self.load()
        self.edit("sessionInterfaceFilter", "fixture")
        self.click("sessionApplyFilters")
        self.ready()
        self.click("sessionNextPage")
        self.ready()
        self.widget.table.selectRow(50)
        self.widget.table.verticalScrollBar().setValue(25)
        snapshot = self.widget.capture_navigation()
        self.assertIsNotNone(snapshot)
        target = self.widget.session_index.sessions[2].identity
        self.assertTrue(self.widget.select_session(target))
        self.ready()
        self.assertEqual(self.widget.selected_identity, target)
        self.assertEqual(self.widget.page.page_number, 1)
        self.assertEqual(self.widget.interface_field.text(), "")
        self.assertTrue(self.widget.restore_navigation(snapshot))
        self.ready()
        self.assertEqual(self.widget.selected_identity, snapshot.selected_identity)
        self.assertEqual(self.widget.page.page_number, 2)
        self.assertEqual(self.widget.interface_field.text(), "fixture")
        self.assertEqual(self.widget.table.verticalScrollBar().value(), snapshot.vertical_scroll_value)
        self.assertEqual(self.widget.table.selectionModel().selectedRows()[0].row(), 50)
        self.widget.set_report(self.report)
        self.ready()
        self.assertFalse(self.widget.restore_navigation(snapshot))
        self.assertIsNone(self.widget.selected_identity)

    def test_navigation_signals_bind_members_and_ungrouped_to_capture(self) -> None:
        self.load()
        selected: list[SessionIdentity] = []
        ungrouped: list[tuple[str, tuple[int, ...]]] = []
        self.widget.session_open_requested.connect(selected.append)
        self.widget.ungrouped_open_requested.connect(lambda digest, frames: ungrouped.append((digest, frames)))
        self.widget.table.selectRow(0)
        self.click("sessionOpenPackets")
        self.click("sessionOpenUngroupedPackets")
        self.assertEqual(selected, [self.widget.selected_identity])
        self.assertEqual(ungrouped, [("a" * 64, (603,))])
        self.assertFalse(self.widget.select_session(SessionIdentity("b" * 64, selected[0].scope_sha256)))
        self.assertFalse(self.widget.select_session(SessionIdentity("invalid", "invalid")))

    def test_cancel_keeps_completed_evidence_with_ui_heartbeat(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        page = self.widget.page
        inspector = self.widget.inspector.toPlainText()
        entered = Event()
        released = Event()
        real_query = session_view.query_sessions
        heartbeats: list[int] = []
        timer = QTimer()
        timer.setInterval(1)
        timer.timeout.connect(lambda: heartbeats.append(1))

        def until_cancelled(index: SessionIndex, query: SessionQuery, selected: SessionIdentity | None, cancellation: Event) -> SessionPage:
            entered.set()
            while not released.wait(0.005):
                if cancellation.is_set():
                    raise SessionCancelled("Controlled query barrier cancelled")
            return real_query(index, query, selected, cancellation)

        session_view.query_sessions = until_cancelled
        try:
            timer.start()
            self.click("sessionApplyFilters")
            wait_until(entered.is_set, 5000)
            wait_until(lambda: len(heartbeats) >= 3, 5000)
            self.click("sessionCancelQuery")
            self.ready()
            self.assertIs(self.widget.page, page)
            self.assertEqual(self.widget.inspector.toPlainText(), inspector)
            self.assertIn("cancelled", self.widget.status_label.text())
        finally:
            timer.stop()
            released.set()
            session_view.query_sessions = real_query

    def test_latest_pending_query_wins_without_promoting_stale_result(self) -> None:
        self.load()
        entered = Event()
        released = Event()
        real_query = session_view.query_sessions
        calls: list[str] = []

        def delayed(index: SessionIndex, query: SessionQuery, selected: SessionIdentity | None, cancellation: Event) -> SessionPage:
            calls.append(query.search)
            if len(calls) == 1:
                entered.set()
                if not released.wait(3):
                    raise RuntimeError("Test barrier release deadline exceeded")
                return real_query(index, query, selected, Event())
            return real_query(index, query, selected, cancellation)

        session_view.query_sessions = delayed
        try:
            self.edit("sessionSearch", "process-1.test")
            self.click("sessionApplyFilters")
            wait_until(entered.is_set, 5000)
            self.edit("sessionSearch", "process-2.test")
            self.click("sessionApplyFilters")
            self.edit("sessionSearch", "process-3.test")
            self.click("sessionApplyFilters")
            released.set()
            self.ready()
            self.assertEqual(calls, ["process-1.test", "process-3.test"])
            self.assertEqual(self.widget.page.sessions[0].member_frames, (7, 8))
        finally:
            released.set()
            session_view.query_sessions = real_query

    def test_new_capture_denies_old_worker_result_and_return_context(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        snapshot = self.widget.capture_navigation()
        entered = Event()
        released = Event()
        real_query = session_view.query_sessions
        digests: list[str] = []

        def delayed(index: SessionIndex, query: SessionQuery, selected: SessionIdentity | None, cancellation: Event) -> SessionPage:
            if index.capture_sha256 == "a" * 64:
                entered.set()
                if not released.wait(3):
                    raise RuntimeError("Test barrier release deadline exceeded")
                return real_query(index, query, selected, Event())
            return real_query(index, query, selected, cancellation)

        self.widget.page_changed.connect(lambda: digests.append(self.widget.page.capture_sha256))
        session_view.query_sessions = delayed
        try:
            self.click("sessionApplyFilters")
            wait_until(entered.is_set, 5000)
            self.widget.set_report(fixture_report(2, "b" * 64))
            self.assertIsNone(self.widget.selected_identity)
            self.assertIsNone(self.widget.page)
            released.set()
            self.ready()
            self.assertEqual(digests, ["b" * 64])
            self.assertFalse(self.widget.restore_navigation(snapshot))
            self.assertNotIn("Capture SHA-256: " + "a" * 64, self.widget.inspector.toPlainText())
        finally:
            released.set()
            session_view.query_sessions = real_query

    def test_clear_report_and_shutdown_wait_for_owned_worker(self) -> None:
        self.load()
        entered = Event()
        real_query = session_view.query_sessions
        shutdown_signals: list[bool] = []

        def until_cancelled(index: SessionIndex, query: SessionQuery, selected: SessionIdentity | None, cancellation: Event) -> SessionPage:
            entered.set()
            if not cancellation.wait(3):
                raise RuntimeError("Test cancellation deadline exceeded")
            raise SessionCancelled("Shutdown cancels owned query")

        session_view.query_sessions = until_cancelled
        try:
            self.click("sessionApplyFilters")
            wait_until(entered.is_set, 5000)
            self.widget.clear_report()
            self.assertIsNone(self.widget.page)
            self.assertIsNone(self.widget.session_index)
            self.assertEqual(self.widget.model.rowCount(QModelIndex()), 0)
            self.widget.shutdown_complete.connect(lambda: shutdown_signals.append(True))
            self.assertFalse(self.widget.shutdown())
            self.ready()
            self.assertEqual(shutdown_signals, [True])
            self.assertTrue(self.widget.shutdown())
        finally:
            session_view.query_sessions = real_query

    def test_index_worker_cancels_without_a_gui_acknowledgement(self) -> None:
        request = session_view._JobRequest(1, None, self.report, "a" * 64, session_view.EMPTY_SESSION_QUERY, None, None, None, None)
        cancellation = Event()
        entered = Event()
        outcomes: list[object] = []
        worker = session_view._SessionQueryWorker(request, cancellation, self.widget)
        worker.checkpoint_requested.connect(lambda value: entered.set(), Qt.ConnectionType.DirectConnection)
        worker.completed.connect(outcomes.append, Qt.ConnectionType.DirectConnection)
        worker.start()
        try:
            self.assertTrue(entered.wait(3), "Indexing did not request a GUI acknowledgement")
            self.assertFalse(worker.continuation.is_set())
            cancellation.set()
            self.assertTrue(worker.wait(1000), "Cancellation depended on a GUI acknowledgement")
            self.assertEqual(len(outcomes), 1)
            outcome = outcomes[0]
            if not isinstance(outcome, session_view._JobOutcome):
                raise AssertionError("Indexing returned an invalid completion outcome")
            self.assertIsInstance(outcome.error, SessionCancelled)
            self.assertIsNone(outcome.index)
            self.assertIsNone(outcome.page)
        finally:
            cancellation.set()
            self.assertTrue(worker.wait(5000), "The owned indexing worker did not finish")
            worker.deleteLater()

    def test_index_worker_reports_an_unacknowledged_gui_deadline(self) -> None:
        request = session_view._JobRequest(1, None, self.report, "a" * 64, session_view.EMPTY_SESSION_QUERY, None, None, None, None)
        outcomes: list[object] = []
        cancellation = Event()
        worker = session_view._SessionQueryWorker(request, cancellation, self.widget)
        worker.completed.connect(outcomes.append, Qt.ConnectionType.DirectConnection)
        worker.start()
        try:
            wait_until(lambda: not worker.isRunning(), 10000)
            self.assertEqual(len(outcomes), 1)
            outcome = outcomes[0]
            if not isinstance(outcome, session_view._JobOutcome):
                raise AssertionError("Indexing returned an invalid completion outcome")
            self.assertIsInstance(outcome.error, session_view.SessionValidationError)
            self.assertIn("within five seconds", str(outcome.error))
            self.assertIsNone(outcome.index)
            self.assertIsNone(outcome.page)
        finally:
            cancellation.set()
            self.assertTrue(worker.wait(5000), "The owned indexing worker did not finish")
            worker.deleteLater()

    def test_legacy_reports_have_explicitly_unavailable_session_evidence(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        self.widget.set_report(replace(self.report, evidence=None, packets=()))
        self.assertIsNone(self.widget.page)
        self.assertIsNone(self.widget.session_index)
        self.assertIsNone(self.widget.selected_identity)
        self.assertIn("legacy report", self.widget.inspector.toPlainText())
        self.assertFalse(self.widget.apply_button.isEnabled())
        self.assertFalse(self.widget.open_button.isEnabled())
        self.assertFalse(self.widget.ungrouped_button.isEnabled())

    def test_invalid_worker_and_navigation_values_cannot_replace_completed_evidence(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        page = self.widget.page
        text = self.widget.inspector.toPlainText()
        self.widget._job_completed(object())
        self.assertIs(self.widget.page, page)
        self.assertEqual(self.widget.inspector.toPlainText(), text)
        self.assertIn("invalid result", self.widget.status_label.text())
        snapshot = self.widget.capture_navigation()
        self.assertIsNotNone(snapshot)
        self.assertFalse(self.widget.restore_navigation(replace(snapshot, report_generation=True)))
        self.assertFalse(self.widget.restore_navigation(replace(snapshot, vertical_scroll_value=True)))
        self.assertFalse(self.widget.restore_navigation(replace(snapshot, selected_identity=SessionIdentity("invalid", "invalid"))))
        self.assertFalse(self.widget.restore_navigation(replace(snapshot, query=replace(snapshot.query, page_number=True))))
        self.assertFalse(self.widget.restore_navigation(replace(snapshot, query=replace(snapshot.query, process_state="conflict"))))
        self.assertFalse(self.widget.restore_navigation(replace(snapshot, query=replace(snapshot.query, endpoint="not an address"))))
        self.assertIs(self.widget.page, page)
        self.assertEqual(self.widget.inspector.toPlainText(), text)

    def test_packet_return_action_is_explicitly_enabled_and_invalidated(self) -> None:
        self.load()
        requests: list[bool] = []
        self.widget.packet_return_requested.connect(lambda: requests.append(True))
        self.widget.return_to_packets()
        self.assertEqual(requests, [])
        self.widget.return_packets_button.setEnabled(True)
        self.click("sessionReturnToPackets")
        self.assertEqual(requests, [True])
        self.widget.clear_report()
        self.widget.return_to_packets()
        self.assertEqual(requests, [True])
        self.assertFalse(self.widget.return_packets_button.isEnabled())


if __name__ == "__main__":
    unittest.main()
