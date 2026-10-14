"""Real Qt widget behavior and owned-worker lifecycle checks using synthetic records."""

from __future__ import annotations

import os
import unittest
from dataclasses import replace
from threading import Event
from typing import Callable

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QModelIndex, QTimer, Qt
from PySide6.QtGui import QTextDocument
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLineEdit, QPushButton, QWidget

import packet_view
from gui_models import AnalysisEvidence, AnalysisReport, AnalysisSummary, CaptureDetails
from packet_models import PacketRecord, decode_packet_fields, packet_document, validate_packet_document
from packet_timeline import PacketIdentity, PacketIndex, PacketPage, PacketQuery, PacketQueryCancelled
from packet_view import CELL_MAX_BYTES, INSPECTOR_MAX_BYTES, PacketTimelineWidget, packet_cell, packet_inspector_text


def wait_until(condition: Callable[[], bool], timeout_milliseconds: int) -> None:
    """Yield Qt events until a specific assertion condition or an explicit deadline."""
    if condition():
        return
    loop = QEventLoop()
    poll = QTimer()
    deadline = QTimer()
    deadline.setSingleShot(True)
    poll.setInterval(5)
    poll.timeout.connect(lambda: loop.quit() if condition() else None)
    deadline.timeout.connect(loop.quit)
    poll.start()
    deadline.start(timeout_milliseconds)
    loop.exec()
    poll.stop()
    deadline.stop()
    if not condition():
        raise AssertionError(f"Qt condition not reached within {timeout_milliseconds} milliseconds")


def fixture_record(frame: int) -> PacketRecord:
    values: dict[str, tuple[str, ...]] = {
        "frame.number": (str(frame),), "frame.time_epoch": (f"1700000000.{frame:09d}",),
        "frame.len": ("64",), "frame.cap_len": ("64",), "frame.protocols": ("ip:tcp",),
        "_ws.col.protocol": ("TCP",), "ip.src": ("192.0.2.1",), "ip.dst": ("198.51.100.2",),
        "tcp.srcport": ("51000",), "tcp.dstport": ("443",), "tcp.stream": ("0",),
        "dns.qry.name": (("<b>literal<script>.test", "second.test") if frame == 1 else (f"frame-{frame}.test",)),
    }
    return decode_packet_fields(values, tuple(values))


def fixture_report(count: int, digest: str) -> AnalysisReport:
    packets = tuple(fixture_record(frame) for frame in range(1, count + 1))
    supported = tuple(field.name for field in packets[0].fields) + ("tls.handshake.extensions_server_name",)
    evidence = AnalysisEvidence(digest, "synthetic test decoder", len(supported), supported, ("pktap.ifname",), count, "imported_unknown", "verified")
    return AnalysisReport(
        CaptureDetails("synthetic.pcap", count * 64, count, None, None, None),
        AnalysisSummary(2, count + 1, 0, 0, frozenset(), frozenset(), frozenset()),
        (), (), (), (), (), (), evidence, packets, None,
    )


class PacketViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication(["test_packet_view"])

    def setUp(self) -> None:
        self.parent = QWidget()
        self.widget = PacketTimelineWidget(self.parent)
        self.widget.resize(1100, 800)
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

    def click(self, object_name: str) -> None:
        control = self.widget.findChild(QPushButton, object_name)
        self.assertIsNotNone(control, object_name)
        QTest.mouseClick(control, Qt.MouseButton.LeftButton)

    def edit(self, object_name: str, value: str) -> None:
        control = self.widget.findChild(QLineEdit, object_name)
        self.assertIsNotNone(control, object_name)
        control.setText(value)

    def ready(self) -> None:
        wait_until(lambda: not self.widget.is_busy, 5000)

    def test_bounded_pages_and_exact_identity(self) -> None:
        self.load()
        self.assertEqual(self.widget.model.rowCount(QModelIndex()), 100)
        self.assertEqual(self.widget.page.matching_count, 301)
        self.assertEqual(self.widget.page.page_count, 4)
        self.click("packetNextPage")
        self.ready()
        self.assertEqual(self.widget.page.page_number, 2)
        self.assertEqual(self.widget.model.packets[0].frame_number, 101)
        self.widget.page_size.setCurrentIndex(2)
        self.ready()
        self.assertEqual(self.widget.model.rowCount(QModelIndex()), 301)
        self.assertEqual(self.widget.page.page_size, 500)

    def test_scoped_members_restore_original_filters_page_and_inspector(self) -> None:
        self.load()
        self.edit("packetProtocolFilter", "tcp")
        self.click("packetApplyFilters")
        self.ready()
        self.click("packetNextPage")
        self.ready()
        self.widget.table.selectRow(20)
        self.widget.table.verticalScrollBar().setValue(40)
        original = self.widget.capture_navigation()
        inspector = self.widget.inspector.toPlainText()
        self.assertIsNotNone(original)
        self.widget.set_packet_scope("a" * 64, (122, 121), "Session TCP stream 0: 2 packets")
        self.ready()
        self.assertEqual(tuple(packet.frame_number for packet in self.widget.page.packets), (121, 122))
        self.assertEqual(self.widget.page.total_count, 2)
        self.assertEqual(self.widget.selected_identity.frame_number, 121)
        self.assertIs(self.widget.model.packets[0], self.report.packets[120])
        self.assertFalse(self.widget.select_packet(PacketIdentity("a" * 64, 123)))
        self.assertTrue(self.widget.restore_navigation(original))
        self.ready()
        self.assertEqual(self.widget.capture_navigation(), original)
        self.assertEqual(self.widget.inspector.toPlainText(), inspector)
        self.assertEqual(self.widget.page.total_count, 301)

    def test_invalid_navigation_rejected_before_completed_evidence_changes(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        original = self.widget.capture_navigation()
        self.assertIsNotNone(original)
        if original is None or original.query is None:
            raise AssertionError("The completed view must provide a navigation snapshot.")
        inspector = self.widget.inspector.toPlainText()
        invalid = (
            replace(original, report_generation=True),
            replace(original, vertical_scroll_value=True),
            replace(original, vertical_scroll_value=-1),
            replace(original, vertical_scroll_value=2**31),
            replace(original, query=replace(original.query, page_size=7)),
            replace(original, query=replace(original.query, endpoint="bad ip")),
            replace(original, query=replace(original.query, process_state="invalid")),
            replace(original, scope_frames=(True,)),
            replace(original, scope_frames=(1, 1)),
            replace(original, scope_frames=(302,)),
            replace(original, scope_frames=(2,)),
            replace(original, scope_label="bad\nlabel"),
            replace(original, selected_identity=PacketIdentity("b" * 64, 1)),
            replace(original, selected_identity=PacketIdentity("a" * 64, True)),
        )
        for navigation in invalid:
            with self.subTest(navigation=navigation):
                self.assertFalse(self.widget.restore_navigation(navigation))
                self.assertEqual(self.widget.capture_navigation(), original)
                self.assertEqual(self.widget.inspector.toPlainText(), inspector)
                self.assertFalse(self.widget.is_busy)

    def test_cancelled_scope_and_same_digest_reload_never_relabel_old_page(self) -> None:
        self.load()
        original = self.widget.capture_navigation()
        self.widget.set_packet_scope("a" * 64, (1, 2), "Session TCP stream 0: 2 packets")
        self.widget.cancel_query()
        self.ready()
        self.assertIsNone(self.widget.page)
        self.assertIn("No completed page", self.widget.status_label.text())
        self.click("packetApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.total_count, 2)
        self.widget.set_report(self.report)
        self.widget.cancel_query()
        self.ready()
        self.assertIsNone(self.widget.page)
        self.assertIsNone(self.widget.selected_identity)
        self.assertEqual(self.widget.scope_label.text(), "All packets in this capture")
        self.assertFalse(self.widget.restore_navigation(original))
        self.click("packetApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.total_count, 301)

    def test_literal_inspector_selection_survives_filter_hide_restore(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        self.assertEqual(self.widget.selected_identity.frame_number, 1)

        original = self.widget.inspector.toPlainText()
        self.assertIn("<b>literal<script>.test", original)
        self.assertIn("[2] second.test", original)
        self.assertIn("1700000000.000000001", original)
        self.assertIn(".000000001Z", original)
        self.assertIn("Capture SHA-256: " + "a" * 64, original)
        self.assertIn("Supported but absent on this packet", original)
        self.assertIn("tls.handshake.extensions_server_name", original)
        self.assertIn("Unsupported decoder fields (1): pktap.ifname", original)
        self.edit("packetSearch", "frame-2.test")
        self.click("packetApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.matching_count, 1)
        self.assertIn("outside the current filter", self.widget.selection_notice.text())
        self.assertEqual(self.widget.inspector.toPlainText(), original)
        self.assertEqual(self.widget.table.selectionModel().selectedRows(), [])
        self.click("packetClearFilters")
        self.ready()
        self.assertEqual(self.widget.table.selectionModel().selectedRows()[0].row(), 0)
        self.assertEqual(self.widget.selected_identity.frame_number, 1)

    def test_recorded_process_tooltip_renders_literal_markup_and_whitespace(self) -> None:
        values = {field.name: field.values for field in fixture_record(1).fields}
        value = '  <b>literal<img src="file:///not-a-real-file"> &  name'
        values["frame.darwin.process_info.pname"] = (value,)
        values["frame.darwin.process_info.pid"] = ("7",)
        packet = decode_packet_fields(values, tuple(values))
        self.widget.model.set_packets((packet,))
        index = self.widget.model.index(0, 5)
        display = self.widget.model.data(index, Qt.ItemDataRole.DisplayRole)
        tooltip = self.widget.model.data(index, Qt.ItemDataRole.ToolTipRole)
        if not isinstance(display, str) or not isinstance(tooltip, str):
            raise AssertionError("The recorded process cell must expose display and tooltip evidence.")
        self.assertIn(value, display)
        document = QTextDocument()
        document.setHtml(tooltip)
        self.assertEqual(document.toPlainText(), display)

    def test_large_valid_record_refuses_inspector_without_silent_truncation(self) -> None:
        values = {field.name: field.values for field in self.report.packets[0].fields}
        occurrences = tuple(f"{position:03d}" + "x" * 1021 for position in range(128))
        for name in ("dns.qry.name", "dns.resp.name", "dns.cname", "http.host", "tls.handshake.extensions_server_name"):
            values[name] = occurrences
        values["frame.darwin.process_info.pname"] = tuple(f"{position:03d}" + "p" * 253 for position in range(128))
        record = decode_packet_fields(values, tuple(values))
        self.assertEqual(validate_packet_document(packet_document(record)), record)
        report = replace(self.report, packets=(record,), evidence=replace(self.report.evidence, supported_fields=tuple(values), supported_field_count=len(values), packet_record_count=1))
        self.widget.set_report(report)
        self.ready()
        self.widget.table.selectRow(0)
        text = self.widget.inspector.toPlainText()
        self.assertLess(len(text.encode("utf-8")), INSPECTOR_MAX_BYTES)
        self.assertIn("Inspector rendering limit exceeded", text)
        self.assertIn("Capture SHA-256: " + "a" * 64, text)
        self.assertIn("frame:1", text)
        self.assertIn("No partial record is presented", text)
        self.assertIn("All original decoded fields remain unchanged", text)
        self.assertIn("exceeds 512 KiB", self.widget.selection_notice.text())
        cell = packet_cell(record, 5)
        self.assertLess(len(cell.encode("utf-8")), CELL_MAX_BYTES)
        self.assertIn("128 recorded labels", cell)
        self.assertIn("8 KiB cell limit", cell)
        self.assertEqual(self.widget.report.packets[0].fields, record.fields)

        prefix = "Ungrouped packet: missing_stream. Passive DNS <b>literal<script>.test & session evidence: "
        context = prefix + "c" * (4096 - len(prefix) - len(" END OF CONTEXT")) + " END OF CONTEXT"
        self.widget.set_correlation_context(context)
        contextual_text = self.widget.inspector.toPlainText()
        self.assertLess(len(contextual_text.encode("utf-8")), INSPECTOR_MAX_BYTES)
        self.assertIn("Inspector rendering limit exceeded", contextual_text)
        self.assertIn("Capture SHA-256: " + "a" * 64, contextual_text)
        self.assertIn("frame:1", contextual_text)
        self.assertIn("Exact recorded epoch: " + record.timestamp.epoch, contextual_text)
        self.assertIn("No partial record is presented", contextual_text)
        self.assertIn("Session correlation\n" + context, contextual_text)
        self.assertNotIn(occurrences[-1], contextual_text)
        self.assertEqual(self.widget.report.packets[0].fields, record.fields)

    def test_complete_record_is_refused_when_correlation_pushes_inspector_over_limit(self) -> None:
        values = {field.name: field.values for field in self.report.packets[0].fields}
        occurrences = tuple(f"{position:03d}" + "x" * 1006 for position in range(128))
        for name in ("dns.qry.name", "dns.resp.name", "dns.cname", "http.host"):
            values[name] = occurrences
        record = decode_packet_fields(values, tuple(values))
        self.assertEqual(validate_packet_document(packet_document(record)), record)
        evidence = self.report.evidence
        if evidence is None:
            raise AssertionError("The synthetic packet report must have capture-bound evidence.")
        report = replace(self.report, packets=(record,), evidence=replace(evidence,
            supported_fields=tuple(values), supported_field_count=len(values), packet_record_count=1))
        raw_text = packet_inspector_text(report, record)
        self.assertLess(len(raw_text.encode("utf-8")), INSPECTOR_MAX_BYTES)
        self.assertNotIn("Inspector rendering limit exceeded", raw_text)
        self.assertIn(occurrences[-1], raw_text)
        self.widget.set_report(report)
        self.ready()
        self.widget.table.selectRow(0)
        short_context = "Scoped TCP stream 0; passive DNS candidate remains uncertain."
        self.widget.set_correlation_context(short_context)
        self.assertEqual(self.widget.inspector.toPlainText(), raw_text + "\n\nSession correlation\n" + short_context)

        prefix = "Scoped TCP stream 0; literal DNS <b>near-limit.test & candidate evidence: "
        context = prefix + "c" * (2000 - len(prefix) - len(" END OF CONTEXT")) + " END OF CONTEXT"
        self.assertGreater(len((raw_text + "\n\nSession correlation\n" + context).encode("utf-8")), INSPECTOR_MAX_BYTES)
        self.widget.set_correlation_context(context)
        text = self.widget.inspector.toPlainText()
        self.assertLess(len(text.encode("utf-8")), INSPECTOR_MAX_BYTES)
        self.assertIn("Inspector rendering limit exceeded", text)
        self.assertIn("Capture SHA-256: " + "a" * 64, text)
        self.assertIn("frame:1", text)
        self.assertIn("Exact recorded epoch: " + record.timestamp.epoch, text)
        self.assertIn("No partial record is presented", text)
        self.assertIn("All original decoded fields remain unchanged", text)
        self.assertIn("Session correlation\n" + context, text)
        self.assertNotIn(occurrences[-1], text)
        self.assertEqual(self.widget.report.packets[0].fields, record.fields)
        self.widget.set_correlation_context(short_context)
        self.assertEqual(self.widget.inspector.toPlainText(), raw_text + "\n\nSession correlation\n" + short_context)

    def test_selection_restores_matching_page_and_navigation_does_not_jump_back(self) -> None:
        self.load()
        self.click("packetNextPage")
        self.ready()
        self.widget.table.selectRow(50)
        self.assertEqual(self.widget.selected_identity.frame_number, 151)
        self.edit("packetProtocolFilter", "tcp")
        self.click("packetApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.page_number, 2)
        self.assertEqual(self.widget.table.selectionModel().selectedRows()[0].row(), 50)
        self.click("packetNextPage")
        self.ready()
        self.assertEqual(self.widget.page.page_number, 3)
        self.assertIn("outside the visible page", self.widget.selection_notice.text())

    def test_invalid_filter_keeps_completed_evidence_and_negative_match_count(self) -> None:
        self.load()
        page = self.widget.page
        self.edit("packetPortFilter", "not-a-port")
        self.click("packetApplyFilters")
        self.assertIs(self.widget.page, page)
        self.assertIn("Invalid packet filter", self.widget.status_label.text())
        self.edit("packetPortFilter", "53")
        self.click("packetApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.matching_count, 0)
        self.assertEqual(self.widget.page.page_count, 0)
        self.assertEqual(self.widget.model.rowCount(QModelIndex()), 0)

    def test_report_replacement_and_legacy_invalidate_selection(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        replacement = fixture_report(2, "b" * 64)
        self.widget.set_report(replacement)
        self.assertIsNone(self.widget.selected_identity)
        self.assertNotIn("Capture SHA-256: " + "a" * 64, self.widget.inspector.toPlainText())
        self.ready()
        self.assertEqual(self.widget.page.capture_sha256, "b" * 64)
        self.widget.set_report(replace(replacement, evidence=None, packets=()))
        self.assertIsNone(self.widget.page)
        self.assertIn("legacy report", self.widget.inspector.toPlainText())
        self.assertFalse(self.widget.apply_button.isEnabled())

    def test_cancel_preserves_completed_page_and_inspector_with_live_ui_heartbeat(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        page = self.widget.page
        inspector = self.widget.inspector.toPlainText()
        entered = Event()
        released = Event()
        real_query = packet_view.query_packets
        heartbeats: list[int] = []
        timer = QTimer()
        timer.setInterval(1)
        timer.timeout.connect(lambda: heartbeats.append(1))

        def blocked_query(index: PacketIndex, query: PacketQuery, selected: PacketIdentity | None, cancellation: Event) -> PacketPage:
            entered.set()
            while not released.wait(0.005):
                if cancellation.is_set():
                    raise PacketQueryCancelled("Controlled query barrier cancelled")
            return real_query(index, query, selected, cancellation)

        packet_view.query_packets = blocked_query
        try:
            timer.start()
            self.edit("packetSearch", "frame")
            self.click("packetApplyFilters")
            wait_until(entered.is_set, 5000)
            wait_until(lambda: len(heartbeats) >= 3, 5000)
            self.click("packetCancelQuery")
            self.ready()
            self.assertIs(self.widget.page, page)
            self.assertEqual(self.widget.inspector.toPlainText(), inspector)
            self.assertEqual(self.widget.selected_identity.frame_number, 1)
            self.assertIn("cancelled", self.widget.status_label.text())
        finally:
            timer.stop()
            released.set()
            packet_view.query_packets = real_query

    def test_latest_pending_query_wins_and_stale_results_cannot_restore_old_capture(self) -> None:
        self.load()
        entered = Event()
        released = Event()
        calls: list[str] = []
        real_query = packet_view.query_packets

        def delayed_query(index: PacketIndex, query: PacketQuery, selected: PacketIdentity | None, cancellation: Event) -> PacketPage:
            calls.append(query.search)
            if len(calls) == 1:
                entered.set()
                if not released.wait(3):
                    raise RuntimeError("Test barrier release deadline exceeded")
                # Deliberately complete stale data after replacement, testing generation denial.
                return real_query(index, query, selected, Event())
            return real_query(index, query, selected, cancellation)

        packet_view.query_packets = delayed_query
        try:
            self.edit("packetSearch", "frame-2.test")
            self.click("packetApplyFilters")
            wait_until(entered.is_set, 5000)
            self.edit("packetSearch", "frame-3.test")
            self.click("packetApplyFilters")
            self.edit("packetSearch", "frame-4.test")
            self.click("packetApplyFilters")
            released.set()
            self.ready()
            self.assertEqual(calls, ["frame-2.test", "frame-4.test"])
            self.assertEqual(tuple(packet.frame_number for packet in self.widget.page.packets), (4,))
        finally:
            released.set()
            packet_view.query_packets = real_query

    def test_old_capture_result_is_denied_after_report_replacement(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        entered = Event()
        released = Event()
        real_query = packet_view.query_packets
        delivered_digests: list[str] = []

        def delayed_old_query(index: PacketIndex, query: PacketQuery, selected: PacketIdentity | None, cancellation: Event) -> PacketPage:
            if index.capture_sha256 == "a" * 64:
                entered.set()
                if not released.wait(3):
                    raise RuntimeError("Test barrier release deadline exceeded")
                return real_query(index, query, selected, Event())
            return real_query(index, query, selected, cancellation)

        def record_page() -> None:
            if self.widget.page is not None:
                delivered_digests.append(self.widget.page.capture_sha256)

        packet_view.query_packets = delayed_old_query
        self.widget.page_changed.connect(record_page)
        try:
            self.click("packetApplyFilters")
            wait_until(entered.is_set, 5000)
            self.widget.set_report(fixture_report(2, "b" * 64))
            self.assertIsNone(self.widget.selected_identity)
            self.assertIsNone(self.widget.page)
            released.set()
            self.ready()
            self.assertEqual(delivered_digests, ["b" * 64])
            self.assertEqual(self.widget.page.capture_sha256, "b" * 64)
            self.assertNotIn("Capture SHA-256: " + "a" * 64, self.widget.inspector.toPlainText())
        finally:
            released.set()
            packet_view.query_packets = real_query

    def test_clear_report_cancels_running_worker_without_stale_promotion(self) -> None:
        self.load()
        entered = Event()
        real_query = packet_view.query_packets

        def until_cancelled(index: PacketIndex, query: PacketQuery, selected: PacketIdentity | None, cancellation: Event) -> PacketPage:
            entered.set()
            if not cancellation.wait(3):
                raise RuntimeError("Test cancellation deadline exceeded")
            raise PacketQueryCancelled("Cleared report cancels owned query")

        packet_view.query_packets = until_cancelled
        try:
            self.click("packetApplyFilters")
            wait_until(entered.is_set, 5000)
            self.widget.clear_report()
            self.ready()
            self.assertIsNone(self.widget.page)
            self.assertIsNone(self.widget.selected_identity)
            self.assertEqual(self.widget.model.rowCount(QModelIndex()), 0)
            self.assertIn("Analyze a saved capture", self.widget.status_label.text())
        finally:
            packet_view.query_packets = real_query

    def test_shutdown_waits_for_owned_worker_completion(self) -> None:
        self.load()
        entered = Event()
        shutdown_signals: list[bool] = []
        real_query = packet_view.query_packets

        def until_cancelled(index: PacketIndex, query: PacketQuery, selected: PacketIdentity | None, cancellation: Event) -> PacketPage:
            entered.set()
            if not cancellation.wait(3):
                raise RuntimeError("Test cancellation deadline exceeded")
            raise PacketQueryCancelled("Shutdown cancels owned query")

        packet_view.query_packets = until_cancelled
        try:
            self.widget.shutdown_complete.connect(lambda: shutdown_signals.append(True))
            self.click("packetApplyFilters")
            wait_until(entered.is_set, 5000)
            self.assertFalse(self.widget.shutdown())
            self.ready()
            self.assertEqual(shutdown_signals, [True])
            self.assertTrue(self.widget.shutdown())
        finally:
            packet_view.query_packets = real_query


if __name__ == "__main__":
    unittest.main()
