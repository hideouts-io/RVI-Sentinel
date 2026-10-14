"""Real Qt passive DNS pages, evidence navigation and owned worker boundaries."""

from __future__ import annotations

import os
import unittest
from dataclasses import replace
from threading import Event

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QModelIndex, QTimer, Qt
from PySide6.QtGui import QTextDocument
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLineEdit, QPushButton, QWidget

import dns_view
from captured_dns import CapturedDnsEvidence, CapturedDnsMessage, DnsQuestion, DnsResourceRecord
from dns_sessions import (
    DnsAssociationIdentity, DnsAssociationPage, DnsQuery, DnsSessionCancelled,
    DnsSessionIndex, build_dns_session_index, observed_dns_frames,
)
from dns_view import DnsSessionWidget, dns_inspector_text
from packet_models import PacketRecord, decode_packet_fields
from packet_sessions import SessionIdentity, build_session_index
from packet_timeline import PacketIdentity, build_packet_index
from tests.test_packet_view import wait_until


def fixture_packet(frame: int, stream: int, transport: str, address: str, reverse: bool, pid: int) -> PacketRecord:
    source, destination = "192.0.2.1", address
    source_port, destination_port = (53000 + stream, 53) if transport == "udp" else (54000 + stream, 443)
    if reverse:
        source, destination = destination, source
        source_port, destination_port = destination_port, source_port
    values: dict[str, tuple[str, ...]] = {
        "frame.number": (str(frame),), "frame.time_epoch": (f"1700000000.{frame:09d}",),
        "frame.len": ("64",), "frame.cap_len": ("64",), "frame.protocols": (f"ip:{transport}",),
        "_ws.col.protocol": (transport.upper(),), "ip.src": (source,), "ip.dst": (destination,),
        f"{transport}.srcport": (str(source_port),), f"{transport}.dstport": (str(destination_port),),
        f"{transport}.stream": (str(stream),), "frame.interface_name": ("fixture0",),
        "frame.darwin.process_info.pid": (str(pid),),
        "frame.darwin.process_info.pname": (("fixture-resolver" if pid == 343 else "fixture-client"),),
        "frame.darwin.process_info.epid": (str(pid + 100),),
        "frame.darwin.process_info.epname": (("effective-resolver" if pid == 343 else "effective-client"),),
    }
    return decode_packet_fields(values, tuple(values))


def fixture_index(count: int, digest: str) -> DnsSessionIndex:
    """Generate real typed questions, answers and scoped session packet records."""
    packets: list[PacketRecord] = []
    messages: list[CapturedDnsMessage] = []
    for stream in range(count):
        first = stream * 4 + 1
        address = f"198.51.{stream // 250}.{stream % 250 + 1}"
        name = "<b>literal<script>.test" if stream == 0 else f"service-{stream}.test"
        question = DnsQuestion(name, 1, 1)
        answers = (
            (DnsResourceRecord(name, 5, 1, 15, "alias.test"), DnsResourceRecord("alias.test", 1, 1, 30, address))
            if stream == 0 else (DnsResourceRecord(name, 1, 1, 30, address),)
        )
        packets.extend((
            fixture_packet(first, stream, "udp", "203.0.113.53", False, 343),
            fixture_packet(first + 1, stream, "udp", "203.0.113.53", True, 343),
            fixture_packet(first + 2, stream, "tcp", address, False, 344),
            fixture_packet(first + 3, stream, "tcp", address, True, 344),
        ))
        messages.extend((
            CapturedDnsMessage(first, 0, "dns", stream, False, False, 0, (question,), None, (), 0),
            CapturedDnsMessage(first + 1, 0, "dns", stream, True, False, 0, (question,), first, answers, 0),
        ))
    packet_index = build_packet_index(digest, tuple(packets), Event())
    session_index = build_session_index(packet_index, Event())
    return build_dns_session_index(session_index, CapturedDnsEvidence(digest, tuple(messages)), Event())


class DnsViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.application = QApplication.instance() or QApplication(["test_dns_view"])

    def setUp(self) -> None:
        self.parent = QWidget()
        self.widget = DnsSessionWidget(self.parent)
        self.widget.resize(1200, 800)
        self.widget.show()
        self.index = fixture_index(301, "a" * 64)

    def tearDown(self) -> None:
        self.widget.shutdown()
        wait_until(lambda: not self.widget.is_busy, 5000)
        self.parent.close()
        self.parent.deleteLater()
        self.application.processEvents()

    def load(self) -> None:
        self.widget.set_index(self.index)
        self.ready()
        self.assertIsNotNone(self.widget.page)

    def ready(self) -> None:
        wait_until(lambda: not self.widget.is_busy, 5000)

    def click(self, name: str) -> None:
        control = self.widget.findChild(QPushButton, name)
        self.assertIsNotNone(control, name)
        QTest.mouseClick(control, Qt.MouseButton.LeftButton)

    def edit(self, value: str) -> None:
        control = self.widget.findChild(QLineEdit, "dnsSearch")
        self.assertIsNotNone(control)
        control.setText(value)

    def test_bounded_pages_and_diagnostic_references_are_visible(self) -> None:
        self.load()
        self.assertEqual(self.widget.model.rowCount(QModelIndex()), 100)
        self.assertEqual(self.widget.page.total_count, 301)
        self.assertEqual(self.widget.page.page_count, 4)
        self.assertIn("602 recorded DNS messages", self.widget.status_label.text())
        self.assertIn("301 diagnostic observations", self.widget.diagnostics_label.text())
        self.assertIn("question_observation: 301", self.widget.diagnostics_label.toolTip())
        self.assertIn("Diagnostic reason counts: question_observation: 301", self.widget.inspector.toPlainText())
        self.assertIn("Frame 1; message index 0: question_observation", self.widget.inspector.toPlainText())
        self.click("dnsNextPage")
        self.ready()
        self.assertEqual(self.widget.page.page_number, 2)
        self.assertEqual(self.widget.model.associations[0].query_frame, 401)
        self.widget.page_size.setCurrentIndex(2)
        self.ready()
        self.assertEqual(self.widget.page.page_size, 500)
        self.assertEqual(self.widget.model.rowCount(QModelIndex()), 301)

    def test_plain_inspector_retains_original_evidence_when_search_hides_selection(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        identity = self.widget.selected_identity
        text = self.widget.inspector.toPlainText()
        self.assertIn("<b>literal<script>.test", text)
        model_index = self.widget.model.index(0, 0, QModelIndex())
        tooltip = self.widget.model.data(model_index, Qt.ItemDataRole.ToolTipRole)
        if not isinstance(tooltip, str):
            raise AssertionError("The selected DNS cell did not provide a typed tooltip.")
        rendered_tooltip = QTextDocument()
        rendered_tooltip.setHtml(tooltip)
        self.assertEqual(rendered_tooltip.toPlainText(), "<b>literal<script>.test")
        self.assertIn("Answer ordinal 1", text)
        self.assertIn("owner=alias.test; type=1; class=1; TTL=30; value=198.51.0.1", text)
        self.assertIn("Effective answer/CNAME TTL: 15 seconds", text)
        self.assertIn("1700000000.000000002", text)
        self.assertIn("1700000015.000000002", text)
        self.assertIn("Response packet/session process relation: different", text)
        self.assertIn("Query process state: recorded", text)
        self.assertIn("Query effective process state: recorded", text)
        self.assertIn("Response process state: recorded", text)
        self.assertIn("Response effective process state: recorded", text)
        self.assertIn("Source: apple_pcapng; PID: 343; name: fixture-resolver", text)
        self.assertIn("Source: apple_pcapng; PID: 443; name: effective-resolver", text)
        self.assertIn("Source: apple_pcapng; PID: 344; name: fixture-client", text)
        self.assertIn("Source: apple_pcapng; PID: 444; name: effective-client", text)
        self.assertIn("does not claim that every message byte", text)
        self.edit("SERVICE-1.TEST")
        self.click("dnsApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.matching_count, 1)
        self.assertEqual(self.widget.selected_identity, identity)
        self.assertEqual(self.widget.inspector.toPlainText(), text)
        self.assertIn("outside the current filter", self.widget.selection_notice.text())
        self.assertEqual(self.widget.table.selectionModel().selectedRows(), [])
        self.click("dnsClearFilters")
        self.ready()
        self.assertEqual(self.widget.table.selectionModel().selectedRows()[0].row(), 0)

    def test_literal_search_and_exact_session_filter_combine(self) -> None:
        self.load()
        association = self.index.associations[1]
        self.edit("SERVICE-1.TEST")
        self.assertTrue(self.widget.filter_for_session(association.session_identity))
        self.ready()
        self.assertEqual(self.widget.page.associations, (association,))
        self.assertIn(association.session_identity.scope_sha256, self.widget.scope_label.text())
        self.edit("service-2.test")
        self.click("dnsApplyFilters")
        self.ready()
        self.assertEqual(self.widget.page.matching_count, 0)
        self.click("dnsShowAllSessions")
        self.ready()
        self.assertEqual(self.widget.page.associations, (self.index.associations[2],))
        self.assertFalse(self.widget.filter_for_session(SessionIdentity("b" * 64, association.session_identity.scope_sha256)))
        self.assertFalse(self.widget.filter_for_session(SessionIdentity("invalid", "invalid")))
        self.assertFalse(self.widget.select_association(DnsAssociationIdentity("invalid", "invalid")))

    def test_navigation_actions_emit_exact_capture_bound_original_references(self) -> None:
        self.load()
        queries: list[PacketIdentity] = []
        responses: list[PacketIdentity] = []
        matches: list[DnsAssociationIdentity] = []
        sessions: list[SessionIdentity] = []
        observed: list[tuple[str, tuple[int, ...]]] = []
        returned: list[bool] = []
        self.widget.query_packet_requested.connect(queries.append)
        self.widget.response_packet_requested.connect(responses.append)
        self.widget.matched_packets_requested.connect(matches.append)
        self.widget.session_requested.connect(sessions.append)
        self.widget.observed_packets_requested.connect(lambda digest, frames: observed.append((digest, frames)))
        self.widget.return_session_requested.connect(lambda: returned.append(True))
        self.widget.table.selectRow(0)
        for name in ("dnsShowQueryPacket", "dnsShowResponsePacket", "dnsShowMatchedPackets", "dnsShowSession", "dnsShowObservedPackets"):
            self.click(name)
        association = self.index.associations[0]
        self.assertEqual(queries, [PacketIdentity("a" * 64, 1)])
        self.assertEqual(responses, [PacketIdentity("a" * 64, 2)])
        self.assertEqual(matches, [association.identity])
        self.assertEqual(sessions, [association.session_identity])
        self.assertEqual(observed, [("a" * 64, observed_dns_frames(self.index))])
        self.widget.return_to_session()
        self.assertEqual(returned, [])
        self.widget.return_session_button.setEnabled(True)
        self.click("dnsReturnToSession")
        self.assertEqual(returned, [True])
        self.widget.clear_index()
        self.widget.return_to_session()
        self.assertEqual(returned, [True])

    def test_snapshot_restores_search_page_selection_scroll_and_rejects_same_hash_reload(self) -> None:
        self.load()
        self.edit("service")
        self.click("dnsApplyFilters")
        self.ready()
        self.click("dnsNextPage")
        self.ready()
        self.widget.table.selectRow(50)
        self.widget.table.verticalScrollBar().setValue(25)
        snapshot = self.widget.capture_navigation()
        self.assertIsNotNone(snapshot)
        self.assertTrue(self.widget.select_association(self.index.associations[0].identity))
        self.ready()
        self.assertEqual(self.widget.page.page_number, 1)
        self.assertTrue(self.widget.restore_navigation(snapshot))
        self.ready()
        self.assertEqual(self.widget.page.page_number, 2)
        self.assertEqual(self.widget.search_field.text(), "service")
        self.assertEqual(self.widget.selected_identity, snapshot.selected_identity)
        self.assertEqual(self.widget.table.verticalScrollBar().value(), snapshot.vertical_scroll_value)
        page = self.widget.page
        text = self.widget.inspector.toPlainText()
        for invalid in (
            replace(snapshot, index_generation=True), replace(snapshot, vertical_scroll_value=True),
            replace(snapshot, vertical_scroll_value=2**31),
            replace(snapshot, query=replace(snapshot.query, page_number=True)),
            replace(snapshot, query=replace(snapshot.query, search="bad\nsearch")),
            replace(snapshot, selected_identity=DnsAssociationIdentity("invalid", "invalid")),
        ):
            self.assertFalse(self.widget.restore_navigation(invalid))
        self.assertIs(self.widget.page, page)
        self.assertEqual(self.widget.inspector.toPlainText(), text)
        self.widget.set_index(self.index)
        self.ready()
        self.assertFalse(self.widget.restore_navigation(snapshot))
        self.assertIsNone(self.widget.selected_identity)

    def test_invalid_filters_and_worker_values_preserve_completed_page(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        page = self.widget.page
        text = self.widget.inspector.toPlainText()
        self.edit("control\ncharacter")
        self.click("dnsApplyFilters")
        self.ready()
        self.assertIs(self.widget.page, page)
        self.assertIn("Invalid DNS filter", self.widget.status_label.text())
        self.widget._job_completed(object())
        self.assertIs(self.widget.page, page)
        self.assertEqual(self.widget.inspector.toPlainText(), text)
        self.assertIn("invalid result", self.widget.status_label.text())
        snapshot = self.widget.capture_navigation()
        for invalid_page in (
            replace(page, matching_count=True), replace(page, page_count=999),
            replace(page, associations=page.associations + (page.associations[0],)),
            replace(page, selected_match_page=True),
        ):
            self.widget._job_completed(dns_view._JobOutcome(self.widget._generation, invalid_page, snapshot.query, None, None))
            self.assertIs(self.widget.page, page)
            self.assertEqual(self.widget.inspector.toPlainText(), text)

    def test_cancel_retains_completed_selection_while_qt_heartbeat_runs(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        page = self.widget.page
        text = self.widget.inspector.toPlainText()
        entered = Event()
        released = Event()
        original = dns_view.query_dns_associations
        heartbeats: list[int] = []
        timer = QTimer()
        timer.setInterval(1)
        timer.timeout.connect(lambda: heartbeats.append(1))

        def barrier(index: DnsSessionIndex, query: DnsQuery, selected: DnsAssociationIdentity | None, cancellation: Event) -> DnsAssociationPage:
            entered.set()
            while not released.wait(0.005):
                if cancellation.is_set():
                    raise DnsSessionCancelled("Controlled query barrier cancelled")
            return original(index, query, selected, cancellation)

        dns_view.query_dns_associations = barrier
        try:
            timer.start()
            self.click("dnsApplyFilters")
            wait_until(entered.is_set, 5000)
            wait_until(lambda: len(heartbeats) >= 3, 5000)
            self.click("dnsCancelQuery")
            self.ready()
            self.assertIs(self.widget.page, page)
            self.assertEqual(self.widget.inspector.toPlainText(), text)
            self.assertIn("cancelled", self.widget.status_label.text())
        finally:
            timer.stop()
            released.set()
            dns_view.query_dns_associations = original

    def test_latest_pending_request_wins_and_old_capture_cannot_promote(self) -> None:
        self.load()
        entered = Event()
        released = Event()
        original = dns_view.query_dns_associations
        calls: list[str] = []

        def barrier(index: DnsSessionIndex, query: DnsQuery, selected: DnsAssociationIdentity | None, cancellation: Event) -> DnsAssociationPage:
            calls.append(query.search)
            if len(calls) == 1:
                entered.set()
                if not released.wait(3):
                    raise RuntimeError("Test barrier release deadline exceeded")
                return original(index, query, selected, Event())
            return original(index, query, selected, cancellation)

        dns_view.query_dns_associations = barrier
        try:
            self.edit("service-1.test")
            self.click("dnsApplyFilters")
            wait_until(entered.is_set, 5000)
            self.edit("service-2.test")
            self.click("dnsApplyFilters")
            self.edit("service-3.test")
            self.click("dnsApplyFilters")
            released.set()
            self.ready()
            self.assertEqual(calls, ["service-1.test", "service-3.test"])
            self.assertEqual(self.widget.page.associations, (self.index.associations[3],))
        finally:
            released.set()
            dns_view.query_dns_associations = original
        snapshot = self.widget.capture_navigation()
        self.widget.set_index(fixture_index(2, "b" * 64))
        self.ready()
        self.assertEqual(self.widget.page.capture_sha256, "b" * 64)
        self.assertIsNone(self.widget.selected_identity)
        self.assertFalse(self.widget.restore_navigation(snapshot))

    def test_clear_and_shutdown_cancel_owned_worker_before_releasing_qt_parent(self) -> None:
        self.load()
        entered = Event()
        original = dns_view.query_dns_associations
        completed: list[bool] = []

        def barrier(index: DnsSessionIndex, query: DnsQuery, selected: DnsAssociationIdentity | None, cancellation: Event) -> DnsAssociationPage:
            entered.set()
            if not cancellation.wait(3):
                raise RuntimeError("Test cancellation deadline exceeded")
            raise DnsSessionCancelled("Controlled shutdown query cancelled")

        dns_view.query_dns_associations = barrier
        try:
            self.click("dnsApplyFilters")
            wait_until(entered.is_set, 5000)
            self.widget.clear_index()
            self.assertIsNone(self.widget.page)
            self.assertIsNone(self.widget.dns_index)
            self.assertEqual(self.widget.model.rowCount(QModelIndex()), 0)
            self.widget.shutdown_complete.connect(lambda: completed.append(True))
            self.assertFalse(self.widget.shutdown())
            self.ready()
            self.assertEqual(completed, [True])
            self.assertTrue(self.widget.shutdown())
        finally:
            dns_view.query_dns_associations = original

    def test_report_replacement_denies_a_completed_old_capture_worker_result(self) -> None:
        self.load()
        self.widget.table.selectRow(0)
        snapshot = self.widget.capture_navigation()
        entered = Event()
        released = Event()
        original = dns_view.query_dns_associations
        promoted: list[str] = []

        def barrier(index: DnsSessionIndex, query: DnsQuery, selected: DnsAssociationIdentity | None, cancellation: Event) -> DnsAssociationPage:
            if index.capture_sha256 == "a" * 64:
                entered.set()
                if not released.wait(3):
                    raise RuntimeError("Test barrier release deadline exceeded")
                return original(index, query, selected, Event())
            return original(index, query, selected, cancellation)

        self.widget.page_changed.connect(lambda: promoted.append(self.widget.page.capture_sha256))
        dns_view.query_dns_associations = barrier
        try:
            self.click("dnsApplyFilters")
            wait_until(entered.is_set, 5000)
            self.widget.set_index(fixture_index(2, "b" * 64))
            self.assertIsNone(self.widget.page)
            self.assertIsNone(self.widget.selected_identity)
            released.set()
            self.ready()
            self.assertEqual(promoted, ["b" * 64])
            self.assertFalse(self.widget.restore_navigation(snapshot))
            self.assertNotIn("Capture SHA-256: " + "a" * 64, self.widget.inspector.toPlainText())
        finally:
            released.set()
            dns_view.query_dns_associations = original

    def test_inspector_refuses_an_oversized_whole_member_reference_view(self) -> None:
        association = replace(self.index.associations[0], matching_frames=tuple(range(1, 200_001)))
        text = dns_inspector_text(self.index, association)
        self.assertIn("Inspector rendering limit exceeded", text)
        self.assertIn("No partial candidate is presented", text)
        self.assertLess(len(text.encode("utf-8")), 1024)

    def test_response_process_difference_is_traceable_even_with_unknown_effective_metadata(self) -> None:
        original = fixture_index(1, "a" * 64)
        query_values = {field.name: field.values for field in original.session_index.packet_index.packets[0].fields}
        query_values.update({
            "frame.darwin.process_info.pid": ("344",), "frame.darwin.process_info.pname": ("query-client",),
            "frame.darwin.process_info.epid": ("444",), "frame.darwin.process_info.epname": ("query-effective-client",),
        })
        response_values = {field.name: field.values for field in original.session_index.packet_index.packets[1].fields}
        response_values.pop("frame.darwin.process_info.epid")
        response_values.pop("frame.darwin.process_info.epname")
        packets = (
            decode_packet_fields(query_values, tuple(query_values)),
            decode_packet_fields(response_values, tuple(response_values)),
        ) + original.session_index.packet_index.packets[2:]
        sessions = build_session_index(build_packet_index("a" * 64, packets, Event()), Event())
        index = build_dns_session_index(sessions, original.dns_evidence, Event())
        self.assertEqual(index.associations[0].process_relation, "different")
        self.widget.set_index(index)
        self.ready()
        self.widget.table.selectRow(0)
        text = self.widget.inspector.toPlainText()
        query_context = text.split("Recorded DNS query client context", 1)[1].split("Recorded DNS response context", 1)[0]
        response_context = text.split("Recorded DNS response context", 1)[1].split("Correlated session scope", 1)[0]
        self.assertIn("Source: apple_pcapng; PID: 344; name: query-client", query_context)
        self.assertIn("Source: apple_pcapng; PID: 444; name: query-effective-client", query_context)
        self.assertIn("Source: apple_pcapng; PID: 343; name: fixture-resolver", response_context)
        self.assertIn("Response effective process state: unknown", response_context)
        self.assertIn("Response packet/session process relation: different", text)

    def test_superseding_response_source_navigation_and_original_ttl_remain_explicit(self) -> None:
        original = fixture_index(1, "a" * 64)
        question = original.dns_evidence.messages[0].questions
        messages = original.dns_evidence.messages + (
            CapturedDnsMessage(5, 0, "dns", 4321, False, False, 0, question, None, (), 0),
            CapturedDnsMessage(6, 0, "dns", 4321, True, False, 3, question, 5, (), 0),
        )
        packets = original.session_index.packet_index.packets + (
            fixture_packet(5, 0, "udp", "203.0.113.53", False, 343),
            fixture_packet(6, 0, "udp", "203.0.113.53", True, 343),
        )
        sessions = build_session_index(build_packet_index("a" * 64, packets, Event()), Event())
        index = build_dns_session_index(sessions, CapturedDnsEvidence("a" * 64, messages), Event())
        association = index.associations[0]
        self.assertEqual(association.superseded_by_frame, 6)
        self.assertEqual(association.matching_frames, (3, 4))
        self.widget.set_index(index)
        self.ready()
        self.widget.table.selectRow(0)
        text = self.widget.inspector.toPlainText()
        self.assertIn("Original TTL expiry epoch: 1700000015.000000002", text)
        self.assertIn("Effective expiry epoch: 1700000000.000000006", text)
        self.assertIn("Superseding decoder frame: 6", text)
        self.assertIn("Superseding DNS message index: 0", text)
        self.assertIn("Superseding structured response evidence", text)
        sources: list[PacketIdentity] = []
        self.widget.superseding_packet_requested.connect(sources.append)
        self.assertTrue(self.widget.superseding_button.isEnabled())
        self.click("dnsShowSupersedingPacket")
        self.assertEqual(sources, [PacketIdentity("a" * 64, 6)])
        self.widget.set_index(original)
        self.ready()
        self.widget.table.selectRow(0)
        self.assertFalse(self.widget.superseding_button.isEnabled())
        self.widget.show_superseding_packet()
        self.assertEqual(sources, [PacketIdentity("a" * 64, 6)])


if __name__ == "__main__":
    unittest.main()
