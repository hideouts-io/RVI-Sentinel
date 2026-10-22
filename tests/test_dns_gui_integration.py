"""Real saved DNS reports and Qt navigation through original scoped evidence."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Literal
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QLineEdit, QPushButton

from analyze import analyze, load_baseline, write_report
from captured_dns import CapturedDnsMessage
from gui import RviSentinelWindow
from gui_models import AnalysisReport, load_report
from packet_timeline import PacketIdentity
from tests.dns_fixture import address_record, dns_capture
from tests.session_fixture import session_capture
from tests.test_packet_gui_integration import child, wait_until
from tests.test_dns_sessions import replacement_capture


def relative_luminance(color: QColor) -> float:
    """Measure the effective widget palette rather than matching theme strings."""
    channels = tuple(
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in (color.redF(), color.greenF(), color.blueF())
    )
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def text_contrast(first: QColor, second: QColor) -> float:
    """Compare actual foreground/background readability for ordinary evidence text."""
    low, high = sorted((relative_luminance(first), relative_luminance(second)))
    return (high + 0.05) / (low + 0.05)


class DnsGuiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("DNS Qt integration requires the real saved-file TShark decoder on PATH.")
        instance = QApplication.instance()
        cls.application = instance if isinstance(instance, QApplication) else QApplication(["test_dns_gui_integration"])

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="rvi-sentinel-dns-gui-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.baseline = self.directory / "baseline.json"
        self.baseline.write_text(json.dumps(load_baseline(self.baseline), sort_keys=True), encoding="utf-8")
        self.exports = self.directory / "exports"

    def saved_report(self, container: Literal["pcap", "pcapng"]) -> tuple[AnalysisReport, Path, bytes]:
        capture = self.directory / ("dns-evidence-" + container + "." + container)
        content = dns_capture(container)
        capture.write_bytes(content)
        document = analyze(capture, load_baseline(self.baseline), 3.8)
        report_path = write_report(document, capture, self.exports)
        return load_report(report_path), capture, content

    def window(self, report: AnalysisReport) -> RviSentinelWindow:
        window = RviSentinelWindow()
        self.addCleanup(self.close_window, window)
        window.resize(1400, 1000)
        window.show()
        window.baseline_field.setText(str(self.baseline))
        window.export_field.setText(str(self.exports))
        window.populate_report(report)
        window.workspace_tabs.setCurrentIndex(1)
        self.wait_views(window)
        return window

    def close_window(self, window: RviSentinelWindow) -> None:
        window.close()
        wait_until(lambda: not window.packet_timeline.is_busy and not window.session_timeline.is_busy and
                   not window.dns_evidence_view.is_busy and window.report_worker is None,
                   20_000, "Owned packet, session, DNS and report workers shut down")

    def wait_views(self, window: RviSentinelWindow) -> None:
        wait_until(lambda: not window.packet_timeline.is_busy and not window.session_timeline.is_busy and
                   not window.dns_evidence_view.is_busy and window.packet_timeline.completed_page is not None and
                   window.session_timeline.completed_page is not None and window.dns_evidence_view.page is not None,
                   30_000, "Packet, session and passive DNS indexes and pages")

    def apply_packets(self, window: RviSentinelWindow) -> None:
        child(window.packet_timeline, QPushButton, "packetApplyFilters").click()
        self.wait_views(window)

    def apply_dns(self, window: RviSentinelWindow) -> None:
        child(window.dns_evidence_view, QPushButton, "dnsApplyFilters").click()
        self.wait_views(window)

    def assert_message_trace(self, inspector: str, message: CapturedDnsMessage) -> None:
        """Require consumed structured values and source ordinals in the actual inspector."""
        self.assertIn(f"Decoder frame: {message.frame_number}; message index: {message.message_index}; protocol: {message.protocol}", inspector)
        self.assertIn(f"Transaction ID: {message.transaction_id}; opcode: {message.opcode}", inspector)
        self.assertIn(f"response: {message.is_response}; truncated: {message.is_truncated}; response code: {message.response_code}", inspector)
        self.assertIn(f"Linked query decoder frame: {message.response_to_frame if message.response_to_frame is not None else 'unavailable'}", inspector)
        for ordinal, question in enumerate(message.questions, 1):
            self.assertIn(f"Question ordinal {ordinal}: canonical name={question.name}; type={question.record_type}; class={question.record_class}", inspector)
        for ordinal, record in enumerate(message.answers, 1):
            owner = record.owner if record.owner is not None else "(not emitted by decoder)"
            self.assertIn(f"Answer ordinal {ordinal}: owner={owner}; type={record.record_type}; class={record.record_class}; TTL={record.ttl_seconds}", inspector)
            if record.value is not None:
                self.assertIn(f"value={record.value}", inspector)

    def test_saved_report_roundtrip_and_query_response_matched_session_navigation(self) -> None:
        original_baseline = self.baseline.read_bytes()
        with patch("socket.gethostbyaddr", side_effect=AssertionError("Passive evidence navigation must not resolve PTR")), patch(
            "socket.getaddrinfo", side_effect=AssertionError("Passive evidence navigation must not resolve names")
        ):
            report, capture, content = self.saved_report("pcapng")
            self.assertIsNotNone(report.dns_evidence)
            if report.dns_evidence is None:
                raise AssertionError("The saved report did not retain typed passive DNS evidence.")
            self.assertEqual((report.dns_evidence.capture_sha256, len(report.dns_evidence.messages)),
                             (hashlib.sha256(content).hexdigest(), 20))
            exports_before = {path.name: path.read_bytes() for path in self.exports.iterdir() if path.is_file()}
            window = self.window(report)
            packets = window.packet_timeline
            sessions = window.session_timeline
            dns = window.dns_evidence_view
            index = dns.dns_index
            self.assertIsNotNone(index)
            if index is None:
                raise AssertionError("The actual Qt session worker did not publish a DNS index.")
            self.assertIs(index, sessions.dns_index)
            association = next(item for item in index.associations if item.matching_frames == (3, 4))
            self.assertEqual(len(index.associations), 7)
            child(packets, QLineEdit, "packetProtocolFilter").setText("udp")
            self.apply_packets(window)
            packets.table.selectRow(0)
            packet_origin = packets.capture_navigation()
            packet_origin_inspector = packets.inspector.toPlainText()
            child(sessions, QLineEdit, "sessionPortFilter").setText("54000")
            child(sessions, QPushButton, "sessionApplyFilters").click()
            self.wait_views(window)
            self.assertEqual(sessions.completed_page.matching_count, 1)
            sessions.table.selectRow(0)
            self.assertEqual(sessions.selected_identity, association.session_identity)
            session_origin = sessions.capture_navigation()
            session_origin_inspector = sessions.inspector.toPlainText()

            child(sessions, QPushButton, "sessionShowDnsEvidence").click()
            self.wait_views(window)
            self.assertEqual(window.results_tabs.currentWidget(), dns)
            self.assertEqual(dns.page.matching_count, 2)
            for width, height in ((1180, 820), (900, 680)):
                window.resize(width, height)
                self.application.processEvents()
                self.assertTrue(dns.isVisible())
                self.assertGreater(dns.table.viewport().width(), 0, f"DNS table width at {width}x{height}")
                self.assertGreaterEqual(dns.table.viewport().height(), 3 * dns.table.rowHeight(0), f"Three complete DNS table rows at {width}x{height}")
                self.assertGreaterEqual(dns.inspector.viewport().height(), 3 * dns.inspector.fontMetrics().lineSpacing(), f"Three complete DNS inspector lines at {width}x{height}")
                for evidence_widget in (packets, sessions, dns):
                    for field in (evidence_widget.table.viewport(), evidence_widget.inspector.viewport()):
                        palette = field.palette()
                        for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
                            foreground = palette.color(group, QPalette.ColorRole.Text)
                            background = palette.color(group, QPalette.ColorRole.Base)
                            self.assertGreaterEqual(text_contrast(foreground, background), 4.5, f"Readable evidence text in {evidence_widget.objectName()} at {width}x{height}")
                for button in (dns.query_button, dns.response_button, dns.superseding_button, dns.matched_button, dns.session_button):
                    self.assertGreaterEqual(button.height(), button.minimumSizeHint().height(), f"Complete source action label in {button.objectName()} at {width}x{height}")
                    self.assertGreaterEqual(button.width(), button.minimumSizeHint().width(), f"Complete source action width in {button.objectName()} at {width}x{height}")
                for identifier in ("analyzeButton", "cancelAnalysisButton", "addToBaselineButton", "openExportsButton", "clearResultsButton"):
                    button = child(window, QPushButton, identifier)
                    self.assertTrue(button.isVisible(), f"Visible analysis toolbar action {identifier} at {width}x{height}")
                    self.assertGreaterEqual(button.height(), button.minimumSizeHint().height(), f"Complete analysis toolbar height in {identifier} at {width}x{height}")
                    self.assertGreaterEqual(button.width(), button.minimumSizeHint().width(), f"Complete analysis toolbar caption in {identifier} at {width}x{height}")
            child(dns, QLineEdit, "dnsSearch").setText("service.test")
            self.apply_dns(window)
            self.assertEqual(dns.page.matching_count, 1)
            dns.table.selectRow(0)
            self.assertEqual(dns.selected_identity, association.identity)
            dns_origin = dns.capture_navigation()
            dns_origin_inspector = dns.inspector.toPlainText()
            for evidence in (report.evidence.sha256, association.identity.association_sha256,
                             association.session_identity.scope_sha256, "service.test", "edge.test",
                             "198.51.100.20", "1791428479.590385001", "fixture-resolver", "fixture-client"):
                self.assertIn(evidence, dns_origin_inspector)
            self.assertIn("Answer record ordinals: 1, 2", dns_origin_inspector)
            self.assertIn("process relation: different", dns_origin_inspector)

            for button, frame in (("dnsShowResponsePacket", 2), ("dnsShowQueryPacket", 1)):
                with self.subTest(button=button):
                    child(dns, QPushButton, button).click()
                    self.wait_views(window)
                    self.assertEqual(window.results_tabs.currentWidget(), packets)
                    self.assertEqual(packets.selected_identity, PacketIdentity(report.evidence.sha256, frame))
                    self.assertEqual(tuple(packet.frame_number for packet in packets.completed_page.packets), (frame,))
                    self.assertIn(f"frame:{frame}", packets.inspector.toPlainText())
                    self.assertIn("service.test", packets.inspector.toPlainText())
                    source_message = next(message for message in report.dns_evidence.messages if message.frame_number == frame)
                    self.assert_message_trace(packets.inspector.toPlainText(), source_message)
                    child(packets, QPushButton, "packetReturnToDnsEvidence").click()
                    self.wait_views(window)
                    self.assertEqual(window.results_tabs.currentWidget(), dns)
                    self.assertEqual(dns.capture_navigation(), dns_origin)
                    self.assertEqual(dns.inspector.toPlainText(), dns_origin_inspector)

            child(dns, QPushButton, "dnsShowMatchedPackets").click()
            self.wait_views(window)
            self.assertEqual(tuple(packet.frame_number for packet in packets.completed_page.packets), (3, 4))
            self.assertEqual(packets.completed_page.matching_count, 2)
            self.assertNotIn(41, tuple(packet.frame_number for packet in packets.completed_page.packets))
            self.assertNotIn(42, tuple(packet.frame_number for packet in packets.completed_page.packets))
            child(packets, QPushButton, "packetReturnToDnsEvidence").click()
            self.wait_views(window)
            child(dns, QPushButton, "dnsShowSession").click()
            self.wait_views(window)
            self.assertEqual(window.results_tabs.currentWidget(), sessions)
            self.assertEqual(sessions.selected_identity, association.session_identity)
            child(sessions, QPushButton, "sessionReturnToDnsEvidence").click()
            self.wait_views(window)
            self.assertEqual(dns.capture_navigation(), dns_origin)
            child(dns, QPushButton, "dnsReturnToSession").click()
            self.wait_views(window)
            self.assertEqual(sessions.capture_navigation(), session_origin)
            self.assertEqual(sessions.inspector.toPlainText(), session_origin_inspector)
            child(packets, QPushButton, "packetRestoreTimeline").click()
            self.wait_views(window)
            self.assertEqual(packets.capture_navigation(), packet_origin)
            self.assertEqual(packets.inspector.toPlainText(), packet_origin_inspector)
            self.assertEqual(capture.read_bytes(), content)
            self.assertEqual(self.baseline.read_bytes(), original_baseline)
            self.assertEqual({path.name: path.read_bytes() for path in self.exports.iterdir() if path.is_file()}, exports_before)

    def test_diagnostic_observed_frames_remain_navigable_without_name_attribution(self) -> None:
        report, capture, content = self.saved_report("pcapng")
        window = self.window(report)
        dns = window.dns_evidence_view
        self.assertIsNone(dns.selected_identity)
        self.assertIn("Frame 23; message index 0", dns.inspector.toPlainText())
        self.assertIn("multicast_or_local_name_protocol", dns.inspector.toPlainText())
        self.assertIn("unlinked_response", dns.inspector.toPlainText())
        child(dns, QPushButton, "dnsShowObservedPackets").click()
        self.wait_views(window)
        packets = window.packet_timeline
        observed_frames = tuple(sorted({message.frame_number for message in report.dns_evidence.messages}))
        self.assertEqual(tuple(packet.frame_number for packet in packets.completed_page.packets), observed_frames)
        row = next(position for position, packet in enumerate(packets.completed_page.packets) if packet.frame_number == 23)
        packets.table.selectRow(row)
        self.assertEqual(packets.selected_identity, PacketIdentity(report.evidence.sha256, 23))
        self.assertIn("printer.local", packets.inspector.toPlainText())
        self.assertIn("multicast_or_local_name_protocol", packets.inspector.toPlainText())
        child(packets, QPushButton, "packetReturnToDnsEvidence").click()
        self.wait_views(window)
        self.assertIsNone(dns.selected_identity)
        self.assertEqual(capture.read_bytes(), content)

    def test_same_sha_reload_replacement_and_older_report_invalidate_dns_navigation(self) -> None:
        report, _, _ = self.saved_report("pcapng")
        replacement, _, _ = self.saved_report("pcap")
        window = self.window(report)
        dns = window.dns_evidence_view
        dns.table.selectRow(0)
        snapshot = dns.capture_navigation()
        selected = dns.selected_identity
        child(dns, QPushButton, "dnsShowResponsePacket").click()
        self.wait_views(window)
        self.assertTrue(child(window.packet_timeline, QPushButton, "packetReturnToDnsEvidence").isEnabled())
        child(dns, QLineEdit, "dnsSearch").setText("shared.test")
        child(dns, QPushButton, "dnsApplyFilters").click()
        self.assertTrue(dns.is_busy)
        window.populate_report(report)
        self.wait_views(window)
        self.assertFalse(dns.restore_navigation(snapshot))
        self.assertIsNone(dns.selected_identity)
        self.assertFalse(child(window.packet_timeline, QPushButton, "packetReturnToDnsEvidence").isEnabled())
        self.assertFalse(child(window.session_timeline, QPushButton, "sessionReturnToDnsEvidence").isEnabled())
        self.assertFalse(child(dns, QPushButton, "dnsReturnToSession").isEnabled())
        window.populate_report(replacement)
        self.wait_views(window)
        self.assertEqual((dns.dns_index.capture_sha256, dns.page.total_count), (replacement.evidence.sha256, 9))
        self.assertFalse(dns.select_association(selected))
        self.assertNotIn(report.evidence.sha256, dns.inspector.toPlainText())
        window.populate_report(replace(replacement, dns_evidence=None))
        wait_until(lambda: not window.packet_timeline.is_busy and not window.session_timeline.is_busy and not dns.is_busy,
                   30_000, "Older report without structured DNS evidence")
        self.assertIsNone(dns.dns_index)
        self.assertIsNone(dns.page)
        self.assertFalse(child(dns, QPushButton, "dnsShowObservedPackets").isEnabled())
        self.assertFalse(dns.restore_navigation(snapshot))

    def test_empty_real_dns_basis_and_close_during_owned_query(self) -> None:
        capture = self.directory / "no-dns.pcapng"
        content = session_capture("pcapng")
        capture.write_bytes(content)
        report = load_report(write_report(analyze(capture, load_baseline(self.baseline), 3.8), capture, self.exports))
        window = self.window(report)
        dns = window.dns_evidence_view
        self.assertEqual((len(dns.dns_index.dns_evidence.messages), dns.page.total_count, dns.page.matching_count), (0, 0, 0))
        self.assertFalse(child(dns, QPushButton, "dnsShowObservedPackets").isEnabled())
        child(dns, QPushButton, "dnsApplyFilters").click()
        self.assertTrue(dns.is_busy)
        self.close_window(window)
        self.assertFalse(dns.is_busy)
        self.assertEqual(capture.read_bytes(), content)

    def test_superseding_negative_response_is_traceable_and_navigable(self) -> None:
        capture = self.directory / "negative-dns.pcap"
        question = ("replace.test", 1, 1)
        content = replacement_capture(question, (address_record("replace.test", "198.51.100.20", 60),),
                                      question, (), 0x8183)
        capture.write_bytes(content)
        report = load_report(write_report(analyze(capture, load_baseline(self.baseline), 3.8), capture, self.exports))
        window = self.window(report)
        dns = window.dns_evidence_view
        self.assertEqual(dns.page.total_count, 1)
        dns.table.selectRow(0)
        association = dns.page.associations[0]
        self.assertEqual(association.matching_frames, (3,))
        self.assertEqual((association.superseded_by_frame, association.superseded_by_message_index), (5, 0))
        inspector = dns.inspector.toPlainText()
        self.assertIn("Original TTL expiry epoch: 1791428509.590385001", inspector)
        self.assertIn("Effective expiry epoch: 1791428452.590385001", inspector)
        self.assertIn("Superseding decoder frame: 5", inspector)
        self.assertIn("response code: 3", inspector)
        snapshot = dns.capture_navigation()
        child(dns, QPushButton, "dnsShowSupersedingPacket").click()
        self.wait_views(window)
        packets = window.packet_timeline
        self.assertEqual(packets.selected_identity, PacketIdentity(report.evidence.sha256, 5))
        self.assertEqual(tuple(packet.frame_number for packet in packets.completed_page.packets), (5,))
        self.assertIn("response code: 3", packets.inspector.toPlainText())
        superseding_message = next(message for message in report.dns_evidence.messages if message.frame_number == 5)
        self.assert_message_trace(packets.inspector.toPlainText(), superseding_message)
        child(packets, QPushButton, "packetReturnToDnsEvidence").click()
        self.wait_views(window)
        self.assertEqual(dns.capture_navigation(), snapshot)
        self.assertEqual(dns.inspector.toPlainText(), inspector)
        self.assertEqual(capture.read_bytes(), content)

    def test_application_quit_finishes_actual_owned_dns_query(self) -> None:
        self.saved_report("pcapng")
        report_path = self.exports / "dns-evidence-pcapng_report.json"
        script = """
from pathlib import Path
import sys
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QPushButton
from gui import RviSentinelWindow, WindowQuitFilter
from gui_models import load_report
from tests.test_packet_gui_integration import child, wait_until

application = QApplication(['test_owned_dns_quit'])
window = RviSentinelWindow()
quit_filter = WindowQuitFilter(window)
application.installEventFilter(quit_filter)
window.show()
window.populate_report(load_report(Path(sys.argv[1])))
wait_until(lambda: not window.packet_timeline.is_busy and not window.session_timeline.is_busy and
           not window.dns_evidence_view.is_busy and window.dns_evidence_view.page is not None,
           30_000, 'Initial real passive DNS report indexes')

def quit_with_actual_dns_worker():
    child(window.dns_evidence_view, QPushButton, 'dnsApplyFilters').click()
    if not window.dns_evidence_view.is_busy:
        print('Expected an owned actual DNS query worker before quit.', flush=True)
        application.exit(4)
        return
    application.quit()

deadline = QTimer()
deadline.setSingleShot(True)
deadline.timeout.connect(lambda: application.exit(3))
deadline.start(15_000)
QTimer.singleShot(0, quit_with_actual_dns_worker)
result = application.exec()
deadline.stop()
assert result == 0, f'Actual DNS shutdown failed: {result}'
assert window.closing_requested and window.quit_requested
assert not window.dns_evidence_view.is_busy
assert not window.session_timeline.is_busy
assert not window.packet_timeline.is_busy
assert not window.isVisible()
print('PASS actual owned DNS query completed application quit', flush=True)
"""
        result = subprocess.run([sys.executable, "-X", "faulthandler", "-c", script, str(report_path)],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True,
                                text=True, timeout=45, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS actual owned DNS query", result.stdout)
        self.assertNotIn("Destroyed while thread is still running", result.stderr)
        self.assertNotIn("Destroyed while process", result.stderr)


if __name__ == "__main__":
    unittest.main()
