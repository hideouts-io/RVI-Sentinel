"""Real saved evidence through the sidebar shell and native Qt detail panes."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QProcess, Qt
from PySide6.QtGui import QPalette
from PySide6.QtTest import QSignalSpy, QTest
from PySide6.QtWidgets import (
    QApplication, QComboBox, QGroupBox, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QPushButton, QStackedWidget, QWidget,
)

from analyze import analyze, load_baseline, write_report
from gui import RviSentinelWindow
from gui_models import AnalysisReport, load_report
from gui_shell import Destination
from packet_timeline import PacketIdentity
from tests.dns_fixture import dns_capture
from tests.test_dns_gui_integration import text_contrast
from tests.test_packet_gui_integration import child, wait_until


def sidebar_item(sidebar: QListWidget, destination: Destination) -> QListWidgetItem:
    """Find a required route by its stable role key, never its visible caption."""
    for row in range(sidebar.count()):
        item = sidebar.item(row)
        if item is not None and item.data(Qt.ItemDataRole.UserRole) == destination:
            return item
    raise AssertionError(f"Required sidebar destination {destination!r} is unavailable.")


def selected_destination(sidebar: QListWidget) -> str:
    item = sidebar.currentItem()
    if item is None:
        raise AssertionError("The visible shell has no selected sidebar destination.")
    key: object = item.data(Qt.ItemDataRole.UserRole)
    if type(key) is not str:
        raise AssertionError("The selected sidebar destination has no typed route key.")
    return key


class GuiShellIntegrationTests(unittest.TestCase):
    application: QApplication

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("GUI shell integration requires the real saved-file TShark decoder on PATH.")
        instance = QApplication.instance()
        cls.application = instance if isinstance(instance, QApplication) else QApplication(["test_gui_shell"])

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="rvi-sentinel-shell-gui-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.baseline = self.directory / "baseline<literal>.json"
        self.baseline.write_text(json.dumps(load_baseline(self.baseline), sort_keys=True), encoding="utf-8")
        self.exports = self.directory / "exports<literal>"
        self.capture = self.directory / "authorized<saved>.pcapng"
        self.capture.write_bytes(dns_capture("pcapng"))
        document = analyze(self.capture, load_baseline(self.baseline), 3.8)
        self.report_path = write_report(document, self.capture, self.exports)
        self.report: AnalysisReport = load_report(self.report_path)

    def window(self) -> RviSentinelWindow:
        window = RviSentinelWindow()
        self.addCleanup(self.close_window, window)
        window.resize(1180, 820)
        window.show()
        window.capture_field.setText(str(self.capture))
        window.baseline_field.setText(str(self.baseline))
        window.export_field.setText(str(self.exports))
        window.populate_report(self.report)
        self.wait_views(window)
        return window

    def close_window(self, window: RviSentinelWindow) -> None:
        window.close()
        wait_until(lambda: not window.packet_timeline.is_busy and not window.session_timeline.is_busy and
                   not window.dns_evidence_view.is_busy and window.report_worker is None,
                   20_000, "Owned shell report, packet, session and DNS workers shut down")

    def wait_views(self, window: RviSentinelWindow) -> None:
        wait_until(lambda: not window.packet_timeline.is_busy and not window.session_timeline.is_busy and
                   not window.dns_evidence_view.is_busy and window.packet_timeline.completed_page is not None and
                   window.session_timeline.completed_page is not None and window.dns_evidence_view.page is not None,
                   30_000, "Real saved report indexes and completed evidence pages")

    def click_destination(self, window: RviSentinelWindow, destination: Destination) -> None:
        sidebar = child(window, QListWidget, "navigationSidebar")
        item = sidebar_item(sidebar, destination)
        rectangle = sidebar.visualItemRect(item)
        self.assertTrue(sidebar.viewport().rect().contains(rectangle.center()), "Required sidebar item is visibly clickable.")
        QTest.mouseClick(sidebar.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, rectangle.center(), 0)
        wait_until(lambda: selected_destination(sidebar) == destination, 5_000, "Sidebar route selection")

    def test_sidebar_routes_preserve_evidence_without_starting_operations(self) -> None:
        window = self.window()
        sidebar = child(window, QListWidget, "navigationSidebar")
        stack = child(window, QStackedWidget, "workspaceStack")
        self.assertEqual(selected_destination(sidebar), "overview")
        self.assertTrue(child(window, QPushButton, "overviewAnalysisButton").isVisible())
        self.assertFalse(window.workspace_tabs.tabBar().isVisible())
        self.assertFalse(window.results_tabs.tabBar().isVisible())

        window.show_destination("analysis")
        original_baseline = self.baseline.read_bytes()
        window.start_analysis()
        wait_until(lambda: window.process.state() == QProcess.ProcessState.NotRunning and not window.report_loading and
                   window.packet_timeline.completed_page is not None,
                   30_000, "Real passive preview and report loading")
        self.wait_views(window)
        wait_until(lambda: window.enrichment_process.state() == QProcess.ProcessState.NotRunning,
                   10_000, "Local endpoint context without PTR")
        self.assertEqual(window.process.exitCode(), 0)
        self.assertIsNotNone(window.preview_sha256)
        self.assertTrue(window.add_to_baseline_button.isEnabled(), "The reviewed update action is available before navigation.")
        self.assertEqual(self.baseline.read_bytes(), original_baseline)
        packets, sessions, dns = window.packet_timeline, window.session_timeline, window.dns_evidence_view
        reviewed_report = packets.report
        self.assertIsNotNone(reviewed_report)
        for view, identifier, value in (
            (packets, "packetProtocolFilter", "udp"),
            (sessions, "sessionPortFilter", "54000"),
            (dns, "dnsSearch", "service.test"),
        ):
            window.results_tabs.setCurrentWidget(view)
            child(view, QLineEdit, identifier).setText(value)
            button_id = {"packetProtocolFilter": "packetApplyFilters", "sessionPortFilter": "sessionApplyFilters", "dnsSearch": "dnsApplyFilters"}[identifier]
            child(view, QPushButton, button_id).click()
            self.wait_views(window)
            view.table.selectRow(0)
        snapshots = (packets.capture_navigation(), sessions.capture_navigation(), dns.capture_navigation())
        pages = (packets.completed_page, sessions.completed_page, dns.completed_page)
        indexes = (sessions.session_index, dns.dns_index)
        inspectors = (packets.inspector.toPlainText(), sessions.inspector.toPlainText(), dns.inspector.toPlainText())
        self.assertTrue(all(snapshot is not None for snapshot in snapshots))
        saved_bytes = {path: path.read_bytes() for path in (self.capture, self.baseline, *self.exports.iterdir()) if path.is_file()}
        operation_spies: list[tuple[str, QSignalSpy]] = []
        for name, process in (
            ("capture", window.capture_process), ("analysis/baseline", window.process),
            ("endpoint enrichment/PTR", window.enrichment_process), ("support setup", window.setup_process),
            ("setup checks", window.check_process),
        ):
            self.assertEqual(process.state(), QProcess.ProcessState.NotRunning)
            spy = QSignalSpy(process.started)
            self.assertTrue(spy.isValid())
            operation_spies.append((name, spy))

        window.show_destination("overview")
        sidebar.setFocus(Qt.FocusReason.TabFocusReason)
        QTest.keyClick(sidebar, Qt.Key.Key_Down, Qt.KeyboardModifier.NoModifier, 0)
        self.assertEqual(selected_destination(sidebar), "setup")
        for destination in ("capture", "analysis", "baselines", "exports", "diagnostics", "overview"):
            self.click_destination(window, destination)
            if destination in ("capture", "analysis", "setup"):
                self.assertIs(stack.currentWidget(), window.workspace_tabs)
            else:
                self.assertEqual(stack.currentWidget().objectName(), destination + "Page")
        card = child(window, QPushButton, "overviewAnalysisButton")
        card.setFocus(Qt.FocusReason.TabFocusReason)
        QTest.keyClick(card, Qt.Key.Key_Space, Qt.KeyboardModifier.NoModifier, 0)
        self.assertEqual(selected_destination(sidebar), "analysis")
        self.assertIs(stack.currentWidget(), window.workspace_tabs)
        self.assertIs(packets.report, reviewed_report)
        self.assertEqual((packets.capture_navigation(), sessions.capture_navigation(), dns.capture_navigation()), snapshots)
        for before, after in zip(pages, (packets.completed_page, sessions.completed_page, dns.completed_page), strict=True):
            self.assertIs(after, before)
        for before, after in zip(indexes, (sessions.session_index, dns.dns_index), strict=True):
            self.assertIs(after, before)
        self.assertEqual((packets.inspector.toPlainText(), sessions.inspector.toPlainText(), dns.inspector.toPlainText()), inspectors)
        configuration = child(window, QGroupBox, "analysisConfiguration")
        self.assertTrue(configuration.isAncestorOf(window.baseline_field))
        self.assertTrue(configuration.isAncestorOf(window.export_field))
        for label_id, path in (("baselinePath", self.baseline), ("exportPath", self.exports)):
            label = child(window, QLabel, label_id)
            self.assertEqual(label.text(), str(path))
            self.assertEqual(label.textFormat(), Qt.TextFormat.PlainText)
        for name, spy in operation_spies:
            self.assertEqual(spy.count(), 0, f"Navigation unexpectedly started {name}.")
        self.assertEqual({path: path.read_bytes() for path in saved_bytes}, saved_bytes)
        self.assertEqual(set(self.exports.iterdir()), {path for path in saved_bytes if path.parent == self.exports})

    def test_programmatic_routes_and_dns_sources_sync_without_recreating_views(self) -> None:
        window = self.window()
        sidebar = child(window, QListWidget, "navigationSidebar")
        stack = child(window, QStackedWidget, "workspaceStack")
        selector = child(window, QComboBox, "analysisResultSelector")
        for index, expected in ((2, "setup"), (0, "capture"), (1, "analysis")):
            window.workspace_tabs.setCurrentIndex(index)
            self.assertEqual(selected_destination(sidebar), expected)
            self.assertIs(stack.currentWidget(), window.workspace_tabs)
        for destination in ("overview", "baselines", "exports", "diagnostics"):
            self.click_destination(window, destination)
            self.assertEqual(window.workspace_tabs.currentIndex(), 1)
            window.show_destination("analysis")
            self.assertEqual(selected_destination(sidebar), "analysis")
            self.assertIs(stack.currentWidget(), window.workspace_tabs)

        for view in (window.packet_timeline, window.session_timeline, window.dns_evidence_view):
            window.results_tabs.setCurrentWidget(view)
            self.assertEqual(selector.currentData(), window.results_tabs.indexOf(view))
            self.assertTrue(view.isVisible())
        for view in (window.packet_timeline, window.session_timeline, window.dns_evidence_view):
            choice = selector.findData(window.results_tabs.indexOf(view))
            self.assertGreaterEqual(choice, 0)
            selector.setCurrentIndex(choice)
            self.assertIs(window.results_tabs.currentWidget(), view)
        console_index = window.results_tabs.indexOf(window.console)
        self.assertEqual(selector.findData(console_index), -1)
        window.advanced_toggle.setChecked(True)
        self.assertGreaterEqual(selector.findData(console_index), 0)
        selector.setCurrentIndex(selector.findData(console_index))
        self.assertIs(window.results_tabs.currentWidget(), window.console)
        window.advanced_toggle.setChecked(False)
        self.assertEqual(selector.findData(console_index), -1)
        self.assertIsNot(window.results_tabs.currentWidget(), window.console)
        self.assertGreaterEqual(selector.currentIndex(), 0)

        dns = window.dns_evidence_view
        index = dns.dns_index
        if index is None:
            raise AssertionError("The real correlation index was not published.")
        association = next(item for item in index.associations if item.matching_frames == (3, 4))
        self.assertTrue(window.session_timeline.select_session(association.session_identity))
        window.results_tabs.setCurrentWidget(window.session_timeline)
        self.wait_views(window)
        child(window.session_timeline, QPushButton, "sessionShowDnsEvidence").click()
        self.wait_views(window)
        self.assertIs(window.results_tabs.currentWidget(), dns)
        self.assertEqual(selector.currentData(), window.results_tabs.indexOf(dns))
        self.assertTrue(dns.select_association(association.identity))
        self.wait_views(window)
        source = dns.capture_navigation()
        child(dns, QPushButton, "dnsShowResponsePacket").click()
        self.wait_views(window)
        packets = window.packet_timeline
        self.assertIs(window.results_tabs.currentWidget(), packets)
        self.assertEqual(selector.currentData(), window.results_tabs.indexOf(packets))
        self.assertEqual(packets.selected_identity, PacketIdentity(index.capture_sha256, association.response_frame))
        child(packets, QPushButton, "packetReturnToDnsEvidence").click()
        self.wait_views(window)
        self.assertIs(window.results_tabs.currentWidget(), dns)
        self.assertEqual(selector.currentData(), window.results_tabs.indexOf(dns))
        self.assertEqual(dns.capture_navigation(), source)
        self.assertEqual(selected_destination(sidebar), "analysis")

    def test_exact_minimum_windows_have_usable_native_evidence_panes(self) -> None:
        window = self.window()
        window.show_destination("analysis")
        for width, height in ((900, 680), (1180, 820)):
            window.resize(width, height)
            for view, control_ids in (
                (window.packet_timeline, (
                    "packetSearch", "packetEndpointFilter", "packetPortFilter", "packetProtocolFilter", "packetProcessFilter",
                    "packetInterfaceFilter", "packetProcessStateFilter", "packetInterfaceStateFilter", "packetDirectionFilter",
                    "packetApplyFilters", "packetClearFilters", "packetCancelQuery", "packetPageSize", "packetPreviousPage", "packetNextPage",
                    "packetShowOwningSession", "packetBackToSessions", "packetRestoreTimeline", "packetReturnToDnsEvidence",
                )),
                (window.session_timeline, (
                    "sessionSearch", "sessionEndpointFilter", "sessionPortFilter", "sessionTransportFilter", "sessionProcessFilter",
                    "sessionProcessStateFilter", "sessionEffectiveProcessStateFilter", "sessionInterfaceFilter", "sessionInterfaceStateFilter",
                    "sessionApplyFilters", "sessionClearFilters", "sessionCancelQuery", "sessionPageSize", "sessionPreviousPage", "sessionNextPage",
                    "sessionOpenUngroupedPackets", "sessionOpenPackets", "sessionShowDnsEvidence", "sessionReturnToPackets", "sessionReturnToDnsEvidence",
                )),
                (window.dns_evidence_view, (
                    "dnsSearch", "dnsPageSize", "dnsApplyFilters", "dnsClearFilters", "dnsShowAllSessions", "dnsCancelQuery", "dnsPreviousPage", "dnsNextPage",
                    "dnsShowQueryPacket", "dnsShowResponsePacket", "dnsShowSupersedingPacket", "dnsShowMatchedPackets", "dnsShowSession",
                    "dnsShowObservedPackets", "dnsReturnToSession",
                )),
            ):
                window.results_tabs.setCurrentWidget(view)
                view.table.selectRow(0)
                self.application.processEvents()
                name = view.objectName()
                self.assertEqual((window.width(), window.height()), (width, height), f"Actual requested window size for {name}.")
                self.assertTrue(view.isVisible())
                self.assertGreaterEqual(view.table.viewport().height(), 3 * view.table.rowHeight(0), f"Three complete {name} table rows at {width}x{height}.")
                self.assertGreaterEqual(view.inspector.viewport().height(), 3 * view.inspector.fontMetrics().lineSpacing(), f"Three complete {name} inspector lines at {width}x{height}.")
                self.assertGreaterEqual(view.table.viewport().width(), 200, f"Readable {name} table width at {width}x{height}.")
                self.assertGreaterEqual(view.inspector.viewport().width(), 200, f"Readable {name} inspector width at {width}x{height}.")
                for field in (view.table.viewport(), view.inspector.viewport()):
                    palette = field.palette()
                    for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
                        self.assertGreaterEqual(text_contrast(palette.color(group, QPalette.ColorRole.Text), palette.color(group, QPalette.ColorRole.Base)), 4.5)
                self.assertFalse(view.table.viewport().grab().isNull())
                for identifier in ("analyzeButton", "cancelAnalysisButton", "addToBaselineButton", "openExportsButton", "clearResultsButton"):
                    button = child(window, QPushButton, identifier)
                    self.assertGreaterEqual(button.width(), button.minimumSizeHint().width(), f"Complete action caption in {identifier}.")
                    self.assertGreaterEqual(button.height(), button.minimumSizeHint().height(), f"Complete action height in {identifier}.")
                for identifier in control_ids:
                    control = child(view, QWidget, identifier)
                    self.assertIsInstance(control, (QPushButton, QComboBox, QLineEdit))
                    self.assertTrue(control.isVisible(), f"Visible evidence control {identifier}.")
                    self.assertGreaterEqual(control.width(), control.minimumSizeHint().width(), f"Usable control/caption width in {identifier}.")
                    self.assertGreaterEqual(control.height(), control.minimumSizeHint().height(), f"Usable control/caption height in {identifier}.")


if __name__ == "__main__":
    unittest.main()
