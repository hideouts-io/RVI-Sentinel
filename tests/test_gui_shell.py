"""Real saved evidence through the sidebar shell and native Qt detail panes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEvent, QPoint, QProcess, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QImage, QPalette, QPixmap
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


def icon_palette(template: QPalette, background: QColor, foreground: QColor,
                 highlight: QColor, highlighted_foreground: QColor) -> QPalette:
    """Exercise Qt palette roles in the owned app without changing OS settings."""
    palette = QPalette(template)
    for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive, QPalette.ColorGroup.Disabled):
        for role in (QPalette.ColorRole.Window, QPalette.ColorRole.Base, QPalette.ColorRole.AlternateBase, QPalette.ColorRole.Button):
            palette.setColor(group, role, background)
        for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText):
            palette.setColor(group, role, foreground)
        palette.setColor(group, QPalette.ColorRole.Highlight, highlight)
        palette.setColor(group, QPalette.ColorRole.HighlightedText, highlighted_foreground)
    return palette


@contextmanager
def inherited_legacy_output_encoding() -> Iterator[None]:
    """Restore the inherited process setting even when actual GUI preview fails."""
    previous = os.environ.get("PYTHONIOENCODING")
    os.environ["PYTHONIOENCODING"] = "cp1252"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("PYTHONIOENCODING", None)
        else:
            os.environ["PYTHONIOENCODING"] = previous


def icon_has_foreground(icon: QIcon, foreground: QColor) -> bool:
    """Wait for rendered palette changes rather than an implementation timer."""
    image = icon.pixmap(QSize(18, 18), 1.0, QIcon.Mode.Normal, QIcon.State.Off).toImage()
    return any(
        color.alpha() >= 224 and abs(color.red() - foreground.red()) <= 2 and
        abs(color.green() - foreground.green()) <= 2 and abs(color.blue() - foreground.blue()) <= 2
        for y in range(image.height()) for x in range(image.width())
        for color in (image.pixelColor(x, y),)
    )


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
        self.baseline = self.directory / "baseline & café.json"
        self.baseline.write_text(json.dumps(load_baseline(self.baseline), sort_keys=True), encoding="utf-8")
        self.exports = self.directory / "exports & café"
        self.capture = self.directory / "authorized & 案件 café.pcapng"
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

    def assert_icon_rendering(self, pixmap: QPixmap, logical_size: int, device_pixel_ratio: float,
                              background: QColor, palette_alpha: int) -> bytes:
        """Inspect alpha-relative stroke coverage and actual composited contrast."""
        self.assertFalse(pixmap.isNull(), "A semantic workspace icon must produce a real Qt pixmap.")
        self.assertEqual(pixmap.devicePixelRatio(), device_pixel_ratio)
        image = pixmap.toImage()
        physical_size = round(logical_size * device_pixel_ratio)
        self.assertEqual((image.width(), image.height()), (physical_size, physical_size))
        self.assertGreater(palette_alpha, 0, "Readable palette ink cannot be fully transparent.")
        self.assertLessEqual(palette_alpha, 255)
        alpha = bytes(image.pixelColor(x, y).alpha() for y in range(image.height()) for x in range(image.width()))
        strong_ink = tuple(image.pixelColor(x, y) for y in range(image.height()) for x in range(image.width())
                           if image.pixelColor(x, y).alpha() * 255 >= 224 * palette_alpha)
        self.assertGreaterEqual(len(strong_ink), logical_size // 2, "Readable vector strokes must survive small-scale rasterization.")
        for color in strong_ink:
            opacity = color.alphaF()
            composite = QColor.fromRgbF(
                color.redF() * opacity + background.redF() * (1 - opacity),
                color.greenF() * opacity + background.greenF() * (1 - opacity),
                color.blueF() * opacity + background.blueF() * (1 - opacity),
            )
            self.assertGreaterEqual(text_contrast(composite, background), 3.0, "Visible icon strokes must contrast with their displayed background.")
        for position in range(physical_size):
            for x, y in ((position, 0), (position, physical_size - 1), (0, position), (physical_size - 1, position)):
                self.assertEqual(image.pixelColor(x, y).alpha(), 0, "The glyph must retain padding rather than clip at an icon edge.")
        return alpha

    def rendered_background(self, image: QImage, widget: QWidget, window: RviSentinelWindow,
                            point: QPoint) -> QColor:
        """Use the visible composite rather than a transparent widget's palette."""
        self.assertTrue(widget.rect().contains(point))
        position = widget.mapTo(window, point)
        scale = image.devicePixelRatio()
        pixel = QPoint(round(position.x() * scale), round(position.y() * scale))
        self.assertTrue(image.rect().contains(pixel))
        return image.pixelColor(pixel)

    def assert_rendered_background(self, image: QImage, widget: QWidget, window: RviSentinelWindow,
                                   point: QPoint, expected: QColor) -> QColor:
        actual = self.rendered_background(image, widget, window, point)
        for channel in (QColor.red, QColor.green, QColor.blue):
            self.assertLessEqual(abs(channel(actual) - channel(expected)), 2,
                                 "The displayed workspace backdrop must adopt the application palette.")
        return actual

    def test_semantic_workspace_icons_render_at_sidebar_card_scales_and_follow_palette(self) -> None:
        original_palette = QPalette(self.application.palette())
        self.addCleanup(self.application.setPalette, original_palette)
        window = self.window()
        sidebar = child(window, QListWidget, "navigationSidebar")
        destinations: tuple[Destination, ...] = ("overview", "setup", "capture", "analysis", "baselines", "exports", "diagnostics")
        original_items = tuple(sidebar_item(sidebar, destination) for destination in destinations)
        original_pages = (window.packet_timeline, window.session_timeline, window.dns_evidence_view)
        original_navigation = tuple(view.capture_navigation() for view in original_pages)
        self.application.processEvents()
        for active_window in (window, None):
            self.application.setActiveWindow(active_window)
            self.application.processEvents()
            wait_until(lambda: not window.icon_refresh_timer.isActive(), 5_000, "Icons refresh after Qt active-window changes")
            self.assertEqual(window.isActiveWindow(), active_window is window)
            viewport = sidebar.viewport()
            selected = sidebar_item(sidebar, "overview")
            rectangle = sidebar.visualItemRect(selected)
            rendered_native = window.grab().toImage()
            native_backgrounds = (
                (QIcon.Mode.Normal, self.rendered_background(rendered_native, viewport, window, QPoint(4, viewport.height() - 4))),
                (QIcon.Mode.Selected, self.rendered_background(rendered_native, viewport, window, QPoint(4, rectangle.center().y()))),
            )
            for mode, background in native_backgrounds:
                role = QPalette.ColorRole.Text if mode == QIcon.Mode.Normal else QPalette.ColorRole.HighlightedText
                foreground_alpha = self.application.palette().color(role).alpha()
                for item in original_items:
                    with self.subTest(native_active=window.isActiveWindow(), destination=item.data(Qt.ItemDataRole.UserRole), mode=mode):
                        self.assert_icon_rendering(item.icon().pixmap(QSize(18, 18), sidebar.devicePixelRatioF(), mode, QIcon.State.Off),
                                                   18, sidebar.devicePixelRatioF(), background, foreground_alpha)
        self.application.setActiveWindow(window)
        self.application.processEvents()
        before_dpr = sidebar_item(sidebar, "overview").icon().cacheKey()
        self.application.sendEvent(window, QEvent(QEvent.Type.DevicePixelRatioChange))
        self.assertTrue(window.icon_refresh_timer.isActive(), "Qt display-scale events schedule the owned icon refresh.")
        wait_until(lambda: not window.icon_refresh_timer.isActive() and sidebar_item(sidebar, "overview").icon().cacheKey() != before_dpr,
                   5_000, "Native Qt display-scale event refreshes existing semantic icon values")
        palettes = (
            icon_palette(original_palette, QColor("#f5f6f8"), QColor("#1b2028"), QColor("#24578b"), QColor("#ffffff")),
            icon_palette(original_palette, QColor("#222831"), QColor("#edf2f8"), QColor("#91c8ff"), QColor("#152333")),
        )
        for palette in palettes:
            self.application.setPalette(palette)
            self.application.processEvents()
            wait_until(lambda: icon_has_foreground(sidebar_item(sidebar, "overview").icon(), palette.color(QPalette.ColorRole.Text)),
                       5_000, "Existing semantic icons adopt the actual application palette")
            self.assertEqual(selected_destination(sidebar), "overview")
            for before, destination in zip(original_items, destinations, strict=True):
                self.assertIs(sidebar_item(sidebar, destination), before, "Palette changes must update existing navigation items.")
            rendered_window = window.grab().toImage()
            self.assertFalse(rendered_window.isNull())
            viewport = sidebar.viewport()
            normal_background = self.assert_rendered_background(
                rendered_window, viewport, window, QPoint(4, viewport.height() - 4),
                palette.color(QPalette.ColorRole.AlternateBase),
            )
            selection = sidebar.visualItemRect(sidebar_item(sidebar, "overview"))
            selected_background = self.assert_rendered_background(
                rendered_window, viewport, window, QPoint(4, selection.center().y()),
                palette.color(QPalette.ColorRole.Highlight),
            )
            for logical_size in (18, 24):
                for device_pixel_ratio in (1.0, 2.0):
                    for mode, background in ((QIcon.Mode.Normal, normal_background), (QIcon.Mode.Selected, selected_background)):
                        with self.subTest(background=palette.color(QPalette.ColorRole.Base).name(), size=logical_size,
                                          dpr=device_pixel_ratio, mode=mode):
                            signatures = tuple(self.assert_icon_rendering(
                                sidebar_item(sidebar, destination).icon().pixmap(QSize(logical_size, logical_size), device_pixel_ratio, mode, QIcon.State.Off),
                                logical_size, device_pixel_ratio, background, 255,
                            ) for destination in destinations)
                            self.assertEqual(len(set(signatures)), len(destinations), "Every workspace needs a distinct visible glyph at each requested scale.")
            card_signatures: list[bytes] = []
            for destination in destinations[1:]:
                label = child(window, QLabel, "overview" + destination.title() + "Icon")
                card = child(window, QPushButton, "overview" + destination.title() + "Button")
                self.assertTrue(label.isVisible())
                self.assertTrue(label.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents))
                background = self.assert_rendered_background(
                    rendered_window, card, window, QPoint(card.width() // 2, 4),
                    palette.color(QPalette.ColorRole.Base),
                )
                foreground_alpha = (self.application.palette().color(QPalette.ColorRole.Text).alpha() if card.isEnabled() else
                                    self.application.palette().color(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text).alpha())
                card_signatures.append(self.assert_icon_rendering(label.pixmap(), 24, label.devicePixelRatioF(), background, foreground_alpha))
            self.assertEqual(len(set(card_signatures)), len(card_signatures), "Overview cards retain distinct readable semantic icons.")
            self.click_destination(window, "analysis")
            self.assertEqual((window.packet_timeline, window.session_timeline, window.dns_evidence_view), original_pages)
            self.assertEqual(tuple(view.capture_navigation() for view in original_pages), original_navigation)
            self.click_destination(window, "overview")
        differential = icon_palette(original_palette, QColor("#f5f6f8"), QColor("#1b2028"), QColor("#24578b"), QColor("#ffffff"))
        differential.setColor(QPalette.ColorGroup.Inactive, QPalette.ColorRole.Highlight, QColor("#c8ddfa"))
        differential.setColor(QPalette.ColorGroup.Inactive, QPalette.ColorRole.HighlightedText, QColor("#152333"))
        self.application.setPalette(differential)
        self.application.processEvents()
        wait_until(lambda: icon_has_foreground(sidebar_item(sidebar, "overview").icon(), differential.color(QPalette.ColorRole.Text)),
                   5_000, "Differential palette reaches actual existing icons")
        for active_window in (window, None):
            self.application.setActiveWindow(active_window)
            self.application.processEvents()
            wait_until(lambda: not window.icon_refresh_timer.isActive(), 5_000, "Differential active-window palette refresh")
            self.assertEqual(window.isActiveWindow(), active_window is window)
            selected = sidebar_item(sidebar, "overview")
            rectangle = sidebar.visualItemRect(selected)
            background = self.rendered_background(window.grab().toImage(), sidebar.viewport(), window, QPoint(4, rectangle.center().y()))
            for item in original_items:
                with self.subTest(differential_active=window.isActiveWindow(), destination=item.data(Qt.ItemDataRole.UserRole)):
                    self.assert_icon_rendering(item.icon().pixmap(QSize(18, 18), sidebar.devicePixelRatioF(), QIcon.Mode.Selected, QIcon.State.Off),
                                               18, sidebar.devicePixelRatioF(), background, 255)
        self.application.setActiveWindow(window)
        self.application.processEvents()
        self.assertEqual(tuple(sidebar_item(sidebar, destination) for destination in destinations), original_items)
        self.assertEqual((window.packet_timeline, window.session_timeline, window.dns_evidence_view), original_pages)
        self.assertEqual(tuple(view.capture_navigation() for view in original_pages), original_navigation)
        script = """
import gc
from PySide6.QtCore import QSize
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication
from gui_icons import workspace_icon

app = QApplication(['workspace-icon-copy-lifetime'])
completed = 0
for key in ('overview', 'setup', 'capture', 'analysis', 'baselines', 'exports', 'diagnostics'):
    original = workspace_icon(key, app.palette())
    before = original.pixmap(QSize(18, 18), 2.0, QIcon.Mode.Normal, QIcon.State.Off).toImage()
    copied = QIcon(original)
    copied.addPixmap(original.pixmap(QSize(24, 24), 2.0, QIcon.Mode.Normal, QIcon.State.Off), QIcon.Mode.Disabled, QIcon.State.Off)
    gc.collect()
    assert original.pixmap(QSize(18, 18), 2.0, QIcon.Mode.Normal, QIcon.State.Off).toImage() == before
    del original
    gc.collect()
    assert not copied.pixmap(QSize(18, 18), 2.0, QIcon.Mode.Normal, QIcon.State.Off).isNull()
    completed += 1
print(completed)
"""
        result = subprocess.run([sys.executable, "-X", "faulthandler", "-c", script],
                                cwd=Path(__file__).resolve().parent.parent, env=os.environ.copy(),
                                capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(result.returncode, 0, "Actual Qt icon copy/detachment lifetime failed: " + result.stderr[-2048:])
        self.assertEqual(result.stdout.strip(), "7", "Every semantic icon survives native Qt value copying and detachment.")

    def test_sidebar_routes_preserve_evidence_without_starting_operations(self) -> None:
        with inherited_legacy_output_encoding():
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
                       30_000, "Real Unicode passive preview and report loading under inherited CP1252")
            self.wait_views(window)
            wait_until(lambda: window.enrichment_process.state() == QProcess.ProcessState.NotRunning,
                       10_000, "Local endpoint context without PTR")
            self.assertEqual(window.process.exitCode(), 0)
            self.assertIsNotNone(window.preview_sha256)
            self.assertTrue(window.add_to_baseline_button.isEnabled(), "The reviewed update action is available before navigation.")
            self.assertEqual(self.baseline.read_bytes(), original_baseline)
            self.assertEqual(window.active_report_path, self.report_path.resolve())
            self.assertIn(unicodedata.normalize("NFC", str(self.report_path.resolve())),
                          unicodedata.normalize("NFC", window.console.toPlainText()))
            self.assertNotIn("\ufffd", window.console.toPlainText())
            self.assertEqual(os.environ.get("PYTHONIOENCODING"), "cp1252", "The owned child environment must not mutate its parent's setting.")
        packets, sessions, dns = window.packet_timeline, window.session_timeline, window.dns_evidence_view
        reviewed_report = packets.report
        self.assertIsNotNone(reviewed_report)
        if reviewed_report is None:
            raise AssertionError("The real Unicode preview did not load its complete saved report.")
        self.assertEqual(unicodedata.normalize("NFC", reviewed_report.capture.path),
                         unicodedata.normalize("NFC", str(self.capture.resolve())))
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
        self.assertTrue(window.add_to_baseline_button.isEnabled(), "Navigation preserves the verified reviewed update action.")
        try:
            for field, identifier, value in (
                (window.baseline_field, "baselinePath", "<b>literal & baseline</b>"),
                (window.export_field, "exportPath", "<i>literal & exports</i>"),
            ):
                field.setText(value)
                label = child(window, QLabel, identifier)
                self.assertEqual(label.text(), value)
                self.assertEqual(label.textFormat(), Qt.TextFormat.PlainText)
            self.assertIsNone(window.preview_sha256, "Changed request fields revoke the previous reviewed digest.")
            self.assertEqual({path: path.read_bytes() for path in saved_bytes}, saved_bytes)
        finally:
            window.baseline_field.setText(str(self.baseline))
            window.export_field.setText(str(self.exports))

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
