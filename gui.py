#!/usr/bin/env python3
"""Cross-platform iOS capture and analysis GUI for RVI-Sentinel."""

from __future__ import annotations

import shlex
import shutil
import sys
import platform
import hashlib
import json
import re
import tempfile
import uuid
from functools import partial
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QEvent, QLockFile, QObject, QProcess, QProcessEnvironment, Qt, QTimer, QUrl, QSignalBlocker, Signal, Slot
from PySide6.QtGui import (
    QColor,
    QCloseEvent,
    QDesktopServices,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QIcon,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gui_shell import (
    DESTINATIONS, Destination, destination_for_key, overview_page, plain_label,
    populate_sidebar, refresh_workspace_icons, scroll_page, shell_stylesheet,
)
from gui_models import (
    AnalysisReport,
    AnalysisRequest,
    EntropyFinding,
    PortFinding,
    RankedFinding,
    ReportValidationError,
    RequestValidationError,
    analyzer_arguments,
    report_path_for,
)
from capture_models import (
    CAPTURE_AUTHORIZATION_EVENT,
    CAPTURE_PREFLIGHT_EVENT,
    CAPTURE_STARTED_EVENT,
    CAPTURE_VALIDATED_EVENT,
    CAPTURE_NO_TRAFFIC_EVENT,
    CaptureRequest,
    CaptureValidationError,
    DeviceInfo,
    capture_session_arguments,
    default_capture_path,
    devices_from_json,
    validate_capture_request,
)
from finding_enrichment import (
    EndpointEnrichment,
    EndpointEnrichmentResult,
    classify_address,
    describe_port,
    parse_enrichment_result_output,
)
from capture_receipt import (
    CAPTURE_RECEIPT_EVENT,
    MAXIMUM_RECEIPT_BYTES,
    CaptureReceipt,
    CaptureReceiptError,
    parse_capture_receipt,
    receipt_is_success,
    validate_receipt_binding,
)
from macos_application import set_macos_application_icon
from report_loader import ReportLoadWorker
from packet_view import PacketTimelineWidget, PacketNavigation
from session_view import SessionTimelineWidget, SessionNavigation
from dns_view import DnsSessionWidget, DnsNavigation
from dns_sessions import DnsAssociationIdentity, DnsSessionValidationError, dns_association_for_identity, observed_dns_frames, dns_messages_for_frame, dns_diagnostics_for_frame
from packet_timeline import PacketIdentity, PacketQueryValidationError
from packet_sessions import (
    SessionIdentity, SessionValidationError, session_for_identity, session_for_packet,
    frames_for_session, ungrouped_for_packet,
)

ROOT = Path(__file__).resolve().parent
ANALYZER = ROOT / "analyze.py"
ANALYZER_PREVIEW = ROOT / "analyze_preview.py"
CAPTURE_ANALYZER = ROOT / "analyze_captured.py"
REVIEWED_ANALYZER = ROOT / "analyze_reviewed.py"
SETUP_CHECKS = ROOT / "setup_checks.py"
ENDPOINT_ENRICHER = ROOT / "enrich_endpoints.py"
LOCAL_ENDPOINT_ENRICHER = ROOT / "local_endpoint_enrichment.py"
DEVICE_DISCOVERY = ROOT / "capture_devices.py"
CAPTURE_SESSION = ROOT / "capture_session.py"
CAPTURE_SUPPORT_SETUP = ROOT / "scripts" / "setup_rvi_capture.py"
DEFAULT_EXPORT_DIRECTORY = ROOT / "exports"
DEFAULT_CAPTURE_DIRECTORY = ROOT / "captures"
APP_ICON = ROOT / "assets" / "rvi-sentinel-app-icon.png"
GUI_INSTANCE_LOCK = Path(tempfile.gettempdir()) / "rvi-sentinel-gui.lock"


def python_helper_environment() -> QProcessEnvironment:
    """Match owned Python pipes to the GUI's UTF-8 text protocol on every host.

    Windows redirected Python streams otherwise use the ANSI locale encoding.
    This creates a child environment without changing the application's process
    environment or binary decoder inputs.
    """
    environment = QProcessEnvironment.systemEnvironment()
    environment.insert("PYTHONUNBUFFERED", "1")
    environment.insert("PYTHONIOENCODING", "utf-8")
    return environment


def passive_analysis_arguments(
    request: AnalysisRequest, receipt: CaptureReceipt | None,
    preview_script: Path, captured_script: Path,
) -> tuple[list[str], str | None]:
    """Bind guided passive exports to the verified receipt's original-byte digest."""
    if receipt is not None and receipt.artifact is not None and request.capture_path == receipt.output_path:
        digest = receipt.artifact.sha256
        return [*analyzer_arguments(request, captured_script), "--expected-sha256", digest], digest
    return analyzer_arguments(request, preview_script), None


class GuiInstanceAlreadyRunningError(RuntimeError):
    """Raised when another RVI-Sentinel GUI process owns the instance lock."""


def acquire_gui_instance_lock(path: Path) -> QLockFile:
    lock = QLockFile(str(path))
    lock.setStaleLockTime(30_000)
    if not lock.tryLock(0):
        raise GuiInstanceAlreadyRunningError(
            "Another RVI-Sentinel window is already running. Close the existing window "
            "before launching a new build."
        )
    return lock


def load_application_icon(path: Path) -> QIcon:
    if not path.is_file():
        raise FileNotFoundError(f"RVI-Sentinel application icon not found: {path}")
    icon = QIcon(str(path))
    if icon.isNull():
        raise ValueError(f"RVI-Sentinel application icon could not be decoded: {path}")
    return icon


class CaptureSetupDialog(QDialog):
    """Collect one explicit, bounded capture request from the user."""

    def __init__(self, devices: tuple[DeviceInfo, ...], parent: QWidget) -> None:
        super().__init__(parent)
        self.devices = tuple(device for device in devices if device.connected)
        self.device_field = QComboBox()
        self.duration_field = QSpinBox()
        self.format_field = QComboBox()
        self.output_field = QLineEdit()
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok
        )
        self.configure_dialog()

    def configure_dialog(self) -> None:
        self.setWindowTitle("New iPhone/iPad Capture")
        self.setMinimumWidth(640)
        layout = QVBoxLayout(self)

        explanation = QLabel(
            "Choose a connected, trusted iPhone or iPad and a bounded capture duration. "
            "RVI-Sentinel records packet metadata to a local PCAP/PCAPNG file; it does not "
            "decrypt protected payloads."
        )
        explanation.setWordWrap(True)
        explanation.setProperty("role", "notice")
        layout.addWidget(explanation)

        form_group = QGroupBox("Capture settings")
        form = QGridLayout(form_group)
        form.setColumnStretch(1, 1)

        for device in self.devices:
            self.device_field.addItem(
                f"{device.name} — {device.operating_system}", device.udid
            )
        if not self.devices:
            self.device_field.addItem("No connected iPhone or iPad found")
            self.device_field.setEnabled(False)
        self.device_field.setAccessibleName("Connected iOS device")
        self.device_field.setObjectName("captureDeviceField")

        self.duration_field.setRange(5, 3_600)
        self.duration_field.setValue(60)
        self.duration_field.setSuffix(" seconds")
        self.duration_field.setAccessibleName("Capture duration in seconds")
        self.duration_field.setObjectName("captureDurationField")

        self.format_field.addItems(("pcapng", "pcap"))
        self.format_field.setAccessibleName("Capture format")
        self.format_field.setObjectName("captureFormatField")

        initial_device_name = self.devices[0].name if self.devices else "ios-device"
        initial_output = default_capture_path(
            DEFAULT_CAPTURE_DIRECTORY, initial_device_name, datetime.now(), "pcapng"
        )
        self.output_field.setText(str(initial_output))
        self.output_field.setAccessibleName("Capture output file")
        self.output_field.setObjectName("captureOutputField")
        output_button = QPushButton("Choose…")
        output_button.setObjectName("captureOutputBrowseButton")

        form.addWidget(QLabel("Device"), 0, 0)
        form.addWidget(self.device_field, 0, 1, 1, 2)
        form.addWidget(QLabel("Duration"), 1, 0)
        form.addWidget(self.duration_field, 1, 1, 1, 2)
        form.addWidget(QLabel("Format"), 2, 0)
        form.addWidget(self.format_field, 2, 1, 1, 2)
        form.addWidget(QLabel("Save capture as"), 3, 0)
        form.addWidget(self.output_field, 3, 1)
        form.addWidget(output_button, 3, 2)
        layout.addWidget(form_group)

        permission_note = QLabel(capture_permission_note(platform.system()))
        permission_note.setWordWrap(True)
        layout.addWidget(permission_note)
        layout.addWidget(self.buttons)

        start_button = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        start_button.setText("Start Capture")
        start_button.setEnabled(bool(self.devices))
        output_button.clicked.connect(self.choose_output)
        self.format_field.currentTextChanged.connect(self.update_output_extension)
        self.buttons.accepted.connect(self.accept_request)
        self.buttons.rejected.connect(self.reject)

    def choose_output(self) -> None:
        capture_format = self.format_field.currentText()
        selected, _filter = QFileDialog.getSaveFileName(
            self,
            "Save iPhone/iPad capture",
            self.output_field.text(),
            f"{capture_format.upper()} captures (*.{capture_format});;All files (*)",
        )
        if selected:
            path = Path(selected)
            if path.suffix.lower() != f".{capture_format}":
                path = path.with_suffix(f".{capture_format}")
            self.output_field.setText(str(path))

    def update_output_extension(self, capture_format: str) -> None:
        output_text = self.output_field.text().strip()
        if output_text:
            self.output_field.setText(str(Path(output_text).with_suffix(f".{capture_format}")))

    def capture_request(self) -> CaptureRequest:
        index = self.device_field.currentIndex()
        if index < 0 or index >= len(self.devices):
            raise CaptureValidationError("Select a connected iPhone or iPad.")
        output_text = self.output_field.text().strip()
        if not output_text:
            raise CaptureValidationError("Choose where to save the capture.")
        request = CaptureRequest(
            device=self.devices[index],
            output_path=Path(output_text).expanduser().resolve(),
            duration_seconds=self.duration_field.value(),
            capture_format=self.format_field.currentText(),
            analyze_after_capture=False,
        )
        validate_capture_request(request)
        return request

    def accept_request(self) -> None:
        try:
            self.capture_request()
        except CaptureValidationError as error:
            message = QMessageBox(self)
            message.setIcon(QMessageBox.Icon.Critical)
            message.setWindowTitle("Invalid capture settings")
            message.setText("Invalid capture settings")
            message.setInformativeText(str(error))
            message.exec()
            return
        self.accept()


def capture_permission_note(host_system: str) -> str:
    if host_system == "Darwin":
        return (
            "macOS uses Apple rvictl and tcpdump. A native administrator authorization prompt "
            "appears only when the timed capture starts; RVI-Sentinel never reads or stores your password."
        )
    if host_system == "Linux":
        return (
            "Linux requires libimobiledevice and a running usbmuxd service. The upstream "
            "gh2o/rvi_capture backend must also be installed locally."
        )
    if host_system == "Windows":
        return (
            "Windows requires iTunes or Apple Mobile Device Support with its service running. "
            "The upstream gh2o/rvi_capture backend must also be installed locally."
        )
    return f"iOS capture is not supported on {host_system}."


@dataclass(frozen=True)
class ReportLoadContext:
    generation: int
    request: AnalysisRequest
    path: Path
    expected_sha256: str | None
    baseline_update: bool


class RviSentinelWindow(QMainWindow):
    report_load_finished = Signal()

    """Main capture and analysis window backed by the existing CLI tools."""

    def __init__(self) -> None:
        self._workspace_icons_ready: bool = False
        super().__init__()
        self.icon_refresh_timer = QTimer(self)
        self.icon_refresh_timer.setSingleShot(True)
        self.icon_refresh_timer.timeout.connect(self.refresh_icons)
        self._workspace_palette_key: int = QApplication.palette().cacheKey()
        self.process = QProcess(self)
        self.enrichment_process = QProcess(self)
        self.device_process = QProcess(self)
        self.capture_process = QProcess(self)
        self.setup_process = QProcess(self)
        self.check_process = QProcess(self)
        self.enrichment_timer = QTimer(self)
        self.enrichment_timer.setSingleShot(True)
        self.analysis_cancel_timer = QTimer(self)
        self.analysis_cancel_timer.setSingleShot(True)
        self.capture_cancel_timer = QTimer(self)
        self.capture_cancel_timer.setSingleShot(True)
        self.capture_timer = QTimer(self)
        self.capture_timer.setInterval(1_000)
        self.enrichment_timed_out = False
        self.enrichment_cancel_requested = False
        self.analysis_cancel_requested = False
        self.endpoint_findings: tuple[RankedFinding, ...] = ()
        self.active_enrichment_source: Literal["local", "ptr"] | None = None
        self.endpoint_enrichment_result: EndpointEnrichmentResult | None = None
        self.active_request: AnalysisRequest | None = None
        self.active_report_path: Path | None = None
        self.active_capture_request: CaptureRequest | None = None
        self.discovered_devices: tuple[DeviceInfo, ...] = ()
        self.capture_elapsed_seconds = 0
        self.capture_countdown_started = False
        self.capture_event_buffer = ""
        self.capture_error_buffer = ""
        self.capture_cancel_requested = False
        self.capture_request_id: str | None = None
        self.capture_receipt: CaptureReceipt | None = None
        self.capture_receipt_error: str | None = None
        self.completed_capture_receipt: CaptureReceipt | None = None
        self.active_analysis_capture_sha256: str | None = None
        self.capture_no_traffic = False
        self.last_capture_request: CaptureRequest | None = None
        self.completed_capture_path: Path | None = None
        self.preview_request: AnalysisRequest | None = None
        self.preview_sha256: str | None = None
        self.baseline_updated_for_report = False
        self.updating_baseline = False
        self.manual_baseline_selected = False
        self.setup_check_results: list[tuple[str, bool]] = []
        self.summary_labels: dict[str, QLabel] = {}

        self.report_worker: ReportLoadWorker | None = None
        self.report_load_context: ReportLoadContext | None = None
        self.pending_report_load: ReportLoadContext | None = None
        self.report_generation = 0
        self.report_loading = False
        self.closing_requested = False
        self.quit_requested = False
        self.overview_cards: tuple[tuple[Destination, QPushButton], ...] = ()
        self.navigation_sidebar = QListWidget()
        self.detail_stack = QStackedWidget()
        self.result_selector = QComboBox()
        self.shortcut_pages: dict[Destination, QWidget] = {}
        self.workspace_tabs = QTabWidget()
        self.results_tabs = QTabWidget()
        self.packet_timeline = PacketTimelineWidget(self)
        self.packet_timeline.shutdown_complete.connect(self.continue_close)
        self.session_timeline = SessionTimelineWidget(self)
        self.session_timeline.shutdown_complete.connect(self.continue_close)
        self.session_timeline.session_open_requested.connect(self.show_session_members)
        self.session_timeline.ungrouped_open_requested.connect(self.show_ungrouped_packets)
        self.session_timeline.packet_return_requested.connect(self.return_from_session_to_packets)
        self.session_timeline.index_ready.connect(self.refresh_packet_session_context)
        self.dns_evidence_view = DnsSessionWidget(self)
        self.dns_evidence_view.shutdown_complete.connect(self.continue_close)
        self.session_timeline.dns_evidence_requested.connect(self.show_session_dns_evidence)
        self.session_timeline.dns_return_requested.connect(self.return_to_dns_evidence)
        self.packet_timeline.return_dns_requested.connect(self.return_to_dns_evidence)
        self.dns_evidence_view.query_packet_requested.connect(self.show_dns_packet)
        self.dns_evidence_view.response_packet_requested.connect(self.show_dns_packet)
        self.dns_evidence_view.superseding_packet_requested.connect(self.show_dns_packet)
        self.dns_evidence_view.matched_packets_requested.connect(self.show_dns_matched_packets)
        self.dns_evidence_view.session_requested.connect(self.show_dns_session)
        self.dns_evidence_view.observed_packets_requested.connect(self.show_observed_dns_packets)
        self.dns_evidence_view.return_session_requested.connect(self.return_from_dns_to_session)
        self.dns_navigation_origin: DnsNavigation | None = None
        self.dns_session_origin: SessionNavigation | None = None
        self.packet_timeline.packet_selected.connect(self.update_packet_session_context)
        self.packet_timeline.owning_session_requested.connect(self.show_owning_session)
        self.packet_timeline.back_to_sessions_requested.connect(self.return_to_sessions)
        self.packet_timeline.restore_timeline_requested.connect(self.return_to_packet_context)
        self.session_navigation_origin: SessionNavigation | None = None
        self.packet_navigation_origin: PacketNavigation | None = None
        self.packet_session_jump_origin: PacketNavigation | None = None
        self.device_table = create_device_table()
        self.capture_status_label = QLabel("Connect and unlock an iPhone or iPad, then refresh devices.")
        self.capture_progress = QProgressBar()
        self.capture_console = QTextEdit()
        self.refresh_devices_button = QPushButton("Refresh Devices")
        self.new_capture_button = QPushButton("New Capture…")
        self.cancel_capture_button = QPushButton("Cancel Capture")
        self.install_capture_support_button = QPushButton("Install Capture Support")
        self.retry_traffic_button = QPushButton("Retry Traffic Check")
        self.advanced_toggle = QCheckBox("Advanced details")
        self.copy_diagnostics_button = QPushButton("Copy diagnostics")
        self.completion_group = QGroupBox("Saved capture evidence")
        self.completion_summary = QLabel()
        self.completion_analyze_button = QPushButton("Analyze without updating baseline")
        self.completion_location_button = QPushButton("Open file location")
        self.completion_again_button = QPushButton("Capture again")
        self.check_button = QPushButton("Run setup checks")
        self.check_table = QTableWidget(0, 3)
        self.check_status = QLabel("Run checks before capturing.")

        self.capture_field = QLineEdit()
        self.baseline_field = QLineEdit()
        self.export_field = QLineEdit(str(DEFAULT_EXPORT_DIRECTORY))
        self.geoip_field = QLineEdit()
        self.entropy_field = QDoubleSpinBox()
        self.top_field = QSpinBox()
        self.command_field = QLineEdit()
        self.status_label = QLabel("Ready to analyze an authorized capture.")
        self.console = QTextEdit()
        self.interpretation = QTextEdit()
        self.analyze_button = QPushButton("Analyze Capture")
        self.cancel_analysis_button = QPushButton("Cancel")
        self.add_to_baseline_button = QPushButton("Update baseline")
        self.open_exports_button = QPushButton("Open exports")
        self.resolve_ptr_button = QPushButton("Resolve current PTR names")
        self.cancel_enrichment_button = QPushButton("Cancel endpoint lookup")
        self.ptr_resolver_notice = QLabel(
            "PTR is optional: this action sends endpoint addresses to the configured DNS resolver. "
            "Current PTR names are separate from captured DNS/SNI and do not change reports or baselines."
        )
        self.enrichment_status_label = QLabel("Local endpoint context appears after analysis; PTR is not requested.")

        self.endpoints_table = create_endpoint_table()
        self.domains_table = create_ranked_table(("DNS name", "Queries", "Baseline"))
        self.tls_table = create_ranked_table(("TLS SNI", "Observations", "Baseline"))
        self.protocols_table = create_ranked_table(("Protocol", "Packets", "Baseline"))
        self.ports_table = create_port_table()
        self.entropy_table = create_entropy_table()

        self.configure_window()
        self.build_interface()
        self.set_advanced_details_visible(False)
        self.connect_signals()
        self.refresh_command_preview()
        QTimer.singleShot(0, self.refresh_devices)

    def configure_window(self) -> None:
        self.setWindowTitle("RVI-Sentinel")
        self.setWindowIcon(load_application_icon(APP_ICON))
        self.resize(1180, 820)
        self.setMinimumSize(900, 680)
        self.setAcceptDrops(True)
        self.setStyleSheet(shell_stylesheet())

    def build_interface(self) -> None:
        """Keep evidence page instances while navigating a native desktop sidebar."""
        root_widget = QWidget()
        root_layout = QHBoxLayout(root_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        sidebar_panel = QWidget(root_widget)
        sidebar_panel.setObjectName("sidebarPanel")
        sidebar_layout = QVBoxLayout(sidebar_panel)
        sidebar_layout.setContentsMargins(10, 18, 10, 12)
        sidebar_layout.setSpacing(14)
        branding = QHBoxLayout()
        logo = QLabel(sidebar_panel)
        logo.setObjectName("applicationLogo")
        logo.setAccessibleName("RVI-Sentinel route application icon")
        logo.setPixmap(self.windowIcon().pixmap(32, 32))
        logo.setFixedSize(32, 32)
        branding.addWidget(logo)
        title = QLabel("RVI-Sentinel", sidebar_panel)
        title.setObjectName("applicationTitle")
        branding.addWidget(title)
        sidebar_layout.addLayout(branding)
        populate_sidebar(self.navigation_sidebar)
        sidebar_layout.addWidget(self.navigation_sidebar, 1)
        local_notice = plain_label("Python • local analysis", "localAnalysisNotice", sidebar_panel)
        sidebar_layout.addWidget(local_notice)
        root_layout.addWidget(sidebar_panel)

        detail = QWidget(root_widget)
        detail_layout = QVBoxLayout(detail)
        detail_layout.setContentsMargins(18, 12, 18, 12)
        detail_layout.setSpacing(10)
        heading = QVBoxLayout()
        heading.setSpacing(2)
        self.page_title = plain_label("Overview", "pageTitle", detail)
        self.page_subtitle = plain_label("Local capture and evidence analysis", "pageSubtitle", detail)
        heading.addWidget(self.page_title)
        heading.addWidget(self.page_subtitle)
        header = QHBoxLayout()
        header.addLayout(heading, 1)
        self.advanced_toggle.setObjectName("advancedDetailsToggle")
        self.copy_diagnostics_button.setObjectName("copyDiagnosticsButton")
        header.addWidget(self.advanced_toggle)
        detail_layout.addLayout(header)
        self.detail_stack.setObjectName("workspaceStack")
        overview, cards = overview_page(detail)
        self.overview_cards = cards
        self.shortcut_pages["overview"] = overview
        self.detail_stack.addWidget(overview)
        for key, button in cards:
            button.clicked.connect(partial(self.show_destination, key))

        self.workspace_tabs.setObjectName("workspaceTabs")
        self.workspace_tabs.setDocumentMode(True)
        self.workspace_tabs.addTab(self.create_capture_workspace(), "Capture iPhone/iPad")
        self.workspace_tabs.addTab(self.create_analysis_workspace(), "Analyze Capture")
        self.workspace_tabs.addTab(self.create_setup_workspace(), "Check setup")
        self.workspace_tabs.tabBar().hide()
        self.detail_stack.addWidget(self.workspace_tabs)
        for key in ("baselines", "exports", "diagnostics"):
            page = self.create_shortcut_page(key)
            self.shortcut_pages[key] = page
            self.detail_stack.addWidget(page)
        detail_layout.addWidget(self.detail_stack, 1)
        root_layout.addWidget(detail, 1)
        self.setCentralWidget(root_widget)
        self.navigation_sidebar.currentRowChanged.connect(self.sidebar_destination_changed)
        self.workspace_tabs.currentChanged.connect(self.workspace_destination_changed)
        self.results_tabs.currentChanged.connect(self.sync_result_selection)
        self.result_selector.currentIndexChanged.connect(self.select_result)
        self.refresh_result_selector()
        self.show_destination("overview")
        self._workspace_icons_ready = True
        self.refresh_icons()

    def changeEvent(self, event: QEvent) -> None:
        """Coalesce icon refresh until Qt has propagated palette and display changes."""
        super().changeEvent(event)
        if self._workspace_icons_ready and not self.closing_requested and event.type() in (
            QEvent.Type.PaletteChange, QEvent.Type.ApplicationPaletteChange,
            QEvent.Type.StyleChange,
            QEvent.Type.ActivationChange, QEvent.Type.EnabledChange,
        ):
            self.icon_refresh_timer.start(0)

    def event(self, event: QEvent) -> bool:
        """Refresh fixed card pixmaps after Qt applies a new display scale."""
        handled = super().event(event)
        if (self._workspace_icons_ready and not self.closing_requested
                and event.type() == QEvent.Type.DevicePixelRatioChange):
            self.icon_refresh_timer.start(0)
        return handled

    @Slot()
    def refresh_icons(self) -> None:
        """Preserve sidebar items and evidence widgets when recoloring the glyphs."""
        palette_key = QApplication.palette().cacheKey()
        if palette_key != self._workspace_palette_key:
            self._workspace_palette_key = palette_key
            # Qt stylesheet palette roles must be repolished after theme changes.
            self.setStyleSheet(self.styleSheet())
        refresh_workspace_icons(self.navigation_sidebar, self.overview_cards)

    def create_shortcut_page(self, key: Destination) -> QWidget:
        """Expose current local choices and reuse explicit existing workflow actions."""
        content = QWidget(self)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(2, 4, 2, 4)
        layout.setSpacing(14)
        if key == "baselines":
            description = "Choose the history for this investigation. Preview analysis leaves it unchanged. Apply reviewed findings using Update baseline in Analysis."
            self.baseline_path_label = plain_label(self.baseline_field.text() or "No baseline selected", "baselinePath", content)
            self.baseline_path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            choose = QPushButton("Choose baseline…", content)
            choose.setObjectName("baselineShortcutBrowseButton")
            choose.clicked.connect(self.choose_baseline)
            review = QPushButton("Review findings in Analysis", content)
            review.setObjectName("baselineReviewButton")
            review.clicked.connect(partial(self.show_destination, "analysis"))
            layout.addWidget(plain_label(description, "baselineExplanation", content))
            layout.addWidget(self.baseline_path_label)
            actions = QHBoxLayout()
            actions.addWidget(choose)
            actions.addWidget(review)
            actions.addStretch(1)
            layout.addLayout(actions)
            self.baseline_field.textChanged.connect(self.refresh_shortcut_paths)
        elif key == "exports":
            description = "Analysis writes JSON reports and CSV summaries to the selected local directory. Inspect packets, sessions, and DNS evidence in Analysis."
            self.export_path_label = plain_label(self.export_field.text(), "exportPath", content)
            self.export_path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            choose = QPushButton("Choose directory…", content)
            choose.setObjectName("exportShortcutBrowseButton")
            choose.clicked.connect(self.choose_export_directory)
            self.export_shortcut_open = QPushButton("Open local exports", content)
            self.export_shortcut_open.setObjectName("exportShortcutOpenButton")
            self.export_shortcut_open.clicked.connect(self.open_exports_button.click)
            layout.addWidget(plain_label(description, "exportExplanation", content))
            layout.addWidget(self.export_path_label)
            actions = QHBoxLayout()
            actions.addWidget(choose)
            actions.addWidget(self.export_shortcut_open)
            actions.addStretch(1)
            layout.addLayout(actions)
            self.export_field.textChanged.connect(self.refresh_shortcut_paths)
        elif key == "diagnostics":
            layout.addWidget(plain_label(
                "Copy local setup and recording status for troubleshooting. The copied text excludes device identifiers, private paths, and packet contents.",
                "diagnosticsExplanation", content,
            ))
            self.diagnostics_status = plain_label("", "diagnosticsStatus", content)
            self.diagnostics_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(self.diagnostics_status)
            self.copy_diagnostics_button.clicked.connect(self.copy_diagnostics)
            layout.addWidget(self.copy_diagnostics_button, 0, Qt.AlignmentFlag.AlignLeft)
            setup = QPushButton("Review setup checks", content)
            setup.setObjectName("diagnosticsSetupButton")
            setup.clicked.connect(partial(self.show_destination, "setup"))
            layout.addWidget(setup, 0, Qt.AlignmentFlag.AlignLeft)
        else:
            raise ValueError(f"Destination has no shortcut page: {key}")
        layout.addStretch(1)
        return scroll_page(content, key + "Page", self)

    @Slot()
    def refresh_shortcut_paths(self) -> None:
        self.baseline_path_label.setText(self.baseline_field.text() or "No baseline selected")
        self.export_path_label.setText(self.export_field.text() or "No export directory selected")
        self.export_shortcut_open.setEnabled(self.open_exports_button.isEnabled())

    def show_destination(self, key: Destination) -> None:
        """Navigate only; analysis, capture, enrichment and persistence stay explicit."""
        destination = destination_for_key(key)
        with QSignalBlocker(self.navigation_sidebar):
            self.navigation_sidebar.setCurrentRow(DESTINATIONS.index(destination))
        if destination.workspace_index is not None:
            with QSignalBlocker(self.workspace_tabs):
                self.workspace_tabs.setCurrentIndex(destination.workspace_index)
            self.detail_stack.setCurrentWidget(self.workspace_tabs)
        else:
            self.detail_stack.setCurrentWidget(self.shortcut_pages[key])
        self.page_title.setText(destination.title)
        self.page_subtitle.setText(destination.subtitle)
        self.refresh_shortcut_paths()
        if key == "diagnostics":
            receipt = self.capture_receipt if self.capture_receipt_error is None else None
            self.diagnostics_status.setText(
                f"Capture host: {platform.system()}\nSetup: {self.check_status.text()}\n"
                f"Recording outcome: {receipt.capture_outcome if receipt is not None else 'unverified'}\n"
                f"Artifact validation: {receipt.validation_status if receipt is not None else 'unverified'}"
            )

    @Slot(int)
    def sidebar_destination_changed(self, row: int) -> None:
        if 0 <= row < len(DESTINATIONS):
            self.show_destination(DESTINATIONS[row].key)

    @Slot(int)
    def workspace_destination_changed(self, index: int) -> None:
        for destination in DESTINATIONS:
            if destination.workspace_index == index:
                self.show_destination(destination.key)
                return

    def refresh_result_selector(self) -> None:
        """Store original page indexes, including advanced-only Console visibility."""
        with QSignalBlocker(self.result_selector):
            self.result_selector.clear()
            for index in range(self.results_tabs.count()):
                if self.results_tabs.isTabVisible(index):
                    self.result_selector.addItem(self.results_tabs.tabText(index), index)
            self.result_selector.setCurrentIndex(self.result_selector.findData(self.results_tabs.currentIndex()))

    @Slot(int)
    def sync_result_selection(self, index: int) -> None:
        with QSignalBlocker(self.result_selector):
            self.result_selector.setCurrentIndex(self.result_selector.findData(index))

    @Slot(int)
    def select_result(self, row: int) -> None:
        index: object = self.result_selector.itemData(row)
        if type(index) is int and 0 <= index < self.results_tabs.count() and self.results_tabs.isTabVisible(index):
            self.results_tabs.setCurrentIndex(index)

    def create_capture_workspace(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        intro = QLabel(
            "1. Connect and trust the iPhone or iPad.  2. Refresh the device list.  "
            "3. Choose New Capture to select the device, duration, format, and local output file."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        device_group = QGroupBox("Connected Apple mobile devices")
        device_layout = QVBoxLayout(device_group)
        host_label = QLabel(
            f"Capture host: {platform.system()} • {capture_backend_summary(platform.system())}"
        )
        host_label.setObjectName("captureBackendLabel")
        device_layout.addWidget(host_label)
        device_layout.addWidget(self.device_table, 1)

        device_actions = QHBoxLayout()
        self.refresh_devices_button.setObjectName("refreshDevicesButton")
        self.new_capture_button.setObjectName("newCaptureButton")
        self.cancel_capture_button.setObjectName("cancelCaptureButton")
        self.install_capture_support_button.setObjectName("installCaptureSupportButton")
        self.new_capture_button.setEnabled(False)
        self.cancel_capture_button.setEnabled(False)
        self.install_capture_support_button.setVisible(platform.system() in {"Linux", "Windows"})
        device_actions.addWidget(self.refresh_devices_button)
        device_actions.addWidget(self.new_capture_button)
        device_actions.addWidget(self.cancel_capture_button)
        device_actions.addWidget(self.install_capture_support_button)
        self.retry_traffic_button.setObjectName("retryTrafficButton")
        self.retry_traffic_button.setVisible(False)
        device_actions.addWidget(self.retry_traffic_button)
        device_actions.addStretch(1)
        device_layout.addLayout(device_actions)
        layout.addWidget(device_group, 2)

        progress_group = QGroupBox("Capture activity")
        progress_layout = QVBoxLayout(progress_group)
        self.capture_status_label.setObjectName("captureStatusLabel")
        self.capture_status_label.setWordWrap(True)
        self.capture_progress.setObjectName("captureProgress")
        self.capture_progress.setRange(0, 1)
        self.capture_progress.setValue(0)
        self.capture_progress.setFormat("Ready")
        self.capture_console.setObjectName("captureConsole")
        self.capture_console.setAccessibleName("Capture activity log")
        self.capture_console.setReadOnly(True)
        self.capture_console.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        console_font = QFont("Menlo")
        console_font.setStyleHint(QFont.StyleHint.Monospace)
        self.capture_console.setFont(console_font)
        progress_layout.addWidget(self.capture_status_label)
        progress_layout.addWidget(self.capture_progress)
        self.capture_console.setVisible(False)
        progress_layout.addWidget(self.capture_console, 1)
        layout.addWidget(progress_group, 1)

        completion_layout = QVBoxLayout(self.completion_group)
        self.completion_group.setObjectName("captureCompletionCard")
        self.completion_summary.setObjectName("captureCompletionSummary")
        self.completion_analyze_button.setObjectName("analyzeSavedCaptureButton")
        self.completion_location_button.setObjectName("openSavedCaptureLocationButton")
        self.completion_summary.setWordWrap(True)
        self.completion_summary.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        completion_layout.addWidget(self.completion_summary)
        completion_actions = QHBoxLayout()
        for button in (self.completion_analyze_button, self.completion_location_button, self.completion_again_button):
            completion_actions.addWidget(button)
        completion_actions.addStretch(1)
        completion_layout.addLayout(completion_actions)
        self.completion_group.setVisible(False)
        layout.addWidget(self.completion_group)

        privacy = QLabel(
            "Captures stay at the local path you choose. Only capture files you are authorized "
            "to inspect. RVI-Sentinel does not upload captures or device identifiers."
        )
        privacy.setWordWrap(True)
        privacy.setProperty("role", "notice")
        layout.addWidget(privacy)
        return page

    def create_setup_workspace(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        explanation = QLabel(
            "Check the selected phone and this computer before capturing. On a Chromebook, "
            "share the USB device with Linux in Settings > Developers > Linux > USB preferences. "
            "USB forwarding support can vary by device. "
            '<a href="https://developers.google.com/chromeos/app-development/develop/linux-on-chromeos-faq">'
            "ChromeOS Linux USB guidance</a>."
        )
        explanation.setWordWrap(True)
        explanation.setOpenExternalLinks(True)
        layout.addWidget(explanation)
        self.check_button.setObjectName("runSetupChecksButton")
        layout.addWidget(self.check_button)
        self.check_status.setObjectName("setupCheckStatus")
        layout.addWidget(self.check_status)
        self.check_table.setObjectName("setupCheckTable")
        self.check_table.setHorizontalHeaderLabels(("Check", "Result", "What to do"))
        self.check_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.check_table.setWordWrap(True)
        self.check_table.verticalHeader().setVisible(False)
        self.check_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.check_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.check_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.check_table, 1)
        return page

    def create_analysis_workspace(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        self.analysis_configuration_group = self.create_configuration_group()
        self.analysis_configuration_group.setObjectName("analysisConfiguration")
        self.analysis_configuration_toggle = QPushButton("Show settings")
        self.analysis_configuration_toggle.setObjectName("analysisConfigurationToggle")
        self.analysis_configuration_toggle.setAccessibleName("Show or hide analysis configuration")
        self.analysis_configuration_toggle.clicked.connect(self.toggle_analysis_configuration)
        self.analysis_configuration_group.hide()
        layout.addWidget(self.analysis_configuration_group)
        layout.addLayout(self.create_action_row())
        results = self.create_results_tabs()
        result_row = QHBoxLayout()
        result_row.addWidget(QLabel("Show"))
        self.result_selector.setObjectName("analysisResultSelector")
        self.result_selector.setAccessibleName("Analysis result page")
        self.result_selector.setMinimumWidth(160)
        result_row.addWidget(self.result_selector)
        result_row.addStretch(1)
        open_capture = QPushButton("Open capture…")
        open_capture.setObjectName("analysisOpenCaptureButton")
        open_capture.clicked.connect(self.choose_capture)
        result_row.addWidget(open_capture)
        result_row.addWidget(self.analysis_configuration_toggle)
        layout.addLayout(result_row)
        layout.addWidget(results, 1)
        layout.addWidget(self.status_label)
        return page

    @Slot()
    def toggle_analysis_configuration(self) -> None:
        visible = self.analysis_configuration_group.isHidden()
        self.analysis_configuration_group.setVisible(visible)
        self.analysis_configuration_toggle.setText("Hide settings" if visible else "Show settings")

    @Slot(int)
    def make_evidence_space(self, index: int) -> None:
        """Keep packet/session rows and inspectors visible on ordinary screens."""
        if self.results_tabs.widget(index) in (self.packet_timeline, self.session_timeline, self.dns_evidence_view):
            self.analysis_configuration_group.hide()
            self.analysis_configuration_toggle.setText("Show settings")

    def create_configuration_group(self) -> QGroupBox:
        group = QGroupBox("Analysis configuration")
        layout = QGridLayout(group)
        layout.setColumnStretch(1, 1)

        capture_button = QPushButton("Browse…")
        capture_button.setObjectName("captureBrowseButton")
        baseline_button = QPushButton("Choose…")
        baseline_button.setObjectName("baselineBrowseButton")
        export_button = QPushButton("Choose…")
        export_button.setObjectName("exportBrowseButton")
        geoip_button = QPushButton("Choose…")
        geoip_button.setObjectName("geoipBrowseButton")

        self.capture_field.setPlaceholderText("Drop or select an authorized .pcap, .pcapng, or .cap file")
        self.capture_field.setAccessibleName("Capture file")
        self.baseline_field.setAccessibleName("Persistent baseline file")
        self.export_field.setAccessibleName("Export directory")
        self.geoip_field.setAccessibleName("Local GeoIP database")
        self.geoip_field.setPlaceholderText(
            "Optional local GeoLite2/GeoIP2 City or Country .mmdb"
        )
        self.geoip_field.setToolTip(
            "Local database only. RVI-Sentinel does not send endpoint IPs to a geolocation API."
        )

        self.entropy_field.setRange(0.0, 8.0)
        self.entropy_field.setDecimals(2)
        self.entropy_field.setSingleStep(0.1)
        self.entropy_field.setValue(3.5)
        self.entropy_field.setAccessibleName("DNS entropy threshold")

        self.top_field.setRange(0, 500)
        self.top_field.setValue(20)
        self.top_field.setAccessibleName("Top console result count")

        self.command_field.setReadOnly(True)
        self.command_field.setAccessibleName("Exact analyzer command")
        command_font = QFont("Menlo")
        command_font.setStyleHint(QFont.StyleHint.Monospace)
        self.command_field.setFont(command_font)

        layout.addWidget(QLabel("Capture"), 0, 0)
        layout.addWidget(self.capture_field, 0, 1)
        layout.addWidget(capture_button, 0, 2)
        layout.addWidget(QLabel("Baseline"), 1, 0)
        layout.addWidget(self.baseline_field, 1, 1)
        layout.addWidget(baseline_button, 1, 2)
        layout.addWidget(QLabel("Exports"), 2, 0)
        layout.addWidget(self.export_field, 2, 1)
        layout.addWidget(export_button, 2, 2)
        layout.addWidget(QLabel("Local GeoIP database"), 3, 0)
        layout.addWidget(self.geoip_field, 3, 1)
        layout.addWidget(geoip_button, 3, 2)
        layout.addWidget(QLabel("DNS entropy threshold"), 4, 0)
        layout.addWidget(self.entropy_field, 4, 1)
        layout.addWidget(QLabel("Console top count"), 4, 2)
        layout.addWidget(self.top_field, 4, 3)
        self.command_label = QLabel("Exact command")
        self.command_label.setVisible(False)
        self.command_field.setVisible(False)
        layout.addWidget(self.command_label, 5, 0)
        layout.addWidget(self.command_field, 5, 1, 1, 3)

        capture_button.clicked.connect(self.choose_capture)
        baseline_button.clicked.connect(self.choose_baseline)
        export_button.clicked.connect(self.choose_export_directory)
        geoip_button.clicked.connect(self.choose_geoip_database)
        return group

    def create_action_row(self) -> QGridLayout:
        layout = QGridLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(4)
        layout.setVerticalSpacing(2)
        self.analyze_button.setText("Preview analysis")
        self.analyze_button.setObjectName("analyzeButton")
        self.analyze_button.setToolTip("Analyze the saved file without updating the baseline.")
        self.analyze_button.setAccessibleName("Analyze the saved file without updating the baseline")
        self.cancel_analysis_button.setObjectName("cancelAnalysisButton")
        self.cancel_analysis_button.setAccessibleName("Cancel current capture-file analysis")
        self.cancel_analysis_button.setEnabled(False)
        self.add_to_baseline_button.setObjectName("addToBaselineButton")
        self.add_to_baseline_button.setToolTip("Apply the reviewed findings to the selected baseline after verifying the original capture.")
        self.add_to_baseline_button.setEnabled(False)
        self.open_exports_button.setObjectName("openExportsButton")
        self.open_exports_button.setEnabled(DEFAULT_EXPORT_DIRECTORY.exists())
        clear_button = QPushButton("Clear")
        clear_button.setObjectName("clearResultsButton")

        self.analyze_button.clicked.connect(self.start_analysis)
        self.cancel_analysis_button.clicked.connect(self.cancel_analysis)
        self.add_to_baseline_button.clicked.connect(self.add_findings_to_baseline)
        self.open_exports_button.clicked.connect(self.open_export_directory)
        clear_button.clicked.connect(self.clear_results)

        requirement = "tshark found" if shutil.which("tshark") else "tshark not found"
        requirement_label = QLabel(requirement)
        requirement_label.setObjectName("decoderRequirement")
        layout.addWidget(self.analyze_button, 0, 0)
        layout.addWidget(self.cancel_analysis_button, 0, 1)
        layout.addWidget(self.add_to_baseline_button, 0, 2)
        layout.addWidget(self.open_exports_button, 0, 3)
        layout.addWidget(clear_button, 0, 4)
        layout.setColumnStretch(5, 1)
        layout.addWidget(requirement_label, 0, 6)
        return layout

    def create_results_tabs(self) -> QTabWidget:
        tabs = self.results_tabs
        tabs.setDocumentMode(True)
        tabs.addTab(self.create_summary_tab(), "Summary")
        tabs.addTab(self.packet_timeline, "Packets")
        tabs.addTab(self.session_timeline, "Sessions")
        tabs.addTab(self.dns_evidence_view, "DNS evidence")
        self.interpretation.setReadOnly(True)
        self.interpretation.setAccessibleName("Findings interpretation")
        self.interpretation.setPlainText(
            "Analyze a capture to receive a plain-language explanation of the findings."
        )
        tabs.addTab(self.interpretation, "Interpretation")
        tabs.addTab(self.create_endpoint_tab(), "Endpoints")
        tabs.addTab(self.domains_table, "DNS")
        tabs.addTab(self.tls_table, "TLS SNI")
        tabs.addTab(self.protocols_table, "Protocols")
        tabs.addTab(self.ports_table, "Ports")
        tabs.addTab(self.entropy_table, "Entropy heuristic")

        self.console.setReadOnly(True)
        self.console.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        console_font = QFont("Menlo")
        console_font.setStyleHint(QFont.StyleHint.Monospace)
        self.console.setFont(console_font)
        tabs.addTab(self.console, "Console")
        tabs.currentChanged.connect(self.make_evidence_space)
        tabs.tabBar().hide()
        return tabs

    def create_endpoint_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.resolve_ptr_button.setObjectName("resolvePtrButton")
        self.resolve_ptr_button.setAccessibleName("Resolve current PTR names using the configured DNS resolver")
        self.resolve_ptr_button.setEnabled(False)
        self.cancel_enrichment_button.setObjectName("cancelEnrichmentButton")
        self.cancel_enrichment_button.setAccessibleName("Cancel current endpoint lookup")
        self.cancel_enrichment_button.setEnabled(False)
        self.ptr_resolver_notice.setObjectName("ptrResolverNotice")
        self.ptr_resolver_notice.setWordWrap(True)
        self.enrichment_status_label.setObjectName("endpointEnrichmentStatus")
        self.enrichment_status_label.setWordWrap(True)
        self.resolve_ptr_button.clicked.connect(self.resolve_current_ptr_names)
        self.cancel_enrichment_button.clicked.connect(self.cancel_endpoint_enrichment)
        actions = QHBoxLayout()
        actions.addWidget(self.resolve_ptr_button)
        actions.addWidget(self.cancel_enrichment_button)
        actions.addStretch(1)
        layout.addWidget(self.ptr_resolver_notice)
        layout.addLayout(actions)
        layout.addWidget(self.endpoints_table, 1)
        layout.addWidget(self.enrichment_status_label)
        return page

    def create_summary_tab(self) -> QWidget:
        """Show observed counts as cards and retain selectable original-file provenance."""
        content = QWidget(self)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(2, 4, 2, 4)
        layout.setSpacing(12)
        metrics = QGridLayout()
        metrics.setSpacing(10)
        fields = (
            ("packet_count", "Packets"), ("duration", "Duration"),
            ("endpoints", "Unique endpoints"), ("dns", "Unique DNS names"),
            ("tls", "Unique TLS SNI"), ("quic", "QUIC-like packets"),
        )
        for index, (key, caption) in enumerate(fields):
            card = QWidget(content)
            card.setProperty("role", "metricCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 10, 12, 10)
            label = plain_label("—", "metricValue", card)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.summary_labels[key] = label
            card_layout.addWidget(label)
            card_layout.addWidget(plain_label(caption, "metricCaption", card))
            metrics.addWidget(card, index // 3, index % 3)
            metrics.setColumnStretch(index % 3, 1)
        layout.addLayout(metrics)
        provenance = QGroupBox("Capture evidence", content)
        form = QFormLayout(provenance)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        for key, caption, name in (
            ("capture_path", "Path", "capturePath"),
            ("size_bytes", "Size", "captureSize"),
            ("first_packet", "First packet", "captureFirstPacket"),
            ("last_packet", "Last packet", "captureLastPacket"),
            ("capture_digest", "SHA-256", "captureDigest"),
            ("capture_integrity", "Import evidence", "captureIntegrity"),
            ("decoder_coverage", "Decoder coverage", "decoderCoverage"),
            ("packet_record_count", "Packet records", "packetRecordCount"),
        ):
            label = plain_label("—", name, provenance)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.summary_labels[key] = label
            form.addRow(caption, label)
        layout.addWidget(provenance)
        layout.addStretch(1)
        return scroll_page(content, "summaryPage", self)

    def connect_signals(self) -> None:
        self.capture_field.textChanged.connect(self.suggest_investigation_baseline)
        self.capture_field.textChanged.connect(self.refresh_command_preview)
        self.baseline_field.textChanged.connect(self.refresh_command_preview)
        self.export_field.textChanged.connect(self.refresh_command_preview)
        self.geoip_field.textChanged.connect(self.refresh_command_preview)
        self.entropy_field.valueChanged.connect(self.refresh_command_preview)
        self.top_field.valueChanged.connect(self.refresh_command_preview)

        self.process.readyReadStandardOutput.connect(self.read_standard_output)
        self.process.readyReadStandardError.connect(self.read_standard_error)
        self.process.finished.connect(self.analysis_finished)
        self.process.errorOccurred.connect(self.process_error)
        self.analysis_cancel_timer.timeout.connect(self.force_stop_analysis)
        self.enrichment_process.finished.connect(self.endpoint_enrichment_finished)
        self.enrichment_process.errorOccurred.connect(self.endpoint_enrichment_error)
        self.enrichment_timer.timeout.connect(self.endpoint_enrichment_timeout)
        self.refresh_devices_button.clicked.connect(self.refresh_devices)
        self.new_capture_button.clicked.connect(self.open_capture_dialog)
        self.cancel_capture_button.clicked.connect(self.cancel_capture)
        self.install_capture_support_button.clicked.connect(self.install_capture_support)
        self.device_process.finished.connect(self.device_discovery_finished)
        self.device_process.errorOccurred.connect(self.device_discovery_error)
        self.capture_process.readyReadStandardOutput.connect(self.read_capture_output)
        self.capture_process.readyReadStandardError.connect(self.read_capture_error)
        self.capture_process.finished.connect(self.capture_finished)
        self.capture_process.errorOccurred.connect(self.capture_process_error)
        self.capture_cancel_timer.timeout.connect(self.force_kill_capture)
        self.setup_process.readyReadStandardOutput.connect(self.read_setup_output)
        self.setup_process.readyReadStandardError.connect(self.read_setup_error)
        self.setup_process.finished.connect(self.capture_support_finished)
        self.setup_process.errorOccurred.connect(self.capture_support_error)
        self.capture_timer.timeout.connect(self.advance_capture_progress)
        self.retry_traffic_button.clicked.connect(self.retry_traffic_check)
        self.advanced_toggle.toggled.connect(self.set_advanced_details_visible)
        self.completion_analyze_button.clicked.connect(self.analyze_completed_capture)
        self.completion_location_button.clicked.connect(self.open_capture_location)
        self.completion_again_button.clicked.connect(self.open_capture_dialog)
        self.check_button.clicked.connect(self.run_setup_checks)
        self.check_process.finished.connect(self.setup_checks_finished)
        self.check_process.errorOccurred.connect(self.setup_checks_error)

    def set_advanced_details_visible(self, visible: bool) -> None:
        self.device_table.setColumnHidden(2, not visible)
        set_device_identifier_visibility(
            self.device_table, self.discovered_devices, visible
        )
        self.capture_console.setVisible(visible)
        self.command_field.setVisible(visible)
        self.command_label.setVisible(visible)
        console_index = self.results_tabs.indexOf(self.console)
        if console_index >= 0:
            if not visible and self.results_tabs.currentIndex() == console_index:
                self.results_tabs.setCurrentIndex(0)
            self.results_tabs.setTabVisible(console_index, visible)
            self.refresh_result_selector()

    def copy_diagnostics(self) -> None:
        checks = "\n".join(
            f"{name}: {'PASS' if passed else 'FAIL'}"
            for name, passed in self.setup_check_results
        )
        receipt = self.capture_receipt if self.capture_receipt_error is None else None
        outcome = receipt.capture_outcome if receipt is not None else "unverified"
        validation = receipt.validation_status if receipt is not None else "unverified"
        process_stop = (
            "verified stopped" if receipt is not None and receipt.cleanup.recording_process_stopped is True else
            "failed to stop" if receipt is not None and receipt.cleanup.recording_process_stopped is False else "unverified"
        )
        interface = receipt.cleanup.interface_status if receipt is not None else "unverified"
        failure_codes = ", ".join(f"{failure.stage}/{failure.code}" for failure in receipt.failures) if receipt is not None else "unavailable"
        text = (
            f"RVI-Sentinel diagnostics\nHost: {platform.system()}\n"
            f"Recording outcome: {outcome}\nArtifact validation: {validation}\n"
            f"Recording process: {process_stop}\nInterface cleanup: {interface}\n"
            f"Failure codes: {failure_codes or 'none'}\nSetup checks:\n{checks or 'not run'}\n"
            "No device identifiers, packet contents, or private paths are included."
        )
        QApplication.clipboard().setText(text)
        self.capture_status_label.setText("Redacted diagnostics copied to clipboard.")
        self.diagnostics_status.setText("Redacted diagnostics copied to clipboard.\n" + text)

    def run_setup_checks(self) -> None:
        if self.check_process.state() != QProcess.ProcessState.NotRunning:
            return
        output_path = self.last_capture_request.output_path.parent if self.last_capture_request else DEFAULT_CAPTURE_DIRECTORY
        arguments = [str(SETUP_CHECKS), "--output-dir", str(output_path)]
        selected = self.device_table.currentRow()
        if 0 <= selected < len(self.discovered_devices):
            arguments.extend(("--udid", self.discovered_devices[selected].udid))
        self.check_button.setEnabled(False)
        self.check_status.setText("Checking this computer and the selected phone…")
        self.check_process.setWorkingDirectory(str(ROOT))
        self.check_process.setProcessEnvironment(python_helper_environment())
        self.check_process.setProgram(sys.executable)
        self.check_process.setArguments(arguments)
        self.check_process.start()

    def setup_checks_finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        self.check_button.setEnabled(True)
        output = bytes(self.check_process.readAllStandardOutput()).decode("utf-8", errors="replace")
        error = bytes(self.check_process.readAllStandardError()).decode("utf-8", errors="replace")
        if exit_code != 0:
            self.check_status.setText(f"Setup check failed: {error.strip() or 'No diagnostics returned.'}")
            return
        try:
            payload: object = json.loads(output)
            if not isinstance(payload, dict) or not isinstance(payload.get("checks"), list):
                raise ValueError("Setup checks returned an invalid result structure.")
            rows = payload["checks"]
            self.check_table.setRowCount(len(rows))
            self.setup_check_results = []
            for index, row in enumerate(rows):
                if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not isinstance(row.get("passed"), bool) or not isinstance(row.get("detail"), str) or not isinstance(row.get("fix"), str):
                    raise ValueError(f"Setup check {index} has an invalid result.")
                name, passed, detail, fix = row["name"], row["passed"], row["detail"], row["fix"]
                self.setup_check_results.append((name, passed))
                self.check_table.setItem(index, 0, QTableWidgetItem(name))
                self.check_table.setItem(index, 1, QTableWidgetItem("PASS" if passed else "FAIL"))
                self.check_table.setItem(index, 2, QTableWidgetItem(detail if passed else f"{detail}  Fix: {fix}"))
                self.check_table.resizeRowToContents(index)
            failed = sum(not passed for _name, passed in self.setup_check_results)
            self.check_status.setText(f"{len(rows) - failed} passed, {failed} failed. Fix failed checks, then run again.")
        except (json.JSONDecodeError, ValueError) as error:
            self.check_status.setText(f"Could not read setup results: {error}")

    def setup_checks_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.Crashed:
            return
        self.check_button.setEnabled(True)
        self.check_status.setText(f"Could not run setup checks: {self.check_process.errorString()}")

    def refresh_devices(self) -> None:
        if self.closing_requested:
            return
        if self.device_process.state() != QProcess.ProcessState.NotRunning:
            return
        self.refresh_devices_button.setEnabled(False)
        self.new_capture_button.setEnabled(False)
        if self.completed_capture_path is None:
            self.capture_status_label.setText("Looking for physical iPhone and iPad devices…")
        self.capture_console.append(f"$ {shlex.join([sys.executable, str(DEVICE_DISCOVERY)])}")
        self.device_process.setWorkingDirectory(str(ROOT))
        self.device_process.setProcessEnvironment(python_helper_environment())
        self.device_process.setProgram(sys.executable)
        self.device_process.setArguments([str(DEVICE_DISCOVERY)])
        self.device_process.start()

    def device_discovery_finished(
        self, exit_code: int, _exit_status: QProcess.ExitStatus
    ) -> None:
        self.refresh_devices_button.setEnabled(True)
        output = bytes(self.device_process.readAllStandardOutput()).decode(
            "utf-8", errors="replace"
        )
        error_output = bytes(self.device_process.readAllStandardError()).decode(
            "utf-8", errors="replace"
        )
        if exit_code != 0:
            self.discovered_devices = ()
            populate_device_table(self.device_table, self.discovered_devices)
            detail = error_output.strip() or output.strip() or "No diagnostic output was returned."
            self.capture_console.append(detail)
            self.capture_status_label.setText(f"Device discovery failed: {detail}")
            self.new_capture_button.setEnabled(False)
            return
        try:
            devices = devices_from_json(output)
        except CaptureValidationError as error:
            self.discovered_devices = ()
            populate_device_table(self.device_table, self.discovered_devices)
            self.capture_console.append(str(error))
            self.capture_status_label.setText(str(error))
            self.new_capture_button.setEnabled(False)
            return
        self.discovered_devices = devices
        populate_device_table(self.device_table, devices)
        connected_count = sum(1 for device in devices if device.connected)
        self.new_capture_button.setEnabled(connected_count > 0)
        if self.completed_capture_receipt is not None:
            return
        elif connected_count:
            self.capture_status_label.setText(
                f"Ready: {connected_count} connected iOS device(s) available for capture."
            )
        elif devices:
            self.capture_status_label.setText(
                "An iPhone/iPad was recognized but is offline. Connect it by USB, unlock it, "
                "tap Trust if prompted, and refresh."
            )
        else:
            self.capture_status_label.setText(
                "No physical iPhone or iPad was found. Connect by USB, unlock, trust this host, "
                "and choose Refresh Devices."
            )
        self.new_capture_button.setEnabled(connected_count > 0)

    def device_discovery_error(self, error: QProcess.ProcessError) -> None:
        self.refresh_devices_button.setEnabled(True)
        self.new_capture_button.setEnabled(False)
        detail = f"Could not start device discovery: {error.name}"
        self.capture_console.append(detail)
        self.capture_status_label.setText(detail)

    def open_capture_dialog(self) -> None:
        if self.capture_process.state() != QProcess.ProcessState.NotRunning:
            return
        dialog = CaptureSetupDialog(self.discovered_devices, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            request = dialog.capture_request()
            arguments = capture_session_arguments(request, CAPTURE_SESSION)
        except CaptureValidationError as error:
            self.show_error("Invalid capture settings", str(error))
            return
        self.start_capture(request, arguments)

    def start_capture(self, request: CaptureRequest, arguments: list[str]) -> None:
        if self.capture_process.state() != QProcess.ProcessState.NotRunning:
            return
        self.active_capture_request = request
        self.last_capture_request = request
        self.completed_capture_path = None
        self.completed_capture_receipt = None
        self.capture_receipt = None
        self.capture_receipt_error = None
        self.capture_request_id = uuid.uuid4().hex
        self.completion_group.setVisible(False)
        self.retry_traffic_button.setVisible(False)
        self.capture_no_traffic = False
        self.capture_elapsed_seconds = 0
        self.capture_countdown_started = False
        self.capture_event_buffer = ""
        self.capture_error_buffer = ""
        self.capture_cancel_requested = False
        self.capture_cancel_timer.stop()
        self.capture_timer.stop()
        self.capture_console.clear()
        session_arguments = [*arguments, "--request-id", self.capture_request_id]
        exact_command = shlex.join([sys.executable, *session_arguments])
        self.capture_console.append(f"$ {exact_command}\n")
        self.capture_status_label.setText(
            f"Verifying {request.device.name} and preparing its capture interface…"
        )
        self.capture_progress.setRange(0, 0)
        self.capture_progress.setFormat("Preparing capture")
        self.refresh_devices_button.setEnabled(False)
        self.new_capture_button.setEnabled(False)
        self.cancel_capture_button.setEnabled(True)
        self.capture_process.setWorkingDirectory(str(ROOT))
        self.capture_process.setProcessEnvironment(python_helper_environment())
        self.capture_process.setProgram(sys.executable)
        self.capture_process.setArguments(session_arguments)
        self.capture_process.start()

    def advance_capture_progress(self) -> None:
        request = self.active_capture_request
        if request is None or not self.capture_countdown_started:
            self.capture_timer.stop()
            return
        self.capture_elapsed_seconds = min(
            self.capture_elapsed_seconds + 1, request.duration_seconds
        )
        self.capture_progress.setValue(self.capture_elapsed_seconds)
        self.capture_progress.setFormat(
            f"{self.capture_elapsed_seconds} / {request.duration_seconds} seconds"
        )
        if self.capture_elapsed_seconds >= request.duration_seconds:
            self.capture_timer.stop()
            self.capture_progress.setFormat(
                f"{request.duration_seconds} / {request.duration_seconds} seconds — Finalizing"
            )
            self.capture_status_label.setText(
                "Capture duration reached. Closing and validating the packet file…"
            )

    def read_capture_output(self) -> None:
        output = bytes(self.capture_process.readAllStandardOutput()).decode(
            "utf-8", errors="replace"
        )
        if output:
            self.capture_console.moveCursor(QTextCursor.MoveOperation.End)
            self.capture_console.insertPlainText(output)
            self.consume_capture_events(output)

    def consume_capture_events(self, output: str) -> None:
        self.capture_event_buffer += output
        while "\n" in self.capture_event_buffer:
            line, self.capture_event_buffer = self.capture_event_buffer.split("\n", 1)
            self.handle_capture_event(line.strip())
        if len(self.capture_event_buffer.encode("utf-8")) > MAXIMUM_RECEIPT_BYTES:
            self.capture_receipt_error = "Capture helper event exceeds the supported size."
            self.capture_event_buffer = ""

    def handle_capture_event(self, event: str) -> None:
        request = self.active_capture_request
        if request is None:
            return
        if event.startswith(CAPTURE_RECEIPT_EVENT):
            if self.capture_receipt_error is not None:
                return
            try:
                if self.capture_receipt is not None:
                    raise CaptureReceiptError("Capture helper emitted more than one final receipt.")
                request_id = self.capture_request_id
                if request_id is None:
                    raise CaptureReceiptError("The active capture has no request nonce.")
                receipt = parse_capture_receipt(event[len(CAPTURE_RECEIPT_EVENT):])
                validate_receipt_binding(receipt, request_id, request.output_path,
                                         request.capture_format, request.duration_seconds)
                self.capture_receipt = receipt
            except CaptureReceiptError as error:
                self.capture_receipt = None
                self.capture_receipt_error = str(error)
            return
        if event == CAPTURE_AUTHORIZATION_EVENT:
            self.capture_status_label.setText(
                "Approve the native macOS authorization prompt for tcpdump. "
                "The capture countdown has not started."
            )
            self.capture_progress.setRange(0, 0)
            self.capture_progress.setFormat("Waiting for tcpdump authorization")
            return
        if event == CAPTURE_PREFLIGHT_EVENT:
            self.capture_status_label.setText(
                "Authorization accepted. Verifying that RVI delivers a packet within five seconds…"
            )
            self.capture_progress.setRange(0, 0)
            self.capture_progress.setFormat("Testing live RVI traffic")
            return
        if event == CAPTURE_STARTED_EVENT and not self.capture_countdown_started:
            self.capture_countdown_started = True
            self.capture_elapsed_seconds = 0
            self.capture_progress.setRange(0, request.duration_seconds)
            self.capture_progress.setValue(0)
            self.capture_progress.setFormat(f"0 / {request.duration_seconds} seconds")
            self.capture_status_label.setText(
                f"Recording started. Capturing {request.device.name} for "
                f"{request.duration_seconds} seconds…"
            )
            self.capture_timer.start()
            return
        if event == CAPTURE_VALIDATED_EVENT:
            self.capture_timer.stop()
            self.capture_progress.setRange(0, request.duration_seconds)
            self.capture_progress.setValue(request.duration_seconds)
            self.capture_progress.setFormat("Awaiting final capture receipt")
            self.capture_status_label.setText(
                "Artifact validation reported. Waiting for the final cleanup outcome."
            )
            return
        if event == CAPTURE_NO_TRAFFIC_EVENT:
            self.capture_no_traffic = True
            self.capture_status_label.setText(
                "The phone is still connected, but no traffic was observed in five seconds. "
                "Open a webpage on the phone, then retry the traffic check."
            )

    def read_capture_error(self) -> None:
        output = bytes(self.capture_process.readAllStandardError()).decode(
            "utf-8", errors="replace"
        )
        if output:
            self.capture_error_buffer += output
            self.capture_console.moveCursor(QTextCursor.MoveOperation.End)
            self.capture_console.insertPlainText(output)

    def cancel_capture(self) -> None:
        if self.capture_process.state() == QProcess.ProcessState.NotRunning:
            return
        self.capture_status_label.setText(
            "Cancellation requested. Waiting for recording termination and interface cleanup evidence…"
        )
        self.capture_console.append("\nCancellation requested by user.")
        self.capture_cancel_requested = True
        self.cancel_capture_button.setEnabled(False)
        self.capture_process.terminate()
        self.capture_cancel_timer.start(60_000)

    def force_kill_capture(self) -> None:
        if self.capture_cancel_requested and self.capture_process.state() != QProcess.ProcessState.NotRunning:
            self.capture_console.append(
                "Capture helper did not exit within 60 seconds; forcing the helper to stop. "
                "Recording-process and interface cleanup remain unverified without a final receipt."
            )
            self.capture_process.kill()

    def capture_finished(
        self, exit_code: int, exit_status: QProcess.ExitStatus
    ) -> None:
        if self.capture_process.isOpen():
            self.read_capture_output()
            self.read_capture_error()
        if self.capture_event_buffer:
            self.handle_capture_event(self.capture_event_buffer.strip())
            self.capture_event_buffer = ""
        self.capture_timer.stop()
        self.capture_cancel_timer.stop()
        request = self.active_capture_request
        cancellation_requested = self.capture_cancel_requested
        receipt = self.capture_receipt
        receipt_error = self.capture_receipt_error
        self.active_capture_request = None
        self.capture_request_id = None
        self.capture_cancel_requested = False
        self.cancel_capture_button.setEnabled(False)
        self.refresh_devices_button.setEnabled(True)
        self.new_capture_button.setEnabled(
            any(device.connected for device in self.discovered_devices)
        )
        self.capture_progress.setRange(0, 1)
        self.capture_progress.setValue(0)
        if request is None:
            self.capture_status_label.setText(
                f"Capture helper exited with code {exit_code}, but no active request was recorded. "
                "Recording termination and interface cleanup are unverified."
            )
            return
        if receipt is None or receipt_error is not None:
            self.capture_progress.setFormat("Capture outcome unverified")
            detail = receipt_error or "The helper returned no valid final capture receipt."
            prefix = "Cancellation was requested. " if cancellation_requested else ""
            self.capture_status_label.setText(
                prefix + detail + " Recording termination, saved-artifact validity, and interface "
                "cleanup are unverified. Inspect owned resources before retrying."
            )
            self.capture_console.append("\n" + self.capture_status_label.text())
            return

        helper_completed_normally = exit_status == QProcess.ExitStatus.NormalExit
        successful = receipt_is_success(receipt) and helper_completed_normally and exit_code == 0
        process_text = (
            "verified stopped" if receipt.cleanup.recording_process_stopped is True else
            "failed to stop" if receipt.cleanup.recording_process_stopped is False else "unverified"
        )
        interface_text = {
            "verified_complete": "verified complete",
            "failed": "failed",
            "unverified": "unverified",
            "not_applicable": "not applicable",
        }[receipt.cleanup.interface_status]
        artifact_text = "verified readable" if receipt.artifact is not None else receipt.validation_status.replace("_", " ")
        result_lines = [
            f"Recording outcome: {receipt.capture_outcome}.",
            f"Saved-artifact validation: {artifact_text}.",
            f"Recording process: {process_text}. Interface cleanup: {interface_text}.",
        ]
        result_lines.extend(
            f"{failure.stage.capitalize()} [{failure.code}]: {redact_capture_detail(failure.message, request)}"
            for failure in receipt.failures
        )
        if not helper_completed_normally or (receipt_is_success(receipt) and exit_code != 0):
            result_lines.append(
                f"Helper communication ended with exit code {exit_code}; overall completion was not confirmed."
            )
        if cancellation_requested and receipt.capture_outcome == "completed":
            result_lines.append("Cancellation arrived after recording completed; the final receipt reports completion.")
        self.capture_progress.setValue(1 if successful else 0)
        self.capture_progress.setFormat("Capture complete" if successful else "Review capture outcome")
        self.capture_status_label.setText("\n".join(result_lines))
        if self.capture_no_traffic:
            self.retry_traffic_button.setVisible(True)
        artifact = receipt.artifact
        if artifact is None:
            return

        self.completed_capture_receipt = receipt
        self.completed_capture_path = request.output_path
        self.capture_field.setText(str(request.output_path))
        self.manual_baseline_selected = False
        self.baseline_field.setText(str(device_baseline_path(request.device)))
        lifetime = (
            format_duration(receipt.recording_lifetime_nanoseconds / 1_000_000_000)
            if receipt.recording_lifetime_nanoseconds is not None else "Unavailable (not observed)"
        )
        self.completion_summary.setText(
            f"Saved location: {request.output_path}\n"
            f"Verified format: {artifact.capture_format.upper()}\n"
            f"File size: {format_bytes(artifact.size_bytes)}\n"
            f"Readable packet records: {artifact.packet_count:,}\n"
            f"Records with positive captured data: {artifact.positive_packet_count:,}\n"
            f"SHA-256: {artifact.sha256}\n"
            f"Requested recording duration: {receipt.requested_duration_seconds} seconds\n"
            f"Observed recording lifetime: {lifetime}\n"
            f"Packet timestamp span: {artifact.packet_span_nanoseconds} nanoseconds\n"
            f"First packet epoch: {artifact.first_packet_epoch}\n"
            f"Last packet epoch: {artifact.last_packet_epoch}\n"
            f"Recording outcome: {receipt.capture_outcome}\n"
            f"Recording process: {process_text}\nInterface cleanup: {interface_text}\n"
            "The verified saved artifact is available for passive inspection."
        )
        self.completion_group.setVisible(True)
        self.capture_console.append("\nVerified saved evidence is available for passive inspection.")

    def retry_traffic_check(self) -> None:
        request = self.last_capture_request
        if request is None:
            self.show_error("No capture to retry", "Start a new capture first.")
            return
        try:
            arguments = capture_session_arguments(request, CAPTURE_SESSION)
        except CaptureValidationError as error:
            self.show_error("Cannot retry capture", str(error))
            return
        self.start_capture(request, arguments)

    def analyze_completed_capture(self) -> None:
        if self.completed_capture_path is None or self.completed_capture_receipt is None:
            self.show_error("No verified saved capture", "Wait for a valid final capture receipt before analyzing it.")
            return
        self.capture_field.setText(str(self.completed_capture_path))
        self.show_destination("analysis")
        self.start_analysis()

    def open_capture_location(self) -> None:
        if self.completed_capture_path is None:
            self.show_error("No verified saved capture", "Wait for a verified saved artifact before opening its location.")
            return
        directory = self.completed_capture_path.parent
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory))):
            self.show_error("Could not open file location", str(directory))

    def capture_process_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.Crashed:
            return
        detail = f"Could not run the capture helper: {error.name}"
        self.capture_console.append(detail)
        if error == QProcess.ProcessError.FailedToStart:
            self.capture_receipt = None
            self.capture_receipt_error = detail
            self.active_capture_request = None
            self.capture_request_id = None
            self.capture_cancel_requested = False
            self.capture_cancel_timer.stop()
            self.capture_timer.stop()
            self.cancel_capture_button.setEnabled(False)
            self.refresh_devices_button.setEnabled(True)
            self.new_capture_button.setEnabled(any(device.connected for device in self.discovered_devices))
            self.capture_progress.setRange(0, 1)
            self.capture_progress.setValue(0)
            self.capture_progress.setFormat("Capture outcome unverified")
        self.capture_status_label.setText(
            detail + ". No final capture receipt is available; saved-artifact validation "
            "and recording/interface cleanup are unverified."
        )

    def install_capture_support(self) -> None:
        if platform.system() not in {"Linux", "Windows"}:
            self.show_error(
                "Capture support installation is not required",
                "macOS uses Apple rvictl and tcpdump instead of the upstream helper.",
            )
            return
        if self.setup_process.state() != QProcess.ProcessState.NotRunning:
            return
        self.capture_console.append(
            f"$ {shlex.join([sys.executable, str(CAPTURE_SUPPORT_SETUP)])}\n"
        )
        self.install_capture_support_button.setEnabled(False)
        self.capture_status_label.setText("Installing the upstream capture backend locally…")
        self.setup_process.setWorkingDirectory(str(ROOT))
        self.setup_process.setProcessEnvironment(python_helper_environment())
        self.setup_process.setProgram(sys.executable)
        self.setup_process.setArguments([str(CAPTURE_SUPPORT_SETUP)])
        self.setup_process.start()

    def read_setup_output(self) -> None:
        output = bytes(self.setup_process.readAllStandardOutput()).decode(
            "utf-8", errors="replace"
        )
        if output:
            self.capture_console.insertPlainText(output)

    def read_setup_error(self) -> None:
        output = bytes(self.setup_process.readAllStandardError()).decode(
            "utf-8", errors="replace"
        )
        if output:
            self.capture_console.insertPlainText(output)

    def capture_support_finished(
        self, exit_code: int, _exit_status: QProcess.ExitStatus
    ) -> None:
        self.read_setup_output()
        self.read_setup_error()
        self.install_capture_support_button.setEnabled(True)
        if exit_code != 0:
            self.capture_status_label.setText(
                f"Capture support installation failed with exit code {exit_code}."
            )
            return
        self.capture_status_label.setText("Capture support installed; refreshing devices…")
        QTimer.singleShot(0, self.refresh_devices)

    def capture_support_error(self, error: QProcess.ProcessError) -> None:
        self.install_capture_support_button.setEnabled(True)
        detail = f"Could not run capture support setup: {error.name}"
        self.capture_console.append(detail)
        self.capture_status_label.setText(detail)

    def choose_capture(self) -> None:
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Select an authorized packet capture",
            str(ROOT / "captures"),
            "Packet captures (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if selected:
            self.select_imported_capture(Path(selected))

    def select_imported_capture(self, path: Path) -> None:
        """An explicit import establishes new evidence independently of a stale receipt."""
        imported_path = path.expanduser().resolve()
        receipt = self.completed_capture_receipt
        if receipt is not None and imported_path == receipt.output_path:
            self.completed_capture_receipt = None
            self.completed_capture_path = None
            self.completion_group.setVisible(False)
        self.capture_field.setText(str(imported_path))

    def choose_baseline(self) -> None:
        selected, _filter = QFileDialog.getSaveFileName(
            self,
            "Select persistent baseline",
            self.baseline_field.text(),
            "JSON files (*.json);;All files (*)",
        )
        if selected:
            self.manual_baseline_selected = True
            self.baseline_field.setText(selected)

    def suggest_investigation_baseline(self, capture_text: str) -> None:
        if not capture_text.strip() or self.manual_baseline_selected:
            return
        path = Path(capture_text).expanduser().resolve()
        self.baseline_field.setText(str(investigation_baseline_path(path)))

    def choose_export_directory(self) -> None:
        selected = QFileDialog.getExistingDirectory(
            self, "Select export directory", self.export_field.text()
        )
        if selected:
            self.export_field.setText(selected)

    def choose_geoip_database(self) -> None:
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Select a local MaxMind GeoIP database",
            str(ROOT / "data"),
            "MaxMind databases (*.mmdb);;All files (*)",
        )
        if selected:
            self.geoip_field.setText(selected)

    def current_geoip_database(self) -> Path | None:
        path_text = self.geoip_field.text().strip()
        if not path_text:
            return None
        path = Path(path_text).expanduser().resolve()
        if not path.is_file():
            raise RequestValidationError(f"GeoIP database not found: {path}")
        if path.suffix.lower() != ".mmdb":
            raise RequestValidationError(
                f"GeoIP database must use the .mmdb format: {path}"
            )
        return path

    def current_request(self) -> AnalysisRequest:
        capture_text = self.capture_field.text().strip()
        baseline_text = self.baseline_field.text().strip()
        export_text = self.export_field.text().strip()
        if not capture_text:
            raise RequestValidationError("Select or drop a capture file before analyzing.")
        if not baseline_text:
            raise RequestValidationError("Choose a persistent baseline file.")
        if not export_text:
            raise RequestValidationError("Choose an export directory.")
        return AnalysisRequest(
            capture_path=Path(capture_text).expanduser().resolve(),
            baseline_path=Path(baseline_text).expanduser().resolve(),
            export_directory=Path(export_text).expanduser().resolve(),
            entropy_threshold=self.entropy_field.value(),
            top_count=self.top_field.value(),
        )

    def refresh_command_preview(self) -> None:
        try:
            request = self.current_request()
            if self.preview_request is not None and request != self.preview_request:
                self.invalidate_reviewed_preview()
            self.current_geoip_database()
            arguments, _digest = passive_analysis_arguments(
                request, self.completed_capture_receipt, ANALYZER_PREVIEW, CAPTURE_ANALYZER
            )
            command = shlex.join([sys.executable, *arguments])
        except RequestValidationError:
            self.invalidate_reviewed_preview()
            command = (
                "Select a valid capture and optional GeoIP database to preview the analyzer command."
            )
        self.command_field.setText(command)
        self.command_field.setCursorPosition(0)
        self.command_field.setToolTip(command)

    def invalidate_reviewed_preview(self) -> None:
        """A reviewed digest authorizes only the current validated preview request."""
        self.preview_request = None
        self.preview_sha256 = None
        self.add_to_baseline_button.setEnabled(False)

    def start_analysis(self) -> None:
        if self.report_loading:
            return
        if self.process.state() != QProcess.ProcessState.NotRunning:
            return
        try:
            request = self.current_request()
            arguments, expected_capture_sha256 = passive_analysis_arguments(
                request, self.completed_capture_receipt, ANALYZER_PREVIEW, CAPTURE_ANALYZER
            )
        except RequestValidationError as error:
            self.show_error("Invalid analysis configuration", str(error))
            return

        self.active_request = request
        self.active_analysis_capture_sha256 = expected_capture_sha256
        self.preview_request = None
        self.updating_baseline = False
        self.analysis_cancel_requested = False
        self.add_to_baseline_button.setEnabled(False)
        self.cancel_endpoint_enrichment()
        self.clear_results()
        self.active_report_path = None
        exact_command = shlex.join([sys.executable, *arguments])
        self.command_field.setText(exact_command)
        self.command_field.setCursorPosition(0)
        self.command_field.setToolTip(exact_command)
        self.console.append(f"$ {exact_command}\n")
        self.status_label.setText(f"Analyzing {request.capture_path.name}…")
        self.analyze_button.setEnabled(False)
        self.cancel_analysis_button.setEnabled(True)

        self.process.setWorkingDirectory(str(ROOT))
        self.process.setProcessEnvironment(python_helper_environment())
        self.process.setProgram(sys.executable)
        self.process.setArguments(arguments)
        self.process.start()

    def cancel_analysis(self) -> None:
        if self.report_loading:
            self.cancel_report_loading()
            self.invalidate_reviewed_preview()
            self.analyze_button.setEnabled(True)
            self.cancel_analysis_button.setEnabled(False)
            self.status_label.setText("Report loading cancelled. Completed local exports remain available for a later review.")
            return
        if self.process.state() == QProcess.ProcessState.NotRunning or self.updating_baseline:
            return
        self.analysis_cancel_requested = True
        self.cancel_analysis_button.setEnabled(False)
        self.status_label.setText("Cancelling analysis; the selected baseline remains unchanged.")
        self.process.terminate()
        # Decoder cleanup permits 1 s terminate, 2 s kill wait and 2 s per pipe reader.
        self.analysis_cancel_timer.start(8_000)

    def force_stop_analysis(self) -> None:
        if self.analysis_cancel_requested and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()

    def add_findings_to_baseline(self) -> None:
        if self.process.state() != QProcess.ProcessState.NotRunning:
            return
        if self.enrichment_process.state() != QProcess.ProcessState.NotRunning:
            self.show_error("Endpoint lookup active", "Finish or cancel the current endpoint lookup before adding reviewed findings.")
            return
        try:
            request = self.current_request()
            if request != self.preview_request:
                self.invalidate_reviewed_preview()
                raise RequestValidationError(
                    "Capture, baseline, or analysis settings changed. Run read-only analysis again first."
                )
            expected_sha256 = self.preview_sha256
            if expected_sha256 is None:
                raise RequestValidationError(
                    "This preview has no verified capture digest. Run read-only analysis again before updating the baseline."
                )
            arguments = analyzer_arguments(request, REVIEWED_ANALYZER)
            arguments.extend(("--expected-sha256", expected_sha256))
        except RequestValidationError as error:
            self.show_error("Cannot update baseline", str(error))
            return
        decision = QMessageBox.question(
            self,
            "Update this baseline?",
            f"Add findings from {request.capture_path.name} to this baseline?\n\n"
            f"{request.baseline_path}\n\nThis changes the selected baseline file.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if decision != QMessageBox.StandardButton.Yes:
            return
        self.active_request = request
        self.updating_baseline = True
        self.analysis_cancel_requested = False
        self.cancel_analysis_button.setEnabled(False)
        self.add_to_baseline_button.setEnabled(False)
        self.analyze_button.setEnabled(False)
        self.console.append("\nAdding findings to the selected baseline…\n")
        self.status_label.setText("Updating the selected baseline…")
        self.process.setWorkingDirectory(str(ROOT))
        self.process.setProcessEnvironment(python_helper_environment())
        self.process.setProgram(sys.executable)
        self.process.setArguments(arguments)
        self.process.start()

    def read_standard_output(self) -> None:
        output = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        if output:
            self.console.moveCursor(self.console.textCursor().MoveOperation.End)
            self.console.insertPlainText(output)

    def read_standard_error(self) -> None:
        output = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")
        if output:
            self.console.moveCursor(self.console.textCursor().MoveOperation.End)
            self.console.insertPlainText(output)

    def analysis_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        self.analysis_cancel_timer.stop()
        if self.process.isOpen():
            self.read_standard_output()
            self.read_standard_error()
        self.analyze_button.setEnabled(True)
        self.cancel_analysis_button.setEnabled(False)
        updating_baseline = self.updating_baseline
        self.updating_baseline = False
        cancelled = self.analysis_cancel_requested
        self.analysis_cancel_requested = False

        request = self.active_request
        expected_capture_sha256 = self.active_analysis_capture_sha256
        self.active_analysis_capture_sha256 = None
        self.active_request = None
        if request is None:
            self.show_error("Analyzer state error", "No active analysis request was recorded.")
            return
        if cancelled:
            self.invalidate_reviewed_preview()
            self.status_label.setText(
                "Analysis cancelled. The selected baseline was not changed; "
                "any completed local exports may remain in the export folder."
            )
            return
        if exit_status != QProcess.ExitStatus.NormalExit or exit_code != 0:
            if updating_baseline:
                self.invalidate_reviewed_preview()
            self.status_label.setText(f"Analysis failed with exit code {exit_code}.")
            self.show_error(
                "Analysis failed",
                f"The analyzer exited with code {exit_code}. Review the Console tab for details.",
            )
            return

        self.begin_report_load(request, report_path_for(request), expected_capture_sha256, updating_baseline)

    def begin_report_load(self, request: AnalysisRequest, report_path: Path,
                          expected_capture_sha256: str | None, updating_baseline: bool) -> None:
        """Queue only the newest generation while an earlier owned load cancels."""
        if self.closing_requested:
            return
        self.report_generation += 1
        context = ReportLoadContext(self.report_generation, request, report_path,
                                    expected_capture_sha256, updating_baseline)
        self.report_load_context = context
        self.report_loading = True
        self.analyze_button.setEnabled(False)
        self.cancel_analysis_button.setEnabled(not updating_baseline)
        self.add_to_baseline_button.setEnabled(False)
        self.status_label.setText("Loading and validating saved report evidence…")
        if self.report_worker is not None:
            self.report_worker.cancel()
            self.pending_report_load = context
        else:
            self.start_report_worker(context)

    def start_report_worker(self, context: ReportLoadContext) -> None:
        worker = ReportLoadWorker(self, context.generation, context.path)
        self.report_worker = worker
        worker.report_ready.connect(self.report_loaded, Qt.ConnectionType.QueuedConnection)
        worker.report_failed.connect(self.report_loading_failed, Qt.ConnectionType.QueuedConnection)
        worker.report_cancelled.connect(self.report_loading_cancelled, Qt.ConnectionType.QueuedConnection)
        worker.finished.connect(self.report_worker_finished, Qt.ConnectionType.QueuedConnection)
        worker.start()

    @Slot(int, AnalysisReport)
    def report_loaded(self, generation: int, report: AnalysisReport) -> None:
        context = self.report_load_context
        if context is None or context.generation != generation or self.closing_requested:
            return
        if not isinstance(report, AnalysisReport):
            self.report_loading_failed(generation, "The report worker returned an invalid typed result.")
            return
        request = context.request
        report_path = context.path
        updating_baseline = context.baseline_update
        expected_capture_sha256 = context.expected_sha256
        if expected_capture_sha256 is not None and (
            report.evidence is None or report.evidence.sha256 != expected_capture_sha256
        ):
            self.invalidate_reviewed_preview()
            self.report_loading_failed(generation,
                "The saved capture changed after its receipt was verified. This report cannot be attributed to the guided capture; select and review the changed file as a separate imported capture.")
            return
        self.report_loading = False
        self.report_load_context = None
        self.analyze_button.setEnabled(True)
        self.cancel_analysis_button.setEnabled(False)
        self.active_report_path = report_path
        self.baseline_updated_for_report = updating_baseline
        if updating_baseline:
            self.invalidate_reviewed_preview()
        else:
            try:
                current_request = self.current_request()
            except RequestValidationError:
                self.invalidate_reviewed_preview()
            else:
                if request == current_request and report.evidence is not None:
                    self.preview_request = request
                    self.preview_sha256 = report.evidence.sha256
                    self.add_to_baseline_button.setEnabled(True)
                else:
                    self.invalidate_reviewed_preview()
        self.populate_report(report)
        self.start_endpoint_enrichment(report.endpoints)
        self.open_exports_button.setEnabled(True)
        self.refresh_shortcut_paths()
        if updating_baseline:
            self.status_label.setText(f"Findings added to baseline: {request.baseline_path}")
        else:
            detail = (
                "Read-only analysis complete. Baseline unchanged; review findings before adding them."
                if self.preview_sha256 is not None else
                "Read-only analysis complete. Run a verified preview for the current settings before adding findings."
            )
            self.status_label.setText(detail)

        self.report_load_finished.emit()

    @Slot(int, str)
    def report_loading_failed(self, generation: int, detail: str) -> None:
        context = self.report_load_context
        if context is None or context.generation != generation:
            return
        self.report_loading = False
        self.report_load_context = None
        self.analyze_button.setEnabled(True)
        self.cancel_analysis_button.setEnabled(False)
        self.invalidate_reviewed_preview()
        self.status_label.setText("Analysis completed, but the report could not be loaded.")
        self.show_error("Report validation failed", detail)
        self.report_load_finished.emit()

    @Slot(int)
    def report_loading_cancelled(self, generation: int) -> None:
        context = self.report_load_context
        if context is not None and context.generation == generation:
            self.report_loading = False
            self.report_load_context = None
            self.analyze_button.setEnabled(True)
            self.cancel_analysis_button.setEnabled(False)
            self.status_label.setText("Report loading cancelled; no partial packet evidence was displayed.")
            self.report_load_finished.emit()

    @Slot()
    def report_worker_finished(self) -> None:
        worker = self.report_worker
        if worker is None:
            return
        if self.report_load_context is not None and self.report_load_context.generation == worker.generation:
            self.report_loading_failed(worker.generation, "The report worker exited without a completed result. Run analysis again before reviewing it.")
        self.report_worker = None
        worker.deleteLater()
        pending = self.pending_report_load
        self.pending_report_load = None
        if pending is not None and self.report_load_context == pending and not self.closing_requested:
            self.start_report_worker(pending)
        if self.closing_requested:
            self.continue_close()

    def cancel_report_loading(self) -> None:
        self.report_generation += 1
        self.report_load_context = None
        self.pending_report_load = None
        self.report_loading = False
        if self.report_worker is not None:
            self.report_worker.cancel()
        self.report_load_finished.emit()

    @Slot()
    def continue_close(self) -> None:
        if self.closing_requested:
            self.close()
            if self.quit_requested and not self.packet_timeline.is_busy and not self.session_timeline.is_busy and not self.dns_evidence_view.is_busy and (
                self.report_worker is None or not self.report_worker.isRunning()
            ):
                QApplication.quit()

    def process_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.Crashed or self.analysis_cancel_requested:
            return
        self.analysis_cancel_timer.stop()
        self.cancel_analysis_button.setEnabled(False)
        self.analyze_button.setEnabled(True)
        self.status_label.setText("The analyzer process could not be started.")
        self.show_error("Process error", self.process.errorString())

    def clear_session_navigation(self) -> None:
        self.dns_navigation_origin = None
        self.dns_session_origin = None
        self.packet_timeline.return_dns_button.setEnabled(False)
        self.session_timeline.return_dns_button.setEnabled(False)
        self.dns_evidence_view.return_session_button.setEnabled(False)
        self.session_navigation_origin = None
        self.packet_navigation_origin = None
        self.packet_session_jump_origin = None
        self.packet_timeline.back_to_sessions_button.setEnabled(False)
        self.packet_timeline.restore_timeline_button.setEnabled(False)
        self.session_timeline.return_packets_button.setEnabled(False)

    def remember_session_navigation(self) -> None:
        if self.packet_navigation_origin is None:
            self.packet_navigation_origin = self.packet_timeline.capture_navigation()
            self.session_navigation_origin = self.session_timeline.capture_navigation()
        self.packet_timeline.back_to_sessions_button.setEnabled(self.session_navigation_origin is not None)
        self.packet_timeline.restore_timeline_button.setEnabled(self.packet_navigation_origin is not None)
        self.session_timeline.return_packets_button.setEnabled(self.packet_navigation_origin is not None)

    @Slot(object)
    def show_session_dns_evidence(self, value: object) -> None:
        if self.closing_requested or not isinstance(value, SessionIdentity):
            return
        if not self.dns_evidence_view.filter_for_session(value):
            self.session_timeline.status_label.setText("Passive DNS evidence is unavailable for this session in the current report.")
            return
        self.dns_session_origin = self.session_timeline.capture_navigation()
        self.dns_evidence_view.return_session_button.setEnabled(self.dns_session_origin is not None)
        self.results_tabs.setCurrentWidget(self.dns_evidence_view)

    def remember_dns_navigation(self) -> None:
        self.dns_navigation_origin = self.dns_evidence_view.capture_navigation()
        self.packet_timeline.return_dns_button.setEnabled(self.dns_navigation_origin is not None)
        self.session_timeline.return_dns_button.setEnabled(self.dns_navigation_origin is not None)

    def open_dns_packet_scope(self, capture_sha256: str, frames: tuple[int, ...], label: str) -> None:
        if self.closing_requested:
            return
        self.remember_dns_navigation()
        self.remember_session_navigation()
        try:
            self.packet_timeline.set_packet_scope(capture_sha256, frames, label)
            if frames:
                self.packet_timeline.select_packet(PacketIdentity(capture_sha256, frames[0]))
        except PacketQueryValidationError as error:
            self.dns_evidence_view.status_label.setText(f"DNS packet navigation failed: {error}")
            return
        self.results_tabs.setCurrentWidget(self.packet_timeline)

    @Slot(object)
    def show_dns_packet(self, value: object) -> None:
        index = self.dns_evidence_view.dns_index
        if not isinstance(value, PacketIdentity) or index is None:
            return
        try:
            available = bool(dns_messages_for_frame(index, value))
        except PacketQueryValidationError as error:
            self.dns_evidence_view.status_label.setText(f"DNS frame navigation failed: {error}")
            return
        if not available:
            self.dns_evidence_view.status_label.setText("The requested DNS evidence frame is unavailable in this capture.")
            return
        self.open_dns_packet_scope(value.capture_sha256, (value.frame_number,), f"Structured DNS evidence decoded in frame {value.frame_number}")

    @Slot(object)
    def show_dns_matched_packets(self, value: object) -> None:
        index = self.dns_evidence_view.dns_index
        if not isinstance(value, DnsAssociationIdentity) or index is None:
            return
        try:
            association = dns_association_for_identity(index, value)
        except DnsSessionValidationError as error:
            self.dns_evidence_view.status_label.setText(f"DNS candidate navigation failed: {error}")
            return
        if association is None:
            self.dns_evidence_view.status_label.setText("The DNS candidate no longer belongs to the current capture.")
            return
        self.open_dns_packet_scope(value.capture_sha256, association.matching_frames,
            f"Passive DNS candidate: {len(association.matching_frames)} scoped member frames inside the answer TTL window")

    @Slot(str, object)
    def show_observed_dns_packets(self, capture_sha256: str, value: object) -> None:
        index = self.dns_evidence_view.dns_index
        if index is None or index.capture_sha256 != capture_sha256 or type(value) is not tuple or value != observed_dns_frames(index):
            self.dns_evidence_view.status_label.setText("DNS observation navigation does not match this report's complete DNS frame evidence.")
            return
        self.open_dns_packet_scope(capture_sha256, value, f"Structured DNS observations: {len(value)} original decoder frames, including unassociated messages")

    @Slot(object)
    def show_dns_session(self, value: object) -> None:
        if self.closing_requested or not isinstance(value, SessionIdentity):
            return
        self.remember_dns_navigation()
        if not self.session_timeline.select_session(value):
            self.dns_evidence_view.status_label.setText("The candidate session is unavailable in the current report.")
            return
        self.results_tabs.setCurrentWidget(self.session_timeline)

    @Slot()
    def return_to_dns_evidence(self) -> None:
        navigation = self.dns_navigation_origin
        if self.closing_requested or navigation is None:
            return
        if not self.dns_evidence_view.restore_navigation(navigation):
            self.clear_session_navigation()
            self.dns_evidence_view.status_label.setText("The previous DNS view belongs to an earlier report and cannot be restored.")
            return
        self.results_tabs.setCurrentWidget(self.dns_evidence_view)

    @Slot()
    def return_from_dns_to_session(self) -> None:
        navigation = self.dns_session_origin
        if self.closing_requested or navigation is None:
            return
        if not self.session_timeline.restore_navigation(navigation):
            self.clear_session_navigation()
            self.dns_evidence_view.status_label.setText("The original session view belongs to an earlier report and cannot be restored.")
            return
        self.results_tabs.setCurrentWidget(self.session_timeline)

    @Slot(object)
    def show_session_members(self, value: object) -> None:
        index = self.session_timeline.session_index
        if not isinstance(value, SessionIdentity) or index is None:
            self.packet_timeline.status_label.setText("The selected session is not available in the current report.")
            return
        try:
            session = session_for_identity(index, value)
            if session is None:
                raise SessionValidationError("The session belongs to another capture or is no longer available.")
            frames = frames_for_session(index, value)
            self.remember_session_navigation()
            self.packet_timeline.set_packet_scope(value.capture_sha256, frames,
                f"Session {session.scope.transport.upper()} stream {session.scope.stream}: {session.packet_count} scoped member packets")
            self.packet_timeline.back_to_sessions_button.setEnabled(self.session_navigation_origin is not None)
            self.packet_timeline.restore_timeline_button.setEnabled(self.packet_navigation_origin is not None)
            if self.packet_timeline.selected_identity is None and frames:
                self.packet_timeline.select_packet(PacketIdentity(value.capture_sha256, frames[0]))
        except (SessionValidationError, PacketQueryValidationError) as error:
            self.packet_timeline.status_label.setText(f"Session navigation failed: {error}")
            return
        self.results_tabs.setCurrentWidget(self.packet_timeline)

    @Slot(str, object)
    def show_ungrouped_packets(self, capture_sha256: str, value: object) -> None:
        index = self.session_timeline.session_index
        if index is None or index.capture_sha256 != capture_sha256 or not isinstance(value, tuple) or any(type(frame) is not int for frame in value):
            self.packet_timeline.status_label.setText("Ungrouped packet navigation belongs to an unavailable capture.")
            return
        expected = tuple(packet.frame_number for packet in index.ungrouped)
        if set(value) != set(expected) or len(value) != len(expected):
            self.packet_timeline.status_label.setText("Ungrouped packet navigation does not match the complete ungrouped evidence.")
            return
        self.remember_session_navigation()
        try:
            self.packet_timeline.set_packet_scope(capture_sha256, value, f"Ungrouped evidence: {len(value)} packets with explicit correlation exclusions")
            if value:
                self.packet_timeline.select_packet(PacketIdentity(capture_sha256, value[0]))
        except PacketQueryValidationError as error:
            self.packet_timeline.status_label.setText(f"Ungrouped packet navigation failed: {error}")
            return
        self.results_tabs.setCurrentWidget(self.packet_timeline)

    @Slot()
    def refresh_packet_session_context(self) -> None:
        index = self.session_timeline.dns_index
        if index is not None:
            self.dns_evidence_view.set_index(index)
        self.update_packet_session_context(self.packet_timeline.selected_identity)

    def dns_packet_context(self, identity: PacketIdentity) -> str:
        index = self.session_timeline.dns_index
        if index is None or index.capture_sha256 != identity.capture_sha256:
            return " Structured passive DNS evidence is unavailable for this report."
        messages = dns_messages_for_frame(index, identity)
        if not messages:
            return " Passive DNS associations cover only their explicitly referenced session frames; inspect DNS evidence for candidates."
        reasons = sorted({item.reason for item in dns_diagnostics_for_frame(index, identity)})
        response_codes = sorted({message.response_code for message in messages if message.is_response})
        response_context = f" DNS response code: {', '.join(str(code) for code in response_codes)}." if response_codes else ""
        if len(response_codes) > 32:
            response_context = f" {len(response_codes)} distinct DNS response codes; complete values remain in DNS evidence."
        return f" Structured DNS messages decoded in this frame: {len(messages)}. Observation reasons: {', '.join(reasons) if reasons else 'eligible positive answer evidence'}.{response_context} DNS messages can be TCP reassemblies; frame references do not imply all message bytes originated in this frame."

    @Slot(object)
    def update_packet_session_context(self, value: object) -> None:
        self.packet_timeline.owning_session_button.setEnabled(False)
        if not isinstance(value, PacketIdentity):
            self.packet_timeline.set_correlation_context("Select a packet to inspect its session membership or exclusion reasons.")
            return
        index = self.session_timeline.session_index
        if index is None or index.capture_sha256 != value.capture_sha256:
            self.packet_timeline.set_correlation_context("Session correlation is not available for this packet's current report.")
            return
        identity = session_for_packet(index, value)
        if identity is not None:
            session = session_for_identity(index, identity)
            if session is not None:
                self.packet_timeline.owning_session_button.setEnabled(True)
                self.packet_timeline.set_correlation_context(
                    f"Scoped {session.scope.transport.upper()} stream {session.scope.stream}; session scope SHA-256 {identity.scope_sha256}; {session.packet_count} member packets. Grouping does not establish connection lifetime or process ownership." + self.dns_packet_context(value))
                return
        ungrouped = ungrouped_for_packet(index, value)
        if ungrouped is not None:
            reasons = ", ".join(ungrouped.reasons)
            self.packet_timeline.set_correlation_context(f"Ungrouped packet. Correlation exclusions: {reasons}. No session membership was inferred." + self.dns_packet_context(value))
        else:
            self.packet_timeline.set_correlation_context("This frame is not present in the current session index; membership is unavailable.")

    @Slot()
    def show_owning_session(self) -> None:
        identity = self.packet_timeline.selected_identity
        index = self.session_timeline.session_index
        if identity is None or index is None:
            return
        session_identity = session_for_packet(index, identity)
        if session_identity is None:
            self.update_packet_session_context(identity)
            return
        self.remember_session_navigation()
        self.packet_session_jump_origin = self.packet_timeline.capture_navigation()
        if not self.session_timeline.select_session(session_identity):
            self.packet_timeline.status_label.setText("The owning session is no longer available in the current report.")
            return
        self.results_tabs.setCurrentWidget(self.session_timeline)

    @Slot()
    def return_to_sessions(self) -> None:
        navigation = self.session_navigation_origin
        if navigation is None:
            return
        self.packet_session_jump_origin = self.packet_timeline.capture_navigation()
        if not self.session_timeline.restore_navigation(navigation):
            self.clear_session_navigation()
            self.packet_timeline.status_label.setText("The original session view belongs to an earlier report and cannot be restored.")
            return
        self.results_tabs.setCurrentWidget(self.session_timeline)

    @Slot()
    def return_from_session_to_packets(self) -> None:
        navigation = self.packet_session_jump_origin or self.packet_navigation_origin
        if navigation is None:
            return
        if not self.packet_timeline.restore_navigation(navigation):
            self.clear_session_navigation()
            self.session_timeline.status_label.setText("The previous packet view belongs to an earlier report and cannot be restored.")
            return
        self.results_tabs.setCurrentWidget(self.packet_timeline)

    @Slot()
    def return_to_packet_context(self) -> None:
        navigation = self.packet_navigation_origin
        if navigation is None:
            return
        if not self.packet_timeline.restore_navigation(navigation):
            self.clear_session_navigation()
            self.session_timeline.status_label.setText("The original packet view belongs to an earlier report and cannot be restored.")
            return
        self.clear_session_navigation()
        self.results_tabs.setCurrentWidget(self.packet_timeline)

    def populate_report(self, report: AnalysisReport) -> None:
        self.clear_session_navigation()
        self.dns_evidence_view.clear_index()
        self.packet_timeline.set_report(report)
        self.session_timeline.set_report(report)
        capture = report.capture
        summary = report.summary
        self.summary_labels["capture_path"].setText(capture.path)
        self.summary_labels["size_bytes"].setText(format_bytes(capture.size_bytes))
        self.summary_labels["packet_count"].setText(f"{capture.packet_count:,}")
        self.summary_labels["duration"].setText(format_duration(capture.duration_seconds))
        self.summary_labels["first_packet"].setText(capture.first_packet or "Not observed")
        self.summary_labels["last_packet"].setText(capture.last_packet or "Not observed")
        self.summary_labels["endpoints"].setText(
            format_observation_count(summary.unique_endpoints, len(summary.new_endpoints))
        )
        self.summary_labels["dns"].setText(
            format_observation_count(summary.unique_dns_queries, len(summary.new_domains))
        )
        self.summary_labels["tls"].setText(
            format_observation_count(summary.unique_tls_sni, len(summary.new_tls_sni))
        )
        self.summary_labels["quic"].setText(f"{summary.quic_like_packets:,}")
        evidence = report.evidence
        if evidence is None:
            self.summary_labels["capture_digest"].setText("Not recorded in this report")
            self.summary_labels["capture_integrity"].setText("Legacy report; import evidence not recorded")
            self.summary_labels["decoder_coverage"].setText("Not recorded in this report")
            self.summary_labels["decoder_coverage"].setToolTip("")
            self.summary_labels["packet_record_count"].setText("Not recorded in this report")
        else:
            self.summary_labels["capture_digest"].setText(evidence.sha256)
            self.summary_labels["capture_integrity"].setText(
                f"{evidence.integrity}; origin: {evidence.origin}. Digest verifies bytes, not origin."
            )
            self.summary_labels["decoder_coverage"].setText(
                f"{evidence.tshark_version}; {evidence.supported_field_count} supported fields, "
                f"{len(evidence.unsupported_fields)} optional fields unavailable"
            )
            self.summary_labels["decoder_coverage"].setToolTip(
                "Unavailable optional fields: " + ", ".join(evidence.unsupported_fields)
                if evidence.unsupported_fields else "All requested optional fields were available."
            )
            self.summary_labels["packet_record_count"].setText(f"{evidence.packet_record_count:,}")

        populate_ranked_table(self.domains_table, report.domains)
        populate_ranked_table(self.tls_table, report.tls_sni)
        populate_ranked_table(self.protocols_table, report.protocols)
        populate_port_table(self.ports_table, report.ports)
        populate_entropy_table(self.entropy_table, report.entropy_findings)
        self.interpretation.setPlainText(build_findings_explanation(report))

    def start_endpoint_enrichment(self, endpoints: tuple[RankedFinding, ...]) -> None:
        self.endpoint_findings = endpoints
        self.endpoint_enrichment_result = None
        populate_endpoint_table(self.endpoints_table, endpoints)
        self.resolve_ptr_button.setEnabled(False)
        if not endpoints:
            self.status_label.setText(self.completed_status("No endpoints to enrich."))
            self.enrichment_status_label.setText("No endpoints to enrich. PTR not requested.")
            return

        arguments = [str(LOCAL_ENDPOINT_ENRICHER)]
        try:
            geo_database = self.current_geoip_database()
        except RequestValidationError as error:
            self.endpoints_table.setSortingEnabled(True)
            self.status_label.setText(self.completed_status("GeoIP configuration is invalid."))
            self.show_error("Invalid GeoIP configuration", str(error))
            return
        if geo_database is not None:
            arguments.extend(("--geo-db", str(geo_database)))
        arguments.extend(finding.value for finding in endpoints)

        self.active_enrichment_source = "local"
        self.enrichment_status_label.setText("Reading local scope and GeoIP context. PTR not requested.")
        self.status_label.setText(self.completed_status("Reading local endpoint context; PTR not requested."))
        self.start_enrichment_process(arguments)

    def resolve_current_ptr_names(self) -> None:
        if (
            not self.endpoint_findings
            or self.active_report_path is None
            or self.enrichment_process.state() != QProcess.ProcessState.NotRunning
            or self.process.state() != QProcess.ProcessState.NotRunning
        ):
            return
        arguments = [str(ENDPOINT_ENRICHER)]
        try:
            geo_database = self.current_geoip_database()
        except RequestValidationError as error:
            self.show_error("Invalid GeoIP configuration", str(error))
            return
        if geo_database is not None:
            arguments.extend(("--geo-db", str(geo_database)))
        arguments.extend(finding.value for finding in self.endpoint_findings)
        self.active_enrichment_source = "ptr"
        self.endpoints_table.setSortingEnabled(False)
        for row in range(self.endpoints_table.rowCount()):
            item = self.endpoints_table.item(row, 1)
            if item is not None:
                item.setText("Resolving current PTR…")
                item.setToolTip("Explicit current resolver query; this is separate from captured DNS/SNI.")
        self.enrichment_status_label.setText(
            "Current PTR names requested from the configured DNS resolver. "
            "Captured DNS/SNI, reports and baselines remain unchanged."
        )
        self.status_label.setText(self.completed_status("Resolving explicitly requested current PTR names."))
        self.start_enrichment_process(arguments)

    def start_enrichment_process(self, arguments: list[str]) -> None:
        self.enrichment_timed_out = False
        self.enrichment_cancel_requested = False
        self.resolve_ptr_button.setEnabled(False)
        self.add_to_baseline_button.setEnabled(False)
        self.cancel_enrichment_button.setEnabled(True)
        self.enrichment_process.setWorkingDirectory(str(ROOT))
        self.enrichment_process.setProcessEnvironment(python_helper_environment())
        self.enrichment_process.setProgram(sys.executable)
        self.enrichment_process.setArguments(arguments)
        self.enrichment_process.start()
        self.enrichment_timer.start(30_000)

    def endpoint_enrichment_finished(
        self, exit_code: int, exit_status: QProcess.ExitStatus
    ) -> None:
        self.enrichment_timer.stop()
        expected_source = self.active_enrichment_source
        self.active_enrichment_source = None
        self.update_enrichment_actions()
        if self.enrichment_timed_out or self.enrichment_cancel_requested:
            self.restore_completed_enrichment()
            return

        error_text = bytes(self.enrichment_process.readAllStandardError()).decode(
            "utf-8", errors="replace"
        ).strip()
        if exit_status != QProcess.ExitStatus.NormalExit or exit_code != 0:
            detail = error_text or f"Endpoint enrichment exited with code {exit_code}."
            self.console.append(f"\n{detail}\n")
            self.enrichment_status_label.setText("Endpoint enrichment failed; no new lookup evidence was added.")
            self.restore_completed_enrichment()
            self.status_label.setText(self.completed_status("Endpoint enrichment failed."))
            self.show_error("Endpoint enrichment failed", detail)
            return

        try:
            output = bytes(self.enrichment_process.readAllStandardOutput()).decode(
                "utf-8", errors="strict"
            )
            result = parse_enrichment_result_output(output)
            if result.evidence_source != expected_source:
                raise ValueError("Endpoint enrichment evidence source does not match the requested operation.")
        except (UnicodeDecodeError, ValueError) as error:
            self.enrichment_status_label.setText("Endpoint enrichment output was invalid; no new lookup evidence was added.")
            self.restore_completed_enrichment()
            self.status_label.setText(
                self.completed_status("Endpoint enrichment output was invalid.")
            )
            self.show_error("Endpoint enrichment output invalid", str(error))
            return

        try:
            apply_endpoint_enrichment(self.endpoints_table, result.endpoints)
        except ValueError as error:
            self.enrichment_status_label.setText("Endpoint enrichment did not match this report; no new lookup evidence was added.")
            self.restore_completed_enrichment()
            self.status_label.setText(
                self.completed_status("Endpoint enrichment did not match the report.")
            )
            self.show_error("Endpoint enrichment mismatch", str(error))
            return
        self.endpoint_enrichment_result = result
        source_description = (
            "Local scope/GeoIP context; PTR not requested"
            if result.evidence_source == "local" else "Current PTR from the configured DNS resolver"
        )
        self.enrichment_status_label.setText(
            f"{source_description}. Requested: {result.requested_at.isoformat()}; "
            f"completed: {result.completed_at.isoformat()}. "
            "This context is separate from captured DNS/SNI and is not written to reports or baselines."
        )
        for row in range(self.endpoints_table.rowCount()):
            item = self.endpoints_table.item(row, 1)
            if item is not None:
                item.setToolTip(
                    f"{item.toolTip()}\nEvidence source: {source_description}\n"
                    f"Requested: {result.requested_at.isoformat()}\nCompleted: {result.completed_at.isoformat()}"
                )
        geo_status = (
            "Local GeoIP applied."
            if self.geoip_field.text().strip()
            else "GeoIP database not configured."
        )
        operation_status = (
            "Local endpoint enrichment complete. PTR not requested."
            if result.evidence_source == "local" else "Current PTR resolution complete."
        )
        self.status_label.setText(
            self.completed_status(f"{operation_status} {geo_status}")
        )

    def update_enrichment_actions(self) -> None:
        lookup_running = self.enrichment_process.state() != QProcess.ProcessState.NotRunning
        self.cancel_enrichment_button.setEnabled(lookup_running)
        self.add_to_baseline_button.setEnabled(
            not lookup_running
            and self.preview_request is not None
            and self.preview_sha256 is not None
            and self.process.state() == QProcess.ProcessState.NotRunning
        )
        self.resolve_ptr_button.setEnabled(
            bool(self.endpoint_findings)
            and self.active_report_path is not None
            and not lookup_running
            and self.process.state() == QProcess.ProcessState.NotRunning
        )

    def restore_completed_enrichment(self) -> None:
        if self.endpoint_enrichment_result is not None:
            result = self.endpoint_enrichment_result
            apply_endpoint_enrichment(self.endpoints_table, result.endpoints)
            retained_note = (
                f"Last completed evidence retained: {result.evidence_source}; "
                f"requested: {result.requested_at.isoformat()}; completed: {result.completed_at.isoformat()}."
            )
            self.enrichment_status_label.setText(f"{self.enrichment_status_label.text()} {retained_note}")
            for row in range(self.endpoints_table.rowCount()):
                item = self.endpoints_table.item(row, 1)
                if item is not None:
                    item.setToolTip(f"{item.toolTip()}\n{retained_note}")
        else:
            for row in range(self.endpoints_table.rowCount()):
                self.endpoints_table.setItem(row, 1, QTableWidgetItem("Not requested"))
                self.endpoints_table.setItem(row, 3, QTableWidgetItem("Local enrichment not completed"))
        self.endpoints_table.setSortingEnabled(True)

    def endpoint_enrichment_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.Crashed or self.enrichment_timed_out or self.enrichment_cancel_requested:
            return
        self.enrichment_timer.stop()
        self.active_enrichment_source = None
        self.update_enrichment_actions()
        self.restore_completed_enrichment()
        detail = self.enrichment_process.errorString()
        self.console.append(f"\nEndpoint enrichment process error: {detail}\n")
        self.status_label.setText(
            self.completed_status("Endpoint enrichment process could not start.")
        )
        self.enrichment_status_label.setText("Endpoint enrichment process could not start; no new evidence was added.")

    def endpoint_enrichment_timeout(self) -> None:
        if self.enrichment_process.state() == QProcess.ProcessState.NotRunning:
            return
        self.enrichment_timed_out = True
        self.cancel_enrichment_button.setEnabled(False)
        self.enrichment_process.kill()
        self.endpoints_table.setSortingEnabled(True)
        detail = "Endpoint lookup exceeded 30 seconds and was stopped. No new lookup evidence was added."
        self.console.append(f"\n{detail}\n")
        self.status_label.setText(self.completed_status(detail))
        self.enrichment_status_label.setText(detail)

    def cancel_endpoint_enrichment(self) -> None:
        self.enrichment_timer.stop()
        if self.enrichment_process.state() != QProcess.ProcessState.NotRunning:
            self.enrichment_cancel_requested = True
            self.cancel_enrichment_button.setEnabled(False)
            self.enrichment_process.kill()
            detail = "Endpoint lookup cancelled. No new lookup evidence was added."
            self.status_label.setText(self.completed_status(detail))
            self.enrichment_status_label.setText(detail)

    def completed_status(self, detail: str) -> str:
        report = str(self.active_report_path) if self.active_report_path else "not available"
        baseline_state = (
            "Selected baseline was updated."
            if self.baseline_updated_for_report else "Selected baseline was not changed by this analysis."
        )
        return f"Analysis complete. {baseline_state} {detail} Report: {report}"

    def clear_results(self) -> None:
        self.cancel_report_loading()
        self.clear_session_navigation()
        self.packet_timeline.clear_report()
        self.session_timeline.clear_report()
        self.dns_evidence_view.clear_index()
        self.cancel_endpoint_enrichment()
        self.invalidate_reviewed_preview()
        self.baseline_updated_for_report = False
        self.endpoint_findings = ()
        self.endpoint_enrichment_result = None
        self.resolve_ptr_button.setEnabled(False)
        self.cancel_enrichment_button.setEnabled(False)
        self.enrichment_status_label.setText("Local endpoint context appears after analysis; PTR is not requested.")
        self.add_to_baseline_button.setEnabled(False)
        for label in self.summary_labels.values():
            label.setText("—")
        for table in (
            self.endpoints_table,
            self.domains_table,
            self.tls_table,
            self.protocols_table,
            self.ports_table,
            self.entropy_table,
        ):
            table.setRowCount(0)
        self.interpretation.setPlainText(
            "Analyze a capture to receive a plain-language explanation of the findings."
        )
        self.console.clear()

    def open_export_directory(self) -> None:
        export_text = self.export_field.text().strip()
        if not export_text:
            self.show_error("Export directory missing", "Choose an export directory first.")
            return
        export_path = Path(export_text).expanduser().resolve()
        if not export_path.is_dir():
            self.show_error("Export directory not found", f"Directory not found: {export_path}")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(export_path))):
            self.show_error("Could not open export directory", str(export_path))

    def show_error(self, title: str, detail: str) -> None:
        message = QMessageBox(self)
        message.setIcon(QMessageBox.Icon.Critical)
        message.setWindowTitle(title)
        message.setText(title)
        message.setInformativeText(detail)
        message.exec()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        urls = event.mimeData().urls()
        if len(urls) == 1 and urls[0].isLocalFile():
            suffix = Path(urls[0].toLocalFile()).suffix.lower()
            if suffix in {".cap", ".pcap", ".pcapng"}:
                event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if len(urls) != 1 or not urls[0].isLocalFile():
            return
        self.select_imported_capture(Path(urls[0].toLocalFile()))
        self.show_destination("analysis")
        event.acceptProposedAction()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.closing_requested = True
        self.icon_refresh_timer.stop()
        self.cancel_report_loading()
        packet_stopped = self.packet_timeline.shutdown()
        session_stopped = self.session_timeline.shutdown()
        dns_stopped = self.dns_evidence_view.shutdown()
        report_stopped = self.report_worker is None or not self.report_worker.isRunning()
        if not packet_stopped or not session_stopped or not dns_stopped or not report_stopped:
            event.ignore()
            return
        self.enrichment_timer.stop()
        self.analysis_cancel_timer.stop()
        self.capture_timer.stop()
        self.capture_cancel_timer.stop()
        for process in (
            self.process,
            self.enrichment_process,
            self.device_process,
            self.capture_process,
            self.setup_process,
            self.check_process,
        ):
            if process.state() != QProcess.ProcessState.NotRunning:
                if process is self.capture_process:
                    self.capture_cancel_requested = True
                process.terminate()
                cleanup_deadline = (
                    60_000 if process is self.capture_process else
                    8_000 if process is self.process else 5_000
                )
                if not process.waitForFinished(cleanup_deadline):
                    process.kill()
                    process.waitForFinished(1_000)
        super().closeEvent(event)


class WindowQuitFilter(QObject):
    """Route application quit through owned worker and process shutdown."""

    def __init__(self, window: RviSentinelWindow) -> None:
        super().__init__(window)
        self.window = window

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is QApplication.instance() and event.type() == QEvent.Type.Quit:
            self.window.quit_requested = True
            self.window.close()
            return self.window.packet_timeline.is_busy or self.window.session_timeline.is_busy or self.window.dns_evidence_view.is_busy or (
                self.window.report_worker is not None and self.window.report_worker.isRunning()
            )
        return False


def capture_backend_summary(host_system: str) -> str:
    if host_system == "Darwin":
        return "Apple rvictl + rvi interface + tcpdump"
    if host_system in {"Linux", "Windows"}:
        return "gh2o/rvi_capture + libimobiledevice"
    return "unsupported capture host"


def device_baseline_path(device: DeviceInfo) -> Path:
    fingerprint = hashlib.sha256(device.udid.encode("utf-8")).hexdigest()[:12]
    return ROOT / "data" / "baselines" / f"device-{fingerprint}.json"


def redact_capture_detail(detail: str, request: CaptureRequest) -> str:
    redacted = detail.replace(request.device.udid, "[device identifier redacted]")
    redacted = redacted.replace(str(request.output_path), "[capture path redacted]")
    redacted = redacted.replace(str(ROOT), "[project path redacted]")
    redacted = re.sub(
        r"\b(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16})\b",
        "[device identifier redacted]",
        redacted,
    )
    return redacted


def investigation_baseline_path(capture: Path) -> Path:
    fingerprint = hashlib.sha256(str(capture).encode("utf-8")).hexdigest()[:12]
    return ROOT / "data" / "baselines" / f"investigation-{fingerprint}.json"


def create_device_table() -> QTableWidget:
    table = QTableWidget(0, 4)
    table.setHorizontalHeaderLabels(("Device", "OS / model", "Device identifier", "Status"))
    table.setAccessibleName("Recognized physical iPhone and iPad devices")
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    table.setSortingEnabled(False)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
    return table


def device_table_matches(
    table: QTableWidget, devices: tuple[DeviceInfo, ...]
) -> bool:
    if table.rowCount() != len(devices):
        return False
    for row_index, device in enumerate(devices):
        name_item = table.item(row_index, 0)
        operating_system_item = table.item(row_index, 1)
        status_item = table.item(row_index, 3)
        if (
            name_item is None
            or operating_system_item is None
            or status_item is None
            or name_item.data(Qt.ItemDataRole.UserRole) != device.udid
            or name_item.text() != device.name
            or operating_system_item.text() != device.operating_system
            or status_item.text() != device.status
        ):
            return False
    return True


def set_device_identifier_visibility(
    table: QTableWidget, devices: tuple[DeviceInfo, ...], visible: bool
) -> None:
    for row_index, device in enumerate(devices):
        identifier_item = table.item(row_index, 2)
        if identifier_item is not None:
            identifier_item.setText(device.udid if visible else "Hidden")


def populate_device_table(
    table: QTableWidget, devices: tuple[DeviceInfo, ...]
) -> None:
    if device_table_matches(table, devices):
        return
    current_row = table.currentRow()
    table.setRowCount(len(devices))
    for row_index, device in enumerate(devices):
        name_item = table.item(row_index, 0) or QTableWidgetItem()
        operating_system_item = table.item(row_index, 1) or QTableWidgetItem()
        identifier_item = table.item(row_index, 2) or QTableWidgetItem()
        status_item = table.item(row_index, 3) or QTableWidgetItem()
        name_item.setText(device.name)
        name_item.setData(Qt.ItemDataRole.UserRole, device.udid)
        operating_system_item.setText(device.operating_system)
        identifier_item.setText(
            device.udid if not table.isColumnHidden(2) else "Hidden"
        )
        status_item.setText(device.status)
        status_item.setForeground(QColor("#3fb950" if device.connected else "#fbbf24"))
        table.setItem(row_index, 0, name_item)
        table.setItem(row_index, 1, operating_system_item)
        table.setItem(row_index, 2, identifier_item)
        table.setItem(row_index, 3, status_item)
    if 0 <= current_row < len(devices):
        table.selectRow(current_row)


def create_ranked_table(headers: tuple[str, str, str]) -> QTableWidget:
    table = QTableWidget(0, 3)
    table.setHorizontalHeaderLabels(list(headers))
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
    return table


def create_endpoint_table() -> QTableWidget:
    table = QTableWidget(0, 6)
    table.setHorizontalHeaderLabels(
        ("Endpoint", "Hostname (PTR)", "Network scope", "Approximate location", "Packets", "Baseline")
    )
    table.setAccessibleName("Endpoint findings with PTR and local GeoIP enrichment")
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
    return table


def create_port_table() -> QTableWidget:
    table = QTableWidget(0, 5)
    table.setHorizontalHeaderLabels(
        ("Transport", "Port", "Service label", "Typical use", "Field observations")
    )
    table.setAccessibleName("Observed ports with service explanations")
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
    return table


def create_entropy_table() -> QTableWidget:
    table = QTableWidget(0, 4)
    table.setHorizontalHeaderLabels(("Domain", "Maximum label", "Entropy", "Interpretation"))
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.setAlternatingRowColors(True)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
    table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
    return table


def populate_ranked_table(
    table: QTableWidget, findings: tuple[RankedFinding, ...]
) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(findings))
    for row_index, finding in enumerate(findings):
        value_item = QTableWidgetItem(finding.value)
        count_item = QTableWidgetItem(f"{finding.count:,}")
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        baseline_item = QTableWidgetItem("NEW" if finding.is_new else "Known")
        if finding.is_new:
            baseline_item.setForeground(QColor("#fbbf24"))
        else:
            baseline_item.setForeground(QColor("#3fb950"))
        table.setItem(row_index, 0, value_item)
        table.setItem(row_index, 1, count_item)
        table.setItem(row_index, 2, baseline_item)
    table.setSortingEnabled(True)


def populate_endpoint_table(
    table: QTableWidget, findings: tuple[RankedFinding, ...]
) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(findings))
    for row_index, finding in enumerate(findings):
        address_item = QTableWidgetItem(finding.value)
        hostname_item = QTableWidgetItem("Not requested")
        hostname_item.setToolTip("Current PTR names require an explicit configured-resolver request.")
        scope_item = QTableWidgetItem(classify_address(finding.value))
        location_item = QTableWidgetItem("Local GeoIP lookup pending…")
        count_item = QTableWidgetItem(f"{finding.count:,}")
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        baseline_item = QTableWidgetItem("NEW" if finding.is_new else "Known")
        baseline_item.setForeground(QColor("#fbbf24" if finding.is_new else "#3fb950"))
        table.setItem(row_index, 0, address_item)
        table.setItem(row_index, 1, hostname_item)
        table.setItem(row_index, 2, scope_item)
        table.setItem(row_index, 3, location_item)
        table.setItem(row_index, 4, count_item)
        table.setItem(row_index, 5, baseline_item)


def apply_endpoint_enrichment(
    table: QTableWidget, enrichment: tuple[EndpointEnrichment, ...]
) -> None:
    row_by_address = {
        table.item(row, 0).text(): row
        for row in range(table.rowCount())
        if table.item(row, 0) is not None
    }
    if len(enrichment) != len(row_by_address):
        raise ValueError(
            "Endpoint enrichment count does not match the endpoint report: "
            f"{len(enrichment)} enrichment rows for {len(row_by_address)} endpoints."
        )
    if {finding.address for finding in enrichment} != set(row_by_address):
        raise ValueError("Endpoint enrichment addresses do not match the endpoint report.")
    table.setSortingEnabled(False)
    for finding in enrichment:
        row = row_by_address.get(finding.address)
        if row is None:
            raise ValueError(
                f"Endpoint enrichment returned an address not present in the report: {finding.address}"
            )
        hostname_item = QTableWidgetItem(finding.hostname)
        hostname_item.setToolTip(finding.resolution_note)
        table.setItem(row, 1, hostname_item)
        table.setItem(row, 2, QTableWidgetItem(finding.scope))
        table.setItem(row, 3, QTableWidgetItem(finding.location))
    table.setSortingEnabled(True)


def populate_port_table(table: QTableWidget, findings: tuple[PortFinding, ...]) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(findings))
    for row_index, finding in enumerate(findings):
        description = describe_port(finding.transport, finding.port)
        count_item = QTableWidgetItem(f"{finding.count:,}")
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        table.setItem(row_index, 0, QTableWidgetItem(finding.transport))
        table.setItem(row_index, 1, QTableWidgetItem(str(finding.port)))
        table.setItem(row_index, 2, QTableWidgetItem(description.service))
        table.setItem(row_index, 3, QTableWidgetItem(description.purpose))
        table.setItem(row_index, 4, count_item)
    table.setSortingEnabled(True)


def populate_entropy_table(
    table: QTableWidget, findings: tuple[EntropyFinding, ...]
) -> None:
    table.setSortingEnabled(False)
    table.setRowCount(len(findings))
    for row_index, finding in enumerate(findings):
        table.setItem(row_index, 0, QTableWidgetItem(finding.domain))
        table.setItem(row_index, 1, QTableWidgetItem(finding.max_label))
        table.setItem(row_index, 2, QTableWidgetItem(f"{finding.entropy:.3f}"))
        table.setItem(row_index, 3, QTableWidgetItem(finding.note))
    table.setSortingEnabled(True)


def build_findings_explanation(report: AnalysisReport) -> str:
    summary = report.summary
    duration = format_duration(report.capture.duration_seconds)
    new_endpoint_count = len(summary.new_endpoints)
    new_domain_count = len(summary.new_domains)
    new_tls_count = len(summary.new_tls_sni)
    entropy_count = len(report.entropy_findings)

    port_lines = []
    for finding in report.ports[:8]:
        description = describe_port(finding.transport, finding.port)
        port_lines.append(
            f"  • {finding.transport}/{finding.port}: {description.service} — "
            f"{description.purpose} ({finding.count:,} source/destination field observations)"
        )
    ports = "\n".join(port_lines) if port_lines else "  • No TCP or UDP ports were observed."

    return (
        "WHAT THIS CAPTURE SHOWS\n"
        f"The analyzer processed {report.capture.packet_count:,} packets across {duration}. "
        f"It observed {summary.unique_endpoints:,} unique IP endpoints, "
        f"{summary.unique_dns_queries:,} visible DNS names, and "
        f"{summary.unique_tls_sni:,} visible TLS SNI hostnames.\n\n"
        "BASELINE CHANGES\n"
        f"{new_endpoint_count:,} endpoints, {new_domain_count:,} DNS names, and "
        f"{new_tls_count:,} TLS SNI names were absent from the selected baseline. "
        "NEW means newly observed relative to that baseline; it is not a malicious verdict. "
        "Investigate unexpected changes using timing, process, signing, ownership, and destination context.\n\n"
        "ENDPOINT NAMES AND LOCATIONS\n"
        "The Endpoints tab adds local address scope and optional local GeoIP context without resolver queries. "
        "Choose Resolve current PTR names to explicitly query the configured DNS resolver. Current PTR names "
        "are separate from captured DNS/SNI and are not written into reports or baselines. PTR records are "
        "controlled by network operators and may be missing, generic, stale, or shared. Geolocation uses only the selected local MMDB "
        "file; public endpoint IPs are not sent to a geolocation web API. IP location is "
        "approximate and must not be interpreted as a precise device, person, or household location.\n\n"
        "PORTS\n"
        f"{ports}\n"
        "A port label describes its conventional use, not a confirmed application or listening service. "
        "Counts include appearances in packet source and destination fields and are not connection counts.\n\n"
        "ENCRYPTED AND HEURISTIC SIGNALS\n"
        f"The capture contained {summary.quic_like_packets:,} QUIC-like packets. Encryption protects "
        "payload content, although endpoints and some handshake metadata can remain visible. "
        f"The DNS entropy heuristic flagged {entropy_count:,} names. High entropy can also be caused "
        "by legitimate CDNs, tracking identifiers, and generated service names, so corroboration is required."
    )


def format_bytes(size_bytes: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(size_bytes)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if value < 1024.0 or candidate == units[-1]:
            break
        value /= 1024.0
    if unit == "B":
        return f"{size_bytes:,} B"
    return f"{value:.2f} {unit} ({size_bytes:,} bytes)"


def format_duration(duration_seconds: float | None) -> str:
    if duration_seconds is None:
        return "Not observed"
    return f"{duration_seconds:,.3f} seconds"


def format_observation_count(total: int, new_count: int) -> str:
    return f"{total:,} ({new_count:,} new)"


def initial_capture_path(arguments: list[str]) -> str | None:
    candidates = [argument for argument in arguments[1:] if argument != "--smoke-test"]
    if not candidates:
        return None
    return str(Path(candidates[0]).expanduser().resolve())


def present_main_window(window: RviSentinelWindow) -> None:
    if window.closing_requested:
        return
    window.setWindowState(Qt.WindowState.WindowNoState)
    if window.width() < 900 or window.height() < 680:
        window.resize(1180, 820)
    screen = window.screen() or QApplication.primaryScreen()
    if screen is not None:
        available = screen.availableGeometry()
        visible = available.intersected(window.frameGeometry())
        if visible.width() < 300 or visible.height() < 240:
            frame = window.frameGeometry()
            frame.moveCenter(available.center())
            window.move(frame.topLeft())
    window.showNormal()
    window.raise_()
    window.activateWindow()


def main(arguments: list[str]) -> int:
    instance_lock: QLockFile | None = None
    if "--smoke-test" not in arguments:
        try:
            instance_lock = acquire_gui_instance_lock(GUI_INSTANCE_LOCK)
        except GuiInstanceAlreadyRunningError as error:
            print(str(error), file=sys.stderr)
            return 0
    qt_arguments = [argument for argument in arguments if argument != "--smoke-test"]
    application = QApplication(qt_arguments)
    application.setApplicationName("RVI-Sentinel")
    application.setApplicationDisplayName("RVI-Sentinel")
    application.setOrganizationName("hideouts-io")
    application.setWindowIcon(load_application_icon(APP_ICON))
    set_macos_application_icon(APP_ICON)

    window = RviSentinelWindow()
    quit_filter = WindowQuitFilter(window)
    application.installEventFilter(quit_filter)
    capture_path = initial_capture_path(arguments)
    if capture_path is not None:
        window.capture_field.setText(capture_path)
        window.show_destination("analysis")
    present_main_window(window)
    QTimer.singleShot(50, lambda: present_main_window(window))

    if "--smoke-test" in arguments:
        QTimer.singleShot(250, application.quit)
    exit_code = application.exec()
    if instance_lock is not None:
        instance_lock.unlock()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
