#!/usr/bin/env python3
"""Cross-platform analysis GUI for RVI-Sentinel."""

from __future__ import annotations

import shlex
import shutil
import sys
from pathlib import Path

from PySide6.QtCore import QProcess, QProcessEnvironment, Qt, QTimer, QUrl
from PySide6.QtGui import (
    QColor,
    QCloseEvent,
    QDesktopServices,
    QDragEnterEvent,
    QDropEvent,
    QFont,
)
from PySide6.QtWidgets import (
    QApplication,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
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
    load_report,
    report_path_for,
)
from finding_enrichment import (
    EndpointEnrichment,
    classify_address,
    describe_port,
    parse_enrichment_output,
)

ROOT = Path(__file__).resolve().parent
ANALYZER = ROOT / "analyze.py"
ENDPOINT_ENRICHER = ROOT / "enrich_endpoints.py"
DEFAULT_BASELINE = ROOT / "data" / "findings_master.json"
DEFAULT_EXPORT_DIRECTORY = ROOT / "exports"


class RviSentinelWindow(QMainWindow):
    """Main analysis window backed by the existing analyzer CLI."""

    def __init__(self) -> None:
        super().__init__()
        self.process = QProcess(self)
        self.enrichment_process = QProcess(self)
        self.enrichment_timer = QTimer(self)
        self.enrichment_timer.setSingleShot(True)
        self.enrichment_timed_out = False
        self.active_request: AnalysisRequest | None = None
        self.active_report_path: Path | None = None
        self.summary_labels: dict[str, QLabel] = {}

        self.capture_field = QLineEdit()
        self.baseline_field = QLineEdit(str(DEFAULT_BASELINE))
        self.export_field = QLineEdit(str(DEFAULT_EXPORT_DIRECTORY))
        self.geoip_field = QLineEdit()
        self.entropy_field = QDoubleSpinBox()
        self.top_field = QSpinBox()
        self.command_field = QLineEdit()
        self.status_label = QLabel("Ready to analyze an authorized capture.")
        self.console = QTextEdit()
        self.interpretation = QTextEdit()
        self.analyze_button = QPushButton("Analyze Capture")
        self.open_exports_button = QPushButton("Open Export Folder")

        self.endpoints_table = create_endpoint_table()
        self.domains_table = create_ranked_table(("DNS name", "Queries", "Baseline"))
        self.tls_table = create_ranked_table(("TLS SNI", "Observations", "Baseline"))
        self.protocols_table = create_ranked_table(("Protocol", "Packets", "Baseline"))
        self.ports_table = create_port_table()
        self.entropy_table = create_entropy_table()

        self.configure_window()
        self.build_interface()
        self.connect_signals()
        self.refresh_command_preview()

    def configure_window(self) -> None:
        self.setWindowTitle("RVI-Sentinel")
        self.resize(1180, 820)
        self.setMinimumSize(900, 680)
        self.setAcceptDrops(True)
        self.setStyleSheet(
            """
            QMainWindow { background: #0b1220; }
            QWidget { color: #e6edf3; font-size: 13px; }
            QLabel#applicationTitle { font-size: 28px; font-weight: 700; }
            QGroupBox {
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding: 12px;
                font-weight: 600;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
            QLineEdit, QSpinBox, QDoubleSpinBox, QTextEdit {
                background: #111827;
                border: 1px solid #374151;
                border-radius: 6px;
                padding: 6px;
                selection-background-color: #2563eb;
            }
            QTableWidget {
                background: #111827;
                alternate-background-color: #0f172a;
                border: 1px solid #374151;
                border-radius: 6px;
                gridline-color: #374151;
                selection-background-color: #1f6feb;
                selection-color: #ffffff;
            }
            QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {
                border: 1px solid #58a6ff;
            }
            QPushButton {
                background: #1f6feb;
                border: 0;
                border-radius: 6px;
                padding: 8px 14px;
                font-weight: 600;
            }
            QPushButton:hover { background: #388bfd; }
            QPushButton:disabled { background: #30363d; color: #8b949e; }
            QTabWidget { background: #0b1220; }
            QTabWidget::pane {
                background: #111827;
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QTabBar { background: #0b1220; }
            QTabBar::tab { background: #161b22; padding: 8px 13px; margin-right: 2px; }
            QTabBar::tab:selected { background: #1f6feb; }
            QHeaderView::section {
                background: #1f2937;
                border: 0;
                border-right: 1px solid #374151;
                padding: 7px;
                font-weight: 600;
            }
            """
        )

    def build_interface(self) -> None:
        root_widget = QWidget()
        root_layout = QVBoxLayout(root_widget)
        root_layout.setContentsMargins(20, 18, 20, 18)
        root_layout.setSpacing(12)

        title = QLabel("RVI-Sentinel")
        title.setObjectName("applicationTitle")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title.setFont(title_font)

        subtitle = QLabel(
            "Authorized PCAP/PCAPNG analysis with persistent new-versus-known baselining"
        )
        subtitle.setStyleSheet("color: #9ca3af; font-size: 14px;")

        scope = QLabel(
            "A new endpoint or hostname is a change to investigate, not proof of malicious activity. "
            "Encrypted payloads remain protected."
        )
        scope.setWordWrap(True)
        scope.setStyleSheet(
            "background: #172554; border-left: 4px solid #3b82f6; "
            "border-radius: 4px; padding: 10px; color: #bfdbfe;"
        )

        root_layout.addWidget(title)
        root_layout.addWidget(subtitle)
        root_layout.addWidget(scope)
        root_layout.addWidget(self.create_configuration_group())
        root_layout.addLayout(self.create_action_row())
        root_layout.addWidget(self.create_results_tabs(), 1)
        root_layout.addWidget(self.status_label)

        self.setCentralWidget(root_widget)

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
        layout.addWidget(QLabel("Exact command"), 5, 0)
        layout.addWidget(self.command_field, 5, 1, 1, 3)

        capture_button.clicked.connect(self.choose_capture)
        baseline_button.clicked.connect(self.choose_baseline)
        export_button.clicked.connect(self.choose_export_directory)
        geoip_button.clicked.connect(self.choose_geoip_database)
        return group

    def create_action_row(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        self.analyze_button.setObjectName("analyzeButton")
        self.open_exports_button.setObjectName("openExportsButton")
        self.open_exports_button.setEnabled(DEFAULT_EXPORT_DIRECTORY.exists())
        clear_button = QPushButton("Clear Results")
        clear_button.setObjectName("clearResultsButton")

        self.analyze_button.clicked.connect(self.start_analysis)
        self.open_exports_button.clicked.connect(self.open_export_directory)
        clear_button.clicked.connect(self.clear_results)

        requirement = "tshark found" if shutil.which("tshark") else "tshark not found"
        requirement_label = QLabel(requirement)
        requirement_label.setStyleSheet(
            "color: #3fb950;" if shutil.which("tshark") else "color: #f85149;"
        )

        layout.addWidget(self.analyze_button)
        layout.addWidget(self.open_exports_button)
        layout.addWidget(clear_button)
        layout.addStretch(1)
        layout.addWidget(requirement_label)
        return layout

    def create_results_tabs(self) -> QTabWidget:
        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.addTab(self.create_summary_tab(), "Summary")
        self.interpretation.setReadOnly(True)
        self.interpretation.setAccessibleName("Findings interpretation")
        self.interpretation.setPlainText(
            "Analyze a capture to receive a plain-language explanation of the findings."
        )
        tabs.addTab(self.interpretation, "Interpretation")
        tabs.addTab(self.endpoints_table, "Endpoints")
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
        return tabs

    def create_summary_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)

        capture_group = QGroupBox("Capture")
        capture_layout = QFormLayout(capture_group)
        summary_group = QGroupBox("Observed metadata")
        summary_layout = QFormLayout(summary_group)

        capture_fields = (
            ("capture_path", "Path"),
            ("size_bytes", "Size"),
            ("packet_count", "Packets"),
            ("duration", "Duration"),
            ("first_packet", "First packet"),
            ("last_packet", "Last packet"),
        )
        summary_fields = (
            ("endpoints", "Unique endpoints"),
            ("dns", "Unique DNS names"),
            ("tls", "Unique TLS SNI"),
            ("quic", "QUIC-like packets"),
        )

        for key, label_text in capture_fields:
            label = QLabel("—")
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.summary_labels[key] = label
            capture_layout.addRow(label_text, label)

        for key, label_text in summary_fields:
            label = QLabel("—")
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.summary_labels[key] = label
            summary_layout.addRow(label_text, label)

        layout.addWidget(capture_group)
        layout.addWidget(summary_group)
        layout.addStretch(1)
        return widget

    def connect_signals(self) -> None:
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
        self.enrichment_process.finished.connect(self.endpoint_enrichment_finished)
        self.enrichment_process.errorOccurred.connect(self.endpoint_enrichment_error)
        self.enrichment_timer.timeout.connect(self.endpoint_enrichment_timeout)

    def choose_capture(self) -> None:
        selected, _filter = QFileDialog.getOpenFileName(
            self,
            "Select an authorized packet capture",
            str(ROOT / "captures"),
            "Packet captures (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if selected:
            self.capture_field.setText(selected)

    def choose_baseline(self) -> None:
        selected, _filter = QFileDialog.getSaveFileName(
            self,
            "Select persistent baseline",
            self.baseline_field.text(),
            "JSON files (*.json);;All files (*)",
        )
        if selected:
            self.baseline_field.setText(selected)

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
            self.current_geoip_database()
            arguments = analyzer_arguments(request, ANALYZER)
            command = shlex.join([sys.executable, *arguments])
        except RequestValidationError:
            command = (
                "Select a valid capture and optional GeoIP database to preview the analyzer command."
            )
        self.command_field.setText(command)
        self.command_field.setCursorPosition(0)
        self.command_field.setToolTip(command)

    def start_analysis(self) -> None:
        if self.process.state() != QProcess.ProcessState.NotRunning:
            return
        try:
            request = self.current_request()
            arguments = analyzer_arguments(request, ANALYZER)
        except RequestValidationError as error:
            self.show_error("Invalid analysis configuration", str(error))
            return

        self.active_request = request
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

        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("PYTHONUNBUFFERED", "1")
        self.process.setProcessEnvironment(environment)
        self.process.setWorkingDirectory(str(ROOT))
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
        self.read_standard_output()
        self.read_standard_error()
        self.analyze_button.setEnabled(True)

        request = self.active_request
        self.active_request = None
        if request is None:
            self.show_error("Analyzer state error", "No active analysis request was recorded.")
            return
        if exit_status != QProcess.ExitStatus.NormalExit or exit_code != 0:
            self.status_label.setText(f"Analysis failed with exit code {exit_code}.")
            self.show_error(
                "Analysis failed",
                f"The analyzer exited with code {exit_code}. Review the Console tab for details.",
            )
            return

        report_path = report_path_for(request)
        try:
            report = load_report(report_path)
        except ReportValidationError as error:
            self.status_label.setText("Analysis completed, but the report could not be loaded.")
            self.show_error("Report validation failed", str(error))
            return

        self.active_report_path = report_path
        self.populate_report(report)
        self.start_endpoint_enrichment(report.endpoints)
        self.open_exports_button.setEnabled(True)

    def process_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.Crashed:
            return
        self.analyze_button.setEnabled(True)
        self.status_label.setText("The analyzer process could not be started.")
        self.show_error("Process error", self.process.errorString())

    def populate_report(self, report: AnalysisReport) -> None:
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

        populate_ranked_table(self.domains_table, report.domains)
        populate_ranked_table(self.tls_table, report.tls_sni)
        populate_ranked_table(self.protocols_table, report.protocols)
        populate_port_table(self.ports_table, report.ports)
        populate_entropy_table(self.entropy_table, report.entropy_findings)
        self.interpretation.setPlainText(build_findings_explanation(report))

    def start_endpoint_enrichment(self, endpoints: tuple[RankedFinding, ...]) -> None:
        populate_endpoint_table(self.endpoints_table, endpoints)
        if not endpoints:
            self.status_label.setText(self.completed_status("No endpoints to enrich."))
            return

        arguments = [str(ENDPOINT_ENRICHER)]
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

        self.enrichment_timed_out = False
        self.enrichment_process.setWorkingDirectory(str(ROOT))
        self.enrichment_process.setProgram(sys.executable)
        self.enrichment_process.setArguments(arguments)
        self.status_label.setText(
            "Analysis complete; resolving PTR hostnames and local GeoIP locations…"
        )
        self.enrichment_process.start()
        self.enrichment_timer.start(30_000)

    def endpoint_enrichment_finished(
        self, exit_code: int, exit_status: QProcess.ExitStatus
    ) -> None:
        self.enrichment_timer.stop()
        if self.enrichment_timed_out:
            self.endpoints_table.setSortingEnabled(True)
            return

        error_text = bytes(self.enrichment_process.readAllStandardError()).decode(
            "utf-8", errors="replace"
        ).strip()
        if exit_status != QProcess.ExitStatus.NormalExit or exit_code != 0:
            detail = error_text or f"Endpoint enrichment exited with code {exit_code}."
            self.console.append(f"\n{detail}\n")
            self.endpoints_table.setSortingEnabled(True)
            self.status_label.setText(self.completed_status("Endpoint enrichment failed."))
            self.show_error("Endpoint enrichment failed", detail)
            return

        output = bytes(self.enrichment_process.readAllStandardOutput()).decode(
            "utf-8", errors="strict"
        )
        try:
            enrichment = parse_enrichment_output(output)
        except (UnicodeDecodeError, ValueError) as error:
            self.endpoints_table.setSortingEnabled(True)
            self.status_label.setText(
                self.completed_status("Endpoint enrichment output was invalid.")
            )
            self.show_error("Endpoint enrichment output invalid", str(error))
            return

        try:
            apply_endpoint_enrichment(self.endpoints_table, enrichment)
        except ValueError as error:
            self.endpoints_table.setSortingEnabled(True)
            self.status_label.setText(
                self.completed_status("Endpoint enrichment did not match the report.")
            )
            self.show_error("Endpoint enrichment mismatch", str(error))
            return
        geo_status = (
            "Local GeoIP applied."
            if self.geoip_field.text().strip()
            else "GeoIP database not configured."
        )
        self.status_label.setText(
            self.completed_status(f"PTR resolution complete. {geo_status}")
        )

    def endpoint_enrichment_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.Crashed or self.enrichment_timed_out:
            return
        self.enrichment_timer.stop()
        self.endpoints_table.setSortingEnabled(True)
        detail = self.enrichment_process.errorString()
        self.console.append(f"\nEndpoint enrichment process error: {detail}\n")
        self.status_label.setText(
            self.completed_status("Endpoint enrichment process could not start.")
        )

    def endpoint_enrichment_timeout(self) -> None:
        if self.enrichment_process.state() == QProcess.ProcessState.NotRunning:
            return
        self.enrichment_timed_out = True
        self.enrichment_process.kill()
        self.endpoints_table.setSortingEnabled(True)
        detail = "Endpoint PTR resolution exceeded 30 seconds and was stopped."
        self.console.append(f"\n{detail}\n")
        self.status_label.setText(self.completed_status(detail))

    def cancel_endpoint_enrichment(self) -> None:
        self.enrichment_timer.stop()
        if self.enrichment_process.state() != QProcess.ProcessState.NotRunning:
            self.enrichment_timed_out = True
            self.enrichment_process.kill()

    def completed_status(self, detail: str) -> str:
        report = str(self.active_report_path) if self.active_report_path else "not available"
        return f"Analysis complete. {detail} Report: {report}"

    def clear_results(self) -> None:
        self.cancel_endpoint_enrichment()
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
        self.capture_field.setText(urls[0].toLocalFile())
        event.acceptProposedAction()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.enrichment_timer.stop()
        for process in (self.process, self.enrichment_process):
            if process.state() != QProcess.ProcessState.NotRunning:
                process.kill()
                process.waitForFinished(1_000)
        super().closeEvent(event)


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
        hostname_item = QTableWidgetItem("Resolving…")
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
        "The Endpoints tab adds PTR reverse-DNS names and address scope. PTR records are controlled "
        "by network operators and may be missing, generic, stale, or shared. PTR lookup queries are "
        "sent to the Mac's configured DNS resolver. Geolocation uses only the selected local MMDB "
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


def main(arguments: list[str]) -> int:
    qt_arguments = [argument for argument in arguments if argument != "--smoke-test"]
    application = QApplication(qt_arguments)
    application.setApplicationName("RVI-Sentinel")
    application.setOrganizationName("hideouts-io")

    window = RviSentinelWindow()
    capture_path = initial_capture_path(arguments)
    if capture_path is not None:
        window.capture_field.setText(capture_path)
    window.show()

    if "--smoke-test" in arguments:
        QTimer.singleShot(250, application.quit)
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
