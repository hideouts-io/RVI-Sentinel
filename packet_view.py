"""Qt packet timeline with bounded pages, cancellable workers and plain-text evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace
from bisect import bisect_left, bisect_right
from datetime import UTC, datetime
from html import escape
from threading import Event
from typing import Callable, Iterator

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QSplitter, QTableView, QVBoxLayout, QWidget,
)

from gui_models import AnalysisReport
from captured_dns import CapturedDnsMessage
from packet_models import PacketRecord, ProcessMetadata
from packet_timeline import (
    PacketIdentity, PacketIndex, PacketPage, PacketQuery, PacketQueryCancelled,
    PacketQueryValidationError, build_packet_index, packet_for_identity, query_packets, restrict_packet_index,
    validate_packet_query,
)

COLUMNS = (
    "Frame", "Time (UTC)", "Protocol", "Source", "Destination", "Process",
    "Effective process", "Interface", "Direction", "Wire / captured bytes", "Stream",
)
CELL_MAX_BYTES = 8 * 1024
INSPECTOR_MAX_BYTES = 512 * 1024
INSPECTOR_LIMIT_NOTICE = "Inspector rendering limit exceeded."


def evidence_tooltip_text(value: str) -> str:
    """Escape recorded text for Qt's rich-text tooltip renderer."""
    return '<pre style="white-space: pre-wrap">' + escape(value) + "</pre>"


def validate_scope_frames(frame_numbers: tuple[int, ...], packet_count: int) -> None:
    """Reject fabricated navigation scopes before changing the completed view."""
    if type(frame_numbers) is not tuple or len(frame_numbers) > packet_count or any(type(frame) is not int or not 1 <= frame <= packet_count for frame in frame_numbers) or len(set(frame_numbers)) != len(frame_numbers):
        raise PacketQueryValidationError("Packet navigation requires unique original frame identities from this capture.")


def validate_scope_label(label: str) -> None:
    if type(label) is not str or len(label.encode("utf-8")) > 512 or any(ord(character) < 32 or ord(character) == 127 for character in label):
        raise PacketQueryValidationError("Packet scope label must be bounded plain text.")


def packet_utc_time(packet: PacketRecord) -> str:
    """Render full nanoseconds where the platform calendar supports the epoch."""
    try:
        calendar = datetime.fromtimestamp(packet.timestamp.seconds, UTC)
    except (OverflowError, OSError, ValueError):
        return f"Epoch {packet.timestamp.epoch} (outside calendar range)"
    return f"{calendar:%Y-%m-%d %H:%M:%S}.{packet.timestamp.nanoseconds:09d}Z"


def endpoint_label(address: str | None, port: int | None) -> str:
    if address is None:
        return "Unknown" if port is None else f"Unknown address, port {port}"
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def metadata_cell(state: str, labels: Iterator[str], label_count: int) -> str:
    """Use an explicit count summary when a recorded-label cell exceeds 8 KiB."""
    rendered: list[str] = []
    size = len(state.encode("utf-8")) + 2
    for label in labels:
        size += len(label.encode("utf-8")) + 2
        if size > CELL_MAX_BYTES:
            return f"{state}: {label_count} recorded labels (8 KiB cell limit; full values in inspector/report)"
        rendered.append(label)
    return state.capitalize() if not rendered else f"{state}: " + "; ".join(rendered)


def process_label(metadata: ProcessMetadata) -> str:
    if not metadata.labels:
        return metadata.state.capitalize()
    labels = (
        f"{label.name or 'Unknown name'} (PID {label.pid if label.pid is not None else 'unknown'})"
        for label in metadata.labels
    )
    return metadata_cell(metadata.state, labels, len(metadata.labels))


def packet_cell(packet: PacketRecord, column: int) -> str:
    """Compute only the requested table cell, with bounded metadata rendering."""
    if column == 0:
        return str(packet.frame_number)
    if column == 1:
        return packet_utc_time(packet)
    if column == 2:
        return ":".join(packet.protocol_stack)
    if column == 3:
        return endpoint_label(packet.source_address, packet.source_port)
    if column == 4:
        return endpoint_label(packet.destination_address, packet.destination_port)
    if column == 5:
        return process_label(packet.process)
    if column == 6:
        return process_label(packet.effective_process)
    if column == 7:
        return metadata_cell(packet.interface.state, (label.name for label in packet.interface.labels), len(packet.interface.labels))
    if column == 8:
        return metadata_cell(packet.direction.state, (label.direction for label in packet.direction.labels), len(packet.direction.labels))
    if column == 9:
        return f"{packet.wire_length} / {packet.captured_length if packet.captured_length is not None else 'unavailable'}"
    if column == 10:
        return f"{packet.transport or 'unknown'} {packet.stream if packet.stream is not None else 'unavailable'}"
    raise IndexError("Packet table column is outside the model schema.")


def dns_message_lines(message: CapturedDnsMessage) -> Iterator[str]:
    """Render one structured message with its original decoder record boundaries."""
    yield f"  Decoder frame: {message.frame_number}; message index: {message.message_index}; protocol: {message.protocol}"
    yield f"  Transaction ID: {message.transaction_id}; opcode: {message.opcode}; response: {message.is_response}; truncated: {message.is_truncated}; response code: {message.response_code}"
    yield f"  Linked query decoder frame: {message.response_to_frame if message.response_to_frame is not None else 'unavailable'}"
    for position, question in enumerate(message.questions, 1):
        yield f"  Question ordinal {position}: canonical name={question.name}; type={question.record_type}; class={question.record_class}"
    for position, record in enumerate(message.answers, 1):
        yield f"  Answer ordinal {position}: owner={record.owner if record.owner is not None else '(not emitted by decoder)'}; type={record.record_type}; class={record.record_class}; TTL={record.ttl_seconds}; value={record.value if record.value is not None else '(unsupported observed record)'}"


def packet_inspector_lines(report: AnalysisReport, packet: PacketRecord) -> Iterator[str]:
    """Yield literal evidence lines without constructing an unbounded text buffer."""
    evidence = report.evidence
    if evidence is None:
        yield "Packet evidence unavailable in this legacy report."
        return
    yield from (
        "Saved-file packet evidence", f"Capture SHA-256: {evidence.sha256}",
        f"Packet identity: sha256:{evidence.sha256} / frame:{packet.frame_number}",
        f"Origin: {evidence.origin}; integrity: {evidence.integrity}",
        f"Frame: {packet.frame_number}", f"Exact recorded epoch: {packet.timestamp.epoch}",
        f"UTC: {packet_utc_time(packet)}", f"Wire length: {packet.wire_length} bytes",
        f"Captured length: {packet.captured_length if packet.captured_length is not None else 'unavailable'}",
        f"Protocol stack: {':'.join(packet.protocol_stack)}",
        f"Source: {endpoint_label(packet.source_address, packet.source_port)}",
        f"Destination: {endpoint_label(packet.destination_address, packet.destination_port)}",
        f"Transport: {packet.transport or 'unknown'}; stream: {packet.stream if packet.stream is not None else 'unavailable'}",
        "", "Recorded process metadata (unknown does not establish absence)",
    )
    for title, metadata in (("Process", packet.process), ("Effective process", packet.effective_process)):
        yield f"{title} state: {metadata.state}"
        for label in metadata.labels:
            yield f"  Source: {label.source}; PID: {label.pid if label.pid is not None else 'unknown'}; name: {label.name if label.name is not None else 'unknown'}"
    yield from ("", f"Interface state: {packet.interface.state}")
    for label in packet.interface.labels:
        yield f"  Source: {label.source}; name: {label.name}"
    yield f"Direction state: {packet.direction.state}"
    for label in packet.direction.labels:
        yield f"  Source: {label.source}; direction: {label.direction}"
    yield from ("", "Decoder coverage", f"Decoder: {evidence.tshark_version}")
    recorded_fields = frozenset(field.name for field in packet.fields)
    absent = tuple(name for name in evidence.supported_fields if name not in recorded_fields)
    yield f"Supported fields ({len(evidence.supported_fields)}): {', '.join(evidence.supported_fields)}"
    yield f"Supported but absent on this packet ({len(absent)}): {', '.join(absent) or '(none)'}"
    yield f"Unsupported decoder fields ({len(evidence.unsupported_fields)}): {', '.join(evidence.unsupported_fields) or '(none)'}"
    yield from ("", "Recorded decoded field occurrences")
    for field in packet.fields:
        yield f"{field.name} ({len(field.values)} occurrences)"
        yield from (f"  [{position}] {value}" for position, value in enumerate(field.values, 1))
    yield from ("", "Packet diagnostics")
    yield from packet.diagnostics or ("(none)",)
    if report.dns_evidence is not None:
        messages = report.dns_evidence.messages
        first = bisect_left(messages, packet.frame_number, key=lambda message: message.frame_number)
        last = bisect_right(messages, packet.frame_number, key=lambda message: message.frame_number)
        if first < last:
            yield from ("", "Structured decoder DNS message evidence", "A decoder frame can contain a completed TCP reassembly; these references do not imply all message bytes originated in this packet.")
            for position in range(first, last):
                yield from dns_message_lines(messages[position])
    yield from ("", "Fields beginning pcapng.apple.process are read directly from the original container; frame and pktap fields are TShark observations.", "Only saved decoded fields are shown. Raw packet bytes are not present in this report. PTR resolution is not performed by the timeline.")


def packet_inspector_text(report: AnalysisReport, packet: PacketRecord) -> str:
    """Render all evidence or explicitly refuse text exceeding 512 KiB; never truncate."""
    lines: list[str] = []
    size = 0
    for line in packet_inspector_lines(report, packet):
        size += len(line.encode("utf-8")) + 1
        if size > INSPECTOR_MAX_BYTES:
            digest = report.evidence.sha256 if report.evidence is not None else "unavailable"
            return "\n".join((
                INSPECTOR_LIMIT_NOTICE, f"Capture SHA-256: {digest}",
                f"Packet identity: sha256:{digest} / frame:{packet.frame_number}",
                f"Exact recorded epoch: {packet.timestamp.epoch}",
                "The complete inspector text exceeds the 512 KiB rendering ceiling. No partial record is presented.",
                "All original decoded fields remain unchanged in the saved analysis report. Inspect that report for the complete evidence.",
            ))
        lines.append(line)
    return "\n".join(lines)


class PacketPageModel(QAbstractTableModel):
    """Expose only the completed visible page; never copy the full packet index."""

    def __init__(self, parent: QObject) -> None:
        super().__init__(parent)
        self.setObjectName("packetPageModel")
        self.packets: tuple[PacketRecord, ...] = ()

    def set_packets(self, packets: tuple[PacketRecord, ...]) -> None:
        self.beginResetModel()
        self.packets = packets
        self.endResetModel()

    def rowCount(self, parent: QModelIndex) -> int:
        return 0 if parent.isValid() else len(self.packets)

    def columnCount(self, parent: QModelIndex) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int) -> str | None:
        if not index.isValid() or index.row() < 0 or index.row() >= len(self.packets) or not 0 <= index.column() < len(COLUMNS):
            return None
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            value = packet_cell(self.packets[index.row()], index.column())
            return evidence_tooltip_text(value) if role == Qt.ItemDataRole.ToolTipRole else value
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int) -> str | None:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal and 0 <= section < len(COLUMNS):
            return COLUMNS[section]
        return None


@dataclass(frozen=True)
class _JobRequest:
    generation: int
    index: PacketIndex | None
    base_index: PacketIndex | None
    scope_frames: tuple[int, ...] | None
    sha256: str
    packets: tuple[PacketRecord, ...]
    query: PacketQuery
    selected_identity: PacketIdentity | None
    selection_page_identity: PacketIdentity | None


@dataclass(frozen=True)
class _JobOutcome:
    generation: int
    index: PacketIndex | None
    page: PacketPage | None
    base_index: PacketIndex | None
    query: PacketQuery
    error: Exception | None


class _PacketQueryWorker(QThread):
    """External Qt thread connector; all domain work runs outside the UI thread."""

    completed = Signal(object)

    def __init__(self, request: _JobRequest, cancellation: Event, parent: QObject) -> None:
        super().__init__(parent)
        self.request = request
        self.cancellation = cancellation

    @Slot()
    def run(self) -> None:
        try:
            base_index = self.request.base_index
            if base_index is None:
                base_index = build_packet_index(self.request.sha256, self.request.packets, self.cancellation)
            index = self.request.index
            if index is None:
                index = base_index if self.request.scope_frames is None else restrict_packet_index(base_index, self.request.scope_frames, self.cancellation)
            query = self.request.query
            page = query_packets(index, query, self.request.selected_identity, self.cancellation)
            if self.request.selection_page_identity is not None and page.selected_match_page is not None and page.selected_match_page != page.page_number:
                query = replace(query, page_number=page.selected_match_page)
                page = query_packets(index, query, self.request.selected_identity, self.cancellation)
            outcome = _JobOutcome(self.request.generation, index, page, base_index, query, None)
        except (PacketQueryCancelled, PacketQueryValidationError) as error:
            outcome = _JobOutcome(self.request.generation, None, None, None, self.request.query, error)
        except Exception as error:
            # Unexpected connector-boundary failures retain their cause and end the owned thread.
            outcome = _JobOutcome(self.request.generation, None, None, None, self.request.query, error)
        self.completed.emit(outcome)


@dataclass(frozen=True)
class PacketNavigation:
    capture_sha256: str
    report_generation: int
    query: PacketQuery | None
    selected_identity: PacketIdentity | None
    scope_frames: tuple[int, ...] | None
    scope_label: str
    vertical_scroll_value: int


class PacketTimelineWidget(QWidget):
    """One owned worker and one replaceable pending query, with stable packet selection."""

    page_changed = Signal()
    busy_changed = Signal(bool)
    shutdown_complete = Signal()
    packet_selected = Signal(object)
    owning_session_requested = Signal()
    back_to_sessions_requested = Signal()
    restore_timeline_requested = Signal()
    return_dns_requested = Signal()

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setObjectName("packetTimeline")
        self.report: AnalysisReport | None = None
        self.completed_page: PacketPage | None = None
        self.selected_identity: PacketIdentity | None = None
        self._index: PacketIndex | None = None
        self._base_index: PacketIndex | None = None
        self._scope_frames: tuple[int, ...] | None = None
        self._report_generation = 0
        self._restore_scroll: int | None = None
        self._completed_query: PacketQuery | None = None
        self._generation = 0
        self._pending: _JobRequest | None = None
        self._active_request: _JobRequest | None = None
        self._thread: QThread | None = None
        self._cancellation: Event | None = None
        self._shutting_down = False
        self._applying_page = False
        self._last_worker_failure: Exception | None = None
        self._create_controls()
        self._show_unavailable("Analyze a saved capture to load traceable packet evidence.")

    def _create_controls(self) -> None:
        layout = QVBoxLayout(self)
        filters = QGridLayout()
        self.search_field = self._text_control("packetSearch", "Literal text across saved decoded fields")
        self.endpoint_field = self._text_control("packetEndpointFilter", "Exact source or destination IP address")
        self.port_field = self._text_control("packetPortFilter", "Either source or destination port")
        self.protocol_field = self._text_control("packetProtocolFilter", "Exact protocol layer or decoder protocol label")
        self.process_field = self._text_control("packetProcessFilter", "Recorded or effective process name, PID or source")
        self.interface_field = self._text_control("packetInterfaceFilter", "Recorded interface text")
        self.process_state = self._state_control("packetProcessStateFilter", ("all", "recorded", "unknown", "conflict"))
        self.process_state.setToolTip("Filter the regular recorded process state. The process text filter also searches effective-process labels.")
        self.interface_state = self._state_control("packetInterfaceStateFilter", ("all", "recorded", "unknown", "conflict"))
        self.direction_field = self._state_control("packetDirectionFilter", ("all", "inbound", "outbound", "unknown", "conflict"))
        self.direction_field.setToolTip("Inbound and outbound require unambiguous recorded direction. Unknown and conflicting evidence have separate filters.")
        controls = (("Search", self.search_field), ("Endpoint", self.endpoint_field), ("Port", self.port_field), ("Protocol", self.protocol_field), ("Process / effective", self.process_field), ("Process state", self.process_state), ("Interface", self.interface_field), ("Interface state", self.interface_state), ("Direction", self.direction_field))
        for position, (name, control) in enumerate(controls):
            row, group = divmod(position, 3)
            label = QLabel(name, self)
            label.setBuddy(control)
            filters.addWidget(label, row, group * 2)
            filters.addWidget(control, row, group * 2 + 1)
        layout.addLayout(filters)
        actions = QHBoxLayout()
        self.apply_button = self._button("packetApplyFilters", "Apply filters", self.apply_filters)
        self.clear_button = self._button("packetClearFilters", "Clear filters", self.clear_filters)
        self.cancel_button = self._button("packetCancelQuery", "Cancel query", self.cancel_query)
        self.page_size = QComboBox(self)
        self.page_size.setObjectName("packetPageSize")
        for size in (100, 250, 500):
            self.page_size.addItem(str(size), size)
        actions.addWidget(self.apply_button)
        actions.addWidget(self.clear_button)
        actions.addWidget(self.cancel_button)
        actions.addStretch()
        actions.addWidget(QLabel("Rows per page", self))
        actions.addWidget(self.page_size)
        layout.addLayout(actions)
        self.scope_label = QLabel("All packets in this capture", self)
        self.scope_label.setObjectName("packetScope")
        self.scope_label.setTextFormat(Qt.TextFormat.PlainText)
        self.scope_label.setWordWrap(True)
        layout.addWidget(self.scope_label)
        self.status_label = QLabel(self)
        self.status_label.setObjectName("packetPageStatus")
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        splitter = QSplitter(Qt.Orientation.Vertical, self)
        splitter.setObjectName("packetTimelineSplitter")
        self.table = QTableView(splitter)
        self.table.setObjectName("packetTable")
        self.model = PacketPageModel(self.table)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.setWordWrap(False)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        inspector_panel = QWidget(splitter)
        inspector_layout = QVBoxLayout(inspector_panel)
        self.selection_notice = QLabel(inspector_panel)
        self.selection_notice.setObjectName("packetSelectionNotice")
        self.selection_notice.setTextFormat(Qt.TextFormat.PlainText)
        self.selection_notice.setWordWrap(True)
        self.correlation_label = QLabel("Session correlation is not yet available.", inspector_panel)
        self.correlation_label.setObjectName("packetSessionCorrelation")
        self.correlation_label.setTextFormat(Qt.TextFormat.PlainText)
        self.correlation_label.setWordWrap(True)
        self.inspector = QPlainTextEdit(inspector_panel)
        self.inspector.setObjectName("packetInspector")
        self.inspector.setReadOnly(True)
        inspector_layout.addWidget(self.selection_notice)
        inspector_layout.addWidget(self.correlation_label)
        inspector_layout.addWidget(self.inspector)
        splitter.addWidget(self.table)
        splitter.addWidget(inspector_panel)
        layout.addWidget(splitter, 1)
        navigation = QHBoxLayout()
        self.previous_button = self._button("packetPreviousPage", "Previous page", self.previous_page)
        self.next_button = self._button("packetNextPage", "Next page", self.next_page)
        navigation.addWidget(self.previous_button)
        navigation.addWidget(self.next_button)
        self.owning_session_button = self._button("packetShowOwningSession", "Show owning session", self.owning_session_requested.emit)
        self.back_to_sessions_button = self._button("packetBackToSessions", "Back to sessions", self.back_to_sessions_requested.emit)
        self.restore_timeline_button = self._button("packetRestoreTimeline", "Restore previous packet view", self.restore_timeline_requested.emit)
        self.return_dns_button = self._button("packetReturnToDnsEvidence", "Return to DNS evidence", self.return_dns_requested.emit)
        self.return_dns_button.setEnabled(False)
        self.owning_session_button.setEnabled(False)
        self.back_to_sessions_button.setEnabled(False)
        self.restore_timeline_button.setEnabled(False)
        navigation.addWidget(self.owning_session_button)
        navigation.addWidget(self.back_to_sessions_button)
        navigation.addWidget(self.restore_timeline_button)
        navigation.addWidget(self.return_dns_button)
        navigation.addStretch()
        layout.addLayout(navigation)
        self.page_size.currentIndexChanged.connect(self.apply_filters)
        for control in (self.search_field, self.endpoint_field, self.port_field, self.protocol_field, self.process_field, self.interface_field):
            control.returnPressed.connect(self.apply_filters)

    def _text_control(self, name: str, placeholder: str) -> QLineEdit:
        control = QLineEdit(self)
        control.setObjectName(name)
        control.setPlaceholderText(placeholder)
        control.setMaxLength(512)
        return control

    def _state_control(self, name: str, choices: tuple[str, ...]) -> QComboBox:
        control = QComboBox(self)
        control.setObjectName(name)
        for choice in choices:
            control.addItem(choice.capitalize(), choice)
        return control

    def _button(self, name: str, text: str, action: Callable[[], None]) -> QPushButton:
        button = QPushButton(text, self)
        button.setObjectName(name)
        button.clicked.connect(action)
        return button

    def _show_unavailable(self, message: str) -> None:
        self.completed_page = None
        self._completed_query = None
        self.model.set_packets(())
        self.selected_identity = None
        self.owning_session_button.setEnabled(False)
        self.correlation_label.setText("No selected packet for session correlation.")
        self.packet_selected.emit(None)
        self.inspector.setPlainText(message)
        self.selection_notice.setText("No selected packet.")
        self.status_label.setText(message)
        self._set_controls(False)

    def set_report(self, report: AnalysisReport) -> None:
        if self._shutting_down:
            return
        new_digest = report.evidence.sha256 if report.evidence is not None else None
        self.report = report
        self._report_generation += 1
        self._base_index = None
        self._scope_frames = None
        self._restore_scroll = None
        self.scope_label.setText("All packets in this capture")
        self.back_to_sessions_button.setEnabled(False)
        self.restore_timeline_button.setEnabled(False)
        self.return_dns_button.setEnabled(False)
        self._invalidate_request()
        self._pending = None
        self._index = None
        if new_digest is None:
            self._index = None
            self._show_unavailable("Packet evidence unavailable in this legacy report. Aggregate findings remain available.")
            return
        self._show_unavailable("Loading packet evidence for the current capture…")
        self._schedule_query(1)

    @property
    def is_busy(self) -> bool:
        return self._thread is not None or self._pending is not None

    @property
    def page(self) -> PacketPage | None:
        return self.completed_page

    def clear_report(self) -> None:
        """Invalidate evidence immediately while cancelling only the owned worker."""
        self.report = None
        self._report_generation += 1
        self._base_index = None
        self._scope_frames = None
        self._restore_scroll = None
        self.scope_label.setText("All packets in this capture")
        self.back_to_sessions_button.setEnabled(False)
        self.restore_timeline_button.setEnabled(False)
        self.return_dns_button.setEnabled(False)
        self._pending = None
        self._index = None
        self._invalidate_request()
        self._show_unavailable("Analyze a saved capture to load traceable packet evidence.")

    def _invalidate_request(self) -> None:
        self._generation += 1
        if self._cancellation is not None:
            self._cancellation.set()

    def _query(self, page_number: int) -> PacketQuery:
        port_text = self.port_field.text().strip()
        if port_text and (not port_text.isascii() or not port_text.isdecimal()):
            raise PacketQueryValidationError("Port must be a decimal integer between 0 and 65535.")
        port = int(port_text) if port_text else None
        if port is not None and not 0 <= port <= 65535:
            raise PacketQueryValidationError("Port must be a decimal integer between 0 and 65535.")
        size = self.page_size.currentData()
        process_state = self.process_state.currentData()
        interface_state = self.interface_state.currentData()
        direction = self.direction_field.currentData()
        if type(size) is not int or size not in (100, 250, 500):
            raise PacketQueryValidationError("Page size must be 100, 250 or 500.")
        if process_state not in ("all", "recorded", "unknown", "conflict") or interface_state not in ("all", "recorded", "unknown", "conflict") or direction not in ("all", "inbound", "outbound", "unknown", "conflict"):
            raise PacketQueryValidationError("Packet metadata filters contain an invalid state.")
        return PacketQuery(self.search_field.text(), self.endpoint_field.text(), port, self.protocol_field.text(), self.process_field.text(), process_state, self.interface_field.text(), interface_state, direction, page_number, size)

    @Slot()
    def apply_filters(self) -> None:
        self._schedule_query(1)

    @Slot()
    def clear_filters(self) -> None:
        for control in (self.search_field, self.endpoint_field, self.port_field, self.protocol_field, self.process_field, self.interface_field):
            control.clear()
        for control in (self.process_state, self.interface_state, self.direction_field):
            control.setCurrentIndex(0)
        self._schedule_query(1)

    @Slot()
    def previous_page(self) -> None:
        if self.completed_page is not None and self._completed_query is not None:
            self._queue_query(replace(self._completed_query, page_number=max(1, self.completed_page.page_number - 1)), None)

    @Slot()
    def next_page(self) -> None:
        if self.completed_page is not None and self._completed_query is not None:
            self._queue_query(replace(self._completed_query, page_number=self.completed_page.page_number + 1), None)

    def _schedule_query(self, page_number: int) -> None:
        report = self.report
        if self._shutting_down or report is None or report.evidence is None:
            return
        try:
            query = self._query(page_number)
        except PacketQueryValidationError as error:
            self._invalidate_request()
            self._pending = None
            self.status_label.setText(f"Invalid packet filter: {error}. The completed page is unchanged.")
            return
        self._queue_query(query, self.selected_identity)

    def _queue_query(self, query: PacketQuery, selection_page_identity: PacketIdentity | None) -> None:
        report = self.report
        if self._shutting_down or report is None or report.evidence is None:
            return
        self._restore_scroll = None
        self._invalidate_request()
        self._pending = _JobRequest(self._generation, self._index, self._base_index, self._scope_frames, report.evidence.sha256, report.packets, query, self.selected_identity, selection_page_identity)
        self.status_label.setText("Querying saved packet evidence… The previous completed page remains available.")
        self._set_controls(True)
        self._start_pending()

    def _start_pending(self) -> None:
        if self._thread is not None or self._pending is None or self._shutting_down:
            return
        request = self._pending
        self._pending = None
        self._active_request = request
        cancellation = Event()
        self._cancellation = cancellation
        thread = _PacketQueryWorker(request, cancellation, self)
        thread.setObjectName("packetQueryThread")
        thread.completed.connect(self._job_completed, Qt.ConnectionType.QueuedConnection)
        thread.finished.connect(self._thread_finished, Qt.ConnectionType.QueuedConnection)
        self._thread = thread
        self.busy_changed.emit(True)
        thread.start()

    @Slot(object)
    def _job_completed(self, value: object) -> None:
        if not isinstance(value, _JobOutcome) or type(value.generation) is not int or not isinstance(value.query, PacketQuery):
            self.status_label.setText("Packet worker returned an invalid result; the completed page is unchanged.")
            return
        if self._shutting_down or value.generation != self._generation:
            return
        active = self._active_request
        if active is not None and active.selected_identity != self.selected_identity:
            self._queue_query(active.query, self.selected_identity if active.selection_page_identity is not None else None)
            return
        if value.error is not None:
            self._last_worker_failure = value.error
            if isinstance(value.error, PacketQueryCancelled):
                self.status_label.setText(self.cancellation_notice())
            elif isinstance(value.error, PacketQueryValidationError):
                self.status_label.setText(f"Invalid packet filter: {value.error}. The previous completed page is unchanged.")
            else:
                self.status_label.setText(f"Unexpected packet query failure ({type(value.error).__name__}). The previous completed page is unchanged. Retry the query or review developer diagnostics.")
            return
        if not isinstance(value.page, PacketPage) or not isinstance(value.index, PacketIndex) or self.report is None or self.report.evidence is None or value.page.capture_sha256 != self.report.evidence.sha256 or value.index.capture_sha256 != value.page.capture_sha256 or not isinstance(value.base_index, PacketIndex) or value.base_index.capture_sha256 != value.page.capture_sha256:
            self.status_label.setText("Packet worker returned inconsistent capture evidence; the completed page is unchanged.")
            return
        self._index = value.index
        self._base_index = value.base_index
        self._last_worker_failure = None
        self.completed_page = value.page
        self._completed_query = value.query
        self._apply_page(value.page)
        self.page_changed.emit()

    @Slot()
    def _thread_finished(self) -> None:
        thread = self._thread
        self._thread = None
        self._active_request = None
        self._cancellation = None
        if thread is not None:
            thread.deleteLater()
        if self._shutting_down:
            self.busy_changed.emit(False)
            self.shutdown_complete.emit()
            return
        if self._pending is not None:
            self._start_pending()
        else:
            self._set_controls(False)
            self.busy_changed.emit(False)

    def _set_controls(self, busy: bool) -> None:
        available = self.report is not None and self.report.evidence is not None and not self._shutting_down
        self.apply_button.setEnabled(available)
        self.clear_button.setEnabled(available)
        self.cancel_button.setEnabled(busy and available)
        page = self.completed_page
        self.previous_button.setEnabled(not busy and available and page is not None and page.page_number > 1)
        self.next_button.setEnabled(not busy and available and page is not None and page.page_number < page.page_count)

    def _apply_page(self, page: PacketPage) -> None:
        self._applying_page = True
        try:
            self.model.set_packets(page.packets)
            if self.selected_identity is not None:
                for row, packet in enumerate(page.packets):
                    if packet.frame_number == self.selected_identity.frame_number:
                        self.table.selectRow(row)
                        break
        finally:
            self._applying_page = False
        self.status_label.setText(f"{page.matching_count} matching / {page.total_count} total packets · Page {page.page_number if page.page_count else 0} of {page.page_count} · {len(page.packets)} displayed · Ordered by exact timestamp, then frame identity")
        self._refresh_inspector()
        if self._restore_scroll is not None:
            self.table.verticalScrollBar().setValue(self._restore_scroll)
            self._restore_scroll = None

    @Slot()
    def _selection_changed(self) -> None:
        if self._applying_page:
            return
        rows = self.table.selectionModel().selectedRows()
        if len(rows) != 1 or self.report is None or self.report.evidence is None:
            return
        row = rows[0].row()
        if not 0 <= row < len(self.model.packets):
            return
        self.selected_identity = PacketIdentity(self.report.evidence.sha256, self.model.packets[row].frame_number)
        self._refresh_inspector()

    def _refresh_inspector(self) -> None:
        if self.selected_identity is None or self._index is None or self.report is None:
            self.selection_notice.setText("Select a packet row to inspect its recorded evidence.")
            self.inspector.setPlainText("No selected packet.")
            return
        packet = packet_for_identity(self._index, self.selected_identity)
        if packet is None:
            self.selection_notice.setText("The selected packet is unavailable in the current capture.")
            self.inspector.setPlainText("Packet evidence unavailable.")
            return
        page = self.completed_page
        visible = page is not None and any(item.frame_number == packet.frame_number for item in page.packets)
        if visible:
            notice = f"Selected frame {packet.frame_number} from the current visible page."
        elif page is not None and page.selected_match_page is None:
            notice = f"Selected frame {packet.frame_number} is outside the current filter. Its original saved evidence remains below."
        else:
            notice = f"Selected frame {packet.frame_number} is outside the visible page. Its original saved evidence remains below."
        text = packet_inspector_text(self.report, packet)
        if text.startswith(INSPECTOR_LIMIT_NOTICE):
            notice += " Full inspector rendering exceeds 512 KiB; complete evidence remains in the report."
        self.selection_notice.setText(notice)
        self.inspector.setPlainText(text)
        self.packet_selected.emit(self.selected_identity)

    def set_correlation_context(self, message: str) -> None:
        if len(message.encode("utf-8")) > 4096 or any(ord(character) < 32 for character in message):
            raise PacketQueryValidationError("Session correlation context must be bounded plain text.")
        self.correlation_label.setText(message)
        if self.selected_identity is not None and self._index is not None and self.report is not None:
            packet = packet_for_identity(self._index, self.selected_identity)
            if packet is not None:
                text = packet_inspector_text(self.report, packet)
                combined = text + "\n\nSession correlation\n" + message
                if not text.startswith(INSPECTOR_LIMIT_NOTICE) and len(combined.encode("utf-8")) <= INSPECTOR_MAX_BYTES:
                    self.inspector.setPlainText(combined)

    def capture_navigation(self) -> PacketNavigation | None:
        report = self.report
        if report is None or report.evidence is None:
            return None
        return PacketNavigation(report.evidence.sha256, self._report_generation,
            self._completed_query, self.selected_identity, self._scope_frames,
            self.scope_label.text(), self.table.verticalScrollBar().value())

    def restore_navigation(self, navigation: PacketNavigation) -> bool:
        report = self.report
        if self._shutting_down or not isinstance(navigation, PacketNavigation) or report is None or report.evidence is None or navigation.capture_sha256 != report.evidence.sha256 or type(navigation.report_generation) is not int or navigation.report_generation != self._report_generation:
            return False
        try:
            if navigation.query is not None:
                validate_packet_query(navigation.query)
            if navigation.scope_frames is not None:
                validate_scope_frames(navigation.scope_frames, report.evidence.packet_record_count)
            validate_scope_label(navigation.scope_label)
        except PacketQueryValidationError:
            return False
        if type(navigation.vertical_scroll_value) is not int or not 0 <= navigation.vertical_scroll_value <= 2**31 - 1:
            return False
        identity = navigation.selected_identity
        if identity is not None and (not isinstance(identity, PacketIdentity) or identity.capture_sha256 != navigation.capture_sha256 or type(identity.frame_number) is not int or not 1 <= identity.frame_number <= report.evidence.packet_record_count or navigation.scope_frames is not None and identity.frame_number not in navigation.scope_frames):
            return False
        self._invalidate_request()
        self._pending = None
        self._scope_frames = navigation.scope_frames
        self._index = None
        self._show_unavailable("Restoring the previous completed packet view…")
        self.scope_label.setText(navigation.scope_label)
        self.selected_identity = navigation.selected_identity
        query = navigation.query
        if query is None:
            self._set_query_controls(PacketQuery("", "", None, "", "", "all", "", "all", "all", 1, 100))
            self._schedule_query(1)
        else:
            self._set_query_controls(query)
            self._queue_query(query, None)
        self._restore_scroll = navigation.vertical_scroll_value
        return True

    def _set_query_controls(self, query: PacketQuery) -> None:
        self.search_field.setText(query.search)
        self.endpoint_field.setText(query.endpoint)
        self.port_field.setText(str(query.port) if query.port is not None else "")
        self.protocol_field.setText(query.protocol)
        self.process_field.setText(query.process_text)
        self.interface_field.setText(query.interface_text)
        for control, value in ((self.process_state, query.process_state), (self.interface_state, query.interface_state), (self.direction_field, query.direction), (self.page_size, query.page_size)):
            control.blockSignals(True)
            control.setCurrentIndex(control.findData(value))
            control.blockSignals(False)

    def set_packet_scope(self, capture_sha256: str, frame_numbers: tuple[int, ...], label: str) -> None:
        report = self.report
        if report is None or report.evidence is None or capture_sha256 != report.evidence.sha256:
            raise PacketQueryValidationError("Packet navigation belongs to a different capture artifact.")
        validate_scope_frames(frame_numbers, report.evidence.packet_record_count)
        validate_scope_label(label)
        self._invalidate_request()
        self._pending = None
        self._restore_scroll = None
        self._scope_frames = frame_numbers
        self._index = None
        selected = self.selected_identity
        self._show_unavailable("Loading packets in the selected scope…")
        self.selected_identity = selected
        if self.selected_identity is not None and self.selected_identity.frame_number not in frame_numbers:
            self.selected_identity = None
            self.inspector.setPlainText("Select a member packet to inspect its original evidence.")
            self.packet_selected.emit(None)
        self.scope_label.setText(label)
        self.clear_filters()

    def select_packet(self, identity: PacketIdentity) -> bool:
        report = self.report
        if self._shutting_down or not isinstance(identity, PacketIdentity) or report is None or report.evidence is None or identity.capture_sha256 != report.evidence.sha256 or type(identity.frame_number) is not int or not 1 <= identity.frame_number <= report.evidence.packet_record_count:
            return False
        if self._scope_frames is not None and identity.frame_number not in self._scope_frames:
            return False
        self.selected_identity = identity
        self._schedule_query(1)
        return True

    @Slot()
    def cancel_query(self) -> None:
        self._invalidate_request()
        self._pending = None
        self._restore_scroll = None
        self.status_label.setText(self.cancellation_notice())
        self.cancel_button.setEnabled(False)

    def cancellation_notice(self) -> str:
        if self.completed_page is None:
            return "Packet query cancelled. No completed page is available for the current scope. Apply filters to load it."
        return "Packet query cancelled. The previous completed page and selection are unchanged."

    def shutdown(self) -> bool:
        """Request owned worker shutdown; false requires awaiting shutdown_complete."""
        self._shutting_down = True
        self._pending = None
        self._invalidate_request()
        self._set_controls(False)
        return self._thread is None
