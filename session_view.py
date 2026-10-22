"""Qt navigation over scoped TCP/UDP observations from immutable saved evidence.

One owned thread builds the session index or queries a bounded page. Selection
and navigation use capture-bound scope identities; these groupings do not prove
a connection lifetime, an owning process, or a device-wide communication history.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from threading import Event
from time import monotonic
from typing import Callable, Iterator

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QSplitter, QTableView, QVBoxLayout, QWidget,
)

from gui_models import AnalysisReport
from packet_models import ProcessMetadata
from packet_sessions import (
    EMPTY_SESSION_QUERY, SessionIdentity, SessionIndex, SessionPage, SessionQuery,
    SessionCancelled, SessionValidationError, SessionRecord,
    session_index_steps, query_sessions, session_for_identity, validate_session_query,
)
from packet_timeline import PacketQueryCancelled, PacketQueryValidationError, build_packet_index
from dns_sessions import DnsSessionIndex, DnsSessionCancelled, DnsSessionValidationError, build_dns_session_index, dns_association_count_for_session
from packet_view import (
    INSPECTOR_MAX_BYTES, configure_evidence_inspector, configure_evidence_table,
    endpoint_label, evidence_tooltip_text, metadata_cell, process_label,
)

COLUMNS = (
    "Transport", "Stream", "Endpoint A", "Endpoint B", "Process", "Effective process",
    "Interface", "Packets", "First exact epoch", "Last exact epoch", "Packet span", "Wire / captured bytes",
)
COLUMN_WIDTHS: tuple[int, ...] = (84, 72, 184, 184, 176, 176, 136, 80, 168, 168, 132, 154)


def session_span(session: SessionRecord) -> str:
    """Render the exact packet timestamp span without implying recording lifetime."""
    first = session.first_timestamp
    last = session.last_timestamp
    nanoseconds = (last.seconds - first.seconds) * 1_000_000_000 + last.nanoseconds - first.nanoseconds
    seconds, fraction = divmod(nanoseconds, 1_000_000_000)
    return f"{seconds}.{fraction:09d} s"


def session_cell(session: SessionRecord, column: int) -> str:
    """Compute one bounded visible cell from a scoped observed session."""
    scope = session.scope
    if column == 0:
        return scope.transport.upper()
    if column == 1:
        return str(scope.stream)
    if column == 2:
        return endpoint_label(scope.endpoint_a.address, scope.endpoint_a.port)
    if column == 3:
        return endpoint_label(scope.endpoint_b.address, scope.endpoint_b.port)
    if column == 4:
        return process_label(scope.process)
    if column == 5:
        return process_label(scope.effective_process)
    if column == 6:
        return metadata_cell(scope.interface.state, (label.name for label in scope.interface.labels), len(scope.interface.labels))
    if column == 7:
        return str(session.packet_count)
    if column == 8:
        return session.first_timestamp.epoch
    if column == 9:
        return session.last_timestamp.epoch
    if column == 10:
        return session_span(session)
    if column == 11:
        return f"{session.wire_bytes} / {session.captured_bytes if session.captured_bytes is not None else 'unavailable'}"
    raise IndexError("Session table column is outside the model schema.")


def _process_lines(name: str, metadata: ProcessMetadata) -> Iterator[str]:
    yield f"{name} state: {metadata.state}"
    for label in metadata.labels:
        yield f"  Source: {label.source}; PID: {label.pid if label.pid is not None else 'unknown'}; name: {label.name if label.name is not None else 'unknown'}"


def session_inspector_lines(session: SessionRecord) -> Iterator[str]:
    """Show the grouping contract and scope evidence without copying member records."""
    scope = session.scope
    yield from (
        "Scoped saved-file TCP/UDP observations",
        f"Capture SHA-256: {session.identity.capture_sha256}",
        f"Session scope SHA-256: {session.identity.scope_sha256}",
        f"Transport: {scope.transport.upper()}; recorded decoder stream: {scope.stream}",
        f"Endpoint A: {endpoint_label(scope.endpoint_a.address, scope.endpoint_a.port)}",
        f"Endpoint B: {endpoint_label(scope.endpoint_b.address, scope.endpoint_b.port)}",
        "Endpoint order is canonical. Both packet directions can belong to this scope.",
        f"Observed member packets: {session.packet_count}",
        f"First exact recorded epoch: {session.first_timestamp.epoch}",
        f"Last exact recorded epoch: {session.last_timestamp.epoch}",
        f"Exact packet timestamp span: {session_span(session)}",
        f"Total wire bytes: {session.wire_bytes}",
        f"Total captured bytes: {session.captured_bytes if session.captured_bytes is not None else 'unavailable'}",
        f"Packets with captured length recorded: {session.captured_length_known_count} / {session.packet_count}",
        f"Observed protocols: {', '.join(session.protocols)}", "", "Recorded metadata defining this scope",
    )
    yield from _process_lines("Process", scope.process)
    yield from _process_lines("Effective process", scope.effective_process)
    yield f"Interface state: {scope.interface.state}"
    for label in scope.interface.labels:
        yield f"  Source: {label.source}; name: {label.name}"
    yield from (
        "", "Interpretation limits",
        "Grouping uses this capture, transport, recorded stream, canonical endpoint pair, and exact recorded process/effective-process/interface scope.",
        "Unknown metadata stays unknown and forms a separate scope from recorded metadata.",
        "Recorded process labels do not establish the process owning a connection.",
        "A decoder stream and packet timestamp span do not prove connection lifetime, completeness, or a TCP handshake.",
        "No DNS attribution, PTR lookup, cross-capture correlation, or baseline update is performed.",
        "Use Show member packets to inspect every original frame in this scope.",
    )


def session_inspector_text(session: SessionRecord) -> str:
    """Render the full scope or explicitly refuse a scope larger than 512 KiB."""
    lines: list[str] = []
    size = 0
    for line in session_inspector_lines(session):
        size += len(line.encode("utf-8")) + 1
        if size > INSPECTOR_MAX_BYTES:
            return "\n".join((
                "Inspector rendering limit exceeded.",
                f"Capture SHA-256: {session.identity.capture_sha256}",
                f"Session scope SHA-256: {session.identity.scope_sha256}",
                "The full scope exceeds the 512 KiB rendering ceiling. No partial scope is presented.",
                "All original metadata remains in the saved report and member packet evidence.",
            ))
        lines.append(line)
    return "\n".join(lines)


class SessionPageModel(QAbstractTableModel):
    """Expose only the completed page of existing immutable session references."""

    def __init__(self, parent: QObject) -> None:
        super().__init__(parent)
        self.setObjectName("sessionPageModel")
        self.sessions: tuple[SessionRecord, ...] = ()

    def set_sessions(self, sessions: tuple[SessionRecord, ...]) -> None:
        self.beginResetModel()
        self.sessions = sessions
        self.endResetModel()

    def rowCount(self, parent: QModelIndex) -> int:
        return 0 if parent.isValid() else len(self.sessions)

    def columnCount(self, parent: QModelIndex) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int) -> str | None:
        if not index.isValid() or not 0 <= index.row() < len(self.sessions) or not 0 <= index.column() < len(COLUMNS):
            return None
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            value = session_cell(self.sessions[index.row()], index.column())
            return evidence_tooltip_text(value) if role == Qt.ItemDataRole.ToolTipRole else value
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int) -> str | None:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal and 0 <= section < len(COLUMNS):
            return COLUMNS[section]
        return None


@dataclass(frozen=True, slots=True)
class SessionNavigation:
    capture_sha256: str
    report_generation: int
    query: SessionQuery
    selected_identity: SessionIdentity | None
    vertical_scroll_value: int


@dataclass(frozen=True)
class _JobRequest:
    generation: int
    index: SessionIndex | None
    report: AnalysisReport
    sha256: str
    query: SessionQuery
    selected_identity: SessionIdentity | None
    selection_page_identity: SessionIdentity | None
    restore_scroll_value: int | None
    dns_index: DnsSessionIndex | None


@dataclass(frozen=True)
class _JobOutcome:
    generation: int
    index: SessionIndex | None
    page: SessionPage | None
    query: SessionQuery
    restore_scroll_value: int | None
    error: Exception | None
    dns_index: DnsSessionIndex | None


class _SessionQueryWorker(QThread):
    """Owned Qt thread connector that returns after pure indexing/query work."""

    completed = Signal(object)
    checkpoint_requested = Signal(object)

    def __init__(self, request: _JobRequest, cancellation: Event, parent: QObject) -> None:
        super().__init__(parent)
        self.request = request
        self.cancellation = cancellation
        self.continuation = Event()

    def _build_index(self) -> SessionIndex:
        """Let the GUI service native paint/accessibility between bounded batches."""
        packets = build_packet_index(self.request.sha256, self.request.report.packets, self.cancellation)
        for result in session_index_steps(packets, self.cancellation):
            if result is not None:
                return result
            self._main_loop_checkpoint()
        raise SessionValidationError("Session correlation ended without a complete index.")

    def _main_loop_checkpoint(self) -> None:
        """Await an owned GUI acknowledgement, with cancellation and a 5s deadline.

        Python's GIL is released while waiting. Merely yielding the worker can
        immediately reacquire it during native widget painting. A queued
        acknowledgement requires GUI event-loop progress before the next batch.
        """
        self.continuation.clear()
        deadline = monotonic() + 5.0
        self.checkpoint_requested.emit(self.continuation)
        while not self.continuation.wait(0.05):
            if self.cancellation.is_set():
                raise SessionCancelled("Session indexing was cancelled while awaiting the GUI.")
            if monotonic() >= deadline:
                raise SessionValidationError("The GUI did not acknowledge session indexing within five seconds. The previous completed page is unchanged.")
        if self.cancellation.is_set():
            raise SessionCancelled("Session indexing was cancelled while awaiting the GUI.")

    @Slot()
    def run(self) -> None:
        try:
            index = self.request.index
            if index is None:
                index = self._build_index()
            dns_index = self.request.dns_index
            if dns_index is None and self.request.report.dns_evidence is not None:
                dns_index = build_dns_session_index(index, self.request.report.dns_evidence, self.cancellation)
            query = self.request.query
            page = query_sessions(index, query, self.request.selected_identity, self.cancellation)
            if self.request.selection_page_identity is not None and page.selected_match_page is not None and page.selected_match_page != page.page_number:
                query = replace(query, page_number=page.selected_match_page)
                page = query_sessions(index, query, self.request.selected_identity, self.cancellation)
            outcome = _JobOutcome(self.request.generation, index, page, query, self.request.restore_scroll_value, None, dns_index)
        except (SessionCancelled, SessionValidationError, PacketQueryCancelled, PacketQueryValidationError, DnsSessionCancelled, DnsSessionValidationError) as error:
            outcome = _JobOutcome(self.request.generation, None, None, self.request.query, None, error, None)
        except Exception as error:
            # Preserve the cause from the external thread boundary, then end the owned thread.
            outcome = _JobOutcome(self.request.generation, None, None, self.request.query, None, error, None)
        self.completed.emit(outcome)


class SessionTimelineWidget(QWidget):
    """Bounded scoped-session pages with capture-bound selection and return context."""

    session_open_requested = Signal(object)
    ungrouped_open_requested = Signal(str, object)
    packet_return_requested = Signal()
    dns_evidence_requested = Signal(object)
    dns_return_requested = Signal()
    index_ready = Signal()
    page_changed = Signal()
    busy_changed = Signal(bool)
    shutdown_complete = Signal()

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setObjectName("sessionTimeline")
        self.report: AnalysisReport | None = None
        self.completed_page: SessionPage | None = None
        self.selected_identity: SessionIdentity | None = None
        self._index: SessionIndex | None = None
        self._dns_index: DnsSessionIndex | None = None
        self._completed_query: SessionQuery | None = None
        self._generation = 0
        self._report_generation = 0
        self._pending: _JobRequest | None = None
        self._active_request: _JobRequest | None = None
        self._thread: _SessionQueryWorker | None = None
        self._cancellation: Event | None = None
        self._shutting_down = False
        self._applying_page = False
        self._last_worker_failure: Exception | None = None
        self._create_controls()
        self._show_unavailable("Analyze a saved capture to load scoped TCP/UDP observations.")

    def _create_controls(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        explanation = QLabel("Sessions group saved TCP/UDP observations by capture, decoder stream, endpoint pair and recorded metadata scope. They do not prove a connection lifetime or owning process.", self)
        explanation.setObjectName("sessionScopeExplanation")
        explanation.setTextFormat(Qt.TextFormat.PlainText)
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        filters = QGridLayout()
        filters.setSpacing(4)
        self.search_field = self._text_control("sessionSearch", "Literal text across recorded scope metadata")
        self.endpoint_field = self._text_control("sessionEndpointFilter", "Exact endpoint IPv4 or IPv6 address")
        self.port_field = self._text_control("sessionPortFilter", "Either endpoint port")
        self.transport_field = self._state_control("sessionTransportFilter", ("all", "tcp", "udp"))
        self.process_field = self._text_control("sessionProcessFilter", "Recorded or effective process name, PID or source")
        self.process_state = self._state_control("sessionProcessStateFilter", ("all", "recorded", "unknown"))
        self.effective_process_state = self._state_control("sessionEffectiveProcessStateFilter", ("all", "recorded", "unknown"))
        self.interface_field = self._text_control("sessionInterfaceFilter", "Recorded interface text")
        self.interface_state = self._state_control("sessionInterfaceStateFilter", ("all", "recorded", "unknown"))
        controls = (("Search", self.search_field), ("Endpoint", self.endpoint_field), ("Port", self.port_field), ("Transport", self.transport_field), ("Process / effective", self.process_field), ("Process state", self.process_state), ("Effective process state", self.effective_process_state), ("Interface", self.interface_field), ("Interface state", self.interface_state))
        for position, (name, control) in enumerate(controls):
            row, group = divmod(position, 3)
            label = QLabel(name, self)
            label.setBuddy(control)
            filters.addWidget(label, row, group * 2)
            filters.addWidget(control, row, group * 2 + 1)
        layout.addLayout(filters)
        actions = QHBoxLayout()
        self.apply_button = self._button("sessionApplyFilters", "Apply filters", self.apply_filters)
        self.clear_button = self._button("sessionClearFilters", "Clear filters", self.clear_filters)
        self.cancel_button = self._button("sessionCancelQuery", "Cancel query", self.cancel_query)
        self.page_size = QComboBox(self)
        self.page_size.setObjectName("sessionPageSize")
        for size in (100, 250, 500):
            self.page_size.addItem(str(size), size)
        for button in (self.apply_button, self.clear_button, self.cancel_button):
            actions.addWidget(button)
        actions.addStretch()
        actions.addWidget(QLabel("Rows per page", self))
        actions.addWidget(self.page_size)
        layout.addLayout(actions)
        self.status_label = QLabel(self)
        self.status_label.setObjectName("sessionPageStatus")
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        ungrouped = QHBoxLayout()
        self.ungrouped_label = QLabel(self)
        self.ungrouped_label.setObjectName("sessionUngroupedStatus")
        self.ungrouped_label.setTextFormat(Qt.TextFormat.PlainText)
        self.ungrouped_label.setWordWrap(True)
        self.ungrouped_button = self._button("sessionOpenUngroupedPackets", "Show ungrouped packets", self.open_ungrouped_packets)
        ungrouped.addWidget(self.ungrouped_label, 1)
        ungrouped.addWidget(self.ungrouped_button)
        layout.addLayout(ungrouped)
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.setObjectName("sessionTimelineSplitter")
        splitter.setChildrenCollapsible(False)
        self.table = QTableView(splitter)
        self.table.setObjectName("sessionTable")
        self.model = SessionPageModel(self.table)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.setWordWrap(False)
        configure_evidence_table(self.table, COLUMN_WIDTHS)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        inspector_panel = QWidget(splitter)
        inspector_panel.setObjectName("sessionInspectorPanel")
        inspector_layout = QVBoxLayout(inspector_panel)
        inspector_layout.setContentsMargins(6, 6, 6, 6)
        inspector_layout.setSpacing(4)
        self.selection_notice = QLabel(inspector_panel)
        self.selection_notice.setObjectName("sessionSelectionNotice")
        self.selection_notice.setTextFormat(Qt.TextFormat.PlainText)
        self.selection_notice.setWordWrap(True)
        self.inspector = QPlainTextEdit(inspector_panel)
        self.inspector.setObjectName("sessionInspector")
        configure_evidence_inspector(self.inspector)
        self.open_button = self._button("sessionOpenPackets", "Show member packets", self.open_member_packets)
        self.dns_button = self._button("sessionShowDnsEvidence", "Show passive DNS evidence", self.open_dns_evidence)
        inspector_layout.addWidget(self.selection_notice)
        inspector_layout.addWidget(self.inspector, 1)
        context_actions = QGridLayout()
        context_actions.setContentsMargins(0, 0, 0, 0)
        context_actions.setSpacing(4)
        context_actions.addWidget(self.open_button, 0, 0)
        context_actions.addWidget(self.dns_button, 0, 1)
        inspector_layout.addLayout(context_actions)
        splitter.addWidget(self.table)
        splitter.addWidget(inspector_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        navigation = QHBoxLayout()
        self.previous_button = self._button("sessionPreviousPage", "Previous page", self.previous_page)
        self.next_button = self._button("sessionNextPage", "Next page", self.next_page)
        navigation.addWidget(self.previous_button)
        navigation.addWidget(self.next_button)
        navigation.addStretch()
        self.return_packets_button = self._button("sessionReturnToPackets", "Return to previous packet view", self.return_to_packets)
        self.return_packets_button.setEnabled(False)
        navigation.addWidget(self.return_packets_button)
        self.return_dns_button = self._button("sessionReturnToDnsEvidence", "Return to DNS evidence", self.return_to_dns)
        self.return_dns_button.setEnabled(False)
        navigation.addWidget(self.return_dns_button)
        layout.addLayout(navigation)
        self.page_size.currentIndexChanged.connect(self.apply_filters)
        for control in (self.search_field, self.endpoint_field, self.port_field, self.process_field, self.interface_field):
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

    @property
    def is_busy(self) -> bool:
        return self._thread is not None or self._pending is not None

    @property
    def page(self) -> SessionPage | None:
        return self.completed_page

    @property
    def session_index(self) -> SessionIndex | None:
        return self._index

    @property
    def dns_index(self) -> DnsSessionIndex | None:
        return self._dns_index

    def _show_unavailable(self, message: str) -> None:
        self.completed_page = None
        self._completed_query = None
        self.model.set_sessions(())
        self.selected_identity = None
        self.inspector.setPlainText(message)
        self.selection_notice.setText("No selected session.")
        self.status_label.setText(message)
        self.ungrouped_label.setText("Ungrouped evidence unavailable.")
        self.return_packets_button.setEnabled(False)
        self.return_dns_button.setEnabled(False)
        self._set_controls(False)

    def set_report(self, report: AnalysisReport) -> None:
        """Replace the artifact and invalidate all selections and return snapshots."""
        if self._shutting_down:
            return
        self.report = report
        self._report_generation += 1
        self._invalidate_request()
        self._pending = None
        self._index = None
        self._dns_index = None
        if report.evidence is None:
            self._show_unavailable("Session evidence unavailable in this legacy report. Aggregate findings remain available.")
            return
        self._show_unavailable("Loading scoped observations for the current capture…")
        self._schedule_query(1)

    def clear_report(self) -> None:
        self.report = None
        self._report_generation += 1
        self._pending = None
        self._index = None
        self._dns_index = None
        self._invalidate_request()
        self._show_unavailable("Analyze a saved capture to load scoped TCP/UDP observations.")

    def capture_navigation(self) -> SessionNavigation | None:
        """Capture the last completed view, including identity and viewport position."""
        if self._index is None or self.completed_page is None or self._completed_query is None:
            return None
        return SessionNavigation(self._index.capture_sha256, self._report_generation, self._completed_query, self.selected_identity, self.table.verticalScrollBar().value())

    def restore_navigation(self, snapshot: SessionNavigation) -> bool:
        """Restore only a snapshot from this exact loaded report generation."""
        report = self.report
        if self._shutting_down or not isinstance(snapshot, SessionNavigation) or report is None or report.evidence is None or snapshot.capture_sha256 != report.evidence.sha256 or type(snapshot.report_generation) is not int or snapshot.report_generation != self._report_generation:
            return False
        if not isinstance(snapshot.query, SessionQuery) or type(snapshot.vertical_scroll_value) is not int or not 0 <= snapshot.vertical_scroll_value <= 2**31 - 1:
            return False
        try:
            validate_session_query(snapshot.query)
            if any(control.findData(value) < 0 for control, value in ((self.transport_field, snapshot.query.transport), (self.process_state, snapshot.query.process_state), (self.effective_process_state, snapshot.query.effective_process_state), (self.interface_state, snapshot.query.interface_state), (self.page_size, snapshot.query.page_size))):
                return False
            if snapshot.selected_identity is not None and (not isinstance(snapshot.selected_identity, SessionIdentity) or snapshot.selected_identity.capture_sha256 != snapshot.capture_sha256 or self._index is None or session_for_identity(self._index, snapshot.selected_identity) is None):
                return False
        except SessionValidationError:
            return False
        self.selected_identity = snapshot.selected_identity
        self._apply_query_controls(snapshot.query)
        self._queue_query(snapshot.query, None, snapshot.vertical_scroll_value)
        return True

    def select_session(self, identity: SessionIdentity) -> bool:
        """Reveal an existing owning scope with explicit filter-reset navigation."""
        try:
            if self._shutting_down or self._index is None or not isinstance(identity, SessionIdentity) or session_for_identity(self._index, identity) is None:
                return False
        except SessionValidationError:
            return False
        size = self.page_size.currentData()
        if type(size) is not int or size not in (100, 250, 500):
            return False
        self.selected_identity = identity
        query = replace(EMPTY_SESSION_QUERY, page_size=size)
        self._apply_query_controls(query)
        self._refresh_inspector()
        self._queue_query(query, identity, None)
        return True

    def _apply_query_controls(self, query: SessionQuery) -> None:
        self.search_field.setText(query.search)
        self.endpoint_field.setText(query.endpoint)
        self.port_field.setText(str(query.port) if query.port is not None else "")
        self.process_field.setText(query.process_text)
        self.interface_field.setText(query.interface_text)
        for control, value in ((self.transport_field, query.transport), (self.process_state, query.process_state), (self.effective_process_state, query.effective_process_state), (self.interface_state, query.interface_state), (self.page_size, query.page_size)):
            control.blockSignals(True)
            control.setCurrentIndex(control.findData(value))
            control.blockSignals(False)

    def _invalidate_request(self) -> None:
        self._generation += 1
        if self._cancellation is not None:
            self._cancellation.set()

    def _query(self, page_number: int) -> SessionQuery:
        port_text = self.port_field.text().strip()
        if port_text and (not port_text.isascii() or not port_text.isdecimal()):
            raise SessionValidationError("Port must be a decimal integer between 0 and 65535.")
        port = int(port_text) if port_text else None
        if port is not None and not 0 <= port <= 65535:
            raise SessionValidationError("Port must be a decimal integer between 0 and 65535.")
        size = self.page_size.currentData()
        transport = self.transport_field.currentData()
        process_state = self.process_state.currentData()
        effective_state = self.effective_process_state.currentData()
        interface_state = self.interface_state.currentData()
        if type(size) is not int or size not in (100, 250, 500):
            raise SessionValidationError("Page size must be 100, 250 or 500.")
        if transport not in ("all", "tcp", "udp") or process_state not in ("all", "recorded", "unknown") or effective_state not in ("all", "recorded", "unknown") or interface_state not in ("all", "recorded", "unknown"):
            raise SessionValidationError("Session scope filters contain an invalid state.")
        return SessionQuery(self.search_field.text(), self.endpoint_field.text(), port, transport, self.process_field.text(), process_state, effective_state, self.interface_field.text(), interface_state, page_number, size)

    @Slot()
    def apply_filters(self) -> None:
        self._schedule_query(1)

    @Slot()
    def clear_filters(self) -> None:
        query = replace(EMPTY_SESSION_QUERY, page_size=self.page_size.currentData())
        self._apply_query_controls(query)
        self._schedule_query(1)

    @Slot()
    def previous_page(self) -> None:
        if self.completed_page is not None and self._completed_query is not None:
            self._queue_query(replace(self._completed_query, page_number=max(1, self.completed_page.page_number - 1)), None, None)

    @Slot()
    def next_page(self) -> None:
        if self.completed_page is not None and self._completed_query is not None:
            self._queue_query(replace(self._completed_query, page_number=self.completed_page.page_number + 1), None, None)

    def _schedule_query(self, page_number: int) -> None:
        if self._shutting_down or self.report is None or self.report.evidence is None:
            return
        try:
            query = self._query(page_number)
        except SessionValidationError as error:
            self._invalidate_request()
            self._pending = None
            self.status_label.setText(f"Invalid session filter: {error}. The completed page is unchanged.")
            return
        self._queue_query(query, self.selected_identity, None)

    def _queue_query(self, query: SessionQuery, selection_page_identity: SessionIdentity | None, restore_scroll_value: int | None) -> None:
        report = self.report
        if self._shutting_down or report is None or report.evidence is None:
            return
        self._invalidate_request()
        self._pending = _JobRequest(self._generation, self._index, report, report.evidence.sha256, query, self.selected_identity, selection_page_identity, restore_scroll_value, self._dns_index)
        self.status_label.setText("Querying saved scoped observations… The previous completed page remains available.")
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
        thread = _SessionQueryWorker(request, cancellation, self)
        thread.setObjectName("sessionQueryThread")
        thread.completed.connect(self._job_completed, Qt.ConnectionType.QueuedConnection)
        thread.checkpoint_requested.connect(self._acknowledge_checkpoint, Qt.ConnectionType.QueuedConnection)
        thread.finished.connect(self._thread_finished, Qt.ConnectionType.QueuedConnection)
        self._thread = thread
        self.busy_changed.emit(True)
        thread.start()

    @Slot(object)
    def _acknowledge_checkpoint(self, value: object) -> None:
        if not isinstance(value, Event):
            raise TypeError("Session indexing requires an owned checkpoint event.")
        value.set()

    @Slot(object)
    def _job_completed(self, value: object) -> None:
        if not isinstance(value, _JobOutcome) or type(value.generation) is not int or not isinstance(value.query, SessionQuery) or value.error is not None and not isinstance(value.error, Exception):
            self.status_label.setText("Session worker returned an invalid result; the completed page is unchanged.")
            return
        if self._shutting_down or value.generation != self._generation:
            return
        active = self._active_request
        if active is not None and active.selected_identity != self.selected_identity:
            self._queue_query(active.query, self.selected_identity if active.selection_page_identity is not None else None, active.restore_scroll_value)
            return
        if value.error is not None:
            self._last_worker_failure = value.error
            if isinstance(value.error, (SessionCancelled, PacketQueryCancelled, DnsSessionCancelled)):
                self.status_label.setText("Session query cancelled. The previous completed page and selection are unchanged.")
            elif isinstance(value.error, (SessionValidationError, PacketQueryValidationError, DnsSessionValidationError)):
                self.status_label.setText(f"Invalid session evidence or filter: {value.error}. The previous completed page is unchanged.")
            else:
                self.status_label.setText(f"Unexpected session query failure ({type(value.error).__name__}). The previous completed page is unchanged. Retry the query or review developer diagnostics.")
            return
        if not isinstance(value.page, SessionPage) or not isinstance(value.index, SessionIndex) or self.report is None or self.report.evidence is None or value.page.capture_sha256 != self.report.evidence.sha256 or value.index.capture_sha256 != value.page.capture_sha256:
            self.status_label.setText("Session worker returned inconsistent capture evidence; the completed page is unchanged.")
            return
        first_index = self._index is None
        if self.report.dns_evidence is not None and (not isinstance(value.dns_index, DnsSessionIndex) or value.dns_index.capture_sha256 != value.page.capture_sha256 or value.dns_index.session_index is not value.index) or self.report.dns_evidence is None and value.dns_index is not None:
            self.status_label.setText("Session worker returned inconsistent structured DNS evidence; the completed page is unchanged.")
            return
        self._index = value.index
        self._dns_index = value.dns_index
        self._last_worker_failure = None
        self.completed_page = value.page
        self._completed_query = value.query
        self._apply_page(value.page)
        if value.restore_scroll_value is not None:
            self.table.verticalScrollBar().setValue(value.restore_scroll_value)
        if first_index:
            self.index_ready.emit()
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
        self.open_button.setEnabled(available and self.selected_identity is not None and self._index is not None)
        self.dns_button.setEnabled(available and self.selected_identity is not None and self._dns_index is not None)
        self.ungrouped_button.setEnabled(available and self._index is not None and bool(self._index.ungrouped))

    def _apply_page(self, page: SessionPage) -> None:
        self._applying_page = True
        try:
            self.model.set_sessions(page.sessions)
            if self.selected_identity is not None:
                for row, session in enumerate(page.sessions):
                    if session.identity == self.selected_identity:
                        self.table.selectRow(row)
                        break
        finally:
            self._applying_page = False
        index = self._index
        packet_total = len(index.packet_index.packets) if index is not None else 0
        eligible = index.eligible_packet_count if index is not None else 0
        ungrouped_count = len(index.ungrouped) if index is not None else 0
        self.status_label.setText(f"{page.matching_count} matching / {page.total_count} total scoped sessions · {eligible} eligible / {packet_total} total packets · {ungrouped_count} ungrouped · Page {page.page_number if page.page_count else 0} of {page.page_count} · {len(page.sessions)} displayed")
        reasons = "; ".join(f"{item.reason}: {item.packet_count}" for item in index.reason_counts) if index is not None else "unavailable"
        self.ungrouped_label.setText(f"Ungrouped packets: {ungrouped_count}. Reasons (a packet can have multiple): {reasons or '(none)'}. Original packets remain available.")
        self._refresh_inspector()

    @Slot()
    def _selection_changed(self) -> None:
        if self._applying_page:
            return
        rows = self.table.selectionModel().selectedRows()
        if len(rows) != 1:
            return
        row = rows[0].row()
        if not 0 <= row < len(self.model.sessions):
            return
        self.selected_identity = self.model.sessions[row].identity
        self._refresh_inspector()

    def _refresh_inspector(self) -> None:
        if self.selected_identity is None or self._index is None:
            self.selection_notice.setText("Select a session row to inspect its recorded scope.")
            self.inspector.setPlainText("No selected session.")
            self.open_button.setEnabled(False)
            self.dns_button.setEnabled(False)
            return
        session = session_for_identity(self._index, self.selected_identity)
        if session is None:
            self.selection_notice.setText("The selected session is unavailable in the current capture.")
            self.inspector.setPlainText("Session evidence unavailable.")
            self.open_button.setEnabled(False)
            self.dns_button.setEnabled(False)
            return
        page = self.completed_page
        visible = page is not None and any(item.identity == session.identity for item in page.sessions)
        if visible:
            notice = "Selected session from the current visible page."
        elif page is not None and page.selected_match_page is None:
            notice = "Selected session is outside the current filter. Its original scope remains below."
        else:
            notice = "Selected session is outside the visible page. Its original scope remains below."
        self.selection_notice.setText(notice)
        text = session_inspector_text(session)
        dns_text = "\n\nStructured passive DNS evidence unavailable in this report. Reanalyze the original saved capture to enable candidate correlation."
        if self._dns_index is not None:
            count = dns_association_count_for_session(self._dns_index, session.identity)
            dns_text = f"\n\nPassive DNS candidates: {count}. Only explicitly referenced member frames inside each answer TTL window match. These observations do not establish application name use, process ownership or DNS authenticity."
        if not text.startswith("Inspector rendering limit exceeded.") and len((text + dns_text).encode("utf-8")) <= INSPECTOR_MAX_BYTES:
            text += dns_text
        self.inspector.setPlainText(text)
        self.open_button.setEnabled(not self._shutting_down)
        self.dns_button.setEnabled(not self._shutting_down and self._dns_index is not None)

    @Slot()
    def open_member_packets(self) -> None:
        if not self._shutting_down and self._index is not None and self.selected_identity is not None and session_for_identity(self._index, self.selected_identity) is not None:
            self.session_open_requested.emit(self.selected_identity)

    @Slot()
    def open_ungrouped_packets(self) -> None:
        if not self._shutting_down and self._index is not None and self._index.ungrouped:
            self.ungrouped_open_requested.emit(self._index.capture_sha256, tuple(packet.frame_number for packet in self._index.ungrouped))

    @Slot()
    def open_dns_evidence(self) -> None:
        if not self._shutting_down and self._dns_index is not None and self.selected_identity is not None:
            self.dns_evidence_requested.emit(self.selected_identity)

    @Slot()
    def return_to_packets(self) -> None:
        if not self._shutting_down and self.return_packets_button.isEnabled():
            self.packet_return_requested.emit()

    @Slot()
    def return_to_dns(self) -> None:
        if not self._shutting_down and self.return_dns_button.isEnabled():
            self.dns_return_requested.emit()

    @Slot()
    def cancel_query(self) -> None:
        self._invalidate_request()
        self._pending = None
        self.status_label.setText("Session query cancelled. The previous completed page and selection are unchanged.")
        self.cancel_button.setEnabled(False)

    def shutdown(self) -> bool:
        """Cancel owned work; a false return requires awaiting shutdown_complete."""
        self._shutting_down = True
        self._pending = None
        self._invalidate_request()
        self._set_controls(False)
        self.return_packets_button.setEnabled(False)
        self.return_dns_button.setEnabled(False)
        return self._thread is None
