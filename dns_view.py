"""Qt pages and navigation over passive, capture-bound DNS candidate evidence.

The widget only queries an already completed immutable correlation index. It
performs no resolver lookup, decoder invocation, capture or evidence-file write.
An owned thread runs one query at a time, retaining only the latest pending
request. Replacing the index invalidates every selection and return snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from threading import Event
from typing import Callable, Iterator

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
    QPushButton, QSplitter, QTableView, QVBoxLayout, QWidget,
)

from captured_dns import CapturedDnsMessage
from dns_sessions import (
    DnsAssociationIdentity, DnsAssociationPage, DnsQuery, DnsSessionAssociation,
    DnsSessionCancelled, DnsSessionIndex, DnsSessionValidationError,
    dns_association_for_identity, dns_messages_for_frame, observed_dns_frames, query_dns_associations,
    validate_dns_query,
)
from packet_models import ProcessMetadata
from packet_sessions import SessionIdentity, SessionValidationError, session_for_identity
from packet_timeline import PacketIdentity, packet_for_identity
from packet_view import INSPECTOR_MAX_BYTES, endpoint_label, dns_message_lines, evidence_tooltip_text

COLUMNS = (
    "Question name", "Answer address", "Query frame", "Response frame", "Message index",
    "TTL seconds", "Response exact epoch", "Effective expiry exact epoch", "Matched packets",
    "Process relation",
)


def dns_association_cell(association: DnsSessionAssociation, column: int) -> str:
    """Render a single bounded table cell without interpreting a DNS candidate."""
    values = (
        association.question_name, association.answer_address, str(association.query_frame),
        str(association.response_frame), str(association.message_index), str(association.ttl_seconds),
        association.response_timestamp.epoch, association.expires_at_epoch,
        str(len(association.matching_frames)), association.process_relation,
    )
    if not 0 <= column < len(values):
        raise IndexError("DNS evidence column is outside the model schema.")
    value = values[column]
    if len(value.encode("utf-8")) > 8 * 1024:
        return "Recorded value exceeds the 8 KiB cell limit; inspect original evidence."
    return value


def dns_inspector_lines(index: DnsSessionIndex, association: DnsSessionAssociation) -> Iterator[str]:
    """Describe the candidate and all frame/record references used to derive it."""
    yield from (
        "Passive DNS-to-session candidate evidence",
        f"Capture SHA-256: {association.identity.capture_sha256}",
        f"Association SHA-256: {association.identity.association_sha256}",
        f"Session scope SHA-256: {association.session_identity.scope_sha256}",
        f"Canonical question name: {association.question_name}",
        f"Recorded answer address: {association.answer_address}",
        f"Query frame: {association.query_frame}",
        f"Response frame: {association.response_frame}",
        f"Response DNS message index: {association.message_index}",
        f"Answer record ordinals: {', '.join(str(ordinal) for ordinal in association.record_ordinals)}",
        f"Effective answer/CNAME TTL: {association.ttl_seconds} seconds",
        f"Exact response epoch: {association.response_timestamp.epoch}",
        f"Original TTL expiry epoch: {association.ttl_expires_at_epoch}",
        f"Effective expiry epoch: {association.expires_at_epoch}",
        f"Superseding decoder frame: {association.superseded_by_frame if association.superseded_by_frame is not None else '(none observed)'}",
        f"Superseding DNS message index: {association.superseded_by_message_index if association.superseded_by_message_index is not None else '(none observed)'}",
        f"Matching session frames: {len(association.matching_frames)}",
    )
    for frame in association.matching_frames:
        yield f"  Frame {frame}"
    yield ""
    yield "Structured decoder message evidence"
    response = next((message for message in dns_messages_for_frame(index, PacketIdentity(index.capture_sha256, association.response_frame)) if message.message_index == association.message_index), None)
    if response is None:
        raise DnsSessionValidationError("The selected DNS candidate references an unavailable response message.")
    queries = tuple(message for message in dns_messages_for_frame(index, PacketIdentity(index.capture_sha256, association.query_frame)) if not message.is_response and message.opcode == 0 and not message.is_truncated and message.response_code == 0 and message.protocol == response.protocol and message.transaction_id == response.transaction_id and message.questions == response.questions)
    if len(queries) != 1:
        raise DnsSessionValidationError("The selected DNS candidate references an unavailable or ambiguous query message.")
    yield from dns_message_lines(queries[0])
    yield from dns_message_lines(response)
    for ordinal in association.record_ordinals:
        yield f"  Candidate answer source ordinal: {ordinal} (one-based answer record)"
    if association.superseded_by_frame is not None:
        replacement = next((message for message in dns_messages_for_frame(index, PacketIdentity(index.capture_sha256, association.superseded_by_frame)) if message.message_index == association.superseded_by_message_index), None)
        if replacement is None:
            raise DnsSessionValidationError("The selected DNS candidate references an unavailable superseding response message.")
        yield "Superseding structured response evidence"
        yield from dns_message_lines(replacement)
    query_packet = packet_for_identity(index.session_index.packet_index, PacketIdentity(index.capture_sha256, association.query_frame))
    if query_packet is not None:
        yield from (
            "", "Recorded DNS query client context",
            f"Client endpoint: {endpoint_label(query_packet.source_address, query_packet.source_port)}",
            f"Resolver endpoint: {endpoint_label(query_packet.destination_address, query_packet.destination_port)}",
        )
        yield from dns_process_lines("Query process", query_packet.process)
        yield from dns_process_lines("Query effective process", query_packet.effective_process)
        yield f"Query interface state: {query_packet.interface.state}"
        for label in query_packet.interface.labels:
            yield f"  Interface source: {label.source}; name: {label.name}"
    response_packet = packet_for_identity(index.session_index.packet_index, PacketIdentity(index.capture_sha256, association.response_frame))
    if response_packet is not None:
        yield from (
            "", "Recorded DNS response context used for process comparison",
            f"Resolver endpoint: {endpoint_label(response_packet.source_address, response_packet.source_port)}",
            f"Client endpoint: {endpoint_label(response_packet.destination_address, response_packet.destination_port)}",
        )
        yield from dns_process_lines("Response process", response_packet.process)
        yield from dns_process_lines("Response effective process", response_packet.effective_process)
        yield f"Response interface state: {response_packet.interface.state}"
        for label in response_packet.interface.labels:
            yield f"  Interface source: {label.source}; name: {label.name}"
    session = session_for_identity(index.session_index, association.session_identity)
    if session is not None:
        yield from (
            "", "Correlated session scope",
            f"Transport: {session.scope.transport.upper()}; recorded stream: {session.scope.stream}",
            f"Endpoint A: {endpoint_label(session.scope.endpoint_a.address, session.scope.endpoint_a.port)}",
            f"Endpoint B: {endpoint_label(session.scope.endpoint_b.address, session.scope.endpoint_b.port)}",
        )
        yield from dns_process_lines("Session process", session.scope.process)
        yield from dns_process_lines("Session effective process", session.scope.effective_process)
        yield f"Session interface state: {session.scope.interface.state}"
        for label in session.scope.interface.labels:
            yield f"  Interface source: {label.source}; name: {label.name}"
    yield from (
        "", f"Response packet/session process relation: {association.process_relation}",
        "An observed regular or effective process difference is reported as different. Otherwise, incomplete comparable metadata makes the relation unknown.",
        "Interpretation limits",
        "This candidate uses saved query/response evidence, the client/interface scope, a recorded answer address and its TTL window.",
        "Matching frames are only the observed members at or after this response and strictly before the effective expiry.",
        "Effective expiry is the earlier of the original answer/CNAME TTL expiry and a later accepted linked answer, NXDOMAIN or NODATA response for this question or an answer-chain dependency in the same client/interface scope.",
        "A decoder frame identifies where a message was decoded, including completed TCP reassembly; it does not claim that every message byte was in that single packet.",
        "It does not prove the application used this DNS answer, that the DNS resolver was authentic, or that a process owned a connection.",
        "Names can have multiple answers and sessions can have multiple candidates. No candidate becomes an asserted host identity.",
        "No active DNS/PTR lookup, cross-capture attribution, baseline update or evidence-file write is performed.",
        "Use the query, response and matched packet actions to inspect original evidence.",
    )


def dns_process_lines(name: str, metadata: ProcessMetadata) -> Iterator[str]:
    """Expose all recorded process source/PID/name values within whole-view bounds."""
    yield f"{name} state: {metadata.state}"
    for label in metadata.labels:
        yield f"  Source: {label.source}; PID: {label.pid if label.pid is not None else 'unknown'}; name: {label.name if label.name is not None else 'unknown'}"


def dns_diagnostics_summary(index: DnsSessionIndex) -> str:
    """Show bounded reason counts while preserving original diagnostic references."""
    counts: dict[str, int] = {}
    for diagnostic in index.diagnostics:
        counts[diagnostic.reason] = counts.get(diagnostic.reason, 0) + 1
    text = "; ".join(f"{reason}: {count}" for reason, count in sorted(counts.items()))
    return text if len(text.encode("utf-8")) <= 8 * 1024 else "Diagnostic reason summary exceeds 8 KiB; original observed DNS packets remain available."


def dns_observation_text(index: DnsSessionIndex) -> str:
    """Describe unassociated diagnostic references or refuse an oversized view."""
    lines = [
        "No selected DNS candidate.", f"Capture SHA-256: {index.capture_sha256}",
        f"Observed DNS messages: {len(index.dns_evidence.messages)}; candidate associations: {len(index.associations)}",
        f"Diagnostic reason counts: {dns_diagnostics_summary(index) or '(none)'}",
        "Diagnostic observations identify original decoder frame/message references. A question observation alone is not a DNS-to-session association.",
    ]
    size = sum(len(line.encode("utf-8")) + 1 for line in lines)
    for diagnostic in index.diagnostics:
        line = f"Frame {diagnostic.frame_number}; message index {diagnostic.message_index}: {diagnostic.reason}"
        size += len(line.encode("utf-8")) + 1
        if size > INSPECTOR_MAX_BYTES:
            return "\n".join((
                "DNS diagnostic inspector rendering limit exceeded.",
                f"Capture SHA-256: {index.capture_sha256}",
                "The complete diagnostic reference view exceeds 512 KiB. No partial list is presented.",
                "Reason counts and original observed DNS packets remain available.",
            ))
        lines.append(line)
    lines.append("Use Show observed DNS packets to inspect associated and unassociated original decoder frames. No resolver lookup is performed.")
    return "\n".join(lines)


def valid_dns_page(index: DnsSessionIndex, query: DnsQuery, page: DnsAssociationPage) -> bool:
    """Validate bounded Qt worker output before exposing evidence or page counts."""
    counts = (page.total_count, page.matching_count, page.page_count, page.page_number, page.page_size)
    if any(type(value) is not int for value in counts) or page.capture_sha256 != index.capture_sha256 or page.total_count != len(index.associations) or not 0 <= page.matching_count <= page.total_count or page.page_size != query.page_size:
        return False
    expected_pages = (page.matching_count + page.page_size - 1) // page.page_size
    expected_page = min(query.page_number, expected_pages) if expected_pages else 1
    expected_rows = min(page.page_size, max(0, page.matching_count - (expected_page - 1) * page.page_size))
    if page.page_count != expected_pages or page.page_number != expected_page or type(page.associations) is not tuple or len(page.associations) != expected_rows:
        return False
    if page.selected_match_page is not None and (type(page.selected_match_page) is not int or not 1 <= page.selected_match_page <= page.page_count):
        return False
    identities: set[DnsAssociationIdentity] = set()
    for association in page.associations:
        if not isinstance(association, DnsSessionAssociation) or dns_association_for_identity(index, association.identity) is not association or association.identity in identities:
            return False
        if query.session_identity is not None and association.session_identity != query.session_identity:
            return False
        identities.add(association.identity)
    return True


def dns_inspector_text(index: DnsSessionIndex, association: DnsSessionAssociation) -> str:
    """Render the whole candidate or explicitly refuse a 512 KiB oversized view."""
    lines: list[str] = []
    size = 0
    for line in dns_inspector_lines(index, association):
        size += len(line.encode("utf-8")) + 1
        if size > INSPECTOR_MAX_BYTES:
            return "\n".join((
                "Inspector rendering limit exceeded.",
                f"Capture SHA-256: {association.identity.capture_sha256}",
                f"Association SHA-256: {association.identity.association_sha256}",
                "The complete DNS candidate exceeds the 512 KiB rendering ceiling. No partial candidate is presented.",
                "Original query, response and matching packet evidence remain available.",
            ))
        lines.append(line)
    return "\n".join(lines)


class DnsAssociationPageModel(QAbstractTableModel):
    """Expose one bounded page of existing immutable association references."""

    def __init__(self, parent: QObject) -> None:
        super().__init__(parent)
        self.setObjectName("dnsEvidencePageModel")
        self.associations: tuple[DnsSessionAssociation, ...] = ()

    def set_associations(self, associations: tuple[DnsSessionAssociation, ...]) -> None:
        self.beginResetModel()
        self.associations = associations
        self.endResetModel()

    def rowCount(self, parent: QModelIndex) -> int:
        return 0 if parent.isValid() else len(self.associations)

    def columnCount(self, parent: QModelIndex) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int) -> str | None:
        if not index.isValid() or not 0 <= index.row() < len(self.associations) or not 0 <= index.column() < len(COLUMNS):
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return dns_association_cell(self.associations[index.row()], index.column())
        if role == Qt.ItemDataRole.ToolTipRole:
            return evidence_tooltip_text(dns_association_cell(self.associations[index.row()], index.column()))
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int) -> str | None:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal and 0 <= section < len(COLUMNS):
            return COLUMNS[section]
        return None


@dataclass(frozen=True, slots=True)
class DnsNavigation:
    capture_sha256: str
    index_generation: int
    query: DnsQuery
    selected_identity: DnsAssociationIdentity | None
    vertical_scroll_value: int


@dataclass(frozen=True, slots=True)
class _JobRequest:
    generation: int
    index: DnsSessionIndex
    query: DnsQuery
    selected_identity: DnsAssociationIdentity | None
    reveal_selection: DnsAssociationIdentity | None
    restore_scroll_value: int | None


@dataclass(frozen=True, slots=True)
class _JobOutcome:
    generation: int
    page: DnsAssociationPage | None
    query: DnsQuery
    restore_scroll_value: int | None
    error: Exception | None


class _DnsQueryWorker(QThread):
    """Owned Qt thread connector that returns naturally after one pure query."""

    completed = Signal(object)

    def __init__(self, request: _JobRequest, cancellation: Event, parent: QObject) -> None:
        super().__init__(parent)
        self.request = request
        self.cancellation = cancellation

    @Slot()
    def run(self) -> None:
        try:
            query = self.request.query
            page = query_dns_associations(self.request.index, query, self.request.selected_identity, self.cancellation)
            if self.request.reveal_selection is not None and page.selected_match_page is not None and page.selected_match_page != page.page_number:
                query = replace(query, page_number=page.selected_match_page)
                page = query_dns_associations(self.request.index, query, self.request.selected_identity, self.cancellation)
            outcome = _JobOutcome(self.request.generation, page, query, self.request.restore_scroll_value, None)
        except Exception as error:
            # Preserve the original cause at the external Qt thread boundary.
            outcome = _JobOutcome(self.request.generation, None, self.request.query, None, error)
        self.completed.emit(outcome)


class DnsSessionWidget(QWidget):
    """Bounded passive DNS candidate pages and capture-bound navigation requests."""

    query_packet_requested = Signal(object)
    response_packet_requested = Signal(object)
    superseding_packet_requested = Signal(object)
    matched_packets_requested = Signal(object)
    session_requested = Signal(object)
    observed_packets_requested = Signal(str, object)
    return_session_requested = Signal()
    page_changed = Signal()
    busy_changed = Signal(bool)
    shutdown_complete = Signal()

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setObjectName("dnsSessionEvidence")
        self._index: DnsSessionIndex | None = None
        self.completed_page: DnsAssociationPage | None = None
        self.selected_identity: DnsAssociationIdentity | None = None
        self._completed_query: DnsQuery | None = None
        self._session_scope: SessionIdentity | None = None
        self._generation = 0
        self._index_generation = 0
        self._pending: _JobRequest | None = None
        self._active_request: _JobRequest | None = None
        self._thread: _DnsQueryWorker | None = None
        self._cancellation: Event | None = None
        self._shutting_down = False
        self._applying_page = False
        self._last_worker_failure: Exception | None = None
        self._create_controls()
        self._show_unavailable("Analyze a saved capture to inspect passive DNS candidate evidence.")

    def _create_controls(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        explanation = QLabel("Saved DNS candidates do not prove application use, process ownership or DNS authenticity.", self)
        explanation.setTextFormat(Qt.TextFormat.PlainText)
        explanation.setWordWrap(True)
        explanation.setObjectName("dnsEvidenceExplanation")
        layout.addWidget(explanation)
        self.scope_label = QLabel("All session candidates", self)
        self.scope_label.setObjectName("dnsScope")
        self.scope_label.setTextFormat(Qt.TextFormat.PlainText)
        self.scope_label.setWordWrap(True)
        layout.addWidget(self.scope_label)
        filters = QHBoxLayout()
        self.search_field = QLineEdit(self)
        self.search_field.setObjectName("dnsSearch")
        self.search_field.setPlaceholderText("Literal question, answer, frame or session evidence text")
        self.search_field.setMaxLength(512)
        self.apply_button = self._button("dnsApplyFilters", "Apply search", self.apply_filters)
        self.clear_button = self._button("dnsClearFilters", "Clear search", self.clear_filters)
        self.show_all_button = self._button("dnsShowAllSessions", "Show all sessions", self.show_all)
        self.cancel_button = self._button("dnsCancelQuery", "Cancel query", self.cancel_query)
        self.page_size = QComboBox(self)
        self.page_size.setObjectName("dnsPageSize")
        for size in (100, 250, 500):
            self.page_size.addItem(str(size), size)
        filters.addWidget(self.search_field, 1)
        for button in (self.apply_button, self.clear_button, self.show_all_button, self.cancel_button):
            filters.addWidget(button)
        filters.addWidget(QLabel("Rows per page", self))
        filters.addWidget(self.page_size)
        layout.addLayout(filters)
        self.status_label = QLabel(self)
        self.status_label.setObjectName("dnsPageStatus")
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.diagnostics_label = QLabel(self)
        self.diagnostics_label.setObjectName("dnsDiagnosticsStatus")
        self.diagnostics_label.setTextFormat(Qt.TextFormat.PlainText)
        self.diagnostics_label.setWordWrap(True)
        layout.addWidget(self.diagnostics_label)
        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        splitter.setObjectName("dnsEvidenceSplitter")
        splitter.setChildrenCollapsible(False)
        self.table = QTableView(splitter)
        self.table.setObjectName("dnsEvidenceTable")
        self.model = DnsAssociationPageModel(self.table)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False)
        self.table.setWordWrap(False)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        panel = QWidget(splitter)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(6, 6, 6, 6)
        panel_layout.setSpacing(4)
        self.selection_notice = QLabel(panel)
        self.selection_notice.setObjectName("dnsSelectionNotice")
        self.selection_notice.setTextFormat(Qt.TextFormat.PlainText)
        self.selection_notice.setWordWrap(True)
        self.inspector = QPlainTextEdit(panel)
        self.inspector.setObjectName("dnsEvidenceInspector")
        self.inspector.setReadOnly(True)
        panel_layout.addWidget(self.selection_notice)
        panel_layout.addWidget(self.inspector)
        actions = QGridLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(4)
        self.query_button = self._button("dnsShowQueryPacket", "Show query packet", self.show_query_packet)
        self.response_button = self._button("dnsShowResponsePacket", "Show response packet", self.show_response_packet)
        self.superseding_button = self._button("dnsShowSupersedingPacket", "Show superseding packet", self.show_superseding_packet)
        self.matched_button = self._button("dnsShowMatchedPackets", "Show matched packets", self.show_matched_packets)
        self.session_button = self._button("dnsShowSession", "Show session", self.show_session)
        for position, button in enumerate((self.query_button, self.response_button, self.superseding_button, self.matched_button, self.session_button)):
            actions.addWidget(button, position // 2, position % 2)
        panel_layout.addLayout(actions)
        splitter.addWidget(self.table)
        splitter.addWidget(panel)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        navigation = QHBoxLayout()
        self.previous_button = self._button("dnsPreviousPage", "Previous page", self.previous_page)
        self.next_button = self._button("dnsNextPage", "Next page", self.next_page)
        self.observed_button = self._button("dnsShowObservedPackets", "Show observed DNS packets", self.show_observed_packets)
        self.return_session_button = self._button("dnsReturnToSession", "Return to previous session view", self.return_to_session)
        for button in (self.previous_button, self.next_button, self.observed_button):
            navigation.addWidget(button)
        navigation.addStretch()
        navigation.addWidget(self.return_session_button)
        layout.addLayout(navigation)
        self.page_size.currentIndexChanged.connect(self.apply_filters)
        self.search_field.returnPressed.connect(self.apply_filters)

    def _button(self, name: str, text: str, action: Callable[[], None]) -> QPushButton:
        button = QPushButton(text, self)
        button.setObjectName(name)
        button.clicked.connect(action)
        return button

    @property
    def is_busy(self) -> bool:
        return self._thread is not None or self._pending is not None

    @property
    def page(self) -> DnsAssociationPage | None:
        return self.completed_page

    @property
    def dns_index(self) -> DnsSessionIndex | None:
        return self._index

    @property
    def index(self) -> DnsSessionIndex | None:
        return self._index

    def _show_unavailable(self, message: str) -> None:
        self.completed_page = None
        self._completed_query = None
        self.model.set_associations(())
        self.selected_identity = None
        self.inspector.setPlainText(message)
        self.selection_notice.setText("No selected DNS candidate.")
        self.status_label.setText(message)
        self.diagnostics_label.setText("DNS message evidence unavailable.")
        self.return_session_button.setEnabled(False)
        self._set_scope_label()
        self._set_controls(False)

    def set_index(self, index: DnsSessionIndex) -> None:
        """Replace completed correlation evidence and invalidate all view snapshots."""
        if self._shutting_down:
            return
        if not isinstance(index, DnsSessionIndex):
            raise DnsSessionValidationError("DNS widget requires a completed DNS session index.")
        self._invalidate_request()
        self._index_generation += 1
        self._pending = None
        self._index = index
        self._session_scope = None
        self.search_field.clear()
        self._set_scope_label()
        self._show_unavailable("Loading passive DNS candidates for the current capture…")
        self._schedule_query(1)

    def clear_index(self) -> None:
        """Forget evidence immediately and cancel any owned query without partial results."""
        self._invalidate_request()
        self._index_generation += 1
        self._pending = None
        self._index = None
        self._session_scope = None
        self._set_scope_label()
        self._show_unavailable("Passive DNS evidence is unavailable for the current report.")

    def _set_scope_label(self) -> None:
        scope = self._completed_query.session_identity if self.completed_page is not None and self._completed_query is not None else self._session_scope
        self.scope_label.setText("Completed page: all session candidates" if scope is None else f"Completed page: candidates for session scope {scope.scope_sha256}")

    def filter_for_session(self, identity: SessionIdentity) -> bool:
        """Apply an existing exact session scope while retaining the literal search."""
        index = self._index
        try:
            if self._shutting_down or index is None or not isinstance(identity, SessionIdentity) or session_for_identity(index.session_index, identity) is None:
                return False
        except SessionValidationError:
            return False
        self._session_scope = identity
        self._set_scope_label()
        self._schedule_query(1)
        return True

    @Slot()
    def show_all(self) -> None:
        self._session_scope = None
        self._set_scope_label()
        self._schedule_query(1)

    def select_association(self, identity: DnsAssociationIdentity) -> bool:
        """Reveal an existing candidate with an explicit search and scope reset."""
        try:
            if self._shutting_down or self._index is None or not isinstance(identity, DnsAssociationIdentity) or dns_association_for_identity(self._index, identity) is None:
                return False
        except DnsSessionValidationError:
            return False
        self.selected_identity = identity
        self._session_scope = None
        self.search_field.clear()
        self._set_scope_label()
        self._refresh_inspector()
        self._queue_query(self._query(1), identity, None)
        return True

    def capture_navigation(self) -> DnsNavigation | None:
        if self._index is None or self.completed_page is None or self._completed_query is None:
            return None
        return DnsNavigation(self._index.capture_sha256, self._index_generation, self._completed_query, self.selected_identity, self.table.verticalScrollBar().value())

    def restore_navigation(self, snapshot: DnsNavigation) -> bool:
        """Restore only a validated snapshot from the exact loaded index generation."""
        index = self._index
        if self._shutting_down or index is None or not isinstance(snapshot, DnsNavigation) or snapshot.capture_sha256 != index.capture_sha256 or type(snapshot.index_generation) is not int or snapshot.index_generation != self._index_generation or not isinstance(snapshot.query, DnsQuery) or type(snapshot.vertical_scroll_value) is not int or not 0 <= snapshot.vertical_scroll_value <= 2**31 - 1:
            return False
        try:
            validate_dns_query(snapshot.query)
            if self.page_size.findData(snapshot.query.page_size) < 0:
                return False
            if snapshot.query.session_identity is not None and session_for_identity(index.session_index, snapshot.query.session_identity) is None:
                return False
            if snapshot.selected_identity is not None and (not isinstance(snapshot.selected_identity, DnsAssociationIdentity) or dns_association_for_identity(index, snapshot.selected_identity) is None):
                return False
        except (DnsSessionValidationError, SessionValidationError):
            return False
        self.selected_identity = snapshot.selected_identity
        self._session_scope = snapshot.query.session_identity
        self._set_scope_label()
        self.search_field.setText(snapshot.query.search)
        self.page_size.blockSignals(True)
        self.page_size.setCurrentIndex(self.page_size.findData(snapshot.query.page_size))
        self.page_size.blockSignals(False)
        self._queue_query(snapshot.query, None, snapshot.vertical_scroll_value)
        return True

    def _query(self, page_number: int) -> DnsQuery:
        size = self.page_size.currentData()
        if type(size) is not int or size not in (100, 250, 500):
            raise DnsSessionValidationError("Page size must be 100, 250 or 500.")
        query = DnsQuery(self.search_field.text(), self._session_scope, page_number, size)
        validate_dns_query(query)
        return query

    def _invalidate_request(self) -> None:
        self._generation += 1
        if self._cancellation is not None:
            self._cancellation.set()

    @Slot()
    def apply_filters(self) -> None:
        self._schedule_query(1)

    @Slot()
    def clear_filters(self) -> None:
        self.search_field.clear()
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
        if self._shutting_down or self._index is None:
            return
        try:
            query = self._query(page_number)
        except DnsSessionValidationError as error:
            self._invalidate_request()
            self._pending = None
            self.status_label.setText(f"Invalid DNS filter: {error}. The completed page is unchanged.")
            return
        self._queue_query(query, self.selected_identity, None)

    def _queue_query(self, query: DnsQuery, reveal_selection: DnsAssociationIdentity | None, restore_scroll_value: int | None) -> None:
        if self._shutting_down or self._index is None:
            return
        self._invalidate_request()
        self._pending = _JobRequest(self._generation, self._index, query, self.selected_identity, reveal_selection, restore_scroll_value)
        self.status_label.setText("Querying passive DNS candidates… The previous completed page remains available.")
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
        thread = _DnsQueryWorker(request, cancellation, self)
        thread.setObjectName("dnsEvidenceQueryThread")
        thread.completed.connect(self._job_completed, Qt.ConnectionType.QueuedConnection)
        thread.finished.connect(self._thread_finished, Qt.ConnectionType.QueuedConnection)
        self._thread = thread
        self.busy_changed.emit(True)
        thread.start()

    @Slot(object)
    def _job_completed(self, value: object) -> None:
        if not isinstance(value, _JobOutcome) or type(value.generation) is not int or not isinstance(value.query, DnsQuery) or value.error is not None and not isinstance(value.error, Exception) or value.restore_scroll_value is not None and (type(value.restore_scroll_value) is not int or not 0 <= value.restore_scroll_value <= 2**31 - 1):
            self.status_label.setText("DNS query worker returned an invalid result; the completed page is unchanged.")
            return
        if self._shutting_down or value.generation != self._generation:
            return
        active = self._active_request
        if active is not None and active.selected_identity != self.selected_identity:
            self._queue_query(active.query, self.selected_identity if active.reveal_selection is not None else None, active.restore_scroll_value)
            return
        if value.error is not None:
            self._last_worker_failure = value.error
            if isinstance(value.error, DnsSessionCancelled):
                self.status_label.setText("DNS query cancelled. The previous completed page and selection are unchanged.")
            elif isinstance(value.error, DnsSessionValidationError):
                self.status_label.setText(f"Invalid DNS evidence or filter: {value.error}. The previous completed page is unchanged.")
            else:
                self.status_label.setText(f"Unexpected DNS query failure ({type(value.error).__name__}). The previous completed page is unchanged. Retry or review developer diagnostics.")
            return
        index = self._index
        page = value.page
        if not isinstance(page, DnsAssociationPage) or index is None:
            self.status_label.setText("DNS query worker returned inconsistent capture evidence; the completed page is unchanged.")
            return
        try:
            validate_dns_query(value.query)
            if not valid_dns_page(index, value.query, page):
                self.status_label.setText("DNS query worker returned unavailable candidate evidence; the completed page is unchanged.")
                return
        except DnsSessionValidationError:
            self.status_label.setText("DNS query worker returned invalid candidate identities; the completed page is unchanged.")
            return
        self._last_worker_failure = None
        self.completed_page = page
        self._completed_query = value.query
        self._set_scope_label()
        self._apply_page(page)
        if value.restore_scroll_value is not None:
            self.table.verticalScrollBar().setValue(value.restore_scroll_value)
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
        elif self._pending is not None:
            self._start_pending()
        else:
            self._set_controls(False)
            self.busy_changed.emit(False)

    def _set_controls(self, busy: bool) -> None:
        available = self._index is not None and not self._shutting_down
        for button in (self.query_button, self.response_button, self.superseding_button, self.matched_button, self.session_button):
            button.setMinimumHeight(button.minimumSizeHint().height())
        self.apply_button.setEnabled(available)
        self.clear_button.setEnabled(available)
        self.show_all_button.setEnabled(available)
        self.page_size.setEnabled(available)
        self.cancel_button.setEnabled(busy and available)
        page = self.completed_page
        self.previous_button.setEnabled(not busy and available and page is not None and page.page_number > 1)
        self.next_button.setEnabled(not busy and available and page is not None and page.page_number < page.page_count)
        selected = available and self.selected_identity is not None
        for button in (self.query_button, self.response_button, self.matched_button, self.session_button):
            button.setEnabled(selected)
        association = self._selected_association()
        self.superseding_button.setEnabled(available and association is not None and association.superseded_by_frame is not None)
        self.observed_button.setEnabled(available and self._index is not None and bool(observed_dns_frames(self._index)))

    def _apply_page(self, page: DnsAssociationPage) -> None:
        self._applying_page = True
        try:
            self.model.set_associations(page.associations)
            if self.selected_identity is not None:
                for row, association in enumerate(page.associations):
                    if association.identity == self.selected_identity:
                        self.table.selectRow(row)
                        break
        finally:
            self._applying_page = False
        index = self._index
        message_count = len(index.dns_evidence.messages) if index is not None else 0
        diagnostic_count = len(index.diagnostics) if index is not None else 0
        self.status_label.setText(f"{page.matching_count} matching / {page.total_count} total DNS candidates · {message_count} recorded DNS messages · {diagnostic_count} diagnostics · Page {page.page_number if page.page_count else 0} of {page.page_count} · {len(page.associations)} displayed")
        summary = dns_diagnostics_summary(index) if index is not None else "unavailable"
        self.diagnostics_label.setText(f"{diagnostic_count} diagnostic observations. Full reason counts and frame references remain available.")
        self.diagnostics_label.setToolTip(f"Diagnostic reason counts: {summary or '(none)'}. Show observed DNS packets retains original frame evidence.")
        self._refresh_inspector()

    @Slot()
    def _selection_changed(self) -> None:
        if self._applying_page:
            return
        rows = self.table.selectionModel().selectedRows()
        if len(rows) != 1 or not 0 <= rows[0].row() < len(self.model.associations):
            return
        self.selected_identity = self.model.associations[rows[0].row()].identity
        self._refresh_inspector()

    def _selected_association(self) -> DnsSessionAssociation | None:
        if self._shutting_down or self._index is None or self.selected_identity is None:
            return None
        return dns_association_for_identity(self._index, self.selected_identity)

    def _refresh_inspector(self) -> None:
        association = self._selected_association()
        if association is None or self._index is None:
            self.selection_notice.setText("Select a candidate to inspect evidence.")
            self.inspector.setPlainText(dns_observation_text(self._index) if self._index is not None else "No selected DNS candidate.")
            for button in (self.query_button, self.response_button, self.superseding_button, self.matched_button, self.session_button):
                button.setEnabled(False)
            return
        page = self.completed_page
        visible = page is not None and any(item.identity == association.identity for item in page.associations)
        notice = "Selected candidate on this page." if visible else "Selected candidate outside the current filter." if page is not None and page.selected_match_page is None else "Selected candidate outside this page."
        self.selection_notice.setText(notice)
        self.inspector.setPlainText(dns_inspector_text(self._index, association))
        for button in (self.query_button, self.response_button, self.matched_button, self.session_button):
            button.setEnabled(True)
        self.superseding_button.setEnabled(association.superseded_by_frame is not None)

    @Slot()
    def show_query_packet(self) -> None:
        association = self._selected_association()
        if association is not None:
            self.query_packet_requested.emit(PacketIdentity(association.identity.capture_sha256, association.query_frame))

    @Slot()
    def show_response_packet(self) -> None:
        association = self._selected_association()
        if association is not None:
            self.response_packet_requested.emit(PacketIdentity(association.identity.capture_sha256, association.response_frame))

    @Slot()
    def show_superseding_packet(self) -> None:
        association = self._selected_association()
        if association is not None and association.superseded_by_frame is not None:
            self.superseding_packet_requested.emit(PacketIdentity(association.identity.capture_sha256, association.superseded_by_frame))

    @Slot()
    def show_matched_packets(self) -> None:
        association = self._selected_association()
        if association is not None:
            self.matched_packets_requested.emit(association.identity)

    @Slot()
    def show_session(self) -> None:
        association = self._selected_association()
        if association is not None:
            self.session_requested.emit(association.session_identity)

    @Slot()
    def show_observed_packets(self) -> None:
        if not self._shutting_down and self._index is not None:
            frames = observed_dns_frames(self._index)
            if frames:
                self.observed_packets_requested.emit(self._index.capture_sha256, frames)

    @Slot()
    def return_to_session(self) -> None:
        if not self._shutting_down and self.return_session_button.isEnabled():
            self.return_session_requested.emit()

    @Slot()
    def cancel_query(self) -> None:
        self._invalidate_request()
        self._pending = None
        self.status_label.setText("DNS query cancelled. The previous completed page and selection are unchanged.")
        self.cancel_button.setEnabled(False)

    def shutdown(self) -> bool:
        """Cancel owned work; false requires awaiting shutdown_complete before close."""
        self._shutting_down = True
        self._pending = None
        self._invalidate_request()
        self._set_controls(False)
        self.return_session_button.setEnabled(False)
        return self._thread is None
