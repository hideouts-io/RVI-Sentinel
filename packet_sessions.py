"""Scoped TCP/UDP correlation over immutable passive packet evidence.

A session is a decoder stream plus its complete bidirectional endpoint tuple,
capture digest, recorded interface, regular process and effective process
contexts. Unknown context is an exact scope, never a wildcard for known context.
These groups do not establish connection lifetime, process ownership, packet
direction or timeout-based conversation boundaries. Conflicts and incomplete
tuples remain explicitly ungrouped. The index holds packet references and frame
identities rather than copying decoded payload values.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
from bisect import bisect_left
from dataclasses import dataclass
from typing import Iterator, Literal, TypedDict

from packet_models import (
    DirectionLabel,
    DirectionMetadata,
    InterfaceLabel,
    InterfaceMetadata,
    InterfaceDocument,
    PacketRecord,
    PacketTimestamp,
    PacketTransport,
    ProcessMetadata,
    ProcessLabel,
    ProcessDocument,
    PacketValidationError,
    PROTOCOL_TOKEN,
    decode_packet_timestamp,
    process_document,
)
from packet_timeline import (
    MAX_QUERY_TEXT,
    PAGE_SIZES,
    InterfaceStateFilter,
    PacketIdentity,
    PacketIndex,
    ProcessStateFilter,
    build_packet_index,
    packet_for_identity,
)

SessionTransportFilter = Literal["all", "tcp", "udp"]
UngroupedReason = Literal[
    "non_tcp_udp", "ambiguous_network", "incomplete_network",
    "ambiguous_transport", "incomplete_transport", "missing_stream",
    "process_conflict", "effective_process_conflict", "interface_conflict",
    "direction_conflict",
]
UNGROUPED_REASONS: tuple[UngroupedReason, ...] = (
    "non_tcp_udp", "ambiguous_network", "incomplete_network",
    "ambiguous_transport", "incomplete_transport", "missing_stream",
    "process_conflict", "effective_process_conflict", "interface_conflict",
    "direction_conflict",
)
MAX_SESSION_PACKETS = 200_000
MAX_SESSION_ESTIMATED_BYTES = 256 * 1_024 * 1_024


class SessionValidationError(ValueError):
    """An identity, query or packet index violates the session contract."""


class SessionCancelled(RuntimeError):
    """Session correlation or filtering was cancelled without a partial result."""


@dataclass(frozen=True, slots=True)
class SessionIdentity:
    capture_sha256: str
    scope_sha256: str


@dataclass(frozen=True, slots=True)
class EndpointScope:
    address: str
    port: int


@dataclass(frozen=True, slots=True)
class SessionScope:
    transport: PacketTransport
    stream: int
    endpoint_a: EndpointScope
    endpoint_b: EndpointScope
    process: ProcessMetadata
    effective_process: ProcessMetadata
    interface: InterfaceMetadata


@dataclass(frozen=True, slots=True)
class SessionRecord:
    identity: SessionIdentity
    scope: SessionScope
    packet_count: int
    first_timestamp: PacketTimestamp
    last_timestamp: PacketTimestamp
    wire_bytes: int
    captured_bytes: int | None
    captured_length_known_count: int
    protocols: tuple[str, ...]
    member_frames: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class UngroupedPacket:
    frame_number: int
    reasons: tuple[UngroupedReason, ...]


@dataclass(frozen=True, slots=True)
class UngroupedReasonCount:
    reason: UngroupedReason
    packet_count: int


@dataclass(frozen=True, slots=True)
class SessionIndex:
    capture_sha256: str
    packet_index: PacketIndex
    sessions: tuple[SessionRecord, ...]
    session_keys: tuple[str, ...]
    key_positions: tuple[int, ...]
    member_frames: tuple[int, ...]
    member_session_positions: tuple[int, ...]
    ungrouped: tuple[UngroupedPacket, ...]
    ungrouped_frame_numbers: tuple[int, ...]
    ungrouped_positions: tuple[int, ...]
    reason_counts: tuple[UngroupedReasonCount, ...]
    eligible_packet_count: int


@dataclass(frozen=True, slots=True)
class SessionQuery:
    search: str
    endpoint: str
    port: int | None
    transport: SessionTransportFilter
    process_text: str
    process_state: ProcessStateFilter
    effective_process_state: ProcessStateFilter
    interface_text: str
    interface_state: InterfaceStateFilter
    page_number: int
    page_size: int


@dataclass(frozen=True, slots=True)
class SessionPage:
    capture_sha256: str
    total_count: int
    matching_count: int
    page_count: int
    page_number: int
    page_size: int
    sessions: tuple[SessionRecord, ...]
    selected_match_page: int | None


class EndpointDocument(TypedDict):
    address: str
    port: int


class ScopeDocument(TypedDict):
    version: int
    capture_sha256: str
    transport: PacketTransport
    stream: int
    endpoints: list[EndpointDocument]
    process: ProcessDocument
    effective_process: ProcessDocument
    interface: InterfaceDocument


EMPTY_SESSION_QUERY = SessionQuery("", "", None, "all", "", "all", "all", "", "all", 1, 100)


def _check_cancelled(cancellation: threading.Event) -> None:
    if cancellation.is_set():
        raise SessionCancelled("Session correlation or filtering was cancelled.")


def _validate_digest(value: str) -> None:
    if type(value) is not str or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SessionValidationError("Session identity requires lowercase 64-character SHA-256 values.")


def _validate_identity(identity: SessionIdentity) -> None:
    if not isinstance(identity, SessionIdentity):
        raise SessionValidationError("Session lookup requires a typed session identity.")
    _validate_digest(identity.capture_sha256)
    _validate_digest(identity.scope_sha256)


def _validate_record(packet: PacketRecord) -> None:
    if not isinstance(packet, PacketRecord):
        raise SessionValidationError("Session input must contain validated packet records.")
    if type(packet.frame_number) is not int or not 1 <= packet.frame_number <= 2**64 - 1:
        raise SessionValidationError("Session input requires valid original frame numbers.")
    try:
        timestamp_matches = isinstance(packet.timestamp, PacketTimestamp) and type(packet.timestamp.seconds) is int and type(packet.timestamp.nanoseconds) is int and decode_packet_timestamp(packet.timestamp.epoch) == packet.timestamp
    except (PacketValidationError, TypeError) as error:
        raise SessionValidationError("Session input requires exact validated packet timestamps.") from error
    if not timestamp_matches:
        raise SessionValidationError("Session input requires exact validated packet timestamps.")
    if type(packet.wire_length) is not int or not 0 <= packet.wire_length <= 2**32 - 1:
        raise SessionValidationError("Session input requires nonnegative wire lengths.")
    if packet.captured_length is not None and (type(packet.captured_length) is not int or not 0 <= packet.captured_length <= packet.wire_length):
        raise SessionValidationError("Session input requires valid captured lengths no larger than wire lengths.")
    for address in (packet.source_address, packet.destination_address):
        if address is not None:
            if type(address) is not str or len(address) > 45 or "%" in address:
                raise SessionValidationError("Session endpoints require complete IP addresses without zone suffixes.")
            try:
                ipaddress.ip_address(address)
            except ValueError as error:
                raise SessionValidationError("Session input contains an invalid IP endpoint.") from error
    for port in (packet.source_port, packet.destination_port):
        if port is not None and (type(port) is not int or not 0 <= port <= 65_535):
            raise SessionValidationError("Session endpoints require integer ports from 0 through 65535.")
    if packet.transport is not None and packet.transport not in ("tcp", "udp"):
        raise SessionValidationError("Session input transport must be TCP, UDP or unavailable.")
    if packet.stream is not None and (type(packet.stream) is not int or not 0 <= packet.stream <= 2**32 - 1):
        raise SessionValidationError("Session input requires valid unsigned decoder stream IDs.")
    if type(packet.protocol_stack) is not tuple or not 1 <= len(packet.protocol_stack) <= 64 or any(type(protocol) is not str or PROTOCOL_TOKEN.fullmatch(protocol) is None for protocol in packet.protocol_stack):
        raise SessionValidationError("Session input requires validated protocol stack tokens.")
    if type(packet.diagnostics) is not tuple or any(type(diagnostic) is not str or len(diagnostic) > 128 for diagnostic in packet.diagnostics):
        raise SessionValidationError("Session input requires bounded immutable diagnostic codes.")
    for metadata in (packet.process, packet.effective_process):
        if not isinstance(metadata, ProcessMetadata) or metadata.state not in ("unknown", "recorded", "conflict") or type(metadata.labels) is not tuple or len(metadata.labels) > 512:
            raise SessionValidationError("Session input requires validated process metadata states.")
        for label in metadata.labels:
            if not isinstance(label, ProcessLabel) or label.source not in ("apple_pcapng", "pktap") or label.pid is not None and (type(label.pid) is not int or not 0 <= label.pid <= 2**31 - 1) or label.name is not None and (type(label.name) is not str or not label.name or len(label.name.encode("utf-8")) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in label.name)):
                raise SessionValidationError("Session input requires validated recorded process labels.")
        identifiers = {label.pid for label in metadata.labels if label.pid is not None}
        names = {label.name for label in metadata.labels if label.name is not None}
        repeated_sources = len({label.source for label in metadata.labels}) != len(metadata.labels)
        expected_state = "conflict" if repeated_sources or len(identifiers) > 1 or len(names) > 1 else "recorded" if identifiers or names else "unknown"
        if metadata.state != expected_state:
            raise SessionValidationError("Session process metadata state contradicts its recorded labels.")
    if not isinstance(packet.interface, InterfaceMetadata) or packet.interface.state not in ("unknown", "recorded", "conflict") or type(packet.interface.labels) is not tuple:
        raise SessionValidationError("Session input requires validated interface metadata.")
    if any(not isinstance(label, InterfaceLabel) or label.source not in ("capture_frame", "pktap") or type(label.name) is not str or not label.name or len(label.name.encode("utf-8")) > 256 or any(ord(character) < 32 or ord(character) == 127 for character in label.name) for label in packet.interface.labels):
        raise SessionValidationError("Session input requires validated recorded interface labels.")
    interface_conflict = len({label.source for label in packet.interface.labels}) != len(packet.interface.labels) or len({label.name for label in packet.interface.labels}) > 1
    expected_interface = "conflict" if interface_conflict else "recorded" if packet.interface.labels else "unknown"
    if packet.interface.state != expected_interface:
        raise SessionValidationError("Session interface metadata state contradicts its recorded labels.")
    if not isinstance(packet.direction, DirectionMetadata) or packet.direction.state not in ("unknown", "recorded", "conflict") or type(packet.direction.labels) is not tuple or any(not isinstance(label, DirectionLabel) or label.source not in ("pcapng_packet_options", "pktap") or label.direction not in ("inbound", "outbound", "unknown") for label in packet.direction.labels):
        raise SessionValidationError("Session input requires a validated direction metadata state.")
    known_directions = {label.direction for label in packet.direction.labels if label.direction != "unknown"}
    direction_conflict = len({label.source for label in packet.direction.labels}) != len(packet.direction.labels) or len(known_directions) > 1
    expected_direction = "conflict" if direction_conflict else "recorded" if known_directions else "unknown"
    if packet.direction.state != expected_direction:
        raise SessionValidationError("Session direction metadata state contradicts its recorded labels.")


def _ungrouped_reasons(packet: PacketRecord) -> tuple[UngroupedReason, ...]:
    reasons: list[UngroupedReason] = []
    if "ambiguous_network_layers" in packet.diagnostics:
        reasons.append("ambiguous_network")
    elif packet.source_address is None or packet.destination_address is None:
        reasons.append("incomplete_network")
    if "ambiguous_transport_layers" in packet.diagnostics:
        reasons.append("ambiguous_transport")
    elif packet.transport is None:
        reasons.append("non_tcp_udp")
    else:
        if packet.source_port is None or packet.destination_port is None:
            reasons.append("incomplete_transport")
        if packet.stream is None:
            reasons.append("missing_stream")
    if packet.process.state == "conflict":
        reasons.append("process_conflict")
    if packet.effective_process.state == "conflict":
        reasons.append("effective_process_conflict")
    if packet.interface.state == "conflict":
        reasons.append("interface_conflict")
    if packet.direction.state == "conflict":
        reasons.append("direction_conflict")
    return tuple(reasons)


def _canonical_process(metadata: ProcessMetadata) -> ProcessMetadata:
    return ProcessMetadata(metadata.state, tuple(sorted(metadata.labels, key=lambda label: (label.source, label.pid if label.pid is not None else -1, label.name if label.name is not None else ""))))


def _scope(packet: PacketRecord) -> SessionScope:
    if packet.source_address is None or packet.destination_address is None or packet.source_port is None or packet.destination_port is None or packet.transport is None or packet.stream is None:
        raise SessionValidationError("Session scope requires complete unambiguous endpoints, transport and decoder stream.")
    endpoints = sorted((EndpointScope(str(ipaddress.ip_address(packet.source_address)), packet.source_port), EndpointScope(str(ipaddress.ip_address(packet.destination_address)), packet.destination_port)), key=lambda endpoint: (ipaddress.ip_address(endpoint.address).version, int(ipaddress.ip_address(endpoint.address)), endpoint.port))
    interface = InterfaceMetadata(packet.interface.state, tuple(sorted(packet.interface.labels, key=lambda label: (label.source, label.name))))
    return SessionScope(packet.transport, packet.stream, endpoints[0], endpoints[1], _canonical_process(packet.process), _canonical_process(packet.effective_process), interface)


def _scope_identity(capture_sha256: str, scope: SessionScope) -> SessionIdentity:
    """Hash a versioned canonical scope; label sources and unknowns stay explicit."""
    payload: ScopeDocument = {
        "version": 1, "capture_sha256": capture_sha256,
        "transport": scope.transport, "stream": scope.stream,
        "endpoints": [{"address": scope.endpoint_a.address, "port": scope.endpoint_a.port}, {"address": scope.endpoint_b.address, "port": scope.endpoint_b.port}],
        "process": process_document(scope.process),
        "effective_process": process_document(scope.effective_process),
        "interface": {"state": scope.interface.state, "labels": [{"source": label.source, "name": label.name} for label in scope.interface.labels]},
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    return SessionIdentity(capture_sha256, digest)


def _scope_estimated_bytes(scope: SessionScope) -> int:
    return 768 + len(scope.endpoint_a.address) + len(scope.endpoint_b.address) + sum(128 + len((label.name or "").encode("utf-8")) for metadata in (scope.process, scope.effective_process) for label in metadata.labels) + sum(128 + len(label.name.encode("utf-8")) for label in scope.interface.labels)


def build_session_index(packet_index: PacketIndex, cancellation: threading.Event) -> SessionIndex:
    """Partition every frame into one scoped session or one ungrouped result.

    Correlation retains at most 200,000 original frame references and applies a
    conservative 256 MiB additional-index estimate. It fails explicitly rather
    than truncating. These ceilings do not measure process RSS. Direction is not
    a grouping key, so reverse traffic joins; conflicting direction metadata
    prevents grouping. Exact timestamp order is inherited from PacketIndex.
    """
    _check_cancelled(cancellation)
    if not isinstance(packet_index, PacketIndex):
        raise SessionValidationError("Session correlation requires a typed packet index.")
    _validate_digest(packet_index.capture_sha256)
    if type(packet_index.packets) is not tuple or len(packet_index.packets) > MAX_SESSION_PACKETS:
        raise SessionValidationError("Session correlation requires an immutable index of at most 200000 packets.")
    if type(packet_index.frame_numbers) is not tuple or type(packet_index.frame_positions) is not tuple or len(packet_index.frame_numbers) != len(packet_index.packets) or len(packet_index.frame_positions) != len(packet_index.packets):
        raise SessionValidationError("Session packet identity index is incomplete.")
    groups: dict[SessionScope, list[PacketRecord]] = {}
    ungrouped: list[UngroupedPacket] = []
    counts: dict[UngroupedReason, int] = {reason: 0 for reason in UNGROUPED_REASONS}
    estimated_bytes = 0
    previous_order: tuple[int, int, int] | None = None
    frames: set[int] = set()
    for position, packet in enumerate(packet_index.packets):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        _validate_record(packet)
        order = (packet.timestamp.seconds, packet.timestamp.nanoseconds, packet.frame_number)
        if packet.frame_number in frames or previous_order is not None and order < previous_order:
            raise SessionValidationError("Session packets must have unique frames in exact timestamp/frame order.")
        frames.add(packet.frame_number)
        previous_order = order
        estimated_bytes += 192
        reasons = _ungrouped_reasons(packet)
        if reasons:
            ungrouped.append(UngroupedPacket(packet.frame_number, reasons))
            estimated_bytes += 128 + 16 * len(reasons)
            for reason in reasons:
                counts[reason] += 1
        else:
            scope = _scope(packet)
            if scope not in groups:
                groups[scope] = []
                estimated_bytes += _scope_estimated_bytes(scope)
            groups[scope].append(packet)
        if estimated_bytes > MAX_SESSION_ESTIMATED_BYTES:
            raise SessionValidationError("Session correlation exceeds the 256 MiB additional-index storage estimate.")
    previous_frame = 0
    for position, (frame, source_position) in enumerate(zip(packet_index.frame_numbers, packet_index.frame_positions)):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        if type(frame) is not int or frame <= previous_frame or type(source_position) is not int or not 0 <= source_position < len(packet_index.packets) or packet_index.packets[source_position].frame_number != frame:
            raise SessionValidationError("Session packet frame lookup is inconsistent with saved evidence.")
        previous_frame = frame
    frames.clear()
    records: list[SessionRecord] = []
    for position, (scope, members) in enumerate(groups.items()):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        known_lengths = sum(packet.captured_length is not None for packet in members)
        captured_bytes = sum(packet.captured_length for packet in members if packet.captured_length is not None) if known_lengths == len(members) else None
        records.append(SessionRecord(_scope_identity(packet_index.capture_sha256, scope), scope, len(members), members[0].timestamp, members[-1].timestamp, sum(packet.wire_length for packet in members), captured_bytes, known_lengths, tuple(sorted({protocol for packet in members for protocol in packet.protocol_stack})), tuple(packet.frame_number for packet in members)))
    records.sort(key=lambda record: (record.first_timestamp.seconds, record.first_timestamp.nanoseconds, record.identity.scope_sha256))
    keys = sorted((record.identity.scope_sha256, position) for position, record in enumerate(records))
    if any(keys[position][0] == keys[position - 1][0] for position in range(1, len(keys))):
        raise SessionValidationError("Distinct session scopes produced duplicate stable identities.")
    members = sorted((frame, position) for position, record in enumerate(records) for frame in record.member_frames)
    ungrouped_keys = sorted((packet.frame_number, position) for position, packet in enumerate(ungrouped))
    _check_cancelled(cancellation)
    eligible_count = sum(record.packet_count for record in records)
    if eligible_count + len(ungrouped) != len(packet_index.packets):
        raise SessionValidationError("Session correlation did not partition every original packet exactly once.")
    return SessionIndex(packet_index.capture_sha256, packet_index, tuple(records), tuple(key for key, _ in keys), tuple(position for _, position in keys), tuple(frame for frame, _ in members), tuple(position for _, position in members), tuple(ungrouped), tuple(frame for frame, _ in ungrouped_keys), tuple(position for _, position in ungrouped_keys), tuple(UngroupedReasonCount(reason, counts[reason]) for reason in UNGROUPED_REASONS if counts[reason]), eligible_count)


def session_for_identity(index: SessionIndex, identity: SessionIdentity) -> SessionRecord | None:
    _validate_identity(identity)
    if identity.capture_sha256 != index.capture_sha256:
        return None
    position = bisect_left(index.session_keys, identity.scope_sha256)
    if position == len(index.session_keys) or index.session_keys[position] != identity.scope_sha256:
        return None
    return index.sessions[index.key_positions[position]]


def session_for_packet(index: SessionIndex, identity: PacketIdentity) -> SessionIdentity | None:
    """Look up exact capture/frame membership; ungrouped packets return None."""
    packet = packet_for_identity(index.packet_index, identity)
    if packet is None:
        return None
    position = bisect_left(index.member_frames, identity.frame_number)
    if position == len(index.member_frames) or index.member_frames[position] != identity.frame_number:
        return None
    return index.sessions[index.member_session_positions[position]].identity


def ungrouped_for_packet(index: SessionIndex, identity: PacketIdentity) -> UngroupedPacket | None:
    """Return every exclusion reason for an original capture-bound frame."""
    if packet_for_identity(index.packet_index, identity) is None:
        return None
    position = bisect_left(index.ungrouped_frame_numbers, identity.frame_number)
    if position == len(index.ungrouped_frame_numbers) or index.ungrouped_frame_numbers[position] != identity.frame_number:
        return None
    return index.ungrouped[index.ungrouped_positions[position]]


def frames_for_session(index: SessionIndex, identity: SessionIdentity) -> tuple[int, ...]:
    """Return time-ordered original frame IDs for a current scoped session."""
    session = session_for_identity(index, identity)
    if session is None:
        raise SessionValidationError("The selected session does not belong to the current capture.")
    return session.member_frames


def ungrouped_frames(index: SessionIndex) -> tuple[int, ...]:
    """Return every ungrouped original frame, in original frame-number order."""
    return index.ungrouped_frame_numbers


def members_for_session(index: SessionIndex, identity: SessionIdentity) -> tuple[PacketRecord, ...]:
    """Return original immutable records in time order without copying payloads."""
    session = session_for_identity(index, identity)
    if session is None:
        raise SessionValidationError("The selected session does not belong to the current capture.")
    records: list[PacketRecord] = []
    for frame in session.member_frames:
        packet = packet_for_identity(index.packet_index, PacketIdentity(index.capture_sha256, frame))
        if packet is None:
            raise SessionValidationError("Session membership references an unavailable original frame.")
        records.append(packet)
    return tuple(records)


def packet_index_for_session(index: SessionIndex, identity: SessionIdentity, cancellation: threading.Event) -> PacketIndex:
    """Build a bounded member-only packet view using the original record objects."""
    _check_cancelled(cancellation)
    records = members_for_session(index, identity)
    _check_cancelled(cancellation)
    return build_packet_index(index.capture_sha256, records, cancellation)


def _normalized_query(query: SessionQuery) -> SessionQuery:
    if not isinstance(query, SessionQuery):
        raise SessionValidationError("Session filtering requires a typed query.")
    for name, value in (("Search", query.search), ("Endpoint", query.endpoint), ("Process", query.process_text), ("Interface", query.interface_text)):
        if type(value) is not str or len(value) > MAX_QUERY_TEXT or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise SessionValidationError(f"{name} filter requires at most 512 characters without control characters.")
    if query.transport not in ("all", "tcp", "udp"):
        raise SessionValidationError("Session transport filter must be all, tcp or udp.")
    if query.port is not None and (type(query.port) is not int or not 0 <= query.port <= 65_535):
        raise SessionValidationError("Session port filter requires an integer from 0 through 65535.")
    for state in (query.process_state, query.effective_process_state, query.interface_state):
        if state not in ("all", "recorded", "unknown", "conflict"):
            raise SessionValidationError("Session metadata filter must be all, recorded, unknown or conflict.")
    if type(query.page_number) is not int or not 1 <= query.page_number <= 2**31 - 1:
        raise SessionValidationError("Session page number requires a positive bounded integer.")
    if type(query.page_size) is not int or query.page_size not in PAGE_SIZES:
        raise SessionValidationError("Session page size must be 100, 250 or 500.")
    endpoint = query.endpoint.strip()
    if endpoint:
        try:
            if "%" in endpoint:
                raise ValueError("zone suffix")
            endpoint = str(ipaddress.ip_address(endpoint))
        except ValueError as error:
            raise SessionValidationError("Session endpoint filter requires a complete IPv4 or IPv6 address without a zone suffix.") from error
    return SessionQuery(query.search.casefold(), endpoint, query.port, query.transport, query.process_text.casefold(), query.process_state, query.effective_process_state, query.interface_text.casefold(), query.interface_state, query.page_number, query.page_size)


def validate_session_query(query: SessionQuery) -> None:
    """Validate a saved query cheaply without scanning or changing session data."""
    _normalized_query(query)


def _process_terms(scope: SessionScope) -> Iterator[str]:
    for metadata in (scope.process, scope.effective_process):
        for label in metadata.labels:
            yield label.source
            if label.name is not None:
                yield label.name
            if label.pid is not None:
                yield str(label.pid)


def _search_terms(session: SessionRecord) -> Iterator[str]:
    yield session.identity.capture_sha256
    yield session.identity.scope_sha256
    yield session.scope.transport
    yield str(session.scope.stream)
    yield str(session.packet_count)
    yield session.first_timestamp.epoch
    yield session.last_timestamp.epoch
    yield from session.protocols
    for endpoint in (session.scope.endpoint_a, session.scope.endpoint_b):
        yield endpoint.address
        yield str(endpoint.port)
    yield session.scope.process.state
    yield session.scope.effective_process.state
    yield session.scope.interface.state
    yield from _process_terms(session.scope)
    for label in session.scope.interface.labels:
        yield label.source
        yield label.name


def _matches(session: SessionRecord, query: SessionQuery) -> bool:
    scope = session.scope
    if query.transport != "all" and scope.transport != query.transport:
        return False
    if query.endpoint and query.endpoint not in (scope.endpoint_a.address, scope.endpoint_b.address):
        return False
    if query.port is not None and query.port not in (scope.endpoint_a.port, scope.endpoint_b.port):
        return False
    if query.process_state != "all" and scope.process.state != query.process_state:
        return False
    if query.effective_process_state != "all" and scope.effective_process.state != query.effective_process_state:
        return False
    if query.interface_state != "all" and scope.interface.state != query.interface_state:
        return False
    if query.process_text and not any(query.process_text in value.casefold() for value in _process_terms(scope)):
        return False
    if query.interface_text and not any(query.interface_text in value.casefold() for label in scope.interface.labels for value in (label.name, label.source)):
        return False
    return not query.search or any(query.search in value.casefold() for value in _search_terms(session))


def query_sessions(index: SessionIndex, query: SessionQuery, selected_identity: SessionIdentity | None, cancellation: threading.Event) -> SessionPage:
    """Return exact matching counts and one bounded page with literal AND filters.

    Selection is capture/scope bound and does not alter filtering. An unmatched
    selection has no matching page. Empty results have page 1 and page_count 0;
    requests beyond the final matching page clamp to that final page. Cancelled
    operations produce no partial page or counts.
    """
    _check_cancelled(cancellation)
    normalized = _normalized_query(query)
    if selected_identity is not None:
        _validate_identity(selected_identity)
    selected = selected_identity.scope_sha256 if selected_identity is not None and selected_identity.capture_sha256 == index.capture_sha256 else None
    matching_count = 0
    selected_page: int | None = None
    requested: list[SessionRecord] = []
    last: list[SessionRecord] = []
    start = (normalized.page_number - 1) * normalized.page_size
    stop = start + normalized.page_size
    for position, session in enumerate(index.sessions):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        if not _matches(session, normalized):
            continue
        if matching_count % normalized.page_size == 0:
            last.clear()
        last.append(session)
        if start <= matching_count < stop:
            requested.append(session)
        if session.identity.scope_sha256 == selected:
            selected_page = matching_count // normalized.page_size + 1
        matching_count += 1
    _check_cancelled(cancellation)
    page_count = (matching_count + normalized.page_size - 1) // normalized.page_size
    page_number = min(normalized.page_number, page_count) if page_count else 1
    records = requested if page_number == normalized.page_number else last
    return SessionPage(index.capture_sha256, len(index.sessions), matching_count, page_count, page_number, normalized.page_size, tuple(records), selected_page)
