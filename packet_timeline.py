"""Pure bounded packet queries over immutable, already validated saved evidence.

The timeline sorts exact decoded epochs, then original frame numbers. Filters
never reattribute conflicting metadata or infer an endpoint pairing. Only page
references and small frame-position indexes are retained; recorded payload values
remain in the original immutable PacketRecord objects.
"""

from __future__ import annotations

import ipaddress
import threading
from bisect import bisect_left
from dataclasses import dataclass
from typing import Iterator, Literal

from packet_models import PacketRecord, packet_values

ProcessStateFilter = Literal["all", "recorded", "unknown", "conflict"]
InterfaceStateFilter = Literal["all", "recorded", "unknown", "conflict"]
DirectionFilter = Literal["all", "inbound", "outbound", "unknown", "conflict"]
PAGE_SIZES = (100, 250, 500)
MAX_QUERY_TEXT = 512


class PacketQueryValidationError(ValueError):
    """A packet identity, timeline input, or filter violates its contract."""


class PacketQueryCancelled(RuntimeError):
    """The caller cancelled indexing or filtering before a result was returned."""


@dataclass(frozen=True, slots=True)
class PacketIdentity:
    capture_sha256: str
    frame_number: int


@dataclass(frozen=True, slots=True)
class PacketIndex:
    capture_sha256: str
    packets: tuple[PacketRecord, ...]
    frame_numbers: tuple[int, ...]
    frame_positions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PacketQuery:
    search: str
    endpoint: str
    port: int | None
    protocol: str
    process_text: str
    process_state: ProcessStateFilter
    interface_text: str
    interface_state: InterfaceStateFilter
    direction: DirectionFilter
    page_number: int
    page_size: int


@dataclass(frozen=True, slots=True)
class PacketPage:
    capture_sha256: str
    total_count: int
    matching_count: int
    page_count: int
    page_number: int
    page_size: int
    packets: tuple[PacketRecord, ...]
    selected_match_page: int | None


def _check_cancelled(cancellation: threading.Event) -> None:
    if cancellation.is_set():
        raise PacketQueryCancelled("Packet timeline indexing or filtering was cancelled.")


def _validate_sha256(value: str) -> None:
    if type(value) is not str or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise PacketQueryValidationError("Packet evidence identity requires a lowercase 64-character SHA-256.")


def _validate_identity(identity: PacketIdentity) -> None:
    _validate_sha256(identity.capture_sha256)
    _validate_frame_number(identity.frame_number)


def _validate_frame_number(frame_number: int) -> None:
    if type(frame_number) is not int or not 1 <= frame_number <= 2**64 - 1:
        raise PacketQueryValidationError("Packet identity requires an original frame number from 1 through 18446744073709551615.")


def build_packet_index(capture_sha256: str, packets: tuple[PacketRecord, ...], cancellation: threading.Event) -> PacketIndex:
    """Index validated records by exact epoch and frame without copying evidence.

    Frame numbers need not arrive in time order, but must be unique positive
    integers. The secondary immutable index makes identity lookup logarithmic.
    This does not validate report provenance: the report boundary owns that check.
    """
    _check_cancelled(cancellation)
    _validate_sha256(capture_sha256)
    if type(packets) is not tuple:
        raise PacketQueryValidationError("Packet index input must be an immutable tuple of validated records.")
    frames: set[int] = set()
    for position, packet in enumerate(packets):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        if not isinstance(packet, PacketRecord):
            raise PacketQueryValidationError("Packet index input contains a value that is not a validated packet record.")
        _validate_frame_number(packet.frame_number)
        if packet.frame_number in frames:
            raise PacketQueryValidationError("Packet index input contains duplicate original frame numbers.")
        frames.add(packet.frame_number)
        if type(packet.timestamp.seconds) is not int or type(packet.timestamp.nanoseconds) is not int or not 0 <= packet.timestamp.nanoseconds < 1_000_000_000:
            raise PacketQueryValidationError("Packet index requires validated integer seconds and nanoseconds.")
    frames.clear()
    _check_cancelled(cancellation)
    ordered = tuple(sorted(packets, key=lambda packet: (packet.timestamp.seconds, packet.timestamp.nanoseconds, packet.frame_number)))
    _check_cancelled(cancellation)
    positions: list[tuple[int, int]] = []
    for position, packet in enumerate(ordered):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        positions.append((packet.frame_number, position))
    positions.sort()
    _check_cancelled(cancellation)
    return PacketIndex(capture_sha256, ordered, tuple(frame for frame, _ in positions), tuple(position for _, position in positions))


def packet_for_identity(index: PacketIndex, identity: PacketIdentity) -> PacketRecord | None:
    """Return the original evidence object only when both capture and frame match."""
    _validate_identity(identity)
    if identity.capture_sha256 != index.capture_sha256:
        return None
    position = bisect_left(index.frame_numbers, identity.frame_number)
    if position == len(index.frame_numbers) or index.frame_numbers[position] != identity.frame_number:
        return None
    return index.packets[index.frame_positions[position]]


def restrict_packet_index(index: PacketIndex, frame_numbers: tuple[int, ...], cancellation: threading.Event) -> PacketIndex:
    """Build a member-only view from exact original frame identities.

    Every requested frame must exist in this artifact exactly once. The new
    index contains references to the original immutable records; no payload or
    endpoint/transport interpretation is changed by a navigation constraint.
    """
    _check_cancelled(cancellation)
    if type(frame_numbers) is not tuple:
        raise PacketQueryValidationError("Packet scope requires an immutable tuple of frame identities.")
    frames: set[int] = set()
    records: list[PacketRecord] = []
    for position, frame in enumerate(frame_numbers):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        _validate_frame_number(frame)
        if frame in frames:
            raise PacketQueryValidationError("Packet scope repeats an original frame identity.")
        frames.add(frame)
        packet = packet_for_identity(index, PacketIdentity(index.capture_sha256, frame))
        if packet is None:
            raise PacketQueryValidationError("Packet scope contains a frame outside the current capture artifact.")
        records.append(packet)
    return build_packet_index(index.capture_sha256, tuple(records), cancellation)


def validate_packet_query(query: PacketQuery) -> None:
    """Validate filter and page inputs without scanning any retained evidence."""
    if not isinstance(query, PacketQuery):
        raise PacketQueryValidationError("Packet filters require a typed PacketQuery.")
    _normalized_query(query)


def _normalized_query(query: PacketQuery) -> PacketQuery:
    for name, value in (("Search", query.search), ("Endpoint", query.endpoint), ("Protocol", query.protocol), ("Process", query.process_text), ("Interface", query.interface_text)):
        if type(value) is not str or len(value) > MAX_QUERY_TEXT or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise PacketQueryValidationError(f"{name} filter requires at most 512 characters without control characters.")
    if query.port is not None and (type(query.port) is not int or not 0 <= query.port <= 65_535):
        raise PacketQueryValidationError("Port filter requires an integer from 0 through 65535.")
    if query.process_state not in ("all", "recorded", "unknown", "conflict"):
        raise PacketQueryValidationError("Process state filter must be all, recorded, unknown, or conflict.")
    if query.interface_state not in ("all", "recorded", "unknown", "conflict"):
        raise PacketQueryValidationError("Interface state filter must be all, recorded, unknown, or conflict.")
    if query.direction not in ("all", "inbound", "outbound", "unknown", "conflict"):
        raise PacketQueryValidationError("Direction filter must be all, inbound, outbound, unknown, or conflict.")
    if type(query.page_number) is not int or not 1 <= query.page_number <= 2**31 - 1:
        raise PacketQueryValidationError("Packet page number requires a positive integer no larger than 2147483647.")
    if type(query.page_size) is not int or query.page_size not in PAGE_SIZES:
        raise PacketQueryValidationError("Packet page size must be 100, 250, or 500.")
    endpoint = query.endpoint.strip()
    if endpoint:
        if "%" in endpoint:
            raise PacketQueryValidationError("Endpoint filter requires an IPv4 or IPv6 address without a zone suffix.")
        try:
            endpoint = str(ipaddress.ip_address(endpoint))
        except ValueError as error:
            raise PacketQueryValidationError("Endpoint filter requires one complete IPv4 or IPv6 address.") from error
    return PacketQuery(query.search.casefold(), endpoint, query.port, query.protocol.strip().casefold(), query.process_text.casefold(), query.process_state, query.interface_text.casefold(), query.interface_state, query.direction, query.page_number, query.page_size)


def _endpoint_matches(packet: PacketRecord, endpoint: str) -> bool:
    if endpoint in (packet.source_address, packet.destination_address):
        return True
    for field in packet.fields:
        if field.name in ("ip.src", "ip.dst") and endpoint in field.values:
            return True
        if field.name in ("ipv6.src", "ipv6.dst") and any(value == endpoint or str(ipaddress.ip_address(value)) == endpoint for value in field.values):
            return True
    return False


def _process_terms(packet: PacketRecord) -> Iterator[str]:
    for metadata in (packet.process, packet.effective_process):
        for label in metadata.labels:
            yield label.source
            if label.name is not None:
                yield label.name
            if label.pid is not None:
                yield str(label.pid)


def _search_terms(packet: PacketRecord) -> Iterator[str]:
    yield str(packet.frame_number)
    yield packet.timestamp.epoch
    yield str(packet.wire_length)
    if packet.captured_length is not None:
        yield str(packet.captured_length)
    yield from packet.protocol_stack
    for field in packet.fields:
        yield field.name
        yield from field.values
    for address in (packet.source_address, packet.destination_address):
        if address is not None:
            yield address
    for port in (packet.source_port, packet.destination_port):
        if port is not None:
            yield str(port)
    if packet.transport is not None:
        yield packet.transport
    if packet.stream is not None:
        yield str(packet.stream)
    yield from _process_terms(packet)
    yield packet.process.state
    yield packet.effective_process.state
    yield packet.interface.state
    yield packet.direction.state
    for label in packet.interface.labels:
        yield label.source
        yield label.name
    for label in packet.direction.labels:
        yield label.source
        yield label.direction
    yield from packet.diagnostics


def _matches(packet: PacketRecord, query: PacketQuery) -> bool:
    if query.process_state != "all" and packet.process.state != query.process_state:
        return False
    if query.interface_state != "all" and packet.interface.state != query.interface_state:
        return False
    if query.direction == "unknown" and packet.direction.state != "unknown":
        return False
    if query.direction == "conflict" and packet.direction.state != "conflict":
        return False
    if query.direction in ("inbound", "outbound") and (packet.direction.state != "recorded" or not any(label.direction == query.direction for label in packet.direction.labels)):
        return False
    if query.endpoint and not _endpoint_matches(packet, query.endpoint):
        return False
    if query.port is not None and query.port not in (packet.source_port, packet.destination_port) and not any(int(value) == query.port for field in packet.fields if field.name in ("tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport") for value in field.values):
        return False
    if query.protocol and query.protocol not in packet.protocol_stack and not any(value.casefold() == query.protocol for value in packet_values(packet, "_ws.col.protocol")):
        return False
    if query.process_text and not any(query.process_text in value.casefold() for value in _process_terms(packet)):
        return False
    if query.interface_text and not any(query.interface_text in value.casefold() for label in packet.interface.labels for value in (label.name, label.source)):
        return False
    return not query.search or any(query.search in value.casefold() for value in _search_terms(packet))


def query_packets(index: PacketIndex, query: PacketQuery, selected_identity: PacketIdentity | None, cancellation: threading.Event) -> PacketPage:
    """Return one bounded page, exact counts, and a selected frame's matching page.

    All filters are combined with AND. Text search is literal Unicode casefolded
    substring matching, with no regular expressions or implicit token operators.
    Endpoint/port filters include every recorded network/transport occurrence,
    even where layers are ambiguous. Protocol matches a complete decoded stack
    token or column value. Process state applies to the regular process metadata;
    process text includes regular and effective labels. Conflicting directions
    match only the conflict filter, never a selected inbound/outbound label.

    Pages are one-based, clamped to the final matching page. Empty matches return
    page 1 and page_count 0. Selection does not change the requested page; callers
    can use selected_match_page to retain a matching selection across new filters.
    Cancellation returns no partial count or page and does not modify the index.
    """
    _check_cancelled(cancellation)
    normalized = _normalized_query(query)
    if selected_identity is not None:
        _validate_identity(selected_identity)
    selected_frame = selected_identity.frame_number if selected_identity is not None and selected_identity.capture_sha256 == index.capture_sha256 else None
    matching_count = 0
    selected_page: int | None = None
    requested_packets: list[PacketRecord] = []
    last_packets: list[PacketRecord] = []
    start = (normalized.page_number - 1) * normalized.page_size
    stop = start + normalized.page_size
    for position, packet in enumerate(index.packets):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        if not _matches(packet, normalized):
            continue
        if matching_count % normalized.page_size == 0:
            last_packets.clear()
        last_packets.append(packet)
        if start <= matching_count < stop:
            requested_packets.append(packet)
        if packet.frame_number == selected_frame:
            selected_page = matching_count // normalized.page_size + 1
        matching_count += 1
    _check_cancelled(cancellation)
    page_count = (matching_count + normalized.page_size - 1) // normalized.page_size
    page_number = min(normalized.page_number, page_count) if page_count else 1
    records = requested_packets if page_number == normalized.page_number else last_packets
    return PacketPage(index.capture_sha256, len(index.packets), matching_count, page_count, page_number, normalized.page_size, tuple(records), selected_page)
