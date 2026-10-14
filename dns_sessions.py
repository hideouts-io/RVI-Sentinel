"""Conservative, passive DNS candidates for scoped saved-file sessions.

Only a captured, decoder-linked unicast question and positive answer can create
a candidate. Exact client address and interface scope must agree; only original
member frames observed within the answer/CNAME TTL window are associated. This
does not authenticate DNS, identify the requesting application, establish name
use, or associate names using flattened fields, PTR, SNI or multicast traffic.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from threading import Event
from typing import Literal

from captured_dns import DNS_MAX_MESSAGES, CapturedDnsEvidence, CapturedDnsMessage, DnsProtocol, DnsQuestion, DnsResourceRecord
from packet_models import InterfaceMetadata, PacketRecord, PacketTimestamp, ProcessMetadata
from packet_sessions import SessionIdentity, SessionIndex, SessionRecord, session_for_identity
from packet_timeline import PAGE_SIZES, PacketIdentity, packet_for_identity

ProcessRelation = Literal["same", "different", "unknown"]
_DnsQueryKey = tuple[int, DnsProtocol, int, tuple[DnsQuestion, ...]]
MAX_DNS_ASSOCIATIONS = 200_000
MAX_DNS_ASSOCIATION_BYTES = 64 * 1024 * 1024
MAX_DNS_CANDIDATE_CHECKS = 2_000_000
MAX_CNAME_HOPS = 16


class DnsSessionValidationError(ValueError):
    """DNS association evidence, query or retained work exceeds its contract."""


class DnsSessionCancelled(RuntimeError):
    """No partial DNS association index or page is published on cancellation."""


@dataclass(frozen=True, slots=True)
class DnsAssociationIdentity:
    capture_sha256: str
    association_sha256: str


@dataclass(frozen=True, slots=True)
class DnsSessionAssociation:
    identity: DnsAssociationIdentity
    session_identity: SessionIdentity
    query_frame: int
    response_frame: int
    message_index: int
    question_name: str
    answer_address: str
    record_ordinals: tuple[int, ...]
    ttl_seconds: int
    response_timestamp: PacketTimestamp
    expires_at_epoch: str
    matching_frames: tuple[int, ...]
    process_relation: ProcessRelation
    ttl_expires_at_epoch: str
    superseded_by_frame: int | None
    superseded_by_message_index: int | None


@dataclass(frozen=True, slots=True)
class DnsDiagnostic:
    frame_number: int
    message_index: int
    reason: str


@dataclass(frozen=True, slots=True)
class DnsSessionIndex:
    capture_sha256: str
    session_index: SessionIndex
    dns_evidence: CapturedDnsEvidence
    associations: tuple[DnsSessionAssociation, ...]
    diagnostics: tuple[DnsDiagnostic, ...]
    association_keys: tuple[str, ...]
    association_positions: tuple[int, ...]
    session_keys: tuple[str, ...]
    session_counts: tuple[int, ...]
    message_frames: tuple[int, ...]
    message_positions: tuple[int, ...]
    diagnostic_frames: tuple[int, ...]
    diagnostic_positions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DnsQuery:
    search: str
    session_identity: SessionIdentity | None
    page_number: int
    page_size: int


@dataclass(frozen=True, slots=True)
class DnsAssociationPage:
    capture_sha256: str
    total_count: int
    matching_count: int
    page_count: int
    page_number: int
    page_size: int
    associations: tuple[DnsSessionAssociation, ...]
    selected_match_page: int | None


@dataclass(frozen=True, slots=True)
class _AnswerPath:
    address: str
    ordinals: tuple[int, ...]
    ttl_seconds: int


@dataclass(frozen=True, slots=True)
class _DnsEvent:
    message: CapturedDnsMessage
    packet: PacketRecord


@dataclass(frozen=True, slots=True)
class _DnsEventLookup:
    orders: tuple[tuple[int, int, int], ...]
    events: tuple[_DnsEvent, ...]


def _check_cancelled(cancellation: Event) -> None:
    if cancellation.is_set():
        raise DnsSessionCancelled("Passive DNS correlation was cancelled; completed evidence is unchanged.")


def _digest(value: str) -> None:
    if type(value) is not str or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise DnsSessionValidationError("DNS navigation requires a lowercase capture-bound SHA-256 identity.")


def _interface(packet: PacketRecord) -> InterfaceMetadata:
    return InterfaceMetadata(packet.interface.state, tuple(sorted(packet.interface.labels, key=lambda label: (label.source, label.name))))


def _process(metadata: ProcessMetadata) -> ProcessMetadata:
    return ProcessMetadata(metadata.state, tuple(sorted(metadata.labels, key=lambda label: (label.source, label.pid or 0, label.name or ""))))


def _process_relation(packet: PacketRecord, session: SessionRecord) -> ProcessRelation:
    contexts = (packet.process, packet.effective_process, session.scope.process, session.scope.effective_process)
    pairs = ((packet.process, session.scope.process), (packet.effective_process, session.scope.effective_process))
    if any(first.state == "recorded" and second.state == "recorded" and _process(first) != second for first, second in pairs):
        return "different"
    if any(metadata.state != "recorded" for metadata in contexts):
        return "unknown"
    return "same" if _process(packet.process) == session.scope.process and _process(packet.effective_process) == session.scope.effective_process else "different"


def _nanoseconds(timestamp: PacketTimestamp) -> int:
    return timestamp.seconds * 1_000_000_000 + timestamp.nanoseconds


def _expiry_epoch(timestamp: PacketTimestamp, ttl: int) -> str:
    seconds, fraction = divmod(_nanoseconds(timestamp) + ttl * 1_000_000_000, 1_000_000_000)
    if seconds < 0 and fraction:
        return f"-{abs(seconds + 1)}.{1_000_000_000 - fraction:09d}"
    return f"{seconds}.{fraction:09d}"


def _context_reason(message: CapturedDnsMessage, packet: PacketRecord) -> str | None:
    if message.protocol != "dns":
        return "multicast_or_local_name_protocol"
    if not message.is_response:
        return "question_observation"
    if message.opcode != 0:
        return "unsupported_opcode"
    if message.is_truncated:
        return "truncated_response"
    if message.response_to_frame is None:
        return "unlinked_response"
    if len(message.questions) != 1:
        return "ambiguous_question_count"
    question = message.questions[0]
    if question.record_class != 1 or question.record_type not in (1, 28):
        return "unsupported_question"
    if packet.transport not in ("tcp", "udp") or packet.source_port != 53 or packet.destination_port is None or packet.source_address is None or packet.destination_address is None or packet.stream is None:
        return "incomplete_or_nonstandard_dns_transport"
    if ipaddress.ip_address(packet.source_address).is_multicast or ipaddress.ip_address(packet.destination_address).is_multicast:
        return "multicast_dns_transport"
    if any(metadata.state == "conflict" for metadata in (packet.process, packet.effective_process, packet.interface, packet.direction)):
        return "conflicting_response_scope"
    return None


def _response_reason(message: CapturedDnsMessage, packet: PacketRecord) -> str | None:
    reason = _context_reason(message, packet)
    if reason is not None:
        return reason
    return "non_success_response" if message.response_code != 0 else None


def _event_order(event: _DnsEvent) -> tuple[int, int, int]:
    return _nanoseconds(event.packet.timestamp), event.packet.frame_number, event.message.message_index


def _query_links(evidence: CapturedDnsEvidence, cancellation: Event) -> dict[_DnsQueryKey, CapturedDnsMessage | None]:
    """Index unique eligible questions once, retaining ambiguity without rescanning frames.

    Values reference the immutable message collection. Multiple eligible
    questions with the same exact key remain ambiguous regardless of order.
    The shared decoded-message ceiling also bounds this temporary lookup.
    """
    _check_cancelled(cancellation)
    if len(evidence.messages) > DNS_MAX_MESSAGES:
        raise DnsSessionValidationError("DNS query link indexing exceeds the 100000-message ceiling. Narrow the capture.")
    result: dict[_DnsQueryKey, CapturedDnsMessage | None] = {}
    for message in evidence.messages:
        _check_cancelled(cancellation)
        if message.is_response or message.opcode != 0 or message.is_truncated or message.response_code != 0:
            continue
        key = (message.frame_number, message.protocol, message.transaction_id, message.questions)
        result[key] = None if key in result else message
    _check_cancelled(cancellation)
    return result


def _validity_events(session_index: SessionIndex, query_links: dict[_DnsQueryKey, CapturedDnsMessage | None], evidence: CapturedDnsEvidence, cancellation: Event) -> dict[tuple[str, InterfaceMetadata, str, int], _DnsEventLookup]:
    """Index later linked observations that conservatively end earlier candidates.

    NXDOMAIN invalidates the questioned name for all address types. Successful
    replies, including NODATA, replace the queried type; answer owners also end
    earlier dependencies of the same type. A CNAME change also ends previous
    address dependencies, and an address answer ends a previous CNAME edge at
    that owner. Independent A and AAAA RRsets remain separate. These event keys
    describe affected dependencies, without changing any recorded wire type or
    asserting cache state or resolver trust.
    """
    grouped: dict[tuple[str, InterfaceMetadata, str, int], list[_DnsEvent]] = {}
    for message in evidence.messages:
        _check_cancelled(cancellation)
        packet = packet_for_identity(session_index.packet_index, PacketIdentity(session_index.capture_sha256, message.frame_number))
        if packet is None or message.response_code not in (0, 3) or _context_reason(message, packet) is not None:
            continue
        if _query_reason(message, packet, query_links, session_index) is not None:
            continue
        if packet.destination_address is None:
            raise DnsSessionValidationError("Accepted DNS event has no validated client endpoint.")
        question = message.questions[0]
        dependencies = {(question.name, 0 if message.response_code == 3 else question.record_type)}
        if message.response_code == 0:
            for record in message.answers:
                if record.owner is None or record.record_class != 1 or record.record_type not in (1, 5, 28):
                    continue
                dependencies.add((record.owner, record.record_type))
                if record.record_type == 5:
                    dependencies.update(((record.owner, 1), (record.owner, 28)))
                else:
                    dependencies.add((record.owner, 5))
        for name, record_type in dependencies:
            grouped.setdefault((packet.destination_address, _interface(packet), name, record_type), []).append(_DnsEvent(message, packet))
    result: dict[tuple[str, InterfaceMetadata, str, int], _DnsEventLookup] = {}
    for key, events in grouped.items():
        _check_cancelled(cancellation)
        ordered = tuple(sorted(events, key=_event_order))
        result[key] = _DnsEventLookup(tuple(_event_order(event) for event in ordered), ordered)
    return result


def _superseding_event(message: CapturedDnsMessage, packet: PacketRecord, path: _AnswerPath, events: dict[tuple[str, InterfaceMetadata, str, int], _DnsEventLookup]) -> _DnsEvent | None:
    dependencies = {(message.questions[0].name, message.questions[0].record_type)}
    for ordinal in path.ordinals:
        record = message.answers[ordinal - 1]
        if record.owner is None:
            raise DnsSessionValidationError("A validated DNS answer path requires a recorded owner.")
        dependencies.add((record.owner, record.record_type))
    current_order = (_nanoseconds(packet.timestamp), packet.frame_number, message.message_index)
    candidates: list[_DnsEvent] = []
    for name, record_type in dependencies:
        for query_type in (record_type, 0):
            lookup = events.get((packet.destination_address, _interface(packet), name, query_type))
            if lookup is None:
                continue
            position = bisect_right(lookup.orders, current_order)
            if position < len(lookup.events):
                candidates.append(lookup.events[position])
    return min(candidates, key=_event_order) if candidates else None


def _query_reason(message: CapturedDnsMessage, response: PacketRecord, query_links: dict[_DnsQueryKey, CapturedDnsMessage | None], session_index: SessionIndex) -> str | None:
    if message.response_to_frame is None:
        return "missing_or_ambiguous_linked_question"
    linked = query_links.get((message.response_to_frame, message.protocol, message.transaction_id, message.questions))
    if linked is None:
        return "missing_or_ambiguous_linked_question"
    query = packet_for_identity(session_index.packet_index, PacketIdentity(session_index.capture_sha256, linked.frame_number))
    if query is None or query.frame_number >= response.frame_number or _nanoseconds(query.timestamp) > _nanoseconds(response.timestamp):
        return "inconsistent_question_order"
    if (query.transport, query.stream, query.source_address, query.destination_address, query.source_port, query.destination_port) != (response.transport, response.stream, response.destination_address, response.source_address, response.destination_port, response.source_port):
        return "question_response_transport_mismatch"
    if any(metadata.state == "conflict" for metadata in (query.process, query.effective_process, query.interface, query.direction)) or _interface(query) != _interface(response):
        return "question_response_scope_mismatch"
    return None


def _answer_paths(message: CapturedDnsMessage) -> tuple[tuple[_AnswerPath, ...], str | None]:
    """Follow one unambiguous answer-section CNAME chain with RRset minimum TTL.

    Authority/additional records are absent from this typed answer collection.
    Each ordinal is one-based within the decoder's ordered answer records.
    Unsupported records stay observed, but never provide a name/address edge.
    """
    name = message.questions[0].name
    visited: set[str] = set()
    chain: list[int] = []
    chain_ttls: list[int] = []
    for hop in range(MAX_CNAME_HOPS + 1):
        if name in visited:
            return (), "cyclic_cname"
        visited.add(name)
        records: tuple[tuple[int, DnsResourceRecord], ...] = tuple((position + 1, record) for position, record in enumerate(message.answers) if record.owner == name and record.record_class == 1)
        aliases = tuple((position, record) for position, record in records if record.record_type == 5)
        addresses = tuple((position, record) for position, record in records if record.record_type in (1, 28))
        if aliases:
            targets = {record.value for _, record in aliases}
            if len(targets) != 1 or None in targets or addresses:
                return (), "ambiguous_cname"
            if hop == MAX_CNAME_HOPS:
                return (), "cname_hop_limit"
            target = aliases[0][1].value
            if target is None:
                raise DnsSessionValidationError("A validated CNAME record has no target.")
            chain.extend(position for position, _ in aliases)
            chain_ttls.extend(record.ttl_seconds for _, record in aliases)
            name = target
            continue
        terminals = tuple((position, record) for position, record in addresses if record.record_type == message.questions[0].record_type)
        if not terminals:
            return (), "no_supported_answer_path"
        ttl = min(chain_ttls + [record.ttl_seconds for _, record in terminals])
        if ttl == 0 or any(value > 2**31 - 1 for value in chain_ttls + [record.ttl_seconds for _, record in terminals]):
            return (), "zero_or_invalid_ttl"
        paths: list[_AnswerPath] = []
        for address in sorted({record.value for _, record in terminals if record.value is not None}):
            ordinals = tuple(chain + [position for position, record in terminals if record.value == address])
            paths.append(_AnswerPath(address, ordinals, ttl))
        return tuple(paths), None
    raise DnsSessionValidationError("DNS CNAME traversal did not reach a bounded result.")


def _association_identity(capture_sha256: str, session: SessionIdentity, message: CapturedDnsMessage, query_frame: int, path: _AnswerPath) -> DnsAssociationIdentity:
    payload: tuple[int | str | tuple[int, ...], ...] = (1, capture_sha256, session.scope_sha256, query_frame, message.frame_number, message.message_index, message.questions[0].name, path.address, path.ordinals, path.ttl_seconds)
    return DnsAssociationIdentity(capture_sha256, hashlib.sha256(json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest())


def build_dns_session_index(session_index: SessionIndex, dns_evidence: CapturedDnsEvidence, cancellation: Event) -> DnsSessionIndex:
    """Build bounded candidate associations without altering saved evidence.

    Repeated/shared-address names remain separate candidates. A session may
    contain earlier/later frames; only matching_frames falls inside this DNS
    response's exact half-open TTL window. Resource limits fail explicitly.
    """
    _check_cancelled(cancellation)
    if not isinstance(session_index, SessionIndex) or not isinstance(dns_evidence, CapturedDnsEvidence) or session_index.capture_sha256 != dns_evidence.capture_sha256:
        raise DnsSessionValidationError("DNS messages and sessions must belong to the same validated capture artifact.")
    _digest(session_index.capture_sha256)
    query_links = _query_links(dns_evidence, cancellation)
    events = _validity_events(session_index, query_links, dns_evidence, cancellation)
    candidates: dict[tuple[str, str, InterfaceMetadata], list[SessionRecord]] = {}
    for position, session in enumerate(session_index.sessions):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        first, second = session.scope.endpoint_a.address, session.scope.endpoint_b.address
        candidates.setdefault((first, second, session.scope.interface), []).append(session)
        if first != second:
            candidates.setdefault((second, first, session.scope.interface), []).append(session)
    associations: list[DnsSessionAssociation] = []
    diagnostics: list[DnsDiagnostic] = []
    work = 0
    estimated_bytes = 0
    for position, message in enumerate(dns_evidence.messages):
        _check_cancelled(cancellation)
        packet = packet_for_identity(session_index.packet_index, PacketIdentity(session_index.capture_sha256, message.frame_number))
        if packet is None:
            raise DnsSessionValidationError("Structured DNS references a frame absent from the original packet index.")
        reason = _response_reason(message, packet)
        if reason is None:
            reason = _query_reason(message, packet, query_links, session_index)
        paths: tuple[_AnswerPath, ...] = ()
        if reason is None:
            paths, reason = _answer_paths(message)
        if reason is not None:
            diagnostics.append(DnsDiagnostic(message.frame_number, message.message_index, reason))
            continue
        response_ns = _nanoseconds(packet.timestamp)
        count_before = len(associations)
        for path in paths:
            until_ns = response_ns + path.ttl_seconds * 1_000_000_000
            until_order = (until_ns, 0)
            invalidator = _superseding_event(message, packet, path, events)
            if invalidator is not None and (_nanoseconds(invalidator.packet.timestamp), invalidator.packet.frame_number) < until_order:
                until_order = (_nanoseconds(invalidator.packet.timestamp), invalidator.packet.frame_number)
            else:
                invalidator = None
            if packet.destination_address is None or message.response_to_frame is None:
                raise DnsSessionValidationError("Eligible DNS response has incomplete validated client/query evidence.")
            for session in candidates.get((packet.destination_address, path.address, _interface(packet)), ()):
                matching: list[int] = []
                for frame in session.member_frames:
                    work += 1
                    if work > MAX_DNS_CANDIDATE_CHECKS:
                        raise DnsSessionValidationError("DNS correlation exceeds 2000000 candidate frame checks. Narrow the capture before correlating it.")
                    if work % 256 == 0:
                        _check_cancelled(cancellation)
                    if frame in (message.response_to_frame, message.frame_number):
                        continue
                    member = packet_for_identity(session_index.packet_index, PacketIdentity(session_index.capture_sha256, frame))
                    if member is None:
                        raise DnsSessionValidationError("A DNS candidate session references unavailable packet evidence.")
                    member_ns = _nanoseconds(member.timestamp)
                    if (response_ns, packet.frame_number) <= (member_ns, frame) < until_order:
                        matching.append(frame)
                if not matching:
                    continue
                estimated_bytes += 1024 + len(message.questions[0].name.encode("utf-8")) + 16 * (len(matching) + len(path.ordinals))
                if len(associations) >= MAX_DNS_ASSOCIATIONS or estimated_bytes > MAX_DNS_ASSOCIATION_BYTES:
                    raise DnsSessionValidationError("DNS associations exceed the 200000-record or 64 MiB estimated storage ceiling. Narrow the capture.")
                ttl_expiry = _expiry_epoch(packet.timestamp, path.ttl_seconds)
                associations.append(DnsSessionAssociation(
                    identity=_association_identity(session_index.capture_sha256, session.identity, message, message.response_to_frame, path),
                    session_identity=session.identity,
                    query_frame=message.response_to_frame,
                    response_frame=message.frame_number,
                    message_index=message.message_index,
                    question_name=message.questions[0].name,
                    answer_address=path.address,
                    record_ordinals=path.ordinals,
                    ttl_seconds=path.ttl_seconds,
                    response_timestamp=packet.timestamp,
                    expires_at_epoch=invalidator.packet.timestamp.epoch if invalidator is not None else ttl_expiry,
                    matching_frames=tuple(matching),
                    process_relation=_process_relation(packet, session),
                    ttl_expires_at_epoch=ttl_expiry,
                    superseded_by_frame=invalidator.packet.frame_number if invalidator is not None else None,
                    superseded_by_message_index=invalidator.message.message_index if invalidator is not None else None,
                ))
        if len(associations) == count_before:
            diagnostics.append(DnsDiagnostic(message.frame_number, message.message_index, "no_matching_scoped_member_in_ttl_window"))
    _check_cancelled(cancellation)
    associations.sort(key=lambda item: (item.response_timestamp.seconds, item.response_timestamp.nanoseconds, item.response_frame, item.message_index, item.identity.association_sha256))
    keys = sorted((item.identity.association_sha256, position) for position, item in enumerate(associations))
    if any(keys[position][0] == keys[position - 1][0] for position in range(1, len(keys))):
        raise DnsSessionValidationError("DNS candidates produced duplicate stable association identities.")
    counts: dict[str, int] = {}
    for association in associations:
        counts[association.session_identity.scope_sha256] = counts.get(association.session_identity.scope_sha256, 0) + 1
    session_keys = tuple(sorted(counts))
    messages = sorted((message.frame_number, position) for position, message in enumerate(dns_evidence.messages))
    reasons = sorted((diagnostic.frame_number, position) for position, diagnostic in enumerate(diagnostics))
    _check_cancelled(cancellation)
    return DnsSessionIndex(session_index.capture_sha256, session_index, dns_evidence, tuple(associations), tuple(diagnostics), tuple(key for key, _ in keys), tuple(position for _, position in keys), session_keys, tuple(counts[key] for key in session_keys), tuple(frame for frame, _ in messages), tuple(position for _, position in messages), tuple(frame for frame, _ in reasons), tuple(position for _, position in reasons))


def dns_association_for_identity(index: DnsSessionIndex, identity: DnsAssociationIdentity) -> DnsSessionAssociation | None:
    if not isinstance(identity, DnsAssociationIdentity):
        raise DnsSessionValidationError("DNS association navigation requires a typed identity.")
    _digest(identity.capture_sha256)
    _digest(identity.association_sha256)
    if identity.capture_sha256 != index.capture_sha256:
        return None
    position = bisect_left(index.association_keys, identity.association_sha256)
    return None if position == len(index.association_keys) or index.association_keys[position] != identity.association_sha256 else index.associations[index.association_positions[position]]


def observed_dns_frames(index: DnsSessionIndex) -> tuple[int, ...]:
    return tuple(sorted({message.frame_number for message in index.dns_evidence.messages}))


def dns_association_count_for_session(index: DnsSessionIndex, identity: SessionIdentity) -> int:
    if session_for_identity(index.session_index, identity) is None:
        return 0
    position = bisect_left(index.session_keys, identity.scope_sha256)
    return 0 if position == len(index.session_keys) or index.session_keys[position] != identity.scope_sha256 else index.session_counts[position]


def dns_messages_for_frame(index: DnsSessionIndex, identity: PacketIdentity) -> tuple[CapturedDnsMessage, ...]:
    if packet_for_identity(index.session_index.packet_index, identity) is None:
        return ()
    start, stop = bisect_left(index.message_frames, identity.frame_number), bisect_right(index.message_frames, identity.frame_number)
    return tuple(index.dns_evidence.messages[index.message_positions[position]] for position in range(start, stop))


def dns_diagnostics_for_frame(index: DnsSessionIndex, identity: PacketIdentity) -> tuple[DnsDiagnostic, ...]:
    if packet_for_identity(index.session_index.packet_index, identity) is None:
        return ()
    start, stop = bisect_left(index.diagnostic_frames, identity.frame_number), bisect_right(index.diagnostic_frames, identity.frame_number)
    return tuple(index.diagnostics[index.diagnostic_positions[position]] for position in range(start, stop))


def validate_dns_query(query: DnsQuery) -> None:
    if not isinstance(query, DnsQuery) or type(query.search) is not str or len(query.search) > 512 or any(ord(character) < 32 or ord(character) == 127 for character in query.search):
        raise DnsSessionValidationError("DNS search requires at most 512 literal characters without control characters.")
    if query.session_identity is not None:
        if not isinstance(query.session_identity, SessionIdentity):
            raise DnsSessionValidationError("DNS session filter requires a typed session identity.")
        _digest(query.session_identity.capture_sha256)
        _digest(query.session_identity.scope_sha256)
    if type(query.page_number) is not int or not 1 <= query.page_number <= 2**31 - 1 or type(query.page_size) is not int or query.page_size not in PAGE_SIZES:
        raise DnsSessionValidationError("DNS pages require a positive bounded page number and 100, 250 or 500 rows.")


def query_dns_associations(index: DnsSessionIndex, query: DnsQuery, selected_identity: DnsAssociationIdentity | None, cancellation: Event) -> DnsAssociationPage:
    _check_cancelled(cancellation)
    validate_dns_query(query)
    if query.session_identity is not None and session_for_identity(index.session_index, query.session_identity) is None:
        raise DnsSessionValidationError("DNS session filter belongs to an unavailable capture or scope.")
    if selected_identity is not None:
        dns_association_for_identity(index, selected_identity)
    start, stop = (query.page_number - 1) * query.page_size, query.page_number * query.page_size
    requested: list[DnsSessionAssociation] = []
    last: list[DnsSessionAssociation] = []
    count = 0
    selected_page: int | None = None
    search = query.search.casefold()
    for position, item in enumerate(index.associations):
        if position % 256 == 0:
            _check_cancelled(cancellation)
        if query.session_identity is not None and item.session_identity != query.session_identity:
            continue
        terms = (item.question_name, item.answer_address, str(item.query_frame), str(item.response_frame), item.process_relation, item.identity.association_sha256, item.session_identity.scope_sha256)
        if search and not any(search in term.casefold() for term in terms):
            continue
        if count % query.page_size == 0:
            last.clear()
        last.append(item)
        if start <= count < stop:
            requested.append(item)
        if item.identity == selected_identity:
            selected_page = count // query.page_size + 1
        count += 1
    _check_cancelled(cancellation)
    pages = (count + query.page_size - 1) // query.page_size
    page_number = min(query.page_number, pages) if pages else 1
    return DnsAssociationPage(index.capture_sha256, len(index.associations), count, pages, page_number, query.page_size, tuple(requested if query.page_number == page_number else last), selected_page)
