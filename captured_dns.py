"""Typed passive DNS questions and answer records from a bounded decoder tree.

Owner, type, class, TTL and RDATA are consumed from the same answer subtree.
Flattened packet fields never establish these relationships. A frame identifies
where TShark decoded a message, which can include reassembled TCP segments.
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, TypedDict

from packet_models import EPOCH_SYNTAX, PacketRecord, PacketTimestamp, PacketValidationError, decode_packet_timestamp

DNS_MAX_JSON_BYTES = 67_108_864
DNS_MAX_RETAINED_BYTES = 67_108_864
DNS_MAX_DEPTH = 48
DNS_MAX_MESSAGES = 100_000
DNS_MAX_RECORDS = 200_000
DNS_MAX_TEXT_BYTES = 1_024
DNS_PROTOCOLS = ("dns", "mdns", "llmnr")
DnsProtocol = Literal["dns", "mdns", "llmnr"]
DNS_DIGEST = re.compile(r"[0-9a-f]{64}")
DNS_UNSIGNED = re.compile(r"(?:[0-9]+|0x[0-9a-fA-F]+)")
DNS_UTC_TIMESTAMP = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z")


class CapturedDnsValidationError(ValueError):
    """Consumed DNS evidence is malformed, incomplete, or exceeds its limit."""


class CapturedDnsCancelled(CapturedDnsValidationError):
    """Cancelled DNS parsing publishes no partially decoded evidence."""


@dataclass(frozen=True, slots=True)
class DnsQuestion:
    name: str
    record_type: int
    record_class: int


@dataclass(frozen=True, slots=True)
class DnsResourceRecord:
    owner: str | None
    record_type: int
    record_class: int
    ttl_seconds: int
    value: str | None


@dataclass(frozen=True, slots=True)
class CapturedDnsMessage:
    frame_number: int
    message_index: int
    protocol: DnsProtocol
    transaction_id: int
    is_response: bool
    is_truncated: bool
    response_code: int
    questions: tuple[DnsQuestion, ...]
    response_to_frame: int | None
    answers: tuple[DnsResourceRecord, ...]
    opcode: int


@dataclass(frozen=True, slots=True)
class CapturedDnsEvidence:
    capture_sha256: str
    messages: tuple[CapturedDnsMessage, ...]


class DnsQuestionDocument(TypedDict):
    name: str
    record_type: int
    record_class: int


class DnsResourceRecordDocument(TypedDict):
    owner: str | None
    record_type: int
    record_class: int
    ttl_seconds: int
    value: str | None


class DnsMessageDocument(TypedDict):
    frame_number: int
    message_index: int
    protocol: DnsProtocol
    transaction_id: int
    is_response: bool
    is_truncated: bool
    response_code: int
    questions: list[DnsQuestionDocument]
    response_to_frame: int | None
    answers: list[DnsResourceRecordDocument]
    opcode: int


class DnsEvidenceDocument(TypedDict):
    capture_sha256: str
    messages: list[DnsMessageDocument]


def _check_cancelled(cancellation: threading.Event) -> None:
    if cancellation.is_set():
        raise CapturedDnsCancelled("Structured DNS decoding was cancelled; no completed DNS evidence was returned.")


def _dictionary(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CapturedDnsValidationError(f"{label} requires an object.")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise CapturedDnsValidationError(f"{label} requires string keys.")
        result[key] = item
    return result


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise CapturedDnsValidationError(f"{label} requires an array.")
    return list(value)


def _one_or_many(value: object, label: str) -> tuple[dict[str, object], ...]:
    values = _list(value, label) if isinstance(value, list) else [value]
    if not values:
        raise CapturedDnsValidationError(f"{label} cannot contain an empty repeated-node array.")
    return tuple(_dictionary(item, label) for item in values)


def _wire_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CapturedDnsValidationError(f"{label} requires one nonempty scalar string of at most {DNS_MAX_TEXT_BYTES} bytes.")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise CapturedDnsValidationError(f"{label} contains invalid Unicode text.") from error
    if size > DNS_MAX_TEXT_BYTES:
        raise CapturedDnsValidationError(f"{label} exceeds {DNS_MAX_TEXT_BYTES} UTF-8 bytes.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise CapturedDnsValidationError(f"{label} contains a control character.")
    return value


def _wire_unsigned(value: object, maximum: int, label: str) -> int:
    text = _wire_text(value, label)
    if DNS_UNSIGNED.fullmatch(text) is None:
        raise CapturedDnsValidationError(f"{label} requires an unsigned decimal or hexadecimal integer.")
    number = int(text[2:], 16) if text.startswith("0x") else int(text, 10)
    if number > maximum:
        raise CapturedDnsValidationError(f"{label} exceeds its unsigned range.")
    return number


def _wire_boolean(value: object, label: str) -> bool:
    text = _wire_text(value, label)
    if text not in ("0", "1"):
        raise CapturedDnsValidationError(f"{label} requires 0 or 1.")
    return text == "1"


def _dns_name(value: object, label: str) -> str:
    text = _wire_text(value, label)
    if text == ".":
        return text
    normalized = text.lower().removesuffix(".")
    if not normalized or len(normalized.encode("utf-8")) > DNS_MAX_TEXT_BYTES:
        raise CapturedDnsValidationError(f"{label} has an empty normalized DNS name.")
    return normalized


def _address(value: object, version: int, label: str) -> str:
    text = _wire_text(value, label)
    if "%" in text:
        raise CapturedDnsValidationError(f"{label} cannot contain an address zone identifier.")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as error:
        raise CapturedDnsValidationError(f"{label} requires a valid IPv{version} address.") from error
    if address.version != version:
        raise CapturedDnsValidationError(f"{label} address family conflicts with its resource-record type.")
    return str(address)


def _wire_timestamp(value: object) -> PacketTimestamp:
    """Normalize TShark's decimal field or JSON UTC instant without float rounding."""
    text = _wire_text(value, "frame.time_epoch")
    if EPOCH_SYNTAX.fullmatch(text) is not None:
        try:
            return decode_packet_timestamp(text)
        except PacketValidationError as error:
            raise CapturedDnsValidationError("Structured DNS frame timestamp is outside its epoch range.") from error
    match = DNS_UTC_TIMESTAMP.fullmatch(text)
    if match is None:
        raise CapturedDnsValidationError("Structured DNS JSON frame.time_epoch requires decimal epoch or exact UTC ISO timestamp syntax.")
    components = tuple(int(match.group(index)) for index in range(1, 7))
    try:
        instant = datetime(*components, 0, tzinfo=timezone.utc)
    except ValueError as error:
        raise CapturedDnsValidationError("Structured DNS JSON UTC timestamp has an invalid calendar instant.") from error
    origin = datetime(1970, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    delta = instant - origin
    seconds = delta.days * 86_400 + delta.seconds
    nanoseconds = int((match.group(7) or "0").ljust(9, "0"))
    return PacketTimestamp(text, seconds, nanoseconds)


def _wire_group(message: dict[str, object], key: str) -> tuple[dict[str, object], ...]:
    if key not in message:
        return ()
    group = _dictionary(message[key], key)
    return tuple(record for value in group.values() for record in _one_or_many(value, key))


def _wire_question(question: dict[str, object]) -> DnsQuestion:
    return DnsQuestion(
        _dns_name(question.get("dns.qry.name"), "dns.qry.name"),
        _wire_unsigned(question.get("dns.qry.type"), 65_535, "dns.qry.type"),
        _wire_unsigned(question.get("dns.qry.class"), 65_535, "dns.qry.class"),
    )


def _wire_record(record: dict[str, object]) -> DnsResourceRecord:
    record_type = _wire_unsigned(record.get("dns.resp.type"), 65_535, "dns.resp.type")
    owner = _dns_name(record["dns.resp.name"], "dns.resp.name") if "dns.resp.name" in record else None
    if owner is None and record_type in (1, 5, 12, 28):
        raise CapturedDnsValidationError("Supported address, CNAME and PTR records require a structured owner name.")
    record_class = _wire_unsigned(record.get("dns.resp.class"), 65_535, "dns.resp.class")
    ttl = _wire_unsigned(record.get("dns.resp.ttl"), 2**32 - 1, "dns.resp.ttl")
    value: str | None = None
    if record_type == 1:
        value = _address(record.get("dns.a"), 4, "dns.a")
    elif record_type == 28:
        value = _address(record.get("dns.aaaa"), 6, "dns.aaaa")
    elif record_type == 5:
        value = _dns_name(record.get("dns.cname"), "dns.cname")
    elif record_type == 12:
        value = _dns_name(record.get("dns.ptr.domain_name"), "dns.ptr.domain_name")
    for field, expected in (("dns.a", 1), ("dns.aaaa", 28), ("dns.cname", 5), ("dns.ptr.domain_name", 12)):
        if field in record and record_type != expected:
            raise CapturedDnsValidationError(f"{field} conflicts with the resource-record type.")
    return DnsResourceRecord(owner, record_type, record_class, ttl, value)


def _extended_response_code(message: dict[str, object]) -> int:
    """Read EDNS response bits only from one complete additional-section OPT."""
    additional = _wire_group(message, "Additional records")
    if _wire_unsigned(message.get("dns.count.add_rr"), 65_535, "dns.count.add_rr") != len(additional):
        raise CapturedDnsValidationError("DNS additional-record count does not match the complete Additional records subtree.")
    extended: list[int] = []
    for record in additional:
        record_type = _wire_unsigned(record.get("dns.resp.type"), 65_535, "Additional dns.resp.type")
        if record_type == 41:
            extended.append(_wire_unsigned(record.get("dns.resp.ext_rcode"), 255, "dns.resp.ext_rcode"))
        elif "dns.resp.ext_rcode" in record:
            raise CapturedDnsValidationError("DNS extended response code occurs outside an OPT resource record.")
    if len(extended) > 1:
        raise CapturedDnsValidationError("DNS additional records contain more than one OPT resource record.")
    return extended[0] if extended else 0


def _wire_message(message: dict[str, object], frame: int, ordinal: int, protocol: DnsProtocol) -> CapturedDnsMessage:
    flags = _wire_unsigned(message.get("dns.flags"), 65_535, "dns.flags")
    flag_tree = _dictionary(message.get("dns.flags_tree"), "dns.flags_tree")
    response = _wire_boolean(flag_tree.get("dns.flags.response"), "dns.flags.response")
    truncated = _wire_boolean(flag_tree.get("dns.flags.truncated"), "dns.flags.truncated")
    if response != bool(flags & 0x8000) or truncated != bool(flags & 0x0200):
        raise CapturedDnsValidationError("DNS response or truncation flags conflict with dns.flags.")
    response_code = flags & 15
    opcode = (flags >> 11) & 15
    if "dns.flags.opcode" in flag_tree and _wire_unsigned(flag_tree["dns.flags.opcode"], 15, "dns.flags.opcode") != opcode:
        raise CapturedDnsValidationError("dns.flags.opcode conflicts with dns.flags.")
    if "dns.flags.rcode" in flag_tree and _wire_unsigned(flag_tree["dns.flags.rcode"], 15, "dns.flags.rcode") != response_code:
        raise CapturedDnsValidationError("dns.flags.rcode conflicts with dns.flags.")
    response_code |= _extended_response_code(message) << 4
    question_nodes = _wire_group(message, "Queries")
    answer_nodes = _wire_group(message, "Answers")
    if _wire_unsigned(message.get("dns.count.queries"), 65_535, "dns.count.queries") != len(question_nodes):
        raise CapturedDnsValidationError("DNS question count does not match the complete Queries subtree.")
    if _wire_unsigned(message.get("dns.count.answers"), 65_535, "dns.count.answers") != len(answer_nodes):
        raise CapturedDnsValidationError("DNS answer count does not match the complete Answers subtree.")
    questions = tuple(_wire_question(question) for question in question_nodes)
    answers = tuple(_wire_record(record) for record in answer_nodes)
    response_to = _wire_unsigned(message["dns.response_to"], 2**64 - 1, "dns.response_to") if "dns.response_to" in message else None
    if response_to is not None and (not response or not 0 < response_to < frame):
        raise CapturedDnsValidationError("dns.response_to requires an earlier positive query frame on a response.")
    return CapturedDnsMessage(frame, ordinal, protocol,
        _wire_unsigned(message.get("dns.id"), 65_535, "dns.id"), response, truncated,
        response_code, questions, response_to, answers, opcode)


def _unique_object(pairs: list[tuple[str, object]], cancellation: threading.Event) -> dict[str, object]:
    _check_cancelled(cancellation)
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CapturedDnsValidationError("Structured DNS JSON contains duplicate object keys.")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise CapturedDnsValidationError("Structured DNS JSON contains an invalid numeric constant.")


def _validate_json_structure(data: bytes, cancellation: threading.Event) -> None:
    if len(data) > DNS_MAX_JSON_BYTES:
        raise CapturedDnsValidationError(f"Structured DNS JSON exceeds its {DNS_MAX_JSON_BYTES}-byte limit.")
    depth = 0
    quoted = False
    escaped = False
    for index, byte in enumerate(data):
        if index % 65_536 == 0:
            _check_cancelled(cancellation)
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > DNS_MAX_DEPTH:
                raise CapturedDnsValidationError(f"Structured DNS JSON nesting exceeds {DNS_MAX_DEPTH} levels.")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise CapturedDnsValidationError("Structured DNS JSON has unbalanced containers.")
    if depth != 0 or quoted:
        raise CapturedDnsValidationError("Structured DNS JSON has incomplete containers or strings.")
    _check_cancelled(cancellation)


def _packet_basis(capture_sha256: str, packets: tuple[PacketRecord, ...], cancellation: threading.Event) -> dict[int, PacketRecord]:
    if not isinstance(capture_sha256, str) or DNS_DIGEST.fullmatch(capture_sha256) is None:
        raise CapturedDnsValidationError("Structured DNS evidence requires a lowercase SHA-256 capture digest.")
    result: dict[int, PacketRecord] = {}
    for packet in packets:
        _check_cancelled(cancellation)
        if packet.frame_number in result:
            raise CapturedDnsValidationError("Structured DNS packet basis contains duplicate frame identities.")
        result[packet.frame_number] = packet
    return result


def _message_bytes(message: CapturedDnsMessage) -> int:
    return 512 + sum(128 + len(question.name.encode("utf-8")) for question in message.questions) + sum(
        160 + (len(record.owner.encode("utf-8")) if record.owner is not None else 0) + (len(record.value.encode("utf-8")) if record.value is not None else 0)
        for record in message.answers)


def _check_retention(messages: int, records: int, estimated: int) -> None:
    if messages > DNS_MAX_MESSAGES:
        raise CapturedDnsValidationError(f"Structured DNS evidence exceeds {DNS_MAX_MESSAGES} messages.")
    if records > DNS_MAX_RECORDS:
        raise CapturedDnsValidationError(f"Structured DNS evidence exceeds {DNS_MAX_RECORDS} questions and answer records.")
    if estimated > DNS_MAX_RETAINED_BYTES:
        raise CapturedDnsValidationError(f"Structured DNS evidence exceeds its {DNS_MAX_RETAINED_BYTES}-byte estimated retained-value limit.")


def _validate_complete_basis(messages: tuple[CapturedDnsMessage, ...], packets: dict[int, PacketRecord], cancellation: threading.Event) -> None:
    seen: dict[int, int] = {}
    records = 0
    estimated = 0
    if len(messages) > DNS_MAX_MESSAGES:
        raise CapturedDnsValidationError(f"Structured DNS evidence exceeds {DNS_MAX_MESSAGES} messages.")
    for message in messages:
        _check_cancelled(cancellation)
        packet = packets.get(message.frame_number)
        if packet is None or message.protocol not in packet.protocol_stack:
            raise CapturedDnsValidationError("Structured DNS message frame or protocol is absent from its retained packet basis.")
        expected = seen.get(message.frame_number, 0)
        if message.message_index != expected:
            raise CapturedDnsValidationError("Structured DNS message indices must be contiguous from zero within each frame.")
        seen[message.frame_number] = expected + 1
        if message.response_to_frame is not None and message.response_to_frame not in packets:
            raise CapturedDnsValidationError("Structured DNS response references an unavailable query frame.")
        records += len(message.questions) + len(message.answers)
        estimated += _message_bytes(message)
        _check_retention(len(messages), records, estimated)
    expected_frames = {frame for frame, packet in packets.items() if any(protocol in packet.protocol_stack for protocol in DNS_PROTOCOLS)}
    if set(seen) != expected_frames:
        raise CapturedDnsValidationError("Structured DNS messages do not cover every DNS, mDNS and LLMNR frame in the retained packet basis.")
    _check_cancelled(cancellation)


def decode_captured_dns(data: bytes, capture_sha256: str, packets: tuple[PacketRecord, ...], cancellation: threading.Event) -> CapturedDnsEvidence:
    """Validate complete structured questions/Answers against a saved packet basis.

    Authority and additional sections are not address-association evidence. Their
    fields remain available in original packet fields. Each ordinal identifies
    one decoded message in a frame, including repeated TCP DNS PDUs.
    """
    basis = _packet_basis(capture_sha256, packets, cancellation)
    _validate_json_structure(data, cancellation)
    try:
        raw: object = json.loads(data.decode("utf-8"), object_pairs_hook=lambda pairs: _unique_object(pairs, cancellation), parse_constant=_reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise CapturedDnsValidationError("Structured DNS output is not complete valid UTF-8 JSON.") from error
    wire_packets = _list(raw, "Structured DNS output")
    if len(wire_packets) > DNS_MAX_MESSAGES:
        raise CapturedDnsValidationError(f"Structured DNS output exceeds {DNS_MAX_MESSAGES} decoded frames.")
    messages: list[CapturedDnsMessage] = []
    seen_frames: set[int] = set()
    records = 0
    estimated = 0
    for item in wire_packets:
        _check_cancelled(cancellation)
        packet = _dictionary(item, "Structured DNS frame")
        source = _dictionary(packet.get("_source"), "_source")
        layers = _dictionary(source.get("layers"), "layers")
        frame_node = _dictionary(layers.get("frame"), "frame")
        frame = _wire_unsigned(frame_node.get("frame.number"), 2**64 - 1, "frame.number")
        if frame == 0 or frame in seen_frames:
            raise CapturedDnsValidationError("Structured DNS frame numbers must be positive and unique.")
        retained = basis.get(frame)
        if retained is None:
            raise CapturedDnsValidationError("Structured DNS frame is absent from its retained packet basis.")
        timestamp = _wire_timestamp(frame_node.get("frame.time_epoch"))
        if (timestamp.seconds, timestamp.nanoseconds) != (retained.timestamp.seconds, retained.timestamp.nanoseconds) or _wire_unsigned(frame_node.get("frame.len"), 2**32 - 1, "frame.len") != retained.wire_length:
            raise CapturedDnsValidationError("Structured DNS frame timestamp or wire length conflicts with its retained packet basis.")
        if _wire_text(frame_node.get("frame.protocols"), "frame.protocols").split(":") != list(retained.protocol_stack):
            raise CapturedDnsValidationError("Structured DNS frame protocol stack conflicts with its retained packet basis.")
        seen_frames.add(frame)
        ordinal = 0
        for protocol in DNS_PROTOCOLS:
            if protocol not in layers:
                continue
            selected: DnsProtocol = "dns" if protocol == "dns" else "mdns" if protocol == "mdns" else "llmnr"
            for message in _one_or_many(layers[protocol], protocol):
                decoded = _wire_message(message, frame, ordinal, selected)
                records += len(decoded.questions) + len(decoded.answers)
                estimated += _message_bytes(decoded)
                _check_retention(len(messages) + 1, records, estimated)
                messages.append(decoded)
                ordinal += 1
                if len(messages) > DNS_MAX_MESSAGES:
                    raise CapturedDnsValidationError(f"Structured DNS output exceeds {DNS_MAX_MESSAGES} decoded messages.")
        if ordinal == 0:
            raise CapturedDnsValidationError("Structured DNS frame contains no supported DNS message tree.")
    result = tuple(sorted(messages, key=lambda message: (message.frame_number, message.message_index)))
    _validate_complete_basis(result, basis, cancellation)
    return CapturedDnsEvidence(capture_sha256, result)


def dns_evidence_document(evidence: CapturedDnsEvidence) -> DnsEvidenceDocument:
    """Serialize validated passive source observations, never inferred links."""
    return {"capture_sha256": evidence.capture_sha256, "messages": [
        {"frame_number": message.frame_number, "message_index": message.message_index,
         "protocol": message.protocol, "transaction_id": message.transaction_id,
         "is_response": message.is_response, "is_truncated": message.is_truncated,
         "response_code": message.response_code, "response_to_frame": message.response_to_frame,
         "opcode": message.opcode,
         "questions": [{"name": question.name, "record_type": question.record_type,
                         "record_class": question.record_class} for question in message.questions],
         "answers": [{"owner": record.owner, "record_type": record.record_type,
                      "record_class": record.record_class, "ttl_seconds": record.ttl_seconds,
                      "value": record.value} for record in message.answers]}
        for message in evidence.messages]}


def _closed_object(value: object, keys: tuple[str, ...], label: str) -> dict[str, object]:
    result = _dictionary(value, label)
    if set(result) != set(keys):
        raise CapturedDnsValidationError(f"{label} requires exactly its documented evidence fields.")
    return result


def _document_unsigned(value: object, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise CapturedDnsValidationError(f"{label} requires an unsigned integer within its supported range.")
    return value


def _document_boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise CapturedDnsValidationError(f"{label} requires a Boolean.")
    return value


def _document_name(value: object, label: str) -> str:
    normalized = _dns_name(value, label)
    if value != normalized:
        raise CapturedDnsValidationError(f"{label} requires a canonical lowercase DNS name without a trailing dot.")
    return normalized


def _document_question(value: object) -> DnsQuestion:
    question = _closed_object(value, ("name", "record_type", "record_class"), "DNS question")
    return DnsQuestion(_document_name(question["name"], "DNS question name"),
        _document_unsigned(question["record_type"], 65_535, "DNS question type"),
        _document_unsigned(question["record_class"], 65_535, "DNS question class"))


def _document_record(value: object) -> DnsResourceRecord:
    record = _closed_object(value, ("owner", "record_type", "record_class", "ttl_seconds", "value"), "DNS answer")
    record_type = _document_unsigned(record["record_type"], 65_535, "DNS answer type")
    owner = _document_name(record["owner"], "DNS answer owner") if record["owner"] is not None else None
    if owner is None and record_type in (1, 5, 12, 28):
        raise CapturedDnsValidationError("Supported address, CNAME and PTR records require a structured owner name.")
    record_class = _document_unsigned(record["record_class"], 65_535, "DNS answer class")
    ttl = _document_unsigned(record["ttl_seconds"], 2**32 - 1, "DNS answer TTL")
    decoded: str | None = None
    if record_type in (1, 28):
        decoded = _address(record["value"], 4 if record_type == 1 else 6, "DNS answer address")
        if decoded != record["value"]:
            raise CapturedDnsValidationError("DNS answer address requires canonical IP spelling.")
    elif record_type in (5, 12):
        decoded = _document_name(record["value"], "DNS answer target")
    elif record["value"] is not None:
        raise CapturedDnsValidationError("Unsupported DNS answer types cannot claim a decoded RDATA value.")
    return DnsResourceRecord(owner, record_type, record_class, ttl, decoded)


def _document_message(value: object) -> CapturedDnsMessage:
    message = _closed_object(value, ("frame_number", "message_index", "protocol", "transaction_id", "is_response", "is_truncated", "response_code", "questions", "response_to_frame", "answers", "opcode"), "DNS message")
    frame = _document_unsigned(message["frame_number"], 2**64 - 1, "DNS frame number")
    if frame == 0:
        raise CapturedDnsValidationError("DNS frame number must be positive.")
    ordinal = _document_unsigned(message["message_index"], DNS_MAX_MESSAGES - 1, "DNS message index")
    protocol = message["protocol"]
    if protocol not in DNS_PROTOCOLS:
        raise CapturedDnsValidationError("DNS message protocol must be dns, mdns or llmnr.")
    selected: DnsProtocol = "dns" if protocol == "dns" else "mdns" if protocol == "mdns" else "llmnr"
    response = _document_boolean(message["is_response"], "DNS response flag")
    query_frame = _document_unsigned(message["response_to_frame"], 2**64 - 1, "DNS query frame") if message["response_to_frame"] is not None else None
    if query_frame is not None and (not response or not 0 < query_frame < frame):
        raise CapturedDnsValidationError("DNS response query reference must be an earlier positive frame.")
    question_values = _list(message["questions"], "DNS questions")
    answer_values = _list(message["answers"], "DNS answers")
    if len(question_values) > 65_535 or len(answer_values) > 65_535:
        raise CapturedDnsValidationError("DNS message question or answer count exceeds its wire header range.")
    return CapturedDnsMessage(frame, ordinal, selected,
        _document_unsigned(message["transaction_id"], 65_535, "DNS transaction identifier"),
        response, _document_boolean(message["is_truncated"], "DNS truncation flag"),
        _document_unsigned(message["response_code"], 4095, "DNS response code"),
        tuple(_document_question(question) for question in question_values),
        query_frame,
        tuple(_document_record(record) for record in answer_values),
        _document_unsigned(message["opcode"], 15, "DNS opcode"))


def validate_dns_evidence_document(value: object, capture_sha256: str, packets: tuple[PacketRecord, ...], cancellation: threading.Event) -> CapturedDnsEvidence:
    """Revalidate the closed report schema and all frame/digest evidence bindings."""
    basis = _packet_basis(capture_sha256, packets, cancellation)
    evidence = _closed_object(value, ("capture_sha256", "messages"), "DNS evidence")
    if evidence["capture_sha256"] != capture_sha256:
        raise CapturedDnsValidationError("DNS evidence digest does not match its saved capture packet basis.")
    raw_messages = _list(evidence["messages"], "DNS messages")
    if len(raw_messages) > DNS_MAX_MESSAGES:
        raise CapturedDnsValidationError(f"DNS evidence exceeds {DNS_MAX_MESSAGES} messages.")
    messages: list[CapturedDnsMessage] = []
    records = 0
    estimated = 0
    for value in raw_messages:
        _check_cancelled(cancellation)
        message = _document_message(value)
        records += len(message.questions) + len(message.answers)
        estimated += _message_bytes(message)
        _check_retention(len(messages) + 1, records, estimated)
        messages.append(message)
    if messages != sorted(messages, key=lambda message: (message.frame_number, message.message_index)):
        raise CapturedDnsValidationError("DNS evidence messages require exact frame and ordinal order.")
    result = tuple(messages)
    _validate_complete_basis(result, basis, cancellation)
    return CapturedDnsEvidence(capture_sha256, result)
