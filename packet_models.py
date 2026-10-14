"""Immutable saved-packet evidence and pure decoding/serialization functions."""

from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass
from typing import Literal, Mapping, TypedDict

MetadataState = Literal["unknown", "recorded", "conflict"]
ProcessSource = Literal["apple_pcapng", "pktap"]
InterfaceSource = Literal["capture_frame", "pktap"]
DirectionSource = Literal["pcapng_packet_options", "pktap"]
PacketDirection = Literal["inbound", "outbound", "unknown"]
PacketTransport = Literal["tcp", "udp"]
EPOCH_SYNTAX = re.compile(r"(-?)([0-9]+)(?:\.([0-9]{1,9}))?")
PROTOCOL_TOKEN = re.compile(r"[a-z0-9_.-]+")
FIELD_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
PCAPNG_PROCESS_FIELDS = (
    "pcapng.apple.process.pid", "pcapng.apple.process.pname",
    "pcapng.apple.process.epid", "pcapng.apple.process.epname",
)


class PacketValidationError(ValueError):
    """A decoder row cannot represent valid, unambiguous packet evidence."""


@dataclass(frozen=True, slots=True)
class PacketTimestamp:
    epoch: str
    seconds: int
    nanoseconds: int


@dataclass(frozen=True, slots=True)
class DecodedField:
    name: str
    values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProcessLabel:
    source: ProcessSource
    pid: int | None
    name: str | None


@dataclass(frozen=True, slots=True)
class ProcessMetadata:
    state: MetadataState
    labels: tuple[ProcessLabel, ...]


@dataclass(frozen=True, slots=True)
class InterfaceLabel:
    source: InterfaceSource
    name: str


@dataclass(frozen=True, slots=True)
class InterfaceMetadata:
    state: MetadataState
    labels: tuple[InterfaceLabel, ...]


@dataclass(frozen=True, slots=True)
class DirectionLabel:
    source: DirectionSource
    direction: PacketDirection


@dataclass(frozen=True, slots=True)
class DirectionMetadata:
    state: MetadataState
    labels: tuple[DirectionLabel, ...]


@dataclass(frozen=True, slots=True)
class PacketRecord:
    frame_number: int
    timestamp: PacketTimestamp
    wire_length: int
    captured_length: int | None
    protocol_stack: tuple[str, ...]
    fields: tuple[DecodedField, ...]
    process: ProcessMetadata
    effective_process: ProcessMetadata
    interface: InterfaceMetadata
    direction: DirectionMetadata
    source_address: str | None
    destination_address: str | None
    source_port: int | None
    destination_port: int | None
    transport: PacketTransport | None
    stream: int | None
    diagnostics: tuple[str, ...]


class TimestampDocument(TypedDict):
    epoch: str
    seconds: int
    nanoseconds: int


class FieldDocument(TypedDict):
    name: str
    values: list[str]


class ProcessLabelDocument(TypedDict):
    source: ProcessSource
    pid: int | None
    name: str | None


class ProcessDocument(TypedDict):
    state: MetadataState
    labels: list[ProcessLabelDocument]


class InterfaceLabelDocument(TypedDict):
    source: InterfaceSource
    name: str


class InterfaceDocument(TypedDict):
    state: MetadataState
    labels: list[InterfaceLabelDocument]


class DirectionLabelDocument(TypedDict):
    source: DirectionSource
    direction: PacketDirection


class DirectionDocument(TypedDict):
    state: MetadataState
    labels: list[DirectionLabelDocument]


class PacketDocument(TypedDict):
    frame_number: int
    timestamp: TimestampDocument
    wire_length: int
    captured_length: int | None
    protocol_stack: list[str]
    fields: list[FieldDocument]
    process: ProcessDocument
    effective_process: ProcessDocument
    interface: InterfaceDocument
    direction: DirectionDocument
    source_address: str | None
    destination_address: str | None
    source_port: int | None
    destination_port: int | None
    transport: PacketTransport | None
    stream: int | None
    diagnostics: list[str]


def packet_values(record: PacketRecord, field: str) -> tuple[str, ...]:
    """Return occurrences; the two advertised protocol-column aliases agree."""
    names = ("_ws.col.protocol", "_ws.col.Protocol") if field in ("_ws.col.protocol", "_ws.col.Protocol") else (field,)
    return next((item.values for item in record.fields if item.name in names), ())


def decode_packet_timestamp(epoch: str) -> PacketTimestamp:
    """Keep exact decimal epoch evidence; floor-normalize negative fractions."""
    match = EPOCH_SYNTAX.fullmatch(epoch)
    if len(epoch.encode("utf-8")) > 40 or match is None:
        raise PacketValidationError("frame.time_epoch requires signed seconds and at most nine fractional digits.")
    seconds = int(match.group(1) + match.group(2))
    nanoseconds = int((match.group(3) or "0").ljust(9, "0"))
    if match.group(1) and nanoseconds:
        seconds -= 1
        nanoseconds = 1_000_000_000 - nanoseconds
    if not -(2**63) <= seconds < 2**63:
        raise PacketValidationError("frame.time_epoch exceeds the signed 64-bit seconds range.")
    return PacketTimestamp(epoch, seconds, nanoseconds)


def decode_packet_row(line: str, field_names: tuple[str, ...]) -> PacketRecord:
    """Decode one quoted TSV row, preserving every nonempty field occurrence."""
    try:
        columns = next(csv.reader([line], delimiter="\t", quotechar='"', strict=True))
    except (csv.Error, StopIteration) as error:
        raise PacketValidationError("TShark returned an invalid quoted TSV row.") from error
    if len(columns) != len(field_names):
        raise PacketValidationError(
            f"TShark returned {len(columns)} columns for {len(field_names)} requested fields."
        )
    values: dict[str, tuple[str, ...]] = {
        name: tuple(value for value in column.split("\x1e") if value)
        for name, column in zip(field_names, columns)
    }
    return decode_packet_fields(values, field_names)


def decode_packet_fields(values: Mapping[str, tuple[str, ...]], field_names: tuple[str, ...]) -> PacketRecord:
    """Select endpoints only when the recorded network/transport layers agree."""
    if len(field_names) > 128 or len(set(field_names)) != len(field_names) or any(FIELD_NAME.fullmatch(name) is None for name in field_names):
        raise PacketValidationError("Recorded field names must be unique bounded decoder abbreviations.")
    for name, occurrences in values.items():
        if name not in field_names or len(occurrences) > 128:
            raise PacketValidationError(f"{name} is unrequested or exceeds the 128-occurrence limit.")
        if any(not value or len(value.encode("utf-8")) > 1_024 or any(ord(character) < 32 or ord(character) == 127 for character in value) for value in occurrences):
            raise PacketValidationError(f"{name} contains an empty, oversized or control-character value.")
    frame_number = required_number(values, "frame.number", 2**64 - 1)
    if frame_number == 0:
        raise PacketValidationError("frame.number starts at 1.")
    timestamp = decode_packet_timestamp(required_text(values, "frame.time_epoch"))
    wire_length = required_number(values, "frame.len", 2**32 - 1)
    captured_length = optional_number(values, "frame.cap_len", 2**32 - 1)
    if captured_length is not None and captured_length > wire_length:
        raise PacketValidationError("frame.cap_len exceeds frame.len.")
    stack = tuple(required_text(values, "frame.protocols").lower().split(":"))
    if len(stack) > 64 or any(PROTOCOL_TOKEN.fullmatch(token) is None for token in stack):
        raise PacketValidationError("frame.protocols contains invalid token syntax or more than 64 layers.")
    protocol_field = "_ws.col.protocol" if "_ws.col.protocol" in values else "_ws.col.Protocol"
    required_text(values, protocol_field)
    ipv4_sources = address_values(values, "ip.src", 4)
    ipv4_destinations = address_values(values, "ip.dst", 4)
    ipv6_sources = address_values(values, "ipv6.src", 6)
    ipv6_destinations = address_values(values, "ipv6.dst", 6)
    address_values(values, "dns.a", 4)
    address_values(values, "dns.aaaa", 6)
    number_values(values, "dns.resp.ttl", 2**32 - 1)
    tcp_sources = number_values(values, "tcp.srcport", 65_535)
    tcp_destinations = number_values(values, "tcp.dstport", 65_535)
    udp_sources = number_values(values, "udp.srcport", 65_535)
    udp_destinations = number_values(values, "udp.dstport", 65_535)
    tcp_streams = number_values(values, "tcp.stream", 2**32 - 1)
    udp_streams = number_values(values, "udp.stream", 2**32 - 1)
    tcp_numbers = tuple(number_values(values, name, 2**32 - 1) for name in ("tcp.seq_raw", "tcp.ack_raw", "tcp.len"))
    tcp_flags = flag_values(values, "tcp.flags", 65_535)
    ipv4_present = bool(ipv4_sources or ipv4_destinations or "ip" in stack)
    ipv6_present = bool(ipv6_sources or ipv6_destinations or "ipv6" in stack)
    tcp_present = bool(tcp_sources or tcp_destinations or tcp_streams or "tcp" in stack)
    udp_present = bool(udp_sources or udp_destinations or udp_streams or "udp" in stack)
    network_ambiguous = (
        any(len(items) > 1 for items in (ipv4_sources, ipv4_destinations, ipv6_sources, ipv6_destinations))
        or ipv4_present and ipv6_present
        or sum(token in ("ip", "ipv6") for token in stack) > 1
    )
    transport_ambiguous = (
        any(len(items) > 1 for items in (tcp_sources, tcp_destinations, udp_sources, udp_destinations, tcp_streams, udp_streams, tcp_flags) + tcp_numbers)
        or tcp_present and udp_present
        or sum(token in ("tcp", "udp") for token in stack) > 1
    )
    source_address = first_value(ipv4_sources + ipv6_sources) if not network_ambiguous else None
    destination_address = first_value(ipv4_destinations + ipv6_destinations) if not network_ambiguous else None
    transport: PacketTransport | None = None if transport_ambiguous else "tcp" if tcp_present else "udp" if udp_present else None
    source_port = first_number(tcp_sources if transport == "tcp" else udp_sources) if transport else None
    destination_port = first_number(tcp_destinations if transport == "tcp" else udp_destinations) if transport else None
    stream = first_number(tcp_streams if transport == "tcp" else udp_streams) if transport else None
    primary_fields = PCAPNG_PROCESS_FIELDS[:2] if any(values.get(name) for name in PCAPNG_PROCESS_FIELDS[:2]) else ("frame.darwin.process_info.pid", "frame.darwin.process_info.pname")
    effective_fields = PCAPNG_PROCESS_FIELDS[2:] if any(values.get(name) for name in PCAPNG_PROCESS_FIELDS[2:]) else ("frame.darwin.process_info.epid", "frame.darwin.process_info.epname")
    process = decode_process_metadata(values, (("apple_pcapng", primary_fields[0], primary_fields[1]), ("pktap", "pktap.pid", "pktap.cmdname")))
    effective_process = decode_process_metadata(values, (("apple_pcapng", effective_fields[0], effective_fields[1]), ("pktap", "pktap.epid", "pktap.ecmdname")))
    interface = decode_interface_metadata(values)
    direction = decode_direction_metadata(values)
    diagnostics: list[str] = []
    if network_ambiguous:
        diagnostics.append("ambiguous_network_layers")
    elif (ipv4_present or ipv6_present) and (source_address is None or destination_address is None):
        diagnostics.append("incomplete_network_header")
    if transport_ambiguous:
        diagnostics.append("ambiguous_transport_layers")
    elif transport is not None and (source_port is None or destination_port is None):
        diagnostics.append("incomplete_transport_header")
    if transport is not None and stream is None:
        diagnostics.append("missing_stream")
    for name, state in (("process", process.state), ("effective_process", effective_process.state), ("interface", interface.state), ("direction", direction.state)):
        if state == "conflict":
            diagnostics.append(f"{name}_metadata_conflict")
    fields = tuple(DecodedField(name, values.get(name, ())) for name in field_names if values.get(name, ()))
    return PacketRecord(frame_number, timestamp, wire_length, captured_length, stack, fields, process, effective_process, interface, direction, source_address, destination_address, source_port, destination_port, transport, stream, tuple(diagnostics))


def required_text(values: Mapping[str, tuple[str, ...]], name: str) -> str:
    items = values.get(name, ())
    if len(items) != 1 or not items[0]:
        raise PacketValidationError(f"{name} requires exactly one nonempty value.")
    return items[0]


def number_values(values: Mapping[str, tuple[str, ...]], name: str, maximum: int) -> tuple[int, ...]:
    items = values.get(name, ())
    if any(not item.isascii() or not item.isdecimal() or len(item) > 20 for item in items):
        raise PacketValidationError(f"{name} requires unsigned decimal integers.")
    numbers = tuple(int(item) for item in items)
    if any(number > maximum for number in numbers):
        raise PacketValidationError(f"{name} exceeds its maximum value {maximum}.")
    return numbers


def required_number(values: Mapping[str, tuple[str, ...]], name: str, maximum: int) -> int:
    numbers = number_values(values, name, maximum)
    if len(numbers) != 1:
        raise PacketValidationError(f"{name} requires exactly one unsigned decimal integer.")
    return numbers[0]


def optional_number(values: Mapping[str, tuple[str, ...]], name: str, maximum: int) -> int | None:
    numbers = number_values(values, name, maximum)
    if len(numbers) > 1:
        raise PacketValidationError(f"{name} cannot identify one value from repeated fields.")
    return first_number(numbers)


def flag_values(values: Mapping[str, tuple[str, ...]], name: str, maximum: int) -> tuple[int, ...]:
    numbers: list[int] = []
    for item in values.get(name, ()):
        if re.fullmatch(r"0x[0-9A-Fa-f]+", item) is not None and len(item) <= 18:
            number = int(item, 16)
        elif item.isascii() and item.isdecimal() and len(item) <= 20:
            number = int(item)
        else:
            raise PacketValidationError(f"{name} requires unsigned decimal or hexadecimal flags.")
        if number > maximum:
            raise PacketValidationError(f"{name} exceeds its maximum value {maximum}.")
        numbers.append(number)
    return tuple(numbers)


def address_values(values: Mapping[str, tuple[str, ...]], name: str, version: int) -> tuple[str, ...]:
    addresses: list[str] = []
    for item in values.get(name, ()):
        if len(item) > 45 or "%" in item:
            raise PacketValidationError(f"{name} contains an oversized or zone-qualified IP address.")
        try:
            address = ipaddress.ip_address(item)
        except ValueError as error:
            raise PacketValidationError(f"{name} contains an invalid IPv{version} address.") from error
        if address.version != version:
            raise PacketValidationError(f"{name} contains the wrong IP address family.")
        addresses.append(str(address))
    return tuple(addresses)


def first_value(items: tuple[str, ...]) -> str | None:
    return items[0] if items else None


def first_number(items: tuple[int, ...]) -> int | None:
    return items[0] if items else None


def decode_process_metadata(values: Mapping[str, tuple[str, ...]], sources: tuple[tuple[ProcessSource, str, str], ...]) -> ProcessMetadata:
    """Preserve source labels; repeated fields remain unpaired conflicting evidence."""
    labels: list[ProcessLabel] = []
    repeated = False
    for source, pid_field, name_field in sources:
        pids = number_values(values, pid_field, 2**31 - 1)
        names = values.get(name_field, ())
        if any(len(name.encode("utf-8")) > 256 for name in names):
            raise PacketValidationError(f"{name_field} exceeds the 256-byte name limit.")
        if len(pids) > 1 or len(names) > 1:
            repeated = True
            labels.extend(ProcessLabel(source, pid, None) for pid in pids)
            labels.extend(ProcessLabel(source, None, name) for name in names)
        elif pids or names:
            labels.append(ProcessLabel(source, first_number(pids), first_value(names)))
    identifiers = {label.pid for label in labels if label.pid is not None}
    names_set = {label.name for label in labels if label.name is not None}
    state: MetadataState = "conflict" if repeated or len(identifiers) > 1 or len(names_set) > 1 else "recorded" if identifiers or names_set else "unknown"
    return ProcessMetadata(state, tuple(labels))


def decode_interface_metadata(values: Mapping[str, tuple[str, ...]]) -> InterfaceMetadata:
    frame_names = values.get("frame.interface_name", ())
    pktap_names = values.get("pktap.ifname", ())
    if any(len(name.encode("utf-8")) > 256 for name in frame_names + pktap_names):
        raise PacketValidationError("Recorded interface names exceed the 256-byte limit.")
    labels = tuple(InterfaceLabel("capture_frame", name) for name in frame_names) + tuple(InterfaceLabel("pktap", name) for name in pktap_names)
    conflict = len(frame_names) > 1 or len(pktap_names) > 1 or len({label.name for label in labels}) > 1
    state: MetadataState = "conflict" if conflict else "recorded" if labels else "unknown"
    return InterfaceMetadata(state, labels)


def decode_direction_metadata(values: Mapping[str, tuple[str, ...]]) -> DirectionMetadata:
    frame_flags = flag_values(values, "frame.packet_flags_direction", 3)
    pktap_flags = flag_values(values, "pktap.flags", 2**32 - 1)
    labels = tuple(DirectionLabel("pcapng_packet_options", direction_value(value)) for value in frame_flags) + tuple(DirectionLabel("pktap", direction_value(value & 3)) for value in pktap_flags)
    known = {label.direction for label in labels if label.direction != "unknown"}
    conflict = len(frame_flags) > 1 or len(pktap_flags) > 1 or len(known) > 1
    state: MetadataState = "conflict" if conflict else "recorded" if known else "unknown"
    return DirectionMetadata(state, labels)


def direction_value(value: int) -> PacketDirection:
    return "inbound" if value == 1 else "outbound" if value == 2 else "unknown"


def estimated_packet_bytes(record: PacketRecord) -> int:
    """Estimate retained value storage conservatively; this does not measure RSS."""
    return 1_024 + sum(64 + len(item.name.encode("utf-8")) + sum(64 + len(value.encode("utf-8")) for value in item.values) for item in record.fields) + 128 * (len(record.process.labels) + len(record.effective_process.labels) + len(record.interface.labels) + len(record.direction.labels))


def process_document(metadata: ProcessMetadata) -> ProcessDocument:
    return {"state": metadata.state, "labels": [{"source": label.source, "pid": label.pid, "name": label.name} for label in metadata.labels]}


def packet_document(record: PacketRecord) -> PacketDocument:
    """Produce JSON-compatible typed evidence without changing recorded values."""
    return {
        "frame_number": record.frame_number,
        "timestamp": {"epoch": record.timestamp.epoch, "seconds": record.timestamp.seconds, "nanoseconds": record.timestamp.nanoseconds},
        "wire_length": record.wire_length,
        "captured_length": record.captured_length,
        "protocol_stack": list(record.protocol_stack),
        "fields": [{"name": item.name, "values": list(item.values)} for item in record.fields],
        "process": process_document(record.process),
        "effective_process": process_document(record.effective_process),
        "interface": {"state": record.interface.state, "labels": [{"source": label.source, "name": label.name} for label in record.interface.labels]},
        "direction": {"state": record.direction.state, "labels": [{"source": label.source, "direction": label.direction} for label in record.direction.labels]},
        "source_address": record.source_address,
        "destination_address": record.destination_address,
        "source_port": record.source_port,
        "destination_port": record.destination_port,
        "transport": record.transport,
        "stream": record.stream,
        "diagnostics": list(record.diagnostics),
    }


def validate_packet_document(payload: object) -> PacketRecord:
    """Require a closed report schema equal to evidence reconstructed from fields.

    JSON objects enter as ``object`` only at this validation boundary. Derived
    endpoints, metadata states, timestamps and diagnostics cannot override their
    source fields; every expected scalar type is checked without unchecked casts.
    """
    document = _report_object(payload, "packet")
    raw_fields = _report_sequence(document.get("fields"), "packet.fields", 128)
    values: dict[str, tuple[str, ...]] = {}
    field_names: list[str] = []
    for index, raw_field in enumerate(raw_fields):
        field = _report_object(raw_field, f"packet.fields[{index}]")
        if set(field) != {"name", "values"}:
            raise PacketValidationError("Each recorded field requires only name and values.")
        name = field.get("name")
        if not isinstance(name, str) or FIELD_NAME.fullmatch(name) is None:
            raise PacketValidationError("Recorded field names must be bounded decoder abbreviations.")
        if name in values:
            raise PacketValidationError("A report repeated a recorded field name.")
        raw_values = _report_sequence(field.get("values"), f"packet.fields[{index}].values", 128)
        occurrences: list[str] = []
        for item in raw_values:
            if not isinstance(item, str):
                raise PacketValidationError("Recorded field occurrences must be strings.")
            occurrences.append(item)
        if not occurrences:
            raise PacketValidationError("Serialized recorded fields must contain at least one occurrence.")
        field_names.append(name)
        values[name] = tuple(occurrences)
    record = decode_packet_fields(values, tuple(field_names))
    _require_equal_document(packet_document(record), payload, "packet")
    return record


def _report_object(payload: object, context: str) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise PacketValidationError(f"{context} requires a JSON object.")
    result: dict[str, object] = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise PacketValidationError(f"{context} requires string property names.")
        result[key] = value
    return result


def _report_sequence(payload: object, context: str, maximum: int) -> tuple[object, ...]:
    if not isinstance(payload, list) or len(payload) > maximum:
        raise PacketValidationError(f"{context} requires an array of at most {maximum} entries.")
    return tuple(payload)


def _require_equal_document(expected: object, received: object, context: str) -> None:
    if isinstance(expected, dict):
        expected_object = _report_object(expected, context)
        received_object = _report_object(received, context)
        if set(expected_object) != set(received_object):
            raise PacketValidationError(f"{context} does not match the closed packet-report schema.")
        for key, value in expected_object.items():
            _require_equal_document(value, received_object[key], context + "." + key)
        return
    if isinstance(expected, list):
        received_items = _report_sequence(received, context, len(expected))
        if len(received_items) != len(expected):
            raise PacketValidationError(f"{context} differs from its recorded field evidence.")
        for index, value in enumerate(expected):
            _require_equal_document(value, received_items[index], f"{context}[{index}]")
        return
    if type(received) is not type(expected) or received != expected:
        raise PacketValidationError(f"{context} has an invalid type or differs from its recorded field evidence.")
