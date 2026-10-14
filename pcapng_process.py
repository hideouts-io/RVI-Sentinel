"""Read Apple process metadata from validated PCAPNG container bytes.

This stage runs independently of TShark's field population. Packet payloads and
network protocols remain the decoder's responsibility. Process references are
section local; frame identities are contiguous across all sections.
"""

from __future__ import annotations

import os
import struct
import threading
import time
from dataclasses import dataclass
from typing import Iterator, Literal

from packet_models import PCAPNG_PROCESS_FIELDS, PacketRecord, decode_packet_fields, estimated_packet_bytes

ByteOrder = Literal["<", ">"]


class PcapngMetadataError(ValueError):
    """Container structure or recorded process metadata is invalid."""


class PcapngMetadataCancelled(PcapngMetadataError):
    """No partial container metadata is returned after cancellation."""


class PcapngMetadataLimitError(PcapngMetadataError):
    """Preserve the caller's explicit record, storage or deadline failure code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ProcessInformation:
    pid: int
    names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FrameProcessInformation:
    frame_number: int
    primary: tuple[ProcessInformation, ...]
    effective: tuple[ProcessInformation, ...]


@dataclass(frozen=True, slots=True)
class PcapngProcessIndex:
    packet_count: int
    frames: tuple[FrameProcessInformation, ...]
    estimated_bytes: int


def _check_operation(deadline: float, cancellation: threading.Event) -> None:
    if cancellation.is_set():
        raise PcapngMetadataCancelled("PCAPNG process metadata reading was cancelled.")
    if time.monotonic() >= deadline:
        raise PcapngMetadataLimitError("deadline_exceeded", "PCAPNG process metadata reading exceeded the analysis deadline.")


def _read(descriptor: int, offset: int, count: int, deadline: float, cancellation: threading.Event) -> bytes:
    _check_operation(deadline, cancellation)
    chunks: list[bytes] = []
    remaining = count
    try:
        os.lseek(descriptor, offset, os.SEEK_SET)
    except OSError as error:
        raise PcapngMetadataError(f"PCAPNG metadata could not be sought at byte {offset} (OS error {error.errno}).") from error
    while remaining:
        try:
            chunk = os.read(descriptor, remaining)
        except OSError as error:
            raise PcapngMetadataError(f"PCAPNG metadata could not be read at byte {offset} (OS error {error.errno}).") from error
        if not chunk:
            raise PcapngMetadataError(f"PCAPNG metadata is truncated at byte {offset}.")
        chunks.append(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
        _check_operation(deadline, cancellation)
    return b"".join(chunks)


def _options(descriptor: int, start: int, end: int, order: ByteOrder, deadline: float, cancellation: threading.Event) -> Iterator[tuple[int, bytes]]:
    offset = start
    while offset < end:
        if end - offset < 4:
            raise PcapngMetadataError("A PCAPNG option header crosses its block boundary.")
        code, length = struct.unpack(order + "HH", _read(descriptor, offset, 4, deadline, cancellation))
        offset += 4
        padded = (length + 3) & ~3
        if offset + padded > end:
            raise PcapngMetadataError("A PCAPNG option value crosses its block boundary.")
        if code == 0:
            if length != 0:
                raise PcapngMetadataError("The PCAPNG end-of-options marker must have zero length.")
            while offset < end:
                amount = min(65_536, end - offset)
                if any(_read(descriptor, offset, amount, deadline, cancellation)):
                    raise PcapngMetadataError("Nonzero bytes follow the PCAPNG end-of-options marker.")
                offset += amount
            return
        value = _read(descriptor, offset, length, deadline, cancellation)
        if padded != length and any(_read(descriptor, offset + length, padded - length, deadline, cancellation)):
            raise PcapngMetadataError("PCAPNG option alignment padding must contain zero bytes.")
        offset += padded
        yield code, value
    # The format requires readers to accept an option list ending at the block boundary.


def _process(descriptor: int, start: int, end: int, order: ByteOrder, deadline: float, cancellation: threading.Event) -> ProcessInformation:
    if end - start < 4:
        raise PcapngMetadataError("An Apple process information block lacks its recorded PID.")
    # Legacy Darwin integer payloads are little endian independently of section framing.
    pid = struct.unpack("<I", _read(descriptor, start, 4, deadline, cancellation))[0]
    if pid > 2**31 - 1:
        raise PcapngMetadataError("An Apple process PID exceeds the supported signed 32-bit range.")
    names: list[str] = []
    for code, value in _options(descriptor, start + 4, end, order, deadline, cancellation):
        if code != 2:
            continue
        if len(value) > 256 or len(names) >= 128:
            raise PcapngMetadataError("Apple process names must contain at most 256 UTF-8 bytes with at most 128 occurrences.")
        encoded = value.split(b"\0", 1)[0]
        if not encoded:
            continue
        try:
            name = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PcapngMetadataError("An Apple process name is not valid UTF-8.") from error
        if any(ord(character) < 32 or ord(character) == 127 for character in name):
            raise PcapngMetadataError("An Apple process name contains a control character.")
        names.append(name)
    return ProcessInformation(pid, tuple(names))


def _references(descriptor: int, start: int, end: int, order: ByteOrder, processes: list[ProcessInformation], deadline: float, cancellation: threading.Event) -> tuple[tuple[ProcessInformation, ...], tuple[ProcessInformation, ...]]:
    primary: list[ProcessInformation] = []
    effective: list[ProcessInformation] = []
    for code, value in _options(descriptor, start, end, order, deadline, cancellation):
        if code not in (0x8001, 0x8003):
            continue
        if len(value) != 4:
            raise PcapngMetadataError("An Apple packet process reference must contain exactly one UInt32 index.")
        index = struct.unpack("<I", value)[0]
        if index >= len(processes):
            raise PcapngMetadataError("An Apple packet process reference is outside its current section's process blocks.")
        selected = primary if code == 0x8001 else effective
        if len(selected) >= 128:
            raise PcapngMetadataError("An Apple packet contains more than 128 process references.")
        selected.append(processes[index])
    return tuple(primary), tuple(effective)


def read_pcapng_process_metadata(descriptor: int, maximum_records: int, maximum_estimated_bytes: int, deadline: float, cancellation: threading.Event) -> PcapngProcessIndex:
    """Stream block framing and section-scoped references from an open original.

    The caller exclusively owns the stable descriptor, its seek position, input-size limit and before/after
    integrity checks. Unknown blocks and packet payloads are skipped by offset,
    while block trailers and option boundaries are still checked. Retained
    process data and frame references use the caller's existing index ceilings.
    """
    try:
        size = os.fstat(descriptor).st_size
    except OSError as error:
        raise PcapngMetadataError(f"PCAPNG metadata size could not be inspected (OS error {error.errno}).") from error
    order: ByteOrder | None = None
    processes: list[ProcessInformation] = []
    frames: list[FrameProcessInformation] = []
    packet_count = 0
    process_count = 0
    estimated_bytes = 0
    interface_count = 0
    section_end: int | None = None
    offset = 0
    while offset < size:
        header = _read(descriptor, offset, 8, deadline, cancellation)
        is_section = header[:4] == b"\x0a\x0d\x0d\x0a"
        if is_section:
            if section_end is not None and offset != section_end:
                raise PcapngMetadataError("A PCAPNG section header does not match the preceding declared section length.")
            magic = _read(descriptor, offset + 8, 4, deadline, cancellation)
            if magic == b"\x4d\x3c\x2b\x1a":
                order = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                order = ">"
            else:
                raise PcapngMetadataError("A PCAPNG section has an invalid byte-order magic.")
        if order is None:
            raise PcapngMetadataError("PCAPNG metadata requires a section header before all other blocks.")
        block_type, length = struct.unpack(order + "II", header)
        if length < 12 or length % 4 or offset + length > size:
            raise PcapngMetadataError("A PCAPNG block length is unaligned, too small or outside the saved file.")
        if section_end is not None and not is_section and offset + length > section_end:
            raise PcapngMetadataError("A PCAPNG block crosses its declared section boundary.")
        end = offset + length - 4
        trailer = struct.unpack(order + "I", _read(descriptor, end, 4, deadline, cancellation))[0]
        if trailer != length:
            raise PcapngMetadataError("A PCAPNG block's leading and trailing lengths disagree.")
        if is_section:
            if length < 28:
                raise PcapngMetadataError("A PCAPNG section header is shorter than its required fields.")
            major, minor, declared = struct.unpack(order + "HHq", _read(descriptor, offset + 12, 12, deadline, cancellation))
            if (major, minor) != (1, 0) or declared < -1 or declared >= 0 and declared % 4:
                raise PcapngMetadataError("PCAPNG process metadata requires version 1.0 and a valid declared section length.")
            section_end = None if declared == -1 else offset + length + declared
            if section_end is not None and section_end > size:
                raise PcapngMetadataError("The PCAPNG declared section length exceeds the saved file.")
            processes = []
            interface_count = 0
            for _ in _options(descriptor, offset + 24, end, order, deadline, cancellation):
                pass
        elif block_type == 1:
            if length < 20:
                raise PcapngMetadataError("A PCAPNG interface block lacks its required fixed fields.")
            interface_count += 1
        elif block_type == 0x80000001:
            process_count += 1
            if process_count > maximum_records:
                raise PcapngMetadataLimitError("record_limit", "PCAPNG process blocks exceed the packet index's record ceiling.")
            process = _process(descriptor, offset + 8, end, order, deadline, cancellation)
            estimated_bytes += 96 + sum(64 + len(name.encode("utf-8")) for name in process.names)
            processes.append(process)
        elif block_type in (2, 3, 6):
            packet_count += 1
            if packet_count > maximum_records:
                raise PcapngMetadataLimitError("record_limit", "PCAPNG packet blocks exceed the packet index's record ceiling.")
            if block_type == 6:
                if length < 32:
                    raise PcapngMetadataError("A PCAPNG enhanced packet block lacks its required fixed fields.")
                interface, _, _, captured, original = struct.unpack(order + "IIIII", _read(descriptor, offset + 8, 20, deadline, cancellation))
                if interface >= interface_count or captured > original:
                    raise PcapngMetadataError("A PCAPNG enhanced packet references an unknown interface or exceeds its original length.")
                option_start = offset + 28 + ((captured + 3) & ~3)
                if option_start > end:
                    raise PcapngMetadataError("PCAPNG captured packet bytes cross their block boundary.")
                primary, effective = _references(descriptor, option_start, end, order, processes, deadline, cancellation)
                if primary or effective:
                    frames.append(FrameProcessInformation(packet_count, primary, effective))
                    estimated_bytes += 128 + 16 * (len(primary) + len(effective))
            elif length < (32 if block_type == 2 else 16):
                raise PcapngMetadataError("A PCAPNG packet block lacks its required fixed fields.")
        if estimated_bytes > maximum_estimated_bytes:
            raise PcapngMetadataLimitError("memory_limit", "PCAPNG process metadata exceeds the packet index's estimated storage ceiling.")
        offset += length
    if section_end is not None and offset != section_end:
        raise PcapngMetadataError("The final PCAPNG section does not match its declared length.")
    _check_operation(deadline, cancellation)
    return PcapngProcessIndex(packet_count, tuple(frames), estimated_bytes)


def attach_pcapng_process_metadata(packets: tuple[PacketRecord, ...], metadata: PcapngProcessIndex, maximum_estimated_bytes: int, deadline: float, cancellation: threading.Event) -> tuple[PacketRecord, ...]:
    """Preserve decoder fields and add separately named container observations.

    Populated TShark Apple fields must agree with recorded container values.
    Missing decoder values do not erase authoritative process references. This
    never parses display strings or invents a process from an absent reference.
    """
    if metadata.packet_count != len(packets):
        raise PcapngMetadataError("PCAPNG packet blocks do not match TShark's complete frame count.")
    by_frame = {frame.frame_number: frame for frame in metadata.frames}
    result: list[PacketRecord] = []
    retained = metadata.estimated_bytes
    decoder_fields = ("frame.darwin.process_info.pid", "frame.darwin.process_info.pname", "frame.darwin.process_info.epid", "frame.darwin.process_info.epname")
    for packet in packets:
        _check_operation(deadline, cancellation)
        values = {field.name: field.values for field in packet.fields}
        frame = by_frame.get(packet.frame_number)
        primary = () if frame is None else frame.primary
        effective = () if frame is None else frame.effective
        observations = (
            tuple(str(process.pid) for process in primary),
            tuple(name for process in primary for name in process.names),
            tuple(str(process.pid) for process in effective),
            tuple(name for process in effective for name in process.names),
        )
        names = [field.name for field in packet.fields]
        for container_field, decoder_field, observed in zip(PCAPNG_PROCESS_FIELDS, decoder_fields, observations, strict=True):
            if any(value not in observed for value in values.get(decoder_field, ())):
                raise PcapngMetadataError(f"TShark's Apple process field disagrees with container metadata at frame {packet.frame_number}.")
            if observed:
                values[container_field] = observed
                names.append(container_field)
        reconstructed = decode_packet_fields(values, tuple(names))
        retained += estimated_packet_bytes(reconstructed)
        if retained > maximum_estimated_bytes:
            raise PcapngMetadataLimitError("memory_limit", "Packets and PCAPNG process metadata exceed the index's estimated storage ceiling.")
        result.append(reconstructed)
    return tuple(result)
