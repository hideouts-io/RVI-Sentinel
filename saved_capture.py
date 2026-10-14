"""Bounded, cancellable passive TShark decoding of a stable saved capture."""

from __future__ import annotations

import hashlib
import math
import os
import queue
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Literal

from captured_dns import (
    DNS_MAX_JSON_BYTES, DNS_PROTOCOLS, CapturedDnsCancelled, CapturedDnsEvidence,
    CapturedDnsValidationError, decode_captured_dns,
)
from packet_models import FIELD_NAME, PCAPNG_PROCESS_FIELDS, PacketRecord, PacketValidationError, decode_packet_row, estimated_packet_bytes
from pcapng_process import PcapngMetadataCancelled, PcapngMetadataError, PcapngMetadataLimitError, PcapngProcessIndex, attach_pcapng_process_metadata, read_pcapng_process_metadata

REQUIRED_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
)
PROTOCOL_FIELDS = ("_ws.col.protocol", "_ws.col.Protocol")
OPTIONAL_FIELDS = (
    "frame.cap_len", "frame.interface_name",
    "frame.darwin.process_info.pid", "frame.darwin.process_info.pname",
    "frame.darwin.process_info.epid", "frame.darwin.process_info.epname",
    "frame.packet_flags_direction",
    "pktap.ifname", "pktap.pid", "pktap.cmdname", "pktap.epid", "pktap.ecmdname", "pktap.flags",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.len",
    "udp.srcport", "udp.dstport", "udp.stream",
    "dns.qry.name", "dns.resp.name", "dns.a", "dns.aaaa", "dns.cname", "dns.ptr.domain_name", "dns.resp.ttl",
    "tls.handshake.extensions_server_name", "tls.handshake.version", "tls.handshake.extensions_alpn_str",
    "x509ce.dNSName", "http.host", "http2.headers.authority", "http3.headers.authority",
)


class SavedCaptureError(RuntimeError):
    """A saved-file operation failed; ``code`` identifies its failure boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class SavedCaptureCancelled(SavedCaptureError):
    """The caller cancelled analysis before any completed result was returned."""

    def __init__(self) -> None:
        super().__init__("cancelled", "Saved capture analysis was cancelled; no completed result was returned.")


@dataclass(frozen=True, slots=True)
class SavedAnalysisLimits:
    max_capture_bytes: int
    max_records: int
    max_estimated_bytes: int
    max_line_bytes: int
    max_output_bytes: int
    max_stderr_bytes: int
    max_probe_bytes: int
    probe_timeout_seconds: float
    total_timeout_seconds: float


@dataclass(frozen=True, slots=True)
class SavedStreamLimits:
    """Independent byte/deadline ceilings for streaming artifact verification.

    Streaming consumers do not inherit the optional packet index's record or
    retained-value storage limits. They must validate each row without keeping
    an unbounded collection of previously decoded rows.
    """

    max_capture_bytes: int
    max_line_bytes: int
    max_output_bytes: int
    max_stderr_bytes: int
    max_probe_bytes: int
    probe_timeout_seconds: float
    total_timeout_seconds: float


DecoderLimits = SavedAnalysisLimits | SavedStreamLimits
CaptureFormat = Literal["pcap", "pcapng"]


@dataclass(frozen=True, slots=True)
class SavedCaptureStream:
    capture_format: CaptureFormat
    sha256: str
    size_bytes: int
    tshark_version: str
    fields: tuple[str, ...]


SAVED_ANALYSIS_LIMITS = SavedAnalysisLimits(
    max_capture_bytes=1_073_741_824,
    max_records=200_000,
    max_estimated_bytes=268_435_456,
    max_line_bytes=131_072,
    max_output_bytes=536_870_912,
    max_stderr_bytes=65_536,
    max_probe_bytes=33_554_432,
    probe_timeout_seconds=30.0,
    total_timeout_seconds=300.0,
)


@dataclass(frozen=True, slots=True)
class SavedAnalysis:
    sha256: str
    size_bytes: int
    tshark_version: str
    supported_fields: tuple[str, ...]
    unsupported_fields: tuple[str, ...]
    packets: tuple[PacketRecord, ...]
    dns_evidence: CapturedDnsEvidence
    container_fields: tuple[str, ...]


def read_saved_capture_stream(path: Path, fields: tuple[str, ...], limits: SavedStreamLimits, cancellation: threading.Event, consume: Callable[[bytes], None]) -> SavedCaptureStream:
    """Fully decode stable original bytes into a caller-owned streaming reducer.

    All requested fields are required and negotiated before decoding. This
    connector brackets the completed child process with original-descriptor
    identity checks and byte hashes. It does not retain packet rows or impose
    packet-index retention limits. The reducer must enforce row/field validity.
    """
    _validate_decoder_limits(limits)
    if not fields or len(fields) > 128 or len(set(fields)) != len(fields) or any(FIELD_NAME.fullmatch(name) is None for name in fields):
        raise SavedCaptureError("invalid_fields", "Streaming capture fields must be unique bounded decoder abbreviations.")
    deadline = time.monotonic() + limits.total_timeout_seconds
    _check_operation(deadline, cancellation)
    original = _capture_identity(path, limits.max_capture_bytes)
    descriptor = _open_capture(path, original)
    try:
        capture_format = _capture_format(descriptor)
        before = _hash_capture(descriptor, limits.max_capture_bytes, deadline, cancellation)
        _verify_capture(path, descriptor, original, limits.max_capture_bytes)
        executable = shutil.which("tshark")
        if executable is None:
            raise SavedCaptureError("decoder_unavailable", "TShark was not found. Install Wireshark/TShark and make tshark available on PATH.")
        version = _probe_version(executable, limits, deadline, cancellation)
        catalog = _probe_fields(executable, limits, deadline, cancellation)
        missing = tuple(name for name in fields if name not in catalog)
        if missing:
            raise SavedCaptureError("required_fields_missing", "The installed TShark lacks required artifact fields: " + ", ".join(missing) + ". Install a compatible Wireshark/TShark version.")
        arguments = ("-n", "-r", "-", "-T", "fields", "-E", "header=n", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=\x1e") + tuple(value for name in fields for value in ("-e", name))
        _run_decoder(executable, arguments, limits.max_output_bytes, limits.max_stderr_bytes, deadline, cancellation, consume, descriptor)
        _verify_capture(path, descriptor, original, limits.max_capture_bytes)
        after = _hash_capture(descriptor, limits.max_capture_bytes, deadline, cancellation)
        _verify_capture(path, descriptor, original, limits.max_capture_bytes)
        if before != after:
            raise SavedCaptureError("changed_capture", "The original capture changed during verification. Reopen a stable saved file before reviewing it.")
        _check_operation(deadline, cancellation)
        result = SavedCaptureStream(capture_format, after, original.size, version, fields)
    except BaseException as error:
        try:
            _close_capture(descriptor)
        except SavedCaptureError as cleanup_error:
            raise SavedCaptureError("capture_cleanup_failed", f"Capture descriptor cleanup failed after {type(error).__name__}: {cleanup_error}.") from error
        raise
    _close_capture(descriptor)
    return result


def _capture_format(descriptor: int) -> CaptureFormat:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        header = os.read(descriptor, 4)
    except OSError as error:
        raise SavedCaptureError("capture_read_failed", f"The saved capture header could not be read (OS error {error.errno}). Check readability.") from error
    if header == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    if header in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "pcap"
    raise SavedCaptureError("unsupported_capture_format", "The saved artifact is not a recognized PCAP or PCAPNG container. Choose the completed original capture.")


@dataclass(frozen=True, slots=True)
class _CaptureIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


PipeName = Literal["stdout", "stderr"]


@dataclass(frozen=True, slots=True)
class _PipeChunk:
    pipe: PipeName
    data: bytes


@dataclass(frozen=True, slots=True)
class _PipeFinished:
    pipe: PipeName


@dataclass(frozen=True, slots=True)
class _PipeFailure:
    pipe: PipeName
    error: OSError


PipeEvent = _PipeChunk | _PipeFinished | _PipeFailure


def read_saved_capture(path: Path, limits: SavedAnalysisLimits, cancellation: threading.Event) -> SavedAnalysis:
    """Read an original in place; hashes/identity bracket passive decoding.

    No resolver or capture command is launched. Source labels describe recorded
    metadata, never independently verified device/process ownership. Limits are
    explicit failure ceilings rather than measured capacity or responsiveness.
    """
    _validate_limits(limits)
    deadline = time.monotonic() + limits.total_timeout_seconds
    _check_operation(deadline, cancellation)
    original = _capture_identity(path, limits.max_capture_bytes)
    descriptor = _open_capture(path, original)
    try:
        before = _hash_capture(descriptor, limits.max_capture_bytes, deadline, cancellation)
        _verify_capture(path, descriptor, original, limits.max_capture_bytes)
        container_format = _capture_format(descriptor)
        process_metadata: PcapngProcessIndex | None = None
        if container_format == "pcapng":
            try:
                process_metadata = read_pcapng_process_metadata(descriptor, limits.max_records, limits.max_estimated_bytes, deadline, cancellation)
            except PcapngMetadataCancelled as error:
                raise SavedCaptureCancelled() from error
            except PcapngMetadataLimitError as error:
                raise SavedCaptureError(error.code, str(error)) from error
            except PcapngMetadataError as error:
                raise SavedCaptureError("invalid_pcapng_metadata", f"PCAPNG container process metadata is invalid: {error}") from error
            _verify_capture(path, descriptor, original, limits.max_capture_bytes)
        executable = shutil.which("tshark")
        if executable is None:
            raise SavedCaptureError("decoder_unavailable", "TShark was not found. Install Wireshark/TShark and make tshark available on PATH.")
        version = _probe_version(executable, limits, deadline, cancellation)
        catalog = _probe_fields(executable, limits, deadline, cancellation)
        missing = tuple(name for name in REQUIRED_FIELDS if name not in catalog)
        protocol_field = next((name for name in PROTOCOL_FIELDS if name in catalog), None)
        if protocol_field is None:
            missing += ("protocol column (_ws.col.protocol or _ws.col.Protocol)",)
        if missing or protocol_field is None:
            raise SavedCaptureError("required_fields_missing", "The installed TShark lacks required saved-packet fields: " + ", ".join(missing) + ". Install a compatible Wireshark/TShark version.")
        selected = tuple(name for name in REQUIRED_FIELDS + (protocol_field,) + OPTIONAL_FIELDS if name in catalog)
        unsupported = tuple(name for name in OPTIONAL_FIELDS if name not in catalog)
        stream = _PacketStream(selected, limits, deadline, cancellation)
        arguments = ("-n", "-r", "-", "-T", "fields", "-E", "header=n", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a", "-E", "aggregator=\x1e") + tuple(value for name in selected for value in ("-e", name))
        _run_decoder(executable, arguments, limits.max_output_bytes, limits.max_stderr_bytes, deadline, cancellation, stream.consume, descriptor)
        packets = stream.finish()
        if not packets:
            raise SavedCaptureError("empty_capture", "TShark decoded zero packets. Choose a nonempty, complete saved PCAP or PCAPNG capture.")
        if process_metadata is not None:
            try:
                packets = attach_pcapng_process_metadata(packets, process_metadata, limits.max_estimated_bytes, deadline, cancellation)
            except PcapngMetadataCancelled as error:
                raise SavedCaptureCancelled() from error
            except PcapngMetadataLimitError as error:
                raise SavedCaptureError(error.code, str(error)) from error
            except (PcapngMetadataError, PacketValidationError) as error:
                raise SavedCaptureError("invalid_pcapng_metadata", f"PCAPNG process observations do not match saved-frame evidence: {error}") from error
        _verify_capture(path, descriptor, original, limits.max_capture_bytes)
        dns_evidence = CapturedDnsEvidence(before, ())
        if any(protocol in packet.protocol_stack for packet in packets for protocol in DNS_PROTOCOLS):
            dns_output: list[bytes] = []
            dns_arguments = ("-n", "-r", "-", "-Y", "dns || mdns || llmnr", "-T", "json", "--no-duplicate-keys", "-J", "frame dns mdns llmnr")
            _run_decoder(executable, dns_arguments, min(DNS_MAX_JSON_BYTES, limits.max_output_bytes), limits.max_stderr_bytes, deadline, cancellation, dns_output.append, descriptor)
            _verify_capture(path, descriptor, original, limits.max_capture_bytes)
            try:
                dns_evidence = decode_captured_dns(b"".join(dns_output), before, packets, cancellation)
            except CapturedDnsCancelled as error:
                raise SavedCaptureCancelled() from error
            except CapturedDnsValidationError as error:
                raise SavedCaptureError("invalid_dns_evidence", f"Structured DNS evidence is invalid: {error} Reimport the original capture or check the installed TShark version.") from error
            _check_operation(deadline, cancellation)
        _verify_capture(path, descriptor, original, limits.max_capture_bytes)
        after = _hash_capture(descriptor, limits.max_capture_bytes, deadline, cancellation)
        _verify_capture(path, descriptor, original, limits.max_capture_bytes)
        if before != after:
            raise SavedCaptureError("changed_capture", "The original capture changed during analysis. Reopen a stable saved file before reviewing its packets.")
        _check_operation(deadline, cancellation)
        analysis = SavedAnalysis(after, original.size, version, selected, unsupported, packets, dns_evidence, PCAPNG_PROCESS_FIELDS if process_metadata is not None else ())
    except BaseException as error:
        try:
            _close_capture(descriptor)
        except SavedCaptureError as cleanup_error:
            raise SavedCaptureError(
                "capture_cleanup_failed",
                f"Capture descriptor cleanup failed after {type(error).__name__}: {cleanup_error}.",
            ) from error
        raise
    _close_capture(descriptor)
    return analysis


def _close_capture(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError as error:
        raise SavedCaptureError(
            "capture_cleanup_failed",
            f"The saved capture descriptor could not be closed (OS error {error.errno}).",
        ) from error


def _validate_limits(limits: SavedAnalysisLimits) -> None:
    _validate_decoder_limits(limits)
    integers = (limits.max_records, limits.max_estimated_bytes)
    if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in integers):
        raise SavedCaptureError("invalid_limits", "Saved analysis record and retained-value limits must be positive.")


def _validate_decoder_limits(limits: DecoderLimits) -> None:
    integers = (limits.max_capture_bytes, limits.max_line_bytes, limits.max_output_bytes, limits.max_stderr_bytes, limits.max_probe_bytes)
    durations = (limits.probe_timeout_seconds, limits.total_timeout_seconds)
    if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in integers) or any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0 for value in durations):
        raise SavedCaptureError("invalid_limits", "Saved analysis byte/record limits and finite deadlines must be positive.")


def _check_operation(deadline: float, cancellation: threading.Event) -> None:
    if cancellation.is_set():
        raise SavedCaptureCancelled()
    if time.monotonic() >= deadline:
        raise SavedCaptureError(
            "deadline_exceeded",
            "Saved analysis exceeded its operation deadline. Check TShark responsiveness and choose a smaller capture or an explicitly reviewed analysis limit.",
        )


def _identity(info: os.stat_result, maximum: int) -> _CaptureIdentity:
    if not stat.S_ISREG(info.st_mode):
        raise SavedCaptureError("invalid_capture", "Saved analysis requires a regular local file; links, directories and special files are not accepted.")
    if info.st_size <= 0:
        raise SavedCaptureError("empty_capture", "The saved capture is empty. Choose a completed nonempty capture.")
    if info.st_size > maximum:
        raise SavedCaptureError("capture_limit", f"The saved capture exceeds the {maximum}-byte analysis limit. Choose a smaller capture.")
    return _CaptureIdentity(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _capture_identity(path: Path, maximum: int) -> _CaptureIdentity:
    try:
        return _identity(path.lstat(), maximum)
    except OSError as error:
        raise SavedCaptureError("capture_unavailable", f"The saved capture could not be inspected (OS error {error.errno}). Choose an existing readable local capture.") from error


def _open_capture(path: Path, expected: _CaptureIdentity) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SavedCaptureError("capture_unavailable", f"The saved capture could not be opened (OS error {error.errno}). Check its permissions and choose a stable regular file.") from error
    try:
        opened = _identity(os.fstat(descriptor), expected.size)
        if opened != expected:
            raise SavedCaptureError("changed_capture", "The saved capture changed while being opened. Reopen a stable original before analysis.")
    except BaseException as error:
        try:
            _close_capture(descriptor)
        except SavedCaptureError as cleanup_error:
            raise SavedCaptureError(
                "capture_cleanup_failed",
                f"Capture descriptor cleanup failed after {type(error).__name__}: {cleanup_error}.",
            ) from error
        raise
    return descriptor


def _verify_capture(path: Path, descriptor: int, expected: _CaptureIdentity, maximum: int) -> None:
    try:
        opened = _identity(os.fstat(descriptor), maximum)
        current = _capture_identity(path, maximum)
    except OSError as error:
        raise SavedCaptureError("capture_unavailable", f"The original capture could not be rechecked (OS error {error.errno}). Restore it and reimport before reviewing packets.") from error
    if opened != expected or current != expected:
        raise SavedCaptureError("changed_capture", "The original capture's identity, size or modification metadata changed during analysis. Reopen a stable saved file.")


def _hash_capture(descriptor: int, maximum: int, deadline: float, cancellation: threading.Event) -> str:
    digest = hashlib.sha256()
    count = 0
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            _check_operation(deadline, cancellation)
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            count += len(chunk)
            if count > maximum:
                raise SavedCaptureError("capture_limit", f"Capture hashing exceeded the {maximum}-byte limit. Choose a stable smaller original.")
            digest.update(chunk)
    except OSError as error:
        raise SavedCaptureError("capture_read_failed", f"The original capture could not be hashed (OS error {error.errno}). Check readability and reimport the original.") from error
    return digest.hexdigest()


def _probe_version(executable: str, limits: DecoderLimits, deadline: float, cancellation: threading.Event) -> str:
    output: list[bytes] = []
    _run_decoder(executable, ("--version",), limits.max_probe_bytes, limits.max_stderr_bytes, min(deadline, time.monotonic() + limits.probe_timeout_seconds), cancellation, output.append, None)
    try:
        lines = b"".join(output).decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise SavedCaptureError("invalid_decoder_version", "TShark returned a non-UTF-8 version identifier. Check the installed decoder.") from error
    if not lines or not lines[0].strip() or len(lines[0].encode("utf-8")) > 512 or any(ord(character) < 32 or ord(character) == 127 for character in lines[0]):
        raise SavedCaptureError("invalid_decoder_version", "TShark returned no valid bounded version identifier. Check the installed decoder.")
    return lines[0]


def _probe_fields(executable: str, limits: DecoderLimits, deadline: float, cancellation: threading.Event) -> frozenset[str]:
    output: list[bytes] = []
    _run_decoder(executable, ("-G", "fields"), limits.max_probe_bytes, limits.max_stderr_bytes, min(deadline, time.monotonic() + limits.probe_timeout_seconds), cancellation, output.append, None)
    try:
        text = b"".join(output).decode("utf-8")
    except UnicodeDecodeError as error:
        raise SavedCaptureError("invalid_field_catalog", "TShark returned a non-UTF-8 field catalog. Check the installed decoder.") from error
    catalog = frozenset(columns[2] for line in text.splitlines() if len(columns := line.split("\t")) > 2 and columns[0] == "F" and columns[2])
    if not catalog:
        raise SavedCaptureError("invalid_field_catalog", "TShark returned no decoder field definitions. Check the installed decoder before analyzing.")
    return catalog


class _PacketStream:
    """Own the bounded byte-to-row stream at the external decoder boundary."""

    def __init__(self, fields: tuple[str, ...], limits: SavedAnalysisLimits, deadline: float, cancellation: threading.Event) -> None:
        self.fields = fields
        self.limits = limits
        self.deadline = deadline
        self.cancellation = cancellation
        self.pending = bytearray()
        self.records: list[PacketRecord] = []
        self.frames: set[int] = set()
        self.estimated_bytes = 0

    def consume(self, chunk: bytes) -> None:
        _check_operation(self.deadline, self.cancellation)
        self.pending.extend(chunk)
        while True:
            boundary = self.pending.find(b"\n")
            if boundary < 0:
                break
            line = bytes(self.pending[:boundary])
            del self.pending[:boundary + 1]
            self._consume_line(line)
        if len(self.pending) > self.limits.max_line_bytes:
            raise SavedCaptureError("line_limit", f"A TShark row exceeds the {self.limits.max_line_bytes}-byte limit. Choose a narrower capture.")

    def _consume_line(self, line: bytes) -> None:
        _check_operation(self.deadline, self.cancellation)
        if len(line) > self.limits.max_line_bytes:
            raise SavedCaptureError("line_limit", f"A TShark row exceeds the {self.limits.max_line_bytes}-byte limit. Choose a narrower capture.")
        if len(self.records) >= self.limits.max_records:
            raise SavedCaptureError("record_limit", f"Packet indexing exceeded its {self.limits.max_records}-record limit. Choose a smaller capture.")
        try:
            record = decode_packet_row(line.decode("utf-8"), self.fields)
        except (PacketValidationError, UnicodeDecodeError) as error:
            raise SavedCaptureError("invalid_row", f"TShark packet row {len(self.records) + 1} is invalid: {error}. Reimport the original or check the decoder version.") from error
        if record.frame_number in self.frames:
            raise SavedCaptureError("duplicate_frame", f"TShark repeated frame {record.frame_number}; packet identity is ambiguous. Reimport the original.")
        if record.frame_number != len(self.records) + 1:
            raise SavedCaptureError("frame_sequence", "TShark did not return the complete contiguous saved-frame sequence. Reimport the original before reviewing its packets.")
        estimate = self.estimated_bytes + estimated_packet_bytes(record)
        if estimate > self.limits.max_estimated_bytes:
            raise SavedCaptureError("memory_limit", f"Packet indexing exceeded its {self.limits.max_estimated_bytes}-byte estimated storage limit. Choose a smaller capture.")
        self.records.append(record)
        self.frames.add(record.frame_number)
        self.estimated_bytes = estimate

    def finish(self) -> tuple[PacketRecord, ...]:
        if self.pending:
            self._consume_line(bytes(self.pending))
            self.pending.clear()
        _check_operation(self.deadline, self.cancellation)
        records = tuple(sorted(self.records, key=lambda record: (record.timestamp.seconds, record.timestamp.nanoseconds, record.frame_number)))
        _check_operation(self.deadline, self.cancellation)
        return records


def _publish_event(events: queue.Queue[PipeEvent], event: PipeEvent, stopped: threading.Event) -> None:
    while not stopped.is_set():
        try:
            events.put(event, timeout=0.05)
            return
        except queue.Full:
            continue


def _read_pipe(pipe: BinaryIO, name: PipeName, events: queue.Queue[PipeEvent], stopped: threading.Event) -> None:
    try:
        while not stopped.is_set():
            chunk = pipe.read(65_536)
            if not chunk:
                _publish_event(events, _PipeFinished(name), stopped)
                return
            _publish_event(events, _PipeChunk(name, chunk), stopped)
    except OSError as error:
        _publish_event(events, _PipeFailure(name, error), stopped)


def _run_decoder(executable: str, arguments: tuple[str, ...], maximum_output_bytes: int, maximum_stderr_bytes: int, deadline: float, cancellation: threading.Event, consume: Callable[[bytes], None], input_descriptor: int | None) -> bytes:
    """Drain both pipes while capture children read the pinned original descriptor.

    Rewind each capture pass immediately before spawning it. Reopening the source
    pathname would allow a replaced parent directory to change the decoded bytes
    without changing the descriptor used for the integrity hashes. Capability
    probes have no capture input. Every exit closes and joins owned pipe readers.
    """
    _check_operation(deadline, cancellation)
    if input_descriptor is not None:
        try:
            os.lseek(input_descriptor, 0, os.SEEK_SET)
        except OSError as error:
            raise SavedCaptureError("capture_read_failed", f"The original capture descriptor could not be rewound for decoding (OS error {error.errno}). Reopen a stable readable saved file.") from error
    try:
        process = subprocess.Popen((executable,) + arguments, stdin=input_descriptor if input_descriptor is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    except OSError as error:
        raise SavedCaptureError("decoder_launch_failed", f"TShark could not be launched (OS error {error.errno}). Check the installed executable and permissions.") from error
    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        process.kill()
        process.wait(timeout=2)
        raise SavedCaptureError("decoder_pipe_failed", "TShark did not create both required output pipes.")
    events: queue.Queue[PipeEvent] = queue.Queue(maxsize=8)
    stopped = threading.Event()
    readers = (
        threading.Thread(target=_read_pipe, args=(stdout, "stdout", events, stopped), name="rvi-saved-stdout"),
        threading.Thread(target=_read_pipe, args=(stderr, "stderr", events, stopped), name="rvi-saved-stderr"),
    )
    started: list[threading.Thread] = []
    error_bytes = bytearray()
    output_count = 0
    finished: set[PipeName] = set()
    try:
        for reader in readers:
            reader.start()
            started.append(reader)
        while len(finished) < 2 or process.poll() is None:
            _check_operation(deadline, cancellation)
            try:
                event = events.get(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if isinstance(event, _PipeFailure):
                raise SavedCaptureError("decoder_read_failed", f"TShark {event.pipe} could not be read (OS error {event.error.errno}).") from event.error
            if isinstance(event, _PipeFinished):
                finished.add(event.pipe)
                continue
            if event.pipe == "stdout":
                output_count += len(event.data)
                if output_count > maximum_output_bytes:
                    raise SavedCaptureError("output_limit", f"TShark output exceeded the {maximum_output_bytes}-byte limit. Choose a smaller capture.")
                consume(event.data)
            else:
                if len(error_bytes) + len(event.data) > maximum_stderr_bytes:
                    raise SavedCaptureError("stderr_limit", f"TShark diagnostics exceeded the {maximum_stderr_bytes}-byte limit. Check the decoder and choose a smaller capture.")
                error_bytes.extend(event.data)
        return_code = process.wait(timeout=0.1)
        if return_code != 0:
            detail = _decoder_failure_reason(bytes(error_bytes))
            raise SavedCaptureError("decoder_failed", f"TShark failed with exit code {return_code}: {detail}. Check capture completeness and decoder compatibility.")
        _check_operation(deadline, cancellation)
    except BaseException as error:
        stopped.set()
        try:
            _cleanup_decoder(process, tuple(started), stdout, stderr)
        except (OSError, subprocess.TimeoutExpired, SavedCaptureError) as cleanup_error:
            raise SavedCaptureError("decoder_cleanup_failed", f"TShark cleanup failed after {type(error).__name__}: {cleanup_error}.") from error
        raise
    stopped.set()
    _cleanup_decoder(process, tuple(started), stdout, stderr)
    return bytes(error_bytes)


def _cleanup_decoder(process: subprocess.Popen[bytes], readers: tuple[threading.Thread, ...], stdout: BinaryIO, stderr: BinaryIO) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    unjoined: list[str] = []
    for reader in readers:
        reader.join(timeout=2)
        if reader.is_alive():
            unjoined.append(reader.name)
    stdout.close()
    stderr.close()
    if unjoined:
        raise SavedCaptureError(
            "decoder_cleanup_failed",
            "TShark pipe readers did not stop after process termination: " + ", ".join(unjoined),
        )


def _decoder_failure_reason(data: bytes) -> str:
    """Classify bounded diagnostics without exposing paths or packet snippets."""
    text = data.decode("utf-8", errors="replace").lower()
    if "cut short" in text or "truncated" in text:
        return "the decoder reported an incomplete or truncated capture"
    if "isn't a capture file" in text or "not a capture file" in text:
        return "the decoder did not recognize a supported capture format"
    if "permission denied" in text:
        return "the decoder could not read the capture because access was denied"
    if "some fields aren't valid" in text or "not a valid field" in text:
        return "the decoder rejected a requested field after capability negotiation"
    if "couldn't open" in text or "no such file" in text:
        return "the decoder could not open the saved capture"
    return "the decoder reported an unsuccessful operation; raw diagnostic contents are withheld"
