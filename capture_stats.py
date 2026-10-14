#!/usr/bin/env python3
"""Fully validate stable saved artifacts with constant-storage packet statistics."""

from __future__ import annotations

import argparse
import csv
import json
import signal
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import TypedDict

from packet_models import PacketTimestamp, PacketValidationError, decode_packet_timestamp
from saved_capture import CaptureFormat, SavedCaptureError, SavedStreamLimits, read_saved_capture_stream

ARTIFACT_FIELDS = ("frame.number", "frame.time_epoch", "frame.len", "frame.cap_len")
CAPTURE_VALIDATION_LIMITS = SavedStreamLimits(
    max_capture_bytes=8_589_934_592,
    max_line_bytes=4_096,
    max_output_bytes=4_294_967_296,
    max_stderr_bytes=65_536,
    max_probe_bytes=33_554_432,
    probe_timeout_seconds=30.0,
    total_timeout_seconds=1_800.0,
)


@dataclass(frozen=True, slots=True)
class CaptureArtifact:
    """Verified original-byte identity and a complete readable frame reduction.

    ``positive_packet_count`` counts frames with observed captured bytes. A
    zero-length frame remains valid frame evidence but does not prove positive
    traffic capture. Packet timestamp span is distinct from recording lifetime.
    Neither this receipt nor hashing establishes the file's origin or device.
    """

    capture_format: CaptureFormat
    sha256: str
    size_bytes: int
    packet_count: int
    positive_packet_count: int
    first_packet_epoch: str
    last_packet_epoch: str
    packet_span_nanoseconds: int
    tshark_version: str


class ArtifactDocument(TypedDict):
    capture_format: CaptureFormat
    sha256: str
    size_bytes: int
    packet_count: int
    positive_packet_count: int
    first_packet_epoch: str
    last_packet_epoch: str
    packet_span_nanoseconds: int
    tshark_version: str


class StatisticsDocument(ArtifactDocument):
    packet_span_seconds: float
    requested_duration_seconds: None
    recording_lifetime_seconds: None


def validate_capture_artifact(path: Path, expected_format: str, cancellation: threading.Event) -> CaptureArtifact:
    """Verify the entire stable file and require its actual requested container.

    A successful decoder exit, contiguous validated frames, stable descriptor
    identity, and matching before/after SHA-256 are all required. Header-only
    captures fail; readable zero-length frames remain explicitly distinguishable
    through ``positive_packet_count`` for the guided workflow's traffic policy.
    """
    if expected_format not in ("pcap", "pcapng"):
        raise SavedCaptureError("invalid_capture_format", "Artifact validation requires an explicit pcap or pcapng format.")
    artifact = inspect_capture_artifact(path, cancellation)
    if artifact.capture_format != expected_format:
        raise SavedCaptureError("capture_format_mismatch", f"The completed artifact contains {artifact.capture_format}, but {expected_format} was requested. Select the correct recording format and capture again.")
    return artifact


def inspect_capture_artifact(path: Path, cancellation: threading.Event) -> CaptureArtifact:
    """Inspect an imported artifact without inventing recording lifetime.

    Independent streaming limits allow more than the packet index's 200,000
    retained records. They are explicit failure ceilings, not measured capacity
    claims. The reducer retains only a partial row, counts, and two timestamps.
    """
    stream = _ArtifactStream(CAPTURE_VALIDATION_LIMITS.max_line_bytes, cancellation)
    verified = read_saved_capture_stream(path, ARTIFACT_FIELDS, CAPTURE_VALIDATION_LIMITS, cancellation, stream.consume)
    count, positive_count, first, last = stream.finish()
    span = (last.seconds - first.seconds) * 1_000_000_000 + last.nanoseconds - first.nanoseconds
    return CaptureArtifact(verified.capture_format, verified.sha256, verified.size_bytes, count, positive_count, first.epoch, last.epoch, span, verified.tshark_version)


def capture_statistics(path: Path) -> tuple[int, float | None]:
    """Preserve the legacy tuple API; its second value is packet span seconds.

    The value is never recording duration. New callers should consume the typed
    artifact instead, including exact integer span and original-byte identity.
    """
    artifact = inspect_capture_artifact(path, threading.Event())
    return artifact.packet_count, artifact.packet_span_nanoseconds / 1_000_000_000


def capture_artifact_document(artifact: CaptureArtifact) -> ArtifactDocument:
    """Serialize the typed original-byte artifact without additional inference."""
    return {
        "capture_format": artifact.capture_format,
        "sha256": artifact.sha256,
        "size_bytes": artifact.size_bytes,
        "packet_count": artifact.packet_count,
        "positive_packet_count": artifact.positive_packet_count,
        "first_packet_epoch": artifact.first_packet_epoch,
        "last_packet_epoch": artifact.last_packet_epoch,
        "packet_span_nanoseconds": artifact.packet_span_nanoseconds,
        "tshark_version": artifact.tshark_version,
    }


def statistics_document(artifact: CaptureArtifact) -> StatisticsDocument:
    """Name packet span explicitly; imported recording timing is unavailable."""
    return {
        **capture_artifact_document(artifact),
        "packet_span_seconds": artifact.packet_span_nanoseconds / 1_000_000_000,
        "requested_duration_seconds": None,
        "recording_lifetime_seconds": None,
    }


def _frame_integer(text: str, name: str, maximum: int) -> int:
    if not text or not text.isascii() or not text.isdecimal() or len(text) > 20:
        raise PacketValidationError(f"{name} requires one unsigned decimal integer.")
    value = int(text)
    if value > maximum:
        raise PacketValidationError(f"{name} exceeds its permitted range.")
    return value


def _decode_frame(line: bytes) -> tuple[int, PacketTimestamp, int, int]:
    try:
        columns = next(csv.reader([line.decode("utf-8")], delimiter="\t", quotechar='"', strict=True))
    except (csv.Error, StopIteration, UnicodeDecodeError) as error:
        raise PacketValidationError("TShark returned an invalid UTF-8 quoted TSV artifact row.") from error
    if len(columns) != len(ARTIFACT_FIELDS):
        raise PacketValidationError("TShark returned a different column count than the requested artifact fields.")
    frame = _frame_integer(columns[0], "frame.number", 2**64 - 1)
    if frame == 0:
        raise PacketValidationError("frame.number starts at 1.")
    timestamp = decode_packet_timestamp(columns[1])
    wire_length = _frame_integer(columns[2], "frame.len", 2**32 - 1)
    captured_length = _frame_integer(columns[3], "frame.cap_len", 2**32 - 1)
    if captured_length > wire_length:
        raise PacketValidationError("frame.cap_len exceeds frame.len.")
    return frame, timestamp, wire_length, captured_length


class _ArtifactStream:
    """Own the bounded byte-to-row connector state without retaining packets."""

    def __init__(self, maximum_line_bytes: int, cancellation: threading.Event) -> None:
        self.maximum_line_bytes = maximum_line_bytes
        self.cancellation = cancellation
        self.pending = bytearray()
        self.count = 0
        self.positive_count = 0
        self.first: PacketTimestamp | None = None
        self.last: PacketTimestamp | None = None

    def consume(self, chunk: bytes) -> None:
        self.pending.extend(chunk)
        while True:
            boundary = self.pending.find(b"\n")
            if boundary < 0:
                break
            line = bytes(self.pending[:boundary])
            del self.pending[:boundary + 1]
            self._consume_line(line)
        if len(self.pending) > self.maximum_line_bytes:
            raise SavedCaptureError("line_limit", f"A TShark artifact row exceeds the {self.maximum_line_bytes}-byte validation limit.")

    def _consume_line(self, line: bytes) -> None:
        if self.cancellation.is_set():
            raise SavedCaptureError("cancelled", "Capture artifact verification was cancelled; no completed artifact was returned.")
        if len(line) > self.maximum_line_bytes:
            raise SavedCaptureError("line_limit", f"A TShark artifact row exceeds the {self.maximum_line_bytes}-byte validation limit.")
        try:
            frame, timestamp, _wire_length, captured_length = _decode_frame(line)
        except PacketValidationError as error:
            raise SavedCaptureError("invalid_row", f"TShark artifact row {self.count + 1} is invalid: {error}. Check capture completeness and decoder compatibility.") from error
        if frame != self.count + 1:
            raise SavedCaptureError("frame_sequence", "TShark did not return the complete contiguous saved-frame sequence. Reopen the completed original capture.")
        self.count += 1
        self.positive_count += int(captured_length > 0)
        key = (timestamp.seconds, timestamp.nanoseconds)
        if self.first is None or key < (self.first.seconds, self.first.nanoseconds):
            self.first = timestamp
        if self.last is None or key > (self.last.seconds, self.last.nanoseconds):
            self.last = timestamp

    def finish(self) -> tuple[int, int, PacketTimestamp, PacketTimestamp]:
        if self.pending:
            self._consume_line(bytes(self.pending))
            self.pending.clear()
        if self.cancellation.is_set():
            raise SavedCaptureError("cancelled", "Capture artifact verification was cancelled; no completed artifact was returned.")
        if self.first is None or self.last is None or self.count == 0:
            raise SavedCaptureError("empty_capture", "TShark decoded zero frames. The capture is header-only or contains no readable packet records.")
        return self.count, self.positive_count, self.first, self.last


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Completely validate a stable saved PCAP/PCAPNG and report exact packet span.")
    parser.add_argument("capture", type=Path)
    args = parser.parse_args(arguments)
    cancellation = threading.Event()

    def request_cancel(_signal: int, _frame: FrameType | None) -> None:
        cancellation.set()

    signal.signal(signal.SIGINT, request_cancel)
    signal.signal(signal.SIGTERM, request_cancel)
    try:
        artifact = inspect_capture_artifact(args.capture, cancellation)
    except SavedCaptureError as error:
        print(f"Capture artifact validation failed [{error.code}]: {error}", file=sys.stderr)
        return 2
    print(json.dumps(statistics_document(artifact), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
