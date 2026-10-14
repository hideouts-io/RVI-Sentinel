#!/usr/bin/env python3
"""Immutable final capture outcomes, with strict validation at the GUI boundary.

Recording, full-file readability, and resource teardown are independent facts.
A receipt is emitted only after owned-resource cleanup has been attempted. Its
request nonce and exact absolute output path bind it to one guided operation;
the artifact digest binds subsequent passive inspection to the verified bytes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypedDict

from capture_stats import ArtifactDocument, CaptureArtifact, capture_artifact_document
from packet_models import decode_packet_timestamp

CAPTURE_RECEIPT_EVENT = "RVI_SENTINEL_EVENT capture_receipt "
MAXIMUM_RECEIPT_BYTES = 65_536
CaptureOutcome = Literal["completed", "cancelled", "failed"]
ValidationStatus = Literal["verified", "failed", "not_attempted"]
InterfaceStatus = Literal["verified_complete", "failed", "unverified", "not_applicable"]
FailureStage = Literal["capture", "validation", "cleanup"]


class CaptureReceiptError(ValueError):
    """A receipt is malformed, internally inconsistent, or belongs to another request."""


@dataclass(frozen=True)
class CaptureFailure:
    stage: FailureStage
    code: str
    message: str


@dataclass(frozen=True)
class CaptureCleanup:
    recording_process_stopped: bool | None
    interface_status: InterfaceStatus


@dataclass(frozen=True)
class CaptureReceipt:
    request_id: str
    output_path: Path
    requested_format: str
    requested_duration_seconds: int
    recording_lifetime_nanoseconds: int | None
    capture_outcome: CaptureOutcome
    validation_status: ValidationStatus
    artifact: CaptureArtifact | None
    cleanup: CaptureCleanup
    failures: tuple[CaptureFailure, ...]


class FailureDocument(TypedDict):
    stage: str
    code: str
    message: str


class CleanupDocument(TypedDict):
    recording_process_stopped: bool | None
    interface_status: str


class CaptureReceiptDocument(TypedDict):
    schema_version: int
    request_id: str
    output_path: str
    requested_format: str
    requested_duration_seconds: int
    recording_lifetime_nanoseconds: int | None
    capture_outcome: str
    validation_status: str
    artifact: ArtifactDocument | None
    cleanup: CleanupDocument
    failures: list[FailureDocument]


def receipt_document(receipt: CaptureReceipt) -> CaptureReceiptDocument:
    artifact = receipt.artifact
    artifact_document: ArtifactDocument | None = None
    if artifact is not None:
        artifact_document = capture_artifact_document(artifact)
    return {
        "schema_version": 1,
        "request_id": receipt.request_id,
        "output_path": str(receipt.output_path),
        "requested_format": receipt.requested_format,
        "requested_duration_seconds": receipt.requested_duration_seconds,
        "recording_lifetime_nanoseconds": receipt.recording_lifetime_nanoseconds,
        "capture_outcome": receipt.capture_outcome,
        "validation_status": receipt.validation_status,
        "artifact": artifact_document,
        "cleanup": {
            "recording_process_stopped": receipt.cleanup.recording_process_stopped,
            "interface_status": receipt.cleanup.interface_status,
        },
        "failures": [{"stage": failure.stage, "code": failure.code, "message": failure.message}
                     for failure in receipt.failures],
    }


def receipt_event(receipt: CaptureReceipt) -> str:
    """Serialize one validated final receipt for the existing line event stream."""
    payload = json.dumps(receipt_document(receipt), separators=(",", ":"), allow_nan=False)
    parse_capture_receipt(payload)
    return CAPTURE_RECEIPT_EVENT + payload


def _mapping(value: object, keys: set[str], context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CaptureReceiptError(f"{context} must be an object.")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise CaptureReceiptError(f"{context} must have string keys.")
        result[key] = item
    if set(result) != keys:
        raise CaptureReceiptError(f"{context} has missing or unsupported fields.")
    return result


def _text(value: object, context: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CaptureReceiptError(f"{context} must be a bounded nonempty string.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise CaptureReceiptError(f"{context} contains control characters.")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise CaptureReceiptError(f"{context} contains invalid Unicode.") from error
    return value


def _integer(value: object, context: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise CaptureReceiptError(f"{context} must be an integer from {minimum} to {maximum}.")
    return value


def _format(value: object, context: str) -> Literal["pcap", "pcapng"]:
    if value == "pcap":
        return "pcap"
    if value == "pcapng":
        return "pcapng"
    raise CaptureReceiptError(f"{context} must be pcap or pcapng.")


def _artifact(value: object) -> CaptureArtifact:
    mapping = _mapping(value, set(ArtifactDocument.__annotations__), "artifact")
    capture_format = _format(mapping["capture_format"], "artifact.capture_format")
    digest = _text(mapping["sha256"], "artifact.sha256", 64)
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise CaptureReceiptError("artifact.sha256 must be a lowercase SHA-256 digest.")
    size = _integer(mapping["size_bytes"], "artifact.size_bytes", 1, 2**63 - 1)
    count = _integer(mapping["packet_count"], "artifact.packet_count", 1, 2**63 - 1)
    positive = _integer(mapping["positive_packet_count"], "artifact.positive_packet_count", 0, count)
    first = _text(mapping["first_packet_epoch"], "artifact.first_packet_epoch", 64)
    last = _text(mapping["last_packet_epoch"], "artifact.last_packet_epoch", 64)
    span = _integer(mapping["packet_span_nanoseconds"], "artifact.packet_span_nanoseconds", 0, 2**127 - 1)
    try:
        first_timestamp = decode_packet_timestamp(first)
        last_timestamp = decode_packet_timestamp(last)
    except ValueError as error:
        raise CaptureReceiptError("Artifact timestamps are invalid.") from error
    expected_span = ((last_timestamp.seconds - first_timestamp.seconds) * 1_000_000_000
                     + last_timestamp.nanoseconds - first_timestamp.nanoseconds)
    if span != expected_span or (count == 1 and span != 0):
        raise CaptureReceiptError("Artifact packet span does not match its exact timestamp bounds.")
    version = _text(mapping["tshark_version"], "artifact.tshark_version", 512)
    return CaptureArtifact(capture_format, digest, size, count, positive, first, last, span, version)


def _failure(value: object) -> CaptureFailure:
    mapping = _mapping(value, set(FailureDocument.__annotations__), "failure")
    stage = mapping["stage"]
    if stage != "capture" and stage != "validation" and stage != "cleanup":
        raise CaptureReceiptError("Failure stage is invalid.")
    code = _text(mapping["code"], "failure.code", 80)
    if re.fullmatch(r"[a-z][a-z0-9_]*", code) is None:
        raise CaptureReceiptError("Failure code must use lowercase letters, digits, and underscores.")
    message = _text(mapping["message"], "failure.message", 4096)
    if stage == "capture":
        return CaptureFailure("capture", code, message)
    if stage == "validation":
        return CaptureFailure("validation", code, message)
    return CaptureFailure("cleanup", code, message)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CaptureReceiptError("Receipt JSON contains a duplicate field.")
        result[key] = value
    return result


def parse_capture_receipt(payload: str) -> CaptureReceipt:
    """Validate the complete closed receipt schema without trusting process status."""
    try:
        payload_size = len(payload.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise CaptureReceiptError("Capture receipt contains invalid Unicode.") from error
    if payload_size > MAXIMUM_RECEIPT_BYTES:
        raise CaptureReceiptError("Capture receipt exceeds the supported size.")
    try:
        decoded: object = json.loads(payload, object_pairs_hook=_unique_object)
    except CaptureReceiptError:
        raise
    except (ValueError, RecursionError) as error:
        raise CaptureReceiptError("Capture receipt is not valid bounded JSON.") from error
    root = _mapping(decoded, set(CaptureReceiptDocument.__annotations__), "receipt")
    _integer(root["schema_version"], "schema_version", 1, 1)
    request_id = _text(root["request_id"], "request_id", 32)
    if re.fullmatch(r"[0-9a-f]{32}", request_id) is None:
        raise CaptureReceiptError("Capture request ID must be a 128-bit lowercase nonce.")
    path_text = _text(root["output_path"], "output_path", 4096)
    output_path = Path(path_text)
    if not output_path.is_absolute() or str(output_path) != path_text:
        raise CaptureReceiptError("Capture receipt output path must be an exact absolute path.")
    requested_format = _format(root["requested_format"], "requested_format")
    duration = _integer(root["requested_duration_seconds"], "requested_duration_seconds", 5, 3600)
    lifetime_value = root["recording_lifetime_nanoseconds"]
    lifetime = None if lifetime_value is None else _integer(lifetime_value, "recording_lifetime_nanoseconds", 0, 2**63 - 1)
    outcome_value = root["capture_outcome"]
    if outcome_value == "completed":
        outcome: CaptureOutcome = "completed"
    elif outcome_value == "cancelled":
        outcome = "cancelled"
    elif outcome_value == "failed":
        outcome = "failed"
    else:
        raise CaptureReceiptError("Capture outcome is invalid.")
    validation_value = root["validation_status"]
    if validation_value == "verified":
        validation: ValidationStatus = "verified"
    elif validation_value == "failed":
        validation = "failed"
    elif validation_value == "not_attempted":
        validation = "not_attempted"
    else:
        raise CaptureReceiptError("Artifact validation status is invalid.")
    artifact = None if root["artifact"] is None else _artifact(root["artifact"])
    cleanup_mapping = _mapping(root["cleanup"], set(CleanupDocument.__annotations__), "cleanup")
    stopped_value = cleanup_mapping["recording_process_stopped"]
    if stopped_value is None:
        stopped: bool | None = None
    elif isinstance(stopped_value, bool):
        stopped = stopped_value
    else:
        raise CaptureReceiptError("Recording-process teardown must be a boolean or null.")
    interface_value = cleanup_mapping["interface_status"]
    if interface_value == "verified_complete":
        interface: InterfaceStatus = "verified_complete"
    elif interface_value == "failed":
        interface = "failed"
    elif interface_value == "unverified":
        interface = "unverified"
    elif interface_value == "not_applicable":
        interface = "not_applicable"
    else:
        raise CaptureReceiptError("Interface cleanup status is invalid.")
    failure_values = root["failures"]
    if not isinstance(failure_values, list) or len(failure_values) > 16:
        raise CaptureReceiptError("Receipt failures must be a bounded array.")
    failures = tuple(_failure(value) for value in failure_values)
    capture_failures = tuple(failure for failure in failures if failure.stage == "capture")
    validation_failures = tuple(failure for failure in failures if failure.stage == "validation")
    cleanup_failures = tuple(failure for failure in failures if failure.stage == "cleanup")
    if (validation == "verified") != (artifact is not None):
        raise CaptureReceiptError("Artifact evidence and validation status disagree.")
    if artifact is not None and artifact.capture_format != requested_format:
        raise CaptureReceiptError("Verified artifact format differs from the request.")
    if validation == "failed" and not validation_failures:
        raise CaptureReceiptError("Failed validation must preserve its failure cause.")
    if validation == "not_attempted" and validation_failures:
        raise CaptureReceiptError("Unattempted validation cannot claim a validation failure.")
    if artifact is not None:
        expected_no_data = artifact.positive_packet_count == 0
        if expected_no_data != bool(validation_failures) or any(failure.code != "no_positive_data" for failure in validation_failures):
            raise CaptureReceiptError("Verified readability and positive-data validation disagree.")
    if outcome == "completed" and capture_failures:
        raise CaptureReceiptError("Completed recording cannot include a capture failure.")
    if outcome == "failed" and not capture_failures:
        raise CaptureReceiptError("Failed recording must preserve its failure cause.")
    if (interface == "failed" or stopped is False) and not cleanup_failures:
        raise CaptureReceiptError("Failed cleanup must preserve its failure cause.")
    return CaptureReceipt(request_id, output_path, requested_format, duration, lifetime, outcome,
                          validation, artifact, CaptureCleanup(stopped, interface), failures)


def validate_receipt_binding(receipt: CaptureReceipt, request_id: str, output_path: Path,
                             requested_format: str, requested_duration_seconds: int) -> None:
    if (receipt.request_id != request_id or receipt.output_path != output_path
            or receipt.requested_format != requested_format
            or receipt.requested_duration_seconds != requested_duration_seconds):
        raise CaptureReceiptError("Capture receipt does not match the active request and output artifact.")


def receipt_is_success(receipt: CaptureReceipt) -> bool:
    """Overall success requires independent evidence for recording, bytes, and teardown."""
    return (receipt.capture_outcome == "completed" and receipt.validation_status == "verified"
            and receipt.artifact is not None and receipt.artifact.positive_packet_count > 0
            and receipt.cleanup.recording_process_stopped is True
            and receipt.cleanup.interface_status in {"verified_complete", "not_applicable"}
            and not receipt.failures)
