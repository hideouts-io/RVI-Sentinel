"""Real complete-file verification and bounded task-owned decoder lifecycles."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from capture_stats import CAPTURE_VALIDATION_LIMITS, capture_statistics, inspect_capture_artifact, statistics_document, validate_capture_artifact
from saved_capture import SavedCaptureError
from tests.saved_capture_fixture import classic_capture, fixture_packets, metadata_capture

REPO = Path(__file__).resolve().parents[1]
FAKE_ARTIFACT_DECODER = r'''#!/usr/bin/env python3
import csv
import json
import os
import sys
import time
from pathlib import Path

arguments = sys.argv[1:]
mode = os.environ.get("RVI_CAPTURE_STATS_MODE", "normal")
with open(os.environ["RVI_CAPTURE_STATS_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps(arguments) + "\n")
if "--version" in arguments:
    print("TShark (Wireshark) task-owned artifact lifecycle fixture 1.0")
    raise SystemExit(0)
if "-G" in arguments:
    for field in ("frame.number", "frame.time_epoch", "frame.len", "frame.cap_len"):
        if mode == "missing_field" and field == "frame.cap_len":
            continue
        print("F\tTest field\t" + field + "\tFT_STRING\tframe\t\t0x0\t")
    raise SystemExit(0)
if "-n" not in arguments:
    raise SystemExit(90)
if mode in ("wait", "cancel"):
    time.sleep(30)
if mode in ("change", "grow", "replace"):
    source = Path(os.environ["RVI_CAPTURE_STATS_SOURCE"])
    content = source.read_bytes()
    if mode == "replace":
        replacement = source.with_name("owned-replacement.pcap")
        replacement.write_bytes(content)
        replacement.replace(source)
    else:
        source.write_bytes(content + b"x" if mode == "grow" else content[:-1] + bytes([content[-1] ^ 1]))
if mode == "stderr_pressure":
    os.write(2, b"sanitized task-owned diagnostics\n" * 10000)
if mode == "both_pipes":
    os.write(2, b"sanitized task-owned diagnostics\n" * 1000)
if mode == "malformed_utf8":
    os.write(1, b"\xff\n")
    raise SystemExit(0)
writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL)
for index in range(1, 4):
    row = [str(index), "1720000000.00000000" + str(index), "60", "60"]
    if mode == "invalid_epoch":
        row[1] = "1720000000.1234567890"
    if mode == "repeated_epoch":
        row[1] += "\x1e" + row[1]
    if mode == "invalid_length":
        row[3] = "61"
    if mode == "negative_length":
        row[2] = "-1"
    if mode == "blank_length":
        row[3] = ""
    if mode == "duplicate_frame":
        row[0] = "1"
    if mode == "frame_gap" and index == 2:
        row[0] = "3"
    if mode == "wrong_columns":
        row.pop()
    writer.writerow(row)
if mode == "nonzero":
    print("task-owned source was cut short", file=sys.stderr)
    raise SystemExit(2)
'''


class RealCaptureArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("Real artifact validation requires TShark on PATH.")

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-capture-artifact-real-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def test_complete_pcap_and_pcapng_bind_exact_metadata_to_unchanged_bytes(self) -> None:
        for capture_format, content in (("pcap", classic_capture(3)), ("pcapng", metadata_capture())):
            with self.subTest(capture_format=capture_format):
                source = self.directory / ("generated." + capture_format)
                source.write_bytes(content)
                result = validate_capture_artifact(source, capture_format, threading.Event())
                self.assertEqual(result.capture_format, capture_format)
                self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())
                self.assertEqual(result.size_bytes, len(content))
                self.assertEqual(result.packet_count, 3)
                self.assertEqual(result.positive_packet_count, 3)
                self.assertEqual(result.first_packet_epoch, "1791428448.590385001")
                self.assertEqual(result.last_packet_epoch, "1791428448.590385003")
                self.assertEqual(result.packet_span_nanoseconds, 2)
                self.assertEqual(source.read_bytes(), content)

    def test_complete_validation_rejects_a_corrupt_tail_after_readable_packets(self) -> None:
        content = classic_capture(3)[:-9]
        source = self.directory / "corrupt-tail.pcap"
        source.write_bytes(content)
        with self.assertRaises(SavedCaptureError) as failure:
            validate_capture_artifact(source, "pcap", threading.Event())
        self.assertEqual(failure.exception.code, "decoder_failed")
        self.assertEqual(source.read_bytes(), content)

    def test_missing_nonregular_link_empty_header_and_wrong_format_fail(self) -> None:
        source = self.directory / "valid.pcap"
        source.write_bytes(classic_capture(1))
        link = self.directory / "linked.pcap"
        link.symlink_to(source)
        header = self.directory / "header-only.pcap"
        header.write_bytes(classic_capture(0))
        empty = self.directory / "empty.pcap"
        empty.write_bytes(b"")
        unsupported = self.directory / "unsupported.bin"
        unsupported.write_bytes(b"not a container")
        for path, expected in ((self.directory / "missing.pcap", "capture_unavailable"), (self.directory, "invalid_capture"), (link, "invalid_capture"), (header, "empty_capture"), (empty, "empty_capture"), (unsupported, "unsupported_capture_format")):
            with self.subTest(path=path.name):
                with self.assertRaises(SavedCaptureError) as failure:
                    validate_capture_artifact(path, "pcap", threading.Event())
                self.assertEqual(failure.exception.code, expected)
        with self.assertRaises(SavedCaptureError) as failure:
            validate_capture_artifact(source, "pcapng", threading.Event())
        self.assertEqual(failure.exception.code, "capture_format_mismatch")
        with self.assertRaises(SavedCaptureError) as failure:
            validate_capture_artifact(source, "guessed", threading.Event())
        self.assertEqual(failure.exception.code, "invalid_capture_format")

    def test_zero_length_frame_is_explicit_evidence_without_positive_data(self) -> None:
        source = self.directory / "zero-frame.pcap"
        source.write_bytes(classic_capture(0) + bytes(16))
        result = validate_capture_artifact(source, "pcap", threading.Event())
        self.assertEqual(result.packet_count, 1)
        self.assertEqual(result.positive_packet_count, 0)
        self.assertEqual(result.packet_span_nanoseconds, 0)

    def test_one_packet_and_sparse_out_of_order_traffic_do_not_invent_lifetime(self) -> None:
        one = self.directory / "one.pcap"
        one.write_bytes(classic_capture(1))
        artifact = inspect_capture_artifact(one, threading.Event())
        self.assertEqual(artifact.packet_span_nanoseconds, 0)
        payload = statistics_document(artifact)
        self.assertIsNone(payload["recording_lifetime_seconds"])
        self.assertIsNone(payload["requested_duration_seconds"])
        self.assertNotIn("duration_seconds", payload)
        self.assertEqual(capture_statistics(one), (1, 0.0))

        epochs = ((100, 1), (102, 2), (101, 3))
        records = tuple(struct.pack("<IIII", seconds, nanos, len(packet), len(packet)) + packet for (seconds, nanos), packet in zip(epochs, fixture_packets()))
        sparse = self.directory / "sparse.pcap"
        sparse.write_bytes(classic_capture(0) + b"".join(records))
        artifact = inspect_capture_artifact(sparse, threading.Event())
        self.assertEqual(artifact.first_packet_epoch, "100.000000001")
        self.assertEqual(artifact.last_packet_epoch, "102.000000002")
        self.assertEqual(artifact.packet_span_nanoseconds, 2_000_000_001)

    def test_streaming_receipt_accepts_more_than_packet_index_retention_limit(self) -> None:
        source = self.directory / "many-generated.pcap"
        content = classic_capture(200_001)
        source.write_bytes(content)
        result = validate_capture_artifact(source, "pcap", threading.Event())
        self.assertEqual(result.packet_count, 200_001)
        self.assertEqual(result.positive_packet_count, 200_001)
        self.assertEqual(result.packet_span_nanoseconds, 200_000)
        self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())

    def test_imported_stats_cli_names_packet_span_and_returns_failure_status(self) -> None:
        source = self.directory / "cli.pcapng"
        source.write_bytes(metadata_capture())
        completed = subprocess.run((sys.executable, str(REPO / "capture_stats.py"), str(source)), capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["packet_span_nanoseconds"], 2)
        self.assertNotIn("duration_seconds", payload)
        self.assertIsNone(payload["recording_lifetime_seconds"])
        source.write_bytes(classic_capture(0))
        completed = subprocess.run((sys.executable, str(REPO / "capture_stats.py"), str(source)), capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertIn("empty_capture", completed.stderr)


class CaptureArtifactLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-capture-artifact-lifecycle-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.source = self.directory / "owned.pcap"
        self.source.write_bytes(classic_capture(3))
        bin_directory = self.directory / "bin"
        bin_directory.mkdir()
        executable = bin_directory / "tshark"
        executable.write_text(FAKE_ARTIFACT_DECODER, encoding="utf-8")
        executable.chmod(0o755)
        self.log = self.directory / "decoder-commands.jsonl"
        environment = patch.dict(os.environ, {"PATH": str(bin_directory) + os.pathsep + os.environ.get("PATH", ""), "RVI_CAPTURE_STATS_LOG": str(self.log), "RVI_CAPTURE_STATS_MODE": "normal", "RVI_CAPTURE_STATS_SOURCE": str(self.source)})
        environment.start()
        self.addCleanup(environment.stop)

    def test_field_negotiation_and_passive_complete_decode_are_required(self) -> None:
        result = validate_capture_artifact(self.source, "pcap", threading.Event())
        self.assertEqual(result.packet_count, 3)
        commands = tuple(json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines())
        decode = tuple(command for command in commands if "-r" in command)
        self.assertEqual(len(decode), 1)
        self.assertIn("-n", decode[0])
        self.assertNotIn("-c", decode[0])
        self.assertNotIn("-N", decode[0])
        self.assertIn("frame.cap_len", decode[0])
        self.log.unlink()
        os.environ["RVI_CAPTURE_STATS_MODE"] = "missing_field"
        with self.assertRaises(SavedCaptureError) as failure:
            validate_capture_artifact(self.source, "pcap", threading.Event())
        self.assertEqual(failure.exception.code, "required_fields_missing")
        commands = tuple(json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines())
        self.assertFalse(any("-r" in command for command in commands))

    def test_invalid_consumed_rows_and_unsuccessful_completion_return_no_artifact(self) -> None:
        cases = (("invalid_epoch", "invalid_row"), ("repeated_epoch", "invalid_row"), ("invalid_length", "invalid_row"), ("negative_length", "invalid_row"), ("blank_length", "invalid_row"), ("wrong_columns", "invalid_row"), ("malformed_utf8", "invalid_row"), ("duplicate_frame", "frame_sequence"), ("frame_gap", "frame_sequence"), ("nonzero", "decoder_failed"))
        for mode, code in cases:
            with self.subTest(mode=mode):
                os.environ["RVI_CAPTURE_STATS_MODE"] = mode
                with self.assertRaises(SavedCaptureError) as failure:
                    validate_capture_artifact(self.source, "pcap", threading.Event())
                self.assertEqual(failure.exception.code, code)

    def test_changed_growing_and_replaced_sources_fail_integrity(self) -> None:
        for mode in ("change", "grow", "replace"):
            with self.subTest(mode=mode):
                self.source.write_bytes(classic_capture(3))
                os.environ["RVI_CAPTURE_STATS_MODE"] = mode
                with self.assertRaises(SavedCaptureError) as failure:
                    validate_capture_artifact(self.source, "pcap", threading.Event())
                self.assertEqual(failure.exception.code, "changed_capture")

    def test_stderr_is_drained_and_independent_limits_fail_explicitly(self) -> None:
        os.environ["RVI_CAPTURE_STATS_MODE"] = "both_pipes"
        result = validate_capture_artifact(self.source, "pcap", threading.Event())
        self.assertEqual(result.packet_count, 3)
        for changes, code in (({"max_capture_bytes": 8}, "capture_limit"), ({"max_line_bytes": 8}, "line_limit"), ({"max_output_bytes": 8}, "output_limit"), ({"max_probe_bytes": 8}, "output_limit")):
            with self.subTest(changes=changes):
                with patch("capture_stats.CAPTURE_VALIDATION_LIMITS", replace(CAPTURE_VALIDATION_LIMITS, **changes)):
                    with self.assertRaises(SavedCaptureError) as failure:
                        validate_capture_artifact(self.source, "pcap", threading.Event())
                    self.assertEqual(failure.exception.code, code)
        os.environ["RVI_CAPTURE_STATS_MODE"] = "stderr_pressure"
        started = time.monotonic()
        with self.assertRaises(SavedCaptureError) as failure:
            validate_capture_artifact(self.source, "pcap", threading.Event())
        self.assertEqual(failure.exception.code, "stderr_limit")
        self.assertLess(time.monotonic() - started, 3)

    def test_deadline_and_cancellation_stop_owned_decoder_without_results(self) -> None:
        os.environ["RVI_CAPTURE_STATS_MODE"] = "wait"
        with patch("capture_stats.CAPTURE_VALIDATION_LIMITS", replace(CAPTURE_VALIDATION_LIMITS, total_timeout_seconds=0.5)):
            started = time.monotonic()
            with self.assertRaises(SavedCaptureError) as failure:
                validate_capture_artifact(self.source, "pcap", threading.Event())
            self.assertEqual(failure.exception.code, "deadline_exceeded")
            self.assertLess(time.monotonic() - started, 3)
        self.log.unlink()
        cancellation = threading.Event()
        cancellation.set()
        with self.assertRaises(SavedCaptureError) as failure:
            validate_capture_artifact(self.source, "pcap", cancellation)
        self.assertEqual(failure.exception.code, "cancelled")
        self.assertFalse(self.log.exists())
        cancellation.clear()
        observed = threading.Event()

        def cancel_after_decode_starts() -> None:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if self.log.exists() and '"-r"' in self.log.read_text(encoding="utf-8"):
                    observed.set()
                    cancellation.set()
                    return
                cancellation.wait(0.01)
            cancellation.set()

        monitor = threading.Thread(target=cancel_after_decode_starts)
        monitor.start()
        try:
            with self.assertRaises(SavedCaptureError) as failure:
                validate_capture_artifact(self.source, "pcap", cancellation)
            self.assertEqual(failure.exception.code, "cancelled")
        finally:
            cancellation.set()
            monitor.join(timeout=4)
        self.assertTrue(observed.is_set())
        self.assertFalse(monitor.is_alive())


if __name__ == "__main__":
    unittest.main()
