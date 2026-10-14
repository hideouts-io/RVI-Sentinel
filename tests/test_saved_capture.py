"""Exercise real saved captures and bounded, task-owned decoder failure processes."""

from __future__ import annotations

import copy
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
from typing import Callable
from unittest.mock import patch

import saved_capture
from analyze import analyze, load_baseline, save_baseline, save_report, updated_baseline
from analysis_baseline import BaselineValidationError
from capture_stats import validate_capture_artifact
from gui_models import ReportValidationError, load_report
from packet_models import packet_values
from saved_capture import (
    SAVED_ANALYSIS_LIMITS,
    SavedCaptureCancelled,
    SavedCaptureError,
    read_saved_capture,
)
from tests.saved_capture_fixture import classic_capture, metadata_capture
from tests.test_analyzer import FAKE_TSHARK


class RealSavedCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("Real saved-capture integration requires TShark on PATH; install Wireshark's command-line tools.")

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-sentinel-real-saved-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def test_real_pcapng_retains_exact_timestamps_all_names_and_recorded_metadata(self) -> None:
        content = metadata_capture()
        capture = self.directory / "metadata.pcapng"
        capture.write_bytes(content)
        result = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())

        self.assertEqual(capture.read_bytes(), content)
        self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(result.size_bytes, len(content))
        self.assertEqual(len(result.packets), 3)
        self.assertIn("Wireshark", result.tshark_version)
        self.assertEqual(tuple(packet.frame_number for packet in result.packets), (1, 2, 3))
        first, second, ipv6 = result.packets
        self.assertEqual(first.timestamp.epoch, "1791428448.590385001")
        self.assertEqual(second.timestamp.nanoseconds, 590_385_002)
        self.assertEqual(ipv6.timestamp.epoch, "1791428448.590385003")
        self.assertEqual(packet_values(first, "dns.qry.name"), ("first.test", "second.test"))
        self.assertEqual(ipv6.source_address, "2001:db8::2")
        self.assertEqual(ipv6.destination_address, "2001:db8::53")
        self.assertEqual(first.process.state, "recorded")
        self.assertEqual(first.process.labels[0].pid, 343)
        self.assertEqual(first.process.labels[0].name, "fixture-maild")
        self.assertEqual(first.process.labels[0].source, "apple_pcapng")
        self.assertEqual(first.effective_process.state, "unknown")
        self.assertEqual(first.interface.labels[0].name, "fixture0")
        self.assertEqual(first.direction.labels[0].direction, "outbound")
        self.assertGreater(first.wire_length, 0)
        self.assertEqual(first.captured_length, first.wire_length)

    def test_real_pcapng_preserves_recorded_zero_process_id(self) -> None:
        content = bytearray(metadata_capture())
        offset = 0
        while offset < len(content):
            block_type, block_length = struct.unpack_from("<II", content, offset)
            if block_type == 0x80000001:
                struct.pack_into("<I", content, offset + 8, 0)
                break
            offset += block_length
        else:
            self.fail("The synthetic PCAPNG fixture must contain a process information block.")
        original = bytes(content)
        capture = self.directory / "zero-process.pcapng"
        capture.write_bytes(original)

        result = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())

        self.assertEqual(len(result.packets), 3)
        for packet in result.packets:
            self.assertEqual(packet_values(packet, "frame.darwin.process_info.pid"), ("0",))
            self.assertEqual(packet.process.state, "recorded")
            self.assertEqual(packet.process.labels[0].pid, 0)
            self.assertEqual(packet.process.labels[0].name, "fixture-maild")
            self.assertEqual(packet.effective_process.state, "unknown")
        self.assertEqual(capture.read_bytes(), original)
        self.assertEqual(result.sha256, hashlib.sha256(original).hexdigest())

    def test_real_classic_pcap_leaves_unrecorded_context_unknown(self) -> None:
        content = classic_capture(3)
        capture = self.directory / "classic.pcap"
        capture.write_bytes(content)
        result = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(len(result.packets), 3)
        for packet in result.packets:
            self.assertEqual(packet.process.state, "unknown")
            self.assertEqual(packet.effective_process.state, "unknown")
            self.assertEqual(packet.interface.state, "unknown")
            self.assertEqual(packet.direction.state, "unknown")
        self.assertEqual(packet_values(result.packets[0], "dns.qry.name"), ("first.test", "second.test"))
        self.assertEqual(capture.read_bytes(), content)

    @unittest.skipUnless(os.name == "posix", "Directory replacement while a capture is open requires POSIX filesystem semantics.")
    def test_real_decoder_keeps_original_bytes_when_parent_directory_is_replaced(self) -> None:
        """Replace only the source pathname during each real child, then restore it before integrity checks."""
        fixtures = (("pcap", classic_capture(3), classic_capture(6)),
                    ("pcapng", metadata_capture(), metadata_capture() + metadata_capture()))
        for capture_format, original, replacement in fixtures:
            for operation in ("saved_analysis", "artifact_validation"):
                with self.subTest(capture_format=capture_format, operation=operation):
                    case = self.directory / (capture_format + "-" + operation)
                    case.mkdir()
                    source_directory = case / "source"
                    replacement_directory = case / "replacement"
                    parked_directory = case / "parked"
                    source_directory.mkdir()
                    replacement_directory.mkdir()
                    filename = "fixture." + capture_format
                    capture = source_directory / filename
                    foreign_capture = replacement_directory / filename
                    capture.write_bytes(original)
                    foreign_capture.write_bytes(replacement)
                    original_stat = capture.stat()
                    swapped_passes: list[str] = []
                    real_run = saved_capture._run_decoder

                    def replace_directory_during_child(
                        executable: str, arguments: tuple[str, ...], output_limit: int,
                        stderr_limit: int, deadline: float, cancellation: threading.Event,
                        consume: Callable[[bytes], None], input_descriptor: int | None,
                    ) -> bytes:
                        if "-r" not in arguments:
                            return real_run(executable, arguments, output_limit, stderr_limit,
                                            deadline, cancellation, consume, input_descriptor)
                        source_directory.rename(parked_directory)
                        replacement_directory.rename(source_directory)
                        try:
                            swapped_passes.append(arguments[arguments.index("-T") + 1])
                            return real_run(executable, arguments, output_limit, stderr_limit,
                                            deadline, cancellation, consume, input_descriptor)
                        finally:
                            source_directory.rename(replacement_directory)
                            parked_directory.rename(source_directory)

                    with patch.object(saved_capture, "_run_decoder", replace_directory_during_child):
                        if operation == "saved_analysis":
                            result = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
                            self.assertEqual(tuple(packet.frame_number for packet in result.packets), (1, 2, 3))
                            self.assertEqual(result.sha256, hashlib.sha256(original).hexdigest())
                            self.assertEqual(result.size_bytes, len(original))
                            self.assertEqual(tuple(message.frame_number for message in result.dns_evidence.messages), (1, 2, 3))
                            self.assertEqual(result.dns_evidence.capture_sha256, result.sha256)
                            self.assertEqual(tuple(question.name for question in result.dns_evidence.messages[0].questions),
                                             ("first.test", "second.test"))
                            self.assertEqual(swapped_passes, ["fields", "json"])
                        else:
                            artifact = validate_capture_artifact(capture, capture_format, threading.Event())
                            self.assertEqual(artifact.packet_count, 3)
                            self.assertEqual(artifact.sha256, hashlib.sha256(original).hexdigest())
                            self.assertEqual(artifact.size_bytes, len(original))
                            self.assertEqual(swapped_passes, ["fields"])
                    restored_stat = capture.stat()
                    self.assertEqual((restored_stat.st_ino, restored_stat.st_mtime_ns, restored_stat.st_ctime_ns),
                                     (original_stat.st_ino, original_stat.st_mtime_ns, original_stat.st_ctime_ns))
                    self.assertEqual(capture.read_bytes(), original)
                    self.assertEqual(foreign_capture.read_bytes(), replacement)
                    self.assertFalse(parked_directory.exists())

    def test_reviewed_baseline_growth_is_denied_before_replacing_readable_history(self) -> None:
        capture = self.directory / "baseline-growth.pcapng"
        content = metadata_capture()
        capture.write_bytes(content)
        baseline_path = self.directory / "baseline.json"
        baseline = load_baseline(baseline_path)
        save_baseline(baseline_path, baseline, (capture,), threading.Event())
        original = baseline_path.read_bytes()
        report = analyze(capture, baseline, 3.8)
        updated = updated_baseline(baseline, report)
        new_destination = self.directory / "new-baseline.json"
        for destination in (baseline_path, new_destination):
            with self.subTest(destination=destination.name), patch("analyze.MAXIMUM_BASELINE_BYTES", len(original)):
                with self.assertRaises(BaselineValidationError):
                    save_baseline(destination, updated, (capture,), threading.Event())
            self.assertEqual(baseline_path.read_bytes(), original)
            self.assertEqual(load_baseline(baseline_path), baseline)
            self.assertFalse(new_destination.exists())
            self.assertEqual(capture.read_bytes(), content)
            self.assertFalse(any(path.name.startswith(".rvi-sentinel-baseline-") for path in self.directory.iterdir()))

    def test_real_empty_header_only_corrupt_and_missing_inputs_fail(self) -> None:
        cases = (
            ("empty.pcap", b""),
            ("header-only.pcap", classic_capture(0)),
            ("bad-header.pcap", b"not a packet capture"),
            ("truncated.pcap", classic_capture(3)[:-9]),
        )
        for filename, content in cases:
            with self.subTest(filename=filename):
                capture = self.directory / filename
                capture.write_bytes(content)
                with self.assertRaises(SavedCaptureError):
                    read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
                self.assertEqual(capture.read_bytes(), content)
        with self.assertRaises(SavedCaptureError):
            read_saved_capture(self.directory / "missing.pcap", SAVED_ANALYSIS_LIMITS, threading.Event())
        with self.assertRaises(SavedCaptureError):
            read_saved_capture(self.directory, SAVED_ANALYSIS_LIMITS, threading.Event())

    def test_zero_length_decoded_frame_preserves_empty_observation_without_network_context(self) -> None:
        capture = self.directory / "zero-length-frame.pcap"
        content = classic_capture(0) + bytes(16)
        capture.write_bytes(content)
        result = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(len(result.packets), 1)
        packet = result.packets[0]
        self.assertEqual(packet.wire_length, 0)
        self.assertEqual(packet.captured_length, 0)
        self.assertEqual(packet.process.state, "unknown")
        self.assertIsNone(packet.source_address)
        self.assertIsNone(packet.destination_address)
        self.assertIsNone(packet.transport)
        self.assertEqual(capture.read_bytes(), content)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO checks require a POSIX filesystem.")
    def test_nonregular_capture_is_rejected_without_waiting_for_writer(self) -> None:
        capture = self.directory / "input.fifo"
        os.mkfifo(capture)
        started = time.monotonic()
        with self.assertRaises(SavedCaptureError):
            read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertLess(time.monotonic() - started, 2)

    def test_real_capture_limits_fail_explicitly(self) -> None:
        capture = self.directory / "bounded.pcapng"
        capture.write_bytes(metadata_capture())
        cases = (
            (replace(SAVED_ANALYSIS_LIMITS, max_capture_bytes=16), "capture_limit"),
            (replace(SAVED_ANALYSIS_LIMITS, max_records=2), "record_limit"),
            (replace(SAVED_ANALYSIS_LIMITS, max_estimated_bytes=1), "memory_limit"),
            (replace(SAVED_ANALYSIS_LIMITS, max_line_bytes=8), "line_limit"),
            (replace(SAVED_ANALYSIS_LIMITS, max_output_bytes=8), "output_limit"),
            (replace(SAVED_ANALYSIS_LIMITS, max_probe_bytes=16), "output_limit"),
        )
        for limits, expected_code in cases:
            with self.subTest(limits=limits):
                with self.assertRaises(SavedCaptureError) as failure:
                    read_saved_capture(capture, limits, threading.Event())
                self.assertEqual(failure.exception.code, expected_code)

    def test_passive_preview_and_updated_baseline_preserve_input_evidence(self) -> None:
        capture = self.directory / "preview.pcapng"
        content = metadata_capture()
        capture.write_bytes(content)
        baseline_path = self.directory / "baseline.json"
        baseline = load_baseline(baseline_path)
        baseline_path.write_text(json.dumps(baseline, sort_keys=True), encoding="utf-8")
        baseline_bytes = baseline_path.read_bytes()
        original_baseline = copy.deepcopy(baseline)

        report = analyze(capture, baseline, 3.5)
        self.assertEqual(baseline, original_baseline)
        self.assertEqual(baseline_path.read_bytes(), baseline_bytes)
        self.assertEqual(capture.read_bytes(), content)
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["capture"]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(report["capture"]["integrity"], "verified")
        self.assertEqual(report["capture"]["origin"], "imported_unknown")
        self.assertEqual(report["capture"]["first_packet_epoch"], "1791428448.590385001")
        self.assertEqual(report["capture"]["last_packet_epoch"], "1791428448.590385003")
        self.assertIs(report["decoder"]["active_resolution_enabled"], False)
        self.assertEqual(len(report["packets"]), 3)
        self.assertEqual(report["summary"]["unique_dns_queries"], 4)
        updated = updated_baseline(baseline, report)
        self.assertEqual(baseline, original_baseline)
        self.assertEqual(baseline_path.read_bytes(), baseline_bytes)
        self.assertEqual(updated["captures_analyzed"], 1)
        self.assertIn("first.test", updated["domains"])
        self.assertIn("second.test", updated["domains"])

        completed = subprocess.run(
            [sys.executable, "analyze_preview.py", str(capture), "--baseline", str(baseline_path), "--export-dir", str(self.directory / "exports"), "--entropy-threshold", "3.5", "--top", "0"],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(baseline_path.read_bytes(), baseline_bytes)
        exported = json.loads((self.directory / "exports" / "preview_report.json").read_text(encoding="utf-8"))
        self.assertEqual(exported["capture"]["sha256"], report["capture"]["sha256"])
        self.assertEqual(len(exported["packets"]), 3)

    def test_preview_and_update_refuse_output_aliases_before_publication(self) -> None:
        for script in ("analyze_preview.py", "analyze.py"):
            for alias in ("baseline_report", "symlink_baseline", "hardlink_baseline", "symlink_capture", "hardlink_capture"):
                with self.subTest(script=script, alias=alias):
                    case_directory = self.directory / (script.replace(".py", "") + "-" + alias)
                    case_directory.mkdir()
                    capture = case_directory / "fixture.pcapng"
                    capture.write_bytes(metadata_capture())
                    exports = case_directory / "exports"
                    exports.mkdir()
                    report_path = exports / "fixture_report.json"
                    baseline = report_path if alias == "baseline_report" else case_directory / "baseline.json"
                    baseline.write_text(json.dumps(load_baseline(baseline), sort_keys=True), encoding="utf-8")
                    if alias != "baseline_report":
                        target = baseline if alias.endswith("baseline") else capture
                        if alias.startswith("symlink"):
                            report_path.symlink_to(target)
                        else:
                            os.link(target, report_path)
                    baseline_bytes = baseline.read_bytes()
                    capture_bytes = capture.read_bytes()
                    report_bytes = report_path.read_bytes()
                    completed = subprocess.run(
                        [sys.executable, script, str(capture), "--baseline", str(baseline), "--export-dir", str(exports), "--entropy-threshold", "3.5", "--top", "0"],
                        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False, timeout=10,
                    )
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertEqual(baseline.read_bytes(), baseline_bytes)
                    self.assertEqual(capture.read_bytes(), capture_bytes)
                    self.assertEqual(report_path.read_bytes(), report_bytes)
                    self.assertFalse(any(exports.glob("*.csv")), "An alias refusal must happen before any report publication.")

    def test_cancelled_report_and_baseline_staging_preserve_existing_destinations(self) -> None:
        capture = self.directory / "cancelled-save.pcapng"
        capture.write_bytes(metadata_capture())
        baseline = self.directory / "baseline.json"
        original = load_baseline(baseline)
        baseline.write_text(json.dumps(original, sort_keys=True), encoding="utf-8")
        baseline_bytes = baseline.read_bytes()
        report = analyze(capture, original, 3.5)
        exports = self.directory / "exports"
        exports.mkdir()
        destinations = tuple(exports / (capture.stem + suffix) for suffix in ("_report.json", "_endpoints.csv", "_dns.csv", "_tls_sni.csv"))
        for destination in destinations:
            destination.write_bytes(b"preexisting output bytes\n")
        before = tuple(destination.read_bytes() for destination in destinations)
        cancellation = threading.Event()
        cancellation.set()
        with self.assertRaises(SavedCaptureError) as report_failure:
            save_report(report, capture, exports, (capture, baseline), cancellation)
        self.assertEqual(report_failure.exception.code, "cancelled")
        self.assertEqual(tuple(destination.read_bytes() for destination in destinations), before)
        with self.assertRaises(SavedCaptureError) as baseline_failure:
            save_baseline(baseline, updated_baseline(original, report), (capture,) + destinations, cancellation)
        self.assertEqual(baseline_failure.exception.code, "cancelled")
        self.assertEqual(baseline.read_bytes(), baseline_bytes)
        self.assertFalse(any(exports.glob(".rvi-sentinel-report-*")))
        self.assertFalse(any(self.directory.glob(".rvi-sentinel-baseline-*")))

    def test_reviewed_update_rejects_changed_or_replaced_capture_without_publication(self) -> None:
        capture = self.directory / "reviewed.pcapng"
        original_content = metadata_capture()
        capture.write_bytes(original_content)
        baseline = self.directory / "baseline.json"
        baseline.write_text(json.dumps(load_baseline(baseline), sort_keys=True), encoding="utf-8")
        baseline_bytes = baseline.read_bytes()
        exports = self.directory / "exports"
        report = analyze(capture, load_baseline(baseline), 3.5)
        save_report(report, capture, exports, (capture, baseline), threading.Event())
        destinations = tuple(sorted(exports.iterdir()))
        report_bytes = tuple(path.read_bytes() for path in destinations)
        expected_sha256 = report["capture"]["sha256"]
        for mutation in ("changed", "replaced"):
            with self.subTest(mutation=mutation):
                if mutation == "changed":
                    capture.write_bytes(original_content.replace(b"fixture-maild", b"changed-maild"))
                else:
                    replacement = self.directory / "replacement.pcap"
                    replacement.write_bytes(classic_capture(3))
                    os.replace(replacement, capture)
                changed_bytes = capture.read_bytes()
                completed = subprocess.run(
                    [sys.executable, "analyze_reviewed.py", str(capture), "--baseline", str(baseline), "--export-dir", str(exports), "--entropy-threshold", "3.5", "--top", "0", "--expected-sha256", expected_sha256],
                    cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False, timeout=20,
                )
                self.assertEqual(completed.returncode, 2, completed.stderr)
                self.assertIn("Capture bytes changed after preview", completed.stderr)
                self.assertEqual(baseline.read_bytes(), baseline_bytes)
                self.assertEqual(tuple(path.read_bytes() for path in destinations), report_bytes)
                self.assertEqual(capture.read_bytes(), changed_bytes)
        capture.write_bytes(original_content)
        completed = subprocess.run(
            [sys.executable, "analyze_reviewed.py", str(capture), "--baseline", str(baseline), "--export-dir", str(exports), "--entropy-threshold", "3.5", "--top", "0", "--expected-sha256", expected_sha256],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(baseline.read_text(encoding="utf-8"))["captures_analyzed"], 1)
        self.assertEqual(capture.read_bytes(), original_content)

    def test_v2_report_loader_rejects_tampered_traceability_fields(self) -> None:
        capture = self.directory / "report-validation.pcapng"
        capture.write_bytes(metadata_capture())
        report = analyze(capture, load_baseline(self.directory / "baseline.json"), 3.5)
        report_path = self.directory / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        loaded = load_report(report_path)
        self.assertIsNotNone(loaded.evidence)
        count = copy.deepcopy(report)
        count["capture"]["packet_count"] += 1
        timestamp = copy.deepcopy(report)
        timestamp["capture"]["first_packet_epoch"] = "0.000000000"
        frame = copy.deepcopy(report)
        frame["packets"][0]["frame_number"] = 2
        digest = copy.deepcopy(report)
        digest["capture"]["sha256"] = "0" * 64
        coverage = copy.deepcopy(report)
        coverage["decoder"]["supported_fields"].remove("frame.number")
        for description, tampered in (("count", count), ("timestamp", timestamp), ("frame", frame), ("digest", digest), ("coverage", coverage)):
            with self.subTest(description=description):
                report_path.write_text(json.dumps(tampered), encoding="utf-8")
                with self.assertRaises(ReportValidationError):
                    load_report(report_path)


class DecoderBoundaryTests(unittest.TestCase):
    """Own every child executable and capture; these are process-boundary tests, not real decoding."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="rvi-sentinel-decoder-boundary-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        binary_directory = self.directory / "bin"
        binary_directory.mkdir()
        decoder = binary_directory / "tshark"
        decoder.write_text(FAKE_TSHARK, encoding="utf-8")
        decoder.chmod(0o755)
        self.capture = self.directory / "fixture.pcap"
        self.capture.write_bytes(classic_capture(7))
        self.log = self.directory / "arguments.jsonl"
        environment = {
            "PATH": str(binary_directory) + os.pathsep + os.environ.get("PATH", ""),
            "RVI_TEST_TSHARK_MODE": "normal",
            "RVI_TEST_TSHARK_LOG": str(self.log),
            "RVI_TEST_TSHARK_SOURCE": str(self.capture),
        }
        patcher = patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_negotiation_records_unavailable_optional_field_and_denies_missing_required_field(self) -> None:
        os.environ["RVI_TEST_TSHARK_MODE"] = "missing_optional"
        result = read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertIn("frame.darwin.process_info.pname", result.unsupported_fields)
        self.assertNotIn("frame.darwin.process_info.pname", result.supported_fields)
        self.assertIsNone(result.packets[0].process.labels[0].name)

        self.log.unlink()
        os.environ["RVI_TEST_TSHARK_MODE"] = "missing_required"
        with self.assertRaisesRegex(SavedCaptureError, "frame.time_epoch"):
            read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        commands = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        self.assertFalse(any("-r" in command for command in commands))

    def test_passive_decoder_never_enables_resolution_and_drains_both_pipes(self) -> None:
        os.environ["RVI_TEST_TSHARK_MODE"] = "both_pipes"
        original = self.capture.read_bytes()
        result = read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(len(result.packets), 700)
        self.assertEqual(result.sha256, hashlib.sha256(original).hexdigest())
        self.assertEqual(result.dns_evidence.capture_sha256, result.sha256)
        self.assertEqual(self.capture.read_bytes(), original)
        commands = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        decode_commands = [command for command in commands if "-r" in command]
        self.assertEqual(len(decode_commands), 2)
        self.assertEqual(tuple(command[command.index("-T") + 1] for command in decode_commands), ("fields", "json"))
        for command in decode_commands:
            self.assertEqual(command.count("-n"), 1)
            self.assertNotIn("-N", command)
            self.assertFalse(any(argument.startswith("-N") for argument in command))
            self.assertEqual(command.count("-r"), 1)
            self.assertEqual(command[command.index("-r") + 1], "-")
        packet_command, dns_command = decode_commands
        self.assertNotIn("-Y", packet_command, "The packet pass must retain the complete original frame sequence.")
        self.assertIn("occurrence=a", packet_command)
        self.assertIn("--no-duplicate-keys", dns_command)
        self.assertEqual(dns_command[dns_command.index("-Y") + 1], "dns || mdns || llmnr")
        self.assertEqual(dns_command[dns_command.index("-J") + 1], "frame dns mdns llmnr")
        self.assertNotIn("-e", dns_command, "Structured DNS ownership must not be reconstructed from flattened fields.")

    def test_source_change_and_growth_fail_integrity(self) -> None:
        for mode in ("change_source", "grow_source"):
            with self.subTest(mode=mode):
                self.capture.write_bytes(classic_capture(7))
                os.environ["RVI_TEST_TSHARK_MODE"] = mode
                with self.assertRaises(SavedCaptureError) as failure:
                    read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, threading.Event())
                self.assertEqual(failure.exception.code, "changed_capture")

    def test_invalid_packet_rows_never_publish_a_report_or_change_baseline(self) -> None:
        baseline = self.directory / "baseline.json"
        baseline.write_text(json.dumps(load_baseline(baseline), sort_keys=True), encoding="utf-8")
        baseline_bytes = baseline.read_bytes()
        capture_bytes = self.capture.read_bytes()
        exports = self.directory / "exports"
        for mode in ("invalid_pid", "invalid_port", "invalid_timestamp", "duplicate_frame", "frame_gap", "wrong_columns"):
            with self.subTest(mode=mode):
                os.environ["RVI_TEST_TSHARK_MODE"] = mode
                completed = subprocess.run(
                    [sys.executable, "analyze_preview.py", str(self.capture), "--baseline", str(baseline), "--export-dir", str(exports), "--entropy-threshold", "3.5", "--top", "0"],
                    cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertNotEqual(completed.returncode, 0, "Invalid decoded evidence cannot produce a completed preview.")
                self.assertFalse((exports / "fixture_report.json").exists())
                self.assertEqual(baseline.read_bytes(), baseline_bytes)
                self.assertEqual(self.capture.read_bytes(), capture_bytes)

    def test_conflicting_metadata_stays_unpaired_and_ambiguous_endpoints_stay_unassigned(self) -> None:
        os.environ["RVI_TEST_TSHARK_MODE"] = "conflict_ambiguous"
        capture_bytes = self.capture.read_bytes()
        result = read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        first = result.packets[0]
        self.assertEqual(first.process.state, "conflict")
        self.assertEqual({label.pid for label in first.process.labels if label.pid is not None}, {343, 344})
        self.assertEqual({label.name for label in first.process.labels if label.name is not None}, {"fixture-maild", "other-label"})
        self.assertTrue(all(label.pid is None or label.name is None for label in first.process.labels))
        self.assertEqual(packet_values(first, "ip.src"), ("192.0.2.2", "192.0.2.3"))
        self.assertIsNone(first.source_address)
        self.assertIsNone(first.destination_address)
        self.assertIn("ambiguous_network_layers", first.diagnostics)
        self.assertIn("process_metadata_conflict", first.diagnostics)
        self.assertEqual(self.capture.read_bytes(), capture_bytes)

    def test_stderr_bound_and_invalid_utf8_fail_explicitly(self) -> None:
        os.environ["RVI_TEST_TSHARK_MODE"] = "stderr_limit"
        with self.assertRaises(SavedCaptureError) as failure:
            read_saved_capture(self.capture, replace(SAVED_ANALYSIS_LIMITS, max_stderr_bytes=64), threading.Event())
        self.assertEqual(failure.exception.code, "stderr_limit")
        os.environ["RVI_TEST_TSHARK_MODE"] = "malformed_utf8"
        with self.assertRaises(SavedCaptureError) as failure:
            read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(failure.exception.code, "invalid_row")

    def test_total_deadline_terminates_a_waiting_decoder(self) -> None:
        os.environ["RVI_TEST_TSHARK_MODE"] = "timeout"
        started = time.monotonic()
        with self.assertRaises(SavedCaptureError) as failure:
            read_saved_capture(self.capture, replace(SAVED_ANALYSIS_LIMITS, total_timeout_seconds=0.5), threading.Event())
        self.assertEqual(failure.exception.code, "deadline_exceeded")
        self.assertLess(time.monotonic() - started, 3)

    def test_cancellation_before_and_during_decode_is_explicit(self) -> None:
        cancellation = threading.Event()
        cancellation.set()
        with self.assertRaises(SavedCaptureCancelled):
            read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, cancellation)
        self.assertFalse(self.log.exists(), "Cancelled analysis should not launch a decoder.")

        cancellation.clear()
        observed = threading.Event()
        os.environ["RVI_TEST_TSHARK_MODE"] = "cancel"

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
            with self.assertRaises(SavedCaptureCancelled):
                read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, cancellation)
        finally:
            cancellation.set()
            monitor.join(timeout=4)
        self.assertFalse(monitor.is_alive())
        self.assertTrue(observed.is_set(), "The cancellation test must exercise a running decoder.")


if __name__ == "__main__":
    unittest.main()
