"""Real saved-file integration for section-scoped Apple process observations."""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from analyze import analyze, load_baseline
from gui_models import ReportValidationError, load_report
from packet_models import PCAPNG_PROCESS_FIELDS, packet_values
from packet_sessions import build_session_index
from packet_timeline import build_packet_index
from pcapng_process import PcapngMetadataError, attach_pcapng_process_metadata, read_pcapng_process_metadata
from saved_capture import SAVED_ANALYSIS_LIMITS, SavedAnalysis, SavedCaptureCancelled, SavedCaptureError, read_saved_capture
from tests.saved_capture_fixture import ipv4_dns_packet, padded


def block(order: str, code: int, body: bytes) -> bytes:
    length = len(body) + 12
    return struct.pack(order + "II", code, length) + body + struct.pack(order + "I", length)


def option(order: str, code: int, value: bytes) -> bytes:
    return struct.pack(order + "HH", code, len(value)) + padded(value)


def process_capture(order: str, pid: int, name: bytes, effective_pid: int, effective_name: bytes) -> bytes:
    """Construct one packet with explicit primary/effective process references."""
    section = block(order, 0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(order, 1, struct.pack(order + "HHI", 101, 0, 65_535))
    primary = block(order, 0x80000001, struct.pack("<I", pid) + option(order, 2, name) + option(order, 0, b""))
    effective = block(order, 0x80000001, struct.pack("<I", effective_pid) + option(order, 2, effective_name) + option(order, 0, b""))
    packet = ipv4_dns_packet(("container.test",))
    timestamp = 1_700_000_000 * 1_000_000 + 5
    body = struct.pack(order + "IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(packet), len(packet)) + padded(packet)
    body += option(order, 0x8001, struct.pack("<I", 0))
    body += option(order, 0x8003, struct.pack("<I", 1)) + option(order, 0, b"")
    return section + interface + primary + effective + block(order, 6, body)


def changed_block(content: bytes, code: int, replacement_body: bytes) -> bytes:
    offset = 0
    while offset < len(content):
        block_code, length = struct.unpack_from("<II", content, offset)
        if block_code == code:
            return content[:offset] + block("<", code, replacement_body) + content[offset + length:]
        offset += length
    raise ValueError("The requested synthetic block does not exist.")


class PcapngProcessIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="rvi-pcapng-process-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def read(self, content: bytes) -> SavedAnalysis:
        capture = self.directory / "process.pcapng"
        capture.write_bytes(content)
        result = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(capture.read_bytes(), content)
        self.assertEqual(result.sha256, hashlib.sha256(content).hexdigest())
        return result

    def test_real_decoder_section_resets_and_effective_pid_zero(self) -> None:
        content = process_capture("<", 343, b"first", 444, b"delegate") + process_capture("<", 343, b"first", 0, b"kernel")
        result = self.read(content)
        self.assertEqual(len(result.packets), 2)
        first, second = result.packets
        self.assertEqual((first.process.labels[0].pid, first.process.labels[0].name), (343, "first"))
        self.assertEqual((first.effective_process.labels[0].pid, first.effective_process.labels[0].name), (444, "delegate"))
        self.assertEqual((second.process.labels[0].pid, second.process.labels[0].name), (343, "first"))
        self.assertEqual((second.effective_process.labels[0].pid, second.effective_process.labels[0].name), (0, "kernel"))
        self.assertEqual(packet_values(first, "pcapng.apple.process.epid"), ("444",))
        self.assertEqual(result.container_fields, PCAPNG_PROCESS_FIELDS)
        self.assertFalse(set(result.container_fields) & set(result.supported_fields))
        sessions = build_session_index(build_packet_index(result.sha256, result.packets, threading.Event()), threading.Event())
        self.assertEqual(len(sessions.sessions), 2)

    def test_big_endian_framing_keeps_little_endian_darwin_payloads(self) -> None:
        content = process_capture(">", 343, b"primary", 0, b"kernel")
        path = self.directory / "big-endian.pcapng"
        path.write_bytes(content)
        with path.open("rb") as stream:
            metadata = read_pcapng_process_metadata(stream.fileno(), 200_000, 268_435_456, time.monotonic() + 30, threading.Event())
        self.assertEqual(metadata.frames[0].primary[0].pid, 343)
        self.assertEqual(metadata.frames[0].effective[0].pid, 0)
        executable = shutil.which("tshark")
        if executable is None:
            self.fail("Real PCAPNG interoperability requires TShark.")
        decoded = subprocess.run([executable, "-n", "-r", str(path), "-T", "fields", "-e", "frame.darwin.process_info.pid"], check=True, capture_output=True, timeout=30)
        observed = decoded.stdout.decode("ascii").strip()
        if observed == "343":
            self.assertEqual(read_saved_capture(path, SAVED_ANALYSIS_LIMITS, threading.Event()).packets[0].process.labels[0].pid, 343)
        else:
            # Wireshark 4.6.9 swaps PIB PIDs using section order; current upstream fixes it.
            self.assertEqual(observed, str(int.from_bytes(struct.pack("<I", 343), "big")))
            with self.assertRaisesRegex(SavedCaptureError, "disagrees with container metadata"):
                read_saved_capture(path, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(path.read_bytes(), content)

    def test_section_local_references_do_not_accept_decoder_cross_section_reuse(self) -> None:
        content = process_capture("<", 343, b"first", 444, b"delegate") + process_capture("<", 555, b"second", 0, b"kernel")
        path = self.directory / "sections.pcapng"
        path.write_bytes(content)
        with path.open("rb") as stream:
            metadata = read_pcapng_process_metadata(stream.fileno(), 200_000, 268_435_456, time.monotonic() + 30, threading.Event())
        self.assertEqual([frame.primary[0].pid for frame in metadata.frames], [343, 555])
        executable = shutil.which("tshark")
        if executable is None:
            self.fail("Real PCAPNG interoperability requires TShark.")
        decoded = subprocess.run([executable, "-n", "-r", str(path), "-T", "fields", "-e", "frame.darwin.process_info.pid"], check=True, capture_output=True, timeout=30)
        observed = decoded.stdout.decode("ascii").splitlines()
        if observed == ["343", "555"]:
            self.assertEqual([packet.process.labels[0].pid for packet in read_saved_capture(path, SAVED_ANALYSIS_LIMITS, threading.Event()).packets], [343, 555])
        else:
            self.assertEqual(observed, ["343", "343"])
            with self.assertRaisesRegex(SavedCaptureError, "disagrees with container metadata"):
                read_saved_capture(path, SAVED_ANALYSIS_LIMITS, threading.Event())

    def test_unnamed_zero_pid_option_boundary_end_and_nul_terminated_name(self) -> None:
        content = process_capture("<", 0, b"", 4343, b"delegate\0")
        content = changed_block(content, 0x80000001, struct.pack("<I", 0))
        packet = self.read(content).packets[0]
        self.assertEqual(packet.process.state, "recorded")
        self.assertEqual((packet.process.labels[0].pid, packet.process.labels[0].name), (0, None))
        self.assertEqual(packet.effective_process.labels[0].name, "delegate")
        process_options = struct.pack("<I", 0) + option("<", 2, b"kernel")
        packet = self.read(changed_block(content, 0x80000001, process_options)).packets[0]
        self.assertEqual((packet.process.labels[0].pid, packet.process.labels[0].name), (0, "kernel"))

    def test_report_container_coverage_is_separate_and_revalidated(self) -> None:
        content = process_capture("<", 4242, b"browser", 4343, b"delegate")
        capture = self.directory / "report.pcapng"
        capture.write_bytes(content)
        report = analyze(capture, load_baseline(self.directory / "baseline.json"), 3.5)
        path = self.directory / "report.json"
        path.write_text(json.dumps(report))
        loaded = load_report(path)
        self.assertEqual(loaded.packets[0].effective_process.labels[0].pid, 4343)
        self.assertNotIn("pcapng.apple.process.epid", loaded.evidence.supported_fields)
        report["decoder"]["container_fields"] = []
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ReportValidationError, "coverage"):
            load_report(path)

    def test_malformed_known_metadata_and_container_boundaries_fail_explicitly(self) -> None:
        valid = process_capture("<", 343, b"primary", 444, b"effective")
        bad_magic = valid[:8] + b"bad!" + valid[12:]
        bad_trailer = valid[:-4] + bytes(4)
        short_option = struct.pack("<I", 343) + struct.pack("<HH", 2, 100) + bytes(4)
        bad_padding = struct.pack("<I", 343) + struct.pack("<HH", 2, 1) + b"a\x01\0\0" + bytes(4)
        malformed = (
            bad_magic, bad_trailer, valid[:-1], valid[:4] + struct.pack("<I", 29) + valid[8:],
            changed_block(valid, 0x80000001, short_option),
            changed_block(valid, 0x80000001, bad_padding),
            changed_block(valid, 0x80000001, struct.pack("<I", 343) + option("<", 2, b"\xff") + bytes(4)),
            changed_block(valid, 0x80000001, struct.pack("<I", 343) + option("<", 2, b"bad\nname") + bytes(4)),
            changed_block(valid, 0x80000001, struct.pack("<I", 2**31) + bytes(4)),
        )
        for content in malformed:
            with self.subTest(sha256=hashlib.sha256(content).hexdigest()):
                path = self.directory / "bad.pcapng"
                path.write_bytes(content)
                with self.assertRaises(SavedCaptureError) as failure:
                    read_saved_capture(path, SAVED_ANALYSIS_LIMITS, threading.Event())
                self.assertEqual(failure.exception.code, "invalid_pcapng_metadata")
                self.assertEqual(path.read_bytes(), content)

    def test_process_index_reference_and_cross_section_reference_are_rejected(self) -> None:
        valid = process_capture("<", 343, b"primary", 444, b"effective")
        marker = option("<", 0x8003, struct.pack("<I", 1))
        missing = valid.replace(marker, option("<", 0x8003, struct.pack("<I", 9)), 1)
        offset = len(block("<", 0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        interface_length = struct.unpack_from("<I", valid, offset + 4)[0]
        interface = valid[offset:offset + interface_length]
        packet_offset = valid.rfind(struct.pack("<I", 6))
        next_section = valid[:offset] + interface + valid[packet_offset:]
        for content in (missing, valid + next_section):
            with self.assertRaisesRegex(SavedCaptureError, "section's process blocks"):
                self.read(content)

    def test_unknown_blocks_are_skipped_and_decoder_disagreement_is_rejected(self) -> None:
        content = process_capture("<", 343, b"primary", 444, b"effective")
        result = self.read(content + block("<", 0x12345678, bytes(1_048_576)))
        with (self.directory / "process.pcapng").open("rb") as stream:
            metadata = read_pcapng_process_metadata(stream.fileno(), 200_000, 268_435_456, time.monotonic() + 30, threading.Event())
        with self.assertRaisesRegex(PcapngMetadataError, "frame count"):
            attach_pcapng_process_metadata((), metadata, 268_435_456, time.monotonic() + 30, threading.Event())
        first = result.packets[0]
        fields = tuple(replace(field, values=("999",)) if field.name == "frame.darwin.process_info.pid" else field for field in first.fields)
        with self.assertRaisesRegex(PcapngMetadataError, "disagrees"):
            attach_pcapng_process_metadata((replace(first, fields=fields),), metadata, 268_435_456, time.monotonic() + 30, threading.Event())

    def test_existing_cancellation_deadline_record_and_storage_ceilings_apply(self) -> None:
        content = process_capture("<", 343, b"primary", 444, b"effective")
        path = self.directory / "bounded.pcapng"
        path.write_bytes(content)
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(SavedCaptureCancelled):
            read_saved_capture(path, SAVED_ANALYSIS_LIMITS, cancelled)
        with path.open("rb") as stream:
            for records, storage, deadline in ((1, 268_435_456, time.monotonic() + 30), (200_000, 1, time.monotonic() + 30), (200_000, 268_435_456, time.monotonic() - 1)):
                with self.subTest(records=records, storage=storage), self.assertRaises(PcapngMetadataError):
                    read_pcapng_process_metadata(stream.fileno(), records, storage, deadline, threading.Event())


if __name__ == "__main__":
    unittest.main()
