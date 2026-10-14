"""Real offline DNS decoding and malformed-evidence rejection at its boundary."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import shutil
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Callable
from unittest.mock import patch

import captured_dns
import saved_capture
from captured_dns import (
    CapturedDnsCancelled, CapturedDnsValidationError, decode_captured_dns,
    dns_evidence_document, validate_dns_evidence_document,
)
from saved_capture import SAVED_ANALYSIS_LIMITS, SavedCaptureCancelled, SavedCaptureError, read_saved_capture
from tests.dns_fixture import address_record, dns_capture, dns_frame_number, dns_message, dns_transport
from tests.saved_capture_fixture import dns_name
from tests.session_fixture import transport_packet


def segmented_dns_capture() -> bytes:
    """Save a split TCP response and two identical DNS messages in one later PDU."""
    question = dns_name("segmented.test") + struct.pack("!HH", 1, 1)
    answer = dns_name("segmented.test") + struct.pack("!HHIH", 1, 1, 30, 4)
    answer += ipaddress.IPv4Address("198.51.100.20").packed
    query = struct.pack("!HHHHHH", 8, 0x0100, 1, 0, 0, 0) + question
    response = struct.pack("!HHHHHH", 8, 0x8180, 1, 1, 0, 0) + question + answer
    message = struct.pack("!H", len(response)) + response
    frames = (
        transport_packet("192.0.2.2", "192.0.2.53", 53001, 53, "tcp", 100, 0, 2, b""),
        transport_packet("192.0.2.53", "192.0.2.2", 53, 53001, "tcp", 200, 101, 18, b""),
        transport_packet("192.0.2.2", "192.0.2.53", 53001, 53, "tcp", 101, 201, 16, b""),
        transport_packet("192.0.2.2", "192.0.2.53", 53001, 53, "tcp", 101, 201, 24, struct.pack("!H", len(query)) + query),
        transport_packet("192.0.2.53", "192.0.2.2", 53, 53001, "tcp", 201, 103 + len(query), 16, message[:20]),
        transport_packet("192.0.2.53", "192.0.2.2", 53, 53001, "tcp", 221, 103 + len(query), 24, message[20:]),
        transport_packet("192.0.2.53", "192.0.2.2", 53, 53001, "tcp", 201 + len(message), 103 + len(query), 24, message + message),
    )
    header = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65_535, 101)
    return header + b"".join(struct.pack("<IIII", 1000 + index, 0, len(packet), len(packet)) + packet
                             for index, packet in enumerate(frames))


class CapturedDnsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        executable = shutil.which("tshark")
        if executable is None:
            raise RuntimeError("Structured DNS integration requires real TShark on PATH.")
        cls.executable = executable
        cls.owned_directory = tempfile.TemporaryDirectory(prefix="rvi-sentinel-dns-decoder-")
        cls.addClassCleanup(cls.owned_directory.cleanup)
        cls.directory = Path(cls.owned_directory.name)
        cls.capture = cls.directory / "dns.pcapng"
        cls.content = dns_capture("pcapng")
        cls.capture.write_bytes(cls.content)
        cls.saved = read_saved_capture(cls.capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        output = subprocess.run((executable, "-n", "-r", str(cls.capture), "-Y", "dns || mdns || llmnr",
                                 "-T", "json", "--no-duplicate-keys", "-J", "frame dns mdns llmnr"),
                                capture_output=True, check=True, timeout=20)
        cls.wire = json.loads(output.stdout)

    def test_real_answer_owners_values_ttls_and_query_references_stay_paired(self) -> None:
        evidence = self.saved.dns_evidence
        self.assertEqual(evidence.capture_sha256, hashlib.sha256(self.content).hexdigest())
        response = next(message for message in evidence.messages
                        if message.frame_number == dns_frame_number("cname_response"))
        self.assertEqual(response.response_to_frame, dns_frame_number("cname_query"))
        self.assertEqual(response.transaction_id, 100)
        self.assertTrue(response.is_response)
        self.assertFalse(response.is_truncated)
        self.assertEqual(response.response_code, 0)
        self.assertEqual(tuple((record.owner, record.record_type, record.ttl_seconds, record.value)
                               for record in response.answers), (
            ("service.test", 5, 30, "edge.test"),
            ("edge.test", 1, 60, "198.51.100.20"),
            ("unrelated-answer.test", 1, 120, "198.51.100.21"),
        ))
        self.assertNotIn("ns.test", tuple(record.owner for record in response.answers))
        self.assertEqual(self.capture.read_bytes(), self.content)

    def test_real_multiple_questions_ipv6_mdns_negative_and_truncated_are_observations(self) -> None:
        messages = {message.frame_number: message for message in self.saved.dns_evidence.messages}
        multiple = messages[dns_frame_number("multiple_questions_response")]
        self.assertEqual(tuple(question.name for question in multiple.questions), ("first.test", "second.test"))
        ipv6 = messages[dns_frame_number("aaaa_response")]
        self.assertEqual(ipv6.answers[0].record_type, 28)
        self.assertEqual(ipv6.answers[0].value, "2001:db8::20")
        mdns = messages[dns_frame_number("mdns_response")]
        self.assertEqual(mdns.protocol, "mdns")
        self.assertEqual(mdns.questions, ())
        self.assertEqual(mdns.answers[0].owner, "printer.local")
        self.assertEqual(messages[dns_frame_number("nxdomain_response")].response_code, 3)
        self.assertTrue(messages[dns_frame_number("truncated_response")].is_truncated)

    def test_real_tcp_reassembly_and_repeated_messages_have_distinct_ordinals(self) -> None:
        capture = self.directory / "tcp-segments.pcap"
        original = segmented_dns_capture()
        capture.write_bytes(original)
        saved = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(tuple((message.frame_number, message.message_index) for message in saved.dns_evidence.messages),
                         ((4, 0), (6, 0), (7, 0), (7, 1)))
        self.assertEqual(saved.dns_evidence.messages[1].response_to_frame, 4)
        self.assertEqual(saved.dns_evidence.messages[1].answers[0].value, "198.51.100.20")
        self.assertEqual(capture.read_bytes(), original)

    def test_real_classic_capture_roundtrip_binds_every_observed_dns_frame(self) -> None:
        capture = self.directory / "dns.pcap"
        capture.write_bytes(dns_capture("pcap"))
        saved = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        document = dns_evidence_document(saved.dns_evidence)
        restored = validate_dns_evidence_document(document, saved.sha256, saved.packets, threading.Event())
        self.assertEqual(restored, saved.dns_evidence)
        self.assertEqual({message.frame_number for message in restored.messages},
                         {packet.frame_number for packet in saved.packets
                          if set(packet.protocol_stack) & {"dns", "mdns", "llmnr"}})
        self.assertTrue(all(packet.process.state == "unknown" for packet in saved.packets))

    def test_unsupported_answer_metadata_is_retained_without_inventing_rdata(self) -> None:
        wire = copy.deepcopy(self.wire)
        response = wire[1]["_source"]["layers"]["dns"]
        record = next(iter(response["Answers"].values()))
        record["dns.resp.type"] = "16"
        del record["dns.cname"]
        record["dns.txt"] = "unconsumed source data"
        evidence = decode_captured_dns(json.dumps(wire).encode(), self.saved.sha256,
                                       self.saved.packets, threading.Event())
        observed = next(message for message in evidence.messages if message.frame_number == 2).answers[0]
        self.assertEqual(observed.record_type, 16)
        self.assertEqual(observed.owner, "service.test")
        self.assertEqual(observed.ttl_seconds, 30)
        self.assertIsNone(observed.value)

    def test_missing_count_scalar_array_and_conflicting_flags_are_rejected(self) -> None:
        mutations = (
            ("count", lambda message: message.__setitem__("dns.count.answers", "4")),
            ("scalar array", lambda message: message.__setitem__("dns.id", ["0x0064", "0x0065"])),
            ("response bit", lambda message: message["dns.flags_tree"].__setitem__("dns.flags.response", "0")),
            ("truncation bit", lambda message: message["dns.flags_tree"].__setitem__("dns.flags.truncated", "1")),
            ("response code", lambda message: message["dns.flags_tree"].__setitem__("dns.flags.rcode", "3")),
            ("opcode", lambda message: message["dns.flags_tree"].__setitem__("dns.flags.opcode", "5")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                wire = copy.deepcopy(self.wire)
                mutate(wire[1]["_source"]["layers"]["dns"])
                with self.assertRaises(CapturedDnsValidationError):
                    decode_captured_dns(json.dumps(wire).encode(), self.saved.sha256,
                                        self.saved.packets, threading.Event())

    def test_rr_scalar_array_family_and_cross_type_values_are_rejected(self) -> None:
        for value in (["198.51.100.20", "198.51.100.21"], "2001:db8::20", "bad address"):
            wire = copy.deepcopy(self.wire)
            record = tuple(wire[1]["_source"]["layers"]["dns"]["Answers"].values())[1]
            record["dns.a"] = value
            with self.subTest(value=value), self.assertRaises(CapturedDnsValidationError):
                decode_captured_dns(json.dumps(wire).encode(), self.saved.sha256,
                                    self.saved.packets, threading.Event())
        wire = copy.deepcopy(self.wire)
        record = tuple(wire[1]["_source"]["layers"]["dns"]["Answers"].values())[1]
        record["dns.aaaa"] = "2001:db8::20"
        with self.assertRaises(CapturedDnsValidationError):
            decode_captured_dns(json.dumps(wire).encode(), self.saved.sha256,
                                self.saved.packets, threading.Event())

    def test_duplicate_keys_excessive_depth_invalid_constants_and_incomplete_output_fail(self) -> None:
        candidates = (b'[{"_source":{},"_source":{}}]', b"[" * 49 + b"]" * 49,
                      b"[NaN]", b"[", b"\xff", b"[]")
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(CapturedDnsValidationError):
                decode_captured_dns(candidate, self.saved.sha256, self.saved.packets, threading.Event())

    def test_one_or_many_rr_nodes_preserve_duplicates_and_counts(self) -> None:
        wire = copy.deepcopy(self.wire)
        response = wire[1]["_source"]["layers"]["dns"]
        key = next(iter(response["Answers"]))
        response["Answers"][key] = [response["Answers"][key], copy.deepcopy(response["Answers"][key])]
        response["dns.count.answers"] = "4"
        evidence = decode_captured_dns(json.dumps(wire).encode(), self.saved.sha256,
                                       self.saved.packets, threading.Event())
        answers = next(message for message in evidence.messages if message.frame_number == 2).answers
        self.assertEqual(len(answers), 4)
        self.assertEqual(answers[0], answers[1])

    def test_report_digest_frame_ordinal_types_and_closed_schema_are_revalidated(self) -> None:
        for mutation in ("digest", "missing", "ordinal", "bool", "unknown", "rdata", "protocol"):
            document = copy.deepcopy(dns_evidence_document(self.saved.dns_evidence))
            if mutation == "digest":
                document["capture_sha256"] = "0" * 64
            elif mutation == "missing":
                document["messages"].pop()
            elif mutation == "ordinal":
                document["messages"][0]["message_index"] = 1
            elif mutation == "bool":
                document["messages"][0]["transaction_id"] = True
            elif mutation == "unknown":
                document["messages"][0]["extra"] = "unrecognized"
            elif mutation == "rdata":
                document["messages"][1]["answers"][0]["value"] = "Edge.Test."
            else:
                document["messages"][0]["protocol"] = "mdns"
            with self.subTest(mutation=mutation), self.assertRaises(CapturedDnsValidationError):
                validate_dns_evidence_document(document, self.saved.sha256, self.saved.packets, threading.Event())

    def test_cancelled_parse_and_report_validation_publish_no_partial_result(self) -> None:
        cancellation = threading.Event()
        cancellation.set()
        with self.assertRaises(CapturedDnsCancelled):
            decode_captured_dns(json.dumps(self.wire).encode(), self.saved.sha256,
                                self.saved.packets, cancellation)
        with self.assertRaises(CapturedDnsCancelled):
            validate_dns_evidence_document(dns_evidence_document(self.saved.dns_evidence),
                                           self.saved.sha256, self.saved.packets, cancellation)

    def test_nonstandard_opcode_is_preserved_without_reinterpreting_header_bits(self) -> None:
        wire = copy.deepcopy(self.wire)
        response = wire[1]["_source"]["layers"]["dns"]
        response["dns.flags"] = "0xa980"
        response["dns.flags_tree"]["dns.flags.opcode"] = "5"
        evidence = decode_captured_dns(json.dumps(wire).encode(), self.saved.sha256,
                                       self.saved.packets, threading.Event())
        observed = next(message for message in evidence.messages if message.frame_number == 2)
        self.assertEqual(observed.opcode, 5)
        self.assertTrue(observed.is_response)
        self.assertEqual(observed.response_code, 0)
        self.assertEqual(validate_dns_evidence_document(dns_evidence_document(evidence),
                         self.saved.sha256, self.saved.packets, threading.Event()), evidence)

    def test_real_edns_extended_error_cannot_become_successful_address_evidence(self) -> None:
        payload = dns_message(77, 0x8180, (("edns.test", 1, 1),),
                              (address_record("edns.test", "198.51.100.20", 60),), (), ())
        payload = payload[:10] + b"\0\1" + payload[12:] + b"\0" + struct.pack("!HHIH", 41, 4096, 1 << 24, 0)
        packet = dns_transport("192.0.2.53", "192.0.2.2", 53, 53000, "udp", payload, 0, 0)
        content = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65_535, 101)
        content += struct.pack("<IIII", 1000, 0, len(packet), len(packet)) + packet
        capture = self.directory / "edns-bad-version.pcap"
        capture.write_bytes(content)
        saved = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(saved.dns_evidence.messages[0].response_code, 16)
        self.assertEqual(saved.dns_evidence.messages[0].answers[0].value, "198.51.100.20")
        self.assertEqual(validate_dns_evidence_document(dns_evidence_document(saved.dns_evidence),
                         saved.sha256, saved.packets, threading.Event()), saved.dns_evidence)
        output = subprocess.run((self.executable, "-n", "-r", str(capture), "-T", "json",
                                 "--no-duplicate-keys", "-J", "frame dns mdns llmnr"),
                                capture_output=True, check=True, timeout=20)
        for mutation in ("scalar", "duplicate", "missing", "outside_opt"):
            wire = json.loads(output.stdout)
            message = wire[0]["_source"]["layers"]["dns"]
            key = next(iter(message["Additional records"]))
            record = message["Additional records"][key]
            if mutation == "scalar":
                record["dns.resp.ext_rcode"] = ["0x01", "0x02"]
            elif mutation == "duplicate":
                message["Additional records"][key] = [record, copy.deepcopy(record)]
                message["dns.count.add_rr"] = "2"
            elif mutation == "missing":
                del message["Additional records"]
            else:
                record["dns.resp.type"] = "1"
            with self.subTest(mutation=mutation), self.assertRaises(CapturedDnsValidationError):
                decode_captured_dns(json.dumps(wire).encode(), saved.sha256, saved.packets, threading.Event())
        self.assertEqual(capture.read_bytes(), content)

    def test_real_srv_without_decoder_owner_remains_an_unsupported_observation(self) -> None:
        payload = dns_message(77, 0x8180, (("_svc._tcp.local", 33, 1),),
            (("_svc._tcp.local", 33, 1, 40, struct.pack("!HHH", 0, 0, 1234) + dns_name("host.local")),), (), ())
        packet = dns_transport("192.0.2.53", "192.0.2.2", 53, 53000, "udp", payload, 0, 0)
        content = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65_535, 101)
        content += struct.pack("<IIII", 1000, 0, len(packet), len(packet)) + packet
        capture = self.directory / "srv.pcap"
        capture.write_bytes(content)
        saved = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        record = saved.dns_evidence.messages[0].answers[0]
        self.assertEqual((record.record_type, record.record_class, record.ttl_seconds), (33, 1, 40))
        self.assertIsNone(record.owner)
        self.assertIsNone(record.value)
        self.assertEqual(validate_dns_evidence_document(dns_evidence_document(saved.dns_evidence),
                         saved.sha256, saved.packets, threading.Event()), saved.dns_evidence)
        document = dns_evidence_document(saved.dns_evidence)
        document["messages"][0]["answers"][0]["record_type"] = 1
        document["messages"][0]["answers"][0]["value"] = "198.51.100.20"
        with self.assertRaises(CapturedDnsValidationError):
            validate_dns_evidence_document(document, saved.sha256, saved.packets, threading.Event())

    def test_frame_time_length_protocol_and_invalid_unicode_cannot_change_evidence_basis(self) -> None:
        for field, replacement in (("frame.time_epoch", "2000-01-01T00:00:00.000000001Z"),
                                   ("frame.len", "1"), ("frame.protocols", "raw:ip:udp:mdns")):
            wire = copy.deepcopy(self.wire)
            wire[0]["_source"]["layers"]["frame"][field] = replacement
            with self.subTest(field=field), self.assertRaises(CapturedDnsValidationError):
                decode_captured_dns(json.dumps(wire).encode(), self.saved.sha256,
                                    self.saved.packets, threading.Event())
        wire = copy.deepcopy(self.wire)
        question = next(iter(wire[0]["_source"]["layers"]["dns"]["Queries"].values()))
        for value in ("\ud800", "a" * 1025):
            question["dns.qry.name"] = value
            with self.subTest(value_length=len(value)), self.assertRaises(CapturedDnsValidationError):
                decode_captured_dns(json.dumps(wire).encode(), self.saved.sha256,
                                    self.saved.packets, threading.Event())
        with self.assertRaises(CapturedDnsValidationError):
            decode_captured_dns(json.dumps(self.wire).encode("utf-16"), self.saved.sha256,
                                self.saved.packets, threading.Event())

    def test_resource_ceiling_failures_never_return_a_partial_collection(self) -> None:
        original = json.dumps(self.wire).encode()
        document = dns_evidence_document(self.saved.dns_evidence)
        for limit in ("DNS_MAX_JSON_BYTES", "DNS_MAX_MESSAGES", "DNS_MAX_RECORDS", "DNS_MAX_RETAINED_BYTES"):
            with self.subTest(limit=limit), patch.object(captured_dns, limit, 1):
                with self.assertRaises(CapturedDnsValidationError):
                    decode_captured_dns(original, self.saved.sha256, self.saved.packets, threading.Event())
                if limit != "DNS_MAX_JSON_BYTES":
                    with self.assertRaises(CapturedDnsValidationError):
                        validate_dns_evidence_document(document, self.saved.sha256,
                                                       self.saved.packets, threading.Event())

    def test_source_change_after_real_structured_pass_is_detected_before_success(self) -> None:
        capture = self.directory / "changed-after-dns.pcapng"
        capture.write_bytes(self.content)
        real_run = saved_capture._run_decoder

        def observe_run(executable: str, arguments: tuple[str, ...], output_limit: int, stderr_limit: int,
                        deadline: float, cancellation: threading.Event,
                        consume: Callable[[bytes], None], input_descriptor: int | None) -> bytes:
            result = real_run(executable, arguments, output_limit, stderr_limit, deadline, cancellation, consume, input_descriptor)
            if "json" in arguments:
                capture.write_bytes(self.content + b"changed")
            return result

        with patch.object(saved_capture, "_run_decoder", observe_run), self.assertRaises(SavedCaptureError) as failure:
            read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        self.assertEqual(failure.exception.code, "changed_capture")

    def test_cancellation_after_real_structured_child_exits_is_not_completed_evidence(self) -> None:
        cancellation = threading.Event()
        real_run = saved_capture._run_decoder

        def observe_run(executable: str, arguments: tuple[str, ...], output_limit: int, stderr_limit: int,
                        deadline: float, event: threading.Event,
                        consume: Callable[[bytes], None], input_descriptor: int | None) -> bytes:
            result = real_run(executable, arguments, output_limit, stderr_limit, deadline, event, consume, input_descriptor)
            if "json" in arguments:
                event.set()
            return result

        with patch.object(saved_capture, "_run_decoder", observe_run), self.assertRaises(SavedCaptureCancelled):
            read_saved_capture(self.capture, SAVED_ANALYSIS_LIMITS, cancellation)
        self.assertEqual(self.capture.read_bytes(), self.content)


if __name__ == "__main__":
    unittest.main()
