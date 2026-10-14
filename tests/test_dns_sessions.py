"""Real saved DNS evidence, conservative candidate boundaries and exact frame tracing."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

import dns_sessions
from captured_dns import (
    CapturedDnsEvidence, CapturedDnsMessage, DnsQuestion, DnsResourceRecord,
    dns_evidence_document, validate_dns_evidence_document,
)
from dns_sessions import (
    DnsAssociationIdentity, DnsQuery, DnsSessionCancelled, DnsSessionIndex,
    DnsSessionValidationError, build_dns_session_index, dns_association_for_identity,
    observed_dns_frames, query_dns_associations,
)
from packet_models import PacketRecord, decode_packet_fields
from packet_sessions import SessionIdentity, build_session_index, session_for_identity
from packet_timeline import build_packet_index
from saved_capture import SAVED_ANALYSIS_LIMITS, SavedAnalysis, read_saved_capture
from tests.dns_fixture import (
    DNSQuestion, DNSResourceRecord, address_record, classic_dns_capture,
    dns_capture, dns_frame_number, dns_message, dns_transport, name_record,
)
from tests.session_fixture import transport_packet


def replacement_capture(initial_question: DNSQuestion, initial_answers: tuple[DNSResourceRecord, ...],
                        later_question: DNSQuestion, later_answers: tuple[DNSResourceRecord, ...],
                        later_flags: int) -> bytes:
    """Build two real linked exchanges around one surviving target transport scope."""
    client, resolver, original, replacement = "192.0.2.2", "192.0.2.53", "198.51.100.20", "198.51.100.30"
    packets = (
        dns_transport(client, resolver, 53000, 53, "udp", dns_message(201, 0x0100, (initial_question,), (), (), ()), 0, 0),
        dns_transport(resolver, client, 53, 53000, "udp", dns_message(201, 0x8180, (initial_question,), initial_answers, (), ()), 0, 0),
        transport_packet(client, original, 54000, 443, "tcp", 100, 0, 2, b""),
        dns_transport(client, resolver, 53001, 53, "udp", dns_message(202, 0x0100, (later_question,), (), (), ()), 0, 0),
        dns_transport(resolver, client, 53, 53001, "udp", dns_message(202, later_flags, (later_question,), later_answers, (), ()), 0, 0),
        transport_packet(client, original, 54000, 443, "tcp", 101, 0, 16, b""),
        transport_packet(client, replacement, 54001, 443, "tcp", 200, 0, 2, b""),
    )
    return classic_dns_capture(tuple((packet, index * 1_000_000_000) for index, packet in enumerate(packets)))


def rewrite_packet(packet: PacketRecord, fields: dict[str, tuple[str, ...]]) -> PacketRecord:
    """Produce new validated packet evidence without modifying its original fields."""
    values = {field.name: field.values for field in packet.fields}
    values.update(fields)
    return decode_packet_fields(values, tuple(values))


def correlate(packets: tuple[PacketRecord, ...], evidence: CapturedDnsEvidence) -> DnsSessionIndex:
    packet_index = build_packet_index(evidence.capture_sha256, packets, threading.Event())
    sessions = build_session_index(packet_index, threading.Event())
    return build_dns_session_index(sessions, evidence, threading.Event())


def replace_message(evidence: CapturedDnsEvidence, message: CapturedDnsMessage) -> CapturedDnsEvidence:
    """Replace one exact frame/message in an immutable evidence collection."""
    return replace(evidence, messages=tuple(message if (item.frame_number, item.message_index) ==
                                          (message.frame_number, message.message_index) else item
                                          for item in evidence.messages))


def many_question_links(saved: SavedAnalysis, count: int) -> tuple[tuple[PacketRecord, ...], CapturedDnsEvidence]:
    """Expand real TCP packet scopes at the typed domain seam; these are synthetic message observations."""
    frames = (dns_frame_number("tcp_dns_query"), dns_frame_number("tcp_dns_response"),
              dns_frame_number("tcp_dns_target"))
    packets = tuple(packet for packet in saved.packets if packet.frame_number in frames)
    query = next(message for message in saved.dns_evidence.messages if message.frame_number == frames[0])
    response = next(message for message in saved.dns_evidence.messages if message.frame_number == frames[1])
    questions = tuple(DnsQuestion(f"question{position}.test", 1, 1) for position in range(count))
    queries = tuple(replace(query, message_index=position, questions=(question,))
                    for position, question in enumerate(questions))
    responses = tuple(replace(response, message_index=position, questions=(question,),
                              answers=(replace(response.answers[0], owner=question.name),))
                      for position, question in enumerate(questions))
    evidence = CapturedDnsEvidence(saved.sha256, queries + responses)
    return packets, validate_dns_evidence_document(dns_evidence_document(evidence), saved.sha256,
                                                   packets, threading.Event())


class DnsSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("DNS session integration requires the real saved-file TShark decoder on PATH.")
        cls.saved: dict[str, SavedAnalysis] = {}
        cls.indexes: dict[str, DnsSessionIndex] = {}
        with tempfile.TemporaryDirectory(prefix="rvi-sentinel-dns-domain-") as temporary:
            for container in ("pcap", "pcapng"):
                capture = Path(temporary) / ("passive-dns." + container)
                content = dns_capture(container)
                capture.write_bytes(content)
                result = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
                cls.saved[container] = result
                cls.indexes[container] = correlate(result.packets, result.dns_evidence)
                if capture.read_bytes() != content:
                    raise AssertionError("Passive decoding modified the original generated capture bytes.")

    def test_real_decoder_preserves_rr_relationships_links_and_original_packet_evidence(self) -> None:
        for container, index in self.indexes.items():
            with self.subTest(container=container):
                result = self.saved[container]
                self.assertEqual(result.sha256, hashlib.sha256(dns_capture(container)).hexdigest())
                self.assertEqual(len(result.packets), 42)
                self.assertEqual(len(result.dns_evidence.messages), 20)
                self.assertIs(index.dns_evidence, result.dns_evidence)
                response = next(item for item in result.dns_evidence.messages if item.frame_number == 2)
                self.assertEqual(response.response_to_frame, 1)
                self.assertEqual(response.message_index, 0)
                self.assertEqual(response.questions[0].name, "service.test")
                self.assertEqual(tuple((record.owner, record.record_type, record.ttl_seconds, record.value)
                                       for record in response.answers),
                                 (("service.test", 5, 30, "edge.test"),
                                  ("edge.test", 1, 60, "198.51.100.20"),
                                  ("unrelated-answer.test", 1, 120, "198.51.100.21")))
                self.assertNotIn("203.0.113.99", {record.value for record in response.answers})
                originals = {packet.frame_number: packet for packet in result.packets}
                self.assertTrue(all(packet is originals[packet.frame_number]
                                    for packet in index.session_index.packet_index.packets))
                for association in index.associations:
                    self.assertIs(dns_association_for_identity(index, association.identity), association)
                    self.assertEqual(association.identity.capture_sha256, result.sha256)
                    session = session_for_identity(index.session_index, association.session_identity)
                    self.assertIsNotNone(session)
                    if session is None:
                        raise AssertionError("The candidate's exact scoped session is unavailable.")
                    self.assertTrue(set(association.matching_frames).issubset(session.member_frames))
                with self.assertRaises(FrozenInstanceError):
                    setattr(response, "frame_number", 900)

    def test_client_interface_shared_address_and_partial_lifetime_are_exact(self) -> None:
        for container, index in self.indexes.items():
            with self.subTest(container=container):
                expected_service = {(3, 4), (5,), (8,)}
                expected_shared = {(8,), (42,)}
                if container == "pcap":
                    expected_service.add((33,))
                    expected_shared.add((33,))
                service = tuple(item for item in index.associations if item.question_name == "service.test")
                shared = tuple(item for item in index.associations if item.question_name == "shared.test")
                self.assertEqual({item.matching_frames for item in service}, expected_service)
                self.assertEqual({item.matching_frames for item in shared}, expected_shared)
                self.assertTrue(all(item.record_ordinals == (1, 2) and item.ttl_seconds == 30 for item in service))
                main = next(item for item in service if item.matching_frames == (3, 4))
                session = session_for_identity(index.session_index, main.session_identity)
                self.assertIsNotNone(session)
                if session is None:
                    raise AssertionError("The partial-lifetime session is unavailable.")
                self.assertEqual(session.member_frames, (41, 3, 4, 42))
                self.assertEqual(main.expires_at_epoch, "1791428479.590385001")
                self.assertNotIn(41, main.matching_frames)
                self.assertNotIn(42, main.matching_frames)
                common = next(item for item in service if item.matching_frames == (8,))
                self.assertEqual(common.session_identity, next(item for item in shared if item.matching_frames == (8,)).session_identity)
                self.assertNotEqual(common.identity, next(item for item in shared if item.matching_frames == (8,)).identity)
                self.assertEqual({item.process_relation for item in index.associations},
                                 {"unknown" if container == "pcap" else "different"})

    def test_aaaa_tcp_dns_and_unsafe_observations_remain_separate(self) -> None:
        index = self.indexes["pcapng"]
        self.assertEqual({item.matching_frames for item in index.associations if item.question_name == "ipv6.test"}, {(11, 12)})
        self.assertEqual({item.matching_frames for item in index.associations if item.question_name == "tcp-dns.test"}, {(40,)})
        excluded = {dns_frame_number(label) for label in (
            "multiple_questions_target", "nxdomain_target", "truncated_target", "mdns_target",
            "unsolicited_target", "cycle_target", "query_known_answer_target", "different_client_target",
            "different_interface_target", "expired_target", "before_response_target",
            "unrelated_answer_target", "additional_target",
        )}
        self.assertTrue(excluded.isdisjoint({frame for item in index.associations for frame in item.matching_frames}))
        reasons = {item.frame_number: item.reason for item in index.diagnostics}
        for label, expected in (
            ("multiple_questions_response", "ambiguous_question_count"),
            ("nxdomain_response", "non_success_response"),
            ("truncated_response", "truncated_response"),
            ("mdns_response", "multicast_or_local_name_protocol"),
            ("unsolicited_response", "unlinked_response"),
            ("cycle_response", "ambiguous_cname"),
            ("query_known_answer", "question_observation"),
        ):
            self.assertEqual(reasons[dns_frame_number(label)], expected)
        self.assertEqual(len(observed_dns_frames(index)), 20)

    def test_linked_question_requires_reversed_tuple_same_stream_and_interface(self) -> None:
        saved = self.saved["pcapng"]
        for changed, reason in (
            ({"udp.srcport": ("53099",)}, "question_response_transport_mismatch"),
            ({"udp.stream": ("999",)}, "question_response_transport_mismatch"),
            ({"frame.interface_name": ("different-fixture",)}, "question_response_scope_mismatch"),
            ({"pktap.ifname": ("different-fixture",)}, "question_response_scope_mismatch"),
        ):
            with self.subTest(changed=changed):
                packets = tuple(rewrite_packet(packet, changed) if packet.frame_number == 1 else packet for packet in saved.packets)
                index = correlate(packets, saved.dns_evidence)
                self.assertFalse(any(item.response_frame == 2 for item in index.associations))
                self.assertEqual(next(item.reason for item in index.diagnostics if item.frame_number == 2), reason)

    def test_zero_high_bit_and_duplicate_rrset_ttls_use_explicit_failures_and_minimum(self) -> None:
        saved = self.saved["pcapng"]
        response = next(item for item in saved.dns_evidence.messages if item.frame_number == 2)
        for ttl in (0, 2**31):
            with self.subTest(ttl=ttl):
                records = (replace(response.answers[0], ttl_seconds=ttl),) + response.answers[1:]
                index = correlate(saved.packets, replace_message(saved.dns_evidence, replace(response, answers=records)))
                self.assertFalse(any(item.response_frame == 2 for item in index.associations))
                self.assertEqual(next(item.reason for item in index.diagnostics if item.frame_number == 2), "zero_or_invalid_ttl")
        duplicate = DnsResourceRecord("edge.test", 1, 1, 5, "198.51.100.20")
        index = correlate(saved.packets, replace_message(saved.dns_evidence,
            replace(response, answers=response.answers + (duplicate,))))
        candidates = tuple(item for item in index.associations if item.response_frame == 2)
        self.assertEqual({item.matching_frames for item in candidates}, {(3, 4), (5,)})
        self.assertTrue(all(item.ttl_seconds == 5 and item.record_ordinals == (1, 2, 4) for item in candidates))

    def test_cname_cycles_and_branching_do_not_guess_an_address_owner(self) -> None:
        saved = self.saved["pcapng"]
        response = next(item for item in saved.dns_evidence.messages if item.frame_number == 2)
        for records, reason in (
            ((response.answers[0], DnsResourceRecord("edge.test", 5, 1, 60, "service.test")), "cyclic_cname"),
            ((response.answers[0], DnsResourceRecord("service.test", 5, 1, 60, "other.test"), response.answers[1]), "ambiguous_cname"),
        ):
            with self.subTest(reason=reason):
                index = correlate(saved.packets, replace_message(saved.dns_evidence, replace(response, answers=records)))
                self.assertFalse(any(item.response_frame == 2 for item in index.associations))
                self.assertEqual(next(item.reason for item in index.diagnostics if item.frame_number == 2), reason)

    def test_question_ambiguity_nonstandard_opcode_and_alias_hop_limit_remain_observed(self) -> None:
        saved = self.saved["pcapng"]
        query = next(item for item in saved.dns_evidence.messages if item.frame_number == 1)
        response = next(item for item in saved.dns_evidence.messages if item.frame_number == 2)
        duplicate_query = replace(saved.dns_evidence,
            messages=(query, replace(query, message_index=1)) + saved.dns_evidence.messages[1:])
        excessive_chain = tuple(DnsResourceRecord("service.test" if hop == 0 else f"hop{hop - 1}.test",
            5, 1, 60, f"hop{hop}.test") for hop in range(17)) + (
            DnsResourceRecord("hop16.test", 1, 1, 60, "198.51.100.20"),)
        for evidence, reason in (
            (duplicate_query, "missing_or_ambiguous_linked_question"),
            (replace_message(saved.dns_evidence, replace(response, opcode=1)), "unsupported_opcode"),
            (replace_message(saved.dns_evidence, replace(response, answers=excessive_chain)), "cname_hop_limit"),
        ):
            with self.subTest(reason=reason):
                index = correlate(saved.packets, evidence)
                self.assertFalse(any(item.response_frame == 2 for item in index.associations))
                self.assertEqual(next(item.reason for item in index.diagnostics if item.frame_number == 2), reason)

    def test_many_messages_in_one_tcp_frame_keep_exact_links_and_reject_duplicate_questions(self) -> None:
        packets, evidence = many_question_links(self.saved["pcapng"], 5_000)
        original_messages = evidence.messages
        index = correlate(packets, evidence)
        self.assertEqual(len(index.associations), 5_000)
        self.assertEqual({item.question_name for item in index.associations},
                         {f"question{position}.test" for position in range(5_000)})
        self.assertTrue(all((item.query_frame, item.response_frame, item.matching_frames, item.record_ordinals) ==
                            (38, 39, (40,), (1,)) for item in index.associations))
        duplicate = replace(evidence.messages[0], message_index=5_000)
        ambiguous = replace(evidence, messages=evidence.messages[:5_000] + (duplicate,) + evidence.messages[5_000:])
        ambiguous = validate_dns_evidence_document(dns_evidence_document(ambiguous), evidence.capture_sha256,
                                                   packets, threading.Event())
        denied = correlate(packets, ambiguous)
        self.assertEqual(len(denied.associations), 4_999)
        self.assertNotIn("question0.test", {item.question_name for item in denied.associations})
        self.assertEqual(next(item.reason for item in denied.diagnostics
                              if item.frame_number == 39 and item.message_index == 0),
                         "missing_or_ambiguous_linked_question")
        self.assertIs(evidence.messages, original_messages)
        self.assertEqual(len(index.associations), 5_000)

    def test_cancelled_query_link_index_publishes_no_partial_correlations(self) -> None:
        packets, evidence = many_question_links(self.saved["pcapng"], 5_000)
        packet_index = build_packet_index(evidence.capture_sha256, packets, threading.Event())
        session_index = build_session_index(packet_index, threading.Event())
        cancellation = threading.Event()
        original_check = dns_sessions._check_cancelled
        checks = 0

        def cancel_during_index(event: threading.Event) -> None:
            nonlocal checks
            checks += 1
            if checks == 128:
                event.set()
            original_check(event)

        with patch.object(dns_sessions, "_check_cancelled", cancel_during_index):
            with self.assertRaises(DnsSessionCancelled):
                build_dns_session_index(session_index, evidence, cancellation)
        self.assertEqual(checks, 128)
        self.assertEqual(len(evidence.messages), 10_000)
        self.assertEqual(len(session_index.packet_index.packets), 3)

    def test_equal_epoch_frame_order_and_half_open_expiry_are_exact(self) -> None:
        saved = self.saved["pcapng"]
        packets = {packet.frame_number: packet for packet in saved.packets}
        query = rewrite_packet(packets[1], {"frame.number": ("2",)})
        response = rewrite_packet(packets[2], {"frame.number": ("3",)})
        before = rewrite_packet(packets[3], {"frame.number": ("1",), "frame.time_epoch": (response.timestamp.epoch,)})
        tied = rewrite_packet(packets[4], {"frame.number": ("4",), "frame.time_epoch": (response.timestamp.epoch,)})
        expiry = f"{response.timestamp.seconds + 30}.{response.timestamp.nanoseconds:09d}"
        expired = rewrite_packet(packets[41], {"frame.number": ("5",), "frame.time_epoch": (expiry,)})
        query_message = next(item for item in saved.dns_evidence.messages if item.frame_number == 1)
        response_message = next(item for item in saved.dns_evidence.messages if item.frame_number == 2)
        evidence = replace(saved.dns_evidence, messages=(replace(query_message, frame_number=2),
            replace(response_message, frame_number=3, response_to_frame=2)))
        index = correlate((before, query, response, tied, expired), evidence)
        self.assertEqual(len(index.associations), 1)
        self.assertEqual(index.associations[0].matching_frames, (4,))
        session = session_for_identity(index.session_index, index.associations[0].session_identity)
        self.assertIsNotNone(session)
        if session is None:
            raise AssertionError("The exact tied-epoch scoped session is unavailable.")
        self.assertEqual(session.member_frames, (1, 4, 5))

    def test_cancel_storage_and_comparison_limits_publish_no_partial_result(self) -> None:
        index = self.indexes["pcapng"]
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(DnsSessionCancelled):
            build_dns_session_index(index.session_index, index.dns_evidence, cancelled)
        with self.assertRaises(DnsSessionCancelled):
            query_dns_associations(index, DnsQuery("", None, 1, 100), None, cancelled)
        for limit in ("DNS_MAX_MESSAGES", "MAX_DNS_ASSOCIATIONS", "MAX_DNS_ASSOCIATION_BYTES", "MAX_DNS_CANDIDATE_CHECKS"):
            with self.subTest(limit=limit), patch("dns_sessions." + limit, 1):
                with self.assertRaises(DnsSessionValidationError):
                    build_dns_session_index(index.session_index, index.dns_evidence, threading.Event())
        self.assertEqual(len(index.associations), 7)

    def test_capture_bound_identity_and_literal_search_session_filters(self) -> None:
        index = self.indexes["pcapng"]
        item = next(item for item in index.associations if item.matching_frames == (3, 4))
        page = query_dns_associations(index, DnsQuery("SERVICE.TEST", None, 1, 100), item.identity, threading.Event())
        self.assertEqual((page.total_count, page.matching_count, page.page_count, page.selected_match_page), (7, 3, 1, 1))
        page = query_dns_associations(index, DnsQuery("", item.session_identity, 1, 100), None, threading.Event())
        self.assertEqual({candidate.question_name for candidate in page.associations}, {"service.test", "shared.test"})
        self.assertEqual(query_dns_associations(index, DnsQuery("service.*", None, 1, 100), None, threading.Event()).matching_count, 0)
        stale = DnsAssociationIdentity("a" * 64, item.identity.association_sha256)
        self.assertIsNone(dns_association_for_identity(index, stale))
        with self.assertRaises(DnsSessionValidationError):
            build_dns_session_index(index.session_index, replace(index.dns_evidence, capture_sha256="a" * 64), threading.Event())
        with self.assertRaises(DnsSessionValidationError):
            query_dns_associations(index, DnsQuery("", SessionIdentity("a" * 64, item.session_identity.scope_sha256), 1, 100), None, threading.Event())
        for invalid in (DnsQuery("line\nbreak", None, 1, 100), DnsQuery("", None, 0, 100), DnsQuery("", None, 1, 101)):
            with self.subTest(invalid=invalid), self.assertRaises(DnsSessionValidationError):
                query_dns_associations(index, invalid, None, threading.Event())

    def test_later_linked_negative_and_changed_answers_end_only_the_old_evidence_window(self) -> None:
        initial_question: DNSQuestion = ("replace.test", 1, 1)
        initial_answers = (address_record("replace.test", "198.51.100.20", 60),)
        cases: tuple[tuple[str, DNSQuestion, tuple[DNSResourceRecord, ...], DNSQuestion, tuple[DNSResourceRecord, ...], int], ...] = (
            ("nxdomain", initial_question, initial_answers, initial_question, (), 0x8183),
            ("nodata", initial_question, initial_answers, initial_question, (), 0x8180),
            ("new_address", initial_question, initial_answers, initial_question,
             (address_record("replace.test", "198.51.100.30", 60),), 0x8180),
            ("cname_dependency", ("alias.test", 1, 1),
             (name_record("alias.test", "edge.test", 5, 60), address_record("edge.test", "198.51.100.20", 60)),
             ("edge.test", 1, 1), (address_record("edge.test", "198.51.100.30", 60),), 0x8180),
        )
        with tempfile.TemporaryDirectory(prefix="rvi-sentinel-dns-replacement-") as temporary:
            for label, question, answers, later_question, later_answers, later_flags in cases:
                with self.subTest(label=label):
                    capture = Path(temporary) / (label + ".pcap")
                    capture.write_bytes(replacement_capture(question, answers, later_question, later_answers, later_flags))
                    saved = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
                    self.assertEqual(tuple(message.response_to_frame for message in saved.dns_evidence.messages if message.is_response), (1, 4))
                    index = correlate(saved.packets, saved.dns_evidence)
                    first = next(item for item in index.associations if item.response_frame == 2)
                    self.assertEqual(first.matching_frames, (3,))
                    self.assertEqual(first.record_ordinals, (1, 2) if label == "cname_dependency" else (1,))
                    self.assertEqual((first.superseded_by_frame, first.superseded_by_message_index), (5, 0))
                    self.assertEqual(first.expires_at_epoch, "1791428452.590385001")
                    self.assertEqual(first.ttl_expires_at_epoch, "1791428509.590385001")
                    self.assertEqual({item.matching_frames for item in index.associations if item.response_frame == 5},
                                     {(7,)} if later_answers else set())

    def test_superseding_scope_links_and_tied_epoch_frame_order_are_exact(self) -> None:
        question: DNSQuestion = ("replace.test", 1, 1)
        answers = (address_record("replace.test", "198.51.100.20", 60),)
        with tempfile.TemporaryDirectory(prefix="rvi-sentinel-dns-superseding-") as temporary:
            capture = Path(temporary) / "negative.pcap"
            capture.write_bytes(replacement_capture(question, answers, question, (), 0x8183))
            saved = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
        later = next(message for message in saved.dns_evidence.messages if message.frame_number == 5)
        for label, changed_packets, changed_evidence in (
            ("different_client", tuple(rewrite_packet(packet, {"ip.src": ("192.0.2.3",)}) if packet.frame_number == 4 else
                                       rewrite_packet(packet, {"ip.dst": ("192.0.2.3",)}) if packet.frame_number == 5 else packet
                                       for packet in saved.packets), saved.dns_evidence),
            ("different_interface", tuple(rewrite_packet(packet, {"frame.interface_name": ("other-fixture",)})
                                          if packet.frame_number in (4, 5) else packet for packet in saved.packets), saved.dns_evidence),
            ("unlinked_negative", saved.packets, replace_message(saved.dns_evidence, replace(later, response_to_frame=None))),
        ):
            with self.subTest(label=label):
                index = correlate(changed_packets, changed_evidence)
                first = next(item for item in index.associations if item.response_frame == 2)
                self.assertEqual(first.matching_frames, (3, 6))
                self.assertIsNone(first.superseded_by_frame)
        negative_epoch = saved.packets[4].timestamp.epoch
        tied_packets = tuple(rewrite_packet(packet, {"frame.time_epoch": (negative_epoch,)})
                             if packet.frame_number in (3, 6) else packet for packet in saved.packets)
        index = correlate(tied_packets, saved.dns_evidence)
        first = next(item for item in index.associations if item.response_frame == 2)
        self.assertEqual(first.matching_frames, (3,))
        self.assertEqual(first.superseded_by_frame, 5)

    def test_intermediate_cname_address_exclusivity_preserves_independent_a_aaaa_records(self) -> None:
        cases: tuple[tuple[str, DNSQuestion, tuple[DNSResourceRecord, ...], DNSQuestion,
                           tuple[DNSResourceRecord, ...], tuple[int, ...], int | None], ...] = (
            ("cname_to_a", ("alias.test", 1, 1),
             (name_record("alias.test", "edge.test", 5, 60),
              name_record("edge.test", "terminal.test", 5, 60),
              address_record("terminal.test", "198.51.100.20", 60)),
             ("other.test", 1, 1),
             (name_record("other.test", "edge.test", 5, 60),
              address_record("edge.test", "198.51.100.30", 60)), (3,), 5),
            ("a_to_cname", ("alias.test", 1, 1),
             (name_record("alias.test", "edge.test", 5, 60),
              address_record("edge.test", "198.51.100.20", 60)),
             ("other.test", 1, 1),
             (name_record("other.test", "edge.test", 5, 60),
              name_record("edge.test", "new-terminal.test", 5, 60),
              address_record("new-terminal.test", "198.51.100.30", 60)), (3,), 5),
            ("a_aaaa_coexistence", ("alias.test", 1, 1),
             (name_record("alias.test", "edge.test", 5, 60),
              address_record("edge.test", "198.51.100.20", 60)),
             ("edge.test", 28, 1),
             (address_record("edge.test", "2001:db8::30", 60),), (3, 6), None),
        )
        with tempfile.TemporaryDirectory(prefix="rvi-sentinel-dns-cname-exclusivity-") as temporary:
            for label, question, answers, later_question, later_answers, matching, superseding in cases:
                with self.subTest(label=label):
                    capture = Path(temporary) / (label + ".pcap")
                    content = replacement_capture(question, answers, later_question, later_answers, 0x8180)
                    capture.write_bytes(content)
                    saved = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
                    index = correlate(saved.packets, saved.dns_evidence)
                    first = next(item for item in index.associations if item.response_frame == 2)
                    self.assertEqual(first.matching_frames, matching)
                    self.assertEqual(first.superseded_by_frame, superseding)
                    self.assertEqual(first.superseded_by_message_index, 0 if superseding is not None else None)
                    self.assertEqual((first.query_frame, first.response_frame, first.message_index), (1, 2, 0))
                    self.assertEqual(first.record_ordinals, tuple(range(1, len(answers) + 1)))
                    self.assertEqual(first.ttl_expires_at_epoch, "1791428509.590385001")
                    self.assertEqual(first.expires_at_epoch, "1791428452.590385001" if superseding is not None
                                     else first.ttl_expires_at_epoch)
                    self.assertEqual(first.identity.capture_sha256, hashlib.sha256(content).hexdigest())
                    self.assertEqual(capture.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
