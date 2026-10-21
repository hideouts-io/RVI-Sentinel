"""Verify exact scoped session partitions with typed and real saved evidence."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from packet_models import PacketRecord, ProcessLabel, ProcessMetadata, decode_packet_fields
from packet_sessions import (
    EMPTY_SESSION_QUERY,
    MAX_SESSION_PACKETS,
    SessionCancelled,
    SessionIdentity,
    SessionIndex,
    SessionValidationError,
    build_session_index,
    frames_for_session,
    members_for_session,
    packet_index_for_session,
    query_sessions,
    session_for_identity,
    session_for_packet,
    session_index_steps,
    ungrouped_for_packet,
    ungrouped_frames,
)
from packet_timeline import PacketIdentity, PacketIndex, build_packet_index
from saved_capture import SAVED_ANALYSIS_LIMITS, read_saved_capture
from tests.session_fixture import diverse_session_records, session_capture

CAPTURE_SHA256 = "0123456789abcdef" * 4


def make_packet(frame: int, epoch: str, fields: dict[str, tuple[str, ...]]) -> PacketRecord:
    values: dict[str, tuple[str, ...]] = {
        "frame.number": (str(frame),), "frame.time_epoch": (epoch,),
        "frame.len": ("96",), "frame.cap_len": ("80",),
        "frame.protocols": ("ip:tcp:tls",), "_ws.col.protocol": ("TLSv1.3",),
        "ip.src": ("192.0.2.2",), "ip.dst": ("198.51.100.20",),
        "tcp.srcport": ("53000",), "tcp.dstport": ("443",), "tcp.stream": ("0",),
    }
    values.update(fields)
    return decode_packet_fields(values, tuple(values))


def correlate(packets: tuple[PacketRecord, ...]) -> SessionIndex:
    return build_session_index(build_packet_index(CAPTURE_SHA256, packets, threading.Event()), threading.Event())


class PacketSessionTests(unittest.TestCase):
    def test_bidirectional_scope_exact_epochs_bytes_and_original_membership(self) -> None:
        outgoing = make_packet(8, "1791428448.000000002", {})
        incoming = make_packet(3, "1791428448.000000001", {
            "ip.src": ("198.51.100.20",), "ip.dst": ("192.0.2.2",),
            "tcp.srcport": ("443",), "tcp.dstport": ("53000",),
            "frame.packet_flags_direction": ("1",),
        })
        index = correlate((outgoing, incoming))
        self.assertEqual((len(index.sessions), index.eligible_packet_count, index.ungrouped), (1, 2, ()))
        session = index.sessions[0]
        self.assertEqual(session.member_frames, (3, 8))
        self.assertEqual(session.first_timestamp.epoch, "1791428448.000000001")
        self.assertEqual(session.last_timestamp.epoch, "1791428448.000000002")
        self.assertEqual((session.wire_bytes, session.captured_bytes, session.captured_length_known_count), (192, 160, 2))
        self.assertEqual(session.protocols, ("ip", "tcp", "tls"))
        self.assertEqual((session.scope.endpoint_a.address, session.scope.endpoint_a.port), ("192.0.2.2", 53000))
        self.assertEqual((session.scope.endpoint_b.address, session.scope.endpoint_b.port), ("198.51.100.20", 443))
        self.assertEqual(session.scope.process.state, "unknown")
        self.assertEqual(frames_for_session(index, session.identity), (3, 8))
        self.assertIs(members_for_session(index, session.identity)[0], incoming)
        member_index = packet_index_for_session(index, session.identity, threading.Event())
        self.assertIs(member_index.packets[1], outgoing)
        self.assertEqual(session_for_packet(index, PacketIdentity(CAPTURE_SHA256, 8)), session.identity)
        self.assertIs(session_for_identity(index, session.identity), session)
        with self.assertRaises(FrozenInstanceError):
            setattr(session, "packet_count", 0)

    def test_stream_transport_endpoint_process_effective_and_interface_separate_scopes(self) -> None:
        fields: tuple[dict[str, tuple[str, ...]], ...] = (
            {}, {"tcp.stream": ("1",)}, {"ip.dst": ("198.51.100.21",)},
            {"tcp.dstport": ("444",)},
            {"frame.darwin.process_info.pid": ("343",), "frame.darwin.process_info.pname": ("fixture-maild",)},
            {"frame.darwin.process_info.epid": ("900",), "frame.darwin.process_info.epname": ("fixture-worker",)},
            {"frame.interface_name": ("fixture0",)},
        )
        packets = tuple(make_packet(frame, str(frame), extra) for frame, extra in enumerate(fields, 1))
        tcp = make_packet(8, "8", {})
        udp_values = {field.name: field.values for field in tcp.fields if not field.name.startswith("tcp.")}
        udp_values.update({"frame.protocols": ("ip:udp",), "_ws.col.protocol": ("UDP",), "udp.srcport": ("53000",), "udp.dstport": ("443",), "udp.stream": ("0",)})
        udp = decode_packet_fields(udp_values, tuple(udp_values))
        index = correlate(packets + (udp,))
        self.assertEqual((len(index.sessions), index.eligible_packet_count), (8, 8))
        scopes = {session.identity.scope_sha256 for session in index.sessions}
        self.assertEqual(len(scopes), 8)
        known = next(session for session in index.sessions if session.scope.process.state == "recorded")
        self.assertEqual(known.scope.process.labels[0].pid, 343)
        different_capture = build_session_index(build_packet_index("a" * 64, packets + (udp,), threading.Event()), threading.Event())
        self.assertTrue(scopes.isdisjoint({session.identity.scope_sha256 for session in different_capture.sessions}))
        self.assertIsNone(session_for_identity(index, different_capture.sessions[0].identity))
        self.assertIsNone(session_for_packet(index, PacketIdentity("a" * 64, 1)))

    def test_metadata_source_and_unknown_labels_are_exact_not_wildcard_scopes(self) -> None:
        packets = (
            make_packet(1, "1", {}),
            make_packet(2, "2", {"frame.darwin.process_info.pid": ("0",)}),
            make_packet(3, "3", {"pktap.pid": ("0",)}),
            make_packet(4, "4", {"frame.darwin.process_info.pid": ("343",)}),
            make_packet(5, "5", {"pktap.pid": ("343",)}),
            make_packet(6, "6", {"frame.interface_name": ("fixture0",)}),
            make_packet(7, "7", {"pktap.ifname": ("fixture0",)}),
            make_packet(8, "8", {"frame.darwin.process_info.epid": ("343",)}),
        )
        index = correlate(packets)
        self.assertEqual(len(index.sessions), 8)
        self.assertEqual(sum(session.scope.process.state == "unknown" for session in index.sessions), 4)
        null_label = index.sessions[1].scope.process.labels[0]
        self.assertEqual(null_label.pid, 0)
        self.assertIsNone(null_label.name)

    def test_canonical_metadata_label_order_ipv6_normalization_and_equal_time_frames(self) -> None:
        metadata = ProcessMetadata("recorded", (ProcessLabel("pktap", 343, "fixture-maild"), ProcessLabel("apple_pcapng", 343, "fixture-maild")))
        packet = make_packet(9, "-0.000000001", {})
        first = replace(packet, process=metadata, source_address="2001:0db8:0:0:0:0:0:2", destination_address="2001:db8::20")
        second = replace(first, frame_number=3, process=replace(metadata, labels=tuple(reversed(metadata.labels))), source_address="2001:db8::20", destination_address="2001:db8::2", source_port=443, destination_port=53000)
        index = correlate((first, second))
        self.assertEqual(len(index.sessions), 1)
        self.assertEqual(index.sessions[0].member_frames, (3, 9))
        self.assertEqual(index.sessions[0].scope.endpoint_a.address, "2001:db8::2")
        reordered = correlate((second, first))
        self.assertEqual(index.sessions[0].identity, reordered.sessions[0].identity)

    def test_all_ineligible_frames_have_exact_explicit_reason_partition(self) -> None:
        base = make_packet(1, "1", {})
        missing_stream = replace(make_packet(2, "2", {}), stream=None, diagnostics=("missing_stream",))
        missing_port = replace(make_packet(3, "3", {}), destination_port=None, diagnostics=("incomplete_transport_header",))
        ambiguous_network = make_packet(4, "4", {"ip.src": ("192.0.2.2", "203.0.113.2")})
        ambiguous_transport = make_packet(5, "5", {"udp.srcport": ("12",), "udp.dstport": ("53",), "udp.stream": ("0",)})
        conflicts = make_packet(6, "6", {
            "frame.darwin.process_info.pid": ("343", "344"),
            "frame.darwin.process_info.epid": ("900", "901"),
            "frame.interface_name": ("fixture0",), "pktap.ifname": ("fixture1",),
            "frame.packet_flags_direction": ("1",), "pktap.flags": ("2",),
        })
        no_network = replace(make_packet(7, "7", {}), source_address=None)
        nontransport = replace(make_packet(8, "8", {}), transport=None, source_port=None, destination_port=None, stream=None)
        packets = (base, missing_stream, missing_port, ambiguous_network, ambiguous_transport, conflicts, no_network, nontransport)
        index = correlate(packets)
        self.assertEqual(index.eligible_packet_count, 1)
        self.assertEqual(ungrouped_frames(index), (2, 3, 4, 5, 6, 7, 8))
        self.assertEqual(index.eligible_packet_count + len(index.ungrouped), len(packets))
        self.assertEqual({frame for session in index.sessions for frame in session.member_frames}.intersection(ungrouped_frames(index)), set())
        reasons = {packet.frame_number: packet.reasons for packet in index.ungrouped}
        self.assertEqual(reasons[2], ("missing_stream",))
        self.assertEqual(reasons[3], ("incomplete_transport",))
        self.assertEqual(reasons[4], ("ambiguous_network",))
        self.assertEqual(reasons[5], ("ambiguous_transport",))
        self.assertEqual(reasons[6], ("process_conflict", "effective_process_conflict", "interface_conflict", "direction_conflict"))
        self.assertEqual(reasons[7], ("incomplete_network",))
        self.assertEqual(reasons[8], ("non_tcp_udp",))
        self.assertEqual(sum(count.packet_count for count in index.reason_counts), 10)
        self.assertEqual(ungrouped_for_packet(index, PacketIdentity(CAPTURE_SHA256, 6)).reasons, reasons[6])
        self.assertIsNone(ungrouped_for_packet(index, PacketIdentity(CAPTURE_SHA256, 1)))
        self.assertIsNone(ungrouped_for_packet(index, PacketIdentity("a" * 64, 6)))
        self.assertIsNone(session_for_packet(index, PacketIdentity(CAPTURE_SHA256, 6)))

    def test_unknown_captured_lengths_do_not_become_false_complete_byte_totals(self) -> None:
        index = correlate((make_packet(1, "1", {}), replace(make_packet(2, "2", {}), captured_length=None)))
        session = index.sessions[0]
        self.assertEqual(session.wire_bytes, 192)
        self.assertIsNone(session.captured_bytes)
        self.assertEqual(session.captured_length_known_count, 1)

    def test_literal_search_combined_scope_filters_and_selection(self) -> None:
        packets = (
            make_packet(1, "1", {"frame.darwin.process_info.pid": ("343",), "frame.darwin.process_info.pname": ("Straße.*fixture",), "frame.darwin.process_info.epname": ("effective-worker",), "frame.interface_name": ("fixture0",)}),
            make_packet(2, "2", {"tcp.stream": ("1",), "frame.darwin.process_info.pname": ("StraßeXfixture",)}),
            make_packet(3, "3", {"tcp.stream": ("2",)}),
        )
        index = correlate(packets)
        selected = index.sessions[0].identity
        query = replace(EMPTY_SESSION_QUERY, search="STRASSE.*", endpoint="192.0.2.2", port=443, transport="tcp", process_text="EFFECTIVE-WORKER", process_state="recorded", effective_process_state="recorded", interface_text="TURE0", interface_state="recorded")
        page = query_sessions(index, query, selected, threading.Event())
        self.assertEqual((page.total_count, page.matching_count, page.selected_match_page), (3, 1, 1))
        self.assertIs(page.sessions[0], index.sessions[0])
        no_match = query_sessions(index, replace(query, transport="udp"), selected, threading.Event())
        self.assertEqual((no_match.matching_count, no_match.page_count, no_match.page_number, no_match.selected_match_page), (0, 0, 1, None))
        unknown = query_sessions(index, replace(EMPTY_SESSION_QUERY, process_state="unknown", effective_process_state="unknown", interface_state="unknown"), selected, threading.Event())
        self.assertEqual(tuple(session.member_frames for session in unknown.sessions), ((3,),))
        self.assertIsNone(unknown.selected_match_page)

    def test_bounded_pages_exact_counts_clamping_and_empty_index(self) -> None:
        packets = tuple(make_packet(frame, str(frame), {"tcp.stream": (str(frame),)}) for frame in range(1, 406))
        index = correlate(packets)
        selected = index.sessions[203].identity
        page = query_sessions(index, replace(EMPTY_SESSION_QUERY, page_number=2), selected, threading.Event())
        self.assertEqual((page.total_count, page.matching_count, page.page_count, page.page_number, page.selected_match_page), (405, 405, 5, 2, 3))
        self.assertEqual((len(page.sessions), page.sessions[0].member_frames, page.sessions[-1].member_frames), (100, (101,), (200,)))
        last = query_sessions(index, replace(EMPTY_SESSION_QUERY, page_number=999), selected, threading.Event())
        self.assertEqual((last.page_number, len(last.sessions)), (5, 5))
        large = query_sessions(index, replace(EMPTY_SESSION_QUERY, page_size=500), None, threading.Event())
        self.assertEqual(len(large.sessions), 405)
        empty = correlate(())
        self.assertEqual(empty.sessions, ())
        self.assertEqual((empty.eligible_packet_count, empty.ungrouped, empty.reason_counts), (0, (), ()))
        self.assertEqual(query_sessions(empty, EMPTY_SESSION_QUERY, None, threading.Event()).page_count, 0)

    def test_invalid_queries_identities_and_packet_index_fail_explicitly(self) -> None:
        index = correlate((make_packet(1, "1", {}),))
        for query in (
            replace(EMPTY_SESSION_QUERY, search="x" * 513), replace(EMPTY_SESSION_QUERY, search="bad\n"),
            replace(EMPTY_SESSION_QUERY, endpoint="192.0.2"), replace(EMPTY_SESSION_QUERY, endpoint="2001:db8::2%fixture0"),
            replace(EMPTY_SESSION_QUERY, port=True), replace(EMPTY_SESSION_QUERY, port=-1), replace(EMPTY_SESSION_QUERY, port=65_536),
            replace(EMPTY_SESSION_QUERY, transport="TLS"), replace(EMPTY_SESSION_QUERY, process_state="inferred"),
            replace(EMPTY_SESSION_QUERY, effective_process_state="inferred"), replace(EMPTY_SESSION_QUERY, interface_state="inferred"),
            replace(EMPTY_SESSION_QUERY, page_number=True), replace(EMPTY_SESSION_QUERY, page_number=0),
            replace(EMPTY_SESSION_QUERY, page_size=10),
        ):
            with self.subTest(query=query), self.assertRaises(SessionValidationError):
                query_sessions(index, query, None, threading.Event())
        for identity in (SessionIdentity("A" * 64, "a" * 64), SessionIdentity(CAPTURE_SHA256, "a" * 63)):
            with self.assertRaises(SessionValidationError):
                session_for_identity(index, identity)
        stale = SessionIdentity("a" * 64, index.sessions[0].identity.scope_sha256)
        with self.assertRaises(SessionValidationError):
            members_for_session(index, stale)
        packet = index.packet_index.packets[0]
        for invalid in (
            replace(packet, source_port=True), replace(packet, stream=True), replace(packet, wire_length=True),
            replace(packet, timestamp=replace(packet.timestamp, seconds=True)),
            replace(packet, captured_length=1000), replace(packet, source_address="bad"),
            replace(packet, process=ProcessMetadata("recorded", (ProcessLabel("apple_pcapng", True, "fixture"),))),
        ):
            source = replace(index.packet_index, packets=(invalid,))
            with self.assertRaises(SessionValidationError):
                build_session_index(source, threading.Event())
        for invalid_index in (
            replace(index.packet_index, frame_numbers=()),
            replace(index.packet_index, frame_positions=(1,)),
            replace(index.packet_index, packets=(packet, packet), frame_numbers=(1, 2), frame_positions=(0, 1)),
            PacketIndex(CAPTURE_SHA256, (packet,) * (MAX_SESSION_PACKETS + 1), (), ()),
        ):
            with self.assertRaises(SessionValidationError):
                build_session_index(invalid_index, threading.Event())

    def test_cancelled_operations_preserve_completed_index_and_members(self) -> None:
        index = correlate((make_packet(1, "1", {}), make_packet(2, "2", {})))
        prior = query_sessions(index, EMPTY_SESSION_QUERY, None, threading.Event())
        cancellation = threading.Event()
        cancellation.set()
        with self.assertRaises(SessionCancelled):
            build_session_index(index.packet_index, cancellation)
        with self.assertRaises(SessionCancelled):
            query_sessions(index, EMPTY_SESSION_QUERY, None, cancellation)
        with self.assertRaises(SessionCancelled):
            packet_index_for_session(index, index.sessions[0].identity, cancellation)
        self.assertEqual(query_sessions(index, EMPTY_SESSION_QUERY, None, threading.Event()), prior)

    def test_incremental_correlation_returns_only_complete_original_evidence(self) -> None:
        packets = diverse_session_records(1024)
        source = build_packet_index(CAPTURE_SHA256, packets, threading.Event())
        expected = build_session_index(source, threading.Event())
        completed = tuple(result for result in session_index_steps(source, threading.Event()) if result is not None)
        self.assertEqual(completed, (expected,))
        self.assertIs(completed[0].packet_index, source)
        self.assertIs(members_for_session(completed[0], completed[0].sessions[0].identity)[0], packets[0])

        cancellation = threading.Event()
        steps = session_index_steps(source, cancellation)
        self.assertIsNone(next(steps))
        self.assertIsNone(next(steps))
        cancellation.set()
        with self.assertRaises(SessionCancelled):
            tuple(steps)
        self.assertEqual(query_sessions(expected, EMPTY_SESSION_QUERY, None, threading.Event()).total_count, 512)


class RealSavedSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("Real scoped session tests require TShark on PATH.")

    def test_real_bidirectional_pcap_and_pcapng_preserve_scope_and_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rvi-scoped-sessions-") as directory:
            for container, expected_count in (("pcap", 4), ("pcapng", 7)):
                with self.subTest(container=container):
                    content = session_capture(container)
                    capture = Path(directory) / f"sessions.{container}"
                    capture.write_bytes(content)
                    decoded = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
                    source = build_packet_index(decoded.sha256, decoded.packets, threading.Event())
                    index = build_session_index(source, threading.Event())
                    self.assertEqual(index.capture_sha256, hashlib.sha256(content).hexdigest())
                    self.assertEqual((len(index.sessions), index.eligible_packet_count, index.ungrouped), (expected_count, 14, ()))
                    self.assertEqual(sum(session.packet_count for session in index.sessions), 14)
                    tcp = next(session for session in index.sessions if session.member_frames[0] == 1)
                    self.assertEqual(tcp.member_frames, (1, 3, 5, 6, 7, 8, 9, 14) if container == "pcap" else (1, 3, 5))
                    udp = next(session for session in index.sessions if session.member_frames[0] == 2)
                    self.assertEqual(udp.member_frames, (2, 4))
                    self.assertEqual(tcp.scope.stream, udp.scope.stream)
                    self.assertNotEqual(tcp.identity, udp.identity)
                    self.assertEqual(tcp.first_timestamp.epoch, "1791428448.590385001")
                    self.assertIs(members_for_session(index, tcp.identity)[0], decoded.packets[0])
                    self.assertEqual(capture.read_bytes(), content)
                    if container == "pcapng":
                        self.assertEqual(tcp.scope.process.state, "recorded")
                        self.assertEqual(tcp.scope.process.labels[0].pid, 343)
                        unknown = next(session for session in index.sessions if session.member_frames == (14,))
                        self.assertEqual(unknown.scope.process.state, "unknown")
                        self.assertNotEqual(unknown.identity, tcp.identity)


if __name__ == "__main__":
    unittest.main()
