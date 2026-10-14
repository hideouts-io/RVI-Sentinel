"""Exercise literal packet filters, immutable paging, and real saved evidence."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

from packet_models import PacketRecord, decode_packet_fields
from packet_timeline import (
    PacketIdentity,
    PacketQuery,
    PacketQueryCancelled,
    PacketQueryValidationError,
    build_packet_index,
    packet_for_identity,
    query_packets,
    restrict_packet_index,
    validate_packet_query,
)
from saved_capture import SAVED_ANALYSIS_LIMITS, read_saved_capture
from tests.saved_capture_fixture import classic_capture, metadata_capture

CAPTURE_SHA256 = "0123456789abcdef" * 4
EMPTY_QUERY = PacketQuery("", "", None, "", "", "all", "", "all", "all", 1, 100)


def make_packet(frame: int, epoch: str, extra: dict[str, tuple[str, ...]]) -> PacketRecord:
    values: dict[str, tuple[str, ...]] = {
        "frame.number": (str(frame),),
        "frame.time_epoch": (epoch,),
        "frame.len": ("80",),
        "frame.cap_len": ("80",),
        "frame.protocols": ("ip:tcp:tls",),
        "_ws.col.Protocol": ("TLSv1.3",),
        "ip.src": ("192.0.2.1",),
        "ip.dst": ("192.0.2.2",),
        "tcp.srcport": ("50123",),
        "tcp.dstport": ("443",),
        "tcp.stream": ("9",),
    }
    values.update(extra)
    return decode_packet_fields(values, tuple(values))


def matching_frames(packets: tuple[PacketRecord, ...], query: PacketQuery) -> tuple[int, ...]:
    index = build_packet_index(CAPTURE_SHA256, packets, threading.Event())
    page = query_packets(index, query, None, threading.Event())
    return tuple(packet.frame_number for packet in page.packets)


class PacketTimelineTests(unittest.TestCase):
    def test_member_scope_uses_original_evidence_and_rejects_fabricated_frames(self) -> None:
        packets = (make_packet(1, "3", {}), make_packet(2, "1", {}), make_packet(3, "2", {}))
        index = build_packet_index(CAPTURE_SHA256, packets, threading.Event())
        members = restrict_packet_index(index, (1, 3), threading.Event())
        self.assertEqual(tuple(packet.frame_number for packet in members.packets), (3, 1))
        self.assertIs(members.packets[0], packets[2])
        self.assertIs(members.packets[1], packets[0])
        self.assertEqual(len(index.packets), 3)
        for frames in ((1, 1), (4,), (True,), (0,)):
            with self.subTest(frames=frames), self.assertRaises(PacketQueryValidationError):
                restrict_packet_index(index, frames, threading.Event())
        cancellation = threading.Event()
        cancellation.set()
        with self.assertRaises(PacketQueryCancelled):
            restrict_packet_index(index, (1,), cancellation)
        self.assertEqual(restrict_packet_index(index, (), threading.Event()).packets, ())
        validate_packet_query(EMPTY_QUERY)
        with self.assertRaises(PacketQueryValidationError):
            validate_packet_query(replace(EMPTY_QUERY, page_number=True))

    def test_exact_epochs_equal_timestamp_frames_and_original_identity(self) -> None:
        packets = (
            make_packet(5, "1791428448.000000002", {}),
            make_packet(3, "1791428448.000000001", {}),
            make_packet(2, "1791428448.000000001", {}),
            make_packet(1, "-0.000000001", {}),
        )
        index = build_packet_index(CAPTURE_SHA256, packets, threading.Event())
        page = query_packets(index, EMPTY_QUERY, PacketIdentity(CAPTURE_SHA256, 3), threading.Event())
        self.assertEqual(tuple(packet.frame_number for packet in page.packets), (1, 2, 3, 5))
        self.assertIs(index.packets[0], packets[3])
        self.assertIs(packet_for_identity(index, PacketIdentity(CAPTURE_SHA256, 3)), packets[1])
        self.assertIsNone(packet_for_identity(index, PacketIdentity("a" * 64, 3)))
        self.assertIsNone(packet_for_identity(index, PacketIdentity(CAPTURE_SHA256, 4)))
        self.assertEqual(page.selected_match_page, 1)
        self.assertEqual(packets[0].frame_number, 5)
        with self.assertRaises(FrozenInstanceError):
            setattr(index, "capture_sha256", "a" * 64)

    def test_literal_casefold_search_repeated_values_protocol_alias_and_metadata(self) -> None:
        packets = (
            make_packet(1, "1.000000001", {"dns.qry.name": ("a.*b.test", "Straße.test"), "tls.handshake.extensions_server_name": ("one.test", "second.test"), "frame.darwin.process_info.pid": ("343",), "frame.darwin.process_info.pname": ("fixture-maild",)}),
            make_packet(2, "1.000000002", {"dns.qry.name": ("axxb.test",)}),
        )
        for text in ("A.*B.TEST", "STRASSE.TEST", "SECOND.TEST", "TLS.HANDSHAKE.EXTENSIONS_SERVER_NAME", "fixture-MAILD", "343", "1.000000001"):
            with self.subTest(search=text):
                self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, search=text)), (1,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, search="a.*")), (1,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, protocol="TLSV1.3")), (1, 2))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, protocol="TCP")), (1, 2))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, protocol="TL")), ())
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, search="Straße", protocol="udp")), ())

    def test_exact_endpoint_and_port_include_unpaired_ambiguous_layers(self) -> None:
        layered = make_packet(1, "1", {
            "frame.protocols": ("ip:ipv6:tcp:udp",),
            "ipv6.src": ("2001:0DB8:0:0:0:0:0:3",),
            "ipv6.dst": ("2001:db8::4",),
            "ip.src": ("192.0.2.1", "192.0.2.99"),
            "udp.srcport": ("123",),
            "udp.dstport": ("53",),
        })
        normal = make_packet(2, "2", {})
        packets = (layered, normal)
        self.assertIsNone(layered.source_address)
        self.assertIsNone(layered.destination_address)
        self.assertIsNone(layered.transport)
        for endpoint in ("2001:db8::3", "2001:0db8:0:0:0:0:0:4", "192.0.2.99"):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, endpoint=endpoint)), (1,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, endpoint="192.0.2.1", port=53)), (1,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, endpoint="192.0.2.1", port=443)), (1, 2))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, endpoint="192.0.2.10")), ())
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, port=0)), ())

    def test_process_interface_and_direction_filters_preserve_unknown_and_conflict(self) -> None:
        unknown = make_packet(1, "1", {"frame.darwin.process_info.epid": ("500",), "frame.darwin.process_info.epname": ("effective-worker",), "frame.packet_flags_direction": ("0",)})
        recorded = make_packet(2, "2", {"frame.darwin.process_info.pid": ("343",), "frame.darwin.process_info.pname": ("fixture-maild",), "frame.interface_name": ("fixture0",), "frame.packet_flags_direction": ("2",)})
        conflict = make_packet(3, "3", {"frame.darwin.process_info.pid": ("343", "444"), "frame.darwin.process_info.pname": ("worker-a", "worker-b"), "frame.interface_name": ("fixture0",), "pktap.ifname": ("fixture1",), "frame.packet_flags_direction": ("2",), "pktap.flags": ("1",)})
        packets = (unknown, recorded, conflict)
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, process_state="unknown")), (1,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, process_state="recorded", process_text="MAIL")), (2,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, process_text="EFFECTIVE-WORKER", process_state="unknown")), (1,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, process_state="conflict", process_text="444")), (3,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, interface_state="unknown")), (1,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, interface_state="conflict", interface_text="fixture1")), (3,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, interface_text="TURE0", interface_state="recorded")), (2,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, direction="unknown")), (1,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, direction="outbound")), (2,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, direction="inbound")), ())
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, direction="conflict")), (3,))
        self.assertEqual(matching_frames(packets, replace(EMPTY_QUERY, process_state="conflict", direction="outbound")), ())

    def test_bounded_paging_exact_counts_clamping_and_selected_filter_membership(self) -> None:
        packets = tuple(make_packet(frame, str(frame), {"dns.qry.name": ("even.test" if frame % 2 == 0 else "odd.test",)}) for frame in range(1, 406))
        index = build_packet_index(CAPTURE_SHA256, packets, threading.Event())
        selected = PacketIdentity(CAPTURE_SHA256, 204)
        page = query_packets(index, replace(EMPTY_QUERY, page_number=2), selected, threading.Event())
        self.assertEqual((page.total_count, page.matching_count, page.page_count, page.page_number), (405, 405, 5, 2))
        self.assertEqual((len(page.packets), page.packets[0].frame_number, page.packets[-1].frame_number), (100, 101, 200))
        self.assertEqual(page.selected_match_page, 3)
        filtered = query_packets(index, replace(EMPTY_QUERY, search="even.test", page_number=99), selected, threading.Event())
        self.assertEqual((filtered.matching_count, filtered.page_count, filtered.page_number), (202, 3, 3))
        self.assertEqual(tuple(packet.frame_number for packet in filtered.packets), (402, 404))
        self.assertEqual(filtered.selected_match_page, 2)
        removed = query_packets(index, replace(EMPTY_QUERY, search="odd.test"), selected, threading.Event())
        self.assertIsNone(removed.selected_match_page)
        stale = query_packets(index, EMPTY_QUERY, PacketIdentity("a" * 64, 204), threading.Event())
        self.assertIsNone(stale.selected_match_page)
        none = query_packets(index, replace(EMPTY_QUERY, search="missing.test", page_number=99), selected, threading.Event())
        self.assertEqual((none.matching_count, none.page_number, none.page_count, none.packets), (0, 1, 0, ()))
        large_page = query_packets(index, replace(EMPTY_QUERY, page_size=500), selected, threading.Event())
        self.assertEqual(len(large_page.packets), 405)
        self.assertIs(large_page.packets[0], packets[0])

    def test_empty_index_and_exact_full_last_page(self) -> None:
        empty = build_packet_index(CAPTURE_SHA256, (), threading.Event())
        self.assertEqual(query_packets(empty, EMPTY_QUERY, None, threading.Event()).packets, ())
        packets = tuple(make_packet(frame, str(frame), {}) for frame in range(1, 201))
        index = build_packet_index(CAPTURE_SHA256, packets, threading.Event())
        page = query_packets(index, replace(EMPTY_QUERY, page_number=999), None, threading.Event())
        self.assertEqual((page.page_number, page.page_count, len(page.packets)), (2, 2, 100))
        self.assertEqual((page.packets[0].frame_number, page.packets[-1].frame_number), (101, 200))

    def test_invalid_filters_and_identity_fail_explicitly(self) -> None:
        index = build_packet_index(CAPTURE_SHA256, (make_packet(1, "1", {}),), threading.Event())
        invalid_queries = (
            replace(EMPTY_QUERY, search="x" * 513),
            replace(EMPTY_QUERY, search="bad\nquery"),
            replace(EMPTY_QUERY, endpoint="192.0.2"),
            replace(EMPTY_QUERY, endpoint="2001:db8::1%fixture0"),
            replace(EMPTY_QUERY, port=True),
            replace(EMPTY_QUERY, port=-1),
            replace(EMPTY_QUERY, port=65_536),
            replace(EMPTY_QUERY, port="443"),
            replace(EMPTY_QUERY, process_state="inferred"),
            replace(EMPTY_QUERY, interface_state="inferred"),
            replace(EMPTY_QUERY, direction="recorded"),
            replace(EMPTY_QUERY, page_number=True),
            replace(EMPTY_QUERY, page_number=0),
            replace(EMPTY_QUERY, page_number=2**31),
            replace(EMPTY_QUERY, page_size=True),
            replace(EMPTY_QUERY, page_size=101),
        )
        for query in invalid_queries:
            with self.subTest(query=query), self.assertRaises(PacketQueryValidationError):
                query_packets(index, query, None, threading.Event())
        for identity in (PacketIdentity("a" * 63, 1), PacketIdentity("G" * 64, 1), PacketIdentity(CAPTURE_SHA256, True), PacketIdentity(CAPTURE_SHA256, 0), PacketIdentity(CAPTURE_SHA256, 2**64)):
            with self.subTest(identity=identity), self.assertRaises(PacketQueryValidationError):
                packet_for_identity(index, identity)

    def test_invalid_index_duplicates_and_timestamp_ranges_fail(self) -> None:
        packet = make_packet(1, "1", {})
        cases = (
            ("A" * 64, (packet,)),
            (CAPTURE_SHA256, (packet, packet)),
            (CAPTURE_SHA256, (replace(packet, frame_number=True),)),
            (CAPTURE_SHA256, (replace(packet, timestamp=replace(packet.timestamp, nanoseconds=1_000_000_000)),)),
            (CAPTURE_SHA256, (replace(packet, timestamp=replace(packet.timestamp, seconds=True)),)),
        )
        for digest, packets in cases:
            with self.subTest(digest=digest, packets=packets), self.assertRaises(PacketQueryValidationError):
                build_packet_index(digest, packets, threading.Event())

    def test_cancellation_returns_no_partial_result_and_keeps_prior_index(self) -> None:
        packets = (make_packet(1, "1", {}), make_packet(2, "2", {}))
        index = build_packet_index(CAPTURE_SHA256, packets, threading.Event())
        prior_page = query_packets(index, EMPTY_QUERY, None, threading.Event())
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(PacketQueryCancelled):
            build_packet_index(CAPTURE_SHA256, packets, cancelled)
        with self.assertRaises(PacketQueryCancelled):
            query_packets(index, replace(EMPTY_QUERY, search="missing"), None, cancelled)
        self.assertEqual(query_packets(index, EMPTY_QUERY, None, threading.Event()), prior_page)
        self.assertIs(packet_for_identity(index, PacketIdentity(CAPTURE_SHA256, 1)), packets[0])


class RealPacketTimelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("tshark") is None:
            raise RuntimeError("Real packet timeline tests require TShark on PATH.")

    def test_real_saved_pcapng_metadata_and_repeated_names_filter_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rvi-packet-timeline-") as directory:
            capture = Path(directory) / "metadata.pcapng"
            content = metadata_capture()
            capture.write_bytes(content)
            decoded = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
            index = build_packet_index(decoded.sha256, decoded.packets, threading.Event())
            page = query_packets(index, replace(EMPTY_QUERY, search="SECOND.TEST", endpoint="192.0.2.53", port=53, protocol="DNS", process_text="343", process_state="recorded", interface_text="fixture0", interface_state="recorded", direction="outbound"), PacketIdentity(decoded.sha256, 1), threading.Event())
            self.assertEqual(tuple(packet.frame_number for packet in page.packets), (1,))
            self.assertEqual(page.capture_sha256, hashlib.sha256(content).hexdigest())
            self.assertEqual(page.packets[0].timestamp.epoch, "1791428448.590385001")
            self.assertIs(page.packets[0], decoded.packets[0])
            self.assertEqual(capture.read_bytes(), content)

    def test_real_classic_ipv6_and_unknown_context_remain_searchable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rvi-packet-timeline-") as directory:
            capture = Path(directory) / "classic.pcap"
            content = classic_capture(3)
            capture.write_bytes(content)
            decoded = read_saved_capture(capture, SAVED_ANALYSIS_LIMITS, threading.Event())
            index = build_packet_index(decoded.sha256, decoded.packets, threading.Event())
            page = query_packets(index, replace(EMPTY_QUERY, endpoint="2001:0db8:0:0:0:0:0:53", port=53, search="IPV6.TEST", process_state="unknown", interface_state="unknown", direction="unknown"), None, threading.Event())
            self.assertEqual(tuple(packet.frame_number for packet in page.packets), (3,))
            self.assertEqual(page.packets[0].timestamp.epoch, "1791428448.590385003")
            self.assertEqual(capture.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
