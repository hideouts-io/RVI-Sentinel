"""Generate passive DNS evidence and target sessions without transmitting packets."""

from __future__ import annotations

import ipaddress
import struct
from typing import Literal

from tests.saved_capture_fixture import (
    FIXTURE_EPOCH_SECONDS, FIXTURE_NANOSECONDS, dns_name, padded,
    pcapng_block, pcapng_option,
)
from tests.session_fixture import transport_packet

DNSQuestion = tuple[str, int, int]
DNSResourceRecord = tuple[str, int, int, int, bytes]
DNSFixtureFrame = tuple[str, bytes, int, int, int | None, int]


def address_record(owner: str, address: str, ttl: int) -> DNSResourceRecord:
    """Return one IN A/AAAA resource record with its exact owner and TTL."""
    value = ipaddress.ip_address(address)
    return owner, 1 if value.version == 4 else 28, 1, ttl, value.packed


def name_record(owner: str, target: str, record_type: int, ttl: int) -> DNSResourceRecord:
    """Return one name-valued record; callers choose CNAME, NS or PTR explicitly."""
    if record_type not in (2, 5, 12):
        raise ValueError("The fixture name-valued record must be NS, CNAME or PTR.")
    return owner, record_type, 1, ttl, dns_name(target)


def dns_message(identifier: int, flags: int, questions: tuple[DNSQuestion, ...],
                answers: tuple[DNSResourceRecord, ...], authorities: tuple[DNSResourceRecord, ...],
                additional: tuple[DNSResourceRecord, ...]) -> bytes:
    """Build complete uncompressed DNS bytes, preserving independent RR sections."""
    question_bytes = b"".join(dns_name(name) + struct.pack("!HH", kind, record_class)
                               for name, kind, record_class in questions)
    record_bytes = b"".join(
        dns_name(owner) + struct.pack("!HHIH", kind, record_class, ttl, len(value)) + value
        for owner, kind, record_class, ttl, value in answers + authorities + additional
    )
    return struct.pack("!HHHHHH", identifier, flags, len(questions), len(answers),
                       len(authorities), len(additional)) + question_bytes + record_bytes


def dns_transport(source: str, destination: str, source_port: int, destination_port: int,
                  transport: Literal["tcp", "udp"], payload: bytes,
                  sequence: int, acknowledgement: int) -> bytes:
    """Wrap DNS bytes in a valid UDP datagram or one complete TCP DNS message."""
    body = struct.pack("!H", len(payload)) + payload if transport == "tcp" else payload
    return transport_packet(source, destination, source_port, destination_port,
                            transport, sequence, acknowledgement, 24 if transport == "tcp" else 0, body)


def dns_capture_frames() -> tuple[DNSFixtureFrame, ...]:
    """Return named real packets with exact offsets, interfaces and process scopes.

    The main CNAME answer and target process differ intentionally: the DNS
    process is a system resolver observation, not proof of application ownership.
    Other frames expose rejection boundaries rather than claiming live poisoning.
    """
    client = "192.0.2.2"
    resolver = "192.0.2.53"
    address = "198.51.100.20"
    frames: list[DNSFixtureFrame] = []

    def append(label: str, packet: bytes, offset: int, interface: int,
               process: int | None, direction: int) -> None:
        frames.append((label, packet, offset, interface, process, direction))

    def exchange(label: str, identifier: int, questions: tuple[DNSQuestion, ...],
                 answers: tuple[DNSResourceRecord, ...], response_flags: int,
                 at_seconds: int, source_port: int) -> None:
        query = dns_message(identifier, 0x0100, questions, (), (), ())
        response = dns_message(identifier, response_flags, questions, answers, (), ())
        append(label + "_query", dns_transport(client, resolver, source_port, 53, "udp", query, 0, 0),
               at_seconds * 1_000_000_000, 0, 0, 2)
        append(label + "_response", dns_transport(resolver, client, 53, source_port, "udp", response, 0, 0),
               (at_seconds + 1) * 1_000_000_000, 0, 0, 1)

    service_question = (("service.test", 1, 1),)
    append("cname_query", dns_transport(client, resolver, 53000, 53, "udp",
        dns_message(100, 0x0100, service_question, (), (), ()), 0, 0), 0, 0, 0, 2)
    append("cname_response", dns_transport(resolver, client, 53, 53000, "udp",
        dns_message(100, 0x8180, service_question,
                    (name_record("service.test", "edge.test", 5, 30),
                     address_record("edge.test", address, 60),
                     address_record("unrelated-answer.test", "198.51.100.21", 120)),
                    (name_record("test", "ns.test", 2, 120),),
                    (address_record("ns.test", "203.0.113.99", 120),)), 0, 0), 1_000_000_000, 0, 0, 1)
    append("cname_target_out", transport_packet(client, address, 54000, 443, "tcp", 100, 0, 2, b""),
           2_000_000_000, 0, 1, 2)
    append("cname_target_in", transport_packet(address, client, 443, 54000, "tcp", 200, 101, 18, b""),
           3_000_000_000, 0, 1, 1)
    append("cname_udp_target", transport_packet(client, address, 54001, 443, "udp", 0, 0, 0, b"fixture"),
           4_000_000_000, 0, 1, 2)
    exchange("shared", 101, (("shared.test", 1, 1),),
             (address_record("shared.test", address, 60),), 0x8180, 5, 53001)
    append("shared_target", transport_packet(client, address, 54002, 443, "tcp", 300, 0, 2, b""),
           7_000_000_000, 0, 1, 2)

    ipv6_client, ipv6_resolver, ipv6_address = "2001:db8::2", "2001:db8::53", "2001:db8::20"
    ipv6_question = (("ipv6.test", 28, 1),)
    append("aaaa_query", dns_transport(ipv6_client, ipv6_resolver, 53002, 53, "udp",
        dns_message(102, 0x0100, ipv6_question, (), (), ()), 0, 0), 8_000_000_000, 0, 0, 2)
    append("aaaa_response", dns_transport(ipv6_resolver, ipv6_client, 53, 53002, "udp",
        dns_message(102, 0x8180, ipv6_question, (address_record("ipv6.test", ipv6_address, 15),), (), ()),
        0, 0), 9_000_000_000, 0, 0, 1)
    append("aaaa_target_out", transport_packet(ipv6_client, ipv6_address, 54003, 443, "tcp", 400, 0, 2, b""),
           10_000_000_000, 0, 1, 2)
    append("aaaa_target_in", transport_packet(ipv6_address, ipv6_client, 443, 54003, "tcp", 500, 401, 18, b""),
           11_000_000_000, 0, 1, 1)

    exchange("multiple_questions", 103, (("first.test", 1, 1), ("second.test", 1, 1)),
             (address_record("first.test", "198.51.100.30", 60),), 0x8180, 12, 53003)
    append("multiple_questions_target", transport_packet(client, "198.51.100.30", 54004, 443, "tcp", 600, 0, 2, b""),
           14_000_000_000, 0, 1, 2)
    exchange("nxdomain", 104, (("absent.test", 1, 1),),
             (address_record("absent.test", "198.51.100.31", 60),), 0x8183, 15, 53004)
    append("nxdomain_target", transport_packet(client, "198.51.100.31", 54005, 443, "tcp", 700, 0, 2, b""),
           17_000_000_000, 0, 1, 2)
    exchange("truncated", 105, (("truncated.test", 1, 1),),
             (address_record("truncated.test", "198.51.100.32", 60),), 0x8380, 18, 53005)
    append("truncated_target", transport_packet(client, "198.51.100.32", 54006, 443, "tcp", 800, 0, 2, b""),
           20_000_000_000, 0, 1, 2)

    mdns_question = (("printer.local", 1, 1),)
    append("mdns_query", dns_transport(client, "224.0.0.251", 5353, 5353, "udp",
        dns_message(0, 0, mdns_question, (), (), ()), 0, 0), 21_000_000_000, 0, 0, 2)
    append("mdns_response", dns_transport("192.0.2.10", "224.0.0.251", 5353, 5353, "udp",
        dns_message(0, 0x8400, (), (address_record("printer.local", "192.0.2.10", 120),), (), ()),
        0, 0), 22_000_000_000, 0, None, 1)
    append("mdns_target", transport_packet(client, "192.0.2.10", 54007, 443, "tcp", 900, 0, 2, b""),
           23_000_000_000, 0, 1, 2)
    append("unsolicited_response", dns_transport(resolver, client, 53, 53006, "udp",
        dns_message(106, 0x8180, (("unsolicited.test", 1, 1),),
                    (address_record("unsolicited.test", "198.51.100.33", 60),), (), ()),
        0, 0), 24_000_000_000, 0, 0, 1)
    append("unsolicited_target", transport_packet(client, "198.51.100.33", 54008, 443, "tcp", 1000, 0, 2, b""),
           25_000_000_000, 0, 1, 2)
    exchange("cycle", 107, (("cycle.test", 1, 1),),
             (name_record("cycle.test", "cycle-other.test", 5, 60),
              name_record("cycle-other.test", "cycle.test", 5, 60),
              address_record("cycle-other.test", "198.51.100.34", 60)), 0x8180, 26, 53007)
    append("cycle_target", transport_packet(client, "198.51.100.34", 54009, 443, "tcp", 1100, 0, 2, b""),
           28_000_000_000, 0, 1, 2)
    append("query_known_answer", dns_transport(client, resolver, 53008, 53, "udp",
        dns_message(108, 0x0100, (("query-answer.test", 1, 1),),
                    (address_record("query-answer.test", "198.51.100.35", 60),), (), ()),
        0, 0), 29_000_000_000, 0, 0, 2)
    append("query_known_answer_target", transport_packet(client, "198.51.100.35", 54010, 443, "tcp", 1200, 0, 2, b""),
           30_000_000_000, 0, 1, 2)
    append("different_client_target", transport_packet("192.0.2.3", address, 54011, 443, "tcp", 1300, 0, 2, b""),
           10_000_000_000, 0, 1, 2)
    append("different_interface_target", transport_packet(client, address, 54012, 443, "tcp", 1400, 0, 2, b""),
           10_000_000_000, 1, 1, 2)
    append("expired_target", transport_packet(client, address, 54013, 443, "tcp", 1500, 0, 2, b""),
           80_000_000_000, 0, 1, 2)
    append("before_response_target", transport_packet(client, address, 54014, 443, "tcp", 1600, 0, 2, b""),
           500_000_000, 0, 1, 2)
    append("unrelated_answer_target", transport_packet(client, "198.51.100.21", 54015, 443, "tcp", 1700, 0, 2, b""),
           10_000_000_000, 0, 1, 2)
    append("additional_target", transport_packet(client, "203.0.113.99", 54016, 443, "tcp", 1800, 0, 2, b""),
           10_000_000_000, 0, 1, 2)

    tcp_question = (("tcp-dns.test", 1, 1),)
    tcp_query = dns_message(109, 0x0100, tcp_question, (), (), ())
    tcp_response = dns_message(109, 0x8180, tcp_question,
                               (address_record("tcp-dns.test", "198.51.100.36", 60),), (), ())
    append("tcp_dns_query", dns_transport(client, resolver, 53010, 53, "tcp", tcp_query, 1900, 2000),
           42_000_000_000, 0, 0, 2)
    append("tcp_dns_response", dns_transport(resolver, client, 53, 53010, "tcp", tcp_response,
                                           2000, 1902 + len(tcp_query)), 43_000_000_000, 0, 0, 1)
    append("tcp_dns_target", transport_packet(client, "198.51.100.36", 54017, 443, "udp", 0, 0, 0, b"fixture"),
           44_000_000_000, 0, 1, 2)
    append("cname_scope_before_response", transport_packet(client, address, 54000, 443, "tcp", 101, 201, 16, b""),
           500_000_000, 0, 1, 2)
    append("cname_scope_after_expiry", transport_packet(client, address, 54000, 443, "tcp", 101, 201, 16, b""),
           32_000_000_000, 0, 1, 2)
    return tuple(frames)


def dns_frame_number(label: str) -> int:
    """Resolve a stable fixture name to the original saved frame number."""
    labels = tuple(frame[0] for frame in dns_capture_frames())
    try:
        return labels.index(label) + 1
    except ValueError as error:
        raise ValueError(f"Unknown DNS fixture frame label: {label}") from error


def classic_dns_capture(packets: tuple[tuple[bytes, int], ...]) -> bytes:
    """Wrap exact relative-nanosecond observations in a whole raw-IP PCAP."""
    header = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65_535, 101)
    records: list[bytes] = []
    for packet, offset in packets:
        timestamp = FIXTURE_EPOCH_SECONDS * 1_000_000_000 + FIXTURE_NANOSECONDS + offset
        seconds, nanos = divmod(timestamp, 1_000_000_000)
        records.append(struct.pack("<IIII", seconds, nanos, len(packet), len(packet)) + packet)
    return header + b"".join(records)


def dns_capture(container: Literal["pcap", "pcapng"]) -> bytes:
    """Return a whole offline capture; Apple metadata exists only in PCAPNG."""
    if container not in ("pcap", "pcapng"):
        raise ValueError("DNS fixture format must be PCAP or PCAPNG.")
    frames = dns_capture_frames()
    if container == "pcap":
        return classic_dns_capture(tuple((packet, offset) for _, packet, offset, _, _, _ in frames))
    blocks = [pcapng_block(0x0A0D0D0A, struct.pack("<IHHQ", 0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF))]
    for name in (b"fixture0", b"fixture1"):
        interface = struct.pack("<HHI", 101, 0, 65_535)
        interface += pcapng_option(2, name) + pcapng_option(9, bytes([9])) + pcapng_option(0, b"")
        blocks.append(pcapng_block(1, interface))
    for pid, name in ((343, b"fixture-resolver"), (344, b"fixture-client")):
        process = struct.pack("<I", pid) + pcapng_option(2, name) + pcapng_option(0, b"")
        blocks.append(pcapng_block(0x80000001, process))
    for _, packet, offset, interface, process, direction in frames:
        timestamp = FIXTURE_EPOCH_SECONDS * 1_000_000_000 + FIXTURE_NANOSECONDS + offset
        body = struct.pack("<IIIII", interface, timestamp >> 32, timestamp & 0xFFFFFFFF,
                           len(packet), len(packet)) + padded(packet)
        if process is not None:
            body += pcapng_option(0x8001, struct.pack("<I", process))
        body += pcapng_option(2, struct.pack("<I", direction)) + pcapng_option(0, b"")
        blocks.append(pcapng_block(6, body))
    return b"".join(blocks)
