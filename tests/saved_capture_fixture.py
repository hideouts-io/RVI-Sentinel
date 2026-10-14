"""Generate saved packet formats locally; none of these packets are transmitted."""

from __future__ import annotations

import ipaddress
import struct

FIXTURE_EPOCH_SECONDS = 1_791_428_448
FIXTURE_NANOSECONDS = 590_385_001


def padded(value: bytes) -> bytes:
    return value + bytes((-len(value)) % 4)


def pcapng_option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + padded(value)


def pcapng_block(block_type: int, body: bytes) -> bytes:
    if len(body) % 4:
        raise ValueError("PCAPNG fixture block body must be aligned to four bytes.")
    length = len(body) + 12
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def dns_name(value: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in value.split(".")) + b"\0"


def dns_questions(names: tuple[str, ...], record_type: int) -> bytes:
    questions = b"".join(dns_name(name) + struct.pack("!HH", record_type, 1) for name in names)
    return struct.pack("!HHHHHH", 7, 0x0100, len(names), 0, 0, 0) + questions


def internet_checksum(value: bytes) -> int:
    aligned = value if len(value) % 2 == 0 else value + b"\0"
    total = sum(struct.unpack(f"!{len(aligned) // 2}H", aligned))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_dns_packet(names: tuple[str, ...]) -> bytes:
    source = ipaddress.IPv4Address("192.0.2.2").packed
    destination = ipaddress.IPv4Address("192.0.2.53").packed
    payload = dns_questions(names, 1)
    udp = struct.pack("!HHHH", 53000, 53, len(payload) + 8, 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(udp) + 20, 1, 0, 64, 17, 0, source, destination)
    header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    return header + udp


def ipv6_dns_packet() -> bytes:
    source = ipaddress.IPv6Address("2001:db8::2").packed
    destination = ipaddress.IPv6Address("2001:db8::53").packed
    payload = dns_questions(("ipv6.test",), 28)
    udp_length = len(payload) + 8
    udp = struct.pack("!HHHH", 53001, 53, udp_length, 0) + payload
    pseudoheader = source + destination + struct.pack("!I3xB", udp_length, 17)
    checksum = internet_checksum(pseudoheader + udp)
    udp = udp[:6] + struct.pack("!H", checksum or 0xFFFF) + udp[8:]
    return struct.pack("!IHBB16s16s", 0x60000000, udp_length, 17, 64, source, destination) + udp


def fixture_packets() -> tuple[bytes, ...]:
    return (
        ipv4_dns_packet(("first.test", "second.test")),
        ipv4_dns_packet(("repeat.test",)),
        ipv6_dns_packet(),
    )


def classic_capture(packet_count: int) -> bytes:
    """Return nanosecond-resolution PCAP with raw IPv4/IPv6 packets and no process metadata."""
    if packet_count < 0:
        raise ValueError("The fixture packet count must not be negative.")
    header = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65_535, 101)
    packets = fixture_packets()
    records = (
        struct.pack("<IIII", FIXTURE_EPOCH_SECONDS, FIXTURE_NANOSECONDS + index, len(packet), len(packet)) + packet
        for index in range(packet_count)
        for packet in (packets[index % len(packets)],)
    )
    return header + b"".join(records)


def metadata_capture() -> bytes:
    """Return PCAPNG with synthetic Apple process, interface, direction, and exact timestamps."""
    section = struct.pack("<IHHQ", 0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF)
    interface = struct.pack("<HHI", 101, 0, 65_535)
    interface += pcapng_option(2, b"fixture0") + pcapng_option(9, bytes([9])) + pcapng_option(0, b"")
    process = struct.pack("<I", 343) + pcapng_option(2, b"fixture-maild") + pcapng_option(0, b"")
    blocks = [pcapng_block(0x0A0D0D0A, section), pcapng_block(1, interface), pcapng_block(0x80000001, process)]
    for index, packet in enumerate(fixture_packets()):
        timestamp = FIXTURE_EPOCH_SECONDS * 1_000_000_000 + FIXTURE_NANOSECONDS + index
        body = struct.pack("<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(packet), len(packet))
        body += padded(packet)
        body += pcapng_option(0x8001, struct.pack("<I", 0)) + pcapng_option(2, struct.pack("<I", 2)) + pcapng_option(0, b"")
        blocks.append(pcapng_block(6, body))
    return b"".join(blocks)
