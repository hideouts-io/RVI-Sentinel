"""Generate diverse saved TCP/UDP observations; no fixture packets are transmitted."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import replace
from typing import Literal

from packet_models import DecodedField, PacketRecord, decode_packet_fields, decode_packet_timestamp
from tests.packet_timeline_fixture import TIMELINE_FIELDS
from tests.saved_capture_fixture import (
    FIXTURE_EPOCH_SECONDS, FIXTURE_NANOSECONDS, internet_checksum, padded,
    pcapng_block, pcapng_option,
)


def transport_packet(source: str, destination: str, source_port: int, destination_port: int,
                     transport: Literal["tcp", "udp"], sequence: int, acknowledgement: int,
                     flags: int, payload: bytes) -> bytes:
    """Build valid raw-IP bidirectional transport bytes with documentation addresses."""
    source_address = ipaddress.ip_address(source)
    destination_address = ipaddress.ip_address(destination)
    if transport not in ("tcp", "udp"):
        raise ValueError("Fixture transport must be TCP or UDP.")
    if source_address.version != destination_address.version:
        raise ValueError("Fixture endpoint families must agree.")
    protocol = 6 if transport == "tcp" else 17
    if transport == "tcp":
        body = struct.pack("!HHIIBBHHH", source_port, destination_port, sequence,
                           acknowledgement, 0x50, flags, 8192, 0, 0) + payload
        checksum_offset = 16
    else:
        body = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
        checksum_offset = 6
    if source_address.version == 4:
        pseudoheader = source_address.packed + destination_address.packed + struct.pack("!BBH", 0, protocol, len(body))
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0, 64,
                             protocol, 0, source_address.packed, destination_address.packed)
        header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    else:
        pseudoheader = source_address.packed + destination_address.packed + struct.pack("!I3xB", len(body), protocol)
        header = struct.pack("!IHBB16s16s", 0x60000000, len(body), protocol, 64,
                             source_address.packed, destination_address.packed)
    checksum = internet_checksum(pseudoheader + body)
    body = body[:checksum_offset] + struct.pack("!H", checksum or 0xFFFF) + body[checksum_offset + 2:]
    return header + body


def scoped_capture_frames() -> tuple[tuple[bytes, int, int | None, int], ...]:
    """Include same-stream metadata scopes, reverse traffic, and separate transports."""
    tcp_out = transport_packet("192.0.2.2", "198.51.100.20", 53000, 443, "tcp", 100, 0, 2, b"")
    tcp_in = transport_packet("198.51.100.20", "192.0.2.2", 443, 53000, "tcp", 200, 101, 18, b"")
    tcp_ack = transport_packet("192.0.2.2", "198.51.100.20", 53000, 443, "tcp", 101, 201, 16, b"")
    udp_out = transport_packet("192.0.2.2", "198.51.100.20", 53000, 443, "udp", 0, 0, 0, b"session-fixture")
    udp_in = transport_packet("198.51.100.20", "192.0.2.2", 443, 53000, "udp", 0, 0, 0, b"session-reply")
    ipv6_tcp_out = transport_packet("2001:db8::2", "2001:db8::20", 53001, 443, "tcp", 300, 0, 2, b"")
    ipv6_tcp_in = transport_packet("2001:db8::20", "2001:db8::2", 443, 53001, "tcp", 400, 301, 18, b"")
    ipv6_udp_out = transport_packet("2001:db8::2", "2001:db8::20", 53001, 443, "udp", 0, 0, 0, b"v6-session")
    ipv6_udp_in = transport_packet("2001:db8::20", "2001:db8::2", 443, 53001, "udp", 0, 0, 0, b"v6-reply")
    return (
        (tcp_out, 0, 0, 2), (udp_out, 0, 0, 2), (tcp_in, 0, 0, 1),
        (udp_in, 0, 0, 1), (tcp_ack, 0, 0, 2),
        (tcp_ack, 0, 1, 2), (tcp_in, 0, 1, 1),
        (tcp_ack, 1, 0, 2), (tcp_in, 1, 0, 1),
        (ipv6_tcp_out, 1, 1, 2), (ipv6_tcp_in, 1, 1, 1),
        (ipv6_udp_out, 1, 1, 2), (ipv6_udp_in, 1, 1, 1),
        (tcp_ack, 0, None, 2),
    )


def session_capture(container: Literal["pcap", "pcapng"]) -> bytes:
    """Return valid whole captures, optionally with two interfaces and two processes."""
    if container not in ("pcap", "pcapng"):
        raise ValueError("Fixture container must be PCAP or PCAPNG.")
    frames = scoped_capture_frames()
    if container == "pcap":
        header = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65_535, 101)
        return header + b"".join(
            struct.pack("<IIII", FIXTURE_EPOCH_SECONDS, FIXTURE_NANOSECONDS + index,
                        len(packet), len(packet)) + packet
            for index, (packet, _, _, _) in enumerate(frames)
        )
    section = struct.pack("<IHHQ", 0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF)
    blocks = [pcapng_block(0x0A0D0D0A, section)]
    for name in (b"fixture0", b"fixture1"):
        interface = struct.pack("<HHI", 101, 0, 65_535)
        interface += pcapng_option(2, name) + pcapng_option(9, bytes([9])) + pcapng_option(0, b"")
        blocks.append(pcapng_block(1, interface))
    for pid, name in ((343, b"fixture-maild"), (344, b"fixture-agent")):
        process = struct.pack("<I", pid) + pcapng_option(2, name) + pcapng_option(0, b"")
        blocks.append(pcapng_block(0x80000001, process))
    for index, (packet, interface, process, direction) in enumerate(frames):
        timestamp = FIXTURE_EPOCH_SECONDS * 1_000_000_000 + FIXTURE_NANOSECONDS + index
        body = struct.pack("<IIIII", interface, timestamp >> 32, timestamp & 0xFFFFFFFF,
                           len(packet), len(packet)) + padded(packet)
        if process is not None:
            body += pcapng_option(0x8001, struct.pack("<I", process))
        body += pcapng_option(2, struct.pack("<I", direction)) + pcapng_option(0, b"")
        blocks.append(pcapng_block(6, body))
    return b"".join(blocks)


def diverse_session_records(frame_count: int) -> tuple[PacketRecord, ...]:
    """Build two-way groups with distinct streams, process scopes, and interfaces.

    Each pair shares its exact scope. Eight groups reuse a stream number while
    varying transport, endpoints, recorded/effective process and interface. This
    corpus measures actual many-session construction and Qt querying, rather
    than representing one repeated flow. It is already typed synthetic evidence;
    benchmark results do not establish decoder or original-capture performance.
    """
    if frame_count < 2 or frame_count % 2:
        raise ValueError("The many-session fixture requires a positive even frame count.")
    records: list[PacketRecord] = []
    for group in range(frame_count // 2):
        transport = "tcp" if group % 2 == 0 else "udp"
        source = f"192.0.2.{2 + group % 16}"
        destination = f"198.51.100.{20 + group % 16}"
        source_port = 53000 + group % 16
        fields: dict[str, tuple[str, ...]] = {
            "frame.number": (str(group * 2 + 1),),
            "frame.time_epoch": (f"1791428448.{590_385_001 + group:09d}",),
            "frame.len": ("96",), "frame.cap_len": ("96",),
            "frame.protocols": (f"ip:{transport}",), "_ws.col.protocol": (transport.upper(),),
            "ip.src": (source,), "ip.dst": (destination,),
            f"{transport}.srcport": (str(source_port),), f"{transport}.dstport": ("443",),
            f"{transport}.stream": (str(group // 8),),
            "frame.darwin.process_info.pid": (str(343 + group % 103),),
            "frame.darwin.process_info.pname": (f"fixture-process-{group % 103}",),
            "frame.darwin.process_info.epid": (str(1000 + group % 113),),
            "frame.darwin.process_info.epname": (f"fixture-effective-{group % 113}",),
            "frame.interface_name": (f"fixture{group % 13}",),
            "frame.packet_flags_direction": ("2",),
        }
        outgoing = decode_packet_fields(fields, TIMELINE_FIELDS)
        records.append(outgoing)
        frame = group * 2 + 2
        epoch = f"1791428448.{590_385_002 + group:09d}"
        reverse_values = {
            "frame.number": (str(frame),), "frame.time_epoch": (epoch,),
            "ip.src": (destination,), "ip.dst": (source,),
            f"{transport}.srcport": ("443",), f"{transport}.dstport": (str(source_port),),
            "frame.packet_flags_direction": ("1",),
        }
        reverse_fields = tuple(DecodedField(field.name, reverse_values.get(field.name, field.values))
                               for field in outgoing.fields)
        incoming = decode_packet_fields({field.name: field.values for field in reverse_fields}, TIMELINE_FIELDS)
        records.append(replace(incoming, timestamp=decode_packet_timestamp(epoch)))
    return tuple(records)


def ungrouped_session_records() -> tuple[PacketRecord, ...]:
    """Retain individually valid packets whose evidence cannot select one scope."""
    pair = diverse_session_records(2)
    base = {field.name: field.values for field in pair[0].fields}
    variations: list[dict[str, tuple[str, ...]]] = []
    missing_stream = dict(base)
    del missing_stream["tcp.stream"]
    variations.append(missing_stream)
    missing_port = dict(base)
    del missing_port["tcp.dstport"]
    variations.append(missing_port)
    variations.append(base | {"pktap.pid": ("901",), "pktap.cmdname": ("conflicting-fixture",)})
    variations.append(base | {"pktap.flags": ("1",)})
    variations.append(base | {"ip.src": ("192.0.2.2", "203.0.113.2"),
                              "ip.dst": ("198.51.100.20", "203.0.113.20")})
    nontransport = {name: value for name, value in base.items() if not name.startswith("tcp.")}
    nontransport |= {"frame.protocols": ("ip:icmp",), "_ws.col.protocol": ("ICMP",)}
    variations.append(nontransport)
    return pair + tuple(
        decode_packet_fields(values | {"frame.number": (str(frame),),
                                       "frame.time_epoch": (f"1791428448.{590_385_001 + frame:09d}",)},
                             TIMELINE_FIELDS)
        for frame, values in enumerate(variations, 3)
    )
