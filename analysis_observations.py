"""Pure aggregate observations over already validated saved-packet records."""

from __future__ import annotations

import ipaddress
import threading
from collections import Counter
from dataclasses import dataclass

from packet_models import PacketRecord, packet_values


class PacketObservationCancelled(Exception):
    """Packet reduction was cancelled before complete observations were returned."""


@dataclass(frozen=True, slots=True)
class PacketObservations:
    endpoints: tuple[tuple[str, int], ...]
    domains: tuple[tuple[str, int], ...]
    tls_sni: tuple[tuple[str, int], ...]
    protocols: tuple[tuple[str, int], ...]
    ports: tuple[tuple[str, int], ...]
    transport_ports: tuple[tuple[str, str, int], ...]
    quic_like_packets: int


def check_observation_cancellation(cancellation: threading.Event) -> None:
    if cancellation.is_set():
        raise PacketObservationCancelled("Packet observation reduction was cancelled.")


def ranked_observations(counts: Counter[str], cancellation: threading.Event) -> tuple[tuple[str, int], ...]:
    check_observation_cancellation(cancellation)
    ranked = tuple(counts.most_common())
    check_observation_cancellation(cancellation)
    return ranked


def summarize_packet_observations(packets: tuple[PacketRecord, ...],
                                  cancellation: threading.Event) -> PacketObservations:
    """Retain historical analyzer counts and Counter first-seen tie ordering.

    Endpoints and ports count every recorded field occurrence, including layered
    headers. DNS names include questions on responses; names and SNI are stripped,
    lowercased and stripped of trailing dots. QUIC-like means a literal UDP port
    occurrence of "443" or QUIC in the packet's protocol column, once per packet.
    Callers own record validation and resource limits. Cancellation is checked
    per bounded record and around each ranking operation; no partial result is
    returned. Counter sorting is a bounded library operation over those records.
    """
    check_observation_cancellation(cancellation)
    endpoints: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    tls_sni: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    transport_ports: Counter[tuple[str, str]] = Counter()
    quic_like_packets = 0
    for packet in packets:
        check_observation_cancellation(cancellation)
        for field in ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst"):
            endpoints.update(str(ipaddress.ip_address(value)) for value in packet_values(packet, field))
        protocol = packet_values(packet, "_ws.col.Protocol")[0]
        protocols[protocol] += 1
        for transport, fields in (("tcp", ("tcp.srcport", "tcp.dstport")), ("udp", ("udp.srcport", "udp.dstport"))):
            for field in fields:
                for value in packet_values(packet, field):
                    port = str(int(value))
                    ports[port] += 1
                    transport_ports[(transport, port)] += 1
        udp_ports = packet_values(packet, "udp.srcport") + packet_values(packet, "udp.dstport")
        if "443" in udp_ports or "QUIC" in protocol.upper():
            quic_like_packets += 1
        for value in packet_values(packet, "dns.qry.name"):
            domain = value.strip().lower().rstrip(".")
            if domain:
                domains[domain] += 1
        for value in packet_values(packet, "tls.handshake.extensions_server_name"):
            host = value.strip().lower().rstrip(".")
            if host:
                tls_sni[host] += 1
    ranked_endpoints = ranked_observations(endpoints, cancellation)
    ranked_domains = ranked_observations(domains, cancellation)
    ranked_sni = ranked_observations(tls_sni, cancellation)
    ranked_protocols = ranked_observations(protocols, cancellation)
    ranked_ports = ranked_observations(ports, cancellation)
    ranked_transport_ports = tuple((transport, port, count) for (transport, port), count in transport_ports.most_common())
    check_observation_cancellation(cancellation)
    return PacketObservations(ranked_endpoints, ranked_domains, ranked_sni, ranked_protocols,
                              ranked_ports, ranked_transport_ports, quic_like_packets)
