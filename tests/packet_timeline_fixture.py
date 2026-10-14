"""Generate typed timeline observations locally, without reading or sending traffic."""

from __future__ import annotations

from dataclasses import replace

from gui_models import AnalysisReport
from packet_models import DecodedField, PacketRecord, decode_packet_fields, decode_packet_timestamp
from saved_capture import OPTIONAL_FIELDS, REQUIRED_FIELDS

TIMELINE_FIELDS = REQUIRED_FIELDS + ("_ws.col.protocol",) + OPTIONAL_FIELDS


def timeline_templates() -> tuple[PacketRecord, ...]:
    """Include both endpoints, effective labels, unknown context and layered conflicts."""
    base: dict[str, tuple[str, ...]] = {
        "frame.number": ("1",),
        "frame.time_epoch": ("1791428448.590385001",),
        "frame.len": ("96",),
        "frame.cap_len": ("96",),
        "frame.protocols": ("ip:tcp:tls",),
        "_ws.col.protocol": ("TLS",),
        "ip.src": ("192.0.2.2",),
        "ip.dst": ("198.51.100.20",),
        "tcp.srcport": ("53000",),
        "tcp.dstport": ("443",),
        "tcp.stream": ("4",),
        "tcp.seq_raw": ("100",),
        "tcp.ack_raw": ("200",),
        "tcp.flags": ("0x0018",),
        "tcp.len": ("40",),
        "tls.handshake.extensions_server_name": ("timeline.test",),
        "http.host": ("authority.test",),
    }
    recorded = base | {
        "frame.darwin.process_info.pid": ("343",),
        "frame.darwin.process_info.pname": ("fixture-maild",),
        "frame.darwin.process_info.epid": ("344",),
        "frame.darwin.process_info.epname": ("fixture-agent",),
        "frame.interface_name": ("fixture0",),
        "frame.packet_flags_direction": ("2",),
    }
    unknown = base | {
        "ip.src": ("198.51.100.20",),
        "ip.dst": ("192.0.2.2",),
        "tcp.srcport": ("443",),
        "tcp.dstport": ("53000",),
        "tls.handshake.extensions_server_name": ("other.test",),
    }
    ipv6 = {
        "frame.number": ("3",), "frame.time_epoch": ("1791428448.590385002",),
        "frame.len": ("88",), "frame.cap_len": ("88",),
        "frame.protocols": ("ipv6:udp:dns",), "_ws.col.protocol": ("DNS",),
        "ipv6.src": ("2001:db8::2",), "ipv6.dst": ("2001:db8::53",),
        "udp.srcport": ("53001",), "udp.dstport": ("53",), "udp.stream": ("2",),
        "dns.qry.name": ("first.test", "second.test"),
        "frame.darwin.process_info.pid": ("345",),
        "frame.darwin.process_info.pname": ("fixture-dns",),
        "frame.interface_name": ("fixture1",), "frame.packet_flags_direction": ("1",),
    }
    conflict = recorded | {
        "frame.protocols": ("ip:ip:tcp:tls",),
        "ip.src": ("192.0.2.2", "203.0.113.7"),
        "ip.dst": ("198.51.100.20", "203.0.113.9"),
        "pktap.pid": ("901",), "pktap.cmdname": ("fixture-other",),
        "pktap.ifname": ("fixture1",), "pktap.flags": ("1",),
    }
    return tuple(decode_packet_fields(fields, TIMELINE_FIELDS) for fields in (recorded, unknown, ipv6, conflict))


def timeline_records(count: int) -> tuple[PacketRecord, ...]:
    """Return unique frames with tied exact epochs and varied shared metadata.

    Frame and timestamp fields are regenerated for every record. Other immutable
    fields repeat across four observations, modeling repeated flows; benchmarks
    using this corpus measure query/index/presentation work, not decoder RSS.
    """
    if count < 1:
        raise ValueError("Timeline fixture count must be positive.")
    templates = timeline_templates()
    records: list[PacketRecord] = []
    for index in range(count):
        template = templates[index % len(templates)]
        frame = index + 1
        epoch = f"1791428448.{590_385_001 + index // 2:09d}"
        fields = tuple(
            DecodedField(field.name, (str(frame),)) if field.name == "frame.number" else
            DecodedField(field.name, (epoch,)) if field.name == "frame.time_epoch" else field
            for field in template.fields
        )
        records.append(replace(template, frame_number=frame, timestamp=decode_packet_timestamp(epoch), fields=fields))
    return tuple(records)


def timeline_report(template: AnalysisReport, records: tuple[PacketRecord, ...], digest: str) -> AnalysisReport:
    """Build an immutable already-validated-model fixture without inventing a file."""
    evidence = template.evidence
    if evidence is None or not records:
        raise ValueError("A timeline fixture requires packet evidence and a nonempty corpus.")
    first = min(records, key=lambda packet: (packet.timestamp.seconds, packet.timestamp.nanoseconds)).timestamp
    last = max(records, key=lambda packet: (packet.timestamp.seconds, packet.timestamp.nanoseconds)).timestamp
    span = ((last.seconds - first.seconds) * 1_000_000_000 + last.nanoseconds - first.nanoseconds) / 1_000_000_000
    return replace(
        template,
        capture=replace(template.capture, packet_count=len(records), duration_seconds=span),
        evidence=replace(evidence, sha256=digest, packet_record_count=len(records),
                         supported_fields=TIMELINE_FIELDS, supported_field_count=len(TIMELINE_FIELDS), unsupported_fields=()),
        packets=records,
        dns_evidence=None,
    )
