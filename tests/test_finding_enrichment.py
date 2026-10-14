#!/usr/bin/env python3
"""Integration-style checks for local finding enrichment."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from finding_enrichment import (
    classify_address,
    describe_port,
    EndpointEnrichmentResult,
    enrich_endpoints,
    enrich_local_endpoints,
    enrichment_payload,
    format_location,
    parse_enrichment_output,
    parse_enrichment_result_output,
)

REPO = Path(__file__).resolve().parents[1]


def main() -> None:
    assert classify_address("127.0.0.1") == "Loopback"
    assert classify_address("10.0.0.1") == "Private/local"
    assert classify_address("100.64.0.1") == "Carrier-grade NAT"
    assert classify_address("224.0.0.251") == "Multicast"
    assert classify_address("203.0.113.1") == "Documentation/reserved"
    assert classify_address("1.1.1.1") == "Public"

    https = describe_port("TCP", 443)
    assert https.service == "HTTPS"
    assert "Encrypted web" in https.purpose
    quic = describe_port("UDP", 443)
    assert quic.service == "QUIC / HTTP/3"
    dynamic = describe_port("TCP", 55000)
    assert dynamic.service == "Dynamic/private port"

    location = format_location(
        {
            "city": {"names": {"en": "Example City"}},
            "subdivisions": [{"names": {"en": "Example Region"}}],
            "country": {"iso_code": "EX", "names": {"en": "Example Country"}},
            "location": {"time_zone": "Etc/UTC"},
        },
        None,
    )
    assert location == "Example City, Example Region, Example Country · Etc/UTC"

    with patch("socket.gethostbyaddr", side_effect=AssertionError("Passive enrichment invoked a resolver")):
        passive = enrich_local_endpoints(("192.0.2.10", "2001:db8::10", "127.0.0.1"), None)
    assert len(passive) == 3
    assert all(endpoint.hostname == "Not requested" for endpoint in passive)
    assert all("local data only" in endpoint.resolution_note for endpoint in passive)
    assert passive[0].scope == "Documentation/reserved"
    assert passive[1].scope == "Documentation/reserved"

    passive_process = subprocess.run(
        [sys.executable, str(REPO / "local_endpoint_enrichment.py"), "192.0.2.10"],
        text=True, capture_output=True, check=False, timeout=10,
    )
    assert passive_process.returncode == 0, passive_process.stderr
    passive_result = parse_enrichment_result_output(passive_process.stdout)
    assert passive_result.evidence_source == "local"
    assert passive_result.completed_at >= passive_result.requested_at
    assert passive_result.endpoints[0].hostname == "Not requested"

    localhost = enrich_endpoints(("127.0.0.1",), None, 2)
    assert localhost[0].scope == "Loopback"
    assert localhost[0].hostname not in {"Resolving…", "Lookup failed"}
    assert localhost[0].location == "Local/special-use address"

    payload = json.dumps(
        {
            "endpoints": [
                {
                    "address": localhost[0].address,
                    "hostname": localhost[0].hostname,
                    "scope": localhost[0].scope,
                    "location": localhost[0].location,
                    "resolution_note": localhost[0].resolution_note,
                }
            ]
        }
    )
    parsed = parse_enrichment_output(payload)
    assert parsed == localhost

    ptr_process = subprocess.run(
        [sys.executable, str(REPO / "enrich_endpoints.py"), "127.0.0.1"],
        text=True, capture_output=True, check=False, timeout=10,
    )
    assert ptr_process.returncode == 0, ptr_process.stderr
    ptr_result = parse_enrichment_result_output(ptr_process.stdout)
    assert ptr_result.evidence_source == "ptr"
    assert ptr_result.endpoints == localhost
    assert "configured DNS resolver" in ptr_result.endpoints[0].resolution_note

    result = EndpointEnrichmentResult(
        endpoints=passive,
        evidence_source="local",
        requested_at=datetime(2026, 10, 11, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 10, 11, 12, 0, 1, tzinfo=timezone.utc),
    )
    assert parse_enrichment_result_output(json.dumps(enrichment_payload(result))) == result
    invalid_source = {"evidence_source": "invalid"}
    try:
        parse_enrichment_result_output(json.dumps(invalid_source))
    except ValueError as error:
        assert "evidence_source" in str(error)
    else:
        raise AssertionError("Unknown enrichment evidence source was accepted")
    invalid_timestamp = enrichment_payload(result)
    invalid_timestamp["requested_at"] = "2026-10-11T12:00:00"
    try:
        parse_enrichment_result_output(json.dumps(invalid_timestamp))
    except ValueError as error:
        assert "timezone" in str(error)
    else:
        raise AssertionError("A timestamp without a timezone was accepted")

    invalid_address = subprocess.run(
        [sys.executable, str(REPO / "local_endpoint_enrichment.py"), "invalid-address"],
        text=True, capture_output=True, check=False, timeout=10,
    )
    assert invalid_address.returncode == 2
    assert "Local endpoint enrichment failed" in invalid_address.stderr

    print("PASS: endpoint address classification")
    print("PASS: transport-aware port explanations")
    print("PASS: local PTR resolution without external geolocation")
    print("PASS: local GeoIP record presentation")
    print("PASS: strict endpoint enrichment output parsing")
    print("PASS: passive endpoint enrichment never invokes the resolver")
    print("PASS: separate local and explicit PTR CLI evidence with timezone-aware timestamps")
    print("PASS: invalid endpoint, evidence source, and timestamp rejection")


if __name__ == "__main__":
    main()
