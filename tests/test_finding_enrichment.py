#!/usr/bin/env python3
"""Integration-style checks for local finding enrichment."""

from __future__ import annotations

import json

from finding_enrichment import (
    classify_address,
    describe_port,
    enrich_endpoints,
    format_location,
    parse_enrichment_output,
)


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

    print("PASS: endpoint address classification")
    print("PASS: transport-aware port explanations")
    print("PASS: local PTR resolution without external geolocation")
    print("PASS: local GeoIP record presentation")
    print("PASS: strict endpoint enrichment output parsing")


if __name__ == "__main__":
    main()
