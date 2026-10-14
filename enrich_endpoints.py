#!/usr/bin/env python3
"""Explicitly query current PTR names and optional local GeoIP locations."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from finding_enrichment import EndpointEnrichmentResult, enrich_endpoints, enrichment_payload
from maxminddb.errors import InvalidDatabaseError


@dataclass(frozen=True)
class EnrichmentRequest:
    geo_database_path: Path | None
    addresses: tuple[str, ...]


def parse_args(arguments: list[str]) -> EnrichmentRequest:
    parser = argparse.ArgumentParser(
        description="Read endpoint addresses and an optional local GeoIP MMDB database path."
    )
    parser.add_argument("--geo-db", type=Path)
    parser.add_argument("addresses", nargs="+")
    parsed = parser.parse_args(arguments)
    geo_database_value: object = parsed.geo_db
    addresses_value: object = parsed.addresses
    if geo_database_value is not None and not isinstance(geo_database_value, Path):
        raise ValueError("--geo-db must resolve to a filesystem path.")
    if not isinstance(addresses_value, list) or not addresses_value:
        raise ValueError("At least one endpoint address is required.")
    if any(not isinstance(address, str) for address in addresses_value):
        raise ValueError("Every endpoint address must be a string.")
    return EnrichmentRequest(
        geo_database_path=geo_database_value,
        addresses=tuple(addresses_value),
    )


def main(arguments: list[str]) -> int:
    try:
        request = parse_args(arguments)
        requested_at = datetime.now(timezone.utc)
        findings = enrich_endpoints(
            request.addresses, request.geo_database_path, 2
        )
    except (FileNotFoundError, InvalidDatabaseError, OSError, ValueError) as error:
        print(f"Endpoint enrichment failed: {error}", file=sys.stderr)
        return 2

    result = EndpointEnrichmentResult(
        endpoints=findings,
        evidence_source="ptr",
        requested_at=requested_at,
        completed_at=datetime.now(timezone.utc),
    )
    json.dump(enrichment_payload(result), sys.stdout, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
