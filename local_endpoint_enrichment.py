#!/usr/bin/env python3
"""Add endpoint scope and optional local MMDB context without resolver queries."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone

from maxminddb.errors import InvalidDatabaseError

from enrich_endpoints import parse_args
from finding_enrichment import (
    EndpointEnrichmentResult,
    enrich_local_endpoints,
    enrichment_payload,
)


def main(arguments: list[str]) -> int:
    try:
        request = parse_args(arguments)
        requested_at = datetime.now(timezone.utc)
        findings = enrich_local_endpoints(request.addresses, request.geo_database_path)
    except (FileNotFoundError, InvalidDatabaseError, OSError, ValueError) as error:
        print(f"Local endpoint enrichment failed: {error}", file=sys.stderr)
        return 2

    result = EndpointEnrichmentResult(
        endpoints=findings,
        evidence_source="local",
        requested_at=requested_at,
        completed_at=datetime.now(timezone.utc),
    )
    json.dump(enrichment_payload(result), sys.stdout, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
