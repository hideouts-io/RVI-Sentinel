#!/usr/bin/env python3
"""Integration-style checks for local finding enrichment."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ptr_lookup import parse_lookup_output, query_ptr_hostname

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


def verify_ptr_process_boundary() -> None:
    """Use actual child processes to exercise the deadline, reaping and owner-pipe cancellation."""

    with tempfile.TemporaryDirectory(prefix="rvi-ptr-process-") as temporary:
        marker = Path(temporary) / "worker.pid"
        blocking_helper = """
import os
from pathlib import Path
import sys
from threading import Event
Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii')
Event().wait()
"""
        started = time.monotonic()
        result = query_ptr_hostname((sys.executable, "-c", blocking_helper, str(marker)), "127.0.0.1", 2, 5.0)
        elapsed = time.monotonic() - started
        assert result[0] == "Lookup timed out", result
        assert "5 seconds" in result[1] and "no hostname was established" in result[1], result
        assert 5.0 <= elapsed < 8.0, f"Five-second PTR deadline/cleanup took {elapsed:.3f}s"
        worker_pid = int(marker.read_text(encoding="ascii"))
        if os.name == "posix":
            try:
                os.waitpid(worker_pid, os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                raise AssertionError("Timed-out owned PTR helper was not reaped")

    ownership_driver = """
import subprocess
import sys
helper = '''
from threading import Event, Thread
from ptr_lookup import exit_when_owner_closes
Thread(target=exit_when_owner_closes, daemon=True).start()
print('ready', flush=True)
Event().wait()
'''
with subprocess.Popen([sys.executable, '-c', helper], stdin=subprocess.PIPE,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
    try:
        assert process.stdout.readline().strip() == 'ready'
        process.stdin.close()
        assert process.wait(timeout=2) == 125
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
print('PASS owner pipe closure stops an actual blocked child')
"""
    ownership = subprocess.run([sys.executable, "-c", ownership_driver], cwd=REPO,
                               text=True, capture_output=True, timeout=10, check=False)
    assert ownership.returncode == 0, ownership.stdout + ownership.stderr
    assert "PASS owner pipe closure" in ownership.stdout

    for helper, expected in (("raise SystemExit(7)", "code 7"),
                             ("print('{}')", "exactly address"),
                             ("import os; os.write(1, b'x' * 65536)", "stdout exceeded 4096 bytes"),
                             ("import os; os.write(2, b'x' * 65536)", "stderr exceeded 4096 bytes")):
        try:
            query_ptr_hostname((sys.executable, "-c", helper), "127.0.0.1", 2, 5.0)
        except (OSError, ValueError) as error:
            assert expected in str(error), error
        else:
            raise AssertionError("PTR helper failure or malformed output was accepted")

    resolved = {"address": "127.0.0.1", "status": "resolved", "hostname": "localhost", "error_code": None}
    assert parse_lookup_output(json.dumps(resolved), "127.0.0.1")[0] == "localhost"
    no_record = {**resolved, "status": "no_record", "hostname": None, "error_code": 1}
    assert parse_lookup_output(json.dumps(no_record), "127.0.0.1")[0] == "No PTR record"
    failed = {**resolved, "status": "failed", "hostname": None, "error_code": 3}
    assert parse_lookup_output(json.dumps(failed), "127.0.0.1")[0] == "Lookup failed"
    for invalid in (
        {**resolved, "address": "192.0.2.1"},
        {**resolved, "extra": "untrusted"},
        {**resolved, "hostname": ""},
        {**resolved, "hostname": "localhost\nextra"},
        {**resolved, "error_code": True},
        {**resolved, "status": "no_record"},
        {**no_record, "error_code": 2},
    ):
        try:
            parse_lookup_output(json.dumps(invalid), "127.0.0.1")
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid PTR helper output was accepted")


def main() -> None:
    verify_ptr_process_boundary()
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
    print("PASS: five-second PTR deadline kills and reaps an actual blocked helper")
    print("PASS: owner-pipe closure cancels an actual blocked helper")
    print("PASS: PTR helper exit, schema and address-binding failures remain explicit")
    print("PASS: helper stdout/stderr overflow fails explicitly without becoming a DNS timeout")


if __name__ == "__main__":
    main()
