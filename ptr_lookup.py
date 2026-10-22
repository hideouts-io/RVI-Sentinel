#!/usr/bin/env python3
"""Bound the platform resolver in an owned process; keep its result separate from capture evidence."""

from __future__ import annotations

import ipaddress
import json
import math
import os
import socket
import subprocess
import sys
import time
from queue import Empty, Queue
from threading import Thread
from typing import IO, Literal, TypedDict


class PtrLookupPayload(TypedDict):
    address: str
    status: Literal["resolved", "no_record", "failed"]
    hostname: str | None
    error_code: int | None


def lookup_payload(address: str, attempts: int) -> PtrLookupPayload:
    """Retry immediate transient resolver failures inside the caller's total deadline."""

    parsed_address = str(ipaddress.ip_address(address))
    if attempts < 1:
        raise ValueError("Reverse DNS attempts must be at least one.")
    error_code: int | None = None
    for attempt in range(attempts):
        try:
            hostname, _aliases, _addresses = socket.gethostbyaddr(parsed_address)
        except socket.herror as error:
            if error.errno is None:
                raise OSError("Reverse DNS failed without a platform resolver error code.") from error
            error_code = error.errno
            # POSIX h_errno and Windows WSA host-not-found/no-data codes.
            if error_code in (1, 4, 11001, 11004):
                return {"address": parsed_address, "status": "no_record", "hostname": None, "error_code": error_code}
            if error_code not in (2, 11002) or attempt + 1 == attempts:
                break
        except socket.gaierror as error:
            if error.errno is None:
                raise OSError("Reverse DNS failed without a platform resolver error code.") from error
            error_code = error.errno
            if error_code != socket.EAI_AGAIN or attempt + 1 == attempts:
                break
        else:
            return {"address": parsed_address, "status": "resolved", "hostname": hostname.rstrip("."), "error_code": None}
    return {"address": parsed_address, "status": "failed", "hostname": None, "error_code": error_code}


def parse_lookup_output(payload_text: str, address: str) -> tuple[str, str]:
    """Require the owned helper's closed schema and matching requested address."""

    payload: object = json.loads(payload_text)
    if not isinstance(payload, dict) or set(payload) != {"address", "status", "hostname", "error_code"}:
        raise ValueError("PTR helper output must contain exactly address, status, hostname and error_code.")
    if payload["address"] != address:
        raise ValueError("PTR helper output does not match the requested address.")
    hostname: object = payload["hostname"]
    error_code: object = payload["error_code"]
    if payload["status"] == "resolved":
        if (not isinstance(hostname, str) or not hostname or len(hostname) > 253
                or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in hostname)
                or error_code is not None):
            raise ValueError("PTR helper returned an invalid resolved hostname.")
        return hostname, "PTR record returned by the configured DNS resolver"
    if hostname is not None or type(error_code) is not int:
        raise ValueError("PTR helper failure must contain no hostname and an integer resolver error.")
    if payload["status"] == "no_record" and error_code in (1, 4, 11001, 11004):
        return "No PTR record", "Reverse DNS returned no hostname from the configured DNS resolver"
    if payload["status"] == "failed":
        return "Lookup failed", f"Reverse DNS failed with resolver error {error_code}; no hostname was established."
    raise ValueError("PTR helper returned an invalid resolver status.")


def query_ptr_hostname(
    command: tuple[str, ...], address: str, attempts: int, timeout_seconds: float
) -> tuple[str, str]:
    """Kill and reap the owned resolver on deadline before returning explicit timeout evidence.

    The five-second production wait excludes process creation and a separate
    two-second cleanup budget. Stdin stays open while bounded readers drain the
    result pipes, so loss of the enrichment owner also stops the resolver.
    """

    parsed_address = str(ipaddress.ip_address(address))
    if attempts < 1:
        raise ValueError("Reverse DNS attempts must be at least one.")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Reverse DNS timeout must be finite and positive.")
    process = subprocess.Popen(
        (*command, parsed_address, str(attempts)), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
    )
    events: Queue[tuple[str, bytes | OSError | ValueError]] = Queue()
    readers: list[Thread] = []
    deadline = time.monotonic() + timeout_seconds
    try:
        for channel, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                raise OSError(f"PTR lookup helper {channel} pipe was not created.")
            reader = Thread(target=collect_lookup_output, args=(stream, channel, events), daemon=True)
            reader.start()
            readers.append(reader)
        outputs: dict[str, bytes] = {}
        while len(outputs) < 2 or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "Lookup timed out", (
                    f"Reverse DNS timed out after {timeout_seconds:g} seconds waiting for the configured DNS resolver; "
                    "no hostname was established."
                )
            try:
                channel, output = events.get(timeout=min(0.05, remaining))
            except Empty:
                continue
            if isinstance(output, (OSError, ValueError)):
                raise output
            outputs[channel] = output
        if process.returncode != 0:
            raise OSError(f"PTR lookup helper exited with code {process.returncode}; no lookup evidence was added.")
        return parse_lookup_output(outputs["stdout"].decode("utf-8"), parsed_address)
    finally:
        finish_lookup_process(process, tuple(readers))


def collect_lookup_output(
    stream: IO[bytes], channel: str, events: Queue[tuple[str, bytes | OSError | ValueError]]
) -> None:
    """Drain each pipe concurrently and refuse more than 4096 bytes per channel."""

    chunks: list[bytes] = []
    byte_count = 0
    try:
        while chunk := stream.read(4096):
            byte_count += len(chunk)
            if byte_count > 4096:
                raise ValueError(f"PTR helper {channel} exceeded 4096 bytes; no lookup evidence was added.")
            chunks.append(chunk)
    except (OSError, ValueError) as error:
        events.put((channel, error))
    else:
        events.put((channel, b"".join(chunks)))


def finish_lookup_process(process: subprocess.Popen[bytes], readers: tuple[Thread, ...]) -> None:
    """Bound forced shutdown and retain an explicit reaper if termination is delayed."""

    cleanup_deadline = time.monotonic() + 2.0
    try:
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
        for reader in readers:
            reader.join(timeout=max(0.0, cleanup_deadline - time.monotonic()))
            if reader.is_alive():
                raise TimeoutError("PTR helper output reader did not finish within its two-second cleanup budget.")
    except (subprocess.TimeoutExpired, TimeoutError) as error:
        Thread(target=reap_lookup_process, args=(process, readers), daemon=True).start()
        raise TimeoutError("PTR helper cleanup exceeded two seconds; owned process, reader and pipe cleanup remains active.") from error
    close_lookup_pipes(process)


def reap_lookup_process(process: subprocess.Popen[bytes], readers: tuple[Thread, ...]) -> None:
    """Retain ownership of delayed cleanup; never close a pipe under an active reader."""

    process.wait()
    for reader in readers:
        reader.join()
    close_lookup_pipes(process)


def close_lookup_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def exit_when_owner_closes() -> None:
    """An EOF on the private owner pipe terminates even a blocked native resolver."""

    os.read(sys.stdin.fileno(), 1)
    os._exit(125)


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        print("PTR helper requires an IP address and attempt count.", file=sys.stderr)
        return 2
    owner_watch = Thread(target=exit_when_owner_closes, daemon=True)
    owner_watch.start()
    try:
        result = lookup_payload(arguments[0], int(arguments[1]))
        json.dump(result, sys.stdout, sort_keys=True)
    except (OSError, ValueError) as error:
        print(f"PTR resolver failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
