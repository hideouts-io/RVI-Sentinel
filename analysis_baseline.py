"""Validate the existing v1 baseline and return new observation history values."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping, TypedDict

MAXIMUM_BASELINE_BYTES = 64 * 1024 * 1024


class BaselineValidationError(ValueError):
    """The consumed v1 baseline fields do not satisfy their existing contract."""


class ObservationCounts(TypedDict, total=False):
    last_capture_packets: int
    last_capture_queries: int
    last_capture_observations: int


class BaselineObservation(ObservationCounts):
    first_seen: str
    last_seen: str
    observations: int
    captures: list[str]


class BaselineDocument(TypedDict):
    schema_version: int
    created_at: str
    updated_at: str
    captures_analyzed: int
    endpoints: dict[str, BaselineObservation]
    domains: dict[str, BaselineObservation]
    tls_sni: dict[str, BaselineObservation]


def require_object(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise BaselineValidationError(f"{field} must be a JSON object.")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise BaselineValidationError(f"{field} contains a non-string key.")
        result[key] = item
    return result


def require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise BaselineValidationError(f"{field} must be nonempty text of at most 4096 characters.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BaselineValidationError(f"{field} contains a control character.")
    return value


def require_count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BaselineValidationError(f"{field} must be a nonnegative integer.")
    return value


def parse_observation(value: object, field: str) -> BaselineObservation:
    data = require_object(value, field)
    captures_value = data.get("captures")
    if not isinstance(captures_value, list):
        raise BaselineValidationError(f"{field}.captures must be an array.")
    observation: BaselineObservation = {
        "first_seen": require_text(data.get("first_seen"), f"{field}.first_seen"),
        "last_seen": require_text(data.get("last_seen"), f"{field}.last_seen"),
        "observations": require_count(data.get("observations"), f"{field}.observations"),
        "captures": [require_text(item, f"{field}.captures[]") for item in captures_value],
    }
    if "last_capture_packets" in data:
        observation["last_capture_packets"] = require_count(data["last_capture_packets"], f"{field}.last_capture_packets")
    if "last_capture_queries" in data:
        observation["last_capture_queries"] = require_count(data["last_capture_queries"], f"{field}.last_capture_queries")
    if "last_capture_observations" in data:
        observation["last_capture_observations"] = require_count(data["last_capture_observations"], f"{field}.last_capture_observations")
    return observation


def parse_bucket(value: object, field: str) -> dict[str, BaselineObservation]:
    data = require_object(value, field)
    return {require_text(key, field): parse_observation(item, f"{field}.{key}") for key, item in data.items()}


def empty_baseline(timestamp: str) -> BaselineDocument:
    return {
        "schema_version": 1,
        "created_at": timestamp,
        "updated_at": timestamp,
        "captures_analyzed": 0,
        "endpoints": {},
        "domains": {},
        "tls_sni": {},
    }


def load_baseline(path: Path, timestamp: str) -> BaselineDocument:
    if not path.exists():
        return empty_baseline(timestamp)
    if not path.is_file():
        raise BaselineValidationError("Baseline must be a regular saved JSON file.")
    if path.stat().st_size > MAXIMUM_BASELINE_BYTES:
        raise BaselineValidationError("Baseline exceeds the 64 MiB input limit.")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAXIMUM_BASELINE_BYTES + 1)
        if len(raw) > MAXIMUM_BASELINE_BYTES:
            raise BaselineValidationError("Baseline grew beyond the 64 MiB input limit.")
        payload: object = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BaselineValidationError("Could not read baseline as valid UTF-8 JSON; select a valid v1 baseline.") from error
    data = require_object(payload, "baseline")
    version = require_count(data.get("schema_version"), "baseline.schema_version")
    if version != 1:
        raise BaselineValidationError(f"Unsupported baseline schema version {version}; select a v1 baseline.")
    return {
        "schema_version": version,
        "created_at": require_text(data.get("created_at"), "baseline.created_at"),
        "updated_at": require_text(data.get("updated_at"), "baseline.updated_at"),
        "captures_analyzed": require_count(data.get("captures_analyzed"), "baseline.captures_analyzed"),
        "endpoints": parse_bucket(data.get("endpoints"), "baseline.endpoints"),
        "domains": parse_bucket(data.get("domains"), "baseline.domains"),
        "tls_sni": parse_bucket(data.get("tls_sni"), "baseline.tls_sni"),
    }


def observation_update(existing: BaselineObservation | None, timestamp: str, capture_id: str) -> BaselineObservation:
    if existing is None:
        return {"first_seen": timestamp, "last_seen": timestamp, "observations": 1, "captures": [capture_id]}
    updated: BaselineObservation = {
        **existing,
        "last_seen": timestamp,
        "observations": existing["observations"] + 1,
        "captures": list(existing["captures"]) + ([] if capture_id in existing["captures"] else [capture_id]),
    }
    return updated


def updated_endpoints(existing: Mapping[str, BaselineObservation], findings: Mapping[str, int], timestamp: str, capture_id: str) -> dict[str, BaselineObservation]:
    result: dict[str, BaselineObservation] = {key: {**item, "captures": list(item["captures"])} for key, item in existing.items()}
    for key, count in findings.items():
        item = observation_update(existing.get(key), timestamp, capture_id)
        item["last_capture_packets"] = count
        result[key] = item
    return result


def updated_domains(existing: Mapping[str, BaselineObservation], findings: Mapping[str, int], timestamp: str, capture_id: str) -> dict[str, BaselineObservation]:
    result: dict[str, BaselineObservation] = {key: {**item, "captures": list(item["captures"])} for key, item in existing.items()}
    for key, count in findings.items():
        item = observation_update(existing.get(key), timestamp, capture_id)
        item["last_capture_queries"] = count
        result[key] = item
    return result


def updated_tls_sni(existing: Mapping[str, BaselineObservation], findings: Mapping[str, int], timestamp: str, capture_id: str) -> dict[str, BaselineObservation]:
    result: dict[str, BaselineObservation] = {key: {**item, "captures": list(item["captures"])} for key, item in existing.items()}
    for key, count in findings.items():
        item = observation_update(existing.get(key), timestamp, capture_id)
        item["last_capture_observations"] = count
        result[key] = item
    return result
