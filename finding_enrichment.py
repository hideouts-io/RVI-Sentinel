#!/usr/bin/env python3
"""Local endpoint enrichment and human-readable port descriptions."""

from __future__ import annotations

import ipaddress
import json
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, cast

import maxminddb
from maxminddb.reader import Reader


@dataclass(frozen=True)
class EndpointEnrichment:
    address: str
    hostname: str
    scope: str
    location: str
    resolution_note: str


@dataclass(frozen=True)
class PortDescription:
    service: str
    purpose: str


PORT_DESCRIPTIONS: dict[tuple[str, int], PortDescription] = {
    ("TCP", 20): PortDescription("FTP data", "Legacy unencrypted file-transfer data"),
    ("TCP", 21): PortDescription("FTP control", "Legacy unencrypted file-transfer commands"),
    ("TCP", 22): PortDescription("SSH", "Encrypted remote shell, tunneling, and file transfer"),
    ("TCP", 23): PortDescription("Telnet", "Legacy unencrypted remote terminal"),
    ("TCP", 25): PortDescription("SMTP", "Server-to-server email delivery"),
    ("TCP", 53): PortDescription("DNS", "Domain-name queries or zone transfers over TCP"),
    ("UDP", 53): PortDescription("DNS", "Domain-name queries over UDP"),
    ("UDP", 67): PortDescription("DHCP server", "IPv4 address configuration from a DHCP server"),
    ("UDP", 68): PortDescription("DHCP client", "IPv4 address configuration for a DHCP client"),
    ("TCP", 80): PortDescription("HTTP", "Unencrypted web traffic"),
    ("TCP", 110): PortDescription("POP3", "Legacy unencrypted email retrieval"),
    ("UDP", 123): PortDescription("NTP", "Network time synchronization"),
    ("UDP", 137): PortDescription("NetBIOS name", "Legacy Windows name service"),
    ("UDP", 138): PortDescription("NetBIOS datagram", "Legacy Windows datagram service"),
    ("TCP", 139): PortDescription("NetBIOS session", "Legacy Windows file and session traffic"),
    ("TCP", 143): PortDescription("IMAP", "Unencrypted email access"),
    ("UDP", 161): PortDescription("SNMP", "Network-device monitoring queries"),
    ("UDP", 162): PortDescription("SNMP trap", "Network-device monitoring notifications"),
    ("TCP", 389): PortDescription("LDAP", "Directory-service queries without implicit TLS"),
    ("UDP", 389): PortDescription("CLDAP", "Connectionless directory-service queries"),
    ("TCP", 443): PortDescription("HTTPS", "Encrypted web and API traffic"),
    ("UDP", 443): PortDescription("QUIC / HTTP/3", "Encrypted web traffic over QUIC"),
    ("TCP", 445): PortDescription("SMB", "Windows and macOS file or printer sharing"),
    ("TCP", 465): PortDescription("SMTPS", "Email submission using implicit TLS"),
    ("UDP", 500): PortDescription("IKE", "IPsec VPN key exchange"),
    ("UDP", 514): PortDescription("Syslog", "Network log delivery, commonly unencrypted"),
    ("TCP", 548): PortDescription("AFP", "Legacy Apple file sharing"),
    ("TCP", 587): PortDescription("SMTP submission", "Authenticated email submission"),
    ("TCP", 631): PortDescription("IPP", "Network printing"),
    ("UDP", 631): PortDescription("IPP discovery", "Network-printer discovery or status"),
    ("TCP", 636): PortDescription("LDAPS", "Directory-service queries using implicit TLS"),
    ("TCP", 993): PortDescription("IMAPS", "Email access using implicit TLS"),
    ("TCP", 995): PortDescription("POP3S", "Email retrieval using implicit TLS"),
    ("UDP", 1900): PortDescription("SSDP", "UPnP device and service discovery"),
    ("TCP", 3283): PortDescription("Apple Remote Desktop", "Apple remote-management traffic"),
    ("UDP", 3283): PortDescription("Apple Remote Desktop", "Apple remote-management discovery or data"),
    ("TCP", 3478): PortDescription("STUN / TURN", "NAT traversal for real-time communications"),
    ("UDP", 3478): PortDescription("STUN / TURN", "NAT traversal for real-time communications"),
    ("UDP", 4500): PortDescription("IPsec NAT-T", "IPsec VPN traffic through NAT"),
    ("TCP", 5223): PortDescription("Apple Push Service", "Persistent Apple push-notification connection"),
    ("UDP", 5353): PortDescription("mDNS", "Local-network service and hostname discovery"),
    ("UDP", 5355): PortDescription("LLMNR", "Local-link hostname resolution"),
    ("TCP", 5900): PortDescription("VNC", "Remote graphical desktop"),
    ("TCP", 62078): PortDescription("iOS lockdown", "Apple device pairing and management via usbmux"),
    ("TCP", 8080): PortDescription("HTTP alternate", "Common alternate web or proxy port"),
    ("TCP", 8443): PortDescription("HTTPS alternate", "Common alternate encrypted web port"),
}

DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")


def describe_port(transport: str, port: int) -> PortDescription:
    normalized_transport = transport.upper()
    exact = PORT_DESCRIPTIONS.get((normalized_transport, port))
    if exact is not None:
        return exact

    service_names = system_service_names(normalized_transport, port)
    if service_names:
        return PortDescription(
            service=" / ".join(service_names),
            purpose="Registered service name; observed port alone does not confirm the application",
        )
    if port == 0:
        return PortDescription("Reserved", "Reserved port; unusual in ordinary application traffic")
    if port <= 1023:
        return PortDescription(
            "Well-known port",
            "System service range; no specific local service name was available",
        )
    if port <= 49151:
        return PortDescription(
            "Registered/application port",
            "Application service range; attribution requires protocol or process evidence",
        )
    return PortDescription(
        "Dynamic/private port",
        "Usually an ephemeral client port, but applications may also listen here",
    )


def system_service_names(transport: str, port: int) -> tuple[str, ...]:
    protocols = ("tcp", "udp") if transport == "TCP/UDP" else (transport.lower(),)
    names: list[str] = []
    for protocol in protocols:
        try:
            name = socket.getservbyport(port, protocol)
        except OSError:
            continue
        if name not in names:
            names.append(name)
    return tuple(names)


def classify_address(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    if parsed.is_unspecified:
        return "Unspecified"
    if parsed.is_loopback:
        return "Loopback"
    if parsed.is_link_local:
        return "Link-local"
    if parsed.is_multicast:
        return "Multicast"
    if any(parsed in network for network in DOCUMENTATION_NETWORKS):
        return "Documentation/reserved"
    if isinstance(parsed, ipaddress.IPv4Address) and parsed in CARRIER_GRADE_NAT:
        return "Carrier-grade NAT"
    if parsed.is_private:
        return "Private/local"
    if parsed.is_reserved:
        return "Reserved"
    if parsed.is_global:
        return "Public"
    return "Special-use"


def reverse_hostname(address: str, attempts: int) -> tuple[str, str]:
    last_error: socket.gaierror | None = None
    for attempt in range(attempts):
        try:
            hostname, _aliases, _addresses = socket.gethostbyaddr(address)
            return hostname.rstrip("."), "PTR record returned by the configured DNS resolver"
        except socket.herror:
            return "No PTR record", "Reverse DNS returned no hostname"
        except socket.gaierror as error:
            last_error = error
            if attempt + 1 == attempts:
                break
    if last_error is None:
        raise ValueError("Reverse DNS attempts must be at least one.")
    return "Lookup failed", f"Reverse DNS failed after {attempts} attempts: {last_error}"


def enrich_endpoints(
    addresses: tuple[str, ...], geo_database_path: Path | None, dns_attempts: int
) -> tuple[EndpointEnrichment, ...]:
    if dns_attempts < 1:
        raise ValueError("Reverse DNS attempts must be at least one.")
    parsed_addresses = tuple(str(ipaddress.ip_address(address)) for address in addresses)
    reader = open_geo_database(geo_database_path)
    try:
        worker_count = min(16, max(1, len(parsed_addresses)))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            hostname_results = tuple(
                executor.map(
                    lambda address: reverse_hostname(address, dns_attempts), parsed_addresses
                )
            )
        return tuple(
            EndpointEnrichment(
                address=address,
                hostname=hostname_result[0],
                scope=classify_address(address),
                location=location_for(address, reader, geo_database_path),
                resolution_note=hostname_result[1],
            )
            for address, hostname_result in zip(
                parsed_addresses, hostname_results, strict=True
            )
        )
    finally:
        if reader is not None:
            reader.close()


def parse_enrichment_output(payload_text: str) -> tuple[EndpointEnrichment, ...]:
    try:
        payload: object = json.loads(payload_text)
    except json.JSONDecodeError as error:
        raise ValueError(f"Endpoint enrichment output is not valid JSON: {error}") from error
    root = require_object(payload, "enrichment output")
    endpoint_values = root.get("endpoints")
    if not isinstance(endpoint_values, list):
        raise ValueError("Endpoint enrichment output must contain an endpoints array.")
    findings: list[EndpointEnrichment] = []
    for index, endpoint_value in enumerate(endpoint_values):
        endpoint = require_object(endpoint_value, f"endpoints[{index}]")
        findings.append(
            EndpointEnrichment(
                address=require_text(endpoint, "address", index),
                hostname=require_text(endpoint, "hostname", index),
                scope=require_text(endpoint, "scope", index),
                location=require_text(endpoint, "location", index),
                resolution_note=require_text(endpoint, "resolution_note", index),
            )
        )
    return tuple(findings)


def require_object(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object.")
    mapping = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in mapping):
        raise ValueError(f"{field} contains a non-string key.")
    return cast(dict[str, object], mapping)


def require_text(mapping: Mapping[str, object], key: str, index: int) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        raise ValueError(f"endpoints[{index}].{key} must be a string.")
    return value


def open_geo_database(path: Path | None) -> Reader | None:
    if path is None:
        return None
    if not path.is_file():
        raise FileNotFoundError(f"GeoIP database not found: {path}")
    if path.suffix.lower() != ".mmdb":
        raise ValueError(f"GeoIP database must use the .mmdb format: {path}")
    return maxminddb.open_database(path)


def location_for(address: str, reader: Reader | None, path: Path | None) -> str:
    scope = classify_address(address)
    if scope != "Public":
        return "Local/special-use address"
    if reader is None:
        return "Not available — select a local GeoIP database"
    record = reader.get(address)
    if record is None:
        return "No record in local GeoIP database"
    return format_location(require_record_mapping(record, address), path)


def require_record_mapping(value: object, address: str) -> Mapping[str, object]:
    return require_object(value, f"GeoIP record for {address}")


def format_location(record: Mapping[str, object], path: Path | None) -> str:
    city = localized_name(record.get("city"))
    subdivisions_value = record.get("subdivisions")
    subdivision = ""
    if isinstance(subdivisions_value, list) and subdivisions_value:
        subdivision = localized_name(subdivisions_value[0])
    country = localized_name(record.get("country"))
    country_code = nested_string(record.get("country"), "iso_code")
    location_value = record.get("location")
    timezone = nested_string(location_value, "time_zone")

    components = [value for value in (city, subdivision, country or country_code) if value]
    location = ", ".join(components) if components else "Location name unavailable"
    if timezone:
        location = f"{location} · {timezone}"
    if path is not None:
        location = f"{location} · local {path.name}"
    return location


def localized_name(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    names = value.get("names")
    if not isinstance(names, dict):
        return ""
    english = names.get("en")
    return english if isinstance(english, str) else ""


def nested_string(value: object, key: str) -> str:
    if not isinstance(value, dict):
        return ""
    nested = value.get(key)
    return nested if isinstance(nested, str) else ""
