#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "tls.handshake.extensions_server_name",
    "_ws.col.Protocol",
]

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def dns_entropy(name: str) -> Tuple[float, str]:
    labels = [x for x in name.rstrip(".").split(".") if x]
    if not labels:
        return 0.0, ""
    label = max(labels, key=len)
    return entropy(label), label

def tshark_rows(pcap: Path) -> Iterable[Dict[str, str]]:
    cmd = [
        "tshark", "-n", "-r", str(pcap),
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]
    for field in FIELDS:
        cmd += ["-e", field]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        raise SystemExit(
            "tshark was not found. Install Wireshark/tshark and ensure `tshark` is in PATH."
        )

    assert proc.stdout is not None
    for line in proc.stdout:
        parts = line.rstrip("\n").split("\t")
        parts += [""] * (len(FIELDS) - len(parts))
        yield dict(zip(FIELDS, parts[:len(FIELDS)]))

    stderr = proc.stderr.read() if proc.stderr else ""
    rc = proc.wait()
    if rc != 0:
        raise SystemExit(f"tshark failed with exit code {rc}: {stderr.strip()}")

def load_baseline(path: Path) -> dict:
    if not path.exists():
        return {
            "schema_version": 1,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "captures_analyzed": 0,
            "endpoints": {},
            "domains": {},
            "tls_sni": {},
        }
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.setdefault("schema_version", 1)
    data.setdefault("captures_analyzed", 0)
    data.setdefault("endpoints", {})
    data.setdefault("domains", {})
    data.setdefault("tls_sni", {})
    return data

def observe(bucket: dict, key: str, timestamp: str, capture_id: str, extra: dict | None = None):
    if not key:
        return
    item = bucket.setdefault(key, {
        "first_seen": timestamp,
        "last_seen": timestamp,
        "observations": 0,
        "captures": [],
    })
    item["last_seen"] = timestamp
    item["observations"] = int(item.get("observations", 0)) + 1
    captures = item.setdefault("captures", [])
    if capture_id not in captures:
        captures.append(capture_id)
    if extra:
        for k, v in extra.items():
            if v not in ("", None):
                item[k] = v

def analyze(pcap: Path, baseline: dict, entropy_threshold: float) -> dict:
    capture_id = f"{pcap.name}:{int(pcap.stat().st_mtime)}:{pcap.stat().st_size}"
    known_endpoints = set(baseline["endpoints"])
    known_domains = set(baseline["domains"])
    known_sni = set(baseline["tls_sni"])

    endpoints = Counter()
    domains = Counter()
    sni = Counter()
    protocols = Counter()
    ports = Counter()
    quic_like = 0
    packet_count = 0
    first_epoch = None
    last_epoch = None
    suspicious_dns = {}

    for row in tshark_rows(pcap):
        packet_count += 1
        epoch = row["frame.time_epoch"]
        if epoch:
            try:
                ts = float(epoch)
                first_epoch = ts if first_epoch is None else min(first_epoch, ts)
                last_epoch = ts if last_epoch is None else max(last_epoch, ts)
            except ValueError:
                pass

        src = row["ip.src"] or row["ipv6.src"]
        dst = row["ip.dst"] or row["ipv6.dst"]
        for ep in (src, dst):
            if ep:
                endpoints[ep] += 1

        proto = row["_ws.col.Protocol"] or "UNKNOWN"
        protocols[proto] += 1

        for p in (row["tcp.srcport"], row["tcp.dstport"], row["udp.srcport"], row["udp.dstport"]):
            if p:
                ports[p] += 1

        if row["udp.srcport"] == "443" or row["udp.dstport"] == "443" or "QUIC" in proto.upper():
            quic_like += 1

        domain = row["dns.qry.name"].strip().lower().rstrip(".")
        if domain:
            domains[domain] += 1
            score, label = dns_entropy(domain)
            if score >= entropy_threshold and len(label) >= 12:
                suspicious_dns[domain] = {
                    "max_label": label,
                    "entropy": round(score, 3),
                    "note": "Heuristic only; legitimate generated/CDN names can score highly.",
                }

        host = row["tls.handshake.extensions_server_name"].strip().lower().rstrip(".")
        if host:
            sni[host] += 1

    analyzed_at = utc_now()

    for ep, count in endpoints.items():
        observe(baseline["endpoints"], ep, analyzed_at, capture_id, {"last_capture_packets": count})
    for name, count in domains.items():
        observe(baseline["domains"], name, analyzed_at, capture_id, {"last_capture_queries": count})
    for host, count in sni.items():
        observe(baseline["tls_sni"], host, analyzed_at, capture_id, {"last_capture_observations": count})

    baseline["captures_analyzed"] = int(baseline.get("captures_analyzed", 0)) + 1
    baseline["updated_at"] = analyzed_at

    def epoch_iso(v):
        if v is None:
            return None
        return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()

    report = {
        "capture": {
            "path": str(pcap),
            "size_bytes": pcap.stat().st_size,
            "capture_id": capture_id,
            "analyzed_at": analyzed_at,
            "packet_count": packet_count,
            "first_packet": epoch_iso(first_epoch),
            "last_packet": epoch_iso(last_epoch),
            "duration_seconds": round(last_epoch - first_epoch, 3) if first_epoch is not None and last_epoch is not None else None,
        },
        "summary": {
            "unique_endpoints": len(endpoints),
            "unique_dns_queries": len(domains),
            "unique_tls_sni": len(sni),
            "quic_like_packets": quic_like,
            "new_endpoints": sorted(set(endpoints) - known_endpoints),
            "new_domains": sorted(set(domains) - known_domains),
            "new_tls_sni": sorted(set(sni) - known_sni),
        },
        "top_endpoints": endpoints.most_common(),
        "top_domains": domains.most_common(),
        "top_tls_sni": sni.most_common(),
        "top_protocols": protocols.most_common(),
        "top_ports": ports.most_common(),
        "dns_entropy_findings": suspicious_dns,
    }
    return report

def write_csv(path: Path, header: List[str], rows: Iterable[Iterable]):
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)

def main():
    parser = argparse.ArgumentParser(description="RVI-Sentinel persistent PCAP/PCAPNG metadata analyzer using tshark.")
    parser.add_argument("pcap", type=Path, help="PCAP or PCAPNG file")
    parser.add_argument("--baseline", type=Path, default=Path("data/findings_master.json"))
    parser.add_argument("--export-dir", type=Path, default=Path("exports"))
    parser.add_argument("--entropy-threshold", type=float, default=3.5)
    parser.add_argument("--top", type=int, default=20, help="Number of rows shown in console summaries")
    args = parser.parse_args()

    if not args.pcap.is_file():
        raise SystemExit(f"Capture not found: {args.pcap}")

    baseline = load_baseline(args.baseline)
    report = analyze(args.pcap, baseline, args.entropy_threshold)

    args.baseline.parent.mkdir(parents=True, exist_ok=True)
    args.export_dir.mkdir(parents=True, exist_ok=True)

    with args.baseline.open("w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, sort_keys=True)

    stem = args.pcap.stem
    report_path = args.export_dir / f"{stem}_report.json"
    with report_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)

    write_csv(args.export_dir / f"{stem}_endpoints.csv", ["endpoint", "packets"], report["top_endpoints"])
    write_csv(args.export_dir / f"{stem}_dns.csv", ["domain", "queries"], report["top_domains"])
    write_csv(args.export_dir / f"{stem}_tls_sni.csv", ["hostname", "observations"], report["top_tls_sni"])

    s = report["summary"]
    c = report["capture"]
    print(f"Capture: {c['path']}")
    print(f"Packets: {c['packet_count']}")
    print(f"Duration: {c['duration_seconds']} seconds")
    print(f"Unique endpoints: {s['unique_endpoints']} ({len(s['new_endpoints'])} new)")
    print(f"Unique DNS names: {s['unique_dns_queries']} ({len(s['new_domains'])} new)")
    print(f"Unique TLS SNI: {s['unique_tls_sni']} ({len(s['new_tls_sni'])} new)")
    print(f"QUIC-like packets: {s['quic_like_packets']}")
    print(f"Report: {report_path}")
    print(f"Baseline: {args.baseline}")

    if args.top > 0:
        print("\nTop endpoints:")
        for key, count in report["top_endpoints"][:args.top]:
            marker = " NEW" if key in s["new_endpoints"] else ""
            print(f"  {count:>8}  {key}{marker}")

        print("\nTop DNS:")
        for key, count in report["top_domains"][:args.top]:
            marker = " NEW" if key in s["new_domains"] else ""
            print(f"  {count:>8}  {key}{marker}")

if __name__ == "__main__":
    main()
