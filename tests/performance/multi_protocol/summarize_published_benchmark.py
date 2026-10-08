#!/usr/bin/env python3
"""Summarize a run_published_benchmark.sh result directory.

Layout read (written by the wrapper):

    <out>/manifest.json
    <out>/raw/<suite>/run<N>/<protocol>.log        proto_bench --json stream
    <out>/raw/<suite>/run<N>/<protocol>.cpu.jsonl  gateway CPU for the gateway leg

Writes <out>/summary.json, <out>/summary.md, and <out>/samples.json (every
raw leg report and gateway CPU sample). Every headline value is the
median across repeated runs; the spread (min..max, CV) is kept beside it so a
noisy row is visible rather than averaged away.
"""

import json
import statistics
import sys
from pathlib import Path

PROTOCOL_ORDER = ["http1", "http1-tls", "http2", "http3", "ws", "grpc",
                  "tcp", "tcp-tls", "udp", "udp-dtls"]
PROTOCOL_NAMES = {
    "http1": "HTTP/1.1", "http1-tls": "HTTP/1.1 + TLS", "http2": "HTTP/2 (TLS)",
    "http3": "HTTP/3 (QUIC)", "ws": "WebSocket", "grpc": "gRPC (h2c)",
    "tcp": "TCP", "tcp-tls": "TCP + TLS", "udp": "UDP", "udp-dtls": "UDP + DTLS",
}
# Gateway listeners used by run_protocol_test.sh; every other port is a backend.
GATEWAY_PORTS = {"8000", "8443", "5010", "5001", "5003", "5004"}
NOISY_CV_PCT = 10.0


def extract_json(raw):
    decoder = json.JSONDecoder()
    records, position = [], 0
    while (position := raw.find("{", position)) >= 0:
        try:
            record, position = decoder.raw_decode(raw, position)
        except json.JSONDecodeError:
            position += 1
            continue
        if isinstance(record, dict) and "rps" in record and "target" in record:
            records.append(record)
    return records


def target_port(target):
    host_port = target.split("://", 1)[-1].split("/", 1)[0]
    return host_port.rsplit(":", 1)[-1]


def split_legs(records):
    legs = {}
    for record in records:
        leg = "gateway" if target_port(record["target"]) in GATEWAY_PORTS else "direct"
        legs[leg] = record
    return legs


def read_cpu(path):
    if not path.exists():
        return None
    lines = [line for line in path.read_text().splitlines() if line.strip()]
    return json.loads(lines[-1]) if lines else None


def leg_requests(record):
    return (record.get("total_requests", 0) + record.get("warmup_requests", 0)
            + record.get("drain_requests", 0))


def load_samples(out):
    """{suite: {protocol: [per-run sample dict]}}"""
    suites = {}
    raw_root = out / "raw"
    for suite_dir in sorted(p for p in raw_root.iterdir() if p.is_dir()):
        per_protocol = suites.setdefault(suite_dir.name, {})
        for run_dir in sorted(p for p in suite_dir.iterdir() if p.is_dir()):
            for log in sorted(run_dir.glob("*.log")):
                protocol = log.stem
                legs = split_legs(extract_json(log.read_text(errors="replace")))
                sample = {"run": run_dir.name, "gateway": legs.get("gateway"),
                          "direct": legs.get("direct"),
                          "cpu": read_cpu(run_dir / f"{protocol}.cpu.jsonl")}
                per_protocol.setdefault(protocol, []).append(sample)
    return suites


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def cv_pct(values):
    values = [v for v in values if v is not None]
    if len(values) < 2 or statistics.mean(values) == 0:
        return None
    return statistics.stdev(values) / statistics.mean(values) * 100


def summarize_protocol(samples):
    complete = [s for s in samples if s["gateway"] and s["direct"]]
    gw = [s["gateway"] for s in complete]
    dr = [s["direct"] for s in complete]
    gw_rps = [r["rps"] for r in gw]
    dr_rps = [r["rps"] for r in dr]
    overhead = [1 - g["rps"] / d["rps"] for g, d in zip(gw, dr) if d["rps"] > 0]
    cpu_us = []
    cores = []
    for s in complete:
        cpu = s["cpu"]
        requests = leg_requests(s["gateway"])
        if cpu and requests > 0:
            cpu_us.append(cpu["gateway_cpu_seconds"] * 1e6 / requests)
            if cpu.get("wall_seconds"):
                cores.append(cpu["gateway_cpu_seconds"] / cpu["wall_seconds"])
    summary = {
        "runs_complete": len(complete),
        "runs_attempted": len(samples),
        "concurrency": gw[0].get("concurrency") if gw else None,
        "duration_secs": gw[0].get("duration_secs") if gw else None,
        "gateway_rps_median": median(gw_rps),
        "gateway_rps_min": min(gw_rps) if gw_rps else None,
        "gateway_rps_max": max(gw_rps) if gw_rps else None,
        "gateway_rps_cv_pct": cv_pct(gw_rps),
        "direct_rps_median": median(dr_rps),
        "direct_rps_cv_pct": cv_pct(dr_rps),
        "rps_overhead_pct_median": None if not overhead else median(overhead) * 100,
        "gateway_p50_us_median": median([r["p50_us"] for r in gw]),
        "gateway_p99_us_median": median([r["p99_us"] for r in gw]),
        "direct_p50_us_median": median([r["p50_us"] for r in dr]),
        "direct_p99_us_median": median([r["p99_us"] for r in dr]),
        "added_p50_us_median": median([g["p50_us"] - d["p50_us"] for g, d in zip(gw, dr)]),
        "added_p99_us_median": median([g["p99_us"] - d["p99_us"] for g, d in zip(gw, dr)]),
        "gateway_cpu_us_per_request_median": median(cpu_us),
        "gateway_cores_busy_median": median(cores),
        "gateway_errors": sum(r.get("total_errors", 0) for r in gw),
        "direct_errors": sum(r.get("total_errors", 0) for r in dr),
        "per_run": [
            {"run": s["run"],
             "gateway_rps": s["gateway"]["rps"], "direct_rps": s["direct"]["rps"],
             "gateway_p50_us": s["gateway"]["p50_us"], "gateway_p99_us": s["gateway"]["p99_us"],
             "direct_p50_us": s["direct"]["p50_us"], "direct_p99_us": s["direct"]["p99_us"],
             "gateway_errors": s["gateway"].get("total_errors", 0),
             "direct_errors": s["direct"].get("total_errors", 0),
             "gateway_cpu_seconds": (s["cpu"] or {}).get("gateway_cpu_seconds")}
            for s in complete
        ],
    }
    flags = []
    if summary["runs_complete"] < summary["runs_attempted"]:
        flags.append("incomplete-runs")
    if summary["gateway_errors"] or summary["direct_errors"]:
        flags.append("errors")
    for key in ("gateway_rps_cv_pct", "direct_rps_cv_pct"):
        if (summary[key] or 0) > NOISY_CV_PCT:
            flags.append(f"noisy-{key.split('_')[0]}")
    summary["flags"] = flags
    return summary


def ordered(protocols):
    known = [p for p in PROTOCOL_ORDER if p in protocols]
    return known + sorted(p for p in protocols if p not in PROTOCOL_ORDER)


def fmt_int(value):
    return "n/a" if value is None else f"{value:,.0f}"


def fmt_us(value):
    if value is None:
        return "n/a"
    if abs(value) >= 1000:
        return f"{value / 1000:.2f} ms"
    return f"{value:.0f} µs"


def fmt_pct(value):
    return "n/a" if value is None else f"{value:.0f}%"


def fmt_cv(value):
    return "n/a" if value is None else f"{value:.1f}%"


def render_markdown(manifest, summary):
    lines = ["# Ferrum Edge multi-protocol benchmark", ""]
    env = manifest.get("environment", {})
    git = manifest.get("git", {})
    args = manifest.get("args", {})
    lines += [
        f"- Date (UTC): {manifest.get('started_utc', 'unknown')}",
        f"- Commit: `{git.get('commit', 'unknown')}`" + (" (dirty tree)" if git.get("dirty") else ""),
        f"- Gateway: {manifest.get('gateway_version', 'unknown')} — `cargo build --release`",
        f"- Host: {env.get('cpu', 'unknown')}, {env.get('logical_cpus', '?')} logical CPUs, "
        f"{env.get('memory_gib', '?')} GiB, {env.get('os', 'unknown')}",
        f"- Load average at start: {env.get('load_average', 'unknown')}",
    ]
    if manifest.get("binaries_older_than_commit"):
        lines.append("- **Warning:** binaries predate the commit above: "
                     + ", ".join(f"`{path}`" for path in manifest["binaries_older_than_commit"]))
    lines += [
        f"- Runs per row: {args.get('runs')} (leg order alternates gateway-first / direct-first)",
        "- Topology: proto_bench → ferrum-edge → proto_backend on one host over loopback; "
        "the direct leg is proto_bench → proto_backend with the same client protocol.",
        "",
        "Values are medians across runs. `Overhead` is 1 − gateway RPS ÷ direct RPS on a shared host, "
        "where the gateway competes with the load generator and backend for the same cores. "
        "`Gateway CPU/req` is the gateway process's CPU time divided by the requests it served "
        "during the leg — the hardware-relative cost of the extra hop.",
        "",
    ]
    for suite, protocols in summary.items():
        first = next(iter(protocols.values()), {})
        lines.append(f"## {suite}")
        lines.append("")
        lines.append(f"Concurrency {first.get('concurrency')}, {first.get('duration_secs')} s measured per leg.")
        if first.get("concurrency") == 1:
            lines.append("")
            lines.append("One connection: RPS is bounded by round-trip latency, so read `Added p50` "
                         "(the time the gateway hop adds) rather than `Overhead`.")
        lines.append("")
        lines.append("| Protocol | Gateway RPS | Direct RPS | Overhead | Gateway p50 | Gateway p99 | Added p50 | "
                     "Gateway CPU/req | RPS CV | Errors | Flags |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
        for protocol, row in protocols.items():
            lines.append(
                f"| {PROTOCOL_NAMES.get(protocol, protocol)} | {fmt_int(row['gateway_rps_median'])} "
                f"| {fmt_int(row['direct_rps_median'])} | {fmt_pct(row['rps_overhead_pct_median'])} "
                f"| {fmt_us(row['gateway_p50_us_median'])} | {fmt_us(row['gateway_p99_us_median'])} "
                f"| {fmt_us(row['added_p50_us_median'])} | {fmt_us(row['gateway_cpu_us_per_request_median'])} "
                f"| {fmt_cv(row['gateway_rps_cv_pct'])} | {row['gateway_errors'] + row['direct_errors']} "
                f"| {', '.join(row['flags']) or '—'} |")
        lines.append("")
    return "\n".join(lines)


def suite_order(suite):
    """Throughput suites by payload size first, then the latency suite."""
    return (suite.startswith("latency"), payload_from_suite(suite) or 0, suite)


def payload_from_suite(suite):
    digits = "".join(ch for ch in suite.rsplit("_", 1)[-1] if ch.isdigit())
    return int(digits) if digits else None


def summarize(out):
    out = Path(out)
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    samples = load_samples(out)
    summary = {}
    for suite in sorted(samples, key=suite_order):
        per_protocol = samples[suite]
        rows = {}
        for protocol in ordered(per_protocol):
            row = summarize_protocol(per_protocol[protocol])
            row["payload_bytes"] = payload_from_suite(suite)
            if protocol.startswith("udp") and row["payload_bytes"]:
                row["payload_bytes"] = min(row["payload_bytes"], 2048)
            rows[protocol] = row
        summary[suite] = rows
    document = {"manifest": manifest, "suites": summary}
    (out / "summary.json").write_text(json.dumps(document, indent=2, allow_nan=False) + "\n")
    # Every raw leg report, so the summary can be re-derived without the logs.
    (out / "samples.json").write_text(json.dumps(samples, separators=(",", ":"), allow_nan=False) + "\n")
    (out / "summary.md").write_text(render_markdown(manifest, summary).rstrip("\n") + "\n")
    return document


def main(argv):
    if len(argv) != 2:
        raise SystemExit("usage: summarize_published_benchmark.py <result-dir>")
    document = summarize(argv[1])
    for suite, rows in document["suites"].items():
        flagged = {p: r["flags"] for p, r in rows.items() if r["flags"]}
        print(f"{suite}: {len(rows)} protocols" + (f", flagged {flagged}" if flagged else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
