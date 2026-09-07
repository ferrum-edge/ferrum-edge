#!/usr/bin/env python3
"""Validate data-only paired release-study evidence; never approve adoption."""

import copy
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys


EXPECTED = [
    ("HTTP/1.1", "http://127.0.0.1:8000/echo"),
    ("HTTP/1.1", "http://127.0.0.1:3001/echo"),
    ("HTTP/1.1+TLS", "https://127.0.0.1:8443/echo"),
    ("HTTP/1.1", "http://127.0.0.1:3001/echo"),
    ("HTTP/2", "https://127.0.0.1:8443/echo"),
    ("HTTP/2", "https://127.0.0.1:3443/echo"),
    ("HTTP/3", "https://127.0.0.1:8443/echo"),
    ("HTTP/3", "https://127.0.0.1:3445/echo"),
    ("WebSocket", "ws://127.0.0.1:8000/ws"),
    ("WebSocket", "ws://127.0.0.1:3003"),
    ("gRPC", "http://127.0.0.1:8000"),
    ("gRPC", "http://127.0.0.1:50052"),
    ("TCP", "127.0.0.1:5010"),
    ("TCP", "127.0.0.1:3004"),
    ("TCP+TLS", "127.0.0.1:5001"),
    ("TCP+TLS", "127.0.0.1:3444"),
    ("UDP", "127.0.0.1:5003"),
    ("UDP", "127.0.0.1:3005"),
    ("UDP+DTLS", "127.0.0.1:5004"),
    ("UDP+DTLS", "127.0.0.1:3006"),
]


def extract(raw):
    decoder = json.JSONDecoder()
    records = []
    position = 0
    while (position := raw.find("{", position)) >= 0:
        try:
            record, position = decoder.raw_decode(raw, position)
            records.append(record)
        except json.JSONDecodeError:
            position += 1
    return records


def validate(records):
    if len(records) != len(EXPECTED):
        raise ValueError(f"expected 20 ordered samples, got {len(records)}")
    for index, (record, expected) in enumerate(zip(records, EXPECTED)):
        if not isinstance(record, dict):
            raise ValueError(f"sample {index}: object required")
        if (record.get("protocol"), record.get("target")) != expected:
            raise ValueError(f"sample {index}: protocol/control identity mismatch")
        for field in ("rps", "p99_us", "total_requests"):
            value = record.get(field)
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"sample {index}: invalid {field}")
        if type(record.get("total_errors")) is not int or record["total_errors"] != 0:
            raise ValueError(f"sample {index}: errors or missing error count")
        if record.get("duration_secs") != 5 or record.get("concurrency") != 100:
            raise ValueError(f"sample {index}: workload differs from the study")


def digest(path):
    value = path.read_text().split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"invalid binary digest: {path}")
    return value


def summarize(root):
    runs = {}
    for profile in ("fat", "thin"):
        runs[profile] = []
        expected_digest = digest(root / profile / "gateway.sha256")
        for round_number in (1, 2, 3):
            prefix = root / profile / f"round-{round_number}"
            if digest(prefix.with_suffix(".sha256")) != expected_digest:
                raise ValueError(f"{profile} round {round_number}: binary changed")
            records = extract(prefix.with_suffix(".log").read_text())
            validate(records)
            runs[profile].append(records)
    (root / "results.json").write_text(json.dumps(runs, indent=2, allow_nan=False) + "\n")
    lines = [
        "## Paired release-profile measurements", "",
        "All 120 samples are present, have positive throughput/p99 and zero errors.",
        "One host; three fat/thin pairs in AB, BA, AB order. Values below are",
        "the median of three paired percentage changes (thin relative to fat).",
        "Positive RPS is faster; positive p99 is worse. These are descriptive",
        "measurements, not confidence bounds or approval to change shipping profiles.", "",
        "| Workload | Role | RPS change | p99 change |",
        "| --- | --- | ---: | ---: |",
    ]
    for index, (protocol, _) in enumerate(EXPECTED):
        changes = {}
        for metric in ("rps", "p99_us"):
            changes[metric] = statistics.median(
                100 * (runs["thin"][r][index][metric] / runs["fat"][r][index][metric] - 1)
                for r in range(3)
            )
        role = "gateway" if index % 2 == 0 else "direct control"
        # The HTTP/1.1 TLS control intentionally uses the plain HTTP backend.
        workload = EXPECTED[index - index % 2][0]
        lines.append(f"| {workload} | {role} | {changes['rps']:+.2f}% | {changes['p99_us']:+.2f}% |")
    output = "\n".join(lines) + "\n"
    (root / "summary.md").write_text(output)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(output)
    print(output)


def self_test():
    valid = [dict(protocol=p, target=t, rps=100.0, p99_us=5,
                  total_requests=500, total_errors=0, duration_secs=5, concurrency=100)
             for p, t in EXPECTED]
    validate(valid)
    validate(extract("runner log\n" + "\n".join(json.dumps(r) for r in valid)))
    invalid = [valid[:-1], valid + [valid[0]], list(reversed(valid))]
    for field, value in (("rps", 0), ("rps", float("nan")), ("p99_us", float("inf")),
                         ("total_errors", 1), ("total_errors", None),
                         ("total_requests", False), ("duration_secs", 30),
                         ("concurrency", 1), ("target", "127.0.0.1:9999")):
        case = copy.deepcopy(valid)
        case[0][field] = value
        invalid.append(case)
    for case in invalid:
        try:
            validate(case)
        except ValueError:
            continue
        raise AssertionError("invalid study evidence accepted")
    print(f"Release study verifier: valid sample and {len(invalid)} invalid cases passed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_release_profile_study.py --self-test | EVIDENCE_DIR")
    try:
        if sys.argv[1] == "--self-test":
            self_test()
        else:
            summarize(Path(sys.argv[1]))
    except (ValueError, OSError, IndexError) as error:
        raise SystemExit(f"Release study evidence rejected: {error}") from error
