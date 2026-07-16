#!/usr/bin/env python3
"""Fail CI when the indexed IP-restriction lookup benchmark regresses."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


DECISIONS = ("deny_miss", "high_match")
INSTANCE_COUNTS = (1, 4)
REFERENCE_RULES = 100
LARGE_RULES = 10_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--criterion-root", type=Path, required=True)
    parser.add_argument("--max-scaling-ratio", type=float, required=True)
    parser.add_argument("--max-ns-per-instance", type=float, required=True)
    return parser.parse_args()


def mean_point_estimate(
    criterion_root: Path, decision: str, rule_count: int, instance_count: int
) -> float:
    estimates_path = (
        criterion_root
        / "ip_restriction_lookup"
        / f"{decision}_{rule_count}_rules_{instance_count}_instances"
        / "new"
        / "estimates.json"
    )
    try:
        estimates = json.loads(estimates_path.read_text(encoding="utf-8"))
        point_estimate = float(estimates["mean"]["point_estimate"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read Criterion mean from {estimates_path}: {error}") from error

    if not math.isfinite(point_estimate) or point_estimate <= 0:
        raise ValueError(
            f"Criterion mean in {estimates_path} must be finite and positive, got {point_estimate}"
        )
    return point_estimate


def main() -> int:
    args = parse_args()
    failures: list[str] = []

    if args.max_scaling_ratio <= 1:
        failures.append("--max-scaling-ratio must be greater than 1")
    if args.max_ns_per_instance <= 0:
        failures.append("--max-ns-per-instance must be positive")

    for decision in DECISIONS:
        for instance_count in INSTANCE_COUNTS:
            try:
                reference_ns = mean_point_estimate(
                    args.criterion_root, decision, REFERENCE_RULES, instance_count
                )
                large_ns = mean_point_estimate(
                    args.criterion_root, decision, LARGE_RULES, instance_count
                )
            except ValueError as error:
                failures.append(str(error))
                continue

            scaling_ratio = large_ns / reference_ns
            ns_per_instance = large_ns / instance_count
            print(
                f"{decision}/{instance_count}_instances: "
                f"100_rules={reference_ns:.2f} ns, "
                f"10000_rules={large_ns:.2f} ns, "
                f"scaling={scaling_ratio:.2f}x, "
                f"per_instance={ns_per_instance:.2f} ns"
            )

            if scaling_ratio > args.max_scaling_ratio:
                failures.append(
                    f"{decision}/{instance_count}_instances scales {scaling_ratio:.2f}x "
                    f"(limit {args.max_scaling_ratio:.2f}x)"
                )
            if ns_per_instance > args.max_ns_per_instance:
                failures.append(
                    f"{decision}/{instance_count}_instances costs "
                    f"{ns_per_instance:.2f} ns per instance "
                    f"(limit {args.max_ns_per_instance:.2f} ns)"
                )

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print("IP-restriction lookup benchmark is within hosted regression guardrails.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
