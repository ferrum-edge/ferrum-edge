#!/usr/bin/env python3
"""Report and gate Criterion p99 samples for semantic-cache cleanup hot paths."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


CARDINALITIES = (10_000, 100_000)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--criterion-root", type=Path, required=True)
    parser.add_argument("--max-scaling-ratio", type=float, required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def p99_per_iteration_ns(criterion_root: Path, cardinality: int) -> float:
    sample_path = (
        criterion_root
        / "ai_semantic_cache_cleanup_hot_path"
        / f"{cardinality}_entries"
        / "new"
        / "sample.json"
    )
    try:
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
        iterations = [float(value) for value in sample["iters"]]
        elapsed_ns = [float(value) for value in sample["times"]]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read Criterion samples from {sample_path}: {error}") from error

    if not iterations or len(iterations) != len(elapsed_ns):
        raise ValueError(f"Criterion samples in {sample_path} have inconsistent lengths")

    per_iteration = []
    for iteration_count, elapsed in zip(iterations, elapsed_ns, strict=True):
        if (
            not math.isfinite(iteration_count)
            or not math.isfinite(elapsed)
            or iteration_count <= 0
            or elapsed <= 0
        ):
            raise ValueError(
                f"Criterion samples in {sample_path} must be finite and positive"
            )
        per_iteration.append(elapsed / iteration_count)

    per_iteration.sort()
    index = max(0, math.ceil(0.99 * len(per_iteration)) - 1)
    return per_iteration[index]


def main() -> int:
    args = parse_args()
    failures: list[str] = []
    results: dict[str, float] = {}

    if args.max_scaling_ratio <= 1:
        failures.append("--max-scaling-ratio must be greater than 1")

    for cardinality in CARDINALITIES:
        try:
            results[str(cardinality)] = p99_per_iteration_ns(
                args.criterion_root, cardinality
            )
        except ValueError as error:
            failures.append(str(error))

    if len(results) == len(CARDINALITIES):
        reference = results[str(CARDINALITIES[0])]
        large = results[str(CARDINALITIES[1])]
        scaling = large / reference
        print(
            "ai_semantic_cache cleanup hot path: "
            f"10000_entries p99={reference:.2f} ns, "
            f"100000_entries p99={large:.2f} ns, scaling={scaling:.2f}x"
        )
        if scaling > args.max_scaling_ratio:
            failures.append(
                f"100k-entry p99 scales {scaling:.2f}x from 10k "
                f"(limit {args.max_scaling_ratio:.2f}x)"
            )
        results["scaling_ratio"] = scaling

    if args.output is not None and results:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print("AI semantic-cache cleanup p99 benchmark is within hosted guardrails.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
