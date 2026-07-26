#!/usr/bin/env python3
"""Fail CI when RoundRobin selection reintroduces single-line counter contention.

Criterion fixture contract (see tests/performance/mesh/benches/rr_selection.rs):
  - Each measured custom iteration runs ITERATIONS_PER_THREAD selections per
    worker thread (currently 50_000).
  - The 1-thread case therefore performs 50_000 selections per iteration.
  - The 8-thread case performs 8 * 50_000 selections per iteration.
  - Multi-thread samples reuse a long-lived barrier-synchronized worker pool;
    Criterion's mean is the wall time from barrier release until every worker
    completes the selection loop, not thread spawn/join overhead.
  - Criterion's mean point estimate is elapsed wall-clock nanoseconds for that
    whole custom iteration (not ns/selection).

Throughput speedup is therefore:

  speedup = (PARALLEL_THREADS * serial_ns) / parallel_ns

A single shared `AtomicU64` on a 2-target RR upstream collapses this toward
1.0x (or below); sharded CachePadded counters clear the hosted floor.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


TARGET_COUNT = 2
PARALLEL_THREADS = 8
HOSTED_CONTENTION_FLOOR = 1.10
# Must match tests/performance/mesh/benches/rr_selection.rs
ITERATIONS_PER_THREAD = 50_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify hosted RoundRobin selection Criterion results. "
            "Speedup units: parallel_throughput / serial_throughput, where "
            f"each custom iteration wall time covers "
            f"{ITERATIONS_PER_THREAD} selections per thread."
        )
    )
    parser.add_argument("--criterion-root", type=Path, required=False)
    parser.add_argument(
        "--min-parallel-speedup",
        type=float,
        required=False,
        help=(
            "Minimum (8-thread throughput / 1-thread throughput) required to "
            "pass. Throughput normalizes Criterion wall time by element count "
            f"({PARALLEL_THREADS} * serial_ns / parallel_ns)."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic unit checks for the speedup formula and exit.",
    )
    return parser.parse_args()


def throughput_speedup(serial_ns: float, parallel_ns: float, parallel_threads: int) -> float:
    """Return parallel/serial selection throughput from Criterion wall times."""
    if serial_ns <= 0 or parallel_ns <= 0 or parallel_threads < 1:
        raise ValueError(
            f"invalid timing inputs serial_ns={serial_ns} parallel_ns={parallel_ns} "
            f"parallel_threads={parallel_threads}"
        )
    return (parallel_threads * serial_ns) / parallel_ns


def mean_point_estimate(criterion_root: Path, targets: int, threads: int) -> float:
    estimates_path = (
        criterion_root
        / "rr_selection"
        / f"{targets}_targets_{threads}_threads"
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


def self_test() -> int:
    failures: list[str] = []

    got = throughput_speedup(100.0, 100.0, PARALLEL_THREADS)
    if not math.isclose(got, float(PARALLEL_THREADS)):
        failures.append(f"perfect scaling expected {PARALLEL_THREADS}.0, got {got}")

    got = throughput_speedup(100.0, 100.0 * PARALLEL_THREADS, PARALLEL_THREADS)
    if not math.isclose(got, 1.0):
        failures.append(f"serialized path expected 1.0, got {got}")

    naive = 100.0 / 100.0
    correct = throughput_speedup(100.0, 100.0, PARALLEL_THREADS)
    if math.isclose(naive, correct):
        failures.append("naive wall-ratio must differ from throughput speedup under equal wall time")

    if throughput_speedup(100.0, 800.0, 8) >= HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"serialized 1.0x must stay below the {HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )
    if throughput_speedup(100.0, 400.0, 8) < HOSTED_CONTENTION_FLOOR:
        failures.append(
            f"2.0x throughput must clear the {HOSTED_CONTENTION_FLOOR:.2f} hosted floor"
        )

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1

    print(
        "RR verifier self-test passed "
        f"(throughput speedup = {PARALLEL_THREADS} * serial_wall_ns / parallel_wall_ns)."
    )
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    if args.criterion_root is None or args.min_parallel_speedup is None:
        print("::error::--criterion-root and --min-parallel-speedup are required unless --self-test")
        return 2

    failures: list[str] = []

    if args.min_parallel_speedup <= 1:
        failures.append("--min-parallel-speedup must be greater than 1")

    try:
        serial_ns = mean_point_estimate(args.criterion_root, TARGET_COUNT, 1)
        parallel_ns = mean_point_estimate(args.criterion_root, TARGET_COUNT, PARALLEL_THREADS)
        speedup = throughput_speedup(serial_ns, parallel_ns, PARALLEL_THREADS)
    except ValueError as error:
        failures.append(str(error))
        speedup = None
        serial_ns = parallel_ns = 0.0

    if speedup is not None:
        serial_elements = ITERATIONS_PER_THREAD
        parallel_elements = ITERATIONS_PER_THREAD * PARALLEL_THREADS
        print(
            f"{TARGET_COUNT}_targets: "
            f"1_thread wall={serial_ns:.2f} ns / {serial_elements} selections, "
            f"{PARALLEL_THREADS}_threads wall={parallel_ns:.2f} ns / {parallel_elements} selections, "
            f"throughput_speedup={speedup:.2f}x "
            f"(= {PARALLEL_THREADS} * serial_wall / parallel_wall)"
        )
        if speedup < args.min_parallel_speedup:
            failures.append(
                f"{TARGET_COUNT}_targets throughput speedup {speedup:.2f}x "
                f"below floor {args.min_parallel_speedup:.2f}x "
                "(shared AtomicU64 cache-line bounce typically collapses near 1.0x)"
            )

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1

    print(
        "RR selection benchmark is within hosted contention guardrails "
        "(throughput speedup normalizes Criterion wall time by element count)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
