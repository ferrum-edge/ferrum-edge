#!/usr/bin/env python3
"""Compare the same RR selection workload across revisions on one hosted runner.

Three interleaved measurements per revision retain Criterion's 95% intervals.
A serial or parallel regression is clear when every candidate interval lies
above every baseline interval, beyond Criterion's default 1% noise threshold.
This conservative envelope is not a joint statistical confidence interval.
Missing, incomplete or invalid baseline/candidate evidence fails the gate.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path

PARALLEL_THREADS = 8
ITERATIONS_PER_THREAD = 50_000
ROUNDS = 3
NOISE_THRESHOLD = 0.01


def throughput_speedup(serial_ns: float, parallel_ns: float, parallel_threads: int) -> float:
    if not all(math.isfinite(x) and x > 0 for x in (serial_ns, parallel_ns)) or parallel_threads < 1:
        raise ValueError("timings must be finite and positive, with at least one thread")
    return parallel_threads * serial_ns / parallel_ns


def read_interval(path: Path) -> dict[str, float]:
    mean = json.loads(path.read_text())["mean"]
    ci = mean["confidence_interval"]
    values = {"lower": float(ci["lower_bound"]), "point": float(mean["point_estimate"]), "upper": float(ci["upper_bound"])}
    if not all(math.isfinite(x) and x > 0 for x in values.values()):
        raise ValueError(f"non-positive or non-finite interval in {path}")
    if not values["lower"] <= values["point"] <= values["upper"]:
        raise ValueError(f"unordered interval in {path}")
    confidence = float(ci["confidence_level"])
    if not 0.95 <= confidence < 1:
        raise ValueError(f"insufficient or invalid confidence level in {path}")
    return values


def compare_intervals(baseline: list[dict], candidate: list[dict]) -> dict:
    if len(baseline) != ROUNDS or len(candidate) != ROUNDS:
        raise ValueError("all three baseline and candidate rounds are required")
    baseline_upper = max(row["upper"] for row in baseline)
    candidate_lower = min(row["lower"] for row in candidate)
    ratio = statistics.median(row["point"] for row in candidate) / statistics.median(row["point"] for row in baseline)
    return {"regression": candidate_lower > baseline_upper * (1 + NOISE_THRESHOLD),
            "median_ratio": ratio, "baseline_envelope_upper_ns": baseline_upper,
            "candidate_envelope_lower_ns": candidate_lower}


def evaluate(root: Path) -> dict:
    evidence = {}
    for threads in (1, PARALLEL_THREADS):
        roles = {}
        for role in ("baseline", "candidate"):
            roles[role] = [read_interval(root / f"{role}-{round}" / "rr_selection" / f"2_targets_{threads}_threads" / "new" / "estimates.json") for round in range(1, ROUNDS + 1)]
        evidence[str(threads)] = {"measurements": roles, **compare_intervals(roles["baseline"], roles["candidate"])}
    return evidence


def self_test() -> int:
    def rows(lower, point, upper):
        return [{"lower": lower, "point": point, "upper": upper} for _ in range(ROUNDS)]
    baseline = rows(98, 100, 102)
    assert not compare_intervals(baseline, rows(97, 101, 104))["regression"]
    assert compare_intervals(baseline, rows(120, 125, 130))["regression"]
    assert not compare_intervals(baseline, rows(70, 75, 80))["regression"]
    assert not compare_intervals(rows(980, 1000, 1020), rows(970, 1010, 1040))["regression"]
    # One transient slow candidate round does not prove sustained regression.
    candidate = rows(97, 101, 104)
    candidate[1] = {"lower": 120, "point": 125, "upper": 130}
    assert not compare_intervals(baseline, candidate)["regression"]
    try:
        compare_intervals([], candidate)
    except ValueError:
        pass
    else:
        raise AssertionError("missing reference must fail")
    assert throughput_speedup(100, 100, 8) == 8
    assert throughput_speedup(100, 800, 8) == 1
    # Exercise on-disk evidence validation, not only the comparison formula.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "estimates.json"
        valid = {"mean": {"point_estimate": 100, "confidence_interval": {"lower_bound": 98, "upper_bound": 102, "confidence_level": 0.95}}}
        path.write_text(json.dumps(valid))
        assert read_interval(path)["point"] == 100
        for key, value in (("lower_bound", -1), ("upper_bound", 90), ("confidence_level", 0.5), ("upper_bound", float("nan"))):
            invalid = json.loads(json.dumps(valid))
            invalid["mean"]["confidence_interval"][key] = value
            path.write_text(json.dumps(invalid))
            try:
                read_interval(path)
            except ValueError:
                pass
            else:
                raise AssertionError(f"invalid {key} must fail")
        try:
            evaluate(Path(tmp))
        except OSError:
            pass
        else:
            raise AssertionError("missing Criterion rounds must fail")
    print("RR same-workload baseline verifier self-tests passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--criterion-root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.criterion_root is None:
        parser.error("--criterion-root is required")
    try:
        result = evaluate(args.criterion_root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"::error::incomplete RR baseline comparison: {error}")
        return 1
    for threads, row in result.items():
        print(f"RR {threads} threads: candidate/baseline median wall ratio={row['median_ratio']:.3f}; regression={row['regression']}")
    for role in ("baseline", "candidate"):
        serial = statistics.median(r["point"] for r in result["1"]["measurements"][role])
        parallel = statistics.median(r["point"] for r in result["8"]["measurements"][role])
        speedup = throughput_speedup(serial, parallel, PARALLEL_THREADS)
        print(f"{role}: throughput speedup={speedup:.3f}x; per-operation parallel/serial cost={1/speedup:.3f}x (1/8 is ideal scaling; 1 is flat throughput)")
    (args.criterion_root / "comparison.json").write_text(json.dumps(result, indent=2) + "\n")
    if any(row["regression"] for row in result.values()):
        print("::error::RR selection shows a consistent same-workload regression")
        return 1
    print("RR comparison found no consistent regression beyond the measured envelopes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
