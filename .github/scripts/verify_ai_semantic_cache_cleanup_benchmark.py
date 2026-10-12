#!/usr/bin/env python3
"""Report and gate semantic-cache cleanup hot-path Criterion samples.

The statistic is the p99 of Criterion's per-sample means (`times / iters` for
each sample), not a p99 of individual request latencies: Criterion records one
elapsed total per sample of many iterations.

Timing data is accepted only together with the fixture evidence the benchmark
writes after it has verified, outside the timed loop, that it seeded and
retained every entry through the production final-body hooks and that the
measured request is an exact local miss (issue #6291).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import tempfile
from pathlib import Path


CARDINALITIES = (10_000, 100_000)
BENCHMARK_GROUP = "ai_semantic_cache_cleanup_hot_path"
STATISTIC = "p99_of_criterion_sample_means_ns"
EXPECTED_REQUEST_HOOK = "on_final_request_body_with_context"
EXPECTED_STORE_HOOK = "on_final_response_body"
EXPECTED_MEASURED_PATH = "exact_local_miss"
REQUIRED_NEGATIVE_FIXTURES = (
    "skipped_seed_rejected",
    "default_hook_seed_rejected",
    "default_hook_measurement_rejected",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--criterion-root", type=Path)
    parser.add_argument("--max-scaling-ratio", type=float)
    parser.add_argument("--fixture-evidence", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def p99_of_sample_means_ns(criterion_root: Path, cardinality: int) -> float:
    sample_path = (
        criterion_root
        / BENCHMARK_GROUP
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

    sample_means = []
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
        sample_means.append(elapsed / iteration_count)

    sample_means.sort()
    index = max(0, math.ceil(0.99 * len(sample_means)) - 1)
    return sample_means[index]


def fixture_evidence_errors(evidence: object) -> list[str]:
    """Reject evidence that does not prove the advertised workload was measured."""
    if not isinstance(evidence, dict):
        return ["fixture evidence must be a JSON object"]

    errors: list[str] = []
    if evidence.get("schema") != 1:
        errors.append("fixture evidence schema must be 1")
    if evidence.get("group") != BENCHMARK_GROUP:
        errors.append(f"fixture evidence group must be {BENCHMARK_GROUP!r}")
    if evidence.get("request_hook") != EXPECTED_REQUEST_HOOK:
        errors.append(
            f"fixture request hook must be {EXPECTED_REQUEST_HOOK!r}, "
            f"found {evidence.get('request_hook')!r}"
        )
    if evidence.get("store_hook") != EXPECTED_STORE_HOOK:
        errors.append(
            f"fixture store hook must be {EXPECTED_STORE_HOOK!r}, "
            f"found {evidence.get('store_hook')!r}"
        )
    if evidence.get("maintenance_workers_started") is not False:
        errors.append("fixture must not start lifecycle maintenance workers")

    fixtures = evidence.get("fixtures")
    if not isinstance(fixtures, dict):
        errors.append("fixture evidence must list per-cardinality fixtures")
        fixtures = {}
    for cardinality in CARDINALITIES:
        fixture = fixtures.get(str(cardinality))
        if not isinstance(fixture, dict):
            errors.append(f"fixture evidence is missing the {cardinality}-entry fixture")
            continue
        for field in ("seeded", "retained_hits"):
            value = fixture.get(field)
            if isinstance(value, bool) or value != cardinality:
                errors.append(
                    f"{cardinality}-entry fixture {field} must be {cardinality}, found {value!r}"
                )
        if fixture.get("measured_path") != EXPECTED_MEASURED_PATH:
            errors.append(
                f"{cardinality}-entry fixture measured path must be "
                f"{EXPECTED_MEASURED_PATH!r}, found {fixture.get('measured_path')!r}"
            )

    negative = evidence.get("negative_fixtures")
    if not isinstance(negative, dict):
        errors.append("fixture evidence must report negative fixtures")
        negative = {}
    for name in REQUIRED_NEGATIVE_FIXTURES:
        if negative.get(name) is not True:
            errors.append(f"negative fixture {name} must be true, found {negative.get(name)!r}")
    return errors


def load_fixture_evidence(path: Path) -> list[str]:
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return [f"cannot read fixture evidence from {path}: {error}"]
    return fixture_evidence_errors(evidence)


def evaluate(
    criterion_root: Path,
    max_scaling_ratio: float,
    fixture_evidence: Path,
) -> tuple[dict[str, object], list[str]]:
    failures: list[str] = []
    results: dict[str, object] = {}

    if not max_scaling_ratio > 1:
        failures.append("--max-scaling-ratio must be greater than 1")

    evidence_errors = load_fixture_evidence(fixture_evidence)
    failures.extend(evidence_errors)
    results["fixture_evidence_verified"] = not evidence_errors

    p99: dict[int, float] = {}
    for cardinality in CARDINALITIES:
        try:
            p99[cardinality] = p99_of_sample_means_ns(criterion_root, cardinality)
        except ValueError as error:
            failures.append(str(error))

    if len(p99) == len(CARDINALITIES):
        reference = p99[CARDINALITIES[0]]
        large = p99[CARDINALITIES[1]]
        scaling = large / reference
        print(
            "ai_semantic_cache cleanup hot path (p99 of Criterion sample means): "
            f"10000_entries={reference:.2f} ns, "
            f"100000_entries={large:.2f} ns, scaling={scaling:.2f}x"
        )
        if scaling > max_scaling_ratio:
            failures.append(
                f"100k-entry p99 of sample means scales {scaling:.2f}x from 10k "
                f"(limit {max_scaling_ratio:.2f}x)"
            )
        results["statistic"] = STATISTIC
        for cardinality, value in p99.items():
            results[str(cardinality)] = value
        results["scaling_ratio"] = scaling

    return results, failures


def write_sample(criterion_root: Path, cardinality: int, iters: list[float], times: list[float]) -> None:
    sample_dir = criterion_root / BENCHMARK_GROUP / f"{cardinality}_entries" / "new"
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / "sample.json").write_text(
        json.dumps({"iters": iters, "times": times}), encoding="utf-8"
    )


def valid_evidence() -> dict[str, object]:
    return {
        "schema": 1,
        "group": BENCHMARK_GROUP,
        "request_hook": EXPECTED_REQUEST_HOOK,
        "store_hook": EXPECTED_STORE_HOOK,
        "maintenance_workers_started": False,
        "fixtures": {
            str(cardinality): {
                "seeded": cardinality,
                "retained_hits": cardinality,
                "measured_path": EXPECTED_MEASURED_PATH,
            }
            for cardinality in CARDINALITIES
        },
        "negative_fixtures": {name: True for name in REQUIRED_NEGATIVE_FIXTURES},
    }


def self_test() -> int:
    failures: list[str] = []

    if fixture_evidence_errors(valid_evidence()):
        failures.append(f"valid evidence rejected: {fixture_evidence_errors(valid_evidence())}")

    def mutated(mutate) -> dict[str, object]:
        evidence = json.loads(json.dumps(valid_evidence()))
        mutate(evidence)
        return evidence

    rejected_cases = {
        # The pre-#6291 shape: lookup through the inherited before_proxy default.
        "default before_proxy hook": lambda e: e.update(request_hook="before_proxy"),
        "skipped seed": lambda e: e["fixtures"]["100000"].update(retained_hits=0),
        "partial retention": lambda e: e["fixtures"]["10000"].update(retained_hits=9_999),
        "unseeded fixture": lambda e: e["fixtures"]["10000"].update(seeded=0),
        "boolean count": lambda e: e["fixtures"]["10000"].update(retained_hits=True),
        "missing cardinality": lambda e: e["fixtures"].pop("100000"),
        "wrong measured path": lambda e: e["fixtures"]["10000"].update(measured_path="hit"),
        "maintenance workers": lambda e: e.update(maintenance_workers_started=True),
        "wrong store hook": lambda e: e.update(store_hook="after_proxy"),
        "negative fixture not run": lambda e: e["negative_fixtures"].pop("skipped_seed_rejected"),
        "negative fixture failed": lambda e: e["negative_fixtures"].update(
            default_hook_seed_rejected=False
        ),
    }
    for name, mutate in rejected_cases.items():
        if not fixture_evidence_errors(mutated(mutate)):
            failures.append(f"evidence with {name} was accepted")
    if not fixture_evidence_errors([]):
        failures.append("non-object evidence was accepted")

    with tempfile.TemporaryDirectory() as raw_dir:
        root = Path(raw_dir) / "criterion"
        evidence_path = Path(raw_dir) / "evidence.json"
        evidence_path.write_text(json.dumps(valid_evidence()), encoding="utf-8")
        # Sample means 100..199 ns and 200..299 ns: p99 index 98 -> 198 and 298.
        write_sample(root, 10_000, [10.0] * 100, [float((100 + i) * 10) for i in range(100)])
        write_sample(root, 100_000, [10.0] * 100, [float((200 + i) * 10) for i in range(100)])

        results, errors = evaluate(root, 3.0, evidence_path)
        if errors:
            failures.append(f"valid samples and evidence rejected: {errors}")
        if not math.isclose(float(results.get("10000", 0.0)), 198.0):
            failures.append(f"10k p99 of sample means expected 198.0, got {results.get('10000')}")
        if not math.isclose(float(results.get("100000", 0.0)), 298.0):
            failures.append(f"100k p99 of sample means expected 298.0, got {results.get('100000')}")
        if results.get("statistic") != STATISTIC:
            failures.append("results must name the sample-mean statistic")

        _, errors = evaluate(root, 1.2, evidence_path)
        if not any("scales" in error for error in errors):
            failures.append(f"scaling over the limit was accepted: {errors}")

        _, errors = evaluate(root, 3.0, Path(raw_dir) / "missing.json")
        if not any("cannot read fixture evidence" in error for error in errors):
            failures.append(f"missing fixture evidence was accepted: {errors}")

        evidence_path.write_text(
            json.dumps(mutated(lambda e: e.update(request_hook="before_proxy"))),
            encoding="utf-8",
        )
        _, errors = evaluate(root, 3.0, evidence_path)
        if not errors:
            failures.append("default-hook evidence was accepted alongside valid samples")
        evidence_path.write_text(json.dumps(valid_evidence()), encoding="utf-8")

        write_sample(root, 10_000, [10.0, 0.0], [100.0, 100.0])
        _, errors = evaluate(root, 3.0, evidence_path)
        if not any("finite and positive" in error for error in errors):
            failures.append(f"zero-iteration sample was accepted: {errors}")

        _, errors = evaluate(Path(raw_dir) / "absent", 3.0, evidence_path)
        if not any("cannot read Criterion samples" in error for error in errors):
            failures.append(f"missing Criterion samples were accepted: {errors}")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1
    print("verify_ai_semantic_cache_cleanup_benchmark self-test passed.")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    if (
        args.criterion_root is None
        or args.max_scaling_ratio is None
        or args.fixture_evidence is None
    ):
        print(
            "::error::--criterion-root, --max-scaling-ratio, and --fixture-evidence "
            "are required unless --self-test"
        )
        return 2

    results, failures = evaluate(
        args.criterion_root, args.max_scaling_ratio, args.fixture_evidence
    )

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

    print(
        "AI semantic-cache cleanup benchmark (p99 of Criterion sample means) is "
        "within hosted guardrails."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
