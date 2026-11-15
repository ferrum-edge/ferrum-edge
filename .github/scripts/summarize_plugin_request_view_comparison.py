#!/usr/bin/env python3
"""Summarize the paired plugin request-view comparison (issue #7207).

Subcommands:

* ``executable BUILD_JSONL`` prints the one `plugin_request_view` bench
  executable that ``cargo bench --no-run --message-format=json`` produced.
* ``summarize OUTPUT_DIR --rounds N --candidate SHA --baseline SHA
  [--json PATH]`` reads every round's Criterion ``estimates.json`` for both
  revisions and prints a Markdown table (median over rounds of the Criterion
  mean, as nanoseconds per resolved view and as the candidate/baseline ratio).
  Any missing or malformed estimate fails the run: a broken harness must not
  read as "no change".
* ``self-test`` exercises both on synthetic inputs.

Informational only: no budget is enforced.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
from pathlib import Path

BENCH_NAME = "plugin_request_view"
GROUP = "plugin_request_view"
ITERATIONS_PER_THREAD = 50_000
FIXTURES = ("scoped", "global_only")
THREAD_COUNTS = (1, 8)
ROLES = ("baseline", "candidate")


def bench_ids() -> list[tuple[str, int]]:
    return [
        (f"{fixture}_{threads}_threads", threads)
        for fixture in FIXTURES
        for threads in THREAD_COUNTS
    ]


def find_executable(build_jsonl: Path) -> str:
    found: set[str] = set()
    for line in build_jsonl.read_text().splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        message = json.loads(line)
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target") or {}
        executable = message.get("executable")
        if target.get("name") == BENCH_NAME and "bench" in target.get("kind", []) and executable:
            found.add(executable)
    if len(found) != 1:
        raise SystemExit(
            f"expected exactly one {BENCH_NAME} bench executable, found {sorted(found)}"
        )
    return found.pop()


def batch_mean_ns(root: Path, bench_id: str) -> float:
    path = root / GROUP / bench_id / "new" / "estimates.json"
    try:
        estimate = json.loads(path.read_text())["mean"]["point_estimate"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise SystemExit(f"missing or malformed Criterion estimate {path}: {error}")
    if not isinstance(estimate, (int, float)) or estimate <= 0:
        raise SystemExit(f"non-positive Criterion estimate in {path}")
    return float(estimate)


def summarize(
    output: Path, rounds: int, candidate: str, baseline: str
) -> tuple[str, dict]:
    rows = []
    for bench_id, threads in bench_ids():
        views_per_batch = ITERATIONS_PER_THREAD * threads
        per_role: dict[str, list[float]] = {}
        for role in ROLES:
            per_role[role] = [
                batch_mean_ns(output / f"{role}-{round_}", bench_id) / views_per_batch
                for round_ in range(1, rounds + 1)
            ]
        base = statistics.median(per_role["baseline"])
        cand = statistics.median(per_role["candidate"])
        rows.append(
            {
                "bench": f"{GROUP}/{bench_id}",
                "threads": threads,
                "baseline_ns_per_view": per_role["baseline"],
                "candidate_ns_per_view": per_role["candidate"],
                "baseline_median_ns_per_view": base,
                "candidate_median_ns_per_view": cand,
                "candidate_over_baseline": cand / base,
            }
        )
    report = {
        "candidate": candidate,
        "baseline": baseline,
        "rounds": rounds,
        "unit": "wall-clock nanoseconds per resolved view (batch mean / views in batch)",
        "rows": rows,
    }
    lines = [
        "## Plugin request-view comparison (#7207)",
        "",
        f"Candidate `{candidate}` vs baseline `{baseline}`, {rounds} interleaved "
        "round(s) on one runner. Each cell is the median over rounds of the "
        "Criterion mean, divided by the views resolved per batch "
        f"({ITERATIONS_PER_THREAD} per thread). With 8 threads this is aggregate "
        "wall time per view, so it falls as throughput rises.",
        "",
        "| Benchmark | Threads | Baseline ns/view | Candidate ns/view | Candidate / baseline |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['bench']}` | {row['threads']} | "
            f"{row['baseline_median_ns_per_view']:.2f} | "
            f"{row['candidate_median_ns_per_view']:.2f} | "
            f"{row['candidate_over_baseline']:.3f} |"
        )
    lines.append("")
    return "\n".join(lines), report


def write_estimate(root: Path, bench_id: str, mean: float) -> None:
    directory = root / GROUP / bench_id / "new"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "estimates.json").write_text(
        json.dumps({"mean": {"point_estimate": mean}})
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temp:
        output = Path(temp)
        for role, scale in (("baseline", 2.0), ("candidate", 1.0)):
            for round_ in (1, 2, 3):
                for bench_id, threads in bench_ids():
                    write_estimate(
                        output / f"{role}-{round_}",
                        bench_id,
                        scale * 100.0 * ITERATIONS_PER_THREAD * threads,
                    )
        markdown, report = summarize(output, 3, "c" * 40, "b" * 40)
        assert len(report["rows"]) == 4, report
        for row in report["rows"]:
            assert abs(row["candidate_median_ns_per_view"] - 100.0) < 1e-9, row
            assert abs(row["candidate_over_baseline"] - 0.5) < 1e-9, row
        assert "scoped_8_threads" in markdown, markdown

        (output / "candidate-2" / GROUP / "scoped_1_threads" / "new" / "estimates.json").unlink()
        try:
            summarize(output, 3, "c" * 40, "b" * 40)
        except SystemExit as error:
            assert "missing or malformed" in str(error), error
        else:
            raise AssertionError("a missing estimate must fail the summary")

        build = output / "build.jsonl"
        artifact = {
            "reason": "compiler-artifact",
            "target": {"name": BENCH_NAME, "kind": ["bench"]},
            "executable": "/tmp/target/release/deps/plugin_request_view-abc",
        }
        other = {
            "reason": "compiler-artifact",
            "target": {"name": "mesh_perf", "kind": ["lib"]},
            "executable": None,
        }
        build.write_text(
            "\n".join([json.dumps(other), json.dumps(artifact), "Finished"]) + "\n"
        )
        assert find_executable(build) == artifact["executable"]
        build.write_text(json.dumps(other) + "\n")
        try:
            find_executable(build)
        except SystemExit:
            pass
        else:
            raise AssertionError("a build without the bench executable must fail")
    print("summarize_plugin_request_view_comparison self-test passed")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    executable = commands.add_parser("executable")
    executable.add_argument("build_jsonl", type=Path)
    summary = commands.add_parser("summarize")
    summary.add_argument("output", type=Path)
    summary.add_argument("--rounds", type=int, required=True)
    summary.add_argument("--candidate", required=True)
    summary.add_argument("--baseline", required=True)
    summary.add_argument("--json", type=Path)
    commands.add_parser("self-test")
    args = parser.parse_args(argv)

    if args.command == "executable":
        print(find_executable(args.build_jsonl))
    elif args.command == "summarize":
        markdown, report = summarize(args.output, args.rounds, args.candidate, args.baseline)
        if args.json is not None:
            args.json.write_text(json.dumps(report, indent=2) + "\n")
        print(markdown)
    else:
        self_test()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
