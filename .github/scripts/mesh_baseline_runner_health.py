#!/usr/bin/env python3
"""Capture machine-readable CPU-steal evidence for mesh baseline collection.

Pre-collection samples `vmstat` with a fixed literal argument vector and
averages the steal column into `runner_health.json`. Interval probes snapshot
aggregate `/proc/stat` CPU counters immediately before and after each selected
mesh Criterion bench and each HBONE or DNS workload, then record the finite
non-negative delta-steal/delta-total percent in `logs/runner_health_probes.jsonl`.
Those records are exact workload-interval evidence; they are not a short sample
of the preceding seconds.

Parse failures, missing samples, malformed state, and invalid thresholds are
emitted as invalid evidence (`avg_steal_percent: null`), never as 0.0%. A
real 0.0% steal remains valid. Steal above the documented threshold is a
warning here; the summarizer's publication gate is what fails closed on it.

This lives in an approved automation root instead of an inline workflow
heredoc so the collection workflow keeps a literal, reviewable command
surface. It is not an arbitrary-command executor: the only subprocess is the
literal pre-collection `vmstat` vector, and E2E probes read `/proc/stat`.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import tempfile
from pathlib import Path

DEFAULT_THRESHOLD_PERCENT = 5.0
STEAL_COLUMN = "st"
PRE_COLLECTION_SAMPLES_KEPT = 5
PROC_STAT_PATH = Path("/proc/stat")
WORKLOAD_INTERVAL_COVERAGE = "workload_interval"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument(
        "--phase",
        choices=("pre_collection", "mesh", "hbone", "dns"),
    )
    parser.add_argument("--scenario", default="")
    parser.add_argument("--repetition", type=int, default=None)
    parser.add_argument("--interval-begin", action="store_true")
    parser.add_argument("--interval-end", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return args
    if args.results_root is None or args.phase is None:
        parser.error("--results-root and --phase are required")
    if args.interval_begin and args.interval_end:
        parser.error("--interval-begin and --interval-end are mutually exclusive")
    if args.phase == "pre_collection":
        if args.interval_begin or args.interval_end:
            parser.error("pre_collection does not take interval snapshots")
        return args
    if args.repetition is None or args.repetition < 1:
        parser.error("--repetition must be a positive integer for E2E probes")
    if args.phase in ("hbone", "mesh") and not args.scenario:
        parser.error("--scenario is required for HBONE and mesh probes")
    if not args.interval_begin and not args.interval_end:
        parser.error("E2E probes require --interval-begin or --interval-end")
    return args


def sample_vmstat() -> tuple[str | None, str | None]:
    """Return (stdout, error). error is a material-free diagnostic on failure."""

    try:
        completed = subprocess.run(
            ["vmstat", "1", "6"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None, "vmstat pre-collection sample failed"
    if completed.returncode != 0:
        return None, "vmstat pre-collection sample failed"
    return completed.stdout, None


def steal_column_index(lines: list[str]) -> int | None:
    for line in lines[:2]:
        fields = line.split()
        if STEAL_COLUMN in fields:
            return fields.index(STEAL_COLUMN)
    return None


def data_rows(lines: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in lines:
        fields = line.split()
        if not fields:
            continue
        if not fields[0].lstrip("-").isdigit():
            continue
        rows.append(fields)
    return rows


def _parse_steal_value(raw: str) -> float | None:
    try:
        value = float(raw)
    except ValueError:
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return value


def average_steal_percent(output: str, kept: int) -> float | None:
    """Average retained vmstat steal samples, or None when evidence is invalid.

    Missing samples, too-short output, bad headers/row widths, and
    non-finite/negative values are invalid evidence. They must never become
    0.0%. A real measured 0.0% remains valid.
    """

    if kept <= 0:
        return None
    lines = output.splitlines()
    index = steal_column_index(lines)
    if index is None:
        return None
    rows = data_rows(lines)
    # The first sample is a since-boot average. Require that extra row so the
    # retained window is `kept` interval samples, never the since-boot line.
    if len(rows) < kept + 1:
        return None
    retained = rows[-kept:]
    values: list[float] = []
    for row in retained:
        if index >= len(row):
            return None
        value = _parse_steal_value(row[index])
        if value is None:
            return None
        values.append(value)
    if len(values) != kept:
        return None
    return float(f"{sum(values) / len(values):.1f}")


def threshold_percent() -> float | None:
    raw = os.environ.get("BENCH_MAX_CPU_STEAL_PERCENT", "")
    if not str(raw).strip():
        return DEFAULT_THRESHOLD_PERCENT
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return value


def parse_proc_stat_cpu(text: str) -> tuple[int, int] | None:
    """Return (steal, total) ticks from the aggregate `cpu` line."""

    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] != "cpu":
            continue
        if len(fields) < 9:
            return None
        try:
            counters = [int(field) for field in fields[1:9]]
        except ValueError:
            return None
        if any(value < 0 for value in counters):
            return None
        user, nice, system, idle, iowait, irq, softirq, steal = counters
        total = user + nice + system + idle + iowait + irq + softirq + steal
        if total <= 0:
            return None
        return steal, total
    return None


def read_proc_stat(path: Path = PROC_STAT_PATH) -> tuple[int, int] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return parse_proc_stat_cpu(text)


def steal_percent_from_delta(
    begin: tuple[int, int],
    end: tuple[int, int],
) -> tuple[float, int, int] | None:
    """Return (percent, delta_steal, delta_total) or None for invalid deltas."""

    begin_steal, begin_total = begin
    end_steal, end_total = end
    if begin_steal < 0 or begin_total <= 0 or end_steal < 0 or end_total <= 0:
        return None
    delta_steal = end_steal - begin_steal
    delta_total = end_total - begin_total
    if delta_total <= 0 or delta_steal < 0:
        return None
    percent = (delta_steal / delta_total) * 100.0
    if not math.isfinite(percent) or percent < 0:
        return None
    return float(f"{percent:.1f}"), delta_steal, delta_total


def interval_state_path(
    results_root: Path,
    phase: str,
    scenario: str,
    repetition: int,
) -> Path:
    safe_scenario = scenario.replace("/", "_") or "_"
    return (
        results_root
        / "logs"
        / "interval_snapshots"
        / f"{phase}__{safe_scenario}__{repetition}.json"
    )


def _load_json_object(path: Path) -> dict[str, object] | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _parse_counter(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0:
        return None
    return value


def write_pre_collection(
    results_root: Path,
    output: str,
    steal: float | None,
    threshold: float | None,
) -> dict[str, object]:
    logs_dir = results_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    (logs_dir / "vmstat_pre.txt").write_text(output, encoding="utf-8")
    health: dict[str, object] = {
        "runner_class": os.environ.get("BENCH_RUNNER_CLASS", "ubuntu-26.04"),
        "build_profile": os.environ.get("BENCH_BUILD_PROFILE", "release"),
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "avg_steal_percent": steal,
        "threshold_percent": threshold,
        "nproc": os.cpu_count(),
        "phase": "pre_collection",
    }
    (results_root / "runner_health.json").write_text(
        json.dumps(health, indent=2) + "\n",
        encoding="utf-8",
    )
    steal_display = "invalid" if steal is None else f"{steal}%"
    (logs_dir / "runner_health.log").write_text(
        "\n".join(
            (
                "==========================================",
                "  RUNNER HEALTH - MESH BASELINE COLLECTION",
                "==========================================",
                f"runner_class={health['runner_class']}",
                f"build_profile={health['build_profile']}",
                f"max_cpu_steal_percent={threshold}",
                f"commit={health['commit_sha']}",
                "",
                output.rstrip(),
                "",
                f"Average CPU steal over {PRE_COLLECTION_SAMPLES_KEPT}s: {steal_display}",
                json.dumps(health, indent=2),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    return health


def write_probe(results_root: Path, probe: dict[str, object]) -> dict[str, object]:
    logs_dir = results_root / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    probes_path = logs_dir / "runner_health_probes.jsonl"
    with probes_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(probe) + "\n")
    return probe


def interval_begin(
    results_root: Path,
    phase: str,
    scenario: str,
    repetition: int,
    counters: tuple[int, int] | None,
) -> tuple[dict[str, object], int]:
    path = interval_state_path(results_root, phase, scenario, repetition)
    path.parent.mkdir(parents=True, exist_ok=True)
    identity = {
        "phase": phase,
        "scenario": scenario,
        "repetition": repetition,
    }
    if path.is_file():
        payload: dict[str, object] = {**identity, "error": "duplicate_begin"}
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        return payload, 1
    if counters is None:
        payload = {**identity, "error": "proc_stat_unreadable"}
        path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        return payload, 1
    steal, total = counters
    payload = {**identity, "steal": steal, "total": total}
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    return payload, 0


def interval_end(
    results_root: Path,
    phase: str,
    scenario: str,
    repetition: int,
    end_counters: tuple[int, int] | None,
    threshold: float | None,
) -> dict[str, object]:
    path = interval_state_path(results_root, phase, scenario, repetition)
    begin_state = _load_json_object(path) if path.is_file() else None
    if path.is_file():
        try:
            path.unlink()
        except OSError:
            pass

    steal: float | None = None
    delta_steal: int | None = None
    delta_total: int | None = None
    error: str | None = None
    if not isinstance(begin_state, dict):
        error = "missing_begin"
    elif isinstance(begin_state.get("error"), str) and begin_state["error"]:
        error = str(begin_state["error"])
    elif (
        begin_state.get("phase") != phase
        or begin_state.get("scenario") != scenario
        or begin_state.get("repetition") != repetition
    ):
        error = "mismatched_identity"
    elif end_counters is None:
        error = "proc_stat_unreadable"
    else:
        begin_steal = _parse_counter(begin_state.get("steal"))
        begin_total = _parse_counter(begin_state.get("total"))
        if begin_steal is None or begin_total is None:
            error = "malformed_begin_state"
        else:
            delta = steal_percent_from_delta((begin_steal, begin_total), end_counters)
            if delta is None:
                error = "invalid_delta"
            else:
                steal, delta_steal, delta_total = delta

    if threshold is None:
        steal = None
        coverage = None
        error = error or "invalid_threshold"
    elif steal is None:
        coverage = None
    else:
        coverage = WORKLOAD_INTERVAL_COVERAGE

    probe: dict[str, object] = {
        "phase": phase,
        "repetition": repetition,
        "avg_steal_percent": steal,
        "threshold_percent": threshold,
        "coverage": coverage,
        "source": "proc_stat_delta",
    }
    if phase in ("hbone", "mesh"):
        probe["scenario"] = scenario
    if error is not None:
        probe["error"] = error
    if delta_steal is not None and delta_total is not None:
        probe["delta_steal"] = delta_steal
        probe["delta_total"] = delta_total
    return write_probe(results_root, probe)


def _warn_if_excessive(
    label: str,
    steal: float | None,
    threshold: float | None,
) -> None:
    if steal is None or threshold is None:
        return
    if steal > threshold:
        print(
            f"::warning::{label}: CPU steal {steal}% (> {threshold}%) "
            "— publication gate will fail closed"
        )


def _vmstat_fixture(*, steal_values: list[str], header: bool = True) -> str:
    lines = []
    if header:
        lines.append(
            "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----"
        )
        lines.append(
            " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st"
        )
    # Leading since-boot row is discarded by the retained-window tail.
    rows = ["0"] + list(steal_values)
    for steal in rows:
        lines.append(
            f" 1  0      0 123456  12345 678901    0    0     0     0  100  200  1  0 99  0 {steal}"
        )
    return "\n".join(lines) + "\n"


def self_test() -> int:
    empty = average_steal_percent("", PRE_COLLECTION_SAMPLES_KEPT)
    # parse failure cannot become healthy evidence
    assert empty is None
    assert empty != 0.0
    assert average_steal_percent("header only\n", 5) is None
    assert average_steal_percent(_vmstat_fixture(steal_values=["0"] * 4), 5) is None
    assert average_steal_percent(_vmstat_fixture(steal_values=["0"] * 5, header=False), 5) is None
    short_lines = _vmstat_fixture(steal_values=["0"] * 5).splitlines()
    short_lines[-1] = " 1  0 0"
    assert average_steal_percent("\n".join(short_lines) + "\n", 5) is None
    assert average_steal_percent(_vmstat_fixture(steal_values=["0", "0", "0", "0", "nan"]), 5) is None
    assert average_steal_percent(_vmstat_fixture(steal_values=["0", "0", "0", "0", "-1"]), 5) is None
    assert average_steal_percent(_vmstat_fixture(steal_values=["0", "0", "0", "0", "inf"]), 5) is None
    zero = average_steal_percent(_vmstat_fixture(steal_values=["0"] * 5), 5)
    assert zero == 0.0
    assert average_steal_percent(_vmstat_fixture(steal_values=["1", "2", "3", "4", "5"]), 5) == 3.0

    assert parse_proc_stat_cpu("cpu0 1 2 3 4 5 6 7 8\n") is None
    assert parse_proc_stat_cpu("cpu 1 2 3\n") is None
    assert parse_proc_stat_cpu("cpu 1 2 3 4 5 6 7 -1\n") is None
    assert parse_proc_stat_cpu("cpu 1 2 3 4 5 6 7 x\n") is None
    assert parse_proc_stat_cpu("cpu 0 0 0 0 0 0 0 0\n") is None
    assert parse_proc_stat_cpu("cpu 100 0 100 800 0 0 0 0 0 0\n") == (0, 1000)

    begin = (10, 1000)
    end = (12, 1100)
    # successful exact-interval evidence
    delta = steal_percent_from_delta(begin, end)
    assert delta == (2.0, 2, 100)
    zero_interval = steal_percent_from_delta((10, 1000), (10, 1100))
    assert zero_interval == (0.0, 0, 100)
    assert steal_percent_from_delta((10, 1000), (10, 1000)) is None
    assert steal_percent_from_delta((10, 1000), (9, 1100)) is None
    assert steal_percent_from_delta((10, 1000), (20, 900)) is None

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        record, status = interval_begin(root, "dns", "", 1, (10, 1000))
        assert status == 0
        assert record["steal"] == 10
        duplicate, dup_status = interval_begin(root, "dns", "", 1, (11, 1001))
        assert dup_status == 1
        assert duplicate["error"] == "duplicate_begin"
        poisoned = interval_end(root, "dns", "", 1, (12, 1100), 5.0)
        assert poisoned["avg_steal_percent"] is None
        assert poisoned["coverage"] is None
        assert poisoned["error"] == "duplicate_begin"

        record, status = interval_begin(root, "hbone", "1kib_c50_30s", 1, (10, 1000))
        assert status == 0
        probe = interval_end(root, "hbone", "1kib_c50_30s", 1, (12, 1100), 5.0)
        assert probe["avg_steal_percent"] == 2.0
        assert probe["coverage"] == WORKLOAD_INTERVAL_COVERAGE
        assert probe["delta_steal"] == 2
        assert probe["delta_total"] == 100
        assert probe["scenario"] == "1kib_c50_30s"

        record, status = interval_begin(root, "mesh", "authz_match", 1, (10, 1000))
        assert status == 0
        mesh_probe = interval_end(root, "mesh", "authz_match", 1, (12, 1100), 5.0)
        assert mesh_probe["avg_steal_percent"] == 2.0
        assert mesh_probe["coverage"] == WORKLOAD_INTERVAL_COVERAGE
        assert mesh_probe["scenario"] == "authz_match"

        # end-without-start evidence
        missing = interval_end(root, "dns", "", 2, (12, 1100), 5.0)
        assert missing["avg_steal_percent"] is None
        assert missing["error"] == "missing_begin"
        assert missing["coverage"] is None

        record, status = interval_begin(root, "dns", "", 3, (10, 1000))
        assert status == 0
        state_path = interval_state_path(root, "dns", "", 3)
        tampered = json.loads(state_path.read_text(encoding="utf-8"))
        tampered["phase"] = "hbone"
        state_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
        mismatched = interval_end(root, "dns", "", 3, (12, 1100), 5.0)
        assert mismatched["error"] == "mismatched_identity"
        assert mismatched["avg_steal_percent"] is None

        record, status = interval_begin(root, "dns", "", 4, (10, 1000))
        assert status == 0
        invalid_delta = interval_end(root, "dns", "", 4, (10, 1000), 5.0)
        assert invalid_delta["avg_steal_percent"] is None
        assert invalid_delta["error"] == "invalid_delta"

        record, status = interval_begin(root, "dns", "", 5, None)
        assert status == 1
        unread = interval_end(root, "dns", "", 5, (12, 1100), 5.0)
        assert unread["avg_steal_percent"] is None

        record, status = interval_begin(root, "dns", "", 6, (10, 1000))
        assert status == 0
        invalid_threshold = interval_end(root, "dns", "", 6, (12, 1100), None)
        assert invalid_threshold["avg_steal_percent"] is None
        assert invalid_threshold["error"] == "invalid_threshold"

        record, status = interval_begin(root, "dns", "", 7, (10, 1000))
        assert status == 0
        # excessive steal
        excessive = interval_end(root, "dns", "", 7, (80, 1100), 5.0)
        assert excessive["avg_steal_percent"] == 70.0
        assert excessive["coverage"] == WORKLOAD_INTERVAL_COVERAGE

        zero_probe_begin, status = interval_begin(root, "dns", "", 8, (10, 1000))
        assert status == 0
        assert zero_probe_begin["steal"] == 10
        zero_probe = interval_end(root, "dns", "", 8, (10, 1100), 5.0)
        assert zero_probe["avg_steal_percent"] == 0.0
        assert zero_probe["coverage"] == WORKLOAD_INTERVAL_COVERAGE

        health = write_pre_collection(root, _vmstat_fixture(steal_values=["0"] * 5), None, 5.0)
        assert health["avg_steal_percent"] is None
        parsed = json.loads((root / "runner_health.json").read_text(encoding="utf-8"))
        assert parsed["avg_steal_percent"] is None

    print("mesh_baseline_runner_health self-test passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()

    threshold = threshold_percent()
    if args.phase == "pre_collection":
        output, vmstat_error = sample_vmstat()
        steal = (
            None
            if output is None
            else average_steal_percent(output, PRE_COLLECTION_SAMPLES_KEPT)
        )
        if threshold is None:
            steal = None
        record = write_pre_collection(
            args.results_root,
            output or "",
            steal,
            threshold,
        )
        print(json.dumps(record, indent=2))
        if vmstat_error is not None:
            print(f"::error::{vmstat_error}")
            return 1
        _warn_if_excessive("pre-collection", steal, threshold)
        return 0

    if args.interval_begin:
        record, status = interval_begin(
            args.results_root,
            args.phase,
            args.scenario,
            args.repetition,
            read_proc_stat(),
        )
        print(json.dumps(record, indent=2))
        return status

    record = interval_end(
        args.results_root,
        args.phase,
        args.scenario,
        args.repetition,
        read_proc_stat(),
        threshold,
    )
    print(json.dumps(record, indent=2))
    label = f"{args.phase} {args.scenario} run {args.repetition}".replace("  ", " ")
    steal = record.get("avg_steal_percent")
    steal_value = steal if isinstance(steal, (int, float)) and not isinstance(steal, bool) else None
    if steal_value is not None:
        steal_value = float(steal_value)
        if not math.isfinite(steal_value):
            steal_value = None
    _warn_if_excessive(label, steal_value, threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
