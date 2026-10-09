#!/usr/bin/env python3
"""Summarize hosted mesh/HBONE/DNS baseline artifacts into machine-readable JSON.

Reads Criterion estimates.json trees and E2E JSON blobs produced by the
mesh-performance-baselines workflow. Never fabricates measurements: missing
inputs become explicit null/incomplete entries. Publication gates fail closed
on undersampling, missing DNS rows, malformed metrics, nonzero errors,
nonzero DNS NXDOMAIN counts (kept as a distinct ``total_nxdomain`` counter,
never folded into ``total_errors``), unexpected target identities, unsupported
suite filters, missing or invalid workload-interval CPU-steal evidence
(including each selected mesh Criterion bench window), or excessive CPU steal.
Repetition evidence counts distinct expected run_N.txt executions with exactly
one valid gateway/direct identity each — duplicate or partial blobs in a single
file do not satisfy the repetition gate.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


AUTHZ_SIZES = (10, 100, 1_000, 10_000)
SLICE_SIZES = (100, 1_000, 5_000)
IP_CASES = (
    ("deny_miss", 1),
    ("deny_miss", 4),
    ("high_match", 1),
    ("high_match", 4),
)
HBONE_SCENARIOS = (
    {"key": "1kib_c50_30s", "payload": 1024, "concurrency": 50, "duration": 30},
    {"key": "16kib_c50_30s", "payload": 16384, "concurrency": 50, "duration": 30},
    {"key": "256kib_c100_60s", "payload": 262144, "concurrency": 100, "duration": 60},
)
DNS_GATEWAY_ROWS = (
    ("mesh-internal", "udp"),
    ("mesh-internal", "tcp"),
    ("mesh-wildcard", "udp"),
    ("mesh-wildcard", "tcp"),
    ("upstream-forward", "udp"),
    ("upstream-forward", "tcp"),
)
DNS_DIRECT_ROWS = (
    ("upstream-forward", "udp"),
    ("upstream-forward", "tcp"),
)
MIN_E2E_REPETITIONS = 3
# Documented publication threshold: same 5.0% CPU-steal ceiling used across
# Ferrum hosted perf workflows. Collections above this are not publication-ready.
MAX_CPU_STEAL_PERCENT = 5.0
SUPPORTED_SUITES = frozenset({"all", "mesh", "hbone", "dns"})
MESH_BENCHES = ("authz_match", "ip_restriction", "slice_apply", "xds_translation")
DNS_GATEWAY_TARGET = "127.0.0.1:15053"
DNS_DIRECT_TARGET = "127.0.0.1:17053"
DNS_CONCURRENCY = 100
DNS_DURATION_SECS = 60
HBONE_GATEWAY_PORT = 18_000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--draft-markdown-dir", type=Path)
    parser.add_argument(
        "--expected-repetitions",
        type=int,
        default=None,
        help="Configured E2E repetition count (floored at 3)",
    )
    parser.add_argument(
        "--suites",
        default="all",
        help="Selected suite filter: all | mesh | hbone | dns",
    )
    parser.add_argument(
        "--check-acceptance",
        action="store_true",
        help="Exit non-zero when selected-suite publication gates fail",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        help="Existing summary.json path for --check-acceptance",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.check_acceptance:
        if args.summary is None:
            parser.error("--check-acceptance requires --summary")
        return args
    if not args.self_test:
        missing = [
            name
            for name in (
                "results_root",
                "provenance",
                "output",
                "draft_markdown_dir",
            )
            if getattr(args, name) is None
        ]
        if missing:
            parser.error(
                "the following arguments are required unless --self-test: "
                + ", ".join(f"--{name.replace('_', '-')}" for name in missing)
            )
    return args


def required_repetitions(configured: int | None) -> int:
    if configured is None:
        return MIN_E2E_REPETITIONS
    return max(MIN_E2E_REPETITIONS, int(configured))


def normalize_suites(suites: str | None) -> str | None:
    """Return a supported suite filter, or None when the value is unsupported."""
    value = (suites or "").strip().lower()
    if value not in SUPPORTED_SUITES:
        return None
    return value


def suites_supported(suites: str | None) -> bool:
    return normalize_suites(suites) is not None


def _present_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not value.lstrip().startswith("<unavailable:")
    )


def provenance_complete(
    provenance: dict[str, Any],
    suites: str,
    required_reps: int,
) -> bool:
    """Require the issue's minimum reproducibility evidence before acceptance."""
    normalized = normalize_suites(suites)
    if normalized is None or provenance.get("schema_version") != 1:
        return False
    commit_sha = provenance.get("commit_sha")
    if (
        not isinstance(commit_sha, str)
        or len(commit_sha) != 40
        or any(char not in "0123456789abcdefABCDEF" for char in commit_sha)
        or not _present_text(provenance.get("collected_at_utc"))
    ):
        return False

    github = provenance.get("github")
    runner = provenance.get("runner")
    toolchain = provenance.get("toolchain")
    build = provenance.get("build")
    dependencies = provenance.get("dependency_harness_versions")
    repetitions = provenance.get("warmup_and_repetitions")
    formulas = provenance.get("overhead_formula")
    if not all(
        isinstance(section, dict)
        for section in (github, runner, toolchain, build, dependencies, repetitions, formulas)
    ):
        return False
    if not all(
        _present_text(github.get(key))
        for key in ("run_id", "run_attempt", "workflow", "job", "repository", "ref", "server_url")
    ):
        return False
    if not all(
        _present_text(runner.get(key))
        for key in ("class", "name", "os", "arch", "cpu_model", "lscpu_raw", "uname", "kernel")
    ):
        return False
    if runner.get("class") != "ubuntu-26.04":
        return False
    nproc = parse_non_negative_int(runner.get("nproc"))
    topology = runner.get("cpu_topology")
    ram = runner.get("ram")
    if (
        nproc is None
        or nproc < 1
        or not isinstance(topology, dict)
        or not all(
            _present_text(topology.get(key))
            for key in ("cpus", "threads_per_core", "cores_per_socket", "sockets")
        )
        or not isinstance(ram, dict)
        or (parse_non_negative_int(ram.get("memtotal_kib")) or 0) < 1
    ):
        return False
    if not all(
        _present_text(toolchain.get(key))
        for key in ("rustc_verbose", "cargo_verbose", "rust_toolchain_file")
    ):
        return False
    if not all(
        _present_text(build.get(key))
        for key in ("gateway_profile", "gateway_features", "harness_profile", "non_default_settings_note")
    ):
        return False
    if (
        build.get("gateway_profile") != "release"
        or build.get("harness_profile") != "release"
    ):
        return False
    if not all(
        _present_text(dependencies.get(key))
        for key in (
            "mesh_criterion",
            "mesh_crate",
            "hbone_crate",
            "dns_crate",
            "hdrhistogram_hbone",
            "hdrhistogram_dns",
        )
    ):
        return False
    if (
        not _present_text(repetitions.get("mesh_microbench"))
        or parse_non_negative_int(repetitions.get("e2e_repetitions")) != required_reps
        or not _present_text(repetitions.get("e2e_policy"))
        or not all(
            _present_text(formulas.get(key))
            for key in (
                "hbone_rps_overhead_percent",
                "dns_upstream_forward_overhead_percent",
                "notes",
            )
        )
    ):
        return False

    selected = {"mesh", "hbone", "dns"} if normalized == "all" else {normalized}
    expected_counts = {
        "mesh": 4,
        "hbone": 1 + len(HBONE_SCENARIOS) * required_reps,
        "dns": 1 + required_reps,
    }
    actual_counts = {suite: 0 for suite in selected}
    commands = provenance.get("suite_commands")
    if not isinstance(commands, list):
        return False
    for command in commands:
        if not isinstance(command, dict):
            return False
        suite = command.get("suite")
        if (
            not isinstance(suite, str)
            or suite not in selected
            or not _present_text(command.get("command"))
        ):
            return False
        actual_counts[suite] += 1
    return actual_counts == {suite: expected_counts[suite] for suite in selected}


def expected_run_paths(root: Path, required_reps: int) -> list[Path]:
    """Distinct expected execution artifacts: run_1.txt .. run_N.txt."""
    return [root / f"run_{idx}.txt" for idx in range(1, required_reps + 1)]


def unexpected_run_paths(root: Path, required_reps: int) -> list[Path]:
    """Return extra/misnumbered run artifacts that conflict with the ledger."""
    expected = set(expected_run_paths(root, required_reps))
    return sorted(
        path
        for path in root.glob("run_*.txt")
        if path.is_file() and path not in expected
    )


def load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def fmt_duration_ns(ns: float) -> str:
    if not math.isfinite(ns) or ns < 0:
        return "n/a"
    if ns >= 1_000_000_000:
        return f"{ns / 1_000_000_000:.3f} s"
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.3f} ms"
    if ns >= 1_000:
        return f"{ns / 1_000:.3f} µs"
    return f"{ns:.1f} ns"


def fmt_us(us: float | int | None) -> str:
    if us is None:
        return "n/a"
    try:
        us_f = float(us)
    except (TypeError, ValueError):
        return "n/a"
    if not math.isfinite(us_f):
        return "n/a"
    if us_f >= 1_000_000:
        return f"{us_f / 1_000_000:.2f}s"
    if us_f >= 1_000:
        return f"{us_f / 1_000:.2f}ms"
    return f"{us_f:.0f}µs"


def fmt_rps(v: float | None) -> str:
    if v is None:
        return "n/a"
    if not math.isfinite(v):
        return "n/a"
    return f"{v:,.0f}"


def fmt_pct(v: float | None) -> str:
    if v is None:
        return "n/a"
    if not math.isfinite(v):
        return "n/a"
    return f"{v:.1f}%"


def mean_stdev(values: list[float]) -> tuple[float | None, float | None, float | None, float | None]:
    if not values:
        return None, None, None, None
    mean_v = statistics.mean(values)
    stdev_v = statistics.stdev(values) if len(values) > 1 else 0.0
    return mean_v, stdev_v, min(values), max(values)


def parse_finite_number(value: Any, *, positive: bool = False, non_negative: bool = False) -> float | None:
    """Parse a finite number; reject bools, strings that coerce poorly, NaN/Inf."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    if positive and number <= 0:
        return None
    if non_negative and number < 0:
        return None
    return number


def parse_non_negative_int(value: Any) -> int | None:
    number = parse_finite_number(value, non_negative=True)
    if number is None:
        return None
    if abs(number - round(number)) > 1e-9:
        return None
    return int(round(number))


def criterion_mean(path: Path) -> dict[str, Any] | None:
    data = load_json(path)
    if not isinstance(data, dict):
        return None
    mean = data.get("mean")
    std_dev = data.get("std_dev")
    if not isinstance(mean, dict):
        return None
    if std_dev is not None and not isinstance(std_dev, dict):
        return None
    point = parse_finite_number(mean.get("point_estimate"), positive=True)
    if point is None:
        return None
    ci = mean.get("confidence_interval")
    if ci is not None and not isinstance(ci, dict):
        return None
    ci = ci or {}
    lower = parse_finite_number(ci.get("lower_bound", point), non_negative=True)
    upper = parse_finite_number(ci.get("upper_bound", point), non_negative=True)
    stdev = parse_finite_number(
        (std_dev or {}).get("point_estimate", 0.0),
        non_negative=True,
    )
    if lower is None or upper is None or stdev is None:
        return None
    return {
        "mean_ns": point,
        "stdev_ns": stdev,
        "ci_lower_ns": lower,
        "ci_upper_ns": upper,
        "mean_display": fmt_duration_ns(point),
        "stdev_display": fmt_duration_ns(stdev),
        "source": str(path),
    }


def hbone_text_looks_relevant(fragment: str) -> bool:
    """Heuristic for syntactically broken top-level HBONE record candidates."""
    return (
        "hbone_e2e" in fragment
        or '"rps"' in fragment
        or '"target"' in fragment
        or '"label"' in fragment
    )


def dns_text_looks_relevant(fragment: str) -> bool:
    """Heuristic for syntactically broken top-level DNS record candidates."""
    return '"reports"' in fragment and '"target"' in fragment


def _malformed_top_level_record_end(text: str, start: int) -> int:
    """Exclusive end of a top-level ``{`` record that failed JSON decode."""
    i = start + 1
    while i < len(text):
        if text[i] == "\n":
            j = i + 1
            while j < len(text) and text[j] in " \t\r":
                j += 1
            if j < len(text) and text[j] == "{":
                return j
        i += 1
    return len(text)


def extract_json_blobs(text: str, *, suite: str | None = None) -> tuple[list[Any], int]:
    """Extract top-level JSON objects; count syntactically broken relevant candidates.

    Pretty-printed harness output is one top-level object per record. When
    ``suite`` is ``hbone`` or ``dns``, a ``{`` that begins a fragment matching
    that suite's relevance markers but cannot be ``raw_decode``d is counted as a
    malformed relevant candidate (fail closed). Unrelated brace-bearing log
    lines are skipped without advancing the malformed counter.
    """
    decoder = json.JSONDecoder()
    blobs: list[Any] = []
    malformed_relevant = 0
    relevance_check = None
    if suite == "hbone":
        relevance_check = hbone_text_looks_relevant
    elif suite == "dns":
        relevance_check = dns_text_looks_relevant

    i = 0
    while i < len(text):
        idx = text.find("{", i)
        if idx == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
            blobs.append(obj)
            i = end
        except json.JSONDecodeError:
            if relevance_check is not None:
                end = _malformed_top_level_record_end(text, idx)
                fragment = text[idx:end]
                if relevance_check(fragment):
                    malformed_relevant += 1
                    i = end
                    continue
            i = idx + 1
    return blobs, malformed_relevant


def summarize_mesh(criterion_root: Path) -> dict[str, Any]:
    authz = {}
    for size in AUTHZ_SIZES:
        estimates = (
            criterion_root
            / "authz_match"
            / "policies"
            / str(size)
            / "new"
            / "estimates.json"
        )
        authz[str(size)] = criterion_mean(estimates)

    ip_rows = {}
    for decision, instances in IP_CASES:
        key = f"{decision}_{instances}"
        estimates = (
            criterion_root
            / "ip_restriction_lookup"
            / f"{decision}_10000_rules_{instances}_instances"
            / "new"
            / "estimates.json"
        )
        ip_rows[key] = criterion_mean(estimates)

    slice_rows = {}
    for size in SLICE_SIZES:
        estimates = (
            criterion_root
            / "slice_apply"
            / "workloads"
            / str(size)
            / "new"
            / "estimates.json"
        )
        slice_rows[str(size)] = criterion_mean(estimates)

    xds_rows = {}
    for size in SLICE_SIZES:
        estimates = (
            criterion_root
            / "xds_translation"
            / "workloads"
            / str(size)
            / "new"
            / "estimates.json"
        )
        xds_rows[str(size)] = criterion_mean(estimates)

    return {
        "authz_match": authz,
        "ip_restriction": ip_rows,
        "slice_apply": slice_rows,
        "xds_translation": xds_rows,
    }


def hbone_blob_looks_relevant(blob: dict[str, Any]) -> bool:
    return "rps" in blob or "target" in blob or "label" in blob


def classify_hbone_blob(blob: dict[str, Any]) -> str | None:
    """Map an actual hbone_loadgen blob to gateway/direct by exact target shape.

    The harness emits the fixed ``hbone_e2e`` label for BOTH phases. Gateway
    identity is the exact loopback HTTP ``/echo`` target on port 18000; the
    direct phase uses the same shape with the backend's non-18000 ephemeral
    port. Synthetic semantic labels are not evidence of what the harness ran,
    and ambiguous or unexpected targets fail closed (return None).
    """
    if blob.get("label") != "hbone_e2e":
        return None
    target = blob.get("target")
    if not isinstance(target, str):
        return None
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or port is None
        or parsed.path != "/echo"
        or parsed.query
        or parsed.fragment
    ):
        return None
    if port == HBONE_GATEWAY_PORT:
        return "gateway"
    if 1 <= port <= 65_535:
        return "direct"
    return None


def classify_dns_target(target: str) -> str | None:
    """Map the exact harness socket identities; lookalikes fail closed."""
    if target == DNS_GATEWAY_TARGET:
        return "gateway"
    if target == DNS_DIRECT_TARGET:
        return "direct"
    return None


def parse_hbone_sample(
    blob: dict[str, Any],
    source: str,
    scenario: dict[str, Any],
) -> dict[str, Any] | None:
    """Fail closed on malformed / non-finite / non-positive HBONE metrics."""
    if "rps" not in blob:
        return None
    rps = parse_finite_number(blob.get("rps"), positive=True)
    p50 = parse_finite_number(blob.get("p50_us"), non_negative=True)
    p95 = parse_finite_number(blob.get("p95_us"), non_negative=True)
    p99 = parse_finite_number(blob.get("p99_us"), non_negative=True)
    if "total_errors" not in blob:
        return None
    errors = parse_non_negative_int(blob.get("total_errors"))
    concurrency = parse_non_negative_int(blob.get("concurrency"))
    duration_secs = parse_non_negative_int(blob.get("duration_secs"))
    payload_size = parse_non_negative_int(blob.get("payload_size"))
    if None in (rps, p50, p95, p99, errors, concurrency, duration_secs, payload_size):
        return None
    if (
        concurrency != scenario["concurrency"]
        or duration_secs != scenario["duration"]
        or payload_size != scenario["payload"]
    ):
        return None
    kind = classify_hbone_blob(blob)
    if kind is None:
        return None
    return {
        "kind": kind,
        "rps": rps,
        "p50_us": p50,
        "p95_us": p95,
        "p99_us": p99,
        "total_errors": errors,
        "source": source,
    }


def parse_dns_report(
    report: dict[str, Any],
    source: str,
    expected_duration_secs: int,
) -> dict[str, Any] | None:
    """Fail closed on malformed / non-finite / non-positive DNS report rows."""
    class_name = report.get("name_class")
    transport = report.get("transport")
    if not isinstance(class_name, str) or not class_name:
        return None
    if not isinstance(transport, str) or not transport:
        return None
    qps = parse_finite_number(report.get("qps"), positive=True)
    p50 = parse_finite_number(report.get("p50_us"), non_negative=True)
    p90 = parse_finite_number(report.get("p90_us"), non_negative=True)
    p99 = parse_finite_number(report.get("p99_us"), non_negative=True)
    if "total_errors" not in report:
        return None
    if "total_nxdomain" not in report:
        return None
    errors = parse_non_negative_int(report.get("total_errors"))
    nxdomain = parse_non_negative_int(report.get("total_nxdomain"))
    duration_secs = parse_non_negative_int(report.get("duration_secs"))
    if None in (qps, p50, p90, p99, errors, nxdomain, duration_secs):
        return None
    if duration_secs != expected_duration_secs:
        return None
    return {
        "name_class": class_name,
        "transport": transport,
        "qps": qps,
        "p50_us": p50,
        "p95_us": p90,  # retained for draft compatibility naming
        "p90_us": p90,
        "p99_us": p99,
        "total_errors": errors,
        "total_nxdomain": nxdomain,
        "source": source,
    }


def aggregate_throughput_samples(
    samples: list[dict[str, Any]],
    *,
    rate_key: str,
    latency_keys: tuple[str, ...],
) -> dict[str, Any] | None:
    if not samples:
        return None
    rate_vals = [s[rate_key] for s in samples]
    mean_rate, stdev_rate, min_rate, max_rate = mean_stdev(rate_vals)
    out: dict[str, Any] = {
        "repetitions": len(samples),
        f"{rate_key}_mean": mean_rate,
        f"{rate_key}_stdev": stdev_rate,
        f"{rate_key}_min": min_rate,
        f"{rate_key}_max": max_rate,
        "total_errors_sum": sum(s["total_errors"] for s in samples),
        "samples": samples,
    }
    for key in latency_keys:
        out[f"{key}_mean"] = statistics.mean(s[key] for s in samples)
    return out


def repetition_evidence(actual: int, required: int) -> dict[str, Any]:
    return {
        "actual": actual,
        "required": required,
        "ok": actual >= required,
    }


def summarize_hbone(hbone_root: Path, required_reps: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for scenario in HBONE_SCENARIOS:
        key = scenario["key"]
        scenario_dir = hbone_root / key
        gateway_samples: list[dict[str, Any]] = []
        direct_samples: list[dict[str, Any]] = []
        unexpected_runs = unexpected_run_paths(scenario_dir, required_reps)
        rejected = len(unexpected_runs)
        shape_failures = len(unexpected_runs)
        for run_path in expected_run_paths(scenario_dir, required_reps):
            if not run_path.is_file():
                shape_failures += 1
                continue
            text = run_path.read_text(encoding="utf-8", errors="replace")
            gateway_for_run: list[dict[str, Any]] = []
            direct_for_run: list[dict[str, Any]] = []
            run_rejected = 0
            blobs, malformed_relevant = extract_json_blobs(text, suite="hbone")
            run_rejected += malformed_relevant
            for blob in blobs:
                if not isinstance(blob, dict):
                    continue
                if not hbone_blob_looks_relevant(blob):
                    continue
                sample = parse_hbone_sample(blob, str(run_path), scenario)
                if sample is None:
                    run_rejected += 1
                    continue
                kind = sample.pop("kind")
                if kind == "gateway":
                    gateway_for_run.append(sample)
                else:
                    direct_for_run.append(sample)
            # Exactly one gateway + one direct identity per expected execution.
            if (
                run_rejected
                or len(gateway_for_run) != 1
                or len(direct_for_run) != 1
            ):
                rejected += run_rejected
                if len(gateway_for_run) != 1:
                    rejected += max(len(gateway_for_run), 1) if gateway_for_run else 1
                if len(direct_for_run) != 1:
                    rejected += max(len(direct_for_run), 1) if direct_for_run else 1
                shape_failures += 1
                continue
            gateway_samples.append(gateway_for_run[0])
            direct_samples.append(direct_for_run[0])

        gateway = aggregate_throughput_samples(
            gateway_samples,
            rate_key="rps",
            latency_keys=("p50_us", "p95_us", "p99_us"),
        )
        direct = aggregate_throughput_samples(
            direct_samples,
            rate_key="rps",
            latency_keys=("p50_us", "p95_us", "p99_us"),
        )
        gateway_reps = len(gateway_samples)
        direct_reps = len(direct_samples)
        gateway_evidence = repetition_evidence(gateway_reps, required_reps)
        direct_evidence = repetition_evidence(direct_reps, required_reps)
        overhead = None
        if (
            gateway
            and direct
            and gateway["rps_mean"] is not None
            and direct["rps_mean"] is not None
            and direct["rps_mean"] > 0
            and math.isfinite(gateway["rps_mean"])
            and math.isfinite(direct["rps_mean"])
        ):
            overhead = (
                (direct["rps_mean"] - gateway["rps_mean"]) / direct["rps_mean"]
            ) * 100.0
        complete = (
            gateway_evidence["ok"]
            and direct_evidence["ok"]
            and shape_failures == 0
            and rejected == 0
            and gateway_reps == required_reps
            and direct_reps == required_reps
        )
        errors_ok = bool(
            complete
            and gateway
            and direct
            and gateway["total_errors_sum"] == 0
            and direct["total_errors_sum"] == 0
        )
        out[key] = {
            "scenario": scenario,
            "gateway": gateway,
            "direct": direct,
            "overhead_percent_mean": overhead,
            "complete": complete,
            "errors_ok": errors_ok,
            "rejected_blobs": rejected,
            "shape_failures": shape_failures,
            "repetition_evidence": {
                "required": required_reps,
                "gateway": gateway_evidence,
                "direct": direct_evidence,
            },
        }
    return out


def _parse_dns_blob_rows(
    blob: dict[str, Any],
    source: str,
    expected_keys: set[tuple[str, str]],
) -> tuple[dict[tuple[str, str], dict[str, Any]] | None, int]:
    """Parse one DNS identity blob; None means malformed/conflicting shape."""
    concurrency = parse_non_negative_int(blob.get("concurrency"))
    duration_secs = parse_non_negative_int(blob.get("duration_secs"))
    reports = blob.get("reports")
    if (
        concurrency != DNS_CONCURRENCY
        or duration_secs != DNS_DURATION_SECS
        or not isinstance(reports, list)
    ):
        return None, 1
    parsed: dict[tuple[str, str], dict[str, Any]] = {}
    rejected = 0
    for report in reports:
        if not isinstance(report, dict):
            rejected += 1
            continue
        sample = parse_dns_report(report, source, DNS_DURATION_SECS)
        if sample is None:
            rejected += 1
            continue
        key = (sample["name_class"], sample["transport"])
        if key in parsed:
            rejected += 1
            continue
        parsed[key] = {
            "qps": sample["qps"],
            "p50_us": sample["p50_us"],
            "p90_us": sample["p90_us"],
            "p99_us": sample["p99_us"],
            "total_errors": sample["total_errors"],
            "total_nxdomain": sample["total_nxdomain"],
            "source": sample["source"],
        }
    if rejected or set(parsed.keys()) != expected_keys:
        return None, rejected + (0 if set(parsed.keys()) == expected_keys else 1)
    return parsed, 0


def summarize_dns(dns_root: Path, required_reps: int) -> dict[str, Any]:
    gateway_rows: dict[tuple[str, str], list[dict[str, Any]]] = {
        key: [] for key in DNS_GATEWAY_ROWS
    }
    direct_rows: dict[tuple[str, str], list[dict[str, Any]]] = {
        key: [] for key in DNS_DIRECT_ROWS
    }
    unexpected_runs = unexpected_run_paths(dns_root, required_reps)
    rejected = len(unexpected_runs)
    shape_failures = len(unexpected_runs)
    gateway_keys = set(DNS_GATEWAY_ROWS)
    direct_keys = set(DNS_DIRECT_ROWS)

    for run_path in expected_run_paths(dns_root, required_reps):
        if not run_path.is_file():
            shape_failures += 1
            continue
        text = run_path.read_text(encoding="utf-8", errors="replace")
        gateway_for_run: dict[tuple[str, str], dict[str, Any]] | None = None
        direct_for_run: dict[tuple[str, str], dict[str, Any]] | None = None
        run_rejected = 0
        gateway_blobs = 0
        direct_blobs = 0
        blobs, malformed_relevant = extract_json_blobs(text, suite="dns")
        run_rejected += malformed_relevant
        for blob in blobs:
            if not isinstance(blob, dict) or "reports" not in blob:
                continue
            target = str(blob.get("target", ""))
            kind = classify_dns_target(target)
            if kind is None:
                # Unexpected/malformed target identity fails closed.
                run_rejected += 1
                continue
            expected = gateway_keys if kind == "gateway" else direct_keys
            parsed, blob_rejected = _parse_dns_blob_rows(blob, str(run_path), expected)
            run_rejected += blob_rejected
            if parsed is None:
                continue
            if kind == "gateway":
                gateway_blobs += 1
                if gateway_blobs == 1:
                    gateway_for_run = parsed
                else:
                    run_rejected += 1
            else:
                direct_blobs += 1
                if direct_blobs == 1:
                    direct_for_run = parsed
                else:
                    run_rejected += 1

        if (
            run_rejected
            or gateway_blobs != 1
            or direct_blobs != 1
            or gateway_for_run is None
            or direct_for_run is None
        ):
            rejected += run_rejected
            if gateway_blobs != 1:
                rejected += 1
            if direct_blobs != 1:
                rejected += 1
            shape_failures += 1
            continue

        for key, sample in gateway_for_run.items():
            gateway_rows[key].append(sample)
        for key, sample in direct_for_run.items():
            direct_rows[key].append(sample)

    def aggregate(samples: list[dict[str, Any]]) -> dict[str, Any] | None:
        out = aggregate_throughput_samples(
            samples,
            rate_key="qps",
            latency_keys=("p50_us", "p90_us", "p99_us"),
        )
        if out is not None:
            out["total_nxdomain_sum"] = sum(s["total_nxdomain"] for s in samples)
        return out

    gateway_summary: dict[str, Any] = {}
    gateway_evidence: dict[str, Any] = {}
    for cls, transport in DNS_GATEWAY_ROWS:
        row_key = f"{cls}/{transport}"
        samples = gateway_rows.get((cls, transport), [])
        agg = aggregate(samples)
        gateway_summary[row_key] = agg
        gateway_evidence[row_key] = repetition_evidence(
            len(samples),
            required_reps,
        )

    direct_summary: dict[str, Any] = {}
    direct_evidence: dict[str, Any] = {}
    for cls, transport in DNS_DIRECT_ROWS:
        row_key = f"{cls}/{transport}"
        samples = direct_rows.get((cls, transport), [])
        agg = aggregate(samples)
        direct_summary[row_key] = agg
        direct_evidence[row_key] = repetition_evidence(
            len(samples),
            required_reps,
        )

    overhead = {}
    for transport in ("udp", "tcp"):
        g_key = f"upstream-forward/{transport}"
        d_key = f"upstream-forward/{transport}"
        g = gateway_summary.get(g_key)
        d = direct_summary.get(d_key)
        if (
            g
            and d
            and g.get("qps_mean") is not None
            and d.get("qps_mean") is not None
            and d["qps_mean"] > 0
            and math.isfinite(g["qps_mean"])
            and math.isfinite(d["qps_mean"])
        ):
            overhead[transport] = (
                (d["qps_mean"] - g["qps_mean"]) / d["qps_mean"]
            ) * 100.0
        else:
            overhead[transport] = None

    row_complete = (
        shape_failures == 0
        and rejected == 0
        and all(v["ok"] for v in gateway_evidence.values())
        and all(v["ok"] for v in direct_evidence.values())
    )
    errors_ok = row_complete and all(
        row.get("total_errors_sum") == 0 and row.get("total_nxdomain_sum") == 0
        for row in list(gateway_summary.values()) + list(direct_summary.values())
        if row is not None
    )

    return {
        "gateway": gateway_summary,
        "direct_stub": direct_summary,
        "upstream_forward_overhead_percent": overhead,
        "complete": row_complete,
        "errors_ok": errors_ok,
        "rejected_blobs": rejected,
        "shape_failures": shape_failures,
        "repetition_evidence": {
            "required": required_reps,
            "gateway": gateway_evidence,
            "direct_stub": direct_evidence,
        },
    }


def mesh_complete(mesh: dict[str, Any]) -> bool:
    for section in mesh.values():
        for value in section.values():
            if value is None:
                return False
    return True


def expected_health_probe_ids(
    suites: str,
    required_reps: int,
) -> set[tuple[str, str, int]]:
    normalized = normalize_suites(suites)
    expected: set[tuple[str, str, int]] = set()
    if normalized in ("all", "mesh"):
        for bench in MESH_BENCHES:
            expected.add(("mesh", bench, 1))
    if normalized in ("all", "hbone"):
        for scenario in HBONE_SCENARIOS:
            for repetition in range(1, required_reps + 1):
                expected.add(("hbone", scenario["key"], repetition))
    if normalized in ("all", "dns"):
        for repetition in range(1, required_reps + 1):
            expected.add(("dns", "", repetition))
    return expected


def load_runner_health(
    results_root: Path,
    suites: str,
    required_reps: int,
) -> dict[str, Any]:
    health_path = results_root / "runner_health.json"
    probes_path = results_root / "logs" / "runner_health_probes.jsonl"
    health = load_json(health_path)
    if not isinstance(health, dict):
        health = {}
    probes: list[dict[str, Any]] = []
    if probes_path.is_file():
        for line in probes_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                probes.append({"parse_error": True, "raw": line[:200]})
                continue
            if isinstance(obj, dict):
                probes.append(obj)
            else:
                probes.append({"parse_error": True, "raw": line[:200]})
    steal_values: list[float] = []
    pre = parse_finite_number(health.get("avg_steal_percent"), non_negative=True)
    if pre is not None:
        steal_values.append(pre)
    actual_probe_ids: set[tuple[str, str, int]] = set()
    malformed_probe = False
    for probe in probes:
        if probe.get("parse_error"):
            malformed_probe = True
            continue
        steal = parse_finite_number(probe.get("avg_steal_percent"), non_negative=True)
        repetition = parse_non_negative_int(probe.get("repetition"))
        phase = probe.get("phase")
        scenario = probe.get("scenario", "")
        if (
            steal is None
            or repetition is None
            or repetition < 1
            or not isinstance(phase, str)
            or not isinstance(scenario, str)
            or probe.get("coverage") != "workload_interval"
        ):
            malformed_probe = True
            continue
        probe_id = (phase, scenario, repetition)
        if probe_id in actual_probe_ids:
            malformed_probe = True
            continue
        actual_probe_ids.add(probe_id)
        steal_values.append(steal)
    max_steal = max(steal_values) if steal_values else None
    # Missing health evidence fails closed: publication requires machine-readable
    # steal samples from the pre-collection probe and every selected mesh
    # Criterion and E2E workload-interval /proc/stat delta.
    expected_probe_ids = expected_health_probe_ids(suites, required_reps)
    evidence_ok = (
        pre is not None
        and not malformed_probe
        and actual_probe_ids == expected_probe_ids
    )
    steal_ok = (
        evidence_ok
        and max_steal is not None
        and max_steal <= MAX_CPU_STEAL_PERCENT
    )
    return {
        "path": str(health_path) if health_path.is_file() else None,
        "pre_collection": health,
        "probes": probes,
        "expected_probe_count": len(expected_probe_ids),
        "valid_probe_count": len(actual_probe_ids),
        "threshold_percent": MAX_CPU_STEAL_PERCENT,
        "max_steal_percent": max_steal,
        "evidence_present": evidence_ok,
        "ok": steal_ok,
    }


def selected_suite_gates(
    acceptance: dict[str, Any],
    suites: str,
) -> dict[str, bool]:
    normalized = normalize_suites(suites)
    required: dict[str, bool] = {
        "suites_supported": normalized is not None,
        "provenance_complete": bool(acceptance.get("provenance_complete")),
        "runner_health_ok": bool(acceptance.get("runner_health_ok")),
    }
    if normalized is None:
        # Unsupported suite values must not silently reduce to runner-health-only.
        return required
    if normalized in ("all", "mesh"):
        required["mesh_complete"] = bool(acceptance.get("mesh_complete"))
    if normalized in ("all", "hbone"):
        required["hbone_complete"] = bool(acceptance.get("hbone_complete"))
        required["hbone_errors_ok"] = bool(acceptance.get("hbone_errors_ok"))
    if normalized in ("all", "dns"):
        required["dns_complete"] = bool(acceptance.get("dns_complete"))
        required["dns_errors_ok"] = bool(acceptance.get("dns_errors_ok"))
    if normalized == "all":
        required["ready_to_publish_baselines"] = bool(
            acceptance.get("ready_to_publish_baselines")
        )
    return required


def selected_suite_accepted(acceptance: dict[str, Any], suites: str) -> bool:
    gates = selected_suite_gates(acceptance, suites)
    return all(gates.values())


def write_draft_markdown(
    draft_dir: Path,
    provenance: dict[str, Any],
    mesh: dict[str, Any],
    hbone: dict[str, Any],
    dns: dict[str, Any],
) -> None:
    draft_dir.mkdir(parents=True, exist_ok=True)
    runner = provenance.get("runner", {})
    commit = provenance.get("commit_sha", "unknown")
    run_id = (provenance.get("github") or {}).get("run_id")
    artifact_note = (
        f"GitHub Actions run `{run_id}` artifact "
        f"`mesh-performance-baselines-{commit}`"
        if run_id
        else "hosted workflow artifact (run id pending)"
    )

    mesh_lines = [
        "# Mesh Performance Baseline (draft from hosted collection)",
        "",
        "**Directional reference numbers only.** Hardware-specific — GitHub-hosted",
        f"`{runner.get('class', 'ubuntu-26.04')}` results are not universal product targets.",
        "",
        "## Reference environment",
        "",
        f"- Ferrum commit: `{commit}`",
        f"- Runner class: `{runner.get('class')}`",
        f"- CPU: `{runner.get('cpu_model')}`",
        f"- Topology: `{json.dumps(runner.get('cpu_topology', {}))}`",
        f"- RAM: `{(runner.get('ram') or {}).get('memtotal_gib')} GiB`",
        f"- OS/kernel/arch: `{runner.get('uname')}` / `{runner.get('arch')}`",
        f"- Build profile: `{(provenance.get('build') or {}).get('gateway_profile', 'release')}`",
        f"- Raw artifacts: {artifact_note}",
        "",
        "## authz_match",
        "",
        "| Policies (N) | Mean per call | Notes |",
        "|---|---|---|",
    ]
    for size in AUTHZ_SIZES:
        row = mesh["authz_match"].get(str(size))
        mean = row["mean_display"] if row else "_INCOMPLETE_"
        stdev = row["stdev_display"] if row else "n/a"
        mesh_lines.append(f"| {size:,} | {mean} (σ {stdev}) | Criterion mean |")
    mesh_lines.extend(
        [
            "",
            "## ip_restriction",
            "",
            "| Decision shape | Instances | Mean per iteration | Notes |",
            "|---|---:|---|---|",
        ]
    )
    labels = {
        ("deny_miss", 1): "Deny miss above every interval",
        ("deny_miss", 4): "Deny miss above every interval",
        ("high_match", 1): "Allow match in final interval",
        ("high_match", 4): "Allow match in final interval",
    }
    for decision, instances in IP_CASES:
        row = mesh["ip_restriction"].get(f"{decision}_{instances}")
        mean = row["mean_display"] if row else "_INCOMPLETE_"
        mesh_lines.append(
            f"| {labels[(decision, instances)]} | {instances} | {mean} | 10,000 rules |"
        )
    mesh_lines.extend(
        [
            "",
            "## slice_apply",
            "",
            "| Workloads (N) | Mean per call | Notes |",
            "|---|---|---|",
        ]
    )
    for size in SLICE_SIZES:
        row = mesh["slice_apply"].get(str(size))
        mean = row["mean_display"] if row else "_INCOMPLETE_"
        mesh_lines.append(f"| {size:,} | {mean} | Criterion mean |")
    mesh_lines.extend(
        [
            "",
            "## xds_translation",
            "",
            "| Workloads (N) | Mean per call | Notes |",
            "|---|---|---|",
        ]
    )
    for size in SLICE_SIZES:
        row = mesh["xds_translation"].get(str(size))
        mean = row["mean_display"] if row else "_INCOMPLETE_"
        mesh_lines.append(f"| {size:,} | {mean} | Criterion mean |")
    (draft_dir / "mesh_baseline_draft.md").write_text(
        "\n".join(mesh_lines) + "\n", encoding="utf-8"
    )

    hbone_lines = [
        "# Mesh HBONE E2E Baseline (draft from hosted collection)",
        "",
        f"- Ferrum revision: `{commit}`",
        f"- CPU: `{runner.get('cpu_model')}`",
        f"- RAM: `{(runner.get('ram') or {}).get('memtotal_gib')} GiB`",
        f"- OS / kernel: `{runner.get('uname')}`",
        "- Build profile: `--release`",
        f"- Raw artifacts: {artifact_note}",
        "",
        "Overhead formula: `((direct_rps - gateway_hbone_rps) / direct_rps) * 100`.",
        "",
    ]
    titles = {
        "1kib_c50_30s": "## 1 KiB payload, concurrency 50, 30 s",
        "16kib_c50_30s": "## 16 KiB payload, concurrency 50, 30 s",
        "256kib_c100_60s": "## 256 KiB payload, concurrency 100, 60 s",
    }
    for key, title in titles.items():
        row = hbone.get(key) or {}
        direct = row.get("direct") or {}
        gateway = row.get("gateway") or {}
        hbone_lines.extend(
            [
                title,
                "",
                "| Path              | RPS    | p50    | p95    | p99    | Overhead vs direct |",
                "|-------------------|--------|--------|--------|--------|--------------------|",
                f"| Direct baseline   | {fmt_rps(direct.get('rps_mean'))}  | {fmt_us(direct.get('p50_us_mean'))}  | {fmt_us(direct.get('p95_us_mean'))}  | {fmt_us(direct.get('p99_us_mean'))}  | —                  |",
                f"| Gateway + HBONE   | {fmt_rps(gateway.get('rps_mean'))}  | {fmt_us(gateway.get('p50_us_mean'))}  | {fmt_us(gateway.get('p95_us_mean'))}  | {fmt_us(gateway.get('p99_us_mean'))}  | {fmt_pct(row.get('overhead_percent_mean'))}            |",
                "",
            ]
        )
    (draft_dir / "hbone_baseline_draft.md").write_text(
        "\n".join(hbone_lines) + "\n", encoding="utf-8"
    )

    dns_lines = [
        "# Mesh DNS Proxy E2E Baseline (draft from hosted collection)",
        "",
        f"- Ferrum commit: `{commit}`",
        f"- Runner: `{runner.get('class')}` / `{runner.get('cpu_model')}`",
        f"- Raw artifacts: {artifact_note}",
        "",
        "Upstream-forward overhead formula: "
        "`((direct_stub_qps - gateway_qps) / direct_stub_qps) * 100`.",
        "",
        "## Via gateway (127.0.0.1:15053)",
        "",
        "UDP transport:",
        "",
        "| Name class | qps | p50 | p90 | p99 | Notes |",
        "|---|---|---|---|---|---|",
    ]
    gateway = dns.get("gateway") or {}
    for cls in ("mesh-internal", "mesh-wildcard", "upstream-forward"):
        row = gateway.get(f"{cls}/udp") or {}
        dns_lines.append(
            f"| {cls} | {fmt_rps(row.get('qps_mean'))} | {fmt_us(row.get('p50_us_mean'))} | "
            f"{fmt_us(row.get('p90_us_mean'))} | {fmt_us(row.get('p99_us_mean'))} | |"
        )
    dns_lines.extend(
        [
            "",
            "TCP transport:",
            "",
            "| Name class | qps | p50 | p90 | p99 | Notes |",
            "|---|---|---|---|---|---|",
        ]
    )
    for cls in ("mesh-internal", "mesh-wildcard", "upstream-forward"):
        row = gateway.get(f"{cls}/tcp") or {}
        dns_lines.append(
            f"| {cls} | {fmt_rps(row.get('qps_mean'))} | {fmt_us(row.get('p50_us_mean'))} | "
            f"{fmt_us(row.get('p90_us_mean'))} | {fmt_us(row.get('p99_us_mean'))} | |"
        )
    direct = dns.get("direct_stub") or {}
    dns_lines.extend(
        [
            "",
            "## Direct baseline (dns_upstream_stub)",
            "",
            "| Class | Transport | qps | p50 | p90 | p99 |",
            "|---|---|---|---|---|---|",
        ]
    )
    for transport in ("udp", "tcp"):
        row = direct.get(f"upstream-forward/{transport}") or {}
        dns_lines.append(
            f"| upstream-forward | {transport.upper()} | {fmt_rps(row.get('qps_mean'))} | "
            f"{fmt_us(row.get('p50_us_mean'))} | {fmt_us(row.get('p90_us_mean'))} | "
            f"{fmt_us(row.get('p99_us_mean'))} |"
        )
    (draft_dir / "dns_baseline_draft.md").write_text(
        "\n".join(dns_lines) + "\n", encoding="utf-8"
    )


def _write_hbone_run(
    path: Path,
    *,
    gateway_rps: float,
    direct_rps: float,
    errors: int = 0,
    scenario: dict[str, Any] | None = None,
) -> None:
    scenario = scenario or HBONE_SCENARIOS[0]
    gateway = {
        "label": "hbone_e2e",
        "target": "http://127.0.0.1:18000/echo",
        "concurrency": scenario["concurrency"],
        "duration_secs": scenario["duration"],
        "payload_size": scenario["payload"],
        "rps": gateway_rps,
        "p50_us": 100,
        "p95_us": 200,
        "p99_us": 300,
        "total_errors": errors,
    }
    direct = {
        "label": "hbone_e2e",
        "target": "http://127.0.0.1:19000/echo",
        "concurrency": scenario["concurrency"],
        "duration_secs": scenario["duration"],
        "payload_size": scenario["payload"],
        "rps": direct_rps,
        "p50_us": 80,
        "p95_us": 160,
        "p99_us": 240,
        "total_errors": errors,
    }
    path.write_text(
        json.dumps(gateway) + "\n" + json.dumps(direct) + "\n",
        encoding="utf-8",
    )


def _dns_blob(
    *,
    target: str,
    rows: list[tuple[str, str, float]],
    errors: int = 0,
    nxdomain: int = 0,
) -> dict[str, Any]:
    return {
        "target": target,
        "concurrency": DNS_CONCURRENCY,
        "duration_secs": DNS_DURATION_SECS,
        "reports": [
            {
                "name_class": cls,
                "transport": transport,
                "duration_secs": DNS_DURATION_SECS,
                "qps": qps,
                "p50_us": 50,
                "p90_us": 90,
                "p99_us": 120,
                "total_errors": errors,
                "total_nxdomain": nxdomain,
            }
            for cls, transport, qps in rows
        ],
    }


def _write_full_dns_run(path: Path, *, errors: int = 0, nxdomain: int = 0) -> None:
    gateway_rows = [
        (cls, transport, 1000.0 + i)
        for i, (cls, transport) in enumerate(DNS_GATEWAY_ROWS)
    ]
    direct_rows = [
        (cls, transport, 2000.0 + i)
        for i, (cls, transport) in enumerate(DNS_DIRECT_ROWS)
    ]
    text = (
        json.dumps(
            _dns_blob(
                target="127.0.0.1:15053",
                rows=gateway_rows,
                errors=errors,
                nxdomain=nxdomain,
            )
        )
        + "\n"
        + json.dumps(
            _dns_blob(
                target="127.0.0.1:17053",
                rows=direct_rows,
                errors=errors,
                nxdomain=nxdomain,
            )
        )
        + "\n"
    )
    path.write_text(text, encoding="utf-8")


def _write_criterion_estimate(path: Path, mean_ns: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "mean": {
                    "point_estimate": mean_ns,
                    "confidence_interval": {
                        "lower_bound": mean_ns * 0.9,
                        "upper_bound": mean_ns * 1.1,
                    },
                },
                "std_dev": {"point_estimate": mean_ns * 0.05},
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _populate_valid_mesh(criterion_root: Path) -> None:
    for size in AUTHZ_SIZES:
        _write_criterion_estimate(
            criterion_root / "authz_match" / "policies" / str(size) / "new" / "estimates.json",
            1000.0 * size,
        )
    for decision, instances in IP_CASES:
        _write_criterion_estimate(
            criterion_root
            / "ip_restriction_lookup"
            / f"{decision}_10000_rules_{instances}_instances"
            / "new"
            / "estimates.json",
            500.0 * instances,
        )
    for size in SLICE_SIZES:
        _write_criterion_estimate(
            criterion_root / "slice_apply" / "workloads" / str(size) / "new" / "estimates.json",
            2000.0 * size,
        )
        _write_criterion_estimate(
            criterion_root
            / "xds_translation"
            / "workloads"
            / str(size)
            / "new"
            / "estimates.json",
            3000.0 * size,
        )


def _self_test_provenance(required_reps: int) -> dict[str, Any]:
    commands = [
        {"suite": "mesh", "command": f"cargo bench --bench mesh-{index}"}
        for index in range(4)
    ]
    commands.append({"suite": "hbone", "command": "build hbone"})
    commands.extend(
        {"suite": "hbone", "command": f"run hbone {scenario['key']} {repetition}"}
        for scenario in HBONE_SCENARIOS
        for repetition in range(1, required_reps + 1)
    )
    commands.append({"suite": "dns", "command": "build dns"})
    commands.extend(
        {"suite": "dns", "command": f"run dns {repetition}"}
        for repetition in range(1, required_reps + 1)
    )
    return {
        "schema_version": 1,
        "collected_at_utc": "2026-08-12T00:00:00+00:00",
        "commit_sha": "d" * 40,
        "github": {
            "run_id": "1",
            "run_attempt": "1",
            "workflow": "Mesh Performance Baselines",
            "job": "collect",
            "repository": "ferrum-edge/ferrum-edge",
            "ref": "refs/heads/main",
            "server_url": "https://github.com",
        },
        "runner": {
            "class": "ubuntu-26.04",
            "name": "GitHub Actions 1",
            "os": "Linux",
            "arch": "X64",
            "nproc": "4",
            "cpu_model": "test cpu",
            "cpu_topology": {
                "cpus": "CPU(s): 4",
                "threads_per_core": "Thread(s) per core: 2",
                "cores_per_socket": "Core(s) per socket: 2",
                "sockets": "Socket(s): 1",
            },
            "lscpu_raw": "test lscpu",
            "ram": {"memtotal_kib": 8_388_608},
            "uname": "Linux test",
            "kernel": "test-kernel",
        },
        "toolchain": {
            "rustc_verbose": "rustc test",
            "cargo_verbose": "cargo test",
            "rust_toolchain_file": "rust-toolchain.toml channel=stable",
        },
        "build": {
            "gateway_profile": "release",
            "gateway_features": "default (no --features)",
            "harness_profile": "release",
            "non_default_settings_note": "documented harness settings",
        },
        "dependency_harness_versions": {
            "mesh_criterion": "0.5.1",
            "mesh_crate": "mesh-perf",
            "hbone_crate": "mesh-hbone-e2e-perf",
            "dns_crate": "mesh-dns-e2e-perf",
            "hdrhistogram_hbone": "7.5.4",
            "hdrhistogram_dns": "7.5.4",
        },
        "warmup_and_repetitions": {
            "mesh_microbench": "Criterion warmup",
            "e2e_repetitions": required_reps,
            "e2e_policy": "three clean repetitions",
        },
        "suite_commands": commands,
        "overhead_formula": {
            "hbone_rps_overhead_percent": "hbone formula",
            "dns_upstream_forward_overhead_percent": "dns formula",
            "notes": "same-run comparison",
        },
    }


def _self_test_health_probes(required_reps: int) -> str:
    probes = [
        {
            "phase": "mesh",
            "scenario": bench,
            "repetition": 1,
            "avg_steal_percent": 1.5,
            "coverage": "workload_interval",
        }
        for bench in MESH_BENCHES
    ]
    probes.extend(
        {
            "phase": "hbone",
            "scenario": scenario["key"],
            "repetition": repetition,
            "avg_steal_percent": 3.0,
            "coverage": "workload_interval",
        }
        for scenario in HBONE_SCENARIOS
        for repetition in range(1, required_reps + 1)
    )
    probes.extend(
        {
            "phase": "dns",
            "repetition": repetition,
            "avg_steal_percent": 2.0,
            "coverage": "workload_interval",
        }
        for repetition in range(1, required_reps + 1)
    )
    return "".join(json.dumps(probe) + "\n" for probe in probes)


def self_test() -> int:
    assert abs((((100.0 - 80.0) / 100.0) * 100.0) - 20.0) < 1e-9
    assert "µs" in fmt_duration_ns(1500.0) or "us" in fmt_duration_ns(1500.0)
    assert required_repetitions(None) == 3
    assert required_repetitions(5) == 5
    assert parse_finite_number("nan", positive=True) is None
    assert parse_finite_number(-1.0, positive=True) is None
    assert parse_finite_number(0.0, positive=True) is None
    assert parse_finite_number(1.5, positive=True) == 1.5
    assert parse_non_negative_int(1.5) is None
    assert parse_non_negative_int(2) == 2

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        drafts = root / "drafts"
        prov_path = root / "provenance.json"
        out_path = root / "summary.json"
        prov_path.write_text(
            json.dumps(_self_test_provenance(3)) + "\n",
            encoding="utf-8",
        )
        (root / "runner_health.json").write_text(
            json.dumps(
                {
                    "runner_class": "ubuntu-26.04",
                    "avg_steal_percent": 1.0,
                    "threshold_percent": MAX_CPU_STEAL_PERCENT,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "logs").mkdir(parents=True)

        # --- undersampling: one gateway + one direct must not be complete ---
        under = root / "under"
        for scenario in HBONE_SCENARIOS:
            scenario_dir = under / "hbone" / scenario["key"]
            scenario_dir.mkdir(parents=True)
            _write_hbone_run(
                scenario_dir / "run_1.txt",
                gateway_rps=80.0,
                direct_rps=100.0,
                scenario=scenario,
            )
        hbone_under = summarize_hbone(under / "hbone", required_repetitions(3))
        assert all(not row["complete"] for row in hbone_under.values())
        evidence = hbone_under["1kib_c50_30s"]["repetition_evidence"]
        assert evidence["required"] == 3
        assert evidence["gateway"]["actual"] == 1
        assert evidence["direct"]["actual"] == 1
        assert evidence["gateway"]["ok"] is False

        # --- duplicate relevant blobs in one run file must not satisfy reps ---
        dup = root / "dup_blobs" / "hbone" / "1kib_c50_30s"
        dup.mkdir(parents=True)
        gateway = {
            "label": "hbone_e2e",
            "target": "http://127.0.0.1:18000/echo",
            "concurrency": 50,
            "duration_secs": 30,
            "payload_size": 1024,
            "rps": 80.0,
            "p50_us": 100,
            "p95_us": 200,
            "p99_us": 300,
            "total_errors": 0,
        }
        direct = {
            "label": "hbone_e2e",
            "target": "http://127.0.0.1:19000/echo",
            "concurrency": 50,
            "duration_secs": 30,
            "payload_size": 1024,
            "rps": 100.0,
            "p50_us": 80,
            "p95_us": 160,
            "p99_us": 240,
            "total_errors": 0,
        }
        # Three duplicate gateway+direct pairs in a single execution artifact.
        (dup / "run_1.txt").write_text(
            "\n".join(json.dumps(x) for x in (gateway, direct, gateway, direct, gateway, direct))
            + "\n",
            encoding="utf-8",
        )
        _write_hbone_run(dup / "run_2.txt", gateway_rps=81.0, direct_rps=101.0)
        _write_hbone_run(dup / "run_3.txt", gateway_rps=82.0, direct_rps=102.0)
        hbone_dup = summarize_hbone(dup.parent, required_repetitions(3))
        assert hbone_dup["1kib_c50_30s"]["complete"] is False
        assert hbone_dup["1kib_c50_30s"]["errors_ok"] is False
        assert hbone_dup["1kib_c50_30s"]["repetition_evidence"]["gateway"]["actual"] == 2
        assert hbone_dup["1kib_c50_30s"]["shape_failures"] >= 1

        # --- extra/misnumbered run artifacts conflict with the exact ledger ---
        extra = root / "extra_runs" / "hbone" / "1kib_c50_30s"
        extra.mkdir(parents=True)
        for run in range(1, 5):
            _write_hbone_run(
                extra / f"run_{run}.txt",
                gateway_rps=80.0 + run,
                direct_rps=100.0 + run,
            )
        hbone_extra = summarize_hbone(extra.parent, required_repetitions(3))
        assert hbone_extra["1kib_c50_30s"]["complete"] is False
        assert hbone_extra["1kib_c50_30s"]["errors_ok"] is False
        assert hbone_extra["1kib_c50_30s"]["shape_failures"] == 1
        assert unexpected_run_paths(extra, 3) == [extra / "run_4.txt"]

        # --- malformed relevant blobs alongside valid samples fail closed ---
        malformed = root / "malformed_mixed" / "hbone" / "1kib_c50_30s"
        malformed.mkdir(parents=True)
        bad_mixed = {
            "label": "hbone_e2e",
            "target": "http://127.0.0.1:18000/echo",
            "rps": "not-a-number",
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "total_errors": 0,
        }
        for run in range(1, 4):
            _write_hbone_run(
                malformed / f"run_{run}.txt",
                gateway_rps=80.0 + run,
                direct_rps=100.0 + run,
            )
            # Append a malformed relevant blob to an otherwise valid run.
            with (malformed / f"run_{run}.txt").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(bad_mixed) + "\n")
        hbone_malformed = summarize_hbone(malformed.parent, required_repetitions(3))
        assert hbone_malformed["1kib_c50_30s"]["complete"] is False
        assert hbone_malformed["1kib_c50_30s"]["errors_ok"] is False
        assert hbone_malformed["1kib_c50_30s"]["rejected_blobs"] >= 1
        assert hbone_malformed["1kib_c50_30s"]["repetition_evidence"]["gateway"]["actual"] == 0

        # --- syntactically malformed relevant top-level records fail closed ---
        hbone_syntax = root / "malformed_syntax" / "hbone" / "1kib_c50_30s"
        hbone_syntax.mkdir(parents=True)
        truncated_hbone = (
            '{\n  "label": "hbone_e2e",\n'
            '  "target": "http://127.0.0.1:18000/echo",\n'
            '  "rps": 80\n'
        )
        for run in range(1, 4):
            _write_hbone_run(
                hbone_syntax / f"run_{run}.txt",
                gateway_rps=80.0 + run,
                direct_rps=100.0 + run,
            )
            with (hbone_syntax / f"run_{run}.txt").open("a", encoding="utf-8") as handle:
                handle.write(truncated_hbone)
        hbone_syntax_summary = summarize_hbone(hbone_syntax.parent, required_repetitions(3))
        assert hbone_syntax_summary["1kib_c50_30s"]["complete"] is False
        assert hbone_syntax_summary["1kib_c50_30s"]["errors_ok"] is False
        assert hbone_syntax_summary["1kib_c50_30s"]["rejected_blobs"] >= 1
        assert hbone_syntax_summary["1kib_c50_30s"]["shape_failures"] >= 1
        assert hbone_syntax_summary["1kib_c50_30s"]["repetition_evidence"]["gateway"]["actual"] == 0
        assert hbone_syntax_summary["1kib_c50_30s"]["repetition_evidence"]["direct"]["actual"] == 0

        # --- unrelated brace-bearing logs must not disturb valid runs ---
        brace_logs = root / "brace_logs" / "hbone" / "1kib_c50_30s"
        brace_logs.mkdir(parents=True)
        for run in range(1, 4):
            _write_hbone_run(
                brace_logs / f"run_{run}.txt",
                gateway_rps=80.0 + run,
                direct_rps=100.0 + run,
            )
            with (brace_logs / f"run_{run}.txt").open("a", encoding="utf-8") as handle:
                handle.write("info: kernel said {oops not json}\n")
                handle.write("debug: map={broken\n")
        hbone_brace = summarize_hbone(brace_logs.parent, required_repetitions(3))
        assert hbone_brace["1kib_c50_30s"]["complete"] is True
        assert hbone_brace["1kib_c50_30s"]["errors_ok"] is True
        assert hbone_brace["1kib_c50_30s"]["repetition_evidence"]["gateway"]["actual"] == 3

        # --- missing counterpart (gateway without direct) fails the run ---
        missing_direct = root / "missing_counterpart" / "hbone" / "1kib_c50_30s"
        missing_direct.mkdir(parents=True)
        for run in range(1, 4):
            (missing_direct / f"run_{run}.txt").write_text(
                json.dumps(gateway) + "\n",
                encoding="utf-8",
            )
        hbone_missing = summarize_hbone(missing_direct.parent, required_repetitions(3))
        assert hbone_missing["1kib_c50_30s"]["complete"] is False
        assert hbone_missing["1kib_c50_30s"]["repetition_evidence"]["direct"]["actual"] == 0
        assert hbone_missing["1kib_c50_30s"]["repetition_evidence"]["gateway"]["actual"] == 0
        assert classify_hbone_blob(
            {"label": "mystery", "target": "127.0.0.1:9999", "rps": 1.0}
        ) is None
        assert classify_hbone_blob(
            {
                "label": "hbone_e2e",
                "target": "http://127.0.0.1:18000/echo",
                "rps": 1.0,
            }
        ) == "gateway"
        assert classify_hbone_blob(
            {
                "label": "hbone_e2e",
                "target": "http://127.0.0.1:54321/echo",
                "rps": 1.0,
            }
        ) == "direct"
        assert classify_hbone_blob(
            {
                "label": "Direct baseline",
                "target": "http://127.0.0.1:54321/echo",
                "rps": 1.0,
            }
        ) is None
        wrong_hbone_shape = dict(gateway)
        wrong_hbone_shape["concurrency"] = 51
        assert parse_hbone_sample(wrong_hbone_shape, "x", HBONE_SCENARIOS[0]) is None

        # --- missing DNS rows / incomplete per-run shape ---
        dns_missing = root / "dns_missing"
        dns_missing.mkdir()
        partial = {
            "target": "127.0.0.1:15053",
            "reports": [
                {
                    "name_class": "mesh-internal",
                    "transport": "udp",
                    "qps": 100.0,
                    "p50_us": 1,
                    "p90_us": 2,
                    "p99_us": 3,
                    "total_errors": 0,
                }
            ],
        }
        for i in range(1, 4):
            (dns_missing / f"run_{i}.txt").write_text(json.dumps(partial) + "\n", encoding="utf-8")
        dns_partial = summarize_dns(dns_missing, required_repetitions(3))
        assert dns_partial["complete"] is False
        assert dns_partial["errors_ok"] is False
        # Incomplete run shape must not credit any row toward repetition evidence.
        assert dns_partial["repetition_evidence"]["gateway"]["mesh-internal/udp"]["ok"] is False
        assert dns_partial["repetition_evidence"]["gateway"]["mesh-wildcard/udp"]["ok"] is False
        assert dns_partial["repetition_evidence"]["direct_stub"]["upstream-forward/udp"]["ok"] is False
        assert dns_partial["shape_failures"] == 3

        # --- unexpected DNS target identity fails closed (not gateway) ---
        dns_unexpected = root / "dns_unexpected"
        dns_unexpected.mkdir()
        for run in range(1, 4):
            _write_full_dns_run(dns_unexpected / f"run_{run}.txt")
            unexpected = _dns_blob(
                target="127.0.0.1:9999",
                rows=[(cls, transport, 50.0) for cls, transport in DNS_GATEWAY_ROWS],
            )
            with (dns_unexpected / f"run_{run}.txt").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(unexpected) + "\n")
        dns_bad_target = summarize_dns(dns_unexpected, required_repetitions(3))
        assert dns_bad_target["complete"] is False
        assert dns_bad_target["errors_ok"] is False
        assert dns_bad_target["rejected_blobs"] >= 1
        assert dns_bad_target["repetition_evidence"]["gateway"]["mesh-internal/udp"]["actual"] == 0
        assert classify_dns_target("127.0.0.1:9999") is None

        # --- syntactically malformed relevant DNS records fail closed ---
        dns_syntax = root / "dns_syntax"
        dns_syntax.mkdir()
        truncated_dns = (
            '{\n  "target": "127.0.0.1:15053",\n'
            '  "concurrency": 100,\n'
            '  "duration_secs": 60,\n'
            '  "reports": [\n'
            '    {"name_class": "mesh-internal", "transport": "udp"\n'
        )
        for run in range(1, 4):
            _write_full_dns_run(dns_syntax / f"run_{run}.txt")
            with (dns_syntax / f"run_{run}.txt").open("a", encoding="utf-8") as handle:
                handle.write(truncated_dns)
        dns_syntax_summary = summarize_dns(dns_syntax, required_repetitions(3))
        assert dns_syntax_summary["complete"] is False
        assert dns_syntax_summary["errors_ok"] is False
        assert dns_syntax_summary["rejected_blobs"] >= 1
        assert dns_syntax_summary["shape_failures"] >= 1
        assert dns_syntax_summary["repetition_evidence"]["gateway"]["mesh-internal/udp"]["actual"] == 0
        assert dns_syntax_summary["repetition_evidence"]["direct_stub"]["upstream-forward/udp"]["actual"] == 0

        # --- unrelated brace-bearing logs must not disturb valid DNS runs ---
        dns_brace = root / "dns_brace"
        dns_brace.mkdir()
        for run in range(1, 4):
            _write_full_dns_run(dns_brace / f"run_{run}.txt")
            with (dns_brace / f"run_{run}.txt").open("a", encoding="utf-8") as handle:
                handle.write("stderr: retry {unclosed\n")
                handle.write("note: value={not json either\n")
        dns_brace_summary = summarize_dns(dns_brace, required_repetitions(3))
        assert dns_brace_summary["complete"] is True
        assert dns_brace_summary["errors_ok"] is True
        assert dns_brace_summary["repetition_evidence"]["gateway"]["mesh-internal/udp"]["actual"] == 3

        assert classify_dns_target("127.0.0.1:15053") == "gateway"
        assert classify_dns_target("127.0.0.1:17053") == "direct"
        assert classify_dns_target("evil:15053") is None
        assert classify_dns_target("127.0.0.1:15053-extra") is None
        assert classify_dns_target("prefix-127.0.0.1:17053") is None
        wrong_dns_shape = _dns_blob(
            target=DNS_GATEWAY_TARGET,
            rows=[(cls, transport, 50.0) for cls, transport in DNS_GATEWAY_ROWS],
        )
        wrong_dns_shape["duration_secs"] = 59
        assert _parse_dns_blob_rows(
            wrong_dns_shape,
            "x",
            set(DNS_GATEWAY_ROWS),
        )[0] is None

        dns_extra = root / "dns_extra_runs"
        dns_extra.mkdir()
        for run in range(1, 5):
            _write_full_dns_run(dns_extra / f"run_{run}.txt")
        dns_extra_summary = summarize_dns(dns_extra, required_repetitions(3))
        assert dns_extra_summary["complete"] is False
        assert dns_extra_summary["errors_ok"] is False
        assert dns_extra_summary["shape_failures"] == 1

        # --- bad metrics rejected (NaN / non-positive / invalid latency) ---
        bad = root / "bad_metrics" / "hbone" / "1kib_c50_30s"
        bad.mkdir(parents=True)
        bad_blob = {
            "label": "hbone_e2e",
            "target": "http://127.0.0.1:18000/echo",
            "rps": "not-a-number",
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "total_errors": 0,
        }
        nan_blob = {
            "label": "hbone_e2e",
            "target": "http://127.0.0.1:19000/echo",
            "rps": float("nan"),
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "total_errors": 0,
        }
        zero_blob = {
            "label": "hbone_e2e",
            "target": "http://127.0.0.1:19000/echo",
            "rps": 0.0,
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
            "total_errors": 0,
        }
        (bad / "run_1.txt").write_text(
            "\n".join(json.dumps(x) for x in (bad_blob, nan_blob, zero_blob)) + "\n",
            encoding="utf-8",
        )
        assert parse_hbone_sample(bad_blob, "x", HBONE_SCENARIOS[0]) is None
        assert parse_hbone_sample(nan_blob, "x", HBONE_SCENARIOS[0]) is None
        assert parse_hbone_sample(zero_blob, "x", HBONE_SCENARIOS[0]) is None
        missing_hbone_errors = {
            "label": "hbone_e2e",
            "target": "http://127.0.0.1:18000/echo",
            "rps": 1.0,
            "p50_us": 1,
            "p95_us": 2,
            "p99_us": 3,
        }
        assert parse_hbone_sample(missing_hbone_errors, "x", HBONE_SCENARIOS[0]) is None
        assert parse_dns_report(
            {
                "name_class": "mesh-internal",
                "transport": "udp",
                "qps": -5,
                "p50_us": 1,
                "p90_us": 2,
                "p99_us": 3,
                "total_errors": 0,
            },
            "x",
            DNS_DURATION_SECS,
        ) is None
        assert parse_dns_report(
            {
                "name_class": "mesh-internal",
                "transport": "udp",
                "qps": 1,
                "p50_us": 1,
                "p90_us": 2,
                "p99_us": 3,
            },
            "x",
            DNS_DURATION_SECS,
        ) is None
        assert criterion_mean(Path("/no/such/estimates.json")) is None

        # --- nonzero errors fail errors_ok ---
        err_root = root / "errors"
        for scenario in HBONE_SCENARIOS:
            scenario_dir = err_root / "hbone" / scenario["key"]
            scenario_dir.mkdir(parents=True)
            for run in range(1, 4):
                _write_hbone_run(
                    scenario_dir / f"run_{run}.txt",
                    gateway_rps=80.0,
                    direct_rps=100.0,
                    errors=1,
                    scenario=scenario,
                )
        hbone_err = summarize_hbone(err_root / "hbone", required_repetitions(3))
        assert all(row["complete"] for row in hbone_err.values())
        assert all(not row["errors_ok"] for row in hbone_err.values())

        dns_err = root / "dns_errors"
        dns_err.mkdir()
        for run in range(1, 4):
            _write_full_dns_run(dns_err / f"run_{run}.txt", errors=2)
        dns_err_summary = summarize_dns(dns_err, required_repetitions(3))
        assert dns_err_summary["complete"] is True
        assert dns_err_summary["errors_ok"] is False

        # --- nonzero NXDOMAIN fails errors_ok without folding into total_errors ---
        dns_nx_all = root / "dns_nxdomain_all"
        dns_nx_all.mkdir()
        for run in range(1, 4):
            _write_full_dns_run(dns_nx_all / f"run_{run}.txt", nxdomain=4)
        dns_nx_all_summary = summarize_dns(dns_nx_all, required_repetitions(3))
        assert dns_nx_all_summary["complete"] is True
        assert dns_nx_all_summary["errors_ok"] is False
        assert (
            dns_nx_all_summary["gateway"]["mesh-internal/udp"]["total_errors_sum"] == 0
        )
        assert (
            dns_nx_all_summary["gateway"]["mesh-internal/udp"]["total_nxdomain_sum"] == 12
        )

        dns_nx_partial = root / "dns_nxdomain_partial"
        dns_nx_partial.mkdir()
        for run in range(1, 4):
            gateway_rows = [
                (cls, transport, 1000.0 + i)
                for i, (cls, transport) in enumerate(DNS_GATEWAY_ROWS)
            ]
            direct_rows = [
                (cls, transport, 2000.0 + i)
                for i, (cls, transport) in enumerate(DNS_DIRECT_ROWS)
            ]
            gateway_blob = _dns_blob(
                target="127.0.0.1:15053",
                rows=gateway_rows,
            )
            gateway_blob["reports"][0]["total_nxdomain"] = 1
            direct_blob = _dns_blob(
                target="127.0.0.1:17053",
                rows=direct_rows,
            )
            (dns_nx_partial / f"run_{run}.txt").write_text(
                json.dumps(gateway_blob) + "\n" + json.dumps(direct_blob) + "\n",
                encoding="utf-8",
            )
        dns_nx_partial_summary = summarize_dns(dns_nx_partial, required_repetitions(3))
        assert dns_nx_partial_summary["complete"] is True
        assert dns_nx_partial_summary["errors_ok"] is False
        assert (
            dns_nx_partial_summary["gateway"]["mesh-internal/udp"]["total_errors_sum"]
            == 0
        )
        assert (
            dns_nx_partial_summary["gateway"]["mesh-internal/udp"]["total_nxdomain_sum"]
            == 3
        )
        assert (
            dns_nx_partial_summary["gateway"]["mesh-wildcard/udp"]["total_nxdomain_sum"]
            == 0
        )

        missing_nxdomain = {
            "name_class": "mesh-internal",
            "transport": "udp",
            "qps": 1,
            "p50_us": 1,
            "p90_us": 2,
            "p99_us": 3,
            "total_errors": 0,
            "duration_secs": DNS_DURATION_SECS,
        }
        assert parse_dns_report(missing_nxdomain, "x", DNS_DURATION_SECS) is None

        # --- valid three-run shape with healthy steal is publication-ready ---
        valid = root / "valid"
        _populate_valid_mesh(valid / "mesh" / "criterion")
        for scenario in HBONE_SCENARIOS:
            scenario_dir = valid / "hbone" / scenario["key"]
            scenario_dir.mkdir(parents=True)
            for run in range(1, 4):
                _write_hbone_run(
                    scenario_dir / f"run_{run}.txt",
                    gateway_rps=80.0 + run,
                    direct_rps=100.0 + run,
                    scenario=scenario,
                )
        (valid / "dns").mkdir(parents=True)
        for run in range(1, 4):
            _write_full_dns_run(valid / "dns" / f"run_{run}.txt")
        (valid / "runner_health.json").write_text(
            json.dumps({"avg_steal_percent": 2.5, "runner_class": "ubuntu-26.04"}) + "\n",
            encoding="utf-8",
        )
        (valid / "logs").mkdir(parents=True, exist_ok=True)
        (valid / "logs" / "runner_health_probes.jsonl").write_text(
            _self_test_health_probes(3),
            encoding="utf-8",
        )
        (valid / "provenance.json").write_text(prov_path.read_text(encoding="utf-8"), encoding="utf-8")
        summary = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary["acceptance_gate"]["mesh_complete"] is True
        assert summary["acceptance_gate"]["hbone_complete"] is True
        assert summary["acceptance_gate"]["hbone_errors_ok"] is True
        assert summary["acceptance_gate"]["dns_complete"] is True
        assert summary["acceptance_gate"]["dns_errors_ok"] is True
        assert summary["acceptance_gate"]["provenance_complete"] is True
        assert summary["acceptance_gate"]["runner_health_ok"] is True
        assert summary["ready_to_publish_baselines"] is True
        assert summary["hbone"]["1kib_c50_30s"]["repetition_evidence"]["gateway"]["actual"] == 3
        assert summary["dns"]["repetition_evidence"]["gateway"]["upstream-forward/tcp"]["actual"] == 3
        write_draft_markdown(drafts, summary["provenance"], summary["mesh"], summary["hbone"], summary["dns"])
        assert (drafts / "mesh_baseline_draft.md").is_file()

        # Complete measurements without complete provenance must not pass.
        summary_without_provenance = build_summary(
            valid,
            {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_without_provenance["acceptance_gate"]["provenance_complete"] is False
        assert summary_without_provenance["ready_to_publish_baselines"] is False

        # A malformed per-run steal probe must not be silently ignored.
        probes_path = valid / "logs" / "runner_health_probes.jsonl"
        probes_path.write_text(
            _self_test_health_probes(3)
            + json.dumps(
                {
                    "phase": "dns",
                    "repetition": 4,
                    "avg_steal_percent": "not-a-number",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        summary_bad_probe = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_bad_probe["acceptance_gate"]["runner_health_ok"] is False
        assert summary_bad_probe["ready_to_publish_baselines"] is False
        probes_path.write_text(_self_test_health_probes(3), encoding="utf-8")

        # successful exact-interval evidence with a real 0.0% steal is valid.
        (valid / "runner_health.json").write_text(
            json.dumps({"avg_steal_percent": 0.0, "runner_class": "ubuntu-26.04"}) + "\n",
            encoding="utf-8",
        )
        zero_probes = [
            {
                "phase": "mesh",
                "scenario": bench,
                "repetition": 1,
                "avg_steal_percent": 0.0,
                "coverage": "workload_interval",
            }
            for bench in MESH_BENCHES
        ]
        zero_probes.extend(
            {
                "phase": "hbone",
                "scenario": scenario["key"],
                "repetition": repetition,
                "avg_steal_percent": 0.0,
                "coverage": "workload_interval",
            }
            for scenario in HBONE_SCENARIOS
            for repetition in range(1, 4)
        )
        zero_probes.extend(
            {
                "phase": "dns",
                "repetition": repetition,
                "avg_steal_percent": 0.0,
                "coverage": "workload_interval",
            }
            for repetition in range(1, 4)
        )
        probes_path.write_text(
            "".join(json.dumps(probe) + "\n" for probe in zero_probes),
            encoding="utf-8",
        )
        summary_zero = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_zero["acceptance_gate"]["runner_health_ok"] is True
        assert summary_zero["ready_to_publish_baselines"] is True

        # parse failure cannot become healthy evidence
        (valid / "runner_health.json").write_text(
            json.dumps({"avg_steal_percent": None, "runner_class": "ubuntu-26.04"}) + "\n",
            encoding="utf-8",
        )
        probes_path.write_text(_self_test_health_probes(3), encoding="utf-8")
        summary_null_pre = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_null_pre["acceptance_gate"]["runner_health_ok"] is False
        assert summary_null_pre["ready_to_publish_baselines"] is False

        (valid / "runner_health.json").write_text(
            json.dumps({"avg_steal_percent": 2.5, "runner_class": "ubuntu-26.04"}) + "\n",
            encoding="utf-8",
        )
        probes_path.write_text("", encoding="utf-8")
        summary_missing = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_missing["acceptance_gate"]["runner_health_ok"] is False
        assert summary_missing["ready_to_publish_baselines"] is False

        # end-without-start evidence is not a healthy interval measurement.
        probes_path.write_text(
            json.dumps(
                {
                    "phase": "dns",
                    "repetition": 1,
                    "avg_steal_percent": None,
                    "coverage": None,
                    "error": "missing_begin",
                }
            )
            + "\n"
            + _self_test_health_probes(3),
            encoding="utf-8",
        )
        summary_end_without_start = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_end_without_start["acceptance_gate"]["runner_health_ok"] is False
        assert summary_end_without_start["ready_to_publish_baselines"] is False

        # A pre-run sample without workload_interval coverage is not exact-interval evidence.
        uncovered = json.loads(_self_test_health_probes(3).splitlines()[0])
        del uncovered["coverage"]
        probes_path.write_text(
            json.dumps(uncovered)
            + "\n"
            + _self_test_health_probes(3),
            encoding="utf-8",
        )
        summary_uncovered = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_uncovered["acceptance_gate"]["runner_health_ok"] is False
        assert summary_uncovered["ready_to_publish_baselines"] is False
        probes_path.write_text(_self_test_health_probes(3), encoding="utf-8")

        # mesh Criterion windows require their own interval evidence
        hbone_dns_only = [
            {
                "phase": "hbone",
                "scenario": scenario["key"],
                "repetition": repetition,
                "avg_steal_percent": 3.0,
                "coverage": "workload_interval",
            }
            for scenario in HBONE_SCENARIOS
            for repetition in range(1, 4)
        ]
        hbone_dns_only.extend(
            {
                "phase": "dns",
                "repetition": repetition,
                "avg_steal_percent": 2.0,
                "coverage": "workload_interval",
            }
            for repetition in range(1, 4)
        )
        probes_path.write_text(
            "".join(json.dumps(probe) + "\n" for probe in hbone_dns_only),
            encoding="utf-8",
        )
        summary_missing_mesh = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_missing_mesh["acceptance_gate"]["runner_health_ok"] is False
        assert summary_missing_mesh["ready_to_publish_baselines"] is False
        probes_path.write_text(_self_test_health_probes(3), encoding="utf-8")

        # excessive steal on a workload-interval probe fails publication
        probes_path.write_text(
            _self_test_health_probes(3).replace(
                '"avg_steal_percent": 3.0',
                '"avg_steal_percent": 9.0',
                1,
            ),
            encoding="utf-8",
        )
        summary_interval_steal = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_interval_steal["acceptance_gate"]["runner_health_ok"] is False
        assert summary_interval_steal["ready_to_publish_baselines"] is False
        probes_path.write_text(_self_test_health_probes(3), encoding="utf-8")

        # excessive steal fails publication even with complete metrics
        (valid / "runner_health.json").write_text(
            json.dumps({"avg_steal_percent": 9.0}) + "\n",
            encoding="utf-8",
        )
        summary_steal = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="all",
        )
        assert summary_steal["acceptance_gate"]["runner_health_ok"] is False
        assert summary_steal["ready_to_publish_baselines"] is False

        # Restore healthy steal evidence for subsequent suite-selection checks.
        (valid / "runner_health.json").write_text(
            json.dumps({"avg_steal_percent": 2.5, "runner_class": "ubuntu-26.04"}) + "\n",
            encoding="utf-8",
        )

        # partial-suite acceptance only requires selected gates
        partial_gates = selected_suite_gates(
            {
                "mesh_complete": False,
                "hbone_complete": True,
                "hbone_errors_ok": True,
                "dns_complete": False,
                "dns_errors_ok": False,
                "provenance_complete": True,
                "runner_health_ok": True,
                "ready_to_publish_baselines": False,
            },
            "hbone",
        )
        assert partial_gates["suites_supported"] is True
        assert partial_gates["hbone_complete"] is True
        assert "mesh_complete" not in partial_gates
        assert selected_suite_accepted(
            {
                "mesh_complete": False,
                "hbone_complete": True,
                "hbone_errors_ok": True,
                "dns_complete": False,
                "dns_errors_ok": False,
                "provenance_complete": True,
                "runner_health_ok": True,
                "ready_to_publish_baselines": False,
            },
            "hbone",
        )
        assert not selected_suite_accepted(
            {
                "mesh_complete": True,
                "hbone_complete": False,
                "hbone_errors_ok": True,
                "dns_complete": True,
                "dns_errors_ok": True,
                "provenance_complete": True,
                "runner_health_ok": True,
                "ready_to_publish_baselines": False,
            },
            "hbone",
        )

        # unsupported suite selection fails closed (does not reduce to health-only)
        assert normalize_suites("nope") is None
        assert suites_supported("all")
        assert not suites_supported("mesh,hbone")
        invalid_gates = selected_suite_gates(
            {
                "mesh_complete": True,
                "hbone_complete": True,
                "hbone_errors_ok": True,
                "dns_complete": True,
                "dns_errors_ok": True,
                "provenance_complete": True,
                "runner_health_ok": True,
                "ready_to_publish_baselines": True,
            },
            "not-a-suite",
        )
        assert invalid_gates == {
            "suites_supported": False,
            "provenance_complete": True,
            "runner_health_ok": True,
        }
        assert not selected_suite_accepted(
            {
                "mesh_complete": True,
                "hbone_complete": True,
                "hbone_errors_ok": True,
                "dns_complete": True,
                "dns_errors_ok": True,
                "provenance_complete": True,
                "runner_health_ok": True,
                "ready_to_publish_baselines": True,
            },
            "not-a-suite",
        )
        summary_invalid = build_summary(
            valid,
            load_json(valid / "provenance.json") or {},
            required_repetitions(3),
            suites="bogus",
        )
        assert summary_invalid["acceptance_gate"]["suites_supported"] is False
        assert summary_invalid["selected_suite_accepted"] is False
        assert summary_invalid["ready_to_publish_baselines"] is False
        assert "mesh_complete" not in summary_invalid["selected_suite_gates"]

        # write + check-acceptance path
        out_path.write_text(json.dumps(summary) + "\n", encoding="utf-8")
        assert check_acceptance(out_path, "all") == 0
        assert check_acceptance(out_path, "bogus") == 1

    print("summarize_mesh_baseline_results self-test passed")
    return 0


def build_summary(
    results_root: Path,
    provenance: dict[str, Any],
    required_reps: int,
    *,
    suites: str,
) -> dict[str, Any]:
    mesh = summarize_mesh(results_root / "mesh" / "criterion")
    hbone = summarize_hbone(results_root / "hbone", required_reps)
    dns = summarize_dns(results_root / "dns", required_reps)
    runner_health = load_runner_health(results_root, suites, required_reps)
    suites_ok = suites_supported(suites)

    acceptance = {
        "suites_supported": suites_ok,
        "provenance_complete": provenance_complete(
            provenance,
            suites,
            required_reps,
        ),
        "mesh_complete": mesh_complete(mesh),
        "hbone_complete": all(v.get("complete") for v in hbone.values()) if hbone else False,
        "hbone_errors_ok": all(v.get("errors_ok") for v in hbone.values()) if hbone else False,
        "dns_complete": bool(dns.get("complete")),
        "dns_errors_ok": bool(dns.get("errors_ok")),
        "runner_health_ok": bool(runner_health.get("ok")),
        "expected_e2e_repetitions": required_reps,
        "min_e2e_repetitions": MIN_E2E_REPETITIONS,
        "max_cpu_steal_percent": MAX_CPU_STEAL_PERCENT,
    }
    ready = all(
        [
            suites_ok,
            acceptance["provenance_complete"],
            acceptance["mesh_complete"],
            acceptance["hbone_complete"],
            acceptance["hbone_errors_ok"],
            acceptance["dns_complete"],
            acceptance["dns_errors_ok"],
            acceptance["runner_health_ok"],
        ]
    )
    acceptance["ready_to_publish_baselines"] = ready
    selected = selected_suite_gates(acceptance, suites)
    return {
        "schema_version": 2,
        "provenance": provenance,
        "suites_selected": suites,
        "mesh": mesh,
        "hbone": hbone,
        "dns": dns,
        "runner_health": runner_health,
        "acceptance_gate": acceptance,
        "selected_suite_gates": selected,
        "selected_suite_accepted": selected_suite_accepted(acceptance, suites),
        "ready_to_publish_baselines": ready,
    }


def check_acceptance(summary_path: Path, suites: str) -> int:
    summary = load_json(summary_path)
    if not isinstance(summary, dict):
        print(f"::error::missing or malformed summary at {summary_path}")
        return 1
    acceptance = summary.get("acceptance_gate")
    if not isinstance(acceptance, dict):
        print("::error::summary.acceptance_gate missing")
        return 1
    if not suites_supported(suites):
        print(
            "::error::unsupported suites value "
            f"{suites!r} (expected one of: {', '.join(sorted(SUPPORTED_SUITES))})"
        )
        return 1
    # Prefer gates recomputed for the suites argument so callers can override.
    gates = selected_suite_gates(acceptance, suites)
    print(json.dumps({"suites": suites, "selected_suite_gates": gates}, indent=2))
    if not all(gates.values()):
        failed = [name for name, ok in gates.items() if not ok]
        print(f"::error::selected suite acceptance failed: {', '.join(failed)}")
        return 1
    print(f"selected suite acceptance OK for suites={suites}")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    if args.check_acceptance:
        return check_acceptance(args.summary, args.suites)

    required_reps = required_repetitions(args.expected_repetitions)
    provenance = load_json(args.provenance) or {}
    summary = build_summary(
        args.results_root,
        provenance,
        required_reps,
        suites=args.suites,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    write_draft_markdown(
        args.draft_markdown_dir,
        provenance,
        summary["mesh"],
        summary["hbone"],
        summary["dns"],
    )
    print(json.dumps(summary["acceptance_gate"], indent=2))
    print(json.dumps(summary["selected_suite_gates"], indent=2))
    print(f"selected_suite_accepted={summary['selected_suite_accepted']}")
    print(f"ready_to_publish_baselines={summary['ready_to_publish_baselines']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
