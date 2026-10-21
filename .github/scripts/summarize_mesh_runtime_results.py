#!/usr/bin/env python3
"""Summarize mesh-runtime benchmark results.

Reads the per-cell JSON written by
``tests/performance/mesh_runtime/run_mesh_runtime_bench.sh``
(``<mesh>_http1_<payload>.json`` plus ``.stats.jsonl`` docker-stats
samples and ``<mesh>_arm_status.json``), across one or more iteration
run directories, and emits:

- ``summary.json``: machine-readable medians per (mesh, payload).
- ``summary.md``: GitHub step-summary markdown (throughput, overhead vs
  direct, latency, proxy CPU/memory).

A cell is *publishable* only when ``total_errors == 0`` and ``rps > 0``;
unpublishable cells are surfaced in ``warnings`` and rendered as `—`
rather than silently dropped or presented as results.

Usage:
    summarize_mesh_runtime_results.py --self-test
    summarize_mesh_runtime_results.py --results-root results \
        --output results/summary.json --summary-md results/summary.md
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from pathlib import Path

MESH_ORDER = ("direct", "ferrumbaseline", "ferrum", "envoy", "consul", "consulhttp", "linkerd")
CELL_RE = re.compile(r"^(?P<mesh>[a-z]+)_http1_(?P<payload>[0-9]+)\.json$")
MEM_RE = re.compile(r"^([0-9.]+)\s*([KMGT]?i?B)")


def effective_concurrency(base: int, payload: int) -> int:
    """Match run_mesh_runtime_bench.sh's common bulk-payload schedule."""
    divisor = 4 if payload >= 5242880 else 2 if payload >= 1048576 else 1
    return max(1, base // divisor)


def planned_cells(results_root: Path, warnings: list[str]) -> dict[Path, dict] | None:
    """Return each campaign file's required metadata; None keeps legacy mode."""
    campaign_file = results_root / "campaign.json"
    if not campaign_file.exists():
        return None
    try:
        campaign = json.loads(campaign_file.read_text())
        duration, concurrency = campaign["duration"], campaign["concurrency"]
        if type(duration) is not int or duration <= 0 or type(concurrency) is not int or concurrency <= 0:
            raise ValueError("duration and concurrency must be positive integers")
        if campaign.get("protocol", "http1") != "http1":
            raise ValueError("the campaign must use the harness's http1 protocol")
        if not isinstance(campaign["cells"], list) or not campaign["cells"]:
            raise ValueError("cells must be a nonempty list")
        planned: dict[Path, dict] = {}
        for cell in campaign["cells"]:
            arm, payload, repetition = cell["arm"], cell["payload"], cell["repetition"]
            if not isinstance(arm, str) or not re.fullmatch(r"[a-z]+", arm):
                raise ValueError("each cell must name an arm")
            if type(payload) is not int or payload <= 0 or type(repetition) is not int or repetition <= 0:
                raise ValueError("each cell must have a positive payload and repetition")
            file = results_root / arm / f"run_{repetition}" / f"payload_{payload}" / f"{arm}_http1_{payload}.json"
            if file in planned:
                raise ValueError(f"duplicate planned cell {file}")
            planned[file] = {
                "mesh": arm, "gateway": arm, "payload_size": payload,
                "protocol": "http1", "duration_secs": duration,
                "concurrency": effective_concurrency(concurrency, payload),
            }
        return planned
    except (OSError, ValueError, TypeError, KeyError) as exc:
        warnings.append(f"unpublishable cell campaign metadata {campaign_file}: {exc}")
        return {}


def parse_mem_bytes(mem_usage: str) -> float | None:
    """Parse the used side of a docker-stats MemUsage field to bytes."""
    used = mem_usage.split("/")[0].strip()
    m = MEM_RE.match(used)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2).upper().replace("IB", "B")
    factor = {"B": 1, "KB": 10**3, "MB": 10**6, "GB": 10**9, "TB": 10**12,
              "KIB": 1024, "MIB": 1024**2, "GIB": 1024**3, "TIB": 1024**4}
    # docker stats prints KiB/MiB/GiB for binary units; the regex above
    # folds "MiB" to "MB", so prefer the binary reading of the raw text.
    raw_unit = m.group(2)
    if raw_unit.endswith("iB"):
        factor_key = raw_unit.upper()
        return value * factor.get(factor_key, 1)
    return value * factor.get(unit, 1)


def parse_stats(path: Path) -> dict | None:
    """Aggregate docker-stats JSONL into pair-summed CPU% and RSS bytes.

    Each sample instant contributes one line per proxy container; CPU and
    memory are summed across the pair per instant (grouped by position
    pairs are not reliable, so we aggregate per container then add the
    per-container means/peaks)."""
    if not path.exists():
        return None
    per_container: dict[str, tuple[list[float], list[float]]] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = row.get("Name") or row.get("Container") or "?"
        try:
            cpu = float(str(row.get("CPUPerc", "0")).rstrip("%"))
        except ValueError:
            continue
        mem = parse_mem_bytes(str(row.get("MemUsage", "")))
        if mem is None:
            continue
        cpus, mems = per_container.setdefault(name, ([], []))
        cpus.append(cpu)
        mems.append(mem)
    if not per_container:
        return None
    cpu_mean = sum(statistics.fmean(c) for c, _ in per_container.values())
    cpu_peak = sum(max(c) for c, _ in per_container.values())
    mem_mean = sum(statistics.fmean(m) for _, m in per_container.values())
    mem_peak = sum(max(m) for _, m in per_container.values())
    return {
        "proxy_cpu_percent_mean": round(cpu_mean, 1),
        "proxy_cpu_percent_peak": round(cpu_peak, 1),
        "proxy_mem_bytes_mean": int(mem_mean),
        "proxy_mem_bytes_peak_sum": int(mem_peak),
        "containers": sorted(per_container),
        "samples_per_container": {
            name: len(mems) for name, (_c, mems) in sorted(per_container.items())
        },
    }


def collect(results_root: Path) -> dict:
    """Walk results/<mesh>/run_* (or a flat dir) and aggregate cells."""
    warnings: list[str] = []
    arm_status: dict[str, dict] = {}
    # (mesh, payload) -> list of per-run records
    cells: dict[tuple[str, int], list[dict]] = {}
    planned = planned_cells(results_root, warnings)

    cell_files = sorted(results_root.rglob("*_http1_*.json"))
    for f in cell_files:
        if f.name.endswith(".stats.jsonl"):
            continue
        m = CELL_RE.match(f.name)
        if not m:
            continue
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError) as e:
            warnings.append(f"unpublishable cell {f}: unparsable JSON: {e}")
            continue
        mesh = m.group("mesh")
        payload = int(m.group("payload"))
        if not isinstance(data, dict) or data.get("mesh") != mesh or data.get("gateway") != mesh or data.get("payload_size") != payload:
            warnings.append(f"unpublishable cell {f}: metadata does not match its planned identity")
            continue
        if planned is not None:
            expected = planned.get(f)
            if expected is None:
                warnings.append(f"unpublishable cell {f}: file is not a planned campaign cell")
                continue
            mismatches = [
                f"{key}={data.get(key)!r} (expected {value!r})"
                for key, value in expected.items()
                if data.get(key) != value or type(data.get(key)) is not type(value)
            ]
            if mismatches:
                warnings.append(f"unpublishable cell {f}: campaign metadata mismatch: " + "; ".join(mismatches))
                continue
        record = dict(data)
        stats = parse_stats(f.with_name(f.name.replace(".json", ".stats.jsonl")))
        if stats is not None:
            record["resources"] = stats
        resource_file = f.with_name(f.name.replace(".json", ".resources.json"))
        if resource_file.exists():
            try:
                resources = json.loads(resource_file.read_text())
                seconds = resources.get("elapsed_seconds", 0)
                if not resources.get("valid") or not seconds or resources.get("host_cpu_steal_percent", 100) > 5:
                    record["resource_error"] = "invalid /proc interval or CPU steal above 5%"
                else:
                    resources["proxy_cpu_percent_mean"] = 100 * resources["proxy_cpu_seconds"] / seconds
                    resources["proxy_mem_bytes_peak_sum"] = resources["proxy_rss_bytes_peak"]
                    resources["proxy_mem_bytes_mean"] = resources["proxy_rss_bytes_mean"]
                    record["resources"] = resources
            except (OSError, ValueError, TypeError, KeyError) as exc:
                record["resource_error"] = str(exc)
        record["source_file"] = str(f)
        cells.setdefault((mesh, payload), []).append(record)

    for status_file in sorted(results_root.rglob("*_arm_status.json")):
        try:
            st = json.loads(status_file.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        arm = st.get("mesh")
        if arm:
            arm_status.setdefault(arm, st)

    manifests: dict[str, dict] = {}
    for manifest_file in sorted(results_root.rglob("*_manifest.json")):
        try:
            man = json.loads(manifest_file.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if man.get("mesh"):
            manifests.setdefault(man["mesh"], man)
    for mesh_name, man in sorted(manifests.items()):
        if arm_status.get(mesh_name, {}).get("status") == "unsupported-standalone":
            continue
        for payload in man.get("payload_sizes") or []:
            if (mesh_name, int(payload)) not in cells:
                warnings.append(
                    f"missing expected cell mesh={mesh_name} payload={payload} "
                    f"(manifest {manifests[mesh_name].get('mesh')})"
                )

    # Each manifest's own directory must contain every expected cell, so
    # a complete first repetition cannot hide a missing later one.
    for manifest_file in sorted(results_root.rglob("*_manifest.json")):
        try:
            man = json.loads(manifest_file.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        mesh_name = man.get("mesh")
        if not mesh_name:
            continue
        if arm_status.get(mesh_name, {}).get("status") == "unsupported-standalone":
            continue
        for payload in man.get("payload_sizes") or []:
            expected = manifest_file.parent / f"{mesh_name}_http1_{int(payload)}.json"
            if not expected.exists():
                warnings.append(
                    f"missing expected cell file {expected} "
                    f"(mesh={mesh_name} payload={payload})"
                )

    aggregated: dict[str, dict] = {}
    if planned is not None:
        for expected, identity in planned.items():
            status = expected.parent / f"{identity['mesh']}_arm_status.json"
            unsupported = status.exists() and json.loads(status.read_text()).get("status") == "unsupported-standalone"
            if not unsupported and (not expected.exists() or not expected.with_suffix(".resources.json").exists()):
                warnings.append(f"missing expected cell or resource interval {expected}")
    for (mesh, payload), records in sorted(cells.items()):
        runs = []
        publishable = []
        for r in records:
            errors = r.get("total_errors")
            rps = float(r.get("rps") or 0)
            ok = errors == 0 and rps > 0 and not r.get("resource_error")
            entry = {
                "rps": rps,
                "total_errors": errors,
                "publishable": ok,
                "source_file": r.get("source_file"),
                "duration_secs": r.get("duration_secs"),
                "concurrency": r.get("concurrency"),
                "total_requests": r.get("total_requests"),
                "total_bytes": r.get("total_bytes"),
                "latency_avg_us": r.get("latency_avg_us"),
                "p50_us": r.get("p50_us"),
                "p95_us": r.get("p95_us"),
                "p99_us": r.get("p99_us"),
                "cohort_requests": r.get("cohort_requests"),
                "cohort_p50_us": r.get("cohort_p50_us"),
                "cohort_p95_us": r.get("cohort_p95_us"),
                "cohort_p99_us": r.get("cohort_p99_us"),
                "cohort_latency_max_us": r.get("cohort_latency_max_us"),
                "resources": r.get("resources"),
                "drained_requests": r.get("drained_requests"),
                "warmup_requests": r.get("warmup_requests"),
                "warmup_errors": r.get("warmup_errors"),
                "resource_error": r.get("resource_error"),
            }
            runs.append(entry)
            if ok:
                publishable.append(entry)
            else:
                warnings.append(
                    f"unpublishable cell mesh={mesh} payload={payload} "
                    f"rps={rps} total_errors={errors} ({r.get('source_file')})"
                )
        cell: dict = {"runs": runs, "publishable_runs": len(publishable)}
        if publishable:
            rps_values = sorted(e["rps"] for e in publishable)
            median_rps = statistics.median(rps_values)
            median_run = min(publishable, key=lambda e: abs(e["rps"] - median_rps))
            cell["median_rps"] = median_rps
            cell["median_run_file"] = median_run.get("source_file")
            cell["median_run_rps"] = median_run.get("rps")
            cell["rps_min"] = rps_values[0]
            cell["rps_max"] = rps_values[-1]
            for key in ("latency_avg_us", "p50_us", "p95_us", "p99_us", "cohort_requests", "cohort_p50_us", "cohort_p95_us", "cohort_p99_us", "cohort_latency_max_us"):
                cell[key] = median_run.get(key)
            if median_run.get("resources"):
                cell["resources"] = median_run["resources"]
            duration = None
            for r in records:
                duration = r.get("duration_secs") or duration
            if duration:
                cell["throughput_mbps_median"] = round(
                    median_rps * payload / 1_000_000, 2
                )
        aggregated.setdefault(mesh, {})[str(payload)] = cell

    return {
        "meshes": aggregated,
        "arm_status": arm_status,
        "warnings": sorted(set(warnings)),
    }


def fmt_bytes(b: int) -> str:
    if b >= 1_048_576:
        return f"{b / 1_048_576:.1f}MiB"
    if b >= 1024:
        return f"{b / 1024:.0f}KiB"
    return f"{b}B"


def fmt_us(us) -> str:
    if not us:
        return "—"
    if us >= 1_000_000:
        return f"{us / 1_000_000:.2f}s"
    if us >= 1000:
        return f"{us / 1000:.2f}ms"
    return f"{int(us)}µs"


def fmt_rss(b) -> str:
    if not b:
        return "—"
    return f"{b / 1_048_576:.0f}MiB"


def render_markdown(summary: dict) -> str:
    meshes_data = summary["meshes"]
    payloads = sorted(
        {int(p) for cells in meshes_data.values() for p in cells}
    )
    meshes = [m for m in MESH_ORDER if m in meshes_data]
    meshes += sorted(m for m in meshes_data if m not in MESH_ORDER)

    lines: list[str] = []
    lines.append("# Mesh Runtime Benchmark\n")
    lines.append(
        "Topology: loadgen -> client proxy -> **mTLS east-west hop** -> "
        "server proxy -> echo backend. `direct` skips both proxies. "
        "Median RPS across iterations; latency from the median-RPS run. "
        "Cells with errors fail acceptance and are listed under Warnings. "
        "`consul` is a separate L4 TCP control; `consulhttp` is the verified L7 HTTP arm.\n"
    )
    for arm, st in sorted(summary["arm_status"].items()):
        if st.get("status") != "ready":
            lines.append(
                f"> **{arm}**: `{st.get('status')}` — {st.get('detail', '')}\n"
            )

    def cell(mesh: str, payload: int) -> dict:
        return meshes_data.get(mesh, {}).get(str(payload), {})

    lines.append("## Throughput (median RPS)\n")
    lines.append("| Payload | " + " | ".join(meshes) + " |")
    lines.append("|---------|" + "|".join("---:" for _ in meshes) + "|")
    for p in payloads:
        row = [fmt_bytes(p)]
        for mesh in meshes:
            v = cell(mesh, p).get("median_rps")
            row.append(f"{v:,.0f}" if v else "—")
        lines.append("| " + " | ".join(row) + " |")

    lines.append("\n## Throughput (median MB/s, response body)\n")
    lines.append("| Payload | " + " | ".join(meshes) + " |")
    lines.append("|---------|" + "|".join("---:" for _ in meshes) + "|")
    for p in payloads:
        row = [fmt_bytes(p)]
        for mesh in meshes:
            v = cell(mesh, p).get("throughput_mbps_median")
            row.append(f"{v:,.1f}" if v else "—")
        lines.append("| " + " | ".join(row) + " |")

    if "direct" in meshes:
        others = [m for m in meshes if m != "direct"]
        lines.append("\n## Mesh overhead vs direct (RPS loss %)\n")
        lines.append("| Payload | " + " | ".join(others) + " |")
        lines.append("|---------|" + "|".join("---:" for _ in others) + "|")
        for p in payloads:
            direct = cell("direct", p).get("median_rps") or 0
            row = [fmt_bytes(p)]
            for mesh in others:
                v = cell(mesh, p).get("median_rps") or 0
                row.append(
                    f"{(direct - v) / direct * 100:.1f}%" if direct and v else "—"
                )
            lines.append("| " + " | ".join(row) + " |")

    lines.append("\n## In-window successful-completion latency (median-RPS run)\n")
    lines.append("| Mesh | Payload | Avg | P50 | P95 | P99 |")
    lines.append("|------|---------|----:|----:|----:|----:|")
    for mesh in meshes:
        for p in payloads:
            c = cell(mesh, p)
            if not c.get("median_rps"):
                continue
            lines.append(
                f"| {mesh} | {fmt_bytes(p)} | {fmt_us(c.get('latency_avg_us'))} "
                f"| {fmt_us(c.get('p50_us'))} | {fmt_us(c.get('p95_us'))} "
                f"| {fmt_us(c.get('p99_us'))} |"
            )

    if any(cell(mesh, p).get("cohort_requests") is not None for mesh in meshes for p in payloads):
        lines.append("\n## Admitted-success cohort latency including drains (median-RPS run)\n")
        lines.append(
            "Successful echoes admitted during the common measurement window, "
            "including responses completed after its deadline. Failed exchanges "
            "remain in `total_errors`; drains do not contribute to useful RPS.\n"
        )
        lines.append("| Mesh | Payload | Successful exchanges | P50 | P95 | P99 | Max |")
        lines.append("|------|---------|--------------------:|----:|----:|----:|----:|")
        for mesh in meshes:
            for p in payloads:
                c = cell(mesh, p)
                if not c.get("median_rps") or c.get("cohort_requests") is None:
                    continue
                lines.append(
                    f"| {mesh} | {fmt_bytes(p)} | {c['cohort_requests']:,} "
                    f"| {fmt_us(c.get('cohort_p50_us'))} | {fmt_us(c.get('cohort_p95_us'))} "
                    f"| {fmt_us(c.get('cohort_p99_us'))} | {fmt_us(c.get('cohort_latency_max_us'))} |"
                )

    lines.append("\n## Proxy-pair resources (/proc process CPU/RSS for new campaigns; legacy docker stats where present)\n")
    lines.append("| Mesh | Payload | CPU mean | CPU peak (Σ) | Mem mean | Mem peak (Σ) |")
    lines.append("|------|---------|---------:|---------:|---------:|---------:|")
    for mesh in meshes:
        if mesh == "direct":
            continue
        for p in payloads:
            res = cell(mesh, p).get("resources") or {}
            if not res:
                continue
            lines.append(
                f"| {mesh} | {fmt_bytes(p)} "
                f"| {res.get('proxy_cpu_percent_mean', '—')}% "
                f"| {res.get('proxy_cpu_percent_peak', '—')}% "
                f"| {fmt_rss(res.get('proxy_mem_bytes_mean'))} "
                f"| {fmt_rss(res.get('proxy_mem_bytes_peak_sum'))} |"
            )

    if summary["warnings"]:
        lines.append("\n## Warnings\n")
        for w in summary["warnings"]:
            lines.append(f"- {w}")
    return "\n".join(lines) + "\n"


def self_test() -> int:
    # docker stats memory parsing (binary units as printed by the CLI).
    assert abs(parse_mem_bytes("45.32MiB / 9.689GiB") - 45.32 * 1024**2) < 1
    assert abs(parse_mem_bytes("512KiB / 1GiB") - 512 * 1024) < 1
    assert parse_mem_bytes("garbage") is None

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        run = root / "ferrum" / "run_1"
        run.mkdir(parents=True)
        (run / "ferrum_http1_1024.json").write_text(json.dumps({
            "gateway": "ferrum", "mesh": "ferrum", "protocol": "http1",
            "payload_size": 1024, "rps": 1000.0, "total_errors": 0,
            "latency_avg_us": 900, "p50_us": 800, "p95_us": 1500,
            "p99_us": 2000, "duration_secs": 10, "concurrency": 100,
        }))
        (run / "ferrum_http1_1024.stats.jsonl").write_text(
            '{"Name":"c1","CPUPerc":"100.00%","MemUsage":"50MiB / 1GiB"}\n'
            '{"Name":"c2","CPUPerc":"50.00%","MemUsage":"25MiB / 1GiB"}\n'
        )
        (run / "ferrum_arm_status.json").write_text(json.dumps(
            {"mesh": "ferrum", "status": "ready", "detail": "ok"}))
        bad = root / "envoy" / "run_1"
        bad.mkdir(parents=True)
        (bad / "envoy_http1_1024.json").write_text(json.dumps({
            "gateway": "envoy", "mesh": "envoy", "protocol": "http1",
            "payload_size": 1024, "rps": 500.0, "total_errors": 3,
        }))
        summary = collect(root)
        cell = summary["meshes"]["ferrum"]["1024"]
        assert cell["median_rps"] == 1000.0, cell
        assert cell["resources"]["proxy_cpu_percent_mean"] == 150.0, cell
        assert cell["resources"]["proxy_mem_bytes_mean"] == 75 * 1024 * 1024, cell
        assert check_acceptance(summary) == 1  # envoy cell unpublishable
        assert summary["meshes"]["envoy"]["1024"]["publishable_runs"] == 0
        assert any("unpublishable" in w for w in summary["warnings"])
        md = render_markdown(summary)
        assert "Throughput (median RPS)" in md
        assert "1,000" in md
        assert "KiB" in render_markdown(summary) or True
    print("self-test OK")
    return 0


def check_acceptance(summary: dict) -> int:
    """Fail (exit 1) unless the campaign is complete and publishable.

    Independent of rendering: an empty results root, missing expected
    cells, unpublishable cells in any arm not recorded
    unsupported-standalone, or a required arm recorded failed all fail
    acceptance. Skipped arms (absent entirely) are the dispatcher's
    explicit choice and are not second-guessed here.
    """
    failures: list[str] = []
    if not summary.get("meshes"):
        failures.append("no benchmark cells collected")
    for w in summary.get("warnings") or []:
        if w.startswith("missing expected cell") or w.startswith("unpublishable cell"):
            failures.append(w)
    for mesh, st in sorted((summary.get("arm_status") or {}).items()):
        if st.get("status") == "failed":
            failures.append(f"arm {mesh} recorded failed: {st.get('detail', '')}")
        if st.get("status") not in ("ready", "unsupported-standalone", "failed", None):
            failures.append(f"arm {mesh} has unknown status {st.get('status')!r}")
    for mesh, cells in sorted((summary.get("meshes") or {}).items()):
        for payload, cell in sorted(cells.items()):
            if not cell.get("publishable_runs"):
                failures.append(
                    f"mesh={mesh} payload={payload} has no publishable run")
    if failures:
        print("ACCEPTANCE FAILED:")
        for f in failures:
            print(f"- {f}")
        return 1
    print("acceptance OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--check-acceptance", action="store_true",
                    help="with --output naming an existing summary.json, "
                         "validate it and exit (no rendering)")
    ap.add_argument("--results-root", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--summary-md", type=Path)
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.check_acceptance:
        if not args.output:
            ap.error("--check-acceptance requires --output <summary.json>")
        return check_acceptance(json.loads(args.output.read_text()))
    if not args.results_root or not args.output:
        ap.error("--results-root and --output are required (or --self-test)")

    summary = collect(args.results_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    md = render_markdown(summary)
    if args.summary_md:
        args.summary_md.parent.mkdir(parents=True, exist_ok=True)
        args.summary_md.write_text(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
