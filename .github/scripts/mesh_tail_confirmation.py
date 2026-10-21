#!/usr/bin/env python3
"""One fixed, complete AA/AB tail confirmation. Never select favorable samples."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".github/scripts"))
sys.path.insert(0, str(ROOT / "tests/performance/multi_protocol"))
from benchmark_plan import gateway_order, paired_comparison
from benchmark_validity import sample_issues
import gateway_regression as gateway
import summarize_mesh_runtime_results as mesh_summary

BASELINE = "4a7be250e45a367314e3dec872ecbd512220558e"
CANDIDATE = "7c4e45b82e656c62b7133d86b23c7e37a2ef3b77"
SCENARIOS = ("mesh-1m", "mesh-5m", "http1-tls", "http2")
PAIRS, DURATION, WORK_SECS = 8, 30, 5700


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def read(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def blocks():
    """Cross-balance leg order independently of alternating comparison order.

    gateway_order's two-arm four-round pattern is C/R,R/C,R/C,C/R. Each
    order therefore occurs twice with AA-first and twice with AB-first.
    """
    result = []
    ordinal = 0
    for pair in range(1, PAIRS + 1):
        for scenario in SCENARIOS if pair % 2 else reversed(SCENARIOS):
            for phase in ("aa", "ab") if pair % 2 else ("ab", "aa"):
                members = []
                for arm in gateway_order(["ferrum", "ferrum-baseline"], pair):
                    ordinal += 1
                    leg = "comparison" if arm == "ferrum" else "reference"
                    members.append(dict(ordinal=ordinal, leg=leg, arm=arm,
                                        image_role="candidate" if phase == "ab" and leg == "comparison" else "baseline"))
                result.append(dict(pair=pair, scenario=scenario, phase=phase,
                                   directory=f"round_{pair:02d}/{scenario}/{phase}", members=members))
    return result


def provenance(images):
    result = dict(baseline_sha=BASELINE, candidate_sha=CANDIDATE,
                  harness_sha=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                  profile="release", features="cloud-secrets", image_ids={}, binary_sha256={}, dockerfile_sha256={})
    for role, revision in (("baseline", BASELINE), ("candidate", CANDIDATE), ("tools", None)):
        document = json.loads((images / f"{role}.image.json").read_text())[0]
        if not gateway.IMAGE_ID.fullmatch(document["Id"]):
            raise ValueError("missing immutable image ID")
        result["image_ids"][role] = document["Id"]
        if revision:
            if (images / f"{role}.source-sha").read_text().strip() != revision:
                raise ValueError("runtime source worktree differs from fixed revision")
            labels = document["Config"]["Labels"]
            if (labels.get("org.opencontainers.image.revision") != revision
                    or labels.get("io.ferrum.benchmark.profile") != "release"
                    or labels.get("io.ferrum.benchmark.features") != "cloud-secrets"):
                raise ValueError("image build source/profile/features differ")
            result["binary_sha256"][role] = (images / f"{role}.binary.sha256").read_text().split()[0]
            result["dockerfile_sha256"][role] = (images / f"{role}.dockerfile.sha256").read_text().split()[0]
    result["harness_file_sha256"] = {str(path.relative_to(ROOT)): digest(path) for path in (
        ROOT / ".github/scripts/mesh_tail_confirmation.py", ROOT / ".github/scripts/mesh_tail_confirmation.sh",
        ROOT / "tests/performance/mesh_runtime/run_mesh_runtime_bench.sh",
        ROOT / "tests/performance/multi_protocol/run_gateway_protocol_bench.sh",
        ROOT / "tests/performance/multi_protocol/configs/http1_tls_e2e_perf.yaml",
        ROOT / "tests/performance/multi_protocol/configs/http2_perf.yaml")}
    result["native_tools_sha256"] = {name: digest(ROOT / "tests/performance/multi_protocol/target/release" / name)
                                     for name in ("proto_bench", "proto_backend")}
    return result


def identity(block, source, run_id, host):
    payload = 5242880 if block["scenario"] == "mesh-5m" else 1048576
    members = [dict(cell, image_id=source["image_ids"][cell["image_role"]],
                    runtime_source_sha=CANDIDATE if cell["image_role"] == "candidate" else BASELINE)
               for cell in block["members"]]
    return dict(block, members=members, duration_secs=DURATION, payload_size=payload,
                effective_concurrency=25 if payload == 5242880 else 50,
                source_sha={"baseline": BASELINE, "candidate": CANDIDATE},
                image_ids=source["image_ids"], harness_sha=source["harness_sha"], host_id=host, run_id=run_id,
                latency_scope="successful admitted cohort including drains" if block["scenario"].startswith("mesh")
                else "completion-window successes only; full admitted-cohort tails unavailable")


def mesh_cell(cell, block, directory, source, run_id, deadline):
    directory.mkdir()
    env = {key: value for key, value in os.environ.items() if not key.startswith("FERRUM_")}
    env.update(TAIL_OPERATION="mesh-cell", TAIL_PAYLOAD=str(block["payload_size"]), TAIL_OUTPUT=str(directory),
               FERRUM_IMAGE=source["image_ids"][cell["image_role"]], TOOLS_IMAGE=source["image_ids"]["tools"],
               MESH_BENCH_RUN_ID=f"{run_id}-{cell['ordinal']}")
    status = dict(state="running", exit_code=None, cleanup_errors=[])
    write(directory / "status.json", status)
    child = process = None
    try:
        with (directory / "run.log").open("wb", buffering=0) as log:
            child = subprocess.Popen(["bash", ".github/scripts/mesh_tail_confirmation.sh"], env=env,
                                     start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            process = gateway.process_identity(child.pid)

            def forward():
                for line in child.stdout:
                    log.write(line)
                    print(line.decode(errors="replace"), end="", flush=True)

            reader = threading.Thread(target=forward, daemon=True)
            reader.start()
            try:
                status.update(exit_code=child.wait(timeout=max(1, min(210, deadline - time.monotonic()))), state="completed")
            except subprocess.TimeoutExpired:
                status["state"] = "timed_out"
            finally:
                status["cleanup_errors"] += gateway.cleanup_session(child, process, directory)
                process = None
                reader.join(timeout=2)
    finally:
        if child is not None and process is not None:
            status["cleanup_errors"] += gateway.cleanup_session(child, process, directory)
        env["TAIL_OPERATION"] = "mesh-cleanup"
        try:
            cleanup = subprocess.run(["bash", ".github/scripts/mesh_tail_confirmation.sh"], env=env,
                                     capture_output=True, timeout=45)
            (directory / "cleanup.log").write_bytes(cleanup.stdout + cleanup.stderr)
            if cleanup.returncode:
                status["cleanup_errors"].append("owned mesh containers did not clean up")
        except subprocess.TimeoutExpired:
            status["cleanup_errors"].append("owned mesh cleanup timed out")
        write(directory / "status.json", status)
    return status


def complete(status):
    return status.get("state") == "completed" and status.get("exit_code") == 0 and status.get("cleanup_errors") == []


def finite(value, minimum=0, maximum=math.inf):
    return type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum


def run(output):
    started, run_id = time.monotonic(), uuid.uuid4().hex
    output.mkdir(parents=True)
    source = provenance(output.parent / "images")
    host = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    planned = [identity(block, source, run_id, host) for block in blocks()]
    plan = dict(source=source, blocks=planned, planned_cells=128, work_budget_secs=WORK_SECS,
                workflow_measurement_timeout_secs=6000, mesh_cell_wall_secs=210,
                gateway_pair_wall_secs=300, mesh_cleanup_wall_secs=45,
                gateway_cleanup="existing owned session/container helper: 7+2+2+2*43 seconds",
                mesh_workload_limits=dict(warmup_secs=2, exchange_timeout_secs=10, readiness_timeout_secs=90,
                                          loadgen_wall_secs=72, force_kill_grace_secs=5),
                gateway_workload_limits=dict(readiness_timeout_secs=30, curl_timeout_secs=2,
                    docker_timeout_secs=10, docker_kill_grace_secs=2, client_wall_secs=158, client_kill_grace_secs=5),
                state="running", cleanup_complete=False, errors=[])
    write(output / "plan.json", plan)
    for block in planned:
        write(output / block["directory"] / "identity.json", block)
        write(output / block["directory"] / "status.json", dict(state="pending"))
    fixture = None
    try:
        plan["image_users"] = {role: gateway.image_identity(source["image_ids"][role], run_id, role)
                               for role in ("baseline", "candidate")}
        write(output / "plan.json", plan)
        fixture = Path(tempfile.mkdtemp(prefix="mesh-tail-confirm-", dir=os.environ.get("RUNNER_TEMP")))
        gateway.prepare_fixture(fixture)
        for block in planned:
            if time.monotonic() >= started + WORK_SECS:
                plan["errors"].append("work deadline reached; all remaining cells stay pending")
                break
            directory = output / block["directory"]
            write(directory / "status.json", dict(state="running"))
            if block["scenario"].startswith("mesh"):
                outcomes = [mesh_cell(cell, block, directory / cell["leg"], source, run_id, started + WORK_SECS)
                            for cell in block["members"]]
                status = dict(state="completed" if all(complete(item) for item in outcomes) else "failed",
                              exit_code=0 if all(complete(item) for item in outcomes) else 1, cleanup_errors=[])
            else:
                comparison = "candidate" if block["phase"] == "ab" else "baseline"
                status = gateway.run_protocol(block["scenario"], directory / "protocol", fixture, run_id,
                    dict(candidate_image_id=source["image_ids"][comparison], baseline_image_id=source["image_ids"]["baseline"]),
                    tail_pair=block["pair"], wall_secs=max(1, min(300, started + WORK_SECS - time.monotonic())))
            write(directory / "status.json", status)
            if not complete(status):
                plan["errors"].append(f"failed block {block['directory']}; remaining planned cells retained")
                break
        plan["state"] = "completed" if not plan["errors"] else "failed"
    except BaseException as error:
        plan["state"] = "interrupted" if isinstance(error, InterruptedError) else "failed"
        plan["errors"].append(f"{type(error).__name__}: {error}")
    finally:
        for role in ("candidate", "baseline"):
            try:
                gateway.runtime("identity-remove", timeout=28, RUN_ID=run_id, ROLE=role)
            except (subprocess.SubprocessError, OSError) as error:
                plan["errors"].append(f"identity cleanup {role}: {type(error).__name__}")
        try:
            if fixture is not None:
                shutil.rmtree(fixture)
            plan["cleanup_complete"] = True
        except OSError as error:
            plan["errors"].append(f"fixture cleanup: {type(error).__name__}")
        plan["elapsed_secs"] = time.monotonic() - started
        write(output / "plan.json", plan)


def observed(cell, block, directory):
    """Validate a raw cell without altering it; retain error/drain/resource data."""
    expected_id = cell["image_id"]
    payload = block["payload_size"]
    if block["scenario"].startswith("mesh"):
        root = directory / cell["leg"]
        raw = read(root / f"ferrum_http1_{payload}.json")
        resources = read(root / f"ferrum_http1_{payload}.resources.json")
        summary = mesh_summary.collect(root)
        if summary["warnings"] or summary["meshes"].get("ferrum", {}).get(str(payload), {}).get("publishable_runs") != 1:
            raise ValueError(f"mesh validity: {summary['warnings']}")
        if not complete(read(root / "status.json")):
            raise ValueError("mesh execution/cleanup incomplete")
        if (raw.get("cohort_requests") != raw.get("total_requests", 0) + raw.get("drained_requests", 0)
                or raw.get("drained_bytes") != raw.get("drained_requests", -1) * payload
                or raw.get("warmup_errors") != 0 or raw.get("total_errors") != 0):
            raise ValueError("mesh admitted-cohort/error/drain accounting incomplete")
        containers = resources.get("containers", [])
        if (len(containers) != 2 or any(item.get("image_id") != expected_id for item in containers)
                or not resources.get("valid") or resources.get("errors") or resources.get("rss_samples", 0) <= 0):
            raise ValueError("mesh proxy image/resource bracket mismatch")
        if (not finite(resources.get("elapsed_seconds"), DURATION * 0.95, DURATION * 1.05)
                or not finite(resources.get("proxy_cpu_seconds"))
                or not finite(resources.get("host_cpu_steal_percent"), 0, 5)
                or not finite(resources.get("proxy_rss_bytes_mean"))
                or not finite(resources.get("proxy_rss_bytes_peak"), resources["proxy_rss_bytes_mean"])):
            raise ValueError("mesh non-finite resources or CPU bracket outside30s +/-5%")
        expected = dict(mesh="ferrum", gateway="ferrum", protocol="http1", concurrency=block["effective_concurrency"])
        cpu = resources["proxy_cpu_seconds"]
        evidence = dict(proxy_cpu_seconds=cpu, bracket_secs=resources["elapsed_seconds"],
                        boundary_slack_secs=resources["elapsed_seconds"] - DURATION,
                        host_cpu_steal_percent=resources["host_cpu_steal_percent"],
                        proxy_rss_bytes_mean=resources["proxy_rss_bytes_mean"],
                        proxy_rss_bytes_peak=resources["proxy_rss_bytes_peak"])
    else:
        root = directory / "protocol"
        manifest = read(root / "manifest.json")
        if (manifest.get("gateways") != ["ferrum", "ferrum-baseline"] or manifest.get("pairs") != 1
                or manifest.get("tail_confirm_pair") != block["pair"] or manifest.get("duration") != DURATION
                or manifest.get("payload_sizes") != [payload] or manifest.get("host_id") != block["host_id"]
                or manifest.get("baseline_image") != block["image_ids"]["baseline"]
                or manifest.get("h2_window") != "default" or manifest.get("h2_observation_enabled") is not False):
            raise ValueError("gateway independent pair manifest mismatch")
        if not complete(read(root / "status.json")):
            raise ValueError("gateway execution/cleanup incomplete")
        pair = root / "pairs" / f"pair_{block['pair']:03d}"
        raw = read(pair / f"{cell['arm']}_{block['scenario']}_{payload}.json")
        runtime = json.loads((pair / "diagnostics" / f"{cell['arm']}_runtime.json").read_text())[0]
        if (runtime.get("Image") != expected_id or runtime.get("Config", {}).get("User") != "65532:65532"
                or "65532" not in runtime.get("HostConfig", {}).get("GroupAdd", [])):
            raise ValueError("gateway actual runtime image/user mismatch")
        expected = dict(gateway=cell["arm"], protocol="HTTP/1.1+TLS" if block["scenario"] == "http1-tls" else "HTTP/2",
                        concurrency=50, effective_concurrency=50, pair=block["pair"], host_id=block["host_id"],
                        order_position=block["members"].index(cell) + 1,
                        gateway_order=[member["arm"] for member in block["members"]], sample_schema=2,
                        target="https://127.0.0.1:8443/echo")
        records = raw.get("process_usage", {}).get("measurement", [])
        proxies = [item for item in records if item.get("role") == "gateway"]
        bracketed = [item for item in records if item.get("role") in ("gateway", "backend")]
        if not proxies or any(not finite(item.get("boundary_slack_secs"), 0, DURATION * 0.05)
                              or not finite(item.get("bracket_secs"), DURATION, DURATION * 1.05)
                              or not math.isclose(item["bracket_secs"] - DURATION, item["boundary_slack_secs"], abs_tol=0.001)
                              for item in bracketed):
            raise ValueError("gateway CPU boundary slack/bracket unavailable, non-finite or outside5%")
        cpu = sum(item["cpu_seconds"] for item in proxies)
        evidence = dict(proxy_cpu_seconds=cpu, process_measurement=records,
                        boundary_slack_secs=max(item["boundary_slack_secs"] for item in proxies))
        for field in ("drain_requests", "drain_bytes"):
            if type(raw.get(field)) is not int or raw[field] < 0:
                raise ValueError(f"missing {field}")
        if raw["drain_bytes"] != raw["drain_requests"] * payload:
            raise ValueError("gateway drain byte accounting mismatch")
    expected.update(payload_size=payload, duration_secs=DURATION)
    if any(raw.get(key) != value or type(raw.get(key)) is not type(value) for key, value in expected.items()):
        raise ValueError("raw cell identity/duration/concurrency mismatch")
    problems = sample_issues(raw)
    if problems:
        raise ValueError(", ".join(problems))
    if not math.isclose(raw["rps"], raw["total_requests"] / DURATION, rel_tol=1e-9):
        raise ValueError("useful completion RPS denominator mismatch")
    row = dict(raw, pair=block["pair"], host_id=block["host_id"], effective_concurrency=block["effective_concurrency"],
               cpu_per_request=cpu / raw["total_requests"])
    return row, dict(cell, actual_image_id=expected_id, source_sha=cell["runtime_source_sha"],
                     resources=evidence, measurement=raw)


def check(output):
    output.mkdir(parents=True, exist_ok=True)
    issues, observations, comparisons, plan = [], [], [], {}
    try:
        plan = read(output / "plan.json")
        source = plan["source"]
        if (source.get("candidate_sha") != CANDIDATE or source.get("baseline_sha") != BASELINE
                or source.get("profile") != "release" or source.get("features") != "cloud-secrets"
                or not re.fullmatch(r"[0-9a-f]{40}", source.get("harness_sha", ""))
                or not all(gateway.IMAGE_ID.fullmatch(value) for value in source["image_ids"].values())):
            raise ValueError("fixed source/profile/image provenance mismatch")
        expected = [identity(block, source, plan["blocks"][0]["run_id"], plan["blocks"][0]["host_id"]) for block in blocks()]
        if plan["blocks"] != expected or plan.get("planned_cells") != 128:
            raise ValueError("complete fixed128-cell plan mismatch")
        if plan.get("state") != "completed" or plan.get("cleanup_complete") is not True or plan.get("errors"):
            issues.append(f"campaign execution/cleanup incomplete: {plan.get('errors')}")
        if any(plan.get("image_users", {}).get(role, {}).get(key) != 65532
               for role in ("baseline", "candidate") for key in ("uid", "gid")):
            issues.append("nonroot image UID/GID not confirmed")
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        issues.append(f"campaign provenance/plan: {error}")
        expected = []
    buckets = {}
    for block in expected:
        directory = output / block["directory"]
        block_issues = []
        try:
            if read(directory / "identity.json") != block or not complete(read(directory / "status.json")):
                block_issues.append("independent identity/execution manifest incomplete")
        except (OSError, ValueError) as error:
            block_issues.append(str(error))
        for cell in block["members"]:
            cell_issues, row = list(block_issues), None
            detail = dict(cell, directory=block["directory"], scenario=block["scenario"], phase=block["phase"], pair=block["pair"])
            try:
                row, evidence = observed(cell, block, directory)
                detail.update(evidence)
            except (OSError, ValueError, KeyError, TypeError, IndexError, ArithmeticError) as error:
                cell_issues.append(str(error))
            detail["issues"] = cell_issues
            observations.append(detail)
            issues += [f"{block['directory']}/{cell['leg']}: {issue}" for issue in cell_issues]
            buckets.setdefault((block["scenario"], block["phase"], cell["leg"]), []).append(row if not cell_issues else {})
    for scenario in SCENARIOS:
        metrics = ["rps", "p50_us", "p95_us", "p99_us", "latency_max_us", "cpu_per_request"]
        if scenario.startswith("mesh"):
            metrics += ["cohort_p50_us", "cohort_p95_us", "cohort_p99_us", "cohort_latency_max_us"]
        for phase in ("aa", "ab"):
            left, right = (buckets.get((scenario, phase, leg), []) for leg in ("reference", "comparison"))
            for metric in metrics:
                pairs = []
                for pair in range(PAIRS):
                    a = left[pair].get(metric) if pair < len(left) else None
                    b = right[pair].get(metric) if pair < len(right) else None
                    pairs.append(dict(pair=pair + 1, reference=a, comparison=b,
                                      ratio=b / a if isinstance(a, (int, float)) and a > 0 and isinstance(b, (int, float)) else None))
                try:
                    # Shared paired log interval; replace only the display metric
                    # in copies. Every original raw sample stays untouched.
                    stats = paired_comparison([dict(row, rps=row[metric]) for row in left],
                                              [dict(row, rps=row[metric]) for row in right], PAIRS)
                except (ValueError, KeyError, TypeError, ArithmeticError):
                    stats = dict(accepted=False, reason="incomplete/invalid metric cohort")
                valid = stats.pop("accepted")
                comparisons.append(dict(scenario=scenario, phase=phase, metric=metric, data_valid=valid,
                                        pairs=pairs, **stats))
                if not valid:
                    issues.append(f"{scenario}/{phase}/{metric}: incomplete/invalid eight-pair cohort")
    report = dict(data_valid=not issues, planned_cells=128, observed_cells=len(observations), issues=issues,
                  source=plan.get("source"), observations=observations, comparisons=comparisons,
                  performance_gate="descriptive final confirmation; no equivalence/noninferiority margin invented",
                  latency_scope="Mesh primary endpoint: successful admitted-cohort p99 including drains, with zero errors required. Gateway: completion-window quantiles only; no full admitted-cohort histogram. Errors and drain_requests retained; low window p99 cannot rule out slow drains.",
                  resource_scope="CPU brackets/slack are retained; RSS mean/peak are descriptive observations without causal attribution.",
                  policy="One prespecified confirmation; no selective sample omission or extra tuning/retest. Assess AA and AB together; adverse tails or inconclusive net benefit do not establish the runtime candidate.")
    write(output / "report.json", report)
    lines = ["# Latest-main tail confirmation", "", f"Data valid: {report['data_valid']}; cells: {len(observations)}/128.",
             "", report["latency_scope"], "", report["resource_scope"], "", report["policy"], "", report["performance_gate"], "",
             "All128 cell measurements, errors, warmup/drain counts, CPU brackets/slack and all eight per-pair ratios are in report.json.", "",
             "| Workload | Control/comparison | Metric | Geometric ratio | Shared paired95% interval | All8 pair ratios |",
             "|---|---|---|---:|---|---|"]
    for item in comparisons:
        value = f"{item['ratio']:.4f}" if item["data_valid"] else "invalid"
        ci = f"{item['ci95_low']:.4f}–{item['ci95_high']:.4f}" if item["data_valid"] else "invalid"
        ratios = ", ".join(f"{row['ratio']:.4f}" if row["ratio"] is not None else "missing" for row in item["pairs"])
        lines.append(f"| {item['scenario']} | {item['phase'].upper()} | {item['metric']} | {value} | {ci} | {ratios} |")
    lines += ["", *[f"- {issue}" for issue in issues]]
    (output / "report.md").write_text("\n".join(lines) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "check"))
    parser.add_argument("--output", type=Path, default=Path("results/confirmation"))
    args = parser.parse_args()
    if args.mode == "run":
        def interrupted(signum, frame):
            raise InterruptedError(f"signal {signum}")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        run(args.output.resolve())
    return 0 if check(args.output.resolve())["data_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
