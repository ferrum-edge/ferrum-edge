#!/usr/bin/env python3
"""Optional same-job gateway evidence; validity is a gate, performance is descriptive.

Reuse the protocol runner's schema, process brackets and paired log-ratio
intervals. Four pairs cannot establish equivalence. No performance tolerance or
absolute floor is changed by this lane; calibrate a tolerance with A/A first.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid

from benchmark_plan import gateway_order, paired_comparison
from benchmark_validity import expected_rows, sample_issues
from h1_diagnostic_campaign import process_identity, terminate_session

TOOLS = Path("tests/performance/multi_protocol")
PROTOCOLS = ("http1-tls", "http2")
GATEWAYS = ("direct", "ferrum", "ferrum-baseline")
SIZES = (10240, 1048576, 5242880)
PAIRS, DURATION, CONCURRENCY = 4, 15, 100
PROTOCOL_WALL_SECS = 1800
LATENCIES = ("p50_us", "p95_us", "p99_us", "latency_max_us")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def read_json(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def effective_concurrency(size):
    return max(4, CONCURRENCY // (4 if size >= 5242880 else 2 if size >= 1048576 else 1))


def cells():
    return [dict(protocol=protocol, gateway=gateway, payload_size=size, pair=pair,
                 order_position=gateway_order(list(GATEWAYS), pair).index(gateway) + 1,
                 effective_concurrency=effective_concurrency(size))
            for protocol in PROTOCOLS for pair in range(1, PAIRS + 1)
            for gateway in GATEWAYS for size in SIZES]


def validate_inputs():
    if not re.fullmatch(r"[0-9a-f]{40}", os.environ.get("BENCH_BASELINE_SHA", "")):
        raise ValueError("gateway regression requires an exact baseline SHA")
    if os.environ.get("BENCH_CARGO_PROFILE", "release") not in ("release", "ci-release"):
        raise ValueError("unsupported matched image profile")
    if os.environ.get("BENCH_FERRUM_FEATURES", "cloud-secrets") != "cloud-secrets":
        raise ValueError("gateway regression requires uninstrumented cloud-secrets images")


def runtime(operation, *, timeout=15, check=True, **data):
    env = dict(os.environ, GATEWAY_REGRESSION_OPERATION=operation)
    env.update({f"GATEWAY_REGRESSION_{key}": str(value) for key, value in data.items()})
    return subprocess.run(["bash", "tests/performance/multi_protocol/gateway_regression_runtime.sh"],
                          env=env, check=check, capture_output=True, timeout=timeout)


def resolve_identity(user, passwd):
    """Resolve Docker's configured user and optional primary group fail-closed."""
    name, _, group = user.partition(":")
    rows = [line.split(":") for line in passwd.splitlines() if len(line.split(":")) == 7]
    row = next((row for row in rows if row[0] == name or row[2] == name), None)
    uid = int(name) if name.isdecimal() else int(row[2]) if row else -1
    gid = int(group) if group.isdecimal() else int(row[3]) if row and not group else -1
    if (uid, gid) != (65532, 65532):
        raise ValueError(f"image must resolve to nonroot 65532:65532; configured user {user!r}")
    return dict(configured_user=user, uid=uid, gid=gid)


def image_identity(image, run_id, role):
    metadata = json.loads(runtime("image-inspect", IMAGE=image).stdout)[0]
    config = metadata["Config"]
    if metadata["Id"] != image or config.get("Entrypoint") != ["/app/ferrum-edge"]:
        raise ValueError("unexpected image identity/entrypoint")
    archive = runtime("image-passwd", timeout=40, IMAGE=image, RUN_ID=run_id, ROLE=role).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as contents:
        passwd = contents.extractfile(contents.getmembers()[0]).read().decode()
    return resolve_identity(config.get("User", ""), passwd)


def prepare_fixture(root):
    """Only new synthetic files; backend fs::write preserves their private mode."""
    certs = root / "certs"
    certs.mkdir(mode=0o700)
    for name in ("ca.pem", "cert.pem", "key.pem"):
        fd = os.open(certs / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
        os.close(fd)
    runtime("fixture-group", FIXTURE=root)
    certs.chmod(0o750)
    for name in ("ca.pem", "cert.pem", "key.pem"):
        (certs / name).chmod(0o640)
    if any(path.stat().st_gid != 65532 for path in (certs, *certs.iterdir())):
        raise ValueError("disposable fixture group was not applied")


def cleanup_session(child, identity, output):
    # Reuse the existing identity-checked session cleanup, including nested GNU
    # timeout groups and sudo readers. Only this invocation's session is owned.
    env = dict(os.environ, H1_DIAGNOSTIC_SESSION=str(child.pid),
               H1_DIAGNOSTIC_START_TICKS=str(identity["start_ticks"]))
    errors = []
    try:
        env["GATEWAY_REGRESSION_OPERATION"] = "cleanup-session"
        result = subprocess.run(["bash", "tests/performance/multi_protocol/gateway_regression_runtime.sh"],
                                env=env, capture_output=True, timeout=7)
        (output / "process_cleanup.log").write_bytes(result.stdout + result.stderr)
        if result.returncode:
            errors.append("privileged owned-session cleanup failed")
    except subprocess.TimeoutExpired:
        errors.append("owned-session cleanup timed out")
    fallback = terminate_session(child.pid, identity["start_ticks"], time.monotonic() + 0.2)
    if not fallback["complete"]:
        errors.append(f"owned-session survivors/signal errors: {fallback}")
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        errors.append("owned shell did not reap")
    return errors


def cleanup_containers(run_id, output):
    errors = []
    for gateway in ("ferrum", "ferrum-baseline"):
        name = f"gateway-regression-{run_id}-{gateway}"
        try:
            # Bounded logs retain failure evidence before this lane's removal.
            logs = runtime("container-logs", check=False, RUN_ID=run_id, ROLE=gateway)
            (output / f"{gateway}_cleanup.log").write_bytes(logs.stdout + logs.stderr)
            runtime("container-remove", timeout=28, RUN_ID=run_id, ROLE=gateway)
        except (subprocess.SubprocessError, OSError) as error:
            errors.append(f"cleanup failed: {name}: {type(error).__name__}")
    return errors


def run_protocol(protocol, output, fixture, run_id, source, *, tail_pair=None, wall_secs=PROTOCOL_WALL_SECS):
    output.mkdir()
    status = dict(state="running", wall_timeout_secs=wall_secs)
    write_json(output / "status.json", status)
    env = {key: value for key, value in os.environ.items() if not key.startswith("FERRUM_")}
    env["FERRUM_IMAGE"] = source["candidate_image_id"]
    env.update(GATEWAY_REGRESSION_OPERATION="protocol", GATEWAY_REGRESSION_PROTOCOL=protocol,
               GATEWAY_REGRESSION_BASELINE_IMAGE=source["baseline_image_id"],
               GATEWAY_REGRESSION_OUTPUT=str(output), GATEWAY_REGRESSION_FIXTURE=str(fixture),
               GATEWAY_REGRESSION_RUN_ID=run_id)
    if tail_pair is not None:
        env.update(GATEWAY_REGRESSION_OPERATION="tail-protocol", GATEWAY_REGRESSION_PAIR=str(tail_pair))
    child, identity = None, None
    cleanup_errors = []
    try:
        with (output / "run.log").open("wb", buffering=0) as log:
            child = subprocess.Popen(["bash", "tests/performance/multi_protocol/gateway_regression_runtime.sh"],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            identity = process_identity(child.pid)
            if identity["session"] != child.pid:
                raise ValueError("protocol shell does not own its session")
            status["session"] = identity

            def forward():
                for line in child.stdout:
                    log.write(line)
                    print(line.decode(errors="replace"), end="", flush=True)

            reader = threading.Thread(target=forward, daemon=True)
            reader.start()
            try:
                status.update(exit_code=child.wait(timeout=wall_secs), state="completed")
            except subprocess.TimeoutExpired:
                status.update(state="timed_out")
            finally:
                cleanup_errors += cleanup_session(child, identity, output)
                identity = None
                reader.join(timeout=2)
    except BaseException as error:
        status.update(state="failed", error=str(error))
        raise
    finally:
        if child is not None and identity is not None:
            cleanup_errors += cleanup_session(child, identity, output)
        status["cleanup_errors"] = cleanup_errors + cleanup_containers(run_id, output)
        write_json(output / "status.json", status)
    return status


def check(output):
    output.mkdir(parents=True, exist_ok=True)
    issues, comparisons, hosts, plan, images = [], [], set(), {}, {}
    try:
        plan = read_json(output / "plan.json")
        if (plan.get("cells") != cells() or plan.get("duration_secs") != DURATION
                or plan.get("offered_concurrency") != CONCURRENCY
                or plan.get("protocol_wall_timeout_secs") != PROTOCOL_WALL_SECS):
            issues.append("campaign plan differs from the fixed complete workload")
        source = read_json(output.parent / "provenance.json")
        images = plan.get("images") if isinstance(plan.get("images"), dict) else {}
        if (plan.get("mesh_provenance_sha256") != sha256(output.parent / "provenance.json")
                or images != {key: source.get(key) for key in ("candidate_image_id", "baseline_image_id")}
                or not all(IMAGE_ID.fullmatch(str(image)) for image in images.values())):
            issues.append("immutable mesh image provenance mismatch")
        if any(plan.get(key) != source.get(key) for key in
               ("candidate_sha", "baseline_sha", "profile", "features")):
            issues.append("image source/profile/features provenance mismatch")
        if plan.get("identity_cleanup_errors") != []:
            issues.append("identity-container cleanup did not complete")
        if plan.get("fixture_cleanup_complete") is not True:
            issues.append("disposable TLS fixture cleanup did not complete")
        if (source.get("features") != "cloud-secrets" or source.get("profile") not in ("release", "ci-release")
                or any(not re.fullmatch(r"[0-9a-f]{40}", str(source.get(key)))
                       for key in ("candidate_sha", "baseline_sha"))):
            issues.append("missing exact uninstrumented matched image build provenance")
        users = plan.get("image_users") or {}
        if (not isinstance(users, dict) or any(not isinstance(users.get(role), dict)
                or any(users[role].get(key) != 65532 for key in ("uid", "gid"))
                for role in ("candidate", "baseline"))):
            issues.append("image nonroot UID/GID was not confirmed")
    except (OSError, ValueError, KeyError, TypeError) as error:
        issues.append(f"missing/invalid campaign provenance: {error}")
    for protocol in PROTOCOLS:
        directory, buckets, invalid = output / protocol, {}, set()
        try:
            status = read_json(directory / "status.json")
            manifest = read_json(directory / "manifest.json")
            if status.get("state") != "completed" or status.get("exit_code") != 0 or status.get("cleanup_errors"):
                issues.append(f"{protocol}: execution/cleanup did not complete")
            if (expected_rows(directory) != [(g, s) for g in GATEWAYS for s in SIZES]
                    or manifest.get("pairs") != PAIRS or manifest.get("sample_schema") != 2
                    or manifest.get("baseline_image") != images.get("baseline_image_id")
                    or manifest.get("h2_window") != "default" or manifest.get("h2_stream_window_bytes") != 8388608
                    or manifest.get("h2_observation_enabled") is not False
                    or manifest.get("adaptive_extension") or manifest.get("h1_profile_mode")):
                issues.append(f"{protocol}: protocol manifest differs from plan")
            hosts.add(manifest["host_id"])
        except (OSError, ValueError, KeyError, TypeError) as error:
            issues.append(f"{protocol}: missing/invalid execution manifest: {error}")
            manifest = {}
        paths = set(directory.glob("pairs/pair_*/*.json"))
        if {path.name for path in (directory / "pairs").glob("pair_*")} != {
                f"pair_{pair:03d}" for pair in range(1, PAIRS + 1)}:
            issues.append(f"{protocol}: missing/unplanned pair directories")
        expected_paths = set()
        for cell in (cell for cell in cells() if cell["protocol"] == protocol):
            gateway, size, pair = cell["gateway"], cell["payload_size"], cell["pair"]
            path = directory / "pairs" / f"pair_{pair:03d}" / f"{gateway}_{protocol}_{size}.json"
            expected_paths.add(path)
            sample = {}
            try:
                sample = read_json(path)
                row_issues = sample_issues(sample)
                expected = dict(cell, sample_schema=2, duration_secs=DURATION,
                                concurrency=cell["effective_concurrency"],
                                host_id=manifest.get("host_id"),
                                gateway_order=gateway_order(list(GATEWAYS), pair))
                expected["protocol"] = "HTTP/1.1+TLS" if protocol == "http1-tls" else "HTTP/2"
                port = (3447 if protocol == "http1-tls" else 3443) if gateway == "direct" else 8443
                expected["target"] = f"https://127.0.0.1:{port}/echo"
                row_issues += [f"unmatched {key}" for key, value in expected.items()
                               if sample.get(key) != value or type(sample.get(key)) is not type(value)]
                if not math.isclose(sample.get("rps", 0), sample.get("total_requests", 0) / DURATION,
                                    rel_tol=1e-9):
                    row_issues.append("RPS differs from useful completions / planned duration")
                for field in LATENCIES:
                    value = sample.get(field)
                    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                        row_issues.append(f"missing/invalid {field}")
                if row_issues:
                    invalid.add((gateway, size))
                    issues.append(f"{path.relative_to(output)}: {', '.join(row_issues)}")
            except (OSError, ValueError, TypeError, OverflowError) as error:
                invalid.add((gateway, size))
                issues.append(f"{path.relative_to(output)}: missing/invalid sample: {error}")
            buckets.setdefault((gateway, size), []).append(sample)
        if paths != expected_paths:
            issues.append(f"{protocol}: missing/unplanned raw sample paths")
        for reference, candidate in (("direct", "ferrum"), ("direct", "ferrum-baseline"),
                                     ("ferrum-baseline", "ferrum")):
            for size in SIZES:
                left, right = buckets[reference, size], buckets[candidate, size]
                try:
                    comparison = paired_comparison(left, right, PAIRS)
                except (ArithmeticError, ValueError, TypeError):
                    comparison = dict(accepted=False, reason="invalid ratio arithmetic")
                if (reference, size) in invalid or (candidate, size) in invalid:
                    comparison = dict(accepted=False, reason="unmatched/invalid planned sample")
                row = dict(protocol=protocol, payload_size=size, baseline=reference,
                           candidate=candidate, data_valid=comparison.pop("accepted"), **comparison)
                row["pair_ratios"] = []
                if row["data_valid"]:
                    for a, b in zip(left, right):
                        ratios = {field: b[field] / a[field] for field in ("rps", *LATENCIES)
                                  if isinstance(a.get(field), (int, float)) and a[field] > 0
                                  and isinstance(b.get(field), (int, float)) and math.isfinite(b[field])}
                        row["pair_ratios"].append(dict(pair=a["pair"], **ratios))
                    if any(not math.isfinite(ratio) for pair in row["pair_ratios"]
                           for field, ratio in pair.items() if field != "pair"):
                        row.update(data_valid=False, pair_ratios=[], reason="non-finite metric ratio")
                        issues.append(f"{protocol}/{size}/{reference}/{candidate}: non-finite metric ratio")
                else:
                    issues.append(f"{protocol}/{size}/{reference}/{candidate}: {row['reason']}")
                comparisons.append(row)
    if len(hosts) != 1 or not all(isinstance(host, str) and host for host in hosts):
        issues.append("protocols do not identify one shared runner boot")
    report = dict(data_valid=not issues, issues=issues, comparisons=comparisons,
                  image_profile=plan.get("profile"), image_features=plan.get("features"),
                  performance_gate="not configured; no nonregression/equivalence claim",
                  interpretation="Descriptive n=4 paired throughput intervals; latency ratios are per-pair completion-window quantiles, excluding successful drain completions. These do not establish admitted-cohort tail improvements. Calibrate a tolerance with A/A before gating performance.")
    write_json(output / "report.json", report)
    lines = ["Gateway regression evidence", "", f"Data valid: {report['data_valid']}; matched image profile: {report['image_profile']} (ci-release is diagnostic only).", "", report["interpretation"], "",
             "| Protocol | Bytes | Reference → candidate | RPS ratio (geomean) | 95% paired interval | Pair RPS ratios |",
             "|---|---:|---|---:|---|---|"]
    for row in comparisons:
        interval = f"{row['ci95_low']:.4f}–{row['ci95_high']:.4f}" if row["data_valid"] else "invalid"
        ratio = f"{row['ratio']:.4f}" if row["data_valid"] else "invalid"
        pairs = ", ".join(f"{r['rps']:.4f}" for r in row["pair_ratios"] if "rps" in r)
        lines.append(f"| {row['protocol']} | {row['payload_size']} | {row['baseline']} → {row['candidate']} | {ratio} | {interval} | {pairs} |")
    lines += ["", "All per-pair RPS and completion-window P50/P95/P99/max latency ratios are in report.json. Successful drain completions are counted separately by the protocol runner but excluded from these quantiles. Use the mesh lane's admitted-cohort histogram for mesh tail claims.", ""]
    lines += [f"- {issue}" for issue in issues]
    (output / "report.md").write_text("\n".join(lines) + "\n")
    return report


def run(output):
    validate_inputs()
    output.mkdir(parents=True)  # refuse stale results
    source = read_json(output.parent / "provenance.json")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if (source.get("candidate_sha") != revision or source.get("baseline_sha") != os.environ["BENCH_BASELINE_SHA"]
            or source.get("profile") != os.environ.get("BENCH_CARGO_PROFILE", "release")
            or source.get("features") != "cloud-secrets"):
        raise ValueError("matched image build provenance is missing or differs from dispatch")
    images = {key: source.get(key) for key in ("candidate_image_id", "baseline_image_id")}
    if not all(IMAGE_ID.fullmatch(str(image)) for image in images.values()):
        raise ValueError("two exact prebuilt image IDs are required")
    plan = dict(cells=cells(), duration_secs=DURATION, offered_concurrency=CONCURRENCY,
                protocol_wall_timeout_secs=PROTOCOL_WALL_SECS,
                workflow_step_timeout_secs=4200, image_inspect_timeout_secs=15,
                image_passwd_timeout_secs=40, identity_cleanup_timeout_secs=28,
                owned_session_cleanup_timeout_secs=7, owned_shell_reap_timeout_secs=2,
                log_forwarder_join_timeout_secs=2, per_container_cleanup_timeout_secs=43,
                readiness_timeout_secs=30, readiness_curl_timeout_secs=2, docker_timeout_secs=10,
                docker_kill_grace_secs=2,
                client_wall_timeout_formula="duration + 120 + ceil(payload / 131072); kill grace 5s",
                mesh_provenance_sha256=sha256(output.parent / "provenance.json"), images=images,
                candidate_sha=revision, baseline_sha=source["baseline_sha"],
                profile=source["profile"], features=source["features"],
                harness_sha256={str(path): sha256(path) for path in
                    (TOOLS / "gateway_regression.py", TOOLS / "gateway_regression_runtime.sh",
                     TOOLS / "run_gateway_protocol_bench.sh",
                     TOOLS / "configs/http1_tls_e2e_perf.yaml", TOOLS / "configs/http2_perf.yaml",
                     TOOLS / "target/release/proto_bench", TOOLS / "target/release/proto_backend")})
    write_json(output / "plan.json", plan)
    run_id = uuid.uuid4().hex
    fixture = None
    try:
        plan["image_users"] = {role: image_identity(images[f"{role}_image_id"], run_id, role)
                               for role in ("candidate", "baseline")}
        write_json(output / "plan.json", plan)
        fixture = Path(tempfile.mkdtemp(prefix="gateway-regression-", dir=os.environ.get("RUNNER_TEMP")))
        prepare_fixture(fixture)
        for protocol in PROTOCOLS:
            status = run_protocol(protocol, output / protocol, fixture, run_id, source)
            if status.get("exit_code") != 0 or status["state"] != "completed" or status["cleanup_errors"]:
                break
    finally:
        plan["identity_cleanup_errors"] = []
        for role in ("candidate", "baseline"):
            try:
                runtime("identity-remove", timeout=28, RUN_ID=run_id, ROLE=role)
            except (subprocess.SubprocessError, OSError) as error:
                plan["identity_cleanup_errors"].append(f"{role}: {type(error).__name__}")
        plan["fixture_cleanup_complete"] = False
        try:
            if fixture is not None:
                shutil.rmtree(fixture)
            plan["fixture_cleanup_complete"] = True
        except OSError as error:
            plan["fixture_cleanup_error"] = type(error).__name__
        write_json(output / "plan.json", plan)
        check(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("validate", "run", "check"))
    parser.add_argument("--output", type=Path, default=Path("results/gateway_regression"))
    args = parser.parse_args()
    if args.mode == "validate":
        validate_inputs()
        return 0
    output = args.output.resolve()
    if args.mode == "run":
        def interrupted(signum, frame):
            raise InterruptedError(f"campaign interrupted by signal {signum}")
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        run(output)
    return 0 if check(output)["data_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
