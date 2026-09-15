#!/usr/bin/env python3
"""Paired HTTP/1.1 TLS POST/echo comparison against a pinned historical revision.

The gateways-protocol-benchmark workflow measured a June-to-September
throughput loss for 10 KiB and 70 KiB HTTP/1.1 TLS POST echoes (issue #5505)
that no scheduled check guarded. Cross-run absolute RPS cannot guard it: hosted
runners change CPU class between runs. This harness instead measures the
candidate and a pinned reference revision on ONE runner, in interleaved rounds,
with the same toolchain, build profile, backend, load generator, and gateway
configuration, and gates the paired throughput ratio per payload size.

    run       start proto_backend once, then for each round start the
              reference and candidate gateways in alternating order and
              measure every payload size; persist every sample as JSON
    evaluate  compute paired ratios, apply the versioned contract, compare
              with the rolling ratio history, write report/trends/summary
    self-test exercise the evaluation rules on synthetic evidence

Every measured sample must report zero errors; missing or malformed evidence is
a harness failure regardless of the enforcement mode. A ratio below the
contract floor fails only when enforcement is "fail" and both sides were stable
within the round-spread bound; a noisy runner downgrades the verdict to a
provisional alert so a single bad neighbour cannot manufacture a regression.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

SCHEMA_VERSION = 1
BACKEND_PORTS = (3001, 3002, 3003, 3004, 3005, 3006, 3010, 3443, 3444, 3445, 3446, 3447, 50052, 50053)
GATEWAY_HTTP_PORT = 18080
GATEWAY_HTTPS_PORT = 18443
GATEWAY_ADMIN_PORT = 19000
BACKEND_READY_PORT = 3447
ROLES = ("reference", "candidate")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# The workload the literal `proto_bench` process commands in `run_bench` spell
# out. Repository automation may only spawn processes with literal argv (see
# verify_cross_build_policy.py), so the contract's workload block is checked
# against this table rather than interpolated into a command line. Changing the
# workload means changing both, deliberately.
LITERAL_WORKLOAD = {
    "target": "https://127.0.0.1:18443/echo",
    "payload_sizes": [10240, 71680],
    "concurrency": 200,
    "duration_secs": 15,
    "warmup_secs": 3,
}
# Each gateway binary is staged by run_h1_tls_post_comparison.sh at the
# ci-release build-output path inside a per-role directory under the output
# directory, so one literal process command starts either role and the policy
# recognises it as the enumerated build output it is.
GATEWAY_BINARY = "target/ci-release/ferrum-edge"

# Mirrors the Ferrum environment of the gateways-protocol-benchmark http1-tls
# job (tests/performance/multi_protocol/run_gateway_protocol_bench.sh) for the
# HTTP/1-relevant settings. Both revisions receive exactly this environment;
# the harness never tunes one side differently from the other.
GATEWAY_ENV = {
    "FERRUM_MODE": "file",
    "FERRUM_PROXY_BIND_ADDRESS": "127.0.0.1",
    "FERRUM_PROXY_HTTP_PORT": str(GATEWAY_HTTP_PORT),
    "FERRUM_PROXY_HTTPS_PORT": str(GATEWAY_HTTPS_PORT),
    "FERRUM_ADMIN_HTTP_PORT": str(GATEWAY_ADMIN_PORT),
    "FERRUM_LOG_LEVEL": "error",
    "FERRUM_ADD_VIA_HEADER": "false",
    "FERRUM_ADD_FORWARDED_HEADER": "false",
    "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES": "0",
    "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES": "0",
    "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES": "0",
    "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS": "0",
    "FERRUM_MAX_CONNECTIONS": "0",
    "FERRUM_POOL_MAX_IDLE_PER_HOST": "200",
    "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE": "true",
    "FERRUM_POOL_WARMUP_ENABLED": "true",
}


class HarnessError(RuntimeError):
    """Evidence is missing, malformed, or the harness itself failed."""


# ── contract ────────────────────────────────────────────────────────────────


def load_contract(path: Path) -> dict:
    contract = json.loads(path.read_text(encoding="utf-8"))
    if contract.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError(f"{path}: unsupported schema_version {contract.get('schema_version')!r}")
    sha = contract.get("reference", {}).get("sha", "")
    if not SHA_RE.match(sha) or sha == "0" * 40:
        raise HarnessError(f"{path}: reference.sha must be an immutable nonzero 40-hex commit SHA")
    workload = contract.get("workload", {})
    sizes = workload.get("payload_sizes")
    if not isinstance(sizes, list) or not sizes or any(not isinstance(s, int) or s <= 0 for s in sizes):
        raise HarnessError(f"{path}: workload.payload_sizes must be a non-empty list of positive integers")
    for key in ("concurrency", "duration_secs", "warmup_secs", "rounds", "worker_threads"):
        value = workload.get(key)
        if not isinstance(value, int) or value <= 0:
            raise HarnessError(f"{path}: workload.{key} must be a positive integer")
    if workload["rounds"] < 3:
        raise HarnessError(f"{path}: workload.rounds must be at least 3 so one noisy round cannot decide the verdict")
    for key, literal in LITERAL_WORKLOAD.items():
        if workload.get(key) != literal:
            raise HarnessError(
                f"{path}: workload.{key} is {workload.get(key)!r} but the literal proto_bench commands in "
                f"{Path(__file__).name} measure {literal!r}; update LITERAL_WORKLOAD and run_bench together"
            )
    if contract.get("enforcement") not in ("fail", "alert"):
        raise HarnessError(f"{path}: enforcement must be 'fail' or 'alert'")
    thresholds = contract.get("thresholds", {})
    for size in sizes:
        floor = thresholds.get(str(size), {}).get("min_ratio")
        if not isinstance(floor, (int, float)) or not 0 < floor <= 1:
            raise HarnessError(f"{path}: thresholds.{size}.min_ratio must be in (0, 1]")
    variance = contract.get("runner_variance", {})
    spread = variance.get("max_round_spread")
    if not isinstance(spread, (int, float)) or not 0 < spread < 1:
        raise HarnessError(f"{path}: runner_variance.max_round_spread must be in (0, 1)")
    rolling = variance.get("rolling", {})
    for key in ("window", "min_samples"):
        if not isinstance(rolling.get(key), int) or rolling[key] < 1:
            raise HarnessError(f"{path}: runner_variance.rolling.{key} must be a positive integer")
    if not isinstance(rolling.get("mad_multiplier"), (int, float)) or rolling["mad_multiplier"] <= 0:
        raise HarnessError(f"{path}: runner_variance.rolling.mad_multiplier must be positive")
    return contract


def workload_signature(contract: dict) -> str:
    """Rolling history only compares runs of the identical reference and workload."""
    body = {"reference": contract["reference"]["sha"], "workload": contract["workload"]}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


# ── run ─────────────────────────────────────────────────────────────────────


def port_open(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def wait_ready(child: subprocess.Popen, port: int, what: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise HarnessError(f"{what} exited with {child.returncode} before listening on {port}")
        if port_open(port):
            return
        time.sleep(0.25)
    raise HarnessError(f"{what} did not listen on {port} within {timeout_s:.0f}s")


def stop(child: subprocess.Popen | None) -> None:
    if child is None or child.poll() is not None:
        return
    child.send_signal(signal.SIGTERM)
    try:
        child.wait(timeout=15)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scheduler_jitter_probe() -> dict:
    samples = []
    for _ in range(100):
        t0 = time.monotonic_ns()
        time.sleep(0.001)
        samples.append((time.monotonic_ns() - t0) / 1000)
    samples.sort()
    return {"sleep_1ms_avg_us": sum(samples) / len(samples), "sleep_1ms_p99_us": samples[98], "sleep_1ms_max_us": samples[-1]}


def clean_env() -> dict:
    """Runner-level FERRUM_* variables must not leak into either gateway."""
    return {k: v for k, v in os.environ.items() if not k.startswith("FERRUM_")}


def validate_sample(report: dict, where: str) -> dict:
    for key in ("rps", "total_requests", "total_errors", "p50_us", "p99_us", "duration_secs", "concurrency"):
        if key not in report:
            raise HarnessError(f"{where}: benchmark JSON is missing {key!r}")
    if report["total_errors"]:
        raise HarnessError(f"{where}: {report['total_errors']} benchmark errors; a paired sample must verify every echo")
    if report["total_requests"] <= 0 or not report["rps"] > 0:
        raise HarnessError(f"{where}: no successful requests were measured")
    return report


def run_bench(kind: str | int, dest: Path, env: dict) -> dict:
    """Run one literal `proto_bench` command: the warm-up, or one payload size.

    `proto_bench` resolves through `PATH` (the harness release directory is
    prepended in `cmd_run`). Every argv here is spelled out because repository
    automation may not build process commands from data; `LITERAL_WORKLOAD`
    keeps the contract honest about what these commands measure.
    """
    if kind == "warmup":
        result = subprocess.run(
            ["proto_bench", "http1", "--target", "https://127.0.0.1:18443/echo", "--payload-size", "10240",
             "--concurrency", "200", "--duration", "3", "--json"],
            env=env, cwd=dest.parent, capture_output=True, text=True, timeout=120)
    elif kind == 10240:
        result = subprocess.run(
            ["proto_bench", "http1", "--target", "https://127.0.0.1:18443/echo", "--payload-size", "10240",
             "--concurrency", "200", "--duration", "15", "--json"],
            env=env, cwd=dest.parent, capture_output=True, text=True, timeout=120)
    elif kind == 71680:
        result = subprocess.run(
            ["proto_bench", "http1", "--target", "https://127.0.0.1:18443/echo", "--payload-size", "71680",
             "--concurrency", "200", "--duration", "15", "--json"],
            env=env, cwd=dest.parent, capture_output=True, text=True, timeout=120)
    else:
        raise HarnessError(f"{dest.name}: no literal proto_bench command for payload size {kind!r}")
    dest.write_text(result.stdout, encoding="utf-8")
    dest.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise HarnessError(f"{dest.name}: proto_bench exited with {result.returncode}")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"{dest.name}: proto_bench did not emit JSON: {exc}") from exc
    return report


def cmd_run(args: argparse.Namespace) -> int:
    contract = load_contract(Path(args.contract))
    workload = contract["workload"]
    out = Path(args.output).resolve()
    samples_dir = out / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    harness = Path(args.harness_dir).resolve()
    harness_bin = harness / "target" / "release"
    bench_bin = harness_bin / "proto_bench"
    backend_bin = harness_bin / "proto_backend"
    binaries = {role: out / role / GATEWAY_BINARY for role in ROLES}
    for name, path in {"proto_bench": bench_bin, "proto_backend": backend_bin, **binaries}.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise HarnessError(f"{name} binary is missing or not executable: {path}")
    for sha, name in ((args.reference_sha, "reference"), (args.candidate_sha, "candidate")):
        if not SHA_RE.match(sha):
            raise HarnessError(f"{name} SHA must be 40 hex characters")
    if args.reference_sha == args.candidate_sha:
        raise HarnessError("reference and candidate are the same commit; a paired comparison needs two revisions")
    for port in (*BACKEND_PORTS, GATEWAY_HTTP_PORT, GATEWAY_HTTPS_PORT, GATEWAY_ADMIN_PORT):
        if port_open(port):
            raise HarnessError(f"port {port} is already in use; the runner is not clean")

    base_env = clean_env()
    # `proto_backend` / `proto_bench` are spelled literally in their process
    # commands and resolved through PATH from the harness build directory.
    base_env["PATH"] = f"{harness_bin}{os.pathsep}{base_env.get('PATH', '')}"
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "reference_version": contract.get("reference_version"),
        "workload_signature": workload_signature(contract),
        "reference": {"sha": args.reference_sha, "label": contract["reference"].get("label"), "binary_sha256": sha256_file(binaries["reference"])},
        "candidate": {"sha": args.candidate_sha, "binary_sha256": sha256_file(binaries["candidate"])},
        "harness": {"proto_bench_sha256": sha256_file(bench_bin), "proto_backend_sha256": sha256_file(backend_bin)},
        "host": {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count()},
        "gateway_env": {**GATEWAY_ENV, "FERRUM_WORKER_THREADS": str(workload["worker_threads"])},
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "jitter_before": scheduler_jitter_probe(),
    }

    backend_log = (out / "backend.log").open("w", encoding="utf-8")
    backend = subprocess.Popen(["proto_backend"], cwd=out, env=base_env, stdout=backend_log, stderr=subprocess.STDOUT)
    gateway: subprocess.Popen | None = None
    try:
        wait_ready(backend, BACKEND_READY_PORT, "proto_backend")
        cert_dir = out / "certs"
        for pem in ("ca.pem", "cert.pem", "key.pem"):
            deadline = time.monotonic() + 30
            while not (cert_dir / pem).is_file():
                if time.monotonic() > deadline:
                    raise HarnessError(f"proto_backend did not write {pem}")
                time.sleep(0.2)
        template = (harness / workload["config"]).read_text(encoding="utf-8")
        config_path = out / "gateway_config.yaml"
        config_path.write_text(template.replace("CA_PATH", str(cert_dir / "ca.pem")), encoding="utf-8")
        gateway_env = {**base_env, **provenance["gateway_env"],
                       "FERRUM_FILE_CONFIG_PATH": str(config_path),
                       "FERRUM_FRONTEND_TLS_CERT_PATH": str(cert_dir / "cert.pem"),
                       "FERRUM_FRONTEND_TLS_KEY_PATH": str(cert_dir / "key.pem"),
                       "FERRUM_DTLS_CERT_PATH": str(cert_dir / "cert.pem"),
                       "FERRUM_DTLS_KEY_PATH": str(cert_dir / "key.pem")}

        rows = []
        for round_no in range(1, workload["rounds"] + 1):
            order = ROLES if round_no % 2 == 1 else tuple(reversed(ROLES))
            for role in order:
                log = (out / f"gateway-{role}-r{round_no}.log").open("w", encoding="utf-8")
                gateway = subprocess.Popen(["target/ci-release/ferrum-edge", "run"], cwd=out / role, env=gateway_env,
                                           stdout=log, stderr=subprocess.STDOUT)
                try:
                    wait_ready(gateway, GATEWAY_HTTPS_PORT, f"{role} gateway")
                    warm = run_bench("warmup", samples_dir / f"{role}-r{round_no}-warmup.json", base_env)
                    for size in workload["payload_sizes"]:
                        dest = samples_dir / f"{role}-r{round_no}-{size}.json"
                        report = validate_sample(run_bench(size, dest, base_env), dest.name)
                        row = {"role": role, "round": round_no, "size": size, "rps": report["rps"],
                               "p50_us": report["p50_us"], "p99_us": report["p99_us"],
                               "total_requests": report["total_requests"], "total_errors": report["total_errors"],
                               "warmup_errors": warm.get("total_errors")}
                        rows.append(row)
                        print(json.dumps(row), flush=True)
                        # Persist progressively so an aborted run still leaves evidence.
                        (out / "rows.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
                finally:
                    stop(gateway)
                    gateway = None
                    log.close()
                if backend.poll() is not None:
                    raise HarnessError("proto_backend exited during the comparison")
        provenance["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        provenance["jitter_after"] = scheduler_jitter_probe()
        (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    finally:
        stop(gateway)
        stop(backend)
        backend_log.close()
        shutil.rmtree(out / "certs", ignore_errors=True)
    return 0


# ── evaluate ────────────────────────────────────────────────────────────────


def spread(values: list[float]) -> float:
    median = statistics.median(values)
    return (max(values) - min(values)) / median if median > 0 else float("inf")


def compare_size(contract: dict, rows: list[dict], size: int) -> dict:
    rounds = contract["workload"]["rounds"]
    by_role: dict[str, dict[int, dict]] = {role: {} for role in ROLES}
    for row in rows:
        if row["size"] != size:
            continue
        if row["role"] not in by_role or row["round"] in by_role[row["role"]]:
            raise HarnessError(f"size {size}: duplicate or unknown sample {row['role']} round {row['round']}")
        if row.get("total_errors"):
            raise HarnessError(f"size {size}: {row['role']} round {row['round']} reported errors")
        if not row.get("rps") or row["rps"] <= 0:
            raise HarnessError(f"size {size}: {row['role']} round {row['round']} has no throughput")
        by_role[row["role"]][row["round"]] = row
    for role in ROLES:
        missing = [r for r in range(1, rounds + 1) if r not in by_role[role]]
        if missing:
            raise HarnessError(f"size {size}: {role} is missing rounds {missing}")
    ratios = [by_role["candidate"][r]["rps"] / by_role["reference"][r]["rps"] for r in range(1, rounds + 1)]
    ref_rps = [by_role["reference"][r]["rps"] for r in range(1, rounds + 1)]
    cand_rps = [by_role["candidate"][r]["rps"] for r in range(1, rounds + 1)]
    floor = contract["thresholds"][str(size)]["min_ratio"]
    max_spread = contract["runner_variance"]["max_round_spread"]
    spreads = {"reference": spread(ref_rps), "candidate": spread(cand_rps)}
    provisional = any(s > max_spread for s in spreads.values())
    median_ratio = statistics.median(ratios)
    return {
        "size": size,
        "min_ratio": floor,
        "paired_ratios": ratios,
        "median_ratio": median_ratio,
        "rounds_below_floor": sum(1 for r in ratios if r < floor),
        "below_floor": median_ratio < floor,
        "provisional": provisional,
        "round_spread": spreads,
        "reference": {"median_rps": statistics.median(ref_rps), "rps": ref_rps,
                      "median_p99_us": statistics.median(by_role["reference"][r]["p99_us"] for r in range(1, rounds + 1))},
        "candidate": {"median_rps": statistics.median(cand_rps), "rps": cand_rps,
                      "median_p99_us": statistics.median(by_role["candidate"][r]["p99_us"] for r in range(1, rounds + 1))},
    }


def rolling_alert(contract: dict, history: dict, size: int, ratio: float) -> str | None:
    rolling = contract["runner_variance"]["rolling"]
    signature = workload_signature(contract)
    prior = [p["ratios"][str(size)] for p in history.get("points", [])
             if p.get("workload_signature") == signature and str(size) in p.get("ratios", {})]
    prior = prior[-rolling["window"]:]
    if len(prior) < rolling["min_samples"]:
        return None
    median = statistics.median(prior)
    mad = statistics.median(abs(p - median) for p in prior)
    floor = median - rolling["mad_multiplier"] * mad
    if ratio < floor:
        return (f"size {size}: paired ratio {ratio:.3f} is below the rolling baseline "
                f"{median:.3f} - {rolling['mad_multiplier']:g}*MAD({mad:.4f}) = {floor:.3f} over {len(prior)} prior runs")
    return None


def evaluate(contract: dict, rows: list[dict], history: dict) -> dict:
    failures: list[str] = []
    alerts: list[str] = []
    sizes = {}
    for size in contract["workload"]["payload_sizes"]:
        try:
            result = compare_size(contract, rows, size)
        except HarnessError as exc:
            failures.append(str(exc))
            continue
        sizes[str(size)] = result
        if result["below_floor"]:
            message = (f"size {size}: paired candidate/reference throughput ratio {result['median_ratio']:.3f} "
                       f"(rounds {', '.join(f'{r:.3f}' for r in result['paired_ratios'])}) is below min_ratio {result['min_ratio']:.2f}")
            if result["provisional"]:
                alerts.append(message + " — provisional: round spread exceeded the runner-variance bound "
                              f"(reference {result['round_spread']['reference']:.1%}, candidate {result['round_spread']['candidate']:.1%})")
            elif contract["enforcement"] == "fail":
                failures.append(message)
            else:
                alerts.append(message + " (enforcement=alert)")
        elif result["provisional"]:
            alerts.append(f"size {size}: within budget but round spread exceeded the runner-variance bound "
                          f"(reference {result['round_spread']['reference']:.1%}, candidate {result['round_spread']['candidate']:.1%})")
        rolling = rolling_alert(contract, history, size, result["median_ratio"])
        if rolling:
            alerts.append(rolling)
    status = "fail" if failures else ("alert" if alerts else "pass")
    return {"schema_version": SCHEMA_VERSION, "status": status, "enforcement": contract["enforcement"],
            "reference_version": contract.get("reference_version"), "reference_sha": contract["reference"]["sha"],
            "workload_signature": workload_signature(contract), "sizes": sizes, "failures": failures, "alerts": alerts}


def append_history(contract: dict, history: dict, report: dict, provenance: dict) -> dict:
    points = [p for p in history.get("points", []) if isinstance(p, dict)]
    points.append({
        "commit": provenance.get("candidate", {}).get("sha"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "timestamp": provenance.get("finished_at"),
        "reference_sha": contract["reference"]["sha"],
        "workload_signature": report["workload_signature"],
        "status": report["status"],
        "ratios": {size: result["median_ratio"] for size, result in report["sizes"].items()},
        "candidate_rps": {size: result["candidate"]["median_rps"] for size, result in report["sizes"].items()},
        "reference_rps": {size: result["reference"]["median_rps"] for size, result in report["sizes"].items()},
    })
    return {"schema_version": SCHEMA_VERSION, "points": points[-64:]}


def summary_markdown(report: dict, provenance: dict) -> str:
    lines = ["## HTTP/1.1 TLS POST historical-baseline check", ""]
    lines.append(f"- Reference: `{provenance.get('reference', {}).get('sha', '?')}` ({provenance.get('reference', {}).get('label', '')})")
    lines.append(f"- Candidate: `{provenance.get('candidate', {}).get('sha', '?')}`")
    lines.append(f"- Contract: `{report.get('reference_version')}`, enforcement `{report.get('enforcement')}`")
    lines.append(f"- Status: **{report['status']}**")
    lines.append("")
    lines.append("| Payload | Reference RPS | Candidate RPS | Paired ratio (rounds) | Floor | Ref p99 | Cand p99 | Spread ref/cand |")
    lines.append("|---:|---:|---:|---|---:|---:|---:|---|")
    for size, result in sorted(report["sizes"].items(), key=lambda kv: int(kv[0])):
        rounds = ", ".join(f"{r:.3f}" for r in result["paired_ratios"])
        flag = " (provisional)" if result["provisional"] else ""
        lines.append(f"| {int(size) // 1024} KiB | {result['reference']['median_rps']:.0f} | {result['candidate']['median_rps']:.0f} "
                     f"| **{result['median_ratio']:.3f}** ({rounds}){flag} | {result['min_ratio']:.2f} "
                     f"| {result['reference']['median_p99_us'] / 1000:.2f} ms | {result['candidate']['median_p99_us'] / 1000:.2f} ms "
                     f"| {result['round_spread']['reference']:.1%} / {result['round_spread']['candidate']:.1%} |")
    if report["failures"]:
        lines += ["", "### Failures"] + [f"- {f}" for f in report["failures"]]
    if report["alerts"]:
        lines += ["", "### Alerts (non-blocking)"] + [f"- {a}" for a in report["alerts"]]
    jitter = provenance.get("jitter_before", {})
    if jitter:
        lines += ["", f"Runner scheduler jitter before measurement: 1 ms sleep p99 {jitter.get('sleep_1ms_p99_us', 0):.0f} µs."]
    return "\n".join(lines) + "\n"


def cmd_evaluate(args: argparse.Namespace) -> int:
    contract = load_contract(Path(args.contract))
    out = Path(args.output).resolve()
    rows_path = out / "rows.json"
    provenance_path = out / "provenance.json"
    if not rows_path.is_file() or not provenance_path.is_file():
        print("::error::comparison evidence (rows.json / provenance.json) is missing", file=sys.stderr)
        return 1
    rows = json.loads(rows_path.read_text(encoding="utf-8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance.get("reference", {}).get("sha") != contract["reference"]["sha"] and not args.allow_reference_override:
        print("::error::measured reference SHA does not match the contract", file=sys.stderr)
        return 1
    history = {"schema_version": SCHEMA_VERSION, "points": []}
    if args.history and Path(args.history).is_file():
        try:
            history = json.loads(Path(args.history).read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("::warning::prior history is not valid JSON; starting a fresh rolling baseline")
    report = evaluate(contract, rows, history)
    report["reference_label"] = provenance.get("reference", {}).get("label")
    Path(args.report_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.trends_out:
        Path(args.trends_out).write_text(json.dumps(append_history(contract, history, report, provenance), indent=2) + "\n", encoding="utf-8")
    markdown = summary_markdown(report, provenance)
    print(markdown)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(markdown)
    for failure in report["failures"]:
        print(f"::error::{failure}")
    for alert in report["alerts"]:
        print(f"::warning::{alert}")
    return 1 if report["failures"] else 0


# ── self-test ───────────────────────────────────────────────────────────────


def _contract(enforcement: str = "fail") -> dict:
    return {
        "schema_version": SCHEMA_VERSION, "reference_version": "test",
        "reference": {"sha": "0c91b23a3f4e3a585eeecc2c0acd68355d3fc203", "label": "test"},
        "workload": {"config": "c", "target": "t", "payload_sizes": [10240], "concurrency": 200,
                     "duration_secs": 15, "warmup_secs": 3, "rounds": 3, "worker_threads": 2},
        "enforcement": enforcement,
        "thresholds": {"10240": {"min_ratio": 0.70}},
        "runner_variance": {"max_round_spread": 0.10, "rolling": {"window": 8, "mad_multiplier": 5.0, "min_samples": 3}},
    }


def _rows(reference: list[float], candidate: list[float]) -> list[dict]:
    rows = []
    for role, values in (("reference", reference), ("candidate", candidate)):
        for round_no, rps in enumerate(values, 1):
            rows.append({"role": role, "round": round_no, "size": 10240, "rps": rps, "p50_us": 1000, "p99_us": 5000,
                         "total_requests": int(rps * 15), "total_errors": 0})
    return rows


def _history(ratios: list[float], contract: dict) -> dict:
    signature = workload_signature(contract)
    return {"schema_version": SCHEMA_VERSION,
            "points": [{"workload_signature": signature, "ratios": {"10240": r}} for r in ratios]}


def self_test() -> int:
    c = _contract()
    empty = {"points": []}
    # Healthy pair: candidate within budget.
    report = evaluate(c, _rows([100, 101, 99], [82, 83, 81]), empty)
    assert report["status"] == "pass", report
    # Ratios are paired per round: 0.820, 0.822, 0.818 -> median 0.820.
    assert abs(report["sizes"]["10240"]["median_ratio"] - 82 / 100) < 1e-9
    # Sustained regression below the floor fails when enforcement is fail...
    report = evaluate(c, _rows([100, 101, 99], [66, 67, 65]), empty)
    assert report["status"] == "fail" and report["failures"] and not report["alerts"], report
    # ...and only alerts when enforcement is alert.
    report = evaluate(_contract("alert"), _rows([100, 101, 99], [66, 67, 65]), empty)
    assert report["status"] == "alert" and not report["failures"], report
    # One noisy candidate round does not decide the verdict (median of three).
    report = evaluate(c, _rows([100, 101, 99], [82, 40, 81]), empty)
    assert report["status"] == "alert" and not report["failures"], report
    assert report["sizes"]["10240"]["rounds_below_floor"] == 1
    # A regression measured on a noisy runner is provisional, not a failure.
    report = evaluate(c, _rows([100, 130, 99], [66, 67, 65]), empty)
    assert report["status"] == "alert" and not report["failures"], report
    assert "provisional" in report["alerts"][0]
    # Rolling baseline: a sudden drop that still clears the floor alerts.
    history = _history([0.85, 0.86, 0.85, 0.86], c)
    report = evaluate(c, _rows([100, 101, 99], [76, 77, 75]), history)
    assert report["status"] == "alert" and "rolling baseline" in report["alerts"][0], report
    # Rolling baseline ignores points from a different reference or workload.
    foreign = {"points": [{"workload_signature": "other", "ratios": {"10240": 0.99}} for _ in range(5)]}
    assert evaluate(c, _rows([100, 101, 99], [82, 83, 81]), foreign)["status"] == "pass"
    # Too few prior points: no rolling verdict.
    assert evaluate(c, _rows([100, 101, 99], [76, 77, 75]), _history([0.85, 0.86], c))["status"] == "pass"
    # Integrity: missing round, errors, or duplicate samples fail regardless of ratio.
    for rows in (_rows([100, 101], [82, 83, 81]), _rows([100, 101, 99], [82, 83, 81]) + _rows([100], [82])[:1]):
        report = evaluate(c, rows, empty)
        assert report["status"] == "fail" and report["failures"], report
    rows = _rows([100, 101, 99], [82, 83, 81])
    rows[3]["total_errors"] = 2
    assert evaluate(c, rows, empty)["status"] == "fail"
    # History append keeps the window bounded and records the paired ratio.
    trends = append_history(c, _history([0.8] * 70, c), evaluate(c, _rows([100, 101, 99], [82, 83, 81]), empty),
                            {"candidate": {"sha": "b" * 40}, "finished_at": "now"})
    assert len(trends["points"]) == 64 and trends["points"][-1]["ratios"]["10240"] > 0.8
    # Contract validation rejects a mutable or self-referential baseline.
    try:
        bad = _contract()
        bad["reference"]["sha"] = "0" * 40
        _validate_contract_dict(bad)
    except HarnessError:
        pass
    else:
        raise AssertionError("zero SHA must be rejected")
    # The contract cannot silently drift away from the literal proto_bench commands.
    literal = _contract()
    literal["workload"].update(LITERAL_WORKLOAD)
    literal["thresholds"]["71680"] = {"min_ratio": 0.78}
    _validate_contract_dict(literal)
    drifted = json.loads(json.dumps(literal))
    drifted["workload"]["duration_secs"] = 5
    try:
        _validate_contract_dict(drifted)
    except HarnessError as exc:
        assert "LITERAL_WORKLOAD" in str(exc), exc
    else:
        raise AssertionError("a workload that differs from the literal commands must be rejected")
    print("h1_tls_post_comparison self-test passed")
    return 0


def _validate_contract_dict(contract: dict) -> dict:
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(contract, handle)
        path = Path(handle.name)
    try:
        return load_contract(path)
    finally:
        path.unlink(missing_ok=True)


# ── entry point ─────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("self-test")
    run = sub.add_parser("run")
    run.add_argument("--contract", required=True)
    run.add_argument("--output", required=True,
                     help="evidence directory; each gateway binary must already be staged at <output>/<role>/target/ci-release/ferrum-edge")
    run.add_argument("--harness-dir", required=True,
                     help="checkout of tests/performance/multi_protocol with proto_bench/proto_backend built in target/release")
    run.add_argument("--reference-sha", required=True)
    run.add_argument("--candidate-sha", required=True)
    ev = sub.add_parser("evaluate")
    ev.add_argument("--contract", required=True)
    ev.add_argument("--output", required=True)
    ev.add_argument("--report-out", required=True)
    ev.add_argument("--history")
    ev.add_argument("--trends-out")
    ev.add_argument("--allow-reference-override", action="store_true",
                    help="accept a manually dispatched reference SHA that differs from the contract")
    args = parser.parse_args()
    try:
        if args.command == "self-test":
            return self_test()
        if args.command == "run":
            return cmd_run(args)
        return cmd_evaluate(args)
    except HarnessError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
