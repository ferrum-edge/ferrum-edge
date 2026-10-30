#!/usr/bin/env python3
"""Same-runner A/B of the gRPC RPC-deadline response path (issue #6904).

#6870 moved client RPC-deadline enforcement on HTTP/1.1 and HTTP/2 frontends
from an inline timer, which fired only when hyper polled the response body, to
a gateway-scheduled response pump (one task and one channel hop per frame). The
first remote measurement was inconclusive: it compared separate hosted VMs while
CI was saturated, and its gRPC load sent no `grpc-timeout`, so the pump never
ran. This harness measures the reference and candidate revisions on ONE runner,
in alternating rounds, with the same toolchain, build profile, backend, load
generator and gateway configuration.

    run       start proto_backend once; per round start each revision's
              gateway twice (open route, key_auth route), measure the four
              cells of that route in a rotated order, then run the stalled-
              stream deadline probe; persist every sample as JSON
    evaluate  paired ratios, the deadline difference-in-differences, the
              same-binary deadline cost, integrity and probe checks; write
              report and step summary
    self-test exercise the evaluation rules on synthetic evidence

Cells cross the RPC shape (unary, server-stream), authentication (open,
key_auth) and the client deadline (none, `grpc-timeout`). Deadline-free cells
run no RPC-deadline code in either revision: they are the null control. The
primary estimate per (shape, auth) is the round-paired difference between the
deadline cell's log candidate/reference ratio and its deadline-free sibling's,
which cancels runner drift and revision changes outside the deadline path.

Integrity is checked from the backend, not the client: every call in a deadline
cell must arrive at proto_backend carrying `grpc-timeout`, and none in a
deadline-free cell. The probe holds each backend stream open after its headers;
only the gateway's deadline can end the call, so every probe call must return
`DEADLINE_EXCEEDED` near the deadline and every stalled backend stream must be
released. Missing evidence is a harness failure. A sample with errors, a failed
integrity check, or a failed candidate probe fails the evaluation; a
performance verdict is reported, never gated.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SCHEMA_VERSION = 1
BACKEND_PORTS = (3001, 3002, 3003, 3004, 3005, 3006, 3010, 3443, 3444, 3445, 3446, 3447, 50052, 50053)
BACKEND_READY_PORTS = (3010, 50052)
BACKEND_STATS_URL = "http://127.0.0.1:3010/bench-stats"
GATEWAY_HTTP_PORT = 18080
GATEWAY_HTTPS_PORT = 18443
GATEWAY_ADMIN_PORT = 19000
ROLES = ("reference", "candidate")
CONFIGS = {"open": "configs/grpc_deadline_open.yaml", "auth": "configs/grpc_deadline_auth.yaml"}
RPCS = ("unary", "stream")
DEADLINES = ("nodeadline", "deadline")
SCENARIOS = tuple(f"{rpc}-{auth}-{deadline}" for rpc in RPCS for auth in CONFIGS for deadline in DEADLINES)
BACKEND_COUNTER = {"unary": "grpc_echo_requests", "stream": "grpc_stream_requests"}

# The workload the literal `proto_bench` process commands below spell out.
# Repository automation may only spawn processes with literal argv (see
# verify_cross_build_policy.py), so the contract is checked against this table
# rather than interpolated into a command line. Change both together.
LITERAL_WORKLOAD = {
    "target": "http://127.0.0.1:18080",
    "payload_bytes": 1024,
    "concurrency": 100,
    "duration_secs": 15,
    "warmup_secs": 3,
    "grpc_timeout_ms": 30000,
    "probe_calls": 20,
    "probe_grpc_timeout_ms": 250,
}
# The authenticated commands send the public benchmark credential from
# configs/grpc_deadline_auth.yaml (`x-api-key`), spelled literally below.
# Each gateway binary is staged by run_grpc_deadline_comparison.sh at the
# ci-release build-output path inside a per-role directory, so one literal
# process command starts either role.
GATEWAY_BINARY = "target/ci-release/ferrum-edge"

# The gRPC-relevant subset of run_protocol_test.sh's gateway environment. Every
# variable is accepted by both pinned revisions; both receive exactly this.
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
    "FERRUM_POOL_IDLE_TIMEOUT_SECONDS": "120",
    "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE": "true",
    "FERRUM_POOL_WARMUP_ENABLED": "true",
    "FERRUM_FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE": "8388608",
    "FERRUM_FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE": "33554432",
    "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS": "1000",
}

# Two-sided 95% Student-t critical values by degrees of freedom.
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262,
       10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110,
       18: 2.101, 19: 2.093, 20: 2.086, 25: 2.060, 30: 2.042}


class HarnessError(RuntimeError):
    """Evidence is missing, malformed, or the harness itself failed."""


# ── contract ────────────────────────────────────────────────────────────────


def _check_sha(value: str, where: str) -> None:
    if not isinstance(value, str) or len(value) != 40 or any(c not in "0123456789abcdef" for c in value) or value == "0" * 40:
        raise HarnessError(f"{where} must be an immutable nonzero 40-hex commit SHA")


def validate_contract(contract: dict, where: str = "contract") -> dict:
    if contract.get("schema_version") != SCHEMA_VERSION:
        raise HarnessError(f"{where}: unsupported schema_version {contract.get('schema_version')!r}")
    for role in ROLES:
        _check_sha(contract.get(role, {}).get("sha", ""), f"{where}: {role}.sha")
    workload = contract.get("workload", {})
    for key, literal in LITERAL_WORKLOAD.items():
        if workload.get(key) != literal:
            raise HarnessError(
                f"{where}: workload.{key} is {workload.get(key)!r} but the literal proto_bench commands in "
                f"{Path(__file__).name} measure {literal!r}; update LITERAL_WORKLOAD and the commands together")
    for key in ("rounds", "worker_threads"):
        if not isinstance(workload.get(key), int) or workload[key] <= 0:
            raise HarnessError(f"{where}: workload.{key} must be a positive integer")
    if workload["rounds"] % 4:
        raise HarnessError(f"{where}: workload.rounds must be a positive multiple of 4: role order has period 2, "
                           "route order and cell rotation period 4, so only then is every position balanced")
    margins = contract.get("margins", {})
    for key in ("throughput", "cpu_per_call", "p99"):
        if not isinstance(margins.get(key), (int, float)) or not 0 < margins[key] < 1:
            raise HarnessError(f"{where}: margins.{key} must be in (0, 1)")
    return contract


def load_contract(path: Path) -> dict:
    return validate_contract(json.loads(path.read_text(encoding="utf-8")), str(path))


# ── run ─────────────────────────────────────────────────────────────────────


def port_open(port: int) -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.2)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def wait_ready(child: subprocess.Popen, ports: tuple[int, ...], what: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise HarnessError(f"{what} exited with {child.returncode} before listening")
        if all(port_open(port) for port in ports):
            return
        time.sleep(0.25)
    raise HarnessError(f"{what} did not listen on {ports} within {timeout_s:.0f}s")


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


def clean_env() -> dict:
    """Runner-level FERRUM_* variables must not leak into either gateway."""
    return {k: v for k, v in os.environ.items() if not k.startswith("FERRUM_")}


def backend_stats() -> dict:
    with urllib.request.urlopen(BACKEND_STATS_URL, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def process_cpu_seconds(pid: int) -> float:
    """utime + stime of a live Linux process, in seconds."""
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
    # After the `(comm)` field, utime and stime are the 12th and 13th fields.
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def process_rss_kib(pid: int) -> int | None:
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return None


def scheduler_jitter_probe() -> dict:
    samples = []
    for _ in range(100):
        t0 = time.monotonic_ns()
        time.sleep(0.001)
        samples.append((time.monotonic_ns() - t0) / 1000)
    samples.sort()
    return {"sleep_1ms_avg_us": sum(samples) / len(samples), "sleep_1ms_p99_us": samples[98], "sleep_1ms_max_us": samples[-1]}


def _finish(result: subprocess.CompletedProcess, dest: Path) -> dict:
    dest.write_text(result.stdout, encoding="utf-8")
    dest.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise HarnessError(f"{dest.name}: proto_bench exited with {result.returncode}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"{dest.name}: proto_bench did not emit JSON: {exc}") from exc


def run_bench(kind: str, dest: Path, env: dict) -> dict:
    """Run one literal `proto_bench` command: a warm-up, a cell, or a probe.

    `proto_bench` resolves through `PATH` (the harness release directory is
    prepended in `cmd_run`). Every argv is spelled out because repository
    automation may not build process commands from data; `LITERAL_WORKLOAD`
    keeps the contract honest about what these commands measure.
    """
    if kind == "warmup-open":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "3", "--grpc-rpc", "unary", "--grpc-timeout-ms", "30000",
             "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "warmup-auth":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "3", "--grpc-rpc", "unary", "--grpc-timeout-ms", "30000",
             "--grpc-metadata", "x-api-key=grpc-deadline-bench-key-0001", "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "unary-open-nodeadline":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "15", "--grpc-rpc", "unary", "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "unary-open-deadline":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "15", "--grpc-rpc", "unary", "--grpc-timeout-ms", "30000",
             "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "unary-auth-nodeadline":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "15", "--grpc-rpc", "unary", "--grpc-metadata", "x-api-key=grpc-deadline-bench-key-0001",
             "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "unary-auth-deadline":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "15", "--grpc-rpc", "unary", "--grpc-timeout-ms", "30000",
             "--grpc-metadata", "x-api-key=grpc-deadline-bench-key-0001", "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "stream-open-nodeadline":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "15", "--grpc-rpc", "server-stream", "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "stream-open-deadline":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "15", "--grpc-rpc", "server-stream",
             "--grpc-timeout-ms", "30000", "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "stream-auth-nodeadline":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "15", "--grpc-rpc", "server-stream", "--grpc-metadata", "x-api-key=grpc-deadline-bench-key-0001",
             "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "stream-auth-deadline":
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "100", "--duration", "15", "--grpc-rpc", "server-stream",
             "--grpc-timeout-ms", "30000", "--grpc-metadata", "x-api-key=grpc-deadline-bench-key-0001", "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "auth-refusal":
        # Negative control on the key_auth route: the same unary call without
        # the API key must be refused before it reaches the backend.
        result = subprocess.run(
            ["proto_bench", "grpc", "--target", "http://127.0.0.1:18080", "--payload-size", "1024",
             "--concurrency", "1", "--duration", "1", "--grpc-rpc", "unary", "--json"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "probe-open":
        result = subprocess.run(
            ["proto_bench", "grpc-deadline-probe", "--target", "http://127.0.0.1:18080", "--calls", "20",
             "--grpc-timeout-ms", "250", "--backend-stats", "127.0.0.1:3010"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    elif kind == "probe-auth":
        result = subprocess.run(
            ["proto_bench", "grpc-deadline-probe", "--target", "http://127.0.0.1:18080", "--calls", "20",
             "--grpc-timeout-ms", "250", "--grpc-metadata", "x-api-key=grpc-deadline-bench-key-0001",
             "--backend-stats", "127.0.0.1:3010"], env=env, cwd=dest.parent,
            capture_output=True, text=True, timeout=180)
    else:
        raise HarnessError(f"{dest.name}: no literal proto_bench command for {kind!r}")
    return _finish(result, dest)


def counter_delta(before: dict, after: dict, key: str) -> int:
    if key not in before or key not in after:
        raise HarnessError(f"backend /bench-stats is missing {key!r}; rebuild proto_backend from this tree")
    return int(after[key]) - int(before[key])


def measure_cell(scenario: str, dest: Path, env: dict, gateway_pid: int) -> dict:
    rpc, auth, deadline = scenario.split("-")
    stats_before = backend_stats()
    cpu_before = process_cpu_seconds(gateway_pid)
    report = run_bench(scenario, dest, env)
    cpu_after = process_cpu_seconds(gateway_pid)
    stats_after = backend_stats()
    for key in ("rps", "total_requests", "total_errors", "p50_us", "p99_us"):
        if key not in report:
            raise HarnessError(f"{dest.name}: benchmark JSON is missing {key!r}")
    calls = counter_delta(stats_before, stats_after, BACKEND_COUNTER[rpc])
    other = counter_delta(stats_before, stats_after, BACKEND_COUNTER["stream" if rpc == "unary" else "unary"])
    with_deadline = counter_delta(stats_before, stats_after, "grpc_deadline_requests")
    gateway_cpu = cpu_after - cpu_before
    return {
        "scenario": scenario, "rpc": rpc, "auth": auth, "deadline": deadline,
        "rps": report["rps"], "p50_us": report["p50_us"], "p90_us": report.get("p90_us"), "p99_us": report["p99_us"],
        "total_requests": report["total_requests"], "total_errors": report["total_errors"],
        "backend_calls": calls, "backend_other_calls": other, "backend_deadline_calls": with_deadline,
        "gateway_cpu_s": gateway_cpu,
        "gateway_cpu_us_per_call": (gateway_cpu * 1e6 / calls) if calls > 0 else None,
        "gateway_rss_kib": process_rss_kib(gateway_pid),
    }


# Failures of one control's process or its bracketing /bench-stats reads. They
# are recorded in-band so the comparison keeps the rest of its evidence.
EVIDENCE_ERRORS = (HarnessError, subprocess.TimeoutExpired, urllib.error.URLError, OSError, ValueError)


def run_probe(auth: str, dest: Path, env: dict) -> dict:
    """Run the stalled-stream probe and return its evidence.

    The probe itself checks backend release after every call while its own
    connection is still open, so client teardown cannot release the streams.
    A probe that fails to run or times out is recorded as evidence, not raised:
    a failing reference must not discard the candidate's measurements.
    """
    started = None
    try:
        stats_before = backend_stats()
        report = run_bench(f"probe-{auth}", dest, env)
        started = counter_delta(stats_before, backend_stats(), "grpc_stalled_started")
        error = None
    except EVIDENCE_ERRORS as exc:
        report, error = {}, f"probe did not complete: {exc}"
    fields = ("calls", "calls_made", "deadline_exceeded", "unexpected_messages", "client_safety_timeouts",
              "grpc_timeout_ms", "release_checked", "release_failures", "max_release_wait_ms",
              "backend_stalled_started", "backend_stalled_released")
    probe = {"auth": auth, "error": error, "backend_started_crosscheck": started,
             "other_statuses": report.get("other_statuses", {}), "elapsed_ms": report.get("elapsed_ms", {})}
    probe.update({field: report.get(field) for field in fields})
    return probe


def run_auth_refusal(dest: Path, env: dict) -> dict:
    """Prove the key_auth route authenticates: a keyless call never reaches the backend.

    A control that cannot run is recorded as evidence (and fails either role),
    so the lifetime's probe row is still persisted.
    """
    try:
        stats_before = backend_stats()
        report = run_bench("auth-refusal", dest, env)
        backend_calls = counter_delta(stats_before, backend_stats(), BACKEND_COUNTER["unary"])
    except EVIDENCE_ERRORS as exc:
        return {"error": f"negative control did not complete: {exc}", "total_requests": None,
                "total_errors": None, "backend_calls": None}
    return {"error": None, "total_requests": report.get("total_requests"),
            "total_errors": report.get("total_errors"), "backend_calls": backend_calls}


def rotated(values: tuple, offset: int) -> tuple:
    offset %= len(values)
    return values[offset:] + values[:offset]


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
    shas = {"reference": args.reference_sha, "candidate": args.candidate_sha}
    for role, sha in shas.items():
        _check_sha(sha, f"{role} SHA")
    if shas["reference"] == shas["candidate"]:
        raise HarnessError("reference and candidate are the same commit; a paired comparison needs two revisions")
    for port in (*BACKEND_PORTS, GATEWAY_HTTP_PORT, GATEWAY_HTTPS_PORT, GATEWAY_ADMIN_PORT):
        if port_open(port):
            raise HarnessError(f"port {port} is already in use; the runner is not clean")

    if sha256_file(binaries["reference"]) == sha256_file(binaries["candidate"]):
        raise HarnessError("reference and candidate gateway binaries are identical; the comparison would measure nothing")
    base_env = clean_env()
    base_env["PATH"] = f"{harness_bin}{os.pathsep}{base_env.get('PATH', '')}"
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "contract_version": contract.get("contract_version"),
        "reference": {"sha": shas["reference"], "label": contract["reference"].get("label") if shas["reference"] == contract["reference"]["sha"] else "manual override",
                      "binary_sha256": sha256_file(binaries["reference"])},
        "candidate": {"sha": shas["candidate"], "label": contract["candidate"].get("label") if shas["candidate"] == contract["candidate"]["sha"] else "manual override",
                      "binary_sha256": sha256_file(binaries["candidate"])},
        "harness": {"proto_bench_sha256": sha256_file(bench_bin), "proto_backend_sha256": sha256_file(backend_bin)},
        "host": {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count()},
        "workload": workload,
        "gateway_env": {**GATEWAY_ENV, "FERRUM_WORKER_THREADS": str(workload["worker_threads"])},
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "jitter_before": scheduler_jitter_probe(),
    }

    backend_log = (out / "backend.log").open("w", encoding="utf-8")
    backend = subprocess.Popen(["proto_backend"], cwd=out, env=base_env, stdout=backend_log, stderr=subprocess.STDOUT)
    gateway: subprocess.Popen | None = None
    rows: list[dict] = []
    probes: list[dict] = []
    try:
        wait_ready(backend, BACKEND_READY_PORTS, "proto_backend")
        cert_dir = out / "certs"
        for pem in ("ca.pem", "cert.pem", "key.pem"):
            deadline = time.monotonic() + 30
            while not (cert_dir / pem).is_file():
                if time.monotonic() > deadline:
                    raise HarnessError(f"proto_backend did not write {pem}")
                time.sleep(0.2)
        config_paths = {}
        for auth, rel in CONFIGS.items():
            config_paths[auth] = out / f"gateway_{auth}.yaml"
            shutil.copyfile(harness / rel, config_paths[auth])

        for round_no in range(1, workload["rounds"] + 1):
            role_order = ROLES if round_no % 2 == 1 else tuple(reversed(ROLES))
            # Route order flips every two rounds so each role meets each route
            # in both positions; cell order rotates every round.
            auth_order = tuple(CONFIGS) if ((round_no - 1) // 2) % 2 == 0 else tuple(reversed(tuple(CONFIGS)))
            for role in role_order:
                for auth in auth_order:
                    gateway_env = {**base_env, **provenance["gateway_env"],
                                   "FERRUM_FILE_CONFIG_PATH": str(config_paths[auth]),
                                   "FERRUM_FRONTEND_TLS_CERT_PATH": str(cert_dir / "cert.pem"),
                                   "FERRUM_FRONTEND_TLS_KEY_PATH": str(cert_dir / "key.pem")}
                    tag = f"{role}-r{round_no}-{auth}"
                    log = (out / f"gateway-{tag}.log").open("w", encoding="utf-8")
                    gateway = subprocess.Popen(["target/ci-release/ferrum-edge", "run"], cwd=out / role, env=gateway_env,
                                               stdout=log, stderr=subprocess.STDOUT)
                    try:
                        wait_ready(gateway, (GATEWAY_HTTP_PORT,), f"{role} gateway ({auth})")
                        run_bench(f"warmup-{auth}", samples_dir / f"{tag}-warmup.json", base_env)
                        cells = tuple(s for s in SCENARIOS if s.split("-")[1] == auth)
                        for scenario in rotated(cells, round_no - 1):
                            row = measure_cell(scenario, samples_dir / f"{role}-r{round_no}-{scenario}.json", base_env, gateway.pid)
                            row.update({"role": role, "round": round_no})
                            rows.append(row)
                            print(json.dumps(row), flush=True)
                            # Persist progressively so an aborted run still leaves evidence.
                            (out / "rows.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
                        probe = run_probe(auth, samples_dir / f"{tag}-probe.json", base_env)
                        probe.update({"role": role, "round": round_no})
                        if auth == "auth":
                            probe["auth_refusal"] = run_auth_refusal(samples_dir / f"{tag}-auth-refusal.json", base_env)
                        probes.append(probe)
                        print(json.dumps(probe), flush=True)
                        (out / "probes.json").write_text(json.dumps(probes, indent=2) + "\n", encoding="utf-8")
                        if gateway.poll() is not None:
                            raise HarnessError(f"{role} gateway ({auth}) exited during round {round_no}")
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


def t95(df: int) -> float:
    if df < 1:
        return float("inf")
    if df in T95:
        return T95[df]
    eligible = [k for k in T95 if k <= df]
    return T95[max(eligible)]


def log_interval(values: list[float]) -> dict:
    """Mean and two-sided 95% interval of paired log ratios, back-transformed."""
    n = len(values)
    mean = statistics.fmean(values)
    sd = statistics.stdev(values) if n > 1 else float("inf")
    half = t95(n - 1) * sd / math.sqrt(n) if n > 1 else float("inf")
    return {"ratio": math.exp(mean), "low": math.exp(mean - half) if math.isfinite(half) else 0.0,
            "high": math.exp(mean + half) if math.isfinite(half) else float("inf"), "n": n,
            "per_round": [math.exp(v) for v in values]}


def sample_integrity(row: dict) -> list[str]:
    where = f"{row['role']} round {row['round']} {row['scenario']}"
    problems = []
    if row.get("total_errors"):
        problems.append(f"{where}: {row['total_errors']} client errors")
    if not row.get("total_requests") or not row.get("rps"):
        problems.append(f"{where}: no successful calls were measured")
    calls = row.get("backend_calls", 0)
    if calls < row.get("total_requests", 0):
        problems.append(f"{where}: backend saw {calls} calls, fewer than the {row.get('total_requests')} measured")
    if row.get("backend_other_calls"):
        problems.append(f"{where}: backend saw {row['backend_other_calls']} calls of the other RPC shape")
    expected = calls if row["deadline"] == "deadline" else 0
    if row.get("backend_deadline_calls") != expected:
        problems.append(f"{where}: {row.get('backend_deadline_calls')} of {calls} backend calls carried grpc-timeout, expected {expected}")
    if row.get("gateway_cpu_us_per_call") is None:
        problems.append(f"{where}: gateway CPU per call is unavailable")
    return problems


def auth_refusal_problems(probe: dict) -> list[str]:
    """The key_auth route must refuse a keyless call, in both revisions."""
    if probe["auth"] != "auth":
        return []
    where = f"{probe['role']} round {probe['round']} key_auth negative control"
    refusal = probe.get("auth_refusal")
    if not isinstance(refusal, dict):
        return [f"{where}: missing"]
    if refusal.get("error"):
        return [f"{where}: {refusal['error']}"]
    if refusal.get("total_requests") or not refusal.get("total_errors") or refusal.get("backend_calls"):
        return [f"{where}: a call without the API key was not refused before the backend "
                f"({refusal.get('total_requests')} succeeded, {refusal.get('total_errors')} errors, "
                f"{refusal.get('backend_calls')} reached the backend); the auth cells may not be authenticated"]
    return []


def probe_problems(probe: dict, timeout_ms: int, expected_calls: int) -> list[str]:
    where = f"{probe['role']} round {probe['round']} {probe['auth']} probe"
    if probe.get("error"):
        return [f"{where}: {probe['error']}"]
    problems = []
    made = probe.get("calls_made") or 0
    if probe.get("calls") != expected_calls or made != expected_calls:
        problems.append(f"{where}: made {made} of {expected_calls} calls (it stops at the first call nothing ended "
                        "or the first stream the backend still held)")
    if probe.get("deadline_exceeded") != expected_calls:
        problems.append(f"{where}: {probe.get('deadline_exceeded')} of {expected_calls} calls ended DEADLINE_EXCEEDED "
                        f"(others {probe.get('other_statuses')}, safety timeouts {probe.get('client_safety_timeouts')})")
    if probe.get("unexpected_messages"):
        problems.append(f"{where}: received {probe['unexpected_messages']} messages from a stalled stream")
    elapsed = probe.get("elapsed_ms") or {}
    if elapsed.get("min", 0) < 0.9 * timeout_ms:
        problems.append(f"{where}: a call ended after {elapsed.get('min', 0):.0f} ms, before the {timeout_ms} ms deadline")
    if elapsed.get("max", float("inf")) > timeout_ms + 1000:
        problems.append(f"{where}: a call took {elapsed.get('max', 0):.0f} ms against a {timeout_ms} ms deadline")
    if probe.get("release_checked") is not True:
        problems.append(f"{where}: backend release was not checked while the client connection was open")
    if probe.get("release_failures"):
        problems.append(f"{where}: the backend still held a stalled stream 5 s after its call ended, "
                        "with the client connection still open")
    if probe.get("backend_stalled_started") != made or probe.get("backend_stalled_released") != made:
        problems.append(f"{where}: backend opened {probe.get('backend_stalled_started')} and released "
                        f"{probe.get('backend_stalled_released')} stalled streams for {made} calls")
    if probe.get("backend_started_crosscheck") != made:
        problems.append(f"{where}: backend counted {probe.get('backend_started_crosscheck')} stalled streams across "
                        f"the probe for {made} calls")
    return problems


def index_rows(rows: list[dict], rounds: int) -> dict:
    table: dict[tuple[str, str, int], dict] = {}
    for row in rows:
        key = (row["role"], row["scenario"], row["round"])
        if row["role"] not in ROLES or row["scenario"] not in SCENARIOS or key in table:
            raise HarnessError(f"duplicate or unknown sample {key}")
        table[key] = row
    missing = [(role, scenario, r) for role in ROLES for scenario in SCENARIOS for r in range(1, rounds + 1)
               if (role, scenario, r) not in table]
    if missing:
        raise HarnessError(f"missing samples: {missing[:6]}{' …' if len(missing) > 6 else ''}")
    return table


METRICS = (("throughput", "rps"), ("cpu_per_call", "gateway_cpu_us_per_call"), ("p99", "p99_us"))


def verdict(interval_by_metric: dict, margins: dict) -> str:
    """Throughput and CPU per call are primary. p99 is secondary: an interval
    wholly above its margin marks a regression, but p99 noise alone never
    prevents a `no material regression` verdict."""
    rps, cpu, p99 = (interval_by_metric[m] for m in ("throughput", "cpu_per_call", "p99"))
    if (rps["high"] < 1 - margins["throughput"] or cpu["low"] > 1 + margins["cpu_per_call"]
            or p99["low"] > 1 + margins["p99"]):
        return "regression"
    if rps["low"] >= 1 - margins["throughput"] and cpu["high"] <= 1 + margins["cpu_per_call"]:
        return "no material regression"
    return "inconclusive"


def evaluate(contract: dict, rows: list[dict], probes: list[dict]) -> dict:
    rounds = contract["workload"]["rounds"]
    margins = contract["margins"]
    failures: list[str] = []
    notes: list[str] = []
    table = index_rows(rows, rounds)
    for row in rows:
        failures.extend(sample_integrity(row))
    computable = all(isinstance(row.get(field), (int, float)) and row[field] > 0 for row in rows for _, field in METRICS)
    timeout_ms = contract["workload"]["probe_grpc_timeout_ms"]
    probe_calls = contract["workload"]["probe_calls"]
    probe_seen = {(p["role"], p["auth"], p["round"]) for p in probes}
    for role in ROLES:
        for auth in CONFIGS:
            for r in range(1, rounds + 1):
                if (role, auth, r) not in probe_seen:
                    failures.append(f"{role} round {r} {auth} probe is missing")
    for probe in probes:
        failures.extend(auth_refusal_problems(probe))
        problems = probe_problems(probe, timeout_ms, probe_calls)
        if probe["role"] == "candidate":
            failures.extend(problems)
        else:
            notes.extend(f"reference (informational): {p}" for p in problems)

    if not computable:
        failures.append("some samples lack positive throughput, CPU-per-call or p99; no ratios were computed")
        return {"schema_version": SCHEMA_VERSION, "status": "fail", "contract_version": contract.get("contract_version"),
                "margins": margins, "rounds": rounds, "cells": {}, "deadline_effects": {}, "null_controls": {},
                "failures": failures, "notes": notes}

    def log_ratio(scenario: str, field: str, r: int) -> float:
        return math.log(table[("candidate", scenario, r)][field] / table[("reference", scenario, r)][field])

    cells = {}
    for scenario in SCENARIOS:
        cell = {}
        for metric, field in METRICS:
            cell[metric] = log_interval([log_ratio(scenario, field, r) for r in range(1, rounds + 1)])
        for role in ROLES:
            cell[f"{role}_median_rps"] = statistics.median(table[(role, scenario, r)]["rps"] for r in range(1, rounds + 1))
            cell[f"{role}_median_p99_us"] = statistics.median(table[(role, scenario, r)]["p99_us"] for r in range(1, rounds + 1))
            cell[f"{role}_median_cpu_us_per_call"] = statistics.median(
                table[(role, scenario, r)]["gateway_cpu_us_per_call"] for r in range(1, rounds + 1))
        cells[scenario] = cell

    deadline_effects = {}
    for rpc in RPCS:
        for auth in CONFIGS:
            with_d, without = f"{rpc}-{auth}-deadline", f"{rpc}-{auth}-nodeadline"
            effect = {}
            for metric, field in METRICS:
                effect[metric] = log_interval([log_ratio(with_d, field, r) - log_ratio(without, field, r)
                                               for r in range(1, rounds + 1)])
            effect["verdict"] = verdict(effect, margins)
            # Same binary, same gateway lifetime: what the deadline path costs in each revision.
            for role in ROLES:
                effect[f"{role}_deadline_cost"] = {
                    metric: log_interval([math.log(table[(role, with_d, r)][field] / table[(role, without, r)][field])
                                          for r in range(1, rounds + 1)])
                    for metric, field in METRICS}
            deadline_effects[f"{rpc}-{auth}"] = effect
    null_controls = {s: verdict(cells[s], margins) for s in SCENARIOS if s.endswith("nodeadline")}
    for scenario, result in null_controls.items():
        if result != "no material regression":
            notes.append(f"null control {scenario} is {result}: revision-wide or runner drift is present; "
                         "rely on the difference-in-differences, not the raw deadline-cell ratio")
    regressions = [k for k, v in deadline_effects.items() if v["verdict"] == "regression"]
    status = "fail" if failures else ("regression" if regressions else
                                       ("inconclusive" if any(v["verdict"] == "inconclusive" for v in deadline_effects.values()) else "pass"))
    return {"schema_version": SCHEMA_VERSION, "status": status, "contract_version": contract.get("contract_version"),
            "margins": margins, "rounds": rounds, "cells": cells, "deadline_effects": deadline_effects,
            "null_controls": null_controls, "failures": failures, "notes": notes}


def _pct(ratio: float) -> str:
    return f"{(ratio - 1) * 100:+.1f}%"


def _ci(interval: dict) -> str:
    return f"{_pct(interval['ratio'])} [{_pct(interval['low'])}, {_pct(interval['high'])}]"


def summary_markdown(report: dict, provenance: dict) -> str:
    lines = ["## gRPC RPC-deadline response path A/B (#6904)", ""]
    for role in ROLES:
        info = provenance.get(role, {})
        lines.append(f"- {role.capitalize()}: `{info.get('sha', '?')}` ({info.get('label', '')})")
    lines.append(f"- Rounds: {report['rounds']} (alternating role order); margins: throughput "
                 f"{report['margins']['throughput']:.0%}, CPU/call {report['margins']['cpu_per_call']:.0%}, "
                 f"p99 {report['margins']['p99']:.0%} (regression-only)")
    lines.append(f"- Status: **{report['status']}**")
    lines += ["", "### Deadline-path effect (difference-in-differences, candidate vs reference, 95% CI)", "",
              "| Cell | Throughput | Gateway CPU / call | p99 | Verdict |", "|---|---|---|---|---|"]
    for key, effect in report["deadline_effects"].items():
        lines.append(f"| {key} | {_ci(effect['throughput'])} | {_ci(effect['cpu_per_call'])} | {_ci(effect['p99'])} | {effect['verdict']} |")
    lines += ["", "### Same-binary deadline cost (deadline cell vs deadline-free sibling, 95% CI)", "",
              "| Cell | Reference throughput | Candidate throughput | Reference CPU/call | Candidate CPU/call |",
              "|---|---|---|---|---|"]
    for key, effect in report["deadline_effects"].items():
        ref, cand = effect["reference_deadline_cost"], effect["candidate_deadline_cost"]
        lines.append(f"| {key} | {_ci(ref['throughput'])} | {_ci(cand['throughput'])} | {_ci(ref['cpu_per_call'])} | {_ci(cand['cpu_per_call'])} |")
    lines += ["", "### Per-cell candidate/reference ratios", "",
              "| Cell | Ref RPS | Cand RPS | Throughput | CPU/call (ref → cand µs) | p99 (ref → cand ms) |",
              "|---|---:|---:|---|---|---|"]
    for scenario, cell in report["cells"].items():
        lines.append(f"| {scenario} | {cell['reference_median_rps']:.0f} | {cell['candidate_median_rps']:.0f} | {_ci(cell['throughput'])} "
                     f"| {cell['reference_median_cpu_us_per_call']:.1f} → {cell['candidate_median_cpu_us_per_call']:.1f} "
                     f"| {cell['reference_median_p99_us'] / 1000:.2f} → {cell['candidate_median_p99_us'] / 1000:.2f} |")
    if report["failures"]:
        lines += ["", "### Failures"] + [f"- {f}" for f in report["failures"]]
    if report["notes"]:
        lines += ["", "### Notes"] + [f"- {n}" for n in report["notes"]]
    jitter = provenance.get("jitter_before", {})
    if jitter:
        lines += ["", f"Runner scheduler jitter before measurement: 1 ms sleep p99 {jitter.get('sleep_1ms_p99_us', 0):.0f} µs."]
    return "\n".join(lines) + "\n"


def cmd_evaluate(args: argparse.Namespace) -> int:
    contract = load_contract(Path(args.contract))
    out = Path(args.output).resolve()
    paths = {name: out / f"{name}.json" for name in ("rows", "probes", "provenance")}
    if not all(p.is_file() for p in paths.values()):
        print("::error::comparison evidence (rows.json / probes.json / provenance.json) is missing", file=sys.stderr)
        return 1
    rows, probes, provenance = (json.loads(paths[n].read_text(encoding="utf-8")) for n in ("rows", "probes", "provenance"))
    report = evaluate(contract, rows, probes)
    report["reference_sha"] = provenance.get("reference", {}).get("sha")
    report["candidate_sha"] = provenance.get("candidate", {}).get("sha")
    Path(args.report_out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown = summary_markdown(report, provenance)
    print(markdown)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(markdown)
    for failure in report["failures"]:
        print(f"::error::{failure}")
    for key, effect in report["deadline_effects"].items():
        if effect["verdict"] == "regression":
            print(f"::warning::{key}: the deadline path regressed beyond the contract margins (throughput {_ci(effect['throughput'])}, "
                  f"CPU/call {_ci(effect['cpu_per_call'])}, p99 {_ci(effect['p99'])})")
    return 1 if report["failures"] else 0


# ── self-test ───────────────────────────────────────────────────────────────


def _contract() -> dict:
    return {"schema_version": SCHEMA_VERSION, "contract_version": "test",
            "reference": {"sha": "de67b235ae3589bd26090c29180b667f5e2f54c3"},
            "candidate": {"sha": "3fe50f8dc6473a734141e8f9b8710f611ef80172"},
            "workload": {**LITERAL_WORKLOAD, "rounds": 4, "worker_threads": 2},
            "margins": {"throughput": 0.03, "cpu_per_call": 0.05, "p99": 0.10}}


def _rows(rounds: int = 4, cand_deadline_factor: float = 1.0, drift: float = 1.0, noise: float = 0.002) -> list[dict]:
    rows = []
    for role in ROLES:
        for scenario in SCENARIOS:
            rpc, auth, deadline = scenario.split("-")
            for r in range(1, rounds + 1):
                rps = 10000.0 * (0.97 if deadline == "deadline" else 1.0)
                if role == "candidate":
                    rps *= drift * (cand_deadline_factor if deadline == "deadline" else 1.0)
                # Deterministic noise that differs by role, cell and round.
                spread = ((r * 7 + SCENARIOS.index(scenario) * 3 + ROLES.index(role) * 2) % 5 - 2) / 2
                rps *= 1 + noise * spread
                calls = int(rps * 15)
                cpu_per_call = 40.0 * 10000.0 / rps
                rows.append({"role": role, "round": r, "scenario": scenario, "rpc": rpc, "auth": auth, "deadline": deadline,
                             "rps": rps, "p50_us": 4000, "p90_us": 6000, "p99_us": 8000 * 10000.0 / rps,
                             "total_requests": calls, "total_errors": 0, "backend_calls": calls + 300,
                             "backend_other_calls": 0, "backend_deadline_calls": calls + 300 if deadline == "deadline" else 0,
                             "gateway_cpu_s": cpu_per_call * calls / 1e6, "gateway_cpu_us_per_call": cpu_per_call,
                             "gateway_rss_kib": 50000})
    return rows


def _probes(rounds: int = 4) -> list[dict]:
    return [{"role": role, "auth": auth, "round": r, "error": None, "calls": 20, "calls_made": 20,
             "deadline_exceeded": 20, "other_statuses": {}, "unexpected_messages": 0, "client_safety_timeouts": 0,
             "elapsed_ms": {"min": 251.0, "median": 253.0, "max": 260.0}, "grpc_timeout_ms": 250,
             "release_checked": True, "release_failures": 0, "max_release_wait_ms": 4.0,
             "backend_stalled_started": 20, "backend_stalled_released": 20, "backend_started_crosscheck": 20,
             **({"auth_refusal": {"error": None, "total_requests": 0, "total_errors": 1, "backend_calls": 0}}
                if auth == "auth" else {})}
            for role in ROLES for auth in CONFIGS for r in range(1, rounds + 1)]


def self_test() -> int:
    c = _contract()
    validate_contract(c)
    eight = json.loads(json.dumps(c))
    eight["workload"]["rounds"] = 8
    validate_contract(eight)
    # Identical revisions: every deadline effect is within margins.
    report = evaluate(c, _rows(), _probes())
    assert report["status"] == "pass", report["status"]
    assert all(v["verdict"] == "no material regression" for v in report["deadline_effects"].values())
    # A 10% candidate loss confined to deadline cells is a regression...
    report = evaluate(c, _rows(cand_deadline_factor=0.90), _probes())
    assert report["status"] == "regression" and not report["failures"], report["status"]
    assert all(abs(v["throughput"]["ratio"] - 0.90) < 0.01 for v in report["deadline_effects"].values())
    # ...while a uniform 10% revision-wide drift cancels in the difference-in-differences
    # and is reported against the null controls instead.
    report = evaluate(c, _rows(drift=0.90), _probes())
    assert report["status"] == "pass", report["status"]
    assert any("null control" in n for n in report["notes"])
    # The same-binary deadline cost is measured inside each revision.
    cost = report["deadline_effects"]["unary-open"]["candidate_deadline_cost"]["throughput"]["ratio"]
    assert abs(cost - 0.97) < 0.01, cost
    # Noise wider than the margin is inconclusive, never a pass.
    report = evaluate(c, _rows(noise=0.05, cand_deadline_factor=0.99), _probes())
    assert report["status"] == "inconclusive", report["status"]
    # Integrity: a deadline cell whose calls lost grpc-timeout fails...
    rows = _rows()
    next(r for r in rows if r["scenario"] == "stream-auth-deadline")["backend_deadline_calls"] = 0
    assert evaluate(c, rows, _probes())["status"] == "fail"
    # ...as does a deadline-free cell that carried one, or client errors.
    rows = _rows()
    next(r for r in rows if r["scenario"] == "unary-open-nodeadline")["backend_deadline_calls"] = 5
    assert evaluate(c, rows, _probes())["status"] == "fail"
    rows = _rows()
    rows[7]["total_errors"] = 1
    assert evaluate(c, rows, _probes())["status"] == "fail"
    rows = _rows()
    rows[3]["gateway_cpu_us_per_call"] = None
    report = evaluate(c, rows, _probes())
    assert report["status"] == "fail" and not report["deadline_effects"], report["status"]
    summary_markdown(report, {})
    # A missing sample is a harness error.
    try:
        evaluate(c, _rows()[1:], _probes())
    except HarnessError:
        pass
    else:
        raise AssertionError("a missing sample must be a harness error")
    # Probe: a candidate stream left open fails; the same on the reference is a note.
    probes = _probes()
    next(p for p in probes if p["role"] == "candidate")["backend_stalled_released"] = 19
    assert evaluate(c, _rows(), probes)["status"] == "fail"
    # Release must be proven while the client connection was open, and a probe
    # that stopped early (nothing ended a call) or never ran fails the candidate.
    for field, value in (("release_checked", False), ("release_failures", 1), ("calls_made", 3),
                         ("error", "probe did not complete: timeout")):
        probes = _probes()
        next(p for p in probes if p["role"] == "candidate")[field] = value
        assert evaluate(c, _rows(), probes)["status"] == "fail", field
    # A key_auth route that let a keyless call through fails either role.
    for role in ROLES:
        probes = _probes()
        next(p for p in probes if p["role"] == role and p["auth"] == "auth")["auth_refusal"]["backend_calls"] = 1
        assert evaluate(c, _rows(), probes)["status"] == "fail", role
    probes = _probes()
    del next(p for p in probes if p["auth"] == "auth")["auth_refusal"]
    assert evaluate(c, _rows(), probes)["status"] == "fail"
    probes = _probes()
    next(p for p in probes if p["role"] == "reference" and p["auth"] == "auth")["auth_refusal"] = {
        "error": "negative control did not complete: timeout", "total_requests": None, "total_errors": None,
        "backend_calls": None}
    assert evaluate(c, _rows(), probes)["status"] == "fail"
    # p99 alone can mark a regression when it is wholly beyond its margin.
    rows = _rows()
    for row in rows:
        if row["role"] == "candidate" and row["deadline"] == "deadline":
            row["p99_us"] *= 1.5
    assert evaluate(c, rows, _probes())["status"] == "regression"
    # The same failure on the reference is informational and keeps the comparison.
    probes = _probes()
    next(p for p in probes if p["role"] == "reference")["error"] = "probe did not complete: timeout"
    report = evaluate(c, _rows(), probes)
    assert report["status"] == "pass" and any("probe did not complete" in n for n in report["notes"]), report["notes"]
    probes = _probes()
    next(p for p in probes if p["role"] == "reference")["deadline_exceeded"] = 0
    report = evaluate(c, _rows(), probes)
    assert report["status"] == "pass" and any(n.startswith("reference (informational)") for n in report["notes"])
    probes = _probes()
    next(p for p in probes if p["role"] == "candidate")["elapsed_ms"]["min"] = 100.0
    assert evaluate(c, _rows(), probes)["status"] == "fail"
    assert evaluate(c, _rows(), _probes()[1:])["status"] == "fail"
    # The contract cannot drift from the literal commands or unbalance role order.
    for key, value in (("duration_secs", 5), ("rounds", 5), ("rounds", 2), ("rounds", 6)):
        bad = json.loads(json.dumps(c))
        bad["workload"][key] = value
        try:
            validate_contract(bad)
        except HarnessError:
            pass
        else:
            raise AssertionError(f"workload.{key}={value} must be rejected")
    bad = json.loads(json.dumps(c))
    bad["candidate"]["sha"] = "0" * 40
    try:
        validate_contract(bad)
    except HarnessError:
        pass
    else:
        raise AssertionError("a zero SHA must be rejected")
    # Every literal command exists for every cell and route.
    source = Path(__file__).read_text(encoding="utf-8")
    for kind in (*SCENARIOS, *(f"warmup-{a}" for a in CONFIGS), *(f"probe-{a}" for a in CONFIGS), "auth-refusal"):
        assert f'kind == "{kind}"' in source, kind
    summary_markdown(evaluate(c, _rows(), _probes()), {"reference": {"sha": "a"}, "candidate": {"sha": "b"}})
    print("grpc_deadline_comparison self-test passed")
    return 0


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
