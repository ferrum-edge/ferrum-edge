#!/usr/bin/env python3
"""Capture runner/toolchain provenance for mesh performance baseline collection.

Pure inspection: reads environment and host facts, writes JSON. Does not build,
bench, or mutate repository sources.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path


def read_fact(facts_dir: Path, name: str) -> str:
    path = facts_dir / name
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as error:
        return f"<unavailable: {error}>"


def first_matching_line(text: str, needle: str) -> str | None:
    for line in text.splitlines():
        if needle.lower() in line.lower():
            return line.strip()
    return None


def parse_meminfo_kib(meminfo: str, key: str) -> int | None:
    prefix = f"{key}:"
    for line in meminfo.splitlines():
        if line.startswith(prefix):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return None


def parse_e2e_repetitions() -> int | None:
    raw = os.environ.get("BENCH_ITERATIONS", "3")
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    if value < 1:
        return None
    return value


def load_suite_commands(path: Path) -> list[object] | None:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(loaded, list):
        return None
    return loaded


def cargo_pkg_version(manifest: Path, package: str) -> str | None:
    if not manifest.is_file():
        return None
    text = manifest.read_text(encoding="utf-8")
    # Prefer lockfile identity when present; fall back to Cargo.toml pin.
    lock = manifest.with_name("Cargo.lock")
    if lock.is_file():
        lock_text = lock.read_text(encoding="utf-8")
        marker = f'name = "{package}"'
        idx = lock_text.find(marker)
        if idx != -1:
            window = lock_text[idx : idx + 200]
            for line in window.splitlines():
                if line.startswith("version = "):
                    return line.split("=", 1)[1].strip().strip('"')
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{package} ") or stripped.startswith(f"{package}="):
            # criterion = { version = "0.5", ... }
            if "version" in stripped:
                start = stripped.find('"')
                end = stripped.find('"', start + 1) if start != -1 else -1
                if start != -1 and end != -1:
                    return stripped[start + 1 : end]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--host-facts-dir",
        type=Path,
        required=True,
        help="Directory of literal-command host/toolchain captures",
    )
    parser.add_argument(
        "--suite-commands",
        type=Path,
        help="Optional JSON file listing exact suite commands that will run",
    )
    args = parser.parse_args()

    lscpu = read_fact(args.host_facts_dir, "lscpu.txt")
    uname_a = read_fact(args.host_facts_dir, "uname.txt")
    free_h = read_fact(args.host_facts_dir, "free.txt")
    meminfo = read_fact(args.host_facts_dir, "meminfo.txt")
    rustc_v = read_fact(args.host_facts_dir, "rustc-version.txt")
    cargo_v = read_fact(args.host_facts_dir, "cargo-version.txt")
    nproc = read_fact(args.host_facts_dir, "nproc.txt")

    mem_total_kib = parse_meminfo_kib(meminfo, "MemTotal")
    suite_commands: list[object] = []
    if args.suite_commands is not None:
        if not args.suite_commands.is_file():
            print("::error::suite command ledger is missing")
            return 1
        loaded = load_suite_commands(args.suite_commands)
        if loaded is None:
            print("::error::suite command ledger is malformed")
            return 1
        suite_commands = loaded

    e2e_repetitions = parse_e2e_repetitions()
    if e2e_repetitions is None:
        print("::error::BENCH_ITERATIONS is missing or malformed")
        return 1

    repo_root = Path(__file__).resolve().parents[2]
    mesh_manifest = repo_root / "tests" / "performance" / "mesh" / "Cargo.toml"
    hbone_manifest = repo_root / "tests" / "performance" / "mesh-hbone-e2e" / "Cargo.toml"
    dns_manifest = repo_root / "tests" / "performance" / "mesh-dns-e2e" / "Cargo.toml"

    provenance = {
        "schema_version": 1,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "github": {
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "job": os.environ.get("GITHUB_JOB"),
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "ref": os.environ.get("GITHUB_REF"),
            "server_url": os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
        },
        "runner": {
            "class": os.environ.get("BENCH_RUNNER_CLASS", "ubuntu-26.04"),
            "name": os.environ.get("RUNNER_NAME"),
            "os": os.environ.get("RUNNER_OS") or platform.system(),
            "arch": os.environ.get("RUNNER_ARCH") or platform.machine(),
            "nproc": nproc,
            "cpu_model": first_matching_line(lscpu, "Model name"),
            "cpu_topology": {
                "cpus": first_matching_line(lscpu, "CPU(s):"),
                "threads_per_core": first_matching_line(lscpu, "Thread(s) per core"),
                "cores_per_socket": first_matching_line(lscpu, "Core(s) per socket"),
                "sockets": first_matching_line(lscpu, "Socket(s):"),
                "hypervisor": first_matching_line(lscpu, "Hypervisor"),
                "virtualization": first_matching_line(lscpu, "Virtualization"),
            },
            "lscpu_raw": lscpu,
            "ram": {
                "memtotal_kib": mem_total_kib,
                "memtotal_gib": round(mem_total_kib / (1024 * 1024), 2)
                if mem_total_kib
                else None,
                "free_h": free_h,
            },
            "uname": uname_a,
            "kernel": platform.release(),
            "platform": platform.platform(),
        },
        "toolchain": {
            "rustc_verbose": rustc_v,
            "cargo_verbose": cargo_v,
            "rust_toolchain_file": "rust-toolchain.toml channel=stable",
        },
        "build": {
            "gateway_profile": os.environ.get("BENCH_BUILD_PROFILE", "release"),
            "gateway_features": os.environ.get("BENCH_GATEWAY_FEATURES", "default (no --features)"),
            "harness_profile": "release",
            "non_default_settings_note": (
                "Suites use each harness run.sh defaults plus the documented "
                "baseline row parameters. Mesh DNS sets explicit FERRUM_MESH_DNS_* "
                "env vars inside tests/performance/mesh-dns-e2e/run.sh and "
                "benchmark-only FERRUM_MESH_ALLOW_NO_CA=true in start_gateway() "
                "(no gateway SVID/CA; production mesh must provide identity)."
            ),
        },
        "dependency_harness_versions": {
            "mesh_criterion": cargo_pkg_version(mesh_manifest, "criterion"),
            "mesh_crate": "mesh-perf (tests/performance/mesh)",
            "hbone_crate": "mesh-hbone-e2e-perf (tests/performance/mesh-hbone-e2e)",
            "dns_crate": "mesh-dns-e2e-perf (tests/performance/mesh-dns-e2e)",
            "hdrhistogram_hbone": cargo_pkg_version(hbone_manifest, "hdrhistogram"),
            "hdrhistogram_dns": cargo_pkg_version(dns_manifest, "hdrhistogram"),
        },
        "warmup_and_repetitions": {
            "mesh_microbench": (
                "Criterion default warm-up plus configured --warm-up-time / "
                "--measurement-time flags recorded in suite_commands"
            ),
            "e2e_repetitions": e2e_repetitions,
            "e2e_policy": (
                "At least three clean repetitions (configured count, never below "
                "three); discard/fail publication if any retained row has non-zero "
                "unexplained errors or NXDOMAIN counts, or if CPU steal exceeds 5.0% on the "
                "pre-collection sample or any selected mesh Criterion / E2E workload-interval "
                "/proc/stat delta"
            ),
        },
        "suite_commands": suite_commands,
        "overhead_formula": {
            "hbone_rps_overhead_percent": (
                "((direct_rps - gateway_hbone_rps) / direct_rps) * 100"
            ),
            "dns_upstream_forward_overhead_percent": (
                "((direct_stub_qps - gateway_upstream_forward_qps) / direct_stub_qps) * 100"
            ),
            "notes": (
                "Overhead is throughput loss versus the same-run direct path. "
                "Latency deltas are reported separately and are not folded into "
                "the overhead percent column."
            ),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote provenance to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
