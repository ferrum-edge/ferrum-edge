#!/usr/bin/env python3
"""Run a balanced mesh campaign; adjacent same-payload baseline/candidate pairs.

The harness and load generator always come from the dispatched revision. The
optional baseline changes only the Ferrum image, built with the same Dockerfile,
features and profile as the candidate. Every raw cell and failed arm is retained.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ARMS = ("direct", "ferrum", "envoy", "consul", "consulhttp", "linkerd")
SIZES = (1024, 10240, 71680, 512000, 1048576, 5242880)


def workload_limits(duration):
    """Explicit harness limits shared by every arm; no timeout A/B drift."""
    return {"warmup_secs": 2, "probe_exchange_timeout_secs": 2,
            "exchange_timeout_secs": 10, "readiness_timeout_secs": 90,
            "cell_wall_timeout_secs": duration + 2 + 2 * 10 + 20,
            "cell_kill_grace_secs": 5, "cell_cleanup_timeout_secs": 2,
            "arm_wall_timeout_secs": duration + 420, "arm_kill_grace_secs": 10}


def plan(arms, sizes, iterations, paired):
    sequence = []
    for repetition in range(1, iterations + 1):
        # Reverse blocks and payload order every other round. Ferrum A/B stay
        # adjacent; their order alternates as AB/BA/AB. No independent runners.
        order = list(arms if repetition % 2 else reversed(arms))
        for payload in sizes if repetition % 2 else reversed(sizes):
            for arm in order:
                pair = ["ferrumbaseline", "ferrum"] if repetition % 2 else ["ferrum", "ferrumbaseline"]
                for measured in pair if paired and arm == "ferrum" else [arm]:
                    sequence.append({"arm": measured, "payload": payload, "repetition": repetition})
    return sequence


def build(args):
    root = Path.cwd()
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    baseline = os.environ.get("BENCH_BASELINE_SHA", "")
    profile = os.environ.get("BENCH_CARGO_PROFILE", "release")
    features = os.environ.get("BENCH_FERRUM_FEATURES", "cloud-secrets")
    if profile not in ("release", "ci-release"):
        raise ValueError("unsupported profile")
    if features not in ("cloud-secrets", "cloud-secrets,bench-h1-profile"):
        raise ValueError("unsupported features")
    if baseline and not re.fullmatch(r"[0-9a-f]{40}", baseline):
        raise ValueError("baseline must be an exact lowercase 40-hex commit SHA")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    provenance = {"candidate_sha": revision, "baseline_sha": baseline or None,
                  "workload_limits": workload_limits(int(os.environ.get("BENCH_DURATION", "30"))),
                  "profile": profile, "features": features, "runner": os.environ.get("RUNNER_OS"),
                  "run_url": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY')}/actions/runs/{os.environ.get('GITHUB_RUN_ID')}",
                  "candidate_image_id": subprocess.check_output(["docker", "image", "inspect", "ferrum-edge:bench", "--format", "{{.Id}}"], text=True).strip(),
                  "tools_image_id": subprocess.check_output(["docker", "image", "inspect", "mesh-bench-tools:local", "--format", "{{.Id}}"], text=True).strip(),
                  "configuration_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                           for p in sorted(Path("tests/performance/mesh_runtime/configs").rglob("*")) if p.is_file()},
                  "topology": "host-network same-host two Sidecar proxies; no capture/CNI/cross-node; H1 POST echo",
                  "consul": "L4 TCP mTLS (legacy control)", "consulhttp": "L7 HTTP mTLS (explicit service-defaults)",
                  "envoy": "static Envoy H2 mTLS, not full Istio", "ferrum": "full mesh Sidecar H2 mTLS"}
    if baseline:
        provenance["baseline_image_id"] = subprocess.check_output(["docker", "image", "inspect", "ferrum-edge:baseline", "--format", "{{.Id}}"], text=True).strip()
    (results / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (results / "lscpu.txt").write_text(subprocess.check_output(["lscpu"], text=True))
    (results / "uname.txt").write_text(subprocess.check_output(["uname", "-a"], text=True))
    (results / "memory.txt").write_text(subprocess.check_output(["free", "-b"], text=True))
    (results / "docker.txt").write_text(subprocess.check_output(["docker", "version"], text=True))


def measure(args):
    results = args.results.resolve()
    provenance = json.loads((results / "provenance.json").read_text())
    skip = set(os.environ.get("BENCH_SKIP_MESHES", "").split())
    skip_sizes = set(os.environ.get("BENCH_SKIP_PAYLOAD_SIZES", "").split())
    if skip - set(ARMS) or skip_sizes - {str(p) for p in SIZES}:
        raise ValueError("unknown skipped arm or payload")
    arms = [a for a in ARMS if a not in skip]
    sizes = [p for p in SIZES if str(p) not in skip_sizes]
    duration = int(os.environ.get("BENCH_DURATION", "30"))
    concurrency = int(os.environ.get("BENCH_CONCURRENCY", "100"))
    iterations = int(os.environ.get("BENCH_ITERATIONS", "3"))
    if not arms or not sizes or duration <= 0 or concurrency <= 0 or iterations not in (1, 3, 4):
        raise ValueError("empty or invalid campaign")
    sequence = plan(arms, sizes, iterations, bool(provenance["baseline_sha"]))
    (results / "campaign.json").write_text(json.dumps({"cells": sequence, "duration": duration,
        "concurrency": concurrency, "workload_limits": workload_limits(duration),
        "order": "balanced round blocks; paired AB/BA Ferrum images"}, indent=2) + "\n")
    (results / "plan.txt").write_text("".join(f"{c['arm']} {c['payload']} {c['repetition']}\n" for c in sequence))


def relabel(directory):
    for file in list(directory.glob("ferrum*.json")):
        document = json.loads(file.read_text())
        for key in ("mesh", "gateway"):
            if document.get(key) == "ferrum":
                document[key] = "ferrumbaseline"
        renamed = file.with_name(file.name.replace("ferrum", "ferrumbaseline", 1))
        renamed.write_text(json.dumps(document, indent=2) + "\n")
        file.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("provenance", "plan", "relabel"))
    parser.add_argument("--results", type=Path, default=Path("results"))
    args = parser.parse_args()
    if args.mode == "relabel":
        return relabel(args.results)
    return build(args) if args.mode == "provenance" else measure(args)


if __name__ == "__main__":
    raise SystemExit(main())
