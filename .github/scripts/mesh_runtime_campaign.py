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
    subprocess.run(["bash", "tests/performance/mesh_runtime/run_mesh_runtime_bench.sh", "--build-only",
          "--output-dir", str(results / "images")], check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    provenance = {"candidate_sha": revision, "baseline_sha": baseline or None,
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
        # This worktree and its build output belong solely to this one run.
        source = results.parent / "mesh-baseline-source"
        subprocess.run(["git", "worktree", "add", "--detach", str(source), baseline], check=True)
        try:
            with (results / "images" / "baseline-build.log").open("w") as log:
                subprocess.run(["docker", "build", "--build-arg", f"CARGO_PROFILE={profile}", "--build-arg", f"FEATURES={features}",
                      "-t", "ferrum-edge:baseline", "-f", str(source / "Dockerfile"), str(source)],
                     check=True, stdout=log, stderr=subprocess.STDOUT)
            provenance["baseline_image_id"] = subprocess.check_output(["docker", "image", "inspect", "ferrum-edge:baseline", "--format", "{{.Id}}"], text=True).strip()
        finally:
            subprocess.run(["git", "worktree", "remove", str(source)], check=True)
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
    if not arms or not sizes or duration <= 0 or concurrency <= 0 or iterations not in (1, 3):
        raise ValueError("empty or invalid campaign")
    sequence = plan(arms, sizes, iterations, bool(provenance["baseline_sha"]))
    (results / "campaign.json").write_text(json.dumps({"cells": sequence, "duration": duration,
        "concurrency": concurrency, "order": "balanced round blocks; paired AB/BA Ferrum images"}, indent=2) + "\n")
    failed = False
    for index, cell in enumerate(sequence, 1):
        arm, payload, repetition = cell["arm"], cell["payload"], cell["repetition"]
        measured_arm = "ferrum" if arm == "ferrumbaseline" else arm
        directory = results / arm / f"run_{repetition}" / f"payload_{payload}"
        directory.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, FERRUM_IMAGE="ferrum-edge:baseline" if arm == "ferrumbaseline" else "ferrum-edge:bench")
        print(f"cell {index}/{len(sequence)} {cell}", flush=True)
        with (directory / "run.log").open("w") as log:
            status = subprocess.run(["bash", "tests/performance/mesh_runtime/run_mesh_runtime_bench.sh", measured_arm,
                "--payload-sizes", str(payload), "--duration", str(duration), "--concurrency", str(concurrency),
                "--output-dir", str(directory), "--skip-build"], env=env, stdout=log, stderr=subprocess.STDOUT).returncode
        failed |= bool(status)
        # Distinct baseline identity in every machine-readable record and path.
        if arm == "ferrumbaseline":
            for file in list(directory.glob("ferrum*.json")):
                document = json.loads(file.read_text())
                if document.get("mesh") == "ferrum":
                    document["mesh"] = arm
                if document.get("gateway") == "ferrum":
                    document["gateway"] = arm
                renamed = file.with_name(file.name.replace("ferrum", arm, 1))
                renamed.write_text(json.dumps(document, indent=2) + "\n")
                file.unlink()
        if status:
            print(f"arm failed ({status}): {directory / 'run.log'}", flush=True)
            print((directory / "run.log").read_text()[-5000:], flush=True)
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "measure"))
    parser.add_argument("--results", type=Path, default=Path("results"))
    args = parser.parse_args()
    return build(args) if args.mode == "build" else measure(args)


if __name__ == "__main__":
    raise SystemExit(main())
