#!/usr/bin/env python3
"""Build two revisions and measure an identical RR harness on one hosted runner."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import tempfile
from pathlib import Path


def command(args: list[str], cwd: Path, **kwargs) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, **kwargs).strip()


def compile_bench(root: Path, role: str, output: Path, target: Path, work: Path) -> dict:
    started = time.monotonic()
    env = {**os.environ, "CARGO_TARGET_DIR": str(target)}
    with (output / f"{role}-compile.jsonl").open("w") as log:
        subprocess.run(["cargo", "bench", "--manifest-path", "tests/performance/mesh/Cargo.toml", "--bench", "rr_selection", "--no-run", "--locked", "--message-format=json"], cwd=root, env=env, stdout=log, check=True)
    artifacts = []
    for line in (output / f"{role}-compile.jsonl").read_text().splitlines():
        record = json.loads(line)
        if record.get("reason") == "compiler-artifact" and record.get("target", {}).get("name") == "rr_selection" and record.get("executable"):
            artifacts.append(Path(record["executable"]))
    if len(artifacts) != 1:
        raise ValueError(f"expected exactly one {role} benchmark executable")
    binary = work / f"rr-selection-{role}"
    shutil.copy2(artifacts[0], binary)
    return {"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "compile_seconds": time.monotonic() - started}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-sha", default="")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    output = args.output.resolve()
    if output.exists():
        raise ValueError("comparison output must be new; stale results cannot be reused")
    output.mkdir(parents=True)
    candidate = command(["git", "rev-parse", "HEAD"], root)
    if not args.baseline_sha and os.environ.get("GITHUB_EVENT_NAME") not in (None, "workflow_dispatch"):
        raise ValueError("this event must provide its baseline SHA")
    baseline = args.baseline_sha or command(["git", "rev-parse", "HEAD^"], root)
    if not re.fullmatch(r"[0-9a-f]{40}", baseline) or baseline == "0" * 40:
        raise ValueError("baseline must be an immutable nonzero commit SHA")
    command(["git", "cat-file", "-e", f"{baseline}^{{commit}}"], root)
    work = Path(tempfile.mkdtemp(prefix="rr-selection-", dir=os.environ.get("RUNNER_TEMP")))
    baseline_root = work / "baseline-source"
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", str(baseline_root), baseline], cwd=root, check=True)
    harness = Path("tests/performance/mesh/benches/rr_selection.rs")
    # The sole baseline overlay is the candidate measurement harness, so both
    # binaries use identical timing boundaries and output-directory handling.
    shutil.copy2(root / harness, baseline_root / harness)
    target = root / "tests/performance/mesh/target"
    binaries = {}
    for role, source in (("candidate", root), ("baseline", baseline_root)):
        binaries[role] = compile_bench(source, role, output, target, work)
    provenance = {"baseline_sha": baseline, "candidate_sha": candidate,
                  "harness_sha256": hashlib.sha256((root / harness).read_bytes()).hexdigest(),
                  "binaries": binaries, "order": []}
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    for round in range(1, 4):
        order = ("baseline", "candidate") if round % 2 else ("candidate", "baseline")
        for role in order:
            result_root = output / f"{role}-{round}"
            env = {**os.environ, "FERRUM_RR_CRITERION_ROOT": str(result_root)}
            with (output / f"{role}-{round}.log").open("w") as log:
                subprocess.run([binaries[role]["binary"], "--bench", "--noplot", "rr_selection/2_targets"], cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            provenance["order"].append({"role": role, "round": round})
            (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    return subprocess.call(["python3", ".github/scripts/verify_rr_selection_benchmark.py", "--criterion-root", str(output)], cwd=root)


if __name__ == "__main__":
    raise SystemExit(main())
