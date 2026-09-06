#!/usr/bin/env python3
"""Preserve RR benchmark binaries and provenance; never execute a process."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("record-build", "record-round"))
    args = parser.parse_args()
    root = Path(os.environ["RR_COMPARISON_ROOT"])
    output = Path(os.environ["RR_COMPARISON_OUTPUT"])
    work = Path(os.environ["RR_COMPARISON_WORK"])
    role = os.environ["RR_COMPARISON_ROLE"]
    if role not in ("baseline", "candidate"):
        raise ValueError("invalid comparison role")
    provenance_path = output / "provenance.json"
    if provenance_path.exists():
        provenance = json.loads(provenance_path.read_text())
    else:
        provenance = {
            "baseline_sha": os.environ["RR_BASE_SHA"],
            "candidate_sha": os.environ["RR_CANDIDATE_SHA"],
            "harness_sha256": digest(root / "tests/performance/mesh/benches/rr_selection.rs"),
            "binaries": {}, "order": [],
        }
    if args.mode == "record-build":
        artifacts = []
        for line in (output / f"{role}-compile.jsonl").read_text().splitlines():
            record = json.loads(line)
            if record.get("reason") == "compiler-artifact" and record.get("target", {}).get("name") == "rr_selection" and record.get("executable"):
                artifacts.append(Path(record["executable"]))
        if len(artifacts) != 1:
            raise ValueError(f"expected exactly one {role} benchmark executable")
        binary = work / role
        shutil.copy2(artifacts[0], binary)
        provenance["binaries"][role] = {
            "binary_sha256": digest(binary),
            "compile_seconds": float((output / f"{role}-compile.time").read_text()),
        }
    else:
        round_number = int(os.environ["RR_COMPARISON_ROUND"])
        if round_number not in (1, 2, 3):
            raise ValueError("invalid comparison round")
        provenance["order"].append({"role": role, "round": round_number})
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
