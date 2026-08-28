#!/usr/bin/env python3
"""B01: missing-protoc diagnostic without overwriting the main debug binary."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("FERRUM_EDGE_ROOT", "/workspace")).resolve()
EV = ROOT / "artifacts/agent-01/evidence"
BIN = Path(os.environ.get("FERRUM_EDGE_BIN", str(ROOT / "target/debug/ferrum-edge")))
RESULTS = EV / "matrix-results.json"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> int:
    EV.mkdir(parents=True, exist_ok=True)
    before = BIN.exists() and os.access(BIN, os.X_OK)
    before_stat = BIN.stat() if before else None
    work = Path(tempfile.mkdtemp(prefix="agent01-noprotoc-", dir="/tmp"))
    hide = work / "hide-bin"
    hide.mkdir()
    target = work / "target"
    # Rebuild PATH without any `protoc` executable, keeping cargo/rustc/cc.
    keep: list[str] = []
    for part in os.environ.get("PATH", "").split(":"):
        if not part:
            continue
        protoc = Path(part) / "protoc"
        if protoc.exists():
            for name in os.listdir(part):
                if name == "protoc":
                    continue
                src = Path(part) / name
                dest = hide / name
                if dest.exists():
                    continue
                try:
                    os.symlink(src, dest)
                except OSError:
                    pass
            if str(hide) not in keep:
                keep.append(str(hide))
        else:
            keep.append(part)
    env = os.environ.copy()
    env["PATH"] = ":".join(keep)
    env.pop("PROTOC", None)
    env["CARGO_TARGET_DIR"] = str(target)
    which = subprocess.run(["which", "protoc"], env=env, text=True, capture_output=True)
    if which.returncode == 0:
        ev = EV / "missing-protoc.err.txt"
        ev.write_text(f"failed to hide protoc: still on PATH at {which.stdout.strip()}\n")
        print("[FAILED] B01 could not hide protoc")
        return 1
    env["CXX"] = "g++"
    env["CC"] = "gcc"
    env["RUSTFLAGS"] = "-C debuginfo=0"
    env["CARGO_BUILD_JOBS"] = "1"
    for key in list(env):
        if key.startswith("FERRUM_"):
            del env[key]
    proto = ROOT / "proto/ferrum.proto"
    orig_mtime = proto.stat().st_mtime
    try:
        proto.touch()
        proc = subprocess.run(
            [
                "cargo",
                "--config",
                'build.rustc-wrapper=""',
                "build",
                "--bin",
                "ferrum-edge",
                "-j",
                "1",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired as exc:
        proc_stdout = exc.stdout or ""
        proc_stderr = exc.stderr or ""
        combined = f"TIMEOUT\n{proc_stdout}\n{proc_stderr}"
        code = 124
    else:
        combined = f"exit={proc.returncode}\n---stdout---\n{proc.stdout}\n---stderr---\n{proc.stderr}"
        code = proc.returncode
    finally:
        os.utime(proto, (orig_mtime, orig_mtime))

    after = BIN.exists() and os.access(BIN, os.X_OK)
    after_stat = BIN.stat() if after else None
    preserved = before and after and before_stat is not None and after_stat is not None and (
        before_stat.st_mtime == after_stat.st_mtime and before_stat.st_size == after_stat.st_size
    )
    actionable = (
        "protoc" in combined.lower()
        and (
            "protobuf-compiler" in combined.lower()
            or "PROTOC" in combined
            or "could not find" in combined.lower()
            or "not found" in combined.lower()
            or "Unable to find" in combined
        )
    )
    ev = EV / "missing-protoc.err.txt"
    ev.write_text(
        f"hidden_protoc=1\nseparate_target={target}\nexit={code}\n"
        f"main_binary_preserved={preserved}\nactionable={actionable}\n"
        f"{combined[-12000:]}\n"
    )
    result = "passed" if (code != 0 and actionable and preserved) else "failed"
    row = {
        "id": "B01",
        "priority": "P0",
        "capability": "missing-protoc build diagnostic",
        "mode": "build",
        "method": "hide protoc, touch proto, cargo build --bin ferrum-edge in CARGO_TARGET_DIR",
        "expected": "actionable protoc install diagnostic; existing debug binary preserved",
        "result": result,
        "evidence": "artifacts/agent-01/evidence/missing-protoc.err.txt",
        "issue": "",
        "notes": f"exit={code} actionable={actionable} preserved={preserved}",
    }
    if RESULTS.exists():
        payload = json.loads(RESULTS.read_text())
        payload["rows"] = [r for r in payload.get("rows", []) if r.get("id") != "B01"]
        payload["rows"].append(row)
        payload["generated_at"] = utcnow()
        RESULTS.write_text(json.dumps(payload, indent=2) + "\n")
    else:
        RESULTS.write_text(json.dumps({"generated_at": utcnow(), "rows": [row]}, indent=2) + "\n")
    print(f"[{result.upper()}] B01 preserved={preserved} actionable={actionable} exit={code}")
    return 0 if result == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
