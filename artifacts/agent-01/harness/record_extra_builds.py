#!/usr/bin/env python3
"""Record B02 release-binary row into matrix-results.json."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get("FERRUM_EDGE_ROOT", "/workspace")).resolve()
EV = ROOT / "artifacts/agent-01/evidence"
RESULTS = EV / "matrix-results.json"
REL = ROOT / "target/release/ferrum-edge"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert(rows: list[dict], row: dict) -> list[dict]:
    rows = [r for r in rows if r.get("id") != row["id"]]
    rows.append(row)
    return rows


def main() -> int:
    payload = {"generated_at": utcnow(), "sha": "", "binary": "", "rows": []}
    if RESULTS.exists():
        payload = json.loads(RESULTS.read_text())
    if REL.exists() and os.access(REL, os.X_OK):
        size = REL.stat().st_size
        ev = EV / "release-smoke.txt"
        ev.write_text(f"release_binary={REL}\nbytes={size}\n")
        row = {
            "id": "B02",
            "priority": "P1",
            "capability": "release binary build",
            "mode": "build",
            "method": "cargo build --release --bin ferrum-edge -j 1",
            "expected": "target/release/ferrum-edge executable",
            "result": "passed",
            "evidence": "artifacts/agent-01/evidence/release-smoke.txt",
            "issue": "",
            "notes": f"bytes={size}",
        }
    else:
        ev = EV / "release-smoke.txt"
        ev.write_text("release binary missing\n")
        row = {
            "id": "B02",
            "priority": "P1",
            "capability": "release binary build",
            "mode": "build",
            "method": "cargo build --release --bin ferrum-edge -j 1",
            "expected": "target/release/ferrum-edge executable",
            "result": "blocked",
            "evidence": "artifacts/agent-01/evidence/release-smoke.txt",
            "issue": "",
            "notes": "not built yet",
        }
    payload["rows"] = upsert(payload.get("rows", []), row)
    payload["generated_at"] = utcnow()
    RESULTS.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"[{row['result'].upper()}] B02 {row['notes']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
