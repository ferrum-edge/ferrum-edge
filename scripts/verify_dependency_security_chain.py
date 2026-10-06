#!/usr/bin/env python3
"""Check security floors in every committed Cargo lockfile (hosted CI only)."""

from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
SECURITY_FLOORS = {
    "opentelemetry_sdk": (0, 32, 1),
    "aws-smithy-json": (0, 62, 7),
    "xxhash-rust": (0, 8, 16),
}


def verify() -> None:
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "Cargo.lock", "**/Cargo.lock"], cwd=ROOT
    ).decode().split("\0")
    failures = []
    for name in sorted(set(names) - {""}):
        packages = tomllib.loads((ROOT / name).read_text())["package"]
        for package in packages:
            floor = SECURITY_FLOORS.get(package["name"])
            if floor is not None:
                version = package["version"]
                parts = version.split(".")
                if len(parts) != 3 or not all(part.isdecimal() for part in parts):
                    failures.append(f"{name}: unrecognized security version {version!r}")
                elif tuple(map(int, parts)) < floor:
                    failures.append(f"{name}: vulnerable {package['name']} {version}")
        print(f"Inspected {name}: {len(packages)} packages")
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    verify()
