#!/usr/bin/env python3
"""Check #5912's security floors in committed Cargo lockfiles (hosted CI only)."""

from pathlib import Path
import json
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
FLOORS = {
    "opentelemetry_sdk": (0, 32, 1),
    "aws-smithy-json": (0, 62, 7),
    "xxhash-rust": (0, 8, 16),
}
GCP_CHAIN = {
    "google-cloud-secretmanager-v1": "1.10.0",
    "google-cloud-auth": "1.11.0",
    "google-cloud-gax-internal": "0.7.14",
    "google-cloud-gax": "1.11.0",
    "google-cloud-wkt": "1.5.0",
    "opentelemetry": "0.32.0",
    "opentelemetry-semantic-conventions": "0.32.0",
    "tracing-opentelemetry": "0.33.0",
}
AWS_CHAIN = {
    "aws-smithy-json": "0.62.7",
    "aws-smithy-runtime-api": "1.12.3",
    "aws-smithy-types": "1.4.9",
    "aws-smithy-schema": "0.1.0",
    "aws-smithy-async": "1.2.14",
}
VENDORS = {"hyper": "1.10.0", "reqwest": "0.13.4"}


def verify() -> None:
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "Cargo.lock", "**/Cargo.lock"], cwd=ROOT
    ).decode().split("\0")
    failures = []
    for name in sorted(set(names) - {""}):
        packages = tomllib.loads((ROOT / name).read_text())["package"]
        by_name = {}
        for package in packages:
            by_name.setdefault(package["name"], []).append(package)
            floor = FLOORS.get(package["name"])
            if floor is not None:
                version = package["version"]
                parts = version.split(".")
                if len(parts) != 3 or not all(part.isdecimal() for part in parts):
                    failures.append(f"{name}: unrecognized security version {version!r}")
                elif tuple(map(int, parts)) < floor:
                    failures.append(f"{name}: vulnerable {package['name']} {version}")
        if "ferrum-edge" in by_name:
            for crate, expected in VENDORS.items():
                copies = by_name.get(crate, [])
                if (
                    len(copies) != 1
                    or copies[0]["version"] != expected
                    or "source" in copies[0]
                    or "checksum" in copies[0]
                ):
                    failures.append(f"{name}: {crate} must use only the {expected} path patch")
        if name == "Cargo.lock":
            for crate, expected in (GCP_CHAIN | AWS_CHAIN).items():
                copies = by_name.get(crate, [])
                if len(copies) != 1 or copies[0]["version"] != expected:
                    failures.append(f"{name}: expected one {crate} {expected}")
            for crate in FLOORS:
                if len(by_name.get(crate, [])) != 1:
                    failures.append(f"{name}: expected one fixed {crate}")
        print(f"Inspected {name}: {len(packages)} packages")
    if "Cargo.lock" not in names or "tests/performance/mesh/Cargo.lock" not in names:
        failures.append("root and mesh lockfiles must both be committed")
    # The lockfile's source-less entry alone cannot identify WHICH path crate
    # Cargo used. Check metadata from each actual production-dependent graph.
    for graph in ("root", "mesh", "fuzz"):
        metadata = ROOT / f"security-lockfiles/evidence/{graph}-metadata.json"
        if not metadata.is_file():
            failures.append(f"missing hosted {graph} metadata")
            continue
        packages = json.loads(metadata.read_text())["packages"]
        for crate, version in VENDORS.items():
            copies = [p for p in packages if p["name"] == crate]
            expected = ROOT / f"vendor/{crate}-{version}-ferrum-patched/Cargo.toml"
            if (
                len(copies) != 1
                or copies[0]["version"] != version
                or copies[0]["source"] is not None
                or Path(copies[0]["manifest_path"]).resolve() != expected.resolve()
            ):
                failures.append(f"{graph} metadata: {crate} must resolve to {expected}")
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    verify()
