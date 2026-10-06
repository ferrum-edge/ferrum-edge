#!/usr/bin/env python3
"""Check security floors and vendored path patches in committed Cargo lockfiles.

Hosted CI only. Every committed lockfile must keep each SECURITY_FLOORS crate at
or above its fixed version. Every lockfile that builds `ferrum-edge` must also
resolve each PATH_PATCHED crate to exactly one copy: the `[patch.crates-io]`
path crate under `vendor/`, which has no `source` or `checksum`. A second,
registry copy (for example a dependency that moves to a semver line the patch
does not cover) would ship that crate without Ferrum's patches.
"""

from pathlib import Path
import re
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
SECURITY_FLOORS = {
    "opentelemetry_sdk": (0, 32, 1),
    "aws-smithy-json": (0, 62, 7),
    "xxhash-rust": (0, 8, 16),
}
PATH_PATCHED = ("hyper", "reqwest", "h2", "hyper-util")


def vendored_version(crate: str) -> str:
    """Return the version of the single `vendor/<crate>-<version>-ferrum-patched` copy."""
    pattern = re.compile(rf"{re.escape(crate)}-(\d+\.\d+\.\d+)-ferrum-patched")
    matches = [path for path in (ROOT / "vendor").iterdir() if pattern.fullmatch(path.name)]
    if len(matches) != 1:
        raise SystemExit(f"expected one vendored {crate} copy, found {len(matches)}")
    manifest = tomllib.loads((matches[0] / "Cargo.toml").read_text())
    version = manifest["package"]["version"]
    if pattern.fullmatch(matches[0].name).group(1) != version:
        raise SystemExit(f"{matches[0].name}: Cargo.toml declares {crate} {version}")
    return version


def verify() -> None:
    patched = {crate: vendored_version(crate) for crate in PATH_PATCHED}
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "Cargo.lock", "**/Cargo.lock"], cwd=ROOT
    ).decode().split("\0")
    failures = []
    for name in sorted(set(names) - {""}):
        packages = tomllib.loads((ROOT / name).read_text())["package"]
        by_name = {}
        for package in packages:
            by_name.setdefault(package["name"], []).append(package)
            floor = SECURITY_FLOORS.get(package["name"])
            if floor is not None:
                version = package["version"]
                parts = version.split(".")
                if len(parts) != 3 or not all(part.isdecimal() for part in parts):
                    failures.append(f"{name}: unrecognized security version {version!r}")
                elif tuple(map(int, parts)) < floor:
                    failures.append(f"{name}: vulnerable {package['name']} {version}")
        if "ferrum-edge" in by_name:
            for crate, expected in patched.items():
                copies = by_name.get(crate, [])
                if (
                    len(copies) != 1
                    or copies[0]["version"] != expected
                    or "source" in copies[0]
                    or "checksum" in copies[0]
                ):
                    failures.append(
                        f"{name}: {crate} must resolve only to the vendored {expected} path patch"
                    )
        print(f"Inspected {name}: {len(packages)} packages")
    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    verify()
