#!/usr/bin/env python3
"""Validate the manual release input before giving any job tag-write access."""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def validate(version: str, package_version: str, ref: str, sha: str, head: str) -> None:
    if ref != "refs/heads/main":
        raise ValueError("Start Production Release must run from main")
    # The current publisher updates stable major/minor aliases and creates a
    # non-prerelease GitHub release. Do not route prereleases through that path.
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise ValueError("version must be a stable vMAJOR.MINOR.PATCH tag")
    if version != f"v{package_version}":
        raise ValueError("version must match [package].version in Cargo.toml")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or head != sha:
        raise ValueError("checkout must match the immutable workflow commit SHA")


def main() -> int:
    try:
        package = tomllib.loads(Path("Cargo.toml").read_text())["package"]
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        validate(
            os.environ.get("RELEASE_VERSION", ""), package["version"],
            os.environ.get("GITHUB_REF", ""), os.environ.get("GITHUB_SHA", ""), head,
        )
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(f"Release version and checkout validated at {head}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
