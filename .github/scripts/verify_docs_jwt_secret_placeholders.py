#!/usr/bin/env python3
"""Reject runnable docs examples with too-short JWT secrets."""

from __future__ import annotations

import re
import sys
from pathlib import Path


MIN_SECRET_LEN = 32
JWT_SECRET_NAMES = ("FERRUM_ADMIN_JWT_SECRET", "FERRUM_CP_DP_GRPC_JWT_SECRET")
SCAN_ROOTS = (Path("README.md"), Path("docs"), Path("ferrum.conf"), Path("docker-compose.yml"))

ASSIGNMENT_RE = re.compile(
    r"(?P<name>FERRUM_(?:ADMIN_JWT_SECRET|CP_DP_GRPC_JWT_SECRET))"
    r"\s*(?::|=)\s*"
    r"(?P<value>\"[^\"]+\"|'[^']+'|[^\s#]+)"
)
SIGNING_NOTE_RE = re.compile(
    r"Sign with (?P<name>FERRUM_ADMIN_JWT_SECRET):\s*(?P<value>\"[^\"]+\"|'[^']+')"
)


def iter_files() -> list[Path]:
    files: list[Path] = []
    for root in SCAN_ROOTS:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(path for path in root.rglob("*.md") if path.is_file())
    return sorted(files)


def literal_value(raw: str) -> str | None:
    value = raw.strip().strip(",")
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        value = value[1:-1]

    if not value:
        return None
    if value.startswith(("$", "${", "<")) or value.endswith(">"):
        return None
    if value.startswith("your-") and "32" in value:
        return None
    if "?" in value or "/" in value:
        return None
    return value


def main() -> int:
    violations: list[str] = []
    patterns = (ASSIGNMENT_RE, SIGNING_NOTE_RE)

    for path in iter_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not any(name in line for name in JWT_SECRET_NAMES):
                continue
            for pattern in patterns:
                for match in pattern.finditer(line):
                    value = literal_value(match.group("value"))
                    if value is not None and len(value) < MIN_SECRET_LEN:
                        violations.append(
                            f"{path}:{lineno}: {match.group('name')} example secret "
                            f"is {len(value)} chars; use a {MIN_SECRET_LEN}+ char placeholder"
                        )

    if not violations:
        print("JWT secret placeholders in runnable docs examples are 32+ chars.")
        return 0

    for violation in violations:
        print(f"::error::{violation}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
