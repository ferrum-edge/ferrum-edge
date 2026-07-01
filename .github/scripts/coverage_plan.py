#!/usr/bin/env python3
"""Select the CI coverage mode from an event name and changed-file list."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


PLUGIN_PATTERNS = [
    re.compile(r"^src/plugin_cache\.rs$"),
    re.compile(r"^tests/functional/functional_redis_rate_limiting_test\.rs$"),
    re.compile(r"^src/plugins/"),
    re.compile(r"^tests/unit/plugins/"),
]

FULL_PATTERNS = [
    re.compile(r"^\.cargo/"),
    re.compile(r"^\.github/workflows/coverage\.yml$"),
    re.compile(r"^\.github/scripts/coverage_plan\.py$"),
    re.compile(r"^scripts/(check_coverage_thresholds|coverage)\.(py|sh)$"),
    re.compile(r"^src/"),
    re.compile(r"^Cargo\.(toml|lock)$"),
    re.compile(r"^build\.rs$"),
    re.compile(r"^proto/"),
    re.compile(r"^ebpf/"),
    re.compile(r"^rust-toolchain\.toml$"),
]


def matches_any(path: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(path) for pattern in patterns)


def select_mode(event_name: str, changed_files: list[str]) -> tuple[str, str]:
    if event_name != "pull_request":
        return "full", f"full coverage is required for {event_name}"

    full_matches = [path for path in changed_files if matches_any(path, FULL_PATTERNS)]
    non_plugin_full_matches = [
        path for path in full_matches if not matches_any(path, PLUGIN_PATTERNS)
    ]
    if non_plugin_full_matches:
        return "full", "core coverage-relevant files changed"

    plugin_matches = [path for path in changed_files if matches_any(path, PLUGIN_PATTERNS)]
    if plugin_matches:
        return "plugin", "plugin coverage-relevant files changed"

    if full_matches:
        return "full", "core coverage-relevant files changed"

    return "skip", "no coverage-relevant files changed"


def read_changed_files(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def self_test() -> int:
    cases = [
        ("pull_request", ["src/proxy/http.rs"], "full"),
        ("pull_request", ["src/modes/mesh/config.rs"], "full"),
        ("pull_request", ["src/grpc/cp_server.rs"], "full"),
        ("pull_request", ["proto/ferrum.proto"], "full"),
        ("pull_request", ["ebpf/src/main.rs"], "full"),
        ("pull_request", ["src/plugins/cors.rs"], "plugin"),
        ("pull_request", ["src/plugins/cors.rs", "src/proxy/http.rs"], "full"),
        ("pull_request", [".github/scripts/coverage_plan.py"], "full"),
        ("pull_request", ["docs/configuration.md"], "skip"),
        ("push", [], "full"),
        ("workflow_dispatch", [], "full"),
        ("schedule", [], "full"),
    ]
    failures: list[str] = []
    for event_name, changed, expected in cases:
        mode, _ = select_mode(event_name, changed)
        if mode != expected:
            failures.append(
                f"{event_name} {changed!r}: expected {expected}, selected {mode}"
            )
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name")
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.event_name:
        parser.error("--event-name is required unless --self-test is used")

    changed_files = read_changed_files(args.changed_files)
    mode, reason = select_mode(args.event_name, changed_files)
    print(f"mode={mode}")
    print(f"reason={reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
