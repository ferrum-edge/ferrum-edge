#!/usr/bin/env python3
"""Verify that the CI aggregate waits on every required validation job."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_JOBS = {
    "fmt",
    "test-unit",
    "plugin-hardening-unit-regressions",
    "test-lib",
    "test-secrets",
    "test-service-integration",
    "test-pkcs11-softhsm",
    "build-integration-tests-archive",
    "test-integration",
    "test-integration-coverage",
    "test-conformance",
    "dependency-audit",
    "test-vendor-patches",
    "build-gateway-binary",
    "build-functional-tests-archive",
    "test-functional",
    "plugin-hardening-redis-regression",
    "gateway-api-conformance",
    "coverage-gate",
    "mesh-multicluster-federation",
    "mesh-e2e-sidecar",
    "mesh-e2e-sidecar-live",
    "helm-chart",
    "lint",
    "detect-ebpf-live-changes",
    "build-ebpf",
    "build-ebpf-userspace",
    "ebpf-live",
    "netns-capture-live",
    "performance-regression",
    "build-binaries",
}


def extract_test_needs(ci_yml: str) -> set[str]:
    match = re.search(r"(?ms)^  test:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", ci_yml)
    if not match:
        raise RuntimeError("could not find jobs.test in ci.yml")

    body = match.group("body")
    needs_match = re.search(r"(?m)^    needs:\n(?P<needs>(?:^      - [^\n]+\n)+)", body)
    if not needs_match:
        raise RuntimeError("could not find jobs.test.needs in ci.yml")

    return {
        line.strip().removeprefix("- ").strip()
        for line in needs_match.group("needs").splitlines()
        if line.strip().startswith("- ")
    }


def main() -> int:
    ci_path = Path(".github/workflows/ci.yml")
    ci_yml = ci_path.read_text(encoding="utf-8")
    needs = extract_test_needs(ci_yml)
    missing = sorted(REQUIRED_JOBS - needs)
    extra = sorted(needs - REQUIRED_JOBS)

    if not missing and not extra:
        print(f"Required CI aggregate covers {len(REQUIRED_JOBS)} jobs.")
        return 0

    for job in missing:
        print(f"::error::jobs.test.needs is missing required job `{job}`", file=sys.stderr)
    for job in extra:
        print(
            f"::error::jobs.test.needs includes `{job}` but verify_required_ci.py does not document it",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
