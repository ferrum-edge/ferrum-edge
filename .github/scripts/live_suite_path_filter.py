#!/usr/bin/env python3
"""Path filter for expensive live CI suites."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SUITE_PATTERNS: dict[str, list[str]] = {
    "gateway-api": [
        r"^\.github/workflows/(ci|gateway-api-conformance)\.yml$",
        r"^\.github/scripts/live_suite_path_filter\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^scripts/gateway_api_data_plane_conformance\.sh$",
        r"^Cargo\.(toml|lock)$",
        r"^build\.rs$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^Dockerfile(\..*)?$",
        r"^\.dockerignore$",
        r"^charts/ferrum-mesh/",
        r"^proto/",
        r"^src/config/",
        r"^src/config_sources/(mod\.rs|k8s/)",
        r"^src/k8s_controller/",
        r"^src/modes/(control_plane|data_plane)\.rs$",
        r"^src/modes/mesh/",
        r"^src/grpc/",
        r"^src/router_cache\.rs$",
        r"^src/load_balancer\.rs$",
        r"^src/plugins/",
        r"^src/proxy/",
        r"^src/tls/",
    ],
    "mesh-federation": [
        r"^\.github/workflows/(ci|multicluster-federation-live)\.yml$",
        r"^\.github/scripts/live_suite_path_filter\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^tests/k8s/multicluster-federation/",
        r"^tests/k8s/lib/(live_assertions|spire)\.sh$",
        r"^Cargo\.(toml|lock)$",
        r"^build\.rs$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^Dockerfile(\..*)?$",
        r"^\.dockerignore$",
        r"^proto/",
        r"^ferrum\.conf$",
        r"^src/config/",
        r"^src/modes/mesh/",
        r"^src/grpc/",
        r"^src/identity/",
        r"^src/tls/",
        r"^src/secrets/",
        r"^src/service_discovery/",
        r"^src/plugins/mesh/",
        r"^src/capture/",
        r"^src/proxy/",
        r"^docs/(mesh|mesh_multicluster_federation_runbook|spire_deployment|configuration)\.md$",
    ],
    # Single-cluster Sidecar mesh live e2e (STRICT mTLS / authz / RequestAuth
    # JWT / DR connectTimeout) + the GA-contract live-assertion validator.
    # Deliberately mirrors mesh-federation minus its multicluster-only
    # surfaces (no src/grpc: the fixture uses the file config source, not the
    # CP/DP gRPC path), plus the JWT plugin the fixture's RequestAuth probes
    # exercise and the conformance contract/validator files its workflow's
    # validator step consumes.
    "mesh-e2e-sidecar": [
        r"^\.github/workflows/(ci|mesh-e2e-sidecar-live)\.yml$",
        r"^\.github/scripts/live_suite_path_filter\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^tests/k8s/mesh_e2e_sidecar/",
        r"^tests/k8s/lib/(live_assertions|spire)\.sh$",
        # mod.rs is what wires `mod live_contract;` into the conformance test
        # binary — unwiring it would silently skip the GA artifact gate.
        r"^tests/conformance/(ga_contract\.yaml|contract\.rs|live_contract\.rs|mod\.rs)$",
        r"^Cargo\.(toml|lock)$",
        r"^build\.rs$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^Dockerfile(\..*)?$",
        r"^\.dockerignore$",
        r"^proto/",
        r"^ferrum\.conf$",
        r"^src/config/",
        r"^src/modes/mesh/",
        r"^src/identity/",
        r"^src/tls/",
        r"^src/secrets/",
        r"^src/service_discovery/",
        r"^src/plugins/mesh/",
        r"^src/plugins/jwks_auth\.rs$",
        # The shared JWT-validation core jwks_auth delegates to — the suite's
        # RequestAuthentication assertions gate real signature/issuer/exp
        # validation, so regressions in these helpers must re-run it. Kept to
        # the JWKS/JWT-specific modules (src/plugins/utils/ is otherwise a
        # broad grab-bag of unrelated plugin helpers).
        r"^src/plugins/utils/(jwt_verifier|jwks_store|jwks_cache)\.rs$",
        r"^src/capture/",
        r"^src/proxy/",
        r"^docs/(mesh|spire_deployment|configuration)\.md$",
    ],
}


COMPILED = {
    suite: [re.compile(pattern) for pattern in patterns]
    for suite, patterns in SUITE_PATTERNS.items()
}


def read_changed_files(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def matched_files(suite: str, changed_files: list[str]) -> list[str]:
    patterns = COMPILED[suite]
    return [path for path in changed_files if any(pattern.search(path) for pattern in patterns)]


def write_summary(suite: str, relevant: bool, changed: list[str], matched: list[str]) -> None:
    title = suite.replace("-", " ").title()
    print(f"## {title} Live Suite Path Filter")
    print()
    print(f"Relevant: **{str(relevant).lower()}**")
    print()
    print("### Matched Files")
    print()
    if matched:
        for path in matched:
            print(f"- `{path}`")
    else:
        print("(none)")
    print()
    print("### Changed Files")
    print()
    if changed:
        for path in changed:
            print(f"- `{path}`")
    else:
        print("(none)")


def self_test() -> int:
    cases = [
        ("gateway-api", ["src/tls/frontend.rs"], True),
        ("gateway-api", [".github/scripts/live_suite_path_filter.py"], True),
        ("gateway-api", ["src/config/model.rs"], True),
        ("gateway-api", ["Dockerfile.release"], True),
        ("gateway-api", ["docs/mesh.md"], False),
        ("mesh-federation", ["tests/k8s/lib/spire.sh"], True),
        ("mesh-federation", [".github/scripts/live_suite_path_filter.py"], True),
        ("mesh-federation", ["src/service_discovery/kubernetes.rs"], True),
        ("mesh-federation", ["charts/ferrum-mesh/values.yaml"], False),
        ("mesh-federation", ["docs/spire_deployment.md"], True),
        ("mesh-e2e-sidecar", ["tests/k8s/mesh_e2e_sidecar/run.sh"], True),
        ("mesh-e2e-sidecar", ["src/plugins/jwks_auth.rs"], True),
        ("mesh-e2e-sidecar", ["src/plugins/utils/jwt_verifier.rs"], True),
        ("mesh-e2e-sidecar", ["src/plugins/utils/jwks_store.rs"], True),
        ("mesh-e2e-sidecar", ["tests/conformance/ga_contract.yaml"], True),
        ("mesh-e2e-sidecar", ["tests/conformance/mod.rs"], True),
        ("mesh-e2e-sidecar", ["tests/k8s/multicluster-federation/run.sh"], False),
        ("mesh-e2e-sidecar", ["src/grpc/mod.rs"], False),
        ("mesh-e2e-sidecar", ["src/plugins/utils/ai_providers.rs"], False),
        ("mesh-e2e-sidecar", ["charts/ferrum-mesh/values.yaml"], False),
    ]
    failures: list[str] = []
    for suite, changed, expected in cases:
        relevant = bool(matched_files(suite, changed))
        if relevant != expected:
            failures.append(
                f"{suite} {changed!r}: expected relevant={expected}, got {relevant}"
            )
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=sorted(SUITE_PATTERNS))
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--force-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.suite or not args.changed_files:
        parser.error("--suite and --changed-files are required unless --self-test is used")

    changed = read_changed_files(args.changed_files)
    matched = matched_files(args.suite, changed)
    relevant = args.force_run or bool(matched)
    print(f"relevant={str(relevant).lower()}")
    print(f"matched_count={len(matched)}")
    write_summary(args.suite, relevant, changed, matched)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
