#!/usr/bin/env python3
"""Path filter for expensive live CI suites."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


MESH_FEDERATION_DOCUMENTATION_PATHS = frozenset(
    {
        "docs/configuration.md",
        "docs/mesh.md",
        "docs/mesh_multicluster_federation_runbook.md",
        "docs/spire_deployment.md",
    }
)

MESH_E2E_SIDECAR_DOCUMENTATION_PATHS = frozenset(
    {
        "docs/configuration.md",
        "docs/mesh.md",
        "docs/spire_deployment.md",
    }
)

# verify_required_ci.py requires the PR planner's protected documentation set
# to cover this union, so new live-suite documentation triggers cannot silently
# receive lightweight CI.
LIVE_SUITE_DOCUMENTATION_PATHS = (
    MESH_FEDERATION_DOCUMENTATION_PATHS | MESH_E2E_SIDECAR_DOCUMENTATION_PATHS
)


def exact_path_patterns(paths: frozenset[str]) -> list[str]:
    return [rf"^{re.escape(path)}$" for path in sorted(paths)]


SUITE_PATTERNS: dict[str, list[str]] = {
    "gateway-api": [
        r"^\.github/workflows/(ci|gateway-api-conformance)\.yml$",
        r"^\.github/scripts/live_suite_path_filter\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^\.github/actions/setup-kubernetes-tools/",
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
        r"^\.github/actions/setup-kubernetes-tools/",
        r"^tests/k8s/multicluster-federation/",
        r"^tests/k8s/lib/(live_assertions|spire)\.sh$",
        # The GA-contract half of this suite is the enforced, non-deferred
        # `multicluster-federation` rows of ga_contract.yaml, pinned by the
        # hosted conformance suite (live_contract.rs,
        # mesh_multicluster_federation.rs, wired through mod.rs /
        # conformance_tests.rs). Editing any of them changes what the live
        # fixture is required to prove, so the live datapath must re-run.
        r"^tests/conformance/(ga_contract\.yaml|contract\.rs|live_contract\.rs|mesh_multicluster_federation\.rs|mod\.rs)$",
        r"^tests/conformance_tests\.rs$",
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
        *exact_path_patterns(MESH_FEDERATION_DOCUMENTATION_PATHS),
    ],
    # Single-cluster Sidecar mesh live e2e (STRICT mTLS / authz / RequestAuth
    # JWT / DR connectTimeout / CP-delivered native MeshSubscribe config) +
    # the GA-contract live-assertion validator. Deliberately mirrors
    # mesh-federation minus its multicluster-only surfaces, plus the JWT
    # plugin the fixture's RequestAuth probes exercise, the conformance
    # contract/validator files its workflow's validator step consumes, and
    # the CP + native-subscribe surfaces backing the required
    # sidecar.config.native_subscribe_delivered assertion (the DP-side native
    # client, src/modes/mesh/config_consumer/native_client.rs, is already
    # covered by src/modes/mesh/).
    "mesh-e2e-sidecar": [
        r"^\.github/workflows/(ci|mesh-e2e-sidecar-live)\.yml$",
        r"^\.github/scripts/live_suite_path_filter\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^\.github/actions/setup-kubernetes-tools/",
        r"^tests/k8s/mesh_e2e_sidecar/",
        r"^tests/k8s/lib/(live_assertions|spire)\.sh$",
        # mod.rs wires `mod live_contract;` into the conformance tree and
        # tests/conformance_tests.rs is the harness that declares
        # `mod conformance;` — unwiring either would let the GA artifact gate
        # vanish (the workflow's exact-path guard only runs when this filter
        # marks the PR relevant).
        r"^tests/conformance/(ga_contract\.yaml|contract\.rs|live_contract\.rs|mod\.rs)$",
        r"^tests/conformance_tests\.rs$",
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
        # CP runtime for the fixture's ferrum-cp Deployment (FERRUM_MODE=cp):
        # binds FERRUM_CP_GRPC_LISTEN_ADDR, wires MeshGrpcServer, starts the
        # K8s controller, and broadcasts reconciled mesh snapshots to
        # subscribers. Kept to the one mode file — dp mode (data_plane.rs) is
        # the gateway ConfigSync consumer, which the mesh DP never uses.
        r"^src/modes/control_plane\.rs$",
        # CP-side MeshSubscribe surface only: mesh_server.rs serves the
        # MeshConfigSync.MeshSubscribe stream (namespace-scoped snapshot
        # build + content_eq dedupe), mesh_registry.rs tracks the subscribed
        # nodes the reconcile broadcasts converge through, auth.rs is the
        # DP<->CP JWT verification the fixture's plaintext-h2c stream still
        # relies on, and cp_server.rs owns the shared CP scope/namespace
        # filtering helpers mesh_server.rs calls when serving native slices;
        # dp_client.rs owns shared DP gRPC JWT/TLS/version helpers imported by
        # the native MeshSubscribe client. mod.rs (pure module wiring,
        # compile-gated on every PR) stays out.
        r"^src/grpc/(mesh_server|mesh_registry|auth|cp_server|dp_client)\.rs$",
        # The watch->reconcile->broadcast pipeline that is the ONLY source of
        # the mesh model the CP serves over MeshSubscribe (there is no DB or
        # admin write path for the mesh block).
        r"^src/k8s_controller/",
        # K8s mesh-model translation the CP leg depends on: core.rs turns the
        # cluster's real Services/Pods/EndpointSlices into MeshService and
        # Workload entries; k8s/mod.rs holds the shared accumulator and
        # translation entry points core.rs plugs into. istio.rs/
        # gateway_api.rs/mesh_config.rs stay out — the fixture disables those
        # watches (FERRUM_K8S_WATCH_ISTIO_CRDS/GATEWAY_API_CRDS/MESH_CONFIG
        # = false), so their translations cannot affect this suite — and so
        # does src/config_sources/mod.rs (pure module wiring).
        r"^src/config_sources/k8s/(mod|core)\.rs$",
        # Serves authenticated GET /mesh/config-drift — the
        # native_subscribe_delivered check requires the route, JWT extraction
        # and role parsing, plus the response builder, to attribute the applied
        # slice to source_protocol=native from the ferrum-cp URL.
        r"^src/admin/(mod|mesh_config_drift|jwt_auth|audit)\.rs$",
        r"^src/identity/",
        r"^src/tls/",
        r"^src/secrets/",
        r"^src/service_discovery/",
        r"^src/plugins/mesh/",
        r"^src/plugins/jwks_auth\.rs$",
        # The shared JWT-validation core jwks_auth delegates to — the suite's
        # RequestAuthentication assertions gate real bearer extraction +
        # signature/issuer/exp validation, so regressions in these helpers
        # must re-run it. Kept to the JWKS/JWT-specific modules
        # (src/plugins/utils/ is otherwise a broad grab-bag of unrelated
        # plugin helpers, and broad shared surfaces like src/plugins/mod.rs
        # stay out by design — they are gated on every PR by the in-process
        # unit/integration/functional mesh suites).
        r"^src/plugins/utils/(jwt_verifier|jwks_store|jwks_cache|token_extract)\.rs$",
        # Owns BackendConnectionGuard — the exact behavior the DR
        # maxConnections WebSocket live assertion validates (held session
        # occupies the slot, concurrent upgrade 503s, slot frees on close).
        r"^src/backend_conn_limit\.rs$",
        r"^src/capture/",
        r"^src/proxy/",
        *exact_path_patterns(MESH_E2E_SIDECAR_DOCUMENTATION_PATHS),
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
        ("gateway-api", [".github/actions/setup-kubernetes-tools/action.yml"], True),
        ("gateway-api", ["src/config/model.rs"], True),
        ("gateway-api", ["Dockerfile.release"], True),
        ("gateway-api", ["docs/mesh.md"], False),
        ("mesh-federation", ["tests/k8s/lib/spire.sh"], True),
        ("mesh-federation", [".github/scripts/live_suite_path_filter.py"], True),
        ("mesh-federation", [".github/actions/setup-kubernetes-tools/action.yml"], True),
        ("mesh-federation", ["src/service_discovery/kubernetes.rs"], True),
        ("mesh-federation", ["charts/ferrum-mesh/values.yaml"], False),
        ("mesh-federation", ["docs/spire_deployment.md"], True),
        ("mesh-e2e-sidecar", ["tests/k8s/mesh_e2e_sidecar/run.sh"], True),
        ("mesh-e2e-sidecar", [".github/actions/setup-kubernetes-tools/action.yml"], True),
        ("mesh-e2e-sidecar", ["src/plugins/jwks_auth.rs"], True),
        ("mesh-e2e-sidecar", ["src/plugins/utils/jwt_verifier.rs"], True),
        ("mesh-e2e-sidecar", ["src/plugins/utils/jwks_store.rs"], True),
        ("mesh-e2e-sidecar", ["src/plugins/utils/token_extract.rs"], True),
        ("mesh-e2e-sidecar", ["src/backend_conn_limit.rs"], True),
        ("mesh-e2e-sidecar", ["tests/conformance/ga_contract.yaml"], True),
        ("mesh-e2e-sidecar", ["tests/conformance/mod.rs"], True),
        ("mesh-e2e-sidecar", ["tests/conformance_tests.rs"], True),
        ("mesh-e2e-sidecar", ["src/modes/control_plane.rs"], True),
        ("mesh-e2e-sidecar", ["src/grpc/mesh_server.rs"], True),
        ("mesh-e2e-sidecar", ["src/grpc/mesh_registry.rs"], True),
        ("mesh-e2e-sidecar", ["src/grpc/auth.rs"], True),
        ("mesh-e2e-sidecar", ["src/grpc/cp_server.rs"], True),
        ("mesh-e2e-sidecar", ["src/grpc/dp_client.rs"], True),
        ("mesh-e2e-sidecar", ["src/k8s_controller/reconciler.rs"], True),
        ("mesh-e2e-sidecar", ["src/config_sources/k8s/core.rs"], True),
        ("mesh-e2e-sidecar", ["src/config_sources/k8s/mod.rs"], True),
        ("mesh-e2e-sidecar", ["src/config_sources/mod.rs"], False),
        ("mesh-e2e-sidecar", ["src/admin/mesh_config_drift.rs"], True),
        ("mesh-e2e-sidecar", ["src/admin/mod.rs"], True),
        ("mesh-e2e-sidecar", ["src/admin/jwt_auth.rs"], True),
        ("mesh-e2e-sidecar", ["src/admin/audit.rs"], True),
        ("mesh-e2e-sidecar", ["tests/k8s/multicluster-federation/run.sh"], False),
        ("mesh-e2e-sidecar", ["src/grpc/mod.rs"], False),
        ("mesh-e2e-sidecar", ["src/modes/data_plane.rs"], False),
        ("mesh-e2e-sidecar", ["src/config_sources/k8s/istio.rs"], False),
        ("mesh-e2e-sidecar", ["src/admin/backup.rs"], False),
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
