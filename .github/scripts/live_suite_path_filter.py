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
        "docs/cp_dp_mode.md",
        "docs/mesh.md",
        "docs/spire_deployment.md",
    }
)

AMBIENT_HOST_UDP_DOCUMENTATION_PATHS = frozenset(
    {
        "docs/ci_cd.md",
        "docs/configuration.md",
        "docs/mesh.md",
        "docs/node_agent.md",
        "docs/tcp_udp_proxy.md",
    }
)

CNI_LIFECYCLE_DOCUMENTATION_PATHS = frozenset(
    {
        "docs/node_agent.md",
        "docs/node_agent_security.md",
    }
)

# Istio Status CAS live has no documentation trigger set: its retired
# workflow-level `paths:` list named only the writer, metrics, fixture, and
# workflow/action surfaces. Keep that cost envelope.
ISTIO_STATUS_CAS_DOCUMENTATION_PATHS: frozenset[str] = frozenset()

# verify_required_ci.py requires the PR planner's protected documentation set
# to cover this union, so new live-suite documentation triggers cannot silently
# receive lightweight CI.
#
# The NodeWaypoint eBPF live suite is deliberately absent: its relevance is
# decided by the `node-waypoint-ebpf-live` suite of `ci_runtime_plan.py`, the
# trusted-base planner that already runs inside
# `node-waypoint-ebpf-live.yml`'s `production-dockerfile-plan` job. Adding a
# second classifier for the same live job would mean two gates that can each
# bypass the other. `verify_required_ci.py` folds that planner's documentation
# patterns into the same full-CI union.
LIVE_SUITE_DOCUMENTATION_PATHS = (
    MESH_FEDERATION_DOCUMENTATION_PATHS
    | MESH_E2E_SIDECAR_DOCUMENTATION_PATHS
    | AMBIENT_HOST_UDP_DOCUMENTATION_PATHS
    | CNI_LIFECYCLE_DOCUMENTATION_PATHS
    | ISTIO_STATUS_CAS_DOCUMENTATION_PATHS
)


def exact_path_patterns(paths: frozenset[str]) -> list[str]:
    return [rf"^{re.escape(path)}$" for path in sorted(paths)]


SUITE_PATTERNS: dict[str, list[str]] = {
    "gateway-api": [
        r"^\.github/workflows/(ci|gateway-api-conformance)\.yml$",
        r"^\.github/scripts/live_suite_path_filter\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^\.github/actions/setup-kubernetes-tools/",
        r"^scripts/gateway_api_conformance_lab_setup\.sh$",
        r"^scripts/gateway_api_data_plane_conformance\.sh$",
        r"^scripts/gateway_api_tcproute_conformance\.sh$",
        r"^scripts/gateway_api_tlsroute_conformance\.sh$",
        r"^scripts/gateway_api_gatewayclass_authority_conformance\.sh$",
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
        r"^\.github/workflows/(ci|multicluster-federation-live|multicluster-poller-partition-live)\.yml$",
        # `validate_live_assertions.py` is the emitted-artifact release gate in
        # the workflow's `gate` job, so editing it changes what a live run must
        # prove about the artifact it published.
        r"^\.github/scripts/(live_suite_path_filter|validate_live_assertions)\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^\.github/actions/setup-kubernetes-tools/",
        r"^tests/k8s/multicluster-federation/",
        r"^tests/k8s/multicluster-poller-partition/",
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
        # The poller-partition fixture sharing this suite filter runs a real
        # CP with Kubernetes discovery enabled. Changes to any leg of that
        # CP watch/translate pipeline must therefore re-run the live gate.
        r"^src/modes/control_plane\.rs$",
        r"^src/k8s_controller/",
        r"^src/config_sources/k8s/",
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
        r"^tests/k8s/lib/native_probe_classify\.py$",
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
        # CP/DP gRPC TLS watchers used by the native MeshSubscribe mTLS
        # rotation assertion (projected Secret generation swap).
        r"^src/modes/grpc_tls_reload\.rs$",
        r"^src/modes/tls_source_util\.rs$",
        # CP-side MeshSubscribe surface only: mesh_server.rs serves the
        # MeshConfigSync.MeshSubscribe stream (namespace-scoped snapshot
        # build + content_eq dedupe), mesh_registry.rs tracks the subscribed
        # nodes the reconcile broadcasts converge through, auth.rs is the
        # DP<->CP JWT verification the fixture's mTLS+JWT stream still
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
    # Ambient host-network UDP live-kernel gate (#3705): production
    # ProxyHostUdpBackend TPROXY capture, attribution, replies, and cleanup.
    "ambient-host-udp": [
        r"^\.github/workflows/(ci|ambient-host-udp-live|release)\.yml$",
        # The trusted release-trust surfaces decide whether the tag the chart
        # selects is owned, gated, signed, and attested at all.
        r"^\.github/scripts/(live_suite_path_filter|pr_ci_plan|verify_cross_build_policy|verify_release_image_attestations)\.py$",
        r"^\.github/scripts/stage_iproute2_runtime\.sh$",
        r"^\.github/actions/setup-rust-ci/",
        # The chart auto-selects a published runtime variant for the Ambient UDP
        # lifecycle, so the image the chart names is part of this gate's subject:
        # a Dockerfile or release-publication edit can make the selected tag stop
        # shipping the shell/iptables tools the production backend executes.
        r"^Dockerfile$",
        r"^tests/k8s/ambient_host_udp_live/",
        r"^tests/unit/gateway_core/(ambient_host_udp_live_contract_tests|mesh_host_udp_capture_plan_tests)\.rs$",
        r"^tests/integration/mesh_k8s_pod_discovery/host_udp_capture_tests\.rs$",
        r"^tests/functional/functional_mesh_mode_test\.rs$",
        r"^Cargo\.(toml|lock)$",
        r"^build\.rs$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^proto/",
        r"^charts/ferrum-mesh/",
        r"^src/capture/",
        r"^src/modes/mesh/",
        r"^src/proxy/(host_udp_capture|host_udp_capture_live_tests|mesh_udp_capture|netns_capture|netns_udp_capture|udp_batch|udp_placement_cleanup|udp_placement_migration|mod)\.rs$",
        # The production entry points for the Ambient UDP lifecycle: the
        # `ambient-udp-preflight` subcommand definition and dispatch, and the
        # node-agent that publishes the node identity every placement proof is
        # bound to. A defect in any of them bypasses the proof this gate
        # exercises live.
        r"^src/(cli|main|gateway_entry)\.rs$",
        r"^src/modes/node_agent\.rs$",
        r"^src/socket_opts\.rs$",
        r"^src/ebpf/veth\.rs$",
        *exact_path_patterns(AMBIENT_HOST_UDP_DOCUMENTATION_PATHS),
    ],
    # Istio status CAS competing-writer live proof. Kept to the retired
    # workflow-level `paths:` list plus the trusted classifier script and the
    # local composite actions the live job executes: the retired list named
    # `setup-rust-ci` but not the `setup-sccache` / `setup-fast-linker` actions
    # it runs, which decide how the live test binary is compiled and linked.
    "istio-status-cas": [
        r"^\.github/workflows/istio-status-cas-live\.yml$",
        r"^\.github/scripts/live_suite_path_filter\.py$",
        r"^\.github/actions/setup-kubernetes-tools/",
        r"^\.github/actions/setup-fast-linker/",
        r"^\.github/actions/setup-rust-ci/",
        r"^\.github/actions/setup-sccache/",
        r"^src/k8s_controller/istio_status\.rs$",
        r"^src/k8s_controller/metrics\.rs$",
        r"^tests/k8s_istio_status_cas_live\.rs$",
        r"^tests/fixtures/k8s/istio_authorizationpolicy_status_crd\.yaml$",
        *exact_path_patterns(ISTIO_STATUS_CAS_DOCUMENTATION_PATHS),
    ],
    # CNI install lifecycle live recovery. Chart matches stay exact-path, not
    # the whole Helm tree, so unrelated chart edits keep the previous cost. The
    # retired `paths:` list named neither `setup-rust-ci` nor the
    # `setup-sccache` / `setup-fast-linker` actions it runs, even though they
    # build the `ferrum-edge` and `ferrum-cni` binaries this suite installs.
    "cni-lifecycle": [
        r"^\.github/workflows/cni-lifecycle-live\.yml$",
        r"^\.github/scripts/live_suite_path_filter\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^\.github/actions/setup-kubernetes-tools/",
        r"^\.github/actions/setup-fast-linker/",
        r"^\.github/actions/setup-rust-ci/",
        r"^\.github/actions/setup-sccache/",
        r"^Cargo\.(toml|lock)$",
        r"^build\.rs$",
        r"^proto/",
        r"^src/bin/ferrum-cni\.rs$",
        r"^src/cni/",
        r"^charts/ferrum-mesh/templates/cni-uninstall-hook\.yaml$",
        r"^charts/ferrum-mesh/templates/cni-cleanup-rbac\.yaml$",
        r"^charts/ferrum-mesh/templates/node-agent-daemonset\.yaml$",
        r"^charts/ferrum-mesh/templates/node-agent-rbac\.yaml$",
        r"^charts/ferrum-mesh/values\.yaml$",
        r"^tests/k8s/cni_lifecycle_live/",
        r"^PRODUCTION_READINESS\.md$",
        *exact_path_patterns(CNI_LIFECYCLE_DOCUMENTATION_PATHS),
    ],
}


COMPILED = {
    suite: [re.compile(pattern) for pattern in patterns]
    for suite, patterns in SUITE_PATTERNS.items()
}


# Local composite actions each newly migrated live job executes, directly or
# through `setup-rust-ci` (whose own steps run `setup-sccache` and
# `setup-fast-linker`). These are direct execution dependencies of the live
# job, so an edit to one must re-run the suite; the retired workflow-level
# `paths:` lists covered them only partially.
# `local_action_dependency_self_test` proves every entry here stays classified
# by its suite, so the list cannot drift away from the patterns.
#
# This is a declared list rather than one scraped from the workflow on disk on
# purpose: the self-test runs from the TRUSTED BASE copy against the pull
# request's checkout, so deriving it from the candidate workflow would make the
# very pull request that adds a new `uses: ./.github/actions/...` step
# unmergeable until its own patterns were already on `main`.
SUITE_LOCAL_ACTION_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "istio-status-cas": (
        "setup-fast-linker",
        "setup-kubernetes-tools",
        "setup-rust-ci",
        "setup-sccache",
    ),
    "cni-lifecycle": (
        "package-ferrum-runtime-image",
        "setup-fast-linker",
        "setup-kubernetes-tools",
        "setup-rust-ci",
        "setup-sccache",
    ),
}


# Conservative repository-relative charset, deliberately identical to the PR CI
# planner's `CLASSIFIABLE_PATH_RE`. C0/C1 controls, DEL, newlines, tabs,
# backslashes, backticks, quotes, and other shell/Markdown metacharacters are
# rejected by omission, so a hostile Git pathname can neither slip past a
# live-suite pattern nor be echoed into a step summary.
CLASSIFIABLE_PATH_RE = re.compile(r"^[A-Za-z0-9._+@~ /-]{1,4096}$")


def is_classifiable_repo_path(path: str) -> bool:
    """Return whether one record is a normal repository-relative pathname.

    Surrounding whitespace, absolute paths, trailing slashes, empty / `.` /
    `..` components, and anything outside the conservative charset fail the
    check. Classification splits on `/` itself rather than going through
    `PurePosixPath.parts`, which silently collapses empty components.
    """

    if path != path.strip():
        return False
    if not CLASSIFIABLE_PATH_RE.fullmatch(path):
        return False
    if path.startswith("/") or path.endswith("/"):
        return False
    return all(part not in {"", ".", ".."} for part in path.split("/"))


def decode_changed_files(text: str) -> tuple[list[str], int]:
    """Split the governed relevance job's change-set listing.

    The frozen relevance job emits `git diff --name-only --no-renames` line by
    line, which C-quotes any pathname carrying a newline, a quote, a backslash,
    or a non-ASCII byte. A quoted record therefore names a DIFFERENT path than
    the one on disk, and classifying it would answer a question about a path
    that does not exist — silently, in the skip direction.

    Rather than drop such a record (which makes the suite look irrelevant) or
    unquote it (which is the same guess by another name), the record is counted
    as unclassifiable and the caller forces the suite to RUN. Unclassifiable
    records are never returned, so hostile bytes never reach a pattern, a
    verdict, or the step summary.

    Returns the classifiable paths and the number of unclassifiable records.
    """

    # Split on the transport's own delimiter, NOT `str.splitlines()`: that also
    # breaks on CR, VT, FF, U+0085, U+2028, and U+2029, which would turn one
    # record holding such a byte into two innocuous-looking halves. Splitting on
    # "\n" alone keeps the byte inside its record, where the charset check
    # refuses it.
    records = text.split("\n")
    if records and records[-1] == "":
        # The terminator of the final line, not an extra record.
        records.pop()
    paths: list[str] = []
    unclassifiable = 0
    for record in records:
        if is_classifiable_repo_path(record):
            paths.append(record)
        else:
            unclassifiable += 1
    return paths, unclassifiable


def read_changed_files(path: Path) -> tuple[list[str], int]:
    # `errors="replace"` keeps an undecodable byte from raising here: it would
    # otherwise abort before the unclassifiable record could force a run, and
    # the replacement character is outside CLASSIFIABLE_PATH_RE anyway.
    return decode_changed_files(
        path.read_text(encoding="utf-8", errors="replace")
    )


def matched_files(suite: str, changed_files: list[str]) -> list[str]:
    patterns = COMPILED[suite]
    return [path for path in changed_files if any(pattern.search(path) for pattern in patterns)]


def write_summary(
    suite: str,
    relevant: bool,
    changed: list[str],
    matched: list[str],
    unclassifiable: int = 0,
) -> None:
    title = suite.replace("-", " ").title()
    print(f"## {title} Live Suite Path Filter")
    print()
    print(f"Relevant: **{str(relevant).lower()}**")
    print()
    if unclassifiable:
        print(
            f"{unclassifiable} change-set record(s) are not normal "
            "repository-relative pathnames and cannot be classified, so the "
            "suite runs. The records themselves are withheld."
        )
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


def native_mtls_fixture_contract_errors(root: Path) -> list[str]:
    """Fail closed if the release-blocking native MeshSubscribe leg is weakened.

    The trusted live-suite filter runs this against the checkout so a PR cannot
    silently restore plaintext h2c, drop client-CA/client-cert controls, enable
    TLS_NO_VERIFY, or drop a required negative/rotation assertion id.
    """

    errors: list[str] = []
    manifests = root / "tests/k8s/mesh_e2e_sidecar/manifests.yaml"
    run_sh = root / "tests/k8s/mesh_e2e_sidecar/run.sh"
    contract = root / "tests/conformance/ga_contract.yaml"
    for path in (manifests, run_sh, contract):
        if not path.is_file():
            errors.append(f"native mTLS live contract missing {path}")
            return errors

    manifests_text = manifests.read_text(encoding="utf-8")
    run_text = run_sh.read_text(encoding="utf-8")
    contract_text = contract.read_text(encoding="utf-8")

    for required in (
        "FERRUM_CP_GRPC_TLS_CERT_PATH",
        "FERRUM_CP_GRPC_TLS_KEY_PATH",
        "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH",
        "FERRUM_DP_GRPC_TLS_CA_CERT_PATH",
        "FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH",
        "FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH",
        "https://ferrum-cp.__NAMESPACE__.svc.cluster.local:50051",
        "ferrum-native-mtls-cp",
        "ferrum-native-mtls-dp",
        "projected:",
        "FERRUM_CP_DP_GRPC_JWT_SECRET",
        "native-mtls-probe",
    ):
        if required not in manifests_text:
            errors.append(
                f"mesh-e2e-sidecar manifests dropped required native mTLS marker `{required}`"
            )

    if "FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT" in manifests_text:
        errors.append("release-blocking native MeshSubscribe manifests enable plaintext")
    if "FERRUM_DP_GRPC_TLS_NO_VERIFY" in manifests_text:
        errors.append("release-blocking native MeshSubscribe manifests skip TLS verify")
    if "http://ferrum-cp." in manifests_text:
        errors.append("release-blocking native MeshSubscribe DP URL is plaintext h2c")
    if "FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT" in run_text:
        errors.append("run.sh restored the plaintext CP/DP gRPC override on the native leg")
    if "FERRUM_DP_GRPC_TLS_NO_VERIFY" in run_text:
        errors.append("run.sh restored TLS_NO_VERIFY on the native MeshSubscribe leg")
    if "http://ferrum-cp." in run_text:
        errors.append("run.sh restored a plaintext h2c ferrum-cp URL")
    if "mint_native_mtls_pki" not in run_text:
        errors.append("run.sh dropped ephemeral native MeshSubscribe PKI minting")
    if "apply_native_mtls_secrets gen2" not in run_text:
        errors.append("run.sh dropped the projected Secret generation swap")
    if "serviceAccountName: native-mtls-probe" not in run_text:
        errors.append("run.sh native mTLS probes must not share sa/capp")
    if "native_probe_classify.py" not in run_text:
        errors.append(
            "run.sh dropped the native probe classifier that correlates CP evidence "
            "to the exact probe pod IP/node_id"
        )
    if "ferrum_edge::modes::control_plane=debug" not in manifests_text:
        errors.append(
            "ferrum-cp FERRUM_LOG_LEVEL dropped control_plane debug, hiding CP TLS "
            "handshake rejections the classifier correlates by pod IP"
        )

    helper_path = root / "tests/k8s/lib/native_probe_classify.py"
    helper_text = (
        helper_path.read_text(encoding="utf-8") if helper_path.is_file() else ""
    )
    errors.extend(native_mtls_rotation_observation_errors(run_text, helper_text))
    errors.extend(native_mtls_negative_control_contract_errors(run_text, helper_text))

    required_ids = (
        "sidecar.config.native_subscribe_delivered",
        "sidecar.config.native_subscribe_mtls_omitted_client_rejected",
        "sidecar.config.native_subscribe_mtls_foreign_client_rejected",
        "sidecar.config.native_subscribe_tls_untrusted_server_ca_rejected",
        "sidecar.config.native_subscribe_tls_wrong_san_rejected",
        "sidecar.config.native_subscribe_jwt_rejected",
        "sidecar.config.native_subscribe_tls_rotation_reconnects",
    )
    native_row_start = contract_text.find("id: mesh.config_transport.native_subscribe")
    if native_row_start < 0:
        errors.append("ga_contract.yaml is missing mesh.config_transport.native_subscribe")
        native_row = ""
    else:
        native_row = contract_text[native_row_start:]
        next_row = native_row.find("\n  - id: ", 1)
        if next_row > 0:
            native_row = native_row[:next_row]
    for assertion_id in required_ids:
        if assertion_id not in run_text:
            errors.append(f"run.sh dropped required live assertion `{assertion_id}`")
        if assertion_id not in native_row:
            errors.append(
                f"ga_contract.yaml native_subscribe row dropped `{assertion_id}`"
            )
        if (
            f"record_live_assertion {assertion_id}" not in run_text
            and f"record_native_negative {assertion_id}" not in run_text
        ):
            errors.append(
                f"run.sh never records `{assertion_id}` (a skipped negative would leave the gate green)"
            )

    if "plaintext h2c with JWT" in contract_text:
        errors.append("ga_contract.yaml still describes the native row as plaintext-only")
    if "CP-DP gRPC TLS is an orthogonal" in contract_text:
        errors.append("ga_contract.yaml still treats CP/DP TLS as orthogonal")
    return errors


def native_mtls_negative_control_contract_errors(run_text: str, helper_text: str) -> list[str]:
    """Reject broad native negative TLS classes; pin per-control evidence."""

    errors: list[str] = []
    for banned in (
        "'tls-handshake|tls-verify'",
        "'tls-verify|tls-handshake'",
        "'tls-name|tls-verify|tls-handshake'",
        "^(tls-handshake|tls-verify)$",
    ):
        if banned in run_text:
            errors.append(
                f"run.sh must not accept broad native negative TLS classes (`{banned}`)"
            )

    for needle, desc in (
        ("NATIVE_EVID_CP_NO_CERT=", "exact CP omit-client evidence constant"),
        (
            "NATIVE_EVID_CP_UNKNOWN_ISSUER=",
            "exact CP UnknownIssuer evidence constant",
        ),
        (
            "NATIVE_EVID_CLIENT_SERVER_VERIFY=",
            "client-side server-verify evidence constant",
        ),
        ("NATIVE_EVID_CLIENT_TLS_NAME=", "client-side hostname/SAN evidence constant"),
        (
            "NATIVE_EVID_CP_JWT_AUTH_FAILED=",
            "exact CP MeshSubscribe JWT rejection evidence constant",
        ),
        (
            'native-omit-client tls-handshake "$NATIVE_EVID_CP_NO_CERT"',
            "omitted-client requires tls-handshake plus CP no-cert evidence",
        ),
        (
            'native-foreign-client tls-verify "$NATIVE_EVID_CP_UNKNOWN_ISSUER"',
            "foreign-client requires tls-verify plus CP UnknownIssuer evidence",
        ),
        (
            'native-untrusted-ca tls-verify "$NATIVE_EVID_CLIENT_SERVER_VERIFY"',
            "untrusted-server-CA requires client-side tls-verify evidence",
        ),
        (
            'native-wrong-san tls-name "$NATIVE_EVID_CLIENT_TLS_NAME"',
            "wrong-SAN requires client-side tls-name evidence",
        ),
        (
            'native-jwt-invalid jwt "$NATIVE_EVID_CP_JWT_AUTH_FAILED"',
            "invalid-JWT requires jwt plus CP MeshSubscribe auth-failure evidence",
        ),
        (
            "wait_for_native_probe_class native-stale-client tls-verify",
            "post-rotation stale client requires tls-verify (not generic handshake)",
        ),
        (
            'printf \'%s\' "$stale_ev" | grep -Eq "$NATIVE_EVID_CP_UNKNOWN_ISSUER"',
            "rotation gate requires CP UnknownIssuer evidence for gen1 stale client",
        ),
        (
            'printf \'%s\' "$reconnect_ev" | grep -Fq "cp_subscribe_accepted node_id="',
            "rotation gate requires helper cp_subscribe_accepted evidence for capp",
        ),
        (
            'printf \'%s\' "$reconnect_ev" | grep -Fq "client_tls_connect before="',
            "rotation gate requires helper client_tls_connect freshness evidence",
        ),
        (
            'printf \'%s\' "$reconnect_ev" | grep -Fq "dp_grpc_anchor=1"',
            "rotation gate requires a post-baseline dp_grpc reload anchor",
        ),
        (
            'printf \'%s\' "$reconnect_ev" | grep -Fq "cp_grpc_anchor=1"',
            "rotation gate requires a post-baseline cp_grpc reload anchor",
        ),
        (
            'printf \'%s\' "$reconnect_ev" | grep -Fq "client_post_anchor=1"',
            "rotation gate requires a Connected-to-CP after the dp_grpc reload",
        ),
        (
            'printf \'%s\' "$reconnect_ev" | grep -Fq "cp_post_anchor=1"',
            "rotation gate requires a Tenant subscription accepted after the cp_grpc reload",
        ),
        (
            'wait_for_native_probe_class "$deploy" "$want_pattern" "$want_evidence"',
            "negative wait loop must gate on classifier evidence, not class alone",
        ),
    ):
        if needle not in run_text:
            errors.append(f"run.sh missing {desc} (`{needle}`)")

    for needle, desc in (
        ("CONTROL_EVIDENCE = {", "classifier pins per-control evidence expectations"),
        (
            "generic-client-handshake-is-not-cp-omit-proof",
            "classifier self-test that generic handshake is not CP omit proof",
        ),
        (
            "client-jwt-alone-is-not-cp-meshsubscribe-proof",
            "classifier self-test that client UNAUTH alone is not CP JWT proof",
        ),
        (
            "hosted-untrusted-ca-native-tls-class",
            "classifier self-test for hosted untrusted-CA native_tls_class evidence",
        ),
        (
            "hosted-wrong-san-native-tls-class",
            "classifier self-test for hosted wrong-SAN native_tls_class evidence",
        ),
        (
            "flattened-tonic-error-is-not-client-verify-proof",
            "classifier self-test that flattened tonic errors stay handshake",
        ),
        (
            "ROTATION_ACCEPTED_EVIDENCE",
            "classifier pins rotation accepted-connect evidence",
        ),
        (
            "Tenant subscription accepted",
            "exact CP MeshSubscribe success audit message",
        ),
        (
            "cp_subscribe_accepted_count",
            "CP MeshSubscribe accept count correlated to exact node_id",
        ),
        (
            "client_tls_connected_count",
            "capp post-TLS connect count correlated to exact node_id",
        ),
        (
            "rotation_fresh_evidence",
            "pre/post freshness comparison for rotation reconnect",
        ),
        (
            "reconnect-attempt-is-not-accepted-proof",
            "classifier self-test that reconnect-attempt logs are not accepts",
        ),
        (
            "reload-log-is-not-accepted-proof",
            "classifier self-test that TLS reload logs are not accepts",
        ),
        (
            "pre-rotation-count-is-not-post-proof",
            "classifier self-test that the pre-swap count cannot satisfy post-swap",
        ),
        (
            "one-half-increase-is-not-fresh-proof",
            "classifier self-test that one half of the rotation proof is not enough",
        ),
        (
            "exact-capp-node-id-accepted",
            "classifier self-test that MeshSubscribe accepts use exact node_id",
        ),
        (
            "connected-without-node-id-is-not-tls-connect-proof",
            "classifier self-test that Connected-to-CP without node_id is not proof",
        ),
        (
            "ROTATION_RELOAD_ANCHORS",
            "classifier pins TLS reload surfaces as generation anchors",
        ),
        (
            "TLS_RELOAD_SURFACE_DP",
            "capp dp_grpc reload surface constant",
        ),
        (
            "TLS_RELOAD_SURFACE_CP",
            "CP cp_grpc reload surface constant",
        ),
        (
            "accepts-before-reload-anchor-are-not-fresh-proof",
            "classifier self-test that count increases before reload anchors are not proof",
        ),
        (
            "reload-anchor-without-later-accept-is-not-proof",
            "classifier self-test that reload anchors without later accepts are not proof",
        ),
        (
            "wrong-reload-surface-is-not-anchor",
            "classifier self-test that the wrong TLS reload surface is not an anchor",
        ),
        (
            "one-post-anchor-event-is-not-fresh-proof",
            "classifier self-test that only one post-anchor event is not enough",
        ),
        (
            "prefix-node-id-is-not-post-anchor-proof",
            "classifier self-test that prefix-overlapping node ids are not post-anchor proof",
        ),
    ):
        if needle not in helper_text:
            errors.append(
                f"native probe classifier helper missing {desc} (`{needle}`)"
            )

    return errors


def native_mtls_negative_control_self_test() -> list[str]:
    """Pin rejection of broad native negative TLS class alternation."""

    failures: list[str] = []
    helper_path = Path.cwd() / "tests/k8s/lib/native_probe_classify.py"
    helper_text = helper_path.read_text(encoding="utf-8") if helper_path.is_file() else ""
    broad_proof = """
record_native_negative sidecar.config.native_subscribe_mtls_omitted_client_rejected \\
  native-omit-client 'tls-handshake|tls-verify' || failed=true
stale_class="$(wait_for_native_probe_class native-stale-client 'tls-handshake|tls-verify')"
"""
    broad_errors = native_mtls_negative_control_contract_errors(broad_proof, helper_text)
    if not broad_errors:
        failures.append(
            "native negative control contract accepted broad TLS class alternation"
        )
    elif not any("broad native negative TLS" in error for error in broad_errors):
        failures.append(
            "native negative control contract must name broad TLS alternation rejection"
        )
    return failures


_BASH_FUNC_DEF_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{")


def _bash_function_body(source: str, name: str) -> str:
    """Return the named bash function including its definition line."""

    lines = source.splitlines()
    start = None
    pattern = re.compile(rf"^{re.escape(name)}\(\)\s*\{{")
    for idx, line in enumerate(lines):
        if pattern.match(line.strip()):
            start = idx
            break
    if start is None:
        return ""
    collected: list[str] = []
    depth = 0
    started = False
    for line in lines[start:]:
        for char in line:
            if char == "{":
                depth += 1
                started = True
            elif char == "}":
                depth -= 1
        collected.append(line)
        if started and depth <= 0:
            break
    return "\n".join(collected)


def _non_comment_lines(source: str) -> str:
    return "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("#")
    )


def _bash_functions_publishing_observe_pid(run_text: str) -> set[str]:
    """Functions that publish NATIVE_OBSERVE_PF_PID=$... (must run in this shell)."""

    names: set[str] = set()
    current: str | None = None
    for line in run_text.splitlines():
        stripped = line.strip()
        match = _BASH_FUNC_DEF_RE.match(stripped)
        if match:
            current = match.group(1)
            continue
        if (
            current
            and not stripped.startswith("#")
            and 'NATIVE_OBSERVE_PF_PID="$' in line
        ):
            names.add(current)
    return names


def _command_substitution_invokes_observe_helper(run_text: str, names: set[str]) -> bool:
    if not names:
        return False
    text = "\n".join(
        line for line in run_text.splitlines() if not line.strip().startswith("#")
    )
    for name in names:
        if re.search(rf"\$\(\s*{re.escape(name)}\b", text):
            return True
        if re.search(rf"`\s*{re.escape(name)}\b", text):
            return True
    return False


def _observe_helper_invoked_in_parent_shell(run_text: str, names: set[str]) -> bool:
    for line in run_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "$(" in stripped or "`" in stripped:
            continue
        for name in names:
            if re.search(rf"(?:^|[\s;]){re.escape(name)}(?:\s|;|$)", stripped):
                return True
    return False


def _live_serial_copied_from_parent_channel(run_text: str) -> bool:
    for line in run_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r'\blive_serial="\$\{?NATIVE_CP_SERVED_SERIAL\b', stripped):
            return True
    return False


def _live_serial_captured_from_command_substitution(run_text: str) -> bool:
    for line in run_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r'\blive_serial="?\$\(', stripped) or re.search(
            r"\blive_serial=`", stripped
        ):
            return True
    return False


def native_mtls_rotation_observation_errors(
    run_text: str, helper_text: str = ""
) -> list[str]:
    """Reject a rotation gate that treats Secret.data.server.pem as live.

    The served serial must come from a verified openssl s_client handshake to
    the running ferrum-cp listener (Service DNS SAN, gen2 CA, gen2 DP client
    cert). Function names may change; the handshake/verify/serial markers and
    the Secret-decode prohibition are the contract. The stateful observe helper
    that publishes NATIVE_OBSERVE_PF_PID must run in the parent shell.

    Rotation reconnect proof must capture a pre-swap baseline for the running
    capp identity, then require a successful surface=dp_grpc TLS reload in
    capp logs followed by a subsequent exact-node Connected-to-CP, and a
    successful surface=cp_grpc TLS reload in CP logs followed by a subsequent
    exact-node Tenant subscription accepted. Reload publications are temporal
    generation anchors only; reconnect-attempt logs are not proof.
    """

    errors: list[str] = []
    if (
        ".data.server" in run_text
        or "jsonpath='{.data.server" in run_text
        or 'jsonpath="{.data.server' in run_text
        or "get secret ferrum-native-mtls-cp" in run_text
    ):
        errors.append(
            "rotation live serial must not be decoded from Secret.data.server.pem"
        )
    if "/transport/server.pem" in run_text:
        errors.append(
            "rotation live serial must not be read from the mounted CP server cert"
        )
    for line in run_text.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("#"):
            continue
        if ("live_serial=" in trimmed or 'live_serial="' in trimmed) and (
            "gen2-server.pem" in trimmed
            or "/server.pem" in trimmed
            or "get secret" in trimmed
            or ".data.server" in trimmed
        ):
            errors.append(
                "live_serial assignment must not use a Secret, mounted file, "
                "or controller-local expected server cert"
            )
    if "pkill" in run_text or "killall" in run_text:
        errors.append(
            "native CP observe helper must kill only its port-forward PID, not pkill/killall"
        )

    required = (
        ("openssl s_client", "over-the-wire openssl s_client handshake"),
        ("-verify_return_error", "TLS verification fail-closed"),
        ("-verify_hostname", "Service DNS SAN verification"),
        ("gen2-ca.pem", "gen2 server CA"),
        ("gen2-client.pem", "gen2 DP client cert"),
        ("gen2-client-key.pem", "gen2 DP client key"),
        ("port-forward", "kubectl port-forward to the live CP"),
        ("NATIVE_CP_DNS", "Kubernetes Service DNS name"),
        ("NATIVE_SERVER_SERIAL_GEN2", "gen2 served-serial gate"),
        ("NATIVE_CP_SERVED_SERIAL", "parent-shell served serial result channel"),
        ("NATIVE_CP_SERVED_CLASS", "parent-shell observe class channel"),
        ("NATIVE_OBSERVE_PF_PID", "parent-shell port-forward PID for EXIT cleanup"),
        ("Verify return code: 0", "verified-handshake success check"),
        (
            "wait_for_native_rotation_evidence",
            "fresh capp MeshSubscribe accept evidence",
        ),
        (
            "capture_native_rotation_baseline",
            "pre-swap accepted-connect baseline for capp",
        ),
        ("--rotation-count", "helper pre-swap accepted-connect count"),
        ("--rotation-fresh", "helper post-swap freshness comparison"),
        (
            "NATIVE_ROTATION_BASELINE_CAPTURED",
            "rotation wait must require a captured baseline",
        ),
        (
            "native_probe_running_identity capp",
            "rotation baseline must use capp's running pod/node identity",
        ),
        ("--baseline-cp", "CP accept baseline passed into freshness comparison"),
        (
            "--baseline-client",
            "capp TLS-connect baseline passed into freshness comparison",
        ),
        (
            "--tail=-1",
            "full current-container logs so pre-swap lines cannot slide out of a tail window",
        ),
        (
            "dp_grpc_anchor=1",
            "rotation evidence must report a post-baseline dp_grpc reload anchor",
        ),
        (
            "cp_grpc_anchor=1",
            "rotation evidence must report a post-baseline cp_grpc reload anchor",
        ),
        (
            "client_post_anchor=1",
            "rotation evidence must report Connected-to-CP after the dp_grpc reload",
        ),
        (
            "cp_post_anchor=1",
            "rotation evidence must report Tenant subscription accepted after the cp_grpc reload",
        ),
    )
    for needle, desc in required:
        if needle not in run_text:
            errors.append(f"native rotation observation missing {desc} (`{needle}`)")

    forwards_cp = "port-forward" in run_text and (
        "svc/ferrum-cp" in run_text
        or "service/ferrum-cp" in run_text
        or "deploy/ferrum-cp" in run_text
    )
    if not forwards_cp:
        errors.append(
            "rotation observation must port-forward the live ferrum-cp listener"
        )

    idx = run_text.find("openssl s_client")
    window = run_text[idx : idx + 5000] if idx >= 0 else ""
    if not (
        "openssl x509" in window
        and "-noout" in window
        and "-serial" in window
        and "CAcreateserial" not in window
    ):
        errors.append(
            "peer leaf serial must be extracted from the openssl s_client "
            "handshake output (openssl x509 -noout -serial)"
        )
    if "shred" in run_text.lower():
        errors.append(
            "run.sh must not claim keys are shredded unless the fixture shreds them"
        )

    observe_helpers = _bash_functions_publishing_observe_pid(run_text)
    if _command_substitution_invokes_observe_helper(run_text, observe_helpers):
        errors.append(
            "stateful native CP observe helper must run in the parent shell, not "
            "via command substitution (NATIVE_OBSERVE_PF_PID / NATIVE_CP_SERVED_CLASS "
            "/ NATIVE_CP_SERVED_SERIAL would not propagate)"
        )
    if observe_helpers and not _observe_helper_invoked_in_parent_shell(
        run_text, observe_helpers
    ):
        errors.append(
            "rotation probe must invoke the stateful observe helper directly in "
            "the parent shell"
        )
    if _live_serial_captured_from_command_substitution(run_text):
        errors.append(
            "live_serial must be copied from NATIVE_CP_SERVED_SERIAL after a "
            "direct helper call; do not capture the observe helper via command "
            "substitution"
        )
    if not _live_serial_copied_from_parent_channel(run_text):
        errors.append(
            "probe must read live_serial from NATIVE_CP_SERVED_SERIAL after a "
            "direct helper call"
        )
    if "observe_class=${NATIVE_CP_SERVED_CLASS" not in run_text and (
        "observe_class=$NATIVE_CP_SERVED_CLASS" not in run_text
    ):
        errors.append(
            "rotation outcome must read NATIVE_CP_SERVED_CLASS from the parent shell"
        )

    wait_body = _non_comment_lines(
        _bash_function_body(run_text, "wait_for_native_rotation_evidence")
    )
    if wait_body:
        if "reconnecting native MeshSubscribe stream" in wait_body:
            errors.append(
                "wait_for_native_rotation_evidence must not treat reconnect-attempt "
                "logs as rotation proof"
            )
        if "TLS material sources reloaded" in wait_body:
            errors.append(
                "wait_for_native_rotation_evidence must not treat TLS reload logs "
                "as rotation proof"
            )
        if "--rotation-fresh" not in wait_body and "native_rotation_fresh_now" not in wait_body:
            errors.append(
                "wait_for_native_rotation_evidence must require helper freshness "
                "comparison, not reload/attempt greps"
            )
        if "NATIVE_ROTATION_BASELINE_CAPTURED" not in wait_body:
            errors.append(
                "wait_for_native_rotation_evidence must refuse to pass without a "
                "captured pre-swap baseline"
            )
        if "seq 1 120" not in wait_body or "sleep 2" not in wait_body:
            errors.append(
                "wait_for_native_rotation_evidence must poll for at least 240s of "
                "projected-volume evidence (seq 1 120 * sleep 2)"
            )
        if "seq 1 45" in wait_body:
            errors.append(
                "wait_for_native_rotation_evidence must not use the 90s projected-volume "
                "window; hosted Kind kubelet projection can exceed it"
            )

    probe_body = _bash_function_body(run_text, "probe_native_mtls_rotation")
    if probe_body:
        idx_base = probe_body.find("capture_native_rotation_baseline")
        idx_gen2 = probe_body.find("apply_native_mtls_secrets gen2")
        idx_wait = probe_body.find("wait_for_native_rotation_evidence")
        if not (0 <= idx_base < idx_gen2 < idx_wait):
            errors.append(
                "probe_native_mtls_rotation must capture the capp baseline, apply "
                "gen2, then wait for a strictly newer accepted MeshSubscribe"
            )

    if helper_text:
        for needle, desc in (
            ("Tenant subscription accepted", "CP MeshSubscribe success audit"),
            ("cp_subscribe_accepted_count", "exact-node CP accept counting"),
            ("client_tls_connected_count", "exact-node capp TLS-connect counting"),
            ("rotation_fresh_evidence", "pre/post freshness comparison"),
            (
                "reconnect-attempt-is-not-accepted-proof",
                "self-test rejecting reconnect-attempt logs",
            ),
            (
                "pre-rotation-count-is-not-post-proof",
                "self-test rejecting pre-swap counts as post-swap proof",
            ),
            (
                "ROTATION_RELOAD_ANCHORS",
                "TLS reload surfaces as generation anchors",
            ),
            (
                "accepts-before-reload-anchor-are-not-fresh-proof",
                "self-test rejecting count increases before reload anchors",
            ),
            (
                "reload-anchor-without-later-accept-is-not-proof",
                "self-test rejecting reload anchors without later accepts",
            ),
            (
                "wrong-reload-surface-is-not-anchor",
                "self-test rejecting the wrong TLS reload surface as an anchor",
            ),
            (
                "one-post-anchor-event-is-not-fresh-proof",
                "self-test rejecting a single post-anchor event",
            ),
            (
                "prefix-node-id-is-not-post-anchor-proof",
                "self-test rejecting prefix-overlapping node ids after reload",
            ),
        ):
            if needle not in helper_text:
                errors.append(
                    f"native rotation helper missing {desc} (`{needle}`)"
                )

    return errors


def native_mtls_rotation_observation_self_test() -> list[str]:
    """Pin the false Secret-decode proof so it cannot silently return."""

    failures: list[str] = []
    secret_false_proof = """
apply_native_mtls_secrets gen2
wait_for_native_rotation_evidence
live_serial="$(kubectl get secret ferrum-native-mtls-cp \\
  -o jsonpath='{.data.server\\.pem}' | base64 -d | openssl x509 -noout -serial)"
record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
"""
    secret_errors = native_mtls_rotation_observation_errors(secret_false_proof)
    if not secret_errors:
        failures.append(
            "rotation observation contract accepted Secret.data.server.pem as live serial"
        )
    elif not any("Secret.data.server.pem" in error for error in secret_errors):
        failures.append(
            "rotation observation contract must name Secret decoding in the rejection"
        )

    subshell_false_proof = r"""
apply_native_mtls_secrets gen2
wait_for_native_rotation_evidence
NATIVE_CP_SERVED_SERIAL=""
NATIVE_CP_SERVED_CLASS=""
NATIVE_OBSERVE_PF_PID=""
observe_native_cp_served_serial() {
  NATIVE_OBSERVE_PF_PID="$pf_pid"
  kubectl port-forward svc/ferrum-cp "${port}:50051"
  openssl s_client -connect 127.0.0.1:${port} -servername "$NATIVE_CP_DNS" \
    -verify_hostname "$NATIVE_CP_DNS" -verify_return_error \
    -CAfile gen2-ca.pem -cert gen2-client.pem -key gen2-client-key.pem
  openssl x509 -noout -serial
  Verify return code: 0
  NATIVE_CP_SERVED_SERIAL="$serial"
  NATIVE_CP_SERVED_CLASS=ok
  printf '%s\n' "$serial"
}
if live_serial="$(observe_native_cp_served_serial)"; then
  live_serial="${NATIVE_CP_SERVED_SERIAL:-}"
fi
outcome="live_serial=$live_serial observe_class=${NATIVE_CP_SERVED_CLASS:-}"
record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
NATIVE_SERVER_SERIAL_GEN2
"""
    subshell_errors = native_mtls_rotation_observation_errors(subshell_false_proof)
    if not subshell_errors:
        failures.append(
            "rotation observation contract accepted invoking the observe helper "
            "through command substitution"
        )
    elif not any(
        "command substitution" in error or "parent shell" in error
        for error in subshell_errors
    ):
        failures.append(
            "rotation observation contract must reject observe-helper command "
            f"substitution by name, got {subshell_errors!r}"
        )

    reload_false_proof = r"""
capture_native_rotation_baseline() { return 0; }
wait_for_native_rotation_evidence() {
  grep -Fq 'TLS material sources reloaded; new handshakes/connections will use rotated material'
  grep -Fq 'Mesh gRPC TLS source changed; reconnecting native MeshSubscribe stream'
  return 0
}
probe_native_mtls_rotation() {
  capture_native_rotation_baseline
  apply_native_mtls_secrets gen2
  wait_for_native_rotation_evidence
  kubectl port-forward svc/ferrum-cp "${port}:50051"
  openssl s_client -connect 127.0.0.1:${port} -servername "$NATIVE_CP_DNS" \
    -verify_hostname "$NATIVE_CP_DNS" -verify_return_error \
    -CAfile gen2-ca.pem -cert gen2-client.pem -key gen2-client-key.pem
  openssl x509 -noout -serial
  Verify return code: 0
  live_serial="${NATIVE_CP_SERVED_SERIAL:-}"
  outcome="observe_class=${NATIVE_CP_SERVED_CLASS:-}"
  record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
}
NATIVE_OBSERVE_PF_PID=""
NATIVE_CP_SERVED_SERIAL=""
NATIVE_CP_SERVED_CLASS=""
NATIVE_SERVER_SERIAL_GEN2=""
NATIVE_ROTATION_BASELINE_CAPTURED=true
--rotation-count
--rotation-fresh
--baseline-cp
--baseline-client
native_probe_running_identity capp
"""
    reload_errors = native_mtls_rotation_observation_errors(reload_false_proof)
    if not reload_errors:
        failures.append(
            "rotation observation contract accepted reload/reconnect-attempt logs "
            "as MeshSubscribe accept proof"
        )
    elif not any(
        "reconnect-attempt" in error or "TLS reload" in error or "freshness" in error
        for error in reload_errors
    ):
        failures.append(
            "rotation observation contract must reject reload/attempt-only evidence "
            f"by name, got {reload_errors!r}"
        )

    no_baseline_false_proof = r"""
wait_for_native_rotation_evidence() {
  python3 helper --rotation-fresh --pod-name "$pod"
  return 0
}
probe_native_mtls_rotation() {
  apply_native_mtls_secrets gen2
  wait_for_native_rotation_evidence
  kubectl port-forward svc/ferrum-cp "${port}:50051"
  openssl s_client -connect 127.0.0.1:${port} -servername "$NATIVE_CP_DNS" \
    -verify_hostname "$NATIVE_CP_DNS" -verify_return_error \
    -CAfile gen2-ca.pem -cert gen2-client.pem -key gen2-client-key.pem
  openssl x509 -noout -serial
  Verify return code: 0
  live_serial="${NATIVE_CP_SERVED_SERIAL:-}"
  outcome="observe_class=${NATIVE_CP_SERVED_CLASS:-}"
  record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass
}
NATIVE_OBSERVE_PF_PID=""
NATIVE_CP_SERVED_SERIAL=""
NATIVE_CP_SERVED_CLASS=""
NATIVE_SERVER_SERIAL_GEN2=""
--rotation-count
--rotation-fresh
--baseline-cp
--baseline-client
native_probe_running_identity capp
"""
    no_baseline_errors = native_mtls_rotation_observation_errors(
        no_baseline_false_proof
    )
    if not no_baseline_errors:
        failures.append(
            "rotation observation contract accepted a post-swap wait without a "
            "pre-swap capp baseline"
        )
    elif not any(
        "baseline" in error or "capture_native_rotation_baseline" in error
        for error in no_baseline_errors
    ):
        failures.append(
            "rotation observation contract must require a pre-swap baseline "
            f"by name, got {no_baseline_errors!r}"
        )
    return failures


def changed_file_transport_self_test() -> list[str]:
    """Prove the change-set reader never turns a hostile record into a skip.

    Every rejected case below is a record `git diff --name-only` can emit for a
    pathname it had to C-quote, or a record no ordinary repository path can
    produce. Classifying any of them as "no relevant file" would skip a live
    gate; each must instead be counted unclassifiable so the caller runs the
    suite, and none may be returned for pattern matching or summary echo.
    """

    failures: list[str] = []

    if decode_changed_files("") != ([], 0):
        failures.append("an actually empty diff must decode to an empty change set")

    exact = [
        "src/proxy/mod.rs",
        ".github/actions/setup-sccache/action.yml",
        "tests/k8s/node waypoint/run.sh",
        "docs/plans/node_waypoint_transport_adr.md",
    ]
    decoded, unclassifiable = decode_changed_files(
        "".join(f"{path}\n" for path in exact)
    )
    if decoded != exact or unclassifiable:
        failures.append(
            "ordinary records must retain exact path identity "
            f"({len(decoded)} record(s) decoded, {unclassifiable} refused)"
        )

    # A listing with no trailing newline is still a complete listing: the
    # frozen job pipes `git diff --name-only` through `sort`, which terminates
    # its last line, but an unterminated final record must not be dropped.
    decoded, unclassifiable = decode_changed_files("src/proxy/mod.rs")
    if decoded != ["src/proxy/mod.rs"] or unclassifiable:
        failures.append("an unterminated final record must still be classified")

    # Exactly one trailing terminator is consumed; a genuinely blank line is a
    # record, and a blank line is not a repository path.
    decoded, unclassifiable = decode_changed_files("src/proxy/mod.rs\n\n")
    if decoded != ["src/proxy/mod.rs"] or unclassifiable != 1:
        failures.append("a trailing blank line must be refused, not swallowed")

    refused = (
        # C-quoted forms `git diff --name-only` emits instead of the real path.
        ("c-quoted-newline", '"src/proxy/\\nmod.rs"'),
        ("c-quoted-non-ascii", '"src/proxy/\\303\\251mod.rs"'),
        ("c-quoted-quote", '"src/proxy/\\"mod.rs"'),
        ("c-quoted-backslash", '"src/proxy/\\\\mod.rs"'),
        # Records no ordinary repository path can produce.
        ("blank-record", ""),
        ("whitespace-record", "   "),
        ("undecodable-byte-replacement", "src/proxy/\ufffdmod.rs"),
        ("tab-in-name", "src/proxy/\tmod.rs"),
        ("carriage-return-in-name", "src/proxy/\rmod.rs"),
        ("c0-soh-in-name", "src/proxy/\x01mod.rs"),
        ("c0-us-in-name", "src/proxy/\x1fmod.rs"),
        ("del-in-name", "src/proxy/\x7fmod.rs"),
        ("bidi-override-in-name", "src/proxy/" + chr(0x202E) + "mod.rs"),
        ("zero-width-joiner-in-name", "src/proxy/" + chr(0x200D) + "mod.rs"),
        # Shape.
        ("absolute", "/src/proxy/mod.rs"),
        ("traversal", "src/../../etc/passwd"),
        ("dot-prefix", "./src/proxy/mod.rs"),
        ("dot-inner", "src/./proxy/mod.rs"),
        ("empty-component", "src//proxy/mod.rs"),
        ("trailing-slash", "src/proxy/"),
        ("leading-space", " src/proxy/mod.rs"),
        ("trailing-space", "src/proxy/mod.rs "),
        ("backslash", "src\\proxy\\mod.rs"),
        ("backtick", "src/proxy/`mod.rs"),
        ("dollar-substitution", "src/proxy/$(id).rs"),
    )
    for label, record in refused:
        decoded, unclassifiable = decode_changed_files(f"{record}\n")
        if decoded or unclassifiable != 1:
            failures.append(
                f"{label} record must be counted unclassifiable and withheld; "
                f"got {len(decoded)} classified / {unclassifiable} refused"
            )

    # An unclassifiable record alongside an ordinary one must force the run
    # rather than let the ordinary record decide relevance on its own.
    decoded, unclassifiable = decode_changed_files(
        'docs/admin_api.md\n"src/cni/\\nmod.rs"\n'
    )
    if decoded != ["docs/admin_api.md"] or unclassifiable != 1:
        failures.append(
            "an unclassifiable record must survive alongside classified ones"
        )
    for suite in ("istio-status-cas", "cni-lifecycle"):
        if matched_files(suite, decoded):
            failures.append(
                f"{suite} fixture must not match on its own; the run has to be "
                "forced by the unclassifiable record"
            )

    return failures


def local_action_dependency_self_test() -> list[str]:
    """Prove every declared local composite action stays suite-relevant."""

    failures: list[str] = []
    for suite, actions in sorted(SUITE_LOCAL_ACTION_DEPENDENCIES.items()):
        if suite not in SUITE_PATTERNS:
            failures.append(f"{suite} has local action dependencies but no patterns")
            continue
        for action in sorted(actions):
            probe = f".github/actions/{action}/action.yml"
            if not matched_files(suite, [probe]):
                failures.append(
                    f"{suite} must stay relevant to local composite action "
                    f"{probe}; its live job executes it"
                )
    return failures


def self_test() -> int:
    cases = [
        ("gateway-api", ["src/tls/frontend.rs"], True),
        ("gateway-api", [".github/scripts/live_suite_path_filter.py"], True),
        ("gateway-api", [".github/actions/setup-kubernetes-tools/action.yml"], True),
        ("gateway-api", ["scripts/gateway_api_conformance_lab_setup.sh"], True),
        ("gateway-api", ["scripts/gateway_api_tcproute_conformance.sh"], True),
        ("gateway-api", ["scripts/gateway_api_tlsroute_conformance.sh"], True),
        ("gateway-api", ["scripts/gateway_api_gatewayclass_authority_conformance.sh"], True),
        ("gateway-api", ["src/config/model.rs"], True),
        ("gateway-api", ["Dockerfile.release"], True),
        ("gateway-api", ["docs/mesh.md"], False),
        ("mesh-federation", ["tests/k8s/lib/spire.sh"], True),
        ("mesh-federation", ["tests/k8s/multicluster-poller-partition/run.sh"], True),
        ("mesh-federation", [".github/scripts/live_suite_path_filter.py"], True),
        ("mesh-federation", [".github/actions/setup-kubernetes-tools/action.yml"], True),
        ("mesh-federation", ["src/service_discovery/kubernetes.rs"], True),
        ("mesh-federation", ["src/modes/control_plane.rs"], True),
        ("mesh-federation", ["src/k8s_controller/reconciler.rs"], True),
        ("mesh-federation", ["src/config_sources/k8s/core.rs"], True),
        ("mesh-federation", ["charts/ferrum-mesh/values.yaml"], False),
        ("mesh-federation", ["docs/spire_deployment.md"], True),
        ("mesh-e2e-sidecar", ["tests/k8s/mesh_e2e_sidecar/run.sh"], True),
        ("mesh-e2e-sidecar", ["tests/k8s/lib/native_probe_classify.py"], True),
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
        ("mesh-e2e-sidecar", ["src/modes/grpc_tls_reload.rs"], True),
        ("mesh-e2e-sidecar", ["src/modes/tls_source_util.rs"], True),
        ("mesh-e2e-sidecar", ["docs/cp_dp_mode.md"], True),
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
        ("ambient-host-udp", ["src/proxy/host_udp_capture.rs"], True),
        ("ambient-host-udp", ["src/proxy/host_udp_capture_live_tests.rs"], True),
        ("ambient-host-udp", ["tests/k8s/ambient_host_udp_live/run.sh"], True),
        ("ambient-host-udp", [".github/workflows/ambient-host-udp-live.yml"], True),
        ("ambient-host-udp", [".github/scripts/live_suite_path_filter.py"], True),
        ("ambient-host-udp", ["charts/ferrum-mesh/values.yaml"], True),
        ("ambient-host-udp", ["docs/tcp_udp_proxy.md"], True),
        ("ambient-host-udp", ["docs/ci_cd.md"], True),
        ("ambient-host-udp", ["Dockerfile"], True),
        ("ambient-host-udp", [".github/workflows/release.yml"], True),
        ("ambient-host-udp", [".github/scripts/stage_iproute2_runtime.sh"], True),
        (
            "ambient-host-udp",
            [".github/scripts/verify_release_image_attestations.py"],
            True,
        ),
        (
            "ambient-host-udp",
            ["charts/ferrum-mesh/templates/ambient-daemonset.yaml"],
            True,
        ),
        ("ambient-host-udp", ["src/proxy/udp_placement_migration.rs"], True),
        ("ambient-host-udp", ["src/proxy/udp_placement_cleanup.rs"], True),
        ("ambient-host-udp", ["src/cli.rs"], True),
        ("ambient-host-udp", ["src/main.rs"], True),
        ("ambient-host-udp", ["src/gateway_entry.rs"], True),
        ("ambient-host-udp", ["src/modes/node_agent.rs"], True),
        ("ambient-host-udp", ["src/modes/data_plane.rs"], False),
        ("ambient-host-udp", ["tests/k8s/mesh_e2e_sidecar/run.sh"], False),
        ("istio-status-cas", ["src/k8s_controller/istio_status.rs"], True),
        ("istio-status-cas", ["src/k8s_controller/metrics.rs"], True),
        ("istio-status-cas", ["tests/k8s_istio_status_cas_live.rs"], True),
        (
            "istio-status-cas",
            ["tests/fixtures/k8s/istio_authorizationpolicy_status_crd.yaml"],
            True,
        ),
        ("istio-status-cas", [".github/workflows/istio-status-cas-live.yml"], True),
        ("istio-status-cas", [".github/scripts/live_suite_path_filter.py"], True),
        ("istio-status-cas", [".github/actions/setup-rust-ci/action.yml"], True),
        ("istio-status-cas", [".github/actions/setup-sccache/action.yml"], True),
        ("istio-status-cas", [".github/actions/setup-fast-linker/action.yml"], True),
        (
            "istio-status-cas",
            [".github/actions/setup-kubernetes-tools/action.yml"],
            True,
        ),
        # This suite compiles a test binary; it never builds an eBPF ELF or
        # packages a runtime image, so those actions stay out of scope.
        ("istio-status-cas", [".github/actions/setup-bpf-linker/action.yml"], False),
        (
            "istio-status-cas",
            [".github/actions/package-ferrum-runtime-image/action.yml"],
            False,
        ),
        ("istio-status-cas", ["src/k8s_controller/reconciler.rs"], False),
        ("istio-status-cas", ["docs/ci_cd.md"], False),
        ("cni-lifecycle", ["src/cni/mod.rs"], True),
        ("cni-lifecycle", ["src/bin/ferrum-cni.rs"], True),
        ("cni-lifecycle", ["tests/k8s/cni_lifecycle_live/run.sh"], True),
        ("cni-lifecycle", [".github/workflows/cni-lifecycle-live.yml"], True),
        ("cni-lifecycle", [".github/scripts/live_suite_path_filter.py"], True),
        (
            "cni-lifecycle",
            ["charts/ferrum-mesh/templates/cni-uninstall-hook.yaml"],
            True,
        ),
        ("cni-lifecycle", ["charts/ferrum-mesh/values.yaml"], True),
        ("cni-lifecycle", ["docs/node_agent_security.md"], True),
        ("cni-lifecycle", ["PRODUCTION_READINESS.md"], True),
        ("cni-lifecycle", [".github/actions/setup-rust-ci/action.yml"], True),
        ("cni-lifecycle", [".github/actions/setup-sccache/action.yml"], True),
        ("cni-lifecycle", [".github/actions/setup-fast-linker/action.yml"], True),
        (
            "cni-lifecycle",
            [".github/actions/package-ferrum-runtime-image/action.yml"],
            True,
        ),
        # The CNI lifecycle job builds no eBPF ELF.
        ("cni-lifecycle", [".github/actions/setup-bpf-linker/action.yml"], False),
        (
            "cni-lifecycle",
            ["charts/ferrum-mesh/templates/sidecar-injector.yaml"],
            False,
        ),
        ("cni-lifecycle", ["docs/ci_cd.md"], False),
        ("cni-lifecycle", ["src/modes/data_plane.rs"], False),
    ]
    failures: list[str] = []
    for suite, changed, expected in cases:
        relevant = bool(matched_files(suite, changed))
        if relevant != expected:
            failures.append(
                f"{suite} {changed!r}: expected relevant={expected}, got {relevant}"
            )
    failures.extend(changed_file_transport_self_test())
    failures.extend(local_action_dependency_self_test())
    failures.extend(native_mtls_fixture_contract_errors(Path.cwd()))
    failures.extend(native_mtls_rotation_observation_self_test())
    failures.extend(native_mtls_negative_control_self_test())
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=sorted(SUITE_PATTERNS))
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--force-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    # The `--list-suites` capability handshake that carried the CNI lifecycle
    # and Istio status-CAS suites through their adoption window (issue #3908)
    # is gone. It existed only while those suite names were newer than the
    # trusted copy of this classifier; both names are on `main`, both
    # workflows now carry the byte-frozen LIVE_SUITE_RELEVANCE_JOB_TEMPLATE,
    # which never invokes the flag, and no workflow, script, or policy calls
    # it. A no-longer-reachable bootstrap is a shape a later relevance job
    # could be written against, so it is deleted rather than left inert.
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.suite or not args.changed_files:
        parser.error("--suite and --changed-files are required unless --self-test is used")

    changed, unclassifiable = read_changed_files(args.changed_files)
    matched = matched_files(args.suite, changed)
    # A record that is not a normal repository-relative pathname was withheld
    # from `changed`, so it cannot match a pattern. Treating that as "nothing
    # relevant changed" is exactly the false skip this classifier exists to
    # prevent, so an unclassifiable change set runs the suite.
    relevant = args.force_run or bool(unclassifiable) or bool(matched)
    print(f"relevant={str(relevant).lower()}")
    print(f"matched_count={len(matched)}")
    print(f"unclassifiable_count={unclassifiable}")
    write_summary(args.suite, relevant, changed, matched, unclassifiable)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
