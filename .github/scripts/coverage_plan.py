#!/usr/bin/env python3
"""Select CI coverage mode and the shard matrix from an event and changed files."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


LIB_UNIT_SHARD = "lib-unit"
ADMIN_API_SHARD = "admin-api"
ADMIN_CONFIG_SHARD = "admin-config"
MESH_ROUTING_SHARD = "mesh-routing"
MESH_PLATFORM_SHARD = "mesh-platform"
PROTOCOLS_SHARD = "protocols-data-plane"

CANONICAL_SHARD_ORDER = (
    LIB_UNIT_SHARD,
    ADMIN_API_SHARD,
    ADMIN_CONFIG_SHARD,
    MESH_ROUTING_SHARD,
    MESH_PLATFORM_SHARD,
    PROTOCOLS_SHARD,
)

ADMIN_SHARDS = frozenset({ADMIN_API_SHARD, ADMIN_CONFIG_SHARD})
MESH_SHARDS = frozenset({MESH_ROUTING_SHARD, MESH_PLATFORM_SHARD})
ALL_INTEGRATION_SHARDS = frozenset(CANONICAL_SHARD_ORDER[1:])
ALL_SHARDS = frozenset(CANONICAL_SHARD_ORDER)
# Serving modes that start admin + proxy (and optionally DB/CP), but are not mesh.
ADMIN_AND_PROTOCOL_SHARDS = frozenset({*ADMIN_SHARDS, PROTOCOLS_SHARD})
# TLS datapath is exercised by mesh and protocol shards, not the admin API suite.
MESH_AND_PROTOCOL_SHARDS = frozenset({*MESH_SHARDS, PROTOCOLS_SHARD})
# K8s translation feeds admin mesh-config tests and both mesh shard families.
CONFIG_SOURCES_SHARDS = frozenset({ADMIN_CONFIG_SHARD, *MESH_SHARDS})

VALID_MODES = frozenset({"skip", "plugin", "shards", "full"})
SHARD_NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f]")
CLASSIFIABLE_PATH_RE = re.compile(r"^[A-Za-z0-9._+@~ /-]{1,4096}$")

PLUGIN_PATTERNS = [
    re.compile(r"^src/plugin_cache\.rs$"),
    re.compile(r"^tests/functional/functional_redis_rate_limiting_test\.rs$"),
    re.compile(r"^src/plugins/"),
    re.compile(r"^tests/unit/plugins/"),
]

CONTROLLER_PATHS = frozenset(
    {
        ".github/workflows/coverage.yml",
        ".github/scripts/coverage_plan.py",
        ".github/scripts/verify_coverage_workflow.py",
        "scripts/check_coverage_thresholds.py",
        "scripts/coverage.sh",
    }
)

BUILD_GRAPH_PATTERNS = [
    re.compile(r"^Cargo\.(toml|lock)$"),
    re.compile(r"^build\.rs$"),
    re.compile(r"^proto/"),
    re.compile(r"^ebpf/"),
    re.compile(r"^\.cargo/"),
    re.compile(r"^rust-toolchain\.toml$"),
]

# Prefixes are matched longest-first. Unknown coverage-relevant paths fail closed
# to the full shard matrix instead of guessing. Isolated admin, mesh-only, and
# protocol-only trees stay narrow when shard modules support that isolation.
# Shared runtime trees select every integration family their modules feed.
CLASSIFIABLE_PREFIXES: tuple[tuple[str, frozenset[str]], ...] = (
    ("src/modes/mesh/", MESH_SHARDS),
    ("src/config_sources/", CONFIG_SOURCES_SHARDS),
    ("src/k8s_controller/", frozenset({MESH_PLATFORM_SHARD})),
    ("src/admin/", ADMIN_SHARDS),
    ("src/config/", ALL_INTEGRATION_SHARDS),
    ("src/http3/", frozenset({PROTOCOLS_SHARD})),
    ("src/identity/", ALL_INTEGRATION_SHARDS),
    ("src/proxy/", ALL_INTEGRATION_SHARDS),
    ("src/dtls/", frozenset({PROTOCOLS_SHARD})),
    ("src/grpc/", ALL_INTEGRATION_SHARDS),
    ("src/pool/", ALL_INTEGRATION_SHARDS),
    ("src/tls/", MESH_AND_PROTOCOL_SHARDS),
    ("src/dns/", ALL_INTEGRATION_SHARDS),
    ("src/xds/", ALL_INTEGRATION_SHARDS),
)

CLASSIFIABLE_FILES: dict[str, frozenset[str]] = {
    "src/bin/ferrum-cni.rs": frozenset({MESH_PLATFORM_SHARD}),
    "src/config_delta.rs": ALL_INTEGRATION_SHARDS,
    "src/connection_pool.rs": ALL_INTEGRATION_SHARDS,
    "src/modes/control_plane.rs": ALL_INTEGRATION_SHARDS,
    "src/modes/data_plane.rs": ADMIN_AND_PROTOCOL_SHARDS,
    "src/modes/database.rs": ADMIN_AND_PROTOCOL_SHARDS,
    "src/modes/file.rs": ADMIN_AND_PROTOCOL_SHARDS,
    "src/modes/injector.rs": frozenset({MESH_PLATFORM_SHARD}),
    "src/modes/node_agent.rs": frozenset({MESH_PLATFORM_SHARD}),
    "src/modes/node_agent_cni_server.rs": frozenset({MESH_PLATFORM_SHARD}),
    "src/tls_offload.rs": frozenset({PROTOCOLS_SHARD}),
}

CORE_RELEVANT_PATTERNS = [
    re.compile(r"^src/"),
    *BUILD_GRAPH_PATTERNS,
    re.compile(r"^\.github/workflows/coverage\.yml$"),
    re.compile(r"^\.github/scripts/coverage_plan\.py$"),
    re.compile(r"^\.github/scripts/verify_coverage_workflow\.py$"),
    re.compile(r"^scripts/(check_coverage_thresholds|coverage)\.(py|sh)$"),
]


SHARD_DEFINITIONS: dict[str, dict[str, str]] = {
    LIB_UNIT_SHARD: {
        "shard": LIB_UNIT_SHARD,
        "kind": "lib-unit",
        "filters": "",
    },
    ADMIN_API_SHARD: {
        "shard": ADMIN_API_SHARD,
        "kind": "integration",
        "filters": "\n".join(
            [
                "integration::admin_api_specs_handler_tests",
                "integration::admin_db_api_specs_tests",
                "integration::admin_db_live_apply_tests",
                "integration::admin_audit_rbac_tests",
                "integration::admin_backend_capabilities_tests",
                "integration::admin_runtime_metrics_tests",
                "integration::admin_observability_auth_tests",
            ]
        ),
    },
    ADMIN_CONFIG_SHARD: {
        "shard": ADMIN_CONFIG_SHARD,
        "kind": "integration",
        "filters": "\n".join(
            [
                "integration::admin_cached_config_tests",
                "integration::admin_cross_namespace_refs_tests",
                "integration::admin_mesh_config_drift_tests",
                "integration::admin_mesh_egress_scope_tests",
                "integration::admin_mesh_policy_denies_tests",
                "integration::admin_mesh_runtime_overlay_tests",
                "integration::admin_mesh_service_graph_tests",
                "integration::admin_node_waypoint_identities_tests",
                "integration::apply_incremental_outcome_tests",
                "integration::log_schema_integration_tests",
                "integration::log_schema_registry_tests",
                "integration::gateway_error_class_observability_tests",
                "integration::deferred_log_tests",
            ]
        ),
    },
    MESH_ROUTING_SHARD: {
        "shard": MESH_ROUTING_SHARD,
        "kind": "integration",
        "filters": "\n".join(
            [
                "integration::mesh_l7_routing_tests",
                "integration::mesh_l4_weighted_routing_tests",
                "integration::mesh_topology_hbone_tests",
                "integration::mesh_authz_e2e_tests",
                "integration::mesh_authz_negative_match_tests",
                "integration::mesh_service_waypoint_tests",
                "integration::mesh_ew_egress_e2e_tests",
                "integration::mesh_destination_rule_tls_tests",
                "integration::mesh_destination_rule_locality_lb_tests",
                "integration::mesh_destination_rule_port_policy_tests",
                "integration::mesh_dr_service_entry_e2e_tests",
                "integration::mesh_sidecar_e2e_tests",
            ]
        ),
    },
    MESH_PLATFORM_SHARD: {
        "shard": MESH_PLATFORM_SHARD,
        "kind": "integration",
        "filters": "\n".join(
            [
                "integration::k8s_controller_istio_status_cas_tests",
                "integration::k8s_controller_istio_status_tests",
                "integration::k8s_controller_status_snapshot_tests",
                "integration::mesh_telemetry_k8s_provider_lookup_tests",
                "integration::mesh_telemetry_tracing_tests",
                "integration::mesh_federation_poller_tests",
                "integration::mesh_proxy_config_tests",
                "integration::mesh_outbound_registry_stream_tests",
                "integration::mesh_runtime_overlay_consumers_tests",
                "integration::mesh_peer_auth_live_reload_tests",
                "integration::mesh_k8s_pod_discovery_tests",
                "integration::mesh_hbone_tests",
                "integration::mesh_bpf_metrics_scrape_tests",
                "integration::cni_tests",
            ]
        ),
    },
    PROTOCOLS_SHARD: {
        "shard": PROTOCOLS_SHARD,
        "kind": "integration",
        "filters": "\n".join(
            [
                "integration::cp_dp_grpc_tests",
                "integration::cp_multi_namespace_tests",
                "integration::connection_pool_tests",
                "integration::http2_pool_tests",
                "integration::http3_integration_tests",
                "integration::grpc_proxy_tests",
                "integration::scripted_backend_smoke_tests",
                "integration::backend_timeout_enforcement_tests",
                "integration::dtls_integration_tests",
                "integration::udp_fault_injection_tests",
                "integration::backend_mtls_tests",
                "integration::backend_tls_san_allow_list_tests",
                "integration::frontend_tls_live_reload_tests",
                "integration::tcp_frontend_tls_order_tests",
                "integration::tcp_fast_path_l4_plugins_tests",
                "integration::gateway_hbone_pool_tests",
                "integration::gateway_svid_identity_tests",
                "integration::graceful_shutdown_tests",
                "integration::port_aware_route_traffic_tests",
                "integration::db_full_load_snapshot_tests",
                "integration::db_incremental_poll_tests",
                "integration::db_offline_bootstrap_tests",
            ]
        ),
    },
}


@dataclass(frozen=True)
class CoveragePlan:
    mode: str
    reason: str
    shards: tuple[str, ...]
    plugin_gate: bool

    @property
    def matrix_include(self) -> list[dict[str, str]]:
        # GitHub rejects an empty `matrix.include` even when the shard job is
        # skipped, so skip plans still emit a dummy lib-unit row that never runs.
        if not self.shards:
            return [dict(SHARD_DEFINITIONS[LIB_UNIT_SHARD])]
        return [dict(SHARD_DEFINITIONS[name]) for name in self.shards]


def matches_any(path: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(pattern.search(path) for pattern in patterns)


def is_path_gated_event(event_name: str) -> bool:
    """Return whether this event may skip or narrow coverage from a file list."""

    return event_name in {"pull_request", "merge_group"}


def is_plugin_path(path: str) -> bool:
    return matches_any(path, PLUGIN_PATTERNS)


def is_controller_path(path: str) -> bool:
    return path in CONTROLLER_PATHS


def is_build_graph_path(path: str) -> bool:
    return matches_any(path, BUILD_GRAPH_PATTERNS)


def is_coverage_relevant_path(path: str) -> bool:
    return is_plugin_path(path) or matches_any(path, CORE_RELEVANT_PATTERNS)


def is_well_formed_repo_path(path: str) -> bool:
    """Reject malformed or hostile path transport instead of classifying it."""

    if (
        not path
        or path != path.strip()
        or CONTROL_CHARS_RE.search(path)
        or not CLASSIFIABLE_PATH_RE.fullmatch(path)
    ):
        return False
    if "\\" in path or path.startswith("/") or "//" in path:
        return False
    posix = PurePosixPath(path)
    if posix.is_absolute():
        return False
    if any(part in {"", ".", ".."} for part in posix.parts):
        return False
    if any(":" in part for part in posix.parts):
        return False
    return str(posix) == path


def classify_path_shards(path: str) -> frozenset[str] | None:
    if path in CLASSIFIABLE_FILES:
        return CLASSIFIABLE_FILES[path]
    for prefix, shards in sorted(
        CLASSIFIABLE_PREFIXES, key=lambda item: len(item[0]), reverse=True
    ):
        if path == prefix.rstrip("/") or path.startswith(prefix):
            return shards
    return None


def ordered_shards(shards: set[str] | frozenset[str]) -> tuple[str, ...]:
    unknown = set(shards) - ALL_SHARDS
    if unknown:
        raise ValueError(f"unknown coverage shards: {sorted(unknown)}")
    return tuple(name for name in CANONICAL_SHARD_ORDER if name in shards)


def full_plan(reason: str, plugin_gate: bool = False) -> CoveragePlan:
    return CoveragePlan(
        mode="full",
        reason=reason,
        shards=CANONICAL_SHARD_ORDER,
        plugin_gate=plugin_gate,
    )


def skip_plan(reason: str) -> CoveragePlan:
    return CoveragePlan(mode="skip", reason=reason, shards=(), plugin_gate=False)


def plugin_plan(reason: str) -> CoveragePlan:
    return CoveragePlan(
        mode="plugin",
        reason=reason,
        shards=(LIB_UNIT_SHARD,),
        plugin_gate=True,
    )


def shard_plan(reason: str, shards: set[str], plugin_gate: bool) -> CoveragePlan:
    selected = set(shards)
    selected.add(LIB_UNIT_SHARD)
    ordered = ordered_shards(selected)
    if set(ordered) == ALL_SHARDS:
        return full_plan(reason, plugin_gate=plugin_gate)
    return CoveragePlan(
        mode="shards",
        reason=reason,
        shards=ordered,
        plugin_gate=plugin_gate,
    )


def select_plan(event_name: str, changed_files: list[str]) -> CoveragePlan:
    if not is_path_gated_event(event_name):
        return full_plan(f"full coverage is required for {event_name}")

    if not changed_files:
        return full_plan(
            "no changed files were detected; defaulting to full coverage"
        )

    if any(not is_well_formed_repo_path(path) for path in changed_files):
        return full_plan(
            "malformed or hostile changed-path transport; defaulting to full coverage"
        )

    if any(is_controller_path(path) for path in changed_files):
        return full_plan("coverage controller files changed")

    if any(is_build_graph_path(path) for path in changed_files):
        return full_plan("dependency or build-graph inputs changed")

    plugin_files = [path for path in changed_files if is_plugin_path(path)]
    classified: set[str] = set()
    unknown_relevant: list[str] = []

    for path in changed_files:
        if is_plugin_path(path) or is_controller_path(path) or is_build_graph_path(path):
            continue
        shards = classify_path_shards(path)
        if shards is not None:
            classified.update(shards)
            continue
        if is_coverage_relevant_path(path):
            unknown_relevant.append(path)

    if unknown_relevant:
        return full_plan("core coverage-relevant files changed")

    if classified:
        return shard_plan(
            "classifiable coverage-relevant files changed",
            classified,
            plugin_gate=bool(plugin_files),
        )

    if plugin_files:
        return plugin_plan("plugin coverage-relevant files changed")

    return skip_plan("no coverage-relevant files changed")


def select_mode(event_name: str, changed_files: list[str]) -> tuple[str, str]:
    plan = select_plan(event_name, changed_files)
    return plan.mode, plan.reason


def read_changed_files(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def parse_planned_shards(raw: str) -> list[str]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"planned shards are not valid JSON: {error}") from error
    if not isinstance(parsed, list) or not parsed:
        raise ValueError("planned shards must be a non-empty JSON array")
    shards: list[str] = []
    for item in parsed:
        if not isinstance(item, str) or not SHARD_NAME_RE.fullmatch(item):
            raise ValueError(f"invalid planned shard name: {item!r}")
        if item not in ALL_SHARDS:
            raise ValueError(f"unknown planned shard: {item}")
        if item in shards:
            raise ValueError(f"duplicate planned shard: {item}")
        shards.append(item)
    if shards != list(ordered_shards(set(shards))):
        raise ValueError("planned shards must be in canonical coverage order")
    if LIB_UNIT_SHARD not in shards:
        raise ValueError("planned shards must include lib-unit")
    return shards


def artifact_names_for_shards(shards: list[str]) -> list[str]:
    return [f"coverage-data-{shard}" for shard in shards]


def verify_downloaded_artifacts(
    planned_shards: list[str], artifact_names: list[str]
) -> None:
    expected = artifact_names_for_shards(planned_shards)
    actual = [name for name in artifact_names if name]
    if actual != expected:
        raise ValueError(
            "downloaded coverage artifacts must match the planned shard list "
            f"exactly; expected {expected}, found {actual}"
        )


def write_github_output(path: Path, plan: CoveragePlan) -> None:
    matrix = json.dumps(plan.matrix_include, separators=(",", ":"))
    shards = json.dumps(list(plan.shards), separators=(",", ":"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"mode={plan.mode}\n")
        handle.write(f"reason={plan.reason}\n")
        handle.write(f"shards={shards}\n")
        handle.write(f"plugin_gate={'true' if plan.plugin_gate else 'false'}\n")
        handle.write("shard-matrix<<COVERAGE_MATRIX_EOF\n")
        handle.write(f"{matrix}\n")
        handle.write("COVERAGE_MATRIX_EOF\n")


def _expect_plan(
    event_name: str,
    changed: list[str],
    mode: str,
    shards: tuple[str, ...],
    plugin_gate: bool | None = None,
) -> str | None:
    plan = select_plan(event_name, changed)
    if plan.mode != mode:
        return f"{event_name} {changed!r}: expected mode {mode}, selected {plan.mode}"
    if plan.shards != shards:
        return (
            f"{event_name} {changed!r}: expected shards {shards}, selected {plan.shards}"
        )
    if plugin_gate is not None and plan.plugin_gate != plugin_gate:
        return (
            f"{event_name} {changed!r}: expected plugin_gate={plugin_gate}, "
            f"selected {plan.plugin_gate}"
        )
    if mode != "skip" and LIB_UNIT_SHARD not in plan.shards:
        return f"{event_name} {changed!r}: non-skip plan omitted lib-unit"
    if set(plan.shards) - ALL_SHARDS:
        return f"{event_name} {changed!r}: plan selected unknown shards"
    return None


def self_test() -> int:
    all_shards = CANONICAL_SHARD_ORDER
    lib_unit = (LIB_UNIT_SHARD,)
    admin = ordered_shards({LIB_UNIT_SHARD, *ADMIN_SHARDS})
    mesh = ordered_shards({LIB_UNIT_SHARD, *MESH_SHARDS})
    protocol = ordered_shards({LIB_UNIT_SHARD, PROTOCOLS_SHARD})
    admin_and_protocol = ordered_shards({LIB_UNIT_SHARD, *ADMIN_AND_PROTOCOL_SHARDS})
    mesh_and_protocol = ordered_shards({LIB_UNIT_SHARD, *MESH_AND_PROTOCOL_SHARDS})
    config_sources = ordered_shards({LIB_UNIT_SHARD, *CONFIG_SOURCES_SHARDS})
    mesh_platform = ordered_shards({LIB_UNIT_SHARD, MESH_PLATFORM_SHARD})

    # Exact ownership lock for every classifiable shared/isolated representative.
    # Equality prevents a later edit from silently narrowing (or widening) a mapping.
    ownership_lock: tuple[tuple[str, frozenset[str]], ...] = (
        ("src/admin/mod.rs", ADMIN_SHARDS),
        ("src/admin/api_specs/handlers.rs", ADMIN_SHARDS),
        ("src/config/env_config.rs", ALL_INTEGRATION_SHARDS),
        ("src/config/types.rs", ALL_INTEGRATION_SHARDS),
        ("src/config/db_loader.rs", ALL_INTEGRATION_SHARDS),
        ("src/config/file_loader.rs", ALL_INTEGRATION_SHARDS),
        ("src/config_delta.rs", ALL_INTEGRATION_SHARDS),
        ("src/config_sources/k8s/core.rs", CONFIG_SOURCES_SHARDS),
        ("src/identity/mod.rs", ALL_INTEGRATION_SHARDS),
        ("src/identity/spiffe/mod.rs", ALL_INTEGRATION_SHARDS),
        ("src/tls/mod.rs", MESH_AND_PROTOCOL_SHARDS),
        ("src/tls_offload.rs", frozenset({PROTOCOLS_SHARD})),
        ("src/dns/mod.rs", ALL_INTEGRATION_SHARDS),
        ("src/grpc/cp_server.rs", ALL_INTEGRATION_SHARDS),
        ("src/grpc/mesh_server.rs", ALL_INTEGRATION_SHARDS),
        ("src/pool/mod.rs", ALL_INTEGRATION_SHARDS),
        ("src/connection_pool.rs", ALL_INTEGRATION_SHARDS),
        ("src/proxy/mod.rs", ALL_INTEGRATION_SHARDS),
        ("src/http3/server.rs", frozenset({PROTOCOLS_SHARD})),
        ("src/dtls/mod.rs", frozenset({PROTOCOLS_SHARD})),
        ("src/xds/mod.rs", ALL_INTEGRATION_SHARDS),
        ("src/modes/mesh/config.rs", MESH_SHARDS),
        ("src/modes/control_plane.rs", ALL_INTEGRATION_SHARDS),
        ("src/modes/data_plane.rs", ADMIN_AND_PROTOCOL_SHARDS),
        ("src/modes/database.rs", ADMIN_AND_PROTOCOL_SHARDS),
        ("src/modes/file.rs", ADMIN_AND_PROTOCOL_SHARDS),
        ("src/modes/injector.rs", frozenset({MESH_PLATFORM_SHARD})),
        ("src/modes/node_agent.rs", frozenset({MESH_PLATFORM_SHARD})),
        ("src/modes/node_agent_cni_server.rs", frozenset({MESH_PLATFORM_SHARD})),
        ("src/k8s_controller/status.rs", frozenset({MESH_PLATFORM_SHARD})),
        ("src/bin/ferrum-cni.rs", frozenset({MESH_PLATFORM_SHARD})),
    )

    cases: list[tuple[str, list[str], str, tuple[str, ...], bool | None]] = [
        ("pull_request", ["src/admin/mod.rs"], "shards", admin, False),
        ("pull_request", ["src/admin/api_specs/handlers.rs"], "shards", admin, False),
        ("pull_request", ["src/config/env_config.rs"], "full", all_shards, False),
        ("pull_request", ["src/config/types.rs"], "full", all_shards, False),
        ("pull_request", ["src/config_delta.rs"], "full", all_shards, False),
        ("pull_request", ["src/config_sources/k8s/core.rs"], "shards", config_sources, False),
        ("pull_request", ["src/identity/mod.rs"], "full", all_shards, False),
        ("pull_request", ["src/tls/mod.rs"], "shards", mesh_and_protocol, False),
        ("pull_request", ["src/dns/mod.rs"], "full", all_shards, False),
        ("pull_request", ["src/grpc/cp_server.rs"], "full", all_shards, False),
        ("pull_request", ["src/pool/mod.rs"], "full", all_shards, False),
        ("pull_request", ["src/connection_pool.rs"], "full", all_shards, False),
        ("pull_request", ["src/proxy/mod.rs"], "full", all_shards, False),
        ("pull_request", ["src/xds/mod.rs"], "full", all_shards, False),
        ("pull_request", ["src/modes/control_plane.rs"], "full", all_shards, False),
        ("pull_request", ["src/modes/data_plane.rs"], "shards", admin_and_protocol, False),
        ("pull_request", ["src/modes/database.rs"], "shards", admin_and_protocol, False),
        ("pull_request", ["src/modes/file.rs"], "shards", admin_and_protocol, False),
        ("pull_request", ["src/modes/mesh/config.rs"], "shards", mesh, False),
        ("pull_request", ["src/k8s_controller/status.rs"], "shards", mesh_platform, False),
        ("pull_request", ["src/http3/server.rs"], "shards", protocol, False),
        ("pull_request", ["src/dtls/mod.rs"], "shards", protocol, False),
        ("pull_request", ["src/tls_offload.rs"], "shards", protocol, False),
        ("pull_request", ["src/plugins/cors.rs"], "plugin", lib_unit, True),
        ("pull_request", ["src/plugin_cache.rs"], "plugin", lib_unit, True),
        ("pull_request", ["tests/unit/plugins/cors_tests.rs"], "plugin", lib_unit, True),
        (
            "pull_request",
            ["src/plugins/cors.rs", "src/admin/mod.rs"],
            "shards",
            admin,
            True,
        ),
        (
            "pull_request",
            ["src/plugins/cors.rs", "src/proxy/http.rs"],
            "full",
            all_shards,
            True,
        ),
        (
            "pull_request",
            ["src/admin/mod.rs", "src/modes/mesh/config.rs"],
            "shards",
            ordered_shards({LIB_UNIT_SHARD, *ADMIN_SHARDS, *MESH_SHARDS}),
            False,
        ),
        (
            "pull_request",
            ["src/admin/mod.rs", "src/modes/mesh/config.rs", "src/http3/server.rs"],
            "full",
            all_shards,
            False,
        ),
        ("pull_request", ["src/cli.rs"], "full", all_shards, False),
        ("pull_request", ["src/main.rs"], "full", all_shards, False),
        ("pull_request", ["src/overload.rs"], "full", all_shards, False),
        ("pull_request", ["src/lib.rs"], "full", all_shards, False),
        ("pull_request", ["Cargo.toml"], "full", all_shards, False),
        ("pull_request", ["Cargo.lock"], "full", all_shards, False),
        ("pull_request", ["build.rs"], "full", all_shards, False),
        ("pull_request", ["proto/ferrum.proto"], "full", all_shards, False),
        ("pull_request", ["ebpf/src/main.rs"], "full", all_shards, False),
        ("pull_request", [".cargo/config.toml"], "full", all_shards, False),
        ("pull_request", ["rust-toolchain.toml"], "full", all_shards, False),
        ("pull_request", [".github/workflows/coverage.yml"], "full", all_shards, False),
        ("pull_request", [".github/scripts/coverage_plan.py"], "full", all_shards, False),
        (
            "pull_request",
            [".github/scripts/verify_coverage_workflow.py"],
            "full",
            all_shards,
            False,
        ),
        ("pull_request", ["scripts/coverage.sh"], "full", all_shards, False),
        (
            "pull_request",
            ["scripts/check_coverage_thresholds.py"],
            "full",
            all_shards,
            False,
        ),
        ("pull_request", ["docs/configuration.md"], "skip", (), False),
        ("pull_request", ["README.md"], "skip", (), False),
        ("pull_request", [], "full", all_shards, False),
        ("merge_group", ["src/admin/mod.rs"], "shards", admin, False),
        ("merge_group", ["src/config/mod.rs"], "full", all_shards, False),
        ("merge_group", ["src/proxy/mod.rs"], "full", all_shards, False),
        ("merge_group", ["src/modes/mesh/mod.rs"], "shards", mesh, False),
        ("merge_group", ["src/http3/mod.rs"], "shards", protocol, False),
        ("merge_group", ["src/plugins/cors.rs"], "plugin", lib_unit, True),
        ("merge_group", ["src/cli.rs"], "full", all_shards, False),
        ("merge_group", ["docs/configuration.md"], "skip", (), False),
        ("merge_group", [], "full", all_shards, False),
        ("push", [], "full", all_shards, False),
        ("push", ["src/admin/mod.rs"], "full", all_shards, False),
        ("push", ["docs/configuration.md"], "full", all_shards, False),
        ("workflow_dispatch", [], "full", all_shards, False),
        ("workflow_dispatch", ["src/plugins/cors.rs"], "full", all_shards, False),
        ("schedule", [], "full", all_shards, False),
        ("schedule", ["docs/coverage.md"], "full", all_shards, False),
        ("pull_request", ["src/admin/../../Cargo.toml"], "full", all_shards, False),
        ("pull_request", ["./src/admin/mod.rs"], "full", all_shards, False),
        ("pull_request", ["src\\admin\\mod.rs"], "full", all_shards, False),
        ("pull_request", ["/src/admin/mod.rs"], "full", all_shards, False),
        ("pull_request", ["C:/src/admin/mod.rs"], "full", all_shards, False),
        ("pull_request", ["src//admin/mod.rs"], "full", all_shards, False),
        ("pull_request", [" src/admin/mod.rs"], "full", all_shards, False),
        ("pull_request", ["src/admin/mod.rs "], "full", all_shards, False),
        ("pull_request", ["src/admin/foo\0.rs"], "full", all_shards, False),
        ("pull_request", ["src/admin/`spoof`.rs"], "full", all_shards, False),
        ("pull_request", ["src/admin/summary|row.rs"], "full", all_shards, False),
        ("pull_request", ["src/admin/del\x7f.rs"], "full", all_shards, False),
        ("pull_request", ["../Cargo.toml"], "full", all_shards, False),
        (
            "pull_request",
            ["src/admin/mod.rs", "src/admin/../cli.rs"],
            "full",
            all_shards,
            False,
        ),
    ]

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        changed_path = Path(temp_dir) / "changed-files.txt"
        changed_path.write_text(
            " src/admin/mod.rs\nsrc/admin/mod.rs \n", encoding="utf-8"
        )
        if read_changed_files(changed_path) != [
            " src/admin/mod.rs",
            "src/admin/mod.rs ",
        ]:
            failures.append(
                "changed-file transport must preserve boundary whitespace for fail-closed validation"
            )
    for event_name, changed, mode, shards, plugin_gate in cases:
        failure = _expect_plan(event_name, changed, mode, shards, plugin_gate)
        if failure:
            failures.append(failure)

    for path, expected in ownership_lock:
        classified = classify_path_shards(path)
        if classified != expected:
            failures.append(
                f"{path}: ownership lock expected {sorted(expected)}, "
                f"classified {sorted(classified or [])}"
            )
            continue
        plan = select_plan("pull_request", [path])
        if LIB_UNIT_SHARD not in plan.shards:
            failures.append(f"{path}: non-skip ownership plan omitted lib-unit")
        if set(plan.shards) - {LIB_UNIT_SHARD} != set(expected):
            failures.append(
                f"{path}: plan shards {plan.shards} drifted from ownership lock"
            )
        expected_mode = "full" if expected == ALL_INTEGRATION_SHARDS else "shards"
        if plan.mode != expected_mode:
            failures.append(
                f"{path}: expected mode {expected_mode}, selected {plan.mode}"
            )

    locked_prefixes: set[str] = set()
    locked_files: set[str] = set()
    for path, _expected in ownership_lock:
        if path in CLASSIFIABLE_FILES:
            locked_files.add(path)
            continue
        for prefix, _shards in CLASSIFIABLE_PREFIXES:
            if path == prefix.rstrip("/") or path.startswith(prefix):
                locked_prefixes.add(prefix)
                break
        else:
            failures.append(f"{path}: ownership lock path is not classifiable")
    for prefix, _shards in CLASSIFIABLE_PREFIXES:
        if prefix not in locked_prefixes:
            failures.append(
                f"classifiable prefix {prefix} has no ownership-lock representative"
            )
    for path in CLASSIFIABLE_FILES:
        if path not in locked_files:
            failures.append(
                f"classifiable file {path} has no ownership-lock representative"
            )

    admin_plan = select_plan("pull_request", ["src/admin/mod.rs"])
    if PROTOCOLS_SHARD in admin_plan.shards or MESH_ROUTING_SHARD in admin_plan.shards:
        failures.append("admin diffs must not select protocol or mesh-routing shards")
    if ADMIN_API_SHARD not in admin_plan.shards or ADMIN_CONFIG_SHARD not in admin_plan.shards:
        failures.append("admin diffs must select both admin-bearing integration shards")

    config_plan = select_plan("pull_request", ["src/config/env_config.rs"])
    if config_plan.mode != "full" or config_plan.shards != all_shards:
        failures.append("config diffs must select the full shard matrix")
    if ADMIN_API_SHARD not in config_plan.shards or ADMIN_CONFIG_SHARD not in config_plan.shards:
        failures.append("config diffs must keep both admin-bearing integration shards")
    if not MESH_SHARDS.issubset(config_plan.shards):
        failures.append("config diffs must keep both mesh shards")
    if PROTOCOLS_SHARD not in config_plan.shards:
        failures.append("config diffs must keep the protocol shard")

    identity_plan = select_plan("pull_request", ["src/identity/mod.rs"])
    if identity_plan.mode != "full" or identity_plan.shards != all_shards:
        failures.append("identity diffs must select the full shard matrix")

    tls_plan = select_plan("pull_request", ["src/tls/mod.rs"])
    if not MESH_SHARDS.issubset(tls_plan.shards) or PROTOCOLS_SHARD not in tls_plan.shards:
        failures.append("tls diffs must select mesh and protocol shards")
    if any(shard in tls_plan.shards for shard in ADMIN_SHARDS):
        failures.append("tls diffs must not select admin shards")

    dns_plan = select_plan("pull_request", ["src/dns/mod.rs"])
    if dns_plan.mode != "full" or dns_plan.shards != all_shards:
        failures.append("dns diffs must select the full shard matrix")

    grpc_plan = select_plan("pull_request", ["src/grpc/cp_server.rs"])
    if grpc_plan.mode != "full" or grpc_plan.shards != all_shards:
        failures.append("grpc diffs must select the full shard matrix")

    pool_plan = select_plan("pull_request", ["src/pool/mod.rs"])
    if pool_plan.mode != "full" or pool_plan.shards != all_shards:
        failures.append("pool diffs must select the full shard matrix")

    connection_pool_plan = select_plan("pull_request", ["src/connection_pool.rs"])
    if connection_pool_plan.mode != "full" or connection_pool_plan.shards != all_shards:
        failures.append("connection_pool diffs must select the full shard matrix")

    proxy_plan = select_plan("pull_request", ["src/proxy/mod.rs"])
    if proxy_plan.mode != "full" or proxy_plan.shards != all_shards:
        failures.append("proxy diffs must select the full shard matrix")

    xds_plan = select_plan("pull_request", ["src/xds/mod.rs"])
    if xds_plan.mode != "full" or xds_plan.shards != all_shards:
        failures.append("xds diffs must select the full shard matrix")

    control_plane_plan = select_plan("pull_request", ["src/modes/control_plane.rs"])
    if control_plane_plan.mode != "full" or control_plane_plan.shards != all_shards:
        failures.append("control_plane diffs must select the full shard matrix")

    for mode_path in (
        "src/modes/data_plane.rs",
        "src/modes/database.rs",
        "src/modes/file.rs",
    ):
        serving_plan = select_plan("pull_request", [mode_path])
        if set(serving_plan.shards) != set(admin_and_protocol):
            failures.append(
                f"{mode_path} diffs must select admin and protocol shards"
            )
        if any(shard in serving_plan.shards for shard in MESH_SHARDS):
            failures.append(f"{mode_path} diffs must not select mesh shards")

    config_sources_plan = select_plan(
        "pull_request", ["src/config_sources/k8s/core.rs"]
    )
    if ADMIN_CONFIG_SHARD not in config_sources_plan.shards:
        failures.append("config_sources diffs must keep the admin-config shard")
    if not MESH_SHARDS.issubset(config_sources_plan.shards):
        failures.append("config_sources diffs must keep both mesh shards")
    if ADMIN_API_SHARD in config_sources_plan.shards or PROTOCOLS_SHARD in config_sources_plan.shards:
        failures.append("config_sources diffs must not select admin-api or protocol shards")

    mesh_plan = select_plan("pull_request", ["src/modes/mesh/config.rs"])
    if any(shard in mesh_plan.shards for shard in ADMIN_SHARDS):
        failures.append("mesh diffs must not select admin shards")
    if PROTOCOLS_SHARD in mesh_plan.shards:
        failures.append("mesh diffs must not select the protocol shard")

    protocol_plan = select_plan("pull_request", ["src/http3/server.rs"])
    if any(shard in protocol_plan.shards for shard in ADMIN_SHARDS | MESH_SHARDS):
        failures.append("protocol diffs must not select admin or mesh shards")

    plugin_only = select_plan("pull_request", ["src/plugins/cors.rs"])
    if plugin_only.shards != lib_unit or plugin_only.mode != "plugin":
        failures.append("plugin-only diffs must stay on plugin mode with lib-unit only")

    mixed = select_plan("pull_request", ["src/plugins/cors.rs", "src/proxy/http.rs"])
    if mixed.mode == "plugin":
        failures.append("mixed plugin and core diffs must not stay in plugin mode")
    if mixed.mode != "full" or mixed.shards != all_shards:
        failures.append("mixed plugin and proxy diffs must select the full shard matrix")
    if not mixed.plugin_gate:
        failures.append("mixed plugin and core diffs must keep the plugin gate")
    if LIB_UNIT_SHARD not in mixed.shards:
        failures.append("mixed plugin and core diffs must still run lib-unit")

    if SHARD_DEFINITIONS.keys() != ALL_SHARDS:
        failures.append("SHARD_DEFINITIONS must cover every canonical shard")
    if SHARD_DEFINITIONS[LIB_UNIT_SHARD]["kind"] != "lib-unit":
        failures.append("lib-unit shard kind must remain lib-unit")
    for name in ALL_INTEGRATION_SHARDS:
        if SHARD_DEFINITIONS[name]["kind"] != "integration":
            failures.append(f"{name} shard kind must remain integration")
        if "integration::" not in SHARD_DEFINITIONS[name]["filters"]:
            failures.append(f"{name} shard is missing integration filters")

    try:
        parse_planned_shards(json.dumps([LIB_UNIT_SHARD, ADMIN_API_SHARD]))
    except ValueError as error:
        failures.append(f"valid planned shards were rejected: {error}")

    for raw, label in (
        ("[]", "empty planned shards"),
        (json.dumps([ADMIN_API_SHARD]), "missing lib-unit"),
        (json.dumps([ADMIN_API_SHARD, LIB_UNIT_SHARD]), "out of order shards"),
        (json.dumps([LIB_UNIT_SHARD, "not-a-shard"]), "unknown shard"),
        (json.dumps([LIB_UNIT_SHARD, LIB_UNIT_SHARD]), "duplicate shard"),
        (json.dumps([LIB_UNIT_SHARD, "admin-api; rm -rf"]), "hostile shard name"),
        ("{", "malformed JSON"),
        ("null", "non-array JSON"),
    ):
        try:
            parse_planned_shards(raw)
        except ValueError:
            pass
        else:
            failures.append(f"{label} were accepted")

    try:
        verify_downloaded_artifacts(
            [LIB_UNIT_SHARD, ADMIN_API_SHARD],
            ["coverage-data-lib-unit", "coverage-data-admin-api"],
        )
    except ValueError as error:
        failures.append(f"matching artifacts were rejected: {error}")

    try:
        verify_downloaded_artifacts(
            [LIB_UNIT_SHARD],
            ["coverage-data-lib-unit", "coverage-data-admin-api"],
        )
    except ValueError:
        pass
    else:
        failures.append("extra downloaded artifacts were accepted")

    try:
        verify_downloaded_artifacts([LIB_UNIT_SHARD, ADMIN_API_SHARD], ["coverage-data-lib-unit"])
    except ValueError:
        pass
    else:
        failures.append("missing planned artifacts were accepted")

    skip = skip_plan("no coverage-relevant files changed")
    if skip.shards:
        failures.append("skip plans must not select coverage shards")
    if skip.matrix_include != [SHARD_DEFINITIONS[LIB_UNIT_SHARD]]:
        failures.append("skip plans must emit a dummy lib-unit matrix row")

    plugin = plugin_plan("plugin coverage-relevant files changed")
    if plugin.matrix_include != [SHARD_DEFINITIONS[LIB_UNIT_SHARD]]:
        failures.append("plugin plans must emit only the lib-unit matrix entry")

    full = full_plan("full coverage is required for push")
    if [entry["shard"] for entry in full.matrix_include] != list(CANONICAL_SHARD_ORDER):
        failures.append("full plans must emit every canonical shard")

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name")
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--verify-artifacts", action="store_true")
    parser.add_argument("--emit-artifact-names", action="store_true")
    parser.add_argument("--planned-shards")
    parser.add_argument("--artifact-names", type=Path)
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if args.verify_artifacts or args.emit_artifact_names:
        if not args.planned_shards:
            parser.error("--planned-shards is required for artifact verification")
        try:
            shards = parse_planned_shards(args.planned_shards)
        except ValueError as error:
            print(f"::error::{error}", file=sys.stderr)
            return 1
        names = artifact_names_for_shards(shards)
        if args.emit_artifact_names:
            sys.stdout.write("\n".join(names) + "\n")
        if args.verify_artifacts:
            if args.artifact_names is None:
                parser.error("--artifact-names is required with --verify-artifacts")
            downloaded = [
                line.strip()
                for line in args.artifact_names.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            try:
                verify_downloaded_artifacts(shards, downloaded)
            except ValueError as error:
                print(f"::error::{error}", file=sys.stderr)
                return 1
        return 0

    if not args.event_name:
        parser.error("--event-name is required unless --self-test is used")

    changed_files = read_changed_files(args.changed_files)
    plan = select_plan(args.event_name, changed_files)
    if args.github_output is not None:
        write_github_output(args.github_output, plan)
    print(f"mode={plan.mode}")
    print(f"reason={plan.reason}")
    print(f"shards={json.dumps(list(plan.shards), separators=(',', ':'))}")
    print(f"plugin_gate={'true' if plan.plugin_gate else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
