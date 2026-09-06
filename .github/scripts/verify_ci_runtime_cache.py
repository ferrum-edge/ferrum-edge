#!/usr/bin/env python3
"""Static contract checks for production-image, FIPS, and Ambient CI caching.

Does not compile Rust or build images. Proves workflow permission/caching
boundaries, pinned actions, fail-closed NUL-delimited planning, preserved live
contracts, telemetry redaction, evidence-backed cache restore bytes, schema-
and architecture-scoped BuildKit keys, exact-hit restore-only vs partial/miss
publish, fail-closed cache-save preparation, fork restore-only / no-save
steps, rust-cache save-if so fork PRs cannot save (and, for the shared
setup-rust-ci action, so only trusted refs/heads/main runs save at all),
the FIPS producer handoff as an immutable run artifact rather than an
eviction-prone repository cache (attempt-wildcard consumer promotion with
stable fallback isolation), rejection
of ignored rust-cache `key` wiring, checksum-pinned sccache install without
credential-exporting installers, a closed FIPS action-invocation allowlist
with exact occurrence counts and checkout provenance (current repository,
default ref, default root, persist-credentials: false) plus shell-only
local actions so JavaScript toolkit carriers cannot reach
the cache-credential environment, same-run producer and immutable inter-run
artifact handoff warming, exact verified executable activation, performance
rust-cache key isolation from runner-unique wrapper paths, empty
SCCACHE_GHA_ENABLED persistence, fail-closed uncached fallback, hosted
cache-token absence assertions, and Ambient production-image GHA cache-to
gated to trusted `refs/heads/main` so pull requests restore without publishing.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

from ci_runtime_plan import (
    SUITE_PATTERNS,
    decide_relevance,
    self_test as plan_self_test,
)
from ci_runtime_telemetry import self_test as telemetry_self_test


REPO_ROOT = Path(__file__).resolve().parents[2]
FIPS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "fips-build.yml"
FIPS_PLANNER_PATH = ".github/scripts/ci_runtime_plan.py"
NODE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "node-waypoint-ebpf-live.yml"
AMBIENT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ambient-host-udp-live.yml"
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERFILE_RELEASE = REPO_ROOT / "Dockerfile.release"
DOCKERFILE_EBPF_TOOLS_LAYER = REPO_ROOT / "Dockerfile.ebpf-tools-layer"
DOCKERFILE_TEST = REPO_ROOT / "Dockerfile.test"
SETUP_RUST = REPO_ROOT / ".github" / "actions" / "setup-rust-ci" / "action.yml"
SETUP_SCCACHE = REPO_ROOT / ".github" / "actions" / "setup-sccache" / "action.yml"
SETUP_FAST_LINKER = REPO_ROOT / ".github" / "actions" / "setup-fast-linker" / "action.yml"
CI_CD_DOC = REPO_ROOT / "docs" / "ci_cd.md"
FIPS_DOC = REPO_ROOT / "docs" / "fips.md"
COVERAGE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "coverage.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# Only the PR-editable direct sites; frozen composites/FIPS/fuzz/perf retain
# their separately governed contracts. True means compiler-cache-only reuse.
DIRECT_CACHE_DIET_JOBS = (
    ("ci.yml", "build-binaries", False),
    ("ci.yml", "build-ebpf", False),
    ("perf-benchmark.yml", "benchmark", False),
    ("payload-size-benchmark.yml", "benchmark", False),
    ("scale-benchmark.yml", "scale-benchmark", False),
    ("comparison-benchmark.yml", "comparison", True),
    ("connection-saturation-benchmark.yml", "saturation", True),
    ("gateways-protocol-benchmark.yml", "benchmark", True),
)

CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
RUST_TOOLCHAIN = "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8"
RUST_CACHE = "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6"
BUILDX = "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e"
BUILD_PUSH = "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a"
CACHE_RESTORE = "actions/cache/restore@374a27f26986edd8c430f386d152a856e179c0ae"
CACHE_SAVE = "actions/cache/save@374a27f26986edd8c430f386d152a856e179c0ae"
UPLOAD_ARTIFACT = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_ARTIFACT = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
FIPS_CONTRACT_HASHFILES = (
    "hashFiles('Cargo.toml', 'Cargo.lock', '.cargo/config.toml', 'build.rs', "
    "'.github/workflows/fips-build.yml', "
    "'.github/scripts/check_fips_feature_policy.py', "
    "'src/fips/**', 'vendor/**')"
)
FIPS_SHARED_KEY = "ci-fips-contract-${{ " + FIPS_CONTRACT_HASHFILES + " }}"
FIPS_HANDOFF_ARTIFACT_EXPR = (
    "fips-producer-handoff-${{ github.event.pull_request.head.sha || github.sha }}-"
    "${{ github.run_id }}-"
    "${{ github.run_attempt }}"
)
FIPS_HANDOFF_PREFIX_EXPR = (
    "fips-producer-handoff-${{ github.event.pull_request.head.sha || github.sha }}-"
    "${{ github.run_id }}-"
)
FIPS_HANDOFF_SOURCE_EXPR = (
    "fips-producer-handoff-${{ github.event.pull_request.head.sha || github.sha }}-"
    "${{ inputs.warm_source_run_id }}-${{ inputs.warm_source_run_attempt }}"
)
SCCACHE_EXPORTERS = ("mozilla-actions/sccache-action",)
# Defense in depth only. Computed JavaScript (`core["export" + "Variable"]`)
# does not contain this contiguous token; the closed FIPS uses allowlist and
# shell-only local-action rule are the fail-closed gate.
SCCACHE_EXPORT_VARIABLE_TOKEN = "exportVariable"
# Exact pins/paths admitted in fips-build.yml, frozen with occurrence counts
# from the checked workflow. Set membership is not enough: duplicating an
# already-allowlisted JavaScript action must fail. JavaScript/docker/
# reusable-workflow carriers cannot enter without an allowlist change.
# actions/cache/save and actions/cache/restore are excluded: the FIPS
# producer/test handoff is an immutable artifact, not a repository cache.
FIPS_ALLOWED_ACTION_COUNTS = {
    CHECKOUT: 7,
    RUST_TOOLCHAIN: 5,
    "./.github/actions/setup-sccache": 4,
    "./.github/actions/setup-fast-linker": 4,
    RUST_CACHE: 4,
    DOWNLOAD_ARTIFACT: 5,
    UPLOAD_ARTIFACT: 2,
}
FIPS_ALLOWED_ACTION_USES = frozenset(FIPS_ALLOWED_ACTION_COUNTS)
FIPS_CHECKOUT_COUNT = FIPS_ALLOWED_ACTION_COUNTS[CHECKOUT]
# Closed checkout `with:` contract: current repo, default ref, default root.
CHECKOUT_ALLOWED_WITH_KEYS = frozenset({"persist-credentials", "fetch-depth"})
CHECKOUT_REDIRECT_KEYS = frozenset({"repository", "ref", "path"})
SHELL_ONLY_COMPOSITE = "composite"
YAML_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
YAML_DOUBLE_QUOTED_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": chr(0x2028),
    "P": chr(0x2029),
}
# `<<` is a YAML merge key, not an identifier. Keep it in the key token so
# block/flow merge spellings are parsed and rejected rather than skipped.
YAML_KEY_TOKEN = r"'(?:[^']|'')*'|\"(?:[^\"\\]|\\.)*\"|<<|[A-Za-z0-9_.+-]+"
YAML_MAPPING_LINE = re.compile(
    rf"^(?P<lead>[ \t]*)(?P<dash>-[ \t]+)?(?P<key>{YAML_KEY_TOKEN})[ \t]*:(?P<value>.*)$"
)
YAML_FLOW_STEP = re.compile(r"^(?P<lead>[ \t]*)-[ \t]+(?P<flow>[\{\[].*)$")
# YAML permits the chomping and indentation indicators in either order
# (`|-2` and `|2-`). A valid indentation indicator is one digit from 1-9.
YAML_BLOCK_SCALAR = re.compile(
    r"^[|>](?:[+-](?:[1-9])?|[1-9][+-]?)?(?:[ \t]+(?:#.*)?)?$"
)
YAML_EXPLICIT_KEY = re.compile(r"^[ \t]*(?:-[ \t]+)?\?")
YAML_SEQUENCE_ITEM = re.compile(r"^[ \t]*-[ \t]+(?P<item>.+)$")
YAML_DOCUMENT_MARK = frozenset({"---", "..."})
JS_ACTION_USING = re.compile(r"^node(?:\d+)?$", re.IGNORECASE)
SCCACHE_PINNED_VERSION = "0.17.0"
SCCACHE_RELEASE_DOWNLOAD = "https://github.com/mozilla/sccache/releases/download/"
CREDENTIAL_ASSERT_VARS = (
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RESULTS_URL",
)
BUILDKIT_CACHE_SCHEMA = "v1"
CACHE_KIND_EXACT = "steps.cache-kind.outputs.kind == 'exact'"
CACHE_KIND_PUBLISH = "steps.cache-kind.outputs.publish == 'true'"
NUL_DIFF = 'git diff --name-only --no-renames -z "${trusted_sha}...HEAD"'
LINE_DIFF = 'git diff --name-only --no-renames "${trusted_sha}...HEAD"'
NODE_WAYPOINT_PLANNER_OUTPUT = (
    "needs.production-dockerfile-plan.outputs.node_waypoint_relevant"
)
NODE_WAYPOINT_LIVE_IF = (
    "${{ !cancelled() && "
    "needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false' }}"
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(
    r"^\s*(?:-\s*)?uses:\s*(?P<ref>\S+)",
    re.MULTILINE,
)
PINNED_REMOTE = re.compile(
    r"^(?P<name>(?!\./)[^@\s]+)@(?P<pin>[0-9a-f]{40})$"
)


def extract_pull_request_paths(workflow: str) -> list[str]:
    match = re.search(
        r"(?ms)^  pull_request:\n    paths:\n(?P<paths>(?:      - .+\n)+)",
        workflow,
    )
    if match is None:
        return []
    paths: list[str] = []
    for line in match.group("paths").splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            paths.append(stripped[2:].strip().strip('"').strip("'"))
    return paths


def extract_on_block(workflow: str) -> str:
    """Return the body of the single top-level `on:` mapping, or "".

    Scoped rather than whole-file so a `paths:` key nested inside a job step
    (or a second `on:`-looking line) cannot be mistaken for a trigger filter,
    and so a workflow with a duplicated `on:` fails closed.
    """

    lines = workflow.splitlines(keepends=True)
    headers = [index for index, line in enumerate(lines) if line.rstrip("\r\n") == "on:"]
    if len(headers) != 1:
        return ""
    start = headers[0]
    end = next(
        (
            index
            for index in range(start + 1, len(lines))
            if re.match(r"^[A-Za-z0-9_-]+:", lines[index])
        ),
        len(lines),
    )
    return "".join(lines[start + 1 : end])


# Repository canonical live-suite event bodies after dropping blank and
# full-line comment rows. This is not a general YAML parser: quoted event
# keys, flow mappings, aliases, and duplicate event blocks fail closed.
_BLANK_OR_COMMENT_LINE = re.compile(r"^\s*(?:#.*)?$")
_CANONICAL_EVENT_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
_PATH_FILTER_KEY = re.compile(
    r"""^[ \t]{2,}["']?(paths|paths-ignore)["']?[ \t]*:"""
)
_FLOW_PATH_FILTER = re.compile(
    r"""^  ["']?[A-Za-z0-9_-]+["']?[ \t]*:[ \t]*\{[^}\n]*["']?(paths(?:-ignore)?)["']?[ \t]*:"""
)

CANONICAL_PULL_REQUEST_BODY: tuple[str, ...] = ()
CANONICAL_MERGE_GROUP_BODY: tuple[str, ...] = (
    "    types:",
    "      - checks_requested",
)
CANONICAL_PUSH_MAIN_BODY: tuple[str, ...] = (
    "    branches:",
    "      - main",
)


def parse_canonical_on_events(workflow: str) -> dict[str, tuple[str, ...]] | None:
    """Parse the single top-level `on:` mapping into event -> body lines.

    Accepts only the repository's canonical block shape: unquoted indent-2
    event keys, mapping form `  event:` with no same-line value, and unique
    events. Blank and full-line comment rows are ignored. Returns None when
    the `on:` block is missing, duplicated, quoted, flow-form, aliased,
    or otherwise malformed.
    """

    on_block = extract_on_block(workflow)
    if not on_block:
        return None
    events: dict[str, list[str]] = {}
    current: str | None = None
    for line in on_block.splitlines():
        raw = line.rstrip("\r\n")
        if _BLANK_OR_COMMENT_LINE.match(raw):
            continue
        header = _CANONICAL_EVENT_HEADER.match(raw)
        if header:
            name = header.group(1)
            if name in events:
                return None
            events[name] = []
            current = name
            continue
        if current is None:
            return None
        if re.match(r'^  ["\']', raw) or re.match(r"^  [A-Za-z0-9_-]+:\s*\S", raw):
            return None
        if re.match(r"^  \S", raw) and not raw.startswith("    "):
            return None
        events[current].append(raw)
    return {name: tuple(body) for name, body in events.items()}


def on_block_path_filters(on_block: str) -> list[str]:
    """Return `paths` / `paths-ignore` keys, including quoted and flow spellings."""

    found: list[str] = []
    for line in on_block.splitlines():
        raw = line.rstrip("\r\n")
        match = _PATH_FILTER_KEY.match(raw)
        if match:
            found.append(match.group(1))
            continue
        flow = _FLOW_PATH_FILTER.match(raw)
        if flow:
            found.append(flow.group(1))
    return found


# Sentinels for a planner pattern this verifier has no probe for. Named so
# the diagnostic strips exactly the prefix it prepended.
PRODUCTION_UNMAPPED_PREFIX = "unmapped-production-pattern:"
NODE_WAYPOINT_UNMAPPED_PREFIX = "unmapped-node-waypoint-pattern:"


def production_dockerfile_probe_paths() -> list[str]:
    probes: list[str] = []
    for pattern in SUITE_PATTERNS["production-dockerfile-smoke"]:
        if pattern == r"^Dockerfile$":
            probes.append("Dockerfile")
        elif pattern == r"^\.dockerignore$":
            probes.append(".dockerignore")
        elif pattern == r"^Cargo\.(toml|lock)$":
            probes.extend(["Cargo.toml", "Cargo.lock"])
        elif pattern == r"^rust-toolchain\.toml$":
            probes.append("rust-toolchain.toml")
        elif pattern == r"^\.cargo/":
            probes.append(".cargo/config.toml")
        elif pattern == r"^vendor/":
            probes.append("vendor/foo/lib.rs")
        elif pattern == r"^build\.rs$":
            probes.append("build.rs")
        elif pattern == r"^proto/":
            probes.append("proto/ferrum.proto")
        elif pattern == r"^src/":
            probes.append("src/main.rs")
        elif pattern == r"^custom_plugins/":
            probes.append("custom_plugins/foo.rs")
        elif pattern == r"^ebpf/":
            probes.append("ebpf/src/lib.rs")
        elif pattern == r"^\.github/scripts/stage_iproute2_runtime\.sh$":
            probes.append(".github/scripts/stage_iproute2_runtime.sh")
        elif pattern == r"^\.github/workflows/node-waypoint-ebpf-live\.yml$":
            probes.append(".github/workflows/node-waypoint-ebpf-live.yml")
        elif pattern == r"^\.github/scripts/ci_runtime_plan\.py$":
            probes.append(".github/scripts/ci_runtime_plan.py")
        elif pattern == r"^\.github/scripts/ci_runtime_telemetry\.py$":
            probes.append(".github/scripts/ci_runtime_telemetry.py")
        elif pattern == r"^\.github/scripts/verify_ci_runtime_cache\.py$":
            probes.append(".github/scripts/verify_ci_runtime_cache.py")
        else:
            probes.append(f"{PRODUCTION_UNMAPPED_PREFIX}{pattern}")
    return probes


# Issue #3908 retired the workflow-level `paths:` filter that used to decide
# whether this workflow started at all. A `paths:` list lives in the pull
# request's own checkout, so the commit that broke a surface could delete its
# own trigger and skip the suite; the superset check below was the guard that
# the trigger at least reached every planner-sensitive input. With no trigger
# filter the workflow starts on every event and the trusted-base planner is the
# only relevance authority, so the contract inverts: any restored `paths:` /
# `paths-ignore` filter is a regression, and all four events must be present so
# merge-group and main-push runs actually happen.
GOVERNED_LIVE_TRIGGER_EVENTS = (
    "workflow_dispatch",
    "pull_request",
    "merge_group",
    "push",
)


def check_governed_live_trigger_shape(
    workflow: str,
    source: str,
    failures: list[str],
) -> None:
    require(
        not extract_pull_request_paths(workflow),
        f"{source} must not restore a pull_request.paths filter; a filter the "
        "pull request itself supplies can skip the suite that would have "
        "caught the same commit",
        failures,
    )
    on_block = extract_on_block(workflow)
    require(
        bool(on_block),
        f"{source} must declare a single top-level `on:` block",
        failures,
    )
    events = parse_canonical_on_events(workflow)
    require(
        events is not None,
        f"{source} must use the canonical block event shape (unquoted event "
        "keys, no flow/alias mappings, no duplicate event blocks)",
        failures,
    )
    for filtered in on_block_path_filters(on_block):
        failures.append(
            f"{source} must not filter a governed live trigger by `{filtered}:`"
        )
    if events is None:
        return
    require(
        set(events) == set(GOVERNED_LIVE_TRIGGER_EVENTS),
        f"{source} trigger events must be exactly "
        f"{list(GOVERNED_LIVE_TRIGGER_EVENTS)}; extra events such as "
        "pull_request_target must not execute a candidate-controlled live "
        "workflow",
        failures,
    )
    for event in GOVERNED_LIVE_TRIGGER_EVENTS:
        require(
            event in events,
            f"{source} must trigger on `{event}` so relevance is re-evaluated "
            "on pull requests, merge-queue combinations, and main pushes",
            failures,
        )
    require(
        events.get("pull_request") == CANONICAL_PULL_REQUEST_BODY,
        f"{source} pull_request trigger must be an input-less block event",
        failures,
    )
    require(
        events.get("merge_group") == CANONICAL_MERGE_GROUP_BODY,
        f"{source} merge_group trigger must request checks on the synthesized "
        "queue commit",
        failures,
    )
    require(
        events.get("push") == CANONICAL_PUSH_MAIN_BODY,
        f"{source} push trigger must cover exactly the main branch",
        failures,
    )
    # Every probe the planner treats as sensitive must still be reachable; with
    # no trigger filter that is now a statement about the planner alone.
    for probe in production_dockerfile_probe_paths():
        if probe.startswith(PRODUCTION_UNMAPPED_PREFIX):
            failures.append(
                f"{source} verifier must map every production-dockerfile-smoke "
                f"planner pattern "
                f"({probe.removeprefix(PRODUCTION_UNMAPPED_PREFIX)})"
            )
            continue
        relevant, _reason, _matched = decide_relevance(
            "production-dockerfile-smoke", [probe]
        )
        require(
            relevant,
            f"{source} production-image sensitive path {probe} must run the "
            "image jobs",
            failures,
        )


def job_if(job_body: str) -> str:
    match = re.search(r"(?m)^    if:\s*(.+)\s*$", job_body)
    if match:
        return match.group(1).strip()
    return ""


# Concrete `src/proxy/node_waypoint_*` modules the planner prefix pattern
# must keep sensitive. Add a row when a new NodeWaypoint proxy module lands;
# the planner stays correct without one, but the probe keeps this assertion
# honest about what the prefix is actually covering today.
NODE_WAYPOINT_PROXY_MODULE_PROBES = (
    "src/proxy/node_waypoint_ingress_capture.rs",
    "src/proxy/node_waypoint_udp_destination.rs",
    "src/proxy/node_waypoint_udp_identity.rs",
    "src/proxy/node_waypoint_udp_reply_source.rs",
    "src/proxy/node_waypoint_udp_steering.rs",
)


def node_waypoint_probe_paths() -> list[str]:
    probes: list[str] = []
    for pattern in SUITE_PATTERNS["node-waypoint-ebpf-live"]:
        if pattern == r"^\.github/workflows/node-waypoint-ebpf-live\.yml$":
            probes.append(".github/workflows/node-waypoint-ebpf-live.yml")
        elif pattern == r"^\.dockerignore$":
            probes.append(".dockerignore")
        elif pattern == r"^\.github/actions/package-ferrum-runtime-image/":
            probes.append(".github/actions/package-ferrum-runtime-image/action.yml")
        elif pattern == r"^\.github/actions/setup-kubernetes-tools/":
            probes.append(".github/actions/setup-kubernetes-tools/action.yml")
        elif pattern == r"^\.github/actions/setup-rust-ci/":
            probes.append(".github/actions/setup-rust-ci/action.yml")
        elif pattern == r"^\.github/actions/setup-sccache/":
            probes.append(".github/actions/setup-sccache/action.yml")
        elif pattern == r"^\.github/actions/setup-fast-linker/":
            probes.append(".github/actions/setup-fast-linker/action.yml")
        elif pattern == r"^\.github/actions/setup-bpf-linker/":
            probes.append(".github/actions/setup-bpf-linker/action.yml")
        elif pattern == r"^Cargo\.(toml|lock)$":
            probes.extend(["Cargo.toml", "Cargo.lock"])
        elif pattern == r"^Dockerfile$":
            probes.append("Dockerfile")
        elif pattern == r"^Dockerfile\.iproute2-layer$":
            probes.append("Dockerfile.iproute2-layer")
        elif pattern == r"^Dockerfile\.ebpf-tools-layer$":
            probes.append("Dockerfile.ebpf-tools-layer")
        elif pattern == r"^Dockerfile\.release$":
            probes.append("Dockerfile.release")
        elif pattern == r"^\.github/scripts/stage_iproute2_runtime\.sh$":
            probes.append(".github/scripts/stage_iproute2_runtime.sh")
        elif pattern == r"^build\.rs$":
            probes.append("build.rs")
        elif pattern == r"^proto/":
            probes.append("proto/ferrum.proto")
        elif pattern == r"^ebpf/":
            probes.append("ebpf/src/lib.rs")
        elif pattern == r"^src/capture/":
            probes.append("src/capture/mod.rs")
        elif pattern == r"^src/ebpf/":
            probes.append("src/ebpf/mod.rs")
        elif pattern == r"^src/grpc/":
            probes.append("src/grpc/mod.rs")
        elif pattern == r"^src/identity/":
            probes.append("src/identity/mod.rs")
        elif pattern == r"^src/k8s_controller/":
            probes.append("src/k8s_controller/mod.rs")
        elif pattern == r"^src/modes/control_plane\.rs$":
            probes.append("src/modes/control_plane.rs")
        elif pattern == r"^src/modes/mesh/":
            probes.append("src/modes/mesh/mod.rs")
        elif pattern == r"^src/modes/node_agent\.rs$":
            probes.append("src/modes/node_agent.rs")
        elif pattern == r"^src/plugins/mesh/":
            probes.append("src/plugins/mesh/mod.rs")
        elif pattern == r"^src/plugins/prometheus_metrics\.rs$":
            probes.append("src/plugins/prometheus_metrics.rs")
        elif pattern == r"^src/proxy/hbone_pool\.rs$":
            probes.append("src/proxy/hbone_pool.rs")
        elif pattern == r"^src/proxy/mesh_tcp_egress\.rs$":
            probes.append("src/proxy/mesh_tcp_egress.rs")
        elif pattern == r"^src/proxy/mesh_tcp_inbound\.rs$":
            probes.append("src/proxy/mesh_tcp_inbound.rs")
        elif pattern == r"^src/proxy/mod\.rs$":
            probes.append("src/proxy/mod.rs")
        elif pattern == r"^src/proxy/hbone_proxy\.rs$":
            probes.append("src/proxy/hbone_proxy.rs")
        elif pattern == r"^src/proxy/netns_capture\.rs$":
            probes.append("src/proxy/netns_capture.rs")
        elif pattern == r"^src/proxy/node_waypoint_":
            # Probe every NodeWaypoint proxy module the prefix is meant to
            # cover, not just one representative, so a module that stops
            # matching is caught here rather than in production.
            probes.extend(NODE_WAYPOINT_PROXY_MODULE_PROBES)
        elif pattern == r"^src/proxy/stream_listener\.rs$":
            probes.append("src/proxy/stream_listener.rs")
        elif pattern == r"^src/proxy/tcp_proxy\.rs$":
            probes.append("src/proxy/tcp_proxy.rs")
        elif pattern == r"^src/proxy/udp_proxy\.rs$":
            probes.append("src/proxy/udp_proxy.rs")
        elif pattern == r"^src/router_cache\.rs$":
            probes.append("src/router_cache.rs")
        elif pattern == r"^src/socket_opts\.rs$":
            probes.append("src/socket_opts.rs")
        elif pattern == r"^charts/ferrum-mesh/":
            probes.append("charts/ferrum-mesh/values.yaml")
        elif pattern == r"^tests/k8s/lib/":
            probes.append("tests/k8s/lib/helpers.sh")
        elif pattern == r"^tests/k8s/node_waypoint_ebpf_live/":
            probes.append("tests/k8s/node_waypoint_ebpf_live/run.sh")
        elif pattern == r"^docs/mesh\.md$":
            probes.append("docs/mesh.md")
        elif pattern == r"^docs/mesh_supported_matrix\.md$":
            probes.append("docs/mesh_supported_matrix.md")
        elif pattern == r"^docs/node_agent\.md$":
            probes.append("docs/node_agent.md")
        elif pattern == r"^docs/ci_cd\.md$":
            probes.append("docs/ci_cd.md")
        elif pattern == r"^docs/plans/node_waypoint_transport_adr\.md$":
            probes.append("docs/plans/node_waypoint_transport_adr.md")
        else:
            probes.append(f"{NODE_WAYPOINT_UNMAPPED_PREFIX}{pattern}")
    return probes


NODE_WAYPOINT_PRODUCTION_ONLY_PROBES = (
    "src/main.rs",
    "src/admin/mod.rs",
    "src/modes/database.rs",
    "src/plugins/cors.rs",
    "vendor/foo/src/lib.rs",
    ".cargo/config.toml",
    "rust-toolchain.toml",
    "custom_plugins/foo.rs",
)


def check_node_waypoint_live_job(
    workflow: str,
    source: str,
    failures: list[str],
) -> None:
    plan_job = extract_job(workflow, "production-dockerfile-plan")
    live_job = extract_job(workflow, "node-waypoint-ebpf-live")
    require(bool(plan_job), f"{source} production-dockerfile-plan job is missing", failures)
    require(bool(live_job), f"{source} node-waypoint-ebpf-live job is missing", failures)
    require(
        "node_waypoint_relevant: ${{ steps.filter.outputs.node_waypoint_relevant }}"
        in plan_job
        or "node_waypoint_relevant: ${{ steps.filter.outputs.node_waypoint_relevant }}"
        in workflow,
        f"{source} plan job must expose node_waypoint_relevant as a job output",
        failures,
    )
    require(
        "node_waypoint_relevant=true" in plan_job
        and "trusted base has not adopted" in plan_job,
        f"{source} must fail closed toward running NodeWaypoint when the trusted "
        "planner is missing",
        failures,
    )
    require(
        "--suite" in plan_job and "node-waypoint-ebpf-live" in plan_job,
        f"{source} must evaluate the node-waypoint-ebpf-live planner suite from "
        "the trusted-base copy",
        failures,
    )
    require(
        "needs: production-dockerfile-plan" in live_job
        or "needs:\n      - production-dockerfile-plan" in live_job,
        f"{source} live job must depend on the trusted planner job",
        failures,
    )
    live_condition = job_if(live_job)
    require(
        bool(live_condition),
        f"{source} live job must declare a single-line if condition",
        failures,
    )
    require(
        live_condition == NODE_WAYPOINT_LIVE_IF,
        f"{source} live job must skip only on exact {NODE_WAYPOINT_PLANNER_OUTPUT} "
        f"!= 'false' under !cancelled(); found: {live_condition}",
        failures,
    )
    require(
        "!cancelled()" in live_condition and "always()" not in live_condition,
        f"{source} live job must use !cancelled() to stop superseded runs and fail closed on planner failure",
        failures,
    )
    require(
        f"{NODE_WAYPOINT_PLANNER_OUTPUT} != 'false'" in live_condition,
        f"{source} live job skip must be exact-false-only",
        failures,
    )
    require(
        "== 'true'" not in live_condition,
        f"{source} live job must not treat blank/malformed output as a skip",
        failures,
    )
    require(
        "result == 'success'" not in live_condition,
        f"{source} live job must not require planner success to run "
        "(planner failure must fail closed toward running)",
        failures,
    )
    require(
        "outputs.relevant" not in live_condition,
        f"{source} live job must not reuse the production-image relevant output",
        failures,
    )
    require(
        "kind create cluster" in live_job,
        f"{source} live job must still create the Kind cluster",
        failures,
    )
    require(
        "tests/k8s/node_waypoint_ebpf_live/run.sh" in live_job,
        f"{source} live job must still run the NodeWaypoint harness",
        failures,
    )
    require(
        'ferrum_mesh_bpf_drops_total{reason="exclude_port_hit"}' in live_job
        or "ferrum_mesh_bpf_drops_total" in live_job,
        f"{source} live job must still assert a real BPF bypass metric",
        failures,
    )
    require(
        "timeout-minutes: 120" in live_job,
        f"{source} live job must keep the 120-minute Kind/eBPF timeout",
        failures,
    )
    unmapped = [
        probe
        for probe in node_waypoint_probe_paths()
        if probe.startswith(NODE_WAYPOINT_UNMAPPED_PREFIX)
    ]
    require(
        not unmapped,
        f"{source} verifier must map every node-waypoint-ebpf-live planner "
        f"pattern ("
        f"{', '.join(item.removeprefix(NODE_WAYPOINT_UNMAPPED_PREFIX) for item in unmapped)})",
        failures,
    )
    for probe in node_waypoint_probe_paths():
        if probe.startswith(NODE_WAYPOINT_UNMAPPED_PREFIX):
            continue
        relevant, _reason, _matched = decide_relevance("node-waypoint-ebpf-live", [probe])
        require(
            relevant,
            f"{source} prior-scope path {probe} must run the NodeWaypoint live job",
            failures,
        )
    for probe in NODE_WAYPOINT_PRODUCTION_ONLY_PROBES:
        node_relevant, _reason, _matched = decide_relevance(
            "node-waypoint-ebpf-live", [probe]
        )
        prod_relevant, _, _ = decide_relevance("production-dockerfile-smoke", [probe])
        require(
            not node_relevant,
            f"{source} production-only path {probe} must skip the NodeWaypoint live job",
            failures,
        )
        require(
            prod_relevant,
            f"{source} production-only path {probe} must still trigger production-image smoke",
            failures,
        )
    empty_relevant, _, _ = decide_relevance("node-waypoint-ebpf-live", [])
    require(
        empty_relevant,
        f"{source} empty NodeWaypoint diff must fail closed toward running",
        failures,
    )
    unknown_relevant, _, _ = decide_relevance(
        "node-waypoint-ebpf-live", ["brand-new-crate/src/lib.rs"]
    )
    require(
        unknown_relevant,
        f"{source} unknown NodeWaypoint path must fail closed toward running",
        failures,
    )


# Issue #3908 gives the Kind/eBPF live job an always-reporting aggregate of its
# own, `NodeWaypoint eBPF Live`. It must be consistent with the live job's
# binding: the ONLY outcome that legitimately skips the live job is an exact
# `false` verdict from the trusted-base planner, so that is the only outcome the
# aggregate may report green without a successful live run. A planner failure
# fails the aggregate, and a blank / malformed verdict runs the live job (the
# `!= 'false'` binding) and is then judged on the live result.
NODE_WAYPOINT_AGGREGATE_JOB = "node-waypoint-ebpf-live-gate"
NODE_WAYPOINT_AGGREGATE_NAME = "NodeWaypoint eBPF Live"


def check_node_waypoint_aggregate(
    workflow: str,
    source: str,
    failures: list[str],
) -> None:
    aggregate = extract_job(workflow, NODE_WAYPOINT_AGGREGATE_JOB)
    require(
        bool(aggregate),
        f"{source} must declare the {NODE_WAYPOINT_AGGREGATE_JOB!r} aggregate so "
        "an irrelevant run still reports a result",
        failures,
    )
    if not aggregate:
        return
    require(
        re.search(
            rf"(?m)^    name: {re.escape(NODE_WAYPOINT_AGGREGATE_NAME)}$", aggregate
        )
        is not None,
        f"{source} aggregate must keep the check name "
        f"{NODE_WAYPOINT_AGGREGATE_NAME!r}",
        failures,
    )
    require(
        re.search(r"(?m)^    if: always\(\)$", aggregate) is not None,
        f"{source} aggregate must run with if: always() so a skipped or failed "
        "live job still reports",
        failures,
    )
    require(
        job_needs_list(aggregate)
        == {"production-dockerfile-plan", "node-waypoint-ebpf-live"},
        f"{source} aggregate must depend on exactly the trusted planner and the "
        "live job",
        failures,
    )
    steps = job_steps(aggregate)
    planner_condition = "needs.production-dockerfile-plan.result != 'success'"
    planner_steps = [step for step in steps if step_if(step) == planner_condition]
    require(
        len(planner_steps) == 1,
        f"{source} aggregate must declare exactly one planner-failure step "
        f"with if: {planner_condition}",
        failures,
    )
    if planner_steps:
        require(
            step_run_ends_with_exit(planner_steps[0], 1),
            f"{source} planner-failure step must terminate with an effective exit 1",
            failures,
        )

    skip_steps = [
        step
        for step in steps
        if re.search(
            r"(?m)^      - name: Skip NodeWaypoint eBPF live datapath for unrelated changes$",
            step,
        )
    ]
    require(
        len(skip_steps) == 1,
        f"{source} aggregate must declare exactly one exact-false skip step",
        failures,
    )
    skip_if = step_if(skip_steps[0]) if skip_steps else ""
    require(
        skip_if == f"{NODE_WAYPOINT_PLANNER_OUTPUT} == 'false'",
        f"{source} aggregate skip must use exact {NODE_WAYPOINT_PLANNER_OUTPUT} "
        f"== 'false', found: {skip_if}",
        failures,
    )
    require(
        "!= 'true'" not in skip_if,
        f"{source} aggregate skip must not treat a blank verdict as irrelevance",
        failures,
    )
    live_failure_condition = (
        f"{NODE_WAYPOINT_PLANNER_OUTPUT} != 'false' && "
        "needs.node-waypoint-ebpf-live.result != 'success'"
    )
    live_failure_steps = [
        step for step in steps if step_if(step) == live_failure_condition
    ]
    require(
        len(live_failure_steps) == 1,
        f"{source} aggregate must fail whenever the live job was scheduled and "
        f"did not succeed, using exactly one step with if: {live_failure_condition}",
        failures,
    )
    if live_failure_steps:
        require(
            step_run_ends_with_exit(live_failure_steps[0], 1),
            f"{source} live-failure step must terminate with an effective exit 1",
            failures,
        )


def check_aggregate_planner_contract(
    aggregate_body: str,
    planner_job: str,
    source: str,
    failures: list[str],
) -> None:
    planner_result = f"needs.{planner_job}.result"
    planner_relevant = f"needs.{planner_job}.outputs.relevant"
    skip_steps = [
        step
        for step in job_steps(aggregate_body)
        if re.search(r"(?m)^      - name: Skip", step)
    ]
    require(
        len(skip_steps) == 1,
        f"{source} aggregate must declare exactly one skip step",
        failures,
    )
    skip_if = step_if(skip_steps[0]) if skip_steps else ""
    require(
        bool(skip_if),
        f"{source} aggregate skip step must declare a single-line if condition",
        failures,
    )
    if skip_if:
        require(
            skip_if == f"{planner_relevant} == 'false'",
            f"{source} aggregate skip must use exact {planner_relevant} == 'false', "
            f"found: {skip_if}",
            failures,
        )
        require(
            "!= 'true'" not in skip_if,
            f"{source} aggregate skip must not use != 'true'",
            failures,
        )
    require(
        f"{planner_result} != 'success'" in aggregate_body,
        f"{source} aggregate must fail when planning fails",
        failures,
    )
    require(
        f"{planner_result} == 'success'" in aggregate_body
        and f"{planner_relevant} != 'true'" in aggregate_body
        and f"{planner_relevant} != 'false'" in aggregate_body,
        f"{source} aggregate must fail closed when planner output is neither "
        "exact true nor exact false",
        failures,
    )
    require(
        f"{planner_relevant} == 'true'" in aggregate_body,
        f"{source} aggregate must gate expensive jobs on exact "
        f"{planner_relevant} == 'true'",
        failures,
    )


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


FORK_IS_TRUE = "github.event.pull_request.head.repo.fork == true"
FORK_NOT_TRUE = "github.event.pull_request.head.repo.fork != true"
AMBIENT_GHA_CACHE_SCOPE = "ambient-host-udp-images"
AMBIENT_GHA_CACHE_FROM = f"type=gha,scope={AMBIENT_GHA_CACHE_SCOPE}"
AMBIENT_GHA_CACHE_TO_EXPORT = f"type=gha,mode=max,scope={AMBIENT_GHA_CACHE_SCOPE}"
AMBIENT_GHA_CACHE_TO = (
    "${{ github.event_name != 'pull_request' && "
    "github.event_name != 'merge_group' && "
    "github.ref == 'refs/heads/main' && "
    f"{FORK_NOT_TRUE} && "
    f"'{AMBIENT_GHA_CACHE_TO_EXPORT}' || '' }}}}"
)
AMBIENT_IMAGE_BUILDS = (
    ("Build the capture tool base stage", "capture-tools-base"),
    (
        "Build the production Ambient UDP lifecycle runtime",
        "runtime-ebpf-tools",
    ),
    ("Build the distroless eBPF runtime", "runtime-ebpf"),
)
AMBIENT_IMAGE_CONTRACTS = (
    "Prove the published runtime can execute the production tool set",
    "Prove the `-ebpf` image keeps its distroless contract",
)
UNCONDITIONAL_AMBIENT_CACHE_TO = re.compile(
    r"(?m)^[ \t]*cache-to:[ \t]*type=gha,mode=max,scope=ambient-host-udp-images\s*$"
)
COLD_IS_TRUE = "github.event.inputs.force_cold_cache == 'true'"
COLD_NOT_TRUE = "github.event.inputs.force_cold_cache != 'true'"
SAVE_IF_NON_FORK = re.compile(
    r"(?m)^[ \t]*save-if:\s*(?:['\"]?)(?:\$\{\{\s*)?"
    r"github\.event\.pull_request\.head\.repo\.fork\s*!=\s*true"
    r"(?:\s*\}\})?(?:['\"]?)\s*(?:#.*)?$"
)
SAVE_IF_FALSE = re.compile(
    r"(?m)^[ \t]*save-if:\s*(?:['\"]?)(?:\$\{\{\s*)?false"
    r"(?:\s*\}\})?(?:['\"]?)\s*(?:#.*)?$"
)
# The shared setup-rust-ci action publishes rust-cache saves only from a
# trusted `refs/heads/main` run: PR-merge-ref-scoped Swatinem entries were
# multi-gigabyte per lane, evicted the default-branch caches every job
# restores from (10 GB repository quota, LRU across refs), and left ordinary
# test lanes compiling cold. The pull_request/merge_group exclusions are
# explicit even though `github.ref` alone would exclude both, so the guard
# stays fail-closed if the ref check is later weakened; the fork guard is the
# same defense in depth.
SAVE_IF_TRUSTED_MAIN = re.compile(
    r"(?m)^[ \t]*save-if:\s*(?:['\"]?)(?:\$\{\{\s*)?"
    r"github\.event_name\s*!=\s*'pull_request'\s*&&\s*"
    r"github\.event_name\s*!=\s*'merge_group'\s*&&\s*"
    r"github\.ref\s*==\s*'refs/heads/main'\s*&&\s*"
    r"github\.event\.pull_request\.head\.repo\.fork\s*!=\s*true"
    r"(?:\s*\}\})?(?:['\"]?)\s*(?:#.*)?$"
)
RUST_CACHE_BARE_KEY = re.compile(r"(?m)^[ \t]*key:")
RUST_CACHE_ADD_JOB_ID = re.compile(r"(?m)^[ \t]*add-job-id-key:")
TOKEN_ECHO = re.compile(
    r"""echo\s+["']?\$\{?(?:ACTIONS_RUNTIME_TOKEN|ACTIONS_RESULTS_URL|ACTIONS_CACHE_URL)"""
)


def extract_job(workflow: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        return ""
    return match.group("body")


def job_needs_list(job_body: str) -> set[str]:
    list_match = re.search(
        r"(?m)^    needs:\n(?P<needs>(?:^      - [^\n]+\n)+)", job_body
    )
    if list_match:
        return {
            line.strip().removeprefix("- ").strip()
            for line in list_match.group("needs").splitlines()
            if line.strip().startswith("- ")
        }
    scalar_match = re.search(r"(?m)^    needs: ([A-Za-z0-9_-]+)$", job_body)
    if scalar_match:
        return {scalar_match.group(1)}
    return set()


def job_steps(job_body: str) -> list[str]:
    match = re.search(r"(?ms)^    steps:\n(.*)\Z", job_body)
    if match is None:
        return []
    chunks = re.split(r"(?m)^(?=      - )", match.group(1))
    return [chunk for chunk in chunks if chunk.lstrip().startswith("- ")]


def step_if(step: str) -> str:
    match = re.search(r"(?m)^      (?:- )?if:\s*(.+)\s*$", step)
    if match:
        return match.group(1).strip()
    match = re.search(r"(?m)^        if:\s*(.+)\s*$", step)
    if match:
        return match.group(1).strip()
    return ""


def step_run_ends_with_exit(step: str, code: int) -> bool:
    """Return whether a run step has one effective terminal `exit CODE`.

    Same-line scalars must be exactly `exit CODE` on the `run:` line. Only
    horizontal whitespace may surround that command, so a `run: |` introducer
    cannot be captured as a scalar and whitespace cannot cross a newline.
    Literal blocks accept `|`, `|-`, and `|+` on that same line; folded `>`
    blocks are refused. Merely mentioning `exit 1` in a comment, echo, or an
    earlier unreachable command is insufficient: the block must contain
    exactly one executable `exit` line and it must be the final non-empty,
    non-comment command.
    """

    expected = f"exit {code}"
    if re.search(rf"(?m)^        run:[ \t]+{re.escape(expected)}[ \t]*$", step):
        return True

    block = re.search(
        r"(?ms)^        run:[ \t]+\|[-+]?[ \t]*\n(?P<body>.*)\Z",
        step,
    )
    if block is None:
        return False
    commands = [
        line.strip()
        for line in block.group("body").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not commands:
        return False
    exits = [line for line in commands if re.fullmatch(r"exit\s+\d+", line)]
    return exits == [expected] and commands[-1] == expected


def step_uses(step: str) -> str:
    match = re.search(r"(?m)^      (?:- )?uses:\s*(\S+)", step)
    if match is None:
        match = re.search(r"(?m)^        uses:\s*(\S+)", step)
    if match is None:
        return ""
    return _yaml_strip_trailing_comment(match.group(1)).strip()


def step_with(step: str) -> str:
    match = re.search(r"(?m)^        with:\n", step)
    if match is None:
        return ""
    lines: list[str] = []
    for line in step[match.end() :].splitlines(keepends=True):
        if line.strip() == "":
            lines.append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent >= 10:
            lines.append(line)
            continue
        break
    return "".join(lines)


def with_has_key(with_block: str, key: str) -> bool:
    return re.search(rf"(?m)^[ \t]*{re.escape(key)}:", with_block) is not None


def rust_cache_with_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    for chunk in re.split(r"(?m)^(?=[ ]{2,}- )", text):
        if RUST_CACHE not in chunk or not re.search(r"(?m)^[ ]{2,}- ", chunk):
            continue
        with_match = re.search(
            r"(?ms)^[ \t]+with:\n((?:[ \t]+[^\n]*\n)*)",
            chunk,
        )
        blocks.append(with_match.group(1) if with_match else "")
    return blocks


def check_rust_cache_uses_shared_key_only(
    with_block: str,
    source: str,
    failures: list[str],
    *,
    expected_shared_key: str,
) -> None:
    require(
        expected_shared_key in with_block,
        f"{source} rust-cache shared-key must be {expected_shared_key}",
        failures,
    )
    require(
        RUST_CACHE_BARE_KEY.search(with_block) is None,
        f"{source} must not set rust-cache `key:` (ignored when shared-key is set)",
        failures,
    )
    require(
        RUST_CACHE_ADD_JOB_ID.search(with_block) is None,
        f"{source} must not set rust-cache add-job-id-key (unused with shared-key)",
        failures,
    )
    require(
        "github.sha" not in with_block
        and "github.run_id" not in with_block
        and "github.run_attempt" not in with_block,
        f"{source} stable rust-cache shared-key must not include sha/run_id/"
        "run_attempt (those belong on the producer channel)",
        failures,
    )
    require(
        re.search(
            r"(?m)^[ \t]*add-rust-environment-hash-key:\s*['\"]?false",
            with_block,
        )
        is None,
        f"{source} must preserve automatic rust environment/manifest/lock hashing",
        failures,
    )


def check_credential_absence_assertion(
    text: str,
    source: str,
    failures: list[str],
) -> None:
    require(
        "Assert cache-service credentials are absent" in text,
        f"{source} must declare a hosted cache-credential absence assertion",
        failures,
    )
    for var in CREDENTIAL_ASSERT_VARS:
        require(
            var in text,
            f"{source} credential assertion must check {var}",
            failures,
        )
    require(
        '[ -n "${!var:-}" ]' in text or "[ -n \"${!var:-}\" ]" in text,
        f"{source} must test credential presence via ${{!var:-}} without "
        "printing values",
        failures,
    )
    require(
        TOKEN_ECHO.search(text) is None,
        f"{source} must not print cache-service credential values",
        failures,
    )
    require(
        "refusing to execute later PR-controlled build steps" in text
        or "refusing to execute PR-controlled" in text,
        f"{source} credential assertion must fail closed",
        failures,
    )


def _decode_double_quoted_yaml(body: str) -> str | None:
    decoded: list[str] = []
    index = 0
    while index < len(body):
        character = body[index]
        if character != "\\":
            decoded.append(character)
            index += 1
            continue
        index += 1
        if index >= len(body):
            return None
        marker = body[index]
        index += 1
        if marker in {"x", "u", "U"}:
            width = {"x": 2, "u": 4, "U": 8}[marker]
            digits = body[index : index + width]
            if len(digits) != width or any(digit not in YAML_HEX_DIGITS for digit in digits):
                return None
            index += width
            try:
                decoded.append(chr(int(digits, 16)))
            except ValueError:
                return None
            continue
        if marker == "\n":
            while index < len(body) and body[index] in " \t":
                index += 1
            continue
        decoded.append(YAML_DOUBLE_QUOTED_ESCAPES.get(marker, marker))
    return "".join(decoded)


def _decode_yaml_scalar(raw: str) -> str | None:
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return _decode_double_quoted_yaml(text[1:-1])
    if text[:1] in {"'", '"'}:
        return None
    return text


def _yaml_comment_starts_at(text: str, index: int) -> bool:
    """YAML 1.2: `#` starts a comment only at start-of-text or after whitespace.

    `harmless#suffix` is plain-scalar data, not a comment. Treating every `#`
    as a comment opener conceals later flow entries on the same line.
    """

    if index < 0 or index >= len(text) or text[index] != "#":
        return False
    if index == 0:
        return True
    return text[index - 1] in " \t\r\n"


def _yaml_strip_trailing_comment(text: str) -> str:
    quote: str | None = None
    index = 0
    while index < len(text):
        character = text[index]
        if quote == '"':
            if character == "\\" and index + 1 < len(text):
                index += 2
                continue
            if character == '"':
                quote = None
            index += 1
            continue
        if quote == "'":
            if character == "'" and index + 1 < len(text) and text[index + 1] == "'":
                index += 2
                continue
            if character == "'":
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if _yaml_comment_starts_at(text, index):
            return text[:index]
        index += 1
    return text


def _yaml_quotes_balanced(text: str) -> bool:
    """Return False for unclosed quotes, including `\\` line-continuation."""

    quote: str | None = None
    index = 0
    while index < len(text):
        character = text[index]
        if quote == '"':
            if character == "\\" and index + 1 < len(text):
                index += 2
                continue
            if character == "\\":
                return False
            if character == '"':
                quote = None
            index += 1
            continue
        if quote == "'":
            if character == "'" and index + 1 < len(text) and text[index + 1] == "'":
                index += 2
                continue
            if character == "'":
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if _yaml_comment_starts_at(text, index):
            return quote is None
        index += 1
    return quote is None


def _leading_yaml_node_properties(text: str) -> tuple[bool, str]:
    """Split `&anchor` / `*alias` / `!tag` prefixes from a node.

    An alias is a complete node. Anchors and tags may precede a collection or
    scalar; the remainder is returned so callers can still parse `{...}` / `[...]`
    after rejecting the indirect spelling.
    """

    remaining = text.lstrip(" \t")
    had = False
    while remaining:
        marker = remaining[0]
        if marker in {"&", "*"}:
            had = True
            index = 1
            while index < len(remaining) and remaining[index] not in " \t,{}[]:#":
                index += 1
            if index == 1:
                return True, remaining
            remaining = remaining[index:].lstrip(" \t")
            if marker == "*":
                break
            continue
        if marker != "!":
            break
        had = True
        index = 1
        if index < len(remaining) and remaining[index] == "<":
            end = remaining.find(">", index)
            if end < 0:
                return True, ""
            index = end + 1
        else:
            while index < len(remaining) and remaining[index] not in " \t,{}[]:#":
                index += 1
        remaining = remaining[index:].lstrip(" \t")
    return had, remaining


def _skip_flow_comment(text: str, index: int) -> int:
    while index < len(text) and text[index] != "\n":
        index += 1
    return index


def _balanced_flow(text: str, start: int) -> tuple[str, int] | None:
    if start >= len(text) or text[start] not in "{[":
        return None
    closers = {"{": "}", "[": "]"}
    stack = [text[start]]
    quote: str | None = None
    index = start + 1
    while index < len(text):
        character = text[index]
        if quote == '"':
            if character == "\\" and index + 1 < len(text):
                index += 2
                continue
            if character == '"':
                quote = None
            index += 1
            continue
        if quote == "'":
            if character == "'" and index + 1 < len(text) and text[index + 1] == "'":
                index += 2
                continue
            if character == "'":
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if _yaml_comment_starts_at(text, index):
            index = _skip_flow_comment(text, index)
            continue
        if character in "{[":
            stack.append(character)
        elif character in "}]":
            if not stack or closers[stack[-1]] != character:
                return None
            stack.pop()
            if not stack:
                return text[start : index + 1], index + 1
        index += 1
    return None


def _split_flow_entries(inner: str) -> list[str] | None:
    entries: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(inner):
        character = inner[index]
        if quote == '"':
            current.append(character)
            if character == "\\" and index + 1 < len(inner):
                current.append(inner[index + 1])
                index += 2
                continue
            if character == '"':
                quote = None
            index += 1
            continue
        if quote == "'":
            current.append(character)
            if character == "'" and index + 1 < len(inner) and inner[index + 1] == "'":
                current.append("'")
                index += 2
                continue
            if character == "'":
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            current.append(character)
            index += 1
            continue
        if _yaml_comment_starts_at(inner, index):
            index = _skip_flow_comment(inner, index)
            continue
        if character in "{[":
            depth += 1
        elif character in "}]":
            depth -= 1
            if depth < 0:
                return None
        elif character == "," and depth == 0:
            entries.append("".join(current))
            current = []
            index += 1
            continue
        current.append(character)
        index += 1
    if quote is not None or depth != 0:
        return None
    entries.append("".join(current))
    return entries


def _parse_uses_value(raw: str) -> tuple[str | None, str | None]:
    text = _yaml_strip_trailing_comment(raw).strip()
    if not text:
        return None, "empty uses value"
    if text[0] in "*&!":
        return None, "indirect uses value"
    if YAML_BLOCK_SCALAR.match(text):
        return None, "block-scalar uses value"
    if text[0] in "{[":
        return None, "collection uses value"
    if "${{" in text:
        return None, "dynamic uses value"
    decoded = _decode_yaml_scalar(text)
    if decoded is None:
        return None, "unreadable uses spelling"
    decoded = decoded.strip()
    if not decoded or decoded[0] in "*&!" or "${{" in decoded or "\n" in decoded:
        return None, "dynamic uses value"
    return decoded, None


def _record_mapping_pair(
    raw_key: str,
    raw_value: str,
    uses: list[str],
    using: list[str],
    errors: list[str],
) -> None:
    key = _decode_yaml_scalar(raw_key)
    if key is None:
        errors.append("unreadable YAML key spelling")
        return
    if key == "<<":
        errors.append("YAML merge key")
        return
    if key == "uses":
        value, error = _parse_uses_value(raw_value)
        if error:
            errors.append(error)
            return
        if value is not None:
            uses.append(value)
        return
    if key == "using":
        value, error = _parse_uses_value(raw_value)
        if error:
            errors.append(error.replace("uses", "using"))
            return
        if value is not None:
            using.append(value)


def _record_flow_pairs(
    pairs: list[tuple[str, str]],
    flow_errors: list[str],
    uses: list[str],
    using: list[str],
    errors: list[str],
) -> None:
    errors.extend(flow_errors)
    for raw_key, raw_value in pairs:
        _record_mapping_pair(raw_key, raw_value, uses, using, errors)


def _collect_nested_flow_value(
    value: str,
    pairs: list[tuple[str, str]],
    errors: list[str],
) -> None:
    had_props, remainder = _leading_yaml_node_properties(value)
    if had_props:
        errors.append("indirect or tagged YAML node")
        value = remainder
    if not value:
        return
    if value.startswith("?"):
        errors.append("explicit YAML key")
        return
    if value.startswith("{"):
        balanced = _balanced_flow(value, 0)
        if balanced is None:
            errors.append("unreadable nested flow mapping")
            return
        nested, nested_errors = _collect_flow_mapping_pairs(balanced[0])
        pairs.extend(nested)
        errors.extend(nested_errors)
        return
    if value.startswith("["):
        balanced = _balanced_flow(value, 0)
        if balanced is None:
            errors.append("unreadable nested flow sequence")
            return
        nested, nested_errors = _collect_flow_sequence(balanced[0])
        pairs.extend(nested)
        errors.extend(nested_errors)


def _collect_flow_mapping_pairs(flow: str) -> tuple[list[tuple[str, str]], list[str]]:
    pairs: list[tuple[str, str]] = []
    errors: list[str] = []
    if not (flow.startswith("{") and flow.endswith("}")):
        return [], ["unreadable flow mapping"]
    entries = _split_flow_entries(flow[1:-1])
    if entries is None:
        return [], ["unreadable flow mapping"]
    for entry in entries:
        item = entry.strip()
        if not item:
            continue
        had_props, item = _leading_yaml_node_properties(item)
        if had_props:
            errors.append("indirect or tagged YAML node")
            if not item:
                continue
        if item.startswith("?"):
            errors.append("explicit YAML key")
            continue
        match = re.match(rf"^({YAML_KEY_TOKEN})[ \t]*:(.*)$", item, re.DOTALL)
        if match is None:
            errors.append("unreadable flow mapping entry")
            continue
        pairs.append((match.group(1), match.group(2)))
        _collect_nested_flow_value(match.group(2).strip(), pairs, errors)
    return pairs, errors


def _collect_flow_sequence(flow: str) -> tuple[list[tuple[str, str]], list[str]]:
    pairs: list[tuple[str, str]] = []
    errors: list[str] = []
    if not (flow.startswith("[") and flow.endswith("]")):
        return [], ["unreadable flow sequence"]
    entries = _split_flow_entries(flow[1:-1])
    if entries is None:
        return [], ["unreadable flow sequence"]
    for entry in entries:
        item = entry.strip()
        if not item:
            continue
        had_props, item = _leading_yaml_node_properties(item)
        if had_props:
            errors.append("indirect or tagged YAML node")
            if not item:
                continue
        if item.startswith("?"):
            errors.append("explicit YAML key")
            continue
        if item.startswith("{"):
            balanced = _balanced_flow(item, 0)
            if balanced is None:
                errors.append("unreadable flow sequence mapping")
                continue
            nested, nested_errors = _collect_flow_mapping_pairs(balanced[0])
            pairs.extend(nested)
            errors.extend(nested_errors)
            continue
        if item.startswith("["):
            balanced = _balanced_flow(item, 0)
            if balanced is None:
                errors.append("unreadable nested flow sequence")
                continue
            nested, nested_errors = _collect_flow_sequence(balanced[0])
            pairs.extend(nested)
            errors.extend(nested_errors)
            continue
        match = re.match(rf"^({YAML_KEY_TOKEN})[ \t]*:(.*)$", item, re.DOTALL)
        if match is not None:
            pairs.append((match.group(1), match.group(2)))
            _collect_nested_flow_value(match.group(2).strip(), pairs, errors)
            continue
        if not _yaml_quotes_balanced(item):
            errors.append("unreadable multiline YAML quoting")
            continue
        # Plain flow scalars (`[main]`) are not action carriers.
    return pairs, errors


def _scan_structural_text(
    text: str,
    uses: list[str],
    using: list[str],
    errors: list[str],
) -> None:
    item = text.strip()
    if not item:
        return
    had_props, item = _leading_yaml_node_properties(item)
    if had_props:
        errors.append("indirect or tagged YAML node")
        if not item:
            return
    if item.startswith("?"):
        errors.append("explicit YAML key")
        return
    if item.startswith("{") or item.startswith("["):
        balanced = _balanced_flow(item, 0)
        if balanced is None:
            errors.append("unreadable flow collection")
            return
        flow_text, _end = balanced
        if flow_text.startswith("{"):
            pairs, flow_errors = _collect_flow_mapping_pairs(flow_text)
        else:
            pairs, flow_errors = _collect_flow_sequence(flow_text)
        _record_flow_pairs(pairs, flow_errors, uses, using, errors)
        return
    match = re.match(rf"^({YAML_KEY_TOKEN})[ \t]*:(.*)$", item, re.DOTALL)
    if match is None:
        errors.append("unreadable YAML structure")
        return
    _record_mapping_pair(match.group(1), match.group(2), uses, using, errors)
    value = _yaml_strip_trailing_comment(match.group(2)).strip()
    had_value_props, remainder = _leading_yaml_node_properties(value)
    if had_value_props:
        errors.append("indirect or tagged YAML node")
        value = remainder
    if value.startswith("{") or value.startswith("["):
        _scan_structural_text(value, uses, using, errors)


def _is_plain_sequence_scalar(item: str) -> bool:
    text = _yaml_strip_trailing_comment(item).strip()
    if not text:
        return True
    if not _yaml_quotes_balanced(text):
        return False
    had_props, remainder = _leading_yaml_node_properties(text)
    if had_props or remainder[:1] in {"{", "[", "?"}:
        return False
    return re.match(rf"^(?:{YAML_KEY_TOKEN})[ \t]*:", remainder, re.DOTALL) is None


def _yaml_mapping_key_indent(parsed: re.Match[str]) -> int:
    """Indentation of a mapping key, not the compact sequence dash.

    For `      - name: |`, the dash sits at column 6 while sibling keys such as
    `uses:` are at column 8. Skipping a block scalar against the dash indent
    would swallow those siblings as scalar body.
    """

    indent = len(parsed.group("lead"))
    dash = parsed.group("dash")
    if dash:
        indent += len(dash)
    return indent


class _StepBucket:
    """One YAML sequence mapping (typically a GHA step) plus its `with:` pairs."""

    def __init__(self, key_indent: int | None) -> None:
        self.key_indent = key_indent
        self.uses: list[str] = []
        self.using: list[str] = []
        self.with_pairs: list[tuple[str, str]] = []
        self.with_errors: list[str] = []
        self.with_declarations = 0
        self.collecting_with = False


def _note_step_actions(
    step: _StepBucket | None,
    uses: list[str],
    using: list[str],
    uses_before: int,
    using_before: int,
) -> None:
    if step is None:
        return
    step.uses.extend(uses[uses_before:])
    step.using.extend(using[using_before:])


def _parse_plain_action_scalar(raw: str, what: str) -> tuple[str | None, str | None]:
    value, error = _parse_uses_value(raw)
    if error:
        return None, error.replace("uses", what)
    return value, None


def _attach_with_value(step: _StepBucket, raw_value: str) -> None:
    step.with_declarations += 1
    value = _yaml_strip_trailing_comment(raw_value).strip()
    had_props, remainder = _leading_yaml_node_properties(value)
    if had_props:
        step.with_errors.append("indirect or tagged YAML node")
        value = remainder
    if not value:
        return
    if YAML_BLOCK_SCALAR.match(value):
        step.with_errors.append("block-scalar with mapping")
        return
    if value.startswith("{"):
        balanced = _balanced_flow(value, 0)
        if balanced is None:
            step.with_errors.append("unreadable with mapping")
            return
        pairs, errors = _collect_flow_mapping_pairs(balanced[0])
        step.with_errors.extend(errors)
        step.with_pairs.extend(pairs)
        return
    step.with_errors.append("unreadable with mapping")


def _begin_step(steps: list[_StepBucket], key_indent: int | None) -> _StepBucket:
    step = _StepBucket(key_indent)
    steps.append(step)
    return step


def _skip_block_scalar(lines: list[str], start: int, parent_indent: int) -> int:
    """Skip a block-scalar body: lines strictly more indented than the key.

    `parent_indent` is the mapping-key column so compact sequence siblings
    (`uses:` after `name: |`) terminate the scalar instead of being skipped.
    """

    index = start
    while index < len(lines):
        line = lines[index]
        if not line.strip():
            index += 1
            continue
        indent = len(line) - len(line.lstrip(" \t"))
        if indent <= parent_indent:
            break
        index += 1
    return index


def _collect_multiline_flow(
    lines: list[str], start_text: str, next_index: int
) -> tuple[str | None, int]:
    collected = [start_text]
    cursor = next_index
    blob = "\n".join(collected)
    while _balanced_flow(blob, 0) is None and cursor < len(lines):
        collected.append(lines[cursor])
        blob = "\n".join(collected)
        cursor += 1
    balanced = _balanced_flow(blob, 0)
    if balanced is None:
        return None, next_index
    return balanced[0], cursor


def _scan_yaml_actions(
    text: str,
) -> tuple[list[str], list[str], list[str], list[_StepBucket]]:
    """Extract `uses`/`using` values and sequence-item step mappings.

    Block-scalar bodies (`run: |`, `description: >-`) are not YAML mappings, so
    they are skipped using the mapping-key column (not the compact `- ` dash
    column) so sibling keys remain visible. Flow mappings, unbraced flow pairs,
    quoted/escaped keys, explicit keys, anchors, aliases, tags, merge keys, and
    multiline quoted keys are parsed or rejected fail-closed. `#` is a comment
    only when YAML would start one. This is not a full YAML implementation;
    unreadable structure is a failure, not an admitted absence of actions.
    """

    uses: list[str] = []
    using: list[str] = []
    errors: list[str] = []
    steps: list[_StepBucket] = []
    current: _StepBucket | None = None
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip(" \t")
        if not stripped or stripped.startswith("#") or stripped in YAML_DOCUMENT_MARK:
            index += 1
            continue
        if not _yaml_quotes_balanced(line):
            errors.append("unreadable multiline YAML quoting")
            index += 1
            continue
        explicit = YAML_EXPLICIT_KEY.match(line)
        if explicit:
            errors.append("explicit YAML key")
            rest = line[explicit.end() :].lstrip(" \t")
            uses_before = len(uses)
            using_before = len(using)
            if rest:
                _scan_structural_text(rest, uses, using, errors)
            _note_step_actions(current, uses, using, uses_before, using_before)
            index += 1
            continue
        dash_item = YAML_SEQUENCE_ITEM.match(line)
        content = dash_item.group("item") if dash_item else stripped
        had_line_props, remainder = _leading_yaml_node_properties(content)
        if had_line_props:
            errors.append("indirect or tagged YAML node")
            uses_before = len(uses)
            using_before = len(using)
            if remainder.startswith("{") or remainder.startswith("["):
                flow_text, cursor = _collect_multiline_flow(
                    lines, remainder, index + 1
                )
                if flow_text is None:
                    errors.append("unreadable flow collection")
                    index += 1
                    continue
                if flow_text.startswith("{"):
                    pairs, flow_errors = _collect_flow_mapping_pairs(flow_text)
                else:
                    pairs, flow_errors = _collect_flow_sequence(flow_text)
                current = _begin_step(steps, None)
                _record_flow_pairs(pairs, flow_errors, uses, using, errors)
                _note_step_actions(current, uses, using, uses_before, using_before)
                for raw_key, raw_value in pairs:
                    if _decode_yaml_scalar(raw_key) == "with":
                        _attach_with_value(current, raw_value)
                index = cursor
                continue
            if remainder:
                if dash_item is not None:
                    current = _begin_step(steps, None)
                _scan_structural_text(remainder, uses, using, errors)
                _note_step_actions(current, uses, using, uses_before, using_before)
            index += 1
            continue
        if dash_item is not None and YAML_BLOCK_SCALAR.match(
            _yaml_strip_trailing_comment(content).strip()
        ):
            # A standalone sequence scalar (`- |` / `- >2-`) is data, not a
            # step mapping. Its body can contain text such as `uses: ...` and
            # must not satisfy the closed action-count allowlist. The dash
            # column is the sequence item's parent indentation; the scalar
            # body is necessarily more indented than it.
            sequence_indent = len(line) - len(stripped)
            index = _skip_block_scalar(lines, index + 1, sequence_indent)
            continue
        flow_step = YAML_FLOW_STEP.match(line)
        if flow_step:
            flow_text, cursor = _collect_multiline_flow(
                lines, line[flow_step.start("flow") :], index + 1
            )
            if flow_text is None:
                errors.append("unreadable flow step")
                index += 1
                continue
            if flow_text.startswith("{"):
                pairs, flow_errors = _collect_flow_mapping_pairs(flow_text)
            else:
                pairs, flow_errors = _collect_flow_sequence(flow_text)
            uses_before = len(uses)
            using_before = len(using)
            current = _begin_step(steps, None)
            _record_flow_pairs(pairs, flow_errors, uses, using, errors)
            _note_step_actions(current, uses, using, uses_before, using_before)
            for raw_key, raw_value in pairs:
                if _decode_yaml_scalar(raw_key) == "with":
                    _attach_with_value(current, raw_value)
            index = cursor
            continue
        parsed = YAML_MAPPING_LINE.match(line)
        if parsed is None:
            if dash_item is not None and _is_plain_sequence_scalar(dash_item.group("item")):
                index += 1
                continue
            errors.append("unreadable YAML structure")
            index += 1
            continue
        key_indent = _yaml_mapping_key_indent(parsed)
        dash = parsed.group("dash")
        decoded_key = _decode_yaml_scalar(parsed.group("key"))
        if dash:
            current = _begin_step(steps, key_indent)
        elif current is not None:
            if current.key_indent is not None and key_indent < current.key_indent:
                current = None
            elif current.key_indent is not None and key_indent == current.key_indent:
                current.collecting_with = False
        raw_value = parsed.group("value")
        value = _yaml_strip_trailing_comment(raw_value).strip()
        had_value_props, remainder = _leading_yaml_node_properties(value)
        if had_value_props:
            errors.append("indirect or tagged YAML node")
        structural = remainder if had_value_props else value
        uses_before = len(uses)
        using_before = len(using)
        if YAML_BLOCK_SCALAR.match(structural):
            if decoded_key in {"uses", "using", "<<"}:
                _record_mapping_pair(parsed.group("key"), raw_value, uses, using, errors)
            _note_step_actions(current, uses, using, uses_before, using_before)
            if (
                current is not None
                and current.collecting_with
                and current.key_indent is not None
                and key_indent > current.key_indent
            ):
                current.with_pairs.append((parsed.group("key"), raw_value))
            if (
                current is not None
                and decoded_key == "with"
                and current.key_indent is not None
                and key_indent == current.key_indent
            ):
                current.with_declarations += 1
                current.with_errors.append("block-scalar with mapping")
            index = _skip_block_scalar(lines, index + 1, key_indent)
            continue
        if structural.startswith("{") or structural.startswith("["):
            flow_text, cursor = _collect_multiline_flow(lines, structural, index + 1)
            if flow_text is None:
                errors.append("unreadable flow collection")
                index += 1
                continue
            if decoded_key in {"uses", "using", "<<"}:
                _record_mapping_pair(parsed.group("key"), raw_value, uses, using, errors)
            if flow_text.startswith("{"):
                pairs, flow_errors = _collect_flow_mapping_pairs(flow_text)
            else:
                pairs, flow_errors = _collect_flow_sequence(flow_text)
            _record_flow_pairs(pairs, flow_errors, uses, using, errors)
            _note_step_actions(current, uses, using, uses_before, using_before)
            if (
                current is not None
                and decoded_key == "with"
                and current.key_indent is not None
                and key_indent == current.key_indent
            ):
                _attach_with_value(current, raw_value)
            elif (
                current is not None
                and current.collecting_with
                and current.key_indent is not None
                and key_indent > current.key_indent
            ):
                current.with_pairs.append((parsed.group("key"), raw_value))
            index = cursor
            continue
        _record_mapping_pair(parsed.group("key"), raw_value, uses, using, errors)
        _note_step_actions(current, uses, using, uses_before, using_before)
        if (
            current is not None
            and decoded_key == "with"
            and current.key_indent is not None
            and key_indent == current.key_indent
        ):
            current.with_declarations += 1
            if not structural:
                current.collecting_with = True
            else:
                current.with_errors.append("unreadable with mapping")
        elif (
            current is not None
            and current.collecting_with
            and current.key_indent is not None
            and key_indent > current.key_indent
        ):
            current.with_pairs.append((parsed.group("key"), raw_value))
        index += 1
    return uses, using, errors, steps


def scan_yaml_action_invocations(text: str) -> tuple[list[str], list[str], list[str]]:
    uses, using, errors, _steps = _scan_yaml_actions(text)
    return uses, using, errors


def _is_inspectable_yaml_scalar(value: str) -> bool:
    """True only for a YAML scalar the description carve-out may blank.

    GitHub renders a string. Flow `{...}` / `[...]`, explicit `?` values,
    compact nested sequences, malformed block indicators, and any other
    structural or unreadable shape stay scanned. Nested `&anchor` properties
    inside a flow collection are invisible to `_leading_yaml_node_properties`,
    which only inspects the start of the node, so a flow value must never be
    treated as rendered description prose.
    """

    if YAML_BLOCK_SCALAR.match(value):
        return True
    if not value:
        return False
    if value[0] in {"'", '"'}:
        return _decode_yaml_scalar(value) is not None
    if value[0] in "{[?|>":
        return False
    if value[0] == "-" and (len(value) == 1 or value[1] in " \t"):
        return False
    if not _yaml_quotes_balanced(value):
        return False
    return True


def _is_root_description_key(parsed: re.Match[str], value: str) -> bool:
    """True only for the root action/workflow metadata `description:` scalar.

    `description` is metadata *at one schema location*: the document root of an
    `action.yml` (or a workflow), where GitHub renders a string and nothing
    evaluates it. A flow mapping, flow sequence, explicit `?` value, or any
    other non-scalar shape is not that string. Relying on GitHub to reject a
    non-string metadata value is not a fail-closed verifier boundary: nested
    `&anchor` names inside `{carrier: &leak exportVariable}` are not leading
    node properties, so blanking the collection would hide the token while
    `env: {description: *leak}` could still feed it into executable data.

    Everywhere else the same spelling is ordinary data whose value is read by
    something: `env: {description: ...}` becomes `process.env.description`,
    `with: {description: ...}` becomes `core.getInput('description')`, and an
    arbitrary nested mapping can be consumed by any `run:` body that reads the
    file. A carrier parked in one of those slots can rebuild the forbidden
    property (`core[process.env.description]`) with no contiguous token left on
    the line, so only the root key may be withheld from the scan.

    Root means column zero with no compact-sequence dash: a `- description:`
    item is a sequence entry, not the root mapping. The value must be an
    inspectable scalar (plain, quoted, or a valid block-scalar indicator) and
    must carry no leading `&anchor` / `*alias` / `!tag` node property, because
    an anchored scalar is reachable by alias from an executable slot elsewhere
    in the document.

    Callers additionally exempt only the *first* such key: an Actions file is a
    single YAML document with one root mapping, so a second root `description:`
    is a duplicate key rather than more rendered metadata.
    """

    if not _is_root_description_mapping_key(parsed):
        return False
    had_properties, remainder = _leading_yaml_node_properties(value)
    if had_properties:
        return False
    return _is_inspectable_yaml_scalar(remainder)


def _is_root_description_mapping_key(parsed: re.Match[str]) -> bool:
    """Return whether this is the unquoted root `description` mapping key."""

    return (
        parsed.group("lead") == ""
        and parsed.group("dash") is None
        and parsed.group("key") == "description"
    )


def _without_yaml_description_prose(text: str) -> str:
    """Blank the root `description:` value only, keeping every other byte.

    A document-root action/workflow `description:` is metadata. GitHub renders
    that scalar; it is never a program, never a step, and never reaches a
    JavaScript runtime, so documenting *which* toolkit call the trusted
    installers refuse to make must not itself read as that call.
    `setup-sccache/action.yml` is whole-file digest-frozen by the Cross build
    policy, so the token rule cannot be made to depend on rewording that prose,
    and its one occurrence is exactly that root scalar.

    Nested `description:` keys — action inputs, `workflow_dispatch` inputs, step
    mappings, `env:`, `with:`, or any other mapping — are *not* exempt. See
    `_is_root_description_key`: those values are action-consumed data, not
    rendered prose, and stripping them would let a carrier build the forbidden
    property indirectly. A root flow mapping, flow sequence, explicit `?`
    value, or any other non-scalar shape is likewise scanned: it is not
    rendered string prose.

    The walk uses the same block-scalar discipline as `_scan_yaml_actions`: a
    `run:` (or any non-description) block-scalar body is stepped over without
    being read, so a `description:`-shaped line *inside* a shell body cannot
    blank the lines after it. Only the root description's own inspectable
    scalar and its correctly delimited block body are blanked, only for the
    unquoted, unaliased, untagged key spelling, and a body that cannot be
    delimited is left in place — so the transform can only ever remove
    root-rendered scalar prose, never an executable or structural slot.
    Exactly one root `description:` is exempted per document; a second is a
    duplicate key and stays scanned.
    """

    lines = text.splitlines()
    index = 0
    saw_root_description = False
    while index < len(lines):
        line = lines[index]
        stripped = line.lstrip(" \t")
        sequence = YAML_SEQUENCE_ITEM.match(line)
        if sequence is not None and YAML_BLOCK_SCALAR.match(
            _yaml_strip_trailing_comment(sequence.group("item")).strip()
        ):
            # `- |` is inert sequence data, not a mapping. Step over its body.
            index = _skip_block_scalar(
                lines, index + 1, len(line) - len(stripped)
            )
            continue
        parsed = YAML_MAPPING_LINE.match(line)
        if parsed is None:
            index += 1
            continue
        key_indent = _yaml_mapping_key_indent(parsed)
        value = _yaml_strip_trailing_comment(parsed.group("value")).strip()
        is_root_description = _is_root_description_mapping_key(parsed)
        prose = (
            not saw_root_description
            and is_root_description
            and _is_root_description_key(parsed, value)
        )
        saw_root_description = saw_root_description or is_root_description
        if prose:
            lines[index] = line[: parsed.start("value")]
        index += 1
        if not YAML_BLOCK_SCALAR.match(value):
            continue
        end = _skip_block_scalar(lines, index, key_indent)
        if prose:
            for body in range(index, end):
                lines[body] = ""
        index = end
    return "\n".join(lines)


def check_no_sccache_credential_exporter(
    text: str,
    source: str,
    failures: list[str],
) -> None:
    for exporter in SCCACHE_EXPORTERS:
        require(
            re.search(
                rf"(?m)^[ \t]*(?:-\s*)?uses:\s*{re.escape(exporter)}@",
                text,
            )
            is None,
            f"{source} must not invoke credential-exporting installer {exporter}",
            failures,
        )
    require(
        # Defense in depth: the contiguous token is insufficient against
        # computed property forms. The allowlist/shell-only checks are the gate.
        # Scanned over everything except the document-root `description:`
        # metadata scalar, so the rule stays a superset of PR #3958's
        # invocation-shaped match on every executable, data, and structural slot
        # while the frozen installers can still document the credential boundary
        # they enforce. Nested `description:` keys (inputs, `env:`, `with:`, any
        # other mapping) and non-scalar root `description:` values are
        # action-consumed or structural data and remain scanned.
        SCCACHE_EXPORT_VARIABLE_TOKEN not in _without_yaml_description_prose(text),
        f"{source} must not contain {SCCACHE_EXPORT_VARIABLE_TOKEN} "
        "(ACTIONS_RUNTIME_TOKEN leak)",
        failures,
    )


def _action_count_drift(
    observed: Counter[str], expected: Counter[str]
) -> tuple[list[str], list[str], list[str]]:
    unknown = sorted(key for key in observed if key not in expected)
    extra_counts: list[str] = []
    missing_counts: list[str] = []
    for key in sorted(set(observed) | set(expected)):
        got = observed[key]
        want = expected[key]
        if got == want:
            continue
        item = f"{key} observed={got} expected={want}"
        if got > want:
            extra_counts.append(item)
        else:
            missing_counts.append(item)
    return unknown, extra_counts, missing_counts


def check_fips_checkout_provenance(
    steps: list[_StepBucket],
    uses: list[str],
    source: str,
    failures: list[str],
) -> None:
    checkout_uses = [item for item in uses if item == CHECKOUT]
    checkout_steps = [step for step in steps if CHECKOUT in step.uses]
    require(
        len(checkout_uses) == FIPS_CHECKOUT_COUNT
        and len(checkout_steps) == FIPS_CHECKOUT_COUNT,
        f"{source} must invoke pinned actions/checkout exactly "
        f"{FIPS_CHECKOUT_COUNT} times with inspectable step mappings; "
        f"uses={len(checkout_uses)} steps={len(checkout_steps)}",
        failures,
    )
    for step in checkout_steps:
        require(
            step.with_declarations == 1,
            f"{source} checkout must declare exactly one inspectable with mapping "
            f"(found {step.with_declarations})",
            failures,
        )
        for error in step.with_errors:
            failures.append(f"{source} checkout {error}")
        persist: str | None = None
        redirected: list[str] = []
        extra: list[str] = []
        seen: set[str] = set()
        for raw_key, raw_value in step.with_pairs:
            key = _decode_yaml_scalar(raw_key)
            if key is None:
                failures.append(f"{source} checkout has an unreadable with key")
                continue
            if key == "<<":
                failures.append(f"{source} checkout with mapping uses a YAML merge key")
                continue
            parsed_value, error = _parse_plain_action_scalar(
                raw_value, "checkout input"
            )
            if error:
                failures.append(f"{source} checkout {error}")
                continue
            if key in seen:
                failures.append(
                    f"{source} checkout declares duplicate with key {key}"
                )
            seen.add(key)
            if key in CHECKOUT_REDIRECT_KEYS:
                redirected.append(key)
            elif key not in CHECKOUT_ALLOWED_WITH_KEYS:
                extra.append(key)
            if key == "persist-credentials":
                persist = parsed_value
            elif key == "fetch-depth" and (
                parsed_value is None or not parsed_value.isdigit()
            ):
                failures.append(
                    f"{source} checkout fetch-depth must be a plain integer, "
                    f"found {parsed_value!r}"
                )
        require(
            persist == "false",
            f"{source} checkout must set persist-credentials: false "
            f"(found {persist!r})",
            failures,
        )
        require(
            not redirected and not extra,
            f"{source} checkout must keep the current-repository/default-ref/"
            f"default-root contract without repository/ref/path redirection; "
            f"redirected={sorted(set(redirected))} extra={sorted(set(extra))}",
            failures,
        )


def check_fips_action_allowlist(
    text: str,
    source: str,
    failures: list[str],
) -> None:
    uses, using, errors, steps = _scan_yaml_actions(text)
    for error in errors:
        failures.append(f"{source} {error}")
    require(
        not using,
        f"{source} must not declare an action runtime (`using:`); JavaScript "
        f"carriers are refused: {using}",
        failures,
    )
    observed = Counter(uses)
    expected = Counter(FIPS_ALLOWED_ACTION_COUNTS)
    unknown, extra_counts, missing_counts = _action_count_drift(observed, expected)
    require(
        not unknown and not extra_counts and not missing_counts and not errors,
        f"{source} action uses must equal the closed FIPS allowlist with exact "
        f"occurrence counts; rejected={unknown} extra=[{'; '.join(extra_counts)}] "
        f"missing=[{'; '.join(missing_counts)}]",
        failures,
    )
    check_fips_checkout_provenance(steps, uses, source, failures)


def check_shell_only_local_action(
    text: str,
    source: str,
    failures: list[str],
) -> None:
    uses, using, errors = scan_yaml_action_invocations(text)
    for error in errors:
        failures.append(f"{source} {error}")
    require(
        not uses and not errors,
        f"{source} must not invoke nested actions; refused uses={uses}",
        failures,
    )
    require(
        using == [SHELL_ONLY_COMPOSITE],
        f"{source} must remain a shell-only composite action; using={using}",
        failures,
    )
    require(
        not any(JS_ACTION_USING.fullmatch(value) for value in using),
        f"{source} must not use a JavaScript action runtime",
        failures,
    )
    check_no_sccache_credential_exporter(text, source, failures)


def check_setup_sccache_verified_activation(
    text: str,
    source: str,
    failures: list[str],
) -> None:
    require(
        'echo "FERRUM_SCCACHE_BIN=" >> "$GITHUB_ENV"' in text,
        f"{source} must publish an empty FERRUM_SCCACHE_BIN sentinel before install",
        failures,
    )
    require(
        'echo "FERRUM_SCCACHE_BIN=${dest}" >> "$GITHUB_ENV"' in text,
        f"{source} must record the checksum-verified executable path",
        failures,
    )
    require(
        "GITHUB_PATH" not in text,
        f"{source} must not put sccache on PATH (PATH lookup can activate an unpinned binary)",
        failures,
    )
    require(
        'echo "RUSTC_WRAPPER=${sccache_bin}" >> "$GITHUB_ENV"' in text,
        f"{source} must set RUSTC_WRAPPER to the verified executable, not a PATH name",
        failures,
    )
    require(
        'echo "CARGO_BUILD_RUSTC_WRAPPER=${sccache_bin}" >> "$GITHUB_ENV"' in text,
        f"{source} must set CARGO_BUILD_RUSTC_WRAPPER to the verified executable",
        failures,
    )
    require(
        'echo "SCCACHE_GHA_ENABLED=" >> "$GITHUB_ENV"' in text,
        f"{source} must persist an empty SCCACHE_GHA_ENABLED value",
        failures,
    )
    require(
        '"$sccache_bin" --start-server' in text and "command -v sccache" not in text,
        f"{source} must invoke only the verified executable, never PATH lookup",
        failures,
    )


def check_performance_cache_wrapper_key(
    workflow: str,
    source: str,
    failures: list[str],
) -> None:
    """Keep runner-unique sccache paths out of the performance cache key."""

    job = extract_job(workflow, "performance-regression")
    require(
        bool(job),
        f"{source} must define performance-regression",
        failures,
    )
    if not job:
        return
    job_env_match = re.search(
        r"(?ms)^    env:\s*\n(?P<body>(?:^      [^\n]*\n)*)",
        job,
    )
    job_env = job_env_match.group("body") if job_env_match is not None else ""
    require(
        re.search(
            r"(?m)^      (?:RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WRAPPER):",
            job_env,
        )
        is None,
        f"{source} performance-regression must not clear the rustc wrapper at "
        "job scope; benchmark builds need the verified sccache wrapper",
        failures,
    )
    steps = job_steps(job)
    setup_steps = [
        (index, step)
        for index, step in enumerate(steps)
        if step_uses(step) == "./.github/actions/setup-rust-ci"
    ]
    require(
        len(setup_steps) == 1,
        f"{source} performance-regression must invoke setup-rust-ci exactly once",
        failures,
    )
    if len(setup_steps) != 1:
        return
    setup_index, setup = setup_steps[0]
    require(
        re.search(
            r'(?m)^        env:\s*\n'
            r'          RUSTC_WRAPPER: ["\']{2}\s*\n'
            r'          CARGO_BUILD_RUSTC_WRAPPER: ["\']{2}\s*$',
            setup,
        )
        is not None,
        f"{source} performance setup-rust-ci step must clear RUSTC_WRAPPER and "
        "CARGO_BUILD_RUSTC_WRAPPER only for the nested rust-cache key calculation",
        failures,
    )
    with_block = step_with(setup)
    require(
        re.search(r'(?m)^          shared-key: ["\']ci-perf["\']\s*$', with_block)
        is not None
        and "tests/performance/mesh -> target" in with_block,
        f"{source} performance setup-rust-ci step must retain the ci-perf shared "
        "key and expanded mesh workspace",
        failures,
    )
    stabilization_steps = [
        (index, step)
        for index, step in enumerate(steps)
        if "name: Stabilize performance compiler wrapper identity" in step
    ]
    require(
        len(stabilization_steps) == 1,
        f"{source} performance-regression must stabilize the verified wrapper "
        "exactly once",
        failures,
    )
    if len(stabilization_steps) != 1:
        return
    stabilization_index, stabilization = stabilization_steps[0]
    require(
        stabilization_index == setup_index + 1,
        f"{source} performance wrapper stabilization must run immediately after "
        "setup-rust-ci and before any benchmark build",
        failures,
    )
    require(
        not step_if(stabilization) and "continue-on-error:" not in stabilization,
        f"{source} performance wrapper stabilization must run unconditionally "
        "after setup-rust-ci and fail the job on an unexpected copy error",
        failures,
    )
    stabilization_contract = (
        "set -euo pipefail",
        'source="${FERRUM_SCCACHE_BIN:-}"',
        '[ -z "$source" ] || [ ! -x "$source" ]',
        "'RUSTC_WRAPPER=' 'CARGO_BUILD_RUSTC_WRAPPER='",
        'stable_root="${RUNNER_TEMP}/ferrum-performance-sccache"',
        'stable_wrapper="${stable_root}/bin/sccache"',
        'rm -rf "$stable_root"',
        'mkdir -p "${stable_root}/bin"',
        'cp -- "$source" "$stable_wrapper"',
        'chmod 0755 "$stable_wrapper"',
        '"RUSTC_WRAPPER=${stable_wrapper}"',
        '"CARGO_BUILD_RUSTC_WRAPPER=${stable_wrapper}"',
        '>> "$GITHUB_ENV"',
    )
    missing = [item for item in stabilization_contract if item not in stabilization]
    require(
        not missing and "GITHUB_PATH" not in stabilization,
        f"{source} performance wrapper stabilization must copy only the verified "
        f"binary to the fixed runner-local path and fail closed to no wrapper; "
        f"missing={missing}",
        failures,
    )


def check_fips_producer_channel(
    workflow: str,
    failures: list[str],
) -> None:
    require(
        f"FIPS_HANDOFF_ARTIFACT: {FIPS_HANDOFF_ARTIFACT_EXPR}" in workflow,
        "FIPS workflow env must define the exact run-attempt handoff artifact as "
        f"{FIPS_HANDOFF_ARTIFACT_EXPR}",
        failures,
    )
    require(
        f"FIPS_HANDOFF_ARTIFACT_PREFIX: {FIPS_HANDOFF_PREFIX_EXPR}" in workflow,
        "FIPS workflow env must define the attempt-independent handoff prefix as "
        f"{FIPS_HANDOFF_PREFIX_EXPR}",
        failures,
    )
    require(
        "--no-absolute-filenames" not in workflow,
        "FIPS workflow must not use BSD-only tar options unsupported by GNU tar "
        "on ubuntu-latest",
        failures,
    )
    require(
        "warm_source_run_id:" in workflow
        and "warm_source_run_attempt:" in workflow
        and "permissions:\n  actions: read\n  contents: read" in workflow,
        "FIPS workflow must expose explicit warm-source run inputs and grant only "
        "read access to Actions artifacts",
        failures,
    )
    compile_job = extract_job(workflow, "fips-compile")
    claimed_job = extract_job(workflow, "fips-claimed-checks")
    clippy_job = extract_job(workflow, "fips-clippy")
    test_build_job = extract_job(workflow, "fips-test-build")
    test_job = extract_job(workflow, "fips-test")
    aggregate = extract_job(workflow, "fips-build")
    mtime_refresh = (
        'find "$target_root" -xdev -type f '
        '\\\n            -exec touch --reference="$mtime_reference" -- {} +'
    )
    compiler_identity_step_name = (
        "Stabilize Cargo compiler identity for exact-target reuse"
    )
    compiler_identity_contract = (
        "FERRUM_SCCACHE_BIN",
        "--stop-server",
        "'RUSTC_WRAPPER='",
        "'CARGO_BUILD_RUSTC_WRAPPER='",
        '>> "$GITHUB_ENV"',
    )
    cmake_quarantine_step_name = (
        "Quarantine restored AWS-LC FIPS CMake state"
    )
    cmake_quarantine_contract = (
        'target_root="${GITHUB_WORKSPACE}/target"',
        '[ -L "$target_root" ]',
        '[ ! -e "$target_root" ]',
        '[ ! -d "$target_root" ]',
        'listing="$(mktemp "${RUNNER_TEMP}/fips-aws-lc-cmake-roots.XXXXXX")"',
        "trap 'rm -f \"$listing\"' EXIT",
        'if ! find "$target_root" -xdev \\',
        '>"$listing"; then',
        'while IFS= read -r -d \'\' cmake_root; do',
        '"$target_root"/*/build/aws-lc-fips-sys-*/out/build',
        '[ ! -d "$cmake_root" ] || [ -L "$cmake_root" ]',
        'rm -rf -- "$cmake_root"',
        "-path '*/build/aws-lc-fips-sys-*/out/build' -prune -print0",
        'done <"$listing"',
        "trap - EXIT",
    )
    restored_binary_checks = (
        'fips_binary="${target_root}/debug/ferrum-edge"',
        '[ ! -f "$fips_binary" ]',
        '[ -L "$fips_binary" ]',
        '[ ! -x "$fips_binary" ]',
    )
    require(bool(test_build_job), "fips-test-build job is missing", failures)
    require(
        workflow.count(mtime_refresh) == 4,
        "FIPS workflow must refresh restored target mtimes exactly once in the "
        "inter-run producer and each of its three exact same-run consumers",
        failures,
    )
    for job_name, job_body in (
        ("fips-compile", compile_job),
        ("fips-claimed-checks", claimed_job),
        ("fips-clippy", clippy_job),
        ("fips-test-build", test_build_job),
    ):
        identity_steps = [
            step
            for step in job_steps(job_body)
            if f"name: {compiler_identity_step_name}" in step
        ]
        require(
            len(identity_steps) == 1,
            f"{job_name} must stabilize the Cargo compiler identity exactly once",
            failures,
        )
        setup_position = job_body.find("uses: ./.github/actions/setup-sccache")
        identity_position = job_body.find(compiler_identity_step_name)
        cache_position = job_body.find(
            "Cache FIPS Rust, AWS-LC, and sccache outputs"
        )
        require(
            setup_position >= 0
            and identity_position >= 0
            and cache_position >= 0
            and setup_position < identity_position < cache_position
            and bool(identity_steps)
            and not step_if(identity_steps[0])
            and all(
                contract in identity_steps[0]
                for contract in compiler_identity_contract
            ),
            f"{job_name} must clear the runner-unique rustc-wrapper identity "
            "after setup-sccache and before any Cargo/cache operation",
            failures,
        )
    cmake_quarantine_steps = [
        step
        for step in job_steps(compile_job)
        if f"name: {cmake_quarantine_step_name}" in step
    ]
    require(
        len(cmake_quarantine_steps) == 1,
        "fips-compile must quarantine restored AWS-LC FIPS CMake state exactly "
        "once",
        failures,
    )
    if cmake_quarantine_steps:
        quarantine_condition = step_if(cmake_quarantine_steps[0])
        require(
            COLD_NOT_TRUE in quarantine_condition
            and "steps.rust-cache.outputs.cache-hit" not in quarantine_condition
            and "continue-on-error:" not in cmake_quarantine_steps[0]
            and all(
                contract in cmake_quarantine_steps[0]
                for contract in cmake_quarantine_contract
            ),
            "fips-compile must fail closed while removing only the restored "
            "aws-lc-fips-sys out/build trees after every non-cold stable-cache "
            "restore attempt",
            failures,
        )
    compile_saves = [
        step for step in job_steps(compile_job) if step_uses(step).startswith(CACHE_SAVE)
    ]
    compile_restores = [
        step
        for step in job_steps(compile_job)
        if step_uses(step).startswith(CACHE_RESTORE)
    ]
    compile_downloads = [
        step
        for step in job_steps(compile_job)
        if step_uses(step).startswith(DOWNLOAD_ARTIFACT)
    ]
    compile_uploads = [
        step
        for step in job_steps(compile_job)
        if step_uses(step).startswith(UPLOAD_ARTIFACT)
    ]
    require(
        "protobuf-compiler zstd" in compile_job,
        "fips-compile must install zstd before extracting or packaging a handoff",
        failures,
    )
    require(
        not compile_saves,
        "fips-compile must not publish the eviction-prone repository cache as a "
        "producer channel; the immutable handoff artifact is the channel, found "
        f"{len(compile_saves)} save steps",
        failures,
    )
    require(
        not compile_restores,
        "fips-compile must not use the eviction-prone repository cache for its "
        f"inter-run handoff; found {len(compile_restores)} restore steps",
        failures,
    )
    require(
        len(compile_downloads) == 1,
        "fips-compile must have exactly one pinned inter-run artifact "
        f"download, found {len(compile_downloads)}",
        failures,
    )
    require(
        len(compile_uploads) == 1,
        "fips-compile must have exactly one pinned producer-handoff artifact "
        f"upload, found {len(compile_uploads)}",
        failures,
    )
    if compile_downloads:
        condition = step_if(compile_downloads[0])
        with_block = step_with(compile_downloads[0])
        require(
            COLD_NOT_TRUE in condition
            and "github.event_name == 'workflow_dispatch'" in condition
            and "inputs.warm_source_run_id != ''" in condition,
            "fips-compile inter-run artifact download must skip force_cold_cache "
            "and require an explicit workflow-dispatch source run",
            failures,
        )
        require(
            f"name: {FIPS_HANDOFF_SOURCE_EXPR}" in with_block,
            "fips-compile must bind the source artifact to the event-stable "
            "source SHA and explicit run/attempt inputs",
            failures,
        )
        require(
            "path: ${{ runner.temp }}/inter-run-fips-handoff" in with_block,
            "fips-compile must stage the inter-run artifact outside the workspace",
            failures,
        )
        require(
            "github-token: ${{ github.token }}" in with_block
            and "repository: ${{ github.repository }}" in with_block
            and "run-id: ${{ inputs.warm_source_run_id }}" in with_block,
            "fips-compile must give only the pinned download action read access to "
            "the exact source run in the current repository",
            failures,
        )
        require(
            "continue-on-error:" not in compile_downloads[0],
            "fips-compile must fail closed when an explicitly requested inter-run "
            "artifact is unavailable",
            failures,
        )
    require(
        "Download exact inter-run FIPS handoff artifact" in compile_job
        and "Promote exact inter-run FIPS handoff artifact" in compile_job
        and "Record inter-run FIPS handoff restore" in compile_job
        and "Record absent inter-run FIPS handoff" in compile_job
        and "inter-run-fips-handoff" in compile_job
        and "steps.inter-run-fips-handoff.outcome == 'success'" in compile_job
        and "layer=inter-run-artifact" in compile_job,
        "fips-compile must download, validate, promote, and record the explicit "
        "same-SHA inter-run handoff artifact",
        failures,
    )
    promote_steps = [
        step
        for step in job_steps(compile_job)
        if "name: Promote exact inter-run FIPS handoff artifact" in step
    ]
    require(
        len(promote_steps) == 1,
        "fips-compile must have exactly one exact-handoff promotion step",
        failures,
    )
    if promote_steps:
        promote_condition = step_if(promote_steps[0])
        require(
            COLD_NOT_TRUE in promote_condition
            and "github.event_name == 'workflow_dispatch'" in promote_condition
            and "inputs.warm_source_run_id != ''" in promote_condition
            and "steps.inter-run-fips-handoff.outcome == 'success'"
            in promote_condition
            and mtime_refresh in promote_steps[0]
            and 'mtime_reference="${RUNNER_TEMP}/fips-target-mtime-reference"'
            in promote_steps[0]
            and 'touch "$mtime_reference"' in promote_steps[0]
            and 'rm -f "$mtime_reference"' in promote_steps[0]
            and all(
                check in promote_steps[0] for check in restored_binary_checks
            )
            and 'tree_manifest="${extract_root}/fips-producer-source-tree"'
            in promote_steps[0]
            and '[ ! -f "$tree_manifest" ] || [ -L "$tree_manifest" ]'
            in promote_steps[0]
            and 'identity="${extract_root}/fips-producer-identity"'
            in promote_steps[0]
            and '[ ! -f "$identity" ] || [ -L "$identity" ]'
            in promote_steps[0]
            and "does not match the named source artifact" in promote_steps[0]
            and "SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}"
            in promote_steps[0]
            and "SOURCE_RUN_ID: ${{ inputs.warm_source_run_id }}"
            in promote_steps[0]
            and "SOURCE_RUN_ATTEMPT: ${{ inputs.warm_source_run_attempt }}"
            in promote_steps[0]
            and 'current_tree="$(git rev-parse HEAD^{tree})"' in promote_steps[0]
            and 'if [ "$archived_tree" != "$current_tree" ]; then'
            in promote_steps[0]
            and "refusing stale-base reuse" in promote_steps[0]
            and "git diff --quiet --no-ext-diff" in promote_steps[0]
            and "git diff --cached --quiet --no-ext-diff" in promote_steps[0]
            and 'if ! tar --zstd -tf "$archive" >"$listing_tmp"; then'
            in promote_steps[0]
            and 'if ! tar --zstd -tvf "$archive" >"$verbose_tmp"; then'
            in promote_steps[0]
            and 'fail "producer handoff archive member uses path traversal"'
            in promote_steps[0]
            and 'fail "producer handoff archive contains a non-file member"'
            in promote_steps[0]
            and '[-]*|d*) ;;' in promote_steps[0]
            and 'if [ "$identity_count" -ne 1 ]; then' in promote_steps[0]
            and '-*) identity_verbose_count=$((identity_verbose_count + 1)) ;;'
            in promote_steps[0]
            and 'tar --zstd --no-same-owner -xf "$archive" -C "$extract_root"'
            in promote_steps[0],
            "fips-compile must refresh mtimes inside the validated exact-handoff "
            "promotion step only after fail-closed archive-member validation, a "
            "successful explicit non-cold download, matching source tree, and "
            "clean tracked checkout",
            failures,
        )
    package_steps = [
        step
        for step in job_steps(compile_job)
        if "name: Package FIPS producer handoff" in step
    ]
    require(
        len(package_steps) == 1,
        "fips-compile must have exactly one producer handoff packaging step",
        failures,
    )
    require(
        "force_cold_cache skipped download" in compile_job
        and "layer=inter-run-artifact" in compile_job
        and "--name inter-run-fips-handoff" in compile_job,
        "fips-compile must record a cold-cache skip for the handoff download "
        "without fabricating a hit",
        failures,
    )
    cache_position = compile_job.find(
        "Cache FIPS Rust, AWS-LC, and sccache outputs"
    )
    quarantine_position = compile_job.find(cmake_quarantine_step_name)
    download_position = compile_job.find(
        "Download exact inter-run FIPS handoff artifact"
    )
    promote_position = compile_job.find("Promote exact inter-run FIPS handoff artifact")
    refresh_position = compile_job.find(mtime_refresh)
    build_position = compile_job.find("Build the FIPS profile")
    package_position = compile_job.find("Package FIPS producer handoff")
    handoff_position = compile_job.find("Publish FIPS producer handoff")
    require(
        cache_position >= 0
        and quarantine_position >= 0
        and download_position >= 0
        and promote_position >= 0
        and refresh_position >= 0
        and build_position >= 0
        and package_position >= 0
        and handoff_position >= 0
        and cache_position < quarantine_position < download_position
        and download_position < promote_position < refresh_position < build_position
        and build_position < package_position < handoff_position,
        "fips-compile must quarantine stable-cache CMake state before an optional "
        "exact inter-run promotion, mtime-refresh that handoff before building, "
        "then publish the packaged immutable handoff",
        failures,
    )
    require(
        'archive="${source_root}/fips-producer-handoff.tar.zst"' in compile_job
        and '[ ! -f "$archive" ] || [ -L "$archive" ]' in compile_job
        and 'tar --zstd --no-same-owner -xf "$archive" -C "$extract_root"'
        in compile_job
        and 'for path in target .cache/sccache; do' in compile_job
        and '[ ! -d "$source_path" ] || [ -L "$source_path" ]' in compile_job,
        "fips-compile must validate the tar payload and both restored directories, "
        "reject symlinks, and preserve archived modes",
        failures,
    )
    require(
        bool(promote_steps)
        and "refusing to refresh restored mtimes" in promote_steps[0],
        "fips-compile must validate the exact restored executable before refreshing "
        "regular target-file mtimes",
        failures,
    )
    require(
        bool(package_steps)
        and COLD_NOT_TRUE in step_if(package_steps[0])
        and 'archive="${RUNNER_TEMP}/fips-producer-handoff.tar.zst"'
        in package_steps[0]
        and 'tree_manifest="${RUNNER_TEMP}/fips-producer-source-tree"'
        in package_steps[0]
        and 'identity="${RUNNER_TEMP}/fips-producer-identity"'
        in package_steps[0]
        and "SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}"
        in package_steps[0]
        and "RUN_ID: ${{ github.run_id }}" in package_steps[0]
        and "RUN_ATTEMPT: ${{ github.run_attempt }}" in package_steps[0]
        and 'source_tree="$(git rev-parse HEAD^{tree})"' in package_steps[0]
        and "git diff --quiet --no-ext-diff" in package_steps[0]
        and "git diff --cached --quiet --no-ext-diff" in package_steps[0]
        and 'printf \'source_sha=%s\\nrun_id=%s\\nrun_attempt=%s\\n\''
        in package_steps[0]
        and 'printf \'%s\\n\' "$source_tree" > "$tree_manifest"'
        in package_steps[0]
        and 'tar --zstd --hard-dereference -cf "$archive" -C "$RUNNER_TEMP"'
        in package_steps[0]
        and "fips-producer-identity fips-producer-source-tree"
        in package_steps[0]
        and '-C "$GITHUB_WORKSPACE" target .cache/sccache'
        in package_steps[0]
        and '[ ! -s "$archive" ] || [ -L "$archive" ]'
        in package_steps[0],
        "fips-compile must package target, sccache, identity, and the clean "
        "checkout tree identity into a nonempty tar.zst handoff that preserves "
        "executable modes and materializes hard-linked outputs as regular files",
        failures,
    )
    require(
        "Precompile FIPS test binaries for consumers" not in compile_job
        and "--test unit_tests --test integration_tests --no-run" not in compile_job
        and "Publish exact FIPS test executables" not in compile_job
        and "fips-test-binaries-${{ github.run_id }}" not in compile_job,
        "fips-compile must remain a build-only producer so test-binary precompile "
        "can overlap claimed-profile and clippy consumers",
        failures,
    )
    if compile_uploads:
        condition = step_if(compile_uploads[0])
        with_block = step_with(compile_uploads[0])
        require(
            COLD_NOT_TRUE in condition,
            "fips-compile handoff artifact upload must skip force_cold_cache",
            failures,
        )
        require(
            "name: ${{ env.FIPS_HANDOFF_ARTIFACT }}" in with_block,
            "fips-compile handoff upload must use the exact run-attempt name",
            failures,
        )
        require(
            "if-no-files-found: error" in with_block
            and "retention-days: 1" in with_block
            and "compression-level: 0" in with_block,
            "fips-compile handoff artifact must be immutable, short-lived, and "
            "avoid recompressing its tar.zst payload",
            failures,
        )
        require(
            "path: ${{ runner.temp }}/fips-producer-handoff.tar.zst" in with_block,
            "fips-compile handoff upload must contain only the packaged producer",
            failures,
        )
    require(
        workflow.count('if ! tar --zstd -tf "$archive" >"$listing_tmp"; then') >= 4,
        "FIPS consumer promotion must capture tar listings in temp files and fail "
        "closed on listing errors",
        failures,
    )
    require(
        'done < <(tar --zstd -tf' not in workflow,
        "FIPS consumer promotion must not read tar listings through process "
        "substitution",
        failures,
    )
    require(
        'tar --zstd -tvf "$archive" "$expected" 2>/dev/null || true' not in workflow,
        "FIPS consumer promotion must not mask tar identity listing failures with "
        "|| true",
        failures,
    )
    require(
        workflow.count('fail "producer handoff archive member uses path traversal"')
        >= 4,
        "FIPS consumer promotion must reject path traversal in archive member names",
        failures,
    )
    require(
        workflow.count('if [ "$identity_count" -ne 1 ]; then') >= 4,
        "FIPS consumer promotion must reject duplicate identity archive members",
        failures,
    )
    require(
        workflow.count('[-]*|d*) ;;') >= 4
        and workflow.count(
            'fail "producer handoff archive contains a non-file member"'
        ) >= 4,
        "FIPS consumer promotion must reject symlink and special tar members",
        failures,
    )
    require(
        workflow.count(
            '-*) identity_verbose_count=$((identity_verbose_count + 1)) ;;'
        ) >= 4,
        "FIPS consumer promotion must require identity members to be regular files",
        failures,
    )
    consumer_promote_contract = (
        'channel_root="${RUNNER_TEMP}/fips-producer-channel"',
        '"$PREFIX"*) ;;',
        'attempt="${name#"$PREFIX"}"',
        "producer handoff channel mixes files and directories",
        "producer handoff channel flattened layout is malformed",
        "producer handoff channel contains an unexpected artifact name",
        "producer handoff channel contains a malformed attempt",
        "producer handoff directory attempt does not match payload identity",
        'payload_dir="$channel_root"',
        'selected_attempt="$identity_attempt"',
        "fips-producer-identity",
        "reject_hostile_tar_member()",
        "assert_identity_member()",
        'mktemp "${RUNNER_TEMP}/fips-tar-listing.XXXXXX")',
        "producer handoff archive listing failed",
        "producer handoff archive verbose listing failed",
        "producer handoff archive identity member listing failed",
        "producer handoff archive contains a non-file member",
        "[-]*|d*) ;;",
        "producer handoff archive listing is inconsistent",
        "producer handoff archive member is malformed",
        "producer handoff archive member uses an absolute path",
        "producer handoff archive member uses path traversal",
        "producer handoff archive identity member is missing or ambiguous",
        "producer handoff archive identity member is not a regular file",
        'if [ -z "$payload_dir" ]',
        "refusing to claim compile-to-consumer reuse",
        'archive="${payload_dir}/fips-producer-handoff.tar.zst"',
        '[ ! -f "$archive" ] || [ -L "$archive" ]',
        'tar --zstd --no-same-owner -xf "$archive" -C "$extract_root"',
        "for path in target .cache/sccache; do",
        '[ ! -d "$source_path" ] || [ -L "$source_path" ]',
        'tree_manifest="${extract_root}/fips-producer-source-tree"',
        '[ ! -f "$tree_manifest" ] || [ -L "$tree_manifest" ]',
        'extracted_identity="${extract_root}/fips-producer-identity"',
        'current_tree="$(git rev-parse HEAD^{tree})"',
        'if [ "$archived_tree" != "$current_tree" ]; then',
        "refusing stale-base reuse",
        "git diff --quiet --no-ext-diff",
        "git diff --cached --quiet --no-ext-diff",
        'mv "${extract_root}/target" "${GITHUB_WORKSPACE}/target"',
        'mv "${extract_root}/.cache/sccache" "${GITHUB_WORKSPACE}/.cache/sccache"',
        'mtime_reference="${RUNNER_TEMP}/fips-target-mtime-reference"',
        'touch "$mtime_reference"',
        'rm -f "$mtime_reference"',
        "refusing to refresh restored mtimes",
    )
    for job_body, job_name in (
        (claimed_job, "fips-claimed-checks"),
        (clippy_job, "fips-clippy"),
        (test_build_job, "fips-test-build"),
    ):
        require(
            "protobuf-compiler zstd" in job_body,
            f"{job_name} must install zstd before extracting the producer handoff",
            failures,
        )
        restores = [
            step
            for step in job_steps(job_body)
            if step_uses(step).startswith(CACHE_RESTORE)
        ]
        saves = [
            step for step in job_steps(job_body) if step_uses(step).startswith(CACHE_SAVE)
        ]
        require(
            not saves,
            f"{job_name} must be a producer-handoff consumer and must not save",
            failures,
        )
        require(
            not restores,
            f"{job_name} must not restore the eviction-prone repository cache "
            "as its producer channel",
            failures,
        )
        downloads = [
            step
            for step in job_steps(job_body)
            if step_uses(step).startswith(DOWNLOAD_ARTIFACT)
        ]
        require(
            len(downloads) == 1,
            f"{job_name} must have exactly one pinned producer-handoff artifact "
            f"download, found {len(downloads)}",
            failures,
        )
        if downloads:
            condition = step_if(downloads[0])
            with_block = step_with(downloads[0])
            require(
                COLD_NOT_TRUE in condition,
                f"{job_name} producer download must skip force_cold_cache",
                failures,
            )
            require(
                FORK_NOT_TRUE not in condition and FORK_IS_TRUE not in condition,
                f"{job_name} producer download must include fork runs; the "
                "run-artifact channel is fork-usable",
                failures,
            )
            require(
                "pattern: ${{ env.FIPS_HANDOFF_ARTIFACT_PREFIX }}*" in with_block,
                f"{job_name} must download the attempt-independent producer "
                "handoff pattern env.FIPS_HANDOFF_ARTIFACT_PREFIX* so failed-job "
                "reruns can reuse an earlier attempt's producer",
                failures,
            )
            require(
                "path: ${{ runner.temp }}/fips-producer-channel" in with_block
                and "merge-multiple: false" in with_block,
                f"{job_name} must stage the producer handoff outside the workspace "
                "and keep merge-multiple false so one-match flattening and "
                "multi-match per-artifact directories stay distinguishable",
                failures,
            )
            require(
                "run-id:" not in with_block and "github-token:" not in with_block,
                f"{job_name} producer download must stay within the current "
                "workflow run",
                failures,
            )
        require(
            "Promote same-run FIPS producer handoff" in job_body,
            f"{job_name} must fail closed when no producer handoff for this "
            "source SHA/run_id was published",
            failures,
        )
        producer_promote_steps = [
            step
            for step in job_steps(job_body)
            if "name: Promote same-run FIPS producer handoff" in step
        ]
        require(
            len(producer_promote_steps) == 1,
            f"{job_name} must have exactly one same-run handoff promotion step",
            failures,
        )
        download_position = job_body.find("Download FIPS producer handoff")
        promote_position = job_body.find("Promote same-run FIPS producer handoff")
        refresh_position = job_body.find(mtime_refresh)
        credential_assert_position = job_body.find(
            "Assert cache-service credentials are absent"
        )
        require(
            download_position >= 0
            and promote_position >= 0
            and refresh_position >= 0
            and credential_assert_position >= 0
            and download_position < promote_position
            and promote_position < refresh_position < credential_assert_position
            and bool(producer_promote_steps)
            and COLD_NOT_TRUE in step_if(producer_promote_steps[0])
            and FORK_NOT_TRUE not in step_if(producer_promote_steps[0])
            and FORK_IS_TRUE not in step_if(producer_promote_steps[0])
            and "PREFIX: ${{ env.FIPS_HANDOFF_ARTIFACT_PREFIX }}"
            in producer_promote_steps[0]
            and "SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}"
            in producer_promote_steps[0]
            and "RUN_ID: ${{ github.run_id }}" in producer_promote_steps[0]
            and "github.run_attempt" not in producer_promote_steps[0]
            and mtime_refresh in producer_promote_steps[0]
            and all(
                contract in producer_promote_steps[0]
                for contract in consumer_promote_contract
            )
            and all(
                check in producer_promote_steps[0]
                for check in restored_binary_checks
            ),
            f"{job_name} must promote the newest attempt-wildcard handoff from "
            "either the one-match flattened payload or per-artifact directories, "
            "bind the attempt from fips-producer-identity, and validate its "
            "payload, source tree, clean checkout, and executable before "
            "refreshing regular target-file mtimes",
            failures,
        )
        require(
            'selected="$channel_root"' not in job_body
            and 'selected_attempt="single"' not in job_body
            and 'selected_attempt="${GITHUB_RUN_ATTEMPT}"' not in job_body
            and "selected_attempt: ${{ github.run_attempt }}" not in job_body
            and 'payload_dir="$channel_root"' in job_body
            and 'selected_attempt="$identity_attempt"' in job_body
            and "producer handoff channel flattened layout is malformed"
            in job_body
            and "producer handoff directory attempt does not match payload identity"
            in job_body,
            f"{job_name} must admit the pinned download action's one-match "
            "flattened payload and multi-match per-artifact directories while "
            "binding attempts from artifact identity rather than the consumer "
            "run attempt or an undocumented direct-root fallback",
            failures,
        )
        require(
            "Drop stable target before producer promotion" in job_body,
            f"{job_name} must drop rust-cache target/sccache before promoting "
            "the SHA-scoped producer handoff",
            failures,
        )
        require(
            "layer=producer" in job_body
            and "transport=same-run-artifact" in job_body,
            f"{job_name} must record the same-run producer handoff separately "
            "from stable fallback",
            failures,
        )
        rust_blocks = rust_cache_with_blocks(job_body)
        if rust_blocks:
            require(
                SAVE_IF_FALSE.search(rust_blocks[0]) is not None,
                f"{job_name} rust-cache must set save-if false so consumers "
                "cannot publish",
                failures,
            )
            require(
                SAVE_IF_NON_FORK.search(rust_blocks[0]) is None,
                f"{job_name} rust-cache must not use the compile producer save-if",
                failures,
            )

    require(
        "--test unit_tests --test integration_tests --no-run" in test_build_job,
        "fips-test-build must compile the exact unit/integration test executables "
        "before the filtered test consumer runs",
        failures,
    )
    require(
        "--message-format=json" in test_build_job
        and "fips-test-bundle" in test_build_job
        and '"sha256"' in test_build_job
        and "fips-test-identity" in test_build_job
        and 'f"run_id={run_id}\\nrun_attempt={run_attempt}\\n"' in test_build_job,
        "fips-test-build must stage digest-bound exact test executables",
        failures,
    )
    require(
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        in test_build_job
        and "if-no-files-found: error" in test_build_job
        and "fips-test-binaries-${{ github.run_id }}-${{ github.run_attempt }}"
        in test_build_job,
        "fips-test-build must publish a pinned, attempt-scoped exact-test artifact",
        failures,
    )
    test_build_precompile = test_build_job.find(
        "Precompile FIPS test binaries for consumers"
    )
    test_build_publish = test_build_job.find("Publish exact FIPS test executables")
    test_build_promote = test_build_job.find(
        "Promote same-run FIPS producer handoff"
    )
    test_build_remove = test_build_job.find("Remove staged FIPS test artifact")
    require(
        test_build_promote >= 0
        and test_build_precompile >= 0
        and test_build_publish >= 0
        and test_build_promote < test_build_precompile < test_build_publish,
        "fips-test-build must promote the compile producer handoff before "
        "precompiling and publishing the exact test artifact",
        failures,
    )
    require(
        test_build_publish >= 0
        and test_build_remove >= 0
        and test_build_publish < test_build_remove,
        "fips-test-build must remove its staged bundle after publishing it",
        failures,
    )
    test_build_uploads = [
        step
        for step in job_steps(test_build_job)
        if step_uses(step).startswith(UPLOAD_ARTIFACT)
    ]
    require(
        len(test_build_uploads) == 1
        and "Publish FIPS producer handoff" not in test_build_job
        and "name: ${{ env.FIPS_HANDOFF_ARTIFACT }}" not in test_build_job,
        "fips-test-build must remain a handoff consumer publishing only the "
        "exact-test artifact; the build-only producer owns the producer handoff",
        failures,
    )
    require(
        "fips-compile" in job_needs_list(test_build_job),
        "fips-test-build must wait for the build-only compile producer",
        failures,
    )
    require(
        "fips-test-build" not in job_needs_list(claimed_job)
        and "fips-test-build" not in job_needs_list(clippy_job),
        "fips-claimed-checks and fips-clippy must not wait for test-binary precompile",
        failures,
    )
    require(
        "fips-test-build" in job_needs_list(test_job),
        "fips-test must wait for the exact test-binary producer",
        failures,
    )
    require(
        "fips-test-build" in job_needs_list(aggregate),
        "FIPS aggregate must depend on the test-binary producer",
        failures,
    )
    require(
        "needs.fips-test-build.result != 'success'" in aggregate,
        "FIPS aggregate must fail closed when the test-binary producer fails",
        failures,
    )

    require(
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        in test_job
        and "pattern: fips-test-binaries-${{ github.run_id }}-*" in test_job
        and "merge-multiple: false" in test_job
        and "FIPS_TEST_ARTIFACT_PREFIX: fips-test-binaries-${{ github.run_id }}-"
        in test_job
        and "FIPS_TEST_RUN_ID: ${{ github.run_id }}" in test_job
        and "fips-test-identity" in test_job
        and "FIPS test artifact channel mixes files and directories" in test_job
        and "admit_bundle(channel, None)" in test_job
        and "does not match payload identity" in test_job
        and "attempts.append((attempt, candidate))" in test_job
        and "_, bundle = max(attempts)" in test_job
        and "GITHUB_RUN_ATTEMPT" not in test_job,
        "fips-test must download the pinned immutable artifacts for this run and "
        "select the newest attempt so failed-job reruns can reuse a skipped "
        "producer's artifact",
        failures,
    )
    require(
        not any(
            step_uses(step).startswith(CACHE_RESTORE)
            or step_uses(step).startswith(CACHE_SAVE)
            for step in job_steps(test_job)
        ),
        "fips-test must consume only the same-run artifact, not shared caches",
        failures,
    )
    require(
        "digest mismatch" in test_job
        and "must not be a symlink" in test_job
        and "candidate.relative_to(bundle)" in test_job,
        "fips-test must fail closed on digest, symlink, or path-boundary violations",
        failures,
    )


def check_rust_cache_fork_save_if(
    text: str,
    source: str,
    failures: list[str],
    *,
    expected_count: int,
) -> None:
    blocks = rust_cache_with_blocks(text)
    require(
        len(blocks) == expected_count,
        f"{source} must have exactly {expected_count} pinned rust-cache "
        f"site(s), found {len(blocks)}",
        failures,
    )
    for index, block in enumerate(blocks, 1):
        require(
            SAVE_IF_NON_FORK.search(block) is not None,
            f"{source} rust-cache site {index} must set save-if so fork PRs "
            "restore only",
            failures,
        )
        require(
            "cache-on-failure:" in block and "true" in block,
            f"{source} rust-cache site {index} must keep cache-on-failure true",
            failures,
        )


def check_rust_cache_trusted_main_save_if(
    text: str,
    source: str,
    failures: list[str],
    *,
    expected_count: int,
) -> None:
    """Require rust-cache saves gated to a trusted `refs/heads/main` run.

    Distinct from `check_rust_cache_fork_save_if`: a site that carries only
    the fork guard still publishes multi-gigabyte PR-merge-ref caches into the
    shared 10 GB quota, so restoring that older shape must fail closed here.
    """

    blocks = rust_cache_with_blocks(text)
    require(
        len(blocks) == expected_count,
        f"{source} must have exactly {expected_count} pinned rust-cache "
        f"site(s), found {len(blocks)}",
        failures,
    )
    for index, block in enumerate(blocks, 1):
        require(
            SAVE_IF_TRUSTED_MAIN.search(block) is not None,
            f"{source} rust-cache site {index} must gate save-if to trusted "
            "refs/heads/main so pull requests and merge groups restore only",
            failures,
        )
        require(
            "cache-on-failure:" in block and "true" in block,
            f"{source} rust-cache site {index} must keep cache-on-failure true",
            failures,
        )


def check_direct_rust_cache_diet(
    job: str,
    source: str,
    failures: list[str],
    *,
    compiler_only: bool,
) -> None:
    blocks = rust_cache_with_blocks(job)
    require(len(blocks) == 1, f"{source} must keep one pinned rust-cache site", failures)
    for block in blocks:
        saves = re.findall(r"(?m)^\s*save-if:([^\n]*)$", block)
        require(
            [value.strip() for value in saves]
            == ["${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"],
            f"{source} must save only on pushes to main",
            failures,
        )
        if compiler_only:
            require(
                re.findall(r"(?m)^\s*cache-targets:([^\n]*)$", block) == [' "false"'],
                f"{source} must not archive the unused root target",
                failures,
            )
        else:
            require(
                not with_has_key(block, "cache-directories"),
                f"{source} must not duplicate sccache alongside target dependencies",
                failures,
            )


def buildkit_cache_key(scope: str) -> str:
    return (
        f"{scope}-{BUILDKIT_CACHE_SCHEMA}-"
        f"${{{{ runner.os }}}}-${{{{ runner.arch }}}}-${{{{ github.sha }}}}"
    )


def buildkit_cache_prefix(scope: str) -> str:
    return (
        f"{scope}-{BUILDKIT_CACHE_SCHEMA}-"
        f"${{{{ runner.os }}}}-${{{{ runner.arch }}}}-"
    )


def check_buildkit_cache_boundary(
    job_body: str,
    source: str,
    failures: list[str],
) -> None:
    steps = [
        step
        for step in job_steps(job_body)
        if step_uses(step).startswith(BUILD_PUSH)
    ]
    trusted_publish = []
    trusted_exact = []
    fork_restore = []
    cold = []
    for step in steps:
        condition = step_if(step)
        with_block = step_with(step)
        has_from = with_has_key(with_block, "cache-from")
        has_to = with_has_key(with_block, "cache-to")
        if FORK_IS_TRUE in condition and FORK_NOT_TRUE not in condition:
            require(
                COLD_NOT_TRUE in condition,
                f"{source} fork restore-only BuildKit step must not run on "
                "force_cold_cache",
                failures,
            )
            require(
                has_from,
                f"{source} fork restore-only BuildKit step must restore cache-from",
                failures,
            )
            require(
                not has_to,
                f"{source} must omit cache-to on the fork restore-only BuildKit step",
                failures,
            )
            require(
                CACHE_KIND_EXACT not in condition,
                f"{source} fork restore-only BuildKit step must not be exact-hit-only",
                failures,
            )
            fork_restore.append(step)
        elif COLD_IS_TRUE in condition and COLD_NOT_TRUE not in condition:
            require(
                not has_from and not has_to,
                f"{source} force-cold BuildKit step must omit cache-from and cache-to",
                failures,
            )
            cold.append(step)
        elif has_to:
            require(
                FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
                f"{source} must exclude fork PRs from every cache-to BuildKit step",
                failures,
            )
            require(
                COLD_NOT_TRUE in condition,
                f"{source} cache-to BuildKit step must not run on force_cold_cache",
                failures,
            )
            require(
                has_from,
                f"{source} trusted-publish BuildKit step must restore cache-from",
                failures,
            )
            require(
                CACHE_KIND_PUBLISH in condition,
                f"{source} trusted-publish BuildKit step must run only on a "
                "partial match or miss (publish == true)",
                failures,
            )
            require(
                CACHE_KIND_EXACT not in condition,
                f"{source} must never export cache-to on an exact github.sha hit",
                failures,
            )
            trusted_publish.append(step)
        elif has_from and not has_to:
            require(
                FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
                f"{source} trusted exact-hit restore-only BuildKit step must "
                "exclude fork PRs",
                failures,
            )
            require(
                COLD_NOT_TRUE in condition,
                f"{source} trusted exact-hit restore-only BuildKit step must "
                "not run on force_cold_cache",
                failures,
            )
            require(
                CACHE_KIND_EXACT in condition,
                f"{source} trusted exact-hit restore-only BuildKit step must "
                "require an exact github.sha hit",
                failures,
            )
            require(
                CACHE_KIND_PUBLISH not in condition,
                f"{source} trusted exact-hit restore-only BuildKit step must "
                "not be the publishing path",
                failures,
            )
            trusted_exact.append(step)
        else:
            failures.append(
                f"{source} has a pinned build-push step that is not a trusted "
                "exact-hit restore-only, trusted-publish, fork restore-only, "
                "or force-cold path"
            )
    require(
        bool(trusted_exact),
        f"{source} must provide a trusted exact-hit restore-only BuildKit step "
        "(cache-from, no cache-to, exact github.sha hit)",
        failures,
    )
    require(
        bool(trusted_publish),
        f"{source} must provide a trusted-publish BuildKit step "
        "(cache-from + cache-to, excluding fork PRs and exact hits)",
        failures,
    )
    require(
        bool(fork_restore),
        f"{source} must provide a fork restore-only BuildKit step "
        "(cache-from, no cache-to, fork PRs only)",
        failures,
    )
    require(
        bool(cold),
        f"{source} must provide a force-cold BuildKit step with neither cache-from "
        "nor cache-to",
        failures,
    )
    require(
        "type=gha" not in job_body,
        f"{source} must not use the BuildKit GHA cache backend",
        failures,
    )


def with_scalar(with_block: str, key: str) -> str:
    match = re.search(
        rf"(?m)^[ \t]*{re.escape(key)}:\s*(.+?)\s*$",
        with_block,
    )
    if match is None:
        return ""
    value = match.group(1).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def check_ambient_image_cache_budget(
    job_body: str,
    source: str,
    failures: list[str],
) -> None:
    require(
        UNCONDITIONAL_AMBIENT_CACHE_TO.search(job_body) is None,
        f"{source} must not publish the Ambient GHA BuildKit cache "
        "unconditionally from pull requests",
        failures,
    )
    steps_by_name: dict[str, str] = {}
    for step in job_steps(job_body):
        match = re.search(r"(?m)^      - name: (.+)$", step)
        if match:
            steps_by_name[match.group(1).strip()] = step
    build_steps = [
        step
        for step in job_steps(job_body)
        if step_uses(step).startswith(BUILD_PUSH)
    ]
    require(
        len(build_steps) == 3,
        f"{source} must keep exactly three pinned build-push steps, found "
        f"{len(build_steps)}",
        failures,
    )
    for name, target in AMBIENT_IMAGE_BUILDS:
        step = steps_by_name.get(name, "")
        require(
            bool(step),
            f"{source} must keep the {name!r} image build",
            failures,
        )
        if not step:
            continue
        require(
            not step_if(step),
            f"{source} must keep {name!r} unconditional; a missing/invalid "
            "event must not skip the required image build",
            failures,
        )
        require(
            step_uses(step).startswith(BUILD_PUSH),
            f"{source} {name!r} must keep the pinned build-push-action",
            failures,
        )
        with_block = step_with(step)
        require(
            with_scalar(with_block, "target") == target,
            f"{source} {name!r} must build target {target}",
            failures,
        )
        require(
            with_scalar(with_block, "load") == "true",
            f"{source} {name!r} must load the image for contract checks",
            failures,
        )
        require(
            with_scalar(with_block, "cache-from") == AMBIENT_GHA_CACHE_FROM,
            f"{source} {name!r} must restore the Ambient GHA BuildKit cache",
            failures,
        )
        require(
            with_scalar(with_block, "cache-to") == AMBIENT_GHA_CACHE_TO,
            f"{source} {name!r} must publish GHA cache only from trusted "
            "refs/heads/main, never from pull_request or merge_group, and "
            "never from a fork",
            failures,
        )
        require(
            FORK_NOT_TRUE in with_scalar(with_block, "cache-to"),
            f"{source} {name!r} cache-to must keep the fork publication guard",
            failures,
        )
    for name in AMBIENT_IMAGE_CONTRACTS:
        require(
            name in steps_by_name,
            f"{source} must keep the {name!r} contract check",
            failures,
        )
        if name in steps_by_name:
            require(
                not step_if(steps_by_name[name]),
                f"{source} must keep {name!r} unconditional",
                failures,
            )


def check_nul_delimited_plan(plan_job: str, source: str, failures: list[str]) -> None:
    require(
        NUL_DIFF in plan_job,
        f"{source} must generate a NUL-delimited trusted diff",
        failures,
    )
    require(
        LINE_DIFF not in plan_job,
        f"{source} must not use line-delimited git diff --name-only",
        failures,
    )
    require(
        "| sort" not in plan_job,
        f"{source} must not pass pathname bytes through sort",
        failures,
    )


def check_local_cache_actions(
    job_body: str,
    source: str,
    failures: list[str],
    *,
    scope: str,
) -> None:
    restore_steps = [
        step for step in job_steps(job_body) if step_uses(step).startswith(CACHE_RESTORE)
    ]
    save_steps = [
        step for step in job_steps(job_body) if step_uses(step).startswith(CACHE_SAVE)
    ]
    require(
        len(restore_steps) == 1,
        f"{source} must have exactly one pinned actions/cache/restore step, "
        f"found {len(restore_steps)}",
        failures,
    )
    require(
        len(save_steps) == 1,
        f"{source} must have exactly one pinned actions/cache/save step, "
        f"found {len(save_steps)}",
        failures,
    )
    key = buildkit_cache_key(scope)
    prefix = buildkit_cache_prefix(scope)
    if restore_steps:
        condition = step_if(restore_steps[0])
        with_block = step_with(restore_steps[0])
        require(
            COLD_NOT_TRUE in condition,
            f"{source} cache restore must skip force_cold_cache",
            failures,
        )
        require(
            FORK_IS_TRUE not in condition or FORK_NOT_TRUE in condition,
            f"{source} cache restore may run for forks but must not be fork-only "
            "in a way that skips trusted restores",
            failures,
        )
        require(
            f"key: {key}" in with_block,
            f"{source} cache restore must use exact key {key}",
            failures,
        )
        require(
            "restore-keys:" in with_block and prefix in with_block,
            f"{source} cache restore must use restore prefix {prefix}",
            failures,
        )
        require(
            "${{ runner.arch }}" in with_block,
            f"{source} cache restore must be architecture-scoped",
            failures,
        )
        require(
            BUILDKIT_CACHE_SCHEMA in with_block,
            f"{source} cache restore must include schema {BUILDKIT_CACHE_SCHEMA}",
            failures,
        )
    if save_steps:
        condition = step_if(save_steps[0])
        with_block = step_with(save_steps[0])
        require(
            COLD_NOT_TRUE in condition,
            f"{source} cache save must skip force_cold_cache",
            failures,
        )
        require(
            FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
            f"{source} must exclude fork PRs from cache save / publication",
            failures,
        )
        require(
            CACHE_KIND_PUBLISH in condition,
            f"{source} cache save must run only after a partial match or miss",
            failures,
        )
        require(
            CACHE_KIND_EXACT not in condition,
            f"{source} must never save an immutable cache on an exact github.sha hit",
            failures,
        )
        require(
            f"key: {key}" in with_block,
            f"{source} cache save must use exact key {key}",
            failures,
        )


def check_cache_save_preparation(
    job_body: str,
    source: str,
    failures: list[str],
    *,
    scope: str,
) -> None:
    prepare_steps = [
        step
        for step in job_steps(job_body)
        if "Prepare BuildKit cache for save" in step
    ]
    require(
        len(prepare_steps) == 1,
        f"{source} must have exactly one Prepare BuildKit cache for save step, "
        f"found {len(prepare_steps)}",
        failures,
    )
    if not prepare_steps:
        return
    step = prepare_steps[0]
    condition = step_if(step)
    require(
        COLD_NOT_TRUE in condition,
        f"{source} cache-save preparation must skip force_cold_cache",
        failures,
    )
    require(
        FORK_NOT_TRUE in condition and FORK_IS_TRUE not in condition,
        f"{source} cache-save preparation must exclude fork PRs",
        failures,
    )
    require(
        CACHE_KIND_PUBLISH in condition,
        f"{source} cache-save preparation must run only after a partial match or miss",
        failures,
    )
    require(
        CACHE_KIND_EXACT not in condition,
        f"{source} cache-save preparation must not run on an exact github.sha hit",
        failures,
    )
    out_dir = f"{scope}-out"
    require(
        out_dir in step,
        f"{source} cache-save preparation must require the fresh {out_dir} directory",
        failures,
    )
    require(
        'if [ ! -d "$out" ]' in step or "if [ ! -d \"$out\" ]" in step,
        f"{source} cache-save preparation must fail when the fresh export is absent",
        failures,
    )
    require(
        "refusing to save" in step and "stale" in step,
        f"{source} cache-save preparation must refuse to relabel a stale restore",
        failures,
    )
    require(
        "present=true" not in step,
        f"{source} cache-save preparation must not mark a stale destination as present",
        failures,
    )


def check_cache_telemetry_evidence(job_body: str, source: str, failures: list[str]) -> None:
    require(
        '--hit ""' not in job_body and "--hit ''" not in job_body,
        f"{source} must not pass empty --hit (unknown is not a miss)",
        failures,
    )
    require(
        "--hit true" not in job_body,
        f"{source} must not fabricate a cache hit literal",
        failures,
    )
    require(
        "cache-hit" in job_body and "cache-matched-key" in job_body,
        f"{source} must record restore evidence from action outputs",
        failures,
    )
    require(
        "classify-restore" in job_body,
        f"{source} must classify actions/cache/restore v4 outputs via classify-restore",
        failures,
    )
    require(
        "id: cache-kind" in job_body,
        f"{source} must expose cache-kind outputs for exact vs publish gating",
        failures,
    )
    require(
        "--path" in job_body,
        f"{source} must measure restored bytes from the restored directory",
        failures,
    )
    require(
        "--phase cache-restore" in job_body
        and "--phase image-build" in job_body
        and "--phase cache-save" in job_body,
        f"{source} must time cache-restore, image-build, and cache-save separately",
        failures,
    )


def remote_uses(text: str) -> list[str]:
    refs: list[str] = []
    for match in USES.finditer(text):
        ref = match.group("ref")
        if ref.startswith("./") or ref.startswith("${{"):
            continue
        refs.append(ref.split("#", 1)[0].strip())
    return refs


def pin_errors(text: str, source: str) -> list[str]:
    failures: list[str] = []
    for ref in remote_uses(text):
        parsed = PINNED_REMOTE.fullmatch(ref)
        if parsed is None:
            failures.append(f"{source} has an unpinned or mutable uses ref: {ref}")
        elif not SHA40.fullmatch(parsed.group("pin")):
            failures.append(f"{source} pin is not a 40-char SHA: {ref}")
    return failures


def builder_arg_features_is_after_apt(dockerfile: str) -> bool:
    # The base is digest-pinned (`rust:<tag>@sha256:...`), so match the stage
    # rather than one literal reference; a pin refresh must not silently turn
    # this contract into a no-op by failing to find its marker.
    match = re.search(
        r"^FROM rust(?::[^\s@]+)?(?:@sha256:[0-9a-f]{64})? AS builder$",
        dockerfile,
        re.M,
    )
    if match is None:
        return False
    rest = dockerfile[match.end() :]
    next_from = rest.find("\nFROM ")
    body = rest if next_from < 0 else rest[:next_from]
    apt = body.find("apt-get update")
    features = body.find("ARG FEATURES")
    return apt >= 0 and features > apt


DOCUMENTED_LOG_LEVEL_DEFAULT = "warn"


def ferrum_log_level_assignments(dockerfile: str) -> list[str]:
    """Every `FERRUM_LOG_LEVEL=<value>` baked into a Dockerfile's runtime ENV.

    The assignments live inside multi-line `ENV ... \\` continuations, so match
    the assignment token itself rather than a line that starts with `ENV`.
    """

    return re.findall(r"\bFERRUM_LOG_LEVEL=([^\s\\]+)", dockerfile)


def check_dockerfile_log_level(
    label: str, dockerfile: str, failures: list[str]
) -> None:
    """Every published runtime image must bake the documented log-level default."""

    values = ferrum_log_level_assignments(dockerfile)
    require(
        bool(values),
        f"{label} must bake a FERRUM_LOG_LEVEL default; found none (a rename or "
        "deletion must fail closed, not pass vacuously)",
        failures,
    )
    offenders = sorted({value for value in values if value != DOCUMENTED_LOG_LEVEL_DEFAULT})
    require(
        not offenders,
        f"{label} sets FERRUM_LOG_LEVEL={', '.join(offenders)}; every published "
        f"runtime stage must use '{DOCUMENTED_LOG_LEVEL_DEFAULT}' so the startup "
        "operability warnings stay visible (docs/configuration.md, docs/docker.md)",
        failures,
    )


DIGEST_PINNED_REFERENCE = re.compile(r"@sha256:[0-9a-f]{64}$")
DIGESTLESS_BASES = frozenset({"scratch"})


def _arg_value_looks_like_image(value: str) -> bool:
    """Whether an `ARG NAME=<value>` default names a registry image.

    Version and checksum defaults (`6.15.0-1`, a bare hex SHA-256) carry neither
    a registry path nor a tag, so they are not build inputs this contract binds.
    """

    if "${" in value:
        return False
    if "/" in value:
        return True
    return re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*:[^\s]+", value) is not None


def dockerfile_image_references(dockerfile: str) -> list[tuple[int, str, str]]:
    """Every registry image reference a Dockerfile pulls, as (line, kind, ref).

    `FROM <stage>` targets that name an earlier `AS` alias are internal edges,
    and `FROM ${VAR}` is an indirection whose `ARG` default is bound instead, so
    neither is a registry input.
    """

    stages: set[str] = set()
    references: list[tuple[int, str, str]] = []
    for number, line in enumerate(dockerfile.splitlines(), start=1):
        stripped = line.strip()
        from_match = re.fullmatch(
            r"FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?",
            stripped,
            re.IGNORECASE,
        )
        if from_match is not None:
            target, alias = from_match.group(1), from_match.group(2)
            internal = target.lower() in stages or target.startswith("${")
            if not internal and target.lower() not in DIGESTLESS_BASES:
                references.append((number, "FROM", target))
            if alias:
                stages.add(alias.lower())
            continue
        arg_match = re.fullmatch(r"ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", stripped)
        if arg_match is not None and _arg_value_looks_like_image(arg_match.group(2)):
            references.append((number, f"ARG {arg_match.group(1)}", arg_match.group(2)))
    return references


def check_dockerfile_image_pins(
    label: str, dockerfile: str, failures: list[str]
) -> None:
    """Every container build input must be pinned by immutable digest.

    A tag is mutable: the bytes a published image was built from would not be
    recoverable, and a compromised or silently re-pushed tag would reach the
    release images with nothing failing. `scratch` is the sole exception.
    """

    references = dockerfile_image_references(dockerfile)
    require(
        bool(references),
        f"{label} must declare at least one registry image reference; found none "
        "(a rewrite must fail closed, not pass this contract vacuously)",
        failures,
    )
    for number, kind, reference in references:
        require(
            DIGEST_PINNED_REFERENCE.search(reference) is not None,
            f"{label}:{number} {kind} uses the unpinned image reference "
            f"'{reference}'; every container build input must carry an "
            "@sha256:<64 hex> digest (docs/dependency-policy.md -> "
            "'Container build inputs')",
            failures,
        )
        require(
            not (
                "@sha256:" not in reference
                and reference.rsplit(":", 1)[-1] == "latest"
            ),
            f"{label}:{number} {kind} uses the mutable tag '{reference}'; "
            "':latest' is only admissible alongside an @sha256: digest",
            failures,
        )


def workflow_permissions_are_read_only(text: str) -> bool:
    """Require one explicit top-level permissions map with no write grants."""

    lines = text.splitlines()
    indexes = [index for index, line in enumerate(lines) if line == "permissions:"]
    if len(indexes) != 1:
        return False

    entries: dict[str, str] = {}
    for line in lines[indexes[0] + 1 :]:
        if line and not line.startswith(" "):
            break
        if not line:
            continue
        match = re.fullmatch(r"  ([a-z][a-z-]*): (read|write|none)", line)
        if match is None:
            return False
        name, access = match.groups()
        if name in entries:
            return False
        entries[name] = access

    return entries.get("contents") == "read" and "write" not in entries.values()


def check_common_trust(text: str, source: str, failures: list[str]) -> None:
    require(
        workflow_permissions_are_read_only(text),
        f"{source} must keep one explicit read-only workflow permissions block "
        "with contents: read",
        failures,
    )
    require(
        "ACTIONS_RUNTIME_TOKEN" not in text
        or "GITHUB_ENV" not in text.split("ACTIONS_RUNTIME_TOKEN", 1)[-1][:400],
        f"{source} must not export ACTIONS_RUNTIME_TOKEN into GITHUB_ENV",
        failures,
    )
    require(
        "SCCACHE_GHA_ENABLED=true" not in text,
        f"{source} must not enable the sccache GHA backend",
        failures,
    )
    failures.extend(pin_errors(text, source))


def check_fips(workflow: str, failures: list[str]) -> None:
    require(
        'name: FIPS Build Policy' in workflow.splitlines()[0]
        or workflow.startswith("name: FIPS Build Policy"),
        "fips-build.yml must keep workflow name FIPS Build Policy",
        failures,
    )
    require(
        re.search(r"(?m)^    name: FIPS Feature Policy$", workflow) is not None,
        "FIPS Feature Policy job name must be preserved",
        failures,
    )
    require(
        re.search(r"(?m)^    name: FIPS Build & Test$", workflow) is not None,
        "FIPS Build & Test required-check name must be preserved",
        failures,
    )
    require(
        f"shared-key: {FIPS_SHARED_KEY}" in workflow,
        "FIPS jobs must share rust-cache shared-key ci-fips-contract-${{ hashFiles(...) }}",
        failures,
    )
    require(
        "shared-key: ci-fips\n" not in workflow
        and 'shared-key: "ci-fips"' not in workflow
        and "shared-key: ci-fips\r" not in workflow,
        "FIPS rust-cache must not use the old ignored shared-key: ci-fips + key: shape",
        failures,
    )
    compile_job = extract_job(workflow, "fips-compile")
    claimed_job = extract_job(workflow, "fips-claimed-checks")
    clippy_job = extract_job(workflow, "fips-clippy")
    test_build_job = extract_job(workflow, "fips-test-build")
    test_job = extract_job(workflow, "fips-test")
    aggregate = extract_job(workflow, "fips-build")
    fips_contract_inputs = (
        "'Cargo.toml'",
        "'Cargo.lock'",
        "'.cargo/config.toml'",
        "'build.rs'",
        "'.github/workflows/fips-build.yml'",
        "'.github/scripts/check_fips_feature_policy.py'",
        "'src/fips/**'",
        "'vendor/**'",
    )
    for job_body, job_name in (
        (compile_job, "fips-compile"),
        (claimed_job, "fips-claimed-checks"),
        (clippy_job, "fips-clippy"),
        (test_build_job, "fips-test-build"),
    ):
        blocks = rust_cache_with_blocks(job_body)
        require(
            len(blocks) == 1,
            f"{job_name} must expose one auditable rust-cache contract key",
            failures,
        )
        if len(blocks) == 1:
            block = blocks[0]
            check_rust_cache_uses_shared_key_only(
                block,
                job_name,
                failures,
                expected_shared_key=FIPS_SHARED_KEY,
            )
            for contract_input in fips_contract_inputs:
                require(
                    contract_input in block,
                    f"{job_name} FIPS cache contract key must include {contract_input}",
                    failures,
                )
    require(
        "cache-on-failure: \"true\"" in workflow or "cache-on-failure: 'true'" in workflow
        or "cache-on-failure: true" in workflow,
        "FIPS rust-cache must save after ordinary failures when post-job cleanup still runs",
        failures,
    )
    require(
        "./.github/actions/setup-sccache" in workflow,
        "FIPS jobs must install sccache through the local action",
        failures,
    )
    require(
        "command -v sccache" not in workflow,
        "FIPS jobs must not PATH-lookup sccache after the trusted installer",
        failures,
    )
    require(
        workflow.count('sccache_bin="${FERRUM_SCCACHE_BIN:-}"') == 4
        and workflow.count('"$sccache_bin" --show-stats') == 4,
        "FIPS compile/claimed-checks/clippy/test-binary jobs must record sccache "
        "stats via FERRUM_SCCACHE_BIN",
        failures,
    )
    require(
        "FERRUM_CUSTOM_PLUGINS" not in workflow,
        "FIPS jobs must not opt example plugins into the cryptographic artifact",
        failures,
    )
    require(
        "cargo build --locked --no-default-features --features fips --bin ferrum-edge"
        in workflow,
        "FIPS compile must still build the locked fips binary",
        failures,
    )
    require(
        "--list-claimed-profiles" in workflow,
        "FIPS claimed-profile enumeration must stay driven by the policy checker",
        failures,
    )
    require(
        "name: FIPS claimed feature combinations (${{ matrix.shard_name }})"
        in claimed_job,
        "FIPS claimed-profile checks must expose their deterministic shard name",
        failures,
    )
    require(
        "fail-fast: false" in claimed_job
        and claimed_job.count("shard_index:") == 3
        and "shard_index: 0" in claimed_job
        and "shard_index: 1" in claimed_job
        and "shard_index: 2" in claimed_job
        and "shard_name: 1-of-3" in claimed_job
        and "shard_name: 2-of-3" in claimed_job
        and "shard_name: 3-of-3" in claimed_job,
        "FIPS claimed-profile checks must use all three fail-fast-disabled shards",
        failures,
    )
    require(
        "FIPS_CLAIMED_SHARD_INDEX: ${{ matrix.shard_index }}" in claimed_job
        and "FIPS_CLAIMED_SHARD_COUNT: 3" in claimed_job
        and "profile_index % FIPS_CLAIMED_SHARD_COUNT" in claimed_job
        and "profile_index=$((profile_index + 1))" in claimed_job
        and "selected=$((selected + 1))" in claimed_job
        and 'profiles_file="$(mktemp)"' in claimed_job
        and '--list-claimed-profiles > "$profiles_file"' in claimed_job
        and 'done < "$profiles_file"' in claimed_job
        and "< <(" not in claimed_job
        and '[ "$selected" -eq 0 ]' in claimed_job,
        "FIPS claimed-profile shards must partition the checker-owned inventory "
        "by ordinal, fail closed when enumeration fails, and reject an empty shard",
        failures,
    )
    require(
        "cargo clippy --locked --no-default-features --features fips" in workflow,
        "FIPS clippy must still lint the fips profile",
        failures,
    )
    require("-D warnings" in workflow, "FIPS clippy must keep -D warnings", failures)
    require(
        "tls::fips_policy_tests" in workflow,
        "FIPS policy tests must remain in the live gate",
        failures,
    )
    require(
        "tls::fips_key_admission_tests" in workflow,
        "FIPS key-admission tests must remain in the live gate",
        failures,
    )
    require(
        '"$unit_test_binary" tls::fips_' in test_job,
        "FIPS unit test binary must use one tls::fips_ TESTNAME prefix",
        failures,
    )
    require(
        "cargo test" not in test_job,
        "FIPS test consumer must execute producer-recorded binaries directly so "
        "fresh-checkout mtimes cannot trigger a rebuild",
        failures,
    )
    require(
        re.search(
            r"cargo test[^\n]*tls::fips_policy_tests[^\n]+tls::fips_key_admission_tests",
            workflow,
        )
        is None,
        "FIPS unit tests must not pass two Cargo TESTNAME filters to one invocation",
        failures,
    )
    require(
        "frontend_and_backend_builders_complete_a_real_tls_handshake" in workflow,
        "FIPS frontend/backend handshake coverage must remain",
        failures,
    )
    require(
        "legitimate_data_plane_connects_once_a_permit_is_released" in workflow,
        "FIPS CP/DP handshake coverage must remain",
        failures,
    )
    require(
        test_job.count('"$integration_test_binary"') == 2,
        "FIPS handshake filters must execute the restored integration test binary twice",
        failures,
    )
    require(
        re.search(
            r"cargo test[^\n]*frontend_and_backend_builders_complete_a_real_tls_handshake"
            r"[^\n]+legitimate_data_plane_connects_once_a_permit_is_released",
            workflow,
        )
        is None,
        "FIPS handshake tests must not pass two Cargo TESTNAME filters to one invocation",
        failures,
    )
    plan_job = extract_job(workflow, "fips-plan")
    planner_path_lines = tuple(
        line.strip()
        for line in plan_job.splitlines()
        if FIPS_PLANNER_PATH in line
    )
    expected_planner_path_lines = (
        f'if ! git cat-file -e "${{trusted_sha}}:{FIPS_PLANNER_PATH}" 2>/dev/null; then',
        (
            f'echo "trusted base has not adopted {FIPS_PLANNER_PATH}; '
            'running the full gate." >> "$GITHUB_STEP_SUMMARY"'
        ),
        f'entry="$(git ls-tree --full-tree "$trusted_sha" -- {FIPS_PLANNER_PATH})"',
        f'echo "::error::{FIPS_PLANNER_PATH} is not a single tree entry at ${{trusted_sha}}" >&2',
        f'if [ "$entry_type" != "blob" ] || [ "$entry_path" != "{FIPS_PLANNER_PATH}" ]; then',
        f'echo "::error::{FIPS_PLANNER_PATH} is not a blob at ${{trusted_sha}}" >&2',
        f'echo "::error::{FIPS_PLANNER_PATH} has non-regular mode ${{entry_mode}}" >&2',
        f'echo "::error::{FIPS_PLANNER_PATH} did not resolve to an object id" >&2',
        f'echo "::error::{FIPS_PLANNER_PATH} exceeds the 256 KiB trusted-filter ceiling" >&2',
        f'proposed_entry="$(git ls-tree --full-tree HEAD -- {FIPS_PLANNER_PATH})"',
        f'echo "::error::{FIPS_PLANNER_PATH} must be a regular blob in the proposed checkout" >&2',
        f'git cat-file blob "$entry_object" > {FIPS_PLANNER_PATH}',
        f'if [ "$(git hash-object {FIPS_PLANNER_PATH})" != "$entry_object" ]; then',
        f"python3 -I {FIPS_PLANNER_PATH} --self-test",
        f'plan="$(python3 -I {FIPS_PLANNER_PATH} "${{filter_args[@]}}")"',
    )
    require(
        "filter_path" not in plan_job
        and planner_path_lines == expected_planner_path_lines
        and "trusted_filter=" not in plan_job
        and 'python3 -I "$trusted_filter"' not in plan_job,
        "FIPS planner must use only the frozen literal repository path for every "
        "trusted lookup, materialization, hash check, and execution; mutable path "
        "aliases are forbidden",
        failures,
    )
    require(
        f"git ls-tree --full-tree HEAD -- {FIPS_PLANNER_PATH}" in plan_job
        and '"100644 blob "*' in plan_job
        and '"100755 blob "*' in plan_job,
        "FIPS planner must reject a non-regular proposed planner path before "
        "materializing trusted bytes",
        failures,
    )
    check_nul_delimited_plan(plan_job, "FIPS planner", failures)
    require(
        "relevant=true" in workflow and "trusted base has not adopted" in workflow,
        "FIPS planner must fail closed toward running when the trusted copy is missing",
        failures,
    )
    require(
        "force_cold_cache" in workflow,
        "FIPS workflow must expose a cold-cache dispatch input",
        failures,
    )
    compile_job = extract_job(workflow, "fips-compile")
    claimed_job = extract_job(workflow, "fips-claimed-checks")
    clippy_job = extract_job(workflow, "fips-clippy")
    test_build_job = extract_job(workflow, "fips-test-build")
    aggregate = extract_job(workflow, "fips-build")
    require(bool(compile_job), "fips-compile job is missing", failures)
    require(bool(claimed_job), "fips-claimed-checks job is missing", failures)
    require(bool(clippy_job), "fips-clippy job is missing", failures)
    require(bool(test_build_job), "fips-test-build job is missing", failures)
    require(bool(test_job), "fips-test job is missing", failures)
    require(
        "needs.fips-plan.outputs.relevant == 'true'" in compile_job,
        "fips-compile must be bound to the trusted planner",
        failures,
    )
    require(
        "fips-compile" in job_needs_list(claimed_job),
        "fips-claimed-checks must wait for the compile producer handoff to be published",
        failures,
    )
    require(
        "fips-compile" in job_needs_list(clippy_job),
        "fips-clippy must wait for the compile producer handoff to be published",
        failures,
    )
    require(
        "fips-compile" in job_needs_list(test_build_job),
        "fips-test-build must wait for the compile producer handoff to be published",
        failures,
    )
    require(
        "fips-test-build" in job_needs_list(test_job),
        "fips-test must wait for the exact test-binary producer",
        failures,
    )
    require(
        "fips-test-build" not in job_needs_list(claimed_job)
        and "fips-test-build" not in job_needs_list(clippy_job),
        "claimed-profile and clippy consumers must overlap test-binary precompile "
        "instead of waiting for it",
        failures,
    )
    require(
        re.search(r"(?m)^    if: always\(\)$", aggregate) is not None,
        "FIPS Build & Test aggregate must run with if: always()",
        failures,
    )
    check_aggregate_planner_contract(
        aggregate,
        "fips-plan",
        "FIPS Build & Test",
        failures,
    )
    require(
        RUST_CACHE in workflow,
        "FIPS workflow must pin Swatinem/rust-cache",
        failures,
    )
    require(
        RUST_TOOLCHAIN in workflow,
        "FIPS workflow must pin dtolnay/rust-toolchain",
        failures,
    )
    check_rust_cache_fork_save_if(
        compile_job,
        "fips-compile",
        failures,
        expected_count=1,
    )
    check_fips_producer_channel(workflow, failures)
    check_fips_action_allowlist(workflow, "fips-build.yml", failures)
    check_no_sccache_credential_exporter(workflow, "fips-build.yml", failures)
    for job_body, job_name in (
        (compile_job, "fips-compile"),
        (claimed_job, "fips-claimed-checks"),
        (clippy_job, "fips-clippy"),
        (test_build_job, "fips-test-build"),
    ):
        check_credential_absence_assertion(job_body, job_name, failures)
        cargo_idx = job_body.find("cargo ")
        assert_idx = job_body.find("Assert cache-service credentials are absent")
        require(
            assert_idx != -1 and cargo_idx != -1 and assert_idx < cargo_idx,
            f"{job_name} must assert cache credentials are absent before cargo",
            failures,
        )
        require(
            "sccache-directory-subset" in job_body
            and "not exposed" in job_body
            and "layer=stable-fallback" in job_body,
            f"{job_name} must label rust-cache as stable-fallback and state that "
            "archive bytes are not exposed",
            failures,
        )
        require(
            "--name rust-cache" in job_body,
            f"{job_name} may still record rust-cache hit/miss from the action output",
            failures,
        )
    check_credential_absence_assertion(test_job, "fips-test", failures)
    require(
        "cargo " not in test_job,
        "fips-test must execute the immutable artifact without invoking Cargo",
        failures,
    )
    require(
        {"fips-plan", "fips-compile", "fips-claimed-checks", "fips-clippy",
         "fips-test-build", "fips-test"} <= job_needs_list(aggregate),
        "FIPS Build & Test aggregate must depend on every expensive FIPS job "
        "including the test-binary producer",
        failures,
    )
    require(
        "needs.fips-compile.result != 'success'" in aggregate,
        "FIPS aggregate must fail closed when compile fails",
        failures,
    )
    require(
        "needs.fips-claimed-checks.result != 'success'" in aggregate,
        "FIPS aggregate must fail closed when claimed-profile checks fail",
        failures,
    )
    require(
        "needs.fips-clippy.result != 'success'" in aggregate,
        "FIPS aggregate must fail closed when clippy fails",
        failures,
    )
    require(
        "needs.fips-test-build.result != 'success'" in aggregate,
        "FIPS aggregate must fail closed when the test-binary producer fails",
        failures,
    )
    require(
        "needs.fips-test.result != 'success'" in aggregate,
        "FIPS aggregate must fail closed when tests fail",
        failures,
    )


def check_production_smoke(workflow: str, failures: list[str]) -> None:
    require(
        re.search(r"(?m)^    name: Production Dockerfile eBPF image smoke$", workflow)
        is not None,
        "Production Dockerfile eBPF image smoke check name must be preserved",
        failures,
    )
    default_job = extract_job(workflow, "production-dockerfile-smoke-default")
    ebpf_job = extract_job(workflow, "production-dockerfile-smoke-ebpf")
    aggregate = extract_job(workflow, "production-dockerfile-smoke")
    require(bool(default_job), "default production-image job is missing", failures)
    require(bool(ebpf_job), "eBPF production-image job is missing", failures)
    require(
        BUILDX in default_job and BUILD_PUSH in default_job,
        "default production-image job must use pinned buildx and build-push-action",
        failures,
    )
    require(
        BUILDX in ebpf_job and BUILD_PUSH in ebpf_job,
        "eBPF production-image job must use pinned buildx and build-push-action",
        failures,
    )
    require(
        "target: runtime" in default_job or "target: runtime\n" in default_job,
        "default production-image job must build the ordinary runtime target",
        failures,
    )
    require(
        "target: runtime-ebpf" in ebpf_job,
        "eBPF production-image job must build runtime-ebpf",
        failures,
    )
    require(
        "FEATURES=cloud-secrets,ebpf" in ebpf_job,
        "eBPF production-image job must keep FEATURES=cloud-secrets,ebpf",
        failures,
    )
    check_buildkit_cache_boundary(
        default_job,
        "production-dockerfile-smoke-default",
        failures,
    )
    check_buildkit_cache_boundary(
        ebpf_job,
        "production-dockerfile-smoke-ebpf",
        failures,
    )
    require(
        "trusted-publish" in default_job
        and "fork-restore-only" in default_job
        and "trusted-publish" in ebpf_job
        and "fork-restore-only" in ebpf_job,
        "production-image telemetry must name the trusted-publish and "
        "fork-restore-only cache-to policies",
        failures,
    )
    require(
        "type=local" in default_job
        and buildkit_cache_key("production-dockerfile-smoke-default") in default_job,
        "default production-image job must restore a schema- and architecture-scoped "
        "local BuildKit cache",
        failures,
    )
    require(
        "type=local" in ebpf_job
        and buildkit_cache_key("production-dockerfile-smoke-ebpf") in ebpf_job,
        "eBPF production-image job must restore a schema- and architecture-scoped "
        "local BuildKit cache",
        failures,
    )
    check_local_cache_actions(
        default_job,
        "production-dockerfile-smoke-default",
        failures,
        scope="production-dockerfile-smoke-default",
    )
    check_local_cache_actions(
        ebpf_job,
        "production-dockerfile-smoke-ebpf",
        failures,
        scope="production-dockerfile-smoke-ebpf",
    )
    check_cache_save_preparation(
        default_job,
        "production-dockerfile-smoke-default",
        failures,
        scope="production-dockerfile-smoke-default",
    )
    check_cache_save_preparation(
        ebpf_job,
        "production-dockerfile-smoke-ebpf",
        failures,
        scope="production-dockerfile-smoke-ebpf",
    )
    check_cache_telemetry_evidence(
        default_job,
        "production-dockerfile-smoke-default",
        failures,
    )
    check_cache_telemetry_evidence(
        ebpf_job,
        "production-dockerfile-smoke-ebpf",
        failures,
    )
    plan_job = extract_job(workflow, "production-dockerfile-plan")
    check_nul_delimited_plan(plan_job, "production-image planner", failures)
    require(
        "run: |\n          docker build" not in default_job
        and "run: |\n          docker build" not in ebpf_job,
        "production-image jobs must not fall back to sequential plain docker build",
        failures,
    )
    require(
        "usr/sbin/ip" in default_job and "ordinary runtime unexpectedly contains" in default_job,
        "ordinary image must still prove it does not ship eBPF-only ip",
        failures,
    )
    require(
        "grep -Fxq usr/sbin/ip" in ebpf_job,
        "eBPF image must still prove it ships ip",
        failures,
    )
    for forbidden in (
        "bin/sh",
        "usr/bin/bash",
        "usr/bin/apt-get",
        "usr/sbin/iptables",
    ):
        require(
            forbidden in default_job and forbidden in ebpf_job,
            f"both production images must still forbid /{forbidden}",
            failures,
        )
    require(
        re.search(r"(?m)^    if: always\(\)$", aggregate) is not None,
        "production-image aggregate must run with if: always()",
        failures,
    )
    check_aggregate_planner_contract(
        aggregate,
        "production-dockerfile-plan",
        "Production Dockerfile eBPF image smoke",
        failures,
    )
    check_governed_live_trigger_shape(
        workflow,
        "node-waypoint-ebpf-live.yml",
        failures,
    )
    check_node_waypoint_live_job(
        workflow,
        "node-waypoint-ebpf-live.yml",
        failures,
    )
    check_node_waypoint_aggregate(
        workflow,
        "node-waypoint-ebpf-live.yml",
        failures,
    )
    require(
        "python3 -I" in workflow and "ci_runtime_plan.py" in workflow,
        "production-image planner must execute an isolated trusted-base copy",
        failures,
    )
    require(
        "force_cold_cache" in workflow,
        "node-waypoint workflow must expose a cold-cache dispatch input",
        failures,
    )


def check_shared_actions(failures: list[str]) -> None:
    rust_ci = SETUP_RUST.read_text(encoding="utf-8")
    sccache = SETUP_SCCACHE.read_text(encoding="utf-8")
    require(
        "cache-on-failure:" in rust_ci and "true" in rust_ci,
        "setup-rust-ci must save rust-cache after ordinary failures when post-job cleanup still runs",
        failures,
    )
    require(
        "cache-hit:" in rust_ci,
        "setup-rust-ci must expose rust-cache hit/miss as an action output",
        failures,
    )
    check_shell_only_local_action(sccache, "setup-sccache", failures)
    check_shell_only_local_action(
        SETUP_FAST_LINKER.read_text(encoding="utf-8"),
        "setup-fast-linker",
        failures,
    )
    check_credential_absence_assertion(sccache, "setup-sccache", failures)
    check_setup_sccache_verified_activation(sccache, "setup-sccache", failures)
    require(
        SCCACHE_RELEASE_DOWNLOAD in sccache,
        "setup-sccache must download a pinned mozilla/sccache GitHub release",
        failures,
    )
    require(
        f'default: "{SCCACHE_PINNED_VERSION}"' in sccache
        or f"default: '{SCCACHE_PINNED_VERSION}'" in sccache,
        f"setup-sccache must pin sccache {SCCACHE_PINNED_VERSION}",
        failures,
    )
    for digest_input in (
        "linux-amd64-sha256",
        "linux-arm64-sha256",
        "macos-amd64-sha256",
        "macos-arm64-sha256",
        "windows-amd64-sha256",
    ):
        require(
            f"{digest_input}:" in sccache,
            f"setup-sccache must pin {digest_input}",
            failures,
        )
        require(
            re.search(
                rf"{re.escape(digest_input)}:[\s\S]{{0,200}}default: \"[0-9a-f]{{64}}\"",
                sccache,
            )
            is not None,
            f"setup-sccache {digest_input} must default to a 64-char SHA-256",
            failures,
        )
    require(
        "Linux-X64" in sccache
        and "macOS-ARM64" in sccache
        and "macOS-X64" in sccache
        and "Windows-X64" in sccache,
        "setup-sccache must cover Linux/macOS/Windows architectures used by callers",
        failures,
    )
    require(
        "ACTIONS_RUNTIME_TOKEN" in sccache and "GITHUB_ENV" in sccache,
        "setup-sccache must keep documenting why the GHA cache token stays out of GITHUB_ENV",
        failures,
    )
    require(
        "unset SCCACHE_GHA_ENABLED" in sccache,
        "setup-sccache must keep the GHA backend disabled",
        failures,
    )
    require(
        "SCCACHE_CACHE_SIZE=2G" in sccache or "SCCACHE_CACHE_SIZE=2G" in sccache,
        "setup-sccache must keep the 2 GiB local cache cap",
        failures,
    )
    require(
        "SCCACHE_IDLE_TIMEOUT=0" in sccache,
        "setup-sccache must keep the idle timeout disabled",
        failures,
    )
    require(
        "lazily after cache restore" in sccache
        or "AFTER the cache restore" in sccache
        or "after cache restore" in sccache,
        "setup-sccache must still start the server lazily after cache restore",
        failures,
    )
    require(
        "continue-on-error: true" in sccache,
        "setup-sccache install must remain a graceful fallback",
        failures,
    )
    require(
        "CARGO_BUILD_RUSTC_WRAPPER=" in sccache,
        "setup-sccache must clear the rustc wrapper when sccache is unavailable",
        failures,
    )
    require(
        RUST_CACHE in rust_ci,
        "setup-rust-ci must keep the pinned rust-cache action",
        failures,
    )
    check_rust_cache_trusted_main_save_if(
        rust_ci,
        "setup-rust-ci",
        failures,
        expected_count=1,
    )


def check_docs_and_coverage(failures: list[str]) -> None:
    ci_cd = CI_CD_DOC.read_text(encoding="utf-8")
    fips_doc = FIPS_DOC.read_text(encoding="utf-8")
    coverage = COVERAGE_WORKFLOW.read_text(encoding="utf-8")
    require(
        "`fips-build.yml`" in ci_cd or "fips-build.yml" in ci_cd,
        "docs/ci_cd.md must inventory fips-build.yml",
        failures,
    )
    require(
        "30 minutes" in ci_cd and "45 minutes" in ci_cd,
        "docs/ci_cd.md must document the warm PR runtime targets",
        failures,
    )
    require(
        "force_cold_cache" in ci_cd,
        "docs/ci_cd.md must document the hosted cold-cache proof path",
        failures,
    )
    require(
        "cache-on-failure" in ci_cd or "runner-loss" in ci_cd or "retry amplification" in ci_cd,
        "docs/ci_cd.md must document retry amplification / runner-loss cache reuse",
        failures,
    )
    require(
        "save-if" in ci_cd and "fork" in ci_cd.lower(),
        "docs/ci_cd.md must document rust-cache save-if for fork pull requests",
        failures,
    )
    require(
        "fips-producer" in ci_cd
        and "github.sha" in ci_cd
        and "run_id" in ci_cd
        and "run_attempt" in ci_cd,
        "docs/ci_cd.md must document the SHA/run_id/run_attempt FIPS producer key",
        failures,
    )
    require(
        "fips-producer-handoff" in ci_cd
        and "inter-run" in ci_cd.lower()
        and "artifact" in ci_cd.lower()
        and "evict" in ci_cd.lower()
        and "deletes" in ci_cd.lower()
        and "zstd" in ci_cd.lower()
        and "executable modes" in ci_cd.lower(),
        "docs/ci_cd.md must document the immutable FIPS inter-run artifact, "
        "mode-preserving payload, cache eviction, and rerun deletion boundary",
        failures,
    )
    require(
        "fips-test-build" in ci_cd,
        "docs/ci_cd.md must document the FIPS test-binary producer job",
        failures,
    )
    require(
        "fips-test-binaries-<run_id>-*" in ci_cd
        and "newest attempt" in ci_cd.lower()
        and "failed-job rerun" in ci_cd.lower()
        and "flattens" in ci_cd.lower()
        and "fips-producer-identity" in ci_cd
        and "fips-test-identity" in ci_cd,
        "docs/ci_cd.md must document attempt-wildcard FIPS test-artifact "
        "selection for failed-job reruns, one-match flattening, and internal "
        "attempt identity",
        failures,
    )
    require(
        "shared-key" in ci_cd and "ignored" in ci_cd.lower(),
        "docs/ci_cd.md must document that pinned rust-cache ignores key when shared-key is set",
        failures,
    )
    require(
        "save-if: false" in ci_cd or "save-if: false" in ci_cd.replace("`", ""),
        "docs/ci_cd.md must document that FIPS clippy/test rust-cache does not save",
        failures,
    )
    require(
        "mozilla-actions/sccache-action" in ci_cd
        and "ACTIONS_RUNTIME_TOKEN" in ci_cd,
        "docs/ci_cd.md must name the rejected sccache installer and token boundary",
        failures,
    )
    require(
        "closed allowlist" in ci_cd.lower()
        and "shell-only" in ci_cd.lower()
        and "setup-fast-linker" in ci_cd
        and "exportVariable" in ci_cd
        and "defense" in ci_cd.lower()
        and "occurrence counts" in ci_cd.lower()
        and "persist-credentials" in ci_cd
        and "repository" in ci_cd
        and "default-ref" in ci_cd.lower(),
        "docs/ci_cd.md must document the FIPS action allowlist, exact occurrence "
        "counts, checkout provenance, shell-only local actions, and "
        "defense-in-depth exportVariable token rule",
        failures,
    )
    require(
        "plain or quoted scalar" in ci_cd
        and "non-scalar" in ci_cd.lower()
        and "flow mapping" in ci_cd
        and "flow sequence" in ci_cd,
        "docs/ci_cd.md must document that the exportVariable description "
        "carve-out is scalar-only and that non-scalar root values stay scanned",
        failures,
    )
    require(
        "actions/cache/restore" in ci_cd
        and "actions/cache/save" in ci_cd
        and "restore-only" in ci_cd,
        "docs/ci_cd.md must document pinned cache restore/save and fork restore-only",
        failures,
    )
    require(
        "runner.arch" in ci_cd and BUILDKIT_CACHE_SCHEMA in ci_cd,
        "docs/ci_cd.md must document schema- and architecture-scoped BuildKit cache keys",
        failures,
    )
    require(
        "exact" in ci_cd.lower() and "partial" in ci_cd.lower(),
        "docs/ci_cd.md must document exact-hit restore-only vs partial/miss publish",
        failures,
    )
    require(
        "sccache-directory" in ci_cd or "sccache directory subset" in ci_cd.lower(),
        "docs/ci_cd.md must document that FIPS telemetry measures the sccache subset",
        failures,
    )
    require(
        "type=local" in ci_cd and "restored bytes" in ci_cd.lower(),
        "docs/ci_cd.md must document local BuildKit cache restore-byte measurement",
        failures,
    )
    require(
        "--name-only --no-renames -z" in ci_cd or "NUL-delimited" in ci_cd,
        "docs/ci_cd.md must document NUL-delimited trusted path planning",
        failures,
    )
    require(
        "merge_group" in ci_cd and "no workflow-level `paths:`" in ci_cd.lower(),
        "docs/ci_cd.md must document that the governed live workflows carry no "
        "pull-request-supplied `paths:` trigger filter and re-evaluate on "
        "merge_group",
        failures,
    )
    require(
        "relevant == 'false'" in ci_cd or "exact false" in ci_cd.lower(),
        "docs/ci_cd.md must document exact-boolean aggregate planner gating",
        failures,
    )
    require(
        "node_waypoint_relevant" in ci_cd and "!cancelled()" in ci_cd,
        "docs/ci_cd.md must document the NodeWaypoint cancellable job-level exact-false skip",
        failures,
    )
    require(
        "prior" in ci_cd.lower()
        and ("nodewaypoint" in ci_cd.lower() or "node-waypoint" in ci_cd.lower()),
        "docs/ci_cd.md must document NodeWaypoint prior-scope scheduling vs "
        "the production-image trigger superset",
        failures,
    )
    require(
        "10 GB" in ci_cd
        and "LRU" in ci_cd
        and "ambient-host-udp-images" in ci_cd,
        "docs/ci_cd.md must document the Ambient GHA cache-budget policy, "
        "10 GB quota, and LRU eviction",
        failures,
    )
    require(
        "#3918" in ci_cd and "Fuzz" in ci_cd,
        "docs/ci_cd.md must identify PR #3918 as the separate Fuzz-lane "
        "cache correction",
        failures,
    )
    require(
        "pull_request" in ci_cd
        and "merge_group" in ci_cd
        and "workflow_dispatch" in ci_cd
        and "restore" in ci_cd.lower(),
        "docs/ci_cd.md must document Ambient PR/merge-group restore-only "
        "versus trusted default-branch publication",
        failures,
    )
    require(
        "setup-rust-ci" in ci_cd
        and "save-if" in ci_cd
        and "refs/heads/main" in ci_cd,
        "docs/ci_cd.md must document the setup-rust-ci trusted-main "
        "rust-cache save policy",
        failures,
    )
    require(
        "trusted" in fips_doc.lower() and "cache" in fips_doc.lower(),
        "docs/fips.md must describe the FIPS CI cache trust boundary",
        failures,
    )
    require(
        "save-if" in fips_doc,
        "docs/fips.md must document rust-cache save-if so fork PRs cannot save",
        failures,
    )
    require(
        "fips-producer" in fips_doc
        and "github.sha" in fips_doc
        and "run_attempt" in fips_doc,
        "docs/fips.md must document the exact producer cache key",
        failures,
    )
    require(
        "fips-producer-handoff" in fips_doc
        and "inter-run" in fips_doc.lower()
        and "artifact" in fips_doc.lower()
        and "evict" in fips_doc.lower()
        and "deletes" in fips_doc.lower()
        and "zstd" in fips_doc.lower()
        and "executable modes" in fips_doc.lower(),
        "docs/fips.md must document the immutable FIPS inter-run artifact, "
        "mode-preserving payload, cache eviction, and rerun deletion boundary",
        failures,
    )
    require(
        "fips-test-build" in fips_doc,
        "docs/fips.md must document the FIPS test-binary producer job",
        failures,
    )
    require(
        "fips-test-binaries-<run_id>-*" in fips_doc
        and "newest attempt" in fips_doc.lower()
        and "failed-job rerun" in fips_doc.lower()
        and "flattens" in fips_doc.lower()
        and "fips-producer-identity" in fips_doc
        and "fips-test-identity" in fips_doc,
        "docs/fips.md must document attempt-wildcard FIPS test-artifact "
        "selection for failed-job reruns, one-match flattening, and internal "
        "attempt identity",
        failures,
    )
    require(
        "mozilla-actions/sccache-action" in fips_doc,
        "docs/fips.md must name the rejected sccache installer",
        failures,
    )
    require(
        "shared-key" in fips_doc and "ignored" in fips_doc.lower(),
        "docs/fips.md must document pinned rust-cache shared-key vs ignored key",
        failures,
    )
    require(
        "--lib" in coverage and "--test unit_tests" in coverage,
        "coverage lib-unit shard must still collect lib and unit_tests coverage",
        failures,
    )
    lib_unit = coverage
    require(
        re.search(
            r"cargo llvm-cov --no-report\s+\\\s*\n\s*--lib\s+\\\s*\n\s*--test unit_tests",
            lib_unit,
        )
        is not None,
        "coverage lib-unit must compile lib and unit_tests in one llvm-cov invocation",
        failures,
    )


def check_dockerfile(failures: list[str]) -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    require(
        builder_arg_features_is_after_apt(dockerfile),
        "Dockerfile builder ARG FEATURES must come after apt-get so ordinary and "
        "eBPF production builds share the compiler toolchain layer",
        failures,
    )
    require(
        "FROM runtime-common AS runtime" in dockerfile,
        "ordinary runtime must remain the default final target",
        failures,
    )
    require(
        "FROM runtime-common AS runtime-ebpf" in dockerfile,
        "runtime-ebpf target must remain",
        failures,
    )
    release = DOCKERFILE_RELEASE.read_text(encoding="utf-8")
    ebpf_tools_layer = DOCKERFILE_EBPF_TOOLS_LAYER.read_text(encoding="utf-8")
    check_dockerfile_log_level("Dockerfile", dockerfile, failures)
    check_dockerfile_log_level("Dockerfile.release", release, failures)
    check_dockerfile_log_level(
        "Dockerfile.ebpf-tools-layer", ebpf_tools_layer, failures
    )
    for label, text in (
        ("Dockerfile", dockerfile),
        ("Dockerfile.release", release),
        ("Dockerfile.test", DOCKERFILE_TEST.read_text(encoding="utf-8")),
        ("Dockerfile.ebpf-tools-layer", ebpf_tools_layer),
    ):
        check_dockerfile_image_pins(label, text, failures)


def self_test() -> int:
    failures: list[str] = []
    direct_cache = (
        f"      - uses: {RUST_CACHE}\n"
        "        with:\n"
        "          shared-key: diet-test\n"
        "          save-if: ${{ github.event_name == 'push' && "
        "github.ref == 'refs/heads/main' }}\n"
    )
    for compiler_only in (False, True):
        good_cache = direct_cache
        if compiler_only:
            good_cache += (
                '          cache-targets: "false"\n'
                "          cache-directories: ${{ github.workspace }}/.cache/sccache\n"
            )
        good_failures: list[str] = []
        check_direct_rust_cache_diet(
            good_cache, "self-test-direct-diet", good_failures, compiler_only=compiler_only
        )
        require(not good_failures, "self-test: valid direct cache diet must pass", failures)
        mutations = [
            good_cache.replace("github.event_name == 'push'", "github.event_name != 'push'"),
            good_cache.replace("refs/heads/main", "refs/heads/feature"),
            good_cache + "          save-if: true\n",
            good_cache.replace(f"      - uses: {RUST_CACHE}\n", ""),
        ]
        if compiler_only:
            mutations.append(
                good_cache.replace('cache-targets: "false"', 'cache-targets: "true"')
            )
        else:
            mutations.append(
                good_cache + "          cache-directories: ${{ github.workspace }}/.cache/sccache\n"
            )
        for mutation in mutations:
            mutation_failures: list[str] = []
            check_direct_rust_cache_diet(
                mutation,
                "self-test-direct-diet-mutation",
                mutation_failures,
                compiler_only=compiler_only,
            )
            require(
                bool(mutation_failures),
                "self-test: direct cache save/archive regression must fail",
                failures,
            )
    require(
        builder_arg_features_is_after_apt(
            "FROM rust:latest AS builder\n"
            "RUN apt-get update && apt-get install -y pkg-config\n"
            "ARG FEATURES\n"
            "RUN cargo build --features \"${FEATURES}\"\n"
        ),
        "self-test: ARG FEATURES after apt should pass",
        failures,
    )
    require(
        not builder_arg_features_is_after_apt(
            "FROM rust:latest AS builder\n"
            "ARG FEATURES\n"
            "RUN apt-get update && apt-get install -y pkg-config\n"
        ),
        "self-test: ARG FEATURES before apt should fail",
        failures,
    )
    require(
        builder_arg_features_is_after_apt(
            "FROM rust:latest@sha256:" + ("0" * 64) + " AS builder\n"
            "RUN apt-get update && apt-get install -y pkg-config\n"
            "ARG FEATURES\n"
        ),
        "self-test: digest-pinned builder base must still be recognized",
        failures,
    )
    require(
        not builder_arg_features_is_after_apt(
            "FROM golang:1.24 AS builder\n"
            "RUN apt-get update\n"
            "ARG FEATURES\n"
        ),
        "self-test: a non-rust builder base must not satisfy the contract",
        failures,
    )
    log_level_warn = (
        'ENV PATH="/app:${PATH}" \\\n'
        "    FERRUM_MODE=database \\\n"
        "    FERRUM_LOG_LEVEL=warn \\\n"
        "    FERRUM_PROXY_HTTP_PORT=8000\n"
    )
    log_level_error = log_level_warn.replace(
        "FERRUM_LOG_LEVEL=warn", "FERRUM_LOG_LEVEL=error"
    )
    log_level_absent = "\n".join(
        line
        for line in log_level_warn.splitlines()
        if "FERRUM_LOG_LEVEL" not in line
    )
    log_level_failures: list[str] = []
    check_dockerfile_log_level("synthetic", log_level_warn, log_level_failures)
    require(
        not log_level_failures,
        "self-test: FERRUM_LOG_LEVEL=warn should pass",
        failures,
    )
    log_level_failures = []
    check_dockerfile_log_level("synthetic", log_level_error, log_level_failures)
    require(
        len(log_level_failures) == 1
        and "FERRUM_LOG_LEVEL=error" in log_level_failures[0],
        "self-test: FERRUM_LOG_LEVEL=error should fail and name the value",
        failures,
    )
    log_level_failures = []
    check_dockerfile_log_level("synthetic", log_level_absent, log_level_failures)
    require(
        len(log_level_failures) == 1 and "found none" in log_level_failures[0],
        "self-test: a missing FERRUM_LOG_LEVEL assignment must fail closed",
        failures,
    )
    pinned_dockerfile = (
        "ARG RUNTIME_BASE=gcr.io/distroless/cc-debian13:nonroot@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "ARG IPROUTE2_VERSION=6.15.0-1\n"
        "FROM rust:latest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa AS builder\n"
        "FROM ${RUNTIME_BASE} AS runtime-base\n"
        "FROM runtime-base AS runtime\n"
        "FROM scratch AS empty\n"
    )
    pin_failures: list[str] = []
    check_dockerfile_image_pins("synthetic", pinned_dockerfile, pin_failures)
    require(
        not pin_failures,
        "self-test: fully digest-pinned Dockerfile should pass",
        failures,
    )
    require(
        [kind for _, kind, _ in dockerfile_image_references(pinned_dockerfile)]
        == ["ARG RUNTIME_BASE", "FROM"],
        "self-test: stage-name FROM, ${VAR} indirection, scratch, and version "
        "ARG defaults must not be treated as registry references",
        failures,
    )
    pin_failures = []
    check_dockerfile_image_pins(
        "synthetic",
        pinned_dockerfile.replace(f"FROM rust:latest@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "FROM rust:latest"),
        pin_failures,
    )
    require(
        len(pin_failures) == 2
        and any("unpinned image reference" in failure for failure in pin_failures)
        and any("mutable tag" in failure for failure in pin_failures),
        "self-test: an unpinned FROM must fail closed as both unpinned and mutable",
        failures,
    )
    pin_failures = []
    check_dockerfile_image_pins(
        "synthetic",
        pinned_dockerfile.replace(
            f"ARG RUNTIME_BASE=gcr.io/distroless/cc-debian13:nonroot@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ARG RUNTIME_BASE=gcr.io/distroless/cc-debian13:nonroot",
        ),
        pin_failures,
    )
    require(
        len(pin_failures) == 1 and "ARG RUNTIME_BASE" in pin_failures[0],
        "self-test: an unpinned ARG image default must fail closed",
        failures,
    )
    pin_failures = []
    check_dockerfile_image_pins("synthetic", "FROM scratch\n", pin_failures)
    require(
        len(pin_failures) == 1 and "found none" in pin_failures[0],
        "self-test: scratch is digest-less by design but cannot satisfy the "
        "contract on its own",
        failures,
    )
    sample = (
        "name: demo\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  x:\n"
        "    steps:\n"
        f"      - uses: {CHECKOUT} # v6\n"
    )
    require(
        workflow_permissions_are_read_only(sample),
        "self-test: contents: read permissions should pass",
        failures,
    )
    require(
        workflow_permissions_are_read_only(
            "name: demo\npermissions:\n  actions: read\n  contents: read\njobs:\n"
        ),
        "self-test: additional read-only workflow permissions should pass",
        failures,
    )
    require(
        not workflow_permissions_are_read_only(
            "name: demo\npermissions:\n  contents: write\njobs:\n"
        )
        and not workflow_permissions_are_read_only(
            "name: demo\npermissions:\n  actions: write\n  contents: read\njobs:\n"
        ),
        "self-test: workflow write permissions must fail",
        failures,
    )
    require(not pin_errors(sample, "self-test"), "self-test: pinned checkout should pass", failures)
    require(
        bool(pin_errors("uses: actions/checkout@v6\n", "self-test")),
        "self-test: floating tag should fail",
        failures,
    )

    build_push = (
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          cache-from: type=local,src=/tmp/production-dockerfile-smoke-default\n"
    )
    good_buildkit = (
        "    steps:\n"
        "      - name: Build ordinary production runtime (trusted exact-hit restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_EXACT}\n"
        f"{build_push}"
        "      - name: Build ordinary production runtime\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime (fork restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_IS_TRUE}\n"
        f"{build_push}"
        "      - name: Build ordinary production runtime (cold cache)\n"
        f"        if: {COLD_IS_TRUE}\n"
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          provenance: false\n"
    )
    good_buildkit_failures: list[str] = []
    check_buildkit_cache_boundary(
        good_buildkit,
        "self-test-good-buildkit",
        good_buildkit_failures,
    )
    require(
        not good_buildkit_failures,
        "self-test: structurally split BuildKit cache paths should pass: "
        + "; ".join(good_buildkit_failures),
        failures,
    )

    substring_false_positive = (
        "    steps:\n"
        "      - name: Record BuildKit cache restore policy\n"
        "        env:\n"
        "          FORK_PR: ${{ github.event.pull_request.head.repo.fork }}\n"
        "        run: echo telemetry-only\n"
        "      - name: Build ordinary production runtime\n"
        f"        if: {COLD_NOT_TRUE}\n"
        f"{build_push}"
        "          cache-to: type=gha,mode=max,scope=production-dockerfile-smoke-default\n"
        "      - name: Build ordinary production runtime (cold cache)\n"
        f"        if: {COLD_IS_TRUE}\n"
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          provenance: false\n"
    )
    require(
        "github.event.pull_request.head.repo.fork" in substring_false_positive,
        "self-test fixture must include the fork substring the old check trusted",
        failures,
    )
    substring_failures: list[str] = []
    check_buildkit_cache_boundary(
        substring_false_positive,
        "self-test-unconditional-cache-to",
        substring_failures,
    )
    require(
        any("exclude fork PRs from every cache-to" in item for item in substring_failures)
        and any("fork restore-only BuildKit step" in item for item in substring_failures),
        "self-test: fork substring plus unconditional cache-to must fail structurally",
        failures,
    )

    fork_cache_to = (
        "    steps:\n"
        "      - name: Build ordinary production runtime (trusted exact-hit restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_EXACT}\n"
        f"{build_push}"
        "      - name: Build ordinary production runtime\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime (fork restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_IS_TRUE}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime (cold cache)\n"
        f"        if: {COLD_IS_TRUE}\n"
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          provenance: false\n"
    )
    fork_cache_to_failures: list[str] = []
    check_buildkit_cache_boundary(
        fork_cache_to,
        "self-test-fork-cache-to",
        fork_cache_to_failures,
    )
    require(
        any(
            "omit cache-to on the fork restore-only BuildKit step" in item
            for item in fork_cache_to_failures
        ),
        "self-test: reintroducing cache-to on a fork path must fail",
        failures,
    )

    exact_hit_export = (
        "    steps:\n"
        "      - name: Build ordinary production runtime (trusted exact-hit restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_EXACT}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        f"{build_push}"
        "          cache-to: type=local,dest=/tmp/production-dockerfile-smoke-default-out,mode=max\n"
        "      - name: Build ordinary production runtime (fork restore-only)\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_IS_TRUE}\n"
        f"{build_push}"
        "      - name: Build ordinary production runtime (cold cache)\n"
        f"        if: {COLD_IS_TRUE}\n"
        f"        uses: {BUILD_PUSH} # v7\n"
        "        with:\n"
        "          provenance: false\n"
    )
    exact_hit_export_failures: list[str] = []
    check_buildkit_cache_boundary(
        exact_hit_export,
        "self-test-exact-hit-export",
        exact_hit_export_failures,
    )
    require(
        any(
            "never export cache-to on an exact github.sha hit" in item
            for item in exact_hit_export_failures
        ),
        "self-test: exact-hit cache-to/export must fail",
        failures,
    )

    rust_step = (
        "      - name: Cache FIPS Rust\n"
        f"        uses: {RUST_CACHE} # v2\n"
        "        with:\n"
        "          shared-key: ci-fips\n"
        "          cache-on-failure: \"true\"\n"
    )
    good_rust = rust_step + (
        "          save-if: ${{ github.event.pull_request.head.repo.fork != true }}\n"
    )
    good_rust_failures: list[str] = []
    check_rust_cache_fork_save_if(
        good_rust,
        "self-test-good-rust-cache",
        good_rust_failures,
        expected_count=1,
    )
    require(
        not good_rust_failures,
        "self-test: rust-cache save-if for non-fork should pass: "
        + "; ".join(good_rust_failures),
        failures,
    )

    missing_save_if_failures: list[str] = []
    check_rust_cache_fork_save_if(
        rust_step,
        "self-test-missing-save-if",
        missing_save_if_failures,
        expected_count=1,
    )
    require(
        any("save-if so fork PRs restore only" in item for item in missing_save_if_failures),
        "self-test: removing rust-cache save-if must fail",
        failures,
    )

    inverted_save_if = rust_step + (
        "          save-if: ${{ github.event.pull_request.head.repo.fork == true }}\n"
    )
    inverted_failures: list[str] = []
    check_rust_cache_fork_save_if(
        inverted_save_if,
        "self-test-inverted-save-if",
        inverted_failures,
        expected_count=1,
    )
    require(
        any("save-if so fork PRs restore only" in item for item in inverted_failures),
        "self-test: inverted rust-cache save-if must fail",
        failures,
    )

    trusted_main_save_if_line = (
        "          save-if: ${{ github.event_name != 'pull_request' && "
        "github.event_name != 'merge_group' && "
        "github.ref == 'refs/heads/main' && "
        "github.event.pull_request.head.repo.fork != true }}\n"
    )
    good_trusted_main = rust_step + trusted_main_save_if_line
    good_trusted_main_failures: list[str] = []
    check_rust_cache_trusted_main_save_if(
        good_trusted_main,
        "self-test-good-trusted-main-save-if",
        good_trusted_main_failures,
        expected_count=1,
    )
    require(
        not good_trusted_main_failures,
        "self-test: trusted-main rust-cache save-if should pass: "
        + "; ".join(good_trusted_main_failures),
        failures,
    )

    pr_publishing_failures: list[str] = []
    check_rust_cache_trusted_main_save_if(
        good_rust,
        "self-test-pr-publishing-save-if",
        pr_publishing_failures,
        expected_count=1,
    )
    require(
        any(
            "gate save-if to trusted refs/heads/main" in item
            for item in pr_publishing_failures
        ),
        "self-test: restoring the fork-only save-if on a trusted-main site "
        "must fail",
        failures,
    )

    trusted_main_missing_failures: list[str] = []
    check_rust_cache_trusted_main_save_if(
        rust_step,
        "self-test-trusted-main-missing-save-if",
        trusted_main_missing_failures,
        expected_count=1,
    )
    require(
        any(
            "gate save-if to trusted refs/heads/main" in item
            for item in trusted_main_missing_failures
        ),
        "self-test: removing save-if from a trusted-main site must fail",
        failures,
    )

    ref_weakened_line = (
        "          save-if: ${{ github.ref == 'refs/heads/main' && "
        "github.event.pull_request.head.repo.fork != true }}\n"
    )
    ref_weakened_failures: list[str] = []
    check_rust_cache_trusted_main_save_if(
        rust_step + ref_weakened_line,
        "self-test-save-if-without-event-guards",
        ref_weakened_failures,
        expected_count=1,
    )
    require(
        any(
            "gate save-if to trusted refs/heads/main" in item
            for item in ref_weakened_failures
        ),
        "self-test: save-if without the pull_request/merge_group exclusions "
        "must fail",
        failures,
    )

    ignored_key_block = (
        "          shared-key: ci-fips\n"
        "          key: fips-contract-${{ hashFiles('Cargo.toml') }}\n"
        "          add-job-id-key: \"false\"\n"
    )
    ignored_key_failures: list[str] = []
    check_rust_cache_uses_shared_key_only(
        ignored_key_block,
        "self-test-ignored-key",
        ignored_key_failures,
        expected_shared_key=FIPS_SHARED_KEY,
    )
    require(
        any("must not set rust-cache `key:`" in item for item in ignored_key_failures)
        and any("add-job-id-key" in item for item in ignored_key_failures)
        and any("shared-key must be" in item for item in ignored_key_failures),
        "self-test: shared-key plus ignored key/add-job-id-key must fail",
        failures,
    )

    sha_in_stable = (
        f"          shared-key: {FIPS_SHARED_KEY}-${{{{ github.sha }}}}\n"
    )
    sha_stable_failures: list[str] = []
    check_rust_cache_uses_shared_key_only(
        sha_in_stable,
        "self-test-sha-in-stable",
        sha_stable_failures,
        expected_shared_key=FIPS_SHARED_KEY,
    )
    require(
        any("must not include sha/run_id" in item for item in sha_stable_failures),
        "self-test: SHA on the stable rust-cache key must fail",
        failures,
    )

    good_shared = f"          shared-key: {FIPS_SHARED_KEY}\n"
    good_shared_failures: list[str] = []
    check_rust_cache_uses_shared_key_only(
        good_shared,
        "self-test-good-shared-key",
        good_shared_failures,
        expected_shared_key=FIPS_SHARED_KEY,
    )
    require(
        not good_shared_failures,
        "self-test: contract shared-key without ignored key should pass: "
        + "; ".join(good_shared_failures),
        failures,
    )

    exporter_failures: list[str] = []
    check_no_sccache_credential_exporter(
        "uses: mozilla-actions/sccache-action@1583d6b38d7be47f593cb472781bbb21cab4321e\n",
        "self-test-sccache-exporter",
        exporter_failures,
    )
    require(
        any("must not invoke credential-exporting installer" in item for item in exporter_failures),
        "self-test: mozilla-actions/sccache-action must fail",
        failures,
    )

    real_fips = FIPS_WORKFLOW.read_text(encoding="utf-8")
    real_sccache = SETUP_SCCACHE.read_text(encoding="utf-8")
    real_linker = SETUP_FAST_LINKER.read_text(encoding="utf-8")
    admitted_failures: list[str] = []
    check_fips_action_allowlist(real_fips, "fips-build.yml", admitted_failures)
    check_no_sccache_credential_exporter(real_fips, "fips-build.yml", admitted_failures)
    check_shell_only_local_action(real_sccache, "setup-sccache", admitted_failures)
    check_shell_only_local_action(real_linker, "setup-fast-linker", admitted_failures)
    require(
        not admitted_failures,
        "self-test: current checked FIPS workflow and shell-only actions must "
        "be admitted: " + "; ".join(admitted_failures),
        failures,
    )

    computed_js = 'core["export" + "Variable"]("ACTIONS_RUNTIME_TOKEN", token)'
    require(
        SCCACHE_EXPORT_VARIABLE_TOKEN not in computed_js,
        "self-test: computed-property fixture must not contain the contiguous token",
        failures,
    )
    github_script = (
        "actions/github-script@3d3c42e5aac5ba805825da76410c181273ba90b1"
    )
    setup_step = "      - uses: ./.github/actions/setup-sccache\n"
    require(
        setup_step in real_fips,
        "self-test: fips-build.yml must still contain the setup-sccache step",
        failures,
    )

    sequence_scalar_text = (
        "paths:\n"
        "  - |\n"
        "      uses: actions/github-script@decoy\n"
        "  - >2-\n"
        "      using: node20\n"
    )
    scalar_uses, scalar_using, scalar_errors = scan_yaml_action_invocations(
        sequence_scalar_text
    )
    require(
        not scalar_uses and not scalar_using and not scalar_errors,
        "self-test: standalone sequence block-scalar bodies must remain data, "
        "not action-count carriers: "
        f"uses={scalar_uses} using={scalar_using} errors={scalar_errors}",
        failures,
    )

    scalar_count_decoy = real_fips.replace(
        "    branches:\n      - main\n",
        "    branches:\n"
        "      - main\n"
        "      - |\n"
        "          uses: ./.github/actions/setup-sccache\n",
        1,
    ).replace(setup_step, "      - run: true\n", 1)
    require(
        "      - |\n          uses: ./.github/actions/setup-sccache\n"
        in scalar_count_decoy
        and scalar_count_decoy.count(setup_step) == real_fips.count(setup_step) - 1,
        "self-test: sequence block-scalar decoy mutation must insert inert text "
        "and remove exactly one real setup-sccache action",
        failures,
    )
    scalar_count_failures: list[str] = []
    check_fips_action_allowlist(
        scalar_count_decoy,
        "self-test-sequence-block-scalar-count-decoy",
        scalar_count_failures,
    )
    require(
        any(
            "./.github/actions/setup-sccache observed=3 expected=4" in item
            for item in scalar_count_failures
        ),
        "self-test: inert sequence block-scalar text must not replace a real "
        f"allowlisted invocation: {scalar_count_failures}",
        failures,
    )

    computed_block = real_fips.replace(
        setup_step,
        "      - uses: "
        + github_script
        + "\n        with:\n          script: "
        + computed_js
        + "\n"
        + setup_step,
        1,
    )
    computed_block_failures: list[str] = []
    check_fips_action_allowlist(
        computed_block, "self-test-computed-block", computed_block_failures
    )
    computed_token_failures: list[str] = []
    check_no_sccache_credential_exporter(
        computed_block, "self-test-computed-block-token", computed_token_failures
    )
    require(
        any("closed FIPS allowlist" in item for item in computed_block_failures),
        "self-test: computed-property github-script block uses must fail the "
        f"allowlist: {computed_block_failures}",
        failures,
    )
    require(
        not computed_token_failures,
        "self-test: computed-property payload must not be caught only by the "
        "token rule: " + "; ".join(computed_token_failures),
        failures,
    )

    computed_flow = real_fips.replace(
        setup_step,
        "      - {uses: "
        + github_script
        + ", with: {script: '"
        + computed_js.replace("'", "''")
        + "'}}\n"
        + setup_step,
        1,
    )
    computed_flow_failures: list[str] = []
    check_fips_action_allowlist(
        computed_flow, "self-test-computed-flow", computed_flow_failures
    )
    require(
        any("closed FIPS allowlist" in item for item in computed_flow_failures),
        "self-test: flow-form github-script uses must fail the allowlist: "
        f"{computed_flow_failures}",
        failures,
    )

    computed_seq = real_fips.replace(
        setup_step,
        "      - [{uses: "
        + github_script
        + ", with: {script: '"
        + computed_js.replace("'", "''")
        + "'}}]\n"
        + setup_step,
        1,
    )
    computed_seq_failures: list[str] = []
    check_fips_action_allowlist(
        computed_seq, "self-test-computed-sequence", computed_seq_failures
    )
    require(
        any("closed FIPS allowlist" in item for item in computed_seq_failures),
        "self-test: flow-sequence github-script uses must fail the allowlist: "
        f"{computed_seq_failures}",
        failures,
    )

    escaped_key = real_fips.replace(
        setup_step,
        '      - "\\u0075ses": ' + github_script + "\n" + setup_step,
        1,
    )
    escaped_failures: list[str] = []
    check_fips_action_allowlist(
        escaped_key, "self-test-escaped-uses-key", escaped_failures
    )
    require(
        any("closed FIPS allowlist" in item for item in escaped_failures),
        "self-test: escaped uses key must fail the allowlist: "
        f"{escaped_failures}",
        failures,
    )

    alias_doc = "x-evil: &evil " + github_script + "\n" + real_fips.replace(
        setup_step, "      - uses: *evil\n" + setup_step, 1
    )
    alias_failures: list[str] = []
    check_fips_action_allowlist(alias_doc, "self-test-uses-alias", alias_failures)
    require(
        any("indirect uses value" in item for item in alias_failures),
        f"self-test: aliased uses must fail closed: {alias_failures}",
        failures,
    )

    block_scalar_uses = real_fips.replace(
        setup_step,
        "      - uses: |\n          " + github_script + "\n" + setup_step,
        1,
    )
    block_scalar_failures: list[str] = []
    check_fips_action_allowlist(
        block_scalar_uses, "self-test-block-scalar-uses", block_scalar_failures
    )
    require(
        any("block-scalar uses value" in item for item in block_scalar_failures),
        f"self-test: block-scalar uses must fail closed: {block_scalar_failures}",
        failures,
    )

    dynamic_uses = real_fips.replace(
        setup_step,
        "      - uses: ${{ env.ACTION }}\n" + setup_step,
        1,
    )
    dynamic_failures: list[str] = []
    check_fips_action_allowlist(
        dynamic_uses, "self-test-dynamic-uses", dynamic_failures
    )
    require(
        any("dynamic uses value" in item for item in dynamic_failures),
        f"self-test: template uses must fail closed: {dynamic_failures}",
        failures,
    )

    quoted_concat = real_fips.replace(
        setup_step,
        '      - uses: "actions/" + "github-script@'
        + "3d3c42e5aac5ba805825da76410c181273ba90b1"
        + '"\n'
        + setup_step,
        1,
    )
    concat_failures: list[str] = []
    check_fips_action_allowlist(
        quoted_concat, "self-test-concatenated-uses", concat_failures
    )
    require(
        bool(concat_failures),
        "self-test: concatenated uses spelling must fail closed: "
        f"{concat_failures}",
        failures,
    )

    chaining_payload = (
        'core?.["export"+"Variable"].call(core, "ACTIONS_RUNTIME_TOKEN", token)'
    )
    require(
        SCCACHE_EXPORT_VARIABLE_TOKEN not in chaining_payload,
        "self-test: optional-chaining computed fixture must not contain the token",
        failures,
    )
    chaining_doc = real_fips.replace(
        setup_step,
        "      - uses: "
        + github_script
        + "\n        with:\n          script: "
        + chaining_payload
        + "\n"
        + setup_step,
        1,
    )
    chaining_failures: list[str] = []
    check_fips_action_allowlist(
        chaining_doc, "self-test-optional-chaining-carrier", chaining_failures
    )
    require(
        any("closed FIPS allowlist" in item for item in chaining_failures),
        "self-test: optional-chaining/call JS carrier must fail the allowlist: "
        f"{chaining_failures}",
        failures,
    )

    unlisted_pin = real_fips.replace(
        setup_step,
        "      - uses: actions/setup-node@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
        + setup_step,
        1,
    )
    unlisted_failures: list[str] = []
    check_fips_action_allowlist(
        unlisted_pin, "self-test-unlisted-pin", unlisted_failures
    )
    require(
        any("closed FIPS allowlist" in item for item in unlisted_failures),
        f"self-test: pinned action outside the allowlist must fail: {unlisted_failures}",
        failures,
    )

    nested_js = real_sccache.replace(
        "  using: composite\n  steps:\n",
        "  using: composite\n  steps:\n"
        "    - uses: "
        + github_script
        + "\n      with:\n        script: "
        + computed_js
        + "\n",
        1,
    )
    nested_failures: list[str] = []
    check_shell_only_local_action(
        nested_js, "self-test-nested-js-action", nested_failures
    )
    require(
        any("must not invoke nested actions" in item for item in nested_failures),
        f"self-test: nested github-script in setup-sccache must fail: {nested_failures}",
        failures,
    )
    require(
        not any("must not contain exportVariable" in item for item in nested_failures),
        "self-test: nested computed JS must fail structurally, not only via the token",
        failures,
    )

    node_runtime = real_sccache.replace(
        "  using: composite\n", "  using: node20\n", 1
    )
    node_failures: list[str] = []
    check_shell_only_local_action(
        node_runtime, "self-test-javascript-runtime", node_failures
    )
    require(
        any("shell-only composite action" in item for item in node_failures)
        or any("JavaScript action runtime" in item for item in node_failures),
        f"self-test: JavaScript using: node20 must fail: {node_failures}",
        failures,
    )

    linker_nested = real_linker.replace(
        "  using: composite\n  steps:\n",
        "  using: composite\n  steps:\n    - uses: " + github_script + "\n",
        1,
    )
    linker_nested_failures: list[str] = []
    check_shell_only_local_action(
        linker_nested, "self-test-linker-nested-action", linker_nested_failures
    )
    require(
        any("must not invoke nested actions" in item for item in linker_nested_failures),
        "self-test: nested action in setup-fast-linker must fail: "
        f"{linker_nested_failures}",
        failures,
    )

    def fips_insert(snippet: str) -> str:
        mutated = real_fips.replace(setup_step, snippet + setup_step, 1)
        require(
            setup_step in mutated and snippet.split("\n", 1)[0] in mutated,
            "self-test: FIPS carrier mutation must insert into the real workflow "
            f"without dropping setup-sccache: {snippet!r}",
            failures,
        )
        return mutated

    def require_fips_carrier(name: str, snippet: str, needles: tuple[str, ...]) -> None:
        carrier_failures: list[str] = []
        check_fips_action_allowlist(fips_insert(snippet), name, carrier_failures)
        require(
            any(any(needle in item for needle in needles) for item in carrier_failures),
            f"self-test: {name} must fail closed {needles}: {carrier_failures}",
            failures,
        )

    require_fips_carrier(
        "self-test-block-merge-key",
        "      - <<: *evil\n",
        ("YAML merge key",),
    )
    require_fips_carrier(
        "self-test-flow-merge-key",
        "      - {<<: *evil}\n",
        ("YAML merge key",),
    )
    require_fips_carrier(
        "self-test-block-merge-mapping",
        "      - <<: {uses: " + github_script + "}\n",
        ("YAML merge key", "closed FIPS allowlist"),
    )
    require_fips_carrier(
        "self-test-sequence-explicit-key",
        "      - ? uses\n        : " + github_script + "\n",
        ("explicit YAML key",),
    )
    require_fips_carrier(
        "self-test-sequence-explicit-key-compact",
        "      - ? uses: " + github_script + "\n",
        ("explicit YAML key", "closed FIPS allowlist"),
    )
    require_fips_carrier(
        "self-test-unbraced-flow-pair",
        "      - [uses: " + github_script + "]\n",
        ("closed FIPS allowlist",),
    )
    require_fips_carrier(
        "self-test-unbraced-flow-pair-after-mapping",
        "      - [{name: hidden}, uses: " + github_script + "]\n",
        ("closed FIPS allowlist",),
    )
    require_fips_carrier(
        "self-test-anchored-flow-step",
        "      - &step {uses: " + github_script + "}\n",
        ("indirect or tagged YAML node", "closed FIPS allowlist"),
    )
    require_fips_carrier(
        "self-test-anchored-mapping-value",
        "      - dummy: &step {uses: " + github_script + "}\n",
        ("indirect or tagged YAML node", "closed FIPS allowlist"),
    )
    require_fips_carrier(
        "self-test-tagged-flow-step",
        "      - !!map {uses: " + github_script + "}\n",
        ("indirect or tagged YAML node", "closed FIPS allowlist"),
    )
    require_fips_carrier(
        "self-test-tagged-uses-key",
        "      - !!str uses: " + github_script + "\n",
        ("indirect or tagged YAML node", "closed FIPS allowlist"),
    )
    require_fips_carrier(
        "self-test-alias-sequence-item",
        "      - *evil\n",
        ("indirect or tagged YAML node",),
    )
    require_fips_carrier(
        "self-test-alias-as-key",
        "      - *uk: " + github_script + "\n",
        ("indirect or tagged YAML node",),
    )
    require_fips_carrier(
        "self-test-multiline-quoted-uses-key",
        '      - "\\\n        uses": ' + github_script + "\n",
        ("unreadable multiline YAML quoting",),
    )
    require_fips_carrier(
        "self-test-block-scalar-sibling-uses-literal",
        "      - name: |\n"
        "          harmless\n"
        "        uses: " + github_script + "\n",
        ("closed FIPS allowlist",),
    )
    require_fips_carrier(
        "self-test-block-scalar-sibling-uses-folded",
        "      - name: >-\n"
        "          harmless\n"
        "        uses: " + github_script + "\n",
        ("closed FIPS allowlist",),
    )
    require_fips_carrier(
        "self-test-plain-scalar-hash-flow",
        "      - {name: harmless#suffix, uses: " + github_script + "\n"
        "        }\n",
        ("closed FIPS allowlist",),
    )
    require_fips_carrier(
        "self-test-duplicate-checkout",
        f"      - uses: {CHECKOUT} # v6\n"
        "        with:\n"
        "          persist-credentials: false\n",
        ("occurrence counts", "observed="),
    )
    require_fips_carrier(
        "self-test-duplicate-setup-sccache",
        setup_step,
        ("occurrence counts", "observed="),
    )

    comment_control = fips_insert(
        "      - {name: harmless, # separated comment\n"
        "        run: echo ok}\n"
    )
    comment_control_failures: list[str] = []
    check_fips_action_allowlist(
        comment_control,
        "self-test-separated-comment-control",
        comment_control_failures,
    )
    require(
        not comment_control_failures,
        "self-test: a whitespace-separated YAML comment must not hide or invent "
        "action carriers: " + "; ".join(comment_control_failures),
        failures,
    )

    checkout_with = "        with:\n          persist-credentials: false\n"
    require(
        checkout_with in real_fips and CHECKOUT in real_fips,
        "self-test: fips-build.yml must still contain the admitted checkout with "
        "persist-credentials: false",
        failures,
    )
    repo_redirect = real_fips.replace(
        checkout_with,
        checkout_with + "          repository: evil/other-repo\n",
        1,
    )
    require(
        setup_step in repo_redirect and "persist-credentials: false" in repo_redirect,
        "self-test: repository redirect mutation must keep original admitted "
        "checkout and setup-sccache text",
        failures,
    )
    repo_redirect_failures: list[str] = []
    check_fips_action_allowlist(
        repo_redirect, "self-test-checkout-repository-redirect", repo_redirect_failures
    )
    require(
        any("repository/ref/path redirection" in item for item in repo_redirect_failures)
        and any("repository" in item for item in repo_redirect_failures),
        "self-test: checkout repository redirect must fail provenance: "
        f"{repo_redirect_failures}",
        failures,
    )
    path_redirect = real_fips.replace(
        checkout_with,
        checkout_with + "          path: .github/actions/setup-sccache\n",
        1,
    )
    require(
        setup_step in path_redirect
        and "./.github/actions/setup-sccache" in path_redirect,
        "self-test: path redirect mutation must keep original setup-sccache text",
        failures,
    )
    path_redirect_failures: list[str] = []
    check_fips_action_allowlist(
        path_redirect, "self-test-checkout-path-redirect", path_redirect_failures
    )
    require(
        any("repository/ref/path redirection" in item for item in path_redirect_failures)
        and any("path" in item for item in path_redirect_failures),
        "self-test: checkout path redirect must fail provenance: "
        f"{path_redirect_failures}",
        failures,
    )
    duplicate_with = real_fips.replace(
        checkout_with,
        checkout_with + "        with:\n          fetch-depth: 1\n",
        1,
    )
    require(
        setup_step in duplicate_with and duplicate_with.count(checkout_with) >= 1,
        "self-test: duplicate checkout with mutation must keep the original "
        "checkout provenance and setup-sccache text",
        failures,
    )
    duplicate_with_failures: list[str] = []
    check_fips_action_allowlist(
        duplicate_with,
        "self-test-checkout-duplicate-with",
        duplicate_with_failures,
    )
    require(
        any(
            "exactly one inspectable with mapping" in item
            for item in duplicate_with_failures
        ),
        "self-test: duplicate checkout with mappings must fail provenance: "
        f"{duplicate_with_failures}",
        failures,
    )

    def sccache_insert(snippet: str) -> str:
        marker = "  using: composite\n  steps:\n"
        mutated = real_sccache.replace(marker, marker + snippet, 1)
        require(
            marker in mutated and snippet.split("\n", 1)[0] in mutated,
            "self-test: setup-sccache carrier mutation must keep using: composite "
            f"and insert the carrier: {snippet!r}",
            failures,
        )
        return mutated

    def require_sccache_carrier(name: str, snippet: str, needles: tuple[str, ...]) -> None:
        carrier_failures: list[str] = []
        check_shell_only_local_action(sccache_insert(snippet), name, carrier_failures)
        require(
            any(any(needle in item for needle in needles) for item in carrier_failures),
            f"self-test: {name} must fail closed {needles}: {carrier_failures}",
            failures,
        )
        require(
            not any("must not contain exportVariable" in item for item in carrier_failures),
            f"self-test: {name} must fail structurally, not only via the token",
            failures,
        )

    require_sccache_carrier(
        "self-test-sccache-block-merge-key",
        "    - <<: *evil\n",
        ("YAML merge key",),
    )
    require_sccache_carrier(
        "self-test-sccache-sequence-explicit-key",
        "    - ? uses: " + github_script + "\n",
        ("explicit YAML key", "must not invoke nested actions"),
    )
    require_sccache_carrier(
        "self-test-sccache-unbraced-flow-pair",
        "    - [uses: " + github_script + "]\n",
        ("must not invoke nested actions",),
    )
    require_sccache_carrier(
        "self-test-sccache-anchored-flow-step",
        "    - &step {uses: " + github_script + "}\n",
        ("indirect or tagged YAML node", "must not invoke nested actions"),
    )
    require_sccache_carrier(
        "self-test-sccache-tagged-flow-step",
        "    - !!map {uses: " + github_script + "}\n",
        ("indirect or tagged YAML node", "must not invoke nested actions"),
    )
    require_sccache_carrier(
        "self-test-sccache-multiline-quoted-uses-key",
        '    - "\\\n      uses": ' + github_script + "\n",
        ("unreadable multiline YAML quoting",),
    )
    require_sccache_carrier(
        "self-test-sccache-block-scalar-sibling-uses-literal",
        "    - name: |\n"
        "        harmless\n"
        "      uses: " + github_script + "\n",
        ("must not invoke nested actions",),
    )
    require_sccache_carrier(
        "self-test-sccache-block-scalar-sibling-uses-folded",
        "    - name: >-\n"
        "        harmless\n"
        "      uses: " + github_script + "\n",
        ("must not invoke nested actions",),
    )
    require_sccache_carrier(
        "self-test-sccache-plain-scalar-hash-flow",
        "    - {name: harmless#suffix, uses: " + github_script + "\n"
        "      }\n",
        ("must not invoke nested actions",),
    )

    sccache_comment_control = sccache_insert(
        "    - {name: harmless, # separated comment\n"
        "      run: echo ok}\n"
    )
    sccache_comment_failures: list[str] = []
    check_shell_only_local_action(
        sccache_comment_control,
        "self-test-sccache-separated-comment-control",
        sccache_comment_failures,
    )
    require(
        not sccache_comment_failures,
        "self-test: a whitespace-separated YAML comment in setup-sccache must "
        "not invent nested actions: " + "; ".join(sccache_comment_failures),
        failures,
    )

    export_variable_bypass_shapes = (
        "core.exportVariable('ACTIONS_RUNTIME_TOKEN', token)",
        "core.exportVariable ('ACTIONS_RUNTIME_TOKEN', token)",
        "core.exportVariable\n('ACTIONS_RUNTIME_TOKEN', token)",
        "core.exportVariable/* indirect */('ACTIONS_RUNTIME_TOKEN', token)",
        'core["exportVariable"](\'ACTIONS_RUNTIME_TOKEN\', token)',
        "core?.exportVariable('ACTIONS_RUNTIME_TOKEN', token)",
        "core.exportVariable.call(core, 'ACTIONS_RUNTIME_TOKEN', token)",
        "core.exportVariable.apply(core, ['ACTIONS_RUNTIME_TOKEN', token])",
        "core.exportVariable.bind(core)('ACTIONS_RUNTIME_TOKEN', token)",
        "const leak = core.exportVariable; leak('ACTIONS_RUNTIME_TOKEN', token)",
        "const { exportVariable } = core; exportVariable('ACTIONS_RUNTIME_TOKEN', token)",
        "(0, core.exportVariable)('ACTIONS_RUNTIME_TOKEN', token)",
    )
    for index, sample in enumerate(export_variable_bypass_shapes):
        sample_failures: list[str] = []
        check_no_sccache_credential_exporter(
            sample,
            f"self-test-export-variable-token-{index}",
            sample_failures,
        )
        require(
            any("must not contain exportVariable" in item for item in sample_failures),
            f"self-test: exportVariable token must fail: {sample!r}",
            failures,
        )

    export_variable_control_failures: list[str] = []
    check_no_sccache_credential_exporter(
        "This action does not persist cache-service credentials into GITHUB_ENV.",
        "self-test-export-variable-control",
        export_variable_control_failures,
    )
    require(
        not export_variable_control_failures,
        "self-test: credential-isolation prose without the token must pass: "
        + "; ".join(export_variable_control_failures),
        failures,
    )

    # The checked-in installer documents the exact toolkit call it refuses to
    # make, and the Cross build policy freezes that file whole, so the token
    # rule has to read the *root* `description:` as prose. Assert the real file
    # still exercises the carve-out at exactly that one location; a silent
    # reword would make it vacuous, and a nested occurrence would mean the
    # frozen file now depends on an exemption the transform does not grant.
    require(
        SCCACHE_EXPORT_VARIABLE_TOKEN in real_sccache,
        "self-test: setup-sccache description must still document the "
        f"{SCCACHE_EXPORT_VARIABLE_TOKEN} boundary it refuses",
        failures,
    )
    # The root `description:` key at column zero plus every line of its block
    # body (indented, or blank). Nothing else in the file is exempt, so every
    # occurrence of the token has to fall inside this span.
    root_description_block = re.search(
        r"(?m)^description:[^\n]*\n(?:(?:[ \t]+[^\n]*)?\n)*",
        real_sccache,
    )
    root_description_hits = (
        0
        if root_description_block is None
        else root_description_block.group(0).count(SCCACHE_EXPORT_VARIABLE_TOKEN)
    )
    require(
        root_description_hits > 0
        and root_description_hits
        == real_sccache.count(SCCACHE_EXPORT_VARIABLE_TOKEN),
        "self-test: every setup-sccache "
        f"{SCCACHE_EXPORT_VARIABLE_TOKEN} occurrence must live in the root "
        "description block; nested description keys are scanned, not exempt",
        failures,
    )

    # Only the document-root metadata `description:` scalar is withheld from
    # the scan: its plain or quoted scalar and its correctly delimited block
    # body. Flow collections and other non-scalar shapes stay scanned.
    description_prose_shapes = (
        "description: >-\n"
        "  Does not invoke an installer that `core.exportVariable`s\n"
        "  ACTIONS_RUNTIME_TOKEN into GITHUB_ENV.\n"
        "runs:\n"
        "  using: composite\n",
        "description: |\n"
        "  core.exportVariable('ACTIONS_RUNTIME_TOKEN', token) is refused.\n"
        "runs:\n"
        "  using: composite\n",
        "description: core.exportVariable is documented, never invoked\n"
        "runs:\n"
        "  using: composite\n",
        'description: "core.exportVariable is documented, never invoked"\n'
        "runs:\n"
        "  using: composite\n",
        "description: 'core.exportVariable is documented, never invoked'\n"
        "runs:\n"
        "  using: composite\n",
        # Quoted scalars whose contents look like a flow collection are still
        # strings GitHub renders, not YAML structure.
        'description: "[exportVariable] is documented, never invoked"\n'
        "runs:\n"
        "  using: composite\n",
        "description: '{carrier: exportVariable} is documented, never invoked'\n"
        "runs:\n"
        "  using: composite\n",
    )
    for index, sample in enumerate(description_prose_shapes):
        prose_failures: list[str] = []
        check_no_sccache_credential_exporter(
            sample,
            f"self-test-export-variable-description-{index}",
            prose_failures,
        )
        require(
            not prose_failures,
            f"self-test: root description prose must not trip the token rule: "
            f"{sample!r}: " + "; ".join(prose_failures),
            failures,
        )

    # The carve-out is the root description value only. A carrier in any
    # executable, data, or structural slot beside it — including a nested
    # `description` key of any depth, which is action-consumed data rather than
    # rendered metadata — must still fail.
    description_adjacent_carriers = (
        "description: >-\n"
        "  Refuses core.exportVariable installers.\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - shell: bash\n"
        "      run: node -e 'core.exportVariable(\"ACTIONS_RUNTIME_TOKEN\", t)'\n",
        "description: harmless\n"
        "runs:\n"
        "  steps:\n"
        "    - run: |\n"
        "        node -e 'const { exportVariable } = core; exportVariable(v, t)'\n",
        '"description": core.exportVariable is quoted, so this is not prose\n',
        "  description-suffix: core.exportVariable('ACTIONS_RUNTIME_TOKEN', t)\n",
        # A `description:`-shaped line inside a shell body must not blank the
        # rest of that body: the walk steps over `run:` scalars without reading
        # them, so the pipeline below is still scanned.
        "runs:\n"
        "  steps:\n"
        "    - shell: bash\n"
        "      run: |\n"
        "        description: |\n"
        "          node -e 'core.exportVariable(\"ACTIONS_RUNTIME_TOKEN\", t)'\n",
        # Same carrier under an inert standalone sequence scalar.
        "notes:\n"
        "  - |\n"
        "    description: |\n"
        "      core.exportVariable('ACTIONS_RUNTIME_TOKEN', t)\n",
        # An action input `description` is `core.getInput('description')` to any
        # JavaScript step in the same job, not rendered prose.
        "inputs:\n"
        "  version:\n"
        "    description: rejected because it would exportVariable the token\n",
        # Step-level compact-sequence `description` is an ordinary step key.
        "      - name: documented step\n"
        "        description: core[\"exportVariable\"] is never reached\n"
        "        run: echo ok\n",
        # A root-column sequence item is a sequence entry, not the root mapping.
        "- description: core.exportVariable('ACTIONS_RUNTIME_TOKEN', t)\n",
        # Arbitrary nested mapping: nothing marks this as rendered metadata.
        "metadata:\n"
        "  annotations:\n"
        "    description: core.exportVariable('ACTIONS_RUNTIME_TOKEN', t)\n",
        # Carrier construction through `env:`: the `run:` body never spells the
        # property contiguously, it reads it out of the environment value. If
        # `env.description` were blanked the whole leak would be invisible.
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - shell: bash\n"
        "      env:\n"
        "        description: exportVariable\n"
        "      run: node -e "
        "'core[process.env.description](\"ACTIONS_RUNTIME_TOKEN\", t)'\n",
        # Same construction through a nested action's `with:` input.
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions/github-script@v7\n"
        "      with:\n"
        "        description: exportVariable\n"
        "        script: core[core.getInput('description')]('X', t)\n",
        # An anchored root description is reachable by alias from an executable
        # slot, so the node property disqualifies the carve-out.
        "description: &leak exportVariable\n"
        "runs:\n"
        "  using: composite\n",
        # Same for a tagged root description.
        "description: !!str exportVariable\n"
        "runs:\n"
        "  using: composite\n",
        # One root mapping means one root `description:`. A second is a
        # duplicate key, not more rendered metadata, so it stays scanned.
        "description: rendered metadata\n"
        "description: exportVariable\n"
        "runs:\n"
        "  using: composite\n",
        # A non-scalar or empty first root description still consumes the
        # one root metadata slot; a later scalar is a scanned duplicate.
        "description: {carrier: harmless}\n"
        "description: exportVariable\n"
        "runs:\n"
        "  using: composite\n",
        "description:\n"
        "description: exportVariable\n"
        "runs:\n"
        "  using: composite\n",
        # A flow sequence is not rendered scalar prose.
        "description: [exportVariable]\n"
        "runs:\n"
        "  using: composite\n",
        # A flow mapping is not rendered scalar prose.
        "description: {carrier: exportVariable}\n"
        "runs:\n"
        "  using: composite\n",
        # Nested anchor inside a flow mapping, revived via alias. If the
        # flow value were blanked, `*leak` would be the only remaining
        # spelling and would not contain the contiguous token.
        "description: {carrier: &leak exportVariable}\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - env: {description: *leak}\n"
        "      run: echo ok\n",
        # Multiline flow: token on the opening line. The prose walker does
        # not collect continuation lines, so blanking this line would hide
        # the only occurrence.
        "description: {carrier: exportVariable\n"
        "}\n"
        "runs:\n"
        "  using: composite\n",
        "description: [exportVariable\n"
        "]\n"
        "runs:\n"
        "  using: composite\n",
        # Continuation-line token: the walker must not start skipping flow
        # bodies the way it skips block-scalar bodies.
        "description: {\n"
        "  carrier: exportVariable\n"
        "}\n"
        "runs:\n"
        "  using: composite\n",
        "description: [\n"
        "  exportVariable]\n"
        "runs:\n"
        "  using: composite\n",
        # Explicit complex value and compact nested sequence are not scalars.
        "description: ? exportVariable\n"
        "runs:\n"
        "  using: composite\n",
        "description: - exportVariable\n"
        "runs:\n"
        "  using: composite\n",
    )
    for index, sample in enumerate(description_adjacent_carriers):
        adjacent_failures: list[str] = []
        check_no_sccache_credential_exporter(
            sample,
            f"self-test-export-variable-adjacent-{index}",
            adjacent_failures,
        )
        require(
            any(
                "must not contain exportVariable" in item
                for item in adjacent_failures
            ),
            f"self-test: a carrier outside root description prose must fail: "
            f"{sample!r}",
            failures,
        )

    # A token-free flow value would pass the exporter check whether or not it
    # was exempted. Assert the transform leaves it in the scanned text.
    flow_kept = _without_yaml_description_prose(
        "description: {carrier: harmless}\nruns:\n  using: composite\n"
    )
    require(
        "{carrier: harmless}" in flow_kept,
        "self-test: a token-free root flow description must stay scanned, "
        f"not blanked: {flow_kept!r}",
        failures,
    )

    path_based_sccache = (
        '        echo "$install_dir" >> "$GITHUB_PATH"\n'
        '        echo "RUSTC_WRAPPER=sccache" >> "$GITHUB_ENV"\n'
        "        command -v sccache &> /dev/null && sccache --start-server\n"
        "        unset SCCACHE_GHA_ENABLED\n"
    )
    path_based_failures: list[str] = []
    check_setup_sccache_verified_activation(
        path_based_sccache,
        "self-test-path-based-sccache",
        path_based_failures,
    )
    require(
        any("empty FERRUM_SCCACHE_BIN sentinel" in item for item in path_based_failures)
        and any("must not put sccache on PATH" in item for item in path_based_failures)
        and any("verified executable, not a PATH name" in item for item in path_based_failures)
        and any("persist an empty SCCACHE_GHA_ENABLED" in item for item in path_based_failures)
        and any("never PATH lookup" in item for item in path_based_failures),
        "self-test: PATH-based sccache activation must fail",
        failures,
    )

    verified_sccache = (
        '        echo "FERRUM_SCCACHE_BIN=" >> "$GITHUB_ENV"\n'
        '        echo "FERRUM_SCCACHE_BIN=${dest}" >> "$GITHUB_ENV"\n'
        '        echo "RUSTC_WRAPPER=${sccache_bin}" >> "$GITHUB_ENV"\n'
        '        echo "CARGO_BUILD_RUSTC_WRAPPER=${sccache_bin}" >> "$GITHUB_ENV"\n'
        '        echo "SCCACHE_GHA_ENABLED=" >> "$GITHUB_ENV"\n'
        '        "$sccache_bin" --start-server 2>/dev/null\n'
    )
    verified_failures: list[str] = []
    check_setup_sccache_verified_activation(
        verified_sccache,
        "self-test-verified-sccache",
        verified_failures,
    )
    require(
        not verified_failures,
        "self-test: exact verified sccache activation should pass: "
        + "; ".join(verified_failures),
        failures,
    )

    performance_cache_fixture = (
        "jobs:\n"
        "  performance-regression:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: ./.github/actions/setup-rust-ci\n"
        "        env:\n"
        '          RUSTC_WRAPPER: ""\n'
        '          CARGO_BUILD_RUSTC_WRAPPER: ""\n'
        "        with:\n"
        '          shared-key: "ci-perf"\n'
        "          workspaces: |\n"
        "            . -> target\n"
        "            tests/performance/mesh -> target\n"
        "      - name: Stabilize performance compiler wrapper identity\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        '          source="${FERRUM_SCCACHE_BIN:-}"\n'
        '          if [ -z "$source" ] || [ ! -x "$source" ]; then\n'
        "            printf '%s\\n' 'RUSTC_WRAPPER=' "
        "'CARGO_BUILD_RUSTC_WRAPPER=' >> \"$GITHUB_ENV\"\n"
        "            exit 0\n"
        "          fi\n"
        '          stable_root="${RUNNER_TEMP}/ferrum-performance-sccache"\n'
        '          stable_wrapper="${stable_root}/bin/sccache"\n'
        '          rm -rf "$stable_root"\n'
        '          mkdir -p "${stable_root}/bin"\n'
        '          cp -- "$source" "$stable_wrapper"\n'
        '          chmod 0755 "$stable_wrapper"\n'
        "          printf '%s\\n' \"RUSTC_WRAPPER=${stable_wrapper}\" "
        '"CARGO_BUILD_RUSTC_WRAPPER=${stable_wrapper}" >> "$GITHUB_ENV"\n'
        "      - name: Build release binaries\n"
        "        run: cargo build --profile ci-release\n"
    )
    performance_cache_failures: list[str] = []
    check_performance_cache_wrapper_key(
        performance_cache_fixture,
        "self-test-performance-cache",
        performance_cache_failures,
    )
    require(
        not performance_cache_failures,
        "self-test: exact step-scoped performance cache wrapper isolation should "
        "pass: " + "; ".join(performance_cache_failures),
        failures,
    )
    for label, mutated in {
        "missing cargo wrapper": performance_cache_fixture.replace(
            '          CARGO_BUILD_RUSTC_WRAPPER: ""\n', "", 1
        ),
        "job-scoped wrapper clearing": performance_cache_fixture.replace(
            "        env:\n"
            '          RUSTC_WRAPPER: ""\n'
            '          CARGO_BUILD_RUSTC_WRAPPER: ""\n',
            "    env:\n"
            '      RUSTC_WRAPPER: ""\n'
            '      CARGO_BUILD_RUSTC_WRAPPER: ""\n',
            1,
        ),
        "missing mesh workspace": performance_cache_fixture.replace(
            "            tests/performance/mesh -> target\n", "", 1
        ),
        "missing stable wrapper copy": performance_cache_fixture.replace(
            '          cp -- "$source" "$stable_wrapper"\n', "", 1
        ),
    }.items():
        mutated_failures: list[str] = []
        check_performance_cache_wrapper_key(
            mutated,
            f"self-test-performance-cache-{label}",
            mutated_failures,
        )
        require(
            bool(mutated_failures),
            f"self-test: {label} must fail the performance cache key contract",
            failures,
        )

    missing_assert_failures: list[str] = []
    check_credential_absence_assertion(
        "run: cargo test\n",
        "self-test-missing-assert",
        missing_assert_failures,
    )
    require(
        any("cache-credential absence assertion" in item for item in missing_assert_failures),
        "self-test: missing credential assertion must fail",
        failures,
    )

    echo_token = (
        "      - name: Assert cache-service credentials are absent\n"
        "        run: |\n"
        "          echo \"$ACTIONS_RUNTIME_TOKEN\"\n"
        "          echo \"$ACTIONS_RESULTS_URL\"\n"
        '          if [ -n "${!var:-}" ]; then echo refusing to execute later PR-controlled build steps; fi\n'
    )
    echo_token_failures: list[str] = []
    check_credential_absence_assertion(
        echo_token,
        "self-test-echo-token",
        echo_token_failures,
    )
    require(
        any("must not print cache-service credential values" in item for item in echo_token_failures),
        "self-test: echoing ACTIONS_RUNTIME_TOKEN must fail",
        failures,
    )

    consumer_save = (
        "name: demo\n"
        "env:\n"
        f"  FIPS_HANDOFF_ARTIFACT: {FIPS_HANDOFF_ARTIFACT_EXPR}\n"
        f"  FIPS_HANDOFF_ARTIFACT_PREFIX: {FIPS_HANDOFF_PREFIX_EXPR}\n"
        "jobs:\n"
        "  fips-compile:\n"
        "    steps:\n"
        f"      - uses: {CACHE_SAVE} # v4.2.4\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE}\n"
        "        with:\n"
        "          path: ${{ github.workspace }}/target\n"
        "          key: fips-producer-legacy\n"
        "  fips-clippy:\n"
        "    steps:\n"
        f"      - uses: {CACHE_SAVE} # v4.2.4\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE}\n"
        "        with:\n"
        "          key: fips-producer-legacy\n"
        "  fips-test:\n"
        "    steps:\n"
        f"      - uses: {CACHE_RESTORE} # v4.2.4\n"
        f"        if: {COLD_NOT_TRUE}\n"
        "        with:\n"
        "          key: fips-producer-legacy\n"
    )
    consumer_save_failures: list[str] = []
    check_fips_producer_channel(consumer_save, consumer_save_failures)
    require(
        any(
            "must be a producer-handoff consumer and must not save" in item
            for item in consumer_save_failures
        ),
        "self-test: clippy producer save must fail",
        failures,
    )
    require(
        any(
            "must not publish the eviction-prone repository cache" in item
            for item in consumer_save_failures
        ),
        "self-test: compile repository-cache producer save must fail",
        failures,
    )
    require(
        any(
            "exactly one pinned inter-run artifact download" in item
            for item in consumer_save_failures
        ),
        "self-test: missing compile inter-run artifact download must fail",
        failures,
    )
    require(
        any(
            "must quarantine stable-cache CMake state before an optional exact inter-run promotion"
            in item
            for item in consumer_save_failures
        ),
        "self-test: missing compile artifact/build/publish ordering must fail",
        failures,
    )
    require(
        any("fips-test-build job is missing" in item for item in consumer_save_failures),
        "self-test: missing fips-test-build job must fail",
        failures,
    )
    require(
        any("test-binary producer" in item for item in consumer_save_failures),
        "self-test: missing test-binary producer dependency/result must fail",
        failures,
    )

    consumer_download = (
        "      - name: Download FIPS producer handoff\n"
        f"        if: {COLD_NOT_TRUE}\n"
        f"        uses: {DOWNLOAD_ARTIFACT} # v8\n"
        "        with:\n"
        "          pattern: ${{ env.FIPS_HANDOFF_ARTIFACT_PREFIX }}*\n"
        "          path: ${{ runner.temp }}/fips-producer-channel\n"
    )
    compile_test_precompile = (
        "      - name: Precompile FIPS test binaries for consumers\n"
        "        run: cargo test --locked --no-default-features --features fips --test unit_tests --test integration_tests --no-run\n"
        "      - name: Publish exact FIPS test executables\n"
        f"        uses: {UPLOAD_ARTIFACT}\n"
    )
    serial_test_build = (
        "name: demo\n"
        "env:\n"
        f"  FIPS_HANDOFF_ARTIFACT: {FIPS_HANDOFF_ARTIFACT_EXPR}\n"
        f"  FIPS_HANDOFF_ARTIFACT_PREFIX: {FIPS_HANDOFF_PREFIX_EXPR}\n"
        "jobs:\n"
        "  fips-compile:\n"
        "    steps:\n"
        "      - name: Build the FIPS profile\n"
        "        run: cargo build --locked --no-default-features --features fips --bin ferrum-edge\n"
        + compile_test_precompile
        + "      - name: Package FIPS producer handoff\n"
        f"        if: {COLD_NOT_TRUE}\n"
        "        run: echo packaged\n"
        "      - name: Publish FIPS producer handoff\n"
        f"        uses: {UPLOAD_ARTIFACT}\n"
        f"        if: {COLD_NOT_TRUE}\n"
        "        with:\n"
        "          name: ${{ env.FIPS_HANDOFF_ARTIFACT }}\n"
        "  fips-claimed-checks:\n"
        "    needs: fips-compile\n"
        "    steps:\n"
        + consumer_download
        + "  fips-clippy:\n"
        "    needs: fips-compile\n"
        "    steps:\n"
        + consumer_download
        + "  fips-test-build:\n"
        "    needs: fips-compile\n"
        "    steps:\n"
        + consumer_download
        + "      - name: Precompile FIPS test binaries for consumers\n"
        "      - name: Publish exact FIPS test executables\n"
        "  fips-test:\n"
        "    needs: fips-test-build\n"
        "    steps:\n"
        "      - name: Download exact FIPS test executables\n"
        "  fips-build:\n"
        "    needs:\n"
        "      - fips-compile\n"
        "      - fips-test-build\n"
        "    steps:\n"
        "      - name: Fail when FIPS test-binary compile did not succeed\n"
        "        if: needs.fips-plan.outputs.relevant == 'true' && needs.fips-test-build.result != 'success'\n"
        "        run: exit 1\n"
    )
    serial_failures: list[str] = []
    check_fips_producer_channel(serial_test_build, serial_failures)
    require(
        any("build-only producer" in item for item in serial_failures),
        "self-test: keeping test-binary precompile on fips-compile must fail",
        failures,
    )

    build_only_producer = serial_test_build.replace(compile_test_precompile, "", 1)

    test_bypass = build_only_producer.replace(
        "    needs: fips-test-build\n",
        "    needs: fips-compile\n",
        1,
    )
    bypass_failures: list[str] = []
    check_fips_producer_channel(test_bypass, bypass_failures)
    require(
        any("exact test-binary producer" in item for item in bypass_failures),
        "self-test: fips-test depending only on fips-compile must fail",
        failures,
    )

    test_build_save = build_only_producer.replace(
        "  fips-test-build:\n"
        "    needs: fips-compile\n"
        "    steps:\n"
        + consumer_download,
        "  fips-test-build:\n"
        "    needs: fips-compile\n"
        "    steps:\n"
        + consumer_download
        + "      - name: Save FIPS producer compile outputs\n"
        f"        uses: {CACHE_SAVE} # v4.2.4\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE}\n"
        "        with:\n"
        "          key: fips-producer-legacy\n",
        1,
    )
    test_build_save_failures: list[str] = []
    check_fips_producer_channel(test_build_save, test_build_save_failures)
    require(
        any(
            "fips-test-build must be a producer-handoff consumer and must not save"
            in item
            for item in test_build_save_failures
        ),
        "self-test: fips-test-build producer save must fail",
        failures,
    )

    missing_artifact_failures: list[str] = []
    check_fips_producer_channel(build_only_producer, missing_artifact_failures)
    require(
        any(
            "pinned, attempt-scoped exact-test artifact" in item
            for item in missing_artifact_failures
        ),
        "self-test: fips-test-build without exact artifact publication must fail",
        failures,
    )

    claimed_waits_for_tests = build_only_producer.replace(
        "  fips-claimed-checks:\n"
        "    needs: fips-compile\n",
        "  fips-claimed-checks:\n"
        "    needs: fips-test-build\n",
        1,
    )
    claimed_wait_failures: list[str] = []
    check_fips_producer_channel(claimed_waits_for_tests, claimed_wait_failures)
    require(
        any(
            "must not wait for test-binary precompile" in item
            for item in claimed_wait_failures
        ),
        "self-test: claimed-profile waiting for test-binary precompile must fail",
        failures,
    )

    missing_result = build_only_producer.replace(
        "        if: needs.fips-plan.outputs.relevant == 'true' && needs.fips-test-build.result != 'success'\n",
        "        if: needs.fips-plan.outputs.relevant == 'true' && needs.fips-compile.result != 'success'\n",
        1,
    )
    missing_result_failures: list[str] = []
    check_fips_producer_channel(missing_result, missing_result_failures)
    require(
        any(
            "fail closed when the test-binary producer fails" in item
            for item in missing_result_failures
        ),
        "self-test: aggregate without test-binary producer result check must fail",
        failures,
    )

    cold_test_build = build_only_producer.replace(
        "  fips-test-build:\n"
        "    needs: fips-compile\n"
        "    steps:\n"
        + consumer_download,
        "  fips-test-build:\n"
        "    needs: fips-compile\n"
        "    steps:\n"
        + consumer_download.replace(
            f"        if: {COLD_NOT_TRUE}\n",
            f"        if: {COLD_IS_TRUE}\n",
        ),
        1,
    )
    cold_test_build_failures: list[str] = []
    check_fips_producer_channel(cold_test_build, cold_test_build_failures)
    require(
        any(
            "fips-test-build producer download must skip force_cold_cache" in item
            for item in cold_test_build_failures
        ),
        "self-test: fips-test-build downloading under force_cold_cache must fail",
        failures,
    )

    handoff_channel = FIPS_WORKFLOW.read_text(encoding="utf-8")
    handoff_failures: list[str] = []
    check_fips_producer_channel(handoff_channel, handoff_failures)
    require(
        not handoff_failures,
        "self-test: checked-in FIPS artifact handoff must pass: "
        + "; ".join(handoff_failures),
        failures,
    )

    missing_cmake_quarantine = handoff_channel.replace(
        "      - name: Quarantine restored AWS-LC FIPS CMake state\n",
        "      - name: Reuse restored AWS-LC FIPS CMake state\n",
        1,
    )
    missing_cmake_quarantine_failures: list[str] = []
    check_fips_producer_channel(
        missing_cmake_quarantine, missing_cmake_quarantine_failures
    )
    require(
        any(
            "must quarantine restored AWS-LC FIPS CMake state exactly once" in item
            for item in missing_cmake_quarantine_failures
        ),
        "self-test: a missing restored AWS-LC CMake quarantine must fail",
        failures,
    )

    widened_cmake_quarantine = handoff_channel.replace(
        "-path '*/build/aws-lc-fips-sys-*/out/build' -prune -print0",
        "-path '*/build/*/out/build' -prune -print0",
        1,
    )
    widened_cmake_quarantine_failures: list[str] = []
    check_fips_producer_channel(
        widened_cmake_quarantine, widened_cmake_quarantine_failures
    )
    require(
        any(
            "removing only the restored aws-lc-fips-sys out/build trees" in item
            for item in widened_cmake_quarantine_failures
        ),
        "self-test: a widened restored CMake quarantine must fail",
        failures,
    )

    exact_hit_only_quarantine = handoff_channel.replace(
        "      - name: Quarantine restored AWS-LC FIPS CMake state\n"
        f"        if: {COLD_NOT_TRUE}\n",
        "      - name: Quarantine restored AWS-LC FIPS CMake state\n"
        f"        if: {COLD_NOT_TRUE} && "
        "steps.rust-cache.outputs.cache-hit == 'true'\n",
        1,
    )
    exact_hit_only_quarantine_failures: list[str] = []
    check_fips_producer_channel(
        exact_hit_only_quarantine, exact_hit_only_quarantine_failures
    )
    require(
        any(
            "after every non-cold stable-cache restore attempt" in item
            for item in exact_hit_only_quarantine_failures
        ),
        "self-test: an exact-hit-only CMake quarantine must fail",
        failures,
    )

    missing_zstd = handoff_channel.replace(
        "protobuf-compiler zstd", "protobuf-compiler", 1
    )
    missing_zstd_failures: list[str] = []
    check_fips_producer_channel(missing_zstd, missing_zstd_failures)
    require(
        any("must install zstd" in item for item in missing_zstd_failures),
        "self-test: a FIPS handoff job without zstd must fail",
        failures,
    )

    bsd_tar_identity_extract = handoff_channel.replace(
        'tar --zstd --no-same-owner \\\n              -xf "$archive" -C "$dest" "$identity_member"',
        'tar --zstd --no-same-owner --no-absolute-filenames \\\n              -xf "$archive" -C "$dest" "$identity_member"',
    )
    bsd_tar_identity_extract_failures: list[str] = []
    check_fips_producer_channel(
        bsd_tar_identity_extract, bsd_tar_identity_extract_failures
    )
    require(
        any(
            "BSD-only tar options unsupported by GNU tar" in item
            for item in bsd_tar_identity_extract_failures
        ),
        "self-test: BSD-only tar identity extraction must fail",
        failures,
    )

    masked_tar_listing_failure = handoff_channel.replace(
        'if ! tar --zstd -tf "$archive" >"$listing_tmp"; then',
        'tar --zstd -tf "$archive" >"$listing_tmp" || true\n'
        '            if false; then',
    )
    masked_tar_listing_failure_failures: list[str] = []
    check_fips_producer_channel(
        masked_tar_listing_failure, masked_tar_listing_failure_failures
    )
    require(
        any(
            "capture tar listings in temp files" in item
            for item in masked_tar_listing_failure_failures
        ),
        "self-test: masking tar listing failure must fail",
        failures,
    )

    hostile_tar_member = handoff_channel.replace(
        'fail "producer handoff archive member uses path traversal"',
        'fail "producer handoff archive member uses an absolute path"',
    )
    hostile_tar_member_failures: list[str] = []
    check_fips_producer_channel(hostile_tar_member, hostile_tar_member_failures)
    require(
        any(
            "reject path traversal in archive member names" in item
            for item in hostile_tar_member_failures
        ),
        "self-test: dropping path-traversal rejection must fail",
        failures,
    )

    duplicate_identity_member = handoff_channel.replace(
        'if [ "$identity_count" -ne 1 ]; then',
        'if [ "$identity_count" -lt 1 ]; then',
    )
    duplicate_identity_member_failures: list[str] = []
    check_fips_producer_channel(
        duplicate_identity_member, duplicate_identity_member_failures
    )
    require(
        any(
            "reject duplicate identity archive members" in item
            for item in duplicate_identity_member_failures
        ),
        "self-test: accepting duplicate identity members must fail",
        failures,
    )

    non_regular_identity_member = handoff_channel.replace(
        '                -*) identity_verbose_count=$((identity_verbose_count + 1)) ;;',
        '                -*|d*) identity_verbose_count=$((identity_verbose_count + 1)) ;;',
    )
    non_regular_identity_member_failures: list[str] = []
    check_fips_producer_channel(
        non_regular_identity_member, non_regular_identity_member_failures
    )
    require(
        any(
            "require identity members to be regular files" in item
            for item in non_regular_identity_member_failures
        ),
        "self-test: accepting a non-regular identity member must fail",
        failures,
    )

    special_tar_member = handoff_channel.replace(
        '                [-]*|d*) ;;',
        '                [-]*|d*|l*) ;;',
    )
    special_tar_member_failures: list[str] = []
    check_fips_producer_channel(special_tar_member, special_tar_member_failures)
    require(
        any(
            "reject symlink and special tar members" in item
            for item in special_tar_member_failures
        ),
        "self-test: accepting special tar members must fail",
        failures,
    )

    mutable_planner_path = handoff_channel.replace(
        '          git cat-file blob "$entry_object" > .github/scripts/ci_runtime_plan.py\n',
        "          filter_path=.github/scripts/ci_runtime_plan.py\n"
        "          filter_path+=.untrusted\n"
        '          git cat-file blob "$entry_object" > "$filter_path"\n',
        1,
    )
    require(
        mutable_planner_path != handoff_channel,
        "self-test: mutable FIPS planner-path fixture must alter the workflow",
        failures,
    )
    mutable_planner_path_failures: list[str] = []
    check_fips(mutable_planner_path, mutable_planner_path_failures)
    require(
        any(
            "mutable path aliases are forbidden" in item
            for item in mutable_planner_path_failures
        ),
        "self-test: a mutable FIPS planner path must fail the literal-path gate",
        failures,
    )

    decoupled_materialization = handoff_channel.replace(
        '          git cat-file blob "$entry_object" > .github/scripts/ci_runtime_plan.py\n',
        '          git cat-file blob "$entry_object" > .github/scripts/ci_runtime_telemetry.py\n',
        1,
    )
    require(
        decoupled_materialization != handoff_channel,
        "self-test: decoupled FIPS materialization fixture must alter the workflow",
        failures,
    )
    decoupled_materialization_failures: list[str] = []
    check_fips(decoupled_materialization, decoupled_materialization_failures)
    require(
        any(
            "mutable path aliases are forbidden" in item
            for item in decoupled_materialization_failures
        ),
        "self-test: a noncanonical FIPS materialization target must fail",
        failures,
    )

    missing_mtime_refresh = handoff_channel.replace(
        '          find "$target_root" -xdev -type f \\\n'
        '            -exec touch --reference="$mtime_reference" -- {} +\n',
        "          true\n",
        1,
    )
    missing_mtime_refresh_failures: list[str] = []
    check_fips_producer_channel(
        missing_mtime_refresh, missing_mtime_refresh_failures
    )
    require(
        any(
            "refresh restored target mtimes exactly once" in item
            or "mtime-refresh the exact inter-run" in item
            for item in missing_mtime_refresh_failures
        ),
        "self-test: exact FIPS restores without mtime normalization must fail",
        failures,
    )

    unstable_compiler_identity = handoff_channel.replace(
        "      - name: Stabilize Cargo compiler identity for exact-target reuse\n",
        "      - name: Leave runner-unique Cargo compiler identity active\n",
        1,
    )
    unstable_compiler_identity_failures: list[str] = []
    check_fips_producer_channel(
        unstable_compiler_identity, unstable_compiler_identity_failures
    )
    require(
        any(
            "stabilize the Cargo compiler identity" in item
            or "clear the runner-unique rustc-wrapper identity" in item
            for item in unstable_compiler_identity_failures
        ),
        "self-test: exact FIPS restores with a runner-unique wrapper must fail",
        failures,
    )

    stale_base_reuse = handoff_channel.replace(
        '          if [ "$archived_tree" != "$current_tree" ]; then\n',
        "          if false; then\n",
        1,
    )
    stale_base_reuse_failures: list[str] = []
    check_fips_producer_channel(stale_base_reuse, stale_base_reuse_failures)
    require(
        any(
            "matching source tree" in item
            for item in stale_base_reuse_failures
        ),
        "self-test: mtime normalization without source-tree equality must fail",
        failures,
    )

    missing_handoff_upload = handoff_channel.replace(
        f"        uses: {UPLOAD_ARTIFACT} # v7\n",
        "        uses: actions/upload-artifact@untrusted\n",
        1,
    )
    missing_handoff_upload_failures: list[str] = []
    check_fips_producer_channel(
        missing_handoff_upload, missing_handoff_upload_failures
    )
    require(
        any(
            "exactly one pinned producer-handoff artifact upload" in item
            for item in missing_handoff_upload_failures
        ),
        "self-test: missing pinned handoff artifact upload must fail",
        failures,
    )

    unpackaged_handoff = handoff_channel.replace(
        '          tar --zstd --hard-dereference -cf "$archive" -C "$RUNNER_TEMP" \\\n'
        "            fips-producer-identity fips-producer-source-tree \\\n"
        '            -C "$GITHUB_WORKSPACE" target .cache/sccache\n',
        "          true\n",
        1,
    )
    unpackaged_failures: list[str] = []
    check_fips_producer_channel(unpackaged_handoff, unpackaged_failures)
    require(
        any(
            "package target, sccache" in item for item in unpackaged_failures
        ),
        "self-test: direct permission-losing producer upload must fail",
        failures,
    )

    linked_handoff = handoff_channel.replace(
        "tar --zstd --hard-dereference -cf", "tar --zstd -cf", 1
    )
    linked_handoff_failures: list[str] = []
    check_fips_producer_channel(linked_handoff, linked_handoff_failures)
    require(
        any(
            "materializes hard-linked outputs as regular files" in item
            for item in linked_handoff_failures
        ),
        "self-test: a producer archive that preserves hard-link members must fail",
        failures,
    )

    eviction_prone_restore = handoff_channel.replace(
        "      - name: Download exact inter-run FIPS handoff artifact\n",
        "      - name: Restore eviction-prone FIPS handoff cache\n"
        f"        uses: {CACHE_RESTORE} # v4.2.4\n"
        "        with:\n"
        "          key: fips-handoff-legacy\n"
        "      - name: Download exact inter-run FIPS handoff artifact\n",
        1,
    )
    eviction_prone_failures: list[str] = []
    check_fips_producer_channel(eviction_prone_restore, eviction_prone_failures)
    require(
        any("eviction-prone repository cache" in item for item in eviction_prone_failures),
        "self-test: repository-cache inter-run restore must fail",
        failures,
    )

    wrong_source_name = handoff_channel.replace(
        f"          name: {FIPS_HANDOFF_SOURCE_EXPR}\n",
        "          name: fips-producer-handoff-${{ inputs.warm_source_run_id }}\n",
        1,
    )
    wrong_source_failures: list[str] = []
    check_fips_producer_channel(wrong_source_name, wrong_source_failures)
    require(
        any(
            "bind the source artifact to the event-stable source SHA" in item
            for item in wrong_source_failures
        ),
        "self-test: inter-run artifact without SHA/run/attempt binding must fail",
        failures,
    )

    synthetic_merge_source = handoff_channel.replace(
        "${{ github.event.pull_request.head.sha || github.sha }}",
        "${{ github.sha }}",
    )
    synthetic_merge_failures: list[str] = []
    check_fips_producer_channel(
        synthetic_merge_source, synthetic_merge_failures
    )
    require(
        any(
            "event-stable source SHA" in item
            or "handoff artifact" in item
            or "handoff prefix" in item
            for item in synthetic_merge_failures
        ),
        "self-test: pull-request synthetic merge SHA handoff identity must fail",
        failures,
    )

    tolerant_missing_artifact = handoff_channel.replace(
        "        id: inter-run-fips-handoff\n"
        f"        uses: {DOWNLOAD_ARTIFACT} # v8\n",
        "        id: inter-run-fips-handoff\n"
        "        continue-on-error: true\n"
        f"        uses: {DOWNLOAD_ARTIFACT} # v8\n",
        1,
    )
    tolerant_missing_failures: list[str] = []
    check_fips_producer_channel(tolerant_missing_artifact, tolerant_missing_failures)
    require(
        any(
            "fail closed when an explicitly requested inter-run" in item
            for item in tolerant_missing_failures
        ),
        "self-test: an unavailable explicitly requested warm source must fail closed",
        failures,
    )

    consumer_cache_restore = handoff_channel.replace(
        "      - name: Download FIPS producer handoff\n",
        "      - name: Restore FIPS producer compile outputs\n"
        f"        uses: {CACHE_RESTORE} # v4.2.4\n"
        "        with:\n"
        "          key: fips-producer-legacy\n"
        "      - name: Download FIPS producer handoff\n",
        1,
    )
    consumer_cache_restore_failures: list[str] = []
    check_fips_producer_channel(
        consumer_cache_restore, consumer_cache_restore_failures
    )
    require(
        any(
            "must not restore the eviction-prone repository cache" in item
            for item in consumer_cache_restore_failures
        ),
        "self-test: consumer repository-cache producer restore must fail",
        failures,
    )

    compile_cache_save = handoff_channel.replace(
        "      - name: Package FIPS producer handoff\n",
        "      - name: Save FIPS producer compile outputs\n"
        f"        uses: {CACHE_SAVE} # v4.2.4\n"
        "        with:\n"
        "          key: fips-producer-legacy\n"
        "      - name: Package FIPS producer handoff\n",
        1,
    )
    compile_cache_save_failures: list[str] = []
    check_fips_producer_channel(compile_cache_save, compile_cache_save_failures)
    require(
        any(
            "must not publish the eviction-prone repository cache" in item
            for item in compile_cache_save_failures
        ),
        "self-test: reintroducing the compile repository-cache save must fail",
        failures,
    )

    attempt_scoped_download = handoff_channel.replace(
        "          pattern: ${{ env.FIPS_HANDOFF_ARTIFACT_PREFIX }}*\n",
        "          name: ${{ env.FIPS_HANDOFF_ARTIFACT }}\n",
        1,
    )
    attempt_scoped_failures: list[str] = []
    check_fips_producer_channel(attempt_scoped_download, attempt_scoped_failures)
    require(
        any(
            "attempt-independent producer "
            "handoff pattern" in item
            for item in attempt_scoped_failures
        ),
        "self-test: an attempt-scoped consumer download must fail",
        failures,
    )

    undocumented_direct_root = handoff_channel.replace(
        '          if [ -z "$payload_dir" ] || ! is_positive_decimal "$selected_attempt"; then\n',
        '          selected="$channel_root"\n'
        '          selected_attempt="single"\n'
        '          if [ -z "$payload_dir" ] || ! is_positive_decimal "$selected_attempt"; then\n',
        1,
    )
    undocumented_direct_root_failures: list[str] = []
    check_fips_producer_channel(
        undocumented_direct_root, undocumented_direct_root_failures
    )
    require(
        any(
            "undocumented direct-root" in item
            for item in undocumented_direct_root_failures
        ),
        "self-test: accepting an undocumented direct-root artifact must fail",
        failures,
    )

    missing_flattened_layout = handoff_channel.replace(
        '            payload_dir="$channel_root"\n',
        "            true\n",
        1,
    )
    missing_flattened_failures: list[str] = []
    check_fips_producer_channel(
        missing_flattened_layout, missing_flattened_failures
    )
    require(
        any(
            "one-match flattened payload" in item
            for item in missing_flattened_failures
        ),
        "self-test: dropping the one-artifact flattened layout must fail",
        failures,
    )

    consumer_attempt_inference = handoff_channel.replace(
        '            selected_attempt="$identity_attempt"\n',
        '            selected_attempt="${GITHUB_RUN_ATTEMPT}"\n',
        1,
    )
    consumer_attempt_failures: list[str] = []
    check_fips_producer_channel(
        consumer_attempt_inference, consumer_attempt_failures
    )
    require(
        any(
            "consumer run attempt" in item or "fips-producer-identity" in item
            for item in consumer_attempt_failures
        ),
        "self-test: inferring a producer attempt from the consumer run attempt must fail",
        failures,
    )

    missing_test_flatten = handoff_channel.replace(
        "              attempt, bundle = admit_bundle(channel, None)\n",
        "              raise SystemExit('flattened layout is unsupported')\n",
        1,
    )
    missing_test_flatten_failures: list[str] = []
    check_fips_producer_channel(
        missing_test_flatten, missing_test_flatten_failures
    )
    require(
        any(
            "admit_bundle(channel, None)" in item
            or "select the newest attempt" in item
            for item in missing_test_flatten_failures
        ),
        "self-test: dropping the one-artifact FIPS test flattened layout must fail",
        failures,
    )

    attempt_scoped_test_download = handoff_channel.replace(
        "          pattern: fips-test-binaries-${{ github.run_id }}-*\n",
        "          name: fips-test-binaries-${{ github.run_id }}-${{ github.run_attempt }}\n",
        1,
    )
    attempt_scoped_test_failures: list[str] = []
    check_fips_producer_channel(
        attempt_scoped_test_download, attempt_scoped_test_failures
    )
    require(
        any(
            "failed-job reruns can reuse a skipped producer's artifact" in item
            for item in attempt_scoped_test_failures
        ),
        "self-test: an attempt-scoped FIPS test download must fail",
        failures,
    )

    oldest_test_artifact = handoff_channel.replace(
        "          _, bundle = max(attempts)\n",
        "          _, bundle = min(attempts)\n",
        1,
    )
    oldest_test_artifact_failures: list[str] = []
    check_fips_producer_channel(
        oldest_test_artifact, oldest_test_artifact_failures
    )
    require(
        any(
            "select the newest attempt" in item
            for item in oldest_test_artifact_failures
        ),
        "self-test: selecting the oldest FIPS test artifact must fail",
        failures,
    )

    fork_gated_promotion = handoff_channel.replace(
        "      - name: Promote same-run FIPS producer handoff\n"
        "        if: github.event.inputs.force_cold_cache != 'true'\n",
        "      - name: Promote same-run FIPS producer handoff\n"
        "        if: github.event.inputs.force_cold_cache != 'true' && "
        "github.event.pull_request.head.repo.fork != true\n",
        1,
    )
    fork_gated_failures: list[str] = []
    check_fips_producer_channel(fork_gated_promotion, fork_gated_failures)
    require(
        any(
            "promote the newest attempt-wildcard handoff" in item
            for item in fork_gated_failures
        ),
        "self-test: fork-gated handoff promotion must fail",
        failures,
    )

    gha_backend = good_buildkit.replace("type=local", "type=gha")
    gha_failures: list[str] = []
    check_buildkit_cache_boundary(
        gha_backend,
        "self-test-gha-backend",
        gha_failures,
    )
    require(
        any("must not use the BuildKit GHA cache backend" in item for item in gha_failures),
        "self-test: reintroducing type=gha must fail",
        failures,
    )

    scope = "production-dockerfile-smoke-default"
    restore_step = (
        "      - name: Restore BuildKit local cache\n"
        f"        if: {COLD_NOT_TRUE}\n"
        f"        uses: {CACHE_RESTORE} # v4.2.4\n"
        "        with:\n"
        f"          path: /tmp/{scope}\n"
        f"          key: {buildkit_cache_key(scope)}\n"
        "          restore-keys: |\n"
        f"            {buildkit_cache_prefix(scope)}\n"
    )
    save_step = (
        "      - name: Save BuildKit local cache\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        f"        uses: {CACHE_SAVE} # v4.2.4\n"
        "        with:\n"
        f"          path: /tmp/{scope}\n"
        f"          key: {buildkit_cache_key(scope)}\n"
    )
    good_local = "    steps:\n" + restore_step + save_step
    good_local_failures: list[str] = []
    check_local_cache_actions(
        good_local,
        "self-test-good-local-cache",
        good_local_failures,
        scope=scope,
    )
    require(
        not good_local_failures,
        "self-test: pinned restore/save should pass: "
        + "; ".join(good_local_failures),
        failures,
    )

    fork_save = good_local.replace(
        f"if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
        f"if: {COLD_NOT_TRUE} && {FORK_IS_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
    )
    fork_save_failures: list[str] = []
    check_local_cache_actions(
        fork_save,
        "self-test-fork-save",
        fork_save_failures,
        scope=scope,
    )
    require(
        any("exclude fork PRs from cache save" in item for item in fork_save_failures),
        "self-test: fork cache publication must fail",
        failures,
    )

    cold_restore = good_local.replace(
        f"if: {COLD_NOT_TRUE}\n        uses: {CACHE_RESTORE}",
        f"if: {COLD_IS_TRUE}\n        uses: {CACHE_RESTORE}",
    )
    cold_restore_failures: list[str] = []
    check_local_cache_actions(
        cold_restore,
        "self-test-cold-restore",
        cold_restore_failures,
        scope=scope,
    )
    require(
        any("restore must skip force_cold_cache" in item for item in cold_restore_failures),
        "self-test: force-cold restore must fail",
        failures,
    )

    cold_save = good_local.replace(
        f"if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
        f"if: {COLD_IS_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
    )
    cold_save_failures: list[str] = []
    check_local_cache_actions(
        cold_save,
        "self-test-cold-save",
        cold_save_failures,
        scope=scope,
    )
    require(
        any("save must skip force_cold_cache" in item for item in cold_save_failures),
        "self-test: force-cold save must fail",
        failures,
    )

    exact_hit_save = good_local.replace(
        f"if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n        uses: {CACHE_SAVE}",
        f"if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_EXACT}\n        uses: {CACHE_SAVE}",
    )
    exact_hit_save_failures: list[str] = []
    check_local_cache_actions(
        exact_hit_save,
        "self-test-exact-hit-save",
        exact_hit_save_failures,
        scope=scope,
    )
    require(
        any(
            "never save an immutable cache on an exact github.sha hit" in item
            or "run only after a partial match or miss" in item
            for item in exact_hit_save_failures
        ),
        "self-test: exact-hit cache save must fail",
        failures,
    )

    good_prepare = (
        "    steps:\n"
        "      - name: Prepare BuildKit cache for save\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        f'          out="${{RUNNER_TEMP}}/{scope}-out"\n'
        f'          dest="${{RUNNER_TEMP}}/{scope}"\n'
        '          if [ ! -d "$out" ]; then\n'
        '            echo "::error::fresh BuildKit cache export is missing; refusing to save a stale restore" >&2\n'
        "            exit 1\n"
        "          fi\n"
        '          rm -rf "$dest"\n'
        '          mv "$out" "$dest"\n'
    )
    good_prepare_failures: list[str] = []
    check_cache_save_preparation(
        good_prepare,
        "self-test-good-prepare",
        good_prepare_failures,
        scope=scope,
    )
    require(
        not good_prepare_failures,
        "self-test: fail-closed cache-save preparation should pass: "
        + "; ".join(good_prepare_failures),
        failures,
    )

    stale_dest_fallback = (
        "    steps:\n"
        "      - name: Prepare BuildKit cache for save\n"
        f"        if: {COLD_NOT_TRUE} && {FORK_NOT_TRUE} && {CACHE_KIND_PUBLISH}\n"
        "        run: |\n"
        "          set -euo pipefail\n"
        f'          out="${{RUNNER_TEMP}}/{scope}-out"\n'
        f'          dest="${{RUNNER_TEMP}}/{scope}"\n'
        '          if [ -d "$out" ]; then\n'
        '            rm -rf "$dest"\n'
        '            mv "$out" "$dest"\n'
        "          fi\n"
        '          if [ -d "$dest" ]; then\n'
        '            echo "present=true" >> "$GITHUB_OUTPUT"\n'
        "          else\n"
        '            echo "present=false" >> "$GITHUB_OUTPUT"\n'
        "          fi\n"
    )
    stale_dest_failures: list[str] = []
    check_cache_save_preparation(
        stale_dest_fallback,
        "self-test-stale-destination",
        stale_dest_failures,
        scope=scope,
    )
    require(
        any("fail when the fresh export is absent" in item for item in stale_dest_failures)
        and any("stale destination as present" in item for item in stale_dest_failures),
        "self-test: stale-destination fallback must fail",
        failures,
    )

    empty_hit = (
        "    steps:\n"
        "      - name: Record BuildKit cache restore\n"
        "        run: python3 .github/scripts/ci_runtime_telemetry.py cache --hit \"\"\n"
    )
    empty_hit_failures: list[str] = []
    check_cache_telemetry_evidence(
        empty_hit,
        "self-test-empty-hit",
        empty_hit_failures,
    )
    require(
        any("must not pass empty --hit" in item for item in empty_hit_failures),
        "self-test: empty --hit must fail",
        failures,
    )

    fabricated_hit = (
        "    steps:\n"
        "      - name: Record BuildKit cache restore\n"
        "        run: python3 .github/scripts/ci_runtime_telemetry.py cache --hit true --bytes 12\n"
    )
    fabricated_failures: list[str] = []
    check_cache_telemetry_evidence(
        fabricated_hit,
        "self-test-fabricated-hit",
        fabricated_failures,
    )
    require(
        any("must not fabricate a cache hit literal" in item for item in fabricated_failures),
        "self-test: fabricated --hit true must fail",
        failures,
    )

    missing_measurement = (
        "    steps:\n"
        "      - name: Record BuildKit cache restore\n"
        "        env:\n"
        "          CACHE_HIT: ${{ steps.buildkit-cache.outputs.cache-hit }}\n"
        "          CACHE_MATCHED: ${{ steps.buildkit-cache.outputs.cache-matched-key }}\n"
        "        run: |\n"
        "          python3 .github/scripts/ci_runtime_telemetry.py cache --hit \"$CACHE_HIT\"\n"
        "          echo produced no hit/miss evidence\n"
    )
    missing_measurement_failures: list[str] = []
    check_cache_telemetry_evidence(
        missing_measurement,
        "self-test-missing-bytes",
        missing_measurement_failures,
    )
    require(
        any("must measure restored bytes" in item for item in missing_measurement_failures),
        "self-test: missing restored-byte measurement must fail",
        failures,
    )

    line_diff_plan = (
        "    steps:\n"
        "      - name: Check for production Dockerfile smoke changes\n"
        "        run: |\n"
        '            git diff --name-only --no-renames "${trusted_sha}...HEAD" \\\n'
        '              | sort > "$changed_files"\n'
    )
    line_diff_failures: list[str] = []
    check_nul_delimited_plan(
        line_diff_plan,
        "self-test-line-diff",
        line_diff_failures,
    )
    require(
        any("must not use line-delimited git diff --name-only" in item for item in line_diff_failures)
        and any("must not pass pathname bytes through sort" in item for item in line_diff_failures),
        "self-test: line-delimited git diff --name-only must fail",
        failures,
    )

    filtered_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request:\n"
        "    paths:\n"
        "      - Dockerfile\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    filtered_trigger_failures: list[str] = []
    check_governed_live_trigger_shape(
        filtered_trigger,
        "self-test-filtered-trigger",
        filtered_trigger_failures,
    )
    require(
        any(
            "must not restore a pull_request.paths filter" in item
            for item in filtered_trigger_failures
        )
        and any(
            "must not filter a governed live trigger by `paths:`" in item
            for item in filtered_trigger_failures
        ),
        "self-test: a restored pull_request.paths filter must fail the governed "
        "trigger shape",
        failures,
    )

    ignored_paths_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request:\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
        "    paths-ignore:\n"
        "      - docs/**\n"
    )
    ignored_paths_failures: list[str] = []
    check_governed_live_trigger_shape(
        ignored_paths_trigger,
        "self-test-paths-ignore-trigger",
        ignored_paths_failures,
    )
    require(
        any(
            "must not filter a governed live trigger by `paths-ignore:`" in item
            for item in ignored_paths_failures
        ),
        "self-test: a paths-ignore filter must fail the governed trigger shape",
        failures,
    )

    wrong_branch_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request:\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - release\n"
    )
    wrong_branch_failures: list[str] = []
    check_governed_live_trigger_shape(
        wrong_branch_trigger,
        "self-test-wrong-branch-trigger",
        wrong_branch_failures,
    )
    require(
        any(
            "push trigger must cover exactly the main branch" in item
            for item in wrong_branch_failures
        ),
        "self-test: a non-main push trigger must fail the governed trigger shape",
        failures,
    )

    wrong_merge_group_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request:\n"
        "  merge_group:\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    wrong_merge_group_failures: list[str] = []
    check_governed_live_trigger_shape(
        wrong_merge_group_trigger,
        "self-test-merge-group-types",
        wrong_merge_group_failures,
    )
    require(
        any(
            "merge_group trigger must request checks on the synthesized" in item
            for item in wrong_merge_group_failures
        ),
        "self-test: a merge_group trigger without checks_requested must fail",
        failures,
    )

    pr_only_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request:\n"
    )
    pr_only_failures: list[str] = []
    check_governed_live_trigger_shape(
        pr_only_trigger,
        "self-test-pr-only-trigger",
        pr_only_failures,
    )
    require(
        any("must trigger on `merge_group`" in item for item in pr_only_failures)
        and any("must trigger on `push`" in item for item in pr_only_failures),
        "self-test: a pull-request-only live trigger must fail closed",
        failures,
    )

    # A `paths:` key inside a job step must not be mistaken for a trigger
    # filter, and the complete four-event shape must pass.
    good_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request:\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
        "\n"
        "jobs:\n"
        "  demo:\n"
        "    steps:\n"
        "      - uses: actions/upload-artifact@0000000000000000000000000000000000000000\n"
        "        with:\n"
        "          paths: target/demo\n"
    )
    good_trigger_failures: list[str] = []
    check_governed_live_trigger_shape(
        good_trigger,
        "self-test-good-trigger",
        good_trigger_failures,
    )
    require(
        not good_trigger_failures,
        "self-test: the governed four-event live trigger should pass: "
        + "; ".join(good_trigger_failures),
        failures,
    )

    extra_event_trigger = good_trigger.replace(
        "  pull_request:\n",
        "  pull_request_target:\n  pull_request:\n",
    )
    extra_event_failures: list[str] = []
    check_governed_live_trigger_shape(
        extra_event_trigger,
        "self-test-extra-trigger",
        extra_event_failures,
    )
    require(
        any("trigger events must be exactly" in item for item in extra_event_failures),
        "self-test: an extra pull_request_target trigger must fail closed",
        failures,
    )

    quoted_paths_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request:\n"
        '    "paths":\n'
        "      - Dockerfile\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    quoted_paths_failures: list[str] = []
    check_governed_live_trigger_shape(
        quoted_paths_trigger,
        "self-test-quoted-paths-trigger",
        quoted_paths_failures,
    )
    require(
        any(
            "must not filter a governed live trigger by `paths:`" in item
            for item in quoted_paths_failures
        )
        and any(
            "pull_request trigger must be an input-less block event" in item
            for item in quoted_paths_failures
        ),
        "self-test: a quoted pull_request \"paths\" key must fail the governed "
        "trigger shape",
        failures,
    )

    quoted_ignore_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request:\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
        '    "paths-ignore":\n'
        "      - docs/**\n"
    )
    quoted_ignore_failures: list[str] = []
    check_governed_live_trigger_shape(
        quoted_ignore_trigger,
        "self-test-quoted-paths-ignore-trigger",
        quoted_ignore_failures,
    )
    require(
        any(
            "must not filter a governed live trigger by `paths-ignore:`" in item
            for item in quoted_ignore_failures
        )
        and any(
            "push trigger must cover exactly the main branch" in item
            for item in quoted_ignore_failures
        ),
        "self-test: a quoted push \"paths-ignore\" key must fail the governed "
        "trigger shape",
        failures,
    )

    flow_paths_trigger = (
        "name: demo\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "  pull_request: {paths: [Dockerfile]}\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    flow_paths_failures: list[str] = []
    check_governed_live_trigger_shape(
        flow_paths_trigger,
        "self-test-flow-paths-trigger",
        flow_paths_failures,
    )
    require(
        any(
            "must use the canonical block event shape" in item
            for item in flow_paths_failures
        ),
        "self-test: a flow-form pull_request.paths mapping must fail the "
        "governed trigger shape",
        failures,
    )

    loose_skip_aggregate = (
        "    steps:\n"
        "      - name: Fail when production-image planning fails\n"
        "        if: needs.production-dockerfile-plan.result != 'success'\n"
        "        run: exit 1\n"
        "      - name: Skip production-image smoke for unrelated changes\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant != 'true'\n"
        "        run: echo skip\n"
        "      - name: Fail when the ordinary production image did not succeed\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'true'\n"
        "        run: exit 1\n"
    )
    loose_skip_failures: list[str] = []
    check_aggregate_planner_contract(
        loose_skip_aggregate,
        "production-dockerfile-plan",
        "self-test-loose-skip",
        loose_skip_failures,
    )
    require(
        any("skip must use exact" in item for item in loose_skip_failures)
        or any("skip must not use != 'true'" in item for item in loose_skip_failures),
        "self-test: aggregate skip on != 'true' must fail",
        failures,
    )

    good_aggregate = (
        "    steps:\n"
        "      - name: Fail when production-image planning fails\n"
        "        if: needs.production-dockerfile-plan.result != 'success'\n"
        "        run: exit 1\n"
        "      - name: Fail when production-image planner output is unusable\n"
        "        if: needs.production-dockerfile-plan.result == 'success' && "
        "needs.production-dockerfile-plan.outputs.relevant != 'true' && "
        "needs.production-dockerfile-plan.outputs.relevant != 'false'\n"
        "        run: exit 1\n"
        "      - name: Skip production-image smoke for unrelated changes\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'false'\n"
        "        run: echo skip\n"
        "      - name: Fail when the ordinary production image did not succeed\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'true'\n"
        "        run: exit 1\n"
    )
    good_aggregate_failures: list[str] = []
    check_aggregate_planner_contract(
        good_aggregate,
        "production-dockerfile-plan",
        "self-test-good-aggregate",
        good_aggregate_failures,
    )
    require(
        not good_aggregate_failures,
        "self-test: exact-boolean aggregate contract should pass: "
        + "; ".join(good_aggregate_failures),
        failures,
    )

    greedy_skip_capture_aggregate = (
        "    steps:\n"
        "      - name: Fail when production-image planning fails\n"
        "        if: needs.production-dockerfile-plan.result != 'success'\n"
        "        run: exit 1\n"
        "      - name: Fail when production-image planner output is unusable\n"
        "        if: needs.production-dockerfile-plan.result == 'success' && "
        "needs.production-dockerfile-plan.outputs.relevant != 'true' && "
        "needs.production-dockerfile-plan.outputs.relevant != 'false'\n"
        "        run: exit 1\n"
        "      - name: Skip production-image smoke for unrelated changes\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'false'\n"
        "        run: echo skip\n"
        "      - name: Fail when the ordinary production image did not succeed\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'true'\n"
        "        run: exit 1\n"
        "      - name: Poison for greedy skip-if capture\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant != 'true'\n"
        "        run: echo must-not-be-in-skip-if\n"
    )
    greedy_skip_capture_failures: list[str] = []
    check_aggregate_planner_contract(
        greedy_skip_capture_aggregate,
        "production-dockerfile-plan",
        "self-test-greedy-skip-capture",
        greedy_skip_capture_failures,
    )
    require(
        not greedy_skip_capture_failures,
        "self-test: post-skip steps must not pollute skip-if extraction: "
        + "; ".join(greedy_skip_capture_failures),
        failures,
    )

    missing_unusable_aggregate = (
        "    steps:\n"
        "      - name: Fail when production-image planning fails\n"
        "        if: needs.production-dockerfile-plan.result != 'success'\n"
        "        run: exit 1\n"
        "      - name: Skip production-image smoke for unrelated changes\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'false'\n"
        "        run: echo skip\n"
        "      - name: Fail when the ordinary production image did not succeed\n"
        "        if: needs.production-dockerfile-plan.outputs.relevant == 'true'\n"
        "        run: exit 1\n"
    )
    missing_unusable_failures: list[str] = []
    check_aggregate_planner_contract(
        missing_unusable_aggregate,
        "production-dockerfile-plan",
        "self-test-missing-unusable",
        missing_unusable_failures,
    )
    require(
        any("fail closed when planner output is neither" in item for item in missing_unusable_failures),
        "self-test: aggregate without unusable-output guard must fail",
        failures,
    )

    def _live_workflow(live_if: str) -> str:
        return (
            "  production-dockerfile-plan:\n"
            "    outputs:\n"
            "      relevant: ${{ steps.filter.outputs.relevant }}\n"
            "      node_waypoint_relevant: ${{ steps.filter.outputs.node_waypoint_relevant }}\n"
            "    steps:\n"
            "      - name: Check\n"
            "        run: |\n"
            '          echo "node_waypoint_relevant=true" >> "$GITHUB_OUTPUT"\n'
            "          echo trusted base has not adopted filter\n"
            '          python3 -I "$trusted_filter" --suite "$suite"\n'
            "          emit_suite_verdict node-waypoint-ebpf-live node_waypoint_relevant\n"
            "  node-waypoint-ebpf-live:\n"
            "    name: NodeWaypoint eBPF live datapath\n"
            "    needs: production-dockerfile-plan\n"
            f"    if: {live_if}\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 120\n"
            "    steps:\n"
            "      - run: kind create cluster --name demo\n"
            "      - run: tests/k8s/node_waypoint_ebpf_live/run.sh\n"
            "      - run: echo ferrum_mesh_bpf_drops_total\n"
            "        if: always()\n"
        )

    good_live_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(NODE_WAYPOINT_LIVE_IF),
        "self-test-good-live",
        good_live_failures,
    )
    require(
        not good_live_failures,
        "self-test: exact-false NodeWaypoint live skip should pass: "
        + "; ".join(good_live_failures),
        failures,
    )

    exact_true_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(
            "always() && needs.production-dockerfile-plan.outputs.node_waypoint_relevant == 'true'"
        ),
        "self-test-live-exact-true",
        exact_true_failures,
    )
    require(
        any("must not treat blank/malformed output as a skip" in item for item in exact_true_failures)
        or any("skip only on exact" in item for item in exact_true_failures),
        "self-test: NodeWaypoint live job gated on == 'true' must fail",
        failures,
    )

    no_cancelled_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(
            "needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false'"
        ),
        "self-test-live-no-cancelled",
        no_cancelled_failures,
    )
    require(
        any("!cancelled()" in item for item in no_cancelled_failures),
        "self-test: NodeWaypoint live job without !cancelled() must fail",
        failures,
    )

    uncancellable_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(
            "always() && needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false'"
        ),
        "self-test-live-uncancellable",
        uncancellable_failures,
    )
    require(
        any("!cancelled()" in item for item in uncancellable_failures),
        "self-test: NodeWaypoint live job with always() must fail cancellation policy",
        failures,
    )

    success_required_failures: list[str] = []
    check_node_waypoint_live_job(
        _live_workflow(
            "always() && needs.production-dockerfile-plan.result == 'success' && "
            "needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false'"
        ),
        "self-test-live-success-required",
        success_required_failures,
    )
    require(
        any("must not require planner success" in item for item in success_required_failures)
        or any("skip only on exact" in item for item in success_required_failures),
        "self-test: NodeWaypoint live job requiring planner success must fail",
        failures,
    )

    unbound_failures: list[str] = []
    unbound_workflow = _live_workflow(NODE_WAYPOINT_LIVE_IF).replace(
        "    needs: production-dockerfile-plan\n",
        "",
    )
    check_node_waypoint_live_job(
        unbound_workflow,
        "self-test-live-unbound",
        unbound_failures,
    )
    require(
        any("must depend on the trusted planner job" in item for item in unbound_failures),
        "self-test: NodeWaypoint live job without needs must fail",
        failures,
    )

    def _node_waypoint_aggregate(
        skip_if: str,
        fail_if: str,
        planner_run: str = "exit 1",
    ) -> str:
        return (
            "  node-waypoint-ebpf-live-gate:\n"
            "    name: NodeWaypoint eBPF Live\n"
            "    runs-on: ubuntu-latest\n"
            "    needs:\n"
            "      - production-dockerfile-plan\n"
            "      - node-waypoint-ebpf-live\n"
            "    if: always()\n"
            "    steps:\n"
            "      - name: Fail when NodeWaypoint relevance planning fails\n"
            "        if: needs.production-dockerfile-plan.result != 'success'\n"
            f"        run: {planner_run}\n"
            "      - name: Skip NodeWaypoint eBPF live datapath for unrelated changes\n"
            f"        if: {skip_if}\n"
            "        run: echo skip\n"
            "      - name: Fail when the NodeWaypoint eBPF live datapath did not succeed\n"
            f"        if: {fail_if}\n"
            "        run: exit 1\n"
        )

    exact_false_skip = f"{NODE_WAYPOINT_PLANNER_OUTPUT} == 'false'"
    scheduled_fail = (
        f"{NODE_WAYPOINT_PLANNER_OUTPUT} != 'false' && "
        "needs.node-waypoint-ebpf-live.result != 'success'"
    )

    good_aggregate_failures: list[str] = []
    check_node_waypoint_aggregate(
        _node_waypoint_aggregate(exact_false_skip, scheduled_fail),
        "self-test-node-waypoint-aggregate",
        good_aggregate_failures,
    )
    require(
        not good_aggregate_failures,
        "self-test: the exact-false NodeWaypoint aggregate should pass: "
        + "; ".join(good_aggregate_failures),
        failures,
    )

    loose_aggregate_failures: list[str] = []
    check_node_waypoint_aggregate(
        _node_waypoint_aggregate(
            f"{NODE_WAYPOINT_PLANNER_OUTPUT} != 'true'", scheduled_fail
        ),
        "self-test-node-waypoint-aggregate-loose",
        loose_aggregate_failures,
    )
    require(
        any(
            "aggregate skip must use exact" in item
            for item in loose_aggregate_failures
        )
        and any(
            "must not treat a blank verdict as irrelevance" in item
            for item in loose_aggregate_failures
        ),
        "self-test: a `!= 'true'` NodeWaypoint aggregate skip must fail",
        failures,
    )

    unscheduled_aggregate_failures: list[str] = []
    check_node_waypoint_aggregate(
        _node_waypoint_aggregate(
            exact_false_skip,
            f"{NODE_WAYPOINT_PLANNER_OUTPUT} == 'true' && "
            "needs.node-waypoint-ebpf-live.result != 'success'",
        ),
        "self-test-node-waypoint-aggregate-unscheduled",
        unscheduled_aggregate_failures,
    )
    require(
        any(
            "must fail whenever the live job was scheduled and did not succeed"
            in item
            for item in unscheduled_aggregate_failures
        ),
        "self-test: a NodeWaypoint aggregate that only judges exact-true runs "
        "must fail",
        failures,
    )

    missing_aggregate_failures: list[str] = []
    check_node_waypoint_aggregate(
        "  other-job:\n    steps:\n      - run: true\n",
        "self-test-node-waypoint-aggregate-missing",
        missing_aggregate_failures,
    )
    require(
        any(
            "aggregate so an irrelevant run still reports a result" in item
            for item in missing_aggregate_failures
        ),
        "self-test: a missing NodeWaypoint aggregate must fail",
        failures,
    )

    inert_exit_failures: list[str] = []
    check_node_waypoint_aggregate(
        _node_waypoint_aggregate(
            exact_false_skip,
            scheduled_fail,
            planner_run="echo 'exit 1'",
        ),
        "self-test-node-waypoint-inert-exit",
        inert_exit_failures,
    )
    require(
        any("effective exit 1" in item for item in inert_exit_failures),
        "self-test: inert exit text must not satisfy a NodeWaypoint failure step",
        failures,
    )

    def _exit_step(run_header: str, *body_lines: str) -> str:
        body = "".join(f"{line}\n" for line in body_lines)
        return f"      - name: Fail\n        run: {run_header}\n{body}"

    require(
        step_run_ends_with_exit("      - name: Fail\n        run: exit 1\n", 1),
        "self-test: same-line scalar `run: exit 1` must pass",
        failures,
    )
    real_literal = _exit_step(
        "|",
        "          {",
        '            echo "## NodeWaypoint eBPF Live"',
        '            echo ""',
        '            echo "Failed before trusted-base relevance planning completed."',
        '          } >> "$GITHUB_STEP_SUMMARY"',
        "          exit 1",
    )
    require(
        step_run_ends_with_exit(real_literal, 1),
        "self-test: `run: |` must reach the literal-block parser and accept "
        "summary commands then terminal exit 1",
        failures,
    )
    require(
        step_run_ends_with_exit(
            _exit_step("|-", "          echo summary", "          exit 1"),
            1,
        ),
        "self-test: literal `run: |-` with terminal exit 1 must pass",
        failures,
    )
    require(
        step_run_ends_with_exit(
            _exit_step("|+", "          echo summary", "          exit 1"),
            1,
        ),
        "self-test: literal `run: |+` with terminal exit 1 must pass",
        failures,
    )
    require(
        not step_run_ends_with_exit(
            "      - name: Fail\n        run: echo 'exit 1'\n",
            1,
        ),
        "self-test: `echo 'exit 1'` must not count as an effective exit",
        failures,
    )
    require(
        not step_run_ends_with_exit(
            _exit_step("|", "          # exit 1", "          echo skip"),
            1,
        ),
        "self-test: a comment-only `exit 1` mention must not count",
        failures,
    )
    require(
        not step_run_ends_with_exit(
            _exit_step("|", "          exit 1", "          echo still running"),
            1,
        ),
        "self-test: a non-terminal `exit 1` must not count",
        failures,
    )
    require(
        not step_run_ends_with_exit(
            _exit_step(">", "          echo summary", "          exit 1"),
            1,
        ),
        "self-test: folded `run: >` blocks must not count as an effective exit",
        failures,
    )

    real_block_planner = (
        "|\n"
        "          {\n"
        '            echo "## NodeWaypoint eBPF Live"\n'
        '            echo ""\n'
        '            echo "Failed before trusted-base relevance planning completed."\n'
        '          } >> "$GITHUB_STEP_SUMMARY"\n'
        "          exit 1"
    )
    real_block_failures: list[str] = []
    check_node_waypoint_aggregate(
        _node_waypoint_aggregate(
            exact_false_skip,
            scheduled_fail,
            planner_run=real_block_planner,
        ),
        "self-test-node-waypoint-literal-block",
        real_block_failures,
    )
    require(
        not real_block_failures,
        "self-test: NodeWaypoint planner `run: |` with summary then exit 1 "
        "should pass: " + "; ".join(real_block_failures),
        failures,
    )

    def _ambient_image_job(cache_to: str, extra_if: str = "") -> str:
        if_line = f"        if: {extra_if}\n" if extra_if else ""
        chunks: list[str] = ["    steps:\n"]
        for name, target in AMBIENT_IMAGE_BUILDS:
            chunks.append(
                f"      - name: {name}\n"
                f"{if_line}"
                f"        uses: {BUILD_PUSH} # v7\n"
                "        with:\n"
                "          context: .\n"
                "          file: Dockerfile\n"
                f"          target: {target}\n"
                "          load: true\n"
                f"          cache-from: {AMBIENT_GHA_CACHE_FROM}\n"
                f"          cache-to: {cache_to}\n"
                "          provenance: false\n"
            )
        for name in AMBIENT_IMAGE_CONTRACTS:
            chunks.append(f"      - name: {name}\n        run: echo ok\n")
        return "".join(chunks)

    good_ambient_failures: list[str] = []
    check_ambient_image_cache_budget(
        _ambient_image_job(AMBIENT_GHA_CACHE_TO),
        "self-test-good-ambient-cache",
        good_ambient_failures,
    )
    require(
        not good_ambient_failures,
        "self-test: trusted-main Ambient cache-to should pass: "
        + "; ".join(good_ambient_failures),
        failures,
    )

    unconditional_ambient_failures: list[str] = []
    check_ambient_image_cache_budget(
        _ambient_image_job(AMBIENT_GHA_CACHE_TO_EXPORT),
        "self-test-unconditional-ambient-cache-to",
        unconditional_ambient_failures,
    )
    require(
        any(
            "unconditionally from pull requests" in item
            for item in unconditional_ambient_failures
        ),
        "self-test: restoring unconditional Ambient cache-to must fail",
        failures,
    )

    skipped_ambient_failures: list[str] = []
    check_ambient_image_cache_budget(
        _ambient_image_job(
            AMBIENT_GHA_CACHE_TO, extra_if="github.event_name == 'workflow_dispatch'"
        ),
        "self-test-skipped-ambient-image-build",
        skipped_ambient_failures,
    )
    require(
        any(
            "must not skip the required image build" in item
            for item in skipped_ambient_failures
        ),
        "self-test: event-gated Ambient image builds must fail",
        failures,
    )

    fork_publish_failures: list[str] = []
    inverted_fork = AMBIENT_GHA_CACHE_TO.replace(FORK_NOT_TRUE, FORK_IS_TRUE)
    check_ambient_image_cache_budget(
        _ambient_image_job(inverted_fork),
        "self-test-ambient-fork-publish",
        fork_publish_failures,
    )
    require(
        any(
            "never from a fork" in item or "fork publication guard" in item
            for item in fork_publish_failures
        ),
        "self-test: inverted Ambient fork cache-to guard must fail",
        failures,
    )

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    failures: list[str] = []
    if self_test() != 0:
        failures.append("verify_ci_runtime_cache internal self-test failed")
    if plan_self_test() != 0:
        failures.append("ci_runtime_plan.py self-test failed")
    if telemetry_self_test() != 0:
        failures.append("ci_runtime_telemetry.py self-test failed")
    if args.self_test:
        for failure in failures:
            print(f"::error::{failure}", file=sys.stderr)
        return 1 if failures else 0

    fips = FIPS_WORKFLOW.read_text(encoding="utf-8")
    node = NODE_WORKFLOW.read_text(encoding="utf-8")
    ambient = AMBIENT_WORKFLOW.read_text(encoding="utf-8")
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    check_common_trust(fips, "fips-build.yml", failures)
    check_common_trust(node, "node-waypoint-ebpf-live.yml", failures)
    check_common_trust(ambient, "ambient-host-udp-live.yml", failures)
    check_fips(fips, failures)
    check_production_smoke(node, failures)
    check_ambient_image_cache_budget(
        extract_job(ambient, "ambient-host-udp-image"),
        "ambient-host-udp-image",
        failures,
    )
    check_shared_actions(failures)
    check_performance_cache_wrapper_key(ci, "ci.yml", failures)
    for filename, job_name, compiler_only in DIRECT_CACHE_DIET_JOBS:
        workflow = (CI_WORKFLOW.parent / filename).read_text(encoding="utf-8")
        check_direct_rust_cache_diet(
            extract_job(workflow, job_name),
            f"{filename}/{job_name}",
            failures,
            compiler_only=compiler_only,
        )
    check_docs_and_coverage(failures)
    check_dockerfile(failures)
    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    if failures:
        return 1
    print(
        "CI runtime cache contracts hold for production-image, FIPS, and "
        "Ambient image-cache gates (permissions, pins, planner, live "
        "assertions, telemetry, restore-only PR publication)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
