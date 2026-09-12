#!/usr/bin/env python3
"""Fail-closed path planner for expensive production-image, FIPS, and NodeWaypoint CI gates.

Hosted workflows extract this file from the trusted base commit before
execution so a pull request cannot widen skip patterns. Uncertainty, a missing
trusted copy, or an unknown suite must run the gate rather than skip it.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath

# Pull-request relevance for the runtime suites. Each suite lists the
# surfaces it exists to exercise; everything on the shared skip allowlist
# below (source, tests, the Cargo build graph, docs, ...) skips the expensive
# gate on a pull request and is exercised by the same suite on every push to
# `main`. Paths that are neither sensitive nor allowlisted still force-run.
SUITE_PATTERNS: dict[str, tuple[str, ...]] = {
    # Production Dockerfile smoke builds the ordinary `runtime` image and the
    # distroless `runtime-ebpf` image from the root Dockerfile. On a pull
    # request only the image definition, its staging inputs, the BPF program
    # tree the eBPF image compiles, and this planner are sensitive; whether
    # the Rust sources compile is proven by the ordinary CI lane.
    "production-dockerfile-smoke": (
        r"^Dockerfile$",
        r"^\.dockerignore$",
        r"^ebpf/",
        r"^\.github/scripts/stage_iproute2_runtime\.sh$",
        r"^\.github/workflows/node-waypoint-ebpf-live\.yml$",
        r"^\.github/scripts/ci_runtime_plan\.py$",
        r"^\.github/scripts/ci_runtime_telemetry\.py$",
        r"^\.github/scripts/verify_ci_runtime_cache\.py$",
        r"^\.github/actions/package-ferrum-runtime-image/",
    ),
    # FIPS compile/clippy/test rebuilds the aws-lc-fips-sys module and the
    # unit/integration binaries that carry the handshake and key-admission
    # assertions. On a pull request only FIPS-specific logic is sensitive: the
    # crypto-provider selection and inventory (`src/fips/`, `src/tls/`, DTLS,
    # the QUIC/TLS listeners that install a provider), the FIPS-aware tests,
    # the Cargo feature graph, and the gate's own workflow/scripts. Every
    # other source change is validated under the FIPS feature on the push to
    # `main`; a commit that breaks the FIPS build is simply not releasable.
    "fips-build": (
        r"^Cargo\.(toml|lock)$",
        r"^rust-toolchain\.toml$",
        r"^\.cargo/",
        r"^vendor/",
        r"^build\.rs$",
        r"^src/fips/",
        r"^src/tls/",
        r"^src/dtls/",
        r"^src/cli\.rs$",
        r"^src/http3/server\.rs$",
        r"^src/proxy/gateway_listener\.rs$",
        r"^src/modes/mesh/app_probe\.rs$",
        r"^tests/unit/tls/",
        r"^tests/unit/plugins/soap_ws_security_tests\.rs$",
        r"^tests/integration/(cp_grpc_handshake_admission|http3_integration)_tests\.rs$",
        r"^docs/fips\.md$",
        r"^\.github/workflows/fips-build\.yml$",
        r"^\.github/scripts/check_fips_feature_policy\.py$",
        r"^\.github/scripts/ci_runtime_plan\.py$",
        r"^\.github/scripts/ci_runtime_telemetry\.py$",
        r"^\.github/scripts/verify_ci_runtime_cache\.py$",
        r"^\.github/actions/setup-sccache/",
        r"^\.github/actions/setup-fast-linker/",
        r"^\.github/actions/setup-rust-ci/",
    ),
    # Kind/eBPF NodeWaypoint live datapath. `^src/proxy/node_waypoint_` is a
    # prefix on purpose: those modules exist solely to implement this suite,
    # so a new one must be sensitive by construction. Since #3908 this suite
    # is the ONLY relevance authority for the live job (the workflow carries
    # no `paths:` filter). Shared runtime trees are validated by the ordinary
    # shards on the PR and by this suite on every push to `main`.
    "node-waypoint-ebpf-live": (
        r"^\.github/workflows/node-waypoint-ebpf-live\.yml$",
        r"^\.dockerignore$",
        r"^\.github/actions/package-ferrum-runtime-image/",
        r"^\.github/actions/setup-kubernetes-tools/",
        r"^\.github/actions/setup-rust-ci/",
        r"^\.github/actions/setup-sccache/",
        r"^\.github/actions/setup-fast-linker/",
        r"^\.github/actions/setup-bpf-linker/",
        r"^Dockerfile$",
        r"^Dockerfile\.iproute2-layer$",
        r"^Dockerfile\.ebpf-tools-layer$",
        r"^Dockerfile\.release$",
        r"^\.github/scripts/stage_iproute2_runtime\.sh$",
        r"^ebpf/",
        r"^src/capture/",
        r"^src/ebpf/",
        r"^src/k8s_controller/",
        r"^src/modes/mesh/",
        r"^src/modes/node_agent\.rs$",
        r"^src/plugins/mesh/",
        r"^src/proxy/hbone_pool\.rs$",
        r"^src/proxy/hbone_proxy\.rs$",
        r"^src/proxy/mesh_tcp_egress\.rs$",
        r"^src/proxy/mesh_tcp_inbound\.rs$",
        r"^src/proxy/netns_capture\.rs$",
        r"^src/proxy/node_waypoint_",
        r"^charts/ferrum-mesh/",
        r"^tests/k8s/lib/",
        r"^tests/k8s/node_waypoint_ebpf_live/",
    ),
}

# Known non-sensitive surfaces that may skip when they do not also match a
# suite's sensitive patterns. Anything neither sensitive nor allowlisted
# force-runs the live gate. `docs/fips.md` and the FIPS/CI-runtime GitHub
# paths remain sensitive because those patterns are checked first.
KNOWN_SAFE_PATTERNS: tuple[str, ...] = (
    r"^README(\.|$)",
    r"^CONTRIBUTING",
    r"^LICENSE",
    r"^COPYING",
    r"^NOTICE",
    r"^AGENTS\.md$",
    r"^CLAUDE\.md$",
    # Any root-level SHOUTY Markdown document (ARCHITECTURE.md, CHANGELOG.md,
    # CONFORMANCE.md, FEATURES.md, PRODUCTION_READINESS.md, WEBSOCKET.md, ...).
    # `.dockerignore` excludes `*.md` and no Dockerfile stage COPYs one, so such
    # a file cannot reach either production image; it is not compiled, so it
    # cannot reach the FIPS build; and it is not a NodeWaypoint datapath input.
    # The class holds no `/`, so it can never match a path inside a directory.
    #
    # Issue #3908 makes this load-bearing: with the workflow-level `paths:`
    # filter retired, an unknown path force-runs the 120-minute Kind/eBPF live
    # job, and a documentation-only pull request must not pay for that.
    r"^[A-Z0-9_-]+\.md$",
    r"^CODE_OF_CONDUCT",
    r"^SECURITY\.md$",
    r"^docs/",
    r"^charts/",
    r"^openapi\.yaml$",
    r"^perftest/",
    r"^fuzz/",
    r"^examples/",
    r"^deploy/",
    r"^scripts/",
    r"^\.agents/",
    r"^\.claude/",
    r"^\.vscode/",
    r"^\.cursor/",
    r"^\.codex/",
    r"^\.github/",
    r"^Dockerfile",
    r"^ferrum\.conf$",
    r"^deny\.toml$",
    r"^\.dockerignore$",
    r"^\.gitignore$",
    r"^\.gitattributes$",
    r"^\.editorconfig$",
    r"^Makefile$",
)

# Production images dockerignore `tests/`, so those paths cannot change the
# image. FIPS clippy/tests compile `tests/`, so FIPS must not allowlist it.
# NodeWaypoint allowlists the production-image-only broadening (`src/**`,
# `vendor/**`, `.cargo/**`, `rust-toolchain.toml`, `custom_plugins/**`) so
# those diffs skip the Kind/eBPF live job unless they also match the prior
# NodeWaypoint scope above. Unknown paths still force-run.
# Shared skip allowlist for the ordinary compile inputs. These trees are
# validated by the ordinary CI lane on the pull request and by every runtime
# suite on the push to `main`, so a diff confined to them skips the expensive
# gate. Unknown paths still force-run.
ORDINARY_COMPILE_SAFE_PATTERNS: tuple[str, ...] = (
    r"^src/",
    r"^tests/",
    r"^Cargo\.(toml|lock)$",
    r"^rust-toolchain\.toml$",
    r"^\.cargo/",
    r"^vendor/",
    r"^build\.rs$",
    r"^proto/",
    r"^custom_plugins/",
    r"^ebpf/",
)

SUITE_SAFE_PATTERNS: dict[str, tuple[str, ...]] = {
    "production-dockerfile-smoke": KNOWN_SAFE_PATTERNS + ORDINARY_COMPILE_SAFE_PATTERNS,
    "fips-build": KNOWN_SAFE_PATTERNS + ORDINARY_COMPILE_SAFE_PATTERNS,
    "node-waypoint-ebpf-live": KNOWN_SAFE_PATTERNS + ORDINARY_COMPILE_SAFE_PATTERNS,
}

COMPILED = {
    suite: tuple(re.compile(pattern) for pattern in patterns)
    for suite, patterns in SUITE_PATTERNS.items()
}
COMPILED_SAFE = {
    suite: tuple(re.compile(pattern) for pattern in patterns)
    for suite, patterns in SUITE_SAFE_PATTERNS.items()
}


class ChangedFilesError(Exception):
    """Malformed or unavailable diff. The planner must fail closed."""


class UnsafeChangedFiles(Exception):
    """Decoded paths that cannot be skipped. Force the live gate to run."""

    def __init__(self, paths: list[str], reason: str) -> None:
        super().__init__(reason)
        self.paths = paths
        self.reason = reason


def unsafe_path_reason(path: str) -> str | None:
    if not path:
        return "empty path"
    if path.startswith(("/", "\\")):
        return "absolute path"
    for char in path:
        code = ord(char)
        if code < 32 or code == 127:
            return "control character"
    posix = PurePosixPath(path)
    if posix.is_absolute():
        return "absolute path"
    if ".." in posix.parts:
        return "path traversal"
    return None


def format_path_for_markdown(path: str) -> str:
    """Render a Git path without giving Markdown/HTML a raw attacker filename.

    JSON-escape (including C0 / non-ASCII) then HTML-escape inside <code>.
    """
    encoded = json.dumps(path, ensure_ascii=True)
    return f"<code>{html.escape(encoded, quote=True)}</code>"


def read_changed_files(path: Path) -> list[str]:
    """Parse a NUL-delimited `git diff --name-only --no-renames -z` listing.

    A truncated or unavailable listing fails closed. Invalid UTF-8, every C0
    control (including tab/newline), DEL, absolute paths, and traversal names
    raise UnsafeChangedFiles so the caller force-runs the suite rather than
    reporting a successful skip. An empty listing is returned as [] and the
    caller force-runs; it must not skip the expensive gate.
    """
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ChangedFilesError(f"cannot read changed-files: {error}") from error

    if raw == b"":
        return []
    if not raw.endswith(b"\0"):
        raise ChangedFilesError(
            "changed-files NUL stream is truncated (missing final NUL)"
        )

    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records = records[:-1]
    if not records:
        return []

    paths: list[str] = []
    unsafe_reason: str | None = None
    for record in records:
        if record == b"":
            raise ChangedFilesError("changed-files contains an empty NUL record")
        try:
            text = record.decode("utf-8")
        except UnicodeDecodeError as error:
            raise UnsafeChangedFiles(paths, f"invalid UTF-8: {error}") from error
        reason = unsafe_path_reason(text)
        if reason is not None:
            unsafe_reason = reason
        paths.append(text)
    if unsafe_reason is not None:
        raise UnsafeChangedFiles(paths, unsafe_reason)
    return paths


def matched_files(suite: str, changed_files: list[str]) -> list[str]:
    if suite not in COMPILED:
        raise ValueError(f"unknown CI runtime suite: {suite}")
    patterns = COMPILED[suite]
    return [
        path for path in changed_files if any(pattern.search(path) for pattern in patterns)
    ]


def unknown_files(suite: str, changed_files: list[str]) -> list[str]:
    if suite not in COMPILED or suite not in COMPILED_SAFE:
        raise ValueError(f"unknown CI runtime suite: {suite}")
    sensitive = COMPILED[suite]
    safe = COMPILED_SAFE[suite]
    unknown: list[str] = []
    for path in changed_files:
        if any(pattern.search(path) for pattern in sensitive):
            continue
        if any(pattern.search(path) for pattern in safe):
            continue
        unknown.append(path)
    return unknown


def decide_relevance(
    suite: str,
    changed: list[str],
    *,
    force_run: bool = False,
    force_unsafe: bool = False,
    unsafe_reason: str = "",
) -> tuple[bool, str, list[str]]:
    matched = matched_files(suite, changed)
    if force_run:
        return True, "Forced run (push, merge_group, dispatch, or cold-cache proof).", matched
    if force_unsafe:
        return (
            True,
            f"Diff contained an unsafe path ({unsafe_reason}); running the live "
            "gate rather than risking a false skip.",
            matched,
        )
    if not changed:
        return (
            True,
            "Empty diff; running the live gate rather than skipping.",
            matched,
        )
    if matched:
        return (
            True,
            "Diff matches a suite-sensitive path; running the live gate.",
            matched,
        )
    unknown = unknown_files(suite, changed)
    if unknown:
        return (
            True,
            "Diff contains paths that are neither sensitive nor on the skip "
            "allowlist; running the live gate.",
            matched,
        )
    return (
        False,
        "No sensitive paths matched. The cheap feature-policy / reporting "
        "jobs still run; the expensive compile/image jobs are skipped.",
        matched,
    )


def write_summary(
    suite: str, relevant: bool, changed: list[str], matched: list[str], reason: str
) -> None:
    title = suite.replace("-", " ").title()
    print(f"## {title} Runtime Path Plan")
    print()
    print(f"Relevant: **{str(relevant).lower()}**")
    print()
    print(reason)
    print()
    print("### Matched Files")
    print()
    if matched:
        for path in matched:
            print(f"- {format_path_for_markdown(path)}")
    else:
        print("(none)")
    print()
    print("### Changed Files")
    print()
    if changed:
        for path in changed:
            print(f"- {format_path_for_markdown(path)}")
    else:
        print("(none)")


def self_test() -> int:
    cases: list[tuple[str, list[str], bool]] = [
        ("production-dockerfile-smoke", ["Dockerfile"], True),
        ("production-dockerfile-smoke", [".dockerignore"], True),
        ("production-dockerfile-smoke", ["ebpf/src/lib.rs"], True),
        (
            "production-dockerfile-smoke",
            [".github/scripts/stage_iproute2_runtime.sh"],
            True,
        ),
        (
            "production-dockerfile-smoke",
            [".github/workflows/node-waypoint-ebpf-live.yml"],
            True,
        ),
        ("production-dockerfile-smoke", [".github/scripts/ci_runtime_plan.py"], True),
        (
            "production-dockerfile-smoke",
            [".github/actions/package-ferrum-runtime-image/action.yml"],
            True,
        ),
        # Ordinary compile inputs are proven by the ordinary CI lane on the
        # PR and by this smoke on every push to main.
        ("production-dockerfile-smoke", ["src/main.rs"], False),
        ("production-dockerfile-smoke", ["Cargo.lock"], False),
        ("production-dockerfile-smoke", ["vendor/foo/src/lib.rs"], False),
        ("production-dockerfile-smoke", ["custom_plugins/mod.rs"], False),
        ("production-dockerfile-smoke", ["proto/ferrum.proto"], False),
        ("production-dockerfile-smoke", ["build.rs"], False),
        ("production-dockerfile-smoke", ["tests/k8s/node_waypoint_ebpf_live/run.sh"], False),
        ("production-dockerfile-smoke", ["docs/ci_cd.md"], False),
        ("production-dockerfile-smoke", ["docs/mesh.md"], False),
        ("production-dockerfile-smoke", ["charts/ferrum-mesh/values.yaml"], False),
        ("production-dockerfile-smoke", ["README.md"], False),
        ("production-dockerfile-smoke", ["Dockerfile.release"], False),
        ("production-dockerfile-smoke", ["Dockerfile.iproute2-layer"], False),
        # FIPS-specific logic is sensitive on a pull request.
        ("fips-build", ["src/fips/policy.rs"], True),
        ("fips-build", ["src/tls/mod.rs"], True),
        ("fips-build", ["src/tls/backend.rs"], True),
        ("fips-build", ["src/dtls/mod.rs"], True),
        ("fips-build", ["src/cli.rs"], True),
        ("fips-build", ["src/http3/server.rs"], True),
        ("fips-build", ["src/proxy/gateway_listener.rs"], True),
        ("fips-build", ["tests/unit/tls/fips_policy_tests.rs"], True),
        ("fips-build", ["tests/unit/tls/fips_key_admission_tests.rs"], True),
        ("fips-build", ["tests/integration/cp_grpc_handshake_admission_tests.rs"], True),
        ("fips-build", ["tests/integration/http3_integration_tests.rs"], True),
        ("fips-build", ["tests/unit/plugins/soap_ws_security_tests.rs"], True),
        ("fips-build", ["Cargo.toml"], True),
        ("fips-build", ["Cargo.lock"], True),
        ("fips-build", ["vendor/foo/src/lib.rs"], True),
        ("fips-build", ["docs/fips.md"], True),
        ("fips-build", [".github/workflows/fips-build.yml"], True),
        ("fips-build", [".github/scripts/check_fips_feature_policy.py"], True),
        ("fips-build", [".github/actions/setup-sccache/action.yml"], True),
        # Everything else compiles under the FIPS feature on the push to main.
        ("fips-build", ["src/proxy/tcp_proxy.rs"], False),
        ("fips-build", ["src/plugins/cors.rs"], False),
        ("fips-build", ["src/admin/mod.rs"], False),
        ("fips-build", ["src/modes/mesh/mod.rs"], False),
        ("fips-build", ["tests/unit_tests.rs"], False),
        ("fips-build", ["tests/integration_tests.rs"], False),
        ("fips-build", ["tests/common/mod.rs"], False),
        ("fips-build", ["tests/scaffolding/harness.rs"], False),
        ("fips-build", ["tests/fixtures/test_rsa_public.pem"], False),
        ("fips-build", ["tests/functional/functional_admin_test.rs"], False),
        ("fips-build", ["tests/k8s/mesh_e2e_sidecar/run.sh"], False),
        ("fips-build", ["proto/ferrum.proto"], False),
        ("fips-build", ["custom_plugins/mod.rs"], False),
        ("fips-build", ["docs/ci_cd.md"], False),
        ("fips-build", ["README.md"], False),
        ("fips-build", ["charts/ferrum-mesh/values.yaml"], False),
        # Paths that match no pattern (here: shell-quoted names) are unknown
        # and force-run. Control characters never reach decide_relevance():
        # read_changed_files() raises UnsafeChangedFiles first, which the
        # transport self-test below proves.
        ("production-dockerfile-smoke", ['"src/main.rs"'], True),
        ("production-dockerfile-smoke", ['"Dockerfile"'], True),
        # NodeWaypoint: its own datapath modules, harness, and image inputs.
        ("node-waypoint-ebpf-live", ["src/ebpf/mod.rs"], True),
        ("node-waypoint-ebpf-live", ["src/capture/mod.rs"], True),
        ("node-waypoint-ebpf-live", ["src/k8s_controller/mod.rs"], True),
        ("node-waypoint-ebpf-live", ["src/modes/mesh/mod.rs"], True),
        ("node-waypoint-ebpf-live", ["src/modes/node_agent.rs"], True),
        ("node-waypoint-ebpf-live", ["src/plugins/mesh/mod.rs"], True),
        ("node-waypoint-ebpf-live", ["src/proxy/hbone_pool.rs"], True),
        ("node-waypoint-ebpf-live", ["src/proxy/mesh_tcp_egress.rs"], True),
        ("node-waypoint-ebpf-live", ["src/proxy/mesh_tcp_inbound.rs"], True),
        ("node-waypoint-ebpf-live", ["src/proxy/hbone_proxy.rs"], True),
        ("node-waypoint-ebpf-live", ["src/proxy/netns_capture.rs"], True),
        (
            "node-waypoint-ebpf-live",
            ["src/proxy/node_waypoint_ingress_capture.rs"],
            True,
        ),
        (
            "node-waypoint-ebpf-live",
            ["src/proxy/node_waypoint_udp_steering.rs"],
            True,
        ),
        # The prefix must also cover a NodeWaypoint proxy module that does not
        # exist yet, which is the regression this pattern is here to prevent.
        (
            "node-waypoint-ebpf-live",
            ["src/proxy/node_waypoint_not_yet_written.rs"],
            True,
        ),
        ("node-waypoint-ebpf-live", ["ebpf/src/lib.rs"], True),
        ("node-waypoint-ebpf-live", ["Dockerfile"], True),
        ("node-waypoint-ebpf-live", ["Dockerfile.iproute2-layer"], True),
        ("node-waypoint-ebpf-live", ["Dockerfile.release"], True),
        ("node-waypoint-ebpf-live", ["Dockerfile.ebpf-tools-layer"], True),
        ("node-waypoint-ebpf-live", [".dockerignore"], True),
        (
            "node-waypoint-ebpf-live",
            [".github/scripts/stage_iproute2_runtime.sh"],
            True,
        ),
        (
            "node-waypoint-ebpf-live",
            [".github/workflows/node-waypoint-ebpf-live.yml"],
            True,
        ),
        (
            "node-waypoint-ebpf-live",
            [".github/actions/package-ferrum-runtime-image/action.yml"],
            True,
        ),
        (
            "node-waypoint-ebpf-live",
            [".github/actions/setup-kubernetes-tools/action.yml"],
            True,
        ),
        ("node-waypoint-ebpf-live", [".github/actions/setup-rust-ci/action.yml"], True),
        ("node-waypoint-ebpf-live", [".github/actions/setup-sccache/action.yml"], True),
        ("node-waypoint-ebpf-live", [".github/actions/setup-fast-linker/action.yml"], True),
        ("node-waypoint-ebpf-live", [".github/actions/setup-bpf-linker/action.yml"], True),
        ("node-waypoint-ebpf-live", ["charts/ferrum-mesh/values.yaml"], True),
        ("node-waypoint-ebpf-live", ["tests/k8s/node_waypoint_ebpf_live/run.sh"], True),
        ("node-waypoint-ebpf-live", ["tests/k8s/lib/helpers.sh"], True),
        # Shared runtime trees, the build graph, and documentation stay on main.
        ("node-waypoint-ebpf-live", ["src/grpc/mod.rs"], False),
        ("node-waypoint-ebpf-live", ["src/identity/mod.rs"], False),
        ("node-waypoint-ebpf-live", ["src/modes/control_plane.rs"], False),
        ("node-waypoint-ebpf-live", ["src/plugins/prometheus_metrics.rs"], False),
        ("node-waypoint-ebpf-live", ["src/proxy/mod.rs"], False),
        ("node-waypoint-ebpf-live", ["src/proxy/stream_listener.rs"], False),
        ("node-waypoint-ebpf-live", ["src/proxy/tcp_proxy.rs"], False),
        ("node-waypoint-ebpf-live", ["src/proxy/udp_proxy.rs"], False),
        ("node-waypoint-ebpf-live", ["src/proxy/grpc_proxy.rs"], False),
        ("node-waypoint-ebpf-live", ["src/proxy/headers.rs"], False),
        ("node-waypoint-ebpf-live", ["src/router_cache.rs"], False),
        ("node-waypoint-ebpf-live", ["src/socket_opts.rs"], False),
        ("node-waypoint-ebpf-live", ["proto/ferrum.proto"], False),
        ("node-waypoint-ebpf-live", ["Cargo.toml"], False),
        ("node-waypoint-ebpf-live", ["Cargo.lock"], False),
        ("node-waypoint-ebpf-live", ["build.rs"], False),
        ("node-waypoint-ebpf-live", ["docs/mesh.md"], False),
        ("node-waypoint-ebpf-live", ["docs/mesh_supported_matrix.md"], False),
        ("node-waypoint-ebpf-live", ["docs/node_agent.md"], False),
        ("node-waypoint-ebpf-live", ["docs/ci_cd.md"], False),
        ("node-waypoint-ebpf-live", ["docs/plans/node_waypoint_transport_adr.md"], False),
        ("node-waypoint-ebpf-live", ["src/main.rs"], False),
        ("node-waypoint-ebpf-live", ["src/admin/mod.rs"], False),
        ("node-waypoint-ebpf-live", ["src/modes/database.rs"], False),
        ("node-waypoint-ebpf-live", ["src/plugins/cors.rs"], False),
        ("node-waypoint-ebpf-live", ["vendor/foo/src/lib.rs"], False),
        ("node-waypoint-ebpf-live", [".cargo/config.toml"], False),
        ("node-waypoint-ebpf-live", ["rust-toolchain.toml"], False),
        ("node-waypoint-ebpf-live", ["custom_plugins/mod.rs"], False),
        ("node-waypoint-ebpf-live", ["README.md"], False),
        ("node-waypoint-ebpf-live", ["ARCHITECTURE.md"], False),
        ("node-waypoint-ebpf-live", ["PRODUCTION_READINESS.md"], False),
        ("node-waypoint-ebpf-live", ["CHANGELOG.md"], False),
        ("production-dockerfile-smoke", ["PRODUCTION_READINESS.md"], False),
        ("fips-build", ["PRODUCTION_READINESS.md"], False),
        # `src/ebpf/` is sensitive even for a README inside it (prefix match).
        ("node-waypoint-ebpf-live", ["src/ebpf/README.md"], True),
        ("production-dockerfile-smoke", ["src/ebpf/README.md"], False),
        ("node-waypoint-ebpf-live", [".github/scripts/ci_runtime_plan.py"], False),
        ("node-waypoint-ebpf-live", [".github/scripts/verify_ci_runtime_cache.py"], False),
    ]
    failures: list[str] = []
    for suite, changed, expected in cases:
        relevant, _reason, _matched = decide_relevance(suite, changed)
        if relevant != expected:
            failures.append(
                f"{suite} {changed!r}: expected relevant={expected}, got {relevant}"
            )
    empty_relevant, empty_reason, _ = decide_relevance("fips-build", [])
    if not empty_relevant or "Empty diff" not in empty_reason:
        failures.append("empty diff must force-run, not skip")
    prod_empty, _, _ = decide_relevance("production-dockerfile-smoke", [])
    if not prod_empty:
        failures.append("empty production-image diff must force-run, not skip")
    unknown_relevant, unknown_reason, _ = decide_relevance(
        "fips-build", ["brand-new-crate/src/lib.rs"]
    )
    if not unknown_relevant or "allowlist" not in unknown_reason:
        failures.append("unknown valid path must force-run rather than skip")
    unknown_prod, _, _ = decide_relevance(
        "production-dockerfile-smoke", ["brand-new-crate/src/lib.rs"]
    )
    if not unknown_prod:
        failures.append("unknown production-image path must force-run rather than skip")
    node_empty, node_empty_reason, _ = decide_relevance("node-waypoint-ebpf-live", [])
    if not node_empty or "Empty diff" not in node_empty_reason:
        failures.append("empty NodeWaypoint diff must force-run, not skip")
    node_unknown, node_unknown_reason, _ = decide_relevance(
        "node-waypoint-ebpf-live", ["brand-new-crate/src/lib.rs"]
    )
    if not node_unknown or "allowlist" not in node_unknown_reason:
        failures.append("unknown NodeWaypoint path must force-run rather than skip")
    if set(SUITE_PATTERNS) != set(SUITE_SAFE_PATTERNS):
        failures.append("every planner suite must declare skip-allowlist patterns")
    try:
        matched_files("not-a-suite", ["src/main.rs"])
        failures.append("unknown suite must raise rather than skip")
    except ValueError:
        pass

    rendered = format_path_for_markdown("src/\nmain.rs")
    if "<code>" not in rendered or "\\n" not in rendered or "\n" in rendered.replace("\\n", ""):
        failures.append("newline filename must be JSON-escaped inside <code>")
    tab_rendered = format_path_for_markdown("src/\tmain.rs")
    if "\\t" not in tab_rendered:
        failures.append("tab filename must be JSON-escaped")
    tick_rendered = format_path_for_markdown("src/`rm -rf`/main.rs")
    if "<code>" not in tick_rendered or "rm -rf" not in tick_rendered:
        failures.append("backtick filename must stay inside <code>")
    pipe_rendered = format_path_for_markdown("a|b.md")
    if "<code>" not in pipe_rendered or "|" not in pipe_rendered:
        failures.append("pipe filename must be wrapped in <code>")
    html_rendered = format_path_for_markdown('<img src=x onerror=alert(1)>')
    if "<img" in html_rendered or "&lt;img" not in html_rendered:
        failures.append("HTML tag filename must be HTML-escaped")
    link_rendered = format_path_for_markdown("[click](https://evil.example/)")
    if "<code>" not in link_rendered or "[click]" not in link_rendered:
        failures.append("markdown-link filename must be wrapped in <code>")
    if link_rendered.startswith("[") or "](" in html.unescape(link_rendered).split("<code>", 1)[0]:
        failures.append("markdown-link filename must not be a raw markdown link")

    def _write(payload: bytes) -> Path:
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(payload)
        handle.close()
        return Path(handle.name)

    empty = _write(b"")
    try:
        if read_changed_files(empty) != []:
            failures.append("empty diff must parse as no changed files")
        relevant, reason, _ = decide_relevance("fips-build", read_changed_files(empty))
        if not relevant:
            failures.append("empty listing must not yield a successful expensive-gate skip")
        if "Empty diff" not in reason:
            failures.append("empty listing reason must say the gate will run")
    finally:
        empty.unlink(missing_ok=True)

    newline_path = "src/\nmain.rs"
    newline_file = _write(newline_path.encode("utf-8") + b"\0")
    try:
        read_changed_files(newline_file)
        failures.append("newline path must be unsafe and force the gate")
    except UnsafeChangedFiles as error:
        if "control" not in error.reason:
            failures.append(f"newline reason missing: {error.reason}")
        if error.paths != [newline_path]:
            failures.append(f"newline path must stay one record, got {error.paths!r}")
    except ChangedFilesError as error:
        failures.append(f"newline should force-run, not fail parse: {error}")
    finally:
        newline_file.unlink(missing_ok=True)

    tab_path = "src/\tmain.rs"
    tab_file = _write(tab_path.encode("utf-8") + b"\0")
    try:
        read_changed_files(tab_file)
        failures.append("tab path must be unsafe and force the gate")
    except UnsafeChangedFiles as error:
        if "control" not in error.reason:
            failures.append(f"tab reason missing: {error.reason}")
    finally:
        tab_file.unlink(missing_ok=True)

    del_file = _write(b"src/\x7fmain.rs\0")
    try:
        read_changed_files(del_file)
        failures.append("DEL path must be unsafe and force the gate")
    except UnsafeChangedFiles as error:
        if "control" not in error.reason:
            failures.append(f"DEL reason missing: {error.reason}")
    finally:
        del_file.unlink(missing_ok=True)

    quoted = _write(b'"src/main.rs"\0')
    try:
        parsed = read_changed_files(quoted)
        if parsed != ['"src/main.rs"']:
            failures.append(f"Git quote-like text must stay literal, got {parsed!r}")
        elif matched_files("production-dockerfile-smoke", parsed):
            failures.append("quoted src/ text must not be unquoted into a sensitive path")
    finally:
        quoted.unlink(missing_ok=True)

    invalid_utf8 = _write(b"src/\xffmain.rs\0")
    try:
        read_changed_files(invalid_utf8)
        failures.append("invalid UTF-8 must force the gate rather than skip")
    except UnsafeChangedFiles as error:
        if "UTF-8" not in error.reason:
            failures.append(f"invalid UTF-8 reason missing: {error.reason}")
    except ChangedFilesError as error:
        failures.append(f"invalid UTF-8 should force-run, not fail parse: {error}")
    finally:
        invalid_utf8.unlink(missing_ok=True)

    truncated = _write(b"src/main.rs")
    try:
        read_changed_files(truncated)
        failures.append("missing final NUL must fail closed rather than skip")
    except ChangedFilesError:
        pass
    except UnsafeChangedFiles:
        failures.append("truncated NUL stream must fail closed, not look like a decoded path")
    finally:
        truncated.unlink(missing_ok=True)

    traversal = _write(b"../Dockerfile\0")
    try:
        read_changed_files(traversal)
        failures.append("traversal path must not parse as a skippable listing")
    except UnsafeChangedFiles as error:
        if "traversal" not in error.reason:
            failures.append(f"traversal reason missing: {error.reason}")
    except ChangedFilesError as error:
        failures.append(f"traversal should force-run, not fail parse: {error}")
    finally:
        traversal.unlink(missing_ok=True)

    absolute = _write(b"/etc/passwd\0")
    try:
        read_changed_files(absolute)
        failures.append("absolute path must not parse as a skippable listing")
    except UnsafeChangedFiles as error:
        if "absolute" not in error.reason:
            failures.append(f"absolute reason missing: {error.reason}")
    except ChangedFilesError as error:
        failures.append(f"absolute should force-run, not fail parse: {error}")
    finally:
        absolute.unlink(missing_ok=True)

    missing = Path(tempfile.mkdtemp()) / "missing-changed-files"
    try:
        read_changed_files(missing)
        failures.append("unavailable diff must fail closed rather than skip")
    except ChangedFilesError:
        pass

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=sorted(SUITE_PATTERNS))
    parser.add_argument("--changed-files", type=Path)
    parser.add_argument("--force-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.suite or not args.changed_files:
        parser.error(
            "--suite and --changed-files are required unless --self-test is used"
        )

    force_unsafe = False
    unsafe_reason = ""
    try:
        changed = read_changed_files(args.changed_files)
    except ChangedFilesError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    except UnsafeChangedFiles as error:
        changed = error.paths
        force_unsafe = True
        unsafe_reason = error.reason
    try:
        relevant, reason, matched = decide_relevance(
            args.suite,
            changed,
            force_run=args.force_run,
            force_unsafe=force_unsafe,
            unsafe_reason=unsafe_reason,
        )
    except ValueError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(f"relevant={str(relevant).lower()}")
    print(f"matched_count={len(matched)}")
    write_summary(args.suite, relevant, changed, matched, reason)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
