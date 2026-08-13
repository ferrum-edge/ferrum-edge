#!/usr/bin/env python3
"""Verify that the CI aggregate waits on every required validation job."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

from check_markdown_links import check_repository, run_self_test
from check_node_agent_chart_runtime import (
    check_repository as check_node_agent_chart_runtime,
    main as node_agent_chart_runtime_main,
)
from live_suite_path_filter import (
    LIVE_SUITE_DOCUMENTATION_PATHS,
    SUITE_PATTERNS,
    exact_path_patterns,
)
from pr_ci_plan import FULL_CI_DOCUMENTATION_PATHS, self_test as planner_self_test
from validate_live_assertions import (
    run_self_test as live_assertion_validator_self_test,
)
from verify_release_image_attestations import (
    run_self_test as release_attestation_self_test,
)
from verify_release_image_attestations import (
    validate_release_workflow,
)


REQUIRED_JOBS = {
    "ci-plan",
    "test-unit",
    "test-secrets",
    "test-service-integration",
    "test-pkcs11-softhsm",
    "build-test-artifacts",
    "test-integration",
    "test-conformance",
    "dependency-audit",
    "test-vendor-patches",
    "test-functional",
    "plugin-hardening-redis-regression",
    "mesh-multicluster-federation",
    "mesh-e2e-sidecar",
    "helm-chart",
    "lint",
    "fuzz-smoke",
    "build-ebpf",
    "build-ebpf-userspace",
    "ebpf-live",
    "netns-capture-live",
    "two-cluster-mesh-live",
    "performance-regression",
    "build-binaries",
    "build-arm64-cross",
}

# These jobs do not depend on another full-CI validation job, so each must
# directly depend on the planner and enforce full mode. Other required jobs are
# downstream of one of these roots and are skipped transitively in light mode.
DIRECT_FULL_CI_JOBS = {
    "test-unit",
    "test-secrets",
    "test-service-integration",
    "test-pkcs11-softhsm",
    "build-test-artifacts",
    "test-conformance",
    "dependency-audit",
    "lint",
    "fuzz-smoke",
    "build-ebpf-userspace",
    "performance-regression",
    "build-binaries",
    "build-arm64-cross",
}

PATH_GATED_JOBS = {
    "mesh-multicluster-federation": "run_mesh_federation",
    "mesh-e2e-sidecar": "run_mesh_sidecar_smoke",
    "helm-chart": "run_helm",
    "build-ebpf": "run_ebpf_build",
    "ebpf-live": "run_ebpf_live",
    "netns-capture-live": "run_ebpf_live",
    "two-cluster-mesh-live": "run_ebpf_live",
}

REMOVED_JOBS = {
    "fmt",
    "test-lib",
    "build-integration-tests-archive",
    "test-integration-coverage",
    "build-gateway-binary",
    "build-functional-tests-archive",
    "detect-ebpf-live-changes",
}

REMOVED_MIRROR_JOBS = {
    "coverage-gate",
    "gateway-api-conformance",
    "mesh-e2e-sidecar-live",
}

DEDICATED_REQUIRED_CHECKS = {
    ".github/workflows/coverage.yml": {
        "job": "coverage-merge",
        "name": "Merge Coverage",
        "needs": {"coverage-plan", "coverage-shard"},
        "contract": {
            "needs.coverage-plan.result != 'success'",
            "needs.coverage-plan.outputs.mode == 'skip'",
            "needs.coverage-plan.outputs.mode == 'full' && needs.coverage-shard.result != 'success'",
            "!contains(fromJSON('[\"skip\", \"plugin\", \"full\"]'), needs.coverage-plan.outputs.mode)",
        },
    },
    ".github/workflows/gateway-api-conformance.yml": {
        "job": "gate",
        "name": "Gateway API Conformance",
        "needs": {"changes", "gateway-api-conformance"},
        "contract": {
            '${{ needs.changes.result }}" != "success"',
            '${{ needs.changes.outputs.relevant }}" = "false"',
            '${{ needs.changes.outputs.relevant }}" != "true"',
            '${{ needs.gateway-api-conformance.result }}" != "success"',
        },
    },
    ".github/workflows/mesh-e2e-sidecar-live.yml": {
        "job": "gate",
        "name": "Mesh E2E Sidecar Live",
        "needs": {"changes", "mesh-e2e-sidecar-live"},
        "contract": {
            '${{ needs.changes.result }}" != "success"',
            '${{ needs.changes.outputs.relevant }}" = "false"',
            '${{ needs.changes.outputs.relevant }}" != "true"',
            '${{ needs.mesh-e2e-sidecar-live.result }}" != "success"',
        },
    },
    ".github/workflows/multicluster-federation-live.yml": {
        "job": "gate",
        "name": "Multicluster Federation Live",
        # The aggregate is also the emitted-artifact release gate: it downloads
        # the published `multicluster-federation-results` artifact and validates
        # live-assertions.json against the GA/release contract. The artifact
        # steps are pinned below so a later pull request cannot keep the check
        # name while dropping the validation, and `validate=true` is emitted
        # only after the relevant-and-successful path is positively established.
        "needs": {
            "changes",
            "multicluster-federation-live",
        },
        "contract": {
            '${{ needs.changes.result }}" != "success"',
            '${{ needs.changes.outputs.relevant }}" = "false"',
            '${{ needs.changes.outputs.relevant }}" != "true"',
            '${{ needs.multicluster-federation-live.result }}" != "success"',
            'echo "validate=false" >> "$GITHUB_OUTPUT"',
            'echo "validate=true" >> "$GITHUB_OUTPUT"',
            "if: steps.summarize.outputs.validate == 'true'",
            "name: multicluster-federation-results",
            "python3 .github/scripts/validate_live_assertions.py --self-test",
            "--artifact multicluster-federation-artifact/live-assertions.json",
            "--suite multicluster-federation",
            "--platform-profile kind-spire-multicluster-federation",
            '--commit "$EXPECTED_COMMIT"',
            "EXPECTED_COMMIT: ${{ github.sha }}",
            "--max-age-seconds 21600",
            "--required-namespace multicluster.",
        },
    },
    ".github/workflows/multicluster-poller-partition-live.yml": {
        "job": "gate",
        "name": "Multicluster Poller Partition Live",
        # Aggregate required check plus emitted-artifact gate. Relevance may
        # skip the expensive live job; validate=true is emitted only after the
        # relevant-and-successful path is positively established so a skipped
        # suite still reports the required check green without demanding an
        # artifact that was never produced.
        "needs": {
            "changes",
            "multicluster-poller-partition-live",
        },
        "contract": {
            '${{ needs.changes.result }}" != "success"',
            '${{ needs.changes.outputs.relevant }}" = "false"',
            '${{ needs.changes.outputs.relevant }}" != "true"',
            '${{ needs.multicluster-poller-partition-live.result }}" != "success"',
            'echo "validate=false" >> "$GITHUB_OUTPUT"',
            'echo "validate=true" >> "$GITHUB_OUTPUT"',
            "if: steps.summarize.outputs.validate == 'true'",
            "name: multicluster-poller-partition-results",
            "python3 .github/scripts/validate_live_assertions.py --self-test",
            "--artifact multicluster-poller-partition-artifact/live-assertions.json",
            "--suite multicluster-poller-partition",
            "--platform-profile kind-spire-toxiproxy-multicluster-pollers",
            '--commit "$EXPECTED_COMMIT"',
            "EXPECTED_COMMIT: ${{ github.sha }}",
            "--max-age-seconds 21600",
            "--required-namespace multicluster_poller.",
            "multicluster_poller.withdrawal.inflight_generation_retired",
            "multicluster_poller.withdrawal.retired_state_not_reinstalled",
        },
    },
}

# The artifact validator is only a gate if it is reached with a SHA-pinned
# download and no toolchain step. Pin those properties structurally rather than
# by substring alone.
ARTIFACT_GATE_WORKFLOW = ".github/workflows/multicluster-federation-live.yml"
ARTIFACT_GATE_DOWNLOAD_ACTION = (
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
)
# The release-blocking `multicluster.*` ids, mirrored from the enforced,
# non-deferred `multicluster-federation` rows of tests/conformance/ga_contract.yaml.
# `tests/conformance/live_contract.rs` asserts set equality between this
# workflow's `--require` list, run.sh's REQUIRED_LIVE_ASSERTIONS, and the
# contract, so a drift in any one of the three fails the hosted suite.
ARTIFACT_GATE_REQUIRED_IDS = {
    "multicluster.spire.federation_ready_a",
    "multicluster.spire.federation_ready_b",
    "multicluster.federation.trust_bundle_exchange",
    "multicluster.spire.workload_entries",
    "multicluster.eastwest.gateway_reachable",
    "multicluster.eastwest.a_to_b_authenticated",
    "multicluster.eastwest.b_to_a_authenticated",
    "multicluster.eastwest.bidirectional_authenticated_traffic",
    "multicluster.eastwest.untrusted_peer_rejected",
    "multicluster.federation.bundle_revoked_rejected",
    "multicluster.federation.trust_restored_recovers",
    "multicluster.eastwest.endpoint_blackhole_when_dest_down",
    "multicluster.eastwest.endpoint_recovers_when_dest_returns",
}

MAIN_PUBLISH_WORKFLOWS = {
    ".github/workflows/coverage.yml": "Coverage",
    ".github/workflows/gateway-api-conformance.yml": "Gateway API Conformance",
    ".github/workflows/mesh-e2e-sidecar-live.yml": (
        "Mesh E2E Sidecar Live Datapath"
    ),
}

DEDICATED_WORKFLOW_NAMES = {
    **MAIN_PUBLISH_WORKFLOWS,
    ".github/workflows/multicluster-federation-live.yml": (
        "Multicluster Federation Live Datapath"
    ),
    ".github/workflows/multicluster-poller-partition-live.yml": (
        "Multicluster Poller Partition Live"
    ),
}

# Every required status check owner must trigger on merge_group. Without that
# trigger a merge queue never receives the required check and deadlocks.
REQUIRED_MERGE_GROUP_WORKFLOWS = {
    ".github/workflows/ci.yml": "Tests",
    ".github/workflows/coverage.yml": "Merge Coverage",
    ".github/workflows/gateway-api-conformance.yml": "Gateway API Conformance",
    ".github/workflows/mesh-e2e-sidecar-live.yml": "Mesh E2E Sidecar Live",
    ".github/workflows/cross-build-policy.yml": "Trusted Cross Build Policy",
    ".github/workflows/launch-integrity.yml": "Launch Readiness Integrity",
    ".github/workflows/multicluster-federation-live.yml": (
        "Multicluster Federation Live"
    ),
    ".github/workflows/multicluster-poller-partition-live.yml": (
        "Multicluster Poller Partition Live"
    ),
    ".github/workflows/ambient-host-udp-live.yml": "Ambient Host UDP Live",
}

# Markers that prove merge-group runs bind validation to the synthesized SHA /
# payload base rather than absent pull_request fields or a main-only fallback.
MERGE_GROUP_SHA_CONTRACT_MARKERS = (
    "merge_group",
    "github.event.merge_group.base_sha",
    "merge_group base_sha missing or malformed",
)

# Concurrency keys must distinguish merge-group runs from PR/push/manual lanes.
MERGE_GROUP_CONCURRENCY_MARKERS = (
    "merge_group",
    "merge_group.head_sha",
)

# The polling implementation is a release-integrity boundary. Pinning the exact
# job body prevents a later pull request from satisfying individual substring
# checks with comments while changing the array, query, row validation, or
# fail-closed conclusions the publishing jobs actually consume. The protected
# Cross verifier independently freezes this complete job, so changing either
# the implementation or this diagnostic digest requires a trusted-base update.
MAIN_PUBLISH_GATE_SHA256 = (
    "51d93dead7e8337df4cd85a8c034d11436ee8d1935d8e6b2e58509c5e7da8fb4"
)


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


def extract_job_body(ci_yml: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        ci_yml,
    )
    if not match:
        raise RuntimeError(f"could not find jobs.{job} in ci.yml")
    return match.group("body")


def extract_job_needs(job_body: str) -> set[str]:
    list_match = re.search(
        r"(?m)^    needs:\n(?P<needs>(?:^      - [^\n]+\n)+)", job_body
    )
    if list_match:
        return {
            line.strip().removeprefix("- ").strip()
            for line in list_match.group("needs").splitlines()
            if line.strip().startswith("- ")
        }

    inline_match = re.search(
        r"(?m)^    needs: \["
        r"(?P<needs>[A-Za-z0-9_-]+(?:, [A-Za-z0-9_-]+)*)"
        r"\]$",
        job_body,
    )
    if inline_match:
        return set(inline_match.group("needs").split(", "))

    scalar_match = re.search(r"(?m)^    needs: ([A-Za-z0-9_-]+)$", job_body)
    if scalar_match:
        return {scalar_match.group(1)}
    return set()


def job_needs(body: str, dependency: str) -> bool:
    return dependency in extract_job_needs(body)


def workflow_event_body(workflow_yml: str, event: str) -> str | None:
    """Extract one canonical event mapping without crossing the `on` scope."""

    lines = workflow_yml.splitlines(keepends=True)
    on_headers = [
        index for index, line in enumerate(lines) if line.rstrip("\r\n") == "on:"
    ]
    if len(on_headers) != 1:
        return None

    on_start = on_headers[0]
    on_end = next(
        (
            index
            for index in range(on_start + 1, len(lines))
            if re.match(r"^[A-Za-z0-9_-]+:", lines[index])
        ),
        len(lines),
    )
    event_line = f"  {event}:"
    event_headers = [
        index
        for index in range(on_start + 1, on_end)
        if lines[index].rstrip("\r\n") == event_line
    ]
    if len(event_headers) != 1:
        return None

    event_start = event_headers[0]
    event_end = next(
        (
            index
            for index in range(event_start + 1, on_end)
            if re.match(r"^  [A-Za-z0-9_-]+:", lines[index])
        ),
        on_end,
    )
    return "".join(lines[event_start + 1 : event_end])


def pull_request_trigger_is_unconditional(workflow_yml: str) -> bool:
    body = workflow_event_body(workflow_yml, "pull_request")
    if body is None:
        # Trusted Cross Build Policy uses pull_request_target instead.
        body = workflow_event_body(workflow_yml, "pull_request_target")
        if body is None:
            return False
    return not re.search(r"(?m)^    paths(?:-ignore)?:", body)


def merge_group_trigger_is_present(workflow_yml: str) -> bool:
    """Return whether the workflow declares an unconditional merge_group trigger."""

    body = workflow_event_body(workflow_yml, "merge_group")
    if body is None:
        return False
    if re.search(r"(?m)^    (?:branches(?:-ignore)?|paths(?:-ignore)?):", body):
        return False
    return True


def merge_group_self_test() -> list[str]:
    """Deterministic fixtures for merge-queue required-check contracts."""

    failures: list[str] = []

    # Absent pull_request payload must not be treated as a path-gated event by
    # the planners once merge_group is selected.
    from coverage_plan import select_mode as coverage_select_mode
    from pr_ci_plan import select_job_gates, select_mode as pr_select_mode

    mode, _ = pr_select_mode("merge_group", [])
    if mode != "full":
        failures.append("empty merge_group change set must fail closed to full CI")
    mode, _ = pr_select_mode(
        "merge_group",
        ["docs/admin_api.md", "src/proxy/mod.rs"],
    )
    if mode != "full":
        failures.append("multi-PR merge_group with code paths must stay full CI")
    mode, _ = pr_select_mode("merge_group", ["docs/admin_api.md"])
    if mode != "light":
        failures.append("docs-only merge_group should remain path-gated light CI")
    gates = select_job_gates("merge_group", [])
    if not all(gates.values()):
        failures.append("empty merge_group gates must fail closed to all suites")
    gates = select_job_gates("merge_group", ["README.md"])
    if any(gates.values()):
        failures.append("irrelevant merge_group paths must not force live suites")
    mode, _ = coverage_select_mode("merge_group", [])
    if mode != "full":
        failures.append("empty merge_group coverage must fail closed to full")
    mode, _ = coverage_select_mode("merge_group", ["docs/configuration.md"])
    if mode != "skip":
        failures.append("irrelevant merge_group coverage paths should skip")

    # Synthetic workflow snippets: path filters / concurrency / fork-safe base.
    bare_pr_only = "on:\n  pull_request:\n"
    if merge_group_trigger_is_present(bare_pr_only):
        failures.append("pull_request-only workflow must not report merge_group")
    with_merge_group = (
        "on:\n  pull_request:\n  merge_group:\n    types:\n      - checks_requested\n"
    )
    if not merge_group_trigger_is_present(with_merge_group):
        failures.append("checks_requested merge_group trigger must be accepted")
    path_filtered = (
        "on:\n  merge_group:\n    paths:\n      - src/**\n"
    )
    if merge_group_trigger_is_present(path_filtered):
        failures.append("path-filtered merge_group must be rejected")
    branches_filtered = (
        "on:\n  merge_group:\n    branches:\n      - main\n"
    )
    if merge_group_trigger_is_present(branches_filtered):
        failures.append("branches-restricted merge_group must be rejected")

    # A merge queue admits a pull request only after its required checks have
    # already passed on the pull request itself, so every required owner must
    # also report unconditionally on the PR event it uses. Trusted Cross Build
    # Policy reports through `pull_request_target`, not `pull_request`.
    target_only = "on:\n  pull_request_target:\n    branches:\n      - main\n"
    if not pull_request_trigger_is_unconditional(target_only):
        failures.append(
            "pull_request_target-only workflow must count as an unconditional "
            "pull-request trigger"
        )
    target_path_filtered = (
        "on:\n  pull_request_target:\n    paths:\n      - src/**\n"
    )
    if pull_request_trigger_is_unconditional(target_path_filtered):
        failures.append("path-filtered pull_request_target must be rejected")
    no_pr_trigger = "on:\n  push:\n    branches:\n      - main\n"
    if pull_request_trigger_is_unconditional(no_pr_trigger):
        failures.append("workflow without any pull-request trigger must be rejected")

    # Fork-origin PR provenance still uses base_ref charset validation in the
    # frozen live-suite contract; merge_group uses payload base_sha instead.
    relevance = Path(
        ".github/workflows/mesh-e2e-sidecar-live.yml"
    ).read_text(encoding="utf-8")
    for marker in (
        'elif [ "$EVENT_NAME" = "merge_group" ]; then',
        "MERGE_BASE_SHA: ${{ github.event.merge_group.base_sha }}",
        'github.base_ref',
        "^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$",
    ):
        if marker not in relevance:
            failures.append(
                f"mesh live relevance contract missing merge_group/fork marker {marker!r}"
            )

    cross = Path(".github/workflows/cross-build-policy.yml").read_text(encoding="utf-8")
    for marker in (
        "pull_request_target:",
        "merge_group:",
        "contents: read",
        'EVENT_NAME: ${{ github.event_name }}',
        'unsupported event',
        "persist-credentials: false",
        "github.event.merge_group.base_sha",
        "github.event.merge_group.head_sha",
    ):
        if marker not in cross:
            failures.append(f"cross-build policy missing merge_group safety marker {marker!r}")

    return failures


def main_push_trigger_is_unconditional(workflow_yml: str) -> bool:
    """Return whether every push to main starts this workflow."""

    body = workflow_event_body(workflow_yml, "push")
    if body is None:
        return False
    if re.search(r"(?m)^    (?:branches-ignore|paths|paths-ignore):", body):
        return False
    branches = re.search(
        r"(?m)^    branches:\n(?P<branches>(?:^      - [^\n]+\n?)+)",
        body,
    )
    if not branches:
        return False
    configured = {
        line.strip().removeprefix("- ").strip("'\"")
        for line in branches.group("branches").splitlines()
        if line.strip().startswith("- ")
    }
    return configured == {"main"}


def workflow_has_exact_name(workflow_yml: str, expected: str) -> bool:
    names = re.findall(r"(?m)^name: ([^\n]+)$", workflow_yml)
    if len(names) != 1:
        return False
    actual = names[0].strip()
    if len(actual) >= 2 and actual[0] == actual[-1] and actual[0] in "'\"":
        actual = actual[1:-1]
    return actual == expected


def extract_documentation_paths(workflow_yml: str) -> set[str]:
    paths = set(
        re.findall(
            r"(?m)^\s+-\s+[\"']?(docs/[^\"'\s]+)[\"']?\s*$",
            workflow_yml,
        )
    )
    if not paths:
        raise RuntimeError("could not find documentation paths in live workflow")
    return paths


def extract_required_assertion_ids(gate_body: str) -> set[str]:
    """Return the `--require <id>` arguments the artifact gate passes."""

    return set(re.findall(r"--require\s+(\S+)", gate_body))


def validate_artifact_gate_wiring() -> list[str]:
    """Prove the emitted-artifact gate is wired, pinned, and fail-closed.

    A `Multicluster Federation Live` check that merely reports the live job's
    conclusion cannot see what the run published. These checks fail the hosted
    `Verify required CI aggregate wiring` step if a later change keeps the
    required check name while removing the download, the validator, the exact
    commit binding, or an id from the release contract.
    """

    errors: list[str] = []
    workflow_yml = Path(ARTIFACT_GATE_WORKFLOW).read_text(encoding="utf-8")
    gate_body = extract_job_body(workflow_yml, "gate")

    if ARTIFACT_GATE_DOWNLOAD_ACTION not in gate_body:
        errors.append(
            f"{ARTIFACT_GATE_WORKFLOW} jobs.gate must download the published live "
            f"artifact with the pinned `{ARTIFACT_GATE_DOWNLOAD_ACTION}`"
        )

    # The gate must stay free of any build/toolchain step so the trusted build
    # policy keeps reading it as a non-build job.
    for forbidden in ("cargo ", "setup-rust", "rustup", "docker build", "kind "):
        if forbidden in gate_body:
            errors.append(
                f"{ARTIFACT_GATE_WORKFLOW} jobs.gate must not run `{forbidden.strip()}`; "
                "the aggregate gate carries no build or toolchain surface"
            )

    validator = Path(".github/scripts/validate_live_assertions.py")
    if not validator.is_file():
        errors.append(f"{validator} must exist; it is the emitted-artifact gate")

    required_ids = extract_required_assertion_ids(gate_body)
    if required_ids != ARTIFACT_GATE_REQUIRED_IDS:
        missing = sorted(ARTIFACT_GATE_REQUIRED_IDS - required_ids)
        unexpected = sorted(required_ids - ARTIFACT_GATE_REQUIRED_IDS)
        errors.append(
            f"{ARTIFACT_GATE_WORKFLOW} jobs.gate must require exactly the "
            f"release-contract assertion ids (missing: {missing}, "
            f"unexpected: {unexpected})"
        )

    # Every artifact step must be reached only through the positively
    # established relevant-and-successful path, so an irrelevant pull request
    # never tries to download an artifact that was never produced.
    for step_marker in (
        "name: Checkout Ferrum Edge",
        "name: Download live assertion artifact",
        "name: Validate emitted live assertion artifact",
    ):
        index = gate_body.find(step_marker)
        if index < 0:
            errors.append(
                f"{ARTIFACT_GATE_WORKFLOW} jobs.gate is missing step `{step_marker}`"
            )
            continue
        following = gate_body[index : index + 400]
        if "if: steps.summarize.outputs.validate == 'true'" not in following:
            errors.append(
                f"{ARTIFACT_GATE_WORKFLOW} jobs.gate step `{step_marker}` must be "
                "gated on the summarize step's `validate` output"
            )

    return errors


def main() -> int:
    ci_path = Path(".github/workflows/ci.yml")
    ci_yml = ci_path.read_text(encoding="utf-8")
    needs = extract_test_needs(ci_yml)
    missing = sorted(REQUIRED_JOBS - needs)
    extra = sorted(needs - REQUIRED_JOBS)

    planner_errors: list[str] = []
    aggregate_body = extract_job_body(ci_yml, "test")
    for job in sorted(REQUIRED_JOBS):
        if f"needs.{job}.result" not in aggregate_body:
            planner_errors.append(
                f"jobs.test must report and enforce the result of `{job}`"
            )

    for job in sorted(REMOVED_MIRROR_JOBS):
        if re.search(rf"(?m)^  {re.escape(job)}:$", ci_yml):
            planner_errors.append(f"jobs.{job} must remain removed from ci.yml")
    if "(CI mirror)" in ci_yml:
        planner_errors.append("ci.yml must not contain runner-holding CI mirror jobs")

    publish_gate_body = extract_job_body(ci_yml, "main-publish-gate")
    publish_gate_sha256 = hashlib.sha256(publish_gate_body.encode()).hexdigest()
    if publish_gate_sha256 != MAIN_PUBLISH_GATE_SHA256:
        planner_errors.append(
            "jobs.main-publish-gate differs from the trusted same-SHA polling "
            "contract"
        )
    if not all(
        job_needs(publish_gate_body, dependency)
        for dependency in ("test", "build-binaries")
    ):
        planner_errors.append(
            "jobs.main-publish-gate must depend on Tests and build-binaries"
        )
    for workflow_path, workflow in sorted(MAIN_PUBLISH_WORKFLOWS.items()):
        workflow_file = Path(workflow_path).name
        specification = f"{workflow_file}|{workflow_path}|{workflow}"
        if f'            "{specification}"' not in publish_gate_body:
            planner_errors.append(
                "jobs.main-publish-gate must bind canonical workflow "
                f"`{workflow_path}` to display name `{workflow}`"
            )
    # The gate polls the Actions API, so it must stay scoped to `main` pushes.
    # Without this it would become a runner-holding mirror job on every pull
    # request, which is exactly what the dedicated workflows replaced.
    for condition in (
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
    ):
        if condition not in publish_gate_body:
            planner_errors.append(
                f"jobs.main-publish-gate must stay scoped by `{condition}`"
            )
    for job in ("latest-release", "docker"):
        body = extract_job_body(ci_yml, job)
        if not job_needs(body, "main-publish-gate"):
            planner_errors.append(f"jobs.{job} must depend on main-publish-gate")
        if "needs.main-publish-gate.result == 'success'" not in body:
            planner_errors.append(
                f"jobs.{job} must require a successful main-publish-gate"
            )

    for job in sorted(DIRECT_FULL_CI_JOBS):
        body = extract_job_body(ci_yml, job)
        if not job_needs(body, "ci-plan"):
            planner_errors.append(f"jobs.{job} must directly need ci-plan")
        if "needs.ci-plan.outputs.mode == 'full'" not in body:
            planner_errors.append(f"jobs.{job} must require full CI mode")

    for job, output in sorted(PATH_GATED_JOBS.items()):
        body = extract_job_body(ci_yml, job)
        if not job_needs(body, "ci-plan"):
            planner_errors.append(f"jobs.{job} must directly need ci-plan")
        if "needs.ci-plan.outputs.mode == 'full'" not in body:
            planner_errors.append(f"jobs.{job} must require full CI mode")
        if f"needs.ci-plan.outputs.{output} == 'true'" not in body:
            planner_errors.append(
                f"jobs.{job} must use the ci-plan `{output}` path gate"
            )
        if f"needs.ci-plan.outputs.{output}" not in aggregate_body:
            planner_errors.append(
                f"jobs.test must enforce the ci-plan `{output}` path gate"
            )

    for job in sorted(REMOVED_JOBS):
        if re.search(rf"(?m)^  {re.escape(job)}:$", ci_yml):
            planner_errors.append(f"consolidated jobs.{job} must not remain in ci.yml")

    for workflow_path, required_check in DEDICATED_REQUIRED_CHECKS.items():
        workflow_yml = Path(workflow_path).read_text(encoding="utf-8")
        expected_workflow_name = DEDICATED_WORKFLOW_NAMES.get(workflow_path)
        if expected_workflow_name is not None:
            if not workflow_has_exact_name(workflow_yml, expected_workflow_name):
                planner_errors.append(
                    f"{workflow_path} must keep workflow name "
                    f"`{expected_workflow_name}` for the main publish gate"
                )
            if not main_push_trigger_is_unconditional(workflow_yml):
                planner_errors.append(
                    f"{workflow_path} must run on every push to main for the "
                    "main publish gate"
                )
        if not pull_request_trigger_is_unconditional(workflow_yml):
            planner_errors.append(
                f"{workflow_path} must trigger on every pull request without path filters"
            )

        job = str(required_check["job"])
        body = extract_job_body(workflow_yml, job)
        expected_name = str(required_check["name"])
        if not re.search(rf"(?m)^    name: {re.escape(expected_name)}$", body):
            planner_errors.append(
                f"{workflow_path} jobs.{job} must keep required check name `{expected_name}`"
            )
        if not re.search(r"(?m)^    if: always\(\)$", body):
            planner_errors.append(f"{workflow_path} jobs.{job} must run with if: always()")
        if not re.search(r"(?m)^    runs-on: ubuntu-latest$", body):
            planner_errors.append(
                f"{workflow_path} jobs.{job} must use the dedicated required-check runner"
            )

        expected_needs = set(required_check["needs"])
        actual_needs = extract_job_needs(body)
        if actual_needs != expected_needs:
            planner_errors.append(
                f"{workflow_path} jobs.{job}.needs must be {sorted(expected_needs)}"
            )

        for contract in sorted(required_check["contract"]):
            if contract not in body:
                planner_errors.append(
                    f"{workflow_path} jobs.{job} is missing fail-closed contract `{contract}`"
                )

    for workflow_path, required_name in sorted(REQUIRED_MERGE_GROUP_WORKFLOWS.items()):
        workflow_yml = Path(workflow_path).read_text(encoding="utf-8")
        if not merge_group_trigger_is_present(workflow_yml):
            planner_errors.append(
                f"{workflow_path} must declare an unconditional merge_group "
                "trigger so the merge queue can report required check "
                f"`{required_name}`"
            )
        # Exact check-name parity on PR and merge-group runs: the job `name:`
        # is the GitHub Actions check context for both events.
        if not re.search(
            rf"(?m)^    name: {re.escape(required_name)}$",
            workflow_yml,
        ):
            planner_errors.append(
                f"{workflow_path} must keep required check name `{required_name}`"
            )
        for marker in MERGE_GROUP_SHA_CONTRACT_MARKERS:
            if marker not in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} must be event-aware for merge_group SHA/base "
                    f"selection (missing `{marker}`)"
                )
        for marker in MERGE_GROUP_CONCURRENCY_MARKERS:
            if marker not in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} concurrency must distinguish merge_group "
                    f"runs (missing `{marker}`)"
                )
        # A merge queue only admits a pull request whose required checks have
        # already passed on the pull request itself, so a `paths:` filter that
        # keeps a required owner from reporting on the PR event would strand
        # the queue entry precondition, including for the merge-group-only
        # trusted boundary, whose PR-side run is what keeps a candidate from
        # rewriting its own gate before the queue executes it.
        if not pull_request_trigger_is_unconditional(workflow_yml):
            planner_errors.append(
                f"{workflow_path} must trigger on every pull request "
                "(pull_request or pull_request_target) without path filters"
            )
        # Fail closed: never trust absent pull_request fields as a silent
        # main-only / no-op path for required merge-group validation.
        if workflow_path == ".github/workflows/cross-build-policy.yml":
            if "pull_request_target:" not in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} must preserve pull_request_target for fork-safe PR checks"
                )
            if "persist-credentials: false" not in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} must keep persist-credentials disabled"
                )
            if re.search(r"(?m)^\s+contents:\s+write\s*$", workflow_yml):
                planner_errors.append(
                    f"{workflow_path} must not grant contents: write"
                )
        if workflow_path == ".github/workflows/launch-integrity.yml":
            # The integrity lane must stay a trusted-base evaluator: no secret,
            # no write scope, and no credentialed checkout of candidate code.
            if "pull_request_target:" not in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} must keep pull_request_target so the "
                    "verifier runs from the trusted base"
                )
            if "persist-credentials: false" not in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} must keep persist-credentials disabled"
                )
            if "secrets." in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} must not consume repository secrets"
                )
            if re.search(r"(?m)^\s+(?:contents|packages|id-token|actions):\s+write\s*$", workflow_yml):
                planner_errors.append(
                    f"{workflow_path} must not grant a write permission"
                )
        if workflow_path == ".github/workflows/ci.yml":
            if "github.event_name == 'merge_group'" not in workflow_yml:
                planner_errors.append(
                    "ci.yml job gates must include merge_group alongside pull_request"
                )
            if 'EVENT_NAME" = "merge_group"' not in workflow_yml and \
               '"$EVENT_NAME" = "merge_group"' not in workflow_yml:
                planner_errors.append(
                    "ci.yml planner must handle merge_group base/head selection"
                )

    planner_errors.extend(merge_group_self_test())

    ci_plan_body = extract_job_body(ci_yml, "ci-plan")
    if 'git diff --name-only --no-renames "${base_ref}...HEAD"' not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must disable rename detection when collecting changed files"
        )
    if 'git diff --name-only --no-renames "${MERGE_BASE_SHA}...HEAD"' not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must diff merge_group commits with rename detection disabled"
        )

    coverage_plan_body = extract_job_body(
        Path(".github/workflows/coverage.yml").read_text(encoding="utf-8"),
        "coverage-plan",
    )
    if (
        'git diff --name-only --no-renames "${base_ref}...HEAD" > "$changed_files"'
        not in coverage_plan_body
    ):
        planner_errors.append(
            "jobs.coverage-plan must disable rename detection when collecting "
            "pull_request changed files"
        )
    if (
        'git diff --name-only --no-renames "${MERGE_BASE_SHA}...HEAD" > "$changed_files"'
        not in coverage_plan_body
    ):
        planner_errors.append(
            "jobs.coverage-plan must diff merge_group commits with rename "
            "detection disabled"
        )

    gateway_changes_body = extract_job_body(
        Path(".github/workflows/gateway-api-conformance.yml").read_text(
            encoding="utf-8"
        ),
        "changes",
    )
    if (
        'git diff --name-only --no-renames "${base_ref}...HEAD" | sort > "$changed_files"'
        not in gateway_changes_body
    ):
        planner_errors.append(
            "jobs.changes in gateway-api-conformance.yml must disable rename "
            "detection when collecting pull_request changed files"
        )
    if (
        'git diff --name-only --no-renames "${MERGE_BASE_SHA}...HEAD" | sort > "$changed_files"'
        not in gateway_changes_body
    ):
        planner_errors.append(
            "jobs.changes in gateway-api-conformance.yml must diff merge_group "
            "commits with rename detection disabled"
        )

    performance_regression_body = extract_job_body(ci_yml, "performance-regression")
    if (
        'git diff --name-only --no-renames "${perf_base}...HEAD"'
        not in performance_regression_body
    ):
        planner_errors.append(
            "jobs.performance-regression must disable rename detection when "
            "collecting changed files for pull_request and merge_group diffs"
        )

    for output in sorted(set(PATH_GATED_JOBS.values())):
        if not re.search(rf"(?m)^      {re.escape(output)}:", ci_plan_body):
            planner_errors.append(f"jobs.ci-plan must publish `{output}`")
    if "cargo fmt --all -- --check" not in ci_plan_body:
        planner_errors.append("jobs.ci-plan must run the Rust formatting gate")
    if "integration-coverage.diff" not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must run the integration shard-coverage gate"
        )
    # Issue #3615: the node-agent/ambient chart runtime lint must run the checker
    # extracted from the trusted base, so a pull request cannot replace its own
    # gate. It lives in the `helm-chart` job, NOT in `ci-plan`: the trusted ARM64
    # Cross build policy freezes the per-job digest of every Cross-sensitive
    # `ci.yml` job and `ci-plan` is one of them, while `helm-chart` carries no
    # Cross executable, configuration, ARM64 target, or opaque inline shell and
    # so contributes no surface to that contract.
    #
    # `helm-chart` rather than a new standalone job because it is already an
    # enforced gate: it is a `needs` of the required `test` aggregate and is
    # asserted there by `require_planned_gate "Helm chart"`. That makes the lint
    # blocking today with no branch-protection change and without touching the
    # aggregate wiring, which the same policy compares byte for byte. Its
    # `run_helm` path gate fires on `^charts/`, a strict superset of the
    # `charts/**` tree the checker scans, so a pull request that skips the job
    # cannot contain a violation for it to find.
    if "check_node_agent_chart_runtime.py" in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must not carry the chart runtime lint; the trusted "
            "Cross build policy freezes its per-job digest"
        )
    chart_runtime_lint_body = extract_job_body(ci_yml, "helm-chart")
    if "fetch-depth: 0" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must check out full history so the trusted "
            "base chart runtime checker is reachable"
        )
    # The chart runtime lint renders with the Helm binary the local composite
    # action installs, so that action must be proven identical to the trusted
    # revision BEFORE `uses:` executes it. The proof itself stays in Python
    # (`verify_trusted_local_action.py`) so this job keeps contributing no
    # opaque inline shell to the trusted Cross build policy's surface contract.
    if "Verify trusted Kubernetes tools installer" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must verify the trusted Kubernetes tools "
            "installer before installing Helm for the chart runtime lint"
        )
    if "Install Kubernetes tools" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must install pinned Kubernetes tools before the "
            "chart runtime lint"
        )
    verify_installer_at = chart_runtime_lint_body.find(
        "Verify trusted Kubernetes tools installer"
    )
    install_at = chart_runtime_lint_body.find("Install Kubernetes tools")
    trusted_check_at = chart_runtime_lint_body.find(
        "Check node-agent chart runtime mounts"
    )
    proposed_check_at = chart_runtime_lint_body.find(
        "Validate proposed chart runtime lint (non-authoritative)"
    )
    if not (
        0 <= verify_installer_at < install_at < trusted_check_at < proposed_check_at
    ):
        planner_errors.append(
            "jobs.helm-chart must order trusted Kubernetes tools installer "
            "verification, Kubernetes tools install, trusted chart runtime "
            "lint, then non-authoritative proposed checker validation"
        )
    if "verify_trusted_local_action.py" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must invoke verify_trusted_local_action.py before "
            "executing the local Kubernetes tools installer"
        )
    if 'python3 -I "$verifier" --self-test' not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must self-test the trusted local action verifier"
        )
    if not re.search(
        r'(?m)^\s*git archive --format=tar --output="\$archive" '
        r'"\$trusted_ref" -- "\$action_dir"\s*$',
        chart_runtime_lint_body,
    ):
        planner_errors.append(
            "jobs.helm-chart must materialize the trusted setup-kubernetes-tools "
            "tree with git archive rather than trusting the checkout"
        )
    if not re.search(
        r'(?m)^\s*python3 -I "\$verifier" --action-path "\$action_dir" '
        r'--trusted-archive "\$archive"\s*$',
        chart_runtime_lint_body,
    ):
        planner_errors.append(
            "jobs.helm-chart must compare the local setup-kubernetes-tools tree "
            "against the trusted archive before the action executes"
        )
    if 'action_dir=.github/actions/setup-kubernetes-tools' not in (
        chart_runtime_lint_body
    ):
        planner_errors.append(
            "jobs.helm-chart must verify exactly the setup-kubernetes-tools "
            "local action directory"
        )
    if "uses: ./.github/actions/setup-kubernetes-tools" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must invoke ./.github/actions/setup-kubernetes-tools"
        )
    if "FERRUM_TRUSTED_HELM" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must pin FERRUM_TRUSTED_HELM for authoritative "
            "rendered-manifest checks"
        )
    if "ferrum-k8s-tools/bin/helm" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must point FERRUM_TRUSTED_HELM at the pinned "
            "installer helm binary"
        )
    if "check_node_agent_chart_runtime.py" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must invoke check_node_agent_chart_runtime.py"
        )
    if "Check node-agent chart runtime mounts" not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must keep the node-agent chart runtime "
            "mounts step"
        )
    if (
        "Validate proposed chart runtime lint (non-authoritative)"
        not in chart_runtime_lint_body
    ):
        planner_errors.append(
            "jobs.helm-chart must validate the proposed chart runtime checker "
            "in a clearly non-authoritative step"
        )
    if 'proposed=.github/scripts/check_node_agent_chart_runtime.py' not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must run the proposed in-tree chart runtime "
            "checker for non-authoritative validation"
        )
    if 'python3 -I "$proposed" --self-test' not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must self-test the proposed chart runtime checker"
        )
    if not re.search(r'(?m)^\s*python3 -I "\$proposed"\s*$', chart_runtime_lint_body):
        planner_errors.append(
            "jobs.helm-chart must execute the proposed chart runtime checker "
            "against the checkout during non-authoritative validation"
        )
    if 'python3 -I "$checker" --self-test' not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must run the chart runtime lint self-test "
            "via isolated python3 -I"
        )
    if not re.search(r'(?m)^\s*python3 -I "\$checker"\s*$', chart_runtime_lint_body):
        planner_errors.append(
            "jobs.helm-chart must run the chart runtime lint against the "
            "checkout"
        )
    if 'git show "${base_ref}:${checker}"' not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must extract check_node_agent_chart_runtime.py "
            "from the trusted base on pull requests"
        )
    if 'git show "${MERGE_BASE_SHA}:${checker}"' not in chart_runtime_lint_body:
        planner_errors.append(
            "jobs.helm-chart must extract check_node_agent_chart_runtime.py "
            "from the merge-group base"
        )
    if (
        'trusted_checker="$RUNNER_TEMP/check-node-agent-chart-runtime.py"'
        not in chart_runtime_lint_body
    ):
        planner_errors.append(
            "jobs.helm-chart must stage the trusted chart runtime checker "
            "under RUNNER_TEMP"
        )
    # The scheduling decision above intentionally executes the trusted-base
    # planner on pull requests. Exercise the proposed planner here as data-plane
    # validation only: this verifier publishes no planner outputs and cannot
    # influence which jobs the trusted scheduler selected.
    if planner_self_test() != 0:
        planner_errors.append("proposed PR CI planner self-test failed")
    try:
        run_self_test()
    except AssertionError as error:
        planner_errors.append(f"Markdown link-check self-test failed: {error}")
    try:
        live_assertion_validator_self_test()
    except AssertionError as error:
        planner_errors.append(
            f"live-assertion artifact validator self-test failed: {error}"
        )
    if node_agent_chart_runtime_main(["--self-test"]) != 0:
        planner_errors.append(
            "proposed node-agent chart runtime lint self-test failed"
        )
    try:
        chart_runtime_findings = check_node_agent_chart_runtime()
    except (OSError, ValueError, NotADirectoryError, FileNotFoundError) as error:
        planner_errors.append(
            f"proposed node-agent chart runtime lint failed closed: {error}"
        )
    else:
        planner_errors.extend(chart_runtime_findings)
    planner_errors.extend(validate_artifact_gate_wiring())
    planner_errors.extend(error.format() for error in check_repository())
    release_yml = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    planner_errors.extend(validate_release_workflow(release_yml))
    planner_errors.extend(release_attestation_self_test(release_yml))

    node_waypoint_yml = Path(
        ".github/workflows/node-waypoint-ebpf-live.yml"
    ).read_text(encoding="utf-8")
    # `ambient-host-udp-live.yml` deliberately carries NO top-level `paths:`
    # block: it runs unconditionally on every pull_request / merge_group and
    # decides relevance from a trusted-base classifier instead, so it has no
    # documentation paths to extract. Its documentation trigger set lives in
    # `AMBIENT_HOST_UDP_DOCUMENTATION_PATHS`, already folded into the shared
    # `LIVE_SUITE_DOCUMENTATION_PATHS` below.
    required_full_ci_docs = LIVE_SUITE_DOCUMENTATION_PATHS | extract_documentation_paths(
        node_waypoint_yml
    )
    configured_live_doc_patterns = {
        pattern
        for patterns in SUITE_PATTERNS.values()
        for pattern in patterns
        if "docs/" in pattern
    }
    declared_live_doc_patterns = set(
        exact_path_patterns(LIVE_SUITE_DOCUMENTATION_PATHS)
    )
    if configured_live_doc_patterns != declared_live_doc_patterns:
        planner_errors.append(
            "live-suite documentation patterns must use the shared exact-path sets"
        )
    for path in sorted(required_full_ci_docs - FULL_CI_DOCUMENTATION_PATHS):
        planner_errors.append(
            f"PR planner must keep live-suite documentation `{path}` on full CI"
        )

    if not missing and not extra and not planner_errors:
        print(
            f"Required CI aggregate covers {len(REQUIRED_JOBS)} jobs; "
            f"{len(DIRECT_FULL_CI_JOBS)} roots and "
            f"{len(required_full_ci_docs)} live-suite docs enforce the CI plan."
        )
        return 0

    for job in missing:
        print(f"::error::jobs.test.needs is missing required job `{job}`", file=sys.stderr)
    for job in extra:
        print(
            f"::error::jobs.test.needs includes `{job}` but verify_required_ci.py does not document it",
            file=sys.stderr,
        )
    for error in planner_errors:
        print(f"::error::{error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
