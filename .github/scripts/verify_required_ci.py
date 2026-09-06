#!/usr/bin/env python3
"""Verify that the CI aggregate waits on every required validation job."""

from __future__ import annotations

import json
import os
import re
import sys
import textwrap
from pathlib import Path

from test_ci_policy_parallel import run_self_test as ci_policy_parallel_self_test
from test_release_dispatch import run_self_test as release_dispatch_self_test
from test_unit_ci import (
    check_repository as unit_ci_contract_errors,
    self_test as unit_ci_self_test,
)

from check_markdown_links import check_repository, run_self_test
from check_node_agent_chart_runtime import (
    check_repository as check_node_agent_chart_runtime,
    main as node_agent_chart_runtime_main,
)
from ci_runtime_plan import (
    SUITE_PATTERNS as CI_RUNTIME_SUITE_PATTERNS,
)
from live_suite_path_filter import (
    LIVE_SUITE_DOCUMENTATION_PATHS,
    SUITE_PATTERNS,
    exact_path_patterns,
)
from pr_ci_plan import (
    FULL_CI_DOCUMENTATION_PATHS,
    JOB_GATE_NAMES,
    UNCLASSIFIABLE_REASON,
    self_test as planner_self_test,
)
from validate_live_assertions import (
    run_self_test as live_assertion_validator_self_test,
)
from verify_coverage_workflow import (
    main as coverage_workflow_main,
)
from verify_mesh_performance_baselines_workflow import (
    main as mesh_baselines_workflow_main,
)
from verify_install_docs_contract import (
    run_self_test as install_docs_contract_self_test,
)
from verify_install_docs_contract import (
    check_repository as check_install_docs_contract,
)
from verify_linux_gnu_abi import (
    run_self_test as linux_gnu_abi_self_test,
)
from verify_linux_gnu_abi import (
    check_repository as check_linux_gnu_abi_contract,
)
from verify_publication_gate import (
    ContractError as PublicationContractError,
    load_inventory as load_publication_inventory,
    repository_contract_errors as publication_gate_contract_errors,
    required_context_parity_errors as publication_context_parity_errors,
    self_test as publication_gate_self_test,
)
from verify_release_image_attestations import (
    run_self_test as release_attestation_self_test,
)
from verify_release_image_attestations import (
    validate_release_workflow,
)
from verify_ci_runtime_cache import (
    CANONICAL_MERGE_GROUP_BODY,
    CANONICAL_PULL_REQUEST_BODY,
    CANONICAL_PUSH_MAIN_BODY,
    extract_job,
    job_if,
    job_steps,
    main as ci_runtime_cache_main,
    parse_canonical_on_events,
    step_if,
    step_run_ends_with_exit,
)


REQUIRED_JOBS = {
    "ci-plan",
    "ci-policy",
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
}

# These jobs do not depend on another full-CI validation job, so each must
# directly depend on the planner and enforce full mode. Other required jobs are
# downstream of one of these roots and are skipped transitively in light mode.
DIRECT_FULL_CI_JOBS = {
    "test-unit",
    "test-service-integration",
    "build-test-artifacts",
    "test-conformance",
    "dependency-audit",
    "lint",
    "fuzz-smoke",
    "build-ebpf-userspace",
    "performance-regression",
    "build-binaries",
}

PATH_GATED_JOBS = {
    "helm-chart": "run_helm",
    "build-ebpf": "run_ebpf_build",
    "ebpf-live": "run_ebpf_kernel_live",
    "netns-capture-live": "run_netns_capture_live",
    "two-cluster-mesh-live": "run_two_cluster_live",
    "test-secrets": "run_secrets_backends",
    "test-pkcs11-softhsm": "run_pkcs11",
}

# Every path-gated job keeps this exact event set: PRs, merge-queue checks,
# pushes to main, and manual workflow_dispatch. Omitting dispatch would skip
# Secret Backends / PKCS#11 (and the rest) on a manual full-mode run even
# though the planner force-schedules those gates.
PATH_GATED_EVENT_GUARD = (
    "(github.event_name == 'pull_request' || "
    "github.event_name == 'merge_group' || "
    "(github.event_name == 'push' && github.ref == 'refs/heads/main') || "
    "github.event_name == 'workflow_dispatch')"
)

REMOVED_JOBS = {
    "fmt",
    "test-lib",
    "build-integration-tests-archive",
    "test-integration-coverage",
    "build-gateway-binary",
    "build-functional-tests-archive",
    "detect-ebpf-live-changes",
    "mesh-multicluster-federation",
    "mesh-e2e-sidecar",
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
            "needs.coverage-plan.outputs.mode != 'skip' && needs.coverage-shard.result != 'success'",
            "!contains(fromJSON('[\"skip\", \"plugin\", \"shards\", \"full\"]'), needs.coverage-plan.outputs.mode)",
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
    ".github/workflows/fips-build.yml": {
        "job": "fips-build",
        "name": "FIPS Build & Test",
        # Issue #4445 promoted the hosted FIPS aggregate to a required and
        # publish-blocking context. Pin its complete `needs` set and every
        # fail-closed step so a later change cannot keep the check name while
        # dropping a producer, and pin the planner-verdict guards so an
        # unusable relevance output cannot be reported as success.
        "needs": {
            "fips-plan",
            "fips-compile",
            "fips-claimed-checks",
            "fips-clippy",
            "fips-test-build",
            "fips-test",
        },
        "contract": {
            "if: needs.fips-plan.result != 'success'",
            "needs.fips-plan.result == 'success' && "
            "needs.fips-plan.outputs.relevant != 'true' && "
            "needs.fips-plan.outputs.relevant != 'false'",
            "needs.fips-plan.outputs.relevant == 'true' && "
            "needs.fips-compile.result != 'success'",
            "needs.fips-plan.outputs.relevant == 'true' && "
            "needs.fips-claimed-checks.result != 'success'",
            "needs.fips-plan.outputs.relevant == 'true' && "
            "needs.fips-clippy.result != 'success'",
            "needs.fips-plan.outputs.relevant == 'true' && "
            "needs.fips-test-build.result != 'success'",
            "needs.fips-plan.outputs.relevant == 'true' && "
            "needs.fips-test.result != 'success'",
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

DEDICATED_WORKFLOW_NAMES = {
    ".github/workflows/coverage.yml": "Coverage",
    ".github/workflows/gateway-api-conformance.yml": "Gateway API Conformance",
    ".github/workflows/mesh-e2e-sidecar-live.yml": (
        "Mesh E2E Sidecar Live Datapath"
    ),
    ".github/workflows/multicluster-federation-live.yml": (
        "Multicluster Federation Live Datapath"
    ),
    ".github/workflows/multicluster-poller-partition-live.yml": (
        "Multicluster Poller Partition Live"
    ),
    ".github/workflows/fips-build.yml": "FIPS Build Policy",
}

# Every required status check owner must trigger on merge_group. Without that
# trigger a merge queue never receives the required check and deadlocks.
REQUIRED_MERGE_GROUP_WORKFLOWS = {
    ".github/workflows/ci.yml": "Tests",
    ".github/workflows/coverage.yml": "Merge Coverage",
    ".github/workflows/gateway-api-conformance.yml": "Gateway API Conformance",
    ".github/workflows/mesh-e2e-sidecar-live.yml": "Mesh E2E Sidecar Live",
    ".github/workflows/cross-build-policy.yml": "Trusted Cross Build Policy",
    ".github/workflows/multicluster-federation-live.yml": (
        "Multicluster Federation Live"
    ),
    ".github/workflows/multicluster-poller-partition-live.yml": (
        "Multicluster Poller Partition Live"
    ),
    ".github/workflows/ambient-host-udp-live.yml": "Ambient Host UDP Live",
    ".github/workflows/fips-build.yml": "FIPS Build & Test",
}

# Issue #3908 migrated three optional live suites off pull-request-supplied
# `paths:` triggers and onto trusted-base relevance with an always-reporting
# aggregate. They are DELIBERATELY not branch-protection-required: the issue
# says so, `.claude/rules/testing.md` says so, and the whole point of the
# always-reporting aggregate is that an irrelevant run is visibly green rather
# than a required check that never arrives.
#
# Pin the check name out of the required tables so a later change cannot
# quietly promote a 120-minute Kind/eBPF suite into the merge queue; pin the
# canonical input-less `pull_request` / `merge_group: checks_requested` /
# `push: [main]` trigger shape so a quoted or flow-form filter cannot give
# the coverage back; and pin the aggregate job (not a whole-file name /
# `if: always()` search), planner/relevance job, and live job so a decoy
# job cannot satisfy the always-reporting contract. NodeWaypoint's stronger
# step-level aggregate verifier lives in verify_ci_runtime_cache.py; the
# checks here are complementary. CNI/Istio live jobs bind on exact
# `relevant == 'true'`.
OPTIONAL_LIVE_SUITE_WORKFLOWS = {
    ".github/workflows/node-waypoint-ebpf-live.yml": {
        "name": "NodeWaypoint eBPF Live",
        "aggregate_job": "node-waypoint-ebpf-live-gate",
        "planner_job": "production-dockerfile-plan",
        "live_job": "node-waypoint-ebpf-live",
        "relevance_output": "node_waypoint_relevant",
        "live_binding": "not_false",
    },
    ".github/workflows/istio-status-cas-live.yml": {
        "name": "Istio Status CAS Live",
        "aggregate_job": "gate",
        "planner_job": "changes",
        "live_job": "istio-status-cas-live",
        "relevance_output": "relevant",
        "live_binding": "exact_true",
    },
    ".github/workflows/cni-lifecycle-live.yml": {
        "name": "CNI Lifecycle Live",
        "aggregate_job": "gate",
        "planner_job": "changes",
        "live_job": "cni-lifecycle-live",
        "relevance_output": "relevant",
        "live_binding": "exact_true",
    },
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


def optional_live_suite_trigger_errors(
    workflow_yml: str, workflow_path: str
) -> list[str]:
    """Require the issue-#3908 canonical live-suite event posture.

    Unlike `pull_request_trigger_is_unconditional`, this rejects
    `pull_request_target`, narrowed `types`, branch/path filters (including
    quoted keys), aliases, flow mappings, extra event directives, and
    malformed or duplicate event blocks. Trusted Cross Build Policy still
    uses the generic helper above.
    """

    errors: list[str] = []
    events = parse_canonical_on_events(workflow_yml)
    if events is None:
        errors.append(
            f"{workflow_path} must declare a single canonical block `on:` "
            "mapping (input-less pull_request, merge_group checks_requested, "
            "push to main; no pull_request_target, quoted keys, flow "
            "mappings, aliases, extra trigger directives, or duplicate "
            "event blocks)"
        )
        return errors
    if "pull_request_target" in events:
        errors.append(
            f"{workflow_path} must not trigger on pull_request_target; "
            "optional live suites require an input-less pull_request event"
        )
    expected_events = {"workflow_dispatch", "pull_request", "merge_group", "push"}
    if set(events) != expected_events:
        errors.append(
            f"{workflow_path} trigger events must be exactly "
            f"{sorted(expected_events)}; extra events must not execute a "
            "candidate-controlled live workflow"
        )
    if events.get("pull_request") != CANONICAL_PULL_REQUEST_BODY:
        errors.append(
            f"{workflow_path} must trigger on every pull request without "
            "path filters, types, or branch restrictions; relevance belongs "
            "to the trusted-base classifier"
        )
    if events.get("merge_group") != CANONICAL_MERGE_GROUP_BODY:
        errors.append(
            f"{workflow_path} must declare merge_group with exactly "
            "types: [checks_requested] so queue-combined commits are "
            "re-evaluated"
        )
    if events.get("push") != CANONICAL_PUSH_MAIN_BODY:
        errors.append(
            f"{workflow_path} must run on every push to main "
            "(branches: [main] only) so a queue-combined regression "
            "surfaces immediately"
        )
    return errors


def check_optional_live_suite_aggregate(
    workflow_yml: str,
    workflow_path: str,
    contract: dict[str, str],
) -> list[str]:
    """Bind the always-reporting aggregate to its intended job block."""

    errors: list[str] = []
    job = contract["aggregate_job"]
    expected_name = contract["name"]
    planner = contract["planner_job"]
    live = contract["live_job"]
    body = extract_job(workflow_yml, job)
    if not body:
        errors.append(
            f"{workflow_path} must declare jobs.{job} as the "
            f"always-reporting aggregate `{expected_name}`"
        )
        return errors
    if not re.search(rf"(?m)^    name: {re.escape(expected_name)}$", body):
        errors.append(
            f"{workflow_path} jobs.{job} must keep the always-reporting "
            f"aggregate `{expected_name}`"
        )
    if not re.search(r"(?m)^    if: always\(\)$", body):
        errors.append(
            f"{workflow_path} jobs.{job} aggregate must run with if: always()"
        )
    expected_needs = {planner, live}
    actual_needs = extract_job_needs(body)
    if actual_needs != expected_needs:
        errors.append(
            f"{workflow_path} jobs.{job}.needs must be {sorted(expected_needs)}"
        )
    if contract["live_binding"] != "exact_true":
        return errors

    live_body = extract_job(workflow_yml, live)
    if not live_body:
        errors.append(f"{workflow_path} must declare jobs.{live}")
        return errors
    if extract_job_needs(live_body) != {planner}:
        errors.append(
            f"{workflow_path} jobs.{live}.needs must be exactly [{planner!r}]"
        )
    relevant = f"needs.{planner}.outputs.{contract['relevance_output']}"
    expected_live_if = f"{relevant} == 'true'"
    if job_if(live_body) != expected_live_if:
        errors.append(
            f"{workflow_path} jobs.{live} must run only on exact true "
            f"relevance (`if: {expected_live_if}`)"
        )

    conditions = {
        "planner_failure": f"needs.{planner}.result != 'success'",
        "skip": f"{relevant} == 'false'",
        "malformed": (
            f"needs.{planner}.result == 'success' && {relevant} != 'true' && "
            f"{relevant} != 'false'"
        ),
        "live_failure": f"{relevant} == 'true' && needs.{live}.result != 'success'",
        "live_success": f"{relevant} == 'true' && needs.{live}.result == 'success'",
    }
    steps = job_steps(body)
    if len(steps) != len(conditions):
        errors.append(
            f"{workflow_path} jobs.{job} must contain exactly the five "
            "planner/skip/malformed/live-failure/live-success report steps"
        )
    matched_steps: dict[str, list[str]] = {
        key: [step for step in steps if step_if(step) == condition]
        for key, condition in conditions.items()
    }
    for key, matched in matched_steps.items():
        if len(matched) != 1:
            errors.append(
                f"{workflow_path} jobs.{job} must declare exactly one {key} "
                f"step with `if: {conditions[key]}`"
            )
    for key in ("planner_failure", "malformed", "live_failure"):
        matched = matched_steps[key]
        if matched and not step_run_ends_with_exit(matched[0], 1):
            errors.append(
                f"{workflow_path} jobs.{job} {key} step must terminate with "
                "an effective exit 1"
            )
    return errors


def merge_group_trigger_is_present(workflow_yml: str) -> bool:
    """Return whether the workflow declares an unconditional merge_group trigger."""

    body = workflow_event_body(workflow_yml, "merge_group")
    if body is None:
        return False
    if re.search(r"(?m)^    (?:branches(?:-ignore)?|paths(?:-ignore)?):", body):
        return False
    return True


NATIVE_BINARY_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
)


def extract_binary_matrix_script(ci_yml: str) -> str:
    """Return the ci-plan Python that selects the native binary matrix."""

    body = extract_job_body(ci_yml, "ci-plan")
    match = re.search(
        r"python3 - <<'PY' >> \"\$GITHUB_OUTPUT\"\n(?P<script>.*?)^          PY\n",
        body,
        flags=re.M | re.S,
    )
    if not match:
        raise RuntimeError("could not find jobs.ci-plan binary-matrix script")
    return textwrap.dedent(match.group("script"))


def load_binary_matrix(script: str, event_name: str) -> list[dict[str, str]]:
    """Execute the checked-in matrix selector with a fake event name."""

    captured: dict[str, object] = {}

    def fake_print(*args: object, **_kwargs: object) -> None:
        text = " ".join(str(arg) for arg in args)
        if text.startswith("matrix="):
            captured["matrix"] = json.loads(text.removeprefix("matrix="))

    previous_event_name = os.environ.get("EVENT_NAME")
    os.environ["EVENT_NAME"] = event_name
    try:
        exec(  # noqa: S102 — deterministic in-repo contract script
            compile(script, "<binary-matrix>", "exec"),
            {"print": fake_print},
        )
    finally:
        if previous_event_name is None:
            os.environ.pop("EVENT_NAME", None)
        else:
            os.environ["EVENT_NAME"] = previous_event_name
    matrix = captured.get("matrix")
    if not isinstance(matrix, dict) or not isinstance(matrix.get("include"), list):
        raise RuntimeError(f"binary-matrix for {event_name} did not emit include[]")
    rows = matrix["include"]
    if not all(isinstance(row, dict) for row in rows):
        raise RuntimeError(f"binary-matrix for {event_name} include rows must be objects")
    return rows  # type: ignore[return-value]


def native_binary_compile_gate_self_test() -> list[str]:
    """Lock merge_group macOS check / Windows link split and cache identity."""

    failures: list[str] = []
    ci_yml = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    try:
        script = extract_binary_matrix_script(ci_yml)
        pull_request_rows = load_binary_matrix(script, "pull_request")
        merge_group_rows = load_binary_matrix(script, "merge_group")
        push_rows = load_binary_matrix(script, "push")
    except (RuntimeError, json.JSONDecodeError, SyntaxError, TypeError) as error:
        return [f"native binary matrix contract failed closed: {error}"]

    if [row.get("target") for row in pull_request_rows] != [
        "x86_64-unknown-linux-gnu"
    ]:
        failures.append("pull_request binary matrix must stay Linux x86_64 only")

    merge_targets = [row.get("target") for row in merge_group_rows]
    if merge_targets != list(NATIVE_BINARY_TARGETS):
        failures.append(
            "merge_group binary matrix must keep Linux, both macOS targets, and Windows"
        )
    push_targets = [row.get("target") for row in push_rows]
    if push_targets != ["x86_64-unknown-linux-gnu"]:
        failures.append("push-to-main verification must build Linux x86_64 only")

    build_body = extract_job_body(ci_yml, "build-binaries")
    macos_check_gate = (
        "- name: Check merge-group macOS target\n"
        "        if: github.event_name == 'merge_group' && runner.os == 'macOS'\n"
        "        run: cargo check --features cloud-secrets --profile pr-build "
        "--target ${{ matrix.target }}"
    )
    if macos_check_gate not in build_body:
        failures.append(
            "jobs.build-binaries merge_group macOS must use a static cargo check step"
        )
    native_build_gate = (
        "- name: Build fast verification binary\n"
        "        if: github.event_name != 'merge_group' || runner.os != 'macOS'\n"
        "        run: cargo build --features cloud-secrets --profile pr-build "
        "--target ${{ matrix.target }}"
    )
    if native_build_gate not in build_body:
        failures.append("CI must use linked pr-build binaries on Linux/Windows")
    if "--release" in build_body or "LINUX_GNU_PROFILE: release" in build_body:
        failures.append("CI must not compile production release binaries")
    if 'shared-key: "build-${{ matrix.target }}-prbuild"' not in build_body:
        failures.append("CI verification must use the prbuild cache namespace")
    if "./.github/actions/setup-sccache" not in build_body:
        failures.append(
            "jobs.build-binaries must install sccache via the pinned repository action"
        )
    if '"${FERRUM_SCCACHE_BIN}" --show-stats' not in build_body:
        failures.append(
            "jobs.build-binaries must report pinned sccache --show-stats telemetry"
        )
    return failures


def merge_group_self_test() -> list[str]:
    """Deterministic fixtures for merge-queue required-check contracts."""

    failures: list[str] = []

    # Absent pull_request payload must not be treated as a path-gated event by
    # the planners once merge_group is selected.
    from coverage_plan import select_mode as coverage_select_mode
    from coverage_plan import select_plan as coverage_select_plan
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
    admin_plan = coverage_select_plan("merge_group", ["src/admin/mod.rs"])
    if admin_plan.mode != "shards" or "lib-unit" not in admin_plan.shards:
        failures.append("merge_group admin coverage must be shard-scoped with lib-unit")
    if any(
        shard in admin_plan.shards
        for shard in ("mesh-routing", "mesh-platform", "protocols-data-plane")
    ):
        failures.append("merge_group admin coverage must not select unrelated shards")
    plugin_plan = coverage_select_plan("merge_group", ["src/plugins/cors.rs"])
    if plugin_plan.mode != "plugin" or plugin_plan.shards != ("lib-unit",):
        failures.append("merge_group plugin coverage must reuse lib-unit only")
    unknown_plan = coverage_select_plan("merge_group", ["src/cli.rs"])
    if unknown_plan.mode != "full":
        failures.append("unknown merge_group coverage paths must fail closed to full")
    main_plan = coverage_select_plan("push", ["src/admin/mod.rs"])
    if main_plan.mode != "full":
        failures.append("push coverage must stay on the full shard matrix")

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
    failures.extend(native_binary_compile_gate_self_test())
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


_OPTIONAL_CANONICAL_ON = (
    "on:\n"
    "  workflow_dispatch:\n"
    "  pull_request:\n"
    "  merge_group:\n"
    "    types:\n"
    "      - checks_requested\n"
    "  push:\n"
    "    branches:\n"
    "      - main\n"
)

_CNI_OPTIONAL_CONTRACT = OPTIONAL_LIVE_SUITE_WORKFLOWS[
    ".github/workflows/cni-lifecycle-live.yml"
]


def _cni_aggregate_steps(
    *,
    skip_condition: str = "needs.changes.outputs.relevant == 'false'",
    malformed_condition: str = (
        "needs.changes.result == 'success' && "
        "needs.changes.outputs.relevant != 'true' && "
        "needs.changes.outputs.relevant != 'false'"
    ),
    live_failure_condition: str = (
        "needs.changes.outputs.relevant == 'true' && "
        "needs.cni-lifecycle-live.result != 'success'"
    ),
    planner_run: str = "exit 1",
) -> str:
    return (
        "      - name: Fail when CNI planning fails\n"
        "        if: needs.changes.result != 'success'\n"
        f"        run: {planner_run}\n"
        "      - name: Skip CNI for unrelated changes\n"
        f"        if: {skip_condition}\n"
        "        run: echo skip\n"
        "      - name: Fail on malformed CNI relevance\n"
        f"        if: {malformed_condition}\n"
        "        run: exit 1\n"
        "      - name: Fail when CNI live did not succeed\n"
        f"        if: {live_failure_condition}\n"
        "        run: exit 1\n"
        "      - name: Report CNI live success\n"
        "        if: needs.changes.outputs.relevant == 'true' && "
        "needs.cni-lifecycle-live.result == 'success'\n"
        "        run: echo pass\n"
    )


def _cni_like_workflow(
    *,
    extra_jobs: str = "",
    gate_name: str = "CNI Lifecycle Live",
    gate_if: str = "always()",
    needs: str | None = None,
    steps: str | None = None,
    live_if: str = "needs.changes.outputs.relevant == 'true'",
) -> str:
    if needs is None:
        needs = "      - changes\n      - cni-lifecycle-live\n"
    if steps is None:
        steps = _cni_aggregate_steps()
    return (
        f"{_OPTIONAL_CANONICAL_ON}\n"
        "jobs:\n"
        f"{extra_jobs}"
        "  changes:\n"
        "    outputs:\n"
        "      relevant: ${{ steps.filter.outputs.relevant }}\n"
        "  cni-lifecycle-live:\n"
        f"    if: {live_if}\n"
        "    needs: changes\n"
        "    steps:\n"
        "      - run: echo live\n"
        "  gate:\n"
        f"    name: {gate_name}\n"
        "    needs:\n"
        f"{needs}"
        f"    if: {gate_if}\n"
        "    steps:\n"
        f"{steps}"
    )


def optional_live_suite_self_test() -> list[str]:
    """Fixtures for issue-#3908 optional trigger and aggregate contracts."""

    failures: list[str] = []
    source = "self-test-optional.yml"

    if optional_live_suite_trigger_errors(_OPTIONAL_CANONICAL_ON, source):
        failures.append(
            "canonical optional live-suite trigger must be accepted: "
            + "; ".join(optional_live_suite_trigger_errors(_OPTIONAL_CANONICAL_ON, source))
        )

    target_only = "on:\n  pull_request_target:\n    branches:\n      - main\n"
    target_errors = optional_live_suite_trigger_errors(target_only, source)
    if not any("must not trigger on pull_request_target" in item for item in target_errors):
        failures.append("optional suite must reject pull_request_target")

    typed_pr = (
        "on:\n"
        "  pull_request:\n"
        "    types:\n"
        "      - opened\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    typed_errors = optional_live_suite_trigger_errors(typed_pr, source)
    if not any("without path filters, types, or branch restrictions" in item for item in typed_errors):
        failures.append("optional suite must reject narrowed pull_request types")

    quoted_paths = (
        "on:\n"
        "  pull_request:\n"
        '    "paths":\n'
        "      - src/**\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    quoted_errors = optional_live_suite_trigger_errors(quoted_paths, source)
    if not any("without path filters, types, or branch restrictions" in item for item in quoted_errors):
        failures.append("optional suite must reject quoted pull_request paths")

    flow_pr = (
        "on:\n"
        "  pull_request: {paths: [src/**]}\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    flow_errors = optional_live_suite_trigger_errors(flow_pr, source)
    if not any("canonical block `on:`" in item for item in flow_errors):
        failures.append("optional suite must reject flow-form pull_request filters")

    alias_pr = (
        "on:\n"
        "  pull_request: &pr\n"
        "  merge_group: *pr\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    alias_errors = optional_live_suite_trigger_errors(alias_pr, source)
    if not any("canonical block `on:`" in item for item in alias_errors):
        failures.append("optional suite must reject aliased trigger mappings")

    extra_merge_types = (
        "on:\n"
        "  pull_request:\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "      - requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    extra_types_errors = optional_live_suite_trigger_errors(extra_merge_types, source)
    if not any("merge_group with exactly" in item for item in extra_types_errors):
        failures.append("optional suite must reject extra merge_group types")

    duplicate_pr = (
        "on:\n"
        "  pull_request:\n"
        "  pull_request:\n"
        "  merge_group:\n"
        "    types:\n"
        "      - checks_requested\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
    )
    duplicate_errors = optional_live_suite_trigger_errors(duplicate_pr, source)
    if not any("canonical block `on:`" in item for item in duplicate_errors):
        failures.append("optional suite must reject duplicate pull_request blocks")

    extra_event = _OPTIONAL_CANONICAL_ON.replace(
        "  pull_request:\n",
        "  schedule:\n    - cron: '0 0 * * *'\n  pull_request:\n",
    )
    extra_event_errors = optional_live_suite_trigger_errors(extra_event, source)
    if not any("trigger events must be exactly" in item for item in extra_event_errors):
        failures.append("optional suite must reject extra trigger events")

    good_aggregate = check_optional_live_suite_aggregate(
        _cni_like_workflow(), source, _CNI_OPTIONAL_CONTRACT
    )
    if good_aggregate:
        failures.append(
            "canonical optional aggregate must be accepted: "
            + "; ".join(good_aggregate)
        )

    split_spoof = _cni_like_workflow(
        extra_jobs=(
            "  decoy-name:\n"
            "    name: CNI Lifecycle Live\n"
            "  decoy-always:\n"
            "    if: always()\n"
        ),
        gate_name="Not The Aggregate",
        gate_if="success()",
    )
    split_errors = check_optional_live_suite_aggregate(
        split_spoof, source, _CNI_OPTIONAL_CONTRACT
    )
    if not (
        any("must keep the always-reporting aggregate" in item for item in split_errors)
        and any("must run with if: always()" in item for item in split_errors)
    ):
        failures.append(
            "optional aggregate must reject a split name/always spoof on decoy jobs"
        )

    severed = _cni_like_workflow(needs="      - changes\n")
    severed_errors = check_optional_live_suite_aggregate(
        severed, source, _CNI_OPTIONAL_CONTRACT
    )
    if not any(".needs must be" in item for item in severed_errors):
        failures.append("optional aggregate must reject a severed needs list")

    loose = _cni_like_workflow(
        steps=_cni_aggregate_steps(
            skip_condition="needs.changes.outputs.relevant != 'true'",
            malformed_condition="needs.changes.outputs.relevant != 'true'",
        )
    )
    loose_errors = check_optional_live_suite_aggregate(
        loose, source, _CNI_OPTIONAL_CONTRACT
    )
    if not (
        any("exactly one skip step" in item for item in loose_errors)
        and any("exactly one malformed step" in item for item in loose_errors)
    ):
        failures.append(
            "optional aggregate must reject loose malformed-verdict handling"
        )

    loose_live = _cni_like_workflow(
        live_if="needs.changes.outputs.relevant != 'false'"
    )
    loose_live_errors = check_optional_live_suite_aggregate(
        loose_live, source, _CNI_OPTIONAL_CONTRACT
    )
    if not any("must run only on exact true relevance" in item for item in loose_live_errors):
        failures.append("optional live job must reject non-false relevance binding")

    inert_exit = _cni_like_workflow(
        steps=_cni_aggregate_steps(planner_run="echo 'exit 1'")
    )
    inert_exit_errors = check_optional_live_suite_aggregate(
        inert_exit, source, _CNI_OPTIONAL_CONTRACT
    )
    if not any("effective exit 1" in item for item in inert_exit_errors):
        failures.append("optional aggregate must reject inert exit text")

    real_block_run = (
        "|\n"
        "          {\n"
        '            echo "## CNI Lifecycle Live"\n'
        '            echo ""\n'
        '            echo "Failed before change detection completed."\n'
        '          } >> "$GITHUB_STEP_SUMMARY"\n'
        "          exit 1"
    )
    real_block = _cni_like_workflow(
        steps=_cni_aggregate_steps(planner_run=real_block_run)
    )
    real_block_errors = check_optional_live_suite_aggregate(
        real_block, source, _CNI_OPTIONAL_CONTRACT
    )
    if real_block_errors:
        failures.append(
            "optional aggregate must accept a real `run: |` block that ends "
            "with exit 1: " + "; ".join(real_block_errors)
        )

    comment_only = _cni_like_workflow(
        steps=_cni_aggregate_steps(
            planner_run="|\n          # exit 1\n          echo skip"
        )
    )
    comment_only_errors = check_optional_live_suite_aggregate(
        comment_only, source, _CNI_OPTIONAL_CONTRACT
    )
    if not any("effective exit 1" in item for item in comment_only_errors):
        failures.append("optional aggregate must reject a comment-only exit mention")

    non_terminal = _cni_like_workflow(
        steps=_cni_aggregate_steps(
            planner_run="|\n          exit 1\n          echo still running"
        )
    )
    non_terminal_errors = check_optional_live_suite_aggregate(
        non_terminal, source, _CNI_OPTIONAL_CONTRACT
    )
    if not any("effective exit 1" in item for item in non_terminal_errors):
        failures.append("optional aggregate must reject a non-terminal exit")

    folded = _cni_like_workflow(
        steps=_cni_aggregate_steps(
            planner_run=">\n          echo summary\n          exit 1"
        )
    )
    folded_errors = check_optional_live_suite_aggregate(
        folded, source, _CNI_OPTIONAL_CONTRACT
    )
    if not any("effective exit 1" in item for item in folded_errors):
        failures.append("optional aggregate must reject a folded `run: >` block")

    return failures


# ci-plan treats paths_classifiable as a trust/transport version handshake.
# Unless the flag is exactly true, every published job gate is forced on
# before $GITHUB_OUTPUT emission so an older newline-only trusted-base
# planner cannot honor syntactically valid false Helm/eBPF/secrets/PKCS values from
# a NUL changed-file stream.
CLASSIFIABLE_HANDSHAKE_SUMMARY = (
    "The planner did not prove a classifiable NUL stream; every job gate was "
    "scheduled fail-closed."
)
CLASSIFIABLE_HANDSHAKE_GATE_BLOCK = (
    '            if [ "$paths_classifiable" != "true" ]; then\n'
    "              value=true\n"
    '            elif [ "$value" != "true" ] && [ "$value" != "false" ]; then\n'
    "              value=true\n"
)
CLASSIFIABLE_HANDSHAKE_SUMMARY_BLOCK = (
    '              if [ "$paths_classifiable" != "true" ]; then\n'
    "                value=true\n"
    '              elif [ "$value" != "true" ] && [ "$value" != "false" ]; then\n'
    "                value=true\n"
)
GATE_OUTPUT_WRITE = 'printf \'%s=%s\\n\' "$gate" "$value" >> "$GITHUB_OUTPUT"'
PARSE_ONLY_GATE_BLOCK = (
    '            if [ "$value" != "true" ] && [ "$value" != "false" ]; then\n'
    "              value=true\n"
)
JOB_GATE_FOR_LOOP = "for gate in " + " ".join(JOB_GATE_NAMES) + "; do"


def resolve_planner_gate(paths_classifiable: str, value: str) -> str:
    """Honor a planner gate only after a successful classifiable handshake.

    Any paths_classifiable value other than exactly ``true`` — including a
    missing flag from an old trusted-base planner, explicit ``false``, and
    malformed tokens — force-runs the gate. Invalid or missing individual
    outputs still fail closed to true after a successful handshake.
    """

    if paths_classifiable != "true":
        return "true"
    if value in {"true", "false"}:
        return value
    return "true"


def check_classifiable_handshake(ci_plan_body: str) -> list[str]:
    """Reject a ci-plan that parses the handshake flag but still honors false gates."""

    errors: list[str] = []
    if JOB_GATE_FOR_LOOP not in ci_plan_body:
        errors.append(
            "jobs.ci-plan must iterate every JOB_GATE_NAMES output in one loop"
        )
    if 's/^paths_classifiable=//p' not in ci_plan_body:
        errors.append(
            "jobs.ci-plan must parse paths_classifiable from the planner plan"
        )

    output_at = ci_plan_body.find(GATE_OUTPUT_WRITE)
    if output_at == -1:
        errors.append(
            "jobs.ci-plan must emit each job gate to $GITHUB_OUTPUT before "
            "the step summary"
        )
        return errors

    prefix = ci_plan_body[:output_at]
    if 's/^paths_classifiable=//p' not in prefix:
        errors.append(
            "jobs.ci-plan must parse paths_classifiable before emitting job gates"
        )
    if JOB_GATE_FOR_LOOP not in prefix:
        errors.append(
            "jobs.ci-plan must force every published job gate in the "
            "$GITHUB_OUTPUT loop"
        )
    if CLASSIFIABLE_HANDSHAKE_GATE_BLOCK not in prefix:
        errors.append(
            "jobs.ci-plan must treat paths_classifiable as a trust/transport "
            "version handshake and force every job gate true unless the flag "
            "is exactly true, before $GITHUB_OUTPUT emission"
        )
    if CLASSIFIABLE_HANDSHAKE_SUMMARY_BLOCK not in ci_plan_body[output_at:]:
        errors.append(
            "jobs.ci-plan must apply the same classifiable handshake to the "
            "step-summary gate table"
        )
    if CLASSIFIABLE_HANDSHAKE_SUMMARY not in ci_plan_body:
        errors.append(
            "jobs.ci-plan must summarize a failed classifiable handshake with "
            "the canned fail-closed reason and must not interpolate hostile bytes"
        )
    if "$" in CLASSIFIABLE_HANDSHAKE_SUMMARY or "`" in CLASSIFIABLE_HANDSHAKE_SUMMARY:
        errors.append("classifiable handshake summary must stay a canned constant")

    # A workflow that only lists files when the flag is true, but still writes
    # planner false values to $GITHUB_OUTPUT, must not satisfy this contract.
    if (
        '[ "$paths_classifiable" = "true" ]' in ci_plan_body
        and CLASSIFIABLE_HANDSHAKE_GATE_BLOCK not in prefix
    ):
        errors.append(
            "jobs.ci-plan must not honor old-planner false gates merely because "
            "it parses paths_classifiable for the step summary"
        )
    return errors


def classifiable_handshake_self_test(ci_plan_body: str) -> list[str]:
    """Static fixtures proving old-planner, false, malformed, and safe-true behavior."""

    failures: list[str] = []
    if set(PATH_GATED_JOBS.values()) != set(JOB_GATE_NAMES):
        failures.append("PATH_GATED_JOBS must publish every JOB_GATE_NAMES output")

    handshake_cases = (
        ("old-planner/no-flag", "", "false", "true"),
        ("old-planner/no-flag-true-gate", "", "true", "true"),
        ("explicit-false-flag", "false", "false", "true"),
        ("explicit-false-flag-true-gate", "false", "true", "true"),
        ("malformed-TRUE", "TRUE", "false", "true"),
        ("malformed-True", "True", "false", "true"),
        ("malformed-1", "1", "false", "true"),
        ("malformed-yes", "yes", "false", "true"),
        ("malformed-empty-token", " ", "false", "true"),
        ("safe-true-narrow-false", "true", "false", "false"),
        ("safe-true-narrow-true", "true", "true", "true"),
        ("safe-true-missing-value", "true", "", "true"),
        ("safe-true-invalid-value", "true", "maybe", "true"),
    )
    for label, flag, value, expected in handshake_cases:
        actual = resolve_planner_gate(flag, value)
        if actual != expected:
            failures.append(
                f"{label}: expected gate {expected!r} for "
                f"paths_classifiable={flag!r} value={value!r}, got {actual!r}"
            )

    production_errors = check_classifiable_handshake(ci_plan_body)
    if production_errors:
        failures.extend(production_errors)
        return failures

    parse_only = ci_plan_body.replace(
        CLASSIFIABLE_HANDSHAKE_GATE_BLOCK, PARSE_ONLY_GATE_BLOCK, 1
    )
    parse_only_errors = check_classifiable_handshake(parse_only)
    if not parse_only_errors:
        failures.append(
            "handshake verifier must reject a workflow that parses "
            "paths_classifiable but still honors old-planner false gate values"
        )
    elif not any("exactly true" in error for error in parse_only_errors):
        failures.append(
            "handshake verifier must reject parse-only workflows for honoring "
            "false gates rather than for an unrelated contract"
        )

    # The pre-handshake substring check used for step-summary listing is not
    # enough: the parse-only mutation still lists files only when the flag is
    # true, which is the gap this handshake exists to close.
    if '[ "$paths_classifiable" = "true" ]' not in parse_only:
        failures.append("parse-only mutation must still parse paths_classifiable")

    explicit_false = ci_plan_body.replace(
        '[ "$paths_classifiable" != "true" ]; then',
        '[ "$paths_classifiable" = "" ]; then',
        1,
    )
    if not check_classifiable_handshake(explicit_false):
        failures.append(
            "handshake verifier must reject a workflow that force-runs only a "
            "missing flag and still honors explicit paths_classifiable=false"
        )

    malformed = ci_plan_body.replace(
        '[ "$paths_classifiable" != "true" ]; then',
        '[ "$paths_classifiable" != "true" ] && [ "$paths_classifiable" != "TRUE" ]; then',
        1,
    )
    if not check_classifiable_handshake(malformed):
        failures.append(
            "handshake verifier must reject a workflow that treats malformed "
            "paths_classifiable tokens as classifiable"
        )

    swapped = ci_plan_body.replace(
        CLASSIFIABLE_HANDSHAKE_GATE_BLOCK
        + "              gate_fallbacks+=(\"$gate\")\n"
        + "            fi\n"
        + f"            {GATE_OUTPUT_WRITE}\n",
        f"            {GATE_OUTPUT_WRITE}\n"
        + CLASSIFIABLE_HANDSHAKE_GATE_BLOCK
        + "              gate_fallbacks+=(\"$gate\")\n"
        + "            fi\n",
        1,
    )
    if swapped == ci_plan_body:
        failures.append(
            "handshake self-test could not relocate the $GITHUB_OUTPUT write "
            "after the classifiable handshake"
        )
    elif not check_classifiable_handshake(swapped):
        failures.append(
            "handshake verifier must reject forcing job gates only after "
            "$GITHUB_OUTPUT emission"
        )

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
    unit_body = extract_job_body(ci_yml, "test-unit")
    unit_precompile = "Precompile inline and hardening test binaries"
    unit_inline = "Run inline lib tests"
    unit_hardening = "Run cache accounting and reload safety regressions"
    if not (
        unit_body.count("cargo test --lib --test unit_tests --no-run") == 1
        and 0 <= unit_body.find(unit_precompile)
        < unit_body.find(unit_inline)
        < unit_body.find(unit_hardening)
    ):
        planner_errors.append(
            "jobs.test-unit must precompile the lib and unit_tests binaries "
            "together before running inline or plugin-hardening tests"
        )

    # Optional ACME coverage must use the small DNS target and prove every
    # required selection. The self-tests exercise missing/ignored tests and
    # disabled, masked, or retargeted literal workflow commands, plus Cargo/tee
    # pipeline failure propagation and read-only report validation (issue #4669).
    planner_errors.extend(unit_ci_contract_errors())
    planner_errors.extend(unit_ci_self_test())

    pkcs11_body = extract_job_body(ci_yml, "test-pkcs11-softhsm")
    pkcs11_precompile = "Precompile PKCS#11 signer and pairing test binaries"
    pkcs11_signer = "Run PKCS#11 signer smoke test"
    pkcs11_pairing = "Run PKCS#11 certificate-pairing tests"
    if not (
        pkcs11_body.count(
            "cargo test --features pkcs11 --lib --test unit_tests --no-run"
        )
        == 1
        and 0 <= pkcs11_body.find(pkcs11_precompile)
        < pkcs11_body.find(pkcs11_signer)
        < pkcs11_body.find(pkcs11_pairing)
    ):
        planner_errors.append(
            "jobs.test-pkcs11-softhsm must precompile the pkcs11 lib and "
            "unit_tests binaries together before running either filter"
        )
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
        if PATH_GATED_EVENT_GUARD not in body:
            planner_errors.append(
                f"jobs.{job} must admit pull_request, merge_group, push to "
                "main, and workflow_dispatch"
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

    # Both production gates require every repository-required product check
    # for the exact release commit. Ordinary main validation publishes nothing
    # and must not poll release prerequisites in a conformance workflow.
    planner_errors.extend(
        f"publication gate self-test: {failure}"
        for failure in publication_gate_self_test()
    )
    try:
        publication_inventory = load_publication_inventory()
    except (OSError, PublicationContractError) as error:
        planner_errors.append(f"publication inventory failed closed: {error}")
    else:
        planner_errors.extend(
            publication_gate_contract_errors(dict(REQUIRED_MERGE_GROUP_WORKFLOWS))
        )
        # Adversarial fixture: a context that branch protection newly requires
        # but that nothing publishes against must fail this policy run.
        fabricated = dict(REQUIRED_MERGE_GROUP_WORKFLOWS)
        fabricated[".github/workflows/fabricated-required.yml"] = (
            "Fabricated Required Check"
        )
        if not publication_context_parity_errors(fabricated, publication_inventory):
            planner_errors.append(
                "a newly required check with no publication-inventory entry "
                "must fail the publication contract"
            )

    planner_errors.extend(ci_policy_parallel_self_test())
    planner_errors.extend(release_dispatch_self_test())
    planner_errors.extend(merge_group_self_test())
    planner_errors.extend(optional_live_suite_self_test())

    # Optional live suites (issue #3908): trusted-base relevance, an
    # always-reporting aggregate, and NO branch-protection requirement.
    required_check_names = set(REQUIRED_MERGE_GROUP_WORKFLOWS.values()) | {
        required_check["name"] for required_check in DEDICATED_REQUIRED_CHECKS.values()
    }
    for workflow_path, contract in sorted(OPTIONAL_LIVE_SUITE_WORKFLOWS.items()):
        workflow_yml = Path(workflow_path).read_text(encoding="utf-8")
        aggregate_name = contract["name"]
        if workflow_path in REQUIRED_MERGE_GROUP_WORKFLOWS:
            planner_errors.append(
                f"{workflow_path} must stay out of REQUIRED_MERGE_GROUP_WORKFLOWS; "
                "promoting an optional live suite to a required check is a "
                "separate, deliberate branch-protection change"
            )
        if workflow_path in DEDICATED_REQUIRED_CHECKS:
            planner_errors.append(
                f"{workflow_path} must stay out of DEDICATED_REQUIRED_CHECKS"
            )
        if aggregate_name in required_check_names:
            planner_errors.append(
                f"{workflow_path} aggregate `{aggregate_name}` must not collide "
                "with a branch-protection-required check name"
            )
        planner_errors.extend(
            check_optional_live_suite_aggregate(workflow_yml, workflow_path, contract)
        )
        planner_errors.extend(
            optional_live_suite_trigger_errors(workflow_yml, workflow_path)
        )
        for marker in MERGE_GROUP_SHA_CONTRACT_MARKERS:
            if marker not in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} must be event-aware for merge_group "
                    f"SHA/base selection (missing `{marker}`)"
                )
        for marker in MERGE_GROUP_CONCURRENCY_MARKERS:
            if marker not in workflow_yml:
                planner_errors.append(
                    f"{workflow_path} concurrency must distinguish merge_group "
                    f"runs (missing `{marker}`)"
                )

    ci_plan_body = extract_job_body(ci_yml, "ci-plan")
    pr_nul_diff = (
        'git diff --name-only --no-renames -z "${base_ref}...HEAD" > "$changed_files"'
    )
    merge_nul_diff = (
        'git diff --name-only --no-renames -z '
        '"${MERGE_BASE_SHA}...HEAD" > "$changed_files"'
    )
    if pr_nul_diff not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must collect pull_request changed files with "
            "`git diff --name-only --no-renames -z`"
        )
    if merge_nul_diff not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must collect merge_group changed files with "
            "`git diff --name-only --no-renames -z`"
        )
    if ci_plan_body.count("--name-only --no-renames -z") != 2:
        planner_errors.append(
            "jobs.ci-plan must NUL-delimit both pull_request and merge_group "
            "changed-file diffs"
        )
    if "| sort > \"$changed_files\"" in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must not pipe changed files through newline sort"
        )
    planner_errors.extend(classifiable_handshake_self_test(ci_plan_body))
    if 's/^paths_classifiable=//p' not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must parse paths_classifiable from the planner plan"
        )
    if '[ "$paths_classifiable" = "true" ]' not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must list changed files only when the planner "
            "marks the NUL stream classifiable"
        )
    classifiable_at = ci_plan_body.find('[ "$paths_classifiable" = "true" ]')
    reason_at = ci_plan_body.find('echo "$reason"')
    if classifiable_at == -1 or reason_at == -1 or classifiable_at > reason_at:
        planner_errors.append(
            "jobs.ci-plan must echo the planner reason only after proving "
            "the changed-file stream is classifiable"
        )
    if "while IFS= read -r -d '' path; do" not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must consume classifiable changed files as a NUL stream"
        )
    if "while IFS= read -r path; do" in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must not parse changed files as newline-delimited"
        )
    if UNCLASSIFIABLE_REASON not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must summarize unclassifiable paths with the "
            "planner canned reason and must not interpolate hostile bytes"
        )
    planner_src = Path(".github/scripts/pr_ci_plan.py").read_text(encoding="utf-8")
    for marker, detail in (
        (
            "def parse_nul_changed_files(",
            "jobs.ci-plan planner must parse changed files as a NUL stream",
        ),
        (
            'if not data.endswith(b"\\0"):',
            "jobs.ci-plan planner must require a complete NUL-terminated stream",
        ),
        (
            'r"^[A-Za-z0-9._+@~ /-]{1,4096}$"',
            "jobs.ci-plan planner must keep the conservative path allowlist",
        ),
        (
            'print(f"paths_classifiable={str(paths_classifiable).lower()}")',
            "jobs.ci-plan planner must emit paths_classifiable before interpolating paths",
        ),
    ):
        if marker not in planner_src:
            planner_errors.append(detail)
    classifiable_emit = planner_src.find(
        'print(f"paths_classifiable={str(paths_classifiable).lower()}")'
    )
    reason_emit = planner_src.find('print(f"reason={reason}")')
    if classifiable_emit == -1 or reason_emit == -1 or classifiable_emit > reason_emit:
        planner_errors.append(
            "jobs.ci-plan planner must emit paths_classifiable before reason"
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
    if "verify_mesh_performance_baselines_workflow.py" not in performance_regression_body:
        planner_errors.append(
            "jobs.performance-regression must invoke "
            "verify_mesh_performance_baselines_workflow.py"
        )
    if (
        "python3 .github/scripts/verify_mesh_performance_baselines_workflow.py --self-test"
        not in performance_regression_body
    ):
        planner_errors.append(
            "jobs.performance-regression must self-test the mesh baselines "
            "workflow verifier"
        )
    if (
        "python3 .github/scripts/verify_mesh_performance_baselines_workflow.py"
        not in performance_regression_body
    ):
        planner_errors.append(
            "jobs.performance-regression must run the mesh baselines workflow verifier"
        )
    static_idx = performance_regression_body.find(
        "Verify mesh performance baselines workflow contract"
    )
    detect_idx = performance_regression_body.find("Detect performance-sensitive changes")
    if static_idx == -1 or detect_idx == -1 or static_idx > detect_idx:
        planner_errors.append(
            "jobs.performance-regression must run mesh baseline workflow "
            "contracts after checkout and before optional benchmark path gating"
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
    if mesh_baselines_workflow_main(["--self-test"]) != 0:
        planner_errors.append(
            "mesh performance baselines workflow self-test failed"
        )
    if mesh_baselines_workflow_main([]) != 0:
        planner_errors.append(
            "mesh performance baselines workflow contract failed"
        )
    if coverage_workflow_main(["--self-test"]) != 0:
        planner_errors.append("coverage workflow verifier self-test failed")
    if coverage_workflow_main([]) != 0:
        planner_errors.append("coverage workflow shard-plan contract failed")
    if ci_runtime_cache_main(["--self-test"]) != 0:
        planner_errors.append("CI runtime cache contract self-test failed")
    if ci_runtime_cache_main([]) != 0:
        planner_errors.append("CI runtime cache contract failed")
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
    planner_errors.extend(install_docs_contract_self_test())
    planner_errors.extend(check_install_docs_contract())
    planner_errors.extend(linux_gnu_abi_self_test())
    planner_errors.extend(check_linux_gnu_abi_contract())
    release_yml = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    planner_errors.extend(validate_release_workflow(release_yml))
    planner_errors.extend(release_attestation_self_test(release_yml))

    # None of the governed live workflows carries a top-level `paths:` block any
    # more: `ambient-host-udp-live.yml` never did, and issue #3908 retired the
    # last three. Every one of them decides relevance from a trusted-base
    # classifier instead, so the documentation trigger set is read from the
    # classifiers rather than scraped from a workflow trigger — from
    # `LIVE_SUITE_DOCUMENTATION_PATHS` for the `live_suite_path_filter.py`
    # suites, and from the `node-waypoint-ebpf-live` suite of
    # `ci_runtime_plan.py`, which is the sole relevance authority for the
    # NodeWaypoint Kind/eBPF job.
    node_waypoint_doc_paths = {
        pattern.removeprefix("^").removesuffix("$").replace("\\.", ".")
        for pattern in CI_RUNTIME_SUITE_PATTERNS["node-waypoint-ebpf-live"]
        if pattern.startswith("^docs/") and pattern.endswith("$")
    }
    if not node_waypoint_doc_paths:
        planner_errors.append(
            "ci_runtime_plan.py node-waypoint-ebpf-live suite must keep exact "
            "documentation trigger patterns"
        )
    required_full_ci_docs = LIVE_SUITE_DOCUMENTATION_PATHS | node_waypoint_doc_paths
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
