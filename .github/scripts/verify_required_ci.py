#!/usr/bin/env python3
"""Verify that the CI aggregate waits on every required validation job."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

from check_markdown_links import check_repository, run_self_test
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
}

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
        return False
    return not re.search(r"(?m)^    paths(?:-ignore)?:", body)


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

    ci_plan_body = extract_job_body(ci_yml, "ci-plan")
    if 'git diff --name-only --no-renames "${base_ref}...HEAD"' not in ci_plan_body:
        planner_errors.append(
            "jobs.ci-plan must disable rename detection when collecting changed files"
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
    planner_errors.extend(validate_artifact_gate_wiring())
    planner_errors.extend(error.format() for error in check_repository())
    release_yml = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    planner_errors.extend(validate_release_workflow(release_yml))
    planner_errors.extend(release_attestation_self_test(release_yml))

    node_waypoint_yml = Path(
        ".github/workflows/node-waypoint-ebpf-live.yml"
    ).read_text(encoding="utf-8")
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
