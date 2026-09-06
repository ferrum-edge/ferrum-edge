#!/usr/bin/env python3
"""Verify the Coverage workflow's shard-plan, artifact, and merge contracts."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import zipfile
from pathlib import Path

from coverage_plan import (
    ADMIN_API_SHARD,
    ADMIN_CONFIG_SHARD,
    ALL_SHARDS,
    CANONICAL_SHARD_ORDER,
    CONTROLLER_PATHS,
    LIB_UNIT_SHARD,
    MESH_PLATFORM_SHARD,
    MESH_ROUTING_SHARD,
    PROTOCOLS_SHARD,
    SHARD_DEFINITIONS,
    VALID_MODES,
    parse_planned_shards,
    select_plan,
    self_test as planner_self_test,
    verify_downloaded_artifacts,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "coverage.yml"
PLANNER_PATH = REPO_ROOT / ".github" / "scripts" / "coverage_plan.py"
DOCS_COVERAGE_PATH = REPO_ROOT / "docs" / "coverage.md"
DOCS_CI_CD_PATH = REPO_ROOT / "docs" / "ci_cd.md"

FROZEN_FILTER_MODULES = {
    ADMIN_API_SHARD: {
        "integration::admin_api_specs_handler_tests",
        "integration::admin_db_api_specs_tests",
        "integration::admin_db_live_apply_tests",
        "integration::admin_audit_rbac_tests",
        "integration::admin_backend_capabilities_tests",
        "integration::admin_runtime_metrics_tests",
        "integration::admin_observability_auth_tests",
    },
    ADMIN_CONFIG_SHARD: {
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
    },
    MESH_ROUTING_SHARD: {
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
    },
    MESH_PLATFORM_SHARD: {
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
    },
    PROTOCOLS_SHARD: {
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
    },
}

VALID_MODES_JSON = '["skip", "plugin", "shards", "full"]'
SHARD_RESULT_CONTRACT = (
    "needs.coverage-plan.outputs.mode != 'skip' && "
    "needs.coverage-shard.result != 'success'"
)
INVALID_MODE_CONTRACT = (
    "!contains(fromJSON('" + VALID_MODES_JSON + "'), needs.coverage-plan.outputs.mode)"
)


def extract_job_body(workflow_yml: str, job: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow_yml,
    )
    if not match:
        raise RuntimeError(f"could not find jobs.{job}")
    return match.group("body")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def filter_modules(filters: str) -> set[str]:
    return {line.strip() for line in filters.splitlines() if line.strip()}


def validate_planner_contract(failures: list[str]) -> None:
    require(
        set(SHARD_DEFINITIONS) == ALL_SHARDS,
        "planner shard definitions must cover the canonical shard set",
        failures,
    )
    require(
        tuple(SHARD_DEFINITIONS) == CANONICAL_SHARD_ORDER
        or set(SHARD_DEFINITIONS) == set(CANONICAL_SHARD_ORDER),
        "planner shard definitions must use canonical shard names",
        failures,
    )
    require(
        SHARD_DEFINITIONS[LIB_UNIT_SHARD]["kind"] == "lib-unit",
        "lib-unit must remain the lib/unit coverage shard",
        failures,
    )
    for shard, expected in FROZEN_FILTER_MODULES.items():
        actual = filter_modules(SHARD_DEFINITIONS[shard]["filters"])
        require(
            actual == expected,
            f"{shard} integration filters drifted from the frozen coverage matrix",
            failures,
        )
    require(
        VALID_MODES == {"skip", "plugin", "shards", "full"},
        "planner must keep skip/plugin/shards/full modes",
        failures,
    )
    require(
        CONTROLLER_PATHS
        >= {
            ".github/workflows/coverage.yml",
            ".github/scripts/coverage_plan.py",
            ".github/scripts/verify_coverage_workflow.py",
            "scripts/check_coverage_thresholds.py",
            "scripts/coverage.sh",
        },
        "planner must fail closed on coverage controller edits",
        failures,
    )


def validate_workflow_text(text: str, failures: list[str]) -> None:
    require(
        "python3 .github/scripts/coverage_plan.py --self-test" in text,
        "Coverage Plan must self-test the coverage planner",
        failures,
    )
    require(
        "python3 .github/scripts/verify_coverage_workflow.py --self-test" in text,
        "Coverage Plan must self-test the coverage workflow verifier",
        failures,
    )
    require(
        "python3 .github/scripts/verify_coverage_workflow.py" in text,
        "Coverage Plan must enforce the coverage workflow contract",
        failures,
    )
    require(
        "shards: ${{ steps.plan.outputs.shards }}" in text,
        "Coverage Plan must publish the planned shard list",
        failures,
    )
    require(
        "shard-matrix: ${{ steps.plan.outputs.shard-matrix }}" in text,
        "Coverage Plan must publish the planned shard matrix",
        failures,
    )
    require(
        "plugin_gate: ${{ steps.plan.outputs.plugin_gate }}" in text,
        "Coverage Plan must publish the plugin-gate flag",
        failures,
    )
    require(
        "--github-output \"$GITHUB_OUTPUT\"" in text
        or '--github-output "$GITHUB_OUTPUT"' in text,
        "Coverage Plan must write planner outputs through --github-output",
        failures,
    )
    require(
        'git diff --name-only --no-renames "${base_ref}...HEAD"' in text,
        "Coverage Plan must disable rename detection for pull_request diffs",
        failures,
    )
    require(
        'git diff --name-only --no-renames "${MERGE_BASE_SHA}...HEAD"' in text,
        "Coverage Plan must disable rename detection for merge_group diffs",
        failures,
    )
    require(
        "failing closed to full coverage" in text,
        "Coverage Plan must fail closed to full coverage when the diff is unavailable",
        failures,
    )

    shard_body = extract_job_body(text, "coverage-shard")
    require(
        "if: needs.coverage-plan.outputs.mode != 'skip'" in shard_body,
        "coverage-shard must run for every non-skip plan, including plugin mode",
        failures,
    )
    require(
        "mode == 'full'" not in shard_body.split("strategy:", 1)[0],
        "coverage-shard must not remain full-mode-only before the matrix runs",
        failures,
    )
    require(
        "include: ${{ fromJSON(needs.coverage-plan.outputs.shard-matrix) }}"
        in shard_body,
        "coverage-shard must use the planner's shard-matrix include list",
        failures,
    )
    require(
        "contains(fromJSON(needs.coverage-plan.outputs.shards), matrix.shard)"
        not in shard_body,
        "coverage-shard must not skip matrix rows in-place; skipped rows false-green",
        failures,
    )
    require(
        re.search(r"(?m)^      matrix:\n        include:\n          - shard:", shard_body)
        is None,
        "coverage-shard must not hardcode a static six-shard include matrix",
        failures,
    )
    require(
        re.search(r"(?m)^    timeout-minutes: 120$", shard_body) is not None,
        "coverage-shard must keep the 120-minute lib-unit wall-clock budget",
        failures,
    )
    require(
        'CARGO_BUILD_JOBS: "2"' in shard_body,
        "coverage-shard must cap CARGO_BUILD_JOBS at 2 for the lib-unit compile",
        failures,
    )
    require(
        'CARGO_BUILD_JOBS: "3"' not in shard_body,
        "coverage-shard must not restore CARGO_BUILD_JOBS=3 after the #4368 OOM recurrence",
        failures,
    )
    require(
        re.search(r"(?m)^    timeout-minutes: 75$", shard_body) is None,
        "coverage-shard must not restore the 75-minute deadline that canceled a progressing suite",
        failures,
    )
    require(
        "--lib" in shard_body and "--test unit_tests" in shard_body,
        "coverage-shard must keep the combined lib + unit_tests coverage invocation",
        failures,
    )

    merge_body = extract_job_body(text, "coverage-merge")
    require(
        re.search(r"(?m)^    if: always\(\)$", merge_body) is not None,
        "Merge Coverage must run with if: always()",
        failures,
    )
    require(
        "needs.coverage-plan.result != 'success'" in merge_body,
        "Merge Coverage must fail when planning fails",
        failures,
    )
    require(
        INVALID_MODE_CONTRACT in merge_body,
        "Merge Coverage must reject modes outside skip/plugin/shards/full",
        failures,
    )
    require(
        SHARD_RESULT_CONTRACT in merge_body,
        "Merge Coverage must require coverage-shard success for every non-skip plan",
        failures,
    )
    require(
        "needs.coverage-shard.result == 'failure'" not in merge_body,
        "Merge Coverage must not treat a skipped shard job as success",
        failures,
    )
    require(
        "needs.coverage-plan.outputs.mode == 'full' && needs.coverage-shard.result != 'success'"
        not in merge_body,
        "Merge Coverage must not ignore plugin/shards shard-job failures",
        failures,
    )
    require(
        "--planned-shards" in merge_body and "--emit-artifact-names" in merge_body,
        "Merge Coverage must download exactly the planned shard artifacts",
        failures,
    )
    require(
        "PLANNED_SHARDS: ${{ needs.coverage-plan.outputs.shards }}" in merge_body,
        "Merge Coverage must bind artifact verification to the planned shard output",
        failures,
    )
    require(
        "Run PR plugin coverage" not in merge_body,
        "Merge Coverage must reuse lib-unit artifacts instead of re-collecting plugin coverage",
        failures,
    )
    require(
        "cargo llvm-cov --lib" not in merge_body,
        "plugin mode must not re-run cargo llvm-cov --lib in the merge job",
        failures,
    )
    require(
        "needs.coverage-plan.outputs.mode != 'skip'" in merge_body,
        "Merge Coverage must still generate reports for plugin and shard-scoped plans",
        failures,
    )
    require(
        "COVERAGE_MODE: ${{ needs.coverage-plan.outputs.mode }}" in merge_body,
        "Merge Coverage must pass the planned mode into threshold enforcement",
        failures,
    )
    require(
        "PLUGIN_GATE: ${{ needs.coverage-plan.outputs.plugin_gate }}" in merge_body,
        "Merge Coverage must pass the plugin gate into threshold enforcement",
        failures,
    )
    require(
        'COVERAGE_MODE" = "full"' in merge_body or "COVERAGE_MODE\" = \"full\"" in merge_body
        or '[ "$COVERAGE_MODE" = "full" ]' in merge_body,
        "full mode must keep the overall and plugin coverage floors",
        failures,
    )
    require(
        "--min-overall-line" in merge_body and "--min-plugins-line" in merge_body,
        "full mode must still enforce overall and plugin floors",
        failures,
    )
    require(
        "--min-changed-plugins-line" in merge_body,
        "plugin-scoped plans must still enforce changed plugin line coverage",
        failures,
    )
    require(
        'name: coverage-report' in merge_body or "name: coverage-report" in merge_body,
        "Merge Coverage must keep publishing the coverage-report artifact",
        failures,
    )


def validate_docs(failures: list[str]) -> None:
    coverage_doc = DOCS_COVERAGE_PATH.read_text(encoding="utf-8")
    ci_cd_doc = DOCS_CI_CD_PATH.read_text(encoding="utf-8")
    require(
        "shard-scoped" in coverage_doc and "lib-unit" in coverage_doc,
        "docs/coverage.md must describe shard-scoped PR coverage planning",
        failures,
    )
    require(
        "fail closed" in coverage_doc.lower() or "fails closed" in coverage_doc.lower(),
        "docs/coverage.md must document fail-closed full coverage",
        failures,
    )
    require(
        "plugin" in coverage_doc and "lib-unit" in coverage_doc,
        "docs/coverage.md must preserve plugin-mode artifact reuse",
        failures,
    )
    require(
        "shard-scoped" in ci_cd_doc or "coverage shard" in ci_cd_doc.lower(),
        "docs/ci_cd.md must describe coverage shard planning",
        failures,
    )
    require(
        "CARGO_BUILD_JOBS=2" in ci_cd_doc and "timeout-minutes: 120" in ci_cd_doc,
        "docs/ci_cd.md must record the coverage-shard jobs=2 / 120-minute contract",
        failures,
    )
    require(
        "#4368" in ci_cd_doc and "33219849557" in ci_cd_doc and "33223661366" in ci_cd_doc,
        "docs/ci_cd.md must record the #4368 recurrence evidence",
        failures,
    )


def artifact_transport_script(workflow: str) -> str:
    body = extract_job_body(workflow, "coverage-merge")
    match = re.search(
        r"(?ms)^      - name: Download and extract coverage data\n"
        r".*?^        run: \|\n(?P<script>.*?)^        env:",
        body,
    )
    if not match:
        raise RuntimeError("missing coverage artifact transport step")
    return textwrap.dedent(match.group("script"))


def validate_artifact_transport(workflow: str, failures: list[str]) -> None:
    shard = extract_job_body(workflow, "coverage-shard")
    for token in (
        "-type d \\( -name incremental -o -name .fingerprint \\) -prune -o",
        "-type f ! -name '*.rlib' ! -name '*.rmeta' ! -name '*.d' ! -name '*.o' -print",
        'tar -cf "coverage-${{ matrix.shard }}.tar" -T coverage-files.txt',
        'path: coverage-${{ matrix.shard }}.tar',
        'name: coverage-data-${{ matrix.shard }}',
    ):
        require(token in shard, f"coverage payload must retain {token}", failures)
    script = artifact_transport_script(workflow)
    for token in (
        "set -euo pipefail",
        "gh api --paginate --slurp",
        'repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/artifacts',
        'select(.name == $name)',
        'length == 1 and .[0].expired == false',
        'repos/${GITHUB_REPOSITORY}/actions/artifacts/${artifact_id}/zip',
        'for attempt in 1 2; do',
        'if [ "$downloaded" != "true" ]; then',
        'member="coverage-${artifact_name#coverage-data-}.tar"',
        'if [ "$(unzip -Z1 "$archive")" != "$member" ]; then',
        'unzip -p "$archive" "$member" | { tar -xpf - && cat > /dev/null; }',
        'done <<< "$artifact_names"',
    ):
        require(token in script, f"coverage transport must retain {token}", failures)
    require(
        "gh run download" not in script,
        "coverage transport must not materialize the intermediate tar",
        failures,
    )


def self_test_artifact_transport(failures: list[str]) -> None:
    """Exercise the hosted shell against tiny ZIP/tar fixtures, without network."""
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    validate_artifact_transport(workflow, failures)
    for old, new in (
        ("set -euo pipefail", "set -eu"),
        ("gh api --paginate --slurp", "gh api --slurp"),
        ("length == 1 and .[0].expired == false", "length >= 1"),
        ('if [ "$downloaded" != "true" ]; then', 'if false; then'),
        ('tar -xpf - && cat > /dev/null', 'tar -xpf - || true'),
    ):
        # Mutate the transport step, not another job's shell prologue.
        merge_start = workflow.index("  coverage-merge:")
        transport_start = workflow.index("      - name: Download and extract coverage data", merge_start)
        changed = workflow[:transport_start] + mutated(workflow[transport_start:], old, new)
        rejected: list[str] = []
        validate_artifact_transport(changed, rejected)
        require(bool(rejected), f"transport mutation not caught: {old}", failures)

    script = artifact_transport_script(workflow)
    cases = (
        "valid", "zip64", "retry", "download-failure", "missing", "expired", "duplicate", "wrong-member",
        "extra-member", "corrupt-zip", "invalid-tar", "no-profiles",
    )
    for case in cases:
        with tempfile.TemporaryDirectory(prefix="coverage-transport-") as directory:
            root = Path(directory)
            scripts = root / ".github/scripts"
            scripts.mkdir(parents=True)
            shutil.copy2(PLANNER_PATH, scripts / PLANNER_PATH.name)
            artifacts = []
            for artifact_id, shard in ((11, LIB_UNIT_SHARD), (12, ADMIN_API_SHARD)):
                artifact = {"id": artifact_id, "name": f"coverage-data-{shard}", "expired": False}
                artifacts.append(artifact)
                contents = io.BytesIO()
                with tarfile.open(fileobj=contents, mode="w") as archive:
                    entries = [("debug/deps/shared-object", f"object-{shard}".encode(), 0o755)]
                    if case != "no-profiles":
                        entries.append((f"{shard}.profraw", f"profile-{shard}".encode(), 0o644))
                    for path, data, mode in entries:
                        entry = tarfile.TarInfo(f"target/llvm-cov-target/{path}")
                        entry.size, entry.mode = len(data), mode
                        archive.addfile(entry, io.BytesIO(data))
                payload = b"not a tar" if case == "invalid-tar" else contents.getvalue()
                member = "unexpected.tar" if case == "wrong-member" else f"coverage-{shard}.tar"
                zip_path = root / f"{artifact_id}.zip"
                with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    with archive.open(member, "w", force_zip64=(case == "zip64")) as zipped:
                        zipped.write(payload)
                    if case == "extra-member":
                        archive.writestr("extra.tar", payload)
                if case == "corrupt-zip":
                    data = bytearray(zip_path.read_bytes())
                    # Corrupt the central-directory CRC, leaving a readable
                    # member list and valid tar so only ZIP integrity fails.
                    data[data.index(b"PK\x01\x02") + 16] ^= 1
                    zip_path.write_bytes(data)
            if case == "missing":
                artifacts.pop()
            elif case == "expired":
                artifacts[-1]["expired"] = True
            elif case == "duplicate":
                artifacts.append(dict(artifacts[-1]))
            # Simulate pagination plus an unplanned artifact that must never be
            # downloaded, even when it belongs to this same run.
            (root / "metadata.json").write_text(json.dumps([
                {"artifacts": artifacts[:1]},
                {"artifacts": artifacts[1:] + [{"id": 99, "name": "coverage-data-mesh-routing", "expired": False}]},
            ]), encoding="utf-8")
            fake_gh = root / "gh"
            fake_gh.write_text("""#!/usr/bin/env bash
set -eu
download() {
  echo "$1" >> downloads
  if [ "$TRANSPORT_TEST_CASE" = download-failure ] ||
     { [ "$TRANSPORT_TEST_CASE" = retry ] && [ ! -f retried ]; }; then
    touch retried
    printf 'partial download'
    exit 1
  fi
  cat "$1.zip"
}
case "$*" in
  'api --paginate --slurp repos/example/coverage/actions/runs/42/artifacts') cat metadata.json ;;
  'api repos/example/coverage/actions/artifacts/11/zip') download 11 ;;
  'api repos/example/coverage/actions/artifacts/12/zip') download 12 ;;
  *) echo "unexpected artifact request: $*" >&2; exit 1 ;;
esac
""", encoding="utf-8")
            fake_gh.chmod(0o755)
            result = subprocess.run(
                # Record the retry delay without spending wall time asleep.
                ["bash", "-c", "sleep() { echo \"$*\" >> retry-delays; }\n" + script], cwd=root,
                env={**os.environ, "PATH": f"{root}{os.pathsep}{os.environ['PATH']}",
                     "TRANSPORT_TEST_CASE": case,
                     "GITHUB_REPOSITORY": "example/coverage", "GITHUB_RUN_ID": "42",
                     "GITHUB_STEP_SUMMARY": str(root / "summary.md"),
                     "PLANNED_SHARDS": json.dumps([LIB_UNIT_SHARD, ADMIN_API_SHARD])},
                capture_output=True, text=True, timeout=30,
            )
            should_succeed = case in {"valid", "zip64", "retry"}
            require(
                (result.returncode == 0) == should_succeed,
                f"transport {case}: exit {result.returncode}; {result.stderr}", failures,
            )
            if case in {"retry", "download-failure"}:
                require((root / "retry-delays").read_text().splitlines() == ["5"], "transport retry delay changed", failures)
            if case == "download-failure":
                require((root / "downloads").read_text().splitlines() == ["11", "11"], "transport must stop after two failed downloads", failures)
            if should_succeed and result.returncode == 0:
                target = root / "target/llvm-cov-target"
                for shard in (LIB_UNIT_SHARD, ADMIN_API_SHARD):
                    require((target / f"{shard}.profraw").read_bytes() == f"profile-{shard}".encode(), "profile bytes changed", failures)
                obj = target / "debug/deps/shared-object"
                require(obj.read_bytes() == b"object-admin-api" and (obj.stat().st_mode & 0o777) == 0o755, "shared object overwrite order or executable mode changed", failures)
                expected_downloads = ["11", "11", "12"] if case == "retry" else ["11", "12"]
                require((root / "downloads").read_text().splitlines() == expected_downloads, "transport downloaded unplanned or reordered artifacts", failures)
                require(not (root / "coverage-data").exists() and not list(root.rglob("*.tar")), "transport left an intermediate archive", failures)


def validate_repository_contract(failures: list[str]) -> None:
    validate_planner_contract(failures)
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    validate_workflow_text(text, failures)
    validate_artifact_transport(text, failures)
    validate_docs(failures)
    if planner_self_test() != 0:
        failures.append("coverage planner self-test failed")


def mutated(text: str, old: str, new: str) -> str:
    if old not in text:
        raise AssertionError(f"mutation source missing: {old!r}")
    return text.replace(old, new, 1)


def self_test() -> int:
    failures: list[str] = []
    self_test_artifact_transport(failures)
    if planner_self_test() != 0:
        failures.append("planner self-test failed during verifier self-test")

    good = """
name: Coverage
jobs:
  coverage-plan:
    outputs:
      mode: ${{ steps.plan.outputs.mode }}
      shards: ${{ steps.plan.outputs.shards }}
      shard-matrix: ${{ steps.plan.outputs.shard-matrix }}
      plugin_gate: ${{ steps.plan.outputs.plugin_gate }}
    steps:
      - run: python3 .github/scripts/coverage_plan.py --self-test
      - run: python3 .github/scripts/verify_coverage_workflow.py --self-test
      - run: python3 .github/scripts/verify_coverage_workflow.py
      - run: |
          git diff --name-only --no-renames "${base_ref}...HEAD"
          git diff --name-only --no-renames "${MERGE_BASE_SHA}...HEAD"
          echo failing closed to full coverage
          python3 .github/scripts/coverage_plan.py --github-output "$GITHUB_OUTPUT"
  coverage-shard:
    if: needs.coverage-plan.outputs.mode != 'skip'
    timeout-minutes: 120
    env:
      CARGO_BUILD_JOBS: "2"
    strategy:
      matrix:
        include: ${{ fromJSON(needs.coverage-plan.outputs.shard-matrix) }}
    steps:
      - run: echo "${{ matrix.shard }}"
      - run: cargo llvm-cov --no-report --lib --test unit_tests
  coverage-merge:
    name: Merge Coverage
    if: always()
    steps:
      - name: Fail when coverage planning fails
        if: needs.coverage-plan.result != 'success'
        run: exit 1
      - name: Fail when coverage mode is invalid
        if: needs.coverage-plan.result == 'success' && !contains(fromJSON('["skip", "plugin", "shards", "full"]'), needs.coverage-plan.outputs.mode)
        run: exit 1
      - name: Fail when planned coverage shards fail
        if: needs.coverage-plan.outputs.mode != 'skip' && needs.coverage-shard.result != 'success'
        run: exit 1
      - name: Download and extract coverage data
        if: needs.coverage-plan.outputs.mode != 'skip'
        run: |
          python3 .github/scripts/coverage_plan.py --emit-artifact-names --planned-shards "$PLANNED_SHARDS"
        env:
          PLANNED_SHARDS: ${{ needs.coverage-plan.outputs.shards }}
          COVERAGE_MODE: ${{ needs.coverage-plan.outputs.mode }}
          PLUGIN_GATE: ${{ needs.coverage-plan.outputs.plugin_gate }}
      - name: Check coverage thresholds
        if: needs.coverage-plan.outputs.mode != 'skip'
        run: |
          if [ "$COVERAGE_MODE" = "full" ]; then
            echo --min-overall-line
            echo --min-plugins-line
          elif [ "$PLUGIN_GATE" = "true" ]; then
            echo --min-changed-plugins-line
          fi
      - name: Upload coverage report
        uses: actions/upload-artifact@sha
        with:
          name: coverage-report
"""
    good_failures: list[str] = []
    validate_workflow_text(good, good_failures)
    if good_failures:
        failures.append(f"good fixture was rejected: {good_failures}")

    mutations = [
        (
            "python3 .github/scripts/coverage_plan.py --self-test",
            "python3 .github/scripts/coverage_plan.py",
            "planner self-test",
        ),
        (
            "include: ${{ fromJSON(needs.coverage-plan.outputs.shard-matrix) }}",
            "include:\n          - shard: lib-unit\n            kind: lib-unit\n            filters: \"\"",
            "static matrix",
        ),
        (
            "if: needs.coverage-plan.outputs.mode != 'skip'",
            "if: needs.coverage-plan.outputs.mode == 'full'",
            "full-only shard job",
        ),
        (
            "needs.coverage-plan.outputs.mode != 'skip' && needs.coverage-shard.result != 'success'",
            "needs.coverage-plan.outputs.mode == 'full' && needs.coverage-shard.result != 'success'",
            "plugin/shards false-green",
        ),
        (
            "needs.coverage-shard.result != 'success'",
            "needs.coverage-shard.result == 'failure'",
            "skipped shard treated as success",
        ),
        (
            '["skip", "plugin", "shards", "full"]',
            '["skip", "plugin", "full"]',
            "dropped shards mode",
        ),
        (
            "--emit-artifact-names --planned-shards \"$PLANNED_SHARDS\"",
            "gh api artifacts",
            "unplanned artifact download",
        ),
        (
            "PLUGIN_GATE: ${{ needs.coverage-plan.outputs.plugin_gate }}",
            "PLUGIN_GATE: false",
            "dropped plugin gate",
        ),
        (
            "timeout-minutes: 120",
            "timeout-minutes: 75",
            "restored 75-minute shard deadline",
        ),
        (
            'CARGO_BUILD_JOBS: "2"',
            'CARGO_BUILD_JOBS: "3"',
            "restored CARGO_BUILD_JOBS=3",
        ),
        (
            "cargo llvm-cov --no-report --lib --test unit_tests",
            "cargo llvm-cov --no-report --lib",
            "narrowed lib-unit coverage set",
        ),
    ]
    for old, new, label in mutations:
        mutated_failures: list[str] = []
        validate_workflow_text(mutated(good, old, new), mutated_failures)
        if not mutated_failures:
            failures.append(f"{label} mutation was not caught")

    recollect = mutated(
        good,
        "- name: Download and extract coverage data",
        "- name: Run PR plugin coverage\n        if: needs.coverage-plan.outputs.mode == 'plugin'\n        run: cargo llvm-cov --no-report --lib\n      - name: Download and extract coverage data",
    )
    recollect_failures: list[str] = []
    validate_workflow_text(recollect, recollect_failures)
    if not recollect_failures:
        failures.append("plugin re-collection mutation was not caught")

    admin = select_plan("pull_request", ["src/admin/mod.rs"])
    config = select_plan("pull_request", ["src/config/env_config.rs"])
    identity = select_plan("pull_request", ["src/identity/mod.rs"])
    proxy = select_plan("pull_request", ["src/proxy/mod.rs"])
    mesh = select_plan("pull_request", ["src/modes/mesh/config.rs"])
    protocol = select_plan("pull_request", ["src/http3/server.rs"])
    plugin = select_plan("pull_request", ["src/plugins/cors.rs"])
    unknown = select_plan("pull_request", ["src/cli.rs"])
    merge_group = select_plan("merge_group", ["src/admin/mod.rs"])
    main_event = select_plan("push", ["src/admin/mod.rs"])
    require(admin.mode == "shards" and ADMIN_API_SHARD in admin.shards, "admin positive", failures)
    require(config.mode == "full" and set(config.shards) == set(CANONICAL_SHARD_ORDER), "config positive vs full shared matrix", failures)
    require(identity.mode == "full" and set(identity.shards) == set(CANONICAL_SHARD_ORDER), "identity positive vs full shared matrix", failures)
    require(proxy.mode == "full" and set(proxy.shards) == set(CANONICAL_SHARD_ORDER), "proxy positive vs full shared matrix", failures)
    require(mesh.mode == "shards" and MESH_ROUTING_SHARD in mesh.shards, "mesh positive", failures)
    require(protocol.mode == "shards" and PROTOCOLS_SHARD in protocol.shards, "protocol positive", failures)
    require(plugin.mode == "plugin" and plugin.shards == (LIB_UNIT_SHARD,), "plugin positive", failures)
    require(unknown.mode == "full" and unknown.shards == CANONICAL_SHARD_ORDER, "unknown fail-closed", failures)
    require(merge_group.mode == "shards", "merge_group remains path-gated", failures)
    require(main_event.mode == "full", "main push stays full", failures)

    try:
        parse_planned_shards(json.dumps([LIB_UNIT_SHARD, ADMIN_API_SHARD]))
        verify_downloaded_artifacts(
            [LIB_UNIT_SHARD],
            ["coverage-data-lib-unit"],
        )
    except ValueError as error:
        failures.append(f"artifact helper self-test failed: {error}")
    try:
        verify_downloaded_artifacts([LIB_UNIT_SHARD], ["coverage-data-admin-api"])
    except ValueError:
        pass
    else:
        failures.append("artifact mismatch mutation was not caught")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}", file=sys.stderr)
        return 1
    print("coverage workflow verifier self-test passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()

    failures: list[str] = []
    validate_repository_contract(failures)
    if failures:
        for failure in failures:
            print(f"::error::{failure}", file=sys.stderr)
        return 1
    print("Coverage workflow shard-plan contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
