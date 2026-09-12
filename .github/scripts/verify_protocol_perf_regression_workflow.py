#!/usr/bin/env python3
"""Static regression checks for the protocol performance regression workflow.

Validates that `.github/workflows/protocol-perf-regression.yml` keeps the
scheduled + manual contract, pinned external actions, approved tool setup
paths, alert-only budget enforcement wiring, harness data-completeness gates,
and artifact/runner-health signals required by issue #2460. Does not execute
benchmarks.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "protocol-perf-regression.yml"
BUDGETS_PATH = (
    REPO_ROOT
    / "tests"
    / "performance"
    / "multi_protocol"
    / "protocol_perf_budgets.json"
)
EVALUATOR_PATH = (
    REPO_ROOT
    / "tests"
    / "performance"
    / "multi_protocol"
    / "evaluate_protocol_perf_budgets.py"
)
SCENARIOS_PATH = (
    REPO_ROOT
    / "tests"
    / "performance"
    / "multi_protocol"
    / "run_protocol_regression_scenarios.py"
)
RUNBOOK_PATH = REPO_ROOT / "docs" / "protocol_perf_regression.md"
CI_CD_PATH = REPO_ROOT / "docs" / "ci_cd.md"
CI_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "performance-regression.yml"
MULTI_PROTOCOL_DIR = REPO_ROOT / "tests" / "performance" / "multi_protocol"
RUN_PROTOCOL_TEST_PATH = MULTI_PROTOCOL_DIR / "run_protocol_test.sh"
NATIVE_FERRUM_CONFIGS = (
    "http1_perf.yaml",
    "http1_tls_perf.yaml",
    "http2_perf.yaml",
    "http3_perf.yaml",
    "ws_perf.yaml",
    "grpc_perf.yaml",
    "tcp_perf.yaml",
    "tcp_tls_perf.yaml",
    "udp_perf.yaml",
    "udp_dtls_perf.yaml",
)
SETUP_RUST_CI_PATH = (
    REPO_ROOT / ".github" / "actions" / "setup-rust-ci" / "action.yml"
)
PERF_CACHE_WORKSPACES = (". -> target", "tests/performance/mesh -> target")
SETUP_RUST_CI_WORKSPACES_PASSTHROUGH = "workspaces: ${{ inputs.workspaces }}"
RUST_CACHE_WITH_KEYS = (
    "shared-key",
    "workspaces",
    # Required by the CI runtime-cache contract (verify_ci_runtime_cache):
    # cache-on-failure is honored only for a lane producer, and save-if gates
    # publication to a producer on a trusted refs/heads/main run. The sccache
    # store is no longer persisted (no cache-directories). Still a closed set —
    # any other key remains a trust-broadening extra.
    "cache-on-failure",
    "save-if",
)

EXTERNAL_ACTION = re.compile(
    r"uses:\s*(?P<action>(?!\./)[^@\s]+)@(?P<ref>[^\s#]+)",
    re.IGNORECASE,
)
APPROVED_SETUP = (
    "./.github/actions/setup-rust-ci",
    "./.github/actions/setup-sccache",
    "./.github/actions/setup-fast-linker",
)

# Bench JSON redirects that must not be silenced with `|| true` in shell form,
# or with swallowed return codes when authored as Python subprocess helpers.
BENCH_JSON_SWALLOWED = re.compile(
    r"--json\s*>\s*\"\$\{OUTPUT_DIR\}/(?:connection_churn|soak|reload_under_load)\.json\""
    r"[^\n]*\|\|\s*true",
)
WAIT_BENCH_SWALLOWED = re.compile(r"wait\s+\"\$\{BENCH_PID\}\"\s*\|\|\s*true")
PY_BENCH_SWALLOWED = re.compile(
    r"subprocess\.(?:run|Popen)\([^\n]*(?:connection_churn|soak|reload_under_load)"
    r"[^\n]*\|\|\s*true"
)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate fixture expectations against synthetic snippets",
    )
    return parser.parse_args()


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def mapping_block(text: str, key: str, indent: int = 0) -> str:
    """Return the body of a YAML mapping key at `indent` spaces."""

    prefix = " " * indent
    match = re.search(
        rf"(?m)^{re.escape(prefix)}{re.escape(key)}:\n",
        text,
    )
    if match is None:
        return ""
    body_lines: list[str] = []
    for line in text[match.end() :].splitlines(keepends=True):
        if not line.strip():
            body_lines.append(line)
            continue
        line_indent = len(line) - len(line.lstrip(" "))
        if line_indent <= indent:
            break
        body_lines.append(line)
    return "".join(body_lines)


def named_step_block(text: str, step_name: str, item_indent: int) -> str:
    """Return one list item whose first line is `- name: {step_name}`."""

    prefix = " " * item_indent
    marker = f"{prefix}- name: {step_name}\n"
    start = text.find(marker)
    if start == -1:
        return ""
    body_lines = [marker]
    for line in text[start + len(marker) :].splitlines(keepends=True):
        if line.startswith(f"{prefix}- "):
            break
        stripped = line.lstrip(" ")
        if stripped == line and stripped.strip() and not stripped.startswith("#"):
            break
        body_lines.append(line)
    return "".join(body_lines)


def uses_step_block(text: str, uses: str, item_indent: int) -> str:
    """Return one list item whose first line is `- uses: {uses}`."""

    prefix = " " * item_indent
    marker = f"{prefix}- uses: {uses}\n"
    start = text.find(marker)
    if start == -1:
        return ""
    body_lines = [marker]
    for line in text[start + len(marker) :].splitlines(keepends=True):
        if line.startswith(f"{prefix}- "):
            break
        stripped = line.lstrip(" ")
        if stripped == line and stripped.strip() and not stripped.startswith("#"):
            break
        body_lines.append(line)
    return "".join(body_lines)


def mapping_keys(block: str, indent: int) -> list[str]:
    """Return top-level keys in a YAML mapping at `indent` spaces."""

    prefix = " " * indent
    keys: list[str] = []
    for line in block.splitlines():
        if not line.startswith(prefix):
            continue
        if len(line) > indent and line[indent] == " ":
            continue
        match = re.match(rf"^{re.escape(prefix)}([A-Za-z0-9_-]+):", line)
        if match:
            keys.append(match.group(1))
    return keys


def parse_workspaces_entries(with_block: str, key_indent: int) -> list[str] | None:
    """Parse rust-cache `workspaces` entries from a workflow `with:` block."""

    prefix = " " * key_indent
    lines = with_block.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(f"{prefix}workspaces:"):
            rest = line[len(prefix) + len("workspaces:") :].strip()
            if rest == "|":
                entries: list[str] = []
                for inner in lines[index + 1 :]:
                    if not inner.strip():
                        continue
                    inner_indent = len(inner) - len(inner.lstrip(" "))
                    if inner_indent <= key_indent:
                        break
                    entries.append(inner.strip())
                return entries
            if rest.startswith("|"):
                return None
            value = rest.strip().strip('"').strip("'")
            if not value:
                return []
            return [part.strip() for part in value.splitlines() if part.strip()]
    return None


def validate_setup_rust_ci_workspaces(text: str, failures: list[str]) -> None:
    """setup-rust-ci must pass `workspaces` through exactly, defaulting to root."""

    inputs = mapping_block(text, "inputs")
    workspaces_input = mapping_block(inputs, "workspaces", indent=2)
    require(
        bool(workspaces_input),
        "setup-rust-ci must declare an optional workspaces input",
        failures,
    )
    require(
        "required: false" in workspaces_input,
        "setup-rust-ci workspaces input must be optional",
        failures,
    )
    require(
        "required: true" not in workspaces_input,
        "setup-rust-ci workspaces input must not be required",
        failures,
    )
    require(
        'default: ""' in workspaces_input,
        'setup-rust-ci workspaces input must default to "" so omitted callers '
        "keep rust-cache root-workspace coverage",
        failures,
    )
    require(
        "passed through exactly" in workspaces_input
        or "pass-through" in workspaces_input
        or "passed through" in workspaces_input,
        "setup-rust-ci workspaces input must document exact rust-cache pass-through",
        failures,
    )
    require(
        ". -> target" in workspaces_input
        and ("omitted" in workspaces_input or "empty" in workspaces_input),
        "setup-rust-ci workspaces input must document omitted/empty `. -> target` "
        "root-workspace behavior",
        failures,
    )

    rust_cache_step = named_step_block(text, "Cache Rust dependencies", item_indent=4)
    require(
        bool(rust_cache_step),
        "setup-rust-ci must contain the Cache Rust dependencies step",
        failures,
    )
    require(
        "uses: Swatinem/rust-cache@" in rust_cache_step,
        "setup-rust-ci Cache Rust dependencies must use Swatinem/rust-cache",
        failures,
    )
    require(
        SETUP_RUST_CI_WORKSPACES_PASSTHROUGH in rust_cache_step,
        "setup-rust-ci must pass workspaces through exactly to rust-cache",
        failures,
    )
    require(
        "workspaces: |" not in rust_cache_step,
        "setup-rust-ci must not wrap the workspaces pass-through in a block scalar",
        failures,
    )
    with_block = mapping_block(rust_cache_step, "with", indent=6)
    require(
        mapping_keys(with_block, indent=8) == list(RUST_CACHE_WITH_KEYS),
        "setup-rust-ci rust-cache with: keys must stay shared-key, workspaces, "
        "cache-on-failure, and save-if (no trust-broadening extras)",
        failures,
    )
    require(
        "cache-all-crates:" not in rust_cache_step
        and "cache-workspace-crates:" not in rust_cache_step,
        "setup-rust-ci rust-cache must not enable cache-all-crates or "
        "cache-workspace-crates",
        failures,
    )


def validate_performance_regression_workspaces(text: str, failures: list[str]) -> None:
    """Perf job must cache root plus tests/performance/mesh without extra workspaces."""

    performance_job = re.search(
        r"(?ms)^  performance-regression:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    require(
        performance_job is not None,
        "performance-regression.yml must contain the performance-regression job",
        failures,
    )
    body = performance_job.group("body") if performance_job else ""
    setup_step = uses_step_block(
        body, "./.github/actions/setup-rust-ci", item_indent=6
    )
    require(
        bool(setup_step),
        "performance-regression.yml performance-regression must use setup-rust-ci",
        failures,
    )
    with_block = mapping_block(setup_step, "with", indent=8)
    require(
        'shared-key: "ci-perf"' in with_block,
        'performance-regression.yml performance-regression setup-rust-ci must keep shared-key "ci-perf"',
        failures,
    )
    entries = parse_workspaces_entries(with_block, key_indent=10)
    require(
        entries == list(PERF_CACHE_WORKSPACES),
        "performance-regression.yml performance-regression rust-cache workspaces must be exactly "
        "`. -> target` then `tests/performance/mesh -> target`",
        failures,
    )
    require(
        "cache-all-crates:" not in setup_step
        and "cache-directories:" not in setup_step,
        "performance-regression.yml performance-regression must not broaden rust-cache trust inputs",
        failures,
    )


def validate_workflow_text(text: str, failures: list[str]) -> None:
    require("schedule:" in text, "workflow must declare a schedule trigger", failures)
    require("workflow_dispatch:" in text, "workflow must declare workflow_dispatch", failures)
    require(
        "pull_request:" not in text and "pull_request_target:" not in text,
        "benchmark workflow must not execute untrusted pull-request code",
        failures,
    )
    require(
        'runs-on: ubuntu-latest' in text or "runs-on: ubuntu-latest" in text,
        "workflow must document/use ubuntu-latest runner class",
        failures,
    )
    require(
        "ci-release" in text,
        "workflow must use the stable ci-release build profile",
        failures,
    )
    require(
        "evaluate_protocol_perf_budgets.py" in text,
        "workflow must evaluate versioned protocol budgets",
        failures,
    )
    require(
        "run_protocol_regression_scenarios.py" in text,
        "workflow must run churn/soak/reload scenario harness",
        failures,
    )
    require(
        "runner_health" in text or "RUNNER HEALTH" in text or "Runner health" in text,
        "workflow must capture runner-health metadata",
        failures,
    )
    require(
        "upload-artifact@" in text,
        "workflow must retain artifacts",
        failures,
    )
    require(
        "enforcement" in text or "alert" in text,
        "workflow must wire alert/non-block budget enforcement",
        failures,
    )
    require(
        "protocol_perf_budgets.json" in text,
        "workflow must reference the versioned budgets file",
        failures,
    )
    require(
        "trends" in text.lower(),
        "workflow must publish machine-readable trends",
        failures,
    )
    require("permissions:" in text, "workflow must declare explicit permissions", failures)
    require("contents: read" in text, "workflow must use contents: read", failures)
    require("actions: read" in text, "workflow must use actions: read", failures)
    require(
        "write-all" not in text
        and not re.search(r"^\s+[A-Za-z_-]+:\s*write\s*$", text, re.MULTILINE),
        "benchmark workflow must not request write permissions",
        failures,
    )
    require(
        "--branch main" in text and "--status success" in text,
        "history must come from a successful run on the trusted main branch",
        failures,
    )

    external = list(EXTERNAL_ACTION.finditer(text))
    require(bool(external), "workflow must use at least one external action", failures)
    for match in external:
        ref = match.group("ref")
        require(
            bool(re.fullmatch(r"[0-9a-f]{40}", ref, flags=re.IGNORECASE)),
            f"mutable external action ref forbidden: {match.group('action')}@{ref}",
            failures,
        )

    local_uses = re.findall(r"uses:\s*(\./\.github/actions/[^\s]+)", text)
    for action in local_uses:
        require(
            action in APPROVED_SETUP,
            f"unexpected local action path: {action}",
            failures,
        )


def validate_evaluator_contract(text: str, failures: list[str]) -> None:
    require(
        "resolve_expected_protocols" in text,
        "evaluator must resolve expected protocols for all vs subset selection",
        failures,
    )
    require(
        "missing expected gateway measurement" in text,
        "evaluator must hard-fail when an expected protocol sample is missing",
        failures,
    )
    require(
        "invalid/zero-total" in text or "zero-total" in text,
        "evaluator must reject zero-total/invalid metric samples",
        failures,
    )
    require(
        "parse_finite_number" in text and "math.isfinite" in text,
        "evaluator must reject non-finite metric values",
        failures,
    )
    require(
        "parse_unit_rate" in text,
        "evaluator must validate scenario rates as finite unit intervals",
        failures,
    )
    require(
        "validate_gateway_run_completeness" in text
        and "expected exactly one" in text,
        "evaluator must require one protocol sample per matrix iteration",
        failures,
    )
    require(
        "validate_history_doc" in text and "schema_version must equal 1" in text,
        "evaluator must fail closed on malformed prior trend artifacts",
        failures,
    )
    require(
        "validate_runner_health" in text and "missing required evidence" in text,
        "evaluator must require valid runner-health evidence",
        failures,
    )
    require(
        "validate_required_scenarios" in text,
        "evaluator must validate required scenario output",
        failures,
    )
    require(
        "hard_fail" in text,
        "evaluator must hard-fail data-completeness independently of enforcement",
        failures,
    )
    require(
        "insufficient" in text and "resource_plateau" in text,
        "evaluator must hard-fail insufficient RSS/FD/task sampling",
        failures,
    )
    for needle, label in (
        ("missing expected protocol should hard-fail", "missing-protocol self-test"),
        ("zero-total gateway sample should hard-fail", "zero-total self-test"),
        ("missing scenarios should hard-fail", "missing-scenario self-test"),
        ("http1 subset should not require HTTP/2", "subset self-test"),
        ("measured regression must not hard-fail under alert enforcement", "alert-only self-test"),
        ("NaN rps should hard-fail", "non-finite rps self-test"),
        ("malformed total_requests should hard-fail", "malformed counts self-test"),
        (
            "sample_total must reject adversarially large counts",
            "oversized counts self-test",
        ),
        ("NaN heartbeat_success_rate should hard-fail", "non-finite heartbeat self-test"),
        ("NaN saturate rps should hard-fail", "non-finite saturate rps self-test"),
        ("non-finite resource plateau values should hard-fail", "non-finite plateau self-test"),
        (
            "finite zero-RPS should alert-only under alert enforcement",
            "zero-RPS alert-only self-test",
        ),
        ("missing p95 gateway metric should hard-fail", "missing-p95 self-test"),
        (
            "missing per-iteration protocol sample should hard-fail",
            "per-iteration completeness self-test",
        ),
        ("malformed history schema should hard-fail", "history-schema self-test"),
        ("missing runner-health evidence should hard-fail", "runner-health self-test"),
        ("undelivered reload SIGHUP should hard-fail", "reload-signal self-test"),
    ):
        require(needle in text, f"evaluator self-test missing coverage: {label}", failures)


def validate_scenarios_contract(text: str, failures: list[str]) -> None:
    require(
        not BENCH_JSON_SWALLOWED.search(text),
        "scenarios harness must not swallow churn/soak/reload bench failures with || true",
        failures,
    )
    require(
        not WAIT_BENCH_SWALLOWED.search(text),
        "scenarios harness must not swallow reload wait failures with || true",
        failures,
    )
    require(
        not PY_BENCH_SWALLOWED.search(text),
        "scenarios harness must not swallow bench failures with || true",
        failures,
    )
    require(
        "missing usable measurement sample" in text,
        "scenarios harness must validate usable measurement samples",
        failures,
    )
    require(
        "insufficient" in text and "resource_plateau" in text,
        "scenarios harness must fail on insufficient resource sampling",
        failures,
    )
    require(
        ("churn_rc" in text and "soak_rc" in text and "reload_rc" in text)
        or ("CHURN_RC" in text and "SOAK_RC" in text and "RELOAD_RC" in text),
        "scenarios harness must capture churn/soak/reload exit codes",
        failures,
    )
    require(
        "subprocess.run" in text or "subprocess.Popen" in text,
        "scenarios harness must launch proto_bench via subprocess",
        failures,
    )
    require(
        '["proto_bench"' in text or "['proto_bench'" in text,
        "scenarios harness must use literal proto_bench argv lists",
        failures,
    )
    require(
        'protocol_tool_env["PATH"]' in text
        and 'str(SCRIPT_DIR / "target" / "release")' in text,
        "scenarios harness must resolve protocol tools only from the built crate directory",
        failures,
    )
    require(
        "terminate_process" in text and "process.wait(" in text,
        "scenarios harness must terminate and reap owned child processes",
        failures,
    )
    require(
        "stop_sampler" in text and "sampler_stop.set()" in text,
        "scenarios harness must deterministically stop its resource sampler",
        failures,
    )
    require(
        "SIGHUP was not delivered" in text,
        "scenarios harness must hard-fail when reload SIGHUP is not delivered",
        failures,
    )


def validate_pr_ci_contract(text: str, failures: list[str]) -> None:
    """Required PR CI must run lightweight protocol-perf validators without benches."""
    performance_job = re.search(
        r"(?ms)^  performance-regression:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        text,
    )
    require(
        performance_job is not None,
        "performance-regression.yml must contain the performance-regression job",
        failures,
    )
    performance_body = performance_job.group("body") if performance_job else ""
    require(
        "    permissions:\n      contents: read" in performance_body,
        "performance-regression.yml performance-regression must use contents: read",
        failures,
    )
    require(
        "persist-credentials: false" in performance_body,
        "performance-regression.yml performance-regression checkout must not persist credentials",
        failures,
    )
    require(
        "Verify protocol-perf contracts (static)" in text,
        "performance-regression.yml Performance Regression Check must run protocol-perf static contracts",
        failures,
    )
    require(
        "verify_protocol_perf_regression_workflow.py --self-test" in text,
        "performance-regression.yml must run the protocol-perf workflow verifier self-test",
        failures,
    )
    require(
        "verify_protocol_perf_regression_workflow.py\n" in text
        or "verify_protocol_perf_regression_workflow.py" in text,
        "performance-regression.yml must run repository-contract verification for protocol-perf",
        failures,
    )
    require(
        "evaluate_protocol_perf_budgets.py --self-test" in text,
        "performance-regression.yml must run the protocol-perf evaluator self-test",
        failures,
    )
    require(
        "python3 -m py_compile tests/performance/multi_protocol/run_protocol_regression_scenarios.py"
        in text,
        "performance-regression.yml must syntax-check the protocol regression scenario harness",
        failures,
    )
    # Ensure the static gate is not buried behind optional benchmark path filters.
    checkout_idx = text.find("performance-regression:")
    static_idx = text.find("Verify protocol-perf contracts (static)")
    detect_idx = text.find("Detect performance-sensitive changes")
    require(
        checkout_idx != -1 and static_idx != -1 and detect_idx != -1,
        "performance-regression.yml must contain performance-regression, static protocol-perf, and path detect steps",
        failures,
    )
    if checkout_idx != -1 and static_idx != -1 and detect_idx != -1:
        require(
            checkout_idx < static_idx < detect_idx,
            "performance-regression.yml must run protocol-perf static contracts after checkout and before "
            "optional benchmark path gating",
            failures,
        )


def validate_native_ferrum_config_paths(failures: list[str]) -> None:
    """Native harness must not point Ferrum YAML at Docker-only cert mount paths."""

    if not RUN_PROTOCOL_TEST_PATH.is_file():
        require(
            False,
            f"missing native protocol harness: {RUN_PROTOCOL_TEST_PATH}",
            failures,
        )
        return

    harness = RUN_PROTOCOL_TEST_PATH.read_text(encoding="utf-8")
    require(
        "prepare_ferrum_config" in harness and "CA_PATH" in harness,
        "run_protocol_test.sh must template Ferrum YAML CA_PATH before gateway start",
        failures,
    )

    configs_dir = MULTI_PROTOCOL_DIR / "configs"
    for name in NATIVE_FERRUM_CONFIGS:
        path = configs_dir / name
        require(path.is_file(), f"missing native Ferrum config: {path}", failures)
        text = path.read_text(encoding="utf-8")
        require(
            "/etc/ferrum/tls" not in text,
            f"{path.relative_to(REPO_ROOT)} must not hardcode Docker-only "
            "/etc/ferrum/tls paths; use CA_PATH and rewrite in the harness",
            failures,
        )


def validate_repository_contract(failures: list[str]) -> None:
    require(WORKFLOW_PATH.is_file(), f"missing workflow: {WORKFLOW_PATH}", failures)
    require(BUDGETS_PATH.is_file(), f"missing budgets file: {BUDGETS_PATH}", failures)
    require(EVALUATOR_PATH.is_file(), f"missing evaluator: {EVALUATOR_PATH}", failures)
    require(SCENARIOS_PATH.is_file(), f"missing scenarios harness: {SCENARIOS_PATH}", failures)
    require(RUNBOOK_PATH.is_file(), f"missing runbook: {RUNBOOK_PATH}", failures)
    require(CI_CD_PATH.is_file(), f"missing CI/CD docs: {CI_CD_PATH}", failures)
    require(CI_WORKFLOW_PATH.is_file(), f"missing performance regression workflow: {CI_WORKFLOW_PATH}", failures)
    require(
        SETUP_RUST_CI_PATH.is_file(),
        f"missing setup-rust-ci action: {SETUP_RUST_CI_PATH}",
        failures,
    )

    if WORKFLOW_PATH.is_file():
        validate_workflow_text(WORKFLOW_PATH.read_text(encoding="utf-8"), failures)

    if EVALUATOR_PATH.is_file():
        validate_evaluator_contract(EVALUATOR_PATH.read_text(encoding="utf-8"), failures)

    if SCENARIOS_PATH.is_file():
        validate_scenarios_contract(SCENARIOS_PATH.read_text(encoding="utf-8"), failures)

    if CI_WORKFLOW_PATH.is_file():
        ci_workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
        validate_pr_ci_contract(ci_workflow, failures)
        validate_performance_regression_workspaces(ci_workflow, failures)

    if SETUP_RUST_CI_PATH.is_file():
        validate_setup_rust_ci_workspaces(
            SETUP_RUST_CI_PATH.read_text(encoding="utf-8"), failures
        )

    if BUDGETS_PATH.is_file():
        import json

        budgets = json.loads(BUDGETS_PATH.read_text(encoding="utf-8"))
        require(
            budgets.get("enforcement") == "alert",
            "budgets must start in alert enforcement until variance is measured",
            failures,
        )
        require(
            budgets.get("runner_class") == "ubuntu-latest",
            "budgets must document ubuntu-latest runner class",
            failures,
        )
        require(
            budgets.get("build_profile") == "ci-release",
            "budgets must document ci-release build profile",
            failures,
        )
        global_cfg = budgets.get("global", {})
        require(
            int(global_cfg.get("min_resource_samples", 0)) >= 2,
            "budgets must require a minimum resource sample count",
            failures,
        )
        protocols = budgets.get("protocols", {})
        for required in (
            "HTTP/1.1",
            "HTTP/2",
            "HTTP/3",
            "WebSocket",
            "gRPC",
            "TCP",
            "UDP",
        ):
            require(required in protocols, f"budgets missing protocol {required}", failures)

    if CI_CD_PATH.is_file():
        ci_cd = CI_CD_PATH.read_text(encoding="utf-8")
        require(
            "protocol-perf-regression.yml" in ci_cd,
            "docs/ci_cd.md must inventory protocol-perf-regression.yml",
            failures,
        )
        require(
            "Multi Protocol Performance Benchmark" in ci_cd
            or "perf-benchmark.yml" in ci_cd,
            "docs/ci_cd.md must still document the manual multi-protocol benchmark",
            failures,
        )
        require(
            "protocol-perf" in ci_cd.lower() and "static" in ci_cd.lower(),
            "docs/ci_cd.md must document protocol-perf static PR CI validation",
            failures,
        )
        require(
            "setup-rust-ci" in ci_cd
            and "workspaces" in ci_cd
            and ". -> target" in ci_cd
            and "tests/performance/mesh -> target" in ci_cd,
            "docs/ci_cd.md must document performance-regression rust-cache "
            "workspaces covering root and tests/performance/mesh",
            failures,
        )

    if RUNBOOK_PATH.is_file():
        runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
        require("ci-release" in runbook, "runbook must document ci-release profile", failures)
        require("ubuntu-latest" in runbook, "runbook must document runner class", failures)
        require(
            "alert" in runbook.lower(),
            "runbook must document alert/non-block budgets",
            failures,
        )
        require(
            "hard" in runbook.lower()
            and ("completeness" in runbook.lower() or "harness" in runbook.lower()),
            "runbook must document hard harness/data-completeness failures",
            failures,
        )
        require(
            "non-finite" in runbook.lower() or "nan" in runbook.lower(),
            "runbook must document non-finite/malformed metric hard failures",
            failures,
        )
        require(
            "ci.yml" in runbook and "overhead" in runbook.lower(),
            "runbook must preserve the lightweight PR overhead check",
            failures,
        )
        require(
            "Performance Regression Check" in runbook
            or "protocol-perf contracts" in runbook.lower(),
            "runbook must document PR CI static protocol-perf contract checks",
            failures,
        )
        require(
            "setup-rust-ci" in runbook
            and "workspaces" in runbook
            and "tests/performance/mesh" in runbook
            and ". -> target" in runbook,
            "runbook must document PR CI mesh workspace rust-cache coverage",
            failures,
        )

    validate_native_ferrum_config_paths(failures)


def self_test() -> int:
    failures: list[str] = []
    good = """
name: Protocol Performance Regression
on:
  schedule:
    - cron: "0 5 * * 0"
  workflow_dispatch:
permissions:
  contents: read
  actions: read
jobs:
  regress:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
      - uses: ./.github/actions/setup-rust-ci
      - run: echo ci-release
      - run: python3 tests/performance/multi_protocol/run_protocol_regression_scenarios.py
      - run: python3 tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py
      - run: echo protocol_perf_budgets.json alert trends runner_health
      - run: gh run list --branch main --status success
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
"""
    validate_workflow_text(good, failures)

    bad_failures: list[str] = []
    bad = """
on:
  workflow_dispatch:
jobs:
  regress:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    validate_workflow_text(bad, bad_failures)
    if not any("schedule" in item for item in bad_failures):
        failures.append("self-test expected missing schedule detection")
    if not any("mutable" in item for item in bad_failures):
        failures.append("self-test expected mutable action detection")

    branch_ref_failures: list[str] = []
    mutable_branch = good.replace(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/checkout@main",
    )
    validate_workflow_text(mutable_branch, branch_ref_failures)
    if not any("mutable" in item for item in branch_ref_failures):
        failures.append("self-test expected mutable branch action detection")

    swallow_failures: list[str] = []
    swallowed = """
proto_bench http1 --json > "${OUTPUT_DIR}/connection_churn.json" 2>"${OUTPUT_DIR}/connection_churn.log" || true
wait "${BENCH_PID}" || true
"""
    validate_scenarios_contract(swallowed, swallow_failures)
    if not any("swallow" in item for item in swallow_failures):
        failures.append("self-test expected || true swallow detection for scenario benches")

    good_scenarios = """
churn_rc = 0
soak_rc = 0
reload_rc = 0
subprocess.run(
    ["proto_bench", "http1", "--json"],
    check=False,
)
protocol_tool_env["PATH"] = str(SCRIPT_DIR / "target" / "release")
# no || true after json redirects
missing usable measurement sample
resource_plateau insufficient rss_bytes sampling
def terminate_process(process):
    process.wait(timeout=5)
def stop_sampler():
    sampler_stop.set()
SIGHUP was not delivered
"""
    good_scenario_failures: list[str] = []
    validate_scenarios_contract(good_scenarios, good_scenario_failures)
    if good_scenario_failures:
        failures.append(
            f"self-test unexpectedly rejected good scenarios snippet: {good_scenario_failures}"
        )

    pr_ci_good = """
  performance-regression:
    name: Performance Regression Check
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v6
        with:
          persist-credentials: false
      - name: Verify protocol-perf contracts (static)
        run: |
          python3 .github/scripts/verify_protocol_perf_regression_workflow.py --self-test
          python3 .github/scripts/verify_protocol_perf_regression_workflow.py
          python3 tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py --self-test
          python3 -m py_compile tests/performance/multi_protocol/run_protocol_regression_scenarios.py
      - name: Detect performance-sensitive changes
        run: echo detect
"""
    pr_ci_failures: list[str] = []
    validate_pr_ci_contract(pr_ci_good, pr_ci_failures)
    if pr_ci_failures:
        failures.append(
            f"self-test unexpectedly rejected good PR CI snippet: {pr_ci_failures}"
        )

    pr_ci_bad_failures: list[str] = []
    validate_pr_ci_contract(
        """
  performance-regression:
    steps:
      - name: Detect performance-sensitive changes
        run: echo detect
""",
        pr_ci_bad_failures,
    )
    if not any("static" in item for item in pr_ci_bad_failures):
        failures.append("self-test expected missing protocol-perf static PR CI detection")

    good_setup_rust_ci = """
name: Setup Rust CI environment
inputs:
  shared-key:
    required: true
  components:
    required: false
    default: ""
  workspaces:
    description: >-
      Optional rust-cache workspaces passed through exactly.
      When omitted or empty, rust-cache keeps `. -> target`.
    required: false
    default: ""
runs:
  using: composite
  steps:
    - name: Cache Rust dependencies
      uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2
      with:
        shared-key: ${{ inputs.shared-key }}
        workspaces: ${{ inputs.workspaces }}
        cache-on-failure: ${{ inputs.save == 'true' && inputs.cache-on-failure == 'true' }}
        save-if: ${{ inputs.save == 'true' && github.event_name != 'pull_request' && github.event_name != 'merge_group' && github.ref == 'refs/heads/main' && github.event.pull_request.head.repo.fork != true }}
"""
    setup_ok: list[str] = []
    validate_setup_rust_ci_workspaces(good_setup_rust_ci, setup_ok)
    if setup_ok:
        failures.append(
            f"self-test unexpectedly rejected good setup-rust-ci snippet: {setup_ok}"
        )

    missing_passthrough: list[str] = []
    validate_setup_rust_ci_workspaces(
        good_setup_rust_ci.replace(
            "        workspaces: ${{ inputs.workspaces }}\n",
            "",
        ),
        missing_passthrough,
    )
    if not any("pass workspaces through exactly" in item for item in missing_passthrough):
        failures.append("self-test expected missing rust-cache workspaces pass-through")

    required_workspaces: list[str] = []
    validate_setup_rust_ci_workspaces(
        good_setup_rust_ci.replace(
            '    required: false\n    default: ""\nruns:',
            '    required: true\n    default: ""\nruns:',
        ),
        required_workspaces,
    )
    if not any(
        "must be optional" in item or "must not be required" in item
        for item in required_workspaces
    ):
        failures.append("self-test expected required workspaces input detection")

    nonempty_default: list[str] = []
    validate_setup_rust_ci_workspaces(
        good_setup_rust_ci.replace(
            '    required: false\n    default: ""\nruns:',
            '    required: false\n    default: "fuzz -> target"\nruns:',
        ),
        nonempty_default,
    )
    if not any("default to" in item for item in nonempty_default):
        failures.append("self-test expected nonempty workspaces default detection")

    wrapped_passthrough: list[str] = []
    validate_setup_rust_ci_workspaces(
        good_setup_rust_ci.replace(
            "        workspaces: ${{ inputs.workspaces }}\n",
            "        workspaces: |\n          ${{ inputs.workspaces }}\n",
        ),
        wrapped_passthrough,
    )
    if not any(
        "block scalar" in item or "pass workspaces through exactly" in item
        for item in wrapped_passthrough
    ):
        failures.append("self-test expected wrapped workspaces pass-through detection")

    extra_cache_keys: list[str] = []
    validate_setup_rust_ci_workspaces(
        good_setup_rust_ci.replace(
            "        workspaces: ${{ inputs.workspaces }}\n",
            "        workspaces: ${{ inputs.workspaces }}\n"
            "        cache-all-crates: true\n",
        ),
        extra_cache_keys,
    )
    if not any("trust-broadening" in item or "cache-all-crates" in item for item in extra_cache_keys):
        failures.append("self-test expected extra rust-cache trust input detection")

    good_perf_cache = """
  performance-regression:
    name: Performance Regression Check
    steps:
      - uses: ./.github/actions/setup-rust-ci
        with:
          shared-key: "ci-perf"
          workspaces: |
            . -> target
            tests/performance/mesh -> target
      - name: Run IP restriction worst-case microbenchmark
        run: echo bench
"""
    perf_ok: list[str] = []
    validate_performance_regression_workspaces(good_perf_cache, perf_ok)
    if perf_ok:
        failures.append(
            f"self-test unexpectedly rejected good perf workspaces snippet: {perf_ok}"
        )

    mesh_only: list[str] = []
    validate_performance_regression_workspaces(
        good_perf_cache.replace(
            "          workspaces: |\n            . -> target\n            tests/performance/mesh -> target\n",
            "          workspaces: |\n            tests/performance/mesh -> target\n",
        ),
        mesh_only,
    )
    if not any("exactly" in item for item in mesh_only):
        failures.append("self-test expected mesh-only workspaces to drop root coverage")

    extra_workspace: list[str] = []
    validate_performance_regression_workspaces(
        good_perf_cache.replace(
            "            tests/performance/mesh -> target\n",
            "            tests/performance/mesh -> target\n            fuzz -> target\n",
        ),
        extra_workspace,
    )
    if not any("exactly" in item for item in extra_workspace):
        failures.append("self-test expected extra perf workspace detection")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1
    print("protocol-perf-regression workflow verifier self-test passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()

    failures: list[str] = []
    validate_repository_contract(failures)
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print("protocol-perf-regression workflow contract ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
