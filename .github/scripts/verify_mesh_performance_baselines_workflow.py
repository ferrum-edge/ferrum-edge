#!/usr/bin/env python3
"""Static contract checks for the mesh performance baselines workflow (#3332).

Does not execute benchmarks. Validates workflow wiring, pinned actions, suite
coverage, provenance/summary scripts, ubuntu-24.04 pin, acceptance step,
mesh/HBONE/DNS interval evidence, and docs inventory pointers.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "mesh-performance-baselines.yml"
PROVENANCE_SCRIPT = REPO_ROOT / ".github" / "scripts" / "collect_mesh_baseline_provenance.py"
SUMMARY_SCRIPT = REPO_ROOT / ".github" / "scripts" / "summarize_mesh_baseline_results.py"
LEDGER_SCRIPT = REPO_ROOT / ".github" / "scripts" / "mesh_baseline_ledger.py"
HEALTH_SCRIPT = REPO_ROOT / ".github" / "scripts" / "mesh_baseline_runner_health.py"
STEP_SUMMARY_SCRIPT = REPO_ROOT / ".github" / "scripts" / "mesh_baseline_step_summary.py"
CI_YML = REPO_ROOT / ".github" / "workflows" / "performance-regression.yml"
PROTOCOL_DOC = REPO_ROOT / "docs" / "protocol_perf_regression.md"
CI_CD_DOC = REPO_ROOT / "docs" / "ci_cd.md"
MESH_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh" / "baseline.md"
HBONE_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh-hbone-e2e" / "baseline.md"
DNS_BASELINE = REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "baseline.md"
HBONE_LOADGEN = (
    REPO_ROOT / "tests" / "performance" / "mesh-hbone-e2e" / "src" / "bin" / "hbone_loadgen.rs"
)
HBONE_RUN = REPO_ROOT / "tests" / "performance" / "mesh-hbone-e2e" / "run.sh"
HBONE_FIXTURE = REPO_ROOT / "examples" / "hbone_perf_fixture.rs"
ROOT_CARGO_TOML = REPO_ROOT / "Cargo.toml"
DNS_LOADGEN = (
    REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "src" / "bin" / "dns_loadgen.rs"
)
DNS_UPSTREAM_STUB = (
    REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "src" / "bin" / "dns_upstream_stub.rs"
)
DNS_UPSTREAM_STUB_LIB = (
    REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "src" / "upstream_stub.rs"
)
DNS_WIRE = REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "src" / "dns_wire.rs"
DNS_METRICS = REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "src" / "metrics.rs"
DNS_README = REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "README.md"
DNS_HARNESS_TESTS = (
    REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "tests" / "dns_harness_prereq_tests.rs"
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
PINNED_SHA = re.compile(r"^[0-9a-f]{40}$")
PUBLISHED_BASELINE_DATE = re.compile(r"\bPublished \d{4}-\d{2}-\d{2}\b")
PUBLISHED_BASELINE_STATUS = re.compile(
    r"Publication status[^\n]*?:\*{0,2}\s*Published\b", re.IGNORECASE
)
PUBLISHED_BASELINE_SHA = re.compile(
    r"Ferrum (?:commit )?SHA[^0-9a-f]+`?([0-9a-f]{40})"
)
PUBLISHED_BASELINE_RUN = re.compile(
    r"https://github\.com/ferrum-edge/ferrum-edge/actions/runs/\d+"
)
PUBLISHED_BASELINE_ARTIFACT = re.compile(
    r"mesh-performance-baselines-([0-9a-f]{40})"
)
PUBLISHED_BASELINE_COLLECTED_AT = re.compile(
    r"Collected at \(UTC\).*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
)
HBONE_BACKEND_ALLOW_IPS_VAR = "FERRUM_BACKEND_ALLOW_IPS"
HBONE_BACKEND_ALLOW_IPS_VALUE = "private"
HBONE_GATEWAY_EXECUTABLE = "$PROJECT_ROOT/target/release/examples/hbone_perf_fixture"
HBONE_PRODUCTION_GATEWAY_EXECUTABLE = "./target/release/ferrum-edge"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def _strip_shell_comment(value: str) -> str:
    """Remove an unquoted shell comment while preserving quoted ``#`` data."""
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote != "'":
            escaped = True
            continue
        if quote is not None:
            if character == quote:
                quote = None
            continue
        if character in "'\"":
            quote = character
            continue
        if character == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index]
    return value


def _logical_shell_lines(text: str) -> list[str]:
    """Join backslash-continued shell lines into one logical command line."""
    logical: list[str] = []
    parts: list[str] = []
    for raw_line in text.splitlines():
        line = _strip_shell_comment(raw_line.rstrip())
        if line.endswith("\\"):
            parts.append(line[:-1].rstrip())
            continue
        parts.append(line)
        logical.append(" ".join(parts))
        parts = []
    if parts:
        logical.append(" ".join(parts))
    return logical


def _is_env_gateway_launch(line: str) -> bool:
    """Return whether a logical line launches the HBONE gateway via env."""
    return HBONE_GATEWAY_EXECUTABLE in line and re.search(r"\benv\b", line) is not None


def _parse_env_assignment(token: str) -> tuple[str, str] | None:
    """Split a single env assignment token into key/value when present."""
    if "=" not in token:
        return None
    key, _, value = token.partition("=")
    if not key:
        return None
    return key, value


def _backend_allow_ips_value_invalid(value: str) -> str | None:
    """Return a rejection reason when the assignment value is not literal private."""
    if not value:
        return "empty value"
    if "$" in value or "`" in value:
        return "variable or command-substitution value"
    if value != HBONE_BACKEND_ALLOW_IPS_VALUE:
        return f"non-private value {value!r}"
    return None


def _check_hbone_backend_allow_ips(hbone_run: str, failures: list[str]) -> None:
    """Require exactly one pre-executable ``FERRUM_BACKEND_ALLOW_IPS=private`` on the env launch."""
    candidates = [
        line.strip()
        for line in _logical_shell_lines(hbone_run)
        if line.strip() and _is_env_gateway_launch(line)
    ]
    if not candidates:
        failures.append(
            f"HBONE harness must contain exactly one logical "
            f"env ... {HBONE_GATEWAY_EXECUTABLE} launch command"
        )
        return
    if len(candidates) != 1:
        failures.append(
            f"HBONE harness must contain exactly one logical "
            f"env ... {HBONE_GATEWAY_EXECUTABLE} launch command (found {len(candidates)})"
        )
        return

    try:
        tokens = shlex.split(candidates[0], posix=True)
    except ValueError as exc:
        failures.append(f"HBONE gateway launch command tokenization failed: {exc}")
        return

    if not tokens or tokens[0] != "env":
        failures.append("HBONE gateway launch command must begin with env")
        return

    executable_hits = [index for index, token in enumerate(tokens) if token == HBONE_GATEWAY_EXECUTABLE]
    if len(executable_hits) != 1:
        failures.append(
            f"HBONE gateway launch command must reference {HBONE_GATEWAY_EXECUTABLE} exactly once"
        )
        return
    exec_idx = executable_hits[0]

    allow_ips_values: list[str] = []
    for token in tokens[1:exec_idx]:
        parsed = _parse_env_assignment(token)
        if parsed is None:
            failures.append(
                f"HBONE gateway launch command has unexpected token {token!r} before the executable"
            )
            return
        key, value = parsed
        if key == HBONE_BACKEND_ALLOW_IPS_VAR:
            allow_ips_values.append(value)

    for token in tokens[exec_idx + 1:]:
        parsed = _parse_env_assignment(token)
        if parsed is not None and parsed[0] == HBONE_BACKEND_ALLOW_IPS_VAR:
            failures.append(
                f"HBONE harness must not place {HBONE_BACKEND_ALLOW_IPS_VAR} after "
                f"{HBONE_GATEWAY_EXECUTABLE}"
            )
            return

    if not allow_ips_values:
        failures.append(
            f"HBONE gateway launch command must set exactly one pre-executable "
            f"{HBONE_BACKEND_ALLOW_IPS_VAR}={HBONE_BACKEND_ALLOW_IPS_VALUE}"
        )
        return
    if len(allow_ips_values) != 1:
        failures.append(
            f"HBONE gateway launch command must set exactly one pre-executable "
            f"{HBONE_BACKEND_ALLOW_IPS_VAR} assignment (found {len(allow_ips_values)}: "
            f"{allow_ips_values!r})"
        )
        return

    reason = _backend_allow_ips_value_invalid(allow_ips_values[0])
    if reason is not None:
        failures.append(
            f"HBONE gateway launch command must set pre-executable "
            f"{HBONE_BACKEND_ALLOW_IPS_VAR}={HBONE_BACKEND_ALLOW_IPS_VALUE} "
            f"({reason})"
        )


def _hbone_example_manifest_block(cargo_toml: str) -> str:
    """Return the `[[example]]` block that declares `hbone_perf_fixture`."""
    marker = 'name = "hbone_perf_fixture"'
    start = cargo_toml.find(marker)
    if start == -1:
        return ""
    block_start = cargo_toml.rfind("[[example]]", 0, start)
    if block_start == -1:
        return ""
    nxt = cargo_toml.find("\n[[", start)
    if nxt == -1:
        return cargo_toml[block_start:]
    return cargo_toml[block_start:nxt]


def _check_hbone_trusted_fixture_contract(
    hbone_run: str,
    fixture_src: str,
    cargo_toml: str,
    workflow: str,
    ledger: str,
    failures: list[str],
) -> None:
    """Pin the trusted fixture launch and reject operator file-mode mesh tags."""
    require(HBONE_FIXTURE.is_file(), "HBONE trusted fixture example source missing", failures)
    require(
        HBONE_GATEWAY_EXECUTABLE in hbone_run,
        "HBONE harness must launch the trusted fixture example",
        failures,
    )
    require(
        HBONE_PRODUCTION_GATEWAY_EXECUTABLE not in hbone_run,
        "HBONE harness must not launch production ferrum-edge",
        failures,
    )
    require(
        "FERRUM_FILE_CONFIG_PATH" not in hbone_run,
        "HBONE harness must not load operator file config",
        failures,
    )
    require(
        "FERRUM_MODE=file" not in hbone_run,
        "HBONE harness must not start production file mode",
        failures,
    )
    require(
        "write_gateway_config" not in hbone_run,
        "HBONE harness must not write operator gateway YAML",
        failures,
    )
    require(
        '"mesh.hbone"' not in hbone_run and "'mesh.hbone'" not in hbone_run,
        "HBONE harness must not stamp reserved mesh.* tags into operator file config",
        failures,
    )
    require(
        "cargo build --release --example hbone_perf_fixture" in hbone_run,
        "HBONE harness must build the trusted fixture example",
        failures,
    )
    require(
        "--example hbone_perf_fixture" in workflow,
        "hosted HBONE collection must build the trusted fixture example",
        failures,
    )
    require(
        "cargo build --release --example hbone_perf_fixture" in ledger,
        "ledger HBONE commands must build the trusted fixture example",
        failures,
    )
    require(
        ledger.count("cargo build --release --bin ferrum-edge") == 1,
        "ledger ferrum-edge build must remain DNS-only",
        failures,
    )

    require("normalize_fields" in fixture_src, "HBONE fixture must normalize projected config", failures)
    require(
        "serve(" in fixture_src and "ServeOptions" in fixture_src,
        "HBONE fixture must call file::serve with ServeOptions",
        failures,
    )
    require(
        "install_crypto_provider" in fixture_src,
        "HBONE fixture must install the rustls crypto provider",
        failures,
    )
    require("JwtManager" in fixture_src, "HBONE fixture must supply an explicit admin JWT manager", failures)
    require(
        '"mesh.hbone"' in fixture_src and '"mesh.hbone_port"' in fixture_src,
        "HBONE fixture must construct reserved mesh.* tags internally",
        failures,
    )
    require(
        ".validate_operator_provided_fields(" not in fixture_src
        and "validate_operator_provided_fields()" not in fixture_src,
        "HBONE fixture must not call operator-field validation",
        failures,
    )
    require(
        "file_loader" not in fixture_src,
        "HBONE fixture must not use the operator file loader",
        failures,
    )
    require(
        "FERRUM_FILE_CONFIG_PATH" not in fixture_src,
        "HBONE fixture must not expose a file-config path",
        failures,
    )
    require(
        "general-purpose trusted config loader" in fixture_src.lower(),
        "HBONE fixture must document that it is not a general-purpose trusted loader",
        failures,
    )
    require(
        "config-file path argument" in fixture_src or "There is no config-file path argument" in fixture_src,
        "HBONE fixture must refuse a config-file path argument",
        failures,
    )

    example_block = _hbone_example_manifest_block(cargo_toml)
    require(
        'path = "examples/hbone_perf_fixture.rs"' in example_block,
        "root Cargo.toml must declare the hbone_perf_fixture example path",
        failures,
    )
    require(
        "test = false" in example_block,
        "hbone_perf_fixture example must set test = false",
        failures,
    )


def check_workflow(text: str, failures: list[str]) -> None:
    require("name: Mesh Performance Baselines" in text, "workflow display name missing", failures)
    require("workflow_dispatch:" in text, "workflow_dispatch trigger required", failures)
    require("runs-on: ubuntu-24.04" in text, "collection must pin runs-on ubuntu-24.04", failures)
    require("BENCH_RUNNER_CLASS: ubuntu-24.04" in text, "BENCH_RUNNER_CLASS must be ubuntu-24.04", failures)
    require("ubuntu-24.04" in text, "default runner class must be ubuntu-24.04", failures)
    require("inputs:\n      runner:" not in text and "runner:" not in _workflow_inputs_block(text), "arbitrary runner input must be removed", failures)
    require(
        "runs-on: self-hosted" not in text.lower()
        and "runs-on: [self-hosted" not in text.lower()
        and "- self-hosted" not in text.lower(),
        "must not dispatch to self-hosted runners",
        failures,
    )
    require("workflow_call:" in text, "trusted reusable entry point required", failures)
    require("cancel-in-progress: false" in text, "collection must serialize without cancelling in-progress runs", failures)
    require("cancel-in-progress: true" not in text, "collection must not cancel in-progress runs", failures)
    require("BENCH_BUILD_PROFILE: release" in text, "release profile required", failures)
    require("BENCH_MAX_CPU_STEAL_PERCENT: \"5.0\"" in text or "BENCH_MAX_CPU_STEAL_PERCENT: '5.0'" in text, "documented CPU steal threshold required", failures)
    require("runner_health_probes.jsonl" in text, "per-E2E runner health probes required", failures)
    require(
        "mesh_baseline_runner_health.py" in text,
        "runner health capture must be wired to the approved automation script",
        failures,
    )
    require(
        "mesh_baseline_runner_health.py --self-test" in text,
        "workflow must run the runner health hosted self-test",
        failures,
    )
    require("--interval-begin" in text, "health probes must snapshot interval begin", failures)
    require("--interval-end" in text, "health probes must snapshot interval end", failures)
    require("MESH_BASELINE_DIAG_DIR" in text, "hosted collection must set an opt-in diagnostic log destination", failures)
    require("sysstat" not in text, "sysstat is unused by selected harnesses and must not be installed", failures)
    require(
        "libcurl4-openssl-dev" not in text,
        "collection must not reinstall libcurl4-openssl-dev; setup-rust-ci already provides it",
        failures,
    )
    require("protobuf-compiler" in text and "lsof" in text, "retain protobuf-compiler and lsof prerequisites", failures)
    require(
        "harness_status" in text and "PIPESTATUS" in text,
        "E2E interval-end must preserve the original harness exit status",
        failures,
    )
    # The trusted Cross build policy refuses a new workflow that carries a
    # dynamic executable surface. Inline interpreter bodies are exactly that:
    # a heredoc program or an awk/bc one-liner is a command the static scan
    # cannot resolve to a literal argument vector. Keep those computations in
    # .github/scripts/ instead of reintroducing them here.
    require(
        re.search(r"(?<!<)<<(?!<)", text) is None,
        "no inline heredoc programs in this workflow",
        failures,
    )
    require(
        not re.search(r"(?<![A-Za-z0-9_-])(awk|bc|gawk|mawk|perl|node|ruby)(?![A-Za-z0-9_.-])", text),
        "no inline non-shell interpreters in this workflow",
        failures,
    )
    require("--check-acceptance" in text, "selected-suite acceptance step required", failures)
    require(
        "unsupported suites value" in text,
        "workflow must reject unsupported suites at the boundary",
        failures,
    )
    require(
        "all|mesh|hbone|dns" in text or 'supported = {"all", "mesh", "hbone", "dns"}' in text,
        "workflow suite allowlist must be all|mesh|hbone|dns",
        failures,
    )
    require(
        "BENCH_ITERATIONS must be an integer from 3 to 5" in text
        and "ITERATIONS > 5" in text,
        "workflow must reject E2E repetition counts outside 3..5",
        failures,
    )
    require("authz_match" in text and "ip_restriction" in text, "mesh benches incomplete", failures)
    require("slice_apply" in text and "xds_translation" in text, "mesh benches incomplete", failures)
    require("1kib_c50_30s" in text and "16kib_c50_30s" in text, "HBONE scenarios incomplete", failures)
    require("256kib_c100_60s" in text, "HBONE 256 KiB scenario missing", failures)
    require("--duration 60 --concurrency 100" in text, "DNS documented row params missing", failures)
    require("collect_mesh_baseline_provenance.py" in text, "provenance script not wired", failures)
    require("summarize_mesh_baseline_results.py" in text, "summary script not wired", failures)
    require("actions/upload-artifact@" in text, "artifact upload required", failures)
    require("mesh-performance-baselines-${{ github.sha }}" in text, "artifact name must include SHA", failures)
    require("permissions:\n  contents: read" in text, "contents: read permission required", failures)
    # Upload must remain available after acceptance failure.
    upload_idx = text.find("Upload mesh baseline artifacts")
    accept_idx = text.find("Enforce selected-suite acceptance gates")
    require(upload_idx != -1 and accept_idx != -1, "acceptance + upload steps required", failures)
    require(accept_idx < upload_idx, "acceptance step must precede artifact upload", failures)
    require(
        "if: always()" in text[upload_idx : upload_idx + 200],
        "artifact upload must use if: always()",
        failures,
    )

    for match in EXTERNAL_ACTION.finditer(text):
        action = match.group("action")
        ref = match.group("ref")
        require(
            PINNED_SHA.match(ref) is not None,
            f"external action {action} must be pinned to a 40-char SHA (got {ref})",
            failures,
        )

    for setup in APPROVED_SETUP:
        if setup == "./.github/actions/setup-rust-ci":
            require(setup in text, "must use setup-rust-ci", failures)

    mesh_step = _named_step(text, "Collect mesh Criterion microbenchmarks")
    hbone_step = _named_step(text, "Collect HBONE E2E baselines (3+ repetitions)")
    dns_step = _named_step(text, "Collect DNS E2E baselines (3+ repetitions)")
    require(bool(mesh_step), "mesh Criterion collection step required", failures)
    require(bool(hbone_step), "HBONE E2E collection step required", failures)
    require(bool(dns_step), "DNS E2E collection step required", failures)
    require(
        "--phase mesh" in mesh_step
        and "--interval-begin" in mesh_step
        and "--interval-end" in mesh_step
        and "authz_match" in mesh_step,
        "mesh Criterion health probes must snapshot /proc/stat around each selected bench",
        failures,
    )
    for body, label, harness, forbidden_cd in (
        (
            hbone_step,
            "HBONE",
            "./tests/performance/mesh-hbone-e2e/run.sh",
            "cd tests/performance/mesh-hbone-e2e",
        ),
        (
            dns_step,
            "DNS",
            "./tests/performance/mesh-dns-e2e/run.sh",
            "cd tests/performance/mesh-dns-e2e",
        ),
    ):
        begin = body.find("--interval-begin")
        run = body.find(harness)
        end = body.find("--interval-end")
        require(
            begin != -1 and run != -1 and end != -1 and begin < run < end,
            f"{label} health probes must snapshot /proc/stat around the workload interval",
            failures,
        )
        require(
            forbidden_cd not in body,
            f"{label} collection must invoke the harness by repository-root path "
            "without changing directory",
            failures,
        )
        require(
            "harness_status" in body and "PIPESTATUS" in body,
            f"{label} must preserve harness exit status around interval-end",
            failures,
        )
        require(
            "set +e" in body,
            f"{label} must attempt interval-end even when the harness exits nonzero",
            failures,
        )
        require(
            "MESH_BASELINE_DIAG_DIR" in body,
            f"{label} must set MESH_BASELINE_DIAG_DIR so failure logs upload",
            failures,
        )


def _named_step(text: str, name: str) -> str:
    """Return the workflow step body starting at `- name: {name}`."""
    marker = f"- name: {name}"
    start = text.find(marker)
    if start == -1:
        return ""
    next_step = text.find("\n      - name:", start + len(marker))
    if next_step == -1:
        return text[start:]
    return text[start:next_step]


def _workflow_inputs_block(text: str) -> str:
    """Return concatenated workflow_dispatch + workflow_call inputs sections."""
    blocks: list[str] = []
    for trigger in ("workflow_dispatch:", "workflow_call:"):
        start = text.find(trigger)
        if start == -1:
            continue
        # Capture until permissions/concurrency/env/jobs at top level-ish.
        chunk = text[start : start + 1200]
        blocks.append(chunk)
    return "\n".join(blocks)


def check_scripts(failures: list[str]) -> None:
    require(PROVENANCE_SCRIPT.is_file(), "provenance script missing", failures)
    require(SUMMARY_SCRIPT.is_file(), "summary script missing", failures)
    require(WORKFLOW_PATH.is_file(), "workflow missing", failures)

    require(LEDGER_SCRIPT.is_file(), "suite command ledger script missing", failures)
    require(HEALTH_SCRIPT.is_file(), "runner health script missing", failures)
    require(STEP_SUMMARY_SCRIPT.is_file(), "step summary script missing", failures)

    provenance = PROVENANCE_SCRIPT.read_text(encoding="utf-8")
    require("ubuntu-24.04" in provenance, "provenance default runner class must be ubuntu-24.04", failures)
    require("::error::suite command ledger" in provenance, "provenance must fail closed on malformed suite ledgers", failures)
    require("::error::BENCH_ITERATIONS" in provenance, "provenance must fail closed on malformed BENCH_ITERATIONS", failures)
    require(
        'int(os.environ.get("BENCH_ITERATIONS"' not in provenance,
        "provenance must not unguardedly convert BENCH_ITERATIONS",
        failures,
    )

    ledger = LEDGER_SCRIPT.read_text(encoding="utf-8")
    require(
        'SUPPORTED_SUITES = ("all", "mesh", "hbone", "dns")' in ledger,
        "ledger suite allowlist must be all|mesh|hbone|dns",
        failures,
    )
    require(
        "BENCH_ITERATIONS must be an integer from 3 to 5" in ledger,
        "ledger must reject E2E repetition counts outside 3..5",
        failures,
    )
    require(
        "1kib_c50_30s" in ledger and "16kib_c50_30s" in ledger and "256kib_c100_60s" in ledger,
        "ledger HBONE scenarios incomplete",
        failures,
    )
    require(
        all(bench in ledger for bench in ("authz_match", "ip_restriction", "slice_apply", "xds_translation")),
        "ledger mesh benches incomplete",
        failures,
    )
    require(
        "./tests/performance/mesh-hbone-e2e/run.sh" in ledger,
        "ledger HBONE commands must invoke the harness by repository-root path",
        failures,
    )
    require(
        "cargo build --release --example hbone_perf_fixture" in ledger,
        "ledger HBONE commands must build the trusted fixture example",
        failures,
    )
    require(
        "./tests/performance/mesh-dns-e2e/run.sh" in ledger,
        "ledger DNS commands must invoke the harness by repository-root path",
        failures,
    )

    health = HEALTH_SCRIPT.read_text(encoding="utf-8")
    require("runner_health.json" in health, "machine-readable runner_health.json required", failures)
    require("runner_health.log" in health, "runner_health.log audit trail required", failures)
    require("runner_health_probes.jsonl" in health, "per-E2E runner health probes required", failures)
    require(
        "BENCH_MAX_CPU_STEAL_PERCENT" in health,
        "runner health script must honour the documented steal threshold",
        failures,
    )
    require(
        '["vmstat", "1", "6"]' in health,
        "pre-collection runner health sampling must use a literal vmstat command vector",
        failures,
    )
    require(
        '["vmstat", "1", "3"]' not in health,
        "E2E probes must not use a short pre-run vmstat sample",
        failures,
    )
    require("/proc/stat" in health, "E2E interval probes must snapshot /proc/stat", failures)
    require(
        "interval-begin" in health and "interval-end" in health,
        "interval probes must expose begin/end snapshots",
        failures,
    )
    require('"mesh"' in health or "mesh" in health, "runner health script must accept mesh Criterion probes", failures)
    require("--self-test" in health, "runner health script must provide hosted self-tests", failures)
    require(
        "parse failure cannot become healthy evidence" in health,
        "runner health self-test must prove parse failure cannot become healthy evidence",
        failures,
    )
    require(
        "successful exact-interval evidence" in health,
        "runner health self-test must cover successful exact-interval evidence",
        failures,
    )
    require(
        "end-without-start" in health,
        "runner health self-test must cover end-without-start evidence",
        failures,
    )
    require("excessive steal" in health, "runner health self-test must cover excessive steal", failures)
    require(
        "return 0.0" not in health,
        "runner health parse failure must not return 0.0 as a healthy steal sample",
        failures,
    )
    require("check=True" not in health, "runner health must not use uncaught check=True subprocess failures", failures)
    require("::error::" in health, "runner health vmstat failures must emit controlled ::error:: diagnostics", failures)

    summary = SUMMARY_SCRIPT.read_text(encoding="utf-8")
    require("repetition_evidence" in summary, "summarizer must expose repetition_evidence", failures)
    require("MAX_CPU_STEAL_PERCENT" in summary, "summarizer must document steal threshold", failures)
    require("DNS_GATEWAY_ROWS" in summary, "summarizer must enumerate required DNS gateway rows", failures)
    require("--check-acceptance" in summary, "summarizer must support acceptance check", failures)
    require("undersampling" in summary or "one gateway" in summary, "summarizer self-test must cover undersampling", failures)
    require("SUPPORTED_SUITES" in summary, "summarizer must define SUPPORTED_SUITES", failures)
    require("suites_supported" in summary, "summarizer must gate on suites_supported", failures)
    require("expected_run_paths" in summary, "summarizer must count distinct expected run files", failures)
    require("unexpected_run_paths" in summary, "summarizer must reject extra or misnumbered run files", failures)
    require("classify_dns_target" in summary, "summarizer must classify DNS targets fail-closed", failures)
    require("duplicate relevant blobs" in summary, "summarizer self-test must cover duplicate blobs", failures)
    require("malformed relevant blobs alongside" in summary, "summarizer self-test must cover malformed mixed runs", failures)
    require("missing counterpart" in summary, "summarizer self-test must cover missing counterpart data", failures)
    require("unexpected DNS target" in summary, "summarizer self-test must cover unexpected DNS targets", failures)
    require("unsupported suite selection" in summary, "summarizer self-test must cover invalid suites", failures)
    require("shape_failures" in summary, "summarizer must track per-run shape failures", failures)
    require("provenance_complete" in summary, "summarizer must gate incomplete provenance", failures)
    require("expected_health_probe_ids" in summary, "summarizer must gate every selected-suite health probe", failures)
    require("MESH_BENCHES" in summary, "summarizer must enumerate mesh Criterion benches", failures)
    require('("mesh", bench, 1)' in summary, "summarizer must require mesh Criterion interval probe IDs", failures)
    require("total_nxdomain" in summary, "summarizer must parse DNS NXDOMAIN counts", failures)
    require("total_nxdomain_sum" in summary, "summarizer must aggregate DNS NXDOMAIN counts", failures)
    require("nonzero NXDOMAIN" in summary, "summarizer self-test must cover NXDOMAIN fail-closed behavior", failures)
    require("dns_nxdomain_partial" in summary, "summarizer self-test must cover partial NXDOMAIN", failures)
    require("dns_nxdomain_all" in summary, "summarizer self-test must cover all-NXDOMAIN", failures)
    require("mesh Criterion windows require" in summary, "summarizer self-test must require mesh interval evidence", failures)
    require("workload_interval" in summary, "summarizer must require workload-interval probe coverage", failures)
    require(
        "successful exact-interval evidence" in summary,
        "summarizer self-test must cover successful exact-interval evidence",
        failures,
    )
    require(
        "parse failure cannot become healthy evidence" in summary,
        "summarizer self-test must prove parse failure cannot become healthy evidence",
        failures,
    )
    require(
        "end-without-start" in summary,
        "summarizer self-test must cover end-without-start evidence",
        failures,
    )
    require(
        "excessive steal" in summary,
        "summarizer self-test must cover excessive steal",
        failures,
    )
    require("payload_size" in summary, "summarizer must validate HBONE scenario parameters", failures)
    require("DNS_DURATION_SECS" in summary, "summarizer must validate DNS scenario parameters", failures)

    hbone_run = HBONE_RUN.read_text(encoding="utf-8")
    dns_run = (REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "run.sh").read_text(encoding="utf-8")
    require("MESH_BASELINE_DIAG_DIR" in hbone_run, "HBONE harness must honour MESH_BASELINE_DIAG_DIR", failures)
    require("MESH_BASELINE_DIAG_DIR" in dns_run, "DNS harness must honour MESH_BASELINE_DIAG_DIR", failures)
    require(
        "FERRUM_MESH_ALLOW_NO_CA=true" in dns_run,
        "DNS harness start_gateway() must set benchmark-only FERRUM_MESH_ALLOW_NO_CA=true",
        failures,
    )
    require("archive_failure_diagnostics" in hbone_run, "HBONE harness must copy logs before deleting runtime", failures)
    require("archive_failure_diagnostics" in dns_run, "DNS harness must copy logs into the artifact destination", failures)
    require("certs" in hbone_run and "Never copy certs" in hbone_run, "HBONE diagnostics must not archive certs", failures)
    _check_hbone_backend_allow_ips(hbone_run, failures)
    _check_hbone_trusted_fixture_contract(
        hbone_run,
        HBONE_FIXTURE.read_text(encoding="utf-8") if HBONE_FIXTURE.is_file() else "",
        ROOT_CARGO_TOML.read_text(encoding="utf-8"),
        WORKFLOW_PATH.read_text(encoding="utf-8"),
        ledger,
        failures,
    )

    hbone_loadgen = HBONE_LOADGEN.read_text(encoding="utf-8")
    dns_loadgen = DNS_LOADGEN.read_text(encoding="utf-8")
    require(
        "worker_join_failed" in hbone_loadgen
        and "one or more HBONE load-generator workers failed" in hbone_loadgen,
        "HBONE load-generator worker join failures must fail the collection",
        failures,
    )
    require(
        "worker_join_failed" in dns_loadgen
        and "one or more DNS load-generator workers failed" in dns_loadgen,
        "DNS load-generator worker join failures must fail the collection",
        failures,
    )
    check_dns_tcp_stub_and_fail_closed(
        DNS_UPSTREAM_STUB.read_text(encoding="utf-8") if DNS_UPSTREAM_STUB.is_file() else "",
        DNS_UPSTREAM_STUB_LIB.read_text(encoding="utf-8") if DNS_UPSTREAM_STUB_LIB.is_file() else "",
        dns_loadgen,
        DNS_METRICS.read_text(encoding="utf-8") if DNS_METRICS.is_file() else "",
        DNS_WIRE.read_text(encoding="utf-8") if DNS_WIRE.is_file() else "",
        dns_run,
        DNS_README.read_text(encoding="utf-8") if DNS_README.is_file() else "",
        DNS_HARNESS_TESTS.read_text(encoding="utf-8") if DNS_HARNESS_TESTS.is_file() else "",
        failures,
    )


def check_dns_tcp_stub_and_fail_closed(
    stub_bin: str,
    stub_lib: str,
    loadgen: str,
    metrics: str,
    dns_wire: str,
    dns_run: str,
    readme: str,
    harness_tests: str,
    failures: list[str],
) -> None:
    """Reject UDP-only stubs, missing TCP framing, and false-success loadgen runs."""
    stub = stub_bin + "\n" + stub_lib
    require("TcpListener" in stub, "dns_upstream_stub must bind TcpListener", failures)
    require("UdpSocket" in stub, "dns_upstream_stub must preserve UDP", failures)
    require("run_tcp_accept_loop" in stub, "dns_upstream_stub must accept TCP connections", failures)
    require("handle_tcp_connection" in stub, "dns_upstream_stub must loop per TCP connection", failures)
    require("read_exact" in stub_lib, "TCP DNS stub must complete length and payload reads", failures)
    require("write_all" in stub_lib, "TCP DNS stub must complete framed writes", failures)
    require(
        "decode_tcp_dns_length" in stub_lib and "decode_tcp_dns_length" in dns_wire,
        "TCP DNS stub must use two-byte length framing",
        failures,
    )
    require(
        "EmptyLength" in dns_wire and "unframe_from_tcp" in dns_wire,
        "TCP DNS framing must reject empty/incomplete prefixes",
        failures,
    )
    require(
        "truncated TCP DNS length prefix" in stub_lib
        and "tcp_stub_rejects_truncated_length_prefix" in harness_tests,
        "TCP DNS stub must reject a one-byte truncated length prefix",
        failures,
    )
    require(
        "UDP+TCP listening" in stub_bin,
        "dns_upstream_stub must advertise UDP+TCP on the configured address",
        failures,
    )
    require(
        "selected_reports_failure" in metrics and "selected_reports_failure" in loadgen,
        "DNS loadgen must fail closed via selected_reports_failure",
        failures,
    )
    require(
        "selected DNS row" in metrics and "selected_classes" in loadgen,
        "DNS loadgen must require every selected class/transport result row",
        failures,
    )
    require(
        "zero successful queries" in metrics,
        "DNS fail-closed path must surface zero successful queries",
        failures,
    )
    require(
        "query errors" in metrics,
        "DNS fail-closed path must surface nonzero query errors",
        failures,
    )
    require(
        "unexpected NXDOMAIN" in metrics,
        "DNS fail-closed path must surface unexpected NXDOMAIN responses",
        failures,
    )
    require(
        "serde_json::to_string_pretty" in loadgen
        and "selected_reports_failure" in loadgen.split("serde_json::to_string_pretty")[-1],
        "DNS loadgen must emit JSON before failing on errorful rows",
        failures,
    )
    require(
        "set -e" in dns_run and "dns_loadgen" in dns_run,
        "DNS run.sh must keep set -e so loadgen failures skip Run completed successfully",
        failures,
    )
    require(
        "tokio UDP server" not in readme and "──UDP DNS──► dns_upstream_stub" not in readme,
        "DNS README must not describe the upstream stub as UDP-only",
        failures,
    )
    require(
        "UDP+TCP" in readme or "UDP and TCP" in readme or "UDP/TCP" in readme,
        "DNS README must document UDP/TCP upstream-stub support",
        failures,
    )
    require(
        "handle_tcp_connection" in harness_tests
        and "zero successful queries" in harness_tests
        and "EmptyLength" in harness_tests,
        "DNS harness must keep regression tests for TCP framing and fail-closed reports",
        failures,
    )


def check_pr_ci_wiring(failures: list[str]) -> None:
    ci = CI_YML.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^  performance-regression:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        ci,
    )
    body = match.group("body") if match else ""
    require(
        bool(body),
        "performance-regression.yml performance-regression job required for mesh baseline contract host",
        failures,
    )
    require(
        "verify_mesh_performance_baselines_workflow.py --self-test" in body,
        "jobs.performance-regression must self-test the mesh baselines workflow verifier",
        failures,
    )
    require(
        "python3 .github/scripts/verify_mesh_performance_baselines_workflow.py" in body,
        "jobs.performance-regression must run the mesh baselines workflow verifier",
        failures,
    )
    static_idx = ci.find("Verify mesh performance baselines workflow contract")
    detect_idx = ci.find("Detect performance-sensitive changes")
    require(
        static_idx != -1 and detect_idx != -1 and static_idx < detect_idx,
        "performance-regression.yml must run mesh baseline workflow contracts after checkout and "
        "before optional benchmark path gating",
        failures,
    )


def check_baseline_publication_state(
    path: Path,
    text: str,
    suite: str,
    failures: list[str],
) -> None:
    """Accept stage-1 placeholders or require provenance-complete publication.

    Stage 1 deliberately keeps ``_TBD_`` cells until accepted hosted evidence
    exists. Once a document removes every placeholder, it must carry enough
    immutable provenance and suite-specific acceptance evidence to make that
    transition fail closed rather than silently accepting fabricated numbers.
    """
    prefix = f"{path}"
    has_tbd = "_TBD_" in text
    # Stage-1 documents use a ``Publication status`` heading to explain why
    # their cells remain placeholders.  Treat the status as a claim only when
    # its value says Published (with or without the required date); treating the
    # heading itself as a claim makes the documented placeholder state
    # impossible.
    claims_publication = (
        PUBLISHED_BASELINE_STATUS.search(text) is not None
        or PUBLISHED_BASELINE_DATE.search(text) is not None
    )
    if has_tbd:
        require(
            not claims_publication,
            f"{prefix} must not claim publication while stage-1 TBD cells remain",
            failures,
        )
        return

    require(
        PUBLISHED_BASELINE_STATUS.search(text) is not None
        and PUBLISHED_BASELINE_DATE.search(text) is not None,
        f"{prefix} removed stage-1 TBD cells without a dated publication status",
        failures,
    )
    require(
        "issue #3332" in text,
        f"{prefix} published baseline must retain the issue #3332 evidence pointer",
        failures,
    )
    ferrum_shas = set(PUBLISHED_BASELINE_SHA.findall(text))
    artifact_shas = set(PUBLISHED_BASELINE_ARTIFACT.findall(text))
    require(
        bool(ferrum_shas),
        f"{prefix} published baseline must identify the exact 40-character Ferrum SHA",
        failures,
    )
    require(
        PUBLISHED_BASELINE_RUN.search(text) is not None,
        f"{prefix} published baseline must link its GitHub Actions run",
        failures,
    )
    require(
        bool(artifact_shas),
        f"{prefix} published baseline must name its SHA-bound artifact",
        failures,
    )
    require(
        bool(ferrum_shas & artifact_shas),
        f"{prefix} published baseline artifact must be bound to a documented Ferrum SHA",
        failures,
    )
    require(
        PUBLISHED_BASELINE_COLLECTED_AT.search(text) is not None,
        f"{prefix} published baseline must record an RFC3339 UTC collection time",
        failures,
    )
    for token, label in (
        ("runner_health_ok=true", "accepted runner-health gate"),
        ("Raw artifacts", "raw-artifact pointer"),
        ("summary.json", "machine-readable summary"),
        ("provenance.json", "machine-readable provenance"),
        ("max CPU steal", "measured CPU-steal result"),
    ):
        require(
            token in text,
            f"{prefix} published baseline missing {label} ({token})",
            failures,
        )

    suite_tokens = {
        "mesh": ("mesh_complete=true",),
        "hbone": (
            "hbone_complete=true",
            "hbone_errors_ok=true",
            "3 clean repetitions",
            "total_errors=0",
        ),
        "dns": (
            "dns_complete=true",
            "dns_errors_ok=true",
            "3 clean repetitions",
            "total_errors=0",
            "total_nxdomain=0",
        ),
    }
    for token in suite_tokens[suite]:
        require(
            token in text,
            f"{prefix} published {suite} baseline missing accepted evidence ({token})",
            failures,
        )


def check_docs_and_baselines(failures: list[str]) -> None:
    protocol = PROTOCOL_DOC.read_text(encoding="utf-8")
    require("mesh-performance-baselines.yml" in protocol, "protocol_perf_regression.md missing workflow pointer", failures)
    require("#3332" in protocol, "protocol_perf_regression.md must keep #3332 pointer", failures)
    require("ubuntu-24.04" in protocol, "protocol_perf_regression.md must document ubuntu-24.04 pin", failures)
    require(
        "workload-interval" in protocol,
        "protocol_perf_regression.md must describe per-E2E workload-interval steal probes",
        failures,
    )
    require(
        "mesh Criterion" in protocol or "Criterion window" in protocol,
        "protocol_perf_regression.md must document mesh Criterion steal windows",
        failures,
    )

    ci_cd = CI_CD_DOC.read_text(encoding="utf-8")
    require("mesh-performance-baselines.yml" in ci_cd, "ci_cd.md inventory missing workflow row", failures)
    mesh_row = next(
        (line for line in ci_cd.splitlines() if "mesh-performance-baselines.yml" in line),
        "",
    )
    require(
        "workflow_dispatch" in mesh_row,
        "ci_cd.md mesh baselines row must describe workflow_dispatch",
        failures,
    )
    require(
        "workflow_call" in mesh_row,
        "ci_cd.md mesh baselines row must describe workflow_call",
        failures,
    )

    dns_text = DNS_BASELINE.read_text(encoding="utf-8")
    require(
        "acceptance_gate.dns_complete" in dns_text,
        "DNS baseline.md must reference acceptance_gate.dns_complete",
        failures,
    )
    require(
        "acceptance_gate.runner_health_ok" in dns_text,
        "DNS baseline.md must reference acceptance_gate.runner_health_ok",
        failures,
    )
    require(
        "edns" in dns_text.lower() or "EDNS" in dns_text,
        "DNS baseline.md must document the EDNS(0) rerun option",
        failures,
    )
    require(
        "nxdomain" in dns_text.lower(),
        "DNS baseline.md must document NXDOMAIN fail-closed publication",
        failures,
    )
    require(
        "FERRUM_MESH_ALLOW_NO_CA=true" in dns_text,
        "DNS baseline.md must document benchmark-only FERRUM_MESH_ALLOW_NO_CA=true",
        failures,
    )

    for path, suite in (
        (MESH_BASELINE, "mesh"),
        (HBONE_BASELINE, "hbone"),
        (DNS_BASELINE, "dns"),
    ):
        text = path.read_text(encoding="utf-8")
        require("Overhead formula" in text or "overhead formula" in text.lower(), f"{path} missing overhead formula", failures)
        require("Rerun procedure" in text or "rerun procedure" in text.lower(), f"{path} missing rerun procedure", failures)
        require("refresh" in text.lower() or "cadence" in text.lower(), f"{path} missing refresh cadence", failures)
        require("directional" in text.lower(), f"{path} missing directional hardware caveat", failures)
        require("bottleneck" in text.lower(), f"{path} missing bottleneck review note", failures)
        require("ubuntu-24.04" in text, f"{path} must pin runner class ubuntu-24.04", failures)
        check_baseline_publication_state(path, text, suite, failures)
        require("5.0%" in text or "5%" in text, f"{path} must document CPU steal publication threshold", failures)
        require(
            "workload-interval" in text.lower() or "workload interval" in text.lower(),
            f"{path} must document workload-interval steal coverage",
            failures,
        )


def _self_test_hbone_backend_allow_ips(failures: list[str]) -> None:
    """Prove launch-command parsing rejects camouflage and widening."""
    good = """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="private" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
"""
    good_failures: list[str] = []
    _check_hbone_backend_allow_ips(good, good_failures)
    require(not good_failures, "active private assignment must pass", failures)

    cases = (
        (
            """
# FERRUM_BACKEND_ALLOW_IPS="private"
    env \\
        FERRUM_BACKEND_ALLOW_IPS="public" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "comment camouflage",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="both" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "both widening",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="10.0.0.0/8" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "CIDR literal",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="private" \\
        FERRUM_BACKEND_ALLOW_IPS="private" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "duplicate assignment",
        ),
        (
            """
    env \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "missing assignment",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="public" # FERRUM_BACKEND_ALLOW_IPS="private"
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "inline comment camouflage",
        ),
        (
            """
    echo FERRUM_BACKEND_ALLOW_IPS=private
    env \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "echo camouflage",
        ),
        (
            """
    env \\
        NOTFERRUM_BACKEND_ALLOW_IPS=private \\
        FERRUM_BACKEND_ALLOW_IPS="public" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "suffix-name camouflage",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="public" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture FERRUM_BACKEND_ALLOW_IPS=private
""",
            "post-executable camouflage",
        ),
        (
            """
    FERRUM_BACKEND_ALLOW_IPS=private
    env \\
        FERRUM_BACKEND_ALLOW_IPS="public" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "detached good assignment with widened launch",
        ),
        (
            """
    FERRUM_BACKEND_ALLOW_IPS=private
    env \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "detached good assignment with missing launch assignment",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS="$ALLOW_IPS" \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "indirect launch value",
        ),
        (
            """
    env \\
        FERRUM_BACKEND_ALLOW_IPS=$(echo private) \\
        $PROJECT_ROOT/target/release/examples/hbone_perf_fixture
""",
            "command-substitution launch value",
        ),
    )
    for sample, label in cases:
        case_failures: list[str] = []
        _check_hbone_backend_allow_ips(sample, case_failures)
        require(case_failures, f"{label} must be rejected", failures)


def _self_test_hbone_trusted_fixture_contract(failures: list[str]) -> None:
    """Prove a production file-mode launch with reserved mesh tags is rejected."""
    fixture = HBONE_FIXTURE.read_text(encoding="utf-8") if HBONE_FIXTURE.is_file() else ""
    cargo = ROOT_CARGO_TOML.read_text(encoding="utf-8") if ROOT_CARGO_TOML.is_file() else ""
    workflow = "cargo build --release --example hbone_perf_fixture"
    ledger = (
        "cargo build --release --example hbone_perf_fixture && "
        "(cd tests/performance/mesh-hbone-e2e && cargo build --release)\n"
        "cargo build --release --bin ferrum-edge && "
        "(cd tests/performance/mesh-dns-e2e && cargo build --release)\n"
    )
    forged = """
write_gateway_config() {
  cat > gateway.yaml <<EOF
          "mesh.hbone": "true"
EOF
}
    env \\
        FERRUM_MODE=file \\
        FERRUM_FILE_CONFIG_PATH=gateway.yaml \\
        FERRUM_BACKEND_ALLOW_IPS=private \\
        ./target/release/ferrum-edge
"""
    forged_failures: list[str] = []
    _check_hbone_trusted_fixture_contract(
        forged, fixture, cargo, workflow, ledger, forged_failures
    )
    require(
        forged_failures,
        "forged operator file-mode launch with reserved mesh.* tags must be rejected",
        failures,
    )

    prod_launch = """
    env \\
        FERRUM_BACKEND_ALLOW_IPS=private \\
        ./target/release/ferrum-edge
"""
    prod_failures: list[str] = []
    _check_hbone_backend_allow_ips(prod_launch, prod_failures)
    require(
        prod_failures,
        "production ferrum-edge launch must not satisfy the trusted fixture pin",
        failures,
    )


def _self_test_dns_tcp_stub_and_fail_closed(failures: list[str]) -> None:
    """Prove a UDP-only stub and a success-on-errors loadgen are rejected."""
    udp_only_stub = """
use tokio::net::UdpSocket;
let socket = UdpSocket::bind(addr).await?;
eprintln!("[dns_upstream_stub] UDP listening on {addr}");
"""
    forged: list[str] = []
    check_dns_tcp_stub_and_fail_closed(
        udp_only_stub,
        "",
        "println!(Run completed successfully);",
        "pub fn print_text_report() {}",
        "pub fn frame_for_tcp(packet: &[u8]) -> Vec<u8> { vec![] }",
        "set -e\necho Run completed successfully\n",
        "dns_upstream_stub is a 100-line tokio UDP server\n──UDP DNS──► dns_upstream_stub\n",
        "",
        forged,
    )
    require(forged, "UDP-only upstream stub must be rejected", failures)

    if DNS_UPSTREAM_STUB.is_file() and DNS_LOADGEN.is_file() and DNS_HARNESS_TESTS.is_file():
        real: list[str] = []
        check_dns_tcp_stub_and_fail_closed(
            DNS_UPSTREAM_STUB.read_text(encoding="utf-8"),
            DNS_UPSTREAM_STUB_LIB.read_text(encoding="utf-8"),
            DNS_LOADGEN.read_text(encoding="utf-8"),
            DNS_METRICS.read_text(encoding="utf-8"),
            DNS_WIRE.read_text(encoding="utf-8"),
            (REPO_ROOT / "tests" / "performance" / "mesh-dns-e2e" / "run.sh").read_text(
                encoding="utf-8"
            ),
            DNS_README.read_text(encoding="utf-8"),
            DNS_HARNESS_TESTS.read_text(encoding="utf-8"),
            real,
        )
        require(not real, f"real DNS harness must pass tcp/fail-closed contract: {real}", failures)


def _self_test_baseline_publication_state(failures: list[str]) -> None:
    """Prove the stage-1-to-published transition requires accepted evidence."""
    stage1_failures: list[str] = []
    check_baseline_publication_state(
        Path("stage1.md"),
        (
            "**Publication status (issue #3332):** result cells remain _TBD_ "
            "until accepted hosted evidence exists. Directional baseline."
        ),
        "mesh",
        stage1_failures,
    )
    require(not stage1_failures, "plain stage-1 TBD baseline must pass", failures)

    common = """
**Publication status (issue #3332):** Published 2026-08-20 from hosted collection
at Ferrum SHA `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
https://github.com/ferrum-edge/ferrum-edge/actions/runs/123456
artifact `mesh-performance-baselines-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
`runner_health_ok=true`, max CPU steal 0.0%
| Collected at (UTC) | 2026-08-14T16:44:57Z |
| Raw artifacts | summary.json, provenance.json |
"""
    suite_evidence = {
        "mesh": "`mesh_complete=true`",
        "hbone": (
            "`hbone_complete=true`, `hbone_errors_ok=true`, 3 clean repetitions, "
            "`total_errors=0`"
        ),
        "dns": (
            "`dns_complete=true`, `dns_errors_ok=true`, 3 clean repetitions, "
            "`total_errors=0`, `total_nxdomain=0`"
        ),
    }
    for suite, evidence in suite_evidence.items():
        published_failures: list[str] = []
        check_baseline_publication_state(
            Path(f"published-{suite}.md"),
            common + evidence,
            suite,
            published_failures,
        )
        require(
            not published_failures,
            f"provenance-complete published {suite} baseline must pass: {published_failures}",
            failures,
        )

    forged_failures: list[str] = []
    check_baseline_publication_state(
        Path("forged.md"),
        "Published benchmark numbers without hosted evidence",
        "mesh",
        forged_failures,
    )
    require(forged_failures, "published numbers without provenance must fail", failures)

    partial_failures: list[str] = []
    check_baseline_publication_state(
        Path("partial.md"),
        common + "`mesh_complete=true` | _TBD_ |",
        "mesh",
        partial_failures,
    )
    require(partial_failures, "published baseline retaining TBD cells must fail", failures)

    undated_claim_failures: list[str] = []
    check_baseline_publication_state(
        Path("undated-claim.md"),
        "**Publication status:** Published from hosted evidence | _TBD_ |",
        "mesh",
        undated_claim_failures,
    )
    require(
        undated_claim_failures,
        "undated publication claim retaining TBD cells must fail",
        failures,
    )


def self_test() -> int:
    sample = """
name: Mesh Performance Baselines
on:
  workflow_dispatch:
    inputs:
      suites:
        default: "all"
      iterations:
        default: "3"
  workflow_call:
    inputs:
      suites:
        default: "all"
        type: string
      iterations:
        default: "3"
        type: string
permissions:
  contents: read
concurrency:
  group: mesh-performance-baselines-ref
  cancel-in-progress: false
env:
  BENCH_BUILD_PROFILE: release
  BENCH_RUNNER_CLASS: ubuntu-24.04
  BENCH_MAX_CPU_STEAL_PERCENT: "5.0"
jobs:
  collect:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: ./.github/actions/setup-rust-ci
      - run: sudo apt-get install -y protobuf-compiler lsof curl
      - run: authz_match ip_restriction slice_apply xds_translation
      - run: 1kib_c50_30s 16kib_c50_30s 256kib_c100_60s
      - run: ./tests/performance/mesh-hbone-e2e/run.sh --duration 60 --concurrency 100
      - run: collect_mesh_baseline_provenance.py
      - run: summarize_mesh_baseline_results.py
      - run: runner_health.json runner_health_probes.jsonl
      - run: python3 .github/scripts/mesh_baseline_runner_health.py --self-test
      - run: python3 .github/scripts/mesh_baseline_runner_health.py --phase pre_collection
      - run: |
          case "${SUITES}" in
            all|mesh|hbone|dns) ;;
            *)
              echo "::error::unsupported suites value"
              exit 1
              ;;
          esac
          if [[ ! "${ITERATIONS}" =~ ^[0-9]+$ ]] || ((ITERATIONS < 3 || ITERATIONS > 5)); then
            echo "::error::BENCH_ITERATIONS must be an integer from 3 to 5"
            exit 1
          fi
      - name: Collect mesh Criterion microbenchmarks
        run: |
          python3 .github/scripts/mesh_baseline_runner_health.py --phase mesh --interval-begin
          set +e
          cargo bench --bench authz_match
          harness_status=${PIPESTATUS[0]}
          python3 .github/scripts/mesh_baseline_runner_health.py --phase mesh --interval-end
      - name: Collect HBONE E2E baselines (3+ repetitions)
        run: |
          python3 .github/scripts/mesh_baseline_runner_health.py --interval-begin
          set +e
          export MESH_BASELINE_DIAG_DIR=mesh-baseline-results/logs/hbone/run_1
          ./tests/performance/mesh-hbone-e2e/run.sh --duration 60 --concurrency 100
          harness_status=${PIPESTATUS[0]}
          python3 .github/scripts/mesh_baseline_runner_health.py --interval-end
      - name: Collect DNS E2E baselines (3+ repetitions)
        run: |
          python3 .github/scripts/mesh_baseline_runner_health.py --interval-begin
          set +e
          export MESH_BASELINE_DIAG_DIR=mesh-baseline-results/logs/dns/run_1
          ./tests/performance/mesh-dns-e2e/run.sh --duration 60 --concurrency 100
          harness_status=${PIPESTATUS[0]}
          python3 .github/scripts/mesh_baseline_runner_health.py --interval-end
      - name: Enforce selected-suite acceptance gates
        if: always()
        run: --check-acceptance
      - name: Upload mesh baseline artifacts
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: mesh-performance-baselines-${{ github.sha }}
"""
    failures: list[str] = []
    check_workflow(sample, failures)
    _self_test_hbone_backend_allow_ips(failures)
    _self_test_hbone_trusted_fixture_contract(failures)
    _self_test_dns_tcp_stub_and_fail_closed(failures)
    _self_test_baseline_publication_state(failures)
    # Intentionally skip repository docs checks in self-test; the publication
    # state machine above is exercised with isolated fixtures.
    if failures:
        print("self-test failures:", *failures, sep="\n- ")
        return 1
    print("verify_mesh_performance_baselines_workflow self-test passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()

    failures: list[str] = []
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    check_workflow(text, failures)
    check_scripts(failures)
    check_docs_and_baselines(failures)
    check_pr_ci_wiring(failures)
    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        return 1
    print("Mesh performance baselines workflow contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
