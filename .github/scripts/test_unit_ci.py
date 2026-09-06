#!/usr/bin/env python3
"""ACME target/selection regressions, executed by verify_required_ci in CI."""

from __future__ import annotations

import io
import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from run_unit_ci import MINIMUM_PASSED, REQUIRED_TESTS, main, validate_output, validate_usage


COMMANDS = {
    "default-build": "cargo test --lib --test unit_tests --no-run",
    "default-lib": "cargo test --lib",
    "default-unit": "cargo test --test unit_tests",
    "acme-build": "cargo test --features acme --lib --test acme_dns01_tests --no-run",
    "acme-outbound": "cargo test --features acme --lib tls::acme::client::tests",
    "acme-dns": "cargo test --features acme --test acme_dns01_tests",
    "acme-renewal": "cargo test --features acme --lib tls::acme_renewal_resume_tests",
}

STEPS = {
    "default-build": "Precompile inline and hardening test binaries",
    "default-lib": "Run inline lib tests",
    "default-unit": "Run unit tests",
    "acme-build": "Precompile ACME library and DNS hook test binaries",
    "acme-outbound": "Run ACME outbound-boundary regressions",
    "acme-dns": "Run ACME DNS-01 hook cancellation regressions",
    "acme-renewal": "Run ACME renewal crash-recovery regressions",
}


def contract_errors(workflow: str, manifest: str, tls_modules: str) -> list[str]:
    errors = []
    job = re.search(r"(?ms)^  test-unit:\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow)
    if job is None:
        return ["missing test-unit job"]
    # These steps have a deliberately small, literal shape. Comments cannot
    # satisfy a command, and conditions/continue-on-error/extra shell fail closed.
    steps = re.split(r"(?m)^(?=      - )", job[1])
    last_position = -1
    for phase, name in STEPS.items():
        candidates = [step for step in steps if step.startswith(f"      - name: {name}\n")]
        expected = [
            f"- name: {name}",
            "run: |",
            "set -euo pipefail",
            'mkdir -p "$RUNNER_TEMP/unit-ci"',
            f"/usr/bin/time --format='wall_seconds=%e max_child_rss_kib=%M exit_status=%x' "
            f'--output="$RUNNER_TEMP/unit-ci/{phase}.time" {COMMANDS[phase]} '
            f'2>&1 | tee "$RUNNER_TEMP/unit-ci/{phase}.log"',
            f"python3 .github/scripts/run_unit_ci.py {phase}",
            "env:",
            "RUST_BACKTRACE: 1",
        ]
        if len(candidates) != 1 or [
            line.strip() for line in candidates[0].splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ] != expected:
            errors.append(f"test-unit must run the unconditional, fail-closed {phase} command")
        position = job[1].find(f"      - name: {name}\n")
        if position <= last_position:
            errors.append(f"test-unit phase missing or out of order: {phase}")
        last_position = position
    executable = "\n".join(line for line in job[1].splitlines() if not line.lstrip().startswith("#"))
    if re.search(r"cargo test[^\n]*--features acme[^\n]*--test unit_tests", executable):
        errors.append("ACME must not recompile the monolithic unit_tests target")
    try:
        cargo = tomllib.loads(manifest)
        targets = [target for target in cargo.get("test", []) if target.get("name") == "acme_dns01_tests"]
        if targets != [{
            "name": "acme_dns01_tests",
            "path": "tests/acme_dns01/mod.rs",
            "required-features": ["acme"],
        }]:
            errors.append("ACME DNS must have its own explicit required-features libtest target")
        if cargo.get("package", {}).get("autotests", True) is not True:
            errors.append("default test auto-discovery must remain enabled")
        if "acme" in cargo.get("features", {}).get("default", []):
            errors.append("ACME must remain optional")
    except (tomllib.TOMLDecodeError, TypeError, AttributeError) as error:
        errors.append(f"invalid Cargo target graph: {error}")
    if "acme_dns01" in tls_modules:
        errors.append("DNS hook tests must not remain linked into unit_tests")
    return errors


def check_repository() -> list[str]:
    return contract_errors(
        Path(".github/workflows/ci.yml").read_text(),
        Path("Cargo.toml").read_text(),
        Path("tests/unit/tls/mod.rs").read_text(),
    )


def output_for(phase: str, *, passed: int | None = None, ignored: int = 0, filtered: int = 0) -> str:
    names = REQUIRED_TESTS.get(phase, set())
    count = MINIMUM_PASSED[phase] if passed is None else passed
    return "\n".join(f"test {name} ... ok" for name in sorted(names)) + (
        f"\ntest result: ok. {count} passed; 0 failed; {ignored} ignored; "
        f"0 measured; {filtered} filtered out; finished in 0.10s\n"
    )


class SelectionTests(unittest.TestCase):
    def test_every_existing_acme_test_is_required(self):
        self.assertEqual({key: len(value) for key, value in REQUIRED_TESTS.items()}, {
            "acme-outbound": 20, "acme-dns": 2, "acme-renewal": 16,
        })
        for phase in MINIMUM_PASSED:
            validate_output(phase, output_for(phase))
            validate_output(phase, output_for(phase, passed=MINIMUM_PASSED[phase] + 1))

    def test_missing_empty_failed_or_duplicate_summary_is_rejected(self):
        for phase in MINIMUM_PASSED:
            for output in ("", output_for(phase, passed=0), output_for(phase, passed=MINIMUM_PASSED[phase] - 1),
                           output_for(phase).replace("0 failed", "1 failed"), output_for(phase) * 2):
                with self.subTest(phase=phase, output=output), self.assertRaises(ValueError):
                    validate_output(phase, output)

    def test_each_missing_named_assertion_fails_even_with_same_total(self):
        for phase, names in REQUIRED_TESTS.items():
            for name in names:
                with self.subTest(phase=phase, name=name), self.assertRaises(ValueError):
                    validate_output(phase, output_for(phase).replace(f"test {name} ... ok", "test unrelated ... ok"))

    def test_ignored_and_filtered_selections_fail_closed(self):
        for phase in MINIMUM_PASSED:
            if phase != "default-lib":
                with self.subTest(phase=phase), self.assertRaises(ValueError):
                    validate_output(phase, output_for(phase, ignored=1))
        validate_output("default-lib", output_for("default-lib", ignored=10))
        for phase in ("default-lib", "default-unit", "acme-dns"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                validate_output(phase, output_for(phase, filtered=1))


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.workflow = Path(".github/workflows/ci.yml").read_text()
        self.manifest = Path("Cargo.toml").read_text()
        self.modules = Path("tests/unit/tls/mod.rs").read_text()

    def check(self, workflow=None, manifest=None, modules=None):
        return contract_errors(
            self.workflow if workflow is None else workflow,
            self.manifest if manifest is None else manifest,
            self.modules if modules is None else modules,
        )

    def test_repository_contract(self):
        self.assertEqual(self.check(), [])

    def test_missing_disabled_or_masked_commands_are_rejected(self):
        for phase, name in STEPS.items():
            reporter = f"python3 .github/scripts/run_unit_ci.py {phase}"
            for before, after in (
                (reporter, "# " + reporter),
                (reporter, reporter + " || true"),
                (reporter, reporter + "\n        if: false"),
                (reporter, reporter + "\n        continue-on-error: true"),
                (COMMANDS[phase], "echo " + COMMANDS[phase]),
                (f'{phase}.time"', 'wrong-phase.time"'),
                (f'{phase}.log"', f'{phase}.log" || true'),
                (f'{phase}.log"', 'wrong-phase.log"'),
            ):
                with self.subTest(phase=phase, replacement=after):
                    self.assertTrue(self.check(workflow=self.workflow.replace(before, after)))
            self.assertTrue(self.check(workflow=self.workflow.replace(f"- name: {name}", "- name: Removed", 1)))

    def test_pipeline_failure_guards_and_timing_cannot_be_removed(self):
        for before, after in (
            ("set -euo pipefail", "set -eu"),
            ("set -euo pipefail", "set -uo pipefail"),
            ("set -euo pipefail", "set -euo pipefail; set +e"),
            ("2>&1 | tee", "2>&1 || tee"),
            ("/usr/bin/time --format=", "echo --format="),
            ("exit_status=%x", "exit_status=0"),
        ):
            with self.subTest(replacement=after):
                self.assertTrue(self.check(workflow=self.workflow.replace(before, after)))

    def test_monolith_rebuild_missing_target_or_feature_gate_are_rejected(self):
        self.assertTrue(self.check(workflow=self.workflow.replace("--test acme_dns01_tests", "--test unit_tests")))
        for before, after in (
            ('required-features = ["acme"]', 'required-features = []'),
            ('name = "acme_dns01_tests"', 'name = "missing_tests"'),
            ('path = "tests/acme_dns01/mod.rs"', 'path = "tests/unit_tests.rs"'),
            ('default = ["crypto-ring"]', 'default = ["crypto-ring", "acme"]'),
            ('[package]', '[package]\nautotests = false'),
        ):
            with self.subTest(before=before):
                self.assertTrue(self.check(manifest=self.manifest.replace(before, after, 1)))
        self.assertTrue(self.check(modules=self.modules + "mod acme_dns01_hook_tests;\n"))


class ReportTests(unittest.TestCase):
    def test_missing_proof_and_failed_commands_cannot_turn_green(self):
        success = "wall_seconds=1.25 max_child_rss_kib=2048 exit_status=0\n"
        for phase in ("acme-dns", "acme-build"):
            for usage, output, expected in (
                (success, output_for("acme-dns"), 0),
                (success.replace("exit_status=0", "exit_status=42"), output_for("acme-dns"), 1),
                ("Command terminated by signal 15\n" + success, output_for("acme-dns"), 1),
                ("", output_for("acme-dns"), 1),
                (None, output_for("acme-dns"), 1),
                (success, None, 1),
                (success, "", 0 if phase.endswith("-build") else 1),
            ):
                with self.subTest(phase=phase, usage=usage, output=output), tempfile.TemporaryDirectory() as root:
                    logs = Path(root) / "unit-ci"
                    logs.mkdir()
                    if usage is not None:
                        (logs / f"{phase}.time").write_text(usage)
                    if output is not None:
                        (logs / f"{phase}.log").write_text(output)
                    summary = Path(root) / "summary.md"
                    with (
                        patch.dict("os.environ", {"RUNNER_TEMP": root, "GITHUB_STEP_SUMMARY": str(summary)}),
                        patch("sys.argv", ["run_unit_ci.py", phase]),
                        patch("sys.stdout", new_callable=io.StringIO),
                        patch("sys.stderr", new_callable=io.StringIO),
                    ):
                        self.assertEqual(main(), expected)
                    self.assertEqual(summary.exists(), expected == 0)
                    if expected == 0:
                        self.assertIn("1.25s; maximum child RSS: 2048 KiB", summary.read_text())
                        self.assertIn("precompile" if phase.endswith("-build") else "2 passed", summary.read_text())

    def test_malformed_or_duplicate_telemetry_is_rejected(self):
        success = "wall_seconds=1.25 max_child_rss_kib=2048 exit_status=0\n"
        for usage in (success * 2, success.replace("1.25", "nan"), success.replace("2048", "-1"),
                      success.replace(" exit_status=0", "")):
            with self.subTest(usage=usage), self.assertRaises(ValueError):
                validate_usage("acme-dns", usage)


class PipelineTests(unittest.TestCase):
    # These literal shell fixtures execute only in remote CI, never Cargo.
    # ContractTests separately pin every workflow to this pipeline shape.
    def test_command_failure_is_fatal_even_when_tee_succeeds(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                ["bash", "-c", """set -euo pipefail
/usr/bin/time --format='wall_seconds=%e max_child_rss_kib=%M exit_status=%x' --output=phase.time bash -c 'echo command-output; exit 42' 2>&1 | tee phase.log
echo reporter-ran > reporter.marker
"""],
                cwd=root, capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 42)
            self.assertIn("command-output", (Path(root) / "phase.log").read_text())
            self.assertFalse((Path(root) / "reporter.marker").exists())

    def test_tee_failure_is_fatal_even_when_command_succeeds(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                ["bash", "-c", """set -euo pipefail
/usr/bin/time --format='wall_seconds=%e max_child_rss_kib=%M exit_status=%x' --output=phase.time echo command-output 2>&1 | tee missing-directory/phase.log
echo reporter-ran > reporter.marker
"""],
                cwd=root, capture_output=True, text=True, check=False, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exit_status=0", (Path(root) / "phase.time").read_text())
            self.assertFalse((Path(root) / "reporter.marker").exists())


def self_test() -> list[str]:
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromTestCase(case)
        for case in (SelectionTests, ContractTests, ReportTests, PipelineTests)
    )
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return [] if result.wasSuccessful() else ["unit CI selection/target self-tests failed"]


if __name__ == "__main__":
    raise SystemExit(bool(self_test() or check_repository()))
