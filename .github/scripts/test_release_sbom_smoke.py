#!/usr/bin/env python3
"""Hosted regressions for the actual release jq predicate and failure evidence."""

import ast
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from release_sbom_smoke import HISTORICAL_PREDICATE, describe_spdx, production_contract, run_stage


WORKFLOW = Path(".github/workflows/release.yml").read_text()
VALID = {
    "spdxVersion": "SPDX-2.3",
    "documentNamespace": "https://example.invalid/sbom/test",
    "packages": [{"SPDXID": "SPDXRef-Package", "name": "fixture"}],
    "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT",
                       "relationshipType": "DESCRIBES",
                       "relatedSpdxElement": "SPDXRef-Package"}],
}


class ProductionPredicateTests(unittest.TestCase):
    def validate(self, document, predicate=None):
        if predicate is None:
            _, predicate, _ = production_contract(WORKFLOW)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "require_sbom.jq"
            path.write_text(predicate)
            return subprocess.run(
                ["jq", "-e", "-f", "require_sbom.jq"], cwd=directory,
                input=json.dumps(document),
                text=True, capture_output=True, check=False, timeout=10,
            ).returncode

    def test_accepts_both_spdx_description_encodings(self):
        self.assertEqual(self.validate(VALID), 0)
        direct = copy.deepcopy(VALID)
        del direct["relationships"]
        direct["documentDescribes"] = ["SPDXRef-Package"]
        self.assertEqual(self.validate(direct), 0)

    def test_failed_release_predicate_rejects_syft_relationship_encoding(self):
        historical = HISTORICAL_PREDICATE.read_text()
        self.assertEqual(self.validate(VALID, historical), 1)
        self.assertEqual(self.validate(VALID), 0)
        direct = copy.deepcopy(VALID)
        direct["documentDescribes"] = ["SPDXRef-Package"]
        self.assertEqual(self.validate(direct, historical), 0)

    def test_rejects_missing_empty_and_wrong_type_required_contents(self):
        for key in ("spdxVersion", "documentNamespace", "packages", "relationships"):
            for invalid in (None, "", [], {}):
                document = copy.deepcopy(VALID)
                document[key] = invalid
                with self.subTest(key=key, invalid=invalid):
                    self.assertNotEqual(self.validate(document), 0)
            document = copy.deepcopy(VALID)
            del document[key]
            with self.subTest(missing=key):
                self.assertNotEqual(self.validate(document), 0)

    def test_rejects_wrong_document_relationship(self):
        for key, value in (("spdxElementId", "SPDXRef-Package"),
                           ("relationshipType", "CONTAINS")):
            document = copy.deepcopy(VALID)
            document["relationships"][0][key] = value
            self.assertNotEqual(self.validate(document), 0)

    def test_contract_extraction_fails_closed_on_drift(self):
        for old, new in (
            ("require_sbom.jq", "different.jq"),
            ("anchore/syft@sha256:", "anchore/syft:latest#"),
            ('-o "spdx-json=/out/', '-o "syft-json=/out/'),
            ('--platform "$platform"', '--platform "linux/amd64"'),
            ('--platform "$platform"', '--platform $platform'),
            ('-e SYFT_CHECK_FOR_APP_UPDATE=false', '-e SYFT_CHECK_FOR_APP_UPDATE=true'),
            ('9a9f85314017f1ea798fb012edfa7fe9259923910f82c8d4bc983ab5c765e60b', 'a' * 64),
        ):
            with self.subTest(old=old), self.assertRaises(ValueError):
                production_contract(WORKFLOW.replace(old, new))

    def test_harness_uses_changed_production_predicate(self):
        # A weakened production gate must change the executed regression, not
        # leave a copied test predicate reporting an unrelated green result.
        _, predicate, _ = production_contract(WORKFLOW.replace(
            '.packages | type == "array" and length > 0',
            '.packages | type == "array" and length >= 0',
        ))
        self.assertIn('length >= 0', predicate)

    def test_every_process_command_is_a_literal_argument_list(self):
        # Guard the exact regression rejected by immutable CI Policy without
        # importing, replacing, or relaxing that admission authority.
        for filename in ("release_sbom_smoke.py", "test_release_sbom_smoke.py"):
            tree = ast.parse(Path(".github/scripts", filename).read_text())
            commands = [node.args[0] for node in ast.walk(tree)
                        if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "subprocess"
                        and node.func.attr == "run"]
            self.assertTrue(commands)
            for command in commands:
                with self.subTest(filename=filename, line=command.lineno):
                    argv = ast.literal_eval(command)
                    self.assertIsInstance(argv, list)
                    self.assertTrue(all(isinstance(value, str) for value in argv))


class DiagnosticTests(unittest.TestCase):
    def scanner_environment(self, work, script):
        binary = work / "bin" / "docker"
        binary.parent.mkdir()
        binary.write_text(script)
        binary.chmod(0o700)
        return {"PATH": str(binary.parent) + os.pathsep + os.environ["PATH"],
                "work": str(work), "family": "standard", "registry": "docker",
                "arch": "amd64", "platform": "linux/amd64",
                "image_ref": "example.invalid/fixture@sha256:" + "a" * 64,
                "registry_username": "", "registry_password": ""}

    def setUp(self):
        # Expected failure diagnostics must not create CI error annotations.
        self.output = io.StringIO()
        self.redirect = redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def test_failed_scanner_retains_distinct_status_and_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            output = work / "standard_docker-amd64.spdx.json"
            results = {}
            env = self.scanner_environment(work, '''#!/bin/sh
printf '{"packages":' > "$work/${family}_${registry}-${arch}.spdx.json"
printf 'scanner failed\n' >&2
exit 17
''')
            passed = run_stage("syft-scan", work, env, results)
            self.assertFalse(passed)
            self.assertEqual(json.loads((work / "status.json").read_text())[
                "syft-scan"]["exit_code"], 17)
            self.assertIn("scanner failed", (work / "syft-scan.stderr.txt").read_text())
            self.assertFalse(describe_spdx(output)["json_valid"])
            _, predicate, _ = production_contract(WORKFLOW)
            (work / "require_sbom.jq").write_text(predicate)
            self.assertFalse(run_stage("spdx-validation", work, env, results))
            self.assertNotEqual(results["spdx-validation"]["exit_code"], 0)
            self.assertEqual(results["syft-scan"]["exit_code"], 17)
            output.write_text(json.dumps(VALID))
            self.assertEqual(describe_spdx(output)["document_describes_relationships"], 1)
            self.assertTrue(run_stage("spdx-validation", work, env, results))
            self.assertEqual(results["syft-scan"]["exit_code"], 17)
            self.assertEqual(describe_spdx(work / "missing.json"), {"file_exists": False})

    def test_launch_failure_and_timeout_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            results = {}
            env = self.scanner_environment(work, "#!/bin/sh\nexec sleep 30\n")
            with patch("release_sbom_smoke.subprocess.run", side_effect=FileNotFoundError(2, "fixture")):
                self.assertFalse(run_stage("manifest", work, env, results))
            self.assertEqual(results["manifest"]["status"], "launch_error")
            self.assertFalse(run_stage("syft-scan", work, env, results, timeout=0.05))
            saved = json.loads((work / "status.json").read_text())
            self.assertEqual(saved["syft-scan"]["status"], "timeout")
            self.assertEqual(saved["manifest"]["status"], "launch_error")

    def test_historical_rejection_requires_exit_one_and_cannot_mask_current_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            env = self.scanner_environment(work, "#!/bin/sh\nexit 17\n")
            results = {}
            (work / "standard_docker-amd64.spdx.json").write_text(json.dumps(VALID))
            # A missing predicate is a jq error, never evidence of rejection.
            self.assertFalse(run_stage("historical-spdx-validation", work, env, results,
                                       expected_exit_code=1))
            (work / "historical_require_sbom.jq").write_text(HISTORICAL_PREDICATE.read_text())
            self.assertTrue(run_stage("historical-spdx-validation", work, env, results,
                                      expected_exit_code=1))
            self.assertEqual((work / "historical-spdx-validation.stdout.txt").read_text().strip(), "false")
            for stage in ("syft-scan", "spdx-validation"):
                with self.subTest(stage=stage), self.assertRaises(ValueError):
                    run_stage(stage, work, env, results, expected_exit_code=1)


if __name__ == "__main__":
    unittest.main()
