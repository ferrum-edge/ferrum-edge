#!/usr/bin/env python3
"""Regression checks for manual version selection and the CI/release boundary."""

from pathlib import Path
import unittest

from validate_release_request import validate
from verify_publication_gate import job_body, _parse_job, _scalar, _sequence, _mapping


class ReleaseRequestTests(unittest.TestCase):
    def test_stable_version_matches_exact_checkout(self):
        validate("v1.2.3", "1.2.3", "refs/heads/main", "a" * 40, "a" * 40)

    def test_rejects_unsafe_or_inconsistent_requests(self):
        for version in ("", "1.2.3", "v1.2.3\n", "v01.2.3", "v1.2.3-rc.1",
                        "v1.2.3+build", "v1.2.3;echo bad", "refs/tags/v1.2.3"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                validate(version, "1.2.3", "refs/heads/main", "a" * 40, "a" * 40)
        for package, ref, sha, head in (
            ("1.2.4", "refs/heads/main", "a" * 40, "a" * 40),
            ("1.2.3", "refs/heads/topic", "a" * 40, "a" * 40),
            ("1.2.3", "refs/tags/v1.2.3", "a" * 40, "a" * 40),
            ("1.2.3", "refs/heads/main", "a" * 40, "b" * 40),
            ("1.2.3", "refs/heads/main", "main", "main"),
        ):
            with self.subTest(ref=ref, package=package), self.assertRaises(ValueError):
                validate("v1.2.3", package, ref, sha, head)

    def test_tag_write_waits_for_read_only_validation(self):
        workflow = Path(".github/workflows/release-dispatch.yml").read_text()
        create = _parse_job(job_body(workflow, "create-tag"))
        self.assertEqual(_scalar(create, "needs"), "validate")
        self.assertNotIn("if", create)
        self.assertNotIn("continue-on-error", create)
        validation = _parse_job(job_body(workflow, "validate"))
        permissions = _mapping(validation, "permissions")
        self.assertEqual({key: _scalar(permissions, key) for key in permissions},
                         {"contents": "read", "actions": "read", "checks": "read"})
        steps = _sequence(validation, "steps")
        scripts = [step["run"][1] for step in steps if "run" in step]
        self.assertTrue(any("validate_release_request.py" in run for run in scripts))
        self.assertTrue(any("--enforce release --deadline-seconds 9600" in run for run in scripts))
        # A tag token must never be persisted into a source checkout.
        self.assertNotIn("actions/checkout", job_body(workflow, "create-tag"))
        self.assertNotIn("${{ secrets.RELEASE_TAG_TOKEN }}", job_body(workflow, "validate"))

    def test_ci_and_production_build_profiles(self):
        ci = Path(".github/workflows/ci.yml").read_text()
        self.assertNotIn("--release", job_body(ci, "build-binaries"))
        image_body = job_body(ci, "main-linux-image")
        self.assertIn("    needs: [test, build-test-artifacts]\n", image_body)
        image = _parse_job(image_body.replace("    needs: [test, build-test-artifacts]\n", ""))
        self.assertEqual(_scalar(image, "if"), "github.event_name == 'push' && github.ref == 'refs/heads/main'")
        for filename in ("ambient-host-udp-live.yml", "node-waypoint-ebpf-live.yml"):
            text = Path(".github/workflows", filename).read_text()
            # Every Dockerfile runtime smoke invocation explicitly selects the
            # fast userspace profile, including cold/fork/exact-hit paths.
            for block in text.split("          target: runtime")[1:]:
                self.assertIn("CARGO_PROFILE=pr-build", block.split("\n      - ")[0])
        dockerfile = Path("Dockerfile").read_text()
        self.assertEqual(dockerfile.count("ARG CARGO_PROFILE=release"), 1)
        self.assertIn('"target/${CARGO_PROFILE}/ferrum-edge" "target/${CARGO_PROFILE}/ferrum-cni" /build/', dockerfile)
        self.assertNotIn("/build/target/release/ferrum-", dockerfile)
        release = Path(".github/workflows/release.yml").read_text()
        self.assertNotIn("CARGO_PROFILE=pr-build", release)
        self.assertIn("--features cloud-secrets --release", release)
        self.assertIn("LINUX_GNU_PROFILE: release", release)


def run_self_test() -> list[str]:
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(ReleaseRequestTests).run(result)
    return [trace for _, trace in result.failures + result.errors]


if __name__ == "__main__":
    unittest.main()
