"""Execute the dispatch skip-input matching in gateways-protocol-benchmark.yml.

The `benchmark` job's `skip_protocols`, `skip_payload_sizes` and
`skip_gateways` inputs are space-separated lists. They used to be matched with
`grep -qw`, which treats `-` as a word boundary, so skipping `udp-dtls` also
skipped the `udp` leg (#7405). These tests run the workflow's own step scripts
under bash with the GitHub expressions substituted, so the shell that ships is
the shell under test.
"""

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
WORKFLOW = REPO_ROOT / ".github/workflows/gateways-protocol-benchmark.yml"
PROTOCOLS = ["http1-tls", "http2", "http3", "grpcs", "wss", "tcp-tls", "udp", "udp-dtls"]
EXPRESSION = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")


def step_script(name):
    """Return the dedented `run: |` body of the benchmark step called `name`."""
    lines = WORKFLOW.read_text().splitlines()
    start = lines.index(f"      - name: {name}")
    run = next(i for i in range(start + 1, len(lines)) if lines[i] == "        run: |")
    body = []
    for line in lines[run + 1:]:
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line)
    return textwrap.dedent("\n".join(body)) + "\n"


def run_step(name, expressions, path_prefix=None):
    """Run a step with its `${{ ... }}` expressions substituted; return outputs."""

    def substitute(match):
        key = match.group(1)
        if key not in expressions:
            raise KeyError(f"step {name!r} uses unexpected expression {key!r}")
        return expressions[key]

    script = EXPRESSION.sub(substitute, step_script(name))
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "github_output"
        output.write_text("")
        env = dict(os.environ, GITHUB_OUTPUT=str(output))
        if path_prefix is not None:
            env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
        result = subprocess.run(["bash", "-e", "-c", script], env=env,
                                capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise AssertionError(f"step {name!r} failed: {result.stderr}")
        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines() if line)
        return outputs, result.stdout


class SkipProtocolTests(unittest.TestCase):
    def skipped(self, skip_list):
        return [protocol for protocol in PROTOCOLS
                if run_step("Skip protocol?", {
                    "inputs.skip_protocols": skip_list,
                    "matrix.protocol": protocol,
                })[0]["skip"] == "true"]

    def test_hyphenated_protocol_does_not_skip_its_prefix(self):
        self.assertEqual(self.skipped("udp-dtls"), ["udp-dtls"])
        self.assertEqual(self.skipped("http1-tls"), ["http1-tls"])
        self.assertEqual(self.skipped("tcp-tls"), ["tcp-tls"])

    def test_prefix_does_not_skip_the_hyphenated_protocol(self):
        self.assertEqual(self.skipped("udp"), ["udp"])

    def test_lists_and_empty_input(self):
        self.assertEqual(self.skipped(""), [])
        self.assertEqual(self.skipped("http2  udp"), ["http2", "udp"])
        self.assertEqual(self.skipped(" ".join(PROTOCOLS)), PROTOCOLS)


class PayloadAndGatewayTests(unittest.TestCase):
    def test_payload_sizes_match_whole_tokens(self):
        outputs, _ = run_step("Compute payload sizes", {
            "inputs.skip_payload_sizes": "1024 71680",
            "matrix.protocol": "http2",
        })
        self.assertEqual(outputs["payload_sizes"], "10240 512000 1048576 5242880")
        outputs, _ = run_step("Compute payload sizes", {
            "inputs.skip_payload_sizes": "512000",
            "matrix.protocol": "udp-dtls",
        })
        self.assertEqual(outputs["payload_sizes"], "1024")

    def test_gateway_skip_matches_whole_tokens(self):
        outputs, _ = run_step("Compute gateway list", {
            "inputs.skip_gateways": "kong-gateway envoy",
            "matrix.protocol": "udp",
        })
        self.assertEqual(outputs["list"], "ferrum kong")
        outputs, _ = run_step("Compute gateway list", {
            "inputs.skip_gateways": "",
            "matrix.protocol": "http1-tls",
        })
        self.assertEqual(outputs["list"], "ferrum envoy kong tyk krakend")

    def test_image_pre_pull_follows_the_gateway_list(self):
        with tempfile.TemporaryDirectory() as bin_directory:
            docker = Path(bin_directory) / "docker"
            docker.write_text('#!/bin/sh\necho "docker $*"\n')
            docker.chmod(0o755)
            _, stdout = run_step("Pre-pull competitor Docker images",
                                 {"steps.gateways.outputs.list": "ferrum kong"},
                                 path_prefix=bin_directory)
        self.assertIn("docker pull kong/kong-gateway:3.16.0.0", stdout)
        self.assertNotIn("envoy", stdout)
        self.assertNotIn("tyk", stdout)
        self.assertNotIn("krakend", stdout)


if __name__ == "__main__":
    unittest.main()
