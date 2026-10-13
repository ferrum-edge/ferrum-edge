#!/usr/bin/env python3
"""Output-contract tests for generate_comparison_report.py.

Covers three report defects:
- #6491: all-Docker metadata must not produce the native/zero-overhead
  Ferrum methodology sentence (or the "(native)" gateway label).
- #6511: a parseable prior-run result for a gateway the new run skipped
  must stay out of the new report when meta.json carries the current
  run's ``result_files`` manifest.
- #6512: the Envoy methodology bullet must not claim key-auth is
  excluded; the suite runs an Envoy key-auth arm.

Run directly: python3 comparison/scripts/test_generate_comparison_report.py
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("generate_comparison_report.py")
_SPEC = importlib.util.spec_from_file_location("generate_comparison_report", SCRIPT)
gen = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen)

WRK = """Running 30s test @ http://127.0.0.1:8000/api/echo
  8 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.00ms    0.10ms   5.00ms   90.00%
    Req/Sec    10.00k     1.00k    12.00k    70.00%
  {requests} requests in 30.00s, 100.00MB read
Requests/sec:  {rps}
Transfer/sec:    3.33MB
--- Comparison Results ---
latency_mean_us: 1000
latency_p50_us: 900
latency_p90_us: 1500
latency_p99_us: 2000
latency_p999_us: 3000
errors_status: 0
errors_connect: 0
errors_read: 0
errors_write: 0
errors_timeout: 0
--- End Results ---
"""

STALE_KONG_RPS = "424,242"  # formatted rendering of 424242 in the tables


def write_result(directory, name, rps):
    (directory / name).write_text(WRK.format(requests=int(rps * 30), rps=rps))


def render(directory, meta):
    output = directory / "report.html"
    gen.generate_report(str(directory), str(output), meta)
    return output.read_text()


class ComparisonReportContractTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        write_result(self.dir, "baseline_http_api_echo_results.txt", 100000)
        write_result(self.dir, "ferrum_http_api_echo_results.txt", 90000)

    def test_all_docker_metadata_never_claims_native_ferrum(self):
        html = render(self.dir, {"execution_mode": "all-docker"})
        self.assertIn("Ferrum Edge</strong> runs inside a Docker container", html)
        self.assertNotIn("runs as a native binary on the host", html)
        self.assertNotIn("Ferrum Edge (native)", html)
        self.assertIn("Ferrum Edge (Docker)", html)

    def test_native_sentence_stays_available_without_all_docker(self):
        html = render(self.dir, {})
        self.assertIn("runs as a native binary on the host", html)

    def test_envoy_bullet_does_not_claim_key_auth_exclusion(self):
        html = render(self.dir, {"execution_mode": "all-docker"})
        self.assertNotIn("Key-auth benchmarks are excluded as Envoy", html)
        self.assertIn("Key-auth benchmarks include Envoy", html)

    def test_skipped_gateway_prior_results_stay_out_with_manifest(self):
        # A prior run left parseable Kong results in the shared directory;
        # the new run skipped Kong, so its manifest omits both files.
        write_result(self.dir, "kong_http_api_echo_results.txt", 424242)
        write_result(self.dir, "kong_key_auth_api_echo_results.txt", 424242)
        meta = {
            "execution_mode": "all-docker",
            "result_files": [
                "baseline_http_api_echo_results.txt",
                "ferrum_http_api_echo_results.txt",
            ],
        }
        html = render(self.dir, meta)
        self.assertNotIn(STALE_KONG_RPS, html)
        self.assertNotIn("Key-Auth Performance", html)

    def test_without_manifest_directory_discovery_is_unchanged(self):
        write_result(self.dir, "kong_http_api_echo_results.txt", 424242)
        html = render(self.dir, {"execution_mode": "all-docker"})
        self.assertIn(STALE_KONG_RPS, html)


if __name__ == "__main__":
    unittest.main()
