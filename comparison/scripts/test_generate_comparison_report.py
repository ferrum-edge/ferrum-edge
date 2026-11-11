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
- #7306: the report never offers a native-Kong mode the driver lacks,
  every gateway's E2E TLS leg skips backend verification the same way,
  and a key-auth arm that fails to start is skipped instead of aborting
  the run.

Run directly: python3 comparison/scripts/test_generate_comparison_report.py
"""

import importlib.util
import json
import re
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


_RESULT_FILE_REDIRECT_RE = re.compile(r'> "\$result_file" 2>&1')


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

    def test_report_never_offers_a_native_kong_mode(self):
        # The driver runs every gateway in Docker; a stale meta key must
        # not resurrect the native-Kong label or advice.
        write_result(self.dir, "kong_http_api_echo_results.txt", 80000)
        html = render(self.dir, {"execution_mode": "all-docker", "kong_native": True})
        self.assertNotIn("Kong Gateway (native)", html)
        self.assertNotIn("natively on the host (installed", html)
        self.assertNotIn("install Kong natively", html)
        self.assertIn("<strong>Kong</strong> runs inside a Docker container", html)

    def test_e2e_tls_methodology_says_no_gateway_verifies_the_backend(self):
        html = render(self.dir, {"execution_mode": "all-docker"})
        self.assertIn("No gateway verifies the backend certificate on this leg", html)

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


class RunComparisonManifestContractTests(unittest.TestCase):
    """Every wrk result the driver writes must land in the run manifest.

    Otherwise a successful arm would be filtered out of its own report
    once ``result_files`` is present (for example Tyk's key-auth path,
    which runs wrk directly rather than through ``run_wrk_key_auth``).
    """

    def test_each_result_writer_appends_to_the_manifest(self):
        driver = SCRIPT.parents[1] / "run_comparison.sh"
        text = driver.read_text()
        writers = [m.start() for m in _RESULT_FILE_REDIRECT_RE.finditer(text)]
        self.assertGreaterEqual(len(writers), 3, "expected the POST, key-auth and Tyk writers")
        for start in writers:
            window = text[start : start + 1200]
            self.assertIn(
                'basename "$result_file" >> "$CURRENT_RUN_MANIFEST"',
                window,
                f"result writer at offset {start} does not record its file in the manifest",
            )


COMPARISON_DIR = SCRIPT.parents[1]
CONFIGS = COMPARISON_DIR / "configs"


def driver_function(text, name):
    """Return the body of shell function ``name`` in run_comparison.sh."""
    match = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}$", text, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"run_comparison.sh has no {name}()")
    return match.group(1)


class E2ETlsVerificationParityTests(unittest.TestCase):
    """Every E2E TLS leg must do the same backend-TLS work (#7306).

    The backend serves tests/certs/server.crt, a self-signed CA:TRUE
    certificate that rustls rejects as an end entity, so Ferrum cannot
    verify it; the other gateways must not verify it either.
    """

    def test_ferrum_skips_backend_verification_on_every_https_proxy(self):
        text = (CONFIGS / "ferrum_comparison_e2e_tls.yaml").read_text()
        https_proxies = len(re.findall(r"^\s+backend_scheme: https$", text, re.MULTILINE))
        skips = re.findall(r"^\s+backend_tls_verify_server_cert: (\S+)$", text, re.MULTILINE)
        self.assertGreater(https_proxies, 0)
        self.assertEqual(skips, ["false"] * https_proxies)

    def test_envoy_upstream_tls_has_no_validation_context(self):
        lines = (CONFIGS / "envoy" / "envoy_e2e_tls.yaml").read_text().splitlines()
        text = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
        self.assertIn("UpstreamTlsContext", text)
        self.assertNotIn("validation_context", text)
        self.assertNotIn("trusted_ca", text)

    def test_krakend_client_tls_skips_verification(self):
        config = json.loads((CONFIGS / "krakend" / "krakend_e2e_tls.json").read_text())
        self.assertEqual(config["client_tls"], {"allow_insecure_connections": True})

    def test_tyk_e2e_apps_skip_verification(self):
        apps = sorted((CONFIGS / "tyk" / "apps_e2e_tls").glob("*.json"))
        self.assertTrue(apps)
        for app in apps:
            transport = json.loads(app.read_text())["proxy"]["transport"]
            self.assertIs(transport.get("ssl_insecure_skip_verify"), True, app.name)

    def test_kong_e2e_container_disables_verification(self):
        text = (COMPARISON_DIR / "run_comparison.sh").read_text()
        self.assertIn("-e KONG_TLS_CERTIFICATE_VERIFY=off", driver_function(text, "start_kong_e2e_tls"))


class KeyAuthStartGuardTests(unittest.TestCase):
    """A key-auth arm whose container fails to start must be skipped.

    run_comparison.sh runs under ``set -euo pipefail``: a bare failing
    ``docker run`` in a test_*_key_auth arm aborted the whole run before
    generate_report (#7306).
    """

    def test_each_key_auth_arm_starts_inside_a_guard(self):
        text = (COMPARISON_DIR / "run_comparison.sh").read_text()
        for gateway in ("ferrum", "kong", "tyk", "envoy"):
            with self.subTest(gateway=gateway):
                arm = driver_function(text, f"test_{gateway}_key_auth")
                self.assertNotIn("docker_run_gateway", arm)
                self.assertNotIn("docker run", arm)
                self.assertRegex(arm, rf"if !? ?start_{gateway}_key_auth; then")
                start = driver_function(text, f"start_{gateway}_key_auth")
                self.assertRegex(start, r"\|\| return 1\n")


if __name__ == "__main__":
    unittest.main()
