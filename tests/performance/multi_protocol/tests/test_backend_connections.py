"""Backend connection counters and the H2 window / gRPC connection options (#6038, #6022)."""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HARNESS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(HARNESS))
from backend_connections import backend_connections, read_counters, stamp  # noqa: E402

RUNNER = HARNESS / "run_gateway_protocol_bench.sh"


def counters(**overrides):
    values = dict(h2_tls_accepted=10, h2_tls_handshakes=10, grpcs_accepted=4,
                  http_echo_requests=100, grpc_echo_requests=50)
    values.update(overrides)
    return values


class BackendConnectionTests(unittest.TestCase):
    def test_http2_counts_accepts_handshakes_and_echoes_in_the_window(self):
        result = backend_connections(
            "http2", counters(), counters(h2_tls_accepted=13, h2_tls_handshakes=12,
                                          http_echo_requests=2100))
        self.assertEqual(result, {
            "available": True, "listener": "h2_tls", "accepted": 3,
            "accepted_since_backend_start": 13, "echo_requests": 2000,
            "accepted_per_1k_echoes": 1.5, "tls_handshakes": 2})

    def test_grpcs_reads_its_own_listener_and_echo_counter(self):
        result = backend_connections(
            "grpcs", counters(), counters(grpcs_accepted=1004, grpc_echo_requests=1050,
                                          http_echo_requests=999))
        self.assertEqual(result["listener"], "grpcs")
        self.assertEqual(result["accepted"], 1000)
        self.assertEqual(result["echo_requests"], 1000)
        self.assertEqual(result["accepted_per_1k_echoes"], 1000.0)
        self.assertNotIn("tls_handshakes", result)

    def test_missing_regressing_or_foreign_counters_are_unavailable_not_zero(self):
        self.assertFalse(backend_connections("http2", None, counters())["available"])
        self.assertFalse(backend_connections("http2", counters(), counters(
            h2_tls_accepted=1))["available"])
        self.assertFalse(backend_connections("wss", counters(), counters())["available"])
        self.assertIsNone(backend_connections("http2", counters(), counters())[
            "accepted_per_1k_echoes"])

    def test_snapshots_reject_malformed_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stats.json"
            path.write_text(json.dumps(counters()))
            self.assertEqual(read_counters(path), counters())
            for bad in (counters(grpcs_accepted=True), counters(grpcs_accepted=-1),
                        {"h2_tls_accepted": 1}, ["not", "an", "object"]):
                path.write_text(json.dumps(bad))
                self.assertIsNone(read_counters(path))
            path.write_text("{truncated")
            self.assertIsNone(read_counters(path))
            self.assertIsNone(read_counters(Path(directory) / "absent.json"))

    def test_stamp_labels_the_sample_with_its_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "before.json").write_text(json.dumps(counters()))
            (root / "after.json").write_text(json.dumps(counters(grpcs_accepted=5,
                                                                 grpc_echo_requests=60)))
            sample = root / "ferrum_grpcs_10240.json"
            sample.write_text(json.dumps({"rps": 1, "gateway": "ferrum"}))
            stamp(sample, "grpcs", root / "before.json", root / "after.json", "64k", "per-rpc")
            stamped = json.loads(sample.read_text())
            self.assertEqual(stamped["workload"],
                             {"h2_window": "64k", "grpc_client_connections": "per-rpc"})
            self.assertEqual(stamped["backend_connections"]["accepted"], 1)
            self.assertEqual(stamped["gateway"], "ferrum")


class RunnerOptionTests(unittest.TestCase):
    def run_runner(self, *args, env=None):
        return subprocess.run(["bash", str(RUNNER), *args], cwd=REPO_ROOT, env=env,
                              capture_output=True, text=True, timeout=5)

    def test_invalid_window_and_client_modes_fail_before_any_work(self):
        result = self.run_runner("http2", "--h2-window", "16k")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--h2-window must be default or 64k", result.stderr)
        result = self.run_runner("grpcs", "--grpc-client-connections", "per-call")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--grpc-client-connections must be pooled or per-rpc", result.stderr)
        # The frozen hosted job passes dispatch inputs as environment.
        result = self.run_runner("http2", env={"PATH": "/usr/bin:/bin", "BENCH_H2_WINDOW": "1"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("--h2-window must be", result.stderr)

    def test_profile_lanes_refuse_changed_windows_or_client_modes(self):
        result = self.run_runner("http2", "--h2-window", "64k", "--pool-profile", "calibration")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot be combined with a profile lane", result.stderr)
        result = self.run_runner("grpcs", "--grpc-client-connections", "per-rpc",
                                 "--h1-profile", "calibration")
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot be combined with a profile lane", result.stderr)

    def test_default_runs_keep_the_historical_fixed_windows(self):
        source = RUNNER.read_text()
        self.assertIn('H2_WINDOW="${BENCH_H2_WINDOW:-default}"', source)
        self.assertIn('GRPC_CLIENT_CONNECTIONS="${BENCH_GRPC_CLIENT_CONNECTIONS:-pooled}"', source)
        self.assertIn("H2_STREAM_WINDOW=8388608\n", source)
        self.assertIn('-e "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=$H2_STREAM_WINDOW"', source)
        # Non-default options are added only when requested.
        self.assertIn('if [ "$H2_WINDOW" != default ]; then\n'
                      '        extra_args+=(--h2-stream-window "$H2_STREAM_WINDOW")', source)
        self.assertIn('if [ "$GRPC_CLIENT_CONNECTIONS" = per-rpc ]; then\n'
                      '        extra_args+=(--connection-per-request)', source)

    def test_each_h2_route_has_one_rewritable_stream_window(self):
        # prepare_ferrum_config rewrites exactly this line for --h2-window 64k
        # and refuses the run when it does not match exactly once.
        for name in ("http2_perf.yaml", "grpcs_e2e_perf.yaml"):
            text = (HARNESS / "configs" / name).read_text()
            self.assertEqual(len(re.findall(
                r"(?m)^    pool_http2_initial_stream_window_size: *8388608", text)), 1, name)

    def test_window_rewrite_failure_refuses_the_run_before_any_work(self):
        source = RUNNER.read_text()
        precheck = source.index('prepare_ferrum_config "$SCRIPT_DIR/configs/$(ferrum_config_name)"')
        self.assertIn('"/etc/ferrum/tls/ca.pem" > /dev/null || exit 2', source[precheck:])
        self.assertLess(precheck, source.index('python3 - "$root_output/manifest.json"'))
        self.assertLess(precheck, source.index("    ensure_baseline_image || exit 2"))

    def test_unpublished_missing_baseline_fails_option_validation(self):
        for image in ("evil/ferrum-edge:main-" + "0" * 40, "ferrumedge/ferrum-edge:latest"):
            result = self.run_runner("http2", env={"PATH": "/usr/bin:/bin",
                                                   "FERRUM_BASELINE_IMAGE": image})
            self.assertEqual(result.returncode, 2, image)
            self.assertIn("--baseline-image must be a local image", result.stderr)

    def test_dispatch_job_validates_baseline_with_the_runner_patterns(self):
        source = RUNNER.read_text()
        workflow = (REPO_ROOT / ".github/workflows/gateways-protocol-benchmark.yml").read_text()
        self.assertEqual(re.search(r"BASELINE_PUBLISHED='([^']+)'", source)[1],
                         re.search(r"published='([^']+)'", workflow)[1])
        self.assertEqual(re.search(r"BASELINE_MIRRORED='([^']+)'", source)[1],
                         re.search(r"mirrored='([^']+)'", workflow)[1])

    def test_only_published_main_images_are_pulled(self):
        source = RUNNER.read_text()
        published = re.search(r"BASELINE_PUBLISHED='([^']+)'", source)[1]
        mirrored = re.search(r"BASELINE_MIRRORED='([^']+)'", source)[1]
        sha = "0123456789abcdef0123456789abcdef01234567"
        digest = "@sha256:" + "a" * 64
        for image in (f"ferrumedge/ferrum-edge:main-{sha}",
                      f"docker.io/ferrumedge/ferrum-edge:main-{sha}",
                      f"ferrumedge/ferrum-edge:main-{sha}{digest}"):
            self.assertTrue(re.fullmatch(published, image), image)
        self.assertTrue(re.fullmatch(mirrored, f"ghcr.io/ferrum-edge/ferrum-edge:main-{sha}"))
        for image in ("ferrumedge/ferrum-edge:latest", "ferrumedge/ferrum-edge:main-abc",
                      f"evil/ferrum-edge:main-{sha}", f"ferrumedge/ferrum-edge:main-{sha} x",
                      f"ghcr.io/other/ferrum-edge:main-{sha}"):
            self.assertIsNone(re.fullmatch(published, image), image)
            self.assertIsNone(re.fullmatch(mirrored, image), image)


if __name__ == "__main__":
    unittest.main()
