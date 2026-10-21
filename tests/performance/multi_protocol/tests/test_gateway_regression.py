"""Cheap contracts for the optional exact-image gateway lane (no containers)."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gateway_regression as lane


def sample(cell):
    cc = cell["effective_concurrency"]
    protocol, gateway = cell["protocol"], cell["gateway"]
    port = (3447 if protocol == "http1-tls" else 3443) if gateway == "direct" else 8443
    value = dict(cell, protocol="HTTP/1.1+TLS" if protocol == "http1-tls" else "HTTP/2",
                 target=f"https://127.0.0.1:{port}/echo", sample_schema=2, host_id="one-boot",
                 gateway_order=lane.gateway_order(list(lane.GATEWAYS), cell["pair"]),
                 concurrency=cc, duration_secs=15, warmup_requests=cc,
                 total_requests=1500, total_bytes=1500 * cell["payload_size"],
                 total_errors=0, rps=100, p50_us=100, p95_us=200, p99_us=300, latency_max_us=400,
                 phases=dict(measurement_secs=15, measurement_elapsed_secs=15.01, timed_out=False),
                 observed=dict(samples=100, workers_at_barrier=cc, workers_retired_before_deadline=0),
                 process_usage=dict(processes=[dict(role="client")], measurement=[
                     dict(role=role, complete_bracket=True, cpu_seconds=1)
                     for role in ("client", "backend", "gateway")]))
    for field in ("active_workers", "active_connections", "active_streams", "queued_requests"):
        value["observed"][field] = dict(min=0, mean=cc, max=cc)
    return value


class GatewayRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "gateway_regression"
        self.output.mkdir()
        self.source = dict(candidate_sha="a" * 40, baseline_sha="b" * 40,
                           profile="release", features="cloud-secrets",
                           candidate_image_id="sha256:" + "a" * 64,
                           baseline_image_id="sha256:" + "b" * 64)
        lane.write_json(self.output.parent / "provenance.json", self.source)
        lane.write_json(self.output / "plan.json", dict(
            cells=lane.cells(), duration_secs=15, offered_concurrency=100,
            protocol_wall_timeout_secs=lane.PROTOCOL_WALL_SECS,
            mesh_provenance_sha256=lane.sha256(self.output.parent / "provenance.json"),
            images={key: self.source[key] for key in ("candidate_image_id", "baseline_image_id")},
            identity_cleanup_errors=[], fixture_cleanup_complete=True,
            image_users={role: dict(uid=65532, gid=65532) for role in ("candidate", "baseline")},
            **{key: self.source[key] for key in ("candidate_sha", "baseline_sha", "profile", "features")}))
        for protocol in lane.PROTOCOLS:
            directory = self.output / protocol
            directory.mkdir()
            lane.write_json(directory / "status.json", dict(state="completed", exit_code=0, cleanup_errors=[]))
            lane.write_json(directory / "manifest.json", dict(
                gateways=list(lane.GATEWAYS), payload_sizes=list(lane.SIZES), pairs=4,
                host_id="one-boot", baseline_image=self.source["baseline_image_id"],
                h2_window="default", h2_stream_window_bytes=8388608,
                h2_observation_enabled=False, sample_schema=2))
        self.paths = []
        for cell in lane.cells():
            path = self.output / cell["protocol"] / "pairs" / f"pair_{cell['pair']:03d}" / f"{cell['gateway']}_{cell['protocol']}_{cell['payload_size']}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            lane.write_json(path, sample(cell))
            self.paths.append(path)

    def mutate(self, path, **updates):
        lane.write_json(path, dict(lane.read_json(path), **updates))

    def test_complete_72_cells_report_all_pairs_without_equivalence_claim(self):
        report = lane.check(self.output)
        self.assertTrue(report["data_valid"], report["issues"])
        self.assertEqual(len(self.paths), 72)
        self.assertEqual(len(report["comparisons"]), 18)
        for comparison in report["comparisons"]:
            self.assertTrue(comparison["data_valid"])
            self.assertEqual(comparison["ratio"], 1)
            self.assertEqual([r["pair"] for r in comparison["pair_ratios"]], [1, 2, 3, 4])
            self.assertEqual(set(comparison["pair_ratios"][0]), {"pair", "rps", *lane.LATENCIES})
        self.assertIn("not configured", report["performance_gate"])
        self.assertNotIn("nonregression", report)  # validity does not imply equivalence

    def test_any_bad_repetition_is_fatal_despite_three_valid_repetitions(self):
        original = lane.read_json(self.paths[0])
        for updates in (dict(duration_secs=14), dict(concurrency=99), dict(effective_concurrency=99),
                        dict(pair=2), dict(pair=True), dict(protocol="HTTP/2"), dict(gateway="ferrum"),
                        dict(target="https://127.0.0.1:9999/echo"), dict(order_position=3),
                        dict(sample_schema=1), dict(host_id="other-boot"), dict(total_errors=1),
                        dict(p99_us=None), dict(process_usage={})):
            with self.subTest(updates=updates):
                lane.write_json(self.paths[0], dict(original, **updates))
                self.assertFalse(lane.check(self.output)["data_valid"])
        lane.write_json(self.paths[0], original)

    def test_missing_and_unplanned_pair_are_fatal(self):
        self.paths[0].unlink()
        self.assertFalse(lane.check(self.output)["data_valid"])
        extra = self.output / "http2/pairs/pair_005"
        extra.mkdir()
        self.assertTrue(any("pair directories" in issue for issue in lane.check(self.output)["issues"]))

    def test_failure_status_is_not_hidden_by_complete_json(self):
        self.mutate(self.output / "http2/status.json", state="timed_out")
        self.assertFalse(lane.check(self.output)["data_valid"])

    def test_final_identity_and_fixture_cleanup_failures_are_fatal(self):
        path = self.output / "plan.json"
        original = lane.read_json(path)
        for updates in (dict(identity_cleanup_errors=["baseline cleanup timed out"]),
                        dict(fixture_cleanup_complete=False)):
            lane.write_json(path, dict(original, **updates))
            self.assertFalse(lane.check(self.output)["data_valid"])

    def test_a_valid_large_slowdown_is_descriptive_and_not_a_validity_failure(self):
        for path in self.paths:
            row = lane.read_json(path)
            if row["gateway"] == "ferrum":
                row.update(rps=50, total_requests=750, total_bytes=750 * row["payload_size"])
                lane.write_json(path, row)
        report = lane.check(self.output)
        self.assertTrue(report["data_valid"], report["issues"])
        comparison = next(row for row in report["comparisons"] if row["baseline"] == "ferrum-baseline")
        self.assertAlmostEqual(comparison["ratio"], 0.5)
        self.assertLess(comparison["ci95_high"], 1)
        self.assertIn("not configured", report["performance_gate"])

    def test_immutable_images_and_confirmed_users_are_required(self):
        path = self.output / "plan.json"
        original = lane.read_json(path)
        for updates in (dict(images=dict(original["images"], candidate_image_id="ferrum-edge:bench")),
                        dict(image_users={}), dict(cells=original["cells"][:-1]), dict(profile="ci-release")):
            lane.write_json(path, dict(original, **updates))
            self.assertFalse(lane.check(self.output)["data_valid"])
        lane.write_json(path, original)
        self.mutate(self.output.parent / "provenance.json", candidate_sha="c" * 40)
        self.assertFalse(lane.check(self.output)["data_valid"])

    def test_completely_missing_campaign_writes_failed_report(self):
        report = lane.check(self.output / "missing")
        self.assertFalse(report["data_valid"])
        self.assertTrue((self.output / "missing/report.json").is_file())

    def test_configured_user_resolves_to_exact_nonroot_identity(self):
        passwd = "nonroot:x:65532:65532:Nonroot:/:/sbin/nologin\n"
        for user in ("nonroot", "65532", "65532:65532"):
            self.assertEqual(lane.resolve_identity(user, passwd)["gid"], 65532)
        for user in ("", "0", "65532:0", "unknown"):
            with self.assertRaises(ValueError):
                lane.resolve_identity(user, passwd)

    def test_fixture_changes_only_new_disposable_paths_and_keeps_key_private(self):
        root = Path(self.temp.name) / "synthetic"
        root.mkdir()
        with patch.object(lane, "runtime") as command, patch.object(
                lane.Path, "stat", return_value=SimpleNamespace(st_gid=65532)):
            lane.prepare_fixture(root)
        command.assert_called_once_with("fixture-group", FIXTURE=root)
        self.assertEqual((root / "certs/key.pem").stat().st_mode & 0o777, 0o640)
        self.assertEqual((root / "certs").stat().st_mode & 0o777, 0o750)

    def test_inputs_require_baseline_and_uninstrumented_matched_features(self):
        with patch.dict(os.environ, dict(BENCH_BASELINE_SHA="b" * 40,
                                        BENCH_CARGO_PROFILE="release",
                                        BENCH_FERRUM_FEATURES="cloud-secrets"), clear=True):
            lane.validate_inputs()
            os.environ["BENCH_FERRUM_FEATURES"] += ",bench-h1-profile"
            with self.assertRaises(ValueError):
                lane.validate_inputs()

    def test_workflow_and_owned_mode_cannot_rebuild_gateways(self):
        root = Path(__file__).resolve().parents[4]
        workflow = (root / ".github/workflows/mesh-runtime-benchmark.yml").read_text()
        runner = (lane.TOOLS / "run_gateway_protocol_bench.sh").read_text()
        dispatch = (lane.TOOLS / "gateway_regression_runtime.sh").read_text()
        self.assertIn("gateway_regression:\n", workflow)
        self.assertIn("default: false\n        type: boolean", workflow)
        self.assertIn("--manifest-path tests/performance/multi_protocol/Cargo.toml", workflow)
        self.assertIn("--bin proto_bench --bin proto_backend", workflow)
        self.assertIn("--user 65532:65532 --group-add 65532", runner)
        self.assertIn('--label "ferrum.gateway-regression=$OWNED_RUN_ID"', runner)
        self.assertIn('--cacert "$CERT_DIR/ca.pem"', runner)
        self.assertIn('timeout --signal=TERM --kill-after=2s 10s docker "$@"', runner)
        self.assertIn('--experiment-manifest /dev/null --skip-build', dispatch)
        self.assertIn('--payload-sizes "10240 1048576 5242880" --duration 15 --concurrency 100 --pairs 4', dispatch)
        self.assertNotIn("docker build", dispatch)


if __name__ == "__main__":
    unittest.main()
