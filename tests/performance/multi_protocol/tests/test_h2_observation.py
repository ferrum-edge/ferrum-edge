import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from experiment_arms import load_experiment, materialize_h2, parse_env, verify_runtime
from h2_diagnostics import annotate, event_phase, parse_gauges
from benchmark_validity import sample_issues
from benchmark_plan import paired_comparison


class H2ObservationTests(unittest.TestCase):
    def setUp(self):
        common = ("FERRUM_LOG_LEVEL=warn,ferrum_h2_observe=debug "
                  "FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32 FERRUM_ADMIN_HTTP_PORT=9000")
        self.plan = dict(enabled=True, name="h2-observation", protocol=["http2", "grpcs"],
                         h2_campaign=dict(pairs=4, duration=15, concurrency=200,
                                          payload_sizes={"http2": [71680], "grpcs": [10240, 71680]}),
                         arms=[dict(gateway=name, FERRUM_EXTRA_ENV=(
                             f"FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW={adaptive} " + common))
                             for name, adaptive in (("ferrum", "true"), ("ferrum-exp-fixed", "false"))])

    def load(self, plan, protocol="http2"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "experiment.json"
            path.write_text(json.dumps(plan))
            return load_experiment(path, protocol)

    def test_campaign_is_opt_in_and_covers_both_native_h2_siblings(self):
        disabled = dict(self.plan, enabled=False)
        self.assertIsNone(self.load(disabled))
        for protocol in ("http2", "grpcs"):
            self.assertEqual(self.load(self.plan, protocol)["h2_campaign"]["pairs"], 4)
        self.assertIsNone(self.load(self.plan, "http3"))
        for key, value in (("pairs", 2), ("duration", 30), ("concurrency", 100)):
            changed = copy.deepcopy(self.plan)
            changed["h2_campaign"][key] = value
            with self.assertRaises(ValueError):
                self.load(changed)

    def test_broad_trace_shell_syntax_and_confounded_arms_are_rejected(self):
        for value in ("FERRUM_LOG_LEVEL=warn,h2=trace", "FERRUM_LOG_LEVEL=debug",
                      "FERRUM_X=$(id)", "FERRUM_X=1 FERRUM_X=2",
                      "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=false FERRUM_MAX_CONNECTIONS=1"):
            plan = copy.deepcopy(self.plan)
            plan["arms"][1]["FERRUM_EXTRA_ENV"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load(plan)
        self.assertEqual(parse_env("FERRUM_LOG_LEVEL=warn,ferrum_h2_observe=debug"),
                         {"FERRUM_LOG_LEVEL": "warn,ferrum_h2_observe=debug"})

    def test_route_override_is_changed_verified_and_hashed_for_each_arm(self):
        for protocol, config in (("http2", "http2_perf.yaml"), ("grpcs", "grpcs_e2e_perf.yaml")):
            plan = self.load(self.plan, protocol)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = root / "manifest.json"
                manifest.write_text("{}")
                rendered = []
                for arm, adaptive in zip(plan["arms"], (True, False)):
                    path = root / (arm["gateway"] + ".yaml")
                    materialize_h2(plan, protocol, arm["gateway"], ROOT / "configs" / config,
                                   path, manifest)
                    data = json.loads(manifest.read_text())["effective_h2_arms"][arm["gateway"]]
                    self.assertEqual(data["route_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
                    self.assertEqual(data["settings"]["adaptive_window"], adaptive)
                    self.assertEqual(data["settings"]["builder_initial_connection_window"],
                                     65535 if adaptive else 33554432)
                    self.assertNotIn("observed_connections", data["settings"])
                    rendered.append(path.read_text())
                self.assertEqual(rendered[0].replace("adaptive_window: true", "adaptive_window: false"),
                                 rendered[1])
                self.assertIn("backend_read_timeout_ms: 30000", rendered[1])
                self.assertIn('backend_tls_server_ca_cert_path: "/etc/ferrum/tls/ca.pem"', rendered[1])
                source = root / "changed.yaml"
                source.write_text((ROOT / "configs" / config).read_text().replace(
                    "pool_http2_adaptive_window: false", "pool_http2_adaptive_window: true"))
                with self.assertRaises(ValueError):
                    materialize_h2(plan, protocol, "ferrum", source, root / "bad.yaml", manifest)

    def test_observed_gauges_never_substitute_configured_shards_or_missing_data(self):
        text = ('ferrum_connection_pool_entries{pool="http2"} 1\n'
                'ferrum_connection_pool_entries{pool="grpc"} 2\n'
                'ferrum_overload_active_connections 21\n')
        gauges = parse_gauges(text)
        self.assertEqual(gauges["resident_http2_pool_entries"], 1)
        with self.assertRaises(ValueError):
            parse_gauges(text.replace('ferrum_overload_active_connections 21\n', ''))
        sample = dict(gateway="ferrum", phases={"measurement_start_unix_secs": 100,
                                                "measurement_secs": 15})
        annotate(sample, {"timeline": [{"h2_gauges": {"unix_secs": 101, "gauges": gauges}}]}, "")
        self.assertEqual(sample["h2_observation"]["configured_pool_shards"], 16)
        self.assertTrue(sample["h2_observation"]["gauges_available"])
        annotate(sample, {}, "")
        self.assertFalse(sample["h2_observation"]["gauges_available"])
        self.assertIn("missing H2 pool/connection observations", sample_issues(sample))

    def test_container_provenance_rejects_shadowed_flags_and_image_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text("{}")
            plan = self.load(self.plan)
            common = dict(FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE="8388608",
                          FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE="33554432",
                          FERRUM_POOL_HTTP2_MAX_FRAME_SIZE="1048576",
                          FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS="1000",
                          FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS="1000",
                          FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES="0")
            for arm in plan["arms"]:
                materialize_h2(plan, "http2", arm["gateway"], ROOT / "configs/http2_perf.yaml",
                               root / (arm["gateway"] + ".yaml"), manifest)
                env = dict(common, **parse_env(arm["FERRUM_EXTRA_ENV"]))
                container = dict(Image="sha256:same", Config={"Env": [f"{k}={v}" for k, v in env.items()]})
                verify_runtime(plan, arm["gateway"], container, manifest)
                container["Config"]["Env"].append("RUST_LOG=h2=trace")
                with self.assertRaises(ValueError):
                    verify_runtime(plan, arm["gateway"], container, manifest)
                container["Config"]["Env"].pop()
            container["Image"] = "sha256:different"
            with self.assertRaises(ValueError):
                verify_runtime(plan, arm["gateway"], container, manifest)

    def test_backend_correlation_uses_actual_boundaries_and_preserves_failure(self):
        phases = dict(setup_start_unix_secs=100, setup_start_monotonic_secs=1,
                      warmup_start_monotonic_secs=2, measurement_start_monotonic_secs=4,
                      measurement_secs=15, drain_start_monotonic_secs=19.1,
                      transport_close_start_monotonic_secs=20)
        self.assertEqual([event_phase(t, phases) for t in (100, 101, 103, 118, 119)],
                         ["setup", "warmup", "measurement", "drain", "transport_close"])
        self.assertEqual(event_phase(100, {}), "unknown")
        sample = dict(gateway="direct", phases=phases)
        event = dict(unix_secs=104, connection_id=7, detail="typed failure", h2_reason=11)
        annotate(sample, {}, "H2_TRANSPORT " + json.dumps(event) + "\nH2_TRANSPORT broken\n")
        observation = sample["h2_observation"]
        self.assertEqual(observation["backend_events"][0]["phase"], "measurement")
        self.assertEqual(observation["backend_errors_observed"], 1)
        self.assertEqual(observation["capture_errors"], ["malformed_backend_event"])
        self.assertIn("H2 backend errors or incomplete diagnostic capture", sample_issues(sample))

    def test_truncated_capture_invalidates_an_otherwise_clean_sample(self):
        clean = dict(gateway="ferrum", total_requests=10, total_bytes=716800,
                     total_errors=0, payload_size=71680, rps=10,
                     phases={"transport_errors_total": 0, "transport_events_suppressed": 0},
                     h2_observation={"gauges_available": True, "capture_errors": [],
                                     "backend_errors_observed": 0})
        self.assertEqual(sample_issues(clean), [])
        client = copy.deepcopy(clean)
        client["phases"]["transport_events_suppressed"] = 1
        backend = copy.deepcopy(clean)
        backend["h2_observation"]["backend_log_limit_reached"] = True
        for sample in (client, backend):
            self.assertIn("truncated H2 transport observations", sample_issues(sample))
            self.assertEqual(sample["total_errors"], 0)

    def test_failed_repetition_invalidates_the_whole_comparison(self):
        left, right = [], []
        for pair in range(1, 5):
            sample = dict(pair=pair, host_id="same", duration_secs=15, payload_size=71680,
                          effective_concurrency=200, total_requests=10, total_bytes=716800,
                          total_errors=0, rps=10, p99_us=100)
            left.append(dict(sample))
            right.append(dict(sample))
        right[2]["total_errors"] = 1
        comparison = paired_comparison(left, right, 4)
        self.assertFalse(comparison["accepted"])
        self.assertEqual(right[2]["total_errors"], 1)


if __name__ == "__main__":
    unittest.main()
