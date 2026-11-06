import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pool_internal_profile as profile
from h2_diagnostics import annotate, parse_gauges


_QUOTED_NAME_RE = re.compile(r'"([a-z0-9_]+)"')


def values():
    result = dict.fromkeys(profile.FIELDS, 0)
    result.update(schema=1, sample_every=64, pid=1, allocator_installed=1, slot_capacity=128)
    return result


def capture(duration=1, family="h2"):
    rows = []
    for index, timestamp in enumerate([9.9, 10 + duration / 2, 10 + duration + 0.1]):
        counters = values()
        counters[family + "_request_poll_alloc"] = index
        counters[family + "_request_sampled"] = index
        counters[family + "_request_completed"] = index
        rows.append(dict(unix_secs=timestamp, processes=[dict(pid=31, start_ticks=100, role="gateway")],
                         pool_profile=dict(unix_secs=timestamp, monotonic_secs=timestamp,
                                           sample_id=index, capture_secs=0.01,
                                           sampler_cpu_secs=0.001, counters=counters)))
    return dict(capture_complete=True, timeline=rows)


def traffic_sample(pair, gateway, size):
    workers = 50 if size >= 5242880 else 100 if size >= 1048576 else 200
    roles = ["client", "backend"] + (["gateway"] if gateway != "direct" else [])
    processes = [dict(pid=index + 1, role=role) for index, role in enumerate(roles)]
    sample = dict(sample_schema=2, pair=pair, gateway=gateway, host_id="host",
                  payload_size=size, duration_secs=15, effective_concurrency=workers,
                  warmup_requests=workers, total_requests=100, total_errors=0,
                  total_bytes=100 * size, rps=100 / 15,
                  phases=dict(measurement_start_unix_secs=10, measurement_secs=15,
                              measurement_elapsed_secs=15.01, timed_out=False,
                              transport_errors_total=0, transport_close_timed_out=False,
                              transport_events_suppressed=0),
                  observed=dict(samples=2, workers_at_barrier=workers,
                                workers_retired_before_deadline=0),
                  process_usage=dict(processes=processes, measurement=[
                      dict(process, complete_bracket=True, cpu_seconds=0.5)
                      for process in processes]))
    for field in ("active_workers", "active_connections", "active_streams", "queued_requests"):
        sample["observed"][field] = dict(min=0, max=workers, mean=workers / 2)
    # Use the real annotation/parser contract: direct has no gateway gauges;
    # backend_log_limit_reached is absent unless a limit marker was captured.
    usage = {}
    if gateway != "direct":
        gauges = parse_gauges('ferrum_connection_pool_entries{pool="http2"} 1\n'
                              'ferrum_connection_pool_entries{pool="grpc"} 2\n'
                              'ferrum_overload_active_connections 21\n')
        usage = dict(timeline=[dict(h2_gauges=dict(unix_secs=11, monotonic_secs=1,
                                                  capture_secs=0.01, gauges=gauges))])
    annotate(sample, usage, "")
    return sample


class PoolInternalProfileTests(unittest.TestCase):
    def test_rust_schema_is_the_fixed_cartesian_product(self):
        source = (profile.ROOT.parents[2] / "src/pool_profile/schema.rs").read_text()
        arrays = {name: _QUOTED_NAME_RE.findall(re.search(
            r"pub const " + name + r": .*?= \[(.*?)\];", source, re.S)[1])
                  for name in ["FAMILIES", "PURPOSES", "EVENTS", "PHASES", "FIELDS", "PROBES"]}
        names = []
        for family in arrays["FAMILIES"]:
            for purpose in arrays["PURPOSES"]:
                prefix = family + "_" + purpose + "_"
                names += [prefix + event for event in arrays["EVENTS"]]
                names += [prefix + phase + "_" + field for phase in arrays["PHASES"]
                          for field in arrays["FIELDS"]]
                names += [prefix + bucket for bucket in arrays["PROBES"]]
        names.append("counter_overflow")
        self.assertEqual(names, profile.SCHEMA["counters"])
        self.assertEqual(len(names), len(set(names)))

    def test_metrics_reject_missing_unknown_duplicate_noninteger_and_bad_samplerate(self):
        text = "\n".join(f"{profile.PREFIX}{key} {value}" for key, value in values().items())
        self.assertEqual(profile.parse_metrics(text), values())
        for malformed in ["", text + "\n" + text, text.replace("schema 1", "schema NaN"),
                          text.replace("sample_every 64", "sample_every 1"),
                          text.replace("allocator_installed 1", "allocator_installed 0"),
                          text + "\nferrum_pool_profile_pool_key 1"]:
            with self.assertRaises(ValueError):
                profile.parse_metrics(malformed)

    def test_missing_reset_loss_overflow_tail_identity_and_observer_cost_fail_closed(self):
        phases = dict(measurement_start_unix_secs=10, measurement_secs=1)
        self.assertTrue(profile.profile_bracket(capture(), phases)["complete"])
        mutations = [
            lambda c: c["timeline"][1].pop("pool_profile"),
            lambda c: c["timeline"][1]["processes"].clear(),
            lambda c: c["timeline"][1]["processes"][0].update(start_ticks=101),
            lambda c: c["timeline"][2]["pool_profile"]["counters"].update(h2_request_poll_alloc=0),
            lambda c: c["timeline"][1]["pool_profile"].pop("sampler_cpu_secs"),
            lambda c: c["timeline"][1]["pool_profile"].update(sample_id=0),
            lambda c: c["timeline"][1]["pool_profile"].update(monotonic_secs=1),
            lambda c: c["timeline"][1]["pool_profile"].update(capture_secs=float("nan")),
            lambda c: c["timeline"][2]["pool_profile"]["counters"].update(h2_request_completed=0),
            lambda c: c.update(capture_complete=False),
            lambda c: c.update(timeline=None),
            lambda c: c["timeline"][1].update(pool_profile=[]),
            lambda c: c["timeline"][1]["pool_profile"].update(counters=[]),
        ]
        for field in ("missing_slots", "lost_events", "counter_overflow", "unpublished_events",
                      "allocator_lost_events", "allocator_overflow"):
            mutations.append(lambda c, field=field: c["timeline"][1]["pool_profile"]["counters"].update(
                {field: 1}))
        for mutate in mutations:
            data = copy.deepcopy(capture())
            mutate(data)
            result = profile.profile_bracket(data, phases)
            self.assertFalse(result["complete"], result)
            self.assertTrue(result["issues"])

    def test_selector_and_materialization_hold_flow_control_policy_fixed(self):
        args = ["profile", "http2", "4", "15", "200", "ferrum", "10240 5242880", "same-image", ""]
        profile.validate_selection(*args)
        for index, replacement in [(0, "cutoff"), (1, "http1-tls"), (2, "2"), (3, "60"),
                                   (4, "100"), (5, "ferrum envoy"), (6, "1024"), (7, ""),
                                   (8, "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true")]:
            invalid = args.copy()
            invalid[index] = replacement
            with self.assertRaises(ValueError):
                profile.validate_selection(*invalid)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text("{}")
            for protocol, fixture in [("http2", "http2_perf.yaml"), ("grpcs", "grpcs_e2e_perf.yaml")]:
                outputs = []
                for arm in ("ferrum", "ferrum-baseline"):
                    output = root / (arm + ".yaml")
                    profile.materialize(protocol, arm, profile.ROOT / "configs" / fixture, output, manifest)
                    outputs.append(output.read_text())
                    self.assertIn("pool_http2_adaptive_window: false", outputs[-1])
                    self.assertNotIn("CA_PATH", outputs[-1])
                self.assertEqual(*outputs)

    def test_report_retains_all_failed_samples_and_malformed_partial_captures(self):
        for usage in ([], dict(timeline=[None]), capture()):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "manifest.json").write_text(json.dumps(dict(
                    pairs=4, gateways=["direct", "ferrum", "ferrum-baseline"],
                    payload_sizes=[5242880], host_id="host")))
                folder = root / "pairs/pair_001/diagnostics"
                folder.mkdir(parents=True)
                (folder / "ferrum_5242880_process_usage.json").write_text(json.dumps(usage))
                (folder.parent / "ferrum_http2_5242880.json").write_text(json.dumps(dict(
                    error="retained protocol failure", phases=dict(
                        measurement_start_unix_secs=10, measurement_secs=1))))
                result = profile.report(root, "profile", "http2")
                self.assertEqual(len(result["observations"]), 12)
                self.assertFalse(result["traffic_complete"])
                self.assertFalse(result["profiles_complete"])
                self.assertFalse(result["fully_measured_comparison_eligible"])
                row = result["observations"][1]
                self.assertEqual(row["capture"], usage)
                self.assertEqual(row["sample"]["error"], "retained protocol failure")

    def test_runtime_mismatch_is_written_before_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.yaml"
            config.write_text("fixture")
            container = dict(Config=dict(Env=[], Labels={}), Image="sha256:x", Id="x",
                             State=dict(Pid=31, StartedAt="now"))
            with self.assertRaises(ValueError):
                profile.retain_runtime(root / "runtime.json", container, config)
            result = json.loads((root / "runtime.json").read_text())
            self.assertTrue(result["issues"])
            self.assertIsNone(result["revision"])


class PoolReportH2EvidenceTests(unittest.TestCase):
    def campaign(self, mode="calibration", protocol="http2", sizes=(10240,)):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        gateways = ["direct", "ferrum", "ferrum-baseline"]
        (root / "manifest.json").write_text(json.dumps(dict(
            pairs=4, gateways=gateways, payload_sizes=sizes, host_id="host")))
        for pair in range(1, 5):
            folder = root / "pairs" / f"pair_{pair:03d}"
            diagnostics = folder / "diagnostics"
            diagnostics.mkdir(parents=True)
            for gateway in gateways:
                observer_off = mode == "calibration" and gateway == "ferrum-baseline"
                if gateway != "direct":
                    (diagnostics / f"{gateway}_runtime.json").write_text(json.dumps(dict(
                        issues=[], revision="a" * 40, image_id="sha256:off" if observer_off else "sha256:on",
                        config_sha256="b" * 64, started_at="2026-09-18T00:00:00Z", host_pid=31,
                        pool_observer="off" if observer_off else "on", environment=profile.FIXED_ENV)))
                for size in sizes:
                    (folder / f"{gateway}_{protocol}_{size}.json").write_text(json.dumps(
                        traffic_sample(pair, gateway, size)))
                    if gateway != "direct" and not observer_off:
                        (diagnostics / f"{gateway}_{size}_process_usage.json").write_text(json.dumps(
                            capture(15, "h2" if protocol == "http2" else "grpc")))
        return root

    def assert_matrix(self, result, sizes=(10240,)):
        expected = {(pair, gateway, size) for pair in range(1, 5)
                    for gateway in ("direct", "ferrum", "ferrum-baseline") for size in sizes}
        rows = result["observations"]
        self.assertEqual(len(rows), len(expected))
        self.assertEqual({(row["pair"], row["gateway"], row["payload"]) for row in rows}, expected)
        self.assertFalse(result["fully_measured_comparison_eligible"])

    def cli_report(self, root, mode, protocol, expected_exit):
        completed = subprocess.run(
            [sys.executable, str(profile.ROOT / "pool_internal_profile.py"), "report",
             str(root), mode, protocol], capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, expected_exit, completed.stderr)
        return json.loads((root / "pool_profile_report.json").read_text())

    def reject(self, root, gateway, mutate, reason, protocol="http2", cli=False):
        path = root / "pairs/pair_002" / f"{gateway}_{protocol}_10240.json"
        original = path.read_text()
        sample = json.loads(original)
        mutate(sample)
        serialized = json.dumps(sample)
        path.write_text(serialized)
        try:
            if cli:
                result = self.cli_report(root, "calibration", protocol, 1)
            else:
                profile.report(root, "calibration", protocol)
                result = json.loads((root / "pool_profile_report.json").read_text())
            self.assert_matrix(result)
            self.assertFalse(result["traffic_complete"])
            failed = [row for row in result["observations"] if row["traffic_issues"]]
            self.assertEqual(len(failed), 1, failed)
            self.assertEqual((failed[0]["pair"], failed[0]["gateway"]), (2, gateway))
            self.assertEqual(json.dumps(failed[0]["sample"]), serialized)
            self.assertTrue(any(reason in issue for issue in failed[0]["traffic_issues"]), failed[0])
        finally:
            path.write_text(original)

    def test_actual_report_accepts_producer_schema_for_all_arms_protocols_and_sizes(self):
        sizes = profile.MANIFEST["payload_sizes"]
        for mode in ("calibration", "profile"):
            for protocol in ("http2", "grpcs"):
                with self.subTest(mode=mode, protocol=protocol):
                    root = self.campaign(mode, protocol, sizes)
                    result = self.cli_report(root, mode, protocol, 0)
                    self.assert_matrix(result, sizes)
                    self.assertTrue(result["traffic_complete"], result["manifest_issues"])
                    self.assertTrue(result["profiles_complete"], result["manifest_issues"])
                    for row in result["observations"]:
                        self.assertEqual(row["traffic_issues"], [])
                        observation = row["sample"]["h2_observation"]
                        self.assertNotIn("backend_log_limit_reached", observation)
                        if row["gateway"] == "direct":
                            self.assertIsNone(observation["gauges_available"])
                            self.assertEqual(observation["gauge_samples"], [])
                            self.assertFalse(row["profile"]["expected"])
                        elif mode == "calibration" and row["gateway"] == "ferrum-baseline":
                            self.assertTrue(observation["gauges_available"])
                            self.assertFalse(row["profile"]["expected"])

    def test_empty_missing_and_malformed_diagnostics_fail_all_arms(self):
        root = self.campaign()
        mutations = [lambda s: s.pop("h2_observation")]
        for value in ({}, None, [], False, "invalid", [1]):
            mutations.append(lambda s, value=value: s.update(h2_observation=value))
        for gateway in ("direct", "ferrum", "ferrum-baseline"):
            for index, mutate in enumerate(mutations):
                with self.subTest(gateway=gateway, case=index):
                    self.reject(root, gateway, mutate, "H2", cli=index == 1)

    def test_phase_failures_survive_absent_empty_or_invalid_diagnostics_and_controls(self):
        for protocol in ("http2", "grpcs"):
            root = self.campaign(protocol=protocol)
            for gateway in ("direct", "ferrum", "ferrum-baseline"):
                for field in ("transport_errors_total", "transport_events_suppressed",
                              "transport_close_timed_out", "timed_out"):
                    for diagnostic in ("valid", "missing", "empty", "invalid"):
                        with self.subTest(protocol=protocol, gateway=gateway, field=field,
                                          diagnostic=diagnostic):
                            def mutate(sample):
                                sample["phases"][field] = True if field.endswith("timed_out") else 1
                                if diagnostic == "missing":
                                    sample.pop("h2_observation")
                                elif diagnostic == "empty":
                                    sample["h2_observation"] = {}
                                elif diagnostic == "invalid":
                                    sample["h2_observation"] = [1]
                            self.reject(root, gateway, mutate, "H2 phase failure: " + field, protocol)

    def test_phase_status_requires_explicit_typed_fields_on_all_arms(self):
        root = self.campaign()
        for gateway in ("direct", "ferrum", "ferrum-baseline"):
            for field in ("transport_errors_total", "transport_events_suppressed",
                          "transport_close_timed_out", "timed_out"):
                invalid = (None, "", [], 0, "false") if field.endswith("timed_out") else (
                    None, False, 0.0, "0", -1, [])
                mutations = [lambda s: s["phases"].pop(field)]
                mutations += [lambda s, value=value: s["phases"].update({field: value})
                              for value in invalid]
                for index, mutate in enumerate(mutations):
                    with self.subTest(gateway=gateway, field=field, case=index):
                        self.reject(root, gateway, mutate, "missing/malformed H2 phase field: " + field)
            for value in (None, [], {}, "invalid"):
                with self.subTest(gateway=gateway, phases=value):
                    self.reject(root, gateway, lambda s: s.update(phases=value), "H2 phase")

    def test_diagnostic_error_and_suppression_status_are_typed_on_all_arms(self):
        root = self.campaign()
        for gateway in ("direct", "ferrum", "ferrum-baseline"):
            for field, invalid in (
                    ("capture_errors", (None, False, "", {}, [None], ["missing_backend_capture"])),
                    ("backend_errors_observed", (None, False, "0", 0.0, -1, 1)),
                    ("backend_log_limit_reached", (None, 0, "false", [], True))):
                for value in invalid:
                    with self.subTest(gateway=gateway, field=field, value=value):
                        self.reject(root, gateway, lambda s: s["h2_observation"].update({field: value}), "H2")
                if field != "backend_log_limit_reached":
                    with self.subTest(gateway=gateway, missing=field):
                        self.reject(root, gateway, lambda s: s["h2_observation"].pop(field), field)

    def test_explicit_false_backend_limit_marker_is_valid(self):
        root = self.campaign()
        for path in (root / "pairs").glob("pair_*/*.json"):
            sample = json.loads(path.read_text())
            sample["h2_observation"]["backend_log_limit_reached"] = False
            path.write_text(json.dumps(sample))
        result = profile.report(root, "calibration", "http2")
        self.assert_matrix(result)
        self.assertTrue(result["traffic_complete"])

    def test_invalid_measurement_windows_and_elapsed_phases_retain_the_matrix(self):
        root = self.campaign()
        for gateway in ("ferrum", "ferrum-baseline"):
            for field in ("measurement_start_unix_secs", "measurement_secs"):
                mutations = [lambda s: s["phases"].pop(field)]
                mutations += [lambda s, value=value: s["phases"].update({field: value})
                              for value in (None, False, "15", -1, float("nan"), float("inf"), 10**400)]
                for index, mutate in enumerate(mutations):
                    with self.subTest(gateway=gateway, field=field, case=index):
                        self.reject(root, gateway, mutate, "H2 gauge measurement window")
        for gateway in ("direct", "ferrum", "ferrum-baseline"):
            for elapsed in (None, 14, 17, "15", float("nan")):
                with self.subTest(gateway=gateway, elapsed=elapsed):
                    self.reject(root, gateway, lambda s: s["phases"].update(
                        measurement_elapsed_secs=elapsed), "invalid/incomplete measurement phase")

    def test_gateway_gauges_must_be_usable_including_observer_off(self):
        root = self.campaign()
        mutations = [lambda o: o.pop("gauges_available"), lambda o: o.pop("gauge_samples")]
        mutations += [lambda o, value=value: o.update(gauges_available=value)
                      for value in (None, False, 1, "true")]
        mutations += [lambda o, value=value: o.update(gauge_samples=value)
                      for value in (None, [], {}, [None], [{}])]
        mutations += [lambda o: o["gauge_samples"][0].update(error="capture failed"),
                      lambda o: o["gauge_samples"][0].update(unix_secs=9),
                      lambda o: o["gauge_samples"][0].update(unix_secs=25),
                      lambda o: o["gauge_samples"].append({})]
        for field in ("unix_secs", "monotonic_secs", "capture_secs", "gauges"):
            mutations.append(lambda o, field=field: o["gauge_samples"][0].pop(field))
            mutations.append(lambda o, field=field: o["gauge_samples"][0].update({field: None}))
        for field in ("unix_secs", "monotonic_secs", "capture_secs"):
            for value in (False, "0", -1, float("nan"), float("inf"), 10**400):
                mutations.append(lambda o, field=field, value=value:
                                 o["gauge_samples"][0].update({field: value}))
        for field in ("resident_http2_pool_entries", "resident_grpc_pool_entries", "active_connections"):
            mutations.append(lambda o, field=field: o["gauge_samples"][0]["gauges"].pop(field))
            for value in (None, False, "0", -1, float("nan"), float("inf"), 10**400):
                mutations.append(lambda o, field=field, value=value:
                                 o["gauge_samples"][0]["gauges"].update({field: value}))
        for gateway in ("ferrum", "ferrum-baseline"):
            for index, mutate in enumerate(mutations):
                with self.subTest(gateway=gateway, case=index):
                    self.reject(root, gateway, lambda s: mutate(s["h2_observation"]), "H2")


if __name__ == "__main__":
    unittest.main()
