import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import udp_internal_profile as profile


def values():
    result = dict.fromkeys(profile.FIELDS, 0)
    result.update(schema=1, pid=1, sample_every=64, publication_interval=2048, slot_capacity=128, registered_slots=1)
    return result


def capture():
    rows = []
    for sample_id, time in enumerate([9.9, 10.5, 11.1]):
        counters = values()
        counters["pending_lookup_calls"] = int(time * 10)
        counters["snapshot_sequence"] = sample_id
        rows.append(dict(unix_secs=time, processes=[dict(pid=31, start_ticks=100, role="gateway")],
                         udp_profile=dict(unix_secs=time, monotonic_secs=time, sample_id=sample_id,
                                          capture_secs=0, sampler_cpu_secs=0, counters=counters,
                                          gateway_bindings=[dict(host_pid=31, start_ticks=100, namespace_pid=1)])))
    return dict(capture_complete=True, timeline=rows)


class UDPInternalProfileTests(unittest.TestCase):
    def test_literal_rust_and_sampler_schema_match(self):
        root = Path(__file__).resolve().parents[4]
        source = (root / "src/udp_profile/schema.rs").read_text()
        names = re.findall(r'^    "([a-z0-9_]+)",$', source, re.M)
        self.assertEqual(names, profile.SCHEMA["counters"])
        self.assertEqual(len(set(names)), len(names))

    def test_metrics_require_every_fixed_field_and_integer(self):
        text = "\n".join(f"{profile.PREFIX}{key} {value}" for key, value in values().items())
        self.assertEqual(profile.parse_metrics(text), values())
        for malformed in [text + "\n" + text, text.replace("schema 1", "schema NaN"),
                          text.replace("schema 1", "schema 2"), "", text + "\nferrum_udp_profile_secret 1"]:
            with self.assertRaises(ValueError):
                profile.parse_metrics(malformed)

    def test_missing_resets_identity_overflow_and_thread_tails_are_explicit(self):
        phases = dict(measurement_start_unix_secs=10, measurement_secs=1)
        self.assertTrue(profile.profile_bracket(capture(), phases)["complete"])
        mutations = [
            lambda c: c["timeline"][1].pop("udp_profile"),
            lambda c: c["timeline"][1]["processes"].clear(),
            lambda c: c["timeline"][1]["processes"][0].update(start_ticks=101),
            lambda c: c["timeline"][1]["udp_profile"]["counters"].update(pending_lookup_calls=0),
            lambda c: c["timeline"][1]["udp_profile"]["counters"].update(counter_overflow=1),
            lambda c: c["timeline"][1]["udp_profile"]["counters"].update(missing_slots=1),
            lambda c: c["timeline"][1]["udp_profile"]["counters"].update(lost_events=1),
            lambda c: c["timeline"][1]["udp_profile"]["counters"].update(unpublished_event_bound=1),
            lambda c: c.update(capture_complete=False),
            lambda c: c.update(timeline=None),
            lambda c: c["timeline"][1].update(udp_profile=[]),
            lambda c: c["timeline"][1]["udp_profile"].update(counters=[]),
            lambda c: c["timeline"][1]["udp_profile"]["counters"].update(pending_lookup_calls=True),
            lambda c: c["timeline"][1]["udp_profile"].update(capture_secs=float("nan")),
            lambda c: c["timeline"][1].update(unix_secs=1),
            lambda c: c["timeline"][1]["udp_profile"].update(gateway_bindings=[]),
            lambda c: c["timeline"][1]["udp_profile"].update(monotonic_secs=0),
            lambda c: c["timeline"][1]["udp_profile"].update(sample_id=0),
            lambda c: c["timeline"][1]["udp_profile"]["counters"].update(snapshot_sequence=0),
            lambda c: c["timeline"][1]["udp_profile"].update(error="HTTPError"),
            lambda c: c["timeline"][1]["udp_profile"]["counters"].update(sample_every=0),
            lambda c: c["timeline"][1]["udp_profile"].update(sampler_cpu_secs=float("nan")),
            lambda c: [row["udp_profile"]["counters"].update(pending_lookup_calls=0)
                       for row in c["timeline"]],
        ]
        for mutate in mutations:
            data = copy.deepcopy(capture())
            mutate(data)
            result = profile.profile_bracket(data, phases)
            self.assertFalse(result["complete"])
            self.assertTrue(result["issues"])
        for invalid in (None, [], dict(measurement_start_unix_secs=float("nan"), measurement_secs=1),
                        dict(measurement_start_unix_secs=10, measurement_secs=-1),
                        dict(measurement_start_unix_secs=10 ** 400, measurement_secs=1)):
            self.assertFalse(profile.profile_bracket(capture(), invalid)["complete"])

        oversized_clock = capture()
        oversized_clock["timeline"][1]["unix_secs"] = 10 ** 400
        result = profile.profile_bracket(oversized_clock,
                                         dict(measurement_start_unix_secs=10, measurement_secs=1))
        self.assertFalse(result["complete"])
        self.assertIn("malformed process capture", result["issues"])

    def test_selection_preserves_declared_policy_and_h2_manifest(self):
        args = ["profile", "udp", "4", "15", "200", "ferrum kong", "1024", "", ""]
        profile.validate_selection(*args)
        for index, replacement in [(1, "http2"), (2, "2"), (3, "60"), (4, "100"),
                                   (5, "ferrum"), (6, "10240"), (7, "other-image"),
                                   (8, "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=1")]:
            invalid = args.copy()
            invalid[index] = replacement
            with self.assertRaises(ValueError):
                profile.validate_selection(*invalid)

    def test_reports_retain_failed_and_missing_echo_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(json.dumps(dict(
                pairs=4, gateways=["direct", "ferrum", "kong"], payload_sizes=[1024], host_id="host")))
            malformed = root / "pairs/pair_001/direct_udp_1024.json"
            malformed.parent.mkdir(parents=True)
            malformed.write_text("[]")
            result = profile.report(root, "profile")
            self.assertEqual(len(result["observations"]), 12)
            self.assertFalse(result["traffic_complete"])
            self.assertFalse(result["profiles_complete"])
            self.assertFalse(result["fully_measured_comparison_eligible"])
            self.assertTrue(all(row["traffic_issues"] for row in result["observations"]))


    def test_oversized_numeric_fields_retain_full_report_and_profile_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateways = ["direct", "ferrum", "kong"]
            (root / "manifest.json").write_text(json.dumps(dict(
                pairs=4, gateways=gateways, payload_sizes=[1024], host_id="host")))
            for pair in range(1, 5):
                folder = root / "pairs" / f"pair_{pair:03d}"
                folder.mkdir(parents=True)
                for gateway in gateways:
                    gauges = {name: dict(min=200, max=200, mean=200)
                              for name in ("active_workers", "active_connections",
                                           "active_streams", "queued_requests")}
                    sample = dict(sample_schema=2, gateway=gateway, pair=pair, host_id="host",
                        effective_concurrency=200, warmup_requests=200, duration_secs=15,
                        total_errors=0, total_requests=150, payload_size=1024, total_bytes=153600, rps=10,
                        phases=dict(measurement_start_unix_secs=10, measurement_secs=15,
                                    measurement_elapsed_secs=15),
                        observed=dict(samples=10, workers_retired_before_deadline=0,
                                      workers_at_barrier=200, **gauges),
                        process_usage=dict(processes=[{}], measurement=[
                            dict(role=role, complete_bracket=True, cpu_seconds=1)
                            for role in ("gateway", "backend", "client")]))
                    if pair == 1 and gateway == "direct":
                        sample["rps"] = 10 ** 400
                    (folder / f"{gateway}_udp_1024.json").write_text(json.dumps(sample))
                    if gateway == "ferrum":
                        usage = capture()
                        for row, timestamp in zip(usage["timeline"], (9.9, 25.5, 26.1)):
                            row["unix_secs"] = timestamp
                            row["udp_profile"]["unix_secs"] = timestamp
                            row["udp_profile"]["monotonic_secs"] = timestamp
                        if pair == 1:
                            usage["timeline"][1]["unix_secs"] = 10 ** 400
                        diagnostics = folder / "diagnostics"
                        diagnostics.mkdir()
                        (diagnostics / "ferrum_1024_process_usage.json").write_text(
                            json.dumps(usage))

            result = profile.report(root, "profile")
            self.assertEqual(len(result["observations"]), 12)
            self.assertFalse(result["traffic_complete"])
            self.assertFalse(result["profiles_complete"])
            self.assertIn("non-positive/invalid throughput",
                          result["observations"][0]["traffic_issues"])
            ferrum = next(row for row in result["observations"]
                          if row["pair"] == 1 and row["gateway"] == "ferrum")
            self.assertIn("malformed process capture", ferrum["profile"]["issues"])
            saved = json.loads((root / "udp_profile_report.json").read_text())
            self.assertEqual(len(saved["observations"]), 12)
            self.assertFalse(saved["traffic_complete"])
            self.assertFalse(saved["profiles_complete"])


    def test_valid_traffic_does_not_imply_complete_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateways = ["direct", "ferrum", "kong"]
            (root / "manifest.json").write_text(json.dumps(dict(
                pairs=4, gateways=gateways, payload_sizes=[1024], host_id="host")))
            for pair in range(1, 5):
                folder = root / "pairs" / f"pair_{pair:03d}"
                folder.mkdir(parents=True)
                for gateway in gateways:
                    gauges = {name: dict(min=200, max=200, mean=200)
                              for name in ("active_workers", "active_connections", "active_streams", "queued_requests")}
                    sample = dict(sample_schema=2, gateway=gateway, pair=pair, host_id="host",
                        effective_concurrency=200, warmup_requests=200, duration_secs=15,
                        total_errors=0, total_requests=150, payload_size=1024, total_bytes=153600, rps=10,
                        phases=dict(measurement_secs=15, measurement_elapsed_secs=15),
                        observed=dict(samples=10, workers_retired_before_deadline=0,
                                      workers_at_barrier=200, **gauges),
                        process_usage=dict(processes=[{}], measurement=[
                            dict(role=role, complete_bracket=True, cpu_seconds=1)
                            for role in ("gateway", "backend", "client")]))
                    (folder / f"{gateway}_udp_1024.json").write_text(json.dumps(sample))
            result = profile.report(root, "profile")
            self.assertTrue(result["traffic_complete"])
            self.assertFalse(result["profiles_complete"])
            self.assertFalse(result["fully_measured_comparison_eligible"])
            self.assertFalse(result["kong_session_comparability"]["complete"])
            self.assertIsNone(result["kong_session_comparability"]["effective_values"])
            # Even ideal Ferrum publication and successful traffic cannot
            # establish native Kong session lifetime from a client gauge.
            from unittest.mock import patch
            for pair in range(1, 5):
                diagnostics = root / "pairs" / f"pair_{pair:03d}" / "diagnostics"
                diagnostics.mkdir()
                (diagnostics / "ferrum_1024_process_usage.json").write_text("{}")
            with patch.object(profile, "profile_bracket", return_value=dict(complete=True)):
                result = profile.report(root, "profile")
            self.assertTrue(result["traffic_complete"])
            self.assertTrue(result["profiles_complete"])
            self.assertFalse(result["fully_measured_comparison_eligible"])
            self.assertTrue(all("error" in row["kong_readback"] for row in result["observations"]
                                if row["gateway"] == "kong"))

    def test_partial_retry_error_accounting_and_histograms_are_validated(self):
        counters = values()
        counters.update(reply_tx_calls=3, reply_tx_requested_slots=8, reply_tx_sent_slots=2,
                        reply_tx_remaining_slots=4, reply_tx_error_slots=2,
                        reply_tx_requested_slots_2_4=3)
        self.assertEqual(profile.counter_relations(counters), [])
        counters["reply_tx_sent_slots"] += 1
        self.assertTrue(profile.counter_relations(counters))


class RawFailureTests(unittest.TestCase):
    def test_failed_parsing_retains_raw_family_without_zero_fill(self):
        from unittest.mock import MagicMock, patch
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = (
            b"ferrum_udp_profile_schema NaN\nother_metric{identity=secret} 1\n")
        with patch.object(profile.urllib.request, "build_opener", return_value=opener):
            row = profile.snapshot()
        self.assertNotIn("counters", row)
        self.assertEqual(row["error"], "ValueError")
        self.assertEqual(row["raw_profile_text"], "ferrum_udp_profile_schema NaN")
        self.assertNotIn("secret", row["raw_profile_text"])

    def test_udp_lane_does_not_enable_ordinary_experiment(self):
        root = Path(__file__).resolve().parents[1]
        self.assertIs(json.loads((root / "experiment.json").read_text())["enabled"], False)
        self.assertEqual(profile.MANIFEST["scenario"], "existing_echo_200")
        self.assertEqual(set(profile.MANIFEST["unimplemented_scenarios"]),
                         {"fixed_locality", "seeded_bursts", "setup_churn"})


if __name__ == "__main__":
    unittest.main()
