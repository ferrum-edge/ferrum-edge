import sys
import json
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_validity import bucket_issues, expected_rows, sample_issues, throughput_value


def clean():
    return dict(total_requests=10, total_errors=0, total_bytes=10240, payload_size=1024, rps=5)


class BenchmarkValidityTests(unittest.TestCase):
    def test_startup_failure_still_has_expected_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            self.assertIsNone(expected_rows(path))
            (path / "manifest.json").write_text(json.dumps({
                "gateways": ["ferrum", "envoy"], "payload_sizes": [10240, 5242880]}))
            self.assertEqual(expected_rows(path), [
                ("ferrum", 10240), ("ferrum", 5242880),
                ("envoy", 10240), ("envoy", 5242880)])
            self.assertTrue(bucket_issues([], 3))

    def test_malformed_manifest_does_not_look_like_an_empty_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            malformed = (
                "{",
                json.dumps({"gateways": ["ferrum"]}),
                json.dumps({"gateways": "ferrum", "payload_sizes": [1024]}),
                json.dumps({"gateways": ["ferrum"], "payload_sizes": [True]}),
            )
            for contents in malformed:
                (path / "manifest.json").write_text(contents)
                self.assertIsNone(expected_rows(path))

    def test_all_iterations_must_be_clean(self):
        self.assertEqual(bucket_issues([clean()] * 3, 3), [])
        bad = dict(clean(), total_errors=1)
        self.assertTrue(bucket_issues([clean(), bad, clean()], 3))
        self.assertTrue(bucket_issues([clean()], 3))
        self.assertTrue(bucket_issues([], 3))

    def test_zero_work_is_not_an_error_free_sample(self):
        self.assertTrue(sample_issues(dict(clean(), total_requests=0, total_bytes=0, rps=0)))

    def test_phase_records_require_full_barrier_and_resource_evidence(self):
        sample = dict(clean(), sample_schema=2, duration_secs=2, effective_concurrency=2,
                      warmup_requests=2,
                      phases=dict(measurement_secs=2, measurement_elapsed_secs=2.01, timed_out=False),
                      observed=dict(samples=5, workers_at_barrier=2,
                                    workers_retired_before_deadline=0),
                      process_usage=dict(processes=[dict(pid=i, role=role) for i, role in
                                                    enumerate(("client", "backend", "gateway"))]))
        for name in ("active_workers", "active_connections", "active_streams", "queued_requests"):
            sample["observed"][name] = dict(min=0, max=2, mean=1)
        sample["process_usage"]["measurement"] = [dict(p, complete_bracket=True, cpu_seconds=0.5)
                                                      for p in sample["process_usage"]["processes"]]
        self.assertEqual(sample_issues(sample), [])
        # Post-measurement transport cleanup is diagnostic, not an echo error.
        sample["phases"]["transport_close_timed_out"] = True
        self.assertEqual(sample_issues(sample), [])
        for elapsed in (1.99, 3, None, float("nan")):
            phases = dict(sample["phases"], measurement_elapsed_secs=elapsed)
            self.assertTrue(sample_issues(dict(sample, phases=phases)))
        usage = sample["process_usage"]
        usage["missing_pids"] = [999]  # never observed transient container process
        self.assertEqual(sample_issues(sample), [])
        for role in ("client", "backend", "gateway"):
            for absent in (False, True):
                records = [dict(p) for p in usage["measurement"]]
                if absent:
                    records = [p for p in records if p["role"] != role]
                else:
                    next(p for p in records if p["role"] == role)["complete_bracket"] = False
                issues = sample_issues(dict(sample, process_usage=dict(usage, measurement=records)))
                self.assertIn(f"incomplete {role} measurement bracket", issues)
        self.assertTrue(sample_issues(dict(sample, process_usage=dict(available=False))))
        for field, value in (("phases", None), ("observed", None),
                             ("warmup_requests", 1), ("process_usage", {})):
            self.assertTrue(sample_issues(dict(sample, **{field: value})))
        self.assertTrue(sample_issues(dict(sample, phases=dict(measurement_secs=2, timed_out=True))))
        self.assertTrue(sample_issues(dict(sample, observed=dict(
            samples=5, workers_at_barrier=2, workers_retired_before_deadline=1))))
        self.assertTrue(sample_issues(dict(sample, process_usage=dict(processes=42))))

    def test_failure_placeholders_and_malformed_measurements(self):
        for sample in [{}, {"error": "bench wallclock timeout", "rps": 0},
                       dict(clean(), total_bytes=10239), dict(clean(), total_errors=None),
                       dict(clean(), rps=float("nan")), dict(clean(), rps=float("inf"))]:
            with self.subTest(sample=sample):
                self.assertTrue(sample_issues(sample))
        self.assertEqual(throughput_value(dict(rps=float("nan"))), 0)

    def test_oversized_integer_throughput_is_invalid_without_aborting(self):
        self.assertEqual(sample_issues(clean()), [])
        sample = dict(clean(), rps=10 ** 400)
        self.assertIn("non-positive/invalid throughput", sample_issues(sample))
        self.assertEqual(throughput_value(sample), 0)


if __name__ == "__main__":
    unittest.main()
