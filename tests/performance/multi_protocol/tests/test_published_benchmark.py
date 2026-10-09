"""Summary math and leg classification for summarize_published_benchmark.py."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import summarize_published_benchmark as summary  # noqa: E402


def report(target, rps, p50, p99, errors=0, requests=None):
    return {"protocol": "HTTP/1.1", "target": target, "rps": rps,
            "duration_secs": 10, "concurrency": 200,
            "total_requests": requests if requests is not None else int(rps * 10),
            "warmup_requests": 200, "drain_requests": 0, "total_errors": errors,
            "p50_us": p50, "p99_us": p99}


def write_run(root, suite, run, protocol, gateway, direct, cpu_seconds=None):
    run_dir = root / "raw" / suite / f"run{run}"
    run_dir.mkdir(parents=True, exist_ok=True)
    noise = "Starting gateway...\n{not json}\n"
    body = noise + json.dumps(gateway, indent=2) + "\nlog line\n" + json.dumps(direct, indent=2)
    (run_dir / f"{protocol}.log").write_text(body)
    if cpu_seconds is not None:
        (run_dir / f"{protocol}.cpu.jsonl").write_text(json.dumps(
            {"protocol_key": protocol, "gateway_cpu_seconds": cpu_seconds,
             "wall_seconds": 12.0}) + "\n")


def write_manifest(root, runs, protocols, payload_sizes, latency_duration_secs=0):
    (root / "manifest.json").write_text(json.dumps({"args": {
        "protocols": protocols, "runs": runs, "payload_sizes": payload_sizes,
        "latency_duration_secs": latency_duration_secs}}))


class PublishedBenchmarkSummaryTests(unittest.TestCase):
    def test_classifies_legs_by_port_not_label(self):
        legs = summary.split_legs([
            report("https://127.0.0.1:8443/echo", 1, 1, 1),
            report("https://127.0.0.1:3447/echo", 2, 1, 1),
        ])
        self.assertEqual(legs["gateway"]["rps"], 1)
        self.assertEqual(legs["direct"]["rps"], 2)
        self.assertEqual(summary.target_port("127.0.0.1:5010"), "5010")

    def test_medians_overhead_cpu_and_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_manifest(root, 3, ["http1", "udp"], [64])
            for run, (gw, dr) in enumerate([(100_000, 200_000), (90_000, 200_000),
                                            (110_000, 200_000)], start=1):
                write_run(root, "throughput_64b", run, "http1",
                          report("http://127.0.0.1:8000/echo", gw, 1500, 4000),
                          report("http://127.0.0.1:3001/echo", dr, 900, 2500),
                          cpu_seconds=gw * 10 * 20e-6)
            write_run(root, "throughput_64b", 1, "udp",
                      report("127.0.0.1:5003", 50_000, 2000, 5000, errors=3),
                      report("127.0.0.1:3005", 100_000, 1000, 3000))
            for run in (2, 3):
                write_run(root, "throughput_64b", run, "udp",
                          report("127.0.0.1:5003", 50_000, 2000, 5000),
                          report("127.0.0.1:3005", 100_000, 1000, 3000))
            document = summary.summarize(root)

        http1 = document["suites"]["throughput_64b"]["http1"]
        self.assertEqual(http1["runs_complete"], 3)
        self.assertEqual(http1["gateway_rps_median"], 100_000)
        self.assertAlmostEqual(http1["rps_overhead_pct_median"], 50.0)
        self.assertEqual(http1["added_p50_us_median"], 600)
        # CPU is divided by every request the gateway served in the leg.
        self.assertLess(http1["gateway_cpu_us_per_request_median"], 20.0)
        self.assertGreater(http1["gateway_cpu_us_per_request_median"], 19.9)
        self.assertEqual(http1["flags"], [])
        self.assertEqual(http1["payload_bytes"], 64)

        udp = document["suites"]["throughput_64b"]["udp"]
        self.assertIn("errors", udp["flags"])
        self.assertIsNone(udp["gateway_cpu_us_per_request_median"])

    def test_noisy_runs_are_flagged_and_udp_payload_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_manifest(root, 2, ["udp"], [10240])
            for run, gw in enumerate([50_000, 100_000], start=1):
                write_run(root, "throughput_10240b", run, "udp",
                          report("127.0.0.1:5003", gw, 1, 1),
                          report("127.0.0.1:3005", 200_000, 1, 1))
            document = summary.summarize(root)
            markdown = (root / "summary.md").read_text()
        udp = document["suites"]["throughput_10240b"]["udp"]
        self.assertIn("noisy-gateway", udp["flags"])
        self.assertEqual(udp["payload_bytes"], 2048)
        self.assertIn("| UDP |", markdown)

    def test_missing_manifest_matrix_entry_is_reported_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_manifest(root, 3, ["http1", "grpc"], [64])
            # Only run 1 of 3 ever wrote a log, and grpc never ran at all.
            write_run(root, "throughput_64b", 1, "http1",
                      report("http://127.0.0.1:8000/echo", 100_000, 1, 1),
                      report("http://127.0.0.1:3001/echo", 200_000, 1, 1))
            result = summary.summarize(root)
            http1 = result["suites"]["throughput_64b"]["http1"]
            self.assertEqual(http1["runs_complete"], 1)
            self.assertEqual(http1["runs_expected"], 3)
            grpc = result["suites"]["throughput_64b"]["grpc"]
            self.assertEqual(grpc["runs_complete"], 0)
            self.assertEqual(grpc["runs_expected"], 3)

    def test_missing_protocol_log_is_reported_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_manifest(root, 1, ["http1", "grpc"], [64])
            write_run(root, "throughput_64b", 1, "http1",
                      report("http://127.0.0.1:8000/echo", 10, 1, 1),
                      report("http://127.0.0.1:3001/echo", 20, 1, 1))
            result = summary.summarize(root)
            self.assertEqual(result["suites"]["throughput_64b"]["http1"]["runs_complete"], 1)
            self.assertEqual(result["suites"]["throughput_64b"]["grpc"]["runs_complete"], 0)

    def test_stale_run_directory_fails_instead_of_mixing_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_manifest(root, 1, ["http1"], [64])
            write_run(root, "throughput_64b", 1, "http1",
                      report("http://127.0.0.1:8000/echo", 10, 1, 1),
                      report("http://127.0.0.1:3001/echo", 20, 1, 1))
            (root / "raw" / "throughput_64b" / "run2").mkdir()
            with self.assertRaisesRegex(ValueError, "run2"):
                summary.summarize(root)

    def test_unselected_protocol_and_suite_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_manifest(root, 1, ["http1"], [64])
            write_run(root, "throughput_64b", 1, "http1",
                      report("http://127.0.0.1:8000/echo", 10, 1, 1),
                      report("http://127.0.0.1:3001/echo", 20, 1, 1))
            (root / "raw" / "throughput_64b" / "run1" / "grpc.log").write_text("")
            with self.assertRaisesRegex(ValueError, "grpc.log"):
                summary.summarize(root)

            (root / "raw" / "throughput_64b" / "run1" / "grpc.log").unlink()
            (root / "raw" / "throughput_128b").mkdir()
            with self.assertRaisesRegex(ValueError, "throughput_128b"):
                summary.summarize(root)

    def test_runner_rejects_nonempty_output_before_building_or_writing_manifest(self):
        runner = (Path(__file__).resolve().parents[1] / "run_published_benchmark.sh").read_text()
        refusal = runner.index("Output directory is not empty")
        self.assertLess(refusal, runner.index("cargo build --release --bin ferrum-edge"))
        self.assertLess(refusal, runner.index('"$OUT/manifest.json"'))
        self.assertIn("shopt -s dotglob nullglob", runner)


if __name__ == "__main__":
    unittest.main()
