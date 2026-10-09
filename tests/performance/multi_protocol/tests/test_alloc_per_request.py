"""Allocations-per-request summarizer and runner contract (#6022 item 1)."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HARNESS = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(HARNESS))
from alloc_per_request import parse_metrics, record, summarize  # noqa: E402

RUNNER = HARNESS / "alloc_per_request.sh"


def metrics(alloc, zeroed=0, realloc=0, dealloc=0, requested=0, unpublished=0, lost=0,
            missing=0, installed=1):
    values = dict(schema=1, allocator_installed=installed, unpublished_events=unpublished,
                  lost_events=lost, missing_slots=missing, alloc_process_alloc_calls=alloc,
                  alloc_process_zeroed_calls=zeroed, alloc_process_realloc_calls=realloc,
                  alloc_process_dealloc_calls=dealloc,
                  alloc_process_successful_requested_bytes=requested)
    lines = ["# HELP unrelated_metric x", "unrelated_metric 7"]
    lines += [f"ferrum_h1_profile_{name} {value}" for name, value in values.items()]
    return "\n".join(lines) + "\n"


def backend(http, grpc=0):
    return json.dumps(dict(h2_tls_accepted=0, h2_tls_handshakes=0, grpcs_accepted=0,
                           http_echo_requests=http, grpc_echo_requests=grpc))


def write_run(directory, before, after, idle=None, echoes=(0, 1000), client_errors=0,
              exit_code="0"):
    directory.mkdir(parents=True)
    (directory / "metrics_before.txt").write_text(before)
    (directory / "metrics_after.txt").write_text(after)
    (directory / "backend_before.json").write_text(backend(echoes[0]))
    (directory / "backend_after.json").write_text(backend(echoes[1]))
    (directory / "time_before.txt").write_text("100.0\n")
    (directory / "time_after.txt").write_text("120.0\n")
    if idle is not None:
        (directory / "metrics_idle.txt").write_text(idle)
        (directory / "time_idle.txt").write_text("125.0\n")
    (directory / "client.json").write_text(json.dumps({"total_errors": client_errors, "rps": 50}))
    (directory / "client.exit").write_text(exit_code + "\n")


class ParseTests(unittest.TestCase):
    def test_reads_profile_counters_and_ignores_other_metrics(self):
        counters = parse_metrics(metrics(5, zeroed=2))
        self.assertEqual(counters["alloc_process_alloc_calls"], 5)
        self.assertEqual(counters["alloc_process_zeroed_calls"], 2)
        self.assertNotIn("unrelated_metric", counters)

    def test_refuses_missing_duplicate_or_uninstalled_counters(self):
        with self.assertRaises(ValueError):
            parse_metrics("ferrum_h1_profile_schema 1\n")
        with self.assertRaises(ValueError):
            parse_metrics(metrics(5) + "ferrum_h1_profile_lost_events 0\n")
        with self.assertRaises(ValueError):
            parse_metrics(metrics(5, installed=0))
        with self.assertRaises(ValueError):
            parse_metrics(metrics(5) + "ferrum_h1_profile_bogus -1\n")


class RecordTests(unittest.TestCase):
    def test_divides_allocator_calls_by_backend_echoes(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / "candidate-r1"
            write_run(run, metrics(1000, zeroed=10, realloc=50, dealloc=900, requested=64_000,
                                   unpublished=30),
                      metrics(26_000, zeroed=1010, realloc=2050, dealloc=27_900,
                              requested=2_064_000, unpublished=20),
                      idle=metrics(26_100, zeroed=1010), echoes=(500, 1500))
            result = record(run)
            self.assertNotIn("error", result)
            self.assertEqual(result["requests"], 1000)
            self.assertEqual(result["allocations_per_request"], 26.0)
            self.assertEqual(result["reallocations_per_request"], 2.0)
            self.assertEqual(result["deallocations_per_request"], 27.0)
            self.assertEqual(result["requested_bytes_per_request"], 2000.0)
            self.assertEqual(result["unpublished_events_bound_per_request"], 0.05)
            self.assertTrue(result["complete"])
            # 100 idle allocations over 5 s, scaled to the 20 s window.
            self.assertEqual(result["idle_allocations_per_second"], 20.0)
            self.assertEqual(result["background_allocations_per_request_estimate"], 0.4)

    def test_failures_are_errors_not_zero_allocations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            failed = root / "failed"
            failed.mkdir()
            (failed / "failure.txt").write_text("gateway did not start\n")
            self.assertEqual(record(failed)["error"], "gateway did not start")

            stalled = root / "stalled"
            write_run(stalled, metrics(10), metrics(20), echoes=(5, 5))
            self.assertIn("not advancing", record(stalled)["error"])

            restarted = root / "restarted"
            write_run(restarted, metrics(50), metrics(20))
            self.assertIn("went backwards", record(restarted)["error"])

            client = root / "client"
            write_run(client, metrics(10), metrics(20), client_errors=3)
            self.assertEqual(record(client)["error"], "3 client errors")

            lost = root / "lost"
            write_run(lost, metrics(10), metrics(20, lost=1))
            self.assertFalse(record(lost)["complete"])


class SummaryTests(unittest.TestCase):
    def test_summarizes_medians_and_candidate_minus_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "candidate-revision.txt").write_text("c" * 40 + "\n")
            (output / "baseline-revision.txt").write_text("b" * 40 + "\n")
            for round_number, (cand, base) in enumerate(((24, 21), (25, 22), (24, 22)), 1):
                write_run(output / "raw" / "h1" / f"candidate-r{round_number}",
                          metrics(0), metrics(cand * 1000))
                write_run(output / "raw" / "h1" / f"baseline-r{round_number}",
                          metrics(0), metrics(base * 1000))
            step_summary = output / "step-summary.md"
            settings = dict(profile="release", duration=20, concurrency=32, payload_size=1024,
                            rounds=3)
            with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(step_summary)}):
                summary = summarize(output, ["h1"], ["candidate", "baseline"], 3, settings)
            entry = summary["paths"]["h1"]
            self.assertEqual(entry["candidate"]["allocations_per_request"],
                             {"median": 24.0, "min": 24.0, "max": 25.0, "runs": 3})
            self.assertEqual(entry["baseline"]["allocations_per_request"]["median"], 22.0)
            self.assertEqual(entry["candidate_minus_baseline_median"], 2.0)
            self.assertTrue(summary["complete"])
            self.assertEqual(summary["revisions"]["baseline"], "b" * 40)
            self.assertIn("+2.00", step_summary.read_text())
            self.assertTrue((output / "raw" / "h1" / "candidate-r1" / "result.json").is_file())
            self.assertEqual(json.loads((output / "summary.json").read_text())["complete"], True)

    def test_a_missing_round_makes_the_summary_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            write_run(output / "raw" / "grpc" / "candidate-r1", metrics(0), metrics(30_000))
            settings = dict(profile="ci-release", duration=5, concurrency=8, payload_size=64,
                            rounds=2)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
                summary = summarize(output, ["grpc"], ["candidate"], 2, settings)
            self.assertFalse(summary["complete"])
            self.assertEqual(summary["paths"]["grpc"]["candidate"]["errors"],
                             ["candidate-r2: run directory missing"])
            self.assertIn("Incomplete", (output / "summary.md").read_text())


class RunnerContractTests(unittest.TestCase):
    def run_runner(self, *args):
        return subprocess.run(["bash", str(RUNNER), *args], cwd=REPO_ROOT,
                              capture_output=True, text=True, timeout=5)

    def test_invalid_arguments_fail_before_any_build_or_process(self):
        cases = [
            ((), "--output is required"),
            (("--output", "x", "--baseline", "HEAD"), "full 40-hex commit SHA"),
            (("--output", "x", "--profile", "dev"), "--profile must be"),
            (("--output", "x", "--duration", "0"), "positive integers"),
            (("--output", "x", "--rounds", "1+1"), "positive integers"),
            (("--output", "x", "--paths", "h1 h4"), "unknown path: h4"),
            (("--output", "x", "--paths", ""), "at least one path"),
        ]
        for args, message in cases:
            with self.subTest(args=args):
                result = self.run_runner(*args)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(message, result.stderr)
        self.assertFalse((REPO_ROOT / "x").exists())

    def test_gateway_is_the_counting_build_started_with_run(self):
        source = RUNNER.read_text()
        self.assertIn("--features bench-h1-profile --bin ferrum-edge", source)
        self.assertIn("exec ./target/release/ferrum-edge run", source)
        self.assertIn("^ferrum_h1_profile_allocator_installed 1$", source)
        # Ambient FERRUM_* settings cannot change the measured path.
        self.assertIn('case "$name" in FERRUM_*) unset "$name" ;; esac', source)

    def test_cleanup_removes_the_baseline_worktree_and_temp_dir(self):
        source = RUNNER.read_text()
        cleanup = source[source.index("cleanup() {"):source.index("trap cleanup EXIT")]
        self.assertIn('worktree remove --force "$WORK/baseline-src"', cleanup)
        self.assertIn('rm -rf "$WORK"', cleanup)

    def test_hosted_duration_is_bounded_against_the_job_timeout(self):
        workflow = (REPO_ROOT / ".github/workflows/alloc-per-request.yml").read_text()
        duration = workflow[workflow.index("      duration:"):workflow.index("      rounds:")]
        self.assertIn("type: choice", duration)
        self.assertIn('options: ["5", "10", "20", "30"]', duration)
        self.assertIn("timeout-minutes: 240", workflow)


if __name__ == "__main__":
    unittest.main()
