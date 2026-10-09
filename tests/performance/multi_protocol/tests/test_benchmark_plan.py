import json
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchmark_plan import (extension_decision, gateway_order, normalize_artifact_layout,
                            ordered_gateways, paired_comparison, position_balance,
                            protocol_runs, read_comparisons, summarize, write_summaries)
from benchmark_validity import sample_issues
from process_usage import measurement_usage, parse_stat


def sample(pair, rps=10):
    return dict(pair=pair, host_id="same-host", payload_size=64, duration_secs=1,
                effective_concurrency=2, total_requests=rps, total_errors=0,
                total_bytes=rps * 64, rps=rps, p99_us=500)


class PairedPlanTests(unittest.TestCase):
    def test_single_and_multiple_artifact_layouts_are_both_discovered(self):
        for nested in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                container = root / "gateways-protocol-bench-http3-sha" if nested else root
                run = container / "run_1"
                run.mkdir(parents=True)
                (run / "envoy_http3_10240.json").write_text('{"protocol":"http3"}')
                self.assertEqual(protocol_runs(root), [("http3", run)])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                protocol_runs(directory)

    def test_tables_include_all_experiment_arms(self):
        self.assertEqual(
            ordered_gateways(["ferrum-exp-b", "ferrum", "direct", "ferrum-exp-a", "ferrum"]),
            ["direct", "ferrum", "ferrum-exp-a", "ferrum-exp-b"],
        )

    def test_single_download_is_wrapped_without_changing_raw_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run_1"
            run.mkdir()
            (run / "paired_comparisons.json").write_text('[{"accepted": false}]\n')
            normalize_artifact_layout(root, ["http1-tls"], "a" * 40)
            files = list(root.glob("*/run_*/paired_comparisons.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].read_text(), '[{"accepted": false}]\n')
            normalize_artifact_layout(root, ["http1-tls"], "a" * 40)
            self.assertEqual(list(root.glob("*/run_*/paired_comparisons.json")), files)

    def test_flat_download_never_guesses_a_protocol_or_overwrites_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run_1").mkdir()
            for protocols in ([], ["http2", "http3"], ["../escape"]):
                with self.assertRaises(ValueError):
                    normalize_artifact_layout(root, protocols, "a" * 40)
            (root / ("gateways-protocol-bench-http2-" + "a" * 40)).mkdir()
            with self.assertRaises(FileExistsError):
                normalize_artifact_layout(root, ["http2"], "a" * 40)
            self.assertTrue((root / "run_1").is_dir())

    def test_every_even_pair_count_has_equal_mean_position_for_any_arm_count(self):
        for count in range(2, 8):
            gateways = [f"arm-{i}" for i in range(count)]
            for pairs in range(2, 13, 2):
                rows = position_balance(gateways, pairs)
                self.assertTrue(all(row["mean_position"] == (count + 1) / 2 for row in rows))

    def test_runner_rejects_odd_pairs_before_starting_any_work(self):
        runner = Path(__file__).resolve().parents[1] / "run_gateway_protocol_bench.sh"
        for pairs in ("1", "3", "5", "11"):
            result = subprocess.run(
                ["bash", "tests/performance/multi_protocol/run_gateway_protocol_bench.sh",
                 "http2", "--pairs", pairs], cwd=Path(__file__).resolve().parents[4],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVEN", result.stderr)
        source = runner.read_text()
        self.assertIn("PAIRS=2\nADAPTIVE=false", source)
        self.assertIn('--adaptive) ADAPTIVE=true', source)
        self.assertIn('--no-process-usage) PROCESS_USAGE=false', source)
        self.assertNotIn('require Linux /proc', source)
        self.assertIn("tr '\\n' ' ' || true)", source)

    def test_runner_rejects_invalid_payload_sizes_before_work_or_udp_override(self):
        runner = Path(__file__).resolve().parents[1] / "run_gateway_protocol_bench.sh"
        for protocol in ("http2", "udp", "udp-dtls"):
            for sizes in ("", "-1", "1+1", "64  128", " 64", "64 ", "64\t128",
                          "64\n128", "a[$(printf invalid)]"):
                with self.subTest(protocol=protocol, sizes=sizes):
                    result = subprocess.run(
                        ["bash", str(runner), protocol, "--payload-sizes", sizes],
                        cwd=Path(__file__).resolve().parents[4],
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("--payload-sizes must be", result.stderr)
        # The next validation rejects the run before any build or gateway startup.
        for sizes in ("64", "10240 71680 512000 1048576 5242880"):
            result = subprocess.run(
                ["bash", str(runner), "http2", "--payload-sizes", sizes, "--pairs", "3"],
                cwd=Path(__file__).resolve().parents[4],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn("EVEN", result.stderr)
            self.assertNotIn("--payload-sizes must be", result.stderr)
        source = runner.read_text()
        validation = source.index("[[ ! $PAYLOAD_SIZES =~ ^[0-9]+( [0-9]+)*$ ]]")
        self.assertLess(validation, source.index('udp|udp-dtls) PAYLOAD_SIZES="1024"'))
        self.assertLess(validation, source.index("local bench_wallclock=$(("))

    def test_adaptive_extension_is_opt_in_and_budget_gated(self):
        self.assertEqual(extension_decision(False, True, 100, 20, 2, 1000)
                         ["extension_skipped"], "disabled")
        self.assertEqual(extension_decision(True, False, 100, 20, 2, 1000)
                         ["extension_skipped"], "not needed")
        decision = extension_decision(True, True, 100, 20, 2, 259)
        self.assertFalse(decision["extend"])
        self.assertEqual(decision["extension_skipped"], "budget")
        self.assertEqual(decision["projected_wallclock_secs"], 260)
        self.assertTrue(extension_decision(True, True, 100, 20, 2, 260)["extend"])

    def test_truncated_comparisons_survive_aggregation_as_diagnostic_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "paired_comparisons.json"
            for contents in ("[", "{}", "[4]"):
                path.write_text(contents)
                self.assertEqual(read_comparisons(path), [dict(accepted=False, reason="unparseable")])

    def test_counterbalances_and_rotates_every_arm_including_direct(self):
        gateways = ["direct", "ferrum", "envoy", "ferrum-baseline"]
        orders = [gateway_order(gateways, pair) for pair in range(1, 9)]
        for i in range(0, 8, 2):
            self.assertEqual(orders[i], list(reversed(orders[i + 1])))
        for position in range(4):
            self.assertEqual(sorted(order[position] for order in orders), sorted(gateways * 2))
        self.assertEqual(gateway_order([], 1), [])
        with self.assertRaises(ValueError):
            gateway_order(["ferrum", "ferrum"], 1)

    def test_requires_even_matched_clean_pairs_without_cherry_picking(self):
        baseline = [sample(i) for i in range(1, 5)]
        candidate = [sample(i, 20) for i in range(1, 5)]
        result = paired_comparison(baseline, candidate, 4)
        self.assertTrue(result["accepted"])
        self.assertAlmostEqual(result["ratio"], 2)
        self.assertFalse(result["needs_more_measurement"])
        self.assertTrue(paired_comparison(baseline[:2], candidate[:2], 2)["accepted"])
        self.assertFalse(paired_comparison(baseline[:3], candidate[:3], 3)["accepted"])
        for field, value in (("host_id", "another-host"), ("pair", 5),
                             ("duration_secs", 2), ("effective_concurrency", 1),
                             ("total_errors", 1)):
            changed = [dict(row) for row in candidate]
            changed[1][field] = value
            self.assertFalse(paired_comparison(baseline, changed, 4)["accepted"])
        self.assertFalse(paired_comparison([sample(1)] * 3, [sample(1, 20)] * 3, 3)["accepted"])
        baseline[1]["host_id"] = candidate[1]["host_id"] = "another-host"
        self.assertFalse(paired_comparison(baseline, candidate, 4)["accepted"])

    def test_uncertainty_requests_more_measurement(self):
        result = paired_comparison([sample(i, 100) for i in range(1, 5)],
                                   [sample(i, rps) for i, rps in enumerate((98, 102, 104, 100), 1)], 4)
        self.assertTrue(result["needs_more_measurement"])
        self.assertLess(result["ci95_low"], 1)
        self.assertGreater(result["ci95_high"], 1)

    def test_summary_retains_raw_records_and_legacy_byte_and_rate_contract(self):
        rows = [sample(i, 10 * i) for i in range(1, 5)]
        summary = summarize(rows, 4)
        self.assertEqual(summary["samples"], rows)
        self.assertEqual(summary["rps"], 25)
        self.assertEqual(summary["total_bytes"], summary["total_requests"] * 64)
        self.assertEqual(sample_issues(summary), [])
        rows[1]["total_errors"] = 1
        self.assertTrue(sample_issues(summarize(rows, 4)))
        self.assertTrue(sample_issues(summarize(rows[:2], 4)))
        rows[1] = sample(1)  # duplicate IDs are not a complete pair set
        self.assertTrue(sample_issues(summarize(rows, 4)))

    def test_missing_arm_remains_visible_in_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            write_summaries(directory, "http3", ["direct", "ferrum"], [64], 4)
            row = json.loads((Path(directory) / "ferrum_http3_64.json").read_text())
            self.assertEqual(len(row["samples"]), 4)
            self.assertTrue(sample_issues(row))

    def test_proc_parser_handles_parentheses_and_counts_process_cpu(self):
        fields = ["0"] * 22
        fields[0] = "S"
        fields[11], fields[12], fields[19], fields[21] = "120", "30", "999", "16"
        record = parse_stat("42 (worker (echo)) " + " ".join(fields), 100, 4096)
        self.assertEqual(record, dict(start_ticks=999, cpu_seconds=1.5, rss_bytes=65536,
                                      user_cpu_seconds=1.2, system_cpu_seconds=0.3))

    def test_measurement_cpu_brackets_and_pid_reuse_are_explicit(self):
        timeline = [dict(unix_secs=t, processes=[dict(
            pid=42, start_ticks=1, role="gateway", cpu_seconds=t * 2, rss_bytes=1024)])
            for t in (0.9, 1.1, 1.9, 2.1)]
        timeline.append(dict(unix_secs=2.2, processes=[dict(
            pid=42, start_ticks=2, role="gateway", cpu_seconds=0, rss_bytes=512)]))
        rows = measurement_usage(dict(timeline=timeline), dict(
            measurement_start_unix_secs=1, measurement_secs=1))
        self.assertEqual(len(rows), 2)
        self.assertAlmostEqual(rows[0]["cpu_seconds"], 2.4)
        self.assertAlmostEqual(rows[0]["boundary_slack_secs"], 0.2)
        self.assertTrue(rows[0]["complete_bracket"])
        self.assertFalse(rows[1]["complete_bracket"])
        self.assertNotIn("cpu_seconds", rows[1])

    def test_every_protocol_uses_shared_phases_and_timed_records(self):
        source = (Path(__file__).resolve().parents[1] / "proto_bench.rs").read_text()
        throughput = source.split("// ── Saturation (")[0]
        self.assertEqual(throughput.count("Phases::new("), 7)
        self.assertEqual(throughput.count("phases.finish(handles).await"), 7)
        self.assertNotIn("Instant::now() < deadline", throughput)
        self.assertIn("endpoint.wait_idle()", throughput)
        self.assertIn("connect_with_connector(GrpcConnector {", throughput)
        transport = (Path(__file__).resolve().parents[1] / "src/transport.rs").read_text()
        self.assertIn("let mut io = connections.call(uri).await?;", transport)


if __name__ == "__main__":
    unittest.main()
