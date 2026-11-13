"""Host-disturbance flags: the rules, replayed hosted runs, and the runner wiring.

The fixtures under ``fixtures/host_disturbance`` are cut from real hosted runs
(``cut_fixture.py`` beside them says how) and keep only what the flags read.
Hosted runs made before the sampler recorded host CPU carry the benchmark's
own processes alone, so those replays exercise the CPU-dip, CPU-per-request
and periodic rules; the host-CPU rules are exercised with built series.
"""

import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[4]
RUNNER = HERE / "run_gateway_protocol_bench.sh"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "host_disturbance"
sys.path.insert(0, str(HERE))

import benchmark_plan  # noqa: E402
import host_disturbance  # noqa: E402

BASE = 1_800_000_000


def expand(fixture, directory):
    """Turn a cut fixture back into the run directory the flags read."""
    directory, lane = Path(directory), fixture["lane"]
    (directory / "manifest.json").write_text(json.dumps(dict(
        gateways=fixture["gateways"], payload_sizes=fixture["payload_sizes"], pairs=fixture["pairs"],
        runner_cpu_model=fixture["source"]["runner_cpu_model"])))
    if fixture["settle"]:
        (directory / "host_settle.json").write_text(json.dumps(dict(schema=1, arms=fixture["settle"])))
    for sample in fixture["samples"]:
        folder = directory / "pairs" / f"pair_{sample['pair']:03d}"
        (folder / "diagnostics").mkdir(parents=True, exist_ok=True)
        start, seconds = sample["measurement"]
        (folder / f"{sample['gateway']}_{lane}_{sample['payload_size']}.json").write_text(json.dumps(dict(
            gateway=sample["gateway"], payload_size=sample["payload_size"], pair=sample["pair"],
            order_position=sample["order_position"], total_requests=sample["total_requests"],
            rps=sample["total_requests"] / seconds, sample_schema=2,
            phases=dict(measurement_start_unix_secs=BASE + start, measurement_secs=seconds))))
        timeline = []
        for time, gateway, backend, *host in sample["series"]:
            processes = [dict(pid=1, start_ticks=1, role="backend", cpu_seconds=backend)]
            if sample["gateway"] != "direct":
                processes.append(dict(pid=2, start_ticks=1, role="gateway", cpu_seconds=gateway))
            point = dict(unix_secs=BASE + time, processes=processes)
            if host:
                client, busy = host
                if client is not None:
                    processes.append(dict(pid=3, start_ticks=1, role="client", cpu_seconds=client))
                point["host"] = dict(busy_cpu_seconds=busy)
            timeline.append(point)
        usage = dict(timeline=timeline)
        if "host_processes" in sample:
            usage["host_processes"] = sample["host_processes"]
        (folder / "diagnostics" / f"{sample['gateway']}_{sample['payload_size']}_process_usage.json"
         ).write_text(json.dumps(usage))
    benchmark_plan.write_summaries(directory, lane, fixture["gateways"], fixture["payload_sizes"],
                                   fixture["pairs"])


class Replay(unittest.TestCase):
    def replay(self, name):
        fixture = json.loads((FIXTURES / name).read_text())
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        expand(fixture, directory)
        report = host_disturbance.annotate(directory, fixture["lane"], fixture["gateways"],
                                           fixture["payload_sizes"], fixture["pairs"])
        flagged = {(row["pair"], row["gateway"], row["payload_size"]): row
                   for row in report["samples"] if row["flags"]}
        return fixture, directory, report, flagged


class ReplayedHostedRuns(Replay):
    def test_dips_every_sixty_seconds_on_an_epyc_7763_runner_are_flagged_as_periodic(self):
        fixture, _, report, flagged = self.replay("periodic_60s_epyc_7763.json")
        self.assertEqual(report["runner_cpu_model"], "AMD EPYC 7763 64-Core Processor")
        self.assertEqual(report["periodic_activity"]["period_seconds"], 60.0)
        self.assertEqual(report["periodic_activity"]["events"], 6)
        self.assertGreaterEqual(report["periodic_activity"]["consecutive_periods"], 3)
        self.assertEqual(report["summary"]["by_flag"], {"cpu_dip": 6, "periodic_60s": 6})
        # Whichever arm is running: direct, the image arm, Envoy and ferrum.
        self.assertEqual({gateway for _, gateway, _ in flagged},
                         {"direct", "ferrum", "envoy", "ferrum-baseline"})
        for row in flagged.values():
            self.assertEqual(row["flags"], ["cpu_dip", "periodic_60s"])
            dip = row["cpu_dips"][0]
            self.assertLess(dip["lowest_share_of_plateau"], 0.85)
            self.assertLessEqual(dip["seconds"], 2.1)
        # Older runs recorded no host CPU: the report says the dip is all it has.
        self.assertFalse(report["host_cpu_recorded"])
        # The settle saw the provisioner react, and a dip that belongs to the
        # periodic activity is not mistaken for a late first-start reaction.
        self.assertGreater(report["settle_provisioner_cpu_seconds"]["ferrum"], 5)
        self.assertNotIn("provisioner_burst_suspected", report["summary"]["by_flag"])

    def test_with_host_cpu_recorded_the_periodic_dips_are_bursts_of_a_named_process(self):
        # The first hosted run made with the sampler's --host-cpu, on an EPYC
        # 7763 runner: what the older runs could only show as a dip is the host
        # busy outside the benchmark, and the process is hv_kvp_daemon.
        _, _, report, flagged = self.replay("host_cpu_periodic_60s_epyc_7763.json")
        self.assertTrue(report["host_cpu_recorded"])
        self.assertEqual(report["summary"]["by_flag"],
                         {"cpu_dip": 7, "host_cpu_burst": 7, "periodic_60s": 7})
        self.assertEqual(report["periodic_activity"]["events"], 7)
        for row in flagged.values():
            self.assertEqual(row["flags"], ["cpu_dip", "host_cpu_burst", "periodic_60s"])
            burst = row["host_cpu_bursts"][0]
            self.assertGreater(burst["excess_cpu_seconds"], 0.9)
            self.assertLess(burst["excess_cpu_seconds"], 1.5)
            named = row["host_processes"][0]
            self.assertEqual(named["comm"], "hv_kvp_daemon")
            self.assertGreater(named["cpu_seconds"], 1.1)
            self.assertLess(named["cpu_seconds"], 1.35)
            # The provisioner's idle background is recorded by the sampler but
            # is neither named beside the sample nor taken for its reaction.
            self.assertNotIn("provisioner_cpu_seconds", row)
        # Every unflagged sample saw the host quiet as well.
        self.assertFalse(any("host_cpu_bursts" in row for row in report["samples"] if not row["flags"]))
        output = io.StringIO()
        host_disturbance.print_report(report, output)
        self.assertNotIn("host CPU was not recorded", output.getvalue())
        self.assertIn("busiest outside the benchmark: hv_kvp_daemon 1.2", output.getvalue())

    def test_cpu_per_request_drift_on_an_epyc_9v45_runner_marks_both_pairs_of_the_arm(self):
        _, _, report, flagged = self.replay("cpu_per_request_drift_epyc_9v45.json")
        self.assertEqual(report["summary"]["by_flag"], {"cpu_per_request_drift": 6})
        for pair in (1, 2):
            drift = flagged[pair, "ferrum", 10240]["cpu_per_request_drift"]
            self.assertEqual((drift["high_pair"], drift["low_pair"]), (2, 1))
            self.assertAlmostEqual(drift["gateway_percent"], 19.9, delta=0.2)
            self.assertAlmostEqual(drift["backend_percent"], 18.2, delta=0.2)
            self.assertIn((pair, "ferrum", 71680), flagged)
            # direct has no gateway: its backend alone moved 6.2% at 70 KiB.
            self.assertNotIn("gateway_percent", flagged[pair, "direct", 71680]["cpu_per_request_drift"])
        # No dip anywhere: the CPU timeline alone would have shown nothing.
        self.assertFalse(any("cpu_dips" in row for row in report["samples"]))
        # The image arm and Envoy agree across pairs and stay unmarked.
        self.assertFalse({"ferrum-baseline", "envoy"} & {gateway for _, gateway, _ in flagged})

    def test_drift_is_judged_per_arm_so_a_steady_arm_beside_drifting_ones_is_not_marked(self):
        _, _, report, flagged = self.replay("cpu_per_request_drift_epyc_9v45_seven_arms.json")
        self.assertEqual({gateway for _, gateway, _ in flagged}, {"ferrum", "envoy", "kong"})
        self.assertEqual(report["summary"]["by_flag"], {"cpu_per_request_drift": 12})
        drift = flagged[1, "ferrum", 10240]["cpu_per_request_drift"]
        self.assertAlmostEqual(drift["gateway_percent"], 33.3, delta=0.2)
        self.assertAlmostEqual(drift["backend_percent"], 31.4, delta=0.2)

    def test_a_first_start_reaction_the_settle_missed_is_suspected_in_the_arm_s_first_cell(self):
        _, _, report, flagged = self.replay("late_first_start_burst.json")
        self.assertEqual(list(flagged), [(1, "ferrum", 10240)])
        row = flagged[1, "ferrum", 10240]
        self.assertEqual(row["flags"], ["cpu_dip", "provisioner_burst_suspected"])
        self.assertAlmostEqual(row["cpu_dips"][0]["seconds"], 2.5, delta=0.1)
        self.assertEqual(row["settle_provisioner_cpu_seconds"], 0.1)
        # Envoy's settle did see the reaction; the image arm's too, in this run.
        self.assertGreater(report["settle_provisioner_cpu_seconds"]["envoy"], 2)

    def test_quiet_runs_are_left_unmarked(self):
        for name in ("quiet_epyc_9v74.json", "quiet_xeon_6975p.json"):
            with self.subTest(name=name):
                _, directory, report, flagged = self.replay(name)
                self.assertEqual(flagged, {})
                self.assertEqual(report["summary"]["samples"], 40)
                self.assertEqual(report["summary"]["flagged"], 0)
                self.assertIsNone(report["periodic_activity"])
                comparisons = json.loads((directory / "paired_comparisons.json").read_text())
                self.assertTrue(comparisons)
                self.assertTrue(all(row["host_disturbance"]["flags"] == [] for row in comparisons))


class WhatAnnotateWrites(Replay):
    def test_flags_land_in_the_sample_the_summary_the_comparison_and_the_report(self):
        fixture, directory, report, _ = self.replay("late_first_start_burst.json")
        lane = fixture["lane"]
        sample = json.loads((directory / "pairs" / "pair_001" / f"ferrum_{lane}_10240.json").read_text())
        self.assertEqual(sample["host_disturbance"]["flags"], ["cpu_dip", "provisioner_burst_suspected"])
        self.assertEqual(sample["host_disturbance"]["schema"], host_disturbance.SCHEMA)
        self.assertIn("gateway_cpu_us_per_request", sample["host_disturbance"])
        # What the sample already says about itself is not repeated.
        self.assertFalse({"gateway", "pair", "payload_size"} & set(sample["host_disturbance"]))
        clean = json.loads((directory / "pairs" / "pair_002" / f"ferrum_{lane}_10240.json").read_text())
        self.assertEqual(clean["host_disturbance"]["flags"], [])
        summary = json.loads((directory / f"ferrum_{lane}_10240.json").read_text())
        self.assertEqual(summary["host_disturbance"]["flags"], ["cpu_dip", "provisioner_burst_suspected"])
        self.assertEqual(summary["host_disturbance"]["samples"],
                         [dict(pair=1, flags=["cpu_dip", "provisioner_burst_suspected"])])
        self.assertEqual([child["host_disturbance"]["flags"] for child in summary["samples"]],
                         [["cpu_dip", "provisioner_burst_suspected"], []])
        comparisons = json.loads((directory / "paired_comparisons.json").read_text())
        touched = [(row["baseline"], row["candidate"], row["payload_size"])
                   for row in comparisons if row["host_disturbance"]["flags"]]
        self.assertEqual(touched, [("direct", "ferrum", 10240), ("ferrum-baseline", "ferrum", 10240)])
        self.assertEqual(comparisons[0]["host_disturbance"]["samples"],
                         [dict(gateway="ferrum", pair=1, flags=["cpu_dip", "provisioner_burst_suspected"])])
        written = json.loads((directory / "host_disturbance.json").read_text())
        self.assertEqual(written["summary"], report["summary"])
        self.assertEqual(written["summary"]["comparisons_flagged"], 2)
        self.assertEqual(written["thresholds"], host_disturbance.THRESHOLDS)

    def test_the_report_file_is_not_taken_for_a_sample(self):
        fixture, directory, _, _ = self.replay("quiet_epyc_9v74.json")
        # benchmark_plan.protocol_runs identifies a flat artifact by the one
        # protocol its root JSON files name; the report must not add another.
        self.assertNotIn("protocol", json.loads((directory / "host_disturbance.json").read_text()))
        flat = tempfile.TemporaryDirectory()
        self.addCleanup(flat.cleanup)
        run = Path(flat.name) / "run_1"
        directory.rename(run)
        self.addCleanup(lambda: run.rename(directory))
        self.assertEqual(benchmark_plan.protocol_runs(flat.name), [(fixture["lane"], run)])

    def test_annotating_twice_changes_nothing_and_a_later_summary_does_not_inherit_a_sample_s_flags(self):
        fixture, directory, report, _ = self.replay("late_first_start_burst.json")
        shape = (fixture["lane"], fixture["gateways"], fixture["payload_sizes"], fixture["pairs"])
        before = {path: path.read_text() for path in directory.rglob("*.json")}
        again = host_disturbance.annotate(directory, *shape)
        self.assertEqual(again["summary"], report["summary"])
        self.assertEqual({path: path.read_text() for path in directory.rglob("*.json")}, before)
        # The adaptive extension summarises again after more pairs: the summary
        # is rebuilt from the samples and must not carry the last sample's flags.
        benchmark_plan.write_summaries(directory, *shape)
        summary = json.loads((directory / f"ferrum-baseline_{fixture['lane']}_10240.json").read_text())
        self.assertNotIn("host_disturbance", summary)
        self.assertIn("host_disturbance", summary["samples"][0])

    def test_report_writes_nothing_and_prints_the_same_table(self):
        fixture = json.loads((FIXTURES / "periodic_60s_epyc_7763.json").read_text())
        with tempfile.TemporaryDirectory() as temporary:
            expand(fixture, temporary)
            before = {path: path.read_text() for path in Path(temporary).rglob("*.json")}
            result = subprocess.run(
                [sys.executable, str(HERE / "host_disturbance.py"), "report", temporary, fixture["lane"]],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({path: path.read_text() for path in Path(temporary).rglob("*.json")}, before)
        lines = result.stdout.splitlines()
        # The run itself prints through annotate: the two tables are the same.
        with tempfile.TemporaryDirectory() as temporary:
            expand(fixture, temporary)
            printed = io.StringIO()
            host_disturbance.print_report(host_disturbance.annotate(
                temporary, fixture["lane"], fixture["gateways"], fixture["payload_sizes"],
                fixture["pairs"]), printed)
        self.assertEqual(printed.getvalue().splitlines(), lines)
        self.assertEqual(lines[0], "[flags] runner CPU: AMD EPYC 7763 64-Core Processor")
        self.assertIn("[flags] host CPU was not recorded in this run", lines[1])
        self.assertEqual(lines[2], "[flags] 6 of 40 samples flagged; 11 of 25 comparisons touched")
        self.assertEqual(lines[3], "[flags] host activity every 60 s: seen in 6 periods over 422.4 s")
        self.assertEqual(len(lines), 10)
        self.assertRegex(lines[4], r"^\[flags\] pair 1 direct +10240  cpu_dip periodic_60s  \(dip to 0\.7\d for 1\.5")


def sample_with(timeline, requests=100000, start=10.0, seconds=10.0, **extra):
    return (dict(total_requests=requests,
                 phases=dict(measurement_start_unix_secs=BASE + start, measurement_secs=seconds)),
            dict(timeline=timeline, **extra))


def series(gateway=2.5, backend=0.7, other=0.3, start=9.0, seconds=12.0, host=True,
           dip=None, burst=None, companion=0.0):
    """A sampler series at 0.5 s. `dip` and `burst` are (from, to, cores) in seconds.

    During a burst the host is busy outside the benchmark; during a dip the
    benchmark's own CPU falls by `cores`. A burst on a saturated host is both.
    """
    timeline, used = [], dict(gateway=0.0, backend=0.0, busy=0.0)
    steps = int(seconds / 0.5)
    for step in range(steps + 1):
        time = start + step * 0.5
        point = dict(unix_secs=BASE + time, processes=[
            dict(pid=1, start_ticks=1, role="backend", cpu_seconds=round(used["backend"], 4)),
            dict(pid=2, start_ticks=1, role="gateway", cpu_seconds=round(used["gateway"], 4))])
        if host:
            point["host"] = dict(busy_cpu_seconds=round(used["busy"], 4))
        timeline.append(point)
        lost = dip[2] if dip and dip[0] <= time < dip[1] else 0.0
        extra = burst[2] if burst and burst[0] <= time < burst[1] else 0.0
        share = 1 - lost / (gateway + backend)
        used["gateway"] += gateway * share * 0.5
        used["backend"] += backend * share * 0.5
        used["busy"] += ((gateway + backend) * share + other + companion + extra) * 0.5
    return timeline


class HostCpuRules(unittest.TestCase):
    def analyse(self, timeline, **extra):
        return host_disturbance.analyse_sample(*sample_with(timeline, **extra))

    def test_a_burst_outside_the_benchmark_is_named_with_its_size_and_the_process(self):
        # One core for two seconds on a saturated host: the benchmark loses it.
        row = self.analyse(
            series(dip=(13.0, 15.0, 1.0), burst=(13.0, 15.0, 1.0)),
            host_processes=[dict(comm="provjobd4157412", pid=900, cpu_seconds=2.1),
                            dict(comm="containerd", pid=901, cpu_seconds=0.05)])
        self.assertNotIn("unavailable", row)
        self.assertTrue(row["host_cpu_recorded"])
        self.assertEqual(row["flags"], ["cpu_dip", "host_cpu_burst", "provisioner_burst"])
        burst = row["host_cpu_bursts"][0]
        self.assertAlmostEqual(burst["seconds"], 2.0, delta=0.01)
        self.assertAlmostEqual(burst["excess_cpu_seconds"], 2.0, delta=0.01)
        self.assertAlmostEqual(burst["peak_cores_above_baseline"], 1.0, delta=0.01)
        self.assertEqual(row["provisioner_cpu_seconds"], 2.1)
        # Only processes worth naming are kept.
        self.assertEqual(row["host_processes"], [dict(comm="provjobd4157412", cpu_seconds=2.1)])

    def test_an_arm_s_own_dip_on_an_idle_host_is_a_dip_and_not_a_host_burst(self):
        row = self.analyse(series(dip=(13.0, 15.0, 1.0)))
        self.assertEqual(row["flags"], ["cpu_dip"])
        self.assertNotIn("host_cpu_bursts", row)
        self.assertAlmostEqual(row["cpu_dips"][0]["lowest_share_of_plateau"], 1 - 1.0 / 3.2, delta=0.01)

    def test_a_steady_companion_process_is_the_cell_s_baseline_not_a_burst(self):
        # Tyk's Redis, or softirq time the kernel charges to no process.
        self.assertEqual(self.analyse(series(companion=0.9))["flags"], [])

    def test_a_small_or_single_sample_excursion_is_not_a_burst(self):
        self.assertEqual(self.analyse(series(burst=(13.0, 15.0, 0.2)))["flags"], [])
        self.assertEqual(self.analyse(series(burst=(13.0, 13.5, 1.0), dip=(13.0, 13.5, 1.0)))["flags"], [])

    def test_only_the_measured_window_counts(self):
        # The client's warm-up before the window and its drain after it.
        self.assertEqual(self.analyse(series(dip=(9.0, 10.0, 2.0)))["flags"], [])
        self.assertEqual(self.analyse(series(dip=(20.0, 21.0, 2.0)))["flags"], [])

    def test_a_provisioner_reaction_outside_the_measured_window_is_recorded_but_not_flagged(self):
        # The sampler's process list covers the client's warm-up and drain. Two
        # CPU-seconds of the provisioner there, with the measured window steady,
        # did not touch the measurement.
        for burst in ((9.0, 10.0, 2.0), (20.0, 21.0, 2.0)):
            with self.subTest(burst=burst):
                row = self.analyse(series(burst=burst),
                                   host_processes=[dict(comm="provjobd7", pid=9, cpu_seconds=2.0)])
                self.assertEqual(row["flags"], [])
                self.assertEqual(row["provisioner_cpu_seconds"], 2.0)
                self.assertEqual(row["host_processes"], [dict(comm="provjobd7", cpu_seconds=2.0)])

    def test_figures_that_are_not_finite_numbers_are_not_used(self):
        self.assertFalse(host_disturbance.is_number(float("nan")))
        self.assertFalse(host_disturbance.is_number(float("inf")))
        self.assertFalse(host_disturbance.is_number(True))
        self.assertFalse(host_disturbance.is_number(10 ** 400))
        self.assertTrue(host_disturbance.is_number(0))
        row = self.analyse(series(), requests=float("nan"))
        self.assertNotIn("gateway_cpu_us_per_request", row)
        self.assertIsNone(row["requests"])
        self.assertEqual(host_disturbance.provisioner_cpu(
            [dict(comm="provjobd1", cpu_seconds=float("nan")), dict(comm="provjobd1", cpu_seconds=0.5)]), 0.5)

    def test_provisioner_cpu_under_a_second_is_its_idle_background(self):
        row = self.analyse(series(), host_processes=[dict(comm="provjobd1", pid=9, cpu_seconds=0.7),
                                                     dict(comm="provjobd1", pid=9, cpu_seconds=0.2)])
        self.assertEqual(row["flags"], [])
        # Named beside the sample only from half a CPU-second up.
        self.assertEqual(row["host_processes"], [dict(comm="provjobd1", cpu_seconds=0.7)])

    def test_a_short_or_missing_series_is_reported_as_not_analysed(self):
        self.assertEqual(self.analyse([])["unavailable"], "no sampler series")
        self.assertEqual(host_disturbance.analyse_sample({}, None)["flags"], [])
        # Too few ticks in the window for a plateau to mean anything: no flags,
        # no figures, and counted as not analysed instead of as clean.
        row = self.analyse(series(seconds=3.0, dip=(10.0, 11.5, 2.0)))
        self.assertEqual(row["flags"], [])
        self.assertNotIn("gateway_cpu_us_per_request", row)
        self.assertEqual(row["unavailable"], "too few sampler ticks inside the measured window")

    def test_cpu_per_request_comes_from_the_measured_window(self):
        row = self.analyse(series(), requests=50000)
        self.assertAlmostEqual(row["gateway_cpu_us_per_request"], 2.5 * 10 / 50000 * 1e6, delta=1)
        self.assertAlmostEqual(row["backend_cpu_us_per_request"], 0.7 * 10 / 50000 * 1e6, delta=1)

    def test_with_host_cpu_recorded_a_late_first_start_reaction_is_seen_not_inferred(self):
        samples = {("ferrum", 10240, 1): dict(self.analyse(series(dip=(13.0, 15.0, 1.0))),
                                              gateway="ferrum", payload_size=10240, pair=1)}
        host_disturbance.flag_suspected_provisioner_bursts(samples, {"ferrum": 0.1}, ["ferrum"], [10240])
        self.assertEqual(samples["ferrum", 10240, 1]["flags"], ["cpu_dip"])


def arm(pairs):
    """{pair: row} for one arm and payload from {pair: (gateway, backend, requests)}."""
    return {pair: dict(flags=[], gateway_cpu_us_per_request=gateway,
                       backend_cpu_us_per_request=backend, requests=requests)
            for pair, (gateway, backend, requests) in pairs.items()}


class CpuPerRequestRules(unittest.TestCase):
    def flags(self, pairs):
        group = arm(pairs)
        host_disturbance.flag_cpu_per_request_drift(group)
        return {pair: row["flags"] for pair, row in group.items()}

    def test_gateway_and_backend_must_both_cost_more_in_the_same_pair(self):
        both = ["cpu_per_request_drift"]
        self.assertEqual(self.flags({1: (64.6, 19.7, 355000), 2: (77.3, 23.2, 294000)}), {1: both, 2: both})
        # Under the threshold, as pairs on a quiet runner are.
        self.assertEqual(self.flags({1: (104.9, 52.7, 176000), 2: (105.4, 52.3, 176000)}), {1: [], 2: []})
        self.assertEqual(self.flags({1: (100.0, 50.0, 90000), 2: (105.0, 52.5, 90000)}), {1: [], 2: []})
        # The gateway alone, or the two in opposite directions, is something else.
        self.assertEqual(self.flags({1: (100.0, 50.0, 90000), 2: (120.0, 50.5, 90000)}), {1: [], 2: []})
        self.assertEqual(self.flags({1: (100.0, 60.0, 90000), 2: (120.0, 50.0, 90000)}), {1: [], 2: []})

    def test_samples_with_too_few_requests_are_not_compared(self):
        # 5 MiB payloads: quiet runners differ by up to 9% there.
        self.assertEqual(self.flags({1: (9000.0, 5000.0, 1900), 2: (9900.0, 5500.0, 1900)}), {1: [], 2: []})

    def test_direct_is_judged_on_the_backend_alone(self):
        self.assertEqual(self.flags({1: (None, 17.9, 990000), 2: (None, 20.1, 990000)}),
                         {1: ["cpu_per_request_drift"], 2: ["cpu_per_request_drift"]})

    def test_one_pair_or_an_unmeasured_pair_gives_no_verdict(self):
        self.assertEqual(self.flags({1: (64.6, 19.7, 355000)}), {1: []})
        self.assertEqual(self.flags({1: (64.6, 19.7, 355000), 2: (None, None, 294000)}), {1: [], 2: []})

    def test_with_more_pairs_any_two_that_disagree_mark_the_arm(self):
        flags = self.flags({1: (100.0, 50.0, 90000), 2: (101.0, 50.5, 90000),
                            3: (112.0, 56.0, 90000), 4: (100.5, 50.2, 90000)})
        self.assertTrue(all(value == ["cpu_per_request_drift"] for value in flags.values()))
        # The backend's dearest pair is not the one whose gateway moved with
        # it: pair 2 against pair 1 is the joint rise, pair 3 is backend alone.
        group = arm({1: (100.0, 50.0, 90000), 2: (120.0, 55.0, 90000),
                     3: (100.0, 60.0, 90000), 4: (100.0, 50.0, 90000)})
        host_disturbance.flag_cpu_per_request_drift(group)
        self.assertTrue(all(row["flags"] == ["cpu_per_request_drift"] for row in group.values()))
        self.assertEqual(group[1]["cpu_per_request_drift"],
                         dict(backend_percent=10.0, gateway_percent=20.0, high_pair=2, low_pair=1))

    def test_pairs_under_the_request_floor_do_not_silence_the_ones_above_it(self):
        # An adaptive extension doubles the duration: pairs 3 and 4 clear the
        # floor that pairs 1 and 2 missed, and they disagree by 20%.
        flags = self.flags({1: (100.0, 50.0, 19000), 2: (100.0, 50.0, 19000),
                            3: (100.0, 50.0, 38000), 4: (120.0, 60.0, 38000)})
        self.assertEqual(flags, {1: [], 2: [], 3: ["cpu_per_request_drift"], 4: ["cpu_per_request_drift"]})
        # One compared pair is not a comparison.
        self.assertEqual(self.flags({1: (100.0, 50.0, 19000), 2: (120.0, 60.0, 38000)}), {1: [], 2: []})


def dips_at(times):
    """{key: row} with one dip per given start time, as analyse_run builds them."""
    return {index: dict(flags=["cpu_dip"], cpu_dips=[dict(start_unix_secs=BASE + time)])
            for index, time in enumerate(times)}


class PeriodicRule(unittest.TestCase):
    def periodic(self, times):
        samples = dips_at(times)
        found = host_disturbance.periodic_activity(samples)
        marked = [times[index] for index, row in samples.items() if "periodic_60s" in row["flags"]]
        return found, marked

    def test_three_consecutive_periods_establish_it_and_a_missed_one_does_not_undo_it(self):
        found, marked = self.periodic([38, 99, 219, 279, 339, 397])
        # The event at 159 fell between two cells; 219 to 397 are four in a row.
        self.assertEqual((found["events"], found["consecutive_periods"]), (6, 4))
        self.assertEqual(marked, [38, 99, 219, 279, 339, 397])
        found, marked = self.periodic([0, 60.5, 119.5])
        self.assertEqual((found["events"], found["consecutive_periods"], found["seconds_spanned"]),
                         (3, 3, 119.5))

    def test_sharing_a_phase_several_periods_apart_is_not_recurrence(self):
        # Six unrelated disturbances; 30.4, 153.6 and 273.4 share a phase with
        # gaps of about 120 s. Nothing here recurs every 60 s.
        self.assertEqual(self.periodic([30.4, 63.4, 136.0, 153.6, 225.1, 273.4]), (None, []))
        self.assertEqual(self.periodic([0, 61, 300, 361]), (None, []))

    def test_two_events_in_one_period_do_not_count_as_two_periods(self):
        self.assertEqual(self.periodic([0, 2, 122]), (None, []))
        found, marked = self.periodic([0, 1.5, 60, 120])
        self.assertEqual(found["events"], 3)
        self.assertEqual(marked, [0, 1.5, 60, 120])

    def test_gaps_must_stay_within_the_tolerance_of_the_period(self):
        self.assertEqual(self.periodic([0, 63, 126]), (None, []))
        self.assertEqual(self.periodic([])[0], None)

    def test_a_period_that_wanders_is_followed_gap_by_gap_and_fitted(self):
        # Start times from a hosted EPYC 7763 run: gaps of 59.1 to 62.4 s, the
        # last event 2.4 s late against a fixed 60 s comb from the first.
        found, marked = self.periodic([15.9, 195.7, 254.8, 315.4, 375.9, 438.3])
        self.assertEqual((found["events"], found["consecutive_periods"]), (6, 5))
        self.assertAlmostEqual(found["fitted_period_seconds"], 60.2, delta=0.1)
        self.assertEqual(len(marked), 6)

    def test_an_unrelated_event_beside_a_periodic_series_is_left_unmarked(self):
        _, marked = self.periodic([10, 70, 95, 130, 190])
        self.assertEqual(marked, [10, 70, 130, 190])


class DriftScope(Replay):
    def test_payloads_of_512_kib_and_above_are_not_compared(self):
        # direct completes more than 20,000 requests at 512 KiB, so the request
        # floor alone would compare it; pairs on quiet runners differ by up to
        # 9% at that size.
        fixture = json.loads((FIXTURES / "periodic_60s_epyc_7763.json").read_text())
        direct = [sample for sample in fixture["samples"]
                  if sample["gateway"] == "direct" and sample["payload_size"] == 512000]
        self.assertTrue(all(sample["total_requests"] > 20000 for sample in direct))
        for sample in direct:
            if sample["pair"] == 2:  # the same CPU for 12% fewer requests
                sample["total_requests"] = int(sample["total_requests"] * 0.88)
        with tempfile.TemporaryDirectory() as temporary:
            expand(fixture, temporary)
            report = host_disturbance.analyse_run(temporary, fixture["lane"], fixture["gateways"],
                                                  fixture["payload_sizes"], fixture["pairs"])
        rows = {row["pair"]: row for row in report["samples"]
                if row["gateway"] == "direct" and row["payload_size"] == 512000}
        self.assertGreater(rows[2]["backend_cpu_us_per_request"],
                           1.1 * rows[1]["backend_cpu_us_per_request"])
        self.assertFalse(any("cpu_per_request_drift" in row["flags"] for row in rows.values()))
        self.assertNotIn("cpu_per_request_drift", report["summary"]["by_flag"])


class SettleRecords(unittest.TestCase):
    def test_reaction_is_read_from_before_the_start_when_recorded_else_from_the_hold(self):
        settle = dict(arms=[
            dict(arm="ferrum", reason="quiet",
                 top_processes=[dict(comm="provjobd7", cpu_seconds=0.04)],
                 host_processes_since_before_start=[dict(comm="provjobd7", cpu_seconds=5.96),
                                                    dict(comm="hv_kvp_daemon", cpu_seconds=1.2)]),
            dict(arm="envoy", reason="quiet", top_processes=[dict(comm="provjobd7", cpu_seconds=2.08)]),
            dict(arm="kong", reason="max_wait", top_processes=[dict(comm="nginx", cpu_seconds=0.5)]),
            dict(arm="tyk", reason="already_started"),
            dict(arm="krakend", reason="unavailable")])
        self.assertEqual(host_disturbance.settle_reactions(settle),
                         {"ferrum": 5.96, "envoy": 2.08, "kong": 0})
        self.assertEqual(host_disturbance.settle_reactions(None), {})

    def test_arms_that_share_an_image_share_its_settle_record(self):
        self.assertEqual(host_disturbance.settle_arm("ferrum-exp-pool"), "ferrum")
        self.assertEqual(host_disturbance.settle_arm("envoy-limit-4"), "envoy")
        self.assertEqual(host_disturbance.settle_arm("ferrum-baseline"), "ferrum-baseline")


class RunnerCpu(unittest.TestCase):
    def test_model_is_added_to_the_manifest_without_losing_anything_in_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "manifest.json"
            manifest.write_text(json.dumps(dict(gateways=["direct"], pairs=2, sample_schema=2)))
            cpuinfo = Path(temporary) / "cpuinfo"
            cpuinfo.write_text("processor\t: 0\nvendor_id\t: AuthenticAMD\n"
                               "model name\t: AMD EPYC 7763 64-Core Processor\nprocessor\t: 1\n"
                               "model name\t: AMD EPYC 7763 64-Core Processor\n")
            self.assertEqual(host_disturbance.record_host(manifest, cpuinfo),
                             "AMD EPYC 7763 64-Core Processor")
            written = json.loads(manifest.read_text())
            self.assertEqual(written["runner_cpu_model"], "AMD EPYC 7763 64-Core Processor")
            self.assertIsInstance(written["runner_cpu_count"], int)
            self.assertEqual({key: written[key] for key in ("gateways", "pairs", "sample_schema")},
                             dict(gateways=["direct"], pairs=2, sample_schema=2))
            # No /proc/cpuinfo (macOS): recorded as unknown, never a failure.
            self.assertIsNone(host_disturbance.record_host(manifest, Path(temporary) / "absent"))
            self.assertIsNone(json.loads(manifest.read_text())["runner_cpu_model"])

    def test_a_missing_manifest_is_an_error_not_a_new_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                host_disturbance.record_host(Path(temporary) / "manifest.json")
            self.assertEqual(list(Path(temporary).iterdir()), [])


class ReportTable(unittest.TestCase):
    def test_a_run_that_could_not_be_analysed_says_so(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "pairs" / "pair_001").mkdir(parents=True)
            (directory / "pairs" / "pair_001" / "direct_http2_10240.json").write_text(
                json.dumps(dict(total_requests=5, order_position=1)))
            report = host_disturbance.analyse_run(directory, "http2", ["direct"], [10240], 1)
            output = io.StringIO()
            host_disturbance.print_report(report, output)
        self.assertEqual(report["summary"], dict(samples=1, flagged=0, not_analysed=1, by_flag={}))
        self.assertIn("[flags] runner CPU: not recorded", output.getvalue())
        self.assertIn("[flags] 1 samples could not be analysed: no usable sampler series", output.getvalue())

    def test_shape_comes_from_the_manifest_unless_given(self):
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "manifest.json").write_text(json.dumps(dict(
                gateways=["direct", "ferrum"], payload_sizes=[10240], pairs=2)))
            self.assertEqual(host_disturbance.run_shape(temporary, None, None, None),
                             (["direct", "ferrum"], [10240], 2))
            self.assertEqual(host_disturbance.run_shape(temporary, "envoy", "1 2", "4"),
                             (["envoy"], [1, 2], 4))
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
            host_disturbance.run_shape(temporary, None, None, None)


class RunnerContract(unittest.TestCase):
    def setUp(self):
        self.source = RUNNER.read_text()
        self.main = self.source.split("# ── Orchestration", 1)[1]

    def test_flags_are_parsed_before_any_work(self):
        for flag in ("--host-flags", "--no-host-flags"):
            result = subprocess.run(
                ["bash", str(RUNNER), "http2", flag, "--pairs", "3"], cwd=REPO_ROOT,
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("EVEN", result.stderr)
            self.assertNotIn("unknown option", result.stderr)

    def test_profile_trace_and_observation_lanes_keep_their_sampler_and_manifest(self):
        self.assertIn("HOST_FLAGS=auto\n", self.source)
        default = self.main.split('if [ "$HOST_FLAGS" = auto ]; then', 1)[1].split(
            'if [ "$HOST_FLAGS" = true ]; then', 1)[0]
        for lane in ("$H1_PROFILE", "$POOL_PROFILE", "$UDP_PROFILE", "$H2_CPU_PROFILE",
                     '"$H1_TRACE" != none', '"$H2_OBSERVE" -eq 1'):
            self.assertIn(lane, default)
        # The sampler gets the extra argument only when the flags are on.
        bench = self.source.split("run_bench() {", 1)[1].split("# ── First-start settle", 1)[0]
        self.assertRegex(bench, r'if \[ "\$HOST_FLAGS" = true \]; then\n\s+sampler_args\+=\(--host-cpu\)')
        self.assertEqual(self.source.count("--host-cpu"), 1 + self.source.count("process_usage.py --host-cpu"))

    def test_the_cpu_model_is_recorded_once_the_manifest_exists_and_cannot_fail_the_run(self):
        record = self.main.index('host_disturbance.py" record-host "$root_output/manifest.json" || true')
        self.assertLess(self.main.index('"sample_schema": 2}, manifest)'), record)
        self.assertLess(record, self.main.index("for PAIR in $(seq"))

    def test_flagging_runs_after_the_last_summary_and_cannot_fail_the_run(self):
        annotate = self.main.index('host_disturbance.py" annotate "$OUTPUT_DIR" "$PROTOCOL"')
        self.assertLess(self.main.rindex('benchmark_plan.py" summarize'), annotate)
        self.assertLess(self.main.rindex("adaptive_extension=sys.argv[3]"), annotate)
        self.assertLess(annotate, self.main.index('echo "[main] done. results in $OUTPUT_DIR"'))
        call = self.main[annotate:self.main.index('echo "[main] done.')]
        self.assertIn('--pairs "$final_pairs"', call)
        self.assertRegex(call, r'\|\| echo "\[flags\] host-disturbance flags could not be computed')
        # Nothing between the samples and the summary reads the flags.
        self.assertNotIn("host_disturbance", (HERE / "benchmark_validity.py").read_text())


if __name__ == "__main__":
    unittest.main()
