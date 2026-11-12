"""First-start settle: the hold decision, the /proc readers, and the runner wiring.

On GitHub-hosted runners the provisioner's job daemon uses about one core for
four to five seconds the first time a new binary or container image runs in a
job. The benchmark runner starts every distinct image once before pair 1 and
waits, through ``host_settle.py``, until the host is quiet. These tests pin the
wait rule without a live host, and the runner's side of the contract from its
source.
"""

import argparse
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
sys.path.insert(0, str(HERE))

import host_settle  # noqa: E402


def settle(**overrides):
    values = dict(min_hold=25.0, quiet_seconds=3.0, max_wait=60.0, quiet_cores=0.2, burst_cores=0.4)
    values.update(overrides)
    return host_settle.Settle(**values)


class SettleRuleTests(unittest.TestCase):
    def test_quiet_before_the_minimum_hold_does_not_release(self):
        # The host's reaction starts up to ~12 s after the start, so an early
        # quiet spell is not evidence that it is over.
        state = settle()
        for _ in range(20):
            state.observe(0.5, 0.01)
        self.assertGreaterEqual(state.quiet_run, state.quiet_seconds)
        self.assertIsNone(state.verdict(10.0))
        self.assertEqual(state.verdict(25.0), "quiet")

    def test_a_burst_that_outlasts_the_minimum_hold_extends_it(self):
        state = settle()
        for _ in range(60):  # 30 s of one busy core
            state.observe(0.5, 0.95)
        self.assertIsNone(state.verdict(30.0))
        for _ in range(5):  # 2.5 s quiet: not yet a full quiet run
            state.observe(0.5, 0.02)
        self.assertIsNone(state.verdict(32.5))
        state.observe(0.5, 0.02)
        self.assertEqual(state.verdict(33.0), "quiet")
        self.assertAlmostEqual(state.burst_seconds, 30.0)
        self.assertAlmostEqual(state.peak_busy_cores, 0.95)

    def test_activity_resets_the_quiet_run(self):
        state = settle(min_hold=0.0)
        for _ in range(5):
            state.observe(0.5, 0.0)
        state.observe(0.5, 0.3)  # above quiet, below burst
        self.assertEqual(state.quiet_run, 0.0)
        self.assertEqual(state.burst_seconds, 0.0)
        self.assertIsNone(state.verdict(3.0))

    def test_a_host_that_is_never_quiet_is_released_at_the_cap(self):
        state = settle()
        for _ in range(200):
            state.observe(0.5, 1.5)
        self.assertIsNone(state.verdict(59.9))
        self.assertEqual(state.verdict(60.0), "max_wait")

    def test_quiet_wins_when_both_conditions_hold_at_the_cap(self):
        state = settle()
        for _ in range(10):
            state.observe(0.5, 0.0)
        self.assertEqual(state.verdict(60.0), "quiet")


class ProcReaderTests(unittest.TestCase):
    def test_busy_time_excludes_idle_iowait_and_steal(self):
        cpu = host_settle.parse_cpu_line(
            "cpu  100 5 40 9000 70 3 2 600 0 0\ncpu0 1 1 1 1 1 1 1 1 0 0\n"
        )
        self.assertEqual(cpu["steal"], 600)
        self.assertEqual(host_settle.busy_ticks(cpu), 100 + 5 + 40 + 3 + 2)

    def test_missing_or_malformed_stat_is_unavailable(self):
        self.assertIsNone(host_settle.parse_cpu_line(""))
        self.assertIsNone(host_settle.parse_cpu_line("cpu  1 2 x 4 5 6 7 8\n"))
        self.assertIsNone(host_settle.parse_cpu_line("cpu  1 2 3\n"))

    def test_process_names_with_spaces_and_parentheses_parse(self):
        fields = ["S"] + ["0"] * 10 + ["7", "5"] + ["0"] * 6 + ["4242"] + ["0"] * 20
        raw = "912 (prov jobd (x)) " + " ".join(fields)
        self.assertEqual(host_settle.parse_process_stat(raw), ("prov jobd (x)", 12, 4242))
        self.assertIsNone(host_settle.parse_process_stat("912 no-comm S 0"))


class WaitTests(unittest.TestCase):
    def arguments(self, root, output, **overrides):
        values = dict(arm="ferrum", image="ferrum-edge:bench", since=0.0, output=str(output),
                      min_hold=0.0, quiet_seconds=0.0, max_wait=60.0, quiet_cores=0.2,
                      burst_cores=0.4, interval=0.5, top=3, proc_root=str(root))
        values.update(overrides)
        return argparse.Namespace(**values)

    def write_stat(self, root, busy, processes):
        (root / "stat").write_text(f"cpu  {busy} 0 0 100000 0 0 0 0 0 0\n")
        for pid, (comm, ticks) in processes.items():
            directory = root / str(pid)
            directory.mkdir(exist_ok=True)
            fields = ["S"] + ["0"] * 10 + [str(ticks), "0"] + ["0"] * 6 + ["1"] + ["0"] * 20
            (directory / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields))

    def test_host_without_proc_is_recorded_and_not_held(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "host_settle.json"
            record = host_settle.wait(
                self.arguments(Path(temporary) / "absent", output, min_hold=25.0, quiet_seconds=3.0),
                sleep=self.fail, now=lambda: 0.0)
            self.assertEqual(record["reason"], "unavailable")
            self.assertFalse(record["available"])
            self.assertEqual(json.loads(output.read_text())["arms"], [record])

    def test_hold_follows_the_burst_and_names_the_process_that_caused_it(self):
        ticks = host_settle.clock_ticks()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir()
            output = Path(temporary) / "host_settle.json"
            clock = [100.0]
            # One busy core for 4 s (8 samples), then idle.
            busy = [0]

            def sleep(interval):
                clock[0] += interval
                step = round((clock[0] - 100.0) / 0.5)
                if step <= 8:
                    busy[0] += int(ticks * interval)
                self.write_stat(root, busy[0], {77: ("provjobd123", busy[0]), 78: ("ferrum-edge", 1)})

            self.write_stat(root, 0, {77: ("provjobd123", 0), 78: ("ferrum-edge", 1)})
            record = host_settle.wait(
                self.arguments(root, output, since=99.0, min_hold=2.0, quiet_seconds=1.5),
                sleep=sleep, now=lambda: clock[0])
            self.assertEqual(record["reason"], "quiet")
            # 4 s of burst plus 1.5 s of quiet, not the 2 s minimum hold.
            self.assertAlmostEqual(record["waited_seconds"], 5.5)
            self.assertAlmostEqual(record["held_since_start_seconds"], 6.5)
            self.assertAlmostEqual(record["burst_seconds"], 4.0)
            self.assertAlmostEqual(record["busy_cpu_seconds"], 4.0, places=1)
            self.assertEqual(record["top_processes"][0]["comm"], "provjobd123")
            self.assertAlmostEqual(record["top_processes"][0]["cpu_seconds"], 4.0, places=1)

    def test_records_accumulate_per_arm_with_the_settings_used(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir()
            self.write_stat(root, 0, {})
            output = Path(temporary) / "host_settle.json"
            for arm in ("direct", "ferrum", "envoy"):
                host_settle.wait(self.arguments(root, output, arm=arm), sleep=self.fail,
                                 now=lambda: 1.0)
            document = json.loads(output.read_text())
            self.assertEqual([row["arm"] for row in document["arms"]], ["direct", "ferrum", "envoy"])
            self.assertEqual(document["schema"], host_settle.SCHEMA)
            self.assertEqual(document["quiet_cores"], 0.2)
            # No "protocol" key: benchmark_plan.protocol_runs must not mistake
            # the record for a sample when it scans a run directory.
            self.assertNotIn("protocol", document)

    def test_an_arm_that_needed_no_hold_is_still_accounted_for(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir()
            self.write_stat(root, 0, {})
            output = Path(temporary) / "host_settle.json"
            host_settle.wait(self.arguments(root, output, arm="direct"), sleep=self.fail,
                             now=lambda: 1.0)
            self.assertEqual(host_settle.main(
                ["note", "--arm", "ferrum", "--image", "ferrum-edge:bench",
                 "--reason", "already_started", "--output", str(output)]), 0)
            document = json.loads(output.read_text())
            self.assertEqual([(row["arm"], row["reason"]) for row in document["arms"]],
                             [("direct", "quiet"), ("ferrum", "already_started")])
            # The settings written by the hold are kept, not replaced.
            self.assertEqual(document["min_hold_seconds"], 0.0)

    def test_cli_rejects_nonsense_bounds(self):
        for flags in (["--interval", "0"], ["--max-wait", "0"], ["--min-hold", "-1"]):
            result = subprocess.run(
                [sys.executable, str(HERE / "host_settle.py"), "wait", "--arm", "a", "--image", "i",
                 "--since", "0", "--output", "/dev/null", *flags],
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0, flags)


class RunnerContractTests(unittest.TestCase):
    def setUp(self):
        self.source = RUNNER.read_text()
        self.settle = self.source.split("settle_first_starts() {", 1)[1].split(
            "# ── Orchestration", 1)[0]
        self.main = self.source.split("# ── Orchestration", 1)[1]

    def test_settle_flags_are_parsed_before_any_work(self):
        # `--pairs 3` is rejected right after option parsing, so reaching that
        # message proves the settle flags were accepted, with no build or docker.
        for flag in ("--settle", "--no-settle"):
            result = subprocess.run(
                ["bash", str(RUNNER), "http2", flag, "--pairs", "3"], cwd=REPO_ROOT,
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("EVEN", result.stderr)
            self.assertNotIn("unknown option", result.stderr)

    def test_settle_runs_after_images_exist_and_before_the_first_measured_pair(self):
        call = self.main.index('settle_first_starts "$root_output/host_settle.json"')
        self.assertLess(self.main.index("build_binaries"), call)
        self.assertLess(self.main.index('docker pull "$ENVOY_IMAGE"'), call)
        self.assertLess(call, self.main.index("local base_started=$SECONDS"),
                        "settle time must not count toward the per-pair wall-clock estimate")
        self.assertLess(call, self.main.index("for PAIR in $(seq"))

    def test_profile_and_observation_lanes_do_not_settle_by_default(self):
        default = self.main.split('if [ "$SETTLE" = auto ]; then', 1)[1].split(
            'if [ "$SETTLE" = true ]; then', 1)[0]
        for lane in ("$H1_PROFILE", "$POOL_PROFILE", "$UDP_PROFILE", "$H2_CPU_PROFILE",
                     '"$H1_TRACE" != none', '"$H2_OBSERVE" -eq 1', "! -r /proc/stat"):
            self.assertIn(lane, default)
        self.assertIn("SETTLE=auto\n", self.source)

    def test_every_gateway_arm_the_runner_can_measure_is_settled(self):
        measured = self.main.split('case "$gw" in', 1)[1].split("esac", 1)[0]
        # Case labels only (`ferrum|ferrum-exp-*)`), not `)` inside an arm body.
        labels = re.findall(r"^\s+([a-z0-9*|-]+)\)", measured, flags=re.MULTILINE)
        names = [name for label in labels for name in label.split("|")]
        for expected in ("direct", "ferrum", "ferrum-exp-*", "ferrum-baseline", "envoy",
                         "envoy-limit-4", "kong", "tyk", "krakend"):
            self.assertIn(expected, names, "the measured-arm list this test reads has moved")
        mapping = self.settle.split('case "$gw" in', 1)[1].split("esac", 1)[0]
        settled = [name for label in re.findall(r"^\s+([a-z0-9*|-]+)\)", mapping, flags=re.MULTILINE)
                   for name in label.split("|")]
        for name in names:
            self.assertIn(name, settled, f"{name} is measured but never settled")

    def test_arms_sharing_an_image_settle_once(self):
        self.assertIn('case "$settled" in *" $image "*) continue ;; esac', self.settle)
        self.assertIn('ferrum|ferrum-exp-*) image="$FERRUM_IMAGE" ;;', self.settle)
        self.assertIn('envoy|envoy-limit-4) image="$ENVOY_IMAGE" ;;', self.settle)

    def test_an_image_already_started_since_boot_is_not_held_again(self):
        # Iteration 2 onwards of the hosted workflow re-invokes the runner in
        # the same job; the host only reacts to an image's first start.
        body = self.settle.split("\n}\n", 1)[0]
        self.assertIn("/proc/sys/kernel/random/boot_id", body)
        skip = body.index('if [ -e "$marker" ]; then')
        self.assertLess(skip, body.index("start_backend"))
        self.assertIn("--reason already_started", body)
        # The marker is written only after the hold, and only outside results.
        self.assertLess(body.index("host_settle.py\" wait"), body.index(': > "$marker"'))
        self.assertIn('${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ferrum-bench-first-start/', body)
        identity = self.source.split("settle_identity() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("docker image inspect", identity)
        self.assertIn("'{{.Id}}'", identity)

    def test_settle_writes_no_sample_and_owns_only_what_it_started(self):
        load = self.source.split("settle_load() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(">/dev/null 2>&1 || true", load)
        for forbidden in ("run_bench", "$OUTPUT_DIR", "pairs/", "benchmark_plan.py"):
            self.assertNotIn(forbidden, load + self.settle.split("\n}\n", 1)[0])
        body = self.settle.split("\n}\n", 1)[0]
        # Each first start is torn down before the next one and before pair 1.
        self.assertLess(body.index("host_settle.py"), body.rindex("stop_gateway"))
        self.assertIn('kill "$BACKEND_PID"', body)
        self.assertNotRegex(body, r"pkill|killall|xargs")


if __name__ == "__main__":
    unittest.main()
