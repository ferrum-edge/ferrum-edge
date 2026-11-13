"""First-start settle: the hold decision, the /proc readers, and the runner wiring.

On GitHub-hosted runners the provisioner's job daemon uses about one core for
four to five seconds the first time a new binary or container image runs in a
job. The benchmark runner starts every distinct image once before pair 1 and
waits, through ``host_settle.py``, until the host is quiet. These tests pin the
wait rule without a live host, the runner's side of the contract from its
source, and the runner's settle code itself, run in bash with the start
functions, Docker and the helper replaced by stand-ins.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
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
                      burst_cores=0.4, interval=0.5, top=3, baseline=None, proc_root=str(root))
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
            # The burst ran from the first sample (1 s after the start) to 5 s
            # after it: the margin left before the release is readable.
            self.assertAlmostEqual(record["first_burst_since_start_seconds"], 1.0)
            self.assertAlmostEqual(record["last_burst_since_start_seconds"], 5.0)
            self.assertAlmostEqual(record["busy_cpu_seconds"], 4.0, places=1)
            self.assertEqual(record["top_processes"][0]["comm"], "provjobd123")
            self.assertAlmostEqual(record["top_processes"][0]["cpu_seconds"], 4.0, places=1)

    def test_host_cpu_during_the_load_is_reported_from_the_snapshot_without_the_arm(self):
        # The reaction usually falls inside the discarded load, before `wait`
        # samples anything. The snapshot taken before the arm started makes it
        # visible; the arm's own processes are born later and are left out.
        ticks = host_settle.clock_ticks()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir()
            output = Path(temporary) / "host_settle.json"
            baseline = Path(temporary) / "before_start.json"
            self.write_stat(root, 0, {77: ("provjobd123", 5 * ticks), 78: ("dockerd", ticks)})
            self.assertEqual(host_settle.main(
                ["snapshot", "--output", str(baseline), "--proc-root", str(root)]), 0)
            # During the start and the load: the provisioner uses 3 CPU-seconds,
            # and the arm's gateway and client appear and use far more.
            self.write_stat(root, 30 * ticks, {
                77: ("provjobd123", 8 * ticks), 78: ("dockerd", ticks),
                90: ("ferrum-edge", 50 * ticks), 91: ("proto_bench", 20 * ticks)})
            record = host_settle.wait(
                self.arguments(root, output, baseline=str(baseline)), sleep=self.fail,
                now=lambda: time.time() + 21.0)
            self.assertEqual(record["host_processes_since_before_start"],
                             [{"comm": "provjobd123", "cpu_seconds": 3.0}])
            self.assertGreater(record["seconds_since_before_start"], 20.0)
            # The hold itself saw nothing: without the snapshot this start
            # would read as one the host never reacted to.
            self.assertEqual(record["top_processes"], [])

    def test_a_missing_or_foreign_baseline_only_drops_the_extra_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir()
            self.write_stat(root, 0, {})
            output = Path(temporary) / "host_settle.json"
            foreign = Path(temporary) / "foreign.json"
            foreign.write_text('{"processes": []}')
            timeless = Path(temporary) / "timeless.json"
            timeless.write_text('{"unix": NaN, "processes": {}}')
            for baseline in (Path(temporary) / "absent.json", foreign, timeless):
                record = host_settle.wait(
                    self.arguments(root, output, baseline=str(baseline)), sleep=self.fail,
                    now=lambda: 1.0)
                self.assertEqual(record["reason"], "quiet")
                self.assertNotIn("host_processes_since_before_start", record)

    def test_a_baseline_entry_of_the_wrong_shape_is_skipped_and_the_record_survives(self):
        ticks = host_settle.clock_ticks()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir()
            self.write_stat(root, 0, {77: ("provjobd123", 8 * ticks), 78: ("dockerd", 3 * ticks),
                                      79: ("containerd", 2 * ticks), 80: ("systemd", 4 * ticks)})
            output = Path(temporary) / "host_settle.json"
            baseline = Path(temporary) / "foreign.json"
            # Ticks as text, as a boolean and as a float; one well-formed entry.
            baseline.write_text(json.dumps({"unix": 0.5, "processes": {
                "77:1": ["provjobd123", "500"], "78:1": ["dockerd", True],
                "80:1": ["systemd", 1.5], "79:1": ["containerd", ticks]}}))
            record = host_settle.wait(
                self.arguments(root, output, baseline=str(baseline)), sleep=self.fail,
                now=lambda: 1.0)
            self.assertEqual(record["reason"], "quiet")
            self.assertEqual(record["host_processes_since_before_start"],
                             [{"comm": "containerd", "cpu_seconds": 1.0}])
            self.assertEqual(json.loads(output.read_text())["arms"], [record])

    def test_proc_lost_during_the_hold_is_not_reported_as_observed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "proc"
            root.mkdir()
            output = Path(temporary) / "host_settle.json"
            clock = [10.0]

            def sleep(interval):
                clock[0] += interval
                if clock[0] >= 11.0:
                    (root / "stat").unlink()

            self.write_stat(root, 0, {})
            record = host_settle.wait(
                self.arguments(root, output, since=10.0, min_hold=25.0, quiet_seconds=3.0),
                sleep=sleep, now=lambda: clock[0])
            self.assertEqual(record["reason"], "unavailable")
            self.assertFalse(record["available"])
            self.assertEqual(record["samples"], 1)

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
            # A hold that saw no burst says so instead of reporting a time.
            self.assertIsNone(document["arms"][0]["first_burst_since_start_seconds"])
            self.assertIsNone(document["arms"][0]["last_burst_since_start_seconds"])
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

    def test_the_since_boot_marker_is_keyed_by_image_identity_outside_the_results(self):
        # Iteration 2 onwards of the hosted workflow re-invokes the runner in
        # the same job; the host only reacts to an image's first start.
        body = self.settle.split("\n}\n", 1)[0]
        self.assertIn("/proc/sys/kernel/random/boot_id", body)
        self.assertIn("--reason already_started", body)
        self.assertIn('${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ferrum-bench-first-start/', body)
        identity = self.source.split("settle_identity() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("docker image inspect", identity)
        self.assertIn("'{{.Id}}'", identity)

    def test_settle_load_is_discarded_and_nothing_is_killed_by_name(self):
        load = self.source.split("settle_load() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(">/dev/null 2>&1 || true", load)
        section = self.source.split("# ── First-start settle", 1)[1].split("# ── Orchestration", 1)[0]
        for forbidden in ("run_bench", "pairs/", "benchmark_plan.py"):
            self.assertNotIn(forbidden, load + self.settle.split("\n}\n", 1)[0])
        self.assertNotRegex(section, r"pkill|killall|xargs")

    def test_the_discarded_load_covers_the_window_in_which_the_reaction_begins(self):
        # Under measured load the reaction had run its course within about
        # 20 s of an arm's first start; with a 3 s load it had not begun by
        # the release in 3 of 14 starts and reached pair 1.
        seconds = int(re.search(r"^SETTLE_LOAD_SECONDS=(\d+)$", self.source, flags=re.MULTILINE).group(1))
        self.assertGreaterEqual(seconds, 20)
        load = self.source.split("settle_load() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('--duration "$SETTLE_LOAD_SECONDS"', load)

    def test_cleanup_takes_down_a_settle_in_progress(self):
        cleanup = self.source.split("\ncleanup() {\n", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('kill -TERM "$SETTLE_PID"', cleanup)
        self.assertIn('wait "$SETTLE_PID"', cleanup)


def shell_function(source, name):
    start = source.index(f"\n{name}() {{\n") + 1
    return source[start:source.index("\n}\n", start) + 3]


DRIVER_HEAD = r"""
set -eo pipefail
FERRUM_IMAGE=ferrum-edge:bench
BASELINE_IMAGE=baseline:image
ENVOY_IMAGE=envoy:image
KONG_IMAGE=kong:image
TYK_IMAGE=tyk:image
KRAKEND_IMAGE=krakend:image
PAYLOAD_SIZES="10240 71680"
CONCURRENCY=100
H2_WINDOW=default
H2_STREAM_WINDOW=0
GRPC_CLIENT_CONNECTIONS=pooled
TIMEOUT_CMD=""
BACKEND_PID=""
REDIS_CID=""
GATEWAY_CID=""
SETTLE_PID=""
SETTLE_STATUS=0
sampler_pid=""
sampler_stop_file=""
OUTPUT_DIR="$RUN_DIR"
log() { printf '%s\n' "$*" >> "$LOG"; }
h1_trace_stop() { :; }
bench_params() { echo "http1 https://127.0.0.1:8443/echo https://127.0.0.1:3443/echo"; }
scale_concurrency_for_payload() { echo "$2"; }
docker() {
    if [ "$1" = image ]; then echo "sha256:$3"; else log "docker $*"; fi
}
# Stands in for both uses of python3: the clock read and host_settle.py.
python3() {
    if [ "$1" = -c ]; then cat "$CLOCK"; return 0; fi
    shift
    log "helper $*"
    if [ "$1" = wait ] && [ -n "${HELPER_BLOCKS:-}" ]; then
        exec "$REAL_PYTHON" -c 'import os, sys, time; open(sys.argv[1], "w").write(str(os.getpid())); time.sleep(60)' "$HELPER_PIDFILE"
    fi
    if [ "$1" = wait ] && [ "${HELPER_FAILS_FOR:-}" = "$gw" ]; then return 3; fi
    return 0
}
start_backend() {
    log "start_backend gw=$gw output=$OUTPUT_DIR"
    if [ "${BACKEND_EXITS_FOR:-}" = "$gw" ]; then log "backend exits"; exit 1; fi
    sleep 300 &
    BACKEND_PID=$!
    log "backend pid $BACKEND_PID"
}
gateway_up() {
    GATEWAY_CID="cid-$gw"
    LEAKED_BY_START=yes
    mkdir -p "$OUTPUT_DIR/diagnostics"
    echo config > "$OUTPUT_DIR/diagnostics/${gw}_config.yaml"
    if [ "${SLOW_START_FOR:-}" = "$gw" ]; then echo 1040.000 > "$CLOCK"; fi
    [ "${GATEWAY_FAILS_FOR:-}" != "$gw" ]
}
start_ferrum() { log "start_ferrum image=$FERRUM_IMAGE"; gateway_up; }
start_envoy() { log "start_envoy limit=$ENVOY_STREAM_LIMIT"; gateway_up; }
start_kong() { log start_kong; gateway_up; }
start_krakend() { log start_krakend; gateway_up; }
start_tyk() {
    log start_tyk
    REDIS_CID=cid-redis
    if [ -n "${REDIS_EXITS:-}" ]; then log "redis exits"; exit 1; fi
    gateway_up
}
stop_gateway() {
    log "stop_gateway gateway=$GATEWAY_CID redis=$REDIS_CID"
    stop_container "$GATEWAY_CID"
    stop_container "$REDIS_CID"
    GATEWAY_CID=""
    REDIS_CID=""
}
"""

DRIVER_TAIL = r"""
trap cleanup EXIT
settle_first_starts "$RUN_DIR/host_settle.json" "$ARMS"
log "measured phase backend=[$BACKEND_PID] gateway=[$GATEWAY_CID] redis=[$REDIS_CID] leaked=[${LEAKED_BY_START:-}] output=$OUTPUT_DIR"
"""


def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class SettleBehaviourTests(unittest.TestCase):
    """The runner's own settle code, with everything it starts replaced."""

    def setUp(self):
        source = RUNNER.read_text()
        section = source.split("# ── First-start settle", 1)[1].split("# ── Orchestration", 1)[0]
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run_dir = self.root / "results"
        self.run_dir.mkdir()
        self.log = self.root / "events.log"
        self.log.write_text("")
        self.clock = self.root / "clock"
        self.clock.write_text("1000.000\n")
        script_dir = self.root / "harness"
        release = script_dir / "target" / "release"
        release.mkdir(parents=True)
        (release / "proto_backend").write_text("backend\n")
        bench = release / "proto_bench"
        bench.write_text('#!/bin/sh\nprintf \'load %s\\n\' "$*" >> "$LOG"\n')
        bench.chmod(0o755)
        self.driver = self.root / "driver.sh"
        self.driver.write_text(
            DRIVER_HEAD
            + shell_function(source, "stop_pid")
            + shell_function(source, "stop_container")
            + shell_function(source, "cleanup")
            + "# ── First-start settle" + section
            + DRIVER_TAIL)
        self.environment = dict(
            os.environ, LOG=str(self.log), RUN_DIR=str(self.run_dir), CLOCK=str(self.clock),
            SCRIPT_DIR=str(script_dir), RUNNER_TEMP=str(self.root / "runner-temp"),
            TMPDIR=str(self.root), REAL_PYTHON=sys.executable,
            HELPER_PIDFILE=str(self.root / "helper.pid"))

    def run_settle(self, arms, **scenario):
        result = subprocess.run(
            ["bash", str(self.driver)], env=dict(self.environment, ARMS=arms, **scenario),
            capture_output=True, text=True, timeout=120)
        return result, self.log.read_text().splitlines()

    def assert_nothing_left(self, events):
        pids = [int(line.split()[-1]) for line in events if line.startswith("backend pid ")]
        self.assertTrue(pids)
        for pid in pids:
            self.assertFalse(alive(pid), f"backend {pid} outlived the settle")
        scratch = {line.split("output=", 1)[1] for line in events if line.startswith("start_backend ")}
        for directory in scratch:
            self.assertNotEqual(Path(directory), self.run_dir)
            self.assertNotIn(self.run_dir, Path(directory).parents)
            self.assertFalse(Path(directory).exists(), "the scratch directory was left behind")
        self.assertEqual(sorted(path.name for path in self.run_dir.iterdir()), [],
                         "a settle start wrote into the run directory")

    def test_each_image_is_started_once_with_default_arguments_then_removed(self):
        result, events = self.run_settle("direct ferrum ferrum-exp-a envoy envoy-limit-4 ferrum-baseline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([line for line in events if line.startswith("start_ferrum")],
                         ["start_ferrum image=ferrum-edge:bench", "start_ferrum image=baseline:image"])
        self.assertEqual([line for line in events if line.startswith("start_envoy")],
                         ["start_envoy limit=100"])
        waits = [line.split() for line in events if line.startswith("helper wait")]
        self.assertEqual([words[words.index("--arm") + 1] for words in waits],
                         ["direct", "ferrum", "envoy", "ferrum-baseline"])
        # Host CPU is snapshotted before anything of the arm exists, and the
        # hold is told where that snapshot is; it lives outside the results.
        steps = [" ".join(line.split()[:2]) for line in events]
        self.assertEqual([step for step in steps if step in ("helper snapshot", "start_backend gw=direct",
                                                              "start_backend gw=ferrum")][:4],
                         ["helper snapshot", "start_backend gw=direct",
                          "helper snapshot", "start_backend gw=ferrum"])
        for words in waits:
            baseline = Path(words[words.index("--baseline") + 1])
            self.assertNotIn(self.run_dir, baseline.parents)
        self.assertEqual(len([line for line in events if line.startswith("load ")]), 4)
        self.assertTrue(all("--duration 20" in line for line in events if line.startswith("load ")))
        # Every arm is taken down before the next starts and before pair 1.
        order = [line.split()[0] for line in events
                 if line.split()[0] in ("start_backend", "stop_gateway", "measured")]
        self.assertEqual(order, ["start_backend", "stop_gateway"] * 4 + ["measured"])
        self.assertIn("docker stop --time 5 cid-ferrum", events)
        self.assert_nothing_left(events)

    def test_no_shell_state_or_file_of_a_settle_start_reaches_the_measured_phase(self):
        result, events = self.run_settle("ferrum")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            f"measured phase backend=[] gateway=[] redis=[] leaked=[] output={self.run_dir}", events)
        self.assert_nothing_left(events)

    def test_the_hold_is_timed_from_when_the_arm_is_up_not_from_before_an_image_pull(self):
        result, events = self.run_settle("direct krakend", SLOW_START_FOR="krakend")
        self.assertEqual(result.returncode, 0, result.stderr)
        waits = {words[words.index("--arm") + 1]: words[words.index("--since") + 1]
                 for words in (line.split() for line in events if line.startswith("helper wait"))}
        # The stand-in start moves the clock by 40 s, as a cold `docker run` would.
        self.assertEqual(waits, {"direct": "1000.000", "krakend": "1040.000"})
        steps = [line.split()[0] for line in events]
        krakend = steps.index("start_krakend")
        self.assertLess(krakend, steps.index("load", krakend))
        self.assertLess(steps.index("load", krakend), len(steps) - 1 - steps[::-1].index("helper"))

    def test_a_backend_that_cannot_start_does_not_end_the_run(self):
        # start_backend reports failure with `exit 1`.
        result, events = self.run_settle("direct ferrum envoy", BACKEND_EXITS_FOR="ferrum")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("backend exits", events)
        self.assertIn("[settle] ferrum was not settled (status 1); continuing", result.stdout)
        self.assertIn("start_envoy limit=100", events)
        self.assertTrue(events[-1].startswith("measured phase"), events[-1])
        waits = [line.split() for line in events if line.startswith("helper wait")]
        self.assertEqual([words[words.index("--arm") + 1] for words in waits], ["direct", "envoy"])
        self.assert_nothing_left(events)

    def test_a_gateway_that_cannot_start_is_removed_and_skipped(self):
        result, events = self.run_settle("ferrum envoy", GATEWAY_FAILS_FOR="ferrum")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("docker stop --time 5 cid-ferrum", events)
        self.assertNotIn("load", [line.split()[0] for line in events[:events.index("start_envoy limit=100")]])
        self.assertTrue(events[-1].startswith("measured phase"), events[-1])
        self.assert_nothing_left(events)

    def test_a_dependency_that_ends_the_shell_inside_a_gateway_start_does_not_end_the_run(self):
        # start_tyk -> start_redis reports failure with `exit 1`.
        result, events = self.run_settle("tyk envoy", REDIS_EXITS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("redis exits", events)
        self.assertIn("docker stop --time 5 cid-redis", events)
        self.assertIn("start_envoy limit=100", events)
        self.assertTrue(events[-1].startswith("measured phase"), events[-1])
        self.assert_nothing_left(events)

    def test_a_helper_failure_skips_the_arm_without_ending_the_run(self):
        result, events = self.run_settle("ferrum envoy", HELPER_FAILS_FOR="ferrum")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[settle] ferrum was not settled (status 3); continuing", result.stdout)
        self.assertIn("start_envoy limit=100", events)
        self.assert_nothing_left(events)

    @unittest.skipUnless(os.path.exists("/proc/sys/kernel/random/boot_id"), "needs Linux boot_id")
    def test_only_a_settled_image_is_skipped_by_a_later_invocation(self):
        first, _ = self.run_settle("direct ferrum envoy", GATEWAY_FAILS_FOR="ferrum")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.log.write_text("")
        second, events = self.run_settle("direct ferrum envoy")
        self.assertEqual(second.returncode, 0, second.stderr)
        notes = [line.split() for line in events if line.startswith("helper note")]
        self.assertEqual([words[words.index("--arm") + 1] for words in notes], ["direct", "envoy"])
        # The image whose first start failed is started and held again.
        self.assertEqual([line for line in events if line.startswith("start_")][1:],
                         ["start_ferrum image=ferrum-edge:bench"])
        markers = list((self.root / "runner-temp" / "ferrum-bench-first-start").glob("*/*"))
        self.assertEqual(len(markers), 3)
        self.assertEqual(sorted(path.name for path in self.run_dir.iterdir()), [])

    def test_an_interrupt_during_the_hold_takes_the_arm_down_at_once(self):
        process = subprocess.Popen(
            ["bash", str(self.driver)],
            env=dict(self.environment, ARMS="ferrum envoy", HELPER_BLOCKS="1"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        pidfile = Path(self.environment["HELPER_PIDFILE"])
        try:
            deadline = time.monotonic() + 30
            while not (pidfile.exists() and pidfile.read_text().strip()):
                self.assertLess(time.monotonic(), deadline, "the hold never began")
                self.assertIsNone(process.poll(), "the runner ended before the hold")
                time.sleep(0.05)
            helper = int(pidfile.read_text())
            signalled = time.monotonic()
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=30)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertLess(time.monotonic() - signalled, 20, "teardown waited for the hold to finish")
        # bash runs its EXIT trap and then dies of the signal.
        self.assertIn(process.returncode, (-signal.SIGTERM, 128 + signal.SIGTERM))
        events = self.log.read_text().splitlines()
        self.assertIn("stop_gateway gateway=cid-ferrum redis=", events)
        self.assertIn("docker stop --time 5 cid-ferrum", events)
        self.assertNotIn("start_envoy limit=100", events)
        self.assertFalse(any(line.startswith("measured phase") for line in events))
        deadline = time.monotonic() + 5
        while alive(helper) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(alive(helper), "the hold helper outlived the interrupt")
        self.assert_nothing_left(events)


if __name__ == "__main__":
    unittest.main()
