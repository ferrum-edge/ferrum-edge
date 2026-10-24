"""Exercise harness failure paths with fake Docker; never start containers."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[4]
HARNESS = ROOT / "tests/performance/mesh_runtime/run_mesh_runtime_bench.sh"
TEXT = HARNESS.read_text()


def functions(*names):
    return "\n".join(re.search(rf"(?ms)^{name}\(\) \{{.*?^\}}", TEXT).group() for name in names)


def executable(path, text):
    path.write_text("#!/usr/bin/env python3\n" + text)
    path.chmod(0o755)


class HarnessBounds(unittest.TestCase):
    def test_fixture_group_alignment_keeps_private_keys_nonpublic(self):
        with tempfile.TemporaryDirectory() as tmp:
            certs = Path(tmp) / "certs"
            for name in ("ca", "svc", "client", "rogue"):
                directory = certs / name
                directory.mkdir(parents=True)
                (directory / "svid.crt").touch()
                (directory / "bundle.pem").touch()
                (directory / ("root.key" if name == "ca" else "svid.key")).touch()
            (certs / "rogue/root.key").touch()
            subprocess.run(["bash", "-ec", functions("prepare_cert_access") + '\nprepare_cert_access'],
                env={**os.environ, "CERT_DIR": str(certs), "CERT_GID": str(os.getgid())}, check=True)
            for name in ("svc", "client", "rogue"):
                key = certs / name / "svid.key"
                self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o640)
                self.assertEqual(key.stat().st_gid, os.getgid())
                self.assertEqual(stat.S_IMODE(key.parent.stat().st_mode), 0o750)
            for name in ("ca", "rogue"):
                self.assertEqual(stat.S_IMODE((certs / name / "root.key").stat().st_mode), 0o600)
            for name in ("start_ferrum", "start_envoy", "start_linkerd", "auth_probes"):
                body = functions(name)
                self.assertIn('--group-add "$CERT_GID"', body)
                if name != "start_envoy":
                    self.assertNotIn("--user", body)
                for mount in re.findall(r'-v "([^"]+)"', body):
                    if "$CERT_DIR" in mount:
                        self.assertTrue(mount.endswith(":ro"), mount)

    def test_both_static_envoy_containers_start_nonroot_with_fixture_group_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable(root / "docker", '''import json, os, sys
with open(os.environ["CALLS"], "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")
''')
            subprocess.run(["bash", "-ec", functions("start_envoy") + '\nstart_envoy'],
                check=True, timeout=5, env={**os.environ,
                    "PATH": str(root) + os.pathsep + os.environ["PATH"],
                    "CALLS": str(root / "calls"), "RUNTIME_DIR": str(root / "runtime"),
                    "SCRIPT_DIR": str(HARNESS.parent), "CERT_DIR": str(root / "certs"),
                    "CERT_GID": str(os.getgid()), "SERVER_NAME": "fixture-server",
                    "CLIENT_NAME": "fixture-client", "ENVOY_IMAGE": "envoyproxy/envoy:v1.39.1"})
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            self.assertEqual(len(calls), 2)
            for call, name in zip(calls, ("fixture-server", "fixture-client")):
                self.assertEqual(call[call.index("--name") + 1], name)
                self.assertEqual(call[call.index("--user") + 1], "65532:65532")
                self.assertEqual(call[call.index("--group-add") + 1], str(os.getgid()))
                self.assertIn("envoyproxy/envoy:v1.39.1", call)
                mounts = [call[index + 1] for index, value in enumerate(call) if value == "-v"]
                self.assertTrue(all(mount.endswith(":ro") for mount in mounts))

    def test_linkerd_identity_is_a_writable_runtime_copy_of_the_readonly_fixture(self):
        # linkerd2-proxy's identity init opens key.p8 for writing and writes a
        # CSR beside it; on a read-only mount it exits before the Destination
        # check that classifies the arm unsupported-standalone.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable(root / "docker", '''import json, os, sys
with open(os.environ["CALLS"], "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")
''')
            certs = root / "certs"
            for name in ("svc", "client"):
                (certs / name).mkdir(parents=True)
                for leaf in ("svid.crt", "svid.key", "bundle.pem"):
                    (certs / name / leaf).write_text(f"{name}-{leaf}")
            runtime = root / "runtime"
            subprocess.run(["bash", "-ec", functions("start_linkerd") + '\nstart_linkerd'],
                check=True, timeout=5, env={**os.environ,
                    "PATH": str(root) + os.pathsep + os.environ["PATH"],
                    "CALLS": str(root / "calls"), "RUNTIME_DIR": str(runtime),
                    "CERT_DIR": str(certs), "CERT_GID": str(os.getgid()),
                    "SERVER_NAME": "fixture-server", "CLIENT_NAME": "fixture-client",
                    "LINKERD_IMAGE": "ghcr.io/linkerd/proxy:edge-25.11.1"})
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            self.assertEqual(len(calls), 2)
            for call, name, role in zip(calls, ("fixture-server", "fixture-client"), ("svc", "client")):
                self.assertEqual(call[call.index("--name") + 1], name)
                self.assertEqual(call[call.index("--group-add") + 1], str(os.getgid()))
                mounts = [call[index + 1] for index, value in enumerate(call) if value == "-v"]
                identity = runtime / "linkerd" / role
                self.assertEqual(mounts, [f"{identity}:/var/run/linkerd/identity/end-entity"])
                self.assertEqual((identity / "key.p8").read_text(), f"{role}-svid.key")
                self.assertEqual((identity / "crt.pem").read_text(), f"{role}-svid.crt")
                self.assertEqual(stat.S_IMODE(identity.stat().st_mode), 0o770)
                self.assertEqual(stat.S_IMODE((identity / "key.p8").stat().st_mode), 0o660)
                self.assertEqual(stat.S_IMODE((identity / "crt.pem").stat().st_mode), 0o664)
                self.assertEqual((identity / "key.p8").stat().st_gid, os.getgid())
            # The shared fixture gains no Linkerd copies.
            self.assertEqual(sorted(path.name for path in certs.iterdir()), ["client", "svc"])

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout required by the Linux harness")
    def test_readiness_detects_dead_container_before_probing(self):
        self.check_readiness("dead", expected_run=False)

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout required by the Linux harness")
    def test_readiness_has_one_wall_budget_even_when_probe_hangs(self):
        self.check_readiness("hang", expected_run=True)

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout required by the Linux harness")
    def test_expired_readiness_budget_starts_no_probe(self):
        self.check_readiness("expired", expected_run=False)

    def check_readiness(self, mode, expected_run):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "logs").mkdir()
            (root / "calls").touch()
            # Keep inspection cheap: cold Python startup can consume a short
            # integer-SECONDS deadline before the hanging probe even starts.
            docker = root / "docker"
            docker.write_text('''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$CALLS"
if [ "$1" = inspect ]; then
    if [ "$MODE" = dead ]; then echo false; else echo true; fi
elif [ "$1" = run ]; then
    exec sleep 20
fi
''')
            docker.chmod(0o755)
            script = functions("readiness_command", "probe_loadgen", "wait_ready") + '''
# Two ticks leave at least one second for inspection despite SECONDS rounding.
# The real probe must still obey this shared budget instead of its 10s request.
READINESS_TIMEOUT_SECS=2
READINESS_DEADLINE=$((SECONDS + READINESS_TIMEOUT_SECS))
if [ "$MODE" = expired ]; then READINESS_DEADLINE=$SECONDS; fi
PROBE_NAME=fixture-probe
TOOLS_IMAGE=fixture-tools
HOST_HEADER=fixture
wait_ready http://fixture/echo fixture fixture-container
'''
            started = time.monotonic()
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=5,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                     "OUTPUT_DIR": str(root), "MODE": mode, "CALLS": str(root / "calls")})
            self.assertNotEqual(result.returncode, 0)
            self.assertLess(time.monotonic() - started, 4.5)
            calls = [shlex.split(line) for line in (root / "calls").read_text().splitlines()]
            runs = [call for call in calls if call[0] == "run"]
            self.assertEqual(bool(runs), expected_run)
            if runs:
                self.assertIn("--exchange-timeout-secs", runs[0])
                self.assertEqual(runs[0][runs[0].index("--exchange-timeout-secs") + 1], "2")
            elif mode == "dead":
                self.assertIn("exited before readiness", result.stderr)
            else:
                self.assertIn("exhausted the shared", result.stderr)

    def test_cell_watchdog_preserves_partial_output_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable(root / "timeout", '''import json, os, sys
with open(os.environ["CALLS"], "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")
if "python3" in sys.argv:
    path = sys.argv[sys.argv.index("--output") + 1]
    open(path, "w").write("partial loadgen output")
    raise SystemExit(124)
''')
            script = functions("effective_concurrency", "cell_wall_timeout_secs", "run_cell") + '\nrun_cell 1024 http://fixture/echo'
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=5,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                     "OUTPUT_DIR": str(root), "CALLS": str(root / "calls"), "MESH": "direct",
                     "DURATION": "3", "WARMUP": "2", "CONCURRENCY": "1", "EXCHANGE_TIMEOUT_SECS": "10",
                     "SCRIPT_DIR": str(HARNESS.parent), "TOOLS_IMAGE": "fixture", "HOST_HEADER": "fixture",
                     "LOADGEN_NAME": "fixture-loadgen"})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / "direct_http1_1024.failed-output.json").read_text(), "partial loadgen output")
            self.assertEqual(json.loads((root / "direct_http1_1024.json").read_text())["total_errors"], -1)
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            self.assertEqual(calls[0][:3], ["--signal=TERM", "--kill-after=5s", "45s"])
            self.assertTrue(any("fixture-loadgen" in call and "rm" in call for call in calls))

    def test_consul_deny_probe_cut_short_by_budget_is_not_a_denial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "logs").mkdir()
            # Plaintext is refused, then the deny-loop probe outlives the
            # shared budget and fails only because readiness expired.
            mocks = (
                'docker() { :; }\nwait_ready() { echo restored-wait; }\n'
                'probe_loadgen() { case "$1" in *21000*) return 1 ;; esac; sleep 2; return 1; }\n'
            )
            script = mocks + functions("consul_intention_probe") + (
                '\nREADINESS_DEADLINE=$((SECONDS + 1)); consul_intention_probe')
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10,
                env={**os.environ, "OUTPUT_DIR": str(root), "OUTBOUND_PORT": "15101",
                     "AGENT_NAME": "fixture-agent", "READINESS_TIMEOUT_SECS": "90"})
            self.assertNotEqual(result.returncode, 0)
            evidence = (root / "logs/auth_probes.log").read_text()
            self.assertIn("readiness budget exhausted before the deny probe completed", evidence)
            self.assertNotIn("deny intention broke echo", evidence)
            self.assertNotIn("restored-wait", result.stdout)

    def test_campaign_streams_progress_stops_on_failure_and_retags_exact_aa(self):
        wrapper = (ROOT / ".github/scripts/mesh_runtime_campaign.sh").read_text()
        same_sha = wrapper.split('if [ "$baseline" = "$(git rev-parse HEAD)" ]; then', 1)[1].split("else", 1)[0]
        self.assertIn("docker tag ferrum-edge:bench ferrum-edge:baseline", same_sha)
        self.assertNotIn("docker build", same_sha)
        self.assertIn('| tee "$directory/run.log"', wrapper)
        self.assertIn('timeout --signal=TERM --kill-after=10s "${arm_budget}s"', wrapper)
        self.assertIn('if [ "$failed" -ne 0 ]; then', wrapper)
        self.assertIn("break", wrapper.split('if [ "$failed" -ne 0 ]; then', 1)[1])
        spec = importlib.util.spec_from_file_location("bounds_campaign", ROOT / ".github/scripts/mesh_runtime_campaign.py")
        campaign = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(campaign)
        limits = campaign.workload_limits(3)
        self.assertEqual(limits["exchange_timeout_secs"], 10)
        self.assertEqual(limits["readiness_timeout_secs"], 90)
        self.assertEqual(limits["cell_wall_timeout_secs"], 45)
        self.assertEqual(limits["arm_wall_timeout_secs"], 423)

    def test_cell_errors_stop_without_overwriting_the_loadgen_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable(root / "timeout", '''import json, sys
if "python3" in sys.argv:
    path = sys.argv[sys.argv.index("--output") + 1]
    open(path, "w").write(json.dumps({"rps": 1, "total_requests": 1, "total_errors": 2}))
''')
            script = functions("effective_concurrency", "cell_wall_timeout_secs", "run_cell") + '\nrun_cell 1024 http://fixture/echo'
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=5,
                env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                     "OUTPUT_DIR": str(root), "MESH": "direct", "DURATION": "3", "WARMUP": "2",
                     "CONCURRENCY": "1", "EXCHANGE_TIMEOUT_SECS": "10", "SCRIPT_DIR": str(HARNESS.parent),
                     "TOOLS_IMAGE": "fixture", "HOST_HEADER": "fixture", "LOADGEN_NAME": "fixture-loadgen"})
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads((root / "direct_http1_1024.json").read_text())["total_errors"], 2)
            self.assertFalse((root / "direct_http1_1024.failed-output.json").exists())


if __name__ == "__main__":
    unittest.main()
