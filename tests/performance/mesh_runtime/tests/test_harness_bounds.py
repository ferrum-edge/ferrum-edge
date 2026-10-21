"""Exercise harness failure paths with fake Docker; never start containers."""
import importlib.util
import json
import os
from pathlib import Path
import re
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
                self.assertNotIn("--user", body)
                for mount in re.findall(r'-v "([^"]+)"', body):
                    if "$CERT_DIR" in mount:
                        self.assertTrue(mount.endswith(":ro"), mount)

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout required by the Linux harness")
    def test_readiness_detects_dead_container_before_probing(self):
        self.check_readiness("dead", expected_run=False)

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout required by the Linux harness")
    def test_readiness_has_one_wall_budget_even_when_probe_hangs(self):
        self.check_readiness("hang", expected_run=True)

    def check_readiness(self, mode, expected_run):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "logs").mkdir()
            executable(root / "docker", '''import json, os, sys, time
with open(os.environ["CALLS"], "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1] == "inspect": print("false" if os.environ["MODE"] == "dead" else "true")
elif sys.argv[1] == "run": time.sleep(20)
''')
            script = functions("readiness_command", "probe_loadgen", "wait_ready") + '''
READINESS_DEADLINE=$((SECONDS + 1))
READINESS_TIMEOUT_SECS=1
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
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
            runs = [call for call in calls if call[0] == "run"]
            self.assertEqual(bool(runs), expected_run)
            if runs:
                self.assertIn("--exchange-timeout-secs", runs[0])
                self.assertEqual(runs[0][runs[0].index("--exchange-timeout-secs") + 1], "2")
            else:
                self.assertIn("exited before readiness", result.stderr)

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
            script = functions("effective_concurrency", "run_cell") + '\nrun_cell 1024 http://fixture/echo'
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
            script = functions("effective_concurrency", "run_cell") + '\nrun_cell 1024 http://fixture/echo'
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
