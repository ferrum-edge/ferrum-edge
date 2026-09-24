"""Static contract for benchmark shell runners' cleanup ownership.

A benchmark runner must refuse a fixed port that is already bound instead of
SIGKILL-ing its owner, and its `EXIT` trap must terminate only the PIDs and
Docker container IDs the current run started. This test scans every checked-in
runner (and the CI workflows that invoke them) and fails if it finds a
port-wide kill idiom — `lsof -ti ... | xargs kill`, `xargs ... kill`, or a bare
`kill -9` over a resolved port list — or if a runner lacks the ownership
helpers that make that guarantee real.

This is a source-level contract, not an execution test: it runs in the
``Benchmark Harness Tests`` lane without starting any process.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]

RUNNERS = [
    "tests/performance/run_perf_test.sh",
    "tests/performance/payload_size/run_payload_test.sh",
    "tests/performance/multi_protocol/run_protocol_test.sh",
    "tests/performance/multi_protocol/run_gateway_protocol_bench.sh",
    "tests/performance/multi_protocol/run_connection_saturation_bench.sh",
    "tests/performance/mesh-dns-e2e/run.sh",
    "tests/performance/mesh-hbone-e2e/run.sh",
]

# Every CI workflow path token that names one of the runners above, so the
# workflow scan covers any lane that invokes them.
RUNNER_TOKENS = {
    "run_perf_test.sh",
    "run_payload_test.sh",
    "run_protocol_test.sh",
    "run_gateway_protocol_bench.sh",
    "run_connection_saturation_bench.sh",
    "mesh-dns-e2e/run.sh",
    "mesh-hbone-e2e/run.sh",
}

# Any of these is a port-wide kill: the runner resolves a port to a list of
# PIDs and SIGKILLs whatever it finds rather than a PID/container it recorded.
BANNED_PORT_KILL = [
    re.compile(r"xargs(\s+-\S+)*\s+kill"),
    re.compile(r"lsof\s+-ti[^\n]*\|[^\n]*kill"),
    re.compile(r"kill\s+-9"),
]


class BenchmarkRunnerCleanupTests(unittest.TestCase):
    def _read(self, rel):
        path = REPO_ROOT / rel
        self.assertTrue(path.is_file(), f"{rel} is missing")
        return path.read_text()

    def test_every_runner_exists(self):
        for rel in RUNNERS:
            self.assertTrue((REPO_ROOT / rel).is_file(), rel)

    def test_no_runner_contains_a_port_wide_kill(self):
        for rel in RUNNERS:
            text = self._read(rel)
            for pattern in BANNED_PORT_KILL:
                self.assertIsNone(
                    pattern.search(text),
                    f"{rel}: port-wide kill idiom {pattern.pattern!r}",
                )

    def test_every_runner_refuses_occupied_ports_and_stops_only_what_it_started(self):
        for rel in RUNNERS:
            text = self._read(rel)
            self.assertIn(
                "check_port_available", text, f"{rel}: missing port-conflict check"
            )
            self.assertIn("stop_pid", text, f"{rel}: missing owned-PID stop helper")
            self.assertIn("kill -TERM", text, f"{rel}: missing graceful TERM")
            self.assertIn("kill -KILL", text, f"{rel}: missing bounded forced kill")
            self.assertTrue(
                "check_ports_available || exit 1" in text
                or re.search(r'check_port_available\s+"\$', text),
                f"{rel}: port-conflict check is defined but never invoked",
            )

    def test_no_invoking_ci_workflow_contains_a_port_wide_kill(self):
        workflows = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows, "expected CI workflows to scan")
        invoked = 0
        for path in workflows:
            text = path.read_text()
            if not any(token in text for token in RUNNER_TOKENS):
                continue
            invoked += 1
            for pattern in BANNED_PORT_KILL:
                self.assertIsNone(
                    pattern.search(text),
                    f"{path.relative_to(REPO_ROOT)}: port-wide kill idiom "
                    f"{pattern.pattern!r}",
                )
        self.assertGreater(
            invoked, 0, "no CI workflow matched the runner tokens — scan is inert"
        )


if __name__ == "__main__":
    unittest.main()