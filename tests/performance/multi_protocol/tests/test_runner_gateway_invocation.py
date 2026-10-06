"""Static contract: benchmark runners start the gateway with `run`.

`ferrum-edge` requires a subcommand; a bare invocation prints help and exits,
so a runner that omits `run` never measures anything ("Gateway failed to
start"). Port 5000 is also not used by any runner config and is held by the
macOS AirPlay receiver, so the multi-protocol preflight must not claim it.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]

RUNNERS = [
    "tests/performance/run_perf_test.sh",
    "tests/performance/payload_size/run_payload_test.sh",
    "tests/performance/multi_protocol/run_protocol_test.sh",
]

# A line that executes the release binary (not cargo build, cp, or a path test).
LAUNCH = re.compile(r'(?:\./target/release/ferrum-edge|"\$GATEWAY_BIN")(?P<rest>[^\n]*)')


class RunnerGatewayInvocationTests(unittest.TestCase):
    def test_gateway_launch_uses_run_subcommand(self):
        for runner in RUNNERS:
            text = (REPO_ROOT / runner).read_text()
            launches = [m for m in LAUNCH.finditer(text) if ">" in m.group("rest") or "&" in m.group("rest")]
            self.assertTrue(launches, f"{runner}: no gateway launch found")
            for match in launches:
                self.assertRegex(match.group("rest"), r"^\s+run\b",
                                 f"{runner}: gateway launched without `run`: {match.group(0)!r}")

    def test_protocol_runner_does_not_claim_unused_port_5000(self):
        text = (REPO_ROOT / "tests/performance/multi_protocol/run_protocol_test.sh").read_text()
        ports = re.search(r'BENCH_PORTS="([^"]*)"', text).group(1)
        self.assertNotIn("5000", ports.split())


if __name__ == "__main__":
    unittest.main()
