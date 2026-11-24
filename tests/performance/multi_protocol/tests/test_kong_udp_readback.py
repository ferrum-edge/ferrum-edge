"""Hosted contracts for the actual bounded reader and immutable fixture binding."""

import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import kong_udp_readback as readback


_SHELL_INVENTORY_PATH_RE = re.compile(r"^    (/\S+?)(?: \\|; do)$", re.M)


class KongUDPReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name) / "readback"
        self.cid = "a" * 64
        self.image = "sha256:" + "b" * 64
        readback.begin(self.folder, self.cid, self.image)

    def record(self, key, raw, status=0, reader_status=0):
        readback.capture(self.folder, key, io.BytesIO(raw))
        readback.status(self.folder, key, status, reader_status)
        return readback.read_record(self.folder, key)

    def source(self, key, raw):
        return self.record(key, hashlib.sha256(raw).hexdigest().encode() + b"  " + key.encode() + b"\n" + raw)

    def test_exact_limit_truncation_aggregate_budget_and_partial_hashes(self):
        row, raw = self.record("kong-version", b"x" * readback.COMMAND_LIMIT)
        self.assertTrue(row["complete"])
        self.assertFalse(row["truncated"])
        row, raw = self.record("nginx-version", b"x" * (readback.COMMAND_LIMIT + 900), 141)
        self.assertFalse(row["complete"])
        self.assertTrue(row["truncated"])
        self.assertEqual(row["command_status"], 141)
        self.assertEqual(row["observed_bytes_at_least"], readback.COMMAND_LIMIT + 1)
        self.assertEqual(row["sha256"], hashlib.sha256(raw).hexdigest())
        for key in readback.KEYS:
            if key in ("kong-version", "nginx-version"):
                continue
            self.record(key, b"x" * (readback.COMMAND_LIMIT + 1), 141)
        self.assertEqual(sum(p.stat().st_size for p in self.folder.glob("*.raw")), readback.TOTAL_LIMIT)
        row, raw = readback.read_record(self.folder, readback.KEYS[-1])
        self.assertEqual(raw, b"")
        self.assertTrue(row["aggregate_limited"])
        self.assertTrue(row["truncated"])

    def test_timeout_missing_executable_reader_failure_and_interruption_survive(self):
        for key, status in zip(readback.QUERIES, (124, 127, 137, 3, 1, 0, 0)):
            row, raw = self.record(key, b"raw failure\n", status, 1 if status == 0 else 0)
            self.assertFalse(row["complete"])
            self.assertEqual(row["command_status"], status)
            self.assertEqual(raw, b"raw failure\n")
        result = readback.finish(self.folder)
        self.assertFalse(result["all_commands_complete"])
        self.assertEqual(len(result["commands"]), len(readback.KEYS))
        self.assertTrue(all(not r["complete"] for r in result["commands"]))
        self.assertFalse(result["session_comparability_complete"])
        self.assertIsNone(result["effective_values"])

    def test_pending_status_is_not_success(self):
        readback.capture(self.folder, "kong-version", io.BytesIO(b"3.10.0.0\n"))
        row, _ = readback.read_record(self.folder, "kong-version")
        self.assertFalse(row["complete"])
        self.assertIsNone(row["command_status"])

    def test_reader_error_keeps_partial_bytes_and_status(self):
        class FailingReader:
            calls = 0

            def read(self, size):
                self.calls += 1
                if self.calls == 1:
                    return b"partial failure output\n"
                raise OSError("fixture read failure")

        with self.assertRaises(OSError):
            readback.capture(self.folder, "kong-version", FailingReader())
        readback.status(self.folder, "kong-version", 141, 1)
        row, raw = readback.read_record(self.folder, "kong-version")
        self.assertFalse(row["complete"])
        self.assertEqual(row["error"], "OSError")
        self.assertEqual(raw, b"partial failure output\n")
        self.assertEqual(row["sha256"], hashlib.sha256(raw).hexdigest())

    def test_identity_requires_owned_running_cid_and_pinned_image(self):
        good = dict(id=self.cid, image=self.image, running=True)
        self.record("container", json.dumps(good).encode())
        self.assertTrue(readback.identity(self.folder))
        for changed in (dict(id="c" * 64), dict(image="sha256:" + "c" * 64), dict(running=False)):
            self.record("container", json.dumps(good | changed).encode())
            self.assertFalse(readback.identity(self.folder))
        self.record("container", json.dumps(good).encode(), 124)
        self.assertFalse(readback.identity(self.folder))
        for bad in ("kong", "--help", "../other"):
            with self.assertRaises(ValueError):
                readback.begin(Path(self.temp.name) / "invalid", bad, self.image)

    def test_full_source_hash_rejects_corruption_and_mixed_stderr(self):
        key = readback.SOURCES[0]
        row, raw = self.source(key, b"source\n")
        self.assertTrue(row["complete"])
        self.assertEqual(raw, b"source\n")
        self.assertEqual(row["source_sha256"], hashlib.sha256(raw).hexdigest())
        row, _ = self.record(key, b"0" * 64 + b"  " + key.encode() + b"\nsource\n")
        self.assertFalse(row["complete"])
        row, _ = self.record(key, b"read error\nsource\n")
        self.assertFalse(row["complete"])
        self.source(key, b"original\n")
        (self.folder / f"{readback.stem(key)}.raw").write_bytes(b"changed after capture")
        self.assertFalse(readback.read_record(self.folder, key)[0]["complete"])

    def test_referenced_stream_include_retained_unknowns_never_followed(self):
        main, stream, inject = readback.CONFIGS[0], readback.CONFIGS[-2], readback.CONFIGS[-1]
        self.source(main, b"stream { include 'nginx-kong-stream.conf'; }\n")
        self.source(stream, b"include 'nginx-kong-stream-inject.conf';\nserver { listen 5003 udp reuseport; }\n")
        self.source(inject, b"proxy_responses 1;\ninclude /secrets/do-not-read;\ninclude conf.d/*.conf;\n")
        result = readback.finish(self.folder)
        self.assertEqual([e["captured"] for e in result["include_candidates"]], [True, True, False, False])
        self.assertEqual(len(result["unresolved_includes"]), 2)
        self.assertFalse(result["session_comparability_complete"])
        self.assertIsNone(result["effective_values"])
        with self.assertRaises(ValueError):
            readback.capture(self.folder, "/secrets/do-not-read", io.BytesIO(b"secret"))

    def test_include_index_is_bounded_and_does_not_claim_parsing_or_inheritance(self):
        raw = b"include extra.conf;\n" * (readback.INCLUDE_LIMIT + 1)
        edges, truncated = readback.include_candidates({readback.CONFIGS[0]: raw})
        self.assertTrue(truncated)
        self.assertEqual(len(edges), readback.INCLUDE_LIMIT)
        edges, truncated = readback.include_candidates({readback.CONFIGS[0]:
            b"include " + b"x" * (readback.INCLUDE_OPERAND_LIMIT + 1) + b";"})
        self.assertTrue(truncated)
        self.assertTrue(edges[0]["operand_truncated"])
        self.assertFalse(edges[0]["captured"])
        self.assertEqual(len(edges[0]["operand"]), readback.INCLUDE_OPERAND_LIMIT)

    def test_fixed_shell_inventory_hosted_guard_and_pre_measurement_registration(self):
        shell = (readback.ROOT / "kong_udp_readback.sh").read_text()
        paths = _SHELL_INVENTORY_PATH_RE.findall(shell)
        self.assertEqual(paths, list(readback.CONFIGS + readback.SOURCES))
        self.assertIn("for query in " + " ".join(readback.QUERIES) + "; do", shell)
        for command in ("kong version -a", "/usr/local/openresty/nginx/sbin/nginx -V",
                        "dpkg-query -W", "dpkg-query -L", "sha256sum /usr/local/openresty/nginx/sbin/nginx"):
            self.assertIn(command, shell)
        self.assertIn('statuses=("${PIPESTATUS[@]}")', shell)
        self.assertIn("github-hosted", shell)
        self.assertIn('if [ -L "$1" ] || [ ! -f "$1" ]', shell)
        self.assertIn("timeout --kill-after=2s 12s docker exec", shell)
        self.assertIn("timeout --kill-after=1s 8s", shell)
        runner = (readback.ROOT / "run_gateway_protocol_bench.sh").read_text()
        start = runner.split("start_kong() {", 1)[1].split("kong_config_name() {", 1)[0]
        self.assertLess(start.index("wait_for_gateway || return 1"), start.index('bash "$SCRIPT_DIR/kong_udp_readback.sh"'))
        self.assertIn('if [ "$UDP_PROFILE" = profile ]; then', start)
        workflow = (readback.ROOT.parents[2] / ".github/workflows/udp-internal-profile.yml").read_text()
        self.assertIn("unittest discover --verbose --start-directory tests/performance/multi_protocol/tests", workflow)
        manifest = json.loads((self.folder / "manifest.json").read_text())
        self.assertEqual(manifest["source_sha256"]["kong_udp_readback.sh"], hashlib.sha256(shell.encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
