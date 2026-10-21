"""Synthetic leaf-profile validity tests. Never run perf, Docker, or a build."""
import contextlib
import os
import importlib.util
import json
from pathlib import Path
import signal
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("production_perf", HERE / "production_perf.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
IMAGE = "sha256:" + "a" * 64
ATTRS = "cpu-clock:u: type: 1 (software), config: 0 (PERF_COUNT_SW_CPU_CLOCK), { sample_period, sample_freq }: 49, sample_type: IP|TID|TIME|CPU, freq: 1, inherit: 1, exclude_kernel: 1, use_clockid: 1, clockid: 1\n"


def line(pid=101, when=15, symbol="ferrum::request", dso="/usr/local/bin/ferrum-edge"):
    return f"worker name {pid}/{pid + 1} {when:.9f}: cpu-clock:u: 0000000040000100 {symbol} ({dso})"


class ProductionPerf(unittest.TestCase):
    def test_window_excludes_warmup_drain_and_keeps_unknown_denominator(self):
        text = "\n".join([line(when=9), *[line() for _ in range(4)], line(symbol="[unknown]"), line(when=21)])
        result = M.parse_leaves(text, 101, 10, 20, {"/usr/local/bin/ferrum-edge": {}})
        self.assertEqual(result["all_capture_sample_count"], 7)
        self.assertEqual(result["measurement_sample_count"], 5)
        self.assertEqual(result["known_leaves"], 4)
        self.assertEqual(result["unknown_leaves"], 1)
        self.assertEqual(result["known_leaf_fraction"], .8)
        self.assertEqual(sum(row["samples"] for row in result["functions"]), 5)
        self.assertAlmostEqual(sum(row["fraction_all_measurement_leaves"] for row in result["functions"]), 1)
        self.assertEqual(len(result["raw_window_lines"]), 5)

    def test_foreign_pid_even_outside_window_is_reported(self):
        result = M.parse_leaves(line(pid=202, when=9) + "\n" + line(), 101, 10, 20, {"/usr/local/bin/ferrum-edge": {}})
        self.assertEqual(result["foreign_pid_samples"], 1)
        self.assertEqual(result["measurement_sample_count"], 1)
        bad = M.parse_leaves(line(symbol="actual", dso="unretained.so"), 101, 10, 20, {})
        self.assertEqual(bad["unknown_leaves"], 1)

    def test_ambiguous_library_basename_is_unknown(self):
        result = M.parse_leaves(line(symbol="request", dso="libsame.so"), 101, 10, 20,
                                {"/a/libsame.so": {}, "/b/libsame.so": {}})
        self.assertEqual(result["unknown_leaves"], 1)
        with self.assertRaisesRegex(ValueError, "finite"):
            M.parse_leaves("", 101, float("nan"), 20, {})

    def test_command_is_leaf_only_fixed_clock_and_rate_with_raw_cap(self):
        args = M.record_argv("/usr/bin/perf", 101, Path("/tmp/owned"))
        self.assertEqual(args[:4], ["/usr/bin/perf", "--buildid-dir", "/tmp/buildid-cache", "record"])
        self.assertEqual(args[args.index("-F") + 1], "49")
        self.assertEqual(args[args.index("-e") + 1], "cpu-clock:u")
        self.assertEqual(args[args.index("--clockid") + 1], "mono")
        self.assertEqual(args[args.index("-p") + 1], "101")
        self.assertIn("--max-size=64M", args)
        self.assertIn("--no-buildid-cache", args)
        self.assertNotIn("--call-graph", args)
        self.assertEqual(M.validate_attributes(ATTRS), [])
        self.assertTrue(M.validate_attributes(ATTRS.replace("49,", "99,")))
        self.assertTrue(M.validate_attributes(ATTRS.replace("IP|TID|TIME|CPU", "IP|TID|TIME|STACK_USER")))
        self.assertTrue(M.validate_attributes(ATTRS.replace("clockid: 1", "clockid: 0")))

    def test_decoder_selects_private_cache_before_subcommand(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = M.PerfCapture([{"name": "a", "pid": 101, "image_id": IMAGE},
                                     {"name": "b", "pid": 102, "image_id": IMAGE}], root, [])
            role = {"directory": root, "report": {"errors": []}}
            read, write = os.pipe()
            os.close(write)
            process = Mock(stdout=os.fdopen(read, "rb"), returncode=0)
            process.poll.return_value = 0
            with patch.object(M.subprocess, "Popen", return_value=process) as launch:
                capture.command(role, "attributes.txt", ["evlist", "-v", "-i", "/tmp/owned-perf.data"])
            self.assertEqual(launch.call_args.args[0][:4], [capture.perf, "--buildid-dir", str(root / "buildid-cache"), "evlist"])
            self.assertEqual(role["report"]["errors"], [])

    def test_identity_rejects_pid_reuse_executable_and_image_changes(self):
        identity = {"pid": 101, "starttime": 7, "exe": "/bin/proxy", "exe_sha256": "a" * 64,
                    "boot_id": "boot", "namespaces": {"time": 123}}
        for field, value in (("starttime", 8), ("exe_sha256", "b" * 64), ("boot_id", "other")):
            changed = dict(identity, **{field: value})
            self.assertFalse(M.same_identity(identity, changed))
        containers = [{"name": "source", "pid": 101, "image_id": IMAGE}, {"name": "destination", "pid": 102, "image_id": IMAGE}]
        capture = M.PerfCapture(containers, "/tmp/not-created", [])
        with patch.object(M, "inspect", return_value={"pid": 101, "image_id": "sha256:" + "b" * 64}):
            with self.assertRaisesRegex(ValueError, "pinned"):
                capture.checked_identity(containers[0])
        with self.assertRaisesRegex(ValueError, "immutable"):
            M.PerfCapture([dict(containers[0], image_id="moving:tag"), containers[1]], "/tmp/not-created", [])
        self.assertEqual(capture.environment()["PERF_CONFIG"], "/dev/null")
        self.assertEqual(capture.environment()["PERF_BUILDID_DIR"], "/tmp/not-created/buildid-cache")
        self.assertEqual(capture.environment()["DEBUGINFOD_URLS"], "")

    def fixture(self, output, *, known=80, lost=0, throttle=0, foreign=False, count_delta=0):
        containers = [{"name": "source", "pid": 101, "image_id": IMAGE}, {"name": "destination", "pid": 102, "image_id": IMAGE}]
        capture = M.PerfCapture(containers, output, [])
        capture.output.mkdir()
        capture.started = capture.stopped = True
        leafs = {}
        for container in capture.containers:
            directory = output / container["role"]
            directory.mkdir()
            (directory / "perf.data").write_bytes(b"synthetic raw; not executed")
            blob = directory / "actual.elf"
            blob.write_bytes(b"synthetic retained ELF; parser is not invoked")
            report = {"role": container["role"], "errors": [], "enabled_at_monotonic": 8,
                      "stopped_at_monotonic": 22}
            mapping = {"/usr/local/bin/ferrum-edge": {"build_id": "1234", "blob": str(blob), "sha256": M.sha256(blob)}}
            capture.roles.append({"container": container, "directory": directory, "mappings": mapping, "report": report})
            rows = [line(container["pid"], symbol="ferrum::request") for _ in range(known)]
            rows += [line(container["pid"], symbol="[unknown]") for _ in range(100 - known)]
            if foreign:
                rows.append(line(999, when=9))
            leafs[container["role"]] = "\n".join(rows) + "\n"
        def command(role, name, argv, raw_records=False):
            text = {"attributes.txt": ATTRS, "buildids.txt": "1234 /usr/local/bin/ferrum-edge\n",
                    "leaf-events-all.txt": leafs[role["container"]["role"]]}.get(name, "PERF_RECORD_SAMPLE\n")
            (role["directory"] / name).write_text(text)
            return {"PERF_RECORD_SAMPLE": 100 + int(foreign) + count_delta, "PERF_RECORD_LOST": lost,
                    "PERF_RECORD_THROTTLE": throttle}
        capture.command = command
        return capture

    def test_complete_two_role_capture_at_80_percent_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = self.fixture(Path(tmp) / "capture")
            result = capture.decode(10, 20)
            self.assertTrue(result["valid"], result)
            self.assertEqual(len(result["roles"]), 2)
            for role in result["roles"]:
                self.assertEqual(role["measurement_sample_count"], 100)
                self.assertEqual(role["unknown_leaves"], 20)
                events = (capture.output / role["role"] / "leaf-events-window.jsonl").read_text().splitlines()
                self.assertEqual(len(events), 100)
            self.assertTrue((capture.output / "capture.json").is_file())

    def test_low_coverage_loss_throttle_foreign_and_decoder_mismatch_are_invalid(self):
        for options in ({"known": 79}, {"lost": 1}, {"throttle": 1}, {"foreign": True}, {"count_delta": 1}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as tmp:
                capture = self.fixture(Path(tmp) / "capture", **options)
                result = capture.decode(10, 20)
                self.assertFalse(result["valid"])
                self.assertTrue(all(role["errors"] for role in result["roles"]))
                self.assertTrue((capture.output / "capture.json").is_file())

    def test_nonfinite_bracket_preserves_invalid_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = self.fixture(Path(tmp) / "capture")
            result = capture.decode(float("nan"), 20)
            self.assertFalse(result["valid"])
            self.assertNotIn("NaN", (capture.output / "capture.json").read_text())

    def test_cleanup_signals_only_owned_perf_session(self):
        capture = M.PerfCapture([{"name": "a", "pid": 101, "image_id": IMAGE},
                                 {"name": "b", "pid": 102, "image_id": IMAGE}], "/tmp/not-created", [])
        process = Mock(pid=7001, returncode=0)
        process.poll.side_effect = [None, None]
        role = {"process": process, "report": {"errors": []}}
        with patch.object(M.os, "killpg") as kill:
            capture.reap(role)
            kill.assert_called_once_with(7001, signal.SIGINT)
        self.assertEqual(role["report"]["errors"], [])

    def test_wall_limit_stops_both_owned_recorders(self):
        capture = M.PerfCapture([{"name": "a", "pid": 101, "image_id": IMAGE},
                                 {"name": "b", "pid": 102, "image_id": IMAGE}], "/tmp/not-created", [])
        capture.roles = [{"container": container, "directory": Path("/tmp/missing-capture"),
                          "started_at": 0, "process": Mock(pid=7001 + index), "report": {"errors": []}}
                         for index, container in enumerate(capture.containers)]
        for role in capture.roles:
            role["process"].poll.return_value = None
        capture.stop_event = Mock()
        capture.stop_event.wait.return_value = False
        with patch.object(M.time, "monotonic", return_value=M.CAPTURE_SECONDS + 1), \
             patch.object(M.os, "killpg") as kill, patch.object(capture, "reap") as reap:
            capture.watch()
        self.assertEqual([call.args[0] for call in kill.call_args_list], [7001, 7002])
        self.assertEqual(reap.call_count, 2)
        self.assertIn("capture wall limit", capture.roles[0]["report"]["errors"])

    def test_symbol_source_report_is_explicit_and_atime_is_not_mutation(self):
        containers = [{"name": "a", "pid": 101, "image_id": IMAGE}, {"name": "b", "pid": 102, "image_id": IMAGE}]
        capture = M.PerfCapture(containers, "/tmp/not-created", [{"path": "/tmp/symbol.elf", "qualification_report": "/tmp/report.json"}])
        self.assertEqual(capture.symbol_reports, {Path("/tmp/symbol.elf"): Path("/tmp/report.json")})
        values = dict(st_dev=1, st_ino=2, st_nlink=1, st_size=30, st_mtime_ns=40, st_ctime_ns=50)
        first = type("FileInfo", (), dict(values, st_atime_ns=0))()
        read = type("FileInfo", (), dict(values, st_atime_ns=100))()
        changed = type("FileInfo", (), dict(values, st_atime_ns=100, st_mtime_ns=41))()
        self.assertEqual(M.immutable_stat(first), M.immutable_stat(read))
        self.assertNotEqual(M.immutable_stat(first), M.immutable_stat(changed))

    def test_retained_dso_byte_budget_checked_before_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "mapped"
            original.write_bytes(b"\x7fELF" + b"x" * 60)
            capture = M.PerfCapture([{"name": "a", "pid": 101, "image_id": IMAGE},
                                     {"name": "b", "pid": 102, "image_id": IMAGE}], root / "capture", [])
            capture.output.mkdir()
            (capture.output / "elfs").mkdir()
            capture.retained_bytes = M.DSO_BYTES - 32
            role = {"container": capture.containers[0], "mappings": {}, "report": {}}
            @contextlib.contextmanager
            def mapped(*args):
                fd = os.open(original, os.O_RDONLY)
                try:
                    yield fd
                finally:
                    os.close(fd)
            with patch.object(Path, "read_text", return_value="1000-2000 r-xp 0 00:01 7 /bin/proxy\n"), \
                 patch.object(M, "mapped_fd", mapped):
                with self.assertRaisesRegex(ValueError, "1 GiB"):
                    capture.retain(role)
            self.assertEqual(list((capture.output / "elfs").iterdir()), [])

    def test_public_artifacts_do_not_follow_external_elf_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = self.fixture(root / "capture")
            external = root / "external.elf"
            external.write_bytes(b"not an owned artifact")
            external.chmod(0o600)
            private = capture.output / "buildid-cache"
            private.mkdir(mode=0o700)
            role = capture.roles[0]["directory"]
            (role / "leaf-events-window.txt").symlink_to(external)
            (role / "perf-record.stderr").write_text("public leaf diagnostic")
            (role / "perf-record.stderr").chmod(0o600)
            (capture.output / "capture.json").write_text("{}")
            capture.publish_artifacts()
            self.assertEqual(stat.S_IMODE(capture.output.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(role.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((role / "perf-record.stderr").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((role / "perf.data").stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)

    def test_symbol_companion_requires_code_and_build_id_identity(self):
        helper = HERE.parents[2] / ".github/scripts/mesh_production_profile_symbols_test.py"
        spec = importlib.util.spec_from_file_location("synthetic_elf_fixture", helper)
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        Elf = M.elf_reader()
        with tempfile.TemporaryDirectory() as tmp:
            actual, companion = Path(tmp) / "actual", Path(tmp) / "companion"
            generator.elf(actual)
            generator.elf(companion, symbols=True)
            binding = M.qualify_symbols(actual, companion, Elf)
            self.assertFalse(binding["exact_elf_sha_match"])
            self.assertFalse(binding["source_lines_verified"])
            generator.elf(companion, symbols=True, identity=b"87654321")
            with self.assertRaisesRegex(ValueError, "build ID"):
                M.qualify_symbols(actual, companion, Elf)
            generator.elf(companion, symbols=True, code=b"B" * 16)
            with self.assertRaisesRegex(ValueError, "code/data"):
                M.qualify_symbols(actual, companion, Elf)


if __name__ == "__main__":
    unittest.main()
