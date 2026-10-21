#!/usr/bin/env python3
"""Offline tests; never invokes Docker, Cargo, downloads or the build entry point."""
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import mesh_production_profile_ferrum as M
from mesh_production_profile_symbols_test import elf


class Equivalence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.shipping, self.diagnostic = self.root / "shipping", self.root / "diagnostic"
        elf(self.shipping)
        elf(self.diagnostic, symbols=True)

    def tearDown(self):
        self.temp.cleanup()

    def compare(self):
        return M.qualify(self.shipping, self.diagnostic, minimum_functions=1)

    def test_matching_code_qualifies_only_diagnostic_image(self):
        result = self.compare()
        self.assertTrue(result["qualified"])
        self.assertFalse(result["symbols_may_be_applied_to_shipping"])
        self.assertFalse(result["sampled_coverage_verified"])
        self.assertFalse(result["source_line_attribution_verified"])

    def test_build_id_alone_may_differ_but_is_retained(self):
        elf(self.diagnostic, symbols=True, identity=b"87654321")
        result = self.compare()
        self.assertTrue(result["qualified"])
        self.assertNotEqual(result["shipping_build_id"], result["diagnostic_build_id"])

    def test_code_mismatch_rejects_same_build_id(self):
        elf(self.diagnostic, symbols=True, code=b"B" * 16)
        result = self.compare()
        self.assertFalse(result["qualified"])
        self.assertIn(".text", result["allocated_section_differences"])

    def test_runtime_data_mismatch_rejected(self):
        content = self.diagnostic.read_bytes().replace(b"DATA1234", b"DATA5678")
        self.diagnostic.write_bytes(content)
        result = self.compare()
        self.assertFalse(result["qualified"])
        self.assertIn(".data", result["allocated_section_differences"])

    def test_segment_layout_and_entry_mismatch_rejected(self):
        original = self.diagnostic.read_bytes()
        for offset, value in [(24, 0x400081), (64 + 16, 0x400081)]:
            with self.subTest(offset=offset):
                changed = bytearray(original)
                struct.pack_into("<Q", changed, offset, value)
                self.diagnostic.write_bytes(changed)
                self.assertFalse(self.compare()["qualified"])

    def test_missing_or_insufficient_symbols_rejected(self):
        self.assertFalse(M.qualify(self.shipping, self.diagnostic)["qualified"])
        elf(self.diagnostic)
        self.assertFalse(self.compare()["qualified"])

    def test_malformed_missing_and_oversize_elf_rejected(self):
        self.diagnostic.write_bytes(b"invalid ELF")
        self.assertFalse(self.compare()["qualified"])
        self.diagnostic.unlink()
        self.assertFalse(self.compare()["qualified"])
        elf(self.diagnostic, symbols=True)
        with patch.dict(M.LIMITS, elf_bytes=4):
            self.assertFalse(self.compare()["qualified"])


class BuildInputs(unittest.TestCase):
    def test_dockerfile_capture_is_after_dummy_warmup_and_changes_no_profile(self):
        original = f"FROM {M.BUILDER} AS builder\nARG CARGO_PROFILE=release\nRUN dummy\nCOPY src ./src\nRUN real\n"
        changed = M.diagnostic_dockerfile(original)
        self.assertNotIn("ENV CARGO_PROFILE", changed)
        self.assertEqual(changed.split("COPY src ./src")[0], original.split("COPY src ./src")[0])
        self.assertTrue(changed.endswith("RUN real\n"))
        self.assertIn('ENV PATH="/opt/mesh-link-capture:${PATH}"', changed)
        for wrong in [original.replace(M.BUILDER, "rust:latest"), original * 2, original + "COPY .cargo ./\n"]:
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                M.diagnostic_dockerfile(wrong)

    def test_canary_report_binds_exact_helpers_and_builder(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "canary.json"
            report = dict(action="canary", qualified=True, builder=M.BUILDER, helpers=M.helper_hashes(),
                          canary=dict(matching_metadata=True, identical_first_output=True, same_result=True,
                                      equivalence=dict(qualified=True)))
            path.write_text(json.dumps(report))
            self.assertEqual(M.validate_canary(path)["builder"], M.BUILDER)
            for key, bad in (("builder", "mutable:latest"), ("helpers", {}), ("qualified", False)):
                changed = dict(report, **{key: bad})
                path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, "passed canary"):
                    M.validate_canary(path)

    def test_three_way_gate_requires_matching_build_ids_and_code(self):
        with tempfile.TemporaryDirectory() as temp:
            a, b, c = [Path(temp) / x for x in ("shipping", "fresh", "symbols")]
            elf(a); elf(b); elf(c, symbols=True)
            self.assertTrue(M.qualify_chain(a, b, c, 1)["symbols_may_be_applied_to_shipping"])
            elf(c, symbols=True, identity=b"87654321")
            result = M.qualify_chain(a, b, c, 1)
            self.assertTrue(result["fresh_to_symbols"]["qualified"])
            self.assertFalse(result["qualified"])
            elf(c, symbols=True); elf(b, code=b"B" * 16)
            self.assertFalse(M.qualify_chain(a, b, c, 1)["qualified"])

    def test_current_source_profile_and_dockerfile_are_admitted(self):
        root = Path(__file__).resolve().parents[2]
        result = M.validate_profile((root / "Cargo.toml").read_text())
        self.assertEqual(result["features"], "cloud-secrets")
        self.assertFalse(result["debug"])
        self.assertEqual(result["diagnostic_override"], {})
        self.assertEqual(M.validate_profile(M.CANARY_MANIFEST)["diagnostic_override"], {})
        self.assertIn("command -v python3", M.VERSION_COMMAND)
        M.diagnostic_dockerfile((root / "Dockerfile").read_text())
        for wrong in [(root / "Cargo.toml").read_text().replace('lto = "fat"', 'lto = "off"'),
                      (root / "Cargo.toml").read_text().replace('[profile.release]', '[profile.release]\ndebug = true')]:
            with self.assertRaises(ValueError):
                M.validate_profile(wrong)

    def test_source_archive_allows_only_known_internal_agents_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as target:
                regular = tarfile.TarInfo("CLAUDE.md")
                regular.size = 4
                target.addfile(regular, io.BytesIO(b"test"))
                link = tarfile.TarInfo("AGENTS.md")
                link.type, link.linkname = tarfile.SYMTYPE, "CLAUDE.md"
                target.addfile(link)
            dest = root / "dest"
            dest.mkdir()
            self.assertEqual(M.unpack_source(archive, dest)["files"], 2)
            self.assertEqual((dest / "AGENTS.md").read_text(), "test")
            with tarfile.open(archive, "w") as target:
                link.linkname = "../escape"
                target.addfile(link)
            with self.assertRaises(ValueError):
                M.unpack_source(archive, dest)

    def test_source_archive_size_and_path_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "source.tar"
            with tarfile.open(archive, "w") as target:
                member = tarfile.TarInfo("../escape")
                member.size = 4
                target.addfile(member, io.BytesIO(b"test"))
            with self.assertRaises(tarfile.FilterError):
                M.unpack_source(archive, root / "dest")
            with patch.dict(M.LIMITS, source_bytes=1), self.assertRaises(ValueError):
                M.unpack_source(archive, root / "dest")


class CommandBounds(unittest.TestCase):
    def test_owned_cleanup_has_separate_bounded_budget_after_total_timeout(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(M, "time") as clock:
            clock.monotonic.return_value = 1.0
            commands = M.Commands(Path(temp), {})
            clock.monotonic.return_value = 1.0 + M.LIMITS["total_seconds"] + 1.0
            _, code = commands.run([sys.executable, "-c", "pass"], "cleanup", cleanup=True)
            self.assertEqual(code, 0)
            self.assertEqual(commands.report["commands"][0]["timeout_seconds"], 30)

    def test_command_receipt_and_nonzero_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            report = {}
            commands = M.Commands(Path(temp), report)
            output, code = commands.run([sys.executable, "-c", "print('retained')"], "success")
            self.assertEqual(code, 0)
            self.assertEqual(output.read_text(), "retained\n")
            self.assertIn("stdout_sha256", report["commands"][0])
            with self.assertRaisesRegex(ValueError, "failed"):
                commands.run([sys.executable, "-c", "raise SystemExit(3)"], "failure")
            self.assertEqual(report["commands"][1]["returncode"], 3)

    def test_shared_build_budget_expires_before_launch(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(M, "time") as clock, \
                patch.object(M.subprocess, "Popen") as launch:
            clock.monotonic.return_value = 2.0
            commands = M.Commands(Path(temp), {})
            commands.build_started = clock.monotonic()
            clock.monotonic.return_value = 2.0 + M.LIMITS["build_seconds"] + 1.0
            with self.assertRaisesRegex(ValueError, "budget exhausted"):
                commands.run(["never-executed"], "no-build", build=True)
            launch.assert_not_called()

    def test_short_host_uptime_is_not_an_expired_build_budget(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(M, "time") as clock, \
                patch.object(M.subprocess, "Popen") as launch:
            clock.monotonic.return_value = 0.25
            commands = M.Commands(Path(temp), {})
            commands.build_started = clock.monotonic()
            clock.monotonic.return_value = 0.75
            launch.return_value.poll.return_value = 0
            launch.return_value.returncode = 0
            _, code = commands.run(["fake-command"], "short-uptime", build=True)
            self.assertEqual(code, 0)
            self.assertEqual(commands.report["commands"][0]["timeout_seconds"], 60)
            launch.assert_called_once()

    def test_short_uptime_expired_budget_still_rejects_before_launch(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(M, "time") as clock, \
                patch.object(M.subprocess, "Popen") as launch, \
                patch.dict(M.LIMITS, build_seconds=0.25):
            clock.monotonic.return_value = 0.25
            commands = M.Commands(Path(temp), {})
            commands.build_started = clock.monotonic()
            clock.monotonic.return_value = 0.75
            with self.assertRaisesRegex(ValueError, "budget exhausted"):
                commands.run(["never-executed"], "short-expired", build=True)
            launch.assert_not_called()

    def test_low_disk_build_stops_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as temp:
            report = {}
            commands = M.Commands(Path(temp), report)
            with patch.dict(M.LIMITS, stop_free_bytes=2**100):
                with self.assertRaisesRegex(ValueError, "disk reserve"):
                    commands.run([sys.executable, "-c", "import time;time.sleep(5)"], "disk-stop", build=True)
            self.assertTrue(report["commands"][0]["interrupted"])
            self.assertIsNotNone(report["commands"][0]["returncode"])

    def test_timeout_reaps_only_owned_child(self):
        with tempfile.TemporaryDirectory() as temp:
            report = {}
            commands = M.Commands(Path(temp), report)
            with self.assertRaises(M.subprocess.TimeoutExpired):
                commands.run([sys.executable, "-c", "import time;time.sleep(5)"], "timeout", seconds=0.05)
            self.assertTrue(report["commands"][0]["interrupted"])
            self.assertIsNotNone(report["commands"][0]["returncode"])
            self.assertIn("stdout_sha256", report["commands"][0])
            self.assertLess(report["commands"][0]["elapsed_seconds"], 2)


if __name__ == "__main__":
    unittest.main()
