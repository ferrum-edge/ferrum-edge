#!/usr/bin/env python3
"""Regressions for bounded, observational release-host telemetry."""

import importlib.util
import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "resources", Path(__file__).resolve().parents[1] / "collect_release_build_resources.py"
)
resources = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resources)


class ResourceObservationTests(unittest.TestCase):
    def test_missing_and_oversized_files_are_explicitly_unavailable(self):
        with patch.object(Path, "open", side_effect=PermissionError):
            self.assertEqual(resources.read_resource(Path("/proc/meminfo"))["status"], "unavailable")
        with patch.object(Path, "open", return_value=io.StringIO("x" * (resources.READ_LIMIT + 1))):
            self.assertEqual(resources.read_resource(Path("/proc/meminfo"))["reason"], "read_limit_exceeded")

    def test_command_failures_and_timeouts_do_not_fabricate_observations(self):
        for failure in (FileNotFoundError(), subprocess.TimeoutExpired("nproc", 10)):
            with self.subTest(failure=failure), patch.object(resources.subprocess, "run", side_effect=failure):
                self.assertEqual(resources.observe_host_commands()["cpu_count"]["status"], "unavailable")
        with patch.object(resources.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "secret")):
            result = resources.observe_host_commands()["cpu_count"]
            self.assertEqual(result, {"status": "unavailable", "exit_code": 1})

    def test_kernel_filter_retains_evidence_without_claiming_causality(self):
        text = "unrelated kernel detail\nOut of memory: Killed process 123 (rustc)\n"
        with patch.object(resources.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, text, "")):
            result = resources.format_observation(subprocess.CompletedProcess([], 0, text, ""), kernel=True)
        self.assertEqual(result["matching_lines"], ["Out of memory: Killed process 123 (rustc)"])
        self.assertTrue(result["absence_does_not_exclude_oom"])
        self.assertNotIn("oom_proven", result)

    def test_empty_and_truncated_kernel_logs_cannot_disprove_oom(self):
        for text in ("nothing relevant", "x" * (resources.READ_LIMIT + 1)):
            with self.subTest(length=len(text)), patch.object(resources.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, text, "")):
                result = resources.format_observation(subprocess.CompletedProcess([], 0, text, ""), kernel=True)
                self.assertEqual(result["matching_lines"], [])
                self.assertTrue(result["absence_does_not_exclude_oom"])
                self.assertEqual(result["truncated"], len(text) > resources.READ_LIMIT)

    def test_collection_reads_only_fixed_resources_and_fixed_commands(self):
        meminfo = "MemTotal: 16000 kB\nMemAvailable: 8000 kB\nSwapTotal: 4000 kB\nSwapFree: 3000 kB\nUnrelated: hidden\n"
        with patch.object(resources, "read_resource", return_value={"status": "observed", "value": meminfo}) as read, patch.object(resources.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "")) as command:
            result = resources.collect("after")
        self.assertEqual(set(result["meminfo"]["value"]), resources.MEMINFO_KEYS)
        self.assertEqual([call.args[0].as_posix() for call in read.call_args_list], ["/proc/meminfo"] + ["/sys/fs/cgroup/" + name for name in resources.CGROUP_FILES])
        self.assertEqual([call.args[0][0] for call in command.call_args_list], ["nproc", "uname", "df", "docker", "sudo"])
        self.assertEqual(command.call_args_list[-1].args[0], ["sudo", "-n", "dmesg", "--ctime"])
        self.assertIn("not per-rustc peak", result["scope"])


if __name__ == "__main__":
    unittest.main()
