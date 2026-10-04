"""Synthetic scanner controls, run by the hosted qualifier before real fixtures."""

import copy
import io
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def check_fixture_scan_helpers(qualifier):
    class FixtureScanTests(unittest.TestCase):
        def setUp(self):
            self.passwords = tuple(character * 64 for character in "abc")
            self.names = (qualifier.PG, qualifier.MYSQL)
            self.containers = {
                name: {
                    "Config": {
                        "Healthcheck": {"Test": ["CMD", "client", "SELECT 1"]},
                        "Env": ["PASSWORD_FILE=/run/secrets/password"],
                        "Entrypoint": ["entrypoint"],
                    },
                    "State": {
                        "Pid": pid,
                        "Health": {
                            "Status": "healthy",
                            "Log": [{"ExitCode": 0, "Output": "1\n"},
                                    {"ExitCode": 0, "Output": "1\n"}],
                        },
                    },
                }
                for name, pid in zip(self.names, (100, 200))
            }
            self.inventories = {name: {pid: "server", pid + 1: "client SELECT SLEEP(4)"}
                                for name, pid in zip(self.names, (100, 200))}
            self.logs = {name: SimpleNamespace(stdout="startup\n", stderr="")
                         for name in self.names}
            self.host_argv = [b"docker\0exec\0client\0SELECT SLEEP(4)\0"]

        def scan(self):
            with patch.object(qualifier, "inspect", side_effect=self.containers.__getitem__), \
                    patch.object(qualifier, "run",
                                 side_effect=lambda command: self.logs[command[1]["container"]]):
                qualifier.assert_no_exposure(
                    self.names, self.passwords, self.inventories, self.host_argv,
                )

        def test_all_surfaces_reject_every_canary(self):
            self.scan()
            for name in self.names:
                for canary in self.passwords:
                    for surface in ("health-config", "health-log-first", "health-log-last",
                                    "server-argv", "client-argv",
                                    "stdout", "stderr", "environment", "entrypoint", "host-argv"):
                        with self.subTest(container=name, surface=surface):
                            original = copy.deepcopy((self.containers, self.inventories,
                                                      self.logs, self.host_argv))
                            container = self.containers[name]
                            if surface == "health-config":
                                container["Config"]["Healthcheck"]["Test"].append(canary)
                            elif surface in ("health-log-first", "health-log-last"):
                                index = 0 if surface == "health-log-first" else -1
                                container["State"]["Health"]["Log"][index]["Output"] += canary
                            elif surface in ("server-argv", "client-argv"):
                                pid = container["State"]["Pid"] + (surface == "client-argv")
                                self.inventories[name][pid] += " " + canary
                            elif surface in ("stdout", "stderr"):
                                setattr(self.logs[name], surface, canary)
                            elif surface == "environment":
                                container["Config"]["Env"].append("OTHER=" + canary)
                            elif surface == "entrypoint":
                                container["Config"]["Entrypoint"].append(canary)
                            else:
                                self.host_argv.append(canary.encode("ascii"))
                            with self.assertRaises(RuntimeError) as failure:
                                self.scan()
                            self.assertNotIn(canary, str(failure.exception))
                            (self.containers, self.inventories,
                             self.logs, self.host_argv) = original

        def test_missing_surfaces_cannot_pass(self):
            for name in self.names:
                for surface in ("health-config", "health-history", "health-output",
                                "unhealthy", "server-argv", "container-logs"):
                    with self.subTest(container=name, surface=surface):
                        original = copy.deepcopy((self.containers, self.inventories, self.logs))
                        container = self.containers[name]
                        if surface == "health-config":
                            container["Config"]["Healthcheck"] = {"Test": ["NONE"]}
                        elif surface == "health-history":
                            container["State"]["Health"]["Log"] = []
                        elif surface == "health-output":
                            del container["State"]["Health"]["Log"][0]["Output"]
                        elif surface == "unhealthy":
                            container["State"]["Health"]["Status"] = "unhealthy"
                        elif surface == "server-argv":
                            del self.inventories[name][container["State"]["Pid"]]
                        else:
                            self.logs[name] = SimpleNamespace(stdout="", stderr="")
                        with self.assertRaises(RuntimeError):
                            self.scan()
                        self.containers, self.inventories, self.logs = original

        def test_process_inventory_requires_pid_and_full_argv(self):
            canary = self.passwords[0]
            argv = "client " + "x" * 4096 + " " + canary
            inventory = qualifier.parse_process_inventory("PID   COMMAND\n123   " + argv + "\n")
            self.assertEqual(inventory, {123: argv})
            with self.assertRaises(RuntimeError):
                qualifier.reject_credentials([inventory[123].encode("ascii")], self.passwords)
            for output in ("", "COMMAND\nclient\n", "PID COMMAND\n", "PID COMMAND\n123\n",
                           "PID COMMAND\n-1 client\n", "PID COMMAND\n123 client\n123 other\n",
                           "PID COMMAND\n\n", "x" * 1048577):
                with self.subTest():
                    with self.assertRaises(RuntimeError):
                        qualifier.parse_process_inventory(output)
            wrapper = Path("scripts/compose_fixture_command.sh").read_text()
            self.assertIn('exec docker top "${FIXTURE_CONTAINER:?}" -eo pid,args -ww', wrapper)

        def test_command_failures_are_fatal_and_private(self):
            command = qualifier.request("top", container=qualifier.PG)
            canary = self.passwords[0]
            failed = SimpleNamespace(returncode=17, stdout=canary, stderr=canary)
            with patch.object(qualifier.subprocess, "run", return_value=failed):
                with self.assertRaises(RuntimeError) as failure:
                    qualifier.process_inventory(qualifier.PG)
                self.assertIn("stage=top-postgres exit=17", str(failure.exception))
                self.assertNotIn(canary, str(failure.exception))
                for operation in ("inspect", "top", "logs"):
                    for name, label in zip(self.names, ("postgres", "mysql")):
                        with self.assertRaises(RuntimeError) as failure:
                            qualifier.run(qualifier.request(operation, container=name))
                        self.assertIn("stage=" + operation + "-" + label, str(failure.exception))
                        self.assertNotIn(canary, str(failure.exception))
            for error, category in (
                (subprocess.TimeoutExpired(canary, 30, output=canary, stderr=canary), "deadline"),
                (OSError(canary), "launch"),
            ):
                with patch.object(qualifier.subprocess, "run", side_effect=error):
                    with self.assertRaises(RuntimeError) as failure:
                        qualifier.run(command)
                    self.assertIn(category + " stage=top-postgres", str(failure.exception))
                    self.assertNotIn(canary, str(failure.exception))
            message = qualifier.command_failure(
                qualifier.request(canary, container=canary), canary, canary,
            )
            self.assertNotIn(canary, message)
            self.assertIn("stage=fixture-command exit=none", message)

        def test_host_inventory_requires_both_owned_clients(self):
            queries = ("SELECT pg_sleep(4)", "SELECT SLEEP(4)")
            probes = [(SimpleNamespace(pid=pid, poll=lambda: None), query)
                      for pid, query in zip((111, 222), queries)]
            paths = [Path("/proc/111"), Path("/proc/222")]
            argv = [b"/usr/bin/docker\0exec\0" + query.encode("ascii") + b"\0" for query in queries]
            with patch.object(qualifier.Path, "iterdir", return_value=paths), \
                    patch.object(qualifier.Path, "read_bytes", side_effect=argv):
                self.assertEqual(qualifier.host_process_inventory(iter(probes)), argv)
            for data in ([], [paths[0]]):
                with patch.object(qualifier.Path, "iterdir", return_value=data), \
                        patch.object(qualifier.Path, "read_bytes", return_value=argv[0]):
                    with self.assertRaises(RuntimeError):
                        qualifier.host_process_inventory(probes)
            for error in (PermissionError("private"), FileNotFoundError("private")):
                with patch.object(qualifier.Path, "iterdir", return_value=paths), \
                        patch.object(qualifier.Path, "read_bytes", side_effect=error):
                    with self.assertRaises(RuntimeError):
                        qualifier.host_process_inventory(probes)
            for data in (b"", b"bash\0SELECT pg_sleep(4)\0", b"docker\0unrelated\0"):
                with patch.object(qualifier.Path, "iterdir", return_value=paths), \
                        patch.object(qualifier.Path, "read_bytes", return_value=data):
                    with self.assertRaises(RuntimeError):
                        qualifier.host_process_inventory(probes)
            exited = SimpleNamespace(pid=111, poll=lambda: 0)
            with self.assertRaises(RuntimeError):
                qualifier.host_process_inventory([(exited, queries[0]), probes[1]])
            with patch.object(qualifier.Path, "iterdir", side_effect=PermissionError("private")):
                with self.assertRaises(RuntimeError):
                    qualifier.host_process_inventory(probes)

        def test_invalid_canaries_cannot_pass(self):
            for passwords in ((), self.passwords[:2], ("", *self.passwords[1:]),
                              ("not-generated", *self.passwords[1:])):
                with self.assertRaises(RuntimeError):
                    qualifier.reject_credentials([b"clean"], passwords)

    # Assertion/exception details can contain synthetic canaries. Withhold the
    # unittest stream even on failure; only a fixed aggregate result is public.
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FixtureScanTests)
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    qualifier.require(result.wasSuccessful(),
                      "Fixture scanner negative self-check failed (details withheld)")
    print("PASS: fixture scanner canary and command-failure self-checks; no runtime scan evidence", flush=True)
