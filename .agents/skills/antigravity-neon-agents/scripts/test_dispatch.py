"""Exercise the real launcher with a fake agy executable; no model requests."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


LAUNCHER = Path(__file__).with_name("dispatch-agent.sh")
EFFORTS = ("low", "medium", "high", "xhigh")


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="antigravity-dispatch-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        primary = self.root / "primary"
        primary.mkdir()
        subprocess.run(["git", "init", "--quiet", str(primary)], check=True)
        subprocess.run(
            ["git", "-C", str(primary), "-c", "user.name=Antigravity tests",
             "-c", "user.email=antigravity-tests@example.invalid",
             "-c", "commit.gpgsign=false",
             "commit", "--quiet", "--allow-empty", "-m", "Initialize fixture"],
            check=True,
        )
        self.worktree = self.root / "worker with spaces"
        subprocess.run(
            ["git", "-C", str(primary), "worktree", "add", "--quiet", "--detach",
             str(self.worktree), "HEAD"], check=True,
        )
        self.prompt = self.root / "prompt with spaces.txt"
        self.prompt_text = "-Implement the scoped task.\nKeep literal $(text) and `text`.\n"
        self.prompt.write_text(self.prompt_text)
        self.mock = self.root / "fake agy"
        self.mock.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "print(json.dumps({'args': sys.argv[1:], 'cwd': os.getcwd(), "
            "'stdin': sys.stdin.read()}))\n"
            "sys.exit(int(os.environ.get('AGY_TEST_EXIT_CODE', '0')))\n"
        )
        self.mock.chmod(0o700)

    def launch(self, *flags, worktree=None, prompt=None, status=0):
        env = os.environ.copy()
        env.update(AGY_BIN=str(self.mock), AGY_TEST_EXIT_CODE=str(status))
        return subprocess.run(
            [
                "bash",
                str(LAUNCHER),
                "--worktree",
                str(worktree or self.worktree),
                "--prompt-file",
                str(prompt or self.prompt),
                *flags,
            ],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=15,
        )

    def test_model_effort_and_prompt(self):
        for effort in EFFORTS:
            with self.subTest(effort=effort):
                result = self.launch("--effort", effort)
                self.assertEqual(result.returncode, 0, result.stderr)
                call = json.loads(result.stdout)
                args = call["args"]
                self.assertEqual(args[args.index("--model") + 1], "gemini-4-neon")
                self.assertEqual(args[args.index("--effort") + 1], effort)
                self.assertIn("--dangerously-skip-permissions", args)
                self.assertIn("--disable-slash-commands", args)
                self.assertNotIn("--sandbox", args)
                self.assertEqual(args[args.index("--output-format") + 1], "stream-json")
                # The prompt is attached to --print so a leading "-" is not
                # parsed as a flag, and is passed byte-for-byte minus the
                # trailing newline that $(<file) strips.
                self.assertEqual(args[-1], "--print=" + self.prompt_text.rstrip("\n"))
                self.assertEqual(call["stdin"], "")
                self.assertEqual(Path(call["cwd"]).resolve(), self.worktree.resolve())
                self.assertIn(f"effort={effort}", result.stderr)

    def test_default_effort_is_high(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(result.stdout)["args"]
        self.assertEqual(args[args.index("--effort") + 1], "high")

    def test_rejects_unpublished_efforts_without_clamping(self):
        for effort in ("max", "ultra", "minimal", ""):
            with self.subTest(effort=effort):
                result = self.launch("--effort", effort)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("Invalid effort", result.stderr)

    def test_rejects_fast_and_model_override(self):
        for flags in (("--fast",), ("--model", "gemini-4-carbon")):
            with self.subTest(flags=flags):
                result = self.launch(*flags)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_requires_worktree_root_and_nonempty_prompt(self):
        sub = self.worktree / "sub"
        sub.mkdir()
        result = self.launch(worktree=sub)
        self.assertEqual(result.returncode, 2)
        self.assertIn("worktree root", result.stderr)
        empty = self.root / "empty.txt"
        empty.write_text(" \n")
        result = self.launch(prompt=empty)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Prompt file is empty", result.stderr)

    def test_propagates_cli_exit_status(self):
        result = self.launch(status=7)
        self.assertEqual(result.returncode, 7)


if __name__ == "__main__":
    unittest.main()
