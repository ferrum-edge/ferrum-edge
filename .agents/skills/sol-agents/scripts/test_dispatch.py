"""Exercise the real launcher with a fake Codex executable; no model requests."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


LAUNCHER = Path(__file__).with_name("dispatch-agent.sh")
EFFORTS = ("low", "medium", "high", "xhigh", "max", "ultra")
LAUNCHERS = (
    (LAUNCHER, "gpt-6.1-sol", EFFORTS),
    (
        Path(__file__).parents[2] / "astra-agents" / "scripts" / "dispatch-agent.sh",
        "gpt-6-astra",
        EFFORTS,
    ),
    (
        Path(__file__).parents[2] / "luna-agents" / "scripts" / "dispatch-agent.sh",
        "gpt-6-luna",
        EFFORTS[:-1],
    ),
)


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sol-dispatch-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        primary = self.root / "primary"
        primary.mkdir()
        subprocess.run(["git", "init", "--quiet", str(primary)], check=True)
        subprocess.run(
            ["git", "-C", str(primary), "-c", "user.name=Sol tests",
             "-c", "user.email=sol-tests@example.invalid", "-c", "commit.gpgsign=false",
             "commit", "--quiet", "--allow-empty", "-m", "Initialize fixture"],
            check=True,
        )
        self.worktree = self.root / "worker with spaces"
        subprocess.run(
            ["git", "-C", str(primary), "worktree", "add", "--quiet", "--detach",
             str(self.worktree), "HEAD"], check=True,
        )
        self.prompt = self.root / "prompt with spaces.txt"
        self.prompt_text = "Implement the scoped task.\nKeep literal $(text) and `text`.\n"
        self.prompt.write_text(self.prompt_text)
        self.mock = self.root / "fake codex"
        self.mock.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "print(json.dumps({'args': sys.argv[1:], 'cwd': os.getcwd(), "
            "'prompt': sys.stdin.read()}))\n"
            "sys.exit(int(os.environ.get('SOL_TEST_EXIT_CODE', '0')))\n"
        )
        self.mock.chmod(0o700)

    def launch(self, *flags, effort="high", status=0, launcher=LAUNCHER):
        env = os.environ.copy()
        env.update(CODEX_BIN=str(self.mock), SOL_TEST_EXIT_CODE=str(status))
        return subprocess.run(
            [
                "bash",
                str(launcher),
                "--worktree",
                str(self.worktree),
                "--prompt-file",
                str(self.prompt),
                "--effort",
                effort,
                *flags,
            ],
            cwd=self.root, env=env, capture_output=True, text=True, timeout=15,
        )

    def test_model_effort_speed_and_prompt(self):
        for launcher, model, efforts in LAUNCHERS:
            for effort in efforts:
                for flags, tier, fast_mode in [
                    ((), "default", None),
                    (("--fast",), "fast", "true"),
                    (("--no-fast",), "default", None),
                ]:
                    with self.subTest(model=model, effort=effort, flags=flags):
                        result = self.launch(*flags, effort=effort, launcher=launcher)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        payload = json.loads(result.stdout)
                        args = payload["args"]
                        self.assertEqual(args[0], "exec")
                        self.assertEqual(args[args.index("--model") + 1], model)
                        configs = [
                            args[i + 1]
                            for i, value in enumerate(args)
                            if value == "--config"
                        ]
                        self.assertIn(f'model_reasoning_effort="{effort}"', configs)
                        self.assertIn(f'service_tier="{tier}"', configs)
                        if fast_mode is None:
                            self.assertNotIn("features.fast_mode=false", configs)
                        else:
                            self.assertIn(f"features.fast_mode={fast_mode}", configs)
                        self.assertEqual(args[-1], "-")
                        self.assertEqual(payload["prompt"], self.prompt_text)
                        self.assertEqual(Path(payload["cwd"]).resolve(), self.worktree)
                        self.assertIn(
                            f"fast={'true' if fast_mode is not None else 'false'} "
                            f"service_tier={tier}",
                            result.stderr,
                        )

    def test_conflicting_speed_options_refuse_dispatch(self):
        for flags in [("--fast", "--no-fast"), ("--no-fast", "--fast")]:
            with self.subTest(flags=flags):
                result = self.launch(*flags)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("Conflicting speed options", result.stderr)

    def test_unsupported_effort_refuses_dispatch(self):
        for effort in ("none", "minimal", "invalid"):
            with self.subTest(effort=effort):
                result = self.launch(effort=effort)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("Invalid effort", result.stderr)

    def test_worker_failure_is_preserved(self):
        result = self.launch("--fast", status=17)
        self.assertEqual(result.returncode, 17, result.stderr)


if __name__ == "__main__":
    unittest.main()
