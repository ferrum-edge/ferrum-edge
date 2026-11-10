"""Tests for resolve-agent-bin.sh without making model requests.

Run: python3 .agents/skills/_lib/test_resolve_agent_bin.py

The regression that matters (#394): with a relative PATH entry, the
resolver used to print the relative result, so a dispatcher that saved
it, changed into a worker worktree, and executed it launched whatever
same-named file the worktree contained. The result must be the
executable chosen in the caller's directory, as an absolute path.
"""

import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

RESOLVER = Path(__file__).resolve().parent / "resolve-agent-bin.sh"
BASH = shutil.which("bash") or "/bin/bash"


def resolve(cwd: Path, path: str, extra_env: dict[str, str] | None = None):
    # The caller's own entries come first; system dirs keep coreutils
    # (dirname/basename) reachable, as on an operator's machine.
    env = {"PATH": f"{path}:/usr/bin:/bin", "HOME": str(cwd)}
    env.update(extra_env or {})
    return subprocess.run(
        [
            BASH,
            "-c",
            f'. "{RESOLVER}"; resolve_agent_bin faketool FAKETOOL_BIN',
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class ResolveAgentBinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_relative_path_entry_resolves_against_caller_directory(self) -> None:
        chosen = executable(self.root / "bin" / "faketool")
        # A same-named decoy where a dispatcher would cd to afterwards.
        executable(self.root / "worktree" / "faketool")
        result = resolve(self.root, "bin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(chosen))

    def test_dot_path_entry_resolves_to_caller_directory(self) -> None:
        chosen = executable(self.root / "faketool")
        result = resolve(self.root, ".")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(chosen))

    def test_absolute_path_entry_is_unchanged(self) -> None:
        chosen = executable(self.root / "bin" / "faketool")
        result = resolve(self.root, str(self.root / "bin"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(chosen))

    def test_symlinked_parent_traversal_keeps_the_selected_executable(self) -> None:
        # PATH=link/../bin selects actual/bin/faketool through the
        # symlink; logical `cd` would cancel link/.. textually and pick
        # the caller's own bin/faketool instead.
        chosen = executable(self.root / "actual" / "bin" / "faketool")
        executable(self.root / "bin" / "faketool")
        (self.root / "actual" / "inner").mkdir(parents=True)
        (self.root / "link").symlink_to(self.root / "actual" / "inner", target_is_directory=True)
        result = resolve(self.root, "link/../bin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(chosen))

    def test_inherited_cdpath_does_not_break_resolution(self) -> None:
        chosen = executable(self.root / "bin" / "faketool")
        result = resolve(self.root, "bin", {"CDPATH": "."})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(chosen))

    def test_relative_override_is_refused(self) -> None:
        result = resolve(self.root, "bin", {"FAKETOOL_BIN": "bin/faketool"})
        self.assertEqual(result.returncode, 127)

    def test_missing_cli_fails(self) -> None:
        result = resolve(self.root, str(self.root))
        self.assertEqual(result.returncode, 127)


if __name__ == "__main__":
    unittest.main(verbosity=2)
