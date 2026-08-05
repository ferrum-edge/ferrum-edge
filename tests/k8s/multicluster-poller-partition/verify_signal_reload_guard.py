#!/usr/bin/env python3
"""Static regression guard for signal_reload process selection in run.sh.

Locks in cmdline-based identity (not pidof or /proc/<pid>/exe), procfs-safe
reads that do not trust pseudo-file stat sizes, exact argv matching, fail-closed
uniqueness, and same-exec HUP signaling. Does not execute run.sh or any cluster
fixture.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent
DEFAULT_RUN_SH = FIXTURE_DIR / "run.sh"

FORBIDDEN_PATTERNS = (
    re.compile(r"pidof\s+ferrum-edge"),
    re.compile(r"readlink\s+[^\n]*/exe"),
    re.compile(r"/proc/\[0-9\]\*/exe"),
    re.compile(r'\[\s+-s\s+"\$process_dir/cmdline"\s+\]'),
)

REQUIRED_INNER_PATTERNS = (
    re.compile(r"for\s+process_dir\s+in\s+/proc/\[0-9\]\*;\s+do"),
    re.compile(r'\[\s+-r\s+"\$process_dir/cmdline"\s+\]'),
    re.compile(r'done\s*<\s*"\$process_dir/cmdline"'),
    re.compile(r'"\$\{argv0##\*/\}"\s*=\s*"ferrum-edge"'),
    re.compile(r'\[ "\$argv1" = "run" \]'),
    re.compile(r"multiple ferrum-edge run processes found"),
    re.compile(r"no ferrum-edge run process found"),
    re.compile(r"kill -HUP \"\$found\""),
)

INNER_SCRIPT_RE = re.compile(
    r"sh -eu -c '([^']*(?:''[^']*)*)'",
    re.DOTALL,
)

GOOD_INNER = """
    found=""
    for process_dir in /proc/[0-9]*; do
      [ -r "$process_dir/cmdline" ] || continue
      argv0=""
      argv1=""
      pos=0
      while IFS= read -r -d "" arg || [ -n "$arg" ]; do
        case "$pos" in
          0) argv0="$arg" ;;
          1) argv1="$arg"; break ;;
        esac
        pos=$((pos + 1))
      done < "$process_dir/cmdline"
      [ -n "$argv0" ] || continue
      [ "${argv0##*/}" = "ferrum-edge" ] || continue
      [ "$argv1" = "run" ] || continue
      candidate="${process_dir##*/}"
      if [ -n "$found" ]; then
        echo "multiple ferrum-edge run processes found: $found $candidate" >&2
        exit 1
      fi
      found="$candidate"
    done
    [ -n "$found" ] || {
      echo "no ferrum-edge run process found" >&2
      exit 1
    }
    kill -HUP "$found"
"""


class GuardFailure(Exception):
    """One static guard or guard-self-test invariant failed."""


def fail(message: str) -> None:
    raise GuardFailure(message)


def extract_signal_reload_block(text: str) -> str:
    start = text.find("signal_reload()")
    if start < 0:
        fail("signal_reload() is missing")
    end = text.find("deploy_topology()", start)
    if end < 0:
        fail("deploy_topology() boundary after signal_reload() is missing")
    return text[start:end]


def extract_signal_reload_inner(function_block: str) -> str:
    match = INNER_SCRIPT_RE.search(function_block)
    if match is None:
        fail("signal_reload inner sh -eu -c script is missing")
    return match.group(1).replace("''", "'")


def verify_inner(inner: str, function_block: str) -> None:
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(inner):
            fail(f"forbidden pattern in signal_reload inner script: {pattern.pattern}")
    for pattern in REQUIRED_INNER_PATTERNS:
        if not pattern.search(inner):
            fail(f"missing required pattern in signal_reload inner script: {pattern.pattern}")
    if "sh -eu -c" not in function_block:
        fail("signal_reload must discover and signal in one kubectl exec")
    scan_at = inner.find("for process_dir")
    kill_at = inner.find("kill -HUP")
    if scan_at < 0 or kill_at < scan_at:
        fail("kill -HUP must stay inside the same inner exec script as the scan")


def verify_run_sh(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    function_block = extract_signal_reload_block(text)
    verify_inner(extract_signal_reload_inner(function_block), function_block)


def self_test() -> None:
    good = (
        "signal_reload() {\n"
        "  kubectl exec pod/foo -c signal -- sh -eu -c '\n"
        + GOOD_INNER
        + "  '\n}\n"
        + "deploy_topology() { :; }\n"
    )
    verify_run_sh_from_text(good)

    bad_pidof = good.replace(
        '[ "${argv0##*/}" = "ferrum-edge" ] || continue',
        "pidof ferrum-edge",
        1,
    )
    if not rejects(bad_pidof):
        fail("self-test: pidof must be rejected")

    bad_exe = good.replace(
        '[ -r "$process_dir/cmdline" ] || continue',
        'executable="$(readlink "$process_dir/exe")"',
        1,
    )
    if not rejects(bad_exe):
        fail("self-test: /proc exe readlink must be rejected")

    bad_procfs_size_gate = good.replace(
        '[ -r "$process_dir/cmdline" ] || continue',
        '[ -r "$process_dir/cmdline" ] || continue\n'
        '      [ -s "$process_dir/cmdline" ] || continue',
        1,
    )
    if not rejects(bad_procfs_size_gate):
        fail("self-test: procfs cmdline must not be gated on its zero stat size")

    bad_argv = good.replace('[ "$argv1" = "run" ]', '[ "$argv1" = "health" ]', 1)
    if not rejects(bad_argv):
        fail("self-test: exact run subcommand check must be required")

    bad_scan_root = good.replace(
        "for process_dir in /proc/[0-9]*; do",
        "for process_dir in /tmp/[0-9]*; do",
        1,
    )
    if not rejects(bad_scan_root):
        fail("self-test: the process scan must stay rooted under /proc")

    bad_cmdline_source = good.replace(
        'done < "$process_dir/cmdline"',
        'done < "$process_dir/status"',
        1,
    )
    if not rejects(bad_cmdline_source):
        fail("self-test: argv parsing must read the process cmdline")

    bad_late_script = (
        "signal_reload() { :; }\n"
        "deploy_topology() {\n"
        "  sh -eu -c '\n"
        + GOOD_INNER
        + "  '\n}\n"
    )
    if not rejects(bad_late_script):
        fail("self-test: a later shell block must not satisfy signal_reload")


def rejects(text: str) -> bool:
    try:
        verify_run_sh_from_text(text)
    except GuardFailure:
        return True
    return False


def verify_run_sh_from_text(text: str) -> None:
    function_block = extract_signal_reload_block(text)
    verify_inner(extract_signal_reload_inner(function_block), function_block)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "run_sh",
        nargs="?",
        default=str(DEFAULT_RUN_SH),
        help="path to run.sh (default: fixture run.sh)",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    try:
        # Always prove the guard accepts its canonical good fixture and rejects
        # every protected regression before trusting it to judge run.sh. The
        # previous guard skipped this path during ordinary preflight and blocked
        # the live topology with an impossible combined-path regex.
        self_test()
        if args.self_test:
            print("verify_signal_reload_guard self-test passed")
            return 0
        verify_run_sh(Path(args.run_sh))
        print(f"signal_reload guard ok: {args.run_sh}")
        return 0
    except GuardFailure as error:
        print(f"signal_reload guard: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
