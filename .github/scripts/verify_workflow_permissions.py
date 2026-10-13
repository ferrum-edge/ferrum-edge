#!/usr/bin/env python3
"""Require an explicit least-privilege token scope in every workflow.

A workflow without a top-level `permissions:` key inherits the repository's
default `GITHUB_TOKEN` scope. That default is a repository setting, not code,
and it can be `write` for every scope (including `checks: write`, which is
enough to create check runs under the GitHub Actions app that the required
status-check rulesets trust). So every workflow must state its own default:

* every file in `.github/workflows/` has exactly one top-level `permissions:`
  key, so no job inherits the repository default;
* that key is never `write-all`;
* a workflow that pull-request, push, merge-queue, or `workflow_run` events
  can start keeps a read-only (or empty) top-level default. Jobs that need a
  write scope ask for it in their own job-level `permissions:` block, where
  review sees it next to the steps that use it.

Executed by verify_required_ci.py inside the `Tests` aggregate, so a pull
request that adds or edits a workflow without explicit permissions fails CI.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOW_DIR = Path(".github/workflows")

# Events whose runs a contributor can start by opening, updating, queueing, or
# pushing code, rather than only by a maintainer dispatch or a schedule.
CODE_TRIGGERED_EVENTS = frozenset(
    {
        "pull_request",
        "pull_request_target",
        "push",
        "merge_group",
        "workflow_run",
    }
)

TOP_LEVEL_KEY = re.compile(r"^(?P<key>[\"']?[A-Za-z_][A-Za-z0-9_-]*[\"']?):(?P<rest>.*)$")
# A scalar may be bare or wrapped in matching single or double quotes; the
# quotes are YAML syntax, not part of the value, so both spellings normalize to
# the same scope or event name.
QUOTED = r"(?P<{0}q>[\"']?)(?P<{0}>[A-Za-z_-]+)(?P={0}q)"
SCOPE_LINE = re.compile(
    r"^\s+" + QUOTED.format("scope") + r"\s*:\s*" + QUOTED.format("level") + r"\s*(?:#.*)?$"
)
FLOW_ENTRY = re.compile(r"^\s*" + QUOTED.format("scope") + r"\s*:\s*" + QUOTED.format("level") + r"\s*$")
EVENT_NAME = re.compile(r"^\s*" + QUOTED.format("event") + r"\s*$")
EVENT_LINE = re.compile(r"^  " + QUOTED.format("event") + r"\s*:(?:\s.*)?$")


def _strip_comment(value: str) -> str:
    return value.split("#", 1)[0].strip()


def top_level_blocks(text: str) -> list[tuple[str, str, list[str]]]:
    """Return (key, inline value, indented body lines) for each top-level key."""

    blocks: list[tuple[str, str, list[str]]] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            if blocks and line.strip():
                blocks[-1][2].append(line)
            continue
        if line[0] not in " \t":
            match = TOP_LEVEL_KEY.match(line)
            if match is None:
                blocks.append(("", line, []))
                continue
            key = match.group("key").strip("\"'")
            blocks.append((key, _strip_comment(match.group("rest")), []))
        elif blocks:
            blocks[-1][2].append(line)
    return blocks


def workflow_triggers(text: str) -> set[str] | None:
    """Return the top-level trigger names, or None when they cannot be read."""

    for key, inline, body in top_level_blocks(text):
        # YAML 1.1 loaders read a bare `on` key as boolean true.
        if key not in {"on", "true"}:
            continue
        if inline:
            items = [inline]
            if inline.startswith("[") and inline.endswith("]"):
                items = inline[1:-1].split(",")
            events = set()
            for item in items:
                # Only plain or plainly quoted names are read; escapes or any
                # other spelling make the trigger set unreadable, never empty.
                match = EVENT_NAME.match(item)
                if match is None:
                    return None
                events.add(match.group("event"))
            return events or None
        events: set[str] = set()
        for line in body:
            if line.lstrip().startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent > 2:
                continue
            match = EVENT_LINE.match(line)
            if match is None:
                # Any other spelling at event depth is unreadable, never ignored.
                return None
            events.add(match.group("event"))
        return events or None
    return None


def permission_grants(inline: str, body: list[str]) -> tuple[str | None, dict[str, str]]:
    """Return (shorthand, scope->level) for a `permissions:` value."""

    if inline:
        if inline in {"read-all", "write-all"}:
            return inline, {}
        if inline.startswith("{") and inline.endswith("}"):
            scopes: dict[str, str] = {}
            inner = inline[1:-1].strip()
            for entry in inner.split(",") if inner else []:
                match = FLOW_ENTRY.match(entry)
                if match is None:
                    return "unreadable", {}
                scopes[match.group("scope")] = match.group("level")
            return None, scopes
        return inline, {}
    scopes: dict[str, str] = {}
    for line in body:
        if line.lstrip().startswith("#"):
            continue
        match = SCOPE_LINE.match(line)
        if match is None:
            return "unreadable", {}
        scopes[match.group("scope")] = match.group("level")
    return None, scopes


def workflow_permission_errors(text: str, source: str) -> list[str]:
    errors: list[str] = []
    blocks = [block for block in top_level_blocks(text) if block[0] == "permissions"]
    if not blocks:
        return [
            f"{source} must declare a top-level `permissions:` block so no job "
            "inherits the repository's default GITHUB_TOKEN scope"
        ]
    if len(blocks) != 1:
        return [f"{source} must declare exactly one top-level `permissions:` block"]
    _, inline, body = blocks[0]
    shorthand, scopes = permission_grants(inline, body)
    if shorthand == "write-all":
        errors.append(f"{source} must not grant `permissions: write-all`")
    elif shorthand not in {None, "read-all"}:
        errors.append(
            f"{source} top-level `permissions:` must be a scope mapping, `{{}}`, "
            f"or `read-all` (found {shorthand!r})"
        )
    for scope, level in sorted(scopes.items()):
        if level not in {"read", "write", "none"}:
            errors.append(f"{source} grants unknown level {level!r} to {scope!r}")
    writes = sorted(scope for scope, level in scopes.items() if level == "write")
    triggers = workflow_triggers(text)
    if triggers is None:
        errors.append(f"{source} must declare a readable top-level `on:` trigger mapping")
    elif writes and triggers & CODE_TRIGGERED_EVENTS:
        errors.append(
            f"{source} is started by {', '.join(sorted(triggers & CODE_TRIGGERED_EVENTS))} "
            f"and must not grant {', '.join(writes)} write at the top level; "
            "grant write scopes on the job that needs them"
        )
    return errors


def check_repository(root: Path = Path(".")) -> list[str]:
    directory = root / WORKFLOW_DIR
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not paths:
        return [f"no workflows found under {directory}"]
    errors: list[str] = []
    for path in paths:
        errors.extend(
            workflow_permission_errors(path.read_text(encoding="utf-8"), path.as_posix())
        )
    return errors


def run_self_test() -> list[str]:
    failures: list[str] = []
    jobs = "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    cases = (
        ("read default", "on:\n  pull_request:\npermissions:\n  contents: read\n" + jobs, True),
        ("empty default", "on:\n  schedule:\n    - cron: '0 0 * * *'\npermissions: {}\n" + jobs, True),
        ("read-all", "on: push\npermissions: read-all\n" + jobs, True),
        (
            "dispatch-only write",
            "on:\n  workflow_dispatch:\npermissions:\n  contents: write\n  pull-requests: write\n" + jobs,
            True,
        ),
        (
            "commented block",
            "on: [push]\npermissions:\n  # read only\n  contents: read  # checkout\n" + jobs,
            True,
        ),
        ("missing", "on:\n  pull_request:\n" + jobs, False),
        ("job-level only", "on:\n  pull_request:\n" + jobs.replace(
            "    runs-on:", "    permissions:\n      contents: read\n    runs-on:"
        ), False),
        ("write-all", "on:\n  workflow_dispatch:\npermissions: write-all\n" + jobs, False),
        ("pr write", "on:\n  pull_request:\npermissions:\n  checks: write\n" + jobs, False),
        ("push flow write", "on: [push]\npermissions: { contents: read, checks: write }\n" + jobs, False),
        (
            "duplicate",
            "on:\n  pull_request:\npermissions:\n  contents: read\npermissions: {}\n" + jobs,
            False,
        ),
        ("expression", "on:\n  pull_request:\npermissions: ${{ fromJSON('{}') }}\n" + jobs, False),
        ("unreadable trigger", "on: ${{ x }}\npermissions: {}\n" + jobs, False),
        ("quoted flow write", "on: push\npermissions: {checks: \"write\"}\n" + jobs, False),
        ("quoted flow scope", "on: push\npermissions: {'checks': write}\n" + jobs, False),
        ("quoted block write", "on: push\npermissions:\n  \"checks\": 'write'\n" + jobs, False),
        ("garbled flow", "on: push\npermissions: {checks write}\n" + jobs, False),
        (
            "mixed quoted triggers",
            "on:\n  workflow_dispatch:\n  \"push\":\npermissions:\n  contents: write\n" + jobs,
            False,
        ),
        (
            "single-quoted trigger",
            "on:\n  'pull_request':\n    branches: [main]\npermissions:\n  checks: write\n" + jobs,
            False,
        ),
        (
            "unreadable trigger key",
            "on:\n  workflow_dispatch:\n  ? push\npermissions:\n  contents: write\n" + jobs,
            False,
        ),
        ("escaped push", 'on: ["pu\\u0073h"]\npermissions: {checks: write}\n' + jobs, False),
        ("escaped target", 'on: ["pull_request_\\x74arget"]\npermissions:\n  checks: write\n' + jobs, False),
        (
            "escaped workflow_run key",
            'on:\n  "workflow_\\u0072un":\n    workflows: [CI]\npermissions:\n  checks: write\n' + jobs,
            False,
        ),
        ("escaped flow scope", 'on: workflow_dispatch\npermissions: {"che\\u0063ks": write}\n' + jobs, False),
        ("empty list trigger", "on: []\npermissions: {}\n" + jobs, False),
        ("quoted list triggers", "on: ['push', \"pull_request\"]\npermissions: {}\n" + jobs, True),
        ("quoted read flow", "on: push\npermissions: {\"contents\": 'read'}\n" + jobs, True),
    )
    for label, text, accepted in cases:
        errors = workflow_permission_errors(text, f"self-test {label}")
        if accepted and errors:
            failures.append(f"workflow permission self-test {label!r} rejected: {errors}")
        if not accepted and not errors:
            failures.append(f"workflow permission self-test {label!r} was accepted")
    return failures


def main() -> int:
    errors = run_self_test() + check_repository()
    for error in errors:
        print(f"::error::{error}", file=sys.stderr)
    if errors:
        return 1
    print("Every workflow declares explicit least-privilege top-level permissions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
