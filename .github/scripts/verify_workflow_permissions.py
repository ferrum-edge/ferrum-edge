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
  review sees it next to the steps that use it;
* every `actions/checkout` step states `persist-credentials: false`, so the
  token is not left in `.git/config` for later steps. `true` is admitted only
  in a workflow none of those events can start (#6581).

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
# Block-style step keys only; `lead` ends where the key starts, so its length
# is the step's key column whether or not the key sits on the `- ` line.
CHECKOUT_USES = re.compile(r"^(?P<lead> *(?:- +)?)uses *: *[\"']?actions/checkout@")
WITH_KEY = re.compile(r"^(?P<lead> *(?:- +)?)with *:(?P<rest>.*)$")
PERSIST_LINE = re.compile(
    r"^ +persist-credentials *: *(?P<q>[\"']?)(?P<value>[A-Za-z]+)(?P=q) *(?:#.*)?$"
)


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


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_content(line: str) -> bool:
    return bool(line.strip()) and not line.lstrip().startswith("#")


def checkout_credential_errors(text: str, source: str) -> list[str]:
    """Every `actions/checkout` step states `persist-credentials` explicitly.

    The action's default (`true`) writes the job's `GITHUB_TOKEN` into
    `.git/config`, where every later step, build script, and test can read it
    (#6581). A checkout must say `persist-credentials: false`. `true` is
    admitted only in a workflow that no pull-request, push, merge-queue, or
    `workflow_run` event can start, for jobs that push with the persisted
    token. Any spelling this line-based reader cannot follow fails closed.
    """

    lines = text.splitlines()
    triggers = workflow_triggers(text)
    code_triggered = triggers is None or bool(triggers & CODE_TRIGGERED_EVENTS)
    errors: list[str] = []
    for index, line in enumerate(lines):
        if "actions/checkout" not in line or line.lstrip().startswith("#"):
            continue
        located = f"{source}:{index + 1}"
        match = CHECKOUT_USES.match(line)
        if match is None:
            errors.append(
                f"{located} names actions/checkout outside a block-style `uses:` "
                "step key; write the step in block style so persist-credentials "
                "can be verified"
            )
            continue
        key_indent = len(match.group("lead"))
        start = index
        if "-" not in match.group("lead"):
            start = -1
            for back in range(index - 1, -1, -1):
                if _is_content(lines[back]) and _indent(lines[back]) < key_indent:
                    start = back
                    break
            dash_line = lines[start] if start >= 0 else ""
            if not dash_line.lstrip().startswith("- ") or (
                _indent(dash_line) + 2 != key_indent
            ):
                errors.append(f"{located} checkout step start could not be read")
                continue
        end = index + 1
        while end < len(lines) and not (
            _is_content(lines[end]) and _indent(lines[end]) < key_indent
        ):
            end += 1
        with_lines = [
            number
            for number in range(start, end)
            if WITH_KEY.match(lines[number]) is not None
            and len(WITH_KEY.match(lines[number]).group("lead")) == key_indent
        ]
        values: list[str] = []
        unreadable = False
        if len(with_lines) > 1:
            unreadable = True
        for number in with_lines:
            if _strip_comment(WITH_KEY.match(lines[number]).group("rest")):
                unreadable = True  # flow mapping or scalar: not read here
                continue
            for body in lines[number + 1 : end]:
                if not _is_content(body):
                    continue
                if _indent(body) <= key_indent:
                    break
                if "persist-credentials" not in body:
                    continue
                persist = PERSIST_LINE.match(body)
                if persist is None:
                    unreadable = True
                else:
                    values.append(persist.group("value"))
        if unreadable or len(values) > 1:
            errors.append(
                f"{located} checkout `with:` must be one block mapping holding a "
                "single plain `persist-credentials: false`"
            )
        elif not values:
            errors.append(
                f"{located} checkout must set `persist-credentials: false` so the "
                "job token is not left in .git/config for later steps"
            )
        elif values[0] == "true":
            if code_triggered:
                errors.append(
                    f"{located} checkout persists credentials in a workflow that "
                    "pull-request, push, merge-queue, or workflow_run events can "
                    "start; use `persist-credentials: false`"
                )
        elif values[0] != "false":
            errors.append(
                f"{located} checkout persist-credentials must be `false` "
                f"(found {values[0]!r})"
            )
    return errors


def check_repository(root: Path = Path(".")) -> list[str]:
    directory = root / WORKFLOW_DIR
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not paths:
        return [f"no workflows found under {directory}"]
    errors: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        errors.extend(workflow_permission_errors(text, path.as_posix()))
        errors.extend(checkout_credential_errors(text, path.as_posix()))
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

    pin = "actions/checkout@" + "0" * 40 + " # v6"
    pr = "on:\n  pull_request:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n"
    scheduled = "on:\n  schedule:\n    - cron: '0 0 * * *'\npermissions: {}\njobs:\n  build:\n    steps:\n"
    tail = "      - run: true\n"
    checkout_cases = (
        ("dash false", pr + f"      - uses: {pin}\n        with:\n          persist-credentials: false\n" + tail, True),
        (
            "named false after other input",
            pr + f"      - name: Checkout\n        uses: {pin}\n        with:\n"
            "          fetch-depth: 0\n          persist-credentials: 'false'  # no token\n" + tail,
            True,
        ),
        (
            "with before uses",
            pr + "      - name: Checkout\n        with:\n          persist-credentials: false\n"
            f"        uses: {pin}\n" + tail,
            True,
        ),
        ("scheduled push true", scheduled + f"      - uses: {pin}\n        with:\n          persist-credentials: true\n" + tail, True),
        ("missing with", pr + f"      - uses: {pin}\n" + tail, False),
        ("missing key", pr + f"      - uses: {pin}\n        with:\n          fetch-depth: 0\n" + tail, False),
        ("pr true", pr + f"      - uses: {pin}\n        with:\n          persist-credentials: true\n" + tail, False),
        (
            "expression",
            pr + f"      - uses: {pin}\n        with:\n          persist-credentials: ${{{{ inputs.p }}}}\n" + tail,
            False,
        ),
        ("flow with", pr + f"      - uses: {pin}\n        with: {{persist-credentials: false}}\n" + tail, False),
        ("flow step", pr + f"      - {{uses: {pin}, with: {{persist-credentials: false}}}}\n" + tail, False),
        (
            "next step's input",
            pr + f"      - uses: {pin}\n      - uses: other/action@{'0' * 40}\n"
            "        with:\n          persist-credentials: false\n" + tail,
            False,
        ),
        (
            "duplicate value",
            pr + f"      - uses: {pin}\n        with:\n          persist-credentials: false\n"
            "          persist-credentials: true\n" + tail,
            False,
        ),
        (
            "unreadable trigger true",
            "on: ${{ x }}\npermissions: {}\njobs:\n  build:\n    steps:\n"
            f"      - uses: {pin}\n        with:\n          persist-credentials: true\n" + tail,
            False,
        ),
    )
    for label, text, accepted in checkout_cases:
        errors = checkout_credential_errors(text, f"self-test checkout {label}")
        if accepted and errors:
            failures.append(f"checkout credential self-test {label!r} rejected: {errors}")
        if not accepted and not errors:
            failures.append(f"checkout credential self-test {label!r} was accepted")
    return failures


def main() -> int:
    errors = run_self_test() + check_repository()
    for error in errors:
        print(f"::error::{error}", file=sys.stderr)
    if errors:
        return 1
    print(
        "Every workflow declares explicit least-privilege top-level permissions "
        "and every checkout sets persist-credentials."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
