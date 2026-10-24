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
* every `actions/checkout` step, in a workflow or a local composite action,
  states `persist-credentials: false`, so the token is not persisted for later
  steps. `true` is admitted only in a workflow started solely by `schedule`
  or `workflow_dispatch` (#6581). The decision is made on a real YAML parse
  (PyYAML's composed node graph); a line-based reader runs alongside it as
  extra spelling policy, and both must accept (#6688).

Executed by verify_required_ci.py inside the `Tests` aggregate, so a pull
request that adds or edits a workflow without explicit permissions fails CI.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:  # the parsed checkout check fails closed without it
    yaml = None

WORKFLOW_DIR = Path(".github/workflows")
ACTIONS_DIR = Path(".github/actions")

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
# GitHub resolves owner/repo case-insensitively, so `Actions/Checkout@` is the
# same action and must be matched the same way.
CHECKOUT_USES = re.compile(
    r"^(?P<lead> *(?:- +)?)uses *: *(?i:actions/checkout)@[0-9a-f]{40} *(?:#.*)?$"
)
# Any `uses` key, block or flow, after escapes are resolved. Its value must be
# one plain literal on this line: no quotes left open, aliases, tags, or block
# scalars, so a reference cannot be assembled where this reader cannot see it.
USES_KEY_LINE = re.compile(r"^ *(?:- +)?[\"']?uses[\"']? *:(?P<value>.*)$", re.IGNORECASE)
FLOW_USES_KEY = re.compile(r"[{,] *[\"']?uses[\"']? *:", re.IGNORECASE)
WITH_KEY = re.compile(r"^(?P<lead> *(?:- +)?)with *:(?P<rest>.*)$")
JOB_KEY = re.compile(r"^  (?P<job>[A-Za-z0-9_-]+): *(?:#.*)?$")
# Checkouts inside jobs whose bytes the trusted Cross policy
# (`verify_cross_build_policy.py`) freezes: the release ARM64 publication
# dependency contract and the required live suites' trusted relevance/execution
# contracts. A pull request cannot change them, so they keep the action default
# until a reviewed policy migration adds `persist-credentials: false`. A missing
# key is the only thing admitted here; `true` is still refused.
POLICY_FROZEN_CHECKOUT_JOBS = frozenset(
    {
        ("release.yml", "create-release"),
        ("release.yml", "docker"),
        ("release.yml", "docker-ebpf"),
        ("ambient-host-udp-live.yml", "changes"),
        ("ambient-host-udp-live.yml", "ambient-host-udp-live"),
        ("cni-lifecycle-live.yml", "changes"),
        ("istio-status-cas-live.yml", "changes"),
        ("mesh-e2e-sidecar-live.yml", "changes"),
        ("multicluster-federation-live.yml", "changes"),
        ("multicluster-poller-partition-live.yml", "changes"),
    }
)
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


PERSIST_TRUE_TRIGGERS = frozenset({"schedule", "workflow_dispatch"})
ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|.)")


def _decode_escapes(line: str) -> str:
    """Resolve every backslash escape on the line, quoted or not.

    Deliberately over-eager: YAML decodes escapes only inside double quotes,
    and deciding where those start needs a full lexer. Decoding everywhere can
    only reveal more, so an escaped `actions\\u002fcheckout` is always seen.
    """

    def unescape(match: re.Match[str]) -> str:
        code = match.group(1)
        if code[0] in "xuU" and len(code) > 1:
            try:
                return chr(int(code[1:], 16))
            except ValueError:
                return code
        return code

    return ESCAPE.sub(unescape, line)


CHILD_INPUT = re.compile(r"^ *(?P<key>[A-Za-z0-9_-]+) *:(?: +(?P<value>.*))?$")
# Step keys whose empty value opens a nested mapping this reader understands.
STEP_MAPPING_KEYS = frozenset({"with", "env"})
SINGLE_QUOTED_VALUE = re.compile(r"^'(?:[^']|'')*' *(?:#.*)?$")
DOUBLE_QUOTED_VALUE = re.compile(r'^"(?:[^"\\]|\\.)*" *(?:#.*)?$')


def _single_line_input(line: str, mapping_keys: frozenset[str] = frozenset()) -> bool:
    """Whether a key's value is complete on this line and cannot continue onward.

    Block scalars (`|`, `>`) are fine: their bodies are indented deeper than
    the key and are skipped. Quoted and flow values must close on this line.
    An empty value is admitted only for the named mapping keys: elsewhere it
    lets a scalar start on the next, deeper line and swallow what follows.
    """

    match = CHILD_INPUT.match(line)
    if match is None:
        return False
    value = (match.group("value") or "").strip()
    if not value or value.startswith("#"):
        return match.group("key") in mapping_keys
    if value.startswith("'"):
        return SINGLE_QUOTED_VALUE.match(value) is not None
    if value.startswith('"'):
        return DOUBLE_QUOTED_VALUE.match(value) is not None
    if value.startswith(("[", "{")):
        # Only simple flow collections: a quote inside could hold the closing
        # bracket and carry the value onto later lines.
        closing = "]" if value[0] == "[" else "}"
        return "'" not in value and '"' not in value and _strip_comment(value).endswith(closing)
    if value.startswith(("&", "*", "!")):
        return False  # anchors, aliases, and tags are not read here
    plain = re.split(r"[ \t]#", value, maxsplit=1)[0].strip()
    if plain.endswith(("'", '"')) and plain.count(plain[-1]) % 2:
        # An unbalanced closing quote ends a value opened on an earlier line.
        return False
    return True


BLOCK_SCALAR_HEADER = re.compile(r"(?:^|[ :-]) *[|>][1-9+-]{0,2} *(?:#.*)?$")
EXPLICIT_KEY = re.compile(r"^ *(?:- +)?[?:](?: |$)")


def _block_scalar_body_lines(lines: list[str]) -> set[int]:
    """Indices of lines inside `|` / `>` block scalar bodies (e.g. `run: |`)."""

    body: set[int] = set()
    header_indent: int | None = None
    for number, line in enumerate(lines):
        if header_indent is not None:
            if not line.strip() or _indent(line) > header_indent:
                body.add(number)
                continue
            header_indent = None
        if _is_content(line) and BLOCK_SCALAR_HEADER.search(line.rstrip()):
            header_indent = _indent(line)
    return body


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_content(line: str) -> bool:
    return bool(line.strip()) and not line.lstrip().startswith("#")


BLOCK_SCALAR_VALUE = re.compile(r"^[|>][1-9+-]{0,2} *(?:#.*)?$")
# The first plain-key separator or comment on a line, whichever comes first.
PLAIN_KEY_OR_COMMENT = re.compile(r":(?=[ \t]|$)|[ \t]#")


def _scan_quoted(text: str, pos: int, quote: str) -> int | None:
    """Index just past the quote closing a scalar whose body starts at `pos`."""

    while pos < len(text):
        char = text[pos]
        if quote == '"' and char == "\\":
            pos += 2
            continue
        if char == quote:
            if quote == "'" and text.startswith("''", pos):
                pos += 2
                continue
            return pos + 1
        pos += 1
    return None


def _scan_flow(text: str, pos: int, depth: int, quote: str | None) -> tuple[int, str | None]:
    """Advance a flow collection; return its remaining depth and any open quote."""

    while pos < len(text):
        if quote is not None:
            closed = _scan_quoted(text, pos, quote)
            if closed is None:
                return depth, quote
            pos, quote = closed, None
            continue
        char = text[pos]
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
            if depth <= 0:
                return 0, None
        elif char in "'\"":
            quote = char
        elif char == "#" and (pos == 0 or text[pos - 1] in " \t"):
            break
        pos += 1
    return depth, quote


def _lex_node(text: str, pos: int, column: int) -> tuple[str, object] | None:
    """Lex the node(s) from `pos` to the end of the line.

    Returns the construct the line leaves open: ("quote", q), ("flow",
    (depth, q)), or ("block", parent column); None when nothing stays open.
    """

    while True:
        while pos < len(text) and text[pos] in " \t":
            pos += 1
        if pos >= len(text) or text[pos] == "#":
            return None
        char = text[pos]
        follows_space = pos + 1 == len(text) or text[pos + 1] in " \t"
        if char in "-?:" and follows_space:
            column = pos  # sequence entry or explicit key / value indicator
            pos += 1
            continue
        if char in "'\"":
            closed = _scan_quoted(text, pos + 1, char)
            if closed is None:
                return ("quote", char)
            rest = text[closed:].lstrip(" \t")
            if not rest.startswith(":"):
                return None
            pos = text.index(":", closed) + 1  # a quoted key; lex its value
            continue
        if char in "[{":
            depth, quote = _scan_flow(text, pos, 0, None)
            return ("flow", (depth, quote)) if depth else None
        if char in "|>":
            return ("block", column)
        if char in "&!":
            while pos < len(text) and text[pos] not in " \t":
                pos += 1
            continue
        match = PLAIN_KEY_OR_COMMENT.search(text, pos)
        if match is None or match.group().endswith("#"):
            return None  # a plain scalar
        column = pos
        pos = match.end()


def _open_scalar_lines(lines: list[str]) -> set[int]:
    """Indices of lines that start inside a quoted scalar or flow collection.

    A forward lexer over the whole file: a quote or bracket that opens a
    value and does not close on its line makes every following line, up to and
    including the one that closes it, scalar text rather than YAML structure.
    Such text can look like a `- ` step, a `with:` key, or a job key, so step
    boundaries and inputs are never read from these lines (#6688). Block
    scalar bodies (`|` / `>`) are skipped from each header's parent column.
    """

    opaque: set[int] = set()
    state: tuple[str, object] | None = None
    for number, line in enumerate(lines):
        if state is not None and state[0] == "block":
            if not line.strip() or _indent(line) > int(state[1]):
                continue
            state = None
        if state is None:
            if line.strip():
                state = _lex_node(line, _indent(line), _indent(line))
            continue
        opaque.add(number)
        kind, data = state
        if kind == "quote":
            closed = _scan_quoted(line, 0, str(data))
            if closed is None:
                continue
            rest = line[closed:].lstrip(" \t")
            state = _lex_node(line, line.index(":", closed) + 1, closed) if rest.startswith(":") else None
        else:
            depth, quote = data
            depth, quote = _scan_flow(line, 0, depth, quote)
            state = ("flow", (depth, quote)) if depth else None
    return opaque


def _checkout_step_readable(lines: list[str], start: int, end: int, key_indent: int) -> bool:
    """Whether every line of a checkout step has the one shape this reader follows.

    A step line is a complete `key: value` step key at `key_indent`, a complete
    `key: value` direct child of an empty `with:` / `env:` key, or the body of a
    block scalar (`|` / `>`) opened by one of those lines. Anything else,
    including a quoted or flow value left open at any depth, a plain scalar
    continued onto a deeper line, or a child nested below another child, is
    refused: it would carry later lines that only look like `with:` and
    `persist-credentials` into a scalar (#6688).

    Block scalar bodies are tracked here from each header's own key column,
    not from the file-wide pass, because a header on a `- key: |` line ends at
    the step key column, not at the dash.
    """

    mapping_open = False
    child_indent: int | None = None
    block_indent: int | None = None
    for number in range(start, end):
        line = lines[number]
        if not line.strip():
            continue
        if number == start and line.lstrip().startswith("- "):
            line = " " * key_indent + line.lstrip()[2:].lstrip()
        indent = _indent(line)
        if block_indent is not None:
            if indent > block_indent:
                continue  # block scalar body, including lines that look like comments
            block_indent = None
        if line.lstrip().startswith("#"):
            continue
        if indent == key_indent:
            if not _single_line_input(line, STEP_MAPPING_KEYS):
                return False
            match = CHILD_INPUT.match(line)
            value = _strip_comment(match.group("value") or "") if match else ""
            mapping_open = (
                match is not None and not value and match.group("key") in STEP_MAPPING_KEYS
            )
            child_indent = None
            if BLOCK_SCALAR_VALUE.match(value):
                block_indent = key_indent
            continue
        if indent < key_indent or not mapping_open:
            return False
        if child_indent is None:
            child_indent = indent
        if indent != child_indent or not _single_line_input(line):
            return False
        match = CHILD_INPUT.match(line)
        if match is not None and BLOCK_SCALAR_VALUE.match((match.group("value") or "").strip()):
            block_indent = child_indent
    return True


def checkout_credential_errors(text: str, source: str, *, composite: bool = False) -> list[str]:
    """Every `actions/checkout` step states `persist-credentials` explicitly.

    The action's default (`true`) writes the job's `GITHUB_TOKEN` to a
    credentials file under `$RUNNER_TEMP` that the checkout's `.git/config`
    includes, so every later step, build script, and test can read it or use
    it through git (#6581). A checkout must say `persist-credentials: false`. `true` is
    admitted only in a workflow started solely by `schedule` or
    `workflow_dispatch` (not a reusable `workflow_call` callee), for jobs that
    push with the persisted token. Only direct children of `with:` count as
    inputs, YAML-escaped checkout references are refused, and any spelling this
    line-based reader cannot follow fails closed.
    """

    lines = text.splitlines()
    triggers = workflow_triggers(text)
    # `true` is only for scheduled or manual pushers. Anything else, including a
    # reusable `workflow_call` callee that a pull-request workflow can invoke,
    # or an unreadable trigger set, must say `false`.
    # A composite action runs inside whatever workflow calls it; an `on:` key in
    # its metadata is ignored by the runner and restricts nothing.
    true_admitted = (
        not composite and triggers is not None and triggers <= PERSIST_TRUE_TRIGGERS
    )
    errors: list[str] = []
    block_bodies = _block_scalar_body_lines(lines)
    open_scalar = _open_scalar_lines(lines)
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        located = f"{source}:{index + 1}"
        if index not in block_bodies and EXPLICIT_KEY.match(line):
            errors.append(
                f"{located} uses an explicit YAML key (`?` / `:` line); write plain "
                "`key: value` mappings so checkout steps can be verified"
            )
            continue
        decoded = _decode_escapes(line)
        if FLOW_USES_KEY.search(decoded):
            errors.append(
                f"{located} declares a step `uses` in flow style; write steps in "
                "block style so checkout credentials can be verified"
            )
            continue
        uses_key = USES_KEY_LINE.match(decoded)
        if uses_key is not None:
            value = uses_key.group("value").strip()
            if value.startswith(("*", "&", "!", "|", ">")) or not _single_line_input(
                f"uses: {value}"
            ):
                errors.append(
                    f"{located} `uses` must be one literal value on its own line "
                    "(no alias, tag, block scalar, or open quote)"
                )
                continue
        if "actions/checkout" not in decoded.lower():
            continue
        match = CHECKOUT_USES.match(line)
        if match is None or decoded != line:
            errors.append(
                f"{located} must reference actions/checkout as a literal block-style "
                "`uses: actions/checkout@<40-hex SHA>` step key so persist-credentials "
                "can be verified"
            )
            continue
        key_indent = len(match.group("lead"))
        start = index
        if "-" not in match.group("lead"):
            start = -1
            for back in range(index - 1, -1, -1):
                if back in open_scalar:
                    continue  # scalar text, never a step boundary
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
        if any(number in open_scalar for number in range(start, end)) or not (
            _checkout_step_readable(lines, start, end, key_indent)
        ):
            errors.append(
                f"{located} checkout step keys, and the direct children of its "
                "`with:` / `env:` mappings, must each be one complete `key: value` "
                "line; a value left open across lines is refused"
            )
            continue
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
            # Only direct children of `with:` are inputs. A deeper line is the
            # body of another input's block scalar (`ssh-known-hosts: |`), whose
            # text must not count as the key.
            child_indent = None
            for body in lines[number + 1 : end]:
                if not _is_content(body):
                    continue
                if _indent(body) <= key_indent:
                    break
                if child_indent is None:
                    child_indent = _indent(body)
                if _indent(body) != child_indent:
                    continue
                # Every direct child must be one complete `key: value` line. A
                # quoted or flow value left open here continues onto later lines
                # at this same indent, which would then only look like keys.
                if not _single_line_input(body):
                    unreadable = True
                    continue
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
            job = None
            for back in range(index - 1, -1, -1):
                if back in open_scalar:
                    job = None  # crossed unread scalar text: no exemption
                    break
                job_match = JOB_KEY.match(lines[back])
                if job_match is not None:
                    job = job_match.group("job")
                    break
                if _is_content(lines[back]) and _indent(lines[back]) == 0:
                    break
            if (Path(source).name, job) in POLICY_FROZEN_CHECKOUT_JOBS:
                continue
            errors.append(
                f"{located} checkout must set `persist-credentials: false` so the "
                "job token is not persisted for later steps"
            )
        elif values[0] == "true":
            if not true_admitted:
                errors.append(
                    f"{located} checkout persists credentials outside a workflow "
                    "started only by schedule or workflow_dispatch; use "
                    "`persist-credentials: false`"
                )
        elif values[0] != "false":
            errors.append(
                f"{located} checkout persist-credentials must be `false` "
                f"(found {values[0]!r})"
            )
    errors.extend(
        parsed_checkout_errors(text, source, composite=composite, line_triggers=triggers)
    )
    return errors


# Characters PyYAML (YAML 1.1) reads as line breaks or strips, where a YAML 1.2
# reader (the Actions runner's) sees ordinary content. Either side could then
# see keys the other does not.
LINE_BREAK_DIVERGENCE = ("\r", "\x85", "\u2028", "\u2029", "\ufeff")
PINNED_CHECKOUT = re.compile(r"(?i:actions/checkout)@[0-9a-f]{40}")
# The runner passes `with:` inputs as INPUT_<NAME> with spaces as underscores,
# upper-cased, so names that differ only in case or spacing are one input.
def _input_name(name: str) -> str:
    return name.replace(" ", "_").upper()


def _lookup(node: "yaml.MappingNode", key: str, located: str, errors: list[str]) -> "yaml.Node | None":
    """The value of `key` in a mapping; any other spelling of it fails closed."""

    found = None
    for key_node, value in node.value:
        name = key_node.value if isinstance(key_node, yaml.ScalarNode) else ""
        if name.lower() != key:
            continue
        if name != key or found is not None:
            errors.append(f"{located} `{key}` must be spelled once, in lower case")
            return None
        found = value
    return found


def _line(node: "yaml.Node") -> int:
    return node.start_mark.line + 1


def _mapping_policy_errors(node: "yaml.Node", source: str) -> list[str]:
    """Duplicate keys, merge keys, and non-scalar keys anywhere in the document."""

    errors: list[str] = []
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, yaml.SequenceNode):
            pending.extend(current.value)
            continue
        if not isinstance(current, yaml.MappingNode):
            continue
        seen: set[str] = set()
        for key_node, value in current.value:
            if not isinstance(key_node, yaml.ScalarNode) or key_node.tag.endswith(":merge"):
                errors.append(f"{source}:{_line(key_node)} mapping keys must be plain scalars")
            elif key_node.value in seen:
                errors.append(
                    f"{source}:{_line(key_node)} duplicate key {key_node.value!r}; "
                    "YAML readers disagree on which one wins"
                )
            else:
                seen.add(key_node.value)
            pending.append(value)
    return errors


def _parsed_triggers(root: "yaml.MappingNode") -> set[str] | None:
    """Trigger names from the parsed `on:` value, or None when unreadable."""

    entries = [
        value for key, value in root.value if isinstance(key, yaml.ScalarNode) and key.value == "on"
    ]
    if len(entries) != 1:
        return None
    value = entries[0]
    if isinstance(value, yaml.ScalarNode):
        names = [value]
    elif isinstance(value, yaml.SequenceNode):
        names = value.value
    elif isinstance(value, yaml.MappingNode):
        names = [key for key, _ in value.value]
    else:
        return None
    if not names or not all(isinstance(name, yaml.ScalarNode) for name in names):
        return None
    return {name.value for name in names}


def _input_env_errors(env: "yaml.Node | None", located: str, errors: list[str]) -> None:
    """An `env:` that could preset the action's persist-credentials input is refused.

    The action reads INPUT_PERSIST-CREDENTIALS from its environment; the
    comparison ignores case so no spelling of it is left to a reader's rules.
    """

    if env is None:
        return
    if not isinstance(env, yaml.MappingNode):
        errors.append(f"{located} `env:` must be a mapping so checkout inputs can be verified")
        return
    for key, _ in env.value:
        if isinstance(key, yaml.ScalarNode) and key.value.upper() == "INPUT_PERSIST-CREDENTIALS":
            errors.append(f"{located} `env:` must not set the checkout input {key.value}")


def parsed_checkout_errors(
    text: str,
    source: str,
    *,
    composite: bool = False,
    line_triggers: set[str] | None = None,
) -> list[str]:
    """Check every checkout step on the parsed YAML structure (#6688).

    Steps are found as `jobs.<job>.steps[*]` (workflow) or `runs.steps[*]`
    (composite action), never by line position, so text inside any scalar
    cannot pose as a step, a `with:` key, or an input. The document must be
    plain: one document, no anchors, aliases, tags, directives, merge keys, or
    duplicate keys, and no characters that YAML 1.1 and 1.2 readers split into
    lines differently. A checkout's `with` must be a block mapping holding one
    `persist-credentials` whose scalar text is exactly `false` (plain or quoted,
    which the action reads as the string "false"); `true` only where the line
    reader also admits it.
    """

    if yaml is None:
        return [f"{source} cannot be verified: PyYAML is not installed"]
    for char in LINE_BREAK_DIVERGENCE:
        if char in text:
            return [f"{source} contains U+{ord(char):04X}; YAML readers split its lines differently"]
    try:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, (yaml.AnchorToken, yaml.AliasToken, yaml.TagToken, yaml.DirectiveToken)):
                return [
                    f"{source}:{token.start_mark.line + 1} uses a YAML anchor, alias, tag, or "
                    "directive; write plain YAML so checkout steps can be verified"
                ]
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as error:
        return [f"{source} could not be parsed as YAML: {error}"]
    if len(documents) != 1 or not isinstance(documents[0], yaml.MappingNode):
        return [f"{source} must be a single YAML mapping document"]
    root = documents[0]
    errors = _mapping_policy_errors(root, source)
    if errors:
        return errors

    parsed_triggers = _parsed_triggers(root)
    true_admitted = (
        not composite
        and line_triggers is not None
        and parsed_triggers is not None
        and line_triggers <= PERSIST_TRUE_TRIGGERS
        and parsed_triggers <= PERSIST_TRUE_TRIGGERS
    )
    # Both step locations are read in every file, so a misfiled or mislabelled
    # document is still checked rather than silently matching neither shape.
    step_lists: list[tuple[str | None, "yaml.Node", list["yaml.Node | None"]]] = []
    runs = _lookup(root, "runs", source, errors)
    if isinstance(runs, yaml.MappingNode):
        steps = _lookup(runs, "steps", f"{source}:{_line(runs)}", errors)
        if steps is not None:
            step_lists.append((None, steps, []))
    workflow_env = _lookup(root, "env", source, errors)
    jobs = _lookup(root, "jobs", source, errors)
    if jobs is not None and not isinstance(jobs, yaml.MappingNode):
        errors.append(f"{source}:{_line(jobs)} `jobs:` must be a mapping")
    elif jobs is not None:
        for job_key, job in jobs.value:
            if not isinstance(job, yaml.MappingNode):
                continue
            located = f"{source}:{_line(job_key)}"
            steps = _lookup(job, "steps", located, errors)
            if steps is not None:
                job_env = _lookup(job, "env", located, errors)
                step_lists.append((job_key.value, steps, [workflow_env, job_env]))
    for job, steps, inherited_env in step_lists:
        if not isinstance(steps, yaml.SequenceNode):
            errors.append(f"{source}:{_line(steps)} `steps:` must be a sequence")
            continue
        for step in steps.value:
            located = f"{source}:{_line(step)}"
            if not isinstance(step, yaml.MappingNode):
                errors.append(f"{located} each step must be a mapping")
                continue
            uses = _lookup(step, "uses", located, errors)
            if not isinstance(uses, yaml.ScalarNode) or "actions/checkout" not in uses.value.lower():
                if uses is not None and not isinstance(uses, yaml.ScalarNode):
                    errors.append(f"{located} `uses` must be a scalar")
                continue
            if PINNED_CHECKOUT.fullmatch(uses.value) is None:
                errors.append(
                    f"{located} checkout must be `actions/checkout@<40-hex SHA>` "
                    f"(found {uses.value!r})"
                )
                continue
            for env in [*inherited_env, _lookup(step, "env", located, errors)]:
                _input_env_errors(env, located, errors)
            inputs = _lookup(step, "with", located, errors)
            values: list["yaml.Node"] = []
            if inputs is not None:
                if not isinstance(inputs, yaml.MappingNode) or inputs.flow_style:
                    errors.append(f"{located} checkout `with:` must be a block mapping")
                    continue
                for key, value in inputs.value:
                    name = key.value if isinstance(key, yaml.ScalarNode) else ""
                    if _input_name(name) != "PERSIST-CREDENTIALS":
                        continue
                    if name != "persist-credentials":
                        errors.append(f"{located} spell the input `persist-credentials`")
                    values.append(value)
            if len(values) > 1:
                errors.append(f"{located} checkout sets persist-credentials more than once")
                continue
            if not values:
                if (Path(source).name, job) in POLICY_FROZEN_CHECKOUT_JOBS:
                    continue
                errors.append(
                    f"{located} checkout must set `persist-credentials: false` (parsed "
                    "`with` has no such input) so the job token is not persisted"
                )
                continue
            value = values[0]
            text_value = value.value if isinstance(value, yaml.ScalarNode) else None
            if not isinstance(value, yaml.ScalarNode) or value.style not in (None, "'", '"'):
                errors.append(f"{located} checkout persist-credentials must be a one-line scalar")
            elif text_value == "true":
                if not true_admitted:
                    errors.append(
                        f"{located} checkout persists credentials outside a workflow "
                        "started only by schedule or workflow_dispatch"
                    )
            elif text_value != "false":
                errors.append(
                    f"{located} checkout persist-credentials must be `false` (found {text_value!r})"
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
    # A workflow can call a local composite action that runs its own checkout.
    # An action has no trigger of its own, so it reads as code-triggered and
    # must always say `false`.
    actions = root / ACTIONS_DIR
    action_paths = (
        [*actions.rglob("action.yml"), *actions.rglob("action.yaml")] if actions.is_dir() else []
    )
    for path in sorted(action_paths):
        errors.extend(
            checkout_credential_errors(
                path.read_text(encoding="utf-8"), path.as_posix(), composite=True
            )
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

    mixed = pin.replace("actions/checkout", "Actions/Checkout")
    sha = "0" * 40
    persist_true = "        with:\n          persist-credentials: true\n"
    scalar_body = (
        "        with:\n          ssh-known-hosts: |\n            persist-credentials: false\n"
    )
    quoted_ok = pr + f"      - uses: {pin}\n        with:\n          ref: 'main' # base\n" \
        "          path: \"src\"\n          persist-credentials: false\n" + tail
    if checkout_credential_errors(quoted_ok, "self-test checkout quoted single-line inputs"):
        failures.append("checkout credential self-test: single-line quoted inputs were rejected")
    # Controls for the nested-scalar pass (#6688): complete `env:` children,
    # block scalars at the step, `env:`, and `with:` depth, and a block scalar
    # opened on the `- ` line must all still be accepted.
    for label, text in (
        (
            "env children",
            pr + f"      - name: Checkout\n        env:\n          A: plain\n"
            "          B: 'single'  # note\n          C: \"double\"\n          D: ${{ github.sha }}\n"
            f"        uses: {pin}\n        with:\n          persist-credentials: false\n" + tail,
        ),
        (
            "env block scalar",
            pr + f"      - uses: {pin}\n        env:\n          NOTE: |\n            \"open\n"
            "            with:\n          OTHER: x\n        with:\n          persist-credentials: false\n" + tail,
        ),
        (
            "dash block scalar",
            pr + "      - name: >-\n          Checkout 'the\n        uses: " + pin + "\n"
            "        with:\n          persist-credentials: false\n" + tail,
        ),
        (
            "with block scalar and comments",
            pr + f"      - uses: {pin}\n        # comment\n        with:\n          # inputs\n"
            "          ssh-known-hosts: |\n            # host keys\n            'x\n"
            "          persist-credentials: false\n" + tail,
        ),
        (
            "balanced quoted expressions",
            pr + f"      - uses: {pin}\n        if: needs.plan.outputs.mode != 'skip'\n"
            "        with:\n          persist-credentials: false\n          ref: x\n" + tail,
        ),
        (
            "multi-line scalar in another step",
            pr + "      - run: \"echo one\n          - name: two\"\n"
            f"      - uses: {pin}\n        with:\n          persist-credentials: false\n" + tail,
        ),
        (
            "composite env children",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      env:\n        A: \"x\"\n      with:\n"
            "        persist-credentials: false\n    - run: true\n      shell: bash\n",
        ),
    ):
        errors = checkout_credential_errors(text, f"self-test checkout {label}")
        if errors:
            failures.append(f"checkout credential self-test {label!r} rejected: {errors}")
    for label, text in (
        ("mixed-case missing", pr + f"      - uses: {mixed}\n" + tail),
        ("mixed-case true", pr + f"      - uses: {mixed}\n" + persist_true + tail),
        ("escaped separator missing", pr + f'      - uses: "actions\\u002fcheckout@{sha}"\n' + tail),
        ("escaped separator true", pr + f'      - uses: "actions\\x2fcheckout@{sha}"\n' + persist_true + tail),
        ("escaped owner true", pr + f'      - uses: "\\u0061ctions/checkout@{sha}"\n' + persist_true + tail),
        ("escaped slash missing", pr + f'      - uses: "actions\\/checkout@{sha}"\n' + tail),
        ("escaped key missing", pr + f'      - "u\\u0073es": actions/checkout@{sha}\n' + tail),
        ("block scalar impersonation", pr + f"      - uses: {pin}\n" + scalar_body + tail),
        (
            "reusable callee true",
            "on:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n"
            f"      - uses: {pin}\n" + persist_true + tail,
        ),
        (
            "single-quoted scalar impersonation",
            pr + f"      - uses: {pin}\n        with:\n          ssh-known-hosts: 'ignored\n"
            "          persist-credentials: false\n          '\n" + tail,
        ),
        (
            "double-quoted scalar impersonation",
            pr + f"      - uses: {pin}\n        with:\n          ssh-known-hosts: \"ignored\n"
            "          persist-credentials: false\n          \"\n" + tail,
        ),
        (
            "composite quoted scalar impersonation",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      with:\n        ssh-known-hosts: 'ignored\n"
            "        persist-credentials: false\n        '\n    - run: true\n      shell: bash\n",
        ),
        (
            "composite true",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      with:\n        persist-credentials: true\n",
        ),
        (
            "quoted name hides with",
            pr + f"      - uses: {pin}\n        name: 'ignored\n        with:\n"
            "          persist-credentials: false\n        '\n" + tail,
        ),
        (
            "composite quoted name hides with",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      name: 'ignored\n      with:\n"
            "        persist-credentials: false\n      '\n    - run: true\n      shell: bash\n",
        ),
        (
            "single-quoted quote hides escaped flow reference",
            pr + f"      - {{name: '\"', uses: \"actions\\u002fcheckout@{sha}\"}}\n" + tail,
        ),
        (
            "composite single-quoted quote hides escaped flow reference",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - {{name: '\"', uses: \"actions\\u002fcheckout@{sha}\"}}\n",
        ),
        (
            "alias reference",
            pr.replace("jobs:\n", f"env:\n  REF: &ref actions/checkout@{sha}\njobs:\n")
            + "      - uses: *ref\n" + tail,
        ),
        (
            "escaped line continuation",
            pr + '      - uses: "actions/che\\\n          ckout@' + sha + '"\n' + tail,
        ),
        (
            "empty input value impersonation",
            pr + f"      - uses: {pin}\n        with:\n          ssh-known-hosts:\n"
            "            'ignored\n          persist-credentials: false\n            '\n" + tail,
        ),
        (
            "empty name hides with",
            pr + f"      - uses: {pin}\n        name:\n          'ignored\n        with:\n"
            "          persist-credentials: false\n          '\n" + tail,
        ),
        (
            "composite empty input value impersonation",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      with:\n        ssh-known-hosts:\n"
            "          'ignored\n        persist-credentials: false\n          '\n",
        ),
        (
            "composite empty name hides with",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      name:\n        'ignored\n      with:\n"
            "        persist-credentials: false\n        '\n",
        ),
        (
            "flow value with quote hides with",
            pr + f"      - uses: {pin}\n        env: {{ X: 'ignored}}\n        with:\n"
            "          persist-credentials: false\n            '}}\n" + tail,
        ),
        (
            "composite flow value with quote hides with",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      env: {{ X: 'ignored}}\n      with:\n"
            "        persist-credentials: false\n          '}}\n",
        ),
        (
            "explicit key escaped continuation",
            pr + '      - ? uses\n        : "actions/che\\\n            ckout@' + sha + '"\n' + tail,
        ),
        (
            "composite explicit key escaped continuation",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            '    - ? uses\n      : "actions/che\\\n          ckout@' + sha + '"\n',
        ),
        (
            "tagged input",
            pr + f"      - uses: {pin}\n        with:\n          persist-credentials: !!str false\n" + tail,
        ),
        (
            "env double-quoted scalar hides with",
            pr + f"      - uses: {pin}\n        env:\n          X: \"ignored\n        with:\n"
            "          persist-credentials: false\n            \"\n" + tail,
        ),
        (
            "env single-quoted scalar hides with",
            pr + f"      - uses: {pin}\n        env:\n          X: 'ignored\n        with:\n"
            "          persist-credentials: false\n            '\n" + tail,
        ),
        (
            "env scalar before uses hides with",
            pr + "      - env:\n          X: \"ignored\n        with:\n"
            f"          persist-credentials: false\n            \"\n        uses: {pin}\n" + tail,
        ),
        (
            "env flow scalar hides with",
            pr + f"      - uses: {pin}\n        env:\n          X: [\"ignored\n        with:\n"
            "          persist-credentials: false\n            \"]\n" + tail,
        ),
        (
            "env empty value hides with",
            pr + f"      - uses: {pin}\n        env:\n          X:\n            \"ignored\n"
            "        with:\n          persist-credentials: false\n            \"\n" + tail,
        ),
        (
            "plain scalar continuation",
            pr + f"      - uses: {pin}\n        name: one\n          two\n        with:\n"
            "          persist-credentials: false\n" + tail,
        ),
        (
            "env nested below child",
            pr + f"      - uses: {pin}\n        env:\n          X: a\n            Y: \"ignored\n"
            "        with:\n          persist-credentials: false\n            \"\n" + tail,
        ),
        (
            "dash block scalar does not cover env scalar",
            pr + "      - name: |\n          x\n        uses: " + pin + "\n        env:\n"
            "          X: \"ignored\n        with:\n          persist-credentials: false\n"
            "            \"\n" + tail,
        ),
        (
            "composite env scalar hides with",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      env:\n        X: \"ignored\n      with:\n"
            "        persist-credentials: false\n          \"\n    - run: true\n      shell: bash\n",
        ),
        (
            "fabricated step start inside env scalar",
            pr + "      - env:\n          X: 'ignored\n      - name: decoy\n        with:\n"
            f"          persist-credentials: false\n          CLOSE: ignored'\n        uses: {pin}\n" + tail,
        ),
        (
            "composite fabricated step start inside env scalar",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            "    - env:\n        X: 'ignored\n    - name: decoy\n      with:\n"
            f"        persist-credentials: false\n        CLOSE: ignored'\n      uses: {pin}\n",
        ),
        (
            "fabricated step start with escaped closing quote",
            pr + "      - env:\n          X: \"ignored\n      - name: decoy\n        with:\n"
            "          persist-credentials: false\n          CLOSE: a\\\"b\"\n"
            f"        uses: {pin}\n" + tail,
        ),
        (
            "fabricated step start closed on its own line",
            pr + "      - env:\n          X: \"ignored\n      - name: decoy\n        with:\n"
            "          persist-credentials: false\n          CLOSE: x\n            \"\n"
            f"        uses: {pin}\n" + tail,
        ),
        (
            "fabricated step start inside tab-separated scalar",
            pr + "      - env:\n          X:\t'ignored\n      - name: decoy\n        with:\n"
            "          persist-credentials: false\n          CLOSE: x\n            '\n"
            f"        uses: {pin}\n" + tail,
        ),
        (
            "fabricated step start inside flow value",
            pr + "      - env:\n          X: [ignored\n      - name: decoy\n        with:\n"
            "          persist-credentials: false\n          CLOSE: x\n            ]\n"
            f"        uses: {pin}\n" + tail,
        ),
        (
            "composite quoted block key hides env scalar",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            "    - \"name\": |\n        Checkout\n      env:\n        X: 'ignored\n"
            "    - name: decoy\n      with:\n        persist-credentials: false\n"
            f"        CLOSE: ignored#'\n      uses: {pin}\n",
        ),
        (
            "quoted block key hides env scalar",
            pr + "      - \"name\": >-\n          Checkout\n        env:\n          X: 'ignored\n"
            "      - name: decoy\n        with:\n          persist-credentials: false\n"
            f"          CLOSE: ignored#'\n        uses: {pin}\n" + tail,
        ),
        (
            "composite flow apostrophe hides env scalar",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            "    - env: { X: foo'bar, Y: 'ignored }\n    - name: decoy\n      with:\n"
            f"        persist-credentials: false\n        CLOSE: ignored#'}}\n      uses: {pin}\n",
        ),
        (
            "flow double quote hides env scalar",
            pr + "      - env: { X: foo\"bar, Y: \"ignored }\n      - name: decoy\n        with:\n"
            f"          persist-credentials: false\n          CLOSE: ignored#\"}}\n        uses: {pin}\n"
            + tail,
        ),
        (
            "duplicate with mapping",
            pr + f"      - uses: {pin}\n        with:\n          persist-credentials: false\n"
            "        with:\n          fetch-depth: 0\n" + tail,
        ),
        (
            "input spelled in another case",
            pr + f"      - uses: {pin}\n        with:\n          persist-credentials: false\n"
            "          Persist-Credentials: true\n" + tail,
        ),
        (
            "job env presets the input",
            pr.replace("  build:\n", "  build:\n    env:\n      INPUT_PERSIST-CREDENTIALS: 'true'\n")
            + f"      - uses: {pin}\n        with:\n          persist-credentials: false\n" + tail,
        ),
        (
            "YAML 1.1 boolean spelling",
            pr + f"      - uses: {pin}\n        with:\n          persist-credentials: off\n" + tail,
        ),
        (
            "upper-case step key",
            pr + f"      - Uses: {pin}\n        with:\n          fetch-depth: 0\n" + tail,
        ),
        (
            "anchor elsewhere in the file",
            pr.replace("permissions:\n", "env:\n  A: &a x\npermissions:\n")
            + f"      - uses: {pin}\n        with:\n          persist-credentials: false\n" + tail,
        ),
        (
            "line separator splits lines differently",
            pr + f"      - uses: {pin}\n        env:\n          X: ignored         with: "
            "          persist-credentials: false\n" + tail,
        ),
        (
            "flow sequence key hides env scalar",
            pr + "      - env:\n          [X]: \"ignored\n      - name: decoy\n        with:\n"
            f"          persist-credentials: false\n          CLOSE: x#y\"\n        uses: {pin}\n" + tail,
        ),
        (
            "comment-bearing closer after single-quoted opener",
            pr + "      - env:\n          X: 'ignored\n      - name: decoy\n        with:\n"
            f"          persist-credentials: false\n          CLOSE: x#y'\n        uses: {pin}\n" + tail,
        ),
        (
            "comment-like suffix on the value",
            pr + f"      - uses: {pin}\n        with:\n          persist-credentials: false#x\n" + tail,
        ),
        (
            "composite block scalar impersonation",
            "name: a\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      with:\n        ssh-known-hosts: |\n"
            "          persist-credentials: false\n    - run: true\n      shell: bash\n",
        ),
    ):
        if not checkout_credential_errors(text, f"self-test checkout {label}"):
            failures.append(f"checkout credential self-test {label!r} was accepted")

    # Without PyYAML the parsed check cannot run, and the verifier must say so.
    global yaml
    parser = yaml
    try:
        yaml = None
        compliant = pr + f"      - uses: {pin}\n        with:\n          persist-credentials: false\n"
        if not checkout_credential_errors(compliant, "self-test checkout without PyYAML"):
            failures.append("checkout credential self-test: accepted a checkout without PyYAML")
    finally:
        yaml = parser

    # Repository level: a compliant workflow cannot hide a credential-persisting
    # checkout inside a local composite action.
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / WORKFLOW_DIR).mkdir(parents=True)
        (root / WORKFLOW_DIR / "ci.yml").write_text(
            pr + f"      - uses: {pin}\n        with:\n          persist-credentials: false\n"
            "      - uses: ./.github/actions/hidden\n",
            encoding="utf-8",
        )
        if check_repository(root):
            failures.append(f"checkout credential self-test: compliant repository rejected: {check_repository(root)}")
        (root / ACTIONS_DIR / "hidden").mkdir(parents=True)
        (root / ACTIONS_DIR / "hidden" / "action.yml").write_text(
            "name: hidden\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n    - run: true\n      shell: bash\n",
            encoding="utf-8",
        )
        if not check_repository(root):
            failures.append("checkout credential self-test: composite-action checkout was accepted")
        (root / ACTIONS_DIR / "hidden" / "action.yml").write_text(
            "name: hidden\non:\n  workflow_dispatch:\nruns:\n  using: composite\n  steps:\n"
            f"    - uses: {pin}\n      with:\n        persist-credentials: true\n",
            encoding="utf-8",
        )
        if not check_repository(root):
            failures.append(
                "checkout credential self-test: composite with a fake trigger persisted credentials"
            )

    frozen = pr.replace("  build:\n", "  docker:\n") + f"      - uses: {pin}\n" + tail
    if checkout_credential_errors(frozen, ".github/workflows/release.yml"):
        failures.append("checkout credential self-test: policy-frozen release job was rejected")
    if not checkout_credential_errors(frozen, ".github/workflows/ci.yml"):
        failures.append("checkout credential self-test: frozen-job exemption leaked to another file")
    decoy_job = pr.replace(
        "  build:\n    steps:\n",
        "  build:\n    env:\n      X: 'ignored\n  docker:\n      '\n    steps:\n",
    ) + f"      - uses: {pin}\n" + tail
    if not checkout_credential_errors(decoy_job, ".github/workflows/release.yml"):
        failures.append("checkout credential self-test: frozen job key inside a scalar was admitted")
    # A flow plain scalar holding a quote must not hide a real job key from the
    # frozen-job exemption: the checkout below belongs to `victim`, not `docker`.
    hidden_job = (
        pr.replace("  build:\n", "  docker:\n")
        + "      - run: true\n"
        + '  "probe":\n    runs-on: ubuntu-latest\n    env: {X: a"b}\n    steps:\n'
        "      - run: true\n  victim:\n    runs-on: ubuntu-latest\n    steps:\n"
        '      - run: echo "}"\n'
        f"      - uses: {pin}\n"
    )
    if not checkout_credential_errors(hidden_job, ".github/workflows/release.yml"):
        failures.append("checkout credential self-test: frozen exemption reached a hidden job")
    frozen_true = frozen.replace(tail, "        with:\n          persist-credentials: true\n" + tail)
    if not checkout_credential_errors(frozen_true, ".github/workflows/release.yml"):
        failures.append("checkout credential self-test: policy-frozen job admitted true")
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
