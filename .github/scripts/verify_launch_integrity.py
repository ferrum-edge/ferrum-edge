#!/usr/bin/env python3
"""Trusted launch-readiness integrity verifier (issue #3803).

This program answers one question: *did the candidate revision preserve the
launch/release governance contract?* It deliberately does **not** compute a
launch verdict, so a truthful `FAIL` from open launch blockers never makes the
integrity check red and blocker-fix pull requests can still merge.

Trust model
-----------
The caller (`.github/workflows/launch-integrity.yml`) runs on
`pull_request_target` / `merge_group`, checks out the *trusted base*, and loads
this file from a pinned trusted-base commit. Candidate content is extracted
with `git show` into a confined directory and is only ever read as inert data:
nothing from the candidate is imported, executed, or evaluated.

Two roots are supplied:

* `--base-dir` — the extraction of the pinned trusted base commit.
* `--candidate-dir` — the extraction of the pull-request head or merge-group
  head commit.

Each root uses a fixed, flat layout so no candidate-controlled path component
is ever joined into a filesystem path:

    <root>/check_launch_readiness.py
    <root>/verify_launch_integrity.py
    <root>/verify_launch_advisory_trust.py
    <root>/launch-blocker-policy.json
    <root>/launch-exemptions.json
    <root>/PRODUCTION_READINESS.md
    <root>/CODEOWNERS
    <root>/workflows/<workflow file>
    <root>/tree.txt

A slot file that is absent means the path is absent from that commit, which is
how deletion and renaming are detected. Everything else fails closed: an
unreadable, unparsable, or unexpected input is an error, never a pass.

Permission model
----------------
Executable launch-governance code — the checker, the release/readiness/
integrity/advisory-trust workflows, this verifier, and the advisory-trust
verifier — is **byte-frozen to the trusted base**. There is no semantic
permission layer for those files, because no source or YAML heuristic can prove
that arbitrary executable gate code is still equivalent to what was reviewed: a
prepended `return 0`, an early `sys.exit(0)`, or an inserted unconditional
branch leaves the original body and any required marker strings intact but
unreachable. Byte identity is the only property that survives that class of
rewrite, so it is the property enforced.

Changing an anchored file is therefore an administrative trusted-base update
(auditable bypass plus an immediate post-merge run on `main`), not an ordinary
pull request. A pull request whose branch predates such an update must merge
latest `main` before this check can go green.

What is still validated semantically is exactly the data a candidate is
*supposed* to edit: the blocker policy, the exemption list, the readiness
document snapshot markers, and the CODEOWNERS map. Workflow enumeration
(check-run producer identity and advisory-secret exposure) is retained as
defense in depth over the *whole* workflow directory, including workflows a
candidate adds; it is not the permission model for the anchored files.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Frozen contract
# ---------------------------------------------------------------------------

CHECKER_PATH = "scripts/check_launch_readiness.py"
VERIFIER_PATH = ".github/scripts/verify_launch_integrity.py"
ADVISORY_VERIFIER_PATH = ".github/scripts/verify_launch_advisory_trust.py"
POLICY_PATH = "docs/launch-blocker-policy.json"
EXEMPTIONS_PATH = "docs/launch-exemptions.json"
DOCUMENT_PATH = "PRODUCTION_READINESS.md"
CODEOWNERS_PATH = ".github/CODEOWNERS"
READINESS_WORKFLOW = ".github/workflows/launch-readiness.yml"
INTEGRITY_WORKFLOW = ".github/workflows/launch-integrity.yml"
RELEASE_WORKFLOW = ".github/workflows/release.yml"
ADVISORY_WORKFLOW = ".github/workflows/launch-advisory-trust.yml"

# Slot name -> repository path. Slots are flat file names inside a root.
FILE_SLOTS = {
    "checker": CHECKER_PATH,
    "verifier": VERIFIER_PATH,
    "advisory_verifier": ADVISORY_VERIFIER_PATH,
    "policy": POLICY_PATH,
    "exemptions": EXEMPTIONS_PATH,
    "document": DOCUMENT_PATH,
    "codeowners": CODEOWNERS_PATH,
}
SLOT_FILENAMES = {
    "checker": "check_launch_readiness.py",
    "verifier": "verify_launch_integrity.py",
    "advisory_verifier": "verify_launch_advisory_trust.py",
    "policy": "launch-blocker-policy.json",
    "exemptions": "launch-exemptions.json",
    "document": "PRODUCTION_READINESS.md",
    "codeowners": "CODEOWNERS",
}
PATH_BY_SLOT_FILENAME = {
    filename: FILE_SLOTS[slot] for slot, filename in SLOT_FILENAMES.items()
}

# Deleting or renaming any of these is an integrity failure on its own.
PROTECTED_PATHS = (
    CHECKER_PATH,
    VERIFIER_PATH,
    POLICY_PATH,
    EXEMPTIONS_PATH,
    DOCUMENT_PATH,
    CODEOWNERS_PATH,
    READINESS_WORKFLOW,
    INTEGRITY_WORKFLOW,
    RELEASE_WORKFLOW,
)

# --- byte-frozen executable gate code ---------------------------------------
#
# `(slot, required)` / `(workflow filename, required)`. A *required* anchor must
# exist on the trusted base: a base that cannot supply it is an incomplete
# extraction, which fails closed rather than silently skipping enforcement. An
# *optional* anchor is one a sibling change is still landing (issue #3802's
# advisory-trust lane); it is unfrozen only while the trusted base also lacks
# it, and becomes a hard anchor — deletion and byte changes both rejected — the
# moment the base carries it.
ANCHOR_FILE_SLOTS = (
    ("verifier", True),
    ("checker", True),
    ("advisory_verifier", False),
)
ANCHOR_WORKFLOWS = (
    ("launch-integrity.yml", True),
    ("launch-readiness.yml", True),
    ("release.yml", True),
    ("launch-advisory-trust.yml", False),
)

# Required check contexts, keyed by the workflow file that must own them. A
# candidate may not move, duplicate, or re-home a required check name: the
# check-run producer is part of the contract.
CHECK_RUN_OWNERS = {
    "Launch Readiness Integrity": "launch-integrity.yml",
    "Launch Readiness Gate": "launch-readiness.yml",
}

CODEOWNERS_GOVERNED_PATHS = (
    "/PRODUCTION_READINESS.md",
    "/docs/launch-blocker-policy.json",
    "/docs/launch-exemptions.json",
    "/docs/launch-readiness.md",
    "/scripts/check_launch_readiness.py",
    "/.github/workflows/launch-readiness.yml",
    "/.github/workflows/launch-integrity.yml",
    "/.github/workflows/release.yml",
    "/.github/scripts/verify_launch_integrity.py",
    "/.github/CODEOWNERS",
)
# Governed only once the repository actually carries the file, so the
# advisory-trust lane can land in either merge order.
CODEOWNERS_OPTIONAL_GOVERNED_PATHS = {
    "/.github/workflows/launch-advisory-trust.yml": ADVISORY_WORKFLOW,
    "/.github/scripts/verify_launch_advisory_trust.py": ADVISORY_VERIFIER_PATH,
}

# --- blocker-policy contract (candidate-editable data) ----------------------

REQUIRED_STATE_MACHINE = {
    "open": "blocking",
    "in_flight": "blocking",
    "merged_awaiting_issue_close": "blocking",
    "closed_completed": "cleared",
    "closed_other": "blocking",
    "exempted": "cleared_for_listed_tiers",
}

# Advisory evidence that must never be checked in: a pull-request-controlled
# count is not evidence.
FORBIDDEN_POLICY_KEYS = (
    "opaque_input",
    "redacted_blocking_count",
    "as_of",
    "private_blocker_count",
)

# Confidential advisory fields the policy must keep listed as never-emitted.
REQUIRED_NEVER_EMIT_FIELDS = (
    "summary",
    "description",
    "ghsa_id",
    "cve_id",
    "html_url",
    "url",
    "vulnerabilities",
    "identifiers",
    "cvss",
    "cwes",
    "credits",
)

# A ceiling, not a tunable: the policy may tighten it and never loosen it.
MAX_FALLBACK_AGE_SECONDS_CEILING = 30 * 24 * 60 * 60

# Mirrors of the frozen production checker's vocabulary
# (`scripts/check_launch_readiness.py`). The checker is byte-frozen, but the
# policy it consumes is candidate-editable data, so a policy that the checker
# would reject — or that quietly narrows what the checker will block — must be
# refused here, at pull-request time, before it can reach the trusted checker on
# `main`.
SEVERITIES = ("critical", "high", "medium")
ADVISORY_STATES = ("triage", "draft", "published", "closed", "withdrawn")
ADVISORY_SEVERITIES = ("critical", "high", "medium", "low")
# GA is the launch tier the release gate runs at: it must keep blocking every
# non-`low` private-advisory severity. Tiers may tighten, never loosen.
REQUIRED_GA_ADVISORY_SEVERITIES = frozenset({"critical", "high", "medium"})

OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,63}$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

# --- workflow scan (defense in depth) ---------------------------------------

ADVISORY_SECRET = "LAUNCH_ADVISORY_READ_TOKEN"
# The privileged advisory credential may be referenced only by workflows that
# are themselves byte-frozen anchors. Any other workflow — including one a
# candidate adds — referencing it is a finding.
ADVISORY_SECRET_HOLDERS = frozenset(
    {
        "launch-readiness.yml",
        "release.yml",
        "launch-advisory-trust.yml",
    }
)

WORKFLOW_FILENAME_RE = re.compile(r"^[A-Za-z0-9._+@~ -]+\.(?:yml|yaml)$")
ISO_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


class IntegrityError(Exception):
    """An input could not be read at all: fail closed, never pass."""


# ---------------------------------------------------------------------------
# Root loading
# ---------------------------------------------------------------------------


class Root:
    """One extracted commit, read as inert data."""

    def __init__(self, label: str, directory: Path) -> None:
        self.label = label
        self.directory = directory
        if not directory.is_dir():
            raise IntegrityError(f"{label} extraction root is missing")
        self.files: dict[str, str | None] = {}
        for slot, filename in SLOT_FILENAMES.items():
            self.files[slot] = read_optional(directory / filename, f"{label}/{slot}")
        self.workflows: dict[str, str] = {}
        workflow_dir = directory / "workflows"
        if workflow_dir.is_dir():
            for entry in sorted(workflow_dir.iterdir()):
                if not entry.is_file():
                    raise IntegrityError(
                        f"{label} workflow extraction holds a non-file entry"
                    )
                if not WORKFLOW_FILENAME_RE.match(entry.name):
                    raise IntegrityError(
                        f"{label} workflow extraction holds an unsupported name"
                    )
                text = read_optional(entry, f"{label}/workflows/{entry.name}")
                if text is None:
                    raise IntegrityError(
                        f"{label} workflow {entry.name} could not be read"
                    )
                self.workflows[entry.name] = text
        listing = read_optional(directory / "tree.txt", f"{label}/tree")
        if listing is None:
            raise IntegrityError(f"{label} tree listing is missing")
        self.tree = {line.strip() for line in listing.splitlines() if line.strip()}
        if not self.tree:
            raise IntegrityError(f"{label} tree listing is empty")

    def text(self, slot: str) -> str | None:
        return self.files.get(slot)


def read_optional(path: Path, label: str) -> str | None:
    if not path.exists():
        return None
    if not path.is_file() or path.is_symlink():
        raise IntegrityError(f"{label} is not a regular file")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:  # pragma: no cover - fail closed
        raise IntegrityError(f"{label} could not be decoded: {exc}") from exc


# ---------------------------------------------------------------------------
# Minimal, layout-strict workflow reading
# ---------------------------------------------------------------------------


def job_blocks(workflow: str) -> dict[str, str]:
    """Split `jobs:` into `job id -> block text` for a block-style workflow."""

    lines = workflow.splitlines(keepends=True)
    headers = [
        index for index, line in enumerate(lines) if line.rstrip("\r\n") == "jobs:"
    ]
    if len(headers) != 1:
        return {}
    start = headers[0]
    blocks: dict[str, str] = {}
    current: str | None = None
    body: list[str] = []
    for line in lines[start + 1 :]:
        if re.match(r"^[A-Za-z0-9_-]+:", line):
            break
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            if current is not None:
                blocks[current] = "".join(body)
            current = match.group(1)
            body = []
            continue
        if current is not None:
            body.append(line)
    if current is not None:
        blocks[current] = "".join(body)
    return blocks


def job_display_name(job_id: str, block: str) -> str:
    match = re.search(r"(?m)^    name:[ \t]*(.+?)[ \t]*$", block)
    if not match:
        return job_id
    return match.group(1).strip().strip("'\"")


def non_comment_text(text: str) -> str:
    """Drop `#` comments so prose about a check name is not read as YAML."""

    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


# ---------------------------------------------------------------------------
# Policy, exemptions, document
# ---------------------------------------------------------------------------


def normalized(value: Any) -> Any:
    """Compare list/tuple spellings by content, mappings by items."""

    if isinstance(value, (list, tuple)):
        return tuple(normalized(item) for item in value)
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in value.items()}
    return value


def load_json(text: str | None, path: str, errors: list[str]) -> Any:
    if text is None:
        errors.append(f"{path} is missing from the candidate revision")
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        errors.append(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})")
        return None


def str_list(value: Any) -> list[str] | None:
    """A non-empty JSON array of non-empty strings, or `None` if it is not one."""

    if not isinstance(value, list) or not value:
        return None
    if not all(isinstance(item, str) and item for item in value):
        return None
    return list(value)


def parse_instant(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp to a UTC instant, mirroring the checker.

    Comparing these lexically is wrong across offsets: `2026-08-02T00:00:00+09:00`
    sorts after `2026-08-01T23:00:00Z` but happens eight hours *before* it. The
    exemption window is therefore compared as instants.
    """

    if not isinstance(value, str) or not ISO_Z_RE.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def contains_key(value: Any, keys: Iterable[str]) -> str | None:
    stack = [value]
    wanted = set(keys)
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, item in current.items():
                if key in wanted:
                    return key
                stack.append(item)
        elif isinstance(current, list):
            stack.extend(current)
    return None


def policy_errors(candidate_text: str | None, base_text: str | None) -> list[str]:
    errors: list[str] = []
    policy = load_json(candidate_text, POLICY_PATH, errors)
    if not isinstance(policy, dict):
        if policy is not None:
            errors.append(f"{POLICY_PATH} is not a JSON object")
        return errors
    # Several policy checks are *comparisons* against the trusted base (the
    # label contract, tier tightening, the credential and evidence-source
    # names). Silently degrading to "no base" when the base copy cannot be read
    # would turn every one of them off, so an unusable base fails closed.
    base: dict[str, Any] = {}
    if base_text is None or not base_text.strip():
        errors.append(
            f"{POLICY_PATH} is missing from the trusted base; refusing to certify "
            "a policy edit against an incomplete base"
        )
    else:
        try:
            loaded = json.loads(base_text)
        except json.JSONDecodeError as exc:
            errors.append(
                f"{POLICY_PATH} on the trusted base is not valid JSON "
                f"({exc.msg}); refusing to certify a policy edit against it"
            )
        else:
            if isinstance(loaded, dict):
                base = loaded
            else:
                errors.append(
                    f"{POLICY_PATH} on the trusted base is not a JSON object; "
                    "refusing to certify a policy edit against it"
                )

    forbidden = contains_key(policy, FORBIDDEN_POLICY_KEYS)
    if forbidden is not None:
        errors.append(
            f"{POLICY_PATH} carries pull-request-controlled advisory evidence "
            f"`{forbidden}`"
        )

    # Repository identity decides which issues and advisories the checker reads.
    # It is a format-checked constant, not a tunable, so it is pinned.
    repository = policy.get("repository")
    if not isinstance(repository, str) or not REPO_RE.fullmatch(repository):
        errors.append(f"{POLICY_PATH} repository is not an `owner/name` identity")
    else:
        base_repository = base.get("repository")
        if isinstance(base_repository, str) and base_repository:
            if repository != base_repository:
                errors.append(
                    f"{POLICY_PATH} repository identity differs from the trusted "
                    "base; the evaluated repository is not a pull-request choice"
                )

    # The versions label the contract the readiness snapshot was produced under.
    # A bump is a legitimate part of a policy edit, so they are required to stay
    # present and non-empty rather than pinned.
    for key in ("policy_version", "classification_version"):
        value = policy.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{POLICY_PATH} {key} is missing or empty")

    if normalized(policy.get("state_machine")) != normalized(REQUIRED_STATE_MACHINE):
        errors.append(f"{POLICY_PATH} state machine differs from the frozen contract")
    if normalized(policy.get("closed_completed_reasons")) != ("completed",):
        errors.append(f"{POLICY_PATH} closed_completed_reasons is not `[completed]`")
    if normalized(policy.get("closed_other_reasons")) != ("not_planned", "duplicate", None):
        errors.append(f"{POLICY_PATH} closed_other_reasons was narrowed")
    if policy.get("in_flight_clears_blocker") is not False:
        errors.append(f"{POLICY_PATH} lets an in-flight PR clear a blocker")
    if policy.get("merged_pr_clears_blocker_before_issue_close") is not False:
        errors.append(f"{POLICY_PATH} lets a merged PR clear a blocker before close")

    tiers = policy.get("tiers")
    if not isinstance(tiers, dict) or not tiers:
        errors.append(f"{POLICY_PATH} has no tier table")
        tiers = {}
    if any(not isinstance(name, str) or not name for name in tiers):
        errors.append(f"{POLICY_PATH} tier table holds a malformed tier name")
    ga = tiers.get("ga")
    ga_severities = ga.get("blocking_severities") if isinstance(ga, dict) else None
    if normalized(ga_severities) != ("critical", "high", "medium"):
        errors.append(f"{POLICY_PATH} GA tier no longer blocks every severity")
    base_tiers = base.get("tiers") if isinstance(base.get("tiers"), dict) else {}
    for tier, entry in tiers.items():
        severities = str_list(entry.get("blocking_severities")) if isinstance(entry, dict) else None
        if severities is None:
            errors.append(f"{POLICY_PATH} tier `{tier}` has no blocking severities")
            continue
        unknown = sorted(set(severities) - set(SEVERITIES))
        if unknown:
            errors.append(
                f"{POLICY_PATH} tier `{tier}` lists severities the checker does "
                f"not know: {unknown}"
            )
        base_entry = base_tiers.get(tier)
        base_severities = (
            base_entry.get("blocking_severities") if isinstance(base_entry, dict) else None
        )
        if isinstance(base_severities, list) and not set(base_severities) <= set(severities):
            errors.append(
                f"{POLICY_PATH} tier `{tier}` dropped a blocking severity the "
                "trusted base enforced"
            )

    default_tier = policy.get("default_launch_tier")
    if not isinstance(default_tier, str) or not default_tier:
        errors.append(f"{POLICY_PATH} default_launch_tier is missing")
    elif tiers and default_tier not in tiers:
        errors.append(
            f"{POLICY_PATH} default_launch_tier `{default_tier}` is not a defined tier"
        )

    labels = policy.get("labels")
    base_labels = base.get("labels")
    if not isinstance(labels, dict):
        errors.append(f"{POLICY_PATH} has no label table")
    else:
        for key in ("launch_blocker", "launch_exempted"):
            value = labels.get(key)
            if not isinstance(value, str) or not LABEL_RE.fullmatch(value):
                errors.append(f"{POLICY_PATH} label `{key}` is missing or malformed")
        severity_labels = labels.get("severity")
        if not isinstance(severity_labels, dict) or set(severity_labels) != set(SEVERITIES):
            errors.append(
                f"{POLICY_PATH} labels.severity must cover exactly "
                f"{sorted(SEVERITIES)}"
            )
        else:
            # Two severities sharing one label collapses their issue sets.
            seen_labels: set[str] = set()
            for severity in SEVERITIES:
                value = severity_labels.get(severity)
                if not isinstance(value, str) or not LABEL_RE.fullmatch(value):
                    errors.append(
                        f"{POLICY_PATH} labels.severity.{severity} is missing or "
                        "malformed"
                    )
                    continue
                if value in seen_labels:
                    errors.append(f"{POLICY_PATH} labels.severity entries must be distinct")
                seen_labels.add(value)
        if isinstance(base_labels, dict) and normalized(labels) != normalized(base_labels):
            errors.append(
                f"{POLICY_PATH} label contract differs from the trusted base; a label "
                "rename silently empties the blocker set"
            )

    advisories = policy.get("private_advisories")
    base_advisories = base.get("private_advisories")
    if not isinstance(advisories, dict):
        errors.append(f"{POLICY_PATH} has no private-advisory contract")
        advisories = {}
    if advisories.get("enabled") is not True:
        errors.append(f"{POLICY_PATH} disables the private-advisory contract")
    if advisories.get("representation") != "redacted_count_only":
        errors.append(f"{POLICY_PATH} private advisories are no longer redacted-count-only")
    blocking_states = str_list(advisories.get("blocking_states"))
    closed_states = str_list(advisories.get("closed_states"))
    if blocking_states is None or not {"triage", "draft"} <= set(blocking_states):
        errors.append(f"{POLICY_PATH} unpublished advisory states no longer block")
    if closed_states is None:
        errors.append(f"{POLICY_PATH} private advisory closed_states is missing")
    if blocking_states is not None and closed_states is not None:
        # The checker partitions advisory states: a state in neither set (or in
        # both) is an unclassified advisory, which is how a blocking state gets
        # quietly demoted.
        blocking_set = set(blocking_states)
        closed_set = set(closed_states)
        if blocking_set & closed_set:
            errors.append(
                f"{POLICY_PATH} advisory blocking and closed state sets overlap"
            )
        if blocking_set | closed_set != set(ADVISORY_STATES):
            errors.append(
                f"{POLICY_PATH} advisory state sets must cover exactly "
                f"{sorted(ADVISORY_STATES)}"
            )

    by_tier = advisories.get("blocking_severities_by_tier")
    base_by_tier = (
        base_advisories.get("blocking_severities_by_tier")
        if isinstance(base_advisories, dict)
        else None
    )
    if not isinstance(by_tier, dict) or not by_tier:
        errors.append(
            f"{POLICY_PATH} has no private-advisory blocking_severities_by_tier table"
        )
    else:
        if tiers and set(by_tier) != set(tiers):
            errors.append(
                f"{POLICY_PATH} private-advisory severities must cover exactly the "
                "policy tiers"
            )
        for tier, value in by_tier.items():
            severities = str_list(value)
            if severities is None:
                errors.append(
                    f"{POLICY_PATH} private-advisory tier `{tier}` has no blocking "
                    "severities"
                )
                continue
            unknown = sorted(set(severities) - set(ADVISORY_SEVERITIES))
            if unknown:
                errors.append(
                    f"{POLICY_PATH} private-advisory tier `{tier}` lists severities "
                    f"the checker does not know: {unknown}"
                )
            base_severities = (
                str_list(base_by_tier.get(tier))
                if isinstance(base_by_tier, dict)
                else None
            )
            if base_severities is not None and not set(base_severities) <= set(severities):
                errors.append(
                    f"{POLICY_PATH} private-advisory tier `{tier}` dropped a blocking "
                    "severity the trusted base enforced"
                )
        ga_advisory = str_list(by_tier.get("ga"))
        if ga_advisory is None or not REQUIRED_GA_ADVISORY_SEVERITIES <= set(ga_advisory):
            errors.append(
                f"{POLICY_PATH} GA tier no longer blocks every private-advisory "
                "severity"
            )

    never_emit = advisories.get("never_emit_fields")
    required_never_emit = set(REQUIRED_NEVER_EMIT_FIELDS)
    if not isinstance(never_emit, list) or not required_never_emit <= set(never_emit):
        errors.append(f"{POLICY_PATH} never_emit_fields dropped a confidential field")
    live_api = advisories.get("live_api")
    if not isinstance(live_api, dict):
        errors.append(f"{POLICY_PATH} has no private-advisory live_api contract")
    else:
        if live_api.get("actions_security_events_permission_is_insufficient") is not True:
            errors.append(
                f"{POLICY_PATH} claims the Actions token can list private advisories"
            )
        token_env = live_api.get("token_env")
        if not isinstance(token_env, str) or not ENV_NAME_RE.fullmatch(token_env):
            errors.append(
                f"{POLICY_PATH} live_api.token_env is not a valid environment-variable "
                "name"
            )
        else:
            # The credential the trusted lanes supply is named by the workflow,
            # not by the candidate: redirecting this name points the live listing
            # at an attacker-chosen (and therefore empty) variable.
            base_live_api = (
                base_advisories.get("live_api")
                if isinstance(base_advisories, dict)
                else None
            )
            base_token_env = (
                base_live_api.get("token_env") if isinstance(base_live_api, dict) else None
            )
            if isinstance(base_token_env, str) and base_token_env:
                if token_env != base_token_env:
                    errors.append(
                        f"{POLICY_PATH} live_api.token_env was redirected away from "
                        "the trusted-base advisory credential"
                    )
    fallback = advisories.get("trusted_fallback")
    base_fallback = (
        base_advisories.get("trusted_fallback")
        if isinstance(base_advisories, dict)
        else None
    )
    if not isinstance(fallback, dict):
        errors.append(f"{POLICY_PATH} has no trusted advisory fallback contract")
    else:
        max_age = fallback.get("max_age_seconds")
        if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
            errors.append(f"{POLICY_PATH} fallback max_age_seconds is not a positive int")
        else:
            if max_age > MAX_FALLBACK_AGE_SECONDS_CEILING:
                errors.append(
                    f"{POLICY_PATH} fallback max_age_seconds exceeds the frozen ceiling"
                )
            base_age = (
                base_fallback.get("max_age_seconds")
                if isinstance(base_fallback, dict)
                else None
            )
            if isinstance(base_age, int) and not isinstance(base_age, bool):
                if max_age > base_age:
                    errors.append(
                        f"{POLICY_PATH} widened the private-advisory freshness window"
                    )
        # The fallback evidence lives in repository Actions variables a pull
        # request can read but not write. Renaming either one redirects the
        # checker at a variable a candidate *can* influence, or at an unrelated
        # repository variable that happens to read as "zero blockers".
        variable_names: dict[str, str] = {}
        for key in ("count_variable", "as_of_variable"):
            name = fallback.get(key)
            if not isinstance(name, str) or not ENV_NAME_RE.fullmatch(name):
                errors.append(
                    f"{POLICY_PATH} fallback `{key}` is not a valid "
                    "environment-variable name"
                )
                continue
            variable_names[key] = name
            base_name = base_fallback.get(key) if isinstance(base_fallback, dict) else None
            if isinstance(base_name, str) and base_name and name != base_name:
                errors.append(
                    f"{POLICY_PATH} fallback `{key}` was redirected away from the "
                    "trusted-base evidence source"
                )
        if len(variable_names) == 2 and len(set(variable_names.values())) != 2:
            errors.append(
                f"{POLICY_PATH} fallback count and as-of variables must be distinct"
            )

    tracked = policy.get("tracked_blockers")
    if not isinstance(tracked, list):
        errors.append(f"{POLICY_PATH} tracked_blockers is not a list")
    else:
        seen: set[int] = set()
        for entry in tracked:
            if not isinstance(entry, dict):
                errors.append(f"{POLICY_PATH} tracked_blockers holds a non-object entry")
                continue
            issue = entry.get("issue")
            severity = entry.get("severity")
            if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
                errors.append(f"{POLICY_PATH} tracked blocker has no usable issue number")
                continue
            if issue in seen:
                errors.append(f"{POLICY_PATH} tracked blocker {issue} is duplicated")
            seen.add(issue)
            if severity not in SEVERITY_ORDER or severity == "low":
                errors.append(
                    f"{POLICY_PATH} tracked blocker {issue} has an unusable severity"
                )
            # Schema only: the inventory's *content* stays a CODEOWNER decision,
            # but an entry the checker would reject must not reach `main`.
            note = entry.get("note")
            if not isinstance(note, str) or not note.strip():
                errors.append(f"{POLICY_PATH} tracked blocker {issue} has no note")

    document = policy.get("document")
    base_document = base.get("document")
    if not isinstance(document, dict):
        errors.append(f"{POLICY_PATH} has no document contract")
    else:
        if document.get("path") != DOCUMENT_PATH:
            errors.append(f"{POLICY_PATH} document path is not {DOCUMENT_PATH}")
        for key in ("marker_begin", "marker_end", "historical_marker"):
            if not isinstance(document.get(key), str) or not document.get(key):
                errors.append(f"{POLICY_PATH} document `{key}` is missing")
        if isinstance(base_document, dict) and normalized(document) != normalized(
            base_document
        ):
            errors.append(
                f"{POLICY_PATH} document marker contract differs from the trusted base"
            )
    if policy.get("exemptions_path") != EXEMPTIONS_PATH:
        errors.append(f"{POLICY_PATH} exemptions_path is not {EXEMPTIONS_PATH}")
    return errors


EXEMPTION_REQUIRED_KEYS = (
    "id",
    "issue",
    "launch_tiers",
    "owner",
    "approver",
    "rationale",
    "compensating_control",
    "approved_at",
    "expires_at",
)


def exemption_errors(
    candidate_text: str | None, tier_names: set[str] | None = None
) -> list[str]:
    """Mirror `check_launch_readiness.py::validate_exemptions` on inert data.

    An exemption is the one mechanism that clears a real blocker, so its schema
    is enforced to the same strength as the production checker's: a positive
    issue number, principals matching the checker's owner grammar, non-empty
    rationale and compensating control, tiers the candidate policy actually
    defines, and a validity window compared as instants.

    `tier_names` is the candidate policy's tier set, passed in as parsed data.
    Nothing from the candidate is imported or executed.
    """

    errors: list[str] = []
    data = load_json(candidate_text, EXEMPTIONS_PATH, errors)
    if data is None:
        return errors
    if not isinstance(data, dict):
        return [f"{EXEMPTIONS_PATH} is not a JSON object"]
    version = data.get("exemptions_version")
    if not isinstance(version, str) or not version.strip():
        errors.append(f"{EXEMPTIONS_PATH} has no exemptions_version")
    entries = data.get("exemptions")
    if not isinstance(entries, list):
        return errors + [f"{EXEMPTIONS_PATH} exemptions is not a list"]
    identifiers: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            errors.append(f"{EXEMPTIONS_PATH} holds a non-object exemption")
            continue
        missing = [key for key in EXEMPTION_REQUIRED_KEYS if key not in entry]
        if missing:
            errors.append(
                f"{EXEMPTIONS_PATH} exemption is missing {sorted(missing)}"
            )
            continue
        identifier = entry["id"]
        if not isinstance(identifier, str) or not identifier:
            errors.append(f"{EXEMPTIONS_PATH} exemption id is not a non-empty string")
            continue
        if identifier in identifiers:
            errors.append(f"{EXEMPTIONS_PATH} exemption `{identifier}` is duplicated")
        identifiers.add(identifier)

        issue = entry["issue"]
        if not isinstance(issue, int) or isinstance(issue, bool) or issue <= 0:
            errors.append(
                f"{EXEMPTIONS_PATH} exemption `{identifier}` has no positive issue "
                "number"
            )

        for key in ("owner", "approver", "rationale", "compensating_control"):
            value = entry[key]
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    f"{EXEMPTIONS_PATH} exemption `{identifier}` has an empty {key}"
                )
                continue
            if key in ("owner", "approver") and not OWNER_RE.fullmatch(value):
                errors.append(
                    f"{EXEMPTIONS_PATH} exemption `{identifier}` {key} is not an "
                    "accountable principal"
                )

        instants: dict[str, datetime] = {}
        for key in ("approved_at", "expires_at"):
            parsed = parse_instant(entry[key])
            if parsed is None:
                errors.append(
                    f"{EXEMPTIONS_PATH} exemption `{identifier}` has a malformed {key}"
                )
                continue
            instants[key] = parsed
        if len(instants) == 2 and instants["expires_at"] <= instants["approved_at"]:
            errors.append(
                f"{EXEMPTIONS_PATH} exemption `{identifier}` never expires after approval"
            )

        tiers = str_list(entry["launch_tiers"])
        if tiers is None:
            errors.append(
                f"{EXEMPTIONS_PATH} exemption `{identifier}` has no launch tiers"
            )
        elif tier_names:
            unknown = sorted(set(tiers) - tier_names)
            if unknown:
                errors.append(
                    f"{EXEMPTIONS_PATH} exemption `{identifier}` names launch tiers "
                    f"the policy does not define: {unknown}"
                )
    return errors


def candidate_tier_names(policy_text: str | None) -> set[str] | None:
    """The candidate policy's tier names, as inert parsed data.

    `None` means "not determinable" — the policy is missing or malformed, which
    `policy_errors` already reports; the tier-membership check is skipped rather
    than reported a second time as an exemption fault.
    """

    if policy_text is None:
        return None
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(policy, dict):
        return None
    tiers = policy.get("tiers")
    if not isinstance(tiers, dict):
        return None
    names = {name for name in tiers if isinstance(name, str) and name}
    return names or None


def document_errors(candidate_text: str | None, policy_text: str | None) -> list[str]:
    errors: list[str] = []
    if candidate_text is None:
        return [f"{DOCUMENT_PATH} is missing from the candidate revision"]
    markers = {
        "marker_begin": "<!-- launch-readiness:begin -->",
        "marker_end": "<!-- launch-readiness:end -->",
        "historical_marker": "<!-- launch-readiness:historical -->",
    }
    if policy_text is not None:
        try:
            policy = json.loads(policy_text)
        except json.JSONDecodeError:
            policy = None
        if isinstance(policy, dict) and isinstance(policy.get("document"), dict):
            for key in markers:
                value = policy["document"].get(key)
                if isinstance(value, str) and value:
                    markers[key] = value
    positions: dict[str, int] = {}
    for key, marker in markers.items():
        occurrences = candidate_text.count(marker)
        if occurrences != 1:
            errors.append(
                f"{DOCUMENT_PATH} must contain exactly one `{key}` marker "
                f"(found {occurrences})"
            )
            continue
        positions[key] = candidate_text.index(marker)
    if {"marker_begin", "marker_end"} <= positions.keys():
        if positions["marker_begin"] >= positions["marker_end"]:
            errors.append(f"{DOCUMENT_PATH} snapshot markers are out of order")
    return errors


# ---------------------------------------------------------------------------
# Workflow scan (defense in depth, not a permission model)
# ---------------------------------------------------------------------------


def check_run_identity_errors(workflows: dict[str, str]) -> list[str]:
    """A required check name must be produced by exactly one known workflow."""

    errors: list[str] = []
    owners: dict[str, list[str]] = {name: [] for name in CHECK_RUN_OWNERS}
    for filename, workflow in sorted(workflows.items()):
        for job_id, block in job_blocks(workflow).items():
            display = job_display_name(job_id, block)
            if display in owners:
                owners[display].append(filename)
    for name, expected in CHECK_RUN_OWNERS.items():
        found = owners[name]
        if found != [expected]:
            errors.append(
                f"required check `{name}` must be produced only by {expected} "
                f"(found {found or 'no producer'})"
            )
        # Block-mapping job parsing can be evaded with flow syntax, so the
        # comment-stripped text is checked too: a required check name may not
        # appear in any other workflow file's live YAML at all.
        for filename, workflow in sorted(workflows.items()):
            if filename != expected and name in non_comment_text(workflow):
                errors.append(
                    f".github/workflows/{filename} must not mention the required "
                    f"check name `{name}`"
                )
    return errors


def secret_exposure_errors(workflows: dict[str, str]) -> list[str]:
    """The advisory credential identifier may only occur in frozen workflows.

    Match the identifier itself rather than only GitHub's dot-property spelling:
    bracket access (``secrets['LAUNCH_ADVISORY_READ_TOKEN']``) is equivalent and
    must receive the same defense-in-depth refusal. The protected environment is
    still the credential's actual authorization boundary.
    """

    errors: list[str] = []
    for filename, workflow in sorted(workflows.items()):
        if ADVISORY_SECRET not in workflow:
            continue
        if filename not in ADVISORY_SECRET_HOLDERS:
            errors.append(
                f".github/workflows/{filename} must not reference the advisory token"
            )
    return errors


# ---------------------------------------------------------------------------
# Anchor, presence, ownership
# ---------------------------------------------------------------------------


def presence_errors(candidate: Root) -> list[str]:
    errors: list[str] = []
    for path in PROTECTED_PATHS:
        if path not in candidate.tree:
            errors.append(f"protected gate file {path} was deleted or renamed")
    for slot, path in FILE_SLOTS.items():
        text = candidate.text(slot)
        if path in candidate.tree and (text is None or not text.strip()):
            errors.append(f"protected gate file {path} is empty or unreadable")
    return errors


def anchor_pairs(
    candidate: Root, base: Root
) -> list[tuple[str, str | None, str | None, bool]]:
    pairs: list[tuple[str, str | None, str | None, bool]] = []
    for slot, required in ANCHOR_FILE_SLOTS:
        pairs.append(
            (FILE_SLOTS[slot], candidate.text(slot), base.text(slot), required)
        )
    for filename, required in ANCHOR_WORKFLOWS:
        pairs.append(
            (
                f".github/workflows/{filename}",
                candidate.workflows.get(filename),
                base.workflows.get(filename),
                required,
            )
        )
    return pairs


def anchor_errors(candidate: Root, base: Root) -> list[str]:
    """Byte-freeze every piece of executable launch-governance code.

    No source-level or YAML-level heuristic can prove that rewritten gate code
    is still equivalent to the reviewed code: an early `return`/`sys.exit(0)`
    or an inserted unconditional branch leaves the original statements and any
    required marker strings present but unreachable. Byte identity against the
    trusted base is the only property that class of rewrite cannot satisfy.
    """

    errors: list[str] = []
    for path, candidate_text, base_text, required in anchor_pairs(candidate, base):
        if base_text is None:
            if required:
                # The workflow only reaches the verifier when the trusted base
                # carries it, so a base missing a required anchor is a broken or
                # tampered extraction, never the one-time adoption commit (which
                # short-circuits before this program runs).
                errors.append(
                    f"the trusted base is missing the governed anchor {path}; "
                    "refusing to certify a candidate against an incomplete base"
                )
            # Optional anchor not yet adopted on the trusted base: nothing to
            # preserve. It freezes as soon as the base carries it.
            continue
        if not base_text.strip():
            errors.append(
                f"the trusted base copy of the governed anchor {path} is empty; "
                "refusing to certify against it"
            )
            continue
        if candidate_text is None:
            errors.append(f"the byte-frozen gate file {path} was deleted or renamed")
            continue
        if candidate_text != base_text:
            errors.append(
                f"the byte-frozen gate file {path} differs from the trusted base; "
                "executable launch-governance code cannot be changed by an "
                "ordinary pull request (merge the latest protected base, or land "
                "the change as an administrative trusted-base update)"
            )
    return errors


def codeowners_map(text: str | None) -> dict[str, set[str]]:
    owners: dict[str, set[str]] = {}
    if text is None:
        return owners
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        owners[parts[0]] = {part for part in parts[1:] if part.startswith("@")}
    return owners


def codeowners_errors(
    candidate_text: str | None,
    base_text: str | None,
    candidate_tree: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    if candidate_text is None:
        return [f"{CODEOWNERS_PATH} is missing from the candidate revision"]
    candidate = codeowners_map(candidate_text)
    base = codeowners_map(base_text)
    governed = list(CODEOWNERS_GOVERNED_PATHS)
    tree = candidate_tree or set()
    for owned_path, repo_path in CODEOWNERS_OPTIONAL_GOVERNED_PATHS.items():
        if repo_path in tree:
            governed.append(owned_path)
    for path in governed:
        assigned = candidate.get(path, set())
        if not assigned:
            errors.append(f"{CODEOWNERS_PATH} no longer assigns an owner to {path}")
            continue
        expected = base.get(path, set())
        if expected and not expected <= assigned:
            errors.append(
                f"{CODEOWNERS_PATH} removed a trusted-base owner from {path}"
            )
    return errors


# ---------------------------------------------------------------------------
# Verification entry point
# ---------------------------------------------------------------------------


def verify(base: Root, candidate: Root) -> list[str]:
    errors: list[str] = []
    errors.extend(presence_errors(candidate))
    errors.extend(anchor_errors(candidate, base))
    errors.extend(policy_errors(candidate.text("policy"), base.text("policy")))
    errors.extend(
        exemption_errors(
            candidate.text("exemptions"), candidate_tier_names(candidate.text("policy"))
        )
    )
    errors.extend(document_errors(candidate.text("document"), candidate.text("policy")))
    errors.extend(check_run_identity_errors(candidate.workflows))
    errors.extend(secret_exposure_errors(candidate.workflows))
    errors.extend(
        codeowners_errors(
            candidate.text("codeowners"), base.text("codeowners"), candidate.tree
        )
    )
    return list(dict.fromkeys(errors))


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


_FIXTURE_VERIFIER = "# trusted verifier anchor fixture\n"

_FIXTURE_ADVISORY_VERIFIER = "# trusted advisory-trust verifier fixture\n"

_FIXTURE_CHECKER = '''"""Synthetic launch checker fixture."""

import sys


def compute_verdict(unknown_reasons, records):
    if unknown_reasons:
        return "UNKNOWN"
    if records:
        return "FAIL"
    return "PASS"


def verify_errors(claim, evaluation):
    errors = []
    if evaluation.verdict != "PASS":
        errors.append("fail closed")
    return errors


def run_verify(argv):
    errors = verify_errors(argv, argv)
    return 1 if errors else 0


def main(argv=None):
    return run_verify(argv or [])


if __name__ == "__main__":
    sys.exit(main())
'''

_FIXTURE_POLICY = {
    "policy_version": "2",
    "classification_version": "launch-blocker-v2",
    "repository": "ferrum-edge/ferrum-edge",
    "default_launch_tier": "ga",
    "labels": {
        "launch_blocker": "launch-blocker",
        "launch_exempted": "launch-exempted",
        "severity": {
            "critical": "severity:critical",
            "high": "severity:high",
            "medium": "severity:medium",
        },
    },
    "tiers": {
        "ga": {"blocking_severities": ["critical", "high", "medium"]},
        "beta": {"blocking_severities": ["critical", "high"]},
        "experimental": {"blocking_severities": ["critical"]},
    },
    "state_machine": dict(REQUIRED_STATE_MACHINE),
    "closed_completed_reasons": ["completed"],
    "closed_other_reasons": ["not_planned", "duplicate", None],
    "in_flight_clears_blocker": False,
    "merged_pr_clears_blocker_before_issue_close": False,
    "tracked_blockers": [{"issue": 4242, "severity": "high", "note": "fixture"}],
    "private_advisories": {
        "enabled": True,
        "blocking_states": ["triage", "draft"],
        "closed_states": ["published", "closed", "withdrawn"],
        "blocking_severities_by_tier": {
            "ga": ["critical", "high", "medium"],
            "beta": ["critical", "high"],
            "experimental": ["critical"],
        },
        "representation": "redacted_count_only",
        "never_emit_fields": list(REQUIRED_NEVER_EMIT_FIELDS),
        "live_api": {
            "token_env": "LAUNCH_ADVISORY_READ_TOKEN",
            "actions_security_events_permission_is_insufficient": True,
        },
        "trusted_fallback": {
            "count_variable": "LAUNCH_PRIVATE_BLOCKER_COUNT",
            "as_of_variable": "LAUNCH_PRIVATE_ADVISORY_AS_OF",
            "max_age_seconds": 604800,
        },
    },
    "document": {
        "path": DOCUMENT_PATH,
        "marker_begin": "<!-- launch-readiness:begin -->",
        "marker_end": "<!-- launch-readiness:end -->",
        "historical_marker": "<!-- launch-readiness:historical -->",
    },
    "exemptions_path": EXEMPTIONS_PATH,
}

_FIXTURE_DOCUMENT = (
    "# Fixture ledger\n\n"
    "<!-- launch-readiness:begin -->\n"
    '```json\n{"verdict": "FAIL"}\n```\n'
    "<!-- launch-readiness:end -->\n\n"
    "<!-- launch-readiness:historical -->\n"
)

_FIXTURE_CODEOWNERS = "\n".join(
    f"{path}   @owner"
    for path in list(CODEOWNERS_GOVERNED_PATHS)
    + list(CODEOWNERS_OPTIONAL_GOVERNED_PATHS)
) + "\n"

_FIXTURE_READINESS_WORKFLOW = """name: Launch Readiness

on:
  pull_request:
  merge_group:
  push:
    branches:
      - main
    tags:
      - "v*"
  schedule:
    - cron: "15 6 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  launch-readiness:
    name: Launch Readiness Gate
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          persist-credentials: false
          ref: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.event_name == 'merge_group' && github.event.merge_group.head_sha || github.sha }}

      - name: Synthetic policy/checker self-tests
        run: python3 -I scripts/check_launch_readiness.py --self-test

      - name: Verify live launch verdict
        env:
          LAUNCH_TARGET_SHA: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.sha || github.event_name == 'merge_group' && github.event.merge_group.head_sha || github.sha }}
          LAUNCH_ADVISORY_READ_TOKEN: ${{ (github.event_name != 'pull_request' && github.event_name != 'merge_group') && secrets.LAUNCH_ADVISORY_READ_TOKEN || '' }}
        run: python3 -I scripts/check_launch_readiness.py --verify --verify-checkout
"""

_FIXTURE_INTEGRITY_WORKFLOW = """name: Launch Readiness Integrity

on:
  pull_request_target:
    branches:
      - main
  merge_group:
    types:
      - checks_requested

permissions:
  contents: read

jobs:
  verify:
    name: Launch Readiness Integrity
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
        with:
          persist-credentials: false

      - name: Enforce the launch governance contract
        run: |
          echo "merge_group base_sha missing or malformed" > /dev/null
"""

_FIXTURE_RELEASE_WORKFLOW = """name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  validate-release-version:
    name: Validate release version
    runs-on: ubuntu-latest
    steps:
      - run: echo version

  validate-launch-readiness:
    name: Validate launch readiness
    needs: validate-release-version
    runs-on: ubuntu-latest
    steps:
      - name: Synthetic policy/checker self-tests
        run: python3 -I scripts/check_launch_readiness.py --self-test

      - name: Require live launch PASS for the exact tag commit
        run: python3 -I scripts/check_launch_readiness.py --verify --require-pass

  validate-release-sha:
    name: Validate release SHA
    needs:
      - validate-release-version
      - validate-launch-readiness
    runs-on: ubuntu-latest
    steps:
      - run: echo sha

  publish:
    name: Publish
    needs: validate-release-sha
    runs-on: ubuntu-latest
    steps:
      - run: echo publish
"""

_FIXTURE_ADVISORY_WORKFLOW = """name: Trusted Launch Advisory Gate

on:
  workflow_run:
    workflows:
      - Release
    types:
      - requested
  workflow_dispatch:

permissions:
  contents: read

jobs:
  advisory-verdict:
    name: Trusted advisory verdict
    runs-on: ubuntu-latest
    steps:
      - name: Read the advisory credential
        env:
          LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}
        run: echo verdict
"""


def _write_root(directory: Path, files: dict[str, str], workflows: dict[str, str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "workflows").mkdir(exist_ok=True)
    for name, text in files.items():
        (directory / name).write_text(text, encoding="utf-8")
    tree = [PATH_BY_SLOT_FILENAME[name] for name in files]
    tree.extend(f".github/workflows/{name}" for name in workflows)
    for name, text in workflows.items():
        (directory / "workflows" / name).write_text(text, encoding="utf-8")
    (directory / "tree.txt").write_text("\n".join(sorted(set(tree))) + "\n", "utf-8")


def _fixture_files() -> dict[str, str]:
    return {
        SLOT_FILENAMES["checker"]: _FIXTURE_CHECKER,
        SLOT_FILENAMES["verifier"]: _FIXTURE_VERIFIER,
        SLOT_FILENAMES["policy"]: json.dumps(_FIXTURE_POLICY, indent=2) + "\n",
        SLOT_FILENAMES["exemptions"]: json.dumps(
            {"exemptions_version": "1", "exemptions": []}, indent=2
        )
        + "\n",
        SLOT_FILENAMES["document"]: _FIXTURE_DOCUMENT,
        SLOT_FILENAMES["codeowners"]: _FIXTURE_CODEOWNERS,
    }


def _fixture_workflows() -> dict[str, str]:
    return {
        "launch-readiness.yml": _FIXTURE_READINESS_WORKFLOW,
        "launch-integrity.yml": _FIXTURE_INTEGRITY_WORKFLOW,
        "release.yml": _FIXTURE_RELEASE_WORKFLOW,
    }


def _adopt_advisory(files: dict[str, str], workflows: dict[str, str]) -> None:
    """Add the issue #3802 advisory-trust lane to a fixture root."""

    files[SLOT_FILENAMES["advisory_verifier"]] = _FIXTURE_ADVISORY_VERIFIER
    workflows["launch-advisory-trust.yml"] = _FIXTURE_ADVISORY_WORKFLOW


_FIXTURE_EXEMPTION = {
    "id": "ex-1",
    "issue": 4242,
    "launch_tiers": ["ga"],
    "owner": "fixture-owner",
    "approver": "fixture-approver",
    "rationale": "fixture rationale",
    "compensating_control": "fixture compensating control",
    "approved_at": "2026-08-01T00:00:00Z",
    "expires_at": "2026-09-01T00:00:00Z",
}


def _exemption(**overrides: Any) -> dict[str, Any]:
    entry = dict(_FIXTURE_EXEMPTION)
    entry.update(overrides)
    return entry


def _exemptions_document(*entries: dict[str, Any]) -> str:
    return (
        json.dumps(
            {"exemptions_version": "1", "exemptions": list(entries)}, indent=2
        )
        + "\n"
    )


def _with_exemptions(*entries: dict[str, Any]) -> Any:
    def mutate(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["exemptions"]] = _exemptions_document(*entries)

    return mutate


def _with_policy(apply: Any) -> Any:
    """Build a fixture mutator that edits the policy as parsed JSON."""

    def mutate(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        apply(policy)
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2) + "\n"

    return mutate


def run_self_test() -> int:
    """Adversarial fixtures for every weakening this check must refuse."""

    failures: list[str] = []

    def evaluate(
        mutate_files: Any = None,
        mutate_workflows: Any = None,
        mutate_base_files: Any = None,
        mutate_base_workflows: Any = None,
        adopt_advisory_base: bool = False,
        adopt_advisory_candidate: bool = False,
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            base_files = _fixture_files()
            base_workflows = _fixture_workflows()
            if adopt_advisory_base:
                _adopt_advisory(base_files, base_workflows)
            if mutate_base_files is not None:
                mutate_base_files(base_files)
            if mutate_base_workflows is not None:
                mutate_base_workflows(base_workflows)
            _write_root(root / "base", base_files, base_workflows)
            files = _fixture_files()
            workflows = _fixture_workflows()
            if adopt_advisory_candidate:
                _adopt_advisory(files, workflows)
            if mutate_files is not None:
                mutate_files(files)
            if mutate_workflows is not None:
                mutate_workflows(workflows)
            _write_root(root / "candidate", files, workflows)
            return verify(Root("base", root / "base"), Root("candidate", root / "candidate"))

    def expect_clean(name: str, errors: list[str]) -> None:
        if errors:
            failures.append(f"{name}: expected no findings, got {errors}")

    def expect_rejected(name: str, errors: list[str]) -> None:
        if not errors:
            failures.append(f"{name}: expected a finding, got none")

    expect_clean("pristine candidate", evaluate())

    # 1. Deletion of byte-frozen executable gate code.
    def delete_checker(files: dict[str, str]) -> None:
        files.pop(SLOT_FILENAMES["checker"])

    expect_rejected("checker deleted", evaluate(delete_checker))

    def delete_verifier(files: dict[str, str]) -> None:
        files.pop(SLOT_FILENAMES["verifier"])

    expect_rejected("verifier deleted", evaluate(delete_verifier))

    def delete_release_workflow(workflows: dict[str, str]) -> None:
        workflows.pop("release.yml")

    expect_rejected("release workflow deleted", evaluate(None, delete_release_workflow))

    def remove_gate_workflow(workflows: dict[str, str]) -> None:
        workflows.pop("launch-readiness.yml")

    expect_rejected("gate workflow deleted", evaluate(None, remove_gate_workflow))

    # 2. Semantic-verifier bypass shapes. Each of these keeps every previous
    #    statement and every historically required marker string present in the
    #    file — an "is the old code still in there?" heuristic accepts them all,
    #    because the retained code is merely unreachable. They must be refused
    #    on bytes alone.
    def prepend_unconditional_pass(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = files[SLOT_FILENAMES["checker"]].replace(
            "def compute_verdict(unknown_reasons, records):\n",
            'def compute_verdict(unknown_reasons, records):\n    return "PASS"\n',
        )

    expect_rejected(
        "early return PASS above the retained body",
        evaluate(prepend_unconditional_pass),
    )

    def prepend_zero_return(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = files[SLOT_FILENAMES["checker"]].replace(
            "def run_verify(argv):\n",
            "def run_verify(argv):\n    return 0\n",
        )

    expect_rejected(
        "early return 0 above the retained body", evaluate(prepend_zero_return)
    )

    def prepend_sys_exit(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = files[SLOT_FILENAMES["checker"]].replace(
            "def main(argv=None):\n",
            "def main(argv=None):\n    sys.exit(0)\n",
        )

    expect_rejected(
        "early sys.exit(0) above the retained body", evaluate(prepend_sys_exit)
    )

    def prepend_unconditional_branch(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = files[SLOT_FILENAMES["checker"]].replace(
            "def verify_errors(claim, evaluation):\n",
            "def verify_errors(claim, evaluation):\n    if True:\n        return []\n",
        )

    expect_rejected(
        "always-true branch above the retained body",
        evaluate(prepend_unconditional_branch),
    )

    def append_unreachable_old_body(files: dict[str, str]) -> None:
        source = files[SLOT_FILENAMES["checker"]]
        files[SLOT_FILENAMES["checker"]] = source.replace(
            "def run_verify(argv):\n"
            "    errors = verify_errors(argv, argv)\n"
            "    return 1 if errors else 0\n",
            "def run_verify(argv):\n"
            "    return 0\n"
            "    errors = verify_errors(argv, argv)\n"
            "    return 1 if errors else 0\n",
        )

    expect_rejected(
        "unreachable old body after return 0", evaluate(append_unreachable_old_body)
    )

    def module_level_short_circuit(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = (
            "import sys\nsys.exit(0)\n" + files[SLOT_FILENAMES["checker"]]
        )

    expect_rejected("module-level short circuit", evaluate(module_level_short_circuit))

    def new_import(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = (
            "import subprocess\n" + files[SLOT_FILENAMES["checker"]]
        )

    expect_rejected("checker grows a process dependency", evaluate(new_import))

    def whitespace_only_checker_edit(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["checker"]] = files[SLOT_FILENAMES["checker"]] + "\n"

    expect_rejected(
        "whitespace-only checker edit", evaluate(whitespace_only_checker_edit)
    )

    # 3. YAML rewrites that retain every frozen substring.
    def disable_readiness_job(workflows: dict[str, str]) -> None:
        workflows["launch-readiness.yml"] = workflows["launch-readiness.yml"].replace(
            "    runs-on: ubuntu-latest\n",
            "    if: false\n    runs-on: ubuntu-latest\n",
            1,
        )

    expect_rejected(
        "gate job disabled with every frozen line retained",
        evaluate(None, disable_readiness_job),
    )

    def neutralize_verify_step(workflows: dict[str, str]) -> None:
        # Keeps the frozen `run:` line verbatim and adds a step-level guard.
        workflows["launch-readiness.yml"] = workflows["launch-readiness.yml"].replace(
            "      - name: Verify live launch verdict\n",
            "      - name: Verify live launch verdict\n        if: false\n",
        )

    expect_rejected(
        "live verdict step guarded off", evaluate(None, neutralize_verify_step)
    )

    def continue_on_error_release_gate(workflows: dict[str, str]) -> None:
        workflows["release.yml"] = workflows["release.yml"].replace(
            "  validate-launch-readiness:\n    name: Validate launch readiness\n",
            "  validate-launch-readiness:\n    continue-on-error: true\n"
            "    name: Validate launch readiness\n",
        )

    expect_rejected(
        "release gate made non-blocking", evaluate(None, continue_on_error_release_gate)
    )

    def sever_release_needs(workflows: dict[str, str]) -> None:
        workflows["release.yml"] = workflows["release.yml"].replace(
            "    needs:\n      - validate-release-version\n"
            "      - validate-launch-readiness\n",
            "    needs: validate-release-version\n",
        )

    expect_rejected("release gate unbound", evaluate(None, sever_release_needs))

    def leak_secret(workflows: dict[str, str]) -> None:
        workflows["launch-readiness.yml"] = workflows["launch-readiness.yml"].replace(
            "LAUNCH_ADVISORY_READ_TOKEN: ${{ (github.event_name != 'pull_request'"
            " && github.event_name != 'merge_group') && "
            "secrets.LAUNCH_ADVISORY_READ_TOKEN || '' }}",
            "LAUNCH_ADVISORY_READ_TOKEN: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}",
        )

    expect_rejected("advisory token exposed to candidates", evaluate(None, leak_secret))

    def rename_gate_job(workflows: dict[str, str]) -> None:
        workflows["launch-readiness.yml"] = workflows["launch-readiness.yml"].replace(
            "    name: Launch Readiness Gate", "    name: Launch Readiness Advisory"
        )

    expect_rejected("required check renamed", evaluate(None, rename_gate_job))

    def weaken_integrity_workflow(workflows: dict[str, str]) -> None:
        workflows["launch-integrity.yml"] = workflows["launch-integrity.yml"].replace(
            "  pull_request_target:\n    branches:\n      - main\n",
            "  pull_request_target:\n    paths:\n      - docs/**\n",
        )

    expect_rejected("integrity anchor edited", evaluate(None, weaken_integrity_workflow))

    def comment_only_integrity_edit(workflows: dict[str, str]) -> None:
        workflows["launch-integrity.yml"] = (
            "# harmless-looking comment\n" + workflows["launch-integrity.yml"]
        )

    expect_rejected(
        "comment-only integrity anchor edit", evaluate(None, comment_only_integrity_edit)
    )

    # 4. Workflows a candidate adds are still scanned.
    def duplicate_check_name(workflows: dict[str, str]) -> None:
        workflows["shadow.yml"] = (
            "name: Shadow\n\non:\n  pull_request:\n\njobs:\n"
            "  shadow:\n    name: Launch Readiness Integrity\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
        )

    expect_rejected("check-run producer spoofed", evaluate(None, duplicate_check_name))

    def new_workflow_reads_token(workflows: dict[str, str]) -> None:
        workflows["exfil.yml"] = (
            "name: Exfil\n\non:\n  pull_request:\n\njobs:\n  go:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - env:\n"
            "          T: ${{ secrets.LAUNCH_ADVISORY_READ_TOKEN }}\n"
            "        run: echo ok\n"
        )

    expect_rejected(
        "candidate workflow reads the advisory token",
        evaluate(None, new_workflow_reads_token),
    )

    def new_workflow_reads_token_with_bracket_syntax(
        workflows: dict[str, str],
    ) -> None:
        workflows["exfil-bracket.yml"] = (
            "name: Exfil bracket\n\non:\n  pull_request:\n\njobs:\n  go:\n"
            "    runs-on: ubuntu-latest\n    steps:\n"
            "      - env:\n"
            "          T: ${{ secrets['LAUNCH_ADVISORY_READ_TOKEN'] }}\n"
            "        run: echo ok\n"
        )

    expect_rejected(
        "candidate workflow reads the advisory token with bracket syntax",
        evaluate(None, new_workflow_reads_token_with_bracket_syntax),
    )

    # 5. Trusted-base extraction must fail closed.
    def base_loses_checker(files: dict[str, str]) -> None:
        files.pop(SLOT_FILENAMES["checker"])

    expect_rejected(
        "trusted base missing a required anchor",
        evaluate(mutate_base_files=base_loses_checker),
    )

    def base_loses_release_workflow(workflows: dict[str, str]) -> None:
        workflows.pop("release.yml")

    expect_rejected(
        "trusted base missing an anchored workflow",
        evaluate(mutate_base_workflows=base_loses_release_workflow),
    )

    def base_anchor_emptied(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["verifier"]] = "   \n"

    expect_rejected(
        "trusted base anchor is empty", evaluate(mutate_base_files=base_anchor_emptied)
    )

    # 6. Optional advisory-trust anchors (issue #3802) in both merge orders.
    expect_clean(
        "advisory lane absent from both roots",
        evaluate(adopt_advisory_base=False, adopt_advisory_candidate=False),
    )
    expect_clean(
        "advisory lane adopted on an un-adopted base",
        evaluate(adopt_advisory_base=False, adopt_advisory_candidate=True),
    )
    expect_clean(
        "advisory lane present and unchanged",
        evaluate(adopt_advisory_base=True, adopt_advisory_candidate=True),
    )

    def edit_advisory_verifier(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["advisory_verifier"]] = "# rewritten\n"

    expect_rejected(
        "advisory verifier edited once anchored",
        evaluate(
            edit_advisory_verifier,
            adopt_advisory_base=True,
            adopt_advisory_candidate=True,
        ),
    )

    def edit_advisory_workflow(workflows: dict[str, str]) -> None:
        workflows["launch-advisory-trust.yml"] = (
            "# rewritten\n" + workflows["launch-advisory-trust.yml"]
        )

    expect_rejected(
        "advisory workflow edited once anchored",
        evaluate(
            None,
            edit_advisory_workflow,
            adopt_advisory_base=True,
            adopt_advisory_candidate=True,
        ),
    )

    expect_rejected(
        "advisory lane deleted once anchored",
        evaluate(adopt_advisory_base=True, adopt_advisory_candidate=False),
    )

    def drop_advisory_owner(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["codeowners"]] = "\n".join(
            line
            for line in files[SLOT_FILENAMES["codeowners"]].splitlines()
            if not line.startswith("/.github/scripts/verify_launch_advisory_trust.py")
        ) + "\n"

    expect_rejected(
        "advisory owner removed once the file exists",
        evaluate(
            drop_advisory_owner,
            adopt_advisory_base=True,
            adopt_advisory_candidate=True,
        ),
    )

    # 7. Policy, exemption, and document downgrades (candidate-editable data).
    def state_machine_downgrade(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["state_machine"]["in_flight"] = "cleared"
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("state machine downgraded", evaluate(state_machine_downgrade))

    def tier_downgrade(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["tiers"]["ga"]["blocking_severities"] = ["critical"]
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("GA severity tier narrowed", evaluate(tier_downgrade))

    def stale_window(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["private_advisories"]["trusted_fallback"]["max_age_seconds"] = 604801
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("advisory freshness widened", evaluate(stale_window))

    def checked_in_count(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["private_advisories"]["opaque_input"] = {"redacted_blocking_count": 0}
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("checked-in advisory evidence", evaluate(checked_in_count))

    def label_rename(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["labels"]["launch_blocker"] = "launch-blocker-unused"
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("blocker label renamed", evaluate(label_rename))

    def never_emit_narrowed(files: dict[str, str]) -> None:
        policy = json.loads(files[SLOT_FILENAMES["policy"]])
        policy["private_advisories"]["never_emit_fields"] = ["summary"]
        files[SLOT_FILENAMES["policy"]] = json.dumps(policy, indent=2)

    expect_rejected("never_emit narrowed", evaluate(never_emit_narrowed))

    def open_ended_exemption(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["exemptions"]] = json.dumps(
            {
                "exemptions_version": "1",
                "exemptions": [
                    {
                        "id": "ex-1",
                        "issue": 1,
                        "launch_tiers": ["ga"],
                        "owner": "o",
                        "approver": "a",
                        "rationale": "r",
                        "compensating_control": "c",
                        "approved_at": "2026-08-01T00:00:00Z",
                        "expires_at": "2026-08-01T00:00:00Z",
                    }
                ],
            },
            indent=2,
        )

    expect_rejected("exemption never expires", evaluate(open_ended_exemption))

    # 7a. Private-advisory policy weakening. The checker is byte-frozen, but the
    #     policy it consumes is candidate-editable, so every narrowing of what it
    #     will block — and every redirection of where it reads evidence — has to
    #     be refused here.
    expect_rejected(
        "GA private-advisory severities narrowed",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"][
                    "blocking_severities_by_tier"
                ].__setitem__("ga", ["critical", "high"])
            )
        ),
    )
    expect_rejected(
        "private-advisory tier set no longer matches the policy tiers",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"][
                    "blocking_severities_by_tier"
                ].__setitem__("nightly", ["critical"])
            )
        ),
    )
    expect_rejected(
        "unknown private-advisory severity",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"][
                    "blocking_severities_by_tier"
                ].__setitem__("beta", ["critical", "high", "catastrophic"])
            )
        ),
    )
    expect_rejected(
        "advisory blocking and closed states overlap",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"]["closed_states"].append(
                    "draft"
                )
            )
        ),
    )
    expect_rejected(
        "advisory state sets no longer cover every known state",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"].__setitem__(
                    "closed_states", ["published", "closed"]
                )
            )
        ),
    )
    expect_rejected(
        "advisory credential lookup redirected",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"]["live_api"].__setitem__(
                    "token_env", "ATTACKER_SUPPLIED_TOKEN"
                )
            )
        ),
    )
    expect_rejected(
        "advisory credential name is not an environment variable",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"]["live_api"].__setitem__(
                    "token_env", "launch advisory token"
                )
            )
        ),
    )
    expect_rejected(
        "fallback count variable redirected",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"][
                    "trusted_fallback"
                ].__setitem__("count_variable", "SOME_UNRELATED_REPO_VARIABLE")
            )
        ),
    )
    expect_rejected(
        "fallback as-of variable redirected",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"][
                    "trusted_fallback"
                ].__setitem__("as_of_variable", "SOME_UNRELATED_REPO_VARIABLE")
            )
        ),
    )
    expect_rejected(
        "fallback count and as-of variables collapsed onto one name",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"][
                    "trusted_fallback"
                ].__setitem__("as_of_variable", "LAUNCH_PRIVATE_BLOCKER_COUNT")
            )
        ),
    )
    expect_rejected(
        "fallback variable name is not an environment variable",
        evaluate(
            _with_policy(
                lambda policy: policy["private_advisories"][
                    "trusted_fallback"
                ].__setitem__("as_of_variable", "launch.private.advisory.as-of")
            )
        ),
    )

    # 7b. Remaining policy schema parity with the frozen production checker.
    expect_rejected(
        "evaluated repository redirected",
        evaluate(_with_policy(lambda policy: policy.__setitem__("repository", "attacker/fork"))),
    )
    expect_rejected(
        "repository is not an owner/name identity",
        evaluate(_with_policy(lambda policy: policy.__setitem__("repository", "ferrum-edge"))),
    )
    expect_rejected(
        "policy version emptied",
        evaluate(_with_policy(lambda policy: policy.__setitem__("policy_version", "  "))),
    )
    expect_rejected(
        "classification version emptied",
        evaluate(
            _with_policy(lambda policy: policy.__setitem__("classification_version", ""))
        ),
    )
    expect_rejected(
        "default launch tier is not a defined tier",
        evaluate(
            _with_policy(lambda policy: policy.__setitem__("default_launch_tier", "nightly"))
        ),
    )
    expect_rejected(
        "unknown severity in a policy tier",
        evaluate(
            _with_policy(
                lambda policy: policy["tiers"]["beta"].__setitem__(
                    "blocking_severities", ["critical", "high", "catastrophic"]
                )
            )
        ),
    )
    expect_rejected(
        "severity label table dropped a severity",
        evaluate(
            _with_policy(lambda policy: policy["labels"]["severity"].pop("medium"))
        ),
    )
    expect_rejected(
        "two severities collapsed onto one label",
        evaluate(
            _with_policy(
                lambda policy: policy["labels"]["severity"].__setitem__(
                    "medium", "severity:high"
                )
            )
        ),
    )
    expect_rejected(
        "tracked blocker loses its note",
        evaluate(_with_policy(lambda policy: policy["tracked_blockers"][0].pop("note"))),
    )

    def base_policy_unparsable(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["policy"]] = "{ not json\n"

    expect_rejected(
        "trusted base policy is unreadable",
        evaluate(mutate_base_files=base_policy_unparsable),
    )

    # 7c. Exemption schema parity. An exemption is the one mechanism that clears
    #     a real blocker, so it is held to the production checker's schema.
    expect_clean(
        "well-formed exemption", evaluate(_with_exemptions(_exemption()))
    )
    expect_rejected(
        "exemption owner is not an accountable principal",
        evaluate(_with_exemptions(_exemption(owner="not a github login!"))),
    )
    expect_rejected(
        "exemption approver is not an accountable principal",
        evaluate(_with_exemptions(_exemption(approver="team/security"))),
    )
    expect_rejected(
        "exemption issue is not positive",
        evaluate(_with_exemptions(_exemption(issue=0))),
    )
    expect_rejected(
        "exemption issue is a boolean",
        evaluate(_with_exemptions(_exemption(issue=True))),
    )
    expect_rejected(
        "exemption names an undefined launch tier",
        evaluate(_with_exemptions(_exemption(launch_tiers=["nightly"]))),
    )
    expect_rejected(
        "exemption rationale is blank",
        evaluate(_with_exemptions(_exemption(rationale="   "))),
    )
    expect_rejected(
        "exemption compensating control is empty",
        evaluate(_with_exemptions(_exemption(compensating_control=""))),
    )
    expect_rejected(
        "exemption ids are duplicated",
        evaluate(_with_exemptions(_exemption(), _exemption(issue=4243))),
    )

    # An offset-bearing window whose lexical order is the reverse of its
    # chronological order. `+09:00` sorts last but happens first: comparing the
    # strings accepts an exemption that expired eight hours before it was
    # approved, so the comparison is made on instants.
    expect_rejected(
        "exemption expiry precedes approval across timezone offsets",
        evaluate(
            _with_exemptions(
                _exemption(
                    approved_at="2026-08-01T23:00:00Z",
                    expires_at="2026-08-02T00:00:00+09:00",
                )
            )
        ),
    )
    # The mirror image: lexically inverted but chronologically valid (approved
    # 2026-07-31T23:30Z, expires 2026-08-01T00:00Z). A lexical comparison would
    # reject this legitimate exemption.
    expect_clean(
        "exemption window valid across timezone offsets",
        evaluate(
            _with_exemptions(
                _exemption(
                    approved_at="2026-08-01T00:30:00+01:00",
                    expires_at="2026-08-01T00:00:00Z",
                )
            )
        ),
    )

    def marker_removed(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["document"]] = files[SLOT_FILENAMES["document"]].replace(
            "<!-- launch-readiness:historical -->\n", ""
        )

    expect_rejected("document marker removed", evaluate(marker_removed))

    # 8. Ownership evasion.
    def drop_owner(files: dict[str, str]) -> None:
        files[SLOT_FILENAMES["codeowners"]] = "\n".join(
            line
            for line in files[SLOT_FILENAMES["codeowners"]].splitlines()
            if not line.startswith("/scripts/check_launch_readiness.py")
        ) + "\n"

    expect_rejected("governance owner removed", evaluate(drop_owner))

    for failure in failures:
        print(f"self-test failure: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("launch-integrity self-test: PASS")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch readiness integrity verifier")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--base-dir", default="")
    parser.add_argument("--candidate-dir", default="")
    args = parser.parse_args(argv)

    if args.self_test:
        code = run_self_test()
        if code != 0:
            return code
    if not args.base_dir and not args.candidate_dir:
        if args.self_test:
            return 0
        print("error: --base-dir and --candidate-dir are required", file=sys.stderr)
        return 2
    if not args.base_dir or not args.candidate_dir:
        print("error: both --base-dir and --candidate-dir are required", file=sys.stderr)
        return 2

    try:
        base = Root("trusted base", Path(args.base_dir))
        candidate = Root("candidate", Path(args.candidate_dir))
        errors = verify(base, candidate)
    except IntegrityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for error in errors:
        print(f"::error::launch integrity: {error}", file=sys.stderr)
    if errors:
        print(f"launch integrity: {len(errors)} finding(s)", file=sys.stderr)
        return 1
    print("launch integrity: the candidate preserves the launch governance contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
