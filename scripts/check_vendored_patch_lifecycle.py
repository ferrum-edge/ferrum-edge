#!/usr/bin/env python3
"""Validate vendored-patch lifecycle inventory parity and upstream status.

The canonical inventory lives in docs/vendored-patch-lifecycle.json. CI runs the
default parity mode on every PR (dependency-audit job) and the weekly
dependency-audit workflow runs --upstream-status after parity passes.

Parity mode fails closed when the lifecycle contract drifts from:
  - root Cargo.toml [patch.crates-io]
  - tests/performance/mesh/Cargo.toml mirrored [patch.crates-io]
  - vendor/*-ferrum-patched directories (vendor_path is derived from crate and
    vendored_version, so a version typo cannot hide behind an existing directory)
  - scripts/check_vendored_patch_status.sh safe wrapper delegation
  - docs/dependency-policy.md inventory Lifecycle ID set, docs-path fragments,
    and the upstream PR/issue numbers the weekly poll watches
  - per-patch README.md paths and dated deliberate-fork reaffirmations

Every governed surface lives on a path that .github/scripts/pr_ci_plan.py keeps
on full CI, because the `dependency-audit` job that runs this checker is required
to stay behind `mode == 'full'`.

Upstream mode queries filed upstream PRs via the GitHub REST API and reports deliberate forks
that still need filing or dated owner reaffirmation before the first stable
release checkpoint (docs/dependency-policy.md).

Every normal invocation runs synthetic self-tests first, then repository parity.
--self-test runs only the synthetic fixtures and exits (no network, no repository
mutation). --upstream-status self-tests, then parity, then network reporting.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LIFECYCLE_PATH = ROOT / "docs" / "vendored-patch-lifecycle.json"
POLICY_PATH = ROOT / "docs" / "dependency-policy.md"
ROOT_CARGO = ROOT / "Cargo.toml"
MESH_PERF_CARGO = ROOT / "tests" / "performance" / "mesh" / "Cargo.toml"
PATCH_STATUS_SCRIPT = ROOT / "scripts" / "check_vendored_patch_status.sh"
VENDOR_ROOT = ROOT / "vendor"

COMPATIBLE_RELEASE_STATUSES = frozenset(
    {"not_started", "in_progress", "passed", "failed", "blocked"}
)
UPSTREAM_FILINGS = frozenset({"filed", "deliberate_fork_unfiled"})
REQUIRED_PATCH_STRING_FIELDS = (
    "id",
    "label",
    "crate",
    "vendored_version",
    "vendor_path",
    "docs_path",
    "owner",
    "reason",
)
REAFFIRMATION_RE = re.compile(
    r"re-affirmed\s+(\d{4}-\d{2}-\d{2})\s+by\s+([^:\n]+):\s*(.+)",
    re.IGNORECASE,
)
INVENTORY_HEADER = (
    "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | "
    "Owner | Reason | Removal trigger | Docs |"
)
GITHUB_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
# Crate names and versions are interpolated into crates.io URLs and into the
# expected vendor directory name, so keep them to the registry's own alphabet.
CRATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
CRATE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")
DOCS_PATH_RE = re.compile(
    r"^docs/upstream-[A-Za-z0-9][A-Za-z0-9._-]*-patches"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*/?$"
)
# Upstream-reported strings are echoed into the Actions log, where a stray
# `::error::` would forge a workflow command. Only print recognizable versions.
CRATES_IO_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$")
# api.github.com / crates.io responses are small; refuse to buffer more.
MAX_RESPONSE_BYTES = 1 << 20
WRAPPER_SET_LINES = frozenset({"set -uo pipefail", "set -euo pipefail"})
WRAPPER_DIR_ASSIGN = 'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"'
WRAPPER_EXEC = (
    'exec python3 "$SCRIPT_DIR/check_vendored_patch_lifecycle.py" --upstream-status'
)
USER_AGENT = "ferrum-edge-dependency-audit (github.com/ferrum-edge/ferrum-edge)"
MAX_MERGED_RELEASE_HOLD_DAYS = 30


def merged_release_hold_shape_errors(patch: dict[str, Any]) -> list[str]:
    retirement = patch.get("retirement")
    if not isinstance(retirement, dict):
        return []  # The enclosing shape validator reports invalid retirement.
    hold = retirement.get("merged_release_hold")
    if hold is None:
        return []
    prefix = f"{patch.get('id')}.retirement.merged_release_hold"
    if not isinstance(hold, dict):
        return [f"{prefix}: must be an object"]
    errors: list[str] = []
    fields = {"reviewed_on", "expires_on", "owner", "latest_release", "merge_commit", "reason", "evidence"}
    if set(hold) != fields:
        errors.append(f"{prefix}: must contain exactly {sorted(fields)}")
    for field in fields - {"evidence"}:
        _require_nonempty_str(hold.get(field), f"{prefix}.{field}", errors)
    _require_nonempty_str_list(hold.get("evidence"), f"{prefix}.evidence", errors)
    if hold.get("owner") != patch.get("owner"):
        errors.append(f"{prefix}.owner: must match the patch owner")
    if not re.fullmatch(r"[0-9a-f]{40}", str(hold.get("merge_commit", ""))):
        errors.append(f"{prefix}.merge_commit: must be a full commit SHA")
    if not CRATES_IO_VERSION_RE.fullmatch(str(hold.get("latest_release", ""))):
        errors.append(f"{prefix}.latest_release: must be a registry version")
    upstream = patch.get("upstream")
    if not isinstance(upstream, dict) or upstream.get("filing") != "filed":
        errors.append(f"{prefix}: requires a filed upstream PR")
    compatible = retirement.get("compatible_release_test")
    if not isinstance(compatible, dict) or compatible.get("status") != "blocked":
        errors.append(f"{prefix}: requires compatible_release_test.status=blocked")
    try:
        if any(not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(hold.get(field)))
               for field in ("reviewed_on", "expires_on")):
            raise ValueError("non-calendar review date")
        reviewed = date.fromisoformat(hold["reviewed_on"])
        expires = date.fromisoformat(hold["expires_on"])
        if not 0 < (expires - reviewed).days <= MAX_MERGED_RELEASE_HOLD_DAYS:
            errors.append(f"{prefix}: review window must be 1..{MAX_MERGED_RELEASE_HOLD_DAYS} days")
    except (KeyError, TypeError, ValueError):
        errors.append(f"{prefix}: review dates must be ISO calendar dates")
    return errors


def merged_release_hold_errors(
    patch: dict[str, Any], latest_release: str | None, *, today: date | None = None
) -> list[str]:
    """A reviewed unreleased fix remains visible and must be reviewed again soon."""
    hold = patch["retirement"].get("merged_release_hold")
    if hold is None:
        return ["no reviewed release hold"]
    errors = merged_release_hold_shape_errors(patch)
    if errors:
        return errors
    today = today or datetime.now(timezone.utc).date()
    if today < date.fromisoformat(hold["reviewed_on"]):
        errors.append("release hold review is in the future")
    if today >= date.fromisoformat(hold["expires_on"]):
        errors.append("release hold expired")
    if latest_release is None:
        errors.append("latest stable release could not be confirmed")
    elif latest_release != hold["latest_release"]:
        errors.append("latest stable release changed; repeat compatibility review")
    return errors


def load_lifecycle() -> Any:
    """Decode the lifecycle inventory. Structural checks live in validate_lifecycle_shape."""
    with LIFECYCLE_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def parse_patch_crates_io(cargo_path: Path) -> dict[str, str]:
    return parse_patch_crates_io_text(cargo_path.read_text(encoding="utf-8"))


def parse_patch_crates_io_text(text: str) -> dict[str, str]:
    """Return crate -> vendor path for each [patch.crates-io] entry."""
    in_block = False
    patches: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[patch.crates-io]":
            in_block = True
            continue
        if in_block:
            if stripped.startswith("[") and stripped.endswith("]"):
                break
            match = re.match(
                r'^(\w[\w-]*)\s*=\s*\{\s*path\s*=\s*"([^"]+)"\s*\}', stripped
            )
            if match:
                patches[match.group(1)] = match.group(2)
    return patches


def readme_candidates(docs_path: str) -> list[Path]:
    rel = docs_path.rstrip("/")
    return [ROOT / rel / "README.md", ROOT / rel / "readme.md"]


def find_readme(docs_path: str) -> Path | None:
    for candidate in readme_candidates(docs_path):
        if candidate.is_file():
            return candidate
    return None


def parse_readme_reaffirmation(readme_path: Path) -> dict[str, str] | None:
    return find_reaffirmation(
        readme_path.read_text(encoding="utf-8", errors="replace")
    )


def find_reaffirmation(text: str) -> dict[str, str] | None:
    """Extract the first `re-affirmed YYYY-MM-DD by <owner>: <reason>` record."""
    match = REAFFIRMATION_RE.search(text)
    if not match:
        return None
    return {
        "date": match.group(1),
        "owner": match.group(2).strip(),
        "reason": match.group(3).strip(),
    }


def reaffirmation_parity_errors(
    pid: str,
    filing: Any,
    lifecycle_reaffirmation: Any,
    readme_reaffirmation: dict[str, str] | None,
) -> list[str]:
    """Pair the lifecycle reaffirmation record with the per-patch README text.

    A dated reaffirmation is a deliberate-fork record (docs/dependency-policy.md
    "Deliberate fork policy and SLA"), so only an unfiled fork may carry one.
    Patches deliberately share a README — the two lossless-takeover patches and
    the frame-limit-origin fork all point at
    docs/upstream-tungstenite-patches/README.md — so reaffirming the fork there
    must not force a fabricated record onto the filed patches beside it.
    """
    errors: list[str] = []
    unfiled = filing == "deliberate_fork_unfiled"
    if lifecycle_reaffirmation is not None and not unfiled:
        errors.append(
            f"{pid}: reaffirmation is a deliberate-fork record; upstream.filing "
            f"{filing!r} must not carry one"
        )
        return errors
    if lifecycle_reaffirmation is None:
        if unfiled and readme_reaffirmation is not None:
            errors.append(
                f"{pid}: README contains dated reaffirmation but "
                "lifecycle.reaffirmation is null"
            )
        return errors
    if readme_reaffirmation is None:
        errors.append(
            f"{pid}: lifecycle.reaffirmation set but README lacks matching dated "
            "reaffirmation"
        )
        return errors
    if isinstance(lifecycle_reaffirmation, dict):
        for key in ("date", "owner", "reason"):
            expected = str(lifecycle_reaffirmation.get(key, "")).strip()
            if expected != readme_reaffirmation[key]:
                errors.append(
                    f"{pid}: lifecycle reaffirmation {key!r} does not match README"
                )
    return errors


def vendor_patch_dirs() -> set[str]:
    if not VENDOR_ROOT.is_dir():
        return set()
    return {
        f"vendor/{entry.name}"
        for entry in VENDOR_ROOT.iterdir()
        if entry.is_dir() and entry.name.endswith("-ferrum-patched")
    }


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_github_repo(value: Any) -> bool:
    """owner/repo with no dot-only segment, so it cannot traverse the API path."""
    if not _is_nonempty_str(value) or not GITHUB_REPO_RE.fullmatch(str(value)):
        return False
    return all(segment.strip(".") for segment in str(value).split("/"))


def _require_nonempty_str(value: Any, path: str, errors: list[str]) -> None:
    if not _is_nonempty_str(value):
        errors.append(f"{path}: must be a non-empty string")


def _require_nonempty_str_list(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{path}: must be a non-empty list")
        return
    for index, item in enumerate(value):
        if not _is_nonempty_str(item):
            errors.append(f"{path}[{index}]: must be a non-empty string")


def validate_lifecycle_shape(data: Any) -> list[str]:
    """Fail-closed structural validation for the lifecycle contract."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["lifecycle inventory must be a JSON object"]

    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    patches = data.get("patches")
    if not isinstance(patches, list) or not patches:
        errors.append("patches must be a non-empty list")
        patches = []

    for index, patch in enumerate(patches):
        if not isinstance(patch, dict):
            errors.append(f"patches[{index}]: must be an object")
            continue

        pid = patch.get("id")
        prefix = pid.strip() if _is_nonempty_str(pid) else f"patches[{index}]"

        for field in REQUIRED_PATCH_STRING_FIELDS:
            _require_nonempty_str(patch.get(field), f"{prefix}.{field}", errors)

        crate = patch.get("crate")
        version = patch.get("vendored_version")
        vendor_path = patch.get("vendor_path")
        docs_path = patch.get("docs_path")
        if _is_nonempty_str(crate) and not CRATE_NAME_RE.fullmatch(str(crate)):
            errors.append(f"{prefix}.crate: must be a registry crate name")
            crate = None
        if _is_nonempty_str(version) and not CRATE_VERSION_RE.fullmatch(str(version)):
            errors.append(f"{prefix}.vendored_version: must be a registry version")
            version = None
        # vendor_path is a derived identity, so a version typo cannot hide behind
        # a directory that happens to exist.
        if all(_is_nonempty_str(value) for value in (crate, version, vendor_path)):
            expected_vendor_path = f"vendor/{crate}-{version}-ferrum-patched"
            if vendor_path != expected_vendor_path:
                errors.append(
                    f"{prefix}.vendor_path: must be {expected_vendor_path!r} for "
                    f"crate {crate!r} at vendored version {version!r}"
                )
        if _is_nonempty_str(docs_path) and not DOCS_PATH_RE.fullmatch(str(docs_path)):
            errors.append(
                f"{prefix}.docs_path: must be a repository-relative "
                "docs/upstream-<dependency>-patches path"
            )

        upstream = patch.get("upstream")
        if not isinstance(upstream, dict):
            errors.append(f"{prefix}.upstream: must be an object")
        else:
            filing = upstream.get("filing")
            if filing not in UPSTREAM_FILINGS:
                errors.append(f"{prefix}: unknown upstream.filing {filing!r}")

            repo = upstream.get("github_repo")
            if not _is_github_repo(repo):
                errors.append(
                    f"{prefix}.upstream.github_repo: must match owner/repo form"
                )

            pr_number = upstream.get("pr_number")
            if filing == "filed":
                if not _is_positive_int(pr_number):
                    errors.append(
                        f"{prefix}: filing=filed requires a positive integer pr_number"
                    )
            elif filing == "deliberate_fork_unfiled":
                if pr_number is not None:
                    errors.append(
                        f"{prefix}: filing=deliberate_fork_unfiled must not carry a pr_number"
                    )

            issue_number = upstream.get("issue_number")
            if issue_number is not None and not _is_positive_int(issue_number):
                errors.append(
                    f"{prefix}.upstream.issue_number: must be a positive integer when present"
                )

            fork_ref = upstream.get("fork_ref")
            if fork_ref is not None and not _is_nonempty_str(fork_ref):
                errors.append(
                    f"{prefix}.upstream.fork_ref: must be null or a non-empty string"
                )

        reaffirmation = patch.get("reaffirmation")
        if reaffirmation is not None:
            if not isinstance(reaffirmation, dict):
                errors.append(f"{prefix}.reaffirmation: must be null or an object")
            else:
                for field in ("date", "owner", "reason"):
                    _require_nonempty_str(
                        reaffirmation.get(field),
                        f"{prefix}.reaffirmation.{field}",
                        errors,
                    )

        _require_nonempty_str_list(
            patch.get("regression_tests"), f"{prefix}.regression_tests", errors
        )

        retirement = patch.get("retirement")
        if not isinstance(retirement, dict):
            errors.append(f"{prefix}.retirement: must be an object")
        else:
            _require_nonempty_str(
                retirement.get("trigger"), f"{prefix}.retirement.trigger", errors
            )
            co_group = retirement.get("co_retirement_group")
            if co_group is not None and not _is_nonempty_str(co_group):
                errors.append(
                    f"{prefix}.retirement.co_retirement_group: must be null or a "
                    "non-empty string"
                )
            compatible = retirement.get("compatible_release_test")
            if not isinstance(compatible, dict):
                errors.append(
                    f"{prefix}.retirement.compatible_release_test: must be an object"
                )
            else:
                status = compatible.get("status")
                if status not in COMPATIBLE_RELEASE_STATUSES:
                    errors.append(
                        f"{prefix}: invalid compatible_release_test.status {status!r}"
                    )
                notes = compatible.get("notes")
                if notes is not None and not isinstance(notes, str):
                    errors.append(
                        f"{prefix}.retirement.compatible_release_test.notes: "
                        "must be null or a string"
                    )
            errors.extend(merged_release_hold_shape_errors(patch))

    checklist = data.get("retirement_checklist")
    _require_nonempty_str_list(checklist, "retirement_checklist", errors)

    declared_groups = data.get("co_retirement_groups", [])
    if not isinstance(declared_groups, list):
        errors.append("co_retirement_groups must be a list when present")
        declared_groups = []

    seen_group_ids: set[str] = set()
    for group_index, group in enumerate(declared_groups):
        if not isinstance(group, dict):
            errors.append(f"co_retirement_groups[{group_index}]: must be an object")
            continue
        gid = group.get("id")
        if not _is_nonempty_str(gid):
            errors.append(f"co_retirement_groups[{group_index}]: id must be a non-empty string")
            continue
        if gid in seen_group_ids:
            errors.append(f"duplicate co_retirement_group id {gid!r}")
        else:
            seen_group_ids.add(gid)

        members = group.get("patch_ids")
        if not isinstance(members, list) or not members:
            errors.append(
                f"co_retirement_groups.{gid}: patch_ids must be a non-empty list"
            )
            continue
        member_ok = True
        for member_index, member in enumerate(members):
            if not _is_nonempty_str(member):
                errors.append(
                    f"co_retirement_groups.{gid}.patch_ids[{member_index}]: "
                    "must be a non-empty string"
                )
                member_ok = False
        if not member_ok:
            continue
        if len(members) != len(set(members)):
            errors.append(
                f"co_retirement_groups.{gid}: duplicate patch id in patch_ids"
            )

    return errors


def executable_wrapper_lines(script_text: str) -> list[str]:
    lines: list[str] = []
    for raw in script_text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(stripped)
    return lines


def wrapper_delegation_errors(script_text: str) -> list[str]:
    """Require the executable body to be exactly set + SCRIPT_DIR + quoted exec."""
    errors: list[str] = []
    lines = executable_wrapper_lines(script_text)
    if not lines:
        return ["scripts/check_vendored_patch_status.sh has no executable lines"]

    exact = (
        len(lines) == 3
        and lines[0] in WRAPPER_SET_LINES
        and lines[1] == WRAPPER_DIR_ASSIGN
        and lines[2] == WRAPPER_EXEC
    )
    if exact:
        return errors

    if lines[0] not in WRAPPER_SET_LINES:
        errors.append(
            "scripts/check_vendored_patch_status.sh must enable nounset/pipefail "
            "(set -uo pipefail or set -euo pipefail) as the first executable line"
        )
    if len(lines) < 2 or lines[1] != WRAPPER_DIR_ASSIGN:
        errors.append(
            "scripts/check_vendored_patch_status.sh must assign SCRIPT_DIR from "
            'the wrapper path via: SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"'
        )
    if len(lines) < 3 or lines[2] != WRAPPER_EXEC:
        errors.append(
            "scripts/check_vendored_patch_status.sh must delegate with: "
            'exec python3 "$SCRIPT_DIR/check_vendored_patch_lifecycle.py" --upstream-status'
        )
    if len(lines) != 3:
        errors.append(
            "scripts/check_vendored_patch_status.sh executable body must be exactly "
            "the accepted set line, SCRIPT_DIR assignment, and quoted exec "
            "(no extra, reordered, duplicated, or conditional statements)"
        )
    return errors


def policy_inventory_rows(policy_text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Extract rows only from the canonical nine-column lifecycle table."""
    rows: list[tuple[str, str]] = []
    errors: list[str] = []
    in_inventory = False
    found_header = False

    for line_number, line in enumerate(policy_text.splitlines(), start=1):
        stripped = line.strip()
        if not in_inventory:
            if stripped == INVENTORY_HEADER:
                in_inventory = True
                found_header = True
            continue
        if stripped and all(char in "|-: " for char in stripped):
            continue
        if not stripped.startswith("|"):
            break
        raw_cells = stripped.split("|")
        if raw_cells[0] or raw_cells[-1] or len(raw_cells[1:-1]) != 9:
            errors.append(
                f"dependency-policy.md lifecycle inventory row {line_number}: "
                "must contain exactly nine columns"
            )
            continue
        cells = [cell.strip() for cell in raw_cells[1:-1]]
        id_match = re.fullmatch(r"`([^`\n]+)`", cells[0])
        if id_match is None:
            errors.append(
                f"dependency-policy.md lifecycle inventory row {line_number}: "
                "Lifecycle ID must be one backticked value"
            )
            continue
        rows.append((id_match.group(1), stripped))

    if not found_header:
        errors.append("docs/dependency-policy.md lifecycle inventory header is missing")
    return rows, errors


def policy_lifecycle_ids(policy_text: str) -> tuple[list[str], list[str]]:
    """Extract canonical inventory Lifecycle IDs; report duplicate rows."""
    rows, errors = policy_inventory_rows(policy_text)
    ids: list[str] = []
    seen: set[str] = set()
    for lifecycle_id, _ in rows:
        if lifecycle_id in seen:
            errors.append(
                f"duplicate lifecycle id in dependency-policy.md inventory: {lifecycle_id!r}"
            )
        else:
            seen.add(lifecycle_id)
        ids.append(lifecycle_id)
    return ids, errors


def policy_id_parity_errors(
    policy_text: str, lifecycle_ids: set[str]
) -> list[str]:
    errors: list[str] = []
    policy_ids, dup_errors = policy_lifecycle_ids(policy_text)
    errors.extend(dup_errors)
    policy_set = set(policy_ids)
    # set() collapses duplicates for missing/extra reporting; dup_errors already
    # covers repeated rows.
    for missing in sorted(lifecycle_ids - policy_set):
        errors.append(
            f"docs/dependency-policy.md inventory missing lifecycle id {missing!r}"
        )
    for extra in sorted(policy_set - lifecycle_ids):
        errors.append(
            f"docs/dependency-policy.md inventory has unknown lifecycle id {extra!r}"
        )
    return errors


def policy_reference_errors(
    policy_text: str, patches: list[dict[str, Any]]
) -> list[str]:
    """Require the policy inventory to name each patch's docs path and upstream refs."""
    errors: list[str] = []
    rows, _ = policy_inventory_rows(policy_text)
    row_by_id = {lifecycle_id: row for lifecycle_id, row in rows}
    for patch in patches:
        pid = patch.get("id", "<unknown>")
        row = row_by_id.get(pid)
        if row is None:
            errors.append(
                f"{pid}: matching dependency-policy.md lifecycle inventory row is missing"
            )
            continue
        docs_path = patch.get("docs_path")
        if _is_nonempty_str(docs_path):
            docs_fragment = str(docs_path).removeprefix("docs/").rstrip("/")
            if docs_fragment not in row:
                errors.append(
                    f"{pid}: docs path fragment {docs_fragment!r} missing from "
                    "its dependency-policy.md inventory row"
                )
        upstream = patch.get("upstream")
        if not isinstance(upstream, dict):
            continue
        repo = upstream.get("github_repo")
        if not _is_github_repo(repo):
            continue
        # A stale PR/issue number would silently poll the wrong upstream thread,
        # so the number the weekly run watches must be the documented one.
        for label, number in (
            ("pr", upstream.get("pr_number")),
            ("issue", upstream.get("issue_number")),
        ):
            if not _is_positive_int(number):
                continue
            reference = f"{repo}#{number}"
            if reference not in row:
                errors.append(
                    f"{pid}: upstream {label} reference {reference!r} missing from "
                    "its dependency-policy.md inventory row"
                )
    return errors


def co_retirement_parity_errors(
    patches: list[dict[str, Any]], declared_groups: Any
) -> list[str]:
    """Cross-check co-retirement membership in both directions."""
    errors: list[str] = []
    if not isinstance(declared_groups, list):
        declared_groups = []
    known_ids = {patch["id"] for patch in patches if _is_nonempty_str(patch.get("id"))}
    patch_declared_group = {
        patch["id"]: patch["retirement"].get("co_retirement_group")
        for patch in patches
    }
    group_members: dict[str, list[str]] = {}
    patch_group_membership: dict[str, str] = {}

    for group in declared_groups:
        # Shape validation already rejected non-objects / bad ids / bad members.
        if not isinstance(group, dict):
            continue
        gid = group.get("id")
        if not _is_nonempty_str(gid):
            continue
        members = group.get("patch_ids")
        if not isinstance(members, list) or not members:
            continue
        if not all(_is_nonempty_str(member) for member in members):
            continue

        group_members[gid] = members
        for member in members:
            if member not in known_ids:
                errors.append(
                    f"co_retirement_groups.{gid}: unknown patch id {member!r}"
                )
                continue
            prior = patch_group_membership.get(member)
            if prior is not None and prior != gid:
                errors.append(
                    f"{member}: listed in multiple co_retirement_groups "
                    f"({prior!r} and {gid!r})"
                )
            else:
                patch_group_membership[member] = gid
            if patch_declared_group.get(member) != gid:
                errors.append(
                    f"co_retirement_groups.{gid}: member {member!r} "
                    f"declares co_retirement_group {patch_declared_group.get(member)!r}"
                )

    for pid, group in patch_declared_group.items():
        if group is None:
            continue
        if group not in group_members:
            errors.append(f"{pid}: unknown co_retirement_group {group!r}")
        elif pid not in group_members.get(group, []):
            errors.append(f"{pid}: not listed in co_retirement_group {group!r}")
    return errors


def parity_errors(data: Any) -> list[str]:
    errors: list[str] = []
    shape_errors = validate_lifecycle_shape(data)
    errors.extend(shape_errors)

    # Synthetic malformed-input self-tests must fail closed before touching live
    # repository files. Normal parity continues below only for a valid contract.
    if shape_errors:
        return errors

    if PATCH_STATUS_SCRIPT.is_file():
        errors.extend(
            wrapper_delegation_errors(
                PATCH_STATUS_SCRIPT.read_text(encoding="utf-8", errors="replace")
            )
        )
    else:
        errors.append("missing scripts/check_vendored_patch_status.sh wrapper")

    patches_raw = data["patches"]
    patches: list[dict[str, Any]] = patches_raw
    patch_ids = [
        patch["id"]
        for patch in patches
        if _is_nonempty_str(patch.get("id"))
    ]
    if len(patch_ids) != len(set(patch_ids)):
        errors.append("duplicate patch id in lifecycle inventory")

    if POLICY_PATH.is_file():
        policy_text = POLICY_PATH.read_text(encoding="utf-8")
        errors.extend(policy_id_parity_errors(policy_text, set(patch_ids)))
        errors.extend(policy_reference_errors(policy_text, patches))
    else:
        errors.append("missing docs/dependency-policy.md")

    for patch in patches:
        pid = patch["id"]
        docs_path = patch["docs_path"]
        readme = find_readme(docs_path)
        if readme is None:
            errors.append(f"{pid}: missing README under {docs_path}")
            continue
        hold = patch["retirement"].get("merged_release_hold")
        if hold is not None:
            errors.extend(f"{pid}: {message}" for message in
                          merged_release_hold_errors(patch, hold["latest_release"]))
            marker = (f"Release hold reviewed {hold['reviewed_on']} by {hold['owner']}; "
                      f"latest stable {hold['latest_release']}; expires {hold['expires_on']}.")
            if marker not in readme.read_text(encoding="utf-8"):
                errors.append(f"{pid}: README lacks matching release hold review")
        errors.extend(
            reaffirmation_parity_errors(
                pid,
                patch["upstream"].get("filing"),
                patch.get("reaffirmation"),
                parse_readme_reaffirmation(readme),
            )
        )

    errors.extend(
        co_retirement_parity_errors(patches, data.get("co_retirement_groups", []))
    )

    lifecycle_vendor_paths = {patch["vendor_path"] for patch in patches}
    on_disk_vendor_paths = vendor_patch_dirs()
    for path in sorted(lifecycle_vendor_paths - on_disk_vendor_paths):
        errors.append(f"lifecycle references missing vendor directory {path}")
    for path in sorted(on_disk_vendor_paths - lifecycle_vendor_paths):
        errors.append(f"vendor directory {path} is not referenced by lifecycle inventory")

    root_patches = parse_patch_crates_io(ROOT_CARGO)
    expected_crates = {patch["crate"] for patch in patches}
    if set(root_patches) != expected_crates:
        errors.append(
            "root Cargo.toml [patch.crates-io] crates "
            f"{sorted(root_patches)} != lifecycle crates {sorted(expected_crates)}"
        )
    for patch in patches:
        crate = patch["crate"]
        expected_path = patch["vendor_path"]
        actual_path = root_patches.get(crate)
        if actual_path != expected_path:
            errors.append(
                f"{patch['id']}: root [patch.crates-io].{crate} path "
                f"{actual_path!r} != lifecycle {expected_path!r}"
            )

    if MESH_PERF_CARGO.is_file():
        mesh_patches = parse_patch_crates_io(MESH_PERF_CARGO)
        if set(mesh_patches) != set(root_patches):
            errors.append(
                "tests/performance/mesh/Cargo.toml [patch.crates-io] crates "
                f"{sorted(mesh_patches)} != root crates {sorted(root_patches)}"
            )
        for crate, path in root_patches.items():
            mesh_path = mesh_patches.get(crate)
            if mesh_path is None:
                errors.append(
                    f"tests/performance/mesh/Cargo.toml missing [patch.crates-io] entry for {crate}"
                )
            elif Path(mesh_path) != Path("../../../" + path):
                errors.append(
                    f"tests/performance/mesh/Cargo.toml {crate} path {mesh_path!r} "
                    f"does not mirror root {path!r}"
                )
    else:
        errors.append("missing tests/performance/mesh/Cargo.toml patch mirror")

    return errors


def github_auth_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_json(request: urllib.request.Request) -> tuple[Any, str | None]:
    """Bounded JSON GET returning (payload, failure reason).

    Reasons never echo request headers, so a token cannot reach the log. The
    read is capped because an unbounded response would be buffered in memory.
    """
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, f"transport failure ({type(exc).__name__})"
    except Exception as exc:
        return None, f"request failed ({type(exc).__name__})"
    if len(raw) > MAX_RESPONSE_BYTES:
        return None, f"response exceeded {MAX_RESPONSE_BYTES} bytes"
    try:
        return json.loads(raw.decode("utf-8")), None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "malformed JSON response"


def github_payload_state(
    payload: Any, expected_merge_commit: str | None = None
) -> tuple[str | None, str | None]:
    if not isinstance(payload, dict):
        return None, "unexpected response shape"
    if expected_merge_commit is not None:
        if not payload.get("merged_at") or payload.get("merge_commit_sha") != expected_merge_commit:
            return None, "reviewed upstream merge could not be confirmed"
    if payload.get("merged_at"):
        return "MERGED", None
    state = payload.get("state")
    if state == "open":
        return "OPEN", None
    if state == "closed":
        return "CLOSED", None
    return None, "unrecognized pull-request state"


def github_pr_state(
    repo: str, pr_number: int, *, expected_merge_commit: str | None = None
) -> tuple[str | None, str | None]:
    """Return (OPEN|CLOSED|MERGED, failure reason); both None-safe for callers."""
    if not _is_github_repo(repo) or not _is_positive_int(pr_number):
        return None, "invalid repository or pull-request number"
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
        headers=github_auth_headers(),
    )
    payload, reason = fetch_json(request)
    if reason is not None:
        return None, reason
    # Never echo the raw field: an untrusted string in the log could forge a
    # `::error::` workflow command.
    return github_payload_state(payload, expected_merge_commit)


def crates_io_latest(crate: str) -> str | None:
    if not CRATE_NAME_RE.fullmatch(crate):
        return None
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{crate}",
        headers={"User-Agent": USER_AGENT},
    )
    payload, reason = fetch_json(request)
    if reason is not None or not isinstance(payload, dict):
        return None
    crate_payload = payload.get("crate")
    if not isinstance(crate_payload, dict):
        return None
    version = crate_payload.get("max_stable_version")
    if not isinstance(version, str) or not CRATES_IO_VERSION_RE.fullmatch(version):
        return None
    return version


def run_upstream_status(data: dict[str, Any], *, today: date | None = None) -> int:
    retire_signal = 0
    query_failed = 0
    held_count = 0
    print("## Vendored patch upstream status")
    print("")
    for patch in data["patches"]:
        upstream = patch["upstream"]
        print(f"### {patch['label']}")
        print(
            f"- patch id: `{patch['id']}`; crate: `{patch['crate']}` "
            f"(vendored {patch['vendored_version']}); owner: {patch['owner']}"
        )
        print(f"- docs: {patch['docs_path']}")
        print(f"- retirement trigger: {patch['retirement']['trigger']}")
        group = patch["retirement"].get("co_retirement_group")
        if group:
            print(f"- co-retirement group: {group}")
        test_status = patch["retirement"]["compatible_release_test"]["status"]
        print(f"- compatible-release test: {test_status}")

        issue = upstream.get("issue_number")
        if issue is not None:
            print(f"- upstream issue: {upstream['github_repo']}#{issue}")

        latest = crates_io_latest(patch["crate"])
        if latest:
            print(f"- crates.io latest stable: {latest}")

        pr = upstream.get("pr_number")
        filing = upstream["filing"]
        if filing == "deliberate_fork_unfiled" and pr is None:
            fork_ref = upstream.get("fork_ref")
            if fork_ref:
                print(f"- deliberate fork staging ref: {fork_ref}")
            reaffirmation = patch.get("reaffirmation")
            if isinstance(reaffirmation, dict):
                print(
                    "- deliberate fork reaffirmation: "
                    f"{reaffirmation['date']} by {reaffirmation['owner']}: "
                    f"{reaffirmation['reason']}"
                )
            else:
                print(
                    "- upstream PR: NOT YET FILED — deliberate fork; needs upstream "
                    "issue/PR or explicit dated owner reaffirmation before the first "
                    "stable release (docs/dependency-policy.md)"
                )
                print(
                    f"  ::warning::{patch['id']} is an unfiled deliberate fork without a "
                    "dated reaffirmation in the lifecycle inventory."
                )
        elif pr is not None:
            hold = patch["retirement"].get("merged_release_hold")
            state, reason = github_pr_state(
                upstream["github_repo"], pr,
                expected_merge_commit=hold["merge_commit"] if hold else None,
            )
            if not state:
                print(
                    f"  ::warning::could not query upstream PR "
                    f"{upstream['github_repo']}#{pr} ({reason}) — failing closed."
                )
                query_failed = 1
            else:
                print(f"- upstream PR {upstream['github_repo']}#{pr}: state={state}")
                if state == "MERGED":
                    hold_errors = merged_release_hold_errors(patch, latest, today=today)
                    if not hold_errors:
                        held_count += 1
                        print(f"- merged fix retained pending a compatible release; "
                              f"review expires {hold['expires_on']}: {hold['reason']}")
                    else:
                        if hold:
                            print("  ::warning::release hold invalid: " + "; ".join(hold_errors))
                        print(
                            f"  ::warning::ACTION — {patch['crate']} PR "
                            f"{upstream['github_repo']}#{pr} merged upstream. Run the "
                            "compatible-release test on a branch without the patch before "
                            f"retiring per {patch['docs_path']}."
                        )
                        retire_signal = 1
                elif state == "CLOSED":
                    print(
                        f"  ::warning::{patch['crate']} PR {upstream['github_repo']}#{pr} "
                        f"was CLOSED without merge — revisit the patch strategy."
                    )
        else:
            print(f"  ::warning::{patch['id']} has filing={filing!r} but no pr_number")
            query_failed = 1
        print("")

    if retire_signal:
        print(
            "::error::One or more vendored patches merged upstream. Run compatible-release "
            "tests and follow docs/vendored-patch-lifecycle.json retirement_checklist before "
            "removing vendor copies."
        )
        return 1
    if query_failed:
        print(
            "::error::One or more upstream PR statuses could not be queried; failing closed."
        )
        return 1
    print(f"No unreviewed merged patches; {held_count} bounded release holds remain active.")
    return 0


def run_parity(data: Any) -> int:
    errors = parity_errors(data)
    if errors:
        for message in errors:
            print(f"::error::{message}")
        print("")
        print(
            "Vendored-patch lifecycle parity failed. Update docs/vendored-patch-lifecycle.json "
            "and every linked surface together (docs/dependency-policy.md, per-patch READMEs, "
            "Cargo.toml [patch.crates-io], scripts/check_vendored_patch_lifecycle.py, vendor/)."
        )
        return 1
    patch_count = len(data["patches"]) if isinstance(data, dict) else 0
    print(
        f"ok: lifecycle inventory covers {patch_count} patches with parity across "
        "Cargo.toml, vendor/, policy docs, and per-patch READMEs."
    )
    return 0


def _valid_patch(**overrides: Any) -> dict[str, Any]:
    patch: dict[str, Any] = {
        "id": "example-001",
        "label": "example patch",
        "crate": "example",
        "vendored_version": "1.0.0",
        "vendor_path": "vendor/example-1.0.0-ferrum-patched",
        "docs_path": "docs/upstream-example-patches/001/",
        "owner": "Ferrum Edge maintainers",
        "reason": "synthetic self-test patch",
        "upstream": {
            "filing": "filed",
            "github_repo": "example/example",
            "pr_number": 1,
            "issue_number": None,
            "fork_ref": None,
        },
        "reaffirmation": None,
        "retirement": {
            "trigger": "upstream ships a compatible release",
            "co_retirement_group": None,
            "compatible_release_test": {
                "status": "not_started",
                "notes": None,
            },
        },
        "regression_tests": ["tests/example.rs"],
    }
    for key, value in overrides.items():
        if key in {"upstream", "retirement"} and isinstance(value, dict):
            merged = dict(patch[key])
            nested = value
            if key == "retirement" and "compatible_release_test" in nested:
                compatible = dict(merged.get("compatible_release_test") or {})
                compatible.update(nested["compatible_release_test"])
                nested = dict(nested)
                nested["compatible_release_test"] = compatible
            merged.update(nested)
            patch[key] = merged
        else:
            patch[key] = value
    return patch


def _inventory_row(
    lifecycle_id: str,
    crate: str = "example",
    upstream: str = "upstream",
    docs_path: str | None = None,
) -> str:
    docs_path = docs_path or f"path/{lifecycle_id}/README.md"
    return (
        f"| `{lifecycle_id}` | `{crate}` | 1.0.0 | patch | {upstream} | owner | "
        f"reason | trigger | [docs]({docs_path}) |"
    )


GOOD_WRAPPER = """#!/usr/bin/env bash
# comment
set -uo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/check_vendored_patch_lifecycle.py" --upstream-status
"""


def run_self_test() -> int:
    """Deterministic static tests; never touches repository files or the network."""
    failures: list[str] = []

    def expect_contains(errors: list[str], needle: str, label: str) -> None:
        if not any(needle in message for message in errors):
            failures.append(f"{label}: expected error containing {needle!r}, got {errors!r}")

    def expect_empty(errors: list[str], label: str) -> None:
        if errors:
            failures.append(f"{label}: unexpected errors {errors!r}")

    base = {
        "schema_version": 1,
        "retirement_checklist": ["retire carefully"],
        "patches": [_valid_patch()],
    }
    expect_empty(validate_lifecycle_shape(base), "valid minimal inventory")

    filed_missing_pr = {
        **base,
        "patches": [
            _valid_patch(upstream={"filing": "filed", "pr_number": None}),
        ],
    }
    expect_contains(
        validate_lifecycle_shape(filed_missing_pr),
        "filing=filed requires a positive integer pr_number",
        "filed without pr_number",
    )

    filed_bad_pr = {
        **base,
        "patches": [_valid_patch(upstream={"filing": "filed", "pr_number": 0})],
    }
    expect_contains(
        validate_lifecycle_shape(filed_bad_pr),
        "filing=filed requires a positive integer pr_number",
        "filed with non-positive pr_number",
    )

    unfiled_with_pr = {
        **base,
        "patches": [
            _valid_patch(
                upstream={
                    "filing": "deliberate_fork_unfiled",
                    "pr_number": 9,
                    "github_repo": "example/example",
                }
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(unfiled_with_pr),
        "must not carry a pr_number",
        "unfiled with pr_number",
    )

    bad_repo = {
        **base,
        "patches": [
            _valid_patch(upstream={"filing": "filed", "pr_number": 1, "github_repo": "bad"})
        ],
    }
    expect_contains(
        validate_lifecycle_shape(bad_repo),
        "github_repo",
        "invalid github_repo",
    )

    empty_regression = {
        **base,
        "patches": [_valid_patch(regression_tests=[])],
    }
    expect_contains(
        validate_lifecycle_shape(empty_regression),
        "regression_tests",
        "empty regression_tests",
    )

    blank_regression_item = {
        **base,
        "patches": [_valid_patch(regression_tests=["  "])],
    }
    expect_contains(
        validate_lifecycle_shape(blank_regression_item),
        "regression_tests[0]",
        "blank regression_tests item",
    )

    empty_checklist = {**base, "retirement_checklist": []}
    expect_contains(
        validate_lifecycle_shape(empty_checklist),
        "retirement_checklist",
        "empty retirement_checklist",
    )

    blank_checklist_item = {**base, "retirement_checklist": [""]}
    expect_contains(
        validate_lifecycle_shape(blank_checklist_item),
        "retirement_checklist[0]",
        "blank retirement_checklist item",
    )

    bad_status = {
        **base,
        "patches": [
            _valid_patch(
                retirement={"compatible_release_test": {"status": "maybe"}}
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(bad_status),
        "compatible_release_test.status",
        "invalid compatible_release_test status",
    )

    missing_trigger = {
        **base,
        "patches": [_valid_patch(retirement={"trigger": ""})],
    }
    expect_contains(
        validate_lifecycle_shape(missing_trigger),
        "retirement.trigger",
        "empty retirement.trigger",
    )

    bad_issue = {
        **base,
        "patches": [
            _valid_patch(
                upstream={"filing": "filed", "pr_number": 1, "issue_number": -3}
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(bad_issue),
        "issue_number",
        "non-positive issue_number",
    )

    non_object_patch = {**base, "patches": ["nope"]}
    expect_contains(
        validate_lifecycle_shape(non_object_patch),
        "must be an object",
        "non-object patch entry",
    )

    expect_empty(wrapper_delegation_errors(GOOD_WRAPPER), "good wrapper")

    cwd_relative = """#!/usr/bin/env bash
set -uo pipefail
exec python3 scripts/check_vendored_patch_lifecycle.py --upstream-status
"""
    expect_contains(
        wrapper_delegation_errors(cwd_relative),
        "exactly",
        "cwd-relative wrapper",
    )

    unquoted = """#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 $SCRIPT_DIR/check_vendored_patch_lifecycle.py --upstream-status
"""
    expect_contains(
        wrapper_delegation_errors(unquoted),
        "must delegate with",
        "unquoted SCRIPT_DIR wrapper",
    )

    noop = """#!/usr/bin/env bash
set -uo pipefail
true
"""
    expect_contains(
        wrapper_delegation_errors(noop),
        "must delegate with",
        "no-op wrapper",
    )

    early_exit = """#!/usr/bin/env bash
set -uo pipefail
exit 0
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/check_vendored_patch_lifecycle.py" --upstream-status
"""
    expect_contains(
        wrapper_delegation_errors(early_exit),
        "exactly",
        "early-exit wrapper with otherwise-valid lines",
    )

    trailing = """#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/check_vendored_patch_lifecycle.py" --upstream-status
true
"""
    expect_contains(
        wrapper_delegation_errors(trailing),
        "exactly",
        "wrapper with trailing command",
    )

    expect_contains(
        validate_lifecycle_shape(["not", "an", "object"]),
        "must be a JSON object",
        "non-object top level",
    )
    expect_contains(
        parity_errors(["not", "an", "object"]),
        "must be a JSON object",
        "parity non-object top level",
    )

    unsupported_schema = {**base, "schema_version": 99}
    expect_contains(
        validate_lifecycle_shape(unsupported_schema),
        "schema_version must be 1",
        "unsupported schema_version",
    )
    expect_contains(
        parity_errors(unsupported_schema),
        "schema_version must be 1",
        "parity unsupported schema_version",
    )

    bad_reaffirmation = {
        **base,
        "patches": [_valid_patch(reaffirmation="not-an-object")],
    }
    expect_contains(
        validate_lifecycle_shape(bad_reaffirmation),
        "reaffirmation: must be null or an object",
        "malformed reaffirmation",
    )
    expect_contains(
        parity_errors(bad_reaffirmation),
        "reaffirmation: must be null or an object",
        "parity malformed reaffirmation",
    )

    incomplete_reaffirmation = {
        **base,
        "patches": [
            _valid_patch(reaffirmation={"date": "2026-01-01", "owner": "", "reason": "x"})
        ],
    }
    expect_contains(
        validate_lifecycle_shape(incomplete_reaffirmation),
        "reaffirmation.owner",
        "reaffirmation missing owner",
    )

    unhashable_members = {
        **base,
        "co_retirement_groups": [
            {"id": "g1", "patch_ids": [{"nested": True}, ["list"]]},
        ],
        "patches": [_valid_patch()],
    }
    expect_contains(
        validate_lifecycle_shape(unhashable_members),
        "must be a non-empty string",
        "unhashable co_retirement group members",
    )
    # Must fail closed as parity errors, never TypeError from set()/dict keys.
    expect_contains(
        parity_errors(unhashable_members),
        "must be a non-empty string",
        "parity unhashable co_retirement group members",
    )

    invalid_co_group = {
        **base,
        "patches": [_valid_patch(retirement={"co_retirement_group": ""})],
    }
    expect_contains(
        validate_lifecycle_shape(invalid_co_group),
        "co_retirement_group: must be null or a non-empty string",
        "empty co_retirement_group",
    )

    list_co_group = {
        **base,
        "patches": [_valid_patch(retirement={"co_retirement_group": ["g"]})],
    }
    expect_contains(
        validate_lifecycle_shape(list_co_group),
        "co_retirement_group: must be null or a non-empty string",
        "list co_retirement_group",
    )
    expect_contains(
        parity_errors(list_co_group),
        "co_retirement_group: must be null or a non-empty string",
        "parity list co_retirement_group",
    )

    matching_policy = "\n".join(
        [
            "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |",
            _inventory_row("example-001"),
            _inventory_row("example-002", "other"),
        ]
    )
    expect_empty(
        policy_id_parity_errors(matching_policy, {"example-001", "example-002"}),
        "matching policy IDs",
    )

    missing_policy = "\n".join(
        [
            "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |",
            _inventory_row("example-001"),
        ]
    )
    expect_contains(
        policy_id_parity_errors(missing_policy, {"example-001", "example-002"}),
        "missing lifecycle id 'example-002'",
        "missing policy ID",
    )

    extra_policy = "\n".join(
        [
            "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |",
            _inventory_row("example-001"),
            _inventory_row("example-extra"),
        ]
    )
    expect_contains(
        policy_id_parity_errors(extra_policy, {"example-001"}),
        "unknown lifecycle id 'example-extra'",
        "extra policy ID",
    )

    duplicate_policy = "\n".join(
        [
            "| Lifecycle ID | Crate | Vendored ver. | Patch | Upstream issue / PR | Owner | Reason | Removal trigger | Docs |",
            _inventory_row("example-001"),
            _inventory_row("example-001"),
        ]
    )
    expect_contains(
        policy_id_parity_errors(duplicate_policy, {"example-001"}),
        "duplicate lifecycle id",
        "duplicate policy ID",
    )

    # --- derived vendor-path identity -------------------------------------
    wrong_vendor_path = {
        **base,
        "patches": [_valid_patch(vendor_path="vendor/example-9.9.9-ferrum-patched")],
    }
    expect_contains(
        validate_lifecycle_shape(wrong_vendor_path),
        "vendor_path: must be 'vendor/example-1.0.0-ferrum-patched'",
        "vendor_path not derived from crate and version",
    )

    bad_crate_name = {
        **base,
        "patches": [
            _valid_patch(
                crate="../evil", vendor_path="vendor/../evil-1.0.0-ferrum-patched"
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(bad_crate_name),
        "crate: must be a registry crate name",
        "crate name with path separator",
    )

    bad_version = {
        **base,
        "patches": [
            _valid_patch(
                vendored_version="1.0.0/../..",
                vendor_path="vendor/example-1.0.0/../..-ferrum-patched",
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(bad_version),
        "vendored_version: must be a registry version",
        "vendored version with path separator",
    )

    bad_docs_path = {
        **base,
        "patches": [_valid_patch(docs_path="../../outside-repository")],
    }
    expect_contains(
        validate_lifecycle_shape(bad_docs_path),
        "docs_path: must be a repository-relative",
        "docs path traversal",
    )

    dot_repo = {
        **base,
        "patches": [
            _valid_patch(
                upstream={
                    "filing": "filed",
                    "pr_number": 1,
                    "github_repo": "../..",
                }
            )
        ],
    }
    expect_contains(
        validate_lifecycle_shape(dot_repo),
        "github_repo",
        "dot-only github_repo segments",
    )

    # --- reaffirmation pairing -------------------------------------------
    readme_record = {"date": "2026-07-01", "owner": "@owner", "reason": "still right"}
    expect_empty(
        reaffirmation_parity_errors(
            "p", "deliberate_fork_unfiled", dict(readme_record), dict(readme_record)
        ),
        "matching reaffirmation",
    )
    expect_contains(
        reaffirmation_parity_errors("p", "deliberate_fork_unfiled", None, readme_record),
        "README contains dated reaffirmation but lifecycle.reaffirmation is null",
        "README reaffirmation without lifecycle record",
    )
    expect_contains(
        reaffirmation_parity_errors("p", "deliberate_fork_unfiled", readme_record, None),
        "README lacks matching dated reaffirmation",
        "lifecycle reaffirmation without README record",
    )
    expect_contains(
        reaffirmation_parity_errors(
            "p",
            "deliberate_fork_unfiled",
            {**readme_record, "reason": "different"},
            readme_record,
        ),
        "reaffirmation 'reason' does not match README",
        "reaffirmation field mismatch",
    )
    # A filed patch may share a README with an unfiled fork (all three
    # tungstenite/tokio-tungstenite takeover records point at one README), so the
    # fork's reaffirmation must not force a fabricated record onto it.
    expect_empty(
        reaffirmation_parity_errors("p", "filed", None, readme_record),
        "filed patch sharing a reaffirmed README",
    )
    expect_contains(
        reaffirmation_parity_errors("p", "filed", readme_record, readme_record),
        "reaffirmation is a deliberate-fork record",
        "filed patch carrying a reaffirmation",
    )
    expect_empty(
        reaffirmation_parity_errors("p", "deliberate_fork_unfiled", None, None),
        "no reaffirmation on either side",
    )

    reaffirmed_readme = (
        "## Status\n\nDeliberate fork — re-affirmed 2026-07-01 by @owner: still right\n"
    )
    if find_reaffirmation(reaffirmed_readme) != readme_record:
        failures.append(
            f"reaffirmation extraction: got {find_reaffirmation(reaffirmed_readme)!r}"
        )
    # The undated policy prose in docs/upstream-tungstenite-patches/README.md
    # must not read as a dated record.
    undated_readme = "must be upstreamed or explicitly re-affirmed before release\n"
    if find_reaffirmation(undated_readme) is not None:
        failures.append("undated re-affirmation prose must not parse as a record")

    # --- co-retirement groups --------------------------------------------
    grouped_patches = [
        _valid_patch(id="a", retirement={"co_retirement_group": "g"}),
        _valid_patch(id="b", retirement={"co_retirement_group": "g"}),
    ]
    expect_empty(
        co_retirement_parity_errors(
            grouped_patches, [{"id": "g", "patch_ids": ["a", "b"]}]
        ),
        "consistent co-retirement group",
    )
    expect_contains(
        co_retirement_parity_errors(
            grouped_patches, [{"id": "g", "patch_ids": ["a", "b", "ghost"]}]
        ),
        "unknown patch id 'ghost'",
        "co-retirement group with unknown member",
    )
    expect_contains(
        co_retirement_parity_errors(
            grouped_patches, [{"id": "g", "patch_ids": ["a"]}]
        ),
        "b: not listed in co_retirement_group 'g'",
        "member omitted from its declared group",
    )
    expect_contains(
        co_retirement_parity_errors(
            [
                _valid_patch(id="a", retirement={"co_retirement_group": "g"}),
                _valid_patch(id="b", retirement={"co_retirement_group": None}),
            ],
            [{"id": "g", "patch_ids": ["a", "b"]}],
        ),
        "member 'b' declares co_retirement_group None",
        "group lists a patch that declares no group",
    )
    expect_contains(
        co_retirement_parity_errors(
            grouped_patches, [{"id": "other", "patch_ids": ["a", "b"]}]
        ),
        "unknown co_retirement_group 'g'",
        "patch declares a group that does not exist",
    )
    expect_contains(
        co_retirement_parity_errors(
            grouped_patches,
            [
                {"id": "g", "patch_ids": ["a", "b"]},
                {"id": "g2", "patch_ids": ["a"]},
            ],
        ),
        "listed in multiple co_retirement_groups",
        "member listed in two groups",
    )

    # --- [patch.crates-io] parsing ---------------------------------------
    root_manifest = "\n".join(
        [
            "[package]",
            'name = "ferrum-edge"',
            "",
            "# [patch.crates-io] in a comment must not open the block",
            "[patch.crates-io]",
            'reqwest = { path = "vendor/reqwest-0.13.4-ferrum-patched" }',
            'tokio-tungstenite = { path = "vendor/tokio-tungstenite-0.29.0-ferrum-patched" }',
            "",
            "[profile.release]",
            'ignored = { path = "vendor/ignored-ferrum-patched" }',
        ]
    )
    parsed_root = parse_patch_crates_io_text(root_manifest)
    if parsed_root != {
        "reqwest": "vendor/reqwest-0.13.4-ferrum-patched",
        "tokio-tungstenite": "vendor/tokio-tungstenite-0.29.0-ferrum-patched",
    }:
        failures.append(f"root [patch.crates-io] parse: got {parsed_root!r}")

    registry_override = "\n".join(
        [
            "[patch.crates-io]",
            'reqwest = { version = "0.13.3" }',
        ]
    )
    if parse_patch_crates_io_text(registry_override) != {}:
        failures.append("a non-path [patch.crates-io] entry must not parse as vendored")

    mesh_manifest = "\n".join(
        [
            "[patch.crates-io]",
            'reqwest = { path = "../../../vendor/reqwest-0.13.4-ferrum-patched" }',
        ]
    )
    mesh_parsed = parse_patch_crates_io_text(mesh_manifest)
    if Path(mesh_parsed["reqwest"]) != Path(
        "../../../" + parsed_root["reqwest"]
    ):
        failures.append("mesh mirror path must resolve to the root vendor path")

    # --- policy inventory references -------------------------------------
    reference_policy = "\n".join(
        [
            INVENTORY_HEADER,
            "|---|---|---|---|---|---|---|---|---|",
            _inventory_row(
                "example-001",
                upstream=(
                    "[example/example#7](https://github.com/example/example/pull/7), "
                    "issue [example/example#6]"
                    "(https://github.com/example/example/issues/6)"
                ),
                docs_path=(
                    "upstream-example-patches/001/README.md"
                ),
            ),
            # A reference outside the matching row must not satisfy parity.
            "unrelated prose mentions example/example#8 and example/example#99",
        ]
    )
    referenced_patch = _valid_patch(
        upstream={"filing": "filed", "pr_number": 7, "issue_number": 6}
    )
    expect_empty(
        policy_reference_errors(reference_policy, [referenced_patch]),
        "documented upstream references",
    )
    expect_contains(
        policy_reference_errors(
            reference_policy,
            [_valid_patch(upstream={"filing": "filed", "pr_number": 8})],
        ),
        "upstream pr reference 'example/example#8' missing",
        "stale upstream PR number",
    )
    expect_contains(
        policy_reference_errors(
            reference_policy,
            [
                _valid_patch(
                    upstream={"filing": "filed", "pr_number": 7, "issue_number": 99}
                )
            ],
        ),
        "upstream issue reference 'example/example#99' missing",
        "stale upstream issue number",
    )
    expect_contains(
        policy_reference_errors("| no rows here |", [referenced_patch]),
        "matching dependency-policy.md lifecycle inventory row is missing",
        "matching inventory row absent from policy",
    )

    unrelated_table = "\n".join(
        [
            "| Other ID | A | B | C | D | E | F | G | H |",
            "|---|---|---|---|---|---|---|---|---|",
            _inventory_row("example-001"),
        ]
    )
    expect_contains(
        policy_id_parity_errors(unrelated_table, {"example-001"}),
        "lifecycle inventory header is missing",
        "unrelated nine-column table must not be treated as lifecycle inventory",
    )

    # A merge alone is not a released fix. A hold must be bounded, match the
    # live release/merge identities, and remain blocked on compatibility.
    hold = {
        "reviewed_on": "2050-01-01", "expires_on": "2050-01-31",
        "owner": _valid_patch()["owner"], "latest_release": "1.0.0", "merge_commit": "a" * 40,
        "reason": "merged fix not released", "evidence": ["https://example.com/source"],
    }
    held = _valid_patch(retirement={
        "compatible_release_test": {"status": "blocked"}, "merged_release_hold": hold,
    })
    review_day = date(2050, 1, 1)
    expect_empty(validate_lifecycle_shape({**base, "patches": [held]}), "valid release hold")
    expect_empty(merged_release_hold_errors(held, "1.0.0", today=review_day), "active hold")
    for latest, day, needle in [
        ("1.0.1", review_day, "release changed"),
        (None, review_day, "could not be confirmed"),
        ("1.0.0", date(2050, 1, 31), "expired"),
        ("1.0.0", date(2049, 12, 31), "in the future"),
    ]:
        expect_contains(merged_release_hold_errors(held, latest, today=day), needle, needle)
    for field, value, needle in [
        ("expires_on", "2050-02-01", "review window"),
        ("reviewed_on", "20500101", "ISO calendar"),
        ("owner", "different owner", "patch owner"),
        ("merge_commit", "not-a-sha", "full commit SHA"),
        ("evidence", [], "non-empty list"),
    ]:
        mutated = _valid_patch(retirement={
            "compatible_release_test": {"status": "blocked"},
            "merged_release_hold": {**hold, field: value},
        })
        expect_contains(validate_lifecycle_shape({**base, "patches": [mutated]}), needle, needle)
    for status in ("not_started", "passed"):
        mutated = _valid_patch(retirement={
            "compatible_release_test": {"status": status}, "merged_release_hold": hold,
        })
        expect_contains(validate_lifecycle_shape({**base, "patches": [mutated]}),
                        "status=blocked", "hold cannot hide compatibility outcome")

    # Exercise the whole upstream decision with synthetic responses, never live
    # network access. Other merged patches still fail without a reviewed hold.
    import contextlib
    import io
    from unittest import mock
    payload = {"merged_at": "2050-01-01", "merge_commit_sha": "a" * 40, "state": "closed"}
    cases = [
        (held, "1.0.0", payload, 0, "reviewed unreleased fix"),
        (held, "1.0.1", payload, 1, "new release requires review"),
        (held, None, payload, 1, "unknown release fails closed"),
        (held, "1.0.0", {**payload, "merge_commit_sha": "b" * 40}, 1, "merge mismatch"),
        (held, "1.0.0", {"state": "open"}, 1, "unconfirmed merge"),
        (_valid_patch(), "1.0.0", payload, 1, "unreviewed merge still fails"),
    ]
    for fixture, latest, response, expected, label in cases:
        with mock.patch(f"{__name__}.fetch_json", return_value=(response, None)), \
             mock.patch(f"{__name__}.crates_io_latest", return_value=latest), \
             contextlib.redirect_stdout(io.StringIO()):
            actual = run_upstream_status({"patches": [fixture]}, today=review_day)
        if actual != expected:
            failures.append(f"{label}: expected status {expected}, got {actual}")

    if failures:
        for message in failures:
            print(f"::error::{message}")
        print("Vendored-patch lifecycle self-test failed.")
        return 1
    print("ok: vendored-patch lifecycle self-test passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--upstream-status",
        action="store_true",
        help=(
            "After self-test and parity, report upstream PR state and deliberate-fork "
            "reaffirmation gaps (weekly workflow)."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help=(
            "Run only deterministic static validator self-tests and exit "
            "(no network, no repo mutation). Normal invocations also self-test first."
        ),
    )
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    # Every normal checker path self-tests first, then repository parity.
    self_test_code = run_self_test()
    if self_test_code != 0:
        return self_test_code

    if not LIFECYCLE_PATH.is_file():
        print(f"::error::missing lifecycle inventory at {LIFECYCLE_PATH}")
        return 1

    try:
        data = load_lifecycle()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::failed to load lifecycle inventory: {exc}")
        return 1

    parity_code = run_parity(data)
    if parity_code != 0:
        return parity_code
    if args.upstream_status:
        if not isinstance(data, dict):
            print("::error::lifecycle inventory must be a JSON object for upstream status")
            return 1
        return run_upstream_status(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
