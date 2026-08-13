#!/usr/bin/env python3
"""Fail-closed launch readiness gate for PRODUCTION_READINESS.md.

Computes a live launch verdict from:
  - docs/launch-blocker-policy.json (labels, tiers, state machine, tracked
    inventory, private-advisory redaction contract)
  - docs/launch-exemptions.json (structured, expiring exemptions)
  - the paginated GitHub Issues API plus timeline cross-references
  - the paginated repository security-advisories API when a dedicated advisory
    token is present, otherwise externally maintained repository *variables*
    carrying a redacted count and an audit timestamp

Nothing in the pull request's own tree may assert that private advisories are
clear: the policy file defines only the freshness ceiling, never the count or
the as-of value. Missing token, API/rate-limit/pagination/schema/staleness
failures all yield UNKNOWN, and UNKNOWN and FAIL both exit non-zero.

Issue, PR, and advisory text is untrusted data. It is never executed and never
echoed: private advisories contribute a count and nothing else.

Modes:
  --self-test   deterministic fixture tests only (no network, injected clock)
  --verify      live evaluation + PRODUCTION_READINESS.md claim parity
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "docs" / "launch-blocker-policy.json"
EXEMPTIONS_PATH = ROOT / "docs" / "launch-exemptions.json"
USER_AGENT = "ferrum-edge-launch-readiness (github.com/ferrum-edge/ferrum-edge)"
API_ORIGIN = "https://api.github.com/"
MAX_RESPONSE_BYTES = 1 << 20
MAX_PAGES = 50
# Blocker discovery walks the unfiltered all-state issue inventory rather than a
# `labels=` filter, so its bounds track the whole repository history, not the
# blocker set. A filtered page held a handful of issues; an unfiltered one holds
# `PER_PAGE` complete issue payloads, bodies included. The shared ceilings would
# wedge the gate at UNKNOWN — on page count once the combined issue+pull-request
# total passed `MAX_PAGES * PER_PAGE`, and on body size well before that, since a
# full page already measures within a tenth of `MAX_RESPONSE_BYTES`. Both walks
# stay fail-closed; only this one gets headroom of its own.
MAX_INVENTORY_PAGES = 400
MAX_INVENTORY_RESPONSE_BYTES = 16 << 20
PER_PAGE = 100
SEVERITIES = ("critical", "high", "medium")
VERDICTS = ("PASS", "FAIL", "UNKNOWN")

# An empty `labels=launch-blocker` listing and a label that does not exist are
# the same HTTP response, so the label vocabulary is proven from repository
# metadata before any issue listing is trusted. These codes keep the three
# outcomes distinguishable in the UNKNOWN reason: a missing/renamed definition
# (`label_inventory`), a tracked blocker that was never classified into the
# labeled inventory (`label_drift`), and an ordinary transport/permission
# failure (`api` / `denied` / `rate_limit`).
LABEL_INVENTORY_CODE = "label_inventory"
LABEL_DRIFT_CODE = "label_drift"

# Repository security advisories are a distinct GitHub permission. The Actions
# `security-events` scope does NOT grant it, so the workflow token gets 403.
ADVISORY_STATES = ("triage", "draft", "published", "closed", "withdrawn")
ADVISORY_SEVERITIES = ("critical", "high", "medium", "low")

# The launch-blocker state machine is a contract, not a tunable: an open issue
# with an in-flight or merged PR is still a blocker until the issue itself is
# closed as completed, and a duplicate/not-planned closure is not a fix.
REQUIRED_STATE_MACHINE = {
    "open": "blocking",
    "in_flight": "blocking",
    "merged_awaiting_issue_close": "blocking",
    "closed_completed": "cleared",
    "closed_other": "blocking",
    "exempted": "cleared_for_listed_tiers",
}
BELOW_TIER = "below_tier"
REQUIRED_CLOSED_COMPLETED_REASONS = ("completed",)
REQUIRED_CLOSED_OTHER_REASONS = ("not_planned", "duplicate", None)
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
# Substrings that must never reach stdout, checked against the rendered record.
BANNED_OUTPUT_TOKENS = (
    "ghsa_id",
    "GHSA-",
    "cve_id",
    "CVE-",
    "html_url",
    "vulnerabilities",
    "identifiers",
    "credits",
    "cvss",
    "cwes",
)
# The policy file must not carry an authoritative private-advisory count or
# as-of value: those would be pull-request-controlled proof of "zero blockers".
FORBIDDEN_POLICY_KEYS = (
    "opaque_input",
    "redacted_blocking_count",
    "as_of",
    "private_blocker_count",
)

MAX_FALLBACK_AGE_SECONDS = 30 * 24 * 60 * 60
MAX_FALLBACK_COUNT = 100000

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ISO_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,63}$")
# Repository label payloads may also contain ordinary GitHub labels with
# spaces or Unicode. They are never emitted, but must remain structurally
# bounded so an unrelated valid label cannot make the unfiltered walk UNKNOWN.
LIVE_LABEL_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,100}$")
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
COUNT_RE = re.compile(r"^(?:0|[1-9][0-9]{0,5})$")
GIT_REF_RE = re.compile(r"^refs/[A-Za-z0-9._/-]{1,200}$")


class GateError(Exception):
    """Fail-closed evaluation error that becomes UNKNOWN or a hard failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class IssueRecord:
    number: int
    state: str
    state_reason: str | None
    labels: set[str]
    severity: str
    source: str
    linked_open_prs: list[int] = field(default_factory=list)
    linked_merged_prs: list[int] = field(default_factory=list)
    classification: str = "open"


@dataclass
class PrivateBlockers:
    count: int
    source: str
    as_of: str | None


@dataclass
class Evaluation:
    verdict: str
    launch_tier: str
    target_sha: str
    as_of: str
    policy_version: str
    classification_version: str
    blocking_issues: list[dict[str, Any]]
    cleared_issues: list[dict[str, Any]]
    exempted_issues: list[dict[str, Any]]
    in_flight: list[dict[str, Any]]
    counts_by_severity: dict[str, int]
    private_blocker_count: int
    private_source: str
    private_as_of: str | None = None
    unknown_reasons: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    """Production wall clock. Every evaluation path takes `now` explicitly so
    tests are deterministic and production freshness is never bypassed."""

    return datetime.now(timezone.utc)


def format_utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso8601(value: Any, label: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not ISO_Z_RE.fullmatch(value):
        raise GateError("schema", f"malformed {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError("schema", f"malformed {label}") from exc
    if parsed.tzinfo is None:
        raise GateError("schema", f"{label} missing timezone")
    return parsed.astimezone(timezone.utc)


def load_json_file(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise GateError("schema", f"missing file {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise GateError("schema", f"malformed JSON in {path.name}") from exc
    except OSError as exc:
        raise GateError("io", f"cannot read {path.name}") from exc
    except UnicodeDecodeError as exc:
        raise GateError("schema", f"non-UTF-8 content in {path.name}") from exc


def read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise GateError("schema", f"missing file {path.name}") from exc
    except OSError as exc:
        raise GateError("io", f"cannot read {path.name}") from exc
    except UnicodeDecodeError as exc:
        raise GateError("schema", f"non-UTF-8 content in {path.name}") from exc


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError("schema", f"{label} must be an object")
    return value


def require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GateError("schema", f"{label} must be a non-empty string")
    return value


def require_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise GateError("schema", f"{label} must be a boolean")
    return value


def require_positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise GateError("schema", f"{label} must be a positive integer")
    return value


def require_nonneg_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GateError("schema", f"{label} must be a non-negative integer")
    return value


def require_str_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise GateError("schema", f"{label} must be a non-empty list")
    for item in value:
        if not isinstance(item, str) or not item:
            raise GateError("schema", f"{label} entries must be non-empty strings")
    return list(value)


def contains_forbidden_key(value: Any) -> str | None:
    """Recursively look for a checked-in authoritative private count/as-of."""

    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str) and key in FORBIDDEN_POLICY_KEYS:
                return key
            found = contains_forbidden_key(nested)
            if found is not None:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = contains_forbidden_key(nested)
            if found is not None:
                return found
    return None


# ---------------------------------------------------------------------------
# Policy / exemption schemas
# ---------------------------------------------------------------------------


def validate_policy(policy: dict[str, Any]) -> None:
    require_str(policy.get("policy_version"), "policy_version")
    require_str(policy.get("classification_version"), "classification_version")
    repo = require_str(policy.get("repository"), "repository")
    if not REPO_RE.fullmatch(repo):
        raise GateError("schema", "repository must be owner/name")

    labels = require_dict(policy.get("labels"), "labels")
    seen_labels: set[str] = set()
    for key in ("launch_blocker", "launch_exempted"):
        label = require_str(labels.get(key), f"labels.{key}")
        if not LABEL_RE.fullmatch(label):
            raise GateError("schema", f"labels.{key} malformed")
        if label in seen_labels:
            raise GateError("schema", "configured label names must be distinct")
        seen_labels.add(label)
    severity_labels = require_dict(labels.get("severity"), "labels.severity")
    if set(severity_labels) != set(SEVERITIES):
        raise GateError("schema", "labels.severity must cover exactly the severities")
    for sev in SEVERITIES:
        label = require_str(severity_labels.get(sev), f"labels.severity.{sev}")
        if not LABEL_RE.fullmatch(label):
            raise GateError("schema", f"labels.severity.{sev} malformed")
        if label in seen_labels:
            # One repository label may not serve two policy roles: the
            # existence proof below would then pass while the vocabulary is
            # ambiguous.
            raise GateError("schema", "configured label names must be distinct")
        seen_labels.add(label)

    tiers = require_dict(policy.get("tiers"), "tiers")
    if not tiers:
        raise GateError("schema", "tiers must not be empty")
    for tier_name, tier in tiers.items():
        if not isinstance(tier_name, str) or not tier_name:
            raise GateError("schema", "tier name malformed")
        tier_obj = require_dict(tier, f"tiers.{tier_name}")
        blocking = require_str_list(
            tier_obj.get("blocking_severities"), f"tiers.{tier_name}.blocking_severities"
        )
        for sev in blocking:
            if sev not in SEVERITIES:
                raise GateError("schema", f"unknown severity in tier {tier_name}")
    default_tier = require_str(policy.get("default_launch_tier"), "default_launch_tier")
    if default_tier not in tiers:
        raise GateError("schema", "default_launch_tier missing from tiers")

    state_machine = require_dict(policy.get("state_machine"), "state_machine")
    if state_machine != REQUIRED_STATE_MACHINE:
        raise GateError("schema", "state_machine does not match the launch contract")
    completed = require_str_list(
        policy.get("closed_completed_reasons"), "closed_completed_reasons"
    )
    if tuple(completed) != REQUIRED_CLOSED_COMPLETED_REASONS:
        raise GateError("schema", "closed_completed_reasons must be exactly completed")
    other = policy.get("closed_other_reasons")
    if not isinstance(other, list) or tuple(other) != REQUIRED_CLOSED_OTHER_REASONS:
        raise GateError("schema", "closed_other_reasons does not match the contract")
    if require_bool(policy.get("in_flight_clears_blocker"), "in_flight_clears_blocker"):
        raise GateError("schema", "in_flight_clears_blocker must be false")
    if require_bool(
        policy.get("merged_pr_clears_blocker_before_issue_close"),
        "merged_pr_clears_blocker_before_issue_close",
    ):
        raise GateError(
            "schema", "merged_pr_clears_blocker_before_issue_close must be false"
        )

    tracked = policy.get("tracked_blockers")
    if not isinstance(tracked, list):
        raise GateError("schema", "tracked_blockers must be a list")
    seen: set[int] = set()
    for idx, entry in enumerate(tracked):
        obj = require_dict(entry, f"tracked_blockers[{idx}]")
        number = require_positive_int(obj.get("issue"), f"tracked_blockers[{idx}].issue")
        if number in seen:
            raise GateError("schema", f"duplicate tracked issue {number}")
        seen.add(number)
        sev = require_str(obj.get("severity"), f"tracked_blockers[{idx}].severity")
        if sev not in SEVERITIES:
            raise GateError("schema", f"tracked_blockers[{idx}].severity invalid")
        require_str(obj.get("note"), f"tracked_blockers[{idx}].note")

    validate_private_advisory_policy(policy, tiers)

    document = require_dict(policy.get("document"), "document")
    for key in ("path", "marker_begin", "marker_end", "historical_marker"):
        require_str(document.get(key), f"document.{key}")
    doc_path = document["path"]
    if doc_path.startswith("/") or ".." in doc_path.split("/"):
        raise GateError("schema", "document.path must be repository-relative")
    require_str(policy.get("exemptions_path"), "exemptions_path")

    forbidden = contains_forbidden_key(policy)
    if forbidden is not None:
        raise GateError(
            "schema",
            f"policy may not carry an authoritative private-advisory field ({forbidden})",
        )


def validate_private_advisory_policy(
    policy: dict[str, Any], tiers: dict[str, Any]
) -> None:
    private = require_dict(policy.get("private_advisories"), "private_advisories")
    if not require_bool(private.get("enabled"), "private_advisories.enabled"):
        raise GateError("schema", "private advisory evaluation may not be disabled")
    if private.get("representation") != "redacted_count_only":
        raise GateError("schema", "private advisories must be redacted_count_only")

    blocking_states = require_str_list(
        private.get("blocking_states"), "private_advisories.blocking_states"
    )
    closed_states = require_str_list(
        private.get("closed_states"), "private_advisories.closed_states"
    )
    blocking_set = set(blocking_states)
    closed_set = set(closed_states)
    if blocking_set & closed_set:
        raise GateError("schema", "advisory state sets overlap")
    if blocking_set | closed_set != set(ADVISORY_STATES):
        raise GateError("schema", "advisory state sets must cover every known state")

    by_tier = require_dict(
        private.get("blocking_severities_by_tier"),
        "private_advisories.blocking_severities_by_tier",
    )
    if set(by_tier) != set(tiers):
        raise GateError("schema", "advisory severities must cover exactly the tiers")
    for tier_name in by_tier:
        severities = require_str_list(
            by_tier[tier_name],
            f"private_advisories.blocking_severities_by_tier.{tier_name}",
        )
        for sev in severities:
            if sev not in ADVISORY_SEVERITIES:
                raise GateError("schema", "unknown advisory severity in policy")

    never_emit = require_str_list(
        private.get("never_emit_fields"), "private_advisories.never_emit_fields"
    )
    missing = [f for f in REQUIRED_NEVER_EMIT_FIELDS if f not in never_emit]
    if missing:
        raise GateError("schema", "private never_emit_fields incomplete")

    live = require_dict(private.get("live_api"), "private_advisories.live_api")
    token_env = require_str(live.get("token_env"), "private_advisories.live_api.token_env")
    if not ENV_NAME_RE.fullmatch(token_env):
        raise GateError("schema", "live_api.token_env malformed")
    if not require_bool(
        live.get("actions_security_events_permission_is_insufficient"),
        "live_api.actions_security_events_permission_is_insufficient",
    ):
        raise GateError(
            "schema",
            "live_api must record that the Actions security-events scope is insufficient",
        )

    fallback = require_dict(
        private.get("trusted_fallback"), "private_advisories.trusted_fallback"
    )
    for key in ("count_variable", "as_of_variable"):
        name = require_str(fallback.get(key), f"trusted_fallback.{key}")
        if not ENV_NAME_RE.fullmatch(name):
            raise GateError("schema", f"trusted_fallback.{key} malformed")
    if fallback["count_variable"] == fallback["as_of_variable"]:
        raise GateError("schema", "trusted_fallback variables must be distinct")
    max_age = require_positive_int(
        fallback.get("max_age_seconds"), "trusted_fallback.max_age_seconds"
    )
    if max_age > MAX_FALLBACK_AGE_SECONDS:
        raise GateError("schema", "trusted_fallback.max_age_seconds exceeds the ceiling")


def validate_exemptions(data: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    require_str(data.get("exemptions_version"), "exemptions_version")
    raw = data.get("exemptions")
    if not isinstance(raw, list):
        raise GateError("schema", "exemptions must be a list")
    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for idx, entry in enumerate(raw):
        obj = require_dict(entry, f"exemptions[{idx}]")
        eid = require_str(obj.get("id"), f"exemptions[{idx}].id")
        if eid in seen_ids:
            raise GateError("schema", f"duplicate exemption id {eid}")
        seen_ids.add(eid)
        issue = require_positive_int(obj.get("issue"), f"exemptions[{idx}].issue")
        tiers = require_str_list(
            obj.get("launch_tiers"), f"exemptions[{idx}].launch_tiers"
        )
        for field_name in ("owner", "approver", "rationale", "compensating_control"):
            value = require_str(obj.get(field_name), f"exemptions[{idx}].{field_name}")
            if field_name in ("owner", "approver") and not OWNER_RE.fullmatch(value):
                raise GateError("schema", f"exemptions[{idx}].{field_name} malformed")
        approved_at = parse_iso8601(
            obj.get("approved_at"), f"exemptions[{idx}].approved_at"
        )
        expires_at = parse_iso8601(
            obj.get("expires_at"), f"exemptions[{idx}].expires_at"
        )
        if expires_at <= approved_at:
            raise GateError(
                "schema", f"exemptions[{idx}] expires_at must be after approved_at"
            )
        validated.append(
            {
                "id": eid,
                "issue": issue,
                "launch_tiers": list(tiers),
                "owner": obj["owner"],
                "approver": obj["approver"],
                "rationale": obj["rationale"],
                "compensating_control": obj["compensating_control"],
                "approved_at": obj["approved_at"],
                "expires_at": obj["expires_at"],
                "expired": expires_at <= now,
            }
        )
    return validated


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


def github_token(env: Mapping[str, str]) -> str | None:
    token = env.get("GITHUB_TOKEN") or env.get("GH_TOKEN")
    if not isinstance(token, str) or not token.strip():
        return None
    return token.strip()


def auth_headers(token: str | None) -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def parse_link_next(link_header: str | None) -> str | None:
    if not link_header:
        return None
    # RFC 5988: <url>; rel="next"
    for part in link_header.split(","):
        piece = part.strip()
        if 'rel="next"' not in piece and "rel=next" not in piece:
            continue
        if piece.startswith("<") and ">" in piece:
            return piece[1 : piece.index(">")]
    return None


def http_get_json(
    url: str,
    token: str | None,
    *,
    opener: Callable[..., Any] | None = None,
    accept: str | None = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> tuple[Any, dict[str, str]]:
    if not url.startswith(API_ORIGIN):
        raise GateError("api", "refusing a non-GitHub API request")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise GateError("schema", "response size bound is malformed")
    headers = auth_headers(token)
    if accept:
        headers["Accept"] = accept
    request = urllib.request.Request(url, headers=headers)
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(request, timeout=30) as response:
            raw = response.read(max_bytes + 1)
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise GateError("denied", f"HTTP {exc.code}") from exc
        if exc.code == 429:
            raise GateError("rate_limit", "HTTP 429") from exc
        raise GateError("api", f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise GateError("api", f"transport failure ({type(exc).__name__})") from exc
    except GateError:
        raise
    except Exception as exc:  # noqa: BLE001 — fail closed on unexpected transport
        raise GateError("api", f"request failed ({type(exc).__name__})") from exc

    if status in (401, 403):
        raise GateError("denied", f"HTTP {status}")
    if not isinstance(raw, (bytes, bytearray)):
        raise GateError("schema", "response body is not bytes")
    if len(raw) > max_bytes:
        raise GateError("api", "response exceeded size cap")
    try:
        payload = json.loads(bytes(raw).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise GateError("schema", "malformed JSON response") from exc
    return payload, response_headers


def paginate(
    url: str,
    token: str | None,
    *,
    opener: Callable[..., Any] | None = None,
    accept: str | None = None,
    per_page: int = PER_PAGE,
    max_pages: int = MAX_PAGES,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> list[Any]:
    """Walk `Link: rel=next` to completion, failing closed on a truncated walk."""

    if not isinstance(max_pages, int) or isinstance(max_pages, bool) or max_pages < 1:
        raise GateError("schema", "pagination bound is malformed")
    items: list[Any] = []
    next_url: str | None = url
    pages = 0
    while next_url:
        pages += 1
        if pages > max_pages:
            raise GateError("pagination", "exceeded max pages without completion")
        payload, headers = http_get_json(
            next_url, token, opener=opener, accept=accept, max_bytes=max_bytes
        )
        if not isinstance(payload, list):
            raise GateError("schema", "expected a list page from the GitHub API")
        items.extend(payload)
        next_url = parse_link_next(headers.get("link"))
        if next_url is None and len(payload) >= per_page:
            # A full page with no continuation means the walk was truncated
            # somewhere; older items would be dropped silently.
            raise GateError("pagination", "full page without a continuation link")
        if next_url is not None and not next_url.startswith(API_ORIGIN):
            raise GateError("pagination", "continuation link left the GitHub API")
    return items


# ---------------------------------------------------------------------------
# Issue classification
# ---------------------------------------------------------------------------


def severity_from_labels(labels: set[str], policy: dict[str, Any]) -> str | None:
    """Return the single configured severity, or None when none is present."""

    severity_map = policy["labels"]["severity"]
    found = sorted(sev for sev, label in severity_map.items() if label in labels)
    if len(found) > 1:
        raise GateError("schema", "issue carries more than one severity label")
    return found[0] if found else None


def parse_issue_payload(
    payload: dict[str, Any],
    *,
    policy: dict[str, Any],
    tracked_severity: str | None,
    source: str,
) -> IssueRecord:
    number = payload.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise GateError("schema", "issue number malformed")
    if "pull_request" in payload:
        raise GateError("schema", f"#{number} is a pull request, not an issue")
    state = payload.get("state")
    if state not in {"open", "closed"}:
        raise GateError("schema", f"issue #{number} state malformed")
    state_reason = payload.get("state_reason")
    if state_reason is not None and not isinstance(state_reason, str):
        raise GateError("schema", f"issue #{number} state_reason malformed")
    label_items = payload.get("labels")
    if not isinstance(label_items, list):
        raise GateError("schema", f"issue #{number} labels malformed")
    labels: set[str] = set()
    for label in label_items:
        name = label.get("name") if isinstance(label, dict) else label
        if not isinstance(name, str) or not LIVE_LABEL_RE.fullmatch(name):
            raise GateError("schema", f"issue #{number} label name malformed")
        labels.add(name)

    label_severity = severity_from_labels(labels, policy)
    if tracked_severity is not None:
        # The reviewed, checked-in tracked severity is the contract. A live
        # label that disagrees is a schema mismatch, never a downgrade. Open
        # tracked blockers still need an explicit severity label: the tracked
        # list is defense in depth, not a substitute for the authoritative
        # labeled inventory. Closed historical entries need no backfill.
        if state == "open" and label_severity is None:
            raise GateError(
                "schema",
                f"issue #{number} is a launch blocker without exactly one severity label",
            )
        if label_severity is not None and label_severity != tracked_severity:
            raise GateError(
                "schema",
                f"issue #{number} severity label disagrees with the tracked contract",
            )
        severity = tracked_severity
    else:
        if label_severity is None:
            raise GateError(
                "schema",
                f"issue #{number} is a launch blocker without exactly one severity label",
            )
        severity = label_severity

    return IssueRecord(
        number=number,
        state=state,
        state_reason=state_reason,
        labels=labels,
        severity=severity,
        source=source,
    )


def classify_issue(
    record: IssueRecord,
    *,
    exemptions: list[dict[str, Any]],
    launch_tier: str,
    policy: dict[str, Any],
) -> str:
    active_exemptions = [
        ex
        for ex in exemptions
        if ex["issue"] == record.number
        and launch_tier in ex["launch_tiers"]
        and not ex["expired"]
    ]
    if active_exemptions:
        return "exempted"

    label_exempt = policy["labels"]["launch_exempted"]
    if label_exempt in record.labels:
        # An expired or absent structured exemption returns the issue to the
        # blocker set; the bare label may never clear one.
        raise GateError(
            "schema",
            f"issue #{record.number} carries {label_exempt} without an active exemption",
        )

    if record.state == "closed":
        if record.state_reason in set(policy["closed_completed_reasons"]):
            return "closed_completed"
        if record.state_reason in set(policy["closed_other_reasons"]):
            return "closed_other"
        raise GateError(
            "schema", f"issue #{record.number} has an unrecognized close reason"
        )

    if record.linked_merged_prs and not record.linked_open_prs:
        return "merged_awaiting_issue_close"
    if record.linked_open_prs:
        return "in_flight"
    return "open"


def blocking_classifications(policy: dict[str, Any]) -> set[str]:
    return {
        state
        for state, disposition in policy["state_machine"].items()
        if disposition == "blocking"
    }


def issue_public_summary(record: IssueRecord) -> dict[str, Any]:
    return {
        "issue": record.number,
        "severity": record.severity,
        "classification": record.classification,
        "state_reason": record.state_reason,
        "open_prs": list(record.linked_open_prs),
        "merged_prs": list(record.linked_merged_prs),
        "source": record.source,
    }


# ---------------------------------------------------------------------------
# GitHub fetchers
# ---------------------------------------------------------------------------


def fetch_issue(
    repo: str,
    number: int,
    token: str | None,
    *,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    url = f"{API_ORIGIN}repos/{repo}/issues/{number}"
    payload, _headers = http_get_json(url, token, opener=opener)
    if not isinstance(payload, dict):
        raise GateError("schema", "issue payload is not an object")
    return payload


def fetch_timeline_prs(
    repo: str,
    number: int,
    token: str | None,
    *,
    opener: Callable[..., Any] | None = None,
) -> tuple[list[int], list[int]]:
    """Return (open_pr_numbers, merged_pr_numbers) from timeline cross-links.

    Timeline bodies are untrusted; only numeric PR numbers and merged/state
    values are retained. Both in-flight and merged-awaiting-close classify as
    blocking, so an unreadable timeline can only ever leave an issue in the
    plain `open` blocking state — never clear it.
    """

    url = f"{API_ORIGIN}repos/{repo}/issues/{number}/timeline?per_page={PER_PAGE}"
    open_prs: list[int] = []
    merged_prs: list[int] = []
    next_url: str | None = url
    pages = 0
    while next_url:
        pages += 1
        if pages > MAX_PAGES:
            raise GateError("pagination", "timeline exceeded max pages")
        try:
            payload, headers = http_get_json(
                next_url,
                token,
                opener=opener,
                accept="application/vnd.github.mockingbird-preview+json",
            )
        except GateError as exc:
            if exc.code == "api" and exc.message in {
                "HTTP 404",
                "HTTP 406",
                "HTTP 410",
                "HTTP 415",
            }:
                return [], []
            raise
        if not isinstance(payload, list):
            raise GateError("schema", "timeline page must be a list")
        for event in payload:
            if not isinstance(event, dict):
                continue
            if event.get("event") != "cross-referenced":
                continue
            origin = event.get("source")
            if not isinstance(origin, dict):
                continue
            issue = origin.get("issue")
            if not isinstance(issue, dict):
                continue
            pull = issue.get("pull_request")
            if not isinstance(pull, dict):
                continue
            pr_number = issue.get("number")
            if (
                not isinstance(pr_number, int)
                or isinstance(pr_number, bool)
                or pr_number < 1
            ):
                continue
            merged_at = pull.get("merged_at")
            if isinstance(merged_at, str) and merged_at:
                if pr_number not in merged_prs:
                    merged_prs.append(pr_number)
            elif issue.get("state") == "open":
                if pr_number not in open_prs:
                    open_prs.append(pr_number)
        next_url = parse_link_next(headers.get("link"))
        if next_url is not None and not next_url.startswith(API_ORIGIN):
            raise GateError("pagination", "continuation link left the GitHub API")
    return [n for n in open_prs if n not in merged_prs], merged_prs


def configured_policy_labels(policy: dict[str, Any]) -> list[str]:
    """Every repository label the policy depends on, in a deterministic order."""

    labels = policy["labels"]
    names = [labels["launch_blocker"], labels["launch_exempted"]]
    names.extend(labels["severity"][sev] for sev in SEVERITIES)
    return names


def fetch_repository_label(
    repo: str,
    name: str,
    token: str | None,
    *,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Read one label definition from repository metadata."""

    url = f"{API_ORIGIN}repos/{repo}/labels/{urllib.parse.quote(name, safe='')}"
    payload, _headers = http_get_json(url, token, opener=opener)
    if not isinstance(payload, dict):
        raise GateError("schema", "repository label payload is not an object")
    return payload


def verify_repository_labels(
    repo: str,
    policy: dict[str, Any],
    token: str | None,
    *,
    opener: Callable[..., Any] | None = None,
    label_fetcher: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, int]:
    """Prove every configured blocker/exemption/severity label exists.

    The Issues API answers `labels=launch-blocker` with an empty list both when
    the label exists and matches nothing and when the label does not exist at
    all, so an empty labeled inventory is only meaningful once the vocabulary
    itself has been independently established. A missing definition, a renamed
    definition (GitHub resolves label lookups case-insensitively, so the
    returned name is compared exactly), or a malformed payload is
    `label_inventory` — never a clean empty set. Transport, permission, and
    rate-limit failures keep their own codes so an unreachable API is never
    reported as an absent label.

    Only the checked-in configured names are echoed; nothing from the response
    body reaches the record.
    """

    fetch = label_fetcher or fetch_repository_label
    verified: dict[str, int] = {}
    for name in configured_policy_labels(policy):
        try:
            payload = fetch(repo, name, token, opener=opener)
        except GateError as exc:
            if exc.code == "api" and exc.message == "HTTP 404":
                raise GateError(
                    LABEL_INVENTORY_CODE,
                    f"configured label {name} is not defined in repository metadata",
                ) from exc
            raise
        if not isinstance(payload, dict):
            raise GateError("schema", "repository label payload is not an object")
        live_name = payload.get("name")
        if not isinstance(live_name, str) or not LABEL_RE.fullmatch(live_name):
            raise GateError(
                "schema", f"repository label payload for {name} is malformed"
            )
        if live_name != name:
            raise GateError(
                LABEL_INVENTORY_CODE,
                f"configured label {name} resolves to a differently named repository label",
            )
        live_id = payload.get("id")
        if (
            not isinstance(live_id, int)
            or isinstance(live_id, bool)
            or live_id < 1
        ):
            raise GateError(
                "schema", f"repository label payload for {name} has a malformed id"
            )
        if live_id in verified.values():
            raise GateError(
                "schema", "repository label payload reuses one id for multiple names"
            )
        verified[name] = live_id
    return verified


def fetch_labeled_blocker_issues(
    repo: str,
    policy: dict[str, Any],
    token: str | None,
    *,
    blocker_label_id: int,
    opener: Callable[..., Any] | None = None,
) -> list[dict[str, Any]]:
    """Every issue carrying the verified launch-blocker label id.

    GitHub's `labels=<name>` filter can transiently return an empty inventory if
    that label is renamed during the request and then renamed back before the
    final metadata fence. Enumerate the unfiltered all-state issue set instead and
    select by the immutable id proven before the walk. The name carried beside
    that id must still match exactly; a rename is UNKNOWN rather than omission.

    Querying blocker+severity combinations would also silently omit a blocker
    whose severity label is missing or unrecognized, so severity remains a
    separate requirement applied after discovery.
    """

    if (
        not isinstance(blocker_label_id, int)
        or isinstance(blocker_label_id, bool)
        or blocker_label_id < 1
    ):
        raise GateError("schema", "verified blocker label id is malformed")
    blocker_name = policy["labels"]["launch_blocker"]
    query = urllib.parse.urlencode(
        {
            # `closed_other` is deliberately blocking. Restricting discovery to
            # open issues would silently drop a dynamically labeled issue closed
            # as duplicate/not-planned before the gate observed it.
            "state": "all",
            "per_page": str(PER_PAGE),
        }
    )
    url = f"{API_ORIGIN}repos/{repo}/issues?{query}"
    collected: list[dict[str, Any]] = []
    for item in paginate(
        url,
        token,
        opener=opener,
        max_pages=MAX_INVENTORY_PAGES,
        max_bytes=MAX_INVENTORY_RESPONSE_BYTES,
    ):
        if not isinstance(item, dict):
            raise GateError("schema", "issues page entry is not an object")
        if "pull_request" in item:
            # PR nodes share the issues API; they are never launch blockers.
            continue
        label_items = item.get("labels")
        if not isinstance(label_items, list):
            raise GateError("schema", "issue labels payload is not a list")
        carries_blocker = False
        for label in label_items:
            if not isinstance(label, dict):
                raise GateError("schema", "issue label payload is not an object")
            label_name = label.get("name")
            label_id = label.get("id")
            if not isinstance(label_name, str) or not LIVE_LABEL_RE.fullmatch(label_name):
                raise GateError("schema", "issue label name is malformed")
            if (
                not isinstance(label_id, int)
                or isinstance(label_id, bool)
                or label_id < 1
            ):
                raise GateError("schema", "issue label id is malformed")
            if label_name == blocker_name and label_id != blocker_label_id:
                raise GateError(
                    LABEL_INVENTORY_CODE,
                    "configured blocker label identity changed during issue discovery",
                )
            if label_id == blocker_label_id:
                if label_name != blocker_name:
                    raise GateError(
                        LABEL_INVENTORY_CODE,
                        "configured blocker label name changed during issue discovery",
                    )
                carries_blocker = True
        if carries_blocker:
            collected.append(item)
    return collected


def fetch_advisories(
    repo: str,
    token: str | None,
    *,
    opener: Callable[..., Any] | None = None,
) -> list[Any]:
    url = f"{API_ORIGIN}repos/{repo}/security-advisories?per_page={PER_PAGE}"
    return paginate(url, token, opener=opener)


# ---------------------------------------------------------------------------
# Private advisories (redacted count only)
# ---------------------------------------------------------------------------


def count_private_blockers(
    advisories: list[Any],
    *,
    policy: dict[str, Any],
    launch_tier: str,
) -> int:
    """Count blocking private advisories, failing closed on any schema problem.

    Only `state` and `severity` are read. A malformed entry, an unknown state,
    or an unknown severity is an error rather than a silently dropped row.
    """

    private = policy["private_advisories"]
    blocking_states = set(private["blocking_states"])
    closed_states = set(private["closed_states"])
    severities = set(private["blocking_severities_by_tier"][launch_tier])
    count = 0
    for item in advisories:
        if not isinstance(item, dict):
            raise GateError("schema", "advisory entry is not an object")
        state = item.get("state")
        severity = item.get("severity")
        if not isinstance(state, str) or not isinstance(severity, str):
            raise GateError("schema", "advisory entry is missing state or severity")
        if state not in blocking_states and state not in closed_states:
            raise GateError("schema", "advisory entry has an unrecognized state")
        if severity not in ADVISORY_SEVERITIES:
            raise GateError("schema", "advisory entry has an unrecognized severity")
        if state in blocking_states and severity in severities:
            count += 1
    return count


def resolve_trusted_fallback(
    *,
    policy: dict[str, Any],
    env: Mapping[str, str],
    now: datetime,
) -> PrivateBlockers:
    """Read the externally maintained redacted count and audit timestamp.

    These are repository Actions *variables*: a pull request can read them but
    cannot change them, so unlike a checked-in value they are not proof the PR
    author wrote. Missing, malformed, future-dated, or stale input is UNKNOWN.
    """

    fallback = policy["private_advisories"]["trusted_fallback"]
    raw_count = env.get(fallback["count_variable"], "")
    raw_as_of = env.get(fallback["as_of_variable"], "")
    if not isinstance(raw_count, str) or not raw_count.strip():
        raise GateError("private_fallback", "trusted private-advisory count is missing")
    if not isinstance(raw_as_of, str) or not raw_as_of.strip():
        raise GateError(
            "private_fallback", "trusted private-advisory audit time is missing"
        )
    count_text = raw_count.strip()
    if not COUNT_RE.fullmatch(count_text):
        raise GateError("private_fallback", "trusted private-advisory count is malformed")
    count = int(count_text)
    if count > MAX_FALLBACK_COUNT:
        raise GateError(
            "private_fallback", "trusted private-advisory count exceeds the ceiling"
        )
    try:
        as_of = parse_iso8601(raw_as_of.strip(), "trusted private-advisory audit time")
    except GateError as exc:
        raise GateError("private_fallback", exc.message) from exc
    age = (now - as_of).total_seconds()
    if age < 0:
        raise GateError(
            "private_fallback", "trusted private-advisory audit time is in the future"
        )
    if age > int(fallback["max_age_seconds"]):
        raise GateError("private_fallback", "trusted private-advisory audit time is stale")
    return PrivateBlockers(count=count, source="trusted_fallback", as_of=format_utc(as_of))


def resolve_private_blockers(
    *,
    policy: dict[str, Any],
    launch_tier: str,
    env: Mapping[str, str],
    now: datetime,
    opener: Callable[..., Any] | None = None,
    advisory_fetcher: Callable[..., list[Any]] | None = None,
) -> PrivateBlockers:
    """Live advisory API when a dedicated token exists, else trusted fallback.

    The Actions `GITHUB_TOKEN` cannot list private repository advisories even
    with `security-events: read`, so its absence is the normal case and must
    never be resolved from anything inside the pull request's own tree.
    """

    token_env = policy["private_advisories"]["live_api"]["token_env"]
    raw_token = env.get(token_env, "")
    token = raw_token.strip() if isinstance(raw_token, str) else ""
    if not token:
        return resolve_trusted_fallback(policy=policy, env=env, now=now)

    fetch = advisory_fetcher or fetch_advisories
    advisories = fetch(policy["repository"], token, opener=opener)
    if not isinstance(advisories, list):
        raise GateError("schema", "advisory listing is not a list")
    count = count_private_blockers(advisories, policy=policy, launch_tier=launch_tier)
    return PrivateBlockers(count=count, source="live_api", as_of=format_utc(now))


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def compute_verdict(
    records: list[IssueRecord],
    *,
    policy: dict[str, Any],
    private_blocker_count: int,
    unknown_reasons: list[str],
) -> str:
    if unknown_reasons:
        return "UNKNOWN"
    blocking = blocking_classifications(policy)
    if any(record.classification in blocking for record in records):
        return "FAIL"
    if private_blocker_count > 0:
        return "FAIL"
    return "PASS"


def build_evaluation(
    *,
    policy: dict[str, Any],
    records: list[IssueRecord],
    private: PrivateBlockers,
    launch_tier: str,
    target_sha: str,
    as_of: datetime,
    unknown_reasons: list[str],
) -> Evaluation:
    counts = {sev: 0 for sev in SEVERITIES}
    blocking_states = blocking_classifications(policy)
    blocking: list[dict[str, Any]] = []
    cleared: list[dict[str, Any]] = []
    exempted: list[dict[str, Any]] = []
    in_flight: list[dict[str, Any]] = []
    for record in records:
        summary = issue_public_summary(record)
        if record.classification == "exempted":
            exempted.append(summary)
        elif record.classification in blocking_states:
            blocking.append(summary)
            counts[record.severity] = counts.get(record.severity, 0) + 1
            if record.classification == "in_flight":
                in_flight.append(summary)
        else:
            cleared.append(summary)
    verdict = compute_verdict(
        records,
        policy=policy,
        private_blocker_count=private.count,
        unknown_reasons=unknown_reasons,
    )
    return Evaluation(
        verdict=verdict,
        launch_tier=launch_tier,
        target_sha=target_sha,
        as_of=format_utc(as_of),
        policy_version=str(policy["policy_version"]),
        classification_version=str(policy["classification_version"]),
        blocking_issues=blocking,
        cleared_issues=cleared,
        exempted_issues=exempted,
        in_flight=in_flight,
        counts_by_severity=counts,
        private_blocker_count=private.count,
        private_source=private.source,
        private_as_of=private.as_of,
        unknown_reasons=list(unknown_reasons),
    )


def unknown_evaluation(
    *,
    policy: dict[str, Any],
    launch_tier: str,
    target_sha: str,
    as_of: datetime,
    reasons: list[str],
) -> Evaluation:
    return build_evaluation(
        policy=policy,
        records=[],
        private=PrivateBlockers(count=0, source="unresolved", as_of=None),
        launch_tier=launch_tier,
        target_sha=target_sha,
        as_of=as_of,
        unknown_reasons=reasons,
    )


def evaluate_live(
    *,
    policy: dict[str, Any],
    exemptions: list[dict[str, Any]],
    launch_tier: str,
    target_sha: str,
    token: str | None,
    now: datetime,
    env: Mapping[str, str] | None = None,
    opener: Callable[..., Any] | None = None,
    issue_fetcher: Callable[..., dict[str, Any]] | None = None,
    timeline_fetcher: Callable[..., tuple[list[int], list[int]]] | None = None,
    labeled_fetcher: Callable[..., list[dict[str, Any]]] | None = None,
    label_fetcher: Callable[..., dict[str, Any]] | None = None,
    advisory_fetcher: Callable[..., list[Any]] | None = None,
) -> Evaluation:
    """Evaluate the live launch state at the injected instant `now`.

    `now` is the only clock: production passes `utc_now()`, tests pass a fixed
    instant, and every freshness decision is made against it, so a fixture can
    never be collapsed to UNKNOWN by the real wall clock.
    """

    environment: Mapping[str, str] = os.environ if env is None else env
    if launch_tier not in policy["tiers"]:
        return unknown_evaluation(
            policy=policy,
            launch_tier=launch_tier,
            target_sha=target_sha,
            as_of=now,
            reasons=["schema:unknown launch tier"],
        )
    if token is None:
        return unknown_evaluation(
            policy=policy,
            launch_tier=launch_tier,
            target_sha=target_sha,
            as_of=now,
            reasons=["token:no GitHub token available for issue state"],
        )

    blocking_severities = set(policy["tiers"][launch_tier]["blocking_severities"])
    repo = policy["repository"]
    issue_fetch = issue_fetcher or fetch_issue
    timeline_fetch = timeline_fetcher or fetch_timeline_prs
    labeled_fetch = labeled_fetcher or fetch_labeled_blocker_issues

    blocker_label = policy["labels"]["launch_blocker"]

    try:
        # Establish the label vocabulary from repository metadata BEFORE any
        # issue listing. Until this succeeds an empty labeled inventory carries
        # no information at all, so it may not be accepted as a clean set.
        initial_label_inventory = verify_repository_labels(
            repo, policy, token, opener=opener, label_fetcher=label_fetcher
        )

        tracked_severity = {
            int(entry["issue"]): str(entry["severity"])
            for entry in policy["tracked_blockers"]
        }
        by_number: dict[int, IssueRecord] = {}
        for number, severity in sorted(tracked_severity.items()):
            payload = issue_fetch(repo, number, token, opener=opener)
            if not isinstance(payload, dict):
                raise GateError("schema", "issue payload is not an object")
            record = parse_issue_payload(
                payload,
                policy=policy,
                tracked_severity=severity,
                source="tracked",
            )
            if record.state == "open" and blocker_label not in record.labels:
                # Defense in depth must not become a private inventory: an open
                # tracked blocker that was never classified into the labeled
                # inventory is unreconciled drift, not a silently covered case.
                raise GateError(
                    LABEL_DRIFT_CODE,
                    f"tracked blocker #{number} is open without the {blocker_label} label",
                )
            record.linked_open_prs, record.linked_merged_prs = timeline_fetch(
                repo, number, token, opener=opener
            )
            by_number[number] = record

        for payload in labeled_fetch(
            repo,
            policy,
            token,
            blocker_label_id=initial_label_inventory[blocker_label],
            opener=opener,
        ):
            if not isinstance(payload, dict):
                raise GateError("schema", "issues page entry is not an object")
            number = payload.get("number")
            if not isinstance(number, int) or isinstance(number, bool):
                raise GateError("schema", "labeled issue number malformed")
            record = parse_issue_payload(
                payload,
                policy=policy,
                tracked_severity=tracked_severity.get(number),
                source="tracked+label" if number in by_number else "label",
            )
            if blocker_label not in record.labels:
                raise GateError(
                    "schema", f"issue #{number} was returned without the blocker label"
                )
            if number in by_number:
                existing = by_number[number]
                record.linked_open_prs = existing.linked_open_prs
                record.linked_merged_prs = existing.linked_merged_prs
                record.labels |= existing.labels
            else:
                record.linked_open_prs, record.linked_merged_prs = timeline_fetch(
                    repo, number, token, opener=opener
                )
            by_number[number] = record

        # Fence deletion/rename/recreation during the issue walk. A label that
        # disappears after the first proof can make GitHub return an empty issue
        # list; comparing immutable label ids prevents that race from becoming
        # a false PASS, including delete-and-recreate under the same name.
        final_label_inventory = verify_repository_labels(
            repo, policy, token, opener=opener, label_fetcher=label_fetcher
        )
        if final_label_inventory != initial_label_inventory:
            raise GateError(
                LABEL_INVENTORY_CODE,
                "configured label identity changed during issue discovery",
            )

        records: list[IssueRecord] = []
        for record in sorted(by_number.values(), key=lambda item: item.number):
            if record.severity not in blocking_severities:
                record.classification = BELOW_TIER
            else:
                record.classification = classify_issue(
                    record,
                    exemptions=exemptions,
                    launch_tier=launch_tier,
                    policy=policy,
                )
            records.append(record)

        private = resolve_private_blockers(
            policy=policy,
            launch_tier=launch_tier,
            env=environment,
            now=now,
            opener=opener,
            advisory_fetcher=advisory_fetcher,
        )
    except GateError as exc:
        return unknown_evaluation(
            policy=policy,
            launch_tier=launch_tier,
            target_sha=target_sha,
            as_of=now,
            reasons=[f"{exc.code}:{exc.message}"],
        )

    return build_evaluation(
        policy=policy,
        records=records,
        private=private,
        launch_tier=launch_tier,
        target_sha=target_sha,
        as_of=now,
        unknown_reasons=[],
    )


# ---------------------------------------------------------------------------
# Document claim
# ---------------------------------------------------------------------------


def extract_document_claim(text: str, policy: dict[str, Any]) -> dict[str, Any]:
    begin = policy["document"]["marker_begin"]
    end = policy["document"]["marker_end"]
    if text.count(begin) != 1 or text.count(end) != 1:
        raise GateError("schema", "live readiness markers missing or duplicated")
    start = text.index(begin) + len(begin)
    stop = text.index(end)
    if stop < start:
        raise GateError("schema", "live readiness markers out of order")
    block = text[start:stop].strip()
    fence = re.search(r"```json\s*(\{.*?\})\s*```", block, re.DOTALL)
    raw = fence.group(1) if fence else block
    try:
        claim = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GateError("schema", "live readiness claim is not valid JSON") from exc
    claim_obj = require_dict(claim, "live readiness claim")
    verdict = require_str(claim_obj.get("verdict"), "claim.verdict")
    if verdict not in VERDICTS:
        raise GateError("schema", "claim.verdict invalid")
    require_str(claim_obj.get("policy_version"), "claim.policy_version")
    require_str(claim_obj.get("classification_version"), "claim.classification_version")
    require_str(claim_obj.get("launch_tier"), "claim.launch_tier")
    require_nonneg_int(
        claim_obj.get("private_blockers_redacted_count"),
        "claim.private_blockers_redacted_count",
    )
    counts = require_dict(claim_obj.get("counts_by_severity"), "claim.counts_by_severity")
    if set(counts) != set(SEVERITIES):
        raise GateError("schema", "claim.counts_by_severity must cover every severity")
    for sev in SEVERITIES:
        require_nonneg_int(counts.get(sev), f"claim.counts_by_severity.{sev}")
    return claim_obj


def assert_document_historical_separation(text: str, policy: dict[str, Any]) -> None:
    historical = policy["document"]["historical_marker"]
    if historical not in text:
        raise GateError("schema", "historical marker missing from the readiness document")
    begin = policy["document"]["marker_begin"]
    end = policy["document"]["marker_end"]
    if begin not in text or end not in text:
        raise GateError("schema", "live readiness markers missing")
    live_start = text.index(begin)
    live_end = text.index(end) + len(end)
    outside = text[:live_start] + text[live_end:]
    hist_idx = outside.find(historical)
    if hist_idx < 0:
        raise GateError("schema", "historical marker is inside the live block")
    pre_hist = outside[:hist_idx]
    forbidden = (
        "None blocking launch",
        "0 critical/high/medium findings; regression tests added",
    )
    for phrase in forbidden:
        if phrase in pre_hist:
            raise GateError(
                "schema",
                "unscoped clean-launch claim appears outside the live/historical sections",
            )


def verify_claim_against_evaluation(
    claim: dict[str, Any], evaluation: Evaluation
) -> list[str]:
    """Compare the reviewed checked-in snapshot with the live evaluated record.

    The claim is never a second source of truth: it may only agree. Every value
    is type-checked here so malformed input is an error, never an exception.
    """

    errors: list[str] = []
    if claim.get("verdict") != evaluation.verdict:
        errors.append(
            f"claimed verdict {claim.get('verdict')!r} does not match "
            f"computed {evaluation.verdict!r}"
        )
    if claim.get("policy_version") != evaluation.policy_version:
        errors.append("claimed policy_version mismatch")
    if claim.get("classification_version") != evaluation.classification_version:
        errors.append("claimed classification_version mismatch")
    if claim.get("launch_tier") != evaluation.launch_tier:
        errors.append("claimed launch_tier mismatch")

    claimed_private = claim.get("private_blockers_redacted_count")
    if not isinstance(claimed_private, int) or isinstance(claimed_private, bool):
        errors.append("claimed private redacted count is not an integer")
    elif claimed_private != evaluation.private_blocker_count:
        errors.append("claimed private redacted count mismatch")

    claimed_counts = claim.get("counts_by_severity")
    if not isinstance(claimed_counts, dict):
        errors.append("claimed counts_by_severity is not an object")
    else:
        for sev in SEVERITIES:
            value = claimed_counts.get(sev)
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(f"claimed {sev} count is not an integer")
            elif value != int(evaluation.counts_by_severity.get(sev, 0)):
                errors.append(f"claimed {sev} count mismatch")
    return errors


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def evaluation_public_dict(evaluation: Evaluation) -> dict[str, Any]:
    return {
        "verdict": evaluation.verdict,
        "launch_tier": evaluation.launch_tier,
        "target_sha": evaluation.target_sha,
        "as_of": evaluation.as_of,
        "policy_version": evaluation.policy_version,
        "classification_version": evaluation.classification_version,
        "counts_by_severity": evaluation.counts_by_severity,
        "blocking_issues": evaluation.blocking_issues,
        "in_flight": evaluation.in_flight,
        "exempted_issues": evaluation.exempted_issues,
        "cleared_issues": evaluation.cleared_issues,
        "private_blockers_redacted_count": evaluation.private_blocker_count,
        "private_blockers_source": evaluation.private_source,
        "private_blockers_as_of": evaluation.private_as_of,
        "unknown_reasons": evaluation.unknown_reasons,
    }


def safe_summary_text(evaluation: Evaluation) -> str:
    try:
        text = json.dumps(evaluation_public_dict(evaluation), indent=2, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise GateError("schema", "evaluation record is not serializable") from exc
    for banned in BANNED_OUTPUT_TOKENS:
        if banned in text:
            raise GateError("schema", "refusing to emit confidential advisory data")
    return text


def print_safe_summary(evaluation: Evaluation) -> None:
    print(safe_summary_text(evaluation))


def sanitize_line(text: str) -> str:
    # Never let a fixture name or API message forge a workflow command.
    return text.replace("\n", " ").replace("\r", " ").replace("::", ":")


# ---------------------------------------------------------------------------
# Checkout provenance
# ---------------------------------------------------------------------------


def resolve_git_dir(root: Path) -> Path:
    git_path = root / ".git"
    if git_path.is_dir():
        return git_path
    if git_path.is_file():
        text = read_text_file(git_path).strip()
        if not text.startswith("gitdir: "):
            raise GateError("io", "unreadable git directory pointer")
        pointer = Path(text[len("gitdir: ") :].strip())
        if not pointer.is_absolute():
            pointer = (root / pointer).resolve()
        return pointer
    raise GateError("io", "no git directory found for the checkout")


def resolve_checked_out_sha(root: Path) -> str:
    """Resolve HEAD without shelling out, failing closed when it is unreadable."""

    git_dir = resolve_git_dir(root)
    head = read_text_file(git_dir / "HEAD").strip()
    if SHA_RE.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        raise GateError("io", "unrecognized HEAD contents")
    ref = head[len("ref: ") :].strip()
    if not GIT_REF_RE.fullmatch(ref):
        raise GateError("io", "unrecognized HEAD reference")
    loose = git_dir / Path(*ref.split("/"))
    if loose.is_file():
        value = read_text_file(loose).strip()
        if SHA_RE.fullmatch(value):
            return value
        raise GateError("io", "loose reference is not a commit SHA")
    packed = git_dir / "packed-refs"
    if packed.is_file():
        for line in read_text_file(packed).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "^")):
                continue
            parts = stripped.split(" ", 1)
            if len(parts) == 2 and parts[1].strip() == ref and SHA_RE.fullmatch(parts[0]):
                return parts[0]
    raise GateError("io", "HEAD reference could not be resolved")


# ---------------------------------------------------------------------------
# Advisory-credential trust boundary
# ---------------------------------------------------------------------------


def advisory_token_present(env: Mapping[str, str]) -> bool:
    """True when a privileged advisory credential is in this environment.

    The value itself is never returned, stored, or logged — only its presence.
    """

    raw = env.get(ADVISORY_TOKEN_VAR, "")
    return isinstance(raw, str) and bool(raw.strip())


def advisory_execution_errors(
    *,
    trusted_execution: bool,
    explicit_target: bool,
    trusted_tree_sha: str,
    checked_out_sha: str | None,
    env: Mapping[str, str],
) -> list[str]:
    """Everything that disqualifies this invocation from using the credential.

    Issue #3802: a `v*` tag can point at any commit, and a tag-triggered job
    executes the tag's own copy of this checker. The credential therefore only
    belongs to an invocation that declares itself trusted AND proves the tree it
    is executing from is the pinned trusted anchor, with the commit under
    evaluation supplied separately as inert data. Every failure below is
    fail-closed and none of them interpolates the credential.
    """

    errors: list[str] = []
    token_present = advisory_token_present(env)
    if token_present and not trusted_execution:
        errors.append(
            "an advisory credential was supplied to an invocation that did not "
            "declare --trusted-execution; refusing to use it"
        )
    if not trusted_execution:
        return errors
    if not explicit_target:
        errors.append(
            "--trusted-execution requires an explicit target SHA; the candidate "
            "commit is data, never the executing tree"
        )
    if not SHA_RE.fullmatch(trusted_tree_sha or ""):
        errors.append(
            "--trusted-execution requires --trusted-tree-sha to name the trusted "
            "anchor commit"
        )
    elif checked_out_sha is None:
        errors.append("the executing tree could not be resolved to a commit")
    elif checked_out_sha != trusted_tree_sha:
        errors.append("the executing tree is not the pinned trusted anchor commit")
    return errors


# ---------------------------------------------------------------------------
# Deterministic fixture self-tests
# ---------------------------------------------------------------------------


FIXED_NOW = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
OTHER_NOW = datetime(2031, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
FRESH_AS_OF = "2026-08-10T12:00:00Z"
STALE_AS_OF = "2020-01-01T00:00:00Z"
FUTURE_AS_OF = "2026-08-12T12:00:00Z"
FALLBACK_COUNT_VAR = "LAUNCH_PRIVATE_BLOCKER_COUNT"
FALLBACK_AS_OF_VAR = "LAUNCH_PRIVATE_ADVISORY_AS_OF"
ADVISORY_TOKEN_VAR = "LAUNCH_ADVISORY_READ_TOKEN"


def _base_policy() -> dict[str, Any]:
    return {
        "policy_version": "1",
        "classification_version": "launch-blocker-v1",
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
        "tracked_blockers": [],
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
                "token_env": ADVISORY_TOKEN_VAR,
                "actions_security_events_permission_is_insufficient": True,
            },
            "trusted_fallback": {
                "count_variable": FALLBACK_COUNT_VAR,
                "as_of_variable": FALLBACK_AS_OF_VAR,
                "max_age_seconds": 604800,
            },
        },
        "document": {
            "path": "PRODUCTION_READINESS.md",
            "marker_begin": "<!-- launch-readiness:begin -->",
            "marker_end": "<!-- launch-readiness:end -->",
            "historical_marker": "<!-- launch-readiness:historical -->",
        },
        "exemptions_path": "docs/launch-exemptions.json",
    }


def _issue(
    number: int,
    *,
    state: str = "open",
    state_reason: str | None = None,
    labels: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "number": number,
        "state": state,
        "state_reason": state_reason,
        "labels": [{"name": name} for name in (labels or [])],
    }


def _fresh_env(count: str = "0") -> dict[str, str]:
    return {FALLBACK_COUNT_VAR: count, FALLBACK_AS_OF_VAR: FRESH_AS_OF}


def _label_fetcher(
    defined: set[str] | None = None,
    *,
    renamed: dict[str, str] | None = None,
    payloads: dict[str, Any] | None = None,
    asked: list[str] | None = None,
):
    """Fixture repository-label endpoint.

    `defined=None` means the whole configured vocabulary exists; pass an
    explicit set to model a deleted definition, `renamed` to model a label the
    lookup resolves to under a different name, and `payloads` to model a
    malformed body.
    """

    configured = configured_policy_labels(_base_policy())
    known = set(configured) if defined is None else defined
    ids = {name: index + 1 for index, name in enumerate(configured)}

    def _fetch(repo: str, name: str, token: str | None, opener=None):  # noqa: ARG001
        if asked is not None:
            asked.append(name)
        if payloads is not None and name in payloads:
            return payloads[name]
        if renamed is not None and name in renamed:
            return {"name": renamed[name], "id": ids[name]}
        if name not in known:
            raise GateError("api", "HTTP 404")
        return {"name": name, "id": ids[name], "color": "ededed"}

    return _fetch


def _issue_fetcher(payloads: dict[int, dict[str, Any]]):
    def _fetch(repo: str, number: int, token: str | None, opener=None):  # noqa: ARG001
        if number not in payloads:
            raise GateError("api", "HTTP 404")
        return payloads[number]

    return _fetch


def _timeline_fetcher(mapping: dict[int, tuple[list[int], list[int]]]):
    def _fetch(repo: str, number: int, token: str | None, opener=None):  # noqa: ARG001
        return mapping.get(number, ([], []))

    return _fetch


def _evaluate(
    policy: dict[str, Any],
    *,
    exemptions: list[dict[str, Any]] | None = None,
    launch_tier: str = "ga",
    now: datetime = FIXED_NOW,
    env: dict[str, str] | None = None,
    issues: dict[int, dict[str, Any]] | None = None,
    timelines: dict[int, tuple[list[int], list[int]]] | None = None,
    labeled: list[dict[str, Any]] | None = None,
    advisories: list[Any] | None = None,
    issue_fetcher=None,
    labeled_fetcher=None,
    label_fetcher=None,
    advisory_fetcher=None,
    token: str | None = "issues-token",
) -> Evaluation:
    return evaluate_live(
        policy=policy,
        exemptions=exemptions or [],
        launch_tier=launch_tier,
        target_sha="0" * 40,
        token=token,
        now=now,
        env=_fresh_env() if env is None else env,
        issue_fetcher=issue_fetcher or _issue_fetcher(issues or {}),
        timeline_fetcher=_timeline_fetcher(timelines or {}),
        labeled_fetcher=labeled_fetcher or (lambda *a, **k: list(labeled or [])),
        label_fetcher=label_fetcher or _label_fetcher(),
        advisory_fetcher=advisory_fetcher or (lambda *a, **k: list(advisories or [])),
    )


def _tracked(policy: dict[str, Any], number: int, severity: str) -> dict[str, Any]:
    policy["tracked_blockers"] = [
        {"issue": number, "severity": severity, "note": "fixture"}
    ]
    return policy


def run_self_test() -> int:  # noqa: C901 — a flat fixture table stays readable
    failures: list[str] = []

    def check(name: str, cond: Any, detail: str = "") -> None:
        if not cond:
            failures.append(f"{name}: {detail}" if detail else name)

    def unknown_because(evaluation: Evaluation, needle: str) -> bool:
        return evaluation.verdict == "UNKNOWN" and any(
            needle in reason for reason in evaluation.unknown_reasons
        )

    # ---- policy schema -----------------------------------------------------
    try:
        validate_policy(_base_policy())
        check("base policy validates", True)
    except GateError as exc:
        check("base policy validates", False, exc.message)

    schema_rejections: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("missing tier coverage", lambda p: p["tiers"].pop("beta")),
        (
            "advisory tier coverage",
            lambda p: p["private_advisories"]["blocking_severities_by_tier"].pop("beta"),
        ),
        (
            "unknown advisory state",
            lambda p: p["private_advisories"]["blocking_states"].append("bogus"),
        ),
        (
            "advisory state overlap",
            lambda p: p["private_advisories"]["blocking_states"].append("closed"),
        ),
        (
            "advisories disabled",
            lambda p: p["private_advisories"].__setitem__("enabled", False),
        ),
        (
            "checked-in private count",
            lambda p: p["private_advisories"].__setitem__(
                "opaque_input", {"redacted_blocking_count": 0}
            ),
        ),
        (
            "state machine downgrade",
            lambda p: p["state_machine"].__setitem__("in_flight", "cleared"),
        ),
        (
            "in-flight clears blocker",
            lambda p: p.__setitem__("in_flight_clears_blocker", True),
        ),
        (
            "merged clears blocker",
            lambda p: p.__setitem__(
                "merged_pr_clears_blocker_before_issue_close", True
            ),
        ),
        (
            "duplicate counted as completed",
            lambda p: p.__setitem__("closed_completed_reasons", ["completed", "duplicate"]),
        ),
        (
            "severity label coverage",
            lambda p: p["labels"]["severity"].pop("medium"),
        ),
        (
            "duplicate severity label names",
            lambda p: p["labels"]["severity"].__setitem__("medium", "severity:high"),
        ),
        (
            "blocker label reused as a severity label",
            lambda p: p["labels"]["severity"].__setitem__("medium", "launch-blocker"),
        ),
        (
            "exemption label equal to the blocker label",
            lambda p: p["labels"].__setitem__("launch_exempted", "launch-blocker"),
        ),
        (
            "never_emit incomplete",
            lambda p: p["private_advisories"].__setitem__("never_emit_fields", ["summary"]),
        ),
        (
            "fallback age ceiling",
            lambda p: p["private_advisories"]["trusted_fallback"].__setitem__(
                "max_age_seconds", MAX_FALLBACK_AGE_SECONDS + 1
            ),
        ),
        (
            "security-events sufficiency claim",
            lambda p: p["private_advisories"]["live_api"].__setitem__(
                "actions_security_events_permission_is_insufficient", False
            ),
        ),
    ]
    for name, mutate in schema_rejections:
        policy = _base_policy()
        mutate(policy)
        try:
            validate_policy(policy)
            check(f"policy rejects {name}", False, "expected a schema error")
        except GateError:
            check(f"policy rejects {name}", True)

    # ---- exemption schema --------------------------------------------------
    def exemption(**overrides: Any) -> dict[str, Any]:
        base = {
            "id": "ex-1",
            "issue": 5001,
            "launch_tiers": ["ga"],
            "owner": "owner1",
            "approver": "approver1",
            "rationale": "path disabled behind a flag",
            "compensating_control": "feature flag off",
            "approved_at": "2026-08-01T00:00:00Z",
            "expires_at": "2026-12-01T00:00:00Z",
        }
        base.update(overrides)
        return base

    for name, entry in (
        ("equal expiry", exemption(expires_at="2026-08-01T00:00:00Z")),
        ("malformed issue", exemption(issue="x")),
        ("malformed owner", exemption(owner="not a login!")),
        ("malformed timestamp", exemption(approved_at="2026-08-01")),
    ):
        try:
            validate_exemptions(
                {"exemptions_version": "1", "exemptions": [entry]}, FIXED_NOW
            )
            check(f"exemptions reject {name}", False, "expected a schema error")
        except GateError:
            check(f"exemptions reject {name}", True)

    expired = validate_exemptions(
        {
            "exemptions_version": "1",
            "exemptions": [
                exemption(
                    approved_at="2026-01-01T00:00:00Z",
                    expires_at="2026-02-01T00:00:00Z",
                )
            ],
        },
        FIXED_NOW,
    )
    check("expired exemption marked", expired[0]["expired"] is True)
    active = validate_exemptions(
        {"exemptions_version": "1", "exemptions": [exemption()]}, FIXED_NOW
    )
    check("active exemption marked", active[0]["expired"] is False)

    # ---- label inventory boundary ------------------------------------------
    # An empty `labels=launch-blocker` listing is indistinguishable from a label
    # that does not exist, so every configured name must be proven present in
    # repository metadata before an empty inventory may be accepted.
    all_labels = set(configured_policy_labels(_base_policy()))
    check(
        "configured vocabulary is the five policy labels",
        configured_policy_labels(_base_policy())
        == [
            "launch-blocker",
            "launch-exempted",
            "severity:critical",
            "severity:high",
            "severity:medium",
        ],
        str(configured_policy_labels(_base_policy())),
    )

    asked: list[str] = []
    verified = verify_repository_labels(
        "ferrum-edge/ferrum-edge",
        _base_policy(),
        "tok",
        label_fetcher=_label_fetcher(asked=asked),
    )
    check("every configured label is verified", set(verified) == all_labels, str(verified))
    check("every configured label is queried", set(asked) == all_labels, str(asked))

    duplicate_ids = {
        name: {"name": name, "id": 1}
        for name in configured_policy_labels(_base_policy())
    }
    ev = _evaluate(
        _base_policy(), label_fetcher=_label_fetcher(payloads=duplicate_ids)
    )
    check(
        "one label id cannot represent multiple configured names",
        unknown_because(ev, "reuses one id for multiple names"),
        str(ev.unknown_reasons),
    )

    # Each individual definition is load-bearing: deleting any one is UNKNOWN.
    for missing in sorted(all_labels):
        ev = _evaluate(
            _base_policy(), label_fetcher=_label_fetcher(all_labels - {missing})
        )
        check(
            f"absent label {missing} is UNKNOWN",
            unknown_because(ev, f"configured label {missing} is not defined"),
            str(ev.unknown_reasons),
        )
        check(
            f"absent label {missing} is not a clean PASS",
            ev.verdict == "UNKNOWN" and ev.counts_by_severity == {s: 0 for s in SEVERITIES},
            ev.verdict,
        )

    # A rename (including a case-only rename, which GitHub's case-insensitive
    # label lookup would otherwise resolve happily) is UNKNOWN, not a clean set.
    for renamed_from, renamed_to in (
        ("launch-blocker", "launch-blocker-v2"),
        ("launch-blocker", "Launch-Blocker"),
        ("severity:high", "severity-high"),
        ("launch-exempted", "launch-exempt"),
    ):
        ev = _evaluate(
            _base_policy(),
            label_fetcher=_label_fetcher(renamed={renamed_from: renamed_to}),
        )
        check(
            f"renamed label {renamed_from}->{renamed_to} is UNKNOWN",
            unknown_because(ev, f"configured label {renamed_from} resolves to a"),
            str(ev.unknown_reasons),
        )

    # A malformed label payload fails closed as a schema error.
    for name, bad_payload in (
        ("non-object", "not-an-object"),
        ("missing name", {"id": 7}),
        ("non-string name", {"name": 7}),
        ("malformed name", {"name": "not a label!"}),
        ("missing id", {"name": "launch-blocker"}),
        ("non-integer id", {"name": "launch-blocker", "id": "7"}),
    ):
        ev = _evaluate(
            _base_policy(),
            label_fetcher=_label_fetcher(payloads={"launch-blocker": bad_payload}),
        )
        check(
            f"malformed label payload ({name}) is UNKNOWN",
            unknown_because(ev, "repository label payload"),
            str(ev.unknown_reasons),
        )

    # An API/permission failure on the label endpoint stays distinct from an
    # absent definition: an unreachable API is never reported as a missing label.
    for code, message, needle in (
        ("api", "HTTP 500", "HTTP 500"),
        ("denied", "HTTP 403", "HTTP 403"),
        ("rate_limit", "HTTP 429", "HTTP 429"),
    ):

        def failing_labels(*a, _code=code, _message=message, **k):  # noqa: ARG001
            raise GateError(_code, _message)

        ev = _evaluate(_base_policy(), label_fetcher=failing_labels)
        check(
            f"label endpoint {message} is UNKNOWN",
            unknown_because(ev, needle),
            str(ev.unknown_reasons),
        )
        check(
            f"label endpoint {message} is not reported as an absent label",
            not any("is not defined" in r for r in ev.unknown_reasons),
            str(ev.unknown_reasons),
        )

    # Existing-but-empty is the one case that may be accepted, and only after
    # the vocabulary has been proven.
    empty_inventory_calls: list[int] = []

    def empty_labeled(*a, **k):  # noqa: ARG001
        empty_inventory_calls.append(1)
        return []

    ev = _evaluate(_base_policy(), labeled_fetcher=empty_labeled)
    check("existing but empty label inventory passes", ev.verdict == "PASS", ev.verdict)
    check("empty inventory was actually queried", empty_inventory_calls == [1])

    # A definition deleted/recreated while the issue pages are read must not
    # turn a temporarily empty listing into PASS. Identity is fenced by id.
    inventory_reads: dict[str, int] = {}

    stable_ids = {
        name: index + 1
        for index, name in enumerate(configured_policy_labels(_base_policy()))
    }

    def replaced_label(repo, name, token, opener=None):  # noqa: ARG001
        inventory_reads[name] = inventory_reads.get(name, 0) + 1
        live_id = stable_ids[name]
        if name == "launch-blocker" and inventory_reads[name] > 1:
            live_id += 100
        return {"name": name, "id": live_id}

    ev = _evaluate(_base_policy(), label_fetcher=replaced_label)
    check(
        "label replacement during issue discovery is UNKNOWN",
        unknown_because(ev, "label identity changed during issue discovery"),
        str(ev.unknown_reasons),
    )

    # ...and label verification runs BEFORE issue discovery, so a missing
    # definition never even reaches the issue listing.
    unreached: list[int] = []

    def must_not_run(*a, **k):  # noqa: ARG001
        unreached.append(1)
        return []

    ev = _evaluate(
        _base_policy(),
        labeled_fetcher=must_not_run,
        label_fetcher=_label_fetcher(all_labels - {"launch-blocker"}),
    )
    check(
        "missing definition short-circuits issue discovery",
        ev.verdict == "UNKNOWN" and unreached == [],
        str(unreached),
    )

    # A newly filed labeled blocker is discovered without editing
    # tracked_blockers, and is additive to the tracked inventory.
    policy = _tracked(_base_policy(), 1200, "critical")
    ev = _evaluate(
        policy,
        issues={1200: _issue(1200, labels=["launch-blocker", "severity:critical"])},
        labeled=[
            _issue(1200, labels=["launch-blocker", "severity:critical"]),
            _issue(1201, labels=["launch-blocker", "severity:medium"]),
        ],
    )
    check("untracked labeled blocker fails the gate", ev.verdict == "FAIL", ev.verdict)
    check(
        "untracked labeled blocker is counted",
        ev.counts_by_severity == {"critical": 1, "high": 0, "medium": 1},
        str(ev.counts_by_severity),
    )
    check(
        "untracked labeled blocker is attributed to the label source",
        [i["source"] for i in ev.blocking_issues] == ["tracked+label", "label"],
        str([i["source"] for i in ev.blocking_issues]),
    )

    # tracked_blockers stays defense in depth, but may not become a private
    # inventory: an open tracked blocker missing the label is unreconciled.
    policy = _tracked(_base_policy(), 1210, "high")
    ev = _evaluate(policy, issues={1210: _issue(1210, labels=["severity:high"])})
    check(
        "unlabeled open tracked blocker is UNKNOWN",
        unknown_because(ev, "#1210 is open without the launch-blocker label"),
        str(ev.unknown_reasons),
    )
    policy = _tracked(_base_policy(), 1211, "high")
    ev = _evaluate(
        policy,
        issues={1211: _issue(1211, state="closed", state_reason="completed")},
    )
    check(
        "closed tracked blocker needs no label backfill",
        ev.verdict == "PASS",
        str(ev.unknown_reasons),
    )

    # ---- severity discovery ------------------------------------------------
    labeled_missing_severity = [_issue(1100, labels=["launch-blocker"])]
    ev = _evaluate(_base_policy(), labeled=labeled_missing_severity)
    check(
        "missing severity is UNKNOWN",
        unknown_because(ev, "without exactly one severity label"),
        str(ev.unknown_reasons),
    )

    labeled_ambiguous = [
        _issue(1101, labels=["launch-blocker", "severity:high", "severity:medium"])
    ]
    ev = _evaluate(_base_policy(), labeled=labeled_ambiguous)
    check(
        "ambiguous severity is UNKNOWN",
        unknown_because(ev, "more than one severity label"),
        str(ev.unknown_reasons),
    )

    # A severity-shaped label that is not the configured vocabulary is not a
    # severity: it leaves the blocker with zero severities, which is UNKNOWN.
    ev = _evaluate(
        _base_policy(),
        labeled=[_issue(1103, labels=["launch-blocker", "severity:low"])],
    )
    check(
        "unconfigured severity label is UNKNOWN",
        unknown_because(ev, "without exactly one severity label"),
        str(ev.unknown_reasons),
    )

    ev = _evaluate(
        _base_policy(),
        labeled=[_issue(1102, labels=["launch-blocker", "severity:high"])],
    )
    check("labeled blocker fails", ev.verdict == "FAIL", ev.verdict)
    check("labeled severity counted", ev.counts_by_severity["high"] == 1)

    # ---- tracked severity contract ----------------------------------------
    policy = _tracked(_base_policy(), 2001, "critical")
    ev = _evaluate(
        policy,
        issues={2001: _issue(2001, labels=["launch-blocker", "severity:critical"])},
    )
    check("tracked critical fails", ev.verdict == "FAIL", ev.verdict)
    check("tracked critical counted", ev.counts_by_severity["critical"] == 1)

    policy = _tracked(_base_policy(), 2002, "critical")
    ev = _evaluate(
        policy,
        issues={2002: _issue(2002, labels=["launch-blocker", "severity:medium"])},
    )
    check(
        "tracked severity mismatch is UNKNOWN",
        unknown_because(ev, "disagrees with the tracked contract"),
        str(ev.unknown_reasons),
    )

    policy = _tracked(_base_policy(), 2003, "high")
    ev = _evaluate(policy, issues={2003: _issue(2003, labels=["launch-blocker"])})
    check(
        "open tracked blocker without severity is UNKNOWN",
        unknown_because(ev, "without exactly one severity label"),
        str(ev.unknown_reasons),
    )

    policy = _tracked(_base_policy(), 2004, "high")
    ev = _evaluate(
        policy,
        issues={2004: _issue(2004, labels=["launch-blocker", "severity:high"])},
        labeled=[_issue(2004, labels=["launch-blocker", "severity:critical"])],
    )
    check(
        "labeled override of tracked severity is UNKNOWN",
        unknown_because(ev, "disagrees with the tracked contract"),
        str(ev.unknown_reasons),
    )

    # ---- tiers -------------------------------------------------------------
    for sev in SEVERITIES:
        policy = _tracked(_base_policy(), 2100, sev)
        ev = _evaluate(
            policy,
            issues={2100: _issue(2100, labels=["launch-blocker", f"severity:{sev}"])},
        )
        check(f"ga blocks {sev}", ev.verdict == "FAIL", ev.verdict)

    policy = _tracked(_base_policy(), 2101, "medium")
    ev = _evaluate(
        policy,
        launch_tier="experimental",
        issues={2101: _issue(2101, labels=["launch-blocker", "severity:medium"])},
    )
    check("experimental ignores medium", ev.verdict == "PASS", ev.verdict)
    policy = _tracked(_base_policy(), 2102, "high")
    ev = _evaluate(
        policy,
        launch_tier="beta",
        issues={2102: _issue(2102, labels=["launch-blocker", "severity:high"])},
    )
    check("beta blocks high", ev.verdict == "FAIL", ev.verdict)

    # ---- issue state machine ----------------------------------------------
    policy = _tracked(_base_policy(), 3001, "high")
    ev = _evaluate(
        policy,
        issues={3001: _issue(3001, labels=["launch-blocker", "severity:high"])},
        timelines={3001: ([555], [])},
    )
    check("open PR does not clear", ev.verdict == "FAIL", ev.verdict)
    check(
        "in_flight classified",
        ev.in_flight and ev.in_flight[0]["classification"] == "in_flight",
        str(ev.in_flight),
    )

    ev = _evaluate(
        policy,
        issues={3001: _issue(3001, labels=["launch-blocker", "severity:high"])},
        timelines={3001: ([], [556])},
    )
    check(
        "merged awaiting close blocks",
        ev.verdict == "FAIL"
        and ev.blocking_issues
        and ev.blocking_issues[0]["classification"] == "merged_awaiting_issue_close",
        str(ev.blocking_issues),
    )

    policy = _tracked(_base_policy(), 4001, "high")
    ev = _evaluate(
        policy,
        issues={4001: _issue(4001, state="closed", state_reason="completed")},
    )
    check("closed completed clears", ev.verdict == "PASS", ev.verdict)

    for reason in ("duplicate", "not_planned", None):
        policy = _tracked(_base_policy(), 4002, "high")
        ev = _evaluate(
            policy,
            issues={4002: _issue(4002, state="closed", state_reason=reason)},
        )
        check(
            f"closed_other {reason!r} blocks",
            ev.verdict == "FAIL"
            and ev.blocking_issues
            and ev.blocking_issues[0]["classification"] == "closed_other",
            str(ev.verdict),
        )

    policy = _tracked(_base_policy(), 4003, "high")
    ev = _evaluate(
        policy,
        issues={4003: _issue(4003, state="closed", state_reason="reopened")},
    )
    check(
        "unknown close reason is UNKNOWN",
        unknown_because(ev, "unrecognized close reason"),
        str(ev.unknown_reasons),
    )

    # ---- exemptions --------------------------------------------------------
    policy = _tracked(_base_policy(), 5001, "high")
    valid_exemption = validate_exemptions(
        {"exemptions_version": "1", "exemptions": [exemption()]}, FIXED_NOW
    )
    ev = _evaluate(
        policy,
        exemptions=valid_exemption,
        issues={5001: _issue(5001, labels=["launch-blocker", "severity:high"])},
    )
    check("active exemption clears", ev.verdict == "PASS", ev.verdict)
    check("exemption reported", len(ev.exempted_issues) == 1)

    stale_exemption = validate_exemptions(
        {
            "exemptions_version": "1",
            "exemptions": [exemption(expires_at="2026-08-05T00:00:00Z")],
        },
        FIXED_NOW,
    )
    ev = _evaluate(
        policy,
        exemptions=stale_exemption,
        issues={5001: _issue(5001, labels=["launch-blocker", "severity:high"])},
    )
    check("expired exemption blocks", ev.verdict == "FAIL", ev.verdict)

    ev = _evaluate(
        policy,
        issues={
            5001: _issue(
                5001,
                labels=["launch-blocker", "launch-exempted", "severity:high"],
            )
        },
    )
    check(
        "bare exempt label is UNKNOWN",
        unknown_because(ev, "without an active exemption"),
        str(ev.unknown_reasons),
    )

    # ---- deterministic clock ----------------------------------------------
    policy = _tracked(_base_policy(), 6001, "high")
    first = _evaluate(
        policy,
        issues={6001: _issue(6001, labels=["launch-blocker", "severity:high"])},
        now=FIXED_NOW,
    )
    second = _evaluate(
        policy,
        issues={6001: _issue(6001, labels=["launch-blocker", "severity:high"])},
        now=OTHER_NOW,
        env={FALLBACK_COUNT_VAR: "0", FALLBACK_AS_OF_VAR: format_utc(OTHER_NOW)},
    )
    check("clock injection is deterministic", first.verdict == second.verdict == "FAIL")
    check("as_of follows the injected clock", first.as_of == "2026-08-11T12:00:00Z")
    check("second as_of follows its clock", second.as_of == "2031-03-04T05:06:07Z")

    # ---- private advisories: trusted fallback ------------------------------
    base = _base_policy()
    ev = _evaluate(base, env={})
    check(
        "missing fallback is UNKNOWN",
        unknown_because(ev, "count is missing"),
        str(ev.unknown_reasons),
    )
    ev = _evaluate(base, env={FALLBACK_COUNT_VAR: "0"})
    check(
        "missing fallback timestamp is UNKNOWN",
        unknown_because(ev, "audit time is missing"),
        str(ev.unknown_reasons),
    )
    for bad in ("zero", "-1", "1.5", " 1 2", "0x1"):
        ev = _evaluate(base, env={FALLBACK_COUNT_VAR: bad, FALLBACK_AS_OF_VAR: FRESH_AS_OF})
        check(
            f"malformed fallback count {bad!r} is UNKNOWN",
            unknown_because(ev, "count is malformed"),
            str(ev.unknown_reasons),
        )
    ev = _evaluate(
        base, env={FALLBACK_COUNT_VAR: "0", FALLBACK_AS_OF_VAR: "not-a-timestamp"}
    )
    check(
        "malformed fallback timestamp is UNKNOWN",
        unknown_because(ev, "audit time"),
        str(ev.unknown_reasons),
    )
    ev = _evaluate(base, env={FALLBACK_COUNT_VAR: "0", FALLBACK_AS_OF_VAR: STALE_AS_OF})
    check(
        "stale fallback is UNKNOWN",
        unknown_because(ev, "stale"),
        str(ev.unknown_reasons),
    )
    ev = _evaluate(base, env={FALLBACK_COUNT_VAR: "0", FALLBACK_AS_OF_VAR: FUTURE_AS_OF})
    check(
        "future fallback is UNKNOWN",
        unknown_because(ev, "in the future"),
        str(ev.unknown_reasons),
    )
    ev = _evaluate(base, env=_fresh_env("0"))
    check("fresh external zero clears", ev.verdict == "PASS", ev.verdict)
    check("fallback source reported", ev.private_source == "trusted_fallback")
    check("fallback as_of reported", ev.private_as_of == "2026-08-10T12:00:00Z")
    ev = _evaluate(base, env=_fresh_env("2"))
    check("fresh external positive fails", ev.verdict == "FAIL", ev.verdict)
    check("fallback count surfaced", ev.private_blocker_count == 2)

    # A checked-in policy can no longer assert zero private blockers at all.
    check(
        "policy carries no private count",
        contains_forbidden_key(_base_policy()) is None,
    )

    # ---- private advisories: live API -------------------------------------
    live_env = {ADVISORY_TOKEN_VAR: "advisory-token"}
    advisories = [
        {
            "ghsa_id": "GHSA-fixture-draft",
            "summary": "confidential fixture text",
            "state": "draft",
            "severity": "high",
            "html_url": "https://example.invalid/fixture",
        },
        {"ghsa_id": "GHSA-fixture-closed", "state": "closed", "severity": "critical"},
        {"state": "published", "severity": "low"},
    ]
    ev = _evaluate(base, env=live_env, advisories=advisories)
    check("live draft advisory fails", ev.verdict == "FAIL", ev.verdict)
    check("live count redacted", ev.private_blocker_count == 1)
    check("live source reported", ev.private_source == "live_api")
    rendered = safe_summary_text(ev)
    check("no advisory identifier emitted", "GHSA-" not in rendered)
    check("no advisory text emitted", "confidential" not in rendered)
    check("no advisory link emitted", "example.invalid" not in rendered)

    ev = _evaluate(base, env=live_env, advisories=[{"state": "closed", "severity": "low"}])
    check("live closed advisory clears", ev.verdict == "PASS", ev.verdict)

    for bad_entry, needle in (
        ("not-an-object", "not an object"),
        ({"state": "draft"}, "missing state or severity"),
        ({"state": "unheard-of", "severity": "high"}, "unrecognized state"),
        ({"state": "draft", "severity": "catastrophic"}, "unrecognized severity"),
    ):
        ev = _evaluate(base, env=live_env, advisories=[bad_entry])
        check(
            f"malformed advisory {needle} is UNKNOWN",
            unknown_because(ev, needle),
            str(ev.unknown_reasons),
        )

    def denied_advisories(*a, **k):  # noqa: ARG001
        raise GateError("denied", "HTTP 403")

    ev = _evaluate(base, env=live_env, advisory_fetcher=denied_advisories)
    check(
        "denied live advisories is UNKNOWN",
        unknown_because(ev, "HTTP 403"),
        str(ev.unknown_reasons),
    )

    def paginated_out(*a, **k):  # noqa: ARG001
        raise GateError("pagination", "full page without a continuation link")

    ev = _evaluate(base, env=live_env, advisory_fetcher=paginated_out)
    check(
        "incomplete advisory pagination is UNKNOWN",
        unknown_because(ev, "continuation link"),
        str(ev.unknown_reasons),
    )

    # Tier scoping of advisory severities.
    ev = _evaluate(
        base,
        launch_tier="experimental",
        env=live_env,
        advisories=[{"state": "triage", "severity": "medium"}],
    )
    check("experimental ignores medium advisory", ev.verdict == "PASS", ev.verdict)

    # ---- issue API failures ------------------------------------------------
    policy = _tracked(_base_policy(), 7001, "high")

    def boom(*a, **k):  # noqa: ARG001
        raise GateError("api", "HTTP 500")

    ev = _evaluate(policy, issue_fetcher=boom)
    check("issue API failure is UNKNOWN", unknown_because(ev, "HTTP 500"))

    def rate_limited(*a, **k):  # noqa: ARG001
        raise GateError("rate_limit", "HTTP 429")

    ev = _evaluate(policy, issue_fetcher=rate_limited)
    check("issue rate limit is UNKNOWN", unknown_because(ev, "HTTP 429"))

    def labeled_paginated_out(*a, **k):  # noqa: ARG001
        raise GateError("pagination", "exceeded max pages without completion")

    ev = _evaluate(_base_policy(), labeled_fetcher=labeled_paginated_out)
    check("issue pagination failure is UNKNOWN", unknown_because(ev, "max pages"))

    ev = _evaluate(_base_policy(), token=None)
    check("missing issue token is UNKNOWN", unknown_because(ev, "token"))

    ev = _evaluate(_base_policy(), launch_tier="nonexistent")
    check("unknown tier is UNKNOWN", unknown_because(ev, "unknown launch tier"))

    # ---- pagination helper -------------------------------------------------
    def page_opener(pages: dict[str, tuple[list[Any], dict[str, str]]]):
        class Opener:
            def __call__(self, request: urllib.request.Request, timeout: int = 30):  # noqa: ARG002
                url = request.full_url
                if url not in pages:
                    raise AssertionError("unexpected fixture URL")
                body, headers = pages[url]

                class Resp:
                    status = 200

                    def __init__(self) -> None:
                        self._body = json.dumps(body).encode()
                        self.headers = headers

                    def read(self, n: int = -1):
                        return self._body if n < 0 else self._body[:n]

                    def __enter__(self):
                        return self

                    def __exit__(self, *a):
                        return False

                return Resp()

        return Opener()

    first_url = f"{API_ORIGIN}items?page=1"
    second_url = f"{API_ORIGIN}items?page=2"
    opener = page_opener(
        {
            first_url: ([{"n": 1}, {"n": 2}], {"link": f'<{second_url}>; rel="next"'}),
            second_url: ([{"n": 3}], {}),
        }
    )
    items = paginate(first_url, "tok", opener=opener, per_page=2)
    check("pagination aggregates pages", [i["n"] for i in items] == [1, 2, 3])

    for bad_bound in (0, -1, True, "1048576"):
        try:
            http_get_json(first_url, "tok", opener=opener, max_bytes=bad_bound)
            check(f"malformed byte bound {bad_bound!r} refused", False)
        except GateError as exc:
            check(
                f"malformed byte bound {bad_bound!r} refused",
                exc.code == "schema",
                exc.message,
            )

    try:
        paginate(first_url, "tok", opener=opener, per_page=2, max_pages=1)
        check("caller page bound is enforced", False)
    except GateError as exc:
        check("caller page bound is enforced", exc.code == "pagination", exc.message)

    for bad_bound in (0, -1, True, "50"):
        try:
            paginate(first_url, "tok", opener=opener, per_page=2, max_pages=bad_bound)
            check(f"malformed page bound {bad_bound!r} refused", False)
        except GateError as exc:
            check(
                f"malformed page bound {bad_bound!r} refused",
                exc.code == "schema",
                exc.message,
            )

    truncated = page_opener({first_url: ([{"n": 1}, {"n": 2}], {})})
    try:
        paginate(first_url, "tok", opener=truncated, per_page=2)
        check("pagination rejects truncation", False)
    except GateError as exc:
        check("pagination rejects truncation", exc.code == "pagination", exc.message)

    off_site = page_opener(
        {first_url: ([{"n": 1}], {"link": '<https://example.invalid/x>; rel="next"'})}
    )
    try:
        paginate(first_url, "tok", opener=off_site, per_page=2)
        check("pagination rejects foreign links", False)
    except GateError:
        check("pagination rejects foreign links", True)

    not_a_list = page_opener({first_url: ({"not": "a list"}, {})})  # type: ignore[arg-type]
    try:
        paginate(first_url, "tok", opener=not_a_list, per_page=2)
        check("pagination rejects non-list pages", False)
    except GateError as exc:
        check("pagination rejects non-list pages", exc.code == "schema", exc.message)

    try:
        http_get_json("https://example.invalid/x", "tok", opener=opener)
        check("non-GitHub request refused", False)
    except GateError:
        check("non-GitHub request refused", True)

    # ---- label discovery walks every issue page and drops PR nodes ----------
    label_query = urllib.parse.urlencode(
        {"state": "all", "per_page": str(PER_PAGE)}
    )
    label_page_one = f"{API_ORIGIN}repos/ferrum-edge/ferrum-edge/issues?{label_query}"
    label_page_two = f"{label_page_one}&page=2"
    label_opener = page_opener(
        {
            label_page_one: (
                [
                    {
                        **_issue(9001),
                        "labels": [
                            {"name": "launch-blocker", "id": 41},
                            {"name": "severity:high", "id": 42},
                            {"name": "good first issue 🚀", "id": 44},
                        ],
                    },
                    {
                        **_issue(9002),
                        "labels": [{"name": "launch-blocker", "id": 41}],
                        "pull_request": {"merged_at": None},
                    },
                    {
                        **_issue(9004),
                        "labels": [{"name": "unrelated", "id": 99}],
                    },
                ],
                {"link": f'<{label_page_two}>; rel="next"'},
            ),
            label_page_two: (
                [
                    {
                        **_issue(9003),
                        "labels": [
                            {"name": "launch-blocker", "id": 41},
                            {"name": "severity:medium", "id": 43},
                        ],
                    }
                ],
                {},
            ),
        }
    )
    discovered = fetch_labeled_blocker_issues(
        "ferrum-edge/ferrum-edge",
        _base_policy(),
        "tok",
        blocker_label_id=41,
        opener=label_opener,
    )
    check(
        "label discovery paginates and excludes PR nodes",
        [item["number"] for item in discovered] == [9001, 9003],
        str([item.get("number") for item in discovered]),
    )

    # The walk is unfiltered, so its page ceiling has to cover the repository's
    # whole issue+pull-request history rather than the blocker set. Bounding it
    # with the shared default would turn ordinary repository growth into a
    # permanent `pagination` UNKNOWN.
    check(
        "inventory page bound exceeds the shared default",
        MAX_INVENTORY_PAGES > MAX_PAGES,
        str(MAX_INVENTORY_PAGES),
    )
    deep_page_count = MAX_PAGES + 5
    deep_pages: dict[str, tuple[list[Any], dict[str, str]]] = {}
    for index in range(deep_page_count):
        current = label_page_one if index == 0 else f"{label_page_one}&page={index + 1}"
        deep_pages[current] = (
            [
                {
                    **_issue(9100 + index),
                    "labels": [
                        {"name": "launch-blocker", "id": 41},
                        {"name": "severity:medium", "id": 43},
                    ],
                }
            ],
            (
                {"link": f'<{label_page_one}&page={index + 2}>; rel="next"'}
                if index + 1 < deep_page_count
                else {}
            ),
        )
    deep = fetch_labeled_blocker_issues(
        "ferrum-edge/ferrum-edge",
        _base_policy(),
        "tok",
        blocker_label_id=41,
        opener=page_opener(deep_pages),
    )
    check(
        "inventory walk continues past the shared page default",
        len(deep) == deep_page_count,
        str(len(deep)),
    )

    # A full unfiltered page carries `PER_PAGE` complete issue payloads and
    # already measures close to `MAX_RESPONSE_BYTES`, so the walk must read
    # against its own larger ceiling — while a body past that ceiling still
    # fails closed rather than being silently truncated.
    check(
        "inventory byte bound exceeds the shared default",
        MAX_INVENTORY_RESPONSE_BYTES > MAX_RESPONSE_BYTES,
        str(MAX_INVENTORY_RESPONSE_BYTES),
    )
    oversized_issue = {
        **_issue(9200),
        "body": "x" * (MAX_RESPONSE_BYTES + 4096),
        "labels": [
            {"name": "launch-blocker", "id": 41},
            {"name": "severity:medium", "id": 43},
        ],
    }
    oversized = fetch_labeled_blocker_issues(
        "ferrum-edge/ferrum-edge",
        _base_policy(),
        "tok",
        blocker_label_id=41,
        opener=page_opener({label_page_one: ([oversized_issue], {})}),
    )
    check(
        "inventory page larger than the shared byte cap is read",
        [item["number"] for item in oversized] == [9200],
        str([item.get("number") for item in oversized]),
    )
    try:
        http_get_json(
            label_page_one,
            "tok",
            opener=page_opener({label_page_one: ([oversized_issue], {})}),
        )
        check("shared byte cap still refuses an oversized body", False)
    except GateError as exc:
        check(
            "shared byte cap still refuses an oversized body",
            exc.code == "api" and "size cap" in exc.message,
            exc.message,
        )

    over_bound = {
        f"{label_page_one}&page={index + 1}" if index else label_page_one: (
            [],
            {"link": f'<{label_page_one}&page={index + 2}>; rel="next"'},
        )
        for index in range(MAX_INVENTORY_PAGES + 1)
    }
    try:
        fetch_labeled_blocker_issues(
            "ferrum-edge/ferrum-edge",
            _base_policy(),
            "tok",
            blocker_label_id=41,
            opener=page_opener(over_bound),
        )
        check("inventory walk still fails closed at its bound", False)
    except GateError as exc:
        check(
            "inventory walk still fails closed at its bound",
            exc.code == "pagination",
            exc.message,
        )

    ev = _evaluate(
        _base_policy(),
        labeled=[
            _issue(
                9007,
                labels=[
                    "launch-blocker",
                    "severity:high",
                    "good first issue 🚀",
                ],
            )
        ],
    )
    check(
        "unrelated labels with spaces or Unicode remain valid",
        ev.verdict == "FAIL" and ev.counts_by_severity["high"] == 1,
        str(ev.unknown_reasons),
    )

    # Closed-as-duplicate/not-planned issues remain blocking by contract, so
    # immutable-id discovery must include closed labeled issues as well as open.
    closed_other = _evaluate(
        _base_policy(),
        labeled=[
            _issue(
                9006,
                state="closed",
                state_reason="duplicate",
                labels=["launch-blocker", "severity:high"],
            )
        ],
    )
    check(
        "dynamically labeled closed_other issue remains blocking",
        closed_other.verdict == "FAIL"
        and closed_other.blocking_issues
        and closed_other.blocking_issues[0]["classification"] == "closed_other",
        str(closed_other.blocking_issues),
    )

    # A rename away-and-back can preserve the metadata id seen before and after
    # the walk. Selecting the unfiltered inventory by id still sees the issue,
    # and the mismatched in-page name fails closed instead of producing PASS.
    renamed_during_walk = page_opener(
        {
            label_page_one: (
                [
                    {
                        **_issue(9005),
                        "labels": [{"name": "launch-blocker-renamed", "id": 41}],
                    }
                ],
                {},
            )
        }
    )
    try:
        fetch_labeled_blocker_issues(
            "ferrum-edge/ferrum-edge",
            _base_policy(),
            "tok",
            blocker_label_id=41,
            opener=renamed_during_walk,
        )
        check("blocker label rename during issue walk is UNKNOWN", False)
    except GateError as exc:
        check(
            "blocker label rename during issue walk is UNKNOWN",
            exc.code == LABEL_INVENTORY_CODE and "name changed" in exc.message,
            exc.message,
        )

    # ---- document claim ----------------------------------------------------
    def document(verdict: str, counts: dict[str, int], private: int = 0) -> str:
        claim = {
            "verdict": verdict,
            "policy_version": "1",
            "classification_version": "launch-blocker-v1",
            "launch_tier": "ga",
            "private_blockers_redacted_count": private,
            "counts_by_severity": counts,
        }
        return (
            "# Readiness\n\n"
            "<!-- launch-readiness:begin -->\n```json\n"
            + json.dumps(claim, indent=2)
            + "\n```\n<!-- launch-readiness:end -->\n\n"
            "<!-- launch-readiness:historical -->\n"
            "Historical audit: 0 critical/high/medium findings; regression tests added\n"
        )

    zero = {"critical": 0, "high": 0, "medium": 0}
    doc = document("FAIL", {"critical": 1, "high": 0, "medium": 0})
    claim = extract_document_claim(doc, _base_policy())
    check("claim extracted", claim["verdict"] == "FAIL")
    try:
        assert_document_historical_separation(doc, _base_policy())
        check("historical separation accepted", True)
    except GateError as exc:
        check("historical separation accepted", False, exc.message)

    bad_doc = "None blocking launch.\n" + document("FAIL", zero)
    try:
        assert_document_historical_separation(bad_doc, _base_policy())
        check("unscoped clean claim rejected", False)
    except GateError:
        check("unscoped clean claim rejected", True)

    for name, text in (
        ("missing markers", "# Readiness\n"),
        (
            "malformed JSON",
            "<!-- launch-readiness:begin -->\n{oops\n<!-- launch-readiness:end -->\n",
        ),
    ):
        try:
            extract_document_claim(text, _base_policy())
            check(f"claim rejects {name}", False)
        except GateError:
            check(f"claim rejects {name}", True)

    for name, claim_json in (
        ("string count", {"critical": "1", "high": 0, "medium": 0}),
        ("missing severity", {"critical": 0, "high": 0}),
        ("negative count", {"critical": -1, "high": 0, "medium": 0}),
    ):
        try:
            extract_document_claim(document("FAIL", claim_json), _base_policy())
            check(f"claim rejects {name}", False)
        except GateError:
            check(f"claim rejects {name}", True)

    policy = _tracked(_base_policy(), 8001, "critical")
    failing = _evaluate(
        policy,
        issues={8001: _issue(8001, labels=["launch-blocker", "severity:critical"])},
    )
    passing = _evaluate(_base_policy())
    unknown = _evaluate(_base_policy(), env={})

    parity_pass = extract_document_claim(document("PASS", zero), _base_policy())
    parity_fail = extract_document_claim(
        document("FAIL", {"critical": 1, "high": 0, "medium": 0}), _base_policy()
    )
    check(
        "claimed PASS against computed FAIL rejected",
        verify_claim_against_evaluation(parity_pass, failing),
    )
    check(
        "claimed FAIL against computed FAIL accepted",
        verify_claim_against_evaluation(parity_fail, failing) == [],
        str(verify_claim_against_evaluation(parity_fail, failing)),
    )
    check(
        "claimed PASS against computed PASS accepted",
        verify_claim_against_evaluation(parity_pass, passing) == [],
    )
    check(
        "claimed count mismatch rejected",
        verify_claim_against_evaluation(
            extract_document_claim(
                document("FAIL", {"critical": 2, "high": 0, "medium": 0}), _base_policy()
            ),
            failing,
        ),
    )
    check(
        "claimed private count mismatch rejected",
        verify_claim_against_evaluation(
            extract_document_claim(document("FAIL", zero, private=3), _base_policy()),
            passing,
        ),
    )
    check(
        "malformed claim types do not raise",
        verify_claim_against_evaluation(
            {
                "verdict": "PASS",
                "policy_version": "1",
                "classification_version": "launch-blocker-v1",
                "launch_tier": "ga",
                "private_blockers_redacted_count": "0",
                "counts_by_severity": {"critical": "x", "high": None, "medium": True},
            },
            passing,
        ),
    )

    # ---- exit-code contract -------------------------------------------------
    for name, evaluation, expected in (
        ("computed FAIL", failing, 1),
        ("computed UNKNOWN", unknown, 1),
        ("computed PASS", passing, 0),
    ):
        claim_for = {
            "verdict": evaluation.verdict,
            "policy_version": "1",
            "classification_version": "launch-blocker-v1",
            "launch_tier": "ga",
            "private_blockers_redacted_count": evaluation.private_blocker_count,
            "counts_by_severity": dict(evaluation.counts_by_severity),
        }
        code = verify_exit_code(claim_for, evaluation)
        check(f"{name} exits {expected}", code == expected, str(code))

    # A claim that merely agrees with a FAIL is still a non-zero exit: only a
    # computed PASS may make the readiness job green.
    check(
        "agreeing FAIL claim still exits non-zero",
        verify_exit_code(parity_fail, failing) == 1,
    )

    # ---- git head parsing ---------------------------------------------------
    try:
        resolve_checked_out_sha(Path("/nonexistent-launch-readiness-fixture"))
        check("missing git dir fails closed", False)
    except GateError as exc:
        check("missing git dir fails closed", exc.code == "io", exc.message)

    # ---- advisory-credential trust boundary (issue #3802) -------------------
    trusted_anchor = "a" * 40
    candidate_anchor = "b" * 40
    token_env = {ADVISORY_TOKEN_VAR: "s3cret-advisory-credential"}

    def boundary(
        *,
        trusted: bool,
        explicit: bool,
        tree: str = "",
        head: str | None = trusted_anchor,
        env: dict[str, str] | None = None,
    ) -> list[str]:
        return advisory_execution_errors(
            trusted_execution=trusted,
            explicit_target=explicit,
            trusted_tree_sha=tree,
            checked_out_sha=head,
            env=env if env is not None else {},
        )

    # A malicious tagged checker/workflow: the tag target rewrote this script to
    # exfiltrate whatever it is given, and the workflow handed it the credential.
    # The credential is refused before a single advisory request is made.
    malicious_tag = boundary(trusted=False, explicit=True, env=token_env)
    check(
        "credential outside a trusted execution is refused",
        malicious_tag and any("did not declare" in err for err in malicious_tag),
        str(malicious_tag),
    )
    check(
        "the refusal never echoes the credential",
        all("s3cret" not in err for err in malicious_tag),
    )

    # The same untrusted invocation with no credential is unaffected: the
    # standalone tag/PR run still evaluates from the redacted variables.
    check(
        "an untrusted invocation without a credential is allowed",
        boundary(trusted=False, explicit=True) == [],
    )

    # A trusted invocation must carry the candidate as data, not as the tree.
    check(
        "trusted execution requires an explicit target SHA",
        any(
            "explicit target SHA" in err
            for err in boundary(trusted=True, explicit=False, tree=trusted_anchor)
        ),
    )
    check(
        "trusted execution requires a trusted anchor SHA",
        any(
            "--trusted-tree-sha" in err
            for err in boundary(trusted=True, explicit=True, tree="")
        ),
    )
    check(
        "a malformed trusted anchor SHA is refused",
        any(
            "--trusted-tree-sha" in err
            for err in boundary(trusted=True, explicit=True, tree="not-a-sha")
        ),
    )
    # The candidate tree substituted for the trusted anchor — the exact swap the
    # tag-triggered path used to perform implicitly.
    check(
        "executing from the candidate tree is refused",
        any(
            "not the pinned trusted anchor" in err
            for err in boundary(
                trusted=True,
                explicit=True,
                tree=trusted_anchor,
                head=candidate_anchor,
            )
        ),
    )
    check(
        "an unresolvable tree is refused",
        any(
            "could not be resolved" in err
            for err in boundary(
                trusted=True, explicit=True, tree=trusted_anchor, head=None
            )
        ),
    )
    check(
        "a pinned trusted execution with an explicit candidate is allowed",
        boundary(
            trusted=True,
            explicit=True,
            tree=trusted_anchor,
            head=trusted_anchor,
            env=token_env,
        )
        == [],
    )
    check(
        "credential presence is detected without returning it",
        advisory_token_present(token_env)
        and not advisory_token_present({ADVISORY_TOKEN_VAR: "   "})
        and not advisory_token_present({}),
    )

    # ---- checked-in policy / exemptions -------------------------------------
    try:
        repo_policy = require_dict(load_json_file(POLICY_PATH), "repo policy")
        validate_policy(repo_policy)
        check("repository policy validates", True)
    except GateError as exc:
        check("repository policy validates", False, exc.message)
    try:
        repo_exemptions = require_dict(load_json_file(EXEMPTIONS_PATH), "repo exemptions")
        validate_exemptions(repo_exemptions, FIXED_NOW)
        check("repository exemptions validate", True)
    except GateError as exc:
        check("repository exemptions validate", False, exc.message)

    if failures:
        print("SELF-TEST FAILURES:", file=sys.stderr)
        for item in failures:
            print(f"- {sanitize_line(item)}", file=sys.stderr)
        return 1
    print("launch-readiness self-test: PASS")
    return 0


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def verify_errors(claim: dict[str, Any], evaluation: Evaluation) -> list[str]:
    """Everything that must make `--verify` fail.

    UNKNOWN and FAIL are both failures. A readiness gate that stays red while
    real launch blockers are open is the honest outcome; it is never disguised
    as success by matching a checked-in FAIL.
    """

    errors = verify_claim_against_evaluation(claim, evaluation)
    if evaluation.verdict != "PASS":
        errors.append(f"computed verdict is {evaluation.verdict} (fail closed)")
    return errors


def verify_exit_code(claim: dict[str, Any], evaluation: Evaluation) -> int:
    """Zero only for a computed PASS whose checked-in snapshot agrees with it."""

    return 1 if verify_errors(claim, evaluation) else 0


def run_verify(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    target_sha = (args.target_sha or env.get("LAUNCH_TARGET_SHA", "") or "").strip()
    explicit_target = bool(target_sha)
    trusted_tree_sha = (args.trusted_tree_sha or "").strip()
    try:
        checked_out_for_trust: str | None = resolve_checked_out_sha(ROOT)
    except GateError:
        checked_out_for_trust = None
    boundary_errors = advisory_execution_errors(
        trusted_execution=args.trusted_execution,
        explicit_target=explicit_target,
        trusted_tree_sha=trusted_tree_sha,
        checked_out_sha=checked_out_for_trust,
        env=env,
    )
    if boundary_errors:
        for err in boundary_errors:
            print(f"error: trust_boundary: {sanitize_line(err)}", file=sys.stderr)
        return 1
    if not explicit_target:
        # No caller-supplied target: evaluate the commit that is checked out,
        # which is what a tag/release job has already pinned via its ref.
        try:
            target_sha = resolve_checked_out_sha(ROOT)
        except GateError as exc:
            print(f"error: {exc.code}: {sanitize_line(exc.message)}", file=sys.stderr)
            return 1
    if not SHA_RE.fullmatch(target_sha):
        print(
            "error: target SHA must be a 40-character lowercase hex commit",
            file=sys.stderr,
        )
        return 1
    launch_tier = (args.launch_tier or env.get("LAUNCH_TIER") or "").strip()
    if not launch_tier:
        print("error: launch tier is required", file=sys.stderr)
        return 1

    now = utc_now()
    try:
        policy = require_dict(load_json_file(POLICY_PATH), "policy")
        validate_policy(policy)
        exemptions = validate_exemptions(
            require_dict(load_json_file(EXEMPTIONS_PATH), "exemptions"), now
        )
        document = read_text_file(ROOT / policy["document"]["path"])
        assert_document_historical_separation(document, policy)
        claim = extract_document_claim(document, policy)
        if args.verify_checkout and explicit_target:
            checked_out = resolve_checked_out_sha(ROOT)
            if checked_out != target_sha:
                raise GateError(
                    "provenance", "checked-out commit is not the evaluation target"
                )
    except GateError as exc:
        print(f"error: {exc.code}: {sanitize_line(exc.message)}", file=sys.stderr)
        return 1

    evaluation = evaluate_live(
        policy=policy,
        exemptions=exemptions,
        launch_tier=launch_tier,
        target_sha=target_sha,
        token=github_token(env),
        now=now,
        env=env,
    )
    try:
        print_safe_summary(evaluation)
    except GateError as exc:
        print(f"error: {exc.code}: {sanitize_line(exc.message)}", file=sys.stderr)
        return 1

    errors = verify_errors(claim, evaluation)
    for err in errors:
        print(f"error: {sanitize_line(err)}", file=sys.stderr)
    return 1 if errors else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch readiness gate")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="accepted for release wiring; --verify always requires a computed PASS",
    )
    parser.add_argument(
        "--verify-checkout",
        action="store_true",
        help="assert the working tree HEAD is the evaluation target commit",
    )
    parser.add_argument(
        "--trusted-execution",
        action="store_true",
        help=(
            "declare that this invocation executes protected default-branch code "
            "and may therefore use an advisory credential; requires an explicit "
            "target SHA and --trusted-tree-sha"
        ),
    )
    parser.add_argument(
        "--trusted-tree-sha",
        default="",
        help="the trusted anchor commit this invocation must be executing from",
    )
    parser.add_argument("--launch-tier", default="")
    parser.add_argument("--target-sha", default="")
    args = parser.parse_args(argv)

    if args.self_test and args.verify:
        print("error: choose one of --self-test or --verify", file=sys.stderr)
        return 1
    if args.self_test:
        return run_self_test()
    if args.verify:
        return run_verify(args, os.environ)
    print("error: specify --self-test or --verify", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
