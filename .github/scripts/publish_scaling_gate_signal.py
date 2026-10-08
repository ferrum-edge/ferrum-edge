#!/usr/bin/env python3
"""Durable signal for Scheduled Scaling Regression (issue #3892).

When the weekly scale/load matrix is red, or the latest scaling-regression run
on `main` is not a completed success within the freshness ceiling, this program
upserts a GitHub issue labeled `severity:high`. Every live invocation queries
the latest `scaling-regression.yml` run on `main`. The current weekly
`SCALING_JOB_RESULT` is bound to `GITHUB_RUN_ID` and is authoritative only
when that exact run is the API's newest-first latest run. An older publisher
derives the issue from that latest run, never from the stale job result: a
newer completed fresh success may close, and a newer failure, cancel, timeout,
skip, nonterminal, malformed, stale, missing, or API-unknown state keeps the
issue open. A stale older success never closes over a newer red or in-progress
run, and a stale older failure never reopens over a newer fresh success.
Missing or malformed current-run identity fails closed and must not close.

The program never grants itself extra credentials: it uses the job-scoped
GITHUB_TOKEN with `issues: write` and `actions: read` only. It refuses
pull_request events and refuses to mutate issues off `refs/heads/main`.
Missing, malformed, out-of-order, future-dated, or API-failed history is
treated as stale (fail-closed). Run links are always constructed from the
repository identity for the generation that drove the decision; an API-supplied
html_url is never used verbatim.
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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable


MARKER = "<!-- ferrum-scaling-gate-signal -->"
ISSUE_TITLE = "[CI] Scheduled Scaling Regression is red or stale"
ISSUE_LABELS = ("severity:high",)
SIGNAL_AUTHOR = "github-actions[bot]"
ISSUE_LIST_PER_PAGE = 30
ISSUE_LIST_MAX_PAGES = 5
ISSUE_REASON_MAX_CHARS = 200
ISSUE_RUN_LINE_RE = re.compile(r"(?m)^Run: \S+/actions/runs/([1-9][0-9]*)\s*$")
WORKFLOW_FILE = "scaling-regression.yml"
WORKFLOW_RUN_LIST_PER_PAGE = 5
# Events that run this repository's own copy of the workflow on `main`. A fork
# cannot schedule or dispatch here, so each event is queried server-side and a
# fork's pull-request run can never crowd trusted runs out of the page.
TRUSTED_RUN_EVENTS = ("schedule", "workflow_dispatch")
# Weekly cadence (7d) plus one day so Sunday–Friday freshness checks do not
# fire between a healthy Saturday run and the next scheduled window.
MAX_AGE_SECONDS = 8 * 24 * 60 * 60
MAX_RESPONSE_BYTES = 1 << 20
USER_AGENT = "ferrum-edge-scaling-gate-signal"
API_VERSION = "2022-11-28"
ISO_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]*$")
RED_RESULTS = frozenset({"failure", "cancelled", "timed_out"})
GREEN_RESULTS = frozenset({"success"})
SKIPPED_RESULTS = frozenset({"skipped", ""})
NON_TERMINAL_STATUSES = frozenset(
    {"queued", "in_progress", "waiting", "requested", "pending"}
)


class SignalError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Decision:
    action: str  # "open" | "close"
    reason: str
    fail_job: bool
    source_run_id: int | None = None


@dataclass(frozen=True)
class LatestRun:
    run_id: int
    status: str
    conclusion: str | None
    age_seconds: int


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso8601(value: Any, label: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not ISO_Z_RE.fullmatch(value):
        raise SignalError("schema", f"malformed {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SignalError("schema", f"malformed {label}") from exc
    if parsed.tzinfo is None:
        raise SignalError("schema", f"{label} missing timezone")
    return parsed.astimezone(timezone.utc)


def parse_github_run_id(value: str) -> tuple[int | None, str | None]:
    raw = (value or "").strip()
    if not raw:
        return None, "schema: missing GITHUB_RUN_ID"
    if not RUN_ID_RE.fullmatch(raw):
        return None, "schema: malformed GITHUB_RUN_ID"
    try:
        parsed = int(raw, 10)
    except ValueError:
        return None, "schema: malformed GITHUB_RUN_ID"
    if parsed <= 0:
        return None, "schema: malformed GITHUB_RUN_ID"
    return parsed, None


def canonical_actions_run_url(server: str, repo: str, run_id: int) -> str:
    return f"{server.rstrip('/')}/{repo}/actions/runs/{run_id}"


def issue_run_url(server: str, repo: str, run_id: int | None) -> str:
    """Construct the issue run link from known repo identity.

    The link is always built from `server`/`repo`/`run_id`. API payloads are
    never consulted for this URL.
    """

    if run_id is None:
        return server.rstrip("/")
    return canonical_actions_run_url(server, repo, run_id)


def public_issue_reason(reason: str) -> str:
    """Keep issue-body Reason lines markdown-safe and bounded."""

    cleaned: list[str] = []
    for char in reason:
        if char in "`\r\n":
            cleaned.append(" ")
        else:
            cleaned.append(char)
    text = " ".join("".join(cleaned).split())
    if len(text) > ISSUE_REASON_MAX_CHARS:
        text = text[:ISSUE_REASON_MAX_CHARS].rstrip()
    return text


def recorded_run_id_from_issue_body(body: Any) -> int | None:
    if not isinstance(body, str):
        return None
    match = ISSUE_RUN_LINE_RE.search(body)
    if match is None:
        return None
    parsed, err = parse_github_run_id(match.group(1))
    if err is not None or parsed is None:
        return None
    return parsed


def close_blocked_by_recorded_generation(
    existing: dict[str, Any], decision: Decision
) -> str | None:
    """Refuse close when the issue already records a newer generation.

    Returns a reason to leave the blocker open, or None when close may proceed.
    An unreadable recorded run id fails closed.
    """

    if decision.source_run_id is None:
        return "close source run id is missing"
    recorded = recorded_run_id_from_issue_body(existing.get("body"))
    if recorded is None:
        return "recorded run id is unreadable"
    if recorded > decision.source_run_id:
        return f"recorded run {recorded} is newer than {decision.source_run_id}"
    return None


def _workflow_run_id(entry: dict[str, Any]) -> int:
    run_id = entry.get("id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise SignalError("schema", "workflow run id is malformed")
    return run_id


def decide_from_latest(latest: LatestRun) -> Decision:
    status = (latest.status or "").strip().lower()
    conclusion = (latest.conclusion or "").strip().lower()
    source = latest.run_id
    if status in NON_TERMINAL_STATUSES:
        return Decision("open", f"latest scaling run is {status}", True, source)
    if status != "completed":
        return Decision("open", f"unknown latest scaling run status {status!r}", True, source)
    if conclusion in GREEN_RESULTS:
        if latest.age_seconds > MAX_AGE_SECONDS:
            return Decision(
                "open",
                f"latest successful scaling run is {latest.age_seconds}s old",
                True,
                source,
            )
        return Decision(
            "close",
            "latest successful scaling run is within freshness",
            False,
            source,
        )
    if not conclusion:
        return Decision("open", "latest scaling run conclusion is missing", True, source)
    return Decision("open", f"latest scaling run conclusion is {conclusion}", True, source)


def decide(
    job_result: str,
    current_run_id: int | None,
    current_run_id_error: str | None,
    latest: LatestRun | None,
    history_error: str | None,
) -> Decision:
    """Pure generation-aware policy.

    Current weekly success/failure/cancel/timeout is authoritative only when
    `current_run_id` is the exact latest scaling-regression run. Ordering uses
    the API's validated newest-first identity, not numeric run-id comparison.
    Freshness and stale publishers inspect that latest run. Only a latest
    completed success within the ceiling may close. A newer non-success,
    in-progress, malformed, or missing history cannot be greened by an older
    success, and an older failure cannot reopen over a newer fresh success.
    """

    if current_run_id_error or current_run_id is None:
        reason = current_run_id_error or "schema: missing GITHUB_RUN_ID"
        return Decision("open", reason, True)
    if history_error:
        return Decision("open", f"scaling history unknown: {history_error}", True, current_run_id)
    if latest is None:
        return Decision("open", "no scaling-regression run on main", True, current_run_id)

    result = (job_result or "").strip().lower()
    if current_run_id == latest.run_id:
        if result in GREEN_RESULTS:
            return Decision("close", "scaling matrix succeeded", False, current_run_id)
        if result in RED_RESULTS:
            return Decision("open", f"scaling matrix result is {result}", False, current_run_id)
        if result not in SKIPPED_RESULTS:
            return Decision(
                "open",
                f"unknown scaling job result {result!r}",
                True,
                current_run_id,
            )
        return decide_from_latest(latest)
    return decide_from_latest(latest)


def issue_body(reason: str, run_url: str) -> str:
    return (
        f"{MARKER}\n"
        "The Scheduled Scaling Regression gate is red or stale. This issue is the\n"
        "durable signal so a broken 10k/30k scale lane cannot stay red unnoticed.\n"
        "\n"
        f"Reason: {public_issue_reason(reason)}\n"
        f"Run: {run_url}\n"
        "\n"
        "The next successful scheduled or dispatched scaling run on `main` closes this\n"
        "issue as completed. Do not close it as not_planned while the gate is still red.\n"
    )


def require_repo(value: str) -> str:
    if not REPO_RE.fullmatch(value):
        raise SignalError("schema", "malformed GITHUB_REPOSITORY")
    return value


def api_request(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": API_VERSION,
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise SignalError("schema", "GitHub API response exceeded bound")
            if not raw:
                return None
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SignalError("schema", "malformed GitHub API JSON") from exc
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise SignalError("api", f"GitHub API {exc.code} for {method} {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SignalError("api", f"GitHub API transport error: {exc}") from exc


def latest_run_on_main(
    repo: str,
    token: str,
    now: datetime,
    request: Callable[[str, str, str, dict[str, Any] | None], Any] = api_request,
) -> tuple[LatestRun | None, str | None]:
    """Return the newest scaling-regression run on `main`, not the last success.

    Scheduled and manually dispatched runs on `main` are both generations of
    this gate, so either can close the signal. Each event is listed separately
    (GitHub returns created_at descending) and the two pages are merged by
    creation time. Freshness must honor that order: a newer failure, cancel,
    timeout, skip, or in-progress run cannot be greened by an older success
    still inside the eight-day window. Out-of-order, malformed, untrusted, or
    future-dated history fails closed. Generation identity is the exact `id` of
    the first validated run, not numeric ordering across ids.
    """

    validated: list[tuple[datetime, dict[str, Any]]] = []
    for event in TRUSTED_RUN_EVENTS:
        query = urllib.parse.urlencode(
            {
                "branch": "main",
                "event": event,
                "per_page": str(WORKFLOW_RUN_LIST_PER_PAGE),
            }
        )
        url = (
            f"https://api.github.com/repos/{repo}/actions/workflows/"
            f"{WORKFLOW_FILE}/runs?{query}"
        )
        try:
            payload = request("GET", url, token, None)
        except SignalError as exc:
            return None, f"{exc.code}: {exc.message}"
        if not isinstance(payload, dict):
            return None, "schema: workflow runs payload is not an object"
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            return None, "schema: workflow_runs is not a list"
        if len(runs) > WORKFLOW_RUN_LIST_PER_PAGE:
            return None, "schema: workflow runs page exceeded bound"

        previous_created: datetime | None = None
        for entry in runs:
            if not isinstance(entry, dict):
                return None, "schema: workflow run item is not an object"
            head_branch = entry.get("head_branch")
            if head_branch != "main":
                return None, "schema: workflow run is not on main"
            if entry.get("event") != event:
                return None, "schema: workflow run is not scheduled or dispatched"
            head_repository = entry.get("head_repository")
            if not isinstance(head_repository, dict) or head_repository.get("full_name") != repo:
                return None, "schema: workflow run is not from the repository"
            if entry.get("path") != f".github/workflows/{WORKFLOW_FILE}":
                return None, "schema: workflow run path is unexpected"
            try:
                created = parse_iso8601(entry.get("created_at"), "workflow run created_at")
            except SignalError as exc:
                return None, f"{exc.code}: {exc.message}"
            if created > now:
                return None, "schema: workflow run timestamp is in the future"
            if previous_created is not None and created > previous_created:
                return None, "schema: workflow runs are out of order"
            previous_created = created
            validated.append((created, entry))

    if not validated:
        return None, None
    # Stable sort: within one event the API order is already newest-first.
    validated.sort(key=lambda item: item[0], reverse=True)
    latest_entry = validated[0][1]
    if not isinstance(latest_entry, dict):
        return None, "schema: workflow run item is not an object"
    stamp = (
        latest_entry.get("updated_at")
        or latest_entry.get("run_started_at")
        or latest_entry.get("created_at")
    )
    try:
        finished = parse_iso8601(stamp, "workflow run timestamp")
    except SignalError as exc:
        return None, f"{exc.code}: {exc.message}"
    if finished > now:
        return None, "schema: workflow run timestamp is in the future"
    age = int((now - finished).total_seconds())
    if age < 0:
        return None, "schema: workflow run timestamp is in the future"

    status = latest_entry.get("status")
    if not isinstance(status, str) or not status.strip():
        return None, "schema: workflow run status is malformed"
    conclusion = latest_entry.get("conclusion")
    if conclusion is not None and not isinstance(conclusion, str):
        return None, "schema: workflow run conclusion is malformed"
    normalized_conclusion = conclusion.strip().lower() if isinstance(conclusion, str) else None
    if normalized_conclusion == "":
        normalized_conclusion = None
    try:
        run_id = _workflow_run_id(latest_entry)
    except SignalError as exc:
        return None, f"{exc.code}: {exc.message}"
    return (
        LatestRun(
            run_id=run_id,
            status=status.strip().lower(),
            conclusion=normalized_conclusion,
            age_seconds=age,
        ),
        None,
    )


def _issue_number(item: dict[str, Any], label: str) -> int:
    number = item.get("number")
    if not isinstance(number, int) or number <= 0:
        raise SignalError("schema", f"{label} signal issue is missing number")
    return number


def _has_exact_signal_identity(item: dict[str, Any]) -> bool:
    body = item.get("body")
    return item.get("title") == ISSUE_TITLE and isinstance(body, str) and MARKER in body


def _author_login(item: dict[str, Any]) -> str | None:
    user = item.get("user")
    if not isinstance(user, dict):
        return None
    login = user.get("login")
    return login if isinstance(login, str) else None


def require_publisher_owned_signal(item: Any, label: str) -> dict[str, Any]:
    if not isinstance(item, dict) or item == {}:
        raise SignalError("schema", f"{label} signal issue is not a durable object")
    if not _has_exact_signal_identity(item):
        raise SignalError("schema", f"{label} signal issue is missing title or marker")
    login = _author_login(item)
    if login is None:
        raise SignalError("schema", f"{label} signal issue author is malformed")
    if login != SIGNAL_AUTHOR:
        raise SignalError("schema", f"{label} signal issue is not publisher-owned")
    _issue_number(item, label)
    return item


def find_signal_issue(
    repo: str,
    token: str,
    request: Callable[[str, str, str, dict[str, Any] | None], Any] = api_request,
) -> dict[str, Any] | None:
    matches: list[dict[str, Any]] = []
    for page in range(1, ISSUE_LIST_MAX_PAGES + 1):
        query = urllib.parse.urlencode(
            {
                "state": "all",
                "labels": ",".join(ISSUE_LABELS),
                "creator": SIGNAL_AUTHOR,
                "sort": "updated",
                "direction": "desc",
                "per_page": str(ISSUE_LIST_PER_PAGE),
                "page": str(page),
            }
        )
        payload = request("GET", f"https://api.github.com/repos/{repo}/issues?{query}", token, None)
        if not isinstance(payload, list):
            raise SignalError("schema", "issue listing payload is not a list")
        if len(payload) > ISSUE_LIST_PER_PAGE:
            raise SignalError("schema", "issue listing page exceeded bound")
        for item in payload:
            if not isinstance(item, dict):
                raise SignalError("schema", "issue listing item is not an object")
            if "pull_request" in item:
                continue
            if not _has_exact_signal_identity(item):
                continue
            login = _author_login(item)
            if login is None:
                raise SignalError("schema", "signal issue author is malformed")
            if login != SIGNAL_AUTHOR:
                continue
            _issue_number(item, "existing")
            matches.append(item)
        if len(payload) < ISSUE_LIST_PER_PAGE:
            break
        if page == ISSUE_LIST_MAX_PAGES:
            # sort=updated keeps the live publisher-owned signal in this
            # window because every mutation rewrites the issue. Unrelated
            # label history must not make discovery unreachable: a unique
            # match already collected is returned. Zero matches on a full
            # window still fail closed; absence cannot be proved past the bound.
            if len(matches) == 1:
                break
            raise SignalError("schema", "issue listing exceeded pagination bound")
    if len(matches) > 1:
        raise SignalError("schema", "ambiguous publisher-owned signal issues")
    if not matches:
        return None
    return matches[0]


def apply_decision(
    repo: str,
    token: str,
    decision: Decision,
    run_url: str,
    mutate: bool,
    request: Callable[[str, str, str, dict[str, Any] | None], Any] = api_request,
) -> None:
    if not mutate:
        print(f"scaling-gate-signal: {decision.action} ({decision.reason}); not mutating off main")
        return
    existing = find_signal_issue(repo, token, request)
    body = issue_body(decision.reason, run_url)
    if decision.action == "open":
        if existing is None:
            created = request(
                "POST",
                f"https://api.github.com/repos/{repo}/issues",
                token,
                {
                    "title": ISSUE_TITLE,
                    "body": body,
                    "labels": list(ISSUE_LABELS),
                },
            )
            owned = require_publisher_owned_signal(created, "created")
            print(f"scaling-gate-signal: opened issue #{owned['number']}")
            return
        number = existing.get("number")
        if not isinstance(number, int):
            raise SignalError("schema", "existing signal issue is missing number")
        patch: dict[str, Any] = {"body": body}
        if existing.get("state") != "open":
            patch["state"] = "open"
        request("PATCH", f"https://api.github.com/repos/{repo}/issues/{number}", token, patch)
        print(f"scaling-gate-signal: updated issue #{number}")
        return
    if existing is None or existing.get("state") != "open":
        print("scaling-gate-signal: no open signal issue to close")
        return
    blocked = close_blocked_by_recorded_generation(existing, decision)
    if blocked is not None:
        print(f"scaling-gate-signal: refusing to close ({blocked})")
        return
    number = existing.get("number")
    if not isinstance(number, int):
        raise SignalError("schema", "existing signal issue is missing number")
    request(
        "PATCH",
        f"https://api.github.com/repos/{repo}/issues/{number}",
        token,
        {
            "state": "closed",
            "state_reason": "completed",
            "body": body,
        },
    )
    print(f"scaling-gate-signal: closed issue #{number} as completed")


def run_live(now: datetime) -> int:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if event_name in {"pull_request", "pull_request_target", "merge_group"}:
        print("::error::refusing to run the scaling-gate signal on a pull-request event", file=sys.stderr)
        return 1
    repo = require_repo(os.environ.get("GITHUB_REPOSITORY", ""))
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise SignalError("config", "GITHUB_TOKEN is missing")
    ref = os.environ.get("GITHUB_REF", "")
    mutate = ref == "refs/heads/main"
    job_result = os.environ.get("SCALING_JOB_RESULT", "skipped")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    current_run_id, current_run_id_error = parse_github_run_id(
        os.environ.get("GITHUB_RUN_ID", "")
    )
    latest, history_error = latest_run_on_main(repo, token, now)
    decision = decide(
        job_result, current_run_id, current_run_id_error, latest, history_error
    )
    run_url = issue_run_url(server, repo, decision.source_run_id)
    print(f"scaling-gate-signal: {decision.action} because {decision.reason}")
    apply_decision(repo, token, decision, run_url, mutate)
    return 1 if decision.fail_job else 0


def self_test() -> int:
    failures: list[str] = []

    def expect(decision: Decision, action: str, fail_job: bool, label: str) -> None:
        if decision.action != action or decision.fail_job != fail_job:
            failures.append(
                f"{label}: expected action={action} fail_job={fail_job}, "
                f"got action={decision.action} fail_job={decision.fail_job}"
            )

    current = 100
    newer = 200
    older = 50
    in_progress_current = LatestRun(current, "in_progress", None, 5)
    expect(
        decide("success", current, None, in_progress_current, None),
        "close",
        False,
        "exact current run success",
    )
    expect(
        decide("failure", current, None, in_progress_current, None),
        "open",
        False,
        "exact current run failure",
    )
    expect(
        decide(
            "cancelled",
            current,
            None,
            LatestRun(current, "in_progress", None, 10),
            None,
        ),
        "open",
        False,
        "matrix cancelled",
    )
    expect(
        decide(
            "success",
            older,
            None,
            LatestRun(newer, "completed", "failure", 10),
            None,
        ),
        "open",
        True,
        "stale older success over newer failure",
    )
    expect(
        decide(
            "failure",
            older,
            None,
            LatestRun(newer, "completed", "success", 60),
            None,
        ),
        "close",
        False,
        "stale older failure over newer fresh success",
    )
    expect(
        decide(
            "success",
            older,
            None,
            LatestRun(newer, "in_progress", None, 20),
            None,
        ),
        "open",
        True,
        "latest nonterminal",
    )
    expect(
        decide(
            "success",
            newer,
            None,
            LatestRun(current, "completed", "failure", 10),
            None,
        ),
        "open",
        True,
        "numeric run-id is not generation order",
    )
    expect(
        decide("success", None, "schema: missing GITHUB_RUN_ID", None, None),
        "open",
        True,
        "missing current run identity",
    )
    expect(
        decide("success", None, "schema: malformed GITHUB_RUN_ID", in_progress_current, None),
        "open",
        True,
        "malformed current run identity",
    )
    expect(
        decide("success", current, None, None, "api: boom"),
        "open",
        True,
        "history API failure",
    )
    expect(decide("skipped", current, None, None, None), "open", True, "never green")
    expect(
        decide("skipped", current, None, None, "api: boom"),
        "open",
        True,
        "history unknown",
    )
    expect(
        decide("weird", current, None, in_progress_current, None),
        "open",
        True,
        "unknown result",
    )
    parsed_ok, parsed_err = parse_github_run_id("12345")
    if parsed_ok != 12345 or parsed_err is not None:
        failures.append("parse_github_run_id must accept a positive integer run id")
    if parse_github_run_id("")[0] is not None or parse_github_run_id("01")[0] is not None:
        failures.append("missing current run identity and leading-zero ids must fail closed")
    if parse_github_run_id("0")[0] is not None or parse_github_run_id("12.0")[0] is not None:
        failures.append("malformed current run identity must fail closed")
    repo = "ferrum-edge/ferrum-edge"
    server = "https://github.com"
    expected_url = f"{server}/{repo}/actions/runs/{current}"
    if issue_run_url(server, repo, current) != expected_url:
        failures.append("run URL must be constructed from repo identity")
    if issue_run_url(server, repo, None) != server:
        failures.append("missing generation must not invent a run URL")

    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)

    def iso(delta: timedelta) -> str:
        return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")

    def workflow_run(
        *,
        created: timedelta,
        status: str = "completed",
        conclusion: str | None = "success",
        head_branch: str | None = "main",
        run_id: int = 1,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stamp = iso(created)
        run: dict[str, Any] = {
            "id": run_id,
            "created_at": stamp,
            "updated_at": stamp,
            "status": status,
            "conclusion": conclusion,
            "head_branch": head_branch,
            "event": "schedule",
            "head_repository": {"full_name": "ferrum-edge/ferrum-edge"},
            "path": f".github/workflows/{WORKFLOW_FILE}",
        }
        if extra:
            run.update(extra)
        return run

    def history_request(
        runs: list[Any],
    ) -> Callable[[str, str, str, dict[str, Any] | None], Any]:
        def request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
            if method != "GET" or f"/workflows/{WORKFLOW_FILE}/runs?" not in url:
                raise AssertionError(f"unexpected {method} {url}")
            if "status=success" in url:
                raise AssertionError(f"must not query only successful runs: {url}")
            if "branch=main" not in url:
                raise AssertionError(f"must query main branch runs: {url}")
            if f"per_page={WORKFLOW_RUN_LIST_PER_PAGE}" not in url:
                raise AssertionError(f"must bound workflow run pagination: {url}")
            # Serve dispatched runs only to the dispatch query and everything
            # else to the schedule query, so an untrusted event still reaches
            # the client-side checks the way an unfiltered page would.
            if "event=workflow_dispatch" in url:
                return {
                    "workflow_runs": [
                        run
                        for run in runs
                        if isinstance(run, dict) and run.get("event") == "workflow_dispatch"
                    ]
                }
            if "event=schedule" not in url:
                raise AssertionError(f"must query trusted run events server-side: {url}")
            return {
                "workflow_runs": [
                    run
                    for run in runs
                    if not isinstance(run, dict) or run.get("event") != "workflow_dispatch"
                ]
            }

        return request

    freshness_run_id = 999

    def expect_history(runs: list[Any], action: str, fail_job: bool, label: str) -> None:
        latest, err = latest_run_on_main(
            "ferrum-edge/ferrum-edge", "token", now, history_request(runs)
        )
        expect(
            decide("skipped", freshness_run_id, None, latest, err),
            action,
            fail_job,
            label,
        )

    older_fresh_success = workflow_run(created=timedelta(days=7), run_id=10)
    expect_history(
        [
            workflow_run(created=timedelta(hours=8), conclusion="failure", run_id=20),
            older_fresh_success,
        ],
        "open",
        True,
        "newer failure plus older fresh success",
    )
    expect_history(
        [
            workflow_run(
                created=timedelta(minutes=20),
                status="in_progress",
                conclusion=None,
                run_id=21,
            ),
            older_fresh_success,
        ],
        "open",
        True,
        "latest in-progress plus older success",
    )
    expect_history(
        [workflow_run(created=timedelta(days=1), run_id=22)],
        "close",
        False,
        "latest fresh success",
    )
    fork_run = workflow_run(
        created=timedelta(minutes=1),
        run_id=221,
        extra={"head_repository": {"full_name": "attacker/ferrum-edge"}},
    )
    expect_history([fork_run], "open", True, "fork run is not trusted")
    pull_request_run = workflow_run(
        created=timedelta(minutes=1),
        run_id=222,
        extra={"event": "pull_request"},
    )
    expect_history([pull_request_run], "open", True, "pull request run is not trusted")
    expect_history(
        [
            workflow_run(
                created=timedelta(hours=2),
                run_id=223,
                extra={"event": "workflow_dispatch"},
            )
        ],
        "close",
        False,
        "dispatched main run closes",
    )
    expect_history(
        [
            workflow_run(
                created=timedelta(hours=2),
                conclusion="failure",
                run_id=224,
                extra={"event": "workflow_dispatch"},
            ),
            workflow_run(created=timedelta(days=1), run_id=225),
        ],
        "open",
        True,
        "newer dispatched failure over older scheduled success",
    )
    expect_history(
        [
            workflow_run(created=timedelta(hours=2), run_id=226),
            workflow_run(
                created=timedelta(days=1),
                conclusion="failure",
                run_id=227,
                extra={"event": "workflow_dispatch"},
            ),
        ],
        "close",
        False,
        "newer scheduled success over older dispatched failure",
    )
    expect_history(
        [workflow_run(created=timedelta(days=9), run_id=23)],
        "open",
        True,
        "stale latest success",
    )
    expect_history(
        ["not-an-object", older_fresh_success],
        "open",
        True,
        "malformed latest item",
    )
    expect_history(
        [workflow_run(created=timedelta(days=-1))],
        "open",
        True,
        "future timestamp",
    )
    expect_history(
        [
            workflow_run(created=timedelta(days=7)),
            workflow_run(created=timedelta(hours=1)),
        ],
        "open",
        True,
        "out-of-order history",
    )
    missing_id = workflow_run(created=timedelta(hours=2), run_id=24)
    del missing_id["id"]
    expect_history([missing_id], "open", True, "malformed latest item")
    expect_history(
        [workflow_run(created=timedelta(hours=3), extra={"id": True})],
        "open",
        True,
        "malformed latest item",
    )
    expect_history(
        [workflow_run(created=timedelta(hours=4), head_branch=None, run_id=25)],
        "open",
        True,
        "missing head_branch is not on main",
    )
    missing_branch = workflow_run(created=timedelta(hours=4), run_id=26)
    del missing_branch["head_branch"]
    expect_history([missing_branch], "open", True, "missing head_branch is not on main")

    def boom_request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        raise SignalError("api", "boom")

    boom_latest, boom_err = latest_run_on_main(
        "ferrum-edge/ferrum-edge", "token", now, boom_request
    )
    expect(
        decide("success", current, None, boom_latest, boom_err),
        "open",
        True,
        "history API failure",
    )

    def expect_live_history(
        job_result: str,
        current_id: int,
        runs: list[Any],
        action: str,
        fail_job: bool,
        label: str,
    ) -> None:
        latest, err = latest_run_on_main(
            "ferrum-edge/ferrum-edge", "token", now, history_request(runs)
        )
        expect(
            decide(job_result, current_id, None, latest, err),
            action,
            fail_job,
            label,
        )

    expect_live_history(
        "success",
        30,
        [workflow_run(created=timedelta(hours=1), run_id=30, status="in_progress", conclusion=None)],
        "close",
        False,
        "exact current run success",
    )
    expect_live_history(
        "failure",
        31,
        [workflow_run(created=timedelta(hours=1), run_id=31, status="in_progress", conclusion=None)],
        "open",
        False,
        "exact current run failure",
    )
    expect_live_history(
        "success",
        32,
        [
            workflow_run(created=timedelta(hours=1), conclusion="failure", run_id=40),
            workflow_run(created=timedelta(days=1), run_id=32),
        ],
        "open",
        True,
        "stale older success over newer failure",
    )
    expect_live_history(
        "failure",
        33,
        [
            workflow_run(created=timedelta(hours=1), conclusion="success", run_id=41),
            workflow_run(created=timedelta(days=1), conclusion="failure", run_id=33),
        ],
        "close",
        False,
        "stale older failure over newer fresh success",
    )

    def signal_issue(
        number: int,
        *,
        title: str = ISSUE_TITLE,
        body: str | None = None,
        state: str = "open",
        login: str = SIGNAL_AUTHOR,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        issue: dict[str, Any] = {
            "number": number,
            "title": title,
            "body": MARKER + "\nowned" if body is None else body,
            "state": state,
            "user": {"login": login},
        }
        if extra:
            issue.update(extra)
        return issue

    def listing_query_ok(url: str) -> None:
        if "state=all" not in url or "labels=" not in url:
            raise AssertionError(f"listing must be bounded labeled state=all: {url}")
        if "sort=updated" not in url or "direction=desc" not in url:
            raise AssertionError(f"listing must sort by updated desc: {url}")
        encoded_creator = urllib.parse.urlencode({"creator": SIGNAL_AUTHOR})
        if encoded_creator not in url:
            raise AssertionError(f"listing must filter by publisher creator: {url}")

    def listing_request(items: list[Any]) -> Callable[[str, str, str, dict[str, Any] | None], Any]:
        def request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
            if method != "GET" or "/issues?" not in url:
                raise AssertionError(f"unexpected {method} {url}")
            listing_query_ok(url)
            return items

        return request

    def dummy_issue(number: int) -> dict[str, Any]:
        return {
            "number": number,
            "title": "unrelated",
            "body": "no marker",
            "state": "open",
            "user": {"login": SIGNAL_AUTHOR},
        }

    def full_window_pages(match: dict[str, Any] | None) -> dict[int, list[Any]]:
        pages: dict[int, list[Any]] = {}
        for page in range(1, ISSUE_LIST_MAX_PAGES + 1):
            start = (page - 1) * ISSUE_LIST_PER_PAGE
            pages[page] = [
                dummy_issue(10_000 + start + index) for index in range(ISSUE_LIST_PER_PAGE)
            ]
        if match is not None:
            pages[1][0] = match
        return pages

    def paged_listing_request(
        pages: dict[int, list[Any]],
    ) -> Callable[[str, str, str, dict[str, Any] | None], Any]:
        def request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
            if method != "GET" or "/issues?" not in url:
                raise AssertionError(f"unexpected {method} {url}")
            listing_query_ok(url)
            parsed = urllib.parse.urlparse(url)
            page_raw = urllib.parse.parse_qs(parsed.query).get("page", ["1"])[0]
            page = int(page_raw, 10)
            if page not in pages:
                raise AssertionError(f"listing requested unbound page {page}")
            return pages[page]

        return request

    def expect_none(items: list[Any], label: str) -> None:
        found = find_signal_issue("ferrum-edge/ferrum-edge", "token", listing_request(items))
        if found is not None:
            failures.append(f"{label}: expected spoof to be ignored, got {found!r}")

    def expect_error(items: list[Any], label: str) -> None:
        try:
            find_signal_issue("ferrum-edge/ferrum-edge", "token", listing_request(items))
        except SignalError:
            return
        failures.append(f"{label}: expected fail-closed SignalError")

    expect_none(
        [signal_issue(7, title="unrelated spoof", body=MARKER + "\nmarker only")],
        "marker-only spoof",
    )
    expect_none(
        [signal_issue(8, body="title only, no marker")],
        "title-only spoof",
    )
    expect_none(
        [signal_issue(9, login="alice")],
        "user-authored exact-title+marker spoof",
    )
    expect_error(
        [signal_issue(11), signal_issue(12)],
        "multiple bot-owned matches",
    )

    closed = signal_issue(13, state="closed")
    found_closed = find_signal_issue(
        "ferrum-edge/ferrum-edge", "token", listing_request([closed])
    )
    if found_closed != closed:
        failures.append("closed publisher-owned signal must be selectable for reopen")

    unique_in_window = signal_issue(1)
    found_in_full_window = find_signal_issue(
        "ferrum-edge/ferrum-edge",
        "token",
        paged_listing_request(full_window_pages(unique_in_window)),
    )
    if found_in_full_window != unique_in_window:
        failures.append("unique match in a full listing window must still be discovered")
    try:
        find_signal_issue(
            "ferrum-edge/ferrum-edge",
            "token",
            paged_listing_request(full_window_pages(None)),
        )
        failures.append("full listing window with no match must fail closed")
    except SignalError as exc:
        if "pagination bound" not in exc.message:
            failures.append(
                f"full listing window with no match must name the pagination bound, got {exc.message}"
            )

    captured: list[tuple[str, str, dict[str, Any] | None]] = []

    def fake_request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        captured.append((method, url, body))
        if method == "GET" and "/issues?" in url:
            listing_query_ok(url)
            return []
        if method == "POST" and url.endswith("/issues"):
            assert body is not None
            assert body["title"] == ISSUE_TITLE
            assert body["labels"] == list(ISSUE_LABELS)
            assert MARKER in body["body"]
            return signal_issue(42, body=body["body"])
        raise AssertionError(f"unexpected {method} {url}")

    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("open", "scaling matrix result is failure", False),
        "https://github.com/ferrum-edge/ferrum-edge/actions/runs/1",
        True,
        fake_request,
    )
    if not any(method == "POST" and url.endswith("/issues") for method, url, _ in captured):
        failures.append("self-test expected issue creation on open")

    captured.clear()

    def reopen_request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        captured.append((method, url, body))
        if method == "GET" and "/issues?" in url:
            listing_query_ok(url)
            return [closed]
        if method == "PATCH" and url.endswith("/issues/13"):
            assert body is not None
            assert body.get("state") == "open"
            assert "labels" not in body
            return closed
        raise AssertionError(f"unexpected {method} {url}")

    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("open", "scaling matrix result is failure", False),
        "https://github.com/ferrum-edge/ferrum-edge/actions/runs/1",
        True,
        reopen_request,
    )
    if not any(method == "PATCH" and url.endswith("/issues/13") for method, url, _ in captured):
        failures.append("self-test expected closed publisher-owned issue to be reopened")

    captured.clear()
    already_open = signal_issue(14, state="open")

    def update_open_request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        captured.append((method, url, body))
        if method == "GET" and "/issues?" in url:
            listing_query_ok(url)
            return [already_open]
        if method == "PATCH" and url.endswith("/issues/14"):
            assert body is not None
            assert "labels" not in body
            assert "state" not in body
            return already_open
        raise AssertionError(f"unexpected {method} {url}")

    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("open", "scaling matrix result is failure", False, 100),
        canonical_actions_run_url(server, repo, 100),
        True,
        update_open_request,
    )
    if not any(method == "PATCH" and url.endswith("/issues/14") for method, url, _ in captured):
        failures.append("self-test expected open publisher-owned issue to be updated without replacing labels")

    def close_request(
        existing: dict[str, Any], *, allow_patch: bool
    ) -> Callable[[str, str, str, dict[str, Any] | None], Any]:
        def request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
            captured.append((method, url, body))
            if method == "GET" and "/issues?" in url:
                listing_query_ok(url)
                return [existing]
            if allow_patch and method == "PATCH" and url.endswith(f"/issues/{existing['number']}"):
                assert body is not None
                assert body.get("state") == "closed"
                assert "labels" not in body
                return existing
            raise AssertionError(f"unexpected {method} {url}")

        return request

    newer_recorded = signal_issue(
        15,
        body=issue_body("already open", canonical_actions_run_url(server, repo, newer)),
    )
    captured.clear()
    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("close", "latest successful scaling run is within freshness", False, current),
        canonical_actions_run_url(server, repo, current),
        True,
        close_request(newer_recorded, allow_patch=False),
    )
    if any(method == "PATCH" for method, _, _ in captured):
        failures.append("must not close when recorded run id is newer than the decision")

    unreadable_recorded = signal_issue(16, body=MARKER + "\nno run line")
    captured.clear()
    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("close", "latest successful scaling run is within freshness", False, current),
        canonical_actions_run_url(server, repo, current),
        True,
        close_request(unreadable_recorded, allow_patch=False),
    )
    if any(method == "PATCH" for method, _, _ in captured):
        failures.append("must not close when recorded run id is unreadable")

    older_recorded = signal_issue(
        17,
        body=issue_body("stale open", canonical_actions_run_url(server, repo, older)),
    )
    captured.clear()
    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("close", "latest successful scaling run is within freshness", False, current),
        canonical_actions_run_url(server, repo, current),
        True,
        close_request(older_recorded, allow_patch=True),
    )
    if not any(method == "PATCH" and url.endswith("/issues/17") for method, url, _ in captured):
        failures.append("newer close must proceed when recorded run id is older")

    def empty_create(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        if method == "GET" and "/issues?" in url:
            listing_query_ok(url)
            return []
        if method == "POST" and url.endswith("/issues"):
            return {}
        raise AssertionError(f"unexpected {method} {url}")

    try:
        apply_decision(
            "ferrum-edge/ferrum-edge",
            "token",
            Decision("open", "scaling matrix result is failure", False),
            "https://github.com/ferrum-edge/ferrum-edge/actions/runs/1",
            True,
            empty_create,
        )
        failures.append("empty create response must fail closed")
    except SignalError as exc:
        if exc.code != "schema":
            failures.append(f"empty create must fail schema-closed, got {exc.code}")

    def no_mutate_request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        raise AssertionError("off-main must not call GitHub")

    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("open", "stale", True),
        "https://example.invalid",
        False,
        no_mutate_request,
    )

    body = issue_body("reason", "https://example.invalid/run")
    if MARKER not in body:
        failures.append("issue body must carry the durable signal marker")
    nasty = "boom\n`inject` " + ("A" * 400)
    sanitized = issue_body(nasty, expected_url)
    reason_lines = [line for line in sanitized.splitlines() if line.startswith("Reason: ")]
    if len(reason_lines) != 1:
        failures.append("issue body must carry exactly one Reason line")
    else:
        reason_line = reason_lines[0]
        payload = reason_line[len("Reason: ") :]
        if "`" in payload or "\n" in payload:
            failures.append("issue Reason line must strip backticks and newlines")
        if len(payload) > ISSUE_REASON_MAX_CHARS:
            failures.append("issue Reason line must stay within the public-reason bound")
        if "inject" not in payload:
            failures.append("issue Reason line must keep the sanitized message")

    if MAX_AGE_SECONDS != 8 * 24 * 60 * 60:
        failures.append("freshness ceiling drifted from the weekly-plus-one-day contract")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1
    print("scaling-gate-signal self-test passed")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    try:
        return run_live(utc_now())
    except SignalError as exc:
        print(f"::error::{exc.code}: {exc.message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
