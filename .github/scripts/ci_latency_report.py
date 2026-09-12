#!/usr/bin/env python3
r"""Read-only hosted CI latency report (issue #4672).

The report separates the four costs issue #4672 asks to be measured before any
cancellation, batching, or cadence policy is changed:

* **queued time** — job creation to job start;
* **execution** — job start to job completion;
* **serial dependency chains** — how much of a run's wall time is spent waiting
  for a previous wave of jobs to finish rather than executing;
* **attempts, cancellations, and whole-required-set completion** — how often a
  head is validated more than once, how much execution lands inside runs that
  are eventually cancelled, and how long it takes for every required context to
  complete for one exact head under one event.

Everything here is read-only. The script never dispatches, re-runs, cancels, or
mutates anything, and it never reads a check verdict from a different head SHA.

The required-context inventory is read from
``.github/required-publication-checks.json`` so this report cannot drift from
the publication gate's own list. That file is frozen by the trusted policy and
is only ever read here.

Usage::

    # Collect from the API and report in one pass.
    python3 .github/scripts/ci_latency_report.py \
        --repository ferrum-edge/ferrum-edge --workflow all --runs 400 \
        --output-dir report

    # Re-report from an earlier collection without touching the network.
    python3 .github/scripts/ci_latency_report.py --input-dir report/raw \
        --output-dir report

    # Offline contract check.
    python3 .github/scripts/ci_latency_report.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

API_ROOT = "https://api.github.com"
REQUIRED_CHECKS_PATH = Path(".github/required-publication-checks.json")
# The Actions REST API caps a listing at 1,000 results, so a wider window has
# to be collected in slices. This tool stays inside one slice on purpose: it is
# a repeatable spot report, not the week-long audit #4672 accepts on.
MAX_RUNS = 1000
PAGE_SIZE = 100
# Two job-creation timestamps closer together than this are treated as one
# dispatch wave. Actions creates a wave's jobs within a few seconds of each
# other, so the gap between waves is what a `needs:` edge actually costs.
WAVE_GAP_SECONDS = 30.0
DEFAULT_WORKFLOW = "all"


class ReportError(RuntimeError):
    """A collection or input problem the caller must see rather than absorb."""


def parse_timestamp(value: Any) -> datetime | None:
    """Parse one ISO-8601 Actions timestamp, or return ``None``."""

    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def elapsed_seconds(start: Any, end: Any) -> float | None:
    """Seconds between two Actions timestamps, or ``None`` when unusable.

    A negative interval is reported as ``None`` rather than clamped to zero:
    the API occasionally records a job start before its creation, and silently
    rewriting that to zero would understate queueing without saying so.
    """

    first = parse_timestamp(start)
    second = parse_timestamp(end)
    if first is None or second is None:
        return None
    delta = (second - first).total_seconds()
    return delta if delta >= 0 else None


def percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile. ``None`` for an empty sample."""

    if not values:
        return None
    ordered = sorted(values)
    if fraction <= 0:
        return ordered[0]
    rank = max(1, min(len(ordered), int(-(-fraction * len(ordered) // 1))))
    return ordered[rank - 1]


def minutes(seconds: float | None) -> float | None:
    return None if seconds is None else round(seconds / 60.0, 2)


def load_required_contexts(repo_root: Path) -> list[dict[str, str]]:
    """Read the publication gate's own required-context inventory."""

    path = repo_root / REQUIRED_CHECKS_PATH
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ReportError(f"missing {REQUIRED_CHECKS_PATH}") from error
    except json.JSONDecodeError as error:
        raise ReportError(f"{REQUIRED_CHECKS_PATH} is not valid JSON: {error}") from error
    entries = document.get("required_checks")
    if not isinstance(entries, list) or not entries:
        raise ReportError(f"{REQUIRED_CHECKS_PATH} declares no required checks")
    contexts: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReportError(f"{REQUIRED_CHECKS_PATH} has a malformed entry")
        context = entry.get("context")
        workflow_path = entry.get("workflow_path")
        evidence = entry.get("evidence", "")
        if not isinstance(context, str) or not isinstance(workflow_path, str):
            raise ReportError(f"{REQUIRED_CHECKS_PATH} entry lacks context/workflow_path")
        contexts.append(
            {
                "context": context,
                "workflow_path": workflow_path,
                "evidence": evidence if isinstance(evidence, str) else "",
            }
        )
    return contexts


def api_get(url: str, token: str | None) -> Any:
    """One authenticated read of the Actions API."""

    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("User-Agent", "ferrum-edge-ci-latency-report")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise ReportError(f"GET {url} failed with HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise ReportError(f"GET {url} failed: {error}") from error


def collect_runs(
    repository: str,
    token: str | None,
    limit: int,
    workflow: str | None,
) -> list[dict[str, Any]]:
    """Page the run listing until ``limit`` runs are collected."""

    if workflow:
        base = f"{API_ROOT}/repos/{repository}/actions/workflows/{workflow}/runs"
    else:
        base = f"{API_ROOT}/repos/{repository}/actions/runs"
    collected: list[dict[str, Any]] = []
    page = 1
    while len(collected) < limit:
        query = urllib.parse.urlencode({"per_page": PAGE_SIZE, "page": page})
        payload = api_get(f"{base}?{query}", token)
        runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
        if not runs:
            break
        collected.extend(runs)
        if len(runs) < PAGE_SIZE:
            break
        page += 1
    return collected[:limit]


def collect_jobs(
    repository: str,
    token: str | None,
    runs: Iterable[dict[str, Any]],
    max_fetches: int,
) -> dict[int, list[dict[str, Any]]]:
    """Fetch the job inventory for at most ``max_fetches`` runs."""

    jobs: dict[int, list[dict[str, Any]]] = {}
    fetched = 0
    for run in runs:
        if fetched >= max_fetches:
            break
        run_id = run.get("id")
        if not isinstance(run_id, int):
            continue
        base = f"{API_ROOT}/repos/{repository}/actions/runs/{run_id}/jobs"
        page = 1
        run_jobs: list[dict[str, Any]] = []
        while True:
            query = urllib.parse.urlencode(
                {"per_page": PAGE_SIZE, "page": page, "filter": "latest"}
            )
            payload = api_get(f"{base}?{query}", token)
            batch = payload.get("jobs") if isinstance(payload, dict) else None
            if not batch:
                break
            run_jobs.extend(batch)
            if len(batch) < PAGE_SIZE:
                break
            page += 1
        jobs[run_id] = run_jobs
        fetched += 1
    return jobs


def dispatch_waves(job_records: list[dict[str, Any]]) -> int:
    """Count distinct job-creation waves inside one run attempt.

    This is an approximation of serial dependency depth, not a `needs:` graph
    read: the API does not expose the dependency edges. Jobs created within
    ``WAVE_GAP_SECONDS`` of each other are one wave, so the wave count is the
    number of times the run had to wait for an earlier wave before it could
    create the next one.
    """

    created = sorted(
        stamp
        for stamp in (parse_timestamp(job.get("created_at")) for job in job_records)
        if stamp is not None
    )
    if not created:
        return 0
    waves = 1
    previous = created[0]
    for stamp in created[1:]:
        if (stamp - previous).total_seconds() > WAVE_GAP_SECONDS:
            waves += 1
        previous = stamp
    return waves


def summarize_jobs(
    runs: list[dict[str, Any]],
    jobs_by_run: dict[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Queue, execution, serial-chain and cancelled-execution accounting."""

    run_by_id = {run.get("id"): run for run in runs}
    queue_seconds: list[float] = []
    execution_seconds: list[float] = []
    chain_seconds: list[float] = []
    wave_counts: list[float] = []
    cancelled_execution = 0.0
    total_execution = 0.0
    per_job: dict[str, list[float]] = defaultdict(list)
    per_job_queue: dict[str, list[float]] = defaultdict(list)
    for run_id, job_records in sorted(jobs_by_run.items(), key=lambda item: item[0]):
        run = run_by_id.get(run_id, {})
        run_cancelled = run.get("conclusion") == "cancelled"
        creations = [
            stamp
            for stamp in (parse_timestamp(job.get("created_at")) for job in job_records)
            if stamp is not None
        ]
        completions = [
            stamp
            for stamp in (
                parse_timestamp(job.get("completed_at")) for job in job_records
            )
            if stamp is not None
        ]
        if creations and completions:
            span = (max(completions) - min(creations)).total_seconds()
            if span >= 0:
                chain_seconds.append(span)
        if job_records:
            wave_counts.append(float(dispatch_waves(job_records)))
        for job in job_records:
            name = str(job.get("name", "")) or "(unnamed)"
            queued = elapsed_seconds(job.get("created_at"), job.get("started_at"))
            if queued is not None:
                queue_seconds.append(queued)
                per_job_queue[name].append(queued)
            executed = elapsed_seconds(job.get("started_at"), job.get("completed_at"))
            if executed is None:
                continue
            execution_seconds.append(executed)
            per_job[name].append(executed)
            total_execution += executed
            if run_cancelled:
                cancelled_execution += executed
    slowest = sorted(
        (
            {
                "job": name,
                "samples": len(samples),
                "p50_minutes": minutes(percentile(samples, 0.50)),
                "p95_minutes": minutes(percentile(samples, 0.95)),
                "queue_p95_minutes": minutes(
                    percentile(per_job_queue.get(name, []), 0.95)
                ),
            }
            for name, samples in per_job.items()
        ),
        key=lambda entry: entry["p50_minutes"] or 0.0,
        reverse=True,
    )
    return {
        "runs_with_jobs": len(jobs_by_run),
        "job_attempts": len(execution_seconds),
        "queue_p50_minutes": minutes(percentile(queue_seconds, 0.50)),
        "queue_p95_minutes": minutes(percentile(queue_seconds, 0.95)),
        "execution_p50_minutes": minutes(percentile(execution_seconds, 0.50)),
        "execution_p95_minutes": minutes(percentile(execution_seconds, 0.95)),
        "run_span_p50_minutes": minutes(percentile(chain_seconds, 0.50)),
        "run_span_p95_minutes": minutes(percentile(chain_seconds, 0.95)),
        "dispatch_waves_p50": percentile(wave_counts, 0.50),
        "dispatch_waves_p95": percentile(wave_counts, 0.95),
        "execution_minutes_total": round(total_execution / 60.0, 1),
        "execution_minutes_in_cancelled_runs": round(cancelled_execution / 60.0, 1),
        "slowest_jobs": slowest[:12],
    }


def summarize_required_sets(
    runs: list[dict[str, Any]],
    required: list[dict[str, str]],
) -> dict[str, Any]:
    """Whole-required-set completion per exact head SHA and event.

    Verdicts are joined on ``(head_sha, event)`` so a later push cancellation
    can never overwrite a merge-group or pull-request observation of the same
    commit. Incomplete heads stay in the denominator; percentiles cover only
    the complete ones and therefore carry survivorship bias.
    """

    by_head: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        head = run.get("head_sha")
        event = run.get("event")
        if isinstance(head, str) and isinstance(event, str):
            by_head[(head, event)].append(run)
    # A push has no associated pull request, so a `pr_head` context cannot run
    # for it. Reporting those heads as incomplete would count a structural
    # absence as latency.
    push_required = [
        entry["workflow_path"] for entry in required if entry["evidence"] != "pr_head"
    ]
    all_required = [entry["workflow_path"] for entry in required]
    results: dict[str, dict[str, Any]] = {}
    for event in sorted({event for _, event in by_head}):
        expected = push_required if event == "push" else all_required
        complete = 0
        heads = 0
        completion_seconds: list[float] = []
        for (_, head_event), head_runs in by_head.items():
            if head_event != event:
                continue
            heads += 1
            successful: dict[str, datetime] = {}
            earliest: datetime | None = None
            for run in head_runs:
                path = run.get("path")
                created = parse_timestamp(run.get("created_at"))
                if created is not None and (earliest is None or created < earliest):
                    earliest = created
                if run.get("conclusion") != "success" or not isinstance(path, str):
                    continue
                finished = parse_timestamp(run.get("updated_at"))
                if finished is None:
                    continue
                previous = successful.get(path)
                if previous is None or finished < previous:
                    successful[path] = finished
            if earliest is None or not all(path in successful for path in expected):
                continue
            complete += 1
            span = (
                max(successful[path] for path in expected) - earliest
            ).total_seconds()
            if span >= 0:
                completion_seconds.append(span)
        results[event] = {
            "heads": heads,
            "complete_sets": complete,
            "expected_contexts": len(expected),
            "p50_minutes": minutes(percentile(completion_seconds, 0.50)),
            "p95_minutes": minutes(percentile(completion_seconds, 0.95)),
        }
    return results


def summarize(
    runs: list[dict[str, Any]],
    jobs_by_run: dict[int, list[dict[str, Any]]],
    required: list[dict[str, str]],
) -> dict[str, Any]:
    """Build the whole report structure from collected API records."""

    by_event: dict[str, Counter[str]] = defaultdict(Counter)
    attempts: Counter[int] = Counter()
    reattempted_heads: set[str] = set()
    created = [parse_timestamp(run.get("created_at")) for run in runs]
    window = [stamp for stamp in created if stamp is not None]
    for run in runs:
        event = str(run.get("event", "unknown"))
        conclusion = str(run.get("conclusion") or run.get("status") or "unknown")
        by_event[event][conclusion] += 1
        attempt = run.get("run_attempt")
        if isinstance(attempt, int):
            attempts[attempt] += 1
            head = run.get("head_sha")
            if attempt > 1 and isinstance(head, str):
                reattempted_heads.add(head)
    required_paths = {entry["workflow_path"] for entry in required}
    observed_paths = sorted(
        required_paths
        & {run["path"] for run in runs if isinstance(run.get("path"), str)}
    )
    return {
        "runs": len(runs),
        "window_start": min(window).isoformat() if window else None,
        "window_end": max(window).isoformat() if window else None,
        "required_contexts": [entry["context"] for entry in required],
        "required_workflows_observed": observed_paths,
        "required_workflows_expected": len(required_paths),
        "runs_by_event": {
            event: dict(sorted(counts.items())) for event, counts in sorted(by_event.items())
        },
        "attempts": dict(sorted(attempts.items())),
        "reattempted_heads": len(reattempted_heads),
        "jobs": summarize_jobs(runs, jobs_by_run),
        "required_set_completion": summarize_required_sets(runs, required),
    }


def render_markdown(summary: dict[str, Any]) -> str:
    """Render the report. Every caveat #4672 requires stays attached."""

    lines: list[str] = []
    lines.append("# Hosted CI latency report")
    lines.append("")
    lines.append(
        f"Collected {summary['runs']} runs "
        f"from {summary['window_start']} to {summary['window_end']} (UTC)."
    )
    lines.append("")
    lines.append(
        "Read-only. Conclusions are the latest retained conclusion per run: a "
        "`cancelled` conclusion may be pending coalescing, an explicit "
        "cancellation, or a lost hosted runner, and this report does not "
        "distinguish them. Percentiles over successful sets carry survivorship "
        "bias, and one collection window is not the representative week issue "
        "#4672 accepts on."
    )
    lines.append("")
    lines.append("## Runs by event and conclusion")
    lines.append("")
    lines.append("| Event | Conclusion | Runs |")
    lines.append("| --- | --- | ---: |")
    for event, counts in summary["runs_by_event"].items():
        for conclusion, count in counts.items():
            lines.append(f"| {event} | {conclusion} | {count} |")
    lines.append("")
    lines.append("## Attempts")
    lines.append("")
    lines.append("| Attempt | Runs |")
    lines.append("| ---: | ---: |")
    for attempt, count in summary["attempts"].items():
        lines.append(f"| {attempt} | {count} |")
    lines.append("")
    lines.append(
        f"Distinct heads validated more than once: {summary['reattempted_heads']}."
    )
    lines.append("")
    jobs = summary["jobs"]
    lines.append("## Queue, execution and serial dependency")
    lines.append("")
    lines.append("| Measure | p50 | p95 |")
    lines.append("| --- | ---: | ---: |")
    lines.append(
        f"| Job queue/dispatch (min) | {jobs['queue_p50_minutes']} "
        f"| {jobs['queue_p95_minutes']} |"
    )
    lines.append(
        f"| Job execution (min) | {jobs['execution_p50_minutes']} "
        f"| {jobs['execution_p95_minutes']} |"
    )
    lines.append(
        f"| Run creation to last job completion (min) | "
        f"{jobs['run_span_p50_minutes']} | {jobs['run_span_p95_minutes']} |"
    )
    lines.append(
        f"| Job dispatch waves per run | {jobs['dispatch_waves_p50']} "
        f"| {jobs['dispatch_waves_p95']} |"
    )
    lines.append("")
    lines.append(
        "A dispatch wave is a group of jobs created within "
        f"{int(WAVE_GAP_SECONDS)}s of each other. The wave count approximates "
        "serial dependency depth; the Actions API does not expose `needs:` "
        "edges, so it is not a read of the dependency graph."
    )
    lines.append("")
    lines.append(
        f"Job execution across {jobs['job_attempts']} job attempts: "
        f"{jobs['execution_minutes_total']} minutes, of which "
        f"{jobs['execution_minutes_in_cancelled_runs']} minutes ran inside runs "
        "that were eventually cancelled. That second figure includes jobs that "
        "completed before the cancellation, so it is not a claim that every "
        "minute was wasted."
    )
    lines.append("")
    lines.append("## Slowest jobs")
    lines.append("")
    lines.append("| Job | Samples | Execution p50 (min) | Execution p95 (min) | Queue p95 (min) |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for entry in jobs["slowest_jobs"]:
        lines.append(
            f"| {entry['job']} | {entry['samples']} | {entry['p50_minutes']} "
            f"| {entry['p95_minutes']} | {entry['queue_p95_minutes']} |"
        )
    lines.append("")
    lines.append("## Whole-required-set completion")
    lines.append("")
    lines.append(
        "Required contexts: " + ", ".join(summary["required_contexts"]) + "."
    )
    lines.append("")
    observed = summary["required_workflows_observed"]
    expected = summary["required_workflows_expected"]
    lines.append(
        f"This collection contains runs from {len(observed)} of the {expected} "
        "required workflows. A collection narrowed to one workflow cannot "
        "complete a required set, so a low completion count below is a "
        "property of the collection, not of the repository."
    )
    lines.append("")
    lines.append(
        "Joined on the exact `(head_sha, event)` pair, so a later push "
        "cancellation cannot overwrite a merge-group or pull-request "
        "observation of the same commit. `push` heads exclude the "
        "pull-request-head context, which structurally cannot run for a push."
    )
    lines.append("")
    lines.append("| Event | Heads | Complete sets | Contexts | p50 (min) | p95 (min) |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for event, entry in summary["required_set_completion"].items():
        lines.append(
            f"| {event} | {entry['heads']} | {entry['complete_sets']} "
            f"| {entry['expected_contexts']} | {entry['p50_minutes']} "
            f"| {entry['p95_minutes']} |"
        )
    lines.append("")
    return "\n".join(lines)


def read_collection(input_dir: Path) -> tuple[list[dict[str, Any]], dict[int, list[dict[str, Any]]]]:
    """Load a previous collection from disk without touching the network."""

    runs_path = input_dir / "runs.json"
    jobs_path = input_dir / "jobs.json"
    try:
        runs = json.loads(runs_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ReportError(f"missing {runs_path}") from error
    except json.JSONDecodeError as error:
        raise ReportError(f"{runs_path} is not valid JSON: {error}") from error
    if not isinstance(runs, list) or any(not isinstance(run, dict) for run in runs):
        raise ReportError(f"{runs_path} must contain a list of run objects")
    jobs_by_run: dict[int, list[dict[str, Any]]] = {}
    if jobs_path.exists():
        try:
            raw = json.loads(jobs_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ReportError(f"{jobs_path} is not valid JSON: {error}") from error
        if not isinstance(raw, dict):
            raise ReportError(f"{jobs_path} must contain a run-id mapping")
        for key, value in raw.items():
            try:
                run_id = int(key)
            except (TypeError, ValueError) as error:
                raise ReportError(f"{jobs_path} has a non-numeric run id") from error
            if not isinstance(value, list) or any(
                not isinstance(job, dict) for job in value
            ):
                raise ReportError(f"{jobs_path} run {run_id} must map to job objects")
            jobs_by_run[run_id] = value
    return runs, jobs_by_run


def write_outputs(output_dir: Path, summary: dict[str, Any], markdown: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ci-latency-report.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "ci-latency-report.md").write_text(markdown, encoding="utf-8")
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(markdown)
            handle.write("\n")


def self_test() -> int:
    """Offline contract checks. No network, no repository execution."""

    assert parse_timestamp("2026-09-08T00:00:00Z") == datetime(
        2026, 9, 8, tzinfo=timezone.utc
    )
    assert parse_timestamp(None) is None
    assert parse_timestamp("not-a-time") is None
    assert elapsed_seconds("2026-09-08T00:00:00Z", "2026-09-08T00:01:00Z") == 60.0
    # A start before creation is withheld rather than clamped to zero.
    assert elapsed_seconds("2026-09-08T00:01:00Z", "2026-09-08T00:00:00Z") is None
    assert elapsed_seconds("2026-09-08T00:00:00Z", None) is None
    assert percentile([], 0.5) is None
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 0.95) == 4.0

    required = [
        {"context": "Tests", "workflow_path": ".github/workflows/ci.yml", "evidence": "check_run"},
        {
            "context": "Trusted Cross Build Policy",
            "workflow_path": ".github/workflows/cross-build-policy.yml",
            "evidence": "pr_head",
        },
    ]
    runs = [
        {
            "id": 1,
            "event": "pull_request",
            "conclusion": "success",
            "run_attempt": 1,
            "head_sha": "aaa",
            "path": ".github/workflows/ci.yml",
            "created_at": "2026-09-08T00:00:00Z",
            "updated_at": "2026-09-08T01:00:00Z",
        },
        {
            "id": 2,
            "event": "pull_request",
            "conclusion": "success",
            "run_attempt": 2,
            "head_sha": "aaa",
            "path": ".github/workflows/cross-build-policy.yml",
            "created_at": "2026-09-08T00:05:00Z",
            "updated_at": "2026-09-08T00:20:00Z",
        },
        {
            "id": 3,
            "event": "push",
            "conclusion": "cancelled",
            "run_attempt": 1,
            "head_sha": "bbb",
            "path": ".github/workflows/ci.yml",
            "created_at": "2026-09-08T02:00:00Z",
            "updated_at": "2026-09-08T02:30:00Z",
        },
        {
            "id": 4,
            "event": "push",
            "conclusion": "success",
            "run_attempt": 1,
            "head_sha": "ccc",
            "path": ".github/workflows/ci.yml",
            "created_at": "2026-09-08T03:00:00Z",
            "updated_at": "2026-09-08T03:40:00Z",
        },
    ]
    jobs_by_run = {
        1: [
            {
                "name": "plan",
                "created_at": "2026-09-08T00:00:00Z",
                "started_at": "2026-09-08T00:01:00Z",
                "completed_at": "2026-09-08T00:03:00Z",
            },
            {
                "name": "test",
                "created_at": "2026-09-08T00:04:00Z",
                "started_at": "2026-09-08T00:05:00Z",
                "completed_at": "2026-09-08T00:55:00Z",
            },
        ],
        3: [
            {
                "name": "test",
                "created_at": "2026-09-08T02:00:00Z",
                "started_at": "2026-09-08T02:01:00Z",
                "completed_at": "2026-09-08T02:21:00Z",
            }
        ],
    }

    # Two waves: `test` is created four minutes after `plan`, well past the gap.
    assert dispatch_waves(jobs_by_run[1]) == 2
    assert dispatch_waves(jobs_by_run[3]) == 1
    assert dispatch_waves([]) == 0

    summary = summarize(runs, jobs_by_run, required)
    assert summary["runs"] == 4
    assert summary["attempts"] == {1: 3, 2: 1}
    assert summary["reattempted_heads"] == 1
    assert summary["runs_by_event"]["push"] == {"cancelled": 1, "success": 1}

    jobs = summary["jobs"]
    assert jobs["job_attempts"] == 3
    # 2 + 50 + 20 minutes of execution, of which the 20 sits in a cancelled run.
    assert jobs["execution_minutes_total"] == 72.0
    assert jobs["execution_minutes_in_cancelled_runs"] == 20.0
    assert jobs["queue_p50_minutes"] == 1.0
    assert jobs["slowest_jobs"][0]["job"] == "test"

    assert summary["required_workflows_expected"] == 2
    assert summary["required_workflows_observed"] == [
        ".github/workflows/ci.yml",
        ".github/workflows/cross-build-policy.yml",
    ]

    completion = summary["required_set_completion"]
    # The pull-request head needs both contexts and has both: complete, and the
    # span runs from the earliest run creation to the last required success.
    assert completion["pull_request"]["heads"] == 1
    assert completion["pull_request"]["complete_sets"] == 1
    assert completion["pull_request"]["expected_contexts"] == 2
    assert completion["pull_request"]["p50_minutes"] == 60.0
    # Push heads expect only the non-`pr_head` context, so `ccc` is complete
    # and the cancelled `bbb` head stays in the denominator.
    assert completion["push"]["heads"] == 2
    assert completion["push"]["complete_sets"] == 1
    assert completion["push"]["expected_contexts"] == 1
    assert completion["push"]["p50_minutes"] == 40.0

    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        (root / ".github").mkdir()
        inventory = root / REQUIRED_CHECKS_PATH
        inventory.write_text(
            json.dumps(
                {
                    "required_checks": [
                        {
                            "context": "Tests",
                            "workflow_path": ".github/workflows/ci.yml",
                            "evidence": "check_run",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        loaded = load_required_contexts(root)
        assert loaded == [
            {
                "context": "Tests",
                "workflow_path": ".github/workflows/ci.yml",
                "evidence": "check_run",
            }
        ]
        inventory.write_text(json.dumps({"required_checks": []}), encoding="utf-8")
        try:
            load_required_contexts(root)
        except ReportError:
            pass
        else:  # pragma: no cover - the loader must fail closed
            raise AssertionError("an empty inventory must be rejected")

    markdown = render_markdown(summary)
    assert "# Hosted CI latency report" in markdown
    assert "Whole-required-set completion" in markdown
    assert "survivorship bias" in markdown
    assert "2 of the 2" in markdown

    print("ci_latency_report self-test passed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run offline checks")
    parser.add_argument(
        "--check-inventory",
        action="store_true",
        help="parse the required-context inventory and exit",
    )
    parser.add_argument("--repository", help="OWNER/NAME to collect from")
    parser.add_argument(
        "--workflow",
        default=DEFAULT_WORKFLOW,
        help=(
            "workflow file to collect, or 'all' for every workflow "
            f"(default: {DEFAULT_WORKFLOW})"
        ),
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=400,
        help=f"runs to collect, at most {MAX_RUNS} (default: 400)",
    )
    parser.add_argument(
        "--max-job-fetches",
        type=int,
        default=120,
        help="runs whose job inventory is fetched (default: 120)",
    )
    parser.add_argument("--input-dir", type=Path, help="report from a saved collection")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ci-latency-report"),
        help="directory for the report and raw collection",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path("."),
        help="repository root holding the required-check inventory",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.check_inventory:
        try:
            required = load_required_contexts(args.repo_root)
        except ReportError as error:
            print(f"ci_latency_report: {error}", file=sys.stderr)
            return 1
        print(f"required contexts: {len(required)}")
        for entry in required:
            print(f"  {entry['context']} <- {entry['workflow_path']}")
        return 0
    if not args.input_dir and not args.repository:
        parser.error("--repository or --input-dir is required unless --self-test is used")
    if args.runs < 1 or args.runs > MAX_RUNS:
        parser.error(f"--runs must be between 1 and {MAX_RUNS}")
    if args.max_job_fetches < 0:
        parser.error("--max-job-fetches must not be negative")

    try:
        required = load_required_contexts(args.repo_root)
        if args.input_dir:
            runs, jobs_by_run = read_collection(args.input_dir)
        else:
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            workflow = None if args.workflow == "all" else args.workflow
            runs = collect_runs(args.repository, token, args.runs, workflow)
            jobs_by_run = collect_jobs(
                args.repository, token, runs, args.max_job_fetches
            )
            raw_dir = args.output_dir / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            (raw_dir / "runs.json").write_text(
                json.dumps(runs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (raw_dir / "jobs.json").write_text(
                json.dumps(
                    {str(key): value for key, value in jobs_by_run.items()},
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        summary = summarize(runs, jobs_by_run, required)
        markdown = render_markdown(summary)
        write_outputs(args.output_dir, summary, markdown)
    except ReportError as error:
        print(f"ci_latency_report: {error}", file=sys.stderr)
        return 1
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
