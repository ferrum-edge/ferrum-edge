#!/usr/bin/env python3
"""Select successful scheduled workflow runs from this repository's main branch."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import urllib.request
from typing import Any

API_ROOT = "https://api.github.com"


def select_runs(
    payload: Any,
    *,
    repository: str,
    workflow_path: str,
    current_sha: str,
    limit: int,
) -> list[str]:
    """Return run ids after checking all origin and workflow identity fields."""
    if not isinstance(payload, dict) or not isinstance(payload.get("workflow_runs"), list):
        raise ValueError("workflow-runs response is malformed")
    runs = payload["workflow_runs"]
    if len(runs) > 100:
        raise ValueError("workflow-runs page exceeded the requested bound")

    selected: list[str] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        head_repository = run.get("head_repository")
        if (
            run.get("event") != "schedule"
            or run.get("head_branch") != "main"
            or not isinstance(head_repository, dict)
            or head_repository.get("full_name") != repository
            or run.get("path") != workflow_path
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
        ):
            continue
        head_sha = run.get("head_sha")
        if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
            continue
        if head_sha == current_sha:
            continue
        run_id = run.get("id")
        if isinstance(run_id, int) and run_id > 0:
            selected.append(str(run_id))
        if len(selected) == limit:
            break
    return selected


def self_test() -> None:
    repo = "ferrum-edge/ferrum-edge"
    path = ".github/workflows/example.yml"
    sha = "a" * 40

    def run(run_id: int, **updates: Any) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": run_id,
            "event": "schedule",
            "head_branch": "main",
            "head_repository": {"full_name": repo},
            "path": path,
            "status": "completed",
            "conclusion": "success",
            "head_sha": "b" * 40,
        }
        result.update(updates)
        return result

    candidates = [
        run(10, event="pull_request", head_repository={"full_name": "fork/project"}),
        run(11, head_repository={"full_name": "fork/project"}),
        run(12, path=".github/workflows/other.yml"),
        run(13, head_branch="feature"),
        run(14, conclusion="failure"),
        run(15, head_sha=sha),
        run(16),
    ]
    actual = select_runs(
        {"workflow_runs": candidates},
        repository=repo,
        workflow_path=path,
        current_sha=sha,
        limit=10,
    )
    if actual != ["16"]:
        raise AssertionError(f"unexpected trusted run selection: {actual!r}")

    try:
        select_runs(
            {"workflow_runs": [run(1)] * 101},
            repository=repo,
            workflow_path=path,
            current_sha=sha,
            limit=10,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("oversized workflow-runs pages must fail closed")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--current-sha", required=True)
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        print("trusted scheduled-run selector self-test passed")
        return 0
    if args.limit < 1 or args.limit > 100:
        parser.error("--limit must be between 1 and 100")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise SystemExit("GITHUB_REPOSITORY is missing or malformed")
    if not re.fullmatch(r"[0-9a-f]{40}", args.current_sha):
        raise SystemExit("--current-sha must be a full commit id")
    workflow_path = f".github/workflows/{args.workflow}"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", args.workflow):
        raise SystemExit("--workflow must be a workflow file name")
    url = (
        f"{API_ROOT}/repos/{repository}/actions/workflows/{args.workflow}/runs"
        "?branch=main&event=schedule&per_page=100"
    )
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("User-Agent", "ferrum-edge-trusted-scheduled-runs")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        selected = select_runs(
            payload,
            repository=repository,
            workflow_path=workflow_path,
            current_sha=args.current_sha,
            limit=args.limit,
        )
    # `OSError` covers `URLError`, timeouts, and connection resets; a
    # truncated body raises `http.client.IncompleteRead`. History is optional,
    # so every transport or decode failure starts fresh instead of failing.
    except (OSError, http.client.HTTPException, ValueError) as exc:
        print(
            f"::warning::Could not load trusted scheduled-run history; starting fresh: {exc}",
            file=sys.stderr,
        )
        return 0
    sys.stdout.write("\n".join(selected))
    if selected:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
