#!/usr/bin/env python3
"""Idempotently publish the reviewed Ferrum Edge launch-audit findings.

The script intentionally creates public issues only. It uses exact hidden markers and
normalized titles for idempotency, refreshes the complete live open backlog before
publication, and verifies every marker after publication. Semantic overlaps are not
silently skipped: each reviewed finding contains an explicit overlap/unique-scope
section naming the existing issue or PR when applicable.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

API = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "ferrum-launch-readiness-audit-publisher/1.0"

MANIFEST_BODY_REWRITES: dict[str, tuple[str, str]] = {
    "ferrum-launch-audit:dr-max-connections-pooled-04b523ef": (
        "Related open issue #3227 covers retiring a connection after `maxRequestsPerConnection`. "
        "This issue is distinct: it enforces concurrent physical connection-count admission from "
        "`tcp.maxConnections` across pooled transports.",
        "Umbrella overlap: open issue #2110 tracks the deferred DestinationRule pool-limit surface, "
        "including close-after-N and other incomplete transport projections. This issue is distinct: "
        "it implements concurrent physical connection-count admission from `tcp.maxConnections` "
        "across pooled transports, with separate pool-key, permit-lifecycle, multiplexing, and reload "
        "acceptance criteria.",
    ),
}


def normalize_title(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def overlap_text(body: str) -> str:
    match = re.search(
        r"## Existing-issue / PR overlap and unique scope\s*(.*?)\s*## How to verify",
        body,
        flags=re.S,
    )
    if not match:
        raise ValueError("finding body is missing the overlap/unique-scope section")
    return " ".join(match.group(1).split())


def load_findings(manifest_file: pathlib.Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payload = json.loads(manifest_file.read_text(encoding="utf-8"))
    findings = payload["findings"]
    for item in findings:
        rewrite = MANIFEST_BODY_REWRITES.get(item.get("marker", ""))
        if rewrite is None:
            continue
        old, new = rewrite
        body = item["body"]
        if new not in body:
            if old not in body:
                raise ValueError(f"expected manifest rewrite source missing: {item['marker']}")
            item["body"] = body.replace(old, new, 1)
    expected = 81
    if len(findings) != expected:
        raise ValueError(f"manifest count mismatch: expected {expected}, loaded {len(findings)}")
    titles = [normalize_title(item["title"]) for item in findings]
    markers = [item["marker"] for item in findings]
    if len(set(titles)) != len(titles):
        raise ValueError("manifest contains duplicate normalized titles")
    if len(set(markers)) != len(markers):
        raise ValueError("manifest contains duplicate markers")
    for item in findings:
        body = item["body"]
        if f"<!-- {item['marker']} -->" not in body:
            raise ValueError(f"marker missing from body: {item['marker']}")
        overlap_text(body)
        if len(item["title"]) > 256:
            raise ValueError(f"title too long: {item['title']}")
        if len(body.encode("utf-8")) > 60_000:
            raise ValueError(f"body too large: {item['title']}")
    index = {
        "repository": payload["repository"],
        "audited_sha": payload["audited_sha"],
        "verified_main_sha": payload["verified_main_sha"],
        "finding_count": len(findings),
    }
    return index, findings


class GitHub:
    def __init__(self, token: str, repository: str) -> None:
        self.token = token
        self.repository = repository

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        attempts: int = 8,
    ) -> Any:
        url = path if path.startswith("https://") else f"{API}{path}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        for attempt in range(attempts):
            request = urllib.request.Request(
                url,
                data=data,
                method=method,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self.token}",
                    "X-GitHub-Api-Version": API_VERSION,
                    "User-Agent": USER_AGENT,
                    **({"Content-Type": "application/json"} if data is not None else {}),
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    raw = response.read()
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="replace")
                retryable = error.code in {403, 408, 409, 429, 500, 502, 503, 504}
                if not retryable or attempt + 1 >= attempts:
                    raise RuntimeError(
                        f"GitHub API {method} {url} failed with {error.code}: {detail}"
                    ) from error
                retry_after = error.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = max(1.0, float(retry_after))
                else:
                    delay = min(90.0, (2 ** attempt) + random.uniform(0.25, 1.25))
                print(
                    f"retryable GitHub error {error.code}; sleeping {delay:.1f}s "
                    f"before attempt {attempt + 2}/{attempts}",
                    flush=True,
                )
                time.sleep(delay)
            except (urllib.error.URLError, TimeoutError) as error:
                if attempt + 1 >= attempts:
                    raise
                delay = min(60.0, (2 ** attempt) + random.uniform(0.25, 1.0))
                print(f"network error {error}; retrying in {delay:.1f}s", flush=True)
                time.sleep(delay)
        raise AssertionError("unreachable")

    def get_all(self, endpoint: str, *, state: str = "open") -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        page = 1
        while True:
            separator = "&" if "?" in endpoint else "?"
            path = f"/repos/{self.repository}/{endpoint}{separator}state={state}&per_page=100&page={page}"
            batch = self.request("GET", path)
            if not isinstance(batch, list):
                raise RuntimeError(f"expected list from {path}")
            rows.extend(batch)
            if len(batch) < 100:
                return rows
            page += 1

    def create_issue(self, title: str, body: str) -> dict[str, Any]:
        return self.request(
            "POST",
            f"/repos/{self.repository}/issues",
            {"title": title, "body": body},
        )


def make_indexes(rows: Iterable[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_title: dict[str, dict[str, Any]] = {}
    by_marker: dict[str, dict[str, Any]] = {}
    marker_re = re.compile(r"ferrum-launch-audit:[a-z0-9-]+-[0-9a-f]{8}")
    for row in rows:
        title = normalize_title(row.get("title") or "")
        if title:
            by_title.setdefault(title, row)
        body = row.get("body") or ""
        for marker in marker_re.findall(body):
            by_marker.setdefault(marker, row)
    return by_title, by_marker


def compact_row(row: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        "status": status,
        "number": row.get("number"),
        "title": row.get("title"),
        "url": row.get("html_url"),
        "state": row.get("state"),
    }


def write_checkpoint(path: pathlib.Path, payload: dict[str, Any]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-file", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--resolved-manifest", type=pathlib.Path, required=True)
    parser.add_argument("--delay", type=float, default=1.35)
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repository:
        raise SystemExit("GITHUB_TOKEN and GITHUB_REPOSITORY are required")

    index, findings = load_findings(args.manifest_file)
    if repository != index["repository"]:
        raise SystemExit(f"repository mismatch: manifest={index['repository']} env={repository}")

    args.resolved_manifest.parent.mkdir(parents=True, exist_ok=True)
    args.resolved_manifest.write_text(
        json.dumps({**index, "findings": findings}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    client = GitHub(token, repository)
    # `issues?state=all` includes pull requests and protects reruns from duplicating a
    # prior marker even if an issue was closed while this workflow was interrupted.
    all_issue_rows = client.get_all("issues", state="all")
    open_issue_api_rows = [row for row in all_issue_rows if row.get("state") == "open"]
    open_issues = [row for row in open_issue_api_rows if "pull_request" not in row]
    open_pulls = client.get_all("pulls", state="open")
    all_by_title, all_by_marker = make_indexes(all_issue_rows)
    open_numbers = {int(row["number"]) for row in open_issue_api_rows}

    checkpoint: dict[str, Any] = {
        "repository": repository,
        "audited_sha": index["audited_sha"],
        "verified_main_sha": index["verified_main_sha"],
        "requested": len(findings),
        "open_issue_count_at_start": len(open_issues),
        "open_pr_count_at_start": len(open_pulls),
        "results": {},
    }

    # Validate that every manually cited overlap was open at publication time.
    # References in source/permalink text are outside the overlap section and are
    # intentionally ignored here.
    overlap_reference_warnings: list[dict[str, Any]] = []
    for item in findings:
        section = overlap_text(item["body"])
        refs = sorted({int(value) for value in re.findall(r"#(\d+)", section)})
        closed_refs = [number for number in refs if number not in open_numbers]
        if closed_refs:
            overlap_reference_warnings.append(
                {"slug": item["slug"], "title": item["title"], "not_open": closed_refs}
            )
    checkpoint["overlap_reference_warnings"] = overlap_reference_warnings
    if overlap_reference_warnings:
        print("warning: some snapshot overlap references are no longer open:", flush=True)
        print(json.dumps(overlap_reference_warnings, indent=2), flush=True)

    for position, item in enumerate(findings, 1):
        marker = item["marker"]
        normalized = normalize_title(item["title"])
        existing = all_by_marker.get(marker) or all_by_title.get(normalized)
        if existing is not None:
            checkpoint["results"][marker] = compact_row(existing, "already-existed")
            write_checkpoint(args.output, checkpoint)
            print(
                f"[{position:02d}/{len(findings)}] existing #{existing.get('number')}: {item['title']}",
                flush=True,
            )
            continue

        live_note = (
            "\n## Live duplicate screening\n\n"
            f"Immediately before this publication run, the complete live backlog contained "
            f"**{len(open_issues)} open issues** and **{len(open_pulls)} open pull requests**. "
            "No existing open item had this finding's hidden audit marker or normalized title. "
            "Mechanism-level overlap found during semantic review is identified in the section above; "
            "the remaining scope and acceptance criteria are intentionally distinct.\n"
        )
        created = client.create_issue(item["title"], item["body"].rstrip() + "\n" + live_note)
        checkpoint["results"][marker] = compact_row(created, "created")
        all_by_marker[marker] = created
        all_by_title[normalized] = created
        write_checkpoint(args.output, checkpoint)
        print(
            f"[{position:02d}/{len(findings)}] created #{created.get('number')}: {item['title']}",
            flush=True,
        )
        time.sleep(max(1.0, args.delay))

    # Post-verify every marker against all issue states. This also makes a partially
    # interrupted rerun self-healing and produces a hard completion condition.
    final_rows = client.get_all("issues", state="all")
    final_by_title, final_by_marker = make_indexes(final_rows)
    missing: list[str] = []
    for item in findings:
        row = final_by_marker.get(item["marker"]) or final_by_title.get(normalize_title(item["title"]))
        if row is None:
            missing.append(item["marker"])
            continue
        checkpoint["results"][item["marker"]] = {
            **compact_row(row, checkpoint["results"][item["marker"]]["status"]),
            "verified": True,
        }

    created_count = sum(row["status"] == "created" for row in checkpoint["results"].values())
    existing_count = sum(row["status"] == "already-existed" for row in checkpoint["results"].values())
    checkpoint["created_count"] = created_count
    checkpoint["already_existed_count"] = existing_count
    checkpoint["verified_count"] = len(findings) - len(missing)
    checkpoint["missing_markers"] = missing
    checkpoint["complete"] = not missing and len(checkpoint["results"]) == len(findings)
    write_checkpoint(args.output, checkpoint)

    print(json.dumps({
        "requested": len(findings),
        "created": created_count,
        "already_existed": existing_count,
        "verified": checkpoint["verified_count"],
        "missing": missing,
        "complete": checkpoint["complete"],
    }, indent=2), flush=True)
    return 0 if checkpoint["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
