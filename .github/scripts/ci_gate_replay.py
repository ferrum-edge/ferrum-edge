#!/usr/bin/env python3
"""Replay merged pull requests through two revisions of the CI relevance gates.

Answers "what would each pull request have scheduled?" for a baseline and a
candidate revision of the PR-time gates, without dispatching anything:

* `pr_ci_plan.py` (ci.yml light/full mode and every `run_*` job gate),
* `live_suite_path_filter.py` (the dedicated Kind live suites),
* workflow-level `on.pull_request.paths` filters of every workflow.

Each merged pull request (squash `(#N)` or `Merge pull request #N` commit) on the first-parent history of `--ref` is one
sample; its changed-file list is `git diff --name-only --no-renames C^1 C`.
Both gate revisions are loaded from Git objects (default baseline
`origin/main`, candidate the working tree) so the comparison is exact.

Output is JSON (`--json`) plus a Markdown summary on stdout. Multiply the
per-job schedule counts by measured hosted job durations to estimate
runner-minute savings; this tool never talks to the GitHub API.

    python3 .github/scripts/ci_gate_replay.py --since 2026-08-24
    python3 .github/scripts/ci_gate_replay.py --baseline <sha> --candidate WORKTREE
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from types import ModuleType

import yaml

WORKTREE = "WORKTREE"
PR_SUBJECT_RE = re.compile(r"^Merge pull request #(\d+) |\(#(\d+)\)\s*$")
LIVE_SUITES = (
    "gateway-api",
    "mesh-federation",
    "mesh-e2e-sidecar",
    "ambient-host-udp",
    "istio-status-cas",
    "cni-lifecycle",
)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def read_revision_file(revision: str, path: str) -> str | None:
    if revision == WORKTREE:
        file = Path(path)
        return file.read_text(encoding="utf-8") if file.is_file() else None
    try:
        return git("show", f"{revision}:{path}")
    except subprocess.CalledProcessError:
        return None


def load_module(revision: str, path: str, name: str, workdir: Path) -> ModuleType:
    source = read_revision_file(revision, path)
    if source is None:
        raise SystemExit(f"{path} is missing at {revision}")
    target = workdir / f"{name}.py"
    target.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(name, target)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {path} at {revision}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def github_glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate an Actions `paths:` glob (`**`, `*`, `?`) to a regex."""

    out = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
            continue
        if pattern.startswith("**", index):
            out.append(".*")
            index += 2
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(char))
        index += 1
    return re.compile("^" + "".join(out) + "$")


def workflow_pr_filters(revision: str) -> dict[str, list[re.Pattern[str]] | None]:
    """Map workflow file -> compiled PR path filters (None = every PR)."""

    if revision == WORKTREE:
        names = sorted(p.name for p in Path(".github/workflows").glob("*.yml"))
    else:
        names = sorted(
            Path(p).name
            for p in git("ls-tree", "--name-only", revision, ".github/workflows/").split()
            if p.endswith(".yml")
        )
    filters: dict[str, list[re.Pattern[str]] | None] = {}
    for name in names:
        text = read_revision_file(revision, f".github/workflows/{name}")
        if text is None:
            continue
        document = yaml.safe_load(text) or {}
        triggers = document.get(True, document.get("on"))
        if isinstance(triggers, str):
            triggers = {triggers: None}
        if isinstance(triggers, list):
            triggers = {trigger: None for trigger in triggers}
        if not isinstance(triggers, dict):
            continue
        for event in ("pull_request", "pull_request_target"):
            if event not in triggers:
                continue
            config = triggers[event] or {}
            paths = config.get("paths") if isinstance(config, dict) else None
            filters[name] = (
                [github_glob_to_regex(str(p)) for p in paths] if paths else None
            )
            break
    return filters


def workflow_triggered(filters: list[re.Pattern[str]] | None, files: list[str]) -> bool:
    if filters is None:
        return True
    return any(regex.match(path) for path in files for regex in filters)


def merged_pull_requests(ref: str, since: str | None, limit: int | None) -> list[dict]:
    args = ["log", "--first-parent", "--format=%H%x09%ad%x09%s", "--date=short", ref]
    if since:
        args.insert(1, f"--since={since}")
    samples = []
    for line in git(*args).splitlines():
        sha, date, subject = line.split("\t", 2)
        match = PR_SUBJECT_RE.search(subject)
        if not match:
            continue
        try:
            names = git("diff", "--name-only", "--no-renames", "-z", f"{sha}^1", sha)
        except subprocess.CalledProcessError:
            continue  # parent outside a shallow clone
        files = [path for path in names.split("\0") if path]
        number = int(match.group(1) or match.group(2))
        samples.append({"sha": sha, "date": date, "pr": number, "files": files})
        if limit and len(samples) >= limit:
            break
    return samples


def evaluate(revision: str, samples: list[dict], workdir: Path, tag: str) -> list[dict]:
    planner = load_module(revision, ".github/scripts/pr_ci_plan.py", f"plan_{tag}", workdir)
    live = load_module(
        revision, ".github/scripts/live_suite_path_filter.py", f"live_{tag}", workdir
    )
    filters = workflow_pr_filters(revision)
    results = []
    for sample in samples:
        files = sample["files"]
        mode, _ = planner.select_mode("pull_request", files)
        gates = planner.select_job_gates("pull_request", files)
        if mode != "full":
            gates = {name: False for name in gates}
        suites = {
            suite: bool(live.matched_files(suite, files))
            for suite in LIVE_SUITES
            if suite in getattr(live, "SUITE_PATTERNS", {})
        }
        workflows = {
            name: workflow_triggered(pattern, files) for name, pattern in filters.items()
        }
        results.append({"mode": mode, "gates": gates, "suites": suites, "workflows": workflows})
    return results


def tally(results: list[dict], key: str) -> Counter:
    counter: Counter = Counter()
    for result in results:
        for name, value in result[key].items():
            counter[name] += int(bool(value))
    return counter


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ref", default="origin/main")
    parser.add_argument("--since", help="git --since date for the PR sample")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--baseline", default="origin/main")
    parser.add_argument("--candidate", default=WORKTREE)
    parser.add_argument("--json", type=Path, help="write per-PR decisions here")
    args = parser.parse_args()

    samples = merged_pull_requests(args.ref, args.since, args.limit)
    if not samples:
        print("no merged pull requests in range", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        base = evaluate(args.baseline, samples, workdir, "base")
        cand = evaluate(args.candidate, samples, workdir, "cand")

    total = len(samples)
    lines = [
        f"# CI gate replay: {args.baseline} -> {args.candidate}",
        "",
        f"{total} merged pull requests, {samples[-1]['date']} .. {samples[0]['date']}.",
        "",
        "| Decision | Baseline | Candidate | Delta |",
        "|---|---:|---:|---:|",
    ]
    base_full = sum(r["mode"] == "full" for r in base)
    cand_full = sum(r["mode"] == "full" for r in cand)
    lines.append(f"| ci.yml full mode | {base_full} | {cand_full} | {cand_full - base_full:+d} |")
    for key, label in (("gates", "ci.yml"), ("suites", "live suite"), ("workflows", "workflow")):
        b, c = tally(base, key), tally(cand, key)
        for name in sorted(set(b) | set(c)):
            if b[name] or c[name]:
                lines.append(
                    f"| {label} `{name}` | {b[name]} | {c[name]} | {c[name] - b[name]:+d} |"
                )
    changed = [
        s["pr"]
        for s, b, c in zip(samples, base, cand)
        if b != c
    ]
    lines += ["", f"{len(changed)} pull requests change at least one decision."]
    print("\n".join(lines))
    if args.json:
        args.json.write_text(
            json.dumps(
                [
                    {**s, "baseline": b, "candidate": c}
                    for s, b, c in zip(samples, base, cand)
                ],
                indent=1,
            ),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
