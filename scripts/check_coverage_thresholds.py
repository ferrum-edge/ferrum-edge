#!/usr/bin/env python3
"""Validate remote cargo-llvm-cov reports against repository coverage gates."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def normalize_path(path: str, workspace: Path) -> str:
    raw = path.replace("\\", "/")
    workspace_raw = str(workspace).replace("\\", "/")
    if raw.startswith(workspace_raw + "/"):
        return raw[len(workspace_raw) + 1 :]
    marker = "/src/plugins/"
    if marker in raw:
        return "src/plugins/" + raw.split(marker, 1)[1]
    return raw.lstrip("./")


def is_plugin_path(path: str) -> bool:
    return path == "src/plugins" or path.startswith("src/plugins/")


def percent(covered: int, count: int) -> float:
    if count == 0:
        return 0.0
    return covered / count * 100.0


def load_json_metrics(coverage_json: Path, workspace: Path) -> tuple[dict[str, float], dict[str, float]]:
    report = json.loads(coverage_json.read_text(encoding="utf-8"))

    overall_count = 0
    overall_covered = 0
    plugin_count = 0
    plugin_covered = 0

    for data in report.get("data", []):
        totals = data.get("totals", {}).get("lines", {})
        overall_count += int(totals.get("count", 0) or 0)
        overall_covered += int(totals.get("covered", 0) or 0)

        for file_entry in data.get("files", []):
            filename = normalize_path(str(file_entry.get("filename", "")), workspace)
            if not is_plugin_path(filename):
                continue
            lines = file_entry.get("summary", {}).get("lines", {})
            plugin_count += int(lines.get("count", 0) or 0)
            plugin_covered += int(lines.get("covered", 0) or 0)

    return (
        {
            "covered": overall_covered,
            "count": overall_count,
            "percent": percent(overall_covered, overall_count),
        },
        {
            "covered": plugin_covered,
            "count": plugin_count,
            "percent": percent(plugin_covered, plugin_count),
        },
    )


def parse_lcov(lcov_path: Path, workspace: Path) -> dict[str, dict[int, int]]:
    coverage: dict[str, dict[int, int]] = {}
    current_file: str | None = None

    for line in lcov_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("SF:"):
            current_file = normalize_path(line[3:], workspace)
            coverage.setdefault(current_file, {})
            continue
        if current_file is None or not line.startswith("DA:"):
            continue

        payload = line[3:].split(",", 2)
        if len(payload) < 2:
            continue
        try:
            line_number = int(payload[0])
            hit_count = int(payload[1])
        except ValueError:
            continue
        coverage[current_file][line_number] = hit_count

    return coverage


def parse_changed_lines(diff_text: str) -> dict[str, set[int]]:
    changed: dict[str, set[int]] = {}
    current_file: str | None = None
    next_line: int | None = None
    hunk_pattern = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[len("+++ b/") :]
            changed.setdefault(current_file, set())
            next_line = None
            continue
        if line.startswith("@@ "):
            match = hunk_pattern.match(line)
            next_line = int(match.group(1)) if match else None
            continue
        if current_file is None or next_line is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            changed[current_file].add(next_line)
            next_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        else:
            next_line += 1

    return {path: lines for path, lines in changed.items() if is_plugin_path(path) and lines}


def git_diff(base_ref: str) -> str:
    commands = [
        ["git", "diff", "--unified=0", "--no-ext-diff", f"{base_ref}...HEAD", "--", "src/plugins"],
        ["git", "diff", "--unified=0", "--no-ext-diff", f"{base_ref}..HEAD", "--", "src/plugins"],
    ]
    last_error = ""
    for command in commands:
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        if result.returncode == 0:
            return result.stdout
        last_error = result.stderr.strip()
    raise RuntimeError(f"failed to read plugin diff against {base_ref}: {last_error}")


def changed_line_metrics(lcov_path: Path, workspace: Path, base_ref: str) -> dict[str, float] | None:
    changed = parse_changed_lines(git_diff(base_ref))
    if not changed:
        return None

    lcov = parse_lcov(lcov_path, workspace)
    covered = 0
    count = 0
    ignored = 0

    for path, lines in changed.items():
        file_coverage = lcov.get(path, {})
        for line_number in lines:
            if line_number not in file_coverage:
                ignored += 1
                continue
            count += 1
            if file_coverage[line_number] > 0:
                covered += 1

    if count == 0:
        return {
            "covered": 0,
            "count": 0,
            "percent": 0.0,
            "ignored": ignored,
        }

    return {
        "covered": covered,
        "count": count,
        "percent": percent(covered, count),
        "ignored": ignored,
    }


def format_metric(name: str, metric: dict[str, float], threshold: float | None) -> str:
    threshold_text = "n/a" if threshold is None else f"{threshold:.2f}%"
    return (
        f"| {name} | {int(metric['covered'])}/{int(metric['count'])} | "
        f"{metric['percent']:.2f}% | {threshold_text} |"
    )


def append_summary(lines: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage-json", type=Path, required=True)
    parser.add_argument("--lcov", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--min-overall-line", type=float, required=True)
    parser.add_argument("--min-plugins-line", type=float, required=True)
    parser.add_argument("--min-changed-plugins-line", type=float, required=True)
    parser.add_argument("--changed-base")
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    overall, plugins = load_json_metrics(args.coverage_json, workspace)
    changed = (
        changed_line_metrics(args.lcov, workspace, args.changed_base)
        if args.changed_base
        else None
    )

    summary_lines = [
        "## Coverage Gate",
        "",
        "| Scope | Covered lines | Coverage | Threshold |",
        "| --- | ---: | ---: | ---: |",
        format_metric("overall", overall, args.min_overall_line),
        format_metric("src/plugins", plugins, args.min_plugins_line),
    ]

    if changed is None:
        summary_lines.append("| changed src/plugins lines | n/a | n/a | n/a |")
    elif int(changed["count"]) == 0:
        summary_lines.append(
            f"| changed src/plugins lines | 0/0 | n/a | {args.min_changed_plugins_line:.2f}% |"
        )
    else:
        summary_lines.append(
            format_metric(
                "changed src/plugins lines",
                changed,
                args.min_changed_plugins_line,
            )
        )

    append_summary(summary_lines)
    print("\n".join(summary_lines))

    failures: list[str] = []
    if overall["percent"] < args.min_overall_line:
        failures.append(
            f"overall line coverage {overall['percent']:.2f}% is below "
            f"{args.min_overall_line:.2f}%"
        )
    if plugins["percent"] < args.min_plugins_line:
        failures.append(
            f"src/plugins line coverage {plugins['percent']:.2f}% is below "
            f"{args.min_plugins_line:.2f}%"
        )
    if (
        changed is not None
        and int(changed["count"]) > 0
        and changed["percent"] < args.min_changed_plugins_line
    ):
        failures.append(
            f"changed src/plugins line coverage {changed['percent']:.2f}% is below "
            f"{args.min_changed_plugins_line:.2f}%"
        )

    for failure in failures:
        print(f"::error::{failure}", file=sys.stderr)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
