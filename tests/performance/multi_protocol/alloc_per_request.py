"""Allocator calls per proxied request from `bench-h1-profile` counters (#6022 item 1).

`alloc_per_request.sh` scrapes the gateway's `ferrum_h1_profile_alloc_process_*`
counters and the echo backend's `/bench-stats` counters before and after each
measured client run. This module turns one run directory into per-request
figures and summarizes all runs by path and role (candidate/baseline).

Allocator calls are `alloc` + `alloc_zeroed`; `realloc` and `dealloc` calls are
reported beside them. Requests are the echoes the backend served between the
two scrapes, so client warmup/drain requests are counted on both sides and
gateway-only traffic (health probes, metrics scrapes) is not a request.

The counters are process-wide, published per thread every 1024 observer events
(docs/h1_internal_profile.md). A thread's unpublished tail is outside a scrape,
so `unpublished_events` at the two scrapes bounds the window's error in events;
`lost_events` or `missing_slots` mark a run incomplete. Background activity
(admin, metrics rendering, timers) is estimated from an idle scrape taken five
seconds after the window.

Data only: no process is started here.
"""

import argparse
import json
import os
import re
import statistics
from pathlib import Path

PREFIX = "ferrum_h1_profile_"
METRIC = re.compile(r"ferrum_h1_profile_([a-z0-9_]+) ([0-9]+)")
ALLOC = "alloc_process_alloc_calls"
ZEROED = "alloc_process_zeroed_calls"
REALLOC = "alloc_process_realloc_calls"
DEALLOC = "alloc_process_dealloc_calls"
BYTES = "alloc_process_successful_requested_bytes"
REQUIRED = (ALLOC, ZEROED, REALLOC, DEALLOC, BYTES, "unpublished_events", "lost_events",
            "missing_slots", "allocator_installed", "schema")
ECHO_FIELDS = ("http_echo_requests", "grpc_echo_requests")
PATHS = ("h1", "h1-reqwest", "h2", "grpc", "h3")
ROLES = ("candidate", "baseline")
PATH_LABELS = {
    "h1": "HTTP/1.1 -> HTTP/1.1, direct hyper pool (default)",
    "h1-reqwest": "HTTP/1.1 -> HTTP/1.1, reqwest (FERRUM_POOL_HTTP1_DIRECT=false)",
    "h2": "HTTP/2+TLS -> HTTP/2+TLS, direct HTTP/2 pool",
    "grpc": "gRPC+TLS -> gRPC+TLS, gRPC pool",
    "h3": "HTTP/3 -> HTTP/3, native HTTP/3 pool",
}


def parse_metrics(text):
    """Return the `ferrum_h1_profile_*` counters; duplicates are refused."""
    counters = {}
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        match = METRIC.fullmatch(line.strip())
        if not match:
            raise ValueError("malformed H1 profile metric line")
        if match[1] in counters:
            raise ValueError(f"duplicate H1 profile metric {match[1]}")
        counters[match[1]] = int(match[2])
    missing = [name for name in REQUIRED if name not in counters]
    if missing:
        raise ValueError(f"missing H1 profile metrics: {', '.join(missing)}")
    if counters["allocator_installed"] != 1:
        raise ValueError("the counting allocator is not installed in this binary")
    return counters


def _read_text(path):
    try:
        return Path(path).read_text()
    except OSError:
        return None


def _read_json(path):
    text = _read_text(path)
    if text is None:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _read_time(path):
    text = _read_text(path)
    try:
        return float(text) if text is not None else None
    except ValueError:
        return None


def _echoes(stats):
    if stats is None:
        return None
    values = [stats.get(field) for field in ECHO_FIELDS]
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
        return None
    return sum(values)


def record(directory):
    """Per-request figures for one measured run directory."""
    directory = Path(directory)
    result = {"run": directory.name}
    if (directory / "failure.txt").exists():
        result["error"] = (_read_text(directory / "failure.txt") or "failed").strip()
        return result
    try:
        before = parse_metrics(_read_text(directory / "metrics_before.txt") or "")
        after = parse_metrics(_read_text(directory / "metrics_after.txt") or "")
    except ValueError as error:
        result["error"] = f"gateway counters: {error}"
        return result
    first = _echoes(_read_json(directory / "backend_before.json"))
    last = _echoes(_read_json(directory / "backend_after.json"))
    if first is None or last is None or last <= first:
        result["error"] = "backend echo counters missing or not advancing"
        return result
    requests = last - first
    delta = {name: after[name] - before[name] for name in (ALLOC, ZEROED, REALLOC, DEALLOC, BYTES)}
    if any(value < 0 for value in delta.values()):
        result["error"] = "gateway counters went backwards (restart or overflow)"
        return result
    allocations = delta[ALLOC] + delta[ZEROED]
    result.update(
        requests=requests,
        allocations=allocations,
        allocations_per_request=allocations / requests,
        reallocations_per_request=delta[REALLOC] / requests,
        deallocations_per_request=delta[DEALLOC] / requests,
        requested_bytes_per_request=delta[BYTES] / requests,
        # Upper bound on events the two scrapes could not see, per request.
        unpublished_events_bound_per_request=(
            before["unpublished_events"] + after["unpublished_events"]) / requests,
        complete=(after["lost_events"] == before["lost_events"]
                  and before["missing_slots"] == 0 and after["missing_slots"] == 0),
    )
    started = _read_time(directory / "time_before.txt")
    ended = _read_time(directory / "time_after.txt")
    idled = _read_time(directory / "time_idle.txt")
    idle_text = _read_text(directory / "metrics_idle.txt")
    if None not in (started, ended, idled) and idle_text and idled > ended > started:
        try:
            idle = parse_metrics(idle_text)
            idle_allocations = (idle[ALLOC] + idle[ZEROED]) - (after[ALLOC] + after[ZEROED])
            rate = idle_allocations / (idled - ended)
            result["idle_allocations_per_second"] = rate
            result["background_allocations_per_request_estimate"] = (
                rate * (ended - started) / requests)
        except ValueError:
            pass
    client = _read_json(directory / "client.json")
    if client is not None:
        result["client_errors"] = client.get("total_errors")
        result["client_rps"] = client.get("rps")
    exit_code = (_read_text(directory / "client.exit") or "").strip()
    if exit_code not in ("", "0"):
        result["error"] = f"client exited with {exit_code}"
    elif isinstance(result.get("client_errors"), int) and result["client_errors"] > 0:
        result["error"] = f"{result['client_errors']} client errors"
    return result


def _spread(values):
    if not values:
        return None
    return {"median": statistics.median(values), "min": min(values), "max": max(values),
            "runs": len(values)}


def summarize(output, paths, roles, rounds, settings):
    output = Path(output)
    runs = {}
    for path in paths:
        for role in roles:
            rows = []
            for round_number in range(1, rounds + 1):
                directory = output / "raw" / path / f"{role}-r{round_number}"
                row = record(directory) if directory.is_dir() else {
                    "run": directory.name, "error": "run directory missing"}
                rows.append(row)
                if directory.is_dir():
                    (directory / "result.json").write_text(json.dumps(row, indent=2) + "\n")
            runs[path, role] = rows
    summary = {"settings": settings, "revisions": {}, "paths": {}}
    for role in roles:
        revision = _read_text(output / f"{role}-revision.txt")
        summary["revisions"][role] = revision.strip() if revision else None
    complete = True
    for path in paths:
        entry = {"label": PATH_LABELS[path]}
        for role in roles:
            rows = runs[path, role]
            valid = [row for row in rows if "error" not in row]
            complete = complete and len(valid) == len(rows) and all(r["complete"] for r in valid)
            entry[role] = {
                "allocations_per_request": _spread(
                    [row["allocations_per_request"] for row in valid]),
                "reallocations_per_request": _spread(
                    [row["reallocations_per_request"] for row in valid]),
                "requested_bytes_per_request": _spread(
                    [row["requested_bytes_per_request"] for row in valid]),
                "unpublished_events_bound_per_request": max(
                    (row["unpublished_events_bound_per_request"] for row in valid), default=None),
                "background_allocations_per_request_estimate": max(
                    (row.get("background_allocations_per_request_estimate", 0) for row in valid),
                    default=None),
                "requests_per_run": _spread([row["requests"] for row in valid]),
                "errors": [f"{row['run']}: {row['error']}" for row in rows if "error" in row],
            }
        candidate = (entry.get("candidate") or {}).get("allocations_per_request")
        baseline = (entry.get("baseline") or {}).get("allocations_per_request")
        if candidate and baseline:
            entry["candidate_minus_baseline_median"] = candidate["median"] - baseline["median"]
        summary["paths"][path] = entry
    summary["complete"] = complete
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    markdown = render_markdown(summary, roles)
    (output / "summary.md").write_text(markdown)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a") as handle:
            handle.write(markdown)
    print(markdown)
    return summary


def _fmt(spread):
    if not spread:
        return "—"
    if spread["min"] == spread["max"]:
        return f"{spread['median']:.2f}"
    return f"{spread['median']:.2f} ({spread['min']:.2f}–{spread['max']:.2f})"


def render_markdown(summary, roles):
    settings = summary["settings"]
    lines = ["# Allocator calls per proxied request (#6022 item 1)", ""]
    for role in roles:
        lines.append(f"- **{role}:** `{summary['revisions'].get(role) or 'unknown'}`")
    lines.append(
        f"- **Settings:** profile `{settings.get('profile')}`, {settings.get('duration')} s per "
        f"run, concurrency {settings.get('concurrency')}, payload {settings.get('payload_size')} B,"
        f" {settings.get('rounds')} round(s)")
    lines += ["", "Allocator calls are `alloc` + `alloc_zeroed` per echo the backend served; "
              "median over rounds, with the range in parentheses.", ""]
    header = ["Path"] + [f"{role} allocs/req" for role in roles]
    if "baseline" in roles:
        header.append("Δ median")
    header += [f"{role} reallocs/req" for role in roles]
    header += ["Bound (unpublished + background)/req", "Errors"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join("---" for _ in header) + "|")
    for path, entry in summary["paths"].items():
        row = [f"`{path}` {entry['label']}"]
        row += [_fmt(entry[role]["allocations_per_request"]) for role in roles]
        if "baseline" in roles:
            delta = entry.get("candidate_minus_baseline_median")
            row.append("—" if delta is None else f"{delta:+.2f}")
        row += [_fmt(entry[role]["reallocations_per_request"]) for role in roles]
        bounds = []
        for role in roles:
            unpublished = entry[role]["unpublished_events_bound_per_request"]
            background = entry[role]["background_allocations_per_request_estimate"]
            if unpublished is not None:
                bounds.append(f"{unpublished + (background or 0):.3f}")
        row.append(" / ".join(bounds) or "—")
        errors = sum(len(entry[role]["errors"]) for role in roles)
        row.append(str(errors))
        lines.append("| " + " | ".join(row) + " |")
    if not summary["complete"]:
        lines += ["", "**Incomplete:** at least one run failed or lost counter events; see "
                  "`summary.json` and each run's `result.json`."]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    summarize_parser = sub.add_parser("summarize")
    summarize_parser.add_argument("output")
    summarize_parser.add_argument("--paths", required=True)
    summarize_parser.add_argument("--roles", required=True)
    summarize_parser.add_argument("--rounds", type=int, required=True)
    summarize_parser.add_argument("--profile", required=True)
    summarize_parser.add_argument("--duration", type=int, required=True)
    summarize_parser.add_argument("--concurrency", type=int, required=True)
    summarize_parser.add_argument("--payload-size", type=int, required=True)
    args = parser.parse_args()
    paths = args.paths.split()
    roles = args.roles.split()
    if not paths or any(path not in PATHS for path in paths):
        raise SystemExit("unknown path")
    if not roles or any(role not in ROLES for role in roles) or roles[0] != "candidate":
        raise SystemExit("roles must be candidate [baseline]")
    settings = {"profile": args.profile, "duration": args.duration,
                "concurrency": args.concurrency, "payload_size": args.payload_size,
                "rounds": args.rounds}
    summary = summarize(args.output, paths, roles, args.rounds, settings)
    # A failed or incomplete run must not read as a clean measurement.
    if not summary["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
