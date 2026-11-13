#!/usr/bin/env python3
"""Mark the benchmark samples and comparisons that the host disturbed.

A hosted runner is shared and busy with its own housekeeping. Three things
have been seen to move a sample without the gateway under test changing:

- another process takes CPU for a second or more (the provisioner's job
  daemon after an image's first start, `hv_kvp_daemon` every 60 seconds on
  some runner models), so gateway and backend CPU dip together;
- the host does less work per CPU-second for a while, so the same arm costs
  more CPU per request in one pair than in the other with no dip at all;
- the provisioner's first-start reaction comes late and lands in a measured
  cell although the first-start settle ran.

This flags them. It changes nothing that is measured, drops nothing and
re-runs nothing: it reads what a run recorded and writes what it found into
each sample, each paired comparison and `host_disturbance.json`.

Inputs per sample: the stamped sample JSON, and the sampler's time series in
`diagnostics/<gateway>_<payload>_process_usage.json`. Runs recorded with the
sampler's `--host-cpu` also carry host-wide CPU, which separates "the host was
busy with something else" from "this arm's own CPU dipped", and names the
processes. Older runs carry only the benchmark's own processes; for those the
CPU dip is the only evidence, and the flags say so.
"""

import argparse
import json
import os
import sys
from pathlib import Path

SCHEMA = 1

# A sample of the series is "low" when gateway plus backend CPU is under this
# share of the cell's plateau, its upper-quartile level. Disturbed cells sat
# at 0.75-0.85 of it. The plateau and not the median: a dip that lasts half
# the cell would otherwise become the norm it is measured against.
DIP_RATIO = 0.88
# Consecutive low samples that make a dip: one second at the 0.5 s interval.
# A single low sample is ordinary scheduling noise.
DIP_MIN_SAMPLES = 2
# Host CPU outside the benchmark, above the cell's own floor (its
# lower-quartile level), that makes a burst. hv_kvp_daemon's is about half a
# core, the provisioner's a full one.
BURST_CORES = 0.25
BURST_MIN_SAMPLES = 2
# The provisioner's job daemon is `/tmp/provjobd<digits>`.
PROVISIONER_PREFIX = "provjobd"
# CPU-seconds of it inside one cell that count as its first-start reaction.
# The reaction is 2-6; its idle background over a cell is under 0.2.
PROVISIONER_CPU_SECONDS = 1.0
# A settle record below this did not see the reaction (see host_settle.py).
SETTLE_REACTION_CPU_SECONDS = 1.0
# Gateway AND backend CPU per request both this much higher in one pair than
# in another, for one arm and payload. On runners without the effect the two
# pairs agree within 5% at 10 KiB and 70 KiB.
DRIFT_RATIO = 1.06
# Samples with fewer requests than this are not compared: at 512 KiB and above
# a sample completes too few for CPU per request to be that steady, and pairs
# on quiet runners differ by up to 9%.
DRIFT_MIN_REQUESTS = 20000
# Known periodic host activity, in seconds, and how loosely events must line up.
PERIODS = (60.0,)
PERIOD_TOLERANCE = 3.0
PERIOD_MIN_EVENTS = 3
# An interval shorter than this cannot resolve CPU ticks; the sampler's first
# two samples are a millisecond apart.
MIN_INTERVAL_SECONDS = 0.1
# Fewer usable intervals than this and a median means nothing.
MIN_INTERVALS = 8
# Processes below this are not worth naming beside a sample: the provisioner's
# idle background over one cell is 0.15-0.4 CPU-seconds, hv_kvp_daemon's burst
# is over one. The sampler's own report keeps every process it saw.
NAMED_PROCESS_CPU_SECONDS = 0.5
BENCHMARK_ROLES = ("gateway", "backend")

THRESHOLDS = {
    "dip_ratio": DIP_RATIO, "dip_min_samples": DIP_MIN_SAMPLES,
    "burst_cores": BURST_CORES, "burst_min_samples": BURST_MIN_SAMPLES,
    "provisioner_cpu_seconds": PROVISIONER_CPU_SECONDS,
    "settle_reaction_cpu_seconds": SETTLE_REACTION_CPU_SECONDS,
    "drift_ratio": DRIFT_RATIO, "drift_min_requests": DRIFT_MIN_REQUESTS,
    "periods_seconds": list(PERIODS),
    "period_tolerance_seconds": PERIOD_TOLERANCE, "period_min_events": PERIOD_MIN_EVENTS,
}


def load(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def write_json(path, document):
    temporary = f"{path}.tmp"
    with open(temporary, "w") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)


def is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def measurement_window(sample):
    """(start, end) unix seconds of the measured interval, or None."""
    phases = sample.get("phases") if isinstance(sample, dict) else None
    if not isinstance(phases, dict):
        return None
    start, duration = phases.get("measurement_start_unix_secs"), phases.get("measurement_secs")
    if not is_number(start) or not is_number(duration) or duration <= 0:
        return None
    return start, start + duration


def intervals(timeline, window):
    """CPU rates between consecutive samples that lie inside the measured window.

    Each row: start and end time, `gateway` and `backend` cores and their sum
    `benchmark`, and `other` (host cores busy outside every sampled process, or
    None when the series has no host CPU or a sampled process appeared or
    vanished).
    Without a window the first two and the last interval, where the client is
    starting and stopping, are left out.
    """
    rows = []
    for before, after in zip(timeline, timeline[1:]):
        try:
            start, end = before["unix_secs"], after["unix_secs"]
            elapsed = end - start
            if elapsed < MIN_INTERVAL_SECONDS:
                continue
            if window is not None and (start < window[0] or end > window[1]):
                continue
            earlier = {(p["pid"], p["start_ticks"]): p for p in before["processes"]}
            later = {(p["pid"], p["start_ticks"]): p for p in after["processes"]}
            used = dict.fromkeys(BENCHMARK_ROLES, 0.0)
            complete = True
            for key, process in later.items():
                if process.get("role") in BENCHMARK_ROLES:
                    if key not in earlier:
                        complete = False
                        break
                    used[process["role"]] += process["cpu_seconds"] - earlier[key]["cpu_seconds"]
            if not complete or any(process.get("role") in BENCHMARK_ROLES and key not in later
                                   for key, process in earlier.items()):
                continue
            other = None
            host_before, host_after = before.get("host"), after.get("host")
            if (isinstance(host_before, dict) and isinstance(host_after, dict)
                    and set(earlier) == set(later)):
                sampled = sum(later[key]["cpu_seconds"] - earlier[key]["cpu_seconds"] for key in later)
                busy = host_after["busy_cpu_seconds"] - host_before["busy_cpu_seconds"]
                other = max(0.0, (busy - sampled) / elapsed)
            rows.append(dict(start=start, end=end, other=other,
                             benchmark=sum(used.values()) / elapsed,
                             **{role: used[role] / elapsed for role in BENCHMARK_ROLES}))
        except (KeyError, TypeError):
            continue
    if window is None:
        rows = rows[2:-1]
    return rows


def quartile(values, upper):
    """The upper or lower quartile of a non-empty list, without interpolation."""
    ordered = sorted(values)
    return ordered[(3 * (len(ordered) - 1) + 2) // 4] if upper else ordered[(len(ordered) - 1) // 4]


def consecutive_runs(rows, selected):
    """Maximal runs of adjacent rows for which `selected(row)` holds."""
    result, current = [], []
    for row in rows:
        if selected(row):
            current.append(row)
        else:
            if current:
                result.append(current)
            current = []
    if current:
        result.append(current)
    return result


def cpu_dips(rows):
    """Stretches where gateway plus backend CPU fell well below the cell's plateau."""
    if len(rows) < MIN_INTERVALS:
        return []
    plateau = quartile([row["benchmark"] for row in rows], upper=True)
    if plateau <= 0:
        return []
    events = []
    for run in consecutive_runs(rows, lambda row: row["benchmark"] < DIP_RATIO * plateau):
        if len(run) >= DIP_MIN_SAMPLES:
            events.append(dict(
                start_unix_secs=round(run[0]["start"], 3),
                seconds=round(run[-1]["end"] - run[0]["start"], 3),
                lowest_share_of_plateau=round(min(row["benchmark"] for row in run) / plateau, 3)))
    return events


def host_bursts(rows):
    """Stretches where the host was busy outside the benchmark, above the cell's floor.

    The floor is the baseline: softirq time the kernel charges to no process,
    and a companion such as Tyk's Redis, are a steady part of a cell's cost and
    are not a disturbance.
    """
    usable = [row for row in rows if row["other"] is not None]
    if len(usable) < MIN_INTERVALS:
        return []
    baseline = quartile([row["other"] for row in usable], upper=False)
    events = []
    for run in consecutive_runs(
            rows, lambda row: row["other"] is not None and row["other"] > baseline + BURST_CORES):
        if len(run) >= BURST_MIN_SAMPLES:
            events.append(dict(
                start_unix_secs=round(run[0]["start"], 3),
                seconds=round(run[-1]["end"] - run[0]["start"], 3),
                excess_cpu_seconds=round(sum(
                    (row["other"] - baseline) * (row["end"] - row["start"]) for row in run), 3),
                peak_cores_above_baseline=round(max(row["other"] for row in run) - baseline, 3)))
    return events


def cpu_per_request(sample, rows, role):
    """Microseconds of `role` CPU per measured request, or None when not recorded.

    The rate comes from the samples inside the measured interval, so the
    client's warm-up and drain on either side of it do not dilute it.
    """
    window = measurement_window(sample)
    requests = sample.get("total_requests")
    covered = sum(row["end"] - row["start"] for row in rows)
    if window is None or not is_number(requests) or requests <= 0 or len(rows) < MIN_INTERVALS:
        return None
    used = sum(row[role] * (row["end"] - row["start"]) for row in rows)
    if used <= 0:
        return None
    return used / covered * (window[1] - window[0]) / requests * 1e6


def provisioner_cpu(processes):
    """CPU-seconds of the provisioner's job daemon in a list of {comm, cpu_seconds}."""
    return sum(row.get("cpu_seconds", 0) for row in processes or []
               if isinstance(row, dict) and str(row.get("comm", "")).startswith(PROVISIONER_PREFIX)
               and is_number(row.get("cpu_seconds")))


def settle_reactions(settle):
    """{arm: provisioner CPU-seconds its first-start settle saw}, from host_settle.json."""
    result = {}
    if not isinstance(settle, dict):
        return result
    for record in settle.get("arms") or []:
        if not isinstance(record, dict) or record.get("reason") not in ("quiet", "max_wait"):
            continue
        # The record from before the start covers the discarded load as well;
        # an older record only has the hold after it.
        processes = record.get("host_processes_since_before_start")
        if processes is None:
            processes = record.get("top_processes")
        result[record.get("arm")] = round(provisioner_cpu(processes), 3)
    return result


def settle_arm(gateway):
    """The arm whose settle record covers this arm's image."""
    if gateway.startswith("ferrum-exp-"):
        return "ferrum"
    return "envoy" if gateway == "envoy-limit-4" else gateway


def analyse_sample(sample, usage):
    """Findings for one sample, from its own JSON and its sampler series."""
    timeline = usage.get("timeline") if isinstance(usage, dict) else None
    result = dict(flags=[], host_cpu_recorded=False)
    if not isinstance(timeline, list) or len(timeline) < 3:
        result["unavailable"] = "no sampler series"
        return result
    rows = intervals(timeline, measurement_window(sample))
    result["host_cpu_recorded"] = any(row["other"] is not None for row in rows)
    dips, bursts = cpu_dips(rows), host_bursts(rows)
    if dips:
        result["cpu_dips"] = dips
        result["flags"].append("cpu_dip")
    if bursts:
        result["host_cpu_bursts"] = bursts
        result["flags"].append("host_cpu_burst")
    processes = [row for row in usage.get("host_processes") or []
                 if isinstance(row, dict) and is_number(row.get("cpu_seconds"))
                 and row["cpu_seconds"] >= NAMED_PROCESS_CPU_SECONDS]
    if processes:
        result["host_processes"] = [dict(comm=row.get("comm"), cpu_seconds=row["cpu_seconds"])
                                    for row in processes]
    provisioner = provisioner_cpu(processes)
    if provisioner >= PROVISIONER_CPU_SECONDS:
        result["provisioner_cpu_seconds"] = round(provisioner, 3)
        result["flags"].append("provisioner_burst")
    for role in BENCHMARK_ROLES:
        value = cpu_per_request(sample, rows, role)
        if value is not None:
            result[f"{role}_cpu_us_per_request"] = round(value, 2)
    requests = sample.get("total_requests")
    result["requests"] = requests if is_number(requests) else None
    return result


def flag_cpu_per_request_drift(group):
    """Mark every sample of one arm and payload when its pairs disagree.

    The backend does the same work per request whatever the pair, and so does
    the gateway. When both cost more in the same pair, the host changed, not
    the code; nothing says which pair is the true one, so all are marked.
    """
    if any((row.get("requests") or 0) < DRIFT_MIN_REQUESTS for row in group.values()):
        return
    backend = {pair: row.get("backend_cpu_us_per_request") for pair, row in group.items()}
    gateway = {pair: row.get("gateway_cpu_us_per_request") for pair, row in group.items()}
    backend = {pair: value for pair, value in backend.items() if value}
    gateway = {pair: value for pair, value in gateway.items() if value}
    if len(backend) < 2:
        return
    high, low = max(backend, key=backend.get), min(backend, key=backend.get)
    if backend[high] < DRIFT_RATIO * backend[low]:
        return
    detail = dict(backend_percent=round(100 * (backend[high] / backend[low] - 1), 1),
                  high_pair=high, low_pair=low)
    if gateway:
        # Same two pairs, same direction: a gateway that merely differs between
        # pairs while the backend drifts the other way is not this.
        if high not in gateway or low not in gateway \
                or gateway[high] < DRIFT_RATIO * gateway[low]:
            return
        detail["gateway_percent"] = round(100 * (gateway[high] / gateway[low] - 1), 1)
    for row in group.values():
        row["cpu_per_request_drift"] = detail
        row["flags"].append("cpu_per_request_drift")


def flag_suspected_provisioner_bursts(samples, reactions, gateways, sizes):
    """Older runs: no host CPU, so infer a late first-start reaction.

    The settle saw no reaction for the arm's image and the arm's first cells of
    its first pair, where the reaction would land, show a dip that is not part
    of the run's periodic activity.
    """
    for gateway in gateways:
        reaction = reactions.get(settle_arm(gateway))
        if reaction is None or reaction >= SETTLE_REACTION_CPU_SECONDS:
            continue
        pairs = sorted(pair for (name, _, pair) in samples if name == gateway)
        if not pairs:
            continue
        for size in list(sizes)[:2]:
            row = samples.get((gateway, size, pairs[0]))
            if row and not row["host_cpu_recorded"] and "cpu_dip" in row["flags"] \
                    and not any(flag.startswith("periodic_") for flag in row["flags"]):
                row["settle_provisioner_cpu_seconds"] = reaction
                row["flags"].append("provisioner_burst_suspected")


def periodic_activity(samples):
    """Dips or bursts that recur on a known period across the whole run."""
    events = []
    for key, row in samples.items():
        # A burst names the cause; a dip is what is left when host CPU was not
        # recorded or the burst stayed under the burst threshold.
        for event in row.get("host_cpu_bursts") or row.get("cpu_dips") or []:
            events.append((event["start_unix_secs"], key))
    best = None
    for period in PERIODS:
        for anchor, _ in events:
            members = [(time, key) for time, key in events
                       if min((time - anchor) % period, (anchor - time) % period) <= PERIOD_TOLERANCE]
            span = max(time for time, _ in members) - min(time for time, _ in members)
            if len(members) >= PERIOD_MIN_EVENTS and span >= 2 * period - PERIOD_TOLERANCE \
                    and (best is None or len(members) > len(best[1])):
                best = (period, members)
    if best is None:
        return None
    period, members = best
    for _, key in members:
        flag = f"periodic_{int(period)}s"
        if flag not in samples[key]["flags"]:
            samples[key]["flags"].append(flag)
    return dict(period_seconds=period, events=len(members),
                seconds_spanned=round(max(t for t, _ in members) - min(t for t, _ in members), 1))


def analyse_run(directory, protocol, gateways, sizes, pairs):
    """Everything this module concludes about one run directory, and writes nothing."""
    directory = Path(directory)
    samples = {}
    for pair in range(1, pairs + 1):
        folder = directory / "pairs" / f"pair_{pair:03d}"
        for gateway in gateways:
            for size in sizes:
                sample = load(folder / f"{gateway}_{protocol}_{size}.json")
                if not isinstance(sample, dict):
                    continue
                usage = load(folder / "diagnostics" / f"{gateway}_{size}_process_usage.json")
                row = analyse_sample(sample, usage)
                row.update(gateway=gateway, payload_size=size, pair=pair,
                           order_position=sample.get("order_position"))
                samples[gateway, size, pair] = row
    for gateway in gateways:
        for size in sizes:
            group = {pair: samples[gateway, size, pair] for pair in range(1, pairs + 1)
                     if (gateway, size, pair) in samples}
            flag_cpu_per_request_drift(group)
    reactions = settle_reactions(load(directory / "host_settle.json"))
    periodic = periodic_activity(samples)
    flag_suspected_provisioner_bursts(samples, reactions, gateways, sizes)
    manifest = load(directory / "manifest.json")
    ordered = [samples[key] for key in sorted(samples, key=lambda k: (k[2], samples[k].get("order_position") or 0, k[1]))]
    counts = {}
    for row in ordered:
        for flag in row["flags"]:
            counts[flag] = counts.get(flag, 0) + 1
    return dict(
        schema=SCHEMA, thresholds=THRESHOLDS,
        runner_cpu_model=manifest.get("runner_cpu_model") if isinstance(manifest, dict) else None,
        host_cpu_recorded=any(row["host_cpu_recorded"] for row in ordered),
        periodic_activity=periodic, settle_provisioner_cpu_seconds=reactions,
        samples=ordered,
        summary=dict(samples=len(ordered), flagged=sum(1 for row in ordered if row["flags"]),
                     not_analysed=sum(1 for row in ordered if "unavailable" in row),
                     by_flag=dict(sorted(counts.items()))))


def sample_note(row):
    """What a sample's own JSON carries: the flags and the figures behind them."""
    note = {key: value for key, value in row.items()
            if key not in ("gateway", "payload_size", "pair", "order_position", "requests")}
    note["schema"] = SCHEMA
    return note


def comparison_note(report, baseline, candidate, size):
    rows = [row for row in report["samples"]
            if row["payload_size"] == size and row["gateway"] in (baseline, candidate) and row["flags"]]
    return dict(schema=SCHEMA,
                flags=sorted({flag for row in rows for flag in row["flags"]}),
                samples=[dict(gateway=row["gateway"], pair=row["pair"], flags=row["flags"])
                         for row in rows])


def annotate(directory, protocol, gateways, sizes, pairs):
    """Write the findings into the run directory. Returns the report."""
    directory = Path(directory)
    report = analyse_run(directory, protocol, gateways, sizes, pairs)
    by_key = {(row["gateway"], row["payload_size"], row["pair"]): row for row in report["samples"]}
    for (gateway, size, pair), row in by_key.items():
        path = directory / "pairs" / f"pair_{pair:03d}" / f"{gateway}_{protocol}_{size}.json"
        sample = load(path)
        if isinstance(sample, dict):
            sample["host_disturbance"] = sample_note(row)
            write_json(path, sample)
    for gateway in gateways:
        for size in sizes:
            path = directory / f"{gateway}_{protocol}_{size}.json"
            summary = load(path)
            if not isinstance(summary, dict):
                continue
            flagged = []
            for child in summary.get("samples") or []:
                row = by_key.get((gateway, size, child.get("pair"))) if isinstance(child, dict) else None
                if row is not None:
                    child["host_disturbance"] = sample_note(row)
                    if row["flags"]:
                        flagged.append(dict(pair=row["pair"], flags=row["flags"]))
            summary["host_disturbance"] = dict(
                schema=SCHEMA, flags=sorted({flag for item in flagged for flag in item["flags"]}),
                samples=flagged)
            write_json(path, summary)
    path = directory / "paired_comparisons.json"
    comparisons = load(path)
    if isinstance(comparisons, list):
        for row in comparisons:
            if isinstance(row, dict) and "baseline" in row and "candidate" in row:
                row["host_disturbance"] = comparison_note(
                    report, row["baseline"], row["candidate"], row.get("payload_size"))
        write_json(path, comparisons)
        report["summary"]["comparisons"] = len(comparisons)
        report["summary"]["comparisons_flagged"] = sum(
            1 for row in comparisons
            if isinstance(row, dict) and (row.get("host_disturbance") or {}).get("flags"))
    write_json(directory / "host_disturbance.json", report)
    return report


def describe(row):
    """One line of figures behind a sample's flags."""
    parts = []
    for event in row.get("host_cpu_bursts") or []:
        parts.append(f"host +{event['excess_cpu_seconds']} CPU-s over {event['seconds']} s")
    for event in row.get("cpu_dips") or []:
        parts.append(f"dip to {event['lowest_share_of_plateau']:.2f} for {event['seconds']} s")
    if "cpu_per_request_drift" in row:
        drift = row["cpu_per_request_drift"]
        gateway = f"gateway +{drift['gateway_percent']}%, " if "gateway_percent" in drift else ""
        parts.append(f"CPU/request {gateway}backend +{drift['backend_percent']}% "
                     f"in pair {drift['high_pair']} over pair {drift['low_pair']}")
    named = ", ".join(f"{process['comm']} {process['cpu_seconds']}"
                      for process in (row.get("host_processes") or [])[:3])
    if named:
        parts.append(f"busiest outside the benchmark: {named}")
    return "; ".join(parts)


def print_report(report, stream=sys.stdout):
    summary = report["summary"]
    write = lambda text: print(f"[flags] {text}", file=stream)  # noqa: E731
    write(f"runner CPU: {report.get('runner_cpu_model') or 'not recorded'}")
    if not report["host_cpu_recorded"]:
        write("host CPU was not recorded in this run: a CPU dip is the only evidence of a disturbance")
    write(f"{summary['flagged']} of {summary['samples']} samples flagged"
          + (f"; {summary['comparisons_flagged']} of {summary['comparisons']} comparisons touched"
             if "comparisons" in summary else ""))
    if summary["not_analysed"]:
        write(f"{summary['not_analysed']} samples could not be analysed: no sampler series")
    periodic = report.get("periodic_activity")
    if periodic:
        write(f"host activity every {int(periodic['period_seconds'])} s: {periodic['events']} events "
              f"over {periodic['seconds_spanned']} s")
    for row in report["samples"]:
        if row["flags"]:
            write(f"pair {row['pair']} {row['gateway']:<16} {row['payload_size']:>8}  "
                  f"{' '.join(row['flags'])}  ({describe(row)})")


def runner_cpu(cpuinfo="/proc/cpuinfo"):
    """(model name, logical CPU count) of this host; (None, count) when unknown."""
    model = None
    try:
        with open(cpuinfo) as handle:
            for line in handle:
                if line.lower().startswith("model name") and ":" in line:
                    model = line.split(":", 1)[1].strip() or None
                    break
    except OSError:
        pass
    return model, os.cpu_count()


def record_host(manifest_path, cpuinfo="/proc/cpuinfo"):
    """Add the runner's CPU model to manifest.json, keeping everything in it."""
    manifest = load(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError("manifest.json is missing or not an object")
    model, count = runner_cpu(cpuinfo)
    manifest.update(runner_cpu_model=model, runner_cpu_count=count)
    write_json(manifest_path, manifest)
    return model


def run_shape(directory, gateways, sizes, pairs):
    """Arms, payloads and pair count: as given, else from the run's manifest."""
    manifest = load(Path(directory) / "manifest.json")
    manifest = manifest if isinstance(manifest, dict) else {}
    gateways = gateways.split() if gateways else manifest.get("gateways")
    sizes = [int(size) for size in sizes.split()] if sizes else manifest.get("payload_sizes")
    pairs = int(pairs) if pairs else manifest.get("pairs")
    if not gateways or not sizes or not isinstance(pairs, int) or pairs < 1:
        raise ValueError("arms, payload sizes and pairs are neither given nor in manifest.json")
    return list(gateways), [int(size) for size in sizes], pairs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    host = commands.add_parser("record-host", help="add the runner's CPU model to manifest.json")
    host.add_argument("manifest")
    for name, text in (("annotate", "flag a run's samples and comparisons in place"),
                       ("report", "print what would be flagged; write nothing")):
        command = commands.add_parser(name, help=text)
        command.add_argument("directory")
        command.add_argument("protocol")
        command.add_argument("--gateways", help="space-separated arms (default: manifest.json)")
        command.add_argument("--payload-sizes", help="space-separated bytes (default: manifest.json)")
        command.add_argument("--pairs", help="pair count (default: manifest.json)")
    args = parser.parse_args(argv)
    if args.command == "record-host":
        print(f"[flags] recorded the runner's CPU model: {record_host(args.manifest) or 'unknown'}")
        return 0
    gateways, sizes, pairs = run_shape(args.directory, args.gateways, args.payload_sizes, args.pairs)
    if args.command == "annotate":
        report = annotate(args.directory, args.protocol, gateways, sizes, pairs)
    else:
        report = analyse_run(args.directory, args.protocol, gateways, sizes, pairs)
    print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
