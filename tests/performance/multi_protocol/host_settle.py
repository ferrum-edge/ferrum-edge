#!/usr/bin/env python3
"""Hold a benchmark arm's first start until the host has finished reacting to it.

On GitHub-hosted runners the provisioner's job daemon (`/tmp/provjobd<digits>`)
uses about one core for four to five seconds the first time a new binary or
container image runs in a job, starting 2 to 12 seconds after that start. On a
4-vCPU runner that is already saturated by gateway, backend and client, the
cell measured in that window loses 20-25% of its CPU. It hit whichever arm ran
an image first, so always the same arms in pair 1.

The runner therefore starts every distinct binary/image once before the first
measured pair, drives a discarded load for as long as the reaction took to run
its course in measured cells, and calls this helper to wait, with the arm idle,
until the host is quiet. The helper only reads `/proc`; it starts and stops nothing.

Times are counted from `--since`: the moment the arm was up, taken by the
runner after the start returned, so an image pull or a slow start cannot use
up the minimum hold. `wait` samples from the moment it is called, after the
discarded load. The reaction usually falls inside that load, where the
benchmark's own processes keep the host busy, so `snapshot` records every
process's CPU before the arm starts and `wait --baseline` reports what the
processes that were already running then used across the start, the load and
the hold. The arm's own processes are born later and are left out.

`wait` appends one record per arm to a JSON file so a run shows what the
first start cost: how long the hold waited, how much CPU the host used during
it, when a burst inside the hold began and ended relative to `--since`, and
which processes used CPU, both during the hold and since before the start. An
arm whose record shows no reaction may still be owed one in its first measured
cell. A burst that ends close to the release time means the minimum hold is too
short for that host.
"""

import argparse
import json
import math
import os
import sys
import time

SCHEMA = 1
# Counted as "busy": time some task on this host was executing. Idle, iowait
# and steal are not work done by a process here.
BUSY_FIELDS = ("user", "nice", "system", "irq", "softirq")
STAT_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")


def clock_ticks():
    try:
        return os.sysconf("SC_CLK_TCK")
    except (AttributeError, ValueError, OSError):
        return 100


def read_text(path):
    try:
        with open(path, "rb") as handle:
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return ""


def parse_cpu_line(text):
    """Aggregate CPU ticks by state from /proc/stat, or None when unavailable."""
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] == "cpu":
            try:
                values = [int(value) for value in parts[1 : 1 + len(STAT_FIELDS)]]
            except ValueError:
                return None
            if len(values) < len(STAT_FIELDS):
                return None
            return dict(zip(STAT_FIELDS, values))
    return None


def busy_ticks(cpu):
    return sum(cpu[field] for field in BUSY_FIELDS)


def parse_process_stat(raw):
    """(comm, cpu ticks, start ticks) from one /proc/<pid>/stat, or None."""
    close = raw.rfind(")")
    open_ = raw.find("(")
    if open_ < 0 or close < open_:
        return None
    fields = raw[close + 2 :].split()
    try:
        return raw[open_ + 1 : close], int(fields[11]) + int(fields[12]), int(fields[19])
    except (IndexError, ValueError):
        return None


def read_processes(proc_root):
    table = {}
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return table
    for entry in entries:
        if not entry.isdigit():
            continue
        parsed = parse_process_stat(read_text(os.path.join(proc_root, entry, "stat")))
        if parsed:
            comm, ticks, started = parsed
            table[(int(entry), started)] = (comm, ticks)
    return table


class Settle:
    """Decides when a first start has settled. Pure: fed samples, holds no clock.

    Release needs both conditions: at least `min_hold` seconds since the start
    (the host's reaction begins up to ~12 s after it, so an early quiet spell
    proves nothing), and `quiet_seconds` of consecutive samples under
    `quiet_cores`. `max_wait` bounds the hold on a host that is never quiet.
    """

    def __init__(self, min_hold, quiet_seconds, max_wait, quiet_cores, burst_cores):
        self.min_hold = min_hold
        self.quiet_seconds = quiet_seconds
        self.max_wait = max_wait
        self.quiet_cores = quiet_cores
        self.burst_cores = burst_cores
        self.quiet_run = 0.0
        self.burst_seconds = 0.0
        self.busy_cpu_seconds = 0.0
        self.peak_busy_cores = 0.0
        self.samples = 0

    def observe(self, interval, busy_cores):
        self.samples += 1
        self.busy_cpu_seconds += busy_cores * interval
        self.peak_busy_cores = max(self.peak_busy_cores, busy_cores)
        if busy_cores >= self.burst_cores:
            self.burst_seconds += interval
        if busy_cores < self.quiet_cores:
            self.quiet_run += interval
        else:
            self.quiet_run = 0.0

    def verdict(self, since_start):
        """`quiet`, `max_wait`, or None while the hold must continue."""
        if since_start >= self.min_hold and self.quiet_run >= self.quiet_seconds:
            return "quiet"
        if since_start >= self.max_wait:
            return "max_wait"
        return None


def write_json(path, document):
    temporary = f"{path}.tmp"
    with open(temporary, "w") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)


def snapshot(args, now=time.time):
    """Record every process's CPU so far, for `wait --baseline`."""
    table = read_processes(args.proc_root)
    write_json(
        args.output,
        {
            "schema": SCHEMA,
            "unix": now(),
            "processes": {f"{pid}:{started}": [comm, ticks] for (pid, started), (comm, ticks) in table.items()},
        },
    )
    return len(table)


def used_since_baseline(path, processes):
    """(seconds field source, ticks by comm) for processes already in the baseline.

    A process is matched by pid and start time, so a pid reused by the arm is
    not mistaken for a host process. None when the baseline cannot be read.
    """
    try:
        with open(path) as handle:
            baseline = json.load(handle)
        before = baseline["processes"]
        taken = float(baseline["unix"])
        if not isinstance(before, dict) or not math.isfinite(taken):
            raise ValueError("unexpected baseline")
    except (OSError, ValueError, KeyError, TypeError):
        return None
    used = {}
    for (pid, started), (comm, total) in processes.items():
        earlier = before.get(f"{pid}:{started}")
        # A baseline this helper did not write must not cost the hold its
        # record: an entry that is not [comm, integer ticks] is skipped.
        if not isinstance(earlier, list) or len(earlier) != 2 or type(earlier[1]) is not int:
            continue
        delta = total - earlier[1]
        if delta > 0:
            used[comm] = used.get(comm, 0) + delta
    return taken, used


def append_record(path, settings, record):
    try:
        with open(path) as handle:
            document = json.load(handle)
        if not isinstance(document, dict) or not isinstance(document.get("arms"), list):
            raise ValueError("unexpected settle record")
    except (OSError, ValueError):
        document = {"schema": SCHEMA, "arms": []}
    document.update(settings)
    document["arms"].append(record)
    write_json(path, document)


def wait(args, sleep=time.sleep, now=time.time):
    settings = {
        "schema": SCHEMA,
        "min_hold_seconds": args.min_hold,
        "quiet_seconds": args.quiet_seconds,
        "max_wait_seconds": args.max_wait,
        "quiet_cores": args.quiet_cores,
        "burst_cores": args.burst_cores,
    }
    record = {"arm": args.arm, "image": args.image, "since_unix": args.since}
    stat_path = os.path.join(args.proc_root, "stat")
    cpu = parse_cpu_line(read_text(stat_path))
    if cpu is None:
        # No /proc (macOS, BSD): nothing to observe and no evidence of the
        # effect there, so do not hold the run.
        record.update(available=False, reason="unavailable", waited_seconds=0.0)
        append_record(args.output, settings, record)
        return record
    ticks = clock_ticks()
    settle = Settle(args.min_hold, args.quiet_seconds, args.max_wait, args.quiet_cores, args.burst_cores)
    processes = read_processes(args.proc_root)
    used = {}
    first_burst = last_burst = None
    started_waiting = previous_time = now()
    verdict = settle.verdict(previous_time - args.since)
    while verdict is None:
        sleep(args.interval)
        current_time = now()
        current_cpu = parse_cpu_line(read_text(stat_path))
        if current_cpu is None:
            verdict = "unavailable"
            break
        elapsed = max(current_time - previous_time, 1e-6)
        busy_cores = (busy_ticks(current_cpu) - busy_ticks(cpu)) / ticks / elapsed
        settle.observe(elapsed, busy_cores)
        if busy_cores >= args.burst_cores:
            if first_burst is None:
                first_burst = previous_time - args.since
            last_burst = current_time - args.since
        current_processes = read_processes(args.proc_root)
        for key, (comm, total) in current_processes.items():
            before = processes.get(key)
            delta = total - (before[1] if before else 0)
            if delta > 0:
                used[comm] = used.get(comm, 0) + delta
        cpu, processes, previous_time = current_cpu, current_processes, current_time
        verdict = settle.verdict(current_time - args.since)
    top = sorted(used.items(), key=lambda item: -item[1])[: args.top]
    record.update(
        # False when /proc/stat stopped being readable part-way: the figures
        # below then cover only the samples taken before that.
        available=verdict != "unavailable",
        reason=verdict,
        waited_seconds=round(previous_time - started_waiting, 3),
        held_since_start_seconds=round(previous_time - args.since, 3),
        samples=settle.samples,
        busy_cpu_seconds=round(settle.busy_cpu_seconds, 3),
        peak_busy_cores=round(settle.peak_busy_cores, 3),
        burst_seconds=round(settle.burst_seconds, 3),
        # Seconds since the arm's start at which the first busy sample began
        # and the last one ended; null when no sample reached `burst_cores`.
        first_burst_since_start_seconds=None if first_burst is None else round(first_burst, 3),
        last_burst_since_start_seconds=None if last_burst is None else round(last_burst, 3),
        top_processes=[{"comm": comm, "cpu_seconds": round(value / ticks, 3)} for comm, value in top],
    )
    since_baseline = used_since_baseline(args.baseline, processes) if args.baseline else None
    if since_baseline is not None:
        taken, host_used = since_baseline
        host_top = sorted(host_used.items(), key=lambda item: -item[1])[: args.top]
        record.update(
            # From before the arm started to the release: the start, the
            # discarded load and the hold. Only processes already running at
            # the baseline, so the arm's own processes are not in it.
            seconds_since_before_start=round(previous_time - taken, 3),
            host_processes_since_before_start=[
                {"comm": comm, "cpu_seconds": round(value / ticks, 3)} for comm, value in host_top
            ],
        )
    append_record(args.output, settings, record)
    return record


def note(args):
    """Record an arm that needed no hold, so the file accounts for every arm."""
    record = {"arm": args.arm, "image": args.image, "reason": args.reason, "waited_seconds": 0.0}
    append_record(args.output, {"schema": SCHEMA}, record)
    return record


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    noter = commands.add_parser("note", help="record an arm that was not held")
    noter.add_argument("--arm", required=True)
    noter.add_argument("--image", required=True)
    noter.add_argument("--reason", required=True, choices=["already_started"])
    noter.add_argument("--output", required=True)
    shooter = commands.add_parser("snapshot", help="record per-process CPU before an arm starts")
    shooter.add_argument("--output", required=True)
    shooter.add_argument("--proc-root", default="/proc")
    waiter = commands.add_parser("wait", help="hold until the host is quiet, then record what was seen")
    waiter.add_argument("--arm", required=True)
    waiter.add_argument("--image", required=True)
    waiter.add_argument("--since", type=float, required=True, help="unix time at which the arm was up")
    waiter.add_argument("--output", required=True)
    waiter.add_argument("--min-hold", type=float, default=25.0)
    waiter.add_argument("--quiet-seconds", type=float, default=3.0)
    waiter.add_argument("--max-wait", type=float, default=60.0)
    waiter.add_argument("--quiet-cores", type=float, default=0.2)
    waiter.add_argument("--burst-cores", type=float, default=0.4)
    waiter.add_argument("--interval", type=float, default=0.5)
    waiter.add_argument("--top", type=int, default=3)
    waiter.add_argument("--baseline", help="snapshot taken before the arm started")
    waiter.add_argument("--proc-root", default="/proc")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == "note":
        note(args)
        return 0
    if args.command == "snapshot":
        snapshot(args)
        return 0
    for name in ("min_hold", "quiet_seconds", "quiet_cores", "burst_cores"):
        if getattr(args, name) < 0:
            raise SystemExit(f"--{name.replace('_', '-')} must not be negative")
    if args.interval <= 0 or args.max_wait <= 0:
        raise SystemExit("--interval and --max-wait must be positive")
    record = wait(args)
    since_before = ", ".join(
        f"{p['comm']} {p['cpu_seconds']}s" for p in record.get("host_processes_since_before_start", [])
    )
    print(
        f"[settle] {record['arm']}: {record['reason']} after {record.get('held_since_start_seconds', 0)}s"
        f" (host CPU used during the hold {record.get('busy_cpu_seconds', 0)}s,"
        f" busiest: {', '.join(p['comm'] for p in record.get('top_processes', [])) or 'n/a'};"
        f" host processes since before the start: {since_before or 'n/a'})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
