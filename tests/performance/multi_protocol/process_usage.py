"""Linux /proc sampler for the hosted shared-runner benchmark.

CPU is a per-PID delta, never host utilization. Raw time series retain phase
boundaries; setup/warmup/drain costs remain visible beside measurement costs.
"""

import argparse
import json
import math
import os
import signal
import time
from pathlib import Path

from transport_diagnostics import snapshot as transport_snapshot, thread_snapshot


def parse_stat(contents, ticks, page_size):
    # comm can contain spaces and parentheses; fields follow its LAST ')'.
    fields = contents[contents.rfind(")") + 2:].split()
    return {"start_ticks": int(fields[19]),
            "cpu_seconds": (int(fields[11]) + int(fields[12])) / ticks,
            "user_cpu_seconds": int(fields[11]) / ticks,
            "system_cpu_seconds": int(fields[12]) / ticks,
            "rss_bytes": int(fields[21]) * page_size}


IO_FIELDS = ("rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes",
             "cancelled_write_bytes")
SWITCH_FIELDS = ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")
CPU_FIELDS = ("user_cpu_seconds", "system_cpu_seconds")


def parse_context_switches(contents):
    fields = dict(line.split(":", 1) for line in contents.splitlines() if ":" in line)
    result = {key: int(fields[key].strip()) for key in SWITCH_FIELDS}
    if any(value < 0 for value in result.values()):
        raise ValueError("negative context-switch counter")
    return result


def capture_scheduler(pid, ticks, page_size, proc_root=Path("/proc")):
    # /proc/PID/status covers only the leader. Include every live worker and
    # retain thread generations; a changing set cannot support a complete delta.
    task = proc_root / str(pid) / "task"
    threads = sorted(path for path in task.iterdir() if path.name.isdecimal())
    if len(threads) > 512:
        raise ValueError("scheduler thread inventory exceeds 512 threads")
    result = {}
    for thread in threads:
        before = parse_stat((thread / "stat").read_text(), ticks, page_size)
        counters = parse_context_switches((thread / "status").read_text())
        after = parse_stat((thread / "stat").read_text(), ticks, page_size)
        if before["start_ticks"] != after["start_ticks"]:
            raise ValueError("thread generation changed during scheduler capture")
        result[thread.name] = dict(start_ticks=before["start_ticks"], **counters)
    if not result or {path.name for path in task.iterdir() if path.name.isdecimal()} != set(result):
        raise ValueError("thread set changed during scheduler capture")
    return result


def scheduler_delta(bracket):
    snapshots = [item.get("scheduler_threads") for item in bracket]
    if not all(isinstance(item, dict) and item for item in snapshots):
        raise ValueError("scheduler counters unavailable at one or more samples")
    first, last = snapshots[0], snapshots[-1]
    for snapshot in snapshots:
        if set(snapshot) != set(first) or any(
                snapshot[tid]["start_ticks"] != first[tid]["start_ticks"] for tid in first):
            raise ValueError("thread set or generation changed within measurement bracket")
    if any(b[tid][key] < a[tid][key] for a, b in zip(snapshots, snapshots[1:])
           for tid in first for key in SWITCH_FIELDS):
        raise ValueError("context-switch counter decreased")
    return {key: sum(last[tid][key] - first[tid][key] for tid in first)
            for key in SWITCH_FIELDS}


def parse_io(contents):
    values = dict(line.split(":", 1) for line in contents.splitlines())
    result = {key: int(values[key].strip()) for key in IO_FIELDS}
    if any(value < 0 for value in result.values()):
        raise ValueError("negative process I/O counter")
    return result


def capture(pid, ticks, page_size, *, scheduler=False):
    try:
        state = parse_stat(Path(f"/proc/{pid}/stat").read_text(), ticks, page_size)
    except (OSError, ValueError, IndexError):
        return None
    try:
        state["io"] = parse_io(Path(f"/proc/{pid}/io").read_text())
    except (OSError, ValueError, KeyError) as error:
        # /proc/io has stricter access rules than stat. Never invent zero I/O
        # when ptrace permissions deny a container PID owned by another UID.
        state["io_error"] = str(error)
    if scheduler:
        try:
            state["scheduler_threads"] = capture_scheduler(pid, ticks, page_size)
            after = parse_stat(Path(f"/proc/{pid}/stat").read_text(), ticks, page_size)
            if after["start_ticks"] != state["start_ticks"]:
                raise ValueError("process generation changed during scheduler capture")
        except (OSError, ValueError, KeyError, IndexError) as error:
            state.pop("scheduler_threads", None)
            state["scheduler_error"] = str(error)
    return state


def measurement_usage(usage, phases):
    """Bracket the common measured interval; expose sampling uncertainty."""
    start = phases.get("measurement_start_unix_secs")
    duration = phases.get("measurement_secs")
    if not isinstance(start, (int, float)) or not isinstance(duration, (int, float)):
        return []
    end = start + duration
    by_process = {}
    for snapshot in usage.get("timeline", []):
        for process in snapshot["processes"]:
            if process["role"] == "client":
                continue  # the client's own boundary snapshots are authoritative
            key = (process["pid"], process["start_ticks"])
            by_process.setdefault(key, []).append((snapshot["unix_secs"], process))
    result = []
    for values in by_process.values():
        before = [item for item in values if item[0] <= start]
        after = [item for item in values if item[0] >= end]
        within = [item for item in values if start <= item[0] <= end]
        identity = values[0][1]
        record = dict(pid=identity["pid"], role=identity["role"],
                      complete_bracket=bool(before and after),
                      peak_rss_bytes=max((item[1]["rss_bytes"] for item in within), default=None))
        if before and after:
            left, right = before[-1], after[0]
            # Endpoints alone must not hide a vanished/reused process mid-window.
            record["complete_bracket"] = all(any(
                p["pid"] == identity["pid"] and p["start_ticks"] == identity["start_ticks"]
                for p in snapshot["processes"])
                for snapshot in usage.get("timeline", [])
                if left[0] <= snapshot["unix_secs"] <= right[0])
            record.update(cpu_seconds=right[1]["cpu_seconds"] - left[1]["cpu_seconds"],
                          bracket_secs=right[0] - left[0],
                          boundary_slack_secs=(start - left[0]) + (right[0] - end))
            bracket = [item[1] for item in values if left[0] <= item[0] <= right[0]]
            if all(all(key in item for key in CPU_FIELDS) for item in bracket):
                if record["complete_bracket"] and all(
                        b[key] >= a[key] for a, b in zip(bracket, bracket[1:]) for key in CPU_FIELDS):
                    record.update({key: right[1][key] - left[1][key] for key in CPU_FIELDS})
                else:
                    record["cpu_split_error"] = "counter decreased or process bracket incomplete"
            if any("scheduler_threads" in item or "scheduler_error" in item for item in bracket):
                try:
                    if not record["complete_bracket"]:
                        raise ValueError("process bracket incomplete")
                    record["context_switches"] = dict(scope="all process threads", **scheduler_delta(bracket))
                except ValueError as error:
                    record["scheduler_error"] = str(error)
            if all(isinstance(item.get("io"), dict) for item in bracket):
                monotonic = all(b["io"][key] >= a["io"][key]
                                for a, b in zip(bracket, bracket[1:]) for key in IO_FIELDS)
                if monotonic and record["complete_bracket"]:
                    record["io"] = {key: right[1]["io"][key] - left[1]["io"][key]
                                    for key in IO_FIELDS}
                else:
                    record["io_error"] = "counter decreased or process bracket incomplete"
            else:
                record["io_error"] = "I/O unavailable at one or more bracket samples"
        result.append(record)
    client = phases.get("client_usage")
    if isinstance(client, dict):
        result.append(dict(client))
    return result


def client_pids(parent, proc_root=Path("/proc")):
    """Find only the runner's direct client or the client below GNU timeout."""
    result = []
    pending = [parent]
    while pending:
        pid = pending.pop()
        try:
            children = (proc_root / str(pid) / "task" / str(pid) / "children").read_text()
        except OSError:
            continue
        for child in children.split():
            if not child.isdecimal():
                continue
            try:
                argv0 = (proc_root / child / "cmdline").read_bytes().split(b"\0", 1)[0]
            except OSError:
                continue
            name = argv0.rsplit(b"/", 1)[-1]
            if name == b"proto_bench":
                result.append(int(child))
            elif pid == parent and name in (b"timeout", b"gtimeout"):
                pending.append(int(child))
    return result


def sample_processes(backend, gateway_pids, output, interval, parent_pid=None, stop_file=None,
                     *, http3=False, envoy=False, h2_gauges=False, h1_profile=False,
                     pool_profile=False, udp_profile=False, scheduler_counters=False,
                     h1_runtime=None, h1_container_id=None):
    """Observe processes until signalled; never launch or control the client."""
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("sampling interval must be positive and finite")
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    # Background jobs inherit ignored SIGINT from Bash. Override it explicitly
    # before publishing readiness so the runner can always stop and reap us.
    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    parent = os.getppid() if parent_pid is None else parent_pid
    ticks = os.sysconf("SC_CLK_TCK")
    page_size = os.sysconf("SC_PAGE_SIZE")
    roles = {pid: "gateway" for pid in gateway_pids}
    roles[backend] = "backend"
    records = {}
    timeline = []
    owned_gateway = None
    identity_error = None
    if h1_profile:
        from h1_internal_profile import gateway_identity
        try:
            runtime = json.loads(Path(h1_runtime).read_text())
            owned_gateway = gateway_identity(runtime)
            if runtime.get("identity_error") or owned_gateway["container_id"] != h1_container_id:
                raise ValueError("runtime does not identify the runner-owned container")
        except (OSError, ValueError, TypeError):
            owned_gateway = None
            identity_error = "owned gateway runtime unavailable or mismatched"
    started = time.monotonic()
    sampler_cpu_start = time.process_time() if pool_profile else None

    def write_pool_capture(document):
        # Atomic replacement retains the previous checkpoint on interruption.
        partial = Path(str(output) + ".partial")
        partial.write_text(json.dumps(document) + "\n")
        partial.replace(output)

    def sample():
        for pid in client_pids(parent):
            roles[pid] = "client"
        before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        unix_ns = time.time_ns()
        after = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        snapshot = {"unix_secs": unix_ns / 1e9, "processes": [],
                    "clock": {"before_ns": before, "unix_ns": unix_ns, "after_ns": after},
                    "clock_domain": "CLOCK_MONOTONIC", "sampler_pid": os.getpid(),
                    "time_namespace": Path("/proc/self/ns/time").stat().st_ino}
        for pid, role in roles.items():
            state = (capture(pid, ticks, page_size, scheduler=True) if scheduler_counters
                     else capture(pid, ticks, page_size))
            if state is None:
                continue
            key = (pid, state["start_ticks"])
            record = records.setdefault(key, dict(pid=pid, role=role, samples=0,
                                                 first_cpu_seconds=state["cpu_seconds"],
                                                 cpu_seconds=0, peak_rss_bytes=0))
            record["samples"] += 1
            record["cpu_seconds"] = state["cpu_seconds"] - record["first_cpu_seconds"]
            record["peak_rss_bytes"] = max(record["peak_rss_bytes"], state["rss_bytes"])
            snapshot["processes"].append(dict(state, pid=pid, role=role))
        if http3:
            snapshot["threads"] = [dict(thread, role=role)
                                   for pid, role in roles.items() if role != "client"
                                   for thread in thread_snapshot(pid, ticks, parse_stat)]
            snapshot["transport"] = transport_snapshot(envoy)
        if h2_gauges:
            from h2_diagnostics import snapshot as h2_snapshot
            snapshot["h2_gauges"] = h2_snapshot()
        if h1_profile:
            from h1_internal_profile import snapshot as h1_snapshot
            snapshot["h1_profile"] = h1_snapshot(len(timeline), snapshot["processes"], owned_gateway)
            if identity_error:
                snapshot["h1_profile"]["identity_error"] = identity_error
        if pool_profile:
            from pool_internal_profile import snapshot as pool_snapshot
            snapshot["pool_profile"] = pool_snapshot(len(timeline))
        if udp_profile:
            from udp_internal_profile import snapshot as udp_snapshot
            snapshot["udp_profile"] = udp_snapshot(len(timeline), snapshot["processes"])
            # Retain each raw scrape even if the sampler later exits abnormally.
            with Path(str(output) + ".udp-profile.jsonl").open("a") as raw:
                raw.write(json.dumps(snapshot) + "\n")
        timeline.append(snapshot)
        if pool_profile:
            # Persist partial observations before the next interval. A killed
            # sampler remains incomplete but does not erase earlier failures.
            write_pool_capture(dict(capture_complete=False, timeline=timeline,
                                    sampler_lifetime_cpu_secs=time.process_time() - sampler_cpu_start))

    try:
        sample()
        if not pool_profile:
            Path(output).write_text(json.dumps({"capture_complete": False}) + "\n")
        while not stopping:
            if stop_file is not None and Path(stop_file).exists():
                stopping = True
                break
            if (parent_pid is None and os.getppid() != parent) or (
                    parent_pid is not None and not Path(f"/proc/{parent}").exists()):
                break
            sample()
            time.sleep(interval)
        sample()
        clients = [record for record in records.values() if record["role"] == "client"]
        report = {
            "scope": "sampler lifetime bracketing client setup, warmup, measurement and drain",
            "interval_ms": interval * 1000,
            "elapsed_secs": time.monotonic() - started,
            "capture_complete": stopping,
            "processes": list(records.values()),
            "missing_pids": sorted(set(roles) - {key[0] for key in records}),
            "client_accounting": "sampled /proc deltas; process endpoints may be missed",
            "client_cpu_seconds": sum(record["cpu_seconds"] for record in clients) if clients else None,
            "client_peak_rss_bytes": max((record["peak_rss_bytes"] for record in clients), default=None),
            "timeline": timeline,
        }
        if h1_profile:
            report["h1_gateway"] = owned_gateway
        if pool_profile:
            report["sampler_lifetime_cpu_secs"] = time.process_time() - sampler_cpu_start
            write_pool_capture(report)
        else:
            Path(output).write_text(json.dumps(report) + "\n")
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", type=int, required=True)
    parser.add_argument("--gateway-pids", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--http3", action="store_true")
    parser.add_argument("--envoy", action="store_true")
    parser.add_argument("--h2-gauges", action="store_true")
    parser.add_argument("--h1-profile", action="store_true")
    parser.add_argument("--pool-profile", action="store_true")
    parser.add_argument("--udp-profile", action="store_true")
    parser.add_argument("--scheduler-counters", action="store_true")
    parser.add_argument("--h1-runtime")
    parser.add_argument("--h1-container-id")
    parser.add_argument("--parent-pid", type=int)
    parser.add_argument("--stop-file")
    args = parser.parse_args()
    sample_processes(args.backend, [int(pid) for pid in args.gateway_pids.split()],
                     args.output, args.interval, parent_pid=args.parent_pid,
                     stop_file=args.stop_file, http3=args.http3, envoy=args.envoy,
                     h2_gauges=args.h2_gauges, h1_profile=args.h1_profile,
                     h1_runtime=args.h1_runtime, h1_container_id=args.h1_container_id,
                     pool_profile=args.pool_profile, udp_profile=args.udp_profile,
                     scheduler_counters=args.scheduler_counters)
