#!/usr/bin/env python3
"""Bracket host /proc counters with the load generator's measurement markers.

No Docker stats subprocess runs in the measurement interval. RSS sampling is
100 ms; CPU and host steal are deltas at marker receipt, so include pipe and
scheduler delivery jitter. Warmup and post-deadline response drains are excluded.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

START = "MESH_BENCH_MEASUREMENT_START"
END = "MESH_BENCH_MEASUREMENT_END"


def process_snapshot(pid: int, proc: Path = Path("/proc")) -> dict:
    # comm may itself contain spaces and parentheses; fields follow its last ).
    fields = (proc / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "starttime": int(fields[19]),
            "cpu_ticks": int(fields[11]) + int(fields[12]),
            "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE")}


def host_snapshot(proc: Path = Path("/proc")) -> dict:
    values = [int(x) for x in (proc / "stat").read_text().splitlines()[0].split()[1:]]
    # guest and guest_nice already occur in user and nice.
    return {"total_ticks": sum(values[:8]), "steal_ticks": values[7]}


def run(args: argparse.Namespace) -> int:
    containers = []
    for name in args.container:
        inspected = json.loads(subprocess.check_output(["docker", "inspect", name]))[0]
        containers.append({"name": name, "pid": inspected["State"]["Pid"],
                           "image_id": inspected["Image"],
                           "cpu_limit_nanos": inspected["HostConfig"]["NanoCpus"],
                           "memory_limit_bytes": inspected["HostConfig"]["Memory"]})
    report = {"schema_version": 1, "containers": containers,
              "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
              "rss_interval_seconds": 0.1,
              "interval": "loadgen common epoch, host receipt of stderr phase markers",
              "valid": False, "errors": []}
    begin = None
    finish = None
    samples: list[int] = []
    stop = threading.Event()

    def snapshot() -> dict:
        return {"monotonic": time.monotonic(), "host": host_snapshot(),
                "processes": [process_snapshot(c["pid"]) for c in containers]}

    def sample() -> None:
        while not stop.wait(0.1):
            try:
                samples.append(sum(process_snapshot(c["pid"])["rss_bytes"] for c in containers))
            except (OSError, ValueError, IndexError) as exc:
                report["errors"].append(str(exc))
                return

    sampler = None
    with args.output.open("w") as output:
        child = subprocess.Popen(["docker", "run", "--rm", "--network", "host", args.image,
            "--target", args.target, "--host-header", args.host_header, "--mesh", args.mesh,
            "--duration", args.duration, "--concurrency", args.concurrency,
            "--warmup", args.warmup, "--payload-size", args.payload_size, "--json"],
            stdout=output, stderr=subprocess.PIPE, text=True)
        assert child.stderr is not None
        for line in child.stderr:
            sys.stderr.write(line)
            marker = line.strip()
            try:
                if marker == START and begin is None:
                    begin = snapshot()
                    sampler = threading.Thread(target=sample, daemon=True)
                    sampler.start()
                elif marker == END and begin is not None and finish is None:
                    finish = snapshot()
                    stop.set()
            except (OSError, ValueError, IndexError) as exc:
                report["errors"].append(str(exc))
        status = child.wait()
    stop.set()
    if sampler is not None:
        sampler.join(timeout=2)
    if begin is None or finish is None:
        report["errors"].append("missing measurement phase marker")
    else:
        report["begin"] = begin
        report["end"] = finish
        elapsed = finish["monotonic"] - begin["monotonic"]
        ticks = 0
        for before, after in zip(begin["processes"], finish["processes"]):
            if before["starttime"] != after["starttime"]:
                report["errors"].append("proxy PID changed during measurement")
            ticks += after["cpu_ticks"] - before["cpu_ticks"]
        total = finish["host"]["total_ticks"] - begin["host"]["total_ticks"]
        steal = finish["host"]["steal_ticks"] - begin["host"]["steal_ticks"]
        report.update({"elapsed_seconds": elapsed,
                       "proxy_cpu_seconds": ticks / report["clock_ticks_per_second"],
                       "host_cpu_steal_percent": 100 * steal / total if total > 0 else None,
                       "proxy_rss_bytes_peak": max(samples, default=0),
                       "rss_samples": len(samples)})
        if elapsed <= 0 or total <= 0 or steal < 0 or ticks < 0:
            report["errors"].append("invalid counter interval")
        report["valid"] = not report["errors"]
    args.resources.write_text(json.dumps(report, indent=2) + "\n")
    return status if status else (0 if report["valid"] else 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    for name in ("image", "target", "host-header", "mesh", "duration", "concurrency", "warmup", "payload-size"):
        parser.add_argument("--" + name, required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
