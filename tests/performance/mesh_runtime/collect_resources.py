#!/usr/bin/env python3
"""Bracket host /proc counters with the load generator's measurement markers.

No Docker stats subprocess runs in the measurement interval. RSS sampling is
100 ms; CPU and host steal are deltas at marker receipt, so include pipe and
scheduler delivery jitter. Warmup and post-deadline response drains are excluded.
"""
from __future__ import annotations

import argparse
import atexit
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

START = "MESH_BENCH_MEASUREMENT_START"
END = "MESH_BENCH_MEASUREMENT_END"


def allocation_snapshot(urls: list[str]) -> list[dict]:
    # Reuse the existing observer-loss/schema/required-counter parser.
    path = Path(__file__).resolve().parents[1] / "multi_protocol" / "alloc_per_request.py"
    spec = importlib.util.spec_from_file_location("alloc_per_request", path)
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    counters = []
    for url in urls:
        with urllib.request.urlopen(url, timeout=2) as response:
            record = parser.parse_metrics(response.read().decode())
        if record["lost_events"] or record["missing_slots"] or record["schema"] != 1:
            raise ValueError("incomplete allocation observer")
        counters.append(record)
    return counters


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
        inspected = json.loads(subprocess.check_output(["docker", "inspect", name], timeout=5))[0]
        if not inspected["State"].get("Running"):
            raise ValueError(f"proxy {name} exited before measurement")
        containers.append({"name": name, "pid": inspected["State"]["Pid"],
                           "image_id": inspected["Image"],
                           "cpu_limit_nanos": inspected["HostConfig"]["NanoCpus"],
                           "memory_limit_bytes": inspected["HostConfig"]["Memory"]})
    report = {"schema_version": 1, "containers": containers,
              "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
              "rss_interval_seconds": 0.1,
              "interval": "loadgen common epoch, host receipt of stderr phase markers",
              "valid": False, "errors": []}
    if args.allocation_url:
        report["idle_alloc_begin"] = allocation_snapshot(args.allocation_url)
        time.sleep(1)
        report["idle_alloc_end"] = allocation_snapshot(args.allocation_url)
    observer = None
    observed = []
    auxiliary = []
    observations = []
    detail_begin = detail_end = None
    if args.production_observe:
        import production_observer as observer
        observed = [observer.inspect_container(c["name"]) for c in containers]
        auxiliary = [observer.inspect_container(name) for name in args.aux_container]
        report["production"] = {"proxy_containers": observed, "auxiliary_containers": auxiliary,
            "limits": "shared runner; CPU limits are recorded per container; thread scheduling is not Tokio task wakes; sampled sockets can miss churn",
            "metric_scope": "before loadgen launch through completed drain (includes warmup)",
            "socket_interval_seconds": 1.0}
        observer.metrics(args.mesh, observed, args.resources.parent, "before")
    perf_capture = None
    if args.perf_leaf:
        if args.mesh not in ("ferrum", "envoy") or len(containers) != 2:
            raise ValueError("leaf profiling requires two Ferrum or Envoy sidecars")
        from production_perf import PerfCapture
        symbols = [{"path": path, "qualification_report": args.symbol_qualification_report}
                   if args.symbol_qualification_report else path for path in args.symbol_elf]
        perf_capture = PerfCapture(containers, args.resources.parent / "perf-leaf", symbols)
        # On ordinary exceptions stop attached recorders; PDEATHSIG also bounds
        # them if this collector is terminated by the outer cell deadline.
        atexit.register(perf_capture.stop)
        perf_capture.start()
    begin = None
    finish = None
    samples: list[int] = []
    stop = threading.Event()

    def snapshot() -> dict:
        return {"monotonic": time.monotonic(), "host": host_snapshot(),
                "processes": [process_snapshot(c["pid"]) for c in containers],
                "auxiliary": [process_snapshot(c["pid"]) for c in auxiliary],
                "allocation_counters": allocation_snapshot(args.allocation_url) if args.allocation_url else []}

    def sample() -> None:
        next_detail = time.monotonic() + 1.0
        while not stop.wait(0.1):
            try:
                samples.append(sum(process_snapshot(c["pid"])["rss_bytes"] for c in containers))
                if observer is not None and time.monotonic() >= next_detail:
                    observations.append(observer.snapshot(observed))
                    next_detail += 1.0
            except (OSError, ValueError, IndexError) as exc:
                report["errors"].append(str(exc))
                return

    sampler = None
    print(f"[measure] starting {args.mesh}: warmup={args.warmup}s duration={args.duration}s", file=sys.stderr, flush=True)
    with args.output.open("w") as output:
        network_args = ["--network", args.loadgen_network]
        if args.loadgen_user:
            network_args += ["--user", args.loadgen_user]
        child = subprocess.Popen(["docker", "run", "--rm", "--label", "ferrum.meshbench.owner=" + args.fixture_owner, *network_args, "--name", args.loadgen_name, args.image,
            "--target", args.target, "--host-header", args.host_header, "--mesh", args.mesh,
            "--duration", args.duration, "--concurrency", args.concurrency,
            "--warmup", args.warmup, "--payload-size", args.payload_size,
            "--exchange-timeout-secs", str(args.exchange_timeout_secs), "--rate", str(args.rate), "--resource-end-grace-ms", "250", "--json"],
            stdout=output, stderr=subprocess.PIPE, text=True, bufsize=1)
        if observer is not None:
            # Discover the child during warmup, before the CPU boundary. The
            # retry budget is bounded; a missing child invalidates observations.
            for attempt in range(20):
                try:
                    child_info = observer.inspect_container(args.loadgen_name)
                    auxiliary.append(child_info)
                    report["production"]["auxiliary_containers"] = auxiliary
                    break
                except (subprocess.CalledProcessError, ValueError):
                    time.sleep(0.05)
            else:
                report["errors"].append("loadgen PID unavailable during warmup")
        assert child.stderr is not None
        for line in child.stderr:
            sys.stderr.write(line)
            sys.stderr.flush()
            marker = line.strip()
            try:
                if marker == START and begin is None:
                    begin = snapshot()
                    if observer is not None:
                        detail_begin = observer.snapshot(observed)
                    sampler = threading.Thread(target=sample, daemon=True)
                    sampler.start()
                elif marker == END and begin is not None and finish is None:
                    finish = snapshot()
                    stop.set()
                    if observer is not None:
                        detail_end = observer.snapshot(observed)
            except (OSError, ValueError, IndexError) as exc:
                report["errors"].append(str(exc))
        status = child.wait()
    if perf_capture is not None:
        perf_capture.stop()
    print(f"[measure] {args.mesh} loadgen exited status={status}", file=sys.stderr, flush=True)
    stop.set()
    if sampler is not None:
        sampler.join(timeout=2)
    if observer is not None:
        observer.metrics(args.mesh, observed, args.resources.parent, "after")
        report["production"].update({"begin": detail_begin, "end": detail_end,
                                     "socket_samples": observations})
        if detail_begin is not None and detail_end is not None:
            report["production"]["scheduler_deltas"] = observer.scheduler_deltas(detail_begin, detail_end)
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
        auxiliary_cpu = []
        for index, (before, after) in enumerate(zip(begin["auxiliary"], finish["auxiliary"])):
            if before["starttime"] != after["starttime"]:
                report["errors"].append("auxiliary PID changed during measurement")
            auxiliary_cpu.append({"name": auxiliary[index]["name"],
                "cpu_seconds": (after["cpu_ticks"]-before["cpu_ticks"])/report["clock_ticks_per_second"],
                "rss_bytes_end": after["rss_bytes"]})
        deviation = elapsed - float(args.duration)
        report.update({"elapsed_seconds": elapsed,
                       "interval_deviation_seconds": deviation,
                       "auxiliary_cpu": auxiliary_cpu,
                       "proxy_cpu_seconds": ticks / report["clock_ticks_per_second"],
                       "host_cpu_steal_percent": 100 * steal / total if total > 0 else None,
                       "proxy_rss_bytes_peak": max(samples, default=0),
                       "proxy_rss_bytes_mean": sum(samples) / len(samples) if samples else 0,
                       "rss_samples": len(samples)})
        if elapsed <= 0 or total <= 0 or steal < 0 or ticks < 0:
            report["errors"].append("invalid counter interval")
        if abs(deviation) > max(0.25, float(args.duration)*0.02):
            report["errors"].append("CPU interval exceeds marker jitter budget")
        report["valid"] = not report["errors"]
    if perf_capture is not None:
        profile = perf_capture.decode(begin["monotonic"] if begin else None, finish["monotonic"] if finish else None)
        report["perf_leaf"] = {"path": str(args.resources.parent / "perf-leaf/capture.json"), "valid": profile["valid"]}
        if not profile["valid"]:
            print(json.dumps({"perf_qualification_errors": profile.get("errors", []),
                "roles": [{"role": role.get("role"), "errors": role.get("errors", []),
                    "known_leaf_fraction": role.get("known_leaf_fraction"),
                    "measurement_sample_count": role.get("measurement_sample_count")}
                    for role in profile.get("roles", [])]}), file=sys.stderr, flush=True)
            report["errors"].append("leaf profile failed identity, loss, or coverage qualification")
            report["valid"] = False
        atexit.unregister(perf_capture.stop)
    args.resources.write_text(json.dumps(report, indent=2) + "\n")
    return status if status else (0 if report["valid"] else 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", action="append", default=[])
    parser.add_argument("--production-observe", action="store_true")
    parser.add_argument("--perf-leaf", action="store_true")
    parser.add_argument("--symbol-elf", action="append", default=[])
    parser.add_argument("--symbol-qualification-report")
    parser.add_argument("--aux-container", action="append", default=[])
    parser.add_argument("--client-name")
    parser.add_argument("--server-name")
    parser.add_argument("--rate", type=int, default=0)
    parser.add_argument("--loadgen-network", default="host")
    parser.add_argument("--loadgen-user", default="")
    parser.add_argument("--fixture-owner", default="local-0")
    parser.add_argument("--allocation-url", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--loadgen-name", required=True)
    parser.add_argument("--exchange-timeout-secs", type=int, default=10)
    for name in ("image", "target", "host-header", "mesh", "duration", "concurrency", "warmup", "payload-size"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.exchange_timeout_secs <= 0:
        parser.error("--exchange-timeout-secs must be positive")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
