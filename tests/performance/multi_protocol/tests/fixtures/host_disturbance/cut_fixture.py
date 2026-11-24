#!/usr/bin/env python3
"""Cut a small host_disturbance fixture out of one unpacked hosted run directory.

    cut_fixture.py <run_dir> <lane> <output.json> --run <id> --cpu "<model>" \
        --note "<what the job shows>" [--gateways "a b"] [--payload-sizes "1 2"]

`<run_dir>` is `.../gateways-protocol-bench-<lane>-<sha>/run_1`. A full run
directory is tens of megabytes; the fixture keeps what host_disturbance.py
reads and nothing else: per sample the request count, the measured window and
the cumulative gateway and backend CPU at each sampler tick near that window,
plus the settle record's process lists. A run recorded with the sampler's
`--host-cpu` also keeps, per tick, the client's CPU and the host's busy CPU,
and per sample the processes outside the benchmark that used a tenth of a
CPU-second or more. `expand` in test_host_disturbance.py turns it back into a
run directory.
"""

import argparse
import json
from pathlib import Path

MARGIN_SECONDS = 1.5


def load(path):
    with open(path) as handle:
        return json.load(handle)


def cut(run_dir, lane, gateways, sizes):
    run_dir = Path(run_dir)
    manifest = load(run_dir / "manifest.json")
    gateways = gateways or manifest["gateways"]
    sizes = sizes or manifest["payload_sizes"]
    samples, origin = [], None
    for pair in range(1, manifest["pairs"] + 1):
        folder = run_dir / "pairs" / f"pair_{pair:03d}"
        for gateway in gateways:
            for size in sizes:
                sample = load(folder / f"{gateway}_{lane}_{size}.json")
                usage = load(folder / "diagnostics" / f"{gateway}_{size}_process_usage.json")
                start = sample["phases"]["measurement_start_unix_secs"]
                seconds = sample["phases"]["measurement_secs"]
                origin = start if origin is None else min(origin, start)
                series = []
                for point in usage["timeline"]:
                    time = point["unix_secs"]
                    if not start - MARGIN_SECONDS <= time <= start + seconds + MARGIN_SECONDS:
                        continue
                    used = {"gateway": 0.0, "backend": 0.0}
                    client = None
                    for process in point["processes"]:
                        if process["role"] in used:
                            used[process["role"]] += process["cpu_seconds"]
                        elif process["role"] == "client":
                            client = round((client or 0.0) + process["cpu_seconds"], 2)
                    row = [time, round(used["gateway"], 2), round(used["backend"], 2)]
                    if "host" in point:
                        row += [client, round(point["host"]["busy_cpu_seconds"], 2)]
                    series.append(row)
                kept = dict(gateway=gateway, payload_size=size, pair=pair,
                            order_position=sample["order_position"],
                            total_requests=sample["total_requests"],
                            measurement=[start, seconds], series=series)
                if "host_processes" in usage:
                    kept["host_processes"] = [
                        dict(comm=process["comm"], cpu_seconds=process["cpu_seconds"])
                        for process in usage["host_processes"] if process["cpu_seconds"] >= 0.1]
                samples.append(kept)
    origin = int(origin) - 10
    for sample in samples:
        sample["measurement"][0] = round(sample["measurement"][0] - origin, 3)
        sample["series"] = [[round(row[0] - origin, 3)] + row[1:] for row in sample["series"]]
    settle = []
    path = run_dir / "host_settle.json"
    if path.exists():
        for record in load(path)["arms"]:
            kept = {key: record[key] for key in (
                "arm", "reason", "top_processes", "host_processes_since_before_start") if key in record}
            settle.append(kept)
    return dict(lane=lane, gateways=gateways, payload_sizes=sizes, pairs=manifest["pairs"],
                settle=settle, samples=samples)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("run_dir")
    parser.add_argument("lane")
    parser.add_argument("output")
    parser.add_argument("--run", required=True, help="GitHub Actions run id")
    parser.add_argument("--cpu", required=True, help="runner CPU model from the job log")
    parser.add_argument("--note", required=True)
    parser.add_argument("--gateways")
    parser.add_argument("--payload-sizes")
    args = parser.parse_args()
    fixture = cut(args.run_dir, args.lane,
                  args.gateways.split() if args.gateways else None,
                  [int(size) for size in args.payload_sizes.split()] if args.payload_sizes else None)
    fixture = dict(source=dict(run=int(args.run), runner_cpu_model=args.cpu, note=args.note), **fixture)
    with open(args.output, "w") as handle:
        json.dump(fixture, handle, separators=(",", ":"))
        handle.write("\n")


if __name__ == "__main__":
    main()
