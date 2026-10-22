#!/usr/bin/env python3
"""Read-only Linux process/transport observations for a disposable CI fixture.

Thread scheduler counters are not Tokio task/wake counters. Socket sampling can
miss short connections. Metric snapshots bracket warmup plus drain, not the exact
CPU epoch. These limits are intentional and recorded in the artifact.
"""
from __future__ import annotations
import json
import os
import socket
import subprocess
import time
from pathlib import Path


def inspect_container(name):
    obj = json.loads(subprocess.check_output(["docker", "inspect", name], timeout=5))[0]
    if not obj["State"].get("Running"):
        raise ValueError(f"container not running: {name}")
    return {"name": name, "pid": obj["State"]["Pid"], "image_id": obj["Image"],
            "image_ref": obj["Config"]["Image"], "args": obj["Args"],
            "cpu_limit_nanos": obj["HostConfig"]["NanoCpus"],
            "cpu_quota": obj["HostConfig"]["CpuQuota"],
            "cpu_period": obj["HostConfig"]["CpuPeriod"],
            "cpuset": obj["HostConfig"]["CpusetCpus"],
            "memory_limit_bytes": obj["HostConfig"]["Memory"],
            "network_mode": obj["HostConfig"]["NetworkMode"],
            "worker_environment": [e for e in obj["Config"].get("Env",[]) if e.startswith("FERRUM_WORKER_THREADS=")]}


def endpoint(value):
    address, port = value.split(":")
    raw = bytes.fromhex(address)
    if len(raw) == 4:
        ip = socket.inet_ntop(socket.AF_INET, raw[::-1])
    else:
        raw = b"".join(raw[i:i+4][::-1] for i in range(0, 16, 4))
        ip = socket.inet_ntop(socket.AF_INET6, raw)
    return {"address": ip, "port": int(port, 16)}


def sockets(pid):
    base = Path("/proc") / str(pid)
    inodes = set()
    for fd in (base / "fd").iterdir():
        try:
            target = fd.readlink().as_posix()
            if target.startswith("socket:["):
                inodes.add(target[8:-1])
        except FileNotFoundError:
            pass
    result = []
    for family in ("tcp", "tcp6"):
        for line in (base / "net" / family).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[9] in inodes:
                result.append({"inode": fields[9], "local": endpoint(fields[1]),
                               "remote": endpoint(fields[2]), "state": fields[3]})
    return result


def thread_snapshot(pid):
    result = []
    for task in (Path("/proc") / str(pid) / "task").iterdir():
        try:
            raw = (task / "stat").read_text()
            stat = raw.rsplit(")", 1)[1].split()
            user_ticks, system_ticks = int(stat[11]), int(stat[12])
            if user_ticks < 0 or system_ticks < 0:
                raise ValueError("negative thread CPU ticks")
            status = dict(line.split(":", 1) for line in (task / "status").read_text().splitlines())
            sched = [int(x) for x in (task / "schedstat").read_text().split()]
            result.append({"tid": int(task.name), "comm": raw.split("(", 1)[1].rsplit(")", 1)[0],
                "starttime": int(stat[19]), "cpu_ticks": user_ticks + system_ticks,
                "last_cpu": int(stat[36]), "runtime_ns": sched[0], "runqueue_wait_ns": sched[1],
                "timeslices": sched[2], "voluntary_context_switches": int(status["voluntary_ctxt_switches"]),
                "involuntary_context_switches": int(status["nonvoluntary_ctxt_switches"]),
                "user_ticks": user_ticks, "system_ticks": system_ticks})
        except FileNotFoundError:
            pass
    return result


def snapshot(containers):
    return {"monotonic": time.monotonic(), "processes": [
        {"name": c["name"], "pid": c["pid"], "threads": thread_snapshot(c["pid"]),
         "sockets": sockets(c["pid"])} for c in containers]}


def metrics(mesh, containers, destination, phase):
    # Listener resources only. Never request an unfiltered Envoy config dump
    # because SDS carries private keys. nsenter changes only this child process.
    for index, container in enumerate(containers[:2]):
        if mesh.startswith("ferrum"):
            port = 15120 if index == 0 else 15020
            paths = [("metrics", "/metrics")]
        else:
            port = (19001 if index == 0 else 19002) if mesh.startswith("consul") else (9901 if index == 0 else 9902)
            paths = [("stats", "/stats?format=json"), ("listeners", "/config_dump?resource=dynamic_listeners"),
                     ("static-listeners", "/config_dump?resource=static_listeners"),
                     ("clusters", "/clusters?format=json")]
        for label, path in paths:
            command = ["nsenter", "-t", str(container["pid"]), "-n", "curl", "--fail", "--silent",
                       "--show-error", "--max-time", "3", "--max-filesize", "4194304", f"http://127.0.0.1:{port}{path}"]
            done = subprocess.run(command, capture_output=True, timeout=5)
            output = {"command_path": path, "phase": phase, "returncode": done.returncode,
                      "body": done.stdout.decode(errors="replace"), "error": done.stderr.decode(errors="replace")}
            (destination / f"{phase}-{index}-{label}.json").write_text(json.dumps(output))


def scheduler_deltas(before, after):
    deltas = []
    for left, right in zip(before["processes"], after["processes"]):
        previous = {(t["tid"], t["starttime"]): t for t in left["threads"]}
        current = {(t["tid"], t["starttime"]): t for t in right["threads"]}
        common = previous.keys() & current.keys()
        counts = {key: sum(current[t][key]-previous[t][key] for t in common) for key in
                  ("cpu_ticks", "runtime_ns", "runqueue_wait_ns", "timeslices", "voluntary_context_switches", "involuntary_context_switches")}
        deltas.append({"name": left["name"], "persistent_threads": len(common),
                       "created_threads": len(current.keys()-previous.keys()),
                       "exited_threads": len(previous.keys()-current.keys()), **counts})
    return deltas
