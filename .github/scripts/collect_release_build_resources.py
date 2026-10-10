#!/usr/bin/env python3
"""Observe Linux release-host resources without changing build inputs or status."""

from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
from pathlib import Path


READ_LIMIT = 65536
MEMINFO_KEYS = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
CGROUP_FILES = (
    "memory.max", "memory.current", "memory.peak", "memory.events",
    "memory.swap.max", "memory.swap.current",
)
OOM_LINE = re.compile(r"out of memory|oom-kill|killed process|oom_reaper", re.I)


def read_resource(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = stream.read(READ_LIMIT + 1)
    except (OSError, UnicodeError) as error:
        return {"status": "unavailable", "reason": type(error).__name__}
    if len(value) > READ_LIMIT:
        return {"status": "unavailable", "reason": "read_limit_exceeded"}
    return {"status": "observed", "value": value.strip()}


def format_observation(result: subprocess.CompletedProcess, *, kernel: bool = False) -> dict:
    if result.returncode:
        return {"status": "unavailable", "exit_code": result.returncode}
    output = result.stdout[-READ_LIMIT:]
    truncated = len(result.stdout) > READ_LIMIT
    if kernel:
        matches = [line[:1000] for line in output.splitlines() if OOM_LINE.search(line)]
        return {"status": "observed", "matching_lines": matches[-100:],
                "truncated": truncated or len(matches) > 100,
                "absence_does_not_exclude_oom": True}
    return {"status": "observed", "value": output.strip(), "truncated": truncated}


def observe_host_commands() -> dict:
    observations = {}
    # Keep every process argv literal for the trusted automation scanner.
    for name in ("cpu_count", "kernel_version", "workspace_disk", "docker_host", "kernel_oom_messages"):
        try:
            if name == "cpu_count":
                result = subprocess.run(["nproc"], capture_output=True, text=True, timeout=10, check=False)
            elif name == "kernel_version":
                result = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=10, check=False)
            elif name == "workspace_disk":
                result = subprocess.run(["df", "-h", "."], capture_output=True, text=True, timeout=10, check=False)
            elif name == "docker_host":
                result = subprocess.run(["docker", "info", "--format", "CPU={{.NCPU}} MemoryBytes={{.MemTotal}} Cgroup={{.CgroupVersion}}"], capture_output=True, text=True, timeout=10, check=False)
            else:
                result = subprocess.run(["sudo", "-n", "dmesg", "--ctime"], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
            observations[name] = {"status": "unavailable", "reason": type(error).__name__}
        else:
            observations[name] = format_observation(result, kernel=name == "kernel_oom_messages")
    return observations


def collect(phase: str) -> dict:
    meminfo = read_resource(Path("/proc/meminfo"))
    if meminfo["status"] == "observed":
        meminfo["value"] = {
            key: value.strip()
            for line in meminfo["value"].splitlines() if ":" in line
            for key, value in [line.split(":", 1)] if key in MEMINFO_KEYS
        }
    return {
        "phase": phase,
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "host observations; not per-rustc peak memory or container OOM proof",
        "meminfo": meminfo,
        "cgroup_root": {name: read_resource(Path("/sys/fs/cgroup") / name)
                        for name in CGROUP_FILES},
        **observe_host_commands(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", required=True, choices=("before", "after", "qualification"))
    args = parser.parse_args()
    # Missing telemetry remains explicit data, never a substitute build result.
    print(json.dumps(collect(args.phase), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
