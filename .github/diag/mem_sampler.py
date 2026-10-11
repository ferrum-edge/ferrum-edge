#!/usr/bin/env python3
"""Temporary diagnostic: sample host memory and per-compiler-process peaks."""

import glob
import json
import os
import signal
import sys
import time

OUT = sys.argv[1]
INTERVAL = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
WATCH = {"rustc", "cc1", "cc1plus", "ld", "ld.bfd", "collect2", "cargo", "lto1",
         "aarch64-linux-g", "cc", "as", "cross", "docker", "containerd", "dockerd"}
running = True


def stop(*_):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)


def meminfo():
    vals = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":", 1)
            vals[k] = int(v.split()[0])
    return vals


def psi():
    try:
        with open("/proc/pressure/memory") as f:
            return f.read().split("\n")[1].strip()  # full
    except OSError:
        return None


def status(pid):
    out = {}
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                if k in ("Name", "VmRSS", "VmHWM", "VmSwap", "VmPeak", "RssAnon"):
                    out[k] = v.strip()
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = f.read().split(b"\0")
        out["argv"] = argv
    except OSError:
        return None
    return out


def kb(s):
    return int(s.split()[0]) if s else 0


def crate_of(argv):
    try:
        i = argv.index(b"--crate-name")
        return argv[i + 1].decode()
    except (ValueError, IndexError):
        return b" ".join(argv[:3]).decode(errors="replace")[:80]


procs = {}
min_avail = None
max_swap_used = 0
max_committed = 0
max_anon_huge = 0
cg_peak = {}
start = time.time()
with open(OUT + ".jsonl", "w") as log:
    while running:
        m = meminfo()
        swap_used = m["SwapTotal"] - m["SwapFree"]
        avail = m["MemAvailable"]
        min_avail = avail if min_avail is None else min(min_avail, avail)
        max_swap_used = max(max_swap_used, swap_used)
        max_committed = max(max_committed, m.get("Committed_AS", 0))
        max_anon_huge = max(max_anon_huge, m.get("AnonHugePages", 0))
        top = []
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            st = status(d)
            if not st or st.get("Name") not in WATCH:
                continue
            rss = kb(st.get("VmRSS")); hwm = kb(st.get("VmHWM")); sw = kb(st.get("VmSwap"))
            key = (d, st.get("Name"))
            p = procs.setdefault(key, {"pid": int(d), "name": st.get("Name"),
                                       "crate": crate_of(st["argv"]), "hwm_kb": 0,
                                       "max_rss_kb": 0, "max_swap_kb": 0, "max_rss_plus_swap_kb": 0,
                                       "first_seen_s": round(time.time() - start, 1)})
            p["hwm_kb"] = max(p["hwm_kb"], hwm)
            p["max_rss_kb"] = max(p["max_rss_kb"], rss)
            p["max_swap_kb"] = max(p["max_swap_kb"], sw)
            p["max_rss_plus_swap_kb"] = max(p["max_rss_plus_swap_kb"], rss + sw)
            p["last_seen_s"] = round(time.time() - start, 1)
            if rss > 200000:
                top.append([p["crate"], st.get("Name"), rss, sw])
        for f in glob.glob("/sys/fs/cgroup/system.slice/docker-*.scope/memory.peak"):
            try:
                with open(f) as fh:
                    cg_peak[f] = max(cg_peak.get(f, 0), int(fh.read().strip()))
            except (OSError, ValueError):
                pass
        log.write(json.dumps({"t": round(time.time() - start, 1), "avail_kb": avail,
                              "swap_used_kb": swap_used, "anon_huge_kb": m.get("AnonHugePages", 0),
                              "committed_kb": m.get("Committed_AS", 0), "psi_full": psi(),
                              "big": sorted(top, key=lambda r: -r[2])[:6]}) + "\n")
        log.flush()
        time.sleep(INTERVAL)

big = sorted(procs.values(), key=lambda p: -p["max_rss_plus_swap_kb"])[:15]
summary = {"duration_s": round(time.time() - start), "min_mem_available_kb": min_avail,
           "max_swap_used_kb": max_swap_used, "max_committed_as_kb": max_committed,
           "max_anon_huge_pages_kb": max_anon_huge, "docker_cgroup_memory_peak_bytes": cg_peak,
           "top_processes": big}
with open(OUT + ".summary.json", "w") as f:
    json.dump(summary, f, indent=2)
