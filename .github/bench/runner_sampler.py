#!/usr/bin/env python3
"""Throwaway runner sampler for bench/runner-loss-rust-1100 (never merged).

Usage:
  runner_sampler.py sample <out.jsonl> <label>   # loop until SIGTERM / parent exits
  runner_sampler.py summary <out.jsonl> <label>  # print peaks

Every 5 s records: MemAvailable, SwapFree, swap-in/out pages, PSI memory/io/cpu,
free disk on / and /mnt, the three largest rustc processes (crate name only),
and every 60 s `du` of target/. Prints a one-line digest to stdout every 30 s so
a job that dies mid-step still leaves a trail in its log.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

IDENT = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")


def meminfo() -> dict[str, int]:
    out = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        k, v = line.split(":", 1)
        out[k] = int(v.split()[0])
    return out


def psi(kind: str) -> dict[str, float]:
    try:
        text = Path(f"/proc/pressure/{kind}").read_text()
    except OSError:
        return {}
    res = {}
    for line in text.splitlines():
        parts = line.split()
        scope = parts[0]
        for p in parts[1:]:
            k, v = p.split("=")
            if k in ("avg10", "total"):
                res[f"{scope}_{k}"] = float(v)
    return res


def disk(path: str) -> int | None:
    try:
        st = os.statvfs(path)
    except OSError:
        return None
    return st.f_bavail * st.f_frsize // (1024 * 1024)


def rustcs() -> list[dict]:
    procs = []
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            if (proc / "comm").read_text().strip() != "rustc":
                continue
            status = (proc / "status").read_text()
            rss = int(re.search(r"^VmRSS:\s+(\d+)", status, re.M).group(1))
            swp = int(re.search(r"^VmSwap:\s+(\d+)", status, re.M).group(1))
            args = (proc / "cmdline").read_bytes().split(b"\0")
            crate = "?"
            for i, a in enumerate(args[:-1]):
                if a == b"--crate-name" and IDENT.fullmatch(args[i + 1]):
                    crate = args[i + 1].decode()
                    break
            procs.append({"crate": crate, "test": b"--test" in args,
                          "rss_mb": rss // 1024, "swap_mb": swp // 1024})
        except (OSError, AttributeError, ValueError):
            continue
    procs.sort(key=lambda p: -(p["rss_mb"] + p["swap_mb"]))
    return procs[:3]


def du_target() -> int | None:
    if not Path("target").exists():
        return 0
    try:
        out = subprocess.run(["du", "-sm", "target"], capture_output=True, text=True, timeout=50)
        return int(out.stdout.split()[0])
    except (subprocess.SubprocessError, ValueError, IndexError):
        return None


def sample(path: str, label: str) -> None:
    stop = False

    def handler(_s, _f):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    parent = os.getppid()
    start = time.monotonic()
    last_du = -1e9
    last_print = -1e9
    du = None
    vm0 = None
    with open(path, "a", encoding="utf-8") as out:
        while not stop and os.getppid() == parent and time.monotonic() - start < 4 * 3600:
            t = time.monotonic() - start
            mi = meminfo()
            vm = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
            if vm0 is None:
                vm0 = vm
            if t - last_du >= 60:
                du = du_target()
                last_du = t
            rec = {
                "label": label, "t": round(t, 1),
                "avail_mb": mi["MemAvailable"] // 1024,
                "swap_used_mb": (mi["SwapTotal"] - mi["SwapFree"]) // 1024,
                "swap_total_mb": mi["SwapTotal"] // 1024,
                "dirty_mb": mi.get("Dirty", 0) // 1024,
                "pswpout_mb": (int(vm["pswpout"]) - int(vm0["pswpout"])) * 4 // 1024,
                "pswpin_mb": (int(vm["pswpin"]) - int(vm0["pswpin"])) * 4 // 1024,
                "psi_mem": psi("memory"), "psi_io": psi("io"), "psi_cpu": psi("cpu"),
                "root_free_mb": disk("/"), "mnt_free_mb": disk("/mnt"),
                "target_du_mb": du,
                "rustc": rustcs(),
            }
            out.write(json.dumps(rec) + "\n")
            out.flush()
            if t - last_print >= 30:
                last_print = t
                top = " ".join(f"{p['crate']}{'[t]' if p['test'] else ''}={p['rss_mb']}+{p['swap_mb']}" for p in rec["rustc"])
                print(f"[sampler {label}] t={t:.0f}s avail={rec['avail_mb']}MB swap={rec['swap_used_mb']}/{rec['swap_total_mb']}MB "
                      f"swpout={rec['pswpout_mb']}MB memfull10={rec['psi_mem'].get('full_avg10', '-')} iofull10={rec['psi_io'].get('full_avg10', '-')} "
                      f"rootfree={rec['root_free_mb']}MB mntfree={rec['mnt_free_mb']}MB target={du}MB rustc: {top}", flush=True)
            time.sleep(5)


def summary(path: str, label: str) -> None:
    recs = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    recs = [r for r in recs if r.get("label") == label]
    if not recs:
        print(f"SUMMARY {label}: no samples")
        return
    def rsum(r):
        return sum(p["rss_mb"] + p["swap_mb"] for p in r["rustc"])
    peak = max(recs, key=rsum)
    res = {
        "label": label, "samples": len(recs), "seconds": recs[-1]["t"],
        "peak_rustc_total_mb": rsum(peak),
        "peak_rustc_procs": [f"{p['crate']}{'[t]' if p['test'] else ''}={p['rss_mb'] + p['swap_mb']}" for p in peak["rustc"]],
        "peak_single_rustc_mb": max((p["rss_mb"] + p["swap_mb"] for r in recs for p in r["rustc"]), default=0),
        "min_avail_mb": min(r["avail_mb"] for r in recs),
        "max_swap_used_mb": max(r["swap_used_mb"] for r in recs),
        "swap_total_mb": recs[0]["swap_total_mb"],
        "pswpout_mb": recs[-1]["pswpout_mb"], "pswpin_mb": recs[-1]["pswpin_mb"],
        "max_psi_mem_full_avg10": max(r["psi_mem"].get("full_avg10", 0) for r in recs),
        "max_psi_io_full_avg10": max(r["psi_io"].get("full_avg10", 0) for r in recs),
        "psi_mem_full_total_s": round((recs[-1]["psi_mem"].get("full_total", 0) - recs[0]["psi_mem"].get("full_total", 0)) / 1e6, 1),
        "psi_io_full_total_s": round((recs[-1]["psi_io"].get("full_total", 0) - recs[0]["psi_io"].get("full_total", 0)) / 1e6, 1),
        "min_root_free_mb": min((r["root_free_mb"] for r in recs if r["root_free_mb"] is not None), default=None),
        "min_mnt_free_mb": min((r["mnt_free_mb"] for r in recs if r["mnt_free_mb"] is not None), default=None),
        "max_target_du_mb": max((r["target_du_mb"] for r in recs if r["target_du_mb"] is not None), default=None),
    }
    print("SUMMARY " + json.dumps(res, sort_keys=True), flush=True)


if __name__ == "__main__":
    mode, path, label = sys.argv[1], sys.argv[2], sys.argv[3]
    if mode == "sample":
        sample(path, label)
    else:
        summary(path, label)
