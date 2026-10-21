#!/usr/bin/env python3
"""Immutable production ranking plan and strict per-cell evidence ledger."""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess

RUNTIME_SHA = "4a7be250e45a367314e3dec872ecbd512220558e"
ARMS = ["direct", "ferruma", "ferrumb", "envoy", "consulhttp", "ferrumtcpa", "ferrumtcpb", "consultcp"]
ROOT = Path("results")


def physical(arm):
    return {"ferruma": "ferrum", "ferrumb": "ferrum", "ferrumtcpa": "ferrumtcp", "ferrumtcpb": "ferrumtcp"}.get(arm, arm)


def plan(phase):
    if phase not in ("smoke-l7", "smoke", "ranking"):
        raise ValueError("unknown phase")
    cells = []
    if phase.startswith("smoke"):
        arms = ARMS[:5] if phase == "smoke-l7" else ARMS
        for arm in arms:
            cells.append(dict(arm=arm, payload=1024, repetition=1, load="saturated", duration=3, rate=0))
        cells.append(dict(arm="ferruma", payload=1024, repetition=1, load="fixed", duration=3, rate=2000))
    else:
        for repetition in range(1, 5):
            arms = ARMS if repetition % 2 else list(reversed(ARMS))
            sizes = [1024, 1048576] if repetition % 2 else [1048576, 1024]
            loads = ["saturated", "fixed"] if repetition <= 2 else ["fixed", "saturated"]
            for payload in sizes:
                for load in loads:
                    for arm in arms:
                        cells.append(dict(arm=arm, payload=payload, repetition=repetition, load=load, duration=30,
                                          rate=(2000 if payload == 1024 else 200) if load == "fixed" else 0))
    return cells


def provenance():
    image_info = json.loads((ROOT/"images/inspect.json").read_text())
    labels = image_info[0]["Config"].get("Labels") or {}
    if labels.get("org.opencontainers.image.revision") != RUNTIME_SHA:
        raise ValueError("published Ferrum image revision does not match pinned source")
    forbidden = subprocess.check_output(["git", "diff", RUNTIME_SHA, "--", "src", "vendor", "Cargo.toml", "Cargo.lock", "Dockerfile"], text=True)
    if forbidden.strip():
        raise ValueError("production campaign must not change runtime source or build inputs")
    data = {"runtime_sha": RUNTIME_SHA, "harness_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "phase": os.environ.get("BENCH_PHASE", "smoke-l7"), "profile": "release", "features": "cloud-secrets",
        "allocation_instrumentation": False, "ferrum_build_run": "https://github.com/ferrum-edge/ferrum-edge/actions/runs/39611137595",
        "images": image_info, "workers_requested": 4, "concurrency_1KiB": 100, "concurrency_1MiB": 50,
        "warmup_seconds": 3, "source_mode": "file config and file SVIDs; no Kubernetes/cross-node capture",
        "l7_topology": "two sidecars; H1 frontend/backend, Ferrum and static Envoy H2 mTLS peers; Consul explicit HTTP xDS",
        "l4_topology": "same source namespace bridge/VIP capture, declared TCP; Ferrum per-connection mTLS H2 CONNECT, Consul native TCP mTLS",
        "fixed_load_rates": {"1024": 2000, "1048576": 200},
        "fixed_boundary_loss_gate": {"max_missed": 2, "all_missed_due_in_final_nanoseconds": 1000000,
            "requires_exact_missed_ordinal_and_count_accounting": True,
            "note": "bounded end-window admission loss, not proof of timer-only cause or zero overload; preserve every miss and successful-cohort latency"},
        "limits": ["one shared runner, backend/loadgen/proxies share CPU", "static Envoy is not full Istio and policy/telemetry work differs", "socket samples are not complete connection churn counters", "thread context switches are not logical task wakes", "saturated latency and fixed scheduled latency are separate populations"],
        "config_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path("tests/performance/mesh_runtime/configs").rglob("*")) if p.is_file()}}
    (ROOT/"production-provenance.json").write_text(json.dumps(data, indent=2)+"\n")


def validate(cell, load, resource):
    errors = []
    count_keys = ("total_requests", "drained_requests", "cohort_requests", "admitted_requests",
                  "admitted_errors", "total_errors", "warmup_requests", "warmup_errors",
                  "scheduled_requests", "cohort_scheduled_requests", "offered_requests",
                  "missed_requests", "missed_slot_count", "missed_reservations", "unclaimed_requests",
                  "total_bytes", "drained_bytes")
    invalid_counts = []
    for key in count_keys:
        if type(load.get(key)) is not int or load[key] < 0:
            invalid_counts.append(key)
            errors.append(f"missing or invalid nonnegative integer count {key}")
    for key in ("cohort_p50_us", "cohort_p95_us", "cohort_p99_us", "cohort_scheduled_p50_us", "cohort_scheduled_p95_us", "cohort_scheduled_p99_us", "admission_delay_p99_us", "admission_delay_max_us"):
        if type(load.get(key)) is not int or load[key] < 0:
            errors.append(f"missing or invalid numeric evidence {key}")
    valid_rps = type(load.get("rps")) in (int, float) and math.isfinite(load["rps"]) and load["rps"] > 0
    if not valid_rps:
        errors.append("missing or invalid throughput evidence")
    expected = {"mesh": physical(cell["arm"]), "protocol": "http1", "payload_size": cell["payload"],
                "duration_secs": cell["duration"], "rate": cell["rate"], "concurrency": 50 if cell["payload"] >= 1048576 else 100}
    for key, value in expected.items():
        if load.get(key) != value:
            errors.append(f"metadata mismatch {key}: {load.get(key)!r} != {value!r}")
    if not resource.get("valid") or resource.get("errors"):
        errors.append("invalid resource interval")
    # Do not perform arithmetic on malformed counts or discard their raw
    # report from the summary ledger through a TypeError.
    if invalid_counts:
        return errors
    if load["warmup_errors"] != 0:
        errors.append("warmup errors or missing evidence")
    if load["total_errors"] != 0 or load["total_requests"] <= 0:
        errors.append("errors or no useful completions")
    if load["cohort_requests"] != load["total_requests"] + load["drained_requests"]:
        errors.append("successful cohort must equal useful completions plus drains")
    if load["admitted_requests"] != load["cohort_requests"] + load["admitted_errors"]:
        errors.append("admitted cohort accounting mismatch")
    if load["total_errors"] < load["admitted_errors"] + load["warmup_errors"]:
        errors.append("total errors do not cover admitted and warmup errors")
    if load["total_bytes"] != load["total_requests"] * cell["payload"] or load["drained_bytes"] != load["drained_requests"] * cell["payload"]:
        errors.append("successful echo byte accounting mismatch")
    if valid_rps and not math.isclose(load["rps"], load["total_requests"] / cell["duration"], rel_tol=1e-12, abs_tol=1e-9):
        errors.append("throughput does not match useful completions and duration")
    if cell["rate"]:
        offered = cell["rate"]*cell["duration"]
        missed = load["missed_requests"]
        first, last = load.get("first_missed_slot"), load.get("last_missed_slot")
        if load["scheduled_requests"] != load["total_requests"] or load["cohort_scheduled_requests"] != load["cohort_requests"]:
            errors.append("scheduled successful histograms do not conserve completions and drains")
        if (load["offered_requests"] != offered
                or load["missed_slot_count"] != missed
                or load["missed_reservations"]+load["unclaimed_requests"] != missed
                or load["admitted_requests"]+missed != offered):
            errors.append("fixed offered/missed count accounting incorrect")
        elif missed == 0:
            if first is not None or last is not None:
                errors.append("zero misses with nonempty missed range")
        elif not (0 < missed <= 2 and type(first) is int and type(last) is int and 0 <= first <= last < offered
                  and first*1000000000 >= (cell["duration"]*1000000000-1000000)*cell["rate"]):
            errors.append("fixed schedule lost a slot outside the bounded final-1ms qualification")
    elif (any(load[key] != 0 for key in ("scheduled_requests", "cohort_scheduled_requests", "offered_requests",
                                        "missed_requests", "missed_slot_count", "missed_reservations", "unclaimed_requests"))
          or load.get("first_missed_slot") is not None or load.get("last_missed_slot") is not None):
        errors.append("saturated mode must not contain scheduled requests or missed slots")
    return errors


def summarize():
    planned = json.loads((ROOT/"production-plan.json").read_text())
    rows, errors = [], []
    for cell in planned:
        directory = ROOT/cell["arm"]/cell["load"]/f"run_{cell['repetition']}"/f"payload_{cell['payload']}"
        name = f"{physical(cell['arm'])}_http1_{cell['payload']}"
        try:
            load = json.loads((directory/f"{name}.json").read_text())
            resource = json.loads((directory/f"{name}.resources.json").read_text())
            failures = validate(cell, load, resource)
            completed, cpu = load.get("total_requests"), resource.get("proxy_cpu_seconds")
            cpu_us_per_completion = None
            if (type(completed) is int and completed > 0 and type(cpu) in (int, float)
                    and math.isfinite(cpu) and cpu >= 0):
                cpu_us_per_completion = cpu*1e6/completed
            elif not failures:
                failures.append("missing or invalid CPU per completion evidence")
            if failures:
                errors.append({"cell": cell, "errors": failures})
            rows.append({**cell, "valid": not failures, "strict_zero_miss": not failures and load.get("missed_requests") == 0, "report": load, "resources": resource,
                         "cpu_us_per_completion": cpu_us_per_completion})
        except (OSError, ValueError, TypeError, KeyError) as exc:
            errors.append({"cell": cell, "errors": [str(exc)]})
    groups = []
    for arm in ARMS:
        for payload in (1024,1048576):
            for mode in ("saturated", "fixed"):
                subset = [r for r in rows if r["arm"]==arm and r["payload"]==payload and r["load"]==mode]
                if not subset:
                    continue
                keys = ("rps", "cohort_p50_us", "cohort_p95_us", "cohort_p99_us", "cohort_scheduled_p50_us", "cohort_scheduled_p95_us", "cohort_scheduled_p99_us")
                if not all(r["valid"] and all(k in r["report"] for k in keys) for r in subset):
                    groups.append({"arm": arm, "payload": payload, "load": mode, "repetitions": len(subset), "all_valid": False, "metrics": None})
                    continue
                metrics = {}
                for key in ("rps", "cohort_p50_us", "cohort_p95_us", "cohort_p99_us", "cohort_scheduled_p50_us", "cohort_scheduled_p95_us", "cohort_scheduled_p99_us", "missed_requests", "admission_delay_p99_us", "admission_delay_max_us"):
                    values = [r["report"][key] for r in subset]
                    metrics[key] = {"median": statistics.median(values), "min": min(values), "max": max(values), "all": values}
                values = [r["cpu_us_per_completion"] for r in subset]
                metrics["cpu_us_per_completion"] = {"median": statistics.median(values), "min": min(values), "max": max(values), "all": values}
                groups.append({"arm": arm, "payload": payload, "load": mode, "repetitions": len(subset), "all_valid": all(r["valid"] for r in subset), "metrics": metrics})
    result = {"planned_cells": len(planned), "parsed_cells": len(rows), "errors": errors, "groups": groups,
              "cells": rows, "valid": not errors and len(rows)==len(planned),
              "strict_zero_miss_valid": not errors and len(rows)==len(planned) and all(r["strict_zero_miss"] for r in rows),
              "fixed_admission_losses": [{"cell": {k: r[k] for k in ("arm", "payload", "load", "repetition")},
                  "offered": r["report"]["offered_requests"], "missed": r["report"]["missed_requests"],
                  "loss_fraction": r["report"]["missed_requests"]/max(1,r["report"]["offered_requests"])}
                  for r in rows if r["load"] == "fixed" and r["valid"]]}
    (ROOT/"production-summary.json").write_text(json.dumps(result, indent=2)+"\n")
    text = ["Production mesh campaign", "", f"Planned: {len(planned)}; parsed: {len(rows)}; invalid/missing: {len(errors)}.",
        f"Strict zero-missed-arrival result: {result['strict_zero_miss_valid']}.",
        "All outcomes retained. L4 and L7 are separate product paths. Fixed scheduled latency includes admission delay. Up to two missed arrivals are qualified only with ordinal proof that every missed due time was in the final 1 ms; all misses remain reported.", "",
        "| Arm | Bytes | Load | N | RPS median | successful cohort p50/p95/p99 us (fixed: scheduled; saturated: service) | CPU us/completion | Missed arrivals (all repetitions) |", "|---|---:|---|---:|---:|---|---:|---|"]
    for group in groups:
        m=group["metrics"]
        if m is None:
            text.append(f"| {group['arm']} | {group['payload']} | {group['load']} | {group['repetitions']} | INVALID | INVALID | INVALID | retained in cell records |")
            continue
        tail_keys = ("cohort_scheduled_p50_us", "cohort_scheduled_p95_us", "cohort_scheduled_p99_us") if group["load"] == "fixed" else ("cohort_p50_us","cohort_p95_us","cohort_p99_us")
        tails="/".join(str(round(m[k]["median"],1)) for k in tail_keys)
        text.append(f"| {group['arm']} | {group['payload']} | {group['load']} | {group['repetitions']} | {m['rps']['median']:.1f} | {tails} | {m['cpu_us_per_completion']['median']:.1f} | {m['missed_requests']['all']} |")
    if errors:
        text += ["", "Invalid/missing cells:", json.dumps(errors, indent=2)]
    (ROOT/"production-summary.md").write_text("\n".join(text)+"\n")
    print("\n".join(text))
    return 0 if result["valid"] else 1


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action", choices=["provenance","plan","summarize","accept"])
    action=parser.parse_args().action
    ROOT.mkdir(exist_ok=True)
    if action=="provenance": provenance()
    elif action=="plan":
        cells=plan(os.environ.get("BENCH_PHASE","smoke-l7"))
        (ROOT/"production-plan.json").write_text(json.dumps(cells,indent=2)+"\n")
        (ROOT/"production-plan.txt").write_text("".join(" ".join(str(c[k]) for k in ("arm","payload","repetition","load","duration","rate"))+"\n" for c in cells))
    elif action=="summarize": return summarize()
    else: return 0 if json.loads((ROOT/"production-summary.json").read_text())["valid"] else 1
    return 0
if __name__=="__main__": raise SystemExit(main())
