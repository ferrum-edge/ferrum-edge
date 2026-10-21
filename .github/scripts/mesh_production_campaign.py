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
    if phase not in ("smoke-l7", "smoke", "smoke-fixed", "ranking"):
        raise ValueError("unknown phase")
    cells = []
    if phase == "smoke-fixed":
        arms = ["direct", "ferruma", "ferrumb", "envoy"]
        for repetition in (1, 2):
            for arm in arms if repetition == 1 else reversed(arms):
                cells.append(dict(arm=arm, payload=1024, repetition=repetition, load="fixed", duration=30, rate=2000))
    elif phase.startswith("smoke"):
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
        "qualification_semantics": {"measurement": "Conserved end-to-end errors and admission losses remain observations; their causes are not automatically attributed to the product.",
            "capacity": "The separate zero-error capacity gate retains its existing error and bounded final-1ms admission-loss requirements."},
        "allocation_instrumentation": False, "ferrum_build_run": "https://github.com/ferrum-edge/ferrum-edge/actions/runs/39611137595",
        "images": image_info, "workers_requested": 4, "concurrency_1KiB": 100, "concurrency_1MiB": 50,
        "warmup_seconds": 3, "source_mode": "localized file config and file SVIDs; synthetic local capture only, no Kubernetes/cross-node deployment",
        "l7_topology": "two sidecars; H1 frontend/backend, Ferrum and static Envoy H2 mTLS peers; Consul explicit HTTP xDS",
        "l4_topology": "matched L4 source namespace bridge/VIP capture, declared TCP; Ferrum per-connection mTLS H2 CONNECT, Consul native TCP mTLS",
        "telemetry_scope": "access logging disabled; native operational counters enabled; full identity-bound workload telemetry not qualified",
        "ferrum_l4_workload_telemetry_qualified": False,
        "telemetry_limits": ["localized file fixture does not inject Prometheus exporter", "captured egress selects only workload_metrics and omits required Prometheus observation/completion hooks", "destination HBONE CONNECT uses HTTP telemetry families, not raw TCP lifecycle families"],
        "fixed_load_rates": {"1024": 2000, "1048576": 200},
        "fixed_boundary_loss_gate": {"max_missed": 2, "all_missed_due_in_final_nanoseconds": 1000000,
            "requires_exact_missed_ordinal_and_count_accounting": True,
            "note": "bounded end-window admission loss, not proof of timer-only cause or zero overload; preserve every miss and successful-cohort latency"},
        "limits": ["one shared runner, backend/loadgen/proxies share CPU", "L4 bridge/capture differs from L7 host-network placement; cross-layer differences do not isolate HTTP overhead", "static Envoy is not full Istio and policy/telemetry work differs", "socket samples are not complete connection churn counters", "thread context switches are not logical task wakes", "saturated latency and fixed scheduled latency are separate populations"],
        "config_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path("tests/performance/mesh_runtime/configs").rglob("*")) if p.is_file()}}
    (ROOT/"production-provenance.json").write_text(json.dumps(data, indent=2)+"\n")


COUNT_KEYS = ("total_requests", "drained_requests", "cohort_requests", "admitted_requests",
              "admitted_errors", "total_errors", "warmup_requests", "warmup_errors",
              "scheduled_requests", "cohort_scheduled_requests", "offered_requests",
              "missed_requests", "missed_slot_count", "missed_reservations", "unclaimed_requests",
              "total_bytes", "drained_bytes")
TAIL_KEYS = ("cohort_p50_us", "cohort_p95_us", "cohort_p99_us",
             "cohort_scheduled_p50_us", "cohort_scheduled_p95_us", "cohort_scheduled_p99_us")


def finite_number(value, *, positive=False):
    return type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0)


def validate_observation(cell, load, resource):
    """Check evidence, not whether the observed product met a zero-error SLO."""
    if not isinstance(load, dict) or not isinstance(resource, dict):
        return ["load and resource reports must be JSON objects"]
    errors, invalid_counts = [], []
    for key in COUNT_KEYS:
        if type(load.get(key)) is not int or load[key] < 0:
            invalid_counts.append(key)
            errors.append(f"missing or invalid nonnegative integer count {key}")
    for key in (*TAIL_KEYS, "admission_delay_p99_us", "admission_delay_max_us"):
        if type(load.get(key)) is not int or load[key] < 0:
            errors.append(f"missing or invalid numeric evidence {key}")
    valid_rps = finite_number(load.get("rps"))
    if not valid_rps:
        errors.append("missing or invalid throughput evidence")
    expected = {"mesh": physical(cell["arm"]), "protocol": "http1", "payload_size": cell["payload"],
                "duration_secs": cell["duration"], "rate": cell["rate"], "concurrency": 50 if cell["payload"] >= 1048576 else 100}
    for key, value in expected.items():
        if load.get(key) != value:
            errors.append(f"metadata mismatch {key}: {load.get(key)!r} != {value!r}")
    if resource.get("valid") is not True or resource.get("errors") != []:
        errors.append("invalid resource interval")
    if not finite_number(resource.get("proxy_cpu_seconds")):
        errors.append("missing or invalid proxy CPU evidence")
    elapsed = resource.get("elapsed_seconds")
    begin, end = resource.get("begin"), resource.get("end")
    if (not finite_number(elapsed, positive=True) or not isinstance(begin, dict) or not isinstance(end, dict)
            or not finite_number(begin.get("monotonic")) or not finite_number(end.get("monotonic"))
            or end["monotonic"] <= begin["monotonic"]
            or not math.isclose(end["monotonic"]-begin["monotonic"], elapsed, rel_tol=1e-12, abs_tol=1e-9)
            or abs(elapsed-cell["duration"]) > max(0.25, cell["duration"]*0.02)):
        errors.append("missing or invalid resource marker interval")
    if invalid_counts:
        return errors
    if load["cohort_requests"] != load["total_requests"] + load["drained_requests"]:
        errors.append("successful cohort must equal useful completions plus drains")
    if load["admitted_requests"] != load["cohort_requests"] + load["admitted_errors"]:
        errors.append("admitted cohort accounting mismatch")
    if load["total_errors"] < load["admitted_errors"] + load["warmup_errors"]:
        errors.append("total errors do not cover admitted and warmup errors")
    for count, keys in (("cohort_requests", TAIL_KEYS[:3]), ("cohort_scheduled_requests", TAIL_KEYS[3:]),
                        ("admitted_requests", ("admission_delay_p99_us", "admission_delay_max_us"))):
        if load[count] == 0 and any(load.get(key) != 0 for key in keys):
            errors.append(f"empty {count} population has nonzero histogram evidence")
    if load["total_bytes"] != load["total_requests"] * cell["payload"] or load["drained_bytes"] != load["drained_requests"] * cell["payload"]:
        errors.append("successful echo byte accounting mismatch")
    if valid_rps and not math.isclose(load["rps"], load["total_requests"] / cell["duration"], rel_tol=1e-12, abs_tol=1e-9):
        errors.append("throughput does not match useful completions and duration")
    if cell["rate"]:
        offered, missed = cell["rate"]*cell["duration"], load["missed_requests"]
        first, last = load.get("first_missed_slot"), load.get("last_missed_slot")
        if load["scheduled_requests"] != load["total_requests"] or load["cohort_scheduled_requests"] != load["cohort_requests"]:
            errors.append("scheduled successful histograms do not conserve completions and drains")
        if (load["offered_requests"] != offered or load["missed_slot_count"] != missed
                or load["missed_reservations"]+load["unclaimed_requests"] != missed
                or load["admitted_requests"]+missed != offered):
            errors.append("fixed offered/missed count accounting incorrect")
        if missed == 0:
            if first is not None or last is not None:
                errors.append("zero misses with nonempty missed range")
        elif not (type(first) is int and type(last) is int and 0 <= first <= last < offered
                  and missed <= last-first+1 and (missed != 1 or first == last)):
            errors.append("invalid missed-slot ordinal bounds")
    elif (any(load[key] != 0 for key in ("scheduled_requests", "cohort_scheduled_requests", "offered_requests",
                                        "missed_requests", "missed_slot_count", "missed_reservations", "unclaimed_requests"))
          or load.get("first_missed_slot") is not None or load.get("last_missed_slot") is not None):
        errors.append("saturated mode must not contain scheduled requests or missed slots")
    return errors


def validate(cell, load, resource, *, require_zero_errors=True):
    errors = validate_observation(cell, load, resource)
    if not require_zero_errors or not isinstance(load, dict):
        return errors
    if any(type(load.get(key)) is not int or load[key] < 0 for key in COUNT_KEYS):
        return errors
    if load["warmup_errors"] != 0:
        errors.append("warmup errors or missing evidence")
    if load["total_errors"] != 0 or load["total_requests"] <= 0:
        errors.append("errors or no useful completions")
    missed = load["missed_requests"]
    if cell["rate"] and missed:
        first, last = load.get("first_missed_slot"), load.get("last_missed_slot")
        if not (0 < missed <= 2 and type(first) is int and type(last) is int
                and 0 <= first <= last < cell["rate"]*cell["duration"]
                and first*1000000000 >= (cell["duration"]*1000000000-1000000)*cell["rate"]):
            errors.append("fixed schedule lost a slot outside the bounded final-1ms qualification")
    return errors


def cell_paths(cell):
    directory = ROOT/cell["arm"]/cell["load"]/f"run_{cell['repetition']}"/f"payload_{cell['payload']}"
    name = f"{physical(cell['arm'])}_http1_{cell['payload']}"
    return directory, directory/f"{name}.json", directory/f"{name}.resources.json"


def fraction(numerator, denominator):
    return numerator/denominator if denominator else None


def read_json(path):
    def invalid_constant(value):
        raise ValueError(f"nonfinite JSON constant {value}")
    return json.loads(path.read_text(), parse_constant=invalid_constant)


def observed_metrics(cell, load, resource):
    """All errors remain counted; successful drains do not increase goodput."""
    outcomes = load["cohort_requests"]+load["warmup_requests"]+load["total_errors"]
    result = {key: load[key] for key in COUNT_KEYS}
    result.update(rps=load["rps"], goodput_rps=load["rps"],
        cpu_us_per_completion=resource["proxy_cpu_seconds"]*1e6/load["total_requests"] if load["total_requests"] else None,
        total_attempt_outcomes=outcomes, total_error_rate=fraction(load["total_errors"], outcomes),
        admitted_error_rate=fraction(load["admitted_errors"], load["admitted_requests"]),
        warmup_error_rate=fraction(load["warmup_errors"], load["warmup_requests"]+load["warmup_errors"]),
        admission_miss_rate=fraction(load["missed_requests"], load["offered_requests"]),
        nonadmitted_nonwarmup_errors=load["total_errors"]-load["admitted_errors"]-load["warmup_errors"])
    for key in TAIL_KEYS:
        count = load["cohort_scheduled_requests"] if key.startswith("cohort_scheduled_") else load["cohort_requests"]
        result[key] = load[key] if count else None
    for key in ("admission_delay_p99_us", "admission_delay_max_us"):
        result[key] = load[key] if cell["rate"] and load["admitted_requests"] else None
    return result


def read_cell(cell, runner_exit_code=None):
    directory, load_path, resource_path = cell_paths(cell)
    reports, read_errors = {}, []
    for name, path in (("report", load_path), ("resources", resource_path)):
        try:
            reports[name] = read_json(path)
        except (OSError, ValueError) as error:
            reports[name] = None
            read_errors.append(f"{path.name}: {error}")
    load, resource = reports["report"], reports["resources"]
    saved = directory/"cell-classification.json"
    if runner_exit_code is None and saved.exists():
        try:
            previous = read_json(saved)
            if any(previous.get(key) != value for key, value in cell.items()):
                raise ValueError("saved classification does not match planned metadata")
            runner_exit_code = previous["runner_exit_code"]
        except (OSError, ValueError, TypeError, KeyError) as error:
            read_errors.append(f"cell-classification.json: {error}")
    if runner_exit_code is not None:
        ordinary_failure = (isinstance(load, dict) and type(load.get("total_errors")) is int
                            and (load["total_errors"] > 0 or load.get("total_requests") == 0))
        if type(runner_exit_code) is not int or not (runner_exit_code == 0 or runner_exit_code == 1 and ordinary_failure):
            read_errors.append("runner failure is not an ordinary error/no-completion load result")
    measurement_errors = read_errors + validate_observation(cell, load, resource)
    capacity_errors = read_errors + validate(cell, load, resource)
    metrics = observed_metrics(cell, load, resource) if not measurement_errors else None
    has_errors = isinstance(load, dict) and type(load.get("total_errors")) is int and load["total_errors"] > 0
    misses = load.get("missed_requests") if isinstance(load, dict) else None
    classification = ("harness_or_evidence_fault" if measurement_errors else "observed_end_to_end_errors" if has_errors
                      else "observed_admission_loss" if misses else "zero_error_capacity_qualified")
    row = {**cell, **reports, "measurement_valid": not measurement_errors, "measurement_errors": measurement_errors,
           "valid": not capacity_errors, "zero_error_capacity_qualified": not capacity_errors,
           "zero_error_observation": not measurement_errors and load["total_errors"] == 0,
           "capacity_errors": capacity_errors, "strict_zero_miss": not capacity_errors and misses == 0,
           "classification": classification, "end_to_end_errors_observed": has_errors,
           "observed_metrics": metrics, "cpu_us_per_completion": metrics["cpu_us_per_completion"] if metrics else None,
           "report_paths": {"load": str(load_path), "resources": str(resource_path)}}
    # Preserve any full raw report that the cell runner backed up before
    # replacing its canonical file with a failure stub; it cannot qualify it.
    failed = load_path.with_name(load_path.stem + ".failed-output.json")
    if failed.exists():
        try:
            row["failed_report"] = read_json(failed)
        except (OSError, ValueError) as error:
            row["failed_report_error"] = str(error)
    return row


def metric_summary(values):
    # Never drop a failed/undefined repetition to manufacture favorable stats.
    defined = all(finite_number(value) for value in values)
    return {"median": statistics.median(values) if defined else None,
            "min": min(values) if defined else None, "max": max(values) if defined else None,
            "all": values, "defined_repetitions": sum(finite_number(value) for value in values)}


def summarize():
    planned = json.loads((ROOT/"production-plan.json").read_text())
    rows = [read_cell(cell) for cell in planned]
    errors = [{"cell": cell, "errors": row["capacity_errors"]} for cell, row in zip(planned, rows) if not row["valid"]]
    measurement_errors = [{"cell": cell, "errors": row["measurement_errors"]} for cell, row in zip(planned, rows) if not row["measurement_valid"]]
    groups = []
    for arm in ARMS:
        for payload in (1024,1048576):
            for mode in ("saturated", "fixed"):
                subset = [row for row in rows if row["arm"] == arm and row["payload"] == payload and row["load"] == mode]
                if not subset:
                    continue
                all_measured = all(row["measurement_valid"] for row in subset)
                metrics = None
                if all_measured:
                    keys = subset[0]["observed_metrics"]
                    metrics = {key: metric_summary([row["observed_metrics"][key] for row in subset]) for key in keys}
                groups.append({"arm": arm, "payload": payload, "load": mode, "repetitions": len(subset),
                    "planned_repetitions": len(subset),
                    "parsed_repetitions": sum(isinstance(row["report"], dict) and isinstance(row["resources"], dict) for row in subset),
                    "measurement_valid_repetitions": sum(row["measurement_valid"] for row in subset),
                    "zero_error_repetitions": sum(row["zero_error_observation"] for row in subset),
                    "capacity_qualified_repetitions": sum(row["zero_error_capacity_qualified"] for row in subset),
                    "end_to_end_error_repetitions": sum(row["end_to_end_errors_observed"] for row in subset),
                    "all_valid": all(row["valid"] for row in subset), "all_measurement_valid": all_measured,
                    "metrics": metrics,
                    "observations": [{key: row[key] for key in ("repetition", "measurement_valid", "measurement_errors", "zero_error_capacity_qualified", "capacity_errors", "classification", "observed_metrics")} for row in subset]})
    result = {"planned_cells": len(planned), "parsed_cells": sum(isinstance(row["report"], dict) and isinstance(row["resources"], dict) for row in rows),
              "measurement_valid_cells": sum(row["measurement_valid"] for row in rows),
              "zero_error_cells": sum(row["zero_error_observation"] for row in rows),
              "zero_error_capacity_cells": sum(row["zero_error_capacity_qualified"] for row in rows),
              "measurement_valid": not measurement_errors, "measurement_errors": measurement_errors,
              "errors": errors, "groups": groups, "cells": rows, "valid": not errors,
              "strict_zero_miss_valid": not errors and all(row["strict_zero_miss"] for row in rows),
              "error_rate_denominators": {"total_error_rate": "total_errors / (cohort_requests + warmup_requests + total_errors); includes warmup/setup and drains",
                  "admitted_error_rate": "admitted_errors / admitted_requests; includes failed admitted drains",
                  "warmup_error_rate": "warmup_errors / (warmup_requests + warmup_errors)",
                  "admission_miss_rate": "missed_requests / offered_requests; undefined for saturated mode"},
              "fixed_admission_losses": [{"cell": {key: row[key] for key in ("arm", "payload", "load", "repetition")},
                  "offered": row["report"].get("offered_requests"), "missed": row["report"].get("missed_requests"),
                  "loss_fraction": fraction(row["report"]["missed_requests"], row["report"]["offered_requests"])
                      if all(type(row["report"].get(key)) is int and row["report"][key] >= 0 for key in ("missed_requests", "offered_requests")) else None,
                  "measurement_valid": row["measurement_valid"], "zero_error_capacity_qualified": row["zero_error_capacity_qualified"]}
                  for row in rows if row["load"] == "fixed" and isinstance(row["report"], dict)]}
    (ROOT/"production-summary.json").write_text(json.dumps(result, indent=2, allow_nan=False)+"\n")
    text = ["Production mesh campaign", "", f"Planned: {len(planned)}; parsed: {result['parsed_cells']}; measurement-valid: {result['measurement_valid_cells']}; zero-error capacity-qualified: {result['zero_error_capacity_cells']}.",
        f"Strict zero-missed-arrival result: {result['strict_zero_miss_valid']}.",
        "Telemetry scope: access logging disabled, native operational counters enabled. Full identity-bound workload telemetry is UNQUALIFIED; localized Ferrum configuration lacks an exporter and captured-egress Prometheus hooks are omitted. Destination CONNECT uses HTTP telemetry families. No full feature parity claim.",
        "All planned outcomes and repetitions retained. End-to-end error observations have unattributed cause; they contribute observed goodput and error rates but fail the zero-error capacity SLO. Undefined successful-cohort tails or CPU/completion remain undefined, including in group statistics.",
        "L4 and L7 are separate product paths with different network placement; cross-layer differences do not isolate HTTP overhead. Fixed scheduled latency includes admission delay. Up to two missed arrivals are capacity-qualified only with ordinal proof that every missed due time was in the final 1 ms; all misses remain reported without assigning a timer cause.",
        "Total error fraction includes warmup/setup and drains; admitted error fraction is admitted_errors/admitted_requests. Goodput counts only successful completions inside the measurement interval.", "",
        "| Arm | Bytes | Load | Planned/parsed/measured/zero-error/capacity N | Capacity SLO | Goodput RPS median | successful cohort p50/p95/p99 us (fixed: scheduled; saturated: service) | CPU us/completion | Total errors (all reps) | Admitted error fractions (all reps) | Missed arrivals (all reps) |",
        "|---|---:|---|---|---|---:|---|---:|---|---|---|"]
    for group in groups:
        m = group["metrics"]
        counts = "/".join(str(group[key]) for key in ("planned_repetitions", "parsed_repetitions", "measurement_valid_repetitions", "zero_error_repetitions", "capacity_qualified_repetitions"))
        if m is None:
            text.append(f"| {group['arm']} | {group['payload']} | {group['load']} | {counts} | HARNESS/EVIDENCE FAULT | INVALID | undefined | undefined | retained in cell records | retained | retained |")
            continue
        tail_keys = TAIL_KEYS[3:] if group["load"] == "fixed" else TAIL_KEYS[:3]
        tails = "/".join(f"{m[key]['median']:g}" if m[key]["median"] is not None else "undefined" for key in tail_keys)
        cpu = m["cpu_us_per_completion"]["median"]
        text.append(f"| {group['arm']} | {group['payload']} | {group['load']} | {counts} | {'PASS' if group['all_valid'] else 'FAIL'} | {m['goodput_rps']['median']:.1f} | {tails} | {cpu if cpu is not None else 'undefined'} | {m['total_errors']['all']} | {m['admitted_error_rate']['all']} | {m['missed_requests']['all']} |")
    if errors:
        text += ["", "Capacity-unqualified or missing cells (raw observations retained):", json.dumps(errors, indent=2)]
    (ROOT/"production-summary.md").write_text("\n".join(text)+"\n")
    print("\n".join(text))
    return 0 if result["valid"] else 1


def classify_planned(args):
    candidate = {key: getattr(args, key) for key in ("arm", "payload", "repetition", "load", "duration", "rate")}
    planned = json.loads((ROOT/"production-plan.json").read_text())
    matches = [cell for cell in planned if cell == candidate]
    if len(matches) != 1:
        raise ValueError("classification requires exactly one matching planned cell")
    row = read_cell(matches[0], runner_exit_code=args.runner_exit_code)
    classification = {key: value for key, value in row.items() if key not in ("report", "resources", "failed_report")}
    classification["runner_exit_code"] = args.runner_exit_code
    classification["continue_ranking"] = row["measurement_valid"] and args.runner_exit_code in (0, 1)
    directory, _, _ = cell_paths(matches[0])
    directory.mkdir(parents=True, exist_ok=True)
    (directory/"cell-classification.json").write_text(json.dumps(classification, indent=2, allow_nan=False)+"\n")
    print(json.dumps(classification, allow_nan=False))
    accepted = row["measurement_valid"] if args.measurement_only else row["valid"]
    return 0 if accepted and args.runner_exit_code in (0, 1) else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["provenance", "plan", "summarize", "accept", "classify"])
    parser.add_argument("--arm", choices=ARMS)
    parser.add_argument("--payload", type=int)
    parser.add_argument("--repetition", type=int)
    parser.add_argument("--load", choices=["fixed", "saturated"])
    parser.add_argument("--duration", type=int)
    parser.add_argument("--rate", type=int)
    parser.add_argument("--runner-exit-code", type=int, default=0)
    parser.add_argument("--measurement-only", action="store_true")
    args = parser.parse_args()
    ROOT.mkdir(exist_ok=True)
    if args.action == "provenance":
        provenance()
    elif args.action == "plan":
        cells = plan(os.environ.get("BENCH_PHASE", "smoke-l7"))
        (ROOT/"production-plan.json").write_text(json.dumps(cells, indent=2)+"\n")
        (ROOT/"production-plan.txt").write_text("".join(" ".join(str(cell[key]) for key in ("arm", "payload", "repetition", "load", "duration", "rate"))+"\n" for cell in cells))
    elif args.action == "summarize":
        return summarize()
    elif args.action == "classify":
        return classify_planned(args)
    else:
        return 0 if json.loads((ROOT/"production-summary.json").read_text())["valid"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
