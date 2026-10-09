"""Validity rules shared by the protocol summaries and combined scoreboard.

Retain failed observations for diagnosis; never select only the clean iterations
of a flaky competitor to manufacture an error-free mean.
"""

import json
import math


def _is_number(value):
    """`bool` is a subclass of `int`; a JSON `true` is not a measurement."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def sample_issues(sample):
    issues = []
    if not isinstance(sample, dict):
        return ["invalid sample object"]
    if "h2_cpu_profile" in sample:
        issues.append("H2 CPU profiling campaign: diagnostic only")
    if "samples" in sample:
        children = sample["samples"]
        expected = sample.get("expected_pairs")
        if (not isinstance(children, list) or not isinstance(expected, int)
                or isinstance(expected, bool) or expected < 2 or expected % 2
                or len(children) != expected):
            issues.append("incomplete paired samples")
        elif any(not isinstance(child, dict) or "samples" in child for child in children):
            issues.append("invalid nested sample")
        else:
            if [child.get("pair") for child in children] != list(range(1, expected + 1)):
                issues.append("missing/duplicate/out-of-order pair IDs")
            for index, child in enumerate(children, 1):
                issues.extend(f"pair {index}: {issue}" for issue in sample_issues(child))
    elif sample.get("sample_schema") == 2:
        phases = sample.get("phases") or {}
        observed = sample.get("observed") or {}
        if not isinstance(phases, dict) or not isinstance(observed, dict):
            issues.append("invalid phase/concurrency record")
        else:
            duration = phases.get("measurement_secs")
            elapsed = phases.get("measurement_elapsed_secs")
            if (not _is_number(duration) or not math.isfinite(duration) or duration <= 0
                    or duration != sample.get("duration_secs") or phases.get("timed_out")
                    or not _is_number(elapsed) or not math.isfinite(elapsed)
                    or not duration <= elapsed <= duration + max(0.1, duration * 0.05)):
                issues.append("invalid/incomplete measurement phase")
            count = observed.get("samples")
            if (not isinstance(count, int) or isinstance(count, bool) or count <= 0
                    or observed.get("workers_retired_before_deadline") != 0):
                issues.append("missing observations or retired workers")
            for name in ("active_workers", "active_connections", "active_streams", "queued_requests"):
                gauge = observed.get(name)
                if (not isinstance(gauge, dict)
                        or any(not _is_number(gauge.get(field))
                               or not math.isfinite(gauge[field]) for field in ("min", "max", "mean"))
                        or not 0 <= gauge["min"] <= gauge["mean"] <= gauge["max"]):
                    issues.append(f"missing/invalid observed {name}")
            if (observed.get("workers_at_barrier") != sample.get("effective_concurrency")
                    or sample.get("warmup_requests") != sample.get("effective_concurrency")):
                issues.append("incomplete setup/warmup barrier")
        usage = sample.get("process_usage") or {}
        if (not isinstance(usage, dict) or usage.get("error") or usage.get("available") is False
                or not isinstance(usage.get("processes"), list) or not usage["processes"]):
            issues.append("missing per-process resource capture")
        else:
            # missing_pids were never observable: preserve them diagnostically,
            # but require continuous live evidence for each role below.
            measurement = usage.get("measurement")
            measurement = measurement if isinstance(measurement, list) else []
            roles = {process.get("role") for process in measurement if isinstance(process, dict)}
            required = {"client", "backend"}
            if sample.get("gateway") != "direct":
                required.add("gateway")
            if not required <= roles:
                issues.append("missing process roles")
            for role in sorted(required):
                records = [p for p in measurement if isinstance(p, dict) and p.get("role") == role]
                if not records or any(
                        p.get("complete_bracket") is not True
                        or not _is_number(p.get("cpu_seconds"))
                        or not math.isfinite(p["cpu_seconds"]) or p["cpu_seconds"] < 0
                        for p in records):
                    issues.append(f"incomplete {role} measurement bracket")
    if sample.get("error"):
        issues.append(str(sample["error"]))
    if sample.get("h2_guard_observation"):
        issues.append("instrumented H2 guard build: diagnostic only")
    if sample.get("h2_observation"):
        observation = sample["h2_observation"]
        phases = sample.get("phases") or {}
        if sample.get("gateway") != "direct" and observation.get("gauges_available") is not True:
            issues.append("missing H2 pool/connection observations")
        if phases.get("transport_errors_total", 0) or phases.get("transport_close_timed_out"):
            issues.append("H2 transport errors or incomplete driver observation")
        if observation.get("capture_errors") or observation.get("backend_errors_observed"):
            issues.append("H2 backend errors or incomplete diagnostic capture")
        if phases.get("transport_events_suppressed", 0) or observation.get("backend_log_limit_reached"):
            issues.append("truncated H2 transport observations")
    if sample.get("h3_experiment"):
        transport = sample.get("transport_diagnostics") or {}
        if transport.get("complete_bracket") is not True:
            issues.append("incomplete H3 transport observations")
        if transport.get("equal_socket_budget_verified") is not True:
            issues.append("H3 socket budget parity unverified")
    errors = sample.get("total_errors")
    if not isinstance(errors, int) or isinstance(errors, bool) or errors < 0:
        issues.append("missing/invalid error count")
    elif errors:
        issues.append(f"{errors} errors")
    requests = sample.get("total_requests")
    if not isinstance(requests, int) or isinstance(requests, bool) or requests <= 0:
        issues.append("no successful requests")
    else:
        size = sample.get("payload_size")
        if not isinstance(size, int) or size <= 0 or sample.get("total_bytes") != requests * size:
            issues.append("echo byte accounting mismatch")
    rps = sample.get("rps")
    if not _is_number(rps) or not math.isfinite(rps) or rps <= 0:
        issues.append("non-positive/invalid throughput")
    return issues


def bucket_issues(samples, expected_iterations):
    issues = []
    if len(samples) != expected_iterations:
        issues.append(f"{len(samples)}/{expected_iterations} iterations")
    for iteration, sample in enumerate(samples, 1):
        issues.extend(f"run {iteration}: {issue}" for issue in sample_issues(sample))
    return issues


def throughput_value(sample):
    """Keep malformed/non-finite measurements out of display arithmetic too."""
    value = sample.get("rps")
    return float(value) if _is_number(value) and math.isfinite(value) and value > 0 else 0.0


def expected_rows(run_directory):
    """New runs record the plan before startup, including gateways that fail.

    Return ``None`` when the plan is unavailable so callers can retain observed
    rows for diagnosis without treating them as a complete benchmark matrix.
    """
    manifest = run_directory / "manifest.json"
    try:
        plan = json.loads(manifest.read_text())
        gateways = plan["gateways"]
        sizes = plan["payload_sizes"]
        if not isinstance(gateways, list) or not all(
                isinstance(gateway, str) and gateway for gateway in gateways):
            raise ValueError("invalid gateway plan")
        if not isinstance(sizes, list) or not all(
                isinstance(size, int) and not isinstance(size, bool) and size > 0
                for size in sizes):
            raise ValueError("invalid payload-size plan")
    except (OSError, ValueError, TypeError, KeyError):
        return None
    return [(gateway, size) for gateway in gateways for size in sizes]
