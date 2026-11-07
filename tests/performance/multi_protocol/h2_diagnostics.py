"""Bounded H2 campaign observations; no packet/header/body capture or subprocesses."""

import json
import math
import re
import sys
import time
import urllib.request
from pathlib import Path


_LOG_SINK_GAUGE_RE = re.compile(
    r'ferrum_log_sink_(healthy|queued_records|queued_bytes|reserved_bytes|'
    r'shutdown_timeouts_total|shutdown_incomplete_records_total)'
    r'\{sink="(stdout|stderr)"\} ([0-9]+)'
)
_LOG_SINK_IO_FAILURE_RE = re.compile(
    r'ferrum_log_sink_io_failures_total\{sink="(stdout|stderr)",'
    r'operation="(write|flush)"\} ([0-9]+)'
)
_LOG_SINK_DROPPED_RE = re.compile(
    r'ferrum_log_sink_dropped_records_total\{sink="(stdout|stderr)",'
    r'reason="(saturation|record_too_large|closed)"\} ([0-9]+)'
)
_RUNTIME_GAUGE_RE = re.compile(
    r'(ferrum_connection_pool_entries|ferrum_overload_active_connections|'
    r'ferrum_overload_active_requests)(\{[^}]*\})? ([0-9.eE+-]+)'
)
_POOL_LABEL_RE = re.compile(r'(?:\{|,)pool="(http2|grpc)"(?:,|\})')


def parse_gauges(text):
    values = {}
    for line in text.splitlines():
        health = _LOG_SINK_GAUGE_RE.fullmatch(line)
        io = _LOG_SINK_IO_FAILURE_RE.fullmatch(line)
        if health or io:
            key = ("log_" + health[2] + "_" + health[1] if health
                   else "log_" + io[1] + "_io_" + io[2])
            if key in values:
                raise ValueError("duplicate log health counter")
            values[key] = int(health[3] if health else io[3])
            continue
        loss = _LOG_SINK_DROPPED_RE.fullmatch(line)
        if loss:
            key = "log_dropped_" + loss[1] + "_" + loss[2]
            if key in values:
                raise ValueError("duplicate log loss counter")
            values[key] = int(loss[3])
            continue
        match = _RUNTIME_GAUGE_RE.fullmatch(line)
        if not match:
            continue
        name, labels, value = match.groups()
        if name == "ferrum_connection_pool_entries":
            pool = _POOL_LABEL_RE.search(labels or "")
            if not pool:
                continue
            key = "resident_" + pool[1] + "_pool_entries"
        else:
            key = name.removeprefix("ferrum_overload_")
        number = float(value)
        if key in values or not math.isfinite(number) or number < 0:
            raise ValueError("ambiguous or invalid gauge")
        values[key] = number
    if not {"resident_http2_pool_entries", "resident_grpc_pool_entries", "active_connections"} <= values.keys():
        raise ValueError("required H2 campaign gauges missing")
    return values


def snapshot():
    row = dict(unix_secs=time.time(), monotonic_secs=time.monotonic())
    try:
        # The campaign grants only loopback metrics access on its disposable VM.
        with urllib.request.urlopen("http://127.0.0.1:9000/metrics", timeout=0.2) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("metrics response exceeded observation bound")
        row["gauges"] = parse_gauges(raw.decode("utf-8"))
    except (OSError, ValueError) as error:
        row["error"] = type(error).__name__
    row["capture_secs"] = time.time() - row["unix_secs"]
    return row


def event_phase(unix_secs, phases):
    """Same phase names as TransportEvent; cross-process wall-clock correlation."""
    origin = phases.get("setup_start_unix_secs")
    epoch = phases.get("setup_start_monotonic_secs")
    if origin is None or epoch is None:
        return "unknown"
    at = unix_secs - origin + epoch
    close = phases.get("transport_close_start_monotonic_secs")
    measure = phases.get("measurement_start_monotonic_secs")
    drain = phases.get("drain_start_monotonic_secs")
    warmup = phases.get("warmup_start_monotonic_secs")
    if close is not None and at >= close:
        return "transport_close"
    if ((measure is not None and at >= measure + phases["measurement_secs"])
            or (drain is not None and at >= drain)):
        return "drain"
    if measure is not None and at >= measure:
        return "measurement"
    if warmup is not None and at >= warmup:
        return "warmup"
    return "setup"


def annotate(sample, usage, backend_log):
    phases = sample.get("phases") or {}
    start = phases.get("measurement_start_unix_secs")
    end = start + phases["measurement_secs"] if start is not None else None
    rows = [row["h2_gauges"] for row in usage.get("timeline", []) if "h2_gauges" in row]
    measured = [row for row in rows if start is not None and start <= row["unix_secs"] < end]
    observations = dict(configured_pool_shards=16 if sample["gateway"] != "direct" else None,
                        gauge_samples=measured, backend_events=[], capture_errors=[],
                        backend_phase_clock="cross_process_unix; clock skew not measured",
                        pool_gauge_scope="resident cached transports, not busy streams or configured shards",
                        tonic_driver_result_available=False)
    if sample["gateway"] != "direct":
        observations["gauges_available"] = bool(measured) and all("gauges" in row for row in measured)
    else:
        observations["gauges_available"] = None
    for line in backend_log.splitlines():
        if line.startswith("H2_TRANSPORT "):
            try:
                event = json.loads(line.removeprefix("H2_TRANSPORT "))
                if event["unix_secs"] >= phases.get("setup_start_unix_secs", float("inf")):
                    event["phase"] = event_phase(event["unix_secs"], phases)
                    observations["backend_events"].append(event)
            except (ValueError, KeyError, TypeError):
                if "malformed_backend_event" not in observations["capture_errors"]:
                    observations["capture_errors"].append("malformed_backend_event")
        elif line.startswith("H2_OBSERVATION_LIMIT "):
            observations["backend_log_limit_reached"] = True
    sample["h2_observation"] = observations
    observations["backend_errors_observed"] = sum(bool(event.get("detail"))
                                                   for event in observations["backend_events"])


if __name__ == "__main__":
    path, usage_path, backend_path = map(Path, sys.argv[1:])
    sample = json.loads(path.read_text())
    errors = []
    try:
        usage = json.loads(usage_path.read_text())
    except (OSError, ValueError):
        usage = {}
        errors.append("missing_or_malformed_process_capture")
    try:
        backend = backend_path.read_text()
    except (OSError, ValueError):
        backend = ""
        errors.append("missing_backend_capture")
    annotate(sample, usage, backend)
    sample["h2_observation"]["capture_errors"].extend(errors)
    path.write_text(json.dumps(sample, indent=2) + "\n")
