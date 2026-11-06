"""Read the diagnostic h2 crate's fixed numeric messages from Ferrum JSON logs.

IDs are local to one gateway process. Cumulative counters include earlier
payloads; phase annotation is of emission time, never a per-frame timeline.
"""
from datetime import datetime
import json
import math
from pathlib import Path
import re
import sys

from h2_diagnostics import event_phase

FIELDS = """seq cid role event branch reason initial_max initial_available max available empty
send recv error_resets remote_resets initial_target target peak_target target_updates
initial_stream stream_window stream_updates wire_window byte_available in_flight frames bytes
zero small medium large final queued ignored_reset ignored_release empty_unqueued rejected
untracked polled cleared returned_credit last_stream trigger_stream last_len last_flow last_end disposition
suppressed_connections suppressed_lifecycle suppressed_failures generation transitions tail_len wraps
overwritten overflow pending high_pending min_credit epoch memory_overflow""".split()
TAIL_FIELDS = "seq cid snapshot generation n epoch kind stream len flow end disposition consume before after delta pending target wire byte_available in_flight stream_window".split()
FENCE_FIELDS = "seq generation registered captured retired missed changed registry_loss memory_overflow suppressed closed ack".split()
MAX_RECORDS = (128 + 8) * 1024 * 1024 // 4096 + 3 * 64 + 16
MAX_BYTES = 144 * 1024 * 1024
BRANCHES = {0: "none", 1: "small_nonfinal_credit", 2: "empty_nonfinal_lifetime",
            3: "send_internal_reset_limit", 4: "recv_internal_reset_limit",
            5: "pending_accept_remote_reset_limit"}
GATEWAYS = ("direct", "ferrum", "ferrum-exp-fixed")
PROTOCOLS = {"http2": "HTTP/2", "grpcs": "gRPC"}


_SIGNED_INT_RE = re.compile(r"-?[0-9]{1,20}")


def finite_time(value):
    return type(value) in (int, float) and 0 <= value < 1e12 and math.isfinite(value)


def matches_fields(value, expected):
    return isinstance(value, dict) and all(
        key in value and type(value[key]) is type(want) and value[key] == want for key, want in expected.items())


def manifest_problems(manifest, protocol):
    sizes = [71680] if protocol == "http2" else [10240, 71680]
    if (not matches_fields(manifest, dict(sample_schema=2, pairs=4, h2_observation_enabled=True))
            or manifest.get("gateways") != list(GATEWAYS)
            or manifest.get("payload_sizes") != sizes
            or any(type(size) is not int for size in manifest.get("payload_sizes", []))
            or not isinstance(manifest.get("host_id"), str) or not manifest["host_id"].strip()):
        return ["missing_or_malformed_campaign_manifest"]
    return []


def expected_sample(manifest, protocol, pair, gateway, size):
    return dict(sample_schema=2, host_id=manifest.get("host_id"), pair=pair,
                gateway=gateway, protocol=PROTOCOLS[protocol], payload_size=size,
                concurrency=200, effective_concurrency=200, duration_secs=15)


def sample_problems(sample, expected):
    errors = []
    if not expected or not matches_fields(sample, expected):
        errors.append("sample_identity_or_workload_mismatch")
    if (not isinstance(sample.get("host_id"), str) or not sample["host_id"].strip()
            or type(sample.get("pair")) is not int or not 1 <= sample["pair"] <= 4
            or sample.get("gateway") not in GATEWAYS
            or sample.get("protocol") not in PROTOCOLS.values()
            or not matches_fields(sample, dict(sample_schema=2, concurrency=200,
                                               effective_concurrency=200, duration_secs=15))
            or type(sample.get("payload_size")) is not int
            or sample["payload_size"] not in ([71680] if sample.get("protocol") == "HTTP/2"
                                             else [10240, 71680])):
        errors.append("invalid_sample_identity_or_workload")
    return errors


def capture_identity(sample):
    return {key: sample.get(key) for key in ("host_id", "pair", "gateway", "protocol", "payload_size")}


def phase_interval(sample):
    """Require real PhaseReport fields; no invented gRPC close timestamp."""
    phases = sample["phases"]
    times = ("setup_start_unix_secs", "measurement_start_unix_secs",
             "setup_start_monotonic_secs", "warmup_start_monotonic_secs",
             "measurement_start_monotonic_secs", "drain_start_monotonic_secs",
             "setup_secs", "warmup_secs", "barrier_secs", "measurement_secs",
             "measurement_elapsed_secs", "drain_secs", "transport_close_secs")
    if not isinstance(phases, dict) or any(not finite_time(phases.get(key)) for key in times):
        raise ValueError("missing or invalid phase timing")
    setup, warmup, measure, drain = (phases[key + "_start_monotonic_secs"]
                                     for key in ("setup", "warmup", "measurement", "drain"))
    if (not setup <= warmup <= measure <= drain or phases["measurement_secs"] != 15
            or phases["measurement_elapsed_secs"] < 15 or drain < measure + 15
            or phases["setup_start_unix_secs"] > phases["measurement_start_unix_secs"]
            or any(type(phases.get(key)) is not bool for key in ("timed_out", "transport_close_timed_out"))):
        raise ValueError("unordered or incomplete phases")
    end = drain + phases["drain_secs"]
    close = phases["transport_close_start_monotonic_secs"]
    if sample.get("protocol") == "HTTP/2" or close is not None:
        if not finite_time(close) or close < end:
            raise ValueError("invalid transport close timing")
        end = close + phases["transport_close_secs"]
    elif phases["transport_close_secs"] != 0:
        raise ValueError("close duration without start")
    # The monotonic epoch is client-local. Anchor the elapsed tail to the
    # client's own measurement wall time, never a gateway/frame timestamp.
    return phases["setup_start_unix_secs"], phases["measurement_start_unix_secs"] + end - measure


def capture_range(record):
    if (not matches_fields(record, dict(schema=2))
            or not all(finite_time(record.get(key)) for key in ("start_unix_secs", "end_unix_secs"))
            or record["start_unix_secs"] > record["end_unix_secs"]):
        raise ValueError("invalid capture range")
    return record["start_unix_secs"], record["end_unix_secs"]


def boundary_range(boundary):
    start, end = capture_range(boundary)
    if (not isinstance(boundary.get("errors"), list)
            or not all(isinstance(error, str) for error in boundary["errors"])
            or not isinstance(boundary.get("sink_samples"), list) or not 1 <= len(boundary["sink_samples"]) <= 6):
        raise ValueError("invalid boundary samples")
    previous = start
    for sink in boundary["sink_samples"]:
        if (not isinstance(sink, dict) or not finite_time(sink.get("unix_secs"))
                or not previous <= sink["unix_secs"] <= end):
            raise ValueError("sink sample outside boundary")
        previous = sink["unix_secs"]
    return start, end


def numeric_fields(pairs, names):
    if len(pairs) != len(names):
        raise ValueError("wrong field count")
    row = {}
    for name, pair in zip(names, pairs):
        key, eq, value = pair.partition("=")
        if key != name or eq != "=" or not _SIGNED_INT_RE.fullmatch(value):
            raise ValueError("invalid fixed guard field")
        number = int(value)
        if number > 2**64 - 1 or number < -(2**63) or (number < 0 and name != "byte_available"):
            raise ValueError("invalid guard counter")
        row[name] = number
    return row


def validate_fence(row):
    if (not 1 <= row["seq"] <= MAX_RECORDS or not 1 <= row["generation"] <= 16 or row["registered"] > 64
            or row["captured"] + row["retired"] + row["missed"] != row["registered"]
            or row["changed"] not in (0, 1) or row["closed"] != 0 or row["ack"] != 1):
        raise ValueError("invalid snapshot fence")


def parse_ack(raw):
    prefix = "# H2_GUARD_ACK_V2 "
    if not isinstance(raw, str) or not raw.startswith(prefix):
        raise ValueError("invalid snapshot acknowledgment")
    row = numeric_fields(raw[len(prefix):].split(" "), FENCE_FIELDS)
    validate_fence(row)
    return row


def sink_problems(gauges, drained=False):
    required = {f"log_dropped_{sink}_{reason}" for sink in ("stdout", "stderr")
                for reason in ("saturation", "record_too_large", "closed")}
    required |= {f"log_{sink}_{field}" for sink in ("stdout", "stderr") for field in (
        "healthy", "queued_records", "queued_bytes", "reserved_bytes", "shutdown_timeouts_total",
        "shutdown_incomplete_records_total", "io_write", "io_flush")}
    if not isinstance(gauges, dict) or not required <= gauges.keys():
        return ["missing_log_sink_health_counters"]
    errors = []
    for key in required:
        value = gauges[key]
        if type(value) is not int or value < 0:
            errors.append("invalid_log_sink_counter")
        elif key.endswith("_healthy"):
            if value != 1:
                errors.append("unhealthy_log_sink")
        elif key.endswith(("_queued_records", "_queued_bytes", "_reserved_bytes")):
            if drained and value != 0:
                errors.append("undrained_log_sink")
        elif value != 0:
            errors.append("log_sink_loss")
    return sorted(set(errors))


def validate_capture(result, sample, boundaries, seqs, invocation):
    errors = result["capture_errors"]
    interval = None
    try:
        interval = phase_interval(sample)
    except (ValueError, KeyError, TypeError):
        errors.append("missing_or_malformed_phases")
    invocation_range = None
    try:
        invocation_range = capture_range(invocation)
        if (not matches_fields(invocation.get("identity"), capture_identity(sample))
                or type(invocation.get("exit_code")) is not int or not 0 <= invocation["exit_code"] <= 255):
            raise ValueError("invocation identity or exit status")
        if interval and not invocation_range[0] <= interval[0] <= interval[1] <= invocation_range[1]:
            errors.append("phases_outside_client_invocation")
    except (ValueError, KeyError, TypeError):
        errors.append("missing_or_malformed_invocation")
    result["invocation"] = invocation
    summaries = {row["seq"]: row for row in result["events"]}
    tails = {}
    for row in sorted(result["transitions"], key=lambda r: r["seq"]):
        tails.setdefault(row["snapshot"], []).append(row)
        parent = summaries.get(row["snapshot"])
        if (not parent or parent["cid"] != row["cid"] or parent["generation"] != row["generation"]
                or parent["event"] not in (1, 3)):
            errors.append("orphan_transition")
    for seq, summary in summaries.items():
        tail = tails.get(seq, [])
        expected = list(range(summary["transitions"] - summary["tail_len"] + 1,
                              summary["transitions"] + 1)) if summary["tail_len"] else []
        if [row["n"] for row in tail] != expected:
            errors.append("missing_or_misordered_transition_tail")
        if tail and (tail[-1]["pending"] != summary["pending"]
                     or tail[-1]["after"] != summary["available"]
                     or tail[-1]["epoch"] != summary["epoch"]):
            errors.append("tail_summary_mismatch")
        for row in tail:
            expected_after = row["before"]
            if row["kind"] == 1 and row["consume"] == 1 and row["len"]:
                expected_after = (row["before"] - (256 - row["len"]) if row["len"] < 256
                                  else min(summary["max"], row["before"] + row["len"] - 256))
            elif row["kind"] in (2, 3) and row["consume"] == 1 and 0 < row["len"] < 256:
                expected_after = min(summary["max"], row["before"] + 256 - row["len"])
            if (row["after"] != expected_after or not 0 <= row["before"] <= summary["max"]
                    or not summary["min_credit"] <= row["after"] <= summary["max"]
                    or (row["kind"] == 1 and row["flow"] < row["len"])
                    or (row["kind"] == 1 and row["end"] and row["consume"] != 0)
                    or (row["kind"] == 1 and row["consume"] == 2 and row["len"] > 0
                        and not (row["len"] < 256 and row["before"] < 256 - row["len"]))):
                errors.append("transition_credit_mismatch")
        for previous, current in zip(tail, tail[1:]):
            delta = (1 if current["kind"] == 1 and current["disposition"] == 1 and current["end"] == 0
                     else -1 if current["kind"] in (2, 3) and current["consume"] == 1 else 0)
            if (current["before"] != previous["after"] or current["epoch"] < previous["epoch"]
                    or current["pending"] != previous["pending"] + delta
                    or current["epoch"] != previous["epoch"] + int(current["kind"] == 6)):
                errors.append("transition_order_or_accounting_mismatch")
        if summary["overflow"] or summary["memory_overflow"]:
            errors.append("observation_overflow")
    fences = {row["generation"]: row for row in result["fences"]}
    if len(fences) != len(result["fences"]):
        errors.append("duplicate_snapshot_generation")
    result["boundaries"] = boundaries
    generations = []
    ranges = {}
    for label in ("smoke", "before", "after"):
        boundary = boundaries.get(label, {})
        try:
            ranges[label] = boundary_range(boundary)
            identity = capture_identity(sample)
            if label == "smoke":
                identity["payload_size"] = 0  # One smoke per gateway process, before either payload.
            if not matches_fields(boundary.get("identity"), identity):
                raise ValueError("boundary identity")
            ack = parse_ack(boundary["raw_ack"])
            if not matches_fields(boundary["ack"], ack):
                raise ValueError("changed ack")
            generation = ack["generation"]
            generations.append(generation)
            fence = fences.get(generation)
            if label == "after":
                result["final_issued_sequence"] = ack["seq"]
                result["final_fence_delivered"] = bool(fence) and all(fence[key] == ack[key] for key in FENCE_FIELDS)
            if not fence or any(fence[key] != ack[key] for key in FENCE_FIELDS):
                errors.append("unacknowledged_snapshot_delivery:" + label)
            # Fence returned over HTTP detects lost LAST log records as well as gaps.
            if sum(seq <= ack["seq"] for seq in seqs) != ack["seq"]:
                errors.append("incomplete_snapshot_prefix:" + label)
            if any(ack[key] for key in ("missed", "changed", "registry_loss", "memory_overflow", "suppressed")):
                errors.append("partial_live_snapshot:" + label)
            live = [row for row in result["events"] if row["event"] == 3 and row["generation"] == generation]
            live_ids = {row["cid"] for row in live}
            active = set()
            for row in sorted(result["events"], key=lambda r: r["seq"]):
                if row["seq"] >= ack["seq"]:
                    continue
                if row["event"] == 0:
                    active.add(row["cid"])
                elif row["event"] == 2:
                    active.discard(row["cid"])
            if len(live) != ack["captured"] or len(live_ids) != len(live) or not live or not active <= live_ids:
                errors.append("missing_live_snapshot:" + label)
            if label == "after" and not any(row["role"] == 1 and row["frames"] > 0 for row in live):
                errors.append("missing_successful_or_fixed_live_traffic_state")
            if boundary["errors"]:
                errors.append("boundary_capture_error:" + label)
            for index, sink in enumerate(boundary["sink_samples"]):
                errors.extend(sink_problems(sink.get("gauges"), drained=index == len(boundary["sink_samples"]) - 1))
            if invocation_range and label == "before" and ranges[label][1] > invocation_range[0]:
                errors.append("late_before_snapshot")
            if invocation_range and label == "after" and ranges[label][0] < invocation_range[1]:
                errors.append("early_after_snapshot")
        except (ValueError, KeyError, TypeError, IndexError):
            errors.append("missing_or_malformed_boundary:" + label)
    if len(ranges) == 3 and not ranges["smoke"][1] <= ranges["before"][0] <= ranges["before"][1] <= ranges["after"][0]:
        errors.append("invalid_boundary_time_order")
    if len(generations) == 3 and not generations[0] < generations[1] < generations[2]:
        errors.append("invalid_boundary_generation_order")
    if len(generations) == 3:
        before = {row["cid"]: row["frames"] for row in result["events"]
                  if row["event"] == 3 and row["generation"] == generations[1] and row["role"] == 1}
        progress = {row["cid"]: row["frames"] - before.get(row["cid"], 0) for row in result["events"]
                    if row["event"] == 3 and row["generation"] == generations[2] and row["role"] == 1}
        result["live_client_frame_deltas"] = progress
        if not any(value > 0 for value in progress.values()) or any(value < 0 for value in progress.values()):
            errors.append("missing_live_client_progress")
    if result["suppression_observed"] or result["sink_loss_observed"]:
        errors.append("capture_loss")
    result["capture_errors"] = sorted(set(errors))
    result["bounded_capture_complete"] = not result["capture_errors"]
    result["capture_status"] = "acknowledged_bounded_snapshots" if result["bounded_capture_complete"] else "partial"
    retained = {}
    latest = {}
    for row in result["transitions"]:
        retained.setdefault(row["cid"], set()).add(row["n"])
    for row in result["events"]:
        latest[row["cid"]] = max(latest.get(row["cid"], 0), row["transitions"])
    result["full_transition_history_complete"] = (result["bounded_capture_complete"]
        and not any(row["overwritten"] for row in result["events"])
        and all(len(retained.get(cid, ())) == count for cid, count in latest.items()))
    result["process_capture_closed"] = False
    result["remaining_limits"] = ["no process shutdown acknowledgment", "no pool-family/cross-hop identity join"]
    if any(row["overwritten"] for row in result["events"]):
        result["remaining_limits"].append("transition ring overwrote earlier history; only retained tails are ordered")


def parse_line(line):
    if "H2_GUARD_" not in line:
        return None
    if len(line) > 8192:
        raise ValueError("oversized guard record")
    # docker logs --timestamps prefixes the existing JSON logging envelope.
    _, separator, envelope = line.partition(" ")
    record = json.loads(envelope if separator and not line.startswith("{") else line)
    if not isinstance(record, dict):
        raise ValueError("invalid log envelope")
    if record.get("target") != "ferrum_h2_guard":
        return None
    message = record["fields"]["message"]
    if not isinstance(message, str):
        raise ValueError("invalid guard message")
    marker, *pairs = message.split(" ")
    schemas = {"H2_GUARD_V2": FIELDS, "H2_GUARD_TAIL_V2": TAIL_FIELDS,
               "H2_GUARD_FENCE_V2": FENCE_FIELDS,
               "H2_GUARD_LIMIT_V1": ["seq", "scope", "suppressed"]}
    if marker not in schemas:
        raise ValueError("unknown guard schema")
    row = numeric_fields(pairs, schemas[marker])
    if not 1 <= row["seq"] <= MAX_RECORDS:
        raise ValueError("invalid guard sequence")
    row["record_type"] = marker
    if marker == "H2_GUARD_V2":
        if (not 1 <= row["cid"] <= 4096 or row["role"] not in (0, 1)
                or row["event"] not in (0, 1, 2, 3) or row["branch"] not in BRANCHES
                or row["last_end"] not in (0, 1) or not 0 <= row["disposition"] <= 6
                or (row["event"] == 1 and (row["branch"] == 0 or row["reason"] != 11))
                or (row["event"] == 3) != (row["generation"] > 0)
                or row["generation"] > 16 or row["pending"] > row["high_pending"]
                or not row["min_credit"] <= row["available"] <= row["max"]
                or row["tail_len"] != (min(512, row["transitions"]) if row["event"] in (1, 3) else 0)
                or row["overwritten"] != max(0, row["transitions"] - 512)
                or row["wraps"] != max(0, row["transitions"] - 1) // 512):
            raise ValueError("invalid guard enum/state")
        row["branch_name"] = BRANCHES[row["branch"]]
    elif marker == "H2_GUARD_TAIL_V2":
        if (not 1 <= row["cid"] <= 4096 or not 1 <= row["kind"] <= 8
                or row["end"] not in (0, 1) or not 0 <= row["disposition"] <= 6
                or row["consume"] not in (0, 1, 2) or row["n"] < 1
                or row["generation"] > 16 or row["snapshot"] >= row["seq"]
                or row["delta"] != abs(row["after"] - row["before"])):
            raise ValueError("invalid transition")
    elif marker == "H2_GUARD_FENCE_V2":
        validate_fence(row)
    elif row["scope"] not in (1, 2, 3) or row["suppressed"] == 0:
        raise ValueError("invalid suppression notice")
    timestamp = record["timestamp"]
    if not isinstance(timestamp, str) or not timestamp.endswith("Z"):
        raise ValueError("missing UTC event timestamp")
    row["unix_secs"] = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    return row


def annotate(sample, usage, lines, boundaries=None, invocation=None, expected=None):
    result = dict(schema=2, diagnostic_only=True, events=[], transitions=[], fences=[], suppression_notices=[], capture_errors=[],
                  id_scope="gateway process / h2 connection; no cross-hop or pool-family mapping",
                  counter_scope="connection lifetime, including earlier payloads",
                  phase_clock="gateway emission Unix time; cross-process skew unmeasured",
                  tail_scope="bounded live boundary snapshots; process shutdown and overwritten history remain unclosed",
                  suppression_counts_are_lower_bounds=True)
    sample["h2_guard_observation"] = result
    result["capture_errors"].extend(sample_problems(sample, expected))
    if not isinstance(boundaries, dict):
        boundaries = {}
    if not isinstance(invocation, dict):
        invocation = {}
    if sample.get("gateway") == "direct":
        result["not_applicable"] = "unpatched direct control"
        try:
            start, end = phase_interval(sample)
            left, right = capture_range(invocation)
            if (not matches_fields(invocation.get("identity"), capture_identity(sample))
                    or not left <= start <= end <= right
                    or type(invocation.get("exit_code")) is not int or not 0 <= invocation["exit_code"] <= 255):
                raise ValueError("invalid direct invocation")
        except (ValueError, KeyError, TypeError):
            result["capture_errors"].append("missing_or_malformed_direct_phases_or_invocation")
        result["invocation"] = invocation
        return
    try:
        phase_interval(sample)
        phases = sample["phases"]
    except (ValueError, KeyError, TypeError):
        phases = {}
    seqs = set()
    size = 0
    for line in lines:
        size += len(line.encode("utf-8"))
        if size > MAX_BYTES:
            result["capture_errors"].append("log_parse_byte_bound")
            break
        try:
            row = parse_line(line.rstrip("\n"))
            if row is None:
                continue
            if len(seqs) >= MAX_RECORDS:
                result["capture_errors"].append("record_bound")
                break
            if row["seq"] in seqs:
                raise ValueError("duplicate sequence")
            seqs.add(row["seq"])
            row["phase"] = ("before_sample" if row["unix_secs"] < phases.get("setup_start_unix_secs", 0)
                            else event_phase(row["unix_secs"], phases))
            bucket = {"H2_GUARD_V2": "events", "H2_GUARD_TAIL_V2": "transitions",
                      "H2_GUARD_FENCE_V2": "fences", "H2_GUARD_LIMIT_V1": "suppression_notices"}
            result[bucket[row["record_type"]]].append(row)
        except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
            if "malformed_guard_record" not in result["capture_errors"]:
                result["capture_errors"].append("malformed_guard_record")
    result["missing_sequence_count"] = max(seqs, default=0) - len(seqs)
    if result["missing_sequence_count"]:
        result["capture_errors"].append("missing_log_sequence")
    if not any(row["role"] == 1 for row in result["events"]):
        result["capture_errors"].append("missing_client_role_observation")
    result["measurement_failures"] = [row["seq"] for row in result["events"]
                                      if row["event"] == 1 and row["phase"] == "measurement"]
    loss_keys = {f"log_dropped_{sink}_{reason}" for sink in ("stdout", "stderr")
                 for reason in ("saturation", "record_too_large", "closed")}
    timeline = usage.get("timeline", []) if isinstance(usage, dict) else []
    if not isinstance(timeline, list):
        result["capture_errors"].append("malformed_process_timeline")
        timeline = []
    if any(not isinstance(row, dict) or ("h2_gauges" in row and not isinstance(row["h2_gauges"], dict))
           for row in timeline):
        result["capture_errors"].append("malformed_log_sink_sample")
    snapshots = [row["h2_gauges"] for row in timeline if isinstance(row, dict)
                 and isinstance(row.get("h2_gauges"), dict)]
    if any(not isinstance(row.get("gauges"), dict) or not finite_time(row.get("unix_secs")) for row in snapshots):
        result["capture_errors"].append("malformed_log_sink_sample")
        snapshots = [row for row in snapshots if isinstance(row.get("gauges"), dict)
                     and finite_time(row.get("unix_secs"))]
    result["sink_loss_samples"] = [dict(unix_secs=row["unix_secs"], **{
        key: value for key, value in row.get("gauges", {}).items() if key in loss_keys})
        for row in snapshots]
    if not snapshots or any(not loss_keys <= row.get("gauges", {}).keys() for row in snapshots):
        result["capture_errors"].append("missing_log_sink_loss_counters")
    result["sink_loss_observed"] = any(type(row.get(key)) is int and row[key] > 0
                                     for row in result["sink_loss_samples"] for key in loss_keys)
    result["suppression_observed"] = bool(result["suppression_notices"]) or any(
        row[key] > 0 for row in result["events"] for key in
        ("suppressed_connections", "suppressed_lifecycle", "suppressed_failures"))

    result["sink_health_samples"] = snapshots
    for snapshot in snapshots:
        result["capture_errors"].extend(sink_problems(snapshot.get("gauges", {})))
    validate_capture(result, sample, boundaries, seqs, invocation)


def main():
    path, usage_path, log_path = map(Path, sys.argv[1:])
    sample = json.loads(path.read_text())
    errors = []
    expected = None
    try:
        gateway, protocol, size = path.stem.rsplit("_", 2)
        manifest = json.loads((path.parents[2] / "manifest.json").read_text())
        errors.extend(manifest_problems(manifest, protocol))
        expected = expected_sample(manifest, protocol, int(path.parent.name.removeprefix("pair_")), gateway, int(size))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        errors.append("missing_or_malformed_campaign_manifest")
    try:
        invocation = json.loads(log_path.with_name(log_path.stem + "_invocation.json").read_text())
    except (OSError, ValueError):
        invocation = {}
    try:
        usage = json.loads(usage_path.read_text())
    except (OSError, ValueError):
        usage = {}
        errors.append("missing_process_capture")
    try:
        with log_path.open() as stream:
            boundaries = {}
            for label in ("smoke", "before", "after"):
                stem = expected["gateway"] if label == "smoke" and expected else log_path.stem
                boundary = log_path.with_name(stem + "_guard_" + label + ".json")
                try:
                    boundaries[label] = json.loads(boundary.read_text())
                except (OSError, ValueError):
                    pass
            annotate(sample, usage, stream, boundaries, invocation, expected)
    except OSError:
        annotate(sample, usage, [], invocation=invocation, expected=expected)
        if sample.get("gateway") != "direct":
            errors.append("missing_gateway_log")
    sample["h2_guard_observation"]["capture_errors"].extend(errors)
    if errors and sample.get("gateway") != "direct":
        sample["h2_guard_observation"].update(bounded_capture_complete=False,
            full_transition_history_complete=False, capture_status="partial")
    path.write_text(json.dumps(sample, indent=2) + "\n")


if __name__ == "__main__":
    main()
