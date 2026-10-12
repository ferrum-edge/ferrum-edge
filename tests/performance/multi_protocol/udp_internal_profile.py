"""UDP-only fixed metrics capture and conservative evidence validation.

No request labels, body capture, packet tracing or benchmark policy changes.
Use the existing CIDR-authenticated loopback endpoint on a disposable runner.
"""

import hashlib
import json
import math
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / "udp_profile_schema.json").read_text())
MANIFEST = json.loads((ROOT / "udp_profile_manifest.json").read_text())
PREFIX = "ferrum_udp_profile_"
FIELDS = set(SCHEMA["counters"] + SCHEMA["metadata"])


def parse_metrics(text):
    counters = {}
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        match = re.fullmatch(r"ferrum_udp_profile_([a-z0-9_]+) ([0-9]+)", line)
        if not match or match[1] not in FIELDS or match[1] in counters:
            raise ValueError("unknown, duplicate or malformed UDP profile metric")
        value = int(match[2])
        if value > 2**64 - 1:
            raise ValueError("UDP counter outside u64 range")
        counters[match[1]] = value
    if counters.keys() != FIELDS or counters["schema"] != SCHEMA["version"]:
        raise ValueError("missing or incompatible UDP profile schema")
    if any(counters[key] != SCHEMA[key] for key in ("sample_every", "publication_interval", "slot_capacity")):
        raise ValueError("invalid UDP observer configuration")
    return counters


def _is_finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def counter_relations(counters):
    issues = []
    for direction in ("ingress", "reply", "other"):
        c = lambda field: counters[direction + "_" + field]
        if c("rx_returned_slots") > c("rx_requested_slots"):
            issues.append(direction + " receive occupancy exceeds requests")
        if c("tx_requested_slots") != c("tx_sent_slots") + c("tx_remaining_slots") + c("tx_error_slots"):
            issues.append(direction + " send slot accounting mismatch")
        for kind in ("rx_requested", "tx_requested", "gso_occupied"):
            bins = sum(value for name, value in counters.items()
                       if name.startswith(direction + "_" + kind + "_slots_"))
            calls = c({"rx_requested": "rx_calls", "tx_requested": "tx_calls",
                       "gso_occupied": "gso_calls"}[kind])
            if bins != calls:
                issues.append(direction + " occupied histogram mismatch: " + kind)
        if c("gso_accepted_segments") > c("gso_segments") or c("gso_accepted_bytes") > c("gso_bytes"):
            issues.append(direction + " GSO acceptance exceeds offered batch")
    return issues


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def snapshot(sample_id=0, processes=()):
    row = dict(sample_id=sample_id, unix_secs=time.time(), monotonic_secs=time.monotonic(),
               sampler_cpu_start=time.process_time())
    try:
        # Fixed URL, no redirects/proxy environment, credentials or public path.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open("http://127.0.0.1:9000/metrics", timeout=0.2) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        row["raw_response_sha256"] = hashlib.sha256(raw).hexdigest()
        decoded = raw.decode("utf-8", errors="replace")
        row["raw_profile_text"] = "\n".join(line for line in decoded.splitlines()
                                             if line.startswith(PREFIX))
        row["response_bytes"] = len(raw)
        row["truncated"] = len(raw) > 2 * 1024 * 1024
        if row["truncated"]:
            raise ValueError("oversized metrics capture")
        row["counters"] = parse_metrics(raw.decode("utf-8"))
    except (OSError, ValueError) as error:
        row["error"] = type(error).__name__
        if hasattr(error, "code"):
            row["http_status"] = error.code
    row["gateway_bindings"] = []
    for process in processes:
        if process.get("role") != "gateway":
            continue
        try:
            status = Path(f"/proc/{process['pid']}/status").read_text()
            namespace_pids = next(line.split()[1:] for line in status.splitlines()
                                  if line.startswith("NSpid:"))
            row["gateway_bindings"].append(dict(host_pid=process["pid"],
                start_ticks=process["start_ticks"], namespace_pid=int(namespace_pids[-1])))
        except (OSError, ValueError, StopIteration, IndexError, KeyError):
            row["identity_error"] = "namespace PID binding unavailable"
    row["capture_secs"] = time.monotonic() - row["monotonic_secs"]
    row["sampler_cpu_secs"] = time.process_time() - row["sampler_cpu_start"]
    return row


def profile_bracket(usage, phases):
    result = dict(complete=False, issues=[], publication_complete=False,
                  coverage="published UDP source-site counts only; no contention or scheduler attribution")
    if not isinstance(usage, dict) or not isinstance(phases, dict):
        result["issues"].append("malformed capture or measurement boundaries")
        return result
    start = phases.get("measurement_start_unix_secs")
    duration = phases.get("measurement_secs")
    if (not _is_finite_number(start) or not _is_finite_number(duration) or duration <= 0):
        result["issues"].append("missing measurement boundaries")
        return result
    timeline = usage.get("timeline", [])
    if not isinstance(timeline, list) or not timeline:
        result["issues"].append("missing or malformed capture timeline")
        return result
    for row in timeline:
        if (not isinstance(row, dict) or not _is_finite_number(row.get("unix_secs"))
                or not isinstance(row.get("processes"), list)
                or any(not isinstance(p, dict) or not {"pid", "start_ticks", "role"} <= p.keys()
                       or type(p["pid"]) is not int or type(p["start_ticks"]) is not int
                       or p["pid"] <= 0 or p["start_ticks"] < 0 or not isinstance(p["role"], str)
                       for p in row["processes"])):
            result["issues"].append("malformed process capture")
            return result
        if "udp_profile" not in row:
            continue
        profile = row["udp_profile"]
        if (not isinstance(profile, dict) or not _is_finite_number(profile.get("unix_secs"))
                or not _is_finite_number(profile.get("capture_secs"))
                or profile["capture_secs"] < 0
                or not _is_finite_number(profile.get("sampler_cpu_secs"))
                or profile["sampler_cpu_secs"] < 0):
            result["issues"].append("malformed profile capture")
            return result
        if "counters" in profile:
            counters = profile["counters"]
            if (not isinstance(counters, dict) or counters.keys() != FIELDS
                    or any(type(value) is not int or not 0 <= value <= 2**64 - 1
                           for value in counters.values())
                    or counters["schema"] != SCHEMA["version"]
                    or any(counters[key] != SCHEMA[key] for key in ("sample_every", "publication_interval", "slot_capacity"))):
                result["issues"].append("malformed profile counters")
                return result
    if any(b["unix_secs"] < a["unix_secs"] for a, b in zip(timeline, timeline[1:])):
        result["issues"].append("capture clock moved backwards")
        return result
    before = [row for row in timeline if "udp_profile" in row and
              row["udp_profile"]["unix_secs"] + row["udp_profile"].get("capture_secs", 0) <= start]
    after = [row for row in timeline if "udp_profile" in row and
             row["udp_profile"]["unix_secs"] >= start + duration]
    if not before or not after or usage.get("capture_complete") is not True:
        result["issues"].append("missing or incomplete capture bracket")
        return result
    left, right = before[-1], after[0]
    rows = [row for row in timeline if left["unix_secs"] <= row["unix_secs"] <= right["unix_secs"]]
    profiles = [row.get("udp_profile", {}) for row in rows]
    identities = [{(p["pid"], p["start_ticks"]) for p in row["processes"]
                   if p["role"] == "gateway"} for row in rows]
    if not identities[0] or any(ids != identities[0] for ids in identities):
        result["issues"].append("missing or changed gateway process identity")
    if any("counters" not in profile for profile in profiles):
        result["issues"].append("missing profile snapshots (never zero-filled)")
        return result
    counters = [p["counters"] for p in profiles]
    for values in counters:
        result["issues"].extend(counter_relations(values))
    for profile, ids in zip(profiles, identities):
        bindings = profile.get("gateway_bindings", [])
        if (profile.get("identity_error") or not isinstance(bindings, list)
                or not any(isinstance(binding, dict)
                           and type(binding.get("host_pid")) is int
                           and type(binding.get("start_ticks")) is int
                           and type(binding.get("namespace_pid")) is int
                           and (binding.get("host_pid"), binding.get("start_ticks")) in ids
                           and binding.get("namespace_pid") == profile["counters"]["pid"]
                           for binding in bindings)):
            result["issues"].append("metrics PID is not bound to observed gateway process")
    for field in ("sample_id", "monotonic_secs", "unix_secs"):
        values = [p.get(field) for p in profiles]
        if (any(not _is_finite_number(value) for value in values)
                or any(b <= a for a, b in zip(values, values[1:]))):
            result["issues"].append("missing or non-increasing capture " + field)
    if any(type(p.get("sample_id")) is not int or p["sample_id"] < 0 for p in profiles):
        result["issues"].append("invalid sample ID")
    clocks_valid = all(_is_finite_number(p.get(field))
                       for p in profiles for field in ("unix_secs", "monotonic_secs"))
    if clocks_valid and any(abs((b["unix_secs"] - a["unix_secs"]) -
                                (b["monotonic_secs"] - a["monotonic_secs"])) > 0.05
                            for a, b in zip(profiles, profiles[1:])):
        result["issues"].append("wall/monotonic clock discontinuity")
    if any(b["snapshot_sequence"] <= a["snapshot_sequence"] for a, b in zip(counters, counters[1:])):
        result["issues"].append("metrics snapshot reset/replay")
    if any(p.get("error") or p.get("truncated") for p in profiles):
        result["issues"].append("scrape failure or truncation")
    if any(c["pid"] <= 0 or not 0 < c["registered_slots"] <= c["slot_capacity"]
           or c["missing_slots"] > c["registered_slots"]
           or c["unpublished_event_bound"] > c["registered_slots"] * c["publication_interval"]
           for c in counters):
        result["issues"].append("invalid slot or process metadata")
    if any(c["pid"] != counters[0]["pid"] for c in counters):
        result["issues"].append("changed container PID")
    for name in SCHEMA["counters"] + ["lost_events", "registered_slots"]:
        if any(b[name] < a[name] for a, b in zip(counters, counters[1:])):
            result["issues"].append("counter reset or missed publication: " + name)
    for name in ("missing_slots", "lost_events", "counter_overflow",
                 "ingress_rx_parse_errors", "reply_gso_short_bytes", "recv_truncated_slots",
                 "recv_control_truncated_slots", "recv_invalid_gro_segment"):
        if any(c[name] != 0 for c in counters):
            result["issues"].append(name)
    result["unpublished_event_bound_at_boundaries"] = [counters[0]["unpublished_event_bound"],
                                                   counters[-1]["unpublished_event_bound"]]
    result["publication_complete"] = all(c["unpublished_event_bound"] == 0 for c in counters)
    if not result["publication_complete"]:
        result["issues"].append("unpublished thread tails; update groups bounded; byte/time residuals unbounded")
    result["boundary_slack_secs"] = (start - left["udp_profile"]["unix_secs"] +
                                     right["udp_profile"]["unix_secs"] +
                                     right["udp_profile"].get("capture_secs", 0) - start - duration)
    result["sample_count"] = len(rows)
    result["sampler_cpu_secs"] = sum(p.get("sampler_cpu_secs", 0) for p in profiles)
    result["capture_secs"] = sum(p.get("capture_secs", 0) for p in profiles)
    result["start"] = counters[0]
    result["end"] = counters[-1]
    if not any("reset" in issue for issue in result["issues"]):
        result["published_delta"] = {name: counters[-1][name] - counters[0][name]
                                     for name in SCHEMA["counters"]}
    if result.get("boundary_slack_secs", 0) > 2:
        result["issues"].append("profile measurement bracket exceeds two-second slack")
    if not result.get("published_delta", {}).get("pending_lookup_calls", 0):
        result["issues"].append("no observed UDP lookup work; zero-filled success forbidden")
    result["complete"] = not result["issues"]
    return result


def validate_selection(mode, protocol, pairs, duration, workers, gateways, sizes, baseline, extra):
    if mode not in ("calibration", "profile") or protocol != "udp":
        raise ValueError("UDP-only calibration/profile selection required")
    expected = "ferrum" if mode == "calibration" else "ferrum kong"
    if (pairs, duration, workers, gateways, sizes) != ("4", "15", "200", expected, "1024") or extra:
        raise ValueError("UDP profile requires four pairs, 15 seconds, 200 workers, 1024 bytes")
    if bool(baseline) != (mode == "calibration"):
        raise ValueError("only calibration requires identical-revision observer-off image")


def retain_runtime(destination, container, config_path):
    # Exact effective, non-secret benchmark settings. Source/config/build hashes
    # accompany this record; no arbitrary environment or credential values.
    keys = {"FERRUM_MODE", "FERRUM_FILE_CONFIG_PATH", "FERRUM_PROXY_HTTP_PORT",
            "FERRUM_PROXY_HTTPS_PORT", "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES",
            "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES",
            "FERRUM_ADMIN_BIND_ADDRESS", "FERRUM_ADMIN_HTTP_PORT",
            "FERRUM_METRICS_ALLOWED_CIDRS", "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE",
            "FERRUM_POOL_WARMUP_ENABLED", "FERRUM_LOG_LEVEL", "FERRUM_UDP_MAX_SESSIONS",
            "FERRUM_UDP_RECVMMSG_BATCH_SIZE", "FERRUM_UDP_GSO_ENABLED",
            "FERRUM_UDP_GRO_ENABLED", "FERRUM_UDP_PKTINFO_ENABLED"}
    environment = dict(entry.split("=", 1) for entry in container["Config"]["Env"])
    result = dict(image_id=container["Image"], container_id=container["Id"],
                  config_sha256=hashlib.sha256(Path(config_path).read_bytes()).hexdigest(),
                  host_pid=container["State"]["Pid"], started_at=container["State"]["StartedAt"],
                  environment={key: environment.get(key) for key in sorted(keys)})
    Path(destination).write_text(json.dumps(result, indent=2) + "\n")


def report(directory, mode):
    from benchmark_validity import sample_issues
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    manifest_issues = []
    try:
        manifest = json.loads((directory / "manifest.json").read_text())
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be an object")
    except (OSError, ValueError):
        manifest_issues.append("campaign manifest missing/malformed; retaining full expected matrix")
        manifest = dict(pairs=4, gateways=["direct"] + list(MANIFEST["campaigns"][mode]),
                        payload_sizes=MANIFEST["payload_sizes"])
    expected_gateways = ["direct"] + list(MANIFEST["campaigns"][mode])
    actual_gateways = manifest.get("gateways")
    if (not isinstance(actual_gateways, list) or
            any(not isinstance(gateway, str) for gateway in actual_gateways) or
            sorted(actual_gateways) != sorted(expected_gateways)):
        manifest_issues.append("missing or unexpected campaign arms")
    if not isinstance(manifest.get("host_id"), str) or not manifest["host_id"]:
        manifest_issues.append("missing same-host identity")
    if manifest.get("pairs") != 4:
        manifest_issues.append("four complete pairs required")
    selected = manifest.get("payload_sizes", [])
    if (not isinstance(selected, list) or not selected or
            any(type(size) is not int or size not in MANIFEST["payload_sizes"] for size in selected) or
            len(set(selected)) != len(selected)):
        manifest_issues.append("invalid payload selection; retaining full expected matrix")
        manifest["payload_sizes"] = MANIFEST["payload_sizes"]
    manifest["pairs"] = 4
    manifest["gateways"] = expected_gateways
    report = dict(mode=mode, manifest_issues=manifest_issues, observations=[],
                  traffic_complete=True, profiles_complete=True,
                  actual_syscalls="instrumented mmsg/GSO sites only; Tokio retries and kernel tracing unavailable",
                  cpu_stacks="unavailable: no collector implemented",
                  overhead="raw same-revision on/off pairs; no guessed subtraction",
                  claims="no performance result asserted by this implementation")
    if manifest_issues:
        report["traffic_complete"] = False
        report["profiles_complete"] = False
    for pair in range(1, manifest["pairs"] + 1):
        folder = directory / "pairs" / f"pair_{pair:03d}"
        for gateway in manifest["gateways"]:
            for size in manifest["payload_sizes"]:
                path = folder / f"{gateway}_udp_{size}.json"
                try:
                    sample = json.loads(path.read_text())
                    if not isinstance(sample, dict):
                        raise ValueError("sample must be an object")
                except (OSError, ValueError):
                    sample = {"error": "missing or malformed sample"}
                try:
                    traffic_issues = sample_issues(sample)
                except (ValueError, KeyError, TypeError, AttributeError):
                    traffic_issues = ["malformed sample fields"]
                observed = sample.get("observed") or {}
                if (sample.get("sample_schema") != 2 or sample.get("gateway") != gateway
                        or sample.get("pair") != pair or sample.get("payload_size") != 1024
                        or sample.get("duration_secs") != 15 or sample.get("effective_concurrency") != 200
                        or sample.get("host_id") != manifest.get("host_id")):
                    traffic_issues.append("sample identity or offered work does not match campaign")
                sockets = observed.get("active_connections", {}) if isinstance(observed, dict) else {}
                if not isinstance(sockets, dict) or sockets.get("min") != 200 or sockets.get("max") != 200:
                    traffic_issues.append("200 continuously observed client sockets required")
                row = dict(pair=pair, gateway=gateway, payload=size, sample=sample,
                           traffic_issues=traffic_issues)
                if row["traffic_issues"]:
                    report["traffic_complete"] = False
                expected = gateway == "ferrum"
                if expected:
                    try:
                        usage = json.loads((folder / "diagnostics" /
                                            f"{gateway}_{size}_process_usage.json").read_text())
                        row["profile"] = profile_bracket(usage, sample.get("phases") or {})
                    except (OSError, ValueError, KeyError):
                        row["profile"] = dict(complete=False, issues=["missing/malformed capture"])
                    if not row["profile"]["complete"]:
                        report["profiles_complete"] = False
                else:
                    row["profile"] = dict(expected=False, reason="direct, Kong, or observer-off control")
                if gateway == "kong":
                    readback = folder / "diagnostics/kong-readback/summary.json"
                    try:
                        raw = readback.read_bytes()
                        evidence = json.loads(raw)
                        if not isinstance(evidence, dict) or evidence.get("schema") != 1:
                            raise ValueError("unknown Kong readback schema")
                        row["kong_readback"] = dict(artifact=str(readback.relative_to(directory)),
                                                   sha256=hashlib.sha256(raw).hexdigest(),
                                                   evidence=evidence)
                    except (OSError, ValueError):
                        row["kong_readback"] = dict(error="missing/malformed Kong readback")
                report["observations"].append(row)
    if mode == "profile":
        # The client gauge measures socket lifetime, not native Kong sessions.
        # Even successful fixed-file readback requires root's config/Lua review
        # and exact enterprise native correspondence; never infer defaults here.
        report["kong_session_comparability"] = dict(complete=False, effective_values=None,
            reason="root must review rendered includes, runtime Lua timeouts and native vendor correspondence")
    report["fully_measured_comparison_eligible"] = (
        report["traffic_complete"] and report["profiles_complete"] and mode != "profile")
    (directory / "udp_profile_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    command, *arguments = sys.argv[1:]
    if command == "validate-selection":
        validate_selection(*arguments)
    elif command == "runtime":
        retain_runtime(arguments[0], json.load(sys.stdin), arguments[1])
    elif command == "report":
        result = report(*arguments)
        # Retained partial profiles can guide follow-up coverage; never a win.
        sys.exit(0 if result["traffic_complete"] else 1)
    else:
        raise ValueError("unknown UDP profile command")
