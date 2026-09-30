"""Pool-only fixed metrics capture and conservative evidence validation.

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
SCHEMA = json.loads((ROOT / "pool_profile_schema.json").read_text())
MANIFEST = json.loads((ROOT / "pool_profile_manifest.json").read_text())
PREFIX = "ferrum_pool_profile_"
FIELDS = set(SCHEMA["counters"] + SCHEMA["metadata"])


def parse_metrics(text):
    counters = {}
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        match = re.fullmatch(r"ferrum_pool_profile_([a-z0-9_]+) ([0-9]+)", line)
        if not match or match[1] not in FIELDS or match[1] in counters:
            raise ValueError("unknown, duplicate or malformed pool profile metric")
        value = int(match[2])
        if value > 2**64 - 1:
            raise ValueError("pool counter outside u64 range")
        counters[match[1]] = value
    if counters.keys() != FIELDS or counters["schema"] != SCHEMA["version"]:
        raise ValueError("missing or incompatible pool profile schema")
    if counters["allocator_installed"] != 1 or counters["sample_every"] != 64:
        raise ValueError("gateway allocator observation not installed")
    return counters


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def snapshot(sample_id=0):
    row = dict(sample_id=sample_id, unix_secs=time.time(), monotonic_secs=time.monotonic(),
               sampler_cpu_start=time.process_time())
    try:
        # Fixed URL, no redirects/proxy environment, credentials or public path.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open("http://127.0.0.1:9000/metrics", timeout=0.2) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("oversized metrics capture")
        row["raw_pool_metrics"] = [line for line in raw.decode("utf-8").splitlines()
                                   if line.startswith(PREFIX)]
        row["counters"] = parse_metrics("\n".join(row["raw_pool_metrics"]))
    except (OSError, ValueError) as error:
        row["error"] = type(error).__name__
    row["capture_secs"] = time.monotonic() - row["monotonic_secs"]
    row["sampler_cpu_secs"] = time.process_time() - row["sampler_cpu_start"]
    return row


def profile_bracket(usage, phases):
    result = dict(complete=False, issues=[], publication_complete=False,
                  coverage="sampled synchronous Rust allocations and elapsed execution; not CPU or stream credit")
    if not isinstance(usage, dict) or not isinstance(phases, dict):
        result["issues"].append("malformed capture or measurement boundaries")
        return result
    start = phases.get("measurement_start_unix_secs")
    duration = phases.get("measurement_secs")
    if (type(start) not in (float, int) or type(duration) not in (float, int)
            or not math.isfinite(start) or not math.isfinite(duration) or duration <= 0):
        result["issues"].append("missing measurement boundaries")
        return result
    timeline = usage.get("timeline", [])
    if not isinstance(timeline, list) or not timeline:
        result["issues"].append("missing or malformed capture timeline")
        return result
    for row in timeline:
        if (not isinstance(row, dict) or type(row.get("unix_secs")) not in (float, int)
                or not math.isfinite(row["unix_secs"]) or not isinstance(row.get("processes"), list)
                or any(not isinstance(p, dict) or not {"pid", "start_ticks", "role"} <= p.keys()
                       or type(p["pid"]) is not int or type(p["start_ticks"]) is not int
                       or p["pid"] <= 0 or p["start_ticks"] < 0 or not isinstance(p["role"], str)
                       for p in row["processes"])):
            result["issues"].append("malformed process capture")
            return result
        if "pool_profile" not in row:
            continue
        profile = row["pool_profile"]
        if (not isinstance(profile, dict) or type(profile.get("unix_secs")) not in (float, int)
                or not math.isfinite(profile["unix_secs"])
                or type(profile.get("capture_secs", 0)) not in (float, int)
                or not math.isfinite(profile.get("capture_secs", 0))
                or profile.get("capture_secs", 0) < 0):
            result["issues"].append("malformed profile capture")
            return result
        for field in ("monotonic_secs", "capture_secs", "sampler_cpu_secs"):
            if (type(profile.get(field)) not in (float, int) or
                    not math.isfinite(profile[field]) or profile[field] < 0):
                result["issues"].append("missing/malformed observer timing: " + field)
                return result
        if type(profile.get("sample_id")) is not int or profile["sample_id"] < 0:
            result["issues"].append("missing/malformed sample identity")
            return result
        if "counters" in profile:
            counters = profile["counters"]
            if (not isinstance(counters, dict) or counters.keys() != FIELDS
                    or any(type(value) is not int or not 0 <= value <= 2**64 - 1
                           for value in counters.values())
                    or counters["schema"] != SCHEMA["version"]
                    or counters["allocator_installed"] != 1 or counters["sample_every"] != 64):
                result["issues"].append("malformed profile counters")
                return result
    if any(b["unix_secs"] < a["unix_secs"] for a, b in zip(timeline, timeline[1:])):
        result["issues"].append("capture clock moved backwards")
        return result
    before = [row for row in timeline if "pool_profile" in row and
              row["pool_profile"]["unix_secs"] + row["pool_profile"].get("capture_secs", 0) <= start]
    after = [row for row in timeline if "pool_profile" in row and
             row["pool_profile"]["unix_secs"] >= start + duration]
    if not before or not after or usage.get("capture_complete") is not True:
        result["issues"].append("missing or incomplete capture bracket")
        return result
    left, right = before[-1], after[0]
    rows = [row for row in timeline if left["unix_secs"] <= row["unix_secs"] <= right["unix_secs"]]
    profiles = [row.get("pool_profile", {}) for row in rows]
    identities = [{(p["pid"], p["start_ticks"]) for p in row["processes"]
                   if p["role"] == "gateway"} for row in rows]
    if not identities[0] or any(ids != identities[0] for ids in identities):
        result["issues"].append("missing or changed gateway process identity")
    if any("counters" not in profile for profile in profiles):
        result["issues"].append("missing profile snapshots (never zero-filled)")
        return result
    if any(b["sample_id"] <= a["sample_id"] or b["monotonic_secs"] < a["monotonic_secs"]
           for a, b in zip(profiles, profiles[1:])):
        result["issues"].append("reset/duplicate sample identity or monotonic clock")
    counters = [p["counters"] for p in profiles]
    if any(c["pid"] != counters[0]["pid"] for c in counters):
        result["issues"].append("changed container PID")
    for c in (counters[0], counters[-1]):
        for family in ("h2", "grpc"):
            for purpose in ("request", "capability"):
                prefix = family + "_" + purpose + "_"
                if c[prefix + "sampled"] != c[prefix + "completed"] + c[prefix + "cancelled"]:
                    result["issues"].append("incomplete acquisition boundary: " + prefix)
    for name in SCHEMA["counters"] + ["lost_events", "allocator_lost_events", "allocator_overflow"]:
        if any(b[name] < a[name] for a, b in zip(counters, counters[1:])):
            result["issues"].append("counter reset or missed publication: " + name)
    for name in ("missing_slots", "lost_events", "counter_overflow",
                 "allocator_lost_events", "allocator_overflow"):
        if any(c[name] != 0 for c in counters):
            result["issues"].append(name)
    result["unpublished_events_at_boundaries"] = [counters[0]["unpublished_events"],
                                                   counters[-1]["unpublished_events"]]
    result["publication_complete"] = all(c["unpublished_events"] == 0 for c in counters)
    if not result["publication_complete"]:
        result["issues"].append("unpublished thread tails; byte residual is not bounded")
    result["boundary_slack_secs"] = (start - left["pool_profile"]["unix_secs"] +
                                     right["pool_profile"]["unix_secs"] +
                                     right["pool_profile"].get("capture_secs", 0) - start - duration)
    result["sample_count"] = len(rows)
    result["process_identities"] = sorted(identities[0])
    result["sampler_cpu_secs"] = sum(p["sampler_cpu_secs"] for p in profiles)
    result["capture_secs"] = sum(p["capture_secs"] for p in profiles)
    result["start"] = counters[0]
    result["end"] = counters[-1]
    if not any("reset" in issue for issue in result["issues"]):
        result["published_delta"] = {name: counters[-1][name] - counters[0][name]
                                     for name in SCHEMA["counters"]}
    result["complete"] = not result["issues"]
    return result


def validate_selection(mode, protocol, pairs, duration, workers, gateways, sizes, baseline, extra):
    if mode not in ("calibration", "profile") or protocol not in MANIFEST["protocols"]:
        raise ValueError("Pool-only calibration/profile selection required")
    if (pairs, duration, workers, gateways) != ("4", "15", "200", "ferrum") or extra:
        raise ValueError("pool profile requires four pairs, 15 seconds, 200 scaled workers, ferrum only")
    selected = [int(size) for size in sizes.split()]
    if not selected or len(set(selected)) != len(selected) or any(
            size not in MANIFEST["payload_sizes"] for size in selected):
        raise ValueError("invalid pool payload subset")
    if not baseline:
        raise ValueError("both campaigns require an explicit same-revision baseline image")


FIXED_ENV = {
    "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW": "false",
    "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE": "8388608",
    "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE": "33554432",
    "FERRUM_POOL_HTTP2_MAX_FRAME_SIZE": "1048576",
    "FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS": "1000",
    "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS": "1000",
    "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES": "0",
    "FERRUM_POOL_WARMUP_ENABLED": "true",
    "FERRUM_ADMIN_BIND_ADDRESS": "127.0.0.1",
    "FERRUM_ADMIN_HTTP_PORT": "9000",
    "FERRUM_METRICS_ALLOWED_CIDRS": "127.0.0.1/32",
    "FERRUM_LOG_LEVEL": "warn,ferrum_h2_observe=debug",
}


def materialize(protocol, gateway, source, destination, manifest):
    from experiment_arms import materialize_h2
    if protocol not in MANIFEST["protocols"] or gateway not in ("ferrum", "ferrum-baseline"):
        raise ValueError("unexpected pool protocol/arm")
    # Reuse the parent's narrow route verification, without its active experiment
    # loader or single-image runtime constraint (calibration uses feature twins).
    plan = dict(h2_campaign=True, arms=[dict(gateway=gateway, FERRUM_EXTRA_ENV=
                " ".join(key + "=" + value for key, value in FIXED_ENV.items()))])
    materialize_h2(plan, protocol, gateway, source, destination, manifest)
    text = Path(destination).read_text()
    route = text.split("  - id:")[1]
    for key, expected in (("backend_connect_timeout_ms", "5000"),
                          ("backend_read_timeout_ms", "30000"),
                          ("backend_write_timeout_ms", "30000")):
        if re.findall(r"(?m)^    " + key + r":\s*(\d+)", route) != [expected]:
            raise ValueError("pool fixture timeout drift: " + key)
    if ("backend_tls_server_ca_cert_path: \"/etc/ferrum/tls/ca.pem\"" not in text or
            "backend_tls_verify_server_cert: false" in text or "    retry:" in text):
        raise ValueError("pool fixture verification/retry policy drift")


def retain_runtime(destination, container, config_path):
    environment = dict(entry.split("=", 1) for entry in container["Config"]["Env"])
    issues = []
    for key, expected in FIXED_ENV.items():
        if environment.get(key) != expected:
            issues.append("runtime differs: " + key)
    if environment.get("RUST_LOG") or environment.get("FERRUM_TLS_NO_VERIFY", "false") != "false":
        issues.append("unexpected logging/verification override")
    revision = container["Config"].get("Labels", {}).get("org.opencontainers.image.revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        issues.append("missing immutable revision")
    observer = container["Config"].get("Labels", {}).get("ferrum.pool-profile")
    if observer not in ("on", "off"):
        issues.append("missing pool observer build identity")
    result = dict(image_id=container["Image"], container_id=container["Id"], revision=revision,
                  pool_observer=observer,
                  config_sha256=hashlib.sha256(Path(config_path).read_bytes()).hexdigest(),
                  host_pid=container["State"]["Pid"], started_at=container["State"]["StartedAt"],
                  environment={key: environment.get(key) for key in sorted(FIXED_ENV)}, issues=issues)
    Path(destination).write_text(json.dumps(result, indent=2) + "\n")
    if issues:
        raise ValueError("pool runtime verification failed; evidence retained")


def _nonnegative_finite_number(value):
    # Reject booleans and oversized JSON integers without float-conversion overflow.
    return type(value) in (int, float) and 0 <= value <= sys.float_info.max


def h2_traffic_issues(sample, gateway):
    """Require the pool campaign's H2 evidence, including on its control arms.

    Keep historical sample_issues contracts unchanged. PhaseReport serializes
    explicit transport status even when diagnostic annotation fails; inspect it
    before the annotation so an empty/missing object cannot hide those failures.
    """
    issues = []
    phases = sample.get("phases")
    if not isinstance(phases, dict):
        issues.append("missing/malformed H2 phase record")
        phases = {}
    for field in ("transport_errors_total", "transport_events_suppressed"):
        value = phases.get(field)
        if type(value) is not int or value < 0:
            issues.append("missing/malformed H2 phase field: " + field)
        elif value:
            issues.append("H2 phase failure: " + field)
    for field in ("transport_close_timed_out", "timed_out"):
        value = phases.get(field)
        if type(value) is not bool:
            issues.append("missing/malformed H2 phase field: " + field)
        elif value:
            issues.append("H2 phase failure: " + field)

    observation = sample.get("h2_observation")
    if not isinstance(observation, dict):
        issues.append("missing/malformed H2 diagnostic record")
        return issues
    errors = observation.get("capture_errors")
    if not isinstance(errors, list) or any(not isinstance(error, str) for error in errors):
        issues.append("missing/malformed H2 capture_errors")
    elif errors:
        issues.append("H2 diagnostic capture errors")
    errors = observation.get("backend_errors_observed")
    if type(errors) is not int or errors < 0:
        issues.append("missing/malformed H2 backend_errors_observed")
    elif errors:
        issues.append("H2 backend errors observed")
    # annotate() emits this marker only when the backend log limit is reached.
    # Absence is normal; a present null/zero/string is not a boolean status.
    if "backend_log_limit_reached" in observation:
        limited = observation["backend_log_limit_reached"]
        if type(limited) is not bool:
            issues.append("malformed H2 backend_log_limit_reached")
        elif limited:
            issues.append("truncated H2 backend observations")

    # Direct traffic has no gateway scrape (gauges_available=None, samples=[]).
    # Observer-off calibration still has the ordinary gateway H2 gauges.
    if gateway == "direct":
        return issues
    if observation.get("gauges_available") is not True:
        issues.append("missing H2 pool/connection observations")
    start, duration = phases.get("measurement_start_unix_secs"), phases.get("measurement_secs")
    window_valid = (_nonnegative_finite_number(start) and _nonnegative_finite_number(duration)
                    and duration > 0 and _nonnegative_finite_number(start + duration))
    if not window_valid:
        issues.append("missing/malformed H2 gauge measurement window")
    rows = observation.get("gauge_samples")
    if not isinstance(rows, list) or not rows:
        issues.append("missing/malformed H2 gauge_samples")
        return issues
    required = {"resident_http2_pool_entries", "resident_grpc_pool_entries", "active_connections"}
    for index, row in enumerate(rows):
        if (not isinstance(row, dict) or "error" in row or
                any(not _nonnegative_finite_number(row.get(field))
                    for field in ("unix_secs", "monotonic_secs", "capture_secs"))):
            issues.append(f"missing/malformed H2 gauge sample: {index}")
            continue
        if window_valid and not start <= row["unix_secs"] < start + duration:
            issues.append(f"H2 gauge sample outside measurement: {index}")
        gauges = row.get("gauges")
        if (not isinstance(gauges, dict) or not required <= gauges.keys() or
                any(not _nonnegative_finite_number(value) for value in gauges.values())):
            issues.append(f"missing/malformed H2 gauge values: {index}")
    return issues


def report(directory, mode, protocol):
    if mode not in MANIFEST["campaigns"] or protocol not in MANIFEST["protocols"]:
        raise ValueError("unknown pool campaign")
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
        manifest_issues.append("missing campaign host identity")
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
    report = dict(mode=mode, protocol=protocol, correctness_disposition="pending root", manifest_issues=manifest_issues, observations=[],
                  traffic_complete=True, profiles_complete=True,
                  actual_syscalls="unavailable: no collector implemented",
                  cpu_stacks="unavailable: no collector implemented",
                  overhead="raw same-revision on/off pairs; no guessed subtraction",
                  claims="no performance result asserted by this implementation")
    if manifest_issues:
        report["traffic_complete"] = False
        report["profiles_complete"] = False
    runtimes = []
    for pair in range(1, manifest["pairs"] + 1):
        folder = directory / "pairs" / f"pair_{pair:03d}"
        for gateway in manifest["gateways"]:
            for size in manifest["payload_sizes"]:
                path = folder / f"{gateway}_{protocol}_{size}.json"
                try:
                    sample = json.loads(path.read_text())
                    if not isinstance(sample, dict):
                        raise ValueError("sample must be an object")
                except (OSError, ValueError):
                    sample = {"error": "missing or malformed sample"}
                try:
                    traffic_issues = sample_issues(sample)
                except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
                    traffic_issues = ["malformed sample fields"]
                traffic_issues.extend(h2_traffic_issues(sample, gateway))
                expected_workers = 50 if size >= 5242880 else 100 if size >= 1048576 else 200
                if (sample.get("sample_schema") != 2 or sample.get("pair") != pair or
                        sample.get("gateway") != gateway or sample.get("payload_size") != size or
                        sample.get("duration_secs") != 15 or
                        sample.get("effective_concurrency") != expected_workers):
                    traffic_issues.append("missing/mismatched sample matrix identity")
                row = dict(pair=pair, gateway=gateway, payload=size, sample=sample,
                           traffic_issues=traffic_issues)
                if (sample.get("host_id") != manifest.get("host_id") or
                        not manifest.get("host_id")):
                    row["traffic_issues"].append("missing/changed campaign host identity")
                if row["traffic_issues"]:
                    report["traffic_complete"] = False
                if gateway != "direct":
                    try:
                        runtime = json.loads((folder / "diagnostics" /
                                              f"{gateway}_runtime.json").read_text())
                        row["runtime"] = runtime
                        if (not isinstance(runtime, dict) or runtime.get("issues") != [] or
                                any(not isinstance(runtime.get(key), str) or not runtime[key]
                                    for key in ("revision", "image_id", "config_sha256", "started_at")) or
                                runtime.get("pool_observer") != (
                                    "off" if mode == "calibration" and gateway == "ferrum-baseline" else "on") or
                                runtime.get("environment") != FIXED_ENV or
                                type(runtime.get("host_pid")) is not int):
                            raise ValueError("runtime identity incomplete")
                        runtimes.append(runtime)
                    except (OSError, ValueError, AttributeError):
                        row["runtime_issues"] = ["missing/malformed/failed runtime identity"]
                        report["profiles_complete"] = False
                expected = gateway != "direct" and not (mode == "calibration" and gateway == "ferrum-baseline")
                if expected:
                    try:
                        usage = json.loads((folder / "diagnostics" /
                                            f"{gateway}_{size}_process_usage.json").read_text())
                        row["capture"] = usage
                        row["profile"] = profile_bracket(usage, sample.get("phases") or {})
                        failed = [entry for entry in usage.get("timeline", [])
                                  if not isinstance(entry, dict) or not isinstance(entry.get("pool_profile"), dict) or
                                  "counters" not in entry["pool_profile"]]
                        row["failed_observations"] = failed
                        if failed:
                            row["profile"]["complete"] = False
                            row["profile"]["issues"].append("failed observations outside/inside bracket")
                    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError):
                        row["profile"] = dict(complete=False, issues=["missing/malformed capture"])
                    delta = row["profile"].get("published_delta", {})
                    family = "h2" if protocol == "http2" else "grpc"
                    sampled = delta.get(family + "_request_sampled")
                    if type(sampled) is not int or sampled <= 0:
                        row["profile"]["complete"] = False
                        row["profile"]["issues"].append("no sampled native request acquisitions")
                    if not row["profile"]["complete"]:
                        report["profiles_complete"] = False
                else:
                    row["profile"] = dict(expected=False, reason="direct or observer-off control")
                report["observations"].append(row)
    if (not runtimes or len({r["revision"] for r in runtimes}) != 1 or
            len({r.get("config_sha256") for r in runtimes}) != 1 or
            any(r.get("environment") != runtimes[0].get("environment") for r in runtimes) or
            (mode == "profile" and len({r.get("image_id") for r in runtimes}) != 1)):
        report["manifest_issues"].append("revision/image/config/runtime pairing mismatch")
        report["profiles_complete"] = False
    report["fully_measured_comparison_eligible"] = False  # root correctness disposition is external
    (directory / "pool_profile_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    command, *arguments = sys.argv[1:]
    if command == "validate-selection":
        validate_selection(*arguments)
    elif command == "materialize":
        materialize(*arguments)
    elif command == "runtime":
        retain_runtime(arguments[0], json.load(sys.stdin), arguments[1])
    elif command == "report":
        result = report(*arguments)
        # Retained partial profiles can guide follow-up coverage; never a win.
        sys.exit(0 if result["traffic_complete"] else 1)
    else:
        raise ValueError("unknown pool profile command")
