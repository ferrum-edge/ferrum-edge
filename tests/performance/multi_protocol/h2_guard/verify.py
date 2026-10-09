"""Hosted artifact checks; failed request samples are observations, never filtered."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from h2_guard_observation import (
    FENCE_FIELDS, GATEWAYS, MAX_BYTES, annotate, boundary_range, expected_sample,
    manifest_problems, matches_fields, parse_ack, parse_line, sink_problems,
)


def verify_smoke(path):
    boundary = json.loads(path.read_text())
    boundary_range(boundary)
    ack = parse_ack(boundary["raw_ack"])
    if (boundary["errors"] or boundary["ack"] != ack or ack["generation"] != 1
            or not ack["captured"] or any(ack[key] for key in
                ("missed", "changed", "registry_loss", "memory_overflow", "suppressed"))
            or sink_problems(boundary["sink_samples"][-1]["gauges"], drained=True)):
        raise ValueError("snapshot trigger smoke is partial")
    log = path.with_suffix(".log")
    if log.stat().st_size > MAX_BYTES:
        raise ValueError("smoke log exceeds parse bound")
    rows = [row for line in log.read_text().splitlines() if (row := parse_line(line)) is not None]
    sequences = [row["seq"] for row in rows if row["seq"] <= ack["seq"]]
    fences = [row for row in rows if row["record_type"] == "H2_GUARD_FENCE_V2"]
    if (sorted(sequences) != list(range(1, ack["seq"] + 1)) or len(fences) != 1
            or any(fences[0][key] != ack[key] for key in FENCE_FIELDS)
            or not any(row.get("event") == 3 and row.get("generation") == 1 for row in rows)):
        raise ValueError("snapshot smoke log delivery not acknowledged")


def verify_graph(path):
    metadata = json.loads(path.read_text())
    packages = {p["id"]: p for p in metadata["packages"]}
    h2 = [p for p in packages.values() if p["name"] == "h2" and p["version"] == "0.4.20"]
    if len(h2) != 1 or h2[0]["source"] is not None or not h2[0]["manifest_path"].endswith(
            "/vendor/h2-0.4.20-observation/Cargo.toml"):
        raise ValueError("diagnostic graph must select exactly one patched h2 0.4.20")
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root = metadata["resolve"]["root"]

    def path_through(start, names):
        if not names:
            return [start]
        for child in nodes[start]["dependencies"]:
            if packages[child]["name"] == names[0]:
                tail = path_through(child, names[1:])
                if tail:
                    return [start] + tail
        return None

    chains = {}
    for label, names in (("reqwest", ["reqwest", "hyper_util", "hyper", "h2"]),
                         ("native_grpc_hyper", ["hyper", "h2"])):
        names = [name.replace("_", "-") for name in names]
        chain = path_through(root, names)
        if not chain or chain[-1] != h2[0]["id"]:
            raise ValueError("transport no longer resolves to observed h2: " + label)
        chains[label] = chain
    return chains


def read_artifact(path, hashes, failures, label, as_json=True):
    """Retain an identity and a cause for each input, even when its JSON is bad."""
    hashes[label] = None
    try:
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("artifact byte bound")
        raw = path.read_bytes()
        hashes[label] = hashlib.sha256(raw).hexdigest()
        value = json.loads(raw) if as_json else raw.decode("utf-8")
        if as_json and not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        failures.append(f"{label}:{type(error).__name__}:{error}")
        return None


def verify_campaign(root, protocol):
    sizes = [71680] if protocol == "http2" else [10240, 71680]
    rows = []
    problems = []
    manifest_hash = {}
    manifest = read_artifact(root / "manifest.json", manifest_hash, problems, "manifest") or {}
    problems.extend(manifest_problems(manifest, protocol))
    for pair in range(1, 5):
        for gateway in GATEWAYS:
            for size in sizes:
                path = root / "pairs" / f"pair_{pair:03d}" / f"{gateway}_{protocol}_{size}.json"
                expected = expected_sample(manifest, protocol, pair, gateway, size)
                failures = []
                hashes = {}
                row = dict(path=str(path.relative_to(root)), expected=expected,
                           validation_failures=failures, raw_sha256={})
                rows.append(row)  # Every expected cell survives absent/malformed input.
                sample = read_artifact(path, hashes, failures, "sample")
                row.update(sha256=hashes["sample"], sample_present=path.is_file(),
                           sample_object_valid=sample is not None)
                retained = sample or {}
                observation = retained.get("h2_guard_observation")
                if not isinstance(observation, dict):
                    failures.append("missing_or_malformed_observer_annotation")
                    observation = {}
                if not matches_fields(observation, dict(schema=2, diagnostic_only=True)):
                    failures.append("invalid_observer_schema")
                if observation.get("capture_errors"):
                    failures.append("annotated_capture_errors")
                if gateway != "direct" and not matches_fields(observation, dict(
                        bounded_capture_complete=True, suppression_observed=False, sink_loss_observed=False)):
                    failures.append("unacknowledged_or_lossy_capture")
                row.update(total_errors=retained.get("total_errors"), error=retained.get("error"),
                           offered=retained.get("effective_concurrency"))
                for key in ("measurement_failures", "capture_errors", "suppression_observed",
                            "sink_loss_observed", "bounded_capture_complete",
                            "full_transition_history_complete", "process_capture_closed"):
                    row[key] = observation.get(key)
                # Read every raw artifact independently, including when the sample
                # or an earlier raw input is missing/corrupt. Never hide later causes.
                diagnostics = path.parent / "diagnostics"
                prefix = f"{gateway}_{size}"
                raw_paths = {"invocation": diagnostics / (prefix + "_invocation.json")}
                if gateway != "direct":
                    raw_paths.update(log=diagnostics / (prefix + ".log"),
                                     usage=diagnostics / (prefix + "_process_usage.json"))
                    raw_paths.update({label: diagnostics / (
                        (gateway if label == "smoke" else prefix) + "_guard_" + label + ".json")
                        for label in ("smoke", "before", "after")})
                raw = {label: read_artifact(raw_path, row["raw_sha256"], failures, label,
                                           as_json=label != "log")
                       for label, raw_path in raw_paths.items()}
                recomputed = dict(sample if sample is not None else expected)
                try:
                    annotate(recomputed, raw.get("usage"), (raw.get("log") or "").splitlines(),
                             {label: raw.get(label) for label in ("smoke", "before", "after")},
                             raw.get("invocation"), expected)
                    actual = json.loads(json.dumps(recomputed["h2_guard_observation"]))
                    row["recomputed_capture_errors"] = actual["capture_errors"]
                    row["recomputed_measurement_failures"] = actual.get("measurement_failures", [])
                    failures.extend(actual["capture_errors"])
                    if actual != observation:
                        failures.append("raw_capture_annotation_mismatch")
                    if gateway != "direct" and actual["bounded_capture_complete"] is not True:
                        failures.append("raw_capture_incomplete")
                except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError) as error:
                    failures.append(f"raw_capture_reconciliation_failed:{type(error).__name__}:{error}")
                problems.extend(f"{row['path']}:{failure}" for failure in failures)
    report = dict(protocol=protocol, expected_samples=12 * len(sizes), samples=rows,
                  manifest_sha256=manifest_hash["manifest"], problems=problems,
                  interpretation="diagnosis only; request failures retained; no repair/rate claim")
    (root / "guard-evidence-index.json").write_text(json.dumps(report, indent=2) + "\n")
    if problems:
        raise ValueError("campaign evidence incomplete; inspect guard-evidence-index.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("graph", "campaign", "smoke"))
    parser.add_argument("path", type=Path)
    parser.add_argument("--protocol", choices=("http2", "grpcs"))
    args = parser.parse_args()
    if args.mode == "graph":
        print(json.dumps(verify_graph(args.path), indent=2))
    elif args.mode == "smoke":
        verify_smoke(args.path)
    else:
        if not args.protocol:
            parser.error("campaign requires --protocol")
        verify_campaign(args.path, args.protocol)
