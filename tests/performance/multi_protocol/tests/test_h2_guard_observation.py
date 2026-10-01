import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "h2_guard"))
from benchmark_validity import sample_issues
from experiment_arms import load_experiment
from h2_diagnostics import parse_gauges
from h2_guard_observation import (
    FIELDS, GATEWAYS, TAIL_FIELDS, annotate, capture_identity, expected_sample,
    parse_line, parse_ack, sink_problems,
)
from prepare import SHA256, apply_ferrum_patch, extract_source, patch_source
from verify import verify_campaign
from lint import compare


def row(**updates):
    values = dict.fromkeys(FIELDS, 0)
    values.update(seq=1, cid=1, role=1, initial_max=32767, initial_available=32767,
                  max=32767, available=32767)
    values.update(updates)
    return values


def line(values, timestamp="2026-09-18T00:00:04Z", marker="H2_GUARD_V2"):
    message = marker + " " + " ".join(f"{key}={value}" for key, value in values.items())
    return timestamp + " " + json.dumps(dict(timestamp=timestamp, target="ferrum_h2_guard",
                                             fields=dict(message=message)))


def usage():
    gauges = {f"log_dropped_{sink}_{reason}": 0 for sink in ("stdout", "stderr")
              for reason in ("saturation", "record_too_large", "closed")}
    for sink in ("stdout", "stderr"):
        for name in ("healthy", "queued_records", "queued_bytes", "reserved_bytes", "io_write", "io_flush",
                     "shutdown_timeouts_total", "shutdown_incomplete_records_total"):
            gauges[f"log_{sink}_{name}"] = int(name == "healthy")
    return dict(timeline=[dict(h2_gauges=dict(unix_secs=1789689604, gauges=gauges))])


def manifest(protocol="http2"):
    return dict(sample_schema=2, host_id="fixture-host", pairs=4, gateways=list(GATEWAYS),
                payload_sizes=[71680] if protocol == "http2" else [10240, 71680],
                h2_observation_enabled=True)


def sample_fixture(gateway="ferrum", protocol="http2", pair=1, size=71680):
    sample = expected_sample(manifest(protocol), protocol, pair, gateway, size)
    # Synthetic harness/PhaseReport metadata around the unchanged actual h2
    # export. These are contract fixtures, not measured campaign/frame times.
    start = 1789689600 + (pair - 1) * 1000 + (GATEWAYS.index(gateway) - 1) * 100
    if protocol == "grpcs" and size == 71680:
        start += 30
    sample.update(total_errors=148, phases=dict(
        setup_start_unix_secs=start, setup_start_monotonic_secs=0,
        warmup_start_monotonic_secs=1, measurement_start_monotonic_secs=3,
        measurement_start_unix_secs=start + 3, drain_start_monotonic_secs=18,
        setup_secs=1, warmup_secs=1, barrier_secs=1, measurement_secs=15,
        measurement_elapsed_secs=15, drain_secs=3,
        transport_close_start_monotonic_secs=21 if protocol == "http2" else None,
        transport_close_secs=1 if protocol == "http2" else 0,
        transport_close_timed_out=False, timed_out=False))
    return sample


def expected_for(sample):
    protocol = "http2" if sample["protocol"] == "HTTP/2" else "grpcs"
    return expected_sample(manifest(protocol), protocol, sample["pair"], sample["gateway"], sample["payload_size"])


def invocation_fixture(sample):
    start = sample["phases"]["setup_start_unix_secs"]
    return dict(schema=2, identity=capture_identity(sample), start_unix_secs=start - 0.5,
                end_unix_secs=start + 23, exit_code=0)


@contextmanager
def limited_json_recursion():
    previous = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(200)
        yield
    finally:
        sys.setrecursionlimit(previous)


class GuardObservationTests(unittest.TestCase):
    def producer_contract(self, sample=None):
        sample = sample or sample_fixture()
        path = os.environ.get("H2_GUARD_PRODUCER_CONTRACT")
        if path is None:
            self.skipTest("actual h2 producer export is required in the dedicated hosted lane")
        # Missing export in that lane is a failure, never a skipped producer test.
        raw = Path(path).read_text().splitlines()
        messages = [message for message in raw if message.startswith("H2_GUARD_")]
        acks = [message for message in raw if message.startswith("# H2_GUARD_ACK_V2 ")]
        self.assertEqual(len(acks), 3)
        self.assertTrue(messages)
        timestamp = "2026-09-18T00:00:04Z"
        lines = [json.dumps(dict(timestamp=timestamp, target="ferrum_h2_guard",
                                 fields=dict(message=message))) for message in messages]
        boundaries = {}
        gauges = usage()["timeline"][0]["h2_gauges"]["gauges"]
        start = sample["phases"]["setup_start_unix_secs"]
        smoke = start - (30 if sample["protocol"] == "gRPC" and sample["payload_size"] == 71680 else 0) - 3
        for label, ack, at in zip(("smoke", "before", "after"), acks, (smoke, start - 1, start + 24)):
            identity = capture_identity(sample)
            if label == "smoke":
                identity["payload_size"] = 0
            boundaries[label] = dict(schema=2, identity=identity, raw_ack=ack, ack=parse_ack(ack), errors=[],
                start_unix_secs=at, end_unix_secs=at + 0.1,
                sink_samples=[dict(unix_secs=at + 0.05, gauges=gauges)])
        return lines, boundaries

    def observe_contract(self, lines, boundaries, sample=None, invocation=None, expected=None):
        sample = sample if sample is not None else sample_fixture()
        annotate(sample, usage(), lines, boundaries,
                 invocation if invocation is not None else invocation_fixture(sample_fixture()),
                 expected if expected is not None else expected_for(sample_fixture()))
        return sample["h2_guard_observation"]

    def test_actual_producer_live_fixed_failure_refund_and_wrap_contract(self):
        lines, boundaries = self.producer_contract()
        result = self.observe_contract(lines, boundaries)
        self.assertEqual(result["capture_errors"], [])
        self.assertTrue(result["bounded_capture_complete"])
        self.assertFalse(result["full_transition_history_complete"])
        self.assertFalse(result["process_capture_closed"])
        self.assertTrue(any(row["event"] == 3 and row["max"] == 16777216 and row["frames"] > 0
                            for row in result["events"]))
        failure = next(row for row in result["events"] if row["event"] == 1)
        self.assertEqual((failure["pending"], failure["high_pending"], failure["min_credit"]), (129, 129, 127))
        tail = [row for row in result["transitions"] if row["snapshot"] == failure["seq"]]
        self.assertEqual((tail[-1]["consume"], tail[-1]["before"], tail[-1]["after"]), (2, 127, 127))
        self.assertTrue(any(row["kind"] == 2 for row in result["transitions"]))
        self.assertTrue(any(row["kind"] == 3 for row in result["transitions"]))
        self.assertTrue(any(row["kind"] == 1 and row["len"] == 1 and row["flow"] == 4
                            for row in result["transitions"]))
        self.assertTrue(any(row["kind"] == 1 and row["len"] == 512 and row["after"] > row["before"]
                            for row in result["transitions"]))
        self.assertTrue(any(row["kind"] == 2 and row["len"] == 1 and row["delta"] == 0
                            for row in result["transitions"]))
        self.assertTrue(any(row["kind"] == 4 for row in result["transitions"]))
        self.assertTrue(any(row["kind"] == 5 for row in result["transitions"]))
        self.assertTrue(any(row["kind"] == 6 for row in result["transitions"]))

    def test_actual_producer_missing_live_tail_loss_order_generation_and_overflow_fail_closed(self):
        lines, boundaries = self.producer_contract()
        parsed = [parse_line(text) for text in lines]
        for label in ("smoke", "before", "after"):
            missing = copy.deepcopy(boundaries)
            del missing[label]
            self.assertFalse(self.observe_contract(lines, missing)["bounded_capture_complete"])
        initial_only = list(lines)
        for index, record in enumerate(parsed):
            if record.get("event") == 3 and record["generation"] == boundaries["after"]["ack"]["generation"]:
                values = {name: record[name] for name in FIELDS}
                values["frames"] = 0
                initial_only[index] = line(values)
        self.assertIn("missing_successful_or_fixed_live_traffic_state",
                      self.observe_contract(initial_only, boundaries)["capture_errors"])
        wrong_order = dict(boundaries, before=boundaries["after"], after=boundaries["before"])
        self.assertIn("invalid_boundary_generation_order",
                      self.observe_contract(lines, wrong_order)["capture_errors"])
        for marker in ("H2_GUARD_V2", "H2_GUARD_TAIL_V2", "H2_GUARD_FENCE_V2"):
            index = next(i for i, row in enumerate(parsed) if row["record_type"] == marker
                         and (marker != "H2_GUARD_V2" or row["event"] == 3))
            self.assertFalse(self.observe_contract(lines[:index] + lines[index + 1:], boundaries)["bounded_capture_complete"])
        index = next(i for i, row in enumerate(parsed) if row["record_type"] == "H2_GUARD_TAIL_V2")
        for key, value in (("n", 9999), ("generation", 16), ("epoch", 2**64 - 1)):
            changed = list(lines)
            row = {key: parsed[index][key] for key in TAIL_FIELDS}
            row[key] = value
            changed[index] = line(row, marker="H2_GUARD_TAIL_V2")
            self.assertFalse(self.observe_contract(changed, boundaries)["bounded_capture_complete"])
        changed = list(lines)
        changed[index] = changed[index].replace(" kind=", " arbitrary=")
        self.assertFalse(self.observe_contract(changed, boundaries)["bounded_capture_complete"])
        for key in ("memory_overflow", "overflow", "overwritten"):
            changed = list(lines)
            index = next(i for i, row in enumerate(parsed) if row.get("event") == 3)
            row = {name: parsed[index][name] for name in FIELDS}
            row[key] += 1
            changed[index] = line(row)
            self.assertFalse(self.observe_contract(changed, boundaries)["bounded_capture_complete"])
        # A final fence present only in HTTP catches otherwise invisible tail loss.
        fence = boundaries["after"]["ack"]["seq"]
        changed = [text for text, row in zip(lines, parsed) if row["seq"] < fence]
        self.assertIn("unacknowledged_snapshot_delivery:after",
                      self.observe_contract(changed, boundaries)["capture_errors"])
        for key in ("log_stdout_io_write", "log_stderr_shutdown_incomplete_records_total",
                    "log_stdout_queued_records", "log_dropped_stdout_record_too_large"):
            changed = copy.deepcopy(boundaries)
            changed["after"]["sink_samples"][-1]["gauges"][key] = 1
            self.assertFalse(self.observe_contract(lines, changed)["bounded_capture_complete"])

    def test_sink_health_requires_every_counter_and_zero_drain(self):
        gauges = usage()["timeline"][0]["h2_gauges"]["gauges"]
        self.assertEqual(sink_problems(gauges, drained=True), [])
        for key in gauges:
            missing = dict(gauges)
            del missing[key]
            self.assertTrue(sink_problems(missing, drained=True))
        gauges["log_stdout_healthy"] = 0
        self.assertIn("unhealthy_log_sink", sink_problems(gauges))
        for bad in (True, False, float("nan"), float("inf"), -float("inf"), 0.0, 0.5, "0", None):
            for key in ("log_stdout_healthy", "log_dropped_stdout_saturation", "log_stdout_queued_bytes"):
                with self.subTest(key=key, value=bad):
                    changed = dict(usage()["timeline"][0]["h2_gauges"]["gauges"], **{key: bad})
                    self.assertIn("invalid_log_sink_counter", sink_problems(changed))

    def test_actual_producer_requires_canonical_schema_identity_and_workload(self):
        lines, boundaries = self.producer_contract()
        for key, value in (("sample_schema", 1), ("sample_schema", True), ("gateway", "ferrum-exp-fixed"),
                           ("pair", 2), ("pair", True), ("host_id", "other-host"),
                           ("protocol", "gRPC"), ("payload_size", 10240),
                           ("concurrency", 199), ("effective_concurrency", 199), ("duration_secs", 14)):
            with self.subTest(key=key, value=value):
                sample = sample_fixture()
                sample[key] = value
                result = self.observe_contract(lines, boundaries, sample)
                self.assertFalse(result["bounded_capture_complete"])
                self.assertIn("sample_identity_or_workload_mismatch", result["capture_errors"])
                self.assertTrue(any(row["event"] == 1 for row in result["events"]))
        for key in expected_for(sample_fixture()):
            sample = sample_fixture()
            del sample[key]
            self.assertFalse(self.observe_contract(lines, boundaries, sample)["bounded_capture_complete"])

    def test_actual_producer_rejects_missing_malformed_nonfinite_and_reversed_phases(self):
        lines, boundaries = self.producer_contract()
        for phases in (None, {}, [], "phases"):
            sample = dict(sample_fixture(), phases=phases)
            self.assertIn("missing_or_malformed_phases", self.observe_contract(lines, boundaries, sample)["capture_errors"])
        for key in ("setup_start_unix_secs", "measurement_start_unix_secs", "setup_start_monotonic_secs",
                    "warmup_start_monotonic_secs", "measurement_start_monotonic_secs", "drain_start_monotonic_secs",
                    "measurement_secs", "drain_secs", "transport_close_start_monotonic_secs", "transport_close_secs"):
            for bad in (None, True, "1", float("nan"), float("inf"), -1):
                with self.subTest(key=key, value=bad):
                    sample = sample_fixture()
                    sample["phases"][key] = bad
                    self.assertFalse(self.observe_contract(lines, boundaries, sample)["bounded_capture_complete"])
        for key, bad in (("warmup_start_monotonic_secs", 4), ("drain_start_monotonic_secs", 17),
                         ("transport_close_start_monotonic_secs", 20), ("measurement_secs", 14)):
            sample = sample_fixture()
            sample["phases"][key] = bad
            self.assertFalse(self.observe_contract(lines, boundaries, sample)["bounded_capture_complete"])

    def test_actual_producer_requires_typed_ordered_boundary_and_whole_invocation(self):
        lines, boundaries = self.producer_contract()
        for label in ("smoke", "before", "after"):
            for key in ("schema", "start_unix_secs", "end_unix_secs"):
                for bad in (None, True, "2", float("nan"), float("inf"), -1):
                    with self.subTest(label=label, key=key, value=bad):
                        changed = copy.deepcopy(boundaries)
                        changed[label][key] = bad
                        self.assertFalse(self.observe_contract(lines, changed)["bounded_capture_complete"])
            changed = copy.deepcopy(boundaries)
            changed[label]["end_unix_secs"] = changed[label]["start_unix_secs"] - 1
            self.assertFalse(self.observe_contract(lines, changed)["bounded_capture_complete"])
            for key, bad in (("gateway", "ferrum-exp-fixed"), ("pair", 2), ("payload_size", 10240),
                             ("host_id", "other-host"), ("protocol", "gRPC")):
                changed = copy.deepcopy(boundaries)
                changed[label]["identity"][key] = bad
                self.assertFalse(self.observe_contract(lines, changed)["bounded_capture_complete"])
        # After measurement but before drain, close, or client process return.
        for offset in (19, 21.5, 22.5):
            changed = copy.deepcopy(boundaries)
            at = sample_fixture()["phases"]["setup_start_unix_secs"] + offset
            changed["after"].update(start_unix_secs=at, end_unix_secs=at + 0.1)
            changed["after"]["sink_samples"][0]["unix_secs"] = at + 0.05
            self.assertIn("early_after_snapshot", self.observe_contract(lines, changed)["capture_errors"])
        for key, bad in (("schema", True), ("start_unix_secs", float("nan")),
                         ("end_unix_secs", 0), ("exit_code", False)):
            invocation = invocation_fixture(sample_fixture())
            invocation[key] = bad
            self.assertFalse(self.observe_contract(lines, boundaries, invocation=invocation)["bounded_capture_complete"])
        self.assertFalse(self.observe_contract(lines, boundaries, invocation={})["bounded_capture_complete"])

    def write_campaign(self, root, protocol):
        (root / "manifest.json").write_text(json.dumps(manifest(protocol)))
        for pair in range(1, 5):
            cell = root / "pairs" / f"pair_{pair:03d}"
            diagnostics = cell / "diagnostics"
            diagnostics.mkdir(parents=True)
            for gateway in GATEWAYS:
                for size in manifest(protocol)["payload_sizes"]:
                    sample = sample_fixture(gateway, protocol, pair, size)
                    lines, boundaries = self.producer_contract(sample)
                    invocation = invocation_fixture(sample)
                    annotate(sample, usage(), lines, boundaries, invocation, expected_for(sample))
                    (cell / f"{gateway}_{protocol}_{size}.json").write_text(json.dumps(sample))
                    prefix = f"{gateway}_{size}"
                    (diagnostics / (prefix + "_invocation.json")).write_text(json.dumps(invocation))
                    if gateway == "direct":
                        continue
                    (diagnostics / (prefix + ".log")).write_text("\n".join(lines) + "\n")
                    (diagnostics / (prefix + "_process_usage.json")).write_text(json.dumps(usage()))
                    for label, boundary in boundaries.items():
                        name = (gateway if label == "smoke" else prefix) + "_guard_" + label + ".json"
                        (diagnostics / name).write_text(json.dumps(boundary))

    def test_actual_producer_index_reconciles_both_matrices_and_rejects_missing_ack(self):
        for protocol, count in (("http2", 12), ("grpcs", 24)):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.write_campaign(root, protocol)
                verify_campaign(root, protocol)
                report = json.loads((root / "guard-evidence-index.json").read_text())
                self.assertEqual(len(report["samples"]), count)
                self.assertTrue(all(row["total_errors"] == 148 for row in report["samples"]))
                self.assertTrue(all(not row["validation_failures"] for row in report["samples"]))
                (root / "pairs/pair_004/diagnostics/ferrum_71680_guard_after.json").unlink()
                with self.assertRaises(ValueError):
                    verify_campaign(root, protocol)
                report = json.loads((root / "guard-evidence-index.json").read_text())
                self.assertEqual(len(report["samples"]), count)
                missing = next(row for row in report["samples"] if row["expected"]["pair"] == 4
                               and row["expected"]["gateway"] == "ferrum"
                               and row["expected"]["payload_size"] == 71680)
                self.assertIsNone(missing["raw_sha256"]["after"])
                self.assertTrue(any("after:FileNotFoundError" in error for error in missing["validation_failures"]))

    def test_actual_producer_corrupt_first_cell_does_not_stop_later_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_campaign(root, "http2")
            first = root / "pairs/pair_001/direct_http2_71680.json"
            original = first.read_text()
            for contents in ("{", "[]", "null", None):
                with self.subTest(contents=contents):
                    if contents is None:
                        first.unlink()
                    else:
                        first.write_text(contents)
                    with self.assertRaises(ValueError):
                        verify_campaign(root, "http2")
                    report = json.loads((root / "guard-evidence-index.json").read_text())
                    self.assertEqual(len(report["samples"]), 12)
                    self.assertTrue(report["samples"][0]["validation_failures"])
                    self.assertFalse(report["samples"][-1]["validation_failures"])
                    self.assertTrue(report["samples"][-1]["raw_sha256"]["after"])
                    self.assertEqual(report["samples"][-1]["recomputed_capture_errors"], [])
                    first.write_text(original)

    def assert_campaign_hashes(self, root, report, count):
        self.assertEqual(report["expected_samples"], count)
        self.assertEqual(len(report["samples"]), count)
        self.assertEqual(report["manifest_sha256"], hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest())
        for row in report["samples"]:
            path = root / row["path"]
            self.assertEqual(row["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            gateway, size = row["expected"]["gateway"], row["expected"]["payload_size"]
            prefix = f"{gateway}_{size}"
            names = {"invocation": prefix + "_invocation.json"}
            if gateway != "direct":
                names.update(log=prefix + ".log", usage=prefix + "_process_usage.json",
                             smoke=gateway + "_guard_smoke.json",
                             before=prefix + "_guard_before.json", after=prefix + "_guard_after.json")
            self.assertEqual(set(row["raw_sha256"]), set(names))
            for label, name in names.items():
                self.assertEqual(row["raw_sha256"][label],
                                 hashlib.sha256((path.parent / "diagnostics" / name).read_bytes()).hexdigest())

    def test_actual_producer_recursive_first_instrumented_log_retains_both_matrices(self):
        # C JSON decoders vary by interpreter. Use the real stdlib recursive
        # scanner with a bounded stack for this envelope only, never a model of
        # annotate or a mock that merely raises the desired exception.
        decoder = json.JSONDecoder()
        decoder.scan_once = json.scanner.py_make_scanner(decoder)
        original_loads = json.loads
        recursive = ('{"timestamp":"2026-09-18T00:00:04Z","target":"ferrum_h2_guard",'
                     '"fields":{"message":"H2_GUARD_V2"},"recursive_log_probe":'
                     + "[" * 1200 + "0" + "]" * 1200 + "}")
        self.assertLess(len(recursive), 8192)
        for protocol, count in (("http2", 12), ("grpcs", 24)):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.write_campaign(root, protocol)
                size = manifest(protocol)["payload_sizes"][0]
                path = root / "pairs/pair_001" / f"ferrum_{protocol}_{size}.json"
                log = path.parent / "diagnostics" / f"ferrum_{size}.log"
                good_lines = log.read_text().splitlines()
                lines = good_lines[:1] + [recursive] + good_lines[1:]
                log.write_text("\n".join(lines) + "\n")
                sample = json.loads(path.read_text())
                expected_observation = sample["h2_guard_observation"]
                _, boundaries = self.producer_contract(sample)
                recursions = []

                def loads(value, *args, **kwargs):
                    if isinstance(value, str) and '"recursive_log_probe":' in value:
                        with limited_json_recursion():
                            try:
                                return decoder.decode(value)
                            except RecursionError:
                                recursions.append(True)
                                raise
                    return original_loads(value, *args, **kwargs)

                with mock.patch("h2_guard_observation.json.loads", side_effect=loads):
                    annotate(sample, usage(), lines, boundaries, invocation_fixture(sample), expected_for(sample))
                    actual = sample["h2_guard_observation"]
                    self.assertEqual(actual["capture_errors"], ["malformed_guard_record"])
                    self.assertFalse(actual["bounded_capture_complete"])
                    for bucket in ("events", "transitions", "fences", "measurement_failures"):
                        self.assertEqual(actual[bucket], expected_observation[bucket])
                    with self.assertRaisesRegex(ValueError, "campaign evidence incomplete"):
                        verify_campaign(root, protocol)
                self.assertEqual(len(recursions), 2)  # annotation and raw reconciliation
                report = json.loads((root / "guard-evidence-index.json").read_text())
                self.assert_campaign_hashes(root, report, count)
                for row in report["samples"]:
                    if row["path"] == str(path.relative_to(root)):
                        self.assertEqual(row["recomputed_capture_errors"], ["malformed_guard_record"])
                        self.assertIn("malformed_guard_record", row["validation_failures"])
                        self.assertEqual(row["recomputed_measurement_failures"], expected_observation["measurement_failures"])
                    else:
                        self.assertEqual(row["validation_failures"], [])
                        self.assertEqual(row["recomputed_capture_errors"], [])

    def test_actual_producer_row_recursion_safety_boundary_retains_both_matrices(self):
        # Exercise the outer safety net independently of the per-line handler:
        # a real recursive stdlib encoder fails while normalizing a deep raw
        # invocation retained by annotate. All later rows still reconcile.
        encoder = json.JSONEncoder()
        original_dumps = json.dumps
        for protocol, count in (("http2", 12), ("grpcs", 24)):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.write_campaign(root, protocol)
                size = manifest(protocol)["payload_sizes"][0]
                path = root / "pairs/pair_001" / f"ferrum_{protocol}_{size}.json"
                invocation = path.parent / "diagnostics" / f"ferrum_{size}_invocation.json"
                invocation.write_text(invocation.read_text()[:-1] + ',"recursive_row_probe":'
                                      + "[" * 300 + "0" + "]" * 300 + "}")
                recursions = []

                def dumps(value, *args, **kwargs):
                    if isinstance(value, dict) and "recursive_row_probe" in value.get("invocation", {}):
                        with limited_json_recursion():
                            try:
                                return "".join(encoder.iterencode(value))
                            except RecursionError:
                                recursions.append(True)
                                raise
                    return original_dumps(value, *args, **kwargs)

                with mock.patch("verify.json.dumps", side_effect=dumps):
                    with self.assertRaisesRegex(ValueError, "campaign evidence incomplete"):
                        verify_campaign(root, protocol)
                self.assertEqual(len(recursions), 1)
                report = json.loads((root / "guard-evidence-index.json").read_text())
                self.assert_campaign_hashes(root, report, count)
                for row in report["samples"]:
                    if row["path"] == str(path.relative_to(root)):
                        self.assertTrue(any(error.startswith("raw_capture_reconciliation_failed:RecursionError:")
                                            for error in row["validation_failures"]))
                    else:
                        self.assertEqual(row["validation_failures"], [])
                        self.assertEqual(row["recomputed_capture_errors"], [])

    def test_actual_producer_index_rejects_copied_cells_and_retains_all_raw_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_campaign(root, "grpcs")
            target = root / "pairs/pair_001/ferrum_grpcs_71680.json"
            original = target.read_text()
            for source in ("pair_002/ferrum_grpcs_71680.json", "pair_001/ferrum-exp-fixed_grpcs_71680.json",
                           "pair_001/ferrum_grpcs_10240.json"):
                with self.subTest(source=source):
                    target.write_text((root / "pairs" / source).read_text())
                    with self.assertRaises(ValueError):
                        verify_campaign(root, "grpcs")
                    report = json.loads((root / "guard-evidence-index.json").read_text())
                    failed = next(row for row in report["samples"] if row["path"] == str(target.relative_to(root)))
                    self.assertIn("sample_identity_or_workload_mismatch", failed["validation_failures"])
                    self.assertEqual(failed["total_errors"], 148)
                    self.assertEqual(len(report["samples"]), 24)
            target.write_text(original)
            diagnostics = target.parent / "diagnostics"
            (diagnostics / "ferrum_71680_process_usage.json").write_text("{")
            (diagnostics / "ferrum_71680_guard_before.json").write_text("[]")
            (diagnostics / "ferrum_71680_guard_after.json").unlink()
            with self.assertRaises(ValueError):
                verify_campaign(root, "grpcs")
            report = json.loads((root / "guard-evidence-index.json").read_text())
            failed = next(row for row in report["samples"] if row["path"] == str(target.relative_to(root)))
            for label in ("usage", "before", "after"):
                self.assertTrue(any(error.startswith(label + ":") for error in failed["validation_failures"]))
            self.assertTrue(failed["raw_sha256"]["log"])
            self.assertTrue(failed["raw_sha256"]["usage"])
            self.assertTrue(failed["raw_sha256"]["before"])
            self.assertFalse(report["samples"][-1]["validation_failures"])

    def test_actual_producer_index_binds_manifest_and_rejects_forged_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_campaign(root, "http2")
            path = root / "pairs/pair_001/ferrum_http2_71680.json"
            original = json.loads(path.read_text())
            for key, bad in (("schema", 2.0), ("bounded_capture_complete", 1),
                             ("suppression_observed", 0), ("sink_loss_observed", 0)):
                sample = copy.deepcopy(original)
                sample["h2_guard_observation"][key] = bad
                path.write_text(json.dumps(sample))
                with self.assertRaises(ValueError):
                    verify_campaign(root, "http2")
            path.write_text(json.dumps(original))
            for key, bad in (("host_id", "other-host"), ("sample_schema", 1), ("pairs", True),
                             ("payload_sizes", [10240]), ("gateways", ["direct", "ferrum"])):
                changed = dict(manifest(), **{key: bad})
                (root / "manifest.json").write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    verify_campaign(root, "http2")
                report = json.loads((root / "guard-evidence-index.json").read_text())
                self.assertEqual(len(report["samples"]), 12)

    def test_missing_manifest_samples_and_raw_files_retain_every_expected_cell(self):
        for protocol, count in (("http2", 12), ("grpcs", 24)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaises(ValueError):
                    verify_campaign(root, protocol)
                report = json.loads((root / "guard-evidence-index.json").read_text())
                self.assertEqual(len(report["samples"]), count)
                self.assertTrue(all(not row["sample_present"] and row["validation_failures"]
                                    for row in report["samples"]))
                self.assertTrue(all(row["sha256"] is None for row in report["samples"]))
                self.assertTrue(all("invocation" in row["raw_sha256"] for row in report["samples"]))

    def test_lint_gate_rejects_new_changed_duplicate_and_incomplete_diagnostics(self):
        warning = dict(reason="compiler-message", message=dict(
            level="warning", code=dict(code="clippy::question_mark"), message="use ?",
            spans=[dict(is_primary=True, file_name="src/upstream.rs", line_start=1,
                        text=[dict(text="match existing {}")])]))
        completed = dict(reason="build-finished", success=True)
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / "before", Path(directory) / "after"

            def write(path, records):
                path.write_text("".join(json.dumps(record) + "\n" for record in records))

            write(before, [warning, completed])
            shifted = copy.deepcopy(warning)
            shifted["message"]["spans"][0]["line_start"] = 99
            write(after, [shifted, completed])
            self.assertEqual(compare(before, after)["new_diagnostics"], 0)
            write(after, [completed])
            self.assertEqual(compare(before, after)["new_diagnostics"], 0)
            changed = copy.deepcopy(warning)
            changed["message"]["spans"][0]["text"][0]["text"] = "match observation {}"
            error = copy.deepcopy(warning)
            error["message"]["level"] = "error"
            unclassified = copy.deepcopy(warning)
            unclassified["message"]["code"] = None
            for records in ([changed, completed], [warning, warning, completed],
                            [error, completed], [unclassified, completed], [warning],
                            [dict(reason="build-finished", success=False)]):
                write(after, records)
                with self.assertRaises(ValueError):
                    compare(before, after)

    def sample(self):
        return dict(sample_fixture(), total_errors=361)

    def test_fixed_schema_and_branch_identity_do_not_copy_arbitrary_fields(self):
        for branch in (1, 2, 3, 4, 5):
            record = parse_line(line(row(event=1, branch=branch, reason=11)))
            self.assertEqual(record["branch"], branch)
        malformed = row()
        malformed["secret"] = "do-not-retain"
        with self.assertRaises(ValueError):
            parse_line(line(malformed))
        with self.assertRaises(ValueError):
            parse_line(line(row(branch=6)))
        for malformed in [
            '["H2_GUARD_V1"]',
            json.dumps(dict(target="ferrum_h2_guard", fields=dict(message=["H2_GUARD_V1"]))),
            line(row(byte_available=-(2**63) - 1)),
        ]:
            with self.assertRaises(ValueError):
                parse_line(malformed)
        message = line(row()).replace('"fields": {', '"peer": "do-not-retain", "fields": {')
        self.assertNotIn("do-not-retain", str(parse_line(message)))
        self.assertIsNone(parse_line(line(row()).replace('"ferrum_h2_guard"', '"another_target"')))

    def test_failures_and_all_phases_retained_without_cross_hop_inference(self):
        sample = self.sample()
        rows = [line(row(seq=1), "2026-09-17T23:59:59Z"),
                line(row(seq=2, event=1, branch=2, reason=11, empty=101)),
                line(row(seq=3, event=2), "2026-09-18T00:00:20Z")]
        annotate(sample, usage(), rows, invocation=invocation_fixture(sample), expected=expected_for(sample))
        observation = sample["h2_guard_observation"]
        self.assertEqual([r["phase"] for r in observation["events"]],
                         ["before_sample", "measurement", "drain"])
        self.assertEqual(observation["measurement_failures"], [2])
        self.assertEqual(observation["capture_errors"], [
            "missing_or_malformed_boundary:after", "missing_or_malformed_boundary:before",
            "missing_or_malformed_boundary:smoke"])
        self.assertEqual(sample["total_errors"], 361)
        self.assertIn("instrumented H2 guard build: diagnostic only", sample_issues(sample))

    def test_missing_malformed_and_suppressed_logs_are_not_zero_failure_proof(self):
        sample = self.sample()
        limits = line(dict(seq=3, scope=3, suppressed=8), marker="H2_GUARD_LIMIT_V1")
        annotate(sample, {}, [line(row()), limits, "H2_GUARD_V1 malformed"])
        observation = sample["h2_guard_observation"]
        self.assertTrue(observation["suppression_observed"])
        self.assertTrue(observation["suppression_counts_are_lower_bounds"])
        self.assertEqual(observation["missing_sequence_count"], 1)
        self.assertIn("malformed_guard_record", observation["capture_errors"])
        self.assertIn("missing_log_sink_loss_counters", observation["capture_errors"])
        annotate(sample, usage(), [])
        self.assertIn("missing_client_role_observation", sample["h2_guard_observation"]["capture_errors"])
        annotate(dict(sample, gateway="direct"), {}, [])

    def test_sampled_logger_loss_and_duplicate_records_remain_visible(self):
        sample = self.sample()
        capture = usage()
        capture["timeline"][0]["h2_gauges"]["gauges"]["log_dropped_stdout_saturation"] = 3
        annotate(sample, capture, [line(row()), line(row())])
        self.assertTrue(sample["h2_guard_observation"]["sink_loss_observed"])
        self.assertIn("malformed_guard_record", sample["h2_guard_observation"]["capture_errors"])
        metrics = ('ferrum_connection_pool_entries{pool="http2"} 1\n'
                   'ferrum_connection_pool_entries{pool="grpc"} 2\n'
                   'ferrum_overload_active_connections 21\n'
                   'ferrum_log_sink_dropped_records_total{sink="stdout",reason="saturation"} 3\n')
        self.assertEqual(parse_gauges(metrics)["log_dropped_stdout_saturation"], 3)

    def test_exported_loss_metric_family_is_retained_and_missing_counters_fail_closed(self):
        # These are the labels emitted by src/logging/mod.rs::render_prometheus.
        gauges = ('ferrum_connection_pool_entries{pool="http2"} 1\n'
                  'ferrum_connection_pool_entries{pool="grpc"} 2\n'
                  'ferrum_overload_active_connections 21\n')
        losses = (
            'ferrum_log_sink_dropped_records_total{sink="stdout",reason="saturation"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stdout",reason="record_too_large"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stdout",reason="closed"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stderr",reason="saturation"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stderr",reason="record_too_large"} 0\n'
            'ferrum_log_sink_dropped_records_total{sink="stderr",reason="closed"} 0\n'
        )

        def observe(metrics):
            capture = usage()
            capture["timeline"][0]["h2_gauges"]["gauges"] = parse_gauges(gauges + metrics)
            sample = self.sample()
            annotate(sample, capture, [line(row())])
            return sample["h2_guard_observation"]

        observation = observe(losses)
        self.assertIn("missing_log_sink_health_counters", observation["capture_errors"])
        self.assertFalse(observation["sink_loss_observed"])
        self.assertEqual(len(observation["sink_loss_samples"][0]), 7)  # timestamp + six counters
        for sink in ("stdout", "stderr"):
            with self.subTest(sink=sink):
                label = f'sink="{sink}",reason="record_too_large"'
                positive = losses.replace(label + '} 0', label + '} 2')
                observation = observe(positive)
                self.assertIn("missing_log_sink_health_counters", observation["capture_errors"])
                self.assertTrue(observation["sink_loss_observed"])
                self.assertEqual(observation["sink_loss_samples"][0][
                    f"log_dropped_{sink}_record_too_large"], 2)
        for missing in losses.splitlines(keepends=True):
            with self.subTest(missing=missing):
                observation = observe(losses.replace(missing, ""))
                self.assertIn("missing_log_sink_loss_counters", observation["capture_errors"])
                self.assertFalse(observation["sink_loss_observed"])

    def test_explicit_manifest_does_not_enable_original_campaign(self):
        old = json.loads((ROOT / "experiment.json").read_text())
        self.assertFalse(old["enabled"])
        plan = load_experiment(ROOT / "h2_guard/experiment.json", "http2")
        self.assertEqual(plan["h2_guard_observation"], 1)
        self.assertEqual(plan["h2_campaign"]["concurrency"], 200)
        self.assertEqual(plan["h2_campaign"]["duration"], 15)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            for bad in ("warn,h2=trace", "warn,ferrum_h2_guard=debug"):
                changed = copy.deepcopy(plan)
                changed["arms"][0]["FERRUM_EXTRA_ENV"] = "FERRUM_LOG_LEVEL=" + bad
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    load_experiment(path, "http2")

    def test_archive_patch_and_asset_identities_fail_closed(self):
        assets = ROOT / "h2_guard"
        provenance = json.loads((assets / "source.json").read_text())
        self.assertEqual(provenance["sha256"], SHA256)
        self.assertEqual(hashlib.sha256((assets / "h2-0.4.19.patch").read_bytes()).hexdigest(),
                         provenance["patch_sha256"])
        for name, digest in provenance["assets"].items():
            self.assertEqual(hashlib.sha256((assets / name).read_bytes()).hexdigest(), digest)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            with self.assertRaises(ValueError):
                extract_source(b"not the approved crate", source)
            bad = dict(provenance, patch_sha256="0" * 64)
            with self.assertRaises(ValueError):
                patch_source(source, bad)
            for name in provenance["files"]:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("drift")
            with self.assertRaises(ValueError):
                patch_source(source, provenance)
            # Ferrum's vendored h2 patch must apply without fuzz and reproduce
            # the drift-manifest sources exactly; anything else fails closed.
            with self.assertRaises(ValueError):
                apply_ferrum_patch(source, ROOT.parents[2])
        # A tree the patch applies to cleanly but that then differs from the
        # drift manifest (here: one extra source file) also fails closed.
        repo = ROOT.parents[2]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            shutil.copytree(repo / "vendor/h2-0.4.19-ferrum-patched/src", source / "src")
            patch = (repo / "docs/upstream-h2-patches/001-coalesce-data-frame-writes"
                     / "h2-coalesce-data-frame-writes.patch").read_bytes()
            subprocess.run(["patch", "--batch", "--fuzz=0", "-R", "-p1"], input=patch,
                           cwd=source, check=True, capture_output=True)
            (source / "src/extra.rs").write_text("// not in the vendored crate\n")
            with self.assertRaisesRegex(ValueError, "differs from the vendored"):
                apply_ferrum_patch(source, repo)

    def test_campaign_index_keeps_failed_repetitions_and_rejects_missing_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pair in range(1, 5):
                path = root / "pairs" / f"pair_{pair:03d}"
                path.mkdir(parents=True)
                for gateway in ("direct", "ferrum", "ferrum-exp-fixed"):
                    sample = dict(effective_concurrency=200, total_errors=361 if pair == 1 else 0,
                                  h2_guard_observation=dict(schema=2, capture_errors=[], bounded_capture_complete=True,
                                      suppression_observed=False, sink_loss_observed=False))
                    (path / f"{gateway}_http2_71680.json").write_text(json.dumps(sample))
            # Completeness booleans without raw live snapshots cannot certify a campaign.
            with self.assertRaises(ValueError):
                verify_campaign(root, "http2")
            report = json.loads((root / "guard-evidence-index.json").read_text())
            self.assertEqual(len(report["samples"]), 12)
            self.assertEqual(report["samples"][0]["total_errors"], 361)
            (root / "pairs/pair_004/ferrum_http2_71680.json").unlink()
            with self.assertRaises(ValueError):
                verify_campaign(root, "http2")
            report = json.loads((root / "guard-evidence-index.json").read_text())
            self.assertEqual(len(report["samples"]), 12)
            missing = next(row for row in report["samples"]
                           if row["path"] == "pairs/pair_004/ferrum_http2_71680.json")
            self.assertFalse(missing["sample_present"])
            self.assertIsNone(missing["sha256"])
            self.assertTrue(missing["validation_failures"])
            self.assertEqual(report["samples"][0]["total_errors"], 361)


if __name__ == "__main__":
    unittest.main()
