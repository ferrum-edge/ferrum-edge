"""Fixed128-cell confirmation contracts; synthetic files only, no builds/Docker."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("tail_confirmation", ROOT / ".github/scripts/mesh_tail_confirmation.py")
lane = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lane
spec.loader.exec_module(lane)


def good_sample(block, cell):
    payload, cc = block["payload_size"], block["effective_concurrency"]
    sample = dict(gateway="ferrum", protocol="http1", mesh="ferrum", payload_size=payload,
                  duration_secs=30, concurrency=cc, total_requests=3000, total_bytes=3000 * payload,
                  total_errors=0, warmup_requests=cc, warmup_errors=0, rps=100,
                  p50_us=100, p95_us=200, p99_us=300, latency_max_us=400)
    if block["scenario"].startswith("mesh"):
        sample.update(cohort_requests=3002, cohort_p50_us=110, cohort_p95_us=210,
                      cohort_p99_us=310, cohort_latency_max_us=410, drained_requests=2, drained_bytes=2 * payload)
    else:
        sample.pop("mesh")
        sample.update(gateway=cell["arm"], protocol="HTTP/1.1+TLS" if block["scenario"] == "http1-tls" else "HTTP/2",
                      target="https://127.0.0.1:8443/echo", sample_schema=2, effective_concurrency=50,
                      pair=block["pair"], host_id="one-boot", order_position=block["members"].index(cell) + 1,
                      gateway_order=[item["arm"] for item in block["members"]], drain_requests=2, drain_bytes=2 * payload,
                      phases=dict(measurement_secs=30, measurement_elapsed_secs=30.01, timed_out=False),
                      observed=dict(samples=100, workers_at_barrier=50, workers_retired_before_deadline=0),
                      process_usage=dict(processes=[dict(role="client")], measurement=[
                          dict(role=role, complete_bracket=True, cpu_seconds=3, boundary_slack_secs=0.4,
                               bracket_secs=30.4, peak_rss_bytes=4096) for role in ("client", "backend", "gateway")]))
        for field in ("active_workers", "active_connections", "active_streams", "queued_requests"):
            sample["observed"][field] = dict(min=0, mean=50, max=50)
    return sample


class TailConfirmation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.source = dict(baseline_sha=lane.BASELINE, candidate_sha=lane.CANDIDATE,
                           harness_sha="c" * 40, profile="release", features="cloud-secrets",
                           image_ids={"baseline": "sha256:" + "a" * 64, "candidate": "sha256:" + "b" * 64,
                                      "tools": "sha256:" + "c" * 64})
        self.blocks = [lane.identity(block, self.source, "a" * 32, "one-boot") for block in lane.blocks()]
        self.plan = dict(source=self.source, blocks=self.blocks, planned_cells=128,
                         state="completed", cleanup_complete=True, errors=[],
                         image_users={role: dict(uid=65532, gid=65532) for role in ("baseline", "candidate")})
        lane.write(self.output / "plan.json", self.plan)
        self.samples = []
        for block in self.blocks:
            directory = self.output / block["directory"]
            status = dict(state="completed", exit_code=0, cleanup_errors=[])
            lane.write(directory / "identity.json", block)
            lane.write(directory / "status.json", status)
            if not block["scenario"].startswith("mesh"):
                lane.write(directory / "protocol/status.json", status)
                lane.write(directory / "protocol/manifest.json", dict(
                    gateways=["ferrum", "ferrum-baseline"], pairs=1, tail_confirm_pair=block["pair"],
                    duration=30, payload_sizes=[1048576], host_id="one-boot", baseline_image=self.source["image_ids"]["baseline"],
                    h2_window="default", h2_observation_enabled=False))
            for cell in block["members"]:
                if block["scenario"].startswith("mesh"):
                    root = directory / cell["leg"]
                    path = root / f"ferrum_http1_{block['payload_size']}.json"
                    lane.write(root / "status.json", status)
                    lane.write(root / "ferrum_arm_status.json", dict(mesh="ferrum", status="ready"))
                    lane.write(root / "ferrum_manifest.json", dict(mesh="ferrum", payload_sizes=[block["payload_size"]]))
                    lane.write(path.with_suffix(".resources.json"), dict(
                        valid=True, errors=[], elapsed_seconds=30.01, proxy_cpu_seconds=6,
                        host_cpu_steal_percent=0, rss_samples=300, proxy_rss_bytes_peak=8192, proxy_rss_bytes_mean=4096,
                        containers=[dict(image_id=cell["image_id"]), dict(image_id=cell["image_id"])]))
                else:
                    root = directory / "protocol/pairs" / f"pair_{block['pair']:03d}"
                    path = root / f"{cell['arm']}_{block['scenario']}_1048576.json"
                    runtime = root / "diagnostics" / f"{cell['arm']}_runtime.json"
                    runtime.parent.mkdir(parents=True, exist_ok=True)
                    runtime.write_text(json.dumps([dict(Image=cell["image_id"], Config=dict(User="65532:65532"),
                                                       HostConfig=dict(GroupAdd=["65532"]))]))
                lane.write(path, good_sample(block, cell))
                self.samples.append((block, cell, path))

    def test_all128_cells_and_all8_pairs_retained_with_separate_latency_scope(self):
        report = lane.check(self.output)
        self.assertTrue(report["data_valid"], report["issues"])
        self.assertEqual(report["observed_cells"], 128)
        self.assertEqual(len(report["comparisons"]), 64)
        self.assertTrue(all(len(item["pairs"]) == 8 for item in report["comparisons"]))
        self.assertIn("full admitted-cohort", report["latency_scope"])
        self.assertIn("no equivalence", report["performance_gate"])
        aa = [row for row in report["observations"] if row["phase"] == "aa"]
        self.assertTrue(all(row["source_sha"] == lane.BASELINE and row["actual_image_id"] == self.source["image_ids"]["baseline"] for row in aa))

    def test_schedule_keeps_pairs_adjacent_and_crossbalances_three_orders(self):
        plan = lane.blocks()
        self.assertEqual(len(plan), 64)
        self.assertEqual([cell["ordinal"] for block in plan for cell in block["members"]], list(range(1, 129)))
        for scenario in lane.SCENARIOS:
            for phase in ("aa", "ab"):
                selected = [block for block in plan if block["scenario"] == scenario and block["phase"] == phase]
                self.assertEqual([block["pair"] for block in selected], list(range(1, 9)))
                self.assertEqual(sum(block["members"][0]["leg"] == "reference" for block in selected), 4)
                for parity in (0, 1):
                    self.assertEqual(sum(block["members"][0]["leg"] == "reference" for block in selected if block["pair"] % 2 == parity), 2)
        self.assertEqual([b["phase"] for b in plan[:2]], ["aa", "ab"])
        self.assertEqual([b["phase"] for b in plan[8:10]], ["ab", "aa"])
        self.assertEqual(plan[0]["scenario"], "mesh-1m")
        self.assertEqual(plan[8]["scenario"], "http2")

    def test_missing_or_bad_repetition_cannot_hide_behind_valid_pairs(self):
        block, cell, path = self.samples[0]
        original = lane.read(path)
        for update in (dict(duration_secs=29), dict(concurrency=25), dict(total_errors=1),
                       dict(warmup_errors=1), dict(cohort_requests=3000)):
            lane.write(path, dict(original, **update))
            self.assertFalse(lane.check(self.output)["data_valid"])
        path.unlink()
        report = lane.check(self.output)
        self.assertFalse(report["data_valid"])
        self.assertEqual(len(report["observations"]), 128)

    def test_wrong_aa_runtime_source_or_digest_is_fatal(self):
        modified = copy.deepcopy(self.plan)
        modified["blocks"][0]["members"][0]["runtime_source_sha"] = lane.CANDIDATE
        lane.write(self.output / "plan.json", modified)
        self.assertFalse(lane.check(self.output)["data_valid"])
        lane.write(self.output / "plan.json", self.plan)
        block, cell, path = self.samples[0]
        resources = path.with_suffix(".resources.json")
        record = lane.read(resources)
        record["containers"][0]["image_id"] = self.source["image_ids"]["candidate"]
        lane.write(resources, record)
        self.assertFalse(lane.check(self.output)["data_valid"])

    def test_gateway_drain_counts_and_cpu_slack_are_required(self):
        block, cell, path = next(item for item in self.samples if item[0]["scenario"] == "http2")
        original = lane.read(path)
        for mutation in ("drain_requests", "boundary_slack_secs"):
            value = copy.deepcopy(original)
            if mutation == "drain_requests":
                value.pop(mutation)
            else:
                value["process_usage"]["measurement"][-1].pop(mutation)
            lane.write(path, value)
            self.assertFalse(lane.check(self.output)["data_valid"])

    def test_bad_resource_brackets_stay_invalid_observations_without_aborting_report(self):
        block, cell, path = self.samples[0]
        resource_path = path.with_suffix(".resources.json")
        original = lane.read(resource_path)
        for field, value in (("elapsed_seconds", 60), ("proxy_cpu_seconds", float("inf")),
                             ("host_cpu_steal_percent", float("nan")), ("proxy_rss_bytes_peak", -1)):
            resource_path.write_text(json.dumps(dict(original, **{field: value})))
            report = lane.check(self.output)
            self.assertFalse(report["data_valid"])
            self.assertEqual(len(report["observations"]), 128)
        lane.write(resource_path, original)
        block, cell, path = next(item for item in self.samples if item[0]["scenario"] == "http2")
        raw = lane.read(path)
        raw["process_usage"]["measurement"][-1]["boundary_slack_secs"] = float("nan")
        path.write_text(json.dumps(raw))
        report = lane.check(self.output)
        self.assertFalse(report["data_valid"])
        self.assertEqual(len(report["observations"]), 128)

    def test_fixed_build_refs_and_workflow_caps(self):
        shell = (ROOT / ".github/scripts/mesh_tail_confirmation.sh").read_text()
        workflow = (ROOT / ".github/workflows/mesh-runtime-benchmark.yml").read_text()
        self.assertIn("candidate=" + lane.CANDIDATE, shell)
        self.assertIn("baseline=" + lane.BASELINE, shell)
        self.assertIn("for role in baseline candidate", shell)
        self.assertIn("--build-arg CARGO_PROFILE=release --build-arg FEATURES=cloud-secrets", shell)
        self.assertNotIn("bench-h1-profile", shell)
        for minutes in (240, 120, 100):
            self.assertIn(f"timeout-minutes: {minutes}", workflow)
        self.assertNotIn("workflow_run:", workflow)


if __name__ == "__main__":
    unittest.main()
