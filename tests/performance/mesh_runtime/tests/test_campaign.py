import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


campaign = module("campaign", ROOT / ".github/scripts/mesh_runtime_campaign.py")
resources = module("resources", Path(__file__).resolve().parents[1] / "collect_resources.py")
protocol = module("protocol", Path(__file__).resolve().parents[1] / "verify_consul_protocol.py")
summary = module("summary", ROOT / ".github/scripts/summarize_mesh_runtime_results.py")


class Contracts(unittest.TestCase):
    def test_plan_balances_pairs_and_retains_every_cell(self):
        cells = campaign.plan(["direct", "ferrum", "envoy"], [1024, 10240], 3, True)
        self.assertEqual(len(cells), 24)
        for repetition in (1, 2, 3):
            block = [c for c in cells if c["repetition"] == repetition]
            for payload in (1024, 10240):
                arms = [c["arm"] for c in block if c["payload"] == payload]
                expected = ["ferrumbaseline", "ferrum"] if repetition % 2 else ["ferrum", "ferrumbaseline"]
                start = arms.index(expected[0])
                self.assertEqual(arms[start:start + 2], expected)
                self.assertEqual(set(arms), {"direct", "ferrum", "ferrumbaseline", "envoy"})

    def test_proc_stat_handles_parenthesized_comm(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            (proc / "123").mkdir()
            tail = ["0"] * 22
            tail[0], tail[11], tail[12], tail[19], tail[21] = "S", "20", "3", "90", "7"
            (proc / "123/stat").write_text("123 (worker ) odd) " + " ".join(tail))
            snapshot = resources.process_snapshot(123, proc)
            self.assertEqual(snapshot["starttime"], 90)
            self.assertEqual(snapshot["cpu_ticks"], 23)
            self.assertGreater(snapshot["rss_bytes"], 0)

    def test_consul_http_requires_live_http_filters_in_both_proxies(self):
        tcp = {"name": "envoy.filters.network.tcp_proxy"}
        http = {"name": "envoy.filters.network.http_connection_manager"}
        def active(port, filter):
            return {"active_state": {"listener": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": port}},
                "filter_chains": [{"filters": [filter]}]}}}
        l4 = [active(15101, tcp), active(21000, tcp)]
        l7 = [active(15101, http), active(21000, http)]
        self.assertTrue(protocol.verify("consul", l4)["accepted"])
        self.assertFalse(protocol.verify("consulhttp", l4)["accepted"])
        self.assertTrue(protocol.verify("consulhttp", l7)["accepted"])
        self.assertFalse(protocol.verify("consul", l7)["accepted"])
        self.assertFalse(protocol.verify("consulhttp", [l7[0], l4[1]])["accepted"])
        wrong_port = [active(21001, http), active(21000, http)]
        self.assertFalse(protocol.verify("consulhttp", wrong_port)["accepted"])
        warming = [{"warming_state": l7[0]["active_state"]}, l7[1]]
        self.assertFalse(protocol.verify("consulhttp", warming)["accepted"])
        mixed = [{"configs": [l4[0], active(21001, http)]}, l7[1]]
        self.assertFalse(protocol.verify("consulhttp", mixed)["accepted"])

    def test_missing_repetition_cannot_be_hidden_by_another_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "campaign.json").write_text(json.dumps({
                "cells": campaign.plan(["ferrum"], [1024], 3, True),
                "duration": 10, "concurrency": 100,
            }))
            collected = summary.collect(root)
            self.assertEqual(len(collected["warnings"]), 6)
            self.assertNotEqual(summary.check_acceptance(collected), 0)

    def test_malformed_or_wrong_identity_repetition_fails_acceptance(self):
        for bad in ("{truncated", '{"mesh":"envoy","gateway":"envoy","payload_size":1024,"rps":2,"total_errors":0}'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for repetition, value in [(1, '{"mesh":"ferrum","gateway":"ferrum","payload_size":1024,"rps":2,"total_errors":0}'), (2, bad)]:
                    directory = root / f"run_{repetition}"
                    directory.mkdir()
                    (directory / "ferrum_manifest.json").write_text('{"mesh":"ferrum","payload_sizes":[1024]}')
                    (directory / "ferrum_http1_1024.json").write_text(value)
                collected = summary.collect(root)
                self.assertNotEqual(summary.check_acceptance(collected), 0)

    def write_campaign(self, root, payloads=(1024,), concurrency=100):
        cells = campaign.plan(["ferrum"], payloads, 2, False)
        (root / "campaign.json").write_text(json.dumps({
            "cells": cells, "duration": 10, "concurrency": concurrency,
        }))
        return cells

    def write_campaign_cell(self, root, payload=1024, repetition=1, concurrency=100, **overrides):
        directory = root / "ferrum" / f"run_{repetition}" / f"payload_{payload}"
        directory.mkdir(parents=True, exist_ok=True)
        file = directory / f"ferrum_http1_{payload}.json"
        record = {
            "mesh": "ferrum", "gateway": "ferrum", "protocol": "http1",
            "payload_size": payload, "duration_secs": 10, "concurrency": concurrency,
            "rps": 2, "total_errors": 0, "warmup_errors": 0,
        }
        record.update(overrides)
        file.write_text(json.dumps(record))
        file.with_suffix(".resources.json").write_text(json.dumps({
            "valid": True, "elapsed_seconds": 10, "host_cpu_steal_percent": 0,
            "proxy_cpu_seconds": 1, "proxy_rss_bytes_peak": 1024,
            "proxy_rss_bytes_mean": 512,
        }))
        return file

    def test_campaign_rejects_wrong_metadata_even_with_a_valid_repetition(self):
        for overrides in (
            {"duration_secs": 9}, {"duration_secs": "10"},
            {"duration_secs": None}, {"protocol": "http2"}, {"protocol": None},
            {"concurrency": 99}, {"concurrency": "100"},
            {"mesh": "envoy"}, {"gateway": "envoy"}, {"payload_size": 10240},
        ):
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_campaign(root)
                self.write_campaign_cell(root)
                self.write_campaign_cell(root, repetition=2, **overrides)
                collected = summary.collect(root)
                self.assertEqual(collected["meshes"]["ferrum"]["1024"]["publishable_runs"], 1)
                self.assertTrue(any("unpublishable cell" in warning for warning in collected["warnings"]))
                self.assertNotEqual(summary.check_acceptance(collected), 0)

    def test_campaign_rejects_warmup_errors_or_missing_evidence(self):
        for warmup_errors in (1, -1, None, "0", False):
            with self.subTest(warmup_errors=warmup_errors), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_campaign(root)
                self.write_campaign_cell(root)
                file = self.write_campaign_cell(root, repetition=2, warmup_errors=warmup_errors)
                if warmup_errors is None:
                    record = json.loads(file.read_text())
                    del record["warmup_errors"]
                    file.write_text(json.dumps(record))
                collected = summary.collect(root)
                self.assertEqual(collected["meshes"]["ferrum"]["1024"]["publishable_runs"], 1)
                self.assertNotEqual(summary.check_acceptance(collected), 0)

    def test_campaign_accepts_bulk_concurrency_at_both_thresholds_and_clamps_to_one(self):
        expected = {1024: 101, 1048575: 101, 1048576: 50, 5242879: 50, 5242880: 25}
        for concurrency, counts in ((101, expected), (1, {payload: 1 for payload in expected})):
            with self.subTest(concurrency=concurrency), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for cell in self.write_campaign(root, tuple(counts), concurrency):
                    self.write_campaign_cell(root, cell["payload"], cell["repetition"], counts[cell["payload"]])
                collected = summary.collect(root)
                self.assertEqual(collected["warnings"], [])
                self.assertEqual(summary.check_acceptance(collected), 0)
                self.assertTrue(all(cell["publishable_runs"] == 2 for cell in collected["meshes"]["ferrum"].values()))

    def test_campaign_rejects_unscaled_bulk_concurrency_in_one_repetition(self):
        for payload, effective in ((1048576, 50), (5242880, 25)):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.write_campaign(root, (payload,))
                self.write_campaign_cell(root, payload, concurrency=effective)
                self.write_campaign_cell(root, payload, repetition=2, concurrency=100)
                collected = summary.collect(root)
                self.assertEqual(collected["meshes"]["ferrum"][str(payload)]["publishable_runs"], 1)
                self.assertTrue(any(f"expected {effective}" in warning for warning in collected["warnings"]))
                self.assertNotEqual(summary.check_acceptance(collected), 0)

    def test_campaign_rejects_unplanned_repetition_even_with_matching_file_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_campaign(root)
            for repetition in (1, 2, 3):
                self.write_campaign_cell(root, repetition=repetition)
            collected = summary.collect(root)
            self.assertEqual(collected["meshes"]["ferrum"]["1024"]["publishable_runs"], 2)
            self.assertTrue(any("not a planned campaign cell" in warning for warning in collected["warnings"]))
            self.assertNotEqual(summary.check_acceptance(collected), 0)

    def test_standalone_legacy_summary_does_not_require_campaign_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "ferrum_http1_1024.json").write_text(json.dumps({
                "mesh": "ferrum", "gateway": "ferrum", "payload_size": 1024,
                "rps": 2, "total_errors": 0,
            }))
            collected = summary.collect(root)
            self.assertEqual(collected["warnings"], [])
            self.assertEqual(summary.check_acceptance(collected), 0)
            self.assertNotIn("Admitted-success cohort", summary.render_markdown(collected))

    def test_markdown_distinguishes_in_window_and_cohort_latency_including_drains(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_campaign(root)
            for repetition in (1, 2):
                self.write_campaign_cell(root, repetition=repetition,
                    latency_avg_us=100, p50_us=80, p95_us=150, p99_us=200,
                    cohort_requests=21, cohort_p50_us=80, cohort_p95_us=1_500_000,
                    cohort_p99_us=2_000_000, cohort_latency_max_us=3_000_000)
            collected = summary.collect(root)
            self.assertEqual(collected["meshes"]["ferrum"]["1024"]["cohort_requests"], 21)
            markdown = summary.render_markdown(collected)
            in_window = markdown.split("## In-window successful-completion latency", 1)[1].split("## Admitted-success cohort", 1)[0]
            self.assertIn("200µs", in_window)
            self.assertNotIn("2.00s", in_window)
            cohort = markdown.split("## Admitted-success cohort latency including drains", 1)[1]
            self.assertIn("| Successful exchanges | P50 | P95 | P99 | Max |", cohort)
            self.assertIn("| ferrum | 1KiB | 21 | 80µs | 1.50s | 2.00s | 3.00s |", cohort)


if __name__ == "__main__":
    unittest.main()
