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
            (root / "campaign.json").write_text(json.dumps({"cells": campaign.plan(["ferrum"], [1024], 3, True)}))
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


if __name__ == "__main__":
    unittest.main()
