import copy
import unittest

from evidence import assess, LOSSES


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.ready = {"status": "supported"}
        self.fixture = {"status": "supported", "mode": "batches", "start_ns": 10,
                        "end_ns": 20, "sockets": [{"cookie": 7}]}
        self.final = {"phase": "final", "start_ns": 1, "end_ns": 30,
                      "rows": [self.row(1), self.row(3)],
                      "losses": [0, 0, 0, 0, 0, 2, 2, 0] + [0] * (len(LOSSES) - 8),
                      "map_read_failures": 0, "pending_tx": 0, "pending_rx": 0, "pending_selector": 0}

    def row(self, kind):
        return {"kind": kind, "cookie": 7, "peer_cookie": 0, "count": 1,
                "length": 2048, "segment": 512, "result": 2048 if kind == 1 else -22,
                "first_ns": 11, "last_ns": 19}

    def test_positive_is_not_gateway_or_absence_proof(self):
        result = assess(self.ready, self.final, self.fixture, "tx")
        self.assertEqual(result["positive"], ["tx_gso"])
        for key in ["exact_totals", "absence_claim_allowed", "gateway_behavior_proven",
                    "routing_distribution_complete"]:
            self.assertFalse(result[key])

    def test_real_loss_preserves_positive(self):
        self.final["losses"][0] = 3
        result = assess(self.ready, self.final, self.fixture, "tx")
        self.assertEqual(result["status"], "partial_coverage")
        self.assertEqual(result["positive"], ["tx_gso"])

    def test_forced_overflow_requires_loss_and_retained_positive(self):
        self.final["rows"] = [self.row(1)]
        with self.assertRaises(AssertionError):
            assess(self.ready, self.final, self.fixture, "tx", True)
        self.final["losses"][0] = 1
        self.assertEqual(assess(self.ready, self.final, self.fixture, "tx", True)["status"], "partial_coverage")
        self.final["rows"] = [self.row(3)]
        with self.assertRaises(AssertionError):
            assess(self.ready, self.final, self.fixture, "tx", True)

    def test_foreign_cookie_fails_attribution(self):
        self.final["rows"][0]["cookie"] = 99
        with self.assertRaises(AssertionError):
            assess(self.ready, self.final, self.fixture, "tx")

    def test_positive_requires_multisegment_success(self):
        for field, value in [("segment", 0), ("length", 512), ("result", -14)]:
            broken = copy.deepcopy(self.final)
            broken["rows"][0][field] = value
            with self.assertRaises(AssertionError):
                assess(self.ready, broken, self.fixture, "tx")

    def test_no_snapshot_no_success(self):
        with self.assertRaises(AssertionError):
            assess(self.ready, None, self.fixture, "tx")

    def test_missing_btf_never_zero_filled(self):
        result = assess({"status": "unsupported", "reason": "btf_read"}, None, {}, "rx")
        self.assertEqual(result["status"], "unsupported")
        self.assertNotIn("loss", result)
        self.assertEqual(result["positive"], [])

    def test_observer_must_bracket_fixture(self):
        self.final["end_ns"] = 19
        with self.assertRaises(AssertionError):
            assess(self.ready, self.final, self.fixture, "tx")

    def test_fallback_is_not_classic_execution_proof(self):
        self.fixture.update(mode="classic-fallback", operations=[{"op": "selection", "selected_cookie": 7}])
        self.final["rows"] = [self.row(k) for k in [11, 13, 14]]
        self.final["rows"][1]["peer_cookie"] = 7
        result = assess(self.ready, self.final, self.fixture, "classic")
        self.assertEqual(result["status"], "partial_coverage")
        self.assertEqual(result["positive"], [])

    def test_classic_selection_joins_lookup_and_selected_socket_cookies(self):
        self.fixture.update(mode="classic-select", sockets=[{"cookie": 7}, {"cookie": 9}],
                            operations=[{"op": "selection", "selected_cookie": 9}])
        self.final["rows"] = [self.row(k) for k in [10, 12, 14]]
        for row in self.final["rows"][:2]:
            row["peer_cookie"] = 9
        result = assess(self.ready, self.final, self.fixture, "classic")
        self.assertEqual(result["positive"], ["classic_execution_selected_socket"])
        self.final["rows"][0]["cookie"] = 99
        with self.assertRaises(AssertionError):
            assess(self.ready, self.final, self.fixture, "classic")


if __name__ == "__main__":
    unittest.main()
