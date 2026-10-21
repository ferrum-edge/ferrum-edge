"""Measured Consul listener selection; no Docker or proxy execution."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("verify_consul_protocol", Path(__file__).resolve().parents[1] / "verify_consul_protocol.py")
protocol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protocol)


def active(host, port, filter_name="envoy.filters.network.tcp_proxy"):
    return {"active_state": {"listener": {"address": {"socket_address": {"address": host, "port_value": port}},
            "filter_chains": [{"filters": [{"name": filter_name}]}]}}}


class ConsulMeasuredListeners(unittest.TestCase):
    def test_private_destination_requires_explicit_address_scope(self):
        documents = [active("127.0.0.1", 15101), active("172.18.0.1", 21000)]
        self.assertFalse(protocol.verify("consul", documents)["accepted"])
        self.assertTrue(protocol.verify("consul", documents, (("127.0.0.1",), ("172.18.0.1",)))["accepted"])
        self.assertFalse(protocol.verify("consul", documents, (("127.0.0.1",), ("172.19.0.1",)))["accepted"])
        for document in documents:
            document["active_state"]["listener"]["filter_chains"][0]["filters"][0]["name"] = "envoy.filters.network.http_connection_manager"
        self.assertFalse(protocol.verify("consulhttp", documents)["accepted"])

    def test_measured_active_listener_must_be_unique_and_all_chains_match(self):
        source, destination = active("127.0.0.1", 15101), active("0.0.0.0", 21000)
        self.assertFalse(protocol.verify("consul", [{"configs": [source, copy.deepcopy(source)]}, destination])["accepted"])
        self.assertFalse(protocol.verify("consul", [{"warming_state": source["active_state"]}, destination])["accepted"])
        self.assertFalse(protocol.verify("consul", [source, destination, copy.deepcopy(destination)])["accepted"])
        destination["active_state"]["listener"]["default_filter_chain"] = {"filters": [{"name": "envoy.filters.network.http_connection_manager"}]}
        self.assertFalse(protocol.verify("consul", [source, destination])["accepted"])


if __name__ == "__main__":
    unittest.main()
