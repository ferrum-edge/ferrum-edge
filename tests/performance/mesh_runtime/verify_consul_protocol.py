#!/usr/bin/env python3
"""Verify live Consul network filter shape; never infer L7 from echo success."""
import json
import sys
from pathlib import Path


def active_listeners(value):
    if isinstance(value, dict):
        active = value.get("active_state", value.get("activeState"))
        if isinstance(active, dict) and isinstance(active.get("listener"), dict):
            yield active["listener"]
        for child in value.values():
            yield from active_listeners(child)
    elif isinstance(value, list):
        for child in value:
            yield from active_listeners(child)


def measured_listener_chains(document, port, addresses=("127.0.0.1", "0.0.0.0")):
    listeners = []
    for listener in active_listeners(document):
        address = listener.get("address", {}).get("socket_address", {})
        if address.get("port_value") == port and address.get("address") in addresses:
            listeners.append(listener)
    if len(listeners) != 1:
        return []
    listener = listeners[0]
    chains = list(listener.get("filter_chains", []))
    if "default_filter_chain" in listener:
        chains.append(listener["default_filter_chain"])
    return chains if chains and all(isinstance(chain, dict) for chain in chains) else []


def measured_filter_chains(document, port, addresses=("127.0.0.1", "0.0.0.0")):
    chains = measured_listener_chains(document, port, addresses)
    return [[entry.get("name") for entry in chain.get("filters", [])] for chain in chains]


def verify(arm, documents, measured_addresses=None):
    # Only the ACTIVE measured outbound and inbound listeners count. An HTTP
    # filter on the client's unused inbound, or a warming/draining listener,
    # does not prove the measured path is HTTP-aware.
    # An L4 fixture may explicitly bind its destination on a private bridge.
    # Callers supply the prespecified addresses, never discover an arbitrary
    # address from the live dump. Ordinary L7 checks keep loopback/wildcard only.
    addresses = measured_addresses if measured_addresses is not None else (("127.0.0.1", "0.0.0.0"),) * 2
    filters = [measured_filter_chains(doc, port, allowed)
               for doc, port, allowed in zip(documents, (15101, 21000), addresses)]
    hcm = "envoy.filters.network.http_connection_manager"
    tcp = "envoy.filters.network.tcp_proxy"
    if arm == "consulhttp":
        accepted = len(documents) == len(addresses) == len(filters) == 2 and all(chains and all(hcm in names for names in chains) for chains in filters)
    else:
        accepted = len(documents) == len(addresses) == len(filters) == 2 and all(chains and all(tcp in names and hcm not in names for names in chains) for chains in filters)
    return {"arm": arm, "expected_layer": "L7 HTTP" if arm == "consulhttp" else "L4 TCP",
            "measured_ports": [15101, 21000], "measured_addresses": [list(allowed) for allowed in addresses], "active_network_filter_chains_by_proxy": filters, "accepted": accepted}


if __name__ == "__main__":
    arm, *paths = sys.argv[1:]
    result = verify(arm, [json.loads(Path(p).read_text()) for p in paths])
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if len(paths) == 2 and result["accepted"] else 1)
