#!/usr/bin/env python3
"""Verify live Consul network filter shape; never infer L7 from echo success."""
import json
import sys
from pathlib import Path


def filter_names(value):
    if isinstance(value, dict):
        name = value.get("name", "")
        if isinstance(name, str) and name.startswith("envoy.filters.network."):
            yield name
        for child in value.values():
            yield from filter_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from filter_names(child)


def verify(arm, documents):
    filters = [sorted(set(filter_names(doc))) for doc in documents]
    hcm = "envoy.filters.network.http_connection_manager"
    tcp = "envoy.filters.network.tcp_proxy"
    if arm == "consulhttp":
        accepted = all(hcm in names for names in filters)
    else:
        accepted = all(tcp in names and hcm not in names for names in filters)
    return {"arm": arm, "expected_layer": "L7 HTTP" if arm == "consulhttp" else "L4 TCP",
            "network_filters_by_proxy": filters, "accepted": accepted}


if __name__ == "__main__":
    arm, *paths = sys.argv[1:]
    result = verify(arm, [json.loads(Path(p).read_text()) for p in paths])
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if len(paths) == 2 and result["accepted"] else 1)
