#!/usr/bin/env python3
"""Adapt a `consul connect envoy -bootstrap` document for this harness.

Two mechanical adaptations, both recorded in the run logs:

1. Admin port: both sidecars share one host network namespace, so the
   generated default (19000) collides; the harness assigns 19001/19002.
2. Local agent xDS endpoint: the generated `local_agent` cluster points
   at the agent's TLS gRPC port with an empty trusted CA when the agent
   runs without its own TLS material (dev agent), which current Envoy
   rejects (`DataSource cannot be empty`). The agent also serves
   plaintext gRPC on 8502 in this posture, so the cluster is repointed
   there and its TLS transport socket dropped. This affects only the
   loopback proxy<->agent control channel; the east-west data path
   (Consul CA mTLS between the sidecars) is untouched.

Usage: prepare_consul_bootstrap.py <bootstrap.json> <admin-port>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def set_port(node: object, port: int) -> None:
    """Set the first socket_address port found under a JSON subtree."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("port_value", "portValue") and isinstance(value, int):
                node[key] = port
                return
            set_port(value, port)
    elif isinstance(node, list):
        for item in node:
            set_port(item, port)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    admin_port = int(sys.argv[2])
    doc = json.loads(path.read_text())

    admin = doc.get("admin") or {}
    if admin:
        set_port(admin.get("address") or {}, admin_port)

    clusters = (doc.get("static_resources") or {}).get("clusters") or []
    for cluster in clusters:
        if cluster.get("name") != "local_agent":
            continue
        cluster.pop("transport_socket", None)
        assignment = cluster.get("loadAssignment") or cluster.get("load_assignment") or {}
        set_port(assignment, 8502)

    path.write_text(json.dumps(doc, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
