"""Stamp the echo backend's connection and echo counters into a sample (#6022).

`proto_backend` counts accepted TCP connections and completed TLS handshakes on
its HTTPS/H2 listener, accepted connections on its gRPC+TLS listener, and echo
requests, and serves the cumulative values at `GET /bench-stats` on the health
port. The runner snapshots them immediately before and after each client run;
this module stores the difference in the sample so a gateway that opens more
backend connections per request (or a connection-per-RPC client) is visible
next to its throughput and p99.

Data only: no process is started here.
"""

import json
import sys
from pathlib import Path

FIELDS = ("h2_tls_accepted", "h2_tls_handshakes", "grpcs_accepted",
          "http_echo_requests", "grpc_echo_requests")
# protocol -> (accepted-connection counter, completed-handshake counter, echo counter)
LISTENERS = {
    "http2": ("h2_tls_accepted", "h2_tls_handshakes", "http_echo_requests"),
    "grpcs": ("grpcs_accepted", None, "grpc_echo_requests"),
}


def read_counters(path):
    """Return the snapshot's counters, or None when it is missing or malformed."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    counters = {}
    for field in FIELDS:
        value = data.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return None
        counters[field] = value
    return counters


def backend_connections(protocol, before, after):
    """Connections the backend accepted and echoes it served during one sample."""
    if protocol not in LISTENERS:
        return {"available": False, "error": f"no backend counters for {protocol}"}
    if before is None or after is None:
        return {"available": False, "error": "backend counter snapshot missing or malformed"}
    if any(after[field] < before[field] for field in FIELDS):
        return {"available": False, "error": "backend counters went backwards"}
    accepted_field, handshake_field, echo_field = LISTENERS[protocol]
    accepted = after[accepted_field] - before[accepted_field]
    echoes = after[echo_field] - before[echo_field]
    result = {
        "available": True,
        "listener": accepted_field.rsplit("_", 1)[0],
        "accepted": accepted,
        # Since this arm's backend started, gateway pool warmup included.
        "accepted_since_backend_start": after[accepted_field],
        "echo_requests": echoes,
        "accepted_per_1k_echoes": round(accepted * 1000 / echoes, 3) if echoes else None,
    }
    if handshake_field:
        result["tls_handshakes"] = after[handshake_field] - before[handshake_field]
    return result


def stamp(sample_path, protocol, before_path, after_path, h2_window, grpc_connections):
    path = Path(sample_path)
    try:
        sample = json.loads(path.read_text())
    except (OSError, ValueError):
        return
    if not isinstance(sample, dict):
        return
    sample["backend_connections"] = backend_connections(
        protocol, read_counters(before_path), read_counters(after_path))
    sample["workload"] = {"h2_window": h2_window, "grpc_client_connections": grpc_connections}
    path.write_text(json.dumps(sample, indent=2) + "\n")


if __name__ == "__main__":
    command, *arguments = sys.argv[1:]
    if command != "stamp" or len(arguments) != 6:
        raise SystemExit("usage: backend_connections.py stamp SAMPLE PROTOCOL BEFORE AFTER "
                         "H2_WINDOW GRPC_CLIENT_CONNECTIONS")
    stamp(*arguments)
