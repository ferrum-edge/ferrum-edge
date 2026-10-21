#!/usr/bin/env python3
"""Disposable captured-L4 fixture data and binary transport proofs.

The measured application remains HTTP/1 keepalive. A separate binary-only
backend is used before measurement to prove the same sidecars relay opaque TCP.
No private credential contents are read or emitted by this helper.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import importlib.util
import http.client
import json
import math
import re
import selectors
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SOURCE = "spiffe://cluster.local/ns/ferrum/sa/client"
DESTINATION = "spiffe://cluster.local/ns/ferrum/sa/svc"
PAYLOAD = bytes(range(256)) + b"\x00mesh-l4-binary\xff"
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z_0-9]*)="((?:\\.|[^"\\])*)"')
SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z_0-9:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+\d+)?$')


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def render(directory: Path, endpoint: str, vip: str, backend_port: int, raw_port: int) -> None:
    endpoint = str(ipaddress.IPv4Address(endpoint))
    vip = str(ipaddress.IPv4Address(vip))
    if endpoint == vip or any(not 1024 <= p <= 65535 for p in (backend_port, raw_port)):
        raise ValueError("invalid fixture endpoint/ports")
    directory.mkdir(parents=True, exist_ok=True)
    ports = [{"port": p, "protocol": "tcp", "name": f"tcp-{p}"} for p in (backend_port, raw_port)]
    mesh = {"mesh": {
        "workloads": [{"spiffe_id": DESTINATION, "service_name": "svc", "namespace": "ferrum",
                       "trust_domain": "cluster.local", "service_account": "svc", "addresses": [endpoint],
                       "ports": ports, "selector": {"labels": {"app": "svc"}, "namespace": "ferrum"}}],
        "services": [{"name": "svc", "namespace": "ferrum", "cluster_ips": [vip],
                      "ports": ports, "workloads": [{"spiffe_id": DESTINATION}]}],
        "peer_authentications": [{"name": "mesh-strict", "namespace": "ferrum", "mtls_mode": "strict"}],
        "telemetry_resources": [{"name": "bench-no-access-log", "namespace": "ferrum",
                                 "config": {"access_logging": {"enabled": False}}}],
    }}
    # Source never receives the destination deny. The refusal must come from
    # B's authenticated inbound CONNECT/stream authorization, not local egress.
    write_json(directory / "source.json", mesh)
    allow = copy.deepcopy(mesh)
    policy = {"name": "bench-client-only", "namespace": "ferrum",
              "scope": {"kind": "workload_selector", "selector": {"labels": {"app": "svc"}, "namespace": "ferrum"}},
              "rules": [{"from": [{"spiffe_id_pattern": SOURCE}], "to": [{"ports": [backend_port, raw_port]}], "action": "allow"}]}
    allow["mesh"]["mesh_policies"] = [policy]
    write_json(directory / "destination-allow.json", allow)
    deny = copy.deepcopy(allow)
    denied = copy.deepcopy(policy)
    denied["name"] = "bench-deny-client"
    denied["rules"][0]["action"] = "deny"
    deny["mesh"]["mesh_policies"].append(denied)
    write_json(directory / "destination-deny.json", deny)
    write_json(directory / "destination.json", allow)
    base = Path(__file__).resolve().parent / "configs" / "consul"
    svc = json.loads((base / "svc.json").read_text())
    svc["service"]["address"] = endpoint
    svc["service"]["port"] = backend_port
    svc["service"]["connect"]["sidecar_service"].update({"address": endpoint,
        "proxy": {"local_service_address": "127.0.0.1", "local_service_port": backend_port}})
    write_json(directory / "consul-svc.json", svc)
    raw = copy.deepcopy(svc)
    raw["service"]["port"] = raw_port
    raw["service"]["connect"]["sidecar_service"]["proxy"]["local_service_port"] = raw_port
    raw["service"]["connect"]["sidecar_service"]["proxy"]["local_service_address"] = endpoint
    write_json(directory / "consul-svc-raw.json", raw)
    write_json(directory / "consul-client.json", json.loads((base / "client.json").read_text()))
    write_json(directory / "consul-allow.json", {"Kind": "service-intentions", "Name": "svc",
        "Sources": [{"Name": "client", "Action": "allow"}, {"Name": "*", "Action": "deny"}]})
    write_json(directory / "consul-deny.json", json.loads((base / "intention-deny.json").read_text()))
    write_json(directory / "topology.json", {"schema_version": 1, "vip": vip, "endpoint": endpoint,
        "backend_port": backend_port, "binary_proof_port": raw_port, "proxy_uid": 65532, "application_uid": 65531,
        "topology": "source application and sidecar share private Docker netns; destination and backend host netns",
        "capture": "fixture IPv4 OUTPUT REDIRECT follows production LOCAL/owner/redirect ordering",
        "measured_application": "HTTP/1 keepalive payloads over opaque TCP mesh route",
        "source_identity": SOURCE, "destination_identity": DESTINATION,
        "consul_binary_probe": "temporarily register svc local application port as binary proof port; restore before measurement"})


def adapt_bootstrap(path: Path, host: str) -> None:
    # Keep the existing, tested admin-port/plaintext dev-agent adaptation.
    # Only the source sidecar's local_agent address crosses the private bridge.
    doc = json.loads(path.read_text())
    found = 0
    for cluster in doc.get("static_resources", {}).get("clusters", []):
        if cluster.get("name") != "local_agent":
            continue
        assignment = cluster.get("load_assignment", cluster.get("loadAssignment", {}))
        for endpoints in assignment.get("endpoints", []):
            for entry in endpoints.get("lb_endpoints", endpoints.get("lbEndpoints", [])):
                address = entry.get("endpoint", {}).get("address", {}).get("socket_address", {})
                if address:
                    address["address"] = str(ipaddress.IPv4Address(host))
                    found += 1
    if found != 1:
        raise ValueError(f"expected one Consul local_agent endpoint, got {found}")
    write_json(path, doc)


def echo_server(host: str, port: int, max_seconds: int) -> None:
    deadline = time.monotonic() + max_seconds
    selector = selectors.DefaultSelector()
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(32)
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ)
        print(json.dumps({"binary_echo_listening": [host, port], "max_seconds": max_seconds}), flush=True)
        try:
            while time.monotonic() < deadline:
                for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                    if key.fileobj is listener:
                        connection, _ = listener.accept()
                        connection.settimeout(0.5)
                        if len(selector.get_map()) >= 33:
                            connection.close()
                        else:
                            selector.register(connection, selectors.EVENT_READ)
                    else:
                        connection = key.fileobj
                        try:
                            data = connection.recv(65536)
                            if data:
                                connection.sendall(data)
                            else:
                                raise ConnectionError("eof")
                        except OSError:
                            selector.unregister(connection)
                            connection.close()
        finally:
            for key in list(selector.get_map().values()):
                selector.unregister(key.fileobj)
                if key.fileobj is not listener:
                    key.fileobj.close()
            selector.close()


def probe(host: str, port: int, timeout: float = 2.0, exchanges: int = 5) -> dict:
    deadline = time.monotonic() + timeout
    def remaining() -> float:
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("whole binary exchange deadline exceeded")
        return seconds
    with socket.create_connection((host, port), timeout=remaining()) as connection:
        peer = connection.getpeername()
        if peer[:2] != (str(ipaddress.IPv4Address(host)), port):
            raise ConnectionError("captured client peer no longer matches declared VIP:port")
        for _ in range(exchanges):
            connection.settimeout(remaining())
            connection.sendall(PAYLOAD)
            reply = bytearray()
            while len(reply) < len(PAYLOAD):
                connection.settimeout(remaining())
                chunk = connection.recv(len(PAYLOAD) - len(reply))
                if not chunk:
                    raise ConnectionError("binary reply truncated")
                reply.extend(chunk)
            if reply != PAYLOAD:
                raise ConnectionError("binary echo mismatch")
        connection.shutdown(socket.SHUT_WR)
        connection.settimeout(remaining())
        if connection.recv(1):
            raise ConnectionError("unexpected bytes after half close")
    return {"ok": True, "peer": [peer[0], peer[1]], "connections": 1, "exchanges": exchanges,
            "payload_bytes": len(PAYLOAD), "byte_exact": True, "half_close": True,
            "whole_exchange_timeout_secs": timeout}


def samples(path: Path):
    for line in path.read_text().splitlines():
        match = SAMPLE.fullmatch(line)
        if not match:
            continue
        value = float(match[3])
        if not math.isfinite(value):
            continue
        labels = {key: json.loads('"' + val + '"') for key, val in LABEL.findall(match[2] or "")}
        yield match[1], labels, value


def verify_ferrum(directory: Path) -> dict:
    """Qualify shipping transport/auth only; retain the separate telemetry gap.

    Captured egress invokes workload_metrics but never the Prometheus observer.
    The destination is an HTTP HBONE CONNECT, not a stream-plugin TCP endpoint.
    Requiring eight TCP series here therefore cannot qualify this shipping
    localized-file configuration. Do not turn this into a telemetry/parity pass.
    """
    errors, observations = [], {}

    def read_json(path):
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError) as error:
            errors.append(f"{path.name}: missing or invalid evidence ({type(error).__name__})")
            return {}

    topology = read_json(directory / "l4-fixture-configs/topology.json")
    if not isinstance(topology, dict):
        errors.append("topology.json: expected object")
        topology = {}
    vip, endpoint, port = topology.get("vip"), topology.get("endpoint"), topology.get("binary_proof_port")
    try:
        ipaddress.IPv4Address(vip)
        ipaddress.IPv4Address(endpoint)
        if type(port) is not int or not 1024 <= port <= 65535 or vip == endpoint:
            raise ValueError("invalid fixture endpoint/port")
    except (ValueError, TypeError):
        errors.append("topology.json: invalid fixture endpoint/port")

    for phase in ("raw-direct", "allowed", "denied", "restored", "bypass-blocked"):
        path = directory / f"l4-{phase}.jsonl"
        try:
            rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
            if not rows or any(not isinstance(row, dict) for row in rows):
                raise ValueError("expected nonempty JSON object records")
        except (OSError, ValueError) as error:
            errors.append(f"{path.name}: missing or invalid evidence ({type(error).__name__})")
            rows = []
        observations[phase] = rows

    def success(row, host):
        timeout = row.get("whole_exchange_timeout_secs")
        return (row.get("ok") is True and row.get("byte_exact") is True
                and row.get("half_close") is True and type(row.get("connections")) is int
                and row["connections"] == 1 and type(row.get("exchanges")) is int
                and row["exchanges"] == 5 and type(row.get("payload_bytes")) is int
                and row["payload_bytes"] == len(PAYLOAD) and row.get("peer") == [host, port]
                and type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 2)

    def refusal(row):
        # A timeout, harness error, or corrupt echo is not a policy refusal.
        return row.get("ok") is False and (
            row.get("kind") in ("ConnectionRefusedError", "ConnectionResetError",
                                "ConnectionAbortedError", "BrokenPipeError")
            or (row.get("kind") == "ConnectionError" and row.get("error") == "binary reply truncated"))

    for phase, host in (("raw-direct", endpoint), ("allowed", vip), ("restored", vip)):
        rows = observations[phase]
        if not rows or not success(rows[-1], host):
            errors.append(f"{phase}: no final one-connection five-exchange byte-exact half-close success")
    denied = observations["denied"]
    if len(denied) < 2 or not all(refusal(row) for row in denied[-2:]):
        errors.append("denied: require two consecutive real connection refusals/resets/EOFs")
    bypass = observations["bypass-blocked"]
    if not bypass or not refusal(bypass[-1]):
        errors.append("bypass-blocked: source proxy direct backend refusal not proved")

    # These are written only after the existing fail-closed shell TLS probes.
    # Check their retained evidence too so a standalone verifier cannot imply
    # that binary transport successes proved the whole authentication matrix.
    try:
        auth = (directory / "auth_probes.log").read_text().splitlines()
    except OSError:
        auth = []
    for proof in ("plaintext refused", "valid client certificate handshake",
                  "no-client-cert refused", "rogue-CA client certificate refused"):
        if f"[auth-probe] ok: {proof}" not in auth:
            errors.append(f"authentication matrix: missing {proof}")
    if any("[auth-probe] FAIL:" in line or "[auth-probe] infrastructure failure" in line for line in auth):
        errors.append("authentication matrix contains a failed probe")

    snapshots, successes = {}, {}
    for phase in ("allowed", "denied", "restored"):
        try:
            records = list(samples(directory / f"l4-{phase}/source.metrics"))
        except (OSError, ValueError):
            records = []
        snapshots[phase] = records
        values = [value for name, labels, value in records
                  if name == "ferrum_mesh_tcp_egress_connections_total"
                  and labels.get("transport") == "mtls" and labels.get("result") == "success"]
        if len(values) != 1 or values[0] < 0 or not values[0].is_integer():
            errors.append(f"{phase}: missing/invalid successful captured mtls TCP egress counter")
        else:
            successes[phase] = values[0]
    delta = None
    if len(successes) == 3:
        delta = successes["restored"] - successes["denied"]
        if not 0 < successes["allowed"] <= successes["denied"] or delta < 1:
            errors.append("mtls success counters must be monotonic with restored-minus-denied >= 1")

    # Preserve the original missing-series observation as a finding, not as an
    # impossible shipping transport gate or an assertion of feature parity.
    telemetry_findings = []
    try:
        destination = list(samples(directory / "l4-restored/destination.metrics"))
    except (OSError, ValueError):
        destination = []
    for role, records in (("source", snapshots["restored"]), ("destination", destination)):
        for name in ("ferrum_mesh_tcp_connections_opened_total", "ferrum_mesh_tcp_connections_closed_total",
                     "ferrum_mesh_tcp_sent_bytes_total", "ferrum_mesh_tcp_received_bytes_total"):
            if not any(metric == name and labels.get("connection_security_policy") == "mutual_tls"
                       and labels.get("destination_principal") == DESTINATION
                       and (role == "source" or labels.get("source_principal") == SOURCE)
                       and value > 0 for metric, labels, value in records):
                telemetry_findings.append(f"{role}: missing authenticated identity-bound {name}")
    return {"accepted": not errors, "transport_auth_qualified": not errors,
            "workload_telemetry_qualified": False, "errors": errors,
            "qualification_scope": "shipping localized-file transport/auth; operational metrics only",
            "workload_telemetry_reasons": [
                "Localized mesh file mode does not inject or carry a configured prometheus_metrics exporter; workload_metrics only annotates identity/policy.",
                "Captured source egress filters hooks to builtin workload_metrics, so the required Prometheus observation marker and registry completion hook never run, even with an exporter.",
                "Destination mTLS HBONE CONNECT is an HTTP request/response telemetry path, not a TCP stream-plugin lifecycle path."],
            "workload_telemetry_findings": telemetry_findings,
            "mtls_success_counts": successes, "restored_minus_denied_mtls_successes": delta,
            "probe_record_counts": {phase: len(rows) for phase, rows in observations.items()},
            "expected_transport": "mtls", "source_identity": SOURCE, "destination_identity": DESTINATION,
            "note": "All raw probes/snapshots retained. Transport/auth acceptance does not qualify workload telemetry or full feature parity; counters include fixture probes."}


METRICS_BODY_LIMIT = 4 * 1024 * 1024
SETTLING_SECONDS = 6.5
SETTLING_ATTEMPTS = 15
SETTLING_INTERVAL = 0.5
RESTORE_COUNTER_ERROR = "mtls success counters must be monotonic with restored-minus-denied >= 1"
METRICS_URL = "http://127.0.0.1:15120/metrics"


class MetricsReadFailure(ValueError):
    def __init__(self, reason, body=b""):
        super().__init__(reason)
        self.reason, self.body = reason, body[:METRICS_BODY_LIMIT]


def fetch_source_metrics(timeout):
    """Only the existing loopback admin endpoint; no proxy or redirect handling."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    body = bytearray()
    try:
        try:
            response = opener.open(METRICS_URL, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            response = response.fp if isinstance(response, urllib.error.HTTPError) else response
            status = response.status
            expected_length = response.length
            # This fixed HTTP URL uses HTTPResponse -> BufferedReader -> SocketIO.
            # Reset its socket timeout before each bounded read so a trickled body
            # cannot restart a full timeout indefinitely.
            sock = response.fp.raw._sock
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MetricsReadFailure("metrics read deadline", bytes(body))
                sock.settimeout(min(0.5, remaining))
                chunk = response.read1(min(65536, METRICS_BODY_LIMIT + 1 - len(body)))
                if not chunk:
                    if expected_length is not None and len(body) != expected_length:
                        raise MetricsReadFailure("truncated metrics response", bytes(body))
                    if status != 200:
                        raise MetricsReadFailure("non-200 metrics response: " + str(status), bytes(body))
                    return bytes(body)
                body.extend(chunk)
                if len(body) > METRICS_BODY_LIMIT:
                    raise MetricsReadFailure("metrics body exceeds 4 MiB", bytes(body))
                if expected_length is not None and len(body) == expected_length:
                    if status != 200:
                        raise MetricsReadFailure("non-200 metrics response: " + str(status), bytes(body))
                    return bytes(body)
    except MetricsReadFailure:
        raise
    except (OSError, ValueError, AttributeError, http.client.HTTPException, urllib.error.URLError) as error:
        # Exception displays can include remote data; retain only the class.
        raise MetricsReadFailure("metrics read failed: " + type(error).__name__, bytes(body)) from None


def strict_mtls_success(body):
    values = []
    for line in body.decode("utf-8").splitlines():
        if not line.startswith("ferrum_mesh_tcp_egress_connections_total"):
            continue
        match = SAMPLE.fullmatch(line)
        if not match or match[1] != "ferrum_mesh_tcp_egress_connections_total":
            raise ValueError("malformed TCP egress counter")
        raw_labels = match[2] or ""
        fields = list(LABEL.finditer(raw_labels))
        if not re.fullmatch(LABEL.pattern + "(?:," + LABEL.pattern + ")*", raw_labels):
            raise ValueError("malformed TCP egress counter labels")
        labels = {field[1]: json.loads('"' + field[2] + '"') for field in fields}
        if len(labels) != len(fields) or not re.fullmatch(r"[0-9]+", match[3]):
            raise ValueError("invalid TCP egress counter labels/value")
        if labels.get("transport") == "mtls" and labels.get("result") == "success":
            values.append(int(match[3]))
    if len(values) != 1:
        raise ValueError("expected exactly one successful mtls TCP egress counter")
    return values[0]


def settle_ferrum_counter(directory, *, fetch=fetch_source_metrics, clock=time.monotonic, wait=time.sleep):
    """Wait for existing relay/cached exposition only; never retry application traffic."""
    started = clock()
    evidence = directory / "l4-counter-settling"
    evidence.mkdir()  # Refuse to overwrite a previous attempt's evidence.
    receipt = {"accepted": False, "errors": [], "attempts": [], "begin_monotonic": started,
               "deadline_monotonic": started + SETTLING_SECONDS, "max_attempts": SETTLING_ATTEMPTS,
               "interval_seconds": SETTLING_INTERVAL, "body_limit_bytes": METRICS_BODY_LIMIT,
               "url": METRICS_URL, "environment_proxies": False,
               "pinned_source_defaults": {"render_cache_ttl_seconds": 5, "invalidation_min_age_ms": 500},
               "mechanism_sources": [
                   "https://github.com/ferrum-edge/ferrum-edge/blob/4a7be250e45a367314e3dec872ecbd512220558e/src/proxy/mesh_tcp_egress.rs#L403-L430",
                   "https://github.com/ferrum-edge/ferrum-edge/blob/4a7be250e45a367314e3dec872ecbd512220558e/src/plugins/prometheus_metrics.rs#L736-L740",
                   "https://github.com/ferrum-edge/ferrum-edge/blob/4a7be250e45a367314e3dec872ecbd512220558e/src/plugins/prometheus_metrics.rs#L2003-L2017",
                   "https://github.com/ferrum-edge/ferrum-edge/blob/4a7be250e45a367314e3dec872ecbd512220558e/src/plugins/prometheus_metrics.rs#L2719-L2735",
                   "https://github.com/ferrum-edge/ferrum-edge/blob/4a7be250e45a367314e3dec872ecbd512220558e/src/plugins/prometheus_metrics.rs#L3054-L3070"],
               "scope": "No new application traffic or forced cache invalidation; EOF/publication ordering and cached exposition are plausible mechanisms, not proven causes. Relay failures log WARN and fixture logs ERROR."}
    try:
        for role in ("source", "destination"):
            with (directory / f"l4-restored/{role}.metrics").open("rb") as stream:
                body = stream.read(METRICS_BODY_LIMIT + 1)
            if len(body) > METRICS_BODY_LIMIT:
                raise ValueError("initial metrics body exceeds 4 MiB")
            (evidence / f"initial-{role}.metrics").write_bytes(body)
        initial = verify_ferrum(directory)
        receipt["initial_proof_errors"] = initial["errors"]
        current = strict_mtls_success((evidence / "initial-source.metrics").read_bytes())
        receipt["initial_counter"] = current
        baseline = initial["mtls_success_counts"].get("denied")
        receipt["denied_counter"] = baseline
        if initial["accepted"]:
            receipt.update(accepted=True, selected_snapshot="initial-source.metrics")
        elif (initial["errors"] != [RESTORE_COUNTER_ERROR]
              or initial["restored_minus_denied_mtls_successes"] != 0
              or not 0 < initial["mtls_success_counts"].get("allowed", 0) <= baseline):
            raise ValueError("unrelated or regressing initial transport/auth proof")
        else:
            for number in range(1, SETTLING_ATTEMPTS + 1):
                remaining = receipt["deadline_monotonic"] - clock()
                if remaining <= 0:
                    break
                attempt = {"attempt": number, "begin_monotonic": clock(),
                           "timeout_seconds": min(0.5, remaining), "counter": None,
                           "raw_path": f"poll-{number:02d}.metrics", "error": None}
                receipt["attempts"].append(attempt)
                body = b""
                try:
                    body = fetch(attempt["timeout_seconds"])
                    if not isinstance(body, bytes) or len(body) > METRICS_BODY_LIMIT:
                        raise MetricsReadFailure("invalid or oversized metrics body", body if isinstance(body, bytes) else b"")
                    attempt["counter"] = strict_mtls_success(body)
                except (OSError, ValueError) as error:
                    body = getattr(error, "body", body)
                    attempt["error"] = error.reason if isinstance(error, MetricsReadFailure) else type(error).__name__
                finally:
                    (evidence / attempt["raw_path"]).write_bytes(body[:METRICS_BODY_LIMIT])
                    attempt["end_monotonic"] = clock()
                if attempt["error"]:
                    raise ValueError("metrics poll failed: " + attempt["error"])
                if clock() > receipt["deadline_monotonic"]:
                    raise ValueError("counter publication deadline exceeded")
                if attempt["counter"] < current:
                    raise ValueError("successful mtls TCP egress counter regressed")
                current = attempt["counter"]
                if current >= baseline + 1:
                    # Initial and every polled response remain immutable above.
                    (directory / "l4-restored/source.metrics").write_bytes(body)
                    final = verify_ferrum(directory)
                    if not final["accepted"]:
                        raise ValueError("final transport/auth proof rejected")
                    receipt.update(accepted=True, selected_snapshot=attempt["raw_path"], final_counter=current)
                    break
                remaining = receipt["deadline_monotonic"] - clock()
                if remaining > 0 and number < SETTLING_ATTEMPTS:
                    wait(min(SETTLING_INTERVAL, remaining))
            if not receipt["accepted"]:
                raise ValueError("counter publication deadline/attempt bound exhausted")
    except (OSError, ValueError, TypeError) as error:
        # Only local fixed validation messages or exception classes enter receipts.
        receipt["errors"].append(str(error) if type(error) is ValueError else type(error).__name__)
    receipt["end_monotonic"] = clock()
    write_json(evidence / "receipt.json", receipt)
    return receipt


def public_config(value):
    # Only listener resources are requested, never SecretsConfigDump. Redact
    # inline TLS credentials as well, in case an xDS producer embeds them.
    private_fields = {"privatekey", "sessionticketkeys", "tlskeylog", "pkcs12", "password", "hmackey", "tokensecret"}
    if isinstance(value, dict):
        return {key: "<redacted private material>" if re.sub(r"[^a-z]", "", key.lower()) in private_fields
                else public_config(child) for key, child in value.items()}
    if isinstance(value, list):
        return [public_config(child) for child in value]
    if isinstance(value, str) and "PRIVATE KEY" in value:
        return "<redacted private material>"
    return value


def verify_consul(directory: Path, topology_path: Path) -> dict:
    # Reuse the active measured-listener checker. A TCP filter elsewhere in
    # the dump, or a warming listener, never proves the measured transport.
    module_spec = importlib.util.spec_from_file_location("verify_consul_protocol", Path(__file__).with_name("verify_consul_protocol.py"))
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    verify = module.verify
    docs = [json.loads((directory / f"{role}-config.json").read_text())
            for role in ("source", "destination")]
    # The source's upstream is the fixture's fixed loopback bind. B's bind is
    # the exact bridge endpoint declared before startup, not any observed IP.
    topology = json.loads(topology_path.read_text())
    endpoint = str(ipaddress.IPv4Address(topology["endpoint"]))
    addresses = (("127.0.0.1",), (endpoint,))
    result = verify("consul", docs, measured_addresses=addresses)
    errors = [] if result["accepted"] else ["active measured filters are not TCP at the declared listener addresses"]
    chains = module.measured_listener_chains(docs[1], 21000, addresses[1])

    def mutual_tls(chain):
        transport = chain.get("transport_socket", {})
        if not isinstance(transport, dict):
            return False
        context = transport.get("typed_config", {})
        if not isinstance(context, dict):
            return False
        common = context.get("common_tls_context", {})
        if not isinstance(common, dict):
            return False
        validation = common.get("validation_context", {})
        if not isinstance(validation, dict):
            return False
        ca = validation.get("trusted_ca", {})
        if not isinstance(ca, dict):
            return False
        trust = validation.get("trust_chain_verification", "VERIFY_TRUST_CHAIN")
        ca_sources = [ca.get(key) for key in ("filename", "inline_string", "inline_bytes")]
        return (transport.get("name") in ("tls", "envoy.transport_sockets.tls")
                and context.get("@type") == "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext"
                and context.get("require_client_certificate") is True
                and sum(isinstance(value, str) and bool(value.strip()) for value in ca_sources) == 1
                and (trust == "VERIFY_TRUST_CHAIN" or type(trust) is int and trust == 0)
                and "custom_validator_config" not in validation)

    if not chains or not all(mutual_tls(chain) for chain in chains):
        errors.append("destination measured TCP listener requires exact DownstreamTlsContext, trusted CA and client certificate verification on every chain")
    for role, service in (("source", "client"), ("destination", "svc")):
        stats = (directory / f"{role}.metrics").read_text()
        if not any(re.search(r"\.ssl\.handshake: [1-9][0-9]*$", line) for line in stats.splitlines()):
            errors.append(f"{role}: no successful TLS handshake counter")
        certs = json.loads((directory / f"{role}-certs.json").read_text())
        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for child in value.values():
                    yield from strings(child)
            elif isinstance(value, list):
                for child in value:
                    yield from strings(child)
        if not any(value.startswith("spiffe://") and value.endswith(f"/svc/{service}") for value in strings(certs)):
            errors.append(f"{role}: missing Consul-issued {service} SPIFFE certificate SAN")
    result.update({"accepted": not errors, "errors": errors,
                   "identity_authority": "Consul Connect CA (distinct trust domain from synthetic Ferrum CA)"})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    config = sub.add_parser("render")
    config.add_argument("--directory", type=Path, required=True)
    config.add_argument("--endpoint", required=True)
    config.add_argument("--vip", default="192.0.2.50")
    config.add_argument("--backend-port", type=int, default=18080)
    config.add_argument("--raw-port", type=int, default=18082)
    bootstrap = sub.add_parser("bootstrap")
    bootstrap.add_argument("path", type=Path)
    bootstrap.add_argument("--agent-address", required=True)
    echo = sub.add_parser("echo")
    echo.add_argument("--host", default="0.0.0.0")
    echo.add_argument("--port", type=int, default=18082)
    echo.add_argument("--max-seconds", type=int, default=600)
    binary = sub.add_parser("probe")
    binary.add_argument("--host", required=True)
    binary.add_argument("--port", type=int, required=True)
    binary.add_argument("--timeout", type=float, default=2)
    verify = sub.add_parser("verify-ferrum")
    verify.add_argument("directory", type=Path)
    settling = sub.add_parser("settle-ferrum-counter")
    settling.add_argument("directory", type=Path)
    sub.add_parser("public-config")
    consul = sub.add_parser("verify-consul")
    consul.add_argument("directory", type=Path)
    consul.add_argument("--topology", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "render":
        render(args.directory, args.endpoint, args.vip, args.backend_port, args.raw_port)
    elif args.command == "bootstrap":
        adapt_bootstrap(args.path, args.agent_address)
    elif args.command == "settle-ferrum-counter":
        result = settle_ferrum_counter(args.directory)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0 if result["accepted"] else 1
    elif args.command == "public-config":
        print(json.dumps(public_config(json.load(sys.stdin)), indent=2, allow_nan=False))
    elif args.command == "echo":
        echo_server(args.host, args.port, args.max_seconds)
    elif args.command == "probe":
        try:
            print(json.dumps(probe(args.host, args.port, args.timeout), allow_nan=False), flush=True)
        except TimeoutError as error:
            print(json.dumps({"ok": False, "error": str(error), "kind": "timeout"}), flush=True)
            return 3
        except OSError as error:
            print(json.dumps({"ok": False, "error": str(error), "kind": type(error).__name__}), flush=True)
            return 1
    else:
        result = verify_consul(args.directory, args.topology) if args.command == "verify-consul" else verify_ferrum(args.directory)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0 if result["accepted"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
