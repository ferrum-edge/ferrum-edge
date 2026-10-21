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
import json
import math
import re
import selectors
import socket
import sys
import time
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


def verify_ferrum(source: Path, destination: Path) -> dict:
    errors = []
    src, dst = list(samples(source)), list(samples(destination))
    if not any(name == "ferrum_mesh_tcp_egress_connections_total" and labels.get("transport") == "mtls"
               and labels.get("result") == "success" and value > 0 for name, labels, value in src):
        errors.append("no successful captured mtls TCP egress completion")
    for role, records in (("source", src), ("destination", dst)):
        def matching(name):
            return sum(value for metric, labels, value in records if metric == name
                       and labels.get("connection_security_policy") == "mutual_tls"
                       and labels.get("destination_principal") == DESTINATION
                       and (role == "source" or labels.get("source_principal") == SOURCE))
        for name in ("ferrum_mesh_tcp_connections_opened_total", "ferrum_mesh_tcp_connections_closed_total",
                     "ferrum_mesh_tcp_sent_bytes_total", "ferrum_mesh_tcp_received_bytes_total"):
            if matching(name) <= 0:
                errors.append(f"{role}: missing authenticated identity-bound {name}")
    return {"accepted": not errors, "errors": errors, "expected_transport": "mtls",
            "source_identity": SOURCE, "destination_identity": DESTINATION,
            "note": "proof counters include fixture probes; measured-cell connection deltas are reported separately"}


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


def verify_consul(directory: Path) -> dict:
    # Reuse the active measured-listener checker. A TCP filter elsewhere in
    # the dump, or a warming listener, never proves the measured transport.
    module_spec = importlib.util.spec_from_file_location("verify_consul_protocol", Path(__file__).with_name("verify_consul_protocol.py"))
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    verify, active_listeners = module.verify, module.active_listeners
    docs = [json.loads((directory / f"{role}-config.json").read_text())
            for role in ("source", "destination")]
    result = verify("consul", docs)
    errors = [] if result["accepted"] else ["active measured filters are not TCP"]
    inbound = [listener for listener in active_listeners(docs[1])
               if listener.get("address", {}).get("socket_address", {}).get("port_value") == 21000]
    chains = [chain for listener in inbound for chain in listener.get("filter_chains", [])]
    if not chains or any(chain.get("transport_socket", {}).get("name") != "envoy.transport_sockets.tls"
                         or chain.get("transport_socket", {}).get("typed_config", {}).get("require_client_certificate") is not True
                         for chain in chains):
        errors.append("destination TCP listener does not require client TLS certificate")
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
    verify.add_argument("source", type=Path)
    verify.add_argument("destination", type=Path)
    sub.add_parser("public-config")
    consul = sub.add_parser("verify-consul")
    consul.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "render":
        render(args.directory, args.endpoint, args.vip, args.backend_port, args.raw_port)
    elif args.command == "bootstrap":
        adapt_bootstrap(args.path, args.agent_address)
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
        result = verify_consul(args.directory) if args.command == "verify-consul" else verify_ferrum(args.source, args.destination)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0 if result["accepted"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
