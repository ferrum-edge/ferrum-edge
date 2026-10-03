"""Data-only same-image Ferrum experiments; never execute manifest contents."""

import json
import hashlib
import re
from pathlib import Path


def load_experiment(path, protocol):
    plan = json.loads(Path(path).read_text())
    if set(plan) - {"enabled", "name", "protocol", "arms", "h2_campaign", "h2_guard_observation"} or not {
            "enabled", "name", "protocol", "arms"} <= set(plan):
        raise ValueError("unexpected experiment fields")
    if not isinstance(plan["enabled"], bool):
        raise ValueError("enabled must be boolean")
    if not isinstance(plan["name"], str) or not re.fullmatch(r"[a-z0-9-]{1,80}", plan["name"]):
        raise ValueError("invalid experiment name")
    protocols = plan["protocol"] if isinstance(plan["protocol"], list) else [plan["protocol"]]
    if not protocols or len(set(protocols)) != len(protocols) or any(
            p not in ("http1-tls", "http2", "http3", "grpcs", "wss", "tcp-tls", "udp", "udp-dtls")
            for p in protocols):
        raise ValueError("invalid experiment protocol")
    arms = plan["arms"]
    if not isinstance(arms, list) or not 2 <= len(arms) <= 4:
        raise ValueError("declare two to four arms, including ferrum")
    names = set()
    for arm in arms:
        if not isinstance(arm, dict) or set(arm) != {"gateway", "FERRUM_EXTRA_ENV"}:
            raise ValueError("arms may change only FERRUM_EXTRA_ENV")
        name, env = arm["gateway"], arm["FERRUM_EXTRA_ENV"]
        if not isinstance(name, str) or not re.fullmatch(r"ferrum(?:-exp-[a-z0-9-]{1,40})?", name):
            raise ValueError("invalid Ferrum experiment arm")
        if name in names:
            raise ValueError("duplicate experiment arm")
        names.add(name)
        parse_env(env)
    if arms[0]["gateway"] != "ferrum":
        raise ValueError("first arm must be the ferrum reference")
    if "h2_guard_observation" in plan and (type(plan["h2_guard_observation"]) is not int or plan["h2_guard_observation"] != 1 or "h2_campaign" not in plan):
        raise ValueError("guard observation requires the H2 campaign and schema 1")
    if "h2_campaign" in plan:
        expected = dict(pairs=4, duration=15, concurrency=200,
                        payload_sizes={"http2": [71680], "grpcs": [10240, 71680]})
        if protocols != ["http2", "grpcs"] or plan["h2_campaign"] != expected:
            raise ValueError("H2 campaign must retain its predeclared scope and four pairs")
        level = "warn,ferrum_h2_observe=debug"
        if plan.get("h2_guard_observation") == 1:
            level += ",ferrum_h2_guard=debug"
        common = dict(FERRUM_LOG_LEVEL=level,
                      FERRUM_METRICS_ALLOWED_CIDRS="127.0.0.1/32", FERRUM_ADMIN_HTTP_PORT="9000")
        if len(arms) != 2 or any(parse_env(arm["FERRUM_EXTRA_ENV"]) != dict(
                common, FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=adaptive)
                for arm, adaptive in zip(arms, ("true", "false"))):
            raise ValueError("H2 arms must differ only in adaptive windows")
    return plan if plan["enabled"] and protocol in protocols else None


def parse_env(env):
    if not isinstance(env, str) or not env or env != " ".join(env.split()):
        raise ValueError("environment must contain literal space-separated KEY=VALUE entries")
    result = {}
    for entry in env.split(" "):
        key, separator, value = entry.partition("=")
        valid = re.fullmatch(r"[a-zA-Z0-9_.:/-]+", value)
        if key == "FERRUM_LOG_LEVEL" and value in ("warn,ferrum_h2_observe=debug",
                "warn,ferrum_h2_observe=debug,ferrum_h2_guard=debug"):
            valid = True
        # EXPERIMENT ONLY (not for merge): jemalloc runtime options.
        if key == "_RJEM_MALLOC_CONF" and re.fullmatch(r"[a-z_]+:[a-z0-9]+(,[a-z_]+:[a-z0-9]+)*", value):
            valid = True
        if not separator or not (re.fullmatch(r"FERRUM_[A-Z0-9_]+", key) or key == "_RJEM_MALLOC_CONF") or not valid:
            raise ValueError("environment must contain literal space-separated KEY=VALUE entries")
        if key in result:
            raise ValueError("duplicate environment key")
        result[key] = value
    return result


def materialize_h2(plan, protocol, gateway, source, destination, manifest):
    """Narrow edit of controlled fixtures; fail on drift, never general YAML parsing."""
    if not plan or "h2_campaign" not in plan:
        raise ValueError("route materialization requires the validated H2 campaign")
    arm = next(arm for arm in plan["arms"] if arm["gateway"] == gateway)
    env = parse_env(arm["FERRUM_EXTRA_ENV"])
    adaptive = env["FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW"] == "true"
    text = Path(source).read_text()
    expected = dict(pool_http2_initial_stream_window_size="8388608",
                    pool_http2_initial_connection_window_size="33554432",
                    pool_http2_max_frame_size="1048576", pool_http2_max_concurrent_streams="1000",
                    pool_http2_keep_alive_interval_seconds="30",
                    pool_http2_keep_alive_timeout_seconds="45", pool_http2_adaptive_window="false")
    for key, value in expected.items():
        matches = re.findall(r"(?m)^    " + key + r":\s*(\S+)[^\n]*$", text)
        if matches != [value]:
            raise ValueError(f"unexpected route fixture: {key}={matches}")
    text = re.sub(r"(?m)^(    pool_http2_adaptive_window:)\s*(?:true|false)[^\n]*$",
                  r"\g<1> " + str(adaptive).lower(), text)
    text = text.replace("CA_PATH", "/etc/ferrum/tls/ca.pem")
    Path(destination).write_text(text)
    # Read back exactly what will be mounted, including the route override.
    materialized = Path(destination).read_bytes()
    if re.findall(rb"(?m)^    pool_http2_adaptive_window: (true|false)$", materialized) != [
            str(adaptive).lower().encode()]:
        raise ValueError("effective route adaptive flag does not match arm")
    settings = dict(adaptive_window=adaptive, configured_stream_window=8388608,
                    configured_connection_window=33554432,
                    builder_initial_stream_window=65535 if adaptive else 8388608,
                    builder_initial_connection_window=65535 if adaptive else 33554432,
                    max_frame_size=1048576, max_concurrent_streams=1000,
                    configured_pool_shards=16,
                    provenance="verified route plus pinned Hyper builder semantics; not negotiated observations")
    document = json.loads(Path(manifest).read_text())
    document.setdefault("effective_h2_arms", {})[gateway] = dict(
        protocol=protocol, environment=env, settings=settings,
        route_sha256=hashlib.sha256(materialized).hexdigest(),
        route_config=str(Path(destination).name))
    Path(manifest).write_text(json.dumps(document, indent=2) + "\n")


def verify_runtime(plan, gateway, container, manifest):
    arm = next(arm for arm in plan["arms"] if arm["gateway"] == gateway)
    expected = dict(parse_env(arm["FERRUM_EXTRA_ENV"]),
                    FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE="8388608",
                    FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE="33554432",
                    FERRUM_POOL_HTTP2_MAX_FRAME_SIZE="1048576",
                    FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS="1000",
                    FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS="1000",
                    FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES="0")
    environment = dict(entry.split("=", 1) for entry in container["Config"]["Env"])
    if environment.get("RUST_LOG") or any(environment.get(key) != value for key, value in expected.items()):
        raise ValueError("container environment differs from the declared H2 campaign")
    document = json.loads(Path(manifest).read_text())
    record = document["effective_h2_arms"][gateway]
    record["verified_container_environment"] = expected
    record["image_id"] = container["Image"]
    if len({arm["image_id"] for arm in document["effective_h2_arms"].values() if "image_id" in arm}) != 1:
        raise ValueError("H2 arms used different images")
    Path(manifest).write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    import sys

    command, path, protocol, *args = sys.argv[1:]
    plan = load_experiment(path, protocol)
    if command == "names":
        print(" ".join(arm["gateway"] for arm in plan["arms"][1:]) if plan else "")
    elif command == "guard":
        print(1 if plan and plan.get("h2_guard_observation") == 1 else 0)
    elif command == "env":
        matches = [arm for arm in plan["arms"] if arm["gateway"] == args[0]] if plan else []
        if len(matches) != 1:
            raise SystemExit("missing experiment arm")
        print(matches[0]["FERRUM_EXTRA_ENV"])
    elif command == "campaign":
        if plan and "h2_campaign" in plan:
            campaign = plan["h2_campaign"]
            duration, concurrency, gateways, adaptive, sizes = args
            if int(duration) != campaign["duration"] or int(concurrency) != campaign["concurrency"]:
                raise SystemExit("H2 campaign requires duration=15 and concurrency=200")
            if gateways.split() != ["ferrum"] or adaptive != "false":
                raise SystemExit("H2 campaign requires only Ferrum, repeated direct, no extension")
            if not set(campaign["payload_sizes"][protocol]) <= set(map(int, sizes.split())):
                raise SystemExit("H2 campaign requested payloads are missing")
            print(campaign["pairs"], *campaign["payload_sizes"][protocol])
    elif command == "materialize":
        materialize_h2(plan, protocol, *args)
    elif command == "verify-runtime":
        verify_runtime(plan, args[0], json.load(sys.stdin), args[1])
    else:
        raise SystemExit("unknown experiment command")
