#!/usr/bin/env bash
# Source from run_mesh_runtime_bench.sh. Every privileged network mutation is
# scoped to the live PID of this run's own Docker namespace holder. No host
# iptables/sysctl/route mutation. Runtime source is never modified.
# Required caller variables: SCRIPT_DIR RUNTIME_DIR OUTPUT_DIR TOOLS_IMAGE
# FERRUM_IMAGE ENVOY_IMAGE CONSUL_IMAGE CERT_DIR CERT_GID RUN_ID BACKEND_PORT
# CLIENT_NAME SERVER_NAME AGENT_NAME READINESS_DEADLINE and readiness_command.
# Caller must apply LOADGEN_NETWORK_ARGS to all readiness/measured loadgens,
# bind the application backend to 0.0.0.0, and call mesh_l4_cleanup from its trap.

L4_VIP=192.0.2.50
L4_RAW_PORT=18082
L4_PROXY_UID=65532
L4_APP_UID=65531
L4_ECHO_PID=""
L4_NETNS_NAME=""
L4_NETWORK_NAME=""
L4_OWNER=""

mesh_l4_ns() {
    local pid running
    running=$(readiness_command 3 docker inspect --format '{{.State.Running}}' "$L4_NETNS_NAME") || return 1
    pid=$(readiness_command 3 docker inspect --format '{{.State.Pid}}' "$L4_NETNS_NAME") || return 1
    [ "$running" = true ] && [ "$pid" = "$L4_NETNS_PID" ] && [ "$pid" -gt 1 ] || return 1
    readiness_command 8 sudo -n nsenter --net="/proc/$pid/ns/net" -- "$@"
}

# The invoking runner opens this public script before setpriv changes UID.
# Unprivileged fixture identities need no traversal access to the checkout.
mesh_l4_probe() {
    mesh_l4_ns setpriv --reuid="$L4_APP_UID" --regid="$L4_APP_UID" --clear-groups -- \
        python3 - probe --host "$L4_VIP" --port "$L4_RAW_PORT" --timeout 2 < "$SCRIPT_DIR/mesh_l4_fixture.py"
}

mesh_l4_wait_binary() {
    local expected="$1" phase="$2" rc consecutive=0 needed=1
    if [ "$expected" -eq 1 ]; then needed=2; fi
    while [ "$SECONDS" -lt "$READINESS_DEADLINE" ]; do
        readiness_command 3 docker inspect --format '{{.State.Running}}' "$CLIENT_NAME" "$SERVER_NAME" \
            | { read -r a; read -r b; [ "$a" = true ] && [ "$b" = true ]; } || return 1
        kill -0 "$L4_ECHO_PID" || return 1
        rc=0
        mesh_l4_probe >> "$OUTPUT_DIR/logs/l4-${phase}.jsonl" 2>&1 || rc=$?
        if [ "$rc" -eq "$expected" ]; then
            consecutive=$((consecutive + 1))
            [ "$consecutive" -ge "$needed" ] && return 0
        else
            consecutive=0
        fi
        [ "$rc" -le 1 ] || return "$rc"
        sleep 0.2
    done
    echo "[l4] shared readiness deadline expired in $phase" >&2
    return 1
}

mesh_l4_setup() {
    local arm="$1"
    L4_NETWORK_NAME="meshbench-l4-${RUN_ID}-${arm}"
    L4_NETNS_NAME="${L4_NETWORK_NAME}-netns"
    L4_OWNER="$RUN_ID-$arm"
    L4_CONFIG_DIR="$RUNTIME_DIR/l4"
    mkdir -p "$L4_CONFIG_DIR"
    readiness_command 5 docker network create --internal --label "ferrum.meshbench.l4=$L4_OWNER" "$L4_NETWORK_NAME" > "$L4_CONFIG_DIR/network-id.txt"
    L4_GATEWAY=$(readiness_command 3 docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$L4_NETWORK_NAME")
    python3 "$SCRIPT_DIR/mesh_l4_fixture.py" render --directory "$L4_CONFIG_DIR" --endpoint "$L4_GATEWAY" \
        --vip "$L4_VIP" --backend-port "$BACKEND_PORT" --raw-port "$L4_RAW_PORT"
    # Public plans/configs survive artifact exclusion of runtime credentials.
    mkdir -p "$OUTPUT_DIR/logs/l4-fixture-configs"
    local public_config
    for public_config in source destination destination-allow destination-deny consul-svc consul-svc-raw consul-client consul-allow consul-deny topology; do
        cp "$L4_CONFIG_DIR/$public_config.json" "$OUTPUT_DIR/logs/l4-fixture-configs/$public_config.json"
    done
    # An idle tools container owns the namespace, like a pod sandbox. Neither
    # proxy lifecycle nor measured loadgen lifecycle can replace that namespace.
    readiness_command 8 docker run --label "$BENCH_OWNER_LABEL" -d --network "$L4_NETWORK_NAME" --name "$L4_NETNS_NAME" --label "ferrum.meshbench.l4=$L4_OWNER" \
        --entrypoint /usr/local/bin/mesh_backend "$TOOLS_IMAGE" --listen 127.0.0.1:18081 >/dev/null
    L4_NETNS_PID=$(readiness_command 3 docker inspect --format '{{.State.Pid}}' "$L4_NETNS_NAME")
    LOADGEN_NETWORK="container:$L4_NETNS_NAME"
    LOADGEN_USER="$L4_APP_UID:$L4_APP_UID"
    LOADGEN_NETWORK_ARGS=(--network "$LOADGEN_NETWORK" --user "$LOADGEN_USER")
    TARGET_URL="http://$L4_VIP:$BACKEND_PORT/echo"
    # Internal bridges may omit a default route. Route just the synthetic VIP
    # in this namespace so initial route lookup can reach the OUTPUT hook.
    mesh_l4_ns ip route add "$L4_VIP/32" via "$L4_GATEWAY"
    python3 "$SCRIPT_DIR/mesh_l4_fixture.py" echo --host "$L4_GATEWAY" --port "$L4_RAW_PORT" \
        --max-seconds "${L4_FIXTURE_WALL_SECS:-600}" > "$OUTPUT_DIR/logs/l4-binary-backend.log" 2>&1 &
    L4_ECHO_PID=$!
    # Fixture REDIRECT, not a claim that the distroless runtime installs rules.
    # Mirrors src/capture/mod.rs LOCAL/owner/REDIRECT ordering. Only this VIP is
    # captured; SO_ORIGINAL_DST therefore carries the actual declared VIP:port.
    mesh_l4_ns sh -s -- "$L4_PROXY_UID" "$L4_VIP" "$BACKEND_PORT" "$L4_RAW_PORT" <<'RULES'
set -eu
proxy_uid=$1
vip=$2
backend_port=$3
raw_port=$4
iptables -w 2 -t nat -N FERRUM_BENCH_L4_OUTPUT
iptables -w 2 -t nat -A FERRUM_BENCH_L4_OUTPUT -m addrtype --dst-type LOCAL -j RETURN
iptables -w 2 -t nat -A FERRUM_BENCH_L4_OUTPUT -m owner --uid-owner "$proxy_uid" -j RETURN
iptables -w 2 -t nat -A FERRUM_BENCH_L4_OUTPUT -p tcp -d "$vip/32" -j REDIRECT --to-ports 15101
iptables -w 2 -t nat -A OUTPUT -p tcp -j FERRUM_BENCH_L4_OUTPUT
# Source proxy cannot reach either application port directly. Only B's
# authenticated mesh listener is reachable, and B dials applications in hostns.
iptables -w 2 -t filter -I OUTPUT 1 -p tcp -m owner --uid-owner "$proxy_uid" -m multiport --dports "$backend_port,$raw_port" -j REJECT
RULES
    mesh_l4_ns iptables-save > "$OUTPUT_DIR/logs/l4-capture-rules.txt"
    readiness_command 3 docker inspect "$L4_NETNS_NAME" > "$OUTPUT_DIR/logs/l4-netns-inspect.json"
    readiness_command 3 docker network inspect "$L4_NETWORK_NAME" > "$OUTPUT_DIR/logs/l4-network-inspect.json"
}

start_ferrum_l4() {
    mesh_l4_setup ferrumtcp
    readiness_command 8 docker run --label "$BENCH_OWNER_LABEL" -d --network host --name "$SERVER_NAME" --user 65532:65532 --group-add "$CERT_GID" \
        -v "$L4_CONFIG_DIR:/etc/ferrum/bench:ro" -v "$CERT_DIR/svc:/etc/ferrum/svid:ro" \
        -e FERRUM_MODE=mesh -e FERRUM_NAMESPACE=ferrum -e FERRUM_MESH_TOPOLOGY=sidecar -e FERRUM_WORKER_THREADS="${BENCH_WORKERS:-4}" \
        -e FERRUM_MESH_CONFIG_PROTOCOL=file -e FERRUM_MESH_FILE_CONFIG_PATH=/etc/ferrum/bench/destination.json \
        -e FERRUM_MESH_PRODUCTION_MODE=true -e FERRUM_MESH_WORKLOAD_SPIFFE_ID=spiffe://cluster.local/ns/ferrum/sa/svc \
        -e FERRUM_GATEWAY_SVID_CERT_PATH=/etc/ferrum/svid/svid.crt -e FERRUM_GATEWAY_SVID_KEY_PATH=/etc/ferrum/svid/svid.key \
        -e FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH=/etc/ferrum/svid/bundle.pem \
        -e FERRUM_MESH_INBOUND_LISTEN_ADDR=0.0.0.0:15006 -e FERRUM_MESH_OUTBOUND_LISTEN_ADDR=127.0.0.1:15001 \
        -e FERRUM_MESH_DNS_PROXY_ENABLED=false -e FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=0 \
        -e FERRUM_POOL_WARMUP_ENABLED=false -e FERRUM_PROXY_HTTP_PORT=0 \
        -e FERRUM_ADMIN_HTTP_PORT=15020 -e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
        -e FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32 -e FERRUM_LOG_LEVEL=error "$FERRUM_IMAGE" >/dev/null
    readiness_command 8 docker run --label "$BENCH_OWNER_LABEL" -d --network "$LOADGEN_NETWORK" --name "$CLIENT_NAME" --user 65532:65532 --group-add "$CERT_GID" \
        -v "$L4_CONFIG_DIR:/etc/ferrum/bench:ro" -v "$CERT_DIR/client:/etc/ferrum/svid:ro" \
        -e FERRUM_MODE=mesh -e FERRUM_NAMESPACE=ferrum -e FERRUM_MESH_TOPOLOGY=sidecar -e FERRUM_WORKER_THREADS="${BENCH_WORKERS:-4}" \
        -e FERRUM_MESH_CONFIG_PROTOCOL=file -e FERRUM_MESH_FILE_CONFIG_PATH=/etc/ferrum/bench/source.json \
        -e FERRUM_MESH_PRODUCTION_MODE=true -e FERRUM_MESH_WORKLOAD_SPIFFE_ID=spiffe://cluster.local/ns/ferrum/sa/client \
        -e FERRUM_GATEWAY_SVID_CERT_PATH=/etc/ferrum/svid/svid.crt -e FERRUM_GATEWAY_SVID_KEY_PATH=/etc/ferrum/svid/svid.key \
        -e FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH=/etc/ferrum/svid/bundle.pem \
        -e FERRUM_MESH_INBOUND_LISTEN_ADDR=127.0.0.1:15106 -e FERRUM_MESH_OUTBOUND_LISTEN_ADDR=127.0.0.1:15101 \
        -e FERRUM_MESH_CAPTURE_MODE=iptables -e FERRUM_MESH_PROXY_UID=65532 -e FERRUM_MESH_EGRESS_MTLS_PORT=15006 \
        -e FERRUM_MESH_OUTBOUND_TRAFFIC_POLICY=registry_only \
        -e FERRUM_MESH_DNS_PROXY_ENABLED=false -e FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=0 \
        -e FERRUM_POOL_WARMUP_ENABLED=false -e FERRUM_PROXY_HTTP_PORT=0 \
        -e FERRUM_ADMIN_HTTP_PORT=15120 -e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
        -e FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32 -e FERRUM_LOG_LEVEL=error "$FERRUM_IMAGE" >/dev/null
}

start_consul_l4() {
    mesh_l4_setup consultcp
    # Agent listens only on loopback plus this private bridge's host address.
    # No public bind. TLS data-plane identity remains Consul CA/xDS/SDS owned.
    readiness_command 8 docker run --label "$BENCH_OWNER_LABEL" -d --network host --name "$AGENT_NAME" "$CONSUL_IMAGE" \
        agent -dev -client="127.0.0.1 $L4_GATEWAY" -bind=127.0.0.1 >/dev/null
    while ! readiness_command 3 docker exec "$AGENT_NAME" consul members >/dev/null 2>&1; do
        [ "$SECONDS" -lt "$READINESS_DEADLINE" ] || return 1
        [ "$(readiness_command 3 docker inspect --format '{{.State.Running}}' "$AGENT_NAME")" = true ] || return 1
        sleep 0.2
    done
    local file
    for file in consul-svc consul-svc-raw consul-client consul-allow consul-deny; do
        readiness_command 3 docker cp "$L4_CONFIG_DIR/$file.json" "$AGENT_NAME:/tmp/$file.json"
    done
    readiness_command 3 docker exec "$AGENT_NAME" consul services register /tmp/consul-svc.json >/dev/null
    readiness_command 3 docker exec "$AGENT_NAME" consul services register /tmp/consul-client.json >/dev/null
    readiness_command 3 docker exec "$AGENT_NAME" consul config write /tmp/consul-allow.json >/dev/null
    readiness_command 5 docker exec "$AGENT_NAME" consul connect envoy -sidecar-for svc-1 -bootstrap > "$L4_CONFIG_DIR/svc-bootstrap.json"
    readiness_command 5 docker exec "$AGENT_NAME" consul connect envoy -sidecar-for client-1 -bootstrap > "$L4_CONFIG_DIR/client-bootstrap.json"
    python3 "$SCRIPT_DIR/prepare_consul_bootstrap.py" "$L4_CONFIG_DIR/svc-bootstrap.json" 19002
    python3 "$SCRIPT_DIR/prepare_consul_bootstrap.py" "$L4_CONFIG_DIR/client-bootstrap.json" 19001
    python3 "$SCRIPT_DIR/mesh_l4_fixture.py" bootstrap "$L4_CONFIG_DIR/client-bootstrap.json" --agent-address "$L4_GATEWAY"
    readiness_command 8 docker run --label "$BENCH_OWNER_LABEL" -d --network host --name "$SERVER_NAME" --user 65532:65532 \
        -v "$L4_CONFIG_DIR/svc-bootstrap.json:/bootstrap.json:ro" "$ENVOY_IMAGE" -c /bootstrap.json --base-id 0 --concurrency "${BENCH_WORKERS:-4}" -l error >/dev/null
    readiness_command 8 docker run --label "$BENCH_OWNER_LABEL" -d --network "$LOADGEN_NETWORK" --name "$CLIENT_NAME" --user 65532:65532 \
        -v "$L4_CONFIG_DIR/client-bootstrap.json:/bootstrap.json:ro" "$ENVOY_IMAGE" -c /bootstrap.json --base-id 1 --concurrency "${BENCH_WORKERS:-4}" -l error >/dev/null
}

mesh_l4_snapshot() {
    local phase="$1" source_port server_port suffix
    mkdir -p "$OUTPUT_DIR/logs/l4-$phase"
    if [ "$MESH" = ferrumtcp ]; then
        source_port=15120; server_port=15020; suffix=metrics
    else
        source_port=19001; server_port=19002; suffix=stats
    fi
    mesh_l4_ns curl --connect-timeout 1 --max-time 2 -fsS "http://127.0.0.1:$source_port/$suffix" \
        > "$OUTPUT_DIR/logs/l4-$phase/source.metrics"
    readiness_command 3 curl --connect-timeout 1 --max-time 2 -fsS "http://127.0.0.1:$server_port/$suffix" \
        > "$OUTPUT_DIR/logs/l4-$phase/destination.metrics"
    if [ "$MESH" = consultcp ]; then
        mesh_l4_ns curl --connect-timeout 1 --max-time 2 -fsS 'http://127.0.0.1:19001/config_dump?resource=dynamic_listeners' \
            | python3 "$SCRIPT_DIR/mesh_l4_fixture.py" public-config > "$OUTPUT_DIR/logs/l4-$phase/source-config.json"
        readiness_command 3 curl --connect-timeout 1 --max-time 2 -fsS 'http://127.0.0.1:19002/config_dump?resource=dynamic_listeners' \
            | python3 "$SCRIPT_DIR/mesh_l4_fixture.py" public-config > "$OUTPUT_DIR/logs/l4-$phase/destination-config.json"
        mesh_l4_ns curl --connect-timeout 1 --max-time 2 -fsS http://127.0.0.1:19001/certs \
            > "$OUTPUT_DIR/logs/l4-$phase/source-certs.json"
        readiness_command 3 curl --connect-timeout 1 --max-time 2 -fsS http://127.0.0.1:19002/certs \
            > "$OUTPUT_DIR/logs/l4-$phase/destination-certs.json"
    fi
}

mesh_l4_prove() {
    # First show the raw echo backend itself is alive, then prove the source
    # proxy UID cannot bypass B and dial that backend directly.
    kill -0 "$L4_ECHO_PID" || return 1
    readiness_command 3 python3 "$SCRIPT_DIR/mesh_l4_fixture.py" probe --host "$L4_GATEWAY" --port "$L4_RAW_PORT" \
        >> "$OUTPUT_DIR/logs/l4-raw-direct.jsonl"
    local rc=0
    mesh_l4_ns setpriv --reuid="$L4_PROXY_UID" --regid="$L4_PROXY_UID" --clear-groups -- \
        python3 - probe --host "$L4_GATEWAY" --port "$L4_RAW_PORT" < "$SCRIPT_DIR/mesh_l4_fixture.py" \
        >> "$OUTPUT_DIR/logs/l4-bypass-blocked.jsonl" 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || { echo '[l4] source proxy direct-backend block was not proved' >&2; return 1; }
    if [ "$MESH" = consultcp ]; then
        readiness_command 3 docker exec "$AGENT_NAME" consul services register /tmp/consul-svc-raw.json >/dev/null
    fi
    mesh_l4_wait_binary 0 allowed || return 1
    mesh_l4_snapshot allowed || return 1
    if [ "$MESH" = ferrumtcp ]; then
        cp "$L4_CONFIG_DIR/destination-deny.json" "$L4_CONFIG_DIR/destination.next.json"
        mv "$L4_CONFIG_DIR/destination.next.json" "$L4_CONFIG_DIR/destination.json"
        readiness_command 3 docker kill --signal HUP "$SERVER_NAME" >/dev/null
    else
        readiness_command 3 docker exec "$AGENT_NAME" consul config write /tmp/consul-deny.json >/dev/null
    fi
    mesh_l4_wait_binary 1 denied || return 1
    mesh_l4_snapshot denied || return 1
    if [ "$MESH" = ferrumtcp ]; then
        cp "$L4_CONFIG_DIR/destination-allow.json" "$L4_CONFIG_DIR/destination.next.json"
        mv "$L4_CONFIG_DIR/destination.next.json" "$L4_CONFIG_DIR/destination.json"
        readiness_command 3 docker kill --signal HUP "$SERVER_NAME" >/dev/null
    else
        readiness_command 3 docker exec "$AGENT_NAME" consul config write /tmp/consul-allow.json >/dev/null
    fi
    mesh_l4_wait_binary 0 restored || return 1
    mesh_l4_snapshot restored || return 1
    if [ "$MESH" = ferrumtcp ]; then
        python3 "$SCRIPT_DIR/mesh_l4_fixture.py" verify-ferrum "$OUTPUT_DIR/logs/l4-restored/source.metrics" \
            "$OUTPUT_DIR/logs/l4-restored/destination.metrics" > "$OUTPUT_DIR/logs/l4-transport-proof.json" || return 1
    else
        python3 "$SCRIPT_DIR/mesh_l4_fixture.py" verify-consul "$OUTPUT_DIR/logs/l4-restored" \
            > "$OUTPUT_DIR/logs/l4-transport-proof.json" || return 1
        readiness_command 3 docker exec "$AGENT_NAME" consul services register /tmp/consul-svc.json >/dev/null
    fi
    # The caller now requires byte-exact H1 readiness again before measuring.
    # Probe-only Python echo stays idle; cleanup owns its exact child PID.
    echo '[l4] binary keepalive/half-close, mTLS stream metrics, destination deny/restore proved' >&2
}

mesh_l4_cleanup() {
    # Called after root runner removes the source sidecar and loadgen. Never
    # remove foreign namespaces/networks or global Docker state.
    if [ -n "$L4_ECHO_PID" ]; then
        # Only signal a still-running job owned by this shell. The echo has
        # its own wall cap and may already have exited during a long arm.
        if jobs -pr | grep -Fxq "$L4_ECHO_PID"; then
            kill "$L4_ECHO_PID" 2>/dev/null || true
        fi
        wait "$L4_ECHO_PID" 2>/dev/null || true
        L4_ECHO_PID=""
    fi
    local owner
    if [ -n "$L4_NETNS_NAME" ]; then
        owner=$(timeout --signal=KILL 3s docker inspect --format '{{index .Config.Labels "ferrum.meshbench.l4"}}' "$L4_NETNS_NAME" 2>/dev/null) || owner=""
        if [ "$owner" = "$L4_OWNER" ] && [ -n "$L4_OWNER" ]; then
            timeout --signal=KILL 5s docker rm -f "$L4_NETNS_NAME" >/dev/null 2>&1 || true
        fi
    fi
    if [ -n "$L4_NETWORK_NAME" ]; then
        owner=$(timeout --signal=KILL 3s docker network inspect --format '{{index .Labels "ferrum.meshbench.l4"}}' "$L4_NETWORK_NAME" 2>/dev/null) || owner=""
        if [ "$owner" = "$L4_OWNER" ] && [ -n "$L4_OWNER" ]; then
            timeout --signal=KILL 5s docker network rm "$L4_NETWORK_NAME" >/dev/null 2>&1 || true
        fi
    fi
}
