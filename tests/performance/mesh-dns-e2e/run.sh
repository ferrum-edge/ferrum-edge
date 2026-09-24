#!/bin/bash
# Mesh DNS proxy E2E perf harness for Ferrum Edge.
# Usage: ./run.sh [options]
#   --duration <secs>     Test duration (default: 30)
#   --concurrency <n>     Parallel query workers (default: 100)
#   --protocol <p>        udp | tcp | both  (default: both)
#   --edns <n>            EDNS(0) udp_payload_size; 0 = off (default: 0)
#   --skip-build          Reuse existing binaries (gateway + harness)
#   --json                Emit JSON results, not a text table

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
DURATION=30
CONCURRENCY=100
PROTOCOL=both
EDNS=0
JSON_FLAG=""
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --protocol) PROTOCOL="$2"; shift 2 ;;
        --edns) EDNS="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --json) JSON_FLAG="--json"; shift ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Ports. Sidecar topology only binds inbound/outbound/HBONE; east-west /
# egress addresses are still exported below so that a future topology swap
# (or a node-waypoint variant) does not collide with whatever the operator
# is running on those ports. They are otherwise unused.
GATEWAY_DNS_PORT=15053
UPSTREAM_STUB_PORT=17053
CP_STUB_PORT=17070
INBOUND_PORT=17006
OUTBOUND_PORT=17001
HBONE_PORT=17008
EAST_WEST_PORT=17443
EGRESS_PORT=17090

# Every fixed port this run binds (gateway DNS, stubs, sidecar topology). The
# startup conflict check and cleanup share this list so they cannot drift apart.
BENCH_PORTS="$GATEWAY_DNS_PORT $UPSTREAM_STUB_PORT $CP_STUB_PORT \
$INBOUND_PORT $OUTBOUND_PORT $HBONE_PORT $EAST_WEST_PORT $EGRESS_PORT"

GATEWAY_PID=""
CP_STUB_PID=""
UPSTREAM_PID=""

# Gracefully stop a PID this run started: TERM, bounded wait, then KILL.
stop_pid() {
    local pid="$1"
    local attempt
    [ -z "$pid" ] && return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for attempt in 1 2 3 4 5; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

# Refuse a port that is already bound instead of killing its owner.
check_port_available() {
    local port="$1"
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        echo -e "${RED}Required TCP port $port is already in use. Inspect it with: lsof -nP -iTCP:$port -sTCP:LISTEN${NC}"
        return 1
    fi
    if lsof -nP -iUDP:"$port" >/dev/null 2>&1; then
        echo -e "${RED}Required UDP port $port is already in use. Inspect it with: lsof -nP -iUDP:$port${NC}"
        return 1
    fi
}

check_ports_available() {
    if ! command -v lsof >/dev/null 2>&1; then
        echo -e "${RED}lsof is required to detect port conflicts before starting.${NC}"
        return 1
    fi
    local port
    for port in $BENCH_PORTS; do
        check_port_available "$port" || return 1
    done
}

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    archive_failure_diagnostics
    stop_pid "$GATEWAY_PID"
    stop_pid "$CP_STUB_PID"
    stop_pid "$UPSTREAM_PID"
    echo -e "${GREEN}Cleanup complete${NC}"
}
trap cleanup EXIT

archive_failure_diagnostics() {
    local dest="${MESH_BASELINE_DIAG_DIR:-}"
    local log
    # Opt-in copy of process logs for hosted artifact upload. Never copy
    # credential material; JWT secrets stay in process env, not these files.
    if [[ -z "$dest" ]]; then
        return 0
    fi
    mkdir -p "$dest"
    for log in gateway.log upstream.log cp_stub.log; do
        if [[ -f "$SCRIPT_DIR/$log" ]]; then
            cp "$SCRIPT_DIR/$log" "$dest/$log" || true
        fi
    done
}

# Refuse to start if any benchmark port is already bound (leftover from a
# crashed run or an unrelated local service) instead of killing its owner.
check_ports_available || exit 1

build() {
    if $SKIP_BUILD; then
        echo -e "${YELLOW}Skipping build (--skip-build)${NC}"
        return
    fi
    echo -e "${BLUE}Building ferrum-edge (release)...${NC}"
    (cd "$PROJECT_ROOT" && cargo build --release --bin ferrum-edge 2>&1 | tail -1)
    echo -e "${BLUE}Building mesh-dns-e2e harness binaries...${NC}"
    (cd "$SCRIPT_DIR" && cargo build --release 2>&1 | tail -1)
    echo -e "${GREEN}Build complete${NC}"
}

# Detect gateway version major.minor so the CP stub's ferrum_version matches.
ferrum_version() {
    "$PROJECT_ROOT/target/release/ferrum-edge" version --json 2>/dev/null \
      | sed -nE 's/.*"version":[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' \
      | head -1
}

start_upstream_stub() {
    echo -e "${YELLOW}Starting dns_upstream_stub on UDP+TCP 127.0.0.1:${UPSTREAM_STUB_PORT}...${NC}"
    "$SCRIPT_DIR/target/release/dns_upstream_stub" --listen "127.0.0.1:${UPSTREAM_STUB_PORT}" \
        > "$SCRIPT_DIR/upstream.log" 2>&1 &
    UPSTREAM_PID=$!
    sleep 0.5
}

start_cp_stub() {
    local version
    version=$(ferrum_version)
    if [ -z "$version" ]; then
        echo -e "${RED}Failed to detect ferrum-edge version — falling back to 0.9.0${NC}"
        version="0.9.0"
    fi
    echo -e "${YELLOW}Starting mesh_cp_stub on 127.0.0.1:${CP_STUB_PORT} (ferrum_version=${version})...${NC}"
    "$SCRIPT_DIR/target/release/mesh_cp_stub" \
        --listen "127.0.0.1:${CP_STUB_PORT}" \
        --ferrum-version "$version" \
        --namespace default \
        > "$SCRIPT_DIR/cp_stub.log" 2>&1 &
    CP_STUB_PID=$!
    sleep 0.5
}

start_gateway() {
    echo -e "${YELLOW}Starting ferrum-edge (mesh mode, DNS on ${GATEWAY_DNS_PORT})...${NC}"
    cd "$PROJECT_ROOT"
    env \
        FERRUM_MODE=mesh \
        FERRUM_LOG_LEVEL=warn \
        FERRUM_NAMESPACE=default \
        FERRUM_MESH_CONFIG_PROTOCOL=native \
        FERRUM_DP_CP_GRPC_URLS="http://127.0.0.1:${CP_STUB_PORT}" \
        FERRUM_CP_DP_GRPC_JWT_SECRET="mesh-dns-e2e-secret-32-characters-XXX" \
        FERRUM_MESH_NODE_ID=mesh-perf-node \
        FERRUM_MESH_TOPOLOGY=sidecar \
        FERRUM_MESH_INBOUND_LISTEN_ADDR="127.0.0.1:${INBOUND_PORT}" \
        FERRUM_MESH_OUTBOUND_LISTEN_ADDR="127.0.0.1:${OUTBOUND_PORT}" \
        FERRUM_MESH_HBONE_LISTEN_ADDR="127.0.0.1:${HBONE_PORT}" \
        FERRUM_MESH_EAST_WEST_LISTEN_PORT="${EAST_WEST_PORT}" \
        FERRUM_MESH_EGRESS_LISTEN_ADDR="127.0.0.1:${EGRESS_PORT}" \
        FERRUM_MESH_DNS_PROXY_ENABLED=true \
        FERRUM_MESH_DNS_LISTEN_ADDR="127.0.0.1:${GATEWAY_DNS_PORT}" \
        FERRUM_MESH_DNS_UPSTREAM_ADDR="127.0.0.1:${UPSTREAM_STUB_PORT}" \
        FERRUM_MESH_DNS_TTL_SECONDS=60 \
        FERRUM_MESH_DNS_MAX_CONCURRENT_QUERIES=4096 \
        FERRUM_MESH_DNS_RESPONSE_CACHE_MAX_ENTRIES=4096 \
        FERRUM_MESH_CLUSTER_DOMAIN=cluster.local \
        FERRUM_MESH_ALLOW_NO_CA=true \
        ./target/release/ferrum-edge run \
        > "$SCRIPT_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!

    # Wait for the gateway's DNS listener to be reachable.
    for i in $(seq 1 30); do
        sleep 0.5
        if lsof -ti:"$GATEWAY_DNS_PORT" >/dev/null 2>&1; then
            echo -e "${GREEN}Gateway DNS listener bound on UDP/TCP ${GATEWAY_DNS_PORT}${NC}"
            return
        fi
    done
    echo -e "${RED}Gateway DNS listener never bound${NC}"
    tail -40 "$SCRIPT_DIR/gateway.log"
    exit 1
}

run_loadgen_via_gateway() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}  Via gateway (127.0.0.1:${GATEWAY_DNS_PORT})${NC}"
    echo -e "${CYAN}  ${DURATION}s, concurrency=${CONCURRENCY}, protocol=${PROTOCOL}${NC}"
    echo -e "${CYAN}========================================${NC}\n"
    "$SCRIPT_DIR/target/release/dns_loadgen" \
        --target "127.0.0.1:${GATEWAY_DNS_PORT}" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --protocol "$PROTOCOL" \
        --edns "$EDNS" \
        $JSON_FLAG
}

run_loadgen_baseline() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}  Baseline direct to dns_upstream_stub (127.0.0.1:${UPSTREAM_STUB_PORT})${NC}"
    echo -e "${CYAN}  Mesh-internal classes are skipped (no upstream equivalent)${NC}"
    echo -e "${CYAN}========================================${NC}\n"
    "$SCRIPT_DIR/target/release/dns_loadgen" \
        --target "127.0.0.1:${UPSTREAM_STUB_PORT}" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --protocol "$PROTOCOL" \
        --edns "$EDNS" \
        --skip-mesh \
        $JSON_FLAG
}

# Main
echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  Ferrum Edge Mesh DNS Proxy Perf (E2E)         ${NC}"
echo -e "${BLUE}=================================================${NC}"
echo ""

build
start_upstream_stub
start_cp_stub
start_gateway

run_loadgen_via_gateway
run_loadgen_baseline

echo -e "\n${GREEN}=======================================${NC}"
echo -e "${GREEN}  Run completed successfully${NC}"
echo -e "${GREEN}=======================================${NC}"
