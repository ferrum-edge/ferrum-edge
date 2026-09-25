#!/bin/bash
# Mesh HBONE end-to-end throughput harness for Ferrum Edge.
# Topology:
#   hbone_loadgen ──► hbone_perf_fixture (trusted projection) ──HBONE──► hbone_sidecar ──► hbone_backend
#   hbone_loadgen ──────────────────────────────────────────────────────────────────────► hbone_backend  (baseline)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

DURATION=30
CONCURRENCY=50
PAYLOAD_SIZE=1024
JSON_FLAG=""
SKIP_BUILD=false
SIDECAR_PORT=15008

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)      DURATION="$2"; shift 2 ;;
        --concurrency)   CONCURRENCY="$2"; shift 2 ;;
        --payload-size)  PAYLOAD_SIZE="$2"; shift 2 ;;
        --skip-build)    SKIP_BUILD=true; shift ;;
        --json)          JSON_FLAG="--json"; shift ;;
        --sidecar-port)  SIDECAR_PORT="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

GATEWAY_HTTP_PORT=18000
GATEWAY_ADMIN_PORT=19999
RUNTIME_DIR="$SCRIPT_DIR/runtime"
CERTS_DIR="$RUNTIME_DIR/certs"
BACKEND_PID=""
SIDECAR_PID=""
GATEWAY_PID=""
BACKEND_PORT=""
ARTIFACTS_OWNED=false

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
    for port in "$GATEWAY_HTTP_PORT" "$SIDECAR_PORT" "$GATEWAY_ADMIN_PORT"; do
        check_port_available "$port" || return 1
    done
}

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    archive_failure_diagnostics
    stop_pid "$GATEWAY_PID"
    stop_pid "$SIDECAR_PID"
    stop_pid "$BACKEND_PID"
    if $ARTIFACTS_OWNED; then
        rm -rf "$RUNTIME_DIR"
    fi
    echo -e "${GREEN}Cleanup complete${NC}"
}
trap cleanup EXIT

archive_failure_diagnostics() {
    local dest="${MESH_BASELINE_DIAG_DIR:-}"
    local log
    # Opt-in copy of process logs for hosted artifact upload. Never copy certs
    # or other secret material from $RUNTIME_DIR.
    if [[ -z "$dest" ]]; then
        return 0
    fi
    mkdir -p "$dest"
    for log in backend.log sidecar.log gateway.log; do
        if [[ -f "$RUNTIME_DIR/$log" ]]; then
            cp "$RUNTIME_DIR/$log" "$dest/$log" || true
        fi
    done
}

require_bin() {
    local path="$1"
    local hint="$2"
    if [[ ! -x "$path" ]]; then
        echo -e "${RED}missing executable: $path${NC}"
        echo -e "${RED}${hint}${NC}"
        exit 1
    fi
}

build() {
    if $SKIP_BUILD; then
        echo -e "${YELLOW}Skipping build (--skip-build)${NC}"
        require_bin "$PROJECT_ROOT/target/release/examples/hbone_perf_fixture" "build with: cargo build --release --example hbone_perf_fixture"
        require_bin "$SCRIPT_DIR/target/release/hbone_backend" "build with: (cd tests/performance/mesh-hbone-e2e && cargo build --release)"
        require_bin "$SCRIPT_DIR/target/release/hbone_sidecar" "build with: (cd tests/performance/mesh-hbone-e2e && cargo build --release)"
        require_bin "$SCRIPT_DIR/target/release/hbone_loadgen" "build with: (cd tests/performance/mesh-hbone-e2e && cargo build --release)"
        return
    fi
    echo -e "${BLUE}Building trusted HBONE fixture and harness binaries...${NC}"
    (cd "$PROJECT_ROOT" && cargo build --release --example hbone_perf_fixture 2>&1 | tail -1)
    (cd "$SCRIPT_DIR" && cargo build --release 2>&1 | tail -1)
    require_bin "$PROJECT_ROOT/target/release/examples/hbone_perf_fixture" "cargo build --release --example hbone_perf_fixture did not produce the fixture"
    require_bin "$SCRIPT_DIR/target/release/hbone_loadgen" "harness crate build did not produce hbone_loadgen"
    echo -e "${GREEN}Build complete${NC}"
}

mkdirs() {
    rm -rf "$RUNTIME_DIR"
    mkdir -p "$RUNTIME_DIR" "$CERTS_DIR"
}

generate_certs() {
    echo -e "${YELLOW}Generating mesh-shaped SPIFFE certs in $CERTS_DIR ...${NC}"
    "$SCRIPT_DIR/target/release/hbone_loadgen" \
        generate-certs \
        --out-dir "$CERTS_DIR" \
        --trust-domain cluster.local
    echo -e "${GREEN}Certs ready${NC}"
}

start_backend() {
    echo -e "${YELLOW}Starting plaintext echo backend...${NC}"
    "$SCRIPT_DIR/target/release/hbone_backend" --listen 127.0.0.1:0 \
        > "$RUNTIME_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    for i in $(seq 1 20); do
        BACKEND_PORT=$(grep -oE 'listening on 127\.0\.0\.1:[0-9]+' "$RUNTIME_DIR/backend.log" 2>/dev/null \
            | head -1 | grep -oE '[0-9]+$' || true)
        [ -n "$BACKEND_PORT" ] && break
        sleep 0.1
    done
    if [ -z "$BACKEND_PORT" ]; then
        echo -e "${RED}backend failed to report its port${NC}"
        cat "$RUNTIME_DIR/backend.log" | tail -20
        exit 1
    fi
    echo -e "${GREEN}Backend ready on 127.0.0.1:$BACKEND_PORT (PID $BACKEND_PID)${NC}"
}

start_sidecar() {
    echo -e "${YELLOW}Starting stub HBONE sidecar on 127.0.0.1:$SIDECAR_PORT ...${NC}"
    "$SCRIPT_DIR/target/release/hbone_sidecar" \
        --listen "127.0.0.1:$SIDECAR_PORT" \
        --cert "$CERTS_DIR/sidecar-cert.pem" \
        --key "$CERTS_DIR/sidecar-key.pem" \
        --ca "$CERTS_DIR/ca.pem" \
        --backend-host 127.0.0.1 \
        --backend-port "$BACKEND_PORT" \
        > "$RUNTIME_DIR/sidecar.log" 2>&1 &
    SIDECAR_PID=$!
    for i in $(seq 1 40); do
        (echo > /dev/tcp/127.0.0.1/"$SIDECAR_PORT") 2>/dev/null && {
            echo -e "${GREEN}Sidecar ready (PID $SIDECAR_PID)${NC}"; return
        }
        sleep 0.1
    done
    echo -e "${RED}Sidecar failed to bind 127.0.0.1:$SIDECAR_PORT${NC}"
    tail -30 "$RUNTIME_DIR/sidecar.log"
    exit 1
}

start_gateway() {
    echo -e "${YELLOW}Starting trusted-projection HBONE fixture...${NC}"

    env \
        FERRUM_BACKEND_ALLOW_IPS=private \
        "$PROJECT_ROOT/target/release/examples/hbone_perf_fixture" \
            --proxy-http-port "$GATEWAY_HTTP_PORT" \
            --admin-http-port "$GATEWAY_ADMIN_PORT" \
            --sidecar-host 127.0.0.1 \
            --sidecar-port "$SIDECAR_PORT" \
            --svid-cert "$CERTS_DIR/gateway-cert.pem" \
            --svid-key "$CERTS_DIR/gateway-key.pem" \
            --trust-bundle "$CERTS_DIR/ca.pem" \
            --spiffe-id "spiffe://cluster.local/ns/edge/sa/gateway" \
        > "$RUNTIME_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!

    for i in $(seq 1 40); do
        if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
            echo -e "${RED}Gateway fixture exited before becoming ready${NC}"
            tail -40 "$RUNTIME_DIR/gateway.log"
            exit 1
        fi
        if curl -sf "http://127.0.0.1:$GATEWAY_ADMIN_PORT/health" > /dev/null 2>&1; then
            echo -e "${GREEN}Gateway ready (PID $GATEWAY_PID)${NC}"
            return
        fi
        sleep 0.25
    done
    echo -e "${RED}Gateway failed to start${NC}"
    tail -40 "$RUNTIME_DIR/gateway.log"
    exit 1
}

run_phase() {
    local label="$1"
    local target="$2"

    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${CYAN}  $label${NC}"
    echo -e "${CYAN}  Target: $target${NC}"
    echo -e "${CYAN}  Duration ${DURATION}s · Concurrency $CONCURRENCY · Payload ${PAYLOAD_SIZE}B${NC}"
    echo -e "${CYAN}========================================${NC}"

    "$SCRIPT_DIR/target/release/hbone_loadgen" \
        run \
        --target "$target" \
        --host-header "edge.local" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --payload-size "$PAYLOAD_SIZE" \
        $JSON_FLAG
}

# Main
echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  Ferrum Edge HBONE E2E Throughput Harness      ${NC}"
echo -e "${BLUE}=================================================${NC}"

check_ports_available || exit 1
mkdirs
ARTIFACTS_OWNED=true
build
generate_certs
start_backend
start_sidecar
start_gateway

# Phase 1: Gateway + HBONE tunnel
run_phase "Gateway → HBONE → Backend" "http://127.0.0.1:$GATEWAY_HTTP_PORT/echo"

# Phase 2: Direct baseline (no gateway, no sidecar, no tunnel)
run_phase "Direct baseline" "http://127.0.0.1:$BACKEND_PORT/echo"

echo -e "\n${GREEN}=============================================${NC}"
echo -e "${GREEN}  Run complete. Logs under $RUNTIME_DIR/.${NC}"
echo -e "${GREEN}=============================================${NC}"
