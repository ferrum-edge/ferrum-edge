#!/bin/bash
# Multi-protocol performance test runner for Ferrum Gateway
# Usage: ./run_protocol_test.sh <protocol> [options]
#   Protocols: http1, http1-tls, http2, http3, ws, grpc, tcp, tcp-tls, udp, udp-dtls, all
#   Options:
#     --duration <secs>    Test duration (default: 30)
#     --concurrency <n>    Concurrent connections (default: 100)
#     --payload-size <n>   Payload bytes for echo tests (default: 64)
#     --json               Output JSON results
#     --skip-build         Skip build entirely (use existing binaries)

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
PROTOCOL="${1:-all}"
shift 2>/dev/null || true
DURATION=30
CONCURRENCY=100
PAYLOAD_SIZE=64
JSON_FLAG=""
SKIP_BUILD=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration) DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --payload-size) PAYLOAD_SIZE="$2"; shift 2 ;;
        --json) JSON_FLAG="--json"; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        *) shift ;;
    esac
done

# Ports
GATEWAY_HTTP_PORT=8000
GATEWAY_HTTPS_PORT=8443

# Track PIDs for cleanup
BACKEND_PID=""
GATEWAY_PID=""

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null || true
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    # Kill processes on known ports
    for port in 3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 50052 \
                $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 5000 5001 5003 5004; do
        lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    rm -rf "$SCRIPT_DIR/certs" 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete${NC}"
}
trap cleanup EXIT

# Check if a binary is up-to-date (newer than all Rust source files in its crate)
binary_is_fresh() {
    local binary="$1"
    local src_dir="$2"
    [ -f "$binary" ] || return 1
    # If any .rs or .toml file is newer than the binary, it's stale
    local newer
    newer=$(find "$src_dir" \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) -newer "$binary" -print -quit 2>/dev/null)
    [ -z "$newer" ]
}

# Build
build() {
    if $SKIP_BUILD; then
        echo -e "${YELLOW}Skipping build (--skip-build)${NC}"
        return
    fi

    local gateway_bin="$PROJECT_ROOT/target/release/ferrum-gateway"
    local bench_bin="$SCRIPT_DIR/target/release/proto_bench"

    local need_gateway=true
    local need_bench=true

    if binary_is_fresh "$gateway_bin" "$PROJECT_ROOT/src"; then
        need_gateway=false
    fi
    if binary_is_fresh "$bench_bin" "$SCRIPT_DIR/src"; then
        need_bench=false
    fi

    if ! $need_gateway && ! $need_bench; then
        echo -e "${GREEN}Binaries up-to-date, skipping build${NC}"
        return
    fi

    echo -e "${BLUE}Building multi-protocol test suite...${NC}"
    if $need_gateway; then
        cd "$PROJECT_ROOT"
        cargo build --release --bin ferrum-gateway 2>&1 | tail -1
    else
        echo -e "  ${GREEN}ferrum-gateway binary is fresh${NC}"
    fi
    if $need_bench; then
        cd "$SCRIPT_DIR"
        cargo build --release 2>&1 | tail -1
    else
        echo -e "  ${GREEN}proto_bench/proto_backend binaries are fresh${NC}"
    fi
    echo -e "${GREEN}Build complete${NC}"
}

# Start multi-protocol backend
start_backend() {
    echo -e "${YELLOW}Starting multi-protocol backend...${NC}"
    cd "$SCRIPT_DIR"
    ./target/release/proto_backend > "$SCRIPT_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!

    # Wait for backend health (check HTTP/1.1 health port)
    for i in $(seq 1 10); do
        if curl -sf http://127.0.0.1:3010/health > /dev/null 2>&1; then
            echo -e "${GREEN}Backend started (PID: $BACKEND_PID)${NC}"
            return
        fi
        sleep 1
    done
    echo -e "${RED}Backend failed to start${NC}"
    cat "$SCRIPT_DIR/backend.log" | tail -20
    exit 1
}

# Start gateway with config
start_gateway() {
    local config_file="$1"
    local extra_env="$2"
    echo -e "${YELLOW}Starting gateway [$(basename "$config_file")]...${NC}"

    # Wait for certs from backend
    local cert_dir="$SCRIPT_DIR/certs"
    for i in $(seq 1 5); do
        [ -f "$cert_dir/cert.pem" ] && break
        sleep 1
    done

    cd "$PROJECT_ROOT"
    local env_cmd=(
        env
        FERRUM_MODE=file
        "FERRUM_FILE_CONFIG_PATH=$config_file"
        "FERRUM_PROXY_HTTP_PORT=$GATEWAY_HTTP_PORT"
        "FERRUM_PROXY_HTTPS_PORT=$GATEWAY_HTTPS_PORT"
        FERRUM_POOL_MAX_IDLE_PER_HOST=200
        FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120
        FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true
        FERRUM_TLS_NO_VERIFY=true
        # HTTP/2 flow control tuning (8 MiB stream, 32 MiB connection, fixed windows)
        FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608
        FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432
        FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=false
        FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=65535
        FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000
        # HTTP/3 QUIC transport tuning (8 MiB stream, 32 MiB connection, 8 MiB send)
        FERRUM_HTTP3_MAX_STREAMS=1000
        FERRUM_HTTP3_STREAM_RECEIVE_WINDOW=8388608
        FERRUM_HTTP3_RECEIVE_WINDOW=33554432
        FERRUM_HTTP3_SEND_WINDOW=8388608
    )
    if [ -f "$cert_dir/cert.pem" ]; then
        env_cmd+=(
            "FERRUM_PROXY_TLS_CERT_PATH=$cert_dir/cert.pem"
            "FERRUM_PROXY_TLS_KEY_PATH=$cert_dir/key.pem"
            "FERRUM_DTLS_CERT_PATH=$cert_dir/cert.pem"
            "FERRUM_DTLS_KEY_PATH=$cert_dir/key.pem"
        )
    fi
    # Append extra env vars (space separated KEY=VALUE pairs)
    if [ -n "$extra_env" ]; then
        for kv in $extra_env; do
            env_cmd+=("$kv")
        done
    fi

    "${env_cmd[@]}" ./target/release/ferrum-gateway > "$SCRIPT_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!

    for i in $(seq 1 10); do
        if curl -sf "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" > /dev/null 2>&1; then
            echo -e "${GREEN}Gateway started (PID: $GATEWAY_PID)${NC}"
            return
        fi
        sleep 1
    done
    echo -e "${RED}Gateway failed to start${NC}"
    tail -20 "$SCRIPT_DIR/gateway.log"
    exit 1
}

stop_gateway() {
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null || true
    GATEWAY_PID=""
    for port in $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 5010 5001 5003 5004; do
        lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    sleep 1
}

# Run bench
run_bench() {
    local label="$1"
    local proto="$2"
    local target="$3"
    shift 3
    local extra_args="$@"

    echo -e "\n${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $label${NC}"
    echo -e "${CYAN}  Target: $target${NC}"
    echo -e "${CYAN}  Duration: ${DURATION}s  Concurrency: $CONCURRENCY${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}\n"

    "$SCRIPT_DIR/target/release/proto_bench" "$proto" \
        --target "$target" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --payload-size "$PAYLOAD_SIZE" \
        $extra_args $JSON_FLAG

    echo ""
}

# ── Protocol test functions ───────────────────────────────────────────────────

test_http1() {
    start_gateway "$SCRIPT_DIR/configs/http1_perf.yaml"
    sleep 1
    run_bench "HTTP/1.1 (via gateway)" http1 "http://127.0.0.1:$GATEWAY_HTTP_PORT/api/users"
    run_bench "HTTP/1.1 (direct backend)" http1 "http://127.0.0.1:3001/api/users"
}

test_http1_tls() {
    start_gateway "$SCRIPT_DIR/configs/http1_tls_perf.yaml"
    sleep 1
    run_bench "HTTP/1.1+TLS (via gateway)" http1 "https://127.0.0.1:$GATEWAY_HTTPS_PORT/api/users"
    run_bench "HTTP/1.1+TLS (direct backend - no TLS)" http1 "http://127.0.0.1:3001/api/users"
}

test_http2() {
    start_gateway "$SCRIPT_DIR/configs/http2_perf.yaml" "FERRUM_POOL_ENABLE_HTTP2=true"
    sleep 1
    run_bench "HTTP/2 (via gateway)" http2 "https://127.0.0.1:$GATEWAY_HTTPS_PORT/api/users"
    run_bench "HTTP/2 (direct backend)" http2 "https://127.0.0.1:3443/api/users"
}

test_http3() {
    start_gateway "$SCRIPT_DIR/configs/http3_perf.yaml" "FERRUM_ENABLE_HTTP3=true"
    sleep 1
    run_bench "HTTP/3 (via gateway)" http3 "https://127.0.0.1:$GATEWAY_HTTPS_PORT/api/users"
    run_bench "HTTP/3 (direct backend)" http3 "https://127.0.0.1:3445/api/users"
}

test_ws() {
    start_gateway "$SCRIPT_DIR/configs/ws_perf.yaml"
    sleep 1
    run_bench "WebSocket (via gateway)" ws "ws://127.0.0.1:$GATEWAY_HTTP_PORT/ws"
    run_bench "WebSocket (direct backend)" ws "ws://127.0.0.1:3003"
}

test_grpc() {
    start_gateway "$SCRIPT_DIR/configs/grpc_perf.yaml"
    sleep 1
    run_bench "gRPC (via gateway)" grpc "http://127.0.0.1:$GATEWAY_HTTP_PORT"
    run_bench "gRPC (direct backend)" grpc "http://127.0.0.1:50052"
}

test_tcp() {
    start_gateway "$SCRIPT_DIR/configs/tcp_perf.yaml"
    sleep 1
    run_bench "TCP (via gateway)" tcp "127.0.0.1:5010"
    run_bench "TCP (direct backend)" tcp "127.0.0.1:3004"
}

test_tcp_tls() {
    start_gateway "$SCRIPT_DIR/configs/tcp_tls_perf.yaml"
    sleep 1
    run_bench "TCP+TLS (via gateway)" tcp "127.0.0.1:5001" --tls
    run_bench "TCP+TLS (direct backend)" tcp "127.0.0.1:3444" --tls
}

test_udp() {
    start_gateway "$SCRIPT_DIR/configs/udp_perf.yaml"
    sleep 1
    run_bench "UDP (via gateway)" udp "127.0.0.1:5003"
    run_bench "UDP (direct backend)" udp "127.0.0.1:3005"
}

test_udp_dtls() {
    start_gateway "$SCRIPT_DIR/configs/udp_dtls_perf.yaml"
    sleep 1
    run_bench "UDP+DTLS (via gateway)" udp "127.0.0.1:5004" --tls
    run_bench "UDP+DTLS (direct backend)" udp "127.0.0.1:3006" --tls
}

# Kill stale processes from prior crashed runs before starting.
# Without this, leftover listeners on test ports cause "Connection refused"
# or "Address already in use" failures when the backend/gateway try to bind.
kill_stale_processes() {
    local stale=false
    for port in 3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 50052 \
                $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 5000 5001 5003 5004 5010; do
        if lsof -ti:"$port" > /dev/null 2>&1; then
            stale=true
            break
        fi
    done
    if $stale; then
        echo -e "${YELLOW}Killing stale processes from prior run...${NC}"
        for port in 3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 50052 \
                    $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 5000 5001 5003 5004 5010; do
            lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
        done
        sleep 1
        echo -e "${GREEN}Stale processes cleaned${NC}"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Ferrum Gateway Multi-Protocol Perf Test ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo ""

kill_stale_processes
build
start_backend

case "$PROTOCOL" in
    http1)     test_http1 ;;
    http1-tls) test_http1_tls ;;
    http2)     test_http2 ;;
    http3)     test_http3 ;;
    ws)        test_ws ;;
    grpc)      test_grpc ;;
    tcp)       test_tcp ;;
    tcp-tls)   test_tcp_tls ;;
    udp)       test_udp ;;
    udp-dtls)  test_udp_dtls ;;
    all)
        test_http1;   stop_gateway
        test_http1_tls; stop_gateway
        test_http2;   stop_gateway
        test_http3;   stop_gateway
        test_ws;      stop_gateway
        test_grpc;    stop_gateway
        test_tcp;     stop_gateway
        test_tcp_tls; stop_gateway
        test_udp;     stop_gateway
        test_udp_dtls
        ;;
    *)
        echo -e "${RED}Unknown protocol: $PROTOCOL${NC}"
        echo "Usage: $0 <http1|http1-tls|http2|http3|ws|grpc|tcp|tcp-tls|udp|udp-dtls|all> [options]"
        exit 1
        ;;
esac

echo -e "\n${GREEN}═══════════════════════════════════════${NC}"
echo -e "${GREEN}  All tests completed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════${NC}"
