#!/bin/bash
# Multi-protocol performance test runner for Ferrum Edge
# Usage: ./run_protocol_test.sh <protocol> [options]
#   Protocols: http1, http1-tls, http2, http3, ws, grpc, tcp, tcp-tls, udp, udp-dtls, all
#   Options:
#     --duration <secs>    Test duration (default: 30)
#     --concurrency <n>    Concurrent connections (default: 100)
#     --payload-size <n>   Payload bytes for echo tests (default: 64)
#     --json               Output JSON results
#     --skip-build         Skip build entirely (use existing binaries)
#     --envoy              Compare Ferrum Edge against Envoy (requires envoy in PATH)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Defaults
PROTOCOL="${1:-all}"
shift 2>/dev/null || true
DURATION=30
CONCURRENCY=100
PAYLOAD_SIZE=64
JSON_FLAG=""
SKIP_BUILD=false
ENVOY_MODE=false

# Parse options
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration) DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --payload-size) PAYLOAD_SIZE="$2"; shift 2 ;;
        --json) JSON_FLAG="--json"; shift ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --envoy) ENVOY_MODE=true; shift ;;
        *) shift ;;
    esac
done

# Ports
GATEWAY_HTTP_PORT=8000
GATEWAY_HTTPS_PORT=8443
ENVOY_ADMIN_PORT=15000

# Track PIDs for cleanup
BACKEND_PID=""
GATEWAY_PID=""
ENVOY_PID=""
RESULTS_DIR=""

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null || true
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    [ -n "$ENVOY_PID" ] && kill "$ENVOY_PID" 2>/dev/null || true
    # Kill processes on known ports
    for port in 3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 50052 \
                $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 5000 5001 5003 5004 5010 $ENVOY_ADMIN_PORT; do
        lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    rm -rf "$SCRIPT_DIR/certs" 2>/dev/null || true
    [ -n "$RESULTS_DIR" ] && rm -rf "$RESULTS_DIR" 2>/dev/null || true
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

    local gateway_bin="$PROJECT_ROOT/target/release/ferrum-edge"
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
        cargo build --release --bin ferrum-edge 2>&1 | tail -1
    else
        echo -e "  ${GREEN}ferrum-edge binary is fresh${NC}"
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
        # Minimize non-proxy overhead
        FERRUM_LOG_LEVEL=error
        FERRUM_ADD_VIA_HEADER=false
        # Connection pool tuning
        FERRUM_POOL_MAX_IDLE_PER_HOST=200
        FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120
        FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true
        FERRUM_POOL_CLEANUP_INTERVAL_SECONDS=30
        FERRUM_POOL_WARMUP_ENABLED=true
        FERRUM_TLS_NO_VERIFY=true
        # HTTP/2 flow control tuning (8 MiB stream, 32 MiB connection, adaptive BDP)
        FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608
        FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432
        FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true
        FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=1048576
        FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000
        # Server-side HTTP/2 tuning
        FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000
        # gRPC pool tuning (documented 3.8% throughput improvement)
        FERRUM_GRPC_POOL_READY_WAIT_MS=1
        # HTTP/3 QUIC transport tuning (8 MiB stream, 32 MiB connection, 8 MiB send)
        FERRUM_HTTP3_MAX_STREAMS=1000
        FERRUM_HTTP3_STREAM_RECEIVE_WINDOW=8388608
        FERRUM_HTTP3_RECEIVE_WINDOW=33554432
        FERRUM_HTTP3_SEND_WINDOW=8388608
        FERRUM_HTTP3_CONNECTIONS_PER_BACKEND=4
        FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS=120
        # UDP tuning
        FERRUM_UDP_MAX_SESSIONS=10000
        FERRUM_UDP_CLEANUP_INTERVAL_SECONDS=10
    )
    if [ -f "$cert_dir/cert.pem" ]; then
        env_cmd+=(
            "FERRUM_FRONTEND_TLS_CERT_PATH=$cert_dir/cert.pem"
            "FERRUM_FRONTEND_TLS_KEY_PATH=$cert_dir/key.pem"
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

    "${env_cmd[@]}" ./target/release/ferrum-edge > "$SCRIPT_DIR/gateway.log" 2>&1 &
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

# ── Envoy lifecycle ──────────────────────────────────────────────────────────

check_envoy() {
    if ! command -v envoy &> /dev/null; then
        echo -e "${RED}Error: envoy not found in PATH${NC}"
        echo -e "Install Envoy:"
        echo -e "  macOS:  brew install envoy"
        echo -e "  Linux:  see https://www.envoyproxy.io/docs/envoy/latest/start/install"
        exit 1
    fi
    local version
    version=$(envoy --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo -e "${GREEN}Found Envoy: v${version}${NC}"
}

# Prepare envoy config with real cert paths (sed CERT_PATH/KEY_PATH placeholders)
prepare_envoy_config() {
    local src_config="$1"
    local cert_dir="$SCRIPT_DIR/certs"
    local runtime_config="$RESULTS_DIR/envoy_runtime_$(basename "$src_config")"

    sed -e "s|CERT_PATH|${cert_dir}/cert.pem|g" \
        -e "s|KEY_PATH|${cert_dir}/key.pem|g" \
        "$src_config" > "$runtime_config"

    echo "$runtime_config"
}

start_envoy() {
    local config_file="$1"
    echo -e "  ${YELLOW}Starting Envoy [$(basename "$config_file")]...${NC}"

    # Prepare config with real cert paths
    local runtime_config
    runtime_config=$(prepare_envoy_config "$config_file")

    # Use all available CPU cores (matches ferrum-edge tokio default)
    local num_cpus
    num_cpus=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

    cd "$SCRIPT_DIR"
    envoy -c "$runtime_config" --concurrency "$num_cpus" -l error --disable-hot-restart \
        > "$SCRIPT_DIR/envoy.log" 2>&1 &
    ENVOY_PID=$!

    # Wait for Envoy admin to be ready
    for i in $(seq 1 15); do
        if curl -sf "http://127.0.0.1:$ENVOY_ADMIN_PORT/ready" > /dev/null 2>&1; then
            echo -e "  ${GREEN}Envoy started (PID: $ENVOY_PID)${NC}"
            return
        fi
        sleep 1
    done
    echo -e "  ${RED}Envoy failed to start${NC}"
    tail -30 "$SCRIPT_DIR/envoy.log"
    exit 1
}

stop_envoy() {
    [ -n "$ENVOY_PID" ] && kill "$ENVOY_PID" 2>/dev/null || true
    ENVOY_PID=""
    for port in $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 5010 5001 5003 $ENVOY_ADMIN_PORT; do
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

# Run bench and capture JSON result to a file (used in --envoy mode)
run_bench_capture() {
    local result_file="$1"
    local label="$2"
    local proto="$3"
    local target="$4"
    shift 4
    local extra_args="$@"

    echo -e "    ${CYAN}$label (${DURATION}s, ${CONCURRENCY}c)${NC}"

    "$SCRIPT_DIR/target/release/proto_bench" "$proto" \
        --target "$target" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --payload-size "$PAYLOAD_SIZE" \
        $extra_args --json > "$RESULTS_DIR/$result_file" 2>/dev/null

    # Show a quick summary inline
    local rps errors
    rps=$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/$result_file')); print(f\"{d['rps']:,.0f}\")" 2>/dev/null || echo "?")
    errors=$(python3 -c "import json; d=json.load(open('$RESULTS_DIR/$result_file')); print(d['total_errors'])" 2>/dev/null || echo "?")
    echo -e "      RPS: ${GREEN}${rps}${NC}  Errors: ${errors}"
}

# ── Protocol test functions (standard mode) ──────────────────────────────────

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

# ── Envoy comparison mode ────────────────────────────────────────────────────

# Protocols supported by both Ferrum Edge and Envoy
ENVOY_SUPPORTED="http1 http1-tls ws grpc tcp tcp-tls udp"
# Protocols only Ferrum Edge supports or where the bench client is incompatible
# http2: hyper's raw h2 client gets ConnectionReset from Envoy (known h2c compat issue);
#         gRPC already covers HTTP/2 semantics via tonic which works fine with Envoy
ENVOY_UNSUPPORTED="http2 http3 udp-dtls"

envoy_compare_protocol() {
    local p="$1"
    local bench_proto bench_target direct_target bench_extra=""
    local ferrum_config ferrum_extra="" envoy_config

    case "$p" in
        http1)
            bench_proto=http1
            bench_target="http://127.0.0.1:$GATEWAY_HTTP_PORT/api/users"
            direct_target="http://127.0.0.1:3001/api/users"
            ferrum_config="$SCRIPT_DIR/configs/http1_perf.yaml"
            envoy_config="$SCRIPT_DIR/configs/envoy/http1.yaml"
            ;;
        http1-tls)
            bench_proto=http1
            bench_target="https://127.0.0.1:$GATEWAY_HTTPS_PORT/api/users"
            direct_target="http://127.0.0.1:3001/api/users"
            ferrum_config="$SCRIPT_DIR/configs/http1_tls_perf.yaml"
            envoy_config="$SCRIPT_DIR/configs/envoy/http1_tls.yaml"
            ;;
        ws)
            bench_proto=ws
            bench_target="ws://127.0.0.1:$GATEWAY_HTTP_PORT/ws"
            direct_target="ws://127.0.0.1:3003"
            ferrum_config="$SCRIPT_DIR/configs/ws_perf.yaml"
            envoy_config="$SCRIPT_DIR/configs/envoy/ws.yaml"
            ;;
        grpc)
            bench_proto=grpc
            bench_target="http://127.0.0.1:$GATEWAY_HTTP_PORT"
            direct_target="http://127.0.0.1:50052"
            ferrum_config="$SCRIPT_DIR/configs/grpc_perf.yaml"
            envoy_config="$SCRIPT_DIR/configs/envoy/grpc.yaml"
            ;;
        tcp)
            bench_proto=tcp
            bench_target="127.0.0.1:5010"
            direct_target="127.0.0.1:3004"
            ferrum_config="$SCRIPT_DIR/configs/tcp_perf.yaml"
            envoy_config="$SCRIPT_DIR/configs/envoy/tcp.yaml"
            ;;
        tcp-tls)
            bench_proto=tcp
            bench_target="127.0.0.1:5001"
            direct_target="127.0.0.1:3444"
            ferrum_config="$SCRIPT_DIR/configs/tcp_tls_perf.yaml"
            envoy_config="$SCRIPT_DIR/configs/envoy/tcp_tls.yaml"
            bench_extra="--tls"
            ;;
        udp)
            bench_proto=udp
            bench_target="127.0.0.1:5003"
            direct_target="127.0.0.1:3005"
            ferrum_config="$SCRIPT_DIR/configs/udp_perf.yaml"
            envoy_config="$SCRIPT_DIR/configs/envoy/udp.yaml"
            ;;
        *)
            echo -e "  ${RED}Unknown protocol for envoy comparison: $p${NC}"
            return 1
            ;;
    esac

    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  ${BOLD}$p${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # Ferrum Edge
    echo -e "\n  ${MAGENTA}▸ Ferrum Edge${NC}"
    start_gateway "$ferrum_config" "$ferrum_extra"
    sleep 1
    run_bench_capture "ferrum_${p}.json" "Ferrum → $bench_target" "$bench_proto" "$bench_target" $bench_extra
    stop_gateway

    # Envoy
    echo -e "  ${MAGENTA}▸ Envoy${NC}"
    start_envoy "$envoy_config"
    sleep 1
    run_bench_capture "envoy_${p}.json" "Envoy  → $bench_target" "$bench_proto" "$bench_target" $bench_extra
    stop_envoy

    # Direct backend baseline
    echo -e "  ${MAGENTA}▸ Direct backend${NC}"
    run_bench_capture "direct_${p}.json" "Direct → $direct_target" "$bench_proto" "$direct_target" $bench_extra
}

print_comparison_table() {
    local protocols=("$@")

    python3 - "$RESULTS_DIR" "${protocols[@]}" <<'PYEOF'
import json, sys, os

results_dir = sys.argv[1]
protocols = sys.argv[2:]

def load(prefix, proto):
    path = os.path.join(results_dir, f"{prefix}_{proto}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def fmt_rps(v):
    if v is None: return "N/A"
    return f"{v:,.0f}"

def fmt_us(us):
    if us is None: return "N/A"
    if us >= 1_000_000: return f"{us/1_000_000:.2f}s"
    if us >= 1000: return f"{us/1000:.2f}ms"
    return f"{us}\u03bcs"

def fmt_pct(v):
    if v is None: return "N/A"
    sign = "+" if v > 0 else ""
    return f"{sign}{v:.1f}%"

# ── Through Gateway ──

first = None
for p in protocols:
    first = load("ferrum", p) or load("envoy", p)
    if first: break

print()
print("\033[1m" + "=" * 105 + "\033[0m")
print("\033[1m  Ferrum Edge vs Envoy \u2014 Through-Gateway Comparison\033[0m")
if first:
    print(f"  Duration: {first.get('duration_secs','')}s | Concurrency: {first.get('concurrency','')} | Payload: 64 bytes")
print("\033[1m" + "=" * 105 + "\033[0m")
print()

hdr = f"| {'Protocol':<14} | {'Ferrum RPS':>12} | {'Envoy RPS':>12} | {'\u0394 RPS':>8} | {'Winner':>7} | {'Ferrum P50':>11} | {'Envoy P50':>11} | {'Ferrum P99':>11} | {'Envoy P99':>11} | {'Ferrum Avg':>11} | {'Envoy Avg':>11} |"
sep = f"|{'-'*16}|{'-'*14}|{'-'*14}|{'-'*10}|{'-'*9}|{'-'*13}|{'-'*13}|{'-'*13}|{'-'*13}|{'-'*13}|{'-'*13}|"

print(hdr)
print(sep)

for p in protocols:
    f = load("ferrum", p)
    e = load("envoy", p)
    if not f or not e:
        continue

    f_rps = f["rps"]
    e_rps = e["rps"]
    delta = ((f_rps - e_rps) / e_rps * 100) if e_rps > 0 else 0
    if abs(delta) < 2:
        winner = "~tie"
    elif f_rps > e_rps:
        winner = "\033[32mFerrum\033[0m"
        winner_plain = "Ferrum"
    else:
        winner = "\033[33mEnvoy\033[0m"
        winner_plain = "Envoy"

    # Determine winner string width for alignment
    if abs(delta) < 2:
        w = winner
        w_pad = 7 - len("~tie")
    elif f_rps > e_rps:
        w = winner
        w_pad = 7 - len("Ferrum")
    else:
        w = winner
        w_pad = 7 - len("Envoy")

    print(f"| {p:<14} | {fmt_rps(f_rps):>12} | {fmt_rps(e_rps):>12} | {fmt_pct(delta):>8} | {w}{' '*w_pad} | {fmt_us(f.get('p50_us')):>11} | {fmt_us(e.get('p50_us')):>11} | {fmt_us(f.get('p99_us')):>11} | {fmt_us(e.get('p99_us')):>11} | {fmt_us(f.get('latency_avg_us')):>11} | {fmt_us(e.get('latency_avg_us')):>11} |")

# ── Direct Backend ──

print()
print("\033[1m" + "=" * 70 + "\033[0m")
print("\033[1m  Direct Backend (baseline \u2014 no gateway overhead)\033[0m")
print("\033[1m" + "=" * 70 + "\033[0m")
print()

hdr2 = f"| {'Protocol':<14} | {'RPS':>12} | {'Avg Latency':>12} | {'P50':>9} | {'P99':>9} | {'Max':>9} |"
sep2 = f"|{'-'*16}|{'-'*14}|{'-'*14}|{'-'*11}|{'-'*11}|{'-'*11}|"

print(hdr2)
print(sep2)

for p in protocols:
    d = load("direct", p)
    if not d:
        continue
    print(f"| {p:<14} | {fmt_rps(d['rps']):>12} | {fmt_us(d.get('latency_avg_us')):>12} | {fmt_us(d.get('p50_us')):>9} | {fmt_us(d.get('p99_us')):>9} | {fmt_us(d.get('latency_max_us')):>9} |")

# ── Gateway Overhead ──

print()
print("\033[1m" + "=" * 70 + "\033[0m")
print("\033[1m  Gateway Overhead vs Direct Backend\033[0m")
print("\033[1m" + "=" * 70 + "\033[0m")
print()

hdr3 = f"| {'Protocol':<14} | {'Direct RPS':>12} | {'Ferrum RPS':>12} | {'Ferrum OH':>10} | {'Envoy RPS':>12} | {'Envoy OH':>10} |"
sep3 = f"|{'-'*16}|{'-'*14}|{'-'*14}|{'-'*12}|{'-'*14}|{'-'*12}|"

print(hdr3)
print(sep3)

for p in protocols:
    f = load("ferrum", p)
    e = load("envoy", p)
    d = load("direct", p)
    if not f or not e or not d:
        continue

    d_rps = d["rps"]
    f_oh = ((d_rps - f["rps"]) / d_rps * 100) if d_rps > 0 else 0
    e_oh = ((d_rps - e["rps"]) / d_rps * 100) if d_rps > 0 else 0

    print(f"| {p:<14} | {fmt_rps(d_rps):>12} | {fmt_rps(f['rps']):>12} | {'~'+str(int(f_oh))+'%':>10} | {fmt_rps(e['rps']):>12} | {'~'+str(int(e_oh))+'%':>10} |")

print()
PYEOF
}

run_envoy_comparison() {
    local -a protos

    case "$PROTOCOL" in
        all)
            protos=(http1 http1-tls ws grpc tcp tcp-tls udp)
            echo -e "${YELLOW}Note: HTTP/2, HTTP/3, and UDP+DTLS are skipped for Envoy comparison${NC}"
            echo -e "${YELLOW}  HTTP/2: hyper h2c client incompatible with Envoy on macOS (gRPC covers HTTP/2 semantics)${NC}"
            echo -e "${YELLOW}  HTTP/3, UDP+DTLS: no standard Envoy equivalent${NC}"
            ;;
        http2|http3|udp-dtls)
            echo -e "${RED}$PROTOCOL is not supported by standard Envoy — cannot compare${NC}"
            echo -e "Envoy-supported protocols: ${ENVOY_SUPPORTED}"
            exit 1
            ;;
        *)
            # Check if protocol is envoy-supported
            if echo "$ENVOY_SUPPORTED" | grep -qw "$PROTOCOL"; then
                protos=("$PROTOCOL")
            else
                echo -e "${RED}Unknown protocol: $PROTOCOL${NC}"
                exit 1
            fi
            ;;
    esac

    RESULTS_DIR=$(mktemp -d)

    for p in "${protos[@]}"; do
        envoy_compare_protocol "$p"
    done

    echo -e "\n\n"
    print_comparison_table "${protos[@]}"
}

# Kill stale processes from prior crashed runs before starting.
# Without this, leftover listeners on test ports cause "Connection refused"
# or "Address already in use" failures when the backend/gateway try to bind.
kill_stale_processes() {
    local stale=false
    for port in 3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 50052 \
                $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 5000 5001 5003 5004 5010 $ENVOY_ADMIN_PORT; do
        if lsof -ti:"$port" > /dev/null 2>&1; then
            stale=true
            break
        fi
    done
    if $stale; then
        echo -e "${YELLOW}Killing stale processes from prior run...${NC}"
        for port in 3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 50052 \
                    $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 5000 5001 5003 5004 5010 $ENVOY_ADMIN_PORT; do
            lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
        done
        sleep 1
        echo -e "${GREEN}Stale processes cleaned${NC}"
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────

if $ENVOY_MODE; then
    echo -e "${BLUE}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  Ferrum Edge vs Envoy — Perf Comparison    ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════╝${NC}"
    echo ""

    check_envoy
    kill_stale_processes
    build
    start_backend

    run_envoy_comparison

    echo -e "\n${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}  Comparison completed successfully!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════${NC}"
else
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  Ferrum Edge Multi-Protocol Perf Test ║${NC}"
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
fi
