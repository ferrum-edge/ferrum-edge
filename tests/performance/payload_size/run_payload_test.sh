#!/usr/bin/env bash
#
# Payload Size Performance Test Runner
#
# Tests gateway performance across content types, protocols, and payload sizes.
# Measures throughput (RPS), latency (P50/P99), and data transfer rates.
# Optionally compares Ferrum Edge against Envoy side-by-side.
#
# Usage:
#   bash run_payload_test.sh <CONTENT_TYPE|TIER|PROTOCOL|all> [OPTIONS]
#
# Content types:
#   json, xml, form-urlencoded, multipart, octet-stream, grpc,
#   sse, ndjson, soap-xml, graphql, ws-binary, tcp, udp
#
# Tiers:
#   tier1  - json, octet-stream, ndjson, grpc, ws-binary, tcp, udp
#   tier2  - multipart, form-urlencoded
#   tier3  - xml, soap-xml, graphql
#
# Protocol groups:
#   http2  - all HTTP content types over HTTP/2
#   http3  - all HTTP content types over HTTP/3
#   all    - all content types over their default protocols
#   all-protocols - all protocols (HTTP/1.1 + HTTP/2 + HTTP/3 + gRPC + WS + TCP + UDP)
#
# Options:
#   --duration <SECS>       Test duration per size (default: 15)
#   --concurrency <N>       Concurrent connections (default: 100)
#   --sizes <S1,S2,...>     Comma-separated sizes (default: 10kb,50kb,100kb,1mb,5mb,9mb)
#   --skip-build            Skip cargo build step
#   --skip-direct           Skip direct-to-backend baseline tests
#   --envoy                 Run Envoy comparison (requires envoy in PATH)
#   --json                  Output machine-readable JSON results
#   --results-dir <DIR>     Directory for JSON result files (default: ./results)
#
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

DURATION=15
CONCURRENCY=100
SIZES="10kb,50kb,100kb,1mb,5mb,9mb"
TCP_SIZES="10kb,50kb,100kb,1mb"
UDP_SIZES="64,512,1kb,4kb"
SKIP_BUILD=false
SKIP_DIRECT=false
ENVOY_MODE=false
JSON_OUTPUT=false
RESULTS_DIR="./results"
CONTENT_TYPE_ARG=""
ENVOY_ADMIN_PORT=15000

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
GATEWAY_BIN="$REPO_ROOT/target/release/ferrum-edge"
BACKEND_BIN="$SCRIPT_DIR/target/release/payload_backend"
BENCH_BIN="$SCRIPT_DIR/target/release/payload_bench"
CONFIGS_DIR="$SCRIPT_DIR/configs"
ENVOY_CONFIGS_DIR="$SCRIPT_DIR/configs/envoy"

# PIDs to clean up
BACKEND_PID=""
GATEWAY_PID=""
ENVOY_PID=""

# ── Parse args ────────────────────────────────────────────────────────────────

if [ $# -lt 1 ]; then
    echo "Usage: bash run_payload_test.sh <CONTENT_TYPE|TIER|PROTOCOL|all> [OPTIONS]"
    echo ""
    echo "Content types: json, xml, form-urlencoded, multipart, octet-stream,"
    echo "               grpc, sse, ndjson, soap-xml, graphql, ws-binary, tcp, udp"
    echo ""
    echo "Tiers: tier1, tier2, tier3"
    echo "Protocol groups: http2, http3, all, all-protocols"
    echo ""
    echo "Options:"
    echo "  --duration <SECS>       Test duration per size (default: 15)"
    echo "  --concurrency <N>       Concurrent connections (default: 100)"
    echo "  --sizes <S1,S2,...>     Comma-separated sizes (default: 10kb,50kb,100kb,1mb,5mb,9mb)"
    echo "  --skip-build            Skip cargo build step"
    echo "  --skip-direct           Skip direct-to-backend baseline tests"
    echo "  --envoy                 Compare against Envoy (requires envoy in PATH)"
    echo "  --json                  Output JSON results"
    echo "  --results-dir <DIR>     Directory for results (default: ./results)"
    exit 1
fi

CONTENT_TYPE_ARG="$1"
shift

while [ $# -gt 0 ]; do
    case "$1" in
        --duration)    DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --sizes)       SIZES="$2"; shift 2 ;;
        --skip-build)  SKIP_BUILD=true; shift ;;
        --skip-direct) SKIP_DIRECT=true; shift ;;
        --envoy)       ENVOY_MODE=true; shift ;;
        --json)        JSON_OUTPUT=true; shift ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Convert sizes to arrays
IFS=',' read -ra SIZE_ARRAY <<< "$SIZES"
IFS=',' read -ra TCP_SIZE_ARRAY <<< "$TCP_SIZES"
IFS=',' read -ra UDP_SIZE_ARRAY <<< "$UDP_SIZES"

# ── Content type resolution ───────────────────────────────────────────────────

# Each entry is "content_type:protocol_override" where protocol_override is optional
resolve_content_types() {
    case "$1" in
        tier1) echo "json octet-stream ndjson grpc ws-binary tcp udp" ;;
        tier2) echo "multipart form-urlencoded" ;;
        tier3) echo "xml soap-xml graphql" ;;
        http2) echo "json:http2 octet-stream:http2 ndjson:http2 xml:http2 soap-xml:http2 graphql:http2 multipart:http2 form-urlencoded:http2" ;;
        http3) echo "json:http3 octet-stream:http3 ndjson:http3 xml:http3" ;;
        all)   echo "json octet-stream ndjson json:http2 octet-stream:http2 ndjson:http2 grpc ws-binary tcp udp multipart form-urlencoded xml soap-xml graphql" ;;
        all-protocols)
            echo "json octet-stream ndjson json:http2 octet-stream:http2 ndjson:http2 json:http3 octet-stream:http3 grpc ws-binary tcp udp multipart form-urlencoded xml soap-xml graphql"
            ;;
        *)     echo "$1" ;;
    esac
}

CONTENT_TYPES=$(resolve_content_types "$CONTENT_TYPE_ARG")

# Map content type (with optional :protocol) to gateway config, bench flags, and targets
# Returns: config|protocol_label|gw_target|direct_target|extra_bench_flags|envoy_config
get_config_and_flags() {
    local ct_spec="$1"
    local ct="${ct_spec%%:*}"
    local proto_override="${ct_spec#*:}"
    [ "$proto_override" = "$ct" ] && proto_override=""

    if [ "$proto_override" = "http2" ]; then
        echo "http2_perf.yaml|HTTP/2|https://127.0.0.1:8443/echo|https://127.0.0.1:4443/echo|--http2|envoy/http2.yaml"
        return
    fi
    if [ "$proto_override" = "http3" ]; then
        echo "http3_perf.yaml|HTTP/3|https://127.0.0.1:8443/echo|https://127.0.0.1:4445/echo|--http3|"
        return
    fi

    case "$ct" in
        grpc)
            echo "grpc_perf.yaml|gRPC|http://127.0.0.1:8000|http://127.0.0.1:50053||envoy/grpc.yaml"
            ;;
        ws-binary)
            echo "ws_perf.yaml|WebSocket|ws://127.0.0.1:8000/ws|ws://127.0.0.1:4003||envoy/ws.yaml"
            ;;
        sse)
            echo "http1_perf.yaml|HTTP/1.1|http://127.0.0.1:8000/sse|http://127.0.0.1:4001/sse||envoy/http1.yaml"
            ;;
        tcp)
            echo "tcp_perf.yaml|TCP|127.0.0.1:5010|127.0.0.1:4004||envoy/tcp.yaml"
            ;;
        udp)
            echo "udp_perf.yaml|UDP|127.0.0.1:5003|127.0.0.1:4005||envoy/udp.yaml"
            ;;
        *)
            echo "http1_perf.yaml|HTTP/1.1|http://127.0.0.1:8000/echo|http://127.0.0.1:4001/echo||envoy/http1.yaml"
            ;;
    esac
}

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "[cleanup] Stopping processes..."
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null && wait "$GATEWAY_PID" 2>/dev/null || true
    [ -n "$ENVOY_PID" ] && kill "$ENVOY_PID" 2>/dev/null && wait "$ENVOY_PID" 2>/dev/null || true
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null && wait "$BACKEND_PID" 2>/dev/null || true
    GATEWAY_PID=""
    ENVOY_PID=""
    BACKEND_PID=""
}

trap cleanup EXIT

kill_stale_processes() {
    local ports=(4001 4003 4004 4005 4010 4443 4445 5003 5010 8000 8443 9000 15000 50053)
    for port in "${ports[@]}"; do
        local pids
        pids=$(lsof -ti ":$port" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            echo "[cleanup] Killing stale process on port $port (PIDs: $pids)"
            echo "$pids" | xargs kill -9 2>/dev/null || true
            sleep 0.5
        fi
    done
}

# ── Build ─────────────────────────────────────────────────────────────────────

build_all() {
    if [ "$SKIP_BUILD" = true ]; then
        echo "[build] Skipping build (--skip-build)"
        return
    fi

    echo "[build] Building gateway (release)..."
    (cd "$REPO_ROOT" && cargo build --release --bin ferrum-edge 2>&1 | tail -1)

    echo "[build] Building payload test binaries (release)..."
    (cd "$SCRIPT_DIR" && cargo build --release 2>&1 | tail -1)

    echo "[build] Build complete."
}

# ── Envoy helpers ─────────────────────────────────────────────────────────────

check_envoy() {
    if ! command -v envoy &> /dev/null; then
        echo "[ERROR] envoy not found in PATH"
        echo "  Install: brew install envoy  (macOS)"
        echo "  Or see:  https://www.envoyproxy.io/docs/envoy/latest/start/install"
        exit 1
    fi
    local version
    version=$(envoy --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    echo "[envoy] Found Envoy v${version}"
}

prepare_envoy_config() {
    local src_config="$1"
    local cert_dir="$SCRIPT_DIR/certs"
    local runtime_config="$RESULTS_DIR/envoy_runtime_$(basename "$src_config")"

    sed -e "s|CERT_PATH|${cert_dir}/cert.pem|g" \
        -e "s|KEY_PATH|${cert_dir}/key.pem|g" \
        "$CONFIGS_DIR/$src_config" > "$runtime_config"

    echo "$runtime_config"
}

start_envoy() {
    local config_file="$1"
    echo "[envoy] Starting Envoy with config: $(basename "$config_file")"

    local runtime_config
    runtime_config=$(prepare_envoy_config "$config_file")

    local num_cpus
    num_cpus=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

    cd "$SCRIPT_DIR"
    envoy -c "$runtime_config" --concurrency "$num_cpus" -l error --disable-hot-restart \
        > "$SCRIPT_DIR/envoy.log" 2>&1 &
    ENVOY_PID=$!

    for i in $(seq 1 15); do
        if curl -sf "http://127.0.0.1:$ENVOY_ADMIN_PORT/ready" > /dev/null 2>&1; then
            echo "[envoy] Envoy ready (PID: $ENVOY_PID)"
            return
        fi
        sleep 1
    done
    echo "[ERROR] Envoy failed to start"
    tail -20 "$SCRIPT_DIR/envoy.log" 2>/dev/null
    exit 1
}

stop_envoy() {
    if [ -n "$ENVOY_PID" ]; then
        kill "$ENVOY_PID" 2>/dev/null && wait "$ENVOY_PID" 2>/dev/null || true
        ENVOY_PID=""
    fi
    # Clean up envoy ports
    for port in 8000 8443 5010 5003 $ENVOY_ADMIN_PORT; do
        lsof -ti:"$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    sleep 0.5
}

# ── Health check ──────────────────────────────────────────────────────────────

wait_for_health() {
    local url="$1"
    local name="$2"
    local max_retries=20
    local retry=0

    while [ $retry -lt $max_retries ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            return 0
        fi
        retry=$((retry + 1))
        sleep 0.5
    done
    echo "[ERROR] $name did not become healthy at $url after ${max_retries} retries"
    return 1
}

# ── Start/Stop servers ────────────────────────────────────────────────────────

start_backend() {
    echo "[server] Starting payload backend..."
    "$BACKEND_BIN" > /dev/null 2>&1 &
    BACKEND_PID=$!
    wait_for_health "http://127.0.0.1:4010/health" "Backend"
    echo "[server] Backend ready (PID: $BACKEND_PID)"
}

start_gateway() {
    local config="$1"
    echo "[server] Starting gateway with config: $config"

    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$CONFIGS_DIR/$config" \
    FERRUM_LOG_LEVEL=error \
    FERRUM_PROXY_HTTP_PORT=8000 \
    FERRUM_PROXY_HTTPS_PORT=8443 \
    FERRUM_ADMIN_HTTP_PORT=9000 \
    FERRUM_ADMIN_HTTPS_PORT=9443 \
    FERRUM_ADD_VIA_HEADER=false \
    FERRUM_ADD_FORWARDED_HEADER=false \
    FERRUM_TLS_NO_VERIFY=true \
    FERRUM_POOL_WARMUP_ENABLED=true \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_CLEANUP_INTERVAL_SECONDS=30 \
    FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608 \
    FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432 \
    FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true \
    FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=1048576 \
    FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
    FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
    FERRUM_MAX_GRPC_RECV_SIZE_BYTES=67108864 \
    FERRUM_GRPC_POOL_READY_WAIT_MS=1 \
    FERRUM_HTTP3_MAX_STREAMS=1000 \
    FERRUM_HTTP3_STREAM_RECEIVE_WINDOW=8388608 \
    FERRUM_HTTP3_RECEIVE_WINDOW=33554432 \
    FERRUM_HTTP3_SEND_WINDOW=8388608 \
    FERRUM_HTTP3_CONNECTIONS_PER_BACKEND=8 \
    FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_UDP_MAX_SESSIONS=10000 \
    FERRUM_UDP_CLEANUP_INTERVAL_SECONDS=10 \
    FERRUM_UDP_RECVMMSG_BATCH_SIZE=64 \
    FERRUM_WEBSOCKET_TUNNEL_MODE=true \
    FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0 \
    FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0 \
    FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 \
    FERRUM_MAX_CONNECTIONS=0 \
    FERRUM_MAX_HEADER_COUNT=0 \
    FERRUM_MAX_URL_LENGTH_BYTES=0 \
    FERRUM_MAX_QUERY_PARAMS=0 \
    FERRUM_FRONTEND_TLS_CERT_PATH="$SCRIPT_DIR/certs/cert.pem" \
    FERRUM_FRONTEND_TLS_KEY_PATH="$SCRIPT_DIR/certs/key.pem" \
        "$GATEWAY_BIN" > /dev/null 2>&1 &
    GATEWAY_PID=$!
    wait_for_health "http://127.0.0.1:9000/health" "Gateway"
    echo "[server] Gateway ready (PID: $GATEWAY_PID)"
}

stop_gateway() {
    if [ -n "$GATEWAY_PID" ]; then
        kill "$GATEWAY_PID" 2>/dev/null && wait "$GATEWAY_PID" 2>/dev/null || true
        GATEWAY_PID=""
        sleep 0.5
    fi
}

# ── Run benchmark ─────────────────────────────────────────────────────────────

run_bench() {
    local ct="$1"
    local size="$2"
    local target="$3"
    local extra_flags="$4"

    local json_flag="--json"
    local bench_ct="${ct%%:*}"

    "$BENCH_BIN" "$bench_ct" \
        --target "$target" \
        --size "$size" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --size-label "$size" \
        $extra_flags \
        $json_flag \
        2>/dev/null || echo '{"rps":0,"p50_us":0,"p99_us":0,"throughput_mbps":0,"total_errors":0}'
}

# ── Formatting helpers ────────────────────────────────────────────────────────

format_rps() {
    printf "%'.0f" "$1" 2>/dev/null || echo "$1"
}

format_latency_us() {
    local us="$1"
    if [ "$us" -ge 1000000 ] 2>/dev/null; then
        printf "%.2fs" "$(echo "$us / 1000000" | bc -l)"
    elif [ "$us" -ge 1000 ] 2>/dev/null; then
        printf "%.2fms" "$(echo "$us / 1000" | bc -l)"
    else
        printf "%sus" "$us"
    fi
}

format_throughput() {
    printf "%.1f Mbps" "$1"
}

extract_json_field() {
    local json="$1"
    local field="$2"
    echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$field', 0))" 2>/dev/null || echo "0"
}

# ── Standard mode table ──────────────────────────────────────────────────────

print_table_header() {
    local ct_display="$1"
    local protocol="$2"
    printf "\n"
    printf "╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n"
    printf "║  %-100s  ║\n" "$ct_display ($protocol)"
    printf "╠══════════╦════════════╦══════════════╦══════════╦══════════╦══════════╦═══════════════╦═════════════════╣\n"
    printf "║ %-8s ║ %-10s ║ %-12s ║ %-8s ║ %-8s ║ %-8s ║ %-13s ║ %-15s ║\n" \
        "Size" "RPS (gw)" "RPS (direct)" "Overhead" "P50" "P99" "Throughput" "Errors"
    printf "╠══════════╬════════════╬══════════════╬══════════╬══════════╬══════════╬═══════════════╬═════════════════╣\n"
}

print_table_row() {
    printf "║ %-8s ║ %10s ║ %12s ║ %8s ║ %8s ║ %8s ║ %13s ║ %15s ║\n" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8"
}

print_table_footer() {
    printf "╚══════════╩════════════╩══════════════╩══════════╩══════════╩══════════╩═══════════════╩═════════════════╝\n"
}

# ── Envoy comparison table ───────────────────────────────────────────────────

print_envoy_header() {
    local ct_display="$1"
    local protocol="$2"
    printf "\n"
    printf "╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n"
    printf "║  %-117s  ║\n" "$ct_display ($protocol) — Ferrum Edge vs Envoy"
    printf "╠══════════╦═══════════════════════════════════════════════╦═══════════════════════════════════════════════╦═════════════════════════╣\n"
    printf "║          ║          Ferrum Edge                         ║          Envoy                                ║        Winner           ║\n"
    printf "║ %-8s ║ %10s %8s %8s %13s ║ %10s %8s %8s %13s ║ %7s %15s ║\n" \
        "Size" "RPS" "P50" "P99" "Throughput" "RPS" "P50" "P99" "Throughput" "RPS" "Overhead"
    printf "╠══════════╬═══════════════════════════════════════════════╬═══════════════════════════════════════════════╬═════════════════════════╣\n"
}

print_envoy_row() {
    local size="$1"
    local fe_rps="$2" fe_p50="$3" fe_p99="$4" fe_tp="$5"
    local ev_rps="$6" ev_p50="$7" ev_p99="$8" ev_tp="$9"
    local winner="${10}" overhead="${11}"

    printf "║ %-8s ║ %10s %8s %8s %13s ║ %10s %8s %8s %13s ║ %7s %15s ║\n" \
        "$size" "$fe_rps" "$fe_p50" "$fe_p99" "$fe_tp" "$ev_rps" "$ev_p50" "$ev_p99" "$ev_tp" "$winner" "$overhead"
}

print_envoy_footer() {
    printf "╚══════════╩═══════════════════════════════════════════════════════════════════════════════════════════════╩═════════════════════════╝\n"
}

# ── Get sizes for a content type ─────────────────────────────────────────────

get_sizes_for_ct() {
    local ct="$1"
    case "$ct" in
        tcp) echo "${TCP_SIZE_ARRAY[@]}" ;;
        udp) echo "${UDP_SIZE_ARRAY[@]}" ;;
        *)   echo "${SIZE_ARRAY[@]}" ;;
    esac
}

# ── Run standard mode (Ferrum only) ──────────────────────────────────────────

run_standard_test() {
    local current_config=""

    for ct_spec in $CONTENT_TYPES; do
        local ct="${ct_spec%%:*}"
        local proto_override="${ct_spec#*:}"
        [ "$proto_override" = "$ct" ] && proto_override=""

        local config_info
        config_info=$(get_config_and_flags "$ct_spec")
        IFS='|' read -r config protocol gw_target direct_target extra_flags envoy_config <<< "$config_info"

        local ct_display
        ct_display=$(get_ct_display "$ct")

        local tier
        tier=$(get_tier "$ct")

        if [ "$config" != "$current_config" ]; then
            stop_gateway
            start_gateway "$config"
            current_config="$config"
        fi

        print_table_header "$tier: $ct_display" "$protocol"

        local sizes
        read -ra sizes <<< "$(get_sizes_for_ct "$ct")"

        for size in "${sizes[@]}"; do
            local gw_result
            gw_result=$(run_bench "$ct_spec" "$size" "$gw_target" "$extra_flags")

            local gw_rps gw_p50 gw_p99 gw_throughput gw_errors
            gw_rps=$(extract_json_field "$gw_result" "rps")
            gw_p50=$(extract_json_field "$gw_result" "p50_us")
            gw_p99=$(extract_json_field "$gw_result" "p99_us")
            gw_throughput=$(extract_json_field "$gw_result" "throughput_mbps")
            gw_errors=$(extract_json_field "$gw_result" "total_errors")

            local direct_rps="N/A"
            local overhead="N/A"
            if [ "$SKIP_DIRECT" != true ]; then
                local direct_result
                direct_result=$(run_bench "$ct_spec" "$size" "$direct_target" "$extra_flags")
                direct_rps=$(extract_json_field "$direct_result" "rps")

                if [ "$(echo "$direct_rps > 0" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
                    overhead=$(printf "%.1f%%" "$(echo "((($direct_rps - $gw_rps) / $direct_rps) * 100)" | bc -l 2>/dev/null || echo 0)")
                fi
                direct_rps=$(format_rps "$direct_rps")
            fi

            if [ -n "$RESULTS_DIR" ]; then
                local result_name="${ct}"
                [ -n "$proto_override" ] && result_name="${ct}_${proto_override}"
                echo "$gw_result" > "$RESULTS_DIR/${result_name}_${size}_gateway.json"
            fi

            print_table_row \
                "$size" \
                "$(format_rps "$gw_rps")" \
                "$direct_rps" \
                "$overhead" \
                "$(format_latency_us "${gw_p50%.*}")" \
                "$(format_latency_us "${gw_p99%.*}")" \
                "$(format_throughput "$gw_throughput")" \
                "$gw_errors"
        done

        print_table_footer
    done

    stop_gateway
}

# ── Run Envoy comparison mode ────────────────────────────────────────────────

run_envoy_comparison() {
    check_envoy

    local current_ferrum_config=""

    for ct_spec in $CONTENT_TYPES; do
        local ct="${ct_spec%%:*}"
        local proto_override="${ct_spec#*:}"
        [ "$proto_override" = "$ct" ] && proto_override=""

        local config_info
        config_info=$(get_config_and_flags "$ct_spec")
        IFS='|' read -r config protocol gw_target direct_target extra_flags envoy_config <<< "$config_info"

        # Skip content types with no envoy config (e.g. HTTP/3)
        if [ -z "$envoy_config" ]; then
            echo "[envoy] Skipping $ct_spec — no Envoy equivalent (HTTP/3 not supported)"
            continue
        fi

        local ct_display
        ct_display=$(get_ct_display "$ct")

        local tier
        tier=$(get_tier "$ct")

        print_envoy_header "$tier: $ct_display" "$protocol"

        local sizes
        read -ra sizes <<< "$(get_sizes_for_ct "$ct")"

        for size in "${sizes[@]}"; do
            # ── Ferrum Edge run ──
            stop_gateway
            stop_envoy
            start_gateway "$config"

            local fe_result
            fe_result=$(run_bench "$ct_spec" "$size" "$gw_target" "$extra_flags")

            local fe_rps fe_p50 fe_p99 fe_tp
            fe_rps=$(extract_json_field "$fe_result" "rps")
            fe_p50=$(extract_json_field "$fe_result" "p50_us")
            fe_p99=$(extract_json_field "$fe_result" "p99_us")
            fe_tp=$(extract_json_field "$fe_result" "throughput_mbps")

            stop_gateway

            # ── Envoy run ──
            start_envoy "$envoy_config"

            local ev_result
            ev_result=$(run_bench "$ct_spec" "$size" "$gw_target" "$extra_flags")

            local ev_rps ev_p50 ev_p99 ev_tp
            ev_rps=$(extract_json_field "$ev_result" "rps")
            ev_p50=$(extract_json_field "$ev_result" "p50_us")
            ev_p99=$(extract_json_field "$ev_result" "p99_us")
            ev_tp=$(extract_json_field "$ev_result" "throughput_mbps")

            stop_envoy

            # ── Compare ──
            local winner="TIE"
            local overhead="0.0%"
            if [ "$(echo "$fe_rps > $ev_rps" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
                winner="FERRUM"
                if [ "$(echo "$ev_rps > 0" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
                    overhead=$(printf "+%.1f%%" "$(echo "(($fe_rps - $ev_rps) / $ev_rps) * 100" | bc -l 2>/dev/null || echo 0)")
                fi
            elif [ "$(echo "$ev_rps > $fe_rps" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
                winner="ENVOY"
                if [ "$(echo "$fe_rps > 0" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
                    overhead=$(printf -- "-%.1f%%" "$(echo "(($ev_rps - $fe_rps) / $fe_rps) * 100" | bc -l 2>/dev/null || echo 0)")
                fi
            fi

            # Save results
            if [ -n "$RESULTS_DIR" ]; then
                local result_name="${ct}"
                [ -n "$proto_override" ] && result_name="${ct}_${proto_override}"
                echo "$fe_result" > "$RESULTS_DIR/${result_name}_${size}_ferrum.json"
                echo "$ev_result" > "$RESULTS_DIR/${result_name}_${size}_envoy.json"
            fi

            print_envoy_row \
                "$size" \
                "$(format_rps "$fe_rps")" \
                "$(format_latency_us "${fe_p50%.*}")" \
                "$(format_latency_us "${fe_p99%.*}")" \
                "$(format_throughput "$fe_tp")" \
                "$(format_rps "$ev_rps")" \
                "$(format_latency_us "${ev_p50%.*}")" \
                "$(format_latency_us "${ev_p99%.*}")" \
                "$(format_throughput "$ev_tp")" \
                "$winner" \
                "$overhead"
        done

        print_envoy_footer
    done

    stop_gateway
    stop_envoy
}

# ── Display name helpers ─────────────────────────────────────────────────────

get_ct_display() {
    case "$1" in
        json)             echo "application/json" ;;
        xml)              echo "application/xml" ;;
        form-urlencoded)  echo "application/x-www-form-urlencoded" ;;
        multipart)        echo "multipart/form-data" ;;
        octet-stream)     echo "application/octet-stream" ;;
        grpc)             echo "application/grpc" ;;
        sse)              echo "text/event-stream" ;;
        ndjson)           echo "application/x-ndjson" ;;
        soap-xml)         echo "application/soap+xml" ;;
        graphql)          echo "application/graphql" ;;
        ws-binary)        echo "WebSocket (binary)" ;;
        tcp)              echo "TCP (binary)" ;;
        udp)              echo "UDP (datagram)" ;;
        *)                echo "$1" ;;
    esac
}

get_tier() {
    case "$1" in
        json|octet-stream|ndjson|grpc|ws-binary|tcp|udp) echo "Tier 1" ;;
        multipart|form-urlencoded) echo "Tier 2" ;;
        xml|soap-xml|graphql) echo "Tier 3" ;;
        *) echo "Tier 1" ;;
    esac
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    local mode_label="Ferrum Edge"
    [ "$ENVOY_MODE" = true ] && mode_label="Ferrum Edge vs Envoy"

    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║       Payload Size Performance Test Suite               ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    printf "║  Mode:         %-40s ║\n" "$mode_label"
    printf "║  Duration:     %-40s ║\n" "${DURATION}s per test"
    printf "║  Concurrency:  %-40s ║\n" "${CONCURRENCY} connections"
    printf "║  Sizes:        %-40s ║\n" "${SIZES}"
    printf "║  TCP sizes:    %-40s ║\n" "${TCP_SIZES}"
    printf "║  UDP sizes:    %-40s ║\n" "${UDP_SIZES}"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""

    kill_stale_processes
    build_all
    mkdir -p "$RESULTS_DIR"

    start_backend

    if [ "$ENVOY_MODE" = true ]; then
        run_envoy_comparison
    else
        run_standard_test
    fi

    echo ""
    echo "[done] All tests complete. Results in $RESULTS_DIR/"
}

main
