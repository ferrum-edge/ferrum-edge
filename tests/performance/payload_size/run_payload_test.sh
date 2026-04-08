#!/usr/bin/env bash
#
# Payload Size Performance Test Runner
#
# Tests gateway performance across content types, protocols, and payload sizes.
# Measures throughput (RPS), latency (P50/P99), and data transfer rates.
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
#   --json                  Output machine-readable JSON results
#   --results-dir <DIR>     Directory for JSON result files (default: ./results)
#
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

DURATION=15
CONCURRENCY=100
SIZES="10kb,50kb,100kb,1mb,5mb,9mb"
SKIP_BUILD=false
SKIP_DIRECT=false
JSON_OUTPUT=false
RESULTS_DIR="./results"
CONTENT_TYPE_ARG=""

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
GATEWAY_BIN="$REPO_ROOT/target/release/ferrum-edge"
BACKEND_BIN="$SCRIPT_DIR/target/release/payload_backend"
BENCH_BIN="$SCRIPT_DIR/target/release/payload_bench"
CONFIGS_DIR="$SCRIPT_DIR/configs"

# PIDs to clean up
BACKEND_PID=""
GATEWAY_PID=""

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
        --json)        JSON_OUTPUT=true; shift ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Convert sizes to array
IFS=',' read -ra SIZE_ARRAY <<< "$SIZES"

# ── Content type resolution ───────────────────────────────────────────────────

# Each entry is "content_type:protocol_override" where protocol_override is optional
# protocol_override can be: (empty)=default, http2, http3
resolve_content_types() {
    case "$1" in
        tier1) echo "json octet-stream ndjson grpc ws-binary tcp udp" ;;
        tier2) echo "multipart form-urlencoded" ;;
        tier3) echo "xml soap-xml graphql" ;;
        http2) echo "json:http2 octet-stream:http2 ndjson:http2 xml:http2 soap-xml:http2 graphql:http2 multipart:http2 form-urlencoded:http2" ;;
        http3) echo "json:http3 octet-stream:http3 ndjson:http3 xml:http3" ;;
        all)   echo "json octet-stream ndjson grpc ws-binary tcp udp multipart form-urlencoded xml soap-xml graphql" ;;
        all-protocols)
            echo "json octet-stream ndjson json:http2 octet-stream:http2 ndjson:http2 json:http3 octet-stream:http3 grpc ws-binary tcp udp multipart form-urlencoded xml soap-xml graphql"
            ;;
        *)     echo "$1" ;;
    esac
}

CONTENT_TYPES=$(resolve_content_types "$CONTENT_TYPE_ARG")

# Map content type (with optional :protocol) to gateway config, bench flags, and targets
# Returns: config|protocol_label|gw_target|direct_target|extra_bench_flags
get_config_and_flags() {
    local ct_spec="$1"
    local ct="${ct_spec%%:*}"
    local proto_override="${ct_spec#*:}"
    [ "$proto_override" = "$ct" ] && proto_override=""

    if [ "$proto_override" = "http2" ]; then
        echo "http2_perf.yaml|HTTP/2|https://127.0.0.1:8443/echo|https://127.0.0.1:4443/echo|--http2"
        return
    fi
    if [ "$proto_override" = "http3" ]; then
        echo "http3_perf.yaml|HTTP/3|https://127.0.0.1:8443/echo|https://127.0.0.1:4445/echo|--http3"
        return
    fi

    case "$ct" in
        grpc)
            echo "grpc_perf.yaml|gRPC|http://127.0.0.1:8000|http://127.0.0.1:50053|"
            ;;
        ws-binary)
            echo "ws_perf.yaml|WebSocket|ws://127.0.0.1:8000/ws|ws://127.0.0.1:4003|"
            ;;
        sse)
            echo "http1_perf.yaml|HTTP/1.1|http://127.0.0.1:8000/sse|http://127.0.0.1:4001/sse|"
            ;;
        tcp)
            echo "tcp_perf.yaml|TCP|127.0.0.1:5010|127.0.0.1:4004|"
            ;;
        udp)
            echo "udp_perf.yaml|UDP|127.0.0.1:5003|127.0.0.1:4005|"
            ;;
        *)
            echo "http1_perf.yaml|HTTP/1.1|http://127.0.0.1:8000/echo|http://127.0.0.1:4001/echo|"
            ;;
    esac
}

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "[cleanup] Stopping processes..."
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null && wait "$GATEWAY_PID" 2>/dev/null || true
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null && wait "$BACKEND_PID" 2>/dev/null || true
    GATEWAY_PID=""
    BACKEND_PID=""
}

trap cleanup EXIT

# Kill any stale processes on our ports
kill_stale_processes() {
    local ports=(4001 4003 4004 4005 4010 4443 4445 5003 5010 8000 8443 9000 50053)
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
    FERRUM_POOL_WARMUP_ENABLED=true \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_ADD_VIA_HEADER=false \
    FERRUM_TLS_NO_VERIFY=true \
    FERRUM_MAX_GRPC_RECV_SIZE_BYTES=67108864 \
    FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
    FERRUM_FRONTEND_TLS_CERT_PATH="$SCRIPT_DIR/certs/cert.pem" \
    FERRUM_FRONTEND_TLS_KEY_PATH="$SCRIPT_DIR/certs/key.pem" \
    FERRUM_GRPC_POOL_READY_WAIT_MS=1 \
    FERRUM_UDP_MAX_SESSIONS=10000 \
    FERRUM_UDP_CLEANUP_INTERVAL_SECONDS=10 \
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
    local label="$5"

    local json_flag=""
    if [ "$JSON_OUTPUT" = true ] || [ -n "$RESULTS_DIR" ]; then
        json_flag="--json"
    fi

    # Strip protocol override from content type for the bench tool
    local bench_ct="${ct%%:*}"

    "$BENCH_BIN" "$bench_ct" \
        --target "$target" \
        --size "$size" \
        --duration "$DURATION" \
        --concurrency "$CONCURRENCY" \
        --size-label "$size" \
        $extra_flags \
        $json_flag \
        2>/dev/null
}

# ── Formatting helpers ────────────────────────────────────────────────────────

format_rps() {
    local rps="$1"
    printf "%'.0f" "$rps" 2>/dev/null || echo "$rps"
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
    local mbps="$1"
    printf "%.1f Mbps" "$mbps"
}

extract_json_field() {
    local json="$1"
    local field="$2"
    echo "$json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$field', 0))" 2>/dev/null || echo "0"
}

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
    local size="$1"
    local gw_rps="$2"
    local direct_rps="$3"
    local overhead="$4"
    local p50="$5"
    local p99="$6"
    local throughput="$7"
    local errors="$8"

    printf "║ %-8s ║ %10s ║ %12s ║ %8s ║ %8s ║ %8s ║ %13s ║ %15s ║\n" \
        "$size" "$gw_rps" "$direct_rps" "$overhead" "$p50" "$p99" "$throughput" "$errors"
}

print_table_footer() {
    printf "╚══════════╩════════════╩══════════════╩══════════╩══════════╩══════════╩═══════════════╩═════════════════╝\n"
}

# ── Main test loop ────────────────────────────────────────────────────────────

main() {
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║       Payload Size Performance Test Suite               ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    printf "║  Duration:     %-40s ║\n" "${DURATION}s per test"
    printf "║  Concurrency:  %-40s ║\n" "${CONCURRENCY} connections"
    printf "║  Sizes:        %-40s ║\n" "${SIZES}"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""

    # Setup
    kill_stale_processes
    build_all
    mkdir -p "$RESULTS_DIR"

    # Start backend (stays running for all tests)
    start_backend

    local current_config=""

    for ct_spec in $CONTENT_TYPES; do
        local ct="${ct_spec%%:*}"
        local proto_override="${ct_spec#*:}"
        [ "$proto_override" = "$ct" ] && proto_override=""

        local config_info
        config_info=$(get_config_and_flags "$ct_spec")
        IFS='|' read -r config protocol gw_target direct_target extra_flags <<< "$config_info"

        # Get display name
        local ct_display
        case "$ct" in
            json)             ct_display="application/json" ;;
            xml)              ct_display="application/xml" ;;
            form-urlencoded)  ct_display="application/x-www-form-urlencoded" ;;
            multipart)        ct_display="multipart/form-data" ;;
            octet-stream)     ct_display="application/octet-stream" ;;
            grpc)             ct_display="application/grpc" ;;
            sse)              ct_display="text/event-stream" ;;
            ndjson)           ct_display="application/x-ndjson" ;;
            soap-xml)         ct_display="application/soap+xml" ;;
            graphql)          ct_display="application/graphql" ;;
            ws-binary)        ct_display="WebSocket (binary)" ;;
            tcp)              ct_display="TCP (binary)" ;;
            udp)              ct_display="UDP (binary)" ;;
            *)                ct_display="$ct" ;;
        esac

        # Get tier
        local tier
        case "$ct" in
            json|octet-stream|ndjson|grpc|ws-binary|tcp|udp) tier="Tier 1" ;;
            multipart|form-urlencoded) tier="Tier 2" ;;
            xml|soap-xml|graphql) tier="Tier 3" ;;
            *) tier="Tier 1" ;;
        esac

        # Start/restart gateway if config changed
        if [ "$config" != "$current_config" ]; then
            stop_gateway
            start_gateway "$config"
            current_config="$config"
        fi

        print_table_header "$tier: $ct_display" "$protocol"

        for size in "${SIZE_ARRAY[@]}"; do
            # For UDP, skip sizes > 64KB (UDP datagram limit)
            if [ "$ct" = "udp" ]; then
                local size_bytes
                size_bytes=$(python3 -c "
s = '${size}'.lower()
if s.endswith('mb'): print(int(s[:-2]) * 1024 * 1024)
elif s.endswith('kb'): print(int(s[:-2]) * 1024)
else: print(int(s))
" 2>/dev/null || echo "0")
                if [ "$size_bytes" -gt 65507 ]; then
                    print_table_row "$size" "SKIP" "SKIP" "N/A" "N/A" "N/A" "N/A" ">64KB dgram"
                    continue
                fi
            fi

            # Run through gateway
            local gw_result
            gw_result=$(run_bench "$ct_spec" "$size" "$gw_target" "$extra_flags" "gateway" 2>/dev/null || echo '{"rps":0,"p50_us":0,"p99_us":0,"throughput_mbps":0,"total_errors":0}')

            local gw_rps gw_p50 gw_p99 gw_throughput gw_errors
            gw_rps=$(extract_json_field "$gw_result" "rps")
            gw_p50=$(extract_json_field "$gw_result" "p50_us")
            gw_p99=$(extract_json_field "$gw_result" "p99_us")
            gw_throughput=$(extract_json_field "$gw_result" "throughput_mbps")
            gw_errors=$(extract_json_field "$gw_result" "total_errors")

            # Run direct to backend (baseline)
            local direct_rps="N/A"
            local overhead="N/A"
            if [ "$SKIP_DIRECT" != true ]; then
                local direct_result
                direct_result=$(run_bench "$ct_spec" "$size" "$direct_target" "$extra_flags" "direct" 2>/dev/null || echo '{"rps":0}')
                direct_rps=$(extract_json_field "$direct_result" "rps")

                # Calculate overhead
                if [ "$(echo "$direct_rps > 0" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
                    overhead=$(printf "%.1f%%" "$(echo "((($direct_rps - $gw_rps) / $direct_rps) * 100)" | bc -l 2>/dev/null || echo 0)")
                fi
                direct_rps=$(format_rps "$direct_rps")
            fi

            # Save raw JSON
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

    # Stop everything
    stop_gateway
    echo ""
    echo "[done] All tests complete. Results in $RESULTS_DIR/"
}

main
