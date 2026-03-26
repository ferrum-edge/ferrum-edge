#!/bin/bash

# ===========================================================================
# API Gateway Comparison Benchmark
# Ferrum Gateway vs Pingora vs Kong vs Tyk vs KrakenD vs Envoy
#
# Runs each gateway sequentially (one at a time) against the same backend
# echo server, testing both HTTP and HTTPS (TLS termination), then generates
# a comparison report with throughput, latency, and error rate analysis.
#
# Usage:
#   ./comparison/run_comparison.sh
#
# Environment variable overrides:
#   WRK_DURATION=30s        Duration of each wrk test run
#   WRK_THREADS=8           wrk thread count
#   WRK_CONNECTIONS=100     wrk concurrent connections
#   KONG_VERSION=3.9        Kong Docker image tag
#   TYK_VERSION=v5.7        Tyk Docker image tag
#   KRAKEND_VERSION=2.13    KrakenD Docker image tag
#   ENVOY_VERSION=1.32-latest  Envoy Docker image tag
#   SKIP_GATEWAYS=tyk       Comma-separated gateways to skip (ferrum,pingora,kong,tyk,krakend,envoy)
#   WARMUP_DURATION=5s      Warm-up duration before measured test
# ===========================================================================

set -euo pipefail

COMP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$COMP_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
BACKEND_PORT=3001
BACKEND_HTTPS_PORT=3443
GATEWAY_HTTP_PORT=8000
GATEWAY_HTTPS_PORT=8443
WRK_DURATION=${WRK_DURATION:-30s}
WRK_THREADS=${WRK_THREADS:-8}
WRK_CONNECTIONS=${WRK_CONNECTIONS:-100}
WARMUP_DURATION=${WARMUP_DURATION:-5s}
KONG_VERSION=${KONG_VERSION:-3.9}
TYK_VERSION=${TYK_VERSION:-v5.7}
KRAKEND_VERSION=${KRAKEND_VERSION:-2.13}
ENVOY_VERSION=${ENVOY_VERSION:-1.32-latest}
SKIP_GATEWAYS=${SKIP_GATEWAYS:-}

RESULTS_DIR="$COMP_DIR/results"
CERTS_DIR="$PROJECT_ROOT/tests/certs"
PERF_DIR="$PROJECT_ROOT/tests/performance"
LUA_SCRIPT="$COMP_DIR/lua/comparison_test.lua"
LUA_SCRIPT_KEY_AUTH="$COMP_DIR/lua/comparison_test_key_auth.lua"

# Docker container names (prefixed for easy cleanup)
KONG_CONTAINER="ferrum-bench-kong"
TYK_CONTAINER="ferrum-bench-tyk"
KRAKEND_CONTAINER="ferrum-bench-krakend"
ENVOY_CONTAINER="ferrum-bench-envoy"
REDIS_CONTAINER="ferrum-bench-redis"

# PIDs to track
BACKEND_PID=""
FERRUM_PID=""
PINGORA_PID=""
KONG_PID=""

# Pingora bench proxy binary path
PINGORA_PROXY_DIR="$COMP_DIR/configs/pingora"
PINGORA_BINARY="$PINGORA_PROXY_DIR/target/release/pingora-bench-proxy"

# Detect platform for Docker networking
# macOS Docker Desktop does not support --network host; use port mapping instead
if [[ "$(uname -s)" == "Darwin" ]]; then
    BACKEND_HOST="host.docker.internal"
    DOCKER_USE_HOST_NETWORK=false
else
    BACKEND_HOST="127.0.0.1"
    DOCKER_USE_HOST_NETWORK=true
fi

# Detect whether Kong is installed natively (preferred over Docker for fair benchmarking)
KONG_NATIVE=false
if command -v kong &>/dev/null; then
    KONG_NATIVE=true
fi

# Detect whether Envoy is installed natively (preferred over Docker for fair benchmarking)
ENVOY_NATIVE=false
if command -v envoy &>/dev/null; then
    ENVOY_NATIVE=true
fi

# ===========================================================================
# Utility functions
# ===========================================================================

log_header() {
    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════${NC}"
}

log_info() {
    echo -e "${CYAN}  ▸ $1${NC}"
}

log_ok() {
    echo -e "${GREEN}  ✓ $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}  ⚠ $1${NC}"
}

log_err() {
    echo -e "${RED}  ✗ $1${NC}"
}

should_skip() {
    local gw="$1"
    echo "$SKIP_GATEWAYS" | tr ',' '\n' | grep -qx "$gw"
}

wait_for_http() {
    local url="$1"
    local label="$2"
    local max_retries="${3:-15}"
    for i in $(seq 1 "$max_retries"); do
        if curl -skf "$url" > /dev/null 2>&1; then
            log_ok "$label is ready"
            return 0
        fi
        sleep 1
    done
    log_err "$label failed to start after ${max_retries}s"
    return 1
}

kill_port() {
    lsof -ti:"$1" 2>/dev/null | xargs kill -9 2>/dev/null || true
}

# ===========================================================================
# Cleanup (always runs on exit)
# ===========================================================================

cleanup() {
    echo ""
    log_header "Cleaning up"

    if [[ -n "$BACKEND_PID" ]]; then
        kill "$BACKEND_PID" 2>/dev/null || true
        log_ok "Backend server stopped"
    fi
    if [[ -n "$FERRUM_PID" ]]; then
        kill "$FERRUM_PID" 2>/dev/null || true
        log_ok "Ferrum gateway stopped"
    fi
    if [[ -n "$PINGORA_PID" ]]; then
        kill "$PINGORA_PID" 2>/dev/null || true
        log_ok "Pingora proxy stopped"
    fi
    if [[ "$KONG_PID" == "native" ]]; then
        KONG_PREFIX="/tmp/kong-bench" kong stop 2>/dev/null || true
    fi
    if [[ -n "$ENVOY_NATIVE_PID" ]]; then
        kill "$ENVOY_NATIVE_PID" 2>/dev/null || true
        log_ok "Envoy proxy stopped"
    fi

    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    docker rm -f "$KRAKEND_CONTAINER" 2>/dev/null || true
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    docker rm -f "$REDIS_CONTAINER" 2>/dev/null || true

    # Clean up Docker network and temporary config files
    docker network rm "$TYK_NETWORK" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.kong_runtime.yaml" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.kong_runtime_e2e_tls.yaml" 2>/dev/null || true
    rm -rf "$COMP_DIR/configs/.tyk_runtime_apps" 2>/dev/null || true
    rm -rf "$COMP_DIR/configs/.tyk_runtime_apps_e2e_tls" 2>/dev/null || true
    rm -rf "$COMP_DIR/configs/.tyk_runtime" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.krakend_runtime_http.json" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.krakend_runtime_https.json" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.krakend_runtime_e2e_tls.json" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.envoy_runtime_http.yaml" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.envoy_runtime_https.yaml" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.envoy_runtime_e2e_tls.yaml" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.envoy_runtime_key_auth.yaml" 2>/dev/null || true

    kill_port "$BACKEND_PORT"
    kill_port "$BACKEND_HTTPS_PORT"
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
}

trap cleanup EXIT

# ===========================================================================
# Dependency checks
# ===========================================================================

needs_docker() {
    # Docker is needed for Tyk (always), KrakenD (always), Envoy (always), and Kong (unless native)
    if ! should_skip "tyk"; then
        return 0
    fi
    if ! should_skip "krakend"; then
        return 0
    fi
    if ! should_skip "envoy" && [[ "$ENVOY_NATIVE" != "true" ]]; then
        return 0
    fi
    if ! should_skip "kong" && [[ "$KONG_NATIVE" != "true" ]]; then
        return 0
    fi
    return 1
}

check_dependencies() {
    log_header "Checking dependencies"

    local missing=0
    local required_cmds=(wrk python3 cargo curl)
    if needs_docker; then
        required_cmds+=(docker)
    fi

    for cmd in "${required_cmds[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            log_ok "$cmd"
        else
            log_err "$cmd not found"
            missing=1
        fi
    done

    if [[ "$missing" -eq 1 ]]; then
        echo ""
        log_err "Install missing dependencies before running."
        echo "  wrk:    brew install wrk (macOS) / apt install wrk (Ubuntu)"
        echo "  docker: https://docs.docker.com/get-docker/"
        exit 1
    fi

    # Check Docker daemon is running (only if needed)
    if needs_docker; then
        if ! docker info &>/dev/null; then
            log_err "Docker daemon is not running. Start Docker and try again."
            exit 1
        fi
        log_ok "Docker daemon"
    else
        log_info "Docker not required (Kong and Tyk skipped)"
    fi
}

# ===========================================================================
# Docker image pull (do this upfront so it doesn't affect timing)
# ===========================================================================

pull_images() {
    if ! needs_docker; then
        return
    fi

    log_header "Pulling Docker images"

    if ! should_skip "kong"; then
        log_info "Pulling kong/kong-gateway:${KONG_VERSION}..."
        docker pull "kong/kong-gateway:${KONG_VERSION}" --quiet || {
            log_warn "Failed to pull Kong image. Will try to use cached version."
        }
    fi

    if ! should_skip "tyk"; then
        log_info "Pulling tykio/tyk-gateway:${TYK_VERSION}..."
        docker pull "tykio/tyk-gateway:${TYK_VERSION}" --quiet || {
            log_warn "Failed to pull Tyk image. Will try to use cached version."
        }
        log_info "Pulling redis:7-alpine..."
        docker pull redis:7-alpine --quiet || true
    fi

    if ! should_skip "krakend"; then
        log_info "Pulling krakend:${KRAKEND_VERSION}..."
        docker pull "krakend:${KRAKEND_VERSION}" --quiet || {
            log_warn "Failed to pull KrakenD image. Will try to use cached version."
        }
    fi

    if ! should_skip "envoy" && [[ "$ENVOY_NATIVE" != "true" ]]; then
        log_info "Pulling envoyproxy/envoy:v${ENVOY_VERSION}..."
        docker pull "envoyproxy/envoy:v${ENVOY_VERSION}" --quiet || {
            log_warn "Failed to pull Envoy image. Will try to use cached version."
        }
    fi
}

# ===========================================================================
# Build Ferrum + backend
# ===========================================================================

build_project() {
    log_header "Building Ferrum Gateway and backend server"

    log_info "Building gateway (release)..."
    cd "$PROJECT_ROOT"
    cargo build --release --bin ferrum-gateway 2>&1 | tail -1

    log_info "Building backend server (release)..."
    cd "$PERF_DIR"
    cargo build --release --bin backend_server 2>&1 | tail -1

    if ! should_skip "pingora"; then
        log_info "Building Pingora bench proxy (release)..."
        cd "$PINGORA_PROXY_DIR"
        cargo build --release 2>&1 | tail -1
        if [[ -f "$PINGORA_BINARY" ]]; then
            log_ok "Pingora bench proxy built"
        else
            log_warn "Pingora bench proxy build failed — will skip Pingora tests"
        fi
    fi

    log_ok "Build completed"
}

# ===========================================================================
# Backend server
# ===========================================================================

start_backend() {
    log_info "Starting backend server on ports $BACKEND_PORT (HTTP) and $BACKEND_HTTPS_PORT (HTTPS)..."
    kill_port "$BACKEND_PORT"
    kill_port "$BACKEND_HTTPS_PORT"
    BACKEND_TLS_CERT="$CERTS_DIR/server.crt" \
    BACKEND_TLS_KEY="$CERTS_DIR/server.key" \
    "$PERF_DIR/target/release/backend_server" > "$RESULTS_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    wait_for_http "http://127.0.0.1:$BACKEND_PORT/health" "Backend server (HTTP)"
    wait_for_http "https://127.0.0.1:$BACKEND_HTTPS_PORT/health" "Backend server (HTTPS)" 10
}

# ===========================================================================
# wrk test runner
# ===========================================================================

run_wrk() {
    local gateway="$1"
    local protocol="$2"
    local endpoint="$3"
    local port="$4"
    local label="${gateway}/${protocol}${endpoint}"
    # Sanitize endpoint for filename: /health -> health, /api/users -> api_users
    local safe_endpoint
    safe_endpoint=$(echo "$endpoint" | sed 's|^/||; s|/|_|g')
    local result_file="${RESULTS_DIR}/${gateway}_${protocol}_${safe_endpoint}_results.txt"

    local url
    if [[ "$protocol" == "https" || "$protocol" == "e2e_tls" ]]; then
        url="https://127.0.0.1:${port}${endpoint}"
    else
        url="http://127.0.0.1:${port}${endpoint}"
    fi

    echo -e "    ${CYAN}Testing ${label}${NC}  →  ${url}"

    # Warm-up (results discarded)
    wrk -t2 -c20 -d"$WARMUP_DURATION" -s "$LUA_SCRIPT" "$url" > /dev/null 2>&1 || true

    # Measured run
    if ! wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"$WRK_DURATION" \
        --latency -s "$LUA_SCRIPT" "$url" > "$result_file" 2>&1; then
        log_warn "wrk failed for ${label} — see ${result_file}"
        return 0
    fi

    # Print summary line
    local rps
    rps=$(grep "Requests/sec:" "$result_file" | awk '{print $2}' || echo "N/A")
    local latency
    latency=$(grep "Latency " "$result_file" | awk '{print $2}' || echo "N/A")
    if [[ -z "$rps" ]]; then
        log_warn "No results for ${label} (connection error?)"
    else
        echo -e "    ${GREEN}→ ${rps} req/s, ${latency} avg latency${NC}"
    fi
}

run_wrk_key_auth() {
    local gateway="$1"
    local port="$2"
    local label="${gateway}/key_auth/api/users-auth"
    local safe_endpoint="api_users"
    local result_file="${RESULTS_DIR}/${gateway}_key_auth_${safe_endpoint}_results.txt"
    local url="http://127.0.0.1:${port}/api/users-auth"

    echo -e "    ${CYAN}Testing ${label}${NC}  →  ${url}"

    # Warm-up (results discarded)
    wrk -t2 -c20 -d"$WARMUP_DURATION" -s "$LUA_SCRIPT_KEY_AUTH" "$url" > /dev/null 2>&1 || true

    # Measured run
    if ! wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"$WRK_DURATION" \
        --latency -s "$LUA_SCRIPT_KEY_AUTH" "$url" > "$result_file" 2>&1; then
        log_warn "wrk failed for ${label} — see ${result_file}"
        return 0
    fi

    # Print summary line
    local rps
    rps=$(grep "Requests/sec:" "$result_file" | awk '{print $2}' || echo "N/A")
    local latency
    latency=$(grep "Latency " "$result_file" | awk '{print $2}' || echo "N/A")
    if [[ -z "$rps" ]]; then
        log_warn "No results for ${label} (connection error?)"
    else
        echo -e "    ${GREEN}→ ${rps} req/s, ${latency} avg latency${NC}"
    fi
}

# ===========================================================================
# Ferrum Gateway
# ===========================================================================

start_ferrum_http() {
    log_info "Starting Ferrum Gateway (HTTP) on port $GATEWAY_HTTP_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    cd "$PROJECT_ROOT"
    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$COMP_DIR/configs/ferrum_comparison.yaml" \
    FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_ENABLE_HTTP2=false \
    FERRUM_LOG_LEVEL=warn \
    ./target/release/ferrum-gateway > "$RESULTS_DIR/ferrum_http.log" 2>&1 &
    FERRUM_PID=$!
    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Ferrum (HTTP)"
}

start_ferrum_https() {
    log_info "Starting Ferrum Gateway (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    cd "$PROJECT_ROOT"
    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$COMP_DIR/configs/ferrum_comparison.yaml" \
    FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    FERRUM_PROXY_HTTPS_PORT="$GATEWAY_HTTPS_PORT" \
    FERRUM_PROXY_TLS_CERT_PATH="$CERTS_DIR/server.crt" \
    FERRUM_PROXY_TLS_KEY_PATH="$CERTS_DIR/server.key" \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_ENABLE_HTTP2=false \
    FERRUM_LOG_LEVEL=warn \
    ./target/release/ferrum-gateway > "$RESULTS_DIR/ferrum_https.log" 2>&1 &
    FERRUM_PID=$!
    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Ferrum (HTTPS)" 15
}

stop_ferrum() {
    if [[ -n "$FERRUM_PID" ]]; then
        kill "$FERRUM_PID" 2>/dev/null || true
        wait "$FERRUM_PID" 2>/dev/null || true
        FERRUM_PID=""
    fi
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

start_ferrum_e2e_tls() {
    log_info "Starting Ferrum Gateway (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    cd "$PROJECT_ROOT"
    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$COMP_DIR/configs/ferrum_comparison_e2e_tls.yaml" \
    FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    FERRUM_PROXY_HTTPS_PORT="$GATEWAY_HTTPS_PORT" \
    FERRUM_PROXY_TLS_CERT_PATH="$CERTS_DIR/server.crt" \
    FERRUM_PROXY_TLS_KEY_PATH="$CERTS_DIR/server.key" \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_ENABLE_HTTP2=false \
    FERRUM_LOG_LEVEL=warn \
    ./target/release/ferrum-gateway > "$RESULTS_DIR/ferrum_e2e_tls.log" 2>&1 &
    FERRUM_PID=$!
    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Ferrum (E2E TLS)" 15
}

test_ferrum() {
    log_header "Testing Ferrum Gateway"

    # HTTP tests
    start_ferrum_http
    run_wrk "ferrum" "http" "/health" "$GATEWAY_HTTP_PORT"
    run_wrk "ferrum" "http" "/api/users" "$GATEWAY_HTTP_PORT"
    stop_ferrum

    # HTTPS tests (TLS termination — plaintext backend)
    start_ferrum_https
    run_wrk "ferrum" "https" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "ferrum" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_ferrum

    # E2E TLS tests (TLS on both sides)
    start_ferrum_e2e_tls
    run_wrk "ferrum" "e2e_tls" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "ferrum" "e2e_tls" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_ferrum
}

# ===========================================================================
# Pingora (Cloudflare) — native Rust proxy framework
# ===========================================================================

start_pingora_http() {
    log_info "Starting Pingora bench proxy (HTTP) on port $GATEWAY_HTTP_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    PINGORA_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    PINGORA_BACKEND_HOST=127.0.0.1 \
    PINGORA_BACKEND_PORT="$BACKEND_PORT" \
    "$PINGORA_BINARY" > "$RESULTS_DIR/pingora_http.log" 2>&1 &
    PINGORA_PID=$!
    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Pingora (HTTP)"
}

start_pingora_https() {
    log_info "Starting Pingora bench proxy (HTTPS) on ports $GATEWAY_HTTP_PORT + $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    PINGORA_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    PINGORA_HTTPS_PORT="$GATEWAY_HTTPS_PORT" \
    PINGORA_BACKEND_HOST=127.0.0.1 \
    PINGORA_BACKEND_PORT="$BACKEND_PORT" \
    PINGORA_TLS_CERT="$CERTS_DIR/server.crt" \
    PINGORA_TLS_KEY="$CERTS_DIR/server.key" \
    "$PINGORA_BINARY" > "$RESULTS_DIR/pingora_https.log" 2>&1 &
    PINGORA_PID=$!
    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Pingora (HTTPS)" 15
}

start_pingora_e2e_tls() {
    log_info "Starting Pingora bench proxy (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    PINGORA_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    PINGORA_HTTPS_PORT="$GATEWAY_HTTPS_PORT" \
    PINGORA_BACKEND_HOST=127.0.0.1 \
    PINGORA_BACKEND_PORT="$BACKEND_HTTPS_PORT" \
    PINGORA_BACKEND_TLS=true \
    PINGORA_TLS_CERT="$CERTS_DIR/server.crt" \
    PINGORA_TLS_KEY="$CERTS_DIR/server.key" \
    "$PINGORA_BINARY" > "$RESULTS_DIR/pingora_e2e_tls.log" 2>&1 &
    PINGORA_PID=$!
    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Pingora (E2E TLS)" 15
}

stop_pingora() {
    if [[ -n "$PINGORA_PID" ]]; then
        kill "$PINGORA_PID" 2>/dev/null || true
        wait "$PINGORA_PID" 2>/dev/null || true
        PINGORA_PID=""
    fi
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_pingora() {
    if [[ ! -f "$PINGORA_BINARY" ]]; then
        log_warn "Pingora bench proxy not built — skipping Pingora tests"
        return
    fi

    log_header "Testing Pingora (Cloudflare)"

    # HTTP tests
    start_pingora_http
    run_wrk "pingora" "http" "/health" "$GATEWAY_HTTP_PORT"
    run_wrk "pingora" "http" "/api/users" "$GATEWAY_HTTP_PORT"
    stop_pingora

    # HTTPS tests (TLS termination — plaintext backend)
    start_pingora_https
    run_wrk "pingora" "https" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "pingora" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_pingora

    # E2E TLS tests (TLS on both sides)
    # Pingora's TLS library requires a valid domain (not IP) for upstream SNI,
    # so E2E TLS to 127.0.0.1 may fail. Skip gracefully if it does.
    if start_pingora_e2e_tls; then
        run_wrk "pingora" "e2e_tls" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "pingora" "e2e_tls" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_pingora
    else
        log_warn "Pingora E2E TLS failed to start — skipping (known IP-based SNI limitation)"
        stop_pingora
    fi
}

# ===========================================================================
# Kong Gateway
# ===========================================================================

prepare_kong_config() {
    # For Docker: replace BACKEND_HOST placeholder
    # For native: always use 127.0.0.1 (backend is on localhost)
    local host
    if [[ "$KONG_NATIVE" == "true" ]]; then
        host="127.0.0.1"
    else
        host="$BACKEND_HOST"
    fi
    sed "s/BACKEND_HOST/$host/g" \
        "$COMP_DIR/configs/kong.yaml" > "$COMP_DIR/configs/.kong_runtime.yaml"
    sed "s/BACKEND_HOST/$host/g" \
        "$COMP_DIR/configs/kong_e2e_tls.yaml" > "$COMP_DIR/configs/.kong_runtime_e2e_tls.yaml"
}

# --- Kong Native ---

start_kong_native_http() {
    log_info "Starting Kong Gateway native (HTTP) on port $GATEWAY_HTTP_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"

    KONG_DATABASE=off \
    KONG_DECLARATIVE_CONFIG="$COMP_DIR/configs/.kong_runtime.yaml" \
    KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT" \
    KONG_ADMIN_LISTEN="off" \
    KONG_PROXY_ACCESS_LOG=/dev/null \
    KONG_PROXY_ERROR_LOG=/dev/stderr \
    KONG_LOG_LEVEL=warn \
    KONG_PREFIX="/tmp/kong-bench" \
    KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
    kong start > "$RESULTS_DIR/kong_http.log" 2>&1

    KONG_PID="native"
    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Kong native (HTTP)" 20
}

start_kong_native_https() {
    log_info "Starting Kong Gateway native (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    KONG_DATABASE=off \
    KONG_DECLARATIVE_CONFIG="$COMP_DIR/configs/.kong_runtime.yaml" \
    KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT, 0.0.0.0:$GATEWAY_HTTPS_PORT ssl" \
    KONG_SSL_CERT="$CERTS_DIR/server.crt" \
    KONG_SSL_CERT_KEY="$CERTS_DIR/server.key" \
    KONG_ADMIN_LISTEN="off" \
    KONG_PROXY_ACCESS_LOG=/dev/null \
    KONG_PROXY_ERROR_LOG=/dev/stderr \
    KONG_LOG_LEVEL=warn \
    KONG_PREFIX="/tmp/kong-bench" \
    KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
    kong start > "$RESULTS_DIR/kong_https.log" 2>&1

    KONG_PID="native"
    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Kong native (HTTPS)" 20
}

start_kong_native_e2e_tls() {
    log_info "Starting Kong Gateway native (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    KONG_DATABASE=off \
    KONG_DECLARATIVE_CONFIG="$COMP_DIR/configs/.kong_runtime_e2e_tls.yaml" \
    KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT, 0.0.0.0:$GATEWAY_HTTPS_PORT ssl" \
    KONG_SSL_CERT="$CERTS_DIR/server.crt" \
    KONG_SSL_CERT_KEY="$CERTS_DIR/server.key" \
    KONG_ADMIN_LISTEN="off" \
    KONG_PROXY_ACCESS_LOG=/dev/null \
    KONG_PROXY_ERROR_LOG=/dev/stderr \
    KONG_LOG_LEVEL=warn \
    KONG_PREFIX="/tmp/kong-bench" \
    KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
    kong start > "$RESULTS_DIR/kong_e2e_tls.log" 2>&1

    KONG_PID="native"
    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Kong native (E2E TLS)" 20
}

stop_kong_native() {
    KONG_PREFIX="/tmp/kong-bench" kong stop 2>/dev/null || true
    KONG_PID=""
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

# --- Kong Docker ---

start_kong_docker_http() {
    log_info "Starting Kong Gateway Docker (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT")
    fi

    docker run -d --name "$KONG_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.kong_runtime.yaml:/etc/kong/kong.yml:ro" \
        -e KONG_DATABASE=off \
        -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
        -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT" \
        -e KONG_ADMIN_LISTEN="off" \
        -e KONG_PROXY_ACCESS_LOG=/dev/null \
        -e KONG_PROXY_ERROR_LOG=/dev/stderr \
        -e KONG_LOG_LEVEL=warn \
        -e KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
        "kong/kong-gateway:${KONG_VERSION}" > /dev/null

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Kong Docker (HTTP)" 20
}

start_kong_docker_https() {
    log_info "Starting Kong Gateway Docker (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT" -p "$GATEWAY_HTTPS_PORT:$GATEWAY_HTTPS_PORT")
    fi

    docker run -d --name "$KONG_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.kong_runtime.yaml:/etc/kong/kong.yml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/kong/ssl/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/kong/ssl/server.key:ro" \
        -e KONG_DATABASE=off \
        -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
        -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT, 0.0.0.0:$GATEWAY_HTTPS_PORT ssl" \
        -e KONG_SSL_CERT=/etc/kong/ssl/server.crt \
        -e KONG_SSL_CERT_KEY=/etc/kong/ssl/server.key \
        -e KONG_ADMIN_LISTEN="off" \
        -e KONG_PROXY_ACCESS_LOG=/dev/null \
        -e KONG_PROXY_ERROR_LOG=/dev/stderr \
        -e KONG_LOG_LEVEL=warn \
        -e KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
        "kong/kong-gateway:${KONG_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Kong Docker (HTTPS)" 20
}

start_kong_docker_e2e_tls() {
    log_info "Starting Kong Gateway Docker (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT" -p "$GATEWAY_HTTPS_PORT:$GATEWAY_HTTPS_PORT")
    fi

    docker run -d --name "$KONG_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.kong_runtime_e2e_tls.yaml:/etc/kong/kong.yml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/kong/ssl/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/kong/ssl/server.key:ro" \
        -e KONG_DATABASE=off \
        -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
        -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT, 0.0.0.0:$GATEWAY_HTTPS_PORT ssl" \
        -e KONG_SSL_CERT=/etc/kong/ssl/server.crt \
        -e KONG_SSL_CERT_KEY=/etc/kong/ssl/server.key \
        -e KONG_ADMIN_LISTEN="off" \
        -e KONG_PROXY_ACCESS_LOG=/dev/null \
        -e KONG_PROXY_ERROR_LOG=/dev/stderr \
        -e KONG_LOG_LEVEL=warn \
        -e KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
        "kong/kong-gateway:${KONG_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Kong Docker (E2E TLS)" 20
}

stop_kong_docker() {
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

# --- Kong dispatch ---

stop_kong() {
    if [[ "$KONG_NATIVE" == "true" ]]; then
        stop_kong_native
    else
        stop_kong_docker
    fi
}

test_kong() {
    if [[ "$KONG_NATIVE" == "true" ]]; then
        log_header "Testing Kong Gateway (native, $(kong version 2>/dev/null || echo 'unknown'))"
    else
        log_header "Testing Kong Gateway (Docker ${KONG_VERSION})"
    fi

    prepare_kong_config

    if [[ "$KONG_NATIVE" == "true" ]]; then
        # HTTP tests
        start_kong_native_http
        run_wrk "kong" "http" "/health" "$GATEWAY_HTTP_PORT"
        run_wrk "kong" "http" "/api/users" "$GATEWAY_HTTP_PORT"
        stop_kong_native

        # HTTPS tests (TLS termination — plaintext backend)
        start_kong_native_https
        run_wrk "kong" "https" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "kong" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_kong_native

        # E2E TLS tests (TLS on both sides)
        start_kong_native_e2e_tls
        run_wrk "kong" "e2e_tls" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "kong" "e2e_tls" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_kong_native
    else
        # HTTP tests
        start_kong_docker_http
        run_wrk "kong" "http" "/health" "$GATEWAY_HTTP_PORT"
        run_wrk "kong" "http" "/api/users" "$GATEWAY_HTTP_PORT"
        stop_kong_docker

        # HTTPS tests (TLS termination — plaintext backend)
        start_kong_docker_https
        run_wrk "kong" "https" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "kong" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_kong_docker

        # E2E TLS tests (TLS on both sides)
        start_kong_docker_e2e_tls
        run_wrk "kong" "e2e_tls" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "kong" "e2e_tls" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_kong_docker
    fi
}

# ===========================================================================
# Tyk Gateway
# ===========================================================================

prepare_tyk_config() {
    # Replace BACKEND_HOST placeholder in Tyk API definitions (HTTP/HTTPS termination)
    mkdir -p "$COMP_DIR/configs/.tyk_runtime_apps"
    for f in "$COMP_DIR/configs/tyk/apps"/*.json; do
        sed "s/BACKEND_HOST/$BACKEND_HOST/g" "$f" > "$COMP_DIR/configs/.tyk_runtime_apps/$(basename "$f")"
    done

    # E2E TLS app definitions (HTTPS backend on port 3443)
    mkdir -p "$COMP_DIR/configs/.tyk_runtime_apps_e2e_tls"
    for f in "$COMP_DIR/configs/tyk/apps_e2e_tls"/*.json; do
        sed "s/BACKEND_HOST/$BACKEND_HOST/g" "$f" > "$COMP_DIR/configs/.tyk_runtime_apps_e2e_tls/$(basename "$f")"
    done

    # On macOS (no --network host), Tyk and Redis share a Docker network.
    # Tyk must connect to Redis by container name instead of 127.0.0.1.
    if [[ "$DOCKER_USE_HOST_NETWORK" != "true" ]]; then
        local redis_host="$REDIS_CONTAINER"
        mkdir -p "$COMP_DIR/configs/.tyk_runtime"
        sed "s/127.0.0.1/$redis_host/g" \
            "$COMP_DIR/configs/tyk/tyk.conf" > "$COMP_DIR/configs/.tyk_runtime/tyk.conf"
        sed "s/127.0.0.1/$redis_host/g" \
            "$COMP_DIR/configs/tyk/tyk_tls.conf" > "$COMP_DIR/configs/.tyk_runtime/tyk_tls.conf"
        TYK_CONF_DIR="$COMP_DIR/configs/.tyk_runtime"
    else
        TYK_CONF_DIR="$COMP_DIR/configs/tyk"
    fi
}

TYK_NETWORK="ferrum-bench-net"

start_redis() {
    log_info "Starting Redis for Tyk..."
    docker rm -f "$REDIS_CONTAINER" 2>/dev/null || true

    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        docker run -d --name "$REDIS_CONTAINER" \
            --network host \
            redis:7-alpine > /dev/null
    else
        docker network create "$TYK_NETWORK" 2>/dev/null || true
        docker run -d --name "$REDIS_CONTAINER" \
            --network "$TYK_NETWORK" \
            redis:7-alpine > /dev/null
    fi
    sleep 2
    log_ok "Redis started"
}

stop_redis() {
    docker rm -f "$REDIS_CONTAINER" 2>/dev/null || true
}

start_tyk_http() {
    log_info "Starting Tyk Gateway (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(--network "$TYK_NETWORK" -p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT")
    fi

    docker run -d --name "$TYK_CONTAINER" \
        "${network_args[@]}" \
        -v "$TYK_CONF_DIR/tyk.conf:/opt/tyk-gateway/tyk.conf:ro" \
        -v "$COMP_DIR/configs/.tyk_runtime_apps:/etc/tyk/apps:ro" \
        "tykio/tyk-gateway:${TYK_VERSION}" > /dev/null

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/hello" "Tyk (HTTP)" 20
}

start_tyk_https() {
    log_info "Starting Tyk Gateway (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(--network "$TYK_NETWORK" -p "$GATEWAY_HTTPS_PORT:$GATEWAY_HTTPS_PORT")
    fi

    docker run -d --name "$TYK_CONTAINER" \
        "${network_args[@]}" \
        -v "$TYK_CONF_DIR/tyk_tls.conf:/opt/tyk-gateway/tyk.conf:ro" \
        -v "$COMP_DIR/configs/.tyk_runtime_apps:/etc/tyk/apps:ro" \
        -v "$CERTS_DIR/server.crt:/etc/tyk/certs/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/tyk/certs/server.key:ro" \
        "tykio/tyk-gateway:${TYK_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/hello" "Tyk (HTTPS)" 20
}

start_tyk_e2e_tls() {
    log_info "Starting Tyk Gateway (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(--network "$TYK_NETWORK" -p "$GATEWAY_HTTPS_PORT:$GATEWAY_HTTPS_PORT")
    fi

    docker run -d --name "$TYK_CONTAINER" \
        "${network_args[@]}" \
        -v "$TYK_CONF_DIR/tyk_tls.conf:/opt/tyk-gateway/tyk.conf:ro" \
        -v "$COMP_DIR/configs/.tyk_runtime_apps_e2e_tls:/etc/tyk/apps:ro" \
        -v "$CERTS_DIR/server.crt:/etc/tyk/certs/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/tyk/certs/server.key:ro" \
        "tykio/tyk-gateway:${TYK_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/hello" "Tyk (E2E TLS)" 20
}

stop_tyk() {
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_tyk() {
    log_header "Testing Tyk Gateway (${TYK_VERSION})"

    prepare_tyk_config
    start_redis

    # HTTP tests
    start_tyk_http
    run_wrk "tyk" "http" "/health" "$GATEWAY_HTTP_PORT"
    run_wrk "tyk" "http" "/api/users" "$GATEWAY_HTTP_PORT"
    stop_tyk

    # HTTPS tests (TLS termination — plaintext backend)
    start_tyk_https
    run_wrk "tyk" "https" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "tyk" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_tyk

    # E2E TLS tests (TLS on both sides)
    start_tyk_e2e_tls
    run_wrk "tyk" "e2e_tls" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "tyk" "e2e_tls" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_tyk
    stop_redis
}

# ===========================================================================
# KrakenD Gateway
# ===========================================================================

prepare_krakend_config() {
    # Replace BACKEND_HOST placeholder in KrakenD config files
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/krakend/krakend_http.json" > "$COMP_DIR/configs/.krakend_runtime_http.json"
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/krakend/krakend_https.json" > "$COMP_DIR/configs/.krakend_runtime_https.json"
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/krakend/krakend_e2e_tls.json" > "$COMP_DIR/configs/.krakend_runtime_e2e_tls.json"
}

start_krakend_http() {
    log_info "Starting KrakenD Gateway (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$KRAKEND_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT")
    fi

    docker run -d --name "$KRAKEND_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.krakend_runtime_http.json:/etc/krakend/krakend.json:ro" \
        "krakend:${KRAKEND_VERSION}" \
        run -c /etc/krakend/krakend.json > /dev/null

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "KrakenD (HTTP)" 20
}

start_krakend_https() {
    log_info "Starting KrakenD Gateway (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KRAKEND_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTPS_PORT:$GATEWAY_HTTPS_PORT")
    fi

    docker run -d --name "$KRAKEND_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.krakend_runtime_https.json:/etc/krakend/krakend.json:ro" \
        -v "$CERTS_DIR/server.crt:/etc/krakend/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/krakend/tls/server.key:ro" \
        "krakend:${KRAKEND_VERSION}" \
        run -c /etc/krakend/krakend.json > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "KrakenD (HTTPS)" 20
}

start_krakend_e2e_tls() {
    log_info "Starting KrakenD Gateway (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KRAKEND_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTPS_PORT:$GATEWAY_HTTPS_PORT")
    fi

    docker run -d --name "$KRAKEND_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.krakend_runtime_e2e_tls.json:/etc/krakend/krakend.json:ro" \
        -v "$CERTS_DIR/server.crt:/etc/krakend/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/krakend/tls/server.key:ro" \
        "krakend:${KRAKEND_VERSION}" \
        run -c /etc/krakend/krakend.json > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "KrakenD (E2E TLS)" 20
}

stop_krakend() {
    docker rm -f "$KRAKEND_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_krakend() {
    log_header "Testing KrakenD Gateway (${KRAKEND_VERSION})"

    prepare_krakend_config

    # HTTP tests
    start_krakend_http
    run_wrk "krakend" "http" "/health" "$GATEWAY_HTTP_PORT"
    run_wrk "krakend" "http" "/api/users" "$GATEWAY_HTTP_PORT"
    stop_krakend

    # HTTPS tests (TLS termination — plaintext backend)
    start_krakend_https
    run_wrk "krakend" "https" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "krakend" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_krakend

    # E2E TLS tests (TLS on both sides)
    start_krakend_e2e_tls
    run_wrk "krakend" "e2e_tls" "/health" "$GATEWAY_HTTPS_PORT"
    run_wrk "krakend" "e2e_tls" "/api/users" "$GATEWAY_HTTPS_PORT"
    stop_krakend
}

# ===========================================================================
# Envoy Proxy
# ===========================================================================

prepare_envoy_config() {
    # For Docker: replace BACKEND_HOST placeholder
    # For native: always use 127.0.0.1 (backend is on localhost)
    local host
    if [[ "$ENVOY_NATIVE" == "true" ]]; then
        host="127.0.0.1"
    else
        host="$BACKEND_HOST"
    fi
    sed "s/BACKEND_HOST/$host/g" \
        "$COMP_DIR/configs/envoy/envoy_http.yaml" > "$COMP_DIR/configs/.envoy_runtime_http.yaml"
    sed "s/BACKEND_HOST/$host/g" \
        "$COMP_DIR/configs/envoy/envoy_key_auth.yaml" > "$COMP_DIR/configs/.envoy_runtime_key_auth.yaml"
    # For native: rewrite TLS cert paths to local filesystem
    if [[ "$ENVOY_NATIVE" == "true" ]]; then
        sed "s/BACKEND_HOST/$host/g; s|/etc/envoy/tls/server.crt|$CERTS_DIR/server.crt|g; s|/etc/envoy/tls/server.key|$CERTS_DIR/server.key|g" \
            "$COMP_DIR/configs/envoy/envoy_https.yaml" > "$COMP_DIR/configs/.envoy_runtime_https.yaml"
        sed "s/BACKEND_HOST/$host/g; s|/etc/envoy/tls/server.crt|$CERTS_DIR/server.crt|g; s|/etc/envoy/tls/server.key|$CERTS_DIR/server.key|g" \
            "$COMP_DIR/configs/envoy/envoy_e2e_tls.yaml" > "$COMP_DIR/configs/.envoy_runtime_e2e_tls.yaml"
    else
        sed "s/BACKEND_HOST/$host/g" \
            "$COMP_DIR/configs/envoy/envoy_https.yaml" > "$COMP_DIR/configs/.envoy_runtime_https.yaml"
        sed "s/BACKEND_HOST/$host/g" \
            "$COMP_DIR/configs/envoy/envoy_e2e_tls.yaml" > "$COMP_DIR/configs/.envoy_runtime_e2e_tls.yaml"
    fi
}

# --- Envoy Native ---

ENVOY_NATIVE_PID=""

start_envoy_native_http() {
    log_info "Starting Envoy Proxy native (HTTP) on port $GATEWAY_HTTP_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port 9901  # Envoy admin port

    envoy -c "$COMP_DIR/configs/.envoy_runtime_http.yaml" --log-level warning \
        > "$RESULTS_DIR/envoy_http.log" 2>&1 &
    ENVOY_NATIVE_PID=$!

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Envoy native (HTTP)" 20
}

start_envoy_native_https() {
    log_info "Starting Envoy Proxy native (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    kill_port 9901

    envoy -c "$COMP_DIR/configs/.envoy_runtime_https.yaml" --log-level warning \
        > "$RESULTS_DIR/envoy_https.log" 2>&1 &
    ENVOY_NATIVE_PID=$!

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Envoy native (HTTPS)" 20
}

start_envoy_native_e2e_tls() {
    log_info "Starting Envoy Proxy native (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    kill_port 9901

    envoy -c "$COMP_DIR/configs/.envoy_runtime_e2e_tls.yaml" --log-level warning \
        > "$RESULTS_DIR/envoy_e2e_tls.log" 2>&1 &
    ENVOY_NATIVE_PID=$!

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Envoy native (E2E TLS)" 20
}

stop_envoy_native() {
    if [[ -n "$ENVOY_NATIVE_PID" ]]; then
        kill "$ENVOY_NATIVE_PID" 2>/dev/null || true
        ENVOY_NATIVE_PID=""
    fi
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    kill_port 9901
    sleep 1
}

# --- Envoy Docker ---

start_envoy_docker_http() {
    log_info "Starting Envoy Proxy Docker (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT")
    fi

    docker run -d --name "$ENVOY_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.envoy_runtime_http.yaml:/etc/envoy/envoy.yaml:ro" \
        "envoyproxy/envoy:v${ENVOY_VERSION}" > /dev/null

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Envoy Docker (HTTP)" 20
}

start_envoy_docker_https() {
    log_info "Starting Envoy Proxy Docker (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTPS_PORT:$GATEWAY_HTTPS_PORT")
    fi

    docker run -d --name "$ENVOY_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.envoy_runtime_https.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/envoy/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/envoy/tls/server.key:ro" \
        "envoyproxy/envoy:v${ENVOY_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Envoy Docker (HTTPS)" 20
}

start_envoy_docker_e2e_tls() {
    log_info "Starting Envoy Proxy Docker (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(-p "$GATEWAY_HTTPS_PORT:$GATEWAY_HTTPS_PORT")
    fi

    docker run -d --name "$ENVOY_CONTAINER" \
        "${network_args[@]}" \
        -v "$COMP_DIR/configs/.envoy_runtime_e2e_tls.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/envoy/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/envoy/tls/server.key:ro" \
        "envoyproxy/envoy:v${ENVOY_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Envoy Docker (E2E TLS)" 20
}

stop_envoy_docker() {
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

# --- Envoy dispatch ---

stop_envoy() {
    if [[ "$ENVOY_NATIVE" == "true" ]]; then
        stop_envoy_native
    else
        stop_envoy_docker
    fi
}

test_envoy() {
    if [[ "$ENVOY_NATIVE" == "true" ]]; then
        log_header "Testing Envoy Proxy (native, $(envoy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'unknown'))"
    else
        log_header "Testing Envoy Proxy (Docker ${ENVOY_VERSION})"
    fi

    prepare_envoy_config

    if [[ "$ENVOY_NATIVE" == "true" ]]; then
        # HTTP tests
        start_envoy_native_http
        run_wrk "envoy" "http" "/health" "$GATEWAY_HTTP_PORT"
        run_wrk "envoy" "http" "/api/users" "$GATEWAY_HTTP_PORT"
        stop_envoy_native

        # HTTPS tests (TLS termination — plaintext backend)
        start_envoy_native_https
        run_wrk "envoy" "https" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "envoy" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_envoy_native

        # E2E TLS tests (TLS on both sides)
        start_envoy_native_e2e_tls
        run_wrk "envoy" "e2e_tls" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "envoy" "e2e_tls" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_envoy_native
    else
        # HTTP tests
        start_envoy_docker_http
        run_wrk "envoy" "http" "/health" "$GATEWAY_HTTP_PORT"
        run_wrk "envoy" "http" "/api/users" "$GATEWAY_HTTP_PORT"
        stop_envoy_docker

        # HTTPS tests (TLS termination — plaintext backend)
        start_envoy_docker_https
        run_wrk "envoy" "https" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "envoy" "https" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_envoy_docker

        # E2E TLS tests (TLS on both sides)
        start_envoy_docker_e2e_tls
        run_wrk "envoy" "e2e_tls" "/health" "$GATEWAY_HTTPS_PORT"
        run_wrk "envoy" "e2e_tls" "/api/users" "$GATEWAY_HTTPS_PORT"
        stop_envoy_docker
    fi
}

# ===========================================================================
# Key-Auth Tests (HTTP only, Ferrum + Kong + Tyk + Envoy)
# Note: KrakenD key-auth requires Enterprise Edition, so it is excluded.
# ===========================================================================

prepare_kong_key_auth_config() {
    local host
    if [[ "$KONG_NATIVE" == "true" ]]; then
        host="127.0.0.1"
    else
        host="$BACKEND_HOST"
    fi
    sed "s/BACKEND_HOST/$host/g" \
        "$COMP_DIR/configs/kong_key_auth.yaml" > "$COMP_DIR/configs/.kong_runtime_key_auth.yaml"
}

prepare_tyk_key_auth_config() {
    mkdir -p "$COMP_DIR/configs/.tyk_runtime_apps_key_auth"
    for f in "$COMP_DIR/configs/tyk/apps_key_auth"/*.json; do
        sed "s/BACKEND_HOST/$BACKEND_HOST/g" "$f" > "$COMP_DIR/configs/.tyk_runtime_apps_key_auth/$(basename "$f")"
    done
}

test_ferrum_key_auth() {
    log_info "Starting Ferrum Gateway (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
    kill_port "$GATEWAY_HTTP_PORT"
    cd "$PROJECT_ROOT"
    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$COMP_DIR/configs/ferrum_comparison_key_auth.yaml" \
    FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_ENABLE_HTTP2=false \
    FERRUM_LOG_LEVEL=warn \
    ./target/release/ferrum-gateway > "$RESULTS_DIR/ferrum_key_auth.log" 2>&1 &
    FERRUM_PID=$!
    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Ferrum (Key Auth)"

    run_wrk_key_auth "ferrum" "$GATEWAY_HTTP_PORT"

    kill "$FERRUM_PID" 2>/dev/null || true
    wait "$FERRUM_PID" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    sleep 1
}

test_kong_key_auth() {
    prepare_kong_key_auth_config

    if [[ "$KONG_NATIVE" == "true" ]]; then
        log_info "Starting Kong Gateway native (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
        kill_port "$GATEWAY_HTTP_PORT"

        KONG_DATABASE=off \
        KONG_DECLARATIVE_CONFIG="$COMP_DIR/configs/.kong_runtime_key_auth.yaml" \
        KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT" \
        KONG_ADMIN_LISTEN="off" \
        KONG_PROXY_ACCESS_LOG=/dev/null \
        KONG_PROXY_ERROR_LOG=/dev/stderr \
        KONG_LOG_LEVEL=warn \
        KONG_PREFIX="/tmp/kong-bench" \
        KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
        kong start > "$RESULTS_DIR/kong_key_auth.log" 2>&1

        wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Kong native (Key Auth)" 20
        run_wrk_key_auth "kong" "$GATEWAY_HTTP_PORT"
        stop_kong_native
    else
        log_info "Starting Kong Gateway Docker (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
        docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
        kill_port "$GATEWAY_HTTP_PORT"

        local network_args=()
        if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
            network_args+=(--network host)
        else
            network_args+=(-p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT")
        fi

        docker run -d --name "$KONG_CONTAINER" \
            "${network_args[@]}" \
            -v "$COMP_DIR/configs/.kong_runtime_key_auth.yaml:/etc/kong/kong.yml:ro" \
            -e KONG_DATABASE=off \
            -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
            -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT" \
            -e KONG_ADMIN_LISTEN="off" \
            -e KONG_PROXY_ACCESS_LOG=/dev/null \
            -e KONG_PROXY_ERROR_LOG=/dev/stderr \
            -e KONG_LOG_LEVEL=warn \
            -e KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
            "kong/kong-gateway:${KONG_VERSION}" > /dev/null

        wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Kong Docker (Key Auth)" 20
        run_wrk_key_auth "kong" "$GATEWAY_HTTP_PORT"
        stop_kong_docker
    fi
}

test_tyk_key_auth() {
    prepare_tyk_key_auth_config

    log_info "Starting Tyk Gateway (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        network_args+=(--network "$TYK_NETWORK" -p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT")
    fi

    docker run -d --name "$TYK_CONTAINER" \
        "${network_args[@]}" \
        -v "$TYK_CONF_DIR/tyk.conf:/opt/tyk-gateway/tyk.conf:ro" \
        -v "$COMP_DIR/configs/.tyk_runtime_apps_key_auth:/etc/tyk/apps:ro" \
        "tykio/tyk-gateway:${TYK_VERSION}" > /dev/null

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/hello" "Tyk (Key Auth)" 20

    # Create an API key for the authenticated endpoint
    log_info "Creating Tyk API key..."
    local tyk_key_resp
    tyk_key_resp=$(curl -sf -X POST "http://127.0.0.1:$GATEWAY_HTTP_PORT/tyk/keys" \
        -H "x-tyk-authorization: benchmark-secret" \
        -H "Content-Type: application/json" \
        -d '{
            "alias": "benchuser",
            "expires": 0,
            "access_rights": {
                "users-auth-api": {
                    "api_id": "users-auth-api",
                    "api_name": "Users Auth API",
                    "versions": ["Default"]
                }
            }
        }' 2>&1) || true

    # Extract the generated key
    local tyk_api_key
    tyk_api_key=$(echo "$tyk_key_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key',''))" 2>/dev/null || echo "")

    if [[ -z "$tyk_api_key" ]]; then
        log_warn "Failed to create Tyk API key — response: $tyk_key_resp"
        log_warn "Skipping Tyk key-auth benchmark"
        stop_tyk
        return 0
    fi
    log_ok "Tyk API key created"

    # Override the lua script key with the Tyk-generated key
    local tyk_lua="$COMP_DIR/lua/.tyk_key_auth_runtime.lua"
    sed "s/test-api-key/$tyk_api_key/g" "$LUA_SCRIPT_KEY_AUTH" > "$tyk_lua"

    # Run wrk with the Tyk-specific key
    local label="tyk/key_auth/api/users-auth"
    local result_file="${RESULTS_DIR}/tyk_key_auth_api_users_results.txt"
    local url="http://127.0.0.1:${GATEWAY_HTTP_PORT}/api/users-auth"

    echo -e "    ${CYAN}Testing ${label}${NC}  →  ${url}"
    wrk -t2 -c20 -d"$WARMUP_DURATION" -s "$tyk_lua" "$url" > /dev/null 2>&1 || true
    if ! wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"$WRK_DURATION" \
        --latency -s "$tyk_lua" "$url" > "$result_file" 2>&1; then
        log_warn "wrk failed for ${label} — see ${result_file}"
    else
        local rps
        rps=$(grep "Requests/sec:" "$result_file" | awk '{print $2}' || echo "N/A")
        local latency
        latency=$(grep "Latency " "$result_file" | awk '{print $2}' || echo "N/A")
        echo -e "    ${GREEN}→ ${rps} req/s, ${latency} avg latency${NC}"
    fi

    stop_tyk
}

test_envoy_key_auth() {
    prepare_envoy_config

    if [[ "$ENVOY_NATIVE" == "true" ]]; then
        log_info "Starting Envoy Proxy native (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
        kill_port "$GATEWAY_HTTP_PORT"
        kill_port 9901

        envoy -c "$COMP_DIR/configs/.envoy_runtime_key_auth.yaml" --log-level warning \
            > "$RESULTS_DIR/envoy_key_auth.log" 2>&1 &
        ENVOY_NATIVE_PID=$!

        wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Envoy native (Key Auth)" 20
        run_wrk_key_auth "envoy" "$GATEWAY_HTTP_PORT"
        stop_envoy_native
    else
        log_info "Starting Envoy Proxy Docker (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
        docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
        kill_port "$GATEWAY_HTTP_PORT"

        local network_args=()
        if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
            network_args+=(--network host)
        else
            network_args+=(-p "$GATEWAY_HTTP_PORT:$GATEWAY_HTTP_PORT")
        fi

        docker run -d --name "$ENVOY_CONTAINER" \
            "${network_args[@]}" \
            -v "$COMP_DIR/configs/.envoy_runtime_key_auth.yaml:/etc/envoy/envoy.yaml:ro" \
            "envoyproxy/envoy:v${ENVOY_VERSION}" > /dev/null

        wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Envoy Docker (Key Auth)" 20
        run_wrk_key_auth "envoy" "$GATEWAY_HTTP_PORT"
        stop_envoy_docker
    fi
}

test_key_auth() {
    log_header "Testing Key-Auth Performance (HTTP)"

    if ! should_skip "ferrum"; then
        test_ferrum_key_auth
    fi

    if ! should_skip "kong"; then
        test_kong_key_auth
    fi

    if ! should_skip "tyk"; then
        # Tyk needs Redis running; start if not already up
        if ! docker ps --filter name="$REDIS_CONTAINER" --format '{{.Names}}' | grep -q "$REDIS_CONTAINER"; then
            prepare_tyk_config
            start_redis
        fi
        test_tyk_key_auth
        stop_redis
    fi

    if ! should_skip "envoy"; then
        test_envoy_key_auth
    fi
}

# ===========================================================================
# Baseline (direct backend)
# ===========================================================================

test_baseline() {
    log_header "Testing Direct Backend (Baseline)"
    run_wrk "baseline" "http" "/health" "$BACKEND_PORT"
    run_wrk "baseline" "http" "/api/users" "$BACKEND_PORT"
    # HTTPS baseline (direct to backend HTTPS port, no gateway)
    run_wrk "baseline" "https" "/health" "$BACKEND_HTTPS_PORT"
    run_wrk "baseline" "https" "/api/users" "$BACKEND_HTTPS_PORT"
}

# ===========================================================================
# Report generation
# ===========================================================================

write_metadata() {
    local kong_info
    if [[ "$KONG_NATIVE" == "true" ]]; then
        kong_info="native ($(kong version 2>/dev/null || echo 'unknown'))"
    else
        kong_info="Docker ${KONG_VERSION}"
    fi

    local envoy_info
    if [[ "$ENVOY_NATIVE" == "true" ]]; then
        envoy_info="native ($(envoy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'unknown'))"
    else
        envoy_info="Docker ${ENVOY_VERSION}"
    fi

    local pingora_info="native (source build)"
    if [[ ! -f "$PINGORA_BINARY" ]]; then
        pingora_info="skipped (not built)"
    fi

    cat > "$RESULTS_DIR/meta.json" <<METAEOF
{
    "duration": "$WRK_DURATION",
    "threads": "$WRK_THREADS",
    "connections": "$WRK_CONNECTIONS",
    "pingora_version": "$pingora_info",
    "kong_version": "$kong_info",
    "tyk_version": "Docker ${TYK_VERSION}",
    "krakend_version": "Docker ${KRAKEND_VERSION}",
    "envoy_version": "$envoy_info",
    "kong_native": $KONG_NATIVE,
    "envoy_native": $ENVOY_NATIVE,
    "os": "$(uname -s) $(uname -r) $(uname -m)",
    "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
METAEOF
}

generate_report() {
    log_header "Generating comparison report"
    write_metadata
    python3 "$COMP_DIR/scripts/generate_comparison_report.py" "$RESULTS_DIR"
    log_ok "Report saved to $RESULTS_DIR/comparison_report.html"
}

# ===========================================================================
# Main
# ===========================================================================

main() {
    echo -e "${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════════════╗"
    echo "  ║              API Gateway Comparison Benchmark Suite              ║"
    echo "  ║   Ferrum vs Pingora vs Kong vs Tyk vs KrakenD vs Envoy          ║"
    echo "  ╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  Duration: ${WRK_DURATION}  Threads: ${WRK_THREADS}  Connections: ${WRK_CONNECTIONS}"
    local kong_label="Docker ${KONG_VERSION}"
    if [[ "$KONG_NATIVE" == "true" ]]; then
        kong_label="native ($(kong version 2>/dev/null || echo '?'))"
    fi
    local envoy_label="Docker ${ENVOY_VERSION}"
    if [[ "$ENVOY_NATIVE" == "true" ]]; then
        envoy_label="native ($(envoy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo '?'))"
    fi
    echo "  Kong: ${kong_label}  Tyk: Docker ${TYK_VERSION}  KrakenD: Docker ${KRAKEND_VERSION}  Envoy: ${envoy_label}"
    if [[ -n "$SKIP_GATEWAYS" ]]; then
        echo -e "  ${YELLOW}Skipping: ${SKIP_GATEWAYS}${NC}"
    fi

    check_dependencies
    pull_images
    build_project

    mkdir -p "$RESULTS_DIR"

    start_backend
    test_baseline

    if ! should_skip "ferrum"; then
        test_ferrum
    fi

    if ! should_skip "pingora"; then
        test_pingora
    fi

    if ! should_skip "kong"; then
        test_kong
    fi

    if ! should_skip "tyk"; then
        test_tyk
    fi

    if ! should_skip "krakend"; then
        test_krakend
    fi

    if ! should_skip "envoy"; then
        test_envoy
    fi

    # Key-Auth tests (HTTP only, Ferrum + Kong + Tyk; KrakenD key-auth requires Enterprise)
    test_key_auth

    generate_report

    echo ""
    log_header "Benchmark Complete"
    echo -e "  ${GREEN}Results: ${RESULTS_DIR}/${NC}"
    echo -e "  ${GREEN}Report:  ${RESULTS_DIR}/comparison_report.html${NC}"
    echo ""
}

main "$@"
