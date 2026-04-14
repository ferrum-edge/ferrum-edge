#!/bin/bash

# ===========================================================================
# API Gateway Comparison Benchmark (All-Docker)
# Ferrum Edge vs Kong vs Tyk vs KrakenD vs Envoy
#
# ALL gateways run inside Docker containers for apples-to-apples comparison.
# The Docker overhead is shared equally across all platforms, eliminating
# the unfair advantage that native binaries had over Docker-gated gateways.
#
# The backend echo server runs natively on the host (it is the shared
# constant — not a gateway being benchmarked).
#
# Usage:
#   ./comparison/run_comparison.sh
#
# Environment variable overrides:
#   WRK_DURATION=30s        Duration of each wrk test run
#   WRK_THREADS=8           wrk thread count
#   WRK_CONNECTIONS=100     wrk concurrent connections
#   KONG_VERSION=3.14       Kong Docker image tag
#   TYK_VERSION=v5.12       Tyk Docker image tag
#   KRAKEND_VERSION=2.13.2  KrakenD Docker image tag
#   ENVOY_VERSION=1.37-latest  Envoy Docker image tag
#   SKIP_GATEWAYS=tyk       Comma-separated gateways to skip (ferrum,kong,tyk,krakend,envoy)
#   WARMUP_DURATION=5s      Warm-up duration before measured test
#   SKIP_BUILD=false        Skip Docker image builds (use cached images)
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
KONG_VERSION=${KONG_VERSION:-3.14}
TYK_VERSION=${TYK_VERSION:-v5.12}
KRAKEND_VERSION=${KRAKEND_VERSION:-2.13.2}
ENVOY_VERSION=${ENVOY_VERSION:-1.37-latest}
SKIP_GATEWAYS=${SKIP_GATEWAYS:-}
SKIP_BUILD=${SKIP_BUILD:-false}

RESULTS_DIR="$COMP_DIR/results"
CERTS_DIR="$PROJECT_ROOT/tests/certs"
PERF_DIR="$PROJECT_ROOT/tests/performance"
LUA_SCRIPT_POST="$COMP_DIR/lua/comparison_test_post.lua"
LUA_SCRIPT_POST_KEY_AUTH="$COMP_DIR/lua/comparison_test_post_key_auth.lua"

# Docker container names (prefixed for easy cleanup)
FERRUM_CONTAINER="ferrum-bench-ferrum"
KONG_CONTAINER="ferrum-bench-kong"
TYK_CONTAINER="ferrum-bench-tyk"
KRAKEND_CONTAINER="ferrum-bench-krakend"
ENVOY_CONTAINER="ferrum-bench-envoy"
REDIS_CONTAINER="ferrum-bench-redis"

# Docker image names for locally-built images
FERRUM_IMAGE="ferrum-bench:local"

# PIDs to track (backend only — gateways are Docker containers)
BACKEND_PID=""

# Detect platform for Docker networking
# macOS Docker Desktop does not support --network host; use port mapping instead
if [[ "$(uname -s)" == "Darwin" ]]; then
    BACKEND_HOST="host.docker.internal"
    DOCKER_USE_HOST_NETWORK=false
else
    BACKEND_HOST="127.0.0.1"
    DOCKER_USE_HOST_NETWORK=true
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
    local container="${4:-}"
    for i in $(seq 1 "$max_retries"); do
        if curl -skf "$url" > /dev/null 2>&1; then
            log_ok "$label is ready"
            return 0
        fi
        sleep 1
    done
    log_err "$label failed to start after ${max_retries}s"
    if [[ -n "$container" ]]; then
        echo -e "${YELLOW}  ── docker logs ($container) ──${NC}"
        docker logs --tail 40 "$container" 2>&1 | sed 's/^/    /' || true
        echo -e "${YELLOW}  ── end docker logs ──${NC}"
    fi
    return 1
}

kill_port() {
    lsof -ti:"$1" 2>/dev/null | xargs kill -9 2>/dev/null || true
}

# Docker run helper — handles network mode per platform
docker_run_gateway() {
    local container_name="$1"
    shift
    local ports=()
    local extra_args=()

    # Parse port arguments (before --)
    while [[ "$1" != "--" ]]; do
        ports+=("$1")
        shift
    done
    shift  # consume --

    # Remaining args are the docker run arguments
    extra_args=("$@")

    local network_args=()
    if [[ "$DOCKER_USE_HOST_NETWORK" == "true" ]]; then
        network_args+=(--network host)
    else
        for p in "${ports[@]}"; do
            network_args+=(-p "$p:$p")
        done
    fi

    docker run -d --name "$container_name" \
        "${network_args[@]}" \
        "${extra_args[@]}" > /dev/null
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

    # Remove all Docker containers
    for c in "$FERRUM_CONTAINER" "$KONG_CONTAINER" \
             "$TYK_CONTAINER" "$KRAKEND_CONTAINER" "$ENVOY_CONTAINER" "$REDIS_CONTAINER"; do
        docker rm -f "$c" 2>/dev/null || true
    done

    # Clean up Docker network and temporary config files
    docker network rm "$TYK_NETWORK" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.ferrum_runtime"*.yaml 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.kong_runtime"*.yaml 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.kong_runtime_key_auth.yaml" 2>/dev/null || true
    rm -rf "$COMP_DIR/configs/.tyk_runtime_apps" 2>/dev/null || true
    rm -rf "$COMP_DIR/configs/.tyk_runtime_apps_e2e_tls" 2>/dev/null || true
    rm -rf "$COMP_DIR/configs/.tyk_runtime_apps_key_auth" 2>/dev/null || true
    rm -rf "$COMP_DIR/configs/.tyk_runtime" 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.krakend_runtime"*.json 2>/dev/null || true
    rm -f "$COMP_DIR/configs/.envoy_runtime"*.yaml 2>/dev/null || true
    rm -f "$COMP_DIR/lua/.tyk_key_auth_runtime.lua" 2>/dev/null || true

    kill_port "$BACKEND_PORT"
    kill_port "$BACKEND_HTTPS_PORT"
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
}

trap cleanup EXIT

# ===========================================================================
# Dependency checks
# ===========================================================================

check_dependencies() {
    log_header "Checking dependencies"

    local missing=0
    local required_cmds=(wrk python3 cargo curl docker)

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

    # Check Docker daemon is running
    if ! docker info &>/dev/null; then
        log_err "Docker daemon is not running. Start Docker and try again."
        exit 1
    fi
    log_ok "Docker daemon"
}

# ===========================================================================
# Docker image pull + local builds
# ===========================================================================

pull_images() {
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

    if ! should_skip "envoy"; then
        log_info "Pulling envoyproxy/envoy:v${ENVOY_VERSION}..."
        docker pull "envoyproxy/envoy:v${ENVOY_VERSION}" --quiet || {
            log_warn "Failed to pull Envoy image. Will try to use cached version."
        }
    fi
}

build_images() {
    log_header "Building Docker images"

    # Build backend server (runs natively — shared constant)
    log_info "Building backend server (release)..."
    cd "$PERF_DIR"
    cargo build --release --bin backend_server 2>&1 | tail -1
    log_ok "Backend server built"

    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "SKIP_BUILD=true — using cached Docker images"
        return
    fi

    if ! should_skip "ferrum"; then
        log_info "Building Ferrum Edge Docker image..."
        docker build -t "$FERRUM_IMAGE" -f "$PROJECT_ROOT/Dockerfile" "$PROJECT_ROOT" 2>&1 | tail -5
        log_ok "Ferrum image built: $FERRUM_IMAGE"
    fi

}

# ===========================================================================
# Backend server (runs natively — shared constant, not benchmarked)
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

run_wrk_post() {
    local gateway="$1"
    local protocol="$2"
    local endpoint="$3"
    local port="$4"
    local label="${gateway}/${protocol}${endpoint}"
    # Sanitize endpoint for filename: /api/echo -> api_echo
    local safe_endpoint
    safe_endpoint=$(echo "$endpoint" | sed 's|^/||; s|/|_|g')
    local result_file="${RESULTS_DIR}/${gateway}_${protocol}_${safe_endpoint}_results.txt"

    local url
    if [[ "$protocol" == "https" || "$protocol" == "e2e_tls" ]]; then
        url="https://127.0.0.1:${port}${endpoint}"
    else
        url="http://127.0.0.1:${port}${endpoint}"
    fi

    echo -e "    ${CYAN}Testing ${label} (POST ~10KB)${NC}  →  ${url}"

    # Warm-up (results discarded)
    wrk -t2 -c20 -d"$WARMUP_DURATION" -s "$LUA_SCRIPT_POST" "$url" > /dev/null 2>&1 || true

    # Measured run
    if ! wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"$WRK_DURATION" \
        --latency -s "$LUA_SCRIPT_POST" "$url" > "$result_file" 2>&1; then
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
    local label="${gateway}/key_auth/api/echo-auth"
    local safe_endpoint="api_echo"
    local result_file="${RESULTS_DIR}/${gateway}_key_auth_${safe_endpoint}_results.txt"
    local url="http://127.0.0.1:${port}/api/echo-auth"

    echo -e "    ${CYAN}Testing ${label} (POST ~10KB)${NC}  →  ${url}"

    # Warm-up (results discarded)
    wrk -t2 -c20 -d"$WARMUP_DURATION" -s "$LUA_SCRIPT_POST_KEY_AUTH" "$url" > /dev/null 2>&1 || true

    # Measured run
    if ! wrk -t"$WRK_THREADS" -c"$WRK_CONNECTIONS" -d"$WRK_DURATION" \
        --latency -s "$LUA_SCRIPT_POST_KEY_AUTH" "$url" > "$result_file" 2>&1; then
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
# Ferrum Edge (Docker)
# ===========================================================================

prepare_ferrum_config() {
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/ferrum_comparison.yaml" > "$COMP_DIR/configs/.ferrum_runtime.yaml"
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/ferrum_comparison_e2e_tls.yaml" > "$COMP_DIR/configs/.ferrum_runtime_e2e_tls.yaml"
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/ferrum_comparison_key_auth.yaml" > "$COMP_DIR/configs/.ferrum_runtime_key_auth.yaml"
}

start_ferrum_http() {
    log_info "Starting Ferrum Edge Docker (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$FERRUM_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    docker_run_gateway "$FERRUM_CONTAINER" "$GATEWAY_HTTP_PORT" -- \
        -v "$COMP_DIR/configs/.ferrum_runtime.yaml:/etc/ferrum/config.yaml:ro" \
        -e FERRUM_MODE=file \
        -e FERRUM_FILE_CONFIG_PATH=/etc/ferrum/config.yaml \
        -e FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
        -e FERRUM_LOG_LEVEL=error \
        -e FERRUM_ADD_VIA_HEADER=false \
        -e FERRUM_ADD_FORWARDED_HEADER=false \
        -e FERRUM_POOL_WARMUP_ENABLED=true \
        -e FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
        -e FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
        -e FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
        -e FERRUM_POOL_ENABLE_HTTP2=false \
        -e FERRUM_POOL_CLEANUP_INTERVAL_SECONDS=30 \
        -e FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608 \
        -e FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432 \
        -e FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true \
        -e FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=1048576 \
        -e FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
        -e FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
        -e FERRUM_MAX_CONNECTIONS=0 \
        -e FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 \
        -e FERRUM_MAX_HEADER_COUNT=0 \
        -e FERRUM_MAX_URL_LENGTH_BYTES=0 \
        -e FERRUM_MAX_QUERY_PARAMS=0 \
        -e FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0 \
        -e FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0 \
        -e FERRUM_RESPONSE_BUFFER_THRESHOLD_BYTES=0 \
        "$FERRUM_IMAGE"

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Ferrum Docker (HTTP)" 15 "$FERRUM_CONTAINER"
}

start_ferrum_https() {
    log_info "Starting Ferrum Edge Docker (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$FERRUM_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker_run_gateway "$FERRUM_CONTAINER" "$GATEWAY_HTTP_PORT" "$GATEWAY_HTTPS_PORT" -- \
        -v "$COMP_DIR/configs/.ferrum_runtime.yaml:/etc/ferrum/config.yaml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/ferrum/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/ferrum/tls/server.key:ro" \
        -e FERRUM_MODE=file \
        -e FERRUM_FILE_CONFIG_PATH=/etc/ferrum/config.yaml \
        -e FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
        -e FERRUM_PROXY_HTTPS_PORT="$GATEWAY_HTTPS_PORT" \
        -e FERRUM_FRONTEND_TLS_CERT_PATH=/etc/ferrum/tls/server.crt \
        -e FERRUM_FRONTEND_TLS_KEY_PATH=/etc/ferrum/tls/server.key \
        -e FERRUM_LOG_LEVEL=error \
        -e FERRUM_ADD_VIA_HEADER=false \
        -e FERRUM_ADD_FORWARDED_HEADER=false \
        -e FERRUM_POOL_WARMUP_ENABLED=true \
        -e FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
        -e FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
        -e FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
        -e FERRUM_POOL_ENABLE_HTTP2=false \
        -e FERRUM_POOL_CLEANUP_INTERVAL_SECONDS=30 \
        -e FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608 \
        -e FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432 \
        -e FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true \
        -e FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=1048576 \
        -e FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
        -e FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
        -e FERRUM_MAX_CONNECTIONS=0 \
        -e FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 \
        -e FERRUM_MAX_HEADER_COUNT=0 \
        -e FERRUM_MAX_URL_LENGTH_BYTES=0 \
        -e FERRUM_MAX_QUERY_PARAMS=0 \
        -e FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0 \
        -e FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0 \
        -e FERRUM_RESPONSE_BUFFER_THRESHOLD_BYTES=0 \
        "$FERRUM_IMAGE"

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Ferrum Docker (HTTPS)" 15 "$FERRUM_CONTAINER"
}

start_ferrum_e2e_tls() {
    log_info "Starting Ferrum Edge Docker (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$FERRUM_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker_run_gateway "$FERRUM_CONTAINER" "$GATEWAY_HTTP_PORT" "$GATEWAY_HTTPS_PORT" -- \
        -v "$COMP_DIR/configs/.ferrum_runtime_e2e_tls.yaml:/etc/ferrum/config.yaml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/ferrum/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/ferrum/tls/server.key:ro" \
        -e FERRUM_MODE=file \
        -e FERRUM_FILE_CONFIG_PATH=/etc/ferrum/config.yaml \
        -e FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
        -e FERRUM_PROXY_HTTPS_PORT="$GATEWAY_HTTPS_PORT" \
        -e FERRUM_FRONTEND_TLS_CERT_PATH=/etc/ferrum/tls/server.crt \
        -e FERRUM_FRONTEND_TLS_KEY_PATH=/etc/ferrum/tls/server.key \
        -e FERRUM_TLS_CA_BUNDLE_PATH=/etc/ferrum/tls/server.crt \
        -e FERRUM_LOG_LEVEL=error \
        -e FERRUM_ADD_VIA_HEADER=false \
        -e FERRUM_ADD_FORWARDED_HEADER=false \
        -e FERRUM_POOL_WARMUP_ENABLED=true \
        -e FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
        -e FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
        -e FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
        -e FERRUM_POOL_ENABLE_HTTP2=false \
        -e FERRUM_POOL_CLEANUP_INTERVAL_SECONDS=30 \
        -e FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608 \
        -e FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432 \
        -e FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true \
        -e FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=1048576 \
        -e FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
        -e FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
        -e FERRUM_MAX_CONNECTIONS=0 \
        -e FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 \
        -e FERRUM_MAX_HEADER_COUNT=0 \
        -e FERRUM_MAX_URL_LENGTH_BYTES=0 \
        -e FERRUM_MAX_QUERY_PARAMS=0 \
        -e FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0 \
        -e FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0 \
        -e FERRUM_RESPONSE_BUFFER_THRESHOLD_BYTES=0 \
        "$FERRUM_IMAGE"

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Ferrum Docker (E2E TLS)" 15 "$FERRUM_CONTAINER"
}

stop_ferrum() {
    docker rm -f "$FERRUM_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_ferrum() {
    log_header "Testing Ferrum Edge (Docker)"

    prepare_ferrum_config

    # HTTP tests
    if start_ferrum_http; then
        run_wrk_post "ferrum" "http" "/api/echo" "$GATEWAY_HTTP_PORT"
        stop_ferrum
    else
        log_warn "Ferrum HTTP failed to start — skipping"
        stop_ferrum
    fi

    # HTTPS tests (TLS termination — plaintext backend)
    if start_ferrum_https; then
        run_wrk_post "ferrum" "https" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_ferrum
    else
        log_warn "Ferrum HTTPS failed to start — skipping"
        stop_ferrum
    fi

    # E2E TLS tests (TLS on both sides)
    if start_ferrum_e2e_tls; then
        run_wrk_post "ferrum" "e2e_tls" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_ferrum
    else
        log_warn "Ferrum E2E TLS failed to start — skipping"
        stop_ferrum
    fi
}

# ===========================================================================
# Kong Gateway (Docker)
# ===========================================================================

prepare_kong_config() {
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/kong.yaml" > "$COMP_DIR/configs/.kong_runtime.yaml"
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/kong_e2e_tls.yaml" > "$COMP_DIR/configs/.kong_runtime_e2e_tls.yaml"
}

start_kong_http() {
    log_info "Starting Kong Gateway Docker (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    docker_run_gateway "$KONG_CONTAINER" "$GATEWAY_HTTP_PORT" -- \
        -v "$COMP_DIR/configs/.kong_runtime.yaml:/etc/kong/kong.yml:ro" \
        -e KONG_DATABASE=off \
        -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
        -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT" \
        -e KONG_ADMIN_LISTEN="off" \
        -e KONG_PROXY_ACCESS_LOG=/dev/null \
        -e KONG_PROXY_ERROR_LOG=/dev/stderr \
        -e KONG_LOG_LEVEL=warn \
        -e KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
        "kong/kong-gateway:${KONG_VERSION}"

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Kong Docker (HTTP)" 20 "$KONG_CONTAINER"
}

start_kong_https() {
    log_info "Starting Kong Gateway Docker (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker_run_gateway "$KONG_CONTAINER" "$GATEWAY_HTTP_PORT" "$GATEWAY_HTTPS_PORT" -- \
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
        "kong/kong-gateway:${KONG_VERSION}"

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Kong Docker (HTTPS)" 20 "$KONG_CONTAINER"
}

start_kong_e2e_tls() {
    log_info "Starting Kong Gateway Docker (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker_run_gateway "$KONG_CONTAINER" "$GATEWAY_HTTP_PORT" "$GATEWAY_HTTPS_PORT" -- \
        -v "$COMP_DIR/configs/.kong_runtime_e2e_tls.yaml:/etc/kong/kong.yml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/kong/ssl/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/kong/ssl/server.key:ro" \
        -v "$CERTS_DIR/server.crt:/etc/kong/ssl/upstream-ca.crt:ro" \
        -e KONG_DATABASE=off \
        -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
        -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT, 0.0.0.0:$GATEWAY_HTTPS_PORT ssl" \
        -e KONG_SSL_CERT=/etc/kong/ssl/server.crt \
        -e KONG_SSL_CERT_KEY=/etc/kong/ssl/server.key \
        -e KONG_LUA_SSL_TRUSTED_CERTIFICATE=/etc/kong/ssl/upstream-ca.crt \
        -e KONG_ADMIN_LISTEN="off" \
        -e KONG_PROXY_ACCESS_LOG=/dev/null \
        -e KONG_PROXY_ERROR_LOG=/dev/stderr \
        -e KONG_LOG_LEVEL=warn \
        -e KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
        "kong/kong-gateway:${KONG_VERSION}"

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Kong Docker (E2E TLS)" 20 "$KONG_CONTAINER"
}

stop_kong() {
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_kong() {
    log_header "Testing Kong Gateway (Docker ${KONG_VERSION})"

    prepare_kong_config

    # HTTP tests
    if start_kong_http; then
        run_wrk_post "kong" "http" "/api/echo" "$GATEWAY_HTTP_PORT"
        stop_kong
    else
        log_warn "Kong HTTP failed to start — skipping"
        stop_kong
    fi

    # HTTPS tests (TLS termination — plaintext backend)
    if start_kong_https; then
        run_wrk_post "kong" "https" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_kong
    else
        log_warn "Kong HTTPS failed to start — skipping"
        stop_kong
    fi

    # E2E TLS tests (TLS on both sides)
    if start_kong_e2e_tls; then
        run_wrk_post "kong" "e2e_tls" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_kong
    else
        log_warn "Kong E2E TLS failed to start — skipping"
        stop_kong
    fi
}

# ===========================================================================
# Tyk Gateway (Docker)
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

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/hello" "Tyk (HTTP)" 20 "$TYK_CONTAINER"
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

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/hello" "Tyk (HTTPS)" 20 "$TYK_CONTAINER"
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
        -v "$CERTS_DIR/server.crt:/etc/tyk/certs/upstream-ca.crt:ro" \
        "tykio/tyk-gateway:${TYK_VERSION}" > /dev/null

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/hello" "Tyk (E2E TLS)" 20 "$TYK_CONTAINER"
}

stop_tyk() {
    docker rm -f "$TYK_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_tyk() {
    log_header "Testing Tyk Gateway (Docker ${TYK_VERSION})"

    prepare_tyk_config
    start_redis

    # HTTP tests
    if start_tyk_http; then
        run_wrk_post "tyk" "http" "/api/echo" "$GATEWAY_HTTP_PORT"
        stop_tyk
    else
        log_warn "Tyk HTTP failed to start — skipping"
        stop_tyk
    fi

    # HTTPS tests (TLS termination — plaintext backend)
    if start_tyk_https; then
        run_wrk_post "tyk" "https" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_tyk
    else
        log_warn "Tyk HTTPS failed to start — skipping"
        stop_tyk
    fi

    # E2E TLS tests (TLS on both sides)
    if start_tyk_e2e_tls; then
        run_wrk_post "tyk" "e2e_tls" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_tyk
    else
        log_warn "Tyk E2E TLS failed to start — skipping"
        stop_tyk
    fi

    stop_redis
}

# ===========================================================================
# KrakenD Gateway (Docker)
# ===========================================================================

prepare_krakend_config() {
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

    docker_run_gateway "$KRAKEND_CONTAINER" "$GATEWAY_HTTP_PORT" -- \
        -v "$COMP_DIR/configs/.krakend_runtime_http.json:/etc/krakend/krakend.json:ro" \
        "krakend:${KRAKEND_VERSION}" \
        run -c /etc/krakend/krakend.json

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "KrakenD (HTTP)" 20 "$KRAKEND_CONTAINER"
}

start_krakend_https() {
    log_info "Starting KrakenD Gateway (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KRAKEND_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker_run_gateway "$KRAKEND_CONTAINER" "$GATEWAY_HTTPS_PORT" -- \
        -v "$COMP_DIR/configs/.krakend_runtime_https.json:/etc/krakend/krakend.json:ro" \
        -v "$CERTS_DIR/server.crt:/etc/krakend/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/krakend/tls/server.key:ro" \
        "krakend:${KRAKEND_VERSION}" \
        run -c /etc/krakend/krakend.json

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "KrakenD (HTTPS)" 20 "$KRAKEND_CONTAINER"
}

start_krakend_e2e_tls() {
    log_info "Starting KrakenD Gateway (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$KRAKEND_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker_run_gateway "$KRAKEND_CONTAINER" "$GATEWAY_HTTPS_PORT" -- \
        -v "$COMP_DIR/configs/.krakend_runtime_e2e_tls.json:/etc/krakend/krakend.json:ro" \
        -v "$CERTS_DIR/server.crt:/etc/krakend/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/krakend/tls/server.key:ro" \
        "krakend:${KRAKEND_VERSION}" \
        run -c /etc/krakend/krakend.json

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "KrakenD (E2E TLS)" 20 "$KRAKEND_CONTAINER"
}

stop_krakend() {
    docker rm -f "$KRAKEND_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_krakend() {
    log_header "Testing KrakenD Gateway (Docker ${KRAKEND_VERSION})"

    prepare_krakend_config

    # HTTP tests
    if start_krakend_http; then
        run_wrk_post "krakend" "http" "/api/echo" "$GATEWAY_HTTP_PORT"
        stop_krakend
    else
        log_warn "KrakenD HTTP failed to start — skipping"
        stop_krakend
    fi

    # HTTPS tests (TLS termination — plaintext backend)
    if start_krakend_https; then
        run_wrk_post "krakend" "https" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_krakend
    else
        log_warn "KrakenD HTTPS failed to start — skipping"
        stop_krakend
    fi

    # E2E TLS tests (TLS on both sides)
    if start_krakend_e2e_tls; then
        run_wrk_post "krakend" "e2e_tls" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_krakend
    else
        log_warn "KrakenD E2E TLS failed to start — skipping"
        stop_krakend
    fi
}

# ===========================================================================
# Envoy Proxy (Docker)
# ===========================================================================

prepare_envoy_config() {
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/envoy/envoy_http.yaml" > "$COMP_DIR/configs/.envoy_runtime_http.yaml"
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/envoy/envoy_https.yaml" > "$COMP_DIR/configs/.envoy_runtime_https.yaml"
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/envoy/envoy_e2e_tls.yaml" > "$COMP_DIR/configs/.envoy_runtime_e2e_tls.yaml"
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/envoy/envoy_key_auth.yaml" > "$COMP_DIR/configs/.envoy_runtime_key_auth.yaml"
}

start_envoy_http() {
    log_info "Starting Envoy Proxy Docker (HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    docker_run_gateway "$ENVOY_CONTAINER" "$GATEWAY_HTTP_PORT" -- \
        -v "$COMP_DIR/configs/.envoy_runtime_http.yaml:/etc/envoy/envoy.yaml:ro" \
        "envoyproxy/envoy:v${ENVOY_VERSION}"

    wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Envoy Docker (HTTP)" 20 "$ENVOY_CONTAINER"
}

start_envoy_https() {
    log_info "Starting Envoy Proxy Docker (HTTPS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker_run_gateway "$ENVOY_CONTAINER" "$GATEWAY_HTTPS_PORT" -- \
        -v "$COMP_DIR/configs/.envoy_runtime_https.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/envoy/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/envoy/tls/server.key:ro" \
        "envoyproxy/envoy:v${ENVOY_VERSION}"

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Envoy Docker (HTTPS)" 20 "$ENVOY_CONTAINER"
}

start_envoy_e2e_tls() {
    log_info "Starting Envoy Proxy Docker (E2E TLS) on port $GATEWAY_HTTPS_PORT..."
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"

    docker_run_gateway "$ENVOY_CONTAINER" "$GATEWAY_HTTPS_PORT" -- \
        -v "$COMP_DIR/configs/.envoy_runtime_e2e_tls.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$CERTS_DIR/server.crt:/etc/envoy/tls/server.crt:ro" \
        -v "$CERTS_DIR/server.key:/etc/envoy/tls/server.key:ro" \
        "envoyproxy/envoy:v${ENVOY_VERSION}"

    wait_for_http "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" "Envoy Docker (E2E TLS)" 20 "$ENVOY_CONTAINER"
}

stop_envoy() {
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"
    kill_port "$GATEWAY_HTTPS_PORT"
    sleep 1
}

test_envoy() {
    log_header "Testing Envoy Proxy (Docker ${ENVOY_VERSION})"

    prepare_envoy_config

    # HTTP tests
    if start_envoy_http; then
        run_wrk_post "envoy" "http" "/api/echo" "$GATEWAY_HTTP_PORT"
        stop_envoy
    else
        log_warn "Envoy HTTP failed to start — skipping"
        stop_envoy
    fi

    # HTTPS tests (TLS termination — plaintext backend)
    if start_envoy_https; then
        run_wrk_post "envoy" "https" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_envoy
    else
        log_warn "Envoy HTTPS failed to start — skipping"
        stop_envoy
    fi

    # E2E TLS tests (TLS on both sides)
    if start_envoy_e2e_tls; then
        run_wrk_post "envoy" "e2e_tls" "/api/echo" "$GATEWAY_HTTPS_PORT"
        stop_envoy
    else
        log_warn "Envoy E2E TLS failed to start — skipping"
        stop_envoy
    fi
}

# ===========================================================================
# Key-Auth Tests (HTTP only, Ferrum + Kong + Tyk + Envoy)
# Note: KrakenD key-auth requires Enterprise Edition, so it is excluded.
# ===========================================================================

prepare_kong_key_auth_config() {
    sed "s/BACKEND_HOST/$BACKEND_HOST/g" \
        "$COMP_DIR/configs/kong_key_auth.yaml" > "$COMP_DIR/configs/.kong_runtime_key_auth.yaml"
}

prepare_tyk_key_auth_config() {
    mkdir -p "$COMP_DIR/configs/.tyk_runtime_apps_key_auth"
    for f in "$COMP_DIR/configs/tyk/apps_key_auth"/*.json; do
        sed "s/BACKEND_HOST/$BACKEND_HOST/g" "$f" > "$COMP_DIR/configs/.tyk_runtime_apps_key_auth/$(basename "$f")"
    done
}

test_ferrum_key_auth() {
    log_info "Starting Ferrum Edge Docker (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$FERRUM_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    docker_run_gateway "$FERRUM_CONTAINER" "$GATEWAY_HTTP_PORT" -- \
        -v "$COMP_DIR/configs/.ferrum_runtime_key_auth.yaml:/etc/ferrum/config.yaml:ro" \
        -e FERRUM_MODE=file \
        -e FERRUM_FILE_CONFIG_PATH=/etc/ferrum/config.yaml \
        -e FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT" \
        -e FERRUM_LOG_LEVEL=error \
        -e FERRUM_ADD_VIA_HEADER=false \
        -e FERRUM_ADD_FORWARDED_HEADER=false \
        -e FERRUM_POOL_WARMUP_ENABLED=true \
        -e FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
        -e FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
        -e FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
        -e FERRUM_POOL_ENABLE_HTTP2=false \
        -e FERRUM_POOL_CLEANUP_INTERVAL_SECONDS=30 \
        -e FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608 \
        -e FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432 \
        -e FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true \
        -e FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=1048576 \
        -e FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
        -e FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000 \
        -e FERRUM_MAX_CONNECTIONS=0 \
        -e FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 \
        -e FERRUM_MAX_HEADER_COUNT=0 \
        -e FERRUM_MAX_URL_LENGTH_BYTES=0 \
        -e FERRUM_MAX_QUERY_PARAMS=0 \
        -e FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0 \
        -e FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0 \
        -e FERRUM_RESPONSE_BUFFER_THRESHOLD_BYTES=0 \
        "$FERRUM_IMAGE"

    if ! wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Ferrum Docker (Key Auth)" 15 "$FERRUM_CONTAINER"; then
        log_warn "Ferrum Key Auth failed to start — skipping"
        stop_ferrum
        return 0
    fi
    run_wrk_key_auth "ferrum" "$GATEWAY_HTTP_PORT"
    stop_ferrum
}

test_kong_key_auth() {
    prepare_kong_key_auth_config

    log_info "Starting Kong Gateway Docker (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$KONG_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    docker_run_gateway "$KONG_CONTAINER" "$GATEWAY_HTTP_PORT" -- \
        -v "$COMP_DIR/configs/.kong_runtime_key_auth.yaml:/etc/kong/kong.yml:ro" \
        -e KONG_DATABASE=off \
        -e KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yml \
        -e KONG_PROXY_LISTEN="0.0.0.0:$GATEWAY_HTTP_PORT" \
        -e KONG_ADMIN_LISTEN="off" \
        -e KONG_PROXY_ACCESS_LOG=/dev/null \
        -e KONG_PROXY_ERROR_LOG=/dev/stderr \
        -e KONG_LOG_LEVEL=warn \
        -e KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=128 \
        "kong/kong-gateway:${KONG_VERSION}"

    if ! wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Kong Docker (Key Auth)" 20 "$KONG_CONTAINER"; then
        log_warn "Kong Key Auth failed to start — skipping"
        stop_kong
        return 0
    fi
    run_wrk_key_auth "kong" "$GATEWAY_HTTP_PORT"
    stop_kong
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

    if ! wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/hello" "Tyk (Key Auth)" 20 "$TYK_CONTAINER"; then
        log_warn "Tyk Key Auth failed to start — skipping"
        stop_tyk
        return 0
    fi

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
                "echo-auth-api": {
                    "api_id": "echo-auth-api",
                    "api_name": "Echo Auth API",
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
    sed "s/test-api-key/$tyk_api_key/g" "$LUA_SCRIPT_POST_KEY_AUTH" > "$tyk_lua"

    # Run wrk with the Tyk-specific key
    local label="tyk/key_auth/api/echo-auth"
    local result_file="${RESULTS_DIR}/tyk_key_auth_api_echo_results.txt"
    local url="http://127.0.0.1:${GATEWAY_HTTP_PORT}/api/echo-auth"

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

    log_info "Starting Envoy Proxy Docker (Key Auth HTTP) on port $GATEWAY_HTTP_PORT..."
    docker rm -f "$ENVOY_CONTAINER" 2>/dev/null || true
    kill_port "$GATEWAY_HTTP_PORT"

    docker_run_gateway "$ENVOY_CONTAINER" "$GATEWAY_HTTP_PORT" -- \
        -v "$COMP_DIR/configs/.envoy_runtime_key_auth.yaml:/etc/envoy/envoy.yaml:ro" \
        "envoyproxy/envoy:v${ENVOY_VERSION}"

    if ! wait_for_http "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" "Envoy Docker (Key Auth)" 20 "$ENVOY_CONTAINER"; then
        log_warn "Envoy Key Auth failed to start — skipping"
        stop_envoy
        return 0
    fi
    run_wrk_key_auth "envoy" "$GATEWAY_HTTP_PORT"
    stop_envoy
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
    run_wrk_post "baseline" "http" "/api/echo" "$BACKEND_PORT"
    # HTTPS baseline (direct to backend HTTPS port, no gateway)
    run_wrk_post "baseline" "https" "/api/echo" "$BACKEND_HTTPS_PORT"
    # E2E TLS baseline (same as HTTPS — direct to backend HTTPS port, no gateway)
    run_wrk_post "baseline" "e2e_tls" "/api/echo" "$BACKEND_HTTPS_PORT"
}

# ===========================================================================
# Report generation
# ===========================================================================

write_metadata() {
    cat > "$RESULTS_DIR/meta.json" <<METAEOF
{
    "duration": "$WRK_DURATION",
    "threads": "$WRK_THREADS",
    "connections": "$WRK_CONNECTIONS",
    "execution_mode": "all-docker",
    "ferrum_version": "Docker (local build)",
    "kong_version": "Docker ${KONG_VERSION}",
    "tyk_version": "Docker ${TYK_VERSION}",
    "krakend_version": "Docker ${KRAKEND_VERSION}",
    "envoy_version": "Docker ${ENVOY_VERSION}",
    "kong_native": false,
    "envoy_native": false,
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
    echo "  ║      API Gateway Comparison Benchmark Suite (All-Docker)          ║"
    echo "  ║     Ferrum vs Kong vs Tyk vs KrakenD vs Envoy                 ║"
    echo "  ╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  Duration: ${WRK_DURATION}  Threads: ${WRK_THREADS}  Connections: ${WRK_CONNECTIONS}"
    echo "  Mode: ALL gateways in Docker (apples-to-apples)"
    echo "  Kong: Docker ${KONG_VERSION}  Tyk: Docker ${TYK_VERSION}  KrakenD: Docker ${KRAKEND_VERSION}  Envoy: Docker ${ENVOY_VERSION}"
    if [[ -n "$SKIP_GATEWAYS" ]]; then
        echo -e "  ${YELLOW}Skipping: ${SKIP_GATEWAYS}${NC}"
    fi

    check_dependencies
    pull_images
    build_images

    mkdir -p "$RESULTS_DIR"

    start_backend
    test_baseline

    if ! should_skip "ferrum"; then
        test_ferrum
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

    # Key-Auth tests (HTTP only, Ferrum + Kong + Tyk + Envoy; KrakenD key-auth requires Enterprise)
    test_key_auth

    generate_report

    echo ""
    log_header "Benchmark Complete"
    echo -e "  ${GREEN}Results: ${RESULTS_DIR}/${NC}"
    echo -e "  ${GREEN}Report:  ${RESULTS_DIR}/comparison_report.html${NC}"
    echo ""
}

main "$@"
