#!/bin/bash

# Performance testing script for Ferrum Gateway
# This script runs backend server, gateway, and load tests

set -e

PERF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$PERF_DIR")")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BACKEND_PORT=3001
GATEWAY_PORT=8000
WRK_DURATION=${WRK_DURATION:-30s}
WRK_THREADS=${WRK_THREADS:-8}
WRK_CONNECTIONS=${WRK_CONNECTIONS:-100}

echo -e "${BLUE}Starting Ferrum Gateway Performance Test${NC}"
echo "=================================================="

# Kill any existing processes on test ports to prevent conflicts
kill_existing() {
    echo -e "${YELLOW}Cleaning up existing processes on ports $BACKEND_PORT and $GATEWAY_PORT...${NC}"
    lsof -ti:$BACKEND_PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti:$GATEWAY_PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 1
    echo -e "${GREEN}Ports cleared${NC}"
}

# Check if required tools are installed
check_dependencies() {
    echo -e "${YELLOW}🔍 Checking dependencies...${NC}"
    
    if ! command -v wrk &> /dev/null; then
        echo -e "${RED}❌ wrk is not installed. Please install wrk for load testing:${NC}"
        echo "  macOS: brew install wrk"
        echo "  Ubuntu: sudo apt-get install wrk"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Dependencies check passed${NC}"
}

# Check if a binary is up-to-date (newer than all Rust source files in its crate)
binary_is_fresh() {
    local binary="$1"
    local src_dir="$2"
    [ -f "$binary" ] || return 1
    local newer
    newer=$(find "$src_dir" \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) -newer "$binary" -print -quit 2>/dev/null)
    [ -z "$newer" ]
}

# Build the project (skips if binaries are newer than source)
build_project() {
    local gateway_bin="$PROJECT_ROOT/target/release/ferrum-gateway"
    local backend_bin="$PERF_DIR/target/release/backend_server"
    local need_gateway=true
    local need_backend=true

    if binary_is_fresh "$gateway_bin" "$PROJECT_ROOT/src"; then
        need_gateway=false
    fi
    if binary_is_fresh "$backend_bin" "$PERF_DIR/src"; then
        need_backend=false
    fi

    if ! $need_gateway && ! $need_backend; then
        echo -e "${GREEN}Binaries up-to-date, skipping build${NC}"
        return
    fi

    echo -e "${YELLOW}Building project...${NC}"
    if $need_gateway; then
        cd "$PROJECT_ROOT"
        cargo build --release --bin ferrum-gateway
    else
        echo -e "  ${GREEN}ferrum-gateway binary is fresh${NC}"
    fi
    if $need_backend; then
        cd "$PERF_DIR"
        cargo build --release --bin backend_server
    else
        echo -e "  ${GREEN}backend_server binary is fresh${NC}"
    fi
    echo -e "${GREEN}Build completed${NC}"
}

# Start backend server
start_backend() {
    echo -e "${YELLOW}Starting backend server on port $BACKEND_PORT...${NC}"
    "$PERF_DIR/target/release/backend_server" > "$PERF_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!

    # Wait for backend to start with retry
    for i in 1 2 3 4 5; do
        if curl -sf "http://127.0.0.1:$BACKEND_PORT/health" > /dev/null 2>&1; then
            echo -e "${GREEN}Backend server started (PID: $BACKEND_PID)${NC}"
            return
        fi
        sleep 1
    done
    echo -e "${RED}Backend server failed to start${NC}"
    cat "$PERF_DIR/backend.log"
    exit 1
}

# Start gateway
start_gateway() {
    echo -e "${YELLOW}Starting gateway on port $GATEWAY_PORT...${NC}"
    cd "$PROJECT_ROOT"
    # ⚠️  IMPORTANT: These pool settings are tuned for performance benchmarking.
    # FERRUM_POOL_MAX_IDLE_PER_HOST MUST be kept at 200 (or higher) to avoid
    # connection churn under high-concurrency wrk load. Lowering this value
    # causes severe throughput degradation and non-2xx errors under load as the
    # pool exhausts idle connections and must re-establish them mid-benchmark.
    # DO NOT reduce FERRUM_POOL_MAX_IDLE_PER_HOST below 200 for perf testing.
    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$PERF_DIR/perf_config.yaml" \
    FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_ENABLE_HTTP2=false \
    ./target/release/ferrum-gateway > "$PERF_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!

    # Wait for gateway to start with retry — verify it's actually our process
    for i in 1 2 3 4 5; do
        if kill -0 $GATEWAY_PID 2>/dev/null && curl -sf "http://127.0.0.1:$GATEWAY_PORT/health" > /dev/null 2>&1; then
            echo -e "${GREEN}Gateway started (PID: $GATEWAY_PID)${NC}"
            return
        fi
        sleep 1
    done
    echo -e "${RED}Gateway failed to start${NC}"
    cat "$PERF_DIR/gateway.log"
    exit 1
}

# Run performance tests
run_load_tests() {
    echo -e "${YELLOW}⚡ Running load tests...${NC}"
    echo "Duration: $WRK_DURATION, Threads: $WRK_THREADS, Connections: $WRK_CONNECTIONS"
    echo ""
    
    # Test 1: Health check endpoint (lightweight)
    echo -e "${BLUE}📊 Test 1: Health Check Endpoint${NC}"
    echo "URL: http://127.0.0.1:$GATEWAY_PORT/health"
    wrk -t$WRK_THREADS -c$WRK_CONNECTIONS -d$WRK_DURATION --latency \
        -s "$PERF_DIR/health_test.lua" \
        "http://127.0.0.1:$GATEWAY_PORT/health" \
        > "$PERF_DIR/health_results.txt"
    
    echo -e "${GREEN}✅ Health check test completed${NC}"
    cat "$PERF_DIR/health_results.txt" | grep -E "(Requests/sec|Latency|Transfer/sec)"
    echo ""
    
    # Test 2: Users API endpoint (moderate load)
    echo -e "${BLUE}📊 Test 2: Users API Endpoint${NC}"
    echo "URL: http://127.0.0.1:$GATEWAY_PORT/api/users"
    wrk -t$WRK_THREADS -c$WRK_CONNECTIONS -d$WRK_DURATION --latency \
        -s "$PERF_DIR/users_test.lua" \
        "http://127.0.0.1:$GATEWAY_PORT/api/users" \
        > "$PERF_DIR/users_results.txt"
    
    echo -e "${GREEN}✅ Users API test completed${NC}"
    cat "$PERF_DIR/users_results.txt" | grep -E "(Requests/sec|Latency|Transfer/sec)"
    echo ""
    
    # Test 3: Direct backend test (baseline)
    echo -e "${BLUE}📊 Test 3: Direct Backend (Baseline)${NC}"
    echo "URL: http://127.0.0.1:$BACKEND_PORT/api/users"
    wrk -t$WRK_THREADS -c$WRK_CONNECTIONS -d$WRK_DURATION --latency \
        -s "$PERF_DIR/backend_test.lua" \
        "http://127.0.0.1:$BACKEND_PORT/api/users" \
        > "$PERF_DIR/backend_results.txt"
    
    echo -e "${GREEN}✅ Direct backend test completed${NC}"
    cat "$PERF_DIR/backend_results.txt" | grep -E "(Requests/sec|Latency|Transfer/sec)"
    echo ""
}

# Generate performance report (optional — requires generate_report.py)
generate_report() {
    if [ -f "$PERF_DIR/generate_report.py" ]; then
        echo -e "${YELLOW}Generating performance report...${NC}"
        python3 "$PERF_DIR/generate_report.py" \
            --gateway-results "$PERF_DIR/health_results.txt" \
            --backend-results "$PERF_DIR/backend_results.txt" \
            --output "$PERF_DIR/performance_report.html" 2>/dev/null \
            && echo -e "${GREEN}Performance report generated: $PERF_DIR/performance_report.html${NC}" \
            || echo -e "${YELLOW}Report generation skipped (generate_report.py error)${NC}"
    else
        echo -e "${YELLOW}Report generation skipped (generate_report.py not found)${NC}"
    fi
}

# Cleanup
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
        echo -e "${GREEN}✅ Backend server stopped${NC}"
    fi
    
    if [ ! -z "$GATEWAY_PID" ]; then
        kill $GATEWAY_PID 2>/dev/null || true
        echo -e "${GREEN}✅ Gateway stopped${NC}"
    fi
}

# Main execution
main() {
    trap cleanup EXIT
    
    check_dependencies
    kill_existing
    build_project
    start_backend
    start_gateway
    run_load_tests
    generate_report
    
    echo ""
    echo -e "${GREEN}Performance test completed successfully!${NC}"
    echo -e "${BLUE}Results saved to: $PERF_DIR/${NC}"
}

# Run main function
main "$@"
