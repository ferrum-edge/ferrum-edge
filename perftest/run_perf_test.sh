#!/bin/bash

# Performance testing script for Ferrum Gateway
# This script runs backend server, gateway, and load tests

set -e

PERF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$PERF_DIR")"

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

echo -e "${BLUE}🚀 Starting Ferrum Gateway Performance Test${NC}"
echo "=================================================="

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

# Build the project
build_project() {
    echo -e "${YELLOW}🔨 Building project...${NC}"
    
    # Build gateway
    cd "$PROJECT_ROOT"
    cargo build --release --bin ferrum-gateway
    
    # Build backend server
    cd "$PERF_DIR"
    cargo build --release --bin backend_server
    
    echo -e "${GREEN}✅ Build completed${NC}"
}

# Start backend server
start_backend() {
    echo -e "${YELLOW}🌐 Starting backend server on port $BACKEND_PORT...${NC}"
    "$PERF_DIR/target/release/backend_server" > "$PERF_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    
    # Wait for backend to start
    sleep 2
    
    if curl -s "http://localhost:$BACKEND_PORT/health" > /dev/null; then
        echo -e "${GREEN}✅ Backend server started (PID: $BACKEND_PID)${NC}"
    else
        echo -e "${RED}❌ Backend server failed to start${NC}"
        cat "$PERF_DIR/backend.log"
        exit 1
    fi
}

# Start gateway
start_gateway() {
    echo -e "${YELLOW}🚪 Starting gateway on port $GATEWAY_PORT...${NC}"
    cd "$PROJECT_ROOT"
    # Set global connection pool defaults optimized for performance testing
    FERRUM_MODE=file \
    FERRUM_FILE_CONFIG_PATH="$PERF_DIR/perf_config.yaml" \
    FERRUM_POOL_MAX_IDLE_PER_HOST=15 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_ENABLE_HTTP2=false \
    ./target/release/ferrum-gateway > "$PERF_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!
    
    # Wait for gateway to start
    sleep 3
    
    if curl -s "http://localhost:$GATEWAY_PORT/health" > /dev/null; then
        echo -e "${GREEN}✅ Gateway started (PID: $GATEWAY_PID)${NC}"
    else
        echo -e "${RED}❌ Gateway failed to start${NC}"
        cat "$PERF_DIR/gateway.log"
        exit 1
    fi
}

# Run performance tests
run_load_tests() {
    echo -e "${YELLOW}⚡ Running load tests...${NC}"
    echo "Duration: $WRK_DURATION, Threads: $WRK_THREADS, Connections: $WRK_CONNECTIONS"
    echo ""
    
    # Test 1: Health check endpoint (lightweight)
    echo -e "${BLUE}📊 Test 1: Health Check Endpoint${NC}"
    echo "URL: http://localhost:$GATEWAY_PORT/health"
    wrk -t$WRK_THREADS -c$WRK_CONNECTIONS -d$WRK_DURATION --latency \
        -s "$PERF_DIR/health_test.lua" \
        "http://localhost:$GATEWAY_PORT/health" \
        > "$PERF_DIR/health_results.txt"
    
    echo -e "${GREEN}✅ Health check test completed${NC}"
    cat "$PERF_DIR/health_results.txt" | grep -E "(Requests/sec|Latency|Transfer/sec)"
    echo ""
    
    # Test 2: Users API endpoint (moderate load)
    echo -e "${BLUE}📊 Test 2: Users API Endpoint${NC}"
    echo "URL: http://localhost:$GATEWAY_PORT/api/users"
    wrk -t$WRK_THREADS -c$WRK_CONNECTIONS -d$WRK_DURATION --latency \
        -s "$PERF_DIR/users_test.lua" \
        "http://localhost:$GATEWAY_PORT/api/users" \
        > "$PERF_DIR/users_results.txt"
    
    echo -e "${GREEN}✅ Users API test completed${NC}"
    cat "$PERF_DIR/users_results.txt" | grep -E "(Requests/sec|Latency|Transfer/sec)"
    echo ""
    
    # Test 3: Direct backend test (baseline)
    echo -e "${BLUE}📊 Test 3: Direct Backend (Baseline)${NC}"
    echo "URL: http://localhost:$BACKEND_PORT/api/users"
    wrk -t$WRK_THREADS -c$WRK_CONNECTIONS -d$WRK_DURATION --latency \
        -s "$PERF_DIR/backend_test.lua" \
        "http://localhost:$BACKEND_PORT/api/users" \
        > "$PERF_DIR/backend_results.txt"
    
    echo -e "${GREEN}✅ Direct backend test completed${NC}"
    cat "$PERF_DIR/backend_results.txt" | grep -E "(Requests/sec|Latency|Transfer/sec)"
    echo ""
}

# Generate performance report
generate_report() {
    echo -e "${YELLOW}📈 Generating performance report...${NC}"
    
    python3 "$PERF_DIR/generate_report.py" \
        --gateway-results "$PERF_DIR/health_results.txt" \
        --backend-results "$PERF_DIR/backend_results.txt" \
        --output "$PERF_DIR/performance_report.html"
    
    echo -e "${GREEN}✅ Performance report generated: $PERF_DIR/performance_report.html${NC}"
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
    build_project
    start_backend
    start_gateway
    run_load_tests
    generate_report
    
    echo -e "${GREEN}🎉 Performance test completed successfully!${NC}"
    echo -e "${BLUE}📄 Results saved to: $PERF_DIR/performance_report.html${NC}"
}

# Run main function
main "$@"
