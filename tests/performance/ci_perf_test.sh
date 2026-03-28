#!/bin/bash

# CI-friendly performance test for Ferrum Gateway
# Runs lighter load tests and outputs machine-readable JSON for baseline comparison
#
# Usage:
#   ./ci_perf_test.sh                    # Run tests and output JSON results
#   ./ci_perf_test.sh --save-baseline    # Run tests and save as new baseline

set -e

PERF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$PERF_DIR")")"
RESULTS_DIR="$PERF_DIR/ci_results"

# CI-tuned parameters (lighter than local perf tests)
BACKEND_PORT=3001
GATEWAY_PORT=8000
CI_WRK_DURATION=${CI_WRK_DURATION:-10s}
CI_WRK_THREADS=${CI_WRK_THREADS:-4}
CI_WRK_CONNECTIONS=${CI_WRK_CONNECTIONS:-50}

# Cleanup function
cleanup() {
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
    fi
    if [ ! -z "$GATEWAY_PID" ]; then
        kill $GATEWAY_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Kill any existing processes on test ports
echo "Cleaning up ports..."
lsof -ti:$BACKEND_PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -ti:$GATEWAY_PORT 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

# Check dependencies
if ! command -v wrk &> /dev/null; then
    echo "ERROR: wrk is not installed"
    echo "  Ubuntu: sudo apt-get install wrk"
    echo "  macOS: brew install wrk"
    exit 1
fi

# Check if a binary is up-to-date (newer than all Rust source files in its crate)
binary_is_fresh() {
    local binary="$1"
    local src_dir="$2"
    [ -f "$binary" ] || return 1
    local newer
    newer=$(find "$src_dir" \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) -newer "$binary" -print -quit 2>/dev/null)
    [ -z "$newer" ]
}

# Build (skips if binaries are newer than source)
GATEWAY_BIN="$PROJECT_ROOT/target/release/ferrum-gateway"
BACKEND_BIN="$PERF_DIR/target/release/backend_server"
NEED_GATEWAY=true
NEED_BACKEND=true

if binary_is_fresh "$GATEWAY_BIN" "$PROJECT_ROOT/src"; then
    NEED_GATEWAY=false
fi
if binary_is_fresh "$BACKEND_BIN" "$PERF_DIR/src"; then
    NEED_BACKEND=false
fi

if ! $NEED_GATEWAY && ! $NEED_BACKEND; then
    echo "Binaries up-to-date, skipping build"
else
    echo "Building project..."
    if $NEED_GATEWAY; then
        cd "$PROJECT_ROOT"
        cargo build --release --bin ferrum-gateway 2>&1
    else
        echo "  ferrum-gateway binary is fresh"
    fi
    if $NEED_BACKEND; then
        cd "$PERF_DIR"
        cargo build --release --bin backend_server 2>&1
    else
        echo "  backend_server binary is fresh"
    fi
fi

# Start backend
echo "Starting backend server..."
"$PERF_DIR/target/release/backend_server" > "$PERF_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf "http://127.0.0.1:$BACKEND_PORT/health" > /dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "ERROR: Backend server failed to start"
        cat "$PERF_DIR/backend.log"
        exit 1
    fi
    sleep 1
done

# Start gateway
echo "Starting gateway..."
cd "$PROJECT_ROOT"
# FERRUM_POOL_MAX_IDLE_PER_HOST MUST be >= wrk connection count to avoid
# connection churn during benchmarks. See tests/performance/README.md.
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH="$PERF_DIR/perf_config.yaml" \
FERRUM_POOL_MAX_IDLE_PER_HOST=200 \
FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
FERRUM_POOL_ENABLE_HTTP2=false \
./target/release/ferrum-gateway > "$PERF_DIR/gateway.log" 2>&1 &
GATEWAY_PID=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
    if kill -0 $GATEWAY_PID 2>/dev/null && curl -sf "http://127.0.0.1:$GATEWAY_PORT/health" > /dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 10 ]; then
        echo "ERROR: Gateway failed to start"
        cat "$PERF_DIR/gateway.log"
        exit 1
    fi
    sleep 1
done

# Prepare results directory
mkdir -p "$RESULTS_DIR"

echo "Running CI performance tests (duration=$CI_WRK_DURATION, threads=$CI_WRK_THREADS, connections=$CI_WRK_CONNECTIONS)..."

# Run each test and capture raw output
echo "  Test 1/3: Health check endpoint..."
wrk -t$CI_WRK_THREADS -c$CI_WRK_CONNECTIONS -d$CI_WRK_DURATION --latency \
    -s "$PERF_DIR/health_test.lua" \
    "http://127.0.0.1:$GATEWAY_PORT/health" \
    > "$RESULTS_DIR/health_raw.txt" 2>&1

echo "  Test 2/3: Users API endpoint..."
wrk -t$CI_WRK_THREADS -c$CI_WRK_CONNECTIONS -d$CI_WRK_DURATION --latency \
    -s "$PERF_DIR/users_test.lua" \
    "http://127.0.0.1:$GATEWAY_PORT/api/users" \
    > "$RESULTS_DIR/users_raw.txt" 2>&1

echo "  Test 3/3: Direct backend baseline..."
wrk -t$CI_WRK_THREADS -c$CI_WRK_CONNECTIONS -d$CI_WRK_DURATION --latency \
    -s "$PERF_DIR/backend_test.lua" \
    "http://127.0.0.1:$BACKEND_PORT/api/users" \
    > "$RESULTS_DIR/backend_raw.txt" 2>&1

echo "Load tests complete. Parsing results..."

# Parse wrk output into JSON using Python
python3 "$PERF_DIR/parse_wrk_results.py" \
    --health "$RESULTS_DIR/health_raw.txt" \
    --users "$RESULTS_DIR/users_raw.txt" \
    --backend "$RESULTS_DIR/backend_raw.txt" \
    --output "$RESULTS_DIR/results.json"

echo "Results saved to $RESULTS_DIR/results.json"

# If --save-baseline flag is set, copy results as the new baseline
if [ "$1" = "--save-baseline" ]; then
    cp "$RESULTS_DIR/results.json" "$PERF_DIR/baseline.json"
    echo "Baseline updated: $PERF_DIR/baseline.json"
fi

# Compare against baseline if it exists
if [ -f "$PERF_DIR/baseline.json" ]; then
    echo ""
    echo "Comparing against baseline..."
    python3 "$PERF_DIR/compare_baselines.py" \
        --baseline "$PERF_DIR/baseline.json" \
        --current "$RESULTS_DIR/results.json"
    COMPARE_EXIT=$?
    exit $COMPARE_EXIT
else
    echo "WARNING: No baseline.json found. Skipping regression check."
    echo "Run with --save-baseline to create one."
    cat "$RESULTS_DIR/results.json"
    exit 0
fi
