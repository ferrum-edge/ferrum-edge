#!/bin/bash

# Quick test script to verify the performance testing setup

set -e

PERF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$PERF_DIR")")"

echo "🚀 Quick Performance Test Setup Verification"
echo "============================================"

# Check if wrk is installed
if ! command -v wrk &> /dev/null; then
    echo "❌ wrk is not installed. Please install wrk:"
    echo "  macOS: brew install wrk"
    echo "  Ubuntu: sudo apt-get install wrk"
    exit 1
fi
echo "✅ wrk is installed"

# Kill stale processes from prior runs
if lsof -ti:3001 > /dev/null 2>&1; then
    echo "Killing stale process on port 3001..."
    lsof -ti:3001 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 1
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

# Build backend server (skip if binary is fresh)
if binary_is_fresh "$PERF_DIR/target/release/backend_server" "$PERF_DIR/src"; then
    echo "✅ backend_server binary is up-to-date, skipping build"
else
    echo "🔨 Building backend server..."
    cd "$PERF_DIR"
    cargo build --release --bin backend_server
fi

# Start backend server in background
echo "🌐 Starting backend server..."
"$PERF_DIR/target/release/backend_server" > "$PERF_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

# Wait for backend to start
sleep 2

# Test backend directly
echo "🧪 Testing backend server..."
if curl -s "http://localhost:3001/health" | grep -q "healthy"; then
    echo "✅ Backend server is working"
else
    echo "❌ Backend server failed to start"
    cat "$PERF_DIR/backend.log"
    kill $BACKEND_PID
    exit 1
fi

# Run a quick wrk test
echo "⚡ Running quick load test (5s)..."
wrk -t2 -c10 -d5s --latency "http://localhost:3001/health" > "$PERF_DIR/quick_test.txt"

echo "📊 Quick test results:"
grep -E "(Requests/sec|Latency)" "$PERF_DIR/quick_test.txt"

# Cleanup
kill $BACKEND_PID
echo "✅ Backend server stopped"

echo ""
echo "🎉 Quick test completed successfully!"
echo "📄 Full results saved to: $PERF_DIR/quick_test.txt"
echo ""
echo "To run the full performance test suite:"
echo "  cd $PERF_DIR"
echo "  ./run_perf_test.sh"
