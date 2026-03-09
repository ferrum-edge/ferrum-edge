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

# Build backend server
echo "🔨 Building backend server..."
cd "$PERF_DIR"
cargo build --release --bin backend_server

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
