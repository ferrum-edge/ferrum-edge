#!/bin/bash
# Run all multi-protocol performance tests
# This is a convenience wrapper around run_protocol_test.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/run_protocol_test.sh" all "$@"
