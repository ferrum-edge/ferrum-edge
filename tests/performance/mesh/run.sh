#!/bin/bash
# Mesh performance bench runner for Ferrum Edge.
# Usage: ./run.sh [bench-name] [--skip-build] [--filter <criterion-filter>]
#   bench-name: authz_match | slice_apply | xds_translation | ip_restriction | all
#               (default: all)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BENCH="all"
SKIP_BUILD=false
FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --filter) FILTER="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [bench-name] [--skip-build] [--filter <criterion-filter>]"
            echo "  bench-name: authz_match | slice_apply | xds_translation | ip_restriction | all (default: all)"
            exit 0
            ;;
        *)
            if [[ "$1" == "authz_match" || "$1" == "slice_apply" || "$1" == "xds_translation" || "$1" == "ip_restriction" || "$1" == "all" ]]; then
                BENCH="$1"
            else
                echo "Unknown argument: $1" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ "$SKIP_BUILD" == "false" ]]; then
    echo "[mesh-perf] cargo build --release (use --skip-build to skip)"
    cargo build --release --benches
fi

run_one() {
    local name="$1"
    echo
    echo "==== bench: $name ===="
    if [[ -n "$FILTER" ]]; then
        cargo bench --bench "$name" -- "$FILTER"
    else
        cargo bench --bench "$name"
    fi
}

if [[ "$BENCH" == "all" ]]; then
    run_one authz_match
    run_one slice_apply
    run_one xds_translation
    run_one ip_restriction
else
    run_one "$BENCH"
fi

echo
echo "[mesh-perf] HTML reports: target/criterion/<bench>/<id>/report/index.html"
