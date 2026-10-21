#!/usr/bin/env bash
# A diagnostic observer qualification, separate from production rankings.
set -euo pipefail
mode="${1:?prepare or measure}"
arm="${BENCH_PROFILE_ARM:-envoy}"
case "$arm" in envoy|ferrum) ;; *) echo "unsupported profile arm" >&2; exit 2 ;; esac
if [ "$mode" = prepare ]; then
    BENCH_PHASE=smoke-l7 bash .github/scripts/mesh_production_campaign.sh prepare
    if [ "$arm" = envoy ]; then
        bash .github/scripts/mesh_production_profile_symbols.sh "$RUNNER_TEMP/mesh-symbol-preflight"
        cp "$RUNNER_TEMP/mesh-symbol-preflight/report.json" results/envoy-symbol-qualification.json
    else
        test -s "${BENCH_SYMBOL_ELF:?qualified Ferrum companion required}"
        test -s "${BENCH_SYMBOL_REPORT:?Ferrum qualification report required}"
        cp "$BENCH_SYMBOL_REPORT" results/ferrum-symbol-qualification.json
    fi
    perf --version > results/perf-version.txt
elif [ "$mode" = measure ]; then
    export FERRUM_IMAGE=ferrumedge/ferrum-edge@sha256:e95e7f8d0d19e5714cb4e93afb600ebe14a1703aab51e84ad5c2be822d82a4af
    export ENVOY_IMAGE=envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4
    export TOOLS_IMAGE=mesh-bench-tools:production
    export BENCH_CARGO_PROFILE=release BENCH_FERRUM_FEATURES=cloud-secrets
    export BENCH_WORKERS=4 BENCH_PRODUCTION_OBSERVE=true BENCH_RATE=0
    if [ "$arm" = envoy ]; then
        export BENCH_SYMBOL_ELF="$RUNNER_TEMP/mesh-symbol-preflight/debug/envoy"
        export BENCH_SYMBOL_REPORT="$RUNNER_TEMP/mesh-symbol-preflight/report.json"
    else
        export BENCH_SYMBOL_ELF BENCH_SYMBOL_REPORT
    fi
    failed=0
    for phase in before profile after; do
        export BENCH_PERF_LEAF=false
        if [ "$phase" = profile ]; then export BENCH_PERF_LEAF=true; fi
        directory="results/profile-$arm/$phase/payload_1024"
        mkdir -p "$directory"
        if timeout --signal=TERM --kill-after=10s 450s \
            bash tests/performance/mesh_runtime/run_mesh_runtime_bench.sh "$arm" \
            --payload-sizes 1024 --duration 30 --concurrency 100 --warmup 3 \
            --output-dir "$directory" --skip-build 2>&1 | tee "$directory/run.log"; then
            :
        else
            failed=1
            echo "[profile] $phase failed; retaining it and completing the prescribed bracket" >&2
        fi
    done
    exit "$failed"
else
    exit 2
fi
