#!/usr/bin/env bash
# Isolated experimental production ranking. Runtime images are immutable.
set -euo pipefail
export FERRUM_IMAGE=ghcr.io/ferrum-edge/ferrum-edge@sha256:e95e7f8d0d19e5714cb4e93afb600ebe14a1703aab51e84ad5c2be822d82a4af
export ENVOY_IMAGE=envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4
export CONSUL_IMAGE=hashicorp/consul@sha256:842ee8b5d0ea228b6c36230a442bcf13b7f92bbe35091676f4482eaa933a6ad7
export TOOLS_IMAGE=mesh-bench-tools:production
export BENCH_CARGO_PROFILE=release BENCH_FERRUM_FEATURES=cloud-secrets
export BENCH_WORKERS=4 BENCH_PRODUCTION_OBSERVE=true
mode="${1:?prepare or measure}"
if [ "$mode" = prepare ]; then
    mkdir -p results/images
    for image in "$FERRUM_IMAGE" "$ENVOY_IMAGE" "$CONSUL_IMAGE"; do
        timeout --signal=TERM --kill-after=10s 300s docker pull "$image"
    done
    docker inspect "$FERRUM_IMAGE" "$ENVOY_IMAGE" "$CONSUL_IMAGE" > results/images/inspect.json
    docker create --name meshbench-production-identity "$FERRUM_IMAGE" >/dev/null
    docker cp meshbench-production-identity:/app/ferrum-edge "$RUNNER_TEMP/mesh-production-binary"
    sha256sum "$RUNNER_TEMP/mesh-production-binary" > results/images/ferrum-binary.sha256
    readelf -n "$RUNNER_TEMP/mesh-production-binary" > results/images/ferrum-elf-notes.txt
    readelf -S "$RUNNER_TEMP/mesh-production-binary" > results/images/ferrum-elf-sections.txt
    rm "$RUNNER_TEMP/mesh-production-binary"
    docker rm meshbench-production-identity >/dev/null
    timeout 20s docker run --rm "$FERRUM_IMAGE" --version > results/images/ferrum-version.txt
    timeout 20s docker run --rm "$ENVOY_IMAGE" --version > results/images/envoy-version.txt
    timeout 20s docker run --rm "$CONSUL_IMAGE" version > results/images/consul-version.txt
    docker build -f tests/performance/mesh_runtime/Dockerfile.production-tools -t "$TOOLS_IMAGE" tests/performance/mesh_runtime         > results/images/tools-build.log 2>&1 || { tail -80 results/images/tools-build.log; exit 1; }
    docker inspect "$TOOLS_IMAGE" > results/images/tools-inspect.json
    python3 .github/scripts/mesh_production_campaign.py provenance
elif [ "$mode" = measure ]; then
    python3 .github/scripts/mesh_production_campaign.py plan
    while read -r arm payload repetition load duration rate; do
        physical="$arm"
        case "$arm" in ferruma|ferrumb) physical=ferrum ;; ferrumtcpa|ferrumtcpb) physical=ferrumtcp ;; esac
        export BENCH_RATE="$rate"
        directory="results/$arm/$load/run_$repetition/payload_$payload"
        mkdir -p "$directory"
        echo "[production] arm=$arm physical=$physical payload=$payload repetition=$repetition load=$load rate=$rate"
        if timeout --signal=TERM --kill-after=10s "$((duration+420))s"             bash tests/performance/mesh_runtime/run_mesh_runtime_bench.sh "$physical"             --payload-sizes "$payload" --duration "$duration" --concurrency 100 --warmup 3             --output-dir "$directory" --skip-build 2>&1 | tee "$directory/run.log"; then
            :
        else
            echo "[production] invalid cell; stopping with every planned outcome retained" >&2
            exit 1
        fi
    done < results/production-plan.txt
else
    exit 2
fi
