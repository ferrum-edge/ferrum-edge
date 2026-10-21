#!/usr/bin/env bash
# Isolated experimental production ranking. Runtime images are immutable.
set -euo pipefail
export FERRUM_IMAGE=ferrumedge/ferrum-edge@sha256:e95e7f8d0d19e5714cb4e93afb600ebe14a1703aab51e84ad5c2be822d82a4af
export ENVOY_IMAGE=envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4
export CONSUL_IMAGE=hashicorp/consul@sha256:842ee8b5d0ea228b6c36230a442bcf13b7f92bbe35091676f4482eaa933a6ad7
export TOOLS_IMAGE=mesh-bench-tools:production
export BENCH_CARGO_PROFILE=release BENCH_FERRUM_FEATURES=cloud-secrets
export BENCH_WORKERS=4 BENCH_PRODUCTION_OBSERVE=true
# Only the explicit diagnostic phase may wire this existing runtime setting.
if [ -n "${BENCH_H1_IDLE_DESTINATION_CAP:-}" ] && [ "${BENCH_PHASE:-smoke-l7}" != h1-idle-diagnostic ]; then
    echo "[production] H1 idle override is forbidden outside its diagnostic phase" >&2
    exit 2
fi
unset BENCH_H1_IDLE_DESTINATION_CAP
observation_campaign=false
case "${BENCH_PHASE:-smoke-l7}" in ranking|h1-idle-diagnostic) observation_campaign=true ;; esac
mode="${1:?prepare or measure}"
if [ "$mode" = prepare ]; then
    mkdir -p results/images
    python3 .github/scripts/mesh_production_campaign.py plan
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
    timeout 20s docker run --rm "$FERRUM_IMAGE" version --json > results/images/ferrum-version.txt
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
        unset BENCH_H1_IDLE_DESTINATION_CAP
        if [ "${BENCH_PHASE:-smoke-l7}" = h1-idle-diagnostic ]; then
            physical=ferrum
            case "$arm" in
                h1idle64a|h1idle64b) export BENCH_H1_IDLE_DESTINATION_CAP=64 ;;
                h1idle128) export BENCH_H1_IDLE_DESTINATION_CAP=128 ;;
                *) echo "[production] unexpected idle diagnostic arm" >&2; exit 2 ;;
            esac
        fi
        export BENCH_RATE="$rate"
        directory="results/$arm/$load/run_$repetition/payload_$payload"
        mkdir -p "$directory"
        if [ -e "$directory/${physical}_http1_${payload}.json" ] || [ -e "$directory/${physical}_http1_${payload}.resources.json" ]; then
            echo "[production] refusing to reuse an existing planned observation: $directory" >&2
            exit 1
        fi
        classification_args=(classify --arm "$arm" --payload "$payload" --repetition "$repetition"
            --load "$load" --duration "$duration" --rate "$rate")
        if $observation_campaign; then classification_args+=(--measurement-only); fi
        echo "[production] arm=$arm physical=$physical payload=$payload repetition=$repetition load=$load rate=$rate"
        if timeout --signal=TERM --kill-after=10s "$((duration+420))s"             bash tests/performance/mesh_runtime/run_mesh_runtime_bench.sh "$physical"             --payload-sizes "$payload" --duration "$duration" --concurrency 100 --warmup 3             --output-dir "$directory" --skip-build 2>&1 | tee "$directory/run.log"; then
            python3 .github/scripts/mesh_production_campaign.py "${classification_args[@]}" --runner-exit-code 0
        else
            pipeline_status=("${PIPESTATUS[@]}")
            # Only an ordinary cell rc=1 can be retained as an observation.
            # Timeouts/signals, failed log capture, auth/fixture failures and
            # incomplete/resource-invalid reports still stop this campaign.
            if $observation_campaign && [ "${pipeline_status[0]}" -eq 1 ] && [ "${pipeline_status[1]}" -eq 0 ] \
                && python3 .github/scripts/mesh_production_campaign.py "${classification_args[@]}" --runner-exit-code 1; then
                echo "[production] retained error-inclusive observation; zero-error capacity SLO remains failed" >&2
                continue
            fi
            echo "[production] unqualified cell; stopping with every planned outcome retained" >&2
            exit 1
        fi
    done < results/production-plan.txt
else
    exit 2
fi
