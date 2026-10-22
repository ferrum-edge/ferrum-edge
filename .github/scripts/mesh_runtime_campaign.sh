#!/usr/bin/env bash
# Literal executable dispatch for the trusted Cross policy; Python owns data.
set -euo pipefail
mode="${1:?build or measure}"
if [ "$mode" = build ]; then
    profile="${BENCH_CARGO_PROFILE:-release}"
    features="${BENCH_FERRUM_FEATURES:-cloud-secrets}"
    baseline="${BENCH_BASELINE_SHA:-}"
    case "$profile" in release|ci-release) ;; *) exit 2 ;; esac
    case "$features" in cloud-secrets|cloud-secrets,bench-h1-profile) ;; *) exit 2 ;; esac
    if [ -n "$baseline" ] && [[ ! "$baseline" =~ ^[0-9a-f]{40}$ ]]; then
        echo 'baseline must be an exact 40-hex SHA' >&2; exit 2
    fi
    bash tests/performance/mesh_runtime/run_mesh_runtime_bench.sh --build-only --output-dir results/images
    docker create --name meshbench-candidate-hash ferrum-edge:bench >/dev/null
    docker cp meshbench-candidate-hash:/app/ferrum-edge "$RUNNER_TEMP/mesh-candidate-binary"
    sha256sum "$RUNNER_TEMP/mesh-candidate-binary" > results/images/candidate-binary.sha256
    rm "$RUNNER_TEMP/mesh-candidate-binary"
    docker rm meshbench-candidate-hash >/dev/null
    if [ -n "$baseline" ]; then
        if [ "$baseline" = "$(git rev-parse HEAD)" ]; then
            # Exact-image A/A control: a same-source rebuild can differ in
            # bytes and must not spend a second compile to answer this check.
            docker tag ferrum-edge:bench ferrum-edge:baseline
        else
            baseline_source="${RUNNER_TEMP:?}/mesh-baseline-source"
            # Branch/tag history does not include unmerged PR heads.
            git cat-file -e "$baseline^{commit}" 2>/dev/null || git fetch --no-tags origin "$baseline"
            git worktree add --detach "$baseline_source" "$baseline"
            trap 'git worktree remove "$baseline_source"' EXIT
            docker build --build-arg "CARGO_PROFILE=$profile" --build-arg "FEATURES=$features" \
                -t ferrum-edge:baseline -f "$baseline_source/Dockerfile" "$baseline_source" \
                > results/images/baseline-build.log 2>&1
            git worktree remove "$baseline_source"
            trap - EXIT
        fi
        docker create --name meshbench-baseline-hash ferrum-edge:baseline >/dev/null
        docker cp meshbench-baseline-hash:/app/ferrum-edge "$RUNNER_TEMP/mesh-baseline-binary"
        sha256sum "$RUNNER_TEMP/mesh-baseline-binary" > results/images/baseline-binary.sha256
        rm "$RUNNER_TEMP/mesh-baseline-binary"
        docker rm meshbench-baseline-hash >/dev/null
    fi
    python3 .github/scripts/mesh_runtime_campaign.py provenance
elif [ "$mode" = measure ]; then
    python3 .github/scripts/mesh_runtime_campaign.py plan
    failed=0
    while read -r arm payload repetition; do
        measured_arm="$arm"
        export FERRUM_IMAGE=ferrum-edge:bench
        if [ "$arm" = ferrumbaseline ]; then
            measured_arm=ferrum
            export FERRUM_IMAGE=ferrum-edge:baseline
        fi
        directory="results/$arm/run_$repetition/payload_$payload"
        mkdir -p "$directory"
        echo "arm=$arm payload=$payload repetition=$repetition"
        arm_budget=$((BENCH_DURATION + 420))
        if timeout --signal=TERM --kill-after=10s "${arm_budget}s" \
            bash tests/performance/mesh_runtime/run_mesh_runtime_bench.sh "$measured_arm" \
            --payload-sizes "$payload" --duration "$BENCH_DURATION" --concurrency "$BENCH_CONCURRENCY" \
            --output-dir "$directory" --skip-build < /dev/null 2>&1 | tee "$directory/run.log"; then
            :
        else
            failed=1
            tail -50 "$directory/run.log"
        fi
        if [ "$arm" = ferrumbaseline ]; then
            python3 .github/scripts/mesh_runtime_campaign.py relabel --results "$directory"
        fi
        if [ "$failed" -ne 0 ]; then
            echo "[campaign] stopping after failed arm; remaining planned cells stay missing" >&2
            break
        fi
    done < results/plan.txt
    exit "$failed"
else
    exit 2
fi
