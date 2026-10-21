#!/usr/bin/env bash
# Fixed manual confirmation, literal executable dispatch for trusted CI policy.
set -euo pipefail
mode="${1:-${TAIL_OPERATION:-}}"
case "$mode" in
    build)
        candidate=7c4e45b82e656c62b7133d86b23c7e37a2ef3b77
        baseline=4a7be250e45a367314e3dec872ecbd512220558e
        mkdir -p results/images
        lscpu > results/images/lscpu.txt
        uname -a > results/images/uname.txt
        free -b > results/images/memory.txt
        timeout --signal=TERM --kill-after=2s 10s docker version > results/images/docker.txt
        git diff --exit-code "$candidate" -- src tests/unit Cargo.toml Cargo.lock Dockerfile
        sources=$(mktemp -d "${RUNNER_TEMP:?}/mesh-tail-sources.XXXXXX")
        cleanup() {
            timeout --signal=KILL 5s docker rm -f mesh-tail-hash-candidate mesh-tail-hash-baseline >/dev/null 2>&1 || true
            for role in candidate baseline; do
                if [ -d "$sources/$role" ]; then git worktree remove --force "$sources/$role"; fi
            done
            rm -rf "$sources"
        }
        trap cleanup EXIT
        # The dispatched tree supplies only harness code. Compile both exact
        # reviewed runtime sources with their own Dockerfiles and equal flags.
        for role in baseline candidate; do
            revision="$baseline"
            if [ "$role" = candidate ]; then revision="$candidate"; fi
            [ "$(git rev-parse "${revision}^{commit}")" = "$revision" ]
            git worktree add --detach "$sources/$role" "$revision"
            git -C "$sources/$role" rev-parse HEAD > "results/images/$role.source-sha"
            sha256sum "$sources/$role/Dockerfile" > "results/images/$role.dockerfile.sha256"
            docker build --build-arg CARGO_PROFILE=release --build-arg FEATURES=cloud-secrets \
                --label "org.opencontainers.image.revision=$revision" \
                --label io.ferrum.benchmark.profile=release --label io.ferrum.benchmark.features=cloud-secrets \
                -t "ferrum-edge:tail-$role" -f "$sources/$role/Dockerfile" "$sources/$role" \
                2>&1 | tee "results/images/$role.build.log"
            timeout --signal=TERM --kill-after=2s 10s docker image inspect "ferrum-edge:tail-$role" > "results/images/$role.image.json"
            timeout --signal=TERM --kill-after=2s 10s docker create --name "mesh-tail-hash-$role" "ferrum-edge:tail-$role" >/dev/null
            timeout --signal=TERM --kill-after=2s 10s docker cp "mesh-tail-hash-$role:/app/ferrum-edge" "$sources/$role.binary"
            sha256sum "$sources/$role.binary" > "results/images/$role.binary.sha256"
            timeout --signal=TERM --kill-after=2s 10s docker rm "mesh-tail-hash-$role" >/dev/null
        done
        docker build -f tests/performance/mesh_runtime/Dockerfile.tools -t mesh-bench-tools:tail \
            tests/performance/mesh_runtime 2>&1 | tee results/images/tools.build.log
        timeout --signal=TERM --kill-after=2s 10s docker image inspect mesh-bench-tools:tail > results/images/tools.image.json
        ;;
    mesh-cell)
        case "$TAIL_PAYLOAD" in 1048576|5242880) ;; *) exit 2 ;; esac
        export BENCH_CARGO_PROFILE=release BENCH_FERRUM_FEATURES=cloud-secrets
        exec bash tests/performance/mesh_runtime/run_mesh_runtime_bench.sh ferrum \
            --payload-sizes "$TAIL_PAYLOAD" --duration 30 --concurrency 100 --warmup 2 \
            --output-dir "$TAIL_OUTPUT" --skip-build
        ;;
    mesh-cleanup)
        [[ "$MESH_BENCH_RUN_ID" =~ ^[0-9a-f]{32}-[0-9]+$ ]] || exit 2
        prefix="meshbench-ferrum-$MESH_BENCH_RUN_ID"
        for role in client server; do
            timeout --signal=TERM --kill-after=2s 5s docker logs --timestamps "$prefix-$role" \
                > "$TAIL_OUTPUT/$role.cleanup.log" 2>&1 || true
        done
        timeout --signal=TERM --kill-after=2s 10s docker rm -f \
            "$prefix-client" "$prefix-server" "$prefix-backend" "$prefix-agent" "$prefix-probe" "$prefix-loadgen" >/dev/null 2>&1 || true
        remaining=$(timeout --signal=TERM --kill-after=2s 10s docker ps --all --quiet \
            --filter "name=^/$prefix-(client|server|backend|agent|probe|loadgen)$")
        [ -z "$remaining" ]
        ;;
    *) exit 2 ;;
esac
