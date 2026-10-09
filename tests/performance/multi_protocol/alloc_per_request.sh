#!/usr/bin/env bash
# Allocator calls per proxied request on each Ferrum dispatch path (#6022 item 1).
#
# Builds `ferrum-edge` with the default-off `bench-h1-profile` feature. Its
# forwarding global allocator counts every Rust allocator call in the process
# and appends the totals to the existing `/metrics` response
# (docs/h1_internal_profile.md); no other code changes with the feature. For
# each path the gateway runs natively, is warmed, has its counters scraped,
# serves a fixed closed-loop proto_bench load, and is scraped again. Allocator
# calls divided by the echoes the backend served in between give the
# per-request figure:
#
#   h1          HTTP/1.1 client -> HTTP/1.1 backend (default direct hyper pool)
#   h1-reqwest  the same with FERRUM_POOL_HTTP1_DIRECT=false (reqwest dispatch)
#   h2          HTTP/2+TLS client -> HTTP/2+TLS backend (direct HTTP/2 pool)
#   grpc        gRPC+TLS client -> gRPC+TLS backend (gRPC pool)
#   h3          HTTP/3 client -> HTTP/3 backend (native HTTP/3 pool)
#
# With --baseline SHA the same feature/profile build of that commit runs in
# the same rounds on this host, candidate and baseline alternating order.
#
# Usage: alloc_per_request.sh --output DIR [--baseline SHA]
#          [--profile release|ci-release] [--paths "h1 h1-reqwest h2 grpc h3"]
#          [--duration N] [--warmup N] [--concurrency N] [--payload-size N]
#          [--rounds N]
#
# Linux only (process accounting and ports via /proc and lsof). Writes
# raw/<path>/<role>-r<round>/ plus summary.json and summary.md under DIR.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"

OUTPUT=""
BASELINE=""
PROFILE=release
PATHS="h1 h1-reqwest h2 grpc h3"
DURATION=20
WARMUP=3
CONCURRENCY=32
PAYLOAD=1024
ROUNDS=3

while [[ $# -gt 0 ]]; do
    case $1 in
        --output) OUTPUT="$2"; shift 2 ;;
        --baseline) BASELINE="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --paths) PATHS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --warmup) WARMUP="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --payload-size) PAYLOAD="$2"; shift 2 ;;
        --rounds) ROUNDS="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# Every value below reaches arithmetic, a path or a command line: validate first.
[ -n "$OUTPUT" ] || { echo "--output is required" >&2; exit 2; }
if [ -n "$BASELINE" ] && [[ ! $BASELINE =~ ^[0-9a-f]{40}$ ]]; then
    echo "--baseline must be a full 40-hex commit SHA" >&2
    exit 2
fi
case "$PROFILE" in release|ci-release) ;; *) echo "--profile must be release or ci-release" >&2; exit 2 ;; esac
for value in "$DURATION" "$WARMUP" "$CONCURRENCY" "$PAYLOAD" "$ROUNDS"; do
    if [[ ! $value =~ ^[1-9][0-9]{0,5}$ ]]; then
        echo "--duration/--warmup/--concurrency/--payload-size/--rounds must be positive integers" >&2
        exit 2
    fi
done
[ -n "$PATHS" ] || { echo "--paths must name at least one path" >&2; exit 2; }
for path in $PATHS; do
    case "$path" in h1|h1-reqwest|h2|grpc|h3) ;; *) echo "unknown path: $path" >&2; exit 2 ;; esac
done

GATEWAY_HTTP_PORT=8000
GATEWAY_HTTPS_PORT=8443
ADMIN_PORT=9000
METRICS_URL="http://127.0.0.1:$ADMIN_PORT/metrics"
BACKEND_STATS_URL="http://127.0.0.1:3010/bench-stats"
# Every fixed port proto_backend and the gateway bind (admin HTTPS included).
BENCH_PORTS="3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 3446 3447 \
50052 50053 $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT $ADMIN_PORT 9443"

BACKEND_PID=""
GATEWAY_PID=""
WORK=""

# Gracefully stop a PID this run started: TERM, bounded wait, then KILL.
stop_pid() {
    local pid="$1"
    local attempt
    [ -z "$pid" ] && return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

# Refuse a port that is already bound instead of killing its owner.
check_port_available() {
    local port="$1"
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "[error] required TCP port $port is already in use; inspect with: lsof -nP -iTCP:$port -sTCP:LISTEN" >&2
        return 1
    fi
    if lsof -nP -iUDP:"$port" >/dev/null 2>&1; then
        echo "[error] required UDP port $port is already in use; inspect with: lsof -nP -iUDP:$port" >&2
        return 1
    fi
}

check_ports_available() {
    if ! command -v lsof >/dev/null 2>&1; then
        echo "[error] lsof is required to detect port conflicts before starting." >&2
        return 1
    fi
    local port
    for port in $BENCH_PORTS; do
        check_port_available "$port" || return 1
    done
}

cleanup() {
    echo "[cleanup] stopping processes this run started..."
    stop_pid "$GATEWAY_PID"
    stop_pid "$BACKEND_PID"
}
trap cleanup EXIT

mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
if [ -n "$(ls -A "$OUTPUT")" ]; then
    echo "--output must be a new or empty directory; stale results cannot be reused" >&2
    exit 2
fi
check_ports_available || exit 1
WORK="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ferrum-alloc.XXXXXX")"

# ── Builds ───────────────────────────────────────────────────────────────────
# Build one revision's gateway with the counting allocator and keep only the
# binary and its identity; the source tree's target directory is its own.
build_gateway() {
    local role="$1" source="$2"
    if ! grep -q '^bench-h1-profile = ' "$source/Cargo.toml"; then
        echo "[build] the $role revision has no bench-h1-profile feature" >&2
        return 1
    fi
    echo "[build] $role: cargo build --profile $PROFILE --features bench-h1-profile"
    (
        cd "$source"
        CARGO_TARGET_DIR="$source/target" cargo build --locked --profile "$PROFILE" \
            --features bench-h1-profile --bin ferrum-edge
    )
    # Staged at the build-output path the Cross policy recognizes, whatever
    # profile produced it, so the launch below names no repository command.
    mkdir -p "$WORK/$role/target/release"
    cp "$source/target/$PROFILE/ferrum-edge" "$WORK/$role/target/release/ferrum-edge"
    git -C "$source" rev-parse HEAD > "$OUTPUT/$role-revision.txt"
    (cd "$WORK/$role" && sha256sum target/release/ferrum-edge) > "$OUTPUT/$role-binary.sha256"
}

ROLES="candidate"
if [ -n "$BASELINE" ]; then
    git -C "$PROJECT_ROOT" cat-file -e "$BASELINE^{commit}"
    git -C "$PROJECT_ROOT" -c core.hooksPath=/dev/null worktree add --detach \
        "$WORK/baseline-src" "$BASELINE"
    build_gateway baseline "$WORK/baseline-src"
    # Only the copied binary is needed; free the runner's disk for the next build.
    rm -rf "$WORK/baseline-src/target"
    ROLES="candidate baseline"
fi
build_gateway candidate "$PROJECT_ROOT"
echo "[build] proto_bench/proto_backend (harness tools, dispatched revision)"
(cd "$SCRIPT_DIR" && cargo build --locked --release --bin proto_bench --bin proto_backend)
rustc -Vv > "$OUTPUT/rustc-version.txt"
lscpu > "$OUTPUT/cpu.txt" 2>/dev/null || true

# ── Backend ──────────────────────────────────────────────────────────────────
# One echo backend serves every run; its counters are cumulative and each run
# reads its own before/after difference.
(cd "$SCRIPT_DIR" && exec ./target/release/proto_backend) > "$OUTPUT/backend.log" 2>&1 &
BACKEND_PID=$!
backend_ready=false
for attempt in $(seq 1 40); do
    if curl -sf "$BACKEND_STATS_URL" >/dev/null 2>&1 \
        && [ -f "$CERT_DIR/ca.pem" ] && [ -f "$CERT_DIR/cert.pem" ]; then
        backend_ready=true
        break
    fi
    sleep 0.5
done
if [ "$backend_ready" != true ]; then
    echo "[backend] failed to start" >&2
    tail -30 "$OUTPUT/backend.log" >&2 || true
    exit 1
fi

# ── Per-path settings ────────────────────────────────────────────────────────
config_name() {
    case "$1" in
        h1|h1-reqwest) echo "http1_perf.yaml" ;;
        h2) echo "http2_perf.yaml" ;;
        grpc) echo "grpcs_e2e_perf.yaml" ;;
        h3) echo "http3_perf.yaml" ;;
    esac
}

start_gateway() {
    local role="$1" path="$2" dir="$3"
    sed -e "s|CA_PATH|$CERT_DIR/ca.pem|g" "$SCRIPT_DIR/configs/$(config_name "$path")" \
        > "$dir/config.yaml"
    (
        # Only the settings below: an ambient FERRUM_* must not change the path.
        for name in $(compgen -e); do
            case "$name" in FERRUM_*) unset "$name" ;; esac
        done
        export FERRUM_MODE=file
        export FERRUM_FILE_CONFIG_PATH="$dir/config.yaml"
        export FERRUM_PROXY_HTTP_PORT="$GATEWAY_HTTP_PORT"
        export FERRUM_PROXY_HTTPS_PORT="$GATEWAY_HTTPS_PORT"
        export FERRUM_FRONTEND_TLS_CERT_PATH="$CERT_DIR/cert.pem"
        export FERRUM_FRONTEND_TLS_KEY_PATH="$CERT_DIR/key.pem"
        export FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1
        export FERRUM_ADMIN_HTTP_PORT="$ADMIN_PORT"
        export FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32
        export FERRUM_LOG_LEVEL=error
        # Warmup records backend capabilities before traffic, so h2 and h3
        # requests take the direct HTTP/2 and native HTTP/3 pools.
        export FERRUM_POOL_WARMUP_ENABLED=true
        if [ "$path" = h1-reqwest ]; then
            export FERRUM_POOL_HTTP1_DIRECT=false
        fi
        if [ "$path" = h3 ]; then
            export FERRUM_ENABLE_HTTP3=true
        fi
        cd "$WORK/$role"
        exec ./target/release/ferrum-edge run
    ) > "$dir/gateway.log" 2>&1 &
    GATEWAY_PID=$!
    local attempt
    for attempt in $(seq 1 60); do
        if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then
            echo "[gateway] $role/$path exited during startup" >&2
            return 1
        fi
        if curl -sf "$METRICS_URL" 2>/dev/null | grep -q '^ferrum_h1_profile_allocator_installed 1$' \
            && curl -sf -o /dev/null "http://127.0.0.1:$GATEWAY_HTTP_PORT/health" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    echo "[gateway] $role/$path not ready after 30s" >&2
    return 1
}

stop_gateway() {
    stop_pid "$GATEWAY_PID"
    GATEWAY_PID=""
    # The next gateway binds the same ports.
    local attempt
    for attempt in $(seq 1 20); do
        if ! lsof -nP -iTCP:"$GATEWAY_HTTPS_PORT" -sTCP:LISTEN >/dev/null 2>&1 \
            && ! lsof -nP -iTCP:"$ADMIN_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
}

run_client() {
    local path="$1" duration="$2" out="$3"
    local common=(--duration "$duration" --concurrency "$CONCURRENCY"
                  --payload-size "$PAYLOAD" --json)
    local target="https://127.0.0.1:$GATEWAY_HTTPS_PORT/echo"
    case "$path" in
        h1|h1-reqwest)
            "$SCRIPT_DIR/target/release/proto_bench" http1 \
                --target "http://127.0.0.1:$GATEWAY_HTTP_PORT/echo" "${common[@]}" ;;
        h2)
            "$SCRIPT_DIR/target/release/proto_bench" http2 --target "$target" "${common[@]}" ;;
        grpc)
            "$SCRIPT_DIR/target/release/proto_bench" grpc \
                --target "https://127.0.0.1:$GATEWAY_HTTPS_PORT" \
                --ca-cert "$CERT_DIR/ca.pem" "${common[@]}" ;;
        h3)
            "$SCRIPT_DIR/target/release/proto_bench" http3 --target "$target" "${common[@]}" ;;
    esac > "$out" 2> "${out%.json}.err"
}

snapshot() {
    local dir="$1" label="$2"
    date +%s.%N > "$dir/time_$label.txt"
    curl -sf --max-time 10 "$METRICS_URL" > "$dir/metrics_$label.txt" || true
    curl -sf --max-time 10 "$BACKEND_STATS_URL" > "$dir/backend_$label.json" || true
}

# One measurement: a fresh gateway, warmup load, then the counted window.
measure() {
    local role="$1" path="$2" round="$3"
    local dir="$OUTPUT/raw/$path/$role-r$round"
    mkdir -p "$dir"
    echo "[measure] round $round $path $role"
    if ! start_gateway "$role" "$path" "$dir"; then
        stop_gateway
        echo "gateway did not start" > "$dir/failure.txt"
        return 0
    fi
    run_client "$path" "$WARMUP" "$dir/warmup.json" || true
    snapshot "$dir" before
    local rc=0
    run_client "$path" "$DURATION" "$dir/client.json" || rc=$?
    snapshot "$dir" after
    # Idle background rate on the same process, for the error estimate.
    sleep 5
    snapshot "$dir" idle
    echo "$rc" > "$dir/client.exit"
    stop_gateway
}

for round in $(seq 1 "$ROUNDS"); do
    order="$ROLES"
    if [ -n "$BASELINE" ] && [ $(( round % 2 )) -eq 0 ]; then
        order="baseline candidate"
    fi
    for path in $PATHS; do
        for role in $order; do
            measure "$role" "$path" "$round"
        done
    done
done

python3 "$SCRIPT_DIR/alloc_per_request.py" summarize "$OUTPUT" \
    --paths "$PATHS" --roles "$ROLES" --rounds "$ROUNDS" \
    --profile "$PROFILE" --duration "$DURATION" --concurrency "$CONCURRENCY" \
    --payload-size "$PAYLOAD"
