#!/bin/bash
# Concurrent-connection saturation benchmark.
#
# Finds the "breaking point" — the smallest N at which a gateway can no longer
# sustain N long-lived HTTP/1.1+TLS connections — for ferrum-edge, envoy, kong,
# tyk, and krakend. Each gateway holds N connections that send a low-rate
# heartbeat; the harness ramps N upward until the first failure (verdict
# "broken" from proto_bench saturate). The whole stack runs in Docker with
# --network host so no gateway gets a native-binary advantage.
#
# This is distinct from run_gateway_protocol_bench.sh which measures RPS at a
# fixed concurrency. Here we measure capacity, not throughput.
#
# Usage: ./run_connection_saturation_bench.sh [options]
#
# Options:
#   --gateways "ferrum envoy kong tyk krakend"
#                                        # Subset to test (default: all five)
#   --connection-levels "1000 5000 10000 25000 50000"
#                                        # N values to ramp through
#   --ramp-seconds 30                    # Spread connection attempts over this
#   --hold-seconds 30                    # Hold open + heartbeat for this long
#   --heartbeat-interval-ms 1000         # Per-connection request rate
#   --output-dir /tmp/connection-saturation-results
#   --skip-build                         # Reuse existing binaries + ferrum image
#   --stop-at-first-break                # Skip remaining N values after breakage
#                                        # (default: keep going to characterize
#                                        #  the failure curve)
#
# Per-(gateway, N) JSON is written to <output-dir>/<gateway>_<N>.json plus a
# summary.json with per-gateway breaking points.
#
# IMPORTANT: requires a high FD ceiling. On Linux:
#     ulimit -n 1048576
#     sysctl -w net.ipv4.ip_local_port_range="1024 65535"
#     sysctl -w net.core.somaxconn=65535
#     sysctl -w net.ipv4.tcp_max_syn_backlog=65535
# macOS hits ~12K FD ceiling and is not suitable for headline numbers — use
# Linux (CI or bare metal). Script warns if soft ulimit is below the highest N.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

# ── Portable `timeout` command (GNU coreutils) ──────────────────────────────
# Bound each saturate run so a hung proto_bench (stuck socket/task or a
# gateway that never accepts) doesn't block the whole matrix until the
# job-level timeout fires. macOS/BSD ships without `timeout`; Homebrew
# installs it as `gtimeout`. Mirrors the helper in run_gateway_protocol_bench.sh.
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    TIMEOUT_CMD=""
    echo "[warn] Neither 'timeout' nor 'gtimeout' found — saturate runs will have no per-N kill-switch" >&2
fi

# ── Defaults ─────────────────────────────────────────────────────────────────
GATEWAYS="ferrum envoy kong tyk krakend"
CONNECTION_LEVELS="1000 5000 10000 25000 50000"
RAMP_SECONDS=30
HOLD_SECONDS=30
HEARTBEAT_MS=1000
OUTPUT_DIR="/tmp/connection-saturation-results"
SKIP_BUILD=false
STOP_AT_FIRST_BREAK=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --gateways) GATEWAYS="$2"; shift 2 ;;
        --connection-levels) CONNECTION_LEVELS="$2"; shift 2 ;;
        --ramp-seconds) RAMP_SECONDS="$2"; shift 2 ;;
        --hold-seconds) HOLD_SECONDS="$2"; shift 2 ;;
        --heartbeat-interval-ms) HEARTBEAT_MS="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --stop-at-first-break) STOP_AT_FIRST_BREAK=true; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# ── FD ceiling sanity check ──────────────────────────────────────────────────
# Each ferrum/proto_bench connection consumes 1 FD on the client side and 2 on
# the gateway (downstream socket + upstream socket). For headroom on the
# *client* (proto_bench) we need at least N + ~64 spare FDs for everything
# else. Warn loudly if soft ulimit is below the highest N value the caller
# requested — silent FD exhaustion looks identical to a gateway breaking.
HIGHEST_N=$(echo "$CONNECTION_LEVELS" | tr ' ' '\n' | sort -n | tail -1)
SOFT_FD=$(ulimit -n)
if [ "$SOFT_FD" -lt "$((HIGHEST_N + 1024))" ]; then
    echo "[warn] soft FD limit is $SOFT_FD but highest N is $HIGHEST_N — client may hit FD ceiling before any gateway breaks" >&2
    echo "[warn] try: ulimit -n 1048576" >&2
fi

# ── Gateway plumbing (HTTP/1.1+TLS only) ─────────────────────────────────────
PROTOCOL="http1-tls"
GATEWAY_HTTP_PORT=8000
GATEWAY_HTTPS_PORT=8443
TARGET_URL="https://127.0.0.1:${GATEWAY_HTTPS_PORT}/echo"

FERRUM_IMAGE="${FERRUM_IMAGE:-ferrum-edge:bench}"
ENVOY_IMAGE="envoyproxy/envoy:v1.33.5"
KONG_IMAGE="kong/kong-gateway:3.10.0.0"
TYK_IMAGE="tykio/tyk-gateway:v5.3.0"
REDIS_IMAGE="redis:7.4.1-alpine"
KRAKEND_IMAGE="krakend:2.13.2"

BACKEND_PID=""
REDIS_CID=""
GATEWAY_CID=""
CERT_DIR="$SCRIPT_DIR/certs"

cleanup() {
    echo "[cleanup] stopping all processes..."
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    [ -n "$GATEWAY_CID" ] && docker rm -f "$GATEWAY_CID" >/dev/null 2>&1 || true
    [ -n "$REDIS_CID" ] && docker rm -f "$REDIS_CID" >/dev/null 2>&1 || true
    for port in 3001 3002 3003 3447 3010 \
                $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT 6379 8001; do
        lsof -ti:"$port" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    done
}
trap cleanup EXIT

# ── Build ────────────────────────────────────────────────────────────────────
build_binaries() {
    if $SKIP_BUILD; then
        echo "[build] skipping (--skip-build)"
        return
    fi
    echo "[build] building proto_bench/proto_backend..."
    ( cd "$SCRIPT_DIR" && cargo build --release 2>&1 | tail -3 )

    echo "[build] verifying ferrum docker image '$FERRUM_IMAGE'..."
    if ! docker image inspect "$FERRUM_IMAGE" >/dev/null 2>&1; then
        echo "[build] building ferrum docker image..."
        docker build -t "$FERRUM_IMAGE" -f "$PROJECT_ROOT/Dockerfile" "$PROJECT_ROOT" 2>&1 | tail -5
    fi
}

# ── Backend ──────────────────────────────────────────────────────────────────
start_backend() {
    echo "[backend] starting proto_backend..."
    local saved_pwd
    saved_pwd="$(pwd)"
    cd "$SCRIPT_DIR"
    ./target/release/proto_backend > "$SCRIPT_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    cd "$saved_pwd"

    for i in $(seq 1 20); do
        if curl -sf http://127.0.0.1:3010/health >/dev/null 2>&1; then
            for j in $(seq 1 10); do
                [ -f "$CERT_DIR/ca.pem" ] && [ -f "$CERT_DIR/cert.pem" ] && break
                sleep 0.5
            done
            echo "[backend] healthy"
            return
        fi
        sleep 0.5
    done
    echo "[backend] failed to start" >&2
    tail -30 "$SCRIPT_DIR/backend.log" >&2
    exit 1
}

# ── Gateway readiness ───────────────────────────────────────────────────────
wait_for_gateway() {
    for i in $(seq 1 40); do
        # Use a plain TCP probe — the gateway is up the moment it accepts on
        # the TLS port, even before its first handshake completes.
        if (echo > "/dev/tcp/127.0.0.1/$GATEWAY_HTTPS_PORT") 2>/dev/null; then
            sleep 1  # small grace for TLS readiness
            return 0
        fi
        if [ -n "$GATEWAY_CID" ] && \
           ! docker inspect -f '{{.State.Running}}' "$GATEWAY_CID" 2>/dev/null | grep -q true; then
            echo "[gateway] container exited" >&2
            docker logs "$GATEWAY_CID" 2>&1 | tail -30 >&2 || true
            return 1
        fi
        sleep 0.5
    done
    echo "[gateway] not ready after 20s" >&2
    return 1
}

# ── Per-gateway start functions ──────────────────────────────────────────────
# Note on FD limits inside containers: docker run --ulimit nofile=N:N raises
# the per-container soft+hard limit so the gateway can actually accept N
# connections. Without this every gateway maxes out at the docker daemon's
# default (~1024 soft / 65536 hard on most distros) regardless of host tuning.
DOCKER_NOFILE_ULIMIT="--ulimit nofile=1048576:1048576"

prepare_ferrum_config() {
    local src_config="$1"
    local ca_path="$2"
    local runtime_config="$SCRIPT_DIR/ferrum_runtime_$(basename "$src_config")"

    sed -e "s|CA_PATH|${ca_path}|g" \
        "$src_config" > "$runtime_config"

    echo "$runtime_config"
}

start_ferrum() {
    local config_src="$SCRIPT_DIR/configs/http1_tls_e2e_perf.yaml"
    local config_file
    config_file=$(prepare_ferrum_config "$config_src" "/etc/ferrum/tls/ca.pem")
    echo "[ferrum] starting..."

    GATEWAY_CID=$(docker run -d --rm --network host $DOCKER_NOFILE_ULIMIT \
        -v "$config_file:/etc/ferrum/config.yaml:ro" \
        -v "$CERT_DIR:/etc/ferrum/tls:ro" \
        -e "FERRUM_MODE=file" \
        -e "FERRUM_FILE_CONFIG_PATH=/etc/ferrum/config.yaml" \
        -e "FERRUM_PROXY_HTTP_PORT=$GATEWAY_HTTP_PORT" \
        -e "FERRUM_PROXY_HTTPS_PORT=$GATEWAY_HTTPS_PORT" \
        -e "FERRUM_FRONTEND_TLS_CERT_PATH=/etc/ferrum/tls/cert.pem" \
        -e "FERRUM_FRONTEND_TLS_KEY_PATH=/etc/ferrum/tls/key.pem" \
        -e "FERRUM_LOG_LEVEL=error" \
        -e "FERRUM_MAX_CONNECTIONS=0" \
        -e "FERRUM_POOL_MAX_IDLE_PER_HOST=1024" \
        -e "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true" \
        -e "FERRUM_POOL_WARMUP_ENABLED=true" \
        -e "FERRUM_TCP_IDLE_TIMEOUT_SECONDS=120" \
        "$FERRUM_IMAGE")
    wait_for_gateway
}

start_envoy() {
    local cfg_src="$SCRIPT_DIR/configs/envoy/http1_tls.yaml"
    local cfg_dst="$SCRIPT_DIR/envoy_runtime.yaml"
    sed -e "s|CERT_PATH|/certs/cert.pem|g" \
        -e "s|KEY_PATH|/certs/key.pem|g" \
        -e "s|CA_PATH|/certs/ca.pem|g" \
        "$cfg_src" > "$cfg_dst"

    echo "[envoy] starting..."
    GATEWAY_CID=$(docker run -d --rm --network host $DOCKER_NOFILE_ULIMIT \
        -v "$cfg_dst:/etc/envoy/envoy.yaml:ro" \
        -v "$CERT_DIR:/certs:ro" \
        "$ENVOY_IMAGE" \
        envoy -c /etc/envoy/envoy.yaml --concurrency "$(nproc 2>/dev/null || echo 4)" -l error --disable-hot-restart)
    wait_for_gateway
}

start_kong() {
    local cfg_src="$SCRIPT_DIR/configs/kong/http1_tls.yaml"
    local cfg_dst="$SCRIPT_DIR/kong_runtime.yaml"
    cp "$cfg_src" "$cfg_dst"

    echo "[kong] starting..."
    GATEWAY_CID=$(docker run -d --rm --network host $DOCKER_NOFILE_ULIMIT \
        -e "KONG_DATABASE=off" \
        -e "KONG_DECLARATIVE_CONFIG=/kong/kong.yaml" \
        -e "KONG_PROXY_LISTEN=0.0.0.0:${GATEWAY_HTTP_PORT}, 0.0.0.0:${GATEWAY_HTTPS_PORT} ssl" \
        -e "KONG_LOG_LEVEL=error" \
        -e "KONG_PROXY_ACCESS_LOG=off" \
        -e "KONG_ADMIN_LISTEN=0.0.0.0:8001" \
        -e "KONG_SSL_CERT=/certs/cert.pem" \
        -e "KONG_SSL_CERT_KEY=/certs/key.pem" \
        -e "KONG_LUA_SSL_TRUSTED_CERTIFICATE=/certs/ca.pem" \
        -e "KONG_NGINX_PROXY_PROXY_SSL_TRUSTED_CERTIFICATE=/certs/ca.pem" \
        -e "KONG_NGINX_PROXY_PROXY_SSL_VERIFY=on" \
        `# nginx worker_connections defaults to 16384 in Kong 3.10. Leave at` \
        `# default so the breaking-point reflects out-of-box behavior; tuned` \
        `# variant can be a separate run if desired.` \
        -v "$cfg_dst:/kong/kong.yaml:ro" \
        -v "$CERT_DIR:/certs:ro" \
        "$KONG_IMAGE")
    wait_for_gateway
}

start_redis_for_tyk() {
    echo "[redis] starting (for tyk)..."
    REDIS_CID=$(docker run -d --rm --network host "$REDIS_IMAGE" redis-server --bind 127.0.0.1 --port 6379)
    for i in $(seq 1 20); do
        if docker exec "$REDIS_CID" redis-cli ping 2>/dev/null | grep -q PONG; then
            return 0
        fi
        sleep 0.5
    done
    echo "[redis] failed to start" >&2
    # Return — don't `exit 1` — so the failure flows through start_tyk →
    # start_gateway and the main loop records tyk as startup_failed and
    # continues with krakend. Bailing out of the whole script here used
    # to bypass the per-gateway ledger and lose later gateways' results.
    return 1
}

start_tyk() {
    if ! start_redis_for_tyk; then
        echo "[tyk] redis dependency failed to start; skipping tyk" >&2
        return 1
    fi
    local apps_dir="$SCRIPT_DIR/configs/tyk/apps_http1_tls"
    local tyk_conf="$SCRIPT_DIR/configs/tyk/tyk.conf"
    echo "[tyk] starting..."

    GATEWAY_CID=$(docker run -d --rm --network host $DOCKER_NOFILE_ULIMIT \
        -v "$apps_dir:/etc/tyk/apps:ro" \
        -v "$tyk_conf:/opt/tyk-gateway/tyk.conf:ro" \
        -v "$CERT_DIR:/etc/tyk/certs:ro" \
        --entrypoint sh \
        "$TYK_IMAGE" \
        -c 'cp /etc/tyk/certs/ca.pem /usr/local/share/ca-certificates/bench.crt && update-ca-certificates >/dev/null 2>&1 && exec /opt/tyk-gateway/tyk --conf /opt/tyk-gateway/tyk.conf')
    wait_for_gateway
}

start_krakend() {
    local cfg_src="$SCRIPT_DIR/configs/krakend/http1_tls.json"
    local cfg_dst="$SCRIPT_DIR/krakend_runtime.json"
    sed -e "s|CERT_PATH|/certs/cert.pem|g" \
        -e "s|KEY_PATH|/certs/key.pem|g" \
        "$cfg_src" > "$cfg_dst"

    echo "[krakend] starting..."
    GATEWAY_CID=$(docker run -d --rm --network host $DOCKER_NOFILE_ULIMIT \
        -v "$cfg_dst:/etc/krakend/krakend.json:ro" \
        -v "$CERT_DIR:/certs:ro" \
        "$KRAKEND_IMAGE" \
        run -c /etc/krakend/krakend.json)
    wait_for_gateway
}

start_gateway() {
    case "$1" in
        ferrum)  start_ferrum ;;
        envoy)   start_envoy ;;
        kong)    start_kong ;;
        tyk)     start_tyk ;;
        krakend) start_krakend ;;
        *) echo "unknown gateway: $1" >&2; return 1 ;;
    esac
}

stop_gateway() {
    [ -n "$GATEWAY_CID" ] && docker rm -f "$GATEWAY_CID" >/dev/null 2>&1 || true
    [ -n "$REDIS_CID" ] && docker rm -f "$REDIS_CID" >/dev/null 2>&1 || true
    GATEWAY_CID=""
    REDIS_CID=""
    sleep 2  # let kernel reclaim sockets before the next gateway binds
}

# ── Single saturate run ─────────────────────────────────────────────────────
run_saturate() {
    local gw="$1" n="$2"
    local out="$OUTPUT_DIR/${gw}_${n}.json"
    echo "[bench] $gw N=$n → $out"

    # Per-run wallclock budget: ramp + hold + slack. The slack covers TLS
    # handshake completion at the tail of the ramp plus the small amount of
    # post-hold reporting work proto_bench does. If proto_bench overshoots
    # this (stuck socket, gateway never accepts, infinite loop in a worker
    # task), $TIMEOUT_CMD kills it — the empty-output branch below then
    # writes a "broken" stub so the per-(gateway, N) ledger reflects the
    # failure instead of the matrix stalling.
    local timeout_s=$((RAMP_SECONDS + HOLD_SECONDS + 60))

    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD --kill-after=10s "${timeout_s}s" \
            "$SCRIPT_DIR/target/release/proto_bench" saturate \
            --target "$TARGET_URL" \
            --connections "$n" \
            --ramp-seconds "$RAMP_SECONDS" \
            --hold-seconds "$HOLD_SECONDS" \
            --heartbeat-interval-ms "$HEARTBEAT_MS" \
            --connect-timeout-ms 10000 \
            --json > "$out" 2> "$out.stderr" || true
    else
        "$SCRIPT_DIR/target/release/proto_bench" saturate \
            --target "$TARGET_URL" \
            --connections "$n" \
            --ramp-seconds "$RAMP_SECONDS" \
            --hold-seconds "$HOLD_SECONDS" \
            --heartbeat-interval-ms "$HEARTBEAT_MS" \
            --connect-timeout-ms 10000 \
            --json > "$out" 2> "$out.stderr" || true
    fi

    if [ ! -s "$out" ]; then
        echo "[bench] empty output for $gw N=$n (proto_bench may have crashed)" >&2
        cat "$out.stderr" >&2 || true
        echo '{"verdict":"broken","error":"proto_bench produced no output"}' > "$out"
        return 1
    fi

    local verdict
    verdict=$(grep -o '"verdict": *"[^"]*"' "$out" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    local cs_pct
    cs_pct=$(grep -o '"connect_success_rate": *[0-9.]*' "$out" | head -1 | awk '{print $2 * 100}')
    local hb_pct
    hb_pct=$(grep -o '"heartbeat_success_rate": *[0-9.]*' "$out" | head -1 | awk '{print $2 * 100}')
    local peak
    peak=$(grep -o '"peak_alive_connections": *[0-9]*' "$out" | head -1 | awk '{print $2}')
    echo "[bench] $gw N=$n: verdict=$verdict connect_ok=${cs_pct:-?}% heartbeat_ok=${hb_pct:-?}% peak_alive=${peak:-?}"
}

# Stash the gateway's terminal status (success | startup_failed) in a sidecar
# file so the summary loop can distinguish "tested and broken at N=X" from
# "never tested because it failed to start".
record_startup_failed() {
    local gw="$1"
    : > "$OUTPUT_DIR/${gw}_startup_failed.marker"
}

# ── Main loop ────────────────────────────────────────────────────────────────
build_binaries
start_backend

# Wipe any prior per-(gateway, N) outputs from a previous run sharing the
# output dir. Without this, the summary block at the end runs `*.json` glob
# over OUTPUT_DIR and would pull in stale results from earlier runs — last_ok
# / first_break would silently mix old + new data and the markdown table
# would show ghost rows. This includes summary.json (regenerated below),
# the per-(gateway, N) JSON, the .stderr sidecar, and the marker files.
rm -f "$OUTPUT_DIR"/*.json "$OUTPUT_DIR"/*.stderr "$OUTPUT_DIR"/*.marker 2>/dev/null || true

for gw in $GATEWAYS; do
    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "  Gateway: $gw"
    echo "════════════════════════════════════════════════════════════════"

    if ! start_gateway "$gw"; then
        echo "[skip] $gw failed to start" >&2
        record_startup_failed "$gw"
        # A timed-out wait_for_gateway can leave a partially-started container
        # holding $GATEWAY_HTTPS_PORT (or 6379, in tyk's case) — without
        # explicit cleanup, the next gateway in the loop hits a port conflict
        # and gets misreported as startup_failed too. The trap-on-EXIT cleanup
        # only fires at the very end, which is too late for the cohort.
        stop_gateway
        continue
    fi

    for n in $CONNECTION_LEVELS; do
        run_saturate "$gw" "$n" || true
        run_verdict=$(grep -o '"verdict": *"[^"]*"' "$OUTPUT_DIR/${gw}_${n}.json" 2>/dev/null \
            | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        if [ "$run_verdict" != "ok" ] && $STOP_AT_FIRST_BREAK; then
            echo "[stop] $gw broke at N=$n; skipping higher levels"
            break
        fi
    done

    stop_gateway
done

# ── Summary ──────────────────────────────────────────────────────────────────
# Re-derive last_ok / first_break by scanning $OUTPUT_DIR — robust to crashes
# mid-run and avoids relying on bash 4 associative arrays (macOS ships 3.2).
gateway_summary() {
    local gw="$1"
    if [ -f "$OUTPUT_DIR/${gw}_startup_failed.marker" ]; then
        echo "startup_failed none"
        return
    fi
    local last_ok="0"
    local first_break="none"
    # Iterate in numeric order so "first break" is correct regardless of how
    # the user specified the levels.
    for n in $(echo "$CONNECTION_LEVELS" | tr ' ' '\n' | sort -n); do
        local f="$OUTPUT_DIR/${gw}_${n}.json"
        [ -f "$f" ] || continue
        local v
        v=$(grep -o '"verdict": *"[^"]*"' "$f" 2>/dev/null \
            | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
        if [ "$v" = "ok" ]; then
            last_ok="$n"
        elif [ "$first_break" = "none" ]; then
            first_break="$n"
        fi
    done
    echo "$last_ok $first_break"
}

# Build a clean comma-separated JSON array from CONNECTION_LEVELS. A naive
# `tr ' ' ','` preserves repeated/leading/trailing whitespace as empty fields
# (e.g. "1000  5000" → "[1000,,5000]"), which is invalid JSON and would crash
# the CI markdown-summary step at json.loads(). The for-loop relies on the
# unquoted-expansion + IFS field-splitting to collapse whitespace and skip
# empty fields cleanly.
levels_csv=""
for level in $CONNECTION_LEVELS; do
    [ -z "$level" ] && continue
    if [ -z "$levels_csv" ]; then
        levels_csv="$level"
    else
        levels_csv="${levels_csv},${level}"
    fi
done

SUMMARY="$OUTPUT_DIR/summary.json"
{
    echo "{"
    echo "  \"protocol\": \"http1-tls\","
    echo "  \"ramp_seconds\": $RAMP_SECONDS,"
    echo "  \"hold_seconds\": $HOLD_SECONDS,"
    echo "  \"heartbeat_interval_ms\": $HEARTBEAT_MS,"
    echo "  \"connection_levels\": [${levels_csv}],"
    echo "  \"results\": {"
    is_first=true
    for gw in $GATEWAYS; do
        if [ "$is_first" = "true" ]; then
            is_first=false
        else
            echo ","
        fi
        read -r last_ok first_break <<< "$(gateway_summary "$gw")"
        if [ "$last_ok" = "startup_failed" ]; then
            printf '    "%s": { "last_ok": 0, "first_break": "startup_failed" }' "$gw"
        else
            printf '    "%s": { "last_ok": %s, "first_break": "%s" }' \
                "$gw" "$last_ok" "$first_break"
        fi
    done
    echo
    echo "  }"
    echo "}"
} > "$SUMMARY"

echo
echo "════════════════════════════════════════════════════════════════"
echo "  Summary"
echo "════════════════════════════════════════════════════════════════"
printf "  %-10s %15s %15s\n" "Gateway" "Last OK N" "First Break N"
for gw in $GATEWAYS; do
    read -r last_ok first_break <<< "$(gateway_summary "$gw")"
    if [ "$last_ok" = "startup_failed" ]; then
        printf "  %-10s %15s %15s\n" "$gw" "—" "startup_failed"
    else
        printf "  %-10s %15s %15s\n" "$gw" "$last_ok" "$first_break"
    fi
done
echo
echo "  full output: $OUTPUT_DIR"
echo "  summary: $SUMMARY"
