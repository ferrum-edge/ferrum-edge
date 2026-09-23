#!/usr/bin/env bash
# Low-rate streaming latency profile for the response-aggregation window.
#
# The throughput benchmark cannot decide whether
# FERRUM_RESPONSE_COALESCE_FLUSH_MS costs anything: a millisecond hold is
# invisible against a saturated p50 of hundreds of milliseconds. This lane runs
# the opposite workload — an idle proxy carrying small frames spaced far apart,
# the SSE / long-poll shape — where a hold is the dominant term.
#
# Arms differ in ONE variable. Both run the coalescing adapter; only the window
# changes, so a difference cannot be attributed to turning coalescing on.
#
#   direct        no gateway, straight to the TLS backend: the floor
#   plain         cutoff=1 flush=0   coalescer, no window
#   window        cutoff=1 flush=N   coalescer, N ms window
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/stream-profile-results}"
FERRUM_IMAGE="${FERRUM_IMAGE:-ferrum-edge:bench}"
GATEWAY_HTTPS_PORT="${GATEWAY_HTTPS_PORT:-8443}"
GATEWAY_HTTP_PORT="${GATEWAY_HTTP_PORT:-8000}"
# The TLS backends are protocol-exclusive by design so a mismatch cannot slip
# through silently: 3447 advertises only http/1.1 and 3443 only h2. A direct
# control that offers the wrong ALPN gets `NoApplicationProtocol` rather than a
# quiet fallback, so pick the port that matches the axis under test.
BACKEND_TLS_PORT_H1=3447
BACKEND_TLS_PORT_H2=3443

FRAMES="${FRAMES:-20}"
FRAME_SIZE="${FRAME_SIZE:-1024}"
GAP_MS="${GAP_MS:-10}"
REQUESTS="${REQUESTS:-30}"
CONCURRENCY="${CONCURRENCY:-4}"
WINDOW_MS="${WINDOW_MS:-2}"
ALPN="${ALPN:-h1}"
REPEATS="${REPEATS:-3}"

BACKEND_PID=""
GATEWAY_CID=""

cleanup() {
    [ -n "$GATEWAY_CID" ] && docker stop "$GATEWAY_CID" >/dev/null 2>&1 || true
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

start_backend() {
    echo "[backend] starting"
    ( cd "$SCRIPT_DIR" && ./target/release/proto_backend > "$OUTPUT_DIR/backend.log" 2>&1 & echo $! > "$OUTPUT_DIR/backend.pid" )
    BACKEND_PID="$(cat "$OUTPUT_DIR/backend.pid")"
    for _ in $(seq 1 40); do
        if curl -sf http://127.0.0.1:3010/health >/dev/null 2>&1; then
            for _ in $(seq 1 20); do
                [ -f "$CERT_DIR/ca.pem" ] && [ -f "$CERT_DIR/cert.pem" ] && break
                sleep 0.5
            done
            echo "[backend] healthy (pid $BACKEND_PID)"
            return 0
        fi
        sleep 0.5
    done
    echo "[backend] never became healthy" >&2
    return 1
}

start_gateway() {
    local flush_ms="$1"
    GATEWAY_CID=$(docker run -d --rm --network host \
        -v "$SCRIPT_DIR/configs/stream_profile.yaml:/etc/ferrum/config.yaml:ro" \
        -v "$CERT_DIR:/etc/ferrum/tls:ro" \
        -e "FERRUM_MODE=file" \
        -e "FERRUM_FILE_CONFIG_PATH=/etc/ferrum/config.yaml" \
        -e "FERRUM_PROXY_HTTP_PORT=$GATEWAY_HTTP_PORT" \
        -e "FERRUM_PROXY_HTTPS_PORT=$GATEWAY_HTTPS_PORT" \
        -e "FERRUM_FRONTEND_TLS_CERT_PATH=/etc/ferrum/tls/cert.pem" \
        -e "FERRUM_FRONTEND_TLS_KEY_PATH=/etc/ferrum/tls/key.pem" \
        -e "FERRUM_LOG_LEVEL=error" \
        -e "FERRUM_ADD_VIA_HEADER=false" \
        -e "FERRUM_ADD_FORWARDED_HEADER=false" \
        -e "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0" \
        -e "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0" \
        -e "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=1" \
        -e "FERRUM_RESPONSE_COALESCE_FLUSH_MS=$flush_ms" \
        -e "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0" \
        -e "FERRUM_MAX_CONNECTIONS=0" \
        -e "FERRUM_POOL_MAX_IDLE_PER_HOST=200" \
        -e "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true" \
        -e "FERRUM_POOL_WARMUP_ENABLED=true" \
        "$FERRUM_IMAGE")
    for _ in $(seq 1 60); do
        if curl -skf "https://127.0.0.1:$GATEWAY_HTTPS_PORT/health" >/dev/null 2>&1; then
            echo "[gateway] ready (flush=${flush_ms}ms)"
            return 0
        fi
        sleep 0.5
    done
    echo "[gateway] never became ready (flush=${flush_ms}ms)" >&2
    docker logs "$GATEWAY_CID" 2>&1 | tail -30 >&2 || true
    return 1
}

stop_gateway() {
    [ -n "$GATEWAY_CID" ] && docker stop "$GATEWAY_CID" >/dev/null 2>&1 || true
    GATEWAY_CID=""
}

profile() {
    local arm="$1" target="$2" repeat="$3"
    echo "[profile] $arm repeat $repeat"
    "$SCRIPT_DIR/target/release/stream_profile" \
        --target "$target" \
        --frames "$FRAMES" --size "$FRAME_SIZE" --gap-ms "$GAP_MS" \
        --requests "$REQUESTS" --concurrency "$CONCURRENCY" \
        --alpn "$ALPN" \
        --out "$OUTPUT_DIR/${arm}_repeat${repeat}.json" > /dev/null
}

case "$ALPN" in
    h2) DIRECT_PORT="$BACKEND_TLS_PORT_H2" ;;
    h1) DIRECT_PORT="$BACKEND_TLS_PORT_H1" ;;
    *) echo "unsupported ALPN: $ALPN" >&2; exit 2 ;;
esac

mkdir -p "$OUTPUT_DIR"
echo "[build] proto_backend + stream_profile"
( cd "$SCRIPT_DIR" && cargo build --release --bin proto_backend --bin stream_profile )

start_backend

# Counterbalanced: every repeat runs the arms in a different order so a drift in
# host conditions cannot load onto one arm.
for repeat in $(seq 1 "$REPEATS"); do
    if [ $((repeat % 2)) -eq 1 ]; then
        order="direct plain window"
    else
        order="window plain direct"
    fi
    for arm in $order; do
        case "$arm" in
            direct)
                profile direct "127.0.0.1:$DIRECT_PORT" "$repeat"
                ;;
            plain)
                start_gateway 0
                profile plain "127.0.0.1:$GATEWAY_HTTPS_PORT" "$repeat"
                stop_gateway
                ;;
            window)
                start_gateway "$WINDOW_MS"
                profile window "127.0.0.1:$GATEWAY_HTTPS_PORT" "$repeat"
                stop_gateway
                ;;
        esac
    done
done

echo "[done] results in $OUTPUT_DIR"
python3 "$SCRIPT_DIR/analyze_stream_profile.py" "$OUTPUT_DIR"
