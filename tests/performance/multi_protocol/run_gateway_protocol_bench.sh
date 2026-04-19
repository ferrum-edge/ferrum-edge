#!/bin/bash
# Multi-gateway, multi-payload protocol benchmark for gateways-protocol-benchmark.yml.
#
# For one protocol, runs proto_bench against every supporting gateway at every
# requested payload size, plus a direct-backend baseline. Writes per-bench JSON
# to the output directory named `<gateway>_<protocol>_<payload>.json`.
#
# Usage: ./run_gateway_protocol_bench.sh <protocol> [options]
#   Protocol: http1-tls | http2 | http3 | grpcs | wss | tcp-tls | udp | udp-dtls
#
# Options:
#   --gateways "ferrum envoy kong tyk krakend"   (auto-filtered by protocol support)
#   --payload-sizes "10240 71680 512000 1048576 5242880"  (UDP & UDP+DTLS forced to 1024)
#   --duration 10
#   --concurrency 100
#   --output-dir /tmp/gateway-protocol-results
#   --skip-build                (reuse existing proto_bench binaries + ferrum docker image)
#   --skip-direct               (skip direct-backend baseline)
#
# All gateways (including Ferrum) run in Docker with --network host so no gateway
# has a native-binary advantage. proto_backend and proto_bench run natively
# since they are the backend and client under test, not gateways being benchmarked.
#
# Exit code: 0 on success (some benches may fail individually — check JSON files).

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

# ── Defaults ─────────────────────────────────────────────────────────────────
PROTOCOL="${1:-}"
[ -z "$PROTOCOL" ] && { echo "usage: $0 <protocol> [options]" >&2; exit 2; }
shift

GATEWAYS="ferrum envoy kong tyk krakend"
PAYLOAD_SIZES="10240 71680 512000 1048576 5242880"
DURATION=10
CONCURRENCY=100
OUTPUT_DIR="/tmp/gateway-protocol-results"
SKIP_BUILD=false
SKIP_DIRECT=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --gateways) GATEWAYS="$2"; shift 2 ;;
        --payload-sizes) PAYLOAD_SIZES="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --skip-direct) SKIP_DIRECT=true; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# UDP protocols are fixed to 1 KB regardless of caller.
case "$PROTOCOL" in
    udp|udp-dtls) PAYLOAD_SIZES="1024" ;;
esac

# Absolutize OUTPUT_DIR immediately so it survives any cd later in the script.
# The workflow passes --output-dir as a relative path (e.g. "results/http1-tls/run_1")
# expecting it to resolve against the caller's CWD (repo root), but start_backend
# must cd into $SCRIPT_DIR before launching proto_backend so cert generation
# lands in the expected location. Resolving to absolute upfront decouples the two.
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# ── Gateway × protocol support matrix ─────────────────────────────────────────
# Returns 0 if the gateway supports the protocol, 1 otherwise.
supports() {
    local gw="$1" proto="$2"
    # Gateway limitations baked into the matrix. Each row is the result of a
    # concrete protocol-uniformity audit — every (gateway, protocol) pair we
    # include speaks the same protocol on BOTH the client→gateway leg and
    # the gateway→backend leg. Gateways that can only do half the protocol
    # are excluded rather than benchmarked dishonestly.
    #
    # - KrakenD Community Edition does NOT support gRPC proxying or WebSocket
    #   proxying — both are Enterprise-only (see
    #   https://www.krakend.io/docs/enterprise/backends/grpc/ and
    #   https://www.krakend.io/docs/enterprise/websockets/). We ship the CE
    #   image (krakend:2.13.2), so krakend is omitted from grpcs and wss.
    #
    # - Kong HTTP/3: KONG_PROXY_LISTEN doesn't accept http3/quic flags, and
    #   HTTP/3 would require experimental KONG_NGINX_HTTP_LISTEN template
    #   injection that isn't a documented supported Kong path. http3 runs
    #   as a ferrum-vs-envoy comparison only.
    #
    # - Kong HTTP/2: Kong can terminate H2 from the downstream client, but
    #   OpenResty/nginx upstream (`proxy_pass`) is HTTP/1.1 only — the
    #   mainline nginx upstream module does not support H2, and the Kong
    #   Docker image bundles no third-party H2-upstream module. So a
    #   Kong/http2 row would measure client→H2→Kong→H1→backend, i.e. not
    #   uniform H2 end-to-end. http2 therefore excludes kong.
    #
    # - Tyk tcp-tls: Tyk Gateway v5.3 rejects per-API `listen_port` +
    #   `protocol: "tls"` definitions with "trying to open disabled
    #   port" unless the port is pre-registered at the gateway level,
    #   which requires enterprise/custom-domain config the OSS image
    #   doesn't ship. Documented as a Tyk OSS limitation, not a bench
    #   harness bug. Remove once Tyk OSS supports secondary TCP/TLS
    #   listener ports or the bench config moves Tyk TCP onto :8443.
    case "$gw:$proto" in
        ferrum:*)  return 0 ;;
        envoy:http1-tls|envoy:http2|envoy:http3|envoy:grpcs|envoy:wss|envoy:tcp-tls|envoy:udp) return 0 ;;
        kong:http1-tls|kong:grpcs|kong:wss|kong:tcp-tls|kong:udp) return 0 ;;
        tyk:http1-tls|tyk:http2|tyk:grpcs|tyk:wss) return 0 ;;
        krakend:http1-tls|krakend:http2) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Protocol plumbing ─────────────────────────────────────────────────────────
# Standard gateway listen ports (all gateways listen on these so bench targets
# match regardless of which gateway is under test).
GATEWAY_HTTP_PORT=8000
GATEWAY_HTTPS_PORT=8443
GATEWAY_TCP_TLS_PORT=5001
GATEWAY_UDP_PORT=5003
GATEWAY_UDP_DTLS_PORT=5004

# Returns: <bench_proto> <bench_target> <direct_target> [extra_bench_args]
#
# Direct-backend targets mirror the gateway's upstream so the baseline reflects
# the same end-to-end TLS cost every gateway must pay. proto_backend exposes:
#   3443 HTTPS/H2, 3444 TCP+TLS, 3445 HTTP/3, 3446 WSS, 3006 DTLS, 50053 grpc+TLS.
#
# grpcs: tonic 0.14 has no insecure-TLS toggle, so we explicitly trust the
# benchmark backend's self-signed CA via --ca-cert for both legs.
bench_params() {
    case "$PROTOCOL" in
        http1-tls) echo "http1 https://127.0.0.1:${GATEWAY_HTTPS_PORT}/echo https://127.0.0.1:3447/echo" ;;
        http2)     echo "http2 https://127.0.0.1:${GATEWAY_HTTPS_PORT}/echo https://127.0.0.1:3443/echo" ;;
        http3)     echo "http3 https://127.0.0.1:${GATEWAY_HTTPS_PORT}/echo https://127.0.0.1:3445/echo" ;;
        grpcs)     echo "grpc https://127.0.0.1:${GATEWAY_HTTPS_PORT} https://127.0.0.1:50053 --ca-cert ${CERT_DIR}/cert.pem" ;;
        wss)       echo "ws wss://127.0.0.1:${GATEWAY_HTTPS_PORT}/ws wss://127.0.0.1:3446" ;;
        tcp-tls)   echo "tcp 127.0.0.1:${GATEWAY_TCP_TLS_PORT} 127.0.0.1:3444 --tls" ;;
        udp)       echo "udp 127.0.0.1:${GATEWAY_UDP_PORT} 127.0.0.1:3005" ;;
        udp-dtls)  echo "udp 127.0.0.1:${GATEWAY_UDP_DTLS_PORT} 127.0.0.1:3006 --tls" ;;
        *) echo "unknown protocol: $PROTOCOL" >&2; exit 2 ;;
    esac
}

# ── Docker images ────────────────────────────────────────────────────────────
# All tags are pinned to exact patch versions (not floating `-latest` / minor-only
# tags) so benchmark runs remain reproducible over time. Bump deliberately when
# upgrading; do not revert to floating tags.
FERRUM_IMAGE="${FERRUM_IMAGE:-ferrum-edge:bench}"
ENVOY_IMAGE="envoyproxy/envoy:v1.33.5"
KONG_IMAGE="kong/kong-gateway:3.10.0.0"
TYK_IMAGE="tykio/tyk-gateway:v5.3.0"
REDIS_IMAGE="redis:7.4.1-alpine"
KRAKEND_IMAGE="krakend:2.13.2"

# ── State ────────────────────────────────────────────────────────────────────
BACKEND_PID=""
REDIS_CID=""
GATEWAY_CID=""
CERT_DIR="$SCRIPT_DIR/certs"

cleanup() {
    echo "[cleanup] stopping all processes..."
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
    [ -n "$GATEWAY_CID" ] && docker rm -f "$GATEWAY_CID" >/dev/null 2>&1 || true
    [ -n "$REDIS_CID" ] && docker rm -f "$REDIS_CID" >/dev/null 2>&1 || true
    for port in 3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 3446 3447 \
                50052 50053 \
                $GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT \
                $GATEWAY_TCP_TLS_PORT $GATEWAY_UDP_PORT $GATEWAY_UDP_DTLS_PORT \
                15000 9901 6379; do
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
    echo "[build] building proto_bench/proto_backend (harness tools only)..."
    ( cd "$SCRIPT_DIR" && cargo build --release 2>&1 | tail -3 )

    echo "[build] verifying ferrum Docker image '$FERRUM_IMAGE' exists..."
    if ! docker image inspect "$FERRUM_IMAGE" >/dev/null 2>&1; then
        echo "[build] building ferrum Docker image from $PROJECT_ROOT/Dockerfile..."
        docker build -t "$FERRUM_IMAGE" -f "$PROJECT_ROOT/Dockerfile" "$PROJECT_ROOT" 2>&1 | tail -5
    else
        echo "[build] ferrum image '$FERRUM_IMAGE' already present"
    fi
}

# ── Backend ──────────────────────────────────────────────────────────────────
start_backend() {
    echo "[backend] starting proto_backend..."
    # proto_backend writes self-signed certs to ./certs relative to its CWD
    # (see tests/performance/multi_protocol/proto_backend.rs — uses
    # std::env::current_dir().join("certs")). We must cd into $SCRIPT_DIR so
    # certs land at $CERT_DIR ($SCRIPT_DIR/certs), but we MUST restore the
    # caller's CWD afterwards — otherwise relative paths passed by the
    # workflow (e.g. --output-dir "results/http1-tls/run_1") would resolve
    # against $SCRIPT_DIR instead of the repo root and subsequent run_bench
    # writes to $OUTPUT_DIR/*.json would fail.
    local saved_pwd
    saved_pwd="$(pwd)"
    cd "$SCRIPT_DIR"
    ./target/release/proto_backend > "$SCRIPT_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!
    cd "$saved_pwd"

    for i in $(seq 1 20); do
        if curl -sf http://127.0.0.1:3010/health >/dev/null 2>&1; then
            echo "[backend] healthy (pid $BACKEND_PID)"
            # Wait for cert generation
            for j in $(seq 1 10); do
                [ -f "$CERT_DIR/cert.pem" ] && break
                sleep 0.5
            done
            return
        fi
        sleep 0.5
    done
    echo "[backend] failed to start" >&2
    tail -30 "$SCRIPT_DIR/backend.log" >&2
    exit 1
}

# ── Ferrum (docker, distroless image from repo Dockerfile) ──────────────────
start_ferrum() {
    local config_file="$SCRIPT_DIR/configs/$(ferrum_config_name)"
    echo "[ferrum] starting ($FERRUM_IMAGE) with $(basename "$config_file")..."

    # FERRUM_POOL_ENABLE_HTTP2 defaults to true (see CLAUDE.md), no need to set.
    local extra_env=()
    case "$PROTOCOL" in
        http3) extra_env+=(-e "FERRUM_ENABLE_HTTP3=true") ;;
    esac

    GATEWAY_CID=$(docker run -d --rm --network host \
        -v "$config_file:/etc/ferrum/config.yaml:ro" \
        -v "$CERT_DIR:/etc/ferrum/tls:ro" \
        -e "FERRUM_MODE=file" \
        -e "FERRUM_FILE_CONFIG_PATH=/etc/ferrum/config.yaml" \
        -e "FERRUM_PROXY_HTTP_PORT=$GATEWAY_HTTP_PORT" \
        -e "FERRUM_PROXY_HTTPS_PORT=$GATEWAY_HTTPS_PORT" \
        -e "FERRUM_FRONTEND_TLS_CERT_PATH=/etc/ferrum/tls/cert.pem" \
        -e "FERRUM_FRONTEND_TLS_KEY_PATH=/etc/ferrum/tls/key.pem" \
        -e "FERRUM_DTLS_CERT_PATH=/etc/ferrum/tls/cert.pem" \
        -e "FERRUM_DTLS_KEY_PATH=/etc/ferrum/tls/key.pem" \
        -e "FERRUM_LOG_LEVEL=error" \
        -e "FERRUM_ADD_VIA_HEADER=false" \
        -e "FERRUM_ADD_FORWARDED_HEADER=false" \
        -e "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0" \
        -e "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0" \
        -e "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0" \
        -e "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0" \
        -e "FERRUM_MAX_CONNECTIONS=0" \
        -e "FERRUM_POOL_MAX_IDLE_PER_HOST=200" \
        -e "FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true" \
        -e "FERRUM_POOL_WARMUP_ENABLED=true" \
        -e "FERRUM_WEBSOCKET_TUNNEL_MODE=true" \
        -e "FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608" \
        -e "FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432" \
        -e "FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=true" \
        -e "FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=1048576" \
        -e "FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000" \
        -e "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000" \
        -e "FERRUM_UDP_MAX_SESSIONS=10000" \
        -e "FERRUM_UDP_RECVMMSG_BATCH_SIZE=64" \
        "${extra_env[@]}" \
        "$FERRUM_IMAGE")

    wait_for_gateway
}

ferrum_config_name() {
    # For TLS-capable protocols, use the *_e2e_perf.yaml variants which proxy
    # to TLS backends (3443/3446/50053/3444/3006) — matching the other
    # gateways' configs and the benchmark's "TLS end-to-end" design.
    # http2 and http3 perf configs already target TLS backends (3443/3445).
    # udp stays plaintext by design (it's the plaintext-vs-encrypted baseline).
    case "$PROTOCOL" in
        http1-tls) echo "http1_tls_e2e_perf.yaml" ;;
        http2)     echo "http2_perf.yaml" ;;
        http3)     echo "http3_perf.yaml" ;;
        grpcs)     echo "grpcs_e2e_perf.yaml" ;;
        wss)       echo "wss_e2e_perf.yaml" ;;
        tcp-tls)   echo "tcp_tls_e2e_perf.yaml" ;;
        udp)       echo "udp_perf.yaml" ;;
        udp-dtls)  echo "udp_dtls_e2e_perf.yaml" ;;
    esac
}

# ── Envoy (docker) ──────────────────────────────────────────────────────────
start_envoy() {
    local cfg_src="$SCRIPT_DIR/configs/envoy/$(envoy_config_name)"
    local cfg_dst="$SCRIPT_DIR/envoy_runtime.yaml"
    # Substitute CERT_PATH/KEY_PATH to mount points inside container
    sed -e "s|CERT_PATH|/certs/cert.pem|g" \
        -e "s|KEY_PATH|/certs/key.pem|g" \
        "$cfg_src" > "$cfg_dst"

    echo "[envoy] starting..."
    GATEWAY_CID=$(docker run -d --rm --network host \
        -v "$cfg_dst:/etc/envoy/envoy.yaml:ro" \
        -v "$CERT_DIR:/certs:ro" \
        "$ENVOY_IMAGE" \
        envoy -c /etc/envoy/envoy.yaml --concurrency "$(nproc 2>/dev/null || echo 4)" -l error --disable-hot-restart)

    wait_for_gateway
}

envoy_config_name() {
    case "$PROTOCOL" in
        http1-tls) echo "http1_tls.yaml" ;;
        http2)     echo "http2_tls.yaml" ;;
        http3)     echo "http3.yaml" ;;
        grpcs)     echo "grpcs.yaml" ;;
        wss)       echo "wss.yaml" ;;
        tcp-tls)   echo "tcp_tls.yaml" ;;
        udp)       echo "udp.yaml" ;;
    esac
}

# ── Kong (docker, DB-less) ──────────────────────────────────────────────────
start_kong() {
    local cfg_src="$SCRIPT_DIR/configs/kong/$(kong_config_name)"
    local cfg_dst="$SCRIPT_DIR/kong_runtime.yaml"
    echo "[kong] starting..."

    # Template the benchmark CA cert into the declarative config.
    #
    # With `tls_verify: true` on a Kong service, nginx's upstream TLS
    # verifier requires a trust anchor that Kong considers valid — which
    # means a `ca_certificates` entity in the declarative config, NOT
    # just `KONG_LUA_SSL_TRUSTED_CERTIFICATE` (that only scopes cosocket
    # Lua callouts, not `proxy_pass` upstream handshakes). Per-config
    # `ca_certificates` entries require the cert content inline, so we
    # read cert.pem at start-up and substitute it into the config file
    # written to $SCRIPT_DIR/kong_runtime.yaml (the running config
    # Kong mounts).
    #
    # `proto_backend`'s self-signed cert carries `basicConstraints:
    # CA:TRUE` (see tls_utils.rs) so Kong accepts it as a CA entity.
    python3 - "$cfg_src" "$cfg_dst" "$CERT_DIR/cert.pem" <<'PYEOF'
import sys, pathlib
src, dst, cert_path = sys.argv[1], sys.argv[2], sys.argv[3]
cert = pathlib.Path(cert_path).read_text().rstrip()
indented = '\n'.join('      ' + line for line in cert.splitlines())
text = pathlib.Path(src).read_text().replace('__BENCH_CA_PEM__', indented)
pathlib.Path(dst).write_text(text)
PYEOF

    local proxy_listen_env
    local stream_listen_env=""
    case "$PROTOCOL" in
        http1-tls)
            proxy_listen_env="0.0.0.0:${GATEWAY_HTTP_PORT}, 0.0.0.0:${GATEWAY_HTTPS_PORT} ssl"
            ;;
        grpcs)
            proxy_listen_env="0.0.0.0:${GATEWAY_HTTP_PORT}, 0.0.0.0:${GATEWAY_HTTPS_PORT} ssl http2"
            ;;
        # NB: http2 and http3 intentionally absent — see supports() for why.
        # http2: Kong has no H2-upstream support (OpenResty/nginx limitation),
        #        so a Kong/http2 row would not be uniform H2 end-to-end.
        # http3: KONG_PROXY_LISTEN does not parse http3/quic flags and Kong
        #        has no documented first-class HTTP/3 config path.
        wss)
            proxy_listen_env="0.0.0.0:${GATEWAY_HTTP_PORT}, 0.0.0.0:${GATEWAY_HTTPS_PORT} ssl"
            ;;
        tcp-tls)
            proxy_listen_env="0.0.0.0:${GATEWAY_HTTP_PORT}"
            stream_listen_env="0.0.0.0:${GATEWAY_TCP_TLS_PORT} ssl"
            ;;
        udp)
            proxy_listen_env="0.0.0.0:${GATEWAY_HTTP_PORT}"
            stream_listen_env="0.0.0.0:${GATEWAY_UDP_PORT} udp reuseport"
            ;;
    esac

    local extra_env=()
    [ -n "$stream_listen_env" ] && extra_env+=(-e "KONG_STREAM_LISTEN=$stream_listen_env")

    GATEWAY_CID=$(docker run -d --rm --network host \
        -e "KONG_DATABASE=off" \
        -e "KONG_DECLARATIVE_CONFIG=/kong/kong.yaml" \
        -e "KONG_PROXY_LISTEN=$proxy_listen_env" \
        -e "KONG_LOG_LEVEL=error" \
        -e "KONG_PROXY_ACCESS_LOG=off" \
        -e "KONG_PROXY_ERROR_LOG=/dev/stderr" \
        -e "KONG_ADMIN_LISTEN=0.0.0.0:8001" \
        -e "KONG_SSL_CERT=/certs/cert.pem" \
        -e "KONG_SSL_CERT_KEY=/certs/key.pem" \
        -e "KONG_STREAM_SSL_CERT=/certs/cert.pem" \
        -e "KONG_STREAM_SSL_CERT_KEY=/certs/key.pem" \
        -e "KONG_LUA_SSL_TRUSTED_CERTIFICATE=/certs/cert.pem" \
        -e "KONG_NGINX_STREAM_LUA_SSL_TRUSTED_CERTIFICATE=/certs/cert.pem" \
        "${extra_env[@]}" \
        -v "$cfg_dst:/kong/kong.yaml:ro" \
        -v "$CERT_DIR:/certs:ro" \
        "$KONG_IMAGE")

    wait_for_gateway
}

kong_config_name() {
    case "$PROTOCOL" in
        http1-tls) echo "http1_tls.yaml" ;;
        grpcs)     echo "grpcs.yaml" ;;
        wss)       echo "wss.yaml" ;;
        tcp-tls)   echo "tcp_tls.yaml" ;;
        udp)       echo "udp.yaml" ;;
    esac
}

# ── Tyk (docker + redis) ────────────────────────────────────────────────────
start_redis() {
    echo "[redis] starting..."
    REDIS_CID=$(docker run -d --rm --network host "$REDIS_IMAGE" redis-server --bind 127.0.0.1 --port 6379)
    for i in $(seq 1 20); do
        if docker exec "$REDIS_CID" redis-cli ping 2>/dev/null | grep -q PONG; then
            return
        fi
        sleep 0.5
    done
    echo "[redis] failed to start" >&2
    exit 1
}

start_tyk() {
    start_redis
    local apps_dir="$SCRIPT_DIR/configs/tyk/apps_$(tyk_apps_suffix)"
    local tyk_conf="$SCRIPT_DIR/configs/tyk/tyk.conf"
    # Tyk listens on 8443 when TLS is enabled in tyk.conf
    echo "[tyk] starting with apps=$apps_dir..."

    # Install the benchmark CA into the container's system trust store
    # before launching Tyk. Tyk Classic API `transport.ssl_ca_cert` does
    # NOT configure upstream trust (confirmed locally: it's a no-op —
    # handshakes fail with the same error whether ssl_ca_cert points at
    # the real cert or a nonexistent path). The Go `net/http` transport
    # Tyk uses for reverse-proxy upstreams consults the default system
    # RootCAs pool, so the reliable fix is to install the PEM as a
    # system CA before starting the gateway. Tyk's image is Debian
    # bookworm-based with `update-ca-certificates` available, and runs
    # as root by default.
    GATEWAY_CID=$(docker run -d --rm --network host \
        -v "$apps_dir:/etc/tyk/apps:ro" \
        -v "$tyk_conf:/opt/tyk-gateway/tyk.conf:ro" \
        -v "$CERT_DIR:/etc/tyk/certs:ro" \
        --entrypoint sh \
        "$TYK_IMAGE" \
        -c 'cp /etc/tyk/certs/cert.pem /usr/local/share/ca-certificates/bench.crt && update-ca-certificates >/dev/null 2>&1; exec /opt/tyk-gateway/tyk --conf /opt/tyk-gateway/tyk.conf')

    wait_for_gateway
}

tyk_apps_suffix() {
    case "$PROTOCOL" in
        http1-tls) echo "http1_tls" ;;
        http2)     echo "http2_tls" ;;
        grpcs)     echo "grpcs" ;;
        wss)       echo "wss" ;;
        tcp-tls)   echo "tcp_tls" ;;
    esac
}

# ── KrakenD (docker) ────────────────────────────────────────────────────────
start_krakend() {
    local cfg_src="$SCRIPT_DIR/configs/krakend/$(krakend_config_name)"
    local cfg_dst="$SCRIPT_DIR/krakend_runtime.json"

    sed -e "s|CERT_PATH|/certs/cert.pem|g" \
        -e "s|KEY_PATH|/certs/key.pem|g" \
        "$cfg_src" > "$cfg_dst"

    echo "[krakend] starting..."
    GATEWAY_CID=$(docker run -d --rm --network host \
        -v "$cfg_dst:/etc/krakend/krakend.json:ro" \
        -v "$CERT_DIR:/certs:ro" \
        "$KRAKEND_IMAGE" \
        run -c /etc/krakend/krakend.json)

    wait_for_gateway
}

krakend_config_name() {
    case "$PROTOCOL" in
        http1-tls) echo "http1_tls.json" ;;
        http2)     echo "http2_tls.json" ;;
        grpcs)     echo "grpcs.json" ;;
        wss)       echo "wss.json" ;;
    esac
}

# ── Gateway readiness check ─────────────────────────────────────────────────
# Verifies the gateway container is alive and (where possible) listening.
# For UDP/QUIC we cannot TCP-probe, so we verify the container is still running
# and scan its recent logs for fatal markers — this catches the common case
# where the gateway crashes during startup (port bind failure, bad config).
container_alive() {
    [ -z "$GATEWAY_CID" ] && return 1
    local state
    state=$(docker inspect -f '{{.State.Running}}' "$GATEWAY_CID" 2>/dev/null || echo "false")
    [ "$state" = "true" ]
}

container_has_fatal_log() {
    [ -z "$GATEWAY_CID" ] && return 1
    # Patterns chosen to match fatal startup errors across all 5 gateways;
    # avoids matching benign log lines like "error_log /var/log/..." (nginx
    # config) or routine "debug: error handling" messages.
    docker logs "$GATEWAY_CID" 2>&1 | tail -100 | \
        grep -qE "FATAL|PANIC|bind: address already in use|failed to bind|cert file not found|no such file|permission denied|listen tcp .*: bind:" && return 0
    return 1
}

# Active UDP probe — sends a datagram and waits briefly for an echo reply.
# Returns 0 iff the reply content matches. Used to confirm an echo-style
# UDP gateway (Ferrum/Envoy/Kong plain UDP) is fully forwarding before
# the bench fires, because the nginx-stream / udp_proxy cold-start window
# can swallow the first datagrams and cause 0 RPS benchmarks.
probe_udp_echo() {
    local port=$1
    local out
    out=$(echo -n "bench-probe" | nc -u -w 1 127.0.0.1 "$port" 2>/dev/null | head -c 32)
    [ "$out" = "bench-probe" ]
}

wait_for_gateway() {
    local target_port
    case "$PROTOCOL" in
        tcp-tls) target_port=$GATEWAY_TCP_TLS_PORT ;;
        udp) target_port=$GATEWAY_UDP_PORT ;;
        udp-dtls) target_port=$GATEWAY_UDP_DTLS_PORT ;;
        http3) target_port=$GATEWAY_HTTPS_PORT ;;
        *) target_port=$GATEWAY_HTTPS_PORT ;;
    esac

    for i in $(seq 1 40); do
        case "$PROTOCOL" in
            udp)
                # Plain UDP: container-alive check is not enough because
                # Kong's stream-subsystem cold start can drop datagrams
                # for 5-15 seconds after the listener binds. Actively
                # probe with a UDP packet and wait for the echo reply;
                # only declare ready when a round-trip actually completes.
                if [ "$i" -ge 6 ]; then
                    if container_has_fatal_log; then
                        echo "[gateway] fatal log entry detected for $PROTOCOL" >&2
                        docker logs "$GATEWAY_CID" 2>&1 | tail -30 >&2 || true
                        return 1
                    fi
                    if ! container_alive; then
                        echo "[gateway] container exited for $PROTOCOL" >&2
                        docker logs "$GATEWAY_CID" 2>&1 | tail -30 >&2 || true
                        return 1
                    fi
                    if probe_udp_echo "$target_port"; then
                        echo "[gateway] udp ready on port $target_port (active probe)"
                        sleep 1
                        return 0
                    fi
                fi
                sleep 0.5
                ;;
            udp-dtls|http3)
                # UDP/DTLS + QUIC cannot be probed with a plain UDP datagram
                # because the first packet has to be a DTLS/QUIC ClientHello.
                # Fall back to container-alive + fatal-log scan, same as
                # before — these protocols don't exhibit the Kong-style
                # cold-start drop problem in the current matrix.
                if [ "$i" -ge 6 ]; then
                    if container_has_fatal_log; then
                        echo "[gateway] fatal log entry detected for $PROTOCOL" >&2
                        docker logs "$GATEWAY_CID" 2>&1 | tail -30 >&2 || true
                        return 1
                    fi
                    if container_alive; then
                        echo "[gateway] container alive for $PROTOCOL (udp-encrypted/quic — no active probe)"
                        sleep 1
                        return 0
                    fi
                    echo "[gateway] container exited for $PROTOCOL" >&2
                    docker logs "$GATEWAY_CID" 2>&1 | tail -30 >&2 || true
                    return 1
                fi
                sleep 0.5
                ;;
            *)
                if bash -c ">/dev/tcp/127.0.0.1/$target_port" 2>/dev/null; then
                    echo "[gateway] ready on port $target_port"
                    sleep 1  # grace period
                    return 0
                fi
                sleep 0.5
                ;;
        esac
    done
    echo "[gateway] failed to become ready on port $target_port" >&2
    [ -n "$GATEWAY_CID" ] && docker logs "$GATEWAY_CID" 2>&1 | tail -50 >&2 || true
    return 1
}

stop_gateway() {
    [ -n "$GATEWAY_CID" ] && docker rm -f "$GATEWAY_CID" >/dev/null 2>&1 || true
    [ -n "$REDIS_CID" ] && docker rm -f "$REDIS_CID" >/dev/null 2>&1 || true
    GATEWAY_CID=""
    REDIS_CID=""
    sleep 2
}

# ── Bench runner ────────────────────────────────────────────────────────────
# Auto-scales concurrency down for large payloads so an ubuntu-latest runner
# (7 GB RAM) doesn't OOM on 5MB × 100 concurrent in-flight bodies.
scale_concurrency_for_payload() {
    local size="$1" base="$2"
    if [ "$size" -ge 5242880 ]; then
        echo $(( base / 4 > 4 ? base / 4 : 4 ))
    elif [ "$size" -ge 1048576 ]; then
        echo $(( base / 2 > 4 ? base / 2 : 4 ))
    else
        echo "$base"
    fi
}

run_bench() {
    local gateway="$1"
    local payload="$2"
    local target="$3"  # "gateway" or "direct"

    local params
    params=($(bench_params))
    local bench_proto="${params[0]}"
    local bench_target
    if [ "$target" = "direct" ]; then
        bench_target="${params[2]}"
    else
        bench_target="${params[1]}"
    fi
    local extra_args=("${params[@]:3}")
    local effective_concurrency
    effective_concurrency=$(scale_concurrency_for_payload "$payload" "$CONCURRENCY")

    local out="$OUTPUT_DIR/${gateway}_${PROTOCOL}_${payload}.json"
    echo "[bench] $gateway/$PROTOCOL payload=${payload}B concurrency=${effective_concurrency} → $bench_target"

    # Wall-clock kill-switch. proto_bench has its own per-iteration I/O
    # timeouts, but this outer `timeout` is a belt-and-suspenders guard
    # against any future hang path (new protocol handler, dependency change,
    # etc.) that would otherwise let a single stuck bench eat the workflow's
    # 75-minute step budget. DURATION seconds of actual work + 60s head-room
    # for connect/handshake/teardown.
    local bench_wallclock=$(( DURATION + 60 ))

    # `|| rc=$?` captures the exit code without tripping `set -e`. Using an
    # `if !` branch here would clear $? inside the then-block (bash semantics
    # of the `!` negation), so we'd lose the ability to distinguish a 124
    # (timeout) from a generic non-zero exit.
    local rc=0
    timeout "${bench_wallclock}s" \
        "$SCRIPT_DIR/target/release/proto_bench" "$bench_proto" \
        --target "$bench_target" \
        --duration "$DURATION" \
        --concurrency "$effective_concurrency" \
        --payload-size "$payload" \
        --json "${extra_args[@]}" > "$out" 2>"$OUTPUT_DIR/${gateway}_${PROTOCOL}_${payload}.err" \
        || rc=$?
    if [ "$rc" -ne 0 ]; then
        if [ "$rc" -eq 124 ]; then
            echo "[bench] TIMED OUT after ${bench_wallclock}s: $gateway/$PROTOCOL payload=${payload}B"
            echo "{\"gateway\":\"$gateway\",\"protocol\":\"$PROTOCOL\",\"payload_size\":$payload,\"effective_concurrency\":$effective_concurrency,\"error\":\"bench wallclock timeout\",\"rps\":0}" > "$out"
        else
            echo "[bench] FAILED (rc=$rc): $gateway/$PROTOCOL payload=${payload}B — see ${out}.err"
            echo "{\"gateway\":\"$gateway\",\"protocol\":\"$PROTOCOL\",\"payload_size\":$payload,\"effective_concurrency\":$effective_concurrency,\"error\":\"bench failed\",\"rps\":0}" > "$out"
        fi
        return 0
    fi

    # Stamp metadata into JSON for aggregation.
    python3 - "$out" "$gateway" "$payload" "$effective_concurrency" <<'PYEOF'
import json, sys
path, gateway, payload, concurrency = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
try:
    with open(path) as f:
        d = json.load(f)
except Exception:
    d = {"rps": 0, "error": "unparseable"}
d["gateway"] = gateway
d["payload_size"] = payload
d["effective_concurrency"] = concurrency
with open(path, "w") as f:
    json.dump(d, f, indent=2)
PYEOF
    local rps
    rps=$(python3 -c "import json; print(f\"{json.load(open('$out'))['rps']:,.0f}\")" 2>/dev/null || echo "?")
    echo "[bench]   → RPS=$rps"
}

# ── Orchestration ───────────────────────────────────────────────────────────
main() {
    mkdir -p "$OUTPUT_DIR"
    echo "[main] protocol=$PROTOCOL sizes=$PAYLOAD_SIZES gateways=$GATEWAYS"

    build_binaries
    start_backend

    # Direct baseline first (no gateway interference)
    if ! $SKIP_DIRECT; then
        for size in $PAYLOAD_SIZES; do
            run_bench "direct" "$size" "direct"
        done
    fi

    for gw in $GATEWAYS; do
        if ! supports "$gw" "$PROTOCOL"; then
            echo "[main] skipping $gw: does not support $PROTOCOL"
            continue
        fi
        echo "[main] === $gw ==="
        case "$gw" in
            ferrum)  start_ferrum ;;
            envoy)   start_envoy ;;
            kong)    start_kong ;;
            tyk)     start_tyk ;;
            krakend) start_krakend ;;
        esac || { echo "[main] $gw failed to start, skipping"; stop_gateway; continue; }

        for size in $PAYLOAD_SIZES; do
            run_bench "$gw" "$size" "gateway"
        done
        stop_gateway
    done

    echo "[main] done. results in $OUTPUT_DIR"
    ls -la "$OUTPUT_DIR"
}

main
