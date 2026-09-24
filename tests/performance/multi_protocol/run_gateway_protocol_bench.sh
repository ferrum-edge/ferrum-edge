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
#   --skip-direct               (accepted for frozen workflow; pairs always include direct)
#   --pairs N                   (even integer 2..12, default 2)
#   --baseline-image IMAGE      (optional pinned Ferrum reference image)
#   --adaptive                  (opt in to one budget-gated extension)
#   --wallclock-budget-seconds N (per invocation, default 4200)
#   --experiment-manifest PATH (explicit opt-in; default remains experiment.json)
#   --no-process-usage          (diagnostic only; paired comparisons invalid)
#   --pool-profile calibration|profile (separate fixed-window H2/gRPC lane)
#   --h1-profile calibration|cutoff|diagnostic (separate manual H1 lane; see docs/h1_internal_profile.md)
#
# All gateways (including Ferrum) run in Docker with --network host so no gateway
# has a native-binary advantage. proto_backend and proto_bench run natively
# since they are the backend and client under test, not gateways being benchmarked.
#
# Exit code: 0 on success (some benches may fail individually — check JSON files).

set -eo pipefail

# Finite opt-in live lane; all ordinary H1/H2 and historical H3 inputs stay intact.
if [[ ${1:-} == http3 && ${2:-} == --h3-live ]]; then
    [[ $# == 6 && $3 == corrected-v1 && $5 == --output-dir ]] || exit 2
    case "$4" in smoke|10240|71680|512000|1048576|5242880) ;; *) exit 2 ;; esac
    exec python3 tests/performance/multi_protocol/h3_proof/live.py \
        --campaign corrected-v1 --payload "$4" --output "$6"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

# ── Portable `timeout` command (GNU coreutils) ──────────────────────────────
# macOS/BSD ships without `timeout`; Homebrew installs it as `gtimeout`.
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
else
    TIMEOUT_CMD=""
    echo "[warn] Neither 'timeout' nor 'gtimeout' found — bench runs will have no wallclock kill-switch" >&2
fi

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
PAIRS=2
ADAPTIVE=false
WALLCLOCK_BUDGET=4200
PROCESS_USAGE=true
BASELINE_IMAGE="${FERRUM_BASELINE_IMAGE:-}"
PAIR=0
ORDER_POSITION=0
HOST_ID=""
EXPERIMENT_MANIFEST="$SCRIPT_DIR/experiment.json"
EXPERIMENT_ARMS=""
H2_OBSERVE=0
H1_PROFILE=""
H1_TRACE=none
H1_TRACE_BUILDS=""
h1_trace_pid=""
h1_trace_output=""
POOL_PROFILE=""
UDP_PROFILE=""
H2_GUARD_OBSERVE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --experiment-manifest) EXPERIMENT_MANIFEST="$2"; shift 2 ;;
        --gateways) GATEWAYS="$2"; shift 2 ;;
        --payload-sizes) PAYLOAD_SIZES="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        --skip-direct) SKIP_DIRECT=true; shift ;;
        --pairs) PAIRS="$2"; shift 2 ;;
        --baseline-image) BASELINE_IMAGE="$2"; shift 2 ;;
        --adaptive) ADAPTIVE=true; shift ;;
        --wallclock-budget-seconds) WALLCLOCK_BUDGET="$2"; shift 2 ;;
        --no-process-usage) PROCESS_USAGE=false; shift ;;
        --h1-profile) H1_PROFILE="$2"; shift 2 ;;
        --h1-trace) H1_TRACE="$2"; shift 2 ;;
        --h1-trace-builds) H1_TRACE_BUILDS="$2"; shift 2 ;;
        --pool-profile) POOL_PROFILE="$2"; shift 2 ;;
        --udp-profile) UDP_PROFILE="$2"; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# DURATION and PAYLOAD_SIZES reach Bash arithmetic below. Validate first so
# caller-controlled values cannot be evaluated as expressions.
if [[ ! $DURATION =~ ^[0-9]+$ ]]; then
    echo "--duration must be a non-negative integer" >&2
    exit 2
fi
if [[ ! $PAYLOAD_SIZES =~ ^[0-9]+( [0-9]+)*$ ]]; then
    echo "--payload-sizes must be non-negative integers separated by single spaces" >&2
    exit 2
fi

if [[ ! $PAIRS =~ ^(2|4|6|8|10|12)$ ]] && ! { [ "$H1_PROFILE" = diagnostic ] && [ "$PAIRS" = 1 ]; }; then
    echo "--pairs must be an EVEN integer from 2 through 12 for exact position balance" >&2
    exit 2
fi
if [[ ! $WALLCLOCK_BUDGET =~ ^[1-9][0-9]{0,4}$ ]]; then
    echo "--wallclock-budget-seconds must be a positive integer (at most 99999)" >&2
    exit 2
fi
if [ ! -r /proc/self/stat ] || [ ! -r /proc/sys/kernel/random/boot_id ]; then
    PROCESS_USAGE=false
fi
if [ "$PROCESS_USAGE" != true ]; then
    echo "[warn] process_usage unavailable; samples are diagnostic and invalid for paired comparisons" >&2
fi

# Separate manual H1 lane: never selects or rewrites the active H2 manifest.
if [ -n "$H1_PROFILE" ]; then
    python3 "$SCRIPT_DIR/h1_internal_profile.py" validate-selection \
        "$H1_PROFILE" "$PROTOCOL" "$PAIRS" "$DURATION" "$CONCURRENCY" \
        "$GATEWAYS" "$PAYLOAD_SIZES" "$BASELINE_IMAGE" "${FERRUM_EXTRA_ENV:-}" || exit 2
    [ "$PROCESS_USAGE" = true ] && [ "$ADAPTIVE" = false ] || exit 2
fi

case "$H1_TRACE" in none|syscalls|cpu) ;; *) exit 2 ;; esac
if [ "$H1_TRACE" != none ]; then
    # One existing payload shard per bounded collector lifetime; all five shards
    # remain required. Direct controls are never profiled.
    [[ "$H1_PROFILE" == trace-calibration || "$H1_PROFILE" == cutoff ]] || exit 2
    [[ "$PAYLOAD_SIZES" != *" "* && -d "$H1_TRACE_BUILDS" ]] || exit 2
    [[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]] || exit 2
fi

# Independent fixed-policy pool lane; ordinary experiment.json stays disabled.
if [ -n "$POOL_PROFILE" ]; then
    [ -z "$H1_PROFILE" ] && [ -z "$UDP_PROFILE" ] && [ "$PROCESS_USAGE" = true ] && [ "$ADAPTIVE" = false ] || exit 2
    python3 "$SCRIPT_DIR/pool_internal_profile.py" validate-selection \
        "$POOL_PROFILE" "$PROTOCOL" "$PAIRS" "$DURATION" "$CONCURRENCY" \
        "$GATEWAYS" "$PAYLOAD_SIZES" "$BASELINE_IMAGE" "${FERRUM_EXTRA_ENV:-}" || exit 2
    H2_OBSERVE=1
fi

# Dedicated UDP campaign; never selects or rewrites H1/H2/H3 manifests.
if [ -n "$UDP_PROFILE" ]; then
    [ -z "$H1_PROFILE" ] && [ -z "$POOL_PROFILE" ] && [ "$PROCESS_USAGE" = true ] && [ "$ADAPTIVE" = false ] || exit 2
    python3 "$SCRIPT_DIR/udp_internal_profile.py" validate-selection \
        "$UDP_PROFILE" "$PROTOCOL" "$PAIRS" "$DURATION" "$CONCURRENCY" \
        "$GATEWAYS" "$PAYLOAD_SIZES" "$BASELINE_IMAGE" "${FERRUM_EXTRA_ENV:-}" || exit 2
fi

if [ "$H1_PROFILE" = diagnostic ] && [ -z "${H1_DIAGNOSTIC_WORK_DEADLINE:-}" ]; then
    # Independent parent owns startup, reader waits, docker and cleanup under
    # one deadline. Re-entry uses a literal, fixed-workload child script.
    exec python3 "$SCRIPT_DIR/h1_diagnostic_campaign.py" \
        --output-dir "$OUTPUT_DIR" --budget "$WALLCLOCK_BUDGET"
fi
if [ "$H1_PROFILE" = diagnostic ]; then
    [ "$PPID" = "${H1_DIAGNOSTIC_SUPERVISOR_PID:-}" ] || exit 2
fi

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

# A committed data manifest is the experiment input to the frozen hosted job.
H3_BUDGET=0
GATEWAY_LOG_LEVEL=error
if [ -n "$POOL_PROFILE" ]; then GATEWAY_LOG_LEVEL=warn,ferrum_h2_observe=debug; fi
if [ "$PROTOCOL" = http3 ]; then
    H3_BUDGET=$(python3 "$SCRIPT_DIR/h3_experiment.py" settings \
        "${H3_EXPERIMENT_MANIFEST:-$SCRIPT_DIR/h3_experiment.json}")
    if [ "$H3_BUDGET" -ne 0 ]; then
        GATEWAY_LOG_LEVEL=info
        # Defaults are effective kernel bytes. Apply identically before creating
        # client, backend and either gateway; Envoy's explicit options read back
        # the same limits. This is scoped to the disposable hosted runner.
        sudo -n sysctl -w "net.core.rmem_max=$H3_BUDGET" "net.core.wmem_max=$H3_BUDGET" \
            "net.core.rmem_default=$H3_BUDGET" "net.core.wmem_default=$H3_BUDGET" \
            > "$OUTPUT_DIR/socket_budget.txt"
    fi
fi

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
        # KrakenD CE HTTP/2: Lura's custom http.Transport doesn't call
        # http2.ConfigureTransport(), so backend connections fall back
        # to HTTP/1.1. The H2-only backend (port 3443) rejects the ALPN
        # mismatch → KrakenD returns 502 for every request. Tyk (also
        # Go) works because it explicitly enables H2 on its transport.
        krakend:http1-tls) return 0 ;;
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
        grpcs)     echo "grpc https://127.0.0.1:${GATEWAY_HTTPS_PORT} https://127.0.0.1:50053 --ca-cert ${CERT_DIR}/ca.pem" ;;
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
sampler_pid=""
sampler_stop_file=""
CERT_DIR="$SCRIPT_DIR/certs"
# Every fixed port this runner's backend/gateways/Redis/Envoy bind. The startup
# conflict check and cleanup share this list so they cannot drift apart.
BENCH_PORTS="3001 3002 3003 3004 3005 3006 3010 3443 3444 3445 3446 3447 \
50052 50053 \
$GATEWAY_HTTP_PORT $GATEWAY_HTTPS_PORT \
$GATEWAY_TCP_TLS_PORT $GATEWAY_UDP_PORT $GATEWAY_UDP_DTLS_PORT \
15000 9901 6379"

# Gracefully stop a PID this run started: TERM, bounded wait, then KILL.
stop_pid() {
    local pid="$1"
    local attempt
    [ -z "$pid" ] && return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for attempt in 1 2 3 4 5; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    fi
}

# Gracefully stop a Docker container this run started: `docker stop` (SIGTERM
# then bounded SIGKILL) with a forced removal fallback.
stop_container() {
    local cid="$1"
    [ -z "$cid" ] && return 0
    docker stop --time 5 "$cid" >/dev/null 2>&1 || true
    docker rm -f "$cid" >/dev/null 2>&1 || true
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
    if [ -n "$sampler_pid" ]; then
        if [ -n "$sampler_stop_file" ]; then
            touch "$sampler_stop_file"
        else
            kill -TERM "$sampler_pid" 2>/dev/null || true
        fi
        wait "$sampler_pid" || true
    fi
    stop_pid "$BACKEND_PID"
    stop_container "$GATEWAY_CID"
    stop_container "$REDIS_CID"
    h1_trace_stop
}
if [ "$H1_PROFILE" != diagnostic ]; then
    trap cleanup EXIT
fi
# Diagnostic cleanup is unconditional in the independent supervisor. In
# particular it does not inherit cleanup()'s owned-process waits; that rerun
# path stops and removes only the gateway/backend IDs that supervisor started.

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
    local backend_log="$SCRIPT_DIR/backend.log"
    if [ "$H1_PROFILE" = diagnostic ]; then
        mkdir -p "$OUTPUT_DIR/diagnostics"
        backend_log="$OUTPUT_DIR/diagnostics/${gw}_backend.raw.log"
    fi
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
    BENCH_H2_OBSERVE="$H2_OBSERVE" H3_PROFILE="$H3_BUDGET" \
        ./target/release/proto_backend > "$backend_log" 2>&1 &
    BACKEND_PID=$!
    cd "$saved_pwd"

    for i in $(seq 1 20); do
        if curl -sf http://127.0.0.1:3010/health >/dev/null 2>&1; then
            echo "[backend] healthy (pid $BACKEND_PID)"
            # Wait for cert generation
            for j in $(seq 1 10); do
                [ -f "$CERT_DIR/ca.pem" ] && [ -f "$CERT_DIR/cert.pem" ] && break
                sleep 0.5
            done
            return
        fi
        sleep 0.5
    done
    echo "[backend] failed to start" >&2
    tail -30 "$backend_log" >&2
    exit 1
}

# ── Ferrum (docker, distroless image from repo Dockerfile) ──────────────────
prepare_ferrum_config() {
    local src_config="$1"
    local ca_path="$2"
    local runtime_config="$SCRIPT_DIR/ferrum_runtime_$(basename "$src_config")"

    sed -e "s|CA_PATH|${ca_path}|g" \
        "$src_config" > "$runtime_config"

    echo "$runtime_config"
}

start_ferrum() {
    local config_src="$SCRIPT_DIR/configs/$(ferrum_config_name)"
    local config_file
    config_file=$(prepare_ferrum_config "$config_src" "/etc/ferrum/tls/ca.pem")
    if [ "$H2_OBSERVE" -eq 1 ]; then
        mkdir -p "$OUTPUT_DIR/diagnostics"
        config_file="$OUTPUT_DIR/diagnostics/${gw}_config.yaml"
        if [ -n "$POOL_PROFILE" ]; then
            python3 "$SCRIPT_DIR/pool_internal_profile.py" materialize \
                "$PROTOCOL" "$gw" "$config_src" "$config_file" "$root_output/manifest.json" || return 2
        else
            python3 "$SCRIPT_DIR/experiment_arms.py" materialize "$EXPERIMENT_MANIFEST" \
                "$PROTOCOL" "$gw" "$config_src" "$config_file" "$root_output/manifest.json" || return 2
        fi
    fi
    echo "[ferrum] starting ($FERRUM_IMAGE) with $(basename "$config_src")..."

    # FERRUM_POOL_ENABLE_HTTP2 defaults to true (see CLAUDE.md), no need to set.
    local extra_env=()
    local response_cutoff=0
    case "$PROTOCOL" in
        http3)
            extra_env+=(
                -e "FERRUM_ENABLE_HTTP3=true"
            )
            ;;
    esac
    # Optional extra env var injection for per-experiment tuning. Set
    # FERRUM_EXTRA_ENV to a space-separated list of KEY=VALUE pairs, e.g.:
    #   FERRUM_EXTRA_ENV='FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE=524288 FERRUM_HTTP3_INITIAL_MTU=1472'
    if [ -n "${FERRUM_EXTRA_ENV:-}" ]; then
        for pair in $FERRUM_EXTRA_ENV; do
            extra_env+=(-e "$pair")
        done
    fi
    if [ -n "$H1_PROFILE" ]; then
        extra_env+=(-e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1
                    -e FERRUM_ADMIN_HTTP_PORT=9000
                    -e FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32)
        if [ "$gw" = ferrum-exp-cutoff-one ]; then
            response_cutoff=1
        fi
    fi
    if [ -n "$POOL_PROFILE" ]; then
        extra_env+=(-e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1
                    -e FERRUM_ADMIN_HTTP_PORT=9000
                    -e FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32
                    -e FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=false)
    fi
    if [ -n "$UDP_PROFILE" ]; then
        extra_env+=(-e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1
                    -e FERRUM_ADMIN_HTTP_PORT=9000
                    -e FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32)
    fi

    if [ "$H1_PROFILE" = diagnostic ]; then
        extra_env+=(--name "$H1_DIAGNOSTIC_CONTAINER_PREFIX-$gw")
    fi
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
        -e "FERRUM_LOG_LEVEL=$GATEWAY_LOG_LEVEL" \
        -e "FERRUM_ADD_VIA_HEADER=false" \
        -e "FERRUM_ADD_FORWARDED_HEADER=false" \
        -e "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0" \
        -e "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0" \
        -e "FERRUM_MAX_GRPC_RECV_SIZE_BYTES=0" \
        -e "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=$response_cutoff" \
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
        -e "FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST=16" \
        -e "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS=1000" \
        -e "FERRUM_UDP_MAX_SESSIONS=10000" \
        -e "FERRUM_UDP_RECVMMSG_BATCH_SIZE=64" \
        -e "FERRUM_TCP_IDLE_TIMEOUT_SECONDS=30" \
        -e "FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS=30" \
        "${extra_env[@]}" \
        "$FERRUM_IMAGE")

    if [ -n "$POOL_PROFILE" ]; then
        docker inspect "$GATEWAY_CID" --format '{{json .}}' | \
            python3 "$SCRIPT_DIR/pool_internal_profile.py" runtime \
                "$OUTPUT_DIR/diagnostics/${gw}_runtime.json" "$config_file" || return 2
    elif [ "$H2_OBSERVE" -eq 1 ]; then
        docker inspect "$GATEWAY_CID" --format '{{json .}}' | \
            python3 "$SCRIPT_DIR/experiment_arms.py" verify-runtime \
                "$EXPERIMENT_MANIFEST" "$PROTOCOL" "$gw" "$root_output/manifest.json" || return 2
    fi
    if [ -n "$H1_PROFILE" ]; then
        mkdir -p "$OUTPUT_DIR/diagnostics"
        cp "$config_file" "$OUTPUT_DIR/diagnostics/${gw}_config.yaml"
        docker inspect "$GATEWAY_CID" --format '{{json .}}' | \
            python3 "$SCRIPT_DIR/h1_internal_profile.py" runtime \
                "$OUTPUT_DIR/diagnostics/${gw}_runtime.json" "$config_file" \
                "$PAIR" "$gw" "$HOST_ID" "$H1_PROFILE"
    fi
    if [ "$H1_TRACE" != none ]; then
        python3 "$SCRIPT_DIR/h1_trace.py" bind --output "$h1_trace_output" \
            --runtime "$OUTPUT_DIR/diagnostics/${gw}_runtime.json" \
            --config "$OUTPUT_DIR/diagnostics/${gw}_config.yaml" \
            --sample "$OUTPUT_DIR/${gw}_${PROTOCOL}_${PAYLOAD_SIZES}.json" \
            --arm "$gw" --pair "$PAIR" --payload "$PAYLOAD_SIZES" \
            --raw-sample "$OUTPUT_DIR/diagnostics/${gw}_${PAYLOAD_SIZES}_client.raw.json" \
            --client-exit "$OUTPUT_DIR/diagnostics/${gw}_${PAYLOAD_SIZES}_client.exit"
        local trace_wait=0
        while [ ! -s "$h1_trace_output/ready.json" ] && [ "$trace_wait" -lt 600 ]; do
            [ ! -s "$h1_trace_output/stopped.json" ] || return 1
            sleep 0.05
            trace_wait=$(( trace_wait + 1 ))
        done
        [ -s "$h1_trace_output/ready.json" ] || return 1
    fi
    if [ -n "$UDP_PROFILE" ]; then
        mkdir -p "$OUTPUT_DIR/diagnostics"
        cp "$config_file" "$OUTPUT_DIR/diagnostics/${gw}_config.yaml"
        docker inspect "$GATEWAY_CID" --format '{{json .}}' | \
            python3 "$SCRIPT_DIR/udp_internal_profile.py" runtime \
                "$OUTPUT_DIR/diagnostics/${gw}_runtime.json" "$config_file"
    fi
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
    # Substitute CERT_PATH / KEY_PATH / CA_PATH to mount points inside
    # container. CA_PATH is a separate placeholder (not reused as
    # CERT_PATH) so run_protocol_test.sh can point it at an absolute
    # host path when running Envoy directly, without Envoy container
    # mount assumptions.
    sed -e "s|CERT_PATH|/certs/cert.pem|g" \
        -e "s|KEY_PATH|/certs/key.pem|g" \
        -e "s|CA_PATH|/certs/ca.pem|g" \
        "$cfg_src" > "$cfg_dst"
    if [ "$PROTOCOL" = http3 ] && [ "$H3_BUDGET" -ne 0 ]; then
        python3 "$SCRIPT_DIR/h3_experiment.py" envoy "$cfg_dst" "$cfg_dst" \
            "${ENVOY_STREAM_LIMIT:-100}" "$H3_BUDGET"
    fi

    echo "[envoy] starting..."
    GATEWAY_CID=$(docker run -d --rm --network host \
        -v "$cfg_dst:/etc/envoy/envoy.yaml:ro" \
        -v "$CERT_DIR:/certs:ro" \
        "$ENVOY_IMAGE" \
        envoy -c /etc/envoy/envoy.yaml --concurrency "$(nproc 2>/dev/null || echo 4)" \
        -l "$GATEWAY_LOG_LEVEL" --disable-hot-restart)

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

    # No CA-into-YAML templating — the upstream trust anchor is now imposed
    # globally via nginx env vars below (KONG_NGINX_*_PROXY_SSL_*), not via
    # per-service `ca_certificates` entities. The declarative configs in
    # configs/kong/ are checked in as-is. See configs/kong/http1_tls.yaml
    # rationale comment for why this matters for upstream pool reuse.
    cp "$cfg_src" "$cfg_dst"

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
        -e "KONG_LUA_SSL_TRUSTED_CERTIFICATE=/certs/ca.pem" \
        `# NB: don't also set KONG_NGINX_STREAM_LUA_SSL_TRUSTED_CERTIFICATE.` \
        `# Kong 3.10 propagates the global KONG_LUA_SSL_TRUSTED_CERTIFICATE` \
        `# directive into BOTH http{} and stream{} blocks; the stream-` \
        `# specific env var would emit a second lua_ssl_trusted_certificate` \
        `# line in nginx-kong-stream.conf and nginx aborts with` \
        `# "directive is duplicate" — visible only when KONG_STREAM_LISTEN` \
        `# is set (i.e. tcp-tls / udp), which is why the dup hid until now.` \
        -e "KONG_UPSTREAM_KEEPALIVE_POOL_SIZE=256" \
        -e "KONG_UPSTREAM_KEEPALIVE_MAX_REQUESTS=10000" \
        `# ── Static upstream TLS trust + verify (global) ──────────────` \
        `# Set via nginx-directive injection so the upstream SSL_CTX is` \
        `# built once at config-load. Per-service ca_certificates +` \
        `# tls_verify rebuilds the SSL_CTX per request via Lua, which` \
        `# defeats OpenResty's keepalive pool match (~450 RPS ceiling` \
        `# on H1-TLS at concurrency 100 vs ~10K with static trust).` \
        `# Three variants cover all three nginx upstream paths:` \
        `#   PROXY_PROXY_SSL_*  → http proxy_pass (HTTP/1.1, HTTPS)` \
        `#   PROXY_GRPC_SSL_*   → http grpc_pass  (gRPC)` \
        `#   STREAM_PROXY_SSL_* → stream proxy    (TCP+TLS)` \
        `# See configs/kong/*.yaml rationale comments for full context.` \
        -e "KONG_NGINX_PROXY_PROXY_SSL_TRUSTED_CERTIFICATE=/certs/ca.pem" \
        -e "KONG_NGINX_PROXY_PROXY_SSL_VERIFY=on" \
        -e "KONG_NGINX_PROXY_PROXY_SSL_VERIFY_DEPTH=2" \
        -e "KONG_NGINX_PROXY_GRPC_SSL_TRUSTED_CERTIFICATE=/certs/ca.pem" \
        -e "KONG_NGINX_PROXY_GRPC_SSL_VERIFY=on" \
        -e "KONG_NGINX_PROXY_GRPC_SSL_VERIFY_DEPTH=2" \
        -e "KONG_NGINX_STREAM_PROXY_SSL_TRUSTED_CERTIFICATE=/certs/ca.pem" \
        -e "KONG_NGINX_STREAM_PROXY_SSL_VERIFY=on" \
        -e "KONG_NGINX_STREAM_PROXY_SSL_VERIFY_DEPTH=2" \
        "${extra_env[@]}" \
        -v "$cfg_dst:/kong/kong.yaml:ro" \
        -v "$CERT_DIR:/certs:ro" \
        "$KONG_IMAGE")

    if [ "$UDP_PROFILE" = profile ]; then
        mkdir -p "$OUTPUT_DIR/diagnostics"
        cp "$cfg_dst" "$OUTPUT_DIR/diagnostics/kong_config.yaml"
    fi
    wait_for_gateway || return 1
    if [ "$UDP_PROFILE" = profile ]; then
        # Capture the actual ready fixture before any measured traffic. Readback
        # failures remain in the ledger; this never changes Kong/traffic policy.
        bash "$SCRIPT_DIR/kong_udp_readback.sh" "$GATEWAY_CID" "$KONG_IMAGE" \
            "$OUTPUT_DIR/diagnostics/kong-readback" || return 1
    fi
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
        -c 'cp /etc/tyk/certs/ca.pem /usr/local/share/ca-certificates/bench.crt && update-ca-certificates >/dev/null 2>&1 && exec /opt/tyk-gateway/tyk --conf /opt/tyk-gateway/tyk.conf')
    # All-`&&` chain so a trust-store setup failure exits before Tyk
    # starts. Otherwise Tyk would run without the benchmark CA while
    # every API config enforces ssl_insecure_skip_verify=false, turning
    # the bench into silent 0-RPS rows rather than a loud startup error.

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
                if bash -c '>/dev/tcp/127.0.0.1/$1' _ "$target_port" 2>/dev/null; then
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

h1_trace_start() {
    [ "$H1_TRACE" != none ] && [ "$gw" != direct ] || return 0
    h1_trace_output="$OUTPUT_DIR/traces/${gw}_${PAYLOAD_SIZES}"
    mkdir -p "$h1_trace_output"
    local enabled=(--enabled)
    if [ "$H1_PROFILE" = trace-calibration ] && [ "$gw" = ferrum-baseline ]; then enabled=(); fi
    sudo --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT,RUNNER_OS,RUNNER_ARCH,GITHUB_SHA,GITHUB_RUN_ID,GITHUB_RUN_ATTEMPT,ImageOS,ImageVersion \
        python3 "$SCRIPT_DIR/h1_trace.py" supervise --mode "$H1_TRACE" "${enabled[@]}" \
        --parent "$$" --builds "$H1_TRACE_BUILDS" --artifact-root "$(dirname "$H1_TRACE_BUILDS")" --output "$h1_trace_output" \
        > "$h1_trace_output/supervisor.stdout" 2> "$h1_trace_output/supervisor.stderr" &
    h1_trace_pid=$!
    local attempts=0
    while [ ! -s "$h1_trace_output/supervisor-ready.json" ] && [ "$attempts" -lt 600 ]; do
        [ ! -s "$h1_trace_output/stopped.json" ] || return 1
        sleep 0.05
        attempts=$(( attempts + 1 ))
    done
    [ -s "$h1_trace_output/supervisor-ready.json" ]
}

h1_trace_stop() {
    if [ -n "$h1_trace_pid" ]; then
        touch "$h1_trace_output/stop"
        # Supervisor enforces its own 300s bound and kills/reaps owned children;
        # decoder bounds are additional finite teardown work, never measurement.
        wait "$h1_trace_pid" || true
        h1_trace_pid=""
        h1_trace_output=""
    fi
}

stop_gateway() {
    # Successful run_bench already obtained the supervisor's teardown receipt.
    # Startup/abort cleanup has no receipt and must remain an incomplete capture.
    stop_container "$GATEWAY_CID"
    stop_container "$REDIS_CID"
    h1_trace_stop
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
    if [ "$H2_OBSERVE" -eq 1 ]; then
        extra_args+=(--h2-observe)
        if [ "$PROTOCOL" = http2 ]; then
            extra_args+=(--ca-cert "$CERT_DIR/ca.pem")
        fi
    fi
    if [ "$H1_PROFILE" = diagnostic ]; then
        extra_args+=(--h1-diagnostic)
    fi
    local effective_concurrency
    effective_concurrency=$(scale_concurrency_for_payload "$payload" "$CONCURRENCY")

    local out="$OUTPUT_DIR/${gateway}_${PROTOCOL}_${payload}.json"
    echo "[bench] $gateway/$PROTOCOL payload=${payload}B concurrency=${effective_concurrency} → $bench_target"

    # Wall-clock kill-switch. proto_bench has its own per-iteration I/O
    # timeouts, but this outer `timeout` is a belt-and-suspenders guard
    # against any future hang path (new protocol handler, dependency change,
    # etc.) that would otherwise let a single stuck bench eat the workflow's
    # 75-minute step budget. DURATION seconds of actual work + 120s head-room
    # for connect/handshake/teardown.
    local bench_wallclock=$(( DURATION + 120 + (payload + 131071) / 131072 ))

    # `|| rc=$?` captures the exit code without tripping `set -e`. Using an
    # `if !` branch here would clear $? inside the then-block (bash semantics
    # of the `!` negation), so we'd lose the ability to distinguish a 124
    # (timeout) from a generic non-zero exit.
    local rc=0
    local diagnostics="$OUTPUT_DIR/diagnostics"
    mkdir -p "$diagnostics"
    local gateway_pids=""
    if [ "$target" = "gateway" ] && [ -n "$GATEWAY_CID" ]; then
        gateway_pids=$(docker top "$GATEWAY_CID" -eo pid | tail -n +2 | tr '\n' ' ' || true)
    fi
    local usage="$diagnostics/${gateway}_${payload}_process_usage.json"
    local sampler_args=()
    if [ -n "$H1_PROFILE" ] && [ "$target" = gateway ]; then
        sampler_args+=(--h1-profile --h1-runtime "$diagnostics/${gateway}_runtime.json"
                      --h1-container-id "$GATEWAY_CID")
    fi
    if [ -n "$UDP_PROFILE" ] && [ "$gateway" = ferrum ]; then
        sampler_args+=(--udp-profile)
    fi
    if [ "$H2_OBSERVE" -eq 1 ] && [ "$target" = gateway ]; then
        sampler_args+=(--h2-gauges)
    fi
    if [ -n "$POOL_PROFILE" ] && [ "$target" = gateway ]; then
        if [ "$POOL_PROFILE" != calibration ] || [ "$gateway" != ferrum-baseline ]; then
            sampler_args+=(--pool-profile)
        fi
    fi
    if [ "$PROTOCOL" = http3 ] && [ "$H3_BUDGET" -ne 0 ]; then
        sampler_args+=(--http3)
        case "$gateway" in envoy|envoy-limit-4) sampler_args+=(--envoy) ;; esac
    fi
    if [ "$PROCESS_USAGE" = true ]; then
        : > "$usage"
        # /proc/<container-pid>/io requires ptrace read permission across UIDs.
        # Elevate ONLY the passive reader. A stop file avoids signalling sudo's
        # root-owned monitor; the client remains an ordinary direct invocation.
        if sudo -n true 2>/dev/null; then
            sampler_stop_file="$usage.stop"
            rm -f "$sampler_stop_file"
            if [ "$H1_PROFILE" = diagnostic ]; then
                # The privileged reader also self-terminates even if sudo
                # changes process groups or the runner is forcibly killed.
                local reader_bound
                reader_bound=$(python3 -c 'import os,time; print(max(0.001, float(os.environ["H1_DIAGNOSTIC_WORK_DEADLINE"])-time.monotonic()-1))')
                sudo -n timeout --signal=TERM --kill-after=1s "${reader_bound}s" \
                    python3 "$SCRIPT_DIR/process_usage.py" \
                    --backend "$BACKEND_PID" --gateway-pids "$gateway_pids" \
                    --output "$usage" --interval 0.5 --parent-pid "$$" \
                    --stop-file "$sampler_stop_file" "${sampler_args[@]}" &
            else
                sudo -n python3 "$SCRIPT_DIR/process_usage.py" \
                    --backend "$BACKEND_PID" --gateway-pids "$gateway_pids" \
                    --output "$usage" --interval 0.5 --parent-pid "$$" \
                    --stop-file "$sampler_stop_file" "${sampler_args[@]}" &
            fi
            sampler_pid=$!
        else
            sampler_stop_file=""
            python3 "$SCRIPT_DIR/process_usage.py" \
                --backend "$BACKEND_PID" --gateway-pids "$gateway_pids" \
                --output "$usage" --interval 0.5 "${sampler_args[@]}" &
            sampler_pid=$!
        fi
        # Wait for the first observation and installed signal handlers. Without
        # readiness, an immediately failing client could leave SIGINT ignored.
        local sampler_wait=0
        while [ ! -s "$usage" ] && [ "$sampler_wait" -lt 100 ]; do
            sleep 0.05
            sampler_wait=$(( sampler_wait + 1 ))
        done
        if [ ! -s "$usage" ]; then
            if [ -n "$sampler_stop_file" ]; then
                touch "$sampler_stop_file"
            else
                kill -TERM "$sampler_pid" 2>/dev/null || true
            fi
            wait "$sampler_pid" || true
            sampler_pid=""
        fi
    else
        echo '{"available":false,"error":"process usage unavailable or disabled"}' > "$usage"
    fi
    if [ "$H2_GUARD_OBSERVE" -eq 1 ] && [ "$target" = gateway ]; then
        mkdir -p "$OUTPUT_DIR/diagnostics"
        python3 "$SCRIPT_DIR/h2_guard_snapshot.py" \
            "$OUTPUT_DIR/diagnostics/${gateway}_${payload}_guard_before.json" \
            --identity "$gateway" "$PROTOCOL" "$payload" "$PAIR" "$HOST_ID"
    fi
    if [ "$H2_GUARD_OBSERVE" -eq 1 ]; then
        python3 "$SCRIPT_DIR/h2_guard_snapshot.py" "$diagnostics/${gateway}_${payload}_invocation.json" \
            --identity "$gateway" "$PROTOCOL" "$payload" "$PAIR" "$HOST_ID" --invocation start
    fi
    if [ "$H1_PROFILE" = diagnostic ]; then
        # Write directly to retained raw stdout so campaign termination during
        # the client/readers/logging cannot lose the original partial output.
        timeout "${bench_wallclock}s" \
            "$SCRIPT_DIR/target/release/proto_bench" "$bench_proto" \
            --target "$bench_target" --duration "$DURATION" \
            --concurrency "$effective_concurrency" --payload-size "$payload" \
            --json "${extra_args[@]}" > "$diagnostics/${gateway}_${payload}_client.raw.json" \
            2>"$OUTPUT_DIR/${gateway}_${PROTOCOL}_${payload}.err" || rc=$?
        printf '%s\n' "$rc" > "$diagnostics/${gateway}_${payload}_client.exit"
        cp "$diagnostics/${gateway}_${payload}_client.raw.json" "$out"
    elif [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD "${bench_wallclock}s" \
            "$SCRIPT_DIR/target/release/proto_bench" "$bench_proto" \
            --target "$bench_target" \
            --duration "$DURATION" \
            --concurrency "$effective_concurrency" \
            --payload-size "$payload" \
            --json "${extra_args[@]}" > "$out" 2>"$OUTPUT_DIR/${gateway}_${PROTOCOL}_${payload}.err" \
            || rc=$?
    else
        "$SCRIPT_DIR/target/release/proto_bench" "$bench_proto" \
            --target "$bench_target" \
            --duration "$DURATION" \
            --concurrency "$effective_concurrency" \
            --payload-size "$payload" \
            --json "${extra_args[@]}" > "$out" 2>"$OUTPUT_DIR/${gateway}_${PROTOCOL}_${payload}.err" \
            || rc=$?
    fi
    if [ "$H2_GUARD_OBSERVE" -eq 1 ]; then
        python3 "$SCRIPT_DIR/h2_guard_snapshot.py" "$diagnostics/${gateway}_${payload}_invocation.json" \
            --identity "$gateway" "$PROTOCOL" "$payload" "$PAIR" "$HOST_ID" --invocation end --exit-code "$rc"
    fi
    if [ -n "$sampler_pid" ]; then
        if [ -n "$sampler_stop_file" ]; then
            touch "$sampler_stop_file"
        else
            kill -INT "$sampler_pid" 2>/dev/null || true
        fi
        wait "$sampler_pid" || true
        sampler_pid=""
        sampler_stop_file=""
    fi
    # Capture after the timed load, while the gateway still exists. Keep these
    # below a subdirectory so summary globs cannot mistake stats for samples.
    local diagnostics="$OUTPUT_DIR/diagnostics"
    mkdir -p "$diagnostics"
    # `set -e` is on: a best-effort capture must never abort the matrix that
    # the capture exists to diagnose.
    if [ "$H1_PROFILE" = diagnostic ]; then
        cp "$diagnostics/${gateway}_backend.raw.log" "$diagnostics/${gateway}_${payload}_backend.log" || true
    else
        cp "$SCRIPT_DIR/backend.log" "$diagnostics/${gateway}_${payload}_backend.log" || true
    fi
    if [ "$target" = "gateway" ] && [ -n "$GATEWAY_CID" ]; then
        if [ "$H2_GUARD_OBSERVE" -eq 1 ]; then
            python3 "$SCRIPT_DIR/h2_guard_snapshot.py" "$diagnostics/${gateway}_${payload}_guard_after.json" \
                --identity "$gateway" "$PROTOCOL" "$payload" "$PAIR" "$HOST_ID"
        fi
        docker logs --timestamps "$GATEWAY_CID" > "$diagnostics/${gateway}_${payload}.log" 2>&1 || true
        if [[ "$gateway" == envoy* ]]; then
            curl --max-time 5 -fsS 'http://127.0.0.1:15000/stats?format=json' \
                > "$diagnostics/${gateway}_${payload}_stats.json" \
                2> "$diagnostics/${gateway}_${payload}_stats.err" || true
        fi
    fi

    if [ "$H1_TRACE" != none ]; then
        # Preserve even partial stdout before error placeholders or stamping.
        cp "$out" "$diagnostics/${gateway}_${payload}_client.raw.json"
        printf '%s\n' "$rc" > "$diagnostics/${gateway}_${payload}_client.exit"
    fi
    if [ "$rc" -ne 0 ]; then
        if [ "$rc" -eq 124 ]; then
            echo "[bench] TIMED OUT after ${bench_wallclock}s: $gateway/$PROTOCOL payload=${payload}B"
            echo "{\"gateway\":\"$gateway\",\"protocol\":\"$PROTOCOL\",\"payload_size\":$payload,\"effective_concurrency\":$effective_concurrency,\"error\":\"bench wallclock timeout\",\"rps\":0}" > "$out"
        else
            echo "[bench] FAILED (rc=$rc): $gateway/$PROTOCOL payload=${payload}B — see ${out}.err"
            echo "{\"gateway\":\"$gateway\",\"protocol\":\"$PROTOCOL\",\"payload_size\":$payload,\"effective_concurrency\":$effective_concurrency,\"error\":\"bench failed\",\"rps\":0}" > "$out"
        fi
    fi

    # Stamp metadata into JSON for aggregation.
    python3 "$SCRIPT_DIR/benchmark_plan.py" stamp \
        "$out" "$gateway" "$payload" "$effective_concurrency" \
        "$PAIR" "$ORDER_POSITION" "$HOST_ID" "$usage" "$GATEWAY_ORDER"
    if [ "$H2_OBSERVE" -eq 1 ]; then
        python3 "$SCRIPT_DIR/h2_diagnostics.py" "$out" "$usage" \
            "$diagnostics/${gateway}_${payload}_backend.log"
    fi
    if [ "$H2_GUARD_OBSERVE" -eq 1 ]; then
        python3 "$SCRIPT_DIR/h2_guard_observation.py" "$out" "$usage" \
            "$diagnostics/${gateway}_${payload}.log"
    fi
    local rps
    rps=$(python3 -c "import json; print(f\"{json.load(open('$out'))['rps']:,.0f}\")" 2>/dev/null || echo "?")
    echo "[bench]   → RPS=$rps"

    # Surface proto_bench stderr (error detail lines) if non-empty.
    local err_file="$OUTPUT_DIR/${gateway}_${PROTOCOL}_${payload}.err"
    if [ -s "$err_file" ] && [ "$H1_PROFILE" != diagnostic ]; then
        local err_lines
        err_lines=$(wc -l < "$err_file")
        echo "[bench]   ⚠ ${err_lines} error lines in stderr (first 10):"
        head -10 "$err_file" | sed 's/^/[bench]     /'
    fi
    if [ -n "$h1_trace_pid" ]; then
        # The synchronous client has returned and its raw result/exit and stamped
        # sample are retained. The supervisor validates full request drain and
        # live target/collectors before acknowledging; capture stays enabled.
        # A failed handshake never changes client work or certifies abort cleanup.
        python3 "$SCRIPT_DIR/h1_trace.py" request-teardown --output "$h1_trace_output" \
            || echo '[trace] teardown not verified; capture remains incomplete' >&2
    fi
}

# ── Orchestration ───────────────────────────────────────────────────────────
main() {
    mkdir -p "$OUTPUT_DIR"
    echo "[main] protocol=$PROTOCOL sizes=$PAYLOAD_SIZES gateways=$GATEWAYS"

    # Refuse to start on a host that already has any benchmark port bound rather
    # than silently killing the unrelated listener later.
    check_ports_available || exit 1

    # A paired suite is self-contained even when the frozen caller passes
    # --skip-direct after iteration one. Every pair measures direct again.
    if $SKIP_DIRECT; then
        echo "[main] --skip-direct ignored: each pair requires its own direct baseline"
    fi
    local expected_gateways="direct"
    for gw in $GATEWAYS; do
        if supports "$gw" "$PROTOCOL"; then expected_gateways+=" $gw"; fi
    done
    if [ -n "$BASELINE_IMAGE" ] && [[ " $expected_gateways " == *" ferrum "* ]]; then
        expected_gateways+=" ferrum-baseline"
    fi
    if [ "$H3_BUDGET" -ne 0 ] && [[ " $expected_gateways " == *" envoy "* ]]; then
        expected_gateways+=" envoy-limit-4"
    fi
    if [ "$H1_PROFILE" = cutoff ] || [ "$H1_PROFILE" = diagnostic ]; then
        expected_gateways+=" ferrum-exp-cutoff-one"
    fi
    if [ -z "$H1_PROFILE" ] && [ -z "$POOL_PROFILE" ] && [ -z "$UDP_PROFILE" ] && [ -f "$EXPERIMENT_MANIFEST" ]; then
        EXPERIMENT_ARMS=$(python3 "$SCRIPT_DIR/experiment_arms.py" names \
            "$EXPERIMENT_MANIFEST" "$PROTOCOL")
        if [ -n "$EXPERIMENT_ARMS" ] && [[ " $expected_gateways " == *" ferrum "* ]]; then
            if [ -n "$BASELINE_IMAGE" ] || [ -n "${FERRUM_EXTRA_ENV:-}" ]; then
                echo "[experiment] manifest cannot be mixed with baseline-image or ambient FERRUM_EXTRA_ENV" >&2
                exit 2
            fi
            expected_gateways+=" $EXPERIMENT_ARMS"
            cp "$EXPERIMENT_MANIFEST" "$OUTPUT_DIR/experiment.json"
            local campaign
            campaign=$(python3 "$SCRIPT_DIR/experiment_arms.py" campaign \
                "$EXPERIMENT_MANIFEST" "$PROTOCOL" "$DURATION" "$CONCURRENCY" \
                "$GATEWAYS" "$ADAPTIVE" "$PAYLOAD_SIZES")
            if [ -n "$campaign" ]; then
                H2_OBSERVE=1
                H2_GUARD_OBSERVE=$(python3 "$SCRIPT_DIR/experiment_arms.py" guard \
                    "$EXPERIMENT_MANIFEST" "$PROTOCOL")
                if [ "$H2_GUARD_OBSERVE" -eq 1 ] && { [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; }; then
                    echo "[experiment] guard observation is hosted-only" >&2
                    exit 2
                fi
                PAIRS="${campaign%% *}"
                PAYLOAD_SIZES="${campaign#* }"
                if [ "$PROCESS_USAGE" != true ]; then
                    echo "[experiment] H2 campaign requires process observations" >&2
                    exit 2
                fi
            fi
        else
            EXPERIMENT_ARMS=""
        fi
    fi
    if [ -r /proc/sys/kernel/random/boot_id ]; then
        HOST_ID=$(cat /proc/sys/kernel/random/boot_id)
    else
        HOST_ID="$(hostname)-$$"
    fi
    local root_output="$OUTPUT_DIR"
    local h1_revision=""
    if [ -n "$H1_PROFILE" ]; then
        h1_revision=$(git -C "$PROJECT_ROOT" rev-parse HEAD) || return 2
    fi
    python3 - "$root_output/manifest.json" "$expected_gateways" "$PAYLOAD_SIZES" "$PAIRS" "$HOST_ID" "$H2_OBSERVE" "$H1_PROFILE" "$PROTOCOL" "$DURATION" "$CONCURRENCY" "$h1_revision" "$H1_TRACE" <<'PYEOF'
import json, sys
with open(sys.argv[1], "w") as manifest:
    json.dump({"gateways": sys.argv[2].split(),
               "payload_sizes": [int(size) for size in sys.argv[3].split()],
               "pairs": int(sys.argv[4]), "host_id": sys.argv[5],
               "h2_observation_enabled": sys.argv[6] == "1",
               **({"h1_diagnostic_enabled": True} if sys.argv[7] == "diagnostic" else {}),
               **({"h1_profile_mode": sys.argv[7], "protocol": sys.argv[8],
                   "duration": int(sys.argv[9]), "offered_workers": int(sys.argv[10]),
                   "h1_revision": sys.argv[11], "h1_trace_mode": sys.argv[12]}
                  if sys.argv[7] else {}),
               "sample_schema": 2}, manifest)
PYEOF
    if [ "$H3_BUDGET" -ne 0 ]; then
        cp "${H3_EXPERIMENT_MANIFEST:-$SCRIPT_DIR/h3_experiment.json}" "$root_output/h3_experiment.json"
    fi

    if [ -n "$H1_PROFILE" ]; then
        cp "$SCRIPT_DIR/h1_profile_manifest.json" "$root_output/h1_profile_manifest.json"
        cp "$SCRIPT_DIR/h1_profile_schema.json" "$root_output/h1_profile_schema.json"
    fi
    if [ -n "$POOL_PROFILE" ]; then
        cp "$SCRIPT_DIR/pool_profile_manifest.json" "$root_output/pool_profile_manifest.json"
        cp "$SCRIPT_DIR/pool_profile_schema.json" "$root_output/pool_profile_schema.json"
    fi
    if [ -n "$UDP_PROFILE" ]; then
        cp "$SCRIPT_DIR/udp_profile_manifest.json" "$root_output/udp_profile_manifest.json"
        cp "$SCRIPT_DIR/udp_profile_schema.json" "$root_output/udp_profile_schema.json"
    fi
    build_binaries
    # Save immutable image IDs as well as operator-supplied tags for revision A/B.
    docker image inspect "$FERRUM_IMAGE" ${BASELINE_IMAGE:+"$BASELINE_IMAGE"} \
        --format '{{.Id}} {{json .RepoTags}} {{index .Config.Labels "org.opencontainers.image.revision"}}' \
        > "$root_output/images.txt"
    if [ "$H2_OBSERVE" -eq 1 ] || [ -n "$H1_PROFILE" ] || [ -n "$UDP_PROFILE" ]; then
        if [ "$H2_GUARD_OBSERVE" -eq 1 ]; then
            local source_identity
            source_identity=$(docker image inspect "$FERRUM_IMAGE" --format '{{index .Config.Labels "io.ferrum.h2-guard-source"}}')
            if [ "$source_identity" != "ef8e5e5a340588f4452631496976cf8636d4a7ecf600239fdc27615d2530bc16" ]; then
                echo "[experiment] image is not the pinned guard diagnostic build" >&2
                exit 2
            fi
        fi
        # Pin the resolved ID for every arm, even if a mutable tag is retargeted.
        FERRUM_IMAGE=$(docker image inspect "$FERRUM_IMAGE" --format '{{.Id}}')
        if [ -n "$BASELINE_IMAGE" ]; then
            BASELINE_IMAGE=$(docker image inspect "$BASELINE_IMAGE" --format '{{.Id}}')
        fi
    fi
    if [ "$H1_PROFILE" = trace-calibration ]; then
        if [ "$FERRUM_IMAGE" != "$BASELINE_IMAGE" ]; then
            echo 'external calibration requires the identical binary/image in both arms' >&2
            exit 2
        fi
        local internal_observer
        internal_observer=$(docker image inspect "$FERRUM_IMAGE" \
            --format '{{index .Config.Labels "ferrum.h1-profile"}}') || return 2
        if [ "$internal_observer" != on ]; then
            echo 'external calibration requires the internal observer ON in both arms' >&2
            exit 2
        fi
    fi
    if [[ " $expected_gateways " == *" envoy "* ]]; then
        docker image inspect "$ENVOY_IMAGE" --format '{{.Id}} {{json .RepoDigests}}' \
            >> "$root_output/images.txt"
    fi
    if [ "$UDP_PROFILE" = profile ]; then
        # Preserve tag and immutable image evidence; no vendor correspondence inferred.
        docker image inspect "$KONG_IMAGE" > "$root_output/kong-image.json"
        KONG_IMAGE=$(docker image inspect "$KONG_IMAGE" --format '{{.Id}}')
    fi
    local requested_pairs="$PAIRS"
    local final_pairs="$PAIRS"
    local extended=false
    local first_pair=1
    local base_started=$SECONDS
    while true; do
        for PAIR in $(seq "$first_pair" "$final_pairs"); do
            OUTPUT_DIR="$root_output/pairs/$(printf 'pair_%03d' "$PAIR")"
            mkdir -p "$OUTPUT_DIR"
            GATEWAY_ORDER=$(python3 "$SCRIPT_DIR/benchmark_plan.py" order "$PAIR" "$expected_gateways")
            ORDER_POSITION=0
            for gw in $GATEWAY_ORDER; do
                ORDER_POSITION=$(( ORDER_POSITION + 1 ))
                # Fresh backend for every arm, including direct: no lingering
                # DTLS sessions or gateway-specific backend state crosses arms.
                if [ -n "$BACKEND_PID" ]; then
                    kill "$BACKEND_PID" 2>/dev/null || true
                    wait "$BACKEND_PID" 2>/dev/null || true
                fi
                start_backend
                h1_trace_start || { stop_gateway; continue; }
                case "$gw" in
                    direct) ;;
                    ferrum|ferrum-exp-*)
                        if [ -n "$EXPERIMENT_ARMS" ]; then
                            local arm_env
                            arm_env=$(python3 "$SCRIPT_DIR/experiment_arms.py" env \
                                "$EXPERIMENT_MANIFEST" "$PROTOCOL" "$gw") || exit 2
                            FERRUM_EXTRA_ENV="$arm_env" start_ferrum
                        else
                            start_ferrum
                        fi
                        ;;
                    ferrum-baseline) FERRUM_IMAGE="$BASELINE_IMAGE" start_ferrum ;;
                    envoy) ENVOY_STREAM_LIMIT=100 start_envoy ;;
                    envoy-limit-4) ENVOY_STREAM_LIMIT=4 start_envoy ;;
                    kong) start_kong ;;
                    tyk) start_tyk ;;
                    krakend) start_krakend ;;
                esac || { echo "[main] $gw failed to start"; stop_gateway; continue; }
                if [ -n "$GATEWAY_CID" ]; then
                    mkdir -p "$OUTPUT_DIR/diagnostics"
                    docker logs --timestamps "$GATEWAY_CID" \
                        > "$OUTPUT_DIR/diagnostics/${gw}_startup.log" 2>&1 || true
                    if [[ "$gw" == envoy* ]]; then
                        cp "$SCRIPT_DIR/envoy_runtime.yaml" "$OUTPUT_DIR/diagnostics/${gw}_config.yaml"
                    fi
                fi
                if [ "$H2_GUARD_OBSERVE" -eq 1 ] && [ "$gw" != direct ]; then
                    # Explicit trigger/HTTP ack/log-fence smoke before offered work.
                    python3 "$SCRIPT_DIR/h2_guard_snapshot.py" "$OUTPUT_DIR/diagnostics/${gw}_guard_smoke.json" \
                        --identity "$gw" "$PROTOCOL" 0 "$PAIR" "$HOST_ID"
                    docker logs --timestamps "$GATEWAY_CID" \
                        > "$OUTPUT_DIR/diagnostics/${gw}_guard_smoke.log" 2>&1 || true
                    python3 "$SCRIPT_DIR/h2_guard/verify.py" smoke \
                        "$OUTPUT_DIR/diagnostics/${gw}_guard_smoke.json" || {
                        echo "[guard] snapshot smoke incomplete; retained raw evidence" >&2
                        stop_gateway
                        continue
                    }
                fi
                for size in $PAYLOAD_SIZES; do
                    if [ "$gw" = direct ]; then
                        run_bench "$gw" "$size" direct
                    else
                        run_bench "$gw" "$size" gateway
                    fi
                done
                stop_gateway
            done
        done
        OUTPUT_DIR="$root_output"
        if [ "$H1_PROFILE" = diagnostic ]; then
            # One pass only: never pair, extend, rerun, or promote a comparison.
            break
        fi
        local decision
        decision=$(python3 "$SCRIPT_DIR/benchmark_plan.py" summarize "$OUTPUT_DIR" \
            "$PROTOCOL" "$expected_gateways" "$PAYLOAD_SIZES" "$final_pairs")
        if ! $extended; then
            local pair_seconds=$(( (SECONDS - base_started + requested_pairs - 1) / requested_pairs ))
            decision=$(python3 "$SCRIPT_DIR/benchmark_plan.py" extension \
                "$OUTPUT_DIR/manifest.json" "$ADAPTIVE" "$decision" "$SECONDS" \
                "$pair_seconds" "$requested_pairs" "$WALLCLOCK_BUDGET")
            echo "[main] extension decision: $decision"
        fi
        if ! $extended && [ "$decision" = extend ]; then
            # One bounded extension of the WHOLE matrix, never just the loser.
            extended=true
            first_pair=$(( final_pairs + 1 ))
            final_pairs=$(( final_pairs + requested_pairs ))
            DURATION=$(( DURATION * 2 ))
            # Publish missing placeholders BEFORE extended work begins, so a
            # killed extension cannot leave a deceptively complete first block.
            python3 "$SCRIPT_DIR/benchmark_plan.py" summarize "$OUTPUT_DIR" \
                "$PROTOCOL" "$expected_gateways" "$PAYLOAD_SIZES" "$final_pairs" >/dev/null
            python3 - "$OUTPUT_DIR/manifest.json" "$final_pairs" <<'PYEOF'
import json, sys
path = sys.argv[1]
with open(path) as f:
    plan = json.load(f)
plan.update(pairs=int(sys.argv[2]), adaptive_extension=True)
with open(path, "w") as f:
    json.dump(plan, f, indent=2)
PYEOF
            echo "[main] uncertainty overlaps gain: adding $requested_pairs pairs at ${DURATION}s"
        else
            break
        fi
    done
    python3 - "$OUTPUT_DIR/manifest.json" "$final_pairs" "$extended" <<'PYEOF'
import json, sys
path = sys.argv[1]
with open(path) as f:
    plan = json.load(f)
plan.update(pairs=int(sys.argv[2]), adaptive_extension=sys.argv[3] == "true")
with open(path, "w") as f:
    json.dump(plan, f, indent=2)
PYEOF
    # The diagnostic supervisor reports only AFTER bounded cleanup and records
    # truthful termination status even if this runner never reaches this point.
    echo "[main] done. results in $OUTPUT_DIR"
}

main
