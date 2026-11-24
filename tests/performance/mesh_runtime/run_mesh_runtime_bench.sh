#!/bin/bash
# Mesh-runtime head-to-head benchmark for mesh-runtime-benchmark.yml.
#
# For one mesh arm, runs mesh_loadgen through a client/server proxy pair
# (mTLS east-west hop) into mesh_backend at every requested payload size,
# plus same-runner resource sampling. Writes per-cell JSON named
# `<mesh>_http1_<payload>.json` (gateway-bench compatible fields) and
# `<mesh>_http1_<payload>.resources.json` (marker-bracketed host /proc CPU
# and sampled RSS of the proxy processes) to the output directory.
#
# Usage: ./run_mesh_runtime_bench.sh <mesh> [options]
#        ./run_mesh_runtime_bench.sh --build-only [options]
#   Mesh: direct | ferrum | envoy | consul | consulhttp | linkerd
#
# Options:
#   --payload-sizes "1024 10240 71680 512000 1048576 5242880"
#   --duration 10
#   --concurrency 100
#   --warmup 2            (seconds of discarded load before each cell)
#   --output-dir /tmp/mesh-runtime-results
#   --build-only          (build the harness tools image and the Ferrum bench
#                          image, then exit without starting an arm)
#   --skip-build          (reuse existing tools/ferrum docker images)
#
# Environment:
#   DOCKER_CONTEXT   docker context name (the docker CLI reads this
#                    env var natively; used for local container VMs)
#   FERRUM_IMAGE     Ferrum image (default: ferrum-edge:bench)
#   ENVOY_IMAGE      Envoy image (default: envoyproxy/envoy:v1.39.1)
#   CONSUL_IMAGE     Consul image (default: hashicorp/consul:1.21.4)
#   LINKERD_IMAGE    Linkerd proxy image (default: ghcr.io/linkerd/proxy:edge-25.11.1)
#   TOOLS_IMAGE      Harness tools image (default: mesh-bench-tools:local)
#
# Every container (backend, proxies, load generator) runs with
# --network host so no arm gets a bridge-NAT advantage or penalty, the
# same convention as run_gateway_protocol_bench.sh. Proxy containers are
# named meshbench-<mesh>-* and only those are cleaned up.

set -eo pipefail

# Runtime Docker operations must not pin a readiness or cleanup step. Image
# builds retain their explicit build-job budget; pulls have a separate cap.
docker() {
    local budget=10 remaining
    case "$1" in
        build) command docker "$@"; return ;;
        pull) budget=120 ;;
    esac
    if [ "${READINESS_DEADLINE:-0}" -gt 0 ] && [ "$1" != logs ] && [ "$1" != rm ]; then
        remaining=$((READINESS_DEADLINE - SECONDS))
        [ "$remaining" -gt 0 ] || return 124
        [ "$remaining" -ge "$budget" ] || budget="$remaining"
    fi
    timeout --signal=TERM --kill-after=2s "${budget}s" docker "$@"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

BUILD_ONLY=false
MESH=""
if [ "${1:-}" = "--build-only" ]; then
    BUILD_ONLY=true
    shift
else
    MESH="${1:-}"
    [ -z "$MESH" ] && { echo "usage: $0 <direct|ferrum|envoy|consul|consulhttp|linkerd> [options]" >&2; exit 2; }
    shift
    case "$MESH" in
        direct|ferrum|envoy|consul|consulhttp|linkerd) ;;
        *) echo "unknown mesh arm: $MESH" >&2; exit 2 ;;
    esac
fi

PAYLOAD_SIZES="1024 10240 71680 512000 1048576 5242880"
DURATION=10
CONCURRENCY=100
WARMUP=2
EXCHANGE_TIMEOUT_SECS=10
READINESS_TIMEOUT_SECS=90
READINESS_DEADLINE=0
OUTPUT_DIR="/tmp/mesh-runtime-results"
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --payload-sizes) PAYLOAD_SIZES="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --concurrency) CONCURRENCY="$2"; shift 2 ;;
        --warmup) WARMUP="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=true; shift ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if $BUILD_ONLY && $SKIP_BUILD; then
    echo "--build-only and --skip-build are mutually exclusive" >&2
    exit 2
fi

# Validate numeric inputs before they reach any command.
for v in "$DURATION" "$CONCURRENCY" "$WARMUP"; do
    [[ "$v" =~ ^[0-9]+$ ]] || { echo "non-numeric bench parameter: $v" >&2; exit 2; }
done
for s in $PAYLOAD_SIZES; do
    [[ "$s" =~ ^[0-9]+$ ]] || { echo "non-numeric payload size: $s" >&2; exit 2; }
done
[ "$DURATION" -gt 0 ] && [ "$CONCURRENCY" -gt 0 ] || { echo "duration and concurrency must be positive" >&2; exit 2; }
command -v timeout >/dev/null || { echo "GNU timeout is required for bounded benchmark operations" >&2; exit 2; }

FERRUM_IMAGE="${FERRUM_IMAGE:-ferrum-edge:bench}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.39.1}"
CONSUL_IMAGE="${CONSUL_IMAGE:-hashicorp/consul:1.21.4}"
LINKERD_IMAGE="${LINKERD_IMAGE:-ghcr.io/linkerd/proxy:edge-25.11.1}"
TOOLS_IMAGE="${TOOLS_IMAGE:-mesh-bench-tools:local}"
BENCH_CARGO_PROFILE="${BENCH_CARGO_PROFILE:-release}"
case "$BENCH_CARGO_PROFILE" in release|ci-release) ;; *) echo "invalid build profile" >&2; exit 2 ;; esac
BENCH_FERRUM_FEATURES="${BENCH_FERRUM_FEATURES:-cloud-secrets}"
case "$BENCH_FERRUM_FEATURES" in cloud-secrets|cloud-secrets,bench-h1-profile) ;; *) echo "invalid build features" >&2; exit 2 ;; esac

BACKEND_PORT=18080
OUTBOUND_PORT=15101
HOST_HEADER="svc.ferrum.svc.cluster.local"
RUN_ID="$$-${RANDOM:-0}"
BACKEND_NAME="meshbench-${MESH}-${RUN_ID}-backend"
CLIENT_NAME="meshbench-${MESH}-${RUN_ID}-client"
SERVER_NAME="meshbench-${MESH}-${RUN_ID}-server"
AGENT_NAME="meshbench-${MESH}-${RUN_ID}-agent"
PROBE_NAME="meshbench-${MESH}-${RUN_ID}-probe"
LOADGEN_NAME="meshbench-${MESH}-${RUN_ID}-loadgen"
# This grants access only through the explicitly mounted, disposable fixture
# directories. Container users stay nonroot and private keys stay mode 0640
# (0660 only for Linkerd's per-proxy runtime copy, whose identity init must
# write beside it).
CERT_GID="$(id -g)"

mkdir -p "$OUTPUT_DIR"
# Docker -v sources must be absolute (a relative results/... source is a
# named volume, not a bind mount), so canonicalize before deriving any
# runtime or mount path from the output directory.
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
# Harness runtime state (certs, rendered configs, logs) lives next to the
# results so CI artifacts carry the evidence. Private keys in this tree
# are single-run throwaways generated below; the workflow artifact step
# excludes the runtime dir.
RUNTIME_DIR="$OUTPUT_DIR/runtime"
CERT_DIR="$RUNTIME_DIR/certs"
mkdir -p "$RUNTIME_DIR" "$OUTPUT_DIR/logs"

ARM_STATUS_FILE="$OUTPUT_DIR/${MESH}_arm_status.json"

write_arm_status() {
    # $1 = status (ready|unsupported-standalone|failed), $2 = detail
    printf '{"mesh":"%s","status":"%s","detail":"%s"}\n' "$MESH" "$1" "$2" > "$ARM_STATUS_FILE"
}

cleanup() {
    local rc=$?
    if [ "$rc" -ne 0 ] && [ -n "$MESH" ]; then
        if ! grep -q '"status":"failed"' "$ARM_STATUS_FILE" 2>/dev/null; then
            write_arm_status failed "harness exited with status $rc"
        fi
        dump_logs
    fi
    timeout --signal=KILL 5s docker rm -f "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME" "$AGENT_NAME" \
        "$PROBE_NAME" "$LOADGEN_NAME" >/dev/null 2>&1 || true
    # Single-run private keys never outlive the run (certificates and
    # public bundles remain as provenance under runtime/).
    rm -f "$CERT_DIR"/*/svid.key "$CERT_DIR"/*/key.p8 "$RUNTIME_DIR"/linkerd/*/key.p8 \
        "$CERT_DIR/ca/root.key" "$CERT_DIR/rogue/root.key" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

prepare_cert_access() {
    # Change only this run's synthetic fixture, never host credential stores.
    chgrp "$CERT_GID" "$CERT_DIR" "$CERT_DIR"/ca "$CERT_DIR"/svc "$CERT_DIR"/client "$CERT_DIR"/rogue \
        "$CERT_DIR"/*/svid.key
    chmod 750 "$CERT_DIR" "$CERT_DIR"/ca "$CERT_DIR"/svc "$CERT_DIR"/client "$CERT_DIR"/rogue
    chmod 640 "$CERT_DIR"/*/svid.key
    chmod 600 "$CERT_DIR/ca/root.key" "$CERT_DIR/rogue/root.key"
    chmod 644 "$CERT_DIR"/*/*.crt "$CERT_DIR"/*/bundle.pem
}

# ── Certs: one EC P-256 CA, svc + client SVID-shaped leaves ────────────────
generate_certs() (
    umask 077
    if [ -f "$CERT_DIR/svc/svid.crt" ] && [ -f "$CERT_DIR/svc/svid.key" ] && \
            [ -f "$CERT_DIR/client/svid.key" ] && [ -f "$CERT_DIR/rogue/svid.key" ]; then
        echo "[certs] reusing $CERT_DIR"
        return
    fi
    echo "[certs] generating shared CA + workload certs in $CERT_DIR"
    mkdir -p "$CERT_DIR/ca" "$CERT_DIR/svc" "$CERT_DIR/client"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$CERT_DIR/ca/root.key" -out "$CERT_DIR/ca/root.crt" \
        -days 30 -subj "/CN=mesh-bench-root" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

    issue_leaf() {
        local dir="$1" spiffe_id="$2" dns_name="$3"
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$dir/svid.key" -out "$dir/svid.csr" \
            -subj "/CN=${spiffe_id##*/}" 2>/dev/null
        printf 'basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = URI:%s, DNS:%s, DNS:localhost\n' \
            "$spiffe_id" "$dns_name" > "$dir/svid.ext"
        openssl x509 -req -in "$dir/svid.csr" -days 7 -sha256 \
            -CA "$CERT_DIR/ca/root.crt" -CAkey "$CERT_DIR/ca/root.key" -CAcreateserial \
            -extfile "$dir/svid.ext" -out "$dir/svid.crt" 2>/dev/null
        cp "$CERT_DIR/ca/root.crt" "$dir/bundle.pem"
        rm -f "$dir/svid.csr" "$dir/svid.ext"
        chmod 640 "$dir/svid.key"; chmod 644 "$dir/svid.crt" "$dir/bundle.pem"
    }
    issue_leaf "$CERT_DIR/svc" "spiffe://cluster.local/ns/ferrum/sa/svc" "svc.ferrum.svc.cluster.local"
    issue_leaf "$CERT_DIR/client" "spiffe://cluster.local/ns/ferrum/sa/client" "client.ferrum.svc.cluster.local"
    openssl verify -CAfile "$CERT_DIR/ca/root.crt" \
        "$CERT_DIR/svc/svid.crt" "$CERT_DIR/client/svid.crt" >/dev/null
    # Rogue CA + client leaf for the wrong-root negative auth probe.
    mkdir -p "$CERT_DIR/rogue"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$CERT_DIR/rogue/root.key" -out "$CERT_DIR/rogue/root.crt" \
        -days 30 -subj "/CN=mesh-bench-rogue" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$CERT_DIR/rogue/svid.key" -out "$CERT_DIR/rogue/svid.csr" \
        -subj "/CN=client" 2>/dev/null
    printf 'basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = URI:spiffe://cluster.local/ns/ferrum/sa/client, DNS:client.ferrum.svc.cluster.local\n' \
        > "$CERT_DIR/rogue/svid.ext"
    openssl x509 -req -in "$CERT_DIR/rogue/svid.csr" -days 7 -sha256 \
        -CA "$CERT_DIR/rogue/root.crt" -CAkey "$CERT_DIR/rogue/root.key" -CAcreateserial \
        -extfile "$CERT_DIR/rogue/svid.ext" -out "$CERT_DIR/rogue/svid.crt" 2>/dev/null
    cp "$CERT_DIR/rogue/root.crt" "$CERT_DIR/rogue/bundle.pem"
    rm -f "$CERT_DIR/rogue/svid.csr" "$CERT_DIR/rogue/svid.ext"
    chmod 640 "$CERT_DIR/rogue/svid.key"
)

# ── Builds / pulls ──────────────────────────────────────────────────────────
build_tools_image() {
    echo "[build] building harness tools image $TOOLS_IMAGE"
    docker build -f "$SCRIPT_DIR/Dockerfile.tools" -t "$TOOLS_IMAGE" "$SCRIPT_DIR" \
        > "$OUTPUT_DIR/logs/tools-build.log" 2>&1 || {
        tail -30 "$OUTPUT_DIR/logs/tools-build.log" >&2; exit 1; }
}

build_ferrum_image() {
    echo "[build] building ferrum image $FERRUM_IMAGE (repo Dockerfile)"
    docker build --build-arg "CARGO_PROFILE=$BENCH_CARGO_PROFILE" --build-arg "FEATURES=$BENCH_FERRUM_FEATURES" \
        -t "$FERRUM_IMAGE" -f "$PROJECT_ROOT/Dockerfile" "$PROJECT_ROOT" \
        > "$OUTPUT_DIR/logs/ferrum-build.log" 2>&1 || {
        tail -30 "$OUTPUT_DIR/logs/ferrum-build.log" >&2; exit 1; }
}

prepare_images() {
    # --build-only: the campaign's one shared build, independent of any arm.
    # The ferrum arm needs this image but cannot be the first arm to build it
    # (the arm loop always runs with --skip-build after this step).
    if $BUILD_ONLY; then
        build_tools_image
        build_ferrum_image
        return
    fi
    if $SKIP_BUILD; then
        echo "[build] --skip-build: expecting $TOOLS_IMAGE to exist"
        if ! docker image inspect "$TOOLS_IMAGE" >/dev/null 2>&1; then
            echo "[build] tools image $TOOLS_IMAGE missing and --skip-build set" >&2; exit 1
        fi
    else
        build_tools_image
    fi
    case "$MESH" in
        ferrum)
            if ! docker image inspect "$FERRUM_IMAGE" >/dev/null 2>&1; then
                if $SKIP_BUILD; then
                    echo "[build] ferrum image $FERRUM_IMAGE missing and --skip-build set" >&2; exit 1
                fi
                build_ferrum_image
            fi
            ;;
        envoy) docker pull "$ENVOY_IMAGE" > "$OUTPUT_DIR/logs/envoy-pull.log" 2>&1 || true ;;
        consul|consulhttp)
            docker pull "$CONSUL_IMAGE" > "$OUTPUT_DIR/logs/consul-pull.log" 2>&1 || true
            docker pull "$ENVOY_IMAGE" > "$OUTPUT_DIR/logs/envoy-pull.log" 2>&1 || true
            ;;
        linkerd) docker pull "$LINKERD_IMAGE" > "$OUTPUT_DIR/logs/linkerd-pull.log" 2>&1 || true ;;
    esac
}

start_backend() {
    echo "[backend] starting mesh_backend on 127.0.0.1:$BACKEND_PORT"
    docker run -d --network host --name "$BACKEND_NAME" \
        --entrypoint /usr/local/bin/mesh_backend \
        "$TOOLS_IMAGE" --listen "127.0.0.1:$BACKEND_PORT" >/dev/null
}

# One short loadgen run used as the readiness probe: portable across
# Linux hosts and local container VMs (no host curl into the VM netns).
probe_loadgen() {
    local target="$1" out="$OUTPUT_DIR/logs/probe.json"
    local rc=0
    readiness_command 10 docker run --rm --network host --name "$PROBE_NAME" "$TOOLS_IMAGE" \
        --target "$target" --host-header "$HOST_HEADER" --mesh probe \
        --duration 1 --concurrency 1 --payload-size 64 --exchange-timeout-secs 2 --json \
        > "$out" 2> "$OUTPUT_DIR/logs/probe.stderr.log" || rc=$?
    if [ "$rc" -ne 0 ]; then
        timeout --signal=KILL 2s docker rm -f "$PROBE_NAME" >/dev/null 2>&1 || true
        return 1
    fi
    grep -q '"total_errors": 0' "$out" && grep -qE '"total_requests": [1-9]' "$out"
}

readiness_command() {
    local budget="$1" remaining
    shift
    if [ "$READINESS_DEADLINE" -gt 0 ]; then
        remaining=$((READINESS_DEADLINE - SECONDS))
        [ "$remaining" -gt 0 ] || return 124
        [ "$remaining" -ge "$budget" ] || budget="$remaining"
    fi
    timeout --signal=TERM --kill-after=2s "${budget}s" "$@"
}

wait_ready() {
    local target="$1" label="$2" container running attempt=0
    shift 2
    while [ "$SECONDS" -lt "$READINESS_DEADLINE" ]; do
        for container in "$@"; do
            running=$(readiness_command 3 docker inspect --format '{{.State.Running}}' "$container") || return 1
            if [ "$running" != true ]; then
                echo "[ready] $label container $container exited before readiness" >&2
                return 1
            fi
        done
        attempt=$((attempt + 1))
        echo "[ready] $label probe=$attempt remaining=$((READINESS_DEADLINE - SECONDS))s"
        if probe_loadgen "$target"; then
            echo "[ready] $label answering through $target"
            return 0
        fi
        sleep 0.5
    done
    echo "[ready] $label exhausted the shared ${READINESS_TIMEOUT_SECS}s readiness budget via $target" >&2
    return 1
}

dump_logs() {
    for c in "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME" "$AGENT_NAME"; do
        timeout --signal=KILL 1s docker logs "$c" > "$OUTPUT_DIR/logs/${c}.log" 2>&1 || true
    done
}

# ── Arm starters ────────────────────────────────────────────────────────────
start_ferrum() {
    # Log level is pinned to error on every proxy arm (Ferrum env below,
    # Envoy -l in start_envoy), mirroring GATEWAY_LOG_LEVEL=error in
    # run_gateway_protocol_bench.sh: at info, Ferrum emits a per-request
    # transaction log line (gigabytes per sweep) that would measure log
    # formatting instead of mesh data-plane cost.
    # Mount a copy under the runtime dir, not the in-repo path: bind-mount
    # sources must be visible to the Docker host (a local container VM
    # only sees mounted host subtrees, and Docker would otherwise create
    # an empty directory at the source path).
    mkdir -p "$RUNTIME_DIR/ferrum"
    cp "$SCRIPT_DIR/configs/ferrum/mesh.yaml" "$RUNTIME_DIR/ferrum/mesh.yaml"
    chmod 644 "$RUNTIME_DIR/ferrum/mesh.yaml"
    # Server (destination) sidecar: inbound :15006 STRICT mTLS.
    docker run -d --network host --name "$SERVER_NAME" --group-add "$CERT_GID" \
        -v "$RUNTIME_DIR/ferrum/mesh.yaml:/etc/ferrum/mesh.yaml:ro" \
        -v "$CERT_DIR/svc:/etc/ferrum/svid:ro" \
        -e FERRUM_MODE=mesh \
        -e FERRUM_NAMESPACE=ferrum \
        -e FERRUM_MESH_TOPOLOGY=sidecar \
        -e FERRUM_MESH_CONFIG_PROTOCOL=file \
        -e FERRUM_MESH_FILE_CONFIG_PATH=/etc/ferrum/mesh.yaml \
        -e FERRUM_MESH_WORKLOAD_SPIFFE_ID=spiffe://cluster.local/ns/ferrum/sa/svc \
        -e FERRUM_GATEWAY_SVID_CERT_PATH=/etc/ferrum/svid/svid.crt \
        -e FERRUM_GATEWAY_SVID_KEY_PATH=/etc/ferrum/svid/svid.key \
        -e FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH=/etc/ferrum/svid/bundle.pem \
        -e FERRUM_MESH_INBOUND_LISTEN_ADDR=127.0.0.1:15006 \
        -e FERRUM_MESH_OUTBOUND_LISTEN_ADDR=127.0.0.1:15001 \
        -e FERRUM_MESH_DNS_PROXY_ENABLED=false \
        -e FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=0 \
        -e FERRUM_POOL_WARMUP_ENABLED=false \
        -e FERRUM_PROXY_HTTP_PORT=0 \
        -e FERRUM_ADMIN_HTTP_PORT=15020 \
        -e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
        -e FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32 \
        -e FERRUM_LOG_LEVEL=error \
        "$FERRUM_IMAGE" >/dev/null
    # Client sidecar: outbound :15101 dials destination :15006, pins SVID.
    docker run -d --network host --name "$CLIENT_NAME" --group-add "$CERT_GID" \
        -v "$RUNTIME_DIR/ferrum/mesh.yaml:/etc/ferrum/mesh.yaml:ro" \
        -v "$CERT_DIR/client:/etc/ferrum/svid:ro" \
        -e FERRUM_MODE=mesh \
        -e FERRUM_NAMESPACE=ferrum \
        -e FERRUM_MESH_TOPOLOGY=sidecar \
        -e FERRUM_MESH_CONFIG_PROTOCOL=file \
        -e FERRUM_MESH_FILE_CONFIG_PATH=/etc/ferrum/mesh.yaml \
        -e FERRUM_MESH_WORKLOAD_SPIFFE_ID=spiffe://cluster.local/ns/ferrum/sa/client \
        -e FERRUM_GATEWAY_SVID_CERT_PATH=/etc/ferrum/svid/svid.crt \
        -e FERRUM_GATEWAY_SVID_KEY_PATH=/etc/ferrum/svid/svid.key \
        -e FERRUM_GATEWAY_SVID_TRUST_BUNDLE_PATH=/etc/ferrum/svid/bundle.pem \
        -e FERRUM_MESH_INBOUND_LISTEN_ADDR=127.0.0.1:15106 \
        -e FERRUM_MESH_OUTBOUND_LISTEN_ADDR=127.0.0.1:15101 \
        -e FERRUM_MESH_EGRESS_MTLS_PORT=15006 \
        -e FERRUM_MESH_DNS_PROXY_ENABLED=false \
        -e FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=0 \
        -e FERRUM_POOL_WARMUP_ENABLED=false \
        -e FERRUM_PROXY_HTTP_PORT=0 \
        -e FERRUM_ADMIN_HTTP_PORT=15120 \
        -e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
        -e FERRUM_METRICS_ALLOWED_CIDRS=127.0.0.1/32 \
        -e FERRUM_LOG_LEVEL=error \
        "$FERRUM_IMAGE" >/dev/null
}

start_envoy() {
    mkdir -p "$RUNTIME_DIR/envoy"
    sed "s|CERT_DIR|/etc/mesh-certs|g" "$SCRIPT_DIR/configs/envoy/server.yaml.tmpl" \
        > "$RUNTIME_DIR/envoy/server.yaml"
    sed "s|CERT_DIR|/etc/mesh-certs|g" "$SCRIPT_DIR/configs/envoy/client.yaml.tmpl" \
        > "$RUNTIME_DIR/envoy/client.yaml"
    chmod 644 "$RUNTIME_DIR/envoy/server.yaml" "$RUNTIME_DIR/envoy/client.yaml"
    # Distinct --base-id: two Envoy processes sharing one host netns
    # otherwise collide on the base-id domain socket and the second exits.
    # v1.39.1's root entrypoint uses su-exec, which rebuilds groups. Start
    # nonroot so its direct-exec branch retains Docker's fixture group.
    docker run -d --network host --name "$SERVER_NAME" --user 65532:65532 --group-add "$CERT_GID" \
        -v "$RUNTIME_DIR/envoy/server.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$CERT_DIR/svc:/etc/mesh-certs/svc:ro" \
        "$ENVOY_IMAGE" -c /etc/envoy/envoy.yaml --base-id 0 -l error >/dev/null
    docker run -d --network host --name "$CLIENT_NAME" --user 65532:65532 --group-add "$CERT_GID" \
        -v "$RUNTIME_DIR/envoy/client.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$CERT_DIR/client:/etc/mesh-certs/client:ro" \
        "$ENVOY_IMAGE" -c /etc/envoy/envoy.yaml --base-id 1 -l error >/dev/null
}

start_consul() {
    # Real Consul control plane (single dev agent) generating real
    # Envoy sidecar config over xDS; east-west mTLS uses Consul's own
    # Connect CA (EC P-256 issuance profile, Consul-issued leaves, so
    # this arm shares the cert *profile* but not the literal cert files
    # of the ferrum/envoy arms). Proxy admin ports and the loopback
    # agent channel are adapted by prepare_consul_bootstrap.py.
    mkdir -p "$RUNTIME_DIR/consul"
    cp "$SCRIPT_DIR/configs/consul/svc.json" "$RUNTIME_DIR/consul/svc.json"
    cp "$SCRIPT_DIR/configs/consul/client.json" "$RUNTIME_DIR/consul/client.json"
    cp "$SCRIPT_DIR/configs/consul/intention-deny.json" "$RUNTIME_DIR/consul/intention-deny.json"
    docker run -d --network host --name "$AGENT_NAME" \
        "$CONSUL_IMAGE" agent -dev -client=127.0.0.1 -bind=127.0.0.1 >/dev/null
    local ready=false running
    while [ "$SECONDS" -lt "$READINESS_DEADLINE" ]; do
        running=$(readiness_command 3 docker inspect --format '{{.State.Running}}' "$AGENT_NAME") || return 1
        [ "$running" = true ] || { echo "[ready] Consul agent exited" >&2; return 1; }
        if docker exec "$AGENT_NAME" consul members >/dev/null 2>&1; then
            ready=true; break
        fi
        sleep 0.5
    done
    [ "$ready" = true ] || { echo "[ready] Consul agent exhausted readiness budget" >&2; return 1; }
    docker cp "$RUNTIME_DIR/consul/svc.json" "$AGENT_NAME:/tmp/svc.json"
    docker cp "$RUNTIME_DIR/consul/client.json" "$AGENT_NAME:/tmp/client.json"
    docker cp "$RUNTIME_DIR/consul/intention-deny.json" "$AGENT_NAME:/tmp/intention-deny.json"
    docker exec "$AGENT_NAME" consul services register /tmp/svc.json >/dev/null
    docker exec "$AGENT_NAME" consul services register /tmp/client.json >/dev/null
    # Keep the historical Consul TCP/L4 arm. HTTP is a separate, explicit
    # service-defaults arm; service registration alone defaults to TCP.
    if [ "$MESH" = consulhttp ]; then
        docker cp "$SCRIPT_DIR/configs/consul/svc-http.json" "$AGENT_NAME:/tmp/svc-http.json"
        docker cp "$SCRIPT_DIR/configs/consul/client-http.json" "$AGENT_NAME:/tmp/client-http.json"
        docker exec "$AGENT_NAME" consul config write /tmp/svc-http.json >/dev/null
        docker exec "$AGENT_NAME" consul config write /tmp/client-http.json >/dev/null
    fi
    docker exec "$AGENT_NAME" consul connect envoy -sidecar-for svc-1 -bootstrap \
        > "$RUNTIME_DIR/consul/svc-bootstrap.json"
    docker exec "$AGENT_NAME" consul connect envoy -sidecar-for client-1 -bootstrap \
        > "$RUNTIME_DIR/consul/client-bootstrap.json"
    python3 "$SCRIPT_DIR/prepare_consul_bootstrap.py" "$RUNTIME_DIR/consul/svc-bootstrap.json" 19002
    python3 "$SCRIPT_DIR/prepare_consul_bootstrap.py" "$RUNTIME_DIR/consul/client-bootstrap.json" 19001
    chmod 644 "$RUNTIME_DIR/consul/svc-bootstrap.json" "$RUNTIME_DIR/consul/client-bootstrap.json"
    # Distinct --base-id: two Envoy processes sharing one host netns
    # otherwise collide on the base-id domain socket.
    docker run -d --network host --name "$SERVER_NAME" \
        -v "$RUNTIME_DIR/consul/svc-bootstrap.json:/bootstrap.json:ro" \
        "$ENVOY_IMAGE" -c /bootstrap.json --base-id 0 -l error >/dev/null
    docker run -d --network host --name "$CLIENT_NAME" \
        -v "$RUNTIME_DIR/consul/client-bootstrap.json:/bootstrap.json:ro" \
        "$ENVOY_IMAGE" -c /bootstrap.json --base-id 1 -l error >/dev/null
}

# Consul-native authorization probe: a deny intention for client->svc
# must break the echo path, and deleting it must restore it. This is
# the Consul equivalent of the cert-matrix probes (identity material is
# Consul-issued and agent-held, not files this harness can present).
consul_intention_probe() {
    local evidence="$OUTPUT_DIR/logs/auth_probes.log"
    : > "$evidence"
    if probe_loadgen "http://127.0.0.1:21000/echo"; then
        echo "[auth-probe] FAIL: plaintext echo succeeded on Consul public listener :21000" | tee -a "$evidence" >&2
        return 1
    fi
    echo "[auth-probe] ok: plaintext refused on public listener" | tee -a "$evidence"
    docker exec "$AGENT_NAME" consul config write /tmp/intention-deny.json >> "$evidence" 2>&1
    local attempt denied=false exhausted=false
    for attempt in $(seq 1 20); do
        [ "$SECONDS" -lt "$READINESS_DEADLINE" ] || { exhausted=true; break; }
        if ! probe_loadgen "http://127.0.0.1:$OUTBOUND_PORT/echo"; then
            # A probe cut short by the shared budget is not a denial.
            [ "$SECONDS" -lt "$READINESS_DEADLINE" ] || { exhausted=true; break; }
            denied=true; break
        fi
        sleep 0.5
    done
    docker exec "$AGENT_NAME" consul config delete -kind service-intentions -name svc >> "$evidence" 2>&1
    if [ "$exhausted" = true ]; then
        echo "[auth-probe] FAIL: shared ${READINESS_TIMEOUT_SECS}s readiness budget exhausted before the deny probe completed" | tee -a "$evidence" >&2
        return 1
    fi
    if [ "$denied" != true ]; then
        echo "[auth-probe] FAIL: deny intention did not break the echo path" | tee -a "$evidence" >&2
        return 1
    fi
    echo "[auth-probe] ok: deny intention broke echo; restoring" | tee -a "$evidence"
    wait_ready "http://127.0.0.1:$OUTBOUND_PORT/echo" consul-pair-restored "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME"
}

start_linkerd() {
    # linkerd2-proxy standalone (no Kubernetes control plane): static file
    # identity, destination service pointed at the peer inbound is NOT
    # available standalone, so outbound uses direct DNS-less routing via
    # LINKERD2_PROXY_DESTINATION_SVC_ADDR unset + outbound listener in
    # "forward" posture is not a supported mode. This arm exists to prove
    # or refute standalone operation with evidence: if the echo probe
    # fails, the arm is recorded unsupported-standalone with logs.
    #
    # linkerd2-proxy's identity init opens key.p8 for writing and writes its
    # CSR into the identity directory; on a read-only mount it exits before
    # the Destination check that classifies this arm. Each proxy therefore
    # gets a disposable, group-writable copy under the runtime directory,
    # and the shared certificate fixture stays read-only.
    local identity="${RUNTIME_DIR:?}/linkerd"
    # Start each cell from a clean copy: no CSR or key left by an earlier run.
    rm -rf "$identity"
    mkdir -p "$identity/svc" "$identity/client"
    cp "$CERT_DIR/svc/svid.crt" "$identity/svc/crt.pem"
    cp "$CERT_DIR/svc/svid.key" "$identity/svc/key.p8"
    cp "$CERT_DIR/client/svid.crt" "$identity/client/crt.pem"
    cp "$CERT_DIR/client/svid.key" "$identity/client/key.p8"
    chgrp "$CERT_GID" "$identity/svc" "$identity/client" "$identity"/*/key.p8
    chmod 770 "$identity/svc" "$identity/client"
    chmod 660 "$identity"/*/key.p8
    chmod 644 "$identity"/*/crt.pem
    docker run -d --network host --name "$SERVER_NAME" --group-add "$CERT_GID" \
        -v "$identity/svc:/var/run/linkerd/identity/end-entity" \
        -e LINKERD2_PROXY_LOG=info \
        -e LINKERD2_PROXY_INBOUND_LISTEN_ADDR=127.0.0.1:4143 \
        -e LINKERD2_PROXY_INBOUND_PORTS=18080 \
        -e LINKERD2_PROXY_DESTINATION_CONTEXT="ns:ferrum" \
        -e LINKERD2_PROXY_IDENTITY_DIR=/var/run/linkerd/identity/end-entity \
        -e LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS="$(cat "$CERT_DIR/svc/bundle.pem")" \
        -e LINKERD2_PROXY_IDENTITY_TOKEN_FILE="" \
        -e LINKERD2_PROXY_IDENTITY_LOCAL_NAME=svc.ferrum.serviceaccount.identity.linkerd.cluster.local \
        "$LINKERD_IMAGE" >/dev/null 2>&1 || true
    docker run -d --network host --name "$CLIENT_NAME" --group-add "$CERT_GID" \
        -v "$identity/client:/var/run/linkerd/identity/end-entity" \
        -e LINKERD2_PROXY_LOG=info \
        -e LINKERD2_PROXY_OUTBOUND_LISTEN_ADDR=127.0.0.1:4140 \
        -e LINKERD2_PROXY_DESTINATION_CONTEXT="ns:ferrum" \
        -e LINKERD2_PROXY_IDENTITY_DIR=/var/run/linkerd/identity/end-entity \
        -e LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS="$(cat "$CERT_DIR/client/bundle.pem")" \
        -e LINKERD2_PROXY_IDENTITY_TOKEN_FILE="" \
        -e LINKERD2_PROXY_IDENTITY_LOCAL_NAME=client.ferrum.serviceaccount.identity.linkerd.cluster.local \
        "$LINKERD_IMAGE" >/dev/null 2>&1 || true
}

# ── Bench cells ─────────────────────────────────────────────────────────────
effective_concurrency() {
    # Common bulk schedule for every arm (mirrors the gateway harness,
    # which halves concurrency at 1 MiB and quarters it at 5 MiB so
    # in-flight bodies cannot OOM the runner). Never reduce only one arm.
    local payload="$1"
    if [ "$payload" -ge 5242880 ]; then
        local q=$(( CONCURRENCY / 4 )); [ "$q" -lt 1 ] && q=1; echo "$q"
    elif [ "$payload" -ge 1048576 ]; then
        local h=$(( CONCURRENCY / 2 )); [ "$h" -lt 1 ] && h=1; echo "$h"
    else
        echo "$CONCURRENCY"
    fi
}

# One exchange budget each for a warmup and a measured drain, plus setup.
cell_wall_timeout_secs() {
    echo $((DURATION + WARMUP + 2 * EXCHANGE_TIMEOUT_SECS + 20))
}

run_cell() {
    local payload="$1" target="$2"
    local out="$OUTPUT_DIR/${MESH}_http1_${payload}.json"
    local eff_concurrency
    eff_concurrency=$(effective_concurrency "$payload")
    echo "[bench] $MESH payload=${payload}B duration=${DURATION}s concurrency=$eff_concurrency"

    # Warm the same frontend connections that are measured. The host sampler
    # brackets /proc CPU/steal at the loadgen's common measurement markers.
    local resource_args=()
    if [ "$MESH" != direct ]; then
        resource_args=(--container "$CLIENT_NAME" --container "$SERVER_NAME")
    fi
    if [ "$MESH" = ferrum ] && [ "$BENCH_FERRUM_FEATURES" = cloud-secrets,bench-h1-profile ]; then
        resource_args+=(--allocation-url http://127.0.0.1:15120/metrics --allocation-url http://127.0.0.1:15020/metrics)
    fi
    local rc=0
    local cell_budget
    cell_budget=$(cell_wall_timeout_secs)
    echo "[bench] cell wall budget=${cell_budget}s exchange budget=${EXCHANGE_TIMEOUT_SECS}s"
    timeout --signal=TERM --kill-after=5s "${cell_budget}s" \
        python3 -u "$SCRIPT_DIR/collect_resources.py" "${resource_args[@]}" \
        --output "$out" --resources "${out%.json}.resources.json" --image "$TOOLS_IMAGE" \
        --loadgen-name "$LOADGEN_NAME" --exchange-timeout-secs "$EXCHANGE_TIMEOUT_SECS" \
        --target "$target" --host-header "$HOST_HEADER" --mesh "$MESH" \
        --duration "$DURATION" --concurrency "$eff_concurrency" \
        --warmup "$WARMUP" --payload-size "$payload" || rc=$?

    timeout --signal=KILL 2s docker rm -f "$LOADGEN_NAME" >/dev/null 2>&1 || true
    if [ "$rc" -ne 0 ] || ! grep -q '"rps"' "$out"; then
        echo "[bench] cell failed (rc=$rc); recording zero-result JSON" >&2
        [ ! -f "$out" ] || cp "$out" "${out%.json}.failed-output.json"
        printf '{"gateway":"%s","mesh":"%s","protocol":"http1","payload_size":%s,"rps":0,"total_errors":-1,"error":"loadgen failed"}\n' \
            "$MESH" "$MESH" "$payload" > "$out"
        return 1
    fi
    if ! grep -q '"total_errors": 0' "$out" || ! grep -qE '"total_requests": [1-9]' "$out"; then
        echo "[bench] cell has errors or no useful completions; preserving its report and stopping" >&2
        return 1
    fi
    grep -o '"rps": [0-9.]*' "$out" | head -1 || true
}

# Authentication probe matrix against the server proxy's mTLS inbound:
# plaintext must not echo, a TLS handshake without a client certificate
# must fail, a client certificate from a rogue CA must fail, and the
# valid workload certificate must complete the handshake. A passing
# negative (or failing positive) means the measured path is not the
# authenticated mesh transport the arm claims.
auth_probes() {
    local inbound_port="$1"
    local evidence="$OUTPUT_DIR/logs/auth_probes.log"
    : > "$evidence"
    if probe_loadgen "http://127.0.0.1:$inbound_port/echo"; then
        echo "[auth-probe] FAIL: plaintext echo succeeded on mTLS inbound :$inbound_port" | tee -a "$evidence" >&2
        return 1
    fi
    echo "[auth-probe] ok: plaintext refused" | tee -a "$evidence"

    tls_probe() {
        local rc=0
        readiness_command 25 docker run --rm --network host --name "$PROBE_NAME" --group-add "$CERT_GID" \
            -v "$CERT_DIR:/certs:ro" \
            --entrypoint /usr/local/bin/mesh_tls_probe \
            "$TOOLS_IMAGE" --addr "127.0.0.1:$inbound_port" \
            --server-name "$HOST_HEADER" "$@" >> "$evidence" 2>&1 || rc=$?
        timeout --signal=KILL 2s docker rm -f "$PROBE_NAME" >/dev/null 2>&1 || true
        return "$rc"
    }
    if tls_probe --ca /certs/client/bundle.pem \
            --cert /certs/client/svid.crt --key /certs/client/svid.key; then
        echo "[auth-probe] ok: valid client certificate handshake" | tee -a "$evidence"
    else
        echo "[auth-probe] FAIL: valid client certificate refused" | tee -a "$evidence" >&2
        return 1
    fi
    if tls_probe --ca /certs/client/bundle.pem; then
        echo "[auth-probe] FAIL: handshake without client certificate succeeded" | tee -a "$evidence" >&2
        return 1
    else
        [ "$?" -eq 1 ] || { echo "[auth-probe] infrastructure failure in no-client-cert probe" | tee -a "$evidence" >&2; return 1; }
    fi
    echo "[auth-probe] ok: no-client-cert refused" | tee -a "$evidence"
    if tls_probe --ca /certs/client/bundle.pem \
            --cert /certs/rogue/svid.crt --key /certs/rogue/svid.key; then
        echo "[auth-probe] FAIL: rogue-CA client certificate accepted" | tee -a "$evidence" >&2
        return 1
    else
        [ "$?" -eq 1 ] || { echo "[auth-probe] infrastructure failure in rogue-CA probe" | tee -a "$evidence" >&2; return 1; }
    fi
    echo "[auth-probe] ok: rogue-CA client certificate refused" | tee -a "$evidence"
    return 0
}

write_manifest() {
    # Expected-cell manifest written before startup; the summarizer
    # flags any expected cell that is missing from the results.
    local cells=""
    for payload in $PAYLOAD_SIZES; do
        cells="${cells}${cells:+,}${payload}"
    done
    printf '{"mesh":"%s","payload_sizes":[%s],"duration":%s,"concurrency":%s,"warmup":%s,"exchange_timeout_secs":%s,"readiness_timeout_secs":%s,"cell_wall_timeout_secs":%s,"cell_kill_grace_secs":5,"cell_cleanup_timeout_secs":2}\n' \
        "$MESH" "$cells" "$DURATION" "$CONCURRENCY" "$WARMUP" "$EXCHANGE_TIMEOUT_SECS" "$READINESS_TIMEOUT_SECS" \
        "$(cell_wall_timeout_secs)" \
        > "$OUTPUT_DIR/${MESH}_manifest.json"
}

# ── Main ────────────────────────────────────────────────────────────────────
if $BUILD_ONLY; then
    echo "================================================="
    echo "  Mesh Runtime Benchmark — build images only"
    echo "================================================="
    prepare_images
    echo "[build] ready: $TOOLS_IMAGE and $FERRUM_IMAGE"
    exit 0
fi

echo "================================================="
echo "  Mesh Runtime Benchmark — arm: $MESH"
echo "================================================="
write_manifest
generate_certs
prepare_cert_access
prepare_images
READINESS_DEADLINE=$((SECONDS + READINESS_TIMEOUT_SECS))
if probe_loadgen "http://127.0.0.1:$BACKEND_PORT/echo" 2>/dev/null; then
    echo "[backend] port $BACKEND_PORT already answers; refusing to displace its owner" >&2
    write_arm_status failed "backend port $BACKEND_PORT already in use"
    exit 1
fi
start_backend

if ! wait_ready "http://127.0.0.1:$BACKEND_PORT/echo" backend "$BACKEND_NAME"; then
    dump_logs
    write_arm_status failed "backend did not become ready"
    exit 1
fi

TARGET="http://127.0.0.1:$BACKEND_PORT/echo"
case "$MESH" in
    direct) ;;
    ferrum)
        start_ferrum
        TARGET="http://127.0.0.1:$OUTBOUND_PORT/echo"
        if ! wait_ready "$TARGET" ferrum-pair "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME"; then
            dump_logs; write_arm_status failed "ferrum pair did not become ready"; exit 1
        fi
        if ! auth_probes 15006; then
            dump_logs; write_arm_status failed "auth probe failed on ferrum inbound"; exit 1
        fi
        ;;
    envoy)
        start_envoy
        TARGET="http://127.0.0.1:$OUTBOUND_PORT/echo"
        if ! wait_ready "$TARGET" envoy-pair "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME"; then
            dump_logs; write_arm_status failed "envoy pair did not become ready"; exit 1
        fi
        if ! auth_probes 15006; then
            dump_logs; write_arm_status failed "auth probe failed on envoy inbound"; exit 1
        fi
        ;;
    consul|consulhttp)
        if ! docker image inspect "$CONSUL_IMAGE" >/dev/null 2>&1; then
            write_arm_status failed "consul image $CONSUL_IMAGE unavailable (pull failed)"
            exit 1
        fi
        start_consul
        TARGET="http://127.0.0.1:$OUTBOUND_PORT/echo"
        if ! wait_ready "$TARGET" consul-pair "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME"; then
            dump_logs; write_arm_status failed "consul pair did not become ready"; exit 1
        fi
        if ! consul_intention_probe; then
            dump_logs; write_arm_status failed "auth probe failed on consul pair"; exit 1
        fi
        # Listener resources only: never upload SDS secrets from config_dump.
        readiness_command 6 curl --fail --silent --show-error --connect-timeout 2 --max-time 5 'http://127.0.0.1:19001/config_dump?resource=dynamic_listeners' \
            > "$OUTPUT_DIR/logs/consul-client-listeners.json"
        readiness_command 6 curl --fail --silent --show-error --connect-timeout 2 --max-time 5 'http://127.0.0.1:19002/config_dump?resource=dynamic_listeners' \
            > "$OUTPUT_DIR/logs/consul-server-listeners.json"
        python3 "$SCRIPT_DIR/verify_consul_protocol.py" "$MESH" \
            "$OUTPUT_DIR/logs/consul-client-listeners.json" \
            "$OUTPUT_DIR/logs/consul-server-listeners.json" \
            > "$OUTPUT_DIR/logs/consul-protocol.json"
        ;;
    linkerd)
        if ! docker image inspect "$LINKERD_IMAGE" >/dev/null 2>&1; then
            write_arm_status failed "linkerd image $LINKERD_IMAGE unavailable (pull failed)"
            exit 1
        fi
        start_linkerd
        TARGET="http://127.0.0.1:4140/echo"
        if ! wait_ready "$TARGET" linkerd-pair "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME"; then
            dump_logs
            if grep -q "no destination service configured" \
                    "$OUTPUT_DIR/logs/${CLIENT_NAME}.log" \
                    "$OUTPUT_DIR/logs/${SERVER_NAME}.log" 2>/dev/null; then
                echo "[linkerd] requires Destination control plane; recording unsupported-standalone" >&2
                write_arm_status unsupported-standalone "linkerd2-proxy ($LINKERD_IMAGE) requires the Destination control-plane service; see logs/"
                exit 0
            fi
            write_arm_status failed "linkerd standalone probe failed without destination-service evidence; see logs/"
            exit 1
        fi
        if ! auth_probes 4143; then
            dump_logs; write_arm_status failed "auth probe failed on linkerd inbound"; exit 1
        fi
        ;;
esac

write_arm_status ready "echo probe passed"
READINESS_DEADLINE=0
for payload in $PAYLOAD_SIZES; do
    if ! run_cell "$payload" "$TARGET"; then
        dump_logs
        write_arm_status failed "loadgen or resource collection failed"
        exit 1
    fi
done
dump_logs
echo "[done] arm $MESH complete; results in $OUTPUT_DIR"
