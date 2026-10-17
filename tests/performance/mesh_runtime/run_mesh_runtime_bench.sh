#!/bin/bash
# Mesh-runtime head-to-head benchmark for mesh-runtime-benchmark.yml.
#
# For one mesh arm, runs mesh_loadgen through a client/server proxy pair
# (mTLS east-west hop) into mesh_backend at every requested payload size,
# plus same-runner resource sampling. Writes per-cell JSON named
# `<mesh>_http1_<payload>.json` (gateway-bench compatible fields) and
# `<mesh>_http1_<payload>.stats.jsonl` (docker stats samples of the proxy
# containers) to the output directory.
#
# Usage: ./run_mesh_runtime_bench.sh <mesh> [options]
#   Mesh: direct | ferrum | envoy | linkerd
#
# Options:
#   --payload-sizes "1024 10240 71680 512000 1048576 5242880"
#   --duration 10
#   --concurrency 100
#   --warmup 2            (seconds of discarded load before each cell)
#   --output-dir /tmp/mesh-runtime-results
#   --skip-build          (reuse existing tools/ferrum docker images)
#
# Environment:
#   DOCKER           docker command (default: docker; may include --context)
#   FERRUM_IMAGE     Ferrum image (default: ferrum-edge:bench)
#   ENVOY_IMAGE      Envoy image (default: envoyproxy/envoy:v1.39.1)
#   LINKERD_IMAGE    Linkerd proxy image (default: ghcr.io/linkerd/proxy:edge-25.11.1)
#   TOOLS_IMAGE      Harness tools image (default: mesh-bench-tools:local)
#
# Every container (backend, proxies, load generator) runs with
# --network host so no arm gets a bridge-NAT advantage or penalty, the
# same convention as run_gateway_protocol_bench.sh. Proxy containers are
# named meshbench-<mesh>-* and only those are cleaned up.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"

MESH="${1:-}"
[ -z "$MESH" ] && { echo "usage: $0 <direct|ferrum|envoy|linkerd> [options]" >&2; exit 2; }
shift
case "$MESH" in
    direct|ferrum|envoy|linkerd) ;;
    *) echo "unknown mesh arm: $MESH" >&2; exit 2 ;;
esac

PAYLOAD_SIZES="1024 10240 71680 512000 1048576 5242880"
DURATION=10
CONCURRENCY=100
WARMUP=2
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

# Validate numeric inputs before they reach any command.
for v in "$DURATION" "$CONCURRENCY" "$WARMUP"; do
    [[ "$v" =~ ^[0-9]+$ ]] || { echo "non-numeric bench parameter: $v" >&2; exit 2; }
done
for s in $PAYLOAD_SIZES; do
    [[ "$s" =~ ^[0-9]+$ ]] || { echo "non-numeric payload size: $s" >&2; exit 2; }
done

DOCKER="${DOCKER:-docker}"
FERRUM_IMAGE="${FERRUM_IMAGE:-ferrum-edge:bench}"
ENVOY_IMAGE="${ENVOY_IMAGE:-envoyproxy/envoy:v1.39.1}"
LINKERD_IMAGE="${LINKERD_IMAGE:-ghcr.io/linkerd/proxy:edge-25.11.1}"
TOOLS_IMAGE="${TOOLS_IMAGE:-mesh-bench-tools:local}"

BACKEND_PORT=18080
OUTBOUND_PORT=15101
HOST_HEADER="svc.ferrum.svc.cluster.local"
BACKEND_NAME="meshbench-${MESH}-backend"
CLIENT_NAME="meshbench-${MESH}-client"
SERVER_NAME="meshbench-${MESH}-server"

mkdir -p "$OUTPUT_DIR"
# Harness runtime state (certs, rendered configs, logs) lives next to the
# results so CI artifacts carry the evidence. Private keys in this tree
# are single-run throwaways generated below; the workflow artifact step
# excludes the runtime dir.
RUNTIME_DIR="$OUTPUT_DIR/runtime"
CERT_DIR="$RUNTIME_DIR/certs"
mkdir -p "$RUNTIME_DIR/logs"

ARM_STATUS_FILE="$OUTPUT_DIR/${MESH}_arm_status.json"

write_arm_status() {
    # $1 = status (ready|unsupported-standalone|failed), $2 = detail
    printf '{"mesh":"%s","status":"%s","detail":"%s"}\n' "$MESH" "$1" "$2" > "$ARM_STATUS_FILE"
}

cleanup() {
    $DOCKER rm -f "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

# ── Certs: one EC P-256 CA, svc + client SVID-shaped leaves ────────────────
generate_certs() {
    if [ -f "$CERT_DIR/svc/svid.crt" ]; then
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
        chmod 644 "$dir/svid.key" "$dir/svid.crt" "$dir/bundle.pem"
    }
    issue_leaf "$CERT_DIR/svc" "spiffe://cluster.local/ns/ferrum/sa/svc" "svc.ferrum.svc.cluster.local"
    issue_leaf "$CERT_DIR/client" "spiffe://cluster.local/ns/ferrum/sa/client" "client.ferrum.svc.cluster.local"
    openssl verify -CAfile "$CERT_DIR/ca/root.crt" \
        "$CERT_DIR/svc/svid.crt" "$CERT_DIR/client/svid.crt" >/dev/null
}

# ── Builds / pulls ──────────────────────────────────────────────────────────
prepare_images() {
    if $SKIP_BUILD; then
        echo "[build] --skip-build: expecting $TOOLS_IMAGE to exist"
    else
        echo "[build] building harness tools image $TOOLS_IMAGE"
        $DOCKER build -f "$SCRIPT_DIR/Dockerfile.tools" -t "$TOOLS_IMAGE" "$SCRIPT_DIR" \
            > "$RUNTIME_DIR/logs/tools-build.log" 2>&1 || {
            tail -30 "$RUNTIME_DIR/logs/tools-build.log" >&2; exit 1; }
    fi
    case "$MESH" in
        ferrum)
            if ! $DOCKER image inspect "$FERRUM_IMAGE" >/dev/null 2>&1; then
                if $SKIP_BUILD; then
                    echo "[build] ferrum image $FERRUM_IMAGE missing and --skip-build set" >&2; exit 1
                fi
                echo "[build] building ferrum image $FERRUM_IMAGE (repo Dockerfile)"
                $DOCKER build -t "$FERRUM_IMAGE" -f "$PROJECT_ROOT/Dockerfile" "$PROJECT_ROOT" \
                    > "$RUNTIME_DIR/logs/ferrum-build.log" 2>&1 || {
                    tail -30 "$RUNTIME_DIR/logs/ferrum-build.log" >&2; exit 1; }
            fi
            ;;
        envoy) $DOCKER pull "$ENVOY_IMAGE" > "$RUNTIME_DIR/logs/envoy-pull.log" 2>&1 || true ;;
        linkerd) $DOCKER pull "$LINKERD_IMAGE" > "$RUNTIME_DIR/logs/linkerd-pull.log" 2>&1 || true ;;
    esac
}

start_backend() {
    echo "[backend] starting mesh_backend on 127.0.0.1:$BACKEND_PORT"
    $DOCKER run -d --network host --name "$BACKEND_NAME" \
        --entrypoint /usr/local/bin/mesh_backend \
        "$TOOLS_IMAGE" --listen "127.0.0.1:$BACKEND_PORT" >/dev/null
}

# One short loadgen run used as the readiness probe: portable across
# Linux hosts and local container VMs (no host curl into the VM netns).
probe_loadgen() {
    local target="$1" out="$RUNTIME_DIR/logs/probe.json"
    $DOCKER run --rm --network host "$TOOLS_IMAGE" \
        --target "$target" --host-header "$HOST_HEADER" --mesh probe \
        --duration 1 --concurrency 1 --payload-size 64 --json > "$out" 2>/dev/null || return 1
    grep -q '"total_errors": 0' "$out" && grep -qE '"total_requests": [1-9]' "$out"
}

wait_ready() {
    local target="$1" label="$2" tries="${3:-60}"
    for _ in $(seq 1 "$tries"); do
        if probe_loadgen "$target"; then
            echo "[ready] $label answering through $target"
            return 0
        fi
        sleep 0.5
    done
    echo "[ready] $label did not become ready via $target" >&2
    return 1
}

dump_logs() {
    for c in "$CLIENT_NAME" "$SERVER_NAME" "$BACKEND_NAME"; do
        $DOCKER logs "$c" > "$RUNTIME_DIR/logs/${c}.log" 2>&1 || true
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
    # Server (destination) sidecar: inbound :15006 STRICT mTLS.
    $DOCKER run -d --network host --name "$SERVER_NAME" \
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
        -e FERRUM_LOG_LEVEL=error \
        "$FERRUM_IMAGE" >/dev/null
    # Client sidecar: outbound :15101 dials destination :15006, pins SVID.
    $DOCKER run -d --network host --name "$CLIENT_NAME" \
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
        -e FERRUM_LOG_LEVEL=error \
        "$FERRUM_IMAGE" >/dev/null
}

start_envoy() {
    mkdir -p "$RUNTIME_DIR/envoy"
    sed "s|CERT_DIR|/etc/mesh-certs|g" "$SCRIPT_DIR/configs/envoy/server.yaml.tmpl" \
        > "$RUNTIME_DIR/envoy/server.yaml"
    sed "s|CERT_DIR|/etc/mesh-certs|g" "$SCRIPT_DIR/configs/envoy/client.yaml.tmpl" \
        > "$RUNTIME_DIR/envoy/client.yaml"
    # Distinct --base-id: two Envoy processes sharing one host netns
    # otherwise collide on the base-id domain socket and the second exits.
    $DOCKER run -d --network host --name "$SERVER_NAME" \
        -v "$RUNTIME_DIR/envoy/server.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$CERT_DIR/svc:/etc/mesh-certs/svc:ro" \
        -v "$CERT_DIR/client:/etc/mesh-certs/client:ro" \
        "$ENVOY_IMAGE" -c /etc/envoy/envoy.yaml --base-id 0 -l error >/dev/null
    $DOCKER run -d --network host --name "$CLIENT_NAME" \
        -v "$RUNTIME_DIR/envoy/client.yaml:/etc/envoy/envoy.yaml:ro" \
        -v "$CERT_DIR/svc:/etc/mesh-certs/svc:ro" \
        -v "$CERT_DIR/client:/etc/mesh-certs/client:ro" \
        "$ENVOY_IMAGE" -c /etc/envoy/envoy.yaml --base-id 1 -l error >/dev/null
}

start_linkerd() {
    # linkerd2-proxy standalone (no Kubernetes control plane): static file
    # identity, destination service pointed at the peer inbound is NOT
    # available standalone, so outbound uses direct DNS-less routing via
    # LINKERD2_PROXY_DESTINATION_SVC_ADDR unset + outbound listener in
    # "forward" posture is not a supported mode. This arm exists to prove
    # or refute standalone operation with evidence: if the echo probe
    # fails, the arm is recorded unsupported-standalone with logs.
    mkdir -p "$CERT_DIR/linkerd-svc" "$CERT_DIR/linkerd-client"
    cp "$CERT_DIR/svc/svid.crt" "$CERT_DIR/linkerd-svc/crt.pem"
    cp "$CERT_DIR/svc/svid.key" "$CERT_DIR/linkerd-svc/key.p8"
    cp "$CERT_DIR/client/svid.crt" "$CERT_DIR/linkerd-client/crt.pem"
    cp "$CERT_DIR/client/svid.key" "$CERT_DIR/linkerd-client/key.p8"
    $DOCKER run -d --network host --name "$SERVER_NAME" \
        -v "$CERT_DIR/linkerd-svc:/var/run/linkerd/identity/end-entity" \
        -e LINKERD2_PROXY_LOG=info \
        -e LINKERD2_PROXY_INBOUND_LISTEN_ADDR=127.0.0.1:4143 \
        -e LINKERD2_PROXY_INBOUND_PORTS=18080 \
        -e LINKERD2_PROXY_DESTINATION_CONTEXT="ns:ferrum" \
        -e LINKERD2_PROXY_IDENTITY_DIR=/var/run/linkerd/identity/end-entity \
        -e LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS="$(cat "$CERT_DIR/svc/bundle.pem")" \
        -e LINKERD2_PROXY_IDENTITY_TOKEN_FILE="" \
        -e LINKERD2_PROXY_IDENTITY_LOCAL_NAME=svc.ferrum.serviceaccount.identity.linkerd.cluster.local \
        "$LINKERD_IMAGE" >/dev/null 2>&1 || true
    $DOCKER run -d --network host --name "$CLIENT_NAME" \
        -v "$CERT_DIR/linkerd-client:/var/run/linkerd/identity/end-entity" \
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

run_cell() {
    local payload="$1" target="$2"
    local out="$OUTPUT_DIR/${MESH}_http1_${payload}.json"
    local stats="$OUTPUT_DIR/${MESH}_http1_${payload}.stats.jsonl"
    local eff_concurrency
    eff_concurrency=$(effective_concurrency "$payload")
    echo "[bench] $MESH payload=${payload}B duration=${DURATION}s concurrency=$eff_concurrency"

    if [ "$WARMUP" -gt 0 ]; then
        $DOCKER run --rm --network host "$TOOLS_IMAGE" \
            --target "$target" --host-header "$HOST_HEADER" --mesh warmup \
            --duration "$WARMUP" --concurrency "$eff_concurrency" \
            --payload-size "$payload" --json > /dev/null 2>&1 || true
    fi

    # Sample proxy container stats (CPU/memory) for the measured window.
    : > "$stats"
    local stats_pid=""
    if [ "$MESH" != direct ]; then
        (
            while :; do
                $DOCKER stats --no-stream --format '{{json .}}' \
                    "$CLIENT_NAME" "$SERVER_NAME" >> "$stats" 2>/dev/null || true
                sleep 1
            done
        ) &
        stats_pid=$!
    fi

    local rc=0
    $DOCKER run --rm --network host "$TOOLS_IMAGE" \
        --target "$target" --host-header "$HOST_HEADER" --mesh "$MESH" \
        --duration "$DURATION" --concurrency "$eff_concurrency" \
        --payload-size "$payload" --json > "$out" || rc=$?

    if [ -n "$stats_pid" ]; then
        kill "$stats_pid" 2>/dev/null || true
        wait "$stats_pid" 2>/dev/null || true
    fi

    if [ "$rc" -ne 0 ] || ! grep -q '"rps"' "$out"; then
        echo "[bench] cell failed (rc=$rc); recording zero-result JSON" >&2
        printf '{"gateway":"%s","mesh":"%s","protocol":"http1","payload_size":%s,"rps":0,"total_errors":-1,"error":"loadgen failed"}\n' \
            "$MESH" "$MESH" "$payload" > "$out"
        return 0
    fi
    grep -o '"rps": [0-9.]*' "$out" | head -1 || true
}

# Plaintext dialed straight at the server proxy's mTLS inbound must not
# produce a successful echo in any mesh arm (a passing plaintext echo
# would mean the measured path is not authenticated mesh traffic).
plaintext_bypass_probe() {
    local inbound_port="$1"
    if probe_loadgen "http://127.0.0.1:$inbound_port/echo"; then
        echo "[auth-probe] FAIL: plaintext echo succeeded on mTLS inbound :$inbound_port" >&2
        return 1
    fi
    echo "[auth-probe] ok: plaintext refused on mTLS inbound :$inbound_port"
    return 0
}

write_manifest() {
    # Expected-cell manifest written before startup; the summarizer
    # flags any expected cell that is missing from the results.
    local cells=""
    for payload in $PAYLOAD_SIZES; do
        cells="${cells}${cells:+,}${payload}"
    done
    printf '{"mesh":"%s","payload_sizes":[%s],"duration":%s,"concurrency":%s,"warmup":%s}\n' \
        "$MESH" "$cells" "$DURATION" "$CONCURRENCY" "$WARMUP" \
        > "$OUTPUT_DIR/${MESH}_manifest.json"
}

# ── Main ────────────────────────────────────────────────────────────────────
echo "================================================="
echo "  Mesh Runtime Benchmark — arm: $MESH"
echo "================================================="
write_manifest
generate_certs
prepare_images
start_backend

if ! wait_ready "http://127.0.0.1:$BACKEND_PORT/echo" backend; then
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
        if ! wait_ready "$TARGET" ferrum-pair 120; then
            dump_logs; write_arm_status failed "ferrum pair did not become ready"; exit 1
        fi
        if ! plaintext_bypass_probe 15006; then
            dump_logs; write_arm_status failed "plaintext bypass on ferrum inbound"; exit 1
        fi
        ;;
    envoy)
        start_envoy
        TARGET="http://127.0.0.1:$OUTBOUND_PORT/echo"
        if ! wait_ready "$TARGET" envoy-pair 120; then
            dump_logs; write_arm_status failed "envoy pair did not become ready"; exit 1
        fi
        if ! plaintext_bypass_probe 15006; then
            dump_logs; write_arm_status failed "plaintext bypass on envoy inbound"; exit 1
        fi
        ;;
    linkerd)
        start_linkerd
        TARGET="http://127.0.0.1:4140/echo"
        if ! wait_ready "$TARGET" linkerd-pair 60; then
            dump_logs
            echo "[linkerd] standalone probe failed; recording unsupported-standalone" >&2
            write_arm_status unsupported-standalone "linkerd2-proxy ($LINKERD_IMAGE) did not pass the standalone echo probe in this attempt; see runtime/logs"
            exit 0
        fi
        ;;
esac

write_arm_status ready "echo probe passed"
for payload in $PAYLOAD_SIZES; do
    run_cell "$payload" "$TARGET"
done
dump_logs
echo "[done] arm $MESH complete; results in $OUTPUT_DIR"
