#!/usr/bin/env bash
set -euo pipefail

# Live ServiceWaypoint mesh e2e suite (issue #7503; design spec
# docs/plans/mesh_virtualservice_servicewaypoint.md section 6.4 and
# Follow-Up 5).
#
# Proves, on a real kind cluster with SPIRE-issued SVIDs and a Ferrum control
# plane serving native MeshSubscribe over production mTLS + JWT, that a
# ServiceWaypoint terminates authenticated HBONE CONNECT tunnels at L7 for the
# Services bound to it and applies mesh-bound VirtualService http[] routes:
#
#   hbone-client (SPIRE SVID) --HTTP/2 CONNECT over mTLS--> swp :15008
#     --inner HTTP/1.1 request, pinned to the CONNECT's bound Service-->
#     VirtualService route --> selected leg's backend (native Sidecar :15006)
#
# Emitted live assertions (`tests/k8s/lib/live_assertions.sh` schema; suite
# `mesh-e2e-service-waypoint`, platform profile `kind-spire-service-waypoint`).
# The six `service_waypoint.*` ids from the design spec, plus the binding and
# metrics rows:
#
#   service_waypoint.binding.bound_services_projected
#                       GET /service-waypoint/services on the waypoint lists
#                       exactly the four bound Services (runs before any L7
#                       probe, and is required even while L7 is absent)
#   service_waypoint.status.mesh_http_routes_reported
#                       the split VirtualService reports FerrumAccepted=True
#                       with status.ferrum.translation.mesh_http_routes
#                       = sidecar_node_and_service_waypoint
#   service_waypoint.virtual_service.weighted_split_90_10
#                       1000 inner requests over HBONE split 90/10 across
#                       swsvc-v1/swsvc-v2 (v1 count in [850, 950])
#   service_waypoint.virtual_service.header_match_and_per_branch_authz
#                       x-canary: true routes every request to swsvc-v2;
#                       swsvc-v2's own AuthorizationPolicy denies x-deny: true
#                       at the waypoint (403, waypoint policy-deny recorded)
#                       while the same header on the swsvc-v1 branch is allowed
#   service_waypoint.virtual_service.host_spoof_rejected
#                       CONNECT to bound Service swsvc with inner Host
#                       swsvc-v2 returns 403 and reaches no backend
#   service_waypoint.virtual_service.cross_namespace_reference_grant
#                       a destination in namespace beta is refused without a
#                       ReferenceGrant (FerrumAccepted=False/RefNotPermitted,
#                       backend not reached), admitted after applying one, and
#                       withdrawn after deleting it
#   service_waypoint.hbone.fence_revocation_on_binding_withdrawal
#                       removing istio.io/use-waypoint from swsvc-v1 cuts an
#                       open L7 tunnel with RST_STREAM(CONNECT_ERROR) and moves
#                       ferrum_mesh_hbone_tunnel_revocations_total
#   service_waypoint.metrics.l7_families_moved
#                       the new ServiceWaypoint L7 families move as the probes
#                       drive them: l7_tunnels_active >= 1 while a tunnel is
#                       held, l7_tunnel_terminations_total{reason=clean_close}
#                       over the split, {reason=fence_revoked} and the HBONE
#                       revocation counter over the withdrawal, and
#                       route_refusals_total{reason=host_mismatch} over the
#                       spoof probe
#
# Until ServiceWaypoint L7 termination ships (issues #7500 / #7501), the
# control plane keeps reporting mesh_http_routes = sidecar_and_node_waypoint.
# The suite treats that as "ServiceWaypoint L7 not present": with
# FERRUM_SWP_E2E_ALLOW_L7_ABSENT=1 it records every L7 row as `skip` with that
# reason (never `pass`) and still requires the binding row; without the flag
# it records them as `fail`. The flag exists only for the adoption window and
# is removed together with the workflow setting once #7501 is on main.
#
# Run locally (requires docker, kind, kubectl, curl, python3, openssl):
#   FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE=true tests/k8s/mesh_e2e_service_waypoint/run.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/.context/mesh-e2e-service-waypoint}"
RESULTS_DIR="${FERRUM_MESH_E2E_RESULTS_DIR:-$ROOT_DIR/target/mesh-e2e-service-waypoint}"
MANIFESTS="$ROOT_DIR/tests/k8s/mesh_e2e_service_waypoint/manifests.yaml"

LIVE_ASSERTIONS_HELPER="$ROOT_DIR/tests/k8s/lib/live_assertions.sh"
SPIRE_HELPER="$ROOT_DIR/tests/k8s/lib/spire.sh"
# shellcheck source=../lib/live_assertions.sh
source "$LIVE_ASSERTIONS_HELPER"
# shellcheck source=../lib/spire.sh
source "$SPIRE_HELPER"

CLUSTER="${FERRUM_MESH_E2E_CLUSTER:-ferrum-swp-e2e}"
CONTEXT="kind-$CLUSTER"
TRUST_DOMAIN="${FERRUM_MESH_E2E_TRUST_DOMAIN:-mesh-e2e.test}"
NS="${FERRUM_NAMESPACE:-ferrum}"
BETA_NS="${FERRUM_MESH_E2E_BETA_NAMESPACE:-beta}"
SPIRE_NS="${FERRUM_SPIRE_NAMESPACE:-spire-system}"
IMAGE_REPOSITORY="${FERRUM_IMAGE_REPOSITORY:-ferrum-edge}"
IMAGE_TAG="${FERRUM_IMAGE_TAG:-mesh-e2e-service-waypoint}"
IMAGE="${IMAGE_REPOSITORY}:${IMAGE_TAG}"
WAYPOINT="swp"
LIVE_ASSERTIONS_FILE="${FERRUM_LIVE_ASSERTIONS_FILE:-$RESULTS_DIR/live-assertions.json}"
LIVE_PLATFORM_PROFILE="${FERRUM_LIVE_PLATFORM_PROFILE:-kind-spire-service-waypoint}"
LIVE_SUITE_NAME="mesh-e2e-service-waypoint"
ALLOW_L7_ABSENT="${FERRUM_SWP_E2E_ALLOW_L7_ABSENT:-0}"

# Status scope the control plane reports once ServiceWaypoint applies mesh
# http[] routes (design spec section 5.2), and the scope it reports before.
L7_PRESENT_SCOPE="sidecar_node_and_service_waypoint"
L7_ABSENT_SCOPE="sidecar_and_node_waypoint"

FRONTEND_HOST="swsvc.$NS.svc.cluster.local"
V1_HOST="swsvc-v1.$NS.svc.cluster.local"
V2_HOST="swsvc-v2.$NS.svc.cluster.local"
XNS_FRONTEND_HOST="swx.$NS.svc.cluster.local"
XSVC_HOST="xsvc.$BETA_NS.svc.cluster.local"
V1_MARKER="sw-backend-v1"
V2_MARKER="sw-backend-v2"
XSVC_MARKER="sw-xsvc-beta"
SPLIT_VS="swsvc-routes"
XNS_VS="swx-xns"
V2_DENY_POLICY="swsvc-v2-deny-flag"
REFERENCE_GRANT="swx-to-xsvc"

# 90/10 split: 1000 inner requests, v1 count in the design's 85%..95% band.
#   X ~ Binomial(1000, 0.9): mean 900, sd 9.49; [850, 950] is +-5.3 sd.
#   P(X < 850) = 2.8e-7, P(X > 950) = 2.8e-9 even under an independent
#   Bernoulli(0.9) model (Ferrum's split upstream is a deterministic smooth
#   weighted round robin). 100/0, 50/50 and a 96/4 drift all fail.
SPLIT_REQUESTS=1000
SPLIT_V1_MIN=850
SPLIT_V1_MAX=950
# x-canary: true must reach swsvc-v2 every time (an ignored rule would follow
# the split: 0.1^100 to pass by chance).
CANARY_REQUESTS=100
# Wall-clock budget for all L7 probes; every in-pod loop and kubectl exec is
# bounded by it, and every request by curl -m.
PROBE_BUDGET_SECS=1500
PROBE_DEADLINE=0

L7_ASSERTIONS=(
  service_waypoint.status.mesh_http_routes_reported
  service_waypoint.virtual_service.weighted_split_90_10
  service_waypoint.virtual_service.header_match_and_per_branch_authz
  service_waypoint.virtual_service.host_spoof_rejected
  service_waypoint.virtual_service.cross_namespace_reference_grant
  service_waypoint.hbone.fence_revocation_on_binding_withdrawal
  service_waypoint.metrics.l7_families_moved
)
REQUIRED_LIVE_ASSERTIONS=(
  service_waypoint.binding.bound_services_projected
  service_waypoint.status.mesh_http_routes_reported
  service_waypoint.virtual_service.weighted_split_90_10
  service_waypoint.virtual_service.header_match_and_per_branch_authz
  service_waypoint.virtual_service.host_spoof_rejected
  service_waypoint.virtual_service.cross_namespace_reference_grant
  service_waypoint.hbone.fence_revocation_on_binding_withdrawal
  service_waypoint.metrics.l7_families_moved
)

LIVE_ASSERTIONS_INITIALIZED=false
L7_STATE="unknown"
L7_ABSENT_REASON=""
SWP_POD_IP=""
CP_DP_JWT_SECRET=""
ADMIN_JWT_SECRET=""
NATIVE_MTLS_DIR=""
# Metric deltas collected by the probes for the metrics row.
METRIC_ACTIVE_MAX=""
METRIC_CLEAN_CLOSE_DELTA=""
METRIC_FENCE_REVOKED_DELTA=""
METRIC_HOST_MISMATCH_DELTA=""
METRIC_HBONE_REVOCATION_DELTA=""

mkdir -p "$ARTIFACT_DIR" "$RESULTS_DIR"

log() {
  printf '\n[mesh-e2e-service-waypoint] %s\n' "$*"
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$1" >&2
    exit 127
  fi
}

preflight() {
  need docker
  need kind
  need kubectl
  need curl
  need python3
  need openssl
  need timeout
  docker info >/dev/null
  if [[ "${FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE:-}" != "true" ]]; then
    echo "Refusing to create/destroy a disposable kind cluster without \
FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE=true" >&2
    exit 1
  fi
}

create_cluster() {
  if kind get clusters | grep -Fxq "$CLUSTER"; then
    log "kind cluster already exists: $CLUSTER"
    return
  fi
  log "creating kind cluster: $CLUSTER"
  kind create cluster --name "$CLUSTER" --wait 180s
}

build_and_load_image() {
  if [[ "${FERRUM_SKIP_IMAGE_BUILD:-0}" != "1" ]]; then
    log "building image $IMAGE"
    docker build -t "$IMAGE" "$ROOT_DIR"
  fi
  log "loading image into $CLUSTER"
  kind load docker-image "$IMAGE" --name "$CLUSTER"
}

# ── live assertions ─────────────────────────────────────────────────────────

init_live_assertions() {
  export FERRUM_LIVE_REPO_ROOT="$ROOT_DIR"
  ferrum_live_assertions_init \
    "$LIVE_ASSERTIONS_FILE" \
    "$LIVE_SUITE_NAME" \
    "$(ferrum_live_git_commit)" \
    "$LIVE_PLATFORM_PROFILE"
  LIVE_ASSERTIONS_INITIALIZED=true
}

record() {
  local assertion_id="$1" status="$2" source="${3:-}" destination="${4:-}"
  local outcome="${5:-}" diagnostics="${6:-}"
  if [[ "$LIVE_ASSERTIONS_INITIALIZED" != "true" ]]; then
    return
  fi
  ferrum_live_record_assertion "$LIVE_ASSERTIONS_FILE" "$assertion_id" "$status" \
    "$source" "$destination" "$outcome" "" "" "" "$diagnostics"
}

# ── secrets and CP/DP transport PKI ─────────────────────────────────────────

ensure_namespaces() {
  local ns
  for ns in "$NS" "$BETA_NS"; do
    kubectl --context "$CONTEXT" create namespace "$ns" \
      --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
  done
}

render_shared_secrets() {
  CP_DP_JWT_SECRET="$(openssl rand -hex 32)"
  ADMIN_JWT_SECRET="$(openssl rand -hex 32)"
  local ns
  for ns in "$NS" "$BETA_NS"; do
    kubectl --context "$CONTEXT" -n "$ns" create secret generic ferrum-mesh-e2e-secrets \
      --from-literal=cp-dp-grpc-jwt-secret="$CP_DP_JWT_SECRET" \
      --from-literal=admin-jwt-secret="$ADMIN_JWT_SECRET" \
      --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
  done
}

# HS256 admin bearer (all six required claims plus `role`, not
# namespace-bounded, so it is also authenticated for /metrics).
mint_admin_jwt() {
  python3 - "$ADMIN_JWT_SECRET" "ferrum-edge" <<'PY'
import base64
import hashlib
import hmac
import json
import sys
import time
import uuid

secret, issuer = sys.argv[1], sys.argv[2]
now = int(time.time())

def b64url(value):
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header = {"alg": "HS256", "typ": "JWT"}
claims = {
    "iss": issuer,
    "sub": "mesh-e2e-service-waypoint",
    "iat": now,
    "nbf": now - 1,
    "exp": now + 900,
    "jti": str(uuid.uuid4()),
    "role": "admin",
}
signing_input = f"{b64url(header)}.{b64url(claims)}"
signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
print(f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}")
PY
}

native_mtls_cleanup() {
  if [[ -n "${NATIVE_MTLS_DIR:-}" && -d "$NATIVE_MTLS_DIR" ]]; then
    find "$NATIVE_MTLS_DIR" -type f -exec rm -f {} + 2>/dev/null || true
    rm -rf "$NATIVE_MTLS_DIR" 2>/dev/null || true
  fi
}

# Ephemeral CP/DP gRPC PKI (production mTLS + JWT, as in mesh-e2e-sidecar):
# the CP server certificate SAN is the Service DNS name the DPs dial, the CP
# requires a DP client certificate, and JWT stays required on the stream.
# Controller-host copies live only in a private temp dir removed on EXIT.
mint_native_mtls_pki() {
  local cp_dns="ferrum-cp.$NS.svc.cluster.local"
  NATIVE_MTLS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ferrum-swp-mtls.XXXXXX")"
  chmod 700 "$NATIVE_MTLS_DIR"
  log "minting ephemeral CP/DP gRPC PKI (SAN=$cp_dns)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ferrum-swp-e2e-ca \
    -keyout "$NATIVE_MTLS_DIR/ca-key.pem" -out "$NATIVE_MTLS_DIR/ca.pem" >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ferrum-swp-e2e-client-ca \
    -keyout "$NATIVE_MTLS_DIR/client-ca-key.pem" -out "$NATIVE_MTLS_DIR/client-ca.pem" \
    >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$cp_dns" \
    > "$NATIVE_MTLS_DIR/server.ext"
  printf 'extendedKeyUsage=clientAuth\n' > "$NATIVE_MTLS_DIR/client.ext"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$cp_dns" \
    -keyout "$NATIVE_MTLS_DIR/server-key.pem" -out "$NATIVE_MTLS_DIR/server.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 -in "$NATIVE_MTLS_DIR/server.csr" \
    -CA "$NATIVE_MTLS_DIR/ca.pem" -CAkey "$NATIVE_MTLS_DIR/ca-key.pem" -CAcreateserial \
    -extfile "$NATIVE_MTLS_DIR/server.ext" -out "$NATIVE_MTLS_DIR/server.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj /CN=ferrum-swp-e2e-dp \
    -keyout "$NATIVE_MTLS_DIR/client-key.pem" -out "$NATIVE_MTLS_DIR/client.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 -in "$NATIVE_MTLS_DIR/client.csr" \
    -CA "$NATIVE_MTLS_DIR/client-ca.pem" -CAkey "$NATIVE_MTLS_DIR/client-ca-key.pem" \
    -CAcreateserial -extfile "$NATIVE_MTLS_DIR/client.ext" \
    -out "$NATIVE_MTLS_DIR/client.pem" >/dev/null 2>&1
  rm -f "$NATIVE_MTLS_DIR"/*.csr
}

apply_native_mtls_secrets() {
  kubectl --context "$CONTEXT" -n "$NS" create secret generic ferrum-native-mtls-cp \
    --from-file=server.pem="$NATIVE_MTLS_DIR/server.pem" \
    --from-file=server-key.pem="$NATIVE_MTLS_DIR/server-key.pem" \
    --from-file=client-ca.pem="$NATIVE_MTLS_DIR/client-ca.pem" \
    --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
  local ns
  for ns in "$NS" "$BETA_NS"; do
    kubectl --context "$CONTEXT" -n "$ns" create secret generic ferrum-native-mtls-dp \
      --from-file=ca.pem="$NATIVE_MTLS_DIR/ca.pem" \
      --from-file=client.pem="$NATIVE_MTLS_DIR/client.pem" \
      --from-file=client-key.pem="$NATIVE_MTLS_DIR/client-key.pem" \
      --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
  done
}

# ── CRDs, SPIRE, workloads ──────────────────────────────────────────────────

# Pinned offline CRDs (tests/fixtures/k8s/), Established before ferrum-cp
# starts so its first discovery pass starts every watcher.
SUITE_CRD_FIXTURES=(
  istio_virtualservice_crd:virtualservices.networking.istio.io
  istio_authorizationpolicy_status_crd:authorizationpolicies.security.istio.io
  gateway_api_gateway_crd:gateways.gateway.networking.k8s.io
  gateway_api_referencegrant_crd:referencegrants.gateway.networking.k8s.io
)

install_crds() {
  log "installing pinned VirtualService, AuthorizationPolicy, Gateway and ReferenceGrant CRDs"
  local entry fixture crd
  local -a crds=()
  for entry in "${SUITE_CRD_FIXTURES[@]}"; do
    fixture="${entry%%:*}"
    crd="${entry#*:}"
    kubectl --context "$CONTEXT" apply -f "$ROOT_DIR/tests/fixtures/k8s/$fixture.yaml"
    crds+=("crd/$crd")
  done
  kubectl --context "$CONTEXT" wait --for=condition=Established "${crds[@]}" --timeout=60s
}

install_spire() {
  log "installing SPIRE in $CONTEXT ($TRUST_DOMAIN)"
  ferrum_spire_apply_minimal "$CONTEXT" "$TRUST_DOMAIN" "$SPIRE_NS"
  ferrum_spire_wait_ready "$CONTEXT" "$SPIRE_NS" 5m
}

# Entries are registered BEFORE the workloads exist so the hbone-client init
# container's one-shot SVID fetch succeeds on its first attempt.
register_spire_workloads() {
  log "registering SPIRE workload entries"
  local -a spire_nodes
  mapfile -t spire_nodes < <(ferrum_spire_agent_nodes "$CONTEXT" "$SPIRE_NS")
  if [[ "${#spire_nodes[@]}" -eq 0 ]]; then
    echo "no attested SPIRE agent node in $CONTEXT" >&2
    return 1
  fi
  local node parent_id entry ns sa
  for node in "${spire_nodes[@]}"; do
    parent_id="$(ferrum_spire_k8s_psat_agent_parent_id_for_node \
      "$CONTEXT" "$SPIRE_NS" "$TRUST_DOMAIN" "$node")"
    for entry in "$NS:$WAYPOINT" "$NS:hbone-client" "$NS:swsvc-v1" "$NS:swsvc-v2" \
      "$BETA_NS:xsvc"; do
      ns="${entry%%:*}"
      sa="${entry#*:}"
      ferrum_spire_register_k8s_workload \
        "$CONTEXT" "$SPIRE_NS" \
        "spiffe://$TRUST_DOMAIN/ns/$ns/sa/$sa" \
        "$parent_id" "$ns" "$sa" \
        "k8s:node-name:$node"
    done
  done
  ferrum_spire_server_exec "$CONTEXT" "$SPIRE_NS" entry show \
    > "$RESULTS_DIR/spire-entries.txt" 2>&1 || true
}

apply_workloads() {
  log "applying workloads"
  awk -v ns="$NS" -v beta="$BETA_NS" -v td="$TRUST_DOMAIN" -v image="$IMAGE" \
    -v spire_agent="$FERRUM_SPIRE_AGENT_IMAGE" -v waypoint="$WAYPOINT" '
    {
      gsub(/__BETA_NAMESPACE__/, beta)
      gsub(/__NAMESPACE__/, ns)
      gsub(/__TRUST_DOMAIN__/, td)
      gsub(/__IMAGE__/, image)
      gsub(/__SPIRE_AGENT_IMAGE__/, spire_agent)
      gsub(/__WAYPOINT__/, waypoint)
      print
    }
  ' "$MANIFESTS" | kubectl --context "$CONTEXT" apply -f -
}

wait_for_rollouts() {
  local entry ns deploy
  for entry in "$NS:ferrum-cp" "$NS:$WAYPOINT" "$NS:swsvc-v1" "$NS:swsvc-v2" \
    "$BETA_NS:xsvc" "$NS:hbone-client"; do
    ns="${entry%%:*}"
    deploy="${entry#*:}"
    kubectl --context "$CONTEXT" -n "$ns" rollout status "deploy/$deploy" --timeout=5m
  done
}

wait_for_pod_ip() {
  local app_label="$1" ip="" _
  for _ in $(seq 1 60); do
    ip="$(kubectl --context "$CONTEXT" -n "$NS" get pod -l "app=$app_label" -o json 2>/dev/null |
      python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for pod in data.get("items", []):
    if pod.get("metadata", {}).get("deletionTimestamp"):
        continue
    status = pod.get("status", {})
    ready = any(
        c.get("type") == "Ready" and c.get("status") == "True"
        for c in status.get("conditions", [])
    )
    if status.get("phase") == "Running" and ready and status.get("podIP"):
        print(status["podIP"])
        break
' 2>/dev/null || true)"
    if [[ -n "$ip" ]]; then
      printf '%s' "$ip"
      return 0
    fi
    sleep 2
  done
  echo "$app_label pod never reported a ready pod IP" >&2
  return 1
}

# ── admin and metrics helpers (waypoint admin binds loopback) ───────────────

waypoint_admin_get() {
  local path="$1" token
  token="$(mint_admin_jwt)"
  # shellcheck disable=SC2016
  timeout 30 kubectl --context "$CONTEXT" -n "$NS" exec "deploy/$WAYPOINT" -c curl -- \
    sh -c 'curl -s -m 10 -H "Authorization: Bearer $1" "http://127.0.0.1:15020$2"' \
    sh "$token" "$path" 2>/dev/null || true
}

# Sum every sample of a Prometheus family, optionally filtered by one
# `reason` label value. Prints 0 when the family is absent.
metric_sum() {
  local family="$1" reason="${2:-}"
  waypoint_admin_get /metrics | python3 -c '
import re
import sys

family, reason = sys.argv[1], sys.argv[2]
total = 0.0
pattern = re.compile(r"^" + re.escape(family) + r"(\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)")
for line in sys.stdin:
    match = pattern.match(line)
    if not match:
        continue
    labels = match.group("labels") or ""
    if reason and ("reason=\"" + reason + "\"") not in labels:
        continue
    try:
        total += float(match.group("value"))
    except ValueError:
        pass
print(int(total))
' "$family" "$reason"
}

delta() {
  local before="$1" after="$2"
  if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]]; then
    printf '%s' "$(( after - before ))"
  else
    printf 'unknown'
  fi
}

remaining() {
  local left
  left=$(( PROBE_DEADLINE - $(date +%s) ))
  (( left < 0 )) && left=0
  printf '%s' "$left"
}

# ── HBONE client ────────────────────────────────────────────────────────────
#
# One inner request through a fresh authenticated HTTP/2 CONNECT tunnel to the
# waypoint's :15008. curl opens the tunnel to the URL's host:port (the bound
# Service host authority the waypoint classifies), presents the pod's SPIRE
# SVID as the proxy client certificate, and sends the inner HTTP/1.1 request
# through it. The waypoint's server certificate is its own SPIFFE SVID (URI SAN
# only), which curl cannot hostname-verify, so the client skips proxy server
# verification; the assertions are about what the waypoint admits and routes.
# Echoes "<curl exit>\t<status>\t<body>".
hbone_request() {
  local url="$1" header="${2:-}" host_override="${3:-}" max_time="${4:-10}"
  # shellcheck disable=SC2016
  timeout "$(( max_time + 20 ))" kubectl --context "$CONTEXT" -n "$NS" exec deploy/hbone-client -c curl -- \
    sh -c '
      url="$1"; header="$2"; host="$3"; proxy="$4"; max="$5"
      : >/tmp/hb 2>/dev/null || true
      set -- -sS -m "$max" -o /tmp/hb -w "%{http_code}" \
        --proxy "$proxy" --proxy-http2 --proxytunnel \
        --proxy-cert /svid/svid.0.pem --proxy-key /svid/svid.0.key --proxy-insecure \
        --proxy-header "x-ferrum-mesh-protocol: hbone"
      [ -n "$header" ] && set -- "$@" -H "$header"
      [ -n "$host" ] && set -- "$@" -H "Host: $host"
      rc=0
      code="$(curl "$@" "$url" 2>/tmp/hb.err)" || rc=$?
      [ -n "$code" ] || code=000
      body="$(tr -d "\r\n\t" </tmp/hb 2>/dev/null | cut -c1-160)"
      printf "%s\t%s\t%s\n" "$rc" "$code" "$body"
    ' sh "$url" "$header" "$host_override" "https://$SWP_POD_IP:15008" "$max_time" \
    2>/dev/null || printf 'EXECFAIL\t000\t\n'
}

field() {
  printf '%s' "$1" | cut -f"$2"
}

# Retry until a request answers 200 with one of the accepted bodies ("a|b").
settle() {
  local url="$1" header="$2" accept="$3" out rc code body
  out="EXECFAIL\t000\t"
  while (( $(remaining) > 0 )); do
    out="$(hbone_request "$url" "$header")"
    rc="$(field "$out" 1)"
    code="$(field "$out" 2)"
    body="$(field "$out" 3)"
    if [[ "$rc" == "0" && "$code" == "200" ]]; then
      case "|$accept|" in
        *"|$body|"*) break ;;
      esac
    fi
    sleep 2
  done
  printf '%s' "$out"
}

# Up to N sequential inner requests, each over its own HBONE tunnel, classified
# by curl exit + status + exact body ("1" = v1 marker, "2" = v2 marker, "x" =
# anything else). Stops as soon as the sample can no longer pass or at the
# budget deadline. Echoes
# "<v1>\t<v2>\t<other>\t<issued>\t<stop>\t<first other>\t<sequence>".
sample() {
  local url="$1" n="$2" header="$3" v1_min="$4" v1_max="$5" budget
  budget="$(remaining)"
  (( budget > 0 )) || { printf '0\t0\t0\t0\tdeadline\t\t\n'; return 0; }
  # shellcheck disable=SC2016
  timeout "$(( budget + 20 ))" kubectl --context "$CONTEXT" -n "$NS" exec deploy/hbone-client -c curl -- \
    sh -c '
      url="$1"; n="$2"; header="$3"; m1="$4"; m2="$5"; v1min="$6"; v1max="$7"
      proxy="$8"; budget="$9"
      end=$(( $(date +%s) + budget ))
      v1=0; v2=0; other=0; i=0; stop=complete; first=""; sequence=""
      while [ "$i" -lt "$n" ]; do
        if [ "$(date +%s)" -ge "$end" ]; then stop=deadline; break; fi
        i=$((i + 1))
        : >/tmp/hs 2>/dev/null || true
        rc=0
        if [ -n "$header" ]; then
          code="$(curl -s -m 10 -o /tmp/hs -w "%{http_code}" --proxy "$proxy" --proxy-http2 \
            --proxytunnel --proxy-cert /svid/svid.0.pem --proxy-key /svid/svid.0.key \
            --proxy-insecure --proxy-header "x-ferrum-mesh-protocol: hbone" \
            -H "$header" "$url" 2>/dev/null)" || rc=$?
        else
          code="$(curl -s -m 10 -o /tmp/hs -w "%{http_code}" --proxy "$proxy" --proxy-http2 \
            --proxytunnel --proxy-cert /svid/svid.0.pem --proxy-key /svid/svid.0.key \
            --proxy-insecure --proxy-header "x-ferrum-mesh-protocol: hbone" \
            "$url" 2>/dev/null)" || rc=$?
        fi
        [ -n "$code" ] || code=000
        body="$(tr -d "\r\n\t" </tmp/hs 2>/dev/null || true)"
        if [ "$rc" = "0" ] && [ "$code" = "200" ] && [ "$body" = "$m1" ]; then
          v1=$((v1 + 1)); sequence="${sequence}1"
        elif [ "$rc" = "0" ] && [ "$code" = "200" ] && [ "$body" = "$m2" ]; then
          v2=$((v2 + 1)); sequence="${sequence}2"
        else
          other=$((other + 1)); sequence="${sequence}x"
          first="rc=$rc:$code:$(printf "%s" "$body" | cut -c1-120)"
          stop=unexpected-response; break
        fi
        if [ "$v1" -gt "$v1max" ]; then stop=v1-above-max; break; fi
        if [ "$v2" -gt $((n - v1min)) ]; then stop=v2-above-max; break; fi
      done
      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$v1" "$v2" "$other" "$i" "$stop" "$first" "$sequence"
    ' sh "$url" "$n" "$header" "$V1_MARKER" "$V2_MARKER" "$v1_min" "$v1_max" \
    "https://$SWP_POD_IP:15008" "$budget" \
    2>/dev/null || printf '0\t0\t0\t0\texec-failed\t\t\n'
}

sample_passes() {
  local out="$1" n="$2" v1_min="$3" v1_max="$4" v1 v2 other issued stop
  v1="$(field "$out" 1)"
  v2="$(field "$out" 2)"
  other="$(field "$out" 3)"
  issued="$(field "$out" 4)"
  stop="$(field "$out" 5)"
  [[ "$stop" == "complete" && "$issued" == "$n" && "$other" == "0" \
    && "$v1" =~ ^[0-9]+$ && "$v2" =~ ^[0-9]+$ ]] \
    && (( v1 + v2 == n && v1 >= v1_min && v1 <= v1_max ))
}

summary_of() {
  local out="$1"
  printf 'v1=%s v2=%s other=%s issued=%s stop=%s first_other=%s' \
    "$(field "$out" 1)" "$(field "$out" 2)" "$(field "$out" 3)" \
    "$(field "$out" 4)" "$(field "$out" 5)" "$(field "$out" 6)"
}

# ── Kubernetes objects the probes apply ─────────────────────────────────────
# (No backticks in these heredocs: they interpolate.)

apply_split_virtual_service() {
  kubectl --context "$CONTEXT" --request-timeout=60s apply -f - <<YAML
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: $SPLIT_VS
  namespace: $NS
spec:
  hosts:
    - $FRONTEND_HOST
  http:
    - match:
        - headers:
            x-canary:
              exact: "true"
      route:
        - destination:
            host: $V2_HOST
            port:
              number: 8080
    - match:
        - headers:
            x-stable:
              exact: "true"
      route:
        - destination:
            host: $V1_HOST
            port:
              number: 8080
    - route:
        - destination:
            host: $V1_HOST
            port:
              number: 8080
          weight: 90
        - destination:
            host: $V2_HOST
            port:
              number: 8080
          weight: 10
YAML
}

# swsvc-v2's own policy: DENY requests carrying x-deny: true. swsvc-v1 has no
# policy, so the same header on the v1 branch must still be served.
apply_v2_authorization_policy() {
  kubectl --context "$CONTEXT" --request-timeout=60s apply -f - <<YAML
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: $V2_DENY_POLICY
  namespace: $NS
spec:
  targetRefs:
    - kind: Service
      group: ""
      name: swsvc-v2
  action: DENY
  rules:
    - when:
        - key: request.headers[x-deny]
          values: ["true"]
YAML
}

apply_cross_namespace_virtual_service() {
  kubectl --context "$CONTEXT" --request-timeout=60s apply -f - <<YAML
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: $XNS_VS
  namespace: $NS
spec:
  hosts:
    - $XNS_FRONTEND_HOST
  http:
    - route:
        - destination:
            host: $XSVC_HOST
            port:
              number: 8080
YAML
}

apply_reference_grant() {
  kubectl --context "$CONTEXT" --request-timeout=60s apply -f - <<YAML
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: $REFERENCE_GRANT
  namespace: $BETA_NS
spec:
  from:
    - group: networking.istio.io
      kind: VirtualService
      namespace: $NS
  to:
    - group: ""
      kind: Service
      name: xsvc
YAML
}

# Poll one VirtualService's status until `want` holds: "accepted" (True) or
# "rejected" (False). Echoes "<True|False|missing> <reason> <mesh_http_routes>".
vs_status_until() {
  local name="$1" want="$2" json verdict _
  verdict="missing - -"
  for _ in $(seq 1 60); do
    (( $(remaining) > 0 )) || break
    json="$(timeout 20 kubectl --context "$CONTEXT" -n "$NS" get \
      "virtualservices.networking.istio.io/$name" -o json 2>/dev/null || true)"
    printf '%s\n' "$json" > "$RESULTS_DIR/vs-$name-status.txt"
    verdict="$(printf '%s' "$json" | python3 -c '
import json
import sys

try:
    status = (json.load(sys.stdin).get("status") or {})
except Exception:
    print("missing - -")
    sys.exit(0)
conditions = [c for c in status.get("conditions") or [] if c.get("type") == "FerrumAccepted"]
scope = ((status.get("ferrum") or {}).get("translation") or {}).get("mesh_http_routes") or "-"
if not conditions:
    print("missing - %s" % scope)
else:
    print("%s %s %s" % (conditions[0].get("status"), conditions[0].get("reason") or "-", scope))
')"
    case "$want:${verdict%% *}" in
      accepted:True|rejected:False) break ;;
    esac
    sleep 2
  done
  printf '%s' "$verdict"
}

# ── probes ──────────────────────────────────────────────────────────────────

probe_binding() {
  log "checking the waypoint's bound-Service projection"
  local json verdict _
  verdict="no-response"
  for _ in $(seq 1 60); do
    json="$(waypoint_admin_get /service-waypoint/services)"
    printf '%s\n' "$json" > "$RESULTS_DIR/service-waypoint-services.txt"
    verdict="$(printf '%s' "$json" | python3 -c '
import json
import sys

ns, waypoint = sys.argv[1], sys.argv[2]
try:
    doc = json.load(sys.stdin)
except Exception:
    print("unparseable")
    sys.exit(0)
names = sorted(
    s.get("name") for s in doc.get("services") or [] if s.get("namespace") == ns
)
want = sorted(["swsvc", "swsvc-v1", "swsvc-v2", "swx"])
if doc.get("waypoint_name") == waypoint and names == want:
    print("bound " + ",".join(names))
else:
    print("unexpected waypoint=%s services=%s" % (doc.get("waypoint_name"), ",".join(names)))
' "$NS" "$WAYPOINT")"
    [[ "$verdict" == bound* ]] && break
    sleep 2
  done
  log "binding: $verdict"
  if [[ "$verdict" == bound* ]]; then
    record service_waypoint.binding.bound_services_projected pass "$WAYPOINT" "" \
      "$verdict" service-waypoint-services.txt
  else
    record service_waypoint.binding.bound_services_projected fail "$WAYPOINT" "" \
      "$verdict" service-waypoint-services.txt
    return 1
  fi
}

# Applies the split VirtualService and v2 policy, then decides whether this
# build's ServiceWaypoint applies mesh http[] routes at all.
probe_status_and_detect_l7() {
  log "applying the split VirtualService and swsvc-v2 AuthorizationPolicy"
  if ! apply_v2_authorization_policy >"$RESULTS_DIR/apply-policy.txt" 2>&1 \
    || ! apply_split_virtual_service >"$RESULTS_DIR/apply-split-vs.txt" 2>&1; then
    L7_STATE="error"
    L7_ABSENT_REASON="apply-failed"
    record service_waypoint.status.mesh_http_routes_reported fail "$SPLIT_VS" "" \
      "apply-failed" apply-split-vs.txt
    return 0
  fi
  local verdict accepted reason scope
  verdict="$(vs_status_until "$SPLIT_VS" accepted)"
  accepted="${verdict%% *}"
  scope="${verdict##* }"
  reason="${verdict#* }"
  reason="${reason%% *}"
  log "split VirtualService status: FerrumAccepted=$accepted reason=$reason mesh_http_routes=$scope"
  if [[ "$accepted" == "True" && "$scope" == "$L7_PRESENT_SCOPE" ]]; then
    L7_STATE="present"
    record service_waypoint.status.mesh_http_routes_reported pass "$SPLIT_VS" "" \
      "FerrumAccepted=True reason=$reason mesh_http_routes=$scope" "vs-$SPLIT_VS-status.txt"
  elif [[ "$accepted" == "True" && "$scope" == "$L7_ABSENT_SCOPE" ]]; then
    L7_STATE="absent"
    L7_ABSENT_REASON="service_waypoint_l7_not_present: control plane reports mesh_http_routes=$scope"
  else
    L7_STATE="error"
    L7_ABSENT_REASON="unexpected status FerrumAccepted=$accepted reason=$reason mesh_http_routes=$scope"
    record service_waypoint.status.mesh_http_routes_reported fail "$SPLIT_VS" "" \
      "$L7_ABSENT_REASON" "vs-$SPLIT_VS-status.txt"
  fi
}

probe_weighted_split() {
  log "probing the 90/10 split over HBONE ($SPLIT_REQUESTS inner requests)"
  local url="http://$FRONTEND_HOST:8080/" settled clean_before clean_after out
  settled="$(settle "$url" "" "$V1_MARKER|$V2_MARKER")"
  printf 'settle: %s\n' "$settled" > "$RESULTS_DIR/swp-split.txt"
  clean_before="$(metric_sum ferrum_mesh_service_waypoint_l7_tunnel_terminations_total clean_close)"
  out="$(sample "$url" "$SPLIT_REQUESTS" "" "$SPLIT_V1_MIN" "$SPLIT_V1_MAX")"
  clean_after="$(metric_sum ferrum_mesh_service_waypoint_l7_tunnel_terminations_total clean_close)"
  METRIC_CLEAN_CLOSE_DELTA="$(delta "$clean_before" "$clean_after")"
  printf 'split %s\nsequence: %s\nclean_close delta: %s\n' "$(summary_of "$out")" \
    "$(field "$out" 7)" "$METRIC_CLEAN_CLOSE_DELTA" >> "$RESULTS_DIR/swp-split.txt"
  log "split: $(summary_of "$out") (accept v1 in [$SPLIT_V1_MIN,$SPLIT_V1_MAX])"
  if sample_passes "$out" "$SPLIT_REQUESTS" "$SPLIT_V1_MIN" "$SPLIT_V1_MAX"; then
    record service_waypoint.virtual_service.weighted_split_90_10 pass hbone-client \
      "swsvc-v1+swsvc-v2" "n=$SPLIT_REQUESTS $(summary_of "$out")" swp-split.txt
  else
    record service_waypoint.virtual_service.weighted_split_90_10 fail hbone-client \
      "swsvc-v1+swsvc-v2" "n=$SPLIT_REQUESTS $(summary_of "$out")" swp-split.txt
  fi
}

# Count non-reevaluation waypoint policy denies attributed to swsvc-v2's
# policy (the `rule` names the AuthorizationPolicy).
v2_policy_deny_count() {
  waypoint_admin_get "/mesh/policy-denies/recent?limit=200" | python3 -c '
import json
import sys

policy = sys.argv[1]
try:
    doc = json.load(sys.stdin)
except Exception:
    print(0)
    sys.exit(0)
total = 0
for group in doc.get("grouped") or []:
    if group.get("reevaluation"):
        continue
    if policy in (group.get("rule") or ""):
        total += int(group.get("count") or 0)
print(total)
' "$V2_DENY_POLICY"
}

probe_header_and_branch_authz() {
  log "probing header-match dispatch and per-branch AuthorizationPolicy"
  local url="http://$FRONTEND_HOST:8080/" canary deny_before deny_after denied stable ok=true
  local diagnostics="$RESULTS_DIR/swp-header-authz.txt"
  canary="$(sample "$url" "$CANARY_REQUESTS" "x-canary: true" 0 0)"
  printf 'canary %s\n' "$(summary_of "$canary")" > "$diagnostics"
  sample_passes "$canary" "$CANARY_REQUESTS" 0 0 || ok=false

  deny_before="$(v2_policy_deny_count)"
  # A second header rides as the inner request's own header line.
  # shellcheck disable=SC2016
  denied="$(timeout 40 kubectl --context "$CONTEXT" -n "$NS" exec deploy/hbone-client -c curl -- \
    sh -c '
      : >/tmp/hd
      rc=0
      code="$(curl -sS -m 10 -o /tmp/hd -w "%{http_code}" --proxy "$2" --proxy-http2 --proxytunnel \
        --proxy-cert /svid/svid.0.pem --proxy-key /svid/svid.0.key --proxy-insecure \
        --proxy-header "x-ferrum-mesh-protocol: hbone" \
        -H "x-canary: true" -H "x-deny: true" "$1" 2>/dev/null)" || rc=$?
      printf "%s\t%s\t%s\n" "$rc" "${code:-000}" "$(tr -d "\r\n\t" </tmp/hd | cut -c1-160)"
    ' sh "$url" "https://$SWP_POD_IP:15008" 2>/dev/null || printf 'EXECFAIL\t000\t\n')"
  deny_after="$(v2_policy_deny_count)"
  # shellcheck disable=SC2016
  stable="$(timeout 40 kubectl --context "$CONTEXT" -n "$NS" exec deploy/hbone-client -c curl -- \
    sh -c '
      : >/tmp/hv
      rc=0
      code="$(curl -sS -m 10 -o /tmp/hv -w "%{http_code}" --proxy "$2" --proxy-http2 --proxytunnel \
        --proxy-cert /svid/svid.0.pem --proxy-key /svid/svid.0.key --proxy-insecure \
        --proxy-header "x-ferrum-mesh-protocol: hbone" \
        -H "x-stable: true" -H "x-deny: true" "$1" 2>/dev/null)" || rc=$?
      printf "%s\t%s\t%s\n" "$rc" "${code:-000}" "$(tr -d "\r\n\t" </tmp/hv | cut -c1-160)"
    ' sh "$url" "https://$SWP_POD_IP:15008" 2>/dev/null || printf 'EXECFAIL\t000\t\n')"
  printf 'v2 branch + x-deny: %s\nv2 policy denies before/after: %s/%s\nv1 branch + x-deny: %s\n' \
    "$denied" "$deny_before" "$deny_after" "$stable" >> "$diagnostics"
  log "header/authz: canary $(summary_of "$canary"); v2+deny=${denied//$'\t'/ } (denies $deny_before->$deny_after); v1+deny=${stable//$'\t'/ }"

  local denied_code denied_body stable_rc stable_code stable_body deny_delta
  denied_code="$(field "$denied" 2)"
  denied_body="$(field "$denied" 3)"
  stable_rc="$(field "$stable" 1)"
  stable_code="$(field "$stable" 2)"
  stable_body="$(field "$stable" 3)"
  deny_delta="$(delta "$deny_before" "$deny_after")"
  [[ "$denied_code" == "403" && "$denied_body" != "$V2_MARKER" ]] || ok=false
  [[ "$deny_delta" =~ ^[0-9]+$ ]] && (( deny_delta >= 1 )) || ok=false
  [[ "$stable_rc" == "0" && "$stable_code" == "200" && "$stable_body" == "$V1_MARKER" ]] || ok=false

  local outcome canary_summary
  canary_summary="$(summary_of "$canary")"
  outcome="canary $canary_summary; v2+deny=$denied_code waypoint-denies+$deny_delta; v1+deny=$stable_code/$stable_body"
  if [[ "$ok" == "true" ]]; then
    record service_waypoint.virtual_service.header_match_and_per_branch_authz pass \
      hbone-client swsvc-v2 "$outcome" swp-header-authz.txt
  else
    record service_waypoint.virtual_service.header_match_and_per_branch_authz fail \
      hbone-client swsvc-v2 "$outcome" swp-header-authz.txt
  fi
}

probe_host_spoof() {
  log "probing inner Host spoofing (CONNECT to swsvc, inner Host swsvc-v2)"
  local before after out spoof_delta
  before="$(metric_sum ferrum_mesh_service_waypoint_route_refusals_total host_mismatch)"
  out="$(hbone_request "http://$FRONTEND_HOST:8080/" "" "$V2_HOST:8080" 10)"
  after="$(metric_sum ferrum_mesh_service_waypoint_route_refusals_total host_mismatch)"
  spoof_delta="$(delta "$before" "$after")"
  METRIC_HOST_MISMATCH_DELTA="$spoof_delta"
  printf 'spoof: %s\nhost_mismatch refusals before/after: %s/%s\n' "$out" "$before" "$after" \
    > "$RESULTS_DIR/swp-host-spoof.txt"
  log "host spoof: ${out//$'\t'/ } (host_mismatch $before->$after)"
  local code body
  code="$(field "$out" 2)"
  body="$(field "$out" 3)"
  if [[ "$code" == "403" && "$body" != "$V1_MARKER" && "$body" != "$V2_MARKER" ]]; then
    record service_waypoint.virtual_service.host_spoof_rejected pass hbone-client swsvc \
      "status=403 no-backend host_mismatch+$spoof_delta" swp-host-spoof.txt
  else
    record service_waypoint.virtual_service.host_spoof_rejected fail hbone-client swsvc \
      "status=$code body=$body host_mismatch+$spoof_delta" swp-host-spoof.txt
  fi
}

# Cross-namespace destination: refused without a ReferenceGrant, admitted with
# one, withdrawn after it is deleted. "Reached" means a completed 200 with the
# beta backend's marker through the swx frontend.
xns_reached() {
  local out rc code body
  out="$(hbone_request "http://$XNS_FRONTEND_HOST:8080/" "" "" 10)"
  rc="$(field "$out" 1)"
  code="$(field "$out" 2)"
  body="$(field "$out" 3)"
  [[ "$rc" == "0" && "$code" == "200" && "$body" == "$XSVC_MARKER" ]]
}

# Retry until the reachability equals `want` (reached|unreached).
xns_until() {
  local want="$1" now
  while (( $(remaining) > 0 )); do
    now=unreached
    xns_reached && now=reached
    [[ "$now" == "$want" ]] && { printf '%s' "$now"; return 0; }
    sleep 2
  done
  printf '%s' "${now:-unreached}"
}

probe_cross_namespace() {
  log "probing the cross-namespace destination and its ReferenceGrant"
  local diagnostics="$RESULTS_DIR/swp-cross-namespace.txt" ok=true s1 s2 s3 r1 r2 r3
  kubectl --context "$CONTEXT" -n "$BETA_NS" delete referencegrant "$REFERENCE_GRANT" \
    --ignore-not-found >/dev/null 2>&1 || true
  apply_cross_namespace_virtual_service > "$diagnostics" 2>&1 || ok=false

  s1="$(vs_status_until "$XNS_VS" rejected)"
  # Rejected + never reached: sample a few times after the status settled.
  r1=unreached
  local _
  for _ in 1 2 3 4 5; do xns_reached && r1=reached; done
  printf 'phase1 (no grant): status=%s reach=%s\n' "$s1" "$r1" >> "$diagnostics"
  [[ "${s1%% *}" == "False" && "$s1" == *" RefNotPermitted "* && "$r1" == "unreached" ]] || ok=false

  apply_reference_grant >> "$diagnostics" 2>&1 || ok=false
  s2="$(vs_status_until "$XNS_VS" accepted)"
  r2="$(xns_until reached)"
  printf 'phase2 (grant applied): status=%s reach=%s\n' "$s2" "$r2" >> "$diagnostics"
  [[ "${s2%% *}" == "True" && "$r2" == "reached" ]] || ok=false

  kubectl --context "$CONTEXT" -n "$BETA_NS" delete referencegrant "$REFERENCE_GRANT" \
    >> "$diagnostics" 2>&1 || ok=false
  s3="$(vs_status_until "$XNS_VS" rejected)"
  r3="$(xns_until unreached)"
  printf 'phase3 (grant deleted): status=%s reach=%s\n' "$s3" "$r3" >> "$diagnostics"
  [[ "${s3%% *}" == "False" && "$r3" == "unreached" ]] || ok=false

  log "cross-namespace: no-grant=[$s1/$r1] grant=[$s2/$r2] deleted=[$s3/$r3]"
  if [[ "$ok" == "true" ]]; then
    record service_waypoint.virtual_service.cross_namespace_reference_grant pass \
      hbone-client "xsvc.$BETA_NS" "refused->admitted->withdrawn" swp-cross-namespace.txt
  else
    record service_waypoint.virtual_service.cross_namespace_reference_grant fail \
      hbone-client "xsvc.$BETA_NS" \
      "no-grant=[$s1/$r1] grant=[$s2/$r2] deleted=[$s3/$r3]" swp-cross-namespace.txt
  fi
}

# Holds one inner GET /slow on swsvc-v1 (backend answers after 90 s) over an L7
# tunnel, removes istio.io/use-waypoint from swsvc-v1, and requires the tunnel
# to be cut with RST_STREAM(CONNECT_ERROR) well before the backend answers.
probe_fence_revocation() {
  log "probing fence revocation on binding withdrawal"
  local diagnostics="$RESULTS_DIR/swp-fence-revocation.txt"
  local revoke_before revoke_after fence_before fence_after active=0 sample_active _
  revoke_before="$(metric_sum ferrum_mesh_hbone_tunnel_revocations_total)"
  fence_before="$(metric_sum ferrum_mesh_service_waypoint_l7_tunnel_terminations_total fence_revoked)"

  # shellcheck disable=SC2016
  timeout 150 kubectl --context "$CONTEXT" -n "$NS" exec deploy/hbone-client -c curl -- \
    sh -c '
      rc=0
      curl -sS -v -m 120 -o /tmp/held.body --proxy "$2" --proxy-http2 --proxytunnel \
        --proxy-cert /svid/svid.0.pem --proxy-key /svid/svid.0.key --proxy-insecure \
        --proxy-header "x-ferrum-mesh-protocol: hbone" "$1" 2>/tmp/held.err || rc=$?
      printf "rc=%s\n" "$rc"
      grep -i -E "CONNECT_ERROR|err 10|reset|stream" /tmp/held.err | tail -n 5
    ' sh "http://$V1_HOST:8080/slow" "https://$SWP_POD_IP:15008" \
    > "$RESULTS_DIR/held-request.txt" 2>&1 &
  local held_pid=$!

  for _ in $(seq 1 30); do
    sample_active="$(metric_sum ferrum_mesh_service_waypoint_l7_tunnels_active)"
    if [[ "$sample_active" =~ ^[0-9]+$ ]] && (( sample_active > active )); then
      active="$sample_active"
    fi
    (( active >= 1 )) && break
    sleep 1
  done
  METRIC_ACTIVE_MAX="$active"
  printf 'l7_tunnels_active observed while held: %s\n' "$active" > "$diagnostics"

  kubectl --context "$CONTEXT" -n "$NS" label service swsvc-v1 istio.io/use-waypoint- \
    >> "$diagnostics" 2>&1 || true
  local started ended
  started="$(date +%s)"
  wait "$held_pid" || true
  ended="$(date +%s)"
  revoke_after="$(metric_sum ferrum_mesh_hbone_tunnel_revocations_total)"
  fence_after="$(metric_sum ferrum_mesh_service_waypoint_l7_tunnel_terminations_total fence_revoked)"
  METRIC_HBONE_REVOCATION_DELTA="$(delta "$revoke_before" "$revoke_after")"
  METRIC_FENCE_REVOKED_DELTA="$(delta "$fence_before" "$fence_after")"
  cat "$RESULTS_DIR/held-request.txt" >> "$diagnostics"
  printf 'held request ended %ss after the label removal\nrevocations before/after: %s/%s\nfence_revoked before/after: %s/%s\n' \
    "$(( ended - started ))" "$revoke_before" "$revoke_after" "$fence_before" "$fence_after" \
    >> "$diagnostics"

  local ok=true held_rc
  held_rc="$(sed -n 's/^rc=//p' "$RESULTS_DIR/held-request.txt" | head -n 1)"
  [[ -n "$held_rc" && "$held_rc" != "0" ]] || ok=false
  grep -q -i -E "CONNECT_ERROR|err 10" "$RESULTS_DIR/held-request.txt" || ok=false
  (( ended - started < 80 )) || ok=false
  [[ "$METRIC_HBONE_REVOCATION_DELTA" =~ ^[0-9]+$ ]] && (( METRIC_HBONE_REVOCATION_DELTA >= 1 )) || ok=false
  log "fence revocation: curl rc=$held_rc after $(( ended - started ))s; revocations +$METRIC_HBONE_REVOCATION_DELTA; fence_revoked +$METRIC_FENCE_REVOKED_DELTA"
  if [[ "$ok" == "true" ]]; then
    record service_waypoint.hbone.fence_revocation_on_binding_withdrawal pass hbone-client \
      swsvc-v1 "CONNECT_ERROR rc=$held_rc revocations+$METRIC_HBONE_REVOCATION_DELTA" \
      swp-fence-revocation.txt
  else
    record service_waypoint.hbone.fence_revocation_on_binding_withdrawal fail hbone-client \
      swsvc-v1 "rc=$held_rc elapsed=$(( ended - started ))s revocations+$METRIC_HBONE_REVOCATION_DELTA" \
      swp-fence-revocation.txt
  fi
}

record_metrics_row() {
  local ok=true value
  for value in "$METRIC_ACTIVE_MAX" "$METRIC_CLEAN_CLOSE_DELTA" "$METRIC_FENCE_REVOKED_DELTA" \
    "$METRIC_HOST_MISMATCH_DELTA" "$METRIC_HBONE_REVOCATION_DELTA"; do
    if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < 1 )); then
      ok=false
    fi
  done
  local outcome="tunnels_active_max=$METRIC_ACTIVE_MAX clean_close+$METRIC_CLEAN_CLOSE_DELTA fence_revoked+$METRIC_FENCE_REVOKED_DELTA host_mismatch+$METRIC_HOST_MISMATCH_DELTA hbone_revocations+$METRIC_HBONE_REVOCATION_DELTA"
  log "metrics: $outcome"
  if [[ "$ok" == "true" ]]; then
    record service_waypoint.metrics.l7_families_moved pass "$WAYPOINT" "" "$outcome"
  else
    record service_waypoint.metrics.l7_families_moved fail "$WAYPOINT" "" "$outcome"
  fi
}

record_l7_rows() {
  local status="$1" reason="$2" id
  for id in "${L7_ASSERTIONS[@]}"; do
    record "$id" "$status" "$WAYPOINT" "" "$reason"
  done
}

run_l7_probes() {
  PROBE_DEADLINE=$(( $(date +%s) + PROBE_BUDGET_SECS ))
  probe_status_and_detect_l7
  case "$L7_STATE" in
    present) ;;
    absent)
      if [[ "$ALLOW_L7_ABSENT" == "1" ]]; then
        log "SKIPPED: $L7_ABSENT_REASON (FERRUM_SWP_E2E_ALLOW_L7_ABSENT=1)"
        record_l7_rows skip "$L7_ABSENT_REASON"
      else
        log "FAILED: $L7_ABSENT_REASON"
        record_l7_rows fail "$L7_ABSENT_REASON"
      fi
      return 0
      ;;
    *)
      # The status row is already recorded as failed; every other L7 row
      # fails with the same reason instead of probing a broken setup.
      local id
      for id in "${L7_ASSERTIONS[@]:1}"; do
        record "$id" fail "$WAYPOINT" "" "$L7_ABSENT_REASON"
      done
      return 0
      ;;
  esac
  probe_weighted_split
  probe_header_and_branch_authz
  probe_host_spoof
  probe_cross_namespace
  # Last: it withdraws swsvc-v1's binding.
  probe_fence_revocation
  record_metrics_row
}

# ── diagnostics + gate ──────────────────────────────────────────────────────

collect_diagnostics() {
  local ns deploy
  for ns in "$NS" "$BETA_NS"; do
    kubectl --context "$CONTEXT" -n "$ns" get all -o wide > "$ARTIFACT_DIR/$ns-all.txt" 2>&1 || true
    kubectl --context "$CONTEXT" -n "$ns" get events --sort-by=.lastTimestamp \
      > "$ARTIFACT_DIR/$ns-events.txt" 2>&1 || true
    kubectl --context "$CONTEXT" -n "$ns" describe pods > "$ARTIFACT_DIR/$ns-pods-describe.txt" 2>&1 || true
  done
  kubectl --context "$CONTEXT" get virtualservices.networking.istio.io,authorizationpolicies.security.istio.io,gateways.gateway.networking.k8s.io,referencegrants.gateway.networking.k8s.io \
    -A -o yaml > "$ARTIFACT_DIR/mesh-objects.yaml" 2>&1 || true
  for deploy in ferrum-cp "$WAYPOINT" swsvc-v1 swsvc-v2 hbone-client; do
    kubectl --context "$CONTEXT" -n "$NS" logs "deploy/$deploy" --all-containers --tail=800 \
      > "$ARTIFACT_DIR/$deploy.log" 2>&1 || true
  done
  kubectl --context "$CONTEXT" -n "$BETA_NS" logs deploy/xsvc --all-containers --tail=800 \
    > "$ARTIFACT_DIR/xsvc.log" 2>&1 || true
  waypoint_admin_get /metrics > "$ARTIFACT_DIR/waypoint-metrics.prom" 2>/dev/null || true
  ferrum_spire_collect_diagnostics "$CONTEXT" "$SPIRE_NS" "$ARTIFACT_DIR/spire" || true
  if [[ -f "$LIVE_ASSERTIONS_FILE" ]]; then
    cp "$LIVE_ASSERTIONS_FILE" "$ARTIFACT_DIR/live-assertions.json" 2>/dev/null || true
  fi
  local note
  for note in "$RESULTS_DIR"/*.txt; do
    [[ -f "$note" ]] || continue
    if grep -Eq 'BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)' "$note" 2>/dev/null; then
      continue
    fi
    cp "$note" "$ARTIFACT_DIR/" 2>/dev/null || true
  done
}

# Fail-closed gate. With L7 present every required row must pass. In the
# adoption window (L7 absent and explicitly allowed) the binding row must pass
# and every L7 row must be an explicit `skip` carrying the absence reason.
require_live_assertions() {
  log "enforcing required live assertions (L7 state: $L7_STATE)"
  if [[ "$L7_STATE" == "absent" && "$ALLOW_L7_ABSENT" == "1" ]]; then
    python3 - "$LIVE_ASSERTIONS_FILE" "${L7_ASSERTIONS[@]}" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1]))
seen = {}
for record in doc.get("assertions", []):
    seen[record["id"]] = record.get("status")
errors = []
if seen.get("service_waypoint.binding.bound_services_projected") != "pass":
    errors.append("service_waypoint.binding.bound_services_projected did not pass")
for assertion_id in sys.argv[2:]:
    if seen.get(assertion_id) != "skip":
        errors.append(f"{assertion_id} is {seen.get(assertion_id)!r}, expected an explicit skip")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
PY
    log "ServiceWaypoint L7 NOT PRESENT in this build: binding verified, every L7 row recorded as skip"
    return 0
  fi
  if ! ferrum_live_assertions_require_all_passed \
    "$LIVE_ASSERTIONS_FILE" "${REQUIRED_LIVE_ASSERTIONS[@]}"; then
    echo "required service_waypoint.* live assertions did not all pass" >&2
    return 1
  fi
  log "all required service_waypoint.* live assertions passed"
}

main() {
  trap 'collect_diagnostics; native_mtls_cleanup' EXIT
  preflight
  init_live_assertions

  create_cluster
  build_and_load_image
  install_spire
  install_crds
  ensure_namespaces
  render_shared_secrets
  mint_native_mtls_pki
  apply_native_mtls_secrets
  register_spire_workloads
  apply_workloads
  wait_for_rollouts
  SWP_POD_IP="$(wait_for_pod_ip "$WAYPOINT")"
  log "waypoint pod IP=$SWP_POD_IP"

  if [[ "${FERRUM_MESH_E2E_DEPLOY_ONLY:-0}" == "1" ]]; then
    log "deploy-only complete; artifacts in $ARTIFACT_DIR"
    return 0
  fi

  probe_binding || true
  run_l7_probes
  # Read by the workflow gate to report the adoption-window state.
  printf '%s\n' "$L7_STATE" > "$RESULTS_DIR/l7-state.txt"

  require_live_assertions
  log "mesh-e2e-service-waypoint suite finished; artifacts in $ARTIFACT_DIR"
}

main "$@"
