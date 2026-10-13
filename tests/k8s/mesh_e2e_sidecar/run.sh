#!/usr/bin/env bash
set -euo pipefail

# Live single-cluster Sidecar mesh e2e suite (M2 sidecar suite, M5 Stage 4).
#
# Proves the Stable sidecar traffic surface on the REAL captured datapath in a
# kind cluster with real SPIRE-issued SVIDs:
#
#   client(sidecar) --capture :15001--> svc pod app port 8080
#     --inbound iptables REDIRECT 8080->:15006--> svc sidecar STRICT inbound
#     (SPIFFE-verifies the client SVID) --> mesh_authz / mesh_request_auth
#     --> local app -> 200.
#
# Emitted `sidecar.*` live assertions (`tests/k8s/lib/live_assertions.sh`
# schema; suite `mesh-e2e-sidecar`, platform profile `kind-spire-sidecar` —
# these strings are LOAD-BEARING: `tests/conformance/ga_contract.yaml` rows
# reference them and `tests/conformance/live_contract.rs` validates the
# artifact against the contract):
#
#   sidecar.spire.workload_entries              SPIRE entries registered
#   sidecar.peer_auth.strict_mtls_authenticated authenticated client -> 200
#   sidecar.peer_auth.strict_mtls_plaintext_rejected
#                                               plaintext dial to the CAPTURED
#                                               app port never reaches the app
#   sidecar.authz.denied_principal_rejected     dest-side identity DENY -> 403
#   sidecar.request_auth.valid_jwt_admitted     RS256 JWT (inline JWKS) -> 200
#   sidecar.request_auth.missing_jwt_rejected   no token on gated path -> 403
#   sidecar.request_auth.invalid_jwt_rejected   wrong-key signature -> 401
#   sidecar.destination_rule.export_to_namespace_visibility
#                                               service-ns sticky DR exportTo=.
#                                               stays RR; exported root sticky
#                                               control pins one backend
#   sidecar.destination_rule.lookup_tier_client_wins
#                                               client-tier RR wins over sticky
#                                               service + root rules
#   sidecar.destination_rule.tcp_connect_timeout
#                                               DR connectTimeout provably
#                                               bounds the mesh-mTLS dial
#                                               (two-phase timing, see below)
#   sidecar.destination_rule.tcp_max_connections
#                                               DR maxConnections=1 admits one
#                                               HELD WebSocket session, rejects
#                                               a concurrent upgrade 503, and
#                                               recovers after release
#   sidecar.virtual_service.cors_policy         VS-derived CORS on the client
#                                               sidecar: allowed Origin
#                                               reflected, preflight answered
#                                               200, unmatched actual/preflight
#                                               forwarded without gateway ACAO
#   sidecar.config.native_subscribe_delivered   a Ferrum CP (cp mode, sqlite,
#                                               K8s pod discovery) serves the
#                                               mesh model over native
#                                               MeshSubscribe to the capp
#                                               sidecar (CONFIG_PROTOCOL=
#                                               native) on the production
#                                               mTLS + JWT channel
#                                               (https://ferrum-cp.<ns>.svc.cluster.local:50051
#                                               with SAN verification, CP
#                                               client-CA, DP client cert);
#                                               client traffic reaches capp's
#                                               app AND /mesh/config-drift
#                                               attributes a native slice
#   sidecar.config.native_subscribe_mtls_omitted_client_rejected
#                                               dedicated probe DP omits its
#                                               client cert; no slice accepted
#   sidecar.config.native_subscribe_mtls_foreign_client_rejected
#                                               dedicated probe DP presents a
#                                               foreign-CA client cert; no
#                                               slice accepted
#   sidecar.config.native_subscribe_tls_untrusted_server_ca_rejected
#                                               dedicated probe DP trusts the
#                                               wrong server CA; no slice
#                                               accepted
#   sidecar.config.native_subscribe_tls_wrong_san_rejected
#                                               dedicated probe DP dials a
#                                               hostname absent from the CP
#                                               server SAN; no slice accepted
#   sidecar.config.native_subscribe_jwt_rejected
#                                               dedicated probe DP completes
#                                               mTLS then presents an invalid
#                                               JWT; no slice accepted
#   sidecar.config.native_subscribe_tls_rotation_reconnects
#                                               projected Secret generation
#                                               swap of CP/DP gRPC TLS
#                                               material reconnects the native
#                                               stream without a pod restart;
#                                               capp's post-swap TLS handshake
#                                               plus CP-accepted MeshSubscribe
#                                               must follow the matching
#                                               generation-2 TLS reload
#                                               publication (surface=dp_grpc in
#                                               capp logs, surface=cp_grpc in
#                                               CP logs) for that exact
#                                               pod/node identity, strictly
#                                               newer than the pre-swap
#                                               baseline; reload publications
#                                               are temporal anchors only; an
#                                               over-the-wire mTLS handshake
#                                               to the running CP observes the
#                                               replacement leaf serial
#
# DestinationRule exportTo / lookup probes drive captured client egress against
# a beta-owned MeshService (`drsvc`) with two labelled sidecar backends. File-mode
# DestinationRule.namespace / MeshService.namespace fields stand in for Istio
# CRDs; a permissive Sidecar egress scope admits the cross-namespace service so
# materialization can exercise exportTo and client > service > root lookup.
# (CRD watching is disabled here). Applied vs ignored rules are distinguished
# by consistent-hash (one backend) versus round-robin (both backends).
#
# The DestinationRule connectTimeout probe is TWO-PHASE on purpose: a
# black-holed dial (the client pod's own OUTPUT DROP, so SYNs vanish
# deterministically with no external-routing dependence) is timed under
# connectTimeout=8000ms and then — after a re-render + rollout restart (the
# runtime image is distroless: no shell, no `kill -HUP`; restart is the
# reload) — under 2000ms. The observed fail time must TRACK the configured
# value across the change (and both windows exclude the built-in 5000ms
# default), which proves the knob itself rather than any default.

# Run locally (requires docker, kind, kubectl, curl, python3, openssl):
#   FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE=true tests/k8s/mesh_e2e_sidecar/run.sh
#
# Set FERRUM_MESH_E2E_DEPLOY_ONLY=1 to run only the SPIRE/workload deploy
# without driving traffic or gating (local smoke; not a CI job).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/.context/mesh-e2e-sidecar}"
RESULTS_DIR="${FERRUM_MESH_E2E_RESULTS_DIR:-$ROOT_DIR/target/mesh-e2e-sidecar}"
MANIFESTS="$ROOT_DIR/tests/k8s/mesh_e2e_sidecar/manifests.yaml"

LIVE_ASSERTIONS_HELPER="$ROOT_DIR/tests/k8s/lib/live_assertions.sh"
SPIRE_HELPER="$ROOT_DIR/tests/k8s/lib/spire.sh"
NATIVE_PROBE_CLASSIFY_HELPER="$ROOT_DIR/tests/k8s/lib/native_probe_classify.py"
# Classifier --evidence-out labels each negative must pin (not broad TLS classes).
# Client-side untrusted-CA / wrong-SAN proof is the closed-set native_tls_class
# field (`client_tls_verify` / `client_tls_name`) emitted by the native
# MeshSubscribe observing verifier, not a generic handshake or tonic transport error.
NATIVE_EVID_CP_NO_CERT='cp_tls_rejected ip=.* reason=peer sent no certificates'
NATIVE_EVID_CP_UNKNOWN_ISSUER='cp_tls_rejected ip=.* reason=invalid peer certificate: UnknownIssuer'
NATIVE_EVID_CLIENT_SERVER_VERIFY='^client_tls_verify$'
NATIVE_EVID_CLIENT_TLS_NAME='^client_tls_name$'
NATIVE_EVID_CP_JWT_AUTH_FAILED='cp_jwt_rejected node_id=.* reason=Invalid token: authentication failed'
# shellcheck source=../lib/live_assertions.sh
source "$LIVE_ASSERTIONS_HELPER"
# shellcheck source=../lib/spire.sh
source "$SPIRE_HELPER"

CLUSTER="${FERRUM_MESH_E2E_CLUSTER:-ferrum-sidecar-e2e}"
CONTEXT="kind-$CLUSTER"
TRUST_DOMAIN="${FERRUM_MESH_E2E_TRUST_DOMAIN:-mesh-e2e.test}"
NS="${FERRUM_NAMESPACE:-ferrum}"
SPIRE_NS="${FERRUM_SPIRE_NAMESPACE:-spire-system}"
IMAGE_REPOSITORY="${FERRUM_IMAGE_REPOSITORY:-ferrum-edge}"
IMAGE_TAG="${FERRUM_IMAGE_TAG:-mesh-e2e-sidecar}"
IMAGE="${IMAGE_REPOSITORY}:${IMAGE_TAG}"
APP_BODY="${FERRUM_MESH_E2E_APP_BODY:-mesh-e2e-app}"
# The client pod's init container installs an OUTPUT DROP for this IP, so the
# slowsvc mesh-mTLS dial ($BLACKHOLE_IP:15006) hangs inside the client's own
# netns — deterministic regardless of cluster/host routing.
BLACKHOLE_IP="${FERRUM_MESH_E2E_BLACKHOLE_IP:-10.255.255.254}"
LIVE_ASSERTIONS_FILE="${FERRUM_LIVE_ASSERTIONS_FILE:-$RESULTS_DIR/live-assertions.json}"
# MUST match ga_contract.yaml's `platform_profile: kind-spire-sidecar`.
LIVE_PLATFORM_PROFILE="${FERRUM_LIVE_PLATFORM_PROFILE:-kind-spire-sidecar}"
LIVE_SUITE_NAME="mesh-e2e-sidecar"

SVC_HOST="svc.$NS.svc.cluster.local"
SLOW_HOST="slowsvc.$NS.svc.cluster.local"
WS_HOST="wssvc.$NS.svc.cluster.local"
CAPP_HOST="capp.$NS.svc.cluster.local"
# DestinationRule exportTo / lookup-tier live host (beta-owned MeshService).
# Declaring namespace `beta` owns MeshService `drsvc`; client subscriber is `$NS`
# (ferrum); root tier is the default `istio-system`. Backend labels are the
# observed wire evidence for applied vs ignored rules. Sidecar outbound
# materialization requires MeshService/workload targets (not ServiceEntry ends).
DR_SERVICE_NAME="drsvc"
DR_SERVICE_NS="beta"
DR_LIVE_HOST="$DR_SERVICE_NAME.$DR_SERVICE_NS.svc.cluster.local"
DR_ROOT_NS="istio-system"
DR_BACKEND_A_BODY="backend-a"
DR_BACKEND_B_BODY="backend-b"
DR_LIVE_REQUESTS=8
DR_BACKEND_A_IP=""
DR_BACKEND_B_IP=""
JWT_ISSUER="mesh-e2e-issuer"
JWT_KID="fixture-key"
# The capp echo answers "<APP_BODY>-native" (manifests.yaml) so a native-leg
# probe answer can never be confused with the file-config svc echo.
NATIVE_APP_MARKER="$APP_BODY-native"
# Two-phase DR connectTimeout values + accepted observation windows (seconds).
# Both windows exclude the built-in 5000ms default (types.rs
# default_connect_timeout), so a DR that silently fails to apply cannot pass
# either phase; requiring the observed time to TRACK the 8000->2000 change
# proves the knob end-to-end. There is no retry inflation: materialized mesh
# outbound proxies carry no Proxy.retry policy.
CONNECT_TIMEOUT_PHASE1_MS=8000
PHASE1_WINDOW_LO=6.0
PHASE1_WINDOW_HI=14.0
CONNECT_TIMEOUT_PHASE2_MS=2000
PHASE2_WINDOW_LO=1.2
PHASE2_WINDOW_HI=4.5

# Discovered at runtime.
SVC_POD_IP=""
WSSVC_POD_IP=""
CAPP_POD_IP=""
# Minted at startup (mint_jwt_material).
JWKS_JSON=""
JWT_VALID=""
JWT_WRONG_KEY=""
# Minted at startup (render_shared_secrets): HS256 secrets for the CP<->DP
# gRPC JWT and for the sidecar/CP admin APIs (the admin API validates but
# never mints, so run.sh signs the /mesh/config-drift bearer itself).
CP_DP_JWT_SECRET=""
ADMIN_JWT_SECRET=""
CP_DP_JWT_SECRET_INVALID=""
# Ephemeral native MeshSubscribe PKI. Controller-host copies live only in this
# private temporary directory, are normally removed on EXIT, and are never
# copied into ARTIFACT_DIR / RESULTS_DIR. The fixture transfers the required
# leaves/keys into ephemeral Kubernetes Secrets for projection.
NATIVE_MTLS_DIR=""
NATIVE_OBSERVE_PF_PID=""
NATIVE_CP_DNS=""
NATIVE_WRONG_SAN_DNS=""
NATIVE_SERVER_SERIAL_GEN1=""
NATIVE_SERVER_SERIAL_GEN2=""
NATIVE_CLIENT_SERIAL_GEN1=""
NATIVE_CLIENT_SERIAL_GEN2=""
NATIVE_CP_SERVED_CLASS=""
NATIVE_CP_SERVED_REASON=""
NATIVE_CP_SERVED_SERIAL=""
NATIVE_ROTATION_NODE_ID=""
NATIVE_ROTATION_POD_IP=""
NATIVE_ROTATION_BASELINE_CP=0
NATIVE_ROTATION_BASELINE_CLIENT=0
NATIVE_ROTATION_BASELINE_CAPTURED=false

LIVE_ASSERTIONS_INITIALIZED=false
REQUIRED_LIVE_ASSERTIONS=(
  sidecar.spire.workload_entries
  sidecar.peer_auth.strict_mtls_authenticated
  sidecar.peer_auth.strict_mtls_plaintext_rejected
  sidecar.authz.denied_principal_rejected
  sidecar.request_auth.valid_jwt_admitted
  sidecar.request_auth.missing_jwt_rejected
  sidecar.request_auth.invalid_jwt_rejected
  sidecar.destination_rule.tcp_connect_timeout
  sidecar.destination_rule.export_to_namespace_visibility
  sidecar.destination_rule.lookup_tier_client_wins
  sidecar.destination_rule.tcp_max_connections
  sidecar.virtual_service.cors_policy
  sidecar.config.native_subscribe_delivered
  sidecar.config.native_subscribe_mtls_omitted_client_rejected
  sidecar.config.native_subscribe_mtls_foreign_client_rejected
  sidecar.config.native_subscribe_tls_untrusted_server_ca_rejected
  sidecar.config.native_subscribe_tls_wrong_san_rejected
  sidecar.config.native_subscribe_jwt_rejected
  sidecar.config.native_subscribe_tls_rotation_reconnects
)
# NOTE: every id backs a GA-contract capability row in
# tests/conformance/ga_contract.yaml — keep the id strings in lock-step.
# `sidecar.spire.workload_entries` (with the strict-mTLS positive) backs the
# SPIFFE identity row `mesh.identity.spire_svid_issuance`;
# `sidecar.peer_auth.strict_mtls_authenticated` is deliberately shared by the
# PeerAuthentication and identity rows;
# `sidecar.config.native_subscribe_*` backs the config-transport row
# `mesh.config_transport.native_subscribe` (issues #2002 / #3855): the
# release-blocking native assertion is mTLS + JWT + SAN verification, plus
# fail-closed negatives and watched projected-Secret rotation. A deleted or
# skipped negative cannot leave that GA row green.

mkdir -p "$ARTIFACT_DIR" "$RESULTS_DIR"

log() {
  printf '\n[mesh-e2e-sidecar] %s\n' "$*"
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
  if [[ ! -f "$NATIVE_PROBE_CLASSIFY_HELPER" ]]; then
    printf 'missing native probe classifier: %s\n' "$NATIVE_PROBE_CLASSIFY_HELPER" >&2
    exit 1
  fi
  docker info >/dev/null
  if [[ "${FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE:-}" != "true" ]]; then
    echo "Refusing to create/destroy a disposable kind cluster without \
FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE=true" >&2
    exit 1
  fi
}

cluster_exists() {
  kind get clusters | grep -Fxq "$1"
}

create_cluster() {
  if cluster_exists "$CLUSTER"; then
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

record_live_assertion() {
  local assertion_id="$1"
  local status="$2"
  local source_workload="${3:-}"
  local destination_workload="${4:-}"
  local observed_outcome="${5:-}"
  local diagnostics="${6:-}"

  if [[ "$LIVE_ASSERTIONS_INITIALIZED" != "true" ]]; then
    return
  fi
  ferrum_live_record_assertion \
    "$LIVE_ASSERTIONS_FILE" \
    "$assertion_id" \
    "$status" \
    "$source_workload" \
    "$destination_workload" \
    "$observed_outcome" \
    "" \
    "" \
    "" \
    "$diagnostics"
}

# ── JWT material (RS256 + inline JWKS) ──────────────────────────────────────
#
# The destination's RequestAuthentication uses an INLINE `jwks` (a JSON string
# in the mesh document), so no JWKS server is needed. Keys are generated fresh
# per run with openssl; python3 stdlib does the base64url/JSON assembly (no
# pip dependencies). A second key signs JWT_WRONG_KEY: a well-formed token
# whose signature cannot verify against the published JWKS — the precise
# "invalid token" negative (the jwks_auth plugin answers 401).

render_jwks() {
  local key_pem="$1" kid="$2"
  local modulus_hex
  modulus_hex="$(openssl rsa -in "$key_pem" -noout -modulus | sed 's/^Modulus=//')"
  python3 - "$modulus_hex" "$kid" <<'PY'
import base64
import json
import sys

n = base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1])).rstrip(b"=").decode()
print(json.dumps(
    {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": sys.argv[2], "n": n, "e": "AQAB"}]},
    separators=(",", ":"),
))
PY
}

mint_rs256_jwt() {
  local key_pem="$1"
  local header payload signing_input signature
  header="$(python3 - "$JWT_KID" <<'PY'
import base64
import json
import sys

print(base64.urlsafe_b64encode(
    json.dumps({"alg": "RS256", "typ": "JWT", "kid": sys.argv[1]}, separators=(",", ":")).encode()
).rstrip(b"=").decode())
PY
)"
  # exp is required (FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP defaults true) and
  # always validated; 2h comfortably outlives the run.
  payload="$(python3 - "$JWT_ISSUER" <<'PY'
import base64
import json
import sys
import time

now = int(time.time())
print(base64.urlsafe_b64encode(
    json.dumps(
        {"iss": sys.argv[1], "sub": "fixture-client", "iat": now, "exp": now + 7200},
        separators=(",", ":"),
    ).encode()
).rstrip(b"=").decode())
PY
)"
  signing_input="$header.$payload"
  signature="$(printf '%s' "$signing_input" |
    openssl dgst -sha256 -sign "$key_pem" -binary |
    python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b"=").decode())')"
  printf '%s.%s' "$signing_input" "$signature"
}

mint_jwt_material() {
  log "minting RS256 JWT material (issuer=$JWT_ISSUER kid=$JWT_KID)"
  openssl genrsa -out "$RESULTS_DIR/jwt-signer.pem" 2048 >/dev/null 2>&1
  openssl genrsa -out "$RESULTS_DIR/jwt-wrong-signer.pem" 2048 >/dev/null 2>&1
  JWKS_JSON="$(render_jwks "$RESULTS_DIR/jwt-signer.pem" "$JWT_KID")"
  JWT_VALID="$(mint_rs256_jwt "$RESULTS_DIR/jwt-signer.pem")"
  # Same kid + issuer, different key: selects the published JWKS key and fails
  # exactly on signature verification.
  JWT_WRONG_KEY="$(mint_rs256_jwt "$RESULTS_DIR/jwt-wrong-signer.pem")"
  printf '%s\n' "$JWKS_JSON" > "$RESULTS_DIR/jwks.json"
}

# ── shared HS256 secrets (CP<->DP gRPC + admin APIs) ────────────────────────
#
# Fresh per run (throwaway fixture material, >=32 chars as the CP/DP secret
# validation requires). Pods read them via secretKeyRef, so on a REUSED
# cluster a re-run re-mints values that already-running pods do not see — the
# disposable-cluster CI flow always starts fresh; local re-runs against a kept
# cluster should `kubectl rollout restart` the ferrum-cp/capp deployments.
render_shared_secrets() {
  CP_DP_JWT_SECRET="$(openssl rand -hex 32)"
  CP_DP_JWT_SECRET_INVALID="$(openssl rand -hex 32)"
  ADMIN_JWT_SECRET="$(openssl rand -hex 32)"
  if [[ "$CP_DP_JWT_SECRET" == "$CP_DP_JWT_SECRET_INVALID" ]]; then
    echo "CP/DP JWT secret collision while minting the invalid-JWT probe secret" >&2
    return 1
  fi
  kubectl --context "$CONTEXT" -n "$NS" create secret generic ferrum-mesh-e2e-secrets \
    --from-literal=cp-dp-grpc-jwt-secret="$CP_DP_JWT_SECRET" \
    --from-literal=cp-dp-grpc-jwt-secret-invalid="$CP_DP_JWT_SECRET_INVALID" \
    --from-literal=admin-jwt-secret="$ADMIN_JWT_SECRET" \
    --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
}

# HS256 admin bearer for the capp sidecar's read-only admin API (the admin API
# validates but never mints; same shape as node_waypoint_ebpf_live's helper —
# all six required claims plus the required `role`). Default issuer
# "ferrum-edge" matches the sidecar's unset FERRUM_ADMIN_JWT_ISSUER.
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
    "sub": "mesh-e2e-sidecar",
    "iat": now,
    "nbf": now - 1,
    "exp": now + 600,
    "jti": str(uuid.uuid4()),
    "role": "admin",
}
signing_input = f"{b64url(header)}.{b64url(claims)}"
signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
print(f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}")
PY
}

# ── Native MeshSubscribe mTLS PKI (issue #3855) ─────────────────────────────
#
# Ephemeral test PKI minted with openssl at run time. Controller-host copies
# live only in NATIVE_MTLS_DIR (not ARTIFACT_DIR / RESULTS_DIR), are normally
# removed on EXIT, and are never copied into results/artifacts. The fixture
# transfers the required leaves/keys into ephemeral Kubernetes Secrets for
# projection. Public serials/CNs/class/reason strings are the only identity
# evidence recorded.

stop_native_observe_port_forward() {
  local pid="${1:-${NATIVE_OBSERVE_PF_PID:-}}"
  if [[ -z "$pid" || "$pid" == "0" ]]; then
    NATIVE_OBSERVE_PF_PID=""
    return 0
  fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  if [[ "${NATIVE_OBSERVE_PF_PID:-}" == "$pid" ]]; then
    NATIVE_OBSERVE_PF_PID=""
  fi
}

native_mtls_cleanup() {
  stop_native_observe_port_forward
  if [[ -n "${NATIVE_MTLS_DIR:-}" && -d "$NATIVE_MTLS_DIR" ]]; then
    find "$NATIVE_MTLS_DIR" -type f -exec rm -f {} + 2>/dev/null || true
    rm -rf "$NATIVE_MTLS_DIR" 2>/dev/null || true
  fi
}

cert_serial() {
  openssl x509 -in "$1" -noout -serial 2>/dev/null | awk -F= '{print $2}'
}

mint_native_leaf() {
  local ca_cert="$1" ca_key="$2" cn="$3" out_cert="$4" out_key="$5" extfile="$6"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$cn" \
    -keyout "$out_key" -out "$NATIVE_MTLS_DIR/$cn.csr" >/dev/null 2>&1
  openssl x509 -req -days 1 -in "$NATIVE_MTLS_DIR/$cn.csr" \
    -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
    -extfile "$extfile" -out "$out_cert" >/dev/null 2>&1
  rm -f "$NATIVE_MTLS_DIR/$cn.csr"
}

mint_native_mtls_pki() {
  NATIVE_CP_DNS="ferrum-cp.$NS.svc.cluster.local"
  NATIVE_WRONG_SAN_DNS="ferrum-cp-wrong-san.$NS.svc.cluster.local"
  NATIVE_MTLS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ferrum-native-mtls.XXXXXX")"
  chmod 700 "$NATIVE_MTLS_DIR"
  log "minting ephemeral native MeshSubscribe PKI (SAN=$NATIVE_CP_DNS)"

  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=ferrum-native-mtls-ca-gen1 \
    -keyout "$NATIVE_MTLS_DIR/ca-key.pem" -out "$NATIVE_MTLS_DIR/ca.pem" \
    >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=ferrum-native-mtls-client-ca-gen1 \
    -keyout "$NATIVE_MTLS_DIR/client-ca-key.pem" -out "$NATIVE_MTLS_DIR/client-ca.pem" \
    >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=ferrum-native-mtls-foreign-ca \
    -keyout "$NATIVE_MTLS_DIR/foreign-ca-key.pem" -out "$NATIVE_MTLS_DIR/foreign-ca.pem" \
    >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=ferrum-native-mtls-untrusted-ca \
    -keyout "$NATIVE_MTLS_DIR/untrusted-ca-key.pem" -out "$NATIVE_MTLS_DIR/untrusted-ca.pem" \
    >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=ferrum-native-mtls-ca-gen2 \
    -keyout "$NATIVE_MTLS_DIR/gen2-ca-key.pem" -out "$NATIVE_MTLS_DIR/gen2-ca.pem" \
    >/dev/null 2>&1
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=ferrum-native-mtls-client-ca-gen2 \
    -keyout "$NATIVE_MTLS_DIR/gen2-client-ca-key.pem" \
    -out "$NATIVE_MTLS_DIR/gen2-client-ca.pem" >/dev/null 2>&1

  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$NATIVE_CP_DNS" \
    > "$NATIVE_MTLS_DIR/server.ext"
  printf 'extendedKeyUsage=clientAuth\n' > "$NATIVE_MTLS_DIR/client.ext"

  mint_native_leaf "$NATIVE_MTLS_DIR/ca.pem" "$NATIVE_MTLS_DIR/ca-key.pem" \
    ferrum-native-mtls-cp "$NATIVE_MTLS_DIR/server.pem" \
    "$NATIVE_MTLS_DIR/server-key.pem" "$NATIVE_MTLS_DIR/server.ext"
  mint_native_leaf "$NATIVE_MTLS_DIR/client-ca.pem" "$NATIVE_MTLS_DIR/client-ca-key.pem" \
    ferrum-native-mtls-dp "$NATIVE_MTLS_DIR/client.pem" \
    "$NATIVE_MTLS_DIR/client-key.pem" "$NATIVE_MTLS_DIR/client.ext"
  mint_native_leaf "$NATIVE_MTLS_DIR/foreign-ca.pem" "$NATIVE_MTLS_DIR/foreign-ca-key.pem" \
    ferrum-native-mtls-foreign "$NATIVE_MTLS_DIR/foreign-client.pem" \
    "$NATIVE_MTLS_DIR/foreign-client-key.pem" "$NATIVE_MTLS_DIR/client.ext"
  mint_native_leaf "$NATIVE_MTLS_DIR/gen2-ca.pem" "$NATIVE_MTLS_DIR/gen2-ca-key.pem" \
    ferrum-native-mtls-cp-gen2 "$NATIVE_MTLS_DIR/gen2-server.pem" \
    "$NATIVE_MTLS_DIR/gen2-server-key.pem" "$NATIVE_MTLS_DIR/server.ext"
  mint_native_leaf "$NATIVE_MTLS_DIR/gen2-client-ca.pem" \
    "$NATIVE_MTLS_DIR/gen2-client-ca-key.pem" \
    ferrum-native-mtls-dp-gen2 "$NATIVE_MTLS_DIR/gen2-client.pem" \
    "$NATIVE_MTLS_DIR/gen2-client-key.pem" "$NATIVE_MTLS_DIR/client.ext"

  NATIVE_SERVER_SERIAL_GEN1="$(cert_serial "$NATIVE_MTLS_DIR/server.pem")"
  NATIVE_CLIENT_SERIAL_GEN1="$(cert_serial "$NATIVE_MTLS_DIR/client.pem")"
  NATIVE_SERVER_SERIAL_GEN2="$(cert_serial "$NATIVE_MTLS_DIR/gen2-server.pem")"
  NATIVE_CLIENT_SERIAL_GEN2="$(cert_serial "$NATIVE_MTLS_DIR/gen2-client.pem")"
  if [[ -z "$NATIVE_SERVER_SERIAL_GEN1" || -z "$NATIVE_SERVER_SERIAL_GEN2" \
    || "$NATIVE_SERVER_SERIAL_GEN1" == "$NATIVE_SERVER_SERIAL_GEN2" ]]; then
    echo "native MeshSubscribe PKI serials are empty or not distinct across generations" >&2
    return 1
  fi
  printf 'gen1 server serial=%s client serial=%s\ngen2 server serial=%s client serial=%s\n' \
    "$NATIVE_SERVER_SERIAL_GEN1" "$NATIVE_CLIENT_SERIAL_GEN1" \
    "$NATIVE_SERVER_SERIAL_GEN2" "$NATIVE_CLIENT_SERIAL_GEN2" \
    > "$RESULTS_DIR/native-mtls-serials.txt"
}

apply_native_mtls_secret() {
  local name="$1"
  shift
  kubectl --context "$CONTEXT" -n "$NS" create secret generic "$name" \
    "$@" --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
}

apply_native_mtls_secrets() {
  local generation="${1:-gen1}"
  if [[ "$generation" == "gen2" ]]; then
    apply_native_mtls_secret ferrum-native-mtls-cp \
      --from-file=server.pem="$NATIVE_MTLS_DIR/gen2-server.pem" \
      --from-file=server-key.pem="$NATIVE_MTLS_DIR/gen2-server-key.pem" \
      --from-file=client-ca.pem="$NATIVE_MTLS_DIR/gen2-client-ca.pem"
    apply_native_mtls_secret ferrum-native-mtls-dp \
      --from-file=ca.pem="$NATIVE_MTLS_DIR/gen2-ca.pem" \
      --from-file=client.pem="$NATIVE_MTLS_DIR/gen2-client.pem" \
      --from-file=client-key.pem="$NATIVE_MTLS_DIR/gen2-client-key.pem"
  else
    apply_native_mtls_secret ferrum-native-mtls-cp \
      --from-file=server.pem="$NATIVE_MTLS_DIR/server.pem" \
      --from-file=server-key.pem="$NATIVE_MTLS_DIR/server-key.pem" \
      --from-file=client-ca.pem="$NATIVE_MTLS_DIR/client-ca.pem"
    apply_native_mtls_secret ferrum-native-mtls-dp \
      --from-file=ca.pem="$NATIVE_MTLS_DIR/ca.pem" \
      --from-file=client.pem="$NATIVE_MTLS_DIR/client.pem" \
      --from-file=client-key.pem="$NATIVE_MTLS_DIR/client-key.pem"
  fi
  apply_native_mtls_secret ferrum-native-mtls-foreign \
    --from-file=ca.pem="$NATIVE_MTLS_DIR/ca.pem" \
    --from-file=client.pem="$NATIVE_MTLS_DIR/foreign-client.pem" \
    --from-file=client-key.pem="$NATIVE_MTLS_DIR/foreign-client-key.pem"
  apply_native_mtls_secret ferrum-native-mtls-untrusted \
    --from-file=ca.pem="$NATIVE_MTLS_DIR/untrusted-ca.pem" \
    --from-file=client.pem="$NATIVE_MTLS_DIR/client.pem" \
    --from-file=client-key.pem="$NATIVE_MTLS_DIR/client-key.pem"
  apply_native_mtls_secret ferrum-native-mtls-omit-client \
    --from-file=ca.pem="$NATIVE_MTLS_DIR/ca.pem"
}

# ── SPIRE ───────────────────────────────────────────────────────────────────

install_spire() {
  log "installing SPIRE in $CONTEXT ($TRUST_DOMAIN)"
  ferrum_spire_apply_minimal "$CONTEXT" "$TRUST_DOMAIN" "$SPIRE_NS"
  ferrum_spire_wait_ready "$CONTEXT" "$SPIRE_NS" 5m
}

register_spire_workloads() {
  log "registering SPIRE workload entries (svc, wssvc, client, rogue, capp, native-mtls-probe, drsvc-a/b)"
  local registered_ok=true
  local -a spire_nodes
  mapfile -t spire_nodes < <(ferrum_spire_agent_nodes "$CONTEXT" "$SPIRE_NS")
  if [[ "${#spire_nodes[@]}" -eq 0 ]]; then
    echo "no attested SPIRE agent node in $CONTEXT" >&2
    kubectl --context "$CONTEXT" -n "$SPIRE_NS" get pods -o wide >&2 || true
    registered_ok=false
  fi
  local node parent_id sa
  for node in "${spire_nodes[@]}"; do
    # Guard under `set -e`: a lookup timeout must still record the fail below.
    if ! parent_id="$(ferrum_spire_k8s_psat_agent_parent_id_for_node \
      "$CONTEXT" "$SPIRE_NS" "$TRUST_DOMAIN" "$node")"; then
      registered_ok=false
      continue
    fi
    # slowsvc has NO entry on purpose: its dial is black-holed and never
    # completes a handshake, so no SVID is ever presented for it. capp (the
    # native-MeshSubscribe destination) needs one: its inbound terminates the
    # client's mesh-mTLS with a SPIRE SVID like every other destination. The
    # ferrum-cp pod is NOT a mesh workload and gets no entry. drsvc-a/b are the
    # DestinationRule visibility backends and need SVIDs for mesh-mTLS.
    for sa in svc wssvc client rogue capp native-mtls-probe drsvc-a drsvc-b; do
      ferrum_spire_register_k8s_workload \
        "$CONTEXT" "$SPIRE_NS" \
        "spiffe://$TRUST_DOMAIN/ns/$NS/sa/$sa" \
        "$parent_id" "$NS" "$sa" \
        "k8s:node-name:$node" || registered_ok=false
    done
  done

  ferrum_spire_server_exec "$CONTEXT" "$SPIRE_NS" entry show \
    > "$RESULTS_DIR/spire-entries.txt" 2>&1 || true

  if [[ "$registered_ok" == "true" ]]; then
    record_live_assertion sidecar.spire.workload_entries pass \
      "" "" "svc-wssvc-client-rogue-capp-native-mtls-probe-drsvc-entries-registered" "spire-entries.txt"
  else
    record_live_assertion sidecar.spire.workload_entries fail \
      "" "" "workload-entry-registration-failed"
    return 1
  fi
}

# ── workloads + mesh config ─────────────────────────────────────────────────

apply_workloads() {
  log "applying workloads"
  awk -v ns="$NS" -v td="$TRUST_DOMAIN" -v image="$IMAGE" -v body="$APP_BODY" \
    -v blackhole="$BLACKHOLE_IP" '
    {
      gsub(/__NAMESPACE__/, ns)
      gsub(/__TRUST_DOMAIN__/, td)
      gsub(/__IMAGE__/, image)
      gsub(/__APP_BODY__/, body)
      gsub(/__BLACKHOLE_IP__/, blackhole)
      print
    }
  ' "$MANIFESTS" | kubectl --context "$CONTEXT" apply -f -
}

# Idempotently create the workload namespace: the namespaced mesh ConfigMaps
# are applied BEFORE apply_workloads creates the Namespace object.
ensure_namespace() {
  kubectl --context "$CONTEXT" create namespace "$NS" \
    --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
}

apply_configmap() {
  local name="$1" mesh_yaml="$2"
  kubectl --context "$CONTEXT" -n "$NS" create configmap "$name" \
    --from-literal=mesh.yaml="$mesh_yaml" \
    --dry-run=client -o yaml | kubectl --context "$CONTEXT" apply -f -
}

# Select a Running, Ready, NON-terminating pod IP for the given app label.
# `Terminating` is NOT a pod phase — a deleting pod keeps phase=Running with a
# deletionTimestamp — so a phase filter alone can pick a dying pod's IP during
# a rollout.
wait_for_pod_ip() {
  local app_label="$1"
  local ip="" _
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
    if status.get("phase") != "Running":
        continue
    ready = any(
        c.get("type") == "Ready" and c.get("status") == "True"
        for c in status.get("conditions", [])
    )
    ip = status.get("podIP")
    if ready and ip:
        print(ip)
        break
' 2>/dev/null || true)"
    if [[ -n "$ip" ]]; then
      printf '%s' "$ip"
      return 0
    fi
    sleep 2
  done
  echo "$app_label pod never reported a ready non-terminating pod IP" >&2
  return 1
}

# Destination sidecar mesh document: local svc workload (loopback inbound
# route :15006 -> 127.0.0.1:8080), STRICT PeerAuthentication, an inline-JWKS
# RequestAuthentication, and two AuthorizationPolicies:
#   deny-rogue  identity-scoped DENY of sa/rogue (DENY evaluates before ALLOW)
#   jwt-gate    ALLOW /jwt-protected only with a request principal minted by
#               $JWT_ISSUER; ALLOW every other path unconditionally. Once any
#               ALLOW rule exists, non-matching requests are implicitly denied
#               — so a token-less /jwt-protected request 403s (mesh_authz),
#               while a bad-signature token 401s earlier (jwks_auth).
# Same-trust-domain inbound verification needs no slice trust_bundles: the
# inbound SPIFFE verifier keeps the gateway SVID's LOCAL bundle (only
# cross-domain federation must be declared on the slice).
render_dest_config() {
  apply_configmap ferrum-mesh-dest "$(cat <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/svc
      service_name: svc
      namespace: $NS
      trust_domain: $TRUST_DOMAIN
      service_account: svc
      addresses:
        - 127.0.0.1
      ports:
        - port: 8080
          protocol: http
          name: http
      selector:
        labels:
          app: svc
        namespace: $NS
  services:
    - name: svc
      namespace: $NS
      ports:
        - port: 8080
          protocol: http
          name: http
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/svc
  peer_authentications:
    - name: mesh-strict
      namespace: $NS
      mtls_mode: strict
  request_authentications:
    - name: jwt-fixture
      namespace: $NS
      scope:
        kind: mesh_wide
      jwt_rules:
        - issuer: $JWT_ISSUER
          jwks: '$JWKS_JSON'
  mesh_policies:
    - name: deny-rogue
      namespace: $NS
      scope:
        kind: workload_selector
        selector:
          labels:
            app: svc
          namespace: $NS
      rules:
        - action: deny
          from:
            - spiffe_id_pattern: spiffe://$TRUST_DOMAIN/ns/$NS/sa/rogue
    - name: jwt-gate
      namespace: $NS
      scope:
        kind: workload_selector
        selector:
          labels:
            app: svc
          namespace: $NS
      rules:
        - action: allow
          to:
            - paths: ["/jwt-protected"]
          request_principals: ["$JWT_ISSUER/*"]
        - action: allow
          to:
            - not_paths: ["/jwt-protected"]
YAML
)"
}

# WebSocket destination sidecar mesh document: wssvc is its OWN pod +
# identity (sa/wssvc) because one local pod backs exactly ONE service —
# declaring wssvc as a second local service_name on sa/svc makes
# resolve_local_workloads fail closed (ambiguous local workload) and the dest
# sidecar materializes NO inbound routes (proven live: every probe 404'd).
# STRICT inbound only; the authz/JWT policies stay on the svc destination.
render_wsdest_config() {
  apply_configmap ferrum-mesh-wsdest "$(cat <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/wssvc
      service_name: wssvc
      namespace: $NS
      trust_domain: $TRUST_DOMAIN
      service_account: wssvc
      addresses:
        - 127.0.0.1
      ports:
        - port: 8080
          protocol: http
          name: ws
      selector:
        labels:
          app: wssvc
        namespace: $NS
  services:
    - name: wssvc
      namespace: $NS
      ports:
        - port: 8080
          protocol: http
          name: ws
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/wssvc
  peer_authentications:
    - name: mesh-strict
      namespace: $NS
      mtls_mode: strict
YAML
)"
}

# DestinationRule visibility destinations: each pod's file slice declares the
# beta-owned MeshService `drsvc` with ONLY that pod's local workload (one
# service_name per SPIFFE). FERRUM_NAMESPACE=beta on the pods keeps the
# service visible without a Sidecar on the destination; SPIFFE / SA stay in
# $NS so SPIRE selectors match the real k8s workload.
render_drdest_config() {
  local sa="$1" app_label="$2" cm_name="$3"
  apply_configmap "$cm_name" "$(cat <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/$sa
      service_name: $DR_SERVICE_NAME
      namespace: $DR_SERVICE_NS
      trust_domain: $TRUST_DOMAIN
      service_account: $sa
      addresses:
        - 127.0.0.1
      ports:
        - port: 8080
          protocol: http
          name: http
      selector:
        labels:
          app: $app_label
        namespace: $NS
  services:
    - name: $DR_SERVICE_NAME
      namespace: $DR_SERVICE_NS
      ports:
        - port: 8080
          protocol: http
          name: http
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/$sa
  peer_authentications:
    - name: mesh-strict
      namespace: $DR_SERVICE_NS
      mtls_mode: strict
YAML
)"
}

render_drdest_configs() {
  render_drdest_config drsvc-a drsvc-a ferrum-mesh-drsvc-a
  render_drdest_config drsvc-b drsvc-b ferrum-mesh-drsvc-b
}

# Client/rogue sidecar mesh document: the svc workload at its REAL pod IP
# (sidecar egress dials workload_address:15006 over mesh-mTLS) plus the
# `slowsvc` workload at the black-holed IP with a DestinationRule
# connectTimeout — the parameter the two-phase probe flips. The capp workload
# (the native-MeshSubscribe destination) rides here too so the client's
# CAPTURED egress can reach it — this leg's file config is deliberately
# ordinary; the native-transport proof lives on capp's INBOUND side, whose
# routes only exist if the CP-delivered slice materialized. Rendered only
# after the svc pod IP is known; a svc pod replacement would need a re-render
# + client restart (this fixture never replaces svc).
#
# Optional DestinationRule visibility extras ($5/$6 = labelled drsvc backend
# pod IPs; $7 = additional destination_rules YAML for DR_LIVE_HOST). Cross-
# namespace MeshService ownership (`beta`/`drsvc`) plus a permissive Sidecar
# egress scope (`*/*`) are required: without an applicable Sidecar the file
# slice stays namespace-local and beta services never materialize. Workloads
# keep identity namespace `$NS` with `service_namespace: beta` so they remain
# visible to the ferrum client while attaching to the beta-owned service.
# Istio CRDs are disabled; declaring namespaces are file-mode fields — the
# same model the functional/integration suites use for issues #2465 / #2469.
render_client_config() {
  local svc_pod_ip="$1" wssvc_pod_ip="$2" capp_pod_ip="$3" slow_connect_timeout_ms="$4"
  local dra_ip="${5:-$DR_BACKEND_A_IP}"
  local drb_ip="${6:-$DR_BACKEND_B_IP}"
  local extra_dr_rules="${7:-}"
  local drsvc_workloads_yaml=""
  local drsvc_service_yaml=""
  if [[ -n "$dra_ip" && -n "$drb_ip" ]]; then
    drsvc_workloads_yaml="$(cat <<YAML
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/drsvc-a
      service_name: $DR_SERVICE_NAME
      service_namespace: $DR_SERVICE_NS
      namespace: $NS
      trust_domain: $TRUST_DOMAIN
      service_account: drsvc-a
      addresses:
        - "$dra_ip"
      ports:
        - port: 8080
          protocol: http
          name: http
      selector:
        labels:
          app: drsvc-a
        namespace: $NS
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/drsvc-b
      service_name: $DR_SERVICE_NAME
      service_namespace: $DR_SERVICE_NS
      namespace: $NS
      trust_domain: $TRUST_DOMAIN
      service_account: drsvc-b
      addresses:
        - "$drb_ip"
      ports:
        - port: 8080
          protocol: http
          name: http
      selector:
        labels:
          app: drsvc-b
        namespace: $NS
YAML
)"
    drsvc_service_yaml="$(cat <<YAML
    - name: $DR_SERVICE_NAME
      namespace: $DR_SERVICE_NS
      ports:
        - port: 8080
          protocol: http
          name: http
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/drsvc-a
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/drsvc-b
YAML
)"
  fi
  apply_configmap ferrum-mesh-client "$(cat <<YAML
mesh:
  istio_root_namespace: $DR_ROOT_NS
  # Permissive Sidecar so cross-namespace MeshService beta/drsvc and its
  # DestinationRules are admitted (integration suite pattern for #2465/#2469).
  sidecars:
    - name: client-egress
      namespace: $NS
      egress:
        - hosts: ["*/*"]
  workloads:
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/svc
      service_name: svc
      namespace: $NS
      trust_domain: $TRUST_DOMAIN
      service_account: svc
      addresses:
        - "$svc_pod_ip"
      ports:
        - port: 8080
          protocol: http
          name: http
      selector:
        namespace: $NS
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/capp
      service_name: capp
      namespace: $NS
      trust_domain: $TRUST_DOMAIN
      service_account: capp
      addresses:
        - "$capp_pod_ip"
      ports:
        - port: 8080
          protocol: http
          name: http
      selector:
        namespace: $NS
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/wssvc
      service_name: wssvc
      namespace: $NS
      trust_domain: $TRUST_DOMAIN
      service_account: wssvc
      addresses:
        - "$wssvc_pod_ip"
      ports:
        - port: 8080
          protocol: http
          name: ws
      selector:
        namespace: $NS
    - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/slowsvc
      service_name: slowsvc
      namespace: $NS
      trust_domain: $TRUST_DOMAIN
      service_account: slowsvc
      addresses:
        - "$BLACKHOLE_IP"
      ports:
        - port: 8080
          protocol: http
          name: http
      selector:
        namespace: $NS
$drsvc_workloads_yaml
  services:
    - name: svc
      namespace: $NS
      ports:
        - port: 8080
          protocol: http
          name: http
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/svc
    - name: capp
      namespace: $NS
      ports:
        - port: 8080
          protocol: http
          name: http
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/capp
    - name: wssvc
      namespace: $NS
      ports:
        - port: 8080
          protocol: http
          name: ws
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/wssvc
    - name: slowsvc
      namespace: $NS
      ports:
        - port: 8080
          protocol: http
          name: http
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/slowsvc
$drsvc_service_yaml
  # Issue #4158: an ordinary namespace-scoped Istio AuthorizationPolicy riding
  # the CLIENT slice. AuthorizationPolicy is a destination-side contract, so it
  # must NOT be enforced on the outbound capture leg (:15001) — where the peer
  # is this pod's own curl container over plaintext loopback and no source
  # principal can ever exist. The implicit-deny floor is raised by policy
  # PRESENCE, not by a match, so before the fix this one policy 403'd EVERY
  # probe in this suite that leaves the client pod. It is deliberately left
  # here with no assertion of its own: every existing client egress assertion
  # below is the regression guard, and each of them fails if source-side
  # enforcement ever comes back.
  mesh_policies:
    - name: client-ns-allow
      namespace: $NS
      scope:
        kind: namespace
        namespace: $NS
      rules:
        - action: allow
          from:
            - spiffe_id_pattern: spiffe://$TRUST_DOMAIN/ns/$NS/sa/svc
  # VirtualService-derived CORS (issue #1973): Istio applies VS policy on the
  # CLIENT sidecar, so the policy rides the client slice and the sidecar
  # synthesizes a cors plugin onto its materialized svc outbound route. The
  # plugin only acts on requests that carry an Origin header, so every other
  # probe in this suite is unaffected. (No backticks in this heredoc: it
  # interpolates, so a backticked word would run as command substitution.)
  virtual_service_cors_policies:
    - name: svc-cors
      namespace: $NS
      host: svc.$NS.svc.cluster.local
      cors:
        allowed_origins:
          - exact: "https://fixture.example"
        allowed_methods: ["GET", "POST", "OPTIONS"]
        allowed_headers: ["content-type", "authorization"]
        max_age_seconds: 600
        unmatched_preflights: forward
  destination_rules:
    - name: slowsvc-connect-timeout
      namespace: $NS
      host: slowsvc.$NS.svc.cluster.local
      traffic_policy:
        connect_timeout_ms: $slow_connect_timeout_ms
    # maxConnections=1 on the WS service: one held WebSocket session occupies
    # the sole slot (BackendConnectionGuard held for the session in the WS
    # connect loop), a concurrent second upgrade is rejected 503 before
    # dialing, and the slot frees on session close.
    - name: wssvc-max-connections
      namespace: $NS
      host: wssvc.$NS.svc.cluster.local
      traffic_policy:
        max_connections: 1
$extra_dr_rules
YAML
)"
}

wait_for_rollouts() {
  local deploy
  # ferrum-cp first: its readiness (gRPC :50051 bound, now mTLS) unblocks capp's
  # native-subscribe convergence; capp's POD readiness itself only requires
  # the app container (the sidecar container has no probe and counts as
  # ready while it waits for its first slice).
  for deploy in ferrum-cp svc wssvc capp client rogue drsvc-a drsvc-b; do
    kubectl --context "$CONTEXT" -n "$NS" rollout status "deploy/$deploy" --timeout=5m
  done
}

# ── probes ──────────────────────────────────────────────────────────────────
#
# All captured probes mirror the federation fixture's drive_request: a
# plaintext HTTP GET sent straight at the sidecar's outbound capture listener
# (:15001) with the destination FQDN as Host. The pod-side script reads its
# parameters from argv so nothing crosses the quote boundary; /tmp/body is
# truncated before every attempt because curl does NOT rewrite -o on a
# connection failure (a stale 200 body must never leak into a negative probe).
# A kubectl-exec failure yields the distinct EXECFAIL sentinel so infra
# failures can never masquerade as datapath outcomes.

# Retry until the response settles on (want_status [+ body grep]); echoes the
# final "<status>\t<body>". Optional 6th arg selects the destination Host
# (defaults to the svc FQDN).
drive_settle() {
  local deploy="$1" path="$2" bearer="$3" want_status="$4" want_body_grep="$5"
  local host="${6:-$SVC_HOST}"
  # shellcheck disable=SC2016
  kubectl --context "$CONTEXT" -n "$NS" exec "deploy/$deploy" -c curl -- \
    sh -c '
      host="$1"; path="$2"; bearer="$3"; want="$4"; grepstr="$5"
      out=000
      body=""
      for _ in $(seq 1 30); do
        : >/tmp/body 2>/dev/null || true
        if [ -n "$bearer" ]; then
          out="$(curl -s -m 10 -o /tmp/body -w "%{http_code}" \
            -H "Host: $host" -H "Authorization: Bearer $bearer" \
            "http://127.0.0.1:15001$path" 2>/dev/null || echo 000)"
        else
          out="$(curl -s -m 10 -o /tmp/body -w "%{http_code}" \
            -H "Host: $host" "http://127.0.0.1:15001$path" 2>/dev/null || echo 000)"
        fi
        body="$(tr -d "\r\n" </tmp/body 2>/dev/null || true)"
        if [ "$out" = "$want" ]; then
          if [ -z "$grepstr" ] || printf "%s" "$body" | grep -q "$grepstr"; then
            printf "%s\t%s\n" "$out" "$body"
            exit 0
          fi
        fi
        sleep 2
      done
      printf "%s\t%s\n" "$out" "$body"
    ' sh "$host" "$path" "$bearer" "$want_status" "$want_body_grep" \
    2>/dev/null || printf 'EXECFAIL\t'
}

probe_authenticated_positive() {
  log "probing authenticated client -> svc (STRICT mTLS positive)"
  local out status body
  out="$(drive_settle client / "" 200 "$APP_BODY")"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "client -> svc: status=$status body=$body"
  if [[ "$status" == "200" && "$body" == *"$APP_BODY"* ]]; then
    record_live_assertion sidecar.peer_auth.strict_mtls_authenticated pass \
      client svc "status=$status body=$body"
  else
    record_live_assertion sidecar.peer_auth.strict_mtls_authenticated fail \
      client svc "status=$status body=$body"
    return 1
  fi
}

# Plaintext dial at the svc pod's CAPTURED app port (8080) from the client's
# curl container: PREROUTING REDIRECTs it to :15006, whose STRICT listener
# rejects plaintext — the request must never reach the app. The request
# carries the SERVICE FQDN Host so that if STRICT ever regressed to ACCEPTING
# plaintext, the request would match the materialized inbound route and reach
# the app (SERVED, failing the assertion) instead of route-missing on a
# pod-IP Host and masquerading as a rejection. Samples a few times and
# short-circuits SERVED if the app ever answers (a capture or STRICT
# regression), so a flaky rejection cannot mask a real bypass.
probe_plaintext_rejected() {
  log "probing plaintext dial to captured app port (STRICT negative)"
  local out verdict status body rest
  # shellcheck disable=SC2016
  out="$(kubectl --context "$CONTEXT" -n "$NS" exec deploy/client -c curl -- \
    sh -c '
      ip="$1"; host="$2"; marker="$3"
      out=000
      body=""
      for _ in 1 2 3; do
        : >/tmp/pt 2>/dev/null || true
        # curl can emit its -w "000" AND fail (connection reset after send),
        # so an `|| echo 000` fallback would double up as "000000" in the
        # recorded outcome; normalize the empty case instead.
        out="$(curl -s -m 5 -o /tmp/pt -w "%{http_code}" \
          -H "Host: $host" "http://$ip:8080/" 2>/dev/null || true)"
        [ -n "$out" ] || out=000
        body="$(tr -d "\r\n" </tmp/pt 2>/dev/null || true)"
        if [ "$out" = "200" ] || printf "%s" "$body" | grep -q "$marker"; then
          printf "SERVED\t%s\t%s\n" "$out" "$body"
          exit 0
        fi
        sleep 1
      done
      printf "REJECTED\t%s\t%s\n" "$out" "$body"
    ' sh "$SVC_POD_IP" "$SVC_HOST" "$APP_BODY" 2>/dev/null || printf 'EXECFAIL\t\t')"
  verdict="${out%%$'\t'*}"
  rest="${out#*$'\t'}"
  status="${rest%%$'\t'*}"
  body="${rest#*$'\t'}"
  log "plaintext -> svc:8080: verdict=$verdict status=$status body=$body"
  if [[ "$verdict" == "REJECTED" ]]; then
    record_live_assertion sidecar.peer_auth.strict_mtls_plaintext_rejected pass \
      client svc "plaintext-captured-dial-rejected status=$status"
  else
    record_live_assertion sidecar.peer_auth.strict_mtls_plaintext_rejected fail \
      client svc "verdict=$verdict status=$status body=$body"
    return 1
  fi
}

probe_rogue_denied() {
  log "probing rogue -> svc (expect dest-side authz DENY)"
  # The proof is a 403 sourced by the destination's mesh_authz (its exact
  # body), NOT merely any non-200 (which a client-side TLS failure would also
  # produce without ever reaching the destination).
  local out status body
  out="$(drive_settle rogue / "" 403 "Mesh authorization denied")"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "rogue -> svc: status=$status body=$body"
  if [[ "$status" == "403" && "$body" == *"Mesh authorization denied"* && "$body" != *"$APP_BODY"* ]]; then
    record_live_assertion sidecar.authz.denied_principal_rejected pass \
      rogue svc "dest-side-mesh-authz-denied status=$status body=$body"
  else
    record_live_assertion sidecar.authz.denied_principal_rejected fail \
      rogue svc "rogue-not-rejected-by-dest-authz status=$status body=$body"
    return 1
  fi
}

probe_request_auth() {
  log "probing RequestAuthentication JWT gate on /jwt-protected"
  local out status body

  # Valid RS256 token -> jwks_auth validates against the inline JWKS, stamps
  # the request principal, jwt-gate's ALLOW matches -> 200.
  out="$(drive_settle client /jwt-protected "$JWT_VALID" 200 "$APP_BODY")"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "valid JWT: status=$status body=$body"
  if [[ "$status" == "200" && "$body" == *"$APP_BODY"* ]]; then
    record_live_assertion sidecar.request_auth.valid_jwt_admitted pass \
      client svc "status=$status body=$body"
  else
    record_live_assertion sidecar.request_auth.valid_jwt_admitted fail \
      client svc "status=$status body=$body"
    return 1
  fi

  # No token -> RequestAuthentication passes through unauthenticated (Istio
  # semantics) and jwt-gate's ALLOW does not match -> implicit deny 403 with
  # mesh_authz's body.
  out="$(drive_settle client /jwt-protected "" 403 "Mesh authorization denied")"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "missing JWT: status=$status body=$body"
  if [[ "$status" == "403" && "$body" == *"Mesh authorization denied"* && "$body" != *"$APP_BODY"* ]]; then
    record_live_assertion sidecar.request_auth.missing_jwt_rejected pass \
      client svc "status=$status body=$body"
  else
    record_live_assertion sidecar.request_auth.missing_jwt_rejected fail \
      client svc "status=$status body=$body"
    return 1
  fi

  # Well-formed token signed by the WRONG key (same kid/issuer) -> signature
  # verification fails in jwks_auth -> 401 before authz runs.
  out="$(drive_settle client /jwt-protected "$JWT_WRONG_KEY" 401 "Invalid or unrecognized JWT")"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "wrong-key JWT: status=$status body=$body"
  if [[ "$status" == "401" && "$body" == *"Invalid or unrecognized JWT"* && "$body" != *"$APP_BODY"* ]]; then
    record_live_assertion sidecar.request_auth.invalid_jwt_rejected pass \
      client svc "status=$status body=$body"
  else
    record_live_assertion sidecar.request_auth.invalid_jwt_rejected fail \
      client svc "status=$status body=$body"
    return 1
  fi
}

# VirtualService-derived CORS on the client sidecar (issue #1973): the policy
# rides the mesh slice and the sidecar synthesizes a `cors` plugin onto its
# materialized svc outbound route. Four observations, one assertion:
#   a) GET with the ALLOWED Origin -> 200 + the app marker + the origin
#      reflected in `access-control-allow-origin` (retried until the route
#      settles);
#   b) OPTIONS preflight (allowed Origin + Access-Control-Request-Method) ->
#      200 answered BY THE SIDECAR with `access-control-allow-methods`
#      containing GET — the preflight never reaches the destination;
#   c) GET with an UNMATCHED Origin -> backend 200 + app marker, without a
#      gateway-added access-control-allow-origin field; and
#   d) unmatched OPTIONS preflight -> backend 200 + app marker, also without
#      gateway-added CORS authorization (omitted/FORWARD semantics).
probe_vs_cors() {
  log "probing VirtualService-derived CORS on the svc outbound route"
  local out a_status a_acao b_status b_methods c_status c_acao c_body d_status d_acao d_body rest
  # shellcheck disable=SC2016
  out="$(kubectl --context "$CONTEXT" -n "$NS" exec deploy/client -c curl -- \
    sh -c '
      host="$1"; good="$2"; evil="$3"; marker="$4"
      tab="$(printf "\t")"
      acao_exact() {
        while IFS= read -r line || [ -n "$line" ]; do
          line="$(printf "%s" "$line" | tr -d "\r")"
          case "$line" in
            *:*)
              name="${line%%:*}"
              value="${line#*:}"
              while :; do case "$value" in " "*) value="${value#?}";; "$tab"*) value="${value#?}";; *) break;; esac; done
              while :; do case "$value" in *" ") value="${value%?}";; *"$tab") value="${value%?}";; *) break;; esac; done
              lname="$(printf "%s" "$name" | tr "[:upper:]" "[:lower:]")"
              if [ "$lname" = "access-control-allow-origin" ] && [ "$value" = "$2" ]; then return 0; fi
              ;;
          esac
        done < "$1"
        return 1
      }
      a_status=000
      a_acao=no
      a_body=""
      for _ in $(seq 1 30); do
        : >/tmp/b 2>/dev/null || true
        : >/tmp/h 2>/dev/null || true
        a_status="$(curl -s -m 10 -o /tmp/b -D /tmp/h -w "%{http_code}" \
          -H "Host: $host" -H "Origin: $good" http://127.0.0.1:15001/ 2>/dev/null || true)"
        [ -n "$a_status" ] || a_status=000
        a_body="$(tr -d "\r\n" </tmp/b 2>/dev/null || true)"
        if [ "$a_status" = "200" ] \
          && acao_exact /tmp/h "$good" \
          && printf "%s" "$a_body" | grep -q "$marker"; then
          a_acao=yes
          break
        fi
        sleep 2
      done
      : >/tmp/h2 2>/dev/null || true
      b_status="$(curl -s -m 10 -o /dev/null -D /tmp/h2 -w "%{http_code}" \
        -X OPTIONS -H "Host: $host" -H "Origin: $good" \
        -H "Access-Control-Request-Method: GET" http://127.0.0.1:15001/ 2>/dev/null || true)"
      [ -n "$b_status" ] || b_status=000
      b_methods=no
      grep -qi "^access-control-allow-methods:.*GET" /tmp/h2 && b_methods=yes
      : >/tmp/b3 2>/dev/null || true
      : >/tmp/h3 2>/dev/null || true
      c_status="$(curl -s -m 10 -o /tmp/b3 -D /tmp/h3 -w "%{http_code}" \
        -H "Host: $host" -H "Origin: $evil" http://127.0.0.1:15001/ 2>/dev/null || true)"
      [ -n "$c_status" ] || c_status=000
      c_acao=no
      grep -qi "^access-control-allow-origin:" /tmp/h3 && c_acao=yes
      c_body="$(tr -d "\r\n" </tmp/b3 2>/dev/null || true)"
      : >/tmp/b4 2>/dev/null || true
      : >/tmp/h4 2>/dev/null || true
      d_status="$(curl -s -m 10 -o /tmp/b4 -D /tmp/h4 -w "%{http_code}" \
        -X OPTIONS -H "Host: $host" -H "Origin: $evil" \
        -H "Access-Control-Request-Method: GET" http://127.0.0.1:15001/ 2>/dev/null || true)"
      [ -n "$d_status" ] || d_status=000
      d_acao=no
      grep -qi "^access-control-allow-origin:" /tmp/h4 && d_acao=yes
      d_body="$(tr -d "\r\n" </tmp/b4 2>/dev/null || true)"
      printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
        "$a_status" "$a_acao" "$b_status" "$b_methods" "$c_status" "$c_acao" \
        "$c_body" "$d_status" "$d_acao" "$d_body"
    ' sh "$SVC_HOST" "https://fixture.example" "https://evil.example" "$APP_BODY" \
    2>/dev/null || printf 'EXECFAIL\tno\t000\tno\t000\tyes\t\t000\tyes\t')"
  a_status="${out%%$'\t'*}"
  rest="${out#*$'\t'}"
  a_acao="${rest%%$'\t'*}"
  rest="${rest#*$'\t'}"
  b_status="${rest%%$'\t'*}"
  rest="${rest#*$'\t'}"
  b_methods="${rest%%$'\t'*}"
  rest="${rest#*$'\t'}"
  c_status="${rest%%$'\t'*}"
  rest="${rest#*$'\t'}"
  c_acao="${rest%%$'\t'*}"
  rest="${rest#*$'\t'}"
  c_body="${rest%%$'\t'*}"
  rest="${rest#*$'\t'}"
  d_status="${rest%%$'\t'*}"
  rest="${rest#*$'\t'}"
  d_acao="${rest%%$'\t'*}"
  d_body="${rest#*$'\t'}"
  log "VS CORS: allowed=$a_status/acao=$a_acao preflight=$b_status/methods=$b_methods unmatched=$c_status/acao=$c_acao/body=$c_body unmatched-preflight=$d_status/acao=$d_acao/body=$d_body"
  if [[ "$a_status" == "200" && "$a_acao" == "yes" && "$b_status" == "200" \
    && "$b_methods" == "yes" && "$c_status" == "200" && "$c_acao" == "no" \
    && "$c_body" == *"$APP_BODY"* && "$d_status" == "200" && "$d_acao" == "no" \
    && "$d_body" == *"$APP_BODY"* ]]; then
    record_live_assertion sidecar.virtual_service.cors_policy pass \
      client svc \
      "allowed=200+acao preflight=200+methods unmatched-actual/preflight=backend-200-no-acao"
  else
    record_live_assertion sidecar.virtual_service.cors_policy fail \
      client svc \
      "allowed=$a_status/acao=$a_acao preflight=$b_status/methods=$b_methods unmatched=$c_status/acao=$c_acao/body=$c_body unmatched-preflight=$d_status/acao=$d_acao/body=$d_body"
    return 1
  fi
}

# Native MeshSubscribe delivery (issue #2002). Two observations, one
# assertion:
#   a) TRAFFIC (the load-bearing proof): a captured client request to the
#      capp FQDN answers 200 with capp's DISTINCT app marker. capp's sidecar
#      runs FERRUM_MESH_CONFIG_PROTOCOL=native with NO ConfigMap — its :15006
#      inbound routes exist ONLY if the ferrum-cp MeshSubscribe stream
#      delivered a slice whose K8s-built capp workload resolved as the local
#      workload. If delivery failed, mesh startup is still blocked in
#      wait_for_initial_mesh_config (nothing listens) or no inbound route
#      matches (404) — either way this probe cannot settle on 200+marker.
#   b) DIAGNOSTICS (also required — it attributes the transport): the capp
#      sidecar's JWT-authenticated GET /mesh/config-drift must report a
#      received slice (slice.last_received_at set), source_protocol=native, a
#      ferrum-cp source_cp_url, and at least one service in the slice. The
#      admin API binds loopback, so the curl runs inside the capp pod; the
#      bearer is HS256-minted by run.sh against the shared Secret.
probe_native_subscribe() {
  log "probing native MeshSubscribe delivery (client -> capp via CP-served slice)"
  local out status body
  out="$(drive_settle client / "" 200 "$NATIVE_APP_MARKER" "$CAPP_HOST")"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "client -> capp: status=$status body=$body"
  local traffic_ok=false
  if [[ "$status" == "200" && "$body" == *"$NATIVE_APP_MARKER"* ]]; then
    traffic_ok=true
  fi

  local admin_token drift_json
  admin_token="$(mint_admin_jwt)"
  # shellcheck disable=SC2016
  drift_json="$(kubectl --context "$CONTEXT" -n "$NS" exec deploy/capp -c curl -- \
    sh -c '
      token="$1"
      out=""
      for _ in $(seq 1 15); do
        out="$(curl -s -m 10 -H "Authorization: Bearer $token" \
          http://127.0.0.1:15020/mesh/config-drift 2>/dev/null || true)"
        if [ -n "$out" ]; then
          printf "%s\n" "$out"
          exit 0
        fi
        sleep 2
      done
      printf "%s\n" "$out"
    ' sh "$admin_token" 2>/dev/null || printf '')"
  printf '%s\n' "$drift_json" > "$RESULTS_DIR/native-config-drift.txt"

  local drift_verdict
  drift_verdict="$(printf '%s' "$drift_json" | python3 -c '
import json
import sys

try:
    doc = json.load(sys.stdin)
except Exception:
    print("drift-unparseable")
    sys.exit(0)
sl = doc.get("slice") or {}
received = bool(sl.get("last_received_at"))
protocol = sl.get("source_protocol")
cp_url = sl.get("source_cp_url") or ""
services = (sl.get("resources") or {}).get("services") or 0
if received and protocol == "native" and "ferrum-cp" in cp_url and cp_url.startswith("https://") and services >= 1:
    print(f"native-slice-received services={services} cp={cp_url}")
else:
    print(
        "drift-unexpected "
        f"received={received} protocol={protocol} cp={cp_url} services={services}"
    )
')"
  log "capp config-drift: $drift_verdict"

  if [[ "$traffic_ok" == "true" && "$drift_verdict" == native-slice-received* ]]; then
    record_live_assertion sidecar.config.native_subscribe_delivered pass \
      client capp \
      "status=$status body=$body $drift_verdict" \
      "native-config-drift.txt"
  else
    record_live_assertion sidecar.config.native_subscribe_delivered fail \
      client capp \
      "traffic status=$status body=$body drift=$drift_verdict" \
      "native-config-drift.txt"
    return 1
  fi
}

# Redact PEM, bearer tokens, and long hex secrets from probe evidence so
# readiness/diagnostics stay at class/reason level.
redact_native_transport_evidence() {
  python3 -c '
import re, sys
text = sys.stdin.read()
text = re.sub(
    r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----",
    "[redacted-pem]",
    text,
    flags=re.S,
)
text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._\-=]+", "bearer [redacted]", text)
text = re.sub(r"(?i)(jwt|secret|token)=[A-Za-z0-9+/=._\-]{16,}", r"\1=[redacted]", text)
print(text[:2000])
'
}

native_probe_container_running() {
  local deploy="$1"
  kubectl --context "$CONTEXT" -n "$NS" get pod -l "app=$deploy" -o json 2>/dev/null |
    python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for pod in data.get("items", []):
    if pod.get("metadata", {}).get("deletionTimestamp"):
        continue
    status = pod.get("status", {})
    if status.get("phase") != "Running":
        continue
    for cs in status.get("containerStatuses", []):
        if cs.get("name") == "ferrum-edge":
            waiting = (cs.get("state") or {}).get("waiting") or {}
            if waiting.get("reason") in ("CrashLoopBackOff", "Error", "ImagePullBackOff"):
                sys.exit(2)
            if cs.get("ready") is False and (cs.get("restartCount") or 0) > 2:
                sys.exit(2)
            if (cs.get("state") or {}).get("running"):
                sys.exit(0)
sys.exit(1)
'
}

native_probe_logs() {
  local deploy="$1"
  kubectl --context "$CONTEXT" -n "$NS" logs "deploy/$deploy" -c ferrum-edge \
    --tail=200 2>/dev/null || true
}

native_cp_logs() {
  kubectl --context "$CONTEXT" -n "$NS" logs deploy/ferrum-cp -c ferrum-edge \
    --tail=400 2>/dev/null || true
}

native_probe_running_identity() {
  local deploy="$1"
  kubectl --context "$CONTEXT" -n "$NS" get pod -l "app=${deploy}" -o json 2>/dev/null |
    python3 "$NATIVE_PROBE_CLASSIFY_HELPER" --running-identity --deploy "$deploy"
}

# Classify a dedicated native-subscribe probe. Distinguishes:
#   crash            process never stayed up (unrelated startup failure)
#   slice-accepted   MeshSubscribe delivered a slice (false-positive for a negative)
#   jwt              mTLS connected, then JWT/UNAUTHENTICATED (client or CP)
#   tls-name         hostname/SAN verification failed (never connected)
#   tls-verify       server-certificate trust failed, or CP rejected a foreign client cert
#   tls-handshake    TLS/mTLS handshake failed before subscribe (never connected)
#   noop             running but no MeshSubscribe attempt evidence
#
# Client `Connected to CP` is only a transient transport-attempt signal and
# must not override exact CP evidence correlated to this probe's pod IP
# (pre-subscribe TLS) or pod/node name (tenant-subscription JWT reject).
# Client-side untrusted-CA / wrong-SAN require native_tls_class
# client_tls_verify / client_tls_name; a generic handshake is not proof.
# Classifier --evidence-out writes one line plus newline; joining with tr '\n' ' '
# leaves a trailing space that breaks anchored evidence greps (^token$).
normalize_native_evidence_file() {
  local path="$1"
  local normalized=""
  if [[ -f "$path" ]]; then
    normalized="$(tr '\n' ' ' < "$path")"
    normalized="${normalized%"${normalized##*[![:space:]]}"}"
  fi
  printf '%s' "$normalized"
}

classify_native_probe() {
  local deploy="$1"
  local logs identity pod_name="" pod_ip="" client_file cp_file evidence_file st
  evidence_file="$RESULTS_DIR/${deploy}.server-evidence.txt"
  if ! native_probe_container_running "$deploy"; then
    printf 'none\n' > "$evidence_file" || true
    printf 'crash'
    return 0
  fi
  logs="$(native_probe_logs "$deploy")"
  identity="$(native_probe_running_identity "$deploy" 2>/dev/null || true)"
  if [[ "$identity" == *$'\t'* ]]; then
    pod_name="${identity%%$'\t'*}"
    pod_ip="${identity#*$'\t'}"
    pod_ip="${pod_ip%%$'\n'*}"
  fi
  client_file="$RESULTS_DIR/${deploy}.client-log.tmp"
  cp_file="$RESULTS_DIR/${deploy}.cp-log.tmp"
  printf '%s\n' "$logs" > "$client_file"
  native_cp_logs > "$cp_file"
  st=0
  python3 "$NATIVE_PROBE_CLASSIFY_HELPER" --classify \
    --pod-name "$pod_name" \
    --pod-ip "$pod_ip" \
    --client-log "$client_file" \
    --cp-log "$cp_file" \
    --evidence-out "$evidence_file" || st=$?
  rm -f "$client_file" "$cp_file"
  if [[ "$st" -ne 0 ]]; then
    printf 'noop'
  fi
}

wait_for_native_probe_class() {
  local deploy="$1" want="${2:-}" want_evidence="${3:-}"
  local class="" server_ev="" _
  # Client "Connected to CP" is a transient transport-attempt; the helper may
  # still return connected-without-jwt-class until exact CP evidence for this
  # probe is visible. A matching class alone is not enough when want_evidence
  # is set — generic client handshake/verify lines may arrive first. 30*2s
  # covers image-already-loaded scheduling plus one reconnect.
  for _ in $(seq 1 30); do
    if native_probe_container_running "$deploy"; then
      class="$(classify_native_probe "$deploy")"
      if [[ "$class" == slice-accepted || "$class" == crash || "$class" == leaked-material ]]; then
        printf '%s' "$class"
        return 0
      fi
      server_ev="$(normalize_native_evidence_file "$RESULTS_DIR/${deploy}.server-evidence.txt")"
      if [[ -n "$want" ]]; then
        if printf '%s' "$class" | grep -Eq "^($want)$"; then
          if [[ -z "$want_evidence" ]] \
            || printf '%s' "$server_ev" | grep -Eq "$want_evidence"; then
            printf '%s' "$class"
            return 0
          fi
        fi
      elif [[ "$class" != "noop" && "$class" != "connected-without-jwt-class" ]]; then
        printf '%s' "$class"
        return 0
      fi
    fi
    sleep 2
  done
  if native_probe_container_running "$deploy"; then
    classify_native_probe "$deploy"
  else
    printf 'crash'
  fi
}

apply_native_mtls_probe() {
  local name="$1"
  local cp_url="$2"
  local jwt_key="$3"
  local secret_name="$4"
  local mount_client="${5:-true}"
  local client_env="" client_items=""
  if [[ "$mount_client" == "true" ]]; then
    client_env=$(cat <<YAML
            - name: FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH
              value: /transport/client.pem
            - name: FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH
              value: /transport/client-key.pem
YAML
)
    client_items=$(cat <<YAML
                    - key: client.pem
                      path: client.pem
                    - key: client-key.pem
                      path: client-key.pem
YAML
)
  fi
  kubectl --context "$CONTEXT" -n "$NS" apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $name
  namespace: $NS
  labels:
    app: $name
    ferrum.io/native-mtls-probe: "true"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: $name
  template:
    metadata:
      labels:
        app: $name
        ferrum.io/native-mtls-probe: "true"
    spec:
      serviceAccountName: native-mtls-probe
      securityContext:
        fsGroup: 1337
      containers:
        - name: ferrum-edge
          image: $IMAGE
          imagePullPolicy: IfNotPresent
          args: ["run"]
          securityContext:
            runAsUser: 1337
            runAsNonRoot: true
            allowPrivilegeEscalation: false
          env:
            - name: FERRUM_MODE
              value: mesh
            - name: FERRUM_MESH_TOPOLOGY
              value: sidecar
            - name: FERRUM_MESH_CONFIG_PROTOCOL
              value: native
            - name: FERRUM_DP_CP_GRPC_URLS
              value: $cp_url
            - name: FERRUM_DP_GRPC_TLS_CA_CERT_PATH
              value: /transport/ca.pem
$client_env
            - name: FERRUM_CP_DP_GRPC_JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: ferrum-mesh-e2e-secrets
                  key: $jwt_key
            - name: FERRUM_NAMESPACE
              value: $NS
            - name: FERRUM_MESH_PRODUCTION_MODE
              value: "true"
            - name: FERRUM_MESH_CA_BACKEND
              value: spire_agent
            - name: FERRUM_MESH_SPIRE_AGENT_SOCKET
              value: /run/spire/sockets/agent.sock
            - name: FERRUM_MESH_WORKLOAD_SPIFFE_ID
              value: spiffe://$TRUST_DOMAIN/ns/$NS/sa/native-mtls-probe
            - name: FERRUM_ADMIN_HTTP_PORT
              value: "15020"
            - name: FERRUM_POOL_WARMUP_ENABLED
              value: "false"
            - name: FERRUM_LOG_LEVEL
              value: info
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
            - name: transport
              mountPath: /transport
              readOnly: true
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
            type: DirectoryOrCreate
        - name: transport
          projected:
            defaultMode: 0440
            sources:
              - secret:
                  name: $secret_name
                  items:
                    - key: ca.pem
                      path: ca.pem
$client_items
YAML
}

delete_native_mtls_probes() {
  kubectl --context "$CONTEXT" -n "$NS" delete deploy \
    -l ferrum.io/native-mtls-probe=true --wait=true --timeout=60s \
    >/dev/null 2>&1 || true
}

record_native_negative() {
  local assertion_id="$1" deploy="$2" want_pattern="$3" want_evidence="${4:-}"
  local class evidence server_ev=""
  class="$(wait_for_native_probe_class "$deploy" "$want_pattern" "$want_evidence")"
  server_ev="$(normalize_native_evidence_file "$RESULTS_DIR/${deploy}.server-evidence.txt")"
  evidence="$(native_probe_logs "$deploy" | redact_native_transport_evidence | tr '\n' ' ')"
  printf 'class=%s\nserver=%s\nclient=%s\n' "$class" "$server_ev" "$evidence" \
    > "$RESULTS_DIR/${deploy}.txt"
  log "$deploy class=$class (want $want_pattern evidence=$want_evidence) server=${server_ev}"
  if [[ "$class" == slice-accepted || "$class" == crash || "$class" == leaked-material || "$class" == noop ]]; then
    record_live_assertion "$assertion_id" fail "$deploy" ferrum-cp \
      "class=$class want=$want_pattern evidence=$want_evidence server=${server_ev}" "${deploy}.txt"
    return 1
  fi
  if printf '%s' "$class" | grep -Eq "^($want_pattern)$" \
    && { [[ -z "$want_evidence" ]] || printf '%s' "$server_ev" | grep -Eq "$want_evidence"; }; then
    record_live_assertion "$assertion_id" pass "$deploy" ferrum-cp \
      "class=$class server=${server_ev}" "${deploy}.txt"
    return 0
  fi
  record_live_assertion "$assertion_id" fail "$deploy" ferrum-cp \
    "class=$class want=$want_pattern evidence=$want_evidence server=${server_ev}" "${deploy}.txt"
  return 1
}

probe_native_mtls_negatives() {
  local url="https://$NATIVE_CP_DNS:50051"
  local wrong="https://$NATIVE_WRONG_SAN_DNS:50051"
  local failed=false
  log "deploying dedicated native MeshSubscribe mTLS/JWT negative probes"
  apply_native_mtls_probe native-omit-client "$url" cp-dp-grpc-jwt-secret \
    ferrum-native-mtls-omit-client false
  apply_native_mtls_probe native-foreign-client "$url" cp-dp-grpc-jwt-secret \
    ferrum-native-mtls-foreign true
  apply_native_mtls_probe native-untrusted-ca "$url" cp-dp-grpc-jwt-secret \
    ferrum-native-mtls-untrusted true
  apply_native_mtls_probe native-wrong-san "$wrong" cp-dp-grpc-jwt-secret \
    ferrum-native-mtls-dp true
  apply_native_mtls_probe native-jwt-invalid "$url" cp-dp-grpc-jwt-secret-invalid \
    ferrum-native-mtls-dp true

  record_native_negative sidecar.config.native_subscribe_mtls_omitted_client_rejected \
    native-omit-client tls-handshake "$NATIVE_EVID_CP_NO_CERT" || failed=true
  record_native_negative sidecar.config.native_subscribe_mtls_foreign_client_rejected \
    native-foreign-client tls-verify "$NATIVE_EVID_CP_UNKNOWN_ISSUER" || failed=true
  record_native_negative sidecar.config.native_subscribe_tls_untrusted_server_ca_rejected \
    native-untrusted-ca tls-verify "$NATIVE_EVID_CLIENT_SERVER_VERIFY" || failed=true
  record_native_negative sidecar.config.native_subscribe_tls_wrong_san_rejected \
    native-wrong-san tls-name "$NATIVE_EVID_CLIENT_TLS_NAME" || failed=true
  record_native_negative sidecar.config.native_subscribe_jwt_rejected \
    native-jwt-invalid jwt "$NATIVE_EVID_CP_JWT_AUTH_FAILED" || failed=true

  delete_native_mtls_probes
  if [[ "$failed" == "true" ]]; then
    return 1
  fi
}

native_rotation_component_logs() {
  local target="$1"
  # Full current-container logs so the pre-swap baseline cannot slide out of a
  # --tail window and later be mistaken for a post-swap increase.
  kubectl --context "$CONTEXT" -n "$NS" logs "$target" -c ferrum-edge \
    --tail=-1 2>/dev/null || true
}

native_rotation_client_logs() {
  # node_id is withheld in application logs. Bind evidence to the original
  # running pod through kubectl provenance, including the container name.
  # Never select deploy/capp here: a replacement pod must not supply proof.
  kubectl --context "$CONTEXT" -n "$NS" logs "pod/$NATIVE_ROTATION_NODE_ID" \
    -c ferrum-edge --prefix=true --tail=-1 2>/dev/null || true
}

count_native_rotation_observations() {
  local client_file cp_file
  client_file="$RESULTS_DIR/native-rotation.client-log.tmp"
  cp_file="$RESULTS_DIR/native-rotation.cp-log.tmp"
  native_rotation_client_logs > "$client_file"
  native_rotation_component_logs deploy/ferrum-cp > "$cp_file"
  python3 "$NATIVE_PROBE_CLASSIFY_HELPER" --rotation-count \
    --pod-name "$NATIVE_ROTATION_NODE_ID" \
    --client-log "$client_file" \
    --cp-log "$cp_file"
  rm -f "$client_file" "$cp_file"
}

capture_native_rotation_baseline() {
  local identity raw cp_count client_count
  NATIVE_ROTATION_BASELINE_CAPTURED=false
  NATIVE_ROTATION_NODE_ID=""
  NATIVE_ROTATION_POD_IP=""
  NATIVE_ROTATION_BASELINE_CP=0
  NATIVE_ROTATION_BASELINE_CLIENT=0
  identity="$(native_probe_running_identity capp 2>/dev/null || true)"
  if [[ "$identity" != *$'\t'* ]]; then
    log "native TLS rotation baseline: failed to read running capp identity"
    return 1
  fi
  NATIVE_ROTATION_NODE_ID="${identity%%$'\t'*}"
  NATIVE_ROTATION_POD_IP="${identity#*$'\t'}"
  NATIVE_ROTATION_POD_IP="${NATIVE_ROTATION_POD_IP%%$'\n'*}"
  raw="$(count_native_rotation_observations 2>/dev/null || true)"
  if [[ "$raw" != *$'\t'* ]]; then
    log "native TLS rotation baseline: helper count failed for node_id=$NATIVE_ROTATION_NODE_ID"
    return 1
  fi
  cp_count="${raw%%$'\t'*}"
  client_count="${raw#*$'\t'}"
  client_count="${client_count%%$'\n'*}"
  if [[ ! "$cp_count" =~ ^[0-9]+$ || ! "$client_count" =~ ^[0-9]+$ ]]; then
    log "native TLS rotation baseline: non-integer counts raw=$raw"
    return 1
  fi
  if (( cp_count < 1 || client_count < 1 )); then
    log "native TLS rotation baseline: missing accepted connection cp=$cp_count client=$client_count"
    return 1
  fi
  NATIVE_ROTATION_BASELINE_CP="$cp_count"
  NATIVE_ROTATION_BASELINE_CLIENT="$client_count"
  NATIVE_ROTATION_BASELINE_CAPTURED=true
  log "native TLS rotation baseline: node_id=$NATIVE_ROTATION_NODE_ID pod_ip=$NATIVE_ROTATION_POD_IP cp_accepted=$NATIVE_ROTATION_BASELINE_CP client_tls_connect=$NATIVE_ROTATION_BASELINE_CLIENT"
}

native_rotation_fresh_now() {
  local client_file cp_file evidence_file st
  evidence_file="$RESULTS_DIR/native-mtls-rotation-reconnect.txt"
  if [[ "$NATIVE_ROTATION_BASELINE_CAPTURED" != "true" \
    || -z "$NATIVE_ROTATION_NODE_ID" ]]; then
    printf 'baseline-missing\n' > "$evidence_file" || true
    return 1
  fi
  client_file="$RESULTS_DIR/native-rotation.client-log.tmp"
  cp_file="$RESULTS_DIR/native-rotation.cp-log.tmp"
  native_rotation_client_logs > "$client_file"
  native_rotation_component_logs deploy/ferrum-cp > "$cp_file"
  st=0
  python3 "$NATIVE_PROBE_CLASSIFY_HELPER" --rotation-fresh \
    --pod-name "$NATIVE_ROTATION_NODE_ID" \
    --client-log "$client_file" \
    --cp-log "$cp_file" \
    --baseline-cp "$NATIVE_ROTATION_BASELINE_CP" \
    --baseline-client "$NATIVE_ROTATION_BASELINE_CLIENT" \
    --evidence-out "$evidence_file" >/dev/null || st=$?
  rm -f "$client_file" "$cp_file"
  return "$st"
}

wait_for_native_rotation_evidence() {
  local _
  # Reload publications are temporal generation anchors only, never proof by
  # themselves, and reconnect-attempt logs can fire while capp stays on
  # last-known-good. Require the captured exact capp pod/node identity, a
  # post-baseline dp_grpc reload in capp logs followed by a subsequent
  # exact-node Connected-to-CP, and a post-baseline cp_grpc reload in CP
  # logs followed by a subsequent exact-node Tenant subscription accepted.
  if [[ "$NATIVE_ROTATION_BASELINE_CAPTURED" != "true" \
    || -z "$NATIVE_ROTATION_NODE_ID" ]]; then
    return 1
  fi
  # kubelet projected-volume propagation plus FERRUM_BACKEND_TLS_WATCH_INTERVAL_SECONDS=2.
  # Hosted Kind has observed DP gen2 revision publication past 150s, so 90s is
  # not a defensible evidence window. Poll every 2s for 240s; keep exact
  # post-anchor Connected-to-CP / Tenant-accepted proof.
  for _ in $(seq 1 120); do
    if native_rotation_fresh_now; then
      return 0
    fi
    sleep 2
  done
  native_rotation_fresh_now || true
  return 1
}

pick_native_observe_loopback_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_native_observe_port_forward() {
  local pf_pid="$1" pf_log="$2" port="$3"
  local _
  for _ in $(seq 1 40); do
    if ! kill -0 "$pf_pid" 2>/dev/null; then
      return 1
    fi
    if grep -Eq "Forwarding from .*:${port}( ->|$)" "$pf_log" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

write_native_observe_evidence() {
  local class="$1" reason="$2" serial="${3:-}"
  NATIVE_CP_SERVED_CLASS="$class"
  NATIVE_CP_SERVED_REASON="$reason"
  NATIVE_CP_SERVED_SERIAL="$serial"
  printf 'class=%s\nreason=%s\nserved_serial=%s\nwant_serial=%s\n' \
    "$class" "$reason" "$serial" "${NATIVE_SERVER_SERIAL_GEN2:-}" \
    > "$RESULTS_DIR/native-mtls-served-serial.txt"
}

classify_native_observe_error() {
  local err_file="$1" out_file="${2:-}"
  local files=("$err_file")
  if [[ -n "$out_file" && -f "$out_file" ]]; then
    files+=("$out_file")
  fi
  if grep -Eqi 'verify (error|return:)|certificate verify failed|hostname mismatch' \
    "${files[@]}" 2>/dev/null; then
    printf '%s\n' "tls-verify"
    return
  fi
  if grep -Eqi 'handshake|ssl routines|alert|certificate required' \
    "${files[@]}" 2>/dev/null; then
    printf '%s\n' "tls-handshake"
    return
  fi
  if grep -Eqi 'connection refused|connection reset|connect' \
    "${files[@]}" 2>/dev/null; then
    printf '%s\n' "connect"
    return
  fi
  printf '%s\n' "observe-failed"
}

# Over-the-wire observation of the leaf certificate served by the running
# ferrum-cp after rotation. Connects through kubectl port-forward to the
# ferrum-cp Service listener (not Secret.data, not a mounted file, not the
# controller-local expected server cert). Verifies TLS against the gen2
# server CA, the Kubernetes Service DNS SAN, and presents the gen2 DP client
# cert because the CP requires mTLS. Publishes the verified peer leaf serial
# on NATIVE_CP_SERVED_SERIAL in this shell; callers must invoke this helper
# directly (never via command substitution) so NATIVE_OBSERVE_PF_PID,
# NATIVE_CP_SERVED_CLASS, and NATIVE_CP_SERVED_SERIAL propagate to the EXIT
# trap and the rotation probe. Raw openssl transcripts stay in
# NATIVE_MTLS_DIR; RESULTS_DIR gets only class/reason/serial evidence.
observe_native_cp_served_serial() {
  local port="" pf_pid=0 pf_log="" out_file="" err_file="" serial="" attempt \
    hs_rc=0 verify_ok=false class reason
  NATIVE_CP_SERVED_CLASS=""
  NATIVE_CP_SERVED_REASON=""
  NATIVE_CP_SERVED_SERIAL=""

  if [[ -z "${NATIVE_MTLS_DIR:-}" || -z "${NATIVE_CP_DNS:-}" \
    || ! -f "$NATIVE_MTLS_DIR/gen2-ca.pem" \
    || ! -f "$NATIVE_MTLS_DIR/gen2-client.pem" \
    || ! -f "$NATIVE_MTLS_DIR/gen2-client-key.pem" ]]; then
    write_native_observe_evidence missing-material \
      "gen2 CA/client material or Service DNS is missing"
    return 1
  fi

  pf_log="$NATIVE_MTLS_DIR/observe-port-forward.log"
  out_file="$NATIVE_MTLS_DIR/observe-handshake.out"
  err_file="$NATIVE_MTLS_DIR/observe-handshake.err"

  for attempt in $(seq 1 5); do
    stop_native_observe_port_forward "$pf_pid"
    pf_pid=0
    port="$(pick_native_observe_loopback_port)"
    if [[ -z "$port" || "$port" == "0" ]]; then
      write_native_observe_evidence port-pick-failed \
        "failed to allocate an ephemeral loopback port"
      return 1
    fi
    : > "$pf_log"
    kubectl --context "$CONTEXT" -n "$NS" port-forward "svc/ferrum-cp" \
      "${port}:50051" >"$pf_log" 2>&1 &
    pf_pid=$!
    NATIVE_OBSERVE_PF_PID="$pf_pid"
    if wait_native_observe_port_forward "$pf_pid" "$pf_log" "$port"; then
      break
    fi
    if [[ "$attempt" -eq 5 ]]; then
      stop_native_observe_port_forward "$pf_pid"
      write_native_observe_evidence port-forward-failed \
        "kubectl port-forward to svc/ferrum-cp:50051 did not become ready"
      return 1
    fi
  done

  : > "$out_file"
  : > "$err_file"
  set +e
  python3 - "$out_file" "$err_file" \
    openssl s_client \
    -connect "127.0.0.1:${port}" \
    -servername "$NATIVE_CP_DNS" \
    -verify_hostname "$NATIVE_CP_DNS" \
    -CAfile "$NATIVE_MTLS_DIR/gen2-ca.pem" \
    -cert "$NATIVE_MTLS_DIR/gen2-client.pem" \
    -key "$NATIVE_MTLS_DIR/gen2-client-key.pem" \
    -verify_return_error \
    -alpn h2 <<'PY'
import subprocess
import sys

out_path, err_path = sys.argv[1], sys.argv[2]
cmd = sys.argv[3:]
try:
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        result = subprocess.run(
            cmd, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=15
        )
    sys.exit(result.returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
PY
  hs_rc=$?
  set -e
  stop_native_observe_port_forward "$pf_pid"
  pf_pid=0

  if [[ "$hs_rc" -eq 124 ]]; then
    write_native_observe_evidence handshake-timeout \
      "openssl s_client timed out before a verified handshake"
    return 1
  fi

  if grep -Fq 'Verify return code: 0 (ok)' "$out_file" "$err_file" 2>/dev/null \
    || grep -Fq 'Verification: OK' "$out_file" "$err_file" 2>/dev/null; then
    verify_ok=true
  fi
  if [[ "$verify_ok" != "true" ]]; then
    class="$(classify_native_observe_error "$err_file" "$out_file")"
    reason="verified mTLS handshake to the running CP failed"
    write_native_observe_evidence "$class" "$reason"
    return 1
  fi

  serial=""
  serial="$(
    awk '/BEGIN CERTIFICATE/{keep=1} keep{print} /END CERTIFICATE/{exit}' \
      "$out_file" 2>/dev/null |
      openssl x509 -noout -serial 2>/dev/null |
      awk -F= '{print $2}' |
      tr -d '[:space:]'
  )" || serial=""
  if [[ -z "$serial" ]]; then
    write_native_observe_evidence empty-serial \
      "peer leaf serial missing after a verified handshake"
    return 1
  fi

  write_native_observe_evidence ok "peer-leaf-serial-observed" "$serial"
}

probe_native_mtls_rotation() {
  log "rotating native MeshSubscribe TLS material via projected Secret generation"
  capture_native_rotation_baseline || true
  apply_native_mtls_secrets gen2
  local rotated=false
  if wait_for_native_rotation_evidence; then
    rotated=true
  fi
  local live_serial="" observe_ok=false
  if observe_native_cp_served_serial; then
    observe_ok=true
    live_serial="${NATIVE_CP_SERVED_SERIAL:-}"
  else
    live_serial=""
  fi
  local out status body traffic_ok=false
  out="$(drive_settle client / "" 200 "$NATIVE_APP_MARKER" "$CAPP_HOST")"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  if [[ "$status" == "200" && "$body" == *"$NATIVE_APP_MARKER"* ]]; then
    traffic_ok=true
  fi

  local admin_token drift_json drift_verdict
  admin_token="$(mint_admin_jwt)"
  # shellcheck disable=SC2016
  drift_json="$(kubectl --context "$CONTEXT" -n "$NS" exec deploy/capp -c curl -- \
    sh -c '
      token="$1"
      out=""
      for _ in $(seq 1 15); do
        out="$(curl -s -m 10 -H "Authorization: Bearer $token" \
          http://127.0.0.1:15020/mesh/config-drift 2>/dev/null || true)"
        if [ -n "$out" ]; then
          printf "%s\n" "$out"
          exit 0
        fi
        sleep 2
      done
      printf "%s\n" "$out"
    ' sh "$admin_token" 2>/dev/null || printf '')"
  drift_verdict="$(printf '%s' "$drift_json" | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)
except Exception:
    print("drift-unparseable")
    sys.exit(0)
sl = doc.get("slice") or {}
received = bool(sl.get("last_received_at"))
protocol = sl.get("source_protocol")
cp_url = sl.get("source_cp_url") or ""
services = (sl.get("resources") or {}).get("services") or 0
if received and protocol == "native" and "ferrum-cp" in cp_url and cp_url.startswith("https://") and services >= 1:
    print(f"native-slice-received services={services}")
else:
    print(f"drift-unexpected received={received} protocol={protocol} services={services}")
')"

  # Gen1 client must now fail: the CP client CA is the gen2 client CA.
  apply_native_mtls_secret ferrum-native-mtls-stale-client \
    --from-file=ca.pem="$NATIVE_MTLS_DIR/gen2-ca.pem" \
    --from-file=client.pem="$NATIVE_MTLS_DIR/client.pem" \
    --from-file=client-key.pem="$NATIVE_MTLS_DIR/client-key.pem"
  apply_native_mtls_probe native-stale-client \
    "https://$NATIVE_CP_DNS:50051" cp-dp-grpc-jwt-secret \
    ferrum-native-mtls-stale-client true
  local stale_class stale_ev=""
  stale_class="$(wait_for_native_probe_class native-stale-client tls-verify \
    "$NATIVE_EVID_CP_UNKNOWN_ISSUER")"
  stale_ev="$(normalize_native_evidence_file "$RESULTS_DIR/native-stale-client.server-evidence.txt")"
  kubectl --context "$CONTEXT" -n "$NS" delete deploy native-stale-client \
    --wait=true --timeout=60s >/dev/null 2>&1 || true
  kubectl --context "$CONTEXT" -n "$NS" delete secret ferrum-native-mtls-stale-client \
    --wait=false >/dev/null 2>&1 || true

  local reconnect_ev=""
  reconnect_ev="$(normalize_native_evidence_file "$RESULTS_DIR/native-mtls-rotation-reconnect.txt")"
  local outcome
  outcome="rotated=$rotated reconnect=$reconnect_ev live_serial=$live_serial want_serial=$NATIVE_SERVER_SERIAL_GEN2 observe_class=${NATIVE_CP_SERVED_CLASS:-} traffic=$status stale_class=$stale_class stale_evidence=$stale_ev $drift_verdict"
  printf '%s\n' "$outcome" > "$RESULTS_DIR/native-mtls-rotation.txt"
  log "native TLS rotation: $outcome"
  if [[ "$rotated" == "true" && "$observe_ok" == "true" \
    && -n "$live_serial" && "$live_serial" == "$NATIVE_SERVER_SERIAL_GEN2" \
    && "$traffic_ok" == "true" && "$drift_verdict" == native-slice-received* \
    && "$stale_class" == tls-verify ]] \
    && printf '%s' "$stale_ev" | grep -Eq "$NATIVE_EVID_CP_UNKNOWN_ISSUER" \
    && printf '%s' "$reconnect_ev" | grep -Fq "cp_subscribe_accepted node_id=" \
    && printf '%s' "$reconnect_ev" | grep -Fq "client_tls_connect before=" \
    && printf '%s' "$reconnect_ev" | grep -Fq "dp_grpc_anchor=1" \
    && printf '%s' "$reconnect_ev" | grep -Fq "cp_grpc_anchor=1" \
    && printf '%s' "$reconnect_ev" | grep -Fq "client_post_anchor=1" \
    && printf '%s' "$reconnect_ev" | grep -Fq "cp_post_anchor=1"; then
    record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects pass \
      capp ferrum-cp "$outcome" "native-mtls-rotation.txt"
    return 0
  fi
  record_live_assertion sidecar.config.native_subscribe_tls_rotation_reconnects fail \
    capp ferrum-cp "$outcome" "native-mtls-rotation.txt"
  return 1
}

# DR maxConnections over a WebSocket flow: maxConnections is enforced on
# stream-family and WebSocket backend connections only (a WS session holds one
# dedicated backend connection for its lifetime), so the probe drives
# hand-rolled RFC 6455 upgrades from the client pod's python container at the
# outbound capture listener:
#   1. upgrade #1 -> 101 (retried until the wssvc route settles) and HELD;
#   2. upgrade #2 while #1 is held -> the client sidecar rejects it 503
#      (backend_max_connections) before dialing — the cap observation;
#   3. close #1 -> the slot frees on session teardown -> upgrade #3 -> 101
#      (retried briefly), proving the cap releases rather than leaking.
# Echoes "<first>\t<second>\t<third>" status codes.
probe_ws_max_connections() {
  log "probing DR maxConnections=1 over WebSocket (wssvc)"
  local out first second third rest
  # shellcheck disable=SC2016
  out="$(kubectl --context "$CONTEXT" -n "$NS" exec deploy/client -c probe -- \
    python3 -c '
import base64
import os
import socket
import sys
import time

host = sys.argv[1]


def upgrade(timeout=10):
    s = socket.create_connection(("127.0.0.1", 15001), timeout=timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        "GET /ws HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    s.sendall(req)
    s.settimeout(timeout)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    code = "000"
    if data.startswith(b"HTTP/"):
        parts = data.split(b" ", 2)
        if len(parts) >= 2:
            code = parts[1][:3].decode(errors="replace")
    return s, code


first_sock = None
first = "000"
for _ in range(30):
    first_sock, first = upgrade()
    if first == "101":
        break
    first_sock.close()
    time.sleep(2)

second = "000"
third = "000"
if first == "101":
    s2, second = upgrade()
    s2.close()
    first_sock.close()
    for _ in range(15):
        s3, third = upgrade()
        s3.close()
        if third == "101":
            break
        time.sleep(2)
print(f"{first}\t{second}\t{third}")
' "$WS_HOST" 2>/dev/null | tail -1 || printf 'EXECFAIL\tEXECFAIL\tEXECFAIL')"
  first="${out%%$'\t'*}"
  rest="${out#*$'\t'}"
  second="${rest%%$'\t'*}"
  third="${rest#*$'\t'}"
  log "WS maxConnections: first=$first second=$second third=$third"
  # The cap proof is EXACTLY: held session admitted (101), concurrent second
  # upgrade rejected with the WS backend_max_connections 503 (a real sidecar
  # response — 000/EXECFAIL never satisfies it), and recovery after release.
  if [[ "$first" == "101" && "$second" == "503" && "$third" == "101" ]]; then
    record_live_assertion sidecar.destination_rule.tcp_max_connections pass \
      client wssvc "held=101 concurrent=$second released=$third (maxConnections=1)"
  else
    record_live_assertion sidecar.destination_rule.tcp_max_connections fail \
      client wssvc "unexpected-sequence first=$first second=$second third=$third"
    return 1
  fi
}

# One timed probe at the black-holed slowsvc. Retries only while the response
# is a NON-5xx (a route-materialization blip); settles on the first 5xx and
# echoes "<status>\t<time_total>\t<body>". curl's own -m must sit ABOVE the
# largest configured connectTimeout so the sidecar's 502, not curl, ends the
# probe.
probe_slowsvc_once() {
  # shellcheck disable=SC2016
  kubectl --context "$CONTEXT" -n "$NS" exec deploy/client -c curl -- \
    sh -c '
      host="$1"
      out=000
      ttot=0
      body=""
      for _ in 1 2 3; do
        : >/tmp/body 2>/dev/null || true
        resp="$(curl -s -m 25 -o /tmp/body -w "%{http_code} %{time_total}" \
          -H "Host: $host" http://127.0.0.1:15001/ 2>/dev/null)"
        [ -z "$resp" ] && resp="000 0"
        out="${resp%% *}"
        ttot="${resp##* }"
        body="$(tr -d "\r\n" </tmp/body 2>/dev/null || true)"
        case "$out" in
          5*)
            printf "%s\t%s\t%s\n" "$out" "$ttot" "$body"
            exit 0
            ;;
        esac
        sleep 2
      done
      printf "%s\t%s\t%s\n" "$out" "$ttot" "$body"
    ' sh "$SLOW_HOST" 2>/dev/null || printf 'EXECFAIL\t0\t'
}

in_window() {
  python3 -c '
import sys
t, lo, hi = (float(a) for a in sys.argv[1:4])
sys.exit(0 if lo <= t <= hi else 1)
' "$1" "$2" "$3"
}

# DestinationRule YAML fragments for the DR_LIVE_HOST scenarios. Sticky rules
# use consistentHash{useSourceIp} so one client IP pins to ONE backend; RR is
# explicit so a client-tier rule can visibly override sticky service/root rules.
dr_rule_sticky() {
  local name="$1" namespace="$2" export_to_yaml="$3"
  cat <<YAML
    - name: $name
      namespace: $namespace
      host: $DR_LIVE_HOST
      export_to: $export_to_yaml
      traffic_policy:
        # MeshLoadBalancer is an externally tagged enum. The localized file
        # source parses YAML directly through serde_yaml, whose newtype-enum
        # representation is a YAML tag rather than JSON's one-key mapping.
        load_balancer: !consistent_hash
          use_source_ip: true
YAML
}

dr_rule_round_robin() {
  local name="$1" namespace="$2" export_to_yaml="$3"
  cat <<YAML
    - name: $name
      namespace: $namespace
      host: $DR_LIVE_HOST
      export_to: $export_to_yaml
      traffic_policy:
        load_balancer: !simple ROUND_ROBIN
YAML
}

# Preserve the exact failing replacement pod's startup evidence. `logs
# deploy/client` can resolve to the old Ready replica during a failed rolling
# update and therefore hide the new pod's parse/validation failure; enumerate
# every client pod and collect both current and previous ferrum-edge logs.
capture_client_rollout_failure() {
  local diagnostics="$RESULTS_DIR/client-rollout-failure.txt"
  local pod
  : >"$diagnostics"
  kubectl --context "$CONTEXT" -n "$NS" get pods -l app=client -o wide \
    >>"$diagnostics" 2>&1 || true
  while IFS= read -r pod; do
    [[ -n "$pod" ]] || continue
    printf '\n=== %s current ferrum-edge log ===\n' "$pod" >>"$diagnostics"
    kubectl --context "$CONTEXT" -n "$NS" logs "$pod" -c ferrum-edge \
      --tail=500 >>"$diagnostics" 2>&1 || true
    printf '\n=== %s previous ferrum-edge log ===\n' "$pod" >>"$diagnostics"
    kubectl --context "$CONTEXT" -n "$NS" logs "$pod" -c ferrum-edge \
      --previous --tail=500 >>"$diagnostics" 2>&1 || true
    printf '\n=== %s describe ===\n' "$pod" >>"$diagnostics"
    kubectl --context "$CONTEXT" -n "$NS" describe "$pod" \
      >>"$diagnostics" 2>&1 || true
  done < <(
    kubectl --context "$CONTEXT" -n "$NS" get pods -l app=client \
      -o name 2>/dev/null || true
  )
}

restart_client_for_config() {
  kubectl --context "$CONTEXT" -n "$NS" rollout restart deploy/client
  if ! kubectl --context "$CONTEXT" -n "$NS" rollout status deploy/client --timeout=3m; then
    capture_client_rollout_failure
    return 1
  fi
}

# Re-render the client ConfigMap with the given DestinationRule extras and
# restart the distroless client so it loads the new slice.
reload_client_with_dr_rules() {
  local extra_dr_rules="$1"
  render_client_config \
    "$SVC_POD_IP" "$WSSVC_POD_IP" "$CAPP_POD_IP" "$CONNECT_TIMEOUT_PHASE1_MS" \
    "$DR_BACKEND_A_IP" "$DR_BACKEND_B_IP" "$extra_dr_rules"
  restart_client_for_config
}

# Drive N requests at DR_LIVE_HOST through the captured client egress listener
# and print the unique backend labels that answered (space-separated, sorted).
# Retries briefly for route convergence, then samples exactly DR_LIVE_REQUESTS
# authoritative 200s. Echoes EXECFAIL on infra failure.
sample_dr_live_backends() {
  # shellcheck disable=SC2016
  kubectl --context "$CONTEXT" -n "$NS" exec deploy/client -c curl -- \
    sh -c '
      host="$1"
      want_a="$2"
      want_b="$3"
      n="$4"
      labels=""
      # Convergence: wait until the MeshService outbound route answers 200 with a
      # fixture label before counting authoritative samples.
      for _ in $(seq 1 30); do
        : >/tmp/drbody 2>/dev/null || true
        code="$(curl -s -m 10 -o /tmp/drbody -w "%{http_code}" \
          -H "Host: $host" "http://127.0.0.1:15001/" 2>/dev/null || true)"
        [ -n "$code" ] || code=000
        body="$(tr -d "\r\n" </tmp/drbody 2>/dev/null || true)"
        if [ "$code" = "200" ] && { [ "$body" = "$want_a" ] || [ "$body" = "$want_b" ]; }; then
          break
        fi
        sleep 2
      done
      i=0
      while [ "$i" -lt "$n" ]; do
        : >/tmp/drbody 2>/dev/null || true
        code="$(curl -s -m 10 -o /tmp/drbody -w "%{http_code}" \
          -H "Host: $host" "http://127.0.0.1:15001/" 2>/dev/null || true)"
        [ -n "$code" ] || code=000
        body="$(tr -d "\r\n" </tmp/drbody 2>/dev/null || true)"
        if [ "$code" != "200" ] || { [ "$body" != "$want_a" ] && [ "$body" != "$want_b" ]; }; then
          printf "BAD\t%s\t%s\n" "$code" "$body"
          exit 0
        fi
        case " $labels " in
          *" $body "*) ;;
          *) labels="$labels $body" ;;
        esac
        i=$((i + 1))
      done
      # Sort uniquely for stable comparison.
      printf "%s\n" $labels | sort -u | tr "\n" " " | sed "s/ \$//"
      printf "\n"
    ' sh "$DR_LIVE_HOST" "$DR_BACKEND_A_BODY" "$DR_BACKEND_B_BODY" "$DR_LIVE_REQUESTS" \
    2>/dev/null || printf 'EXECFAIL\n'
}

# Count whitespace-separated backend labels in a sample_dr_live_backends result.
count_dr_labels() {
  local sample="$1"
  if [[ -z "$sample" || "$sample" == "EXECFAIL" || "$sample" == BAD$'\t'* || "$sample" == BAD* ]]; then
    printf '0'
    return
  fi
  # shellcheck disable=SC2086
  set -- $sample
  printf '%s' "$#"
}

# Issues #2465 / #2469 on the live captured datapath: apply DestinationRules
# with distinct declaring namespaces via the client file-mode slice (Istio CRDs
# are disabled in this fixture), drive traffic through :15001, and distinguish
# applied vs ignored rules by observing consistent-hash vs round-robin backends.
probe_destination_rule_namespace_security() {
  local diagnostics="$RESULTS_DIR/destination-rule-namespace-security.txt"
  : >"$diagnostics"
  log "probing DestinationRule namespace visibility and lookup precedence on the live datapath"

  local hidden_rules visible_rules lookup_rules
  hidden_rules="$(dr_rule_sticky service-dr "$DR_SERVICE_NS" '["."]')"
  visible_rules="$(dr_rule_sticky root-dr "$DR_ROOT_NS" '["*"]')"
  lookup_rules="$(
    dr_rule_sticky service-dr "$DR_SERVICE_NS" '["*"]'
    dr_rule_sticky root-dr "$DR_ROOT_NS" '["*"]'
    dr_rule_round_robin client-dr "$NS" '["*"]'
  )"

  local sample count visibility_ok=false lookup_ok=false

  log "DR exportTo phase 1: service-namespace sticky rule exportTo=['.'] (must stay round-robin)"
  reload_client_with_dr_rules "$hidden_rules"
  sample="$(sample_dr_live_backends)"
  count="$(count_dr_labels "$sample")"
  printf 'phase1-hidden sample=%s count=%s\n' "$sample" "$count" >>"$diagnostics"
  log "phase 1 (hidden): sample=$sample count=$count"
  local phase1_ok=false
  [[ "$count" == "2" ]] && phase1_ok=true

  log "DR exportTo phase 2: root-namespace sticky rule exportTo=['*'] (must pin one backend)"
  reload_client_with_dr_rules "$visible_rules"
  sample="$(sample_dr_live_backends)"
  count="$(count_dr_labels "$sample")"
  printf 'phase2-visible sample=%s count=%s\n' "$sample" "$count" >>"$diagnostics"
  log "phase 2 (visible): sample=$sample count=$count"
  local phase2_ok=false
  [[ "$count" == "1" ]] && phase2_ok=true

  if [[ "$phase1_ok" == "true" && "$phase2_ok" == "true" ]]; then
    visibility_ok=true
    record_live_assertion sidecar.destination_rule.export_to_namespace_visibility pass \
      "client/$NS" "meshservice/$DR_SERVICE_NS/$DR_SERVICE_NAME" \
      "hidden-service-rule kept RR (2 backends); exported root control pinned (1 backend)" \
      "$(basename "$diagnostics")"
  else
    record_live_assertion sidecar.destination_rule.export_to_namespace_visibility fail \
      "client/$NS" "meshservice/$DR_SERVICE_NS/$DR_SERVICE_NAME" \
      "exportTo visibility did not match expected LB outcomes phase1_ok=$phase1_ok phase2_ok=$phase2_ok" \
      "$(basename "$diagnostics")"
  fi

  log "DR lookup hierarchy: client RR must win over sticky service + root rules"
  reload_client_with_dr_rules "$lookup_rules"
  sample="$(sample_dr_live_backends)"
  count="$(count_dr_labels "$sample")"
  printf 'phase3-lookup sample=%s count=%s\n' "$sample" "$count" >>"$diagnostics"
  log "phase 3 (client wins): sample=$sample count=$count"
  if [[ "$count" == "2" ]]; then
    lookup_ok=true
    record_live_assertion sidecar.destination_rule.lookup_tier_client_wins pass \
      "client/$NS" "meshservice/$DR_SERVICE_NS/$DR_SERVICE_NAME" \
      "client-tier ROUND_ROBIN won; both backends served" \
      "$(basename "$diagnostics")"
  else
    record_live_assertion sidecar.destination_rule.lookup_tier_client_wins fail \
      "client/$NS" "meshservice/$DR_SERVICE_NS/$DR_SERVICE_NAME" \
      "client-tier rule did not win; observed label count=$count sample=$sample" \
      "$(basename "$diagnostics")"
  fi

  # Restore the baseline client slice (no DR_LIVE_HOST policy) before the
  # connectTimeout two-phase probe re-renders with its own timeout value.
  reload_client_with_dr_rules ""

  if [[ "$visibility_ok" != "true" || "$lookup_ok" != "true" ]]; then
    cat "$diagnostics" >&2
    return 1
  fi
}

probe_connect_timeout_two_phase() {
  log "DR connectTimeout phase 1: ${CONNECT_TIMEOUT_PHASE1_MS}ms (window ${PHASE1_WINDOW_LO}-${PHASE1_WINDOW_HI}s)"
  local out status1 t1 body rest
  out="$(probe_slowsvc_once)"
  status1="${out%%$'\t'*}"
  rest="${out#*$'\t'}"
  t1="${rest%%$'\t'*}"
  body="${rest#*$'\t'}"
  log "phase 1: status=$status1 time=${t1}s body=$body"

  log "re-rendering client config with ${CONNECT_TIMEOUT_PHASE2_MS}ms and restarting client"
  # Distroless runtime image: no shell/kill, so config reload is a rollout
  # restart (the new pod reads the updated ConfigMap at startup).
  render_client_config "$SVC_POD_IP" "$WSSVC_POD_IP" "$CAPP_POD_IP" "$CONNECT_TIMEOUT_PHASE2_MS"
  restart_client_for_config
  # Re-settle the positive route first so phase 2 never times a request that
  # raced the fresh pod's slice load.
  local settle settle_status
  settle="$(drive_settle client / "" 200 "$APP_BODY")"
  settle_status="${settle%%$'\t'*}"
  if [[ "$settle_status" != "200" ]]; then
    record_live_assertion sidecar.destination_rule.tcp_connect_timeout fail \
      client slowsvc "client-did-not-recover-after-restart status=$settle_status"
    return 1
  fi

  log "DR connectTimeout phase 2: ${CONNECT_TIMEOUT_PHASE2_MS}ms (window ${PHASE2_WINDOW_LO}-${PHASE2_WINDOW_HI}s)"
  local status2 t2
  out="$(probe_slowsvc_once)"
  status2="${out%%$'\t'*}"
  rest="${out#*$'\t'}"
  t2="${rest%%$'\t'*}"
  body="${rest#*$'\t'}"
  log "phase 2: status=$status2 time=${t2}s body=$body"

  # Both phases must be a REAL upstream 5xx (the sidecar's connect-timeout
  # 502), inside their phase's window, and the observed time must TRACK the
  # 8000 -> 2000 change. EXECFAIL/000 never satisfies the 5xx regex.
  local ok=true
  [[ "$status1" =~ ^5[0-9][0-9]$ ]] || ok=false
  [[ "$status2" =~ ^5[0-9][0-9]$ ]] || ok=false
  in_window "$t1" "$PHASE1_WINDOW_LO" "$PHASE1_WINDOW_HI" || ok=false
  in_window "$t2" "$PHASE2_WINDOW_LO" "$PHASE2_WINDOW_HI" || ok=false
  python3 -c '
import sys
t1, t2 = float(sys.argv[1]), float(sys.argv[2])
sys.exit(0 if t1 > t2 + 2.0 else 1)
' "$t1" "$t2" || ok=false

  if [[ "$ok" == "true" ]]; then
    record_live_assertion sidecar.destination_rule.tcp_connect_timeout pass \
      client slowsvc \
      "phase1=${CONNECT_TIMEOUT_PHASE1_MS}ms->status=$status1,t=${t1}s phase2=${CONNECT_TIMEOUT_PHASE2_MS}ms->status=$status2,t=${t2}s"
  else
    record_live_assertion sidecar.destination_rule.tcp_connect_timeout fail \
      client slowsvc \
      "timing-did-not-track-configured-timeout phase1=status=$status1,t=${t1}s phase2=status=$status2,t=${t2}s"
    return 1
  fi
}

# ── diagnostics + gate ──────────────────────────────────────────────────────

collect_diagnostics() {
  kubectl --context "$CONTEXT" -n "$NS" get all -o wide \
    > "$ARTIFACT_DIR/all.txt" 2>&1 || true
  kubectl --context "$CONTEXT" -n "$NS" get events --sort-by=.lastTimestamp \
    > "$ARTIFACT_DIR/events.txt" 2>&1 || true
  kubectl --context "$CONTEXT" -n "$NS" describe pods \
    > "$ARTIFACT_DIR/pods-describe.txt" 2>&1 || true
  kubectl --context "$CONTEXT" -n "$NS" get configmap -o yaml \
    > "$ARTIFACT_DIR/configmaps.yaml" 2>&1 || true
  local deploy
  for deploy in svc wssvc client rogue capp ferrum-cp drsvc-a drsvc-b \
    native-omit-client native-foreign-client native-untrusted-ca \
    native-wrong-san native-jwt-invalid native-stale-client; do
    kubectl --context "$CONTEXT" -n "$NS" logs "deploy/$deploy" \
      --all-containers --tail=500 \
      > "$ARTIFACT_DIR/${deploy}.log" 2>&1 || true
  done
  kubectl --context "$CONTEXT" -n "$NS" logs deploy/svc -c ferrum-edge-init \
    --tail=50 > "$ARTIFACT_DIR/svc-iptables.txt" 2>&1 || true
  kubectl --context "$CONTEXT" -n "$NS" logs deploy/client -c ferrum-blackhole-init \
    --tail=50 > "$ARTIFACT_DIR/client-blackhole.txt" 2>&1 || true
  ferrum_spire_collect_diagnostics "$CONTEXT" "$SPIRE_NS" \
    "$ARTIFACT_DIR/spire" || true
  if [[ -f "$LIVE_ASSERTIONS_FILE" ]]; then
    cp "$LIVE_ASSERTIONS_FILE" "$ARTIFACT_DIR/live-assertions.json" 2>/dev/null || true
  fi
  # Diagnostics referenced by basename from live-assertions.json live in
  # RESULTS_DIR; the workflows upload ARTIFACT_DIR, so mirror them (the JWT
  # signing keys and native mTLS private keys stay in throwaway per-run
  # directories and are intentionally NOT copied). Skip any note that grew a
  # PEM body so raw openssl handshake transcripts cannot be uploaded.
  local note
  for note in "$RESULTS_DIR"/*.txt; do
    [[ -f "$note" ]] || continue
    if grep -Eq 'BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH)' \
      "$note" 2>/dev/null; then
      continue
    fi
    cp "$note" "$ARTIFACT_DIR/" 2>/dev/null || true
  done
}

require_live_assertions() {
  log "enforcing required live assertions"
  if ! ferrum_live_assertions_require_all_passed \
    "$LIVE_ASSERTIONS_FILE" "${REQUIRED_LIVE_ASSERTIONS[@]}"; then
    echo "required sidecar.* live assertions did not all pass" >&2
    return 1
  fi
  log "all required sidecar.* live assertions passed"
}

main() {
  trap 'collect_diagnostics; native_mtls_cleanup' EXIT
  preflight
  init_live_assertions

  create_cluster
  build_and_load_image
  install_spire

  ensure_namespace
  mint_jwt_material
  render_shared_secrets
  mint_native_mtls_pki
  apply_native_mtls_secrets gen1
  render_dest_config
  render_wsdest_config
  render_drdest_configs
  apply_workloads
  register_spire_workloads

  # svc rolls out first (its ConfigMap exists); capp needs no ConfigMap (its
  # sidecar subscribes to the CP) and its pod Ready only requires the app
  # container; client/rogue block in ContainerCreating until the client
  # ConfigMap — rendered with the discovered svc/wssvc/capp/drsvc pod IPs — is
  # applied. drsvc-a/b are sidecar-backed MeshService endpoints for DestinationRule
  # LB observation (inbound mesh-mTLS, SPIRE SVIDs).
  SVC_POD_IP="$(wait_for_pod_ip svc)"
  WSSVC_POD_IP="$(wait_for_pod_ip wssvc)"
  CAPP_POD_IP="$(wait_for_pod_ip capp)"
  DR_BACKEND_A_IP="$(wait_for_pod_ip drsvc-a)"
  DR_BACKEND_B_IP="$(wait_for_pod_ip drsvc-b)"
  log "svc pod IP=$SVC_POD_IP   wssvc pod IP=$WSSVC_POD_IP   capp pod IP=$CAPP_POD_IP"
  log "drsvc-a IP=$DR_BACKEND_A_IP   drsvc-b IP=$DR_BACKEND_B_IP"
  render_client_config "$SVC_POD_IP" "$WSSVC_POD_IP" "$CAPP_POD_IP" "$CONNECT_TIMEOUT_PHASE1_MS"
  wait_for_rollouts

  if [[ "${FERRUM_MESH_E2E_DEPLOY_ONLY:-0}" == "1" ]]; then
    log "deploy-only complete; artifacts in $ARTIFACT_DIR"
    return 0
  fi

  probe_authenticated_positive
  probe_plaintext_rejected
  probe_rogue_denied
  probe_request_auth
  probe_vs_cors
  probe_native_subscribe
  # Every probe records its own pass/fail live assertion and
  # require_live_assertions is the single fail-closed gate. These two return
  # non-zero on a recorded failure, so under set -e they would abort the run
  # and leave the remaining release-blocking rows (DR maxConnections, DR
  # exportTo/lookup, DR connectTimeout) unexercised — the artifact gate would
  # then report those ids as MISSING alongside the real native failure.
  # Swallow the status here; the recorded fail still closes the gate below.
  probe_native_mtls_negatives || true
  probe_native_mtls_rotation || true
  probe_ws_max_connections
  probe_destination_rule_namespace_security
  probe_connect_timeout_two_phase

  require_live_assertions
  log "mesh-e2e-sidecar suite PASSED; artifacts in $ARTIFACT_DIR"
}

main "$@"
