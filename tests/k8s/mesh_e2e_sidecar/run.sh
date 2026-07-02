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
#   sidecar.destination_rule.tcp_connect_timeout
#                                               DR connectTimeout provably
#                                               bounds the mesh-mTLS dial
#                                               (two-phase timing, see below)
#   sidecar.destination_rule.tcp_max_connections
#                                               DR maxConnections=1 admits one
#                                               HELD WebSocket session, rejects
#                                               a concurrent upgrade 503, and
#                                               recovers after release
#
# The DestinationRule probe is TWO-PHASE on purpose: a black-holed dial (the
# client pod's own OUTPUT DROP, so SYNs vanish deterministically with no
# external-routing dependence) is timed under connectTimeout=8000ms and then —
# after a re-render + rollout restart (the runtime image is distroless: no
# shell, no `kill -HUP`; restart is the reload) — under 2000ms. The observed
# fail time must TRACK the configured value across the change (and both
# windows exclude the built-in 5000ms default), which proves the knob itself
# rather than any default.
#
# Run locally (requires docker, kind, kubectl, curl, python3, openssl):
#   FERRUM_MESH_E2E_LIVE_ACK_DISPOSABLE=true tests/k8s/mesh_e2e_sidecar/run.sh
#
# Set FERRUM_MESH_E2E_DEPLOY_ONLY=1 to run only the SPIRE/workload deploy
# without driving traffic or gating (the ci.yml smoke).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/.context/mesh-e2e-sidecar}"
RESULTS_DIR="${FERRUM_MESH_E2E_RESULTS_DIR:-$ROOT_DIR/target/mesh-e2e-sidecar}"
MANIFESTS="$ROOT_DIR/tests/k8s/mesh_e2e_sidecar/manifests.yaml"

LIVE_ASSERTIONS_HELPER="$ROOT_DIR/tests/k8s/lib/live_assertions.sh"
SPIRE_HELPER="$ROOT_DIR/tests/k8s/lib/spire.sh"
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
JWT_ISSUER="mesh-e2e-issuer"
JWT_KID="fixture-key"
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
# Minted at startup (mint_jwt_material).
JWKS_JSON=""
JWT_VALID=""
JWT_WRONG_KEY=""

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
  sidecar.destination_rule.tcp_max_connections
)
# NOTE: every id except `sidecar.spire.workload_entries` (fixture
# infrastructure, suite-local) backs a GA-contract capability row in
# tests/conformance/ga_contract.yaml — keep the id strings in lock-step. The
# one remaining `live_deferred` contract id is VS CORS (issue #1973).

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

# ── SPIRE ───────────────────────────────────────────────────────────────────

install_spire() {
  log "installing SPIRE in $CONTEXT ($TRUST_DOMAIN)"
  ferrum_spire_apply_minimal "$CONTEXT" "$TRUST_DOMAIN" "$SPIRE_NS"
  ferrum_spire_wait_ready "$CONTEXT" "$SPIRE_NS" 5m
}

register_spire_workloads() {
  log "registering SPIRE workload entries (svc, wssvc, client, rogue)"
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
    # completes a handshake, so no SVID is ever presented for it.
    for sa in svc wssvc client rogue; do
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
      "" "" "svc-wssvc-client-rogue-entries-registered" "spire-entries.txt"
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

# Client/rogue sidecar mesh document: the svc workload at its REAL pod IP
# (sidecar egress dials workload_address:15006 over mesh-mTLS) plus the
# `slowsvc` workload at the black-holed IP with a DestinationRule
# connectTimeout — the parameter the two-phase probe flips. Rendered only
# after the svc pod IP is known; a svc pod replacement would need a re-render
# + client restart (this fixture never replaces svc).
render_client_config() {
  local svc_pod_ip="$1" wssvc_pod_ip="$2" slow_connect_timeout_ms="$3"
  apply_configmap ferrum-mesh-client "$(cat <<YAML
mesh:
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
  services:
    - name: svc
      namespace: $NS
      ports:
        - port: 8080
          protocol: http
          name: http
      workloads:
        - spiffe_id: spiffe://$TRUST_DOMAIN/ns/$NS/sa/svc
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
YAML
)"
}

wait_for_rollouts() {
  local deploy
  for deploy in svc wssvc client rogue; do
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
# final "<status>\t<body>".
drive_settle() {
  local deploy="$1" path="$2" bearer="$3" want_status="$4" want_body_grep="$5"
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
    ' sh "$SVC_HOST" "$path" "$bearer" "$want_status" "$want_body_grep" \
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
  render_client_config "$SVC_POD_IP" "$WSSVC_POD_IP" "$CONNECT_TIMEOUT_PHASE2_MS"
  kubectl --context "$CONTEXT" -n "$NS" rollout restart deploy/client
  kubectl --context "$CONTEXT" -n "$NS" rollout status deploy/client --timeout=3m
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
  for deploy in svc wssvc client rogue; do
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
  # signing keys are throwaway per-run material and intentionally NOT copied).
  cp "$RESULTS_DIR"/*.txt "$ARTIFACT_DIR/" 2>/dev/null || true
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
  trap collect_diagnostics EXIT
  preflight
  init_live_assertions

  create_cluster
  build_and_load_image
  install_spire

  ensure_namespace
  mint_jwt_material
  render_dest_config
  render_wsdest_config
  apply_workloads
  register_spire_workloads

  # svc rolls out first (its ConfigMap exists); client/rogue block in
  # ContainerCreating until the client ConfigMap — rendered with the
  # discovered svc pod IP — is applied.
  SVC_POD_IP="$(wait_for_pod_ip svc)"
  WSSVC_POD_IP="$(wait_for_pod_ip wssvc)"
  log "svc pod IP=$SVC_POD_IP   wssvc pod IP=$WSSVC_POD_IP"
  render_client_config "$SVC_POD_IP" "$WSSVC_POD_IP" "$CONNECT_TIMEOUT_PHASE1_MS"
  wait_for_rollouts

  if [[ "${FERRUM_MESH_E2E_DEPLOY_ONLY:-0}" == "1" ]]; then
    log "deploy-only complete; artifacts in $ARTIFACT_DIR"
    return 0
  fi

  probe_authenticated_positive
  probe_plaintext_rejected
  probe_rogue_denied
  probe_request_auth
  probe_ws_max_connections
  probe_connect_timeout_two_phase

  require_live_assertions
  log "mesh-e2e-sidecar suite PASSED; artifacts in $ARTIFACT_DIR"
}

main "$@"
