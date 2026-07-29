#!/usr/bin/env bash
set -euo pipefail

# Live two-cluster cross-cluster east-west federation fixture (M5 Stage 2).
#
# Proves BIDIRECTIONAL authenticated cross-cluster traffic over the REAL captured
# datapath between two SPIRE-federated kind clusters, plus a trust-boundary
# negative. This is the live counterpart of the in-process functional test
# `functional_mesh_sidecar_cross_cluster_egress_routes_a_to_c_over_east_west`,
# which COLLAPSES the destination-side iptables redirect; here both directions
# run the real app-port -> :15006 capture across two real clusters with real
# SPIRE-issued SVIDs that cross-verify through federated trust bundles.
#
# Topology (symmetric in both clusters A=cluster-a.test and B=cluster-b.test):
#   client(sidecar) --capture :15001--> cross-cluster target (dial PEER east-west
#     gateway NodePort, SNI = peer svc FQDN, trust-domain-only mTLS) -->
#   PEER east-west gateway (:15443 SNI passthrough) --> PEER svc pod app port
#     8080 --> PEER svc pod inbound iptables REDIRECT 8080->:15006 -->
#   PEER svc sidecar STRICT inbound (verifies client SVID via FEDERATED bundle)
#     --> local app -> 200.
#
# A -> B drives cluster A's client at the svc in cluster B; B -> A mirrors it.
#
# SCOPE: Stage 2 (two-cluster SPIRE federation + injected workloads +
# bidirectional authenticated traffic + a negative) PLUS Stage 3 failure
# injection (peer-trust revocation -> fail closed -> restore -> recover; dest
# endpoint black-hole -> recover). Network-partition / last-good retention is
# explicitly DEFERRED (it is a federation/remote-discovery POLLER property; this
# static file-config fixture runs no poller — see the "Stage 3" section below).
#
# Run locally (requires docker, kind, kubectl, helm, curl, python3):
#   FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE=true \
#     tests/k8s/multicluster-federation/run.sh
#
# Set FERRUM_MULTICLUSTER_DEPLOY_ONLY=1 to run only the SPIRE/workload deploy
# without driving traffic or gating (smoke).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/.context/multicluster-federation}"
RESULTS_DIR="${FERRUM_MULTICLUSTER_RESULTS_DIR:-$ROOT_DIR/target/multicluster-federation}"
MANIFESTS="$ROOT_DIR/tests/k8s/multicluster-federation/manifests.yaml"

LIVE_ASSERTIONS_HELPER="$ROOT_DIR/tests/k8s/lib/live_assertions.sh"
SPIRE_HELPER="$ROOT_DIR/tests/k8s/lib/spire.sh"
# shellcheck source=../lib/live_assertions.sh
source "$LIVE_ASSERTIONS_HELPER"
# shellcheck source=../lib/spire.sh
source "$SPIRE_HELPER"

CLUSTER_A="${CLUSTER_A:-ferrum-fed-a}"
CLUSTER_B="${CLUSTER_B:-ferrum-fed-b}"
CONTEXT_A="kind-$CLUSTER_A"
CONTEXT_B="kind-$CLUSTER_B"
TRUST_DOMAIN_A="${FERRUM_TRUST_DOMAIN_A:-cluster-a.test}"
TRUST_DOMAIN_B="${FERRUM_TRUST_DOMAIN_B:-cluster-b.test}"
NETWORK_A="${FERRUM_NETWORK_A:-net-a}"
NETWORK_B="${FERRUM_NETWORK_B:-net-b}"
NS="${FERRUM_NAMESPACE:-ferrum}"
SPIRE_NS="${FERRUM_SPIRE_NAMESPACE:-spire-system}"
EAST_WEST_NODEPORT="${FERRUM_EAST_WEST_NODEPORT:-31443}"
IMAGE_REPOSITORY="${FERRUM_IMAGE_REPOSITORY:-ferrum-edge}"
IMAGE_TAG="${FERRUM_IMAGE_TAG:-multicluster-federation}"
IMAGE="${IMAGE_REPOSITORY}:${IMAGE_TAG}"
KIND_DOCKER_NETWORK="${FERRUM_KIND_DOCKER_NETWORK:-kind}"
LIVE_ASSERTIONS_FILE="${FERRUM_LIVE_ASSERTIONS_FILE:-$RESULTS_DIR/live-assertions.json}"
LIVE_PLATFORM_PROFILE="${FERRUM_LIVE_PLATFORM_PROFILE:-kind-spire-multicluster-federation}"

# Discovered at runtime (peer east-west endpoints + svc pod IPs).
NODE_IP_A=""
NODE_IP_B=""
SVC_POD_IP_A=""
SVC_POD_IP_B=""

LIVE_ASSERTIONS_INITIALIZED=false
RECORDED_LIVE_ASSERTIONS=" "
REQUIRED_LIVE_ASSERTIONS=(
  multicluster.spire.federation_ready_a
  multicluster.spire.federation_ready_b
  multicluster.federation.trust_bundle_exchange
  multicluster.spire.workload_entries
  multicluster.eastwest.gateway_reachable
  multicluster.eastwest.a_to_b_authenticated
  multicluster.eastwest.b_to_a_authenticated
  multicluster.eastwest.bidirectional_authenticated_traffic
  multicluster.eastwest.untrusted_peer_rejected
  # Stage 3 failure injection (A -> B): revoke peer trust -> fail closed -> restore
  # -> recover; scale dest to 0 -> black-hole -> scale up -> recover.
  multicluster.federation.bundle_revoked_rejected
  multicluster.federation.trust_restored_recovers
  multicluster.eastwest.endpoint_blackhole_when_dest_down
  multicluster.eastwest.endpoint_recovers_when_dest_returns
)
# NOTE: these required IDs are the live-gate for cross-cluster east-west, gated
# below by `ferrum_live_assertions_require_all_passed` and additionally enrolled
# in `tests/conformance/ga_contract.yaml` (suite `multicluster-federation`,
# platform `kind-spire-multicluster-federation`) so the dedicated live workflow's
# `live_contract_artifact_gate` step can fail closed on missing/stale artifacts
# (issue #2459). Cross-cluster endpoint *discovery* (poller-driven) remains
# Experimental and is excluded from those GA rows.

mkdir -p "$ARTIFACT_DIR" "$RESULTS_DIR"

log() {
  printf '\n[multicluster-federation] %s\n' "$*"
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
  docker info >/dev/null
  if [[ "${FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE:-}" != "true" ]]; then
    echo "Refusing to create/destroy disposable kind clusters without \
FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE=true" >&2
    exit 1
  fi
}

cluster_exists() {
  kind get clusters | grep -Fxq "$1"
}

create_cluster() {
  local cluster="$1"
  if cluster_exists "$cluster"; then
    log "kind cluster already exists: $cluster"
    return
  fi
  log "creating kind cluster: $cluster"
  kind create cluster --name "$cluster" --wait 180s
}

build_and_load_image() {
  if [[ "${FERRUM_SKIP_IMAGE_BUILD:-0}" != "1" ]]; then
    log "building image $IMAGE"
    docker build -t "$IMAGE" "$ROOT_DIR"
  fi
  log "loading image into $CLUSTER_A and $CLUSTER_B"
  kind load docker-image "$IMAGE" --name "$CLUSTER_A"
  kind load docker-image "$IMAGE" --name "$CLUSTER_B"
}

# ── live assertions ─────────────────────────────────────────────────────────

init_live_assertions() {
  export FERRUM_LIVE_REPO_ROOT="$ROOT_DIR"
  ferrum_live_assertions_init \
    "$LIVE_ASSERTIONS_FILE" \
    multicluster-federation \
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
  local observed_source_spiffe="${6:-}"
  local observed_destination_spiffe="${7:-}"
  local diagnostics="${8:-}"

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
    "$observed_source_spiffe" \
    "$observed_destination_spiffe" \
    "" \
    "$diagnostics"
  RECORDED_LIVE_ASSERTIONS="$RECORDED_LIVE_ASSERTIONS$assertion_id "
}

# ── SPIRE (per cluster + federation) ────────────────────────────────────────

install_spire() {
  local context="$1"
  local trust_domain="$2"
  log "installing SPIRE in $context ($trust_domain)"
  ferrum_spire_apply_minimal "$context" "$trust_domain" "$SPIRE_NS"
  ferrum_spire_wait_ready "$context" "$SPIRE_NS" 5m
}

federate_spire() {
  log "exchanging SPIRE trust bundles ($TRUST_DOMAIN_A <-> $TRUST_DOMAIN_B)"
  if ! ferrum_spire_federate_bundles \
    "$CONTEXT_A" "$TRUST_DOMAIN_A" \
    "$CONTEXT_B" "$TRUST_DOMAIN_B" \
    "$SPIRE_NS"; then
    record_live_assertion multicluster.federation.trust_bundle_exchange fail \
      "" "" "spire-bundle-set-failed"
    echo "SPIRE federation bundle exchange failed" >&2
    return 1
  fi

  local ready_a="fail" ready_b="fail"
  if ferrum_spire_assert_federated_bundle_present "$CONTEXT_A" "$SPIRE_NS" "$TRUST_DOMAIN_B"; then
    ready_a="pass"
  fi
  if ferrum_spire_assert_federated_bundle_present "$CONTEXT_B" "$SPIRE_NS" "$TRUST_DOMAIN_A"; then
    ready_b="pass"
  fi
  ferrum_spire_server_exec "$CONTEXT_A" "$SPIRE_NS" bundle list \
    > "$RESULTS_DIR/cluster-a-bundles.txt" 2>&1 || true
  ferrum_spire_server_exec "$CONTEXT_B" "$SPIRE_NS" bundle list \
    > "$RESULTS_DIR/cluster-b-bundles.txt" 2>&1 || true

  record_live_assertion multicluster.spire.federation_ready_a "$ready_a" \
    "" "" "cluster-a-holds-bundle-for-$TRUST_DOMAIN_B" "" "" "cluster-a-bundles.txt"
  record_live_assertion multicluster.spire.federation_ready_b "$ready_b" \
    "" "" "cluster-b-holds-bundle-for-$TRUST_DOMAIN_A" "" "" "cluster-b-bundles.txt"
  if [[ "$ready_a" == "pass" && "$ready_b" == "pass" ]]; then
    record_live_assertion multicluster.federation.trust_bundle_exchange pass \
      "" "" "both-spire-servers-hold-peer-bundle" "" "" \
      "cluster-a-bundles.txt,cluster-b-bundles.txt"
  else
    record_live_assertion multicluster.federation.trust_bundle_exchange fail \
      "" "" "ready_a=$ready_a ready_b=$ready_b"
    return 1
  fi
}

register_spire_workloads() {
  log "registering federated SPIRE workload entries"
  local registered_ok=true
  _register_cluster_workloads() {
    local context="$1" trust_domain="$2" peer_td="$3"
    local -a spire_nodes
    mapfile -t spire_nodes < <(ferrum_spire_agent_nodes "$context" "$SPIRE_NS")
    if [[ "${#spire_nodes[@]}" -eq 0 ]]; then
      echo "no attested SPIRE agent node in $context" >&2
      kubectl --context "$context" -n "$SPIRE_NS" get pods -o wide >&2 || true
      registered_ok=false
      return 1
    fi
    local node parent_id
    for node in "${spire_nodes[@]}"; do
      parent_id="$(ferrum_spire_k8s_psat_agent_parent_id_for_node \
        "$context" "$SPIRE_NS" "$trust_domain" "$node")" || {
        registered_ok=false
        return 1
      }
      # svc, ew-gateway, client AND rogue all federate WITH the peer trust
      # domain so their SVIDs carry the peer bundle (cross-cluster mTLS
      # verification). The negative's trust boundary is NOT "rogue can't do
      # cross-cluster TLS" (that would be an incidental client-side failure that
      # never reaches the destination) — it is a DESTINATION-SIDE identity DENY:
      # rogue completes valid federated mTLS to the peer svc and is then
      # rejected by the peer svc's `deny-peer-rogue` AuthorizationPolicy
      # (mesh_authz 403). So rogue is registered federated, exactly like client,
      # and the dest-side DENY (render_dest_config) is what distinguishes them.
      local sa
      for sa in svc ew-gateway client rogue; do
        ferrum_spire_register_k8s_workload_federated \
          "$context" "$SPIRE_NS" \
          "spiffe://$trust_domain/ns/$NS/sa/$sa" \
          "$parent_id" "$NS" "$sa" "$peer_td" \
          "k8s:node-name:$node" || registered_ok=false
      done
    done
  }
  # Guard under `set -e`: `_register_cluster_workloads` `return 1`s when no agent
  # is attested or the k8s_psat parent lookup times out. Without `|| ...` the
  # script would exit HERE, skipping the entry-diagnostics dump and the
  # `multicluster.spire.workload_entries fail` record below. The function already
  # sets `registered_ok=false` on those paths; the `||` just lets that branch run
  # so the failure is recorded (and the run still fails via the `return 1` below).
  _register_cluster_workloads "$CONTEXT_A" "$TRUST_DOMAIN_A" "$TRUST_DOMAIN_B" \
    || registered_ok=false
  _register_cluster_workloads "$CONTEXT_B" "$TRUST_DOMAIN_B" "$TRUST_DOMAIN_A" \
    || registered_ok=false

  ferrum_spire_server_exec "$CONTEXT_A" "$SPIRE_NS" entry show \
    > "$RESULTS_DIR/cluster-a-entries.txt" 2>&1 || true
  ferrum_spire_server_exec "$CONTEXT_B" "$SPIRE_NS" entry show \
    > "$RESULTS_DIR/cluster-b-entries.txt" 2>&1 || true

  if [[ "$registered_ok" == "true" ]]; then
    record_live_assertion multicluster.spire.workload_entries pass \
      "" "" "federated-svc-ew-client-rogue-entries-registered-both-clusters" "" "" \
      "cluster-a-entries.txt,cluster-b-entries.txt"
  else
    record_live_assertion multicluster.spire.workload_entries fail \
      "" "" "workload-entry-registration-failed"
    return 1
  fi
}

# ── workloads + east-west exposure ──────────────────────────────────────────

apply_workloads() {
  local context="$1" trust_domain="$2" app_body="$3"
  log "applying workloads in $context ($app_body)"
  awk -v ns="$NS" -v td="$trust_domain" -v image="$IMAGE" -v body="$app_body" \
    -v nodeport="$EAST_WEST_NODEPORT" '
    {
      gsub(/__NAMESPACE__/, ns)
      gsub(/__TRUST_DOMAIN__/, td)
      gsub(/__IMAGE__/, image)
      gsub(/__APP_BODY__/, body)
      gsub(/__EAST_WEST_NODEPORT__/, nodeport)
      print
    }
  ' "$MANIFESTS" | kubectl --context "$context" apply -f -
}

# Idempotently create the workload namespace in `context`. The namespaced mesh
# ConfigMaps are rendered+applied (render_dest_config / render_client_config /
# render_ew_config) BEFORE apply_workloads creates the Namespace object from the
# manifest, so on a fresh kind cluster the first ConfigMap apply would fail with
# `namespaces "$NS" not found`. Creating the namespace up front (per context)
# fixes the ordering; apply_workloads later re-applies the same Namespace object
# (with its mesh label) idempotently.
ensure_namespace() {
  local context="$1"
  kubectl --context "$context" create namespace "$NS" \
    --dry-run=client -o yaml | kubectl --context "$context" apply -f -
}

# Discover a kind node's address on the shared kind docker network. The east-west
# NodePort is reachable on every node's docker IP; the peer cluster's pods route
# to it over the shared network.
discover_node_ip() {
  local cluster="$1"
  local node
  node="$(kind get nodes --name "$cluster" | head -n 1)"
  if [[ -z "$node" ]]; then
    echo "could not list kind nodes for $cluster" >&2
    return 1
  fi
  local ip
  ip="$(docker inspect -f \
    "{{(index .NetworkSettings.Networks \"$KIND_DOCKER_NETWORK\").IPAddress}}" \
    "$node" 2>/dev/null)"
  if [[ -z "$ip" || "$ip" == "<no value>" ]]; then
    echo "could not resolve $cluster node $node IP on docker network $KIND_DOCKER_NETWORK" >&2
    docker inspect -f '{{json .NetworkSettings.Networks}}' "$node" >&2 || true
    return 1
  fi
  printf '%s' "$ip"
}

wait_for_svc_pod_ip() {
  local context="$1"
  local ip="" _
  for _ in $(seq 1 60); do
    # Select a Running, Ready, NON-terminating svc pod's IP. `Terminating` is NOT
    # a pod phase — a deleting pod keeps phase=Running with a deletionTimestamp
    # set — so a phase filter alone still matches the OLD pod during a Stage-3
    # rollout/scale, and rendering the east-west gateway with that soon-dead IP
    # makes recovery fail. Pick the pod with no deletionTimestamp whose Ready
    # condition is True (python3 is a fixture preflight requirement).
    ip="$(kubectl --context "$context" -n "$NS" get pod -l app=svc -o json 2>/dev/null |
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
  echo "svc pod never reported a ready non-terminating pod IP in $context" >&2
  return 1
}

# Block until NO svc pod remains in `context` (incl. Terminating). Stage 3's
# black-hole probe calls this after `scale --replicas=0` so a request can't
# transiently hit a still-draining pod during its termination grace period and
# observe a 200 (which would false-fail the fail-closed assertion).
wait_for_no_svc_pod() {
  local context="$1" n _
  for _ in $(seq 1 60); do
    n="$(kubectl --context "$context" -n "$NS" get pod -l app=svc \
      --no-headers 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$n" == "0" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "svc pods did not terminate in $context" >&2
  return 1
}

# File-config mesh documents are rendered into ConfigMaps in two phases to avoid
# a stale-pod-IP race: the `dest` and `client` documents need no runtime endpoint
# discovery (loopback / peer node IP), so they are created BEFORE the pods; the
# `ew` document needs the local svc pod's IP, so it is created AFTER svc is up.
# This way no pod is ever restarted with a config that points at a since-rotated
# IP.
#
# INBOUND vs OUTBOUND federation trust differ in Ferrum, so only the `dest`
# document declares `trust_bundles`:
#   - OUTBOUND (client -> peer): the mesh-mTLS pool verifies the peer's SERVER
#     SVID against the gateway SVID bundle, which DOES include the SPIRE Agent's
#     `-federatesWith` peer bundles — so the client needs no slice trust_bundles.
#   - INBOUND (dest verifies the client cert): the :15006 STRICT verifier sources
#     federated trust ONLY from `slice.trust_bundles`
#     (`merge_trust_overlay_into_svid_bundle` DROPS the SVID's `-federatesWith`
#     bundles for inbound) — so without the peer bundle declared in the dest
#     document the handshake fails "no trust bundle for peer's trust domain".
# `render_dest_config` therefore fetches the peer SPIRE server's bundle live and
# declares it as a federated trust bundle (the `ew` gateway is SNI passthrough
# and the `client` is outbound-only, so neither needs one). Cross-cluster remote
# classification rides `local_cluster` + the workload's `cluster` field
# (workload_is_remote fallback), so no live remote discovery poll is needed.

apply_configmap() {
  local context="$1" name="$2" mesh_yaml="$3"
  kubectl --context "$context" -n "$NS" create configmap "$name" \
    --from-literal=mesh.yaml="$mesh_yaml" \
    --dry-run=client -o yaml | kubectl --context "$context" apply -f -
}

# Client: declares the PEER svc as a REMOTE workload + an EastWestGateway at the
# peer NodePort. Outbound materialization emits the cross-cluster target.
render_client_config() {
  local context="$1" local_cluster="$2"
  local peer_cluster="$3" peer_td="$4" peer_network="$5" peer_node_ip="$6"
  apply_configmap "$context" ferrum-mesh-client "$(cat <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$peer_td/ns/$NS/sa/svc
      service_name: svc
      namespace: $NS
      trust_domain: $peer_td
      service_account: svc
      cluster: $peer_cluster
      network: $peer_network
      addresses:
        - 10.255.255.255
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
        - spiffe_id: spiffe://$peer_td/ns/$NS/sa/svc
  multi_cluster:
    local_cluster: $local_cluster
    east_west_gateways:
      - name: ew-$peer_network
        namespace: $NS
        host: "$peer_node_ip"
        port: $EAST_WEST_NODEPORT
        sni_hosts:
          - svc.$NS.svc.cluster.local
        trust_domain: $peer_td
        network: $peer_network
YAML
)"
}

# Emit a cluster's SPIRE trust bundle as base64-encoded DER X.509 authorities,
# one per line — the encoding `MeshConfig.trust_bundles[].x509_authorities` wants
# (`decode_x509_authorities` base64-STANDARD-decodes each entry to DER). A PEM
# certificate body IS exactly standard-base64 DER, so we strip the PEM armor and
# join each block's wrapped lines; a multi-cert bundle yields multiple lines.
spire_bundle_b64der() {
  local context="$1"
  ferrum_spire_server_exec "$context" "$SPIRE_NS" bundle show -format pem 2>/dev/null \
    | awk '
        /-----BEGIN CERTIFICATE-----/ { cap = 1; buf = ""; next }
        /-----END CERTIFICATE-----/   { if (cap) print buf; cap = 0; next }
        cap { gsub(/[[:space:]]/, ""); buf = buf $0 }
      '
}

# Render an `x509_authorities:` YAML list (one `- <b64der>` per line) at $1
# indent from a newline-separated base64-DER blob ($2).
yaml_x509_authorities() {
  local indent="$1" blob="$2" line
  while IFS= read -r line; do
    [[ -n "$line" ]] && printf '%s- %s\n' "$indent" "$line"
  done <<<"$blob"
}

# Dest svc: LOCAL workload (loopback) + STRICT PeerAuth + a DENY
# AuthorizationPolicy for the PEER cluster's rogue principal + the FEDERATED
# peer trust bundle. workload_is_local materializes the inbound loopback route to
# the app on :8080. No discovery.
#
# trust_bundles is LOAD-BEARING for cross-cluster INBOUND mTLS: Ferrum's inbound
# SPIFFE verifier validates a peer cert's trust domain against the gateway SVID's
# LOCAL bundle plus the SLICE's federated bundles (`slice.trust_bundles`,
# `merge_trust_overlay_into_svid_bundle`) — it intentionally DROPS the SPIRE
# Agent's `-federatesWith` bundles for inbound (those feed only the OUTBOUND
# pool's trust). So even with a federated SVID, the dest's :15006 STRICT inbound
# rejects a peer-trust-domain cert ("no trust bundle for peer's trust domain")
# unless the peer bundle is declared HERE. We source it live from the peer's
# SPIRE server (`spire_bundle_b64der`). `local` re-declares this cluster's own
# bundle (same trust domain as the SVID ⇒ additive/deduped, never a replacement).
#
# The DENY policy is what makes the negative prove a DESTINATION-SIDE trust-
# boundary rejection rather than an incidental client-side TLS failure: once
# the peer trust domain is federated (above), STRICT PeerAuth alone cannot tell
# sa/rogue from sa/client (both present a valid peer SVID in the now-trusted
# domain), so this fixture registers BOTH client AND rogue as federated and
# relies on this identity-scoped DENY on the destination's mesh_authz to reject
# exactly the rogue principal. A matched DENY makes mesh_authz return a 403 with
# the body {"error":"Mesh authorization denied"} — a signal SOURCED AT THE
# DESTINATION — while the federated sa/client still gets 200/svc-<dest>. The
# policy is scoped to the local svc workload and denies the peer rogue SPIFFE.
render_dest_config() {
  local context="$1" local_td="$2" peer_context="$3" peer_td="$4"
  # include_peer_trust=false renders the dest with LOCAL trust only — no federated
  # peer bundle — so the peer trust domain is no longer accepted on inbound mTLS.
  # Stage 3 revocation uses this; default true is the normal cross-cluster posture.
  local include_peer_trust="${5:-true}"
  local local_b64 peer_b64 federated_block=""
  local_b64="$(spire_bundle_b64der "$context")"
  if [[ -z "$local_b64" ]]; then
    echo "failed to fetch local SPIRE trust bundle for dest config (local=$local_td)" >&2
    return 1
  fi
  if [[ "$include_peer_trust" == "true" ]]; then
    peer_b64="$(spire_bundle_b64der "$peer_context")"
    if [[ -z "$peer_b64" ]]; then
      echo "failed to fetch peer SPIRE trust bundle for dest config (peer=$peer_td)" >&2
      return 1
    fi
    federated_block="$(printf '    federated:\n      - trust_domain: %s\n        x509_authorities:\n%s' \
      "$peer_td" "$(yaml_x509_authorities "          " "$peer_b64")")"
  fi
  apply_configmap "$context" ferrum-mesh-dest "$(cat <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$local_td/ns/$NS/sa/svc
      service_name: svc
      namespace: $NS
      trust_domain: $local_td
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
        - spiffe_id: spiffe://$local_td/ns/$NS/sa/svc
  trust_bundles:
    local:
      trust_domain: $local_td
      x509_authorities:
$(yaml_x509_authorities "        " "$local_b64")
$federated_block
  mesh_policies:
    - name: deny-peer-rogue
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
            - spiffe_id_pattern: spiffe://$peer_td/ns/$NS/sa/rogue
  peer_authentications:
    - name: mesh-strict
      namespace: $NS
      mtls_mode: strict
YAML
)"
}

# East-west gateway: the svc workload carries the REAL svc pod IP + app port so
# the SNI passthrough forwards opaque TLS to the pod (where inbound iptables
# redirects 8080 -> :15006). Auto-materialized SNI host = svc FQDN. Needs the
# discovered svc pod IP.
render_ew_config() {
  local context="$1" local_td="$2" svc_pod_ip="$3"
  apply_configmap "$context" ferrum-mesh-ew "$(cat <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$local_td/ns/$NS/sa/svc
      service_name: svc
      namespace: $NS
      trust_domain: $local_td
      service_account: svc
      addresses:
        - "$svc_pod_ip"
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
        - spiffe_id: spiffe://$local_td/ns/$NS/sa/svc
YAML
)"
}

# Wait for every DP rollout in a cluster. The east-west gateway pod blocks in
# ContainerCreating until its ConfigMap (rendered after svc-pod-IP discovery)
# exists, so this is called only AFTER render_ew_config — at which point the
# gateway starts fresh with the correct svc pod IP (no restart needed).
wait_for_rollouts() {
  local context="$1"
  local deploy
  for deploy in svc ferrum-mesh-east-west client rogue; do
    kubectl --context "$context" -n "$NS" rollout status "deploy/$deploy" --timeout=5m
  done
}

# Echo "1" iff a TCP connect to host:port from `context`'s client pod succeeds.
# A successful connect to the open SNI-passthrough listener keeps the stream
# open (the gateway sends nothing on a bare TCP connect), so BOTH a small
# `--max-time` AND a connect-specific success signal are load-bearing: --max-time
# stops the probe from BLOCKING until the workflow timeout, and curl's
# `%{time_connect}` write-out (nonzero once the TCP handshake completes) is what
# we assert on — curl exits 28 when --max-time fires AFTER a successful connect
# (no data ever arrives), which is indistinguishable by EXIT CODE from a
# connect-timeout, so exit code alone would false-FAIL a reachable gateway. A
# refused/unroutable port yields an empty/zero connect time → not reachable.
probe_tcp_connect() {
  local context="$1" host="$2" port="$3"
  local connect_time
  # shellcheck disable=SC2016
  connect_time="$(kubectl --context "$context" -n "$NS" exec deploy/client -c curl -- \
    sh -c '
      curl -s --connect-timeout 5 --max-time 5 -o /dev/null \
        -w "%{time_connect}" "telnet://$1:$2" 2>/dev/null || true
    ' sh "$host" "$port" 2>/dev/null || true)"
  # time_connect is "0.000000" (or empty) when no TCP connection was established,
  # nonzero once the handshake completed.
  case "$connect_time" in
    "" | 0 | 0.0 | 0.00 | 0.000 | 0.000000) printf '0' ;;
    *) printf '1' ;;
  esac
}

probe_gateway_reachable() {
  log "probing cross-cluster east-west reachability"
  # From a client pod in A, TCP-connect to B's east-west NodePort, and vice
  # versa. A successful TCP open proves L4 cross-cluster routing independent of
  # the mTLS/auth path.
  #
  # RETRY (not one-shot): `wait_for_rollouts` returns when Kubernetes marks the
  # Deployments rolled out, but the east-west Ferrum container has no readiness
  # probe and may still be loading its SPIRE SVID/config — so the :15443 SNI
  # listener can bind a few seconds AFTER rollout. A single connect would
  # false-FAIL this required assertion on a slow node; retry each direction
  # (latching successes) until both converge, mirroring the HTTP traffic probes.
  local ok_a=false ok_b=false _
  for _ in $(seq 1 30); do
    if [[ "$ok_a" != "true" ]] &&
      [[ "$(probe_tcp_connect "$CONTEXT_A" "$NODE_IP_B" "$EAST_WEST_NODEPORT")" == "1" ]]; then
      ok_a=true
    fi
    if [[ "$ok_b" != "true" ]] &&
      [[ "$(probe_tcp_connect "$CONTEXT_B" "$NODE_IP_A" "$EAST_WEST_NODEPORT")" == "1" ]]; then
      ok_b=true
    fi
    if [[ "$ok_a" == "true" && "$ok_b" == "true" ]]; then
      break
    fi
    sleep 2
  done
  if [[ "$ok_a" == "true" && "$ok_b" == "true" ]]; then
    record_live_assertion multicluster.eastwest.gateway_reachable pass \
      "" "" "tcp-connect-both-east-west-nodeports"
  else
    record_live_assertion multicluster.eastwest.gateway_reachable fail \
      "" "" "a_to_b=$ok_a b_to_a=$ok_b"
    return 1
  fi
}

# ── traffic ─────────────────────────────────────────────────────────────────

# Drive a captured request from `context`'s `deploy` pod at the peer svc through
# the cross-cluster east-west path. Mirrors the functional test's
# plaintext_http_get: a plaintext HTTP GET sent straight at the client sidecar's
# outbound capture listener (:15001) with the destination FQDN as Host. Retries
# until it converges (slice apply / route materialization race). Echoes the final
# "<status>\t<body>" on stdout.
drive_request() {
  local context="$1" deploy="$2"
  local host="svc.$NS.svc.cluster.local"
  # The pod-side script reads the destination Host from $1 (passed after the
  # `sh -c <script> sh <host>` argv) so no host interpolation crosses the quote
  # boundary; $host/$out/$body are pod-side variables, intentionally unexpanded
  # by the outer shell.
  # shellcheck disable=SC2016
  kubectl --context "$context" -n "$NS" exec "deploy/$deploy" -c curl -- \
    sh -c '
      host="$1"
      out=000
      body=""
      for _ in $(seq 1 30); do
        out="$(curl -s -m 5 -o /tmp/body -w "%{http_code}" \
          -H "Host: $host" http://127.0.0.1:15001/ 2>/dev/null || echo 000)"
        body="$(tr -d "\r\n" </tmp/body 2>/dev/null || true)"
        if [ "$out" = "200" ]; then
          printf "%s\t%s\n" "$out" "$body"
          exit 0
        fi
        sleep 2
      done
      printf "%s\t%s\n" "$out" "$body"
    ' sh "$host" 2>/dev/null || printf '000\t'
}

drive_positive_both_directions() {
  log "driving A -> B authenticated cross-cluster request"
  local out_ab status_ab body_ab
  out_ab="$(drive_request "$CONTEXT_A" client)"
  status_ab="${out_ab%%$'\t'*}"
  body_ab="${out_ab#*$'\t'}"
  log "A -> B result: status=$status_ab body=$body_ab"

  log "driving B -> A authenticated cross-cluster request"
  local out_ba status_ba body_ba
  out_ba="$(drive_request "$CONTEXT_B" client)"
  status_ba="${out_ba%%$'\t'*}"
  body_ba="${out_ba#*$'\t'}"
  log "B -> A result: status=$status_ba body=$body_ba"

  # A -> B must carry cluster B's body (svc-b); B -> A must carry svc-a.
  local pass_ab=fail pass_ba=fail
  if [[ "$status_ab" == "200" && "$body_ab" == *"svc-b"* ]]; then
    pass_ab=pass
  fi
  if [[ "$status_ba" == "200" && "$body_ba" == *"svc-a"* ]]; then
    pass_ba=pass
  fi
  # source/destination_workload (3/4) carry the workload NAMES. The observed-
  # SPIFFE fields (6/7) are LEFT EMPTY on purpose: this fixture does not read the
  # peer SVID off the datapath, so filling them from the configured trust domains
  # would record EXPECTED identities as if OBSERVED. The real identity proof is
  # implicit in the outcome — only a valid federated client SVID completes mTLS to
  # get 200/svc-<dest>, and the rogue negative below proves the dest-side 403.
  record_live_assertion multicluster.eastwest.a_to_b_authenticated "$pass_ab" \
    client svc "status=$status_ab body=$body_ab"
  record_live_assertion multicluster.eastwest.b_to_a_authenticated "$pass_ba" \
    client svc "status=$status_ba body=$body_ba"
  if [[ "$pass_ab" == "pass" && "$pass_ba" == "pass" ]]; then
    record_live_assertion multicluster.eastwest.bidirectional_authenticated_traffic pass \
      "" "" "a_to_b=200/$body_ab b_to_a=200/$body_ba"
  else
    record_live_assertion multicluster.eastwest.bidirectional_authenticated_traffic fail \
      "" "" "a_to_b=$pass_ab($status_ab) b_to_a=$pass_ba($status_ba)"
    return 1
  fi
}

# Like drive_request but for the rogue: it must never get 200, so DON'T spin the
# 30×-retry-until-200 loop. Retry only until the dest-side authz DENY signal
# settles (a 403 whose body is mesh_authz's {"error":"Mesh authorization
# denied"}) so a one-off route-materialization race doesn't masquerade as the
# rejection, then echo the final "<status>\t<body>". The DENY is sourced AT THE
# DESTINATION (the peer svc's mesh_authz), which is the whole point of the
# negative — a client-side transport failure (000/502, no authz body) is NOT an
# acceptable proof and is surfaced as-is so the assertion can reject it.
drive_request_expect_dest_deny() {
  local context="$1" deploy="$2"
  local host="svc.$NS.svc.cluster.local"
  # shellcheck disable=SC2016
  kubectl --context "$context" -n "$NS" exec "deploy/$deploy" -c curl -- \
    sh -c '
      host="$1"
      out=000
      body=""
      for _ in $(seq 1 30); do
        out="$(curl -s -m 5 -o /tmp/body -w "%{http_code}" \
          -H "Host: $host" http://127.0.0.1:15001/ 2>/dev/null || echo 000)"
        body="$(tr -d "\r\n" </tmp/body 2>/dev/null || true)"
        # Settle on the destination-side authz DENY (403 + mesh_authz body).
        if [ "$out" = "403" ] && printf "%s" "$body" | grep -q "Mesh authorization denied"; then
          printf "%s\t%s\n" "$out" "$body"
          exit 0
        fi
        sleep 2
      done
      printf "%s\t%s\n" "$out" "$body"
    ' sh "$host" 2>/dev/null || printf '000\t'
}

drive_untrusted_negative() {
  log "driving rogue cross-cluster request A -> B (expect dest-side authz DENY)"
  # rogue is FEDERATED (so it completes valid cross-cluster mTLS to the peer
  # svc) but is denied at the DESTINATION by the peer svc's `deny-peer-rogue`
  # AuthorizationPolicy. The proof is a 403 sourced by the peer's mesh_authz —
  # NOT merely "any non-200" (which a client-side TLS failure would also produce
  # without ever reaching the destination). We assert BOTH the 403 status AND
  # mesh_authz's body, AND that it did not reach the app (no svc-b body).
  local out status body
  out="$(drive_request_expect_dest_deny "$CONTEXT_A" rogue)"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "rogue A -> B result: status=$status body=$body"
  if [[ "$status" == "403" && "$body" == *"Mesh authorization denied"* && "$body" != *"svc-b"* ]]; then
    record_live_assertion multicluster.eastwest.untrusted_peer_rejected pass \
      rogue svc \
      "dest-side-mesh-authz-denied status=$status body=$body"
  else
    record_live_assertion multicluster.eastwest.untrusted_peer_rejected fail \
      "" "" "rogue-not-rejected-by-dest-authz status=$status body=$body"
    return 1
  fi
}

# ── Stage 3: failure injection ──────────────────────────────────────────────
#
# These run AFTER the positive/negative traffic tests and MUTATE cluster state,
# each scenario self-contained (inject -> assert fail-closed -> restore -> assert
# recovery) so it leaves the mesh healthy for the next. They exercise A -> B only
# (the dest is cluster B); one direction proves the property.
#
# IMPORTANT — why restart, not SIGHUP: the Ferrum runtime image is distroless (no
# shell / no `kill`), so an in-pod SIGHUP live-reload isn't reachable via
# `kubectl exec`; reloads happen by `rollout restart` (the new pod reads the
# updated ConfigMap at startup — deterministic, no ConfigMap-mount-propagation
# race). A svc restart changes the svc POD IP, and this file-config fixture's
# east-west gateway pins a STATIC svc pod IP (no live endpoint discovery), so any
# svc replacement must also re-render + restart the gateway to follow the new IP.
# `restart_dest_with_trust` encapsulates that.
#
# DEFERRED (network partition / last-good retention): bounded-staleness last-good
# retention is a property of the federation/remote-discovery POLLER, which this
# static file-config fixture does not run (endpoints are statically declared, not
# polled) — so a partition here would only prove "network down => fail; up =>
# recover", not the M5 retention machinery. A meaningful partition/last-good test
# needs poller-driven remote discovery (CP- or federation-endpoint-fed) and is a
# separate fixture; kind also has no NetworkPolicy enforcement (kindnet), so a
# clean in-cluster partition primitive is unavailable here regardless.

# Drive a captured request and CONFIRM it fails closed (never 200) — for the
# revocation / black-hole scenarios. Exits immediately on any 200 (so a stale
# still-draining connection serving 200 correctly FAILS the "fail-closed"
# assertion), otherwise settles on a stable non-200. Echoes "<status>\t<body>".
# Probe the FULL window and report the worst case for a "fails closed" claim:
# exit IMMEDIATELY with a 200 if the route ever serves one (so the assertion
# fails), otherwise keep probing the whole window and report the final non-200.
# Probing the whole window — not just the first few samples — prevents a transient
# post-restart 000/502 from passing while the route is still materializing
# (rollout-status already waited for Ready, but the mesh slice loads slightly
# after). `%{time_total}` lets callers tell a real error response (fast 5xx) from
# a hang to curl's own timeout (000). Echoes "<status>\t<time_total>\t<body>".
drive_request_expect_failclosed() {
  local context="$1" deploy="$2"
  local host="svc.$NS.svc.cluster.local"
  # shellcheck disable=SC2016
  kubectl --context "$context" -n "$NS" exec "deploy/$deploy" -c curl -- \
    sh -c '
      host="$1"
      out=000
      ttot=0
      body=""
      for _ in $(seq 1 20); do
        # Truncate any prior response body FIRST: on a connection reset/refused
        # curl writes "000" to -w but does NOT rewrite -o /tmp/body, so a stale
        # "svc-b" from the earlier positive request could otherwise leak into the
        # body read and false-fail a correctly fail-closed probe.
        : >/tmp/body 2>/dev/null || true
        resp="$(curl -s -m 10 -o /tmp/body -w "%{http_code} %{time_total}" \
          -H "Host: $host" http://127.0.0.1:15001/ 2>/dev/null)"
        [ -z "$resp" ] && resp="000 0"
        out="${resp%% *}"
        ttot="${resp##* }"
        body="$(tr -d "\r\n" </tmp/body 2>/dev/null || true)"
        if [ "$out" = "200" ]; then
          printf "%s\t%s\t%s\n" "$out" "$ttot" "$body"
          exit 0
        fi
        sleep 2
      done
      printf "%s\t%s\t%s\n" "$out" "$ttot" "$body"
    ' sh "$host" 2>/dev/null || printf 'EXECFAIL\t0\t'
}

# Re-render `context`'s dest mesh config (optionally WITHOUT the federated peer
# trust bundle), restart svc so it loads the new config, then re-render + restart
# the east-west gateway to follow svc's new pod IP. Leaves both rolled out.
restart_dest_with_trust() {
  local context="$1" local_td="$2" peer_context="$3" peer_td="$4" include_peer_trust="$5"
  render_dest_config "$context" "$local_td" "$peer_context" "$peer_td" "$include_peer_trust"
  kubectl --context "$context" -n "$NS" rollout restart deploy/svc
  kubectl --context "$context" -n "$NS" rollout status deploy/svc --timeout=3m
  local new_ip
  new_ip="$(wait_for_svc_pod_ip "$context")"
  render_ew_config "$context" "$local_td" "$new_ip"
  kubectl --context "$context" -n "$NS" rollout restart deploy/ferrum-mesh-east-west
  kubectl --context "$context" -n "$NS" rollout status deploy/ferrum-mesh-east-west --timeout=3m
}

# Scenario A — trust revocation: drop cluster A's federated bundle from cluster
# B's dest, reload, and assert A -> B now fails closed; then restore and assert
# it recovers. Proves slice.trust_bundles is load-bearing for inbound mTLS.
inject_trust_revocation() {
  log "STAGE 3: revoking cluster-A trust on cluster-B dest; expect A -> B fails closed"
  restart_dest_with_trust "$CONTEXT_B" "$TRUST_DOMAIN_B" "$CONTEXT_A" "$TRUST_DOMAIN_A" false
  local out status ttot body rest
  # drive_request_expect_failclosed returns "<status>\t<time_total>\t<body>" and
  # only short-circuits on a 200 (which would mean trust was NOT revoked).
  out="$(drive_request_expect_failclosed "$CONTEXT_A" client)"
  status="${out%%$'\t'*}"
  rest="${out#*$'\t'}"
  ttot="${rest%%$'\t'*}"
  body="${rest#*$'\t'}"
  log "A -> B after revocation: status=$status time=${ttot}s body=$body"
  # PASS only if the probe ACTUALLY RAN (status != EXECFAIL) and never served:
  # a kubectl-exec failure must not masquerade as destination fail-closed.
  if [[ "$status" != "200" && "$status" != "EXECFAIL" && "$body" != *"svc-b"* ]]; then
    record_live_assertion multicluster.federation.bundle_revoked_rejected pass \
      client svc "revoked-peer-trust-fails-closed-over-window status=$status time=${ttot}s body=$body"
  else
    record_live_assertion multicluster.federation.bundle_revoked_rejected fail \
      client svc "served-or-probe-did-not-run status=$status time=${ttot}s body=$body"
  fi

  log "STAGE 3: restoring cluster-A trust on cluster-B dest; expect A -> B recovers"
  restart_dest_with_trust "$CONTEXT_B" "$TRUST_DOMAIN_B" "$CONTEXT_A" "$TRUST_DOMAIN_A" true
  out="$(drive_request "$CONTEXT_A" client)"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "A -> B after trust restore: status=$status body=$body"
  if [[ "$status" == "200" && "$body" == *"svc-b"* ]]; then
    record_live_assertion multicluster.federation.trust_restored_recovers pass \
      client svc "status=$status body=$body"
  else
    record_live_assertion multicluster.federation.trust_restored_recovers fail \
      client svc "did-not-recover-after-restore status=$status body=$body"
    return 1
  fi
}

# Scenario B — endpoint black-hole: scale cluster B's svc to 0 and assert A -> B
# fails fast (the gateway's pinned backend is gone), then scale back up, re-render
# the gateway for the new pod IP, and assert recovery.
inject_endpoint_blackhole() {
  log "STAGE 3: scaling cluster-B svc to 0; expect A -> B black-holes (fail-fast)"
  kubectl --context "$CONTEXT_B" -n "$NS" scale deploy/svc --replicas=0
  wait_for_no_svc_pod "$CONTEXT_B"
  local out status ttot body rest
  out="$(drive_request_expect_failclosed "$CONTEXT_A" client)"
  status="${out%%$'\t'*}"
  rest="${out#*$'\t'}"
  ttot="${rest%%$'\t'*}"
  body="${rest#*$'\t'}"
  log "A -> B with dest down: status=$status time=${ttot}s body=$body"
  # Fail-fast proof: the client must return a real UPSTREAM error — a 5xx from the
  # client sidecar because its gateway backend is gone. Strictly 5xx (not merely
  # "non-200/non-000"): a fast 4xx/route-or-policy regression, a `000` curl-timeout
  # hang, or an EXECFAIL must NOT satisfy the black-hole gate.
  if [[ "$status" =~ ^5[0-9][0-9]$ && "$body" != *"svc-b"* ]]; then
    record_live_assertion multicluster.eastwest.endpoint_blackhole_when_dest_down pass \
      client svc "dest-down-upstream-5xx status=$status time=${ttot}s body=$body"
  else
    record_live_assertion multicluster.eastwest.endpoint_blackhole_when_dest_down fail \
      client svc "not-upstream-5xx-or-served status=$status time=${ttot}s body=$body"
  fi

  log "STAGE 3: scaling cluster-B svc back up + re-rendering gateway; expect recovery"
  kubectl --context "$CONTEXT_B" -n "$NS" scale deploy/svc --replicas=1
  kubectl --context "$CONTEXT_B" -n "$NS" rollout status deploy/svc --timeout=3m
  local new_ip
  new_ip="$(wait_for_svc_pod_ip "$CONTEXT_B")"
  render_ew_config "$CONTEXT_B" "$TRUST_DOMAIN_B" "$new_ip"
  kubectl --context "$CONTEXT_B" -n "$NS" rollout restart deploy/ferrum-mesh-east-west
  kubectl --context "$CONTEXT_B" -n "$NS" rollout status deploy/ferrum-mesh-east-west --timeout=3m
  out="$(drive_request "$CONTEXT_A" client)"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "A -> B after dest recovery: status=$status body=$body"
  if [[ "$status" == "200" && "$body" == *"svc-b"* ]]; then
    record_live_assertion multicluster.eastwest.endpoint_recovers_when_dest_returns pass \
      client svc "status=$status body=$body"
  else
    record_live_assertion multicluster.eastwest.endpoint_recovers_when_dest_returns fail \
      client svc "did-not-recover-after-scale-up status=$status body=$body"
    return 1
  fi
}

# ── diagnostics + gate ──────────────────────────────────────────────────────

collect_diagnostics() {
  local context cluster
  for cluster in "$CLUSTER_A" "$CLUSTER_B"; do
    context="kind-$cluster"
    kubectl --context "$context" -n "$NS" get all -o wide \
      > "$ARTIFACT_DIR/${cluster}-all.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" get events --sort-by=.lastTimestamp \
      > "$ARTIFACT_DIR/${cluster}-events.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" describe pods \
      > "$ARTIFACT_DIR/${cluster}-pods-describe.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" get configmap -o yaml \
      > "$ARTIFACT_DIR/${cluster}-configmaps.yaml" 2>&1 || true
    local deploy
    for deploy in svc ferrum-mesh-east-west client rogue; do
      kubectl --context "$context" -n "$NS" logs "deploy/$deploy" \
        --all-containers --tail=500 \
        > "$ARTIFACT_DIR/${cluster}-${deploy}.log" 2>&1 || true
    done
    ferrum_spire_collect_diagnostics "$context" "$SPIRE_NS" \
      "$ARTIFACT_DIR/${cluster}-spire" || true
  done
  # Dump the dest sidecar's iptables init logs (the captured-redirect proof).
  for context in "$CONTEXT_A" "$CONTEXT_B"; do
    kubectl --context "$context" -n "$NS" logs "deploy/svc" -c ferrum-edge-init \
      --tail=50 > "$ARTIFACT_DIR/$(basename "$context")-svc-iptables.txt" 2>&1 || true
  done
  if [[ -f "$LIVE_ASSERTIONS_FILE" ]]; then
    cp "$LIVE_ASSERTIONS_FILE" "$ARTIFACT_DIR/live-assertions.json" 2>/dev/null || true
  fi
  # The bundle/entry dumps (`cluster-{a,b}-{bundles,entries}.txt`) are written to
  # RESULTS_DIR and referenced BY BASENAME from live-assertions.json's diagnostic
  # paths, but the workflow uploads ARTIFACT_DIR (+ only the JSON from RESULTS_DIR).
  # Copy them into ARTIFACT_DIR so a failed-assertion artifact actually contains
  # the files it points at.
  cp "$RESULTS_DIR"/*.txt "$ARTIFACT_DIR/" 2>/dev/null || true
}

require_live_assertions() {
  log "enforcing required live assertions"
  if ! ferrum_live_assertions_require_all_passed \
    "$LIVE_ASSERTIONS_FILE" "${REQUIRED_LIVE_ASSERTIONS[@]}"; then
    echo "required multicluster.* live assertions did not all pass" >&2
    return 1
  fi
  log "all required multicluster.* live assertions passed"
}

main() {
  trap collect_diagnostics EXIT
  preflight
  init_live_assertions

  create_cluster "$CLUSTER_A"
  create_cluster "$CLUSTER_B"
  build_and_load_image

  install_spire "$CONTEXT_A" "$TRUST_DOMAIN_A"
  install_spire "$CONTEXT_B" "$TRUST_DOMAIN_B"
  federate_spire

  # Node IPs are known as soon as the kind nodes exist (no pod dependency);
  # discover them up front so the client + dest ConfigMaps can be rendered
  # BEFORE the pods start (the only ConfigMap that needs a pod IP is the
  # east-west gateway's, rendered after svc is scheduled).
  NODE_IP_A="$(discover_node_ip "$CLUSTER_A")"
  NODE_IP_B="$(discover_node_ip "$CLUSTER_B")"
  log "cluster A node IP=$NODE_IP_A   cluster B node IP=$NODE_IP_B"

  # The mesh ConfigMaps below are namespaced, so the workload namespace must
  # exist before they are applied (apply_workloads creates the Namespace object
  # only later). Create it idempotently per cluster first.
  ensure_namespace "$CONTEXT_A"
  ensure_namespace "$CONTEXT_B"

  # Dest (loopback) + client (peer node IP) ConfigMaps — no svc-pod-IP needed.
  # Each dest's DENY policy targets the PEER cluster's rogue principal (the
  # source identity that cluster's rogue presents over cross-cluster mTLS).
  render_dest_config "$CONTEXT_A" "$TRUST_DOMAIN_A" "$CONTEXT_B" "$TRUST_DOMAIN_B"
  render_dest_config "$CONTEXT_B" "$TRUST_DOMAIN_B" "$CONTEXT_A" "$TRUST_DOMAIN_A"
  # Cluster A's client reaches cluster B's svc through B's east-west NodePort.
  render_client_config "$CONTEXT_A" "$CLUSTER_A" \
    "$CLUSTER_B" "$TRUST_DOMAIN_B" "$NETWORK_B" "$NODE_IP_B"
  # Cluster B's client reaches cluster A's svc through A's east-west NodePort.
  render_client_config "$CONTEXT_B" "$CLUSTER_B" \
    "$CLUSTER_A" "$TRUST_DOMAIN_A" "$NETWORK_A" "$NODE_IP_A"

  apply_workloads "$CONTEXT_A" "$TRUST_DOMAIN_A" svc-a
  apply_workloads "$CONTEXT_B" "$TRUST_DOMAIN_B" svc-b
  register_spire_workloads

  # svc pods are scheduled (and have stable pod IPs) even while the east-west
  # gateway pod waits in ContainerCreating for its not-yet-rendered ConfigMap.
  SVC_POD_IP_A="$(wait_for_svc_pod_ip "$CONTEXT_A")"
  SVC_POD_IP_B="$(wait_for_svc_pod_ip "$CONTEXT_B")"
  log "cluster A svc pod IP=$SVC_POD_IP_A   cluster B svc pod IP=$SVC_POD_IP_B"
  render_ew_config "$CONTEXT_A" "$TRUST_DOMAIN_A" "$SVC_POD_IP_A"
  render_ew_config "$CONTEXT_B" "$TRUST_DOMAIN_B" "$SVC_POD_IP_B"

  # Now that every ConfigMap exists, all DP pods (incl. the east-west gateway,
  # which was blocked on its ConfigMap) can roll out with correct config.
  wait_for_rollouts "$CONTEXT_A"
  wait_for_rollouts "$CONTEXT_B"

  if [[ "${FERRUM_MULTICLUSTER_DEPLOY_ONLY:-0}" == "1" ]]; then
    log "deploy-only complete; artifacts in $ARTIFACT_DIR"
    return 0
  fi

  probe_gateway_reachable
  drive_positive_both_directions
  drive_untrusted_negative

  # Stage 3 failure injection (mutates cluster state; each scenario self-restores).
  inject_trust_revocation
  inject_endpoint_blackhole

  require_live_assertions
  log "multicluster-federation fixture PASSED; artifacts in $ARTIFACT_DIR"
}

main "$@"
