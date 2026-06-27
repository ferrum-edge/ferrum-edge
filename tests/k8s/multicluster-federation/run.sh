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
# SCOPE: Stage 2 only (two-cluster SPIRE federation + injected workloads +
# bidirectional authenticated traffic + a negative). Bundle rotation/removal,
# endpoint failover, and network partitions are Stage 3 (see `# STAGE 3:`
# markers below).
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
)
# NOTE: these required IDs are the live-gate for cross-cluster east-west, gated
# below by `ferrum_live_assertions_require_all_passed` exactly as the
# node-waypoint eBPF live suite gates its `node_waypoint.*` IDs (run.sh-local
# REQUIRED array). Cross-cluster east-west is Beta/Experimental per docs/mesh.md,
# so there is intentionally NO ga_contract.yaml row yet (a GA promotion would add
# a `maturity: ga` capability with a backing conformance semantic assertion).

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
      # svc, ew-gateway, client federate WITH the peer trust domain so their
      # SVIDs carry the peer bundle (cross-cluster verification). rogue is
      # registered WITHOUT FederatesWith — the negative's trust boundary.
      local sa
      for sa in svc ew-gateway client; do
        ferrum_spire_register_k8s_workload_federated \
          "$context" "$SPIRE_NS" \
          "spiffe://$trust_domain/ns/$NS/sa/$sa" \
          "$parent_id" "$NS" "$sa" "$peer_td" \
          "k8s:node-name:$node" || registered_ok=false
      done
      ferrum_spire_register_k8s_workload \
        "$context" "$SPIRE_NS" \
        "spiffe://$trust_domain/ns/$NS/sa/rogue" \
        "$parent_id" "$NS" rogue \
        "k8s:node-name:$node" || registered_ok=false
    done
  }
  _register_cluster_workloads "$CONTEXT_A" "$TRUST_DOMAIN_A" "$TRUST_DOMAIN_B"
  _register_cluster_workloads "$CONTEXT_B" "$TRUST_DOMAIN_B" "$TRUST_DOMAIN_A"

  ferrum_spire_server_exec "$CONTEXT_A" "$SPIRE_NS" entry show \
    > "$RESULTS_DIR/cluster-a-entries.txt" 2>&1 || true
  ferrum_spire_server_exec "$CONTEXT_B" "$SPIRE_NS" entry show \
    > "$RESULTS_DIR/cluster-b-entries.txt" 2>&1 || true

  if [[ "$registered_ok" == "true" ]]; then
    record_live_assertion multicluster.spire.workload_entries pass \
      "" "" "federated-svc-ew-client-entries-registered-both-clusters" "" "" \
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
  awk -v ns="$NS" -v td="$trust_domain" -v image="$IMAGE" -v body="$app_body" '
    {
      gsub(/__NAMESPACE__/, ns)
      gsub(/__TRUST_DOMAIN__/, td)
      gsub(/__IMAGE__/, image)
      gsub(/__APP_BODY__/, body)
      print
    }
  ' "$MANIFESTS" | kubectl --context "$context" apply -f -
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
    ip="$(kubectl --context "$context" -n "$NS" get pod -l app=svc \
      -o jsonpath='{.items[0].status.podIP}' 2>/dev/null || true)"
    if [[ -n "$ip" ]]; then
      printf '%s' "$ip"
      return 0
    fi
    sleep 2
  done
  echo "svc pod never reported a pod IP in $context" >&2
  return 1
}

# File-config mesh documents are rendered into ConfigMaps in two phases to avoid
# a stale-pod-IP race: the `dest` and `client` documents need no runtime endpoint
# discovery (loopback / peer node IP), so they are created BEFORE the pods; the
# `ew` document needs the local svc pod's IP, so it is created AFTER svc is up.
# This way no pod is ever restarted with a config that points at a since-rotated
# IP.
#
# IMPORTANT: NO `trust_bundles` in any document — the SPIRE Agent supplies the
# SVID *and* the federated peer bundle (set up by federate_spire), and a static
# file `trust_bundles` overlay would OVERRIDE that and defeat the federation
# proof. Cross-cluster remote classification rides `local_cluster` + the
# workload's `cluster` field (workload_is_remote fallback), so no live remote
# discovery poll is needed.

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

# Dest svc: LOCAL workload (loopback) + STRICT PeerAuth. workload_is_local
# materializes the inbound loopback route to the app on :8080. No discovery.
render_dest_config() {
  local context="$1" local_td="$2"
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

probe_gateway_reachable() {
  log "probing cross-cluster east-west reachability"
  # From a client pod in A, TCP-connect to B's east-west NodePort, and vice
  # versa. A successful TCP open proves L4 cross-cluster routing independent of
  # the mTLS/auth path.
  local ok_a=false ok_b=false
  if kubectl --context "$CONTEXT_A" -n "$NS" exec deploy/client -c curl -- \
    sh -c "curl -sS --connect-timeout 5 -o /dev/null \
      telnet://$NODE_IP_B:$EAST_WEST_NODEPORT" >/dev/null 2>&1; then
    ok_a=true
  fi
  if kubectl --context "$CONTEXT_B" -n "$NS" exec deploy/client -c curl -- \
    sh -c "curl -sS --connect-timeout 5 -o /dev/null \
      telnet://$NODE_IP_A:$EAST_WEST_NODEPORT" >/dev/null 2>&1; then
    ok_b=true
  fi
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
  record_live_assertion multicluster.eastwest.a_to_b_authenticated "$pass_ab" \
    "spiffe://$TRUST_DOMAIN_A/ns/$NS/sa/client" \
    "spiffe://$TRUST_DOMAIN_B/ns/$NS/sa/svc" \
    "status=$status_ab body=$body_ab"
  record_live_assertion multicluster.eastwest.b_to_a_authenticated "$pass_ba" \
    "spiffe://$TRUST_DOMAIN_B/ns/$NS/sa/client" \
    "spiffe://$TRUST_DOMAIN_A/ns/$NS/sa/svc" \
    "status=$status_ba body=$body_ba"
  if [[ "$pass_ab" == "pass" && "$pass_ba" == "pass" ]]; then
    record_live_assertion multicluster.eastwest.bidirectional_authenticated_traffic pass \
      "" "" "a_to_b=200/$body_ab b_to_a=200/$body_ba"
  else
    record_live_assertion multicluster.eastwest.bidirectional_authenticated_traffic fail \
      "" "" "a_to_b=$pass_ab($status_ab) b_to_a=$pass_ba($status_ba)"
    return 1
  fi
}

drive_untrusted_negative() {
  log "driving untrusted (unfederated) cross-cluster request A -> B"
  # The rogue pod's SVID is NOT federated with cluster B, so cluster B's STRICT
  # inbound rejects it. The request must NOT return 200/svc-b.
  local out status body
  out="$(drive_request "$CONTEXT_A" rogue)"
  status="${out%%$'\t'*}"
  body="${out#*$'\t'}"
  log "untrusted A -> B result: status=$status body=$body"
  if [[ "$status" != "200" || "$body" != *"svc-b"* ]]; then
    record_live_assertion multicluster.eastwest.untrusted_peer_rejected pass \
      "spiffe://$TRUST_DOMAIN_A/ns/$NS/sa/rogue" \
      "spiffe://$TRUST_DOMAIN_B/ns/$NS/sa/svc" \
      "rejected status=$status body=$body"
  else
    record_live_assertion multicluster.eastwest.untrusted_peer_rejected fail \
      "" "" "unfederated-peer-unexpectedly-reached-destination status=$status body=$body"
    return 1
  fi
}

# STAGE 3: bundle rotation/removal/invalid-delivery, endpoint failover, and
# network partitions hook in HERE. e.g. withdraw cluster B's federated bundle on
# A's SPIRE server (`spire-server bundle delete -id spiffe://$TRUST_DOMAIN_B`),
# re-drive A -> B, and assert it now fails closed (multicluster.federation.bundle_revoked_rejected);
# scale svc to 0 in B and assert failover/black-hole semantics; partition the
# kind docker network and assert last-good behavior. Out of scope for Stage 2.

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

  # Dest (loopback) + client (peer node IP) ConfigMaps — no svc-pod-IP needed.
  render_dest_config "$CONTEXT_A" "$TRUST_DOMAIN_A"
  render_dest_config "$CONTEXT_B" "$TRUST_DOMAIN_B"
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

  require_live_assertions
  log "multicluster-federation fixture PASSED; artifacts in $ARTIFACT_DIR"
}

main "$@"
