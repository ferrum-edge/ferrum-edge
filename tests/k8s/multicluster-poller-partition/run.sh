#!/usr/bin/env bash
set -euo pipefail

# Real two-CP/two-DP poller partition gate. All state transitions are observed
# through active bounded polling; the only sleeps are polling-loop cadences.
#
# Capturing assignments are spelled `VAR="$( cmd ... )"` with a space after the
# opening `$(`. The trusted Cross build policy scans a quote-stripped rendering
# of this file, where `VAR="$(cmd "$arg" ...)"` collapses to `VAR=$(cmd arg ...)`
# and `VAR=$(cmd` parses as an assignment word, promoting the following argument
# into an executable slot. The space keeps the substitution's command word in the
# executable slot it actually occupies. Do not remove it.

ROOT_DIR="$( cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FIXTURE_DIR="$ROOT_DIR/tests/k8s/multicluster-poller-partition"
MANIFESTS="$FIXTURE_DIR/manifests.yaml"
SPIRE_MANIFESTS="$FIXTURE_DIR/spire-manifests.yaml"
RESULTS_DIR="${FERRUM_POLLER_RESULTS_DIR:-$ROOT_DIR/target/multicluster-poller-partition}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/.context/multicluster-poller-partition}"

CLUSTER_A="${CLUSTER_A:-ferrum-poller-a}"
CLUSTER_B="${CLUSTER_B:-ferrum-poller-b}"
CONTEXT_A="kind-$CLUSTER_A"
CONTEXT_B="kind-$CLUSTER_B"
TOXIPROXY_CONTAINER="${TOXIPROXY_CONTAINER:-ferrum-poller-toxiproxy}"
TOXIPROXY_IMAGE="${TOXIPROXY_IMAGE:-ghcr.io/shopify/toxiproxy:2.12.0@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e}"
NS="${FERRUM_NAMESPACE:-ferrum}"
SPIRE_NS="${FERRUM_SPIRE_NAMESPACE:-spire-system}"
SPIRE_SERVER_IMAGE="${FERRUM_SPIRE_SERVER_IMAGE:-ghcr.io/spiffe/spire-server:1.12.4}"
SPIRE_AGENT_IMAGE="${FERRUM_SPIRE_AGENT_IMAGE:-ghcr.io/spiffe/spire-agent:1.12.4}"
SPIRE_SERVER_HEALTH_PORT="${FERRUM_SPIRE_SERVER_HEALTH_PORT:-8080}"
SPIRE_AGENT_HEALTH_PORT="${FERRUM_SPIRE_AGENT_HEALTH_PORT:-8082}"
SPIRE_BUNDLE_ENDPOINT_PORT="${FERRUM_SPIRE_BUNDLE_ENDPOINT_PORT:-8443}"
TD_A="${FERRUM_TRUST_DOMAIN_A:-cluster-a.test}"
TD_B="${FERRUM_TRUST_DOMAIN_B:-cluster-b.test}"
IMAGE_REPOSITORY="${FERRUM_IMAGE_REPOSITORY:-ferrum-edge}"
IMAGE_TAG="${FERRUM_IMAGE_TAG:-multicluster-poller-partition}"
IMAGE="$IMAGE_REPOSITORY:$IMAGE_TAG"
LIVE_ASSERTIONS_FILE="${FERRUM_LIVE_ASSERTIONS_FILE:-$RESULTS_DIR/live-assertions.json}"
LIVE_PLATFORM_PROFILE="${FERRUM_LIVE_PLATFORM_PROFILE:-kind-spire-toxiproxy-multicluster-pollers}"

FED_AB=federation-a-to-b
DISC_AB=discovery-a-to-b
FED_BA=federation-b-to-a
DISC_BA=discovery-b-to-a
FED_AB_PORT=15441
DISC_AB_PORT=15442
FED_BA_PORT=15443
DISC_BA_PORT=15444
NODE_A="" NODE_B="" TOXI_IP="" ADMIN_SECRET="" JWT_A="" JWT_B=""
INITIAL_TRUST_AGE=0 INITIAL_ENDPOINT_AGE=0
INITIAL_FEDERATION_SUCCESS_AT=0 INITIAL_DISCOVERY_SUCCESSES=0
INITIAL_REVERSE_FEDERATION_SUCCESS_AT=0 INITIAL_REVERSE_DISCOVERY_SUCCESSES=0
INITIAL_FEDERATION_FAILURES=0 INITIAL_DISCOVERY_FAILURES=0
TRANSIENT_FEDERATION_FAILURE_DELTA=0 TRANSIENT_DISCOVERY_FAILURE_DELTA=0
RECORDED=" "

mkdir -p "$RESULTS_DIR" "$ARTIFACT_DIR"

log() { printf '\n[multicluster-poller] %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 127; }; }

record() {
  local id="$1" status="$2" outcome="${3:-}" diagnostic="${4:-}"
  python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py record "$LIVE_ASSERTIONS_FILE" \
    "$id" "$status" "$outcome" "$diagnostic"
  RECORDED="$RECORDED$id "
}

cleanup() {
  set +e
  if [[ -n "$TOXI_IP" ]]; then collect_diagnostics; fi
  docker rm -f "$TOXIPROXY_CONTAINER" >/dev/null 2>&1
  kind delete cluster --name "$CLUSTER_A" >/dev/null 2>&1
  kind delete cluster --name "$CLUSTER_B" >/dev/null 2>&1
}
trap cleanup EXIT

preflight() {
  python3 ./tests/k8s/multicluster-poller-partition/verify_signal_reload_guard.py
  for command in docker kind kubectl curl python3 openssl sed; do need "$command"; done
  docker info >/dev/null
  [[ "${FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE:-}" == true ]] || {
    echo "set FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE=true" >&2; exit 1;
  }
  if kind get clusters | grep -Fxq "$CLUSTER_A" || kind get clusters | grep -Fxq "$CLUSTER_B"; then
    echo "refusing to share pre-existing kind cluster state" >&2; exit 1
  fi
  if docker inspect "$TOXIPROXY_CONTAINER" >/dev/null 2>&1; then
    echo "refusing to share pre-existing Toxiproxy state" >&2; exit 1
  fi
}

wait_for_curl() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if curl "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_state() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if state_matches "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_fresh_state() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if fresh_state "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_traffic() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if traffic_once "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_not_found() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if traffic_not_found "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_ages_increased() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if ages_increased_below_stale "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_projected_withdrawal() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if projected_config_withdrawn "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_proxy_accept() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if proxy_accepted_client_increased "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_metric_increase() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if metric_increased "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

wait_for_no_configured_state() {
  local label="$1" timeout="$2"; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if no_configured_state "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

# Keep this policy-scanned fixture's dependency graph limited to the exact
# SPIRE operations it uses. Shared live helpers also serve broader suites and
# expose unrelated automation that this gate neither needs nor should inherit.
spire_apply_minimal() {
  local context="$1" trust_domain="$2" namespace="$3"
  # Keep replacement expansions behind a sed-only delimiter so the trusted
  # automation scanner never has to interpret them as shell pipeline slots.
  sed -e "s#__SPIRE_NAMESPACE__#$namespace#g" \
    -e "s#__TRUST_DOMAIN__#$trust_domain#g" \
    -e "s#__SPIRE_SERVER_IMAGE__#$SPIRE_SERVER_IMAGE#g" \
    -e "s#__SPIRE_AGENT_IMAGE__#$SPIRE_AGENT_IMAGE#g" \
    -e "s#__SPIRE_SERVER_HEALTH_PORT__#$SPIRE_SERVER_HEALTH_PORT#g" \
    -e "s#__SPIRE_AGENT_HEALTH_PORT__#$SPIRE_AGENT_HEALTH_PORT#g" \
    -e "s#__SPIRE_BUNDLE_ENDPOINT_PORT__#$SPIRE_BUNDLE_ENDPOINT_PORT#g" \
    "$SPIRE_MANIFESTS" | kubectl --context "$context" apply -f -
}

spire_wait_ready() {
  local context="$1" namespace="$2" timeout="$3"
  kubectl --context "$context" -n "$namespace" rollout status statefulset/spire-server --timeout="$timeout"
  kubectl --context "$context" -n "$namespace" rollout status daemonset/spire-agent --timeout="$timeout"
}

spire_agent_nodes() {
  kubectl --context "$1" -n "$2" get pod -l app=spire-agent \
    -o jsonpath='{range .items[*]}{.status.phase}{"\t"}{.spec.nodeName}{"\n"}{end}' |
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      running-spire-nodes
}

spire_server_pod() {
  kubectl --context "$1" -n "$2" get pod -l app=spire-server \
    -o jsonpath='{.items[0].metadata.name}'
}

spire_server_exec() {
  local context="$1" namespace="$2" pod
  shift 2
  pod="$( spire_server_pod "$context" "$namespace")"
  [[ -n "$pod" ]] || { echo "no spire-server pod found in namespace $namespace" >&2; return 1; }
  kubectl --context "$context" -n "$namespace" exec "$pod" -- \
    /opt/spire/bin/spire-server "$@" -socketPath /run/spire/server.sock
}

spire_entry_has_selectors() {
  local output="$1" selector
  shift
  for selector in "$@"; do
    grep -q "Selector[[:space:]]*:[[:space:]]*$selector" <<<"$output" || return 1
  done
}

spire_parent_id_for_node() {
  local context="$1" namespace="$2" trust_domain="$3" node_name="$4"
  local attempts="${FERRUM_SPIRE_AGENT_PARENT_ID_ATTEMPTS:-30}"
  local sleep_seconds="${FERRUM_SPIRE_AGENT_PARENT_ID_SLEEP_SECONDS:-2}"
  local node_uid parent_id attempt
  node_uid="$( kubectl --context "$context" get node "$node_name" -o jsonpath='{.metadata.uid}')"
  [[ -n "$node_uid" ]] || { echo "node $node_name has no Kubernetes UID" >&2; return 1; }
  parent_id="spiffe://$trust_domain/spire/agent/k8s_psat/$trust_domain/$node_uid"
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if spire_server_exec "$context" "$namespace" agent show -spiffeID "$parent_id" >/dev/null 2>&1; then
      printf '%s\n' "$parent_id"
      return 0
    fi
    sleep "$sleep_seconds"
  done
  echo "SPIRE agent for node $node_name is not attested" >&2
  spire_server_exec "$context" "$namespace" agent list >&2 || true
  return 1
}

spire_register_workload() {
  # Closed call contract: exactly one node selector beyond ns/sa (see sole caller).
  # A dynamic argv array here is opaque to the trusted build-policy
  # verifier for newly added automation, so keep the create dispatch fully literal.
  local context="$1" namespace="$2" spiffe_id="$3" parent_id="$4"
  local workload_namespace="$5" service_account="$6" node_selector="$7"
  local existing="" ns_selector sa_selector
  [[ $# -eq 7 && -n "$node_selector" ]] || {
    echo "spire_register_workload requires ns, sa, and exactly one node selector" >&2
    return 1
  }
  ns_selector="k8s:ns:$workload_namespace"
  sa_selector="k8s:sa:$service_account"
  if existing="$( spire_server_exec "$context" "$namespace" entry show \
      -spiffeID "$spiffe_id" -parentID "$parent_id" 2>/dev/null)" &&
    spire_entry_has_selectors "$existing" \
      "$ns_selector" "$sa_selector" "$node_selector"; then
    return 0
  fi
  spire_server_exec "$context" "$namespace" \
    entry create \
    -spiffeID "$spiffe_id" \
    -parentID "$parent_id" \
    -selector "$ns_selector" \
    -selector "$sa_selector" \
    -selector "$node_selector"
}

spire_bundle_b64der() {
  spire_server_exec "$1" "$SPIRE_NS" bundle show -format pem 2>/dev/null |
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      bundle-b64der
}

mint_admin_jwt() {
  python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
    mint-admin-jwt "$ADMIN_SECRET"
}

create_clusters_and_fault_layer() {
  kind create cluster --name "$CLUSTER_A" --wait 180s
  kind create cluster --name "$CLUSTER_B" --wait 180s
  kind load docker-image "$IMAGE" --name "$CLUSTER_A"
  kind load docker-image "$IMAGE" --name "$CLUSTER_B"
  NODE_A="$( docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLUSTER_A-control-plane")"
  NODE_B="$( docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLUSTER_B-control-plane")"
  [[ -n "$NODE_A" && -n "$NODE_B" ]] || { echo "kind node IP discovery failed" >&2; return 1; }

  docker run -d --name "$TOXIPROXY_CONTAINER" --network kind "$TOXIPROXY_IMAGE" \
    -host=0.0.0.0 -proxy-metrics >/dev/null
  TOXI_IP="$( docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TOXIPROXY_CONTAINER")"
  [[ -n "$TOXI_IP" ]] || { echo "Toxiproxy IP discovery failed" >&2; return 1; }
  wait_for_curl "Toxiproxy API" 30 -fsS "http://$TOXI_IP:8474/version" >/dev/null

  create_proxy "$FED_AB" "$FED_AB_PORT" "$NODE_B:32443"
  create_proxy "$DISC_AB" "$DISC_AB_PORT" "$NODE_B:32551"
  create_proxy "$FED_BA" "$FED_BA_PORT" "$NODE_A:32443"
  create_proxy "$DISC_BA" "$DISC_BA_PORT" "$NODE_A:32551"
  local count
  count="$( curl -fsS "http://$TOXI_IP:8474/proxies" | \
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py proxy-count)"
  [[ "$count" == 4 ]] || { echo "Toxiproxy fixture startup incomplete: $count/4 proxies" >&2; return 1; }
}

create_proxy() {
  curl -fsS -X POST -H 'Content-Type: application/json' "http://$TOXI_IP:8474/proxies" \
    --data "{\"name\":\"$1\",\"listen\":\"0.0.0.0:$2\",\"upstream\":\"$3\",\"enabled\":true}" >/dev/null
}

set_proxy() {
  curl -fsS -X POST -H 'Content-Type: application/json' "http://$TOXI_IP:8474/proxies/$1" \
    --data "{\"enabled\":$2}" >/dev/null
}

set_all_proxies() { local name; for name in "$FED_AB" "$DISC_AB" "$FED_BA" "$DISC_BA"; do set_proxy "$name" "$1"; done; }

add_latency() {
  curl -fsS -X POST -H 'Content-Type: application/json' "http://$TOXI_IP:8474/proxies/$1/toxics" \
    --data '{"name":"inflight","type":"latency","stream":"downstream","toxicity":1,"attributes":{"latency":60000,"jitter":0}}' >/dev/null
}

remove_latency() { curl -fsS -X DELETE "http://$TOXI_IP:8474/proxies/$1/toxics/inflight" >/dev/null; }

proxy_accepted_client_count() {
  docker logs "$TOXIPROXY_CONTAINER" | \
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      toxiproxy-accepted-client-count "$1"
}

proxy_accepted_client_increased() {
  local current
  current="$( proxy_accepted_client_count "$1")" || return 1
  bounded_uint "$current" "accepted-client count for $1" >/dev/null || return 1
  (( current > $2 ))
}

generate_transport_material() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ferrum-poller-live-ca \
    -keyout "$ARTIFACT_DIR/ca-key.pem" -out "$ARTIFACT_DIR/ca.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj /CN=ferrum-poller-server \
    -keyout "$ARTIFACT_DIR/server-key.pem" -out "$ARTIFACT_DIR/server.csr" >/dev/null 2>&1
  printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$TOXI_IP" > "$ARTIFACT_DIR/server.ext"
  openssl x509 -req -days 1 -in "$ARTIFACT_DIR/server.csr" -CA "$ARTIFACT_DIR/ca.pem" \
    -CAkey "$ARTIFACT_DIR/ca-key.pem" -CAcreateserial -extfile "$ARTIFACT_DIR/server.ext" \
    -out "$ARTIFACT_DIR/server.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj /CN=ferrum-poller-dp \
    -keyout "$ARTIFACT_DIR/client-key.pem" -out "$ARTIFACT_DIR/client.csr" >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' > "$ARTIFACT_DIR/client.ext"
  openssl x509 -req -days 1 -in "$ARTIFACT_DIR/client.csr" -CA "$ARTIFACT_DIR/ca.pem" \
    -CAkey "$ARTIFACT_DIR/ca-key.pem" -CAcreateserial -extfile "$ARTIFACT_DIR/client.ext" \
    -out "$ARTIFACT_DIR/client.pem" >/dev/null 2>&1
}

register_spire_workload() {
  local context="$1" td="$2" node parent
  while IFS= read -r node; do
    parent="$( spire_parent_id_for_node "$context" "$SPIRE_NS" "$td" "$node")"
    spire_register_workload "$context" "$SPIRE_NS" \
      "spiffe://$td/ns/$NS/sa/mesh-dp" "$parent" "$NS" mesh-dp "k8s:node-name:$node"
  done < <(spire_agent_nodes "$context" "$SPIRE_NS")
}

apply_support_material() {
  local context="$1" td="$2" cluster="$3" local_secret="$4" peer_secret="$5" bundle
  kubectl --context "$context" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
  kubectl --context "$context" -n "$NS" create secret generic poller-transport \
    --from-file=ca.pem="$ARTIFACT_DIR/ca.pem" --from-file=server.pem="$ARTIFACT_DIR/server.pem" \
    --from-file=server-key.pem="$ARTIFACT_DIR/server-key.pem" --from-file=client.pem="$ARTIFACT_DIR/client.pem" \
    --from-file=client-key.pem="$ARTIFACT_DIR/client-key.pem" --dry-run=client -o yaml |
    kubectl --context "$context" apply -f -
  kubectl --context "$context" -n "$NS" create secret generic poller-secrets \
    --from-literal=admin-jwt-secret="$ADMIN_SECRET" --from-literal=discovery-jwt-secret="$local_secret" \
    --from-literal=remote-discovery-credentials="{\"peer\":\"$peer_secret\"}" \
    --dry-run=client -o yaml | kubectl --context "$context" apply -f -
  bundle="$( spire_bundle_b64der "$context")"
  [[ -n "$bundle" ]] || { echo "empty SPIRE bundle for $cluster" >&2; return 1; }
  python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
    bundle-json "$td" "$bundle" > "$ARTIFACT_DIR/bundle-$cluster.json"
  kubectl --context "$context" -n "$NS" create configmap federation-bundle \
    --from-file=bundle.json="$ARTIFACT_DIR/bundle-$cluster.json" --dry-run=client -o yaml |
    kubectl --context "$context" apply -f -
}

render_mesh_config() {
  local context="$1" local_cluster="$2" local_td="$3" local_service="$4" local_region="$5"
  local peer_cluster="$6" peer_td="$7" peer_service="$8" peer_node="$9" fed_port="${10}" disc_port="${11}"
  local peer_context="${12}" local_bundle peer_bundle remote_block
  local_bundle="$( spire_bundle_b64der "$context")"
  peer_bundle="$( spire_bundle_b64der "$peer_context")"
  remote_block="$( cat <<YAML
  multi_cluster:
    local_cluster: $local_cluster
    remote_clusters:
      - name: $peer_cluster
        trust_domain: $peer_td
        network: net-$peer_cluster
        control_plane_url: grpcs://$TOXI_IP:$disc_port
        federation_endpoint: https://$TOXI_IP:$fed_port/bundle
        discovery_credential_ref: peer
    east_west_gateways:
      - name: ew-$peer_cluster
        namespace: $NS
        host: $peer_node
        port: 31506
        sni_hosts:
          - $peer_service.$NS.svc.cluster.local
        trust_domain: $peer_td
        network: net-$peer_cluster
YAML
)"
  apply_mesh_config "$context" "$local_cluster" "$local_td" "$local_service" "$local_region" "$local_bundle" "$remote_block" "$peer_td" "$peer_bundle"
}

apply_mesh_config() {
  local context="$1" local_cluster="$2" local_td="$3" local_service="$4" local_region="$5" local_bundle="$6" remote_block="${7:-}"
  local peer_td="${8:-}" peer_bundle="${9:-}" authorities="" federated="" line
  while IFS= read -r line; do
    if [[ -n "$line" ]]; then
      authorities="${authorities}        - ${line}"$'\n'
    fi
  done <<<"$local_bundle"
  if [[ -n "$peer_td" && -n "$peer_bundle" ]]; then
    federated="    federated:"$'\n'"      - trust_domain: $peer_td"$'\n'"        x509_authorities:"$'\n'
    while IFS= read -r line; do
      if [[ -n "$line" ]]; then
        federated="${federated}          - ${line}"$'\n'
      fi
    done <<<"$peer_bundle"
  fi
  kubectl --context "$context" -n "$NS" create configmap mesh-config --from-literal=mesh.yaml="$( cat <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$local_td/ns/$NS/sa/mesh-dp
      service_name: $local_service
      namespace: $NS
      trust_domain: $local_td
      service_account: mesh-dp
      addresses: [127.0.0.1]
      locality: $local_region/zone-1
      ports:
        - {port: 8080, protocol: http, name: http}
      selector:
        labels: {app: echo}
        namespace: $NS
  services:
    - name: $local_service
      namespace: $NS
      ports:
        - {port: 8080, protocol: http, name: http}
      workloads:
        - spiffe_id: spiffe://$local_td/ns/$NS/sa/mesh-dp
  trust_bundles:
    local:
      trust_domain: $local_td
      x509_authorities:
$authorities$federated  peer_authentications:
    - name: strict
      namespace: $NS
      mtls_mode: strict
$remote_block
YAML
)" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
}

apply_manifest() {
  local context="$1" td="$2" cluster="$3" service="$4" body="$5" region="$6"
  sed -e "s#__NAMESPACE__#$NS#g" -e "s#__TRUST_DOMAIN__#$td#g" \
    -e "s#__CLUSTER_NAME__#$cluster#g" -e "s#__ECHO_SERVICE__#$service#g" \
    -e "s#__ECHO_BODY__#$body#g" -e "s#__REGION__#$region#g" -e "s#__IMAGE__#$IMAGE#g" \
    "$MANIFESTS" | kubectl --context "$context" apply -f -
  kubectl --context "$context" -n "$NS" rollout status deploy/ferrum-cp --timeout=5m
  kubectl --context "$context" -n "$NS" rollout status deploy/federation-bundle --timeout=5m
  kubectl --context "$context" -n "$NS" rollout status deploy/echo --timeout=5m
}

admin_json() {
  kubectl --context "$1" -n "$NS" exec deploy/echo -c probe -- \
    curl -fsS -m 5 -H "Authorization: Bearer $2" http://127.0.0.1:15020/mesh/remote-clusters
}

metrics() {
  kubectl --context "$1" -n "$NS" exec deploy/echo -c probe -- \
    curl -fsS -m 5 -H "Authorization: Bearer $2" http://127.0.0.1:15020/metrics
}

state_matches() {
  local context="$1" token="$2" peer="$3" discovered="$4" trust_source="$5" outbound="$6" inbound="$7"
  admin_json "$context" "$token" | \
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      state-matches "$peer" "$discovered" "$trust_source" "$outbound" "$inbound"
}

no_configured_state() {
  admin_json "$1" "$2" | \
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      no-configured-state
}

traffic_once() {
  local context="$1" service="$2" expected="$3" response status body
  response="$( kubectl --context "$context" -n "$NS" exec deploy/echo -c probe -- \
    curl -sS -m 5 -w $'\n%{http_code}' -H "Host: $service.$NS.svc.cluster.local" \
      http://127.0.0.1:15001/)" || return 1
  status="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [[ "$status" == 200 ]] || return 1
  [[ "$body" == *"$expected"* ]]
}

traffic_fails() { ! traffic_once "$1" "$2" "$3"; }

traffic_not_found() {
  local context="$1" service="$2" response status body
  response="$( kubectl --context "$context" -n "$NS" exec deploy/echo -c probe -- \
    curl -sS -m 5 -w $'\n%{http_code}' -H "Host: $service.$NS.svc.cluster.local" \
      http://127.0.0.1:15001/)" || return 1
  status="${response##*$'\n'}"
  body="${response%$'\n'*}"
  [[ "$status" == 404 ]] || return 1
  [[ "$body" == *"Not Found"* ]]
}

metric_value() {
  local context="$1" token="$2" metric="$3" selector="$4"
  metrics "$context" "$token" | \
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      prometheus-value "$metric" "$selector"
}

metric_file_value() {
  local file="$1" metric="$2" selector="$3"
  python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
    prometheus-value "$metric" "$selector" < "$file"
}

bounded_uint() {
  local value="$1" label="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "metric is not a bounded unsigned integer: $label" >&2
    return 1
  fi
  if [[ "${#value}" -gt 18 ]]; then
    echo "metric is not a bounded unsigned integer: $label" >&2
    return 1
  fi
  printf '%s\n' "$((10#$value))"
}

metric_file_uint_value() {
  local value metric="$2"
  value="$( metric_file_value "$@")" || return 1
  bounded_uint "$value" "$metric"
}

# A missing Prometheus family and a genuinely zero counter both read as 0.
# Report which one a snapshot actually contains so a zero delta names its own
# cause instead of leaving "absent series" and "no increment" indistinguishable.
metric_family_presence() {
  local file="$1" metric="$2"
  if grep -Fq "$metric{" "$file"; then
    printf 'series-present\n'
  else
    printf 'series-absent\n'
  fi
}

metric_uint_value() {
  local value metric="$3"
  value="$( metric_value "$@")" || return 1
  bounded_uint "$value" "$metric"
}

metric_increased() {
  local current
  current="$( metric_uint_value "$1" "$2" "$3" "$4")" || return 1
  (( current > $5 ))
}

ages_between() {
  admin_json "$1" "$2" | \
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      ages-between "$3" "$4" "$5"
}

fresh_state() { ages_between "$1" "$2" "$3" 0 5; }

admin_ages() {
  admin_json "$1" "$2" | \
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      admin-ages "$3"
}

ages_increased_below_stale() {
  local ages trust_age endpoint_age
  ages="$( admin_ages "$1" "$2" "$3")" || return 1
  read -r trust_age endpoint_age <<<"$ages"
  (( trust_age >= 3 && endpoint_age >= 3 &&
     trust_age > INITIAL_TRUST_AGE && endpoint_age > INITIAL_ENDPOINT_AGE &&
     endpoint_age < 8 && trust_age < 12 ))
}

capture_boundary() {
  admin_json "$1" "$2" > "$RESULTS_DIR/$3.json"
  metrics "$1" "$2" > "$RESULTS_DIR/$3.prom"
}

assert_metric_admin_parity() {
  local context="$1" token="$2" peer="$3" td="$4"
  local json_before="$RESULTS_DIR/parity-before.json"
  local json_after="$RESULTS_DIR/parity-after.json"
  local metrics_file="$RESULTS_DIR/parity.prom"
  # Admin/metrics are separate HTTP requests. Capture enclosing admin snapshots
  # so a poll that lands between them cannot fail a single-generation parity check.
  admin_json "$context" "$token" > "$json_before"
  metrics "$context" "$token" > "$metrics_file"
  admin_json "$context" "$token" > "$json_after"
  python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
    assert-metric-admin-parity "$json_before" "$metrics_file" "$json_after" "$peer" "$td"
}

projected_config_withdrawn() {
  local config
  config="$( kubectl --context "$1" -n "$NS" exec deploy/echo -c signal -- \
    cat /mesh/mesh.yaml)" || return 1
  ! grep -q remote_clusters <<<"$config"
}

signal_reload() {
  local context="$1" pod
  pod="$( kubectl --context "$context" -n "$NS" --request-timeout=10s \
    get pod -l app=echo --field-selector=status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}')" || return 1
  [[ -n "$pod" ]] || { echo "no running echo pod found for ConfigMap refresh" >&2; return 1; }
  # Mutate only the live Pod object. This prompts kubelet to refresh its projected
  # ConfigMap without replacing the Pod or the in-flight poll generation.
  kubectl --context "$context" -n "$NS" --request-timeout=10s \
    annotate pod "$pod" \
      "ferrum-edge.io/projected-config-refresh=withdrawal-$SECONDS" --overwrite
  wait_for_projected_withdrawal "projected withdrawn mesh config" 30 "$context"
  # The readiness probe also runs `ferrum-edge health` in this shared process
  # namespace. `pidof ferrum-edge` can therefore return both the daemon and a
  # transient probe process. `/proc/<pid>/exe` is an unnecessary identity race,
  # so select by argv instead. The signal sidecar deliberately runs as the same
  # non-root UID 1337 as the gateway: Linux credential checks otherwise deny
  # both `/proc/<pid>/cmdline` reads and signal delivery across containers.
  # procfs reports cmdline pseudo-files with st_size=0 even when reading them
  # returns argv, so never gate the scan with `test -s`. Parse the file and
  # require argv[0] basename
  # `ferrum-edge` and argv[1] `run`, compare only as data, and discover +
  # signal exactly one candidate in one exec to minimize the PID lifetime gap.
  kubectl --context "$context" -n "$NS" exec "pod/$pod" -c signal -- sh -eu -c '
    found=""
    for process_dir in /proc/[0-9]*; do
      [ -r "$process_dir/cmdline" ] || continue
      argv0=""
      argv1=""
      pos=0
      while IFS= read -r -d "" arg || [ -n "$arg" ]; do
        case "$pos" in
          0) argv0="$arg" ;;
          1) argv1="$arg"; break ;;
        esac
        pos=$((pos + 1))
      done < "$process_dir/cmdline"
      [ -n "$argv0" ] || continue
      [ "${argv0##*/}" = "ferrum-edge" ] || continue
      [ "$argv1" = "run" ] || continue
      candidate="${process_dir##*/}"
      if [ -n "$found" ]; then
        echo "multiple ferrum-edge run processes found: $found $candidate" >&2
        exit 1
      fi
      found="$candidate"
    done
    [ -n "$found" ] || {
      echo "no ferrum-edge run process found" >&2
      exit 1
    }
    kill -HUP "$found"
  '
}

deploy_topology() {
  spire_apply_minimal "$CONTEXT_A" "$TD_A" "$SPIRE_NS"
  spire_apply_minimal "$CONTEXT_B" "$TD_B" "$SPIRE_NS"
  spire_wait_ready "$CONTEXT_A" "$SPIRE_NS" 5m
  spire_wait_ready "$CONTEXT_B" "$SPIRE_NS" 5m
  register_spire_workload "$CONTEXT_A" "$TD_A"
  register_spire_workload "$CONTEXT_B" "$TD_B"
  ADMIN_SECRET="$( openssl rand -hex 32)"
  local secret_a secret_b
  secret_a="$( openssl rand -hex 32)"; secret_b="$( openssl rand -hex 32)"
  apply_support_material "$CONTEXT_A" "$TD_A" cluster-a "$secret_a" "$secret_b"
  apply_support_material "$CONTEXT_B" "$TD_B" cluster-b "$secret_b" "$secret_a"
  render_mesh_config "$CONTEXT_A" cluster-a "$TD_A" echo-a region-a cluster-b "$TD_B" echo-b "$NODE_B" "$FED_AB_PORT" "$DISC_AB_PORT" "$CONTEXT_B"
  render_mesh_config "$CONTEXT_B" cluster-b "$TD_B" echo-b region-b cluster-a "$TD_A" echo-a "$NODE_A" "$FED_BA_PORT" "$DISC_BA_PORT" "$CONTEXT_A"
  apply_manifest "$CONTEXT_A" "$TD_A" cluster-a echo-a echo-a region-a
  apply_manifest "$CONTEXT_B" "$TD_B" cluster-b echo-b echo-b region-b
  JWT_A="$( mint_admin_jwt)"; JWT_B="$( mint_admin_jwt)"
}

scenario_initial() {
  wait_for_state "A initial polled trust and endpoints" 90 "$CONTEXT_A" "$JWT_A" cluster-b true polled true true
  wait_for_state "B initial polled trust and endpoints" 90 "$CONTEXT_B" "$JWT_B" cluster-a true polled true true
  wait_for_fresh_state "A initial cache freshness" 20 "$CONTEXT_A" "$JWT_A" cluster-b
  INITIAL_FEDERATION_SUCCESS_AT="$( metric_uint_value "$CONTEXT_A" "$JWT_A" ferrum_mesh_federation_last_success_timestamp_seconds "trust_domain=\"$TD_B\"")"
  INITIAL_DISCOVERY_SUCCESSES="$( metric_uint_value "$CONTEXT_A" "$JWT_A" ferrum_mesh_remote_discovery_poll_successes_total "cluster=\"cluster-b\"")"
  INITIAL_REVERSE_FEDERATION_SUCCESS_AT="$( metric_uint_value "$CONTEXT_B" "$JWT_B" ferrum_mesh_federation_last_success_timestamp_seconds "trust_domain=\"$TD_A\"")"
  INITIAL_REVERSE_DISCOVERY_SUCCESSES="$( metric_uint_value "$CONTEXT_B" "$JWT_B" ferrum_mesh_remote_discovery_poll_successes_total "cluster=\"cluster-a\"")"
  wait_for_traffic "A to B initial traffic" 60 "$CONTEXT_A" echo-b echo-b
  wait_for_traffic "B to A initial traffic" 60 "$CONTEXT_B" echo-a echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.initial.polled_trust_endpoints_installed
  local initial_metrics="$RESULTS_DIR/poller.initial.polled_trust_endpoints_installed.prom"
  INITIAL_FEDERATION_FAILURES="$( metric_file_uint_value "$initial_metrics" ferrum_mesh_federation_poll_failures_total "trust_domain=\"$TD_B\"")"
  INITIAL_DISCOVERY_FAILURES="$( metric_file_uint_value "$initial_metrics" ferrum_mesh_remote_discovery_poll_failures_total "cluster=\"cluster-b\"")"
  record multicluster_poller.initial.polled_trust_endpoints_installed pass "both-directions-polled-and-200" "poller.initial.polled_trust_endpoints_installed.{json,prom}"
}

scenario_transient() {
  read -r INITIAL_TRUST_AGE INITIAL_ENDPOINT_AGE < <(admin_ages "$CONTEXT_A" "$JWT_A" cluster-b)
  set_all_proxies false
  # Observe the retained caches before doing any serial counter accounting.
  # The endpoint window is only eight seconds; waiting for metrics first can
  # consume that window and turn a short-partition assertion into an expiry.
  wait_for_ages_increased "last-good cache ages increase below both stale windows" 7 "$CONTEXT_A" "$JWT_A" cluster-b
  traffic_once "$CONTEXT_A" echo-b echo-b; traffic_once "$CONTEXT_B" echo-a echo-a
  local transient_json="$RESULTS_DIR/poller.transient.last_good_retained.json"
  local transient_metrics="$RESULTS_DIR/poller.transient.last_good_retained.prom"
  local snapshot_ages snapshot_trust_age snapshot_endpoint_age ff df
  local fed_presence disc_presence
  admin_json "$CONTEXT_A" "$JWT_A" > "$transient_json"
  metrics "$CONTEXT_A" "$JWT_A" > "$transient_metrics"
  set_all_proxies true
  snapshot_ages="$( python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
    admin-ages cluster-b < "$transient_json")"
  read -r snapshot_trust_age snapshot_endpoint_age <<<"$snapshot_ages"
  (( snapshot_trust_age >= 3 && snapshot_endpoint_age >= 3 &&
     snapshot_trust_age > INITIAL_TRUST_AGE &&
     snapshot_endpoint_age > INITIAL_ENDPOINT_AGE &&
     snapshot_endpoint_age < 8 && snapshot_trust_age < 12 )) || {
    echo "transient cache snapshot escaped stale bounds: trust=$snapshot_trust_age endpoint=$snapshot_endpoint_age" >&2
    return 1
  }
  ff="$( metric_file_uint_value "$transient_metrics" ferrum_mesh_federation_poll_failures_total "trust_domain=\"$TD_B\"")"
  df="$( metric_file_uint_value "$transient_metrics" ferrum_mesh_remote_discovery_poll_failures_total "cluster=\"cluster-b\"")"
  (( ff >= INITIAL_FEDERATION_FAILURES && df >= INITIAL_DISCOVERY_FAILURES )) || {
    echo "failure counter regressed over partition boundary" >&2; return 1;
  }
  TRANSIENT_FEDERATION_FAILURE_DELTA=$((ff - INITIAL_FEDERATION_FAILURES))
  TRANSIENT_DISCOVERY_FAILURE_DELTA=$((df - INITIAL_DISCOVERY_FAILURES))
  (( TRANSIENT_FEDERATION_FAILURE_DELTA >= 1 && TRANSIENT_FEDERATION_FAILURE_DELTA <= 5 &&
     TRANSIENT_DISCOVERY_FAILURE_DELTA >= 1 && TRANSIENT_DISCOVERY_FAILURE_DELTA <= 5 )) || {
    fed_presence="$( metric_family_presence "$transient_metrics" ferrum_mesh_federation_poll_failures_total)"
    disc_presence="$( metric_family_presence "$transient_metrics" ferrum_mesh_remote_discovery_poll_failures_total)"
    echo "unbounded partition failure deltas during backoff: federation=$TRANSIENT_FEDERATION_FAILURE_DELTA discovery=$TRANSIENT_DISCOVERY_FAILURE_DELTA" >&2
    echo "partition snapshot series: federation=$fed_presence discovery=$disc_presence" >&2
    return 1
  }
  record multicluster_poller.transient.last_good_retained pass "traffic-200-during-short-partition" "poller.transient.last_good_retained.{json,prom}"
  record multicluster_poller.transient.cache_age_increased pass "trust-and-endpoint-age-3-to-7-seconds" "poller.transient.last_good_retained.json"
  # Cache age is deliberately still below the stale windows here. Merely
  # observing an age below five seconds after re-enabling Toxiproxy can therefore
  # accept the retained pre-partition value before either poller has recovered.
  # Prove a real post-partition poll in both directions by waiting on each
  # monotonic success signal before using freshness as the admin/status check.
  wait_for_metric_increase "A federation poll recovery" 40 "$CONTEXT_A" "$JWT_A" \
    ferrum_mesh_federation_last_success_timestamp_seconds "trust_domain=\"$TD_B\"" \
    "$INITIAL_FEDERATION_SUCCESS_AT"
  wait_for_metric_increase "A discovery poll recovery" 40 "$CONTEXT_A" "$JWT_A" \
    ferrum_mesh_remote_discovery_poll_successes_total "cluster=\"cluster-b\"" \
    "$INITIAL_DISCOVERY_SUCCESSES"
  wait_for_metric_increase "B federation poll recovery" 40 "$CONTEXT_B" "$JWT_B" \
    ferrum_mesh_federation_last_success_timestamp_seconds "trust_domain=\"$TD_A\"" \
    "$INITIAL_REVERSE_FEDERATION_SUCCESS_AT"
  wait_for_metric_increase "B discovery poll recovery" 40 "$CONTEXT_B" "$JWT_B" \
    ferrum_mesh_remote_discovery_poll_successes_total "cluster=\"cluster-a\"" \
    "$INITIAL_REVERSE_DISCOVERY_SUCCESSES"
  wait_for_fresh_state "same-generation transient recovery" 40 "$CONTEXT_A" "$JWT_A" cluster-b
  wait_for_fresh_state "same-generation reverse recovery" 40 "$CONTEXT_B" "$JWT_B" cluster-a
  assert_metric_admin_parity "$CONTEXT_A" "$JWT_A" cluster-b "$TD_B"
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.metrics.failure_backoff_recovery_cache_age
  record multicluster_poller.metrics.failure_backoff_recovery_bounded pass \
    "bounded-partition-deltas-federation-$TRANSIENT_FEDERATION_FAILURE_DELTA-discovery-$TRANSIENT_DISCOVERY_FAILURE_DELTA-redacted-labels-recovered" \
    "poller.initial.polled_trust_endpoints_installed.prom,poller.transient.last_good_retained.prom,poller.metrics.failure_backoff_recovery_cache_age.prom"
  record multicluster_poller.metrics.admin_status_parity pass \
    "cache-ages-match-enclosing-admin-snapshots-within-two-seconds" \
    "parity-before.json,parity.prom,parity-after.json"
}

scenario_endpoint_expiry() {
  set_proxy "$DISC_AB" false
  wait_for_state "endpoint stale eviction independent of trust" 40 "$CONTEXT_A" "$JWT_A" cluster-b false polled true true
  wait_for_not_found "remote target removed with no-route reason" 20 "$CONTEXT_A" echo-b
  traffic_once "$CONTEXT_B" echo-a echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.endpoint.expired_fail_closed_target_removed
  record multicluster_poller.endpoint.expired_fail_closed pass "endpoint-window-8s-404-Not-Found-trust-still-polled" "poller.endpoint.expired_fail_closed_target_removed.{json,prom}"
  record multicluster_poller.endpoint.remote_target_removed pass "configured-peer-not-discovered" "poller.endpoint.expired_fail_closed_target_removed.json"
  set_proxy "$DISC_AB" true
  wait_for_state "endpoint reinstall by live generation" 45 "$CONTEXT_A" "$JWT_A" cluster-b true polled true true
  wait_for_traffic "endpoint traffic recovery" 30 "$CONTEXT_A" echo-b echo-b
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.endpoint.recovered_same_generation
  record multicluster_poller.endpoint.recovered_same_generation pass "no-slice-change-200" "poller.endpoint.recovered_same_generation.{json,prom}"
}

scenario_trust_expiry() {
  set_proxy "$FED_AB" false; set_proxy "$FED_BA" false
  # Trust and endpoint-discovery caches expire independently. Assert trust is
  # inactive here; the exact 404 checks below prove effective route removal.
  wait_for_state "A trust stale eviction" 50 "$CONTEXT_A" "$JWT_A" cluster-b any blocked_pending_poll false false
  wait_for_state "B trust stale eviction" 50 "$CONTEXT_B" "$JWT_B" cluster-a any blocked_pending_poll false false
  wait_for_not_found "A trust fail closed with no-route reason" 15 "$CONTEXT_A" echo-b
  wait_for_not_found "B trust fail closed with no-route reason" 15 "$CONTEXT_B" echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.trust.expired_fail_closed_recomputed
  record multicluster_poller.trust.expired_fail_closed pass "trust-window-12s-bidirectional-404-Not-Found" "poller.trust.expired_fail_closed_recomputed.{json,prom}"
  record multicluster_poller.trust.inbound_outbound_recomputed pass "trust-source=blocked_pending_poll-outbound=false-inbound=false-bidirectional-404-Not-Found" "poller.trust.expired_fail_closed_recomputed.json"
  set_proxy "$FED_AB" true; set_proxy "$FED_BA" true
  wait_for_state "A trust same-generation recovery" 60 "$CONTEXT_A" "$JWT_A" cluster-b true polled true true
  wait_for_state "B trust same-generation recovery" 60 "$CONTEXT_B" "$JWT_B" cluster-a true polled true true
  wait_for_traffic "A recovered traffic" 30 "$CONTEXT_A" echo-b echo-b
  wait_for_traffic "B recovered traffic" 30 "$CONTEXT_B" echo-a echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.trust.recovered_same_generation
  record multicluster_poller.trust.recovered_same_generation pass "trust-and-discovery-reinstalled-without-slice" "poller.trust.recovered_same_generation.{json,prom}"
}

scenario_inflight_withdrawal() {
  local fed_failure_before disc_failure_before fed_failure_after disc_failure_after
  local fed_accepts_before disc_accepts_before fed_accepts_after disc_accepts_after fault_started
  wait_for_fresh_state "pre-withdrawal poller freshness" 20 "$CONTEXT_A" "$JWT_A" cluster-b

  # Own each poller's next-attempt boundary instead of assuming that a previous
  # recovery reset its independent jittered backoff in time for a fixed sample
  # window. Establish the boundaries independently so one disabled proxy cannot
  # climb its backoff while the other catches up. A measured failure proves the
  # current attempt completed. Capture the proxy's accepted-client baseline at
  # that disabled boundary, then install downstream latency before re-enabling
  # it. A new proxy-scoped accept proves the next poll entered the already-toxic
  # proxy; Toxiproxy only accounts received bytes after its copy exits, so that
  # counter cannot prove a still-delayed connection. The 60-second federation
  # delay leaves enough time to synchronize discovery before withdrawing the
  # peer.
  fed_failure_before="$( metric_uint_value "$CONTEXT_A" "$JWT_A" \
    ferrum_mesh_federation_poll_failures_total "trust_domain=\"$TD_B\"")"
  set_proxy "$FED_AB" false
  wait_for_metric_increase "federation poll failure boundary" 10 "$CONTEXT_A" "$JWT_A" \
    ferrum_mesh_federation_poll_failures_total "trust_domain=\"$TD_B\"" "$fed_failure_before"
  fed_failure_after="$( metric_uint_value "$CONTEXT_A" "$JWT_A" \
    ferrum_mesh_federation_poll_failures_total "trust_domain=\"$TD_B\"")"
  fed_accepts_before="$( proxy_accepted_client_count "$FED_AB")"
  bounded_uint "$fed_accepts_before" "federation accepted-client baseline" >/dev/null
  add_latency "$FED_AB"
  fault_started=$SECONDS
  set_proxy "$FED_AB" true
  wait_for_proxy_accept "federation delayed poll connection" 10 "$FED_AB" "$fed_accepts_before"

  disc_failure_before="$( metric_uint_value "$CONTEXT_A" "$JWT_A" \
    ferrum_mesh_remote_discovery_poll_failures_total "cluster=\"cluster-b\"")"
  set_proxy "$DISC_AB" false
  wait_for_metric_increase "discovery poll failure boundary" 10 "$CONTEXT_A" "$JWT_A" \
    ferrum_mesh_remote_discovery_poll_failures_total "cluster=\"cluster-b\"" "$disc_failure_before"
  disc_failure_after="$( metric_uint_value "$CONTEXT_A" "$JWT_A" \
    ferrum_mesh_remote_discovery_poll_failures_total "cluster=\"cluster-b\"")"
  disc_accepts_before="$( proxy_accepted_client_count "$DISC_AB")"
  bounded_uint "$disc_accepts_before" "discovery accepted-client baseline" >/dev/null
  add_latency "$DISC_AB"
  set_proxy "$DISC_AB" true
  wait_for_proxy_accept "discovery delayed poll connection" 10 "$DISC_AB" "$disc_accepts_before"
  fed_accepts_after="$( proxy_accepted_client_count "$FED_AB")"
  disc_accepts_after="$( proxy_accepted_client_count "$DISC_AB")"
  bounded_uint "$fed_accepts_after" "federation accepted-client observation" >/dev/null
  bounded_uint "$disc_accepts_after" "discovery accepted-client observation" >/dev/null
  (( fed_accepts_after > fed_accepts_before && disc_accepts_after > disc_accepts_before )) || {
    echo "delayed poll connection evidence regressed" >&2
    return 1
  }
  printf 'federation_failures_before=%s\nfederation_failures_boundary=%s\ndiscovery_failures_before=%s\ndiscovery_failures_boundary=%s\nfederation_accepted_clients_before=%s\nfederation_accepted_clients_delayed=%s\ndiscovery_accepted_clients_before=%s\ndiscovery_accepted_clients_delayed=%s\n' \
    "$fed_failure_before" "$fed_failure_after" "$disc_failure_before" "$disc_failure_after" \
    "$fed_accepts_before" "$fed_accepts_after" "$disc_accepts_before" "$disc_accepts_after" \
    > "$RESULTS_DIR/poller.withdrawal.inflight-observed.txt"
  local local_bundle
  local_bundle="$( spire_bundle_b64der "$CONTEXT_A")"
  apply_mesh_config "$CONTEXT_A" cluster-a "$TD_A" echo-a region-a "$local_bundle" ""
  signal_reload "$CONTEXT_A"
  wait_for_no_configured_state "withdrawn RemoteCluster accepted" 40 "$CONTEXT_A" "$JWT_A"
  (( SECONDS - fault_started < 50 )) || {
    echo "withdrawal did not retire the generation before the delayed polls could complete" >&2
    return 1
  }
  remove_latency "$FED_AB"; remove_latency "$DISC_AB"
  # Removing a toxic does not have to wake a delay already sleeping inside the
  # proxy. Observe longer than the full injected delay so both pre-withdrawal
  # polls have time to finish and attempt their retired-generation writes.
  local deadline=$((SECONDS + 68))
  while (( SECONDS < deadline )); do
    no_configured_state "$CONTEXT_A" "$JWT_A" || { echo "retired poll generation reinstalled state" >&2; return 1; }
    sleep 1
  done
  metrics "$CONTEXT_A" "$JWT_A" > "$RESULTS_DIR/poller.withdrawal.inflight_generation_retired.prom"
  if grep -q "ferrum_mesh_federation_bundle_age_seconds{trust_domain=\"$TD_B\"" "$RESULTS_DIR/poller.withdrawal.inflight_generation_retired.prom" ||
     grep -q "ferrum_mesh_remote_discovery_endpoint_age_seconds{cluster=\"cluster-b\"" "$RESULTS_DIR/poller.withdrawal.inflight_generation_retired.prom"; then
    echo "withdrawn peer retained freshness metrics" >&2; return 1
  fi
  admin_json "$CONTEXT_A" "$JWT_A" > "$RESULTS_DIR/poller.withdrawal.inflight_generation_retired.json"
  record multicluster_poller.withdrawal.inflight_generation_retired pass \
    "withdrawal-accepted-after-synchronized-failure-boundaries-and-observed-delayed-poll-connections" \
    "poller.withdrawal.inflight-observed.txt,poller.withdrawal.inflight_generation_retired.json,poller.withdrawal.inflight_generation_retired.prom"
  record multicluster_poller.withdrawal.retired_state_not_reinstalled pass \
    "empty-beyond-full-delayed-poll-window" \
    "poller.withdrawal.inflight-observed.txt,poller.withdrawal.inflight_generation_retired.json"
}

collect_diagnostics() {
  local context label
  for pair in "$CONTEXT_A:a" "$CONTEXT_B:b"; do
    context="${pair%%:*}"; label="${pair##*:}"
    kubectl --context "$context" -n "$NS" get pods -o wide > "$RESULTS_DIR/cluster-$label-pods.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" get events --sort-by=.lastTimestamp > "$RESULTS_DIR/cluster-$label-events.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" logs deploy/echo -c ferrum-edge --tail=500 > "$RESULTS_DIR/cluster-$label-dp.log" 2>&1 || true
    kubectl --context "$context" -n "$NS" logs deploy/ferrum-cp -c ferrum-edge --tail=500 > "$RESULTS_DIR/cluster-$label-cp.log" 2>&1 || true
  done
  curl -fsS "http://$TOXI_IP:8474/proxies" | \
    python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py \
      redact-toxiproxy > "$RESULTS_DIR/toxiproxy-redacted.json" 2>/dev/null || true
}

main() {
  preflight
  python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py init "$LIVE_ASSERTIONS_FILE" \
    "$(git -C "$ROOT_DIR" rev-parse HEAD)" "$LIVE_PLATFORM_PROFILE"
  [[ "${FERRUM_SKIP_IMAGE_BUILD:-0}" == 1 ]] || {
    echo "poller fixture requires a pre-packaged runtime image; set FERRUM_SKIP_IMAGE_BUILD=1" >&2
    return 1
  }
  create_clusters_and_fault_layer
  generate_transport_material
  deploy_topology
  scenario_initial
  scenario_transient
  scenario_endpoint_expiry
  scenario_trust_expiry
  scenario_inflight_withdrawal
  collect_diagnostics
  # Keep the required assertion argv literal for trusted automation inspection.
  python3 ./tests/k8s/multicluster-poller-partition/live_assertions.py require "$LIVE_ASSERTIONS_FILE" \
    multicluster_poller.initial.polled_trust_endpoints_installed \
    multicluster_poller.transient.last_good_retained \
    multicluster_poller.transient.cache_age_increased \
    multicluster_poller.endpoint.expired_fail_closed \
    multicluster_poller.endpoint.remote_target_removed \
    multicluster_poller.endpoint.recovered_same_generation \
    multicluster_poller.trust.expired_fail_closed \
    multicluster_poller.trust.inbound_outbound_recomputed \
    multicluster_poller.trust.recovered_same_generation \
    multicluster_poller.metrics.failure_backoff_recovery_bounded \
    multicluster_poller.metrics.admin_status_parity \
    multicluster_poller.withdrawal.inflight_generation_retired \
    multicluster_poller.withdrawal.retired_state_not_reinstalled
  log "all poller partition boundaries passed"
}

main "$@"
