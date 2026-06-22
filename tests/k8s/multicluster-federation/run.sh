#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/.context/multicluster-federation}"
CLUSTER_A="${CLUSTER_A:-ferrum-fed-a}"
CLUSTER_B="${CLUSTER_B:-ferrum-fed-b}"
NS="${FERRUM_NAMESPACE:-ferrum}"
IMAGE_REPOSITORY="${FERRUM_IMAGE_REPOSITORY:-ferrum-edge}"
IMAGE_TAG="${FERRUM_IMAGE_TAG:-multicluster-federation}"
IMAGE="${IMAGE_REPOSITORY}:${IMAGE_TAG}"
ADMIN_SECRET_A="${FERRUM_ADMIN_SECRET_A:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
ADMIN_SECRET_B="${FERRUM_ADMIN_SECRET_B:-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789}"
GRPC_SECRET_A="${FERRUM_GRPC_SECRET_A:-fed-a-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab}"
GRPC_SECRET_B="${FERRUM_GRPC_SECRET_B:-fed-b-abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345}"

mkdir -p "$ARTIFACT_DIR"

log() {
  printf '[multicluster-federation] %s\n' "$*"
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
  need helm
  docker info >/dev/null
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

install_cluster() {
  local context="$1"
  local release="$2"
  local admin_secret="$3"
  local grpc_secret="$4"
  local trust_domain="$5"
  local peer_name="$6"
  local fail_open="$7"

  log "installing Ferrum chart in $context ($trust_domain)"
  kubectl --context "$context" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
  kubectl --context "$context" -n "$NS" create secret generic ferrum-mesh-dev-credentials \
    --from-literal=admin-jwt-secret="$admin_secret" \
    --from-literal=cp-dp-grpc-jwt-secret="$grpc_secret" \
    --dry-run=client -o yaml | kubectl --context "$context" apply -f -

  helm upgrade --install "$release" "$ROOT_DIR/charts/ferrum-mesh" \
    --kube-context "$context" \
    --namespace "$NS" \
    -f "$ROOT_DIR/charts/ferrum-mesh/examples/development-values.yaml" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.tag="$IMAGE_TAG" \
    --set image.pullPolicy=IfNotPresent \
    --set eastWest.enabled=true \
    --set-string eastWest.env.FERRUM_MODE=mesh \
    --set-string eastWest.env.FERRUM_MESH_TOPOLOGY=east_west_gateway \
    --set-string eastWest.env.FERRUM_MESH_CONFIG_PROTOCOL=native \
    --set-string eastWest.env.FERRUM_ADMIN_JWT_SECRET="$admin_secret" \
    --set-string eastWest.env.FERRUM_CP_DP_GRPC_JWT_SECRET="$grpc_secret" \
    --set-string eastWest.env.FERRUM_DP_CP_GRPC_URLS="grpc://ferrum-mesh-control-plane.$NS.svc.cluster.local:50051" \
    --set-string eastWest.env.FERRUM_MESH_FEDERATION_FAIL_OPEN="$fail_open" \
    --set-string eastWest.env.FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS=5 \
    --set-string eastWest.env.FERRUM_MESH_REMOTE_DISCOVERY_POLL_INTERVAL_SECONDS=5 \
    --set-string eastWest.env.FERRUM_MESH_WORKLOAD_SPIFFE_ID="spiffe://$trust_domain/ns/$NS/sa/ferrum-mesh" \
    --set-string eastWest.env.FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true \
    --set-string eastWest.env.FERRUM_MESH_ALLOW_NO_CA=true \
    --wait \
    --timeout 180s

  kubectl --context "$context" -n "$NS" rollout status deployment/ferrum-mesh-control-plane --timeout=180s
  kubectl --context "$context" -n "$NS" rollout status deployment/ferrum-mesh-east-west --timeout=180s
  kubectl --context "$context" -n "$NS" get pods -o wide > "$ARTIFACT_DIR/${peer_name}-pods.txt"
  kubectl --context "$context" -n "$NS" get services -o wide > "$ARTIFACT_DIR/${peer_name}-services.txt"
}

collect_diagnostics() {
  for cluster in "$CLUSTER_A" "$CLUSTER_B"; do
    local context="kind-$cluster"
    kubectl --context "$context" -n "$NS" get all -o wide > "$ARTIFACT_DIR/${cluster}-all.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" get events --sort-by=.lastTimestamp > "$ARTIFACT_DIR/${cluster}-events.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" logs deployment/ferrum-mesh-control-plane --all-containers --tail=1000 > "$ARTIFACT_DIR/${cluster}-cp.log" 2>&1 || true
    kubectl --context "$context" -n "$NS" logs deployment/ferrum-mesh-east-west --all-containers --tail=1000 > "$ARTIFACT_DIR/${cluster}-east-west.log" 2>&1 || true
  done
}

full_fixture_required() {
  cat >&2 <<'MSG'
The two-cluster CP/east-west smoke deployment completed, but the full workload
traffic fixture is not implemented in this script yet. Full acceptance still
requires injected workloads, bidirectional authenticated requests, bundle
rotation/removal/invalid delivery, endpoint failover, and network partitions.

Set FERRUM_MULTICLUSTER_DEPLOY_ONLY=1 to run only the deployment smoke.
MSG
  exit 2
}

main() {
  trap collect_diagnostics EXIT
  preflight
  create_cluster "$CLUSTER_A"
  create_cluster "$CLUSTER_B"
  build_and_load_image
  install_cluster "kind-$CLUSTER_A" ferrum-a "$ADMIN_SECRET_A" "$GRPC_SECRET_A" cluster-a.test "$CLUSTER_A" "${FERRUM_FAIL_OPEN_A:-false}"
  install_cluster "kind-$CLUSTER_B" ferrum-b "$ADMIN_SECRET_B" "$GRPC_SECRET_B" cluster-b.test "$CLUSTER_B" "${FERRUM_FAIL_OPEN_B:-false}"

  if [[ "${FERRUM_MULTICLUSTER_DEPLOY_ONLY:-0}" == "1" ]]; then
    log "deploy-only smoke complete; artifacts in $ARTIFACT_DIR"
    return 0
  fi

  full_fixture_required
}

main "$@"
