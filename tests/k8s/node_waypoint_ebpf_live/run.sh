#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART_DIR="$ROOT_DIR/charts/ferrum-mesh"
MANIFESTS="$ROOT_DIR/tests/k8s/node_waypoint_ebpf_live/manifests.yaml"

# shellcheck source=../lib/live_assertions.sh
LIVE_ASSERTIONS_HELPER="$ROOT_DIR/tests/k8s/lib/live_assertions.sh"
if [[ ! -f "$LIVE_ASSERTIONS_HELPER" && -f "$PWD/tests/k8s/lib/live_assertions.sh" ]]; then
  LIVE_ASSERTIONS_HELPER="$PWD/tests/k8s/lib/live_assertions.sh"
fi
source "$LIVE_ASSERTIONS_HELPER"

MESH_NS="${FERRUM_LIVE_MESH_NAMESPACE:-ferrum}"
WORKLOAD_NS="${FERRUM_LIVE_WORKLOAD_NAMESPACE:-ferrum-ebpf-live}"
RELEASE="${FERRUM_LIVE_RELEASE:-ferrum-live}"
IMAGE_REPOSITORY="${FERRUM_LIVE_IMAGE_REPOSITORY:-ferrumedge/ferrum-edge}"
IMAGE_TAG="${FERRUM_LIVE_IMAGE_TAG:-0.9.0}"
DEFAULT_CHART_IMAGE_REPOSITORY="${FERRUM_LIVE_DEFAULT_IMAGE_REPOSITORY:-ferrumedge/ferrum-edge}"
DEFAULT_CHART_IMAGE_TAG="${FERRUM_LIVE_DEFAULT_IMAGE_TAG:-0.9.0}"
BPFTOOL_IMAGE="${FERRUM_LIVE_BPFTOOL_IMAGE:-quay.io/cilium/cilium:v1.16.5}"
REQUIRE_DUAL_STACK="${FERRUM_LIVE_REQUIRE_DUAL_STACK:-false}"
DOCKER_NODE_EVIDENCE="${FERRUM_LIVE_DOCKER_NODE_EVIDENCE:-false}"
NODE_WAYPOINT_REGISTRY_DIR="${FERRUM_LIVE_NODE_WAYPOINT_REGISTRY_DIR:-/run/ferrum/node-waypoint-pods}"
AMBIENT_ADMIN_PORT="${FERRUM_LIVE_AMBIENT_ADMIN_PORT:-19010}"
NODE_AGENT_ADMIN_PORT="${FERRUM_LIVE_NODE_AGENT_ADMIN_PORT:-19090}"
ADMIN_JWT_SECRET="${FERRUM_LIVE_ADMIN_JWT_SECRET:-ferrum-edge-node-waypoint-live-admin-secret}"
ADMIN_JWT_ISSUER="${FERRUM_LIVE_ADMIN_JWT_ISSUER:-ferrum-edge}"
RESULTS_DIR="$ROOT_DIR/target/node-waypoint-ebpf-live"
LIVE_ASSERTIONS_FILE="${FERRUM_LIVE_ASSERTIONS_FILE:-$RESULTS_DIR/live-assertions.json}"
LIVE_PLATFORM_PROFILE="${FERRUM_LIVE_PLATFORM_PROFILE:-kind-dual-stack-node-waypoint-ebpf}"
LIVE_ASSERTIONS_INITIALIZED=false
RECORDED_LIVE_ASSERTIONS=" "
REQUIRED_LIVE_ASSERTIONS=(
  node_waypoint.ebpf.chart_profile
  node_waypoint.ebpf.capture_ready
  node_waypoint.ebpf.bpf_attached
  node_waypoint.ebpf.registry_ready
  node_waypoint.mesh_slice.accepted
  node_waypoint.ipv4.service_allow_same_node
  node_waypoint.ipv4.service_allow_cross_node
  node_waypoint.ipv4.service_deny_same_node
  node_waypoint.ipv4.service_deny_cross_node
  node_waypoint.ipv4.pod_ip_bypass_guard_same_node
  node_waypoint.ipv4.pod_ip_bypass_guard_cross_node
  node_waypoint.identity.stale_cleanup
)
if [[ "$REQUIRE_DUAL_STACK" == "true" ]]; then
  REQUIRED_LIVE_ASSERTIONS+=(
    node_waypoint.ebpf.registry_ready_ipv6
    node_waypoint.ipv6.service_allow
    node_waypoint.ipv6.service_deny
    node_waypoint.ipv6.pod_ip_bypass_guard
  )
fi

if [[ "${FERRUM_EBPF_LIVE_ACK_DISPOSABLE:-}" != "true" ]]; then
  echo "Refusing to run against the current kube-context without FERRUM_EBPF_LIVE_ACK_DISPOSABLE=true" >&2
  exit 1
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_cmd kubectl
require_cmd helm
require_cmd curl
require_cmd python3
if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
  require_cmd docker
fi

log() {
  printf '\n[node-waypoint-ebpf-live] %s\n' "$*"
}

init_live_assertions() {
  mkdir -p "$RESULTS_DIR"
  export FERRUM_LIVE_REPO_ROOT="$ROOT_DIR"
  ferrum_live_assertions_init \
    "$LIVE_ASSERTIONS_FILE" \
    node-waypoint-ebpf-live \
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
}

record_live_assertion_once() {
  local assertion_id="$1"
  if [[ "$RECORDED_LIVE_ASSERTIONS" == *" $assertion_id "* ]]; then
    return
  fi
  record_live_assertion "$@"
  RECORDED_LIVE_ASSERTIONS="$RECORDED_LIVE_ASSERTIONS$assertion_id "
}

spiffe_for_sa() {
  local service_account="$1"
  printf 'spiffe://cluster.local/ns/%s/sa/%s' "$WORKLOAD_NS" "$service_account"
}

render_chart_assertions() {
  log "rendering chart defaults for eBPF image selection"
  local rendered
  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf)"
  if ! grep -q "image: \"$DEFAULT_CHART_IMAGE_REPOSITORY:$DEFAULT_CHART_IMAGE_TAG-ebpf\"" <<<"$rendered"; then
    echo "nodeAgent.enabled=true,captureMode=ebpf did not render $DEFAULT_CHART_IMAGE_REPOSITORY:$DEFAULT_CHART_IMAGE_TAG-ebpf" >&2
    grep -n 'image:' <<<"$rendered" >&2 || true
    exit 1
  fi

  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.tag="$IMAGE_TAG" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set-string "ambient.env.FERRUM_ADMIN_HTTP_PORT=$AMBIENT_ADMIN_PORT" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint \
    --set-string "nodeAgent.admin.port=$NODE_AGENT_ADMIN_PORT" \
    --set-string "nodeAgent.podRegistryDir=$NODE_WAYPOINT_REGISTRY_DIR")"
  local ebpf_count
  ebpf_count="$(grep -c "image: \"$IMAGE_REPOSITORY:$IMAGE_TAG-ebpf\"" <<<"$rendered" || true)"
  if [[ "$ebpf_count" -lt 2 ]]; then
    echo "NodeWaypoint eBPF render did not select -ebpf images for both proxy and node-agent" >&2
    grep -n 'image:' <<<"$rendered" >&2 || true
    exit 1
  fi
  if [[ "$(grep -c "name: node-waypoint-pod-registry" <<<"$rendered" || true)" -lt 4 ]] ||
    ! grep -q "FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR" <<<"$rendered" ||
    ! grep -q "path: $NODE_WAYPOINT_REGISTRY_DIR" <<<"$rendered"; then
    echo "NodeWaypoint eBPF render did not mount the shared pod registry for both daemonsets" >&2
    grep -nE 'node-waypoint-pod-registry|FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR|hostPath|mountPath' <<<"$rendered" >&2 || true
    exit 1
  fi
  if [[ "$(grep -c "dnsPolicy: ClusterFirstWithHostNet" <<<"$rendered" || true)" -lt 2 ]]; then
    echo "NodeWaypoint eBPF render did not set ClusterFirstWithHostNet on host-network daemonsets" >&2
    grep -nE 'kind: DaemonSet|name: ferrum-mesh-(ambient|node-agent)|hostNetwork:|dnsPolicy:' <<<"$rendered" >&2 || true
    exit 1
  fi
  if [[ "$(grep -c "hostPID: true" <<<"$rendered" || true)" -lt 2 ]]; then
    echo "NodeWaypoint eBPF render did not grant hostPID to both ambient and node-agent daemonsets" >&2
    grep -nE 'kind: DaemonSet|name: ferrum-mesh-(ambient|node-agent)|hostPID:|hostNetwork:' <<<"$rendered" >&2 || true
    exit 1
  fi
  if [[ "$(grep -c -- '- BPF' <<<"$rendered" || true)" -lt 2 ]] ||
    [[ "$(grep -c -- '- PERFMON' <<<"$rendered" || true)" -lt 2 ]] ||
    [[ "$(grep -c -- '- SYS_ADMIN' <<<"$rendered" || true)" -lt 2 ]]; then
    echo "NodeWaypoint eBPF render did not grant BPF/PERFMON/SYS_ADMIN to both proxy and node-agent" >&2
    grep -nE 'capabilities:|add:|- SYS_ADMIN|- BPF|- NET_ADMIN|- PERFMON|- SYS_PTRACE' <<<"$rendered" >&2 || true
    exit 1
  fi
  if ! grep -q -- '- SYS_PTRACE' <<<"$rendered"; then
    echo "NodeWaypoint eBPF render did not grant SYS_PTRACE to the node-waypoint proxy" >&2
    grep -nE 'kind: DaemonSet|name: ferrum-mesh-ambient|capabilities:|add:|- SYS_ADMIN|- SYS_PTRACE' <<<"$rendered" >&2 || true
    exit 1
  fi
  local ambient_registry_override="/var/run/ferrum/custom-node-waypoint-pods"
  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.tag="$IMAGE_TAG" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set-string "ambient.env.FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR=$ambient_registry_override" \
    --set-string "ambient.env.FERRUM_ADMIN_HTTP_PORT=$AMBIENT_ADMIN_PORT" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint \
    --set-string "nodeAgent.admin.port=$NODE_AGENT_ADMIN_PORT" \
    --set-string "nodeAgent.podRegistryDir=$NODE_WAYPOINT_REGISTRY_DIR")"
  if ! grep -q "FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR" <<<"$rendered" ||
    ! grep -q "value: \"$ambient_registry_override\"" <<<"$rendered" ||
    ! grep -q "mountPath: $ambient_registry_override" <<<"$rendered" ||
    ! grep -q "path: $NODE_WAYPOINT_REGISTRY_DIR" <<<"$rendered"; then
    echo "NodeWaypoint eBPF render did not mount the shared registry at the ambient override path" >&2
    grep -nE 'node-waypoint-pod-registry|FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR|hostPath|mountPath|path:' <<<"$rendered" >&2 || true
    exit 1
  fi
  if ! grep -q "FERRUM_ADMIN_HTTP_PORT" <<<"$rendered" ||
    ! grep -q "value: \"$AMBIENT_ADMIN_PORT\"" <<<"$rendered" ||
    ! grep -q "value: \"$NODE_AGENT_ADMIN_PORT\"" <<<"$rendered"; then
    echo "NodeWaypoint eBPF render did not set distinct ambient and node-agent admin ports" >&2
    grep -nE "name: ferrum-mesh-(ambient|node-agent)|FERRUM_ADMIN_HTTP_PORT|value: \"?(9000|$AMBIENT_ADMIN_PORT|$NODE_AGENT_ADMIN_PORT)\"?" <<<"$rendered" >&2 || true
    exit 1
  fi
  local ambient_block
  ambient_block="$(awk '
    /name: ferrum-mesh-ambient/ { in_ambient = 1 }
    in_ambient { print }
    /name: ferrum-mesh-node-agent/ && in_ambient { exit }
  ' <<<"$rendered")"
  if ! grep -q "readinessProbe:" <<<"$ambient_block" ||
    ! grep -A15 "readinessProbe:" <<<"$ambient_block" | grep -q -- "- \"$AMBIENT_ADMIN_PORT\""; then
    echo "NodeWaypoint ambient render did not add an admin health readiness probe" >&2
    grep -nA18 "readinessProbe:" <<<"$ambient_block" >&2 || true
    exit 1
  fi
  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.tag="$IMAGE_TAG" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set-string "ambient.env.FERRUM_NAMESPACE=$WORKLOAD_NS" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint)"
  if ! grep -A1 "name: FERRUM_NAMESPACE" <<<"$rendered" | grep -q "value: \"$WORKLOAD_NS\""; then
    echo "NodeWaypoint eBPF render did not preserve an explicit workload namespace subscription" >&2
    grep -nE 'FERRUM_NAMESPACE|FERRUM_MESH_TOPOLOGY' <<<"$rendered" >&2 || true
    exit 1
  fi
  if [[ "$(grep -c "name: bpf-fs" <<<"$rendered" || true)" -lt 4 ]] ||
    [[ "$(grep -c "name: cgroup" <<<"$rendered" || true)" -lt 4 ]]; then
    echo "NodeWaypoint eBPF render did not mount host bpffs and cgroup roots for both proxy and node-agent" >&2
    grep -nE 'name: (bpf-fs|cgroup)|mountPath: /sys/fs/(bpf|cgroup)|path: /sys/fs/(bpf|cgroup)' <<<"$rendered" >&2 || true
    exit 1
  fi

  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.tag="$IMAGE_TAG" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node-waypoint \
    --set-string "ambient.env.FERRUM_ADMIN_HTTP_PORT=$AMBIENT_ADMIN_PORT" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node-waypoint \
    --set-string "nodeAgent.admin.port=$NODE_AGENT_ADMIN_PORT" \
    --set-string "nodeAgent.podRegistryDir=$NODE_WAYPOINT_REGISTRY_DIR")"
  if [[ "$(grep -c "image: \"$IMAGE_REPOSITORY:$IMAGE_TAG-ebpf\"" <<<"$rendered" || true)" -lt 2 ]] ||
    ! grep -A1 "name: FERRUM_NODE_AGENT_PROXY_MODE" <<<"$rendered" | grep -q 'value: "node_waypoint"' ||
    [[ "$(grep -c "name: node-waypoint-pod-registry" <<<"$rendered" || true)" -lt 4 ]]; then
    echo "NodeWaypoint eBPF render did not normalize node-waypoint aliases" >&2
    grep -nE 'image:|FERRUM_MESH_TOPOLOGY|FERRUM_NODE_AGENT_PROXY_MODE|node-waypoint-pod-registry' <<<"$rendered" >&2 || true
    exit 1
  fi

  if ! helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint >/tmp/ferrum-node-waypoint-default-admin-port-render.out 2>&1; then
    echo "NodeWaypoint render rejected the non-conflicting default node-agent admin port" >&2
    cat /tmp/ferrum-node-waypoint-default-admin-port-render.out >&2 || true
    exit 1
  fi

  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set-string ambient.env.FERRUM_ADMIN_HTTP_PORT=0 \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint >/tmp/ferrum-node-waypoint-ambient-admin-disabled-render.out 2>&1; then
    echo "NodeWaypoint render accepted disabled ambient admin readiness port" >&2
    cat /tmp/ferrum-node-waypoint-ambient-admin-disabled-render.out >&2 || true
    exit 1
  fi
  if ! grep -q "requires FERRUM_ADMIN_HTTP_PORT to stay enabled" /tmp/ferrum-node-waypoint-ambient-admin-disabled-render.out; then
    echo "NodeWaypoint render rejected disabled ambient admin port without a clear error" >&2
    cat /tmp/ferrum-node-waypoint-ambient-admin-disabled-render.out >&2 || true
    exit 1
  fi

  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set controlPlane.enabled=true \
    --set controlPlane.database.type=sqlite \
    --set-string controlPlane.database.sqlite.path=/tmp/ferrum.db \
    --set-string "controlPlane.credentials.adminJwtSecret.value=$ADMIN_JWT_SECRET" \
    --set-string "controlPlane.credentials.cpDpGrpcJwtSecret.value=ferrum-edge-node-waypoint-live-grpc-secret" \
    --set-string "controlPlane.env.FERRUM_NAMESPACE=$WORKLOAD_NS")"
  if ! grep -A1 "name: FERRUM_K8S_CONTROLLER_NAMESPACE" <<<"$rendered" | grep -q "value: \"$MESH_NS\"" ||
    ! grep -A1 "name: FERRUM_NAMESPACE" <<<"$rendered" | grep -q "value: \"$WORKLOAD_NS\""; then
    echo "Control-plane render did not keep install and managed namespaces separate" >&2
    grep -nE 'FERRUM_K8S_CONTROLLER_NAMESPACE|FERRUM_NAMESPACE' <<<"$rendered" >&2 || true
    exit 1
  fi

  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.admin.enabled=true \
    --set-string nodeAgent.admin.port=0)"
  if grep -q "readinessProbe:" <<<"$rendered"; then
    echo "Node-agent render emitted a readiness probe for disabled admin port 0" >&2
    grep -nE 'readinessProbe:|FERRUM_ADMIN_HTTP_PORT|value: "?0"?' <<<"$rendered" >&2 || true
    exit 1
  fi

  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.admin.enabled=true \
    --set-string nodeAgent.admin.bindAddress=::1)"
  if ! grep -A8 "readinessProbe:" <<<"$rendered" | grep -q -- '- "::1"'; then
    echo "Node-agent readiness probe did not use the concrete IPv6 admin bind address" >&2
    grep -nA10 "readinessProbe:" <<<"$rendered" >&2 || true
    exit 1
  fi

  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.admin.enabled=true \
    --set-string nodeAgent.admin.bindAddress=0.0.0.0)"
  if ! grep -A8 "readinessProbe:" <<<"$rendered" | grep -q -- '- "127.0.0.1"'; then
    echo "Node-agent readiness probe did not use loopback for wildcard admin bind address" >&2
    grep -nA10 "readinessProbe:" <<<"$rendered" >&2 || true
    exit 1
  fi

  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint \
    --set-string nodeAgent.admin.port=9000 >/tmp/ferrum-node-waypoint-admin-port-render.out 2>&1; then
    echo "NodeWaypoint render accepted ambient and node-agent host-network admin port collision" >&2
    cat /tmp/ferrum-node-waypoint-admin-port-render.out >&2 || true
    exit 1
  fi

  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set-string nodeAgent.env.FERRUM_ADMIN_HTTP_PORT=9000 >/tmp/ferrum-node-agent-managed-env-render.out 2>&1; then
    echo "Node-agent render accepted a chart-managed env override" >&2
    cat /tmp/ferrum-node-agent-managed-env-render.out >&2 || true
    exit 1
  fi
  if ! grep -q "nodeAgent.env.FERRUM_ADMIN_HTTP_PORT is chart-managed" /tmp/ferrum-node-agent-managed-env-render.out; then
    echo "Node-agent render rejected managed env override without a clear error" >&2
    cat /tmp/ferrum-node-agent-managed-env-render.out >&2 || true
    exit 1
  fi

  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf >/tmp/ferrum-node-waypoint-invalid-render.out 2>&1; then
    echo "NodeWaypoint render accepted ambient node_waypoint without nodeAgent.proxyMode=node_waypoint" >&2
    cat /tmp/ferrum-node-waypoint-invalid-render.out >&2 || true
    exit 1
  fi
  record_live_assertion \
    node_waypoint.ebpf.chart_profile \
    pass \
    "" \
    "" \
    "helm-rendered-ebpf-images-registry-hostpid-capabilities"
}

ready_worker_nodes() {
  kubectl get nodes \
    -l '!node-role.kubernetes.io/control-plane,!node-role.kubernetes.io/master' \
    --no-headers | awk '$2 == "Ready" {print $1}'
}

validate_cluster() {
  log "validating cluster prerequisites"
  mapfile -t NODES < <(ready_worker_nodes)
  if [[ "${#NODES[@]}" -lt 2 ]]; then
    echo "expected at least two Ready worker nodes, found ${#NODES[@]}" >&2
    kubectl get nodes -o wide >&2
    exit 1
  fi
  NODE_A="${NODES[0]}"
  NODE_B="${NODES[1]}"
  log "using nodes: $NODE_A and $NODE_B"

  if ! kubectl get crd authorizationpolicies.security.istio.io >/dev/null 2>&1; then
    echo "Istio AuthorizationPolicy CRD is required for this live policy enforcement test" >&2
    exit 1
  fi

  for node in "$NODE_A" "$NODE_B"; do
    log "checking kernel/cgroup/bpffs on $node"
    kubectl debug "node/$node" -n default --image=busybox:1.36 --quiet -- \
      chroot /host sh -eu -c '
        kernel="$(uname -r)"
        major="${kernel%%.*}"
        rest="${kernel#*.}"
        minor="${rest%%.*}"
        if [ "$major" -lt 5 ] || { [ "$major" -eq 5 ] && [ "$minor" -lt 7 ]; }; then
          echo "kernel $kernel is older than 5.7" >&2
          exit 1
        fi
        test -f /sys/fs/cgroup/cgroup.controllers
        mount | grep -q " /sys/fs/bpf type bpf "
      '
  done
}

label_nodes() {
  log "labeling test nodes"
  kubectl label node "$NODE_A" ferrum.io/live-node=a --overwrite
  kubectl label node "$NODE_B" ferrum.io/live-node=b --overwrite
}

install_ferrum() {
  log "installing Ferrum chart"
  kubectl create namespace "$MESH_NS" --dry-run=client -o yaml | kubectl apply -f -
  helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.tag="$IMAGE_TAG" \
    --set image.pullPolicy=IfNotPresent \
    --set injector.enabled=false \
    --set ca.enabled=false \
    --set controlPlane.enabled=true \
    --set controlPlane.rbac.create=true \
    --set controlPlane.rbac.gatewayApi=false \
    --set controlPlane.rbac.istio=true \
    --set controlPlane.rbac.meshConfig=false \
    --set controlPlane.rbac.podDiscovery=true \
    --set controlPlane.database.type=sqlite \
    --set-string 'controlPlane.database.url=sqlite:////tmp/ferrum-node-waypoint-ebpf-live.db?mode=rwc' \
    --set-string "controlPlane.credentials.adminJwtSecret.value=$ADMIN_JWT_SECRET" \
    --set controlPlane.credentials.cpDpGrpcJwtSecret.value=ferrum-edge-node-waypoint-live-grpc-secret \
    --set-string 'controlPlane.env.FERRUM_CP_NAMESPACES=*' \
    --set controlPlane.env.FERRUM_LOG_LEVEL=info \
    --set controlPlane.env.FERRUM_K8S_CONTROLLER_ENABLED=true \
    --set controlPlane.env.FERRUM_K8S_POD_DISCOVERY_ENABLED=true \
    --set controlPlane.env.FERRUM_K8S_WATCH_GATEWAY_API_CRDS=false \
    --set controlPlane.env.FERRUM_K8S_WATCH_ISTIO_CRDS=true \
    --set controlPlane.env.FERRUM_K8S_WATCH_MESH_CONFIG=false \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MODE=mesh \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set-string "ambient.env.FERRUM_DP_CP_GRPC_URLS=http://ferrum-mesh-control-plane.$MESH_NS.svc.cluster.local:50051" \
    --set ambient.env.FERRUM_CP_DP_GRPC_JWT_SECRET=ferrum-edge-node-waypoint-live-grpc-secret \
    --set-string "ambient.env.FERRUM_NAMESPACE=$WORKLOAD_NS" \
    --set-string "ambient.env.FERRUM_ADMIN_HTTP_PORT=$AMBIENT_ADMIN_PORT" \
    --set-string "ambient.env.FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET" \
    --set-string "ambient.env.FERRUM_ADMIN_JWT_ISSUER=$ADMIN_JWT_ISSUER" \
    --set ambient.env.FERRUM_LOG_LEVEL=info \
    --set ambient.env.FERRUM_MESH_ALLOW_NO_CA=true \
    --set ambient.env.FERRUM_MESH_HBONE_LISTEN_ADDR=0.0.0.0:15008 \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set-string "nodeAgent.admin.port=$NODE_AGENT_ADMIN_PORT" \
    --set nodeAgent.proxyMode=node_waypoint \
    --set nodeAgent.env.FERRUM_LOG_LEVEL=info \
    --set-string "nodeAgent.podRegistryDir=$NODE_WAYPOINT_REGISTRY_DIR" \
    --set nodeAgent.fallbackMode=fail \
    --wait \
    --timeout 5m

  kubectl -n "$MESH_NS" rollout status deployment/ferrum-mesh-control-plane --timeout=5m
  kubectl -n "$MESH_NS" rollout status daemonset/ferrum-mesh-node-agent --timeout=5m
  kubectl -n "$MESH_NS" rollout status daemonset/ferrum-mesh-ambient --timeout=5m
}

collect_node_agent_metrics() {
  local out_dir="$RESULTS_DIR/node-agent-metrics"
  mkdir -p "$out_dir"
  local -a pods
  mapfile -t pods < <(kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-node-agent \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  local idx=0
  for pod in "${pods[@]}"; do
    local port=$((19200 + idx))
    local metrics_file="$out_dir/$pod.prom"
    local pf_log="$out_dir/$pod-port-forward.log"
    local pf_pid
    idx=$((idx + 1))
    kubectl -n "$MESH_NS" port-forward "pod/$pod" "$port:$NODE_AGENT_ADMIN_PORT" >"$pf_log" 2>&1 &
    pf_pid=$!
    for _ in $(seq 1 20); do
      if curl -fsS "http://127.0.0.1:$port/metrics" >"$metrics_file"; then
        break
      fi
      sleep 0.25
    done
    kill "$pf_pid" 2>/dev/null || true
    wait "$pf_pid" 2>/dev/null || true
  done
}

collect_ambient_node_waypoint_identities() {
  local out_dir="$RESULTS_DIR/ambient-node-waypoint-identities"
  mkdir -p "$out_dir"
  local token
  token="$(admin_bearer_token)"
  local -a pods
  mapfile -t pods < <(kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)
  local idx=0
  for pod in "${pods[@]}"; do
    local port=$((19300 + idx))
    local identities_file="$out_dir/$pod.json"
    local pf_log="$out_dir/$pod-port-forward.log"
    local pf_pid
    idx=$((idx + 1))
    kubectl -n "$MESH_NS" port-forward "pod/$pod" "$port:$AMBIENT_ADMIN_PORT" >"$pf_log" 2>&1 &
    pf_pid=$!
    for _ in $(seq 1 20); do
      if curl -fsS -H "Authorization: Bearer $token" \
        "http://127.0.0.1:$port/node-waypoint/identities" >"$identities_file"; then
        break
      fi
      sleep 0.25
    done
    kill "$pf_pid" 2>/dev/null || true
    wait "$pf_pid" 2>/dev/null || true
  done
}

collect_traffic_failure_diagnostics() {
  collect_node_agent_metrics
  collect_ambient_node_waypoint_identities
  collect_bpf_evidence || true
  for node in "$NODE_A" "$NODE_B"; do
    dump_node_waypoint_registry "$node"
    dump_node_waypoint_runtime_state "$node"
  done
}

first_pod_for() {
  kubectl -n "$1" get pod -l "$2" \
    -o jsonpath='{.items[0].metadata.name}'
}

assert_node_agent_ready_metric() {
  log "checking node-agent capture-state metric"
  local pod pf_pid metrics_file
  pod="$(first_pod_for "$MESH_NS" 'app.kubernetes.io/name=ferrum-mesh-node-agent')"
  metrics_file="$(mktemp)"
  kubectl -n "$MESH_NS" port-forward "pod/$pod" "19000:$NODE_AGENT_ADMIN_PORT" >/tmp/ferrum-node-agent-port-forward.log 2>&1 &
  pf_pid=$!
  local fetched=false
  for _ in $(seq 1 20); do
    if curl -fsS http://127.0.0.1:19000/metrics >"$metrics_file"; then
      fetched=true
      break
    fi
    sleep 0.5
  done
  kill "$pf_pid" 2>/dev/null || true
  wait "$pf_pid" 2>/dev/null || true
  if [[ "$fetched" != "true" ]]; then
    echo "failed to fetch node-agent metrics through port-forward" >&2
    cat /tmp/ferrum-node-agent-port-forward.log >&2 || true
    exit 1
  fi
  grep -q 'ferrum_node_agent_capture_state{state="ready"} 1' "$metrics_file"
  grep -q 'ferrum_mesh_node_topology_degraded{reason="none"} 0' "$metrics_file"
  mkdir -p "$RESULTS_DIR/node-agent-metrics"
  cp "$metrics_file" "$RESULTS_DIR/node-agent-metrics/ready-check.prom"
  record_live_assertion \
    node_waypoint.ebpf.capture_ready \
    pass \
    "" \
    "" \
    "node-agent-capture-state-ready" \
    "" \
    "" \
    "node-agent-metrics/ready-check.prom"
}

collect_bpf_evidence() {
  log "collecting bpftool evidence"
  mkdir -p "$RESULTS_DIR"
  for node in "$NODE_A" "$NODE_B"; do
    local out="$RESULTS_DIR/bpftool-$node.txt"
    local tmp="$out.tmp"
    local ok=false
    for attempt in 1 2 3; do
      set +e
      if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
        docker exec --privileged "$node" sh -eu -c '
          if ! command -v bpftool >/dev/null 2>&1; then
            if ! command -v apt-get >/dev/null 2>&1; then
              echo "bpftool missing and apt-get unavailable in node container" >&2
              exit 127
            fi
            export DEBIAN_FRONTEND=noninteractive
            apt-get update >/dev/null
            apt-get install -y bpftool >/dev/null
          fi
          bpftool prog show
          bpftool link show
          bpftool map show
          for pin in /sys/fs/bpf/ferrum/orig_dst4 /sys/fs/bpf/ferrum/orig_dst6; do
            echo "## bpftool map dump pinned $pin"
            bpftool map dump pinned "$pin" 2>&1 || true
          done
          find /sys/fs/bpf/ferrum -maxdepth 1 -type f -print 2>/dev/null || true
        ' >"$tmp" 2>&1
      else
        kubectl debug "node/$node" -n "$MESH_NS" --image="$BPFTOOL_IMAGE" --quiet -- \
          sh -eu -c '
            if ! command -v bpftool >/dev/null 2>&1; then
              echo "bpftool missing from debug image" >&2
              exit 127
            fi
            bpftool prog show
            bpftool link show
            bpftool map show
            for pin in /host/sys/fs/bpf/ferrum/orig_dst4 /host/sys/fs/bpf/ferrum/orig_dst6 /sys/fs/bpf/ferrum/orig_dst4 /sys/fs/bpf/ferrum/orig_dst6; do
              [ -e "$pin" ] || continue
              echo "## bpftool map dump pinned $pin"
              bpftool map dump pinned "$pin" 2>&1 || true
            done
            if [ -d /host/sys/fs/bpf/ferrum ]; then
              find /host/sys/fs/bpf/ferrum -maxdepth 1 -type f -print 2>/dev/null | sed "s#^/host##" || true
            elif command -v nsenter >/dev/null 2>&1; then
              nsenter -t 1 -m -n sh -eu -c "find /sys/fs/bpf/ferrum -maxdepth 1 -type f -print 2>/dev/null || true"
            else
              find /sys/fs/bpf/ferrum -maxdepth 1 -type f -print 2>/dev/null || true
            fi
          ' >"$tmp" 2>&1
      fi
      local status=$?
      set -e
      cat "$tmp"
      cp "$tmp" "$out"
      if [[ "$status" -eq 0 ]] &&
        grep -Eq 'ferrum_(connect4|connect6|getpeername4|getpeername6|sock_ops)|FERRUM_(ORIG_DST|WORKLOAD_IDENTITY|CAPTURE_CONFIG)' "$out"; then
        ok=true
        break
      fi
      log "bpftool evidence attempt $attempt failed for $node; retrying"
      sleep $((attempt * 5))
    done
    rm -f "$tmp"
    if [[ "$ok" != "true" ]]; then
      echo "failed to collect Ferrum BPF program/link/map evidence on $node" >&2
      exit 1
    fi
  done
  record_live_assertion \
    node_waypoint.ebpf.bpf_attached \
    pass \
    "" \
    "" \
    "bpftool-program-link-map-evidence-present" \
    "" \
    "" \
    "bpftool-$NODE_A.txt,bpftool-$NODE_B.txt"
}

apply_workloads() {
  log "applying live traffic workloads"
  awk -v ns="$WORKLOAD_NS" -v require_dual="$REQUIRE_DUAL_STACK" '
    {
      gsub(/__NAMESPACE__/, ns)
      if ($0 ~ /__SERVICE_IP_FAMILY_BLOCK__/) {
        if (require_dual == "true") {
          print "  ipFamilyPolicy: RequireDualStack"
          print "  ipFamilies:"
          print "    - IPv4"
          print "    - IPv6"
        } else {
          print "  ipFamilyPolicy: PreferDualStack"
        }
      } else {
        print
      }
    }
  ' "$MANIFESTS" | kubectl apply -f -
  kubectl -n "$WORKLOAD_NS" rollout status deploy/src-a --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/src-b --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/dst-a --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/dst-b --timeout=3m
}

admin_bearer_token() {
  python3 - "$ADMIN_JWT_SECRET" "$ADMIN_JWT_ISSUER" <<'PY'
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
    "sub": "node-waypoint-ebpf-live",
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

workload_pod_records() {
  kubectl -n "$WORKLOAD_NS" get pod -l ferrum.io/mesh=enabled \
    -o jsonpath='{range .items[*]}{.metadata.uid}{"\t"}{.spec.nodeName}{"\t"}{.metadata.name}{"\n"}{end}' |
    awk 'NF == 3'
}

workload_pod_record_for_app() {
  local app="$1"
  kubectl -n "$WORKLOAD_NS" get pod -l "app=$app" \
    -o jsonpath='{.items[0].metadata.uid}{"\t"}{.items[0].spec.nodeName}{"\t"}{.items[0].metadata.name}'
}

ambient_pod_on_node() {
  local node="$1"
  kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    --field-selector "spec.nodeName=$node" \
    -o jsonpath='{.items[0].metadata.name}'
}

pick_loopback_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

fetch_node_waypoint_identities_for_node() {
  local node="$1"
  local out="$2"
  local ambient_pod port token pf_log pf_pid fetched
  ambient_pod="$(ambient_pod_on_node "$node")"
  if [[ -z "$ambient_pod" ]]; then
    echo "no ferrum-mesh-ambient pod found on node $node" >&2
    return 1
  fi
  port="$(pick_loopback_port)"
  token="$(admin_bearer_token)"
  pf_log="$out.port-forward.log"
  kubectl -n "$MESH_NS" port-forward "pod/$ambient_pod" "$port:$AMBIENT_ADMIN_PORT" >"$pf_log" 2>&1 &
  pf_pid=$!
  fetched=false
  for _ in $(seq 1 20); do
    if curl -fsS -H "Authorization: Bearer $token" \
      "http://127.0.0.1:$port/node-waypoint/identities" >"$out" 2>"$out.curl"; then
      fetched=true
      break
    fi
    sleep 0.25
  done
  kill "$pf_pid" 2>/dev/null || true
  wait "$pf_pid" 2>/dev/null || true
  [[ "$fetched" == "true" ]]
}

node_waypoint_identities_include_uid() {
  local identities_file="$1"
  local uid="$2"
  python3 - "$identities_file" "$uid" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

uid = sys.argv[2]
for identity in data.get("identities") or []:
    if identity.get("pod_uid") == uid:
        sys.exit(0)
sys.exit(1)
PY
}

summarize_orig_dst4_records_for_uid() {
  local node="$1"
  local uid="$2"
  local expected_port="$3"
  local evidence_file="$RESULTS_DIR/bpftool-$node.txt"
  if [[ ! -f "$evidence_file" ]]; then
    return 0
  fi
  python3 - "$evidence_file" "$uid" "$expected_port" <<'PY'
import ipaddress
import re
import sys
import uuid

path, uid_text, expected_port_text = sys.argv[1:4]
uid = uuid.UUID(uid_text).bytes
expected_port = int(expected_port_text)
records = []
in_orig_dst4 = False
pending_value = False
hex_bytes = []

def flush_value():
    global hex_bytes
    if len(hex_bytes) >= 32:
        value = bytes(hex_bytes[:32])
        if value[8:24] == uid:
            records.append(
                (
                    str(ipaddress.IPv4Address(value[0:4])),
                    int.from_bytes(value[4:8], "little"),
                    int.from_bytes(value[24:32], "little"),
                )
            )
    hex_bytes = []

with open(path, encoding="utf-8", errors="replace") as fh:
    for raw in fh:
        line = raw.strip()
        if line.startswith("## bpftool map dump pinned "):
            if pending_value:
                flush_value()
                pending_value = False
            in_orig_dst4 = line.endswith("/orig_dst4")
            continue
        if not in_orig_dst4:
            continue
        if line == "value:":
            if pending_value:
                flush_value()
            pending_value = True
            continue
        if line == "key:" or line.startswith("Found ") or line.startswith("## "):
            if pending_value:
                flush_value()
                pending_value = False
            if line.startswith("## "):
                in_orig_dst4 = False
            continue
        if pending_value:
            hex_bytes.extend(int(token, 16) for token in re.findall(r"\b[0-9a-fA-F]{2}\b", line))
    if pending_value:
        flush_value()

if not records:
    print(f"orig_dst4 records for uid {uid_text}: none")
    sys.exit(0)

ports = sorted({port for _, port, _ in records})
destinations = ", ".join(f"{addr}:{port}" for addr, port, _ in records[:12])
suffix = "" if len(records) <= 12 else f", ... +{len(records) - 12} more"
print(
    f"orig_dst4 records for uid {uid_text}: count={len(records)} "
    f"ports={ports} destinations=[{destinations}{suffix}]"
)
if expected_port not in ports:
    print(
        f"orig_dst4 records for uid {uid_text} did not include expected port "
        f"{expected_port}; this means capture stamped records, but not the intended "
        "Service destination port"
    )
PY
}

node_host_file_exists() {
  local node="$1"
  local path="$2"
  if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
    docker exec "$node" test -f "$path" >/dev/null 2>&1
  else
    kubectl debug "node/$node" -n default --image=busybox:1.36 --quiet -- \
      chroot /host sh -eu -c 'test -f "$1"' sh "$path" >/dev/null 2>&1
  fi
}

dump_node_waypoint_registry() {
  local node="$1"
  local out="$RESULTS_DIR/node-waypoint-registry-$node.txt"
  mkdir -p "$RESULTS_DIR"
  if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
    docker exec "$node" sh -eu -c '
      dir="$1"
      if [ ! -d "$dir" ]; then
        echo "$dir does not exist"
        exit 0
      fi
      find "$dir" -maxdepth 2 -type f -print 2>/dev/null | sort | while IFS= read -r file; do
        echo "--- $file"
        sed -n "1,3p" "$file" 2>/dev/null || true
      done
    ' sh "$NODE_WAYPOINT_REGISTRY_DIR" >"$out" 2>&1 || true
  else
    kubectl debug "node/$node" -n default --image=busybox:1.36 --quiet -- \
      chroot /host sh -eu -c '
        dir="$1"
        if [ ! -d "$dir" ]; then
          echo "$dir does not exist"
          exit 0
        fi
        find "$dir" -maxdepth 2 -type f -print 2>/dev/null | sort | while IFS= read -r file; do
          echo "--- $file"
          sed -n "1,3p" "$file" 2>/dev/null || true
        done
      ' sh "$NODE_WAYPOINT_REGISTRY_DIR" >"$out" 2>&1 || true
  fi
  cat "$out" >&2 || true
}

dump_node_waypoint_runtime_state() {
  local node="$1"
  local out="$RESULTS_DIR/node-waypoint-runtime-$node.txt"
  mkdir -p "$RESULTS_DIR"
  if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
    docker exec "$node" sh -eu -c '
      echo "## host interfaces"
      ip -o link show 2>/dev/null || true
      echo
      echo "## pod cgroups and process netns views"
      find /sys/fs/cgroup -maxdepth 8 \( -name "pod*" -o -name "*pod*.slice" \) -type d 2>/dev/null |
        sort |
        head -n 200 |
        while IFS= read -r cg; do
          echo "--- cgroup $cg"
          find "$cg" -maxdepth 3 -name cgroup.procs -type f 2>/dev/null |
            sort |
            while IFS= read -r procs; do
              pids="$(tr "\n" " " < "$procs" 2>/dev/null || true)"
              [ -n "$pids" ] || continue
              echo "### $procs: $pids"
              for pid in $pids; do
                [ -d "/proc/$pid" ] || continue
                echo "pid=$pid netns=$(readlink "/proc/$pid/ns/net" 2>/dev/null || true)"
                net_dir="/proc/$pid/root/sys/class/net"
                if [ -d "$net_dir" ]; then
                  for iface in "$net_dir"/*; do
                    [ -e "$iface/ifindex" ] || continue
                    name="$(basename "$iface")"
                    ifindex="$(cat "$iface/ifindex" 2>/dev/null || true)"
                    iflink="$(cat "$iface/iflink" 2>/dev/null || true)"
                    echo "  iface=$name ifindex=$ifindex iflink=$iflink"
                  done
                else
                  echo "  missing $net_dir"
                fi
                if command -v nsenter >/dev/null 2>&1; then
                  echo "  sockets:"
                  nsenter -t "$pid" -n sh -c "
                    if command -v ss >/dev/null 2>&1; then
                      ss -ltnp 2>/dev/null || true
                      ss -tnp 2>/dev/null || true
                    elif command -v netstat >/dev/null 2>&1; then
                      netstat -tnlp 2>/dev/null || true
                      netstat -tn 2>/dev/null || true
                    else
                      echo \"ss/netstat unavailable\"
                    fi
                  " 2>/dev/null | sed "s/^/    /" || true
                fi
              done
            done
        done
    ' >"$out" 2>&1 || true
  else
    kubectl debug "node/$node" -n default --image=busybox:1.36 --quiet -- \
      chroot /host sh -eu -c '
        echo "## host interfaces"
        ip -o link show 2>/dev/null || true
        echo
        echo "## pod cgroups and process netns views"
        find /sys/fs/cgroup -maxdepth 8 \( -name "pod*" -o -name "*pod*.slice" \) -type d 2>/dev/null |
          sort |
          head -n 200 |
          while IFS= read -r cg; do
            echo "--- cgroup $cg"
            find "$cg" -maxdepth 3 -name cgroup.procs -type f 2>/dev/null |
              sort |
              while IFS= read -r procs; do
                pids="$(tr "\n" " " < "$procs" 2>/dev/null || true)"
                [ -n "$pids" ] || continue
                echo "### $procs: $pids"
                for pid in $pids; do
                  [ -d "/proc/$pid" ] || continue
                  echo "pid=$pid netns=$(readlink "/proc/$pid/ns/net" 2>/dev/null || true)"
                  net_dir="/proc/$pid/root/sys/class/net"
                  if [ -d "$net_dir" ]; then
                    for iface in "$net_dir"/*; do
                      [ -e "$iface/ifindex" ] || continue
                      name="$(basename "$iface")"
                      ifindex="$(cat "$iface/ifindex" 2>/dev/null || true)"
                      iflink="$(cat "$iface/iflink" 2>/dev/null || true)"
                      echo "  iface=$name ifindex=$ifindex iflink=$iflink"
                    done
                  else
                    echo "  missing $net_dir"
                  fi
                  if command -v nsenter >/dev/null 2>&1; then
                    echo "  sockets:"
                    nsenter -t "$pid" -n sh -c "
                      if command -v ss >/dev/null 2>&1; then
                        ss -ltnp 2>/dev/null || true
                        ss -tnp 2>/dev/null || true
                      elif command -v netstat >/dev/null 2>&1; then
                        netstat -tnlp 2>/dev/null || true
                        netstat -tn 2>/dev/null || true
                      else
                        echo \"ss/netstat unavailable\"
                      fi
                    " 2>/dev/null | sed "s/^/    /" || true
                  fi
                done
              done
          done
      ' >"$out" 2>&1 || true
  fi
  cat "$out" >&2 || true
}

wait_for_node_waypoint_ready_markers() {
  log "checking node-waypoint pod registry and in-netns ready markers"
  local missing_file="$RESULTS_DIR/node-waypoint-ready-missing.txt"
  mkdir -p "$RESULTS_DIR"
  for _ in $(seq 1 60); do
    local count=0
    local all_ready=true
    : >"$missing_file"
    while IFS=$'\t' read -r uid node pod_name; do
      [[ -n "$uid" ]] || continue
      count=$((count + 1))
      if ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/$uid"; then
        all_ready=false
        echo "$pod_name on $node missing registry entry $NODE_WAYPOINT_REGISTRY_DIR/$uid" >>"$missing_file"
      fi
      if ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/.ready/$uid"; then
        all_ready=false
        echo "$pod_name on $node missing ready marker $NODE_WAYPOINT_REGISTRY_DIR/.ready/$uid" >>"$missing_file"
      fi
    done < <(workload_pod_records)
    if [[ "$count" -ge 4 && "$all_ready" == "true" ]]; then
      record_live_assertion_once \
        node_waypoint.ebpf.registry_ready \
        pass \
        "" \
        "" \
        "pod-registry-and-in-netns-ready-markers-present" \
        "" \
        "" \
        "node-waypoint-ready-missing.txt"
      return
    fi
    sleep 2
  done

  echo "NodeWaypoint pod registry did not become ready for every workload pod" >&2
  cat "$missing_file" >&2 || true
  collect_node_agent_metrics
  for node in "$NODE_A" "$NODE_B"; do
    dump_node_waypoint_registry "$node"
    dump_node_waypoint_runtime_state "$node"
  done
  exit 1
}

wait_for_node_waypoint_ipv6_ready_markers() {
  log "checking node-waypoint IPv6 in-netns ready markers"
  local missing_file="$RESULTS_DIR/node-waypoint-ready6-missing.txt"
  mkdir -p "$RESULTS_DIR"
  for _ in $(seq 1 60); do
    local count=0
    local all_ready=true
    : >"$missing_file"
    while IFS=$'\t' read -r uid node pod_name; do
      [[ -n "$uid" ]] || continue
      count=$((count + 1))
      if ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/.ready6/$uid"; then
        all_ready=false
        echo "$pod_name on $node missing IPv6 ready marker $NODE_WAYPOINT_REGISTRY_DIR/.ready6/$uid" >>"$missing_file"
      fi
    done < <(workload_pod_records)
    if [[ "$count" -ge 4 && "$all_ready" == "true" ]]; then
      record_live_assertion_once \
        node_waypoint.ebpf.registry_ready_ipv6 \
        pass \
        "" \
        "" \
        "pod-registry-ipv6-in-netns-ready-markers-present" \
        "" \
        "" \
        "node-waypoint-ready6-missing.txt"
      return
    fi
    sleep 2
  done

  echo "NodeWaypoint IPv6 ready markers did not appear for every workload pod" >&2
  cat "$missing_file" >&2 || true
  collect_node_agent_metrics
  for node in "$NODE_A" "$NODE_B"; do
    dump_node_waypoint_registry "$node"
    dump_node_waypoint_runtime_state "$node"
  done
  record_live_assertion \
    node_waypoint.ebpf.registry_ready_ipv6 \
    fail \
    "" \
    "" \
    "missing-ipv6-in-netns-ready-markers" \
    "" \
    "" \
    "node-waypoint-ready6-missing.txt"
  exit 1
}

wait_for_node_waypoint_marker_removed() {
  local node="$1"
  local uid="$2"
  for _ in $(seq 1 60); do
    if ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/$uid" &&
      ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/.ready/$uid" &&
      ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/.ready4/$uid" &&
      ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/.ready6/$uid"; then
      return
    fi
    sleep 1
  done
  echo "stale NodeWaypoint registry or readiness marker remained for deleted pod $uid on $node" >&2
  dump_node_waypoint_registry "$node"
  exit 1
}

mesh_drift_ready() {
  local file="$1"
  local expected_namespace="$2"
  python3 - "$file" "$expected_namespace" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)

expected_namespace = sys.argv[2]
slice_view = data.get("slice") or {}
resources = slice_view.get("resources") or {}
# This scenario needs both source-only identity workloads and both destination
# workloads in every ambient proxy slice; a lower count can pass readiness but
# fail the NodeWaypoint listener-UID identity fallback later.
expected = {
    "workloads": 4,
    "services": 2,
    "mesh_policies": 1,
    "peer_authentications": 1,
}
errors = []
if not slice_view.get("last_received_at"):
    errors.append("missing slice.last_received_at")
if slice_view.get("namespace") != expected_namespace:
    errors.append(f"slice.namespace={slice_view.get('namespace')!r}, expected {expected_namespace!r}")
if slice_view.get("source_protocol") != "native":
    errors.append(f"slice.source_protocol={slice_view.get('source_protocol')!r}, expected 'native'")
for key, minimum in expected.items():
    actual = resources.get(key, 0)
    if actual < minimum:
        errors.append(f"slice.resources.{key}={actual}, expected >= {minimum}")
if errors:
    print("; ".join(errors), file=sys.stderr)
    sys.exit(1)
PY
}

wait_for_ambient_mesh_slice() {
  log "checking ambient proxies accepted the live mesh slice"
  local token
  token="$(admin_bearer_token)"
  local drift_dir="$RESULTS_DIR/mesh-drift"
  mkdir -p "$drift_dir"
  local -a ambient_pods
  mapfile -t ambient_pods < <(kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
  if [[ "${#ambient_pods[@]}" -lt 2 ]]; then
    echo "expected at least two ambient pods, found ${#ambient_pods[@]}" >&2
    kubectl -n "$MESH_NS" get pods -o wide >&2
    exit 1
  fi

  for attempt in $(seq 1 60); do
    local ready=0
    local idx=0
    for pod in "${ambient_pods[@]}"; do
      local port=$((19100 + idx))
      local drift_file="$drift_dir/$pod.json"
      local check_file="$drift_dir/$pod.check"
      local pf_log="$drift_dir/$pod-port-forward.log"
      local pf_pid
      idx=$((idx + 1))
      kubectl -n "$MESH_NS" port-forward "pod/$pod" "$port:$AMBIENT_ADMIN_PORT" >"$pf_log" 2>&1 &
      pf_pid=$!
      local fetched=false
      for retry in $(seq 1 20); do
        if curl -fsS -H "Authorization: Bearer $token" \
          "http://127.0.0.1:$port/mesh/config-drift?include_overlay=false" >"$drift_file" 2>"$check_file.curl"; then
          fetched=true
          break
        fi
        sleep 0.25
      done
      kill "$pf_pid" 2>/dev/null || true
      wait "$pf_pid" 2>/dev/null || true
      if [[ "$fetched" == "true" ]] && mesh_drift_ready "$drift_file" "$WORKLOAD_NS" >"$check_file" 2>&1; then
        ready=$((ready + 1))
      else
        cat "$check_file.curl" >"$check_file" 2>/dev/null || true
      fi
    done
    if [[ "$ready" -eq "${#ambient_pods[@]}" ]]; then
      record_live_assertion_once \
        node_waypoint.mesh_slice.accepted \
        pass \
        "" \
        "" \
        "ambient-proxies-accepted-live-mesh-slice" \
        "" \
        "" \
        "mesh-drift"
      return
    fi
    sleep 2
  done

  echo "ambient proxies did not accept the expected live mesh slice" >&2
  for file in "$drift_dir"/*; do
    echo "--- $file" >&2
    cat "$file" >&2 || true
  done
  exit 1
}

pod_ip() {
  kubectl -n "$WORKLOAD_NS" get pod -l "app=$1" -o jsonpath='{.items[0].status.podIP}'
}

pod_ipv6() {
  kubectl -n "$WORKLOAD_NS" get pod -l "app=$1" -o jsonpath='{range .items[0].status.podIPs[*]}{.ip}{"\n"}{end}' | grep ':' | head -n1 || true
}

svc_ipv6() {
  kubectl -n "$WORKLOAD_NS" get svc "$1" -o go-template='{{range .spec.clusterIPs}}{{.}}{{"\n"}}{{end}}' | grep ':' | head -n1 || true
}

curl_family_from() {
  local family="$1"
  local deploy="$2"
  local url="$3"
  if [[ -n "$family" ]]; then
    kubectl -n "$WORKLOAD_NS" exec "deploy/$deploy" -- \
      sh -c 'curl "$1" -g -sS -m 8 -w "\n%{http_code}" "$2"' -- "$family" "$url"
  else
    kubectl -n "$WORKLOAD_NS" exec "deploy/$deploy" -- \
      sh -c 'curl -g -sS -m 8 -w "\n%{http_code}" "$1"' -- "$url"
  fi
}

curl_from() {
  local deploy="$1"
  local url="$2"
  curl_family_from "" "$deploy" "$url"
}

curl4_from() {
  local deploy="$1"
  local url="$2"
  curl_family_from "-4" "$deploy" "$url"
}

curl6_from() {
  local deploy="$1"
  local url="$2"
  curl_family_from "-6" "$deploy" "$url"
}

curl_for_family_from() {
  local family="$1"
  local deploy="$2"
  local url="$3"
  case "$family" in
    4) curl4_from "$deploy" "$url" ;;
    6) curl6_from "$deploy" "$url" ;;
    "") curl_from "$deploy" "$url" ;;
    *)
      echo "unsupported curl address family '$family'" >&2
      exit 1
      ;;
  esac
}

wait_for_node_waypoint_admission() {
  local from="$1"
  local label="$2"
  local url="$3"
  local family="${4:-4}"
  local uid node pod identities_dir identities_file curl_out curl_err curl_status_file curl_status record
  record="$(workload_pod_record_for_app "$from")"
  IFS=$'\t' read -r uid node pod <<<"$record"
  if [[ -z "${uid:-}" || -z "${node:-}" || -z "${pod:-}" ]]; then
    echo "could not resolve workload pod record for app=$from" >&2
    kubectl -n "$WORKLOAD_NS" get pods -o wide >&2 || true
    exit 1
  fi

  log "waiting for NodeWaypoint admission for $label ($pod on $node)"
  identities_dir="$RESULTS_DIR/ambient-node-waypoint-admission"
  mkdir -p "$identities_dir"
  identities_file="$identities_dir/$from-$uid.json"
  curl_out="$identities_dir/$from-$uid.curl.out"
  curl_err="$identities_dir/$from-$uid.curl.err"
  curl_status_file="$identities_dir/$from-$uid.curl.status"

  for _ in $(seq 1 30); do
    set +e
    curl_for_family_from "$family" "$from" "$url" >"$curl_out" 2>"$curl_err"
    curl_status=$?
    set -e
    echo "$curl_status" >"$curl_status_file"

    if fetch_node_waypoint_identities_for_node "$node" "$identities_file" &&
      node_waypoint_identities_include_uid "$identities_file" "$uid"; then
      return
    fi
    sleep 2
  done

  echo "NodeWaypoint did not admit $label traffic from $pod ($uid) on $node to $url" >&2
  if [[ -f "$curl_status_file" ]]; then
    echo "last curl status: $(cat "$curl_status_file")" >&2 || true
  fi
  if [[ -s "$curl_out" ]]; then
    echo "--- last curl stdout" >&2
    cat "$curl_out" >&2 || true
  fi
  if [[ -s "$curl_err" ]]; then
    echo "--- last curl stderr" >&2
    cat "$curl_err" >&2 || true
  fi
  if [[ -f "$identities_file" ]]; then
    cat "$identities_file" >&2 || true
  fi
  collect_traffic_failure_diagnostics
  summarize_orig_dst4_records_for_uid "$node" "$uid" 8080 >&2 || true
  exit 1
}

expect_allowed() {
  local from="$1"
  local label="$2"
  local url="$3"
  local expected_body="$4"
  local family="${5:-}"
  local output="" code="" body="" status=1 err
  err="$(mktemp)"
  for attempt in $(seq 1 8); do
    set +e
    output="$(curl_for_family_from "$family" "$from" "$url" 2>"$err")"
    status=$?
    set -e
    code="${output##*$'\n'}"
    body="${output%$'\n'*}"
    body="${body//$'\r'/}"
    while [[ "$body" == *$'\n' ]]; do
      body="${body%$'\n'}"
    done
    if [[ "$status" -eq 0 && "$code" == "200" ]]; then
      if [[ "$body" == "$expected_body" ]]; then
        rm -f "$err"
        return
      fi
      break
    fi
    if [[ "$status" -eq 0 ]]; then
      break
    fi
    sleep 1
  done
  echo "expected allow for $label from $from to $url with body '$expected_body', got HTTP ${code:-curl-exit-$status} body '${body:-<empty>}'" >&2
  cat "$err" >&2 || true
  rm -f "$err"
  collect_traffic_failure_diagnostics
  return 1
}

recorded_expect_allowed() {
  local assertion_id="$1"
  local from="$2"
  local destination="$3"
  local label="$4"
  local url="$5"
  local expected_body="$6"
  local family="${7:-}"
  local outcome="${8:-allowed-http-200}"
  local source_spiffe destination_spiffe
  source_spiffe="$(spiffe_for_sa "$from")"
  destination_spiffe="$(spiffe_for_sa "$destination")"
  if expect_allowed "$from" "$label" "$url" "$expected_body" "$family"; then
    record_live_assertion \
      "$assertion_id" \
      pass \
      "$from" \
      "$destination" \
      "$outcome" \
      "$source_spiffe" \
      "$destination_spiffe"
  else
    record_live_assertion \
      "$assertion_id" \
      fail \
      "$from" \
      "$destination" \
      "expected-$outcome" \
      "$source_spiffe" \
      "$destination_spiffe"
    return 1
  fi
}

recorded_expect_blocked() {
  local assertion_id="$1"
  local from="$2"
  local destination="$3"
  local label="$4"
  local url="$5"
  local family="${6:-}"
  local outcome="${7:-blocked-not-http-200}"
  local source_spiffe destination_spiffe
  source_spiffe="$(spiffe_for_sa "$from")"
  destination_spiffe="$(spiffe_for_sa "$destination")"
  if expect_blocked "$from" "$label" "$url" "$family"; then
    record_live_assertion \
      "$assertion_id" \
      pass \
      "$from" \
      "$destination" \
      "$outcome" \
      "$source_spiffe" \
      "$destination_spiffe"
  else
    record_live_assertion \
      "$assertion_id" \
      fail \
      "$from" \
      "$destination" \
      "unexpected-http-200" \
      "$source_spiffe" \
      "$destination_spiffe"
    return 1
  fi
}

expect_blocked() {
  local from="$1"
  local label="$2"
  local url="$3"
  local family="${4:-}"
  local output code err
  err="$(mktemp)"
  set +e
  output="$(curl_for_family_from "$family" "$from" "$url" 2>"$err")"
  local status=$?
  set -e
  code="${output##*$'\n'}"
  if [[ "$status" -eq 0 && "$code" == "200" ]]; then
    echo "expected block for $label from $from to $url, got HTTP 200" >&2
    cat "$err" >&2 || true
    rm -f "$err"
    collect_traffic_failure_diagnostics
    return 1
  fi
  rm -f "$err"
}

run_traffic_checks() {
  log "running IPv4 Service authorization and bypass checks"
  local dst_a_ip dst_b_ip
  dst_a_ip="$(pod_ip dst-a)"
  dst_b_ip="$(pod_ip dst-b)"

  wait_for_node_waypoint_admission src-a "src-a same-node Service path" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" 4
  wait_for_node_waypoint_admission src-b "src-b same-node Service path" "http://dst-b.$WORKLOAD_NS.svc.cluster.local:8080/" 4

  recorded_expect_allowed \
    node_waypoint.ipv4.service_allow_same_node \
    src-a \
    dst-a \
    "same-node Service ClusterIP" \
    "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" \
    "ok-a" \
    4
  recorded_expect_allowed \
    node_waypoint.ipv4.service_allow_cross_node \
    src-a \
    dst-b \
    "cross-node Service ClusterIP" \
    "http://dst-b.$WORKLOAD_NS.svc.cluster.local:8080/" \
    "ok-b" \
    4

  recorded_expect_blocked \
    node_waypoint.ipv4.service_deny_same_node \
    src-b \
    dst-b \
    "same-node Service AuthorizationPolicy DENY" \
    "http://dst-b.$WORKLOAD_NS.svc.cluster.local:8080/" \
    4 \
    "denied-by-authorization-policy"
  recorded_expect_blocked \
    node_waypoint.ipv4.service_deny_cross_node \
    src-b \
    dst-a \
    "cross-node Service AuthorizationPolicy DENY" \
    "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" \
    4 \
    "denied-by-authorization-policy"

  recorded_expect_blocked \
    node_waypoint.ipv4.pod_ip_bypass_guard_same_node \
    src-b \
    dst-b \
    "same-node direct Pod IP AuthorizationPolicy bypass guard" \
    "http://$dst_b_ip:8080/" \
    4 \
    "direct-pod-ip-fail-closed"
  recorded_expect_blocked \
    node_waypoint.ipv4.pod_ip_bypass_guard_cross_node \
    src-b \
    dst-a \
    "cross-node direct Pod IP AuthorizationPolicy bypass guard" \
    "http://$dst_a_ip:8080/" \
    4 \
    "direct-pod-ip-fail-closed"

  log "checking stale identity cleanup across source workload recreation"
  local old_src_a_uid old_src_a_node
  old_src_a_uid="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].metadata.uid}')"
  old_src_a_node="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].spec.nodeName}')"
  kubectl -n "$WORKLOAD_NS" delete pod -l app=src-a --wait=true
  wait_for_node_waypoint_marker_removed "$old_src_a_node" "$old_src_a_uid"
  kubectl -n "$WORKLOAD_NS" rollout status deploy/src-a --timeout=3m
  wait_for_node_waypoint_ready_markers
  wait_for_ambient_mesh_slice
  wait_for_node_waypoint_admission src-a "recreated src-a Service path" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" 4
  wait_for_node_waypoint_admission src-b "post-recreation src-b Service path" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" 4
  if ! expect_allowed src-a "recreated source identity" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" "ok-a" 4; then
    record_live_assertion \
      node_waypoint.identity.stale_cleanup \
      fail \
      src-a \
      dst-a \
      "recreated-source-not-admitted" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    return 1
  fi
  if ! expect_blocked src-b "post-recreation AuthorizationPolicy DENY" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" 4; then
    record_live_assertion \
      node_waypoint.identity.stale_cleanup \
      fail \
      src-b \
      dst-a \
      "post-recreation-deny-regressed" \
      "$(spiffe_for_sa src-b)" \
      "$(spiffe_for_sa dst-a)"
    return 1
  fi
  record_live_assertion \
    node_waypoint.identity.stale_cleanup \
    pass \
    src-a \
    dst-a \
    "deleted-source-registry-marker-removed-and-recreated-source-admitted" \
    "$(spiffe_for_sa src-a)" \
    "$(spiffe_for_sa dst-a)"
}

run_ipv6_checks() {
  log "running dual-stack IPv6 admission checks"
  local dst_a_v6 svc_a_v6 svc_a_url
  dst_a_v6="$(pod_ipv6 dst-a)"
  svc_a_v6="$(svc_ipv6 dst-a)"
  if [[ -z "$dst_a_v6" || -z "$svc_a_v6" ]]; then
    if [[ "$REQUIRE_DUAL_STACK" == "true" ]]; then
      echo "dual-stack pass required, but dst-a pod/service has no IPv6 address (pod='$dst_a_v6' service='$svc_a_v6')" >&2
      kubectl -n "$WORKLOAD_NS" get pod -l app=dst-a -o yaml >&2 || true
      kubectl -n "$WORKLOAD_NS" get svc dst-a -o yaml >&2 || true
      exit 1
    fi
    log "cluster is not dual-stack; skipping IPv6 pass"
    record_live_assertion \
      node_waypoint.ebpf.registry_ready_ipv6 \
      skip \
      "" \
      "" \
      "cluster-not-dual-stack" \
      "" \
      ""
    record_live_assertion \
      node_waypoint.ipv6.service_allow \
      skip \
      src-a \
      dst-a \
      "cluster-not-dual-stack" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    record_live_assertion \
      node_waypoint.ipv6.service_deny \
      skip \
      src-b \
      dst-a \
      "cluster-not-dual-stack" \
      "$(spiffe_for_sa src-b)" \
      "$(spiffe_for_sa dst-a)"
    record_live_assertion \
      node_waypoint.ipv6.pod_ip_bypass_guard \
      skip \
      src-b \
      dst-a \
      "cluster-not-dual-stack" \
      "$(spiffe_for_sa src-b)" \
      "$(spiffe_for_sa dst-a)"
    record_live_assertion \
      node_waypoint.ipv6.pod_ip_fail_closed \
      skip \
      src-a \
      dst-a \
      "cluster-not-dual-stack" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    record_live_assertion \
      node_waypoint.ipv6.service_fail_closed \
      skip \
      src-a \
      dst-a \
      "cluster-not-dual-stack" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    return
  fi

  wait_for_node_waypoint_ipv6_ready_markers
  svc_a_url="http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/"
  wait_for_node_waypoint_admission src-a "src-a IPv6 Service path" "$svc_a_url" 6

  # Historical fail-closed assertion IDs remain in the artifact for comparability,
  # but they are no longer required once IPv6 admission is implemented.
  record_live_assertion \
    node_waypoint.ipv6.pod_ip_fail_closed \
    skip \
    src-a \
    dst-a \
    "superseded-by-ipv6-admission" \
    "$(spiffe_for_sa src-a)" \
    "$(spiffe_for_sa dst-a)"
  record_live_assertion \
    node_waypoint.ipv6.service_fail_closed \
    skip \
    src-a \
    dst-a \
    "superseded-by-ipv6-admission" \
    "$(spiffe_for_sa src-a)" \
    "$(spiffe_for_sa dst-a)"

  recorded_expect_allowed \
    node_waypoint.ipv6.service_allow \
    src-a \
    dst-a \
    "IPv6 Service ClusterIP" \
    "$svc_a_url" \
    "ok-a" \
    6 \
    "allowed-ipv6-http-200"
  recorded_expect_blocked \
    node_waypoint.ipv6.service_deny \
    src-b \
    dst-a \
    "IPv6 Service AuthorizationPolicy DENY" \
    "$svc_a_url" \
    6 \
    "denied-by-authorization-policy"
  recorded_expect_blocked \
    node_waypoint.ipv6.pod_ip_bypass_guard \
    src-b \
    dst-a \
    "IPv6 direct Pod IP AuthorizationPolicy bypass guard" \
    "http://[$dst_a_v6]:8080/" \
    6 \
    "direct-ipv6-pod-ip-fail-closed"
}

cleanup() {
  if [[ "${FERRUM_LIVE_KEEP_RESOURCES:-false}" != "true" ]]; then
    kubectl delete namespace "$WORKLOAD_NS" --ignore-not-found=true >/dev/null 2>&1 || true
    helm uninstall "$RELEASE" -n "$MESH_NS" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

init_live_assertions
render_chart_assertions
validate_cluster
label_nodes
install_ferrum
assert_node_agent_ready_metric
collect_bpf_evidence
apply_workloads
wait_for_node_waypoint_ready_markers
wait_for_ambient_mesh_slice
run_traffic_checks
run_ipv6_checks
ferrum_live_assertions_require_all_passed "$LIVE_ASSERTIONS_FILE" "${REQUIRED_LIVE_ASSERTIONS[@]}"

log "live NodeWaypoint eBPF datapath checks passed"
