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

# shellcheck source=../lib/spire.sh
SPIRE_HELPER="$ROOT_DIR/tests/k8s/lib/spire.sh"
if [[ ! -f "$SPIRE_HELPER" && -f "$PWD/tests/k8s/lib/spire.sh" ]]; then
  SPIRE_HELPER="$PWD/tests/k8s/lib/spire.sh"
fi
source "$SPIRE_HELPER"

MESH_NS="${FERRUM_LIVE_MESH_NAMESPACE:-ferrum}"
WORKLOAD_NS="${FERRUM_LIVE_WORKLOAD_NAMESPACE:-ferrum-ebpf-live}"
UNMANAGED_NS="${FERRUM_LIVE_UNMANAGED_NAMESPACE:-$WORKLOAD_NS-unmanaged}"
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
DIAGNOSTIC_TIMEOUT_SECONDS="${FERRUM_LIVE_DIAGNOSTIC_TIMEOUT_SECONDS:-30}"
ADMIN_JWT_SECRET="${FERRUM_LIVE_ADMIN_JWT_SECRET:-ferrum-edge-node-waypoint-live-admin-secret}"
ADMIN_JWT_ISSUER="${FERRUM_LIVE_ADMIN_JWT_ISSUER:-ferrum-edge}"
KUBE_CONTEXT="${FERRUM_LIVE_KUBE_CONTEXT:-}"
SPIRE_PRODUCTION="${FERRUM_LIVE_SPIRE_PRODUCTION:-true}"
SPIRE_NS="${FERRUM_LIVE_SPIRE_NAMESPACE:-$FERRUM_SPIRE_NAMESPACE}"
TRUST_DOMAIN="${FERRUM_LIVE_TRUST_DOMAIN:-cluster.local}"
RESULTS_DIR="$ROOT_DIR/target/node-waypoint-ebpf-live"
LIVE_ASSERTIONS_FILE="${FERRUM_LIVE_ASSERTIONS_FILE:-$RESULTS_DIR/live-assertions.json}"
LIVE_PLATFORM_PROFILE="${FERRUM_LIVE_PLATFORM_PROFILE:-kind-dual-stack-node-waypoint-ebpf}"
STALE_IP_REUSE_HOST_LOCAL_PROFILE=false
if [[ "$LIVE_PLATFORM_PROFILE" == "kind-dual-stack-node-waypoint-ebpf" ]]; then
  STALE_IP_REUSE_HOST_LOCAL_PROFILE=true
fi
LIVE_ASSERTIONS_INITIALIZED=false
RECORDED_LIVE_ASSERTIONS=" "
TRUSTED_KUBELET_PROBE_IPS=""
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
  node_waypoint.ipv4.direct_inbound_guard_same_node
  node_waypoint.ipv4.direct_inbound_guard_cross_node
  node_waypoint.identity.stale_cleanup
  node_waypoint.identity.spire_chart_profile
)
if [[ "$STALE_IP_REUSE_HOST_LOCAL_PROFILE" == "true" ]]; then
  REQUIRED_LIVE_ASSERTIONS+=(
    node_waypoint.identity.stale_ip_reuse
  )
fi
if [[ "$REQUIRE_DUAL_STACK" == "true" ]]; then
  REQUIRED_LIVE_ASSERTIONS+=(
    node_waypoint.ebpf.registry_ready_ipv6
    node_waypoint.ipv6.service_allow
    node_waypoint.ipv6.service_deny
    node_waypoint.ipv6.pod_ip_bypass_guard
    node_waypoint.ipv6.direct_inbound_guard
  )
fi
if [[ "$SPIRE_PRODUCTION" == "true" ]]; then
  REQUIRED_LIVE_ASSERTIONS+=(
    node_waypoint.identity.spire_live_ready
    node_waypoint.identity.spire_workload_entries
    node_waypoint.identity.workload_api_svid
    node_waypoint.identity.plaintext_hbone_rejected
    node_waypoint.identity.unauthenticated_hbone_rejected
    node_waypoint.identity.forged_assertion_rejected
  )
fi

if [[ "${FERRUM_EBPF_LIVE_ACK_DISPOSABLE:-}" != "true" ]]; then
  echo "Refusing to run against the current kube-context without FERRUM_EBPF_LIVE_ACK_DISPOSABLE=true" >&2
  exit 1
fi

helm_set_string_escape() {
  local value="$1"
  printf '%s' "${value//,/\\,}"
}

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
if [[ -z "$KUBE_CONTEXT" ]]; then
  KUBE_CONTEXT="$(kubectl config current-context)"
fi
if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
  require_cmd docker
fi

log() {
  printf '\n[node-waypoint-ebpf-live] %s\n' "$*"
}

diagnostic_timeout() {
  local label="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    local -a timeout_args
    if timeout --foreground 1s true >/dev/null 2>&1; then
      timeout_args=(--foreground "${DIAGNOSTIC_TIMEOUT_SECONDS}s")
    else
      timeout_args=("${DIAGNOSTIC_TIMEOUT_SECONDS}s")
    fi
    timeout "${timeout_args[@]}" "$@" || {
      local status=$?
      if [[ "$status" -eq 124 || "$status" -eq 137 ]]; then
        echo "$label timed out after ${DIAGNOSTIC_TIMEOUT_SECONDS}s" >&2
      fi
      return "$status"
    }
  else
    "$@"
  fi
}

select_kube_context() {
  local current_context
  current_context="$(kubectl config current-context 2>/dev/null || true)"
  if [[ "$current_context" != "$KUBE_CONTEXT" ]]; then
    log "switching kube context to $KUBE_CONTEXT"
    kubectl config use-context "$KUBE_CONTEXT" >/dev/null
  fi
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
  printf 'spiffe://%s/ns/%s/sa/%s' "$TRUST_DOMAIN" "$WORKLOAD_NS" "$service_account"
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

  local spire_id="spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/ferrum-mesh/node/"'$(FERRUM_K8S_NODE_NAME)'
  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.tag="$IMAGE_TAG" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set ambient.spire.enabled=true \
    --set-string "ambient.spire.workloadSpiffeId=$spire_id" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint)"
  if ! grep -q "name: spire-agent-socket" <<<"$rendered" ||
    ! grep -q "mountPath: /run/spire/sockets" <<<"$rendered" ||
    ! grep -q "path: /run/spire/sockets" <<<"$rendered" ||
    ! grep -A3 "name: FERRUM_K8S_NODE_NAME" <<<"$rendered" | grep -q "fieldPath: spec.nodeName" ||
    ! grep -A1 "name: FERRUM_MESH_CA_BACKEND" <<<"$rendered" | grep -q 'value: "spire_agent"' ||
    ! grep -A1 "name: FERRUM_MESH_SPIRE_AGENT_SOCKET" <<<"$rendered" | grep -q 'value: "/run/spire/sockets/agent.sock"' ||
    ! grep -A1 "name: FERRUM_MESH_WORKLOAD_SPIFFE_ID" <<<"$rendered" | grep -q "value: \"$spire_id\"" ||
    ! grep -A1 "name: FERRUM_MESH_PRODUCTION_MODE" <<<"$rendered" | grep -q 'value: "true"' ||
    grep -q "name: FERRUM_MESH_ALLOW_NO_CA" <<<"$rendered"; then
    echo "NodeWaypoint SPIRE render did not mount/configure the Workload API identity source" >&2
    grep -nE 'spire-agent-socket|FERRUM_MESH_CA_BACKEND|FERRUM_MESH_SPIRE_AGENT_SOCKET|FERRUM_MESH_WORKLOAD_SPIFFE_ID|FERRUM_MESH_PRODUCTION_MODE|FERRUM_MESH_ALLOW_NO_CA|mountPath: /run/spire|path: /run/spire' <<<"$rendered" >&2 || true
    exit 1
  fi

  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set image.repository="$IMAGE_REPOSITORY" \
    --set image.tag="$IMAGE_TAG" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set ambient.spire.enabled=true \
    --set ambient.spire.productionMode=false \
    --set-string "ambient.spire.workloadSpiffeId=$spire_id" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint)"
  if ! grep -A1 "name: FERRUM_MESH_PRODUCTION_MODE" <<<"$rendered" | grep -q 'value: "false"'; then
    echo "NodeWaypoint SPIRE render did not preserve ambient.spire.productionMode=false" >&2
    grep -nA1 "FERRUM_MESH_PRODUCTION_MODE" <<<"$rendered" >&2 || true
    exit 1
  fi

  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set ambient.spire.enabled=true \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint >/tmp/ferrum-node-waypoint-spire-missing-id-render.out 2>&1; then
    echo "NodeWaypoint SPIRE render accepted ambient.spire.enabled without a workload SPIFFE ID" >&2
    cat /tmp/ferrum-node-waypoint-spire-missing-id-render.out >&2 || true
    exit 1
  fi
  if ! grep -q "ambient.spire.enabled=true requires ambient.spire.workloadSpiffeId" /tmp/ferrum-node-waypoint-spire-missing-id-render.out; then
    echo "NodeWaypoint SPIRE render rejected missing workload SPIFFE ID without a clear error" >&2
    cat /tmp/ferrum-node-waypoint-spire-missing-id-render.out >&2 || true
    exit 1
  fi

  local shared_spire_id="spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/ferrum-mesh"
  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set ambient.spire.enabled=true \
    --set-string "ambient.spire.workloadSpiffeId=$shared_spire_id" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint >/tmp/ferrum-node-waypoint-spire-shared-id-render.out 2>&1; then
    echo "NodeWaypoint SPIRE render accepted a shared DaemonSet SPIFFE ID" >&2
    cat /tmp/ferrum-node-waypoint-spire-shared-id-render.out >&2 || true
    exit 1
  fi
  if ! grep -q "requires ambient.spire.workloadSpiffeId to include" /tmp/ferrum-node-waypoint-spire-shared-id-render.out; then
    echo "NodeWaypoint SPIRE render rejected shared SPIFFE ID without a clear error" >&2
    cat /tmp/ferrum-node-waypoint-spire-shared-id-render.out >&2 || true
    exit 1
  fi

  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set ambient.env.FERRUM_MESH_CA_BACKEND=none \
    --set ambient.spire.enabled=true \
    --set-string "ambient.spire.workloadSpiffeId=$spire_id" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint >/tmp/ferrum-node-waypoint-spire-managed-env-render.out 2>&1; then
    echo "NodeWaypoint SPIRE render accepted a chart-managed identity env override" >&2
    cat /tmp/ferrum-node-waypoint-spire-managed-env-render.out >&2 || true
    exit 1
  fi
  if ! grep -q "ambient.env.FERRUM_MESH_CA_BACKEND is chart-managed" /tmp/ferrum-node-waypoint-spire-managed-env-render.out; then
    echo "NodeWaypoint SPIRE render rejected managed identity env override without a clear error" >&2
    cat /tmp/ferrum-node-waypoint-spire-managed-env-render.out >&2 || true
    exit 1
  fi

  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set ambient.env.FERRUM_GATEWAY_SVID_CERT_PATH=/etc/ferrum/svid/cert.pem \
    --set ambient.spire.enabled=true \
    --set-string "ambient.spire.workloadSpiffeId=$spire_id" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint >/tmp/ferrum-node-waypoint-spire-file-svid-render.out 2>&1; then
    echo "NodeWaypoint SPIRE render accepted a file-SVID override" >&2
    cat /tmp/ferrum-node-waypoint-spire-file-svid-render.out >&2 || true
    exit 1
  fi
  if ! grep -q "ambient.env.FERRUM_GATEWAY_SVID_CERT_PATH is chart-managed" /tmp/ferrum-node-waypoint-spire-file-svid-render.out; then
    echo "NodeWaypoint SPIRE render rejected file-SVID override without a clear error" >&2
    cat /tmp/ferrum-node-waypoint-spire-file-svid-render.out >&2 || true
    exit 1
  fi
  if helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set ambient.env.FERRUM_GATEWAY_SVID_CERT_PATH_FILE=/etc/ferrum/svid/cert-path-secret \
    --set ambient.spire.enabled=true \
    --set-string "ambient.spire.workloadSpiffeId=$spire_id" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint >/tmp/ferrum-node-waypoint-spire-file-svid-suffix-render.out 2>&1; then
    echo "NodeWaypoint SPIRE render accepted a suffixed file-SVID override" >&2
    cat /tmp/ferrum-node-waypoint-spire-file-svid-suffix-render.out >&2 || true
    exit 1
  fi
  if ! grep -q "ambient.env.FERRUM_GATEWAY_SVID_CERT_PATH_FILE is chart-managed" /tmp/ferrum-node-waypoint-spire-file-svid-suffix-render.out; then
    echo "NodeWaypoint SPIRE render rejected suffixed file-SVID override without a clear error" >&2
    cat /tmp/ferrum-node-waypoint-spire-file-svid-suffix-render.out >&2 || true
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
    grep -q "name: FERRUM_NODE_AGENT_NODE_IP" <<<"$rendered" ||
    grep -q "name: FERRUM_NODE_AGENT_NODE_IPS" <<<"$rendered" ||
    [[ "$(grep -c "name: node-waypoint-pod-registry" <<<"$rendered" || true)" -lt 4 ]]; then
    echo "NodeWaypoint eBPF render did not normalize node-waypoint aliases or rendered implicit probe source trust" >&2
    grep -nE 'image:|FERRUM_MESH_TOPOLOGY|FERRUM_NODE_AGENT_PROXY_MODE|FERRUM_NODE_AGENT_NODE_IP|FERRUM_NODE_AGENT_NODE_IPS|status.hostIP|node-waypoint-pod-registry' <<<"$rendered" >&2 || true
    exit 1
  fi

  local trusted_probe_render_ips="10.244.1.1,10.244.2.1"
  local trusted_probe_render_ips_helm
  trusted_probe_render_ips_helm="$(helm_set_string_escape "$trusted_probe_render_ips")"
  rendered="$(helm template "$RELEASE" "$CHART_DIR" \
    --namespace "$MESH_NS" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint \
    --set-string "nodeAgent.trustedKubeletProbeSourceIps=$trusted_probe_render_ips_helm")"
  if ! grep -A1 "name: FERRUM_NODE_AGENT_NODE_IPS" <<<"$rendered" | grep -q "value: \"$trusted_probe_render_ips\""; then
    echo "NodeWaypoint render did not emit explicit trusted kubelet probe source IPs" >&2
    grep -nE 'FERRUM_NODE_AGENT_NODE_IPS|trustedKubeletProbeSourceIps' <<<"$rendered" >&2 || true
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
    --set controlPlane.enabled=true \
    --set controlPlane.database.type=sqlite \
    --set-string controlPlane.database.sqlite.path=/tmp/ferrum.db \
    --set-string "controlPlane.credentials.adminJwtSecret.value=$ADMIN_JWT_SECRET" \
    --set-string "controlPlane.credentials.cpDpGrpcJwtSecret.value=ferrum-edge-node-waypoint-live-grpc-secret" \
    --set-string "controlPlane.env.FERRUM_K8S_TRUST_DOMAIN=$TRUST_DOMAIN" \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set-string "nodeAgent.admin.port=$NODE_AGENT_ADMIN_PORT" \
    --set nodeAgent.proxyMode=node_waypoint \
    --set-string "nodeAgent.env.FERRUM_K8S_TRUST_DOMAIN=$TRUST_DOMAIN")"
  if [[ "$(grep -A1 -F "name: FERRUM_K8S_TRUST_DOMAIN" <<<"$rendered" | grep -c -F "value: \"$TRUST_DOMAIN\"" || true)" -lt 2 ]]; then
    echo "NodeWaypoint render did not propagate the live trust domain to control-plane and node-agent K8s identity env" >&2
    grep -nE 'name: FERRUM_K8S_TRUST_DOMAIN|value: "' <<<"$rendered" >&2 || true
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
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set-string nodeAgent.env.FERRUM_NODE_AGENT_NODE_IPS=10.244.1.1 >/tmp/ferrum-node-agent-managed-probe-env-render.out 2>&1; then
    echo "Node-agent render accepted a chart-managed probe source env override" >&2
    cat /tmp/ferrum-node-agent-managed-probe-env-render.out >&2 || true
    exit 1
  fi
  if ! grep -q "nodeAgent.env.FERRUM_NODE_AGENT_NODE_IPS is chart-managed" /tmp/ferrum-node-agent-managed-probe-env-render.out; then
    echo "Node-agent render rejected managed probe env override without a clear error" >&2
    cat /tmp/ferrum-node-agent-managed-probe-env-render.out >&2 || true
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
  record_live_assertion \
    node_waypoint.identity.spire_chart_profile \
    pass \
    "" \
    "" \
    "helm-rendered-spire-workload-api-production-identity-source"
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

discover_trusted_kubelet_probe_ips() {
  log "deriving trusted kubelet probe source IPs from node PodCIDRs"
  TRUSTED_KUBELET_PROBE_IPS="$(kubectl get node "$NODE_A" "$NODE_B" -o json | python3 -c '
import ipaddress
import json
import sys

data = json.load(sys.stdin)
items = data.get("items") or [data]
seen = set()
out = []
for node in items:
    spec = node.get("spec") or {}
    cidrs = spec.get("podCIDRs") or []
    if not cidrs and spec.get("podCIDR"):
        cidrs = [spec["podCIDR"]]
    for raw in cidrs:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            ip = next(network.hosts())
        except (StopIteration, ValueError):
            continue
        text = str(ip)
        if text not in seen:
            seen.add(text)
            out.append(text)
print(",".join(out))
')"
  if [[ -z "$TRUSTED_KUBELET_PROBE_IPS" ]]; then
    echo "could not derive trusted kubelet probe source IPs from node PodCIDRs" >&2
    kubectl get node "$NODE_A" "$NODE_B" -o json >&2 || true
    exit 1
  fi
  log "trusted kubelet probe source IPs: $TRUSTED_KUBELET_PROBE_IPS"
}

node_waypoint_spiffe_template() {
  printf 'spiffe://%s/ns/%s/sa/ferrum-mesh/node/$(FERRUM_K8S_NODE_NAME)' "$TRUST_DOMAIN" "$MESH_NS"
}

node_waypoint_spiffe_for_node() {
  local node="$1"
  printf 'spiffe://%s/ns/%s/sa/ferrum-mesh/node/%s' "$TRUST_DOMAIN" "$MESH_NS" "$node"
}

collect_spire_diagnostics() {
  if [[ "$SPIRE_PRODUCTION" != "true" ]]; then
    return
  fi
  ferrum_spire_collect_diagnostics "$KUBE_CONTEXT" "$SPIRE_NS" "$RESULTS_DIR/spire" || true
}

install_spire_production_identity() {
  if [[ "$SPIRE_PRODUCTION" != "true" ]]; then
    log "SPIRE production identity disabled; using explicit no-CA test mode"
    return
  fi

  log "installing minimal SPIRE and registering NodeWaypoint SVID entries"
  ferrum_spire_apply_minimal "$KUBE_CONTEXT" "$TRUST_DOMAIN" "$SPIRE_NS"
  ferrum_spire_wait_ready "$KUBE_CONTEXT" "$SPIRE_NS" 5m

  local -a spire_nodes
  mapfile -t spire_nodes < <(ferrum_spire_agent_nodes "$KUBE_CONTEXT" "$SPIRE_NS")
  if [[ "${#spire_nodes[@]}" -eq 0 ]]; then
    echo "expected at least one scheduled SPIRE Agent node for NodeWaypoint registration" >&2
    kubectl --context "$KUBE_CONTEXT" -n "$SPIRE_NS" get pods -o wide >&2 || true
    exit 1
  fi

  mkdir -p "$RESULTS_DIR/spire"
  ferrum_spire_server_exec "$KUBE_CONTEXT" "$SPIRE_NS" agent list \
    > "$RESULTS_DIR/spire/attested-agents.txt"

  local node spiffe_id agent_parent_id
  for node in "${spire_nodes[@]}"; do
    agent_parent_id="$(ferrum_spire_k8s_psat_agent_parent_id_for_node \
      "$KUBE_CONTEXT" \
      "$SPIRE_NS" \
      "$TRUST_DOMAIN" \
      "$node")"
    spiffe_id="$(node_waypoint_spiffe_for_node "$node")"
    ferrum_spire_register_k8s_workload \
      "$KUBE_CONTEXT" \
      "$SPIRE_NS" \
      "$spiffe_id" \
      "$agent_parent_id" \
      "$MESH_NS" \
      ferrum-mesh \
      "k8s:node-name:$node" \
      "k8s:container-name:ferrum-edge"
  done

  ferrum_spire_server_exec "$KUBE_CONTEXT" "$SPIRE_NS" entry show \
    > "$RESULTS_DIR/spire/registered-entries.txt"
  record_live_assertion \
    node_waypoint.identity.spire_live_ready \
    pass \
    "" \
    "" \
    "spire-server-and-agent-ready" \
    "" \
    "" \
    "spire"
  record_live_assertion \
    node_waypoint.identity.spire_workload_entries \
    pass \
    "" \
    "" \
    "registered-nodewaypoint-per-node-svid-entries" \
    "" \
    "" \
    "spire/attested-agents.txt,spire/registered-entries.txt"
}

install_ferrum() {
  log "installing Ferrum chart"
  local -a identity_args=()
  local trusted_probe_ips_helm
  trusted_probe_ips_helm="$(helm_set_string_escape "$TRUSTED_KUBELET_PROBE_IPS")"
  if [[ "$SPIRE_PRODUCTION" == "true" ]]; then
    local spire_id_template
    spire_id_template="$(node_waypoint_spiffe_template)"
    identity_args=(
      --set ambient.spire.enabled=true
      --set-string "ambient.spire.workloadSpiffeId=$spire_id_template"
      --set ambient.spire.productionMode=true
    )
  else
    identity_args=(
      --set ambient.env.FERRUM_MESH_ALLOW_NO_CA=true
    )
  fi

  kubectl create namespace "$MESH_NS" --dry-run=client -o yaml | kubectl apply -f -
  helm upgrade --install "$RELEASE" "$CHART_DIR" \
    --kube-context "$KUBE_CONTEXT" \
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
    --set-string "controlPlane.env.FERRUM_K8S_TRUST_DOMAIN=$TRUST_DOMAIN" \
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
    "${identity_args[@]}" \
    --set ambient.env.FERRUM_MESH_HBONE_LISTEN_ADDR=0.0.0.0:15008 \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set-string "nodeAgent.admin.port=$NODE_AGENT_ADMIN_PORT" \
    --set nodeAgent.proxyMode=node_waypoint \
    --set nodeAgent.env.FERRUM_LOG_LEVEL=info \
    --set-string "nodeAgent.env.FERRUM_K8S_TRUST_DOMAIN=$TRUST_DOMAIN" \
    --set-string "nodeAgent.trustedKubeletProbeSourceIps=$trusted_probe_ips_helm" \
    --set-string "nodeAgent.podRegistryDir=$NODE_WAYPOINT_REGISTRY_DIR" \
    --set nodeAgent.fallbackMode=fail \
    --wait \
    --timeout 5m

  kubectl -n "$MESH_NS" rollout status deployment/ferrum-mesh-control-plane --timeout=5m
  kubectl -n "$MESH_NS" rollout status daemonset/ferrum-mesh-node-agent --timeout=5m
  kubectl -n "$MESH_NS" rollout status daemonset/ferrum-mesh-ambient --timeout=5m
}

verify_ambient_spire_identity() {
  if [[ "$SPIRE_PRODUCTION" != "true" ]]; then
    return
  fi

  log "checking ambient NodeWaypoint Workload API SVIDs"
  local spec_file="$RESULTS_DIR/ambient-spire-pods.json"
  mkdir -p "$RESULTS_DIR/ambient-spire-metrics"
  kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    -o json > "$spec_file"

  python3 - "$spec_file" "$TRUST_DOMAIN" "$MESH_NS" <<'PY'
import json
import sys

path, trust_domain, mesh_ns = sys.argv[1:4]
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)

items = data.get("items") or []
if not items:
    raise SystemExit("no ferrum-mesh-ambient pods found")

errors = []
for pod in items:
    name = pod["metadata"]["name"]
    node = pod["spec"].get("nodeName")
    containers = pod["spec"].get("containers") or []
    ferrum = next((c for c in containers if c.get("name") == "ferrum-edge"), None)
    if ferrum is None:
        errors.append(f"{name}: missing ferrum-edge container")
        continue

    env = {item["name"]: item for item in ferrum.get("env") or []}
    expected_spiffe_template = f"spiffe://{trust_domain}/ns/{mesh_ns}/sa/ferrum-mesh/node/$(FERRUM_K8S_NODE_NAME)"
    expected_values = {
        "FERRUM_MESH_CA_BACKEND": "spire_agent",
        "FERRUM_MESH_SPIRE_AGENT_SOCKET": "/run/spire/sockets/agent.sock",
        "FERRUM_MESH_WORKLOAD_SPIFFE_ID": expected_spiffe_template,
        "FERRUM_MESH_PRODUCTION_MODE": "true",
    }
    for key, expected in expected_values.items():
        actual = env.get(key, {}).get("value")
        if actual != expected:
            errors.append(f"{name}: {key}={actual!r}, expected {expected!r}")
    if "FERRUM_MESH_ALLOW_NO_CA" in env:
        errors.append(f"{name}: FERRUM_MESH_ALLOW_NO_CA must not be present in SPIRE mode")
    node_env = env.get("FERRUM_K8S_NODE_NAME", {})
    field_path = ((node_env.get("valueFrom") or {}).get("fieldRef") or {}).get("fieldPath")
    if field_path != "spec.nodeName":
        errors.append(f"{name}: FERRUM_K8S_NODE_NAME fieldPath={field_path!r}, expected spec.nodeName")

    mounts = ferrum.get("volumeMounts") or []
    if not any(
        mount.get("name") == "spire-agent-socket"
        and mount.get("mountPath") == "/run/spire/sockets"
        and mount.get("readOnly") is True
        for mount in mounts
    ):
        errors.append(f"{name}: missing read-only spire-agent-socket mount")

    volumes = pod["spec"].get("volumes") or []
    if not any(
        volume.get("name") == "spire-agent-socket"
        and (volume.get("hostPath") or {}).get("path") == "/run/spire/sockets"
        for volume in volumes
    ):
        errors.append(f"{name}: missing /run/spire/sockets hostPath volume")

if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
PY

  local -a pod_records
  mapfile -t pod_records < <(kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.nodeName}{"\n"}{end}')
  local idx=0 pod node expected_spiffe metrics_file pf_log pf_pid fetched port
  for record in "${pod_records[@]}"; do
    IFS=$'\t' read -r pod node <<<"$record"
    [[ -n "$pod" && -n "$node" ]] || continue
    expected_spiffe="$(node_waypoint_spiffe_for_node "$node")"
    port=$((19400 + idx))
    idx=$((idx + 1))
    metrics_file="$RESULTS_DIR/ambient-spire-metrics/$pod.prom"
    pf_log="$RESULTS_DIR/ambient-spire-metrics/$pod-port-forward.log"
    kubectl -n "$MESH_NS" port-forward "pod/$pod" "$port:$AMBIENT_ADMIN_PORT" >"$pf_log" 2>&1 &
    pf_pid=$!
    fetched=false
    for _ in $(seq 1 40); do
      if curl -fsS "http://127.0.0.1:$port/metrics" >"$metrics_file"; then
        if grep -Fq "ferrum_mesh_cert_expiry_seconds{spiffe_id=\"$expected_spiffe\",source=\"workload_api\"}" "$metrics_file"; then
          fetched=true
          break
        fi
      fi
      sleep 0.5
    done
    kill "$pf_pid" 2>/dev/null || true
    wait "$pf_pid" 2>/dev/null || true
    if [[ "$fetched" != "true" ]]; then
      echo "ambient pod $pod on $node did not report SPIRE Agent SVID metric for $expected_spiffe" >&2
      cat "$metrics_file" >&2 || true
      collect_spire_diagnostics
      exit 1
    fi
  done

  record_live_assertion \
    node_waypoint.identity.workload_api_svid \
    pass \
    "" \
    "" \
    "ambient-nodewaypoints-loaded-per-node-workload-api-svids" \
    "" \
    "" \
    "ambient-spire-pods.json,ambient-spire-metrics"
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
  collect_spire_diagnostics
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
  awk -v ns="$WORKLOAD_NS" -v td="$TRUST_DOMAIN" -v require_dual="$REQUIRE_DUAL_STACK" '
    {
      gsub(/__NAMESPACE__/, ns)
      gsub(/__TRUST_DOMAIN__/, td)
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

  log "applying unmanaged direct-inbound probe workloads"
  kubectl create namespace "$UNMANAGED_NS" --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unmanaged-a
  namespace: $UNMANAGED_NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: unmanaged-a
  template:
    metadata:
      labels:
        app: unmanaged-a
    spec:
      nodeSelector:
        ferrum.io/live-node: a
      containers:
        - name: curl
          image: curlimages/curl:8.10.1
          command: ["sh", "-c", "sleep 365d"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unmanaged-b
  namespace: $UNMANAGED_NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: unmanaged-b
  template:
    metadata:
      labels:
        app: unmanaged-b
    spec:
      nodeSelector:
        ferrum.io/live-node: b
      containers:
        - name: curl
          image: curlimages/curl:8.10.1
          command: ["sh", "-c", "sleep 365d"]
EOF
  kubectl -n "$UNMANAGED_NS" rollout status deploy/unmanaged-a --timeout=3m
  kubectl -n "$UNMANAGED_NS" rollout status deploy/unmanaged-b --timeout=3m
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
    -o go-template='{{range .items}}{{- $name := .metadata.name -}}{{- if not .metadata.deletionTimestamp -}}{{- range .status.conditions -}}{{- if and (eq .type "Ready") (eq .status "True") -}}{{ $name }}{{"\n"}}{{- end -}}{{- end -}}{{- end -}}{{- end -}}' |
    head -n 1
}

pick_loopback_port() {
  python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

ambient_pods() {
  kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    -o go-template='{{range .items}}{{- $name := .metadata.name -}}{{- if not .metadata.deletionTimestamp -}}{{- range .status.conditions -}}{{- if and (eq .type "Ready") (eq .status "True") -}}{{ $name }}{{"\n"}}{{- end -}}{{- end -}}{{- end -}}{{- end -}}'
}

wait_for_port_forward_ready() {
  local pf_pid="$1"
  local pf_log="$2"
  local port="$3"
  for _ in $(seq 1 40); do
    if ! kill -0 "$pf_pid" 2>/dev/null; then
      echo "port-forward process exited before local port $port became ready" >&2
      cat "$pf_log" >&2 || true
      return 1
    fi
    if grep -q "Forwarding from .*:$port" "$pf_log" 2>/dev/null; then
      return
    fi
    sleep 0.25
  done
  echo "port-forward did not become ready on local port $port" >&2
  cat "$pf_log" >&2 || true
  return 1
}

stop_port_forward() {
  local pf_pid="$1"
  kill "$pf_pid" 2>/dev/null || true
  wait "$pf_pid" 2>/dev/null || true
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

ipv4_predecessor() {
  local ip="$1"
  python3 - "$ip" <<'PY'
import ipaddress
import sys

ip = ipaddress.IPv4Address(sys.argv[1])
if int(ip) == 0:
    raise SystemExit("0.0.0.0 has no predecessor")
print(ipaddress.IPv4Address(int(ip) - 1))
PY
}

kind_cni_network_dir_for_ip() {
  local node="$1"
  local ip="$2"
  if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
    docker exec "$node" sh -eu -c '
      ip="$1"
      cni_roots() {
        printf "%s\n" /run/cni-ipam-state /var/lib/cni/networks
        [ -d /etc/cni/net.d ] || return 0
        find /etc/cni/net.d -maxdepth 1 -type f \( -name "*.conf" -o -name "*.conflist" -o -name "*.json" \) -print 2>/dev/null |
          while IFS= read -r config; do
            sed -n "s/.*\"dataDir\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$config" 2>/dev/null || true
          done
      }
      path=""
      roots="$(cni_roots)"
      while IFS= read -r root; do
        [ -n "$root" ] || continue
        [ -d "$root" ] || continue
        candidate="$(find "$root" -mindepth 2 -maxdepth 2 -type f -name "$ip" -print -quit 2>/dev/null || true)"
        if [ -n "$candidate" ]; then
          path="$candidate"
          break
        fi
      done <<EOF
$roots
EOF
      [ -n "$path" ] || exit 1
      dirname "$path"
    ' sh "$ip"
  else
    kubectl debug "node/$node" -n default --image=busybox:1.36 --quiet -- \
      chroot /host sh -eu -c '
        ip="$1"
        cni_roots() {
          printf "%s\n" /run/cni-ipam-state /var/lib/cni/networks
          [ -d /etc/cni/net.d ] || return 0
          find /etc/cni/net.d -maxdepth 1 -type f \( -name "*.conf" -o -name "*.conflist" -o -name "*.json" \) -print 2>/dev/null |
            while IFS= read -r config; do
              sed -n "s/.*\"dataDir\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$config" 2>/dev/null || true
            done
        }
        path=""
        roots="$(cni_roots)"
        while IFS= read -r root; do
          [ -n "$root" ] || continue
          [ -d "$root" ] || continue
          candidate="$(find "$root" -mindepth 2 -maxdepth 2 -type f -name "$ip" -print -quit 2>/dev/null || true)"
          if [ -n "$candidate" ]; then
            path="$candidate"
            break
          fi
        done <<EOF
$roots
EOF
        [ -n "$path" ] || exit 1
        dirname "$path"
      ' sh "$ip"
  fi
}

force_next_kind_ipv4_pod_ip_reuse() {
  local node="$1"
  local cni_network_dir="$2"
  local ip="$3"
  local predecessor
  predecessor="$(ipv4_predecessor "$ip")"
  mkdir -p "$RESULTS_DIR/cni-ip-reuse"
  local out="$RESULTS_DIR/cni-ip-reuse/$node.txt"
  # The CI profile is disposable kind with host-local CNI. Resetting
  # last_reserved_ip to the predecessor makes the next pod allocation reuse
  # this IPv4 address while preserving the real CNI allocation path.
  if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
    docker exec "$node" sh -eu -c '
      dir="$1"
      ip="$2"
      predecessor="$3"
      [ -d "$dir" ] || {
        echo "missing CNI host-local network directory $dir" >&2
        exit 1
      }
      [ ! -e "$dir/$ip" ] || {
        echo "CNI lease $dir/$ip still exists; refusing to force reuse" >&2
        exit 1
      }
      cursor_files="$(
        find "$dir" -maxdepth 1 -type f \( -name last_reserved_ip -o -name "last_reserved_ip.*" \) -print |
          while IFS= read -r candidate; do
            current="$(cat "$candidate" 2>/dev/null || true)"
            printf "%s\n" "$current" | grep -q ":" && continue
            printf "%s\n" "$candidate"
          done
      )"
      [ -n "$cursor_files" ] || cursor_files="$dir/last_reserved_ip.0"
      printf "%s\n" "$cursor_files" |
        while IFS= read -r cursor; do
          [ -n "$cursor" ] || continue
          printf "%s\n" "$predecessor" >"$cursor"
        done
      printf "network_dir=%s\nforced_next_ip=%s\n" "$dir" "$ip"
      printf "%s\n" "$cursor_files" |
        while IFS= read -r cursor; do
          [ -n "$cursor" ] || continue
          printf "cursor_file=%s\ncursor_value=%s\n" "$cursor" "$(cat "$cursor")"
        done
    ' sh "$cni_network_dir" "$ip" "$predecessor" >"$out"
  else
    kubectl debug "node/$node" -n default --image=busybox:1.36 --quiet -- \
      chroot /host sh -eu -c '
        dir="$1"
        ip="$2"
        predecessor="$3"
        [ -d "$dir" ] || {
          echo "missing CNI host-local network directory $dir" >&2
          exit 1
        }
        [ ! -e "$dir/$ip" ] || {
          echo "CNI lease $dir/$ip still exists; refusing to force reuse" >&2
          exit 1
        }
        cursor_files="$(
          find "$dir" -maxdepth 1 -type f \( -name last_reserved_ip -o -name "last_reserved_ip.*" \) -print |
            while IFS= read -r candidate; do
              current="$(cat "$candidate" 2>/dev/null || true)"
              printf "%s\n" "$current" | grep -q ":" && continue
              printf "%s\n" "$candidate"
            done
        )"
        [ -n "$cursor_files" ] || cursor_files="$dir/last_reserved_ip.0"
        printf "%s\n" "$cursor_files" |
          while IFS= read -r cursor; do
            [ -n "$cursor" ] || continue
            printf "%s\n" "$predecessor" >"$cursor"
          done
        printf "network_dir=%s\nforced_next_ip=%s\n" "$dir" "$ip"
        printf "%s\n" "$cursor_files" |
          while IFS= read -r cursor; do
            [ -n "$cursor" ] || continue
            printf "cursor_file=%s\ncursor_value=%s\n" "$cursor" "$(cat "$cursor")"
          done
      ' sh "$cni_network_dir" "$ip" "$predecessor" >"$out"
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
    diagnostic_timeout "node waypoint runtime state for $node" \
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
    diagnostic_timeout "node waypoint runtime state for $node" \
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

  for attempt in $(seq 1 60); do
    local -a ambient_pods
    mapfile -t ambient_pods < <(ambient_pods)
    if [[ "${#ambient_pods[@]}" -lt 2 ]]; then
      sleep 2
      continue
    fi
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
  kubectl -n "$MESH_NS" get pods -o wide >&2 || true
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

curl_family_from_namespace() {
  local namespace="$1"
  local family="$2"
  local deploy="$3"
  local url="$4"
  if [[ -n "$family" ]]; then
    kubectl -n "$namespace" exec "deploy/$deploy" -- \
      sh -c 'curl "$1" -g -sS -m 8 -w "\n%{http_code}" "$2"' -- "$family" "$url"
  else
    kubectl -n "$namespace" exec "deploy/$deploy" -- \
      sh -c 'curl -g -sS -m 8 -w "\n%{http_code}" "$1"' -- "$url"
  fi
}

curl_family_from() {
  local family="$1"
  local deploy="$2"
  local url="$3"
  curl_family_from_namespace "$WORKLOAD_NS" "$family" "$deploy" "$url"
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
  curl_for_family_from_namespace "$WORKLOAD_NS" "$family" "$deploy" "$url"
}

curl_for_family_from_namespace() {
  local namespace="$1"
  local family="$2"
  local deploy="$3"
  local url="$4"
  case "$family" in
    4) curl_family_from_namespace "$namespace" "-4" "$deploy" "$url" ;;
    6) curl_family_from_namespace "$namespace" "-6" "$deploy" "$url" ;;
    "") curl_family_from_namespace "$namespace" "" "$deploy" "$url" ;;
    *)
      echo "unsupported curl address family '$family'" >&2
      exit 1
      ;;
  esac
}

try_wait_for_node_waypoint_admission() {
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
    return 1
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
  return 1
}

wait_for_node_waypoint_admission() {
  try_wait_for_node_waypoint_admission "$@" || exit 1
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

recorded_expect_blocked_unmanaged() {
  local assertion_id="$1"
  local namespace="$2"
  local from="$3"
  local destination="$4"
  local label="$5"
  local url="$6"
  local family="${7:-}"
  local outcome="${8:-unmanaged-direct-pod-ip-fail-closed}"
  if expect_blocked_from_namespace "$namespace" "$from" "$label" "$url" "$family"; then
    record_live_assertion \
      "$assertion_id" \
      pass \
      "$from" \
      "$destination" \
      "$outcome" \
      "none" \
      "$(spiffe_for_sa "$destination")"
  else
    record_live_assertion \
      "$assertion_id" \
      fail \
      "$from" \
      "$destination" \
      "unexpected-http-200" \
      "none" \
      "$(spiffe_for_sa "$destination")"
    return 1
  fi
}

expect_blocked() {
  local from="$1"
  local label="$2"
  local url="$3"
  local family="${4:-}"
  expect_blocked_from_namespace "$WORKLOAD_NS" "$from" "$label" "$url" "$family"
}

expect_blocked_from_namespace() {
  local namespace="$1"
  local from="$2"
  local label="$3"
  local url="$4"
  local family="${5:-}"
  local output code err
  err="$(mktemp)"
  set +e
  output="$(curl_for_family_from_namespace "$namespace" "$family" "$from" "$url" 2>"$err")"
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

hbone_probe_error_is_transport_rejection() {
  local err="$1"
  grep -Eiq 'SSL|TLS|alert|handshake|certificate|connection reset|empty reply|unexpected eof|Recv failure|server returned nothing|HTTP/0\.9|HTTP/2 stream .*PROTOCOL_ERROR' "$err"
}

hbone_probe_body_is_unauthenticated_policy_rejection() {
  local out="$1"
  local body expected
  [[ -f "$out" ]] || return 1
  body="$(cat "$out")"
  body="${body//$'\r'/}"
  body="${body#"${body%%[![:space:]]*}"}"
  body="${body%"${body##*[![:space:]]}"}"
  expected='{"error":"Mesh authorization denied: missing per-pod policy scope"}'
  [[ "$body" == "$expected" ]]
}

run_hbone_listener_negative_probe_for_pod() {
  local mode="$1"
  local ambient_pod="$2"
  local port pf_log pf_pid out err status code url
  port="$(pick_loopback_port)"
  mkdir -p "$RESULTS_DIR/hbone-negative"
  out="$RESULTS_DIR/hbone-negative/$mode-$ambient_pod.out"
  err="$RESULTS_DIR/hbone-negative/$mode-$ambient_pod.err"
  pf_log="$RESULTS_DIR/hbone-negative/$mode-$ambient_pod-port-forward.log"

  kubectl -n "$MESH_NS" port-forward "pod/$ambient_pod" "$port:15008" >"$pf_log" 2>&1 &
  pf_pid=$!
  if ! wait_for_port_forward_ready "$pf_pid" "$pf_log" "$port"; then
    stop_port_forward "$pf_pid"
    return 1
  fi

  set +e
  case "$mode" in
    plaintext)
      url="http://127.0.0.1:$port"
      code="$(curl -sS -m 8 -o "$out" -w "%{http_code}" -X CONNECT \
        --request-target "127.0.0.1:8080" \
        "$url" 2>"$err")"
      ;;
    unauthenticated)
      url="https://127.0.0.1:$port"
      code="$(curl -k --http2 -sS -m 8 -o "$out" -w "%{http_code}" -X CONNECT \
        --request-target "127.0.0.1:8080" \
        -H "baggage: source.principal=$(spiffe_for_sa src-a)" \
        "$url" 2>"$err")"
      ;;
    *)
      echo "unsupported HBONE negative probe mode '$mode'" >&2
      status=1
      code=""
      ;;
  esac
  status=$?
  set -e
  stop_port_forward "$pf_pid"

  if [[ "$status" -ne 0 && "${code:-000}" == "000" ]] && hbone_probe_error_is_transport_rejection "$err"; then
    return
  fi

  if [[ "$mode" == "unauthenticated" && "$status" -eq 0 && "$code" == "403" ]] && \
    hbone_probe_body_is_unauthenticated_policy_rejection "$out"; then
    return
  fi

  echo "expected $mode HBONE probe against $ambient_pod to fail at transport/client-auth/authz boundary, got curl status=$status HTTP ${code:-<none>}" >&2
  cat "$err" >&2 || true
  [[ -f "$out" ]] && cat "$out" >&2 || true
  return 1
}

run_hbone_listener_negative_check() {
  local assertion_id="$1"
  local mode="$2"
  local outcome="$3"
  local -a pods
  mapfile -t pods < <(ambient_pods)
  if [[ "${#pods[@]}" -lt 2 ]]; then
    echo "expected at least two ambient pods for HBONE listener negative check, found ${#pods[@]}" >&2
    kubectl -n "$MESH_NS" get pods -o wide >&2 || true
    record_live_assertion \
      "$assertion_id" \
      fail \
      unmanaged-a \
      dst-a \
      "missing-ambient-pods" \
      "none" \
      "$(spiffe_for_sa dst-a)" \
      "hbone-negative"
    return 1
  fi

  local pod
  for pod in "${pods[@]}"; do
    if ! run_hbone_listener_negative_probe_for_pod "$mode" "$pod"; then
      record_live_assertion \
        "$assertion_id" \
        fail \
        unmanaged-a \
        dst-a \
        "unexpected-$mode-hbone-admission-on-$pod" \
        "none" \
        "$(spiffe_for_sa dst-a)" \
        "hbone-negative"
      return 1
    fi
  done

  record_live_assertion \
    "$assertion_id" \
    pass \
    unmanaged-a \
    dst-a \
    "$outcome-all-ambient-pods" \
    "none" \
    "$(spiffe_for_sa dst-a)" \
    "hbone-negative"
}

run_plaintext_hbone_rejection_check() {
  run_hbone_listener_negative_check \
    node_waypoint.identity.plaintext_hbone_rejected \
    plaintext \
    plaintext-to-hbone-listener-rejected
}

run_unauthenticated_hbone_rejection_check() {
  run_hbone_listener_negative_check \
    node_waypoint.identity.unauthenticated_hbone_rejected \
    unauthenticated \
    no-client-svid-hbone-listener-rejected
}

fetch_policy_denies_for_node() {
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
  if ! wait_for_port_forward_ready "$pf_pid" "$pf_log" "$port"; then
    stop_port_forward "$pf_pid"
    return 1
  fi
  fetched=false
  for _ in $(seq 1 20); do
    if curl -fsS -H "Authorization: Bearer $token" \
      "http://127.0.0.1:$port/mesh/policy-denies/recent?window=30s&limit=100" >"$out" 2>"$out.curl"; then
      fetched=true
      break
    fi
    sleep 0.25
  done
  stop_port_forward "$pf_pid"
  [[ "$fetched" == "true" ]]
}

policy_deny_count_for_source_and_reasons() {
  local file="$1"
  local expected_source="$2"
  shift 2
  python3 - "$file" "$expected_source" "$@" <<'PY'
import json
import sys

path = sys.argv[1]
expected_source = sys.argv[2]
reasons = set(sys.argv[3:])
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)

count = 0
for group in data.get("grouped") or []:
    if group.get("reason") not in reasons:
        continue
    if expected_source and group.get("source") != expected_source:
        continue
    count += int(group.get("count") or 0)
print(count)
PY
}

forged_assertion_response_is_policy_rejection() {
  local code="$1"
  local body="$2"
  body="${body//$'\r'/}"
  body="${body#"${body%%[![:space:]]*}"}"
  body="${body%"${body##*[![:space:]]}"}"

  if [[ "$code" == "403" ]]; then
    return
  fi

  if [[ "$code" == "502" && "$body" == \{\"error\":\"HBONE\ backend\ unavailable:\ HBONE\ CONNECT\ rejected\ for\ *\ with\ status\ 403\"\} ]]; then
    return
  fi

  return 1
}

expect_attributed_forged_assertion_blocked() {
  local from="$1"
  local destination="$2"
  local url="$3"
  local family="${4:-4}"
  local from_record from_uid from_node from_pod destination_record dst_uid dst_node dst_pod expected_assertor
  local out_dir before_file after_file output code body err status before_count after_count
  from_record="$(workload_pod_record_for_app "$from")"
  IFS=$'\t' read -r from_uid from_node from_pod <<<"$from_record"
  destination_record="$(workload_pod_record_for_app "$destination")"
  IFS=$'\t' read -r dst_uid dst_node dst_pod <<<"$destination_record"
  if [[ -z "${from_node:-}" || -z "${dst_node:-}" ]]; then
    echo "could not resolve source/destination nodes for forged assertion check" >&2
    kubectl -n "$WORKLOAD_NS" get pods -o wide >&2 || true
    return 1
  fi
  expected_assertor="$(node_waypoint_spiffe_for_node "$from_node")"
  out_dir="$RESULTS_DIR/hbone-negative/forged-assertion-deny"
  mkdir -p "$out_dir"
  before_file="$out_dir/before.json"
  after_file="$out_dir/after.json"
  err="$out_dir/curl.err"

  if ! fetch_policy_denies_for_node "$dst_node" "$before_file"; then
    echo "could not fetch baseline policy-deny counts from destination node $dst_node" >&2
    return 1
  fi
  before_count="$(policy_deny_count_for_source_and_reasons "$before_file" "$expected_assertor" scope_missing untrusted_assertor)"

  set +e
  output="$(curl_for_family_from "$family" "$from" "$url" 2>"$err")"
  status=$?
  set -e
  code="${output##*$'\n'}"
  body="${output%$'\n'*}"
  printf '%s\n' "$output" >"$out_dir/curl.out"
  printf '%s\n' "$status" >"$out_dir/curl.status"
  if [[ "$status" -ne 0 ]] || ! forged_assertion_response_is_policy_rejection "$code" "$body"; then
    echo "expected forged assertion request to fail via destination HBONE policy rejection, got curl status=$status HTTP ${code:-<none>} body '${body:-<empty>}'" >&2
    cat "$err" >&2 || true
    return 1
  fi

  for _ in $(seq 1 20); do
    if fetch_policy_denies_for_node "$dst_node" "$after_file"; then
      after_count="$(policy_deny_count_for_source_and_reasons "$after_file" "$expected_assertor" scope_missing untrusted_assertor)"
      if [[ "$after_count" =~ ^[0-9]+$ && "$before_count" =~ ^[0-9]+$ && "$after_count" -gt "$before_count" ]]; then
        return
      fi
    fi
    sleep 0.5
  done

  echo "expected destination policy-deny recorder to add scope_missing/untrusted_assertor for $expected_assertor; before=$before_count after=${after_count:-<unread>}" >&2
  cat "$after_file" >&2 || true
  return 1
}

rollout_ambient_after_assertor_change() {
  kubectl -n "$MESH_NS" rollout status daemonset/ferrum-mesh-ambient --timeout=5m || return 1
  wait_for_node_waypoint_ready_markers || return 1
  wait_for_ambient_mesh_slice || return 1
}

restore_default_hbone_assertors() {
  kubectl -n "$MESH_NS" set env daemonset/ferrum-mesh-ambient FERRUM_MESH_TRUSTED_HBONE_ASSERTORS- >/dev/null || return 1
  rollout_ambient_after_assertor_change
}

run_forged_assertion_rejection_check() {
  local bad_assertor blocked_ok=0 restored_ok=0 recovery_ok=0
  bad_assertor="spiffe://$TRUST_DOMAIN/ns/$MESH_NS/sa/not-a-node-waypoint"
  mkdir -p "$RESULTS_DIR/hbone-negative"
  log "checking authenticated HBONE baggage is rejected from an untrusted assertor"

  if kubectl -n "$MESH_NS" set env daemonset/ferrum-mesh-ambient \
    "FERRUM_MESH_TRUSTED_HBONE_ASSERTORS=$bad_assertor" >/dev/null; then
    if rollout_ambient_after_assertor_change; then
      if expect_attributed_forged_assertion_blocked \
        src-a \
        dst-a \
        "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" \
        4; then
        blocked_ok=0
      else
        blocked_ok=$?
      fi
    else
      blocked_ok=$?
    fi
  else
    blocked_ok=$?
  fi

  if restore_default_hbone_assertors; then
    restored_ok=0
  else
    restored_ok=$?
  fi
  if [[ "$restored_ok" -eq 0 ]]; then
    if expect_allowed src-a \
      "restored trusted HBONE assertors" \
      "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" \
      "ok-a" \
      4; then
      recovery_ok=0
    else
      recovery_ok=$?
    fi
  fi

  if [[ "$blocked_ok" -eq 0 && "$restored_ok" -eq 0 && "$recovery_ok" -eq 0 ]]; then
    record_live_assertion \
      node_waypoint.identity.forged_assertion_rejected \
      pass \
      src-a \
      dst-a \
      "authenticated-hbone-baggage-from-untrusted-assertor-fail-closed-and-recovers" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    return
  fi

  record_live_assertion \
    node_waypoint.identity.forged_assertion_rejected \
    fail \
    src-a \
    dst-a \
    "bad-assertor-blocked=$blocked_ok restore=$restored_ok recovery=$recovery_ok" \
    "$(spiffe_for_sa src-a)" \
    "$(spiffe_for_sa dst-a)"
  collect_traffic_failure_diagnostics
  return 1
}

run_hbone_identity_negative_checks() {
  if [[ "$SPIRE_PRODUCTION" != "true" ]]; then
    return
  fi

  log "running HBONE identity negative checks"
  run_plaintext_hbone_rejection_check
  run_unauthenticated_hbone_rejection_check
  run_forged_assertion_rejection_check
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

  recorded_expect_blocked_unmanaged \
    node_waypoint.ipv4.direct_inbound_guard_same_node \
    "$UNMANAGED_NS" \
    unmanaged-a \
    dst-a \
    "same-node unmanaged direct Pod IP inbound guard" \
    "http://$dst_a_ip:8080/" \
    4
  recorded_expect_blocked_unmanaged \
    node_waypoint.ipv4.direct_inbound_guard_cross_node \
    "$UNMANAGED_NS" \
    unmanaged-b \
    dst-a \
    "cross-node unmanaged direct Pod IP inbound guard" \
    "http://$dst_a_ip:8080/" \
    4

  run_hbone_identity_negative_checks

  if [[ "$STALE_IP_REUSE_HOST_LOCAL_PROFILE" != "true" ]]; then
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
    return
  fi

  log "checking stale identity cleanup across forced source workload IPv4 reuse"
  local old_src_a_uid old_src_a_node old_src_a_pod old_src_a_ip old_src_a_cni_dir
  local new_src_a_uid new_src_a_ip src_a_reuse_identities_file
  IFS=$'\t' read -r old_src_a_uid old_src_a_node old_src_a_pod < <(workload_pod_record_for_app src-a)
  old_src_a_ip="$(pod_ip src-a)"
  if [[ -z "$old_src_a_uid" || -z "$old_src_a_node" || -z "$old_src_a_pod" || -z "$old_src_a_ip" ]]; then
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "could-not-resolve-original-source-pod-for-ip-reuse" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    return 1
  fi
  if [[ "$old_src_a_ip" == *:* ]]; then
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "source-pod-primary-ip-is-not-ipv4-$old_src_a_ip" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    return 1
  fi
  if ! old_src_a_cni_dir="$(kind_cni_network_dir_for_ip "$old_src_a_node" "$old_src_a_ip")"; then
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "could-not-find-kind-cni-lease-for-$old_src_a_ip" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    collect_traffic_failure_diagnostics
    return 1
  fi
  kubectl -n "$WORKLOAD_NS" scale deploy/src-a --replicas=0
  if kubectl -n "$WORKLOAD_NS" get "pod/$old_src_a_pod" >/dev/null 2>&1; then
    if ! kubectl -n "$WORKLOAD_NS" wait --for=delete "pod/$old_src_a_pod" --timeout=3m; then
      record_live_assertion \
        node_waypoint.identity.stale_ip_reuse \
        fail \
        src-a \
        dst-a \
        "source-pod-delete-timeout-before-ip-reuse" \
        "$(spiffe_for_sa src-a)" \
        "$(spiffe_for_sa dst-a)"
      collect_traffic_failure_diagnostics
      return 1
    fi
  fi
  wait_for_node_waypoint_marker_removed "$old_src_a_node" "$old_src_a_uid"
  if ! force_next_kind_ipv4_pod_ip_reuse "$old_src_a_node" "$old_src_a_cni_dir" "$old_src_a_ip"; then
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "could-not-force-kind-cni-reuse-for-$old_src_a_ip" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)" \
      "cni-ip-reuse"
    collect_traffic_failure_diagnostics
    return 1
  fi
  kubectl -n "$WORKLOAD_NS" scale deploy/src-a --replicas=1
  kubectl -n "$WORKLOAD_NS" rollout status deploy/src-a --timeout=3m
  wait_for_node_waypoint_ready_markers
  wait_for_ambient_mesh_slice
  new_src_a_uid="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].metadata.uid}')"
  new_src_a_ip="$(pod_ip src-a)"
  if [[ "$new_src_a_uid" == "$old_src_a_uid" || "$new_src_a_ip" != "$old_src_a_ip" ]]; then
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "expected-new-uid-with-reused-ip-$old_src_a_ip-got-uid-$new_src_a_uid-ip-$new_src_a_ip" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)" \
      "cni-ip-reuse"
    collect_traffic_failure_diagnostics
    return 1
  fi
  if ! try_wait_for_node_waypoint_admission src-a "recreated src-a Service path" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" 4; then
    record_live_assertion \
      node_waypoint.identity.stale_cleanup \
      fail \
      src-a \
      dst-a \
      "recreated-source-not-admitted" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "reused-ip-replacement-source-not-admitted" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)" \
      "cni-ip-reuse"
    return 1
  fi
  src_a_reuse_identities_file="$RESULTS_DIR/ambient-node-waypoint-admission/src-a-$new_src_a_uid.json"
  if [[ ! -f "$src_a_reuse_identities_file" ]] ||
    node_waypoint_identities_include_uid "$src_a_reuse_identities_file" "$old_src_a_uid"; then
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "reused-ip-identity-snapshot-still-contained-old-uid-$old_src_a_uid" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)" \
      "cni-ip-reuse"
    collect_traffic_failure_diagnostics
    return 1
  fi
  if ! try_wait_for_node_waypoint_admission src-b "post-recreation src-b Service path" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" 4; then
    record_live_assertion \
      node_waypoint.identity.stale_cleanup \
      fail \
      src-b \
      dst-a \
      "post-recreation-source-not-admitted" \
      "$(spiffe_for_sa src-b)" \
      "$(spiffe_for_sa dst-a)"
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-b \
      dst-a \
      "post-recreation-source-not-admitted-after-reused-ip" \
      "$(spiffe_for_sa src-b)" \
      "$(spiffe_for_sa dst-a)" \
      "cni-ip-reuse"
    return 1
  fi
  if ! expect_allowed src-a "recreated source identity" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" "ok-a" 4; then
    record_live_assertion \
      node_waypoint.identity.stale_cleanup \
      fail \
      src-a \
      dst-a \
      "recreated-source-not-admitted" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "reused-ip-replacement-traffic-not-allowed" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)" \
      "cni-ip-reuse"
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
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-b \
      dst-a \
      "post-recreation-deny-regressed-after-reused-ip" \
      "$(spiffe_for_sa src-b)" \
      "$(spiffe_for_sa dst-a)" \
      "cni-ip-reuse"
    return 1
  fi
  record_live_assertion \
    node_waypoint.identity.stale_ip_reuse \
    pass \
    src-a \
    dst-a \
    "source-workload-recreated-with-new-uid-reused-ip-$old_src_a_ip-old-uid-absent-and-traffic-verified" \
    "$(spiffe_for_sa src-a)" \
    "$(spiffe_for_sa dst-a)" \
    "cni-ip-reuse"
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
      node_waypoint.ipv6.direct_inbound_guard \
      skip \
      unmanaged-b \
      dst-a \
      "cluster-not-dual-stack" \
      "none" \
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
  recorded_expect_blocked_unmanaged \
    node_waypoint.ipv6.direct_inbound_guard \
    "$UNMANAGED_NS" \
    unmanaged-b \
    dst-a \
    "IPv6 unmanaged direct Pod IP inbound guard" \
    "http://[$dst_a_v6]:8080/" \
    6 \
    "unmanaged-direct-ipv6-pod-ip-fail-closed"
}

cleanup() {
  if [[ "${FERRUM_LIVE_KEEP_RESOURCES:-false}" != "true" ]]; then
    kubectl --context "$KUBE_CONTEXT" delete namespace "$UNMANAGED_NS" --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl --context "$KUBE_CONTEXT" delete namespace "$WORKLOAD_NS" --ignore-not-found=true >/dev/null 2>&1 || true
    helm uninstall "$RELEASE" -n "$MESH_NS" --kube-context "$KUBE_CONTEXT" >/dev/null 2>&1 || true
    if [[ "$SPIRE_PRODUCTION" == "true" ]]; then
      ferrum_spire_cleanup_minimal "$KUBE_CONTEXT" "$SPIRE_NS"
    fi
  fi
}

trap cleanup EXIT

select_kube_context
init_live_assertions
render_chart_assertions
validate_cluster
label_nodes
discover_trusted_kubelet_probe_ips
install_spire_production_identity
install_ferrum
verify_ambient_spire_identity
assert_node_agent_ready_metric
collect_bpf_evidence
apply_workloads
wait_for_node_waypoint_ready_markers
wait_for_ambient_mesh_slice
run_traffic_checks
run_ipv6_checks
ferrum_live_assertions_require_all_passed "$LIVE_ASSERTIONS_FILE" "${REQUIRED_LIVE_ASSERTIONS[@]}"

log "live NodeWaypoint eBPF datapath checks passed"
