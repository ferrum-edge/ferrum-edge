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
# Service port of the in-mesh `udp-echo` Service. The NodeWaypoint materializes
# its UDP listener on this exact port number in the host network namespace
# (issue #3286), so co-located pods reach it at <node IP>:<this port>. Kept out
# of the reserved mesh port range (15001/15006/15008/15011/15090/15443).
UDP_LISTENER_PORT="${FERRUM_LIVE_UDP_LISTENER_PORT:-15353}"
# `NODE_WAYPOINT_INBOUND_AUTH_MARK` (ferrum-ebpf-common). Public and fixed by
# design — the forgery probe sets it with `SO_MARK` precisely to prove that on
# its own, even beside a trusted node source or a published ClusterIP, it
# authorizes nothing (issues #3956, #3957).
NODE_WAYPOINT_INBOUND_AUTH_MARK="${FERRUM_LIVE_NODE_WAYPOINT_INBOUND_AUTH_MARK:-1844}"
# Service port of the in-mesh `dtls-echo` Service. Same `protocol: UDP` L4
# transport, but its `appProtocol: dtls` hint makes the NodeWaypoint TERMINATE
# frontend DTLS on the materialized listener and forward PLAINTEXT datagrams to
# the backing pod (issue #3286).
DTLS_LISTENER_PORT="${FERRUM_LIVE_DTLS_LISTENER_PORT:-15354}"
# Secret + mount for the DTLS server material the NodeWaypoint terminates with.
# The mesh data plane loads it from the DTLS-specific FERRUM_DTLS_CERT_PATH /
# FERRUM_DTLS_KEY_PATH (NOT FERRUM_FRONTEND_TLS_*, which is the inbound TCP
# listener's server identity and here is the SPIRE-issued NodeWaypoint SVID).
# Without it every `dtls` listener stays deferred as `FrontendDtlsDeferred` and
# never binds.
DTLS_SECRET_NAME="${FERRUM_LIVE_DTLS_SECRET:-ferrum-live-node-waypoint-dtls}"
DTLS_MOUNT_PATH=/etc/ferrum/dtls
# Same numeric port for two compatible plain-UDP Services with distinct
# ClusterIPs (issue #3861). Must not collide with udp-echo (15353) or
# dtls-echo (15354).
DEMUX_UDP_PORT="${FERRUM_LIVE_DEMUX_UDP_PORT:-15355}"
DTLS_CLIENT_SECRET_NAME="${FERRUM_LIVE_DTLS_CLIENT_SECRET:-ferrum-live-dtls-clients}"
DTLS_CLIENT_MOUNT_PATH=/etc/ferrum/dtls-clients
# openssl CLI image for the enrolled DTLS probe pods. Built on the runner and
# loaded into kind: those pods are mesh-captured, so they cannot `apk add`.
DTLS_CLIENT_IMAGE="${FERRUM_LIVE_DTLS_CLIENT_IMAGE:-ferrum-live-dtls-client:local}"
DTLS_CLIENT_DOCKERFILE="$ROOT_DIR/tests/k8s/node_waypoint_ebpf_live/dtls-client.Dockerfile"
RELEASE="${FERRUM_LIVE_RELEASE:-ferrum-live}"
IMAGE_REPOSITORY="${FERRUM_LIVE_IMAGE_REPOSITORY:-ferrumedge/ferrum-edge}"
# Default to the crate version so a release bump cannot desynchronise this lane
# from the tree it tests; CI overrides both with the live image tag it built.
FERRUM_TREE_VERSION="$(sed -nE '/^\[package\]$/,/^\[/{s/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p;}' "$ROOT_DIR/Cargo.toml")"
IMAGE_TAG="${FERRUM_LIVE_IMAGE_TAG:-$FERRUM_TREE_VERSION}"
DEFAULT_CHART_IMAGE_REPOSITORY="${FERRUM_LIVE_DEFAULT_IMAGE_REPOSITORY:-ferrumedge/ferrum-edge}"
# The chart's own appVersion is what an untouched install renders, so the
# expectation follows the chart rather than a literal that a release bump
# would silently break.
DEFAULT_CHART_IMAGE_TAG="${FERRUM_LIVE_DEFAULT_IMAGE_TAG:-$(sed -nE 's/^appVersion:[[:space:]]*"?([^"]+)"?[[:space:]]*$/\1/p' "$CHART_DIR/Chart.yaml")}"
BPFTOOL_IMAGE="${FERRUM_LIVE_BPFTOOL_IMAGE:-quay.io/cilium/cilium:v1.16.5}"
REQUIRE_DUAL_STACK="${FERRUM_LIVE_REQUIRE_DUAL_STACK:-false}"
DOCKER_NODE_EVIDENCE="${FERRUM_LIVE_DOCKER_NODE_EVIDENCE:-false}"
LIVE_TESTS_REQUIRED="${FERRUM_LIVE_TESTS_REQUIRED:-0}"
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
INGRESS_REDIRECT_IFACES=""
TOPOLOGY_ROUTE_MUTATED=false
TOPOLOGY_ROUTE_NODE=""
TOPOLOGY_ROUTE_STATE_FILE=""
REQUIRED_LIVE_ASSERTIONS=(
  node_waypoint.ebpf.chart_profile
  node_waypoint.ebpf.capture_ready
  node_waypoint.ebpf.ingress_topology_valid
  node_waypoint.ebpf.ingress_topology_wrong_interface_startup
  node_waypoint.ebpf.ingress_topology_route_drift
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
  node_waypoint.udp.listener_allow_attributed_source
  node_waypoint.udp.service_path_allow_attributed_source
  node_waypoint.udp.listener_deny_scoped_policy
  node_waypoint.udp.listener_deny_unattributed_source
  node_waypoint.udp.listener_deny_spoofed_source
  node_waypoint.udp.listener_deny_forged_relay_mark
  node_waypoint.udp.policy_change_denies_live
  node_waypoint.udp.policy_withdrawal_recovers_live
  node_waypoint.dtls.listener_bound
  node_waypoint.dtls.listener_allow_attributed_source
  node_waypoint.dtls.listener_deny_scoped_policy
  node_waypoint.dtls.service_path_allow_attributed_source
  node_waypoint.dtls.service_path_deny_scoped_policy
  node_waypoint.dtls.service_path_deny_unattributed_source
  node_waypoint.udp.same_port_demux_serves_a
  node_waypoint.udp.same_port_demux_serves_b
  node_waypoint.udp.same_port_demux_isolated
  node_waypoint.udp.same_port_demux_shared_client_tuple
  node_waypoint.udp.same_port_demux_retract_a_keeps_b
  node_waypoint.dtls.reload_permissive_to_strict
  node_waypoint.dtls.reload_current_ca_admitted
  node_waypoint.dtls.reload_stale_ca_rejected
  node_waypoint.dtls.reload_unauthenticated_rejected
  node_waypoint.dtls.operator_isolated_across_reload
)
if [[ "$STALE_IP_REUSE_HOST_LOCAL_PROFILE" == "true" ]]; then
  REQUIRED_LIVE_ASSERTIONS+=(
    node_waypoint.identity.stale_ip_reuse
  )
fi
if [[ "$REQUIRE_DUAL_STACK" == "true" ]]; then
  REQUIRED_LIVE_ASSERTIONS+=(
    node_waypoint.ebpf.registry_ready_ipv6
    node_waypoint.ebpf.ingress_topology_dual_family
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
    node_waypoint.identity.spire_restart_recovery
    node_waypoint.observability.hbone_handshake_inbound_tls_failure
    node_waypoint.observability.asserted_identity_rejected
    node_waypoint.observability.hbone_handshake_outbound_success
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

# Chart-managed metrics auth. Component env.FERRUM_METRICS_* is reserved;
# observability.enabled is required for the chart to render the env. Alerts,
# dashboards, and Prometheus Operator monitors stay off so kind/live clusters
# without those CRDs, and loopback admin binds, still render.
CHART_METRICS_HELM_ARGS=(
  --set observability.enabled=true
  --set observability.alerts.enabled=false
  --set observability.dashboards.enabled=false
  --set observability.metrics.serviceMonitor.enabled=false
  --set observability.metrics.podMonitor.enabled=false
  --set-string "observability.metrics.allowedCidrs=127.0.0.1/32"
)

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
# Mints the throwaway DTLS server material the NodeWaypoint `dtls` listener
# terminates with (issue #3286).
require_cmd openssl
if [[ -z "$KUBE_CONTEXT" ]]; then
  KUBE_CONTEXT="$(kubectl config current-context)"
fi
if [[ "$DOCKER_NODE_EVIDENCE" == "true" ]]; then
  require_cmd docker
elif [[ "$LIVE_TESTS_REQUIRED" == "1" ]]; then
  echo "FERRUM_LIVE_TESTS_REQUIRED=1 requires Docker node access for ingress-topology validation" >&2
  exit 1
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
  if grep -q "image: \"$IMAGE_REPOSITORY:$IMAGE_TAG-ebpf-tools\"" <<<"$rendered"; then
    echo "TCP-only NodeWaypoint unexpectedly selected the tools-capable -ebpf-tools image" >&2
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
    --set-string "ambient.env.FERRUM_ADMIN_HTTP_PORT=$AMBIENT_ADMIN_PORT" \
    --set ambient.env.FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED=true \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set nodeAgent.proxyMode=node_waypoint \
    --set-string "nodeAgent.admin.port=$NODE_AGENT_ADMIN_PORT" \
    --set-string "nodeAgent.podRegistryDir=$NODE_WAYPOINT_REGISTRY_DIR")"
  local udp_tools_count udp_ebpf_exact
  udp_tools_count="$(grep -c "image: \"$IMAGE_REPOSITORY:$IMAGE_TAG-ebpf-tools\"" <<<"$rendered" || true)"
  udp_ebpf_exact="$(grep -E "image: \"$IMAGE_REPOSITORY:$IMAGE_TAG-ebpf\"[[:space:]]*$" <<<"$rendered" | grep -c . || true)"
  if [[ "$udp_tools_count" -ne 1 ]]; then
    echo "NodeWaypoint UDP listeners did not select exactly one -ebpf-tools ambient image" >&2
    grep -n 'image:' <<<"$rendered" >&2 || true
    exit 1
  fi
  if [[ "$udp_ebpf_exact" -lt 1 ]]; then
    echo "NodeWaypoint UDP listeners did not keep the distroless -ebpf node-agent image" >&2
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
  local ambient_ds node_agent_ds
  ambient_ds="$(awk '
    /name: ferrum-mesh-ambient/ { in_ambient = 1 }
    in_ambient { print }
    /name: ferrum-mesh-node-agent/ && in_ambient { exit }
  ' <<<"$rendered")"
  node_agent_ds="$(awk '
    /name: ferrum-mesh-node-agent/ { in_agent = 1 }
    in_agent { print }
  ' <<<"$rendered")"
  for cap in BPF PERFMON SYS_ADMIN; do
    if ! grep -q -- "- ${cap}" <<<"$ambient_ds" || ! grep -q -- "- ${cap}" <<<"$node_agent_ds"; then
      echo "NodeWaypoint eBPF render did not grant ${cap} to both proxy and node-agent" >&2
      grep -nE "kind: DaemonSet|name: ferrum-mesh-(ambient|node-agent)|capabilities:|add:|- ${cap}" <<<"$rendered" >&2 || true
      exit 1
    fi
    if grep -q -- "- \"${cap}\"" <<<"$rendered"; then
      echo "NodeWaypoint eBPF render quoted ${cap}; live greps require the unquoted datapath form" >&2
      grep -nE "capabilities:|add:|- ${cap}" <<<"$rendered" >&2 || true
      exit 1
    fi
  done
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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
    "${CHART_METRICS_HELM_ARGS[@]}" \
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

topology_targets_for_node() {
  local local_node="$1"
  local remote_filter="${2:-}"
  kubectl get nodes -o json | python3 -c '
import ipaddress
import json
import sys

local_node = sys.argv[1]
require_v6 = sys.argv[2] == "true"
remote_filter = sys.argv[3]
data = json.load(sys.stdin)
for node in data.get("items") or []:
    name = (node.get("metadata") or {}).get("name")
    if name == local_node or (remote_filter and name != remote_filter):
        continue
    spec = node.get("spec") or {}
    cidrs = spec.get("podCIDRs") or ([spec["podCIDR"]] if spec.get("podCIDR") else [])
    if not cidrs:
        raise SystemExit("remote Node has no PodCIDR evidence")
    for raw in cidrs:
        network = ipaddress.ip_network(raw, strict=False)
        if network.version == 6 and not require_v6:
            continue
        target = next(network.hosts(), network.network_address)
        print(f"cidr|{network.version}|{network}|{target}")
    addresses = (node.get("status") or {}).get("addresses") or []
    seen = False
    for item in addresses:
        if item.get("type") != "InternalIP":
            continue
        address = ipaddress.ip_address(item.get("address", ""))
        if address.version == 6 and not require_v6:
            continue
        seen = True
        prefix = 32 if address.version == 4 else 128
        print(f"address|{address.version}|{address}/{prefix}|{address}")
    if not seen:
        raise SystemExit("remote Ready Node has no usable InternalIP evidence")
' "$local_node" "$REQUIRE_DUAL_STACK" "$remote_filter"
}

discover_ingress_redirect_ifaces() {
  if [[ "$DOCKER_NODE_EVIDENCE" != "true" ]]; then
    if [[ "$LIVE_TESTS_REQUIRED" == "1" ]]; then
      echo "live ingress topology requires Docker access to the kind node route tables" >&2
      exit 1
    fi
    return
  fi
  log "deriving the explicit ingress redirect interface set for the live kind topology"
  local common_set="" node version target route_output iface node_set
  for node in "$NODE_A" "$NODE_B"; do
    local -a discovered=()
    while IFS='|' read -r _kind version _prefix target; do
      [[ -n "$target" ]] || continue
      if [[ "$version" == "6" ]]; then
        route_output="$(docker exec "$node" ip -6 route get "$target")"
      else
        route_output="$(docker exec "$node" ip -4 route get "$target")"
      fi
      iface="$(awk '{for (i=1;i<=NF;i++) if ($i == "dev") {print $(i+1); exit}}' <<<"$route_output")"
      if [[ -z "$iface" ]]; then
        echo "could not resolve a route device on $node for a required family-$version topology target" >&2
        exit 1
      fi
      discovered+=("$iface")
    done < <(topology_targets_for_node "$node")
    node_set="$(printf '%s\n' "${discovered[@]}" | sort -u | paste -sd, -)"
    if [[ -z "$node_set" ]]; then
      echo "no ingress redirect interface could be proved for $node" >&2
      exit 1
    fi
    if [[ -z "$common_set" ]]; then
      common_set="$node_set"
    elif [[ "$common_set" != "$node_set" ]]; then
      echo "the chart's shared ingressRedirectIfaces value cannot represent differing node sets ($common_set vs $node_set)" >&2
      exit 1
    fi
  done
  INGRESS_REDIRECT_IFACES="$common_set"
  log "explicit ingress redirect interface set: $INGRESS_REDIRECT_IFACES"
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

# Mint the DTLS server certificate the NodeWaypoint's `dtls` listener terminates
# with, and publish it as a TLS Secret mounted into the ambient DaemonSet.
#
# Deliberately a throwaway self-signed P-256 leaf minted per run: Ferrum's DTLS
# admission accepts only ECDSA P-256/P-384 server leaves, and using an RSA leaf
# here would leave the listener deferred before the datapath under test exists.
# The property under test is the DTLS datapath and scoped source authorization,
# not PKI trust, and the live client does not verify the server certificate. No
# key material leaves the cluster or the run's temp dir, and nothing is echoed
# to the log.
create_dtls_listener_secret() {
  log "minting the NodeWaypoint frontend DTLS material and client CAs"
  local dir
  dir="$(mktemp -d)"
  if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=ferrum-node-waypoint-dtls" \
    -keyout "$dir/tls.key" -out "$dir/tls.crt" >/dev/null 2>&1; then
    rm -rf "$dir"
    echo "could not mint the NodeWaypoint frontend DTLS listener certificate" >&2
    exit 1
  fi
  if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=ferrum-live-dtls-current-ca" \
    -keyout "$dir/current-ca.key" -out "$dir/ca.crt" >/dev/null 2>&1; then
    rm -rf "$dir"
    echo "could not mint the current DTLS client CA" >&2
    exit 1
  fi
  if ! openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=ferrum-live-dtls-current-client" \
    -keyout "$dir/current.key" -out "$dir/current.csr" >/dev/null 2>&1; then
    rm -rf "$dir"
    echo "could not mint the current DTLS client key" >&2
    exit 1
  fi
  printf '%s\n' 'basicConstraints=CA:FALSE' 'keyUsage=digitalSignature' \
    'extendedKeyUsage=clientAuth' >"$dir/client.ext"
  if ! openssl x509 -req -in "$dir/current.csr" -CA "$dir/ca.crt" \
    -CAkey "$dir/current-ca.key" -CAcreateserial -days 2 \
    -out "$dir/current.crt" -extfile "$dir/client.ext" >/dev/null 2>&1; then
    rm -rf "$dir"
    echo "could not sign the current DTLS client certificate" >&2
    exit 1
  fi
  if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=ferrum-live-dtls-stale-ca" \
    -keyout "$dir/stale-ca.key" -out "$dir/stale-ca.crt" >/dev/null 2>&1; then
    rm -rf "$dir"
    echo "could not mint the stale DTLS client CA" >&2
    exit 1
  fi
  if ! openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=ferrum-live-dtls-stale-client" \
    -keyout "$dir/stale.key" -out "$dir/stale.csr" >/dev/null 2>&1; then
    rm -rf "$dir"
    echo "could not mint the stale DTLS client key" >&2
    exit 1
  fi
  if ! openssl x509 -req -in "$dir/stale.csr" -CA "$dir/stale-ca.crt" \
    -CAkey "$dir/stale-ca.key" -CAcreateserial -days 2 \
    -out "$dir/stale.crt" -extfile "$dir/client.ext" >/dev/null 2>&1; then
    rm -rf "$dir"
    echo "could not sign the stale DTLS client certificate" >&2
    exit 1
  fi
  kubectl create namespace "$MESH_NS" --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "$MESH_NS" create secret generic "$DTLS_SECRET_NAME" \
    --from-file=tls.crt="$dir/tls.crt" \
    --from-file=tls.key="$dir/tls.key" \
    --from-file=ca.crt="$dir/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f -
  kubectl create namespace "$WORKLOAD_NS" --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "$WORKLOAD_NS" create secret generic "$DTLS_CLIENT_SECRET_NAME" \
    --from-file=current.crt="$dir/current.crt" \
    --from-file=current.key="$dir/current.key" \
    --from-file=stale.crt="$dir/stale.crt" \
    --from-file=stale.key="$dir/stale.key" \
    --dry-run=client -o yaml | kubectl apply -f -
  rm -rf "$dir"
}

install_ferrum() {
  log "installing Ferrum chart"
  create_dtls_listener_secret
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
    --set-string "controlPlane.env.FERRUM_NAMESPACE=$WORKLOAD_NS" \
    --set controlPlane.env.FERRUM_LOG_LEVEL=info \
    --set controlPlane.env.FERRUM_K8S_CONTROLLER_ENABLED=true \
    --set controlPlane.env.FERRUM_K8S_POD_DISCOVERY_ENABLED=true \
    --set-string "controlPlane.env.FERRUM_K8S_TRUST_DOMAIN=$TRUST_DOMAIN" \
    --set controlPlane.env.FERRUM_K8S_WATCH_GATEWAY_API_CRDS=false \
    --set controlPlane.env.FERRUM_K8S_WATCH_ISTIO_CRDS=true \
    --set controlPlane.env.FERRUM_K8S_WATCH_MESH_CONFIG=false \
    --set controlPlane.env.FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true \
    --set ambient.enabled=true \
    --set ambient.captureMode=ebpf \
    --set ambient.env.FERRUM_MODE=mesh \
    --set ambient.env.FERRUM_MESH_TOPOLOGY=node_waypoint \
    "${CHART_METRICS_HELM_ARGS[@]}" \
    --set-string "ambient.env.FERRUM_DP_CP_GRPC_URLS=http://ferrum-mesh-control-plane.$MESH_NS.svc.cluster.local:50051" \
    --set ambient.env.FERRUM_CP_DP_GRPC_JWT_SECRET=ferrum-edge-node-waypoint-live-grpc-secret \
    --set-string "ambient.env.FERRUM_NAMESPACE=$WORKLOAD_NS" \
    --set-string "ambient.env.FERRUM_ADMIN_HTTP_PORT=$AMBIENT_ADMIN_PORT" \
    --set-string "ambient.env.FERRUM_ADMIN_JWT_SECRET=$ADMIN_JWT_SECRET" \
    --set-string "ambient.env.FERRUM_ADMIN_JWT_ISSUER=$ADMIN_JWT_ISSUER" \
    --set ambient.env.FERRUM_LOG_LEVEL=info \
    "${identity_args[@]}" \
    --set ambient.env.FERRUM_MESH_HBONE_LISTEN_ADDR=0.0.0.0:15008 \
    --set-string 'ambient.env.FERRUM_MESH_INBOUND_LISTEN_ADDR=[::]:15006' \
    --set ambient.env.FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED=true \
    --set ambient.env.FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true \
    --set-string "ambient.env.FERRUM_DTLS_CERT_PATH=$DTLS_MOUNT_PATH/tls.crt" \
    --set-string "ambient.env.FERRUM_DTLS_KEY_PATH=$DTLS_MOUNT_PATH/tls.key" \
    --set-string "ambient.env.FERRUM_DTLS_CLIENT_CA_CERT_PATH=$DTLS_MOUNT_PATH/ca.crt" \
    --set-json "ambient.extraVolumes=[{\"name\":\"node-waypoint-dtls\",\"secret\":{\"secretName\":\"$DTLS_SECRET_NAME\"}}]" \
    --set-json "ambient.extraVolumeMounts=[{\"name\":\"node-waypoint-dtls\",\"mountPath\":\"$DTLS_MOUNT_PATH\",\"readOnly\":true}]" \
    --set nodeAgent.enabled=true \
    --set nodeAgent.captureMode=ebpf \
    --set-string "nodeAgent.admin.port=$NODE_AGENT_ADMIN_PORT" \
    --set nodeAgent.proxyMode=node_waypoint \
    --set-string "nodeAgent.ingressRedirectIfaces=$(helm_set_string_escape "$INGRESS_REDIRECT_IFACES")" \
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

  log "checking ambient NodeWaypoint SPIRE Agent SVID metrics"
  local spec_file="$RESULTS_DIR/ambient-spire-pods.json"
  local metrics_proof="$ROOT_DIR/tests/k8s/lib/spire_ambient_metrics.py"
  if [[ ! -f "$metrics_proof" && -f "$PWD/tests/k8s/lib/spire_ambient_metrics.py" ]]; then
    metrics_proof="$PWD/tests/k8s/lib/spire_ambient_metrics.py"
  fi
  if [[ ! -f "$metrics_proof" ]]; then
    echo "missing SPIRE ambient metrics proof helper: $metrics_proof" >&2
    return 1
  fi
  mkdir -p "$RESULTS_DIR/ambient-spire-metrics"
  if ! kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    -o json >"$spec_file"; then
    echo "could not fetch ambient NodeWaypoint pod specs" >&2
    collect_spire_diagnostics
    return 1
  fi

  if ! python3 - "$spec_file" "$TRUST_DOMAIN" "$MESH_NS" <<'PY'
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
  then
    collect_spire_diagnostics
    return 1
  fi

  local -a pod_records
  mapfile -t pod_records < <(kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.nodeName}{"\n"}{end}')
  if [[ "${#pod_records[@]}" -eq 0 ]]; then
    echo "no ambient NodeWaypoint pod records found for SPIRE SVID metric check" >&2
    collect_spire_diagnostics
    return 1
  fi
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
        if python3 -I "$metrics_proof" \
          --metrics-file "$metrics_file" \
          --expected-spiffe "$expected_spiffe" \
          --trust-domain "$TRUST_DOMAIN"; then
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
      python3 -I "$metrics_proof" \
        --metrics-file "$metrics_file" \
        --expected-spiffe "$expected_spiffe" \
        --trust-domain "$TRUST_DOMAIN" >&2 || true
      cat "$metrics_file" >&2 || true
      collect_spire_diagnostics
      return 1
    fi
  done

  record_live_assertion \
    node_waypoint.identity.workload_api_svid \
    pass \
    "" \
    "" \
    "ambient-nodewaypoints-loaded-per-node-spire-agent-svids" \
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
  grep -q 'ferrum_node_agent_ingress_interface_topology{state="ready",reason="valid"} 1' "$metrics_file"
  grep -Eq '^ferrum_node_agent_ingress_interface_configured_interfaces [1-9][0-9]*$' "$metrics_file"
  grep -Eq '^ferrum_node_agent_ingress_interface_expected_interfaces [1-9][0-9]*$' "$metrics_file"
  grep -q 'ferrum_node_agent_ingress_interface_family_required{family="ipv4"} 1' "$metrics_file"
  grep -q 'ferrum_node_agent_ingress_interface_family_covered{family="ipv4"} 1' "$metrics_file"
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
  record_live_assertion \
    node_waypoint.ebpf.ingress_topology_valid \
    pass \
    "" \
    "" \
    "configured-interface-set-exactly-proved" \
    "" \
    "" \
    "node-agent-metrics/ready-check.prom"
  if [[ "$REQUIRE_DUAL_STACK" == "true" ]]; then
    grep -q 'ferrum_node_agent_ingress_interface_family_required{family="ipv6"} 1' "$metrics_file"
    grep -q 'ferrum_node_agent_ingress_interface_family_covered{family="ipv6"} 1' "$metrics_file"
    record_live_assertion \
      node_waypoint.ebpf.ingress_topology_dual_family \
      pass \
      "" \
      "" \
      "ipv4-and-ipv6-route-families-proved" \
      "" \
      "" \
      "node-agent-metrics/ready-check.prom"
  fi
}

fetch_node_agent_metrics_on_node() {
  local node="$1"
  local output="$2"
  local pod port_forward_pid fetched=false
  pod="$(kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-node-agent \
    --field-selector "spec.nodeName=$node" \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{.items[-1:].metadata.name}')"
  [[ -n "$pod" ]] || return 1
  kubectl -n "$MESH_NS" port-forward "pod/$pod" "19551:$NODE_AGENT_ADMIN_PORT" \
    >"$RESULTS_DIR/topology-port-forward.log" 2>&1 &
  port_forward_pid=$!
  for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:19551/metrics >"$output"; then
      fetched=true
      break
    fi
    sleep 0.5
  done
  kill "$port_forward_pid" 2>/dev/null || true
  wait "$port_forward_pid" 2>/dev/null || true
  [[ "$fetched" == "true" ]]
}

inject_wrong_ingress_routes() {
  local node="$1"
  local remote_node="$2"
  local state_file="$3"
  : >"$state_file"
  TOPOLOGY_ROUTE_NODE="$node"
  TOPOLOGY_ROUTE_STATE_FILE="$state_file"
  TOPOLOGY_ROUTE_MUTATED=true
  docker exec "$node" ip link add ferrumwrong0 type veth peer name ferrumwrong1
  docker exec "$node" ip link set ferrumwrong0 up
  docker exec "$node" ip link set ferrumwrong1 up
  local version prefix target original
  while IFS='|' read -r _kind version prefix target; do
    [[ -n "$target" ]] || continue
    if [[ "$version" == "6" ]]; then
      original="$(docker exec "$node" ip -6 route show exact "$prefix")"
    else
      original="$(docker exec "$node" ip -4 route show exact "$prefix")"
    fi
    printf '%s|%s|%s\n' "$version" "$prefix" "$original" >>"$state_file"
    if [[ "$version" == "6" ]]; then
      docker exec "$node" ip -6 route replace "$prefix" dev ferrumwrong0
    else
      docker exec "$node" ip -4 route replace "$prefix" dev ferrumwrong0
    fi
  done < <(topology_targets_for_node "$node" "$remote_node")
}

restore_ingress_routes() {
  local node="$1"
  local state_file="$2"
  local version prefix original
  while IFS='|' read -r version prefix original; do
    [[ -n "$prefix" ]] || continue
    if [[ -n "$original" ]]; then
      if [[ "$version" == "6" ]]; then
        # Intentional word splitting reconstructs the kernel-produced `ip route`
        # argument vector; no untrusted value is evaluated as shell code.
        docker exec "$node" ip -6 route replace $original
      else
        docker exec "$node" ip -4 route replace $original
      fi
    elif [[ "$version" == "6" ]]; then
      docker exec "$node" ip -6 route del "$prefix" dev ferrumwrong0 2>/dev/null || true
    else
      docker exec "$node" ip -4 route del "$prefix" dev ferrumwrong0 2>/dev/null || true
    fi
  done <"$state_file"
  docker exec "$node" ip link del ferrumwrong0 2>/dev/null || true
  TOPOLOGY_ROUTE_MUTATED=false
  TOPOLOGY_ROUTE_NODE=""
  TOPOLOGY_ROUTE_STATE_FILE=""
}

wait_for_node_agent_topology_state() {
  local node="$1"
  local expected_state="$2"
  local output="$3"
  for _ in $(seq 1 40); do
    if fetch_node_agent_metrics_on_node "$node" "$output" \
      && grep -q "ferrum_node_agent_ingress_interface_topology{state=\"$expected_state\"" "$output"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

run_ingress_topology_negative_and_drift_checks() {
  if [[ "$DOCKER_NODE_EVIDENCE" != "true" ]]; then
    if [[ "$LIVE_TESTS_REQUIRED" == "1" ]]; then
      echo "required ingress-topology live cases need Docker node access" >&2
      exit 1
    fi
    return
  fi
  log "checking wrong-interface startup and runtime route drift readiness withdrawal"
  mkdir -p "$RESULTS_DIR/ingress-topology"
  local state_file="$RESULTS_DIR/ingress-topology/routes-before.txt"
  local metrics_file="$RESULTS_DIR/ingress-topology/wrong-startup.prom"
  local startup_log="$RESULTS_DIR/ingress-topology/wrong-startup.log"
  local old_pod new_pod
  old_pod="$(kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-node-agent \
    --field-selector "spec.nodeName=$NODE_A" \
    -o jsonpath='{.items[0].metadata.name}')"

  inject_wrong_ingress_routes "$NODE_A" "$NODE_B" "$state_file"
  kubectl -n "$MESH_NS" delete "pod/$old_pod" --wait=false
  new_pod=""
  for _ in $(seq 1 60); do
    new_pod="$(kubectl -n "$MESH_NS" get pod \
      -l app.kubernetes.io/name=ferrum-mesh-node-agent \
      --field-selector "spec.nodeName=$NODE_A" \
      --sort-by=.metadata.creationTimestamp \
      -o jsonpath='{.items[-1:].metadata.name}' 2>/dev/null || true)"
    if [[ -n "$new_pod" && "$new_pod" != "$old_pod" ]]; then
      break
    fi
    sleep 1
  done
  if [[ -z "$new_pod" || "$new_pod" == "$old_pod" ]] \
    || ! wait_for_node_agent_topology_state "$NODE_A" unavailable "$metrics_file"; then
    restore_ingress_routes "$NODE_A" "$state_file"
    echo "replacement node-agent did not expose unavailable topology for an existing wrong route device" >&2
    exit 1
  fi
  grep -q 'ferrum_node_agent_capture_state{state="interface_topology_unavailable"} 1' "$metrics_file"
  # A deliberately wrong route can fail closed as an incomplete configured set
  # or as divergent remote-node/PodCIDR evidence. Both are bounded unavailable
  # outcomes; the capture-state and Pod readiness assertions above prove the
  # security behavior this case requires.
  grep -Eq 'reason="(incomplete_interface_set|unsupported_topology)"' "$metrics_file"
  if ! kubectl -n "$MESH_NS" logs "pod/$new_pod" >"$startup_log" \
    || ! grep -Fq 'NodeWaypoint inbound tc ingress redirect attached' "$startup_log"; then
    restore_ingress_routes "$NODE_A" "$state_file"
    echo "replacement did not prove tc attach success on the topologically wrong interface" >&2
    exit 1
  fi
  if kubectl -n "$MESH_NS" get "pod/$new_pod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q '^True$'; then
    restore_ingress_routes "$NODE_A" "$state_file"
    echo "node-agent remained Ready with a wrong ingress interface topology" >&2
    exit 1
  fi
  record_live_assertion \
    node_waypoint.ebpf.ingress_topology_wrong_interface_startup \
    pass "" "" "replacement-started-not-ready-on-existing-wrong-route-device" "" "" \
    "ingress-topology/wrong-startup.prom"

  restore_ingress_routes "$NODE_A" "$state_file"
  kubectl -n "$MESH_NS" wait --for=condition=Ready "pod/$new_pod" --timeout=120s

  inject_wrong_ingress_routes "$NODE_A" "$NODE_B" "$state_file"
  metrics_file="$RESULTS_DIR/ingress-topology/runtime-drift.prom"
  if ! wait_for_node_agent_topology_state "$NODE_A" unavailable "$metrics_file"; then
    restore_ingress_routes "$NODE_A" "$state_file"
    echo "running node-agent did not withdraw readiness after route drift" >&2
    exit 1
  fi
  # The node-agent withdraws /health readiness synchronously with the topology
  # state above, but kubelet observes that change on its configured probe
  # cadence. Wait for the Pod condition instead of racing the next probe.
  if ! kubectl -n "$MESH_NS" wait \
    --for=condition=Ready=false "pod/$new_pod" --timeout=30s; then
    restore_ingress_routes "$NODE_A" "$state_file"
    echo "running node-agent stayed Ready after its proved route topology drifted" >&2
    exit 1
  fi
  record_live_assertion \
    node_waypoint.ebpf.ingress_topology_route_drift \
    pass "" "" "route-drift-withdrew-readiness" "" "" \
    "ingress-topology/runtime-drift.prom"
  restore_ingress_routes "$NODE_A" "$state_file"
  kubectl -n "$MESH_NS" wait --for=condition=Ready "pod/$new_pod" --timeout=120s
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

prepare_dtls_client_image() {
  log "building the NodeWaypoint DTLS client image with openssl preinstalled"
  require_cmd docker
  require_cmd kind
  if [[ ! -f "$DTLS_CLIENT_DOCKERFILE" ]]; then
    echo "missing DTLS client Dockerfile: $DTLS_CLIENT_DOCKERFILE" >&2
    exit 1
  fi
  local cluster="${FERRUM_LIVE_KIND_CLUSTER:-${KIND_CLUSTER:-ferrum-ebpf-live}}"
  docker build -t "$DTLS_CLIENT_IMAGE" -f "$DTLS_CLIENT_DOCKERFILE" \
    "$(dirname "$DTLS_CLIENT_DOCKERFILE")"
  kind load docker-image "$DTLS_CLIENT_IMAGE" --name "$cluster"
}

apply_workloads() {
  log "applying live traffic workloads"
  awk -v ns="$WORKLOAD_NS" -v td="$TRUST_DOMAIN" -v require_dual="$REQUIRE_DUAL_STACK" \
    -v udp_port="$UDP_LISTENER_PORT" -v dtls_port="$DTLS_LISTENER_PORT" \
    -v demux_port="$DEMUX_UDP_PORT" \
    -v dtls_image="$DTLS_CLIENT_IMAGE" -v dtls_client_secret="$DTLS_CLIENT_SECRET_NAME" '
    {
      gsub(/__NAMESPACE__/, ns)
      gsub(/__TRUST_DOMAIN__/, td)
      gsub(/__UDP_LISTENER_PORT__/, udp_port)
      gsub(/__DTLS_LISTENER_PORT__/, dtls_port)
      gsub(/__DEMUX_UDP_PORT__/, demux_port)
      gsub(/__DTLS_CLIENT_IMAGE__/, dtls_image)
      gsub(/__DTLS_CLIENT_CERT_SECRET__/, dtls_client_secret)
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
  kubectl -n "$WORKLOAD_NS" rollout status deploy/udp-echo --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/udp-src-a --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/udp-src-b --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/udp-demux-a --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/udp-demux-b --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/dtls-echo --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/dtls-src-a --timeout=3m
  kubectl -n "$WORKLOAD_NS" rollout status deploy/dtls-src-b --timeout=3m
  local dtls_app
  for dtls_app in dtls-src-a dtls-src-b; do
    if ! kubectl -n "$WORKLOAD_NS" exec "deploy/$dtls_app" -c dtls -- openssl version >/dev/null; then
      echo "$dtls_app is missing the openssl CLI; the DTLS live client image did not load" >&2
      exit 1
    fi
  done

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
---
# Unenrolled UDP sender for the NodeWaypoint UDP listener attribution checks
# (issue #3286). It lives outside the mesh namespace and is not enrolled, so the
# node-agent registry publishes no binding for its veth: every datagram it sends
# to the NodeWaypoint UDP listener is UNATTRIBUTABLE and must be refused while a
# scoped AuthorizationPolicy is enforcing. It also drives the source-address
# spoof probe, where it names an enrolled pod's IP from its own interface.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: udp-unmanaged
  namespace: $UNMANAGED_NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: udp-unmanaged
  template:
    metadata:
      labels:
        app: udp-unmanaged
    spec:
      nodeSelector:
        ferrum.io/live-node: a
      containers:
        - name: udp
          image: python:3.12-alpine
          command: ["sh", "-c", "sleep 365d"]
          securityContext:
            capabilities:
              # Explicit so the source-address spoof probe is DETERMINISTIC:
              # without NET_RAW the forged datagram could not be built, and the
              # required spoof-refusal assertion would have nothing to observe.
              # The harness fails that assertion closed rather than recording a
              # refusal for a datagram that was never emitted.
              add: ["NET_RAW"]
---
# HOST-NETWORK forger for the UDP relay sender-proof check (issues #3956,
# #3957). This is the actual threat model, and it is deliberately NOT the
# pod-netns prober above: a datagram leaving a pod netns crosses a veth, where
# skb_scrub_packet clears skb->mark, so a pod cannot deliver a forged mark
# into the host namespace at all. A host-network workload with NET_ADMIN and
# NET_RAW can: its socket IS in the host netns, so SO_MARK reaches the enrolled
# pod's veth egress hook intact, and a raw datagram can carry a Service ClusterIP
# and the occupied listener source port. That combination presents every packet
# attribute the tc UDP guard used to accept. What it cannot present is
# bpf_skb_cgroup_id(): its socket carries its OWN cgroup, not the NodeWaypoint
# relay's.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: udp-forger
  namespace: $UNMANAGED_NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: udp-forger
  template:
    metadata:
      labels:
        app: udp-forger
    spec:
      nodeSelector:
        ferrum.io/live-node: a
      # The whole point: forge from the HOST network namespace, where a socket
      # mark survives to the enrolled pod's veth egress hook.
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: udp
          image: python:3.12-alpine
          command: ["sh", "-c", "sleep 365d"]
          securityContext:
            capabilities:
              # NET_ADMIN for SO_MARK and NET_RAW for the exact raw source
              # tuple. Explicit so the forgery is DETERMINISTIC: a sandbox that
              # cannot forge FAILS the required gate rather than recording a
              # refusal for an attack nothing attempted.
              add: ["NET_ADMIN", "NET_RAW"]
---
# Unenrolled DTLS sender for the Service-path refusal check (issue #3286 root
# review). Same posture as udp-unmanaged — outside the mesh namespace, no
# registry binding for its veth — but carrying openssl, so it can attempt a real
# handshake against the dtls-echo Service DNS name. No steering rule names its
# interface, so its datagram takes the ordinary path: kube-proxy DNATs the
# ClusterIP to the backing pod and the pod-veth guard drops it. The backend log
# is the authority that it arrived nowhere.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dtls-unmanaged
  namespace: $UNMANAGED_NS
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dtls-unmanaged
  template:
    metadata:
      labels:
        app: dtls-unmanaged
    spec:
      nodeSelector:
        ferrum.io/live-node: a
      containers:
        - name: dtls
          image: $DTLS_CLIENT_IMAGE
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", "sleep 365d"]
EOF
  kubectl -n "$UNMANAGED_NS" rollout status deploy/unmanaged-a --timeout=3m
  kubectl -n "$UNMANAGED_NS" rollout status deploy/unmanaged-b --timeout=3m
  kubectl -n "$UNMANAGED_NS" rollout status deploy/udp-unmanaged --timeout=3m
  kubectl -n "$UNMANAGED_NS" rollout status deploy/udp-forger --timeout=3m
  kubectl -n "$UNMANAGED_NS" rollout status deploy/dtls-unmanaged --timeout=3m
  if ! kubectl -n "$UNMANAGED_NS" exec deploy/dtls-unmanaged -c dtls -- openssl version >/dev/null; then
    echo "dtls-unmanaged is missing the openssl CLI; the DTLS live client image did not load" >&2
    exit 1
  fi
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

fetch_ambient_admin_json() {
  local node="$1"
  local path="$2"
  local out="$3"
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
      "http://127.0.0.1:$port$path" >"$out" 2>"$out.curl"; then
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

node_waypoint_identity_has_policy_scope() {
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
        sys.exit(0 if identity.get("has_policy_scope") is True else 1)
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

try_wait_for_node_waypoint_marker_removed() {
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
  return 1
}

wait_for_node_waypoint_marker_removed() {
  try_wait_for_node_waypoint_marker_removed "$@" || exit 1
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
    # Destination Service workloads must carry node_waypoint metadata before
    # Service routes can materialize. Identity-only src workloads do not.
    # A count-only wait can pass on a metadata-stripped snapshot and then 404.
    "workloads_with_node_waypoint": 2,
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

  # Watch-based pod discovery normally reaches the slice in seconds, but the
  # CP's watch -> translate -> rebuild -> broadcast pipeline has no periodic
  # reconcile fallback, so slow or recovering propagation can take far longer.
  # Give it a generous window (~7 min): a live run exceeded the previous
  # ~3 min window while the proxies still held a pre-workload slice
  # (2026-07-14, actions run 29307789287). The bound is ELAPSED time, not an
  # attempt count — when admin port-forwards are unusable each attempt burns
  # ~10s+ in curl retries, and an attempt-count bound would balloon that
  # failure mode to ~30 min of the live job's budget.
  local slice_wait_deadline=$((SECONDS + 420))
  while ((SECONDS < slice_wait_deadline)); do
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
  # The drift files above only show what the proxies last RECEIVED. When this
  # check fails, the missing evidence is CP-side: did the K8s controller see
  # the workload pods, and did it rebuild and broadcast a fresh slice? Dump
  # control-plane and ambient logs so a recurrence is root-causable. List
  # ambient pods UNFILTERED here — `ambient_pods` returns only Ready pods, and
  # a never-Ready (crash-looping / probe-failing) ambient pod is exactly the
  # one whose logs matter in this failure dump.
  echo "--- control-plane logs (tail)" >&2
  kubectl -n "$MESH_NS" logs deployment/ferrum-mesh-control-plane --tail=300 >&2 || true
  for pod in $(kubectl -n "$MESH_NS" get pods \
    -l app.kubernetes.io/name=ferrum-mesh-ambient -o name 2>/dev/null); do
    echo "--- $pod logs (tail)" >&2
    kubectl -n "$MESH_NS" logs "$pod" --tail=100 --all-containers >&2 || true
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
  local uid node pod identities_dir identities_file curl_out curl_err curl_status_file
  local curl_status curl_code record
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
    curl_code="$(tail -n 1 "$curl_out" 2>/dev/null || true)"

    # The in-netns identity registry can become visible before the newly
    # received mesh slice has installed the exact pod UID's policy scope and
    # rebuilt the request router. Do not declare admission ready on either
    # half-converged state: the identity endpoint reports has_policy_scope=false
    # while authz correctly returns its fail-closed scope_missing 403, and the
    # router can return a transient route-miss 404. Every caller of this helper
    # targets a scoped-policy fixture, so require the exact UID's live scope plus
    # the converged 200 or policy 403 before the following traffic assertion.
    if fetch_node_waypoint_identities_for_node "$node" "$identities_file" &&
      node_waypoint_identities_include_uid "$identities_file" "$uid" &&
      node_waypoint_identity_has_policy_scope "$identities_file" "$uid" &&
      [[ "$curl_status" -eq 0 ]] &&
      [[ "$curl_code" == "200" || "$curl_code" == "403" ]]; then
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
  local retry_route_not_found="${6:-false}"
  local max_attempts="${7:-8}"
  local output="" code="" body="" status=1 err
  err="$(mktemp)"
  for attempt in $(seq 1 "$max_attempts"); do
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
      if [[ "$retry_route_not_found" == "true" ]] &&
        [[ "$code" == "404" ]] &&
        [[ "$body" == '{"error":"Not Found"}' ]]; then
        sleep 1
        continue
      fi
      break
    fi
    # A rolling NodeWaypoint restart becomes Kubernetes-Ready before the CP's
    # updated waypoint inventory has necessarily rematerialized every outbound
    # route. Only callers that opt into this bounded convergence mode retry the
    # exact route-missing response above; authorization failures and other HTTP
    # errors still fail immediately so policy regressions cannot be hidden.
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

expect_policy_denied() {
  local from="$1"
  local label="$2"
  local url="$3"
  local family="${4:-}"
  local max_attempts="${5:-8}"
  local output="" code="" body="" status=1 err
  err="$(mktemp)"
  for attempt in $(seq 1 "$max_attempts"); do
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
    if [[ "$status" -eq 0 && "$code" == "403" ]]; then
      rm -f "$err"
      return
    fi
    if [[ "$status" -eq 0 && "$code" == "200" ]]; then
      echo "expected policy deny for $label from $from to $url, got HTTP 200 body '${body:-<empty>}'" >&2
      cat "$err" >&2 || true
      rm -f "$err"
      collect_traffic_failure_diagnostics
      return 1
    fi
    if [[ "$status" -eq 0 ]]; then
      if [[ "$code" == "404" ]] && [[ "$body" == '{"error":"Not Found"}' ]]; then
        sleep 1
        continue
      fi
      echo "expected HTTP 403 policy deny for $label from $from to $url, got HTTP ${code} body '${body:-<empty>}'" >&2
      cat "$err" >&2 || true
      rm -f "$err"
      collect_traffic_failure_diagnostics
      return 1
    fi
    sleep 1
  done
  echo "expected HTTP 403 policy deny for $label from $from to $url, got HTTP ${code:-curl-exit-$status} body '${body:-<empty>}'" >&2
  cat "$err" >&2 || true
  rm -f "$err"
  collect_traffic_failure_diagnostics
  return 1
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

collect_ambient_observability_metrics() {
  local out_root="$RESULTS_DIR/ambient-observability-metrics"
  mkdir -p "$out_root"
  # Keep each scrape isolated. Ambient rollouts replace pod names, so reusing
  # one directory would leave stale .prom files that could make a later
  # counter assertion pass against metrics from a terminated process.
  local out_dir
  out_dir="$(mktemp -d "$out_root/snapshot.XXXXXX")"
  local -a pods
  mapfile -t pods < <(ambient_pods)
  local idx=0 pod port metrics_file pf_log pf_pid
  for pod in "${pods[@]}"; do
    port=$((19600 + idx))
    idx=$((idx + 1))
    metrics_file="$out_dir/$pod.prom"
    pf_log="$out_dir/$pod-port-forward.log"
    kubectl -n "$MESH_NS" port-forward "pod/$pod" "$port:$AMBIENT_ADMIN_PORT" >"$pf_log" 2>&1 &
    pf_pid=$!
    if wait_for_port_forward_ready "$pf_pid" "$pf_log" "$port"; then
      curl -fsS "http://127.0.0.1:$port/metrics" >"$metrics_file" 2>/dev/null || true
    fi
    stop_port_forward "$pf_pid"
  done
  printf '%s\n' "$out_dir"
}

sum_ambient_metric_total() {
  # Sum a Prometheus series across all ambient NodeWaypoint pods. Callers pass
  # an exact selector ending in `}`, e.g. metric{phase="x",result="y"}. Match
  # both that form and the same required labels with optional
  # gateway_namespace appended before the closing brace. Missing series count
  # as zero so first-scrape baselines work. Malformed samples are skipped.
  local metric_selector="$1"
  local snapshot_dir
  snapshot_dir="$(collect_ambient_observability_metrics)"
  python3 - "$snapshot_dir" "$metric_selector" <<'PY'
import pathlib
import re
import sys

out_dir = pathlib.Path(sys.argv[1])
selector = sys.argv[2]
total = 0
# Exact closed selectors end with `}`; strip it so a rendered series with
# `,gateway_namespace="…"` still matches the required metric+label prefix.
if not selector.endswith("}"):
    print(0)
    raise SystemExit(0)
required_prefix = selector[:-1]
# After the required-label prefix: either `} <sample>` or
# `,gateway_namespace="<value>"} <sample>`. Reject other extra labels and
# junk between the label set and the sample (fail closed).
rest_re = re.compile(
    r'^(?:\}|,gateway_namespace="[^"]*"\})\s+(\S+)\s*$'
)
for path in sorted(out_dir.glob("*.prom")):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#") or not line:
            continue
        if not line.startswith(required_prefix):
            continue
        match = rest_re.match(line[len(required_prefix):])
        if match is None:
            continue
        try:
            total += int(float(match.group(1)))
        except ValueError:
            continue
print(total)
PY
}

run_plaintext_hbone_rejection_check() {
  local before after
  before="$(sum_ambient_metric_total 'ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure"}')"
  run_hbone_listener_negative_check \
    node_waypoint.identity.plaintext_hbone_rejected \
    plaintext \
    plaintext-to-hbone-listener-rejected
  after="$(sum_ambient_metric_total 'ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="inbound_tls",result="failure"}')"
  if [[ "$after" -gt "$before" ]]; then
    record_live_assertion \
      node_waypoint.observability.hbone_handshake_inbound_tls_failure \
      pass \
      unmanaged-a \
      dst-a \
      "inbound_tls_failure_before=$before after=$after" \
      "none" \
      "$(spiffe_for_sa dst-a)" \
      "hbone-negative,ambient-observability-metrics"
  else
    record_live_assertion \
      node_waypoint.observability.hbone_handshake_inbound_tls_failure \
      fail \
      unmanaged-a \
      dst-a \
      "inbound_tls_failure_did_not_increase before=$before after=$after" \
      "none" \
      "$(spiffe_for_sa dst-a)" \
      "hbone-negative,ambient-observability-metrics"
    return 1
  fi
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

  # Issue #3927 redacted the CONNECT authority out of the client body, so this
  # is now an EXACT literal match rather than a glob over the peer address. The
  # peer's own admission status is deliberately retained
  # (`HbonePoolError::public_status`) so a destination POLICY denial stays
  # distinguishable from any other tunnel refusal; do not relax this to the
  # bare reason.
  if [[ "$code" == "502" && "$body" == '{"error":"HBONE backend unavailable: tunnel rejected by peer with status 403"}' ]]; then
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
  local out_dir before_file after_file output code body err status before_count after_count attempt
  local dispatch_not_ready_body route_not_found_body peer_not_ready_body
  local relay_denied_selector relay_denied_before relay_denied_after
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
  # A destination refuses a CONNECT for an address it does not (yet) own with
  # the SAME 403 a policy deny uses (issue #5763), and a source waypoint
  # surfaces either one as "tunnel rejected by peer with status 403". Only the
  # destination-policy rejection counter tells them apart: a 403 that moved
  # `relay_destination_denied` is ownership convergence (for example the
  # node-local registry not yet enrolling the destination after the rollout),
  # never the policy deny this check proves.
  relay_denied_selector='ferrum_mesh_node_waypoint_destination_policy_rejections_total{reason="relay_destination_denied"}'
  relay_denied_before="$(sum_ambient_metric_total "$relay_denied_selector")"

  dispatch_not_ready_body='{"error":"Bad Gateway","message":"HBONE dispatch required for this backend target"}'
  # A destination that has not applied its first mesh slice answers 503
  # `hbone_relay_not_ready` (issue #5763): convergence, never a policy result.
  peer_not_ready_body='{"error":"HBONE backend unavailable: tunnel rejected by peer with status 503"}'
  # Exact Ferrum HTTP route-miss body. A rolling NodeWaypoint restart can
  # accept the slice and report ready before outbound HTTP routes rematerialize;
  # captured traffic then hits the source waypoint and 404s instead of reaching
  # destination HBONE policy. This is the same post-rollout window as the 502
  # HBONE-tag miss below — wait through it, never treat 404 as a policy deny.
  route_not_found_body='{"error":"Not Found"}'
  for attempt in $(seq 1 120); do
    set +e
    output="$(curl_for_family_from "$family" "$from" "$url" 2>"$err")"
    status=$?
    set -e
    code="${output##*$'\n'}"
    body="${output%$'\n'*}"
    printf '%s\n' "$output" >"$out_dir/curl.out"
    printf '%s\n' "$status" >"$out_dir/curl.status"
    if [[ "$status" -eq 0 ]] && forged_assertion_response_is_policy_rejection "$code" "$body"; then
      relay_denied_after="$(sum_ambient_metric_total "$relay_denied_selector")"
      if [[ "$relay_denied_after" =~ ^[0-9]+$ && "$relay_denied_before" =~ ^[0-9]+$ &&
        "$relay_denied_after" -gt "$relay_denied_before" ]]; then
        echo "attempt $attempt: HTTP $code was a destination OWNERSHIP refusal, not a policy deny (relay_destination_denied $relay_denied_before -> $relay_denied_after); waiting for convergence" >&2
        relay_denied_before="$relay_denied_after"
        if [[ "$attempt" -lt 120 ]]; then
          sleep 0.5
          continue
        fi
        echo "expected forged assertion request to fail via destination HBONE policy rejection, but the destination still refuses the relay destination itself (relay_destination_denied) after every attempt" >&2
        return 1
      fi
      echo "attempt $attempt: HTTP $code is a destination policy deny (relay_destination_denied unchanged at ${relay_denied_after:-<unread>})" >&2
      break
    fi

    # A hosted DaemonSet rollout can report ready after accepting the slice but
    # before the restarted source NodeWaypoint has rematerialized outbound HTTP
    # routes or per-workload HBONE target tags, or before the destination has
    # applied its first slice. Retry only those exact fail-closed convergence
    # responses; every other transport/HTTP outcome still fails immediately,
    # and success still requires a destination-policy rejection plus the deny
    # counter below. A 404 is never a policy pass.
    if [[ "$attempt" -lt 120 ]]; then
      if [[ "$status" -eq 0 && "$code" == "502" && "$body" == "$dispatch_not_ready_body" ]]; then
        sleep 0.5
        continue
      fi
      if [[ "$status" -eq 0 && "$code" == "502" && "$body" == "$peer_not_ready_body" ]]; then
        sleep 0.5
        continue
      fi
      if [[ "$status" -eq 0 && "$code" == "404" && "$body" == "$route_not_found_body" ]]; then
        sleep 0.5
        continue
      fi
    fi

    echo "expected forged assertion request to fail via destination HBONE policy rejection, got curl status=$status HTTP ${code:-<none>} body '${body:-<empty>}'" >&2
    cat "$err" >&2 || true
    return 1
  done

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
  local bad_assertor blocked_ok=0 restored_ok=0 recovery_ok=0 assert_after=0
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
        # Capture before restore_default_hbone_assertors restarts ambient pods
        # and resets process-static counters.
        assert_after="$(sum_ambient_metric_total 'ferrum_mesh_node_waypoint_asserted_identity_total{result="rejected",reason="untrusted_assertor"}')"
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
      4 \
      true \
      30; then
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
    if [[ "$assert_after" -gt 0 ]]; then
      record_live_assertion \
        node_waypoint.observability.asserted_identity_rejected \
        pass \
        src-a \
        dst-a \
        "asserted_identity_rejected_untrusted_assertor=$assert_after" \
        "$(spiffe_for_sa src-a)" \
        "$(spiffe_for_sa dst-a)" \
        "ambient-observability-metrics"
    else
      record_live_assertion \
        node_waypoint.observability.asserted_identity_rejected \
        fail \
        src-a \
        dst-a \
        "asserted_identity_rejected_untrusted_assertor_still_zero" \
        "$(spiffe_for_sa src-a)" \
        "$(spiffe_for_sa dst-a)" \
        "ambient-observability-metrics"
      return 1
    fi
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

run_spire_restart_recovery_check() {
  if [[ "$SPIRE_PRODUCTION" != "true" ]]; then
    return
  fi

  log "checking SPIRE Agent and NodeWaypoint restart recovery"
  local out_dir="$RESULTS_DIR/spire-restart-recovery"
  mkdir -p "$out_dir"

  local spire_ok=0 ambient_ok=0 svid_ok=0 admission_ok=0 deny_admission_ok=0 allow_ok=0 deny_ok=0 hbone_ok=0

  if kubectl --context "$KUBE_CONTEXT" -n "$SPIRE_NS" rollout restart daemonset/spire-agent >"$out_dir/spire-agent-restart.log" 2>&1 &&
    ferrum_spire_wait_ready "$KUBE_CONTEXT" "$SPIRE_NS" 5m >"$out_dir/spire-ready.log" 2>&1; then
    spire_ok=0
  else
    spire_ok=$?
  fi

  if [[ "$spire_ok" -eq 0 ]]; then
    if kubectl -n "$MESH_NS" rollout restart daemonset/ferrum-mesh-ambient >"$out_dir/ambient-restart.log" 2>&1 &&
      kubectl -n "$MESH_NS" rollout status daemonset/ferrum-mesh-ambient --timeout=5m >"$out_dir/ambient-ready.log" 2>&1 &&
      (wait_for_node_waypoint_ready_markers) >"$out_dir/node-waypoint-ready.log" 2>&1 &&
      (wait_for_ambient_mesh_slice) >"$out_dir/mesh-slice-ready.log" 2>&1; then
      ambient_ok=0
    else
      ambient_ok=$?
    fi
  fi

  if [[ "$spire_ok" -eq 0 && "$ambient_ok" -eq 0 ]]; then
    if (verify_ambient_spire_identity) >"$out_dir/workload-api-svid.log" 2>&1; then
      svid_ok=0
    else
      svid_ok=$?
    fi

    if try_wait_for_node_waypoint_admission src-a \
      "post-restart src-a Service path" \
      "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" \
      4 >"$out_dir/admission-src-a.log" 2>&1; then
      admission_ok=0
    else
      admission_ok=$?
    fi

    if try_wait_for_node_waypoint_admission src-b \
      "post-restart src-b Service path" \
      "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" \
      4 >"$out_dir/admission-src-b.log" 2>&1; then
      deny_admission_ok=0
    else
      deny_admission_ok=$?
    fi

    if expect_allowed src-a \
      "post-restart allowed Service path" \
      "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" \
      "ok-a" \
      4 >"$out_dir/allow-src-a.log" 2>&1; then
      allow_ok=0
    else
      allow_ok=$?
    fi

    if expect_policy_denied src-b \
      "post-restart AuthorizationPolicy DENY" \
      "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" \
      4 >"$out_dir/deny-src-b.log" 2>&1; then
      deny_ok=0
    else
      deny_ok=$?
    fi

    local pod hbone_pod_count=0
    hbone_ok=0
    while IFS= read -r pod; do
      [[ -n "$pod" ]] || continue
      hbone_pod_count=$((hbone_pod_count + 1))
      if ! run_hbone_listener_negative_probe_for_pod plaintext "$pod" >"$out_dir/hbone-plaintext-$pod.log" 2>&1; then
        hbone_ok=1
        break
      fi
      if ! run_hbone_listener_negative_probe_for_pod unauthenticated "$pod" >"$out_dir/hbone-unauthenticated-$pod.log" 2>&1; then
        hbone_ok=1
        break
      fi
    done < <(ambient_pods)
    if [[ "$hbone_pod_count" -lt 2 ]]; then
      echo "expected at least two recovered ambient pods for post-restart HBONE probes, found $hbone_pod_count" >"$out_dir/hbone-pods.log"
      hbone_ok=1
    fi
  fi

  if [[ "$spire_ok" -eq 0 && "$ambient_ok" -eq 0 && "$svid_ok" -eq 0 &&
    "$admission_ok" -eq 0 && "$deny_admission_ok" -eq 0 && "$allow_ok" -eq 0 &&
    "$deny_ok" -eq 0 && "$hbone_ok" -eq 0 ]]; then
    record_live_assertion \
      node_waypoint.identity.spire_restart_recovery \
      pass \
      src-a \
      dst-a \
      "spire-agent-and-nodewaypoint-restarted-svids-reloaded-traffic-and-hbone-authn-recovered" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)" \
      "spire-restart-recovery,hbone-negative"
    return
  fi

  record_live_assertion \
    node_waypoint.identity.spire_restart_recovery \
    fail \
    src-a \
    dst-a \
    "spire=$spire_ok ambient=$ambient_ok svid=$svid_ok admission=$admission_ok deny_admission=$deny_admission_ok allow=$allow_ok deny=$deny_ok hbone=$hbone_ok" \
    "$(spiffe_for_sa src-a)" \
    "$(spiffe_for_sa dst-a)" \
    "spire-restart-recovery,hbone-negative"
  collect_traffic_failure_diagnostics
  return 1
}

run_traffic_checks() {
  log "running IPv4 Service authorization and bypass checks"
  local dst_a_ip dst_b_ip outbound_before outbound_after
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

  if [[ "$SPIRE_PRODUCTION" == "true" ]]; then
    outbound_before="$(sum_ambient_metric_total 'ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="outbound_dial",result="success"}')"
  fi

  recorded_expect_allowed \
    node_waypoint.ipv4.service_allow_cross_node \
    src-a \
    dst-b \
    "cross-node Service ClusterIP" \
    "http://dst-b.$WORKLOAD_NS.svc.cluster.local:8080/" \
    "ok-b" \
    4

  if [[ "$SPIRE_PRODUCTION" == "true" ]]; then
    outbound_after="$(sum_ambient_metric_total 'ferrum_mesh_node_waypoint_hbone_handshakes_total{phase="outbound_dial",result="success"}')"
    if [[ "$outbound_after" -gt "$outbound_before" ]]; then
      record_live_assertion \
        node_waypoint.observability.hbone_handshake_outbound_success \
        pass \
        src-a \
        dst-b \
        "outbound_dial_success_before=$outbound_before after=$outbound_after" \
        "$(spiffe_for_sa src-a)" \
        "$(spiffe_for_sa dst-b)" \
        "ambient-observability-metrics"
    else
      record_live_assertion \
        node_waypoint.observability.hbone_handshake_outbound_success \
        fail \
        src-a \
        dst-b \
        "outbound_dial_success_did_not_increase before=$outbound_before after=$outbound_after" \
        "$(spiffe_for_sa src-a)" \
        "$(spiffe_for_sa dst-b)" \
        "ambient-observability-metrics"
      collect_traffic_failure_diagnostics
      return 1
    fi
  fi

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
  run_spire_restart_recovery_check

  if [[ "$STALE_IP_REUSE_HOST_LOCAL_PROFILE" != "true" ]]; then
    log "checking stale identity cleanup across source workload recreation"
    local old_src_a_uid old_src_a_node
    old_src_a_uid="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].metadata.uid}')"
    old_src_a_node="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].spec.nodeName}')"
    kubectl -n "$WORKLOAD_NS" delete pod -l app=src-a --wait=true
    if ! try_wait_for_node_waypoint_marker_removed "$old_src_a_node" "$old_src_a_uid"; then
      record_live_assertion \
        node_waypoint.identity.stale_cleanup \
        fail \
        src-a \
        dst-a \
        "deleted-source-registry-marker-remained" \
        "$(spiffe_for_sa src-a)" \
        "$(spiffe_for_sa dst-a)"
      collect_traffic_failure_diagnostics
      return 1
    fi
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
  old_src_a_uid="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].metadata.uid}')"
  old_src_a_node="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].spec.nodeName}')"
  old_src_a_pod="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].metadata.name}')"
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
  if ! try_wait_for_node_waypoint_marker_removed "$old_src_a_node" "$old_src_a_uid"; then
    record_live_assertion \
      node_waypoint.identity.stale_cleanup \
      fail \
      src-a \
      dst-a \
      "deleted-source-registry-marker-remained-before-ip-reuse" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)"
    record_live_assertion \
      node_waypoint.identity.stale_ip_reuse \
      fail \
      src-a \
      dst-a \
      "deleted-source-registry-marker-remained-before-ip-reuse" \
      "$(spiffe_for_sa src-a)" \
      "$(spiffe_for_sa dst-a)" \
      "cni-ip-reuse"
    collect_traffic_failure_diagnostics
    return 1
  fi
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

# ── NodeWaypoint UDP listener datapath (issue #3286) ────────────────────────
#
# These checks push REAL datagrams through the production UDP listener the
# NodeWaypoint materializes for the `udp-echo` Service's `protocol: UDP` port
# (`materialize_node_waypoint_udp_listeners`, gated by
# FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED). Every assertion observes the
# datagram outcome, never source code or model state:
#
#   * an ADMITTED enrolled source reaches the backend and gets its echo back;
#   * a DENIED enrolled source (matched by the namespace-scoped `deny-src-b`
#     AuthorizationPolicy on its attributed source principal) gets nothing;
#   * an UNATTRIBUTABLE source (unenrolled pod, and the same pod SPOOFING an
#     enrolled pod's source address) gets nothing — the ingress interface, not
#     the forgeable source address, is what attributes the datagram;
#   * a policy CHANGE denies the previously admitted source, and WITHDRAWING it
#     restores service, both without restarting the data plane.

# Send one datagram from a pod and print the reply, `TIMEOUT`, or `EXECFAIL`.
udp_probe_from() {
  local ns="$1" app="$2" target_ip="$3" port="$4" payload="$5" wait_secs="${6:-3}"
  kubectl -n "$ns" exec "deploy/$app" -c udp -- python -u -c '
import socket
import sys

target, port, payload, wait = sys.argv[1], int(sys.argv[2]), sys.argv[3], float(sys.argv[4])
target = target.strip("[]")
family = socket.AF_INET6 if ":" in target else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM)
s.settimeout(wait)
addr = (target, port, 0, 0) if family == socket.AF_INET6 else (target, port)
try:
    s.sendto(payload.encode(), addr)
    data, _ = s.recvfrom(2048)
    sys.stdout.write(data.decode("utf-8", "replace"))
except socket.timeout:
    sys.stdout.write("TIMEOUT")
except OSError as exc:
    sys.stdout.write("OSERROR:%s" % exc.errno)
' "$target_ip" "$port" "$payload" "$wait_secs" 2>/dev/null || echo "EXECFAIL"
}

# Send one datagram whose IP source address is FORGED to `spoof_ip`, from a pod
# whose veth is not the one that address belongs to.
#
# Output contract, so a refusal can never be recorded for a datagram that was
# never put on the wire:
#   SPOOF-UNAVAILABLE  — the raw socket or the send FAILED; nothing was emitted.
#   SPOOF-SENT:TIMEOUT — the forged datagram WAS emitted and drew no reply.
#   SPOOF-SENT:<data>  — the forged datagram WAS emitted and drew a reply.
# The `SPOOF-SENT:` prefix is printed only after `sendto` returns, so it is the
# emission proof itself.
udp_spoof_probe_from() {
  local ns="$1" app="$2" target_ip="$3" port="$4" spoof_ip="$5" payload="$6" wait_secs="${7:-3}"
  kubectl -n "$ns" exec "deploy/$app" -c udp -- python -u -c '
import socket
import struct
import sys

target, port, spoof, payload, wait = (
    sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4].encode(), float(sys.argv[5])
)

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

# The forging socket. The pod is granted NET_RAW explicitly, so a failure here
# is an environment fault the caller must fail closed on, not a refusal.
try:
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except OSError:
    sys.stdout.write("SPOOF-UNAVAILABLE")
    raise SystemExit(0)

sport = 45001
udp_len = 8 + len(payload)
pseudo = (
    socket.inet_aton(spoof)
    + socket.inet_aton(target)
    + struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_len)
)
udp_header = struct.pack("!HHHH", sport, port, udp_len, 0)
csum = checksum(pseudo + udp_header + payload)
udp_header = struct.pack("!HHHH", sport, port, udp_len, csum or 0xFFFF)
total_len = 20 + udp_len
ip_header = struct.pack(
    "!BBHHHBBH4s4s",
    0x45, 0, total_len, 0x1234, 0, 64, socket.IPPROTO_UDP, 0,
    socket.inet_aton(spoof), socket.inet_aton(target),
)
# Bound BEFORE the send, on the same source port the forged datagram carries,
# so a reply the listener does send is observable rather than dropped by the
# kernel.
sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sink.settimeout(wait)
try:
    sink.bind(("0.0.0.0", sport))
except OSError:
    sys.stdout.write("SPOOF-UNAVAILABLE")
    raise SystemExit(0)

try:
    raw.sendto(ip_header + udp_header + payload, (target, 0))
except OSError:
    sys.stdout.write("SPOOF-UNAVAILABLE")
    raise SystemExit(0)

# Past this point the forged datagram IS on the wire, so every remaining
# outcome is an observation about the listener rather than about the sandbox.
sys.stdout.write("SPOOF-SENT:")
try:
    data, _ = sink.recvfrom(2048)
    sys.stdout.write(data.decode("utf-8", "replace"))
except socket.timeout:
    sys.stdout.write("TIMEOUT")
except OSError:
    sys.stdout.write("TIMEOUT")
' "$target_ip" "$port" "$spoof_ip" "$payload" "$wait_secs" 2>/dev/null || echo "SPOOF-UNAVAILABLE"
}

# Forge the COMPLETE pre-#3956/#3957 UDP admission from the HOST network
# namespace and send it straight at an enrolled pod, bypassing the waypoint.
#
# A raw IPv4 datagram is intentional: the live NodeWaypoint already owns the
# wildcard listener port, so a second UDP socket cannot reliably bind the exact
# `(ClusterIP, listener port)` tuple. The raw packet carries that exact source
# port without colliding with the serving listener. This drives BOTH historical
# bypass shapes from one helper: pass a trusted node source address for the
# #3956 shape (node source + mark) and a published Service ClusterIP for the
# #3957 shape (listener-wide reply tuple + mark, replayed at a destination its
# Service never named). `mark` is the public NODE_WAYPOINT_INBOUND_AUTH_MARK.
#
# Output contract mirrors `udp_spoof_probe_from`, so a refusal can never be
# recorded for an attack that was never mounted:
#   FORGED-UNAVAILABLE:<detail>  — the socket, mark, header, or send FAILED.
#   FORGED-SENT                  — the datagram WAS emitted.
# The prefix is printed only after `sendto` returns.
udp_forged_relay_probe_from() {
  local ns="$1" app="$2" target_ip="$3" port="$4" source_ip="$5" mark="$6" payload="$7"
  kubectl -n "$ns" exec "deploy/$app" -c udp -- python -u -c '
import socket
import struct
import sys

target, port, source, mark, payload = (
    sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5].encode()
)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except OSError as exc:
    sys.stdout.write("FORGED-UNAVAILABLE:socket:%s" % exc.errno)
    raise SystemExit(0)

# The relay mark. Public and fixed, and settable by anything holding
# CAP_NET_ADMIN — which is exactly why it cannot be an authorization.
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
except OSError as exc:
    sys.stdout.write("FORGED-UNAVAILABLE:so_mark:%s" % exc.errno)
    raise SystemExit(0)

try:
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
except OSError as exc:
    sys.stdout.write("FORGED-UNAVAILABLE:ip_hdrincl:%s" % exc.errno)
    raise SystemExit(0)

try:
    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", port, port, udp_len, 0)
    total_len = 20 + udp_len
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64, socket.IPPROTO_UDP, 0,
        socket.inet_aton(source), socket.inet_aton(target),
    )
except (OSError, struct.error) as exc:
    sys.stdout.write("FORGED-UNAVAILABLE:header:%s" % type(exc).__name__)
    raise SystemExit(0)

try:
    s.sendto(ip_header + udp_header + payload, (target, 0))
except OSError as exc:
    sys.stdout.write("FORGED-UNAVAILABLE:sendto:%s" % exc.errno)
    raise SystemExit(0)

# Past this point the forged datagram IS on the wire, so a backend that never
# logged it is an observation about the guard rather than about the sandbox.
sys.stdout.write("FORGED-SENT")
' "$target_ip" "$port" "$source_ip" "$mark" "$payload" 2>/dev/null || echo "FORGED-UNAVAILABLE:exec"
}

udp_backend_received() {
  local ns="$1" deploy="$2" payload="$3"
  kubectl -n "$ns" logs "deploy/$deploy" --tail=-1 2>/dev/null |
    grep -c "^recv:${payload}$" || true
}

# How many datagrams carrying `payload` the udp-echo backend actually received.
# Reply-absence alone is not proof for the spoofed-source case (a spoofed
# datagram's reply is sent to the FORGED address, so the prober would see a
# timeout either way); the backend log is.
udp_echo_backend_received() {
  udp_backend_received "$WORKLOAD_NS" udp-echo "$1"
}

ambient_restart_total() {
  kubectl -n "$MESH_NS" get pods -l app.kubernetes.io/component=ambient \
    -o jsonpath='{range .items[*]}{.status.containerStatuses[*].restartCount}{"\n"}{end}' 2>/dev/null |
    awk '{ for (i = 1; i <= NF; i++) total += $i } END { print total + 0 }'
}

# The node-local address the NodeWaypoint UDP/DTLS listeners are PROBED at.
#
# This is deliberately NOT the node's `status.hostIP`. Both listeners bind
# `0.0.0.0`, and every reply leaves with its source pinned by IP(v6)_PKTINFO to
# the exact local address the client targeted — that is the reply-source
# invariant the wildcard bind depends on, and for the DTLS listener a
# route-selected source would break the client's connected socket outright. The
# node-agent's direct-pod guard then admits a datagram to an enrolled pod only
# when it carries the relay's socket mark AND its source is one of the trusted
# node source IPs (`FERRUM_NODE_AGENT_NODE_IPS`, derived here from the node
# PodCIDR gateways by `discover_trusted_kubelet_probe_ips`). Probing the
# listener at an untrusted node address therefore produces a reply the node's
# own guard drops, which is the documented fail-closed contract, not a datapath
# defect. Probe at a trusted node source address so the relay can answer.
node_waypoint_listener_ip() {
  kubectl get node "$NODE_A" -o json | python3 -c '
import ipaddress
import json
import sys

node = json.load(sys.stdin)
spec = node.get("spec") or {}
cidrs = spec.get("podCIDRs") or []
if not cidrs and spec.get("podCIDR"):
    cidrs = [spec["podCIDR"]]
for raw in cidrs:
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        continue
    if network.version != 4:
        continue
    try:
        print(next(network.hosts()))
    except StopIteration:
        continue
    break
'
}

# Poll a probe until its reply matches (or stops matching) the expected prefix.
wait_for_udp_outcome_on() {
  local mode="$1" expected="$2" ns="$3" app="$4" listener_ip="$5" port="$6" payload="$7" budget="${8:-40}"
  local attempt reply
  for ((attempt = 0; attempt < budget; attempt++)); do
    reply="$(udp_probe_from "$ns" "$app" "$listener_ip" "$port" "$payload" 2)"
    case "$mode" in
      match)
        if [[ "$reply" == "$expected"* ]]; then
          printf '%s' "$reply"
          return 0
        fi
        ;;
      refuse)
        if [[ "$reply" == "TIMEOUT" ]]; then
          printf '%s' "$reply"
          return 0
        fi
        ;;
    esac
    sleep 3
  done
  printf '%s' "$reply"
  return 1
}

wait_for_udp_outcome() {
  wait_for_udp_outcome_on "$1" "$2" "$3" "$4" "$5" "$UDP_LISTENER_PORT" "$6" "${7:-40}"
}

run_node_waypoint_udp_datapath_checks() {
  log "running NodeWaypoint UDP listener datapath checks (issue #3286)"
  local listener_ip reply restarts_before restarts_after echo_pod_ip

  listener_ip="$(node_waypoint_listener_ip)"
  if [[ -z "$listener_ip" ]]; then
    record_live_assertion node_waypoint.udp.listener_allow_attributed_source fail \
      udp-src-a udp-echo "could not resolve a trusted node source address for the listener" \
      "" "" "node-waypoint-udp-listener"
    return 1
  fi
  echo_pod_ip="$(kubectl -n "$WORKLOAD_NS" get pod -l app=udp-echo \
    -o jsonpath='{.items[0].status.podIP}')"
  log "NodeWaypoint UDP listener target ${listener_ip}:${UDP_LISTENER_PORT} (backend $echo_pod_ip)"

  # 1. First construction: an admitted, attributed source reaches the backend.
  if ! reply="$(wait_for_udp_outcome match "udp-ok:ping-a" \
    "$WORKLOAD_NS" udp-src-a "$listener_ip" ping-a 40)"; then
    record_live_assertion node_waypoint.udp.listener_allow_attributed_source fail \
      udp-src-a udp-echo "observed=$reply" "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" \
      "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  local allow_backend_hits
  allow_backend_hits="$(udp_echo_backend_received ping-a)"
  if [[ "$allow_backend_hits" == "0" ]]; then
    record_live_assertion node_waypoint.udp.listener_allow_attributed_source fail \
      udp-src-a udp-echo "the echo arrived but the backend logged no datagram" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.listener_allow_attributed_source pass \
    udp-src-a udp-echo "observed=$reply backend_hits=$allow_backend_hits" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"

  # 1b. The ORDINARY user path (issue #3286 root review): an enrolled workload
  #     addressing its Service's ClusterIP — not a node address. Without the
  #     Service-path steering this cannot work at all: kube-proxy DNATs the
  #     ClusterIP to a backing pod and the pod-veth guard drops the unmarked
  #     datagram, so the workload sees a timeout. Passing therefore proves the
  #     steering rules diverted the datagram to the materialized listener with
  #     its original destination intact AND that the reply came back sourced
  #     from the ClusterIP (an unmarked or wrongly-sourced reply is dropped
  #     before the workload ever sees it). The check above stays as the distinct
  #     direct-node-address boundary.
  local service_ip service_reply service_backend_hits
  service_ip="$(kubectl -n "$WORKLOAD_NS" get svc udp-echo -o jsonpath='{.spec.clusterIP}')"
  if [[ -z "$service_ip" || "$service_ip" == "None" ]]; then
    record_live_assertion node_waypoint.udp.service_path_allow_attributed_source fail \
      udp-src-a udp-echo "the udp-echo Service publishes no ClusterIP to steer" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  log "NodeWaypoint UDP Service path target ${service_ip}:${UDP_LISTENER_PORT} (udp-echo ClusterIP)"
  if ! service_reply="$(wait_for_udp_outcome match "udp-ok:svc-a" \
    "$WORKLOAD_NS" udp-src-a "$service_ip" svc-a 40)"; then
    # A no-reply outcome has two very different causes and the backend log is
    # what separates them: zero hits means the steering rules never diverted the
    # datagram to the materialized listener, while a non-zero count means the
    # forward leg worked and only the ClusterIP-sourced reply was lost on the
    # way back to the enrolled source pod. Record it so the failure is
    # actionable from the job log alone.
    local unreplied_backend_hits
    unreplied_backend_hits="$(udp_echo_backend_received svc-a)"
    record_live_assertion node_waypoint.udp.service_path_allow_attributed_source fail \
      udp-src-a udp-echo \
      "service_ip=$service_ip observed=$service_reply backend_hits=$unreplied_backend_hits" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
    echo "[node-waypoint-ebpf-live] Service-path probe got no reply," \
      "backend observed $unreplied_backend_hits svc-a datagram(s)" >&2
    collect_traffic_failure_diagnostics
    return 1
  fi
  service_backend_hits="$(udp_echo_backend_received svc-a)"
  if [[ "$service_backend_hits" == "0" ]]; then
    record_live_assertion node_waypoint.udp.service_path_allow_attributed_source fail \
      udp-src-a udp-echo "the echo arrived but the backend logged no Service-path datagram" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.service_path_allow_attributed_source pass \
    udp-src-a udp-echo "service_ip=$service_ip observed=$service_reply backend_hits=$service_backend_hits" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"

  # 2. A source the scoped AuthorizationPolicy denies gets no datagram through.
  reply="$(udp_probe_from "$WORKLOAD_NS" udp-src-b "$listener_ip" "$UDP_LISTENER_PORT" ping-b 4)"
  if [[ "$reply" != "TIMEOUT" ]]; then
    record_live_assertion node_waypoint.udp.listener_deny_scoped_policy fail \
      udp-src-b udp-echo "observed=$reply" "$(spiffe_for_sa src-b)" "$(spiffe_for_sa dst-a)" \
      "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.listener_deny_scoped_policy pass \
    udp-src-b udp-echo "observed=$reply" "$(spiffe_for_sa src-b)" "$(spiffe_for_sa dst-a)" \
    "node-waypoint-udp-listener"

  # 3. An UNATTRIBUTABLE source (unenrolled pod, no registry binding for its
  #    veth) is refused while scoped enforcement applies.
  reply="$(udp_probe_from "$UNMANAGED_NS" udp-unmanaged "$listener_ip" "$UDP_LISTENER_PORT" ping-x 4)"
  if [[ "$reply" != "TIMEOUT" ]]; then
    record_live_assertion node_waypoint.udp.listener_deny_unattributed_source fail \
      udp-unmanaged udp-echo "observed=$reply" "" "$(spiffe_for_sa dst-a)" \
      "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  sleep 2
  local unattributed_backend_hits
  unattributed_backend_hits="$(udp_echo_backend_received ping-x)"
  if [[ "$unattributed_backend_hits" != "0" ]]; then
    record_live_assertion node_waypoint.udp.listener_deny_unattributed_source fail \
      udp-unmanaged udp-echo \
      "the refused datagram still reached the backend hits=$unattributed_backend_hits" "" \
      "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.listener_deny_unattributed_source pass \
    udp-unmanaged udp-echo "observed=$reply backend_hits=0" "" "$(spiffe_for_sa dst-a)" \
    "node-waypoint-udp-listener"

  # 4. The same unenrolled pod FORGING the admitted pod's source address is
  #    still refused: attribution is the kernel-reported ingress interface.
  local src_a_pod_ip spoof_reply
  src_a_pod_ip="$(kubectl -n "$WORKLOAD_NS" get pod -l app=udp-src-a \
    -o jsonpath='{.items[0].status.podIP}')"
  spoof_reply="$(udp_spoof_probe_from "$UNMANAGED_NS" udp-unmanaged "$listener_ip" \
    "$UDP_LISTENER_PORT" "$src_a_pod_ip" ping-spoof 4)"
  sleep 2
  local spoof_backend_hits
  spoof_backend_hits="$(udp_echo_backend_received ping-spoof)"
  # A refusal is only recorded when the forged datagram was ACTUALLY emitted
  # (`SPOOF-SENT:` is printed after `sendto` returns) and the backend proved it
  # never arrived. A sandbox that cannot forge fails the gate closed rather than
  # recording a refusal nothing attempted: the pod is granted NET_RAW
  # explicitly, so "no raw socket" is a broken environment, not a property of
  # the listener.
  case "$spoof_reply" in
    SPOOF-SENT:TIMEOUT)
      if [[ "$spoof_backend_hits" != "0" ]]; then
        record_live_assertion node_waypoint.udp.listener_deny_spoofed_source fail \
          udp-unmanaged udp-echo \
          "forged_source=$src_a_pod_ip reached the backend hits=$spoof_backend_hits" "" \
          "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
        collect_traffic_failure_diagnostics
        return 1
      fi
      record_live_assertion node_waypoint.udp.listener_deny_spoofed_source pass \
        udp-unmanaged udp-echo \
        "forged_source=$src_a_pod_ip emitted=true observed=TIMEOUT backend_hits=0" "" \
        "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
      ;;
    SPOOF-UNAVAILABLE)
      record_live_assertion node_waypoint.udp.listener_deny_spoofed_source fail \
        udp-unmanaged udp-echo \
        "no forged datagram could be emitted (raw socket unavailable despite NET_RAW), so no \
refusal was observed" "" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
      collect_traffic_failure_diagnostics
      return 1
      ;;
    *)
      record_live_assertion node_waypoint.udp.listener_deny_spoofed_source fail \
        udp-unmanaged udp-echo "forged_source=$src_a_pod_ip observed=$spoof_reply" "" \
        "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
      collect_traffic_failure_diagnostics
      return 1
      ;;
  esac

  # 4b. The actual pre-fix bypass (issues #3956, #3957): a HOST-NETWORK
  #     workload with NET_ADMIN forges the complete admission and sends
  #     DIRECTLY at the enrolled backend pod, bypassing the waypoint entirely.
  #
  #     Two shapes, one assertion, because the two competing fixes each closed
  #     one and left the other open:
  #       * node source + relay mark   (what #3957 removed, #3956 kept)
  #       * ClusterIP tuple + relay mark, replayed at a destination that
  #         Service never named (what #3956 removed, #3957 kept)
  #
  #     Both are refused only by the sender proof — `bpf_skb_cgroup_id()` names
  #     the forger's own cgroup, never the relay's. The backend log is the
  #     authority: a forged datagram addressed straight at the pod draws no
  #     reply either way, so absence of a reply proves nothing on its own.
  local forger_result forged_backend_hits shape
  for shape in node-source cluster-ip; do
    local forged_source forged_payload
    case "$shape" in
      node-source)
        forged_source="$listener_ip"
        forged_payload="ping-forged-node"
        ;;
      cluster-ip)
        forged_source="$service_ip"
        forged_payload="ping-forged-vip"
        ;;
    esac
    forger_result="$(udp_forged_relay_probe_from "$UNMANAGED_NS" udp-forger \
      "$echo_pod_ip" "$UDP_LISTENER_PORT" "$forged_source" \
      "$NODE_WAYPOINT_INBOUND_AUTH_MARK" "$forged_payload")"
    if [[ "$forger_result" != "FORGED-SENT" ]]; then
      record_live_assertion node_waypoint.udp.listener_deny_forged_relay_mark fail \
        udp-forger udp-echo \
        "shape=$shape no forged datagram could be emitted despite hostNetwork+NET_ADMIN+NET_RAW \
($forger_result), so no refusal was observed" "" "$(spiffe_for_sa dst-a)" \
        "node-waypoint-udp-listener"
      collect_traffic_failure_diagnostics
      return 1
    fi
    sleep 2
    forged_backend_hits="$(udp_echo_backend_received "$forged_payload")"
    if [[ "$forged_backend_hits" != "0" ]]; then
      record_live_assertion node_waypoint.udp.listener_deny_forged_relay_mark fail \
        udp-forger udp-echo \
        "shape=$shape forged_source=$forged_source mark=$NODE_WAYPOINT_INBOUND_AUTH_MARK \
reached the enrolled pod hits=$forged_backend_hits" "" "$(spiffe_for_sa dst-a)" \
        "node-waypoint-udp-listener"
      collect_traffic_failure_diagnostics
      return 1
    fi
  done
  record_live_assertion node_waypoint.udp.listener_deny_forged_relay_mark pass \
    udp-forger udp-echo \
    "host_netns_forgery emitted=true shapes=node-source,cluster-ip \
mark=$NODE_WAYPOINT_INBOUND_AUTH_MARK backend_hits=0" "" "$(spiffe_for_sa dst-a)" \
    "node-waypoint-udp-listener"

  # 5. Policy CHANGE: deny the previously admitted source and prove the live
  #    data plane converges with no restart.
  restarts_before="$(ambient_restart_total)"
  kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-src-a-udp
  namespace: $WORKLOAD_NS
spec:
  action: DENY
  rules:
    - from:
        - source:
            principals:
              - $TRUST_DOMAIN/ns/$WORKLOAD_NS/sa/src-a
EOF
  if ! reply="$(wait_for_udp_outcome refuse "" "$WORKLOAD_NS" udp-src-a "$listener_ip" ping-a 40)"; then
    kubectl -n "$WORKLOAD_NS" delete authorizationpolicy deny-src-a-udp --ignore-not-found=true
    record_live_assertion node_waypoint.udp.policy_change_denies_live fail \
      udp-src-a udp-echo "observed=$reply" "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" \
      "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  restarts_after="$(ambient_restart_total)"
  if [[ "$restarts_after" != "$restarts_before" ]]; then
    kubectl -n "$WORKLOAD_NS" delete authorizationpolicy deny-src-a-udp --ignore-not-found=true
    record_live_assertion node_waypoint.udp.policy_change_denies_live fail \
      udp-src-a udp-echo \
      "convergence required a data plane restart before=$restarts_before after=$restarts_after" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
    return 1
  fi
  record_live_assertion node_waypoint.udp.policy_change_denies_live pass \
    udp-src-a udp-echo \
    "observed=TIMEOUT ambient_restarts=$restarts_after (unchanged)" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"

  # 6. Policy WITHDRAWAL: removing it restores the datapath, still with no
  #    data-plane restart.
  kubectl -n "$WORKLOAD_NS" delete authorizationpolicy deny-src-a-udp --ignore-not-found=true
  if ! reply="$(wait_for_udp_outcome match "udp-ok:ping-a" \
    "$WORKLOAD_NS" udp-src-a "$listener_ip" ping-a 40)"; then
    record_live_assertion node_waypoint.udp.policy_withdrawal_recovers_live fail \
      udp-src-a udp-echo "observed=$reply" "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" \
      "node-waypoint-udp-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  restarts_after="$(ambient_restart_total)"
  if [[ "$restarts_after" != "$restarts_before" ]]; then
    record_live_assertion node_waypoint.udp.policy_withdrawal_recovers_live fail \
      udp-src-a udp-echo \
      "recovery required a data plane restart before=$restarts_before after=$restarts_after" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
    return 1
  fi
  record_live_assertion node_waypoint.udp.policy_withdrawal_recovers_live pass \
    udp-src-a udp-echo \
    "observed=$reply ambient_restarts=$restarts_after (unchanged)" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-listener"
}

# ── NodeWaypoint DTLS listener datapath (issue #3286) ───────────────────────
#
# The DTLS half of the same listener family. `dtls-echo` is an in-mesh Service
# whose `protocol: UDP` port carries `appProtocol: dtls`, so
# `materialize_node_waypoint_udp_listeners` gives its listener
# `frontend_tls: true`: the NodeWaypoint TERMINATES DTLS on the host-netns
# socket and forwards PLAINTEXT datagrams to the backing pod. Everything below
# is observed from a REAL `openssl s_client -dtls1_2` handshake and real
# application data, never from rendered config:
#
#   * the listener actually bound and presents the operator DTLS material;
#   * an ADMITTED enrolled source completes the handshake and its decrypted
#     datagram reaches the backend, which logs it;
#   * a source the namespace-scoped `deny-src-b` AuthorizationPolicy names
#     reaches the backend with NOTHING, proving scoped source authorization is
#     enforced on the DTLS path and not only on plain UDP.
#
# The frontend socket also has to carry NODE_WAYPOINT_INBOUND_AUTH_MARK, since
# the DtlsServer owns the socket every encrypted record leaves from; an unmarked
# one would be dropped by the pod-veth guard and the allow case below could not
# pass.
#
# These three probe a trusted NODE address. That is a real but DISTINCT
# boundary and is deliberately NOT substitute evidence for the ordinary user
# path — the Service DNS name / ClusterIP — which
# `run_node_waypoint_dtls_service_path_checks` proves separately.

# Machine-classifiable DTLS handshake capture (stdout+stderr+exit).
#
# OpenSSL semantics used here (openssl 3 s_client):
# - `CONNECTED(...)` is printed as soon as the UDP socket is connected. For
#   DTLS that is a local connect(2) and does NOT prove a peer exists, so it
#   is not used as listener identity.
# - `-brief` sets quiet mode (bio_c_out discarded) and prints
#   `CONNECTION ESTABLISHED` plus `print_ssl_summary` to stderr ONLY after
#   `SSL_is_init_finished`. That is the positive completed-handshake marker.
# - `-brief` also sets verify quiet, but the verify callback still prints
#   `depth=0 CN=...` when verification is NOT ok. The generated listener's
#   throwaway leaf is self-signed, so CN=ferrum-node-waypoint-dtls remains
#   visible on an incomplete handshake that reached our Certificate flight.
# - `-timeout` enables DTLS BIO send/recv timeouts so an unfinished
#   handshake retransmits instead of blocking on a silent peer forever.
# - `-no_ign_eof` undoes the `-brief`/`-quiet` ign_eof default so a
#   completed handshake exits when kubectl exec provides no stdin, instead
#   of hanging until the outer timeout.
# - The wrapper `timeout` is the hard bound. Its status is appended as
#   `FERRUM_DTLS_HS_RC:` locally so kubectl/exec/image failures stay
#   distinguishable from a finished handshake.
DTLS_GENERATED_LISTENER_CN="ferrum-node-waypoint-dtls"
DTLS_HS_RC_MARKER="FERRUM_DTLS_HS_RC:"

dtls_handshake_report_from() {
  local ns="$1" app="$2" target_ip="$3" port="$4" wait_secs="${5:-8}"
  local cert="${6:-}" key="${7:-}"
  local -a extra=()
  local report rc
  if [[ -n "$cert" && -n "$key" ]]; then
    extra=(-cert "$cert" -key "$key")
  fi
  report=""
  rc=0
  set +e
  report="$(kubectl -n "$ns" exec "deploy/$app" -c dtls -- \
    timeout "$wait_secs" openssl s_client -dtls1_2 -brief -timeout -no_ign_eof \
      -connect "$target_ip:$port" "${extra[@]}" 2>&1)"
  rc=$?
  set -e
  printf '%s\n%s%s\n' "$report" "$DTLS_HS_RC_MARKER" "$rc"
}

# Complete a DTLS handshake and send one application datagram; print whatever
# application data comes back (empty when the session is denied or dropped).
#
# `-quiet` implies `-ign_eof`, so s_client keeps reading after stdin closes and
# `timeout` bounds the wait. The server certificate is deliberately NOT
# verified: this exercises the datagram datapath and its scoped source
# authorization, not PKI trust, and the material is a per-run throwaway leaf.
# Optional cert/key (args 7/8) present a client certificate for STRICT mTLS.
dtls_probe_from() {
  local ns="$1" app="$2" target_ip="$3" port="$4" payload="$5" wait_secs="${6:-8}"
  local cert="${7:-}" key="${8:-}"
  local -a extra=()
  if [[ -n "$cert" && -n "$key" ]]; then
    extra=(-cert "$cert" -key "$key")
  fi
  printf '%s\n' "$payload" | kubectl -n "$ns" exec -i "deploy/$app" -c dtls -- \
    timeout "$wait_secs" openssl s_client -dtls1_2 \
      -connect "$target_ip:$port" "${extra[@]}" -quiet 2>/dev/null \
    || true
}

dtls_backend_received() {
  local ns="$1" deploy="$2" payload="$3"
  kubectl -n "$ns" logs "deploy/$deploy" --tail=-1 2>/dev/null |
    grep -c "^recv:${payload}$" || true
}

# How many decrypted datagrams carrying `payload` the dtls-echo backend received.
# Reply-absence alone would not distinguish "denied before the backend" from
# "reply lost", so the backend log is the authority for the deny case.
dtls_echo_backend_received() {
  dtls_backend_received "$WORKLOAD_NS" dtls-echo "$1"
}

wait_for_dtls_echo_on() {
  local ns="$1" app="$2" listener_ip="$3" port="$4" expected_prefix="$5" payload="$6"
  local budget="${7:-20}" cert="${8:-}" key="${9:-}"
  local attempt reply
  for ((attempt = 0; attempt < budget; attempt++)); do
    reply="$(dtls_probe_from "$ns" "$app" "$listener_ip" "$port" "$payload" 6 "$cert" "$key")"
    if [[ "$reply" == *"${expected_prefix}${payload}"* ]]; then
      printf '%s' "$reply"
      return 0
    fi
    sleep 3
  done
  printf '%s' "$reply"
  return 1
}

wait_for_dtls_echo() {
  wait_for_dtls_echo_on "$1" "$2" "$3" "$DTLS_LISTENER_PORT" "dtls-ok:" "$4" "${5:-20}"
}

dtls_handshake_rc() {
  local report="$1"
  local line
  line="$(printf '%s\n' "$report" | sed -n "s/^${DTLS_HS_RC_MARKER}//p" | tail -n1)"
  printf '%s' "${line:-missing}"
}

# Positive completed-handshake evidence. Seeing the generated CN is NOT enough:
# the Certificate message arrives before client authentication finishes, which
# is exactly the hosted false-fail (CN presented, then the remote timeout
# killed the client with no CONNECTION ESTABLISHED).
dtls_handshake_completed() {
  local report="$1"
  [[ "$report" == *"CONNECTION ESTABLISHED"* \
    && "$report" == *"Protocol version: DTLS"* \
    && "$report" == *"${DTLS_GENERATED_LISTENER_CN}"* \
    && "$report" != *"Ciphersuite: (NONE)"* \
    && "$report" != *"Cipher is (NONE)"* ]]
}

# The generated listener presented its throwaway leaf. UDP CONNECTED is not
# this check: connect(2) on SOCK_DGRAM succeeds with no peer.
dtls_reached_generated_listener() {
  local report="$1"
  [[ "$report" == *"${DTLS_GENERATED_LISTENER_CN}"* ]]
}

# DNS/connectivity/exec/image/listener outages. Must not count as a STRICT pass.
# UDP CONNECTED is not identity, so anything that did not present the generated
# leaf and did not finish the handshake is treated as inconclusive/outage.
dtls_handshake_outage() {
  local report="$1"
  dtls_handshake_completed "$report" && return 1
  dtls_reached_generated_listener "$report" && return 1
  return 0
}

# Handshake started against OUR generated listener and did not finish.
# Alert strings are sufficient but not required: rustls may drop an
# unauthenticated STRICT session without printing handshake failure.
dtls_handshake_incomplete_against_generated_listener() {
  local report="$1"
  dtls_reached_generated_listener "$report" || return 1
  dtls_handshake_completed "$report" && return 1
  return 0
}

dtls_report_snippet() {
  local rc
  rc="$(dtls_handshake_rc "$1")"
  printf 'rc=%s %s' "$rc" "$(printf '%s' "$1" | sed '/-----BEGIN/,/-----END/d' | tr '\n' ' ' | cut -c1-240)"
}

# ── The ORDINARY user path for DTLS: the Service DNS name / ClusterIP ───────
#
# Everything above targets a trusted NODE address, which is a deliberate but
# NARROW boundary — no workload dials a node IP to reach a Service. The checks
# below drive the same production listener through the address a workload
# actually uses, which only works when the Service-path steering diverted the
# datagram with its original destination intact AND every encrypted record came
# back sourced from that ClusterIP (a `connect()`ed DTLS client discards a
# record arriving from any other source, so a wrong reply source is
# indistinguishable from no listener at all).
#
# The DNS name is resolved BY THE CLIENT POD, so a passing check also proves the
# ordinary discovery path reaches the steered address rather than a hardcoded
# one.
run_node_waypoint_dtls_service_path_checks() {
  log "running NodeWaypoint DTLS Service-path datapath checks (issue #3286 root review)"
  local service_dns service_ip reply hits

  service_dns="dtls-echo.${WORKLOAD_NS}.svc.cluster.local"
  service_ip="$(kubectl -n "$WORKLOAD_NS" get svc dtls-echo -o jsonpath='{.spec.clusterIP}')"
  if [[ -z "$service_ip" || "$service_ip" == "None" ]]; then
    record_live_assertion node_waypoint.dtls.service_path_allow_attributed_source fail \
      dtls-src-a dtls-echo "the dtls-echo Service publishes no ClusterIP to steer" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  log "NodeWaypoint DTLS Service path target ${service_dns} (${service_ip}:${DTLS_LISTENER_PORT})"

  # 1. Admitted, attributed source addressing the Service DNS NAME. openssl
  #    resolves it in the pod, handshakes through the steered listener, and the
  #    backend logs the decrypted datagram it relayed.
  if ! reply="$(wait_for_dtls_echo "$WORKLOAD_NS" dtls-src-a "$service_dns" dtls-svc-a 20)"; then
    record_live_assertion node_waypoint.dtls.service_path_allow_attributed_source fail \
      dtls-src-a dtls-echo "service_dns=$service_dns service_ip=$service_ip observed=$reply" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  hits="$(dtls_echo_backend_received dtls-svc-a)"
  if [[ "$hits" == "0" ]]; then
    record_live_assertion node_waypoint.dtls.service_path_allow_attributed_source fail \
      dtls-src-a dtls-echo \
      "the echo arrived but the backend logged no Service-path decrypted datagram" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.service_path_allow_attributed_source pass \
    dtls-src-a dtls-echo \
    "service_dns=$service_dns service_ip=$service_ip observed=dtls-ok backend_hits=$hits" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"

  # 2. A source the namespace-scoped policy denies reaches the same steered
  #    listener and is refused there. Reply-absence alone would be vacuous, so
  #    the backend log is the authority.
  reply="$(dtls_probe_from "$WORKLOAD_NS" dtls-src-b "$service_dns" "$DTLS_LISTENER_PORT" \
    dtls-svc-b 8)"
  sleep 2
  hits="$(dtls_echo_backend_received dtls-svc-b)"
  if [[ "$reply" == *"dtls-ok:dtls-svc-b"* || "$hits" != "0" ]]; then
    record_live_assertion node_waypoint.dtls.service_path_deny_scoped_policy fail \
      dtls-src-b dtls-echo "observed=$reply backend_hits=$hits" \
      "$(spiffe_for_sa src-b)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.service_path_deny_scoped_policy pass \
    dtls-src-b dtls-echo "no application data returned and backend_hits=0" \
    "$(spiffe_for_sa src-b)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"

  # 3. An UNENROLLED source. No steering rule names its interface, so its
  #    datagram takes the pre-existing path: kube-proxy DNATs the ClusterIP to
  #    the backing pod and the pod-veth guard drops it. Nothing reaches the
  #    backend and no application data comes back — the fail-closed contract,
  #    proven for the Service address rather than only for a node address.
  reply="$(dtls_probe_from "$UNMANAGED_NS" dtls-unmanaged "$service_dns" "$DTLS_LISTENER_PORT" \
    dtls-svc-x 8)"
  sleep 2
  hits="$(dtls_echo_backend_received dtls-svc-x)"
  if [[ "$reply" == *"dtls-ok:dtls-svc-x"* || "$hits" != "0" ]]; then
    record_live_assertion node_waypoint.dtls.service_path_deny_unattributed_source fail \
      dtls-unmanaged dtls-echo "observed=$reply backend_hits=$hits" "" \
      "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.service_path_deny_unattributed_source pass \
    dtls-unmanaged dtls-echo "no application data returned and backend_hits=0" "" \
    "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
}

run_node_waypoint_dtls_datapath_checks() {
  log "running NodeWaypoint DTLS listener datapath checks (issue #3286)"
  local listener_ip report reply attempt

  listener_ip="$(node_waypoint_listener_ip)"
  if [[ -z "$listener_ip" ]]; then
    record_live_assertion node_waypoint.dtls.listener_bound fail \
      dtls-src-a dtls-echo "could not resolve a trusted node source address for the listener" \
      "" "" "node-waypoint-dtls-listener"
    return 1
  fi
  log "NodeWaypoint DTLS listener target ${listener_ip}:${DTLS_LISTENER_PORT}"

  # 1. The materialized `dtls` listener really bound and terminates DTLS with
  #    the operator-supplied material. Positive proof is a completed
  #    `-brief` handshake (`CONNECTION ESTABLISHED`) that presents the
  #    generated leaf. Seeing the CN alone is the Certificate flight, not
  #    handshake completion.
  report=""
  for ((attempt = 0; attempt < 20; attempt++)); do
    report="$(dtls_handshake_report_from "$WORKLOAD_NS" dtls-src-a "$listener_ip" \
      "$DTLS_LISTENER_PORT" 10)"
    if dtls_handshake_completed "$report"; then
      break
    fi
    sleep 4
  done
  if ! dtls_handshake_completed "$report"; then
    local snippet
    snippet="$(dtls_report_snippet "$report")"
    record_live_assertion node_waypoint.dtls.listener_bound fail \
      dtls-src-a dtls-echo \
      "no DTLS handshake completed on ${listener_ip}:${DTLS_LISTENER_PORT}, last probe=${snippet}" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.listener_bound pass \
    dtls-src-a dtls-echo \
    "dtls1.2 handshake completed against the materialized listener with the operator DTLS \
material" "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"

  # 2. An admitted, attributed source: handshake, decrypt, relay, echo — and the
  #    backend logs the plaintext datagram it received.
  if ! reply="$(wait_for_dtls_echo "$WORKLOAD_NS" dtls-src-a "$listener_ip" dtls-a 20)"; then
    record_live_assertion node_waypoint.dtls.listener_allow_attributed_source fail \
      dtls-src-a dtls-echo "observed=$reply" "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" \
      "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  local dtls_allow_hits
  dtls_allow_hits="$(dtls_echo_backend_received dtls-a)"
  if [[ "$dtls_allow_hits" == "0" ]]; then
    record_live_assertion node_waypoint.dtls.listener_allow_attributed_source fail \
      dtls-src-a dtls-echo "the echo arrived but the backend logged no decrypted datagram" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.listener_allow_attributed_source pass \
    dtls-src-a dtls-echo "observed=dtls-ok backend_hits=$dtls_allow_hits" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"

  # 3. A source the namespace-scoped policy denies gets nothing through, and —
  #    the load-bearing half — the backend never sees its datagram.
  reply="$(dtls_probe_from "$WORKLOAD_NS" dtls-src-b "$listener_ip" "$DTLS_LISTENER_PORT" dtls-b 8)"
  sleep 2
  local dtls_deny_hits
  dtls_deny_hits="$(dtls_echo_backend_received dtls-b)"
  if [[ "$reply" == *"dtls-ok:dtls-b"* || "$dtls_deny_hits" != "0" ]]; then
    record_live_assertion node_waypoint.dtls.listener_deny_scoped_policy fail \
      dtls-src-b dtls-echo "observed=$reply backend_hits=$dtls_deny_hits" \
      "$(spiffe_for_sa src-b)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.listener_deny_scoped_policy pass \
    dtls-src-b dtls-echo "no application data returned and backend_hits=0" \
    "$(spiffe_for_sa src-b)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-listener"
}

service_cluster_ip() {
  local ns="$1" svc="$2" family="$3"
  kubectl -n "$ns" get svc "$svc" -o json | python3 -c '
import ipaddress
import json
import sys

family = int(sys.argv[1])
svc = json.load(sys.stdin)
spec = svc.get("spec") or {}
ips = list(spec.get("clusterIPs") or [])
cip = spec.get("clusterIP")
if cip and cip != "None":
    ips = list(dict.fromkeys(ips + [cip]))
for raw in ips:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        continue
    if ip.version == family:
        print(raw)
        break
' "$family"
}

udp_shared_tuple_probe() {
  local ns="$1" app="$2" ip_a="$3" ip_b="$4" port="$5" payload_a="$6" payload_b="$7" wait_secs="${8:-3}"
  kubectl -n "$ns" exec "deploy/$app" -c udp -- python -u -c '
import socket
import sys

ip_a, ip_b, port, pa, pb, wait = (
    sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], float(sys.argv[6])
)
ip_a = ip_a.strip("[]")
ip_b = ip_b.strip("[]")
family = socket.AF_INET6 if ":" in ip_a else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM)
s.bind(("::", 0) if family == socket.AF_INET6 else ("0.0.0.0", 0))
s.settimeout(wait)

def addr(ip):
    return (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)

out = []
try:
    s.sendto(pa.encode(), addr(ip_a))
    data, _ = s.recvfrom(2048)
    out.append("A:" + data.decode("utf-8", "replace"))
except socket.timeout:
    out.append("A:TIMEOUT")
except OSError as exc:
    out.append("A:OSERROR:%s" % exc.errno)
try:
    s.sendto(pb.encode(), addr(ip_b))
    data, _ = s.recvfrom(2048)
    out.append("B:" + data.decode("utf-8", "replace"))
except socket.timeout:
    out.append("B:TIMEOUT")
except OSError as exc:
    out.append("B:OSERROR:%s" % exc.errno)
sys.stdout.write("|".join(out))
' "$ip_a" "$ip_b" "$port" "$payload_a" "$payload_b" "$wait_secs" 2>/dev/null || echo "EXECFAIL"
}

# Same-port UDP Service demultiplexing (issue #3861): two compatible plain-UDP
# Services, distinct ClusterIPs, one numeric port, distinct backends. Proof is
# the backend logs plus the echo prefix, never reply-absence alone.
run_node_waypoint_udp_same_port_demux_checks() {
  log "running NodeWaypoint same-port UDP Service demultiplex checks (issue #3861)"
  local ip_a ip_b reply hits_a hits_b restarts_before restarts_after

  ip_a="$(service_cluster_ip "$WORKLOAD_NS" udp-demux-a 4)"
  ip_b="$(service_cluster_ip "$WORKLOAD_NS" udp-demux-b 4)"
  if [[ -z "$ip_a" || -z "$ip_b" || "$ip_a" == "$ip_b" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_serves_a fail \
      udp-src-a udp-demux-a "ClusterIPs are missing or not distinct ipv4_a=$ip_a ipv4_b=$ip_b" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  log "same-port UDP demux IPv4 ${ip_a}:${DEMUX_UDP_PORT} vs ${ip_b}:${DEMUX_UDP_PORT}"

  if ! reply="$(wait_for_udp_outcome_on match "demux-a:demux-ping-a" \
    "$WORKLOAD_NS" udp-src-a "$ip_a" "$DEMUX_UDP_PORT" demux-ping-a 40)"; then
    record_live_assertion node_waypoint.udp.same_port_demux_serves_a fail \
      udp-src-a udp-demux-a "observed=$reply cluster_ip=$ip_a" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  hits_a="$(udp_backend_received "$WORKLOAD_NS" udp-demux-a demux-ping-a)"
  hits_b="$(udp_backend_received "$WORKLOAD_NS" udp-demux-b demux-ping-a)"
  if [[ "$hits_a" == "0" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_serves_a fail \
      udp-src-a udp-demux-a "echo arrived but backend A logged no datagram" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.same_port_demux_serves_a pass \
    udp-src-a udp-demux-a "cluster_ip=$ip_a observed=$reply backend_hits=$hits_a" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"

  if ! reply="$(wait_for_udp_outcome_on match "demux-b:demux-ping-b" \
    "$WORKLOAD_NS" udp-src-a "$ip_b" "$DEMUX_UDP_PORT" demux-ping-b 40)"; then
    record_live_assertion node_waypoint.udp.same_port_demux_serves_b fail \
      udp-src-a udp-demux-b "observed=$reply cluster_ip=$ip_b" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  hits_b="$(udp_backend_received "$WORKLOAD_NS" udp-demux-b demux-ping-b)"
  hits_a="$(udp_backend_received "$WORKLOAD_NS" udp-demux-a demux-ping-b)"
  if [[ "$hits_b" == "0" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_serves_b fail \
      udp-src-a udp-demux-b "echo arrived but backend B logged no datagram" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.same_port_demux_serves_b pass \
    udp-src-a udp-demux-b "cluster_ip=$ip_b observed=$reply backend_hits=$hits_b" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"

  if [[ "$hits_a" != "0" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_isolated fail \
      udp-src-a udp-demux-a "payload for B reached backend A hits=$hits_a" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  hits_b="$(udp_backend_received "$WORKLOAD_NS" udp-demux-b demux-ping-a)"
  if [[ "$hits_b" != "0" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_isolated fail \
      udp-src-a udp-demux-b "payload for A reached backend B hits=$hits_b" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.same_port_demux_isolated pass \
    udp-src-a udp-demux-a "A payload only on A, B payload only on B" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"

  local shared
  if ! shared="$(udp_shared_tuple_probe "$WORKLOAD_NS" udp-src-a "$ip_a" "$ip_b" \
    "$DEMUX_UDP_PORT" demux-shared-a demux-shared-b 3)"; then
    shared="EXECFAIL"
  fi
  hits_a="$(udp_backend_received "$WORKLOAD_NS" udp-demux-a demux-shared-a)"
  hits_b="$(udp_backend_received "$WORKLOAD_NS" udp-demux-b demux-shared-b)"
  local misroute_a misroute_b
  misroute_a="$(udp_backend_received "$WORKLOAD_NS" udp-demux-b demux-shared-a)"
  misroute_b="$(udp_backend_received "$WORKLOAD_NS" udp-demux-a demux-shared-b)"
  if [[ "$shared" != *"A:demux-a:demux-shared-a"* || "$shared" != *"B:demux-b:demux-shared-b"* \
    || "$hits_a" == "0" || "$hits_b" == "0" || "$misroute_a" != "0" || "$misroute_b" != "0" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_shared_client_tuple fail \
      udp-src-a udp-demux-a "observed=$shared hits_a=$hits_a hits_b=$hits_b misroute_a=$misroute_a misroute_b=$misroute_b" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.same_port_demux_shared_client_tuple pass \
    udp-src-a udp-demux-a "one bound client socket addressed both ClusterIPs without collision" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"

  restarts_before="$(ambient_restart_total)"
  kubectl -n "$WORKLOAD_NS" delete svc udp-demux-a --wait=true --timeout=60s
  # Convergence polls use a dedicated payload so pre-convergence datagrams that
  # still reach backend A cannot pollute the post-convergence backend evidence.
  if ! reply="$(wait_for_udp_outcome_on refuse "" \
    "$WORKLOAD_NS" udp-src-a "$ip_a" "$DEMUX_UDP_PORT" demux-retract-converge-a 40)"; then
    record_live_assertion node_waypoint.udp.same_port_demux_retract_a_keeps_b fail \
      udp-src-a udp-demux-a "ClusterIP A still answered after Service delete observed=$reply" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  reply="$(udp_probe_from "$WORKLOAD_NS" udp-src-a "$ip_a" "$DEMUX_UDP_PORT" demux-retract-proof-a 2)"
  if [[ "$reply" != "TIMEOUT" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_retract_a_keeps_b fail \
      udp-src-a udp-demux-a "ClusterIP A still answered after convergence observed=$reply" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  hits_a="$(udp_backend_received "$WORKLOAD_NS" udp-demux-a demux-retract-proof-a)"
  if [[ "$hits_a" != "0" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_retract_a_keeps_b fail \
      udp-src-a udp-demux-a "backend A still received demux-retract-proof-a after Service delete" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  if ! reply="$(wait_for_udp_outcome_on match "demux-b:demux-keep-b" \
    "$WORKLOAD_NS" udp-src-a "$ip_b" "$DEMUX_UDP_PORT" demux-keep-b 40)"; then
    record_live_assertion node_waypoint.udp.same_port_demux_retract_a_keeps_b fail \
      udp-src-a udp-demux-b "B stopped serving after A was retracted observed=$reply" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  hits_b="$(udp_backend_received "$WORKLOAD_NS" udp-demux-b demux-keep-b)"
  hits_a="$(udp_backend_received "$WORKLOAD_NS" udp-demux-a demux-keep-b)"
  restarts_after="$(ambient_restart_total)"
  if [[ "$hits_b" == "0" || "$hits_a" != "0" || "$restarts_before" != "$restarts_after" ]]; then
    record_live_assertion node_waypoint.udp.same_port_demux_retract_a_keeps_b fail \
      udp-src-a udp-demux-b \
      "hits_b=$hits_b hits_a=$hits_a restarts_before=$restarts_before restarts_after=$restarts_after" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.udp.same_port_demux_retract_a_keeps_b pass \
    udp-src-a udp-demux-b \
    "A retracted cluster_ip=$ip_a, B still isolated on $ip_b, ambient restarts unchanged=$restarts_after" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-udp-same-port-demux"
}

frontend_dtls_reload_generation() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
gen = ((data.get("stream_listeners") or {}).get("frontend_dtls_reload") or {}).get("generation")
if gen is None:
    sys.exit(1)
print(gen)
PY
}

health_ready() {
  local file="$1"
  python3 - "$file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
sys.exit(0 if data.get("ready") is True else 1)
PY
}

# NodeWaypoint DTLS owner-scoped reload (issue #3858): generated dtls-echo
# moves PERMISSIVE → STRICT for NEW sessions (current client CA required).
# Ordinary-slot isolation is the authenticated /overload
# stream_listeners.frontend_dtls_reload.generation captured before and after
# that generated-owner publication — not a bound operator listener handshake.
# Generated success requires CONNECTION ESTABLISHED plus backend log.
# Unauthenticated/stale-CA rejection requires an incomplete handshake against
# the generated listener PLUS backend_hits=0 and no application reply.
# Reply-absence plus zero hits alone is not a pass: that is also what an
# authorization drop after a successful unauthenticated handshake, or a
# DNS/exec/listener outage, would look like.
run_node_waypoint_dtls_reload_isolation_checks() {
  log "running NodeWaypoint DTLS owner-scoped reload isolation checks (issue #3858)"
  local listener_ip current_cert current_key stale_cert stale_key
  local overload_before overload_after health_file report reply hits
  local gen_before gen_after restarts_before restarts_after attempt payload snippet
  local ambient_pod stale_payload

  listener_ip="$(node_waypoint_listener_ip)"
  if [[ -z "$listener_ip" ]]; then
    record_live_assertion node_waypoint.dtls.reload_permissive_to_strict fail \
      dtls-src-a dtls-echo "could not resolve a trusted node source address" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    return 1
  fi
  current_cert="$DTLS_CLIENT_MOUNT_PATH/current.crt"
  current_key="$DTLS_CLIENT_MOUNT_PATH/current.key"
  stale_cert="$DTLS_CLIENT_MOUNT_PATH/stale.crt"
  stale_key="$DTLS_CLIENT_MOUNT_PATH/stale.key"
  overload_before="$RESULTS_DIR/dtls-reload-overload-before.json"
  overload_after="$RESULTS_DIR/dtls-reload-overload-after.json"
  health_file="$RESULTS_DIR/dtls-reload-health.json"
  ambient_pod="$(ambient_pod_on_node "$NODE_A")"
  restarts_before="$(ambient_restart_total)"

  if ! fetch_ambient_admin_json "$NODE_A" /health "$health_file" \
    || ! health_ready "$health_file"; then
    record_live_assertion node_waypoint.dtls.operator_isolated_across_reload fail \
      dtls-src-a dtls-echo "authenticated /health was not ready on $ambient_pod" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  if ! fetch_ambient_admin_json "$NODE_A" /overload "$overload_before"; then
    record_live_assertion node_waypoint.dtls.operator_isolated_across_reload fail \
      dtls-src-a dtls-echo "could not fetch authenticated /overload before generated-owner publication" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  gen_before="$(frontend_dtls_reload_generation "$overload_before")" || gen_before=""
  # 0 is a valid captured ordinary-slot generation (none published yet).
  if [[ -z "$gen_before" ]]; then
    record_live_assertion node_waypoint.dtls.operator_isolated_across_reload fail \
      dtls-src-a dtls-echo "frontend_dtls_reload.generation missing from /overload before generated-owner publication" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi

  kubectl -n "$WORKLOAD_NS" get peerauthentication dtls-echo -o json | python3 -c '
import json
import sys

obj = json.load(sys.stdin)
spec = obj.get("spec") or {}
spec.pop("portLevelMtls", None)
spec["mtls"] = {"mode": "STRICT"}
obj["spec"] = spec
obj.pop("status", None)
print(json.dumps(obj))
' | kubectl apply -f -

  payload=""
  report=""
  reply=""
  hits="0"
  for ((attempt = 0; attempt < 20; attempt++)); do
    payload="dtls-reload-unauth-${attempt}"
    report="$(dtls_handshake_report_from "$WORKLOAD_NS" dtls-src-a "$listener_ip" \
      "$DTLS_LISTENER_PORT" 4)"
    if dtls_handshake_completed "$report"; then
      # Still PERMISSIVE: unauthenticated handshake finished. Wait for STRICT.
      sleep 3
      continue
    fi
    if dtls_handshake_outage "$report"; then
      sleep 3
      continue
    fi
    if dtls_handshake_incomplete_against_generated_listener "$report"; then
      # Same conclusive incomplete-handshake state: do not spend another
      # full quiet-probe timeout before classifying. A short application
      # probe plus the backend log still prove no plaintext mutation.
      reply="$(dtls_probe_from "$WORKLOAD_NS" dtls-src-a "$listener_ip" \
        "$DTLS_LISTENER_PORT" "$payload" 2)"
      hits="$(dtls_echo_backend_received "$payload")"
      if [[ "$reply" != *"dtls-ok:$payload"* && "$hits" == "0" ]]; then
        break
      fi
    fi
    sleep 3
  done
  if dtls_handshake_completed "$report"; then
    snippet="$(dtls_report_snippet "$report")"
    record_live_assertion node_waypoint.dtls.reload_permissive_to_strict fail \
      dtls-src-a dtls-echo "generated listener still admitted unauthenticated traffic observed=$reply hits=$hits report=${snippet}" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  if dtls_handshake_outage "$report" \
    || ! dtls_handshake_incomplete_against_generated_listener "$report" \
    || [[ "$reply" == *"dtls-ok:$payload"* || "$hits" != "0" ]]; then
    snippet="$(dtls_report_snippet "$report")"
    record_live_assertion node_waypoint.dtls.reload_permissive_to_strict fail \
      dtls-src-a dtls-echo "STRICT unauthenticated rejection was not proved observed=$reply hits=$hits report=${snippet}" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.reload_permissive_to_strict pass \
    dtls-src-a dtls-echo "generated listener moved to STRICT, unauthenticated handshake failed closed, backend_hits=0" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
  record_live_assertion node_waypoint.dtls.reload_unauthenticated_rejected pass \
    dtls-src-a dtls-echo "payload=$payload backend_hits=0 handshake did not complete" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"

  if ! reply="$(wait_for_dtls_echo_on "$WORKLOAD_NS" dtls-src-a "$listener_ip" \
    "$DTLS_LISTENER_PORT" "dtls-ok:" dtls-reload-current 20 \
    "$current_cert" "$current_key")"; then
    record_live_assertion node_waypoint.dtls.reload_current_ca_admitted fail \
      dtls-src-a dtls-echo "observed=$reply" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  hits="$(dtls_echo_backend_received dtls-reload-current)"
  report="$(dtls_handshake_report_from "$WORKLOAD_NS" dtls-src-a "$listener_ip" \
    "$DTLS_LISTENER_PORT" 10 "$current_cert" "$current_key")"
  if [[ "$hits" == "0" ]] || ! dtls_handshake_completed "$report"; then
    snippet="$(dtls_report_snippet "$report")"
    record_live_assertion node_waypoint.dtls.reload_current_ca_admitted fail \
      dtls-src-a dtls-echo "backend_hits=$hits report=${snippet}" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.reload_current_ca_admitted pass \
    dtls-src-a dtls-echo "current-CA handshake admitted, backend_hits=$hits" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"

  report=""
  reply=""
  hits="0"
  stale_payload=""
  for ((attempt = 0; attempt < 5; attempt++)); do
    stale_payload="dtls-reload-stale-${attempt}"
    report="$(dtls_handshake_report_from "$WORKLOAD_NS" dtls-src-a "$listener_ip" \
      "$DTLS_LISTENER_PORT" 4 "$stale_cert" "$stale_key")"
    if dtls_handshake_outage "$report"; then
      sleep 2
      continue
    fi
    if dtls_handshake_completed "$report"; then
      break
    fi
    if dtls_handshake_incomplete_against_generated_listener "$report"; then
      reply="$(dtls_probe_from "$WORKLOAD_NS" dtls-src-a "$listener_ip" \
        "$DTLS_LISTENER_PORT" "$stale_payload" 2 "$stale_cert" "$stale_key")"
      hits="$(dtls_echo_backend_received "$stale_payload")"
      if [[ "$reply" != *"dtls-ok:$stale_payload"* && "$hits" == "0" ]]; then
        break
      fi
    fi
    sleep 2
  done
  if dtls_handshake_completed "$report" \
    || dtls_handshake_outage "$report" \
    || ! dtls_handshake_incomplete_against_generated_listener "$report" \
    || [[ "$reply" == *"dtls-ok:$stale_payload"* || "$hits" != "0" ]]; then
    snippet="$(dtls_report_snippet "$report")"
    record_live_assertion node_waypoint.dtls.reload_stale_ca_rejected fail \
      dtls-src-a dtls-echo "observed=$reply backend_hits=$hits report=${snippet}" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.reload_stale_ca_rejected pass \
    dtls-src-a dtls-echo "stale client CA rejected on generated listener, backend_hits=0" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"

  if ! fetch_ambient_admin_json "$NODE_A" /overload "$overload_after"; then
    record_live_assertion node_waypoint.dtls.operator_isolated_across_reload fail \
      dtls-src-a dtls-echo "could not fetch authenticated /overload after generated-owner publication" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  gen_after="$(frontend_dtls_reload_generation "$overload_after")" || gen_after=""
  restarts_after="$(ambient_restart_total)"
  if [[ -z "$gen_after" ]]; then
    record_live_assertion node_waypoint.dtls.operator_isolated_across_reload fail \
      dtls-src-a dtls-echo "frontend_dtls_reload.generation missing from /overload after generated-owner publication" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  if [[ "$gen_after" != "$gen_before" || "$restarts_before" != "$restarts_after" ]]; then
    record_live_assertion node_waypoint.dtls.operator_isolated_across_reload fail \
      dtls-src-a dtls-echo \
      "ordinary frontend_dtls_reload.generation or ambient restarts changed gen_before=$gen_before gen_after=$gen_after restarts_before=$restarts_before restarts_after=$restarts_after" \
      "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
    collect_traffic_failure_diagnostics
    return 1
  fi
  record_live_assertion node_waypoint.dtls.operator_isolated_across_reload pass \
    dtls-src-a dtls-echo \
    "ordinary /overload frontend_dtls_reload.generation captured pre/post generated-owner publication unchanged=$gen_after, ambient restarts unchanged=$restarts_after, no bound ordinary listener claimed" \
    "$(spiffe_for_sa src-a)" "$(spiffe_for_sa dst-a)" "node-waypoint-dtls-reload"
}

cleanup() {
  if [[ "$TOPOLOGY_ROUTE_MUTATED" == "true" && -n "$TOPOLOGY_ROUTE_NODE" \
    && -f "$TOPOLOGY_ROUTE_STATE_FILE" ]]; then
    restore_ingress_routes "$TOPOLOGY_ROUTE_NODE" "$TOPOLOGY_ROUTE_STATE_FILE" || true
  fi
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
discover_ingress_redirect_ifaces
install_spire_production_identity
install_ferrum
verify_ambient_spire_identity
assert_node_agent_ready_metric
run_ingress_topology_negative_and_drift_checks
collect_bpf_evidence
prepare_dtls_client_image
apply_workloads
wait_for_node_waypoint_ready_markers
wait_for_ambient_mesh_slice
run_traffic_checks
run_node_waypoint_udp_datapath_checks
run_node_waypoint_udp_same_port_demux_checks
run_node_waypoint_dtls_datapath_checks
run_node_waypoint_dtls_service_path_checks
run_node_waypoint_dtls_reload_isolation_checks
run_ipv6_checks
ferrum_live_assertions_require_all_passed "$LIVE_ASSERTIONS_FILE" "${REQUIRED_LIVE_ASSERTIONS[@]}"

log "live NodeWaypoint eBPF datapath checks passed"
