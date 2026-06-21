#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART_DIR="$ROOT_DIR/charts/ferrum-mesh"
MANIFESTS="$ROOT_DIR/tests/k8s/node_waypoint_ebpf_live/manifests.yaml"

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
    echo "Istio AuthorizationPolicy CRD is required for this live policy-scope test" >&2
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
}

apply_workloads() {
  log "applying live traffic workloads"
  local service_ip_family_block
  if [[ "$REQUIRE_DUAL_STACK" == "true" ]]; then
    service_ip_family_block=$'  ipFamilyPolicy: RequireDualStack\n  ipFamilies:\n    - IPv4\n    - IPv6'
  else
    service_ip_family_block=$'  ipFamilyPolicy: PreferDualStack'
  fi
  awk -v ns="$WORKLOAD_NS" -v family_block="$service_ip_family_block" '
    {
      gsub(/__NAMESPACE__/, ns)
      if ($0 ~ /__SERVICE_IP_FAMILY_BLOCK__/) {
        print family_block
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

wait_for_node_waypoint_marker_removed() {
  local node="$1"
  local uid="$2"
  for _ in $(seq 1 60); do
    if ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/$uid" &&
      ! node_host_file_exists "$node" "$NODE_WAYPOINT_REGISTRY_DIR/.ready/$uid"; then
      return
    fi
    sleep 1
  done
  echo "stale NodeWaypoint registry or ready marker remained for deleted pod $uid on $node" >&2
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
# MeshSubscribe slices are node-local; each ambient proxy must see its local
# source/destination workloads plus the policy objects needed to enforce them.
expected = {
    "workloads": 2,
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
  kubectl -n "$WORKLOAD_NS" get svc "$1" -o jsonpath='{range .spec.clusterIPs[*]}{.}{"\n"}{end}' | grep ':' | head -n1 || true
}

curl_from() {
  local deploy="$1"
  local url="$2"
  kubectl -n "$WORKLOAD_NS" exec "deploy/$deploy" -- \
    sh -c 'curl -g -sS -m 8 -w "\n%{http_code}" "$1"' -- "$url"
}

expect_allowed() {
  local from="$1"
  local label="$2"
  local url="$3"
  local expected_body="$4"
  local output="" code="" body="" status=1 err
  err="$(mktemp)"
  for attempt in $(seq 1 8); do
    set +e
    output="$(curl_from "$from" "$url" 2>"$err")"
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
  exit 1
}

expect_blocked() {
  local from="$1"
  local label="$2"
  local url="$3"
  local output code
  set +e
  output="$(curl_from "$from" "$url" 2>/tmp/ferrum-live-curl.err)"
  local status=$?
  set -e
  code="${output##*$'\n'}"
  if [[ "$status" -eq 0 && "$code" == "200" ]]; then
    echo "expected block for $label from $from to $url, got HTTP 200" >&2
    exit 1
  fi
}

expect_no_hbone_dispatch_required() {
  local from="$1"
  local label="$2"
  local url="$3"
  local expected_body="$4"
  local output="" code="" body="" status=1 err
  err="$(mktemp)"
  set +e
  output="$(curl_from "$from" "$url" 2>"$err")"
  status=$?
  set -e
  code="${output##*$'\n'}"
  body="${output%$'\n'*}"
  body="${body//$'\r'/}"
  while [[ "$body" == *$'\n' ]]; do
    body="${body%$'\n'}"
  done
  if [[ "$status" -eq 0 && "$code" == "502" && "$body" == *"HBONE dispatch required"* ]]; then
    echo "expected $label from $from to $url to avoid unreachable pod-IP HBONE dispatch, got HTTP 502 body '$body'" >&2
    cat "$err" >&2 || true
    rm -f "$err"
    collect_traffic_failure_diagnostics
    exit 1
  fi
  if [[ "$status" -eq 0 && "$code" == "200" && "$body" != "$expected_body" ]]; then
    echo "expected $label from $from to $url to return body '$expected_body' when allowed, got '$body'" >&2
    cat "$err" >&2 || true
    rm -f "$err"
    collect_traffic_failure_diagnostics
    exit 1
  fi
  rm -f "$err"
}

run_traffic_checks() {
  log "running IPv4 same-node/cross-node Service checks and direct Pod-IP HBONE regression checks"
  local dst_a_ip dst_b_ip
  dst_a_ip="$(pod_ip dst-a)"
  dst_b_ip="$(pod_ip dst-b)"

  expect_allowed src-a "same-node Service ClusterIP" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" "ok-a"
  expect_no_hbone_dispatch_required src-a "same-node direct Pod IP" "http://$dst_a_ip:8080/" "ok-a"
  expect_allowed src-a "cross-node Service ClusterIP" "http://dst-b.$WORKLOAD_NS.svc.cluster.local:8080/" "ok-b"
  expect_no_hbone_dispatch_required src-a "cross-node direct Pod IP" "http://$dst_b_ip:8080/" "ok-b"

  expect_blocked src-b "selector/namespace DENY same-node" "http://dst-b.$WORKLOAD_NS.svc.cluster.local:8080/"
  expect_blocked src-b "selector/namespace DENY cross-node" "http://$dst_a_ip:8080/"

  log "checking stale identity cleanup across source workload recreation"
  local old_src_a_uid old_src_a_node
  old_src_a_uid="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].metadata.uid}')"
  old_src_a_node="$(kubectl -n "$WORKLOAD_NS" get pod -l app=src-a -o jsonpath='{.items[0].spec.nodeName}')"
  kubectl -n "$WORKLOAD_NS" delete pod -l app=src-a --wait=true
  wait_for_node_waypoint_marker_removed "$old_src_a_node" "$old_src_a_uid"
  kubectl -n "$WORKLOAD_NS" rollout status deploy/src-a --timeout=3m
  wait_for_node_waypoint_ready_markers
  wait_for_ambient_mesh_slice
  expect_allowed src-a "recreated source identity" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/" "ok-a"
  expect_blocked src-b "wrong-pod attribution guard after recreation" "http://dst-a.$WORKLOAD_NS.svc.cluster.local:8080/"
}

run_ipv6_checks() {
  log "running dual-stack IPv6 admission checks"
  local dst_a_v6 svc_a_v6
  dst_a_v6="$(pod_ipv6 dst-a)"
  svc_a_v6="$(svc_ipv6 dst-a)"
  if [[ -z "$dst_a_v6" || -z "$svc_a_v6" ]]; then
    if [[ "$REQUIRE_DUAL_STACK" == "true" ]]; then
      echo "dual-stack pass required, but dst-a pod/service has no IPv6 address" >&2
      exit 1
    fi
    log "cluster is not dual-stack; skipping IPv6 pass"
    return
  fi

  # Current NodeWaypoint e2e IPv6 capture is intentionally rejected before
  # admission: connect6 fail-closes captured IPv6 until the in-netns listener
  # and policy path are fully IPv6-capable. A 200 here would mean IPv6 bypassed
  # enforcement or was misattributed.
  expect_blocked src-a "IPv6 direct Pod IP fail-closed" "http://[$dst_a_v6]:8080/"
  expect_blocked src-a "IPv6 Service ClusterIP fail-closed" "http://[$svc_a_v6]:8080/"
}

cleanup() {
  if [[ "${FERRUM_LIVE_KEEP_RESOURCES:-false}" != "true" ]]; then
    kubectl delete namespace "$WORKLOAD_NS" --ignore-not-found=true >/dev/null 2>&1 || true
    helm uninstall "$RELEASE" -n "$MESH_NS" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

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

log "live NodeWaypoint eBPF datapath checks passed"
