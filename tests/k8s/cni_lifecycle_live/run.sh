#!/usr/bin/env bash
# Live CNI install / fail-closed / rollback / uninstall / chart-cleanup proof
# for issue #3609.
#
# The Rust integration suite drives install/uninstall/rollback-watch against
# temporary directories. That proves ownership and filesystem logic but not the
# operator-visible contract: a chained ferrum-cni really gates pod creation on
# a live node, and rollback / uninstall / chart pre-delete cleanup give that
# node back without mutating the primary CNI configuration.
#
# This suite creates a disposable two-node kind cluster and, on the WORKER
# node only (the control plane stays clean so kubectl keeps working):
#
#   1. installs the chain with the real binary against the cluster's real
#      primary CNI configuration;
#   2. injects the failure the issue describes — no node-agent socket — and
#      proves a new pod on that node sticks in Pending / ContainerCreating;
#   3. runs rollback-watch and proves the same pod recovers once the chain is
#      removed;
#   4. reinstalls, uninstalls, proves uninstall is idempotent, proves the
#      primary CNI config is byte-identical throughout, and proves pod creation
#      still works afterwards;
#   5. drives the chart's own cleanup manifests (RBAC + pre-delete hook graph)
#      and proves an obstructed node fails the wait Job while leaving retry
#      identity in place, then that a retry succeeds and deletes the cleanup
#      DaemonSet;
#   6. runs a scoped helm install/uninstall with nodeAgent.cni.enabled so the
#      chart-authored installer + pre-delete hook path is exercised end to end
#      under kindnet (or whatever primary the kind image ships).
#
# Every lifecycle pod uses hostNetwork: a pod that needed its own CNI sandbox
# could not start on a node whose chain is broken — the same reason the chart
# cleanup hook is hostNetwork.
#
# Post-readiness failure recovery is deliberately NOT auto-rolled-back: once
# STATUS has answered Ok, the watcher retains the chain for the pod lifetime.
# That boundary is covered by the Rust suite
# (`rollback_watch_retains_artifacts_once_readiness_is_observed`) and documented
# in docs/node_agent.md "Recovering a node". This live job proves the automatic
# recovery paths that DO exist (never-ready rollback + uninstall).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CHART_DIR="$ROOT_DIR/charts/ferrum-mesh"
HELPER_DIR="$ROOT_DIR/tests/k8s/cni_lifecycle_live"

KIND_CLUSTER="${KIND_CLUSTER:-ferrum-cni-lifecycle}"
IMAGE_REPOSITORY="${FERRUM_IMAGE_REPOSITORY:-ferrum-edge}"
IMAGE_TAG="${FERRUM_IMAGE_TAG:-cni-lifecycle-live}"
IMAGE="${IMAGE_REPOSITORY}:${IMAGE_TAG}"
OWNER_ID="${OWNER_ID:-ferrum/cni-lifecycle-live}"
INSTALL_GENERATION="${INSTALL_GENERATION:-live-generation-1}"
CONF_FILE_NAME="${CONF_FILE_NAME:-00-ferrum.conflist}"
RESULTS_DIR="${ARTIFACT_DIR:-$ROOT_DIR/target/cni-lifecycle-live}"
WORKER="${KIND_CLUSTER}-worker"
CNI_BIN_PATH="${CNI_BIN_PATH:-/app/ferrum-cni}"

mkdir -p "$RESULTS_DIR"
cd "$ROOT_DIR"

command -v docker >/dev/null
command -v kind >/dev/null
command -v kubectl >/dev/null
command -v helm >/dev/null
command -v python3 >/dev/null

cleanup_cluster() {
  kind delete cluster --name "$KIND_CLUSTER" >/dev/null 2>&1 || true
}
trap cleanup_cluster EXIT

cat > "$RESULTS_DIR/kind-cni-lifecycle.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
YAML

kind create cluster \
  --name "$KIND_CLUSTER" \
  --config "$RESULTS_DIR/kind-cni-lifecycle.yaml" \
  --wait 180s
kubectl get nodes -o wide | tee "$RESULTS_DIR/nodes-after-create.txt"
kind load docker-image "$IMAGE" --name "$KIND_CLUSTER"

# ---------------------------------------------------------------------------
# Discover the worker's primary CNI configuration.
# ---------------------------------------------------------------------------
primary_file=""
while IFS= read -r candidate; do
  case "$candidate" in
    *.conf|*.conflist)
      primary_file="$candidate"
      break
      ;;
  esac
done < <(docker exec "$WORKER" ls -1 /etc/cni/net.d)

if [ -z "$primary_file" ]; then
  echo "::error title=No primary CNI config on the kind worker::cannot chain behind nothing"
  exit 1
fi

docker exec "$WORKER" cat "/etc/cni/net.d/${primary_file}" > "$RESULTS_DIR/primary-before.json"
chained_with="$(python3 -I "$HELPER_DIR/primary_plugin_type.py" "$RESULTS_DIR/primary-before.json")"
primary_sha="$(sha256sum "$RESULTS_DIR/primary-before.json" | cut -d' ' -f1)"
echo "Primary CNI config ${primary_file} (first plugin: ${chained_with}, sha256 ${primary_sha})" \
  | tee "$RESULTS_DIR/primary-summary.txt"

assert_primary_untouched() {
  docker exec "$WORKER" cat "/etc/cni/net.d/${primary_file}" > "$RESULTS_DIR/primary-now.json"
  local now
  now="$(sha256sum "$RESULTS_DIR/primary-now.json" | cut -d' ' -f1)"
  if [ "$now" != "$primary_sha" ]; then
    echo "::error title=Primary CNI config was modified::${primary_file} changed (${primary_sha} -> ${now})"
    diff -u "$RESULTS_DIR/primary-before.json" "$RESULTS_DIR/primary-now.json" || true
    exit 1
  fi
}

# Render one lifecycle Job. $1 = job name, $2 = ferrum-cni verb, $3.. = name=value env.
render_job() {
  local name="$1" verb="$2"
  shift 2
  {
    cat <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: ${name}
  namespace: default
spec:
  backoffLimit: 0
  template:
    spec:
      hostNetwork: true
      dnsPolicy: Default
      restartPolicy: Never
      nodeSelector:
        kubernetes.io/hostname: ${WORKER}
      containers:
        - name: ferrum-cni
          image: ${IMAGE}
          imagePullPolicy: Never
          command: ["${CNI_BIN_PATH}", "${verb}"]
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          env:
            - name: HOST_BIN_DIR
              value: /opt/cni/bin
            - name: HOST_CONF_DIR
              value: /etc/cni/net.d
            - name: HOST_SOCKET_DIR
              value: /var/run/ferrum
            - name: CONF_FILE_NAME
              value: ${CONF_FILE_NAME}
YAML
    local pair
    for pair in "$@"; do
      printf '            - name: %s\n              value: "%s"\n' \
        "${pair%%=*}" "${pair#*=}"
    done
    cat <<'YAML'
          volumeMounts:
            - name: host-cni-bin
              mountPath: /opt/cni/bin
            - name: host-cni-conf
              mountPath: /etc/cni/net.d
            - name: host-socket
              mountPath: /var/run/ferrum
      volumes:
        - name: host-cni-bin
          hostPath:
            path: /opt/cni/bin
            type: DirectoryOrCreate
        - name: host-cni-conf
          hostPath:
            path: /etc/cni/net.d
            type: DirectoryOrCreate
        - name: host-socket
          hostPath:
            path: /var/run/ferrum
            type: DirectoryOrCreate
YAML
  }
}

# Run a lifecycle Job. rollback-watch exits non-zero by design; callers decide.
run_job() {
  local name="$1"
  shift
  kubectl delete job "$name" --ignore-not-found --wait=true >/dev/null
  render_job "$name" "$@" | kubectl apply -f -
  local deadline=$((SECONDS + 300)) phase=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    phase="$(kubectl get pods -l "job-name=$name" \
      -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)"
    case "$phase" in
      Succeeded|Failed) break ;;
    esac
    sleep 3
  done
  echo "--- $name logs (phase=$phase) ---"
  kubectl logs "job/$name" --all-containers --tail=200 || true
  if [ "$phase" != "Succeeded" ] && [ "$phase" != "Failed" ]; then
    kubectl describe "job/$name" || true
    echo "::error title=Lifecycle job never terminated::$name stayed in phase '$phase'"
    return 99
  fi
  [ "$phase" = "Succeeded" ]
}

wait_for_pod_not_pending() {
  local pod="$1" budget="${2:-90}"
  local deadline=$((SECONDS + budget)) phase=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    phase="$(kubectl get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [ "$phase" != "Pending" ] && [ -n "$phase" ]; then
      break
    fi
    sleep 5
  done
  printf '%s' "$phase"
}

# ---------------------------------------------------------------------------
# 1. Install the chain with the real binary on a real node.
# ---------------------------------------------------------------------------
run_job cni-install install \
  "CHAINED_WITH=${chained_with}" \
  "SOCKET_PATH=/var/run/ferrum/node-agent-cni.sock" \
  "OWNER_ID=${OWNER_ID}" \
  "INSTALL_GENERATION=${INSTALL_GENERATION}"
docker exec "$WORKER" cat "/etc/cni/net.d/${CONF_FILE_NAME}" \
  | tee "$RESULTS_DIR/installed-conflist.json" >/dev/null
docker exec "$WORKER" test -x /opt/cni/bin/ferrum-cni
docker exec "$WORKER" grep -q ferrum-edge /etc/cni/net.d/.ferrum-cni-owned.marker
assert_primary_untouched

# ---------------------------------------------------------------------------
# 2. Failure injection: no node-agent socket. A NEW pod on this node must
#    fail closed rather than start unenrolled.
# ---------------------------------------------------------------------------
docker exec "$WORKER" rm -f /var/run/ferrum/node-agent-cni.sock
kubectl delete pod stuck-pod --ignore-not-found --wait=true >/dev/null
kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: stuck-pod
  namespace: default
spec:
  nodeSelector:
    kubernetes.io/hostname: ${WORKER}
  restartPolicy: Never
  containers:
    - name: pause
      image: ${IMAGE}
      imagePullPolicy: Never
      command: ["${CNI_BIN_PATH}", "uninstall-status"]
YAML
phase="$(wait_for_pod_not_pending stuck-pod 90)"
kubectl describe pod stuck-pod | tee "$RESULTS_DIR/stuck-pod-describe.txt" | tail -n 30
if [ "$phase" != "Pending" ]; then
  echo "::error title=Pod creation did not fail closed::stuck-pod reached phase '$phase' without a node-agent"
  exit 1
fi
if ! grep -qiE 'ferrum-cni|FailedCreatePodSandBox' "$RESULTS_DIR/stuck-pod-describe.txt"; then
  echo "::error title=Missing ferrum-cni failure evidence::stuck-pod Pending without a CNI/sandbox error"
  exit 1
fi
echo "Confirmed live: chained ADD fails closed when the node-agent socket is absent."

# ---------------------------------------------------------------------------
# 3. Rollback-watch removes this generation and restores pod creation.
# ---------------------------------------------------------------------------
set +e
run_job cni-rollback rollback-watch \
  "SOCKET_PATH=/var/run/ferrum/node-agent-cni.sock" \
  "EXPECTED_OWNER=${OWNER_ID}" \
  "EXPECTED_GENERATION=${INSTALL_GENERATION}" \
  "PUBLISH_TIMEOUT_SECS=30" \
  "READY_TIMEOUT_SECS=30" \
  "POLL_INTERVAL_SECS=2"
rollback_status=$?
set -e
# RolledBack exits non-zero by design (visible failure), but the chain must be gone.
if docker exec "$WORKER" test -e "/etc/cni/net.d/${CONF_FILE_NAME}"; then
  echo "::error title=Rollback left the chained conflist::exit=$rollback_status"
  exit 1
fi
assert_primary_untouched

deadline=$((SECONDS + 120))
while [ "$SECONDS" -lt "$deadline" ]; do
  phase="$(kubectl get pod stuck-pod -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [ "$phase" != "Pending" ] && [ -n "$phase" ]; then
    break
  fi
  # Recreate if kubelet gave up on the original sandbox attempt.
  if [ "$phase" = "Failed" ] || [ -z "$phase" ]; then
    kubectl delete pod stuck-pod --ignore-not-found --wait=true >/dev/null || true
    kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: stuck-pod
  namespace: default
spec:
  nodeSelector:
    kubernetes.io/hostname: ${WORKER}
  restartPolicy: Never
  containers:
    - name: pause
      image: ${IMAGE}
      imagePullPolicy: Never
      command: ["${CNI_BIN_PATH}", "uninstall-status"]
YAML
  fi
  sleep 5
done
phase="$(kubectl get pod stuck-pod -o jsonpath='{.status.phase}')"
if [ "$phase" = "Pending" ]; then
  kubectl describe pod stuck-pod | tee "$RESULTS_DIR/stuck-pod-after-rollback.txt" | tail -n 30
  echo "::error title=Pod creation did not recover after rollback::stuck-pod is still Pending"
  exit 1
fi
echo "Confirmed live: rollback restored pod creation on the node (stuck-pod reached '$phase')."

# ---------------------------------------------------------------------------
# 4. Reinstall, uninstall, prove idempotency, prove primary untouched.
# ---------------------------------------------------------------------------
run_job cni-reinstall install \
  "CHAINED_WITH=${chained_with}" \
  "SOCKET_PATH=/var/run/ferrum/node-agent-cni.sock" \
  "OWNER_ID=${OWNER_ID}" \
  "INSTALL_GENERATION=${INSTALL_GENERATION}"
docker exec "$WORKER" test -e "/etc/cni/net.d/${CONF_FILE_NAME}"

run_job cni-uninstall uninstall "EXPECTED_OWNER=${OWNER_ID}"
if docker exec "$WORKER" test -e "/etc/cni/net.d/${CONF_FILE_NAME}"; then
  echo "::error title=Uninstall left the chained conflist"
  exit 1
fi
assert_primary_untouched

run_job cni-uninstall-repeat uninstall "EXPECTED_OWNER=${OWNER_ID}"
assert_primary_untouched
echo "Confirmed live: uninstall is idempotent and never mutates the primary CNI config."

kubectl delete pod recovered-pod --ignore-not-found --wait=true >/dev/null || true
kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: recovered-pod
  namespace: default
spec:
  nodeSelector:
    kubernetes.io/hostname: ${WORKER}
  restartPolicy: Never
  containers:
    - name: pause
      image: ${IMAGE}
      imagePullPolicy: Never
      command: ["${CNI_BIN_PATH}", "uninstall-status"]
YAML
phase="$(wait_for_pod_not_pending recovered-pod 120)"
if [ "$phase" = "Pending" ]; then
  kubectl describe pod recovered-pod | tee "$RESULTS_DIR/recovered-pod-describe.txt" | tail -n 30
  echo "::error title=Pod creation still broken after uninstall::recovered-pod is Pending"
  exit 1
fi
echo "Confirmed live: after uninstall the node creates pods normally (recovered-pod reached '$phase')."

# ---------------------------------------------------------------------------
# 5. Chart cleanup resource graph: failure leaves retry identity; retry deletes.
# ---------------------------------------------------------------------------
ns=default
probe_conf=99-ferrum-cleanup-probe.conflist

helm template ferrum "$CHART_DIR" --namespace "$ns" \
  --set nodeAgent.enabled=true \
  --set nodeAgent.cni.enabled=true \
  --set nodeAgent.captureMode=iptables \
  --set image.repository="$IMAGE_REPOSITORY" \
  --set image.tag="$IMAGE_TAG" \
  --set image.pullPolicy=Never \
  --set nodeAgent.cni.confFileName="$probe_conf" \
  --set nodeAgent.cni.uninstall.timeoutSeconds=90 \
  --show-only templates/cni-cleanup-rbac.yaml > "$RESULTS_DIR/cleanup-rbac.yaml"

helm template ferrum "$CHART_DIR" --namespace "$ns" \
  --set nodeAgent.enabled=true \
  --set nodeAgent.cni.enabled=true \
  --set nodeAgent.captureMode=iptables \
  --set image.repository="$IMAGE_REPOSITORY" \
  --set image.tag="$IMAGE_TAG" \
  --set image.pullPolicy=Never \
  --set nodeAgent.cni.confFileName="$probe_conf" \
  --set nodeAgent.cni.uninstall.timeoutSeconds=90 \
  --show-only templates/cni-uninstall-hook.yaml > "$RESULTS_DIR/cleanup-hook.yaml"

if grep -Fq 'helm.sh/hook' "$RESULTS_DIR/cleanup-rbac.yaml"; then
  echo "::error title=Cleanup identity is a hook resource::a failed wait Job would delete the SA/RBAC a retry needs"
  exit 1
fi
kubectl apply -n "$ns" -f "$RESULTS_DIR/cleanup-rbac.yaml"
python3 -I "$HELPER_DIR/split_cleanup_hook.py" \
  "$RESULTS_DIR/cleanup-hook.yaml" \
  "$RESULTS_DIR/cleanup-daemonset.yaml" \
  "$RESULTS_DIR/cleanup-wait-job.yaml"

wait_for_job() {
  local name="$1" budget="${2:-240}"
  local deadline=$((SECONDS + budget)) phase=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    phase="$(kubectl -n "$ns" get pods -l "job-name=$name" \
      -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)"
    case "$phase" in
      Succeeded|Failed) break ;;
    esac
    sleep 5
  done
  echo "--- $name logs (phase=$phase) ---"
  kubectl -n "$ns" logs "job/$name" --all-containers --tail=200 || true
  [ "$phase" = "Succeeded" ]
}

# A. Failure path: foreign conflist at the configured name is retained.
cat > "$RESULTS_DIR/foreign-probe.json" <<'JSON'
{"cniVersion":"1.0.0","name":"operator-authored","plugins":[{"type":"ferrum-cni","ferrum":{"socketPath":"/custom.sock"}}]}
JSON
docker cp "$RESULTS_DIR/foreign-probe.json" "${WORKER}:/etc/cni/net.d/${probe_conf}"
kubectl apply -n "$ns" -f "$RESULTS_DIR/cleanup-daemonset.yaml"
kubectl apply -n "$ns" -f "$RESULTS_DIR/cleanup-wait-job.yaml"
set +e
wait_for_job ferrum-mesh-cni-cleanup-wait 240
wait_status=$?
set -e
if [ "$wait_status" -eq 0 ]; then
  echo "::error title=Wait Job passed with an uncleaned node::a node that cannot be cleaned must fail the uninstall"
  exit 1
fi
kubectl -n "$ns" get daemonset ferrum-mesh-cni-cleanup
kubectl -n "$ns" get serviceaccount ferrum-mesh-cni-cleanup
kubectl -n "$ns" get serviceaccount ferrum-mesh-cni-cleanup-wait
kubectl -n "$ns" get role ferrum-mesh-cni-cleanup-wait
kubectl -n "$ns" get rolebinding ferrum-mesh-cni-cleanup-wait
echo "Confirmed live: a failed cleanup leaves the DaemonSet, its logs and its identity in place."

# B. Retry path.
docker exec "$WORKER" rm -f "/etc/cni/net.d/${probe_conf}"
kubectl -n "$ns" delete pod -l app.kubernetes.io/name=ferrum-mesh-cni-cleanup --wait=true
kubectl -n "$ns" delete job ferrum-mesh-cni-cleanup-wait --wait=true
kubectl apply -n "$ns" -f "$RESULTS_DIR/cleanup-wait-job.yaml"
if ! wait_for_job ferrum-mesh-cni-cleanup-wait 240; then
  echo "::error title=Retry did not succeed::cleanup should have completed on every node after the obstruction was removed"
  exit 1
fi
if kubectl -n "$ns" get daemonset ferrum-mesh-cni-cleanup 2>/dev/null; then
  echo "::error title=Cleanup DaemonSet still present::the wait Job must delete it and verify it is gone before reporting success"
  exit 1
fi
if [ -n "$(kubectl -n "$ns" get pods -l app.kubernetes.io/name=ferrum-mesh-cni-cleanup -o name)" ]; then
  echo "::error title=Cleanup pods still running::foreground deletion must have reaped them before success was reported"
  exit 1
fi
echo "Confirmed live: the wait Job deleted the cleanup DaemonSet and proved it was gone."
kubectl delete -n "$ns" -f "$RESULTS_DIR/cleanup-rbac.yaml" --ignore-not-found

# ---------------------------------------------------------------------------
# 6. Full-chart install / uninstall under kind CNI conditions.
#    Rollback is disabled so the installer-published chain stays for the
#    pre-delete hook to remove. The main node-agent container may crash-loop
#    without a full mesh control plane; that is the crash-loop outage the
#    uninstall path must still recover from.
# ---------------------------------------------------------------------------
chart_ns=ferrum-cni-live
chart_release=ferrum-cni-live
kubectl delete namespace "$chart_ns" --ignore-not-found --wait=true >/dev/null || true
kubectl create namespace "$chart_ns"

helm install "$chart_release" "$CHART_DIR" -n "$chart_ns" \
  --set nodeAgent.enabled=true \
  --set nodeAgent.cni.enabled=true \
  --set nodeAgent.cni.rollback.enabled=false \
  --set nodeAgent.cni.chainedWith="$chained_with" \
  --set nodeAgent.captureMode=iptables \
  --set image.repository="$IMAGE_REPOSITORY" \
  --set image.tag="$IMAGE_TAG" \
  --set image.pullPolicy=Never \
  --set nodeAgent.image.repository="$IMAGE_REPOSITORY" \
  --set nodeAgent.image.tag="$IMAGE_TAG"

deadline=$((SECONDS + 180))
while [ "$SECONDS" -lt "$deadline" ]; do
  if docker exec "$WORKER" test -e "/etc/cni/net.d/${CONF_FILE_NAME}"; then
    break
  fi
  sleep 5
done
if ! docker exec "$WORKER" test -e "/etc/cni/net.d/${CONF_FILE_NAME}"; then
  kubectl -n "$chart_ns" get pods -o wide | tee "$RESULTS_DIR/chart-install-pods.txt" || true
  kubectl -n "$chart_ns" describe daemonset ferrum-mesh-node-agent \
    | tee "$RESULTS_DIR/chart-install-daemonset.txt" || true
  echo "::error title=Chart install never published a chained conflist"
  exit 1
fi
docker exec "$WORKER" grep -q ferrum-edge /etc/cni/net.d/.ferrum-cni-owned.marker
assert_primary_untouched
echo "Confirmed live: chart-authored installer published the chained conflist."

helm uninstall "$chart_release" -n "$chart_ns" --timeout 5m
deadline=$((SECONDS + 180))
while [ "$SECONDS" -lt "$deadline" ]; do
  if ! docker exec "$WORKER" test -e "/etc/cni/net.d/${CONF_FILE_NAME}"; then
    break
  fi
  sleep 5
done
if docker exec "$WORKER" test -e "/etc/cni/net.d/${CONF_FILE_NAME}"; then
  echo "::error title=helm uninstall left the chained conflist"
  docker exec "$WORKER" ls -la /etc/cni/net.d | tee "$RESULTS_DIR/post-uninstall-cni-dir.txt" || true
  exit 1
fi
assert_primary_untouched
echo "Confirmed live: helm uninstall removed only the Ferrum-owned chain before the socket disappeared."

kubectl delete namespace "$chart_ns" --ignore-not-found --wait=true >/dev/null || true

# Diagnostics always (trap still destroys the cluster).
{
  kubectl get nodes -o wide
  kubectl get pods -A -o wide
  kubectl get events -A --sort-by=.lastTimestamp
} > "$RESULTS_DIR/final-cluster-state.txt" 2>&1 || true

echo "CNI lifecycle live suite passed."
