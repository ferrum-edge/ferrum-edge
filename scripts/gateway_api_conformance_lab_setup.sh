#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-ferrum-gwapi}"
FERRUM_IMAGE="${FERRUM_IMAGE:-ferrum-edge:gateway-api-conformance}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"

# Pinned SHA-256 of the experimental-channel CRD bundle served for
# GATEWAY_API_PINNED_VERSION. The version and its checksum live next to each
# other and must move together: bumping the default above without bumping the
# digest below fails the install closed. Recompute with
#   curl -fsSL "https://github.com/kubernetes-sigs/gateway-api/releases/download/<version>/experimental-install.yaml" | shasum -a 256
# A dispatch run that overrides GATEWAY_API_VERSION to some other tag must
# supply the matching digest in GATEWAY_API_EXPERIMENTAL_SHA256; there is no
# unverified path.
GATEWAY_API_PINNED_VERSION="v1.5.1"
GATEWAY_API_PINNED_EXPERIMENTAL_SHA256="64ec76609a6ac885e0405dea79ca509c229fa019d342f0857aa8b6bdc8b8ba92"
GATEWAY_API_EXPERIMENTAL_SHA256="${GATEWAY_API_EXPERIMENTAL_SHA256:-}"
GATEWAY_API_CRD_FETCH_ATTEMPTS="${GATEWAY_API_CRD_FETCH_ATTEMPTS:-5}"
GATEWAY_API_PROFILE="${GATEWAY_API_PROFILE:-GATEWAY-HTTP,GATEWAY-GRPC}"
GATEWAY_API_SUPPORTED_FEATURES="${GATEWAY_API_SUPPORTED_FEATURES:-Gateway,ReferenceGrant,HTTPRoute,GRPCRoute}"
GATEWAY_API_SKIP_TESTS="${GATEWAY_API_SKIP_TESTS:-}"
GATEWAY_API_STATUS_ADDRESS="${GATEWAY_API_STATUS_ADDRESS:-127.0.0.1}"

# Live TCPRoute black-box listeners (Gateway listener port == DP stream listen_port).
# Host ports map through kind NodePorts so CI can dial without in-cluster clients.
TCP_BLACKBOX_PORT_MAIN="${TCP_BLACKBOX_PORT_MAIN:-9001}"
TCP_BLACKBOX_PORT_CROSS="${TCP_BLACKBOX_PORT_CROSS:-9002}"
TCP_BLACKBOX_PORT_FAIL="${TCP_BLACKBOX_PORT_FAIL:-9003}"
TCP_BLACKBOX_PORT_DELETE="${TCP_BLACKBOX_PORT_DELETE:-9004}"
TCP_BLACKBOX_PORT_PARENT_CROSS="${TCP_BLACKBOX_PORT_PARENT_CROSS:-9005}"
TCP_BLACKBOX_NODEPORT_MAIN="${TCP_BLACKBOX_NODEPORT_MAIN:-30901}"
TCP_BLACKBOX_NODEPORT_CROSS="${TCP_BLACKBOX_NODEPORT_CROSS:-30902}"
TCP_BLACKBOX_NODEPORT_FAIL="${TCP_BLACKBOX_NODEPORT_FAIL:-30903}"
TCP_BLACKBOX_NODEPORT_DELETE="${TCP_BLACKBOX_NODEPORT_DELETE:-30904}"
TCP_BLACKBOX_NODEPORT_PARENT_CROSS="${TCP_BLACKBOX_NODEPORT_PARENT_CROSS:-30905}"
TCP_ECHO_BACKEND_PORT="${TCP_ECHO_BACKEND_PORT:-9090}"

# Live TLSRoute black-box listeners (TLS Passthrough + SNI). Distinct from TCPRoute
# ports so the two L4 labs do not share stream listen_port identity.
TLS_BLACKBOX_PORT_SNI="${TLS_BLACKBOX_PORT_SNI:-9011}"
TLS_BLACKBOX_PORT_CROSS="${TLS_BLACKBOX_PORT_CROSS:-9012}"
TLS_BLACKBOX_PORT_FAIL="${TLS_BLACKBOX_PORT_FAIL:-9013}"
TLS_BLACKBOX_PORT_DELETE="${TLS_BLACKBOX_PORT_DELETE:-9014}"
TLS_BLACKBOX_NODEPORT_SNI="${TLS_BLACKBOX_NODEPORT_SNI:-30911}"
TLS_BLACKBOX_NODEPORT_CROSS="${TLS_BLACKBOX_NODEPORT_CROSS:-30912}"
TLS_BLACKBOX_NODEPORT_FAIL="${TLS_BLACKBOX_NODEPORT_FAIL:-30913}"
TLS_BLACKBOX_NODEPORT_DELETE="${TLS_BLACKBOX_NODEPORT_DELETE:-30914}"
TLS_ECHO_BACKEND_PORT="${TLS_ECHO_BACKEND_PORT:-9443}"

CP_NAMESPACE="${CP_NAMESPACE:-ferrum}"
DP_SERVICE_NAME="${DP_SERVICE_NAME:-ferrum-gateway-data-plane}"
DP_GATEWAY_NAMESPACE="${DP_GATEWAY_NAMESPACE:-gateway-conformance-infra}"
BACKEND_NAMESPACE="${BACKEND_NAMESPACE:-gateway-conformance-web-backend}"
# Upstream Gateway API conformance also provisions this fixed backend namespace
# (see kubernetes-sigs/gateway-api conformance constants). Keep it on the K8s
# watch list even though CP/DP auth stays single-namespace.
APP_BACKEND_NAMESPACE="${APP_BACKEND_NAMESPACE:-gateway-conformance-app-backend}"
JWT_SECRET="${JWT_SECRET:-ferrum-edge-gateway-api-conformance-grpc-secret}"
ADMIN_SECRET="${ADMIN_SECRET:-ferrum-edge-gateway-api-conformance-admin-secret}"
METRICS_TOKEN="${METRICS_TOKEN:-ferrum-edge-gateway-api-conformance-metrics-token}"

mkdir -p "$RESULTS_DIR"

kind_config_path() {
  printf '%s/kind-gateway-api.yaml' "${RUNNER_TEMP:-/tmp}"
}

create_kind_cluster() {
  cat > "$(kind_config_path)" <<YAML
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 80
        protocol: TCP
      - containerPort: 30443
        hostPort: 443
        protocol: TCP
      - containerPort: ${TCP_BLACKBOX_NODEPORT_MAIN}
        hostPort: ${TCP_BLACKBOX_PORT_MAIN}
        protocol: TCP
      - containerPort: ${TCP_BLACKBOX_NODEPORT_CROSS}
        hostPort: ${TCP_BLACKBOX_PORT_CROSS}
        protocol: TCP
      - containerPort: ${TCP_BLACKBOX_NODEPORT_FAIL}
        hostPort: ${TCP_BLACKBOX_PORT_FAIL}
        protocol: TCP
      - containerPort: ${TCP_BLACKBOX_NODEPORT_DELETE}
        hostPort: ${TCP_BLACKBOX_PORT_DELETE}
        protocol: TCP
      - containerPort: ${TCP_BLACKBOX_NODEPORT_PARENT_CROSS}
        hostPort: ${TCP_BLACKBOX_PORT_PARENT_CROSS}
        protocol: TCP
      - containerPort: ${TLS_BLACKBOX_NODEPORT_SNI}
        hostPort: ${TLS_BLACKBOX_PORT_SNI}
        protocol: TCP
      - containerPort: ${TLS_BLACKBOX_NODEPORT_CROSS}
        hostPort: ${TLS_BLACKBOX_PORT_CROSS}
        protocol: TCP
      - containerPort: ${TLS_BLACKBOX_NODEPORT_FAIL}
        hostPort: ${TLS_BLACKBOX_PORT_FAIL}
        protocol: TCP
      - containerPort: ${TLS_BLACKBOX_NODEPORT_DELETE}
        hostPort: ${TLS_BLACKBOX_PORT_DELETE}
        protocol: TCP
YAML
  kind create cluster --name "$KIND_CLUSTER_NAME" --config "$(kind_config_path)" --wait 120s
  kind load docker-image "$FERRUM_IMAGE" --name "$KIND_CLUSTER_NAME"
}

file_sha256() {
  # Prefer sha256sum (Linux runners); fall back to shasum (macOS).
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "::error::neither sha256sum nor shasum is available" >&2
    return 1
  fi
}

expected_gateway_api_crd_sha256() {
  # Explicit override wins so a workflow_dispatch run can pin a different
  # Gateway API tag together with its own reviewed digest.
  if [ -n "$GATEWAY_API_EXPERIMENTAL_SHA256" ]; then
    printf '%s' "$GATEWAY_API_EXPERIMENTAL_SHA256"
    return 0
  fi
  if [ "$GATEWAY_API_VERSION" = "$GATEWAY_API_PINNED_VERSION" ]; then
    printf '%s' "$GATEWAY_API_PINNED_EXPERIMENTAL_SHA256"
    return 0
  fi
  echo "::error::no pinned SHA-256 for Gateway API ${GATEWAY_API_VERSION} (repository pin is ${GATEWAY_API_PINNED_VERSION}); set GATEWAY_API_EXPERIMENTAL_SHA256 to the reviewed digest for that tag" >&2
  return 1
}

# Fetch the CRD bundle to a local file and verify it against the pinned digest.
# Both a failed download and a digest mismatch are retried with backoff: the
# upstream release CDN answers 5xx during outages and can serve partially
# published bytes mid-release, and both read as this pull request's fault when
# the cascade surfaces as "the server doesn't have a resource type". Retrying
# never relaxes verification — every attempt must match the pin, and the last
# failing attempt exits non-zero.
fetch_gateway_api_crd_bundle() {
  local dest="$1"
  local url="$2"
  local expected="$3"
  local attempts="$GATEWAY_API_CRD_FETCH_ATTEMPTS"
  local i backoff actual

  if ! [[ "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    echo "::error::expected Gateway API CRD bundle digest must be a 64-character lowercase hex SHA-256" >&2
    return 1
  fi

  for i in $(seq 1 "$attempts"); do
    rm -f "$dest"
    if curl -fsSL --retry 3 --retry-all-errors --retry-delay 2 \
      --connect-timeout 30 --max-time 300 -o "$dest" "$url"; then
      actual="$(file_sha256 "$dest")" || return 1
      if [ "$actual" = "$expected" ]; then
        echo "Gateway API CRD bundle ${GATEWAY_API_VERSION} verified (sha256 ${actual})"
        return 0
      fi
      echo "::warning::Gateway API CRD bundle attempt ${i}/${attempts}: checksum mismatch (got ${actual}, want ${expected}); not applying these bytes"
    else
      echo "::warning::Gateway API CRD bundle attempt ${i}/${attempts} failed to download from ${url} (transient release CDN error?)"
    fi
    if [ "$i" -lt "$attempts" ]; then
      backoff=$((i * 5))
      echo "::warning::retrying Gateway API CRD bundle download in ${backoff}s"
      sleep "$backoff"
    fi
  done

  rm -f "$dest"
  echo "::error::Gateway API CRD bundle ${GATEWAY_API_VERSION} could not be downloaded and verified after ${attempts} attempts — likely a gateway-api release CDN outage or a stale checksum pin, not this change" >&2
  return 1
}

install_gateway_api_crds() {
  # Install the experimental-channel bundle (includes standard resources plus
  # TCPRoute/TLSRoute). Mixing standard-install with a standalone experimental
  # L4 CRD fails upstream init with "multiple gateway API CRDs channels detected".
  # Profile/features stay GATEWAY-HTTP,GATEWAY-GRPC /
  # Gateway,ReferenceGrant,HTTPRoute,GRPCRoute; TCPRoute/TLSRoute coverage
  # remains Ferrum black-box only.
  #
  # The bundle is downloaded to a file, checksum-verified against the pin above,
  # and only then applied — same posture as the checksum-pinned kind/kubectl/Helm
  # installs. kubectl never reads the URL itself, so a transient 504 is a retry
  # here rather than a required-gate failure, and the applied CRD content is a
  # reviewed input rather than whatever the URL serves that day.
  local bundle expected
  expected="$(expected_gateway_api_crd_sha256)"
  bundle="${RUNNER_TEMP:-/tmp}/gateway-api-experimental-install-${GATEWAY_API_VERSION}.yaml"
  fetch_gateway_api_crd_bundle "$bundle" \
    "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/experimental-install.yaml" \
    "$expected"
  kubectl apply --server-side=true -f "$bundle"
  for crd in \
    gatewayclasses.gateway.networking.k8s.io \
    gateways.gateway.networking.k8s.io \
    httproutes.gateway.networking.k8s.io \
    grpcroutes.gateway.networking.k8s.io \
    tcproutes.gateway.networking.k8s.io \
    tlsroutes.gateway.networking.k8s.io \
    referencegrants.gateway.networking.k8s.io; do
    kubectl wait --for=condition=Established "crd/${crd}" --timeout=120s
  done
}

create_tls_secret() {
  local namespace="$1"
  local name="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "$tmpdir/tls.key" \
    -out "$tmpdir/tls.crt" \
    -subj "/CN=*.example.com" \
    -addext "subjectAltName=DNS:*.example.com,DNS:example.com,DNS:second-example.org,DNS:*.wildcard.org,DNS:fourth-example.wildcard.org,DNS:tls.blackbox.example" \
    >/dev/null 2>&1
  kubectl -n "$namespace" create secret tls "$name" \
    --cert="$tmpdir/tls.crt" \
    --key="$tmpdir/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f -
}

create_frontend_tls_secret() {
  create_tls_secret "$CP_NAMESPACE" ferrum-gateway-data-plane-tls
}

deploy_control_plane() {
  # Namespaced reflectors must complete their initial list before the
  # reconciler publishes any status, including cluster-scoped GatewayClass
  # status. Create every explicit watch namespace before the controller starts
  # so a not-yet-created upstream backend namespace cannot hold readiness open.
  local watched_namespace
  for watched_namespace in \
    "$DP_GATEWAY_NAMESPACE" \
    "$BACKEND_NAMESPACE" \
    "$APP_BACKEND_NAMESPACE"; do
    kubectl create namespace "$watched_namespace" --dry-run=client -o yaml | kubectl apply -f -
  done
  kubectl create namespace "$CP_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  create_frontend_tls_secret
  # FERRUM_K8S_WATCH_IDLE_RELIST_SECS, not FERRUM_K8S_FULL_SYNC_INTERVAL_SECS, is
  # the bound on watch staleness: a full sync re-reconciles the SAME reflector
  # store. The black-box phases delete the upstream conformance objects and apply
  # their own seconds later, and a scope still holding a deleted Gateway or route
  # keeps serving it (issue #4491). Keep the window well inside the black-box
  # probe budgets rather than at the 300s production default; this matches the
  # standalone gateway_api_data_plane_conformance.sh control-plane deployment.
  # The short window buys convergence, not cover: the TLSRoute delete check in
  # gateway_api_tlsroute_conformance.sh fails when the withdrawal was repaired
  # by a relist instead of observed as a watch Delete event, so a missed delete
  # still turns the run red.
  # Harness owns GatewayClass/ferrum create/delete/recreate out of band; Helm must
  # not claim or recreate the cluster-scoped object (chart default is create=true).
  helm upgrade --install ferrum "$ROOT_DIR/charts/ferrum-mesh" \
    --namespace "$CP_NAMESPACE" \
    --set image.repository=ferrum-edge \
    --set image.tag=gateway-api-conformance \
    --set image.pullPolicy=IfNotPresent \
    --set injector.enabled=false \
    --set ca.enabled=false \
    --set gatewayClass.create=false \
    --set controlPlane.enabled=true \
    --set controlPlane.rbac.create=true \
    --set controlPlane.rbac.gatewayApi=true \
    --set controlPlane.rbac.istio=false \
    --set controlPlane.rbac.meshConfig=false \
    --set controlPlane.rbac.podDiscovery=true \
    --set controlPlane.database.type=sqlite \
    --set-string controlPlane.database.sqlite.path=/tmp/ferrum-gateway-api-conformance.db \
    --set controlPlane.database.sqlite.mode=rwc \
    --set-string controlPlane.credentials.adminJwtSecret.value="$ADMIN_SECRET" \
    --set-string controlPlane.credentials.cpDpGrpcJwtSecret.value="$JWT_SECRET" \
    --set-string "controlPlane.env.FERRUM_NAMESPACE=$DP_GATEWAY_NAMESPACE" \
    --set-string "controlPlane.env.FERRUM_K8S_WATCH_NAMESPACES=${DP_GATEWAY_NAMESPACE}\\,${BACKEND_NAMESPACE}\\,${APP_BACKEND_NAMESPACE}" \
    --set controlPlane.env.FERRUM_LOG_LEVEL=info \
    --set controlPlane.env.FERRUM_K8S_CONTROLLER_ENABLED=true \
    --set controlPlane.env.FERRUM_K8S_WATCH_GATEWAY_API_CRDS=true \
    --set controlPlane.env.FERRUM_K8S_WATCH_ISTIO_CRDS=false \
    --set controlPlane.env.FERRUM_K8S_WATCH_MESH_CONFIG=false \
    --set controlPlane.env.FERRUM_K8S_POD_DISCOVERY_ENABLED=true \
    --set controlPlane.env.FERRUM_K8S_FULL_SYNC_INTERVAL_SECS=15 \
    --set controlPlane.env.FERRUM_K8S_WATCH_IDLE_RELIST_SECS=20 \
    --set observability.enabled=true \
    --set observability.alerts.enabled=false \
    --set observability.dashboards.enabled=false \
    --set observability.metrics.serviceMonitor.enabled=false \
    --set observability.metrics.podMonitor.enabled=false \
    --set-string "observability.metrics.bearerToken.value=$METRICS_TOKEN" \
    --set controlPlane.env.FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAMESPACE="$CP_NAMESPACE" \
    --set controlPlane.env.FERRUM_GATEWAY_API_DATA_PLANE_SERVICE_NAME="$DP_SERVICE_NAME" \
    --set controlPlane.env.FERRUM_GATEWAY_API_STATUS_ADDRESS="$GATEWAY_API_STATUS_ADDRESS" \
    --set controlPlane.env.FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true

  kubectl -n "$CP_NAMESPACE" rollout status deployment/ferrum-mesh-control-plane --timeout=180s
}

deploy_data_plane() {
  cat <<YAML | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${DP_SERVICE_NAME}
  namespace: ${CP_NAMESPACE}
  labels:
    app.kubernetes.io/name: ${DP_SERVICE_NAME}
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ${DP_SERVICE_NAME}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${DP_SERVICE_NAME}
    spec:
      serviceAccountName: ferrum-mesh
      containers:
        - name: ferrum-edge
          image: ${FERRUM_IMAGE}
          imagePullPolicy: IfNotPresent
          args: ["run"]
          ports:
            - name: http
              containerPort: 8000
            - name: https
              containerPort: 8443
            - name: admin
              containerPort: 9000
            - name: tcp-main
              containerPort: ${TCP_BLACKBOX_PORT_MAIN}
            - name: tcp-cross
              containerPort: ${TCP_BLACKBOX_PORT_CROSS}
            - name: tcp-fail
              containerPort: ${TCP_BLACKBOX_PORT_FAIL}
            - name: tcp-delete
              containerPort: ${TCP_BLACKBOX_PORT_DELETE}
            - name: tcp-parent-xns
              containerPort: ${TCP_BLACKBOX_PORT_PARENT_CROSS}
            - name: tls-sni
              containerPort: ${TLS_BLACKBOX_PORT_SNI}
            - name: tls-cross
              containerPort: ${TLS_BLACKBOX_PORT_CROSS}
            - name: tls-fail
              containerPort: ${TLS_BLACKBOX_PORT_FAIL}
            - name: tls-delete
              containerPort: ${TLS_BLACKBOX_PORT_DELETE}
          env:
            - name: FERRUM_MODE
              value: dp
            - name: FERRUM_NAMESPACE
              value: ${DP_GATEWAY_NAMESPACE}
            - name: FERRUM_DP_CP_GRPC_URLS
              value: http://ferrum-mesh-control-plane.${CP_NAMESPACE}.svc.cluster.local:50051
            # Test harness: CP/DP gRPC config sync runs plaintext in-cluster.
            - name: FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT
              value: "true"
            - name: FERRUM_CP_DP_GRPC_JWT_SECRET
              value: ${JWT_SECRET}
            - name: FERRUM_ADMIN_JWT_SECRET
              value: ${ADMIN_SECRET}
            - name: FERRUM_PROXY_HTTP_PORT
              value: "8000"
            - name: FERRUM_PROXY_HTTPS_PORT
              value: "8443"
            - name: FERRUM_ADMIN_HTTP_PORT
              value: "9000"
            - name: FERRUM_FRONTEND_TLS_CERT_PATH
              value: /etc/ferrum/tls/tls.crt
            - name: FERRUM_FRONTEND_TLS_KEY_PATH
              value: /etc/ferrum/tls/tls.key
            - name: FERRUM_POOL_WARMUP_ENABLED
              value: "false"
            - name: FERRUM_LOG_LEVEL
              value: info
          readinessProbe:
            exec:
              command: ["/app/ferrum-edge", "health", "-p", "9000", "--host", "127.0.0.1"]
            periodSeconds: 2
            failureThreshold: 30
          volumeMounts:
            - name: frontend-tls
              mountPath: /etc/ferrum/tls
              readOnly: true
      volumes:
        - name: frontend-tls
          secret:
            secretName: ferrum-gateway-data-plane-tls
---
apiVersion: v1
kind: Service
metadata:
  name: ${DP_SERVICE_NAME}
  namespace: ${CP_NAMESPACE}
spec:
  type: NodePort
  selector:
    app.kubernetes.io/name: ${DP_SERVICE_NAME}
  ports:
    - name: http
      port: 80
      targetPort: http
      nodePort: 30080
    - name: https
      port: 443
      targetPort: https
      nodePort: 30443
    - name: tcp-main
      port: ${TCP_BLACKBOX_PORT_MAIN}
      targetPort: ${TCP_BLACKBOX_PORT_MAIN}
      nodePort: ${TCP_BLACKBOX_NODEPORT_MAIN}
    - name: tcp-cross
      port: ${TCP_BLACKBOX_PORT_CROSS}
      targetPort: ${TCP_BLACKBOX_PORT_CROSS}
      nodePort: ${TCP_BLACKBOX_NODEPORT_CROSS}
    - name: tcp-fail
      port: ${TCP_BLACKBOX_PORT_FAIL}
      targetPort: ${TCP_BLACKBOX_PORT_FAIL}
      nodePort: ${TCP_BLACKBOX_NODEPORT_FAIL}
    - name: tcp-delete
      port: ${TCP_BLACKBOX_PORT_DELETE}
      targetPort: ${TCP_BLACKBOX_PORT_DELETE}
      nodePort: ${TCP_BLACKBOX_NODEPORT_DELETE}
    - name: tcp-parent-xns
      port: ${TCP_BLACKBOX_PORT_PARENT_CROSS}
      targetPort: ${TCP_BLACKBOX_PORT_PARENT_CROSS}
      nodePort: ${TCP_BLACKBOX_NODEPORT_PARENT_CROSS}
    - name: tls-sni
      port: ${TLS_BLACKBOX_PORT_SNI}
      targetPort: ${TLS_BLACKBOX_PORT_SNI}
      nodePort: ${TLS_BLACKBOX_NODEPORT_SNI}
    - name: tls-cross
      port: ${TLS_BLACKBOX_PORT_CROSS}
      targetPort: ${TLS_BLACKBOX_PORT_CROSS}
      nodePort: ${TLS_BLACKBOX_NODEPORT_CROSS}
    - name: tls-fail
      port: ${TLS_BLACKBOX_PORT_FAIL}
      targetPort: ${TLS_BLACKBOX_PORT_FAIL}
      nodePort: ${TLS_BLACKBOX_NODEPORT_FAIL}
    - name: tls-delete
      port: ${TLS_BLACKBOX_PORT_DELETE}
      targetPort: ${TLS_BLACKBOX_PORT_DELETE}
      nodePort: ${TLS_BLACKBOX_NODEPORT_DELETE}
YAML
  kubectl -n "$CP_NAMESPACE" rollout status "deployment/${DP_SERVICE_NAME}" --timeout=240s
}

apply_gateway_class() {
  cat <<'YAML' | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: ferrum
spec:
  controllerName: ferrum.io/gateway-controller
YAML
}

wait_for_gateway_class() {
  # Block until the control plane reconciles the GatewayClass to Accepted before
  # handing off to the upstream Go suite. The suite has its own 180s wait for this
  # condition, but on a cold kind cluster the CP's first reconcile can outlast it,
  # surfacing as "GatewayClass ... Accepted ... context deadline exceeded" and
  # flaking the suite before any test runs. The class is applied before the CP
  # rollout so the controller's initial reflector list sees it; this wait confirms
  # the status writer completed before the conformance suite starts.
  if ! kubectl wait --for=condition=Accepted gatewayclass/ferrum --timeout=240s; then
    echo "GatewayClass 'ferrum' did not reach Accepted within timeout; current status:" >&2
    kubectl get gatewayclass ferrum -o yaml >&2 || true
    return 1
  fi
}

setup() {
  create_kind_cluster
  install_gateway_api_crds
  apply_gateway_class
  deploy_control_plane
  deploy_data_plane
  wait_for_gateway_class
}

# Gateway API lab setup with TCPRoute/TLSRoute listener ports and experimental
# CRDs. Kept separate from scripts/gateway_api_data_plane_conformance.sh because
# that file is a Trusted Cross Build Policy frozen automation surface on main.

case "${1:-}" in
  setup)
    setup
    ;;
  *)
    echo "usage: $0 setup" >&2
    exit 2
    ;;
esac
