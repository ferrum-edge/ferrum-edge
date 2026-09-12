#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-ferrum-gwapi}"
FERRUM_IMAGE="${FERRUM_IMAGE:-ferrum-edge:gateway-api-conformance}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"
GATEWAY_API_PROFILE="${GATEWAY_API_PROFILE:-GATEWAY-HTTP}"
GATEWAY_API_SUPPORTED_FEATURES="${GATEWAY_API_SUPPORTED_FEATURES:-Gateway,ReferenceGrant,HTTPRoute}"
GATEWAY_API_SKIP_TESTS="${GATEWAY_API_SKIP_TESTS:-}"
GATEWAY_API_STATUS_ADDRESS="${GATEWAY_API_STATUS_ADDRESS:-127.0.0.1}"

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
# Dedicated scrape credential so a failure-only diagnostics step can read
# authenticated /metrics without minting an admin JWT. Must match the CP env.
METRICS_TOKEN="${METRICS_TOKEN:-ferrum-edge-gateway-api-conformance-metrics-token}"
ADMIN_HTTP_PORT="${ADMIN_HTTP_PORT:-9000}"

mkdir -p "$RESULTS_DIR"

kind_config_path() {
  printf '%s/kind-gateway-api.yaml' "${RUNNER_TEMP:-/tmp}"
}

create_kind_cluster() {
  cat > "$(kind_config_path)" <<'YAML'
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
YAML
  kind create cluster --name "$KIND_CLUSTER_NAME" --config "$(kind_config_path)" --wait 120s
  kind load docker-image "$FERRUM_IMAGE" --name "$KIND_CLUSTER_NAME"
}

install_gateway_api_crds() {
  kubectl apply --server-side=true \
    -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"
  for crd in \
    gatewayclasses.gateway.networking.k8s.io \
    gateways.gateway.networking.k8s.io \
    httproutes.gateway.networking.k8s.io \
    grpcroutes.gateway.networking.k8s.io \
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
  # store. The black-box phase deletes the upstream conformance Gateways and
  # applies its own seconds later, and Ferrum serves one frontend TLS certificate
  # per Gateway namespace, so a scope still holding a deleted Gateway makes the
  # new Gateway lose that slot and withholds its HTTPS listener routes (404, not
  # 502). Keep the window well inside the 120s black-box probe budget rather than
  # at the 300s production default.
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

run_upstream_conformance() {
  rm -rf /tmp/gateway-api
  git clone --depth 1 --branch "$GATEWAY_API_VERSION" \
    https://github.com/kubernetes-sigs/gateway-api.git /tmp/gateway-api
  cd /tmp/gateway-api
  local args=(
    ./conformance
    -run TestConformance
    -count=1
    -timeout=45m
    -args
    --gateway-class=ferrum
    --conformance-profiles="$GATEWAY_API_PROFILE"
    --supported-features="$GATEWAY_API_SUPPORTED_FEATURES"
    --cleanup-base-resources=false
    --organization=Ferrum
    --project="Ferrum Edge"
    --url=https://github.com/ferrum-edge/ferrum-edge
    --version="${GITHUB_SHA:-local}"
    --contact=https://github.com/ferrum-edge/ferrum-edge/issues
    --report-output="$RESULTS_DIR/gateway-api-conformance-report.yaml"
  )
  if [ -n "$GATEWAY_API_SKIP_TESTS" ]; then
    args+=(--skip-tests="$GATEWAY_API_SKIP_TESTS")
  fi
  go test -json "${args[@]}" 2>&1 | tee "$RESULTS_DIR/gateway-api-conformance-test.json"
}

apply_blackbox_backends() {
  kubectl create namespace "$DP_GATEWAY_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create namespace "$BACKEND_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl label namespace "$DP_GATEWAY_NAMESPACE" gateway-conformance=backend --overwrite
  kubectl label namespace "$BACKEND_NAMESPACE" gateway-conformance=backend --overwrite
  create_tls_secret "$DP_GATEWAY_NAMESPACE" blackbox-tls
  cat <<'YAML' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-a
  namespace: gateway-conformance-infra
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-a
  template:
    metadata:
      labels:
        app: blackbox-a
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: blackbox-a
          command: ["python", "-c"]
          args:
            - |
              import os
              from http.server import BaseHTTPRequestHandler, HTTPServer
              class H(BaseHTTPRequestHandler):
                  def do_GET(self): self.reply()
                  def do_POST(self): self.reply()
                  def reply(self):
                      body = f"backend={os.environ['BACKEND_NAME']}\nmethod={self.command}\npath={self.path}\nhost={self.headers.get('host','')}\nx-ferrum-test={self.headers.get('x-ferrum-test','')}\nx-added-by-ferrum={self.headers.get('x-added-by-ferrum','')}\n"
                      self.send_response(200)
                      self.end_headers()
                      self.wfile.write(body.encode())
                      print(body.replace("\n", " "), flush=True)
              HTTPServer(("", 8080), H).serve_forever()
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-a
  namespace: gateway-conformance-infra
spec:
  selector:
    app: blackbox-a
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-b
  namespace: gateway-conformance-infra
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-b
  template:
    metadata:
      labels:
        app: blackbox-b
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: blackbox-b
          command: ["python", "-c"]
          args:
            - |
              import os
              from http.server import BaseHTTPRequestHandler, HTTPServer
              class H(BaseHTTPRequestHandler):
                  def do_GET(self): self.reply()
                  def do_POST(self): self.reply()
                  def reply(self):
                      body = f"backend={os.environ['BACKEND_NAME']}\nmethod={self.command}\npath={self.path}\nhost={self.headers.get('host','')}\nx-ferrum-test={self.headers.get('x-ferrum-test','')}\nx-added-by-ferrum={self.headers.get('x-added-by-ferrum','')}\n"
                      self.send_response(200)
                      self.end_headers()
                      self.wfile.write(body.encode())
                      print(body.replace("\n", " "), flush=True)
              HTTPServer(("", 8080), H).serve_forever()
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-b
  namespace: gateway-conformance-infra
spec:
  selector:
    app: blackbox-b
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-cross
  namespace: gateway-conformance-web-backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-cross
  template:
    metadata:
      labels:
        app: blackbox-cross
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: blackbox-cross
          command: ["python", "-c"]
          args:
            - |
              import os
              from http.server import BaseHTTPRequestHandler, HTTPServer
              class H(BaseHTTPRequestHandler):
                  def do_GET(self): self.reply()
                  def do_POST(self): self.reply()
                  def reply(self):
                      body = f"backend={os.environ['BACKEND_NAME']}\nmethod={self.command}\npath={self.path}\nhost={self.headers.get('host','')}\nx-ferrum-test={self.headers.get('x-ferrum-test','')}\nx-added-by-ferrum={self.headers.get('x-added-by-ferrum','')}\n"
                      self.send_response(200)
                      self.end_headers()
                      self.wfile.write(body.encode())
                      print(body.replace("\n", " "), flush=True)
              HTTPServer(("", 8080), H).serve_forever()
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-cross
  namespace: gateway-conformance-web-backend
spec:
  selector:
    app: blackbox-cross
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-empty
  namespace: gateway-conformance-infra
spec:
  ports:
    - name: http
      port: 8080
      targetPort: 8080
YAML
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-a --timeout=180s
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-b --timeout=180s
  kubectl -n "$BACKEND_NAMESPACE" rollout status deployment/blackbox-cross --timeout=180s
}

cleanup_upstream_gateway_api_resources_for_blackbox() {
  local resource
  for resource in \
    gateways.gateway.networking.k8s.io \
    httproutes.gateway.networking.k8s.io \
    grpcroutes.gateway.networking.k8s.io \
    referencegrants.gateway.networking.k8s.io; do
    kubectl -n "$DP_GATEWAY_NAMESPACE" delete "$resource" --all --ignore-not-found
  done
  kubectl -n "$BACKEND_NAMESPACE" delete \
    referencegrants.gateway.networking.k8s.io --all --ignore-not-found
}

apply_blackbox_routes() {
  cat <<'YAML' | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox
  namespace: gateway-conformance-infra
spec:
  gatewayClassName: ferrum
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              gateway-conformance: backend
    - name: https
      port: 443
      protocol: HTTPS
      hostname: tls.blackbox.example
      tls:
        mode: Terminate
        certificateRefs:
          - name: blackbox-tls
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: blackbox-main
  namespace: gateway-conformance-infra
spec:
  hostnames: ["blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox
      sectionName: http
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /host
      backendRefs:
        - name: blackbox-a
          port: 8080
    - matches:
        - method: POST
          path:
            type: PathPrefix
            value: /method
      backendRefs:
        - name: blackbox-b
          port: 8080
    - matches:
        - headers:
            - name: x-ferrum-test
              value: ok
          path:
            type: PathPrefix
            value: /header
      backendRefs:
        - name: blackbox-b
          port: 8080
    - matches:
        - path:
            type: PathPrefix
            value: /modifier
      filters:
        - type: RequestHeaderModifier
          requestHeaderModifier:
            set:
              - name: x-added-by-ferrum
                value: ok
      backendRefs:
        - name: blackbox-a
          port: 8080
    - matches:
        - path:
            type: PathPrefix
            value: /redirect
      filters:
        - type: RequestRedirect
          requestRedirect:
            hostname: redirected.blackbox.example
            path:
              type: ReplaceFullPath
              replaceFullPath: /redirected
            statusCode: 302
    - matches:
        - path:
            type: PathPrefix
            value: /weight
      backendRefs:
        - name: blackbox-a
          port: 8080
          weight: 1
        - name: blackbox-b
          port: 8080
          weight: 1
    - matches:
        - path:
            type: PathPrefix
            value: /down
      backendRefs:
        - name: blackbox-empty
          port: 8080
    - matches:
        - path:
            type: PathPrefix
            value: /zero-weight
      backendRefs:
        - name: blackbox-a
          port: 8080
          weight: 0
    - matches:
        - path:
            type: PathPrefix
            value: /zero
      backendRefs:
        - name: blackbox-a
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: blackbox-update
  namespace: gateway-conformance-infra
spec:
  hostnames: ["blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox
      sectionName: http
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /update
      backendRefs:
        - name: blackbox-a
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: blackbox-delete
  namespace: gateway-conformance-infra
spec:
  hostnames: ["blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox
      sectionName: http
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /delete
      backendRefs:
        - name: blackbox-a
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: blackbox-invalid
  namespace: gateway-conformance-infra
spec:
  hostnames: ["blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox
      sectionName: http
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /invalid
      backendRefs:
        - name: blackbox-missing
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: blackbox-cross
  namespace: gateway-conformance-infra
spec:
  hostnames: ["cross.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox
      sectionName: http
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /cross
      backendRefs:
        - name: blackbox-cross
          namespace: gateway-conformance-web-backend
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-infra-route-to-blackbox-cross
  namespace: gateway-conformance-web-backend
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: gateway-conformance-infra
  to:
    - group: ""
      kind: Service
      name: blackbox-cross
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: blackbox-tls
  namespace: gateway-conformance-infra
spec:
  hostnames: ["tls.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox
      sectionName: https
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /tls
      backendRefs:
        - name: blackbox-a
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-declared-unsupported
  namespace: gateway-conformance-infra
spec:
  hostnames: ["grpc.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox
      sectionName: http
  rules:
    - backendRefs:
        - name: blackbox-a
          port: 8080
YAML
}

curl_body() {
  local host="$1"
  local path="$2"
  shift 2
  curl --fail --silent --show-error --max-time 10 \
    -H "Host: ${host}" "$@" "http://${GATEWAY_API_STATUS_ADDRESS}${path}"
}

curl_status() {
  local host="$1"
  local path="$2"
  curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    -H "Host: ${host}" "http://${GATEWAY_API_STATUS_ADDRESS}${path}"
}

curl_redirect() {
  local host="$1"
  local path="$2"
  curl --silent --output /dev/null --write-out '%{http_code} %{redirect_url}' --max-time 10 \
    -H "Host: ${host}" "http://${GATEWAY_API_STATUS_ADDRESS}${path}"
}

curl_tls_body() {
  local host="$1"
  local path="$2"
  curl --fail --silent --show-error --max-time 10 --insecure \
    --resolve "${host}:443:${GATEWAY_API_STATUS_ADDRESS}" \
    "https://${host}${path}"
}

# Wait until the redirect rule is programmed before asserting the 302.
#
# Same class as the /weight RCA below (PR #3971): the redirect rule is one rule
# among several on the same HTTPRoute, so an intermediate snapshot can 404 it
# while sibling paths already answer. `curl_redirect` is a single shot, so that
# propagation race failed the whole suite under `bash -e` with
# "unexpected redirect response: 404" and no retry — unlike every assertion
# above it, which polls through wait_for_body_contains.
#
# Always exits 0 and prints the last observed value so the caller's existing
# comparison still reports a genuine mismatch.
wait_for_redirect() {
  local host="$1"
  local path="$2"
  local expected="$3"
  local redirect=""
  for _ in $(seq 1 60); do
    redirect="$(curl_redirect "$host" "$path" 2>/dev/null || true)"
    if [ "$redirect" = "$expected" ]; then
      break
    fi
    sleep 2
  done
  printf '%s\n' "$redirect"
}

wait_for_body_contains() {
  local host="$1"
  local path="$2"
  local expected="$3"
  shift 3
  for _ in $(seq 1 60); do
    if body="$(curl_body "$host" "$path" "$@" 2>/dev/null)" && grep -q "$expected" <<<"$body"; then
      printf '%s\n' "$body"
      return 0
    fi
    sleep 2
  done
  echo "expected ${host}${path} to contain ${expected}" >&2
  return 1
}

# Wait until /weight is served, then rapid-sample both backends.
#
# Hosted RCA (PR #3971, SHA 3e4f5e4): neighboring PathPrefix rules on the same
# HTTPRoute were already answering, then `curl --fail` aborted the script on the
# first /weight 404 (exit 22) before the 20-probe loop ran. The weighted rule
# programs a backend set, so an intermediate snapshot can omit that path even
# while /host and /redirect are live. Treat that miss like wait_for_body_contains
# (60 * 2s). Once a 200 lands, fire the original 20-probe budget with no sleep
# so a single-backend product defect fails quickly instead of soaking 2s gaps.
# Failure prints which backends were seen, sample count, last body, and last
# HTTP status so a 404 miss cannot be confused with broken weighting.
wait_for_weighted_backends() {
  local host="$1"
  local path="$2"
  local seen_a=0
  local seen_b=0
  local last_body=""
  local samples=0
  local body

  for _ in $(seq 1 60); do
    if body="$(curl_body "$host" "$path" 2>/dev/null)"; then
      last_body="$body"
      samples=$((samples + 1))
      grep -q "backend=blackbox-a" <<<"$body" && seen_a=1
      grep -q "backend=blackbox-b" <<<"$body" && seen_b=1
      break
    fi
    sleep 2
  done
  if [ "$samples" -eq 0 ]; then
    echo "weighted path ${host}${path} did not converge (seen_a=${seen_a} seen_b=${seen_b} samples=0 last_http=$(curl_status "$host" "$path"))" >&2
    return 1
  fi

  for _ in $(seq 1 19); do
    if [ "$seen_a" -eq 1 ] && [ "$seen_b" -eq 1 ]; then
      break
    fi
    if body="$(curl_body "$host" "$path" 2>/dev/null)"; then
      last_body="$body"
      samples=$((samples + 1))
      grep -q "backend=blackbox-a" <<<"$body" && seen_a=1
      grep -q "backend=blackbox-b" <<<"$body" && seen_b=1
    else
      # A later snapshot can 404 the weighted path again; do not burn the
      # remaining samples in a tight loop, and do not treat that miss as a hit.
      sleep 2
    fi
  done

  if [ "$seen_a" -ne 1 ] || [ "$seen_b" -ne 1 ]; then
    echo "weighted backend selection did not reach both backends (seen_a=${seen_a} seen_b=${seen_b} samples=${samples} last_body=${last_body} last_http=$(curl_status "$host" "$path"))" >&2
    return 1
  fi
  printf '%s\n' "$last_body"
}

# Same retry budget as wait_for_body_contains, over the HTTPS listener. The TLS
# route is the only black-box assertion whose listener depends on the CP having
# already withdrawn the deleted upstream Gateway's claim on the namespace's
# single frontend TLS slot, so it needs at least as much convergence room as the
# plaintext probes, not a single non-retrying request.
wait_for_tls_body_contains() {
  local host="$1"
  local path="$2"
  local expected="$3"
  for _ in $(seq 1 60); do
    if body="$(curl_tls_body "$host" "$path" 2>/dev/null)" && grep -q "$expected" <<<"$body"; then
      printf '%s\n' "$body"
      return 0
    fi
    sleep 2
  done
  echo "expected https://${host}${path} to contain ${expected}" >&2
  return 1
}

run_blackbox_tests() {
  cleanup_upstream_gateway_api_resources_for_blackbox
  apply_blackbox_backends
  apply_blackbox_routes
  local report="$RESULTS_DIR/gateway-api-blackbox.md"
  : > "$report"
  echo "# Gateway API Black-Box Traffic" >> "$report"

  wait_for_body_contains blackbox.example /host "backend=blackbox-a" | tee -a "$report"
  wait_for_body_contains blackbox.example /method "method=POST" -X POST | tee -a "$report"
  wait_for_body_contains blackbox.example /header "x-ferrum-test=ok" -H "x-ferrum-test: ok" | tee -a "$report"
  wait_for_body_contains blackbox.example /modifier "x-added-by-ferrum=ok" | tee -a "$report"
  wait_for_body_contains cross.blackbox.example /cross "backend=blackbox-cross" | tee -a "$report"

  local redirect
  redirect="$(wait_for_redirect blackbox.example /redirect \
    "302 http://redirected.blackbox.example/redirected")"
  if [ "$redirect" != "302 http://redirected.blackbox.example/redirected" ]; then
    echo "unexpected redirect response: ${redirect}" >&2
    return 1
  fi
  echo "request redirect returned ${redirect}" >> "$report"

  wait_for_weighted_backends blackbox.example /weight | tee -a "$report"
  echo "weighted backend selection reached blackbox-a and blackbox-b" >> "$report"

  local invalid_status
  invalid_status="$(curl_status blackbox.example /invalid)"
  if [ "$invalid_status" != "500" ]; then
    echo "invalid backendRef returned ${invalid_status}, expected 500" >&2
    return 1
  fi
  echo "invalid backendRef failed closed with HTTP ${invalid_status}" >> "$report"

  local zero_weight_status
  zero_weight_status="$(curl_status blackbox.example /zero-weight)"
  if [ "$zero_weight_status" != "500" ]; then
    echo "zero-weight-only rule returned ${zero_weight_status}, expected 500" >&2
    return 1
  fi
  echo "zero-weight-only rule failed closed with HTTP ${zero_weight_status}" >> "$report"

  local down_status
  down_status="$(curl_status blackbox.example /down)"
  if [ "$down_status" = "200" ]; then
    echo "backend with no endpoints returned 200" >&2
    return 1
  fi
  echo "backend with no endpoints failed closed with HTTP ${down_status}" >> "$report"

  wait_for_body_contains blackbox.example /update "backend=blackbox-a" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" patch httproute blackbox-update --type=json \
    -p='[{"op":"replace","path":"/spec/rules/0/backendRefs/0/name","value":"blackbox-b"}]'
  wait_for_body_contains blackbox.example /update "backend=blackbox-b" | tee -a "$report"

  wait_for_body_contains blackbox.example /delete "backend=blackbox-a" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete httproute blackbox-delete
  local delete_status
  for _ in $(seq 1 30); do
    delete_status="$(curl_status blackbox.example /delete)"
    [ "$delete_status" != "200" ] && break
    sleep 2
  done
  if [ "$delete_status" = "200" ]; then
    echo "deleted route kept returning 200" >&2
    return 1
  fi
  echo "deleted route stopped serving with HTTP ${delete_status}" >> "$report"

  wait_for_tls_body_contains tls.blackbox.example /tls "backend=blackbox-a" \
    | tee -a "$report"

  if [[ ",${GATEWAY_API_SUPPORTED_FEATURES}," == *",GRPCRoute,"* ]]; then
    echo "GRPCRoute resource applied; live request traffic coverage is provided by the upstream Gateway API conformance suite (GRPCRoute is in GATEWAY_API_SUPPORTED_FEATURES)." >> "$report"
  else
    echo "GRPCRoute resource applied but request traffic is not run because GRPCRoute is not in GATEWAY_API_SUPPORTED_FEATURES for this job." >> "$report"
  fi
}

collect_diagnostics() {
  set +e
  mkdir -p "$RESULTS_DIR"
  kubectl get gatewayclasses,gateways,httproutes,grpcroutes,referencegrants -A -o yaml > "$RESULTS_DIR/gateway-api-resources.yaml"
  kubectl get namespaces --show-labels > "$RESULTS_DIR/namespaces.txt"
  kubectl get pods,deployments,services,endpoints,endpointslices -A -o wide > "$RESULTS_DIR/kubernetes-workloads.txt"
  kubectl -n "$CP_NAMESPACE" describe deployment/ferrum-mesh-control-plane > "$RESULTS_DIR/ferrum-control-plane-deployment.txt"
  kubectl -n "$CP_NAMESPACE" describe "deployment/${DP_SERVICE_NAME}" > "$RESULTS_DIR/ferrum-data-plane-deployment.txt"
  kubectl -n "$CP_NAMESPACE" describe pods > "$RESULTS_DIR/ferrum-pods.txt"
  kubectl -n "$CP_NAMESPACE" logs deployment/ferrum-mesh-control-plane --all-containers --tail=2000 > "$RESULTS_DIR/ferrum-control-plane.log"
  kubectl -n "$CP_NAMESPACE" logs deployment/ferrum-mesh-control-plane --all-containers --previous --tail=2000 > "$RESULTS_DIR/ferrum-control-plane-previous.log"
  kubectl -n "$CP_NAMESPACE" logs "deployment/${DP_SERVICE_NAME}" --all-containers --tail=2000 > "$RESULTS_DIR/ferrum-data-plane.log"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-a --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-a.log"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-b --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-b.log"
  kubectl -n "$BACKEND_NAMESPACE" logs deployment/blackbox-cross --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-cross.log"
  kubectl -n "$CP_NAMESPACE" get events --sort-by=.lastTimestamp > "$RESULTS_DIR/ferrum-events.txt"
  cat > "$RESULTS_DIR/CONFORMANCE.md" <<EOF
# Gateway API Conformance

Gateway API version: ${GATEWAY_API_VERSION}

Profile: ${GATEWAY_API_PROFILE}

Supported features: ${GATEWAY_API_SUPPORTED_FEATURES}

Gateway API status address: ${GATEWAY_API_STATUS_ADDRESS}

Ferrum data-plane Service: ${CP_NAMESPACE}/${DP_SERVICE_NAME}

Artifacts:
- gateway-api-conformance-test.json
- gateway-api-conformance-report.yaml
- gateway-api-blackbox.md
- gateway-api-resources.yaml
- kubernetes-workloads.txt
- ferrum-pods.txt
- ferrum-control-plane.log
- ferrum-control-plane-previous.log
- ferrum-data-plane.log
- blackbox-*.log
- failure-evidence/ (only on a failing job; see that directory's README)
EOF
}

# Failure-only capture for issue #4239: distinguish slow reconcile under
# contention from a watch that stopped delivering. Green runs skip this.
# Output is files under $RESULTS_DIR/failure-evidence/ (capped); do not echo
# large YAML into the job log.
collect_failure_evidence() {
  set +e
  set +o pipefail
  local dest="$RESULTS_DIR/failure-evidence"
  mkdir -p "$dest"
  echo "Collecting Gateway API failure evidence into $dest"

  cat > "$dest/README.md" <<'EOF'
# Gateway API conformance failure evidence

Captured only when a conformance step fails. Use it to tell (a) slow
reconciliation under contention from (b) a watch that stopped delivering.

- `controller.log` / `controller-previous.log`: Ferrum control-plane logs.
  Route parent-status publications log `latency_ms`. "Reconciliation complete"
  is emitted only on an actual config change.
- `controller-metrics-k8s.txt`: `ferrum_k8s_controller_*` families from
  authenticated `/metrics` (reconciliations, full_syncs, errors, last
  reconcile duration, watch_idle_relists, route-status publication latency,
  and the issue #4239 status budget counters `status_request_timeouts_total` /
  `status_batch_timeouts_total`). For a "deleted object kept serving" failure,
  `watch_deletes_total` and `config_publications_total` are the issue #4491
  pair: neither advancing across the deletion means the withdrawal was never
  observed; both advancing rules the control plane out.
- `status-budget-warnings.txt`: every controller line about a status operation
  that exceeded its budget or a batch that held the reconcile loop. A reconcile
  whose `elapsed_ms` dwarfs its neighbours next to one of these lines is the
  #4239 shape (one stalled status write blocking every other publication), not
  a wedged watch.
- `httproutes-status.txt`: compact parent-status digest. Empty Ferrum
  `parents[]` with a live HTTPRoute is the suite's 60s wait.
- `httproutes.yaml` / `gateways.describe.txt`: cluster objects at failure.
- `top-nodes.txt` / `top-pods.txt` / `nodes.describe.txt`: resource pressure.
  `kubectl top` needs metrics-server; kind labs usually fall back to describe.
EOF

  kubectl -n "$CP_NAMESPACE" logs deployment/ferrum-mesh-control-plane \
    --all-containers --tail=4000 > "$dest/controller.log" 2>&1
  kubectl -n "$CP_NAMESPACE" logs deployment/ferrum-mesh-control-plane \
    --all-containers --previous --tail=2000 > "$dest/controller-previous.log" 2>&1

  # Surface the status-budget evidence in the JOB LOG too. The #4239 root cause
  # was already in this artifact, but nothing in the log pointed at it, so
  # triage needed an artifact download first.
  grep -E 'exceeded its budget|held the reconcile loop|defensive backstop' \
    "$dest/controller.log" "$dest/controller-previous.log" \
    | tail -n 40 > "$dest/status-budget-warnings.txt" 2>/dev/null \
    || echo "no status-budget warnings in the captured controller logs" \
      > "$dest/status-budget-warnings.txt"
  echo "--- controller status-budget warnings ---"
  cat "$dest/status-budget-warnings.txt"
  echo "--- end controller status-budget warnings ---"

  kubectl get httproutes.gateway.networking.k8s.io -A -o json \
    2>"$dest/httproutes.err" | head -c 1048576 > "$dest/httproutes.json"
  python3 - "$dest/httproutes.json" "$dest/httproutes-status.txt" <<'PY'
import json
import sys

src, dest = sys.argv[1], sys.argv[2]
try:
    with open(src, encoding="utf-8") as handle:
        doc = json.load(handle)
except Exception as exc:
    with open(dest, "w", encoding="utf-8") as handle:
        handle.write(f"failed to parse HTTPRoute list: {exc}\n")
    sys.exit(0)

items = doc.get("items") or []
lines = [f"httproutes={len(items)}"]
for item in items:
    md = item.get("metadata") or {}
    st = item.get("status") or {}
    parents = st.get("parents") or []
    ns = md.get("namespace") or ""
    name = md.get("name") or ""
    lines.append(
        f"{ns}/{name} generation={md.get('generation')} "
        f"resourceVersion={md.get('resourceVersion')} parents={len(parents)}"
    )
    for parent in parents:
        pref = parent.get("parentRef") or {}
        conds = ",".join(
            f"{c.get('type')}={c.get('status')}/{c.get('reason')}"
            for c in (parent.get("conditions") or [])
        )
        lines.append(
            f"  controller={parent.get('controllerName')} "
            f"parent={pref.get('namespace')}/{pref.get('name')} {conds}"
        )
with open(dest, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
PY
  rm -f "$dest/httproutes.json"
  kubectl get httproutes.gateway.networking.k8s.io -A -o yaml 2>/dev/null \
    | head -c 1048576 > "$dest/httproutes.yaml"

  : > "$dest/gateways.describe.txt"
  while read -r ns name; do
    [ -n "$name" ] || continue
    kubectl -n "$ns" describe "gateway.gateway.networking.k8s.io/$name"
  done < <(
    kubectl get gateways.gateway.networking.k8s.io -A \
      --no-headers -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name 2>/dev/null
  ) 2>&1 | head -c 524288 >> "$dest/gateways.describe.txt"

  if kubectl top nodes > "$dest/top-nodes.txt" 2>&1; then
    kubectl top pods -A --sort-by=cpu > "$dest/top-pods.txt" 2>&1
  else
    echo "kubectl top unavailable; see nodes.describe.txt" >> "$dest/top-pods.txt"
  fi
  kubectl describe nodes 2>&1 | head -c 524288 > "$dest/nodes.describe.txt"

  scrape_controller_metrics "$dest"

  echo "Failure evidence written under $dest"
}

scrape_controller_metrics() {
  local dest="$1"
  local local_port=18090
  local pf_log="$dest/port-forward.log"
  local metrics_raw="$dest/controller-metrics.prom"
  local metrics_tmp="$dest/controller-metrics.prom.tmp"
  local pf_pid=""

  kubectl -n "$CP_NAMESPACE" port-forward \
    deploy/ferrum-mesh-control-plane \
    "${local_port}:${ADMIN_HTTP_PORT}" \
    >"$pf_log" 2>&1 &
  pf_pid=$!

  local scraped=""
  local attempt
  for attempt in 1 2 3 4 5; do
    sleep 1
    if curl -fsS -m 5 \
      -H "Authorization: Bearer ${METRICS_TOKEN}" \
      -o "$metrics_tmp" \
      "http://127.0.0.1:${local_port}/metrics" \
      2>"$dest/controller-metrics.err"
    then
      scraped=1
      break
    fi
  done

  if [ -n "$scraped" ]; then
    head -c 262144 "$metrics_tmp" > "$metrics_raw"
    grep -E '^(# (HELP|TYPE) )?ferrum_k8s_controller' "$metrics_raw" \
      > "$dest/controller-metrics-k8s.txt" 2>/dev/null \
      || echo "no ferrum_k8s_controller families in scrape" \
        > "$dest/controller-metrics-k8s.txt"
  else
    echo "controller /metrics scrape failed after ${attempt} attempts; see controller-metrics.err and port-forward.log" \
      > "$dest/controller-metrics-k8s.txt"
  fi
  rm -f "$metrics_tmp"

  if [ -n "$pf_pid" ]; then
    kill "$pf_pid" >/dev/null 2>&1
    wait "$pf_pid" >/dev/null 2>&1
  fi
}

case "${1:-}" in
  setup) setup ;;
  upstream) run_upstream_conformance ;;
  blackbox) run_blackbox_tests ;;
  diagnostics) collect_diagnostics ;;
  failure-evidence) collect_failure_evidence ;;
  *)
    echo "usage: $0 {setup|upstream|blackbox|diagnostics|failure-evidence}" >&2
    exit 2
    ;;
esac
