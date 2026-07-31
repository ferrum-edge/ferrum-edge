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
  helm upgrade --install ferrum "$ROOT_DIR/charts/ferrum-mesh" \
    --namespace "$CP_NAMESPACE" \
    --set image.repository=ferrum-edge \
    --set image.tag=gateway-api-conformance \
    --set image.pullPolicy=IfNotPresent \
    --set injector.enabled=false \
    --set ca.enabled=false \
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
  redirect="$(curl_redirect blackbox.example /redirect)"
  if [ "$redirect" != "302 http://redirected.blackbox.example/redirected" ]; then
    echo "unexpected redirect response: ${redirect}" >&2
    return 1
  fi
  echo "request redirect returned ${redirect}" >> "$report"

  local seen_a=0
  local seen_b=0
  for _ in $(seq 1 20); do
    body="$(curl_body blackbox.example /weight)"
    grep -q "backend=blackbox-a" <<<"$body" && seen_a=1
    grep -q "backend=blackbox-b" <<<"$body" && seen_b=1
  done
  if [ "$seen_a" -ne 1 ] || [ "$seen_b" -ne 1 ]; then
    echo "weighted backend selection did not reach both backends" >&2
    return 1
  fi
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

  curl --fail --silent --show-error --max-time 10 --insecure \
    --resolve "tls.blackbox.example:443:${GATEWAY_API_STATUS_ADDRESS}" \
    https://tls.blackbox.example/tls | tee -a "$report"

  echo "GRPCRoute resource applied but request traffic is not run because Ferrum does not claim GATEWAY-GRPC support in this job." >> "$report"
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
EOF
}

case "${1:-}" in
  setup) setup ;;
  upstream) run_upstream_conformance ;;
  blackbox) run_blackbox_tests ;;
  diagnostics) collect_diagnostics ;;
  *)
    echo "usage: $0 {setup|upstream|blackbox|diagnostics}" >&2
    exit 2
    ;;
esac
