#!/usr/bin/env bash
# Ferrum-specific live black-box coverage for Gateway API ListenerSet.
# Does NOT advertise upstream ListenerSet / GATEWAY-* profile features.
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"
DP_GATEWAY_NAMESPACE="${DP_GATEWAY_NAMESPACE:-gateway-conformance-infra}"
GATEWAY_API_STATUS_ADDRESS="${GATEWAY_API_STATUS_ADDRESS:-127.0.0.1}"
LISTENERSET_HOST="${LISTENERSET_HOST:-listenerset-blackbox.example}"
LISTENERSET_PATH="${LISTENERSET_PATH:-/listenerset-blackbox}"

mkdir -p "$RESULTS_DIR"

curl_status() {
  local host="$1"
  local path="$2"
  curl --silent --output /dev/null --write-out '%{http_code}' --max-time 10 \
    -H "Host: ${host}" "http://${GATEWAY_API_STATUS_ADDRESS}${path}" || true
}

wait_for_status() {
  local expected="$1"
  local label="$2"
  local code=""
  for _ in $(seq 1 45); do
    code="$(curl_status "$LISTENERSET_HOST" "$LISTENERSET_PATH")"
    if [ "$code" = "$expected" ]; then
      echo "ListenerSet black-box ${label}: HTTP ${code}"
      return 0
    fi
    sleep 2
  done
  echo "ListenerSet black-box ${label}: expected HTTP ${expected}, got '${code}'" >&2
  return 1
}

condition_status() {
  local kind="$1"
  local name="$2"
  local ctype="$3"
  kubectl -n "$DP_GATEWAY_NAMESPACE" get "$kind" "$name" \
    -o "jsonpath={.status.conditions[?(@.type==\"${ctype}\")].status}" 2>/dev/null || true
}

route_parent_condition_status() {
  local kind="$1"
  local name="$2"
  local ctype="$3"
  kubectl -n "$DP_GATEWAY_NAMESPACE" get "$kind" "$name" \
    -o "jsonpath={.status.parents[0].conditions[?(@.type==\"${ctype}\")].status}" 2>/dev/null || true
}

apply_resources() {
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox-listenerset
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  gatewayClassName: ferrum
  allowedListeners:
    namespaces:
      from: Same
  listeners:
    - name: gateway-http
      port: 80
      protocol: HTTP
      hostname: "gateway-listenerset-anchor.example"
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata:
  name: ferrum-blackbox-listenerset
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: ferrum-blackbox-listenerset
    namespace: ${DP_GATEWAY_NAMESPACE}
  listeners:
    - name: set-http
      port: 80
      protocol: HTTP
      hostname: "${LISTENERSET_HOST}"
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ferrum-blackbox-listenerset
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - group: gateway.networking.k8s.io
      kind: ListenerSet
      name: ferrum-blackbox-listenerset
      namespace: ${DP_GATEWAY_NAMESPACE}
  hostnames:
    - ${LISTENERSET_HOST}
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: ${LISTENERSET_PATH}
      backendRefs:
        - name: infra-backend-v1
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox-listenerset-denied
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  gatewayClassName: ferrum
  listeners:
    - name: gateway-http
      port: 80
      protocol: HTTP
      hostname: "gateway-listenerset-denied.example"
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: ListenerSet
metadata:
  name: ferrum-blackbox-listenerset-denied
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: ferrum-blackbox-listenerset-denied
    namespace: ${DP_GATEWAY_NAMESPACE}
  listeners:
    - name: denied-http
      port: 80
      protocol: HTTP
      hostname: "listenerset-denied.example"
      allowedRoutes:
        namespaces:
          from: Same
YAML
}

run_blackbox() {
  local report="$RESULTS_DIR/gateway-api-blackbox.md"
  apply_resources

  local accepted=""
  for _ in $(seq 1 45); do
    accepted="$(condition_status listenerset ferrum-blackbox-listenerset Accepted)"
    if [ "$accepted" = "True" ]; then
      break
    fi
    sleep 2
  done
  if [ "$accepted" != "True" ]; then
    echo "ListenerSet ferrum-blackbox-listenerset Accepted='${accepted}'" >&2
    return 1
  fi

  local attached=""
  for _ in $(seq 1 45); do
    attached="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get gateway ferrum-blackbox-listenerset \
      -o jsonpath='{.status.attachedListenerSets}' 2>/dev/null || true)"
    if [ "$attached" = "1" ]; then
      break
    fi
    sleep 2
  done
  if [ "$attached" != "1" ]; then
    echo "Gateway attachedListenerSets='${attached}' (expected 1)" >&2
    return 1
  fi

  local route_accepted=""
  local route_programmed=""
  for _ in $(seq 1 45); do
    route_accepted="$(route_parent_condition_status httproute ferrum-blackbox-listenerset Accepted)"
    route_programmed="$(route_parent_condition_status httproute ferrum-blackbox-listenerset Programmed)"
    if [ "$route_accepted" = "True" ] && [ "$route_programmed" = "True" ]; then
      break
    fi
    sleep 2
  done
  if [ "$route_accepted" != "True" ] || [ "$route_programmed" != "True" ]; then
    echo "ListenerSet HTTPRoute Accepted='${route_accepted}' Programmed='${route_programmed}'" >&2
    return 1
  fi

  wait_for_status "200" "attach" | tee -a "$report"
  echo "ListenerSet HTTPRoute parentRef served ${LISTENERSET_HOST}${LISTENERSET_PATH}" >> "$report"
  echo "ListenerSet HTTPRoute parent status Accepted=True/Programmed=True" >> "$report"
  echo "Gateway attachedListenerSets=1" >> "$report"

  local denied=""
  for _ in $(seq 1 45); do
    denied="$(condition_status listenerset ferrum-blackbox-listenerset-denied Accepted)"
    if [ "$denied" = "False" ]; then
      break
    fi
    sleep 2
  done
  local denied_reason
  denied_reason="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get listenerset ferrum-blackbox-listenerset-denied \
    -o "jsonpath={.status.conditions[?(@.type==\"Accepted\")].reason}" 2>/dev/null || true)"
  if [ "$denied" != "False" ] || [ "$denied_reason" != "NotAllowed" ]; then
    echo "denied ListenerSet Accepted='${denied}' reason='${denied_reason}'" >&2
    return 1
  fi
  echo "ListenerSet without allowedListeners reported Accepted=False/NotAllowed" >> "$report"

  kubectl -n "$DP_GATEWAY_NAMESPACE" delete listenerset ferrum-blackbox-listenerset --wait=true
  # Positive evidence of withdrawal: the still-running gateway must answer
  # the withdrawn host with its no-route 404. A curl failure ('000'), a 5xx
  # from a crashed or restarting gateway, or any other code is not proof.
  wait_for_status "404" "withdraw" | tee -a "$report"
  echo "deleted ListenerSet withdrew ${LISTENERSET_HOST}${LISTENERSET_PATH}" >> "$report"
}

collect_diagnostics() {
  set +e
  kubectl get gatewayclasses,gateways,listenersets,httproutes,grpcroutes,tcproutes,tlsroutes,referencegrants -A -o yaml \
    > "$RESULTS_DIR/gateway-api-resources.yaml"
  {
    echo ""
    echo "ListenerSet black-box host: ${LISTENERSET_HOST}${LISTENERSET_PATH}"
  } >> "$RESULTS_DIR/CONFORMANCE.md"
}

case "${1:-}" in
  blackbox) run_blackbox ;;
  diagnostics) collect_diagnostics ;;
  *)
    echo "usage: $0 {blackbox|diagnostics}" >&2
    exit 2
    ;;
esac
