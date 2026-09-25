#!/usr/bin/env bash
# Ferrum-specific live black-box coverage for GatewayClass observed authority
# (issue #3835). A listener must appear when the owned GatewayClass is created
# and withdraw/drain when that class is deleted, without restarting Ferrum.
# Does NOT advertise an extra upstream Gateway API profile.
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"
. "$ROOT_DIR/scripts/gateway_api_gatewayclass_ownership.sh"
DP_GATEWAY_NAMESPACE="${DP_GATEWAY_NAMESPACE:-gateway-conformance-infra}"
GATEWAY_API_STATUS_ADDRESS="${GATEWAY_API_STATUS_ADDRESS:-127.0.0.1}"
AUTHORITY_HOST="${AUTHORITY_HOST:-gatewayclass-authority.example}"
AUTHORITY_PATH="${AUTHORITY_PATH:-/gatewayclass-authority}"

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
    code="$(curl_status "$AUTHORITY_HOST" "$AUTHORITY_PATH")"
    if [ "$code" = "$expected" ]; then
      echo "GatewayClass authority black-box ${label}: HTTP ${code}"
      return 0
    fi
    sleep 2
  done
  echo "GatewayClass authority black-box ${label}: expected HTTP ${expected}, got '${code}'" >&2
  return 1
}

apply_resources() {
  cat <<YAML | kubectl --context "$GATEWAY_API_LAB_CONTEXT" apply -f -
apiVersion: v1
kind: Service
metadata:
  name: ferrum-blackbox-gatewayclass
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  selector:
    app: blackbox-a
  ports:
    - name: http
      port: 8080
      targetPort: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox-gatewayclass
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  gatewayClassName: ferrum
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      hostname: ${AUTHORITY_HOST}
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: ferrum-blackbox-gatewayclass
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-gatewayclass
  hostnames:
    - ${AUTHORITY_HOST}
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: ${AUTHORITY_PATH}
      backendRefs:
        - name: ferrum-blackbox-gatewayclass
          port: 8080
YAML
}

run_blackbox() {
  local report="$RESULTS_DIR/gateway-api-gatewayclass-authority-blackbox.md"
  gatewayclass_lab_require_identity
  gatewayclass_lab_read_record
  gatewayclass_lab_verify_owned
  : > "$report"
  echo "# GatewayClass Observed Authority Black-Box" >> "$report"

  apply_resources
  wait_for_status "200" "owned-class-create" | tee -a "$report"
  echo "owned GatewayClass programmed ${AUTHORITY_HOST}${AUTHORITY_PATH}" >> "$report"

  gatewayclass_lab_delete_owned
  wait_for_status "404" "owned-class-delete" | tee -a "$report"
  echo "deleting GatewayClass withdrew the listener without restarting Ferrum" >> "$report"

  gatewayclass_lab_create_owned "$GATEWAYCLASS_RUN_NONCE"
  wait_for_status "200" "owned-class-recreate" | tee -a "$report"
  echo "recreating the owned GatewayClass restored the listener" >> "$report"
}

collect_diagnostics() {
  gatewayclass_lab_require_identity || return 1
  set +e
  mkdir -p "$RESULTS_DIR"
  kubectl --context "$GATEWAY_API_LAB_CONTEXT" get gatewayclass ferrum -o yaml \
    > "$RESULTS_DIR/gatewayclass-authority-gatewayclass.yaml"
  kubectl --context "$GATEWAY_API_LAB_CONTEXT" -n "$DP_GATEWAY_NAMESPACE" \
    get gateway,httproute ferrum-blackbox-gatewayclass -o yaml \
    > "$RESULTS_DIR/gatewayclass-authority-resources.yaml"
  kubectl --context "$GATEWAY_API_LAB_CONTEXT" -n "$DP_GATEWAY_NAMESPACE" get events --sort-by=.lastTimestamp \
    > "$RESULTS_DIR/gatewayclass-authority-events.txt"
}

case "${1:-}" in
  blackbox) run_blackbox ;;
  diagnostics) collect_diagnostics ;;
  *)
    echo "usage: $0 {blackbox|diagnostics}" >&2
    exit 2
    ;;
esac
