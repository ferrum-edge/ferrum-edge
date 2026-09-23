#!/usr/bin/env bash
# Shared ownership fence for the Gateway API lab's cluster-scoped GatewayClass.

GATEWAY_API_LAB_CONTEXT="${GATEWAY_API_LAB_CONTEXT:-}"
GATEWAY_API_LAB_OWNERSHIP_FILE="${GATEWAY_API_LAB_OWNERSHIP_FILE:-}"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-ferrum-gwapi}"
GATEWAYCLASS_OWNERSHIP_ANNOTATION="conformance.ferrum.io/run-id"

gatewayclass_lab_error() {
  echo "GatewayClass lab fence: $*" >&2
  return 1
}

gatewayclass_lab_require_identity() {
  local expected_context="kind-${KIND_CLUSTER_NAME}"
  local configured_cluster node

  if [ -z "$GATEWAY_API_LAB_CONTEXT" ] || [ "$GATEWAY_API_LAB_CONTEXT" != "$expected_context" ]; then
    gatewayclass_lab_error "set GATEWAY_API_LAB_CONTEXT explicitly to ${expected_context}"
    return 1
  fi
  if [ -z "$GATEWAY_API_LAB_OWNERSHIP_FILE" ] || [[ "$GATEWAY_API_LAB_OWNERSHIP_FILE" != /* ]]; then
    gatewayclass_lab_error "set GATEWAY_API_LAB_OWNERSHIP_FILE to an absolute path shared with lab setup"
    return 1
  fi

  configured_cluster="$(kubectl --context "$GATEWAY_API_LAB_CONTEXT" config view --minify \
    -o jsonpath='{.contexts[0].context.cluster}')" || return 1
  if [ "$configured_cluster" != "$expected_context" ]; then
    gatewayclass_lab_error "context ${GATEWAY_API_LAB_CONTEXT} does not select cluster ${expected_context}"
    return 1
  fi
  node="$(kubectl --context "$GATEWAY_API_LAB_CONTEXT" get node \
    "${KIND_CLUSTER_NAME}-control-plane" -o jsonpath='{.metadata.name}')" || return 1
  if [ "$node" != "${KIND_CLUSTER_NAME}-control-plane" ]; then
    gatewayclass_lab_error "expected Kind control-plane node is absent from ${GATEWAY_API_LAB_CONTEXT}"
    return 1
  fi
}

gatewayclass_lab_write_record() {
  local nonce="$1"
  local uid="$2"
  local temp_file

  if ! [[ "$nonce" =~ ^[0-9a-f]{32}$ ]] || ! [[ "$uid" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    gatewayclass_lab_error "refusing to record an invalid GatewayClass nonce or UID"
    return 1
  fi
  temp_file="$(mktemp "${GATEWAY_API_LAB_OWNERSHIP_FILE}.XXXXXX")"
  printf '%s\t%s\t%s\n' "$GATEWAY_API_LAB_CONTEXT" "$nonce" "$uid" > "$temp_file"
  mv "$temp_file" "$GATEWAY_API_LAB_OWNERSHIP_FILE"
}

gatewayclass_lab_read_record() {
  local recorded_context extra

  if [ ! -f "$GATEWAY_API_LAB_OWNERSHIP_FILE" ]; then
    gatewayclass_lab_error "ownership record is missing: ${GATEWAY_API_LAB_OWNERSHIP_FILE}"
    return 1
  fi
  IFS=$'\t' read -r recorded_context GATEWAYCLASS_RUN_NONCE GATEWAYCLASS_UID extra \
    < "$GATEWAY_API_LAB_OWNERSHIP_FILE" || return 1
  if [ "$recorded_context" != "$GATEWAY_API_LAB_CONTEXT" ] || [ -n "$extra" ] || \
    ! [[ "$GATEWAYCLASS_RUN_NONCE" =~ ^[0-9a-f]{32}$ ]] || \
    ! [[ "$GATEWAYCLASS_UID" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    gatewayclass_lab_error "ownership record is invalid or belongs to another context"
    return 1
  fi
}

gatewayclass_lab_verify_owned() {
  local actual_uid actual_nonce

  actual_uid="$(kubectl --context "$GATEWAY_API_LAB_CONTEXT" get gatewayclass ferrum \
    -o jsonpath='{.metadata.uid}')" || return 1
  actual_nonce="$(kubectl --context "$GATEWAY_API_LAB_CONTEXT" get gatewayclass ferrum \
    -o jsonpath='{.metadata.annotations.conformance\.ferrum\.io/run-id}')" || return 1
  if [ "$actual_uid" != "$GATEWAYCLASS_UID" ] || [ "$actual_nonce" != "$GATEWAYCLASS_RUN_NONCE" ]; then
    gatewayclass_lab_error "GatewayClass/ferrum UID or run marker differs from the lab ownership record; refusing to modify it"
    return 1
  fi
}

gatewayclass_lab_create_owned() {
  local nonce="$1"
  local existing uid

  existing="$(kubectl --context "$GATEWAY_API_LAB_CONTEXT" get gatewayclass ferrum \
    --ignore-not-found -o name)" || return 1
  if [ -n "$existing" ]; then
    gatewayclass_lab_error "GatewayClass/ferrum already exists; refusing to overwrite it"
    return 1
  fi

  uid="$(cat <<YAML | kubectl --context "$GATEWAY_API_LAB_CONTEXT" create -f - -o jsonpath='{.metadata.uid}'
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: ferrum
  annotations:
    ${GATEWAYCLASS_OWNERSHIP_ANNOTATION}: ${nonce}
spec:
  controllerName: ferrum.io/gateway-controller
YAML
)" || return 1
  gatewayclass_lab_write_record "$nonce" "$uid"
}

gatewayclass_lab_delete_owned() {
  gatewayclass_lab_verify_owned || return 1
  # A named kubectl delete has no UID precondition. Send DeleteOptions so a
  # replacement between the read above and the DELETE receives HTTP 409.
  kubectl --context "$GATEWAY_API_LAB_CONTEXT" delete \
    --raw '/apis/gateway.networking.k8s.io/v1/gatewayclasses/ferrum' -f - <<JSON
{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"${GATEWAYCLASS_UID}"}}
JSON
  kubectl --context "$GATEWAY_API_LAB_CONTEXT" wait --for=delete gatewayclass/ferrum --timeout=120s
}
