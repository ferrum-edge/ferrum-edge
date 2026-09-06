#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"

# Live TLSRoute black-box listeners (Gateway TLS Passthrough port == DP stream
# listen_port). Host ports map through kind NodePorts so CI can dial with SNI.
TLS_BLACKBOX_PORT_SNI="${TLS_BLACKBOX_PORT_SNI:-9011}"
TLS_BLACKBOX_PORT_CROSS="${TLS_BLACKBOX_PORT_CROSS:-9012}"
TLS_BLACKBOX_PORT_FAIL="${TLS_BLACKBOX_PORT_FAIL:-9013}"
TLS_BLACKBOX_PORT_DELETE="${TLS_BLACKBOX_PORT_DELETE:-9014}"
TLS_ECHO_BACKEND_PORT="${TLS_ECHO_BACKEND_PORT:-9443}"

DP_GATEWAY_NAMESPACE="${DP_GATEWAY_NAMESPACE:-gateway-conformance-infra}"
BACKEND_NAMESPACE="${BACKEND_NAMESPACE:-gateway-conformance-web-backend}"

TLS_SNI_A="${TLS_SNI_A:-a.tls.blackbox.example}"
TLS_SNI_B="${TLS_SNI_B:-b.tls.blackbox.example}"
TLS_SNI_CROSS="${TLS_SNI_CROSS:-cross.tls.blackbox.example}"
TLS_SNI_DELETE="${TLS_SNI_DELETE:-delete.tls.blackbox.example}"
TLS_SNI_UNKNOWN="${TLS_SNI_UNKNOWN:-unknown.tls.blackbox.example}"

# Control-plane reconcile observability (issue #4491). "The withdrawn route is
# still served" is two very different faults wearing one message: the control
# plane never observed the delete (a stalled watch), or it observed and
# published and the data plane kept the listener. The counters below separate
# them, so the delete assertion below can say which one it hit instead of
# leaving triage to guess. Defaults mirror the lab setup script; the metrics
# bearer token authenticates `/metrics` without minting an admin JWT.
CP_NAMESPACE="${CP_NAMESPACE:-ferrum}"
CP_DEPLOYMENT="${CP_DEPLOYMENT:-ferrum-mesh-control-plane}"
ADMIN_HTTP_PORT="${ADMIN_HTTP_PORT:-9000}"
METRICS_TOKEN="${METRICS_TOKEN:-ferrum-edge-gateway-api-conformance-metrics-token}"
# Distinct from the data-plane script's 18090 so the two can never collide.
CONTROLLER_METRICS_LOCAL_PORT="${CONTROLLER_METRICS_LOCAL_PORT:-18094}"
CONTROLLER_METRICS_PF_PID=""

mkdir -p "$RESULTS_DIR"

create_tls_echo_secret() {
  local namespace="$1"
  local name="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "$tmpdir/tls.key" \
    -out "$tmpdir/tls.crt" \
    -subj "/CN=*.tls.blackbox.example" \
    -addext "subjectAltName=DNS:*.tls.blackbox.example,DNS:a.tls.blackbox.example,DNS:b.tls.blackbox.example,DNS:cross.tls.blackbox.example,DNS:delete.tls.blackbox.example" \
    >/dev/null 2>&1
  kubectl -n "$namespace" create secret tls "$name" \
    --cert="$tmpdir/tls.crt" \
    --key="$tmpdir/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f -
  rm -rf "$tmpdir"
}

tls_echo_deployment_yaml() {
  local name="$1"
  local namespace="$2"
  cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${name}
  template:
    metadata:
      labels:
        app: ${name}
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: ${name}
            - name: LISTEN_PORT
              value: "${TLS_ECHO_BACKEND_PORT}"
          ports:
            - containerPort: ${TLS_ECHO_BACKEND_PORT}
          volumeMounts:
            - name: tls
              mountPath: /tls
              readOnly: true
          command: ["python", "-c"]
          args:
            - |
              import os, socket, ssl
              name = os.environ["BACKEND_NAME"].encode()
              port = int(os.environ["LISTEN_PORT"])
              ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
              ctx.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
              srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              srv.bind(("", port))
              srv.listen()
              print(f"tls echo {name.decode()} on {port}", flush=True)
              while True:
                  conn, _ = srv.accept()
                  try:
                      with ctx.wrap_socket(conn, server_side=True) as ssock:
                          data = b""
                          while b"\n" not in data and len(data) < 65536:
                              chunk = ssock.recv(4096)
                              if not chunk:
                                  break
                              data += chunk
                          payload = data.partition(b"\n")[0]
                          ssock.sendall(name + b":" + payload)
                  except Exception as exc:
                      print(f"tls echo session error: {exc}", flush=True)
                  finally:
                      try:
                          conn.close()
                      except Exception:
                          pass
      volumes:
        - name: tls
          secret:
            secretName: blackbox-tls-echo
---
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  selector:
    app: ${name}
  ports:
    - name: tls
      port: ${TLS_ECHO_BACKEND_PORT}
      targetPort: ${TLS_ECHO_BACKEND_PORT}
YAML
}

apply_tls_blackbox_backends() {
  create_tls_echo_secret "$DP_GATEWAY_NAMESPACE" blackbox-tls-echo
  create_tls_echo_secret "$BACKEND_NAMESPACE" blackbox-tls-echo
  {
    tls_echo_deployment_yaml blackbox-tls-a "$DP_GATEWAY_NAMESPACE"
    echo "---"
    tls_echo_deployment_yaml blackbox-tls-b "$DP_GATEWAY_NAMESPACE"
    echo "---"
    tls_echo_deployment_yaml blackbox-tls-cross "$BACKEND_NAMESPACE"
    cat <<YAML
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-tls-empty
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  ports:
    - name: tls
      port: ${TLS_ECHO_BACKEND_PORT}
      targetPort: ${TLS_ECHO_BACKEND_PORT}
YAML
  } | kubectl apply -f -
}

apply_tls_blackbox_routes() {
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox-tls
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  gatewayClassName: ferrum
  listeners:
    - name: tls-sni
      port: ${TLS_BLACKBOX_PORT_SNI}
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        kinds:
          - kind: TLSRoute
        namespaces:
          from: Same
    - name: tls-cross
      port: ${TLS_BLACKBOX_PORT_CROSS}
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        kinds:
          - kind: TLSRoute
        namespaces:
          from: Same
    - name: tls-fail
      port: ${TLS_BLACKBOX_PORT_FAIL}
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        kinds:
          - kind: TLSRoute
        namespaces:
          from: Same
    - name: tls-delete
      port: ${TLS_BLACKBOX_PORT_DELETE}
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        kinds:
          - kind: TLSRoute
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-a
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-sni
  hostnames:
    - ${TLS_SNI_A}
  rules:
    - backendRefs:
        - name: blackbox-tls-a
          port: ${TLS_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-b
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-sni
  hostnames:
    - ${TLS_SNI_B}
  rules:
    - backendRefs:
        - name: blackbox-tls-b
          port: ${TLS_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-cross
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-cross
  hostnames:
    - ${TLS_SNI_CROSS}
  rules:
    - backendRefs:
        - name: blackbox-tls-cross
          namespace: ${BACKEND_NAMESPACE}
          port: ${TLS_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-infra-tlsroute-to-blackbox-tls-cross
  namespace: ${BACKEND_NAMESPACE}
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: TLSRoute
      namespace: ${DP_GATEWAY_NAMESPACE}
  to:
    - group: ""
      kind: Service
      name: blackbox-tls-cross
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-fail
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-fail
  hostnames:
    - fail.tls.blackbox.example
  rules:
    - backendRefs:
        - name: blackbox-tls-empty
          port: ${TLS_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-delete
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-delete
  hostnames:
    - ${TLS_SNI_DELETE}
  rules:
    - backendRefs:
        - name: blackbox-tls-a
          port: ${TLS_ECHO_BACKEND_PORT}
YAML
}

tls_exchange() {
  local host="$1"
  local port="$2"
  local sni="$3"
  local payload="$4"
  python3 - "$host" "$port" "$sni" "$payload" <<'PY'
import socket
import ssl
import sys

host, port_s, sni, payload = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].encode()
port = int(port_s)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((host, port), timeout=5) as sock:
    with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
        # A newline frames the request. Waiting for TLS/TCP EOF here races the
        # backend response with close-notify and made this live gate flaky.
        ssock.sendall(payload + b"\n")
        chunks = []
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
sys.stdout.buffer.write(b"".join(chunks))
PY
}

wait_for_tls_echo() {
  local port="$1"
  local sni="$2"
  local expected_prefix="$3"
  local payload="${4:-ping}"
  local body=""
  for _ in $(seq 1 60); do
    if body="$(tls_exchange 127.0.0.1 "$port" "$sni" "$payload" 2>/dev/null)" \
      && grep -q "^${expected_prefix}:" <<<"$body" \
      && grep -q "$payload" <<<"$body"; then
      printf '%s\n' "$body"
      return 0
    fi
    sleep 2
  done
  echo "expected TLS :${port} SNI=${sni} echo prefixed with ${expected_prefix} for payload ${payload}; last body=${body}" >&2
  return 1
}

assert_tls_exchange_fails() {
  local port="$1"
  local sni="$2"
  local label="$3"
  local body=""
  if body="$(tls_exchange 127.0.0.1 "$port" "$sni" "should-fail" 2>/dev/null)"; then
    if [ -n "$body" ]; then
      echo "${label}: unexpected backend data on :${port} SNI=${sni}: ${body}" >&2
      return 1
    fi
    # Accepted-then-reset/empty responses are still fail-closed (no backend echo).
    echo "${label}: TLS :${port} SNI=${sni} produced no successful backend echo"
    return 0
  fi
  echo "${label}: TLS :${port} SNI=${sni} connection failed closed"
  return 0
}

# Hold one port-forward open for the whole delete assertion rather than paying
# a new one per scrape. Best-effort: every caller tolerates an empty reading, so
# an unreachable admin port degrades the message and never fails a green run.
start_controller_metrics_forward() {
  [ -z "$CONTROLLER_METRICS_PF_PID" ] || return 0
  local log="$RESULTS_DIR/tlsroute-controller-metrics-port-forward.log"
  kubectl -n "$CP_NAMESPACE" port-forward "deploy/${CP_DEPLOYMENT}" \
    "${CONTROLLER_METRICS_LOCAL_PORT}:${ADMIN_HTTP_PORT}" >"$log" 2>&1 &
  CONTROLLER_METRICS_PF_PID=$!
  local _attempt
  for _attempt in 1 2 3 4 5; do
    sleep 1
    if [ -n "$(controller_metric ferrum_k8s_controller_reconciliations_total)" ]; then
      return 0
    fi
  done
  echo "controller /metrics is unreadable; the TLSRoute delete assertion will report data-plane state only (see ${log})" >&2
  stop_controller_metrics_forward
  return 1
}

stop_controller_metrics_forward() {
  [ -n "$CONTROLLER_METRICS_PF_PID" ] || return 0
  kill "$CONTROLLER_METRICS_PF_PID" >/dev/null 2>&1 || true
  wait "$CONTROLLER_METRICS_PF_PID" >/dev/null 2>&1 || true
  CONTROLLER_METRICS_PF_PID=""
}

# Print one unlabeled `ferrum_k8s_controller_*` counter value, or nothing when
# the scrape fails or the family is absent. Never fails the caller.
controller_metric() {
  local family="$1"
  local scrape=""
  scrape="$(curl -fsS -m 5 -H "Authorization: Bearer ${METRICS_TOKEN}" \
    "http://127.0.0.1:${CONTROLLER_METRICS_LOCAL_PORT}/metrics" 2>/dev/null || true)"
  [ -n "$scrape" ] || return 0
  awk -v family="$family" '$1 == family { value = $2 } END { if (value != "") print value }' \
    <<<"$scrape"
}

# Space-separated snapshot: watch Delete events observed, reconciles that
# committed a changed config, reconcile passes started, watch-scope relists,
# and objects a relist found withdrawn without a Delete event (issue #4491).
controller_reconcile_observable() {
  printf '%s %s %s %s %s\n' \
    "$(controller_metric ferrum_k8s_controller_watch_deletes_total)" \
    "$(controller_metric ferrum_k8s_controller_config_publications_total)" \
    "$(controller_metric ferrum_k8s_controller_reconciliations_total)" \
    "$(controller_metric ferrum_k8s_controller_watch_idle_relists_total)" \
    "$(controller_metric ferrum_k8s_controller_watch_relist_missed_deletes_total)"
}

wait_for_tlsroute_parent_condition() {
  local name="$1"
  local condition_type="$2"
  local expected_status="$3"
  local status=""
  for _ in $(seq 1 60); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get tlsroute "$name" -o jsonpath="{.status.parents[0].conditions[?(@.type==\"${condition_type}\")].status}" 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ]; then
      echo "TLSRoute ${name} ${condition_type}=${status}"
      return 0
    fi
    sleep 2
  done
  echo "TLSRoute ${name} did not reach ${condition_type}=${expected_status} (got '${status}')" >&2
  kubectl -n "$DP_GATEWAY_NAMESPACE" get tlsroute "$name" -o yaml >&2 || true
  return 1
}

wait_for_gateway_listener_attached_routes() {
  local gateway="$1"
  local listener="$2"
  local minimum="$3"
  local attached=""
  for _ in $(seq 1 60); do
    attached="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get gateway "$gateway" -o jsonpath="{.status.listeners[?(@.name==\"${listener}\")].attachedRoutes}" 2>/dev/null || true)"
    if [ -n "$attached" ] && [ "$attached" -ge "$minimum" ]; then
      echo "Gateway ${gateway} listener ${listener} attachedRoutes=${attached}"
      return 0
    fi
    sleep 2
  done
  echo "Gateway ${gateway} listener ${listener} attachedRoutes stayed below ${minimum} (got '${attached}')" >&2
  kubectl -n "$DP_GATEWAY_NAMESPACE" get gateway "$gateway" -o yaml >&2 || true
  return 1
}

run_tls_blackbox_tests() {
  local report="$1"
  echo "" >> "$report"
  echo "## TLSRoute live data-plane (SNI passthrough)" >> "$report"

  apply_tls_blackbox_routes

  wait_for_tlsroute_parent_condition blackbox-tls-a Accepted True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-a ResolvedRefs True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-a Programmed True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-b Accepted True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-b ResolvedRefs True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-b Programmed True | tee -a "$report"
  wait_for_gateway_listener_attached_routes ferrum-blackbox-tls tls-sni 2 | tee -a "$report"

  wait_for_tls_echo "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_A" "blackbox-tls-a" "sni-a-ping" | tee -a "$report"
  echo "TLSRoute SNI ${TLS_SNI_A} served tagged echo on :${TLS_BLACKBOX_PORT_SNI}" >> "$report"
  wait_for_tls_echo "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_B" "blackbox-tls-b" "sni-b-ping" | tee -a "$report"
  echo "TLSRoute SNI ${TLS_SNI_B} served tagged echo on :${TLS_BLACKBOX_PORT_SNI}" >> "$report"

  assert_tls_exchange_fails "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_UNKNOWN" "unmatched TLSRoute SNI" | tee -a "$report"
  echo "TLSRoute unmatched SNI ${TLS_SNI_UNKNOWN} failed closed on :${TLS_BLACKBOX_PORT_SNI}" >> "$report"

  wait_for_tlsroute_parent_condition blackbox-tls-cross Accepted True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-cross ResolvedRefs True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-cross Programmed True | tee -a "$report"
  wait_for_tls_echo "$TLS_BLACKBOX_PORT_CROSS" "$TLS_SNI_CROSS" "blackbox-tls-cross" "cross-ping" | tee -a "$report"
  echo "TLSRoute cross-namespace backendRef with ReferenceGrant served echo on :${TLS_BLACKBOX_PORT_CROSS}" >> "$report"

  # Empty Service endpoints must fail closed (no successful tagged echo).
  wait_for_tlsroute_parent_condition blackbox-tls-fail Accepted True | tee -a "$report"
  assert_tls_exchange_fails "$TLS_BLACKBOX_PORT_FAIL" "fail.tls.blackbox.example" "empty TLS backend endpoints" | tee -a "$report"
  echo "TLSRoute empty-endpoint backend failed closed on :${TLS_BLACKBOX_PORT_FAIL}" >> "$report"

  # Missing Service backendRef: replace the fail route and require fail-closed traffic.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tlsroute blackbox-tls-fail --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-invalid
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-fail
  hostnames:
    - fail.tls.blackbox.example
  rules:
    - backendRefs:
        - name: blackbox-tls-missing
          port: ${TLS_ECHO_BACKEND_PORT}
YAML
  sleep 5
  assert_tls_exchange_fails "$TLS_BLACKBOX_PORT_FAIL" "fail.tls.blackbox.example" "missing TLS backend Service" | tee -a "$report"
  echo "TLSRoute missing backend Service failed closed on :${TLS_BLACKBOX_PORT_FAIL}" >> "$report"

  # Cross-namespace backendRef without ReferenceGrant must fail closed.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tlsroute blackbox-tls-invalid --wait=true
  kubectl -n "$BACKEND_NAMESPACE" delete referencegrant allow-infra-tlsroute-to-blackbox-tls-cross --ignore-not-found --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-denied
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-fail
  hostnames:
    - fail.tls.blackbox.example
  rules:
    - backendRefs:
        - name: blackbox-tls-cross
          namespace: ${BACKEND_NAMESPACE}
          port: ${TLS_ECHO_BACKEND_PORT}
YAML
  # Translation rejects unpermitted refs fail-closed; wait for status and refuse echo.
  local status=""
  for _ in $(seq 1 30); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get tlsroute blackbox-tls-denied -o jsonpath='{.status.parents[0].conditions[?(@.type=="ResolvedRefs")].status}' 2>/dev/null || true)"
    if [ "$status" = "False" ]; then
      break
    fi
    sleep 2
  done
  if [ "${status:-}" = "False" ]; then
    echo "TLSRoute denied cross-namespace backendRef reported ResolvedRefs=False" | tee -a "$report"
  else
    echo "TLSRoute denied cross-namespace backendRef status ResolvedRefs='${status:-}' (traffic still must fail closed)" | tee -a "$report"
  fi
  assert_tls_exchange_fails "$TLS_BLACKBOX_PORT_FAIL" "fail.tls.blackbox.example" "unpermitted cross-namespace TLS backendRef" | tee -a "$report"
  echo "TLSRoute unpermitted cross-namespace backendRef failed closed on :${TLS_BLACKBOX_PORT_FAIL}" >> "$report"

  wait_for_tls_echo "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_A" "blackbox-tls-a" "pre-update" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" patch tlsroute blackbox-tls-a --type=json \
    -p='[{"op":"replace","path":"/spec/rules/0/backendRefs/0/name","value":"blackbox-tls-b"}]'
  wait_for_tls_echo "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_A" "blackbox-tls-b" "post-update" | tee -a "$report"
  echo "TLSRoute update switched live SNI ${TLS_SNI_A} traffic to blackbox-tls-b on :${TLS_BLACKBOX_PORT_SNI}" >> "$report"

  wait_for_tls_echo "$TLS_BLACKBOX_PORT_DELETE" "$TLS_SNI_DELETE" "blackbox-tls-a" "pre-delete" | tee -a "$report"

  # Issue #4491. Read the control plane's reconcile observable on both sides of
  # the deletion so a failure here names the fault instead of only its symptom.
  # Best-effort by construction: an unreadable observable weakens the message
  # and leaves the data-plane assertion below exactly as it was.
  local observable_ok=0
  local pre_deletes="" pre_publications="" pre_reconciles="" pre_relists=""
  local pre_missed_deletes=""
  if start_controller_metrics_forward; then
    observable_ok=1
    read -r pre_deletes pre_publications pre_reconciles pre_relists pre_missed_deletes \
      < <(controller_reconcile_observable) || true
  fi

  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tlsroute blackbox-tls-delete --wait=true
  local delete_ok=0
  local delete_body=""
  for _ in $(seq 1 30); do
    if ! delete_body="$(tls_exchange 127.0.0.1 "$TLS_BLACKBOX_PORT_DELETE" "$TLS_SNI_DELETE" "post-delete" 2>/dev/null)"; then
      delete_ok=1
      break
    fi
    if ! grep -q '^blackbox-tls-a:post-delete$' <<<"$delete_body"; then
      delete_ok=1
      break
    fi
    sleep 2
  done

  local post_deletes="" post_publications="" post_reconciles="" post_relists=""
  local post_missed_deletes=""
  local observable_line="controller reconcile observable unavailable"
  if [ "$observable_ok" -eq 1 ]; then
    read -r post_deletes post_publications post_reconciles post_relists post_missed_deletes \
      < <(controller_reconcile_observable) || true
    printf -v observable_line \
      'watch_deletes %s->%s config_publications %s->%s reconciliations %s->%s watch_idle_relists %s->%s watch_relist_missed_deletes %s->%s' \
      "${pre_deletes:-?}" "${post_deletes:-?}" \
      "${pre_publications:-?}" "${post_publications:-?}" \
      "${pre_reconciles:-?}" "${post_reconciles:-?}" \
      "${pre_relists:-?}" "${post_relists:-?}" \
      "${pre_missed_deletes:-?}" "${post_missed_deletes:-?}"
  fi
  stop_controller_metrics_forward

  local observable_read=0
  if [ -n "$pre_deletes" ] && [ -n "$post_deletes" ] \
    && [ -n "$pre_publications" ] && [ -n "$post_publications" ]; then
    observable_read=1
  fi

  if [ "$delete_ok" -ne 1 ]; then
    # Two faults, one symptom. Say which one this run hit.
    if [ "$observable_read" -eq 1 ] \
      && [ "$post_deletes" = "$pre_deletes" ] \
      && [ "$post_publications" = "$pre_publications" ]; then
      echo "deleted TLSRoute kept serving TLS echo on :${TLS_BLACKBOX_PORT_DELETE}: the control plane never observed the withdrawal (no watch Delete event and no config publication) — stalled watch, recovery bounded by FERRUM_K8S_WATCH_IDLE_RELIST_SECS; ${observable_line}" >&2
    elif [ "$observable_read" -eq 1 ]; then
      echo "deleted TLSRoute kept serving TLS echo on :${TLS_BLACKBOX_PORT_DELETE}: the control plane observed the withdrawal and reconciled, so the fault is downstream of reconcile (CP->DP distribution or stream listener rebuild); ${observable_line}" >&2
    else
      echo "deleted TLSRoute kept serving TLS echo on :${TLS_BLACKBOX_PORT_DELETE}; ${observable_line}" >&2
    fi
    return 1
  fi

  # Issue #4491: the port going dark is not enough. The lab relists every scope
  # on a 20s window, so a withdrawal the watch MISSED is repaired by a relist
  # inside this probe budget and the data plane still goes dark in time. That
  # is exactly the failure this check exists to catch, so it must not pass
  # green with the evidence buried in the report. Both TLSRoute alias scopes
  # deliver a watch Delete for one withdrawal; a flat watch_deletes counter
  # across the deletion therefore means no watch delivered it.
  if [ "$observable_read" -eq 1 ] && [ "$post_deletes" = "$pre_deletes" ]; then
    echo "::error::deleted TLSRoute stopped serving on :${TLS_BLACKBOX_PORT_DELETE}, but the control plane never observed the withdrawal: no watch Delete event reached it and the store was repaired by a relist instead (issue #4491); ${observable_line}"
    echo "deleted TLSRoute stopped serving on :${TLS_BLACKBOX_PORT_DELETE} only because a relist repaired a missed watch Delete — FAILED (${observable_line})" >> "$report"
    echo "deleted TLSRoute was withdrawn by a relist, not by a watch Delete event; ${observable_line}" >&2
    return 1
  fi
  # A rising missed-deletes counter alongside an observed Delete names some
  # OTHER object's repair during this window. An object deleted while a relist
  # was in flight is counted there too, so this is surfaced, not failed.
  if [ -n "$pre_missed_deletes" ] && [ -n "$post_missed_deletes" ] \
    && [ "$post_missed_deletes" != "$pre_missed_deletes" ]; then
    echo "::warning::a relist repaired a missed watch Delete on some watched scope during the TLSRoute delete check (issue #4491); ${observable_line}"
    echo "WARNING: a relist repaired a missed watch Delete during the delete check (${observable_line})" >> "$report"
  fi
  echo "deleted TLSRoute stopped serving on :${TLS_BLACKBOX_PORT_DELETE} (${observable_line})" >> "$report"
}

run_blackbox() {
  local report="$RESULTS_DIR/gateway-api-blackbox.md"
  apply_tls_blackbox_backends
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-tls-a --timeout=180s
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-tls-b --timeout=180s
  kubectl -n "$BACKEND_NAMESPACE" rollout status deployment/blackbox-tls-cross --timeout=180s
  run_tls_blackbox_tests "$report"
}

collect_diagnostics() {
  set +e
  kubectl get gatewayclasses,gateways,httproutes,grpcroutes,tcproutes,tlsroutes,referencegrants -A -o yaml > "$RESULTS_DIR/gateway-api-resources.yaml"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-tls-a --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tls-a.log"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-tls-b --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tls-b.log"
  kubectl -n "$BACKEND_NAMESPACE" logs deployment/blackbox-tls-cross --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tls-cross.log"
  {
    echo ""
    echo "TLSRoute black-box ports: ${TLS_BLACKBOX_PORT_SNI},${TLS_BLACKBOX_PORT_CROSS},${TLS_BLACKBOX_PORT_FAIL},${TLS_BLACKBOX_PORT_DELETE}"
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
