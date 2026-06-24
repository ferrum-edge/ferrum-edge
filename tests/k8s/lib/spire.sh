#!/usr/bin/env bash
# Shared SPIRE helpers for Ferrum live-data-path suites.

set -euo pipefail

FERRUM_SPIRE_NAMESPACE="${FERRUM_SPIRE_NAMESPACE:-spire-system}"
FERRUM_SPIRE_SERVER_IMAGE="${FERRUM_SPIRE_SERVER_IMAGE:-ghcr.io/spiffe/spire-server:1.12.4}"
FERRUM_SPIRE_AGENT_IMAGE="${FERRUM_SPIRE_AGENT_IMAGE:-ghcr.io/spiffe/spire-agent:1.12.4}"
FERRUM_SPIRE_SERVER_HEALTH_PORT="${FERRUM_SPIRE_SERVER_HEALTH_PORT:-8080}"
FERRUM_SPIRE_AGENT_HEALTH_PORT="${FERRUM_SPIRE_AGENT_HEALTH_PORT:-8082}"

ferrum_spire_require_tools() {
  command -v kubectl >/dev/null 2>&1 || {
    printf 'missing required command: kubectl\n' >&2
    return 127
  }
}

ferrum_spire_apply_minimal() {
  local context="${1:?kube context is required}"
  local trust_domain="${2:?trust domain is required}"
  local namespace="${3:-$FERRUM_SPIRE_NAMESPACE}"

  ferrum_spire_require_tools
  kubectl --context "$context" create namespace "$namespace" --dry-run=client -o yaml |
    kubectl --context "$context" apply -f -

  kubectl --context "$context" -n "$namespace" apply -f - <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spire-server
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spire-agent
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ferrum-spire-server-tokenreviewer
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes"]
    verbs: ["get"]
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ferrum-spire-server-tokenreviewer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ferrum-spire-server-tokenreviewer
subjects:
  - kind: ServiceAccount
    name: spire-server
    namespace: "$namespace"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ferrum-spire-agent-workload-reader
rules:
  - apiGroups: [""]
    resources: ["nodes", "pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["nodes/proxy"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ferrum-spire-agent-workload-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ferrum-spire-agent-workload-reader
subjects:
  - kind: ServiceAccount
    name: spire-agent
    namespace: "$namespace"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-server
data:
  server.conf: |
    server {
      bind_address = "0.0.0.0"
      bind_port = "8081"
      socket_path = "/run/spire/server.sock"
      trust_domain = "$trust_domain"
      data_dir = "/run/spire/data"
      log_level = "INFO"
    }
    plugins {
      DataStore "sql" {
        plugin_data {
          database_type = "sqlite3"
          connection_string = "/run/spire/data/datastore.sqlite3"
        }
      }
      NodeAttestor "k8s_psat" {
        plugin_data {
          clusters = {
            "$trust_domain" = {
              service_account_allow_list = ["$namespace:spire-agent"]
            }
          }
        }
      }
      KeyManager "disk" {
        plugin_data {
          keys_path = "/run/spire/data/keys.json"
        }
      }
    }
    health_checks {
      listener_enabled = true
      bind_address = "0.0.0.0"
      bind_port = "$FERRUM_SPIRE_SERVER_HEALTH_PORT"
      live_path = "/live"
      ready_path = "/ready"
    }
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: spire-agent
data:
  agent.conf: |
    agent {
      data_dir = "/run/spire"
      log_level = "INFO"
      server_address = "spire-server.$namespace.svc"
      server_port = "8081"
      socket_path = "/run/spire/sockets/agent.sock"
      trust_domain = "$trust_domain"
      # Test-only minimal install: trust the server during first bootstrap.
      insecure_bootstrap = true
    }
    plugins {
      NodeAttestor "k8s_psat" {
        plugin_data {
          cluster = "$trust_domain"
          token_path = "/var/run/secrets/tokens/spire-agent"
        }
      }
      KeyManager "memory" {
        plugin_data {}
      }
      WorkloadAttestor "k8s" {
        plugin_data {
          skip_kubelet_verification = true
          node_name_env = "MY_NODE_NAME"
        }
      }
    }
    health_checks {
      listener_enabled = true
      bind_address = "0.0.0.0"
      bind_port = "$FERRUM_SPIRE_AGENT_HEALTH_PORT"
      live_path = "/live"
      ready_path = "/ready"
    }
---
apiVersion: v1
kind: Service
metadata:
  name: spire-server
spec:
  selector:
    app: spire-server
  ports:
    - name: grpc
      port: 8081
      targetPort: 8081
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: spire-server
spec:
  serviceName: spire-server
  replicas: 1
  selector:
    matchLabels:
      app: spire-server
  template:
    metadata:
      labels:
        app: spire-server
    spec:
      serviceAccountName: spire-server
      containers:
        - name: spire-server
          image: "$FERRUM_SPIRE_SERVER_IMAGE"
          args: ["-config", "/run/spire/config/server.conf"]
          ports:
            - containerPort: 8081
            - containerPort: $FERRUM_SPIRE_SERVER_HEALTH_PORT
              name: health
          livenessProbe:
            httpGet:
              path: /live
              port: health
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: health
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
          volumeMounts:
            - name: config
              mountPath: /run/spire/config
            - name: data
              mountPath: /run/spire/data
      volumes:
        - name: config
          configMap:
            name: spire-server
        - name: data
          emptyDir: {}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: spire-agent
spec:
  selector:
    matchLabels:
      app: spire-agent
  template:
    metadata:
      labels:
        app: spire-agent
    spec:
      serviceAccountName: spire-agent
      hostPID: true
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: spire-agent
          image: "$FERRUM_SPIRE_AGENT_IMAGE"
          args: ["-config", "/run/spire/config/agent.conf"]
          ports:
            - containerPort: $FERRUM_SPIRE_AGENT_HEALTH_PORT
              name: health
          env:
            - name: MY_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          livenessProbe:
            httpGet:
              path: /live
              port: health
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: health
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
          volumeMounts:
            - name: config
              mountPath: /run/spire/config
              readOnly: true
            - name: sockets
              mountPath: /run/spire/sockets
            - name: spire-agent-token
              mountPath: /var/run/secrets/tokens
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: spire-agent
        - name: sockets
          hostPath:
            path: /run/spire/sockets
            type: DirectoryOrCreate
        - name: spire-agent-token
          projected:
            sources:
              - serviceAccountToken:
                  path: spire-agent
                  expirationSeconds: 3600
                  audience: spire-server
YAML
}

ferrum_spire_wait_ready() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"
  local timeout="${3:-180s}"

  kubectl --context "$context" -n "$namespace" rollout status statefulset/spire-server --timeout="$timeout"
  kubectl --context "$context" -n "$namespace" rollout status daemonset/spire-agent --timeout="$timeout"
}

ferrum_spire_cleanup_minimal() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"

  ferrum_spire_require_tools
  kubectl --context "$context" delete clusterrolebinding \
    ferrum-spire-server-tokenreviewer \
    ferrum-spire-agent-workload-reader \
    --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl --context "$context" delete clusterrole \
    ferrum-spire-server-tokenreviewer \
    ferrum-spire-agent-workload-reader \
    --ignore-not-found=true >/dev/null 2>&1 || true
  kubectl --context "$context" delete namespace "$namespace" \
    --ignore-not-found=true >/dev/null 2>&1 || true
}

ferrum_spire_agent_nodes() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"

  kubectl --context "$context" -n "$namespace" get pod \
    -l app=spire-agent \
    -o jsonpath='{range .items[*]}{.status.phase}{"\t"}{.spec.nodeName}{"\n"}{end}' |
    awk '$1 == "Running" && $2 != "" {print $2}' |
    sort -u
}

ferrum_spire_server_pod() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"

  kubectl --context "$context" -n "$namespace" get pod \
    -l app=spire-server \
    -o jsonpath='{.items[0].metadata.name}'
}

ferrum_spire_server_exec() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"
  shift 2

  local pod
  pod="$(ferrum_spire_server_pod "$context" "$namespace")"
  if [[ -z "$pod" ]]; then
    printf 'no spire-server pod found in namespace %s\n' "$namespace" >&2
    return 1
  fi

  kubectl --context "$context" -n "$namespace" exec "$pod" -- \
    /opt/spire/bin/spire-server "$@" -socketPath /run/spire/server.sock
}

ferrum_spire_entry_has_selectors() {
  local output="$1"
  shift

  local selector
  for selector in "$@"; do
    if ! grep -q "Selector[[:space:]]*:[[:space:]]*$selector" <<<"$output"; then
      return 1
    fi
  done
}

ferrum_spire_k8s_psat_agent_parent_id_for_node() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"
  local trust_domain="${3:?trust domain is required}"
  local node_name="${4:?node name is required}"
  local cluster="${5:-$trust_domain}"
  local node_uid
  node_uid="$(kubectl --context "$context" get node "$node_name" -o jsonpath='{.metadata.uid}')"
  if [[ -z "$node_uid" ]]; then
    printf 'node %s has no Kubernetes UID\n' "$node_name" >&2
    return 1
  fi

  local parent_id="spiffe://$trust_domain/spire/agent/k8s_psat/$cluster/$node_uid"
  local attempts="${FERRUM_SPIRE_AGENT_PARENT_ID_ATTEMPTS:-30}"
  local sleep_seconds="${FERRUM_SPIRE_AGENT_PARENT_ID_SLEEP_SECONDS:-2}"
  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if ferrum_spire_server_exec "$context" "$namespace" agent show -spiffeID "$parent_id" >/dev/null 2>&1; then
      printf '%s\n' "$parent_id"
      return 0
    fi
    sleep "$sleep_seconds"
  done

  printf 'SPIRE k8s_psat agent for node %s is not attested; expected parent ID %s\n' \
    "$node_name" "$parent_id" >&2
  ferrum_spire_server_exec "$context" "$namespace" agent list >&2 || true
  return 1
}

ferrum_spire_register_k8s_workload() {
  local context="${1:?kube context is required}"
  local spire_namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"
  local spiffe_id="${3:?workload SPIFFE ID is required}"
  local parent_id="${4:?parent SPIFFE ID is required}"
  local workload_namespace="${5:?workload namespace is required}"
  local service_account="${6:?service account is required}"
  shift 6

  local -a selectors=(
    "k8s:ns:$workload_namespace"
    "k8s:sa:$service_account"
  )
  local selector
  for selector in "$@"; do
    selectors+=("$selector")
  done

  local existing=""
  if existing="$(ferrum_spire_server_exec "$context" "$spire_namespace" entry show -spiffeID "$spiffe_id" -parentID "$parent_id" 2>/dev/null)" &&
    ferrum_spire_entry_has_selectors "$existing" "${selectors[@]}"; then
    return 0
  fi

  local -a args=(
    entry create
    -spiffeID "$spiffe_id"
    -parentID "$parent_id"
  )
  for selector in "${selectors[@]}"; do
    args+=(-selector "$selector")
  done
  ferrum_spire_server_exec "$context" "$spire_namespace" "${args[@]}"
}

ferrum_spire_collect_diagnostics() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"
  local artifact_dir="${3:?artifact dir is required}"

  mkdir -p "$artifact_dir"
  kubectl --context "$context" -n "$namespace" get all -o wide > "$artifact_dir/spire-all.txt" 2>&1 || true
  kubectl --context "$context" -n "$namespace" logs statefulset/spire-server --all-containers --tail=1000 > "$artifact_dir/spire-server.log" 2>&1 || true
  kubectl --context "$context" -n "$namespace" logs daemonset/spire-agent --all-containers --tail=1000 > "$artifact_dir/spire-agent.log" 2>&1 || true
  ferrum_spire_server_exec "$context" "$namespace" agent list > "$artifact_dir/spire-agents.txt" 2>&1 || true
  ferrum_spire_server_exec "$context" "$namespace" entry show > "$artifact_dir/spire-entries.txt" 2>&1 || true
}
