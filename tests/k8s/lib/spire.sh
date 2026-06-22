#!/usr/bin/env bash
# Shared SPIRE helpers for Ferrum live-data-path suites.

set -euo pipefail

FERRUM_SPIRE_NAMESPACE="${FERRUM_SPIRE_NAMESPACE:-spire-system}"
FERRUM_SPIRE_SERVER_IMAGE="${FERRUM_SPIRE_SERVER_IMAGE:-ghcr.io/spiffe/spire-server:1.12.4}"
FERRUM_SPIRE_AGENT_IMAGE="${FERRUM_SPIRE_AGENT_IMAGE:-ghcr.io/spiffe/spire-agent:1.12.4}"

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
    }
    plugins {
      NodeAttestor "k8s_psat" {
        plugin_data {
          cluster = "$trust_domain"
        }
      }
      KeyManager "memory" {
        plugin_data {}
      }
      WorkloadAttestor "k8s" {
        plugin_data {
          kubelet_read_only_port = 10255
        }
      }
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
          volumeMounts:
            - name: config
              mountPath: /run/spire/config
            - name: sockets
              mountPath: /run/spire/sockets
      volumes:
        - name: config
          configMap:
            name: spire-agent
        - name: sockets
          hostPath:
            path: /run/spire/sockets
            type: DirectoryOrCreate
YAML
}

ferrum_spire_wait_ready() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"
  local timeout="${3:-180s}"

  kubectl --context "$context" -n "$namespace" rollout status statefulset/spire-server --timeout="$timeout"
  kubectl --context "$context" -n "$namespace" rollout status daemonset/spire-agent --timeout="$timeout"
}

ferrum_spire_collect_diagnostics() {
  local context="${1:?kube context is required}"
  local namespace="${2:-$FERRUM_SPIRE_NAMESPACE}"
  local artifact_dir="${3:?artifact dir is required}"

  mkdir -p "$artifact_dir"
  kubectl --context "$context" -n "$namespace" get all -o wide > "$artifact_dir/spire-all.txt" 2>&1 || true
  kubectl --context "$context" -n "$namespace" logs statefulset/spire-server --all-containers --tail=1000 > "$artifact_dir/spire-server.log" 2>&1 || true
  kubectl --context "$context" -n "$namespace" logs daemonset/spire-agent --all-containers --tail=1000 > "$artifact_dir/spire-agent.log" 2>&1 || true
}
