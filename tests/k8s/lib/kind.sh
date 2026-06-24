#!/usr/bin/env bash
# Shared kind helpers for Ferrum live-data-path suites.

set -euo pipefail

ferrum_kind_require_tools() {
  command -v docker >/dev/null 2>&1 || {
    printf 'missing required command: docker\n' >&2
    return 127
  }
  command -v kind >/dev/null 2>&1 || {
    printf 'missing required command: kind\n' >&2
    return 127
  }
  command -v kubectl >/dev/null 2>&1 || {
    printf 'missing required command: kubectl\n' >&2
    return 127
  }
  docker info >/dev/null
}

ferrum_kind_cluster_exists() {
  local cluster="${1:?cluster name is required}"
  kind get clusters | grep -Fxq "$cluster"
}

ferrum_kind_write_config() {
  local output_file="${1:?output file is required}"
  local worker_count="${2:-2}"
  local ip_family="${3:-dual}"
  local pod_subnets="${4:-10.244.0.0/16,fd00:10:244::/56}"
  local service_subnets="${5:-10.96.0.0/16,fd00:10:96::/112}"

  mkdir -p "$(dirname "$output_file")"
  {
    printf 'kind: Cluster\n'
    printf 'apiVersion: kind.x-k8s.io/v1alpha4\n'
    printf 'networking:\n'
    printf '  ipFamily: %s\n' "$ip_family"
    printf '  podSubnet: "%s"\n' "$pod_subnets"
    printf '  serviceSubnet: "%s"\n' "$service_subnets"
    printf 'nodes:\n'
    printf '  - role: control-plane\n'
    for _ in $(seq 1 "$worker_count"); do
      printf '  - role: worker\n'
    done
  } > "$output_file"
}

ferrum_kind_create_disposable_cluster() {
  local cluster="${1:?cluster name is required}"
  local config_file="${2:?kind config file is required}"
  local wait="${3:-180s}"

  ferrum_kind_require_tools
  if ferrum_kind_cluster_exists "$cluster"; then
    printf 'kind cluster already exists: %s\n' "$cluster" >&2
    return 0
  fi
  kind create cluster --name "$cluster" --config "$config_file" --wait "$wait"
}

ferrum_kind_mount_bpffs_on_nodes() {
  local cluster="${1:?cluster name is required}"
  local node
  for node in $(kind get nodes --name "$cluster"); do
    docker exec "$node" sh -eu -c '
      mkdir -p /sys/fs/bpf
      grep -q " /sys/fs/bpf bpf " /proc/mounts || mount -t bpf bpf /sys/fs/bpf
      test -f /sys/fs/cgroup/cgroup.controllers
      mount | grep -q " /sys/fs/bpf type bpf "
    '
  done
}

ferrum_kind_load_images() {
  local cluster="${1:?cluster name is required}"
  shift
  local image
  for image in "$@"; do
    kind load docker-image "$image" --name "$cluster"
  done
}

ferrum_kind_collect_basics() {
  local context="${1:?kube context is required}"
  local namespace="${2:?namespace is required}"
  local artifact_dir="${3:?artifact dir is required}"

  mkdir -p "$artifact_dir"
  kubectl --context "$context" get nodes -o wide > "$artifact_dir/nodes.txt" 2>&1 || true
  kubectl --context "$context" -n "$namespace" get all -o wide > "$artifact_dir/${namespace}-all.txt" 2>&1 || true
  kubectl --context "$context" -n "$namespace" get events --sort-by=.lastTimestamp > "$artifact_dir/${namespace}-events.txt" 2>&1 || true
}
