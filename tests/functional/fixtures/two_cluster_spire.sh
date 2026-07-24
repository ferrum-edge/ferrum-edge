#!/usr/bin/env bash
set -euo pipefail

# Minimal process-local SPIRE harness for the privileged two-cluster netns test.
# It deliberately uses join-token node attestation and the unix workload
# attestor: the fixture is validating Ferrum's live Workload API consumption,
# federated bundles, and cross-cluster datapath, not Kubernetes attestation.

command_name="${1:-}"
shift || true

wait_for_socket() {
  local socket="$1" label="$2"
  for _ in $(seq 1 100); do
    [[ -S "$socket" ]] && return 0
    sleep 0.1
  done
  echo "$label socket did not appear: $socket" >&2
  return 1
}

server_cli() {
  local root="$1"
  shift
  spire-server "$@" -socketPath "$root/server.sock"
}

wait_for_workload_svid() {
  local root="$1" workload_id="$2" workload_uid="$3"
  for _ in $(seq 1 100); do
    if setpriv \
      "--reuid=$workload_uid" \
      "--regid=$workload_uid" \
      --clear-groups \
      -- spire-agent api fetch x509 \
        -socketPath "$root/agent.sock" \
        -timeout 1s \
        -silent >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "SPIRE SVID was not issued for $workload_id (uid $workload_uid)" >&2
  return 1
}

case "$command_name" in
  start)
    root="${1:?root directory is required}"
    trust_domain="${2:?trust domain is required}"
    server_port="${3:?server port is required}"
    mkdir -p "$root/server-data" "$root/agent-data"
    chmod 0755 "$root"

    cat >"$root/server.conf" <<EOF
server {
  bind_address = "127.0.0.1"
  bind_port = "$server_port"
  socket_path = "$root/server.sock"
  trust_domain = "$trust_domain"
  data_dir = "$root/server-data"
  log_level = "DEBUG"
}
plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "$root/server-data/datastore.sqlite3"
    }
  }
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "disk" {
    plugin_data { keys_path = "$root/server-data/keys.json" }
  }
}
EOF

    spire-server run -config "$root/server.conf" >"$root/server.log" 2>&1 &
    echo "$!" >"$root/server.pid"
    wait_for_socket "$root/server.sock" "SPIRE server"
    server_cli "$root" bundle show -format pem >"$root/bundle.pem"

    # Capture the producer's full output before parsing: under `set -o pipefail`,
    # piping into an awk that exits early (the `exit` below) can SIGPIPE the
    # producer and surface as exit status 141, masking a valid token.
    token_output="$(server_cli "$root" token generate)"
    token="$(awk '/Token:/ {print $2; exit}' <<<"$token_output")"
    [[ -n "$token" ]] || {
      echo "SPIRE join token generation returned no token" >&2
      exit 1
    }
    agent_id="spiffe://$trust_domain/spire/agent/join_token/$token"
    printf '%s\n' "$agent_id" >"$root/agent.id"

    cat >"$root/agent.conf" <<EOF
agent {
  data_dir = "$root/agent-data"
  log_level = "DEBUG"
  server_address = "127.0.0.1"
  server_port = "$server_port"
  socket_path = "$root/agent.sock"
  trust_domain = "$trust_domain"
  trust_bundle_path = "$root/bundle.pem"
}
plugins {
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory" { plugin_data {} }
  WorkloadAttestor "unix" { plugin_data {} }
}
EOF

    spire-agent run -config "$root/agent.conf" -joinToken "$token" >"$root/agent.log" 2>&1 &
    echo "$!" >"$root/agent.pid"
    wait_for_socket "$root/agent.sock" "SPIRE agent"
    chmod 0777 "$root/agent.sock"
    ;;

  federate)
    root_a="${1:?cluster A root is required}"
    td_a="${2:?cluster A trust domain is required}"
    root_b="${3:?cluster B root is required}"
    td_b="${4:?cluster B trust domain is required}"
    server_cli "$root_a" bundle show -format spiffe >"$root_a/bundle.spiffe"
    server_cli "$root_b" bundle show -format spiffe >"$root_b/bundle.spiffe"
    server_cli "$root_b" bundle set -format spiffe -id "spiffe://$td_a" <"$root_a/bundle.spiffe"
    server_cli "$root_a" bundle set -format spiffe -id "spiffe://$td_b" <"$root_b/bundle.spiffe"
    server_cli "$root_a" bundle list -id "spiffe://$td_b" -format spiffe >/dev/null
    server_cli "$root_b" bundle list -id "spiffe://$td_a" -format spiffe >/dev/null
    ;;

  register)
    root="${1:?root directory is required}"
    trust_domain="${2:?trust domain is required}"
    workload_id="${3:?workload SPIFFE ID is required}"
    peer_domain="${4:-}"
    workload_uid="${5:-1337}"
    agent_id="$(<"$root/agent.id")"
    [[ "$agent_id" == "spiffe://$trust_domain/spire/agent/join_token/"* ]] || {
      echo "SPIRE agent ID does not belong to trust domain $trust_domain: $agent_id" >&2
      exit 1
    }
    args=(entry create
      -parentID "$agent_id"
      -spiffeID "$workload_id"
      -selector "unix:uid:$workload_uid")
    if [[ -n "$peer_domain" ]]; then
      args+=(-federatesWith "spiffe://$peer_domain")
    fi
    server_cli "$root" "${args[@]}"
    wait_for_workload_svid "$root" "$workload_id" "$workload_uid"
    ;;

  wait-svid)
    root="${1:?root directory is required}"
    workload_id="${2:?workload SPIFFE ID is required}"
    workload_uid="${3:-1337}"
    wait_for_workload_svid "$root" "$workload_id" "$workload_uid"
    ;;

  stop)
    root="${1:?root directory is required}"
    for name in agent server; do
      if [[ -f "$root/$name.pid" ]]; then
        pid="$(cat "$root/$name.pid")"
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.1
        done
        kill -KILL "$pid" 2>/dev/null || true
      fi
    done
    ;;

  *)
    echo "usage: $0 {start|federate|register|wait-svid|stop} ..." >&2
    exit 2
    ;;
esac
