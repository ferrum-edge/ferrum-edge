#!/usr/bin/env bash
# Ambient host-network UDP live-kernel gate (#3705 / ownership-safe cleanup #3804).
#
# Expects prebuilt lib and functional test binaries from the workflow (never
# builds here). Reuses the repository skip-or-fail contract:
# FERRUM_LIVE_TESTS_REQUIRED=1 turns unsupported runners into hard failures.
#
# Ownership contract (#3804):
#   * Complete root/tool/kernel/preflight validation before any network mutation.
#   * Acquire a fixed shared-filesystem exclusive flock before creating a netns.
#   * Every ordinary root execution runs the complete fixture inside newly
#     created disposable outer network + mount namespaces (the ownership
#     boundary). A fresh sysfs mount is bound to that network namespace.
#   * Isolation is proven structurally (self netns != parent-captured identity
#     and != init netns). Environment flags are never trusted as proof.
#   * Ordinary teardown never enumerates or deletes canonical host objects;
#     fixture networking state vanishes only when the owned outer netns ends.
#   * Early non-root / missing-tool / preflight SKIP paths leave networking
#     byte-for-byte unchanged.
#   * Emergency canonical destroy is a separate loud opt-in, never ordinary exits.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RESULTS="${FERRUM_HOST_UDP_LIVE_RESULTS:-$ROOT/target/ambient-host-udp-live}"
mkdir -p "$RESULTS"

LIVE_REQUIRED="${FERRUM_LIVE_TESTS_REQUIRED:-0}"
LIB_BIN="${FERRUM_HOST_UDP_LIB_TEST_BIN:?FERRUM_HOST_UDP_LIB_TEST_BIN must point at the lib test binary}"
FUNC_BIN="${FERRUM_HOST_UDP_FUNCTIONAL_TEST_BIN:?FERRUM_HOST_UDP_FUNCTIONAL_TEST_BIN must point at the functional test binary}"
EMERGENCY_DESTROY="${FERRUM_HOST_UDP_LIVE_EMERGENCY_DESTROY_CANONICAL:-0}"

# Fixed lock location only. /run is a root-owned, non-user-writable shared
# mount across the network namespaces created below. Never place this
# privileged lock beneath /tmp: an unprivileged user could pre-create a
# directory or symlink and redirect Bash's root open/truncate operation.
readonly FERRUM_HOST_UDP_LIVE_LOCK_PATH="/run/ferrum-edge-ambient-host-udp-live.lock"
# Internal argv marker for the disposable-outer child. Not an operator trust root;
# structural netns proof below is mandatory.
readonly FERRUM_HOST_UDP_LIVE_INNER_ARGV="--ferrum-inner-host-udp-live"

lib_raw=""
func_raw=""
LOCK_FD=""
LOCK_HELD=0
PARENT_NETNS_ID=""
OUTER_PID=""

HOST_UDP_CHAINS=(
  FERRUM_MESH_UDP_HOST
  FERRUM_MESH_UDP_HOST_GUARD_A
  FERRUM_MESH_UDP_HOST_GUARD_B
)

redact() {
  # Bound and scrub diagnostics in one consumer. Avoid a sed|head pipeline:
  # under pipefail, head closing early can turn an intentionally truncated
  # diagnostic into a false test failure.
  LC_ALL=C awk '
    BEGIN { lines = 0; bytes = 0 }
    {
      lower = tolower($0)
      if (lower ~ /token=/ || lower ~ /secret/ || lower ~ /bearer/ || lower ~ /authorization:/) {
        next
      }
      rendered = $0 ORS
      if (lines >= 200 || bytes + length(rendered) > 16384) {
        next
      }
      printf "%s", rendered
      lines++
      bytes += length(rendered)
    }
  '
}

collect_diag() {
  local out="$1"
  {
    echo "=== ip rule ==="
    ip rule show 2>/dev/null | head -n 40 || true
    echo "=== Ferrum host UDP table 33135 ==="
    ip route show table 33135 2>/dev/null | head -n 20 || true
    ip -6 route show table 33135 2>/dev/null | head -n 20 || true
    echo "=== Ferrum mangle chains ==="
    iptables-save -t mangle 2>/dev/null | grep -E 'FERRUM_MESH_UDP_HOST|FERRUM_UDP' | head -n 60 || true
    ip6tables-save -t mangle 2>/dev/null | grep -E 'FERRUM_MESH_UDP_HOST|FERRUM_UDP' | head -n 60 || true
    echo "=== interface indexes ==="
    for i in /sys/class/net/*/ifindex; do
      echo "$i=$(cat "$i" 2>/dev/null || true)"
    done | head -n 40
    echo "=== sysfs namespace probe ==="
    if [[ -r /sys/class/net/lo/ifindex ]]; then
      echo "lo_ifindex=$(cat /sys/class/net/lo/ifindex 2>/dev/null || true)"
    fi
    echo "=== udp binds ==="
    (cat /proc/net/udp /proc/net/udp6 2>/dev/null || true) | head -n 30
    echo "=== netns identity ==="
    echo "self=$(netns_identity)"
    echo "parent=${PARENT_NETNS_ID:-}"
    echo "init=$(init_netns_identity)"
  } | redact >"$out"
}

fail_required() {
  echo "::error::$1" >&2
  exit 1
}

netns_identity() {
  readlink /proc/self/ns/net 2>/dev/null | tr -d '[:space:]' || true
}

init_netns_identity() {
  readlink /proc/1/ns/net 2>/dev/null | tr -d '[:space:]' || true
}

release_lock() {
  if [[ "$LOCK_HELD" == "1" && -n "${LOCK_FD:-}" ]]; then
    flock -u "$LOCK_FD" 2>/dev/null || true
    # Safe Bash dynamic-FD close — never eval.
    exec {LOCK_FD}>&- 2>/dev/null || true
    LOCK_FD=""
    LOCK_HELD=0
  fi
}

# Temp-file-only cleanup. Ordinary exits must NEVER enumerate or delete
# canonical iptables/ip6tables chains, jumps, rules, or routes.
ordinary_exit_cleanup() {
  trap - EXIT INT TERM HUP
  if [[ -n "$lib_raw" ]]; then
    rm -f -- "$lib_raw"
  fi
  if [[ -n "$func_raw" ]]; then
    rm -f -- "$func_raw"
  fi
  release_lock
}

terminate_outer_child() {
  local outer_pid="${OUTER_PID:-}"
  if [[ -z "$outer_pid" ]]; then
    return
  fi

  # The child is launched as its own session/process-group leader. Signal the
  # whole tree so a synchronous test binary cannot outlive the namespace
  # owner. Give normal traps a brief chance to scrub raw temp output, then
  # force termination and reap the leader before the exclusive lock is freed.
  kill -TERM -- "-$outer_pid" 2>/dev/null || true
  sleep 1
  kill -KILL -- "-$outer_pid" 2>/dev/null || true
  wait "$outer_pid" 2>/dev/null || true
  OUTER_PID=""
}

handle_outer_signal() {
  local status="$1"
  trap - EXIT INT TERM HUP
  terminate_outer_child
  ordinary_exit_cleanup
  exit "$status"
}

early_temp_cleanup() {
  if [[ -n "$lib_raw" ]]; then
    rm -f -- "$lib_raw"
  fi
  if [[ -n "$func_raw" ]]; then
    rm -f -- "$func_raw"
  fi
}

emergency_destroy_canonical() {
  echo "EMERGENCY: FERRUM_HOST_UDP_LIVE_EMERGENCY_DESTROY_CANONICAL is set" >&2
  echo "EMERGENCY: removing canonical Ferrum host-UDP objects in the current netns" >&2
  echo "EMERGENCY: this path is never reached from ordinary fixture exits" >&2
  local chain
  for chain in "${HOST_UDP_CHAINS[@]}"; do
    iptables -t mangle -D PREROUTING -j "$chain" 2>/dev/null || true
    iptables -t mangle -F "$chain" 2>/dev/null || true
    iptables -t mangle -X "$chain" 2>/dev/null || true
    ip6tables -t mangle -D PREROUTING -j "$chain" 2>/dev/null || true
    ip6tables -t mangle -F "$chain" 2>/dev/null || true
    ip6tables -t mangle -X "$chain" 2>/dev/null || true
  done
  ip rule del priority 101 lookup 33135 2>/dev/null || true
  ip -6 rule del priority 101 lookup 33135 2>/dev/null || true
  ip route del local 0.0.0.0/0 dev lo table 33135 2>/dev/null || true
  ip -6 route del local ::/0 dev lo table 33135 2>/dev/null || true
}

acquire_exclusive_lock() {
  local lock_parent lock_parent_meta lock_parent_owner lock_parent_mode
  local lock_meta lock_owner lock_mode previous_umask

  # Ignore any operator-supplied lock directory; path is fixed above.
  if [[ -n "${FERRUM_HOST_UDP_LIVE_LOCK_DIR:-}" ]]; then
    echo "warning: ignoring FERRUM_HOST_UDP_LIVE_LOCK_DIR (lock path is fixed)" >&2
  fi

  lock_parent="${FERRUM_HOST_UDP_LIVE_LOCK_PATH%/*}"
  if [[ -L "$lock_parent" || ! -d "$lock_parent" ]]; then
    fail_required "host-UDP live lock parent must be a real directory: $lock_parent"
  fi
  lock_parent_meta="$(stat -Lc '%u:%a' -- "$lock_parent")" || \
    fail_required "unable to inspect host-UDP live lock parent: $lock_parent"
  lock_parent_owner="${lock_parent_meta%%:*}"
  lock_parent_mode="${lock_parent_meta#*:}"
  if [[ "$lock_parent_owner" != "0" ]] || (( (8#$lock_parent_mode & 0022) != 0 )); then
    fail_required "host-UDP live lock parent must be root-owned and not group/world-writable: $lock_parent"
  fi
  if [[ -L "$FERRUM_HOST_UDP_LIVE_LOCK_PATH" ]] \
    || [[ -e "$FERRUM_HOST_UDP_LIVE_LOCK_PATH" && ! -f "$FERRUM_HOST_UDP_LIVE_LOCK_PATH" ]]; then
    fail_required "host-UDP live lock path must be a regular file, never a symlink"
  fi
  if [[ -e "$FERRUM_HOST_UDP_LIVE_LOCK_PATH" ]]; then
    lock_meta="$(stat -Lc '%u:%a' -- "$FERRUM_HOST_UDP_LIVE_LOCK_PATH")" || \
      fail_required "unable to inspect existing host-UDP live lock"
    lock_owner="${lock_meta%%:*}"
    lock_mode="${lock_meta#*:}"
    if [[ "$lock_owner" != "0" ]] || (( (8#$lock_mode & 0077) != 0 )); then
      fail_required "existing host-UDP live lock must be root-owned and mode 0600"
    fi
  fi

  # Safe Bash dynamic-FD open — never eval. Treat path as data only.
  previous_umask="$(umask)"
  umask 077
  if exec {LOCK_FD}>"$FERRUM_HOST_UDP_LIVE_LOCK_PATH"; then
    umask "$previous_umask"
  else
    umask "$previous_umask"
    fail_required "unable to open host-UDP live lock at $FERRUM_HOST_UDP_LIVE_LOCK_PATH"
  fi
  if ! flock -n "$LOCK_FD"; then
    exec {LOCK_FD}>&- 2>/dev/null || true
    LOCK_FD=""
    fail_required "another ambient_host_udp_live owner already holds the exclusive lock at $FERRUM_HOST_UDP_LIVE_LOCK_PATH"
  fi
  LOCK_HELD=1
}

prove_disposable_outer_netns() {
  local self init parent="$1"
  self="$(netns_identity)"
  init="$(init_netns_identity)"
  if [[ -z "$self" ]]; then
    fail_required "unable to resolve /proc/self/ns/net for disposable outer-netns proof"
  fi
  if [[ -z "$parent" ]]; then
    fail_required "missing parent-captured netns identity for disposable outer-netns proof"
  fi
  if [[ "$self" == "$parent" ]]; then
    fail_required "refusing to run: still in the parent network namespace (disposable outer netns required)"
  fi
  # Do not trust FERRUM_HOST_UDP_LIVE_IN_OUTER_NETNS or any other env flag.
  # Init comparison catches forged "already isolated" claims on the host.
  if [[ -z "$init" ]]; then
    fail_required "unable to resolve /proc/1/ns/net for disposable outer-netns proof"
  fi
  if [[ "$self" == "$init" ]]; then
    fail_required "refusing to run: still in the init/host network namespace (disposable outer netns required)"
  fi
  PARENT_NETNS_ID="$parent"
  echo "disposable outer netns proven: self=$self parent=$parent init=$init"
}

# A network namespace alone is not enough for this gate. A sysfs superblock is
# associated with the network namespace in which it was mounted, so carrying
# the runner's existing /sys mount into `unshare --net` leaves production's
# `/sys/class/net/<veth>` validation looking at the parent interfaces. Mount a
# fresh, read-only sysfs inside the private mount namespace, then prove the view
# follows a disposable veth through creation and removal before test mutation.
mount_and_prove_disposable_sysfs() {
  local probe_host="fhsys0" probe_peer="fhsys1"

  if ! mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys; then
    fail_required "unable to mount disposable-netns sysfs view"
  fi
  if ! ip link add "$probe_host" type veth peer name "$probe_peer"; then
    fail_required "unable to create disposable sysfs namespace probe"
  fi
  if [[ ! -r "/sys/class/net/$probe_host/ifindex" \
    || ! -r "/sys/class/net/$probe_host/iflink" \
    || ! -r "/sys/class/net/$probe_peer/ifindex" ]]; then
    ip link del "$probe_host" 2>/dev/null || true
    fail_required "disposable sysfs view does not track the owned network namespace"
  fi
  ip link del "$probe_host" || \
    fail_required "unable to remove disposable sysfs namespace probe"
  if [[ -e "/sys/class/net/$probe_host" || -e "/sys/class/net/$probe_peer" ]]; then
    fail_required "disposable sysfs view retained a removed namespace probe"
  fi
  echo "disposable sysfs view proven for the owned network namespace"
}

bring_up_loopback() {
  ip link set lo up
  if [[ -w /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
    printf 0 >/proc/sys/net/ipv6/conf/all/disable_ipv6 || true
  fi
  ip -6 link set lo up 2>/dev/null || true
}

run_live_tests() {
  collect_diag "$RESULTS/pre-run-diagnostics.txt"

  echo "Running ambient host-UDP live-kernel lib tests via $LIB_BIN"
  lib_raw="$(mktemp "${TMPDIR:-/tmp}/ferrum-host-udp-lib.XXXXXX")"
  set +e
  FERRUM_LIVE_TESTS_REQUIRED=1 \
    timeout --signal=KILL 180s \
    "$LIB_BIN" proxy::host_udp_capture_live_tests --ignored --nocapture --test-threads=1 \
    >"$lib_raw" 2>&1
  local lib_status=$?
  set -e
  redact <"$lib_raw" | tee "$RESULTS/lib-tests.log"
  if [[ "$lib_status" -ne 0 ]]; then
    collect_diag "$RESULTS/post-run-diagnostics.txt" || true
    exit "$lib_status"
  fi
  if grep -q '^SKIP:' "$lib_raw"; then
    fail_required "ambient host-UDP lib live tests skipped under required CI mode"
  fi
  if ! grep -Eq '^test result: ok\. 2 passed; 0 failed;' "$lib_raw"; then
    fail_required "expected exactly 2 ambient host-UDP lib live tests to pass"
  fi
  rm -f -- "$lib_raw"
  lib_raw=""

  echo "Running ambient host-UDP production ProxyHostUdpBackend functional live test via $FUNC_BIN"
  func_raw="$(mktemp "${TMPDIR:-/tmp}/ferrum-host-udp-functional.XXXXXX")"
  set +e
  FERRUM_LIVE_TESTS_REQUIRED=1 \
    FERRUM_SKIP_GATEWAY_BUILD=1 \
    timeout --signal=KILL 300s \
    "$FUNC_BIN" functional_mesh_live_host_udp_capture --ignored --nocapture --test-threads=1 \
    >"$func_raw" 2>&1
  local func_status=$?
  set -e
  redact <"$func_raw" | tee "$RESULTS/functional-tests.log"
  if [[ "$func_status" -ne 0 ]]; then
    collect_diag "$RESULTS/post-run-diagnostics.txt" || true
    exit "$func_status"
  fi
  if grep -q '^SKIP:' "$func_raw"; then
    fail_required "ambient host-UDP functional live tests skipped under required CI mode"
  fi
  if ! grep -Eq '^test result: ok\. 1 passed; 0 failed;' "$func_raw"; then
    fail_required "expected exactly 1 ambient host-UDP functional live test to pass"
  fi
  rm -f -- "$func_raw"
  func_raw=""

  collect_diag "$RESULTS/post-run-diagnostics.txt" || true
  echo "ambient-host-udp-live: ok"
}

run_inner_fixture() {
  local parent_ns="$1"
  # Inner child: prove isolation, run tests. No networking delete on exit —
  # leaving this netns discards all canonical objects created here.
  trap early_temp_cleanup EXIT
  trap 'early_temp_cleanup; exit 130' INT
  trap 'early_temp_cleanup; exit 143' TERM
  trap 'early_temp_cleanup; exit 129' HUP

  prove_disposable_outer_netns "$parent_ns"
  bring_up_loopback
  mount_and_prove_disposable_sysfs
  run_live_tests
}

# ---------------------------------------------------------------------------
# Optional explicit emergency path (never implicit on ordinary exits).
# ---------------------------------------------------------------------------
if [[ "$EMERGENCY_DESTROY" == "1" || "$EMERGENCY_DESTROY" == "true" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    fail_required "FERRUM_HOST_UDP_LIVE_EMERGENCY_DESTROY_CANONICAL requires root"
  fi
  emergency_destroy_canonical
  echo "emergency canonical destroy complete"
  exit 0
fi

# Inner re-entry used only by the outer wrapper's `unshare --net -- "$0" ...`.
# Structural netns proof is mandatory; argv alone is not trusted.
if [[ "${1:-}" == "$FERRUM_HOST_UDP_LIVE_INNER_ARGV" ]]; then
  shift
  parent_ns="${1:-}"
  if [[ -z "$parent_ns" ]]; then
    fail_required "inner fixture requires parent-captured netns identity argv"
  fi
  shift || true
  run_inner_fixture "$parent_ns"
  exit 0
fi

# Temp cleanup only until the exclusive lock is held. Networking must stay
# untouched through every early SKIP / prerequisite failure.
trap early_temp_cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  if [[ "$LIVE_REQUIRED" == "1" || "$LIVE_REQUIRED" == "true" ]]; then
    fail_required "FERRUM_LIVE_TESTS_REQUIRED=1 requires root for ambient host-UDP live"
  fi
  echo "SKIP: not root"
  exit 0
fi

for bin in unshare nsenter mount ip iptables ip6tables iptables-save ip6tables-save timeout mktemp flock stat setsid sleep; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    if [[ "$LIVE_REQUIRED" == "1" || "$LIVE_REQUIRED" == "true" ]]; then
      fail_required "FERRUM_LIVE_TESTS_REQUIRED=1 requires $bin"
    fi
    echo "SKIP: $bin unavailable"
    exit 0
  fi
done

# Prove both mangle implementations are usable in throwaway network namespaces
# before the suite. Invoke fixed executables directly: generated `sh -c` input
# is intentionally forbidden in automation surfaces by the trusted Cross
# policy. Production setup below performs the full TPROXY/policy-route proof.
if ! unshare --net -- iptables -t mangle -L >"$RESULTS/preflight.txt" 2>&1 \
  || ! unshare --net -- ip6tables -t mangle -L >>"$RESULTS/preflight.txt" 2>&1; then
  if [[ "$LIVE_REQUIRED" == "1" || "$LIVE_REQUIRED" == "true" ]]; then
    fail_required "host-UDP live preflight failed under required mode"
  fi
  echo "SKIP: throwaway netns / mangle preflight failed"
  cat "$RESULTS/preflight.txt" >&2 || true
  exit 0
fi

# --- From here on: exclusive lock, then disposable outer netns. Host
# networking is never entered for fixture mutation; pre-existing canonical
# host state remains byte-for-byte untouched.

acquire_exclusive_lock
trap ordinary_exit_cleanup EXIT
trap 'handle_outer_signal 130' INT
trap 'handle_outer_signal 143' TERM
trap 'handle_outer_signal 129' HUP

PARENT_NETNS_ID="$(netns_identity)"
if [[ -z "$PARENT_NETNS_ID" ]]; then
  fail_required "unable to capture parent /proc/self/ns/net before disposable outer netns"
fi

echo "Creating disposable outer network namespace for ambient host-UDP live (#3804)"
set +e
# A dedicated session gives signal cleanup an exact process-group ownership
# boundary. Bash records the session leader in $!, allowing the parent to
# terminate and reap the complete namespace child tree before lock release.
setsid unshare --mount --net --propagation private -- \
  "$0" "$FERRUM_HOST_UDP_LIVE_INNER_ARGV" "$PARENT_NETNS_ID" &
OUTER_PID=$!
wait "$OUTER_PID"
inner_status=$?
OUTER_PID=""
set -e

# Ordinary teardown: release lock / temps only. Do not enumerate or delete
# canonical objects in this (parent) namespace — the child's netns lifetime
# already discarded every chain/jump/rule/route the fixture created.
exit "$inner_status"
