#!/usr/bin/env bash
# Ambient host-network UDP live-kernel gate (#3705 / ownership-safe cleanup #3804).
#
# Expects prebuilt lib and functional test binaries from the workflow (never
# builds here). Reuses the repository skip-or-fail contract:
# FERRUM_LIVE_TESTS_REQUIRED=1 turns unsupported runners into hard failures.
#
# Ownership contract (#3804):
#   * Complete root/tool/kernel/preflight validation before arming cleanup.
#   * Refuse pre-existing canonical Ferrum host-UDP state before mutation.
#   * Namespace-scoped exclusive flock prevents concurrent fixture owners.
#   * Ownership ledger is acquired only after verified-empty + lock.
#   * Cleanup removes only state still provably owned by this run.
#   * No snapshot-and-blind-delete: foreign/reconciled state fails closed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RESULTS="${FERRUM_HOST_UDP_LIVE_RESULTS:-$ROOT/target/ambient-host-udp-live}"
mkdir -p "$RESULTS"

LIVE_REQUIRED="${FERRUM_LIVE_TESTS_REQUIRED:-0}"
LIB_BIN="${FERRUM_HOST_UDP_LIB_TEST_BIN:?FERRUM_HOST_UDP_LIB_TEST_BIN must point at the lib test binary}"
FUNC_BIN="${FERRUM_HOST_UDP_FUNCTIONAL_TEST_BIN:?FERRUM_HOST_UDP_FUNCTIONAL_TEST_BIN must point at the functional test binary}"
IN_OUTER_NETNS="${FERRUM_HOST_UDP_LIVE_IN_OUTER_NETNS:-0}"
ALLOW_DESTRUCTIVE_ADOPT="${FERRUM_HOST_UDP_LIVE_ALLOW_DESTRUCTIVE_ADOPT:-0}"
EMERGENCY_DESTROY="${FERRUM_HOST_UDP_LIVE_EMERGENCY_DESTROY_CANONICAL:-0}"

lib_raw=""
func_raw=""
CLEANUP_ARMED=0
OWNED_MUTATION=0
LOCK_FD=""
LOCK_PATH=""
LEDGER_PATH=""
RUN_ID=""
NETNS_ID=""
OWNER_CHANGE_DETECTED=0

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
    echo "=== udp binds ==="
    (cat /proc/net/udp /proc/net/udp6 2>/dev/null || true) | head -n 30
    echo "=== ownership ledger ==="
    if [[ -n "$LEDGER_PATH" && -f "$LEDGER_PATH" ]]; then
      cat "$LEDGER_PATH" 2>/dev/null || true
    else
      echo "(none)"
    fi
  } | redact >"$out"
}

fail_required() {
  echo "::error::$1" >&2
  exit 1
}

netns_identity() {
  # Stable per-namespace id for lock/ledger scoping (inode from ns link).
  readlink /proc/self/ns/net 2>/dev/null | tr -d '[:space:]' || true
}

mangle_chain_exists() {
  local family="$1"
  local chain="$2"
  case "$family" in
    v4) iptables -t mangle -L "$chain" -n >/dev/null 2>&1 ;;
    v6) ip6tables -t mangle -L "$chain" -n >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

prerouting_jump_exists() {
  local family="$1"
  local chain="$2"
  local dump=""
  case "$family" in
    v4) dump="$(iptables-save -t mangle 2>/dev/null || true)" ;;
    v6) dump="$(ip6tables-save -t mangle 2>/dev/null || true)" ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$dump" | grep -Eq -- "-A PREROUTING .* -j ${chain}([[:space:]]|$)"
}

priority_rule_exists() {
  local family="$1"
  case "$family" in
    v4) ip rule show 2>/dev/null | grep -Eq '(^|[[:space:]])101:.*lookup 33135' ;;
    v6) ip -6 rule show 2>/dev/null | grep -Eq '(^|[[:space:]])101:.*lookup 33135' ;;
    *) return 1 ;;
  esac
}

table_local_route_exists() {
  local family="$1"
  case "$family" in
    v4) ip route show table 33135 2>/dev/null | grep -Eq '^local 0\.0\.0\.0/0([[:space:]]|$)' ;;
    v6) ip -6 route show table 33135 2>/dev/null | grep -Eq '^local ::/0([[:space:]]|$)' ;;
    *) return 1 ;;
  esac
}

# Emit one line per canonical object currently present (v4/v6 symmetric).
list_canonical_host_udp_objects() {
  local family chain
  for family in v4 v6; do
    for chain in "${HOST_UDP_CHAINS[@]}"; do
      if mangle_chain_exists "$family" "$chain"; then
        echo "chain:${family}:${chain}"
      fi
      if prerouting_jump_exists "$family" "$chain"; then
        echo "jump:${family}:PREROUTING:${chain}"
      fi
    done
    if priority_rule_exists "$family"; then
      echo "rule:${family}:101:33135"
    fi
    if table_local_route_exists "$family"; then
      echo "route:${family}:33135:local-default"
    fi
  done
}

canonical_state_present() {
  [[ -n "$(list_canonical_host_udp_objects)" ]]
}

production_ferrum_process_detected() {
  # Inside a disposable outer netns the host's Ferrum process cannot own THIS
  # namespace's chains/rules/routes, so process presence is not a refusal.
  if [[ "$IN_OUTER_NETNS" == "1" || "$IN_OUTER_NETNS" == "true" ]]; then
    return 1
  fi
  local self_pid=$$
  local pid cmd
  # Busybox/ps portability: prefer /proc walk over parsing ps flags.
  for pid in /proc/[0-9]*; do
    pid="${pid#/proc/}"
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [[ "$pid" == "$self_pid" ]] && continue
    cmd="$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)"
    [[ -n "$cmd" ]] || continue
    # Ignore this fixture's own prebuilt test binaries and explicit helpers.
    case "$cmd" in
      *"$LIB_BIN"*|*"$FUNC_BIN"*|*ambient_host_udp_live/run.sh*) continue ;;
    esac
    case "$cmd" in
      *ferrum-edge*|*/ferrum-edge\ *|*/ferrum-edge)
        echo "$pid $cmd"
        return 0
        ;;
    esac
  done
  return 1
}

release_lock() {
  if [[ -n "$LOCK_FD" ]]; then
    # shellcheck disable=SC2094
    flock -u "$LOCK_FD" 2>/dev/null || true
    eval "exec ${LOCK_FD}>&-" 2>/dev/null || true
    LOCK_FD=""
  fi
}

remove_owned_object() {
  local key="$1"
  case "$key" in
    chain:v4:*)
      iptables -t mangle -F "${key#chain:v4:}" 2>/dev/null || true
      iptables -t mangle -X "${key#chain:v4:}" 2>/dev/null || true
      ;;
    chain:v6:*)
      ip6tables -t mangle -F "${key#chain:v6:}" 2>/dev/null || true
      ip6tables -t mangle -X "${key#chain:v6:}" 2>/dev/null || true
      ;;
    jump:v4:PREROUTING:*)
      iptables -t mangle -D PREROUTING -j "${key#jump:v4:PREROUTING:}" 2>/dev/null || true
      ;;
    jump:v6:PREROUTING:*)
      ip6tables -t mangle -D PREROUTING -j "${key#jump:v6:PREROUTING:}" 2>/dev/null || true
      ;;
    rule:v4:101:33135)
      ip rule del priority 101 lookup 33135 2>/dev/null || true
      ;;
    rule:v6:101:33135)
      ip -6 rule del priority 101 lookup 33135 2>/dev/null || true
      ;;
    route:v4:33135:local-default)
      ip route del local 0.0.0.0/0 dev lo table 33135 2>/dev/null || true
      ;;
    route:v6:33135:local-default)
      ip -6 route del local ::/0 dev lo table 33135 2>/dev/null || true
      ;;
    *)
      echo "ownership-safe cleanup: refusing unknown ledger key: $key" >&2
      OWNER_CHANGE_DETECTED=1
      return 1
      ;;
  esac
}

ledger_field() {
  local key="$1"
  local path="$2"
  # Exact KEY='value' lines written by write_ownership_ledger.
  sed -n "s/^${key}='\\(.*\\)'$/\\1/p" "$path" 2>/dev/null | head -n 1
}

ledger_is_authoritative() {
  [[ -n "$LEDGER_PATH" && -f "$LEDGER_PATH" ]] || return 1
  local ledger_run ledger_netns ledger_pid ledger_owned ledger_empty
  ledger_run="$(ledger_field LEDGER_RUN_ID "$LEDGER_PATH")"
  ledger_netns="$(ledger_field LEDGER_NETNS_ID "$LEDGER_PATH")"
  ledger_pid="$(ledger_field LEDGER_OWNER_PID "$LEDGER_PATH")"
  ledger_owned="$(ledger_field LEDGER_OWNED_MUTATION "$LEDGER_PATH")"
  ledger_empty="$(ledger_field LEDGER_ACQUIRED_EMPTY "$LEDGER_PATH")"
  [[ "$ledger_run" == "$RUN_ID" ]] || return 1
  [[ "$ledger_netns" == "$NETNS_ID" ]] || return 1
  [[ "$ledger_pid" == "$$" ]] || return 1
  [[ "$ledger_owned" == "1" ]] || return 1
  [[ "$ledger_empty" == "1" ]] || return 1
  return 0
}

ownership_safe_cleanup() {
  # Disarm first so EXIT after a signal handler cannot double-run teardown.
  trap - EXIT INT TERM HUP
  CLEANUP_ARMED=0

  collect_diag "$RESULTS/pre-cleanup-diagnostics.txt" || true

  # Temp logs are always safe to remove; networking cleanup is gated below.
  if [[ -n "$lib_raw" ]]; then
    rm -f -- "$lib_raw"
  fi
  if [[ -n "$func_raw" ]]; then
    rm -f -- "$func_raw"
  fi

  if [[ "$OWNED_MUTATION" != "1" ]]; then
    collect_diag "$RESULTS/post-cleanup-diagnostics.txt" || true
    release_lock
    return 0
  fi

  if ! ledger_is_authoritative; then
    echo "ownership-safe cleanup: ledger not authoritative; leaving networking untouched" >&2
    OWNER_CHANGE_DETECTED=1
    collect_diag "$RESULTS/post-cleanup-diagnostics.txt" || true
    release_lock
    return 0
  fi

  local prod=""
  if prod="$(production_ferrum_process_detected)"; then
    echo "ownership-safe cleanup: production Ferrum owner detected; refusing networking teardown" >&2
    echo "$prod" >&2
    OWNER_CHANGE_DETECTED=1
    collect_diag "$RESULTS/post-cleanup-diagnostics.txt" || true
    release_lock
    return 0
  fi

  # Only delete objects present now that are part of the canonical contract we
  # acquired empty. Re-read presence at delete time; never delete from a stale
  # snapshot list alone (no snapshot-and-blind-delete).
  local key
  while IFS= read -r key; do
    [[ -n "$key" ]] || continue
    if ! ledger_is_authoritative; then
      echo "ownership-safe cleanup: owner changed during teardown; stopping" >&2
      OWNER_CHANGE_DETECTED=1
      break
    fi
    if prod="$(production_ferrum_process_detected)"; then
      echo "ownership-safe cleanup: production owner appeared during teardown; stopping" >&2
      echo "$prod" >&2
      OWNER_CHANGE_DETECTED=1
      break
    fi
    remove_owned_object "$key" || true
  done < <(list_canonical_host_udp_objects)

  rm -f -- "$LEDGER_PATH" 2>/dev/null || true
  OWNED_MUTATION=0
  collect_diag "$RESULTS/post-cleanup-diagnostics.txt" || true
  release_lock
}

# Temp-file-only cleanup used before ownership is acquired. Never touches net.
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
  local lock_dir
  lock_dir="${FERRUM_HOST_UDP_LIVE_LOCK_DIR:-/tmp/ferrum-host-udp-live-locks}"
  mkdir -p "$lock_dir"
  NETNS_ID="$(netns_identity)"
  if [[ -z "$NETNS_ID" ]]; then
    fail_required "unable to resolve /proc/self/ns/net for host-UDP live lock"
  fi
  # Encode ns identity into a filesystem-safe lock name.
  local safe_ns
  safe_ns="$(printf '%s' "$NETNS_ID" | tr -c 'A-Za-z0-9._-' '_')"
  LOCK_PATH="$lock_dir/netns-${safe_ns}.lock"
  LOCK_FD=9
  eval "exec ${LOCK_FD}>\"${LOCK_PATH}\""
  if ! flock -n "$LOCK_FD"; then
    fail_required "another ambient_host_udp_live owner already holds the netns lock at $LOCK_PATH"
  fi
}

write_ownership_ledger() {
  local acquired_empty="${1:-1}"
  RUN_ID="host-udp-live-$$-$(date +%s)-${RANDOM}"
  LEDGER_PATH="$RESULTS/ownership-ledger-${RUN_ID}.env"
  cat >"$LEDGER_PATH" <<EOF
LEDGER_RUN_ID='${RUN_ID}'
LEDGER_OWNER_PID='$$'
LEDGER_NETNS_ID='${NETNS_ID}'
LEDGER_ACQUIRED_EMPTY='${acquired_empty}'
LEDGER_OWNED_MUTATION='${acquired_empty}'
LEDGER_IN_OUTER_NETNS='${IN_OUTER_NETNS}'
EOF
  if [[ "$acquired_empty" == "1" ]]; then
    OWNED_MUTATION=1
  else
    # Destructive-adopt runs must not claim ownership of pre-existing objects.
    OWNED_MUTATION=0
  fi
}

arm_ownership_cleanup() {
  CLEANUP_ARMED=1
  trap ownership_safe_cleanup EXIT
  # Handled signals must take the ownership-safe path, never an unarmed skip.
  trap 'ownership_safe_cleanup; exit 130' INT
  trap 'ownership_safe_cleanup; exit 143' TERM
  trap 'ownership_safe_cleanup; exit 129' HUP
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

# Temp cleanup only until ownership is acquired. Networking must stay untouched
# through every early SKIP / prerequisite failure.
trap early_temp_cleanup EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  if [[ "$LIVE_REQUIRED" == "1" || "$LIVE_REQUIRED" == "true" ]]; then
    fail_required "FERRUM_LIVE_TESTS_REQUIRED=1 requires root for ambient host-UDP live"
  fi
  echo "SKIP: not root"
  exit 0
fi

for bin in unshare nsenter ip iptables ip6tables iptables-save ip6tables-save timeout mktemp flock; do
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

# --- From here on we may refuse, but we still have not armed destructive cleanup.

if prod="$(production_ferrum_process_detected)"; then
  fail_required "refusing to mutate host networking: production Ferrum process detected (use a disposable outer netns). ${prod}"
fi

preexisting_at_lock=0
if canonical_state_present; then
  if [[ "$ALLOW_DESTRUCTIVE_ADOPT" == "1" || "$ALLOW_DESTRUCTIVE_ADOPT" == "true" ]]; then
    echo "::warning::FERRUM_HOST_UDP_LIVE_ALLOW_DESTRUCTIVE_ADOPT overrides pre-existing canonical refusal; cleanup will not claim or remove that state" >&2
    preexisting_at_lock=1
  else
    {
      echo "pre-existing canonical Ferrum host-UDP state:"
      list_canonical_host_udp_objects
    } >"$RESULTS/pre-existing-canonical-state.txt" || true
    fail_required "refusing to mutate host networking: pre-existing canonical Ferrum host-UDP state (chains/jumps/rules/routes). Set FERRUM_HOST_UDP_LIVE_ALLOW_DESTRUCTIVE_ADOPT=1 only for explicit destructive development."
  fi
fi

acquire_exclusive_lock

# TOCTOU: another owner may have raced between the empty check and the lock.
if canonical_state_present \
  && [[ "$ALLOW_DESTRUCTIVE_ADOPT" != "1" && "$ALLOW_DESTRUCTIVE_ADOPT" != "true" ]]; then
  release_lock
  fail_required "refusing to mutate host networking: canonical Ferrum host-UDP state appeared before ownership acquisition"
fi

if prod="$(production_ferrum_process_detected)"; then
  release_lock
  fail_required "refusing to mutate host networking: production Ferrum process detected after lock. ${prod}"
fi

# Ownership ledger is acquired immediately before first mutation, after every
# preflight and the verified-empty + exclusive-lock gate.
if [[ "$preexisting_at_lock" == "1" ]] || canonical_state_present; then
  write_ownership_ledger 0
else
  write_ownership_ledger 1
fi
arm_ownership_cleanup

collect_diag "$RESULTS/pre-run-diagnostics.txt"

echo "Running ambient host-UDP live-kernel lib tests via $LIB_BIN"
lib_raw="$(mktemp "${TMPDIR:-/tmp}/ferrum-host-udp-lib.XXXXXX")"
set +e
FERRUM_LIVE_TESTS_REQUIRED=1 \
  timeout --signal=KILL 180s \
  "$LIB_BIN" proxy::host_udp_capture_live_tests --ignored --nocapture --test-threads=1 \
  >"$lib_raw" 2>&1
lib_status=$?
set -e
redact <"$lib_raw" | tee "$RESULTS/lib-tests.log"
if [[ "$lib_status" -ne 0 ]]; then
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
func_status=$?
set -e
redact <"$func_raw" | tee "$RESULTS/functional-tests.log"
if [[ "$func_status" -ne 0 ]]; then
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

echo "ambient-host-udp-live: ok"
