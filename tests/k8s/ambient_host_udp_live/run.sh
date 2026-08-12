#!/usr/bin/env bash
# Ambient host-network UDP live-kernel gate (#3705).
#
# Expects prebuilt lib and functional test binaries from the workflow (never
# builds here). Reuses the repository skip-or-fail contract:
# FERRUM_LIVE_TESTS_REQUIRED=1 turns unsupported runners into hard failures.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RESULTS="${FERRUM_HOST_UDP_LIVE_RESULTS:-$ROOT/target/ambient-host-udp-live}"
mkdir -p "$RESULTS"

LIVE_REQUIRED="${FERRUM_LIVE_TESTS_REQUIRED:-0}"
LIB_BIN="${FERRUM_HOST_UDP_LIB_TEST_BIN:?FERRUM_HOST_UDP_LIB_TEST_BIN must point at the lib test binary}"
FUNC_BIN="${FERRUM_HOST_UDP_FUNCTIONAL_TEST_BIN:?FERRUM_HOST_UDP_FUNCTIONAL_TEST_BIN must point at the functional test binary}"
lib_raw=""
func_raw=""

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
  } | redact >"$out"
}

cleanup_trap() {
  collect_diag "$RESULTS/pre-cleanup-diagnostics.txt" || true
  # Best-effort exact Ferrum-owned cleanup if a test left host state behind.
  iptables -t mangle -D PREROUTING -j FERRUM_MESH_UDP_HOST 2>/dev/null || true
  iptables -t mangle -D PREROUTING -j FERRUM_MESH_UDP_HOST_GUARD_A 2>/dev/null || true
  iptables -t mangle -D PREROUTING -j FERRUM_MESH_UDP_HOST_GUARD_B 2>/dev/null || true
  iptables -t mangle -F FERRUM_MESH_UDP_HOST 2>/dev/null || true
  iptables -t mangle -X FERRUM_MESH_UDP_HOST 2>/dev/null || true
  iptables -t mangle -F FERRUM_MESH_UDP_HOST_GUARD_A 2>/dev/null || true
  iptables -t mangle -X FERRUM_MESH_UDP_HOST_GUARD_A 2>/dev/null || true
  iptables -t mangle -F FERRUM_MESH_UDP_HOST_GUARD_B 2>/dev/null || true
  iptables -t mangle -X FERRUM_MESH_UDP_HOST_GUARD_B 2>/dev/null || true
  ip6tables -t mangle -D PREROUTING -j FERRUM_MESH_UDP_HOST 2>/dev/null || true
  ip6tables -t mangle -D PREROUTING -j FERRUM_MESH_UDP_HOST_GUARD_A 2>/dev/null || true
  ip6tables -t mangle -D PREROUTING -j FERRUM_MESH_UDP_HOST_GUARD_B 2>/dev/null || true
  ip6tables -t mangle -F FERRUM_MESH_UDP_HOST 2>/dev/null || true
  ip6tables -t mangle -X FERRUM_MESH_UDP_HOST 2>/dev/null || true
  ip6tables -t mangle -F FERRUM_MESH_UDP_HOST_GUARD_A 2>/dev/null || true
  ip6tables -t mangle -X FERRUM_MESH_UDP_HOST_GUARD_A 2>/dev/null || true
  ip6tables -t mangle -F FERRUM_MESH_UDP_HOST_GUARD_B 2>/dev/null || true
  ip6tables -t mangle -X FERRUM_MESH_UDP_HOST_GUARD_B 2>/dev/null || true
  ip rule del priority 101 lookup 33135 2>/dev/null || true
  ip -6 rule del priority 101 lookup 33135 2>/dev/null || true
  ip route del local 0.0.0.0/0 dev lo table 33135 2>/dev/null || true
  ip -6 route del local ::/0 dev lo table 33135 2>/dev/null || true
  collect_diag "$RESULTS/post-cleanup-diagnostics.txt" || true
  if [[ -n "$lib_raw" ]]; then
    rm -f -- "$lib_raw"
  fi
  if [[ -n "$func_raw" ]]; then
    rm -f -- "$func_raw"
  fi
}
trap cleanup_trap EXIT

fail_required() {
  echo "::error::$1" >&2
  exit 1
}

if [[ "$(id -u)" -ne 0 ]]; then
  if [[ "$LIVE_REQUIRED" == "1" || "$LIVE_REQUIRED" == "true" ]]; then
    fail_required "FERRUM_LIVE_TESTS_REQUIRED=1 requires root for ambient host-UDP live"
  fi
  echo "SKIP: not root"
  exit 0
fi

for bin in unshare nsenter ip iptables ip6tables iptables-save ip6tables-save timeout mktemp; do
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
