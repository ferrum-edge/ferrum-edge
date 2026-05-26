#!/usr/bin/env bash
# Run cargo-llvm-cov across the deterministic test suites (lib + unit +
# integration) and emit HTML, LCOV, JSON, and stdout summary reports under
# target/llvm-cov/.
#
# The first run on a clean checkout may take 5-10 minutes because llvm-cov
# rebuilds instrumented artifacts in target/llvm-cov-target/. Later runs are
# incrementally faster.
#
# Usage:
#   scripts/coverage.sh                    # full default run
#   scripts/coverage.sh --open             # also open the HTML report
#   scripts/coverage.sh --functional       # also run curated functional gap tests
#   scripts/coverage.sh --functional-filter functional_udp_proxy
#                                          # run only specified filter(s), replacing defaults
#   scripts/coverage.sh -- plugins::cors   # narrow by test filter
#
# Install (one-time):
#   cargo install cargo-llvm-cov --locked
#   rustup component add llvm-tools-preview

set -euo pipefail

if ! command -v cargo-llvm-cov > /dev/null 2>&1; then
  echo "cargo-llvm-cov not installed." >&2
  echo "Run: cargo install cargo-llvm-cov --locked" >&2
  echo "And: rustup component add llvm-tools-preview" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

open_report=false
include_functional=false
functional_filters=()
forward_args=()
while (($#)); do
  case "$1" in
    --open)
      open_report=true
      shift
      ;;
    --functional | --with-functional)
      include_functional=true
      shift
      ;;
    --functional-filter)
      include_functional=true
      shift
      if [ "$#" -eq 0 ]; then
        echo "--functional-filter requires a filter value" >&2
        exit 1
      fi
      functional_filters+=("$1")
      shift
      ;;
    *)
      forward_args+=("$1")
      shift
      ;;
  esac
done

ignore_filename_regex='(vendor/|tests/|build\.rs|target/|custom_plugins/|ebpf/|proto/)'
report_dir="target/llvm-cov"
html_report="${repo_root}/${report_dir}/html/index.html"
lcov_report="target/llvm-cov/lcov.info"
json_report="target/llvm-cov/coverage.json"
gateway_bin_name="ferrum-edge"
if [[ "$(uname -s)" =~ ^(MINGW|MSYS|CYGWIN) ]]; then
  gateway_bin_name="ferrum-edge.exe"
fi
instrumented_gateway_bin="${repo_root}/target/llvm-cov-target/debug/${gateway_bin_name}"

run_coverage_target() {
  local target_flag="$1"
  local target_name="${2:-}"
  local cmd=(
    cargo llvm-cov --no-report
    "${target_flag}"
  )

  if [ -n "${target_name}" ]; then
    cmd+=("${target_name}")
  fi
  if [ "${#forward_args[@]}" -gt 0 ]; then
    cmd+=("${forward_args[@]}")
  fi

  "${cmd[@]}"
}

echo "Cleaning stale cargo-llvm-cov profile data..."
cargo llvm-cov clean --workspace

echo "Collecting lib coverage..."
run_coverage_target --lib

echo "Collecting unit test coverage..."
run_coverage_target --test unit_tests

echo "Collecting integration test coverage..."
run_coverage_target --test integration_tests

if "${include_functional}"; then
  echo "Building instrumented ferrum-edge binary for functional subprocess coverage..."
  # Force cargo to build the instrumented binary into target/llvm-cov-target/;
  # "version" is a cheap invocation that exits before the functional filters run.
  cargo llvm-cov run --no-report --bin ferrum-edge -- version
  if [ ! -x "${instrumented_gateway_bin}" ]; then
    echo "Instrumented gateway binary not found: ${instrumented_gateway_bin}" >&2
    exit 1
  fi

  if [ "${#functional_filters[@]}" -eq 0 ]; then
    # The default list prioritizes top gaps and includes the coverage-aware
    # TCP/UDP/Mongo/common-harness subprocess paths. Broad or custom filters can
    # still select legacy direct-kill tests that under-report child coverage.
    functional_filters=(
      functional_admin
      functional_database
      functional_file_mode
      functional_protocol_validation
      h3
      functional_tcp_proxy
      functional_udp_proxy
      functional_mongodb
    )
  fi

  echo "Collecting functional coverage for top gap filters..."
  for filter in "${functional_filters[@]}"; do
    echo "  functional_tests: ${filter}"
    FERRUM_EDGE_TEST_BIN="${instrumented_gateway_bin}" \
      cargo llvm-cov --no-report --test functional_tests -- \
      --ignored \
      --test-threads=1 \
      "${filter}"
  done
fi

echo "Writing HTML report..."
cargo llvm-cov report \
  --ignore-filename-regex "${ignore_filename_regex}" \
  --html \
  --output-dir "${report_dir}"

echo "Writing LCOV report..."
cargo llvm-cov report \
  --ignore-filename-regex "${ignore_filename_regex}" \
  --lcov \
  --output-path "${lcov_report}"

echo "Writing JSON summary..."
cargo llvm-cov report \
  --ignore-filename-regex "${ignore_filename_regex}" \
  --json \
  --summary-only \
  --output-path "${json_report}"

echo "Coverage summary:"
cargo llvm-cov report \
  --ignore-filename-regex "${ignore_filename_regex}"

echo ""
echo "HTML report: ${html_report}"
echo "LCOV report: ${repo_root}/${lcov_report}"
echo "JSON summary: ${repo_root}/${json_report}"

if "${open_report}"; then
  case "$(uname -s)" in
    Darwin) opener="open" ;;
    Linux) opener="xdg-open" ;;
    *)
      echo "No opener configured for OS: $(uname -s)" >&2
      exit 0
      ;;
  esac

  if command -v "${opener}" > /dev/null 2>&1; then
    "${opener}" "${html_report}"
  else
    echo "${opener} not found; open ${html_report} manually." >&2
  fi
fi
