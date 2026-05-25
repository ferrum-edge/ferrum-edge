#!/usr/bin/env bash
# Run cargo-llvm-cov across the deterministic test suites (lib + unit +
# integration) and emit HTML, LCOV, and stdout summary reports under
# target/llvm-cov/.
#
# The first run on a clean checkout may take 5-10 minutes because llvm-cov
# rebuilds instrumented artifacts in target/llvm-cov-target/. Later runs are
# incrementally faster.
#
# Usage:
#   scripts/coverage.sh                    # full default run
#   scripts/coverage.sh --open             # also open the HTML report
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
forward_args=()
while (($#)); do
  case "$1" in
    --open)
      open_report=true
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

echo "Coverage summary:"
cargo llvm-cov report \
  --ignore-filename-regex "${ignore_filename_regex}"

echo ""
echo "HTML report: ${html_report}"
echo "LCOV report: ${repo_root}/${lcov_report}"

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
