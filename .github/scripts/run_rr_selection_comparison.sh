#!/usr/bin/env bash
# Build both revisions before interleaved measurement on one hosted runner.
set -euo pipefail

export RR_COMPARISON_ROOT="$PWD"
export RR_COMPARISON_OUTPUT="$PWD/tests/performance/ci_results/rr-comparison"
if [ -e "$RR_COMPARISON_OUTPUT" ]; then
  echo '::error::comparison output must be new; stale results cannot be reused'
  exit 1
fi
mkdir -p "$RR_COMPARISON_OUTPUT"
RR_CANDIDATE_SHA="$(git rev-parse HEAD)"
export RR_CANDIDATE_SHA
if [ -z "${RR_BASE_SHA:-}" ]; then
  if [ "${GITHUB_EVENT_NAME:-}" != workflow_dispatch ]; then
    echo '::error::this event must supply its baseline SHA'
    exit 1
  fi
  RR_BASE_SHA="$(git rev-parse HEAD^)"
fi
if ! [[ "$RR_BASE_SHA" =~ ^[0-9a-f]{40}$ ]] || [ "$RR_BASE_SHA" = 0000000000000000000000000000000000000000 ]; then
  echo '::error::baseline must be an immutable nonzero commit SHA'
  exit 1
fi
export RR_BASE_SHA
git cat-file -e "$RR_BASE_SHA^{commit}"
RR_COMPARISON_WORK="$(mktemp -d "$RUNNER_TEMP/rr-selection.XXXXXX")"
export RR_COMPARISON_WORK
git -c core.hooksPath=/dev/null worktree add --detach "$RR_COMPARISON_WORK/baseline-source" "$RR_BASE_SHA"
# The only baseline overlay is the candidate measurement harness.
cp tests/performance/mesh/benches/rr_selection.rs "$RR_COMPARISON_WORK/baseline-source/tests/performance/mesh/benches/rr_selection.rs"
export CARGO_TARGET_DIR="$PWD/tests/performance/mesh/target"
for role in candidate baseline; do
  export RR_COMPARISON_ROLE="$role"
  if [ "$role" = candidate ]; then
    cd "$RR_COMPARISON_ROOT"
  else
    cd "$RR_COMPARISON_WORK/baseline-source"
  fi
  /usr/bin/time --format='%e' --output="$RR_COMPARISON_OUTPUT/$role-compile.time" \
    cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench rr_selection --no-run --locked --message-format=json \
    > "$RR_COMPARISON_OUTPUT/$role-compile.jsonl"
  cd "$RR_COMPARISON_ROOT"
  python3 .github/scripts/run_rr_selection_comparison.py record-build
done

for round in 1 2 3; do
  export RR_COMPARISON_ROUND="$round"
  if [ "$round" = 2 ]; then
    order='candidate baseline'
  else
    order='baseline candidate'
  fi
  for role in $order; do
    export RR_COMPARISON_ROLE="$role"
    export FERRUM_RR_CRITERION_ROOT="$RR_COMPARISON_OUTPUT/$role-$round"
    if [ "$role" = baseline ]; then
      "$RR_COMPARISON_WORK/baseline" --bench --noplot rr_selection/2_targets > "$RR_COMPARISON_OUTPUT/$role-$round.log" 2>&1
    else
      "$RR_COMPARISON_WORK/candidate" --bench --noplot rr_selection/2_targets > "$RR_COMPARISON_OUTPUT/$role-$round.log" 2>&1
    fi
    python3 .github/scripts/run_rr_selection_comparison.py record-round
  done
done
python3 .github/scripts/verify_rr_selection_benchmark.py --criterion-root "$RR_COMPARISON_OUTPUT"
