#!/usr/bin/env bash
# Paired plugin request-view comparison (issue #7207).
#
# Builds the candidate's `plugin_request_view` Criterion harness against the
# candidate revision AND against a baseline revision, then interleaves
# measurements of the two binaries on one hosted runner so both see the same
# machine. The harness uses only public API that both revisions provide; the
# one source overlay is the harness itself (plus its `[[bench]]` stanza when the
# baseline predates it).
#
# Inputs: REQUEST_VIEW_BASE_SHA (required, a full commit SHA that is an ancestor
# of HEAD), REQUEST_VIEW_ROUNDS (optional, 1-5, default 3),
# REQUEST_VIEW_EXPECTED_CANDIDATE (optional; when set, HEAD must be exactly
# this commit, so a pull request run measures its head and never the
# synthetic merge commit) and REQUEST_VIEW_EVENT_SHA (optional; recorded in
# provenance.json).
set -euo pipefail

BENCH_NAME=plugin_request_view
BENCH_REL="tests/performance/mesh/benches/${BENCH_NAME}.rs"
MANIFEST_REL=tests/performance/mesh/Cargo.toml
SUMMARIZER="$PWD/.github/scripts/summarize_plugin_request_view_comparison.py"

base_sha="${REQUEST_VIEW_BASE_SHA:-}"
rounds="${REQUEST_VIEW_ROUNDS:-3}"
if ! [[ "$base_sha" =~ ^[0-9a-f]{40}$ ]] || [ "$base_sha" = 0000000000000000000000000000000000000000 ]; then
  echo '::error::REQUEST_VIEW_BASE_SHA must be an immutable nonzero commit SHA'
  exit 1
fi
if ! [[ "$rounds" =~ ^[1-5]$ ]]; then
  echo '::error::REQUEST_VIEW_ROUNDS must be 1-5'
  exit 1
fi
git cat-file -e "${base_sha}^{commit}"
git merge-base --is-ancestor "$base_sha" HEAD
candidate_sha="$(git rev-parse HEAD)"
expected_candidate="${REQUEST_VIEW_EXPECTED_CANDIDATE:-}"
if [ -n "$expected_candidate" ] && [ "$candidate_sha" != "$expected_candidate" ]; then
  echo "::error::checked-out HEAD $candidate_sha is not the expected candidate $expected_candidate"
  exit 1
fi
event_sha="${REQUEST_VIEW_EVENT_SHA:-$candidate_sha}"

output="$PWD/tests/performance/ci_results/plugin-request-view"
if [ -e "$output" ]; then
  echo '::error::comparison output must be new; stale results cannot be reused'
  exit 1
fi
mkdir -p "$output"

# Both revisions compile at the SAME source path so the vendored path
# dependencies keep one Cargo identity and the second build reuses the first
# build's dependency artifacts. Each finished tree is moved aside, not reused.
work="${RUNNER_TEMP:?}/ferrum-request-view-comparison"
mkdir "$work"
source_dir="$work/source"
export CARGO_TARGET_DIR="$work/target"

rustc -Vv > "$output/rustc-version.txt"
cargo -Vv > "$output/cargo-version.txt"
lscpu --json > "$output/cpu.json" || true
printf '{"candidate": "%s", "baseline": "%s", "event_sha": "%s", "rounds": %s}\n' \
  "$candidate_sha" "$base_sha" "$event_sha" "$rounds" > "$output/provenance.json"

for role in candidate baseline; do
  revision="$candidate_sha"
  if [ "$role" = baseline ]; then
    revision="$base_sha"
  fi
  git -c core.hooksPath=/dev/null worktree add --detach "$source_dir" "$revision"
  cp "$BENCH_REL" "$source_dir/$BENCH_REL"
  if ! grep -q "^name = \"${BENCH_NAME}\"\$" "$source_dir/$MANIFEST_REL"; then
    printf '\n[[bench]]\nname = "%s"\nharness = false\n' "$BENCH_NAME" >> "$source_dir/$MANIFEST_REL"
  fi
  cargo bench --manifest-path "$source_dir/$MANIFEST_REL" --bench "$BENCH_NAME" \
    --no-run --locked --message-format=json > "$output/$role-build.jsonl"
  executable="$(python3 -I "$SUMMARIZER" executable "$output/$role-build.jsonl")"
  cp "$executable" "$work/$role"
  git -c core.hooksPath=/dev/null worktree move "$source_dir" "$work/$role-source"
done

for round in $(seq 1 "$rounds"); do
  if [ $((round % 2)) -eq 0 ]; then
    order='candidate baseline'
  else
    order='baseline candidate'
  fi
  for role in $order; do
    echo "round $round: $role"
    FERRUM_REQUEST_VIEW_CRITERION_ROOT="$output/$role-$round" \
      "$work/$role" --bench --noplot > "$output/$role-$round.log" 2>&1
  done
done

python3 -I "$SUMMARIZER" summarize "$output" --rounds "$rounds" \
  --candidate "$candidate_sha" --baseline "$base_sha" \
  --json "$output/comparison.json" > "$output/summary.md"
cat "$output/summary.md"
