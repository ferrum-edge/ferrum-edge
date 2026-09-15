#!/usr/bin/env bash
# Build the pinned reference revision and the candidate with one toolchain and
# the ci-release profile, then measure both in interleaved rounds on this host.
# See .github/scripts/h1_tls_post_comparison.py for the measurement contract.
set -euo pipefail

CONTRACT="tests/performance/multi_protocol/h1_tls_post_reference.json"
HARNESS_DIR="tests/performance/multi_protocol"
OUTPUT="$PWD/tests/performance/ci_results/h1-tls-post-comparison"
if [ -e "$OUTPUT" ]; then
  echo '::error::comparison output must be new; stale results cannot be reused'
  exit 1
fi
mkdir -p "$OUTPUT/candidate/target/ci-release" "$OUTPUT/reference/target/ci-release"

python3 .github/scripts/h1_tls_post_comparison.py self-test

CANDIDATE_SHA="$(git rev-parse HEAD)"
CONTRACT_REFERENCE_SHA="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reference"]["sha"])' "$CONTRACT")"
REFERENCE_SHA="${H1_REFERENCE_SHA:-$CONTRACT_REFERENCE_SHA}"
EVALUATE_FLAGS=()
if [ "$REFERENCE_SHA" != "$CONTRACT_REFERENCE_SHA" ]; then
  if [ "${GITHUB_EVENT_NAME:-}" != workflow_dispatch ]; then
    echo '::error::only a manual dispatch may override the contract reference SHA'
    exit 1
  fi
  echo "::notice::manual reference override: ${REFERENCE_SHA} (contract pins ${CONTRACT_REFERENCE_SHA}); the floor still applies but rolling history is keyed to the contract reference"
  EVALUATE_FLAGS+=(--allow-reference-override)
fi
if ! [[ "$REFERENCE_SHA" =~ ^[0-9a-f]{40}$ ]] || [ "$REFERENCE_SHA" = 0000000000000000000000000000000000000000 ]; then
  echo '::error::reference must be an immutable nonzero commit SHA'
  exit 1
fi
if [ "$REFERENCE_SHA" = "$CANDIDATE_SHA" ]; then
  echo '::error::reference and candidate are the same commit; nothing to compare'
  exit 1
fi
if ! git cat-file -e "${REFERENCE_SHA}^{commit}" 2>/dev/null; then
  git fetch --no-tags origin "$REFERENCE_SHA"
fi
git cat-file -e "${REFERENCE_SHA}^{commit}"

# Both revisions compile with the toolchain the candidate checkout resolves so
# compiler drift cannot masquerade as a source regression.
TOOLCHAIN="$(rustup show active-toolchain | awk '{print $1}')"
export RUSTUP_TOOLCHAIN="$TOOLCHAIN"
rustc -Vv > "$OUTPUT/rustc-version.txt"
cargo -Vv > "$OUTPUT/cargo-version.txt"
if command -v lscpu >/dev/null 2>&1; then
  lscpu --json > "$OUTPUT/cpu.json" || true
fi

echo "::group::Build candidate ${CANDIDATE_SHA} (ci-release)"
cargo build --profile ci-release --bin ferrum-edge --locked
cp target/ci-release/ferrum-edge "$OUTPUT/candidate/target/ci-release/ferrum-edge"
echo "::endgroup::"

echo "::group::Build benchmark harness from the candidate tree (release)"
(cd "$HARNESS_DIR" && cargo build --release --locked --bin proto_bench --bin proto_backend)
echo "::endgroup::"

WORK="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ferrum-h1-tls-post-comparison"
rm -rf "$WORK"
mkdir -p "$WORK"
cleanup() {
  git -c core.hooksPath=/dev/null worktree remove --force "$WORK/reference-source" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "::group::Build reference ${REFERENCE_SHA} (ci-release)"
git -c core.hooksPath=/dev/null worktree add --detach "$WORK/reference-source" "$REFERENCE_SHA"
# The reference gets its own target directory: it is compiled once per run and
# must not disturb the cached candidate artifacts.
(cd "$WORK/reference-source" && CARGO_TARGET_DIR="$WORK/reference-target" \
  cargo build --profile ci-release --bin ferrum-edge --locked)
cp "$WORK/reference-target/ci-release/ferrum-edge" "$OUTPUT/reference/target/ci-release/ferrum-edge"
echo "::endgroup::"

python3 .github/scripts/h1_tls_post_comparison.py run \
  --contract "$CONTRACT" \
  --output "$OUTPUT" \
  --harness-dir "$HARNESS_DIR" \
  --reference-sha "$REFERENCE_SHA" \
  --candidate-sha "$CANDIDATE_SHA"

# Binaries are large and reproducible from the recorded SHAs; keep the artifact small.
rm -rf "$OUTPUT/candidate" "$OUTPUT/reference"

python3 .github/scripts/h1_tls_post_comparison.py evaluate \
  --contract "$CONTRACT" \
  --output "$OUTPUT" \
  --history "${H1_HISTORY_FILE:-$OUTPUT/history.json}" \
  --trends-out "$OUTPUT/h1_tls_post_trends.json" \
  --report-out "$OUTPUT/report.json" \
  "${EVALUATE_FLAGS[@]+"${EVALUATE_FLAGS[@]}"}"
