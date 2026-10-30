#!/usr/bin/env bash
# Build the reference and candidate revisions of the gRPC deadline A/B (#6904)
# with one toolchain and the ci-release profile, then measure both in
# alternating rounds on this host. See .github/scripts/grpc_deadline_comparison.py
# for the measurement contract.
#
# Both revisions default to the contract's pinned SHAs. A manual dispatch may
# override either (GRPC_AB_REFERENCE_SHA / GRPC_AB_CANDIDATE_SHA) to compare any
# two commits on one runner with the same workload.
set -euo pipefail

CONTRACT="tests/performance/multi_protocol/grpc_deadline_reference.json"
HARNESS_DIR="tests/performance/multi_protocol"
OUTPUT="$PWD/tests/performance/ci_results/grpc-deadline-comparison"
if [ -e "$OUTPUT" ]; then
  echo '::error::comparison output must be new; stale results cannot be reused'
  exit 1
fi
mkdir -p "$OUTPUT/candidate/target/ci-release" "$OUTPUT/reference/target/ci-release"

python3 -I .github/scripts/grpc_deadline_comparison.py self-test

contract_sha() {
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["sha"])' "$CONTRACT" "$1"
}
REFERENCE_SHA="${GRPC_AB_REFERENCE_SHA:-$(contract_sha reference)}"
CANDIDATE_SHA="${GRPC_AB_CANDIDATE_SHA:-$(contract_sha candidate)}"
for sha in "$REFERENCE_SHA" "$CANDIDATE_SHA"; do
  if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || [ "$sha" = 0000000000000000000000000000000000000000 ]; then
    echo '::error::reference and candidate must be immutable nonzero 40-hex commit SHAs'
    exit 1
  fi
  if ! git cat-file -e "${sha}^{commit}" 2>/dev/null; then
    git fetch --no-tags origin "$sha"
  fi
  git cat-file -e "${sha}^{commit}"
done
if [ "$REFERENCE_SHA" = "$CANDIDATE_SHA" ]; then
  echo '::error::reference and candidate are the same commit; nothing to compare'
  exit 1
fi
echo "Reference: ${REFERENCE_SHA}"
echo "Candidate: ${CANDIDATE_SHA}"

# Both revisions compile with the toolchain this checkout resolves so compiler
# drift cannot masquerade as a source difference.
TOOLCHAIN="$(rustup show active-toolchain | awk '{print $1}')"
export RUSTUP_TOOLCHAIN="$TOOLCHAIN"
rustc -Vv > "$OUTPUT/rustc-version.txt"
cargo -Vv > "$OUTPUT/cargo-version.txt"
if command -v lscpu >/dev/null 2>&1; then
  lscpu --json > "$OUTPUT/cpu.json" || true
fi

echo "::group::Build benchmark harness from this checkout (release)"
(cd "$HARNESS_DIR" && cargo build --release --locked --bin proto_bench --bin proto_backend)
echo "::endgroup::"

WORK="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/ferrum-grpc-deadline-comparison"
rm -rf "$WORK"
mkdir -p "$WORK"
cleanup() {
  git -c core.hooksPath=/dev/null worktree remove --force "$WORK/source" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# One worktree and one target directory for both revisions: adjacent revisions
# share almost every dependency artifact, so the second build is incremental.
git -c core.hooksPath=/dev/null worktree add --detach "$WORK/source" "$REFERENCE_SHA"

echo "::group::Build reference ${REFERENCE_SHA} (ci-release)"
(cd "$WORK/source" && CARGO_TARGET_DIR="$WORK/target" \
  cargo build --profile ci-release --bin ferrum-edge --locked)
cp "$WORK/target/ci-release/ferrum-edge" "$OUTPUT/reference/target/ci-release/ferrum-edge"
echo "::endgroup::"

echo "::group::Build candidate ${CANDIDATE_SHA} (ci-release)"
git -c core.hooksPath=/dev/null -C "$WORK/source" checkout --quiet --detach "$CANDIDATE_SHA"
(cd "$WORK/source" && CARGO_TARGET_DIR="$WORK/target" \
  cargo build --profile ci-release --bin ferrum-edge --locked)
cp "$WORK/target/ci-release/ferrum-edge" "$OUTPUT/candidate/target/ci-release/ferrum-edge"
echo "::endgroup::"

if cmp -s "$OUTPUT/reference/target/ci-release/ferrum-edge" "$OUTPUT/candidate/target/ci-release/ferrum-edge"; then
  echo '::error::reference and candidate binaries are identical; the comparison would measure nothing'
  exit 1
fi

python3 -I .github/scripts/grpc_deadline_comparison.py run \
  --contract "$CONTRACT" \
  --output "$OUTPUT" \
  --harness-dir "$HARNESS_DIR" \
  --reference-sha "$REFERENCE_SHA" \
  --candidate-sha "$CANDIDATE_SHA"

# Binaries are large and reproducible from the recorded SHAs; keep the artifact small.
rm -rf "$OUTPUT/candidate" "$OUTPUT/reference"

python3 -I .github/scripts/grpc_deadline_comparison.py evaluate \
  --contract "$CONTRACT" \
  --output "$OUTPUT" \
  --report-out "$OUTPUT/report.json"
