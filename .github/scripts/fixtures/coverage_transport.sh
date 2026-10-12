set -euo pipefail
# Each shard tar holds *.profraw plus the instrumented binaries with
# their executable bit intact (see the shard "Package coverage data"
# step), so cargo-llvm-cov can collect them as object files without a
# chmod. Preserve the existing sequential overwrite order for shared
# paths; do not assume binaries from separate runners are identical.
# Keep the compressed Actions ZIP on disk and stream its tar member
# into tar, avoiding a multi-GiB intermediate uncompressed tar write
# and reread per shard. The uploaded ZIP/tar and file set are unchanged.
# Only one compressed shard archive is staged at a time.
#
# Only the planner's shard list is downloaded. Leftover coverage-data-*
# artifacts from a prior attempt of the same run must not join the
# merge, and a skipped/missing planned shard must not green the gate.
fanin_started=$SECONDS
artifact_names="$(python3 .github/scripts/coverage_plan.py \
  --emit-artifact-names \
  --planned-shards "$PLANNED_SHARDS")"
test -n "$artifact_names"

# Resolve names only within this run, including all API pages. Reject
# missing, expired, or ambiguous planned artifacts before downloading.
gh api --paginate --slurp \
  "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/artifacts" \
  > coverage-artifacts.json

{
  echo "## Coverage artifact fan-in"
  echo ""
  echo "| Shard artifact | ZIP bytes | Tar bytes | Download seconds | Extract seconds |"
  echo "| --- | ---: | ---: | ---: | ---: |"
} >> "$GITHUB_STEP_SUMMARY"

while IFS= read -r artifact_name; do
  [ -z "$artifact_name" ] && continue
  artifact_id="$(jq -er --arg name "$artifact_name" '
    [.[].artifacts[] | select(.name == $name)]
    | if length == 1 and .[0].expired == false
      then .[0].id
      else error("expected exactly one non-expired planned artifact: " + $name)
      end
  ' coverage-artifacts.json)"
  [[ "$artifact_id" =~ ^[0-9]+$ ]]
  echo "downloading ${artifact_name}"
  rm -rf coverage-data
  mkdir -p coverage-data
  archive="coverage-data/artifact.zip"
  download_started=$SECONDS
  downloaded=false
  for attempt in 1 2; do
    if gh api \
      "repos/${GITHUB_REPOSITORY}/actions/artifacts/${artifact_id}/zip" \
      > "$archive"; then
      downloaded=true
      break
    fi
    if [ "$attempt" -lt 2 ]; then
      echo "::warning::artifact download for ${artifact_name} failed; retrying"
      sleep 5
    fi
  done
  if [ "$downloaded" != "true" ]; then
    echo "::error::artifact download failed for ${artifact_name}"
    exit 1
  fi

  download_seconds=$((SECONDS - download_started))
  extract_started=$SECONDS
  member="coverage-${artifact_name#coverage-data-}.tar"
  if [ "$(unzip -Z1 "$archive")" != "$member" ]; then
    echo "::error::expected exactly ${member} in ${artifact_name}"
    exit 1
  fi
  zip_bytes="$(stat -c '%s' "$archive")"
  # The validated ZIP has one member; its directory records the exact
  # expanded tar size without a second decompression pass.
  tar_bytes="$(unzip -l "$archive" | tail -n 1 | awk '{print $1}')"
  [[ "$tar_bytes" =~ ^[0-9]+$ ]]
  echo "streaming ${member} from ${archive} (${zip_bytes} ZIP bytes, ${tar_bytes} tar bytes)"
  # Drain any tar end padding so unzip always reaches its CRC check.
  # pipefail propagates corrupt ZIPs AND tar extraction failures.
  unzip -p "$archive" "$member" | { tar -xpf - && cat > /dev/null; }
  extract_seconds=$((SECONDS - extract_started))
  echo "| ${artifact_name} | ${zip_bytes} | ${tar_bytes} | ${download_seconds} | ${extract_seconds} |" >> "$GITHUB_STEP_SUMMARY"
  rm -rf coverage-data
done <<< "$artifact_names"

find target/llvm-cov-target -name '*.profraw' -print
test -n "$(find target/llvm-cov-target -name '*.profraw' -print -quit)"
echo "Fan-in wall time: $((SECONDS - fanin_started)) seconds." >> "$GITHUB_STEP_SUMMARY"
