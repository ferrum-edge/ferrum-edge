#!/usr/bin/env bash
# Report the upstream status of each vendored, patched crate so that a fix
# merged upstream cannot sit unnoticed — once upstream ships, the vendor copy
# and its [patch.crates-io] entry should be retired (see each patch's docs).
#
# Run weekly by .github/workflows/dependency-audit.yml. Exits non-zero if any
# tracked upstream PR has MERGED (a retirement signal), so the scheduled run
# goes red and a maintainer follows the retirement checklist.
#
# Requires `gh` (GitHub CLI, auto-authenticated via GH_TOKEN in Actions) and
# `curl`. Safe to run locally if `gh auth status` is set up.
#
# SINGLE SOURCE OF TRUTH for tracked patches: keep the PATCHES array below in
# sync with the inventory table in docs/dependency-policy.md.
set -uo pipefail

# "<label>|<crate>|<vendored_version>|<gh_repo>|<pr_or_NONE>|<issue_or_NONE>|<docs_path>"
PATCHES=(
  "reqwest per-request connect_timeout|reqwest|0.13.3|seanmonstar/reqwest|3017|NONE|docs/upstream-reqwest-patches/001-per-request-connect-timeout/"
  "h3 frame-drain on QUIC close|h3|0.0.8|hyperium/h3|339|338|docs/upstream-h3-patches/001-recv-frame-drain-on-quic-close/"
  "h3 Extended CONNECT :protocol=websocket|h3|0.0.8|hyperium/h3|NONE|NONE|docs/upstream-h3-patches/002-extended-connect-websocket-protocol/"
  "h3 peek buffered trailers before FIN|h3|0.0.8|hyperium/h3|NONE|NONE|docs/upstream-h3-patches/003-peek-buffered-trailers-before-fin/"
  "tungstenite lossless raw takeover|tungstenite|0.29.0|snapview/tungstenite-rs|556|NONE|docs/upstream-tungstenite-patches/"
  "tungstenite distinct frame-limit origin|tungstenite|0.29.0|snapview/tungstenite-rs|NONE|NONE|docs/upstream-tungstenite-patches/"
  "tungstenite optional auto_pong|tungstenite|0.29.0|snapview/tungstenite-rs|NONE|NONE|docs/upstream-tungstenite-patches/003-optional-auto-pong/"
  "tokio-tungstenite lossless raw takeover|tokio-tungstenite|0.29.0|snapview/tokio-tungstenite|380|NONE|docs/upstream-tungstenite-patches/"
  "dimpl certificate chains and key zeroization|dimpl|0.6.1|algesten/dimpl|NONE|NONE|docs/upstream-dimpl-patches/001-certificate-chain-and-key-zeroization/"
)

retire_signal=0
query_failed=0
echo "## Vendored patch upstream status"
echo ""

for row in "${PATCHES[@]}"; do
  IFS='|' read -r label crate ver repo pr issue docs <<< "$row"
  echo "### ${label}"
  echo "- crate: \`${crate}\` (vendored ${ver}); docs: ${docs}"
  [ "$issue" != "NONE" ] && echo "- upstream issue: ${repo}#${issue}"

  # crates.io rejects requests without a descriptive User-Agent.
  latest="$(curl -fsSL -A "ferrum-edge-dependency-audit (github.com/ferrum-edge/ferrum-edge)" \
    "https://crates.io/api/v1/crates/${crate}" 2>/dev/null \
    | sed -nE 's/.*"max_stable_version":"([^"]+)".*/\1/p' | head -n1)"
  [ -n "${latest:-}" ] && echo "- crates.io latest stable: ${latest}"

  if [ "$pr" = "NONE" ]; then
    echo "- upstream PR: NOT YET FILED — deliberate fork; see the docs hand-off section and dependency-policy.md 'Deliberate fork policy and SLA'"
  else
    st="$(gh pr view "$pr" --repo "$repo" --json state --jq '.state' 2>/dev/null || echo "")"
    if [ -z "$st" ]; then
      echo "  ::warning::could not query upstream PR ${repo}#${pr} (network/auth/rate-limit?) — failing closed so a merged patch isn't missed."
      query_failed=1
    else
      echo "- upstream PR ${repo}#${pr}: state=${st}"
      if [ "$st" = "MERGED" ]; then
        echo "  ::warning::ACTION — ${crate} PR ${repo}#${pr} merged upstream. Retire the vendored copy per ${docs}."
        retire_signal=1
      elif [ "$st" = "CLOSED" ]; then
        echo "  ::warning::${crate} PR ${repo}#${pr} was CLOSED without merge — revisit the patch strategy (${docs})."
      fi
    fi
  fi
  echo ""
done

if [ "$retire_signal" -ne 0 ]; then
  echo "::error::One or more vendored patches merged upstream and should be retired. See docs/dependency-policy.md."
  exit 1
fi
if [ "$query_failed" -ne 0 ]; then
  echo "::error::One or more upstream PR statuses could not be queried; failing closed so a merged patch cannot slip through unseen. Re-run after confirming gh auth / network."
  exit 1
fi
echo "No vendored patch has merged upstream yet; nothing to retire."
