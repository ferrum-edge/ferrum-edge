#!/usr/bin/env bash
# Fail if any [advisories.ignore] entry in deny.toml has passed its
# [expires:YYYY-MM-DD] date, or is missing one entirely.
#
# This is what makes a security exception time-boxed rather than permanent: the
# weekly dependency-audit workflow runs this, so an expired ignore turns the
# scheduled run red and forces a human to re-fix or consciously extend it.
#
# Usage: scripts/check_advisory_expiry.sh [path/to/deny.toml]
# See docs/dependency-policy.md.
set -euo pipefail

DENY_TOML="${1:-deny.toml}"

if [ ! -f "$DENY_TOML" ]; then
  echo "::error::deny.toml not found at '$DENY_TOML'"
  exit 1
fi

today="$(date -u +%Y-%m-%d)"
today_cmp="${today//-/}"
fail=0

# Each ignore is a single line: { id = "RUSTSEC-...", reason = "... [expires:YYYY-MM-DD]" }
while IFS= read -r line; do
  id="$(printf '%s' "$line" | sed -nE 's/.*id = "([^"]+)".*/\1/p')"
  exp="$(printf '%s' "$line" | sed -nE 's/.*\[expires:([0-9]{4}-[0-9]{2}-[0-9]{2})\].*/\1/p')"
  [ -z "$id" ] && continue
  if [ -z "$exp" ]; then
    echo "::error::deny.toml ignore '$id' is missing an [expires:YYYY-MM-DD] token"
    fail=1
    continue
  fi
  exp_cmp="${exp//-/}"
  if [ "$exp_cmp" -lt "$today_cmp" ]; then
    echo "::error::deny.toml ignore '$id' EXPIRED on $exp (today $today) — re-fix the advisory or consciously extend the date"
    fail=1
  else
    echo "ok: $id valid through $exp"
  fi
done < <(grep -E 'id = "RUSTSEC' "$DENY_TOML" || true)

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "One or more advisory exceptions need re-review. See docs/dependency-policy.md."
  exit 1
fi
echo "All advisory exceptions carry a valid, unexpired [expires:] date."
