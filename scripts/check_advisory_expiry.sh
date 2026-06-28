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

# Match every RUSTSEC id in the ignore list, in EITHER cargo-deny form:
#   table:  { id = "RUSTSEC-YYYY-NNNN", reason = "... [expires:YYYY-MM-DD]" }
#   string: "RUSTSEC-YYYY-NNNN"
# Comment lines are skipped. Each id must carry an [expires:] token, so a
# string-form ignore (which has nowhere to put one) is correctly rejected —
# that form would otherwise bypass the time-boxing control entirely.
while IFS= read -r line; do
  id="$(printf '%s' "$line" | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' | head -n1)"
  [ -z "$id" ] && continue
  # The [expires:] token MUST live INSIDE the table entry's `reason = "..."`
  # string value — never in a TOML comment, and never via the string-ignore
  # form ("RUSTSEC-...") which has no reason field. Extract the quoted reason
  # first, then look for the token only within it. This rejects both
  # `"RUSTSEC-..."` and `"RUSTSEC-...", # [expires:...]` (trailing comment),
  # which cargo-deny treats as an ignore with no time-boxed rationale.
  reason="$(printf '%s' "$line" | sed -nE 's/.*reason *= *"([^"]*)".*/\1/p')"
  exp="$(printf '%s' "$reason" | sed -nE 's/.*\[expires:([0-9]{4}-[0-9]{2}-[0-9]{2})\].*/\1/p')"
  if [ -z "$exp" ]; then
    echo "::error::deny.toml ignore '$id' has no [expires:YYYY-MM-DD] inside a table reason = \"...\" value (string-form and comment-only expiry are rejected; use { id = \"$id\", reason = \"... [expires:YYYY-MM-DD]\" })"
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
done < <(grep -E 'RUSTSEC-[0-9]{4}-[0-9]{4}' "$DENY_TOML" | grep -vE '^[[:space:]]*#' || true)

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "One or more advisory exceptions need re-review. See docs/dependency-policy.md."
  exit 1
fi
echo "All advisory exceptions carry a valid, unexpired [expires:] date."
