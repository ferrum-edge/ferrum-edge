#!/usr/bin/env bash
# Fail if any [advisories.ignore] OR [licenses.exceptions] entry in deny.toml has
# passed its [expires:YYYY-MM-DD] date, or is missing one entirely.
#
# This is what makes an exception time-boxed rather than permanent: the weekly
# dependency-audit workflow and the per-PR ci.yml dependency-audit job both run
# this, so an expired exception turns the run red and forces a human to re-fix
# or consciously extend it.
#
# Token placement differs between the two lists because cargo-deny's schemas do:
#   * [advisories.ignore] entries accept a free-text `reason = "..."` field, so
#     the token MUST live inside that string.
#   * [licenses.exceptions] entries do NOT. cargo-deny 0.19.9 rejects any key
#     other than the crate spec plus `allow`
#     ("error[unexpected-keys]: found 1 unexpected keys, expected: [\"allow\"]"),
#     so there is nowhere in the value to put a rationale. The repo convention is
#     therefore a `#` comment carrying owner, rationale and token, either on the
#     line immediately preceding the entry or trailing the entry itself:
#         # owner: <name> - <rationale> [expires:YYYY-MM-DD]
#         { crate = "foo", allow = ["Bar-1.0"] },
#
# Usage: scripts/check_advisory_expiry.sh [path/to/deny.toml]
#        scripts/check_advisory_expiry.sh --self-test
# See docs/dependency-policy.md.
set -euo pipefail

if [ "${1:-}" = "--self-test" ]; then
  self_test_script="${BASH_SOURCE[0]}"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  st_fail=0

  # Assert that running this script over a fixture yields the expected exit code.
  # $1 = case name, $2 = expected exit code, $3 = deny.toml body.
  st_case() {
    local name="$1" want="$2" body="$3" got=0
    printf '%s' "$body" > "$tmpdir/deny.toml"
    bash "$self_test_script" "$tmpdir/deny.toml" > "$tmpdir/out.txt" 2>&1 || got=$?
    if [ "$got" -eq "$want" ]; then
      echo "self-test ok: $name (exit $got)"
    else
      echo "::error::self-test FAILED: $name expected exit $want, got $got"
      sed 's/^/    /' "$tmpdir/out.txt"
      st_fail=1
    fi
  }

  st_case "valid advisory ignore + valid license exception" 0 \
'[advisories]
ignore = [
    { id = "RUSTSEC-2099-0001", reason = "tracked upstream [expires:2099-12-31]" },
]

[licenses]
version = 2
allow = ["MIT"]
exceptions = [
    # owner: platform - vendored data license [expires:2099-12-31]
    { crate = "some-crate", allow = ["Bar-1.0"] },
]
'

  st_case "license exception with no [expires:] token" 1 \
'[licenses]
version = 2
exceptions = [
    { crate = "some-crate", allow = ["Bar-1.0"] },
]
'

  st_case "literal-string license exception with no [expires:] token" 1 \
'[licenses]
version = 2
exceptions = [
    { crate = '\''some-crate'\'', allow = ["Bar-1.0"] },
]
'

  st_case "license exception with a past [expires:] date" 1 \
'[licenses]
version = 2
exceptions = [
    # owner: platform - stale [expires:2000-01-01]
    { crate = "some-crate", allow = ["Bar-1.0"] },
]
'

  st_case "string-form advisory ignore (no reason field)" 1 \
'[advisories]
ignore = ["RUSTSEC-2099-0001"]
'

  st_case "empty exceptions array" 0 \
'[licenses]
version = 2
allow = ["MIT"]
exceptions = []
'

  st_case "absent exceptions block" 0 \
'[licenses]
version = 2
allow = ["MIT"]
'

  st_case "multi-line license exception entry" 0 \
'[licenses]
version = 2
exceptions = [
    # owner: platform - multi-line form [expires:2099-12-31]
    { crate = "some-crate", allow = [
        "Bar-1.0",
    ] },
]
'

  st_case "trailing-comment license exception" 0 \
'[licenses]
version = 2
exceptions = [
    { crate = "some-crate", allow = ["Bar-1.0"] }, # owner: p - r [expires:2099-12-31]
]
'

  st_case "second exception missing its own token" 1 \
'[licenses]
version = 2
exceptions = [
    # owner: platform - first [expires:2099-12-31]
    { crate = "a", allow = ["Bar-1.0"] },
    { crate = "b", allow = ["Bar-1.0"] },
]
'

  st_case "same-line second exception missing its own token" 1 \
'[licenses]
version = 2
exceptions = [
    # owner: platform - first [expires:2099-12-31]
    { crate = "a", allow = ["Bar-1.0"] }, { crate = '\''b'\'', allow = ["Bar-1.0"] },
]
'

  if [ "$st_fail" -ne 0 ]; then
    echo ""
    echo "check_advisory_expiry.sh self-test FAILED."
    exit 1
  fi
  echo "check_advisory_expiry.sh self-test passed."
  exit 0
fi

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

# ---------------------------------------------------------------------------
# [licenses.exceptions]
#
# cargo-deny 0.19.9 accepts no free-text field inside an exceptions entry, so the
# [expires:] token lives in a `#` comment on the line immediately preceding the
# entry (or trailing it). Emit one "<crate>\t<date-or-empty>" record per entry
# with awk, walking the `exceptions = [ ... ]` array inside [licenses] with
# bracket depth so both the single-line `{ ... }` and the multi-line `{`/`}`
# forms resolve. Comments are stripped before depth counting so an
# `[expires:...]` token can never be mistaken for array nesting.
# ---------------------------------------------------------------------------
license_entries="$(awk '
  function token(s) {
    if (match(s, /\[expires:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\]/))
      return substr(s, RSTART + 9, 10)
    return ""
  }
  BEGIN { in_lic = 0; in_exc = 0; depth = 0; pending = "" }
  {
    line = $0
    hash = index(line, "#")
    if (hash > 0) { code = substr(line, 1, hash - 1); comment = substr(line, hash) }
    else          { code = line;                      comment = "" }

    if (!in_exc && code ~ /^[[:space:]]*\[/) {
      in_lic = (code ~ /^[[:space:]]*\[licenses\]/) ? 1 : 0
      next
    }

    if (!in_exc) {
      if (!in_lic) next
      if (code !~ /^[[:space:]]*exceptions[[:space:]]*=[[:space:]]*\[/) next
      in_exc = 1; depth = 0; pending = ""
      sub(/^[^=]*=[[:space:]]*/, "", code)
    }

    t = token(comment)
    if (t != "") pending = t

    # An entry opens at its crate spec key. Consume the pending token so a later
    # entry cannot inherit an earlier entry comment.
    # TOML permits several entries on one line. Check each of them; the
    # first entry must not hide a later exception without its own token.
    remaining = code
    while (match(remaining, /(crate|name)[[:space:]]*=[[:space:]]*("[^"]*"|\047[^\047]*\047)/)) {
      spec = substr(remaining, RSTART, RLENGTH)
      remaining = substr(remaining, RSTART + RLENGTH)
      sub(/^[^=]*=[[:space:]]*/, "", spec)
      spec = substr(spec, 2, length(spec) - 2)
      printf "%s\t%s\n", spec, pending
      pending = ""
    }

    n = split(code, ch, "")
    for (i = 1; i <= n; i++) {
      if (ch[i] == "[") depth++
      else if (ch[i] == "]") { depth--; if (depth <= 0) { in_exc = 0; in_lic = 0; break } }
    }
  }
' "$DENY_TOML")"

while IFS=$'\t' read -r crate exp; do
  [ -z "$crate" ] && continue
  if [ -z "$exp" ]; then
    echo "::error::deny.toml license exception '$crate' has no [expires:YYYY-MM-DD] token (cargo-deny rejects a reason field here, so put it in a comment on the preceding line: # owner: <name> - <rationale> [expires:YYYY-MM-DD])"
    fail=1
    continue
  fi
  exp_cmp="${exp//-/}"
  if [ "$exp_cmp" -lt "$today_cmp" ]; then
    echo "::error::deny.toml license exception '$crate' EXPIRED on $exp (today $today) - drop the exception or consciously extend the date"
    fail=1
  else
    echo "ok: license exception $crate valid through $exp"
  fi
done <<< "$license_entries"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "One or more advisory or license exceptions need re-review. See docs/dependency-policy.md."
  exit 1
fi
echo "All advisory and license exceptions carry a valid, unexpired [expires:] date."
