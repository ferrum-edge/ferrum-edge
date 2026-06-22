#!/usr/bin/env bash
# Shared live-datapath assertion artifact helpers.
#
# Suites source this file and write one JSON document per run:
#   {
#     "schema_version": 1,
#     "suite": "...",
#     "commit": "...",
#     "platform_profile": "...",
#     "assertions": [...]
#   }
#
# Required GA assertions must be recorded as "pass" or "fail"; "skip" is
# represented so non-GA diagnostics can stay machine-readable, but contract
# gates should treat required skips as failures.

set -euo pipefail

ferrum_live_require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$1" >&2
    return 127
  }
}

ferrum_live_git_commit() {
  git -C "${FERRUM_LIVE_REPO_ROOT:-.}" rev-parse HEAD 2>/dev/null || printf 'unknown'
}

ferrum_live_assertions_init() {
  local output_file="${1:?output file is required}"
  local suite="${2:?suite is required}"
  local commit="${3:-$(ferrum_live_git_commit)}"
  local platform_profile="${4:-unknown}"

  ferrum_live_require_cmd python3
  mkdir -p "$(dirname "$output_file")"
  python3 - "$output_file" "$suite" "$commit" "$platform_profile" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "schema_version": 1,
    "suite": sys.argv[2],
    "commit": sys.argv[3],
    "platform_profile": sys.argv[4],
    "created_at": datetime.now(timezone.utc).isoformat(),
    "assertions": [],
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

ferrum_live_record_assertion() {
  local output_file="${1:?output file is required}"
  local assertion_id="${2:?assertion id is required}"
  local assertion_status="${3:?status is required}"
  local source_workload="${4:-}"
  local destination_workload="${5:-}"
  local observed_outcome="${6:-}"
  local observed_source_spiffe="${7:-}"
  local observed_destination_spiffe="${8:-}"
  local configuration_generation="${9:-}"
  local diagnostics_csv="${10:-}"

  case "$assertion_status" in
    pass|fail|skip) ;;
    *)
      printf 'invalid live assertion status for %s: %s\n' "$assertion_id" "$assertion_status" >&2
      return 2
      ;;
  esac

  ferrum_live_require_cmd python3
  python3 - "$output_file" "$assertion_id" "$assertion_status" "$source_workload" \
    "$destination_workload" "$observed_outcome" "$observed_source_spiffe" \
    "$observed_destination_spiffe" "$configuration_generation" "$diagnostics_csv" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
diagnostics = [item for item in sys.argv[10].split(",") if item]
payload.setdefault("assertions", []).append({
    "id": sys.argv[2],
    "status": sys.argv[3],
    "source_workload": sys.argv[4] or None,
    "destination_workload": sys.argv[5] or None,
    "observed_outcome": sys.argv[6] or None,
    "observed_source_spiffe_id": sys.argv[7] or None,
    "observed_destination_spiffe_id": sys.argv[8] or None,
    "configuration_generation": sys.argv[9] or None,
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "diagnostic_artifact_paths": diagnostics,
})
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

ferrum_live_assertions_require_all_passed() {
  local output_file="${1:?output file is required}"
  shift
  ferrum_live_require_cmd python3
  python3 - "$output_file" "$@" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
required = sys.argv[2:]
observed = {entry.get("id"): entry for entry in payload.get("assertions", [])}
missing = [assertion_id for assertion_id in required if assertion_id not in observed]
failed = [
    assertion_id
    for assertion_id in required
    if assertion_id in observed and observed[assertion_id].get("status") != "pass"
]
if missing or failed:
    if missing:
        print("missing live assertions: " + ", ".join(missing), file=sys.stderr)
    if failed:
        print("non-passing live assertions: " + ", ".join(failed), file=sys.stderr)
    sys.exit(1)
PY
}
