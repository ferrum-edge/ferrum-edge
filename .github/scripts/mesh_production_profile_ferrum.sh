#!/usr/bin/env bash
# Remote-only: canary first, then an explicitly requested full qualification.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'Ferrum symbol qualification requires GitHub Actions Linux x64' >&2
  exit 1
fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
  canary)
    [[ "$#" == 2 ]] || { echo 'usage: mesh_production_profile_ferrum.sh canary NEW_OUTPUT' >&2; exit 2; }
    timeout --signal=TERM --kill-after=10s 900s python3 "$script_dir/mesh_production_profile_ferrum.py" canary --output "$2"
    ;;
  qualify)
    [[ "$#" == 4 ]] || { echo 'usage: mesh_production_profile_ferrum.sh qualify REPOSITORY NEW_OUTPUT PASSED_CANARY_REPORT' >&2; exit 2; }
    timeout --signal=TERM --kill-after=10s 7900s python3 "$script_dir/mesh_production_profile_ferrum.py" qualify --repo "$2" --output "$3" --canary-report "$4"
    ;;
  *) echo 'expected canary or qualify action' >&2; exit 2 ;;
esac
