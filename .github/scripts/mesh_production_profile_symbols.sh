#!/usr/bin/env bash
# Remote-only anonymous registry reads. No image execution, build or Docker mutation.
# Usage: bash .github/scripts/mesh_production_profile_symbols.sh NEW_OUTPUT_DIRECTORY
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'symbol preflight requires GitHub Actions Linux x64' >&2
  exit 1
fi
if [[ "$#" != 1 ]]; then
  echo 'usage: mesh_production_profile_symbols.sh NEW_OUTPUT_DIRECTORY' >&2
  exit 2
fi
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Outer wall limit also covers a slow registry redirect, decompressor or ELF scan.
timeout --signal=TERM --kill-after=5s 960s \
  python3 "$script_dir/mesh_production_profile_symbols.py" --output "$1"
