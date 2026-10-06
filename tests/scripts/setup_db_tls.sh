#!/usr/bin/env bash
# Convenience entrypoint; the implementation lives in scripts/setup_db_tls.sh.
set +x
set -euo pipefail
readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec bash "$REPO_ROOT/scripts/setup_db_tls.sh" "$@"
