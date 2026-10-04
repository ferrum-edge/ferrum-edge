#!/usr/bin/env bash
# Retain the released manual entrypoint referenced by the five SQL TLS consumers.
# Hosted workflows call the audited scripts/ implementation directly.
set +x
set -euo pipefail
readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec bash "$REPO_ROOT/scripts/setup_db_tls.sh" "$@"
