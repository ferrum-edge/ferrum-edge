#!/usr/bin/env bash
# Run on a Docker-capable CI runner against a built or published default image.
# Usage: bash scripts/smoke_sqlite_volume.sh IMAGE
set -euo pipefail

if [[ $# -ne 1 || -z "$1" || "$1" == -* ]]; then
  echo "Usage: bash scripts/smoke_sqlite_volume.sh IMAGE" >&2
  exit 2
fi
image="$1"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/ferrum-sqlite-volume.XXXXXX")"
migrate=""
gateway=""

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    if [[ -n "$migrate" ]]; then docker logs "$migrate" >&2 || true; fi
    if [[ -n "$gateway" ]]; then docker logs "$gateway" >&2 || true; fi
  fi
  # Remove the borrower first, then the owner of the fresh anonymous volume.
  if [[ -n "$gateway" ]]; then docker rm -fv "$gateway" >/dev/null || true; fi
  if [[ -n "$migrate" ]]; then docker rm -fv "$migrate" >/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  echo "SQLite volume smoke failed: $*" >&2
  exit 1
}

# No --user override or permission repair: exercise the published image identity.
migrate="$(docker create --network none \
  --mount type=volume,destination=/data \
  -e FERRUM_MODE=migrate \
  -e FERRUM_DB_TYPE=sqlite \
  -e 'FERRUM_DB_URL=sqlite:////data/ferrum.db?mode=rwc' \
  "$image" run)"
runtime_user="$(docker inspect --format '{{.Config.User}}' "$migrate")"
case "$runtime_user" in
  65532:65532|nonroot:nonroot) ;;
  *) fail "expected default UID/GID 65532:65532, got $runtime_user" ;;
esac
docker start "$migrate" >/dev/null
deadline=$((SECONDS + 60))
while [[ "$(docker inspect --format '{{.State.Running}}' "$migrate")" == true ]]; do
  if (( SECONDS >= deadline )); then fail "migration timed out"; fi
  sleep 1
done
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$migrate")" == 0 ]] \
  || fail "migration exited unsuccessfully"
docker cp "$migrate:/data/ferrum.db" "$tmp/migrated.db"
[[ -s "$tmp/migrated.db" ]] || fail "migration did not create /data/ferrum.db"

# Share precisely the fresh volume initialized above, without mounting host data.
gateway="$(docker create --network none --volumes-from "$migrate" \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=sqlite \
  -e 'FERRUM_DB_URL=sqlite:////data/ferrum.db?mode=rwc' \
  -e FERRUM_ADMIN_JWT_SECRET=sqlite-volume-smoke-only-admin-secret-65532 \
  -e FERRUM_SHUTDOWN_DRAIN_SECONDS=0 \
  "$image" run)"

wait_for_gateway() {
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    [[ "$(docker inspect --format '{{.State.Running}}' "$gateway")" == true ]] \
      || fail "gateway exited before becoming ready"
    # Exec the built-in HTTP client in this container: no shell or curl required,
    # and no host-port race can accidentally probe a different gateway.
    if docker exec "$gateway" /app/ferrum-edge health --live >/dev/null 2>&1 \
      && docker exec "$gateway" /app/ferrum-edge health >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  fail "gateway did not pass /live and /health before timeout"
}

docker start "$gateway" >/dev/null
wait_for_gateway
docker restart --time 30 "$gateway" >/dev/null
wait_for_gateway
docker stop --time 30 "$gateway" >/dev/null
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$gateway")" == 0 ]] \
  || fail "gateway did not shut down cleanly"
# Read a stopped database, avoiding an inconsistent copy of an active WAL.
docker cp "$gateway:/data/ferrum.db" "$tmp/restarted.db"
[[ -s "$tmp/restarted.db" ]] || fail "database disappeared after restart"

python3 - "$tmp/migrated.db" "$tmp/restarted.db" <<'PY'
import sqlite3
import sys
from pathlib import Path


def migration_records(path):
    with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise SystemExit(f"SQLite integrity check failed: {path}")
        rows = db.execute(
            "SELECT version, name, applied_at, checksum, execution_time_ms "
            "FROM _ferrum_migrations ORDER BY version"
        ).fetchall()
        if not rows:
            raise SystemExit(f"No applied migrations in {path}")
        return rows


if migration_records(sys.argv[1]) != migration_records(sys.argv[2]):
    raise SystemExit("Original SQLite migration records did not persist across restart")
PY

echo "SQLite volume smoke passed for $image (default user $runtime_user)"
