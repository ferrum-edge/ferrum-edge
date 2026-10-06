#!/usr/bin/env bash
# Hosted check for the disposable Compose fixtures: Mongo stays out of default
# startup and refuses a missing password, SQL ports bind loopback only, SQL
# requires TLS, and generated passwords never reach argv, Docker metadata,
# healthcheck output, or container logs. Secrets are compared with bash
# pattern matching only, so the check itself never puts one on argv.
set +x
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true ]]; then
    echo "Run only on a disposable hosted runner." >&2
    exit 1
fi

readonly SQL_DIR="${RUNNER_TEMP:?}/compose-fixture-check/sql"
readonly PG=ferrum-test-pg-tls MYSQL=ferrum-test-mysql-tls
readonly PG_CONN="host=localhost user=ferrum dbname=ferrum connect_timeout=3"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }
compose() {
    docker compose --env-file /dev/null -p ferrum-fixture-check -f docker-compose.yml "$@"
}
pg_sql() { # $1 = extra libpq settings, $2 = query; the password is read inside the container.
    docker exec -e CONN="$PG_CONN $1" -e QUERY="$2" "$PG" sh -c \
        'PGPASSWORD="$(cat /run/secrets/pg-password)" psql "$CONN" -Atqc "$QUERY"' 2>&1
}
mysql_sql() { # $1 = extra client option (or --batch), $2 = query
    docker exec "$MYSQL" mysql --defaults-extra-file=/run/secrets/mysql-client.cnf "$1" \
        --skip-column-names -e "$2" 2>&1
}
cleanup() {
    compose --profile mongodb down --volumes >/dev/null 2>&1 || true
    if [[ -f "$SQL_DIR/.fixture-owned" ]]; then
        bash scripts/setup_db_tls.sh --cleanup "$SQL_DIR" >/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 1' TERM INT

# Placeholders satisfy unrelated `:?` interpolation guards; they are not secrets.
export FERRUM_ADMIN_JWT_SECRET=compose-fixture-check-placeholder-admin-secret
export POSTGRES_PASSWORD=compose-fixture-check-placeholder-postgres
export FERRUM_CP_DP_GRPC_JWT_SECRET=compose-fixture-check-placeholder-grpc-secret
unset MONGO_PASSWORD COMPOSE_PROFILES

# --- Mongo profile boundary ---------------------------------------------------
services="$(compose config --services)"
if grep -qx -e mongodb -e ferrum-mongodb <<<"$services"; then
    fail "Mongo is part of default startup"
fi
for value in "" short-password "contains/a/reserved:character@0123456789"; do
    export MONGO_PASSWORD="$value"
    output="$(compose --profile mongodb run --rm --no-deps -T mongodb </dev/null 2>&1)" \
        && fail "Mongo started with an invalid password"
    [[ "$output" == *"Set MONGO_PASSWORD"* ]] || fail "Mongo guard did not reject the password"
done
MONGO_PASSWORD="$(openssl rand -hex 32)"
compose --profile mongodb up -d --wait --wait-timeout 120 mongodb >/dev/null 2>&1 \
    || fail "Mongo did not start with a valid password"
[[ "$(docker inspect --format '{{json .HostConfig.PortBindings}}' ferrum-mongodb-db)" == "{}" ]] \
    || fail "Mongo publishes a host port"
compose --profile mongodb down --volumes >/dev/null 2>&1
pass "Mongo is opt-in, refuses missing/short/reserved passwords, publishes no port"

# --- SQL TLS fixture ------------------------------------------------------------
bash scripts/setup_db_tls.sh "$SQL_DIR" >/dev/null
bad_modes="$(find "$SQL_DIR" \( -type d ! -perm 700 \) -o \( -type f ! -perm 600 \))"
[[ -z "$bad_modes" ]] || fail "Fixture material is not private: $bad_modes"
for name in "$PG" "$MYSQL"; do
    host_ips="$(docker inspect --format \
        '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}} {{end}}{{end}}' "$name")"
    [[ "$host_ips" == "127.0.0.1 " ]] || fail "$name publishes on '$host_ips'"
done
exposed="$(ss -Hltn | awk '$4 ~ /:(15432|13306)$/ && $4 !~ /^127\.0\.0\.1:/')"
[[ -z "$exposed" ]] || fail "SQL fixture listens beyond loopback: $exposed"
pass "SQL ports bind 127.0.0.1 only; fixture files are 0600 in a 0700 directory"

[[ "$(pg_sql "sslmode=verify-full sslrootcert=/client/ca.crt" "SELECT 1")" == 1 ]] \
    || fail "Verified PostgreSQL TLS query failed"
output="$(pg_sql "sslmode=disable" "SELECT 1")" && fail "PostgreSQL accepted plaintext"
[[ "$output" == *"no encryption"* ]] || fail "PostgreSQL plaintext refusal was not the HBA rule"
[[ "$(mysql_sql --batch "SELECT 1")" == 1 ]] || fail "Verified MySQL TLS query failed"
output="$(mysql_sql --ssl-mode=DISABLED "SELECT 1")" && fail "MySQL accepted plaintext"
[[ "$output" == *"insecure transport"* ]] || fail "MySQL plaintext refusal was not secure transport"
pass "SQL accepts verified TLS and refuses plaintext"

# Hold one authenticated in-container client per database open while argv is sampled.
pg_sql "sslmode=verify-full sslrootcert=/client/ca.crt" "SELECT pg_sleep(30)" >/dev/null &
pg_pid=$!
mysql_sql --batch "SELECT SLEEP(30)" >/dev/null &
mysql_pid=$!
argv=""
for _ in $(seq 1 30); do
    argv="$(ps -eww -o args)"
    grep -Eq '^psql host=localhost .*pg_sleep\(30\)$' <<<"$argv" \
        && grep -Eq '^mysql --defaults-extra-file=.*SLEEP\(30\)$' <<<"$argv" && break
    argv=""
    sleep 0.5
done
[[ -n "$argv" ]] || fail "Live SQL clients were not observed within 15 seconds"
metadata="$(docker inspect "$PG" "$MYSQL")"
logs="$(docker logs "$PG" 2>&1; docker logs "$MYSQL" 2>&1)"
[[ "$metadata" == *'"Healthcheck"'* && "$metadata" == *'"Log"'* ]] \
    || fail "Healthcheck configuration or output is missing from inspect"
for secret_file in pg-password mysql-password mysql-root-password; do
    read -r secret < "$SQL_DIR/$secret_file"
    [[ ${#secret} -ge 32 ]] || fail "Generated $secret_file is too short"
    [[ "$argv" != *"$secret"* ]] || fail "$secret_file appears in process argv"
    [[ "$metadata" != *"$secret"* ]] || fail "$secret_file appears in inspect/healthcheck output"
    [[ "$logs" != *"$secret"* ]] || fail "$secret_file appears in container logs"
done
unset secret
kill "$pg_pid" "$mysql_pid" 2>/dev/null || true
wait "$pg_pid" "$mysql_pid" 2>/dev/null || true
pass "Generated SQL passwords are absent from argv, inspect, healthcheck output and logs"
