#!/usr/bin/env bash
set -euo pipefail

# setup_db_tls.sh — Generate TLS certificates and start PostgreSQL/MySQL containers for TLS testing.
#
# Usage:
#   ./setup_db_tls.sh [CERT_DIR]        Start containers (default cert dir: /tmp/ferrum-db-tls-certs)
#   ./setup_db_tls.sh --cleanup          Stop and remove containers
#   ./setup_db_tls.sh --help             Show this help message

readonly PG_CONTAINER="ferrum-test-pg-tls"
readonly MYSQL_CONTAINER="ferrum-test-mysql-tls"
readonly PG_PORT=15432
readonly MYSQL_PORT=13306
readonly DB_NAME="ferrum"
readonly DB_USER="ferrum"
readonly DB_PASSWORD="test-password"
readonly HEALTH_TIMEOUT=120  # seconds

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
err() { log "ERROR: $*" >&2; }
die() { err "$@"; exit 1; }

usage() {
    sed -n '3,7s/^# \?//p' "$0"
    exit 0
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    log "Stopping and removing containers..."
    for name in "$PG_CONTAINER" "$MYSQL_CONTAINER"; do
        if docker inspect "$name" &>/dev/null; then
            docker rm -f "$name" >/dev/null 2>&1 && log "Removed $name"
        else
            log "$name not found, skipping"
        fi
    done
    log "Cleanup complete."
}

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

generate_certs() {
    local cert_dir="$1"
    mkdir -p "$cert_dir"

    log "Generating certificates in $cert_dir ..."

    # --- CA ---
    openssl genrsa -out "$cert_dir/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days 3650 -key "$cert_dir/ca.key" \
        -out "$cert_dir/ca.crt" -subj "/CN=Ferrum Test CA" 2>/dev/null

    # --- PostgreSQL server cert ---
    local pg_ext
    pg_ext=$(mktemp)
    cat > "$pg_ext" <<EXTEOF
[v3_req]
subjectAltName = DNS:localhost,DNS:postgres-tls,IP:127.0.0.1
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXTEOF

    openssl genrsa -out "$cert_dir/pg-server.key" 2048 2>/dev/null
    openssl req -new -key "$cert_dir/pg-server.key" \
        -out "$cert_dir/pg-server.csr" -subj "/CN=postgres-tls" 2>/dev/null
    openssl x509 -req -in "$cert_dir/pg-server.csr" -CA "$cert_dir/ca.crt" \
        -CAkey "$cert_dir/ca.key" -CAcreateserial -days 3650 \
        -extensions v3_req -extfile "$pg_ext" \
        -out "$cert_dir/pg-server.crt" 2>/dev/null
    rm -f "$pg_ext" "$cert_dir/pg-server.csr"

    # --- MySQL server cert ---
    local mysql_ext
    mysql_ext=$(mktemp)
    cat > "$mysql_ext" <<EXTEOF
[v3_req]
subjectAltName = DNS:localhost,DNS:mysql-tls,IP:127.0.0.1
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXTEOF

    openssl genrsa -out "$cert_dir/mysql-server.key" 2048 2>/dev/null
    openssl req -new -key "$cert_dir/mysql-server.key" \
        -out "$cert_dir/mysql-server.csr" -subj "/CN=mysql-tls" 2>/dev/null
    openssl x509 -req -in "$cert_dir/mysql-server.csr" -CA "$cert_dir/ca.crt" \
        -CAkey "$cert_dir/ca.key" -CAcreateserial -days 3650 \
        -extensions v3_req -extfile "$mysql_ext" \
        -out "$cert_dir/mysql-server.crt" 2>/dev/null
    rm -f "$mysql_ext" "$cert_dir/mysql-server.csr"

    # --- Client cert (for mTLS) ---
    local client_ext
    client_ext=$(mktemp)
    cat > "$client_ext" <<EXTEOF
[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EXTEOF

    openssl genrsa -out "$cert_dir/client.key" 2048 2>/dev/null
    openssl req -new -key "$cert_dir/client.key" \
        -out "$cert_dir/client.csr" -subj "/CN=$DB_USER" 2>/dev/null
    openssl x509 -req -in "$cert_dir/client.csr" -CA "$cert_dir/ca.crt" \
        -CAkey "$cert_dir/ca.key" -CAcreateserial -days 3650 \
        -extensions v3_req -extfile "$client_ext" \
        -out "$cert_dir/client.crt" 2>/dev/null
    rm -f "$client_ext" "$cert_dir/client.csr" "$cert_dir/ca.srl"

    # PostgreSQL requires the server key to have restrictive permissions.
    # The postgres:16 image runs as uid 999 (postgres user).
    # We copy the key with correct ownership in a post-start step.
    chmod 600 "$cert_dir/pg-server.key"
    # MySQL requires the server key to be readable by the mysql process.
    chmod 644 "$cert_dir/mysql-server.key" "$cert_dir/mysql-server.crt"
    # Make all certs readable for Docker volume mounts
    chmod 644 "$cert_dir/ca.crt" "$cert_dir/pg-server.crt" "$cert_dir/client.crt"
    chmod 600 "$cert_dir/client.key"

    log "Certificates generated successfully."
}

# ---------------------------------------------------------------------------
# Container startup
# ---------------------------------------------------------------------------

start_postgres() {
    local cert_dir="$1"

    if docker inspect "$PG_CONTAINER" &>/dev/null; then
        log "Container $PG_CONTAINER already exists, removing..."
        docker rm -f "$PG_CONTAINER" >/dev/null
    fi

    log "Starting PostgreSQL 16 container ($PG_CONTAINER) on port $PG_PORT ..."

    # Mount the cert directory and use an init script to fix permissions.
    # PostgreSQL refuses to start if the key file is group/world-readable,
    # and Docker bind mounts (especially on macOS) may not preserve permissions.
    docker run -d \
        --name "$PG_CONTAINER" \
        -p "${PG_PORT}:5432" \
        -e POSTGRES_DB="$DB_NAME" \
        -e POSTGRES_USER="$DB_USER" \
        -e POSTGRES_PASSWORD="$DB_PASSWORD" \
        -v "$cert_dir:/certs-src:ro" \
        --entrypoint sh \
        postgres:16 \
        -c '
            cp /certs-src/pg-server.crt /var/lib/postgresql/server.crt &&
            cp /certs-src/pg-server.key /var/lib/postgresql/server.key &&
            cp /certs-src/ca.crt /var/lib/postgresql/ca.crt &&
            chown postgres:postgres /var/lib/postgresql/server.* /var/lib/postgresql/ca.crt &&
            chmod 600 /var/lib/postgresql/server.key &&
            chmod 644 /var/lib/postgresql/server.crt /var/lib/postgresql/ca.crt &&
            exec docker-entrypoint.sh postgres \
                -c ssl=on \
                -c ssl_cert_file=/var/lib/postgresql/server.crt \
                -c ssl_key_file=/var/lib/postgresql/server.key \
                -c ssl_ca_file=/var/lib/postgresql/ca.crt
        ' >/dev/null

    log "PostgreSQL container started."
}

start_mysql() {
    local cert_dir="$1"

    if docker inspect "$MYSQL_CONTAINER" &>/dev/null; then
        log "Container $MYSQL_CONTAINER already exists, removing..."
        docker rm -f "$MYSQL_CONTAINER" >/dev/null
    fi

    log "Starting MySQL 8 container ($MYSQL_CONTAINER) on port $MYSQL_PORT ..."

    # MySQL needs the cert directory mounted and the my.cnf to reference them.
    # We pass TLS flags via --require-secure-transport and server-side cert options.
    docker run -d \
        --name "$MYSQL_CONTAINER" \
        -p "${MYSQL_PORT}:3306" \
        -e MYSQL_DATABASE="$DB_NAME" \
        -e MYSQL_USER="$DB_USER" \
        -e MYSQL_PASSWORD="$DB_PASSWORD" \
        -e MYSQL_ROOT_PASSWORD="$DB_PASSWORD" \
        -v "$cert_dir/mysql-server.crt:/etc/mysql/ssl/server-cert.pem:ro" \
        -v "$cert_dir/mysql-server.key:/etc/mysql/ssl/server-key.pem:ro" \
        -v "$cert_dir/ca.crt:/etc/mysql/ssl/ca.pem:ro" \
        mysql:8 \
        --require-secure-transport=ON \
        --ssl-cert=/etc/mysql/ssl/server-cert.pem \
        --ssl-key=/etc/mysql/ssl/server-key.pem \
        --ssl-ca=/etc/mysql/ssl/ca.pem \
        >/dev/null

    log "MySQL container started."
}

# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

wait_for_healthy() {
    local container="$1"
    local check_cmd="$2"
    local elapsed=0

    log "Waiting for $container to become healthy (timeout: ${HEALTH_TIMEOUT}s) ..."

    while (( elapsed < HEALTH_TIMEOUT )); do
        if docker exec "$container" sh -c "$check_cmd" &>/dev/null; then
            log "$container is ready (${elapsed}s)."
            return 0
        fi
        sleep 2
        (( elapsed += 2 ))
    done

    err "$container did not become healthy within ${HEALTH_TIMEOUT}s."
    log "Container logs:"
    docker logs --tail 30 "$container" >&2
    return 1
}

wait_for_containers() {
    local pg_ok=0
    local mysql_ok=0

    wait_for_healthy "$PG_CONTAINER" \
        "pg_isready -U $DB_USER -d $DB_NAME" || pg_ok=1

    wait_for_healthy "$MYSQL_CONTAINER" \
        "mysqladmin ping -u root -p$DB_PASSWORD" || mysql_ok=1

    if (( pg_ok != 0 || mysql_ok != 0 )); then
        die "One or more containers failed to start. Run '$0 --cleanup' to remove them."
    fi

    log "All containers are healthy and ready for testing."
    log ""
    log "Connection details:"
    log "  PostgreSQL: postgres://$DB_USER:$DB_PASSWORD@localhost:$PG_PORT/$DB_NAME?sslmode=verify-full"
    log "  MySQL:      mysql://$DB_USER:$DB_PASSWORD@localhost:$MYSQL_PORT/$DB_NAME"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    # Handle flags
    case "${1:-}" in
        --cleanup)
            cleanup
            exit 0
            ;;
        --help|-h)
            usage
            ;;
    esac

    # Ensure docker is available
    command -v docker >/dev/null 2>&1 || die "docker is not installed or not in PATH."
    command -v openssl >/dev/null 2>&1 || die "openssl is not installed or not in PATH."

    local cert_dir="${1:-/tmp/ferrum-db-tls-certs}"

    # Use absolute path
    cert_dir="$(cd "$(dirname "$cert_dir")" 2>/dev/null && pwd)/$(basename "$cert_dir")"

    generate_certs "$cert_dir"
    start_postgres "$cert_dir"
    start_mysql "$cert_dir"
    wait_for_containers

    log ""
    log "Certificates are in: $cert_dir"
    log "To tear down: $0 --cleanup"
}

main "$@"
