#!/usr/bin/env bash
# Disposable SQL TLS fixtures; never use this stack for persistent data.
# Usage: setup_db_tls.sh [CERT_DIR] | --cleanup [CERT_DIR] | --help
set +x
set -euo pipefail
umask 077

readonly PG_CONTAINER="ferrum-test-pg-tls"
readonly MYSQL_CONTAINER="ferrum-test-mysql-tls"
readonly PROJECT="ferrum-db-tls-fixture"
readonly HEALTH_TIMEOUT=120
readonly REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
readonly COMPOSE_FILE="$REPO_ROOT/docker-compose.tls-test.yml"
CERTS_DIR=""

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

compose() {
    docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

check_container_ownership() {
    local name owner
    for name in "$PG_CONTAINER" "$MYSQL_CONTAINER"; do
        if docker inspect "$name" >/dev/null 2>&1; then
            owner=$(docker inspect --format \
                '{{ index .Config.Labels "org.ferrum.fixture.path" }}' "$name")
            [[ "$owner" == "$CERTS_DIR" ]] || die \
                "Refusing to remove $name owned by another fixture. Remove it deliberately first."
        fi
    done
}

cleanup() {
    [[ ! -L "$CERTS_DIR" && -f "$CERTS_DIR/.fixture-owned" \
        && ! -L "$CERTS_DIR/.fixture-owned" ]] || die \
        "No owned fixture directory at $CERTS_DIR; refusing cleanup."
    [[ "$(cat "$CERTS_DIR/.fixture-owned")" == "$PROJECT" ]] || die \
        "Unrecognized fixture ownership marker."
    check_container_ownership
    compose down --volumes >/dev/null
    rm -rf -- "$CERTS_DIR"
    log "Removed disposable containers, volumes, network, and private fixture directory."
}

on_exit() {
    local status=$?
    trap - EXIT
    if (( status != 0 )) && [[ -f "$CERTS_DIR/.fixture-owned" ]]; then
        # Do not print container logs: upstream initialization can include credentials.
        cleanup || true
    fi
    exit "$status"
}

generate_certs() {
    local name cn usage sans
    openssl genrsa -out "$CERTS_DIR/ca.key" 3072 2>/dev/null
    openssl req -new -x509 -days 7 -key "$CERTS_DIR/ca.key" \
        -out "$CERTS_DIR/ca.crt" -subj "/CN=Ferrum Disposable Fixture CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

    for name in pg-server mysql-server client; do
        case "$name" in
            pg-server)
                cn=postgres-tls; usage=serverAuth
                sans="DNS:localhost,DNS:postgres-tls,IP:127.0.0.1"
                ;;
            mysql-server)
                cn=mysql-tls; usage=serverAuth
                sans="DNS:localhost,DNS:mysql-tls,IP:127.0.0.1"
                ;;
            client)
                cn=ferrum; usage=clientAuth; sans=""
                ;;
        esac
        {
            printf '[v3_req]\nbasicConstraints=critical,CA:FALSE\n'
            printf 'keyUsage=digitalSignature,keyEncipherment\n'
            printf 'extendedKeyUsage=%s\n' "$usage"
            [[ -z "$sans" ]] || printf 'subjectAltName=%s\n' "$sans"
        } > "$CERTS_DIR/extensions.cnf"
        openssl genrsa -out "$CERTS_DIR/$name.key" 2048 2>/dev/null
        openssl req -new -key "$CERTS_DIR/$name.key" \
            -out "$CERTS_DIR/$name.csr" -subj "/CN=$cn" 2>/dev/null
        openssl x509 -req -in "$CERTS_DIR/$name.csr" -CA "$CERTS_DIR/ca.crt" \
            -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -days 7 \
            -extensions v3_req -extfile "$CERTS_DIR/extensions.cnf" \
            -out "$CERTS_DIR/$name.crt" 2>/dev/null
        rm -f "$CERTS_DIR/$name.csr"
    done
    rm -f "$CERTS_DIR/extensions.cnf" "$CERTS_DIR/ca.srl"

    mkdir "$CERTS_DIR/postgres" "$CERTS_DIR/mysql" "$CERTS_DIR/client"
    cp "$CERTS_DIR/pg-server.crt" "$CERTS_DIR/postgres/server.crt"
    cp "$CERTS_DIR/pg-server.key" "$CERTS_DIR/postgres/server.key"
    cp "$CERTS_DIR/mysql-server.crt" "$CERTS_DIR/mysql/server.crt"
    cp "$CERTS_DIR/mysql-server.key" "$CERTS_DIR/mysql/server.key"
    cp "$CERTS_DIR/ca.crt" "$CERTS_DIR/postgres/ca.crt"
    cp "$CERTS_DIR/ca.crt" "$CERTS_DIR/mysql/ca.crt"
    cp "$CERTS_DIR/ca.crt" "$CERTS_DIR/client/ca.crt"
    cp "$CERTS_DIR/client.crt" "$CERTS_DIR/client/client.crt"
    cp "$CERTS_DIR/client.key" "$CERTS_DIR/client/client.key"

    # Socket access is container-local. Every TCP connection requires TLS and a password.
    cat > "$CERTS_DIR/postgres/pg_hba.conf" <<'EOF'
local all all trust
hostssl all all all scram-sha-256
hostnossl all all all reject
EOF
    cat > "$CERTS_DIR/mysql/init.sql" <<'EOF'
GRANT CREATE, DROP, ALTER, INDEX, SELECT, INSERT, UPDATE, DELETE, REFERENCES,
CREATE TEMPORARY TABLES, LOCK TABLES, TRIGGER ON *.* TO 'ferrum'@'%';
EOF
    # Every host file stays 0600 and every directory 0700. The Compose root
    # entrypoints copy server material and chown by account name, not numeric UID.
}

generate_secrets() {
    local pg_password mysql_password root_password
    openssl rand -hex 32 > "$CERTS_DIR/pg-password"
    openssl rand -hex 32 > "$CERTS_DIR/mysql-password"
    openssl rand -hex 32 > "$CERTS_DIR/mysql-root-password"
    pg_password=$(< "$CERTS_DIR/pg-password")
    mysql_password=$(< "$CERTS_DIR/mysql-password")
    root_password=$(< "$CERTS_DIR/mysql-root-password")
    # Hexadecimal passwords need no URI, shell, or MySQL option-file escaping.
    {
        printf '[client]\nuser=ferrum\npassword=%s\n' "$mysql_password"
        printf 'host=localhost\nprotocol=TCP\ndatabase=ferrum\nconnect-timeout=3\n'
        printf 'ssl-mode=VERIFY_IDENTITY\nssl-ca=/client/ca.crt\n'
        printf 'ssl-cert=/client/client.crt\nssl-key=/client/client.key\n'
    } > "$CERTS_DIR/mysql-client.cnf"
    {
        printf '[client]\nuser=root\npassword=%s\nprotocol=SOCKET\n' "$root_password"
    } > "$CERTS_DIR/mysql-root.cnf"
    {
        printf 'PG_TLS_URL=postgres://ferrum:%s@localhost:15432/ferrum\n' "$pg_password"
        printf 'MYSQL_TLS_URL=mysql://ferrum:%s@localhost:13306/ferrum\n' "$mysql_password"
    } > "$CERTS_DIR/connections.env"
    unset pg_password mysql_password root_password
}

main() {
    local cleanup_requested=0 cert_dir name
    case "${1:-}" in
        --help|-h)
            log "Usage: $0 [CERT_DIR] | --cleanup [CERT_DIR]"
            log "Default: /tmp/ferrum-db-tls-certs (must not already exist at setup)."
            return
            ;;
        --cleanup)
            cleanup_requested=1
            shift
            ;;
    esac
    (( $# <= 1 )) || die "Too many arguments."
    command -v docker >/dev/null 2>&1 || die "docker is not installed."
    cert_dir="${1:-/tmp/ferrum-db-tls-certs}"
    CERTS_DIR="$(cd "$(dirname "$cert_dir")" && pwd)/$(basename "$cert_dir")"
    export CERTS_DIR
    if (( cleanup_requested != 0 )); then
        cleanup
        return
    fi
    command -v openssl >/dev/null 2>&1 || die "openssl is not installed."
    [[ ! -e "$CERTS_DIR" && ! -L "$CERTS_DIR" ]] || die \
        "Fixture directory already exists; clean up deliberately before generating fresh secrets."
    for name in "$PG_CONTAINER" "$MYSQL_CONTAINER"; do
        if docker inspect "$name" >/dev/null 2>&1; then
            die "Container $name already exists; refusing to replace it."
        fi
    done
    mkdir -m 700 "$CERTS_DIR"
    printf '%s\n' "$PROJECT" > "$CERTS_DIR/.fixture-owned"
    trap on_exit EXIT
    generate_certs
    generate_secrets
    log "Starting SQL TLS fixtures on 127.0.0.1:15432 and 127.0.0.1:13306."
    compose up -d --wait --wait-timeout "$HEALTH_TIMEOUT" >/dev/null 2>&1 \
        || die "SQL TLS SELECT 1 readiness failed within the startup budget."
    log "Verified TLS SQL probes succeeded."
    log "Private credentials: $CERTS_DIR/connections.env (do not print or commit)."
    log "Certificates: $CERTS_DIR"
    printf 'Cleanup: %q --cleanup %q\n' "$0" "$CERTS_DIR"
}

main "$@"
