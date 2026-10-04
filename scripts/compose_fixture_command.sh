#!/usr/bin/env bash
# Finite hosted qualification operations; environment inputs are quoted data.
# Keep executable names and repository edges literal for the frozen policy scan.
set +x
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true ]] || exit 1

compose() {
    exec docker compose --env-file /dev/null -p ferrum-fixture-qualification \
        -f docker-compose.yml -f "${FIXTURE_OVERRIDE:?}" "$@"
}

case "${FIXTURE_OPERATION:?}" in
    inspect)
        exec docker inspect "${FIXTURE_CONTAINER:?}"
        ;;
    top)
        exec docker top "${FIXTURE_CONTAINER:?}" -eo args
        ;;
    logs)
        exec docker logs "${FIXTURE_CONTAINER:?}"
        ;;
    compose-services)
        compose config --services
        ;;
    compose-config-check)
        compose --profile mongodb config --quiet
        ;;
    compose-config-json)
        compose --profile mongodb config --format json
        ;;
    compose-default-up)
        compose up -d --no-build --wait --wait-timeout 120
        ;;
    compose-postgres-up)
        compose --profile postgres up -d --no-build --wait --wait-timeout 120 ferrum-postgres
        ;;
    compose-mongo-invalid-up)
        compose --profile mongodb up -d --no-build --wait --wait-timeout 30 \
            mongodb ferrum-mongodb
        ;;
    compose-mongo-up)
        compose --profile mongodb up -d --no-build --wait --wait-timeout 120 \
            mongodb ferrum-mongodb
        ;;
    compose-mongo-recreate)
        compose --profile mongodb up -d --no-build --wait --force-recreate \
            --wait-timeout 30 mongodb ferrum-mongodb
        ;;
    compose-down)
        compose --profile mongodb --profile postgres down --volumes
        ;;
    mongo-authenticated)
        exec docker exec ferrum-mongodb-db mongosh --quiet --nodb --eval \
            "const c = new Mongo('mongodb://ferrum:' + process.env.MONGO_INITDB_ROOT_PASSWORD + '@localhost:27017/?authSource=admin'); const s = c.getDB('admin').runCommand({connectionStatus:1}); if (!s.ok || !s.authInfo.authenticatedUsers.some(u => u.user === 'ferrum')) quit(1);"
        ;;
    mongo-historical-password)
        exec docker exec ferrum-mongodb-db mongosh --quiet --nodb --eval \
            "new Mongo('mongodb://ferrum:dev-password-change-in-production@localhost:27017/?authSource=admin')"
        ;;
    setup)
        exec bash scripts/setup_db_tls.sh "${FIXTURE_CERTS_DIR:?}"
        ;;
    cleanup)
        exec bash scripts/setup_db_tls.sh --cleanup "${FIXTURE_CERTS_DIR:?}"
        ;;
    pg-query)
        exec docker exec -e PGPASSWORD ferrum-test-pg-tls psql "${FIXTURE_CONNECTION:?}" \
            -v ON_ERROR_STOP=1 -Atqc "${FIXTURE_QUERY:?}"
        ;;
    pg-require-client)
        exec docker exec ferrum-test-pg-tls sh -ec \
            "sed -i 's/scram-sha-256\$/scram-sha-256 clientcert=verify-full/' /var/lib/postgresql/tls/pg_hba.conf; psql -U ferrum -d ferrum -v ON_ERROR_STOP=1 -c 'SELECT pg_reload_conf()'"
        ;;
    mysql-require-client)
        exec docker exec ferrum-test-mysql-tls mysql \
            --defaults-extra-file=/run/secrets/mysql-root.cnf \
            -e "ALTER USER 'ferrum'@'%' REQUIRE X509"
        ;;
    mysql-query)
        client_file=/run/secrets/mysql-client.cnf
        set --
        case "${FIXTURE_MYSQL_MODE:?}" in
            trusted) ;;
            wrong-ca) set -- --ssl-ca=/client/bad-ca.crt ;;
            wrong-hostname) set -- --host=127.0.0.2 ;;
            plaintext) set -- --ssl-mode=DISABLED ;;
            no-client) client_file=/client/no-client.cnf ;;
            trusted-tls12) set -- --tls-version=TLSv1.2 ;;
            rogue-tls12)
                set -- --tls-version=TLSv1.2 --ssl-cert=/client/rogue.crt \
                    --ssl-key=/client/rogue.key
                ;;
            rogue-default) set -- --ssl-cert=/client/rogue.crt --ssl-key=/client/rogue.key ;;
            *) exit 1 ;;
        esac
        exec docker exec ferrum-test-mysql-tls mysql "--defaults-extra-file=$client_file" \
            --batch --skip-column-names "$@" -e "${FIXTURE_QUERY:?}"
        ;;
    untrusted-ca)
        exec openssl req -new -x509 -newkey rsa:2048 -nodes -days 1 \
            -subj '/CN=Untrusted Fixture CA' -keyout "${FIXTURE_CERTS_DIR:?}/client/bad-ca.key" \
            -out "$FIXTURE_CERTS_DIR/client/bad-ca.crt"
        ;;
    rogue-key)
        exec openssl req -new -newkey rsa:2048 -nodes -subj /CN=ferrum \
            -keyout "${FIXTURE_CERTS_DIR:?}/client/rogue.key" \
            -out "$FIXTURE_CERTS_DIR/client/rogue.csr"
        ;;
    rogue-cert)
        exec openssl x509 -req -days 1 -in "${FIXTURE_CERTS_DIR:?}/client/rogue.csr" \
            -CA "$FIXTURE_CERTS_DIR/client/bad-ca.crt" \
            -CAkey "$FIXTURE_CERTS_DIR/client/bad-ca.key" -CAcreateserial \
            -extfile "$FIXTURE_CERTS_DIR/client/rogue.cnf" \
            -out "$FIXTURE_CERTS_DIR/client/rogue.crt"
        ;;
    *) exit 1 ;;
esac
