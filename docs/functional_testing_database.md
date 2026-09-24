# Database Mode Functional Testing

This document describes the comprehensive functional test suite for ferrum-edge
in database mode, including the required CI backend × behavior matrix.

## Backend × behavior matrix

Hosted CI owns these cells in the `Functional Tests (data-plane)` and `Functional Tests (data-plane-runtime)` jobs
(`.github/workflows/ci.yml`). That job provisions Redis, MongoDB (plaintext +
TLS/mTLS), PostgreSQL, and MySQL (plaintext + TLS), sets explicit
`FERRUM_TEST_*_URL` values, and enables fail-closed mode via
`FERRUM_DB_BACKENDS_REQUIRED=1` and `FERRUM_DB_TLS_REQUIRED=1`. A
missing/unreachable expected backend fails the job instead of silently skipping.

The shard runs four mongod instances: the standalone on `27017` (the required
backend for the cells below, and for the documented `POST /batch` 501 refusal),
a single-node replica set on `27020` for the multi-document transactional batch
and gateway trust-bundle paths, TLS on `27018` (verify-full and require modes),
and mTLS on `27019`. The
replica set is opt-in through `FERRUM_TEST_MONGO_REPLICA_SET` rather than
`FERRUM_DB_BACKENDS_REQUIRED`, but once declared an unreachable member fails the
cell instead of skipping. Mongo TLS/mTLS cells fail closed under
`FERRUM_DB_TLS_REQUIRED=1`.

Local developers keep the historical opt-out: leave those required flags unset
and omit backend URLs / containers; suites print `SKIPPED` and return success.

Shared CI PostgreSQL/MySQL containers are resumed defensively at the start of
SQL-backed cells (`ensure_shared_sql_containers_resumed`) so a prior
connectivity-recovery `docker pause` cannot leave later cells frozen. Each
SQL-backed cell also provisions a dedicated `ferrum_cell_*` database on those
containers (`provision_isolated_sql_database`) so one cell cannot poison later
full-loads. MySQL row mappers decode TEXT/MEDIUMTEXT through UTF-8 helpers so
sqlx-Any BLOB mapping cannot turn a successful write into a false admin 404.

| Behavior | SQLite | PostgreSQL | MySQL | MongoDB |
|---|---|---|---|---|
| Admin CRUD + polling + delete | `test_admin_sqlite_runtime_resource_crud_matrix` | `test_admin_postgres_runtime_resource_crud_matrix` | `test_admin_mysql_runtime_resource_crud_matrix` | `test_admin_mongodb_runtime_resource_crud_matrix` |
| Namespace + runtime isolation | `namespace_suite_sqlite`, `runtime_isolation_sqlite` | `namespace_suite_postgres`, `runtime_isolation_postgres` | `namespace_suite_mysql`, `runtime_isolation_mysql` | `namespace_suite_mongodb`, `runtime_isolation_mongodb` |
| Concurrent mutations | included in SQLite CRUD matrix | included in PostgreSQL CRUD matrix | included in MySQL CRUD matrix | included in MongoDB CRUD matrix |
| Migrate up + idempotency | `functional_migrate_*` (application shard) | `test_postgres_migrate_up_is_idempotent` | `test_mysql_migrate_up_is_idempotent` | N/A (index ensure path in Mongo lifecycle) |
| Connectivity recovery | `functional_db_outage_test` (debug-only `FERRUM_TEST_DB_FAULT_CONTROL` file seam; never corrupts live SQLite/WAL/SHM) / `functional_db_failover_test` | `test_postgres_connectivity_recovery_after_container_pause` | `test_mysql_connectivity_recovery_after_container_pause` | proxy continues on cached config in Mongo lifecycle |
| Supported TLS modes | `test_sqlite_without_tls_settings` (N/A network TLS) | `test_postgresql_tls_verify_full`, `test_postgresql_tls_require` | `test_mysql_tls_verify_identity`, `test_mysql_tls_required` | `test_mongodb_tls_connection` (verify-full), `test_mongodb_tls_require_connection` (require), `test_mongodb_mtls_connection` (mTLS); hosted inline in data-plane CI |
| Gateway trust-bundle acceptance (issue #3727) | `test_gateway_trust_bundle_acceptance_sqlite` | `test_gateway_trust_bundle_acceptance_postgres` | `test_gateway_trust_bundle_acceptance_mysql` | `test_gateway_trust_bundle_acceptance_mongodb_standalone`, `test_gateway_trust_bundle_acceptance_mongodb_replica_set` |
| Two-replica CP convergence + concurrent writers | N/A (single-writer embedded store) | `test_two_control_plane_replicas_converge_postgres` | covered by the PostgreSQL cell (shared `DatabaseStore`) | `test_two_control_plane_replicas_converge_mongodb` |
| Interrupted trust mutation leaves no committed revision without a change row | N/A (SQL writes are transactional) | N/A (SQL writes are transactional) | N/A (SQL writes are transactional) | `test_mongodb_standalone_leaves_no_unrecorded_trust_revision`, `test_mongodb_replica_set_leaves_no_unrecorded_trust_revision` |
| A committed trust mutation whose change row was already consumed is still detected | N/A (SQL writes are transactional) | N/A (SQL writes are transactional) | N/A (SQL writes are transactional) | not live — the interleaving is staged deterministically in `tests/unit/config/gateway_trust_bundle_tests.rs` |

All of the gateway trust-bundle cells live in
`tests/functional/functional_gateway_trust_bundle_ha_test.rs`. They run the same
backend-agnostic acceptance body — create, read, singleton refusal, refused
malformed/oversized candidate, rotation with overlap, lost compare-and-set,
publication at the `ArcSwap` swap, redaction of `/gateway-trust/status` and
`/metrics`, namespace isolation, restart reconstruction, explicit revocation —
so a dialect, driver, or concurrency difference between backends shows up as a
diff in one place. The replica-set cells are opt-in through
`FERRUM_TEST_MONGO_REPLICA_SET` and fail closed once it is declared.

### CI job mapping

| Hosted job | Required backends | Required behaviors |
|---|---|---|
| `Functional Tests (data-plane)` / `(data-plane-runtime)` | sqlite, postgres, mysql, mongodb, redis | admin-crud, polling-delete, namespace-isolation, migrate-idempotent, concurrent-mutations, connectivity-recovery, tls-modes, gateway-trust-bundle acceptance + two-replica CP convergence |
| `Functional Tests (application)` | sqlite (migrate/file/admin) | migrate baseline on SQLite; no network DB URLs |
| `Plugin Hardening Redis Regression` | redis (`FERRUM_REDIS_REQUIRED=1`) | request-dedup cross-instance; shared single-use replay authority across two gateway replicas (`hmac_v2`, DPoP, `replay_scope: shared`); the whole `test_rate_limiting_redis` suite — centralized admission, previous-bucket decay, sustained single- and multi-window admission at the configured rate, multi-window refusals that leave every counter untouched (issue #5517), the database selector handshake, namespace/key-prefix isolation, a shared budget across two gateway instances, and the default `local_fallback` per-pod outage plus live recovery (issue #5519) alongside explicit `fail_closed` |

### Environment variables

| Variable | CI value (data-plane) | Purpose |
|---|---|---|
| `FERRUM_TEST_POSTGRES_URL` | `postgres://ferrum:ferrum@127.0.0.1:5432/ferrum` | Plaintext PostgreSQL CRUD/namespace/migrate/recovery |
| `FERRUM_TEST_MYSQL_URL` | `mysql://ferrum:ferrum@127.0.0.1:3306/ferrum` | Plaintext MySQL CRUD/namespace/migrate/recovery |
| `FERRUM_TEST_MONGO_URL` | `mongodb://127.0.0.1:27017/ferrum_test` | Plaintext MongoDB CRUD/namespace/lifecycle |
| `FERRUM_TEST_MONGO_TLS_URL` | `mongodb://127.0.0.1:27018/ferrum_test` | MongoDB TLS verify-full |
| `FERRUM_TEST_MONGO_TLS_REQUIRE_URL` | `mongodb://127.0.0.1:27018/ferrum_test` | MongoDB TLS require (encryption without cert verification) |
| `FERRUM_TEST_MONGO_MTLS_URL` | `mongodb://127.0.0.1:27019/ferrum_test` | MongoDB mTLS client authentication |
| `FERRUM_TEST_MONGO_CERT_DIR` | `${RUNNER_TEMP}/ferrum-mongo-tls-certs` | Certs provisioned inline by data-plane CI (`ca.crt`, `client.crt`, `client.key`) |
| `FERRUM_TEST_MONGO_REPLICA_SET` | `rs0` | Enables the transactional `POST /batch` cell and the transactional gateway trust-bundle cells |
| `FERRUM_TEST_MONGO_REPLICA_SET_URL` | `mongodb://localhost:27020/ferrum_test` | Replica-set member for those cells |
| `FERRUM_TEST_CERT_DIR` | `${RUNNER_TEMP}/ferrum-db-tls-certs` | SQL TLS certs provisioned inline by data-plane CI (local: `tests/scripts/setup_db_tls.sh`) |
| `FERRUM_DB_BACKENDS_REQUIRED` | `1` | Fail when an expected plaintext backend is missing |
| `FERRUM_DB_TLS_REQUIRED` | `1` | Fail when PostgreSQL/MySQL/MongoDB TLS fixtures are missing |
| `FERRUM_TEST_DB_FAULT_CONTROL` | path set by `functional_db_outage_test` harness | **Debug builds only.** Test-only file seam that forces config-DB acquires to fail with `PoolClosed` while the control file exists. Not a product setting; omitted from `ferrum.conf` / operator configuration docs. Release binaries ignore it. |

## Overview

The functional tests under `tests/functional/` validate end-to-end database-mode
behavior across the backends in the matrix above. Coverage includes:

- Building/starting the gateway binary in database mode
- Admin API operations (CRUD for proxies, consumers, plugin configs, upstreams)
- Request routing through configured proxies
- Configuration synchronization via database polling
- Namespace and runtime isolation
- Migration idempotency and connectivity recovery
- TLS modes for network backends
- Health and metrics endpoint functionality
- Authentication and authorization via JWT tokens
- Proper cleanup of resources

The historical SQLite-focused harness in `functional_database_test.rs` remains
the deep lifecycle walkthrough for a single embedded backend; the matrix rows
above are what required CI must keep green for dialect parity.

## Running the Test

### Prerequisites

- Rust toolchain (1.70+)
- Cargo
- SQLite development libraries (usually included with the system)
- For PostgreSQL/MySQL/MongoDB cells: running servers (or Docker) and the matching `FERRUM_TEST_*_URL`
- Optional fail-closed local gate: `FERRUM_DB_BACKENDS_REQUIRED=1` / `FERRUM_DB_TLS_REQUIRED=1`
- ~30 seconds per backend lifecycle (gateway startup time)

### Execute the Test

```bash
# Run the functional test (ignored by default)
cargo test --test functional_tests functional_database -- --ignored --nocapture

# Or with verbose logging
RUST_LOG=debug cargo test --test functional_tests functional_database -- --ignored --nocapture

# Cross-backend parity cells (requires live Postgres/MySQL URLs)
FERRUM_TEST_POSTGRES_URL=postgres://ferrum:ferrum@127.0.0.1:5432/ferrum \
FERRUM_TEST_MYSQL_URL=mysql://ferrum:ferrum@127.0.0.1:3306/ferrum \
cargo test --test functional_tests functional_database_parity -- --ignored --nocapture
```

### Test Output

The test produces detailed output for each major step:

```
=== Starting Database Mode Functional Test ===

Test harness created:
  Database: /tmp/.../test.db
  Proxy URL: http://127.0.0.1:12345
  Admin URL: http://127.0.0.1:12346

Echo backend started on port 54321

--- Test 1: Create Proxy ---
✓ Proxy created successfully

--- Test 2: Get Proxy ---
✓ Proxy retrieved successfully

[... more tests ...]

=== All Tests Passed ===
```

## Test Harness Architecture

### DatabaseModeTestHarness

The `DatabaseModeTestHarness` struct manages the complete test environment:

```rust
struct DatabaseModeTestHarness {
    temp_dir: TempDir,           // Temporary directory for test artifacts
    gateway_process: Option<Child>, // Gateway process handle
    proxy_base_url: String,      // URL for proxy traffic (port randomized)
    admin_base_url: String,      // URL for admin API (port randomized)
    jwt_secret: String,          // JWT signing secret
    jwt_issuer: String,          // JWT issuer identifier
    admin_port: u16,             // Randomly selected admin port
    proxy_port: u16,             // Randomly selected proxy port
}
```

### Key Features

1. **Port Randomization**: Binds to port 0 to let the OS assign random available ports, avoiding conflicts
2. **Automatic Cleanup**: Drop implementation ensures gateway process is terminated and temporary files cleaned up
3. **JWT Generation**: Produces valid, signed JWT tokens for Admin API authentication
4. **Gateway Startup**: Builds binary in release mode and starts with database mode environment variables
5. **Health Polling**: Waits up to 30 seconds for gateway to be ready before running tests

## Test Cases

### Test 1: Create Proxy
**Endpoint**: `POST /proxies`

Creates a new proxy configuration via the Admin API.

**Validates**:
- Admin API accepts proxy creation requests
- Successful HTTP 2xx response
- Proxy is stored in database

### Test 2: Get Proxy
**Endpoint**: `GET /proxies/{id}`

Retrieves a previously created proxy.

**Validates**:
- Proxy can be retrieved from Admin API
- Returned data matches what was created
- Proper JSON response format

### Test 3: Route Request Through Proxy
**Endpoint**: `GET /test-path` (via proxy)

Sends an HTTP request through the configured proxy to verify routing.

**Validates**:
- Proxy correctly routes traffic to backend
- Backend receives the request
- Response from backend is returned to client
- Complete request-response cycle works

### Test 4: Update Proxy
**Endpoint**: `PUT /proxies/{id}`

Updates an existing proxy configuration.

**Validates**:
- Admin API accepts proxy updates
- Changes are persisted to database
- Database polling picks up the changes
- Updated configuration is used for subsequent requests

### Test 5: Create Consumer
**Endpoint**: `POST /consumers`

Creates a consumer identity.

**Validates**:
- Consumer CRUD operations work
- Consumer data is persisted

### Test 6: Get Consumer
**Endpoint**: `GET /consumers/{id}`

Retrieves a consumer.

**Validates**:
- Consumer retrieval works correctly

### Test 7: Create Plugin Config
**Endpoint**: `POST /plugins/config`

Creates a plugin configuration.

**Validates**:
- Plugin config CRUD operations work
- Plugin configurations are persisted

### Test 8: Get Plugin Config
**Endpoint**: `GET /plugins/config/{id}`

Retrieves a plugin configuration.

**Validates**:
- Plugin config retrieval works correctly

### Test 9: Health Endpoint
**Endpoint**: `GET /health`

Checks gateway health status.

**Validates**:
- Health endpoint responds
- Returns proper JSON with status field

### Test 10: Metrics Endpoint
**Endpoint**: `GET /admin/metrics`

Retrieves operational metrics.

**Validates**:
- Metrics endpoint is available
- Returns metric data

### Test 11: Delete Proxy
**Endpoint**: `DELETE /proxies/{id}`

Deletes a proxy configuration.

**Validates**:
- Proxy deletion works
- Deletion is persisted to database

### Test 12: Verify Proxy Deletion
**Endpoint**: `GET /proxies/{id}` (after deletion)

Confirms proxy is no longer available.

**Validates**:
- Deleted proxy returns 404
- Deletion is reflected after database poll

### Test 13: Verify Deleted Proxy Not Routable
**Endpoint**: `GET /test-path` (after proxy deletion)

Confirms requests to deleted proxy path fail.

**Validates**:
- Deleted proxy is removed from routing table
- Requests fail appropriately

### Test 14: JWT Authentication Required
**Endpoint**: `GET /proxies` (without Authorization header)

Confirms authentication is enforced.

**Validates**:
- Requests without valid JWT are rejected with 401
- Authentication is required for Admin API

### Test 15: List Proxies
**Endpoint**: `GET /proxies`

Lists all proxies.

**Validates**:
- Multiple proxies can be listed
- Returns array of proxies

## Environment Variables Used

| Variable | Value | Purpose |
|----------|-------|---------|
| `FERRUM_MODE` | `database` | Operating mode |
| `FERRUM_ADMIN_JWT_SECRET` | `change-me-to-a-32-character-admin-secret` | JWT signing secret |
| `FERRUM_ADMIN_JWT_ISSUER` | `ferrum-edge-test` | JWT issuer claim |
| `FERRUM_DB_TYPE` | `sqlite` | Database type |
| `FERRUM_DB_URL` | `sqlite:////tmp/xxx/test.db` | Database connection string |
| `FERRUM_DB_POLL_INTERVAL` | `2` | Database poll interval (seconds) |
| `FERRUM_PROXY_HTTP_PORT` | (random) | Proxy HTTP port |
| `FERRUM_ADMIN_HTTP_PORT` | (random) | Admin API HTTP port |
| `FERRUM_LOG_LEVEL` | `info` | Logging level |

## Database Schema

The test uses SQLite with the following schema (automatically created):

**proxies table**
- `id` (TEXT): Proxy identifier, unique within its namespace
- `namespace` (TEXT): Owning tenant; `PRIMARY KEY (namespace, id)`
- `listen_path` (TEXT NOT NULL UNIQUE): Path the proxy listens on
- `backend_scheme` (TEXT): Backend protocol (http/https)
- `backend_host` (TEXT): Backend hostname
- `backend_port` (INTEGER): Backend port number
- `strip_listen_path` (INTEGER): Whether to strip listen path from requests
- ... (additional timeout and TLS fields)

**consumers table**
- `id` (TEXT): Consumer identifier, unique within its namespace
- `namespace` (TEXT): Owning tenant; `PRIMARY KEY (namespace, id)`
- `username` (TEXT): Username
- `custom_id` (TEXT): Custom identifier
- ... (credential and timing fields)

**plugins_config table**
- `id` (TEXT PRIMARY KEY): Plugin config identifier
- `name` (TEXT): Plugin name
- `scope` (TEXT): Scope (proxy, consumer, global)
- `target_id` (TEXT): Target proxy/consumer ID
- `config` (JSON): Plugin configuration

## Echo Backend Server

The test starts a simple in-process echo backend server that:

1. Listens on a random available port
2. Accepts TCP connections
3. Reads HTTP requests
4. Returns `{"status":"ok","echo":true}` for any request
5. Runs until test completes

This allows testing the complete request-response path through the gateway without external dependencies.

## Common Issues and Troubleshooting

### Test Timeout (30 seconds)

**Symptom**: Test fails with "Gateway did not start within 30 seconds"

**Cause**: Gateway process not starting or database not initializing

**Solution**:
- Ensure SQLite is installed: `sqlite3 --version`
- Check build logs: `cargo build --release 2>&1`
- Verify disk space in /tmp
- Try with `FERRUM_LOG_LEVEL=debug` for more details

### Port Already in Use

**Symptom**: "Address already in use" error

**Cause**: Random port selection hit occupied port (unlikely but possible)

**Solution**:
- Run test again (different ports will be selected)
- Check for lingering processes: `lsof -i :PORT`

### Database Lock

**Symptom**: "database is locked" errors

**Cause**: SQLite not properly closed between tests

**Solution**:
- Ensure Drop implementation runs
- Use `--test-threads=1` to serialize tests

### JWT Token Errors

**Symptom**: 401 Unauthorized errors

**Cause**: Token expiration or invalid signature

**Solution**:
- Check system time is correct
- Verify JWT secret matches in harness and gateway
- Ensure token generation uses same algorithm (HS256)

## Performance Expectations

| Operation | Expected Duration |
|-----------|-------------------|
| Gateway startup | 3-5 seconds |
| Proxy creation | <100ms |
| Proxy retrieval | <50ms |
| Proxy routing | <10ms |
| Database poll cycle | 2 seconds (configured) |
| Full test suite | 30-45 seconds |

## Extending the Tests

To add new test cases:

1. Add a new numbered test section (Test N)
2. Follow the pattern: setup → execute → assert
3. Add detailed println! statements for clarity
4. Ensure proper cleanup
5. Update this documentation

Example:

```rust
// Test N: Your Test Name
println!("\n--- Test N: Your Test Name ---");
let response = client
    .post(format!("{}/endpoint", harness.admin_base_url))
    .header("Authorization", &auth_header)
    .json(&data)
    .send()
    .await
    .expect("Request failed");

assert!(response.status().is_success());
println!("✓ Test description");
```

## Future Enhancements

Broad "add X testing" bullets from the original checklist are reconciled against
current functional coverage. Retain only exact residuals.

### Covered (do not reopen as missing database-mode work)

- [x] PostgreSQL/MySQL backend testing — required CI matrix in this doc + `functional_database_parity_test` / admin CRUD / namespace entry points
- [x] TLS configuration testing — see [Database TLS Testing](database_tls.md#functional-testing); hosted data-plane provisions SQL + Mongo TLS fixtures inline with `FERRUM_DB_TLS_REQUIRED=1`
- [x] Metrics verification (endpoint + selected metric values) — `functional_database_test` hits `/admin/metrics`; value-level asserts live in `functional_admin_observability_test` / `functional_admin_connection_limit_test`
- [x] Concurrent request testing — `run_concurrent_admin_mutations` in the admin CRUD matrix
- [x] Large / bounded payload testing — `functional_body_size_limits_test` (request/response Content-Length and streaming limits)
- [x] WebSocket proxy testing — `functional_websocket_*` / `functional_ws_*` suites
- [x] Plugin execution verification — see [Auth & ACL Functional Testing](functional_testing_auth_acl.md)
- [x] Consumer authentication testing — see [Auth & ACL Functional Testing](functional_testing_auth_acl.md)
- [x] Rate limiting verification — `functional_redis_rate_limiting_test` + plugin network suites
- [x] Performance / scale stress — `tests/performance/multi_protocol/` plus scheduled `.github/workflows/scaling-regression.yml` (30k/10k suites excluded from PR shards by design)

### Exact residuals (live trackers)

- [ ] MongoDB replica-set **change-stream-triggered** config wakeups (polling remains the authoritative backstop) — [#3330](https://github.com/ferrum-edge/ferrum-edge/issues/3330)
- [x] Live OIDC relying-party / OAuth2 introspection service-integration coverage — [#3333](https://github.com/ferrum-edge/ferrum-edge/issues/3333)

## Testing with MongoDB

The MongoDB functional test (`tests/functional/functional_mongodb_test.rs`) provides the same end-to-end coverage as the SQLite test but with a MongoDB backend.

### Prerequisites

```bash
# Start MongoDB (plaintext)
docker run -d --name mongo-test -p 27017:27017 mongo:7

# MongoDB TLS/mTLS fixtures are provisioned inline by hosted data-plane CI.
# Local TLS cells skip unless FERRUM_TEST_MONGO_CERT_DIR and ports 27018/27019
# are already available.

# Build the gateway
cargo build
```

### Running Tests

```bash
# Run the plaintext MongoDB test
cargo test --test functional_tests test_mongodb_plaintext_full_lifecycle -- --ignored --nocapture

# Run TLS tests (hosted CI sets FERRUM_DB_TLS_REQUIRED=1; local skips without fixtures)
cargo test --test functional_tests test_mongodb_tls_connection -- --ignored --nocapture
cargo test --test functional_tests test_mongodb_tls_require_connection -- --ignored --nocapture
cargo test --test functional_tests test_mongodb_mtls_connection -- --ignored --nocapture
```

### Test Coverage

| Test | Connection | What It Verifies |
|---|---|---|
| `test_mongodb_plaintext_full_lifecycle` | Plaintext | Health (reports `"type":"mongodb"`), CRUD (proxy, consumer, plugin), live proxy routing, update, delete |
| `test_mongodb_tls_connection` | TLS `verify-full` | Same CRUD lifecycle over TLS with server certificate verification |
| `test_mongodb_tls_require_connection` | TLS `require` | Same CRUD lifecycle over TLS with server certificate verification disabled |
| `test_mongodb_mtls_connection` | mTLS | Same CRUD lifecycle with client certificate auth |

### Environment Variable Overrides

| Variable | Default | Purpose |
|---|---|---|
| `FERRUM_TEST_MONGO_URL` | `mongodb://localhost:27017/ferrum_test` | Plaintext test URL |
| `FERRUM_TEST_MONGO_TLS_URL` | `mongodb://localhost:27018/ferrum_test` | TLS verify-full test URL |
| `FERRUM_TEST_MONGO_TLS_REQUIRE_URL` | falls back to `FERRUM_TEST_MONGO_TLS_URL` | TLS `require` test URL |
| `FERRUM_TEST_MONGO_MTLS_URL` | `mongodb://localhost:27019/ferrum_test` | mTLS test URL |
| `FERRUM_TEST_MONGO_CERT_DIR` | `/tmp/ferrum-mongo-tls-certs` | Directory with `ca.crt`, `client.crt`, `client.key` |
| `FERRUM_DB_TLS_REQUIRED` | unset locally / `1` in hosted data-plane | Fail closed when Mongo TLS fixtures are missing |

### Cleanup

```bash
docker stop mongo-test && docker rm mongo-test
```

## References

- [Database Mode Documentation](../README.md#database-mode-sqlite)
- [MongoDB Deployment Guide](mongodb.md)
- [Admin API Reference](../README.md#admin-api)
- [JWT Authentication](configuration.md#authentication)
- [Proxy Configuration](configuration.md#proxy-listener)
- [Database TLS Configuration](database_tls.md)
