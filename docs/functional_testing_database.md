# Database Mode Functional Testing

This document describes the comprehensive functional test suite for the ferrum-edge in DATABASE MODE.

## Overview

The functional test (`tests/functional/functional_database_test.rs`) validates the complete end-to-end functionality of ferrum-edge when operating in database mode. This includes:

- Building the gateway binary
- Creating and initializing a temporary SQLite database
- Starting the gateway in database mode
- Admin API operations (CRUD for proxies, consumers, and plugin configs)
- Request routing through configured proxies
- Configuration synchronization via database polling
- Health and metrics endpoint functionality
- Authentication and authorization via JWT tokens
- Proper cleanup of resources

## Running the Test

### Prerequisites

- Rust toolchain (1.70+)
- Cargo
- SQLite development libraries (usually included with the system)
- ~30 seconds per test run (gateway startup time)

### Execute the Test

```bash
# Run the functional test (ignored by default)
cargo test --test functional_tests functional_database -- --ignored --nocapture

# Or with verbose logging
RUST_LOG=debug cargo test --test functional_tests functional_database -- --ignored --nocapture
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
| `FERRUM_ADMIN_JWT_SECRET` | `test-gateway-secret-key-12345` | JWT signing secret |
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
- `id` (TEXT PRIMARY KEY): Unique proxy identifier
- `listen_path` (TEXT NOT NULL UNIQUE): Path the proxy listens on
- `backend_scheme` (TEXT): Backend protocol (http/https)
- `backend_host` (TEXT): Backend hostname
- `backend_port` (INTEGER): Backend port number
- `strip_listen_path` (INTEGER): Whether to strip listen path from requests
- ... (additional timeout and TLS fields)

**consumers table**
- `id` (TEXT PRIMARY KEY): Consumer identifier
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

- [x] Add PostgreSQL/MySQL backend testing — see [Database TLS Testing](database_tls.md#functional-testing)
- [x] Add TLS configuration testing — see [Database TLS Testing](database_tls.md#functional-testing)
- [ ] Add metrics verification (check actual metric values)
- [ ] Add concurrent request testing
- [ ] Add large payload testing
- [ ] Add WebSocket proxy testing
- [x] Add plugin execution verification — see [Auth & ACL Functional Testing](functional_testing_auth_acl.md)
- [x] Add consumer authentication testing — see [Auth & ACL Functional Testing](functional_testing_auth_acl.md)
- [ ] Add rate limiting verification
- [ ] Add performance benchmarking

## Testing with MongoDB

The MongoDB functional test (`tests/functional/functional_mongodb_test.rs`) provides the same end-to-end coverage as the SQLite test but with a MongoDB backend.

### Prerequisites

```bash
# Start MongoDB
docker run -d --name mongo-test -p 27017:27017 mongo:7

# Build the gateway
cargo build
```

### Running Tests

```bash
# Run the plaintext MongoDB test
cargo test --test functional_tests test_mongodb_plaintext_full_lifecycle -- --ignored --nocapture

# Run TLS tests (requires TLS-enabled MongoDB — see tests/scripts/setup_mongo_tls.sh)
cargo test --test functional_tests test_mongodb_tls_connection -- --ignored --nocapture
cargo test --test functional_tests test_mongodb_mtls_connection -- --ignored --nocapture
```

### Test Coverage

| Test | Connection | What It Verifies |
|---|---|---|
| `test_mongodb_plaintext_full_lifecycle` | Plaintext | Health (reports `"type":"mongodb"`), CRUD (proxy, consumer, plugin), live proxy routing, update, delete |
| `test_mongodb_tls_connection` | TLS | Same CRUD lifecycle over TLS-encrypted connection |
| `test_mongodb_mtls_connection` | mTLS | Same CRUD lifecycle with client certificate auth |

### Environment Variable Overrides

| Variable | Default | Purpose |
|---|---|---|
| `FERRUM_TEST_MONGO_URL` | `mongodb://localhost:27017/ferrum_test` | Plaintext test URL |
| `FERRUM_TEST_MONGO_TLS_URL` | `mongodb://localhost:27018/ferrum_test` | TLS test URL |
| `FERRUM_TEST_MONGO_MTLS_URL` | `mongodb://localhost:27019/ferrum_test` | mTLS test URL |
| `FERRUM_TEST_MONGO_CERT_DIR` | `/tmp/ferrum-mongo-tls-certs` | Directory with `ca.crt`, `client.crt`, `client.key` |

### Cleanup

```bash
docker stop mongo-test && docker rm mongo-test
```

## References

- [Database Mode Documentation](../README.md#database-mode)
- [MongoDB Deployment Guide](mongodb.md)
- [Admin API Reference](../README.md#admin-api)
- [JWT Authentication](../README.md#jwt-authentication)
- [Proxy Configuration](../README.md#proxy-configuration)
- [Database TLS Configuration](database_tls.md)
