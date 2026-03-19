# Functional Testing Guide

This document describes the functional testing strategy for the Ferrum Gateway, particularly for Control Plane (CP) and Data Plane (DP) mode integration.

## Test Files

### cp_dp_grpc_tests.rs

Located in `tests/integration/cp_dp_grpc_tests.rs`, this file contains integration tests for gRPC communication between CP and DP.

**Tests:**
- `test_dp_receives_initial_config_from_cp` - Verifies DP receives initial config snapshot from CP
- `test_dp_receives_config_updates` - Verifies DP receives streaming config updates
- `test_dp_rejects_invalid_token` - Verifies authentication is enforced
- `test_dp_handles_malformed_config` - Verifies DP handles invalid updates gracefully
- `test_dp_preserves_config_after_cp_shutdown` - Verifies DP caches config when CP goes down

**Running:**
```bash
cargo test --test cp_dp_grpc_tests
```

### functional_cp_dp_test.rs

Located in `tests/functional/functional_cp_dp_test.rs`, this file contains higher-level functional tests for CP/DP integration and database TLS support.

**Test Coverage:**
1. **test_cp_dp_grpc_config_sync** - Tests complete gRPC config sync flow
   - Starts a CP gRPC server
   - Connects a DP client
   - Verifies initial config reception
   - Broadcasts config updates and verifies DP receives them

2. **test_database_connection_with_tls_config** - Tests database connection with TLS parameters
   - Tests plaintext SQLite connection
   - Creates and loads proxies from database
   - Tests TLS configuration parameters (with and without certs)
   - Tests TLS insecure mode

3. **test_env_config_tls_fields** - Verifies all TLS fields are present in EnvConfig
   - Checks db_tls_enabled
   - Checks db_tls_ca_cert_path
   - Checks db_tls_client_cert_path
   - Checks db_tls_client_key_path
   - Checks db_tls_insecure

4. **test_grpc_url_construction** - Tests URL construction for PostgreSQL and MySQL with TLS

**Running (Ignored by Default):**
```bash
# Run all functional tests
cargo test --test functional_cp_dp_test -- --ignored

# Run specific test
cargo test --test functional_cp_dp_test test_database_connection_with_tls_config -- --ignored

# Run with output
cargo test --test functional_cp_dp_test -- --ignored --nocapture
```

## Database TLS Support

The database layer now supports TLS configuration for PostgreSQL and MySQL connections.

### Configuration

Set these environment variables to enable database TLS:

```bash
# Enable TLS for database connection
FERRUM_DB_TLS_ENABLED=true

# Path to CA certificate (for server verification)
FERRUM_DB_TLS_CA_CERT_PATH=/path/to/ca.pem

# Path to client certificate (for mTLS)
FERRUM_DB_TLS_CLIENT_CERT_PATH=/path/to/client.pem

# Path to client private key (for mTLS)
FERRUM_DB_TLS_CLIENT_KEY_PATH=/path/to/client-key.pem

# Skip TLS certificate verification (testing only)
FERRUM_DB_TLS_INSECURE=true
```

### Implementation Details

#### EnvConfig Changes

Added to `src/config/env_config.rs`:
```rust
pub db_tls_enabled: bool,
pub db_tls_ca_cert_path: Option<String>,
pub db_tls_client_cert_path: Option<String>,
pub db_tls_client_key_path: Option<String>,
pub db_tls_insecure: bool,
```

#### DatabaseStore Changes

Added to `src/config/db_loader.rs`:
- New method: `connect_with_tls_config()` - Accepts TLS configuration and constructs appropriate connection URLs
- New method: `build_tls_connection_url()` - Builds database-specific TLS URLs
- Legacy method: `connect()` - Remains for backward compatibility, calls `connect_with_tls_config()` with default (no TLS) parameters

**For PostgreSQL:**
- Uses `sslmode=require` parameter
- Supports `sslrootcert`, `sslcert`, `sslkey` parameters

**For MySQL:**
- Uses `ssl-mode=REQUIRED` parameter
- Supports `ssl-ca`, `ssl-client-cert`, `ssl-client-key` parameters

**For SQLite:**
- TLS parameters are ignored (SQLite doesn't use network TLS)

#### Mode Changes

Updated `src/modes/control_plane.rs` and `src/modes/database.rs` to pass TLS configuration to `DatabaseStore::connect_with_tls_config()`.

## CP/DP Mode Integration

### Control Plane (CP)

When FERRUM_MODE=cp:

1. Connects to database (with optional TLS)
2. Loads initial gateway configuration
3. Starts gRPC server on FERRUM_CP_GRPC_LISTEN_ADDR (default: 0.0.0.0:50051)
2. Starts Admin HTTP listener on port FERRUM_ADMIN_HTTP_PORT (default: 9000)
4. Polls database for updates at FERRUM_DB_POLL_INTERVAL (default: 30s)
5. Broadcasts config updates to connected DPs via gRPC

**Required Environment Variables:**
```bash
FERRUM_MODE=cp
FERRUM_ADMIN_JWT_SECRET=<secret-key>
FERRUM_DB_TYPE=sqlite  # or postgres, mysql
FERRUM_DB_URL=sqlite://ferrum.db
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051
FERRUM_CP_GRPC_JWT_SECRET=<secret-key>
```

### Data Plane (DP)

When FERRUM_MODE=dp:

1. Connects to Control Plane via gRPC
2. Receives initial gateway configuration
3. Subscribes to streaming config updates
4. Starts proxy HTTP listener on FERRUM_PROXY_HTTP_PORT (default: 8000)
5. Routes traffic according to configuration

**Required Environment Variables:**
```bash
FERRUM_MODE=dp
FERRUM_DP_CP_GRPC_URL=http://cp-host:50051
FERRUM_DP_GRPC_AUTH_TOKEN=<jwt-token>
FERRUM_ADMIN_JWT_SECRET=<secret-key>
```

## Admin API

The CP mode exposes an Admin API on HTTP port (default: 9000) for managing configuration.

### Create Proxy
```bash
curl -X POST http://localhost:9000/proxies \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "proxy-1",
    "name": "Example Proxy",
    "listen_path": "/api/v1",
    "backend_protocol": "http",
    "backend_host": "example.com",
    "backend_port": 80,
    "strip_listen_path": true,
    "preserve_host_header": false,
    "backend_connect_timeout_ms": 5000,
    "backend_read_timeout_ms": 30000,
    "backend_write_timeout_ms": 30000,
    "auth_mode": "single"
  }'
```

### Create Consumer
```bash
curl -X POST http://localhost:9000/consumers \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test-user",
    "custom_id": "custom-123"
  }'
```

## Testing Workflow

### Local Testing with CP/DP

1. Create database:
```bash
# Using in-memory or file SQLite
export FERRUM_DB_URL="sqlite://./test-ferrum.db"
```

2. Start CP in one terminal:
```bash
FERRUM_MODE=cp \
FERRUM_ADMIN_JWT_SECRET=test-secret \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL=sqlite://./test-ferrum.db \
FERRUM_CP_GRPC_LISTEN_ADDR=127.0.0.1:50051 \
FERRUM_CP_GRPC_JWT_SECRET=test-grpc-secret \
FERRUM_ADMIN_HTTP_PORT=9000 \
FERRUM_LOG_LEVEL=debug \
cargo run --bin ferrum-gateway
```

3. Create a JWT token for Admin API:
```bash
# Use a tool like jwt.io or write a simple script
# Example payload:
{
  "sub": "admin",
  "role": "admin",
  "iat": 1704067200
}
# Sign with FERRUM_ADMIN_JWT_SECRET: "test-secret"
```

4. Create a proxy via Admin API:
```bash
curl -X POST http://localhost:9000/proxies \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "my-proxy",
    "listen_path": "/test",
    "backend_host": "httpbin.org",
    "backend_port": 80,
    "backend_protocol": "http",
    "strip_listen_path": true,
    "auth_mode": "single",
    "backend_connect_timeout_ms": 5000,
    "backend_read_timeout_ms": 30000,
    "backend_write_timeout_ms": 30000
  }'
```

5. Create a JWT token for DP gRPC connection:
```bash
# Example payload:
{
  "sub": "dp-node",
  "role": "data_plane",
  "iat": 1704067200
}
# Sign with FERRUM_CP_GRPC_JWT_SECRET: "test-grpc-secret"
```

6. Start DP in another terminal:
```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URL=http://127.0.0.1:50051 \
FERRUM_DP_GRPC_AUTH_TOKEN=<jwt-token> \
FERRUM_ADMIN_JWT_SECRET=test-secret \
FERRUM_PROXY_HTTP_PORT=8000 \
FERRUM_LOG_LEVEL=debug \
cargo run --bin ferrum-gateway
```

7. Test proxy traffic:
```bash
curl http://localhost:8000/test/get
```

### Testing with TLS Database Connection

For PostgreSQL or MySQL with TLS, set:
```bash
FERRUM_DB_TLS_ENABLED=true
FERRUM_DB_TLS_CA_CERT_PATH=/path/to/ca.pem
FERRUM_DB_TLS_CLIENT_CERT_PATH=/path/to/client.pem
FERRUM_DB_TLS_CLIENT_KEY_PATH=/path/to/client-key.pem
FERRUM_DB_TLS_INSECURE=false  # For testing only, use true to skip verification
```

Then start CP/DP modes normally. The database connection will use TLS.

## Troubleshooting

### DP Not Receiving Config
- Verify CP is running and gRPC server is listening on FERRUM_CP_GRPC_LISTEN_ADDR
- Check that FERRUM_DP_GRPC_AUTH_TOKEN is valid (signed with FERRUM_CP_GRPC_JWT_SECRET)
- Check logs for JWT validation errors

### Admin API Endpoints Failing
- Verify JWT token is properly signed with FERRUM_ADMIN_JWT_SECRET
- Check that token has not expired
- Verify token format: `Authorization: Bearer <token>`

### Database Connection Failures
- For TLS: Ensure certificate paths exist and are readable
- For SQLite: Check file path and permissions
- For PostgreSQL/MySQL: Verify FERRUM_DB_TLS_ENABLED and certificate validity

### Proxy Traffic Not Working
- Verify proxy exists in CP database via Admin API
- Check DP has received config (look for "proxies loaded" in logs)
- Verify backend is reachable from DP
- Check proxy listen_path matches request path

## Performance Considerations

- **Database polling**: Adjust FERRUM_DB_POLL_INTERVAL based on how frequently config changes
- **Config update delay**: DP receives updates via gRPC stream, typically within 100ms
- **Admin API**: Limited by database query performance
- **Proxy throughput**: DP performance scales with number of concurrent connections

## Security Best Practices

1. **JWT Secrets**: Use strong, random secrets for FERRUM_ADMIN_JWT_SECRET and FERRUM_CP_GRPC_JWT_SECRET
2. **TLS Database**: Always use TLS in production for remote databases
3. **Admin API**: Restrict network access to CP Admin API port
4. **Certificate Validation**: Avoid FERRUM_DB_TLS_INSECURE=true in production
5. **DP gRPC**: Ensure DP is only accessible from authorized locations
